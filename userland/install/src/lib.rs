// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-install: the text installer (ADR 0029) on the install engine,
//! and what the graphical one (`gui`, ADR 0034) shares with it.
//!
//! On the live system it runs on the console when there is no display
//! (or `slate.installer=text`). It asks for the disk (preselected when
//! there is one), an explicit `erase`, the first account (name,
//! username, computer name, password: root gets no password, ADR 0035),
//! whether to turn on Linux compatibility mode (ADR 0032, default no) and
//! the network (DHCP or a fixed address, ADR 0054), and on a machine with
//! an AMD card whether to use full graphics (ADR 0173, default no); then
//! it installs and restarts. `slate-install --disk sda --password-file F
//! --yes [--linux-compat] [--full-graphics] [--network WORDS]` installs
//! without asking, with F as
//! root's password. On a disk that has partitions it offers to go beside
//! them, in a free space, or lets the person delete some and choose the
//! place and size (ADR 0116); `--beside [--delete N]... [--root-size G]`
//! does that unattended, and `--map DISK` shows what a disk holds.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod bootent;
pub mod engine;
pub mod front;
pub mod gui;
pub mod region;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use engine::{Device, Payload, Step};
use slate_coreutils::crypt;
use slate_rt::{fs, io, lossy, print, println, process, term};

/// Where the live system keeps what it installs.
const PAYLOAD: &str = "/install";
const KEYS: &str = "/usr/share/quarry/keys";

/// A disk that can be installed to.
#[derive(Clone, Debug)]
pub struct Disk {
    pub name: String,
    pub bytes: u64,
    pub model: String,
    pub removable: bool,
}

impl Disk {
    /// "sda  256.1 GB  KINGSTON SKC600MS256G"
    pub fn describe(&self) -> String {
        let gb = self.bytes / 100_000_000;
        let kind = if self.removable { "  (removable)" } else { "" };
        format!("{:<8} {:>4}.{} GB  {}{kind}", self.name, gb / 10, gb % 10, self.model)
    }
}

fn read_text(path: &str) -> String {
    String::from(lossy(&fs::read_file(path.as_bytes()).unwrap_or_default()).trim())
}

/// The install medium: an ISO 9660 volume ("CD001" at byte 32769,
/// ECMA-119 §8.1), or the USB image: an MBR partition of type EFh whose
/// FAT32 volume label (boot sector bytes 71-81, fatgen103 §3.3) is
/// `SLATE-LIVE` (ADR 0029).
fn is_install_medium(name: &str) -> bool {
    let Ok(fd) = fs::open(format!("/dev/{name}").as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0) else { return false };
    let mut b = [0u8; 8];
    let iso = io::pread(fd, &mut b, 32768) == Ok(8) && &b[1..6] == b"CD001";
    let usb = !iso && is_live_stick(fd);
    let _ = io::close(fd);
    iso || usb
}

fn is_live_stick(fd: i32) -> bool {
    let mut mbr = [0u8; 512];
    if io::pread(fd, &mut mbr, 0) != Ok(512) || mbr[510..512] != [0x55, 0xAA] {
        return false;
    }
    (0..4).any(|i| {
        let e = &mbr[446 + 16 * i..462 + 16 * i];
        let first = u32::from_le_bytes([e[8], e[9], e[10], e[11]]);
        let mut bs = [0u8; 512];
        e[4] == 0xEF && io::pread(fd, &mut bs, u64::from(first) * 512) == Ok(512) && &bs[71..82] == b"SLATE-LIVE "
    })
}

/// Disks from /sys/block that are big enough and not the install medium.
pub fn disks() -> Vec<Disk> {
    disks_with(false)
}

/// Disks from /sys/block that are big enough, with the install medium if
/// `medium` (the live system runs from memory, ADR 0029, so an
/// unattended install may overwrite the disk it started from).
fn disks_with(medium: bool) -> Vec<Disk> {
    let mut out = Vec::new();
    let mut names: Vec<String> =
        fs::read_dir(b"/sys/block").unwrap_or_default().into_iter().map(|e| String::from(lossy(&e.name))).collect();
    names.sort();
    for name in names {
        let dir = format!("/sys/block/{name}");
        let bytes = read_text(&format!("{dir}/size")).parse::<u64>().unwrap_or(0) * 512;
        if bytes < engine::MIN_DISK || (!medium && is_install_medium(&name)) {
            continue;
        }
        out.push(Disk {
            model: read_text(&format!("{dir}/device/model")),
            removable: read_text(&format!("{dir}/removable")) == "1",
            name,
            bytes,
        });
    }
    out
}

/// A block device opened for the engine.
struct BlockDev {
    fd: i32,
}

impl Device for BlockDev {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> engine::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            match io::pread(self.fd, &mut buf[done..], offset + done as u64) {
                Ok(0) => return Err(engine::Error("unexpected end of the disk".into())),
                Ok(n) => done += n,
                Err(e) => return Err(engine::Error(format!("reading the disk: {e}"))),
            }
        }
        Ok(())
    }
    fn write(&mut self, offset: u64, data: &[u8]) -> engine::Result<()> {
        let mut done = 0;
        while done < data.len() {
            match io::pwrite(self.fd, &data[done..], offset + done as u64) {
                Ok(0) => return Err(engine::Error("unexpected end of the disk".into())),
                Ok(n) => done += n,
                Err(e) => return Err(engine::Error(format!("writing the disk: {e}"))),
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> engine::Result<()> {
        const BLKFLSBUF: u32 = 0x1261;
        let _ = fs::fsync(self.fd);
        io::ioctl(self.fd, BLKFLSBUF, 0).map(|_| ()).map_err(|e| engine::Error(format!("flushing the disk: {e}")))
    }
}

/// The payload files, read and checked.
struct Files {
    system: Vec<u8>,
    kernel: Vec<u8>,
    efi: Vec<u8>,
    bios_hdd: Vec<u8>,
    /// Limine's stage 3, when the media carry Limine for BIOS.
    bios_sys: Option<Vec<u8>>,
}

/// The running kernel's own file, on the live system.
const KERNEL_FILE: &str = "/proc/slate_kernel";

fn load_payload() -> Result<Files, String> {
    let read = |p: &str| fs::read_file(format!("{PAYLOAD}/{p}").as_bytes()).map_err(|e| format!("{PAYLOAD}/{p}: {e}"));
    let files = Files {
        system: read("system.cpio")?,
        // The media carry the kernel once, to boot: the live system's
        // kernel shows its own file (older media had a copy here).
        kernel: fs::read_file(KERNEL_FILE.as_bytes()).or_else(|_| read("boot/kernel"))?,
        efi: read("boot/BOOTX64.EFI")?,
        bios_hdd: read("boot/bios-hdd.bin")?,
        bios_sys: read("boot/limine-bios.sys").ok(),
    };
    let sig = read("system.sig")?;
    let mut keys = Vec::new();
    for e in fs::read_dir(KEYS.as_bytes()).unwrap_or_default() {
        if e.name.ends_with(b".pub") {
            let text = read_text(&format!("{KEYS}/{}", lossy(&e.name)));
            if let Ok(k) = slate_qpkg::PublicKey::parse(&text) {
                keys.push(k);
            }
        }
    }
    engine::verify(&files.system, &sig, &slate_qpkg::Keyring::new(keys)).map_err(|e| e.0)?;
    Ok(files)
}

fn kernel_log() -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 256 * 1024];
    match slate_rt::process::kernel_log(slate_rt::process::KernelLog::ReadAll, &mut buf) {
        Ok(n) => {
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// Where an install is: checking the payload, then the engine's steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Verifying,
    Step(Step),
}

fn hash(password: &[u8]) -> Result<String, String> {
    let mut salt = [0u8; 12];
    process::random(&mut salt).map_err(|e| format!("random numbers: {e}"))?;
    crypt::crypt(password, crypt::new_salt(&salt).as_bytes()).ok_or_else(|| "hashing the password failed".into())
}

/// A new master key and the header guarding it with `password`, for a
/// root partition of `sectors` (ADR 0036).
fn encryption(password: &[u8], sectors: u64) -> Result<engine::Encryption, String> {
    let mut random = [0u8; 64 + 32 + 16];
    process::random(&mut random).map_err(|e| format!("random numbers: {e}"))?;
    let mut key: [u8; 64] = random[..64].try_into().unwrap_or([0; 64]);
    let salt: [u8; 32] = random[64..96].try_into().unwrap_or([0; 32]);
    let uuid: [u8; 16] = random[96..].try_into().unwrap_or([0; 16]);
    slatecrypt::wipe(&mut random);
    let params = slatecrypt::Params::DEFAULT;
    let mut memory = alloc::vec![slatecrypt::Block::default(); params.blocks()];
    let slot = slatecrypt::new_slot(&key, password, salt, params, &mut memory);
    let slot = match slot {
        Ok(s) => s,
        Err(e) => {
            slatecrypt::wipe(&mut key);
            return Err(format!("setting up encryption: {e:?}"));
        }
    };
    let mut header = slatecrypt::Header::new(sectors, uuid);
    // The slot is the first account's (ADR 0058): UID 1000, the first
    // free one after the base system's accounts (engine::next_uid).
    header.slots[0] = Some(slatecrypt::Slot { owner: Some(1000), ..slot });
    let e = engine::Encryption { header: alloc::boxed::Box::new(header.to_bytes()), key };
    slatecrypt::wipe(&mut key);
    Ok(e)
}

/// What is on `disk` now (ADR 0116).
pub fn disk_map(disk: &Disk) -> Result<engine::DiskMap, String> {
    let path = format!("/dev/{}", disk.name);
    let fd = fs::open(path.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let r = engine::scan(&mut BlockDev { fd }, disk.bytes).map_err(|e| e.0);
    let _ = io::close(fd);
    r
}

/// Whether the installer can make boot entries, as installing beside
/// another system needs: the computer started it on UEFI firmware.
pub fn can_go_beside() -> bool {
    bootent::available()
}

/// Lay out `disk` as `p` says.
fn plan_for(disk: &Disk, p: &Placement, random: &[u8; 64]) -> Result<engine::Plan, String> {
    let Placement::Beside { delete, region, size } = p else {
        return engine::plan(disk.bytes, random).map_err(|e| e.0);
    };
    if !can_go_beside() {
        return Err("installing beside another system needs UEFI firmware (this computer started in BIOS mode)".into());
    }
    let map = disk_map(disk)?.without(delete);
    let at = match region {
        Some(r) => *r,
        None => map.largest_free().ok_or("the disk has no free space")?.0,
    };
    engine::plan_beside(&map, at, *size, random).map_err(|e| e.0)
}

/// Install on `disk` as `c` says, reporting progress.
pub fn install_on(disk: &Disk, c: &Choices, progress: &mut dyn FnMut(Progress)) -> Result<(), String> {
    progress(Progress::Verifying);
    let files = load_payload()?;
    let mut random = [0u8; 64];
    process::random(&mut random).map_err(|e| format!("random numbers: {e}"))?;
    // No root password locks root (shadow(5)'s "!").
    let root_hash = match &c.root_password {
        Some(p) => hash(p)?,
        None => String::from("!"),
    };
    let mut plan = plan_for(disk, &c.placement, &random)?;
    plan.cmdline_extra = c.cmdline.clone();
    plan.root_keys = c.keys.clone();
    plan.linux_compat = c.linux_compat;
    plan.hostname = c.hostname.clone();
    plan.locale = c.locale.clone();
    plan.keyboard = c.keyboard.clone();
    plan.timezone = c.timezone.clone();
    plan.desktop = c.desktop;
    plan.full_graphics = c.full_graphics;
    plan.network = c.network.clone();
    if let Some(a) = &c.account {
        plan.account = Some(engine::Account {
            username: a.username.clone(),
            full_name: a.full_name.clone(),
            hash: hash(&a.password)?,
        });
    }
    if c.encrypt {
        let password = match (&c.account, &c.root_password) {
            (Some(a), _) => &a.password,
            (None, Some(p)) => p,
            (None, None) => return Err("encryption needs a password".into()),
        };
        plan.encryption = Some(encryption(password, plan.root.1 + 1 - plan.root.0)?);
    }
    let path = format!("/dev/{}", disk.name);
    let fd = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let mut dev = BlockDev { fd };
    let bios = engine::BiosBoot { hdd: &files.bios_hdd, sys: files.bios_sys.as_deref() };
    let payload = Payload { system: &files.system, kernel: &files.kernel, efi: &files.efi, bios: Some(bios) };
    let (secs, nanos) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
    let log = kernel_log();
    let r = engine::install(&mut dev, &plan, &payload, &root_hash, &log, (secs, nanos as u32), &mut |s| {
        progress(Progress::Step(s))
    });
    // Have the kernel read the new partition table (BLKRRPART).
    let _ = io::ioctl(fd, 0x125F, 0);
    let _ = io::close(fd);
    r.map_err(|e| e.0)?;
    // A boot entry of its own (ADR 0088). Without one the firmware still
    // finds the removable-media path, so a failure only warns.
    if bootent::available() {
        let (number, start, size) = (plan.esp_number(), plan.esp.0, plan.esp.1 + 1 - plan.esp.0);
        let esp = bootent::Partition { number, start, size, guid: plan.esp_guid };
        let loader = format!("\\{}", plan.loader_path().replace('/', "\\"));
        if let Err(e) = bootent::add_at(&esp, &loader) {
            slate_rt::eprintln!("\nslate-install: no boot entry: {e}");
        }
    }
    Ok(())
}

/// Install, reporting progress on the console.
fn run_install(disk: &Disk, c: &Choices) -> Result<(), String> {
    let mut last: Option<Progress> = None;
    let mut show = |p: Progress| {
        use Progress::Step as S;
        // Finish the previous line unless it is the copy counter going on.
        let copying = |p: Option<Progress>| matches!(p, Some(S(Step::Copy(..))));
        if last.is_some() && !copying(last) {
            println!(" done");
        }
        match p {
            S(Step::Copy(done, total)) => {
                print!("\r  Copying the system... {}%", done * 100 / total.max(1));
                if done == total {
                    println!(" done");
                }
            }
            Progress::Verifying => print!("  Checking the system image..."),
            S(Step::Partition) => print!("  Partitioning the disk..."),
            S(Step::BootPartition) => print!("  Writing the boot partition..."),
            S(Step::FileSystem) => print!("  Creating the file system..."),
            S(Step::Account) => print!("  Setting up the accounts..."),
            S(Step::Finish) => print!("  Finishing..."),
        }
        io::flush_stdout();
        last = Some(p);
    };
    install_on(disk, c, &mut show)?;
    println!(" done");
    Ok(())
}

/// Read a line from the console; echo off for passwords.
fn read_line(secret: bool) -> Option<Vec<u8>> {
    let saved = term::get(0).ok();
    if let Some(t) = saved {
        let mut q = t;
        q.lflag |= term::ICANON;
        if secret {
            q.lflag &= !term::ECHO;
        } else {
            q.lflag |= term::ECHO;
        }
        let _ = term::set(0, &q, true);
    }
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let ok = loop {
        match io::read(0, &mut b) {
            Ok(1) if b[0] == b'\n' || b[0] == b'\r' => break true,
            Ok(1) => line.push(b[0]),
            _ => break !line.is_empty(),
        }
    };
    if let Some(t) = saved {
        let _ = term::set(0, &t, true);
    }
    if secret {
        println!();
    }
    ok.then_some(line)
}

fn ask(prompt: &str) -> String {
    print!("{prompt}");
    io::flush_stdout();
    String::from(lossy(&read_line(false).unwrap_or_default()).trim())
}

fn header() {
    // Clear the screen, cursor home (ECMA-48 ED and CUP).
    print!("\x1b[2J\x1b[H");
    println!();
    println!("  Slate installer");
    println!("  ===============");
    println!();
}

fn pause(msg: &str) {
    let _ = ask(&format!("  {msg} Press Enter to continue. "));
}

/// A command line, until it exits.
fn shell() {
    println!("  Type 'exit' to come back to the installer.");
    let argv = [b"/bin/sh".to_vec(), b"-l".to_vec()];
    let env = [b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec(), b"HOME=/root".to_vec(), b"TERM=linux".to_vec()];
    match process::fork() {
        Ok(0) => {
            let e = process::execve(b"/bin/sh", &argv, &env);
            slate_rt::eprintln!("/bin/sh: {e}");
            process::exit_now(127);
        }
        Ok(pid) => {
            let _ = process::wait(pid, 0);
        }
        Err(e) => println!("  fork: {e}"),
    }
}

/// Choose the disk: `None` to go back to the start.
fn choose_disk(list: &[Disk]) -> Option<Disk> {
    println!("  This installs Slate on this computer: on a whole disk, or beside");
    println!("  the systems a disk has.");
    println!();
    println!("  Disks:");
    for (i, d) in list.iter().enumerate() {
        println!("    {}) {}", i + 1, d.describe());
    }
    println!();
    println!("  (Type 'shell' for a command line, 'try' to try SlateOS as the live user,");
    println!("  'r' to look for disks again.)");
    println!();
    let answer = ask("  Install on which disk? [1]: ");
    match answer.as_str() {
        "shell" => {
            shell();
            None
        }
        // Trying SlateOS without a display: a shell as the live user
        // (ADR 0118's addendum); the installer comes back when it ends.
        "try" if fs::exists(b"/etc/slate/live") => {
            let _ = live_login("slate-install");
            take_console();
            None
        }
        "r" => None,
        "" => list.first().cloned(),
        n => n.parse::<usize>().ok().and_then(|i| list.get(i.wrapping_sub(1))).cloned(),
    }
}

/// A disk's partitions and free spaces, numbered as they are named
/// (`sda3`), the free spaces lettered: one line each.
pub fn map_lines(map: &engine::DiskMap) -> Vec<String> {
    let mut letter = b'a';
    map.rows()
        .into_iter()
        .map(|r| match r {
            engine::Row::Part(p) => format!("{:>4}  {:<36} {:>9}", p.number, p.describe(), gui::human_size(p.bytes())),
            engine::Row::Free(_, n) => {
                let l = letter as char;
                letter += 1;
                format!("{l:>4}) {:<35} {:>9}", "Free space", gui::human_size(n * engine::SECTOR))
            }
        })
        .collect()
}

/// Confirm erasing the whole disk.
fn confirm_erase(disk: &Disk) -> bool {
    header();
    println!("  Everything on this disk will be erased:");
    println!();
    println!("    {}", disk.describe());
    println!();
    ask("  Type 'erase' to continue, or press Enter to go back: ") == "erase"
}

/// Where on `disk` SlateOS goes (ADR 0116): beside what it holds, over
/// all of it, or where the person says; None to go back.
fn choose_placement(disk: &Disk) -> Option<Placement> {
    let Some(map) = disk_map(disk).ok().filter(|m| !m.parts.is_empty()) else {
        return confirm_erase(disk).then_some(Placement::Whole);
    };
    header();
    println!("  {} holds:", disk.name);
    println!();
    for l in map_lines(&map) {
        println!("  {l}");
    }
    println!();
    let uefi = can_go_beside();
    let gpt = matches!(map.table, engine::Table::Gpt(_));
    let free = map.largest_free().map_or(0, |f| f.1 * engine::SECTOR);
    let mut ways: Vec<(&str, String)> = Vec::new();
    if uefi && map.room_beside() {
        ways.push(("beside", format!("Install beside them, in the free space ({})", gui::human_size(free))));
    }
    ways.push(("erase", String::from("Erase the whole disk")));
    if uefi && gpt {
        ways.push(("manual", String::from("Choose partitions yourself")));
    }
    if !uefi {
        println!("  (Installing beside them needs UEFI firmware: this computer started");
        println!("  the installer in BIOS mode.)");
        println!();
    } else if !gpt {
        println!("  (SlateOS goes beside other systems only on GPT disks.)");
        println!();
    } else if !map.room_beside() {
        println!("  (There is not enough free space for SlateOS beside them: it needs");
        println!("  2.1 GB, or 2.7 GB with an EFI System Partition of its own.)");
        println!();
    }
    for (i, (_, w)) in ways.iter().enumerate() {
        println!("    {}) {w}", i + 1);
    }
    println!();
    let answer = ask("  How should SlateOS be installed? [1]: ");
    let way = match answer.as_str() {
        "" => ways.first(),
        n => n.parse::<usize>().ok().and_then(|i| ways.get(i.wrapping_sub(1))),
    }?;
    match way.0 {
        "beside" => Some(Placement::Beside { delete: Vec::new(), region: None, size: None }),
        "erase" => confirm_erase(disk).then_some(Placement::Whole),
        _ => choose_partitions(disk, &map),
    }
}

/// Manual partitioning (ADR 0116): partitions to delete, the free space
/// for SlateOS and its size; None to go back.
fn choose_partitions(disk: &Disk, map: &engine::DiskMap) -> Option<Placement> {
    let mut delete: Vec<u32> = Vec::new();
    loop {
        let m = map.without(&delete);
        header();
        println!("  {} after the changes:", disk.name);
        println!();
        for l in map_lines(&m) {
            println!("  {l}");
        }
        println!();
        if !delete.is_empty() {
            let gone: Vec<String> = delete.iter().map(|n| format!("{n}")).collect();
            println!("  To be deleted: {}.", gone.join(", "));
            println!();
        }
        println!("  Type a partition's number to delete it, a free space's letter to");
        println!("  install SlateOS there, 'undo' to keep every partition, or press");
        println!("  Enter to go back.");
        println!();
        let a = ask("  > ");
        if a.is_empty() {
            return None;
        }
        if a == "undo" {
            delete.clear();
            continue;
        }
        if let Ok(n) = a.parse::<u32>() {
            if m.parts.iter().any(|p| p.number == n) {
                delete.push(n);
            } else {
                pause(&format!("There is no partition {n}."));
            }
            continue;
        }
        let free = a.bytes().next().filter(|_| a.len() == 1).and_then(|c| c.checked_sub(b'a')).map(usize::from);
        let Some(&(first, n)) = free.and_then(|i| m.free.get(i)) else {
            pause(&format!("{a:?} is neither a partition nor a free space."));
            continue;
        };
        let all = gui::human_size(n * engine::SECTOR);
        let size = ask(&format!("  How much for SlateOS, in GB? [all of it, {all}]: "));
        let size = match size.as_str() {
            "" => None,
            s => match s.trim_end_matches("GB").trim().parse::<f64>() {
                Ok(gb) if gb > 0.0 => Some((gb * 1e9) as u64),
                _ => {
                    pause("That is not a size in GB.");
                    continue;
                }
            },
        };
        if let Err(e) = engine::plan_beside(&m, first, size, &[0; 64]) {
            pause(&format!("That does not work: {e}."));
            continue;
        }
        if !delete.is_empty() {
            println!();
            println!("  Everything on the partitions to be deleted is lost.");
            if ask("  Type 'delete' to continue, or press Enter to go back: ") != "delete" {
                continue;
            }
        }
        return Some(Placement::Beside { delete, region: Some(first), size });
    }
}

/// The zone names the system knows (`slate_rt::tz::ZONES`), sorted, UTC
/// first.
pub fn zone_names() -> Vec<String> {
    let table = fs::read_file(slate_rt::tz::ZONES).unwrap_or_default();
    let mut names: Vec<String> =
        lossy(&table).lines().filter_map(|l| l.split_whitespace().next()).map(String::from).collect();
    names.sort();
    names.dedup();
    names.retain(|n| n != "UTC");
    names.insert(0, String::from("UTC"));
    names
}

/// The keyboard layout (ADR 0117), from a numbered list; the console
/// takes it at once, so the password is typed as it will be at login.
fn ask_keyboard() -> String {
    header();
    println!("  Keyboard layouts:");
    println!();
    let all: Vec<slate_term::keymap::Layout> = slate_term::keymap::Layout::all().collect();
    for (i, l) in all.iter().enumerate() {
        println!("    {:>2}) {:<38} {}", i + 1, l.description(), l.name());
    }
    println!();
    loop {
        let a = ask("  Which layout? [1]: ");
        let chosen = match a.as_str() {
            "" => all.first(),
            n => n
                .parse::<usize>()
                .ok()
                .and_then(|i| all.get(i.wrapping_sub(1)))
                .or_else(|| all.iter().find(|l| l.name() == n)),
        };
        if let Some(l) = chosen {
            let _ = fs::write_file(b"/proc/sys/slate/keyboard", l.name().as_bytes(), 0o644);
            return String::from(l.name());
        }
        println!("  {a:?} is not one of them.");
    }
}

/// The time zone (ADR 0117): a zone's name, or part of one or of a
/// country's name to look for. Enter takes the guess (ADR 0151): the
/// network's zone, else the keyboard's country's, else UTC.
fn ask_timezone(keyboard: &str) -> String {
    header();
    let names = zone_names();
    let countries = region::Countries::load();
    let guess = region::guess(region::network_zone().as_deref(), Some(keyboard), &countries, &names)
        .unwrap_or_else(|| String::from("UTC"));
    println!("  The time zone sets the clock to local time. Type the name of a city,");
    println!("  a country or a region (like Berlin, Brazil or America/Chicago), or");
    println!("  press Enter for {guess}.");
    println!();
    loop {
        let a = ask(&format!("  Time zone [{guess}]: "));
        if a.is_empty() {
            return guess;
        }
        let found = gui::zone_matches(&names, &countries, &a);
        match found.as_slice() {
            [one] => return names[*one].clone(),
            _ if names.iter().any(|n| n.eq_ignore_ascii_case(&a)) => {
                return names.iter().find(|n| n.eq_ignore_ascii_case(&a)).cloned().unwrap_or_default();
            }
            [] => println!("  No time zone has {a:?} in its name."),
            many => {
                println!("  Those with {a:?} in their names:");
                for i in many.iter().take(12) {
                    let country = countries.code(&names[*i]).and_then(|c| countries.name(c)).unwrap_or("");
                    println!("    {:<32} {country}", names[*i]);
                }
                if many.len() > 12 {
                    println!("    ... and {} more", many.len() - 12);
                }
                println!("  Type one of them.");
            }
        }
    }
}

/// The network (ADR 0054): DHCP, or a fixed address for every card,
/// checked as the graphical installer checks it (`gui::network_card`).
fn ask_network() -> Option<slate_netconf::Card> {
    header();
    println!("  SlateOS sets up the network by itself (DHCP), as most networks");
    println!("  expect. You can give a fixed address instead; 'slate-network'");
    println!("  changes this later.");
    println!();
    if !matches!(ask("  Use a fixed address? [y/N]: ").to_ascii_lowercase().as_str(), "y" | "yes") {
        return None;
    }
    loop {
        let address = ask("  Address and prefix length (like 192.168.1.20/24): ");
        let gateway = ask("  Gateway (Enter for none): ");
        let dns = ask("  Name servers, spaces between (Enter for none): ");
        match gui::network_card(&address, &gateway, &dns) {
            Ok(c) => return Some(c),
            Err(e) => {
                println!();
                for p in [e.address, e.gateway, e.dns].iter().flatten() {
                    println!("  {p}");
                }
                println!("  Please try again.");
                println!();
            }
        }
    }
}

/// Ask for the first account and the computer's name, as the graphical
/// installer does (the same rules, `gui::validate_account`).
fn ask_account() -> Choices {
    header();
    println!("  Create your account. Slate has no root password: you approve");
    println!("  system changes with your own (su asks for it).");
    println!();
    loop {
        let name = ask("  Your name: ");
        let suggested = gui::suggest_username(&name);
        let mut username = ask(&format!("  Username [{suggested}]: "));
        if username.is_empty() {
            username = suggested.clone();
        }
        let host_default = gui::suggest_hostname(&username);
        let mut hostname = ask(&format!("  Computer name [{host_default}]: "));
        if hostname.is_empty() {
            hostname = host_default;
        }
        print!("  Password: ");
        io::flush_stdout();
        let a = read_line(true).unwrap_or_default();
        print!("  Again:    ");
        io::flush_stdout();
        let b = read_line(true).unwrap_or_default();
        let (pa, pb) = (String::from(lossy(&a)), String::from(lossy(&b)));
        let e = gui::validate_account(&name, &username, &hostname, &pa, &pb);
        let problems = [e.name, e.username, e.hostname, e.password, e.confirm];
        if problems.iter().all(Option::is_none) {
            return Choices {
                account: Some(NewAccount { username, full_name: String::from(name.trim()), password: a }),
                hostname: Some(hostname),
                ..Choices::default()
            };
        }
        println!();
        for p in problems.iter().flatten() {
            println!("  {p}");
        }
        println!("  Please try again.");
        println!();
    }
}

fn interactive() -> i32 {
    loop {
        header();
        let mut list = disks();
        // Disks on USB may still be appearing just after boot.
        for _ in 0..30 {
            if !list.is_empty() {
                break;
            }
            slate_rt::time::sleep_ns(200_000_000);
            list = disks();
        }
        if list.is_empty() {
            println!("  No disk to install on was found (it needs 2 GB or more).");
            println!("  SATA (AHCI), NVMe and USB disks are supported.");
            println!();
            if ask("  Press Enter to look again, or type 'shell': ") == "shell" {
                shell();
            }
            continue;
        }
        let Some(disk) = choose_disk(&list) else { continue };
        let Some(placement) = choose_placement(&disk) else { continue };
        let keyboard = ask_keyboard();
        let timezone = ask_timezone(&keyboard);
        let account = ask_account();
        header();
        println!("  Encrypt the disk? Your password will be asked every time the");
        println!("  computer starts, and nobody can read the disk without it.");
        println!();
        let encrypt = !matches!(ask("  Encrypt the disk? [Y/n]: ").to_ascii_lowercase().as_str(), "n" | "no");
        header();
        println!("  Strata is SlateOS's own desktop: tiled windows, a terminal and a");
        println!("  launcher. Without it, you log in on a text console.");
        println!();
        let desktop = !matches!(ask("  Install the Strata desktop? [Y/n]: ").to_ascii_lowercase().as_str(), "n" | "no");
        header();
        println!("  Slate runs its own programs. Linux compatibility mode also lets");
        println!("  Linux programs run, in a separate domain. You can change this");
        println!("  later with 'slate-compat on' or 'slate-compat off'.");
        println!();
        let linux_compat =
            matches!(ask("  Turn on Linux compatibility mode? [y/N]: ").to_ascii_lowercase().as_str(), "y" | "yes");
        let full_graphics = ask_graphics();
        let network = ask_network();
        header();
        println!("  Installing Slate on {}.", disk.name);
        println!();
        let choices = Choices {
            linux_compat,
            encrypt,
            desktop,
            full_graphics,
            network,
            keyboard: Some(keyboard),
            timezone: Some(timezone),
            locale: Some("en_US.UTF-8".into()),
            placement,
            ..account
        };
        match run_install(&disk, &choices) {
            Ok(()) => {
                println!();
                println!("  Slate is installed.");
                println!();
                let _ = ask("  Remove the USB stick, then press Enter to restart. ");
                fs::sync();
                let e = process::reboot(process::RB_AUTOBOOT);
                println!("  Restarting failed ({e}); turn the computer off and on.");
                loop {
                    slate_rt::time::sleep_ns(1_000_000_000);
                }
            }
            Err(e) => {
                println!();
                println!();
                println!("  The installation failed: {e}");
                println!("  The kernel log has more (type 'shell', then 'dmesg').");
                pause("Nothing was installed completely.");
            }
        }
    }
}

/// Full graphics (ADR 0173), asked only with an AMD card the driver has
/// and AMD's firmware on the medium; the notice first, no by default.
fn ask_graphics() -> bool {
    use slate_display::graphics;
    if graphics::amd_cards() == 0 || !graphics::available() {
        return false;
    }
    header();
    println!("  {}", graphics::TITLE);
    println!();
    for line in wrap(graphics::NOTICE, 66) {
        println!("  {line}");
    }
    println!();
    println!("  If full graphics doesn't work, SlateOS goes back to its own by itself.");
    println!();
    matches!(ask("  Use full graphics? [y/N]: ").to_ascii_lowercase().as_str(), "y" | "yes")
}

/// `text` in lines of at most `width` characters, broken at spaces.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        match lines.last_mut() {
            Some(l) if l.len() + 1 + word.len() <= width => {
                l.push(' ');
                l.push_str(word);
            }
            _ => lines.push(String::from(word)),
        }
    }
    lines
}

/// The first account.
#[derive(Clone, Debug, Default)]
pub struct NewAccount {
    pub username: String,
    pub full_name: String,
    pub password: Vec<u8>,
}

/// Everything an install is told: the answers, and what an unattended
/// install may add (kernel arguments, `--cmdline`; root's SSH keys,
/// `--authorized-keys`).
#[derive(Clone, Debug, Default)]
pub struct Choices {
    /// None locks root (ADR 0035).
    pub root_password: Option<Vec<u8>>,
    pub account: Option<NewAccount>,
    pub hostname: Option<String>,
    pub locale: Option<String>,
    pub keyboard: Option<String>,
    /// The time zone's name (ADR 0117); None: UTC.
    pub timezone: Option<String>,
    pub linux_compat: bool,
    /// Encrypt the root with the account's password (or root's, without
    /// an account) (ADR 0036).
    pub encrypt: bool,
    /// Install the Strata desktop (ADR 0037).
    pub desktop: bool,
    /// Full graphics: AMD's firmware from the medium (ADR 0173).
    pub full_graphics: bool,
    pub cmdline: String,
    pub keys: Option<Vec<u8>>,
    /// The network settings (ADR 0054); None: DHCP.
    pub network: Option<slate_netconf::Card>,
    /// The whole disk, or beside what it keeps (ADR 0116).
    pub placement: Placement,
}

/// Where on the disk SlateOS goes (ADR 0116).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Placement {
    /// The whole disk, erased.
    #[default]
    Whole,
    /// Beside the partitions the disk keeps: after deleting `delete`
    /// (their numbers), in the free space starting at sector `region`
    /// (None: the largest), with a root of `size` bytes (None: all of it).
    Beside { delete: Vec<u32>, region: Option<u64>, size: Option<u64> },
}

/// `--update-boot --efi FILE [--bios-hdd FILE [--bios-sys FILE]]`: put a
/// new bootloader on the disk that holds the running root, in place (and
/// its BIOS stages, on disks with a BIOS boot partition; `--bios-sys` is
/// Limine's stage 3). Kernels are not
/// this: each system carries its own, and `slate-update` puts them on the
/// boot partition (ADR 0086).
fn update_boot(efi: &str, bios: Option<(String, Option<String>)>) -> i32 {
    let run = || -> Result<String, String> {
        let read = |p: &str| fs::read_file(p.as_bytes()).map_err(|e| format!("{p}: {e}"));
        let efi = read(efi)?;
        let bios = match &bios {
            Some((hdd, sys)) => Some((read(hdd)?, sys.as_deref().map(read).transpose()?)),
            None => None,
        };
        let cmdline = String::from(lossy(&read("/proc/cmdline")?).trim());
        let root = String::from(
            cmdline
                .split_whitespace()
                .find_map(|w| w.strip_prefix("root=PARTUUID="))
                .ok_or("the running system was not booted with root=PARTUUID=")?,
        );
        let bios = bios.as_ref().map(|(hdd, sys)| engine::BiosBoot { hdd, sys: sys.as_deref() });
        let payload = Payload { system: &[], kernel: &[], efi: &efi, bios };
        let (secs, nanos) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
        let mut names: Vec<String> =
            fs::read_dir(b"/sys/block").unwrap_or_default().into_iter().map(|e| String::from(lossy(&e.name))).collect();
        names.sort();
        for name in names {
            let path = format!("/dev/{name}");
            let Ok(fd) = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0) else { continue };
            let mut dev = BlockDev { fd };
            let holds_root = engine::partitions(&mut dev)
                .is_ok_and(|ps| ps.iter().any(|p| engine::guid_text(p.1).eq_ignore_ascii_case(&root)));
            let r = holds_root.then(|| engine::update_boot(&mut dev, &root, &payload, (secs, nanos as u32)));
            let _ = io::close(fd);
            if let Some(r) = r {
                return r.map(|()| name).map_err(|e| e.0);
            }
        }
        Err(format!("no disk holds the root partition {root}"))
    };
    match run() {
        Ok(disk) => {
            println!("slate-install: updated the boot partition on {disk}");
            0
        }
        Err(e) => {
            slate_rt::eprintln!("slate-install: {e}");
            1
        }
    }
}

/// `--disk NAME --password-file FILE --yes`: install without questions.
fn unattended(name: &str, password_file: &str, extra: &Choices, medium: bool) -> i32 {
    let Some(disk) = disks_with(medium).into_iter().find(|d| d.name == name) else {
        slate_rt::eprintln!("slate-install: no usable disk {name}");
        return 1;
    };
    let pw = match fs::read_file(password_file.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            slate_rt::eprintln!("slate-install: {password_file}: {e}");
            return 1;
        }
    };
    let pw: Vec<u8> = pw.into_iter().take_while(|&c| c != b'\n').collect();
    let c = Choices { root_password: Some(pw), ..extra.clone() };
    match run_install(&disk, &c) {
        Ok(()) => {
            println!("slate-install: installed on {name}");
            0
        }
        Err(e) => {
            slate_rt::eprintln!("slate-install: {e}");
            1
        }
    }
}

/// The live system's user (M27, "Try SlateOS"): no password, not root,
/// in the seat group so seatd gives it the screen and input.
pub const LIVE_USER: &str = "live";

/// The account files with the live user added, and its UID.
#[derive(Debug)]
pub struct LiveFiles {
    pub passwd: Vec<u8>,
    pub group: Vec<u8>,
    pub shadow: Vec<u8>,
    pub uid: u32,
}

/// The account files with the live user added (passwd(5), group(5),
/// shadow(5)): None when it is there already.
pub fn with_live_user(passwd: &[u8], group: &[u8], shadow: &[u8], days: i64) -> Option<LiveFiles> {
    let has = String::from_utf8_lossy(passwd).lines().any(|l| l.split(':').next() == Some(LIVE_USER));
    if has {
        return None;
    }
    let uid = engine::next_uid(passwd);
    let a = engine::Account { username: LIVE_USER.into(), full_name: "Live session".into(), hash: String::new() };
    let passwd = engine::add_passwd(passwd, &a, uid);
    let mut g = String::new();
    for line in String::from_utf8_lossy(group).lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        match f[..] {
            ["seat", pw, gid, members] => {
                let m = if members.is_empty() { String::from(LIVE_USER) } else { format!("{members},{LIVE_USER}") };
                g += &format!("seat:{pw}:{gid}:{m}\n");
            }
            _ => g += &format!("{line}\n"),
        }
    }
    g += &format!("{LIVE_USER}:x:{uid}:\n");
    let shadow = engine::add_shadow(shadow, LIVE_USER, "", days);
    Some(LiveFiles { passwd, group: g.into_bytes(), shadow, uid })
}

/// Make the live user on the running (live) system, with its home.
pub fn add_live_user() -> Result<(), String> {
    let read = |p: &str| fs::read_file(p.as_bytes()).map_err(|e| format!("{p}: {e}"));
    let (secs, _) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
    let Some(LiveFiles { passwd, group, shadow, uid }) =
        with_live_user(&read("/etc/passwd")?, &read("/etc/group")?, &read("/etc/shadow")?, secs / 86400)
    else {
        return Ok(());
    };
    let write = |p: &str, d: &[u8], mode: u32| fs::write_file(p.as_bytes(), d, mode).map_err(|e| format!("{p}: {e}"));
    write("/etc/passwd", &passwd, 0o644)?;
    write("/etc/group", &group, 0o644)?;
    write("/etc/shadow", &shadow, 0o600)?;
    let home = format!("/home/{LIVE_USER}");
    let _ = fs::mkdir(b"/home", 0o755);
    let _ = fs::mkdir(home.as_bytes(), 0o700);
    fs::chown(home.as_bytes(), uid, uid).map_err(|e| format!("{home}: {e}"))?;
    // The live system is in memory: its user administers it, approving
    // system actions without a password (ADR 0118's addendum). First in
    // the policy, before `su * *` (the first match decides).
    let policy = fs::read_file(b"/etc/slate/broker.conf").unwrap_or_default();
    let lines = live_policy(&policy);
    write("/etc/slate/broker.conf", &lines, 0o644)
}

/// The policy with the live user's lines first (once).
pub fn live_policy(policy: &[u8]) -> Vec<u8> {
    let head = format!(
        "# The live session (ADR 0118's addendum): its user administers this\n\
         # system, which runs from memory.\n\
         su {LIVE_USER} root nopassword\n\
         run {LIVE_USER} *:* nopassword\n\n"
    );
    if policy.starts_with(head.as_bytes()) {
        return policy.to_vec();
    }
    [head.as_bytes(), policy].concat()
}

// --- Keeping the live session's files (ADR 0118's addendum) ---------------

/// Where the live session's files go on the stick, in its FAT partition.
const KEPT: &str = "LIVE/HOME.TGZ";

/// Whether the person chose to keep the live session's files on the
/// stick (the boot menu's entry, `slate.live.keep`).
pub fn keep_wanted() -> bool {
    let cmdline = fs::read_file(b"/proc/cmdline").unwrap_or_default();
    lossy(&cmdline).split_ascii_whitespace().any(|w| w == "slate.live.keep")
}

/// The install stick's FAT partition, as sectors of one block device.
struct StickPart {
    fd: i32,
    base: u64,
    sectors: u64,
    name: String,
}

impl Drop for StickPart {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

impl slate_fat::edit::Disk for StickPart {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> core::result::Result<(), slate_fat::Error> {
        if sector >= self.sectors {
            return Err(slate_fat::Error::Io);
        }
        match io::pread(self.fd, buf, (self.base + sector) * 512) {
            Ok(512) => Ok(()),
            r => {
                slate_rt::eprintln!("slate-install: reading /dev/{} at sector {sector}: {r:?}", self.name);
                Err(slate_fat::Error::Io)
            }
        }
    }
    fn write(&mut self, sector: u64, data: &[u8; 512]) -> core::result::Result<(), slate_fat::Error> {
        if sector >= self.sectors {
            return Err(slate_fat::Error::Io);
        }
        match io::pwrite(self.fd, data, (self.base + sector) * 512) {
            Ok(512) => Ok(()),
            r => {
                slate_rt::eprintln!("slate-install: writing /dev/{} at sector {sector}: {r:?}", self.name);
                Err(slate_fat::Error::Io)
            }
        }
    }
    fn flush(&mut self) -> core::result::Result<(), slate_fat::Error> {
        fs::fsync(self.fd).map_err(|_| slate_fat::Error::Io)
    }
}

/// The install stick's FAT partition (the one labelled SLATE-LIVE).
fn stick() -> Result<StickPart, String> {
    let mut names: Vec<String> =
        fs::read_dir(b"/sys/block").unwrap_or_default().into_iter().map(|e| String::from(lossy(&e.name))).collect();
    names.sort();
    for name in names {
        let Ok(fd) = fs::open(format!("/dev/{name}").as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0) else { continue };
        let mut mbr = [0u8; 512];
        if io::pread(fd, &mut mbr, 0) == Ok(512) && mbr[510..512] == [0x55, 0xAA] {
            for i in 0..4 {
                let e = &mbr[446 + 16 * i..462 + 16 * i];
                let first = u64::from(u32::from_le_bytes([e[8], e[9], e[10], e[11]]));
                let sectors = u64::from(u32::from_le_bytes([e[12], e[13], e[14], e[15]]));
                let mut bs = [0u8; 512];
                if e[4] == 0xEF && io::pread(fd, &mut bs, first * 512) == Ok(512) && &bs[71..82] == b"SLATE-LIVE " {
                    return Ok(StickPart { fd, base: first, sectors, name });
                }
            }
        }
        let _ = io::close(fd);
    }
    Err(String::from("the install stick isn't there (a disc can't keep files)"))
}

/// Run `argv` with `input` on its standard input; its output.
fn run_with(argv: &[&[u8]], input: &[u8]) -> Result<Vec<u8>, String> {
    let (in_r, in_w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("{e}"))?;
    let (out_r, out_w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("{e}"))?;
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.to_vec()).collect();
    let pid = match process::fork() {
        Ok(0) => {
            let _ = process::dup2(in_r, 0);
            let _ = process::dup2(out_w, 1);
            let e = process::execve(&argv[0], &argv, &[b"PATH=/bin:/sbin:/usr/bin:/usr/sbin".to_vec()]);
            slate_rt::eprintln!("{}: {e}", lossy(&argv[0]));
            process::exit_now(127);
        }
        Ok(pid) => pid,
        Err(e) => return Err(format!("{e}")),
    };
    let _ = io::close(in_r);
    let _ = io::close(out_w);
    let _ = io::write_all(in_w, input);
    let _ = io::close(in_w);
    let out = io::read_to_end(out_r).unwrap_or_default();
    let _ = io::close(out_r);
    match process::wait(pid, 0) {
        Ok((_, 0)) => Ok(out),
        Ok((_, st)) => Err(format!("{} ended with {st}", lossy(&argv[0]))),
        Err(e) => Err(format!("{e}")),
    }
}

/// Put the kept files back in the live user's home; their size, or none
/// kept yet.
pub fn restore_live_home() -> Result<Option<usize>, String> {
    let mut fs_ = slate_fat::edit::Fs::open(stick()?).map_err(|e| format!("the stick: {e:?}"))?;
    if !fs_.exists(KEPT) {
        return Ok(None);
    }
    let data = fs_.read(KEPT).map_err(|e| format!("reading {KEPT}: {e:?}"))?;
    let home = format!("/home/{LIVE_USER}");
    run_with(&[b"/bin/tar", b"-xzpf", b"-", b"-C", home.as_bytes()], &data)?;
    Ok(Some(data.len()))
}

/// Keep the live user's home on the stick, in place of what was kept.
pub fn save_live_home() -> Result<usize, String> {
    let home = format!("/home/{LIVE_USER}");
    let data = run_with(&[b"/bin/tar", b"-czf", b"-", b"-C", home.as_bytes(), b"."], b"")?;
    let mut fs_ = slate_fat::edit::Fs::open(stick()?).map_err(|e| format!("the stick: {e:?}"))?;
    if !fs_.exists("LIVE") {
        fs_.mkdir("LIVE").map_err(|e| format!("the stick: {e:?}"))?;
    }
    let old = if fs_.exists(KEPT) { fs_.size(KEPT).unwrap_or(0) } else { 0 };
    if data.len() as u64 > fs_.free_bytes() + old {
        return Err(format!("the files ({} KiB) don't fit on the stick", data.len() / 1024));
    }
    fs_.write(KEPT, &data).map_err(|e| format!("writing {KEPT}: {e:?}"))?;
    let mut disk = fs_.into_disk();
    let _ = slate_fat::edit::Disk::flush(&mut disk);
    let _ = io::close(disk.fd);
    Ok(data.len())
}

/// Log in as the live user on the console, in this process's place, or
/// (keeping files) as a child, with the kept files put back first and
/// saved after. The installer comes back when it returns.
pub fn live_login(tag: &str) -> i32 {
    if let Err(e) = add_live_user() {
        slate_rt::eprintln!("{tag}: the live user: {e}");
        return 1;
    }
    slate_rt::eprintln!("{tag}: trying SlateOS as {LIVE_USER}");
    if !keep_wanted() {
        let argv = [b"/bin/login".to_vec(), b"-f".to_vec(), LIVE_USER.as_bytes().to_vec()];
        let e = process::execve(b"/bin/login", &argv, &[]);
        slate_rt::eprintln!("{tag}: /bin/login: {e}");
        return 1;
    }
    match restore_live_home() {
        Ok(Some(n)) => slate_rt::eprintln!("{tag}: the live session's files restored from the stick ({n} bytes)"),
        Ok(None) => slate_rt::eprintln!("{tag}: no live session's files on the stick yet"),
        Err(e) => slate_rt::eprintln!("{tag}: the live session's files: {e}"),
    }
    match process::fork() {
        Ok(0) => {
            let argv = [b"/bin/login".to_vec(), b"-f".to_vec(), LIVE_USER.as_bytes().to_vec()];
            let e = process::execve(b"/bin/login", &argv, &[]);
            slate_rt::eprintln!("{tag}: /bin/login: {e}");
            process::exit_now(1);
        }
        Ok(pid) => {
            let _ = process::wait(pid, 0);
        }
        Err(e) => {
            slate_rt::eprintln!("{tag}: {e}");
            return 1;
        }
    }
    take_console();
    match save_live_home() {
        Ok(n) => slate_rt::eprintln!("{tag}: the live session's files kept on the stick ({n} bytes)"),
        Err(e) => slate_rt::eprintln!("{tag}: the live session's files were not kept: {e}"),
    }
    0
}

/// On the live system the installer owns the console.
pub fn take_console() {
    if let Ok(fd) = fs::open(b"/dev/console", fs::O_RDWR, 0) {
        for n in 0..3 {
            let _ = process::dup2(fd, n);
        }
        if fd > 2 {
            let _ = io::close(fd);
        }
        let _ = term::set_controlling(0);
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let mut disk = None;
    let mut password_file = None;
    let mut yes = false;
    let mut live = false;
    let mut update = false;
    let mut medium = false;
    let (mut efi, mut bios_hdd, mut bios_sys) = (None, None, None);
    let mut extra = Choices::default();
    let (mut beside, mut delete, mut root_size) = (false, Vec::new(), None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--disk" => disk = it.next().cloned(),
            "--password-file" => password_file = it.next().cloned(),
            "--yes" => yes = true,
            // Install on the medium the live system started from (ADR 0085:
            // The reference PC has one drive for Slate).
            "--overwrite-medium" => medium = true,
            "--live" => live = true,
            "--update-boot" => update = true,
            "--efi" => efi = it.next().cloned(),
            "--bios-hdd" => bios_hdd = it.next().cloned(),
            "--bios-sys" => bios_sys = it.next().cloned(),
            "--cmdline" => extra.cmdline = it.next().cloned().unwrap_or_default(),
            "--linux-compat" => extra.linux_compat = true,
            "--full-graphics" => extra.full_graphics = true,
            // Beside what the disk has (ADR 0116): in its largest free
            // space, after deleting partitions `--delete N`, the root
            // `--root-size N` GiB.
            "--beside" => beside = true,
            // The layout and the time zone by name (ADR 0117).
            "--keyboard" => {
                let k = it.next().cloned().unwrap_or_default();
                if slate_term::keymap::Layout::by_name(&k).is_none() {
                    slate_rt::eprintln!("slate-install: --keyboard: no layout {k:?}");
                    return 2;
                }
                extra.keyboard = Some(k);
            }
            "--timezone" => {
                let z = it.next().cloned().unwrap_or_default();
                if !zone_names().contains(&z) {
                    slate_rt::eprintln!("slate-install: --timezone: no time zone {z:?}");
                    return 2;
                }
                extra.timezone = Some(z);
            }
            "--delete" => match it.next().and_then(|n| n.parse::<u32>().ok()) {
                Some(n) => delete.push(n),
                None => {
                    slate_rt::eprintln!("slate-install: --delete takes a partition's number");
                    return 2;
                }
            },
            "--root-size" => match it.next().and_then(|n| n.parse::<u64>().ok()) {
                Some(g) => root_size = Some(g << 30),
                None => {
                    slate_rt::eprintln!("slate-install: --root-size takes GiB");
                    return 2;
                }
            },
            "--map" => {
                let name = it.next().cloned().unwrap_or_default();
                let Some(d) = disks_with(true).into_iter().find(|d| d.name == name) else {
                    slate_rt::eprintln!("slate-install: no usable disk {name}");
                    return 1;
                };
                return match disk_map(&d) {
                    Ok(m) => {
                        map_lines(&m).iter().for_each(|l| println!("{l}"));
                        0
                    }
                    Err(e) => {
                        slate_rt::eprintln!("slate-install: {e}");
                        1
                    }
                };
            }
            // `--network "* static 10.0.2.15/24 gateway 10.0.2.2"` (ADR 0054).
            "--network" => {
                let words = it.next().cloned().unwrap_or_default();
                match slate_netconf::Card::from_words(&words.split_whitespace().collect::<Vec<_>>()) {
                    Ok(c) => extra.network = Some(c),
                    Err(e) => {
                        slate_rt::eprintln!("slate-install: --network: {}", e.0);
                        return 2;
                    }
                }
            }
            "--authorized-keys" => {
                let f = it.next().cloned().unwrap_or_default();
                match fs::read_file(f.as_bytes()) {
                    Ok(k) => extra.keys = Some(k),
                    Err(e) => {
                        slate_rt::eprintln!("slate-install: {f}: {e}");
                        return 1;
                    }
                }
            }
            "--list" => {
                for d in disks() {
                    println!("{}", d.describe());
                }
                return 0;
            }
            _ => {
                slate_rt::eprintln!(
                    "usage: slate-install [--live | --list | --map DISK | --disk NAME --password-file FILE --yes \
                     [--overwrite-medium] [--beside [--delete N]... [--root-size GIB]] [--keyboard L] [--timezone Z] \
                     [--linux-compat] [--full-graphics] [--network WORDS]]"
                );
                return 2;
            }
        }
    }
    if update {
        return match efi {
            Some(e) => update_boot(&e, bios_hdd.map(|h| (h, bios_sys))),
            None => {
                slate_rt::eprintln!(
                    "slate-install: --update-boot needs --efi FILE (kernels follow the systems: slate-update)"
                );
                2
            }
        };
    }
    if beside || !delete.is_empty() || root_size.is_some() {
        extra.placement = Placement::Beside { delete, region: None, size: root_size };
    }
    if live {
        take_console();
    }
    match (disk, password_file, yes) {
        (Some(d), Some(p), true) => unattended(&d, &p, &extra, medium),
        (None, None, false) => interactive(),
        _ => {
            slate_rt::eprintln!("slate-install: --disk, --password-file and --yes go together");
            2
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// The live user (M27): added once, in seat, not in wheel, no password.
    #[test]
    fn the_live_user() {
        let passwd = b"root:x:0:0:root:/root:/bin/sh\ngreeter:x:65:65::/:/bin/nologin\n";
        let group = b"root:x:0:\nwheel:x:10:root\nseat:x:64:greeter\ngreeter:x:65:\n";
        let shadow = b"root::20000:0:99999:7:::\n";
        let LiveFiles { passwd: p, group: g, shadow: s, uid } = with_live_user(passwd, group, shadow, 20500).unwrap();
        assert_eq!(uid, 1000);
        assert!(String::from_utf8(p.clone()).unwrap().ends_with("live:x:1000:1000:Live session:/home/live:/bin/sh\n"));
        let g = String::from_utf8(g).unwrap();
        assert!(
            g.contains("seat:x:64:greeter,live\n") && g.contains("wheel:x:10:root\n") && g.ends_with("live:x:1000:\n")
        );
        assert!(String::from_utf8(s).unwrap().ends_with("live::20500:0:99999:7:::\n"));
        assert!(with_live_user(&p, group, shadow, 20500).is_none());
    }

    /// The live user administers the live system: its lines come first,
    /// once.
    #[test]
    fn live_user_policy() {
        let policy = b"su %wheel root ownpassword\nsu * *\n";
        let p = live_policy(policy);
        let text = String::from_utf8(p.clone()).unwrap();
        assert!(text.contains("su live root nopassword\nrun live *:* nopassword\n"));
        assert!(text.find("su live").unwrap() < text.find("su * *").unwrap());
        assert_eq!(live_policy(&p), p, "only once");
    }
}
