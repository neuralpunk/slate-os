// SPDX-License-Identifier: MIT OR Apache-2.0

//! The running root's EFI System Partition, kept in step with the SlateFS
//! boot state (ADR 0086): `slate-update` calls [`sync`] after every change
//! of the boot state and after every boot.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use slate_rt::subvol::{self, Subvol, flagged, running, system_number};
use slate_rt::{fs, io, lossy};

const SECTOR: u64 = 512;
/// Where another system is mounted while its kernel is read.
const OTHER_AT: &str = "/run/slate-update-other";
/// Held while something changes the boot state or the boot partition:
/// two at once (slinit's `boot-ok` and an update) would each change the
/// partition from their own view of it (ADR 0086).
const LOCK: &str = "/run/slate-update.lock";

/// Wait for, and take, the lock: released when the process ends.
pub fn lock() -> Result<(), String> {
    let fd = fs::open(LOCK.as_bytes(), fs::O_RDWR | fs::O_CREAT | fs::O_CLOEXEC, 0o600)
        .map_err(|e| format!("{LOCK}: {e}"))?;
    fs::flock(fd, fs::LOCK_EX).map_err(|e| format!("{LOCK}: {e}"))
}

/// A partition of a disk, as an [`slate_fat::edit::Disk`].
struct Partition {
    fd: i32,
    base: u64,
    sectors: u64,
}

impl slate_fat::edit::Disk for Partition {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), slate_fat::Error> {
        if sector >= self.sectors {
            return Err(slate_fat::Error::Io);
        }
        match io::pread(self.fd, buf, (self.base + sector) * SECTOR) {
            Ok(512) => Ok(()),
            _ => Err(slate_fat::Error::Io),
        }
    }
    fn write(&mut self, sector: u64, data: &[u8; 512]) -> Result<(), slate_fat::Error> {
        if sector >= self.sectors {
            return Err(slate_fat::Error::Io);
        }
        match io::pwrite(self.fd, data, (self.base + sector) * SECTOR) {
            Ok(512) => Ok(()),
            _ => Err(slate_fat::Error::Io),
        }
    }
    fn flush(&mut self) -> Result<(), slate_fat::Error> {
        fs::fsync(self.fd).map_err(|_| slate_fat::Error::Io)
    }
    fn read_run(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), slate_fat::Error> {
        if sector + (buf.len() as u64).div_ceil(SECTOR) > self.sectors {
            return Err(slate_fat::Error::Io);
        }
        // pread(2) may move less than asked (Slate's at most 1 MiB a call).
        let mut done = 0;
        while done < buf.len() {
            match io::pread(self.fd, &mut buf[done..], (self.base + sector) * SECTOR + done as u64) {
                Ok(n) if n > 0 => done += n,
                _ => return Err(slate_fat::Error::Io),
            }
        }
        Ok(())
    }
    fn write_run(&mut self, sector: u64, data: &[u8]) -> Result<(), slate_fat::Error> {
        if sector + (data.len() as u64).div_ceil(SECTOR) > self.sectors {
            return Err(slate_fat::Error::Io);
        }
        let mut done = 0;
        while done < data.len() {
            match io::pwrite(self.fd, &data[done..], (self.base + sector) * SECTOR + done as u64) {
                Ok(n) if n > 0 => done += n,
                _ => return Err(slate_fat::Error::Io),
            }
        }
        Ok(())
    }
}

/// How the kernel was told its root: `root=PARTUUID=` or `root=PARTLABEL=`.
enum Root {
    Uuid(String),
    Label(String),
}

fn root_spec(cmdline: &str) -> Option<Root> {
    cmdline.split_ascii_whitespace().find_map(|w| {
        if let Some(u) = w.strip_prefix("root=PARTUUID=") {
            Some(Root::Uuid(u.to_ascii_lowercase()))
        } else {
            w.strip_prefix("root=PARTLABEL=").map(|l| Root::Label(String::from(l)))
        }
    })
}

/// The used entries of the GPT on `fd`.
fn gpt(fd: i32) -> Option<Vec<slate_gpt::Entry>> {
    let mut header = [0u8; 512];
    if io::pread(fd, &mut header, SECTOR) != Ok(512) {
        return None;
    }
    let h = slate_gpt::parse_header(&header).ok()?;
    let len = h.entry_count as usize * h.entry_size as usize;
    if len > 1 << 20 {
        return None;
    }
    let mut array = vec![0u8; len];
    if io::pread(fd, &mut array, h.entries_lba * SECTOR) != Ok(len) {
        return None;
    }
    Some(slate_gpt::parse_entries(&h, &array).ok()?.collect())
}

fn name_of(e: &slate_gpt::Entry) -> String {
    let end = e.name_utf16.iter().position(|&u| u == 0).unwrap_or(e.name_utf16.len());
    char::decode_utf16(e.name_utf16[..end].iter().copied()).map(|r| r.unwrap_or('?')).collect()
}

/// Whether a menu boots this root: one of its entries names it.
fn names_root(conf: &str, root: &Root) -> bool {
    conf.lines().filter_map(|l| l.trim().strip_prefix("cmdline:")).any(|c| {
        c.split_ascii_whitespace().any(|w| match root {
            Root::Uuid(u) => w.strip_prefix("root=PARTUUID=").is_some_and(|x| x.eq_ignore_ascii_case(u)),
            Root::Label(l) => w.strip_prefix("root=PARTLABEL=") == Some(l.as_str()),
        })
    })
}

/// The EFI System Partition on the disk that holds the root: the disk's
/// name, the open disk and the partition. A disk with another system on
/// it may have more than one (ADR 0116): the root's is the one whose menu
/// boots it.
fn find(root: &Root) -> Option<(String, Partition)> {
    let mut names: Vec<String> =
        fs::read_dir(b"/sys/block").unwrap_or_default().into_iter().map(|e| String::from(lossy(&e.name))).collect();
    names.sort();
    for name in names.into_iter().filter(|n| !n.starts_with("dm-") && !n.starts_with("loop")) {
        let Ok(fd) = fs::open(format!("/dev/{name}").as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0) else { continue };
        let entries = gpt(fd).unwrap_or_default();
        let holds_root = entries.iter().any(|e| match root {
            Root::Uuid(u) => format!("{}", e.unique_guid) == *u,
            Root::Label(l) => name_of(e) == *l,
        });
        let esps: Vec<&slate_gpt::Entry> =
            entries.iter().filter(|e| e.type_guid == slate_gpt::Guid::EFI_SYSTEM).collect();
        if holds_root {
            let part =
                |e: &slate_gpt::Entry| Partition { fd, base: e.first_lba, sectors: e.last_lba + 1 - e.first_lba };
            let ours = esps.iter().find_map(|e| {
                let mut fat = slate_fat::edit::Fs::open(part(e)).ok()?;
                slate_esp::active(&mut fat).is_some_and(|(_, c)| names_root(&c, root)).then(|| fat.into_disk())
            });
            match (ours, esps.as_slice()) {
                (Some(p), _) => return Some((name, p)),
                (None, [only]) => return Some((name, part(only))),
                _ => {}
            }
        }
        let _ = io::close(fd);
    }
    None
}

/// Whether the root is an encrypted (mapped) device.
fn encrypted() -> bool {
    let mounts = String::from(lossy(&fs::read_file(b"/proc/mounts").unwrap_or_default()));
    mounts.lines().any(|l| {
        let mut w = l.split_whitespace();
        matches!((w.next(), w.next()), (Some(src), Some("/")) if src.starts_with("/dev/dm-"))
    })
}

/// A system's boot files read from its tree at `base` ("" for the running
/// one): its kernel (None if it has none) and, for an encrypted root, its
/// unlock archive, checked against the kernel. The unlock screen's fonts
/// come from `fonts` when the system has none of its own.
pub fn boot_files(
    system: &str,
    base: &str,
    encrypted: bool,
    fonts: &[(String, Vec<u8>)],
) -> Result<slate_esp::Boot, String> {
    let get = |p: &str| fs::read_file(format!("{base}/{p}").as_bytes()).ok();
    let kernel = get(slate_esp::SYSTEM_KERNEL);
    let unlock = match (&kernel, encrypted) {
        (Some(k), true) => {
            let program = get(slate_esp::UNLOCK_PROGRAM).ok_or_else(|| format!("{system} has no unlock program"))?;
            slate_esp::check_unlock(k, &program).map_err(|e| format!("{system}: {e}"))?;
            let kept = |p: &str| fonts.iter().find(|(n, _)| n == p).map(|(_, d)| d.clone());
            Some(slate_esp::unlock_archive(&mut |p| get(p).or_else(|| kept(p)))?)
        }
        _ => None,
    };
    Ok(slate_esp::Boot { system: String::from(system), kernel, unlock, source: None, kept: None, full_graphics: false })
}

/// What a system's boot files are made from, without reading them: its
/// subvolume (systems are snapshots, their ids never reused), whether the
/// root is encrypted, and the size and change time of the files they are
/// built from in its tree at `base`. When the boot partition recorded the
/// same, its copies are current.
fn source(id: u64, base: &str, encrypted: bool) -> String {
    let mut files = alloc::vec![slate_esp::SYSTEM_KERNEL];
    if encrypted {
        files.push(slate_esp::UNLOCK_PROGRAM);
        files.extend(slate_esp::UNLOCK_FONTS);
    }
    let stamps: Vec<String> = files
        .iter()
        .map(|p| match fs::stat(format!("{base}/{p}").as_bytes()) {
            Ok(s) => format!("{}.{}.{}", s.size, s.mtime, s.mtime_nsec),
            Err(_) => String::from("-"),
        })
        .collect();
    format!("subvolume={id} encrypted={} files={}", u8::from(encrypted), stamps.join(","))
}

/// What `sync` did, for a line of output.
#[derive(Debug)]
pub struct Done {
    pub disk: String,
    pub report: slate_esp::Report,
}

/// The most older systems the menu lists after the default and the
/// fallback (each takes a kernel's room on the partition).
const MAX_OLDER: usize = 3;

/// Make the root's EFI System Partition boot the boot state's default
/// first and its fallback second, then list up to [`MAX_OLDER`] older
/// systems. None when the running system was not
/// booted from a disk partition (an initramfs, an ext4 root). With
/// `quick`, nothing is read or written when the menu already names the
/// right systems (the check at every boot).
pub fn sync(list: &[Subvol], quick: bool) -> Result<Option<Done>, String> {
    let cmdline = String::from(lossy(&fs::read_file(b"/proc/cmdline").unwrap_or_default()).trim());
    let Some(root) = root_spec(&cmdline) else { return Ok(None) };
    let Some((disk, part)) = find(&root) else { return Ok(None) };
    let default = flagged(list, "default").ok_or("there is no default system")?;
    let fallback = flagged(list, "fallback").filter(|f| *f != default);
    let here = running(list)?;
    let enc = encrypted();
    let mut esp = slate_fat::edit::Fs::open(part).map_err(|e| format!("the boot partition on {disk}: {e:?}"))?;
    // The older systems on the menu too (ADR 0089), newest first.
    let mut older: Vec<(u64, String)> = list
        .iter()
        .filter(|v| v.name != default && Some(&v.name) != fallback.as_ref())
        .filter_map(|v| Some((system_number(&v.name)?, v.name.clone())))
        .collect();
    older.sort_by_key(|o| core::cmp::Reverse(o.0));
    let older: Vec<String> = older.into_iter().take(MAX_OLDER).map(|(_, n)| n).collect();
    let older_names: Vec<&str> = older.iter().map(String::as_str).collect();
    // The default is on trial until it is confirmed: the loader counts
    // its boots (ADR 0089).
    let state = subvol::ctl("/", "boot").unwrap_or_default();
    let trial = state.split_whitespace().any(|w| w == "pending=1").then_some(default.as_str());
    if quick && slate_esp::in_step(&mut esp, &default, fallback.as_deref(), &older_names, trial) {
        let _ = io::close(esp.into_disk().fd);
        return Ok(Some(Done { disk, report: slate_esp::Report::default() }));
    }
    let mut boots = Vec::new();
    for name in core::iter::once(&default).chain(fallback.as_ref()).chain(&older) {
        // The fonts the system's unlock screen has now.
        let fonts = |esp: &mut slate_fat::edit::Fs<Partition>| {
            if enc {
                [name.as_str(), here.as_str()]
                    .iter()
                    .find_map(|n| slate_esp::current_unlock(esp, n))
                    .map(|a| slate_esp::archive_fonts(&a))
                    .unwrap_or_default()
            } else {
                Vec::new()
            }
        };
        let id = list.iter().find(|v| v.name == *name).map_or(0, |v| v.id);
        let mut made = |base: &str| -> Result<slate_esp::Boot, String> {
            // Current on the partition: nothing is read (GAPS: boot-ok read
            // every kernel on every boot).
            let src = source(id, base, enc);
            // Full graphics: AMD's firmware in this system (ADR 0173).
            let full_graphics = fs::exists(format!("{base}/usr/lib/quarry/db/slate-firmware-gpu").as_bytes());
            if let Some(unlock) = slate_esp::current_from(&mut esp, name, &src) {
                let kept = Some(unlock);
                return Ok(slate_esp::Boot {
                    system: name.clone(),
                    kernel: None,
                    unlock: None,
                    source: Some(src),
                    kept,
                    full_graphics,
                });
            }
            let mut b = boot_files(name, base, enc, &fonts(&mut esp))?;
            b.source = Some(src);
            b.full_graphics = full_graphics;
            Ok(b)
        };
        let b = if *name == here {
            made("")
        } else {
            subvol::mount(name, OTHER_AT).and_then(|()| {
                let b = made(OTHER_AT);
                let _ = fs::umount(OTHER_AT.as_bytes());
                b
            })
        };
        // An older system that cannot boot stays off the menu.
        match b {
            Ok(b) => boots.push(b),
            Err(_) if older.contains(name) => {}
            Err(e) => return Err(e),
        }
    }
    let (secs, _) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
    let (date, time) = fat_time(secs);
    esp.set_time(date, time);
    let main = 1 + usize::from(fallback.is_some());
    let fb = if fallback.is_some() { boots.get(1) } else { None };
    let report = slate_esp::sync(&mut esp, &slate_esp::base_cmdline(&cmdline), &boots[0], fb, &boots[main..], trial)?;
    let _ = io::close(esp.into_disk().fd);
    Ok(Some(Done { disk, report }))
}

/// The boot menu's titles, and with `title` make it the one-shot choice
/// for the next boot (ADR 0116): the loader starts it once, at once.
pub fn next(title: Option<&str>) -> Result<Vec<String>, String> {
    let cmdline = String::from(lossy(&fs::read_file(b"/proc/cmdline").unwrap_or_default()).trim());
    let root = root_spec(&cmdline).ok_or("the running system was not booted from a disk partition")?;
    let (disk, part) = find(&root).ok_or("no boot partition boots the running system")?;
    let mut esp = slate_fat::edit::Fs::open(part).map_err(|e| format!("the boot partition on {disk}: {e:?}"))?;
    let titles = slate_esp::active(&mut esp).map(|(_, c)| slate_esp::titles(&c)).unwrap_or_default();
    let r = match title {
        Some(t) if !titles.iter().any(|x| x == t) => Err(format!("the boot menu has no entry {t:?}")),
        Some(t) => {
            esp.write(slate_esp::NEXT, format!("{t}\n").as_bytes()).map_err(|e| format!("{}: {e:?}", slate_esp::NEXT))
        }
        None => Ok(()),
    };
    let _ = io::close(esp.into_disk().fd);
    r.map(|()| titles)
}

/// A FAT date and time (fatgen103 §6.1) for `secs` since 1970, UTC.
fn fat_time(secs: i64) -> (u16, u16) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days (Howard Hinnant's algorithm, public domain).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if !(1980..=2107).contains(&year) {
        return (((2026 - 1980) << 9) | (1 << 5) | 1, 0);
    }
    let date = (((year - 1980) << 9) | (month << 5) | day) as u16;
    let time = (((rem / 3600) << 11) | ((rem / 60 % 60) << 5) | (rem % 60 / 2)) as u16;
    (date, time)
}

/// The line `slate-update` prints after a sync.
pub fn describe(d: &Done) -> String {
    let mut parts = Vec::new();
    if !d.report.written.is_empty() {
        parts.push(format!("wrote {}", d.report.written.join(", ")));
    }
    if !d.report.removed.is_empty() {
        parts.push(format!("removed {}", d.report.removed.join(", ")));
    }
    if d.report.switched {
        parts.push("switched the boot menu".to_string());
    }
    if parts.is_empty() {
        format!("the boot partition on {} is up to date", d.disk)
    } else {
        format!("boot partition on {}: {}", d.disk, parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn fat_times() {
        // 2026-10-23 14:41:30 UTC.
        assert_eq!(super::fat_time(1_792_766_490), ((46 << 9) | (10 << 5) | 23, (14 << 11) | (41 << 5) | 15));
        assert_eq!(super::fat_time(0).0, (46 << 9) | (1 << 5) | 1);
    }
}
