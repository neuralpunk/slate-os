// SPDX-License-Identifier: MIT OR Apache-2.0

//! UEFI boot entries (ADR 0088): the load options in `Boot####` and the
//! order in `BootOrder`, built and read here, and `slate-boot`, which
//! writes them through efivarfs.
//!
//! Sources: the UEFI Specification 2.10: EFI_LOAD_OPTION and the boot
//! manager's variables (§3.1.3, §3.3), the device path node header
//! (§10.3.1), the hard drive media path (§10.3.5.1), the file path media
//! path (§10.3.5.4) and the end node (§10.3.1, table 10-2); the variable
//! attributes (§8.2.1).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_gpt::Guid;
use slate_rt::{eprintln, fs, io, lossy, println};

/// Where efivarfs is mounted.
pub const EFIVARS: &str = "/sys/firmware/efi/efivars";
/// EFI_GLOBAL_VARIABLE (§3.3), in the registry form efivarfs names use.
pub const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS (§8.2.1).
pub const ATTRS: u32 = 7;
/// LOAD_OPTION_ACTIVE (§3.1.3).
pub const ACTIVE: u32 = 1;
/// The description Slate's entry has.
pub const DESCRIPTION: &str = "Slate";
/// The loader on the EFI System Partition (the removable-media path,
/// §3.5.1.1, where the installer puts Limine).
pub const LOADER: &str = "\\EFI\\BOOT\\BOOTX64.EFI";

/// Device path types and subtypes (§10.3.1, §10.3.5).
const MEDIA: u8 = 4;
const HARD_DRIVE: u8 = 1;
const FILE_PATH: u8 = 4;
const END: u8 = 0x7F;
const END_ENTIRE: u8 = 0xFF;
/// The hard drive node's length, partition format (GPT) and signature
/// type (GUID) (§10.3.5.1).
const HD_LEN: usize = 42;
const FORMAT_GPT: u8 = 2;
const SIGNATURE_GUID: u8 = 2;

/// A GPT partition, as the hard drive node names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    /// Its number, from 1.
    pub number: u32,
    pub start: u64,
    /// In logical blocks.
    pub size: u64,
    /// Its unique partition GUID.
    pub guid: Guid,
}

/// A load option, as far as Slate reads them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    /// The first hard drive node of its device path, if it names a GPT
    /// partition.
    pub partition: Option<Partition>,
    /// Or an MBR partition: its number, the disk's 32-bit signature, its
    /// start and size (§10.3.5.1, signature type 1).
    pub mbr: Option<(u32, u32, u64, u64)>,
    /// The first file path node's path.
    pub path: Option<String>,
}

fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

/// A load option for `path` on `part`, active.
pub fn load_option(description: &str, part: &Partition, path: &str) -> Vec<u8> {
    let mut dp = Vec::new();
    dp.extend_from_slice(&[MEDIA, HARD_DRIVE]);
    dp.extend_from_slice(&(HD_LEN as u16).to_le_bytes());
    dp.extend_from_slice(&part.number.to_le_bytes());
    dp.extend_from_slice(&part.start.to_le_bytes());
    dp.extend_from_slice(&part.size.to_le_bytes());
    dp.extend_from_slice(&part.guid.to_bytes());
    dp.extend_from_slice(&[FORMAT_GPT, SIGNATURE_GUID]);
    let file = ucs2(path);
    dp.extend_from_slice(&[MEDIA, FILE_PATH]);
    dp.extend_from_slice(&(4 + file.len() as u16).to_le_bytes());
    dp.extend_from_slice(&file);
    dp.extend_from_slice(&[END, END_ENTIRE, 4, 0]);
    let mut out = Vec::new();
    out.extend_from_slice(&ACTIVE.to_le_bytes());
    out.extend_from_slice(&(dp.len() as u16).to_le_bytes());
    out.extend_from_slice(&ucs2(description));
    out.extend_from_slice(&dp);
    out
}

fn read_ucs2(b: &[u8]) -> (String, usize) {
    let mut units = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let u = u16::from_le_bytes([b[i], b[i + 1]]);
        i += 2;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    (char::decode_utf16(units).map(|c| c.unwrap_or('?')).collect(), i)
}

/// Read a load option; None if it is malformed.
pub fn parse_load_option(b: &[u8]) -> Option<LoadOption> {
    let attributes = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
    let list_len = u16::from_le_bytes(b.get(4..6)?.try_into().ok()?) as usize;
    let (description, n) = read_ucs2(b.get(6..)?);
    let mut dp = b.get(6 + n..6 + n + list_len)?;
    let (mut partition, mut mbr, mut path) = (None, None, None);
    while dp.len() >= 4 {
        let (kind, sub) = (dp[0], dp[1]);
        let len = u16::from_le_bytes([dp[2], dp[3]]) as usize;
        if len < 4 || len > dp.len() {
            return None;
        }
        let node = &dp[4..len];
        match (kind, sub) {
            (END, END_ENTIRE) => break,
            (MEDIA, HARD_DRIVE) if len == HD_LEN && partition.is_none() && mbr.is_none() => {
                let u64_at = |o: usize| u64::from_le_bytes(node[o..o + 8].try_into().unwrap());
                let number = u32::from_le_bytes(node[0..4].try_into().unwrap());
                if node[37] == SIGNATURE_GUID {
                    partition = Some(Partition {
                        number,
                        start: u64_at(4),
                        size: u64_at(12),
                        guid: Guid::from_bytes(node[20..36].try_into().unwrap()),
                    });
                } else {
                    mbr = Some((number, u32::from_le_bytes(node[20..24].try_into().unwrap()), u64_at(4), u64_at(12)));
                }
            }
            (MEDIA, FILE_PATH) if path.is_none() => path = Some(read_ucs2(node).0),
            _ => {}
        }
        dp = &dp[len..];
    }
    Some(LoadOption { attributes, description, partition, mbr, path })
}

/// `BootOrder`'s data: option numbers, u16 each.
pub fn parse_order(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect()
}

pub fn encode_order(order: &[u16]) -> Vec<u8> {
    order.iter().flat_map(|n| n.to_le_bytes()).collect()
}

/// The number for Slate's entry, given the options there are: the first
/// one already described as Slate's, otherwise the lowest number unused.
pub fn pick_number(options: &[(u16, Option<LoadOption>)]) -> Option<u16> {
    if let Some((n, _)) = options.iter().find(|(_, o)| o.as_ref().is_some_and(|o| o.description == DESCRIPTION)) {
        return Some(*n);
    }
    (0..=u16::MAX).find(|n| !options.iter().any(|(m, _)| m == n))
}

/// `order` with `n` first, and nowhere else.
pub fn put_first(order: &[u16], n: u16) -> Vec<u16> {
    core::iter::once(n).chain(order.iter().copied().filter(|&m| m != n)).collect()
}

/// `Boot####`'s number, from an efivarfs file name.
fn option_number(file: &str) -> Option<u16> {
    let hex = file.strip_prefix("Boot")?.strip_suffix(GLOBAL)?.strip_suffix('-')?;
    if hex.len() != 4 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

fn var_path(name: &str) -> String {
    format!("{EFIVARS}/{name}-{GLOBAL}")
}

/// A global variable's data, without its attributes.
fn read_var(name: &str) -> Option<Vec<u8>> {
    let b = fs::read_file(var_path(name).as_bytes()).ok()?;
    (b.len() >= 4).then(|| b[4..].to_vec())
}

/// Set a global variable: the attributes and the data in one write, as
/// efivarfs wants them.
fn write_var(name: &str, data: &[u8]) -> Result<(), String> {
    let mut b = ATTRS.to_le_bytes().to_vec();
    b.extend_from_slice(data);
    fs::write_file(var_path(name).as_bytes(), &b, 0o644).map_err(|e| format!("{name}: {e}"))
}

/// The boot options there are, by number.
pub fn options() -> Result<Vec<(u16, Option<LoadOption>)>, String> {
    let entries = fs::read_dir(EFIVARS.as_bytes()).map_err(|e| format!("{EFIVARS}: {e}"))?;
    let mut out: Vec<(u16, Option<LoadOption>)> = entries
        .iter()
        .filter_map(|e| option_number(&lossy(&e.name)))
        .map(|n| (n, read_var(&format!("Boot{n:04X}")).and_then(|d| parse_load_option(&d))))
        .collect();
    out.sort_by_key(|(n, _)| *n);
    Ok(out)
}

/// Whether the firmware's variables can be written here (a UEFI boot with
/// efivarfs mounted).
pub fn available() -> bool {
    fs::exists(var_path("BootOrder").as_bytes())
        || fs::read_dir(EFIVARS.as_bytes()).is_ok_and(|e| e.iter().any(|e| option_number(&lossy(&e.name)).is_some()))
}

/// Make or update Slate's entry for the loader on `part`, and put it first
/// in `BootOrder`. Returns its number.
pub fn add(part: &Partition) -> Result<u16, String> {
    add_at(part, LOADER)
}

/// [`add`] for the loader at `path` (`\EFI\slate\BOOTX64.EFI` on a
/// partition shared with another system, ADR 0116).
pub fn add_at(part: &Partition, path: &str) -> Result<u16, String> {
    let opts = options()?;
    let n = pick_number(&opts).ok_or("no free boot option number")?;
    write_var(&format!("Boot{n:04X}"), &load_option(DESCRIPTION, part, path))?;
    let order = read_var("BootOrder").map(|d| parse_order(&d)).unwrap_or_default();
    write_var("BootOrder", &encode_order(&put_first(&order, n)))?;
    Ok(n)
}

/// SlateOS's EFI System Partition on the GPT disk `path` (the one that
/// boots the running root, when it is on this disk; ADR 0116), and its
/// loader's path there.
pub fn esp_of(path: &str) -> Result<(Partition, String), String> {
    let fd = fs::open(path.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let cmdline = String::from(lossy(&fs::read_file(b"/proc/cmdline").unwrap_or_default()));
    let root = cmdline.split_whitespace().find_map(|w| w.strip_prefix("root=PARTUUID="));
    let mut dev = crate::BlockDev { fd };
    // The running root's, or else the first with SlateOS's menu.
    let r = crate::engine::find_esp(&mut dev, root).or_else(|_| crate::engine::find_esp(&mut dev, None));
    let _ = io::close(fd);
    let e = r.map_err(|e| format!("{path}: {e}"))?;
    let loader =
        if e.shared { format!("\\{}", crate::engine::SHARED_LOADER.replace('/', "\\")) } else { String::from(LOADER) };
    Ok((Partition { number: e.number, start: e.range.0, size: e.range.1 + 1 - e.range.0, guid: e.guid }, loader))
}

fn describe(o: &LoadOption) -> String {
    let mut s = String::new();
    if let Some(p) = &o.partition {
        s += &format!("HD({},GPT,{},{},{})", p.number, p.guid, p.start, p.size);
    }
    if let Some((n, sig, start, size)) = o.mbr {
        s += &format!("HD({n},MBR,{sig:#010x},{start},{size})");
    }
    if let Some(f) = &o.path {
        s += f;
    }
    s
}

const USAGE: &str = "usage: slate-boot list | add --disk DISK";

/// `slate-boot list` and `slate-boot add --disk DISK`.
pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let r = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["list"] => list(),
        ["add", "--disk", disk] => {
            let path = if disk.starts_with('/') { String::from(*disk) } else { format!("/dev/{disk}") };
            esp_of(&path)
                .and_then(|(p, loader)| add_at(&p, &loader))
                .map(|n| println!("Boot{n:04X}: {DESCRIPTION}, first in BootOrder"))
        }
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    match r {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slate-boot: {e}");
            1
        }
    }
}

fn list() -> Result<(), String> {
    let opts = options()?;
    let numbers = |d: Option<Vec<u8>>| -> String {
        d.map(|d| parse_order(&d).iter().map(|n| format!("{n:04X}")).collect::<Vec<_>>().join(" ")).unwrap_or_default()
    };
    println!("BootCurrent  {}", numbers(read_var("BootCurrent")));
    println!("BootOrder    {}", numbers(read_var("BootOrder")));
    for (n, o) in &opts {
        match o {
            Some(o) => {
                let active = if o.attributes & ACTIVE != 0 { "active" } else { "off" };
                println!("Boot{n:04X}     {active:<6}  {}  {}", o.description, describe(o));
            }
            None => println!("Boot{n:04X}     (unreadable)"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esp() -> Partition {
        Partition { number: 1, start: 2048, size: 1_048_576, guid: Guid::from_seed([7; 16]) }
    }

    /// The layout of §3.1.3 and §10.3.5, byte by byte.
    #[test]
    fn load_option_layout() {
        let b = load_option("Slate", &esp(), LOADER);
        assert_eq!(&b[0..4], &[1, 0, 0, 0]);
        let list_len = u16::from_le_bytes([b[4], b[5]]) as usize;
        // "Slate" and its NUL in UCS-2.
        assert_eq!(&b[6..18], &[b'S', 0, b'l', 0, b'a', 0, b't', 0, b'e', 0, 0, 0]);
        let dp = &b[18..];
        assert_eq!(dp.len(), list_len);
        assert_eq!(&dp[0..4], &[4, 1, 42, 0]);
        assert_eq!(&dp[4..8], &1u32.to_le_bytes());
        assert_eq!(&dp[8..16], &2048u64.to_le_bytes());
        assert_eq!(&dp[16..24], &1_048_576u64.to_le_bytes());
        assert_eq!(&dp[24..40], &esp().guid.to_bytes());
        assert_eq!(&dp[40..42], &[2, 2]);
        let file_len = 4 + 2 * (LOADER.len() + 1);
        assert_eq!(&dp[42..46], &[4, 4, file_len as u8, 0]);
        assert_eq!(&dp[42 + file_len..], &[0x7F, 0xFF, 4, 0]);
    }

    #[test]
    fn load_option_round_trip() {
        let o = parse_load_option(&load_option("Slate", &esp(), LOADER)).unwrap();
        assert_eq!(o.attributes, ACTIVE);
        assert_eq!(o.description, "Slate");
        assert_eq!(o.partition, Some(esp()));
        assert_eq!(o.path.as_deref(), Some(LOADER));
        assert!(parse_load_option(&[1, 0, 0, 0, 200, 0]).is_none());
    }

    /// A firmware entry with only a vendor node: read, without a disk.
    #[test]
    fn foreign_option() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        let dp = [[1u8, 4, 20, 0].as_slice(), &[0; 16], &[0x7F, 0xFF, 4, 0]].concat();
        b.extend_from_slice(&(dp.len() as u16).to_le_bytes());
        b.extend_from_slice(&ucs2("UEFI Shell"));
        b.extend_from_slice(&dp);
        let o = parse_load_option(&b).unwrap();
        assert_eq!((o.description.as_str(), o.partition, o.path), ("UEFI Shell", None, None));
    }

    /// A firmware's entry for a USB stick with an MBR (the reference PC's).
    #[test]
    fn mbr_partitions() {
        let mut b = load_option("UEFI: a stick", &esp(), LOADER);
        let hd = 4 + 2 + 2 * ("UEFI: a stick".len() + 1);
        b[hd + 4 + 20..hd + 4 + 36].fill(0);
        b[hd + 4 + 20..hd + 4 + 24].copy_from_slice(&0x534c_4154u32.to_le_bytes());
        b[hd + 4 + 36] = 1;
        b[hd + 4 + 37] = 1;
        let o = parse_load_option(&b).unwrap();
        assert_eq!((o.partition, o.mbr), (None, Some((1, 0x534c_4154, 2048, 1_048_576))));
        assert_eq!(describe(&o), "HD(1,MBR,0x534c4154,2048,1048576)\\EFI\\BOOT\\BOOTX64.EFI");
    }

    #[test]
    fn numbers_and_order() {
        let other =
            |d: &str| Some(LoadOption { attributes: 1, description: d.into(), partition: None, mbr: None, path: None });
        assert_eq!(pick_number(&[(0, other("UEFI Shell")), (1, other("Fedora")), (3, None)]), Some(2));
        assert_eq!(pick_number(&[(0, other("UEFI Shell")), (5, other("Slate"))]), Some(5));
        assert_eq!(pick_number(&[]), Some(0));
        assert_eq!(put_first(&[1, 5, 0], 5), [5, 1, 0]);
        assert_eq!(put_first(&[1, 0], 2), [2, 1, 0]);
        assert_eq!(parse_order(&encode_order(&[0x10, 0xABCD])), [0x10, 0xABCD]);
        assert_eq!(option_number(&format!("Boot000A-{GLOBAL}")), Some(10));
        assert_eq!(option_number(&format!("BootOrder-{GLOBAL}")), None);
        assert_eq!(option_number("Boot0001-00000000-0000-0000-0000-000000000000"), None);
    }
}
