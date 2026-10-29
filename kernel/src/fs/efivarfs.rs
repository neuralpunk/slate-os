// SPDX-License-Identifier: MIT OR Apache-2.0

//! efivarfs (ADR 0088): UEFI variables as files, as Linux lays them out
//! at /sys/firmware/efi/efivars (Linux's Documentation/filesystems/
//! efivarfs.rst). A variable is the file `Name-GUID`, the GUID in its
//! registry form; its contents are the variable's 32-bit attributes
//! (little-endian) and then its data. Writing a file (attributes and data
//! in one write) sets the variable, unlinking it deletes it; a write past
//! the start (O_APPEND) appends to it (`EFI_VARIABLE_APPEND_WRITE`).
//!
//! Deleting some variables leaves some machines unable to boot, so, as
//! efivarfs.rst says Linux does, every variable but the standard ones a
//! boot manager writes is immutable (ioctl_iflags(2): FS_IMMUTABLE_FL)
//! until a process with CAP_LINUX_IMMUTABLE clears the flag (`chattr -i`).
//! A variable created through the mount is not. The flags live in the
//! mount: a new mount starts from the defaults (ADR 0088).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::vfs::*;
use crate::abi::linux::errno::*;
use crate::arch::efi;
use crate::sync::IrqSpinLock;

/// statfs(2)'s magic for efivarfs (statfs(2): EFIVARFS_MAGIC).
pub const EFIVARFS_MAGIC: i64 = 0xDE5E_81E4;
const DEV: u64 = 0xF3;
/// A walk over the variables stops here (firmware with a loop in its list).
const MAX_VARIABLES: usize = 4096;

/// FS_IOC_GETFLAGS and FS_IOC_SETFLAGS, `_IOR('f', 1, long)` and
/// `_IOW('f', 2, long)`, and their 32-bit forms with an int (ioctl_iflags(2)).
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;
const FS_IOC32_GETFLAGS: u32 = 0x8004_6601;
const FS_IOC32_SETFLAGS: u32 = 0x4004_6602;
/// ioctl_iflags(2): "FS_IMMUTABLE_FL 'i': The file is immutable".
const FS_IMMUTABLE_FL: u32 = 0x10;
/// EFI_VARIABLE_APPEND_WRITE (UEFI 2.10 §8.2.3).
const APPEND_WRITE: u32 = 0x40;

/// EFI_GLOBAL_VARIABLE (UEFI 2.10 §3.3), as stored.
const GLOBAL: [u8; 16] =
    [0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c];

type Key = (Vec<u16>, [u8; 16]);

/// A mount's immutable flags that differ from the default.
type Flags = IrqSpinLock<BTreeMap<Key, bool>>;

enum Node {
    Root,
    Var { name: Vec<u16>, guid: [u8; 16], ino: u64 },
}

struct EfiVar {
    node: Node,
    flags: Arc<Flags>,
}

/// A new efivarfs mount: ENODEV without UEFI runtime services.
pub fn new() -> Result<Arc<dyn Inode>> {
    if !efi::available() {
        return Err(ENODEV);
    }
    Ok(Arc::new(EfiVar { node: Node::Root, flags: Arc::new(IrqSpinLock::new(BTreeMap::new())) }))
}

/// The global variables UEFI 2.10 §3.3 (table 3-1) has the OS write to
/// choose how the machine boots: these stay writable. `Boot####` and the
/// like take four hexadecimal digits.
fn standard(name: &[u16], guid: &[u8; 16]) -> bool {
    const FIXED: &[&str] = &[
        "BootOrder",
        "BootNext",
        "DriverOrder",
        "SysPrepOrder",
        "ConIn",
        "ConOut",
        "ErrOut",
        "Lang",
        "PlatformLang",
        "Timeout",
        "OsIndications",
    ];
    const NUMBERED: &[&str] = &["Boot", "Driver", "SysPrep", "Key"];
    if *guid != GLOBAL {
        return false;
    }
    let Ok(n) = String::from_utf16(name) else { return false };
    FIXED.contains(&n.as_str())
        || NUMBERED
            .iter()
            .any(|p| n.strip_prefix(p).is_some_and(|d| d.len() == 4 && d.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// A GUID in its registry form, as the EFI stores it: the first three
/// fields little-endian (UEFI 2.10 appendix A).
fn guid_text(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn parse_guid(t: &str) -> Option<[u8; 16]> {
    let p: Vec<&str> = t.split('-').collect();
    let ok = p.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&p).all(|(n, s)| s.len() == *n);
    if !ok {
        return None;
    }
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&u32::from_str_radix(p[0], 16).ok()?.to_le_bytes());
    g[4..6].copy_from_slice(&u16::from_str_radix(p[1], 16).ok()?.to_le_bytes());
    g[6..8].copy_from_slice(&u16::from_str_radix(p[2], 16).ok()?.to_le_bytes());
    let tail = format!("{}{}", p[3], p[4]);
    for (i, b) in g[8..].iter_mut().enumerate() {
        *b = u8::from_str_radix(tail.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(g)
}

/// `Name-GUID` split into the UCS-2 name and the GUID.
fn parse_file_name(f: &str) -> Option<(Vec<u16>, [u8; 16])> {
    if f.len() < 38 || !f.is_char_boundary(f.len() - 37) {
        return None;
    }
    let (name, rest) = f.split_at(f.len() - 37);
    let guid = parse_guid(rest.strip_prefix('-')?)?;
    if name.is_empty() {
        return None;
    }
    Some((name.encode_utf16().collect(), guid))
}

fn file_name(name: &[u16], guid: &[u8; 16]) -> String {
    let n: String = char::decode_utf16(name.iter().copied()).map(|c| c.unwrap_or('?')).collect();
    format!("{n}-{}", guid_text(guid))
}

/// An inode number for a variable: FNV-1a over its file name.
fn ino_of(name: &str) -> u64 {
    name.bytes().fold(0xCBF2_9CE4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01B3)) | 2
}

fn errno(s: efi::Status) -> Errno {
    match s.0 & !(1 << 63) {
        14 => ENOENT,
        2 => EINVAL,
        9 => ENOSPC,
        8 | 26 => EPERM,
        3 => EOPNOTSUPP,
        _ => EIO,
    }
}

impl EfiVar {
    fn var(&self, name: Vec<u16>, guid: [u8; 16]) -> Arc<dyn Inode> {
        let ino = ino_of(&file_name(&name, &guid));
        Arc::new(EfiVar { node: Node::Var { name, guid, ino }, flags: self.flags.clone() })
    }

    fn immutable(&self, name: &[u16], guid: &[u8; 16]) -> bool {
        let key = (name.to_vec(), *guid);
        self.flags.lock().get(&key).copied().unwrap_or_else(|| !standard(name, guid))
    }

    fn set_immutable(&self, name: &[u16], guid: &[u8; 16], on: bool) {
        let key = (name.to_vec(), *guid);
        let mut f = self.flags.lock();
        if on == !standard(name, guid) {
            f.remove(&key);
        } else {
            f.insert(key, on);
        }
    }

    /// EPERM for a write to an immutable variable (ioctl_iflags(2)).
    fn writable(&self) -> Result<(&[u16], &[u8; 16])> {
        let Node::Var { name, guid, .. } = &self.node else { return Err(EISDIR) };
        if self.immutable(name, guid) {
            return Err(EPERM);
        }
        Ok((name, guid))
    }
}

impl Inode for EfiVar {
    fn metadata(&self) -> Metadata {
        let now = Timespec::now();
        let (ino, mode, size) = match &self.node {
            Node::Root => (1, S_IFDIR | 0o755, 0),
            Node::Var { name, guid, ino } => {
                let size = efi::get_variable(name, guid).map_or(0, |(_, d)| d.len() as u64 + 4);
                (*ino, S_IFREG | 0o644, size)
            }
        };
        Metadata { dev: DEV, ino, mode, nlink: 1, size, atime: now, mtime: now, ctime: now, ..Default::default() }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        let (n, g) = parse_file_name(name).ok_or(ENOENT)?;
        efi::get_variable(&n, &g).map_err(errno)?;
        Ok(self.var(n, g))
    }

    /// Variables come and go through the firmware: never cached.
    fn uncached_child(&self, _name: &str) -> bool {
        true
    }

    /// A new file is a variable not yet written: its first write makes it.
    /// Its maker may change it (not immutable, efivarfs.rst).
    fn create(&self, name: &str, mode: u32, _rdev: u64) -> Result<Arc<dyn Inode>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        if mode & S_IFMT != S_IFREG {
            return Err(EINVAL);
        }
        let (n, g) = parse_file_name(name).ok_or(EINVAL)?;
        self.set_immutable(&n, &g, false);
        Ok(self.var(n, g))
    }

    fn unlink(&self, name: &str) -> Result<()> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        let (n, g) = parse_file_name(name).ok_or(ENOENT)?;
        let attrs = efi::get_variable(&n, &g).map_err(errno)?.0;
        if self.immutable(&n, &g) {
            return Err(EPERM);
        }
        efi::set_variable(&n, &g, attrs & !APPEND_WRITE, &[]).map_err(errno)?;
        self.flags.lock().remove(&(n, g));
        Ok(())
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        let mut out = Vec::new();
        let mut prev: Option<(Vec<u16>, [u8; 16])> = None;
        while out.len() < MAX_VARIABLES {
            let next = efi::next_variable(prev.as_ref().map(|(n, g)| (n.as_slice(), g))).map_err(errno)?;
            let Some((n, g)) = next else { break };
            let name = file_name(&n, &g);
            let ino = ino_of(&name);
            out.push(DirEntry { name, ino, kind: FileType::Regular, pos: out.len() as u64 + 1 });
            prev = Some((n, g));
        }
        Ok(out)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Node::Var { name, guid, .. } = &self.node else { return Err(EISDIR) };
        let (attrs, data) = efi::get_variable(name, guid).map_err(errno)?;
        let mut all = attrs.to_le_bytes().to_vec();
        all.extend_from_slice(&data);
        let at = (offset as usize).min(all.len());
        let n = buf.len().min(all.len() - at);
        buf[..n].copy_from_slice(&all[at..at + n]);
        Ok(n)
    }

    /// The attributes and the data, in one write: from the start it
    /// replaces the variable, past it (O_APPEND) it appends the data.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        let (name, guid) = self.writable()?;
        if buf.len() < 4 {
            return Err(EINVAL);
        }
        let mut attrs = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if offset != 0 {
            attrs |= APPEND_WRITE;
        }
        efi::set_variable(name, guid, attrs, &buf[4..]).map_err(errno)?;
        Ok(buf.len())
    }

    /// Opening with O_TRUNC changes nothing: a variable is written whole.
    fn truncate(&self, _size: u64) -> Result<()> {
        self.writable().map(|_| ())
    }

    /// The immutable flag (ioctl_iflags(2)); setting it needs
    /// CAP_LINUX_IMMUTABLE, and no other flag can be set.
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        use crate::arch::uaccess::{read_user, write_user};
        let Node::Var { name, guid, .. } = &self.node else { return Err(ENOTTY) };
        match cmd {
            FS_IOC_GETFLAGS | FS_IOC32_GETFLAGS => {
                let f: u32 = if self.immutable(name, guid) { FS_IMMUTABLE_FL } else { 0 };
                write_user(arg, &f).map_err(|_| EFAULT)?;
                Ok(0)
            }
            FS_IOC_SETFLAGS | FS_IOC32_SETFLAGS => {
                let f: u32 = read_user(arg).map_err(|_| EFAULT)?;
                if f & !FS_IMMUTABLE_FL != 0 {
                    return Err(EOPNOTSUPP);
                }
                let on = f & FS_IMMUTABLE_FL != 0;
                if on != self.immutable(name, guid)
                    && !crate::proc::cred::current().capable(crate::proc::cred::CAP_LINUX_IMMUTABLE)
                {
                    return Err(EPERM);
                }
                self.set_immutable(name, guid, on);
                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }

    fn statfs(&self) -> Option<StatFs> {
        Some(StatFs {
            magic: EFIVARFS_MAGIC,
            block_size: 4096,
            blocks: 0,
            free_blocks: 0,
            files: 0,
            free_files: 0,
            read_only: false,
        })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "fs::efivarfs_names", run: test_names }];

/// File names and GUIDs both ways (EFI_GLOBAL_VARIABLE, UEFI 2.10 §3.3).
fn test_names() -> core::result::Result<(), &'static str> {
    use crate::ktest::ensure;
    let f = "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c";
    let (n, g) = parse_file_name(f).ok_or("parse")?;
    ensure(
        g == [0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
        "guid",
    )?;
    ensure(file_name(&n, &g) == f, "round trip")?;
    ensure(g == GLOBAL, "global guid")?;
    ensure(parse_file_name("x-not-a-guid").is_none(), "bad guid accepted")?;
    let u = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    ensure(standard(&n, &g) && standard(&u("Boot000A"), &g) && standard(&u("Timeout"), &g), "standard")?;
    ensure(!standard(&u("Boot00"), &g) && !standard(&u("BootX000"), &g), "numbered")?;
    ensure(!standard(&u("PK"), &g) && !standard(&n, &[0; 16]), "vendor")
}
