// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-crypt` (ADR 0039): the key slots of encrypted partitions
//! (ADR 0036), and opening them after boot.
//!
//! ```text
//! slate-crypt format DEVICE             a new encrypted partition (its
//!                                       contents become unreadable)
//! slate-crypt status DEVICE             the header: slots, the copy
//! slate-crypt check DEVICE              which slot a password opens
//! slate-crypt add-password DEVICE       a password in a free slot
//! slate-crypt add-recovery-key DEVICE   a recovery key in a free slot
//! slate-crypt change-password DEVICE    the slot a password opens, anew
//! slate-crypt remove-slot DEVICE N      (never the last one)
//! slate-crypt repair DEVICE             both copies of the header again
//! slate-crypt open DEVICE               → /dev/dm-N
//! slate-crypt close dm-N
//! ```
//!
//! DEVICE is a partition (`/dev/sda2`) or `root`, the partition under the
//! encrypted root. Changing slots asks for a password or recovery key that
//! opens the disk first. Secrets are read from the terminal with echo off,
//! or line by line from standard input when it isn't one. Root only.
//!
//! The library half also serves the privilege broker: when an account's
//! password changes, [`follow_password`] moves the disk's slot along.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, lossy, print, println, process, term};
use slatecrypt::{BACKUP_OFFSET, Block, HEADER_BYTES, Header, KEY_BYTES, SlotKind};

/// BLKFLSBUF (musl `sys/mount.h`, ADR 0009).
const BLKFLSBUF: u32 = 0x1261;

/// An encrypted partition, open.
#[derive(Debug)]
pub struct Disk {
    fd: i32,
    pub path: String,
    pub header: Header,
    /// The first copy of the header is damaged (the second was read).
    pub damaged: bool,
}

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

impl Disk {
    pub fn open(path: &str, write: bool) -> Result<Disk, String> {
        let flags = if write { fs::O_RDWR } else { fs::O_RDONLY };
        let fd = fs::open(path.as_bytes(), flags | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
        let mut first = alloc::vec![0u8; HEADER_BYTES];
        let mut copy = alloc::vec![0u8; HEADER_BYTES];
        let read = io::pread(fd, &mut first, 0);
        let _ = io::pread(fd, &mut copy, BACKUP_OFFSET * 512);
        let r = match read {
            Ok(n) if n == HEADER_BYTES => Header::parse_either(&first, &copy),
            Ok(_) => Err(slatecrypt::Error::NotEncrypted),
            Err(e) => {
                let _ = io::close(fd);
                return Err(format!("{path}: {e}"));
            }
        };
        let header = match r {
            Ok(h) => h,
            Err(e) => {
                let _ = io::close(fd);
                return Err(match e {
                    slatecrypt::Error::NotEncrypted => format!("{path}: not an encrypted partition"),
                    slatecrypt::Error::Damaged => format!("{path}: both copies of the header are damaged"),
                    e => format!("{path}: {e:?}"),
                });
            }
        };
        let damaged = Header::parse(&first).is_err();
        Ok(Disk { fd, path: String::from(path), header, damaged })
    }

    /// Write both copies of the header, and flush them to the disk.
    pub fn save(&mut self) -> Result<(), String> {
        let b = self.header.to_bytes();
        for at in [0, BACKUP_OFFSET * 512] {
            if io::pwrite(self.fd, &b, at) != Ok(b.len()) {
                return Err(format!("{}: writing the header failed", self.path));
            }
        }
        let _ = fs::fsync(self.fd);
        let _ = io::ioctl(self.fd, BLKFLSBUF, 0);
        self.damaged = false;
        Ok(())
    }

    /// The slot `secret` opens, and the master key (wipe it after use).
    pub fn master_key(&self, secret: &[u8]) -> Result<(usize, [u8; KEY_BYTES]), String> {
        let mut memory = memory_for(&self.header);
        self.header.unlock_slot(secret, &mut memory).map_err(|e| match e {
            slatecrypt::Error::WrongPassword => String::from("that does not unlock the disk"),
            e => format!("{e:?}"),
        })
    }

    /// Put `secret` in a new slot of `kind` (or slot `at`), guarding
    /// `master`; the slot's number. The header is not saved.
    pub fn add_slot(
        &mut self,
        kind: SlotKind,
        master: &[u8; KEY_BYTES],
        secret: &[u8],
        at: Option<usize>,
    ) -> Result<usize, String> {
        let i = at.or_else(|| self.header.free_slot()).ok_or("every key slot is in use")?;
        let mut salt = [0u8; 32];
        process::random(&mut salt).map_err(|e| format!("random numbers: {e}"))?;
        let mut memory = alloc::vec![Block::default(); slatecrypt::Params::DEFAULT.blocks()];
        let slot = slatecrypt::new_slot_of(kind, master, secret, salt, &mut memory).map_err(|e| format!("{e:?}"))?;
        self.header.slots[i] = Some(slot);
        Ok(i)
    }

    /// Open the partition with `secret` as a mapped device: its number N.
    pub fn map(&self, secret: &[u8]) -> Result<u32, String> {
        let mut memory = memory_for(&self.header);
        let mut recovery = slatecrypt::normalize_recovery_key(secret);
        let mut result = Err(String::from("that does not unlock the disk"));
        for (i, slot) in self.header.slots.iter().enumerate() {
            let Some(slot) = slot else { continue };
            let s: &[u8] = match (slot.kind, &recovery) {
                (SlotKind::Password, _) => secret,
                (SlotKind::RecoveryKey, Some(r)) => r,
                (SlotKind::RecoveryKey, None) => continue,
            };
            let mut kek = match slatecrypt::slot_key(slot, s, &mut memory) {
                Ok(k) => k,
                Err(e) => {
                    result = Err(format!("{e:?}"));
                    break;
                }
            };
            let r = process::crypt_open(self.fd, i, &kek);
            slatecrypt::wipe(&mut kek);
            match r {
                Ok(n) => {
                    result = Ok(n);
                    break;
                }
                Err(slate_rt::Errno::EACCES) => continue,
                Err(slate_rt::Errno::EBUSY) => {
                    result = Err(format!("{} is open already", self.path));
                    break;
                }
                Err(e) => {
                    result = Err(format!("opening {}: {e}", self.path));
                    break;
                }
            }
        }
        if let Some(r) = recovery.as_mut() {
            slatecrypt::wipe(r);
        }
        result
    }
}

/// Memory for the costliest slot's key derivation.
fn memory_for(h: &Header) -> Vec<Block> {
    let blocks = h.slots.iter().flatten().map(|s| s.params.blocks()).max().unwrap_or(0);
    alloc::vec![Block::default(); blocks]
}

/// The partition under the encrypted root (`/dev/sda2`), if the root is
/// encrypted: the mapped device /proc/mounts names for /, and the slave
/// /sys/block lists for it.
pub fn root_partition() -> Option<String> {
    root_mapping().map(|(_, part)| part)
}

/// The encrypted root's mapped device's number N (`dm-N`) and partition.
fn root_mapping() -> Option<(u32, String)> {
    let mounts = fs::read_file(b"/proc/mounts").ok()?;
    let mounts = String::from(lossy(&mounts));
    let dm = mounts.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        match (w.next(), w.next()) {
            (Some(src), Some("/")) => src.strip_prefix("/dev/").filter(|d| d.starts_with("dm-")).map(String::from),
            _ => None,
        }
    })?;
    let slaves = fs::read_dir(format!("/sys/block/{dm}/slaves").as_bytes()).ok()?;
    let n = dm.strip_prefix("dm-")?.parse().ok()?;
    slaves.into_iter().next().map(|e| (n, format!("/dev/{}", lossy(&e.name))))
}

/// Root reset `uid`'s account password to `new` (ADR 0058): the slot the
/// account owns holds `new` now, wrapped by the kernel from the mapped
/// root's key. Ok(false) when the root isn't encrypted or no slot is the
/// account's (slots learn their owner when the password follows, and the
/// installer marks the first account's).
pub fn reset_password(uid: u32, new: &[u8]) -> Result<bool, String> {
    let Some((n, path)) = root_mapping() else { return Ok(false) };
    let mut disk = Disk::open(&path, true)?;
    let Some(i) =
        disk.header.slots.iter().position(|s| s.is_some_and(|s| s.kind == SlotKind::Password && s.owner == Some(uid)))
    else {
        return Ok(false);
    };
    let mut salt = [0u8; 32];
    process::random(&mut salt).map_err(|e| format!("random numbers: {e}"))?;
    let params = slatecrypt::Params::DEFAULT;
    let mut memory = alloc::vec![Block::default(); params.blocks()];
    let mut kek = slatecrypt::new_slot_key(new, &salt, params, &mut memory).map_err(|e| format!("{e:?}"))?;
    drop(memory);
    let wrapped = process::crypt_wrap(n, &kek).map_err(|e| format!("the kernel could not wrap the key: {e}"));
    slatecrypt::wipe(&mut kek);
    let wrapped = wrapped?;
    disk.header.slots[i] = Some(slatecrypt::Slot { kind: SlotKind::Password, params, salt, wrapped, owner: Some(uid) });
    disk.save().map(|()| true)
}

/// The account password changed from `old` to `new`: the encrypted root's
/// password slot that `old` opens holds `new` now. Ok(false) when the root
/// isn't encrypted or `old` opens no password slot.
pub fn follow_password(old: &[u8], new: &[u8]) -> Result<bool, String> {
    follow_password_of(None, old, new)
}

/// [`follow_password`], recording `owner` as the slot's account (ADR
/// 0058) so a later reset by root can find it.
pub fn follow_password_of(owner: Option<u32>, old: &[u8], new: &[u8]) -> Result<bool, String> {
    let Some(path) = root_partition() else { return Ok(false) };
    let mut disk = Disk::open(&path, true)?;
    let mut memory = memory_for(&disk.header);
    // Only password slots follow the account (not recovery keys).
    let mut found = None;
    for (i, slot) in disk.header.slots.iter().enumerate() {
        if let Some(s) = slot.filter(|s| s.kind == SlotKind::Password)
            && let Ok(k) = slatecrypt::open_slot(&s, old, &mut memory)
        {
            found = Some((i, k));
            break;
        }
    }
    drop(memory);
    let Some((i, mut key)) = found else { return Ok(false) };
    let r = disk.add_slot(SlotKind::Password, &key, new, Some(i)).and_then(|_| {
        if let Some(s) = disk.header.slots[i].as_mut()
            && owner.is_some()
        {
            s.owner = owner;
        }
        disk.save()
    });
    slatecrypt::wipe(&mut key);
    r.map(|()| true)
}

/// A line from the terminal with echo off, or from standard input.
fn secret(prompt: &str) -> Result<Vec<u8>, String> {
    let tty = term::isatty(0);
    io::flush_stdout();
    let _ = io::write_all(if tty { 0 } else { 2 }, prompt.as_bytes());
    let saved = if tty { term::get(0).ok() } else { None };
    if let Some(t) = saved {
        let mut q = t;
        q.lflag &= !term::ECHO;
        q.lflag |= term::ICANON;
        let _ = term::set(0, &q, true);
    }
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let got = loop {
        match io::read(0, &mut b) {
            Ok(1) if b[0] == b'\n' => break true,
            Ok(1) => line.push(b[0]),
            _ => break !line.is_empty(),
        }
    };
    if let Some(t) = saved {
        let _ = term::set(0, &t, true);
        let _ = io::write_all(0, b"\n");
    }
    if !tty {
        let _ = io::write_all(2, b"\n");
    }
    if got { Ok(line) } else { Err(String::from("no input")) }
}

/// A new password, asked twice.
fn new_password() -> Result<Vec<u8>, String> {
    let a = secret("New password: ")?;
    let mut b = secret("Again: ")?;
    let same = a == b;
    slatecrypt::wipe(&mut b);
    if !same {
        return Err("the passwords differ".into());
    }
    if a.len() < 6 {
        return Err("a disk password needs 6 characters or more".into());
    }
    Ok(a)
}

/// The disk opened by a password or recovery key asked for: the slot and
/// the master key.
fn unlocked(disk: &Disk) -> Result<(usize, [u8; KEY_BYTES]), String> {
    let mut s = secret(&format!("Password or recovery key for {}: ", disk.path))?;
    let r = disk.master_key(&s);
    slatecrypt::wipe(&mut s);
    r
}

fn kind_name(k: SlotKind) -> &'static str {
    match k {
        SlotKind::Password => "password",
        SlotKind::RecoveryKey => "recovery key",
    }
}

/// `status`: the header's slots and the state of its copies.
pub fn describe(disk: &Disk) -> String {
    let h = &disk.header;
    let mut out = format!("{}: encrypted (AES-256-XTS), {} MiB of data\n", disk.path, h.data_sectors / 2048);
    for (i, s) in h.slots.iter().enumerate() {
        match s {
            Some(s) => {
                let owner = s.owner.map(|u| format!(" (UID {u})")).unwrap_or_default();
                out += &format!("  slot {i}: {}{owner}\n", kind_name(s.kind));
            }
            None => out += &format!("  slot {i}: free\n"),
        }
    }
    out += if disk.damaged {
        "  header: the first copy is damaged; `slate-crypt repair` rewrites it\n"
    } else {
        "  header: both copies read\n"
    };
    out
}

fn device(arg: Option<&String>) -> Result<String, String> {
    match arg.map(String::as_str) {
        Some("root") => root_partition().ok_or_else(|| String::from("the root is not encrypted")),
        Some(d) => Ok(String::from(d)),
        None => Err("which partition? (a device, or root)".into()),
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    if cmd != "status" && process::geteuid() != 0 {
        return Err("changing key slots needs root (su -)".into());
    }
    match cmd {
        "status" => {
            let disk = Disk::open(&device(args.get(1))?, false)?;
            print!("{}", describe(&disk));
            Ok(())
        }
        "add-password" | "add-recovery-key" | "change-password" => {
            let mut disk = Disk::open(&device(args.get(1))?, true)?;
            let (opened, mut key) = unlocked(&disk)?;
            let r = (|| -> Result<String, String> {
                match cmd {
                    "add-password" => {
                        let mut p = new_password()?;
                        let r = disk.add_slot(SlotKind::Password, &key, &p, None);
                        slatecrypt::wipe(&mut p);
                        let i = r?;
                        disk.save()?;
                        Ok(format!("The new password is in slot {i}."))
                    }
                    "change-password" => {
                        if disk.header.slots[opened].is_some_and(|s| s.kind != SlotKind::Password) {
                            return Err("that was a recovery key; give the password to change".into());
                        }
                        let mut p = new_password()?;
                        let r = disk.add_slot(SlotKind::Password, &key, &p, Some(opened));
                        slatecrypt::wipe(&mut p);
                        r?;
                        disk.save()?;
                        Ok(format!("Slot {opened} has the new password."))
                    }
                    _ => {
                        let mut random = [0u8; 20];
                        process::random(&mut random).map_err(|e| format!("random numbers: {e}"))?;
                        let mut rk = slatecrypt::recovery_key(&random);
                        slatecrypt::wipe(&mut random);
                        let r = disk.add_slot(SlotKind::RecoveryKey, &key, &rk, None);
                        let text = String::from(lossy(&rk));
                        slatecrypt::wipe(&mut rk);
                        let i = r?;
                        disk.save()?;
                        Ok(format!(
                            "Recovery key (slot {i}), to write down and keep somewhere safe:\n\n    {text}\n\n\
                             It unlocks the disk where a password is asked for."
                        ))
                    }
                }
            })();
            slatecrypt::wipe(&mut key);
            println!("{}", r?);
            Ok(())
        }
        "format" => {
            let path = device(args.get(1))?;
            if path == root_partition().unwrap_or_default() {
                return Err(format!("{path} holds the running system"));
            }
            let fd = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
            let mut size = 0u64;
            // BLKGETSIZE64 (musl `sys/mount.h`).
            let r = io::ioctl(fd, 0x8008_1272, &mut size as *mut u64 as usize);
            let _ = io::close(fd);
            r.map_err(|e| format!("{path}: {e}"))?;
            let sectors = size / 512;
            if sectors <= slatecrypt::DATA_OFFSET * 2 {
                return Err(format!("{path} is too small"));
            }
            let mut p = new_password()?;
            let mut random = [0u8; KEY_BYTES + 16];
            let made = process::random(&mut random).map_err(|e| format!("random numbers: {e}"));
            let mut key: [u8; KEY_BYTES] = random[..KEY_BYTES].try_into().unwrap_or([0; KEY_BYTES]);
            let uuid: [u8; 16] = random[KEY_BYTES..].try_into().unwrap_or([0; 16]);
            slatecrypt::wipe(&mut random);
            let r = made.and_then(|()| {
                let mut disk = Disk {
                    fd: fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?,
                    path: path.clone(),
                    header: Header::new(sectors, uuid),
                    damaged: false,
                };
                disk.add_slot(SlotKind::Password, &key, &p, None)?;
                disk.save()
            });
            slatecrypt::wipe(&mut key);
            slatecrypt::wipe(&mut p);
            r?;
            println!("{path} is encrypted, with the password in slot 0; `slate-crypt open {path}` opens it.");
            Ok(())
        }
        "remove-slot" => {
            let mut disk = Disk::open(&device(args.get(1))?, true)?;
            let n: usize = args.get(2).and_then(|n| n.parse().ok()).ok_or("which slot? (0-3)")?;
            if disk.header.slots.get(n).copied().flatten().is_none() {
                return Err(format!("slot {n} is not in use"));
            }
            if disk.header.slots.iter().flatten().count() == 1 {
                return Err("that is the last key slot; the disk could never be unlocked again".into());
            }
            let (opened, mut key) = unlocked(&disk)?;
            slatecrypt::wipe(&mut key);
            if opened == n {
                return Err(format!("give a password or key of another slot than {n}"));
            }
            disk.header.slots[n] = None;
            disk.save()?;
            println!("Slot {n} is free.");
            Ok(())
        }
        "check" => {
            let disk = Disk::open(&device(args.get(1))?, false)?;
            let (i, mut key) = unlocked(&disk)?;
            slatecrypt::wipe(&mut key);
            let kind = disk.header.slots[i].map_or("slot", |s| kind_name(s.kind));
            println!("That opens slot {i} ({kind}).");
            Ok(())
        }
        "repair" => {
            let mut disk = Disk::open(&device(args.get(1))?, true)?;
            disk.save()?;
            println!("Both copies of {}'s header are written.", disk.path);
            Ok(())
        }
        "open" => {
            let disk = Disk::open(&device(args.get(1))?, false)?;
            let mut s = secret(&format!("Password or recovery key for {}: ", disk.path))?;
            let r = disk.map(&s);
            slatecrypt::wipe(&mut s);
            println!("{} is open as /dev/dm-{}", disk.path, r?);
            Ok(())
        }
        "close" => {
            let name = args.get(1).ok_or("which device? (dm-N)")?;
            let n: u32 = name
                .trim_start_matches("/dev/")
                .strip_prefix("dm-")
                .and_then(|n| n.parse().ok())
                .ok_or("a mapped device is named dm-N")?;
            process::crypt_close(n).map_err(|e| match e {
                slate_rt::Errno::EBUSY => format!("dm-{n} is in use (mounted?)"),
                e => format!("dm-{n}: {e}"),
            })?;
            println!("dm-{n} is closed.");
            Ok(())
        }
        _ => Err(String::from(
            "usage: slate-crypt format|status|check|add-password|add-recovery-key|change-password|repair|open DEVICE\n\
             \x20      slate-crypt remove-slot DEVICE N | close dm-N",
        )),
    }
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(lossy(a))).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slate-crypt: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_text() {
        let mut h = Header::new(1 << 20, [0; 16]);
        let mut memory = alloc::vec![Block::default(); 64];
        let quick = slatecrypt::Params { memory_kib: 64, passes: 1, lanes: 1 };
        h.slots[0] = Some(slatecrypt::new_slot(&[1; 64], b"pw", [2; 32], quick, &mut memory).unwrap());
        let mut r = slatecrypt::new_slot(&[1; 64], b"rk", [3; 32], quick, &mut memory).unwrap();
        r.kind = SlotKind::RecoveryKey;
        h.slots[2] = Some(r);
        let d = Disk { fd: -1, path: "/dev/sda2".into(), header: h, damaged: true };
        let text = describe(&d);
        assert!(text.contains("slot 0: password\n  slot 1: free\n  slot 2: recovery key\n  slot 3: free"), "{text}");
        assert!(text.contains("first copy is damaged"));
        assert!(text.starts_with("/dev/sda2: encrypted (AES-256-XTS), 511 MiB of data"));
        core::mem::forget(d);
    }
}
