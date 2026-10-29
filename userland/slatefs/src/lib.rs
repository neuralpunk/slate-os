// SPDX-License-Identifier: MIT OR Apache-2.0

//! slatefs: make, check and inspect SlateFS file systems on unmounted
//! devices and image files (ADR 0026). It runs on Slate and on the host,
//! where xtask makes images with it (`mkfs -d DIR`, like `mkfs.ext4 -d`).
//! A mounted SlateFS is changed through the kernel instead (slate-update).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod esp;
pub mod update;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, lossy, println};
use slatefs::{BootState, DT_DIR, DT_LNK, Disk, Fs, ROOT_INO};

const USAGE: &str = "usage: slatefs [--offset BYTES] [--password-file FILE] COMMAND [ARGS]

  --password-file opens an encrypted partition (ADR 0036)

  mkfs [-L LABEL] [-s SUBVOL] [--size SIZE] [-d DIR [--owner UID:GID]] IMAGE
  populate IMAGE SUBVOL DIR [--owner UID:GID]   copy DIR into a subvolume
  fsck [--repair] IMAGE              check every checksum and invariant;
                                     --repair fixes what it safely can
  ls IMAGE [SUBVOL:]PATH             list a directory
  cat IMAGE [SUBVOL:]PATH            print a file
  subvol IMAGE list
  subvol IMAGE create NAME
  subvol IMAGE snapshot SOURCE NAME [ro]
  subvol IMAGE delete NAME
  boot IMAGE [default=NAME] [fallback=NAME] [tries=N] [pending=0|1]
  ctl PATH COMMAND...                on a mounted SlateFS: list, snapshot NAME [ro],
                                     delete NAME, readonly NAME 0|1, boot, commit
";

type Res<T = ()> = Result<T, String>;

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| lossy(a).into_owned()).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slatefs: {e}");
            1
        }
    }
}

/// A device or image file, or a region of one (`--offset`); its sectors
/// encrypted when it is an encrypted partition.
struct FileDisk {
    fd: i32,
    base: u64,
    xts: Option<slatecrypt::Xts>,
}

impl FileDisk {
    fn whole_sectors(&self, offset: u64, len: usize) -> bool {
        self.xts.is_none() || (offset % 512 == 0 && len % 512 == 0)
    }
}

impl Disk for FileDisk {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> slatefs::Result<()> {
        if !self.whole_sectors(offset, buf.len()) {
            return Err(slatefs::Error::Io);
        }
        let mut done = 0;
        while done < buf.len() {
            match io::pread(self.fd, &mut buf[done..], self.base + offset + done as u64) {
                Ok(0) | Err(_) => return Err(slatefs::Error::Io),
                Ok(n) => done += n,
            }
        }
        if let Some(x) = &self.xts {
            x.decrypt(offset / 512, buf);
        }
        Ok(())
    }
    fn write(&mut self, offset: u64, buf: &[u8]) -> slatefs::Result<()> {
        if !self.whole_sectors(offset, buf.len()) {
            return Err(slatefs::Error::Io);
        }
        let mut sealed;
        let data = match &self.xts {
            Some(x) => {
                sealed = buf.to_vec();
                x.encrypt(offset / 512, &mut sealed);
                &sealed[..]
            }
            None => buf,
        };
        let mut done = 0;
        while done < data.len() {
            match io::pwrite(self.fd, &data[done..], self.base + offset + done as u64) {
                Ok(0) | Err(_) => return Err(slatefs::Error::Io),
                Ok(n) => done += n,
            }
        }
        Ok(())
    }
    fn flush(&mut self) -> slatefs::Result<()> {
        fs::fsync(self.fd).map_err(|_| slatefs::Error::Io)
    }
    fn now(&self) -> (i64, u32) {
        let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
        (s, ns as u32)
    }
}

/// The byte offset of the file system in the image (`--offset`).
static OFFSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The password for encrypted partitions (`--password-file`).
static PASSWORD: slate_sync::Once<Vec<u8>> = slate_sync::Once::new();

fn open(path: &str, write: bool) -> Res<FileDisk> {
    let flags = if write { fs::O_RDWR } else { fs::O_RDONLY };
    let fd = fs::open(path.as_bytes(), flags | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let base = OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    let mut head = alloc::vec![0u8; slatecrypt::HEADER_BYTES];
    if io::pread(fd, &mut head, base) != Ok(head.len()) || !slatecrypt::is_encrypted(&head) {
        return Ok(FileDisk { fd, base, xts: None });
    }
    let password = PASSWORD.get().ok_or_else(|| format!("{path}: the partition is encrypted (--password-file)"))?;
    let mut copy = alloc::vec![0u8; slatecrypt::HEADER_BYTES];
    let _ = io::pread(fd, &mut copy, base + slatecrypt::BACKUP_OFFSET * 512);
    let h = slatecrypt::Header::parse_either(&head, &copy).map_err(|e| format!("{path}: {e:?}"))?;
    let blocks = h.slots.iter().flatten().map(|s| s.params.blocks()).max().unwrap_or(0);
    let mut memory = alloc::vec![slatecrypt::Block::default(); blocks];
    let mut key = h.unlock(password, &mut memory).map_err(|e| format!("{path}: {e:?}"))?;
    let xts = slatecrypt::Xts::new(&key);
    slatecrypt::wipe(&mut key);
    Ok(FileDisk { fd, base: base + h.data_offset * 512, xts: Some(xts) })
}

fn mount(path: &str, write: bool) -> Res<Fs<FileDisk>> {
    Fs::mount(open(path, write)?, !write).map_err(|e| format!("{path}: {e:?}"))
}

fn parse_size(s: &str) -> Res<u64> {
    let (num, mul) = match s.as_bytes().last() {
        Some(b'K' | b'k') => (&s[..s.len() - 1], 1 << 10),
        Some(b'M' | b'm') => (&s[..s.len() - 1], 1 << 20),
        Some(b'G' | b'g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().map(|n| n * mul).map_err(|_| format!("bad size {s:?}"))
}

fn run(mut args: &[String]) -> Res {
    if args.first().is_some_and(|a| a == "--offset") {
        let v = args.get(1).ok_or("--offset needs a value")?;
        OFFSET.store(parse_size(v)?, core::sync::atomic::Ordering::Relaxed);
        args = &args[2..];
    }
    if args.first().is_some_and(|a| a == "--password-file") {
        let f = args.get(1).ok_or("--password-file needs a file")?;
        let p = fs::read_file(f.as_bytes()).map_err(|e| format!("{f}: {e}"))?;
        PASSWORD.call_once(|| p.into_iter().take_while(|&c| c != b'\n').collect());
        args = &args[2..];
    }
    let (cmd, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
    match cmd.as_str() {
        "mkfs" => mkfs(rest),
        "populate" if rest.len() == 3 || rest.len() == 5 => populate_cmd(rest),
        "fsck" if rest.len() == 1 => fsck(&rest[0], false),
        "fsck" if rest.len() == 2 && rest[0] == "--repair" => fsck(&rest[1], true),
        "ls" if rest.len() == 2 => ls(&rest[0], &rest[1]),
        "cat" if rest.len() == 2 => cat(&rest[0], &rest[1]),
        "subvol" if rest.len() >= 2 => subvol(&rest[0], &rest[1..]),
        "boot" if !rest.is_empty() => boot(&rest[0], &rest[1..]),
        "ctl" if rest.len() >= 2 => {
            slate_rt::print!("{}", slate_rt::subvol::ctl(&rest[0], &rest[1..].join(" "))?);
            Ok(())
        }
        "-h" | "--help" => {
            slate_rt::print!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.trim_end().to_string()),
    }
}

fn mkfs(args: &[String]) -> Res {
    let (mut label, mut subvol, mut size, mut dir, mut owner) = (String::new(), String::from("root"), None, None, None);
    let mut it = args.iter();
    let mut image = None;
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "-L" => label = val()?,
            "-s" => subvol = val()?,
            "--size" => size = Some(parse_size(&val()?)?),
            "-d" => dir = Some(val()?),
            "--owner" => {
                let v = val()?;
                let (u, g) = v.split_once(':').ok_or("--owner wants UID:GID")?;
                owner = Some((u.parse().map_err(|_| "bad uid")?, g.parse().map_err(|_| "bad gid")?));
            }
            _ if image.is_none() => image = Some(a.clone()),
            _ => return Err(USAGE.trim_end().into()),
        }
    }
    let image = image.ok_or_else(|| USAGE.trim_end().to_string())?;
    let offset = OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    // Within a larger image (--offset) the size says how much is ours;
    // otherwise it sets the file's size.
    if let Some(sz) = size
        && offset == 0
    {
        if !fs::exists(image.as_bytes()) {
            fs::write_file(image.as_bytes(), b"", 0o644).map_err(|e| format!("{image}: {e}"))?;
        }
        fs::truncate(image.as_bytes(), sz).map_err(|e| format!("{image}: {e}"))?;
    }
    let disk = open(&image, true)?;
    let bytes = match size {
        Some(sz) if offset > 0 => sz,
        _ => io::lseek(disk.fd, 0, 2).map_err(|e| format!("{image}: {e}"))?.saturating_sub(offset),
    };
    let blocks = bytes / slatefs::layout::BLOCK as u64;
    let mut uuid = [0u8; 16];
    let _ = slate_rt::process::random(&mut uuid);
    let mut f = slatefs::mkfs(disk, blocks, &label, uuid, &subvol).map_err(|e| format!("{image}: {e:?}"))?;
    if let Some(d) = dir {
        let sv = f.subvol_by_name(&subvol).ok_or("subvolume vanished")?;
        let mut links = BTreeMap::new();
        populate(&mut f, sv, ROOT_INO, d.trim_end_matches('/'), owner, &mut links)?;
        // The root directory takes the source directory's owner and mode.
        let st = fs::stat(d.as_bytes()).map_err(|e| format!("{d}: {e}"))?;
        f.set_mode(sv, ROOT_INO, st.mode & 0o7777).map_err(|e| format!("{e:?}"))?;
        let (u, g) = owner.unwrap_or((st.uid, st.gid));
        f.set_owner(sv, ROOT_INO, Some(u), Some(g)).map_err(|e| format!("{e:?}"))?;
    }
    f.sync().map_err(|e| format!("{e:?}"))?;
    let t = f.totals();
    println!("{image}: {} MiB, {} blocks free, subvolume {subvol}", blocks * 4 / 1024, t.free);
    Ok(())
}

/// Copy `src` into directory `dir` of subvolume `sv`.
fn populate(
    f: &mut Fs<FileDisk>,
    sv: u64,
    dir: u64,
    src: &str,
    owner: Option<(u32, u32)>,
    links: &mut BTreeMap<(u64, u64), u64>,
) -> Res {
    let mut names: Vec<Vec<u8>> =
        fs::read_dir(src.as_bytes()).map_err(|e| format!("{src}: {e}"))?.into_iter().map(|e| e.name).collect();
    names.sort();
    for name in names {
        let path = format!("{src}/{}", lossy(&name));
        let st = fs::lstat(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
        let (uid, gid) = owner.unwrap_or((st.uid, st.gid));
        let err = |e: slatefs::Error| format!("{path}: {e:?}");
        if st.is_dir() {
            let d = f.mkdir(sv, dir, &name, st.mode & 0o7777, uid, gid).map_err(err)?;
            populate(f, sv, d, &path, owner, links)?;
            f.set_times(sv, d, None, Some((st.mtime, st.mtime_nsec as u32))).map_err(err)?;
        } else if st.is_symlink() {
            let t = fs::readlink(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
            f.symlink(sv, dir, &name, &t, uid, gid).map_err(err)?;
        } else if st.nlink > 1 && links.contains_key(&(st.dev, st.ino)) {
            f.link(sv, dir, &name, links[&(st.dev, st.ino)]).map_err(err)?;
        } else if st.is_file() {
            let ino = f.create(sv, dir, &name, st.mode, uid, gid, 0).map_err(err)?;
            let data = fs::read_file(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
            f.write(sv, ino, 0, &data).map_err(err)?;
            f.set_times(sv, ino, None, Some((st.mtime, st.mtime_nsec as u32))).map_err(err)?;
            links.insert((st.dev, st.ino), ino);
        } else {
            let ino = f.create(sv, dir, &name, st.mode, uid, gid, st.rdev).map_err(err)?;
            links.insert((st.dev, st.ino), ino);
        }
    }
    Ok(())
}

fn populate_cmd(args: &[String]) -> Res {
    let owner = match args.get(3).map(String::as_str) {
        Some("--owner") => {
            let v = args.get(4).ok_or("--owner wants UID:GID")?;
            let (u, g) = v.split_once(':').ok_or("--owner wants UID:GID")?;
            Some((u.parse().map_err(|_| "bad uid")?, g.parse().map_err(|_| "bad gid")?))
        }
        Some(_) => return Err(USAGE.trim_end().into()),
        None => None,
    };
    let mut f = mount(&args[0], true)?;
    let sv = match f.subvol_by_name(&args[1]) {
        Some(sv) => sv,
        None => f.create_subvolume(&args[1]).map_err(|e| format!("{e:?}"))?,
    };
    let mut links = BTreeMap::new();
    populate(&mut f, sv, ROOT_INO, args[2].trim_end_matches('/'), owner, &mut links)?;
    f.sync().map_err(|e| format!("{e:?}"))
}

fn fsck(image: &str, repair: bool) -> Res {
    let mut f = mount(image, repair)?;
    let problems = if repair {
        let (done, left) = f.repair().map_err(|e| format!("{e:?}"))?;
        for d in &done {
            println!("{d}");
        }
        left
    } else {
        f.check().map_err(|e| format!("{e:?}"))?
    };
    for p in &problems {
        println!("{p}");
    }
    let t = f.totals();
    println!(
        "{image}: generation {}, {} subvolumes, {} of {} blocks free{}",
        f.generation(),
        f.subvolumes().len(),
        t.free,
        t.blocks,
        if problems.is_empty() { ", clean" } else { "" }
    );
    if problems.is_empty() { Ok(()) } else { Err(format!("{} problems", problems.len())) }
}

/// `[SUBVOL:]PATH` to (subvolume, inode).
fn resolve(f: &mut Fs<FileDisk>, spec: &str) -> Res<(u64, u64)> {
    let (sv, path) = match spec.split_once(':') {
        Some((s, p)) => (f.subvol_by_name(s).ok_or_else(|| format!("{s}: no such subvolume"))?, p),
        None => {
            let b = f.boot().default;
            let first = f.subvolumes().first().map(|s| s.id).ok_or("no subvolumes")?;
            (if b != 0 { b } else { first }, spec)
        }
    };
    let mut ino = ROOT_INO;
    for part in path.split('/').filter(|p| !p.is_empty()) {
        ino = f.lookup(sv, ino, part.as_bytes()).map_err(|e| format!("{part}: {e:?}"))?;
    }
    Ok((sv, ino))
}

fn ls(image: &str, spec: &str) -> Res {
    let mut f = mount(image, false)?;
    let (sv, dir) = resolve(&mut f, spec)?;
    let mut list = f.readdir(sv, dir).map_err(|e| format!("{e:?}"))?;
    list.sort_by(|a, b| a.1.name.cmp(&b.1.name));
    for (_, d) in list {
        let i = f.stat(sv, d.ino).map_err(|e| format!("{e:?}"))?;
        let mark = match d.kind {
            DT_DIR => "/",
            DT_LNK => "@",
            _ => "",
        };
        println!("{:o} {:>5} {:>5} {:>9} {}{mark}", i.mode, i.uid, i.gid, i.size, lossy(&d.name));
    }
    Ok(())
}

fn cat(image: &str, spec: &str) -> Res {
    let mut f = mount(image, false)?;
    let (sv, ino) = resolve(&mut f, spec)?;
    let size = f.stat(sv, ino).map_err(|e| format!("{e:?}"))?.size as usize;
    let mut buf = alloc::vec![0u8; size];
    f.read(sv, ino, 0, &mut buf).map_err(|e| format!("{e:?}"))?;
    io::write_all(io::STDOUT, &buf).map_err(|e| e.to_string())
}

fn subvol(image: &str, args: &[String]) -> Res {
    let write = args[0] != "list";
    let mut f = mount(image, write)?;
    let by_name = |f: &Fs<FileDisk>, n: &str| f.subvol_by_name(n).ok_or_else(|| format!("{n}: no such subvolume"));
    match (args[0].as_str(), &args[1..]) {
        ("list", []) => {
            let b = f.boot();
            for s in f.subvolumes() {
                let mut tags = Vec::new();
                if s.readonly {
                    tags.push("ro");
                }
                if s.id == b.default {
                    tags.push("default");
                }
                if s.id == b.fallback {
                    tags.push("fallback");
                }
                println!("{} {} {}", s.id, s.name, tags.join(","));
            }
            return Ok(());
        }
        ("create", [name]) => {
            f.create_subvolume(name).map_err(|e| format!("{e:?}"))?;
        }
        ("snapshot", [src, name]) | ("snapshot", [src, name, _]) => {
            let ro = args.get(3).is_some_and(|a| a == "ro");
            let s = by_name(&f, src)?;
            f.snapshot(s, name, ro).map_err(|e| format!("{e:?}"))?;
        }
        ("delete", [name]) => {
            let s = by_name(&f, name)?;
            f.delete_subvolume(s).map_err(|e| format!("{e:?}"))?;
        }
        _ => return Err(USAGE.trim_end().into()),
    }
    f.sync().map_err(|e| format!("{e:?}"))
}

fn boot(image: &str, args: &[String]) -> Res {
    let mut f = mount(image, !args.is_empty())?;
    let mut b: BootState = f.boot();
    let name_of = |f: &Fs<FileDisk>, id: u64| f.subvolumes().iter().find(|s| s.id == id).map(|s| s.name.clone());
    for a in args {
        let (k, v) = a.split_once('=').ok_or_else(|| format!("{a}: want KEY=VALUE"))?;
        match k {
            "default" | "fallback" => {
                let id = f.subvol_by_name(v).ok_or_else(|| format!("{v}: no such subvolume"))?;
                if k == "default" { b.default = id } else { b.fallback = id }
            }
            "tries" => b.tries = v.parse().map_err(|_| "bad tries")?,
            "pending" => b.pending = v == "1",
            _ => return Err(format!("{k}: unknown boot setting")),
        }
    }
    if !args.is_empty() {
        f.set_boot(b).map_err(|e| format!("{e:?}"))?;
        f.sync().map_err(|e| format!("{e:?}"))?;
    }
    println!(
        "default={} fallback={} tries={} pending={}",
        name_of(&f, b.default).unwrap_or_else(|| "-".into()),
        name_of(&f, b.fallback).unwrap_or_else(|| "-".into()),
        b.tries,
        u8::from(b.pending)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("64M").unwrap(), 64 << 20);
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert!(parse_size("x").is_err());
    }
}
