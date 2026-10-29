// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archives as the Archive Manager sees them (ADR 0106): zip, tar
//! (plain or gzipped), cpio and a lone gzipped file, read into one list
//! of items; extracting them safely; and making zip, tar and tar.gz
//! archives from files and folders.
//!
//! An archive is never trusted when extracted:
//! - names are made relative: absolute paths lose their `/`, and a name
//!   with `..` in it is skipped;
//! - everything goes into a new folder (named after the archive, with a
//!   number if that is taken), so nothing is overwritten;
//! - symbolic links are made last, and only those that point inside
//!   that folder, so no file is written through one;
//! - only permission bits are kept (no set-user-ID, set-group-ID or
//!   sticky bits); devices, pipes and hard links are skipped.
//!
//! Archives are read and made in memory, up to [`MAX_ARCHIVE`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The largest archive read or made (bytes), and the most it may hold
/// uncompressed.
pub const MAX_ARCHIVE: u64 = 1 << 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Zip,
    Tar,
    TarGz,
    Cpio,
    /// One gzipped file (not a tar).
    Gz,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Zip => "zip",
            Kind::Tar => "tar",
            Kind::TarGz => "tar.gz",
            Kind::Cpio => "cpio",
            Kind::Gz => "gzip",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Kind::Zip => ".zip",
            Kind::Tar => ".tar",
            Kind::TarGz => ".tar.gz",
            Kind::Cpio => ".cpio",
            Kind::Gz => ".gz",
        }
    }
}

/// What an archive file is called without its extension.
pub fn stem(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    for ext in [".tar.gz", ".tgz", ".zip", ".tar", ".cpio", ".gz"] {
        if lower.ends_with(ext) && name.len() > ext.len() {
            return &name[..name.len() - ext.len()];
        }
    }
    name
}

/// Whether a file looks like an archive, by its name.
pub fn is_archive(name: &str) -> bool {
    stem(name) != name
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    File,
    Dir,
    /// A symbolic link, to this.
    Link(String),
    /// Something not extracted: a device, a pipe, a hard link.
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The name as the archive has it.
    pub path: String,
    pub what: What,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    /// Where its data is in the (decompressed) archive, or which zip
    /// entry it is.
    at: (usize, usize),
}

#[derive(Debug)]
pub struct Archive {
    pub kind: Kind,
    pub items: Vec<Item>,
    /// The archive, decompressed for tar.gz and gz.
    raw: Vec<u8>,
    zip: Vec<slate_zip::Entry>,
}

/// Where `inner`, a part of `outer`, starts in it (0 for an empty part,
/// which may be any empty slice).
fn offset_in(outer: &[u8], inner: &[u8]) -> usize {
    if inner.is_empty() {
        return 0;
    }
    (inner.as_ptr() as usize)
        .checked_sub(outer.as_ptr() as usize)
        .filter(|o| o + inner.len() <= outer.len())
        .unwrap_or(0)
}

impl Archive {
    /// Read the archive `name` (its file name, for a lone .gz file's
    /// name) holding `data`.
    pub fn open(name: &str, data: Vec<u8>) -> Result<Archive, String> {
        let err = |e: &str| String::from(e);
        if data.len() as u64 > MAX_ARCHIVE {
            return Err(err("It is too large to open."));
        }
        if data.starts_with(b"PK") {
            let zip = slate_zip::entries(&data).map_err(|e| match e {
                slate_zip::Error::Unsupported => {
                    err("It is encrypted, split, or compressed in a way Slate doesn't read.")
                }
                _ => err("It is not a zip archive Slate can read: it may be damaged."),
            })?;
            let items = zip
                .iter()
                .enumerate()
                .map(|(i, e)| Item {
                    path: e.name.clone(),
                    what: if e.is_dir() {
                        What::Dir
                    } else if e.is_symlink() {
                        What::Link(String::new())
                    } else {
                        What::File
                    },
                    size: e.size,
                    mode: if e.mode & 0o777 != 0 {
                        e.mode & 0o777
                    } else if e.is_dir() {
                        0o755
                    } else {
                        0o644
                    },
                    mtime: e.mtime,
                    at: (i, 0),
                })
                .collect();
            let mut a = Archive { kind: Kind::Zip, items, raw: data, zip };
            // A link's target is its data.
            for i in 0..a.items.len() {
                if matches!(a.items[i].what, What::Link(_)) {
                    let t = a.data(i).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    a.items[i].what = What::Link(t);
                }
            }
            return Ok(a);
        }
        let (raw, gz) = if data.starts_with(&[0x1F, 0x8B]) {
            let (d, _) = slate_flate::gunzip(&data).map_err(|_| err("Its gzip data is damaged."))?;
            if d.len() as u64 > MAX_ARCHIVE {
                return Err(err("It is too large to open."));
            }
            (d, true)
        } else {
            (data, false)
        };
        if raw.get(257..262) == Some(b"ustar") || (!gz && is_tar_name(name)) {
            let items = tar_items(&raw)?;
            return Ok(Archive { kind: if gz { Kind::TarGz } else { Kind::Tar }, items, raw, zip: Vec::new() });
        }
        if raw.starts_with(b"070701") {
            let mut items = Vec::new();
            for e in slate_cpio::entries(&raw) {
                let e = e.map_err(|_| err("Its cpio data is damaged."))?;
                let what = match e.mode & 0o170_000 {
                    0o040_000 => What::Dir,
                    0o100_000 => What::File,
                    0o120_000 => What::Link(String::from_utf8_lossy(e.data).into_owned()),
                    _ => What::Other,
                };
                items.push(Item {
                    path: String::from(e.name),
                    what,
                    size: e.data.len() as u64,
                    mode: e.mode & 0o7777,
                    mtime: i64::from(e.mtime),
                    at: (offset_in(&raw, e.data), e.data.len()),
                });
            }
            return Ok(Archive { kind: Kind::Cpio, items, raw, zip: Vec::new() });
        }
        if gz {
            // One file, named as the archive without .gz.
            let path = String::from(stem(name.rsplit('/').next().unwrap_or(name)));
            let n = raw.len();
            let item = Item { path, what: What::File, size: n as u64, mode: 0o644, mtime: 0, at: (0, n) };
            return Ok(Archive { kind: Kind::Gz, items: alloc::vec![item], raw, zip: Vec::new() });
        }
        Err(err("It is not an archive Slate reads (zip, tar, tar.gz, cpio or gz)."))
    }

    /// Item `i`'s data.
    pub fn data(&self, i: usize) -> Result<Vec<u8>, String> {
        let it = &self.items[i];
        match self.kind {
            Kind::Zip => slate_zip::read(&self.raw, &self.zip[it.at.0]).map_err(|e| match e {
                slate_zip::Error::Crc => String::from("its data doesn't match its checksum"),
                slate_zip::Error::Unsupported => String::from("it is encrypted or compressed another way"),
                _ => String::from("it is damaged"),
            }),
            _ => Ok(self.raw[it.at.0..it.at.0 + it.at.1].to_vec()),
        }
    }

    /// The total size of the files.
    pub fn total(&self) -> u64 {
        self.items.iter().filter(|i| i.what == What::File).map(|i| i.size).sum()
    }

    /// What is directly inside folder `dir` ("" for the top; folders end
    /// with `/`): (name, is a folder, size, item index if it has one),
    /// folders first, then by name. Folders implied by deeper names are
    /// listed too.
    pub fn list(&self, dir: &str) -> Vec<(String, bool, u64, Option<usize>)> {
        let mut out: Vec<(String, bool, u64, Option<usize>)> = Vec::new();
        for (i, it) in self.items.iter().enumerate() {
            let Some(p) = safe_path(&it.path) else { continue };
            let Some(rest) = p.strip_prefix(dir) else { continue };
            if rest.is_empty() {
                continue;
            }
            match rest.split_once('/') {
                Some((first, _)) => {
                    let name = alloc::format!("{first}/");
                    if !out.iter().any(|o| o.0 == name) {
                        out.push((name, true, 0, None));
                    }
                }
                None => {
                    let folder = it.what == What::Dir;
                    let name = if folder { alloc::format!("{rest}/") } else { String::from(rest) };
                    match out.iter_mut().find(|o| o.0 == name) {
                        Some(o) => o.3 = Some(i),
                        None => out.push((name, folder, it.size, Some(i))),
                    }
                }
            }
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase())));
        out
    }
}

fn is_tar_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".tar")
}

fn tar_items(raw: &[u8]) -> Result<Vec<Item>, String> {
    let es = slate_tar::entries(raw).map_err(|_| String::from("Its tar data is damaged."))?;
    Ok(es
        .iter()
        .map(|e| {
            let what = match e.kind {
                slate_tar::Kind::File => What::File,
                slate_tar::Kind::Dir => What::Dir,
                slate_tar::Kind::Symlink => What::Link(String::from_utf8_lossy(&e.link).into_owned()),
                _ => What::Other,
            };
            Item {
                path: String::from_utf8_lossy(&e.path).into_owned(),
                what,
                size: e.data.len() as u64,
                mode: e.mode & 0o7777,
                mtime: e.mtime,
                at: (offset_in(raw, e.data), e.data.len()),
            }
        })
        .collect())
}

/// `p` as a relative path inside the destination, or None if it would
/// leave it (`..`) or is empty. Leading `/` and `./` go; folders keep a
/// trailing `/`.
pub fn safe_path(p: &str) -> Option<String> {
    let dir = p.ends_with('/');
    let mut parts = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => return None,
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return None;
    }
    let mut s = parts.join("/");
    if dir {
        s.push('/');
    }
    Some(s)
}

/// Whether link `link` (a relative path) pointing at `target` stays
/// inside the folder it is extracted to.
pub fn link_stays_inside(link: &str, target: &str) -> bool {
    if target.starts_with('/') {
        return false;
    }
    let mut depth: i32 = link.trim_end_matches('/').matches('/').count() as i32;
    for c in target.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

/// A folder or file name not yet taken in `dir`: `name`, else
/// `name (2)`, `name (3)`, ...
pub fn free_name(dir: &str, name: &str, ext: &str) -> String {
    let path = |n: &str| alloc::format!("{}/{n}{ext}", dir.trim_end_matches('/'));
    if !slate_rt::fs::exists(path(name).as_bytes()) {
        return path(name);
    }
    (2..10_000)
        .map(|k| path(&alloc::format!("{name} ({k})")))
        .find(|p| !slate_rt::fs::exists(p.as_bytes()))
        .unwrap_or_else(|| path(name))
}

/// What an extraction did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Where it went.
    pub dest: String,
    pub files: usize,
    pub folders: usize,
    pub links: usize,
    /// Names skipped, and why.
    pub skipped: Vec<(String, String)>,
}

fn mkdirs(path: &str) -> Result<(), String> {
    let mut at = String::new();
    for c in path.split('/') {
        if c.is_empty() {
            at.push('/');
            continue;
        }
        if !at.is_empty() && !at.ends_with('/') {
            at.push('/');
        }
        at.push_str(c);
        match slate_rt::fs::lstat(at.as_bytes()) {
            Ok(st) if st.mode & slate_rt::fs::S_IFMT == slate_rt::fs::S_IFDIR => {}
            Ok(_) => return Err(alloc::format!("{at} is not a folder")),
            Err(_) => slate_rt::fs::mkdir(at.as_bytes(), 0o755).map_err(|e| alloc::format!("{at}: {e}"))?,
        }
    }
    Ok(())
}

impl Archive {
    /// Extract the items `which` (all if empty) into a new folder in
    /// `dir`, named after the archive `name`. A lone gzipped file is
    /// written as a file in `dir`.
    pub fn extract(&self, name: &str, dir: &str, which: &[usize]) -> Result<Report, String> {
        let chosen: Vec<usize> = if which.is_empty() { (0..self.items.len()).collect() } else { which.to_vec() };
        let base = stem(name.rsplit('/').next().unwrap_or(name));
        let mut r = Report::default();
        if self.kind == Kind::Gz {
            let dest = free_name(dir, base, "");
            let data = self.data(0)?;
            slate_rt::fs::write_file(dest.as_bytes(), &data, 0o644).map_err(|e| alloc::format!("{dest}: {e}"))?;
            r.dest = dest;
            r.files = 1;
            return Ok(r);
        }
        let dest = free_name(dir, base, "");
        mkdirs(&dest)?;
        r.dest = dest.clone();
        let mut links = Vec::new();
        let mut times = Vec::new();
        for &i in &chosen {
            let it = &self.items[i];
            let Some(rel) = safe_path(&it.path) else {
                r.skipped.push((it.path.clone(), String::from("its name leaves the folder")));
                continue;
            };
            let full = alloc::format!("{dest}/{}", rel.trim_end_matches('/'));
            let parent = full.rsplit_once('/').map_or(dest.clone(), |(p, _)| p.to_string());
            let parent = parent.as_str();
            match &it.what {
                What::Dir => {
                    mkdirs(&full)?;
                    r.folders += 1;
                    times.push((full, it.mtime));
                }
                What::File => {
                    mkdirs(parent)?;
                    let data = match self.data(i) {
                        Ok(d) => d,
                        Err(e) => {
                            r.skipped.push((it.path.clone(), e));
                            continue;
                        }
                    };
                    let mode = (it.mode & 0o777) | 0o600;
                    if slate_rt::fs::exists(full.as_bytes()) {
                        r.skipped.push((it.path.clone(), String::from("it is in the archive twice")));
                        continue;
                    }
                    slate_rt::fs::write_file(full.as_bytes(), &data, mode)
                        .map_err(|e| alloc::format!("{full}: {e}"))?;
                    r.files += 1;
                    times.push((full, it.mtime));
                }
                What::Link(target) => {
                    if link_stays_inside(&rel, target) {
                        links.push((full, target.clone(), parent.to_string()));
                    } else {
                        r.skipped.push((it.path.clone(), String::from("its link points outside the folder")));
                    }
                }
                What::Other => r.skipped.push((it.path.clone(), String::from("it is not a file, folder or link"))),
            }
        }
        for (full, target, parent) in links {
            mkdirs(&parent)?;
            if slate_rt::fs::symlink(target.as_bytes(), full.as_bytes()).is_ok() {
                r.links += 1;
            }
        }
        // Times last: writing into a folder changes its own.
        for (path, t) in times.iter().rev() {
            if *t > 0 {
                let _ = slate_rt::fs::set_times(path.as_bytes(), None, Some(Some((*t, 0))), false);
            }
        }
        Ok(r)
    }
}

/// A file or folder to put in a new archive.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Node {
    rel: String,
    what: What,
    mode: u32,
    mtime: i64,
    data: Vec<u8>,
}

fn collect(path: &str, rel: &str, out: &mut Vec<Node>, total: &mut u64) -> Result<(), String> {
    let st = slate_rt::fs::lstat(path.as_bytes()).map_err(|e| alloc::format!("{path}: {e}"))?;
    let (mode, mtime) = (st.mode & 0o7777, st.mtime);
    match st.mode & slate_rt::fs::S_IFMT {
        slate_rt::fs::S_IFDIR => {
            out.push(Node { rel: alloc::format!("{rel}/"), what: What::Dir, mode, mtime, data: Vec::new() });
            let mut names: Vec<String> = slate_rt::fs::read_dir(path.as_bytes())
                .map_err(|e| alloc::format!("{path}: {e}"))?
                .iter()
                .map(|e| String::from(slate_rt::lossy(&e.name)))
                .collect();
            names.sort();
            for n in names {
                collect(&alloc::format!("{path}/{n}"), &alloc::format!("{rel}/{n}"), out, total)?;
            }
        }
        slate_rt::fs::S_IFLNK => {
            let t = slate_rt::fs::readlink(path.as_bytes()).map_err(|e| alloc::format!("{path}: {e}"))?;
            let t = String::from(slate_rt::lossy(&t));
            out.push(Node { rel: String::from(rel), what: What::Link(t), mode: 0o777, mtime, data: Vec::new() });
        }
        slate_rt::fs::S_IFREG => {
            *total += st.size as u64;
            if *total > MAX_ARCHIVE {
                return Err(String::from("That is more than an archive made here can hold (1 GiB)."));
            }
            let data = slate_rt::fs::read_file(path.as_bytes()).map_err(|e| alloc::format!("{path}: {e}"))?;
            out.push(Node { rel: String::from(rel), what: What::File, mode, mtime, data });
        }
        // Devices, pipes and sockets don't go in.
        _ => {}
    }
    Ok(())
}

/// An archive of `paths` (files and folders, each under its own name),
/// as `kind`.
pub fn make(kind: Kind, paths: &[String]) -> Result<Vec<u8>, String> {
    let mut nodes = Vec::new();
    let mut total = 0;
    for p in paths {
        let p = p.trim_end_matches('/');
        let name = p.rsplit('/').next().unwrap_or(p);
        collect(p, name, &mut nodes, &mut total)?;
    }
    Ok(match kind {
        Kind::Zip => {
            let mut w = slate_zip::Writer::new();
            for n in &nodes {
                match &n.what {
                    What::Dir => w.dir(&n.rel, n.mode, n.mtime),
                    What::File => w.file(&n.rel, n.mode, n.mtime, &n.data),
                    What::Link(t) => w.symlink(&n.rel, t, n.mtime),
                    What::Other => {}
                }
            }
            w.finish()
        }
        Kind::Tar | Kind::TarGz => {
            let mut b = slate_tar::Builder::new();
            for n in &nodes {
                let (kind, link) = match &n.what {
                    What::Dir => (slate_tar::Kind::Dir, Vec::new()),
                    What::Link(t) => (slate_tar::Kind::Symlink, t.as_bytes().to_vec()),
                    _ => (slate_tar::Kind::File, Vec::new()),
                };
                b.add(&slate_tar::Entry {
                    path: n.rel.trim_end_matches('/').as_bytes().to_vec(),
                    link,
                    kind,
                    mode: n.mode,
                    uid: 0,
                    gid: 0,
                    mtime: n.mtime,
                    uname: Vec::new(),
                    gname: Vec::new(),
                    dev: (0, 0),
                    data: &n.data,
                });
            }
            let tar = b.finish();
            if kind == Kind::TarGz { slate_flate::gzip(&tar, &slate_flate::Header::default()) } else { tar }
        }
        Kind::Cpio | Kind::Gz => return Err(String::from("Slate makes zip, tar and tar.gz archives.")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("slate-archive-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    fn tree(at: &str) {
        std::fs::create_dir_all(format!("{at}/notes/deep")).unwrap();
        std::fs::write(format!("{at}/notes/a.txt"), b"alpha\n").unwrap();
        std::fs::write(format!("{at}/notes/deep/b.txt"), "βeta ".repeat(500)).unwrap();
        std::os::unix::fs::symlink("a.txt", format!("{at}/notes/link")).unwrap();
    }

    #[test]
    fn made_opened_and_extracted() {
        for kind in [Kind::Zip, Kind::Tar, Kind::TarGz] {
            let s = scratch(kind.name());
            tree(&s);
            let data = make(kind, &[format!("{s}/notes")]).unwrap();
            let name = format!("notes{}", kind.extension());
            let a = Archive::open(&name, data).unwrap();
            assert_eq!(a.kind, kind);
            let top: Vec<String> = a.list("").into_iter().map(|e| e.0).collect();
            assert_eq!(top, ["notes/"]);
            let inside: Vec<(String, bool)> = a.list("notes/").into_iter().map(|e| (e.0, e.1)).collect();
            assert_eq!(inside, [("deep/".into(), true), ("a.txt".into(), false), ("link".into(), false)]);
            let r = a.extract(&name, &s, &[]).unwrap();
            assert_eq!((r.files, r.links, r.skipped.len()), (2, 1, 0), "{kind:?}");
            let out = format!("{s}/notes/notes");
            assert_eq!(r.dest, format!("{s}/notes (2)"), "notes was taken");
            assert_eq!(std::fs::read(format!("{}/notes/deep/b.txt", r.dest)).unwrap(), "βeta ".repeat(500).as_bytes());
            assert_eq!(std::fs::read_link(format!("{}/notes/link", r.dest)).unwrap().to_string_lossy(), "a.txt");
            let _ = out;
            std::fs::remove_dir_all(&s).unwrap();
        }
    }

    #[test]
    fn hostile_archives_stay_in_their_folder() {
        let s = scratch("hostile");
        let mut b = slate_tar::Builder::new();
        let e = |path: &str, kind, link: &str, data: &'static [u8]| slate_tar::Entry {
            path: path.as_bytes().to_vec(),
            link: link.as_bytes().to_vec(),
            kind,
            mode: 0o4755,
            uid: 0,
            gid: 0,
            mtime: 0,
            uname: Vec::new(),
            gname: Vec::new(),
            dev: (0, 0),
            data,
        };
        b.add(&e("../escape.txt", slate_tar::Kind::File, "", b"no"));
        b.add(&e("/etc/abs.txt", slate_tar::Kind::File, "", b"inside"));
        b.add(&e("ok/out", slate_tar::Kind::Symlink, "../../outside", b""));
        b.add(&e("ok/etc", slate_tar::Kind::Symlink, "/etc", b""));
        b.add(&e("ok/fine", slate_tar::Kind::Symlink, "../etc/abs.txt", b""));
        b.add(&e("ok/setuid", slate_tar::Kind::File, "", b"x"));
        let a = Archive::open("bad.tar", b.finish()).unwrap();
        let r = a.extract("bad.tar", &s, &[]).unwrap();
        let skipped: Vec<&str> = r.skipped.iter().map(|x| x.0.as_str()).collect();
        assert_eq!(skipped, ["../escape.txt", "ok/out", "ok/etc"]);
        assert!(!std::path::Path::new(&format!("{s}/escape.txt")).exists());
        assert_eq!(std::fs::read(format!("{s}/bad/etc/abs.txt")).unwrap(), b"inside");
        assert_eq!(std::fs::read(format!("{s}/bad/ok/fine")).unwrap(), b"inside");
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(format!("{s}/bad/ok/setuid")).unwrap().permissions().mode();
        assert_eq!(m & 0o7777, 0o755, "no set-user-ID");
        std::fs::remove_dir_all(&s).unwrap();
        assert_eq!(safe_path("./a//b/"), Some("a/b/".into()));
        assert_eq!(safe_path("a/../b"), None);
        assert!(link_stays_inside("a/b", "../c") && !link_stays_inside("a", "../c"));
    }

    #[test]
    fn names_and_a_lone_gzip() {
        assert_eq!((stem("photos.tar.gz"), stem("a.TGZ"), stem("x.zip"), stem("plain")), ("photos", "a", "x", "plain"));
        assert!(is_archive("logs.tar") && !is_archive("notes.txt"));
        let gz = slate_flate::gzip(b"one file\n", &slate_flate::Header::default());
        let a = Archive::open("/tmp/readme.txt.gz", gz).unwrap();
        assert_eq!((a.kind, a.items[0].path.as_str()), (Kind::Gz, "readme.txt"));
        assert_eq!(a.data(0).unwrap(), b"one file\n");
        assert!(Archive::open("x.bin", b"nothing".to_vec()).is_err());
    }
}
