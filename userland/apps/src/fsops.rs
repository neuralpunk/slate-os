// SPDX-License-Identifier: MIT OR Apache-2.0

//! What Files does to files (ADR 0108), apart from its window: listing a
//! folder, copying and moving (across disks too), names that don't
//! clash, the trash as freedesktop.org's Trash specification (1.0)
//! describes it, the disks mounted, and which of Slate's apps opens a
//! file.
//!
//! Copies and moves never overwrite: a name that is taken gets
//! " (copy)", " (copy 2)" and so on. Links are copied as links, never
//! followed, and a folder is never copied into itself. Files are copied
//! a mebibyte at a time, saying how far they are.
//!
//! Each disk has its own trash (the specification's `$topdir/.Trash-UID`)
//! where one can be made, so trashing never copies a file across disks.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_rt::fs::{self, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Folder,
    File,
    Link,
    /// A device, pipe or socket.
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub mtime: i64,
    pub mode: u32,
    /// A link's target, and whether it leads to a folder.
    pub target: Option<String>,
    pub to_folder: bool,
}

impl Entry {
    pub fn hidden(&self) -> bool {
        self.name.starts_with('.')
    }

    /// Whether opening it goes into it.
    pub fn is_folder(&self) -> bool {
        self.kind == Kind::Folder || self.to_folder
    }
}

pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') { alloc::format!("{dir}{name}") } else { alloc::format!("{dir}/{name}") }
}

pub fn parent(path: &str) -> String {
    match path.trim_end_matches('/').rsplit_once('/') {
        Some(("", _)) | None => String::from("/"),
        Some((p, _)) => String::from(p),
    }
}

pub fn base(path: &str) -> &str {
    let t = path.trim_end_matches('/');
    if t.is_empty() { "/" } else { t.rsplit('/').next().unwrap_or(t) }
}

fn err(path: &str, e: slate_rt::Errno) -> String {
    alloc::format!("{}: {e}", base(path))
}

/// A folder's entries (`.` and `..` left out), unsorted.
pub fn list(dir: &str) -> Result<Vec<Entry>, String> {
    let names = fs::read_dir(dir.as_bytes()).map_err(|e| err(dir, e))?;
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let name = String::from(slate_rt::lossy(&n.name));
        let path = join(dir, &name);
        let Ok(st) = fs::lstat(path.as_bytes()) else { continue };
        let kind = match st.mode & S_IFMT {
            S_IFDIR => Kind::Folder,
            S_IFREG => Kind::File,
            S_IFLNK => Kind::Link,
            _ => Kind::Other,
        };
        let (target, to_folder) = if kind == Kind::Link {
            let t = fs::readlink(path.as_bytes()).ok().map(|t| String::from(slate_rt::lossy(&t)));
            let dir = fs::stat(path.as_bytes()).is_ok_and(|s| s.mode & S_IFMT == S_IFDIR);
            (t, dir)
        } else {
            (None, false)
        };
        out.push(Entry { name, kind, size: st.size.max(0) as u64, mtime: st.mtime, mode: st.mode, target, to_folder });
    }
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Name,
    Size,
    Modified,
}

/// Folders first, then by `sort` (names ignoring case, numbers in names
/// by their value: "2" before "10").
pub fn sort(entries: &mut [Entry], sort: Sort, reverse: bool) {
    entries.sort_by(|a, b| {
        let by = match sort {
            Sort::Name => natural(&a.name, &b.name),
            Sort::Size => a.size.cmp(&b.size).then_with(|| natural(&a.name, &b.name)),
            Sort::Modified => b.mtime.cmp(&a.mtime).then_with(|| natural(&a.name, &b.name)),
        };
        b.is_folder().cmp(&a.is_folder()).then(if reverse { by.reverse() } else { by })
    });
}

/// Names compared as people read them: case ignored, runs of digits by
/// value.
pub fn natural(a: &str, b: &str) -> core::cmp::Ordering {
    let (mut x, mut y) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, _) => return core::cmp::Ordering::Less,
            (_, None) => return core::cmp::Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let take = |it: &mut core::iter::Peekable<core::str::Chars<'_>>| {
                    let mut s = String::new();
                    while let Some(c) = it.peek().copied().filter(char::is_ascii_digit) {
                        s.push(c);
                        it.next();
                    }
                    s
                };
                let (m, n) = (take(&mut x), take(&mut y));
                let (m, n) = (m.trim_start_matches('0'), n.trim_start_matches('0'));
                let o = m.len().cmp(&n.len()).then_with(|| m.cmp(n));
                if o.is_ne() {
                    return o;
                }
            }
            (Some(c), Some(d)) => {
                let o = c.to_lowercase().cmp(d.to_lowercase());
                if o.is_ne() {
                    return o;
                }
                x.next();
                y.next();
            }
        }
    }
}

/// A name for `name` in `dir` that isn't taken: itself, else with
/// `word` ("copy") before its extension: "a (copy).txt", "a (copy 2).txt".
pub fn free_name(dir: &str, name: &str, word: &str) -> String {
    if !exists(&join(dir, name)) {
        return String::from(name);
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !name.ends_with('.') => (s, alloc::format!(".{e}")),
        _ => (name, String::new()),
    };
    for k in 1..10_000 {
        let n =
            if k == 1 { alloc::format!("{stem} ({word}){ext}") } else { alloc::format!("{stem} ({word} {k}){ext}") };
        if !exists(&join(dir, &n)) {
            return n;
        }
    }
    String::from(name)
}

fn exists(path: &str) -> bool {
    fs::lstat(path.as_bytes()).is_ok()
}

/// The bytes of the files in `path` (itself, or everything in a folder;
/// links not followed), stopping at `limit` entries: (bytes, files and
/// folders counted, whether it stopped short).
pub fn size_of(path: &str, limit: usize) -> (u64, usize, bool) {
    let mut total = (0u64, 0usize, false);
    let mut stack = alloc::vec![String::from(path)];
    while let Some(p) = stack.pop() {
        if total.1 >= limit {
            total.2 = true;
            break;
        }
        let Ok(st) = fs::lstat(p.as_bytes()) else { continue };
        total.1 += 1;
        match st.mode & S_IFMT {
            S_IFREG => total.0 += st.size.max(0) as u64,
            S_IFDIR => {
                for e in fs::read_dir(p.as_bytes()).unwrap_or_default() {
                    stack.push(join(&p, &String::from(slate_rt::lossy(&e.name))));
                }
            }
            _ => {}
        }
    }
    total
}

/// How much is copied at a time.
const CHUNK: usize = 1 << 20;

/// Copy `from` (a file, a link or a whole folder) to `to`, which must not
/// exist.
pub fn copy(from: &str, to: &str) -> Result<(), String> {
    copy_with(from, to, &mut |_| {})
}

/// [`copy`], telling `moved` of each piece of a file's bytes copied.
pub fn copy_with(from: &str, to: &str, moved: &mut dyn FnMut(u64)) -> Result<(), String> {
    let st = fs::lstat(from.as_bytes()).map_err(|e| err(from, e))?;
    match st.mode & S_IFMT {
        S_IFDIR => {
            // Never into itself (a/ into a/b/).
            let (f, t) =
                (alloc::format!("{}/", from.trim_end_matches('/')), alloc::format!("{}/", to.trim_end_matches('/')));
            if t.starts_with(&f) {
                return Err(alloc::format!("{} can't go inside itself", base(from)));
            }
            fs::mkdir(to.as_bytes(), st.mode & 0o7777).map_err(|e| err(to, e))?;
            let mut names: Vec<String> = fs::read_dir(from.as_bytes())
                .map_err(|e| err(from, e))?
                .iter()
                .map(|e| String::from(slate_rt::lossy(&e.name)))
                .collect();
            names.sort();
            for n in names {
                copy_with(&join(from, &n), &join(to, &n), moved)?;
            }
            let _ = fs::set_times(to.as_bytes(), None, Some(Some((st.mtime, 0))), false);
        }
        S_IFLNK => {
            let t = fs::readlink(from.as_bytes()).map_err(|e| err(from, e))?;
            fs::symlink(&t, to.as_bytes()).map_err(|e| err(to, e))?;
        }
        S_IFREG => {
            copy_file(from, to, st.mode & 0o7777, moved)?;
            let _ = fs::chmod(to.as_bytes(), st.mode & 0o7777);
            let _ = fs::set_times(to.as_bytes(), None, Some(Some((st.mtime, 0))), false);
        }
        _ => return Err(alloc::format!("{} is not a file, folder or link", base(from))),
    }
    Ok(())
}

/// A regular file's bytes, a piece at a time, into a new file `to`; a
/// failed copy leaves nothing behind.
fn copy_file(from: &str, to: &str, mode: u32, moved: &mut dyn FnMut(u64)) -> Result<(), String> {
    let src = fs::open(from.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| err(from, e))?;
    let dst = match fs::open(to.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, mode) {
        Ok(fd) => fd,
        Err(slate_rt::Errno::EEXIST) => {
            let _ = slate_rt::io::close(src);
            return Err(alloc::format!("{} is there already", base(to)));
        }
        Err(e) => {
            let _ = slate_rt::io::close(src);
            return Err(err(to, e));
        }
    };
    let mut buf = alloc::vec![0u8; CHUNK];
    let r = loop {
        match slate_rt::io::read(src, &mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = slate_rt::io::write_all(dst, &buf[..n]) {
                    break Err(err(to, e));
                }
                moved(n as u64);
            }
            Err(slate_rt::Errno::EINTR) => {}
            Err(e) => break Err(err(from, e)),
        }
    };
    let _ = slate_rt::io::close(src);
    let closed = slate_rt::io::close(dst).map_err(|e| err(to, e));
    let r = r.and(closed);
    if r.is_err() {
        let _ = fs::unlink(to.as_bytes());
    }
    r
}

/// Remove `path`, a whole folder included.
pub fn remove(path: &str) -> Result<(), String> {
    let st = fs::lstat(path.as_bytes()).map_err(|e| err(path, e))?;
    if st.mode & S_IFMT == S_IFDIR {
        for n in fs::read_dir(path.as_bytes()).map_err(|e| err(path, e))? {
            remove(&join(path, &String::from(slate_rt::lossy(&n.name))))?;
        }
        fs::rmdir(path.as_bytes()).map_err(|e| err(path, e))
    } else {
        fs::unlink(path.as_bytes()).map_err(|e| err(path, e))
    }
}

/// Move `from` to `to` (which must not exist): a rename, or a copy and a
/// removal across disks.
pub fn move_to(from: &str, to: &str) -> Result<(), String> {
    move_with(from, to, &mut |_| {})
}

/// [`move_to`], telling `moved` of the bytes a copy across disks moves.
pub fn move_with(from: &str, to: &str, moved: &mut dyn FnMut(u64)) -> Result<(), String> {
    if exists(to) {
        return Err(alloc::format!("{} is there already", base(to)));
    }
    match fs::rename(from.as_bytes(), to.as_bytes()) {
        Ok(()) => Ok(()),
        Err(slate_rt::Errno::EXDEV) => {
            if let Err(e) = copy_with(from, to, moved) {
                // Half a copy is no copy: the original stays whole.
                let _ = remove(to);
                return Err(e);
            }
            remove(from)
        }
        Err(e) => Err(err(from, e)),
    }
}

/// Whether moving `from` into `dir` is a rename (the same disk) rather
/// than a copy.
pub fn same_disk(from: &str, dir: &str) -> bool {
    match (fs::lstat(from.as_bytes()), fs::stat(dir.as_bytes())) {
        (Ok(a), Ok(b)) => a.dev == b.dev,
        _ => false,
    }
}

/// A trash folder (freedesktop.org's Trash specification 1.0): `files/`
/// holds what was trashed, `info/NAME.trashinfo` where it came from and
/// when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trash {
    pub dir: String,
    /// A disk's trash: the folder its paths are relative to (the
    /// specification's `$topdir`); None for the home trash.
    pub top: Option<String>,
}

fn mkdirs(path: &str) {
    let mut at = String::new();
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at.push('/');
        at.push_str(c);
        let _ = fs::mkdir(at.as_bytes(), 0o700);
    }
}

/// Percent-encoding for the info file's Path (RFC 2396 escaping, as the
/// specification asks): everything but unreserved characters and `/`.
fn escape(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()/".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&alloc::format!("%{b:02X}"));
        }
    }
    out
}

fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Some(v) = core::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Something in the trash: its name there, where it came from, when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trashed {
    pub name: String,
    pub from: String,
    pub date: String,
}

impl Trash {
    /// The person's: `$XDG_DATA_HOME/Trash`, else `~/.local/share/Trash`
    /// (the specification's "home trash").
    pub fn home() -> Option<Trash> {
        let var = |n: &[u8]| slate_rt::env::var(n).map(|v| String::from(slate_rt::lossy(&v))).filter(|v| !v.is_empty());
        let dir = var(b"XDG_DATA_HOME")
            .map(|d| join(&d, "Trash"))
            .or_else(|| var(b"HOME").map(|h| join(&h, ".local/share/Trash")))?;
        Some(Trash { dir, top: None })
    }

    /// The trash of the disk mounted at `top`, for user `uid`:
    /// `$topdir/.Trash-UID` (the specification's second kind; the shared
    /// `.Trash` with a sticky bit isn't used).
    pub fn on_disk(top: &str, uid: u32) -> Trash {
        Trash { dir: join(top, &alloc::format!(".Trash-{uid}")), top: Some(String::from(top)) }
    }

    /// Whether `path` is in this trash.
    pub fn holds(&self, path: &str) -> bool {
        parent(path) == self.files()
    }

    fn files(&self) -> String {
        join(&self.dir, "files")
    }

    fn info(&self, name: &str) -> String {
        join(&join(&self.dir, "info"), &alloc::format!("{name}.trashinfo"))
    }

    /// Move `path` to the trash, with its info file; the name it has
    /// there.
    pub fn put(&self, path: &str, now: i64) -> Result<String, String> {
        mkdirs(&self.files());
        mkdirs(&join(&self.dir, "info"));
        // A disk's trash keeps paths relative to its top (the
        // specification's choice for them).
        let shown = match &self.top {
            Some(top) => path
                .strip_prefix(top.trim_end_matches('/'))
                .and_then(|r| r.strip_prefix('/'))
                .map_or_else(|| String::from(path), String::from),
            None => String::from(path),
        };
        let name = free_name(&self.files(), base(path), "trashed");
        let tm = slate_rt::time::gmtime(now);
        // Path and DeletionDate (local time in the specification; the
        // system's clock, UTC, here).
        let info = alloc::format!(
            "[Trash Info]\nPath={}\nDeletionDate={:04}-{:02}-{:02}T{:02}:{:02}:{:02}\n",
            escape(&shown),
            tm.year,
            tm.month,
            tm.day,
            tm.hour,
            tm.min,
            tm.sec
        );
        let info_path = self.info(&name);
        fs::write_file(info_path.as_bytes(), info.as_bytes(), 0o600).map_err(|e| err(&info_path, e))?;
        if let Err(e) = move_to(path, &join(&self.files(), &name)) {
            let _ = fs::unlink(info_path.as_bytes());
            return Err(e);
        }
        Ok(name)
    }

    /// What is in it, the latest first.
    pub fn list(&self) -> Vec<Trashed> {
        let mut out: Vec<Trashed> = fs::read_dir(self.files().as_bytes())
            .map(|es| {
                es.iter()
                    .map(|e| {
                        let name = String::from(slate_rt::lossy(&e.name));
                        let info = fs::read_file(self.info(&name).as_bytes())
                            .map(|b| String::from(slate_rt::lossy(&b)))
                            .unwrap_or_default();
                        let field = |k: &str| info.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
                        let mut from = unescape(&field("Path="));
                        if let Some(top) = self.top.as_deref().filter(|_| !from.is_empty() && !from.starts_with('/')) {
                            from = join(top, &from);
                        }
                        Trashed { name, from, date: field("DeletionDate=") }
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.name.cmp(&b.name)));
        out
    }

    /// Where something in the trash is.
    pub fn path_of(&self, name: &str) -> String {
        join(&self.files(), name)
    }

    /// Put `name` back where it came from (under another name if that
    /// is taken); where it went.
    pub fn restore(&self, name: &str) -> Result<String, String> {
        let item = self.list().into_iter().find(|x| x.name == name).ok_or("it is no longer in the trash")?;
        if item.from.is_empty() {
            return Err(String::from("its first place is not known"));
        }
        let dir = parent(&item.from);
        mkdirs(&dir);
        let to = join(&dir, &free_name(&dir, base(&item.from), "restored"));
        move_to(&join(&self.files(), name), &to)?;
        let _ = fs::unlink(self.info(name).as_bytes());
        Ok(to)
    }

    /// Delete `name` from the trash for good.
    pub fn delete(&self, name: &str) -> Result<(), String> {
        remove(&join(&self.files(), name))?;
        let _ = fs::unlink(self.info(name).as_bytes());
        Ok(())
    }
}

/// The trash `path` goes to: its disk's own when it is on a mounted disk
/// other than home's (from `mounts`), else home's.
pub fn trash_for(path: &str, home: &Trash, home_dir: &str, mounts: &[Mount], uid: u32) -> Trash {
    let dev = |p: &str| fs::lstat(p.as_bytes()).ok().map(|s| s.dev);
    let here = dev(path);
    if here.is_none() || here == dev(home_dir) {
        return home.clone();
    }
    let top = mounts
        .iter()
        .filter(|m| path.starts_with(&alloc::format!("{}/", m.at.trim_end_matches('/'))))
        .max_by_key(|m| m.at.len());
    match top {
        Some(m) if dev(&m.at) == here => Trash::on_disk(&m.at, uid),
        _ => home.clone(),
    }
}

/// A disk mounted: where, what device, and its file system.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub at: String,
    pub device: String,
    pub fs: String,
}

/// The disks worth showing, from /proc/mounts' text: real file systems
/// (not /proc, /sys, /dev, /run and the like), the root first.
pub fn mounts(text: &str) -> Vec<Mount> {
    const REAL: [&str; 6] = ["slatefs", "ext4", "ext3", "ext2", "vfat", "iso9660"];
    let mut out: Vec<Mount> = text
        .lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let (device, at, fs) = (w.next()?, w.next()?, w.next()?);
            let at = at.replace("\\040", " ");
            (REAL.contains(&fs) && !at.starts_with("/boot")).then(|| Mount {
                at,
                device: device.to_string(),
                fs: fs.to_string(),
            })
        })
        .collect();
    out.sort_by(|a, b| (a.at != "/").cmp(&(b.at != "/")).then_with(|| a.at.cmp(&b.at)));
    out.dedup_by(|a, b| a.at == b.at);
    out
}

/// Which of Slate's apps opens a file, by its name and its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opener {
    Images,
    Archives,
    Calendar,
    Contacts,
    Text,
    /// Nothing in Slate opens it.
    None,
}

impl Opener {
    pub fn program(self) -> Option<&'static str> {
        match self {
            Opener::Images => Some("/bin/image-viewer"),
            Opener::Archives => Some("/bin/archive-manager"),
            Opener::Calendar => Some("/bin/calendar"),
            Opener::Contacts => Some("/bin/contacts"),
            Opener::Text => Some("/bin/text-editor"),
            Opener::None => None,
        }
    }

    pub fn kind_name(self) -> &'static str {
        match self {
            Opener::Images => "picture",
            Opener::Archives => "archive",
            Opener::Calendar => "calendar",
            Opener::Contacts => "contacts",
            Opener::Text => "text",
            Opener::None => "file",
        }
    }
}

pub fn opener(name: &str, head: &[u8]) -> Opener {
    if crate::viewer::is_image(name) || slate_image::format(head).is_some() {
        Opener::Images
    } else if name.to_ascii_lowercase().ends_with(".ics") || head.starts_with(b"BEGIN:VCALENDAR") {
        Opener::Calendar
    } else if name.to_ascii_lowercase().ends_with(".vcf") || head.starts_with(b"BEGIN:VCARD") {
        Opener::Contacts
    } else if crate::archive::is_archive(name) || head.starts_with(b"PK\x03\x04") || head.starts_with(&[0x1F, 0x8B]) {
        Opener::Archives
    } else if !head.contains(&0) && (core::str::from_utf8(head).is_ok() || head.len() >= 4096) {
        // Text: no NUL bytes, and UTF-8 (a full read may end inside a
        // character).
        Opener::Text
    } else {
        Opener::None
    }
}

/// The first bytes of a file, to know what it is.
pub fn head(path: &str) -> Vec<u8> {
    let Ok(fd) = fs::open(path.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0) else { return Vec::new() };
    let mut buf = alloc::vec![0u8; 4096];
    let n = slate_rt::io::read(fd, &mut buf).unwrap_or(0);
    let _ = slate_rt::io::close(fd);
    buf.truncate(n);
    buf
}

/// Start `program` with `args`, on its own: twice forked, so it is
/// nobody's child to wait for, in a session of its own.
pub fn start(program: &str, args: &[String]) -> Result<(), String> {
    let mut argv: Vec<Vec<u8>> = alloc::vec![program.as_bytes().to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    let env: Vec<Vec<u8>> = slate_rt::env::vars().to_vec();
    match slate_rt::process::fork() {
        Ok(0) => {
            let _ = slate_rt::process::setsid();
            match slate_rt::process::fork() {
                Ok(0) => {
                    let e = slate_rt::process::execve(program.as_bytes(), &argv, &env);
                    slate_rt::eprintln!("files: {program}: {e}");
                    slate_rt::process::exit_now(127);
                }
                _ => slate_rt::process::exit_now(0),
            }
        }
        Ok(pid) => {
            let _ = slate_rt::process::wait(pid, 0);
            Ok(())
        }
        Err(e) => Err(alloc::format!("starting {}: {e}", base(program))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("slate-files-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn listing_and_sorting() {
        let s = scratch("list");
        for n in ["b10.txt", "B2.txt", "a.txt", ".hidden"] {
            std::fs::write(format!("{s}/{n}"), n).unwrap();
        }
        std::fs::create_dir(format!("{s}/zed")).unwrap();
        std::os::unix::fs::symlink("zed", format!("{s}/link")).unwrap();
        let mut es = list(&s).unwrap();
        sort(&mut es, Sort::Name, false);
        let names: Vec<&str> = es.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["link", "zed", ".hidden", "a.txt", "B2.txt", "b10.txt"]);
        let link = &es[0];
        assert!(link.kind == Kind::Link && link.to_folder && link.target.as_deref() == Some("zed"));
        assert!(es[2].hidden());
        sort(&mut es, Sort::Size, true);
        assert_eq!(es[2].name, "b10.txt", "the largest file first, after the folders");
        std::fs::remove_dir_all(&s).unwrap();
    }

    #[test]
    fn copies_moves_and_names() {
        let s = scratch("ops");
        std::fs::create_dir_all(format!("{s}/a/b")).unwrap();
        std::fs::write(format!("{s}/a/b/f.txt"), b"data").unwrap();
        std::os::unix::fs::symlink("b/f.txt", format!("{s}/a/l")).unwrap();
        assert_eq!(free_name(&s, "a", "copy"), "a (copy)");
        copy(&format!("{s}/a"), &format!("{s}/a (copy)")).unwrap();
        assert_eq!(std::fs::read(format!("{s}/a (copy)/b/f.txt")).unwrap(), b"data");
        assert_eq!(std::fs::read_link(format!("{s}/a (copy)/l")).unwrap().to_string_lossy(), "b/f.txt");
        assert_eq!(free_name(&s, "a", "copy"), "a (copy 2)");
        std::fs::write(format!("{s}/n.tar.gz"), b"").unwrap();
        assert_eq!(free_name(&s, "n.tar.gz", "copy"), "n.tar (copy).gz");
        assert!(copy(&format!("{s}/a"), &format!("{s}/a/b/inside")).is_err(), "not into itself");
        move_to(&format!("{s}/a (copy)"), &format!("{s}/moved")).unwrap();
        assert!(std::path::Path::new(&format!("{s}/moved/b/f.txt")).exists());
        assert!(move_to(&format!("{s}/moved"), &format!("{s}/a")).is_err(), "never over something");
        remove(&format!("{s}/moved")).unwrap();
        assert!(!std::path::Path::new(&format!("{s}/moved")).exists());
        std::fs::remove_dir_all(&s).unwrap();
    }

    #[test]
    fn the_trash() {
        let s = scratch("trash");
        let t = Trash { dir: format!("{s}/data/Trash"), top: None };
        // A name with a space and a % to escape.
        std::fs::write(format!("{s}/a b%.txt"), b"x").unwrap();
        let name = t.put(&format!("{s}/a b%.txt"), 1_792_879_170).unwrap();
        assert_eq!(name, "a b%.txt");
        let info = std::fs::read_to_string(format!("{s}/data/Trash/info/a b%.txt.trashinfo")).unwrap();
        assert!(info.contains("a%20b%25.txt") && info.contains("DeletionDate=2026-10-24T"), "{info}");
        let l = t.list();
        assert_eq!((l[0].name.as_str(), l[0].from.clone()), ("a b%.txt", format!("{s}/a b%.txt")));
        // The same name again: kept apart in the trash.
        std::fs::write(format!("{s}/a b%.txt"), b"y").unwrap();
        assert_eq!(t.put(&format!("{s}/a b%.txt"), 1_792_879_171).unwrap(), "a b% (trashed).txt");
        // Restored to its place; and with something there, beside it.
        assert_eq!(t.restore("a b%.txt").unwrap(), format!("{s}/a b%.txt"));
        assert_eq!(std::fs::read(format!("{s}/a b%.txt")).unwrap(), b"x");
        let again = t.put(&format!("{s}/a b%.txt"), 1_792_879_172).unwrap();
        std::fs::write(format!("{s}/a b%.txt"), b"z").unwrap();
        assert_eq!(t.restore(&again).unwrap(), format!("{s}/a b% (restored).txt"));
        t.delete("a b% (trashed).txt").unwrap();
        assert!(t.list().is_empty());
        std::fs::remove_dir_all(&s).unwrap();
    }

    #[test]
    fn a_disks_trash_and_sizes() {
        let s = scratch("disktrash");
        std::fs::create_dir_all(format!("{s}/disk/notes")).unwrap();
        std::fs::write(format!("{s}/disk/notes/a.txt"), b"abc").unwrap();
        let t = Trash::on_disk(&format!("{s}/disk"), 1000);
        assert_eq!(t.dir, format!("{s}/disk/.Trash-1000"));
        let name = t.put(&format!("{s}/disk/notes/a.txt"), 1_792_879_170).unwrap();
        // Its path relative to the disk's top, as the specification says.
        let info = std::fs::read_to_string(format!("{s}/disk/.Trash-1000/info/a.txt.trashinfo")).unwrap();
        assert!(info.contains("Path=notes/a.txt\n"), "{info}");
        assert_eq!(t.list()[0].from, format!("{s}/disk/notes/a.txt"));
        assert!(t.holds(&t.path_of(&name)));
        assert_eq!(t.restore(&name).unwrap(), format!("{s}/disk/notes/a.txt"));
        // On the same disk as home, home's trash.
        let home = Trash { dir: format!("{s}/h/Trash"), top: None };
        assert_eq!(trash_for(&format!("{s}/disk/notes/a.txt"), &home, &s, &[], 1000), home);
        // (The trash's own folders count too.)
        assert_eq!(size_of(&format!("{s}/disk"), 100), (3, 6, false));
        assert!(size_of(&format!("{s}/disk"), 2).2, "stopped short");
        // A failed move across disks would leave the original whole;
        // within one it is a rename.
        assert!(same_disk(&format!("{s}/disk/notes/a.txt"), &s));
        std::fs::remove_dir_all(&s).unwrap();
    }

    #[test]
    fn mounts_and_openers() {
        let text = "/dev/dm-0 / slatefs rw 0 0\nproc /proc proc rw 0 0\n/dev/vdc /mnt/My\\040Disk ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n/dev/vda1 /boot/efi vfat rw 0 0\n";
        let m = mounts(text);
        let ats: Vec<&str> = m.iter().map(|x| x.at.as_str()).collect();
        assert_eq!(ats, ["/", "/mnt/My Disk"]);
        assert_eq!(opener("x.png", b""), Opener::Images);
        assert_eq!(opener("noext", &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]), Opener::Images);
        assert_eq!(opener("a.tar.gz", b""), Opener::Archives);
        assert_eq!(opener("notes", b"hello\n"), Opener::Text);
        assert_eq!(opener("work.ICS", b""), Opener::Calendar);
        assert_eq!(opener("export", b"BEGIN:VCARD\r\n"), Opener::Contacts);
        assert_eq!(opener("blob", &[0, 1, 2]), Opener::None);
        assert!(natural("file2", "file10").is_lt() && natural("A", "b").is_lt());
        assert_eq!(unescape(&escape("/a b/ü%")), "/a b/ü%");
    }
}
