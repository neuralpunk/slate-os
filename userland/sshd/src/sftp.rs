// SPDX-License-Identifier: MIT OR Apache-2.0

//! sftp-server: SFTP version 3 (draft-ietf-secsh-filexfer-02), with the
//! extensions OpenSSH's PROTOCOL file documents that its `sftp` and `scp`
//! use (ADR 0061). It runs as the user, on the session's standard input
//! and output, like any session program; the server starts it for the
//! `sftp` subsystem.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, fs, io};

use crate::wire::{Reader, Writer};

// Packet types (filexfer-02 §3).
const FXP_INIT: u8 = 1;
const FXP_VERSION: u8 = 2;
const FXP_OPEN: u8 = 3;
const FXP_CLOSE: u8 = 4;
const FXP_READ: u8 = 5;
const FXP_WRITE: u8 = 6;
const FXP_LSTAT: u8 = 7;
const FXP_FSTAT: u8 = 8;
const FXP_SETSTAT: u8 = 9;
const FXP_FSETSTAT: u8 = 10;
const FXP_OPENDIR: u8 = 11;
const FXP_READDIR: u8 = 12;
const FXP_REMOVE: u8 = 13;
const FXP_MKDIR: u8 = 14;
const FXP_RMDIR: u8 = 15;
const FXP_REALPATH: u8 = 16;
const FXP_STAT: u8 = 17;
const FXP_RENAME: u8 = 18;
const FXP_READLINK: u8 = 19;
const FXP_SYMLINK: u8 = 20;
const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;
const FXP_ATTRS: u8 = 105;
const FXP_EXTENDED: u8 = 200;
const FXP_EXTENDED_REPLY: u8 = 201;

// Status codes (§7).
pub const FX_OK: u32 = 0;
pub const FX_EOF: u32 = 1;
pub const FX_NO_SUCH_FILE: u32 = 2;
pub const FX_PERMISSION_DENIED: u32 = 3;
pub const FX_FAILURE: u32 = 4;
pub const FX_BAD_MESSAGE: u32 = 5;
pub const FX_OP_UNSUPPORTED: u32 = 8;

// Open flags (§6.3).
const FXF_READ: u32 = 1;
const FXF_WRITE: u32 = 2;
const FXF_APPEND: u32 = 4;
const FXF_CREAT: u32 = 8;
const FXF_TRUNC: u32 = 0x10;
const FXF_EXCL: u32 = 0x20;

// Attribute flags (§5).
const ATTR_SIZE: u32 = 1;
const ATTR_UIDGID: u32 = 2;
const ATTR_PERMISSIONS: u32 = 4;
const ATTR_ACMODTIME: u32 = 8;
const ATTR_EXTENDED: u32 = 0x8000_0000;

/// The largest packet accepted, and the largest read or write (the
/// `limits@openssh.com` answer).
const MAX_PACKET: usize = 256 * 1024 + 1024;
const MAX_IO: usize = 255 * 1024;
const MAX_HANDLES: usize = 256;

/// The extensions announced in VERSION (name, version).
const EXTENSIONS: [(&[u8], &[u8]); 8] = [
    (b"posix-rename@openssh.com", b"1"),
    (b"statvfs@openssh.com", b"2"),
    (b"fstatvfs@openssh.com", b"2"),
    (b"hardlink@openssh.com", b"1"),
    (b"fsync@openssh.com", b"1"),
    (b"lsetstat@openssh.com", b"1"),
    (b"limits@openssh.com", b"1"),
    (b"expand-path@openssh.com", b"1"),
];

#[derive(Debug)]
enum Handle {
    File { fd: i32, path: Vec<u8> },
    Dir { entries: Vec<Vec<u8>>, path: Vec<u8> },
}

/// File attributes as SFTP carries them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attrs {
    pub size: Option<u64>,
    pub ids: Option<(u32, u32)>,
    pub mode: Option<u32>,
    pub times: Option<(u32, u32)>,
}

impl Attrs {
    fn of(st: &fs::Stat) -> Attrs {
        Attrs {
            size: Some(st.size.max(0) as u64),
            ids: Some((st.uid, st.gid)),
            mode: Some(st.mode),
            times: Some((st.atime as u32, st.mtime as u32)),
        }
    }

    fn write(&self, w: &mut Writer) {
        let flags = self.size.map_or(0, |_| ATTR_SIZE)
            | self.ids.map_or(0, |_| ATTR_UIDGID)
            | self.mode.map_or(0, |_| ATTR_PERMISSIONS)
            | self.times.map_or(0, |_| ATTR_ACMODTIME);
        w.u32(flags);
        if let Some(s) = self.size {
            w.u64(s);
        }
        if let Some((u, g)) = self.ids {
            w.u32(u).u32(g);
        }
        if let Some(m) = self.mode {
            w.u32(m);
        }
        if let Some((a, m)) = self.times {
            w.u32(a).u32(m);
        }
    }

    fn read(r: &mut Reader) -> Result<Attrs, crate::wire::Short> {
        let flags = r.u32()?;
        let mut a = Attrs::default();
        if flags & ATTR_SIZE != 0 {
            a.size = Some(r.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            a.ids = Some((r.u32()?, r.u32()?));
        }
        if flags & ATTR_PERMISSIONS != 0 {
            a.mode = Some(r.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            a.times = Some((r.u32()?, r.u32()?));
        }
        if flags & ATTR_EXTENDED != 0 {
            for _ in 0..r.u32()? {
                r.string()?;
                r.string()?;
            }
        }
        Ok(a)
    }
}

/// An errno as an SFTP status code.
fn status_of(e: Errno) -> u32 {
    match e {
        Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP => FX_NO_SUCH_FILE,
        Errno::EACCES | Errno::EPERM | Errno::EROFS => FX_PERMISSION_DENIED,
        Errno::ENOSYS | Errno::EOPNOTSUPP => FX_OP_UNSUPPORTED,
        _ => FX_FAILURE,
    }
}

/// `ls -l`'s line for a directory entry (the NAME longname, which `sftp
/// ls -l` shows).
fn longname(name: &[u8], st: &fs::Stat) -> Vec<u8> {
    let mode = slate_coreutils::ls::mode_string(st.mode);
    let tm = slate_rt::time::gmtime(st.mtime);
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let when = format!("{} {:2} {:02}:{:02}", MONTHS[(tm.month.clamp(1, 12) - 1) as usize], tm.day, tm.hour, tm.min);
    let mut l =
        format!("{} {:4} {:<8} {:<8} {:8} {when} ", String::from_utf8_lossy(&mode), st.nlink, st.uid, st.gid, st.size)
            .into_bytes();
    l.extend_from_slice(name);
    l
}

#[derive(Debug)]
pub struct Server {
    handles: BTreeMap<u32, Handle>,
    next: u32,
    /// Where relative paths start (the user's home directory).
    home: Vec<u8>,
}

impl Server {
    pub fn new(home: &[u8]) -> Server {
        Server { handles: BTreeMap::new(), next: 0, home: home.to_vec() }
    }

    fn path(&self, p: &[u8]) -> Vec<u8> {
        if p.starts_with(b"/") {
            p.to_vec()
        } else if p.is_empty() || p == b"." {
            self.home.clone()
        } else {
            fs::join(&self.home, p)
        }
    }

    fn add(&mut self, h: Handle) -> Option<Vec<u8>> {
        if self.handles.len() >= MAX_HANDLES {
            return None;
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.handles.insert(id, h);
        Some(id.to_be_bytes().to_vec())
    }

    fn handle_id(h: &[u8]) -> Option<u32> {
        h.try_into().ok().map(u32::from_be_bytes)
    }

    fn file(&self, h: &[u8]) -> Option<(i32, Vec<u8>)> {
        match self.handles.get(&Self::handle_id(h)?)? {
            Handle::File { fd, path } => Some((*fd, path.clone())),
            Handle::Dir { .. } => None,
        }
    }

    /// Apply attributes to a path (SETSTAT, FSETSTAT, lsetstat).
    fn set(&self, path: &[u8], a: &Attrs, follow: bool) -> Result<(), Errno> {
        if let Some(s) = a.size {
            fs::truncate(path, s)?;
        }
        if let Some((u, g)) = a.ids {
            if follow { fs::chown(path, u, g)? } else { fs::lchown(path, u, g)? }
        }
        if let Some(m) = a.mode {
            fs::chmod(path, m & 0o7777)?;
        }
        if let Some((at, mt)) = a.times {
            fs::set_times(path, Some(Some((i64::from(at), 0))), Some(Some((i64::from(mt), 0))), follow)?;
        }
        Ok(())
    }

    fn status(id: u32, code: u32, msg: &str) -> Vec<u8> {
        Writer::new(FXP_STATUS).u32(id).u32(code).string(msg.as_bytes()).string(b"").finish()
    }

    fn result(id: u32, r: Result<(), Errno>) -> Vec<u8> {
        match r {
            Ok(()) => Self::status(id, FX_OK, "Success"),
            Err(e) => Self::status(id, status_of(e), e.message()),
        }
    }

    fn name(id: u32, names: &[(Vec<u8>, Vec<u8>, Attrs)]) -> Vec<u8> {
        let mut w = Writer::new(FXP_NAME);
        w.u32(id).u32(names.len() as u32);
        for (n, long, a) in names {
            w.string(n).string(long);
            a.write(&mut w);
        }
        w.finish()
    }

    fn attrs(id: u32, st: Result<fs::Stat, Errno>) -> Vec<u8> {
        match st {
            Ok(st) => {
                let mut w = Writer::new(FXP_ATTRS);
                w.u32(id);
                Attrs::of(&st).write(&mut w);
                w.finish()
            }
            Err(e) => Self::status(id, status_of(e), e.message()),
        }
    }

    /// A canonical absolute path (REALPATH, expand-path).
    fn canonical(&self, p: &[u8]) -> Result<Vec<u8>, Errno> {
        slate_coreutils::fileops::canonicalize(&self.path(p), true, true)
    }

    fn statvfs(id: u32, path: &[u8]) -> Vec<u8> {
        match fs::statfs(path) {
            Ok(s) => {
                let bs = s.block_size.max(1) as u64;
                let mut w = Writer::new(FXP_EXTENDED_REPLY);
                w.u32(id);
                // f_bsize f_frsize f_blocks f_bfree f_bavail f_files
                // f_ffree f_favail f_fsid f_flag f_namemax
                for v in [bs, bs, s.blocks, s.free, s.available, s.files, s.free_files, s.free_files, 0, 0, 255] {
                    w.u64(v);
                }
                w.finish()
            }
            Err(e) => Self::status(id, status_of(e), e.message()),
        }
    }

    /// One request (without its length) → the reply, if any.
    pub fn request(&mut self, pkt: &[u8]) -> Option<Vec<u8>> {
        let (&kind, body) = pkt.split_first()?;
        let mut r = Reader::new(body);
        if kind == FXP_INIT {
            let mut w = Writer::new(FXP_VERSION);
            w.u32(3);
            for (n, v) in EXTENSIONS {
                w.string(n).string(v);
            }
            return Some(w.finish());
        }
        let id = r.u32().ok()?;
        Some(self.dispatch(kind, id, &mut r).unwrap_or_else(|_| Self::status(id, FX_BAD_MESSAGE, "Bad message")))
    }

    fn dispatch(&mut self, kind: u8, id: u32, r: &mut Reader) -> Result<Vec<u8>, crate::wire::Short> {
        Ok(match kind {
            FXP_OPEN => {
                let path = self.path(r.string()?);
                let (pflags, attrs) = (r.u32()?, Attrs::read(r)?);
                let mut flags = match (pflags & FXF_READ != 0, pflags & FXF_WRITE != 0) {
                    (true, true) => fs::O_RDWR,
                    (false, true) => fs::O_WRONLY,
                    _ => fs::O_RDONLY,
                } | fs::O_CLOEXEC;
                for (f, o) in [(FXF_APPEND, fs::O_APPEND), (FXF_CREAT, fs::O_CREAT), (FXF_TRUNC, fs::O_TRUNC)] {
                    if pflags & f != 0 {
                        flags |= o;
                    }
                }
                if pflags & FXF_EXCL != 0 {
                    flags |= fs::O_EXCL;
                }
                match fs::open(&path, flags, attrs.mode.map_or(0o666, |m| m & 0o7777)) {
                    Ok(fd) => match self.add(Handle::File { fd, path }) {
                        Some(h) => Writer::new(FXP_HANDLE).u32(id).string(&h).finish(),
                        None => {
                            let _ = io::close(fd);
                            Self::status(id, FX_FAILURE, "Too many open files")
                        }
                    },
                    Err(e) => Self::status(id, status_of(e), e.message()),
                }
            }
            FXP_CLOSE => {
                let h = r.string()?;
                match Self::handle_id(h).and_then(|i| self.handles.remove(&i)) {
                    Some(Handle::File { fd, .. }) => Self::result(id, io::close(fd)),
                    Some(Handle::Dir { .. }) => Self::status(id, FX_OK, "Success"),
                    None => Self::status(id, FX_FAILURE, "Bad handle"),
                }
            }
            FXP_READ => {
                let h = r.string()?;
                let (off, len) = (r.u64()?, r.u32()? as usize);
                let Some((fd, _)) = self.file(h) else { return Ok(Self::status(id, FX_FAILURE, "Bad handle")) };
                let mut buf = alloc::vec![0u8; len.min(MAX_IO)];
                match io::pread(fd, &mut buf, off) {
                    Ok(0) => Self::status(id, FX_EOF, "End of file"),
                    Ok(n) => Writer::new(FXP_DATA).u32(id).string(&buf[..n]).finish(),
                    Err(e) => Self::status(id, status_of(e), e.message()),
                }
            }
            FXP_WRITE => {
                let h = r.string()?;
                let off = r.u64()?;
                let data = r.string()?;
                let Some((fd, _)) = self.file(h) else { return Ok(Self::status(id, FX_FAILURE, "Bad handle")) };
                let mut done = 0;
                let mut res = Ok(());
                while done < data.len() {
                    match io::pwrite(fd, &data[done..], off + done as u64) {
                        Ok(0) => {
                            res = Err(Errno::EIO);
                            break;
                        }
                        Ok(n) => done += n,
                        Err(Errno::EINTR) => {}
                        Err(e) => {
                            res = Err(e);
                            break;
                        }
                    }
                }
                Self::result(id, res)
            }
            FXP_LSTAT => Self::attrs(id, fs::lstat(&self.path(r.string()?))),
            FXP_STAT => Self::attrs(id, fs::stat(&self.path(r.string()?))),
            FXP_FSTAT => match self.file(r.string()?) {
                Some((fd, _)) => Self::attrs(id, fs::fstat(fd)),
                None => Self::status(id, FX_FAILURE, "Bad handle"),
            },
            FXP_SETSTAT => {
                let path = self.path(r.string()?);
                let a = Attrs::read(r)?;
                Self::result(id, self.set(&path, &a, true))
            }
            FXP_FSETSTAT => {
                let h = r.string()?.to_vec();
                let a = Attrs::read(r)?;
                match self.file(&h) {
                    Some((fd, path)) => {
                        let res = match a.size {
                            Some(s) => fs::ftruncate(fd, s),
                            None => Ok(()),
                        };
                        Self::result(id, res.and_then(|()| self.set(&path, &Attrs { size: None, ..a }, true)))
                    }
                    None => Self::status(id, FX_FAILURE, "Bad handle"),
                }
            }
            FXP_OPENDIR => {
                let path = self.path(r.string()?);
                match fs::read_dir(&path) {
                    Ok(list) => {
                        let mut entries: Vec<Vec<u8>> = alloc::vec![b".".to_vec(), b"..".to_vec()];
                        entries.extend(list.into_iter().map(|e| e.name));
                        match self.add(Handle::Dir { entries, path }) {
                            Some(h) => Writer::new(FXP_HANDLE).u32(id).string(&h).finish(),
                            None => Self::status(id, FX_FAILURE, "Too many open files"),
                        }
                    }
                    Err(e) => Self::status(id, status_of(e), e.message()),
                }
            }
            FXP_READDIR => {
                let h = r.string()?;
                let Some(Handle::Dir { entries, path }) = Self::handle_id(h).and_then(|i| self.handles.get_mut(&i))
                else {
                    return Ok(Self::status(id, FX_FAILURE, "Bad handle"));
                };
                if entries.is_empty() {
                    return Ok(Self::status(id, FX_EOF, "End of directory"));
                }
                let batch: Vec<Vec<u8>> = entries.drain(..entries.len().min(100)).collect();
                let names: Vec<(Vec<u8>, Vec<u8>, Attrs)> = batch
                    .into_iter()
                    .map(|n| match fs::lstat(&fs::join(path, &n)) {
                        Ok(st) => (n.clone(), longname(&n, &st), Attrs::of(&st)),
                        Err(_) => (n.clone(), n, Attrs::default()),
                    })
                    .collect();
                Self::name(id, &names)
            }
            FXP_REMOVE => Self::result(id, fs::unlink(&self.path(r.string()?))),
            FXP_MKDIR => {
                let path = self.path(r.string()?);
                let a = Attrs::read(r)?;
                Self::result(id, fs::mkdir(&path, a.mode.map_or(0o777, |m| m & 0o7777)))
            }
            FXP_RMDIR => Self::result(id, fs::rmdir(&self.path(r.string()?))),
            FXP_REALPATH => match self.canonical(r.string()?) {
                Ok(p) => Self::name(id, &[(p.clone(), p, Attrs::default())]),
                Err(e) => Self::status(id, status_of(e), e.message()),
            },
            FXP_RENAME => {
                let (from, to) = (self.path(r.string()?), self.path(r.string()?));
                // filexfer-02: renaming over an existing file fails.
                if fs::lstat(&to).is_ok() {
                    Self::status(id, FX_FAILURE, "File exists")
                } else {
                    Self::result(id, fs::rename(&from, &to))
                }
            }
            FXP_READLINK => match fs::readlink(&self.path(r.string()?)) {
                Ok(t) => Self::name(id, &[(t.clone(), t, Attrs::default())]),
                Err(e) => Self::status(id, status_of(e), e.message()),
            },
            FXP_SYMLINK => {
                // OpenSSH sends the target first (PROTOCOL §4.1: the
                // arguments were reversed).
                let target = r.string()?.to_vec();
                let link = self.path(r.string()?);
                Self::result(id, fs::symlink(&target, &link))
            }
            FXP_EXTENDED => {
                let name = r.string()?.to_vec();
                match name.as_slice() {
                    b"posix-rename@openssh.com" => {
                        let (from, to) = (self.path(r.string()?), self.path(r.string()?));
                        Self::result(id, fs::rename(&from, &to))
                    }
                    b"hardlink@openssh.com" => {
                        let (from, to) = (self.path(r.string()?), self.path(r.string()?));
                        Self::result(id, fs::link(&from, &to))
                    }
                    b"statvfs@openssh.com" => Self::statvfs(id, &self.path(r.string()?)),
                    b"fstatvfs@openssh.com" => match self.file(r.string()?) {
                        Some((_, path)) => Self::statvfs(id, &path),
                        None => Self::status(id, FX_FAILURE, "Bad handle"),
                    },
                    b"fsync@openssh.com" => match self.file(r.string()?) {
                        Some((fd, _)) => Self::result(id, fs::fsync(fd)),
                        None => Self::status(id, FX_FAILURE, "Bad handle"),
                    },
                    b"lsetstat@openssh.com" => {
                        let path = self.path(r.string()?);
                        let a = Attrs::read(r)?;
                        Self::result(id, self.set(&path, &a, false))
                    }
                    b"limits@openssh.com" => {
                        let mut w = Writer::new(FXP_EXTENDED_REPLY);
                        w.u32(id).u64(MAX_PACKET as u64).u64(MAX_IO as u64).u64(MAX_IO as u64).u64(MAX_HANDLES as u64);
                        w.finish()
                    }
                    b"expand-path@openssh.com" => {
                        // `~` and `~/x` are the home directory; `~user`
                        // another's (from /etc/passwd).
                        let p = r.string()?.to_vec();
                        let expanded = if p == b"~" || p.starts_with(b"~/") {
                            Some([self.home.as_slice(), &p[1..]].concat())
                        } else if let Some(rest) = p.strip_prefix(b"~") {
                            let (user, tail) = match rest.iter().position(|&c| c == b'/') {
                                Some(i) => (&rest[..i], &rest[i..]),
                                None => (rest, &b""[..]),
                            };
                            crate::auth::lookup(&String::from_utf8_lossy(user))
                                .map(|u| [u.home.as_bytes(), tail].concat())
                        } else {
                            Some(p)
                        };
                        match expanded.map(|p| self.canonical(&p)) {
                            Some(Ok(p)) => Self::name(id, &[(p.clone(), p, Attrs::default())]),
                            Some(Err(e)) => Self::status(id, status_of(e), e.message()),
                            None => Self::status(id, FX_NO_SUCH_FILE, "No such user"),
                        }
                    }
                    _ => Self::status(id, FX_OP_UNSUPPORTED, "Unsupported extension"),
                }
            }
            _ => Self::status(id, FX_OP_UNSUPPORTED, "Unsupported request"),
        })
    }
}

/// `sftp-server`: serve standard input and output until the client
/// closes them.
pub fn main() -> i32 {
    let home = slate_rt::env::var(b"HOME").unwrap_or_else(|| b"/".to_vec());
    let mut server = Server::new(&home);
    let mut input: Vec<u8> = Vec::new();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        // Every whole packet received so far.
        while input.len() >= 4 {
            let len = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
            if len == 0 || len > MAX_PACKET {
                slate_rt::eprintln!("sftp-server: bad packet length {len}");
                return 1;
            }
            if input.len() < 4 + len {
                break;
            }
            let pkt: Vec<u8> = input.drain(..4 + len).skip(4).collect();
            if let Some(reply) = server.request(&pkt) {
                let mut out = (reply.len() as u32).to_be_bytes().to_vec();
                out.extend_from_slice(&reply);
                if io::write_all(io::STDOUT, &out).is_err() {
                    return 1;
                }
            }
        }
        match io::read(io::STDIN, &mut buf) {
            Ok(0) => return 0,
            Ok(n) => input.extend_from_slice(&buf[..n]),
            Err(Errno::EINTR) => {}
            Err(_) => return 1,
        }
    }
}
