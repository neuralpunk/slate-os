// SPDX-License-Identifier: MIT OR Apache-2.0

//! tar, on slate-tar, streaming: an archive is read and written a block
//! at a time, whatever its size.
//!
//! `tar -c|-x|-t|-r|-u|-A|--delete [options] [-f ARCHIVE] [FILE...]`, also
//! in the old bundled form (`tar xzf a.tar.gz`). Compressed archives are
//! recognised by their magic number when read; -z, -j, -J, --lzma,
//! --zstd, -a (by the archive's suffix) or -I PROGRAM compress when
//! writing. The format's codec runs in a child connected by a pipe, as
//! GNU tar runs its compressors.
//!
//! Extraction refuses names that climb out (`..`; a leading `/` is
//! dropped, as GNU tar does) and makes symbolic links last, so no member
//! is written through one an archive just made; as root it keeps owners
//! and modes, otherwise modes lose the umask's bits. Sparse files (-S)
//! and extended attributes (--xattrs) are kept; hard links are archived
//! once.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_regex::fnmatch::{Flags, fnmatch_with};
use slate_rt::{Errno, fs, io, lossy, process};
use slate_tar::{BLOCK, END, Header, Kind, Reader};

use crate::compress::{FdIn, FdOut, Format};
use crate::util::{Opt, Parser, bad_option};

/// `tar: message` on standard error.
fn warn(args: core::fmt::Arguments<'_>) {
    io::flush_stdout();
    io::err(format!("tar: {args}\n").as_bytes());
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Create,
    Extract,
    List,
    Append,
    Update,
    Catenate,
    Delete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    None,
    Name,
    Inode,
}

/// How to compress what is written.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Squeeze {
    Format(Format),
    Program(Vec<u8>),
}

#[derive(Clone, Debug)]
struct Opts {
    mode: Option<Mode>,
    verbose: u8,
    archive: Vec<u8>,
    /// Creating: the operands, each with the directory it is relative to.
    items: Vec<Item>,
    dir: Option<Vec<u8>>,
    squeeze: Option<Squeeze>,
    auto: bool,
    same_owner: bool,
    same_permissions: bool,
    numeric: bool,
    to_stdout: bool,
    keep_old: bool,
    touch: bool,
    strip: usize,
    excludes: Vec<Vec<u8>>,
    exclude_vcs: bool,
    files_from: Vec<Vec<u8>>,
    null: bool,
    dereference: bool,
    absolute: bool,
    recursion: bool,
    sort: Sort,
    sparse: bool,
    xattrs: bool,
    owner: Option<(Vec<u8>, u32)>,
    group: Option<(Vec<u8>, u32)>,
    mtime: Option<i64>,
    remove_files: bool,
    record: usize,
}

impl Opts {
    fn new() -> Opts {
        let root = process::geteuid() == 0;
        Opts {
            mode: None,
            verbose: 0,
            archive: b"-".to_vec(),
            items: Vec::new(),
            dir: None,
            squeeze: None,
            auto: false,
            same_owner: root,
            same_permissions: root,
            numeric: false,
            to_stdout: false,
            keep_old: false,
            touch: false,
            strip: 0,
            excludes: Vec::new(),
            exclude_vcs: false,
            files_from: Vec::new(),
            null: false,
            dereference: false,
            absolute: false,
            recursion: true,
            sort: Sort::Name,
            sparse: false,
            xattrs: false,
            owner: None,
            group: None,
            mtime: None,
            remove_files: false,
            record: 20 * BLOCK,
        }
    }

    /// Where verbose names go: standard error when the archive itself is
    /// on standard output.
    fn say(&self, line: &[u8]) {
        if self.archive == b"-" && matches!(self.mode, Some(Mode::Create | Mode::Append | Mode::Update)) {
            io::err(line);
        } else {
            io::out(line);
        }
    }
}

/// Version-control files and directories (--exclude-vcs).
const VCS: &[&str] = &[
    "CVS",
    ".cvsignore",
    "RCS",
    "SCCS",
    ".svn",
    ".git",
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".arch-ids",
    "{arch}",
    "=RELEASE-ID",
    "=meta-update",
    "=update",
    ".bzr",
    ".bzrignore",
    ".bzrtags",
    ".hg",
    ".hgignore",
    ".hgtags",
    "_darcs",
];

/// Whether `name` is excluded: a pattern matches the whole name or any
/// part of it after a `/` (GNU tar's defaults: wildcards, not anchored,
/// `*` matching `/`).
fn excluded(o: &Opts, name: &[u8]) -> bool {
    let name = name.strip_suffix(b"/").unwrap_or(name);
    let tails =
        core::iter::once(name).chain(name.iter().enumerate().filter(|(_, c)| **c == b'/').map(|(i, _)| &name[i + 1..]));
    let pats = o.excludes.iter().map(Vec::as_slice);
    for t in tails {
        for p in pats.clone() {
            if fnmatch_with(p, t, Flags::default()) {
                return true;
            }
        }
        let base = t.split(|&c| c == b'/').next().unwrap_or(t);
        if o.exclude_vcs && VCS.iter().any(|v| v.as_bytes() == base) {
            return true;
        }
    }
    false
}

// --- The archive's bytes -------------------------------------------------------------

/// The archive read: a descriptor (or a pipe from a decompressing
/// child), with bytes already looked at given back first.
struct ArchiveIn {
    prefix: Vec<u8>,
    at: usize,
    input: FdIn,
    child: Option<(i32, Format)>,
    fd: i32,
}

impl slate_flate::Source for &mut ArchiveIn {
    fn fill(&mut self, buf: &mut [u8]) -> Result<usize, slate_flate::Error> {
        if self.at < self.prefix.len() {
            let n = buf.len().min(self.prefix.len() - self.at);
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        self.input.read(buf).map_err(|_| slate_flate::Error::Io)
    }
}

/// Open the archive to read, decompressing in a child if its magic says
/// so (or -I's program was given).
fn open_in(o: &Opts) -> Result<ArchiveIn, String> {
    let fd = if o.archive == b"-" {
        io::STDIN
    } else {
        fs::open(&o.archive, fs::O_RDONLY | fs::O_CLOEXEC, 0)
            .map_err(|e| format!("{}: Cannot open: {e}", lossy(&o.archive)))?
    };
    let mut input = FdIn::new(fd);
    let mut prefix = vec![0u8; 512];
    let mut got = 0;
    while got < prefix.len() {
        match input.read(&mut prefix[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => return Err(format!("{}: Cannot read: {e}", lossy(&o.archive))),
        }
    }
    prefix.truncate(got);
    // Uncompressed archives have "ustar" (or a GNU or v7 header) at once.
    let fmt = match &o.squeeze {
        Some(Squeeze::Program(p)) => return spawn_filter_in(p, prefix, fd),
        _ if got >= 262 && (&prefix[257..262] == b"ustar") => None,
        _ => Format::sniff(&prefix),
    };
    let Some(fmt) = fmt else { return Ok(ArchiveIn { prefix, at: 0, input, child: None, fd }) };
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = io::close(r);
            let mut out = FdOut::new(Some(w));
            let st = match crate::compress::decompress_after(fmt, prefix, &mut input, &mut out) {
                Ok(_) => 0,
                Err(e) => {
                    let name = if o.archive == b"-" { String::from("stdin") } else { String::from(lossy(&o.archive)) };
                    if out.err.is_none() {
                        io::err(format!("{}\n", crate::compress::failure_message(fmt, &name, e)).as_bytes());
                    }
                    1
                }
            };
            process::exit_now(st);
        }
        Ok(pid) => {
            let _ = io::close(w);
            Ok(ArchiveIn { prefix: Vec::new(), at: 0, input: FdIn::new(r), child: Some((pid, fmt)), fd })
        }
        Err(e) => Err(format!("fork: {e}")),
    }
}

/// -I PROGRAM: run `PROGRAM -d` on the archive.
fn spawn_filter_in(prog: &[u8], prefix: Vec<u8>, fd: i32) -> Result<ArchiveIn, String> {
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    let (pr, pw) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = io::close(r);
            let _ = io::close(pw);
            let _ = process::dup2(pr, 0);
            let _ = process::dup2(w, 1);
            run_shell(&[prog, b" -d"].concat());
        }
        Ok(pid) => {
            let _ = io::close(w);
            let _ = io::close(pr);
            // Feed the prefix and the rest of the archive to the program.
            match process::fork() {
                Ok(0) => {
                    let _ = io::close(r);
                    let _ = io::write_all(pw, &prefix);
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = io::read(fd, &mut buf) {
                        if n == 0 || io::write_all(pw, &buf[..n]).is_err() {
                            break;
                        }
                    }
                    process::exit_now(0);
                }
                Ok(_) => {
                    let _ = io::close(pw);
                }
                Err(e) => return Err(format!("fork: {e}")),
            }
            Ok(ArchiveIn { prefix: Vec::new(), at: 0, input: FdIn::new(r), child: Some((pid, Format::Gzip)), fd })
        }
        Err(e) => Err(format!("fork: {e}")),
    }
}

fn run_shell(cmd: &[u8]) -> ! {
    let argv = vec![b"sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
    let env = slate_rt::env::vars();
    let e = process::execve(b"/bin/sh", &argv, env);
    io::err(format!("tar: {}: {e}\n", lossy(cmd)).as_bytes());
    process::exit_now(2)
}

/// Wait for a decompressing or compressing child; false (after saying
/// so) if it failed.
fn reap(child: Option<(i32, Format)>) -> bool {
    let Some((pid, _)) = child else { return true };
    match process::wait(pid, 0) {
        Ok((_, s)) if process::exit_code(s) == 0 => true,
        Ok((_, s)) => {
            warn(format_args!("Child returned status {}", process::exit_code(s)));
            false
        }
        Err(_) => true,
    }
}

/// The archive written: a descriptor (or a pipe to a compressing child),
/// counting bytes for the record padding.
struct ArchiveOut {
    fd: i32,
    written: u64,
    child: Option<(i32, Format)>,
    buf: Vec<u8>,
    err: Option<Errno>,
}

impl ArchiveOut {
    fn put(&mut self, d: &[u8]) {
        self.written += d.len() as u64;
        self.buf.extend_from_slice(d);
        if self.buf.len() >= 64 * 1024 {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.err.is_none()
            && let Err(e) = io::write_all(self.fd, &self.buf)
        {
            self.err = Some(e);
        }
        self.buf.clear();
    }

    /// The end blocks and the record's padding; false on a write error.
    fn finish(mut self, record: usize, close: bool) -> bool {
        self.put(&END);
        let pad = (self.written.div_ceil(record as u64) * record as u64 - self.written) as usize;
        self.put(&vec![0u8; pad]);
        self.flush();
        if let Some(e) = self.err {
            warn(format_args!("write error: {e}"));
            return false;
        }
        if close || self.child.is_some() {
            let _ = io::close(self.fd);
        }
        reap(self.child)
    }
}

/// Open the archive to write, compressing through a child if asked.
fn open_out(o: &Opts, fd: i32) -> Result<ArchiveOut, String> {
    let squeeze = match (&o.squeeze, o.auto) {
        (Some(s), _) => Some(s.clone()),
        (None, true) => crate::compress::by_suffix(&o.archive).map(Squeeze::Format),
        _ => None,
    };
    let Some(squeeze) = squeeze else {
        return Ok(ArchiveOut { fd, written: 0, child: None, buf: Vec::new(), err: None });
    };
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = io::close(w);
            match squeeze {
                Squeeze::Program(p) => {
                    let _ = process::dup2(r, 0);
                    let _ = process::dup2(fd, 1);
                    run_shell(&p);
                }
                Squeeze::Format(fmt) => {
                    let mut input = FdIn::new(r);
                    let mut out = FdOut::new(Some(fd));
                    let set = crate::compress::Settings::new(fmt);
                    let st = i32::from(crate::compress::compress(fmt, &mut input, &mut out, set, None).is_err());
                    process::exit_now(st);
                }
            }
        }
        Ok(pid) => {
            let _ = io::close(r);
            if fd != io::STDOUT {
                let _ = io::close(fd);
            }
            Ok(ArchiveOut { fd: w, written: 0, child: Some((pid, Format::Gzip)), buf: Vec::new(), err: None })
        }
        Err(e) => Err(format!("fork: {e}")),
    }
}

// --- Names --------------------------------------------------------------------------

/// /etc/passwd's or /etc/group's entries: name, id, members.
type Db = Vec<(Vec<u8>, u32, Vec<Vec<u8>>)>;

/// An operand to archive and the directory it is relative to.
type Item = (Option<Vec<u8>>, Vec<u8>);

/// A symbolic link to make: where, its target, owner, group and time.
type LateLink = (Vec<u8>, Vec<u8>, u32, u32, i64);

/// Owner and group names, looked up once.
#[derive(Default)]
struct Names {
    users: Option<Db>,
    groups: Option<Db>,
}

impl Names {
    fn user(&mut self, uid: u32) -> Vec<u8> {
        let u = self.users.get_or_insert_with(|| crate::simple::db_names(b"/etc/passwd"));
        u.iter().find(|e| e.1 == uid).map(|e| e.0.clone()).unwrap_or_default()
    }

    fn group(&mut self, gid: u32) -> Vec<u8> {
        let g = self.groups.get_or_insert_with(|| crate::simple::db_names(b"/etc/group"));
        g.iter().find(|e| e.1 == gid).map(|e| e.0.clone()).unwrap_or_default()
    }

    fn uid_of(&mut self, name: &[u8]) -> Option<u32> {
        let u = self.users.get_or_insert_with(|| crate::simple::db_names(b"/etc/passwd"));
        u.iter().find(|e| e.0 == name).map(|e| e.1)
    }

    fn gid_of(&mut self, name: &[u8]) -> Option<u32> {
        let g = self.groups.get_or_insert_with(|| crate::simple::db_names(b"/etc/group"));
        g.iter().find(|e| e.0 == name).map(|e| e.1)
    }
}

/// The name to extract an entry to: without a leading `/`, None when it
/// would climb out (`..`).
fn safe_name(path: &[u8]) -> Option<Vec<u8>> {
    let p: Vec<&[u8]> = path.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".").collect();
    if p.iter().any(|c| *c == b"..") {
        return None;
    }
    Some(p.join(&b'/'))
}

/// A name without its first `n` components (None: nothing left).
fn strip(path: &[u8], n: usize) -> Option<Vec<u8>> {
    if n == 0 {
        return Some(path.to_vec());
    }
    let parts: Vec<&[u8]> = path.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    (parts.len() > n).then(|| parts[n..].join(&b'/'))
}

/// Make the directories leading to a member. Something else in the way
/// (a file an earlier member left) is replaced, as GNU tar does; a
/// symbolic link to a directory is followed.
fn mkdirs(path: &[u8]) {
    let mut at = Vec::new();
    for c in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
        if !at.is_empty() || path.starts_with(b"/") {
            at.push(b'/');
        }
        at.extend_from_slice(c);
        if fs::stat(&at).is_ok_and(|s| s.mode & 0o170000 == 0o040000) {
            continue;
        }
        if fs::lstat(&at).is_ok() {
            let _ = fs::unlink(&at);
        }
        let _ = fs::mkdir(&at, 0o755);
    }
}

// --- Listing --------------------------------------------------------------------------

/// `tar -tv`'s line: mode, owner/group, size, date, name (as GNU tar lays
/// it out).
fn listing(e: &Header) -> String {
    let t = match e.kind() {
        Kind::Dir => 'd',
        Kind::Symlink => 'l',
        Kind::Char => 'c',
        Kind::Block => 'b',
        Kind::Fifo => 'p',
        Kind::HardLink => 'h',
        Kind::File => '-',
    };
    let mut perms = String::new();
    perms.push(t);
    for (i, c) in "rwxrwxrwx".chars().enumerate() {
        let on = e.mode & (0o400 >> i) != 0;
        let special = match i {
            2 => e.mode & 0o4000 != 0,
            5 => e.mode & 0o2000 != 0,
            8 => e.mode & 0o1000 != 0,
            _ => false,
        };
        perms.push(match (special, on, i) {
            (true, true, 8) => 't',
            (true, false, 8) => 'T',
            (true, true, _) => 's',
            (true, false, _) => 'S',
            (false, true, _) => c,
            _ => '-',
        });
    }
    let owner = if e.uname.is_empty() { format!("{}", e.uid) } else { String::from(lossy(&e.uname)) };
    let group = if e.gname.is_empty() { format!("{}", e.gid) } else { String::from(lossy(&e.gname)) };
    let tm = slate_rt::tz::localtime(e.mtime);
    let mut date = String::new();
    slate_rt::time::format(&tm, "%Y-%m-%d %H:%M", &mut date);
    let who = format!("{owner}/{group}");
    let size = match e.kind() {
        Kind::Char | Kind::Block => format!("{},{}", e.dev.0, e.dev.1),
        _ => format!("{}", e.real_size()),
    };
    let pad = 19usize.saturating_sub(who.len() + 1);
    let mut line = format!("{perms} {who} {size:>pad$} {date} {}", lossy(&e.path));
    match e.kind() {
        Kind::Symlink => line += &format!(" -> {}", lossy(&e.link)),
        Kind::HardLink => line += &format!(" link to {}", lossy(&e.link)),
        _ => {}
    }
    line.push('\n');
    line
}

// --- Reading members ----------------------------------------------------------------

/// Whether a member is one the operands ask for (all when there are
/// none): the name itself or something under it.
fn wanted(files: &[Vec<u8>], path: &[u8], hits: &mut [bool]) -> bool {
    if files.is_empty() {
        return true;
    }
    let p = path.strip_suffix(b"/").unwrap_or(path);
    let p = p.strip_prefix(b"./").unwrap_or(p);
    let mut any = false;
    for (i, f) in files.iter().enumerate() {
        let f = f.strip_suffix(b"/").unwrap_or(f);
        let f = f.strip_prefix(b"./").unwrap_or(f);
        if p == f || (p.starts_with(f) && p.get(f.len()) == Some(&b'/')) {
            hits[i] = true;
            any = true;
        }
    }
    any
}

/// Read the rest of the current member's data into `sink` (a sparse
/// file's pieces at their places).
fn copy_data<S: slate_flate::Source>(
    r: &mut Reader<S>,
    h: &Header,
    mut sink: impl FnMut(u64, &[u8]) -> bool,
) -> Result<(), slate_tar::Error> {
    let mut buf = vec![0u8; 64 * 1024];
    let pieces: Vec<(u64, u64)> = match &h.sparse {
        Some((_, map)) => map.clone(),
        None => vec![(0, h.size)],
    };
    for (off, len) in pieces {
        let mut done = 0u64;
        while done < len {
            let want = ((len - done) as usize).min(buf.len());
            let n = r.read_data(&mut buf[..want])?;
            if n == 0 {
                return Err(slate_tar::Error::Truncated);
            }
            if !sink(off + done, &buf[..n]) {
                return Ok(());
            }
            done += n as u64;
        }
        // Each piece of a sparse file starts on a block.
        if h.sparse.is_some() {
            let mut pad = vec![0u8; slate_tar::padding(len)];
            let mut got = 0;
            while got < pad.len() {
                let n = r.read_data(&mut pad[got..])?;
                if n == 0 {
                    break;
                }
                got += n;
            }
        }
    }
    Ok(())
}

/// Walk the archive's members, `f` deciding what to do with each.
fn each_member(
    o: &Opts,
    mut f: impl FnMut(&mut Reader<&mut ArchiveIn>, &Header) -> Result<(), String>,
) -> Result<(), String> {
    let mut a = open_in(o)?;
    let child = a.child;
    let r = {
        let mut r = Reader::new(&mut a);
        loop {
            match r.next() {
                Ok(Some(h)) => f(&mut r, &h)?,
                Ok(None) => break Ok(()),
                Err(slate_tar::Error::Checksum) => break Err(String::from("This does not look like a tar archive")),
                Err(slate_tar::Error::Truncated) => break Err(String::from("Unexpected EOF in archive")),
                Err(e) => break Err(format!("{}: {e:?}", lossy(&o.archive))),
            }
        }
    };
    // Drain what a decompressor still writes, then collect it.
    if child.is_some() {
        let mut buf = vec![0u8; 64 * 1024];
        while matches!(a.input.read(&mut buf), Ok(n) if n > 0) {}
        let _ = io::close(a.input.fd);
    }
    if a.fd != io::STDIN && a.fd != a.input.fd {
        let _ = io::close(a.fd);
    }
    if !reap(child) {
        return Err(String::from("Error is not recoverable: exiting now"));
    }
    r
}

fn list(o: &Opts, files: &[Vec<u8>]) -> i32 {
    let mut hits = vec![false; files.len()];
    let mut out = Vec::new();
    let r = each_member(o, |_, h| {
        if !wanted(files, &h.path, &mut hits) || excluded(o, &h.path) {
            return Ok(());
        }
        if o.verbose > 0 {
            out.extend_from_slice(listing(h).as_bytes());
        } else {
            out.extend_from_slice(&h.path);
            out.push(b'\n');
        }
        if out.len() > 32 * 1024 {
            io::out(&out);
            out.clear();
        }
        Ok(())
    });
    io::out(&out);
    finish_read(r, files, &hits)
}

/// The status after reading: archive errors and operands never found.
fn finish_read(r: Result<(), String>, files: &[Vec<u8>], hits: &[bool]) -> i32 {
    let mut status = 0;
    if let Err(e) = r {
        warn(format_args!("{e}"));
        status = 2;
    }
    for (f, hit) in files.iter().zip(hits) {
        if !hit {
            warn(format_args!("{}: Not found in archive", lossy(f)));
            status = 2;
        }
    }
    if status != 0 {
        warn(format_args!("Exiting with failure status due to previous errors"));
    }
    status
}

/// Extracting: what is left for the end (directories' modes and times,
/// symbolic links) and what went wrong.
struct Extractor<'a> {
    o: &'a Opts,
    dest: Vec<u8>,
    umask: u32,
    dirs: Vec<(Vec<u8>, u32, i64)>,
    links: Vec<LateLink>,
    names: Names,
    said_slash: bool,
    failed: usize,
}

impl<'a> Extractor<'a> {
    fn new(o: &'a Opts) -> Extractor<'a> {
        let umask = fs::umask(0o022);
        fs::umask(umask);
        Extractor {
            o,
            dest: o.dir.clone().unwrap_or_else(|| b".".to_vec()),
            umask,
            dirs: Vec::new(),
            links: Vec::new(),
            names: Names::default(),
            said_slash: false,
            failed: 0,
        }
    }

    /// Extract one member (its data read from `r`).
    fn member<S: slate_flate::Source>(&mut self, r: &mut Reader<S>, h: &Header) -> Result<(), String> {
        let o = self.o;
        if o.to_stdout {
            if h.kind() == Kind::File {
                if o.verbose > 0 {
                    io::err(&[h.path.as_slice(), b"\n"].concat());
                }
                let mut pos = 0u64;
                copy_data(r, h, |off, d| {
                    // Holes as zeros.
                    if off > pos {
                        io::out(&vec![0u8; (off - pos) as usize]);
                    }
                    io::out(d);
                    pos = off + d.len() as u64;
                    true
                })
                .map_err(|e| format!("{e:?}"))?;
                if h.real_size() > pos {
                    io::out(&vec![0u8; (h.real_size() - pos) as usize]);
                }
            }
            return Ok(());
        }
        let Some(stripped) = strip(&h.path, o.strip) else { return Ok(()) };
        if h.path.starts_with(b"/") && !self.said_slash {
            self.said_slash = true;
            warn(format_args!("Removing leading `/' from member names"));
        }
        let Some(rel) = safe_name(&stripped) else {
            warn(format_args!("{}: Member name contains '..'", lossy(&h.path)));
            self.failed += 1;
            return Ok(());
        };
        if rel.is_empty() {
            return Ok(());
        }
        if o.verbose > 1 {
            io::out(listing(h).as_bytes());
        } else if o.verbose > 0 {
            io::out(&[h.path.as_slice(), b"\n"].concat());
        }
        let path = fs::join(&self.dest, &rel);
        mkdirs(fs::dirname(&path));
        let mode = if o.same_permissions { h.mode } else { h.mode & !self.umask };
        if o.keep_old && h.kind() != Kind::Dir && fs::lstat(&path).is_ok() {
            warn(format_args!("{}: Cannot open: File exists", lossy(&rel)));
            self.failed += 1;
            return Ok(());
        }
        let (uid, gid) = if o.numeric {
            (h.uid, h.gid)
        } else {
            (
                self.names.uid_of(&h.uname).filter(|_| !h.uname.is_empty()).unwrap_or(h.uid),
                self.names.gid_of(&h.gname).filter(|_| !h.gname.is_empty()).unwrap_or(h.gid),
            )
        };
        let res = match h.kind() {
            Kind::Dir => {
                let _ = fs::mkdir(&path, 0o700);
                self.dirs.push((path.clone(), mode, h.mtime));
                Ok(())
            }
            Kind::File => {
                // Replace what is there (a link must not be written through).
                let _ = fs::unlink(&path);
                match fs::open(&path, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600) {
                    Ok(fd) => {
                        let mut werr = None;
                        copy_data(r, h, |off, d| {
                            let w = if h.sparse.is_some() {
                                io::pwrite(fd, d, off).map(|_| ())
                            } else {
                                io::write_all(fd, d)
                            };
                            if let Err(e) = w {
                                werr = Some(e);
                                return false;
                            }
                            true
                        })
                        .map_err(|e| format!("{e:?}"))?;
                        if h.sparse.is_some() {
                            let _ = fs::ftruncate(fd, h.real_size());
                        }
                        if o.xattrs {
                            for (k, v) in &h.xattrs {
                                let _ = fs::xattr_set(fd, k, v, 0);
                            }
                        }
                        let _ = io::close(fd);
                        match werr {
                            Some(e) => Err(e),
                            None => fs::chmod(&path, mode),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Kind::Symlink => {
                self.links.push((path.clone(), h.link.clone(), uid, gid, h.mtime));
                return Ok(());
            }
            Kind::HardLink => {
                let target = strip(&h.link, o.strip).and_then(|t| safe_name(&t));
                match target {
                    Some(t) => {
                        let _ = fs::unlink(&path);
                        fs::link(&fs::join(&self.dest, &t), &path)
                    }
                    None => Err(Errno::EPERM),
                }
            }
            Kind::Char | Kind::Block | Kind::Fifo => {
                let kind = match h.kind() {
                    Kind::Char => 0o020000,
                    Kind::Block => 0o060000,
                    _ => 0o010000,
                };
                let dev = (u64::from(h.dev.0) << 8) | u64::from(h.dev.1);
                let _ = fs::unlink(&path);
                fs::mknod(&path, kind | mode, dev)
            }
        };
        if let Err(err) = res {
            warn(format_args!("{}: Cannot open: {err}", lossy(&rel)));
            self.failed += 1;
            return Ok(());
        }
        if o.same_owner {
            let _ = fs::lchown(&path, uid, gid);
        }
        if h.kind() != Kind::Dir && !o.touch {
            let _ = fs::set_times(&path, None, Some(Some((h.mtime, 0))), true);
        }
        Ok(())
    }

    /// Symbolic links, then directories' own modes and times; how many
    /// members failed.
    fn finish(self) -> usize {
        let mut failed = self.failed;
        for (path, target, uid, gid, mtime) in self.links {
            let _ = fs::unlink(&path);
            if let Err(e) = fs::symlink(&target, &path) {
                warn(format_args!("{}: Cannot create symlink to '{}': {e}", lossy(&path), lossy(&target)));
                failed += 1;
                continue;
            }
            if self.o.same_owner {
                let _ = fs::lchown(&path, uid, gid);
            }
            if !self.o.touch {
                let _ = fs::set_times(&path, None, Some(Some((mtime, 0))), false);
            }
        }
        for (path, mode, mtime) in self.dirs.into_iter().rev() {
            let _ = fs::chmod(&path, mode);
            if !self.o.touch {
                let _ = fs::set_times(&path, None, Some(Some((mtime, 0))), true);
            }
        }
        failed
    }
}

fn extract(o: &Opts, files: &[Vec<u8>]) -> i32 {
    let mut hits = vec![false; files.len()];
    let mut ex = Extractor::new(o);
    let r = each_member(o, |r, h| {
        if !wanted(files, &h.path, &mut hits) || excluded(o, &h.path) {
            return Ok(());
        }
        ex.member(r, h)
    });
    let failed = ex.finish();
    let st = finish_read(r, files, &hits);
    if failed > 0 && st == 0 {
        warn(format_args!("Exiting with failure status due to previous errors"));
        return 2;
    }
    st
}

/// How [`extract_bytes`] treats owners and modes.
#[derive(Clone, Copy, Debug)]
pub struct ExtractOptions {
    /// Keep the archive's owners.
    pub same_owner: bool,
    /// Keep the archive's modes as they are.
    pub same_permissions: bool,
    pub verbose: bool,
}

/// Extract an archive held in memory under `dest` (slate-linux's runtime
/// setup); the number of members that failed.
pub fn extract_bytes(archive: &[u8], dest: &[u8], eo: &ExtractOptions) -> usize {
    let mut o = Opts::new();
    o.dir = Some(dest.to_vec());
    o.same_owner = eo.same_owner;
    o.same_permissions = eo.same_permissions;
    o.verbose = u8::from(eo.verbose);
    let mut ex = Extractor::new(&o);
    let mut r = Reader::new(slate_tar::SliceSource::new(archive));
    let mut bad = 0;
    loop {
        match r.next() {
            Ok(Some(h)) => {
                if let Err(e) = ex.member(&mut r, &h) {
                    warn(format_args!("{e}"));
                    bad += 1;
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                warn(format_args!("{e:?}"));
                bad += 1;
                break;
            }
        }
    }
    ex.finish() + bad
}

// --- Writing members -----------------------------------------------------------------

struct Creator<'a> {
    o: &'a Opts,
    out: &'a mut ArchiveOut,
    names: Names,
    /// Files with several links already archived: (device, inode) → name.
    links: BTreeMap<(u64, u64), Vec<u8>>,
    /// The archive itself, not to be put into itself.
    archive_id: Option<(u64, u64)>,
    said_slash: bool,
    failed: bool,
    changed: bool,
    /// -u: the members already there and their times.
    have: Option<BTreeMap<Vec<u8>, i64>>,
}

/// Where a sparse file's data lies: runs of non-zero 512-byte blocks.
fn data_map(fd: i32, size: u64) -> Vec<(u64, u64)> {
    let mut map: Vec<(u64, u64)> = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < size {
        let n = match io::pread(fd, &mut buf, off) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for (i, blk) in buf[..n].chunks(BLOCK).enumerate() {
            let at = off + (i * BLOCK) as u64;
            if blk.iter().any(|&b| b != 0) {
                match map.last_mut() {
                    Some(last) if last.0 + last.1 == at => last.1 += blk.len() as u64,
                    _ => map.push((at, blk.len() as u64)),
                }
            }
        }
        off += n as u64;
    }
    // GNU tar's maps end with the file's end.
    if map.last().is_none_or(|l| l.0 + l.1 < size) {
        map.push((size, 0));
    }
    map
}

impl Creator<'_> {
    fn say(&self, h: &Header) {
        if self.o.verbose > 1 {
            self.o.say(listing(h).as_bytes());
        } else if self.o.verbose > 0 {
            let mut p = h.path.clone();
            if h.kind() == Kind::Dir && !p.ends_with(b"/") {
                p.push(b'/');
            }
            p.push(b'\n');
            self.o.say(&p);
        }
    }

    /// Add `path` (and, for a directory, what is under it) as `name`.
    fn add(&mut self, path: &[u8], name: &[u8], top: bool) {
        let st = if self.o.dereference { fs::stat(path) } else { fs::lstat(path) };
        let st = match st {
            Ok(s) => s,
            Err(e) => {
                warn(format_args!("{}: Cannot stat: {e}", lossy(path)));
                self.failed = true;
                return;
            }
        };
        let mut name = name.to_vec();
        if !self.o.absolute {
            let trimmed = name.iter().position(|&c| c != b'/').map_or(Vec::new(), |i| name[i..].to_vec());
            if trimmed.len() != name.len() && !self.said_slash {
                self.said_slash = true;
                warn(format_args!("Removing leading `/' from member names"));
            }
            name = trimmed;
            if name.is_empty() {
                name = b".".to_vec();
            }
        }
        let _ = top;
        if excluded(self.o, &name) {
            return;
        }
        if self.archive_id == Some((st.dev, st.ino)) {
            warn(format_args!("{}: file is the archive; not dumped", lossy(path)));
            return;
        }
        let fmt = st.mode & 0o170000;
        let mut h = Header {
            path: name.clone(),
            kind: Some(Kind::File),
            mode: st.mode & 0o7777,
            uid: self.o.owner.as_ref().map_or(st.uid, |x| x.1),
            gid: self.o.group.as_ref().map_or(st.gid, |x| x.1),
            mtime: self.o.mtime.unwrap_or(st.mtime),
            dev: ((st.rdev >> 8) as u32 & 0xFFF, (st.rdev & 0xFF) as u32),
            ..Header::default()
        };
        if !self.o.numeric {
            h.uname = match &self.o.owner {
                Some((n, _)) => n.clone(),
                None => self.names.user(st.uid),
            };
            h.gname = match &self.o.group {
                Some((n, _)) => n.clone(),
                None => self.names.group(st.gid),
            };
        }
        // -u: only what is newer than the archive's copy.
        let skip = self.have.as_ref().and_then(|m| m.get(&name)).is_some_and(|&t| t >= st.mtime) && fmt != 0o040000;
        if fmt == 0o040000 {
            h.kind = Some(Kind::Dir);
            if !skip && !(self.have.as_ref().is_some_and(|m| m.contains_key(&[name.as_slice(), b"/"].concat()))) {
                self.write_simple(&h);
            }
            if self.o.recursion {
                let mut kids: Vec<(Vec<u8>, u64)> = fs::read_dir(path)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|d| d.name != b"." && d.name != b"..")
                    .map(|d| (d.name, d.ino))
                    .collect();
                match self.o.sort {
                    Sort::Name => kids.sort(),
                    Sort::Inode => kids.sort_by_key(|k| k.1),
                    Sort::None => {}
                }
                for (k, _) in kids {
                    self.add(&fs::join(path, &k), &fs::join(&name, &k), false);
                }
            }
            if self.o.remove_files {
                let _ = fs::rmdir(path);
            }
            return;
        }
        if skip {
            return;
        }
        // A file with several links: archived once, the others as links.
        if st.nlink > 1 {
            if let Some(first) = self.links.get(&(st.dev, st.ino)) {
                h.kind = Some(Kind::HardLink);
                h.link = first.clone();
                self.write_simple(&h);
                self.removed(path);
                return;
            }
            self.links.insert((st.dev, st.ino), name.clone());
        }
        match fmt {
            0o120000 => {
                h.kind = Some(Kind::Symlink);
                h.link = fs::readlink(path).unwrap_or_default();
                self.write_simple(&h);
            }
            0o020000 => {
                h.kind = Some(Kind::Char);
                self.write_simple(&h);
            }
            0o060000 => {
                h.kind = Some(Kind::Block);
                self.write_simple(&h);
            }
            0o010000 => {
                h.kind = Some(Kind::Fifo);
                self.write_simple(&h);
            }
            0o140000 => {
                warn(format_args!("{}: socket ignored", lossy(path)));
                return;
            }
            _ => self.write_file(path, &mut h, st.size as u64, st.blocks as u64),
        }
        self.removed(path);
    }

    fn removed(&mut self, path: &[u8]) {
        if self.o.remove_files {
            let _ = fs::unlink(path);
        }
    }

    fn write_simple(&mut self, h: &Header) {
        self.say(h);
        self.out.put(&slate_tar::header(h));
    }

    fn write_file(&mut self, path: &[u8], h: &mut Header, size: u64, blocks: u64) {
        let fd = match fs::open(path, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => {
                warn(format_args!("{}: Cannot open: {e}", lossy(path)));
                self.failed = true;
                return;
            }
        };
        if self.o.xattrs {
            for n in fs::xattr_list(fd).unwrap_or_default() {
                if let Ok(v) = fs::xattr_get(fd, &n) {
                    h.xattrs.push((n, v));
                }
            }
        }
        // Sparse: when the file holds fewer blocks than its length needs.
        let map = (self.o.sparse && blocks * 512 < size).then(|| data_map(fd, size));
        h.size = match &map {
            Some(m) => m.iter().map(|&(_, l)| l + slate_tar::padding(l) as u64).sum(),
            None => size,
        };
        if let Some(m) = &map {
            h.sparse = Some((size, m.clone()));
        }
        self.say(h);
        self.out.put(&slate_tar::header(h));
        let pieces = map.unwrap_or_else(|| vec![(0, size)]);
        let mut buf = vec![0u8; 64 * 1024];
        let sparse = h.sparse.is_some();
        for (off, len) in pieces {
            let mut done = 0u64;
            while done < len {
                let want = ((len - done) as usize).min(buf.len());
                let n = match io::pread(fd, &mut buf[..want], off + done) {
                    Ok(n) => n,
                    Err(e) => {
                        warn(format_args!("{}: Read error: {e}", lossy(path)));
                        self.failed = true;
                        0
                    }
                };
                if n == 0 {
                    // It shrank: zeros keep the archive whole.
                    let left = len - done;
                    warn(format_args!("{}: File shrank by {} bytes; padding with zeros", lossy(path), left));
                    self.out.put(&vec![0u8; left as usize]);
                    self.changed = true;
                    break;
                }
                self.out.put(&buf[..n]);
                done += n as u64;
            }
            if sparse {
                self.out.put(&vec![0u8; slate_tar::padding(len)]);
            }
        }
        if !sparse {
            self.out.put(&vec![0u8; slate_tar::padding(size)]);
        }
        if fs::fstat(fd).is_ok_and(|s| s.size as u64 != size) {
            warn(format_args!("{}: file changed as we read it", lossy(path)));
            self.changed = true;
        }
        let _ = io::close(fd);
    }
}

/// The operands to archive: the command line's, and -T's lists.
fn operands(o: &Opts) -> Result<Vec<Item>, String> {
    let mut items = o.items.clone();
    for list in &o.files_from {
        let data = if list == b"-" {
            io::read_to_end(io::STDIN).map_err(|e| format!("-: {e}"))?
        } else {
            fs::read_file(list).map_err(|e| format!("{}: Cannot open: {e}", lossy(list)))?
        };
        let sep = if o.null { 0 } else { b'\n' };
        for n in data.split(|&c| c == sep).filter(|n| !n.is_empty()) {
            items.push((o.dir.clone(), n.to_vec()));
        }
    }
    Ok(items)
}

/// Archive the operands into `out`.
fn write_members(o: &Opts, out: &mut ArchiveOut, have: Option<BTreeMap<Vec<u8>, i64>>) -> (bool, bool) {
    let items = match operands(o) {
        Ok(i) => i,
        Err(e) => {
            warn(format_args!("{e}"));
            return (true, false);
        }
    };
    let archive_id = (o.archive != b"-").then(|| fs::stat(&o.archive).ok().map(|s| (s.dev, s.ino))).flatten();
    let mut c = Creator {
        o,
        out,
        names: Names::default(),
        links: BTreeMap::new(),
        archive_id,
        said_slash: false,
        failed: false,
        changed: false,
        have,
    };
    let start = fs::getcwd().unwrap_or_else(|_| b".".to_vec());
    for (dir, name) in items {
        if let Some(d) = &dir {
            let _ = fs::chdir(&start);
            if let Err(e) = fs::chdir(d) {
                warn(format_args!("{}: Cannot open: {e}", lossy(d)));
                c.failed = true;
                continue;
            }
        }
        c.add(&name, &name, true);
    }
    let _ = fs::chdir(&start);
    (c.failed, c.changed)
}

fn create(o: &Opts) -> i32 {
    if o.items.is_empty() && o.files_from.is_empty() {
        warn(format_args!("Cowardly refusing to create an empty archive"));
        io::err(format!("Try '{0} --help' or '{0} --usage' for more information.\n", slate_rt::prog_name()).as_bytes());
        return 2;
    }
    let fd = if o.archive == b"-" {
        io::STDOUT
    } else {
        match fs::open(&o.archive, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o666) {
            Ok(fd) => fd,
            Err(e) => {
                warn(format_args!("{}: Cannot open: {e}", lossy(&o.archive)));
                warn(format_args!("Error is not recoverable: exiting now"));
                return 2;
            }
        }
    };
    let mut out = match open_out(o, fd) {
        Ok(a) => a,
        Err(e) => {
            warn(format_args!("{e}"));
            return 2;
        }
    };
    let (failed, changed) = write_members(o, &mut out, None);
    let ok = out.finish(o.record, fd != io::STDOUT);
    exit_status(failed || !ok, changed)
}

fn exit_status(failed: bool, changed: bool) -> i32 {
    if failed {
        warn(format_args!("Exiting with failure status due to previous errors"));
        2
    } else if changed {
        1
    } else {
        0
    }
}

/// -r, -u and -A: the archive must be a plain, uncompressed file; new
/// members go where its end blocks were.
fn append(o: &Opts) -> i32 {
    if o.squeeze.is_some() || o.archive == b"-" {
        warn(format_args!("Cannot update compressed archives"));
        warn(format_args!("Error is not recoverable: exiting now"));
        return 2;
    }
    let fd = match fs::open(&o.archive, fs::O_RDWR | fs::O_CREAT | fs::O_CLOEXEC, 0o666) {
        Ok(fd) => fd,
        Err(e) => {
            warn(format_args!("{}: Cannot open: {e}", lossy(&o.archive)));
            return 2;
        }
    };
    // The end of what is there (and, for -u, its members' times).
    let mut head = [0u8; 13];
    let n = io::pread(fd, &mut head, 0).unwrap_or(0);
    if Format::sniff(&head[..n]).is_some() {
        warn(format_args!("Cannot update compressed archives"));
        warn(format_args!("Error is not recoverable: exiting now"));
        let _ = io::close(fd);
        return 2;
    }
    let (end, have) = match scan(fd) {
        Ok(x) => x,
        Err(e) => {
            warn(format_args!("{}: {e}", lossy(&o.archive)));
            let _ = io::close(fd);
            return 2;
        }
    };
    let _ = io::lseek(fd, end as i64, io::SEEK_SET);
    let mut out = ArchiveOut { fd, written: end, child: None, buf: Vec::new(), err: None };
    let (failed, changed) = if o.mode == Some(Mode::Catenate) {
        (catenate(o, &mut out), false)
    } else {
        write_members(o, &mut out, (o.mode == Some(Mode::Update)).then_some(have))
    };
    let ok = out.finish(o.record, false);
    let len = io::lseek(fd, 0, io::SEEK_CUR).unwrap_or(0);
    let _ = fs::ftruncate(fd, len);
    let _ = io::close(fd);
    exit_status(failed || !ok, changed)
}

/// Read an archive on `fd` to its end: where it ends and its members'
/// times.
fn scan(fd: i32) -> Result<(u64, BTreeMap<Vec<u8>, i64>), String> {
    let _ = io::lseek(fd, 0, io::SEEK_SET);
    let mut input = FdIn::new(fd);
    let mut r = Reader::new(&mut input);
    let mut have = BTreeMap::new();
    loop {
        match r.next() {
            Ok(Some(h)) => {
                let t = have.entry(h.path.clone()).or_insert(h.mtime);
                *t = (*t).max(h.mtime);
            }
            Ok(None) => return Ok((r.header_offset(), have)),
            Err(e) => return Err(format!("{e:?}")),
        }
    }
}

/// -A: each operand archive's members, copied as they are.
fn catenate(o: &Opts, out: &mut ArchiveOut) -> bool {
    let mut failed = false;
    for (_, other) in &o.items {
        let fd = match fs::open(other, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => {
                warn(format_args!("{}: Cannot open: {e}", lossy(other)));
                failed = true;
                continue;
            }
        };
        match scan(fd) {
            Ok((end, _)) => {
                let mut buf = vec![0u8; 64 * 1024];
                let mut off = 0u64;
                while off < end {
                    let want = ((end - off) as usize).min(buf.len());
                    match io::pread(fd, &mut buf[..want], off) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            out.put(&buf[..n]);
                            off += n as u64;
                        }
                    }
                }
            }
            Err(e) => {
                warn(format_args!("{}: {e}", lossy(other)));
                failed = true;
            }
        }
        let _ = io::close(fd);
    }
    failed
}

/// --delete: the archive again without the named members (a file is
/// replaced; standard input goes to standard output).
fn delete(o: &Opts, files: &[Vec<u8>]) -> i32 {
    if o.squeeze.is_some() {
        warn(format_args!("Cannot update compressed archives"));
        return 2;
    }
    let (in_fd, out_fd, tmp) = if o.archive == b"-" {
        (io::STDIN, io::STDOUT, None)
    } else {
        let fd = match fs::open(&o.archive, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => {
                warn(format_args!("{}: Cannot open: {e}", lossy(&o.archive)));
                return 2;
            }
        };
        let tmp = [o.archive.as_slice(), format!(".tar-delete.{}", process::getpid()).as_bytes()].concat();
        let _ = fs::unlink(&tmp);
        match fs::open(&tmp, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600) {
            Ok(out) => (fd, out, Some(tmp)),
            Err(e) => {
                warn(format_args!("{}: Cannot open: {e}", lossy(&tmp)));
                return 2;
            }
        }
    };
    let mut hits = vec![false; files.len()];
    let mut input = FdIn::new(in_fd);
    let mut out = ArchiveOut { fd: out_fd, written: 0, child: None, buf: Vec::new(), err: None };
    let mut r = Reader::new(&mut input);
    let mut result = Ok(());
    loop {
        let h = match r.next() {
            Ok(Some(h)) => h,
            Ok(None) => break,
            Err(e) => {
                result = Err(format!("{e:?}"));
                break;
            }
        };
        if wanted(files, &h.path, &mut hits) && !files.is_empty() {
            continue;
        }
        // The member again: its headers rebuilt, its data copied.
        out.put(&slate_tar::header(&h));
        let mut buf = vec![0u8; 64 * 1024];
        let mut left = h.size;
        while left > 0 {
            match r.read_data(&mut buf[..(left as usize).min(64 * 1024)]) {
                Ok(0) | Err(_) => {
                    result = Err(String::from("Unexpected EOF in archive"));
                    break;
                }
                Ok(n) => {
                    out.put(&buf[..n]);
                    left -= n as u64;
                }
            }
        }
        out.put(&vec![0u8; slate_tar::padding(h.size)]);
    }
    let ok = out.finish(o.record, false);
    if let Some(t) = &tmp {
        let _ = io::close(out_fd);
        let _ = io::close(in_fd);
        if ok && result.is_ok() {
            if let Ok(st) = fs::stat(&o.archive) {
                let _ = fs::chmod(t, st.mode & 0o7777);
            }
            if let Err(e) = fs::rename(t, &o.archive) {
                warn(format_args!("{}: Cannot rename: {e}", lossy(&o.archive)));
                result = Err(String::new());
            }
        } else {
            let _ = fs::unlink(t);
        }
    }
    finish_read(result, files, &hits)
}

// --- The command ---------------------------------------------------------------------

pub fn tar(args: &[Vec<u8>]) -> i32 {
    // The old form: the first argument's letters are options (`tar xzf x`).
    let mut argv = args.to_vec();
    if let Some(first) = argv.get(1).cloned()
        && !first.starts_with(b"-")
        && !first.is_empty()
    {
        argv[1] = [b"-".as_slice(), &first].concat();
    }
    let mut o = Opts::new();
    let mut operands_seen: Vec<Vec<u8>> = Vec::new();
    let mut p = Parser::new(&argv, b"fCTXbI");
    let mut names = Names::default();
    while let Some(opt) = p.next() {
        let set_mode = |o: &mut Opts, m: Mode| -> bool {
            if o.mode.is_some_and(|x| x != m) {
                warn(format_args!(
                    "You may not specify more than one '-Acdtrux', '--delete' or  '--test-label' option"
                ));
                return false;
            }
            o.mode = Some(m);
            true
        };
        let ok = match opt {
            Opt::Short(b'c') => set_mode(&mut o, Mode::Create),
            Opt::Short(b'x') => set_mode(&mut o, Mode::Extract),
            Opt::Short(b't') => set_mode(&mut o, Mode::List),
            Opt::Short(b'r') => set_mode(&mut o, Mode::Append),
            Opt::Short(b'u') => set_mode(&mut o, Mode::Update),
            Opt::Short(b'A') => set_mode(&mut o, Mode::Catenate),
            Opt::Short(b'v') => {
                o.verbose += 1;
                true
            }
            Opt::Short(b'z') => {
                o.squeeze = Some(Squeeze::Format(Format::Gzip));
                true
            }
            Opt::Short(b'j') => {
                o.squeeze = Some(Squeeze::Format(Format::Bzip2));
                true
            }
            Opt::Short(b'J') => {
                o.squeeze = Some(Squeeze::Format(Format::Xz));
                true
            }
            Opt::Short(b'a') => {
                o.auto = true;
                true
            }
            Opt::Short(b'I') => {
                o.squeeze = p.value().map(Squeeze::Program);
                true
            }
            Opt::Short(b'p') => {
                o.same_permissions = true;
                true
            }
            Opt::Short(b'O') => {
                o.to_stdout = true;
                true
            }
            Opt::Short(b'k') => {
                o.keep_old = true;
                true
            }
            Opt::Short(b'm') => {
                o.touch = true;
                true
            }
            Opt::Short(b'h') => {
                o.dereference = true;
                true
            }
            Opt::Short(b'P') => {
                o.absolute = true;
                true
            }
            Opt::Short(b'S') => {
                o.sparse = true;
                true
            }
            Opt::Short(b'f') => {
                o.archive = p.value().unwrap_or_else(|| b"-".to_vec());
                true
            }
            Opt::Short(b'C') => {
                o.dir = p.value();
                true
            }
            Opt::Short(b'T') => {
                o.files_from.extend(p.value());
                true
            }
            Opt::Short(b'X') => match p.value().map(|f| fs::read_file(&f).map_err(|e| (f, e))) {
                Some(Ok(d)) => {
                    o.excludes.extend(d.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec));
                    true
                }
                Some(Err((f, e))) => {
                    warn(format_args!("{}: Cannot open: {e}", lossy(&f)));
                    return 2;
                }
                None => true,
            },
            Opt::Short(b'b') => {
                o.record = p.value().and_then(|v| crate::util::parse_num::<usize>(&v)).unwrap_or(20).max(1) * BLOCK;
                true
            }
            Opt::Short(b'U' | b'w' | b'W') => true,
            Opt::Long(l) => {
                let value = |p: &mut Parser<'_>| p.value().unwrap_or_default();
                match l.as_str() {
                    "create" => set_mode(&mut o, Mode::Create),
                    "extract" | "get" => set_mode(&mut o, Mode::Extract),
                    "list" => set_mode(&mut o, Mode::List),
                    "append" => set_mode(&mut o, Mode::Append),
                    "update" => set_mode(&mut o, Mode::Update),
                    "catenate" | "concatenate" => set_mode(&mut o, Mode::Catenate),
                    "delete" => set_mode(&mut o, Mode::Delete),
                    "verbose" => {
                        o.verbose += 1;
                        true
                    }
                    "gzip" | "gunzip" | "ungzip" => {
                        o.squeeze = Some(Squeeze::Format(Format::Gzip));
                        true
                    }
                    "bzip2" => {
                        o.squeeze = Some(Squeeze::Format(Format::Bzip2));
                        true
                    }
                    "xz" => {
                        o.squeeze = Some(Squeeze::Format(Format::Xz));
                        true
                    }
                    "lzma" => {
                        o.squeeze = Some(Squeeze::Format(Format::Lzma));
                        true
                    }
                    "zstd" => {
                        o.squeeze = Some(Squeeze::Format(Format::Zstd));
                        true
                    }
                    "auto-compress" => {
                        o.auto = true;
                        true
                    }
                    "no-auto-compress" => {
                        o.auto = false;
                        true
                    }
                    "use-compress-program" => {
                        o.squeeze = Some(Squeeze::Program(value(&mut p)));
                        true
                    }
                    "file" => {
                        o.archive = value(&mut p);
                        true
                    }
                    "directory" => {
                        o.dir = Some(value(&mut p));
                        true
                    }
                    "same-owner" => {
                        o.same_owner = true;
                        true
                    }
                    "no-same-owner" => {
                        o.same_owner = false;
                        true
                    }
                    "preserve-permissions" | "same-permissions" => {
                        o.same_permissions = true;
                        true
                    }
                    "no-same-permissions" => {
                        o.same_permissions = false;
                        true
                    }
                    "numeric-owner" => {
                        o.numeric = true;
                        true
                    }
                    "to-stdout" => {
                        o.to_stdout = true;
                        true
                    }
                    "keep-old-files" | "skip-old-files" => {
                        o.keep_old = true;
                        true
                    }
                    "overwrite" | "unlink-first" | "recursive-unlink" | "no-overwrite-dir" => true,
                    "touch" => {
                        o.touch = true;
                        true
                    }
                    "dereference" => {
                        o.dereference = true;
                        true
                    }
                    "absolute-names" => {
                        o.absolute = true;
                        true
                    }
                    "no-recursion" => {
                        o.recursion = false;
                        true
                    }
                    "recursion" => {
                        o.recursion = true;
                        true
                    }
                    "sparse" => {
                        o.sparse = true;
                        true
                    }
                    "xattrs" => {
                        o.xattrs = true;
                        true
                    }
                    "no-xattrs" => {
                        o.xattrs = false;
                        true
                    }
                    "strip-components" => match crate::util::parse_num::<usize>(&value(&mut p)) {
                        Some(n) => {
                            o.strip = n;
                            true
                        }
                        None => {
                            warn(format_args!("Invalid number of elements"));
                            return 2;
                        }
                    },
                    "exclude" => {
                        o.excludes.push(value(&mut p));
                        true
                    }
                    "exclude-from" => match fs::read_file(&value(&mut p)) {
                        Ok(d) => {
                            o.excludes.extend(d.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec));
                            true
                        }
                        Err(e) => {
                            warn(format_args!("Cannot open exclusion list: {e}"));
                            return 2;
                        }
                    },
                    "exclude-vcs" => {
                        o.exclude_vcs = true;
                        true
                    }
                    "files-from" => {
                        o.files_from.push(value(&mut p));
                        true
                    }
                    "null" => {
                        o.null = true;
                        true
                    }
                    "no-null" => {
                        o.null = false;
                        true
                    }
                    "remove-files" => {
                        o.remove_files = true;
                        true
                    }
                    "sort" => match value(&mut p).as_slice() {
                        b"none" => {
                            o.sort = Sort::None;
                            true
                        }
                        b"name" => {
                            o.sort = Sort::Name;
                            true
                        }
                        b"inode" => {
                            o.sort = Sort::Inode;
                            true
                        }
                        v => {
                            warn(format_args!("invalid argument '{}' for '--sort'", lossy(v)));
                            return 2;
                        }
                    },
                    "owner" | "group" => {
                        let v = value(&mut p);
                        let (n, id) = match v.iter().position(|&c| c == b':') {
                            Some(i) => (v[..i].to_vec(), crate::util::parse_num::<u32>(&v[i + 1..])),
                            None => (v.clone(), None),
                        };
                        let id = id
                            .or_else(|| crate::util::parse_num::<u32>(&n))
                            .or_else(|| if l == "owner" { names.uid_of(&n) } else { names.gid_of(&n) });
                        let Some(id) = id else {
                            warn(format_args!("{}: Invalid {}", lossy(&v), l));
                            return 2;
                        };
                        // A number alone keeps the name its id has here.
                        let shown = if crate::util::parse_num::<u32>(&n).is_some() {
                            if l == "owner" { names.user(id) } else { names.group(id) }
                        } else {
                            n
                        };
                        if l == "owner" {
                            o.owner = Some((shown, id));
                        } else {
                            o.group = Some((shown, id));
                        }
                        true
                    }
                    "mtime" => {
                        let v = value(&mut p);
                        let now = crate::datetime::Instant { secs: slate_rt::time::unix(), nsec: 0 };
                        let t = core::str::from_utf8(&v).ok().and_then(|s| crate::datetime::parse(s, now, false));
                        let t = t
                            .or_else(|| fs::stat(&v).ok().map(|s| crate::datetime::Instant { secs: s.mtime, nsec: 0 }));
                        match t {
                            Some(t) => {
                                o.mtime = Some(t.secs);
                                true
                            }
                            None => {
                                warn(format_args!(
                                    "Substituting -9223372036854775807 for unknown date format '{}'",
                                    lossy(&v)
                                ));
                                return 2;
                            }
                        }
                    }
                    "blocking-factor" => {
                        o.record = crate::util::parse_num::<usize>(&value(&mut p)).unwrap_or(20).max(1) * BLOCK;
                        true
                    }
                    "format" | "checkpoint" | "warning" | "quoting-style" | "label" => {
                        p.inline_value();
                        true
                    }
                    "acls"
                    | "no-acls"
                    | "selinux"
                    | "no-selinux"
                    | "totals"
                    | "wildcards"
                    | "no-wildcards"
                    | "anchored"
                    | "no-anchored"
                    | "ignore-zeros"
                    | "ignore-failed-read"
                    | "check-links"
                    | "no-unquote"
                    | "unquote"
                    | "delay-directory-restore"
                    | "show-transformed-names" => true,
                    _ => return bad_option(&Opt::Long(l)),
                }
            }
            Opt::Operand(f) => {
                operands_seen.push(f.clone());
                o.items.push((o.dir.clone(), f));
                true
            }
            other => return bad_option(&other),
        };
        if !ok {
            return 2;
        }
    }
    let files: Vec<Vec<u8>> = operands_seen;
    match o.mode {
        Some(Mode::Create) => create(&o),
        Some(Mode::List) => list(&o, &files),
        Some(Mode::Extract) => extract(&o, &files),
        Some(Mode::Append | Mode::Update | Mode::Catenate) => append(&o),
        Some(Mode::Delete) => delete(&o, &files),
        None => {
            warn(format_args!("You must specify one of the '-Acdtrux', '--delete' or '--test-label' options"));
            io::err(
                format!("Try '{0} --help' or '{0} --usage' for more information.\n", slate_rt::prog_name()).as_bytes(),
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(safe_name(b"/etc/passwd").as_deref(), Some(b"etc/passwd".as_slice()));
        assert_eq!(safe_name(b"./a//b/").as_deref(), Some(b"a/b".as_slice()));
        assert_eq!(safe_name(b"a/../../x"), None);
        assert_eq!(strip(b"a/b/c", 1).as_deref(), Some(&b"b/c"[..]));
        assert_eq!(strip(b"a/", 1), None);
        let mut hits = [false];
        assert!(wanted(&[b"d".to_vec()], b"d/x", &mut hits) && hits[0]);
        assert!(!wanted(&[b"d".to_vec()], b"dx", &mut [false]));
    }

    #[test]
    fn exclusions() {
        let mut o = Opts::new();
        o.excludes = vec![b"sub".to_vec(), b"*.o".to_vec(), b"d/a".to_vec()];
        assert!(excluded(&o, b"d/sub"));
        assert!(excluded(&o, b"x/y/z.o"));
        assert!(excluded(&o, b"d/a"));
        assert!(!excluded(&o, b"d/ab"));
        o.exclude_vcs = true;
        assert!(excluded(&o, b"proj/.git"));
    }

    #[test]
    fn listing_layout() {
        // Listings are in local time: make it UTC, whatever the host's.
        slate_rt::tz::set_tz(Some(b"UTC0"));
        let e = Header {
            path: b"dir/f.txt".to_vec(),
            kind: Some(Kind::File),
            mode: 0o644,
            uname: b"root".to_vec(),
            gname: b"root".to_vec(),
            size: 1234,
            ..Header::default()
        };
        assert_eq!(listing(&e), "-rw-r--r-- root/root      1234 1970-01-01 00:00 dir/f.txt\n");
    }
}
