// SPDX-License-Identifier: MIT OR Apache-2.0

//! cat, mkdir, rmdir, rm, cp, mv, ln, touch, chmod, chown, chgrp,
//! readlink, realpath, mktemp, truncate.

use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy};

use crate::util::{Opt, Parser, bad_option, close_input, error, error_path, open_input, parse_num};

pub fn cat(args: &[Vec<u8>]) -> i32 {
    let (mut number, mut nonblank, mut ends, mut squeeze, mut tabs, mut nonprint) =
        (false, false, false, false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'n') => number = true,
            Opt::Short(b'b') => nonblank = true,
            Opt::Short(b'E') => ends = true,
            Opt::Short(b's') => squeeze = true,
            Opt::Short(b'T') => tabs = true,
            Opt::Short(b'v') => nonprint = true,
            Opt::Short(b'A') => (nonprint, ends, tabs) = (true, true, true),
            Opt::Short(b'e') => (nonprint, ends) = (true, true),
            Opt::Short(b't') => (nonprint, tabs) = (true, true),
            Opt::Short(b'u') => {}
            Opt::Long(l) if l == "number" => number = true,
            Opt::Long(l) if l == "number-nonblank" => nonblank = true,
            Opt::Long(l) if l == "show-ends" => ends = true,
            Opt::Long(l) if l == "squeeze-blank" => squeeze = true,
            Opt::Long(l) if l == "show-tabs" => tabs = true,
            Opt::Long(l) if l == "show-all" => (nonprint, ends, tabs) = (true, true, true),
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    let plain = !(number || nonblank || ends || squeeze || tabs || nonprint);
    let mut status = 0;
    let mut line_no = 0u64;
    let mut blank_run = false;
    let mut at_line_start = true;
    for f in &files {
        let fd = match open_input(f) {
            Ok(fd) => fd,
            Err(e) => {
                error_path(f, e);
                status = 1;
                continue;
            }
        };
        if let Ok(st) = fs::fstat(fd)
            && st.is_dir()
        {
            error_path(f, Errno::EISDIR);
            status = 1;
            close_input(fd);
            continue;
        }
        let mut buf = alloc::vec![0u8; 64 * 1024];
        loop {
            let n = match io::read(fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    error_path(f, e);
                    status = 1;
                    break;
                }
            };
            if plain {
                io::flush_stdout();
                if io::write_all(io::STDOUT, &buf[..n]).is_err() {
                    return 1;
                }
                continue;
            }
            let mut out = Vec::with_capacity(n * 2);
            for &c in &buf[..n] {
                if at_line_start {
                    let blank = c == b'\n';
                    if squeeze && blank && blank_run {
                        continue;
                    }
                    blank_run = blank;
                    if (number && !nonblank) || (nonblank && !blank) {
                        line_no += 1;
                        out.extend_from_slice(alloc::format!("{line_no:6}\t").as_bytes());
                    }
                    at_line_start = false;
                }
                match c {
                    b'\n' => {
                        if ends {
                            out.push(b'$');
                        }
                        out.push(b'\n');
                        at_line_start = true;
                    }
                    b'\t' if tabs => out.extend_from_slice(b"^I"),
                    b'\t' => out.push(b'\t'),
                    _ if nonprint && c >= 128 => {
                        out.extend_from_slice(b"M-");
                        let c = c - 128;
                        if c < 32 || c == 127 {
                            out.push(b'^');
                            out.push(c ^ 0x40);
                        } else {
                            out.push(c);
                        }
                    }
                    _ if nonprint && (c < 32 || c == 127) => {
                        out.push(b'^');
                        out.push(c ^ 0x40);
                    }
                    _ => out.push(c),
                }
            }
            io::out(&out);
        }
        close_input(fd);
    }
    status
}

/// Apply a chmod(1) mode (octal, or symbolic like `u+x,go-w,a=r,+X`) to
/// `old`. `dir` matters for `X`; `umask` applies when no who is given.
pub fn apply_mode(spec: &[u8], old: u32, dir: bool, umask: u32) -> Option<u32> {
    if !spec.is_empty() && spec.iter().all(|c| (b'0'..=b'7').contains(c)) {
        let v = u32::from_str_radix(core::str::from_utf8(spec).ok()?, 8).ok()?;
        // Directories keep set-id bits unless given explicitly (GNU).
        return Some(if dir && spec.len() < 5 { v | (old & 0o6000) } else { v });
    }
    let mut mode = old & 0o7777;
    for clause in spec.split(|&c| c == b',') {
        let mut i = 0;
        let mut who = 0u32;
        while i < clause.len() && b"ugoa".contains(&clause[i]) {
            who |= match clause[i] {
                b'u' => 0o4700,
                b'g' => 0o2070,
                b'o' => 0o1007,
                _ => 0o7777,
            };
            i += 1;
        }
        let explicit = who != 0;
        if !explicit {
            who = 0o7777;
        }
        if i >= clause.len() {
            return None;
        }
        while i < clause.len() {
            let op = clause[i];
            if !b"+-=".contains(&op) {
                return None;
            }
            i += 1;
            let mut perm = 0u32;
            while i < clause.len() && !b"+-=".contains(&clause[i]) {
                perm |= match clause[i] {
                    b'r' => 0o444,
                    b'w' => 0o222,
                    b'x' => 0o111,
                    b'X' if dir || mode & 0o111 != 0 => 0o111,
                    b'X' => 0,
                    b's' => 0o6000,
                    b't' => 0o1000,
                    b'u' => {
                        let u = (mode >> 6) & 7;
                        u * 0o111
                    }
                    b'g' => {
                        let g = (mode >> 3) & 7;
                        g * 0o111
                    }
                    b'o' => (mode & 7) * 0o111,
                    _ => return None,
                };
                i += 1;
            }
            let mut bits = perm & who;
            if !explicit {
                bits &= !umask | 0o7000;
            }
            match op {
                b'+' => mode |= bits,
                b'-' => mode &= !bits,
                // `=`: the given bits become the only ones for `who`.
                _ => mode = (mode & !who) | bits,
            }
        }
    }
    Some(mode)
}

pub fn mkdir(args: &[Vec<u8>]) -> i32 {
    let (mut parents, mut verbose) = (false, false);
    let mut mode: Option<Vec<u8>> = None;
    let mut dirs = Vec::new();
    let mut p = Parser::new(args, b"m");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'p') => parents = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b'm') => mode = p.value(),
            Opt::Long(l) if l == "parents" => parents = true,
            Opt::Long(l) if l == "verbose" => verbose = true,
            Opt::Long(l) if l == "mode" => mode = p.value(),
            Opt::Operand(d) => dirs.push(d),
            o => return bad_option(&o),
        }
    }
    if dirs.is_empty() {
        error("missing operand");
        return 1;
    }
    let umask = fs::umask(0);
    fs::umask(umask);
    let m = match &mode {
        Some(s) => match apply_mode(s, 0o777 & !umask, true, umask) {
            Some(m) => m,
            None => {
                error(format_args!("invalid mode '{}'", lossy(s)));
                return 1;
            }
        },
        None => 0o777,
    };
    let mut status = 0;
    for d in &dirs {
        if parents {
            let mut path = Vec::new();
            if d.starts_with(b"/") {
                path.push(b'/');
            }
            for comp in d.split(|&c| c == b'/').filter(|c| !c.is_empty()) {
                path = fs::join(&path, comp);
                match fs::mkdir(&path, 0o777) {
                    Ok(()) => {
                        if verbose {
                            slate_rt::println!("mkdir: created directory '{}'", lossy(&path));
                        }
                    }
                    Err(Errno::EEXIST) if fs::stat(&path).is_ok_and(|s| s.is_dir()) => {}
                    Err(e) => {
                        error_path(&path, e);
                        status = 1;
                        break;
                    }
                }
            }
            if mode.is_some() {
                let _ = fs::chmod(d, m);
            }
        } else {
            match fs::mkdir(d, m) {
                Ok(()) => {
                    if mode.is_some() {
                        let _ = fs::chmod(d, m);
                    }
                    if verbose {
                        slate_rt::println!("mkdir: created directory '{}'", lossy(d));
                    }
                }
                Err(e) => {
                    error(format_args!("cannot create directory '{}': {e}", lossy(d)));
                    status = 1;
                }
            }
        }
    }
    status
}

pub fn rmdir(args: &[Vec<u8>]) -> i32 {
    let (mut parents, mut ignore) = (false, false);
    let mut dirs = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'p') => parents = true,
            Opt::Long(l) if l == "parents" => parents = true,
            Opt::Long(l) if l == "ignore-fail-on-non-empty" => ignore = true,
            Opt::Operand(d) => dirs.push(d),
            o => return bad_option(&o),
        }
    }
    let mut status = 0;
    for d in &dirs {
        let mut cur = d.clone();
        loop {
            match fs::rmdir(&cur) {
                Ok(()) => {}
                Err(Errno::ENOTEMPTY | Errno::EEXIST) if ignore => break,
                Err(e) => {
                    error(format_args!("failed to remove '{}': {e}", lossy(&cur)));
                    status = 1;
                    break;
                }
            }
            if !parents {
                break;
            }
            let parent = fs::dirname(&cur).to_vec();
            if parent == b"." || parent == b"/" || parent == cur {
                break;
            }
            cur = parent;
        }
    }
    status
}

fn remove_tree(path: &[u8], force: bool, verbose: bool) -> bool {
    let st = match fs::lstat(path) {
        Ok(st) => st,
        Err(Errno::ENOENT) if force => return true,
        Err(e) => {
            error(format_args!("cannot remove '{}': {e}", lossy(path)));
            return false;
        }
    };
    let mut ok = true;
    if st.is_dir() {
        match fs::read_dir(path) {
            Ok(entries) => {
                for e in entries {
                    ok &= remove_tree(&fs::join(path, &e.name), force, verbose);
                }
            }
            Err(e) => {
                error(format_args!("cannot remove '{}': {e}", lossy(path)));
                return false;
            }
        }
        if let Err(e) = fs::rmdir(path) {
            error(format_args!("cannot remove '{}': {e}", lossy(path)));
            return false;
        }
    } else if let Err(e) = fs::unlink(path)
        && !(force && e == Errno::ENOENT)
    {
        error(format_args!("cannot remove '{}': {e}", lossy(path)));
        return false;
    }
    if verbose {
        slate_rt::println!("removed '{}'", lossy(path));
    }
    ok
}

pub fn rm(args: &[Vec<u8>]) -> i32 {
    let (mut force, mut recursive, mut dirs, mut verbose) = (false, false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'f') => force = true,
            Opt::Short(b'r' | b'R') => recursive = true,
            Opt::Short(b'd') => dirs = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b'i' | b'I') => {}
            Opt::Long(l) if l == "force" => force = true,
            Opt::Long(l) if l == "recursive" => recursive = true,
            Opt::Long(l) if l == "dir" => dirs = true,
            Opt::Long(l) if l == "verbose" => verbose = true,
            Opt::Long(l) if l == "no-preserve-root" || l == "preserve-root" => {}
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.is_empty() && !force {
        error("missing operand");
        return 1;
    }
    let mut status = 0;
    for f in &files {
        let base = fs::basename(f);
        if base == b"." || base == b".." {
            error(format_args!("refusing to remove '.' or '..' directory: skipping '{}'", lossy(f)));
            status = 1;
            continue;
        }
        if recursive {
            if f == b"/" {
                error("it is dangerous to operate recursively on '/'");
                status = 1;
                continue;
            }
            if !remove_tree(f, force, verbose) {
                status = 1;
            }
            continue;
        }
        match fs::lstat(f) {
            Ok(st) if st.is_dir() => {
                if dirs {
                    if let Err(e) = fs::rmdir(f) {
                        error(format_args!("cannot remove '{}': {e}", lossy(f)));
                        status = 1;
                    }
                } else {
                    error(format_args!("cannot remove '{}': Is a directory", lossy(f)));
                    status = 1;
                }
            }
            Ok(_) => match fs::unlink(f) {
                Ok(()) => {
                    if verbose {
                        slate_rt::println!("removed '{}'", lossy(f));
                    }
                }
                Err(e) => {
                    error(format_args!("cannot remove '{}': {e}", lossy(f)));
                    status = 1;
                }
            },
            Err(Errno::ENOENT) if force => {}
            Err(e) => {
                error(format_args!("cannot remove '{}': {e}", lossy(f)));
                status = 1;
            }
        }
    }
    status
}

#[derive(Clone, Copy, Debug, Default)]
struct CopyOpts {
    recursive: bool,
    preserve: bool,
    no_deref: bool,
    force: bool,
    no_clobber: bool,
    verbose: bool,
    update: bool,
}

fn copy_file(from: &[u8], to: &[u8], st: &fs::Stat, o: &CopyOpts) -> Result<(), Errno> {
    let src = fs::open(from, fs::O_RDONLY | fs::O_CLOEXEC, 0)?;
    let mut dst = fs::open(to, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, st.mode & 0o7777);
    if dst.is_err() && o.force {
        let _ = fs::unlink(to);
        dst = fs::open(to, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, st.mode & 0o7777);
    }
    let dst = match dst {
        Ok(d) => d,
        Err(e) => {
            let _ = io::close(src);
            return Err(e);
        }
    };
    let mut buf = alloc::vec![0u8; 128 * 1024];
    let r = loop {
        match io::read(src, &mut buf) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                if let Err(e) = io::write_all(dst, &buf[..n]) {
                    break Err(e);
                }
            }
            Err(e) => break Err(e),
        }
    };
    let _ = io::close(src);
    let _ = io::close(dst);
    r
}

fn preserve(to: &[u8], st: &fs::Stat, link: bool) {
    if link {
        let _ = fs::lchown(to, st.uid, st.gid);
    } else {
        let _ = fs::chown(to, st.uid, st.gid);
        let _ = fs::chmod(to, st.mode & 0o7777);
    }
    let _ = fs::set_times(to, Some(Some((st.atime, st.atime_nsec))), Some(Some((st.mtime, st.mtime_nsec))), !link);
}

fn copy_any(from: &[u8], to: &[u8], o: &CopyOpts, top: bool) -> bool {
    let st = if o.no_deref { fs::lstat(from) } else { fs::stat(from) };
    let st = match st {
        Ok(s) => s,
        Err(e) => {
            error(format_args!("cannot stat '{}': {e}", lossy(from)));
            return false;
        }
    };
    if let Ok(dst) = fs::stat(to) {
        if dst.dev == st.dev && dst.ino == st.ino {
            error(format_args!("'{}' and '{}' are the same file", lossy(from), lossy(to)));
            return false;
        }
        if o.no_clobber && !st.is_dir() {
            return true;
        }
        if o.update && !st.is_dir() && (dst.mtime, dst.mtime_nsec) >= (st.mtime, st.mtime_nsec) {
            return true;
        }
    }
    let _ = top;
    if st.is_dir() {
        if !o.recursive {
            error(format_args!("-r not specified; omitting directory '{}'", lossy(from)));
            return false;
        }
        match fs::mkdir(to, st.mode & 0o7777 | 0o700) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => {
                error(format_args!("cannot create directory '{}': {e}", lossy(to)));
                return false;
            }
        }
        let mut ok = true;
        match fs::read_dir(from) {
            Ok(entries) => {
                for e in entries {
                    ok &= copy_any(&fs::join(from, &e.name), &fs::join(to, &e.name), o, false);
                }
            }
            Err(e) => {
                error(format_args!("cannot read directory '{}': {e}", lossy(from)));
                ok = false;
            }
        }
        if o.preserve {
            preserve(to, &st, false);
        } else {
            let _ = fs::chmod(to, st.mode & 0o7777);
        }
        return ok;
    }
    if st.is_symlink() {
        let target = match fs::readlink(from) {
            Ok(t) => t,
            Err(e) => {
                error_path(from, e);
                return false;
            }
        };
        let _ = fs::unlink(to);
        if let Err(e) = fs::symlink(&target, to) {
            error(format_args!("cannot create symbolic link '{}': {e}", lossy(to)));
            return false;
        }
        if o.preserve {
            preserve(to, &st, true);
        }
    } else if matches!(st.kind(), fs::S_IFIFO | fs::S_IFCHR | fs::S_IFBLK | fs::S_IFSOCK) && o.recursive {
        let _ = fs::unlink(to);
        if let Err(e) = fs::mknod(to, st.mode, st.rdev) {
            error(format_args!("cannot create special file '{}': {e}", lossy(to)));
            return false;
        }
    } else if let Err(e) = copy_file(from, to, &st, o) {
        error(format_args!("cannot copy '{}' to '{}': {e}", lossy(from), lossy(to)));
        return false;
    }
    if o.preserve {
        preserve(to, &st, false);
    }
    if o.verbose {
        slate_rt::println!("'{}' -> '{}'", lossy(from), lossy(to));
    }
    true
}

/// Split operands into sources and a target; a target that is a
/// directory receives each source under its basename.
/// (source, destination) pairs.
type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

fn targets(ops: &[Vec<u8>], target_dir: Option<Vec<u8>>, no_target_dir: bool) -> Result<Pairs, i32> {
    let (sources, dest) = match target_dir {
        Some(t) => (ops, t),
        None if ops.len() >= 2 => (&ops[..ops.len() - 1], ops[ops.len() - 1].clone()),
        None => {
            if ops.is_empty() {
                error("missing file operand");
            } else {
                error(format_args!("missing destination file operand after '{}'", lossy(&ops[0])));
            }
            return Err(1);
        }
    };
    let is_dir = !no_target_dir && fs::stat(&dest).is_ok_and(|s| s.is_dir());
    if sources.len() > 1 && !is_dir {
        error(format_args!("target '{}' is not a directory", lossy(&dest)));
        return Err(1);
    }
    Ok(sources
        .iter()
        .map(|s| (s.clone(), if is_dir { fs::join(&dest, fs::basename(s)) } else { dest.clone() }))
        .collect())
}

pub fn cp(args: &[Vec<u8>]) -> i32 {
    let mut o = CopyOpts::default();
    let mut ops = Vec::new();
    let (mut tdir, mut no_tdir) = (None, false);
    let mut p = Parser::new(args, b"t");
    while let Some(opt) = p.next() {
        match opt {
            Opt::Short(b'r' | b'R') => o.recursive = true,
            Opt::Short(b'a') => (o.recursive, o.preserve, o.no_deref) = (true, true, true),
            Opt::Short(b'p') => o.preserve = true,
            Opt::Short(b'P') => o.no_deref = true,
            Opt::Short(b'L') => o.no_deref = false,
            Opt::Short(b'd') => o.no_deref = true,
            Opt::Short(b'f') => o.force = true,
            Opt::Short(b'n') => o.no_clobber = true,
            Opt::Short(b'u') => o.update = true,
            Opt::Short(b'v') => o.verbose = true,
            Opt::Short(b'i') => {}
            Opt::Short(b't') => tdir = p.value(),
            Opt::Short(b'T') => no_tdir = true,
            Opt::Long(l) if l == "recursive" => o.recursive = true,
            Opt::Long(l) if l == "archive" => (o.recursive, o.preserve, o.no_deref) = (true, true, true),
            Opt::Long(l) if l == "force" => o.force = true,
            Opt::Long(l) if l == "no-clobber" => o.no_clobber = true,
            Opt::Long(l) if l == "verbose" => o.verbose = true,
            Opt::Long(l) if l == "update" => o.update = true,
            Opt::Long(l) if l == "no-dereference" => o.no_deref = true,
            Opt::Long(l) if l.starts_with("preserve") => o.preserve = true,
            Opt::Long(l) if l == "target-directory" => tdir = p.value(),
            Opt::Long(l) if l == "no-target-directory" => no_tdir = true,
            Opt::Operand(f) => ops.push(f),
            opt => return bad_option(&opt),
        }
    }
    if o.recursive && !o.preserve {
        o.no_deref = true; // -r copies symlinks as links (GNU -R behaviour).
    }
    let pairs = match targets(&ops, tdir, no_tdir) {
        Ok(p) => p,
        Err(s) => return s,
    };
    let mut status = 0;
    for (from, to) in pairs {
        if !copy_any(&from, &to, &o, true) {
            status = 1;
        }
    }
    status
}

pub fn mv(args: &[Vec<u8>]) -> i32 {
    let (mut no_clobber, mut verbose, mut tdir, mut no_tdir) = (false, false, None, false);
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"t");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'f' | b'i') => {}
            Opt::Short(b'n') => no_clobber = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b't') => tdir = p.value(),
            Opt::Short(b'T') => no_tdir = true,
            Opt::Long(l) if l == "force" => {}
            Opt::Long(l) if l == "no-clobber" => no_clobber = true,
            Opt::Long(l) if l == "verbose" => verbose = true,
            Opt::Long(l) if l == "target-directory" => tdir = p.value(),
            Opt::Operand(f) => ops.push(f),
            o => return bad_option(&o),
        }
    }
    let pairs = match targets(&ops, tdir, no_tdir) {
        Ok(p) => p,
        Err(s) => return s,
    };
    let mut status = 0;
    for (from, to) in pairs {
        if no_clobber && fs::lstat(&to).is_ok() {
            continue;
        }
        match fs::rename(&from, &to) {
            Ok(()) => {}
            Err(Errno::EXDEV) => {
                // Across file systems: copy, then remove.
                let o = CopyOpts { recursive: true, preserve: true, no_deref: true, ..Default::default() };
                if !copy_any(&from, &to, &o, true) || !remove_tree(&from, false, false) {
                    status = 1;
                    continue;
                }
            }
            Err(e) => {
                error(format_args!("cannot move '{}' to '{}': {e}", lossy(&from), lossy(&to)));
                status = 1;
                continue;
            }
        }
        if verbose {
            slate_rt::println!("renamed '{}' -> '{}'", lossy(&from), lossy(&to));
        }
    }
    status
}

pub fn ln(args: &[Vec<u8>]) -> i32 {
    let (mut symbolic, mut force, mut verbose, mut no_deref, mut tdir, mut no_tdir) =
        (false, false, false, false, None, false);
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"t");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b's') => symbolic = true,
            Opt::Short(b'f') => force = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b'n') => no_deref = true,
            Opt::Short(b'T') => no_tdir = true,
            Opt::Short(b't') => tdir = p.value(),
            Opt::Long(l) if l == "symbolic" => symbolic = true,
            Opt::Long(l) if l == "force" => force = true,
            Opt::Long(l) if l == "no-dereference" => no_deref = true,
            Opt::Long(l) if l == "verbose" => verbose = true,
            Opt::Long(l) if l == "target-directory" => tdir = p.value(),
            Opt::Operand(f) => ops.push(f),
            o => return bad_option(&o),
        }
    }
    if ops.len() == 1 && tdir.is_none() {
        tdir = Some(b".".to_vec());
    }
    let no_tdir = no_tdir || (no_deref && ops.len() == 2 && fs::lstat(&ops[1]).is_ok_and(|s| s.is_symlink()));
    let pairs = match targets(&ops, tdir, no_tdir) {
        Ok(p) => p,
        Err(s) => return s,
    };
    let mut status = 0;
    for (target, name) in pairs {
        if force {
            let _ = fs::unlink(&name);
        }
        let r = if symbolic { fs::symlink(&target, &name) } else { fs::link(&target, &name) };
        match r {
            Ok(()) => {
                if verbose {
                    slate_rt::println!("'{}' -> '{}'", lossy(&name), lossy(&target));
                }
            }
            Err(e) => {
                let kind = if symbolic { "symbolic link" } else { "hard link" };
                error(format_args!("failed to create {kind} '{}': {e}", lossy(&name)));
                status = 1;
            }
        }
    }
    status
}

/// A touch -d/-t time: `[[CC]YY]MMDDhhmm[.ss]`, `@SECONDS`, or
/// `YYYY-MM-DD[ HH:MM[:SS]]`.
fn parse_time(s: &[u8], stamp: bool) -> Option<i64> {
    let s = core::str::from_utf8(s).ok()?.trim();
    if let Some(n) = s.strip_prefix('@') {
        return n.parse().ok();
    }
    if stamp {
        let (main, secs) = match s.split_once('.') {
            Some((m, ss)) => (m, ss.parse().ok()?),
            None => (s, 0),
        };
        let now = slate_rt::tz::localtime(slate_rt::time::unix());
        let n = |a: usize, b: usize| -> Option<u32> { main.get(a..b)?.parse().ok() };
        let (year, rest) = match main.len() {
            8 => (now.year, 0),
            10 => (2000 + i64::from(n(0, 2)?), 2),
            12 => (i64::from(n(0, 4)?), 4),
            _ => return None,
        };
        let tm = slate_rt::time::Tm {
            year,
            month: n(rest, rest + 2)?,
            day: n(rest + 2, rest + 4)?,
            hour: n(rest + 4, rest + 6)?,
            min: n(rest + 6, rest + 8)?,
            sec: secs,
            ..Default::default()
        };
        return Some(slate_rt::tz::timelocal(&tm));
    }
    let (date, time) = s.split_once([' ', 'T']).unwrap_or((s, "00:00:00"));
    let d: Vec<u32> = date.split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<u32> = time.split(':').filter_map(|x| x.parse().ok()).collect();
    if d.len() != 3 {
        return None;
    }
    let tm = slate_rt::time::Tm {
        year: i64::from(d[0]),
        month: d[1],
        day: d[2],
        hour: *t.first().unwrap_or(&0),
        min: *t.get(1).unwrap_or(&0),
        sec: *t.get(2).unwrap_or(&0),
        ..Default::default()
    };
    Some(slate_rt::tz::timelocal(&tm))
}

pub fn touch(args: &[Vec<u8>]) -> i32 {
    let (mut no_create, mut only_a, mut only_m, mut no_deref) = (false, false, false, false);
    let mut time: Option<(i64, i64)> = None;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"dtr");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'c') => no_create = true,
            Opt::Short(b'a') => only_a = true,
            Opt::Short(b'm') => only_m = true,
            Opt::Short(b'h') => no_deref = true,
            Opt::Short(c @ (b'd' | b't')) => {
                let v = p.value().unwrap_or_default();
                match parse_time(&v, c == b't') {
                    Some(t) => time = Some((t, 0)),
                    None => {
                        error(format_args!("invalid date format '{}'", lossy(&v)));
                        return 1;
                    }
                }
            }
            Opt::Short(b'r') => {
                let r = p.value().unwrap_or_default();
                match fs::stat(&r) {
                    Ok(st) => time = Some((st.mtime, st.mtime_nsec)),
                    Err(e) => {
                        error_path(&r, e);
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "no-create" => no_create = true,
            Opt::Long(l) if l == "date" => {
                let v = p.value().unwrap_or_default();
                time = parse_time(&v, false).map(|t| (t, 0));
                if time.is_none() {
                    error(format_args!("invalid date format '{}'", lossy(&v)));
                    return 1;
                }
            }
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.is_empty() {
        error("missing file operand");
        return 1;
    }
    let t = Some(time);
    let (a, m) = match (only_a, only_m) {
        (true, false) => (t, None),
        (false, true) => (None, t),
        _ => (t, t),
    };
    let mut status = 0;
    for f in &files {
        if fs::lstat(f).is_err() {
            if no_create {
                continue;
            }
            match fs::open(f, fs::O_WRONLY | fs::O_CREAT | fs::O_CLOEXEC, 0o666) {
                Ok(fd) => {
                    let _ = io::close(fd);
                }
                Err(e) => {
                    error(format_args!("cannot touch '{}': {e}", lossy(f)));
                    status = 1;
                    continue;
                }
            }
        }
        if let Err(e) = fs::set_times(f, a, m, !no_deref) {
            error(format_args!("setting times of '{}': {e}", lossy(f)));
            status = 1;
        }
    }
    status
}

fn walk(path: &[u8], f: &mut dyn FnMut(&[u8], &fs::Stat) -> bool) -> bool {
    let Ok(st) = fs::lstat(path) else { return false };
    let mut ok = f(path, &st);
    if st.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        for e in entries {
            ok &= walk(&fs::join(path, &e.name), f);
        }
    }
    ok
}

pub fn chmod(args: &[Vec<u8>]) -> i32 {
    let (mut recursive, mut verbose, mut quiet) = (false, false, false);
    let mut mode: Option<Vec<u8>> = None;
    let mut files = Vec::new();
    for a in &args[1..] {
        match a.as_slice() {
            b"-R" | b"--recursive" => recursive = true,
            b"-v" | b"--verbose" => verbose = true,
            b"-f" | b"--silent" | b"--quiet" => quiet = true,
            b"-c" | b"--changes" => {}
            // Symbolic modes like -w are modes, not options.
            _ if mode.is_none() => mode = Some(a.clone()),
            _ => files.push(a.clone()),
        }
    }
    let Some(mode) = mode else {
        error("missing operand");
        return 1;
    };
    if files.is_empty() {
        error(format_args!("missing operand after '{}'", lossy(&mode)));
        return 1;
    }
    let umask = fs::umask(0);
    fs::umask(umask);
    let mut status = 0;
    for f in &files {
        let mut apply = |p: &[u8], st: &fs::Stat| -> bool {
            if st.is_symlink() && p != f.as_slice() {
                return true;
            }
            let st = if st.is_symlink() { fs::stat(p).unwrap_or(*st) } else { *st };
            let Some(m) = apply_mode(&mode, st.mode, st.is_dir(), umask) else {
                error(format_args!("invalid mode: '{}'", lossy(&mode)));
                return false;
            };
            match fs::chmod(p, m) {
                Ok(()) => {
                    if verbose {
                        slate_rt::println!("mode of '{}' changed to {:04o}", lossy(p), m);
                    }
                    true
                }
                Err(e) => {
                    if !quiet {
                        error(format_args!("changing permissions of '{}': {e}", lossy(p)));
                    }
                    false
                }
            }
        };
        let ok = if recursive {
            walk(f, &mut apply)
        } else {
            match fs::stat(f) {
                Ok(st) => apply(f, &st),
                Err(e) => {
                    error(format_args!("cannot access '{}': {e}", lossy(f)));
                    false
                }
            }
        };
        if !ok {
            status = 1;
        }
    }
    status
}

/// A user or group operand: a name or a number.
pub(crate) fn lookup_id(s: &[u8], db: &[u8]) -> Option<u32> {
    if let Some(n) = parse_num::<u32>(s) {
        return Some(n);
    }
    crate::simple::db_names(db).into_iter().find(|e| e.0 == s).map(|e| e.1)
}

fn chown_common(args: &[Vec<u8>], group_only: bool) -> i32 {
    let (mut recursive, mut no_deref, mut verbose) = (false, false, false);
    let mut spec: Option<Vec<u8>> = None;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'R') => recursive = true,
            Opt::Short(b'h') => no_deref = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b'f' | b'c' | b'H' | b'L' | b'P') => {}
            Opt::Long(l) if l == "recursive" => recursive = true,
            Opt::Long(l) if l == "no-dereference" => no_deref = true,
            Opt::Operand(a) if spec.is_none() => spec = Some(a),
            Opt::Operand(a) => files.push(a),
            o => return bad_option(&o),
        }
    }
    let Some(spec) = spec else {
        error("missing operand");
        return 1;
    };
    let (user, group) = if group_only {
        (None, Some(spec.clone()))
    } else {
        match spec.iter().position(|&c| c == b':' || c == b'.') {
            Some(i) => (
                Some(spec[..i].to_vec()).filter(|u| !u.is_empty()),
                Some(spec[i + 1..].to_vec()).filter(|g| !g.is_empty()),
            ),
            None => (Some(spec.clone()), None),
        }
    };
    let uid = match &user {
        Some(u) => match lookup_id(u, b"/etc/passwd") {
            Some(id) => Some(id),
            None => {
                error(format_args!("invalid user: '{}'", lossy(u)));
                return 1;
            }
        },
        None => None,
    };
    let gid = match &group {
        Some(g) => match lookup_id(g, b"/etc/group") {
            Some(id) => Some(id),
            None => {
                error(format_args!("invalid group: '{}'", lossy(g)));
                return 1;
            }
        },
        None => None,
    };
    let (u, g) = (uid.unwrap_or(u32::MAX), gid.unwrap_or(u32::MAX));
    let mut status = 0;
    for f in &files {
        let mut apply = |p: &[u8], st: &fs::Stat| -> bool {
            let r = if no_deref || (st.is_symlink() && p != f.as_slice()) {
                fs::lchown(p, u, g)
            } else {
                fs::chown(p, u, g)
            };
            match r {
                Ok(()) => {
                    if verbose {
                        slate_rt::println!("ownership of '{}' retained", lossy(p));
                    }
                    true
                }
                Err(e) => {
                    error(format_args!("changing ownership of '{}': {e}", lossy(p)));
                    false
                }
            }
        };
        let ok = if recursive {
            walk(f, &mut apply)
        } else {
            match fs::lstat(f) {
                Ok(st) => apply(f, &st),
                Err(e) => {
                    error(format_args!("cannot access '{}': {e}", lossy(f)));
                    false
                }
            }
        };
        if !ok {
            status = 1;
        }
    }
    status
}

pub fn chown(args: &[Vec<u8>]) -> i32 {
    chown_common(args, false)
}

pub fn chgrp(args: &[Vec<u8>]) -> i32 {
    chown_common(args, true)
}

/// Resolve `path` to an absolute path without `.`, `..` or symlinks.
/// With `missing_ok`, components after the first missing one are kept.
pub fn canonicalize(path: &[u8], follow: bool, missing_ok: bool) -> Result<Vec<u8>, Errno> {
    let mut rest: Vec<Vec<u8>> = Vec::new();
    let start = if path.starts_with(b"/") { b"/".to_vec() } else { fs::getcwd()? };
    let mut pending: Vec<Vec<u8>> =
        path.split(|&c| c == b'/').filter(|c| !c.is_empty()).map(<[u8]>::to_vec).rev().collect();
    let mut out: Vec<Vec<u8>> = start.split(|&c| c == b'/').filter(|c| !c.is_empty()).map(<[u8]>::to_vec).collect();
    let mut links = 0;
    let mut missing = false;
    while let Some(c) = pending.pop() {
        match c.as_slice() {
            b"." => continue,
            b".." => {
                out.pop();
                continue;
            }
            _ => {}
        }
        out.push(c);
        if missing {
            continue;
        }
        let cur = alloc::format!("/{}", lossy(&out.join(&b'/')));
        match fs::lstat(cur.as_bytes()) {
            Ok(st) if st.is_symlink() && (follow || !pending.is_empty()) => {
                links += 1;
                if links > 40 {
                    return Err(Errno::ELOOP);
                }
                let t = fs::readlink(cur.as_bytes())?;
                out.pop();
                if t.starts_with(b"/") {
                    out.clear();
                }
                pending.extend(t.split(|&c| c == b'/').filter(|c| !c.is_empty()).map(<[u8]>::to_vec).rev());
            }
            Ok(_) => {}
            Err(Errno::ENOENT) if missing_ok => missing = true,
            Err(e) => return Err(e),
        }
        rest.clear();
    }
    let mut r = b"/".to_vec();
    r.extend_from_slice(&out.join(&b'/'));
    Ok(r)
}

pub fn readlink(args: &[Vec<u8>]) -> i32 {
    let (mut canon, mut missing, mut newline) = (false, false, true);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'f') => canon = true,
            Opt::Short(b'e') => canon = true,
            Opt::Short(b'm') => (canon, missing) = (true, true),
            Opt::Short(b'n') => newline = false,
            Opt::Short(b'q' | b's' | b'v') => {}
            Opt::Long(l) if l == "canonicalize" || l == "canonicalize-existing" => canon = true,
            Opt::Long(l) if l == "canonicalize-missing" => (canon, missing) = (true, true),
            Opt::Long(l) if l == "no-newline" => newline = false,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let mut status = 0;
    for f in &files {
        let r = if canon { canonicalize(f, true, missing) } else { fs::readlink(f) };
        match r {
            Ok(t) => {
                io::out(&t);
                if newline || files.len() > 1 {
                    io::out(b"\n");
                }
            }
            Err(_) => status = 1,
        }
    }
    status
}

pub fn realpath(args: &[Vec<u8>]) -> i32 {
    let (mut missing, mut quiet, mut no_symlinks) = (false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'm') => missing = true,
            Opt::Short(b'e') => missing = false,
            Opt::Short(b'q') => quiet = true,
            Opt::Short(b's') => no_symlinks = true,
            Opt::Long(l) if l == "canonicalize-missing" => missing = true,
            Opt::Long(l) if l == "quiet" => quiet = true,
            Opt::Long(l) if l == "no-symlinks" || l == "strip" => no_symlinks = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let _ = no_symlinks;
    let mut status = 0;
    for f in &files {
        match canonicalize(f, true, missing) {
            Ok(t) => {
                io::out(&t);
                io::out(b"\n");
            }
            Err(e) => {
                if !quiet {
                    error_path(f, e);
                }
                status = 1;
            }
        }
    }
    status
}

pub fn mktemp(args: &[Vec<u8>]) -> i32 {
    let (mut dir, mut dry, mut quiet) = (false, false, false);
    let mut tmpdir: Option<Vec<u8>> = None;
    let mut template: Option<Vec<u8>> = None;
    let mut p = Parser::new(args, b"p");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'd') => dir = true,
            Opt::Short(b'u') => dry = true,
            Opt::Short(b'q') => quiet = true,
            Opt::Short(b't') => tmpdir = Some(slate_rt::env::var(b"TMPDIR").unwrap_or_else(|| b"/tmp".to_vec())),
            Opt::Short(b'p') => tmpdir = p.value(),
            Opt::Long(l) if l == "directory" => dir = true,
            Opt::Long(l) if l == "dry-run" => dry = true,
            Opt::Long(l) if l == "quiet" => quiet = true,
            Opt::Long(l) if l == "tmpdir" => tmpdir = Some(p.value().unwrap_or_else(|| b"/tmp".to_vec())),
            Opt::Operand(t) => template = Some(t),
            o => return bad_option(&o),
        }
    }
    let template = match template {
        Some(t) => {
            if tmpdir.is_none() && !t.contains(&b'/') && args.iter().any(|a| a == b"-t") {
                tmpdir = Some(b"/tmp".to_vec());
            }
            t
        }
        None => {
            tmpdir.get_or_insert_with(|| slate_rt::env::var(b"TMPDIR").unwrap_or_else(|| b"/tmp".to_vec()));
            b"tmp.XXXXXXXXXX".to_vec()
        }
    };
    let xs = template.iter().rev().take_while(|&&c| c == b'X').count();
    if xs < 3 {
        error(format_args!("too few X's in template '{}'", lossy(&template)));
        return 1;
    }
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for _ in 0..100 {
        let mut rnd = alloc::vec![0u8; xs];
        let _ = slate_rt::process::random(&mut rnd);
        let mut name = template[..template.len() - xs].to_vec();
        name.extend(rnd.iter().map(|&b| CHARS[usize::from(b) % CHARS.len()]));
        let path = match &tmpdir {
            Some(d) => fs::join(d, &name),
            None => name,
        };
        let r = if dry {
            if fs::lstat(&path).is_ok() { Err(Errno::EEXIST) } else { Ok(()) }
        } else if dir {
            fs::mkdir(&path, 0o700)
        } else {
            fs::open(&path, fs::O_RDWR | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600).map(|fd| {
                let _ = io::close(fd);
            })
        };
        match r {
            Ok(()) => {
                io::out(&path);
                io::out(b"\n");
                return 0;
            }
            Err(Errno::EEXIST) => continue,
            Err(e) => {
                if !quiet {
                    error(format_args!("failed to create '{}': {e}", lossy(&path)));
                }
                return 1;
            }
        }
    }
    1
}

pub fn truncate(args: &[Vec<u8>]) -> i32 {
    let mut size: Option<Vec<u8>> = None;
    let mut no_create = false;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"s");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b's') => size = p.value(),
            Opt::Short(b'c') => no_create = true,
            Opt::Long(l) if l == "size" => size = p.value(),
            Opt::Long(l) if l == "no-create" => no_create = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let Some(spec) = size else {
        error("you must specify '--size'");
        return 1;
    };
    let (rel, num) = match spec.first() {
        Some(&c @ (b'+' | b'-')) => (Some(c), &spec[1..]),
        _ => (None, &spec[..]),
    };
    let Some(n) = parse_size(num) else {
        error(format_args!("invalid number: '{}'", lossy(&spec)));
        return 1;
    };
    let mut status = 0;
    for f in &files {
        let cur = match fs::stat(f) {
            Ok(st) => st.size as u64,
            Err(_) if no_create => continue,
            Err(_) => {
                if let Ok(fd) = fs::open(f, fs::O_WRONLY | fs::O_CREAT | fs::O_CLOEXEC, 0o666) {
                    let _ = io::close(fd);
                }
                0
            }
        };
        let new = match rel {
            Some(b'+') => cur + n,
            Some(_) => cur.saturating_sub(n),
            None => n,
        };
        if let Err(e) = fs::truncate(f, new) {
            error(format_args!("cannot truncate '{}': {e}", lossy(f)));
            status = 1;
        }
    }
    status
}

/// Sizes like `10`, `4K`, `1M`, `2G` (powers of 1024), `1kB` (1000).
pub fn parse_size(s: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(s).ok()?;
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n: u64 = s[..digits].parse().ok()?;
    let suffix = &s[digits..];
    let m: u64 = match suffix {
        "" | "c" => 1,
        "b" => 512,
        "K" | "k" | "KiB" => 1 << 10,
        "M" | "MiB" => 1 << 20,
        "G" | "GiB" => 1 << 30,
        "T" | "TiB" => 1 << 40,
        "kB" | "KB" => 1000,
        "MB" => 1_000_000,
        "GB" => 1_000_000_000,
        _ => return None,
    };
    n.checked_mul(m)
}
