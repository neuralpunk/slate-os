// SPDX-License-Identifier: MIT OR Apache-2.0

//! install: copy files into place with a mode (0755 unless `-m`), owner
//! and group, creating directories with `-d` and leading ones with `-D`;
//! `-C` leaves a destination that already matches alone, and `-s` runs a
//! strip program (`strip`, or `--strip-program`), failing if there is
//! none rather than installing unstripped without a word.

use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy, println, process};

use crate::fileops::{apply_mode, lookup_id};
use crate::util::{Opt, Parser, bad_option, error, missing_value};

struct Opts {
    mode: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    compare: bool,
    preserve: bool,
    strip: Option<Vec<u8>>,
    verbose: bool,
    backup: bool,
}

/// Create `path` and its missing parents, saying so with `-v`.
fn make_dirs(path: &[u8], mode: u32, verbose: bool) -> Result<(), Errno> {
    let mut cur = Vec::new();
    if path.starts_with(b"/") {
        cur.push(b'/');
    }
    let parts: Vec<&[u8]> = path.split(|&c| c == b'/').filter(|p| !p.is_empty()).collect();
    for (i, part) in parts.iter().enumerate() {
        if !cur.is_empty() && cur.last() != Some(&b'/') {
            cur.push(b'/');
        }
        cur.extend_from_slice(part);
        match fs::stat(&cur) {
            Ok(st) if st.is_dir() => continue,
            Ok(_) => return Err(Errno::ENOTDIR),
            Err(_) => {}
        }
        let last = i + 1 == parts.len();
        fs::mkdir(&cur, if last { mode } else { 0o755 })?;
        if last {
            // mkdir is subject to the umask; the mode asked for is not.
            fs::chmod(&cur, mode)?;
        }
        if verbose {
            println!("{}: creating directory '{}'", slate_rt::prog_name(), lossy(&cur));
        }
    }
    Ok(())
}

fn same_content(a: &[u8], b: &[u8]) -> bool {
    match (fs::read_file(a), fs::read_file(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn copy(src: &[u8], dst: &[u8], o: &Opts) -> bool {
    let st = match fs::stat(src) {
        Ok(s) => s,
        Err(e) => {
            error(format_args!("cannot stat '{}': {e}", lossy(src)));
            return false;
        }
    };
    if st.is_dir() {
        error(format_args!("omitting directory '{}'", lossy(src)));
        return false;
    }
    if let Ok(d) = fs::stat(dst) {
        if d.is_dir() {
            error(format_args!("cannot overwrite directory '{}' with non-directory '{}'", lossy(dst), lossy(src)));
            return false;
        }
        if d.dev == st.dev && d.ino == st.ino {
            error(format_args!("'{}' and '{}' are the same file", lossy(src), lossy(dst)));
            return false;
        }
        if o.compare {
            let uid = o.uid.unwrap_or(d.uid);
            let gid = o.gid.unwrap_or(d.gid);
            if d.mode & 0o7777 == o.mode && d.uid == uid && d.gid == gid && same_content(src, dst) {
                return true;
            }
            if fs::unlink(dst).is_ok() && o.verbose {
                println!("removed '{}'", lossy(dst));
            }
        }
        if o.backup {
            let mut b = dst.to_vec();
            b.push(b'~');
            let _ = fs::rename(dst, &b);
        }
    }
    let data = match fs::read_file(src) {
        Ok(d) => d,
        Err(e) => {
            error(format_args!("cannot open '{}' for reading: {e}", lossy(src)));
            return false;
        }
    };
    let flags = fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC;
    let fd = match fs::open(dst, flags, 0o600) {
        Ok(fd) => fd,
        // A busy or unwritable file is replaced instead.
        Err(_) if fs::unlink(dst).is_ok() => match fs::open(dst, flags, 0o600) {
            Ok(fd) => fd,
            Err(e) => {
                error(format_args!("cannot create regular file '{}': {e}", lossy(dst)));
                return false;
            }
        },
        Err(e) => {
            error(format_args!("cannot create regular file '{}': {e}", lossy(dst)));
            return false;
        }
    };
    let r = io::write_all(fd, &data);
    let _ = io::close(fd);
    if let Err(e) = r {
        error(format_args!("error writing '{}': {e}", lossy(dst)));
        return false;
    }
    if o.verbose {
        println!("'{}' -> '{}'", lossy(src), lossy(dst));
    }
    if let Some(prog) = &o.strip {
        let Some(path) = (if prog.contains(&b'/') { Some(prog.clone()) } else { process::find_in_path(prog) }) else {
            error(format_args!("cannot run strip program '{}': No such file or directory", lossy(prog)));
            return false;
        };
        match process::run(&path, &[prog.clone(), dst.to_vec()]) {
            Ok(0) => {}
            _ => {
                error("strip process terminated abnormally");
                return false;
            }
        }
    }
    finish(dst, o, Some(&st))
}

/// Owner, group, mode and (with `-p`) times.
fn finish(path: &[u8], o: &Opts, src: Option<&fs::Stat>) -> bool {
    if (o.uid.is_some() || o.gid.is_some())
        && let Err(e) = fs::chown(path, o.uid.unwrap_or(u32::MAX), o.gid.unwrap_or(u32::MAX))
    {
        error(format_args!("cannot change ownership of '{}': {e}", lossy(path)));
        return false;
    }
    if let Err(e) = fs::chmod(path, o.mode) {
        error(format_args!("cannot change permissions of '{}': {e}", lossy(path)));
        return false;
    }
    if o.preserve
        && let Some(st) = src
    {
        let _ = fs::set_times(path, Some(Some((st.atime, st.atime_nsec))), Some(Some((st.mtime, st.mtime_nsec))), true);
    }
    true
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let (mut dirs, mut leading, mut target, mut no_target) = (false, false, None::<Vec<u8>>, false);
    let mut mode_spec: Option<Vec<u8>> = None;
    let (mut owner, mut group) = (None::<Vec<u8>>, None::<Vec<u8>>);
    let mut o = Opts {
        mode: 0o755,
        uid: None,
        gid: None,
        compare: false,
        preserve: false,
        strip: None,
        verbose: false,
        backup: false,
    };
    let mut strip = false;
    let mut strip_prog = b"strip".to_vec();
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"mogtS");
    while let Some(opt) = p.next() {
        match opt {
            Opt::Short(b'c') => {}
            Opt::Short(b'd') => dirs = true,
            Opt::Short(b'D') => leading = true,
            Opt::Short(b'C') => o.compare = true,
            Opt::Short(b'p') => o.preserve = true,
            Opt::Short(b's') => strip = true,
            Opt::Short(b'v') => o.verbose = true,
            Opt::Short(b'b') => o.backup = true,
            Opt::Short(b'T') => no_target = true,
            Opt::Long(ref l) if l == "directory" => dirs = true,
            Opt::Long(ref l) if l == "compare" => o.compare = true,
            Opt::Long(ref l) if l == "preserve-timestamps" => o.preserve = true,
            Opt::Long(ref l) if l == "strip" => strip = true,
            Opt::Long(ref l) if l == "verbose" => o.verbose = true,
            Opt::Long(ref l) if l == "no-target-directory" => no_target = true,
            Opt::Short(c @ (b'm' | b'o' | b'g' | b't')) => {
                let Some(v) = p.value() else { return missing_value(c as char) };
                match c {
                    b'm' => mode_spec = Some(v),
                    b'o' => owner = Some(v),
                    b'g' => group = Some(v),
                    _ => target = Some(v),
                }
            }
            Opt::Long(ref l)
                if matches!(l.as_str(), "mode" | "owner" | "group" | "target-directory" | "strip-program") =>
            {
                let Some(v) = p.value() else { return missing_value(l) };
                match l.as_str() {
                    "mode" => mode_spec = Some(v),
                    "owner" => owner = Some(v),
                    "group" => group = Some(v),
                    "strip-program" => strip_prog = v,
                    _ => target = Some(v),
                }
            }
            Opt::Operand(x) => ops.push(x),
            o => return bad_option(&o),
        }
    }
    if strip {
        o.strip = Some(strip_prog);
    }
    if let Some(m) = &mode_spec {
        match apply_mode(m, 0o755, dirs, 0) {
            Some(v) => o.mode = v,
            None => {
                error(format_args!("invalid mode '{}'", lossy(m)));
                return 1;
            }
        }
    }
    if let Some(u) = &owner {
        match lookup_id(u, b"/etc/passwd") {
            Some(id) => o.uid = Some(id),
            None => {
                error(format_args!("invalid user '{}'", lossy(u)));
                return 1;
            }
        }
    }
    if let Some(g) = &group {
        match lookup_id(g, b"/etc/group") {
            Some(id) => o.gid = Some(id),
            None => {
                error(format_args!("invalid group '{}'", lossy(g)));
                return 1;
            }
        }
    }
    let usage = |msg: core::fmt::Arguments| -> i32 {
        error(msg);
        slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
        1
    };
    let mut status = 0;
    if dirs {
        if ops.is_empty() {
            return usage(format_args!("missing file operand"));
        }
        for d in &ops {
            if let Err(e) = make_dirs(d, o.mode, o.verbose)
                .and_then(|()| if finish(d, &o, None) { Ok(()) } else { Err(Errno::EPERM) })
            {
                if e != Errno::EPERM {
                    error(format_args!("cannot create directory '{}': {e}", lossy(d)));
                }
                status = 1;
            }
        }
        io::flush_stdout();
        return status;
    }
    if ops.is_empty() && target.is_none() {
        return usage(format_args!("missing file operand"));
    }
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = if let Some(t) = &target {
        if leading && let Err(e) = make_dirs(t, 0o755, o.verbose) {
            error(format_args!("cannot create directory '{}': {e}", lossy(t)));
            return 1;
        }
        ops.iter().map(|s| (s.clone(), fs::join(t, fs::basename(s)))).collect()
    } else {
        if ops.len() < 2 {
            return usage(format_args!("missing destination file operand after '{}'", lossy(&ops[0])));
        }
        let dest = ops.pop().unwrap_or_default();
        let into_dir = !no_target && fs::stat(&dest).is_ok_and(|s| s.is_dir());
        if ops.len() > 1 && !into_dir {
            error(format_args!("target '{}' is not a directory", lossy(&dest)));
            return 1;
        }
        if into_dir {
            ops.iter().map(|s| (s.clone(), fs::join(&dest, fs::basename(s)))).collect()
        } else {
            alloc::vec![(ops[0].clone(), dest)]
        }
    };
    for (src, dst) in &pairs {
        if leading && target.is_none() {
            let parent = fs::dirname(dst);
            if parent != b"."
                && !parent.is_empty()
                && let Err(e) = make_dirs(parent, 0o755, o.verbose)
            {
                error(format_args!("cannot create directory '{}': {e}", lossy(parent)));
                status = 1;
                continue;
            }
        }
        if !copy(src, dst, &o) {
            status = 1;
        }
    }
    io::flush_stdout();
    status
}
