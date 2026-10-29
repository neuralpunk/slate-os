// SPDX-License-Identifier: MIT OR Apache-2.0

//! Small utilities: true, false, yes, echo, pwd, basename, dirname, sleep,
//! sync, env, printenv, uname, hostname, whoami, id, nproc, tty, clear,
//! seq, tee, logname, groups.

use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, print, println, process, term};

use crate::util::{Opt, Parser, bad_option, error, error_path, parse_num};

pub fn r#true(_: &[Vec<u8>]) -> i32 {
    0
}

pub fn r#false(_: &[Vec<u8>]) -> i32 {
    1
}

pub fn yes(args: &[Vec<u8>]) -> i32 {
    let mut line = if args.len() > 1 { args[1..].join(&b' ') } else { b"y".to_vec() };
    line.push(b'\n');
    let block: Vec<u8> = line.iter().copied().cycle().take(line.len() * (8192 / line.len()).max(1)).collect();
    while io::write_all(io::STDOUT, &block).is_ok() {}
    1
}

/// echo: `-n` (no newline), `-e` (escapes), `-E` (no escapes), as GNU.
pub fn echo(args: &[Vec<u8>]) -> i32 {
    let mut newline = true;
    let mut escapes = false;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a.len() < 2 || a[0] != b'-' || !a[1..].iter().all(|c| b"neE".contains(c)) {
            break;
        }
        for &c in &a[1..] {
            match c {
                b'n' => newline = false,
                b'e' => escapes = true,
                _ => escapes = false,
            }
        }
        i += 1;
    }
    let mut out = Vec::new();
    for (k, a) in args[i..].iter().enumerate() {
        if k > 0 {
            out.push(b' ');
        }
        if escapes {
            let (b, stop) = crate::util::unescape(a, false);
            out.extend_from_slice(&b);
            if stop {
                io::out(&out);
                return 0;
            }
        } else {
            out.extend_from_slice(a);
        }
    }
    if newline {
        out.push(b'\n');
    }
    io::out(&out);
    0
}

pub fn pwd(args: &[Vec<u8>]) -> i32 {
    let mut logical = false;
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'L') => logical = true,
            Opt::Short(b'P') => logical = false,
            o => return bad_option(&o),
        }
    }
    if logical
        && let Some(pwd) = slate_rt::env::var(b"PWD")
        && pwd.starts_with(b"/")
        && fs::stat(&pwd).ok().map(|s| (s.dev, s.ino)) == fs::stat(b".").ok().map(|s| (s.dev, s.ino))
    {
        io::out(&pwd);
        io::out(b"\n");
        return 0;
    }
    match fs::getcwd() {
        Ok(c) => {
            io::out(&c);
            io::out(b"\n");
            0
        }
        Err(e) => {
            error(e);
            1
        }
    }
}

pub fn basename(args: &[Vec<u8>]) -> i32 {
    let mut multiple = false;
    let mut suffix: Option<Vec<u8>> = None;
    let mut zero = false;
    let mut names = Vec::new();
    let mut p = Parser::new(args, b"s");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'a') => multiple = true,
            Opt::Short(b's') => {
                suffix = p.value();
                multiple = true;
            }
            Opt::Short(b'z') => zero = true,
            Opt::Long(l) if l == "multiple" => multiple = true,
            Opt::Long(l) if l == "suffix" => {
                suffix = p.value();
                multiple = true;
            }
            Opt::Long(l) if l == "zero" => zero = true,
            Opt::Operand(a) => names.push(a),
            o => return bad_option(&o),
        }
    }
    if names.is_empty() {
        error("missing operand");
        return 1;
    }
    if !multiple && names.len() == 2 {
        suffix = names.pop();
    }
    if !multiple && names.len() > 1 {
        error(format_args!("extra operand '{}'", lossy(&names[1])));
        return 1;
    }
    for n in &names {
        let mut b = fs::basename(n).to_vec();
        if let Some(s) = &suffix
            && b.len() > s.len()
            && b.ends_with(s)
        {
            b.truncate(b.len() - s.len());
        }
        b.push(if zero { 0 } else { b'\n' });
        io::out(&b);
    }
    0
}

pub fn dirname(args: &[Vec<u8>]) -> i32 {
    let names: Vec<&Vec<u8>> = args[1..].iter().filter(|a| a.as_slice() != b"--").collect();
    if names.is_empty() {
        error("missing operand");
        return 1;
    }
    for n in names {
        io::out(fs::dirname(n));
        io::out(b"\n");
    }
    0
}

/// A duration like `1.5`, `2m`, `1h`, `3d` in nanoseconds.
pub fn parse_duration(s: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(s).ok()?;
    let (num, mult) = match s.as_bytes().last()? {
        b's' => (&s[..s.len() - 1], 1.0),
        b'm' => (&s[..s.len() - 1], 60.0),
        b'h' => (&s[..s.len() - 1], 3600.0),
        b'd' => (&s[..s.len() - 1], 86400.0),
        _ => (s, 1.0),
    };
    let v: f64 = num.parse().ok()?;
    if v < 0.0 || v.is_nan() {
        return None;
    }
    Some((v * mult * 1e9) as u64)
}

pub fn sleep(args: &[Vec<u8>]) -> i32 {
    if args.len() < 2 {
        error("missing operand");
        return 1;
    }
    let mut total = 0u64;
    for a in &args[1..] {
        match parse_duration(a) {
            Some(ns) => total += ns,
            None => {
                error(format_args!("invalid time interval '{}'", lossy(a)));
                return 1;
            }
        }
    }
    let end = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    let end_ns = end.0 as u64 * 1_000_000_000 + end.1 as u64 + total;
    loop {
        let n = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
        let now = n.0 as u64 * 1_000_000_000 + n.1 as u64;
        if now >= end_ns {
            return 0;
        }
        slate_rt::time::sleep_ns(end_ns - now);
    }
}

pub fn sync(_: &[Vec<u8>]) -> i32 {
    fs::sync();
    0
}

/// env [-i] [-u NAME] [NAME=VALUE]... [COMMAND [ARG]...]
pub fn env(args: &[Vec<u8>]) -> i32 {
    let mut vars: Vec<Vec<u8>> = slate_rt::env::vars().to_vec();
    let mut i = 1;
    let mut zero = false;
    while i < args.len() {
        let a = &args[i];
        match a.as_slice() {
            b"-i" | b"-" | b"--ignore-environment" => vars.clear(),
            b"-0" | b"--null" => zero = true,
            b"-u" | b"--unset" => {
                i += 1;
                let Some(n) = args.get(i) else { return crate::util::missing_value('u') };
                vars.retain(|v| v.split(|&c| c == b'=').next() != Some(n.as_slice()));
            }
            b"--" => {
                i += 1;
                break;
            }
            _ if a.starts_with(b"-") && a.len() > 1 => return bad_option(&Opt::Short(a[1])),
            _ => break,
        }
        i += 1;
    }
    while i < args.len() && args[i].contains(&b'=') {
        let name = args[i].split(|&c| c == b'=').next().unwrap().to_vec();
        vars.retain(|v| v.split(|&c| c == b'=').next() != Some(name.as_slice()));
        vars.push(args[i].clone());
        i += 1;
    }
    if i >= args.len() {
        for v in &vars {
            io::out(v);
            io::out(if zero { b"\0" } else { b"\n" });
        }
        return 0;
    }
    let cmd = &args[i];
    let path_var = vars.iter().find_map(|v| v.strip_prefix(b"PATH=")).map(<[u8]>::to_vec);
    let found = if cmd.contains(&b'/') {
        Some(cmd.clone())
    } else {
        let path = path_var.unwrap_or_else(|| b"/bin:/usr/bin".to_vec());
        path.split(|&c| c == b':').map(|d| fs::join(d, cmd)).find(|c| fs::stat(c).is_ok_and(|s| s.is_file()))
    };
    let Some(path) = found else {
        error_path(cmd, slate_rt::Errno::ENOENT);
        return 127;
    };
    let e = process::execve(&path, &args[i..], &vars);
    error_path(cmd, e);
    if e == slate_rt::Errno::ENOENT { 127 } else { 126 }
}

pub fn printenv(args: &[Vec<u8>]) -> i32 {
    if args.len() < 2 {
        for v in slate_rt::env::vars() {
            io::out(v);
            io::out(b"\n");
        }
        return 0;
    }
    let mut status = 0;
    for n in &args[1..] {
        match slate_rt::env::var(n) {
            Some(v) => {
                io::out(&v);
                io::out(b"\n");
            }
            None => status = 1,
        }
    }
    status
}

pub fn uname(args: &[Vec<u8>]) -> i32 {
    let [sys, node, rel, ver, mach] = process::uname();
    // Flags in output order: s n r v m p i o.
    let mut want = [false; 8];
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        let idx = match &o {
            Opt::Short(b'a') => {
                want = [true, true, true, true, true, false, false, true];
                continue;
            }
            Opt::Short(b's') => 0,
            Opt::Short(b'n') => 1,
            Opt::Short(b'r') => 2,
            Opt::Short(b'v') => 3,
            Opt::Short(b'm') => 4,
            Opt::Short(b'p') => 5,
            Opt::Short(b'i') => 6,
            Opt::Short(b'o') => 7,
            Opt::Long(l) if l == "all" => {
                want = [true, true, true, true, true, false, false, true];
                continue;
            }
            Opt::Long(l) if l == "kernel-name" => 0,
            Opt::Long(l) if l == "nodename" => 1,
            Opt::Long(l) if l == "kernel-release" => 2,
            Opt::Long(l) if l == "kernel-version" => 3,
            Opt::Long(l) if l == "machine" => 4,
            Opt::Long(l) if l == "operating-system" => 7,
            o => return bad_option(o),
        };
        want[idx] = true;
    }
    if !want.iter().any(|&w| w) {
        want[0] = true;
    }
    // The operating system: SlateOS on Slate's kernel (ADR 0153), and as
    // GNU's uname says it elsewhere.
    let os: &[u8] = if sys == b"Slate" { b"SlateOS" } else { b"GNU/Linux" };
    let fields: [&[u8]; 8] = [&sys, &node, &rel, &ver, &mach, b"unknown", b"unknown", os];
    let parts: Vec<&[u8]> = (0..8).filter(|&i| want[i]).map(|i| fields[i]).collect();
    io::out(&parts.join(&b' '));
    io::out(b"\n");
    0
}

pub fn hostname(args: &[Vec<u8>]) -> i32 {
    if let Some(name) = args.get(1) {
        return match process::sethostname(name) {
            Ok(()) => 0,
            Err(e) => {
                error(e);
                1
            }
        };
    }
    let [_, node, ..] = process::uname();
    io::out(&node);
    io::out(b"\n");
    0
}

/// A user or group database entry: (name, id).
pub fn db_names(path: &[u8]) -> Vec<(Vec<u8>, u32, Vec<Vec<u8>>)> {
    let Ok(data) = fs::read_file(path) else { return Vec::new() };
    data.split(|&c| c == b'\n')
        .filter_map(|l| {
            let f: Vec<&[u8]> = l.split(|&c| c == b':').collect();
            let id = parse_num(f.get(2)?)?;
            let members = f
                .get(3)
                .map(|m| m.split(|&c| c == b',').filter(|x| !x.is_empty()).map(<[u8]>::to_vec).collect())
                .unwrap_or_default();
            Some((f[0].to_vec(), id, members))
        })
        .collect()
}

pub fn user_name(uid: u32) -> Option<Vec<u8>> {
    db_names(b"/etc/passwd").into_iter().find(|e| e.1 == uid).map(|e| e.0)
}

pub fn group_name(gid: u32) -> Option<Vec<u8>> {
    db_names(b"/etc/group").into_iter().find(|e| e.1 == gid).map(|e| e.0)
}

pub fn whoami(_: &[Vec<u8>]) -> i32 {
    let uid = process::geteuid();
    match user_name(uid) {
        Some(n) => {
            io::out(&n);
            io::out(b"\n");
            0
        }
        None => {
            error(format_args!("cannot find name for user ID {uid}"));
            1
        }
    }
}

pub fn id(args: &[Vec<u8>]) -> i32 {
    let (mut only_u, mut only_g, mut only_gs, mut names, mut real) = (false, false, false, false, false);
    let mut user: Option<Vec<u8>> = None;
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'u') => only_u = true,
            Opt::Short(b'g') => only_g = true,
            Opt::Short(b'G') => only_gs = true,
            Opt::Short(b'n') => names = true,
            Opt::Short(b'r') => real = true,
            Opt::Operand(u) => user = Some(u),
            o => return bad_option(&o),
        }
    }
    let (uid, gid, groups) = match &user {
        Some(u) => {
            let pw = db_passwd(u);
            let Some((uid, gid)) = pw else {
                error(format_args!("'{}': no such user", lossy(u)));
                return 1;
            };
            let mut gs = alloc::vec![gid];
            for (_, g, members) in db_names(b"/etc/group") {
                if members.iter().any(|m| m == u) && !gs.contains(&g) {
                    gs.push(g);
                }
            }
            (uid, gid, gs)
        }
        None => {
            let (uid, gid) =
                if real { (process::getuid(), process::getgid()) } else { (process::geteuid(), process::getegid()) };
            let mut gs = alloc::vec![gid];
            for g in process::getgroups() {
                if !gs.contains(&g) {
                    gs.push(g);
                }
            }
            (uid, gid, gs)
        }
    };
    let uname = |u: u32| user_name(u).map(|n| lossy(&n).into_owned());
    let gname = |g: u32| group_name(g).map(|n| lossy(&n).into_owned());
    if only_u || only_g || only_gs {
        let ids: Vec<u32> = if only_u {
            alloc::vec![uid]
        } else if only_g {
            alloc::vec![gid]
        } else {
            groups
        };
        let parts: Vec<alloc::string::String> = ids
            .iter()
            .map(|&i| {
                if names {
                    (if only_u { uname(i) } else { gname(i) }).unwrap_or_else(|| alloc::format!("{i}"))
                } else {
                    alloc::format!("{i}")
                }
            })
            .collect();
        println!("{}", parts.join(" "));
        return 0;
    }
    let fmt = |i: u32, n: Option<alloc::string::String>| match n {
        Some(n) => alloc::format!("{i}({n})"),
        None => alloc::format!("{i}"),
    };
    let gs: Vec<alloc::string::String> = groups.iter().map(|&g| fmt(g, gname(g))).collect();
    println!("uid={} gid={} groups={}", fmt(uid, uname(uid)), fmt(gid, gname(gid)), gs.join(","));
    0
}

/// (uid, gid) of a user name in /etc/passwd.
pub fn db_passwd(name: &[u8]) -> Option<(u32, u32)> {
    let data = fs::read_file(b"/etc/passwd").ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let f: Vec<&[u8]> = l.split(|&c| c == b':').collect();
        (f.first() == Some(&name)).then(|| Some((parse_num(f.get(2)?)?, parse_num(f.get(3)?)?)))?
    })
}

pub fn groups(args: &[Vec<u8>]) -> i32 {
    let mut a = alloc::vec![b"id".to_vec(), b"-Gn".to_vec()];
    a.extend(args[1..].iter().cloned());
    id(&a)
}

pub fn nproc(_: &[Vec<u8>]) -> i32 {
    let n = fs::read_file(b"/proc/cpuinfo")
        .map(|d| d.split(|&c| c == b'\n').filter(|l| l.starts_with(b"processor")).count())
        .unwrap_or(1)
        .max(1);
    println!("{n}");
    0
}

pub fn tty(args: &[Vec<u8>]) -> i32 {
    let silent = args.iter().any(|a| a == b"-s" || a == b"--silent" || a == b"--quiet");
    if !term::isatty(io::STDIN) {
        if !silent {
            println!("not a tty");
        }
        return 1;
    }
    if !silent {
        let name = fs::readlink(b"/proc/self/fd/0").unwrap_or_else(|_| b"/dev/tty".to_vec());
        io::out(&name);
        io::out(b"\n");
    }
    0
}

pub fn clear(_: &[Vec<u8>]) -> i32 {
    print!("\x1b[H\x1b[2J\x1b[3J");
    0
}

/// seq [-s SEP] [-w] [FIRST [INCREMENT]] LAST (integers and decimals).
pub fn seq(args: &[Vec<u8>]) -> i32 {
    let mut sep = b"\n".to_vec();
    let mut width = false;
    let mut nums: Vec<Vec<u8>> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        // Negative numbers are operands.
        if a.len() > 1 && a[0] == b'-' && !(a[1].is_ascii_digit() || a[1] == b'.') {
            match a.as_slice() {
                b"-s" => {
                    i += 1;
                    sep = args.get(i).cloned().unwrap_or_default();
                }
                b"-w" => width = true,
                x if x.starts_with(b"-s") => sep = x[2..].to_vec(),
                _ => return bad_option(&Opt::Short(a[1])),
            }
        } else {
            nums.push(a.clone());
        }
        i += 1;
    }
    let parse = |b: &[u8]| -> Option<f64> { core::str::from_utf8(b).ok()?.parse().ok() };
    let decimals = |b: &[u8]| b.iter().position(|&c| c == b'.').map_or(0, |p| b.len() - p - 1);
    let (first, inc, last) = match nums.len() {
        1 => (b"1".to_vec(), b"1".to_vec(), nums[0].clone()),
        2 => (nums[0].clone(), b"1".to_vec(), nums[1].clone()),
        3 => (nums[0].clone(), nums[1].clone(), nums[2].clone()),
        _ => {
            error("missing operand");
            return 1;
        }
    };
    let (Some(f), Some(st), Some(l)) = (parse(&first), parse(&inc), parse(&last)) else {
        error("invalid floating point argument");
        return 1;
    };
    if st == 0.0 {
        error("invalid Zero increment value: '0'");
        return 1;
    }
    let prec = decimals(&first).max(decimals(&inc));
    let fmt = |v: f64| alloc::format!("{:.*}", prec, v);
    let w = if width { fmt(f).len().max(fmt(l).len()) } else { 0 };
    let mut out = Vec::new();
    let mut k = 0u64;
    loop {
        let v = f + st * k as f64;
        if (st > 0.0 && v > l + 1e-9) || (st < 0.0 && v < l - 1e-9) {
            break;
        }
        if k > 0 {
            out.extend_from_slice(&sep);
        }
        let s = fmt(v);
        if s.len() < w {
            let (neg, digits) = if let Some(d) = s.strip_prefix('-') { (true, d) } else { (false, s.as_str()) };
            if neg {
                out.push(b'-');
            }
            out.resize(out.len() + w - s.len(), b'0');
            out.extend_from_slice(digits.as_bytes());
        } else {
            out.extend_from_slice(s.as_bytes());
        }
        k += 1;
        if out.len() > 64 * 1024 {
            io::out(&out);
            out.clear();
        }
    }
    if k > 0 {
        out.push(b'\n');
    }
    io::out(&out);
    0
}

pub fn tee(args: &[Vec<u8>]) -> i32 {
    let mut append = false;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'a') => append = true,
            Opt::Short(b'i') => {
                let _ = slate_rt::signal::set(slate_rt::signal::SIGINT, slate_rt::signal::Disposition::Ignore);
            }
            Opt::Long(l) if l == "append" => append = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let mut status = 0;
    let mut fds = Vec::new();
    for f in &files {
        let flags = fs::O_WRONLY | fs::O_CREAT | fs::O_CLOEXEC | if append { fs::O_APPEND } else { fs::O_TRUNC };
        match fs::open(f, flags, 0o666) {
            Ok(fd) => fds.push(fd),
            Err(e) => {
                error_path(f, e);
                status = 1;
            }
        }
    }
    let mut buf = alloc::vec![0u8; 64 * 1024];
    loop {
        let n = match io::read(io::STDIN, &mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                error(e);
                return 1;
            }
        };
        if io::write_all(io::STDOUT, &buf[..n]).is_err() {
            status = 1;
        }
        for &fd in &fds {
            if io::write_all(fd, &buf[..n]).is_err() {
                status = 1;
            }
        }
    }
    status
}

pub fn logname(_: &[Vec<u8>]) -> i32 {
    whoami(&[])
}
