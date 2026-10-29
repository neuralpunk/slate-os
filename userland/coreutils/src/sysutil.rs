// SPDX-License-Identifier: MIT OR Apache-2.0

//! System tools: date, stat, df, du, dmesg, mount, umount, free, uptime, ps,
//! kill, which, cmp, xargs, nohup, timeout, expr, chroot.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, fs, io, lossy, println, process, signal};

use crate::util::{Opt, Parser, bad_option, error, error_path, human, parse_num, read_input};

pub fn date(args: &[Vec<u8>]) -> i32 {
    use crate::datetime::{self, Instant};
    let mut fmt: Option<String> = None;
    let mut when: Option<Instant> = None;
    let mut date_arg: Option<String> = None;
    let mut file_arg: Option<Vec<u8>> = None;
    let mut set_arg: Option<String> = None;
    let mut posix_set: Option<String> = None;
    let mut utc = false;
    let (mut debug, mut resolution) = (false, false);
    let iso_fmt = |v: Option<&[u8]>| -> Option<&'static str> {
        Some(match v.unwrap_or(b"date") {
            b"date" => "%Y-%m-%d",
            b"hours" => "%Y-%m-%dT%H%:z",
            b"minutes" => "%Y-%m-%dT%H:%M%:z",
            b"seconds" => "%Y-%m-%dT%H:%M:%S%:z",
            b"ns" => "%Y-%m-%dT%H:%M:%S,%N%:z",
            _ => return None,
        })
    };
    let mut p = Parser::new(args, b"dfrs");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'u') => utc = true,
            Opt::Short(b'R') => fmt = Some(String::from("%a, %d %b %Y %H:%M:%S %z")),
            Opt::Short(b'I') => {
                let v = p.inline_bundle();
                match iso_fmt((!v.is_empty()).then_some(v.as_slice())) {
                    Some(f) => fmt = Some(String::from(f)),
                    None => {
                        error(format_args!("invalid argument '{}' for '--iso-8601'", lossy(&v)));
                        return 1;
                    }
                }
            }
            Opt::Short(b'd') => date_arg = Some(lossy(&p.value().unwrap_or_default()).into_owned()),
            Opt::Short(b'f') => file_arg = p.value(),
            Opt::Short(b's') => set_arg = Some(lossy(&p.value().unwrap_or_default()).into_owned()),
            Opt::Short(b'r') => {
                let f = p.value().unwrap_or_default();
                match fs::stat(&f) {
                    Ok(st) => when = Some(Instant { secs: st.mtime, nsec: st.mtime_nsec as u32 }),
                    Err(e) => {
                        error_path(&f, e);
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "utc" || l == "universal" => utc = true,
            Opt::Long(l) if l == "debug" => debug = true,
            Opt::Long(l) if l == "resolution" => resolution = true,
            Opt::Long(l) if l == "rfc-email" || l == "rfc-2822" => fmt = Some(String::from("%a, %d %b %Y %H:%M:%S %z")),
            Opt::Long(l) if l == "date" => date_arg = Some(lossy(&p.value().unwrap_or_default()).into_owned()),
            Opt::Long(l) if l == "file" => file_arg = p.value(),
            Opt::Long(l) if l == "set" => set_arg = Some(lossy(&p.value().unwrap_or_default()).into_owned()),
            Opt::Long(l) if l == "reference" => {
                let f = p.value().unwrap_or_default();
                match fs::stat(&f) {
                    Ok(st) => when = Some(Instant { secs: st.mtime, nsec: st.mtime_nsec as u32 }),
                    Err(e) => {
                        error_path(&f, e);
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "iso-8601" => {
                let v = p.inline_value();
                match iso_fmt(v.as_deref()) {
                    Some(f) => fmt = Some(String::from(f)),
                    None => {
                        error(format_args!("invalid argument '{}' for '--iso-8601'", lossy(&v.unwrap_or_default())));
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "rfc-3339" => {
                let v = p.inline_value().or_else(|| p.value()).unwrap_or_default();
                fmt = Some(String::from(match v.as_slice() {
                    b"date" => "%Y-%m-%d",
                    b"seconds" => "%Y-%m-%d %H:%M:%S%:z",
                    b"ns" => "%Y-%m-%d %H:%M:%S.%N%:z",
                    _ => {
                        error(format_args!("invalid argument '{}' for '--rfc-3339'", lossy(&v)));
                        return 1;
                    }
                }));
            }
            Opt::Operand(f) if f.starts_with(b"+") => fmt = Some(lossy(&f[1..]).into_owned()),
            Opt::Operand(f) if posix_set.is_none() => posix_set = Some(lossy(&f).into_owned()),
            o => return bad_option(&o),
        }
    }
    // The clock's resolution: Slate keeps the time in nanoseconds.
    if resolution {
        println!("0.000000001");
        return 0;
    }
    let (secs, nsec) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
    let now = Instant { secs, nsec: nsec as u32 };
    let out_fmt = fmt.clone().unwrap_or_else(|| String::from("%a %b %e %H:%M:%S %Z %Y"));
    let show = |t: Instant| {
        let tm = if utc { slate_rt::time::gmtime(t.secs) } else { slate_rt::tz::localtime(t.secs) };
        let f = fmt.as_deref().unwrap_or("%a %b %e %H:%M:%S %Z %Y");
        println!("{}", datetime::format(&tm, t.nsec, f));
    };
    if let Some(file) = &file_arg {
        let data = match crate::util::read_input(file) {
            Ok(d) => d,
            Err(e) => {
                error_path(file, e);
                return 1;
            }
        };
        let mut status = 0;
        for line in crate::util::lines(&data, b'\n') {
            match datetime::parse(&lossy(line), now, utc) {
                Some(t) => show(t),
                None => {
                    error(format_args!("invalid date '{}'", lossy(line)));
                    status = 1;
                }
            }
        }
        return status;
    }
    if let Some(s) = &date_arg {
        let (t, traced) = datetime::parse_traced(s, now, utc);
        if debug {
            for l in &traced.lines {
                error(l);
            }
        }
        match t {
            Some(t) => {
                when = Some(t);
                if debug {
                    // The zone the result is shown in, as GNU's --debug
                    // says it (the string's own zone if it named one).
                    let (zone, tm) = match &traced.zone_in_string {
                        Some((name, rule)) => {
                            (alloc::format!("TZ=\"{name}\" environment value"), rule.localtime(t.secs))
                        }
                        None if utc => (String::from("Universal Time"), slate_rt::time::gmtime(t.secs)),
                        None => (
                            match slate_rt::env::var(b"TZ") {
                                Some(tz) => alloc::format!("TZ=\"{}\" environment value", lossy(&tz)),
                                None => String::from("system default"),
                            },
                            slate_rt::tz::localtime(t.secs),
                        ),
                    };
                    let u = slate_rt::time::gmtime(t.secs);
                    let ymd = |x: &slate_rt::time::Tm| datetime::format(x, 0, "(Y-M-D) %Y-%m-%d %H:%M:%S");
                    error(format_args!("timezone: {zone}"));
                    error(format_args!("final: {}.{:09} (epoch-seconds)", t.secs, t.nsec));
                    error(format_args!("final: {} (UTC)", ymd(&u)));
                    error(format_args!("final: {} (UTC{})", ymd(&tm), datetime::offset_text(tm.offset)));
                }
            }
            None => {
                error(format_args!("invalid date '{s}'"));
                return 1;
            }
        }
    }
    if debug {
        error(format_args!("output format: '{out_fmt}'"));
    }
    // Setting the clock: -s STRING, or POSIX's MMDDhhmm[[CC]YY][.ss].
    let target = match (&set_arg, &posix_set) {
        (Some(s), _) => Some((s, datetime::parse(s, now, utc))),
        (None, Some(s)) => Some((s, parse_posix_date(s, utc).map(|secs| Instant { secs, nsec: 0 }))),
        _ => None,
    };
    if let Some((s, t)) = target {
        let Some(t) = t else {
            error(format_args!("invalid date '{s}'"));
            return 1;
        };
        if let Err(e) = slate_rt::time::set(slate_rt::time::CLOCK_REALTIME, t.secs, i64::from(t.nsec)) {
            error(format_args!("cannot set date: {e}"));
            return 1;
        }
        when = Some(t);
    }
    show(when.unwrap_or(now));
    0
}

/// POSIX date(1)'s `MMDDhhmm[[CC]YY][.ss]`: two-digit years 69-99 are
/// 19YY, 00-68 20YY; the year defaults to this one.
pub fn parse_posix_date(s: &str, utc: bool) -> Option<i64> {
    let (digits, secs) = match s.split_once('.') {
        Some((d, ss)) if ss.len() == 2 => (d, ss.parse().ok()?),
        Some(_) => return None,
        None => (s, 0),
    };
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let two = |i: usize| digits[i..i + 2].parse::<u32>().ok();
    let now = slate_rt::time::unix();
    let mut tm = if utc { slate_rt::time::gmtime(now) } else { slate_rt::tz::localtime(now) };
    tm.year = match digits.len() {
        8 => tm.year,
        10 => match two(8)? {
            yy @ 69..=99 => 1900 + i64::from(yy),
            yy => 2000 + i64::from(yy),
        },
        12 => digits[8..12].parse().ok()?,
        _ => return None,
    };
    (tm.month, tm.day, tm.hour, tm.min, tm.sec) = (two(0)?, two(2)?, two(4)?, two(6)?, secs);
    to_time(&tm, utc)
}

/// A checked broken-down time as seconds since the epoch.
fn to_time(tm: &slate_rt::time::Tm, utc: bool) -> Option<i64> {
    let leap = slate_rt::time::is_leap(tm.year);
    let days = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let ok = (1..=12).contains(&tm.month)
        && (1..=days[tm.month as usize - 1]).contains(&tm.day)
        && tm.hour < 24
        && tm.min < 60
        && tm.sec < 61;
    ok.then(|| if utc { slate_rt::time::timegm(tm) } else { slate_rt::tz::timelocal(tm) })
}

fn file_type(st: &fs::Stat) -> &'static str {
    match st.kind() {
        fs::S_IFREG if st.size == 0 => "regular empty file",
        fs::S_IFREG => "regular file",
        fs::S_IFDIR => "directory",
        fs::S_IFLNK => "symbolic link",
        fs::S_IFCHR => "character special file",
        fs::S_IFBLK => "block special file",
        fs::S_IFIFO => "fifo",
        fs::S_IFSOCK => "socket",
        _ => "weird file",
    }
}

pub fn stat(args: &[Vec<u8>]) -> i32 {
    let mut format: Option<Vec<u8>> = None;
    let (mut deref, mut fs_mode, mut terse) = (false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"c");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'c') => format = p.value(),
            Opt::Short(b'L') => deref = true,
            Opt::Short(b'f') => fs_mode = true,
            Opt::Short(b't') => terse = true,
            Opt::Long(l) if l == "format" => format = p.value(),
            Opt::Long(l) if l == "printf" => format = p.value().map(|v| crate::util::unescape(&v, true).0),
            Opt::Long(l) if l == "dereference" => deref = true,
            Opt::Long(l) if l == "file-system" => fs_mode = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let mut status = 0;
    for f in &files {
        if fs_mode {
            let b = match statfs(f) {
                Ok(b) => b,
                Err(e) => {
                    error_path(f, e);
                    status = 1;
                    continue;
                }
            };
            let i64_at = |i: usize| b[i];
            let magic = i64_at(0);
            let tname = fs_type_name(magic);
            let fsid = alloc::format!("{:x}{:08x}", b[7] as u64 >> 32, b[7] as u64 & 0xFFFF_FFFF);
            let out = match &format {
                Some(fmt) => {
                    let mut s = Vec::new();
                    let mut i = 0;
                    while i < fmt.len() {
                        if fmt[i] == b'%' && i + 1 < fmt.len() {
                            i += 1;
                            let v = match fmt[i] {
                                b'T' => String::from(tname),
                                b't' => alloc::format!("{magic:x}"),
                                b'b' => alloc::format!("{}", i64_at(2)),
                                b'f' => alloc::format!("{}", i64_at(3)),
                                b'a' => alloc::format!("{}", i64_at(4)),
                                b's' => alloc::format!("{}", i64_at(1)),
                                b'S' => alloc::format!("{}", i64_at(9)),
                                b'c' => alloc::format!("{}", i64_at(5)),
                                b'd' => alloc::format!("{}", i64_at(6)),
                                b'i' => fsid.clone(),
                                b'l' => alloc::format!("{}", i64_at(8)),
                                b'n' => String::from(lossy(f)),
                                b'%' => String::from("%"),
                                c => alloc::format!("?{}", c as char),
                            };
                            s.extend_from_slice(v.as_bytes());
                        } else {
                            s.push(fmt[i]);
                        }
                        i += 1;
                    }
                    s
                }
                None if terse => alloc::format!(
                    "{} {fsid} {} {magic:x} {} {} {} {} {} {} {}",
                    lossy(f), i64_at(8), i64_at(1), i64_at(9), i64_at(2), i64_at(3), i64_at(4), i64_at(5), i64_at(6)
                )
                .into_bytes(),
                None => alloc::format!(
                    "  File: \"{}\"\n    ID: {fsid} Namelen: {:<7} Type: {tname}\nBlock size: {:<10} Fundamental block size: {}\nBlocks: Total: {:<10} Free: {:<10} Available: {}\nInodes: Total: {:<10} Free: {}",
                    lossy(f), i64_at(8), i64_at(1), i64_at(9), i64_at(2), i64_at(3), i64_at(4), i64_at(5), i64_at(6)
                )
                .into_bytes(),
            };
            io::out(&out);
            io::out(b"\n");
            continue;
        }
        let st = match if deref { fs::stat(f) } else { fs::lstat(f) } {
            Ok(s) => s,
            Err(e) => {
                error(format_args!("cannot stat '{}': {e}", lossy(f)));
                status = 1;
                continue;
            }
        };
        let mode = {
            let s = crate::ls_mode(st.mode);
            String::from_utf8_lossy(&s).into_owned()
        };
        let user = crate::simple::user_name(st.uid).map_or_else(|| String::from("UNKNOWN"), |n| lossy(&n).into_owned());
        let group =
            crate::simple::group_name(st.gid).map_or_else(|| String::from("UNKNOWN"), |n| lossy(&n).into_owned());
        let time = |t: i64, ns: i64| {
            let mut s = String::new();
            let tm = slate_rt::tz::localtime(t);
            slate_rt::time::format(&tm, "%Y-%m-%d %H:%M:%S", &mut s);
            s.push_str(&alloc::format!(".{ns:09} "));
            slate_rt::time::format(&tm, "%z", &mut s);
            s
        };
        let name = if st.is_symlink() {
            alloc::format!("{} -> {}", lossy(f), lossy(&fs::readlink(f).unwrap_or_default()))
        } else {
            String::from(lossy(f))
        };
        let out: Vec<u8> = match &format {
            Some(fmt) => {
                let mut s = Vec::new();
                let mut i = 0;
                while i < fmt.len() {
                    if fmt[i] != b'%' || i + 1 >= fmt.len() {
                        s.push(fmt[i]);
                        i += 1;
                        continue;
                    }
                    i += 1;
                    let v = match fmt[i] {
                        b'n' => String::from(lossy(f)),
                        b'N' => alloc::format!("'{}'", name),
                        b's' => alloc::format!("{}", st.size),
                        b'a' => alloc::format!("{:o}", st.mode & 0o7777),
                        b'A' => mode.clone(),
                        b'f' => alloc::format!("{:x}", st.mode),
                        b'F' => String::from(file_type(&st)),
                        b'u' => alloc::format!("{}", st.uid),
                        b'U' => user.clone(),
                        b'g' => alloc::format!("{}", st.gid),
                        b'G' => group.clone(),
                        b'h' => alloc::format!("{}", st.nlink),
                        b'i' => alloc::format!("{}", st.ino),
                        b'b' => alloc::format!("{}", st.blocks),
                        b'B' => String::from("512"),
                        b'd' => alloc::format!("{}", st.dev),
                        b'X' => alloc::format!("{}", st.atime),
                        b'Y' => alloc::format!("{}", st.mtime),
                        b'Z' => alloc::format!("{}", st.ctime),
                        b'x' => time(st.atime, st.atime_nsec),
                        b'y' => time(st.mtime, st.mtime_nsec),
                        b'z' => time(st.ctime, st.ctime_nsec),
                        b't' => alloc::format!("{:x}", (st.rdev >> 8) & 0xFFF),
                        b'T' => alloc::format!("{:x}", st.rdev & 0xFF),
                        b'%' => String::from("%"),
                        c => alloc::format!("?{}", c as char),
                    };
                    s.extend_from_slice(v.as_bytes());
                    i += 1;
                }
                s.push(b'\n');
                s
            }
            None if terse => alloc::format!(
                "{} {} {} {:x} {} {} {:x} {} {} 0 0 {} {} {} 0 4096\n",
                lossy(f), st.size, st.blocks, st.mode, st.uid, st.gid, st.dev, st.ino, st.nlink, st.atime, st.mtime, st.ctime
            )
            .into_bytes(),
            None => alloc::format!(
                "  File: {name}\n  Size: {:<15} Blocks: {:<10} IO Block: {:<6} {}\nDevice: {:x}h/{}d\tInode: {:<11} Links: {}\nAccess: ({:04o}/{mode})  Uid: ({:>5}/{:>8})   Gid: ({:>5}/{:>8})\nAccess: {}\nModify: {}\nChange: {}\n Birth: -\n",
                st.size, st.blocks, st.blksize, file_type(&st), st.dev, st.dev, st.ino, st.nlink, st.mode & 0o7777,
                st.uid, user, st.gid, group, time(st.atime, st.atime_nsec), time(st.mtime, st.mtime_nsec), time(st.ctime, st.ctime_nsec)
            )
            .into_bytes(),
        };
        io::out(&out);
    }
    status
}

/// (source, mount point, type) from /proc/mounts.
fn mounts() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let data = fs::read_file(b"/proc/mounts").unwrap_or_default();
    data.split(|&c| c == b'\n')
        .filter_map(|l| {
            let f: Vec<&[u8]> = l.split(|&c| c == b' ').collect();
            Some((f.first()?.to_vec(), f.get(1)?.to_vec(), f.get(2)?.to_vec()))
        })
        .collect()
}

/// statfs(2)'s fields: type, block size, blocks, free, available, files,
/// free files, the ID, the longest name, the fundamental block size.
fn statfs(path: &[u8]) -> slate_rt::Result<[i64; 10]> {
    let s = fs::statfs(path)?;
    Ok([
        s.kind,
        s.block_size,
        s.blocks as i64,
        s.free as i64,
        s.available as i64,
        s.files as i64,
        s.free_files as i64,
        s.fsid as i64,
        s.name_max as i64,
        s.fragment_size,
    ])
}

/// A file system type's name as `stat -f` shows it, by its statfs(2)
/// magic number (the names GNU's stat was seen to print).
fn fs_type_name(magic: i64) -> &'static str {
    match magic {
        0xEF53 => "ext2/ext3",
        0x0102_1994 => "tmpfs",
        0x9FA0 => "proc",
        0x6265_6572 => "sysfs",
        0x1CD1 => "devpts",
        0x6367_7270 => "cgroup2fs",
        0x4D44 => "msdos",
        0x9123_683E => "btrfs",
        0x7363_6673 => "securityfs",
        0xCAFE_4A11 => "bpf_fs",
        0x4249_4E4D => "binfmt_misc",
        0x6462_6720 => "debugfs",
        0x6165_676C => "pstorefs",
        0x1980_0202 => "mqueue",
        0x6265_6570 => "configfs",
        0x7472_6163 => "tracefs",
        0x6573_5543 => "fusectl",
        // Slate's own (ADR 0026).
        0x534C_4154 => "slatefs",
        _ => "UNKNOWN",
    }
}

pub fn df(args: &[Vec<u8>]) -> i32 {
    let (mut hum, mut kinds, mut all, mut inodes) = (false, false, false, false);
    let (mut total, mut sync) = (false, false);
    let (mut only, mut except) = (Vec::<Vec<u8>>::new(), Vec::<Vec<u8>>::new());
    let mut output: Option<Vec<String>> = None;
    let mut paths = Vec::new();
    let mut p = Parser::new(args, b"tx");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'h' | b'H') => hum = true,
            Opt::Short(b'T') => kinds = true,
            Opt::Short(b'a') => all = true,
            Opt::Short(b'i') => inodes = true,
            Opt::Short(b'k' | b'P' | b'l') => {}
            Opt::Short(b't') => only.push(p.value().unwrap_or_default()),
            Opt::Short(b'x') => except.push(p.value().unwrap_or_default()),
            Opt::Long(l) if l == "human-readable" => hum = true,
            Opt::Long(l) if l == "inodes" => inodes = true,
            Opt::Long(l) if l == "all" => all = true,
            Opt::Long(l) if l == "print-type" => kinds = true,
            Opt::Long(l) if l == "type" => only.push(p.value().unwrap_or_default()),
            Opt::Long(l) if l == "exclude-type" => except.push(p.value().unwrap_or_default()),
            Opt::Long(l) if l == "total" => total = true,
            Opt::Long(l) if l == "sync" => sync = true,
            Opt::Long(l) if l == "no-sync" => sync = false,
            Opt::Long(l) if l == "output" => {
                let v = p.inline_value().unwrap_or_else(|| {
                    b"source,fstype,itotal,iused,iavail,ipcent,size,used,avail,pcent,file,target".to_vec()
                });
                let fields: Vec<String> = lossy(&v).split(',').map(String::from).collect();
                const KNOWN: [&str; 12] = [
                    "source", "fstype", "itotal", "iused", "iavail", "ipcent", "size", "used", "avail", "pcent",
                    "file", "target",
                ];
                if let Some(bad) = fields.iter().find(|f| !KNOWN.contains(&f.as_str())) {
                    error(format_args!("'{bad}': not a valid field for --output"));
                    return 1;
                }
                output = Some(fields);
            }
            Opt::Operand(x) => paths.push(x),
            o => return bad_option(&o),
        }
    }
    // --sync: written data first, so the figures are current.
    if sync {
        fs::sync();
    }
    let ms = mounts();
    let mut status = 0;
    let wanted = |t: &[u8]| (only.is_empty() || only.iter().any(|o| o == t)) && !except.iter().any(|x| x == t);
    // Each mount to show, with the operand that named it.
    type Mount = (Vec<u8>, Vec<u8>, Vec<u8>);
    let chosen: Vec<(&Mount, Vec<u8>)> = if paths.is_empty() {
        ms.iter()
            .filter(|m| all || !matches!(m.2.as_slice(), b"proc" | b"devpts" | b"sysfs"))
            .filter(|m| wanted(&m.2))
            .map(|m| (m, b"-".to_vec()))
            .collect()
    } else {
        let mut v = Vec::new();
        for p in &paths {
            let canon = match crate::fileops::canonicalize(p, true, false) {
                Ok(c) => c,
                Err(e) => {
                    error(format_args!("{}: {e}", lossy(p)));
                    status = 1;
                    continue;
                }
            };
            let m = ms
                .iter()
                .filter(|m| {
                    canon.starts_with(&m.1) && (canon.len() == m.1.len() || m.1 == b"/" || canon[m.1.len()] == b'/')
                })
                .max_by_key(|m| m.1.len());
            if let Some(m) = m
                && wanted(&m.2)
            {
                v.push((m, p.clone()));
            }
        }
        v
    };
    // The columns: GNU's defaults for the mode, or --output's.
    let fields: Vec<String> = output.clone().unwrap_or_else(|| {
        let names: &[&str] = match (inodes, kinds) {
            (true, true) => &["source", "fstype", "itotal", "iused", "iavail", "ipcent", "target"],
            (true, false) => &["source", "itotal", "iused", "iavail", "ipcent", "target"],
            (false, true) => &["source", "fstype", "size", "used", "avail", "pcent", "target"],
            (false, false) => &["source", "size", "used", "avail", "pcent", "target"],
        };
        names.iter().map(|s| String::from(*s)).collect()
    });
    let header = |f: &str| -> String {
        String::from(match f {
            "source" => "Filesystem",
            "fstype" => "Type",
            "itotal" => "Inodes",
            "iused" => "IUsed",
            "iavail" => "IFree",
            "ipcent" => "IUse%",
            "size" if hum => "Size",
            "size" => "1K-blocks",
            "used" => "Used",
            "avail" if hum => "Avail",
            "avail" => "Available",
            "pcent" => "Use%",
            "file" => "File",
            _ => "Mounted on",
        })
    };
    let mut rows: Vec<Vec<String>> = alloc::vec![fields.iter().map(|f| header(f)).collect()];
    let pct = |used: u64, avail: u64| {
        if used + avail == 0 { String::from("-") } else { alloc::format!("{}%", (used * 100).div_ceil(used + avail)) }
    };
    let size = |v: u64| if hum { human(v) } else { alloc::format!("{}", v / 1024) };
    let count = |v: u64| if hum { human(v) } else { alloc::format!("{v}") };
    // One row: (bytes: size, free, available), (inodes: total, free), and
    // the source, type, file and mount point.
    let row = |(size_b, free, avail): (u64, u64, u64), (itotal, ifree): (u64, u64), names: [&str; 4]| -> Vec<String> {
        let used = size_b - free;
        let iused = itotal.saturating_sub(ifree);
        fields
            .iter()
            .map(|f| match f.as_str() {
                "source" => String::from(names[0]),
                "fstype" => String::from(names[1]),
                "itotal" => count(itotal),
                "iused" => count(iused),
                "iavail" => count(ifree),
                "ipcent" => pct(iused, ifree),
                "size" => size(size_b),
                "used" => size(used),
                "avail" => size(avail),
                "pcent" => pct(used, avail),
                "file" => String::from(names[2]),
                _ => String::from(names[3]),
            })
            .collect()
    };
    let mut sums = ((0u64, 0u64, 0u64), (0u64, 0u64));
    for (m, file) in chosen {
        let Ok(s) = statfs(&m.1) else { continue };
        let bs = s[1] as u64;
        let bytes = (s[2] as u64 * bs, s[3] as u64 * bs, s[4] as u64 * bs);
        let inodes = (s[5] as u64, s[6] as u64);
        sums =
            ((sums.0.0 + bytes.0, sums.0.1 + bytes.1, sums.0.2 + bytes.2), (sums.1.0 + inodes.0, sums.1.1 + inodes.1));
        let names = [lossy(&m.0), lossy(&m.2), lossy(&file), lossy(&m.1)];
        rows.push(row(bytes, inodes, [&names[0], &names[1], &names[2], &names[3]]));
    }
    // --total: a last row of the sums.
    if total && rows.len() > 1 {
        rows.push(row(sums.0, sums.1, ["total", "-", "-", "-"]));
    }
    if rows.len() == 1 {
        // Nothing to show: no header either.
        if status == 0 {
            error("no file systems processed");
        }
        return 1;
    }
    let n = fields.len();
    let w: Vec<usize> = (0..n).map(|i| rows.iter().map(|r| r[i].len()).max().unwrap_or(0)).collect();
    let left = |f: &str| matches!(f, "source" | "fstype" | "file" | "target");
    for r in &rows {
        let mut line = String::new();
        for (i, f) in fields.iter().enumerate() {
            if i > 0 {
                line.push(' ');
            }
            if i + 1 == n && left(f) {
                line.push_str(&r[i]);
            } else if left(f) {
                line.push_str(&alloc::format!("{:<wi$}", r[i], wi = w[i]));
            } else {
                line.push_str(&alloc::format!("{:>wi$}", r[i], wi = w[i]));
            }
        }
        println!("{line}");
    }
    status
}

pub fn du(args: &[Vec<u8>]) -> i32 {
    let (mut summary, mut hum, mut all, mut total_line, mut apparent) = (false, false, false, false, false);
    let (mut inodes, mut one_fs, mut count_links, mut deref, mut zero, mut times) =
        (false, false, false, false, false, false);
    // -H: the operands' symbolic links followed (not those found below).
    let mut deref_args = false;
    // --time=WORD: which time (m, a or c); --time-style: how it is shown.
    let mut which_time = b'm';
    let mut time_style = String::from("%Y-%m-%d %H:%M");
    let mut excludes: Vec<Vec<u8>> = Vec::new();
    let mut max_depth: Option<usize> = None;
    let mut paths = Vec::new();
    let mut p = Parser::new(args, b"dX");
    let read_patterns = |f: &[u8], out: &mut Vec<Vec<u8>>| -> bool {
        match crate::util::read_input(f) {
            Ok(d) => {
                out.extend(crate::util::lines(&d, b'\n').into_iter().filter(|l| !l.is_empty()).map(<[u8]>::to_vec));
                true
            }
            Err(e) => {
                error_path(f, e);
                false
            }
        }
    };
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b's') => summary = true,
            Opt::Short(b'h') => hum = true,
            Opt::Short(b'a') => all = true,
            Opt::Short(b'c') => total_line = true,
            Opt::Short(b'k') => {}
            Opt::Short(b'x') => one_fs = true,
            Opt::Short(b'l') => count_links = true,
            Opt::Short(b'L') => deref = true,
            Opt::Short(b'P') => (deref, deref_args) = (false, false),
            Opt::Short(b'H' | b'D') => deref_args = true,
            Opt::Long(l) if l == "dereference-args" => deref_args = true,
            Opt::Short(b'0') => zero = true,
            Opt::Short(b'b') => apparent = true,
            Opt::Short(b'd') => max_depth = p.value().and_then(|v| parse_num(&v)),
            Opt::Short(b'X') => {
                if !read_patterns(&p.value().unwrap_or_default(), &mut excludes) {
                    return 1;
                }
            }
            Opt::Long(l) if l == "summarize" => summary = true,
            Opt::Long(l) if l == "human-readable" => hum = true,
            Opt::Long(l) if l == "apparent-size" => apparent = true,
            Opt::Long(l) if l == "inodes" => inodes = true,
            Opt::Long(l) if l == "one-file-system" => one_fs = true,
            Opt::Long(l) if l == "count-links" => count_links = true,
            Opt::Long(l) if l == "dereference" => deref = true,
            Opt::Long(l) if l == "null" => zero = true,
            Opt::Long(l) if l == "time" => {
                times = true;
                if let Some(w) = p.inline_value() {
                    which_time = match w.as_slice() {
                        b"atime" | b"access" | b"use" => b'a',
                        b"ctime" | b"status" => b'c',
                        _ => {
                            error(format_args!("invalid argument '{}' for '--time'", lossy(&w)));
                            slate_rt::eprintln!(
                                "Valid arguments are:\n  - 'atime', 'access', 'use'\n  - 'ctime', 'status'"
                            );
                            slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                            return 1;
                        }
                    };
                }
            }
            Opt::Long(l) if l == "time-style" => {
                let v = p.value().unwrap_or_default();
                time_style = match v.as_slice() {
                    b"full-iso" => String::from("%Y-%m-%d %H:%M:%S.%N %z"),
                    b"long-iso" => String::from("%Y-%m-%d %H:%M"),
                    b"iso" => String::from("%Y-%m-%d"),
                    f if f.starts_with(b"+") => String::from(lossy(&f[1..])),
                    _ => {
                        error(format_args!("invalid argument '{}' for 'time style'", lossy(&v)));
                        slate_rt::eprintln!(
                            "Valid arguments are:\n  - full-iso\n  - long-iso\n  - iso\n  - +FORMAT (e.g., +%H:%M) for a 'date'-style format"
                        );
                        slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                        return 1;
                    }
                };
            }
            Opt::Long(l) if l == "total" => total_line = true,
            Opt::Long(l) if l == "all" => all = true,
            Opt::Long(l) if l == "exclude" => excludes.push(p.value().unwrap_or_default()),
            Opt::Long(l) if l == "exclude-from" => {
                if !read_patterns(&p.value().unwrap_or_default(), &mut excludes) {
                    return 1;
                }
            }
            Opt::Long(l) if l == "max-depth" => max_depth = p.value().and_then(|v| parse_num(&v)),
            Opt::Operand(x) => paths.push(x),
            o => return bad_option(&o),
        }
    }
    if summary {
        max_depth = Some(0);
    }
    if paths.is_empty() {
        paths.push(b".".to_vec());
    }
    struct Walk<'a> {
        apparent: bool,
        inodes: bool,
        hum: bool,
        all: bool,
        max: Option<usize>,
        one_fs: bool,
        count_links: bool,
        deref: bool,
        zero: bool,
        times: bool,
        deref_args: bool,
        which_time: u8,
        time_style: String,
        excludes: &'a [Vec<u8>],
        seen: Vec<(u64, u64)>,
        root_dev: u64,
    }
    impl Walk<'_> {
        fn excluded(&self, path: &[u8]) -> bool {
            use slate_regex::fnmatch::{Flags, fnmatch_with};
            let base = fs::basename(path);
            self.excludes
                .iter()
                .any(|p| fnmatch_with(p, base, Flags::default()) || fnmatch_with(p, path, Flags::default()))
        }

        fn show(&self, n: u64, (t, ns): (i64, i64), path: &[u8]) {
            let v = if self.inodes {
                if self.hum { human(n) } else { alloc::format!("{n}") }
            } else if self.hum {
                human(n)
            } else {
                alloc::format!("{}", n.div_ceil(1024))
            };
            let mut line = v;
            line.push('\t');
            if self.times {
                let tm = slate_rt::tz::localtime(t);
                line.push_str(&crate::datetime::format(&tm, ns as u32, &self.time_style));
                line.push('\t');
            }
            let mut out = line.into_bytes();
            out.extend_from_slice(path);
            out.push(if self.zero { 0 } else { b'\n' });
            io::out(&out);
        }

        /// Size (or inode count) and newest time (seconds, nanoseconds)
        /// under `path`.
        fn walk(&mut self, path: &[u8], depth: usize) -> (u64, (i64, i64)) {
            if depth > 0 && self.excluded(path) {
                return (0, (0, 0));
            }
            let follow = self.deref || (depth == 0 && self.deref_args);
            let st = if follow { fs::stat(path) } else { fs::lstat(path) };
            let Ok(st) = st else {
                error(format_args!("cannot access '{}'", lossy(path)));
                return (0, (0, 0));
            };
            if depth == 0 {
                self.root_dev = st.dev;
            }
            if self.one_fs && st.dev != self.root_dev {
                return (0, (0, 0));
            }
            // Hard links once (unless -l); directories once when links are
            // followed (a loop would never end).
            if (!self.count_links && st.nlink > 1 && !st.is_dir()) || (self.deref && st.is_dir()) {
                if self.seen.contains(&(st.dev, st.ino)) {
                    return (0, (0, 0));
                }
                self.seen.push((st.dev, st.ino));
            }
            let mut total = if self.inodes {
                1
            } else if self.apparent {
                st.size as u64
            } else {
                st.blocks as u64 * 512
            };
            let mut newest = match self.which_time {
                b'a' => (st.atime, st.atime_nsec),
                b'c' => (st.ctime, st.ctime_nsec),
                _ => (st.mtime, st.mtime_nsec),
            };
            if st.is_dir() {
                for e in fs::read_dir(path).unwrap_or_default() {
                    let (n, t) = self.walk(&fs::join(path, &e.name), depth + 1);
                    total += n;
                    newest = newest.max(t);
                }
                if self.max.is_none_or(|m| depth <= m) {
                    self.show(total, newest, path);
                }
            } else if (self.all || depth == 0) && self.max.is_none_or(|m| depth <= m) {
                self.show(total, newest, path);
            }
            (total, newest)
        }
    }
    let mut w = Walk {
        apparent,
        inodes,
        hum,
        all,
        max: max_depth,
        one_fs,
        count_links,
        deref,
        zero,
        times,
        deref_args,
        which_time,
        time_style,
        excludes: &excludes,
        seen: Vec::new(),
        root_dev: 0,
    };
    let (mut grand, mut newest) = (0, (0, 0));
    for p in &paths {
        let (n, t) = w.walk(p, 0);
        grand += n;
        newest = newest.max(t);
    }
    if total_line {
        w.show(grand, newest, b"total");
    }
    io::flush_stdout();
    0
}

/// dmesg: print the kernel log (syslog(2) READ_ALL); `-c` clears it
/// after printing, `-C` only clears it.
pub fn dmesg(args: &[Vec<u8>]) -> i32 {
    use process::KernelLog;
    let mut action = KernelLog::ReadAll;
    for a in args.iter().skip(1) {
        match a.as_slice() {
            b"-c" | b"--read-clear" => action = KernelLog::ReadClear,
            b"-C" | b"--clear" => action = KernelLog::Clear,
            _ => {
                error(format_args!("unrecognized argument '{}'", lossy(a)));
                return 1;
            }
        }
    }
    if action == KernelLog::Clear {
        return match process::kernel_log(KernelLog::Clear, &mut []) {
            Ok(_) => 0,
            Err(e) => {
                error(format_args!("clearing the kernel log: {}", e));
                1
            }
        };
    }
    let size = process::kernel_log(KernelLog::Size, &mut []).unwrap_or(1 << 18);
    let mut buf = alloc::vec![0u8; size];
    match process::kernel_log(action, &mut buf) {
        Ok(n) => {
            io::out(&buf[..n]);
            0
        }
        Err(e) => {
            error(format_args!("reading the kernel log: {}", e));
            1
        }
    }
}

pub fn mount(args: &[Vec<u8>]) -> i32 {
    let mut fstype: Option<Vec<u8>> = None;
    let mut opts: Vec<u8> = Vec::new();
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"to");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b't') => fstype = p.value(),
            Opt::Short(b'o') => opts = p.value().unwrap_or_default(),
            Opt::Short(b'r') => opts = b"ro".to_vec(),
            Opt::Short(b'w' | b'v' | b'n') => {}
            Opt::Operand(x) => ops.push(x),
            o => return bad_option(&o),
        }
    }
    if ops.is_empty() {
        // /proc/mounts' lines: source, mount point, type, options.
        let data = fs::read_file(b"/proc/mounts").unwrap_or_default();
        for l in data.split(|&c| c == b'\n') {
            let f: Vec<&[u8]> = l.split(|&c| c == b' ').collect();
            if let [src, at, kind, opts, ..] = f[..] {
                println!("{} on {} type {} ({})", lossy(src), lossy(at), lossy(kind), lossy(opts));
            }
        }
        return 0;
    }
    // A remount names only the mount point.
    let remount = opts.split(|&c| c == b',').any(|o| o == b"remount");
    if remount && ops.len() == 1 {
        ops.insert(0, b"none".to_vec());
    }
    if ops.len() != 2 {
        error("usage: mount [-t TYPE] [-o OPTIONS] SOURCE TARGET");
        return 1;
    }
    let mut flags = 0;
    // Options that are not flags go to the file system as its data
    // (mount(2)), such as SlateFS's `subvol=NAME`.
    let mut data: Vec<u8> = Vec::new();
    for o in opts.split(|&c| c == b',').filter(|o| !o.is_empty()) {
        match o {
            b"ro" => flags |= fs::MS_RDONLY,
            b"rw" => {}
            b"nosuid" => flags |= fs::MS_NOSUID,
            b"nodev" => flags |= fs::MS_NODEV,
            b"noexec" => flags |= fs::MS_NOEXEC,
            b"remount" => flags |= fs::MS_REMOUNT,
            b"bind" => flags |= fs::MS_BIND,
            b"rbind" => flags |= fs::MS_BIND | fs::MS_REC,
            // Access times (ADR 0162).
            b"noatime" => flags |= fs::MS_NOATIME,
            b"nodiratime" => flags |= fs::MS_NODIRATIME,
            b"relatime" => flags |= fs::MS_RELATIME,
            b"strictatime" => flags |= fs::MS_STRICTATIME,
            // mount(8)'s flag words that ask for the default, and the
            // lazytime and sync words, which Slate's file systems have no
            // modes for (docs/GAPS.md): never file-system data.
            b"defaults" | b"suid" | b"dev" | b"exec" | b"async" | b"atime" | b"diratime" | b"norelatime"
            | b"lazytime" | b"nolazytime" | b"sync" | b"dirsync" => {}
            _ => {
                if !data.is_empty() {
                    data.push(b',');
                }
                data.extend_from_slice(o);
            }
        }
    }
    let kind = fstype.unwrap_or_else(|| b"ext4".to_vec());
    match fs::mount(&ops[0], &ops[1], &kind, flags, &data) {
        Ok(_) => 0,
        Err(e) => {
            error(format_args!("mounting {} on {} failed: {e}", lossy(&ops[0]), lossy(&ops[1])));
            32
        }
    }
}

pub fn umount(args: &[Vec<u8>]) -> i32 {
    let mut status = 0;
    for a in args[1..].iter().filter(|a| !a.starts_with(b"-")) {
        if let Err(e) = fs::umount(a) {
            error(format_args!("{}: {e}", lossy(a)));
            status = 32;
        }
    }
    status
}

fn meminfo() -> Vec<(Vec<u8>, u64)> {
    let d = fs::read_file(b"/proc/meminfo").unwrap_or_default();
    d.split(|&c| c == b'\n')
        .filter_map(|l| {
            let colon = l.iter().position(|&c| c == b':')?;
            let v = l[colon + 1..].split(|&c| c == b' ').find(|x| !x.is_empty())?;
            Some((l[..colon].to_vec(), parse_num(v)?))
        })
        .collect()
}

pub fn free(args: &[Vec<u8>]) -> i32 {
    let hum = args.iter().any(|a| a == b"-h" || a == b"--human");
    let mega = args.iter().any(|a| a == b"-m");
    let m = meminfo();
    let get = |k: &[u8]| m.iter().find(|e| e.0 == k).map_or(0, |e| e.1);
    let (total, free, avail, buffers, cached) =
        (get(b"MemTotal"), get(b"MemFree"), get(b"MemAvailable"), get(b"Buffers"), get(b"Cached"));
    let used = total - free - buffers - cached;
    let f = |kb: u64| {
        if hum {
            human(kb * 1024)
        } else if mega {
            alloc::format!("{}", kb / 1024)
        } else {
            alloc::format!("{kb}")
        }
    };
    println!("{:>15} {:>11} {:>11} {:>11} {:>11} {:>11}", "total", "used", "free", "shared", "buff/cache", "available");
    println!(
        "Mem:    {:>11} {:>11} {:>11} {:>11} {:>11} {:>11}",
        f(total),
        f(used),
        f(free),
        f(0),
        f(buffers + cached),
        f(avail)
    );
    println!("Swap:   {:>11} {:>11} {:>11}", f(0), f(0), f(0));
    0
}

pub fn uptime(_: &[Vec<u8>]) -> i32 {
    let up = fs::read_file(b"/proc/uptime")
        .ok()
        .and_then(|d| lossy(&d).split('.').next().and_then(|s| s.trim().parse::<u64>().ok()))
        .unwrap_or(0);
    let tm = slate_rt::tz::localtime(slate_rt::time::unix());
    let users = slate_rt::utmp::current().len();
    let (d, h, m) = (up / 86400, up / 3600 % 24, up / 60 % 60);
    let span = if d > 0 {
        alloc::format!("{d} day{}, {h:2}:{m:02}", if d == 1 { "" } else { "s" })
    } else if h > 0 {
        alloc::format!("{h:2}:{m:02}")
    } else {
        alloc::format!("{m} min")
    };
    let la = crate::procs::loadavg();
    println!(
        " {:02}:{:02}:{:02} up {span},  {users} user{},  load average: {}, {}, {}",
        tm.hour,
        tm.min,
        tm.sec,
        if users == 1 { "" } else { "s" },
        la[0],
        la[1],
        la[2]
    );
    0
}

pub fn kill(args: &[Vec<u8>]) -> i32 {
    let mut sig = signal::SIGTERM;
    let mut i = 1;
    if let Some(a) = args.get(1) {
        if a == b"-l" || a == b"-L" {
            if let Some(n) = args.get(2).and_then(|n| parse_num::<i32>(n)) {
                let n = if n > 128 { n - 128 } else { n };
                println!("{}", signal::NAMES.get(n as usize).copied().unwrap_or("?"));
            } else {
                let names: Vec<&str> = signal::NAMES[1..].to_vec();
                println!("{}", names.join(" "));
            }
            return 0;
        }
        if a == b"-s" || a == b"-n" {
            let Some(name) = args.get(2).and_then(|n| signal::by_name(&lossy(n))) else {
                error("invalid signal");
                return 1;
            };
            sig = name;
            i = 3;
        } else if let Some(s) = a.strip_prefix(b"-")
            && s.first().is_some_and(|c| c.is_ascii_alphanumeric())
        {
            match signal::by_name(&lossy(s)) {
                Some(n) => sig = n,
                None => {
                    error(format_args!("invalid signal specification '{}'", lossy(s)));
                    return 1;
                }
            }
            i = 2;
        }
    }
    if args.get(i).map(Vec::as_slice) == Some(b"--") {
        i += 1;
    }
    if i >= args.len() {
        error("usage: kill [-s SIGNAL | -SIGNAL] PID...");
        return 1;
    }
    let mut status = 0;
    for a in &args[i..] {
        let Some(pid) = parse_num::<i32>(a) else {
            error(format_args!("'{}': arguments must be process or job IDs", lossy(a)));
            status = 1;
            continue;
        };
        if let Err(e) = process::kill(pid, sig) {
            error(format_args!("({pid}) - {e}"));
            status = 1;
        }
    }
    status
}

pub fn which(args: &[Vec<u8>]) -> i32 {
    let all = args.iter().any(|a| a == b"-a");
    let mut status = 0;
    let path = slate_rt::env::var(b"PATH").unwrap_or_default();
    for name in args[1..].iter().filter(|a| !a.starts_with(b"-")) {
        let mut found = false;
        if name.contains(&b'/') {
            if fs::access(name, 1).is_ok() {
                io::out(name);
                io::out(b"\n");
                found = true;
            }
        } else {
            for dir in path.split(|&c| c == b':') {
                let c = fs::join(if dir.is_empty() { b"." } else { dir }, name);
                if fs::stat(&c).is_ok_and(|s| s.is_file()) && fs::access(&c, 1).is_ok() {
                    io::out(&c);
                    io::out(b"\n");
                    found = true;
                    if !all {
                        break;
                    }
                }
            }
        }
        if !found {
            status = 1;
        }
    }
    status
}

pub fn cmp(args: &[Vec<u8>]) -> i32 {
    let (mut silent, mut list) = (false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b's') => silent = true,
            Opt::Short(b'l') => list = true,
            Opt::Long(l) if l == "silent" || l == "quiet" => silent = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.len() == 1 {
        files.push(b"-".to_vec());
    }
    if files.len() < 2 {
        error("missing operand");
        return 2;
    }
    let (a, b) = match (read_input(&files[0]), read_input(&files[1])) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            if !silent {
                error(e);
            }
            return 2;
        }
    };
    let mut diff = false;
    let mut line = 1;
    for i in 0..a.len().min(b.len()) {
        if a[i] != b[i] {
            diff = true;
            if silent {
                return 1;
            }
            if list {
                println!("{} {:o} {:o}", i + 1, a[i], b[i]);
                continue;
            }
            println!("{} {} differ: char {}, line {line}", lossy(&files[0]), lossy(&files[1]), i + 1);
            return 1;
        }
        if a[i] == b'\n' {
            line += 1;
        }
    }
    if a.len() != b.len() {
        if !silent {
            let shorter = if a.len() < b.len() { &files[0] } else { &files[1] };
            error(format_args!("EOF on {} after byte {}", lossy(shorter), a.len().min(b.len())));
        }
        return 1;
    }
    i32::from(diff)
}

pub fn xargs(args: &[Vec<u8>]) -> i32 {
    let (mut zero, mut no_empty, mut verbose) = (false, false, false);
    let mut max_args: Option<usize> = None;
    let mut replace: Option<Vec<u8>> = None;
    let mut delim: Option<u8> = None;
    let mut i = 1;
    while i < args.len() && args[i].starts_with(b"-") {
        let a = args[i].clone();
        match a.as_slice() {
            b"-0" | b"--null" => zero = true,
            b"-r" | b"--no-run-if-empty" => no_empty = true,
            b"-t" | b"--verbose" => verbose = true,
            b"-n" | b"-L" => {
                i += 1;
                max_args = args.get(i).and_then(|v| parse_num(v));
            }
            b"-I" => {
                i += 1;
                replace = args.get(i).cloned();
                max_args = Some(1);
            }
            b"-d" => {
                i += 1;
                delim = args.get(i).map(|d| crate::util::unescape(d, true).0).and_then(|d| d.first().copied());
            }
            b"-i" => (replace, max_args) = (Some(b"{}".to_vec()), Some(1)),
            b"--" => {
                i += 1;
                break;
            }
            x if x.starts_with(b"-n") => max_args = parse_num(&x[2..]),
            x if x.starts_with(b"-I") => (replace, max_args) = (Some(x[2..].to_vec()), Some(1)),
            _ => return bad_option(&Opt::Short(a[1])),
        }
        i += 1;
    }
    let cmd: Vec<Vec<u8>> = if i < args.len() { args[i..].to_vec() } else { alloc::vec![b"echo".to_vec()] };
    let input = read_input(b"-").unwrap_or_default();
    let items: Vec<Vec<u8>> = if zero {
        input.split(|&c| c == 0).filter(|x| !x.is_empty()).map(<[u8]>::to_vec).collect()
    } else if let Some(d) = delim {
        input.split(|&c| c == d).filter(|x| !x.is_empty()).map(<[u8]>::to_vec).collect()
    } else if replace.is_some() {
        crate::util::lines(&input, b'\n').iter().map(|l| l.to_vec()).filter(|l| !l.is_empty()).collect()
    } else {
        split_words(&input)
    };
    if items.is_empty() && no_empty {
        return 0;
    }
    let Some(path) = process::find_in_path(&cmd[0]) else {
        error(format_args!("{}: No such file or directory", lossy(&cmd[0])));
        return 127;
    };
    let chunk = max_args.unwrap_or(5000).max(1);
    let mut status = 0;
    let groups: Vec<&[Vec<u8>]> =
        if items.is_empty() { alloc::vec![&items[..]] } else { items.chunks(chunk).collect() };
    for group in groups {
        let argv: Vec<Vec<u8>> = match &replace {
            Some(r) => cmd.iter().map(|a| replace_all(a, r, &group[0])).collect(),
            None => cmd.iter().cloned().chain(group.iter().cloned()).collect(),
        };
        if verbose {
            let words: Vec<String> = argv.iter().map(|a| lossy(a).into_owned()).collect();
            slate_rt::eprintln!("{}", words.join(" "));
        }
        match process::run(&path, &argv) {
            Ok(s) => {
                let code = process::exit_code(s);
                if code == 255 {
                    return 124;
                }
                if process::signaled(s).is_some() {
                    return 125;
                }
                if code != 0 {
                    status = 123;
                }
            }
            Err(e) => {
                error(e);
                return 126;
            }
        }
    }
    status
}

fn replace_all(s: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(from) {
            out.extend_from_slice(to);
            i += from.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

/// xargs's default splitting: blanks and newlines, with quotes and
/// backslashes.
fn split_words(input: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut in_word = false;
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < input.len() {
        let c = input[i];
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None => match c {
                b'\'' | b'"' => {
                    quote = Some(c);
                    in_word = true;
                }
                b'\\' if i + 1 < input.len() => {
                    i += 1;
                    cur.push(input[i]);
                    in_word = true;
                }
                b' ' | b'\t' | b'\n' => {
                    if in_word {
                        out.push(core::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                _ => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
        i += 1;
    }
    if in_word {
        out.push(cur);
    }
    out
}

pub fn nohup(args: &[Vec<u8>]) -> i32 {
    if args.len() < 2 {
        error("missing operand");
        return 125;
    }
    let _ = signal::set(signal::SIGHUP, signal::Disposition::Ignore);
    if slate_rt::term::isatty(io::STDOUT)
        && let Ok(fd) = fs::open(b"nohup.out", fs::O_WRONLY | fs::O_CREAT | fs::O_APPEND, 0o600)
    {
        let _ = process::dup2(fd, io::STDOUT);
        slate_rt::eprintln!("nohup: ignoring input and appending output to 'nohup.out'");
    }
    let Some(path) = process::find_in_path(&args[1]) else {
        error_path(&args[1], Errno::ENOENT);
        return 127;
    };
    let e = process::execve(&path, &args[1..], slate_rt::env::vars());
    error_path(&args[1], e);
    126
}

/// setsid [-f] [-w] PROGRAM [ARG]...: run PROGRAM in a new session
/// (util-linux setsid(1)): forked first when this process leads its
/// process group (or with -f); -w waits for it and returns its status.
pub fn setsid(args: &[Vec<u8>]) -> i32 {
    let (mut fork, mut wait) = (false, false);
    let mut i = 1;
    while let Some(a) = args.get(i).filter(|a| a.len() > 1 && a[0] == b'-') {
        match a.as_slice() {
            b"-f" | b"--fork" => fork = true,
            b"-w" | b"--wait" => wait = true,
            b"--" => {
                i += 1;
                break;
            }
            _ => {
                error(alloc::format!("invalid option -- '{}'", lossy(&a[1..])));
                return 1;
            }
        }
        i += 1;
    }
    if i >= args.len() {
        error("no command specified");
        slate_rt::eprintln!("Try 'setsid --help' for more information.");
        return 1;
    }
    if fork || process::getpgrp() == process::getpid() {
        match process::fork() {
            Ok(0) => {}
            Ok(pid) => {
                if !wait {
                    return 0;
                }
                return match process::wait(pid, 0) {
                    Ok((_, st)) => process::exit_code(st),
                    Err(_) => 1,
                };
            }
            Err(e) => {
                error(alloc::format!("fork failed: {e}"));
                return 1;
            }
        }
    }
    if let Err(e) = process::setsid() {
        error(alloc::format!("setsid failed: {e}"));
        return 1;
    }
    let Some(path) = process::find_in_path(&args[i]) else {
        error_path(&args[i], Errno::ENOENT);
        return 127;
    };
    let e = process::execve(&path, &args[i..], slate_rt::env::vars());
    error_path(&args[i], e);
    126
}

/// chroot NEWROOT [COMMAND [ARG]...]: run COMMAND (default `$SHELL -i`)
/// with NEWROOT as its root directory (chroot(1) as GNU coreutils
/// behaves: the working directory becomes the new root; exit status 125
/// if the chroot fails, 126 if COMMAND cannot run, 127 if it is missing).
pub fn chroot(args: &[Vec<u8>]) -> i32 {
    let mut i = 1;
    if args.get(i).is_some_and(|a| a.as_slice() == b"--") {
        i += 1;
    }
    let Some(root) = args.get(i) else {
        error("missing operand");
        return 125;
    };
    if let Err(e) = fs::chroot(root).and_then(|()| fs::chdir(b"/")) {
        slate_rt::eprintln!("chroot: cannot change root directory to '{}': {}", lossy(root), e.message());
        return 125;
    }
    let cmd: Vec<Vec<u8>> = if args.len() > i + 1 {
        args[i + 1..].to_vec()
    } else {
        let shell = slate_rt::env::var(b"SHELL").unwrap_or_else(|| b"/bin/sh".to_vec());
        alloc::vec![shell, b"-i".to_vec()]
    };
    let Some(path) = process::find_in_path(&cmd[0]) else {
        slate_rt::eprintln!("chroot: failed to run command '{}': {}", lossy(&cmd[0]), Errno::ENOENT.message());
        return 127;
    };
    let e = process::execve(&path, &cmd, slate_rt::env::vars());
    slate_rt::eprintln!("chroot: failed to run command '{}': {}", lossy(&cmd[0]), e.message());
    if e == Errno::ENOENT { 127 } else { 126 }
}

pub fn timeout(args: &[Vec<u8>]) -> i32 {
    let mut sig = signal::SIGTERM;
    let mut i = 1;
    while i < args.len() && args[i].starts_with(b"-") {
        match args[i].as_slice() {
            b"-s" | b"--signal" => {
                i += 1;
                sig = args.get(i).and_then(|s| signal::by_name(&lossy(s))).unwrap_or(signal::SIGTERM);
            }
            b"--preserve-status" | b"--foreground" => {}
            _ => return bad_option(&Opt::Short(args[i][1])),
        }
        i += 1;
    }
    let (Some(d), Some(cmd)) = (args.get(i).and_then(|d| crate::simple::parse_duration(d)), args.get(i + 1)) else {
        error("missing operand");
        return 125;
    };
    let Some(path) = process::find_in_path(cmd) else {
        error_path(cmd, Errno::ENOENT);
        return 127;
    };
    let pid = match process::fork() {
        Ok(0) => {
            let e = process::execve(&path, &args[i + 1..], slate_rt::env::vars());
            error_path(cmd, e);
            process::exit_now(126);
        }
        Ok(p) => p,
        Err(e) => {
            error(e);
            return 125;
        }
    };
    let start = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    let start_ns = start.0 as u64 * 1_000_000_000 + start.1 as u64;
    loop {
        if let Ok((p, status)) = process::wait(pid, process::WNOHANG)
            && p == pid
        {
            return process::exit_code(status);
        }
        let n = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
        if n.0 as u64 * 1_000_000_000 + n.1 as u64 - start_ns >= d {
            let _ = process::kill(pid, sig);
            let _ = process::wait(pid, 0);
            return 124;
        }
        slate_rt::time::sleep_ns(10_000_000);
    }
}

/// expr(1): `|`, `&`, comparisons, `+ - * / %`, `length`, `substr`,
/// `index`, and `:` with literal-prefix patterns (full regular expressions
/// come with grep's engine).
/// `STRING : REGEX`: an anchored BRE match; the first subexpression's
/// text if the pattern has one, else the length of the match.
fn expr_match(s: &[u8], pat: &[u8]) -> Vec<u8> {
    let re = match slate_regex::Regex::new(pat, slate_regex::Options::basic()) {
        Ok(r) => r,
        Err(e) => {
            error(e);
            slate_rt::process::exit(2);
        }
    };
    let m = re.match_at(s, 0);
    if re.groups() > 0 {
        return m.and_then(|c| c[1]).map_or(Vec::new(), |(a, b)| s[a..b].to_vec());
    }
    let n = m.and_then(|c| c[0]).map_or(0, |(a, b)| s[a..b].iter().filter(|&&c| c & 0xC0 != 0x80).count());
    alloc::format!("{n}").into_bytes()
}

pub fn expr(args: &[Vec<u8>]) -> i32 {
    let toks: Vec<Vec<u8>> = args[1..].to_vec();
    let mut e = Expr { t: &toks, i: 0 };
    let v = match e.or() {
        Some(v) if e.i == toks.len() => v,
        _ => {
            error("syntax error");
            return 2;
        }
    };
    io::out(&v);
    io::out(b"\n");
    i32::from(v.is_empty() || v == b"0")
}

struct Expr<'a> {
    t: &'a [Vec<u8>],
    i: usize,
}

fn as_int(v: &[u8]) -> Option<i64> {
    core::str::from_utf8(v).ok()?.parse().ok()
}

fn null(v: &[u8]) -> bool {
    v.is_empty() || as_int(v) == Some(0)
}

impl Expr<'_> {
    fn peek(&self) -> Option<&[u8]> {
        self.t.get(self.i).map(Vec::as_slice)
    }
    fn or(&mut self) -> Option<Vec<u8>> {
        let mut l = self.and()?;
        while self.peek() == Some(b"|") {
            self.i += 1;
            let r = self.and()?;
            if null(&l) {
                l = if null(&r) { b"0".to_vec() } else { r };
            }
        }
        Some(l)
    }
    fn and(&mut self) -> Option<Vec<u8>> {
        let mut l = self.cmp()?;
        while self.peek() == Some(b"&") {
            self.i += 1;
            let r = self.cmp()?;
            if null(&l) || null(&r) {
                l = b"0".to_vec();
            }
        }
        Some(l)
    }
    fn cmp(&mut self) -> Option<Vec<u8>> {
        let mut l = self.add()?;
        while let Some(op) =
            self.peek().filter(|o| matches!(*o, b"=" | b"!=" | b"<" | b"<=" | b">" | b">=")).map(<[u8]>::to_vec)
        {
            self.i += 1;
            let r = self.add()?;
            let o = match (as_int(&l), as_int(&r)) {
                (Some(a), Some(b)) => a.cmp(&b),
                _ => l.cmp(&r),
            };
            let t = match op.as_slice() {
                b"=" => o.is_eq(),
                b"!=" => o.is_ne(),
                b"<" => o.is_lt(),
                b"<=" => o.is_le(),
                b">" => o.is_gt(),
                _ => o.is_ge(),
            };
            l = if t { b"1".to_vec() } else { b"0".to_vec() };
        }
        Some(l)
    }
    fn add(&mut self) -> Option<Vec<u8>> {
        let mut l = self.mul()?;
        while let Some(op) = self.peek().filter(|o| *o == b"+" || *o == b"-").map(<[u8]>::to_vec) {
            self.i += 1;
            let r = self.mul()?;
            let (a, b) = (as_int(&l)?, as_int(&r)?);
            l = alloc::format!("{}", if op == b"+" { a + b } else { a - b }).into_bytes();
        }
        Some(l)
    }
    fn mul(&mut self) -> Option<Vec<u8>> {
        let mut l = self.colon()?;
        while let Some(op) = self.peek().filter(|o| matches!(*o, b"*" | b"/" | b"%")).map(<[u8]>::to_vec) {
            self.i += 1;
            let r = self.colon()?;
            let (a, b) = (as_int(&l)?, as_int(&r)?);
            if b == 0 && op != b"*" {
                error("division by zero");
                return None;
            }
            l = alloc::format!(
                "{}",
                match op.as_slice() {
                    b"*" => a * b,
                    b"/" => a / b,
                    _ => a % b,
                }
            )
            .into_bytes();
        }
        Some(l)
    }
    fn colon(&mut self) -> Option<Vec<u8>> {
        let l = self.primary()?;
        if self.peek() == Some(b":") {
            self.i += 1;
            let pat = self.primary()?;
            return Some(expr_match(&l, &pat));
        }
        Some(l)
    }
    fn primary(&mut self) -> Option<Vec<u8>> {
        let t = self.peek()?.to_vec();
        self.i += 1;
        match t.as_slice() {
            b"(" => {
                let v = self.or()?;
                (self.peek() == Some(b")")).then(|| self.i += 1)?;
                Some(v)
            }
            b"length" => {
                let s = self.primary()?;
                Some(alloc::format!("{}", s.len()).into_bytes())
            }
            b"substr" => {
                let s = self.primary()?;
                let p = as_int(&self.primary()?)?;
                let n = as_int(&self.primary()?)?;
                if p < 1 || n < 1 {
                    return Some(Vec::new());
                }
                let start = (p as usize - 1).min(s.len());
                let end = (start + n as usize).min(s.len());
                Some(s[start..end].to_vec())
            }
            b"index" => {
                let s = self.primary()?;
                let chars = self.primary()?;
                let i = s.iter().position(|c| chars.contains(c)).map_or(0, |i| i + 1);
                Some(alloc::format!("{i}").into_bytes())
            }
            b"match" => {
                let s = self.primary()?;
                let pat = self.primary()?;
                Some(expr_match(&s, &pat))
            }
            b"+" => self.primary(),
            _ => Some(t),
        }
    }
}

/// The kernel's Linux compatibility switch and its saved setting
/// (ADR 0032).
const COMPAT_KNOB: &[u8] = b"/proc/sys/slate/linux_compat";
const COMPAT_SAVED: &[u8] = b"/etc/slate/linux-compat";

/// Running Linux-domain processes: (pid, name), from /proc/PID/status.
fn linux_processes() -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    for e in fs::read_dir(b"/proc").unwrap_or_default() {
        if e.name.is_empty() || !e.name.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Ok(status) = fs::read_file(&fs::join(b"/proc", &fs::join(&e.name, b"status"))) else { continue };
        let field = |key: &[u8]| {
            status.split(|&c| c == b'\n').find_map(|l| l.strip_prefix(key)).map(|v| v.trim_ascii().to_vec())
        };
        if field(b"Domain:").as_deref() == Some(b"linux") {
            out.push((e.name.clone(), field(b"Name:").unwrap_or_default()));
        }
    }
    out
}

/// slate-compat [on|off|status] [--yes]: Linux compatibility mode. `off`
/// stops the running Linux programs, so it lists them and asks first.
pub fn slate_compat(args: &[Vec<u8>]) -> i32 {
    let (mut op, mut yes) = (None, false);
    for a in &args[1..] {
        match a.as_slice() {
            b"on" | b"off" | b"status" if op.is_none() => op = Some(a.clone()),
            b"-y" | b"--yes" => yes = true,
            _ => {
                error("usage: slate-compat [on|off|status] [--yes]");
                return 2;
            }
        }
    }
    let current = fs::read_file(COMPAT_KNOB).ok().map(|v| v.starts_with(b"1"));
    let Some(on) = current else {
        error("Linux compatibility mode is not available here (no /proc/sys/slate/linux_compat)");
        return 1;
    };
    let word = |b: bool| if b { "on" } else { "off" };
    match op.as_deref().unwrap_or(b"status") {
        b"status" => {
            println!("Linux compatibility mode is {}", word(on));
            if let Ok(saved) = fs::read_file(COMPAT_SAVED) {
                let saved = saved.trim_ascii() == b"on";
                if saved != on {
                    println!("(it will be {} after a reboot)", word(saved));
                }
            }
            0
        }
        want => {
            let turn_on = want == b"on";
            if !turn_on {
                let running = linux_processes();
                if !running.is_empty() && !yes {
                    println!("These Linux programs will stop:");
                    for (pid, name) in &running {
                        println!("  {} {}", lossy(pid), lossy(name));
                    }
                    io::out(b"Turn Linux compatibility mode off? [y/N] ");
                    io::flush_stdout();
                    let mut answer = [0u8; 16];
                    let n = io::read(io::STDIN, &mut answer).unwrap_or(0);
                    if !matches!(answer[..n].first(), Some(b'y' | b'Y')) {
                        println!("Nothing changed.");
                        return 1;
                    }
                }
            }
            if let Err(e) = fs::write_file(COMPAT_KNOB, if turn_on { b"1" } else { b"0" }, 0o644) {
                error(format_args!("changing Linux compatibility mode: {e}"));
                return 1;
            }
            let _ = fs::mkdir(b"/etc/slate", 0o755);
            if let Err(e) = fs::write_file(COMPAT_SAVED, format!("{}\n", word(turn_on)).as_bytes(), 0o644) {
                error(format_args!("saving the setting in /etc/slate/linux-compat: {e} (it lasts until a reboot)"));
            }
            println!("Linux compatibility mode is {}", word(turn_on));
            0
        }
    }
}
