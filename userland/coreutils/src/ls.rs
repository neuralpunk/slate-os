// SPDX-License-Identifier: MIT OR Apache-2.0

//! ls(1), with the GNU options scripts and people use: -a -A -l -1 -C -x
//! -d -R -h -i -s -t -S -r -U -F -p -n -g -o -L -c -u, --color,
//! --group-directories-first. Names sort bytewise (the C locale).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

use slate_rt::{Errno, fs, io, lossy, term};

use crate::simple::{group_name, user_name};
use crate::util::{Opt, Parser, bad_option, error, human};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Name,
    Time,
    Size,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    Long,
    One,
    Columns,
    Across,
}

#[derive(Debug)]
struct Opts {
    all: bool,
    almost: bool,
    dir_self: bool,
    recursive: bool,
    human: bool,
    inode: bool,
    blocks: bool,
    sort: Sort,
    reverse: bool,
    classify: bool,
    slash: bool,
    numeric: bool,
    no_owner: bool,
    no_group: bool,
    deref: bool,
    ctime: bool,
    atime: bool,
    color: bool,
    dirs_first: bool,
    layout: Layout,
    width: usize,
    time_style: TimeStyle,
}

/// `--time-style`: date(1) formats for files older than six months and
/// for recent ones.
#[derive(Clone, Debug)]
enum TimeStyle {
    Locale,
    Formats(String, String),
}

impl TimeStyle {
    fn parse(v: &[u8]) -> Option<TimeStyle> {
        let v = lossy(v).into_owned();
        // posix-STYLE is STYLE outside the C locale, and locale in it (the
        // only locale Slate has).
        let v = if v.starts_with("posix-") { "locale" } else { v.as_str() };
        let f = |a: &str, b: &str| Some(TimeStyle::Formats(String::from(a), String::from(b)));
        match v {
            "locale" => Some(TimeStyle::Locale),
            "full-iso" => f("%Y-%m-%d %H:%M:%S.%N %z", "%Y-%m-%d %H:%M:%S.%N %z"),
            "long-iso" => f("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M"),
            "iso" => f("%Y-%m-%d ", "%m-%d %H:%M"),
            _ => {
                let fmt = v.strip_prefix('+')?;
                let (old, recent) = fmt.split_once('\n').unwrap_or((fmt, fmt));
                f(old, recent)
            }
        }
    }
}

struct Entry {
    name: Vec<u8>,
    path: Vec<u8>,
    st: Option<fs::Stat>,
    /// For symlinks: the target and the target's metadata.
    link: Option<(Vec<u8>, Option<fs::Stat>)>,
}

impl Entry {
    fn load(name: Vec<u8>, path: Vec<u8>, deref: bool, need_link: bool) -> Result<Entry, Errno> {
        let st = if deref { fs::stat(&path).or_else(|_| fs::lstat(&path))? } else { fs::lstat(&path)? };
        let link =
            (st.is_symlink() && need_link).then(|| (fs::readlink(&path).unwrap_or_default(), fs::stat(&path).ok()));
        Ok(Entry { name, path, st: Some(st), link })
    }
}

pub fn mode_string(m: u32) -> [u8; 10] {
    let kind = match m & fs::S_IFMT {
        fs::S_IFDIR => b'd',
        fs::S_IFLNK => b'l',
        fs::S_IFCHR => b'c',
        fs::S_IFBLK => b'b',
        fs::S_IFIFO => b'p',
        fs::S_IFSOCK => b's',
        _ => b'-',
    };
    let bit = |b: u32, c: u8| if m & b != 0 { c } else { b'-' };
    let special = |x: u32, s: u32, lower: u8, upper: u8| match (m & x != 0, m & s != 0) {
        (true, true) => lower,
        (false, true) => upper,
        (true, false) => b'x',
        _ => b'-',
    };
    [
        kind,
        bit(0o400, b'r'),
        bit(0o200, b'w'),
        special(0o100, 0o4000, b's', b'S'),
        bit(0o040, b'r'),
        bit(0o020, b'w'),
        special(0o010, 0o2000, b's', b'S'),
        bit(0o004, b'r'),
        bit(0o002, b'w'),
        special(0o001, 0o1000, b't', b'T'),
    ]
}

/// GNU's default colours (dircolors).
fn color_of(e: &Entry) -> Option<&'static str> {
    let st = e.st.as_ref()?;
    Some(match st.kind() {
        fs::S_IFDIR if st.mode & 0o1002 == 0o1002 => "30;42",
        fs::S_IFDIR if st.mode & 0o002 != 0 => "34;42",
        fs::S_IFDIR => "01;34",
        fs::S_IFLNK => match &e.link {
            Some((_, None)) => "40;31;01",
            _ => "01;36",
        },
        fs::S_IFIFO => "40;33",
        fs::S_IFSOCK => "01;35",
        fs::S_IFBLK | fs::S_IFCHR => "40;33;01",
        _ if st.mode & 0o4000 != 0 => "37;41",
        _ if st.mode & 0o2000 != 0 => "30;43",
        _ if st.mode & 0o111 != 0 => "01;32",
        _ => return None,
    })
}

fn indicator(st: &fs::Stat, classify: bool, slash: bool) -> &'static str {
    match st.kind() {
        fs::S_IFDIR if classify || slash => "/",
        _ if !classify => "",
        fs::S_IFLNK => "@",
        fs::S_IFIFO => "|",
        fs::S_IFSOCK => "=",
        _ if st.mode & 0o111 != 0 => "*",
        _ => "",
    }
}

fn display_name(e: &Entry, o: &Opts, with_link: bool) -> (String, usize) {
    let name = lossy(&e.name).into_owned();
    let width = name.chars().count();
    let mut s = String::new();
    let mut w = width;
    match (o.color, color_of(e)) {
        (true, Some(c)) => {
            let _ = write!(s, "\x1b[{c}m{name}\x1b[0m");
        }
        _ => s.push_str(&name),
    }
    if let Some(st) = &e.st {
        // -F on a symlink in long format marks the target instead.
        let ind = if with_link && st.is_symlink() { "" } else { indicator(st, o.classify, o.slash) };
        s.push_str(ind);
        w += ind.len();
    }
    if with_link && let Some((target, tst)) = &e.link {
        let t = lossy(target);
        s.push_str(" -> ");
        match (o.color, tst) {
            (true, Some(ts)) => {
                let te = Entry { name: target.clone(), path: Vec::new(), st: Some(*ts), link: None };
                match color_of(&te) {
                    Some(c) => {
                        let _ = write!(s, "\x1b[{c}m{t}\x1b[0m");
                    }
                    None => s.push_str(&t),
                }
            }
            _ => s.push_str(&t),
        }
        if let Some(ts) = tst {
            s.push_str(indicator(ts, o.classify, false));
        }
        w += 4 + t.chars().count();
    }
    (s, w)
}

fn sort_entries(v: &mut [Entry], o: &Opts) {
    let time = |e: &Entry| {
        e.st.as_ref().map_or((0, 0), |s| {
            if o.ctime {
                (s.ctime, s.ctime_nsec)
            } else if o.atime {
                (s.atime, s.atime_nsec)
            } else {
                (s.mtime, s.mtime_nsec)
            }
        })
    };
    match o.sort {
        Sort::None => {}
        Sort::Name => v.sort_by(|a, b| a.name.cmp(&b.name)),
        // Newest first; ties by name.
        Sort::Time => v.sort_by(|a, b| time(b).cmp(&time(a)).then_with(|| a.name.cmp(&b.name))),
        Sort::Size => v.sort_by(|a, b| {
            let s = |e: &Entry| e.st.as_ref().map_or(0, |s| s.size);
            s(b).cmp(&s(a)).then_with(|| a.name.cmp(&b.name))
        }),
    }
    if o.reverse {
        v.reverse();
    }
    if o.dirs_first {
        v.sort_by_key(|e| {
            !e.st
                .as_ref()
                .is_some_and(|s| s.is_dir() || e.link.as_ref().is_some_and(|l| l.1.is_some_and(|t| t.is_dir())))
        });
    }
}

fn time_string(t: i64, nsec: i64, style: &TimeStyle) -> String {
    let now = slate_rt::time::unix();
    let tm = slate_rt::tz::localtime(t);
    // Older than six months, or in the future: show the year.
    let six_months = 31_556_952 / 2;
    let old = t > now || now - t > six_months;
    let fmt = match style {
        TimeStyle::Locale if old => "%b %e  %Y",
        TimeStyle::Locale => "%b %e %H:%M",
        TimeStyle::Formats(o, _) if old => o.as_str(),
        TimeStyle::Formats(_, r) => r.as_str(),
    };
    crate::datetime::format(&tm, nsec as u32, fmt)
}

fn kib_blocks(st: &fs::Stat) -> u64 {
    (st.blocks as u64 * 512).div_ceil(1024)
}

fn print_long(v: &[Entry], o: &Opts, out: &mut Vec<u8>) {
    struct Row {
        inode: String,
        blocks: String,
        mode: String,
        links: String,
        owner: String,
        group: String,
        size: String,
        time: String,
        name: String,
    }
    let rows: Vec<Row> = v
        .iter()
        .filter_map(|e| {
            let st = e.st.as_ref()?;
            let owner = if o.numeric { None } else { user_name(st.uid) };
            let group = if o.numeric { None } else { group_name(st.gid) };
            let size = if matches!(st.kind(), fs::S_IFCHR | fs::S_IFBLK) {
                let (ma, mi) = (
                    ((st.rdev >> 32) & 0xFFFF_F000) | ((st.rdev >> 8) & 0xFFF),
                    ((st.rdev >> 12) & 0xFFFF_FF00) | (st.rdev & 0xFF),
                );
                alloc::format!("{ma}, {mi}")
            } else if o.human {
                human(st.size as u64)
            } else {
                alloc::format!("{}", st.size)
            };
            let (t, ns) = if o.ctime {
                (st.ctime, st.ctime_nsec)
            } else if o.atime {
                (st.atime, st.atime_nsec)
            } else {
                (st.mtime, st.mtime_nsec)
            };
            Some(Row {
                inode: alloc::format!("{}", st.ino),
                blocks: if o.human { human(kib_blocks(st) * 1024) } else { alloc::format!("{}", kib_blocks(st)) },
                mode: String::from_utf8_lossy(&mode_string(st.mode)).into_owned(),
                links: alloc::format!("{}", st.nlink),
                owner: owner.map_or_else(|| alloc::format!("{}", st.uid), |n| lossy(&n).into_owned()),
                group: group.map_or_else(|| alloc::format!("{}", st.gid), |n| lossy(&n).into_owned()),
                size,
                time: time_string(t, ns, &o.time_style),
                name: display_name(e, o, true).0,
            })
        })
        .collect();
    let w = |f: fn(&Row) -> &String| rows.iter().map(|r| f(r).len()).max().unwrap_or(0);
    let (wi, wb, wl, wo, wg, ws) =
        (w(|r| &r.inode), w(|r| &r.blocks), w(|r| &r.links), w(|r| &r.owner), w(|r| &r.group), w(|r| &r.size));
    for r in &rows {
        let mut line = String::new();
        if o.inode {
            let _ = write!(line, "{:>wi$} ", r.inode);
        }
        if o.blocks {
            let _ = write!(line, "{:>wb$} ", r.blocks);
        }
        let _ = write!(line, "{} {:>wl$} ", r.mode, r.links);
        if !o.no_owner {
            let _ = write!(line, "{:<wo$} ", r.owner);
        }
        if !o.no_group {
            let _ = write!(line, "{:<wg$} ", r.group);
        }
        let _ = write!(line, "{:>ws$} {} {}", r.size, r.time, r.name);
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
}

fn print_short(v: &[Entry], o: &Opts, out: &mut Vec<u8>) {
    let cells: Vec<(String, usize)> = v
        .iter()
        .map(|e| {
            let (name, w) = display_name(e, o, false);
            let mut prefix = String::new();
            if let Some(st) = &e.st {
                if o.inode {
                    let _ = write!(prefix, "{} ", st.ino);
                }
                if o.blocks {
                    let _ = write!(
                        prefix,
                        "{} ",
                        if o.human { human(kib_blocks(st) * 1024) } else { alloc::format!("{}", kib_blocks(st)) }
                    );
                }
            }
            let w = w + prefix.len();
            (prefix + &name, w)
        })
        .collect();
    if o.layout == Layout::One || cells.is_empty() {
        for (c, _) in &cells {
            out.extend_from_slice(c.as_bytes());
            out.push(b'\n');
        }
        return;
    }
    // The most columns that fit, with two spaces between columns.
    let n = cells.len();
    let mut best = (1, n, alloc::vec![cells.iter().map(|c| c.1).max().unwrap_or(0)]);
    for cols in (2..=n.min(o.width / 3 + 1)).rev() {
        let rows = n.div_ceil(cols);
        let cols = n.div_ceil(rows);
        let idx = |r: usize, c: usize| if o.layout == Layout::Across { r * cols + c } else { c * rows + r };
        let widths: Vec<usize> =
            (0..cols).map(|c| (0..rows).filter_map(|r| cells.get(idx(r, c))).map(|x| x.1).max().unwrap_or(0)).collect();
        let total: usize = widths.iter().sum::<usize>() + 2 * (cols - 1);
        if total < o.width {
            best = (cols, rows, widths);
            break;
        }
    }
    let (cols, rows, widths) = best;
    for r in 0..rows {
        let mut line = String::new();
        for (c, &width) in widths.iter().enumerate().take(cols) {
            let i = if o.layout == Layout::Across { r * cols + c } else { c * rows + r };
            let Some((text, w)) = cells.get(i) else { continue };
            line.push_str(text);
            let next = if o.layout == Layout::Across { r * cols + c + 1 } else { (c + 1) * rows + r };
            if c + 1 < cols && next < n && (o.layout != Layout::Across || c + 1 < cols) {
                line.extend(core::iter::repeat_n(' ', width - w + 2));
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
}

fn print_entries(v: &[Entry], o: &Opts, out: &mut Vec<u8>) {
    if o.layout == Layout::Long {
        print_long(v, o, out);
    } else {
        print_short(v, o, out);
    }
}

fn list_dir(path: &[u8], o: &Opts, out: &mut Vec<u8>, header: bool, first: &mut bool) -> bool {
    let names = match fs::read_dir(path) {
        Ok(n) => n,
        Err(e) => {
            io::out(out);
            out.clear();
            error(format_args!("cannot open directory '{}': {e}", lossy(path)));
            return false;
        }
    };
    if header {
        if !*first {
            out.push(b'\n');
        }
        out.extend_from_slice(path);
        out.extend_from_slice(b":\n");
    }
    *first = false;
    let mut entries: Vec<Entry> = Vec::new();
    if o.all {
        for dot in [&b"."[..], b".."] {
            if let Ok(e) = Entry::load(dot.to_vec(), fs::join(path, dot), false, false) {
                entries.push(e);
            }
        }
    }
    let need_link = o.layout == Layout::Long || o.color || o.classify;
    for d in names {
        if d.name.starts_with(b".") && !o.all && !o.almost {
            continue;
        }
        let p = fs::join(path, &d.name);
        match Entry::load(d.name.clone(), p.clone(), o.deref, need_link) {
            Ok(e) => entries.push(e),
            Err(_) => entries.push(Entry { name: d.name, path: p, st: None, link: None }),
        }
    }
    sort_entries(&mut entries, o);
    if o.layout == Layout::Long || o.blocks {
        let total: u64 = entries.iter().filter_map(|e| e.st.as_ref()).map(kib_blocks).sum();
        let t = if o.human { human(total * 1024) } else { alloc::format!("{total}") };
        out.extend_from_slice(alloc::format!("total {t}\n").as_bytes());
    }
    print_entries(&entries, o, out);
    if out.len() > 64 * 1024 {
        io::out(out);
        out.clear();
    }
    let mut ok = true;
    if o.recursive {
        for e in &entries {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            if e.st.as_ref().is_some_and(|s| s.is_dir()) {
                ok &= list_dir(&e.path, o, out, true, first);
            }
        }
    }
    ok
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let tty = term::isatty(io::STDOUT);
    let width = term::size(io::STDOUT)
        .map(|(_, c)| usize::from(c))
        .or_else(|| slate_rt::env::var(b"COLUMNS").and_then(|c| crate::util::parse_num(&c)))
        .unwrap_or(80);
    let mut o = Opts {
        all: false,
        almost: false,
        dir_self: false,
        recursive: false,
        human: false,
        inode: false,
        blocks: false,
        sort: Sort::Name,
        reverse: false,
        classify: false,
        slash: false,
        numeric: false,
        no_owner: false,
        no_group: false,
        deref: false,
        ctime: false,
        atime: false,
        color: false,
        dirs_first: false,
        layout: if tty { Layout::Columns } else { Layout::One },
        width,
        time_style: TimeStyle::Locale,
    };
    if let Some(v) = slate_rt::env::var(b"TIME_STYLE")
        && let Some(t) = TimeStyle::parse(&v)
    {
        o.time_style = t;
    }
    let mut paths = Vec::new();
    let mut p = Parser::new(args, b"wT");
    while let Some(opt) = p.next() {
        match opt {
            Opt::Short(b'a') => o.all = true,
            Opt::Short(b'A') => o.almost = true,
            Opt::Short(b'l') => o.layout = Layout::Long,
            Opt::Short(b'1') => o.layout = Layout::One,
            Opt::Short(b'C') => o.layout = Layout::Columns,
            Opt::Short(b'x') => o.layout = Layout::Across,
            Opt::Short(b'd') => o.dir_self = true,
            Opt::Short(b'R') => o.recursive = true,
            Opt::Short(b'h') => o.human = true,
            Opt::Short(b'i') => o.inode = true,
            Opt::Short(b's') => o.blocks = true,
            Opt::Short(b't') => o.sort = Sort::Time,
            Opt::Short(b'S') => o.sort = Sort::Size,
            Opt::Short(b'U') => o.sort = Sort::None,
            Opt::Short(b'f') => (o.sort, o.all) = (Sort::None, true),
            Opt::Short(b'r') => o.reverse = true,
            Opt::Short(b'F') => o.classify = true,
            Opt::Short(b'p') => o.slash = true,
            Opt::Short(b'n') => (o.numeric, o.layout) = (true, Layout::Long),
            Opt::Short(b'g') => (o.no_owner, o.layout) = (true, Layout::Long),
            Opt::Short(b'o') => (o.no_group, o.layout) = (true, Layout::Long),
            Opt::Short(b'G') => o.no_group = true,
            Opt::Short(b'L') => o.deref = true,
            Opt::Short(b'H') => {}
            Opt::Short(b'c') => o.ctime = true,
            Opt::Short(b'u') => o.atime = true,
            Opt::Short(b'w') => o.width = p.value().and_then(|v| crate::util::parse_num(&v)).unwrap_or(80),
            Opt::Short(b'T' | b'b' | b'q' | b'N' | b'v') => {}
            Opt::Long(l) => match l.as_str() {
                "all" => o.all = true,
                "almost-all" => o.almost = true,
                "directory" => o.dir_self = true,
                "recursive" => o.recursive = true,
                "human-readable" => o.human = true,
                "inode" => o.inode = true,
                "size" => o.blocks = true,
                "reverse" => o.reverse = true,
                "classify" => o.classify = true,
                "numeric-uid-gid" => (o.numeric, o.layout) = (true, Layout::Long),
                "dereference" => o.deref = true,
                "group-directories-first" => o.dirs_first = true,
                "color" | "colour" => {
                    let v = p.value_inline();
                    o.color = match v.as_deref() {
                        None | Some(b"always" | b"yes" | b"force") => true,
                        Some(b"auto" | b"tty" | b"if-tty") => tty,
                        _ => false,
                    }
                }
                "full-time" => {
                    o.layout = Layout::Long;
                    o.time_style = TimeStyle::parse(b"full-iso").unwrap_or(TimeStyle::Locale);
                }
                "time-style" => {
                    let v = p.value_inline().or_else(|| p.value()).unwrap_or_default();
                    match TimeStyle::parse(&v) {
                        Some(t) => o.time_style = t,
                        None => {
                            error(format_args!("invalid argument '{}' for 'time style'", lossy(&v)));
                            slate_rt::eprintln!(
                                "Valid arguments are:\n  - [posix-]full-iso\n  - [posix-]long-iso\n  - [posix-]iso\n  - [posix-]locale\n  - +FORMAT (e.g., +%H:%M) for a 'date'-style format"
                            );
                            slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
                            return 2;
                        }
                    }
                }
                "sort" => {
                    o.sort = match p.value().as_deref() {
                        Some(b"time") => Sort::Time,
                        Some(b"size") => Sort::Size,
                        Some(b"none") => Sort::None,
                        _ => Sort::Name,
                    }
                }
                _ => return bad_option(&Opt::Long(l)),
            },
            Opt::Operand(path) => paths.push(path),
            opt => return bad_option(&opt),
        }
    }
    let mut out = Vec::new();
    let mut status = 0;
    let explicit = !paths.is_empty();
    if paths.is_empty() {
        paths.push(b".".to_vec());
    }
    let mut files = Vec::new();
    let mut dirs = Vec::new();
    for path in &paths {
        // Command-line symlinks are followed unless -d, -F or -l (GNU).
        let deref = o.deref || path.ends_with(b"/") || (!o.dir_self && o.layout != Layout::Long && !o.classify);
        match Entry::load(path.clone(), path.clone(), deref, true) {
            Ok(e) => {
                if !o.dir_self && e.st.as_ref().is_some_and(|s| s.is_dir()) {
                    dirs.push(e);
                } else {
                    files.push(e);
                }
            }
            Err(e) => {
                error(format_args!("cannot access '{}': {e}", lossy(path)));
                status = 2;
            }
        }
    }
    sort_entries(&mut files, &o);
    sort_entries(&mut dirs, &o);
    print_entries(&files, &o, &mut out);
    let mut first = files.is_empty();
    let header = explicit && (dirs.len() + files.len() > 1 || o.recursive) || o.recursive;
    for d in &dirs {
        if !list_dir(&d.path, &o, &mut out, header, &mut first) {
            status = status.max(1);
        }
    }
    io::out(&out);
    status
}

impl Parser<'_> {
    /// The value of a long option only when given inline (`--color=x`).
    pub fn value_inline(&mut self) -> Option<Vec<u8>> {
        self.inline_value()
    }
}
