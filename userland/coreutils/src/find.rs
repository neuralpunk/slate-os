// SPDX-License-Identifier: MIT OR Apache-2.0

//! find (POSIX.1-2017 XCU find, plus the GNU tests and actions people use:
//! -maxdepth/-mindepth, -iname, -ipath, -regex, -empty, -readable, -mmin,
//! -newerXY, -print0, -printf, -ls, -fprint*, -fls, -delete, -execdir,
//! -ok/-okdir, -quit).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use slate_regex::fnmatch::{Flags, fnmatch_with};
use slate_regex::{Options, Regex, Syntax, Whole};
use slate_rt::{fs, io, lossy, process};

use crate::util::{error, parse_num};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cmp {
    Less,
    More,
    Exactly,
}

fn cmp(c: Cmp, v: i64, n: i64) -> bool {
    match c {
        Cmp::Less => v < n,
        Cmp::More => v > n,
        Cmp::Exactly => v == n,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimeField {
    A,
    C,
    M,
}

#[derive(Debug)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    /// `,` (GNU): both, the value of the right.
    List(Box<Expr>, Box<Expr>),
    True,
    False,
    Name(Vec<u8>, bool),
    Path(Vec<u8>, bool),
    LinkName(Vec<u8>, bool),
    Regex(Box<Regex>),
    Type(Vec<u8>, bool),
    Size(Cmp, i64, u64),
    Empty,
    Perm(u32, u8),
    Uid(Cmp, i64),
    Gid(Cmp, i64),
    NoUser,
    NoGroup,
    Links(Cmp, i64),
    Inum(Cmp, i64),
    /// Age in units (seconds per unit).
    Time(TimeField, Cmp, i64, i64),
    Newer(TimeField, i64, i64),
    SameFile(u64, u64),
    Access(u32),
    /// Output actions: the terminator or format, and the `-fprint*`
    /// file (an index into `Ctx::files`), or standard output.
    Print(u8, Option<usize>),
    Printf(Vec<u8>, Option<usize>),
    Ls(Option<usize>),
    Exec {
        cmd: Vec<Vec<u8>>,
        batch: bool,
        dir: bool,
        /// -ok/-okdir: ask first.
        ask: bool,
        pending: Vec<Vec<u8>>,
    },
    Delete,
    Prune,
    Quit,
}

struct Ctx {
    now: i64,
    maxdepth: Option<usize>,
    mindepth: usize,
    depth_first: bool,
    xdev: bool,
    follow: Follow,
    status: i32,
    quit: bool,
    out: Vec<u8>,
    /// `-fprint*` and `-fls` files: descriptor and pending output.
    files: Vec<(i32, Vec<u8>)>,
    names: Names,
}

/// User and group names, read once (`%u`, `%g`, `-ls`, `-nouser`).
#[derive(Default)]
struct Names {
    users: Option<Vec<(Vec<u8>, u32)>>,
    groups: Option<Vec<(Vec<u8>, u32)>>,
    /// Device numbers and file system types, from mountinfo (`%F`).
    mounts: Option<Vec<(u64, Vec<u8>)>>,
}

impl Names {
    fn load(db: &[u8]) -> Vec<(Vec<u8>, u32)> {
        crate::simple::db_names(db).into_iter().map(|(n, id, _)| (n, id)).collect()
    }

    fn user(&mut self, uid: u32) -> Option<Vec<u8>> {
        let u = self.users.get_or_insert_with(|| Names::load(b"/etc/passwd"));
        u.iter().find(|(_, id)| *id == uid).map(|(n, _)| n.clone())
    }

    fn group(&mut self, gid: u32) -> Option<Vec<u8>> {
        let g = self.groups.get_or_insert_with(|| Names::load(b"/etc/group"));
        g.iter().find(|(_, id)| *id == gid).map(|(n, _)| n.clone())
    }

    /// The type of the file system on device `dev` (proc(5), mountinfo:
    /// field 3 is major:minor, the type follows the ` - `).
    fn fs_type(&mut self, dev: u64) -> Vec<u8> {
        let m = self.mounts.get_or_insert_with(|| {
            let data = fs::read_file(b"/proc/self/mountinfo").unwrap_or_default();
            data.split(|&c| c == b'\n')
                .filter_map(|l| {
                    let f: Vec<&[u8]> = l.split(|&c| c == b' ').collect();
                    let (maj, min) = lossy(f.get(2)?)
                        .split_once(':')
                        .map(|(a, b)| (a.parse::<u64>().ok(), b.parse::<u64>().ok()))?;
                    let (maj, min) = (maj?, min?);
                    let sep = f.iter().position(|x| *x == b"-")?;
                    let dev = (maj << 8) | (min & 0xff) | ((min & !0xff) << 12) | ((maj & !0xfff) << 32);
                    Some((dev, f.get(sep + 1)?.to_vec()))
                })
                .collect()
        });
        // The last mount of the device wins (a later mount covers it).
        m.iter().rev().find(|(d, _)| *d == dev).map_or_else(|| b"unknown".to_vec(), |(_, t)| t.clone())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Follow {
    Never,
    CommandLine,
    Always,
}

/// The file being looked at.
struct Entry<'a> {
    path: &'a [u8],
    /// Its starting point (for %P, -execdir).
    start: &'a [u8],
    depth: usize,
    st: fs::Stat,
    /// The lstat of a symlink that was followed.
    link: Option<fs::Stat>,
    prune: bool,
}

fn basename(p: &[u8]) -> &[u8] {
    let mut t = p;
    while t.len() > 1 && t.ends_with(b"/") {
        t = &t[..t.len() - 1];
    }
    match t.iter().rposition(|&c| c == b'/') {
        Some(i) if i + 1 < t.len() => &t[i + 1..],
        Some(_) => b"/",
        None => t,
    }
}

fn type_char(mode: u32) -> u8 {
    match mode & fs::S_IFMT {
        fs::S_IFDIR => b'd',
        fs::S_IFLNK => b'l',
        fs::S_IFBLK => b'b',
        fs::S_IFCHR => b'c',
        fs::S_IFIFO => b'p',
        fs::S_IFSOCK => b's',
        _ => b'f',
    }
}

fn user_id(name: &[u8]) -> Option<i64> {
    if let Some(n) = parse_num::<i64>(name) {
        return Some(n);
    }
    crate::simple::db_names(b"/etc/passwd").into_iter().find(|(n, _, _)| n == name).map(|(_, id, _)| id as i64)
}

fn group_id(name: &[u8]) -> Option<i64> {
    if let Some(n) = parse_num::<i64>(name) {
        return Some(n);
    }
    crate::simple::db_names(b"/etc/group").into_iter().find(|(n, _, _)| n == name).map(|(_, id, _)| id as i64)
}

/// The parser of the expression (XCU find's grammar).
struct P<'a> {
    a: &'a [Vec<u8>],
    i: usize,
    ctx: &'a mut Ctx,
    has_action: bool,
    regextype: Syntax,
    emacs: bool,
}

type R<T> = Result<T, String>;

fn num_arg(s: &[u8]) -> Option<(Cmp, i64)> {
    let (c, rest) = match s.first() {
        Some(b'+') => (Cmp::More, &s[1..]),
        Some(b'-') => (Cmp::Less, &s[1..]),
        _ => (Cmp::Exactly, s),
    };
    Some((c, parse_num::<i64>(rest)?))
}

impl P<'_> {
    fn peek(&self) -> Option<&[u8]> {
        self.a.get(self.i).map(Vec::as_slice)
    }
    fn arg(&mut self, opt: &[u8]) -> R<Vec<u8>> {
        let v = self.a.get(self.i).cloned().ok_or_else(|| alloc::format!("missing argument to `{}'", lossy(opt)))?;
        self.i += 1;
        Ok(v)
    }

    fn or(&mut self) -> R<Expr> {
        let mut l = self.and()?;
        loop {
            match self.peek() {
                Some(b"-o" | b"-or") => {
                    self.i += 1;
                    let r = self.and()?;
                    l = Expr::Or(Box::new(l), Box::new(r));
                }
                Some(b",") => {
                    self.i += 1;
                    let r = self.and()?;
                    l = Expr::List(Box::new(l), Box::new(r));
                }
                _ => return Ok(l),
            }
        }
    }

    fn and(&mut self) -> R<Expr> {
        let mut l = self.not()?;
        loop {
            match self.peek() {
                Some(b"-a" | b"-and") => {
                    self.i += 1;
                    let r = self.not()?;
                    l = Expr::And(Box::new(l), Box::new(r));
                }
                Some(b"-o" | b"-or" | b"," | b")") | None => return Ok(l),
                Some(_) => {
                    let r = self.not()?;
                    l = Expr::And(Box::new(l), Box::new(r));
                }
            }
        }
    }

    fn not(&mut self) -> R<Expr> {
        match self.peek() {
            Some(b"!" | b"-not") => {
                self.i += 1;
                Ok(Expr::Not(Box::new(self.not()?)))
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> R<Expr> {
        let Some(t) = self.peek().map(<[u8]>::to_vec) else { return Err(String::from("expected an expression")) };
        self.i += 1;
        Ok(match t.as_slice() {
            b"(" => {
                let e = self.or()?;
                if self.peek() != Some(b")") {
                    return Err(String::from(
                        "invalid expression; I was expecting to find a ')' somewhere but did not see one.",
                    ));
                }
                self.i += 1;
                e
            }
            b"-true" => Expr::True,
            b"-false" => Expr::False,
            b"-name" | b"-iname" => Expr::Name(self.arg(&t)?, t == b"-iname"),
            b"-path" | b"-wholename" | b"-ipath" | b"-iwholename" => Expr::Path(self.arg(&t)?, t.starts_with(b"-i")),
            b"-lname" | b"-ilname" => Expr::LinkName(self.arg(&t)?, t == b"-ilname"),
            b"-regex" | b"-iregex" => {
                let mut pat = self.arg(&t)?;
                if self.emacs {
                    // Emacs syntax: unescaped + and ? are operators.
                    let mut o = Vec::new();
                    let mut k = 0;
                    while k < pat.len() {
                        match pat[k] {
                            b'\\' if k + 1 < pat.len() => {
                                o.extend_from_slice(&pat[k..k + 2]);
                                k += 2;
                                continue;
                            }
                            c @ (b'+' | b'?') => o.extend_from_slice(&[b'\\', c]),
                            c => o.push(c),
                        }
                        k += 1;
                    }
                    pat = o;
                }
                let opts = Options {
                    syntax: self.regextype,
                    icase: t == b"-iregex",
                    whole: Whole::Line,
                    utf8: crate::util::utf8_locale(),
                    ..Options::default()
                };
                Expr::Regex(Box::new(Regex::new(&pat, opts).map_err(|e| e.0)?))
            }
            b"-type" | b"-xtype" => {
                let v = self.arg(&t)?;
                for c in v.split(|&c| c == b',') {
                    if c.len() != 1 || !b"fdlbcps".contains(&c[0]) {
                        return Err(alloc::format!("Unknown argument to {}: {}", lossy(&t), lossy(&v)));
                    }
                }
                Expr::Type(v.into_iter().filter(|&c| c != b',').collect(), t == b"-xtype")
            }
            b"-size" => {
                let v = self.arg(&t)?;
                let (unit, digits) = match v.last() {
                    Some(b'c') => (1, &v[..v.len() - 1]),
                    Some(b'w') => (2, &v[..v.len() - 1]),
                    Some(b'b') => (512, &v[..v.len() - 1]),
                    Some(b'k') => (1024, &v[..v.len() - 1]),
                    Some(b'M') => (1024 * 1024, &v[..v.len() - 1]),
                    Some(b'G') => (1024 * 1024 * 1024, &v[..v.len() - 1]),
                    _ => (512, &v[..]),
                };
                let (c, n) = num_arg(digits).ok_or_else(|| alloc::format!("invalid -size argument `{}'", lossy(&v)))?;
                Expr::Size(c, n, unit)
            }
            b"-empty" => Expr::Empty,
            b"-perm" => {
                let v = self.arg(&t)?;
                let (kind, m) = match v.first() {
                    Some(b'-') => (b'-', &v[1..]),
                    Some(b'/') => (b'/', &v[1..]),
                    _ => (b'=', &v[..]),
                };
                let mode = crate::fileops::apply_mode(m, 0, false, 0)
                    .ok_or_else(|| alloc::format!("invalid mode `{}'", lossy(&v)))?;
                Expr::Perm(mode & 0o7777, kind)
            }
            b"-user" => {
                let v = self.arg(&t)?;
                let id =
                    user_id(&v).ok_or_else(|| alloc::format!("'{}' is not the name of a known user", lossy(&v)))?;
                Expr::Uid(Cmp::Exactly, id)
            }
            b"-group" => {
                let v = self.arg(&t)?;
                let id = group_id(&v)
                    .ok_or_else(|| alloc::format!("'{}' is not the name of an existing group", lossy(&v)))?;
                Expr::Gid(Cmp::Exactly, id)
            }
            b"-uid" | b"-gid" | b"-links" | b"-inum" => {
                let v = self.arg(&t)?;
                let (c, n) =
                    num_arg(&v).ok_or_else(|| alloc::format!("invalid argument `{}' to `{}'", lossy(&v), lossy(&t)))?;
                match t.as_slice() {
                    b"-uid" => Expr::Uid(c, n),
                    b"-gid" => Expr::Gid(c, n),
                    b"-links" => Expr::Links(c, n),
                    _ => Expr::Inum(c, n),
                }
            }
            b"-nouser" => Expr::NoUser,
            b"-nogroup" => Expr::NoGroup,
            b"-mtime" | b"-atime" | b"-ctime" | b"-mmin" | b"-amin" | b"-cmin" => {
                let v = self.arg(&t)?;
                let (c, n) =
                    num_arg(&v).ok_or_else(|| alloc::format!("invalid argument `{}' to `{}'", lossy(&v), lossy(&t)))?;
                let field = match t[1] {
                    b'a' => TimeField::A,
                    b'c' => TimeField::C,
                    _ => TimeField::M,
                };
                let unit = if t.ends_with(b"min") { 60 } else { 86400 };
                Expr::Time(field, c, n, unit)
            }
            b"-newer" | b"-anewer" | b"-cnewer" => {
                let f = self.arg(&t)?;
                let st = fs::stat(&f).map_err(|e| alloc::format!("'{}': {e}", lossy(&f)))?;
                let field = match t[1] {
                    b'a' => TimeField::A,
                    b'c' => TimeField::C,
                    _ => TimeField::M,
                };
                Expr::Newer(field, st.mtime, st.mtime_nsec)
            }
            _ if t.len() == 8 && t.starts_with(b"-newer") => {
                // -newerXY: the file's X time against the reference's Y
                // time, or (Y = t) a date.
                let (x, y) = (t[6], t[7]);
                let field = |c: u8| -> R<Option<TimeField>> {
                    match c {
                        b'a' => Ok(Some(TimeField::A)),
                        b'c' => Ok(Some(TimeField::C)),
                        b'm' => Ok(Some(TimeField::M)),
                        b'B' => {
                            Err(String::from("This system does not provide a way to find the birth time of a file."))
                        }
                        b't' => Ok(None),
                        _ => Err(alloc::format!("invalid predicate `{}'", lossy(&t))),
                    }
                };
                let Some(fx) = field(x)? else { return Err(alloc::format!("invalid predicate `{}'", lossy(&t))) };
                let v = self.arg(&t)?;
                let (secs, ns) = match field(y)? {
                    Some(fy) => {
                        let st = fs::stat(&v).map_err(|e| alloc::format!("'{}': {e}", lossy(&v)))?;
                        time_of(&st, fy)
                    }
                    None => {
                        let (s, n) = slate_rt::time::now(slate_rt::time::CLOCK_REALTIME);
                        let now = crate::datetime::Instant { secs: s, nsec: n as u32 };
                        let d = crate::datetime::parse(&lossy(&v), now, false).ok_or_else(|| {
                            alloc::format!("I cannot figure out how to interpret `{}' as a date or time", lossy(&v))
                        })?;
                        (d.secs, i64::from(d.nsec))
                    }
                };
                Expr::Newer(fx, secs, ns)
            }
            b"-samefile" => {
                let f = self.arg(&t)?;
                let st = fs::stat(&f).map_err(|e| alloc::format!("'{}': {e}", lossy(&f)))?;
                Expr::SameFile(st.dev, st.ino)
            }
            b"-readable" => Expr::Access(4),
            b"-writable" => Expr::Access(2),
            b"-executable" => Expr::Access(1),
            b"-print" => {
                self.has_action = true;
                Expr::Print(b'\n', None)
            }
            b"-print0" => {
                self.has_action = true;
                Expr::Print(0, None)
            }
            b"-printf" => {
                self.has_action = true;
                Expr::Printf(self.arg(&t)?, None)
            }
            b"-ls" => {
                self.has_action = true;
                Expr::Ls(None)
            }
            b"-fprint" | b"-fprint0" | b"-fprintf" | b"-fls" => {
                self.has_action = true;
                let f = self.arg(&t)?;
                let file = self.open_output(&f)?;
                match t.as_slice() {
                    b"-fprint" => Expr::Print(b'\n', Some(file)),
                    b"-fprint0" => Expr::Print(0, Some(file)),
                    b"-fls" => Expr::Ls(Some(file)),
                    _ => Expr::Printf(self.arg(&t)?, Some(file)),
                }
            }
            b"-exec" | b"-execdir" | b"-ok" | b"-okdir" => {
                let ask = t.starts_with(b"-ok");
                self.has_action = true;
                let mut cmd = Vec::new();
                let batch = loop {
                    let Some(w) = self.a.get(self.i).cloned() else {
                        return Err(alloc::format!("missing argument to `{}'", lossy(&t)));
                    };
                    self.i += 1;
                    if w == b";" {
                        break false;
                    }
                    if w == b"+" && cmd.last().is_some_and(|l: &Vec<u8>| l == b"{}") {
                        cmd.pop();
                        break true;
                    }
                    cmd.push(w);
                };
                if cmd.is_empty() {
                    return Err(alloc::format!("missing argument to `{}'", lossy(&t)));
                }
                if ask && batch {
                    return Err(alloc::format!("you have used `+' with `{}'; use `;' instead", lossy(&t)));
                }
                let dir = t.ends_with(b"dir");
                Expr::Exec { cmd, batch, dir, ask, pending: Vec::new() }
            }
            b"-delete" => {
                self.has_action = true;
                self.ctx.depth_first = true;
                Expr::Delete
            }
            b"-prune" => Expr::Prune,
            b"-quit" => Expr::Quit,
            // Options anywhere in the expression (GNU warns; we do not).
            b"-maxdepth" | b"-mindepth" => {
                let v = self.arg(&t)?;
                let n = parse_num::<usize>(&v)
                    .ok_or_else(|| alloc::format!("invalid argument `{}' to `{}'", lossy(&v), lossy(&t)))?;
                if t == b"-maxdepth" {
                    self.ctx.maxdepth = Some(n);
                } else {
                    self.ctx.mindepth = n;
                }
                Expr::True
            }
            b"-depth" | b"-d" => {
                self.ctx.depth_first = true;
                Expr::True
            }
            b"-xdev" | b"-mount" => {
                self.ctx.xdev = true;
                Expr::True
            }
            b"-follow" => {
                self.ctx.follow = Follow::Always;
                Expr::True
            }
            b"-noleaf" | b"-ignore_readdir_race" | b"-noignore_readdir_race" | b"-nowarn" | b"-warn" | b"-daystart" => {
                Expr::True
            }
            b"-regextype" => {
                let v = self.arg(&t)?;
                match v.as_slice() {
                    b"posix-basic" | b"grep" | b"sed" => {
                        self.regextype = Syntax::Basic;
                        self.emacs = false;
                    }
                    b"posix-extended" | b"egrep" | b"awk" | b"posix-egrep" | b"posix-awk" | b"gnu-awk" => {
                        self.regextype = Syntax::Extended;
                        self.emacs = false;
                    }
                    b"emacs" | b"findutils-default" => {
                        self.regextype = Syntax::Basic;
                        self.emacs = true;
                    }
                    _ => return Err(alloc::format!("Unknown regular expression type `{}'", lossy(&v))),
                }
                Expr::True
            }
            _ if t.starts_with(b"-") => return Err(alloc::format!("unknown predicate `{}'", lossy(&t))),
            _ => return Err(alloc::format!("paths must precede expression: `{}'", lossy(&t))),
        })
    }
}

impl P<'_> {
    /// Open (truncating) a `-fprint*`/`-fls` file; the same name twice
    /// shares one file, as GNU's does.
    fn open_output(&mut self, name: &[u8]) -> R<usize> {
        let fd = if name == b"/dev/stdout" {
            io::STDOUT
        } else if name == b"/dev/stderr" {
            io::STDERR
        } else {
            fs::open(name, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o666)
                .map_err(|e| alloc::format!("'{}': {e}", lossy(name)))?
        };
        self.ctx.files.push((fd, Vec::new()));
        Ok(self.ctx.files.len() - 1)
    }
}

/// `-ok`'s question: `< cmd args... > ? ` on standard error, and an
/// answer starting with y or Y from standard input.
fn confirm(argv: &[Vec<u8>]) -> bool {
    let mut q = Vec::from(b"< ".as_slice());
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            q.push(b' ');
        }
        q.extend_from_slice(a);
    }
    q.extend_from_slice(b" > ? ");
    io::flush_stdout();
    io::err(&q);
    let mut r = io::Reader::new(io::STDIN);
    matches!(r.line(), Ok(Some(l)) if matches!(l.first(), Some(b'y' | b'Y')))
}

/// Run a command; true if it exited 0.
fn run(cmd: &[Vec<u8>], dir: Option<&[u8]>) -> bool {
    let Some(path) = process::find_in_path(&cmd[0]) else {
        error(alloc::format!("'{}': No such file or directory", lossy(&cmd[0])));
        return false;
    };
    io::flush_stdout();
    match process::fork() {
        Ok(0) => {
            if let Some(d) = dir
                && let Err(e) = fs::chdir(d)
            {
                error(alloc::format!("{}: {e}", lossy(d)));
                process::exit_now(1);
            }
            let e = process::execve(&path, cmd, slate_rt::env::vars());
            error(alloc::format!("'{}': {e}", lossy(&cmd[0])));
            process::exit_now(127);
        }
        Ok(pid) => process::wait(pid, 0).is_ok_and(|(_, s)| process::exited(s) == Some(0)),
        Err(e) => {
            error(alloc::format!("fork: {e}"));
            false
        }
    }
}

fn substitute(cmd: &[Vec<u8>], path: &[u8]) -> Vec<Vec<u8>> {
    cmd.iter()
        .map(|a| {
            let mut o = Vec::new();
            let mut k = 0;
            while k < a.len() {
                if a[k..].starts_with(b"{}") {
                    o.extend_from_slice(path);
                    k += 2;
                } else {
                    o.push(a[k]);
                    k += 1;
                }
            }
            o
        })
        .collect()
}

fn time_of(st: &fs::Stat, f: TimeField) -> (i64, i64) {
    match f {
        TimeField::A => (st.atime, st.atime_nsec),
        TimeField::C => (st.ctime, st.ctime_nsec),
        TimeField::M => (st.mtime, st.mtime_nsec),
    }
}

/// `-printf` directives.
fn printf(fmt: &[u8], e: &Entry<'_>, out: &mut Vec<u8>, names: &mut Names) {
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c == b'\\' && i < fmt.len() {
            let x = fmt[i];
            i += 1;
            match x {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'0' => out.push(0),
                b'\\' => out.push(b'\\'),
                b'a' => out.push(7),
                b'r' => out.push(b'\r'),
                other => {
                    out.push(b'\\');
                    out.push(other);
                }
            }
            continue;
        }
        if c != b'%' || i >= fmt.len() {
            out.push(c);
            continue;
        }
        // Flags and width.
        let spec_start = i;
        while i < fmt.len() && b"-+ #0".contains(&fmt[i]) {
            i += 1;
        }
        while i < fmt.len() && (fmt[i].is_ascii_digit() || fmt[i] == b'.') {
            i += 1;
        }
        if i >= fmt.len() {
            break;
        }
        let spec = &fmt[spec_start..i];
        let d = fmt[i];
        i += 1;
        let st = &e.st;
        let val: Vec<u8> = match d {
            b'%' => b"%".to_vec(),
            b'p' => e.path.to_vec(),
            b'f' => basename(e.path).to_vec(),
            b'h' => {
                let t = e.path.strip_suffix(b"/").unwrap_or(e.path);
                match t.iter().rposition(|&c| c == b'/') {
                    Some(0) => b"/".to_vec(),
                    Some(k) => t[..k].to_vec(),
                    None => b".".to_vec(),
                }
            }
            b'P' => {
                let rest = &e.path[e.start.len().min(e.path.len())..];
                rest.strip_prefix(b"/").unwrap_or(rest).to_vec()
            }
            b'H' => e.start.to_vec(),
            b's' => alloc::format!("{}", st.size).into_bytes(),
            b'm' => alloc::format!("{:o}", st.mode & 0o7777).into_bytes(),
            b'M' => crate::ls_mode(st.mode).to_vec(),
            b'u' => names.user(st.uid).unwrap_or_else(|| alloc::format!("{}", st.uid).into_bytes()),
            b'g' => names.group(st.gid).unwrap_or_else(|| alloc::format!("{}", st.gid).into_bytes()),
            b'U' => alloc::format!("{}", st.uid).into_bytes(),
            b'G' => alloc::format!("{}", st.gid).into_bytes(),
            b'd' => alloc::format!("{}", e.depth).into_bytes(),
            b'y' => alloc::vec![type_char(e.link.unwrap_or(*st).mode)],
            b'Y' => alloc::vec![type_char(if st.is_symlink() {
                fs::stat(e.path).map_or(st.mode, |s| s.mode)
            } else {
                st.mode
            })],
            b'l' => {
                if e.link.unwrap_or(*st).is_symlink() {
                    fs::readlink(e.path).unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            b'i' => alloc::format!("{}", st.ino).into_bytes(),
            b'n' => alloc::format!("{}", st.nlink).into_bytes(),
            b'k' => alloc::format!("{}", (st.blocks + 1) / 2).into_bytes(),
            b'b' => alloc::format!("{}", st.blocks).into_bytes(),
            b'D' => alloc::format!("{}", st.dev).into_bytes(),
            b'S' => {
                // Sparseness: allocated over apparent size (%g).
                let r = if st.size > 0 { (st.blocks as f64 * 512.0) / st.size as f64 } else { 1.0 };
                let e = alloc::format!("{r:.5e}");
                let (m, x) = e.split_once('e').unwrap_or((&e, "0"));
                let m = if m.contains('.') { m.trim_end_matches('0').trim_end_matches('.') } else { m };
                crate::od::format_g(r, &alloc::format!("{m}e{x}"), 6).into_bytes()
            }
            b'F' => names.fs_type(st.dev),
            b'a' | b'c' | b't' => {
                let (t, _) = time_of(
                    st,
                    match d {
                        b'a' => TimeField::A,
                        b'c' => TimeField::C,
                        _ => TimeField::M,
                    },
                );
                let mut s = String::new();
                slate_rt::time::format(&slate_rt::tz::localtime(t), "%a %b %e %H:%M:%S %Y", &mut s);
                s.into_bytes()
            }
            b'A' | b'C' | b'T' if i < fmt.len() => {
                let k = fmt[i];
                i += 1;
                let (t, ns) = time_of(
                    st,
                    match d {
                        b'A' => TimeField::A,
                        b'C' => TimeField::C,
                        _ => TimeField::M,
                    },
                );
                if k == b'@' {
                    alloc::format!("{t}.{ns:09}0").into_bytes()
                } else {
                    let mut s = String::new();
                    let f = alloc::format!("%{}", k as char);
                    slate_rt::time::format(&slate_rt::tz::localtime(t), &f, &mut s);
                    s.into_bytes()
                }
            }
            other => {
                out.push(b'%');
                out.push(other);
                continue;
            }
        };
        pad(spec, &val, out);
    }
}

/// Apply a printf-style flags/width/precision to a string.
fn pad(spec: &[u8], val: &[u8], out: &mut Vec<u8>) {
    let left = spec.contains(&b'-');
    let digits: Vec<u8> = spec.iter().copied().skip_while(|c| b"-+ #0".contains(c)).collect();
    let (w, prec) = match digits.iter().position(|&c| c == b'.') {
        Some(d) => (parse_num::<usize>(&digits[..d]).unwrap_or(0), parse_num::<usize>(&digits[d + 1..])),
        None => (parse_num::<usize>(&digits).unwrap_or(0), None),
    };
    let v = &val[..prec.unwrap_or(val.len()).min(val.len())];
    let fill = w.saturating_sub(v.len());
    if !left {
        out.resize(out.len() + fill, b' ');
    }
    out.extend_from_slice(v);
    if left {
        out.resize(out.len() + fill, b' ');
    }
}

/// `-ls`: like `ls -dils`.
fn ls_line(e: &Entry<'_>, out: &mut Vec<u8>, names: &mut Names) {
    let st = &e.st;
    let user = names.user(st.uid).unwrap_or_else(|| alloc::format!("{}", st.uid).into_bytes());
    let group = names.group(st.gid).unwrap_or_else(|| alloc::format!("{}", st.gid).into_bytes());
    let tm = slate_rt::tz::localtime(st.mtime);
    let mut when = String::new();
    let now = slate_rt::time::unix();
    let fmt = if st.mtime > now - 182 * 86400 && st.mtime <= now + 3600 { "%b %e %H:%M" } else { "%b %e  %Y" };
    slate_rt::time::format(&tm, fmt, &mut when);
    let size = if matches!(st.mode & fs::S_IFMT, fs::S_IFCHR | fs::S_IFBLK) {
        alloc::format!("{:>3}, {:>3}", (st.rdev >> 8) & 0xfff, (st.rdev & 0xff) | ((st.rdev >> 12) & 0xfff00))
    } else {
        alloc::format!("{:>8}", st.size)
    };
    out.extend_from_slice(
        alloc::format!(
            "{:>6} {:>4} {} {:>3} {:<8} {:<8} {size} {when} ",
            st.ino,
            (st.blocks + 1) / 2,
            lossy(&crate::ls_mode(st.mode)),
            st.nlink,
            lossy(&user),
            lossy(&group)
        )
        .as_bytes(),
    );
    out.extend_from_slice(e.path);
    if st.is_symlink()
        && let Ok(t) = fs::readlink(e.path)
    {
        out.extend_from_slice(b" -> ");
        out.extend_from_slice(&t);
    }
    out.push(b'\n');
}

impl Expr {
    fn eval(&mut self, e: &mut Entry<'_>, ctx: &mut Ctx) -> bool {
        let st = e.st;
        match self {
            Expr::And(a, b) => a.eval(e, ctx) && !ctx.quit && b.eval(e, ctx),
            Expr::Or(a, b) => a.eval(e, ctx) || (!ctx.quit && b.eval(e, ctx)),
            Expr::Not(a) => !a.eval(e, ctx),
            Expr::List(a, b) => {
                a.eval(e, ctx);
                b.eval(e, ctx)
            }
            Expr::True => true,
            Expr::False => false,
            Expr::Name(p, i) => fnmatch_with(p, basename(e.path), Flags { casefold: *i, ..Flags::default() }),
            Expr::Path(p, i) => fnmatch_with(p, e.path, Flags { casefold: *i, ..Flags::default() }),
            Expr::LinkName(p, i) => {
                e.link.unwrap_or(st).is_symlink()
                    && fs::readlink(e.path)
                        .is_ok_and(|t| fnmatch_with(p, &t, Flags { casefold: *i, ..Flags::default() }))
            }
            Expr::Regex(r) => r.is_match(e.path),
            Expr::Type(ts, x) => {
                let m = if !*x {
                    st.mode
                } else {
                    // -xtype: the other side of a symlink.
                    match e.link {
                        Some(l) => l.mode,
                        None if st.is_symlink() => fs::stat(e.path).map_or(st.mode, |s| s.mode),
                        None => st.mode,
                    }
                };
                ts.contains(&type_char(m))
            }
            Expr::Size(c, n, unit) => {
                let units = (st.size as u64).div_ceil(*unit);
                cmp(*c, units as i64, *n)
            }
            Expr::Empty => {
                if st.is_dir() {
                    fs::read_dir(e.path).is_ok_and(|d| d.is_empty())
                } else {
                    st.is_file() && st.size == 0
                }
            }
            Expr::Perm(m, kind) => {
                let p = st.mode & 0o7777;
                match kind {
                    b'-' => p & *m == *m,
                    b'/' => *m == 0 || p & *m != 0,
                    _ => p == *m,
                }
            }
            Expr::Uid(c, n) => cmp(*c, st.uid as i64, *n),
            Expr::Gid(c, n) => cmp(*c, st.gid as i64, *n),
            Expr::NoUser => ctx.names.user(st.uid).is_none(),
            Expr::NoGroup => ctx.names.group(st.gid).is_none(),
            Expr::Links(c, n) => cmp(*c, st.nlink as i64, *n),
            Expr::Inum(c, n) => cmp(*c, st.ino as i64, *n),
            Expr::Time(f, c, n, unit) => {
                let (t, _) = time_of(&st, *f);
                // The age in whole units, fractions dropped.
                cmp(*c, (ctx.now - t).div_euclid(*unit), *n)
            }
            Expr::Newer(f, s, ns) => {
                let (t, tn) = time_of(&st, *f);
                (t, tn) > (*s, *ns)
            }
            Expr::SameFile(dev, ino) => st.dev == *dev && st.ino == *ino,
            Expr::Access(m) => fs::access(e.path, *m).is_ok(),
            Expr::Print(term, file) => {
                let out = ctx.sink(*file);
                out.extend_from_slice(e.path);
                out.push(*term);
                true
            }
            Expr::Printf(f, file) => {
                let mut v = Vec::new();
                printf(f, e, &mut v, &mut ctx.names);
                ctx.sink(*file).extend_from_slice(&v);
                true
            }
            Expr::Ls(file) => {
                let mut v = Vec::new();
                ls_line(e, &mut v, &mut ctx.names);
                ctx.sink(*file).extend_from_slice(&v);
                true
            }
            Expr::Exec { cmd, batch, dir, ask, pending } => {
                let (target, cwd): (Vec<u8>, Option<Vec<u8>>) = if *dir {
                    let b = basename(e.path);
                    let d = {
                        let t = e.path.strip_suffix(b"/").unwrap_or(e.path);
                        match t.iter().rposition(|&c| c == b'/') {
                            Some(0) => b"/".to_vec(),
                            Some(k) => t[..k].to_vec(),
                            None => b".".to_vec(),
                        }
                    };
                    ([b"./".as_slice(), b].concat(), Some(d))
                } else {
                    (e.path.to_vec(), None)
                };
                if *batch {
                    pending.push(target);
                    if pending.len() >= 1000 {
                        flush_batch(cmd, pending, ctx);
                    }
                    return true;
                }
                io::out(&ctx.out);
                ctx.out.clear();
                let argv = substitute(cmd, &target);
                if *ask && !confirm(&argv) {
                    return false;
                }
                run(&argv, cwd.as_deref())
            }
            Expr::Delete => {
                let r = if st.is_dir() && e.link.is_none() { fs::rmdir(e.path) } else { fs::unlink(e.path) };
                if let Err(err) = r {
                    error(alloc::format!("cannot delete '{}': {err}", lossy(e.path)));
                    ctx.status = 1;
                    return false;
                }
                true
            }
            Expr::Prune => {
                e.prune = true;
                true
            }
            Expr::Quit => {
                ctx.quit = true;
                true
            }
        }
    }

    /// Run outstanding `-exec ... +` batches.
    fn finish(&mut self, ctx: &mut Ctx) {
        match self {
            Expr::And(a, b) | Expr::Or(a, b) | Expr::List(a, b) => {
                a.finish(ctx);
                b.finish(ctx);
            }
            Expr::Not(a) => a.finish(ctx),
            Expr::Exec { cmd, batch: true, pending, .. } => flush_batch(cmd, pending, ctx),
            _ => {}
        }
    }
}

impl Ctx {
    /// Where an output action writes.
    fn sink(&mut self, file: Option<usize>) -> &mut Vec<u8> {
        match file {
            Some(i) => &mut self.files[i].1,
            None => &mut self.out,
        }
    }

    /// Write out what the `-fprint*` files hold.
    fn flush_files(&mut self) {
        for (fd, buf) in &mut self.files {
            if !buf.is_empty() {
                if *fd == io::STDOUT {
                    io::out(&self.out);
                    self.out.clear();
                }
                let _ = io::write_all(*fd, buf);
                buf.clear();
            }
        }
    }
}

fn flush_batch(cmd: &[Vec<u8>], pending: &mut Vec<Vec<u8>>, ctx: &mut Ctx) {
    if pending.is_empty() {
        return;
    }
    io::out(&ctx.out);
    ctx.out.clear();
    let mut argv = cmd.to_vec();
    argv.append(pending);
    if !run(&argv, None) {
        ctx.status = 1;
    }
}

fn walk(
    path: &[u8],
    start: &[u8],
    depth: usize,
    expr: &mut Expr,
    ctx: &mut Ctx,
    root_dev: u64,
    ancestors: &mut Vec<(u64, u64)>,
) {
    if ctx.quit {
        return;
    }
    let follow = ctx.follow == Follow::Always || (ctx.follow == Follow::CommandLine && depth == 0);
    let lst = match fs::lstat(path) {
        Ok(s) => s,
        Err(e) => {
            error(alloc::format!("'{}': {e}", lossy(path)));
            ctx.status = 1;
            return;
        }
    };
    let (st, link) = if follow && lst.is_symlink() {
        match fs::stat(path) {
            Ok(s) => (s, Some(lst)),
            // A dangling link stays a link.
            Err(_) => (lst, None),
        }
    } else {
        (lst, None)
    };
    let mut entry = Entry { path, start, depth, st, link, prune: false };
    let in_range = depth >= ctx.mindepth;
    if !ctx.depth_first && in_range {
        expr.eval(&mut entry, ctx);
        if ctx.out.len() > 32 * 1024 {
            io::out(&ctx.out);
            ctx.out.clear();
        }
        if ctx.files.iter().any(|f| f.1.len() > 32 * 1024) {
            ctx.flush_files();
        }
    }
    let descend = st.is_dir()
        && !entry.prune
        && ctx.maxdepth.is_none_or(|m| depth < m)
        && !(ctx.xdev && depth > 0 && st.dev != root_dev);
    if descend {
        if ancestors.contains(&(st.dev, st.ino)) {
            error(alloc::format!("File system loop detected; '{}' is part of the same file system loop.", lossy(path)));
            ctx.status = 1;
        } else {
            match fs::read_dir(path) {
                Ok(entries) => {
                    ancestors.push((st.dev, st.ino));
                    for d in entries {
                        if ctx.quit {
                            break;
                        }
                        let child = fs::join(path, &d.name);
                        walk(&child, start, depth + 1, expr, ctx, root_dev, ancestors);
                    }
                    ancestors.pop();
                }
                Err(e) => {
                    error(alloc::format!("'{}': {e}", lossy(path)));
                    ctx.status = 1;
                }
            }
        }
    }
    if ctx.depth_first && in_range && !ctx.quit {
        let mut entry = Entry { path, start, depth, st, link, prune: false };
        expr.eval(&mut entry, ctx);
    }
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut ctx = Ctx {
        now: slate_rt::time::unix(),
        maxdepth: None,
        mindepth: 0,
        depth_first: false,
        xdev: false,
        follow: Follow::Never,
        status: 0,
        quit: false,
        out: Vec::new(),
        files: Vec::new(),
        names: Names::default(),
    };
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_slice() {
            b"-H" => ctx.follow = Follow::CommandLine,
            b"-L" => ctx.follow = Follow::Always,
            b"-P" => ctx.follow = Follow::Never,
            b"--" => {
                i += 1;
                break;
            }
            _ => break,
        }
        i += 1;
    }
    let mut paths = Vec::new();
    while let Some(a) = args.get(i) {
        if (a.starts_with(b"-") && a.len() > 1) || a == b"(" || a == b"!" {
            break;
        }
        paths.push(a.clone());
        i += 1;
    }
    if paths.is_empty() {
        paths.push(b".".to_vec());
    }
    let rest = &args[i..];
    let (mut expr, has_action) = if rest.is_empty() {
        (Expr::True, false)
    } else {
        let mut p = P { a: rest, i: 0, ctx: &mut ctx, has_action: false, regextype: Syntax::Basic, emacs: true };
        let e = match p.or() {
            Ok(e) => e,
            Err(m) => {
                error(m);
                return 1;
            }
        };
        if p.i < rest.len() {
            error(alloc::format!("unexpected `{}'", lossy(&rest[p.i])));
            return 1;
        }
        (e, p.has_action)
    };
    if !has_action {
        expr = Expr::And(Box::new(expr), Box::new(Expr::Print(b'\n', None)));
    }
    for p in &paths {
        if ctx.quit {
            break;
        }
        let root_dev = fs::stat(p).map_or(0, |s| s.dev);
        let mut ancestors = Vec::new();
        walk(p, p, 0, &mut expr, &mut ctx, root_dev, &mut ancestors);
    }
    expr.finish(&mut ctx);
    io::out(&ctx.out);
    ctx.out.clear();
    ctx.flush_files();
    for (fd, _) in &ctx.files {
        if *fd > 2 {
            let _ = io::close(*fd);
        }
    }
    ctx.status
}
