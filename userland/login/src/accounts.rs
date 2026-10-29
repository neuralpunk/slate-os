// SPDX-License-Identifier: MIT OR Apache-2.0

//! Account administration (ADR 0057): the passwd(5), group(5),
//! shadow(5) and gshadow(5) records as data, written atomically under /etc/.pwd.lock;
//! password ageing (shadow(5)'s fields, as login, su, the login screen
//! and sshd enforce them); and the tools: useradd, usermod, userdel,
//! groupadd, groupmod, groupdel, gpasswd, chpasswd, chage and chsh.
//! Their options and exit statuses are the ones those tools' manual
//! pages document.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_coreutils::crypt;
use slate_rt::{Errno, fs, io, lossy, println, process};

use crate::db;

pub const LOCK: &[u8] = b"/etc/.pwd.lock";
const LOGIN_DEFS: &[u8] = b"/etc/login.defs";
const USERADD_DEFAULTS: &[u8] = b"/etc/default/useradd";
const SHELLS: &[u8] = b"/etc/shells";

// --- records ------------------------------------------------------------------------

fn split(line: &[u8]) -> Vec<Vec<u8>> {
    line.split(|&c| c == b':').map(<[u8]>::to_vec).collect()
}

fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split(|&c| c == b'\n').filter(|l| !l.is_empty())
}

/// A passwd(5) line, kept as its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pw(pub Vec<Vec<u8>>);

impl Pw {
    pub fn name(&self) -> &[u8] {
        &self.0[0]
    }
    pub fn uid(&self) -> Option<u32> {
        num(&self.0[2])
    }
    pub fn gid(&self) -> Option<u32> {
        num(&self.0[3])
    }
}

/// A group(5) line: name, password, GID, members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gr(pub Vec<Vec<u8>>);

impl Gr {
    pub fn name(&self) -> &[u8] {
        &self.0[0]
    }
    pub fn gid(&self) -> Option<u32> {
        num(&self.0[2])
    }
    pub fn members(&self) -> Vec<Vec<u8>> {
        self.0[3].split(|&c| c == b',').filter(|m| !m.is_empty()).map(<[u8]>::to_vec).collect()
    }
    pub fn set_members(&mut self, m: &[Vec<u8>]) {
        self.0[3] = m.join(&b',');
    }
}

/// A shadow(5) line: name, hash, last change, min, max, warn, inactive,
/// expire, reserved. Empty numeric fields mean "not set".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sp(pub Vec<Vec<u8>>);

impl Sp {
    pub fn new(name: &[u8], hash: &[u8], d: &Defs) -> Sp {
        let n = |v: Option<i64>| v.map(|x| format!("{x}").into_bytes()).unwrap_or_default();
        Sp(alloc::vec![
            name.to_vec(),
            hash.to_vec(),
            format!("{}", db::today()).into_bytes(),
            n(Some(d.pass_min)),
            n(Some(d.pass_max)),
            n(Some(d.pass_warn)),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        ])
    }
    pub fn name(&self) -> &[u8] {
        &self.0[0]
    }
    pub fn field(&self, i: usize) -> Option<i64> {
        self.0.get(i).and_then(|f| core::str::from_utf8(f).ok()?.parse().ok())
    }
    pub fn set(&mut self, i: usize, v: Option<i64>) {
        self.0.resize(self.0.len().max(9), Vec::new());
        self.0[i] = v.map(|x| format!("{x}").into_bytes()).unwrap_or_default();
    }
}

fn num(b: &[u8]) -> Option<u32> {
    core::str::from_utf8(b).ok()?.parse().ok()
}

fn parse<T>(data: &[u8], min_fields: usize, f: fn(Vec<Vec<u8>>) -> T) -> Vec<T> {
    lines(data)
        .map(split)
        .filter(|v| v.len() >= min_fields)
        .map(|mut v| {
            v.resize(v.len().max(min_fields), Vec::new());
            f(v)
        })
        .collect()
}

/// The databases, read under the lock and written back together.
#[derive(Debug)]
pub struct Db {
    pub passwd: Vec<Pw>,
    pub group: Vec<Gr>,
    pub shadow: Vec<Sp>,
    /// gshadow(5) lines: name, password, administrators, members. The
    /// file is written only if it was there or now has a line (ADR 0119).
    pub gshadow: Vec<Vec<Vec<u8>>>,
    had_gshadow: bool,
    lock: i32,
}

impl Db {
    /// Read everything, holding /etc/.pwd.lock until dropped.
    pub fn open() -> Result<Db, String> {
        let lock = fs::open(LOCK, fs::O_RDWR | fs::O_CREAT | fs::O_CLOEXEC, 0o600)
            .map_err(|e| format!("cannot lock /etc/passwd: {e}"))?;
        fs::flock(lock, fs::LOCK_EX).map_err(|e| format!("cannot lock /etc/passwd: {e}"))?;
        let read = |p: &[u8]| fs::read_file(p).unwrap_or_default();
        let gshadow = fs::read_file(db::GSHADOW);
        let had_gshadow = gshadow.is_ok();
        Ok(Db {
            gshadow: parse(&gshadow.unwrap_or_default(), 4, |v| v),
            had_gshadow,
            passwd: parse(&read(db::PASSWD), 7, Pw),
            group: parse(&read(db::GROUP), 4, Gr),
            shadow: parse(&read(db::SHADOW), 2, |mut v| {
                v.resize(9, Vec::new());
                Sp(v)
            }),
            lock,
        })
    }

    pub fn user(&self, name: &[u8]) -> Option<usize> {
        self.passwd.iter().position(|p| p.name() == name)
    }
    pub fn group_named(&self, name: &[u8]) -> Option<usize> {
        self.group.iter().position(|g| g.name() == name)
    }
    pub fn group_by(&self, spec: &[u8]) -> Option<usize> {
        self.group_named(spec).or_else(|| {
            let id = num(spec)?;
            self.group.iter().position(|g| g.gid() == Some(id))
        })
    }
    /// The group's gshadow line, made (no password) if it has none.
    pub fn gshadow_of(&mut self, name: &[u8]) -> &mut Vec<Vec<u8>> {
        let i = match self.gshadow.iter().position(|g| g[0] == name) {
            Some(i) => i,
            None => {
                self.gshadow.push(alloc::vec![name.to_vec(), b"!".to_vec(), Vec::new(), Vec::new()]);
                self.gshadow.len() - 1
            }
        };
        &mut self.gshadow[i]
    }

    pub fn shadow_of(&mut self, name: &[u8]) -> &mut Sp {
        if let Some(i) = self.shadow.iter().position(|s| s.name() == name) {
            return &mut self.shadow[i];
        }
        self.shadow.push(Sp(alloc::vec![
            name.to_vec(),
            b"!".to_vec(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new()
        ]));
        let last = self.shadow.len() - 1;
        &mut self.shadow[last]
    }

    /// Write the files back: each to a new file renamed over the old one.
    pub fn save(&self) -> Result<(), String> {
        fn write(path: &[u8], rows: &[Vec<u8>], mode: u32) -> Result<(), Errno> {
            let mut out = Vec::new();
            for r in rows {
                out.extend_from_slice(r);
                out.push(b'\n');
            }
            let tmp = [path, b"+"].concat();
            fs::write_file(&tmp, &out, mode)?;
            let r = fs::chmod(&tmp, mode).and_then(|()| fs::rename(&tmp, path));
            if r.is_err() {
                let _ = fs::unlink(&tmp);
            }
            r
        }
        let join = |v: &Vec<Vec<u8>>| v.join(&b':');
        write(db::PASSWD, &self.passwd.iter().map(|p| join(&p.0)).collect::<Vec<_>>(), 0o644)
            .and_then(|()| write(db::GROUP, &self.group.iter().map(|g| join(&g.0)).collect::<Vec<_>>(), 0o644))
            .and_then(|()| write(db::SHADOW, &self.shadow.iter().map(|s| join(&s.0)).collect::<Vec<_>>(), 0o600))
            .and_then(|()| {
                if self.had_gshadow || !self.gshadow.is_empty() {
                    write(db::GSHADOW, &self.gshadow.iter().map(join).collect::<Vec<_>>(), 0o600)
                } else {
                    Ok(())
                }
            })
            .map_err(|e| format!("cannot update the account files: {e}"))
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = io::close(self.lock);
    }
}

// --- defaults ------------------------------------------------------------------------

/// The settings from /etc/login.defs and /etc/default/useradd that the
/// tools use, with shadow-utils' documented defaults.
#[derive(Clone, Debug)]
pub struct Defs {
    pub uid_min: u32,
    pub uid_max: u32,
    pub sys_uid_min: u32,
    pub sys_uid_max: u32,
    pub gid_min: u32,
    pub gid_max: u32,
    pub sys_gid_min: u32,
    pub sys_gid_max: u32,
    pub pass_min: i64,
    pub pass_max: i64,
    pub pass_warn: i64,
    pub create_home: bool,
    pub usergroups: bool,
    pub home: Vec<u8>,
    pub shell: Vec<u8>,
    pub skel: Vec<u8>,
    pub group: u32,
    pub inactive: Option<i64>,
    pub expire: Option<i64>,
    /// useradd makes an empty mail spool in `mail_dir` (login.defs(5)'s
    /// MAIL_DIR, useradd(8)'s CREATE_MAIL_SPOOL).
    pub mail_spool: bool,
    pub mail_dir: Vec<u8>,
}

impl Defs {
    pub fn load() -> Defs {
        Defs::parse(
            &fs::read_file(LOGIN_DEFS).unwrap_or_default(),
            &fs::read_file(USERADD_DEFAULTS).unwrap_or_default(),
        )
    }

    pub fn parse(login_defs: &[u8], useradd: &[u8]) -> Defs {
        let mut d = Defs {
            uid_min: 1000,
            uid_max: 60000,
            sys_uid_min: 101,
            sys_uid_max: 999,
            gid_min: 1000,
            gid_max: 60000,
            sys_gid_min: 101,
            sys_gid_max: 999,
            pass_min: 0,
            pass_max: 99999,
            pass_warn: 7,
            create_home: true,
            usergroups: true,
            home: b"/home".to_vec(),
            shell: b"/bin/sh".to_vec(),
            skel: b"/etc/skel".to_vec(),
            group: 100,
            inactive: None,
            expire: None,
            mail_spool: false,
            mail_dir: b"/var/spool/mail".to_vec(),
        };
        for l in login_defs.split(|&c| c == b'\n') {
            let w: Vec<&[u8]> = l.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).collect();
            let [k, v, ..] = w[..] else { continue };
            if k.starts_with(b"#") {
                continue;
            }
            let n = || num(v);
            let yes = v.eq_ignore_ascii_case(b"yes");
            match k {
                b"UID_MIN" => d.uid_min = n().unwrap_or(d.uid_min),
                b"UID_MAX" => d.uid_max = n().unwrap_or(d.uid_max),
                b"SYS_UID_MIN" => d.sys_uid_min = n().unwrap_or(d.sys_uid_min),
                b"SYS_UID_MAX" => d.sys_uid_max = n().unwrap_or(d.sys_uid_max),
                b"GID_MIN" => d.gid_min = n().unwrap_or(d.gid_min),
                b"GID_MAX" => d.gid_max = n().unwrap_or(d.gid_max),
                b"SYS_GID_MIN" => d.sys_gid_min = n().unwrap_or(d.sys_gid_min),
                b"SYS_GID_MAX" => d.sys_gid_max = n().unwrap_or(d.sys_gid_max),
                b"PASS_MIN_DAYS" => d.pass_min = n().map_or(d.pass_min, i64::from),
                b"PASS_MAX_DAYS" => d.pass_max = n().map_or(d.pass_max, i64::from),
                b"PASS_WARN_AGE" => d.pass_warn = n().map_or(d.pass_warn, i64::from),
                b"CREATE_HOME" => d.create_home = yes,
                b"USERGROUPS_ENAB" => d.usergroups = yes,
                b"MAIL_DIR" => d.mail_dir = v.to_vec(),
                _ => {}
            }
        }
        for l in useradd.split(|&c| c == b'\n') {
            let Some(eq) = l.iter().position(|&c| c == b'=') else { continue };
            let (k, v) = (&l[..eq], &l[eq + 1..]);
            match k {
                b"HOME" => d.home = v.to_vec(),
                b"SHELL" => d.shell = v.to_vec(),
                b"SKEL" => d.skel = v.to_vec(),
                b"GROUP" => d.group = num(v).unwrap_or(d.group),
                b"INACTIVE" => {
                    d.inactive = core::str::from_utf8(v).ok().and_then(|s| s.parse().ok()).filter(|&x: &i64| x >= 0)
                }
                b"EXPIRE" => d.expire = parse_day(v),
                b"CREATE_MAIL_SPOOL" => d.mail_spool = v.eq_ignore_ascii_case(b"yes"),
                _ => {}
            }
        }
        d
    }
}

/// A day as shadow(5) counts them (days since 1970-01-01) from
/// `YYYY-MM-DD` or a plain number; `-1` and empty mean none.
pub fn parse_day(v: &[u8]) -> Option<i64> {
    let s = core::str::from_utf8(v).ok()?.trim();
    if s.is_empty() || s == "-1" {
        return None;
    }
    if let Ok(n) = s.parse::<i64>() {
        return Some(n);
    }
    let mut it = s.split('-');
    let (y, m, d) = (it.next()?.parse().ok()?, it.next()?.parse().ok()?, it.next()?.parse().ok()?);
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(slate_rt::time::civil_to_days(y, m, d))
}

/// `passwd -S`'s line (passwd(1)): the name; L (locked), NP (no
/// password) or P; the last change as YYYY-MM-DD (or `never`); the
/// minimum and maximum ages, the warning and the inactivity period in
/// days (-1 when unset).
pub fn status_line(name: &[u8], sp: Option<&Sp>) -> String {
    let hash = sp.and_then(|s| s.0.get(1)).map_or(&[][..], Vec::as_slice);
    let state = if hash.is_empty() {
        "NP"
    } else if hash.starts_with(b"!") || hash.starts_with(b"*") {
        "L"
    } else {
        "P"
    };
    let field = |i| sp.and_then(|s| s.field(i));
    let changed = match field(2) {
        Some(d) => {
            let mut s = String::new();
            slate_rt::time::format(&slate_rt::time::gmtime(d * 86_400), "%Y-%m-%d", &mut s);
            s
        }
        None => String::from("never"),
    };
    let n = |i| field(i).unwrap_or(-1);
    format!("{} {state} {changed} {} {} {} {}", lossy(name), n(3), n(4), n(5), n(6))
}

fn day_string(d: i64) -> String {
    let tm = slate_rt::time::gmtime(d * 86_400);
    let mut s = String::new();
    slate_rt::time::format(&tm, "%b %d, %Y", &mut s);
    s
}

// --- password ageing -----------------------------------------------------------------

/// What an account's shadow entry says about logging in today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ageing {
    Ok,
    /// The password expires in this many days.
    Warn(i64),
    /// The password must be changed before going on (expired, or reset
    /// with `passwd -e`).
    MustChange,
    /// No login at all (account expired, or inactive too long).
    Refused(&'static str),
}

/// Ageing for `name` on day `today` (shadow(5)).
pub fn ageing_of(sp: Option<&Sp>, today: i64) -> Ageing {
    let Some(sp) = sp else { return Ageing::Ok };
    if sp.field(7).is_some_and(|e| today >= e) {
        return Ageing::Refused("Your account has expired; please contact your system administrator.");
    }
    let last = sp.field(2);
    if last == Some(0) {
        return Ageing::MustChange;
    }
    let (Some(last), Some(max)) = (last, sp.field(4)) else { return Ageing::Ok };
    if max >= 99999 {
        return Ageing::Ok;
    }
    let expires = last + max;
    if today > expires {
        if sp.field(6).is_some_and(|inactive| today > expires + inactive) {
            return Ageing::Refused("Your account has expired; please contact your system administrator.");
        }
        return Ageing::MustChange;
    }
    match sp.field(5) {
        Some(warn) if expires - today <= warn => Ageing::Warn(expires - today),
        _ => Ageing::Ok,
    }
}

/// Ageing for the account called `name` today, from /etc/shadow.
pub fn ageing(name: &[u8]) -> Ageing {
    let data = fs::read_file(db::SHADOW).unwrap_or_default();
    let sp = parse(&data, 2, |mut v| {
        v.resize(9, Vec::new());
        Sp(v)
    })
    .into_iter()
    .find(|s| s.name() == name);
    ageing_of(sp.as_ref(), db::today() as i64)
}

/// A new hash for `password`.
pub fn hash(password: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 12];
    process::random(&mut salt).map_err(|e| format!("random numbers: {e}"))?;
    crypt::crypt(password, crypt::new_salt(&salt).as_bytes())
        .map(String::into_bytes)
        .ok_or_else(|| String::from("hashing failed"))
}

// --- the tools ------------------------------------------------------------------------

fn prog() -> String {
    String::from(lossy(slate_rt::prog_name().as_bytes()))
}

fn fail(code: i32, msg: impl core::fmt::Display) -> i32 {
    slate_rt::eprintln!("{}: {msg}", prog());
    code
}

fn need_root() -> Option<i32> {
    (process::getuid() != 0).then(|| fail(1, "Permission denied."))
}

/// A user or group name as shadow-utils accepts it: a letter or `_`
/// first, then letters, digits, `_`, `-` and `.`, an optional final `$`;
/// at most 32 bytes.
pub fn valid_name(n: &[u8]) -> bool {
    let body = n.strip_suffix(b"$").unwrap_or(n);
    !body.is_empty()
        && n.len() <= 32
        && (body[0].is_ascii_lowercase() || body[0] == b'_')
        && body.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.'))
}

/// Parsed options (letter, value) and operands.
type Parsed = (Vec<(u8, Vec<u8>)>, Vec<Vec<u8>>);

/// Options of the form `-x VALUE`, `--long VALUE`, `--long=VALUE`, and
/// bundled flags; returns (options, operands).
fn options(args: &[Vec<u8>], with_value: &[u8], long: &[(&str, u8)]) -> Result<Parsed, i32> {
    let mut opts = Vec::new();
    let mut ops = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if a == b"--" {
            ops.extend(args[i..].iter().cloned());
            break;
        }
        if let Some(l) = a.strip_prefix(b"--") {
            let (k, v) = match l.iter().position(|&c| c == b'=') {
                Some(e) => (&l[..e], Some(l[e + 1..].to_vec())),
                None => (l, None),
            };
            let Some(&(_, c)) = long.iter().find(|(n, _)| n.as_bytes() == k) else {
                return Err(fail(2, format!("unrecognized option '--{}'", lossy(k))));
            };
            let v = if with_value.contains(&c) {
                match v.or_else(|| {
                    i += 1;
                    args.get(i - 1).cloned()
                }) {
                    Some(v) => v,
                    None => return Err(fail(2, format!("option '--{}' requires an argument", lossy(k)))),
                }
            } else {
                Vec::new()
            };
            opts.push((c, v));
            continue;
        }
        if a.len() > 1 && a[0] == b'-' {
            let mut j = 1;
            while j < a.len() {
                let c = a[j];
                j += 1;
                if with_value.contains(&c) {
                    let v = if j < a.len() {
                        a[j..].to_vec()
                    } else {
                        i += 1;
                        match args.get(i - 1) {
                            Some(v) => v.clone(),
                            None => return Err(fail(2, format!("option requires an argument -- '{}'", c as char))),
                        }
                    };
                    opts.push((c, v));
                    break;
                }
                opts.push((c, Vec::new()));
            }
            continue;
        }
        ops.push(a.clone());
    }
    Ok((opts, ops))
}

/// The first free ID in `lo..=hi` (upwards), or from the top for system
/// accounts, as useradd(8) picks them.
fn free_id(taken: &[u32], lo: u32, hi: u32, from_top: bool) -> Option<u32> {
    if from_top { (lo..=hi).rev().find(|i| !taken.contains(i)) } else { (lo..=hi).find(|i| !taken.contains(i)) }
}

fn copy_skel(from: &[u8], to: &[u8], uid: u32, gid: u32) {
    let Ok(entries) = fs::read_dir(from) else { return };
    for e in entries {
        let (src, dst) = (fs::join(from, &e.name), fs::join(to, &e.name));
        let Ok(st) = fs::lstat(&src) else { continue };
        if st.is_dir() {
            let _ = fs::mkdir(&dst, st.mode & 0o7777);
            copy_skel(&src, &dst, uid, gid);
        } else if st.is_symlink() {
            if let Ok(t) = fs::readlink(&src) {
                let _ = fs::symlink(&t, &dst);
            }
        } else if let Ok(data) = fs::read_file(&src) {
            let _ = fs::write_file(&dst, &data, st.mode & 0o7777);
        }
        let _ = fs::lchown(&dst, uid, gid);
    }
}

fn remove_tree(path: &[u8]) {
    if let Ok(st) = fs::lstat(path) {
        if st.is_dir() {
            for e in fs::read_dir(path).unwrap_or_default() {
                remove_tree(&fs::join(path, &e.name));
            }
            let _ = fs::rmdir(path);
        } else {
            let _ = fs::unlink(path);
        }
    }
}

fn chown_tree(path: &[u8], uid: u32, gid: u32) {
    let _ = fs::lchown(path, uid, gid);
    if fs::lstat(path).is_ok_and(|s| s.is_dir()) {
        for e in fs::read_dir(path).unwrap_or_default() {
            chown_tree(&fs::join(path, &e.name), uid, gid);
        }
    }
}

const USERADD_LONG: &[(&str, u8)] = &[
    ("comment", b'c'),
    ("home-dir", b'd'),
    ("expiredate", b'e'),
    ("inactive", b'f'),
    ("gid", b'g'),
    ("groups", b'G'),
    ("skel", b'k'),
    ("create-home", b'm'),
    ("no-create-home", b'M'),
    ("no-user-group", b'N'),
    ("non-unique", b'o'),
    ("password", b'p'),
    ("system", b'r'),
    ("shell", b's'),
    ("uid", b'u'),
    ("user-group", b'U'),
    ("defaults", b'D'),
];

pub fn useradd_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, ops) = match options(args, b"cdefgGkpsu", USERADD_LONG) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let d = Defs::load();
    if opts.iter().any(|(c, _)| *c == b'D') {
        println!("GROUP={}", d.group);
        println!("HOME={}", lossy(&d.home));
        println!("INACTIVE={}", d.inactive.unwrap_or(-1));
        println!("EXPIRE=");
        println!("SHELL={}", lossy(&d.shell));
        println!("SKEL={}", lossy(&d.skel));
        println!("CREATE_MAIL_SPOOL={}", if d.mail_spool { "yes" } else { "no" });
        io::flush_stdout();
        return 0;
    }
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: useradd [options] LOGIN") };
    if !valid_name(name) {
        return fail(3, format!("invalid user name '{}'", lossy(name)));
    }
    let get = |c: u8| opts.iter().rev().find(|(o, _)| *o == c).map(|(_, v)| v.clone());
    let has = |c: u8| opts.iter().any(|(o, _)| *o == c);
    let system = has(b'r');
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    if db.user(name).is_some() {
        return fail(9, format!("user '{}' already exists", lossy(name)));
    }
    let taken_uids: Vec<u32> = db.passwd.iter().filter_map(Pw::uid).collect();
    let uid = match get(b'u') {
        Some(v) => match num(&v) {
            Some(u) if has(b'o') || !taken_uids.contains(&u) => u,
            Some(_) => return fail(4, format!("UID {} is not unique", lossy(&v))),
            None => return fail(3, format!("invalid user ID '{}'", lossy(&v))),
        },
        None => {
            let (lo, hi) = if system { (d.sys_uid_min, d.sys_uid_max) } else { (d.uid_min, d.uid_max) };
            match free_id(&taken_uids, lo, hi, system) {
                Some(u) => u,
                None => return fail(4, "can't get unique UID (no more available UIDs)"),
            }
        }
    };
    // The primary group: -g, or a group of the user's own, or the default.
    let user_group = !has(b'N') && (has(b'U') || (d.usergroups && get(b'g').is_none()));
    let gid = if let Some(g) = get(b'g') {
        match db.group_by(&g).and_then(|i| db.group[i].gid()) {
            Some(gid) => gid,
            None => return fail(6, format!("group '{}' does not exist", lossy(&g))),
        }
    } else if user_group {
        if db.group_named(name).is_some() {
            return fail(
                9,
                format!("group {} exists - if you want to add this user to that group, use -g.", lossy(name)),
            );
        }
        let taken: Vec<u32> = db.group.iter().filter_map(Gr::gid).collect();
        let gid = if !taken.contains(&uid) {
            uid
        } else {
            let (lo, hi) = if system { (d.sys_gid_min, d.sys_gid_max) } else { (d.gid_min, d.gid_max) };
            match free_id(&taken, lo, hi, system) {
                Some(g) => g,
                None => return fail(4, "can't get unique GID (no more available GIDs)"),
            }
        };
        db.group.push(Gr(alloc::vec![name.clone(), b"x".to_vec(), format!("{gid}").into_bytes(), Vec::new()]));
        gid
    } else {
        d.group
    };
    let mut supplementary = Vec::new();
    if let Some(gs) = get(b'G') {
        for g in gs.split(|&c| c == b',').filter(|g| !g.is_empty()) {
            match db.group_by(g) {
                Some(i) => supplementary.push(i),
                None => return fail(6, format!("group '{}' does not exist", lossy(g))),
            }
        }
    }
    for i in supplementary {
        let mut m = db.group[i].members();
        if !m.contains(name) {
            m.push(name.clone());
            db.group[i].set_members(&m);
        }
    }
    let home = get(b'd').unwrap_or_else(|| fs::join(&d.home, name));
    let shell = get(b's').unwrap_or_else(|| d.shell.clone());
    let comment = get(b'c').unwrap_or_default();
    if comment.contains(&b':') || home.contains(&b':') || shell.contains(&b':') {
        return fail(3, "invalid field (a ':' is not allowed)");
    }
    db.passwd.push(Pw(alloc::vec![
        name.clone(),
        b"x".to_vec(),
        format!("{uid}").into_bytes(),
        format!("{gid}").into_bytes(),
        comment,
        home.clone(),
        shell,
    ]));
    let hash = get(b'p').unwrap_or_else(|| b"!".to_vec());
    let mut sp = Sp::new(name, &hash, &d);
    if system {
        // System accounts do not age.
        sp.set(3, None);
        sp.set(4, None);
        sp.set(5, None);
    }
    if let Some(e) = get(b'e') {
        match parse_day(&e) {
            Some(day) => sp.set(7, Some(day)),
            None if e.is_empty() || e == b"-1" => {}
            None => return fail(3, format!("invalid date '{}'", lossy(&e))),
        }
    }
    let inactive = get(b'f').and_then(|v| core::str::from_utf8(&v).ok()?.parse::<i64>().ok()).or(d.inactive);
    sp.set(6, inactive.filter(|&x| x >= 0));
    db.shadow.retain(|s| s.name() != name.as_slice());
    db.shadow.push(sp);
    if let Err(e) = db.save() {
        return fail(1, e);
    }
    let create = has(b'm') || (!has(b'M') && !system && d.create_home);
    if create && !fs::exists(&home) {
        if let Err(e) = fs::mkdir(&home, 0o700) {
            return fail(12, format!("cannot create directory {}: {e}", lossy(&home)));
        }
        let _ = fs::chmod(&home, 0o700);
        copy_skel(&get(b'k').unwrap_or_else(|| d.skel.clone()), &home, uid, gid);
        let _ = fs::chown(&home, uid, gid);
    }
    if d.mail_spool {
        // An empty spool, the mail group's to write if there is one
        // (as shadow-utils makes it), else the user's alone.
        let spool = fs::join(&d.mail_dir, name);
        let mail = db::group_id(b"mail");
        let made = fs::open(&spool, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600).and_then(|fd| {
            let _ = io::close(fd);
            fs::chown(&spool, uid, mail.unwrap_or(gid))?;
            fs::chmod(&spool, if mail.is_some() { 0o660 } else { 0o600 })
        });
        if let Err(e) = made {
            slate_rt::eprintln!("useradd: cannot create the mail spool {}: {e}", lossy(&spool));
        }
    }
    0
}

const USERMOD_LONG: &[(&str, u8)] = &[
    ("append", b'a'),
    ("comment", b'c'),
    ("home", b'd'),
    ("expiredate", b'e'),
    ("inactive", b'f'),
    ("gid", b'g'),
    ("groups", b'G'),
    ("login", b'l'),
    ("lock", b'L'),
    ("move-home", b'm'),
    ("non-unique", b'o'),
    ("password", b'p'),
    ("shell", b's'),
    ("uid", b'u'),
    ("unlock", b'U'),
];

pub fn usermod_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, ops) = match options(args, b"cdefgGlpsu", USERMOD_LONG) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: usermod [options] LOGIN") };
    let get = |c: u8| opts.iter().rev().find(|(o, _)| *o == c).map(|(_, v)| v.clone());
    let has = |c: u8| opts.iter().any(|(o, _)| *o == c);
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let Some(ui) = db.user(name) else { return fail(6, format!("user '{}' does not exist", lossy(name))) };
    if let Some(v) = get(b'c') {
        db.passwd[ui].0[4] = v;
    }
    if let Some(s) = get(b's') {
        db.passwd[ui].0[6] = s;
    }
    let old_uid = db.passwd[ui].uid().unwrap_or(0);
    if let Some(v) = get(b'u') {
        match num(&v) {
            Some(u) if has(b'o') || u == old_uid || !db.passwd.iter().any(|p| p.uid() == Some(u)) => {
                db.passwd[ui].0[2] = v;
            }
            Some(_) => return fail(4, format!("UID '{}' already exists", lossy(&v))),
            None => return fail(3, format!("invalid user ID '{}'", lossy(&v))),
        }
    }
    if let Some(g) = get(b'g') {
        match db.group_by(&g).and_then(|i| db.group[i].gid()) {
            Some(gid) => db.passwd[ui].0[3] = format!("{gid}").into_bytes(),
            None => return fail(6, format!("group '{}' does not exist", lossy(&g))),
        }
    }
    if let Some(gs) = get(b'G') {
        let wanted: Vec<&[u8]> = gs.split(|&c| c == b',').filter(|g| !g.is_empty()).collect();
        let mut idx = Vec::new();
        for g in &wanted {
            match db.group_by(g) {
                Some(i) => idx.push(i),
                None => return fail(6, format!("group '{}' does not exist", lossy(g))),
            }
        }
        for (i, g) in db.group.iter_mut().enumerate() {
            let mut m = g.members();
            let in_list = idx.contains(&i);
            if in_list && !m.contains(name) {
                m.push(name.clone());
            } else if !in_list && !has(b'a') {
                m.retain(|x| x != name);
            }
            g.set_members(&m);
        }
    }
    let old_home = db.passwd[ui].0[5].clone();
    if let Some(h) = get(b'd') {
        db.passwd[ui].0[5] = h.clone();
        if has(b'm') && fs::exists(&old_home) && !fs::exists(&h) && fs::rename(&old_home, &h).is_err() {
            return fail(12, format!("cannot move {} to {}", lossy(&old_home), lossy(&h)));
        }
    }
    let sp = db.shadow_of(name);
    if let Some(e) = get(b'e') {
        sp.set(7, parse_day(&e));
    }
    if let Some(f) = get(b'f') {
        sp.set(6, core::str::from_utf8(&f).ok().and_then(|s| s.parse().ok()).filter(|&x: &i64| x >= 0));
    }
    if let Some(p) = get(b'p') {
        sp.0[1] = p;
    }
    if has(b'L') && !sp.0[1].starts_with(b"!") {
        sp.0[1].insert(0, b'!');
    }
    if has(b'U') {
        if sp.0[1] == b"!" {
            return fail(1, "unlocking the user's password would result in a passwordless account.");
        }
        if let Some(rest) = sp.0[1].strip_prefix(b"!") {
            sp.0[1] = rest.to_vec();
        }
    }
    if let Some(new) = get(b'l') {
        if !valid_name(&new) {
            return fail(3, format!("invalid user name '{}'", lossy(&new)));
        }
        if db.user(&new).is_some() {
            return fail(9, format!("user '{}' already exists", lossy(&new)));
        }
        db.passwd[ui].0[0] = new.clone();
        for s in db.shadow.iter_mut().filter(|s| s.name() == name.as_slice()) {
            s.0[0] = new.clone();
        }
        for g in db.group.iter_mut() {
            let m: Vec<Vec<u8>> = g.members().into_iter().map(|x| if x == *name { new.clone() } else { x }).collect();
            g.set_members(&m);
        }
    }
    let (new_uid, gid) = (db.passwd[ui].uid().unwrap_or(0), db.passwd[ui].gid().unwrap_or(0));
    let home = db.passwd[ui].0[5].clone();
    if let Err(e) = db.save() {
        return fail(1, e);
    }
    if new_uid != old_uid && fs::stat(&home).is_ok_and(|s| s.uid == old_uid) {
        chown_tree(&home, new_uid, gid);
    }
    0
}

pub fn userdel_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, ops) = match options(args, b"", &[("remove", b'r'), ("force", b'f')]) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: userdel [options] LOGIN") };
    let (remove, force) = (opts.iter().any(|o| o.0 == b'r'), opts.iter().any(|o| o.0 == b'f'));
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let Some(ui) = db.user(name) else { return fail(6, format!("user '{}' does not exist", lossy(name))) };
    let uid = db.passwd[ui].uid().unwrap_or(u32::MAX);
    if !force && let Some(p) = slate_rt::utmp::current().into_iter().find(|e| e.user == *name) {
        return fail(8, format!("user {} is currently used by process {}", lossy(name), p.pid));
    }
    let home = db.passwd[ui].0[5].clone();
    let gid = db.passwd[ui].gid();
    db.passwd.remove(ui);
    db.shadow.retain(|s| s.name() != name.as_slice());
    for g in db.group.iter_mut() {
        let mut m = g.members();
        m.retain(|x| x != name);
        g.set_members(&m);
    }
    // The user's own group goes too, if nobody else uses it.
    if let Some(gi) = db.group_named(name)
        && db.group[gi].gid() == gid
        && db.group[gi].members().is_empty()
        && !db.passwd.iter().any(|p| p.gid() == gid)
    {
        db.group.remove(gi);
    }
    if let Err(e) = db.save() {
        return fail(1, e);
    }
    if remove {
        if fs::stat(&home).is_ok_and(|s| s.uid == uid) || force {
            remove_tree(&home);
        } else if fs::exists(&home) {
            slate_rt::eprintln!("userdel: {} not owned by {}, not removing", lossy(&home), lossy(name));
            return 12;
        }
        // The mail spool goes too, if it is the user's.
        let spool = fs::join(&Defs::load().mail_dir, name);
        if fs::lstat(&spool).is_ok_and(|s| s.uid == uid) || force {
            let _ = fs::unlink(&spool);
        }
    }
    0
}

pub fn groupadd_main() -> i32 {
    let args = slate_rt::env::args();
    let long = &[("gid", b'g'), ("force", b'f'), ("system", b'r'), ("non-unique", b'o'), ("users", b'U')];
    let (opts, ops) = match options(args, b"gU", long) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: groupadd [options] GROUP") };
    if !valid_name(name) {
        return fail(3, format!("'{}' is not a valid group name", lossy(name)));
    }
    let get = |c: u8| opts.iter().rev().find(|(o, _)| *o == c).map(|(_, v)| v.clone());
    let has = |c: u8| opts.iter().any(|(o, _)| *o == c);
    let d = Defs::load();
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    if db.group_named(name).is_some() {
        return if has(b'f') { 0 } else { fail(9, format!("group '{}' already exists", lossy(name))) };
    }
    let taken: Vec<u32> = db.group.iter().filter_map(Gr::gid).collect();
    let system = has(b'r');
    let pick = || {
        let (lo, hi) = if system { (d.sys_gid_min, d.sys_gid_max) } else { (d.gid_min, d.gid_max) };
        free_id(&taken, lo, hi, system)
    };
    let gid = match get(b'g') {
        Some(v) => match num(&v) {
            Some(g) if has(b'o') || !taken.contains(&g) => g,
            Some(_) if has(b'f') => match pick() {
                Some(g) => g,
                None => return fail(4, "can't get unique GID (no more available GIDs)"),
            },
            Some(_) => return fail(4, format!("GID '{}' already exists", lossy(&v))),
            None => return fail(3, format!("invalid group ID '{}'", lossy(&v))),
        },
        None => match pick() {
            Some(g) => g,
            None => return fail(4, "can't get unique GID (no more available GIDs)"),
        },
    };
    let members = get(b'U').unwrap_or_default();
    db.group.push(Gr(alloc::vec![name.clone(), b"x".to_vec(), format!("{gid}").into_bytes(), members]));
    match db.save() {
        Ok(()) => 0,
        Err(e) => fail(10, e),
    }
}

pub fn groupmod_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, ops) = match options(args, b"gn", &[("gid", b'g'), ("new-name", b'n'), ("non-unique", b'o')]) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: groupmod [options] GROUP") };
    let get = |c: u8| opts.iter().rev().find(|(o, _)| *o == c).map(|(_, v)| v.clone());
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let Some(gi) = db.group_named(name) else { return fail(6, format!("group '{}' does not exist", lossy(name))) };
    let old_gid = db.group[gi].gid();
    if let Some(v) = get(b'g') {
        match num(&v) {
            Some(g)
                if opts.iter().any(|o| o.0 == b'o')
                    || !db.group.iter().any(|x| x.gid() == Some(g))
                    || Some(g) == old_gid =>
            {
                db.group[gi].0[2] = v.clone();
                // Users whose primary group it was follow it.
                for p in db.passwd.iter_mut().filter(|p| p.gid() == old_gid) {
                    p.0[3] = v.clone();
                }
            }
            Some(_) => return fail(4, format!("GID '{}' already exists", lossy(&v))),
            None => return fail(3, format!("invalid group ID '{}'", lossy(&v))),
        }
    }
    if let Some(n) = get(b'n') {
        if !valid_name(&n) {
            return fail(3, format!("invalid group name '{}'", lossy(&n)));
        }
        if db.group_named(&n).is_some() {
            return fail(9, format!("group '{}' already exists", lossy(&n)));
        }
        for g in db.gshadow.iter_mut().filter(|g| g[0] == *name) {
            g[0] = n.clone();
        }
        db.group[gi].0[0] = n;
    }
    match db.save() {
        Ok(()) => 0,
        Err(e) => fail(10, e),
    }
}

pub fn groupdel_main() -> i32 {
    let args = slate_rt::env::args();
    let (_, ops) = match options(args, b"", &[]) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let [name] = ops.as_slice() else { return fail(2, "usage: groupdel GROUP") };
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let Some(gi) = db.group_named(name) else { return fail(6, format!("group '{}' does not exist", lossy(name))) };
    let gid = db.group[gi].gid();
    if let Some(u) = db.passwd.iter().find(|p| p.gid() == gid) {
        return fail(8, format!("cannot remove the primary group of user '{}'", lossy(u.name())));
    }
    db.group.remove(gi);
    db.gshadow.retain(|g| g[0] != *name);
    match db.save() {
        Ok(()) => 0,
        Err(e) => fail(10, e),
    }
}

/// gpasswd -a USER GROUP / -d USER GROUP / -M USER,... GROUP; gpasswd
/// GROUP sets the group's password (asked twice), -r removes it
/// (gshadow(5), for newgrp).
pub fn gpasswd_main() -> i32 {
    let args = slate_rt::env::args();
    let long = &[
        ("add", b'a'),
        ("delete", b'd'),
        ("members", b'M'),
        ("administrators", b'A'),
        ("remove-password", b'r'),
        ("restrict", b'R'),
    ];
    let (opts, ops) = match options(args, b"adMA", long) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let [group] = ops.as_slice() else {
        return fail(2, "usage: gpasswd [-a USER | -d USER | -M USER,... | -A USER,... | -r | -R] GROUP");
    };
    let op = opts.last().cloned();
    // A group's administrators (gshadow(5)) add and delete members, set,
    // remove or restrict its password, through the broker; -M and -A are
    // root's.
    if process::geteuid() != 0 {
        if matches!(op, Some((b'M' | b'A', _))) {
            return fail(1, "Permission denied.");
        }
        return gpasswd_as_admin(group, op);
    }
    let Some((op, who)) = op else { return set_group_password(group) };
    if op == b'r' || op == b'R' || op == b'A' {
        let mut db = match Db::open() {
            Ok(db) => db,
            Err(e) => return fail(1, e),
        };
        if db.group_named(group).is_none() {
            return fail(3, format!("group '{}' does not exist", lossy(group)));
        }
        let entry = db.gshadow_of(group);
        match op {
            // No password: only members get in with newgrp.
            b'r' => entry[1] = Vec::new(),
            // Restricted: no password works (gshadow's `!`).
            b'R' => entry[1] = b"!".to_vec(),
            _ => entry[2] = who.split(|&c| c == b',').filter(|x| !x.is_empty()).collect::<Vec<_>>().join(&b','),
        }
        return match db.save() {
            Ok(()) => 0,
            Err(e) => fail(1, e),
        };
    }
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let Some(gi) = db.group_named(group) else { return fail(3, format!("group '{}' does not exist", lossy(group))) };
    let mut m = db.group[gi].members();
    match op {
        b'a' => {
            if db.user(&who).is_none() {
                return fail(3, format!("user '{}' does not exist", lossy(&who)));
            }
            if !m.contains(&who) {
                m.push(who.clone());
            }
            println!("Adding user {} to group {}", lossy(&who), lossy(group));
        }
        b'd' => {
            if !m.contains(&who) {
                return fail(3, format!("user '{}' is not a member of '{}'", lossy(&who), lossy(group)));
            }
            m.retain(|x| *x != who);
            println!("Removing user {} from group {}", lossy(&who), lossy(group));
        }
        _ => m = who.split(|&c| c == b',').filter(|x| !x.is_empty()).map(<[u8]>::to_vec).collect(),
    }
    db.group[gi].set_members(&m);
    io::flush_stdout();
    match db.save() {
        Ok(()) => 0,
        Err(e) => fail(1, e),
    }
}

/// The new password, asked twice on the terminal (or read from standard
/// input).
fn ask_group_password(group: &[u8]) -> Result<Vec<u8>, i32> {
    let ask = |what: &str| {
        let tty = slate_rt::term::isatty(io::STDIN);
        if tty {
            io::out(what.as_bytes());
        }
        let line = crate::read_line(io::STDIN, tty);
        if tty {
            io::out(b"\n");
        }
        line
    };
    println!("Changing the password for group {}", lossy(group));
    io::flush_stdout();
    let (Some(p1), Some(p2)) = (ask("New Password: "), ask("Re-enter new password: ")) else {
        return Err(fail(3, "no password given"));
    };
    if p1 != p2 || p1.is_empty() {
        return Err(fail(3, "They don't match; try again"));
    }
    Ok(p1)
}

/// gpasswd as a group's administrator: the broker checks gshadow(5)'s
/// administrators, then does what root's gpasswd would.
fn gpasswd_as_admin(group: &[u8], op: Option<(u8, Vec<u8>)>) -> i32 {
    if crate::db::group_id(group).is_none() {
        return fail(3, format!("group '{}' does not exist", lossy(group)));
    }
    let r = match &op {
        None => match ask_group_password(group) {
            Ok(pw) => crate::broker::request(&[b"gpasswd", b"password", group, &[b"p".as_slice(), &pw].concat()]),
            Err(c) => return c,
        },
        Some((o, who)) => {
            let flag = [b'-', *o];
            crate::broker::request(&[b"gpasswd", &flag, group, &[b"u".as_slice(), who].concat()])
        }
    };
    match (r, &op) {
        (Ok(()), Some((b'a', who))) => {
            println!("Adding user {} to group {}", lossy(who), lossy(group));
            0
        }
        (Ok(()), Some((b'd', who))) => {
            println!("Removing user {} from group {}", lossy(who), lossy(group));
            0
        }
        (Ok(()), _) => 0,
        (Err(e), _) => fail(if e == "Permission denied." { 1 } else { 3 }, e),
    }
}

/// gpasswd GROUP: the new password, asked twice on the terminal (or read
/// from standard input), into gshadow(5).
fn set_group_password(group: &[u8]) -> i32 {
    if crate::db::group_id(group).is_none() {
        return fail(3, format!("group '{}' does not exist", lossy(group)));
    }
    let p1 = match ask_group_password(group) {
        Ok(p) => p,
        Err(c) => return c,
    };
    match set_group_hash(group, &p1) {
        Ok(()) => 0,
        Err(e) => fail(1, e),
    }
}

/// Group `group`'s password, hashed, into gshadow(5) (gpasswd as root,
/// and the broker for a group's administrators).
pub fn set_group_hash(group: &[u8], password: &[u8]) -> Result<(), String> {
    let h = hash(password)?;
    let mut db = Db::open()?;
    db.gshadow_of(group)[1] = h;
    db.save()
}

/// chpasswd: `user:password` lines on standard input (`-e`: already
/// hashed).
pub fn chpasswd_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, _) = match options(args, b"c", &[("encrypted", b'e'), ("crypt-method", b'c')]) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if let Some(c) = need_root() {
        return c;
    }
    let encrypted = opts.iter().any(|o| o.0 == b'e');
    let input = io::read_to_end(io::STDIN).unwrap_or_default();
    let mut followed: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    let mut status = 0;
    for (n, l) in input.split(|&c| c == b'\n').enumerate() {
        if l.is_empty() {
            continue;
        }
        let Some(colon) = l.iter().position(|&c| c == b':') else {
            slate_rt::eprintln!("chpasswd: line {}: missing new password", n + 1);
            status = 1;
            continue;
        };
        let (name, pw) = (&l[..colon], &l[colon + 1..]);
        if db.user(name).is_none() {
            slate_rt::eprintln!("chpasswd: line {}: user '{}' does not exist", n + 1, lossy(name));
            status = 1;
            continue;
        }
        let h = if encrypted {
            pw.to_vec()
        } else {
            match hash(pw) {
                Ok(h) => h,
                Err(e) => return fail(1, e),
            }
        };
        let sp = db.shadow_of(name);
        sp.0[1] = h;
        sp.set(2, Some(db::today() as i64));
        // The disk's slot for the account follows (ADR 0058).
        if !encrypted && let Some(uid) = db.user(name).and_then(|i| db.passwd[i].uid()) {
            followed.push((uid, pw.to_vec()));
        }
    }
    if let Err(e) = db.save() {
        return fail(1, e);
    }
    drop(db);
    for (uid, pw) in followed {
        if let Err(e) = slate_crypt::reset_password(uid, &pw) {
            slate_rt::eprintln!("chpasswd: the disk's password did not change: {e}");
        }
    }
    status
}

/// Set `name`'s password to `pw` as chpasswd does: hashed, changed
/// today, and the disk's slot for the account following (ADR 0058).
pub fn set_password(name: &[u8], pw: &[u8]) -> Result<(), String> {
    let h = hash(pw)?;
    let mut db = Db::open()?;
    let Some(uid) = db.user(name).and_then(|i| db.passwd[i].uid()) else {
        return Err(format!("user '{}' does not exist", lossy(name)));
    };
    let sp = db.shadow_of(name);
    sp.0[1] = h;
    sp.set(2, Some(db::today() as i64));
    db.save()?;
    drop(db);
    if let Err(e) = slate_crypt::reset_password(uid, pw) {
        slate_rt::eprintln!("{}: the disk's password did not change: {e}", prog());
    }
    Ok(())
}

/// chage: show or change an account's password ageing.
pub fn chage_main() -> i32 {
    let args = slate_rt::env::args();
    let long = &[
        ("lastday", b'd'),
        ("expiredate", b'E'),
        ("inactive", b'I'),
        ("list", b'l'),
        ("mindays", b'm'),
        ("maxdays", b'M'),
        ("warndays", b'W'),
    ];
    let (opts, ops) = match options(args, b"dEImMW", long) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let [name] = ops.as_slice() else { return fail(2, "usage: chage [options] LOGIN") };
    let list = opts.iter().any(|o| o.0 == b'l');
    let me = db::user_by_uid(process::getuid());
    if process::getuid() != 0 && !(list && opts.len() == 1 && me.as_ref().is_some_and(|m| m.name == *name)) {
        return fail(1, "Permission denied.");
    }
    let mut db = match Db::open() {
        Ok(db) => db,
        Err(e) => return fail(1, e),
    };
    if db.user(name).is_none() {
        return fail(1, format!("user '{}' does not exist in /etc/passwd", lossy(name)));
    }
    if list {
        let sp = db.shadow_of(name).clone();
        let never = String::from("never");
        let last = match sp.field(2) {
            Some(0) => String::from("password must be changed"),
            Some(d) => day_string(d),
            None => never.clone(),
        };
        let expires = match (sp.field(2), sp.field(4)) {
            (Some(0), _) => String::from("password must be changed"),
            (Some(l), Some(m)) if m < 99999 => day_string(l + m),
            _ => never.clone(),
        };
        let inactive = match (sp.field(2), sp.field(4), sp.field(6)) {
            (Some(l), Some(m), Some(i)) if m < 99999 => day_string(l + m + i),
            _ => never.clone(),
        };
        let account = sp.field(7).map_or(never, day_string);
        let n = |i: usize| sp.field(i).map_or_else(|| String::from("-1"), |v| format!("{v}"));
        println!("Last password change\t\t\t\t\t: {last}");
        println!("Password expires\t\t\t\t\t: {expires}");
        println!("Password inactive\t\t\t\t\t: {inactive}");
        println!("Account expires\t\t\t\t\t\t: {account}");
        println!("Minimum number of days between password change\t\t: {}", n(3));
        println!("Maximum number of days between password change\t\t: {}", n(4));
        println!("Number of days of warning before password expires\t: {}", n(5));
        io::flush_stdout();
        return 0;
    }
    if opts.is_empty() {
        return fail(2, "nothing to change (try chage -l)");
    }
    let sp = db.shadow_of(name);
    for (c, v) in &opts {
        let as_num = || core::str::from_utf8(v).ok().and_then(|s| s.trim().parse::<i64>().ok());
        let val = match c {
            b'd' | b'E' => parse_day(v),
            _ => as_num().filter(|&x| x >= 0),
        };
        if val.is_none() && !(v == b"-1" || v.is_empty()) {
            return fail(2, format!("invalid value '{}'", lossy(v)));
        }
        let field = match c {
            b'd' => 2,
            b'm' => 3,
            b'M' => 4,
            b'W' => 5,
            b'I' => 6,
            _ => 7,
        };
        sp.set(field, val);
    }
    match db.save() {
        Ok(()) => 0,
        Err(e) => fail(1, e),
    }
}

/// The shells /etc/shells lists.
pub fn valid_shell(shell: &[u8]) -> bool {
    fs::read_file(SHELLS).is_ok_and(|d| d.split(|&c| c == b'\n').any(|l| l == shell))
}

/// chsh [-s SHELL] [USER]: root changes anyone's; others their own,
/// through the broker, to a shell /etc/shells lists.
pub fn chsh_main() -> i32 {
    let args = slate_rt::env::args();
    let (opts, ops) = match options(args, b"s", &[("shell", b's'), ("list-shells", b'l')]) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if opts.iter().any(|o| o.0 == b'l') {
        if let Ok(d) = fs::read_file(SHELLS) {
            io::out(&d);
        }
        return 0;
    }
    let uid = process::getuid();
    let me = db::user_by_uid(uid);
    let name = match ops.as_slice() {
        [n] => n.clone(),
        [] => match &me {
            Some(m) => m.name.clone(),
            None => return fail(1, "you do not exist"),
        },
        _ => return fail(2, "usage: chsh [-s SHELL] [USER]"),
    };
    let Some(shell) = opts.iter().rev().find(|o| o.0 == b's').map(|o| o.1.clone()) else {
        return fail(2, "usage: chsh -s SHELL [USER]");
    };
    if uid != 0 {
        if !valid_shell(&shell) {
            return fail(1, format!("{} is an invalid shell", lossy(&shell)));
        }
        // Not set-user-ID (ADR 0032): the broker checks the password and
        // writes the change.
        crate::prompt(0, b"Password: ");
        let pw = crate::read_line(0, true).unwrap_or_default();
        return match crate::broker::request(&[b"chsh", &name, &pw, &shell]) {
            Ok(()) => 0,
            Err(e) => fail(1, e),
        };
    }
    set_shell(&name, &shell).map_or_else(|e| fail(1, e), |()| 0)
}

/// Write `shell` as `name`'s login shell.
pub fn set_shell(name: &[u8], shell: &[u8]) -> Result<(), String> {
    if shell.contains(&b':') || shell.contains(&b'\n') {
        return Err(String::from("invalid shell"));
    }
    let mut db = Db::open()?;
    let i = db.user(name).ok_or_else(|| format!("user '{}' does not exist", lossy(name)))?;
    db.passwd[i].0[6] = shell.to_vec();
    db.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sp(fields: &str) -> Sp {
        let mut v = split(fields.as_bytes());
        v.resize(9, Vec::new());
        Sp(v)
    }

    #[test]
    fn ageing_rules() {
        let today = 20_000;
        assert_eq!(ageing_of(Some(&sp("a:h:19990:0:99999:7:::")), today), Ageing::Ok);
        assert_eq!(ageing_of(Some(&sp("a:h:0:0:99999:7:::")), today), Ageing::MustChange);
        assert_eq!(status_line(b"a", Some(&sp("a:$6$x:20387:0:99999:7:::"))), "a P 2025-10-26 0 99999 7 -1");
        assert_eq!(status_line(b"b", Some(&sp("b:!$6$x:0::::30::"))), "b L 1970-01-01 -1 -1 -1 30");
        assert_eq!(status_line(b"c", Some(&sp("c::::::::"))), "c NP never -1 -1 -1 -1");
        assert_eq!(status_line(b"d", None), "d NP never -1 -1 -1 -1");
        assert_eq!(ageing_of(Some(&sp("a:h:19900:0:90:7:::")), today), Ageing::MustChange);
        assert_eq!(ageing_of(Some(&sp("a:h:19912:0:90:7:::")), today), Ageing::Warn(2));
        assert!(matches!(ageing_of(Some(&sp("a:h:19900:0:90:7:5::")), today), Ageing::Refused(_)));
        assert!(matches!(ageing_of(Some(&sp("a:h:19990:::::19999:")), today), Ageing::Refused(_)));
        assert_eq!(ageing_of(Some(&sp("a:h:19990:::::20001:")), today), Ageing::Ok);
        assert_eq!(ageing_of(None, today), Ageing::Ok);
    }

    #[test]
    fn names_days_and_defaults() {
        assert!(valid_name(b"bob") && valid_name(b"_svc") && valid_name(b"a.b-c_1") && valid_name(b"host$"));
        assert!(!valid_name(b"Bob") && !valid_name(b"1x") && !valid_name(b"") && !valid_name(b"a:b"));
        assert_eq!(parse_day(b"1970-01-02"), Some(1));
        assert_eq!(parse_day(b"-1"), None);
        assert_eq!(parse_day(b"20000"), Some(20_000));
        let d = Defs::parse(b"UID_MIN 2000\n# x\nPASS_MAX_DAYS 90\nCREATE_HOME no\n", b"SHELL=/bin/chalk\nHOME=/u\n");
        assert_eq!((d.uid_min, d.pass_max, d.create_home), (2000, 90, false));
        assert_eq!((d.shell.as_slice(), d.home.as_slice()), (b"/bin/chalk".as_slice(), b"/u".as_slice()));
        assert_eq!(free_id(&[1000, 1001], 1000, 60000, false), Some(1002));
        assert_eq!(free_id(&[999], 101, 999, true), Some(998));
    }

    #[test]
    fn option_parsing() {
        let a: Vec<Vec<u8>> = ["useradd", "-mG", "wheel,tty", "--shell=/bin/sh", "-u", "1500", "bob"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        let (o, ops) = options(&a, b"cdefgGkpsu", USERADD_LONG).unwrap();
        assert_eq!(ops, [b"bob".to_vec()]);
        assert_eq!(
            o,
            alloc::vec![
                (b'm', Vec::new()),
                (b'G', b"wheel,tty".to_vec()),
                (b's', b"/bin/sh".to_vec()),
                (b'u', b"1500".to_vec())
            ]
        );
    }
}
