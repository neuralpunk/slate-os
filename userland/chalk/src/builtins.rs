// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in commands: POSIX.1-2017 XCU §2.14 special built-ins, the
//! regular built-ins a shell must provide (cd, read, jobs, ...), and the
//! bash ones scripts commonly use (local, source, declare, let, ...).
//! echo, printf, test and kill share code with Slate's coreutils.

use alloc::string::String;
use alloc::vec::Vec;

use slate_coreutils::util::parse_num;
use slate_rt::{fs, io, process, signal};

use crate::ast::Command;
use crate::expand::word_text;
use crate::jobs::{State, describe_state};
use crate::shell::{Flow, Res, Shell, Var, text};

pub type Builtin = fn(&mut Shell, &[Vec<u8>]) -> Res;

const BUILTINS: &[(&str, Builtin)] = &[
    (".", dot),
    (":", colon),
    ("[", bracket),
    ("alias", alias),
    ("bg", bg),
    ("break", r#break),
    ("builtin", builtin),
    ("caller", caller),
    ("cd", cd),
    ("command", command),
    ("continue", r#continue),
    ("declare", declare),
    ("dirs", dirs),
    ("disown", disown),
    ("echo", echo),
    ("eval", eval),
    ("exec", exec),
    ("exit", exit),
    ("export", export),
    ("false", r#false),
    ("fc", fc),
    ("fg", fg),
    ("getopts", getopts),
    ("hash", colon),
    ("history", history),
    ("jobs", jobs),
    ("kill", kill),
    ("let", let_),
    ("local", local),
    ("logout", logout),
    ("mapfile", mapfile),
    ("popd", popd),
    ("printf", printf),
    ("pushd", pushd),
    ("pwd", pwd),
    ("read", read),
    ("readarray", mapfile),
    ("readonly", readonly),
    ("return", r#return),
    ("set", set),
    ("shift", shift),
    ("shopt", shopt),
    ("source", dot),
    ("test", test),
    ("times", times),
    ("trap", trap),
    ("true", colon),
    ("type", type_),
    ("ulimit", ulimit),
    ("typeset", declare),
    ("umask", umask),
    ("unalias", unalias),
    ("unset", unset),
    ("wait", wait),
];

const SPECIAL: &[&str] = &[
    ".", ":", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set", "shift", "times",
    "trap", "unset",
];

pub const KEYWORDS: &[&str] = &[
    "!", "[[", "]]", "{", "}", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function", "if",
    "in", "select", "then", "time", "until", "while",
];

pub fn find(name: &[u8]) -> Option<Builtin> {
    BUILTINS.iter().find(|(n, _)| n.as_bytes() == name).map(|(_, f)| *f)
}

pub fn is_special(name: &[u8]) -> bool {
    SPECIAL.iter().any(|n| n.as_bytes() == name)
}

pub fn names() -> impl Iterator<Item = &'static str> {
    BUILTINS.iter().map(|(n, _)| *n)
}

fn err(name: &str, msg: impl core::fmt::Display) {
    crate::error(format_args!("{name}: {msg}"));
}

/// Quote a word so the shell reads it back as itself.
pub fn quote(w: &[u8]) -> Vec<u8> {
    if !w.is_empty() && w.iter().all(|c| c.is_ascii_alphanumeric() || b"_-./:=@%+,^".contains(c)) {
        return w.to_vec();
    }
    let mut o = alloc::vec![b'\''];
    for &c in w {
        if c == b'\'' {
            o.extend_from_slice(b"'\\''");
        } else {
            o.push(c);
        }
    }
    o.push(b'\'');
    o
}

/// A command's text for job listings.
pub fn describe(c: &Command) -> String {
    match c {
        Command::Simple { assigns, words, .. } => {
            let mut parts: Vec<String> =
                assigns.iter().map(|a| alloc::format!("{}={}", text(&a.name), text(&word_text(&a.value)))).collect();
            parts.extend(words.iter().map(|w| text(&word_text(w))));
            parts.join(" ")
        }
        Command::Pipeline { bang, cmds } => {
            let s: Vec<String> = cmds.iter().map(describe).collect();
            if *bang { alloc::format!("! {}", s.join(" | ")) } else { s.join(" | ") }
        }
        Command::And(a, b) => alloc::format!("{} && {}", describe(a), describe(b)),
        Command::Or(a, b) => alloc::format!("{} || {}", describe(a), describe(b)),
        Command::Subshell(..) => String::from("( ... )"),
        Command::Group(..) => String::from("{ ... }"),
        Command::If { .. } => String::from("if ..."),
        Command::Loop { until: false, .. } => String::from("while ..."),
        Command::Loop { .. } => String::from("until ..."),
        Command::For { var, .. } => alloc::format!("for {} ...", text(var)),
        Command::ArithFor { .. } => String::from("for ((...))"),
        Command::Select { var, .. } => alloc::format!("select {} ...", text(var)),
        Command::Coproc { .. } | Command::Time { .. } => text(&crate::print::command(c)),
        Command::Case { .. } => String::from("case ..."),
        Command::FuncDef { name, .. } => alloc::format!("{}()", text(name)),
        Command::Cond(..) => String::from("[[ ... ]]"),
        Command::Arith(..) => String::from("(( ... ))"),
    }
}

fn status_arg(sh: &Shell, name: &str, a: Option<&Vec<u8>>) -> Result<i32, Flow> {
    match a {
        None => Ok(sh.status),
        Some(a) => match parse_num::<i64>(a) {
            Some(n) => Ok((n & 0xFF) as i32),
            None => {
                err(name, alloc::format!("{}: numeric argument required", text(a)));
                Ok(2)
            }
        },
    }
}

// --- trivial ------------------------------------------------------------

fn colon(_: &mut Shell, _: &[Vec<u8>]) -> Res {
    Ok(0)
}

fn r#false(_: &mut Shell, _: &[Vec<u8>]) -> Res {
    Ok(1)
}

fn echo(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if sh.shopt("xpg_echo") {
        let mut v = alloc::vec![a[0].clone(), b"-e".to_vec()];
        v.extend_from_slice(&a[1..]);
        return Ok(slate_coreutils::simple::echo(&v));
    }
    Ok(slate_coreutils::simple::echo(a))
}

fn test(_: &mut Shell, a: &[Vec<u8>]) -> Res {
    Ok(slate_coreutils::test::test(a))
}

fn bracket(_: &mut Shell, a: &[Vec<u8>]) -> Res {
    Ok(slate_coreutils::test::bracket(a))
}

/// printf as bash's builtin: `-v var`, `%q` quoting with backslashes,
/// `%(datefmt)T`.
fn printf(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let style = slate_coreutils::printf::Style::Bash { start: sh.start_time };
    let mut i = 1;
    let mut var = None;
    if a.get(1).map(Vec::as_slice) == Some(b"-v") {
        var = a.get(2).cloned();
        i = 3;
    }
    if a.get(i).map(Vec::as_slice) == Some(b"--") {
        i += 1;
    }
    let Some(fmt) = a.get(i) else {
        err("printf", "usage: printf [-v var] format [arguments]");
        return Ok(2);
    };
    let mut out = Vec::new();
    let st = slate_coreutils::printf::format_as(fmt, &a[i + 1..], &mut out, style);
    match var {
        Some(v) => {
            sh.set_var(&v, &out);
        }
        None => io::out(&out),
    }
    Ok(st)
}

fn times(_: &mut Shell, _: &[Vec<u8>]) -> Res {
    let t = slate_rt::process::cpu_times().unwrap_or([0; 4]);
    let f = |ns: u64| {
        let ms = ns / 1_000_000;
        alloc::format!("{}m{}.{:03}s", ms / 60_000, ms / 1000 % 60, ms % 1000)
    };
    io::out(alloc::format!("{} {}\n{} {}\n", f(t[0]), f(t[1]), f(t[2]), f(t[3])).as_bytes());
    Ok(0)
}

/// ulimit's resources: letter, Linux's `RLIMIT_*` number (musl
/// `sys/resource.h`), the unit in bytes (or 1), and -a's description.
const LIMITS: &[(u8, u32, u64, &str)] = &[
    (b'c', 4, 512, "core file size              (blocks, -c)"),
    (b'd', 2, 1024, "data seg size               (kbytes, -d)"),
    (b'e', 13, 1, "scheduling priority                 (-e)"),
    (b'f', 1, 512, "file size                   (blocks, -f)"),
    (b'i', 11, 1, "pending signals                     (-i)"),
    (b'l', 8, 1024, "max locked memory           (kbytes, -l)"),
    (b'm', 5, 1024, "max memory size             (kbytes, -m)"),
    (b'n', 7, 1, "open files                          (-n)"),
    (b'q', 12, 1, "POSIX message queues         (bytes, -q)"),
    (b'r', 14, 1, "real-time priority                  (-r)"),
    (b's', 3, 1024, "stack size                  (kbytes, -s)"),
    (b't', 0, 1, "cpu time                   (seconds, -t)"),
    (b'u', 6, 1, "max user processes                  (-u)"),
    (b'v', 9, 1024, "virtual memory              (kbytes, -v)"),
    (b'x', 10, 1, "file locks                          (-x)"),
];

/// ulimit [-SHa] [-cdefilmnqrstuvx] [limit] (POSIX, with bash's letters).
fn ulimit(_: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut soft, mut hard, mut all) = (false, false, false);
    let mut which: Vec<u8> = Vec::new();
    let mut value: Option<Vec<u8>> = None;
    for arg in &a[1..] {
        if arg.len() > 1 && arg[0] == b'-' {
            for &c in &arg[1..] {
                match c {
                    b'S' => soft = true,
                    b'H' => hard = true,
                    b'a' => all = true,
                    c if LIMITS.iter().any(|l| l.0 == c) => which.push(c),
                    _ => {
                        err("ulimit", alloc::format!("-{}: invalid option", c as char));
                        return Ok(2);
                    }
                }
            }
        } else {
            value = Some(arg.clone());
        }
    }
    let show = |v: u64, unit: u64| {
        if v == u64::MAX { String::from("unlimited") } else { alloc::format!("{}", v / unit) }
    };
    if all {
        let mut out = String::new();
        for &(_, r, unit, desc) in LIMITS {
            let (cur, max) = slate_rt::process::getrlimit(r).unwrap_or((0, 0));
            out.push_str(&alloc::format!("{desc} {}\n", show(if hard { max } else { cur }, unit)));
        }
        io::out(out.as_bytes());
        return Ok(0);
    }
    if which.is_empty() {
        which.push(b'f');
    }
    let mut st = 0;
    for c in which {
        let Some(&(_, r, unit, _)) = LIMITS.iter().find(|l| l.0 == c) else { continue };
        let Ok((cur, max)) = slate_rt::process::getrlimit(r) else {
            st = 1;
            continue;
        };
        match &value {
            None => io::out(alloc::format!("{}\n", show(if hard { max } else { cur }, unit)).as_bytes()),
            Some(v) => {
                let n = match v.as_slice() {
                    b"unlimited" => u64::MAX,
                    b"hard" => max,
                    b"soft" => cur,
                    _ => match parse_num::<u64>(v) {
                        Some(n) => n.saturating_mul(unit),
                        None => {
                            err("ulimit", alloc::format!("{}: invalid number", text(v)));
                            return Ok(1);
                        }
                    },
                };
                // Neither -S nor -H: both.
                let (nc, nm) = match (soft, hard) {
                    (true, false) => (n, max),
                    (false, true) => (cur.min(n), n),
                    _ => (n, n),
                };
                if let Err(e) = slate_rt::process::setrlimit(r, nc, nm) {
                    err("ulimit", alloc::format!("{}: cannot modify limit: {e}", desc_name(c)));
                    st = 1;
                }
            }
        }
    }
    Ok(st)
}

fn desc_name(c: u8) -> String {
    LIMITS
        .iter()
        .find(|l| l.0 == c)
        .map_or_else(String::new, |l| String::from(l.3.split('(').next().unwrap_or("").trim()))
}

/// mapfile / readarray (bash): lines of input into an indexed array.
fn mapfile(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut delim, mut count, mut origin, mut skip, mut strip, mut fd) =
        (b'\n', 0usize, None::<i64>, 0usize, false, 0i32);
    let (mut callback, mut quantum) = (None::<Vec<u8>>, 5000usize);
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-') {
        let take = |i: &mut usize| -> Option<Vec<u8>> {
            if o.len() > 2 {
                Some(o[2..].to_vec())
            } else {
                *i += 1;
                a.get(*i).cloned()
            }
        };
        match o[1] {
            b't' => strip = true,
            b'd' => delim = take(&mut i).and_then(|v| v.first().copied()).unwrap_or(0),
            b'n' => count = take(&mut i).and_then(|v| parse_num(&v)).unwrap_or(0),
            b'O' => origin = take(&mut i).and_then(|v| parse_num(&v)),
            b's' => skip = take(&mut i).and_then(|v| parse_num(&v)).unwrap_or(0),
            b'u' => fd = take(&mut i).and_then(|v| parse_num(&v)).unwrap_or(0),
            b'C' => callback = take(&mut i),
            b'c' => match take(&mut i).and_then(|v| parse_num::<usize>(&v)).filter(|&q| q > 0) {
                Some(q) => quantum = q,
                None => {
                    err("mapfile", "invalid callback quantum");
                    return Ok(1);
                }
            },
            c => {
                err("mapfile", alloc::format!("-{}: invalid option", c as char));
                return Ok(2);
            }
        }
        i += 1;
    }
    let name = a.get(i).cloned().unwrap_or_else(|| b"MAPFILE".to_vec());
    if !crate::parser::is_name(&name) {
        err("mapfile", alloc::format!("'{}': not a valid identifier", text(&name)));
        return Ok(1);
    }
    // Without -O the array starts afresh.
    if origin.is_none() && !sh.assign_array(&name, Vec::new(), false) {
        return Ok(1);
    }
    // (next index, lines stored)
    let mut at = (origin.unwrap_or(0), 0usize);
    // Each line goes in as it is read; the callback (-C, every `quantum`
    // lines) sees the index and the line before it is stored (bash).
    let store = |sh: &mut Shell, line: Vec<u8>, at: &mut (i64, usize)| -> Result<bool, Flow> {
        let idx = alloc::format!("{}", at.0).into_bytes();
        if let Some(cb) = &callback
            && (at.1 + 1) % quantum == 0
        {
            sh.eval(&[cb.as_slice(), b" ", &idx, b" ", &quote(&line)].concat())?;
        }
        if !sh.set_elem(&name, &idx, &line, false) {
            return Ok(false);
        }
        at.0 += 1;
        at.1 += 1;
        Ok(true)
    };
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    let mut seen = 0;
    loop {
        if count > 0 && at.1 >= count {
            break;
        }
        match io::read(fd, &mut b) {
            Ok(1) => {}
            _ => break,
        }
        if b[0] != delim {
            line.push(b[0]);
            continue;
        }
        if !strip {
            line.push(delim);
        }
        seen += 1;
        if seen > skip {
            if !store(sh, core::mem::take(&mut line), &mut at)? {
                return Ok(1);
            }
        } else {
            line.clear();
        }
    }
    if !line.is_empty() && seen >= skip && (count == 0 || at.1 < count) && !store(sh, line, &mut at)? {
        return Ok(1);
    }
    Ok(0)
}

// --- control flow ---------------------------------------------------------

fn loop_count(sh: &Shell, name: &str, a: &[Vec<u8>]) -> Result<usize, i32> {
    let n = match a.get(1) {
        None => 1,
        Some(v) => match parse_num::<usize>(v) {
            Some(n) if n > 0 => n,
            _ => {
                err(name, alloc::format!("{}: loop count out of range", text(v)));
                return Err(1);
            }
        },
    };
    if sh.loop_depth == 0 {
        err(name, "only meaningful in a 'for', 'while', or 'until' loop");
        return Err(0);
    }
    Ok(n.min(sh.loop_depth))
}

fn r#break(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    match loop_count(sh, "break", a) {
        Ok(n) => Err(Flow::Break(n)),
        Err(s) => Ok(s),
    }
}

fn r#continue(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    match loop_count(sh, "continue", a) {
        Ok(n) => Err(Flow::Continue(n)),
        Err(s) => Ok(s),
    }
}

fn r#return(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let st = status_arg(sh, "return", a.get(1))?;
    if sh.func_depth == 0 && sh.source_depth == 0 {
        err("return", "can only 'return' from a function or sourced script");
        return Ok(1);
    }
    Err(Flow::Return(st))
}

fn exit(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let st = status_arg(sh, "exit", a.get(1))?;
    if sh.interactive && !sh.warned_jobs && sh.jobs.list.iter().any(|j| j.state == State::Stopped) {
        sh.warned_jobs = true;
        io::err(b"There are stopped jobs.\n");
        return Ok(1);
    }
    if sh.interactive && !sh.subshell {
        io::err(b"exit\n");
    }
    Err(Flow::Exit(st))
}

fn eval(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let src = a[1..].join(&b' ');
    sh.eval(&src)
}

fn exec(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut i = 1;
    if a.get(i).map(Vec::as_slice) == Some(b"--") {
        i += 1;
    }
    if i >= a.len() {
        return Ok(0);
    }
    if let Some(ed) = sh.editor.as_mut() {
        ed.save_history(&sh.history);
        ed.restore_modes();
    }
    let st = sh.exec(&a[i..], &[]);
    if sh.interactive || sh.shopt("execfail") { Ok(st) } else { Err(Flow::Exit(st)) }
}

fn dot(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let Some(name) = a.get(1) else {
        err(".", "filename argument required");
        return Ok(2);
    };
    let path = if name.contains(&b'/') || !sh.shopt("sourcepath") {
        fs::stat(name).is_ok_and(|s| s.is_file()).then(|| name.clone())
    } else {
        let path = sh.get_var(b"PATH").unwrap_or_default();
        path.split(|&c| c == b':')
            .map(|d| fs::join(if d.is_empty() { b"." } else { d }, name))
            .find(|p| fs::stat(p).is_ok_and(|s| s.is_file()))
            .or_else(|| fs::stat(name).is_ok_and(|s| s.is_file()).then(|| name.clone()))
    };
    let src = match path.as_ref().map(|p| fs::read_file(p)) {
        Some(Ok(s)) => s,
        Some(Err(e)) => {
            err(".", alloc::format!("{}: {e}", text(name)));
            return if sh.interactive { Ok(1) } else { Err(Flow::Exit(1)) };
        }
        None => {
            err(".", alloc::format!("{}: file not found", text(name)));
            return if sh.interactive { Ok(1) } else { Err(Flow::Exit(1)) };
        }
    };
    let saved = (a.len() > 2).then(|| core::mem::replace(&mut sh.positional, a[2..].to_vec()));
    sh.source_depth += 1;
    let r = sh.source(&src);
    sh.source_depth -= 1;
    if let Some(p) = saved {
        sh.positional = p;
    }
    match r {
        Err(Flow::Return(s)) => Ok(s),
        r => r,
    }
}

// --- variables ------------------------------------------------------------

/// An argument of export, readonly, local or declare: `name`,
/// `name=value` (arrays and `+=` included). The name, empty if the
/// assignment failed; None if it is not a valid name.
fn assign_arg(sh: &mut Shell, a: &[u8]) -> Option<Vec<u8>> {
    if a.contains(&b'=') {
        let (name, ok) = sh.assign_text(a)?;
        return Some(if ok { name } else { Vec::new() });
    }
    crate::parser::is_name(a).then(|| a.to_vec())
}

fn print_vars(sh: &Shell, prefix: &str, f: impl Fn(&Var) -> bool) {
    let mut out = Vec::new();
    for (k, v) in sh.vars.iter().filter(|(_, v)| f(v)) {
        out.extend_from_slice(prefix.as_bytes());
        out.extend_from_slice(k);
        out.push(b'=');
        out.extend_from_slice(&quote(&v.value));
        out.push(b'\n');
    }
    io::out(&out);
}

fn export(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut unexport = false;
    let mut i = 1;
    while let Some(o) = a.get(i) {
        match o.as_slice() {
            b"-p" => {}
            b"-n" => unexport = true,
            b"--" => {
                i += 1;
                break;
            }
            _ => break,
        }
        i += 1;
    }
    if i >= a.len() {
        print_vars(sh, "export ", |v| v.exported);
        return Ok(0);
    }
    let mut st = 0;
    for arg in &a[i..] {
        match assign_arg(sh, arg) {
            Some(n) if n.is_empty() => st = 1,
            Some(n) if unexport => {
                if let Some(v) = sh.vars.get_mut(&n) {
                    v.exported = false;
                }
            }
            Some(n) => sh.export(&n),
            None => {
                err("export", alloc::format!("'{}': not a valid identifier", text(arg)));
                st = 1;
            }
        }
    }
    Ok(st)
}

fn readonly(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let args: Vec<&Vec<u8>> = a[1..].iter().filter(|x| x.as_slice() != b"-p").collect();
    if args.is_empty() {
        print_vars(sh, "readonly ", |v| v.readonly);
        return Ok(0);
    }
    let mut st = 0;
    for arg in args {
        match assign_arg(sh, arg) {
            Some(n) if n.is_empty() => st = 1,
            Some(n) => sh.vars.entry(n).or_default().readonly = true,
            None => {
                err("readonly", alloc::format!("'{}': not a valid identifier", text(arg)));
                st = 1;
            }
        }
    }
    Ok(st)
}

fn unset(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut funcs, mut refs) = (false, false);
    let mut st = 0;
    for arg in &a[1..] {
        match arg.as_slice() {
            b"-f" => funcs = true,
            b"-v" => funcs = false,
            b"-n" => refs = true,
            _ if funcs => {
                sh.functions.remove(arg);
            }
            _ if refs && sh.is_nameref(arg) => {
                if !sh.unset_ref(arg) {
                    st = 1;
                }
            }
            _ => {
                if let Some((n, sub)) = crate::shell::split_subscript(arg) {
                    if !sh.unset_elem(n, sub) {
                        st = 1;
                    }
                } else if !sh.unset_var(arg) {
                    st = 1;
                }
            }
        }
    }
    Ok(st)
}

fn local(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if sh.func_depth == 0 {
        err("local", "can only be used in a function");
        return Ok(1);
    }
    declare_as(sh, a, "local", true)
}

fn declare(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    declare_as(sh, a, "declare", false)
}

/// declare, typeset and local (bash): attributes `-a -A -i -l -u -r -x`
/// (`+` takes one away), `-p` to print, `-g` global, `-f`/`-F` functions.
fn declare_as(sh: &mut Shell, a: &[Vec<u8>], name_of: &str, local: bool) -> Res {
    use crate::arrays::Array;
    let (mut print, mut global, mut funcs) = (false, false, false);
    let mut on: Vec<u8> = Vec::new();
    let mut off: Vec<u8> = Vec::new();
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && (o[0] == b'-' || o[0] == b'+')) {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        for &c in &o[1..] {
            match c {
                b'p' => print = true,
                b'g' => global = true,
                b'f' | b'F' => funcs = true,
                b'a' | b'A' | b'i' | b'l' | b'n' | b'u' | b'r' | b'x' => {
                    if o[0] == b'-' {
                        on.push(c)
                    } else {
                        off.push(c)
                    }
                }
                _ => {
                    err(name_of, alloc::format!("-{}: invalid option", c as char));
                    return Ok(2);
                }
            }
        }
        i += 1;
    }
    if funcs {
        // -F: names; -f: whole definitions, as bash prints them.
        let names_only = a[1..i].iter().any(|o| o.contains(&b'F'));
        let names: Vec<Vec<u8>> = if i >= a.len() { sh.functions.keys().cloned().collect() } else { a[i..].to_vec() };
        let mut out = Vec::new();
        let mut st = 0;
        for n in &names {
            let Some(f) = sh.functions.get(n.as_slice()) else {
                st = 1;
                continue;
            };
            if names_only && i >= a.len() {
                out.extend_from_slice(b"declare -f ");
                out.extend_from_slice(n);
            } else if names_only {
                out.extend_from_slice(n);
            } else {
                out.extend(crate::print::function(n, f));
            }
            out.push(b'\n');
        }
        io::out(&out);
        return Ok(st);
    }
    if i >= a.len() {
        // A listing: everything (`name=value`), or with -p or attributes
        // the declarations of the variables that have them.
        let mut out = Vec::new();
        let names: Vec<Vec<u8>> = sh.vars.keys().cloned().collect();
        for n in names {
            let v = sh.vars.get(&n).cloned().unwrap_or_default();
            let has = |c: u8| match c {
                b'a' => matches!(v.array, Array::Indexed(_)),
                b'A' => matches!(v.array, Array::Assoc(_)),
                b'n' => v.nameref,
                b'i' => v.integer,
                b'l' => v.case == b'l',
                b'u' => v.case == b'u',
                b'r' => v.readonly,
                _ => v.exported,
            };
            if !on.iter().all(|&c| has(c)) {
                continue;
            }
            if print || !on.is_empty() {
                out.extend(sh.declaration(&n, &v));
            } else if !v.unset && !v.array.is_some() {
                out.extend_from_slice(&n);
                out.push(b'=');
                out.extend(quote(&v.value));
            } else {
                continue;
            }
            out.push(b'\n');
        }
        io::out(&out);
        return Ok(0);
    }
    let mut st = 0;
    for arg in &a[i..] {
        let lhs = arg.split(|&c| c == b'=').next().unwrap_or_default();
        let lhs = lhs.strip_suffix(b"+").unwrap_or(lhs);
        let name = lhs.split(|&c| c == b'[').next().unwrap_or_default().to_vec();
        if !crate::parser::is_name(&name) {
            err(name_of, alloc::format!("'{}': not a valid identifier", text(arg)));
            st = 1;
            continue;
        }
        if print {
            match sh.vars.get(&name).cloned() {
                Some(v) => {
                    let mut l = sh.declaration(&name, &v);
                    l.push(b'\n');
                    io::out(&l);
                }
                None => {
                    err(name_of, alloc::format!("{}: not found", text(&name)));
                    st = 1;
                }
            }
            continue;
        }
        let has_value = arg.contains(&b'=');
        // In a function, declare (and always local) makes a new local:
        // unset until given a value.
        if sh.func_depth > 0 && (local || !global) {
            let new_here = sh.locals.last().is_some_and(|f| !f.iter().any(|(n, _)| *n == name));
            sh.make_local(&name);
            if new_here {
                sh.vars.insert(name.clone(), crate::shell::Var { unset: true, ..Default::default() });
            }
        }
        if sh.vars.get(&name).is_some_and(|v| v.readonly) && (has_value || !on.is_empty()) {
            err(name_of, alloc::format!("{}: readonly variable", text(&name)));
            st = 1;
            continue;
        }
        if on.contains(&b'n') {
            // A name reference holds the name it stands for.
            let target = arg.iter().position(|&c| c == b'=').map(|e| arg[e + 1..].to_vec());
            if let Some(t) = &target {
                let base = t.split(|&c| c == b'[').next().unwrap_or_default();
                if !crate::parser::is_name(base) {
                    err(name_of, alloc::format!("'{}': invalid variable name for name reference", text(t)));
                    st = 1;
                    continue;
                }
                if *t == name {
                    err(name_of, alloc::format!("{}: nameref variable self references not allowed", text(&name)));
                    st = 1;
                    continue;
                }
            }
            let v = sh.vars.entry(name.clone()).or_insert_with(|| Var { unset: true, ..Default::default() });
            v.nameref = true;
            if let Some(t) = target {
                v.value = t;
                v.unset = false;
            }
            for &c in &on {
                match c {
                    b'r' => v.readonly = true,
                    b'x' => v.exported = true,
                    _ => {}
                }
            }
            continue;
        }
        {
            let v =
                sh.vars.entry(name.clone()).or_insert_with(|| crate::shell::Var { unset: true, ..Default::default() });
            for &c in &on {
                match c {
                    b'a' if !v.array.is_some() => {
                        let mut m = alloc::collections::BTreeMap::new();
                        if !v.unset {
                            m.insert(0, core::mem::take(&mut v.value));
                        }
                        v.array = Array::Indexed(m);
                    }
                    b'A' if !v.array.is_some() => {
                        let mut m = crate::arrays::AssocMap::new();
                        if !v.unset {
                            m.insert(b"0".to_vec(), core::mem::take(&mut v.value));
                        }
                        v.array = Array::Assoc(m);
                    }
                    b'i' => v.integer = true,
                    b'l' | b'u' => v.case = c,
                    b'x' => v.exported = true,
                    _ => {}
                }
            }
            for &c in &off {
                match c {
                    b'n' => v.nameref = false,
                    b'i' => v.integer = false,
                    b'l' | b'u' if v.case == c => v.case = 0,
                    b'x' => v.exported = false,
                    _ => {}
                }
            }
        }
        if has_value && assign_arg(sh, arg).is_none_or(|n| n.is_empty()) {
            st = 1;
            continue;
        }
        if !has_value && on.iter().any(|c| matches!(c, b'l' | b'u')) {
            // A value already there changes case now.
            if let Some(v) = sh.get_var(&name).filter(|_| !sh.vars.get(&name).is_some_and(|v| v.array.is_some())) {
                sh.set_var(&name, &v);
            }
        }
        if on.contains(&b'r') {
            sh.vars.entry(name).or_default().readonly = true;
        }
    }
    Ok(st)
}

fn shift(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let n = match a.get(1) {
        None => 1,
        Some(v) => match parse_num::<usize>(v) {
            Some(n) => n,
            None => {
                err("shift", alloc::format!("{}: numeric argument required", text(v)));
                return Ok(1);
            }
        },
    };
    if n > sh.positional.len() {
        if sh.shopt("shift_verbose") {
            err("shift", alloc::format!("{n}: shift count out of range"));
        }
        return Ok(1);
    }
    sh.positional.drain(..n);
    Ok(0)
}

fn let_(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if a.len() < 2 {
        err("let", "expression expected");
        return Ok(1);
    }
    let mut last = 0;
    for e in &a[1..] {
        match crate::arith::eval(e, sh) {
            Ok(v) => last = v,
            Err(m) => {
                err("let", alloc::format!("{}: {m}", text(e)));
                return Ok(1);
            }
        }
    }
    Ok((last == 0) as i32)
}

// --- options ----------------------------------------------------------------

const LONG_OPTS: &[(&str, char)] = &[
    ("allexport", 'a'),
    ("errexit", 'e'),
    ("ignoreeof", '\0'),
    ("monitor", 'm'),
    ("noclobber", 'C'),
    ("noexec", 'n'),
    ("noglob", 'f'),
    ("nounset", 'u'),
    ("pipefail", '\0'),
    ("verbose", 'v'),
    ("xtrace", 'x'),
];

fn opt_ref<'a>(sh: &'a mut Shell, name: &str) -> Option<&'a mut bool> {
    let o = &mut sh.opts;
    Some(match name {
        "allexport" => &mut o.allexport,
        "errexit" => &mut o.errexit,
        "ignoreeof" => &mut o.ignoreeof,
        "monitor" => &mut o.monitor,
        "noclobber" => &mut o.noclobber,
        "noexec" => &mut o.noexec,
        "noglob" => &mut o.noglob,
        "nounset" => &mut o.nounset,
        "pipefail" => &mut o.pipefail,
        "verbose" => &mut o.verbose,
        "xtrace" => &mut o.xtrace,
        _ => return None,
    })
}

fn letter_opt(c: u8) -> Option<&'static str> {
    LONG_OPTS.iter().find(|(_, l)| *l == c as char && c != 0).map(|(n, _)| *n)
}

/// `[[ -o name ]]` and `set -o` reports.
pub fn option_value(sh: &mut Shell, name: &[u8]) -> Option<bool> {
    opt_ref(sh, &text(name)).map(|b| *b)
}

/// Set a single-letter option (`set -e`, `chalk -x`).
pub fn set_letter(sh: &mut Shell, c: u8, on: bool) -> bool {
    match letter_opt(c).and_then(|n| opt_ref(sh, n)) {
        Some(b) => {
            *b = on;
            true
        }
        None => false,
    }
}

pub fn set_long(sh: &mut Shell, name: &[u8], on: bool) -> bool {
    let name = text(name);
    match opt_ref(sh, &name) {
        Some(b) => {
            *b = on;
            if name == "monitor" {
                sh.setup_job_control(on);
            }
            true
        }
        None => false,
    }
}

fn set(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if a.len() == 1 {
        print_vars(sh, "", |_| true);
        return Ok(0);
    }
    let mut i = 1;
    while let Some(arg) = a.get(i) {
        let on = match arg.first() {
            Some(b'-') => true,
            Some(b'+') => false,
            _ => break,
        };
        if arg.as_slice() == b"--" {
            i += 1;
            sh.positional = a[i..].to_vec();
            return Ok(0);
        }
        if arg.as_slice() == b"-" {
            sh.opts.xtrace = false;
            sh.opts.verbose = false;
            i += 1;
            break;
        }
        for &c in &arg[1..] {
            if c == b'o' {
                i += 1;
                match a.get(i) {
                    None => {
                        let mut out = String::new();
                        for (n, _) in LONG_OPTS {
                            let v = opt_ref(sh, n).is_some_and(|b| *b);
                            if on {
                                out.push_str(&alloc::format!("{n:<15}\t{}\n", if v { "on" } else { "off" }));
                            } else {
                                out.push_str(&alloc::format!("set {}o {n}\n", if v { '-' } else { '+' }));
                            }
                        }
                        io::out(out.as_bytes());
                        return Ok(0);
                    }
                    Some(name) => {
                        if !set_long(sh, name, on) {
                            err("set", alloc::format!("{}: invalid option name", text(name)));
                            return Ok(2);
                        }
                    }
                }
            } else if c == b'm' {
                sh.opts.monitor = on;
                sh.setup_job_control(on);
            } else if !set_letter(sh, c, on) {
                err("set", alloc::format!("-{}: invalid option", c as char));
                return Ok(2);
            }
        }
        i += 1;
    }
    if i < a.len() {
        sh.positional = a[i..].to_vec();
    }
    Ok(0)
}

fn getopts(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (Some(spec), Some(var)) = (a.get(1), a.get(2)) else {
        err("getopts", "usage: getopts optstring name [arg ...]");
        return Ok(2);
    };
    let args: Vec<Vec<u8>> = if a.len() > 3 { a[3..].to_vec() } else { sh.positional.clone() };
    let silent = spec.first() == Some(&b':');
    let spec = if silent { &spec[1..] } else { &spec[..] };
    let mut optind = sh.get_var(b"OPTIND").and_then(|v| parse_num::<usize>(&v)).unwrap_or(1).max(1);
    if optind == 1 && sh.getopts_last_ind != 1 {
        sh.getopts_pos = 0;
    }
    let finish = |sh: &mut Shell, optind: usize| {
        sh.getopts_last_ind = optind;
        sh.set_var(b"OPTIND", alloc::format!("{optind}").as_bytes());
    };
    let Some(cur) = args.get(optind - 1) else {
        sh.set_var(var, b"?");
        finish(sh, optind);
        return Ok(1);
    };
    if sh.getopts_pos == 0 {
        if cur.as_slice() == b"--" {
            sh.set_var(var, b"?");
            finish(sh, optind + 1);
            return Ok(1);
        }
        if cur.len() < 2 || cur[0] != b'-' {
            sh.set_var(var, b"?");
            finish(sh, optind);
            return Ok(1);
        }
        sh.getopts_pos = 1;
    }
    let c = cur[sh.getopts_pos];
    sh.getopts_pos += 1;
    let at_end = sh.getopts_pos >= cur.len();
    let known = spec.iter().position(|&x| x == c && x != b':');
    let takes = known.is_some_and(|k| spec.get(k + 1) == Some(&b':'));
    sh.unset_var(b"OPTARG");
    match known {
        None => {
            if silent {
                sh.set_var(b"OPTARG", &[c]);
            } else {
                err("getopts", alloc::format!("illegal option -- {}", c as char));
            }
            sh.set_var(var, b"?");
        }
        Some(_) if takes => {
            let value = if !at_end {
                Some(cur[sh.getopts_pos..].to_vec())
            } else {
                optind += 1;
                args.get(optind - 1).cloned()
            };
            sh.getopts_pos = 0;
            optind += 1;
            match value {
                Some(v) => {
                    sh.set_var(b"OPTARG", &v);
                    sh.set_var(var, &[c]);
                }
                None => {
                    optind -= 1;
                    if silent {
                        sh.set_var(b"OPTARG", &[c]);
                        sh.set_var(var, b":");
                    } else {
                        err("getopts", alloc::format!("option requires an argument -- {}", c as char));
                        sh.set_var(var, b"?");
                    }
                }
            }
            finish(sh, optind);
            return Ok(0);
        }
        Some(_) => {
            sh.set_var(var, &[c]);
        }
    }
    if at_end {
        sh.getopts_pos = 0;
        optind += 1;
    }
    finish(sh, optind);
    Ok(0)
}

// --- directories --------------------------------------------------------------

/// `.` and `..` resolved textually (cd -L).
fn normalize(path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in path.split(|&c| c == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = Vec::new();
    for p in parts {
        out.push(b'/');
        out.extend_from_slice(p);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

fn cd(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut physical = false;
    let mut i = 1;
    while let Some(o) = a.get(i) {
        match o.as_slice() {
            b"-L" => physical = false,
            b"-P" => physical = true,
            b"--" => {
                i += 1;
                break;
            }
            _ => break,
        }
        i += 1;
    }
    let mut print = false;
    let target = match a.get(i).map(Vec::as_slice) {
        None => match sh.get_var(b"HOME") {
            Some(h) if !h.is_empty() => h,
            _ => {
                err("cd", "HOME not set");
                return Ok(1);
            }
        },
        Some(b"-") => match sh.get_var(b"OLDPWD") {
            Some(o) => {
                print = true;
                o
            }
            None => {
                err("cd", "OLDPWD not set");
                return Ok(1);
            }
        },
        Some(d) => d.to_vec(),
    };
    // CDPATH applies to relative names not starting with . or ..
    let mut candidates = Vec::new();
    if target[0] != b'/'
        && !target.starts_with(b"./")
        && !target.starts_with(b"../")
        && target != b"."
        && target != b".."
        && let Some(cdpath) = sh.get_var(b"CDPATH")
    {
        for d in cdpath.split(|&c| c == b':').filter(|d| !d.is_empty()) {
            candidates.push((fs::join(d, &target), true));
        }
    }
    candidates.push((target.clone(), false));
    let pwd = sh.get_var(b"PWD").filter(|p| p.starts_with(b"/")).or_else(|| fs::getcwd().ok()).unwrap_or_default();
    let mut last_err = None;
    for (cand, from_cdpath) in candidates {
        let logical = if cand.starts_with(b"/") { normalize(&cand) } else { normalize(&fs::join(&pwd, &cand)) };
        let attempt = if physical { cand.clone() } else { logical.clone() };
        match fs::chdir(&attempt) {
            Ok(()) => {
                let new = if physical { fs::getcwd().unwrap_or(logical) } else { logical };
                sh.set_var(b"OLDPWD", &pwd);
                sh.set_var(b"PWD", &new);
                if print || from_cdpath {
                    io::out(&[new.as_slice(), b"\n"].concat());
                }
                return Ok(0);
            }
            Err(e) => last_err = Some(e),
        }
    }
    err("cd", alloc::format!("{}: {}", text(&target), last_err.unwrap_or(slate_rt::Errno::ENOENT)));
    Ok(1)
}

fn pwd(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let physical = a.iter().skip(1).any(|x| x == b"-P");
    let cwd = match fs::getcwd() {
        Ok(c) => c,
        Err(e) => {
            err("pwd", e);
            return Ok(1);
        }
    };
    let logical = sh.get_var(b"PWD").filter(|p| {
        p.starts_with(b"/")
            && fs::stat(p).ok().zip(fs::stat(b".").ok()).is_some_and(|(a, b)| a.ino == b.ino && a.dev == b.dev)
    });
    let out = if physical { cwd } else { logical.unwrap_or(cwd) };
    io::out(&[out.as_slice(), b"\n"].concat());
    Ok(0)
}

fn umask(_: &mut Shell, a: &[Vec<u8>]) -> Res {
    let symbolic = a.get(1).map(Vec::as_slice) == Some(b"-S");
    let arg = a.iter().skip(1).find(|x| x.as_slice() != b"-S");
    let Some(m) = arg else {
        let cur = fs::umask(0);
        fs::umask(cur);
        if symbolic {
            let p = |shift: u32| {
                let bits = !cur >> shift & 7;
                let mut s = String::new();
                for (b, c) in [(4, 'r'), (2, 'w'), (1, 'x')] {
                    if bits & b != 0 {
                        s.push(c);
                    }
                }
                s
            };
            io::out(alloc::format!("u={},g={},o={}\n", p(6), p(3), p(0)).as_bytes());
        } else {
            io::out(alloc::format!("{cur:04o}\n").as_bytes());
        }
        return Ok(0);
    };
    match u32::from_str_radix(&text(m), 8) {
        Ok(v) if v <= 0o777 => {
            fs::umask(v);
            Ok(0)
        }
        _ => {
            // Symbolic modes: the bits a mode string leaves allowed.
            let cur = fs::umask(0);
            match slate_coreutils::fileops::apply_mode(m, 0o777 & !cur, true, 0) {
                Some(allowed) => {
                    fs::umask(0o777 & !allowed);
                    Ok(0)
                }
                None => {
                    fs::umask(cur);
                    err("umask", alloc::format!("{}: invalid mode", text(m)));
                    Ok(1)
                }
            }
        }
    }
}

// --- read -----------------------------------------------------------------------

fn read(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut raw = false;
    let mut prompt = None;
    let mut delim = b'\n';
    let mut nchars: Option<usize> = None;
    let mut silent = false;
    let mut fd = 0;
    let mut array: Option<Vec<u8>> = None;
    let mut timeout: Option<i64> = None;
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-') {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        let mut k = 1;
        while k < o.len() {
            let c = o[k];
            let mut value = || -> Option<Vec<u8>> {
                if k + 1 < o.len() {
                    let v = o[k + 1..].to_vec();
                    k = o.len();
                    Some(v)
                } else {
                    i += 1;
                    a.get(i).cloned()
                }
            };
            match c {
                b'r' => raw = true,
                b's' => silent = true,
                b'p' => prompt = value(),
                b'd' => delim = value().and_then(|v| v.first().copied()).unwrap_or(0),
                b'n' | b'N' => nchars = value().and_then(|v| parse_num(&v)),
                b'u' => fd = value().and_then(|v| parse_num(&v)).unwrap_or(0),
                b'a' => array = value(),
                b't' => {
                    let v = value().unwrap_or_default();
                    match core::str::from_utf8(&v).ok().and_then(|t| t.parse::<f64>().ok()).filter(|t| *t >= 0.0) {
                        Some(t) => timeout = Some((t * 1000.0) as i64),
                        None => {
                            err("read", alloc::format!("{}: invalid timeout specification", text(&v)));
                            return Ok(1);
                        }
                    }
                }
                _ => {
                    err("read", alloc::format!("-{}: invalid option", c as char));
                    return Ok(2);
                }
            }
            k += 1;
        }
        i += 1;
    }
    let names: Vec<Vec<u8>> = if i < a.len() { a[i..].to_vec() } else { alloc::vec![b"REPLY".to_vec()] };
    if let Some(p) = prompt
        && slate_rt::term::isatty(fd)
    {
        io::err(&p);
    }
    let saved_tty = if silent { slate_rt::term::get(fd).ok() } else { None };
    if let Some(t) = saved_tty {
        let mut q = t;
        q.lflag &= !slate_rt::term::ECHO;
        let _ = slate_rt::term::set(fd, &q, false);
    }
    // Bytes with "escaped" flags (escaped bytes never split).
    let mut line: Vec<(u8, bool)> = Vec::new();
    let mut got_delim = false;
    let mut b = [0u8; 1];
    // -t: a deadline for the whole line; -t 0 only asks whether input is
    // there.
    let deadline = timeout.map(|ms| now_ms() + ms);
    let ready = |fd: i32| -> bool {
        let Some(d) = deadline else { return true };
        let left = (d - now_ms()).max(0);
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        io::poll(&mut p, left as i32).unwrap_or(0) > 0
    };
    if timeout == Some(0) {
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        return Ok(if io::poll(&mut p, 0).unwrap_or(0) > 0 { 0 } else { 1 });
    }
    let mut timed_out = false;
    // Ctrl-C at the prompt, or a trapped signal, ends the read (bash);
    // waiting is in slices so a restarted call cannot hide it.
    let watched = |sh: &Shell| {
        (1..64).find(|&s| {
            signal::pending(s)
                && (sh.traps.get(&s).is_some_and(|a| !a.is_empty()) || s == signal::SIGINT && sh.interactive)
        })
    };
    let watching = sh.interactive || sh.traps.values().any(|a| !a.is_empty());
    let mut interrupted = None;
    loop {
        if nchars.is_some_and(|n| line.len() >= n) {
            got_delim = true;
            break;
        }
        if watching {
            loop {
                if let Some(s) = watched(sh) {
                    interrupted = Some(s);
                    break;
                }
                let left = deadline.map_or(250, |d| (d - now_ms()).clamp(0, 250));
                let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
                match io::poll(&mut p, left as i32) {
                    Ok(0) if deadline.is_some_and(|d| now_ms() >= d) => break,
                    Ok(0) | Err(slate_rt::Errno::EINTR) => {}
                    _ => break,
                }
            }
            if interrupted.is_some() {
                break;
            }
        }
        if !ready(fd) {
            timed_out = true;
            break;
        }
        match io::read(fd, &mut b) {
            Ok(1) => {}
            _ => break,
        }
        let c = b[0];
        if c == delim {
            got_delim = true;
            break;
        }
        if c == b'\\' && !raw {
            match io::read(fd, &mut b) {
                Ok(1) if b[0] == b'\n' => continue,
                Ok(1) => line.push((b[0], true)),
                _ => break,
            }
            continue;
        }
        line.push((c, false));
    }
    if let Some(t) = saved_tty {
        let _ = slate_rt::term::set(fd, &t, false);
        if silent {
            io::err(b"\n");
        }
    }
    if let Some(s) = interrupted {
        if s == signal::SIGINT && sh.interactive && !sh.traps.contains_key(&s) {
            signal::take();
            return Err(Flow::Interrupt);
        }
        sh.run_traps()?;
        return Ok(128 + s);
    }
    let ifs = sh.get_var(b"IFS").unwrap_or_else(|| b" \t\n".to_vec());
    if let Some(arr) = array {
        let fields = read_split(&line, &ifs, usize::MAX);
        if !crate::parser::is_name(&arr) {
            err("read", alloc::format!("'{}': not a valid identifier", text(&arr)));
            return Ok(2);
        }
        sh.assign_array(&arr, fields.into_iter().map(|f| (None, f)).collect(), false);
        return Ok(if timed_out {
            142
        } else if got_delim {
            0
        } else {
            1
        });
    }
    let fields = read_split(&line, &ifs, names.len());
    for (k, n) in names.iter().enumerate() {
        let v = fields.get(k).cloned().unwrap_or_default();
        if !crate::parser::is_name(n) {
            err("read", alloc::format!("'{}': not a valid identifier", text(n)));
            return Ok(2);
        }
        sh.set_var(n, &v);
    }
    // bash: 128 + SIGALRM on a timeout.
    Ok(if timed_out {
        142
    } else if got_delim {
        0
    } else {
        1
    })
}

fn now_ms() -> i64 {
    let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
    s * 1000 + ns / 1_000_000
}

/// Split a line for `read` into at most `n` fields; the last one keeps the
/// rest (minus trailing IFS white space).
pub fn read_split(line: &[(u8, bool)], ifs: &[u8], n: usize) -> Vec<Vec<u8>> {
    let delim = |x: &(u8, bool)| !x.1 && ifs.contains(&x.0);
    let white = |x: &(u8, bool)| delim(x) && matches!(x.0, b' ' | b'\t' | b'\n');
    let mut out = Vec::new();
    let mut i = 0;
    let len = line.len();
    while i < len && white(&line[i]) {
        i += 1;
    }
    while i < len {
        if out.len() + 1 == n {
            // The rest, without trailing IFS white space.
            let mut end = len;
            while end > i && white(&line[end - 1]) {
                end -= 1;
            }
            let rest = &line[i..end];
            // A trailing single non-white delimiter is dropped as well.
            let rest = if !rest.is_empty() && delim(&rest[rest.len() - 1]) && !rest[..rest.len() - 1].iter().any(delim)
            {
                &rest[..rest.len() - 1]
            } else {
                rest
            };
            out.push(rest.iter().map(|x| x.0).collect());
            return out;
        }
        let mut f = Vec::new();
        while i < len && !delim(&line[i]) {
            f.push(line[i].0);
            i += 1;
        }
        out.push(f);
        while i < len && white(&line[i]) {
            i += 1;
        }
        if i < len && delim(&line[i]) && !white(&line[i]) {
            i += 1;
            while i < len && white(&line[i]) {
                i += 1;
            }
        }
    }
    out
}

// --- aliases, lookup ------------------------------------------------------------

fn alias(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let show = |n: &[u8], v: &[u8]| io::out(&[b"alias ".as_slice(), n, b"=", &quote(v), b"\n"].concat());
    if a.len() == 1 {
        for (n, v) in &sh.aliases {
            show(n, v);
        }
        return Ok(0);
    }
    let mut st = 0;
    for arg in &a[1..] {
        match arg.iter().position(|&c| c == b'=') {
            Some(eq) => {
                sh.aliases.insert(arg[..eq].to_vec(), arg[eq + 1..].to_vec());
                sh.alias_gen += 1;
            }
            None => match sh.aliases.get(arg) {
                Some(v) => show(arg, v),
                None => {
                    err("alias", alloc::format!("{}: not found", text(arg)));
                    st = 1;
                }
            },
        }
    }
    Ok(st)
}

fn unalias(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut st = 0;
    for arg in &a[1..] {
        if arg.as_slice() == b"-a" {
            sh.aliases.clear();
        } else if sh.aliases.remove(arg).is_none() {
            err("unalias", alloc::format!("{}: not found", text(arg)));
            st = 1;
        }
    }
    sh.alias_gen += 1;
    Ok(st)
}

/// What a name runs as: (kind, detail).
enum Kind {
    Alias(Vec<u8>),
    Keyword,
    Function,
    Builtin(bool),
    File(Vec<u8>),
}

fn classify(sh: &mut Shell, name: &[u8], functions: bool) -> Option<Kind> {
    if functions {
        if let Some(v) = sh.aliases.get(name) {
            return Some(Kind::Alias(v.clone()));
        }
        if KEYWORDS.iter().any(|k| k.as_bytes() == name) {
            return Some(Kind::Keyword);
        }
        if sh.functions.contains_key(name) {
            return Some(Kind::Function);
        }
    }
    if find(name).is_some() {
        return Some(Kind::Builtin(is_special(name)));
    }
    let p = sh.lookup(name)?;
    fs::stat(&p).is_ok_and(|s| !s.is_dir() && s.mode & 0o111 != 0).then_some(Kind::File(p))
}

/// type [-afptP] name...: how each name would run (-t: one word for
/// it, -p/-P: the file only, -a: every way).
fn type_(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut all, mut word, mut path, mut force_path, mut no_funcs) = (false, false, false, false, false);
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-') {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        for &c in &o[1..] {
            match c {
                b'a' => all = true,
                b't' => word = true,
                b'p' => path = true,
                b'P' => force_path = true,
                b'f' => no_funcs = true,
                _ => {
                    err("type", alloc::format!("-{}: invalid option", c as char));
                    return Ok(2);
                }
            }
        }
        i += 1;
    }
    let mut st = 0;
    for n in &a[i..] {
        let mut kinds = Vec::new();
        if !force_path {
            if let Some(v) = sh.aliases.get(n.as_slice()) {
                kinds.push(Kind::Alias(v.clone()));
            }
            if KEYWORDS.iter().any(|k| k.as_bytes() == n.as_slice()) {
                kinds.push(Kind::Keyword);
            }
            if !no_funcs && sh.functions.contains_key(n.as_slice()) {
                kinds.push(Kind::Function);
            }
            if find(n).is_some() {
                kinds.push(Kind::Builtin(is_special(n)));
            }
        }
        // Files: the first on PATH, or with -a each of them.
        if n.contains(&b'/') {
            if fs::stat(n).is_ok_and(|s| !s.is_dir() && s.mode & 0o111 != 0) {
                kinds.push(Kind::File(n.clone()));
            }
        } else {
            let p = sh.get_var(b"PATH").unwrap_or_default();
            for dir in p.split(|&c| c == b':') {
                let cand = fs::join(if dir.is_empty() { b"." } else { dir }, n);
                if fs::stat(&cand).is_ok_and(|s| !s.is_dir() && s.mode & 0o111 != 0) {
                    kinds.push(Kind::File(cand));
                    if !all {
                        break;
                    }
                }
            }
        }
        if !all {
            kinds.truncate(1);
        }
        if kinds.is_empty() {
            if !word && !path && !force_path {
                err("type", alloc::format!("{}: not found", text(n)));
            }
            st = 1;
            continue;
        }
        let mut out = Vec::new();
        for k in kinds {
            let line = match (&k, word, path || force_path) {
                (Kind::File(p), _, true) => text(p),
                (_, _, true) => continue,
                (Kind::Alias(_), true, _) => String::from("alias"),
                (Kind::Keyword, true, _) => String::from("keyword"),
                (Kind::Function, true, _) => String::from("function"),
                (Kind::Builtin(_), true, _) => String::from("builtin"),
                (Kind::File(_), true, _) => String::from("file"),
                (Kind::Alias(v), ..) => alloc::format!("{} is aliased to '{}'", text(n), text(v)),
                (Kind::Keyword, ..) => alloc::format!("{} is a shell keyword", text(n)),
                (Kind::Function, ..) => {
                    let def = sh.functions.get(n.as_slice()).map(|f| crate::print::function(n, f)).unwrap_or_default();
                    alloc::format!("{} is a function\n{}", text(n), text(&def))
                }
                (Kind::Builtin(true), ..) => alloc::format!("{} is a special shell builtin", text(n)),
                (Kind::Builtin(false), ..) => alloc::format!("{} is a shell builtin", text(n)),
                (Kind::File(p), ..) => alloc::format!("{} is {}", text(n), text(p)),
            };
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        io::out(&out);
    }
    Ok(st)
}

fn command(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut i = 1;
    let (mut v, mut big_v) = (false, false);
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-') {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        for &c in &o[1..] {
            match c {
                b'v' => v = true,
                b'V' => big_v = true,
                // -p: the default PATH; ours is the same.
                b'p' => {}
                _ => {
                    err("command", alloc::format!("-{}: invalid option", c as char));
                    return Ok(2);
                }
            }
        }
        i += 1;
    }
    let Some(name) = a.get(i) else { return Ok(0) };
    if big_v {
        return type_(sh, &[b"type".to_vec(), name.clone()]);
    }
    if v {
        let mut st = 1;
        for name in &a[i..] {
            if command_v(sh, name) {
                st = 0;
            }
        }
        return Ok(st);
    }
    let argv = &a[i..];
    if let Some(b) = find(name) {
        return b(sh, argv);
    }
    let label = || text(&argv.join(&b' '));
    Ok(sh.fork_job(&|sh: &mut Shell| Ok(sh.exec(argv, &[])), &label))
}

/// `command -v name`: how the shell would run it.
fn command_v(sh: &mut Shell, name: &[u8]) -> bool {
    let line = match classify(sh, name, true) {
        Some(Kind::Alias(val)) => [b"alias ".as_slice(), name, b"=", &quote(&val)].concat(),
        Some(Kind::File(p)) => p,
        Some(_) => name.to_vec(),
        None => return false,
    };
    io::out(&[line.as_slice(), b"\n"].concat());
    true
}

fn history(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if a.get(1).map(Vec::as_slice) == Some(b"-c") {
        sh.history.clear();
        return Ok(0);
    }
    let n = a.get(1).and_then(|v| parse_num::<usize>(v)).unwrap_or(sh.history.len());
    let start = sh.history.len().saturating_sub(n);
    let mut out = Vec::new();
    for (k, h) in sh.history.iter().enumerate().skip(start) {
        out.extend_from_slice(alloc::format!("{:5}  ", k + 1).as_bytes());
        out.extend_from_slice(h);
        out.push(b'\n');
    }
    io::out(&out);
    Ok(0)
}

// --- traps ------------------------------------------------------------------------

fn signal_number(s: &[u8]) -> Option<i32> {
    match s {
        b"EXIT" | b"0" => Some(0),
        _ => signal::by_name(&text(s).to_ascii_uppercase()),
    }
}

fn signal_name(n: i32) -> String {
    if n == 0 {
        return String::from("EXIT");
    }
    alloc::format!("SIG{}", signal::NAMES.get(n as usize).copied().unwrap_or("?"))
}

fn trap(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let mut i = 1;
    if a.get(i).map(Vec::as_slice) == Some(b"--") {
        i += 1;
    }
    match a.get(i).map(Vec::as_slice) {
        None | Some(b"-p") => {
            let mut out = Vec::new();
            let traps = sh.parent_traps.as_ref().unwrap_or(&sh.traps);
            let only: Vec<i32> = a[i..].iter().skip(1).filter_map(|s| signal_number(s)).collect();
            for (s, act) in traps.iter().filter(|(s, _)| only.is_empty() || only.contains(s)) {
                out.extend_from_slice(b"trap -- ");
                out.extend_from_slice(&quote(act));
                out.push(b' ');
                out.extend_from_slice(signal_name(*s).as_bytes());
                out.push(b'\n');
            }
            io::out(&out);
            return Ok(0);
        }
        Some(b"-l") => {
            let mut out = String::new();
            for (n, name) in signal::NAMES.iter().enumerate().skip(1) {
                out.push_str(&alloc::format!("{n:2}) SIG{name}\n"));
            }
            io::out(out.as_bytes());
            return Ok(0);
        }
        _ => {}
    }
    let first = &a[i];
    // A lone number, or `-`, resets (§2.14 trap).
    let (action, sigs) = if signal_number(first).is_some() && first.iter().all(u8::is_ascii_digit) || a.len() == i + 1 {
        (None, &a[i..])
    } else if first.as_slice() == b"-" {
        (None, &a[i + 1..])
    } else {
        (Some(first.clone()), &a[i + 1..])
    };
    let mut st = 0;
    sh.parent_traps = None;
    for s in sigs {
        let Some(n) = signal_number(s) else {
            err("trap", alloc::format!("{}: invalid signal specification", text(s)));
            st = 1;
            continue;
        };
        if n == signal::SIGKILL || n == signal::SIGSTOP {
            continue;
        }
        // A signal ignored when a script started stays ignored (§2.11).
        if n > 0 && !sh.interactive && sh.ignored_at_start & (1 << n) != 0 {
            continue;
        }
        match &action {
            None => {
                sh.traps.remove(&n);
                if n > 0 {
                    let keep = sh.interactive && matches!(n, signal::SIGINT | signal::SIGQUIT | signal::SIGTERM);
                    let d = if keep && n == signal::SIGINT {
                        signal::Disposition::Catch
                    } else if keep {
                        signal::Disposition::Ignore
                    } else {
                        signal::Disposition::Default
                    };
                    let _ = signal::set(n, d);
                }
            }
            Some(act) => {
                sh.traps.insert(n, act.clone());
                if n > 0 {
                    let d = if act.is_empty() { signal::Disposition::Ignore } else { signal::Disposition::Catch };
                    let _ = signal::set(n, d);
                }
            }
        }
    }
    Ok(st)
}

// --- jobs ---------------------------------------------------------------------------

fn job_arg(sh: &mut Shell, name: &str, a: &[Vec<u8>]) -> Option<usize> {
    sh.jobs.poll();
    let spec = a.get(1).map_or(&b"%+"[..], |v| v.as_slice());
    let id = if spec.starts_with(b"%") {
        sh.jobs.find(spec)
    } else {
        parse_num::<i32>(spec).and_then(|p| sh.jobs.by_pid(p)).or_else(|| sh.jobs.find(spec))
    };
    if id.is_none() {
        err(name, alloc::format!("{}: no such job", text(spec)));
    }
    id
}

fn jobs(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    sh.jobs.poll();
    let pids_only = a.iter().any(|x| x == b"-p");
    let long = a.iter().any(|x| x == b"-l");
    let mut out = String::new();
    for j in &sh.jobs.list {
        if pids_only {
            out.push_str(&alloc::format!("{}\n", j.last_pid()));
            continue;
        }
        let pid = if long { alloc::format!("{} ", j.last_pid()) } else { String::new() };
        let amp = if j.state == State::Running { " &" } else { "" };
        out.push_str(&alloc::format!(
            "[{}]{}  {pid}{:<24}{}{amp}\n",
            j.id,
            sh.jobs.mark(j.id),
            describe_state(j.state),
            j.label
        ));
    }
    io::out(out.as_bytes());
    // Reported finished jobs are forgotten.
    let done: Vec<usize> = sh.jobs.list.iter().filter(|j| matches!(j.state, State::Done(_))).map(|j| j.id).collect();
    for id in done {
        sh.jobs.remove(id);
    }
    Ok(0)
}

fn fg(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if sh.tty.is_none() || !sh.opts.monitor {
        err("fg", "no job control");
        return Ok(1);
    }
    let Some(id) = job_arg(sh, "fg", a) else { return Ok(1) };
    let Some(job) = sh.jobs.remove(id) else { return Ok(1) };
    io::out(alloc::format!("{}\n", job.label).as_bytes());
    io::flush_stdout();
    let _ = process::kill(-job.pgid, signal::SIGCONT);
    let pids: Vec<i32> = job.pids.iter().filter(|p| p.1.is_none()).map(|p| p.0).collect();
    if pids.is_empty() {
        return Ok(job.pids.last().and_then(|p| p.1).map_or(0, process::exit_code));
    }
    let label = || job.label.clone();
    Ok(sh.wait_fg(&pids, job.pgid, &label))
}

fn bg(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if sh.tty.is_none() || !sh.opts.monitor {
        err("bg", "no job control");
        return Ok(1);
    }
    let Some(id) = job_arg(sh, "bg", a) else { return Ok(1) };
    let mark = sh.jobs.mark(id);
    if let Some(j) = sh.jobs.list.iter_mut().find(|j| j.id == id) {
        let _ = process::kill(-j.pgid, signal::SIGCONT);
        j.state = State::Running;
        io::out(alloc::format!("[{}]{mark} {} &\n", j.id, j.label).as_bytes());
    }
    Ok(0)
}

fn disown(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let Some(id) = job_arg(sh, "disown", a) else { return Ok(1) };
    sh.jobs.remove(id);
    Ok(0)
}

fn wait(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if a.len() < 2 {
        let ids: Vec<usize> = sh.jobs.list.iter().map(|j| j.id).collect();
        for id in ids {
            sh.jobs.wait(id);
            sh.jobs.remove(id);
        }
        return Ok(0);
    }
    let mut st = 0;
    for spec in &a[1..] {
        let id = if spec.starts_with(b"%") {
            sh.jobs.find(spec)
        } else {
            match parse_num::<i32>(spec) {
                Some(p) => sh.jobs.by_pid(p),
                None => {
                    err("wait", alloc::format!("'{}': not a pid or valid job spec", text(spec)));
                    st = 2;
                    continue;
                }
            }
        };
        st = match id {
            Some(id) => {
                let s = sh.jobs.wait(id).unwrap_or(0);
                sh.jobs.remove(id);
                process::exit_code(s)
            }
            None => 127,
        };
    }
    Ok(st)
}

fn kill(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    sh.jobs.poll();
    let mut sig = signal::SIGTERM;
    let mut i = 1;
    match a.get(1).map(Vec::as_slice) {
        Some(b"-l" | b"-L") => return Ok(slate_coreutils::sysutil::kill(a)),
        Some(b"-s" | b"-n") => {
            let Some(n) = a.get(2).and_then(|n| signal::by_name(&text(n).to_ascii_uppercase())) else {
                err("kill", "invalid signal specification");
                return Ok(1);
            };
            sig = n;
            i = 3;
        }
        Some(o) if o.len() > 1 && o[0] == b'-' && o != b"--" => {
            let Some(n) = signal::by_name(&text(&o[1..]).to_ascii_uppercase()) else {
                err("kill", alloc::format!("{}: invalid signal specification", text(&o[1..])));
                return Ok(1);
            };
            sig = n;
            i = 2;
        }
        _ => {}
    }
    if a.get(i).map(Vec::as_slice) == Some(b"--") {
        i += 1;
    }
    if i >= a.len() {
        err("kill", "usage: kill [-s sigspec | -signum | -sigspec] pid | jobspec ...");
        return Ok(2);
    }
    let mut st = 0;
    for x in &a[i..] {
        let pid = if x.starts_with(b"%") {
            match sh.jobs.find(x).and_then(|id| sh.jobs.list.iter().find(|j| j.id == id)) {
                Some(j) if j.pgid != 0 => -j.pgid,
                Some(j) => j.last_pid(),
                None => {
                    err("kill", alloc::format!("{}: no such job", text(x)));
                    st = 1;
                    continue;
                }
            }
        } else {
            match parse_num::<i32>(x) {
                Some(p) => p,
                None => {
                    err("kill", alloc::format!("{}: arguments must be process or job IDs", text(x)));
                    st = 1;
                    continue;
                }
            }
        };
        if let Err(e) = process::kill(pid, sig) {
            err("kill", alloc::format!("({}) - {e}", text(x)));
            st = 1;
        }
    }
    Ok(st)
}

// --- shopt -------------------------------------------------------------------------

/// shopt [-pqsu] [-o] [name ...] (bash): its options, or set's with -o.
fn shopt(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut set, mut unset, mut quiet, mut print, mut long) = (false, false, false, false, false);
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-') {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        for &c in &o[1..] {
            match c {
                b's' => set = true,
                b'u' => unset = true,
                b'q' => quiet = true,
                b'p' => print = true,
                b'o' => long = true,
                _ => {
                    err("shopt", alloc::format!("-{}: invalid option", c as char));
                    io::err(b"shopt: usage: shopt [-pqsu] [-o] [optname ...]\n");
                    return Ok(2);
                }
            }
        }
        i += 1;
    }
    if set && unset {
        err("shopt", "cannot set and unset shell options simultaneously");
        return Ok(1);
    }
    let names: Vec<String> = if long {
        LONG_OPTS.iter().map(|(n, _)| String::from(*n)).collect()
    } else {
        crate::shell::SHOPTS.iter().map(|(n, _)| String::from(*n)).collect()
    };
    let get = |sh: &mut Shell, n: &str| if long { opt_ref(sh, n).map(|b| *b) } else { Some(sh.shopt(n)) };
    let show = |sh: &mut Shell, n: &str, out: &mut String| {
        let on = get(sh, n).unwrap_or(false);
        if print {
            let flag = if on { "-s" } else { "-u" };
            out.push_str(&if long {
                alloc::format!("set {}o {n}\n", if on { '-' } else { '+' })
            } else {
                alloc::format!("shopt {flag} {n}\n")
            });
        } else if long {
            out.push_str(&alloc::format!("{n:<15}\t{}\n", if on { "on" } else { "off" }));
        } else {
            out.push_str(&alloc::format!("{n:<20}\t{}\n", if on { "on" } else { "off" }));
        }
    };
    let mut out = String::new();
    if i >= a.len() {
        // A listing: everything, or with -s / -u the options on / off.
        for n in &names {
            let on = get(sh, n).unwrap_or(false);
            if (set && !on) || (unset && on) {
                continue;
            }
            if !quiet {
                show(sh, n, &mut out);
            }
        }
        io::out(out.as_bytes());
        return Ok(0);
    }
    let mut st = 0;
    for arg in &a[i..] {
        let n = text(arg);
        if !names.contains(&n) {
            err("shopt", alloc::format!("{n}: invalid shell option name"));
            st = 1;
            continue;
        }
        if set || unset {
            if long {
                set_long(sh, arg, set);
            } else if matches!(n.as_str(), "login_shell" | "restricted_shell") {
                err("shopt", alloc::format!("{n}: cannot set"));
                st = 1;
            } else {
                sh.set_shopt(&n, set);
                if n == "expand_aliases" {
                    sh.alias_gen += 1;
                }
            }
            continue;
        }
        if !get(sh, &n).unwrap_or(false) {
            st = 1;
        }
        if !quiet {
            show(sh, &n, &mut out);
        }
    }
    io::out(out.as_bytes());
    Ok(st)
}

// --- fc ----------------------------------------------------------------------------

/// A history position: a number (negative: back from the current
/// command), or the newest earlier command starting with the text.
/// History numbers start at 1; the current command is the last.
fn history_index(sh: &Shell, spec: &[u8]) -> Option<usize> {
    let cur = sh.history.len();
    if let Some(n) = parse_num::<i64>(spec) {
        let i = if n < 0 { cur as i64 + n } else { n };
        return Some(i.clamp(1, cur.saturating_sub(1).max(1) as i64) as usize);
    }
    (1..cur).rev().find(|&i| sh.history[i - 1].starts_with(spec))
}

/// fc (POSIX, with bash's details): list (-l), re-run with a change (-s
/// old=new), or edit commands and run them.
fn fc(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut list, mut numbers, mut reverse, mut again) = (false, true, false, false);
    let mut editor: Option<Vec<u8>> = None;
    let mut i = 1;
    while let Some(o) = a.get(i).filter(|o| o.len() > 1 && o[0] == b'-' && !o[1].is_ascii_digit()) {
        if o.as_slice() == b"--" {
            i += 1;
            break;
        }
        for &c in &o[1..] {
            match c {
                b'l' => list = true,
                b'n' => numbers = false,
                b'r' => reverse = true,
                b's' => again = true,
                b'e' => {
                    i += 1;
                    editor = a.get(i).cloned();
                    if editor.is_none() {
                        err("fc", "-e: option requires an argument");
                        return Ok(2);
                    }
                }
                _ => {
                    err("fc", alloc::format!("-{}: invalid option", c as char));
                    return Ok(2);
                }
            }
        }
        i += 1;
    }
    if editor.as_deref() == Some(b"-") {
        again = true;
    }
    if sh.history.is_empty() {
        err("fc", "no command found");
        return Ok(1);
    }
    let cur = sh.history.len();
    if again {
        let mut changes: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        while let Some(c) = a.get(i).filter(|c| c.contains(&b'=')) {
            let eq = c.iter().position(|&x| x == b'=').unwrap_or(0);
            changes.push((c[..eq].to_vec(), c[eq + 1..].to_vec()));
            i += 1;
        }
        let at = match a.get(i) {
            Some(spec) => history_index(sh, spec),
            None => (cur > 1).then(|| cur - 1),
        };
        let Some(at) = at else {
            err("fc", "no command found");
            return Ok(1);
        };
        let mut cmd = sh.history[at - 1].clone();
        for (old, new) in &changes {
            cmd = replace_all(&cmd, old, new);
        }
        return fc_run(sh, cmd);
    }
    let first = a.get(i).map(|s| history_index(sh, s));
    let last = a.get(i + 1).map(|s| history_index(sh, s));
    let (first, last) = match (first, last) {
        (Some(None), _) | (_, Some(None)) => {
            err("fc", "history specification out of range");
            return Ok(1);
        }
        (Some(Some(f)), Some(Some(l))) => (f, l),
        (Some(Some(f)), None) => (f, if list { cur.saturating_sub(1).max(1) } else { f }),
        (None, _) if list => (cur.saturating_sub(16).max(1), cur.saturating_sub(1).max(1)),
        (None, _) => (cur.saturating_sub(1).max(1), cur.saturating_sub(1).max(1)),
    };
    let mut range: Vec<usize> = if first <= last { (first..=last).collect() } else { (last..=first).rev().collect() };
    if reverse {
        range.reverse();
    }
    if list {
        let mut out = Vec::new();
        for n in range {
            if numbers {
                out.extend_from_slice(alloc::format!("{n}").as_bytes());
            }
            out.extend_from_slice(b"\t ");
            out.extend_from_slice(&sh.history[n - 1]);
            out.push(b'\n');
        }
        io::out(&out);
        return Ok(0);
    }
    // Edit: the commands in a file, the editor on it, then run what it
    // holds.
    let path = alloc::format!("/tmp/chalk-fc.{}", process::getpid()).into_bytes();
    let mut body = Vec::new();
    for n in range {
        body.extend_from_slice(&sh.history[n - 1]);
        body.push(b'\n');
    }
    // A file of our own: one left behind goes, and a new one is made
    // exclusively (no following a link someone put there).
    let _ = fs::unlink(&path);
    let made = fs::open(&path, fs::O_WRONLY | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600)
        .and_then(|fd| io::write_all(fd, &body).and_then(|()| io::close(fd)));
    if let Err(e) = made {
        err("fc", alloc::format!("{}: {e}", text(&path)));
        return Ok(1);
    }
    let ed = editor
        .or_else(|| sh.get_var(b"FCEDIT"))
        .or_else(|| sh.get_var(b"EDITOR"))
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| b"vi".to_vec());
    let st = sh.eval(&[ed.as_slice(), b" ", &quote(&path)].concat())?;
    let edited = fs::read_file(&path).unwrap_or_default();
    let _ = fs::unlink(&path);
    if st != 0 {
        return Ok(st);
    }
    fc_run(sh, edited)
}

/// Show and run a command fc chose; it takes fc's own place in the
/// history.
fn fc_run(sh: &mut Shell, cmd: Vec<u8>) -> Res {
    let cmd = cmd.strip_suffix(b"\n").unwrap_or(&cmd).to_vec();
    io::err(&[cmd.as_slice(), b"\n"].concat());
    sh.history.pop();
    sh.history.push(cmd.clone());
    sh.eval(&cmd)
}

fn replace_all(s: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    if old.is_empty() {
        return s.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(old) {
            out.extend_from_slice(new);
            i += old.len();
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

// --- builtin, caller, logout ---------------------------------------------------------

/// builtin NAME [args]: the built-in itself, not a function by its name.
fn builtin(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let Some(name) = a.get(1) else { return Ok(0) };
    match find(name) {
        Some(b) => b(sh, &a[1..]),
        None => {
            err("builtin", alloc::format!("{}: not a shell builtin", text(name)));
            Ok(1)
        }
    }
}

/// caller [N]: where the running function (or the Nth one out) was
/// called from: `LINE FILE`, or with N `LINE FUNCTION FILE` (bash).
fn caller(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let file = if sh.script.is_empty() { b"NULL".to_vec() } else { sh.script.clone() };
    let depth = sh.call_lines.len();
    let Some(n) = a.get(1) else {
        // Outside any function bash says `0 NULL`.
        let (line, file) = match sh.call_lines.last() {
            Some(&l) => (l, file),
            None => (0, b"NULL".to_vec()),
        };
        io::out(&[alloc::format!("{line} ").as_bytes(), &file, b"\n"].concat());
        return Ok(0);
    };
    let Some(n) = parse_num::<usize>(n) else {
        err("caller", alloc::format!("{}: invalid number", text(n)));
        return Ok(2);
    };
    if n >= depth {
        return Ok(1);
    }
    let line = sh.call_lines[depth - 1 - n];
    let func = sh
        .funcnames
        .get(n + 1)
        .cloned()
        .unwrap_or_else(|| if sh.source_depth > 0 { b"source".to_vec() } else { b"main".to_vec() });
    io::out(&[alloc::format!("{line} ").as_bytes(), &func, b" ", &file, b"\n"].concat());
    Ok(0)
}

fn logout(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    if !sh.login {
        err("logout", "not login shell: use 'exit'");
        return Ok(1);
    }
    exit(sh, a)
}

// --- the directory stack -------------------------------------------------------------

/// The stack as dirs shows it: the current directory first.
fn dir_list(sh: &mut Shell) -> Vec<Vec<u8>> {
    let pwd = sh.get_var(b"PWD").or_else(|| fs::getcwd().ok()).unwrap_or_default();
    let mut v = alloc::vec![pwd];
    v.extend(sh.dirstack.iter().cloned());
    v
}

/// `~` for the home directory (unless `long`).
fn tilde(sh: &mut Shell, d: &[u8], long: bool) -> Vec<u8> {
    let home = sh.get_var(b"HOME").unwrap_or_default();
    if !long && !home.is_empty() && home != b"/" {
        if d == home.as_slice() {
            return b"~".to_vec();
        }
        if let Some(rest) = d.strip_prefix(home.as_slice())
            && rest.starts_with(b"/")
        {
            return [b"~".as_slice(), rest].concat();
        }
    }
    d.to_vec()
}

/// `+N` / `-N`: an index into the stack, counting from the left or right.
fn stack_index(sh: &mut Shell, spec: &[u8]) -> Option<usize> {
    let len = dir_list(sh).len();
    let n = parse_num::<usize>(&spec[1..])?;
    match spec[0] {
        b'+' if n < len => Some(n),
        b'-' if n < len => Some(len - 1 - n),
        _ => None,
    }
}

fn print_dirs(sh: &mut Shell, long: bool, per_line: bool, numbered: bool) {
    let mut out = Vec::new();
    for (i, d) in dir_list(sh).into_iter().enumerate() {
        let d = tilde(sh, &d, long);
        if numbered {
            out.extend_from_slice(alloc::format!("{i:2}  ").as_bytes());
            out.extend_from_slice(&d);
            out.push(b'\n');
        } else if per_line {
            out.extend_from_slice(&d);
            out.push(b'\n');
        } else {
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(&d);
        }
    }
    if !numbered && !per_line {
        out.push(b'\n');
    }
    io::out(&out);
}

/// dirs [-clpv] [+N | -N] (bash).
fn dirs(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let (mut long, mut per_line, mut numbered) = (false, false, false);
    for o in &a[1..] {
        match o.as_slice() {
            [b'+' | b'-', d, ..] if d.is_ascii_digit() => {
                let Some(i) = stack_index(sh, o) else {
                    err("dirs", alloc::format!("{}: directory stack index out of range", text(o)));
                    return Ok(1);
                };
                let d = dir_list(sh).swap_remove(i);
                let d = tilde(sh, &d, long);
                io::out(&[d.as_slice(), b"\n"].concat());
                return Ok(0);
            }
            b"-c" => {
                sh.dirstack.clear();
                return Ok(0);
            }
            _ if o.starts_with(b"-") => {
                for &c in &o[1..] {
                    match c {
                        b'l' => long = true,
                        b'p' => per_line = true,
                        b'v' => numbered = true,
                        b'c' => sh.dirstack.clear(),
                        _ => {
                            err("dirs", alloc::format!("-{}: invalid option", c as char));
                            return Ok(2);
                        }
                    }
                }
            }
            _ => {
                err("dirs", alloc::format!("{}: invalid argument", text(o)));
                return Ok(2);
            }
        }
    }
    print_dirs(sh, long, per_line, numbered);
    Ok(0)
}

/// Change to `dir` as cd does; true if it worked.
fn chdir_to(sh: &mut Shell, name: &str, dir: &[u8]) -> bool {
    match cd(sh, &[b"cd".to_vec(), dir.to_vec()]) {
        Ok(0) => true,
        _ => {
            let _ = name;
            false
        }
    }
}

/// pushd [-n] [dir | +N | -N] (bash).
fn pushd(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let no_cd = a.iter().skip(1).any(|o| o == b"-n");
    let arg = a.iter().skip(1).find(|o| o.as_slice() != b"-n").cloned();
    match arg {
        None => {
            if sh.dirstack.is_empty() {
                err("pushd", "no other directory");
                return Ok(1);
            }
            let pwd = dir_list(sh).swap_remove(0);
            let top = sh.dirstack[0].clone();
            if !chdir_to(sh, "pushd", &top) {
                return Ok(1);
            }
            sh.dirstack[0] = pwd;
        }
        Some(spec) if matches!(spec.as_slice(), [b'+' | b'-', d, ..] if d.is_ascii_digit()) => {
            let Some(i) = stack_index(sh, &spec) else {
                err("pushd", alloc::format!("{}: directory stack index out of range", text(&spec)));
                return Ok(1);
            };
            // Rotate so that entry i comes first.
            let mut all = dir_list(sh);
            all.rotate_left(i);
            let first = all.remove(0);
            if !chdir_to(sh, "pushd", &first) {
                return Ok(1);
            }
            sh.dirstack = all;
        }
        Some(dir) => {
            let pwd = dir_list(sh).swap_remove(0);
            if no_cd {
                sh.dirstack.insert(0, dir);
            } else {
                if !chdir_to(sh, "pushd", &dir) {
                    return Ok(1);
                }
                sh.dirstack.insert(0, pwd);
            }
        }
    }
    print_dirs(sh, false, false, false);
    Ok(0)
}

/// popd [-n] [+N | -N] (bash).
fn popd(sh: &mut Shell, a: &[Vec<u8>]) -> Res {
    let no_cd = a.iter().skip(1).any(|o| o == b"-n");
    let spec = a.iter().skip(1).find(|o| o.as_slice() != b"-n").cloned();
    if sh.dirstack.is_empty() {
        err("popd", "directory stack empty");
        return Ok(1);
    }
    let i = match &spec {
        Some(s) => match stack_index(sh, s) {
            Some(i) => i,
            None => {
                err("popd", alloc::format!("{}: directory stack index out of range", text(s)));
                return Ok(1);
            }
        },
        None => 0,
    };
    if i == 0 && !no_cd {
        let top = sh.dirstack[0].clone();
        if !chdir_to(sh, "popd", &top) {
            return Ok(1);
        }
        sh.dirstack.remove(0);
    } else if i == 0 {
        sh.dirstack.remove(0);
    } else {
        sh.dirstack.remove(i - 1);
    }
    print_dirs(sh, false, false, false);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell_with_history(h: &[&str]) -> Shell {
        let mut sh = Shell::new();
        sh.history = h.iter().map(|l| l.as_bytes().to_vec()).collect();
        sh
    }

    #[test]
    fn history_positions() {
        // The last entry is the running fc itself.
        let sh = shell_with_history(&["echo a", "echo b", "ls", "fc -l"]);
        assert_eq!(history_index(&sh, b"-1"), Some(3));
        assert_eq!(history_index(&sh, b"-2"), Some(2));
        assert_eq!(history_index(&sh, b"1"), Some(1));
        assert_eq!(history_index(&sh, b"99"), Some(3));
        assert_eq!(history_index(&sh, b"echo"), Some(2));
        assert_eq!(history_index(&sh, b"nothing"), None);
        assert_eq!(replace_all(b"echo aa aa", b"a", b"b"), b"echo bb bb");
    }

    #[test]
    fn shopt_table() {
        let mut sh = Shell::new();
        assert!(sh.shopt("expand_aliases") && !sh.shopt("extglob"));
        assert!(sh.set_shopt("nullglob", true) && sh.shopt("nullglob"));
        assert!(!sh.set_shopt("nonsense", true));
    }
}
