// SPDX-License-Identifier: MIT OR Apache-2.0

//! chalk, Slate's shell: the POSIX.1-2017 shell command language (XCU
//! chapter 2) plus the bash extensions scripts commonly rely on (`[[ ]]`,
//! `(( ))`, `local`, `source`, `${var/pat/rep}`, brace expansion, `&>`,
//! `<<<`, `pipefail`), with job control and a line editor when
//! interactive. Written from the POSIX specification and observed
//! behaviour (ADR 0012); no shell's source was consulted.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod arith;
pub mod arrays;
pub mod ast;
pub mod builtins;
pub mod exec;
pub mod expand;
pub mod glob;
pub mod jobs;
pub mod lineedit;
pub mod parser;
pub mod print;
pub mod shell;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use slate_rt::{fs, io, process, signal, term};

use crate::lineedit::{Editor, Input};
use crate::parser::ParseError;
use crate::shell::{Flow, Shell, text};

/// The name error messages start with (the script's, `$0`), and the
/// line of the command running in a script (0: none, as when
/// interactive).
static ERROR_NAME: slate_rt::sync::Mutex<Vec<u8>> = slate_rt::sync::Mutex::new(Vec::new());
static ERROR_LINE: AtomicUsize = AtomicUsize::new(0);

pub fn set_error_name(name: &[u8]) {
    *ERROR_NAME.lock() = name.to_vec();
}

pub fn set_error_line(line: usize) {
    ERROR_LINE.store(line, Ordering::Relaxed);
}

/// Report an error on standard error, as bash does: `NAME: line N: ...`
/// in scripts, `chalk: ...` at the prompt.
pub fn error(args: core::fmt::Arguments<'_>) {
    io::flush_stdout();
    let name = {
        let n = ERROR_NAME.lock();
        if n.is_empty() { alloc::string::String::from("chalk") } else { shell::text(&n) }
    };
    let msg = match ERROR_LINE.load(Ordering::Relaxed) {
        0 => alloc::format!("{name}: {args}\n"),
        line => alloc::format!("{name}: line {line}: {args}\n"),
    };
    io::err(msg.as_bytes());
}

pub fn syntax_error(e: &ParseError) {
    match e {
        ParseError::Incomplete => error(format_args!("syntax error: unexpected end of file")),
        ParseError::Syntax(m) => error(format_args!("{m}")),
    }
}

/// The shell's entry point.
pub fn main() -> i32 {
    let args = slate_rt::env::args();
    let mut sh = Shell::new();
    let argv0 = args.first().cloned().unwrap_or_else(|| b"chalk".to_vec());
    sh.arg0 = argv0.clone();
    sh.login = argv0.first() == Some(&b'-');
    let mut command = false;
    let mut force_interactive = false;
    let mut from_stdin = false;
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_slice() {
            b"--" | b"-" => {
                i += 1;
                break;
            }
            b"--login" => sh.login = true,
            // Accepted for compatibility: chalk is always POSIX-minded and
            // reads ~/.chalkrc only when interactive.
            b"--posix" | b"--norc" | b"--noprofile" => {}
            b"--version" => {
                io::out(b"chalk 0.1 (Slate)\n");
                return 0;
            }
            _ if a.len() >= 2 && (a[0] == b'-' || a[0] == b'+') => {
                let on = a[0] == b'-';
                for &c in &a[1..] {
                    match c {
                        b'c' => command = true,
                        b'i' => force_interactive = true,
                        b'l' => sh.login = true,
                        b's' => from_stdin = true,
                        b'o' => {
                            i += 1;
                            let Some(name) = args.get(i) else {
                                error(format_args!("-o: option requires an argument"));
                                return 2;
                            };
                            if !builtins::set_long(&mut sh, name, on) {
                                error(format_args!("{}: invalid option name", text(name)));
                                return 2;
                            }
                        }
                        c => {
                            if !builtins::set_letter(&mut sh, c, on) {
                                error(format_args!("-{}: invalid option", c as char));
                                return 2;
                            }
                        }
                    }
                }
            }
            _ => break,
        }
        i += 1;
    }
    if command {
        let Some(src) = args.get(i) else {
            error(format_args!("-c: option requires an argument"));
            return 2;
        };
        if let Some(name) = args.get(i + 1) {
            sh.arg0 = name.clone();
            sh.positional = args[i + 2..].to_vec();
        }
        sh.interactive = force_interactive;
        set_error_name(&sh.arg0);
        let st = sh.run_source(src);
        sh.exit_shell(st);
    }
    if !from_stdin && let Some(script) = args.get(i) {
        let src = match fs::read_file(script) {
            Ok(s) => s,
            Err(e) => {
                error(format_args!("{}: {e}", text(script)));
                return if e == slate_rt::Errno::ENOENT { 127 } else { 126 };
            }
        };
        sh.arg0 = script.clone();
        sh.script = script.clone();
        sh.positional = args[i + 1..].to_vec();
        set_error_name(&sh.arg0);
        let st = sh.run_source(&src);
        sh.exit_shell(st);
    }
    sh.positional = args[i..].to_vec();
    if force_interactive || (term::isatty(0) && term::isatty(2)) {
        interactive(&mut sh)
    }
    run_stdin(&mut sh)
}

/// Read one line from a descriptor without reading past it (the rest of
/// the input belongs to the commands). The flag says the input ended.
pub(crate) fn read_line_raw(fd: i32) -> (Vec<u8>, bool) {
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    loop {
        match io::read(fd, &mut b) {
            Ok(1) => {
                line.push(b[0]);
                if b[0] == b'\n' {
                    return (line, false);
                }
            }
            _ => return (line, true),
        }
    }
}

/// A script on standard input: run each complete command as it arrives.
fn run_stdin(sh: &mut Shell) -> ! {
    let mut buf = Vec::new();
    // The line the command being read starts on.
    let mut line_no = 1;
    loop {
        let (line, eof) = read_line_raw(0);
        buf.extend_from_slice(&line);
        let mut p = sh.parser(&buf);
        p.set_line(line_no);
        match p.program() {
            Err(ParseError::Incomplete) if !eof => continue,
            Ok(prog) => {
                line_no += buf.iter().filter(|&&c| c == b'\n').count();
                buf.clear();
                match sh.run_program(&prog) {
                    Ok(_) | Err(Flow::Break(_) | Flow::Continue(_) | Flow::Return(_) | Flow::Interrupt) => {}
                    Err(Flow::Exit(c)) => sh.exit_shell(c),
                }
            }
            Err(e) => {
                syntax_error(&e);
                sh.exit_shell(2);
            }
        }
        if eof {
            let st = sh.status;
            sh.exit_shell(st);
        }
    }
}

impl Shell {
    /// Take over the terminal for job control (`set -m`, interactive
    /// shells).
    pub fn setup_job_control(&mut self, on: bool) {
        if !on {
            self.tty = None;
            return;
        }
        if self.tty.is_some() || self.subshell {
            return;
        }
        let Some(fd) = [0, 2, 1].into_iter().find(|&f| term::isatty(f)) else {
            self.opts.monitor = false;
            return;
        };
        let Ok(tty) = process::fcntl(fd, process::F_DUPFD_CLOEXEC, 10).map(|d| d as i32) else { return };
        // Wait until we are in the foreground.
        for _ in 0..1000 {
            match term::foreground(tty) {
                Ok(pg) if pg == process::getpgrp() => break,
                Ok(_) => {
                    let _ = process::kill(0, signal::SIGTTIN);
                }
                Err(_) => {
                    self.opts.monitor = false;
                    let _ = io::close(tty);
                    return;
                }
            }
        }
        for s in [signal::SIGTSTP, signal::SIGTTIN, signal::SIGTTOU] {
            let _ = signal::set(s, signal::Disposition::Ignore);
        }
        let pid = process::getpid();
        if process::getpgrp() != pid {
            let _ = process::setpgid(0, 0);
        }
        self.pgid = process::getpgrp();
        let _ = term::set_foreground(tty, self.pgid);
        self.tty = Some(tty);
    }

    /// Expand a prompt string: bash's backslash escapes, then parameter
    /// expansion and command substitution.
    pub fn prompt(&mut self, ps: &[u8]) -> Vec<u8> {
        let esc = |out: &mut Vec<u8>, v: &[u8]| {
            for &c in v {
                if matches!(c, b'$' | b'`' | b'\\') {
                    out.push(b'\\');
                }
                out.push(c);
            }
        };
        let mut o = Vec::new();
        let mut i = 0;
        while i < ps.len() {
            let c = ps[i];
            i += 1;
            if c != b'\\' || i >= ps.len() {
                o.push(c);
                continue;
            }
            let e = ps[i];
            i += 1;
            match e {
                b'u' => {
                    let u = self.get_var(b"USER").or_else(|| slate_coreutils::simple::user_name(process::geteuid()));
                    esc(&mut o, &u.unwrap_or_default());
                }
                b'h' | b'H' => {
                    let host = process::uname()[1].clone();
                    let h =
                        if e == b'h' { host.split(|&c| c == b'.').next().unwrap_or_default().to_vec() } else { host };
                    esc(&mut o, &h);
                }
                b'w' | b'W' => {
                    let pwd = self.get_var(b"PWD").unwrap_or_default();
                    let home = self.get_var(b"HOME").unwrap_or_default();
                    let mut shown = if !home.is_empty()
                        && home != b"/"
                        && (pwd == home || pwd.starts_with(&[home.as_slice(), b"/"].concat()))
                    {
                        [b"~".as_slice(), &pwd[home.len()..]].concat()
                    } else {
                        pwd
                    };
                    if e == b'W' && shown != b"/" && shown != b"~" {
                        shown = fs::basename(&shown).to_vec();
                    }
                    esc(&mut o, &shown);
                }
                b'$' => o.extend_from_slice(if process::geteuid() == 0 { b"#" } else { b"\\$" }),
                b'n' => o.push(b'\n'),
                b'r' => o.push(b'\r'),
                b'a' => o.push(7),
                b'e' => o.push(0x1B),
                b's' => o.extend_from_slice(b"chalk"),
                b'v' | b'V' => o.extend_from_slice(b"0.1"),
                b'j' => o.extend_from_slice(alloc::format!("{}", self.jobs.list.len()).as_bytes()),
                b'!' | b'#' => o.extend_from_slice(alloc::format!("{}", self.history.len() + 1).as_bytes()),
                b't' | b'T' | b'@' | b'A' | b'd' => {
                    // The shell's own TZ, which may differ from the one it started with.
                    slate_rt::tz::set_tz(self.get_var(b"TZ").as_deref());
                    let tm = slate_rt::tz::localtime(slate_rt::time::unix());
                    let fmt = match e {
                        b't' => "%H:%M:%S",
                        b'T' => "%I:%M:%S",
                        b'@' => "%I:%M %p",
                        b'A' => "%H:%M",
                        _ => "%a %b %d",
                    };
                    let mut s = alloc::string::String::new();
                    slate_rt::time::format(&tm, fmt, &mut s);
                    o.extend_from_slice(s.as_bytes());
                }
                b'[' | b']' => {}
                b'\\' => o.extend_from_slice(b"\\\\"),
                b'0'..=b'7' => {
                    let mut v = (e - b'0') as u32;
                    let mut n = 1;
                    while n < 3 && i < ps.len() && (b'0'..=b'7').contains(&ps[i]) {
                        v = v * 8 + (ps[i] - b'0') as u32;
                        i += 1;
                        n += 1;
                    }
                    o.push(v as u8);
                }
                other => {
                    o.push(b'\\');
                    o.push(other);
                }
            }
        }
        match parser::heredoc_word(&o) {
            Ok(w) => {
                let st = self.status;
                let r = self.expand_single(&w).unwrap_or(o);
                self.status = st;
                r
            }
            Err(_) => o,
        }
    }

    /// Candidates for tab completion at `cur` in `line`.
    pub fn complete(&mut self, line: &[u8], cur: usize) -> (usize, Vec<Vec<u8>>) {
        let sep = |c: u8| matches!(c, b' ' | b'\t' | b'|' | b';' | b'&' | b'(' | b'<' | b'>' | b'`');
        let start = line[..cur].iter().rposition(|&c| sep(c)).map_or(0, |p| p + 1);
        let word = &line[start..cur];
        let before: Vec<u8> = line[..start].iter().copied().filter(|c| !matches!(c, b' ' | b'\t')).collect();
        let command_pos =
            before.is_empty() || before.last().is_some_and(|&c| matches!(c, b'|' | b';' | b'&' | b'(' | b'`'));
        let mut out: Vec<Vec<u8>> = Vec::new();
        if let Some(var) = word.strip_prefix(b"$") {
            out = self.vars.keys().filter(|k| k.starts_with(var)).map(|k| [b"$".as_slice(), k].concat()).collect();
        } else if command_pos && !word.contains(&b'/') {
            out.extend(builtins::names().map(|n| n.as_bytes().to_vec()).filter(|n| n.starts_with(word)));
            out.extend(self.functions.keys().filter(|k| k.starts_with(word)).cloned());
            out.extend(self.aliases.keys().filter(|k| k.starts_with(word)).cloned());
            let path = self.get_var(b"PATH").unwrap_or_default();
            for dir in path.split(|&c| c == b':').filter(|d| !d.is_empty()) {
                for e in fs::read_dir(dir).unwrap_or_default() {
                    if e.name.starts_with(word) && e.name != b"." && e.name != b".." {
                        out.push(e.name);
                    }
                }
            }
        } else {
            let (dir, prefix) = match word.iter().rposition(|&c| c == b'/') {
                Some(p) => (&word[..=p], &word[p + 1..]),
                None => (&b""[..], word),
            };
            let real_dir = if let Some(rest) = dir.strip_prefix(b"~") {
                [self.get_var(b"HOME").unwrap_or_default().as_slice(), rest].concat()
            } else {
                dir.to_vec()
            };
            let list_dir = if real_dir.is_empty() { b".".to_vec() } else { real_dir.clone() };
            for e in fs::read_dir(&list_dir).unwrap_or_default() {
                if e.name == b"." || e.name == b".." || !e.name.starts_with(prefix) {
                    continue;
                }
                if e.name.starts_with(b".") && !prefix.starts_with(b".") {
                    continue;
                }
                let mut c = [dir, e.name.as_slice()].concat();
                if fs::stat(&fs::join(&list_dir, &e.name)).is_ok_and(|s| s.is_dir()) {
                    c.push(b'/');
                }
                out.push(c);
            }
        }
        out.sort();
        out.dedup();
        (start, out)
    }
}

/// The interactive read-eval loop.
fn interactive(sh: &mut Shell) -> ! {
    sh.interactive = true;
    sh.opts.monitor = true;
    sh.setup_job_control(true);
    let _ = signal::set(signal::SIGINT, signal::Disposition::Catch);
    let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
    let _ = signal::set(signal::SIGTERM, signal::Disposition::Ignore);
    if term::isatty(0) {
        sh.editor = Editor::new(0);
    }
    let home = sh.get_var(b"HOME").unwrap_or_default();
    if sh.login {
        source_if_exists(sh, b"/etc/profile");
        source_if_exists(sh, &fs::join(&home, b".profile"));
    }
    match sh.get_var(b"ENV") {
        Some(env) => {
            let w = parser::heredoc_word(&env).ok();
            if let Some(path) = w.and_then(|w| sh.expand_single(&w).ok()) {
                source_if_exists(sh, &path);
            }
        }
        None => source_if_exists(sh, &fs::join(&home, b".chalkrc")),
    }
    let hist_file = sh.get_var(b"HISTFILE").unwrap_or_else(|| fs::join(&home, b".chalk_history"));
    let hist_size = sh.get_var(b"HISTSIZE").and_then(|v| slate_coreutils::util::parse_num(&v)).unwrap_or(1000);
    if let Some(ed) = sh.editor.as_mut() {
        if !home.is_empty() {
            ed.history_file = Some(hist_file);
        }
        ed.history_size = hist_size;
        sh.history = ed.load_history();
    }
    'outer: loop {
        sh.jobs.poll();
        for m in sh.jobs.notify() {
            io::err(alloc::format!("{m}\n").as_bytes());
        }
        if let Err(Flow::Exit(c)) = sh.run_traps() {
            sh.exit_shell(c);
        }
        let mut entry = Vec::new();
        let mut ps_name: &[u8] = b"PS1";
        let prog = loop {
            let ps = sh.get_var(ps_name).unwrap_or_default();
            let prompt = sh.prompt(&ps);
            let input = match sh.editor.take() {
                Some(mut ed) => {
                    let hist = core::mem::take(&mut sh.history);
                    let r = {
                        let mut complete = |l: &[u8], c: usize| sh.complete(l, c);
                        ed.read_line(&prompt, &hist, &mut complete)
                    };
                    sh.history = hist;
                    sh.editor = Some(ed);
                    r
                }
                None => {
                    io::err(&prompt);
                    let (l, eof) = read_line_raw(0);
                    if eof && l.is_empty() {
                        Input::Eof
                    } else {
                        Input::Line(l.strip_suffix(b"\n").unwrap_or(&l).to_vec())
                    }
                }
            };
            match input {
                Input::Eof if entry.is_empty() => {
                    if sh.opts.ignoreeof {
                        io::err(b"Use \"exit\" to leave the shell.\n");
                        continue;
                    }
                    io::err(b"exit\n");
                    let st = sh.status;
                    sh.exit_shell(st);
                }
                Input::Eof => {
                    syntax_error(&ParseError::Incomplete);
                    sh.status = 2;
                    continue 'outer;
                }
                Input::Interrupt => {
                    sh.status = 130;
                    signal::take();
                    continue 'outer;
                }
                Input::Line(l) => {
                    entry.extend_from_slice(&l);
                    entry.push(b'\n');
                }
            }
            let mut p = sh.parser(&entry);
            match p.program() {
                Ok(prog) => break prog,
                Err(ParseError::Incomplete) => ps_name = b"PS2",
                Err(e) => {
                    syntax_error(&e);
                    sh.status = 2;
                    add_history(sh, &entry);
                    continue 'outer;
                }
            }
        };
        add_history(sh, &entry);
        signal::take();
        match sh.run_program(&prog) {
            Ok(_) => {}
            Err(Flow::Exit(c)) => sh.exit_shell(c),
            Err(Flow::Interrupt) => {
                io::err(b"\n");
                sh.status = 130;
            }
            Err(_) => {}
        }
        io::flush_stdout();
    }
}

fn add_history(sh: &mut Shell, entry: &[u8]) {
    let e = entry.strip_suffix(b"\n").unwrap_or(entry);
    if e.iter().all(|c| c.is_ascii_whitespace()) || sh.history.last().is_some_and(|l| l == e) {
        return;
    }
    sh.history.push(e.to_vec());
}

fn source_if_exists(sh: &mut Shell, path: &[u8]) {
    if let Ok(src) = fs::read_file(path) {
        sh.source_depth += 1;
        let r = sh.source(&src);
        sh.source_depth -= 1;
        if let Err(Flow::Exit(c)) = r {
            sh.exit_shell(c);
        }
    }
}
