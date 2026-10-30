// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shell's state: variables, positional and special parameters,
//! options, functions, aliases, traps and jobs.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, process};

use crate::ast::Command;
use crate::jobs::Jobs;

#[derive(Clone, Debug, Default)]
pub struct Var {
    pub value: Vec<u8>,
    pub exported: bool,
    pub readonly: bool,
    /// Declared (`declare x`, `local x`) but given no value yet.
    pub unset: bool,
    /// `declare -i`: assignments are arithmetic.
    pub integer: bool,
    /// `declare -l` / `-u`: values change case on assignment (b'l', b'u').
    pub case: u8,
    /// Indexed or associative elements (bash arrays); `value` is unused
    /// then, and `$name` is element 0.
    pub array: crate::arrays::Array,
    /// `declare -n`: `value` names the variable this one stands for.
    pub nameref: bool,
}

/// bash's `shopt` options with their defaults (bash 5.3 in POSIX mode, as
/// `bash --posix -c shopt` lists them). Those marked act; the others are
/// kept and reported only.
pub const SHOPTS: &[(&str, bool)] = &[
    ("array_expand_once", false),
    ("assoc_expand_once", false),
    ("autocd", false),
    ("bash_source_fullpath", false),
    ("cdable_vars", false),
    ("cdspell", false),
    ("checkhash", false),
    ("checkjobs", false),
    ("checkwinsize", true),
    ("cmdhist", true),
    ("compat31", false),
    ("compat32", false),
    ("compat40", false),
    ("compat41", false),
    ("compat42", false),
    ("compat43", false),
    ("compat44", false),
    ("complete_fullquote", true),
    ("direxpand", false),
    ("dirspell", false),
    // Acts: `*` and `?` match a leading dot.
    ("dotglob", false),
    // Acts: a failed `exec` does not end a script.
    ("execfail", false),
    // Acts: aliases expand.
    ("expand_aliases", true),
    ("extdebug", false),
    // Acts: extended patterns.
    ("extglob", false),
    ("extquote", true),
    // Acts: a pattern that matches nothing is an error.
    ("failglob", false),
    ("force_fignore", true),
    ("globasciiranges", true),
    // Acts: `.` and `..` match only by name.
    ("globskipdots", true),
    // Acts: `**` matches any directories.
    ("globstar", false),
    ("gnu_errfmt", false),
    ("histappend", false),
    ("histreedit", false),
    ("histverify", false),
    ("hostcomplete", true),
    ("huponexit", false),
    // Acts: `$(...)` keeps `set -e`.
    ("inherit_errexit", true),
    ("interactive_comments", true),
    // Acts: a pipeline's last command runs in the shell.
    ("lastpipe", false),
    ("lithist", false),
    ("localvar_inherit", false),
    ("localvar_unset", false),
    ("login_shell", false),
    ("mailwarn", false),
    ("no_empty_cmd_completion", false),
    // Acts: pathname expansion ignores case.
    ("nocaseglob", false),
    // Acts: `case` and `[[ == ]]` ignore case.
    ("nocasematch", false),
    ("noexpand_translation", false),
    // Acts: a pattern that matches nothing goes away.
    ("nullglob", false),
    ("patsub_replacement", true),
    ("progcomp", true),
    ("progcomp_alias", false),
    ("promptvars", true),
    ("restricted_shell", false),
    // Acts: `shift` past the end says so.
    ("shift_verbose", true),
    // Acts: `.` searches PATH.
    ("sourcepath", true),
    ("syslog_history", false),
    ("varredir_close", false),
    // Acts: echo expands backslash escapes.
    ("xpg_echo", false),
];

/// Non-local control flow out of commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Break(usize),
    Continue(usize),
    Return(i32),
    Exit(i32),
    /// Ctrl-C in an interactive shell: abandon the command line.
    Interrupt,
}

pub type Res = core::result::Result<i32, Flow>;

#[derive(Clone, Copy, Debug, Default)]
pub struct Opts {
    pub errexit: bool,
    pub nounset: bool,
    pub xtrace: bool,
    pub noglob: bool,
    pub noclobber: bool,
    pub monitor: bool,
    pub verbose: bool,
    pub allexport: bool,
    pub pipefail: bool,
    pub noexec: bool,
    pub ignoreeof: bool,
}

#[derive(Debug)]
pub struct Shell {
    pub vars: BTreeMap<Vec<u8>, Var>,
    /// Saved variables of each active function call (for `local`).
    pub locals: Vec<Vec<(Vec<u8>, Option<Var>)>>,
    pub positional: Vec<Vec<u8>>,
    pub arg0: Vec<u8>,
    pub status: i32,
    pub last_bg: i32,
    pub functions: BTreeMap<Vec<u8>, Rc<Command>>,
    pub aliases: BTreeMap<Vec<u8>, Vec<u8>>,
    pub opts: Opts,
    pub interactive: bool,
    /// A subshell of an interactive shell: what it runs was typed at the
    /// prompt, so it may ask (a Linux source folder, ADR 0183).
    pub from_prompt: bool,
    pub login: bool,
    /// Trap actions by signal number (0 = EXIT).
    pub traps: BTreeMap<i32, Vec<u8>>,
    pub jobs: Jobs,
    pub loop_depth: usize,
    pub func_depth: usize,
    /// Running in a forked subshell.
    pub subshell: bool,
    /// `$$`: the main shell's pid, also in subshells.
    pub pid: i32,
    /// Commands whose failure must not trigger `set -e`.
    pub errexit_off: u32,
    pub history: Vec<Vec<u8>>,
    pub start_secs: i64,
    /// When the shell started, in seconds since the epoch (`%(...)T`'s -2).
    pub start_time: i64,
    pub rand: u32,
    pub getopts_pos: usize,
    /// The terminal and the shell's own process group (job control).
    pub tty: Option<i32>,
    pub pgid: i32,
    /// The status of the last command substitution of a simple command.
    pub cmdsub_status: Option<i32>,
    /// Bumped when aliases change (the parser takes a fresh copy).
    pub alias_gen: usize,
    pub editor: Option<crate::lineedit::Editor>,
    /// Nesting of `.` (for `return`).
    pub source_depth: usize,
    /// `exit` warned about stopped jobs once.
    pub warned_jobs: bool,
    /// OPTIND as getopts last left it (a reset to 1 restarts parsing).
    pub getopts_last_ind: usize,
    /// Open process substitutions: our end of the pipe, and the program.
    pub procsubs: Vec<(i32, i32)>,
    /// Their programs, still to be collected.
    pub procsub_pids: Vec<i32>,
    /// `shopt` settings, in [`SHOPTS`]' order.
    pub shopts: Vec<bool>,
    /// The line of the command running (`$LINENO`, error messages).
    pub lineno: usize,
    /// Running functions, innermost first (`$FUNCNAME`).
    pub funcnames: Vec<Vec<u8>>,
    /// The lines each running function was called from, outermost first
    /// (`caller`).
    pub call_lines: Vec<usize>,
    /// The script being run (`caller`'s file), empty for none.
    pub script: Vec<u8>,
    /// pushd's directories under the current one, newest first.
    pub dirstack: Vec<Vec<u8>>,
    /// The last pipeline's statuses (`$PIPESTATUS`).
    pub pipestatus: Vec<i32>,
    /// A subshell's parent's traps, which `trap` shows until the subshell
    /// sets its own (bash; POSIX allows it for `$(trap)`).
    pub parent_traps: Option<BTreeMap<i32, Vec<u8>>>,
    /// Signals ignored when the shell started: a non-interactive shell
    /// cannot trap them (§2.11).
    pub ignored_at_start: u64,
    /// Running coprocesses: (name, pid).
    pub coprocs: Vec<(Vec<u8>, i32)>,
    /// In a child that only runs one command: an external program may
    /// replace the shell rather than fork again.
    pub exec_in_place: bool,
}

impl Shell {
    pub fn new() -> Shell {
        let mut sh = Shell {
            vars: BTreeMap::new(),
            locals: Vec::new(),
            positional: Vec::new(),
            arg0: b"chalk".to_vec(),
            status: 0,
            last_bg: 0,
            functions: BTreeMap::new(),
            aliases: BTreeMap::new(),
            opts: Opts::default(),
            interactive: false,
            from_prompt: false,
            login: false,
            traps: BTreeMap::new(),
            jobs: Jobs::default(),
            loop_depth: 0,
            func_depth: 0,
            subshell: false,
            pid: process::getpid(),
            errexit_off: 0,
            history: Vec::new(),
            start_secs: slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).0,
            start_time: slate_rt::time::unix(),
            rand: process::getpid() as u32 ^ slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).1 as u32,
            getopts_pos: 0,
            tty: None,
            pgid: process::getpgrp(),
            cmdsub_status: None,
            alias_gen: 0,
            editor: None,
            source_depth: 0,
            warned_jobs: false,
            getopts_last_ind: 1,
            procsubs: Vec::new(),
            procsub_pids: Vec::new(),
            shopts: SHOPTS.iter().map(|o| o.1).collect(),
            lineno: 0,
            funcnames: Vec::new(),
            call_lines: Vec::new(),
            script: Vec::new(),
            dirstack: Vec::new(),
            pipestatus: Vec::new(),
            parent_traps: None,
            ignored_at_start: 0,
            coprocs: Vec::new(),
            exec_in_place: false,
        };
        for sig in 1..64 {
            if slate_rt::signal::action(sig, None).is_ok_and(|a| a.handler == 1) {
                sh.ignored_at_start |= 1 << sig;
                sh.traps.insert(sig, Vec::new());
            }
        }
        for e in slate_rt::env::vars() {
            if let Some(eq) = e.iter().position(|&c| c == b'=')
                && crate::parser::is_name(&e[..eq])
            {
                sh.vars.insert(
                    e[..eq].to_vec(),
                    Var { value: e[eq + 1..].to_vec(), exported: true, ..Default::default() },
                );
            }
        }
        let defaults: [(&[u8], &[u8]); 4] = [(b"IFS", b" \t\n"), (b"PS1", b"\\$ "), (b"PS2", b"> "), (b"PS4", b"+ ")];
        for (k, v) in defaults {
            sh.vars.entry(k.to_vec()).or_insert(Var { value: v.to_vec(), ..Default::default() });
        }
        sh.vars.insert(
            b"PPID".to_vec(),
            Var { value: alloc::format!("{}", process::getppid()).into_bytes(), ..Default::default() },
        );
        if !sh.vars.contains_key(b"PWD".as_slice())
            && let Ok(c) = fs::getcwd()
        {
            sh.set_var(b"PWD", &c);
            sh.export(b"PWD");
        }
        sh.vars.entry(b"OPTIND".to_vec()).or_insert(Var { value: b"1".to_vec(), ..Default::default() });
        sh
    }

    // --- options ---------------------------------------------------------------

    /// A `shopt` option's setting.
    pub fn shopt(&self, name: &str) -> bool {
        SHOPTS.iter().position(|o| o.0 == name).is_some_and(|i| self.shopts[i])
    }

    /// Set a `shopt` option; false if there is none by that name.
    pub fn set_shopt(&mut self, name: &str, on: bool) -> bool {
        let Some(i) = SHOPTS.iter().position(|o| o.0 == name) else { return false };
        self.shopts[i] = on;
        if name == "extglob" {
            crate::glob::EXTGLOB.store(on, core::sync::atomic::Ordering::Relaxed);
        }
        true
    }

    /// A parser for `src` with the shell's aliases and options.
    pub fn parser(&self, src: &[u8]) -> crate::parser::Parser {
        let mut p = crate::parser::Parser::new(src);
        if self.shopt("expand_aliases") {
            p.set_aliases(self.aliases.clone());
        }
        p.extglob = self.shopt("extglob");
        p
    }

    // --- variables -----------------------------------------------------------

    /// The variable `name` stands for, through name references
    /// (`declare -n`); a reference that loops gives `name` itself.
    pub fn resolve(&self, name: &[u8]) -> Vec<u8> {
        let mut n = name;
        for _ in 0..16 {
            match self.vars.get(n) {
                Some(v) if v.nameref && !v.unset && !v.value.is_empty() => n = &v.value,
                _ => return n.to_vec(),
            }
        }
        crate::error(format_args!("warning: {}: circular name reference", slate_rt::lossy(name)));
        name.to_vec()
    }

    /// `FUNCNAME` and `PIPESTATUS`, which the shell keeps (unless a
    /// variable of that name was made).
    pub fn special_array(&self, name: &[u8]) -> Option<Vec<Vec<u8>>> {
        if self.vars.contains_key(name) {
            return None;
        }
        match name {
            b"FUNCNAME" if !self.funcnames.is_empty() => {
                let mut v = self.funcnames.clone();
                v.push(if self.source_depth > 0 { b"source".to_vec() } else { b"main".to_vec() });
                Some(v)
            }
            b"PIPESTATUS" => Some(self.pipestatus.iter().map(|s| alloc::format!("{s}").into_bytes()).collect()),
            _ => None,
        }
    }

    /// Whether `name` is a name reference.
    pub fn is_nameref(&self, name: &[u8]) -> bool {
        self.vars.get(name).is_some_and(|v| v.nameref)
    }

    pub fn get_var(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        if self.is_nameref(name) {
            let target = self.resolve(name);
            if target.as_slice() == name {
                return None;
            }
            return match split_subscript(&target) {
                Some((n, sub)) => self.get_elem(n, sub),
                None => self.get_var(&target),
            };
        }
        match name {
            b"LINENO" => return Some(alloc::format!("{}", self.lineno).into_bytes()),
            b"FUNCNAME" | b"PIPESTATUS" if !self.vars.contains_key(name) => {
                return self.special_array(name).and_then(|a| a.into_iter().next());
            }
            b"RANDOM" => {
                self.rand = self.rand.wrapping_mul(1_103_515_245).wrapping_add(12345);
                return Some(alloc::format!("{}", (self.rand >> 16) & 0x7FFF).into_bytes());
            }
            b"SECONDS" => {
                let now = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC).0;
                return Some(alloc::format!("{}", now - self.start_secs).into_bytes());
            }
            _ => {}
        }
        let v = self.vars.get(name)?;
        match &v.array {
            crate::arrays::Array::None if v.unset => None,
            crate::arrays::Array::None => Some(v.value.clone()),
            a => a.get_text(b"0"),
        }
    }

    /// Set a variable; fails (with a message) on a read-only one.
    pub fn set_var(&mut self, name: &[u8], value: &[u8]) -> bool {
        if self.is_nameref(name) {
            let target = self.resolve(name);
            if target.as_slice() != name {
                return match split_subscript(&target) {
                    Some((n, sub)) => self.set_elem(n, sub, value, false),
                    None => self.set_var(&target, value),
                };
            }
        }
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            crate::error(format_args!("{}: readonly variable", slate_rt::lossy(name)));
            return false;
        }
        let value = self.attribute_value(name, value, false);
        let export = self.opts.allexport;
        let v = self.vars.entry(name.to_vec()).or_default();
        if v.array.is_some() {
            // `a=x` on an array sets element 0.
            v.array.set_text(b"0", value);
        } else {
            v.value = value;
            v.unset = false;
        }
        if export {
            v.exported = true;
        }
        true
    }

    pub fn export(&mut self, name: &[u8]) {
        self.vars.entry(name.to_vec()).or_default().exported = true;
    }

    /// `unset name`: through a name reference, its target.
    pub fn unset_var(&mut self, name: &[u8]) -> bool {
        let target = self.resolve(name);
        if let Some((n, sub)) = split_subscript(&target) {
            return self.unset_elem(n, sub);
        }
        self.unset_ref(&target)
    }

    /// Unset `name` itself (`unset -n`).
    pub fn unset_ref(&mut self, name: &[u8]) -> bool {
        if self.vars.get(name).is_some_and(|v| v.readonly) {
            crate::error(format_args!("{}: cannot unset: readonly variable", slate_rt::lossy(name)));
            return false;
        }
        self.vars.remove(name);
        true
    }

    /// Make `name` local to the current function call.
    pub fn make_local(&mut self, name: &[u8]) {
        let saved = self.vars.get(name).cloned();
        if let Some(frame) = self.locals.last_mut()
            && !frame.iter().any(|(n, _)| n == name)
        {
            frame.push((name.to_vec(), saved));
        }
    }

    /// The environment for a new program: exported variables.
    pub fn environ(&self) -> Vec<Vec<u8>> {
        self.vars
            .iter()
            .filter(|(_, v)| v.exported && !v.unset && !v.array.is_some())
            .map(|(k, v)| {
                let mut e = k.clone();
                e.push(b'=');
                e.extend_from_slice(&v.value);
                e
            })
            .collect()
    }

    /// `$-`: the active single-letter options.
    pub fn flags(&self) -> Vec<u8> {
        let o = &self.opts;
        let mut f = Vec::new();
        for (on, c) in [
            (o.allexport, b'a'),
            (o.errexit, b'e'),
            (o.noglob, b'f'),
            (self.interactive, b'i'),
            (o.monitor, b'm'),
            (o.noexec, b'n'),
            (o.nounset, b'u'),
            (o.verbose, b'v'),
            (o.xtrace, b'x'),
            (o.noclobber, b'C'),
        ] {
            if on {
                f.push(c);
            }
        }
        f
    }

    /// A parameter's value: variables, positionals and specials. `None`
    /// when unset.
    pub fn param(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        match name {
            b"?" => Some(alloc::format!("{}", self.status).into_bytes()),
            b"#" => Some(alloc::format!("{}", self.positional.len()).into_bytes()),
            b"$" => Some(alloc::format!("{}", self.pid).into_bytes()),
            b"!" => (self.last_bg != 0).then(|| alloc::format!("{}", self.last_bg).into_bytes()),
            b"-" => Some(self.flags()),
            b"0" => Some(self.arg0.clone()),
            b"@" | b"*" => {
                if self.positional.is_empty() {
                    return None;
                }
                let sep = self.get_var(b"IFS").map_or(b' ', |i| i.first().copied().unwrap_or(0));
                let mut v = Vec::new();
                for (i, p) in self.positional.iter().enumerate() {
                    if i > 0 && sep != 0 {
                        v.push(sep);
                    }
                    v.extend_from_slice(p);
                }
                Some(v)
            }
            n if n.iter().all(u8::is_ascii_digit) => {
                let i: usize = core::str::from_utf8(n).ok()?.parse().ok()?;
                self.positional.get(i.checked_sub(1)?).cloned()
            }
            n => self.get_var(n),
        }
    }

    pub fn home_of(user: &[u8]) -> Option<Vec<u8>> {
        let data = fs::read_file(b"/etc/passwd").ok()?;
        data.split(|&c| c == b'\n').find_map(|l| {
            let f: Vec<&[u8]> = l.split(|&c| c == b':').collect();
            (f.first() == Some(&user) && f.len() > 5).then(|| f[5].to_vec())
        })
    }
}

impl Default for Shell {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::arith::Vars for Shell {
    fn get(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        match split_subscript(name) {
            Some((n, sub)) => self.get_elem(n, sub),
            None => self.param(name),
        }
    }
    fn set(&mut self, name: &[u8], value: i64) {
        let v = alloc::format!("{value}").into_bytes();
        match split_subscript(name) {
            Some((n, sub)) => {
                self.set_elem(n, sub, &v, false);
            }
            None => {
                self.set_var(name, &v);
            }
        }
    }
}

/// `name[sub]` as (name, sub).
pub fn split_subscript(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let b = s.iter().position(|&c| c == b'[')?;
    s.ends_with(b"]").then(|| (&s[..b], &s[b + 1..s.len() - 1]))
}

/// Text for messages.
pub fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
