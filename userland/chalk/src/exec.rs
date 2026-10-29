// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running commands (POSIX.1-2017 XCU §2.9): simple commands and their
//! lookup, pipelines, lists, compound commands, functions, redirections
//! (§2.7), subshells and command substitution.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::errno::Errno;
use slate_rt::{fs, io, process, signal};

use crate::ast::*;
use crate::builtins;
use crate::expand::ExpandError;
use crate::shell::{Flow, Res, Shell, text};

/// File descriptors saved by a redirection: (fd, saved copy or -1 if it
/// was closed).
pub type Saved = Vec<(i32, i32)>;

/// A redirection failed (already reported).
#[derive(Clone, Copy, Debug)]
pub struct RedirError;

/// The lowest descriptor the shell uses for its own copies.
const SAVE_FD: usize = 10;

impl Shell {
    /// Run a list of commands; its status is the last one's.
    pub fn run_program(&mut self, p: &Program) -> Res {
        let mut st = 0;
        for (cmd, bg) in &p.0 {
            self.run_traps()?;
            if !self.coprocs.is_empty() {
                self.reap_coprocs();
            }
            st = if *bg { self.background(cmd) } else { self.run(cmd)? };
            self.status = st;
        }
        Ok(st)
    }

    /// Run one command. Process substitutions it opened (`<(...)`) end
    /// with it.
    pub fn run(&mut self, c: &Command) -> Res {
        let mark = self.procsubs.len();
        let r = self.run_inner(c);
        self.end_procsubs(mark);
        r
    }

    /// Close the process substitutions from `mark` on, and collect the
    /// programs behind them that have finished.
    fn end_procsubs(&mut self, mark: usize) {
        for (fd, pid) in self.procsubs.split_off(mark.min(self.procsubs.len())) {
            let _ = io::close(fd);
            self.procsub_pids.push(pid);
        }
        self.procsub_pids.retain(|&pid| !matches!(process::wait(pid, process::WNOHANG), Ok((p, _)) if p == pid));
    }

    /// The line of the command running, for `$LINENO` and messages.
    pub fn set_line(&mut self, line: usize) {
        self.lineno = line;
        if !self.interactive {
            crate::set_error_line(line);
        }
    }

    fn run_inner(&mut self, c: &Command) -> Res {
        if self.opts.noexec && !self.interactive {
            return Ok(0);
        }
        match c {
            Command::Simple { assigns, words, redirs, line } => {
                self.set_line(*line);
                let r = self.simple(assigns, words, redirs);
                if let Ok(st) | Err(Flow::Exit(st)) = r {
                    self.pipestatus = alloc::vec![st];
                }
                r
            }
            Command::Pipeline { bang, cmds } => {
                if *bang {
                    self.errexit_off += 1;
                }
                let r = self.pipeline(cmds);
                if *bang {
                    self.errexit_off -= 1;
                }
                let st = r?;
                if *bang { Ok((st == 0) as i32) } else { self.check_errexit(st) }
            }
            Command::And(a, b) | Command::Or(a, b) => {
                self.errexit_off += 1;
                let r = self.run(a);
                self.errexit_off -= 1;
                let st = r?;
                self.status = st;
                if (st == 0) == matches!(c, Command::And(..)) { self.run(b) } else { Ok(st) }
            }
            Command::Subshell(p, redirs) => self.with_redirs(redirs, |sh| {
                let st = sh.fork_job(
                    &|sh| {
                        sh.exec_in_place = only_simple(p);
                        sh.run_program(p)
                    },
                    &|| String::from("( ... )"),
                );
                sh.check_errexit(st)
            }),
            Command::Group(p, redirs) => self.with_redirs(redirs, |sh| sh.run_program(p)),
            Command::If { arms, otherwise, redirs } => self.with_redirs(redirs, |sh| {
                for (cond, body) in arms {
                    if sh.condition(cond)? == 0 {
                        return sh.run_program(body);
                    }
                }
                match otherwise {
                    Some(p) => sh.run_program(p),
                    None => Ok(0),
                }
            }),
            Command::Loop { until, cond, body, redirs } => {
                self.with_redirs(redirs, |sh| sh.run_loop(|sh| Ok(Some((sh.condition(cond)? == 0) != *until)), body))
            }
            Command::For { var, words, body, redirs, line } => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                let items = match words {
                    Some(ws) => match sh.expand_words(ws) {
                        Ok(v) => v,
                        Err(e) => return sh.expand_failed(e),
                    },
                    None => sh.positional.clone(),
                };
                let mut it = items.into_iter();
                sh.run_loop(
                    |sh| match it.next() {
                        Some(v) => Ok(Some(sh.set_var(var, &v))),
                        None => Ok(Some(false)),
                    },
                    body,
                )
            }),
            Command::ArithFor { exprs, body, redirs, line } => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                sh.arith_for(exprs, body)
            }),
            Command::Select { var, words, body, redirs, line } => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                sh.select(var, words.as_deref(), body)
            }),
            Command::Case { word, arms, redirs, line } => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                sh.case(word, arms)
            }),
            Command::FuncDef { name, body } => {
                self.functions.insert(name.clone(), body.clone());
                Ok(0)
            }
            Command::Cond(cond, redirs, line) => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                let st = match sh.cond(cond) {
                    Ok(true) => 0,
                    Ok(false) => 1,
                    Err(Some(e)) => return sh.expand_failed(e),
                    Err(None) => 2,
                };
                if sh.opts.xtrace {
                    sh.trace(&[b"[[ ... ]]".to_vec()]);
                }
                sh.check_errexit(st)
            }),
            Command::Arith(w, redirs, line) => self.with_redirs(redirs, |sh| {
                sh.set_line(*line);
                let e = match sh.expand_single(w) {
                    Ok(e) => e,
                    Err(e) => return sh.expand_failed(e),
                };
                match crate::arith::eval(&e, sh) {
                    Ok(v) => sh.check_errexit((v == 0) as i32),
                    Err(m) => {
                        crate::error(format_args!("((: {}: {m}", text(&e)));
                        Ok(1)
                    }
                }
            }),
            Command::Coproc { name, body } => Ok(self.coproc(name, body)),
            Command::Time { posix, cmd } => self.time(*posix, cmd.as_deref()),
        }
    }

    /// `for ((init; cond; step))`: an empty condition is true.
    fn arith_for(&mut self, exprs: &[Word; 3], body: &Program) -> Res {
        let mut first = true;
        let mut failed = false;
        let st = self.run_loop(
            |sh| {
                let eval = |sh: &mut Shell, w: &Word, empty: i64| -> Result<i64, Flow> {
                    let e = sh.expand_single(w).map_err(|_| Flow::Break(1))?;
                    if e.iter().all(u8::is_ascii_whitespace) {
                        return Ok(empty);
                    }
                    crate::arith::eval(&e, sh).map_err(|m| {
                        crate::error(format_args!("((: {}: {m}", text(&e)));
                        Flow::Break(1)
                    })
                };
                let r = (|| {
                    if core::mem::take(&mut first) {
                        eval(sh, &exprs[0], 0)?;
                    } else {
                        eval(sh, &exprs[2], 0)?;
                    }
                    eval(sh, &exprs[1], 1)
                })();
                match r {
                    Ok(v) => Ok(Some(v != 0)),
                    Err(_) => {
                        failed = true;
                        Ok(Some(false))
                    }
                }
            },
            body,
        )?;
        Ok(if failed { 1 } else { st })
    }

    /// `select`: the menu on standard error, PS3, a line from standard
    /// input; an empty line shows the menu again, end of input ends it.
    fn select(&mut self, var: &[u8], words: Option<&[Word]>, body: &Program) -> Res {
        let items = match words {
            Some(ws) => match self.expand_words(ws) {
                Ok(v) => v,
                Err(e) => return self.expand_failed(e),
            },
            None => self.positional.clone(),
        };
        if items.is_empty() {
            return Ok(0);
        }
        let mut menu = true;
        let mut eof = false;
        let st = self.run_loop(
            |sh| loop {
                if core::mem::take(&mut menu) {
                    let cols = sh.get_var(b"COLUMNS").and_then(|c| slate_coreutils::util::parse_num(&c)).unwrap_or(80);
                    io::err(&select_menu(&items, cols));
                }
                let ps3 = sh.get_var(b"PS3").unwrap_or_else(|| b"#? ".to_vec());
                io::err(&ps3);
                let (line, end) = crate::read_line_raw(0);
                if end && line.is_empty() {
                    io::err(b"\n");
                    eof = true;
                    return Ok(Some(false));
                }
                let line = line.strip_suffix(b"\n").unwrap_or(&line).to_vec();
                if line.is_empty() {
                    menu = true;
                    continue;
                }
                sh.set_var(b"REPLY", &line);
                let pick = slate_coreutils::util::parse_num::<usize>(&line)
                    .filter(|&n| n >= 1 && n <= items.len())
                    .map_or_else(Vec::new, |n| items[n - 1].clone());
                return Ok(Some(sh.set_var(var, &pick)));
            },
            body,
        )?;
        Ok(if eof { 1 } else { st })
    }

    /// `coproc`: the command in the background, its input and output on
    /// pipes whose other ends are `NAME[1]` and `NAME[0]`.
    fn coproc(&mut self, name: &[u8], body: &Command) -> i32 {
        let (Ok((in_r, in_w)), Ok((out_r, out_w))) = (process::pipe(fs::O_CLOEXEC), process::pipe(fs::O_CLOEXEC))
        else {
            crate::error(format_args!("coproc: pipe failed"));
            return 1;
        };
        let Some(pid) = self.fork() else { return 1 };
        if pid == 0 {
            let _ = process::dup2(in_r, 0);
            let _ = process::dup2(out_w, 1);
            for fd in [in_r, in_w, out_r, out_w] {
                let _ = io::close(fd);
            }
            self.exec_in_place = matches!(body, Command::Simple { .. });
            let r = self.run(body);
            self.child_exit(r);
        }
        let _ = io::close(in_r);
        let _ = io::close(out_w);
        // Out of the way of the descriptors scripts use (bash: about 60).
        let high = |fd: i32| match process::fcntl(fd, process::F_DUPFD_CLOEXEC, 60) {
            Ok(n) => {
                let _ = io::close(fd);
                n as i32
            }
            Err(_) => fd,
        };
        let (rd, wr) = (high(out_r), high(in_w));
        let elems =
            alloc::vec![(None, alloc::format!("{rd}").into_bytes()), (None, alloc::format!("{wr}").into_bytes())];
        self.assign_array(name, elems, false);
        self.set_var(&[name, b"_PID"].concat(), alloc::format!("{pid}").as_bytes());
        self.last_bg = pid;
        let label = String::from_utf8_lossy(&crate::print::command(body)).into_owned();
        self.jobs.add(0, &[pid], label, false);
        self.coprocs.push((name.to_vec(), pid));
        0
    }

    /// Forget coprocesses that ended: their variables and descriptors go.
    fn reap_coprocs(&mut self) {
        self.jobs.poll();
        let done: Vec<(Vec<u8>, i32)> = self
            .coprocs
            .iter()
            .filter(|(_, pid)| {
                self.jobs.by_pid(*pid).is_none_or(|id| {
                    self.jobs.list.iter().any(|j| j.id == id && matches!(j.state, crate::jobs::State::Done(_)))
                })
            })
            .cloned()
            .collect();
        for (name, pid) in done {
            self.coprocs.retain(|c| c.1 != pid);
            for fd in self.elements(&name) {
                if let Some(n) = slate_coreutils::util::parse_num::<i32>(&fd) {
                    let _ = io::close(n);
                }
            }
            self.unset_var(&name);
            self.unset_var(&[name.as_slice(), b"_PID"].concat());
        }
    }

    /// `time [-p] pipeline`: real, user and system time on standard error,
    /// as TIMEFORMAT says (bash's default without it).
    fn time(&mut self, posix: bool, cmd: Option<&Command>) -> Res {
        let now = || {
            let (s, ns) = slate_rt::time::now(slate_rt::time::CLOCK_MONOTONIC);
            s as u64 * 1_000_000_000 + ns as u64
        };
        let cpu = || {
            let t = process::cpu_times().unwrap_or([0; 4]);
            (t[0] + t[2], t[1] + t[3])
        };
        let (t0, (u0, s0)) = (now(), cpu());
        let r = match cmd {
            Some(c) => self.run(c),
            None => Ok(0),
        };
        let (t1, (u1, s1)) = (now(), cpu());
        let fmt = if posix {
            b"real %2R\nuser %2U\nsys %2S".to_vec()
        } else {
            self.get_var(b"TIMEFORMAT").unwrap_or_else(|| b"\nreal\t%3lR\nuser\t%3lU\nsys\t%3lS".to_vec())
        };
        let mut out = time_format(&fmt, t1 - t0, u1.saturating_sub(u0), s1.saturating_sub(s0));
        if !fmt.is_empty() {
            out.push(b'\n');
        }
        io::err(&out);
        r
    }

    /// A condition (if/while/until): `set -e` does not apply inside.
    fn condition(&mut self, p: &Program) -> Res {
        self.errexit_off += 1;
        let r = self.run_program(p);
        self.errexit_off -= 1;
        r
    }

    /// `set -e`: leave when a command fails outside a condition.
    pub fn check_errexit(&mut self, st: i32) -> Res {
        if st != 0 && self.opts.errexit && self.errexit_off == 0 {
            return Err(Flow::Exit(st));
        }
        Ok(st)
    }

    /// The loop driver for while/until/for: `next` sets up an iteration
    /// and says whether to run it.
    fn run_loop(&mut self, mut next: impl FnMut(&mut Shell) -> Result<Option<bool>, Flow>, body: &Program) -> Res {
        self.loop_depth += 1;
        let mut st = 0;
        let r = loop {
            match next(self) {
                Ok(Some(true)) => {}
                Ok(_) => break Ok(st),
                Err(Flow::Break(n)) => break if n > 1 { Err(Flow::Break(n - 1)) } else { Ok(0) },
                Err(f) => break Err(f),
            }
            match self.run_program(body) {
                Ok(s) => st = s,
                Err(Flow::Break(n)) => break if n > 1 { Err(Flow::Break(n - 1)) } else { Ok(st) },
                Err(Flow::Continue(n)) if n > 1 => break Err(Flow::Continue(n - 1)),
                Err(Flow::Continue(_)) => {}
                Err(f) => break Err(f),
            }
            self.status = st;
        };
        self.loop_depth -= 1;
        r
    }

    fn case(&mut self, word: &Word, arms: &[CaseArm]) -> Res {
        let subject = match self.expand_single(word) {
            Ok(w) => w,
            Err(e) => return self.expand_failed(e),
        };
        let mut st = 0;
        let mut fall = false;
        for arm in arms {
            if !fall {
                let mut hit = false;
                for p in &arm.patterns {
                    let pat = match self.expand_pattern(p) {
                        Ok(p) => p,
                        Err(e) => return self.expand_failed(e),
                    };
                    if crate::glob::matches_with(&pat, &subject, self.match_flags(false)) {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    continue;
                }
            }
            st = self.run_program(&arm.body)?;
            match arm.end {
                CaseEnd::Break => return Ok(st),
                CaseEnd::FallThrough => fall = true,
                CaseEnd::Continue => fall = false,
            }
        }
        Ok(st)
    }

    /// How `case` and `[[ == ]]` match (`nocasematch`; `[[ ]]` always takes
    /// extended patterns).
    fn match_flags(&self, cond: bool) -> crate::glob::Flags {
        crate::glob::Flags { ext: cond || self.shopt("extglob"), nocase: self.shopt("nocasematch") }
    }

    /// `[[ ... ]]`: Err(None) is a usage error (status 2).
    fn cond(&mut self, c: &Cond) -> Result<bool, Option<ExpandError>> {
        Ok(match c {
            Cond::Paren(a) => self.cond(a)?,
            Cond::And(a, b) => self.cond(a)? && self.cond(b)?,
            Cond::Or(a, b) => self.cond(a)? || self.cond(b)?,
            Cond::Not(a) => !self.cond(a)?,
            Cond::Word(w) => !self.expand_single(w).map_err(Some)?.is_empty(),
            Cond::Unary(op, w) => {
                let v = self.expand_single(w).map_err(Some)?;
                if op == b"-v" {
                    return Ok(self.param(&v).is_some());
                }
                if op == b"-o" {
                    return Ok(builtins::option_value(self, &v).unwrap_or(false));
                }
                match slate_coreutils::test::run(&[op.clone(), v]) {
                    0 => true,
                    1 => false,
                    _ => return Err(None),
                }
            }
            Cond::Binary(l, op, r) => {
                let lv = self.expand_single(l).map_err(Some)?;
                match op.as_slice() {
                    b"==" | b"=" | b"!=" => {
                        let pat = self.expand_pattern(r).map_err(Some)?;
                        crate::glob::matches_with(&pat, &lv, self.match_flags(true)) == (op != b"!=")
                    }
                    b"=~" => {
                        // Quoted parts of the pattern match literally (bash).
                        let pat = self.expand_pattern(r).map_err(Some)?;
                        let mut re = Vec::new();
                        for (c, quoted) in pat {
                            if quoted && b"\\.[]()*+?{}|^$".contains(&c) {
                                re.push(b'\\');
                            }
                            re.push(c);
                        }
                        let mut opts = slate_regex::Options::extended();
                        opts.icase = self.shopt("nocasematch");
                        match slate_regex::Regex::new(&re, opts) {
                            Ok(rx) => {
                                // BASH_REMATCH: the match, then each group
                                // (empty if it took no part).
                                let caps = rx.find_at(&lv, 0).filter(|c| c[0].is_some()).unwrap_or_default();
                                let elems =
                                    caps.iter().map(|g| (None, g.map_or_else(Vec::new, |(a, b)| lv[a..b].to_vec())));
                                self.assign_array(b"BASH_REMATCH", elems.collect(), false);
                                !caps.is_empty()
                            }
                            Err(e) => {
                                crate::error(format_args!("[[: {}: {e}", text(&re)));
                                return Err(None);
                            }
                        }
                    }
                    b"<" => lv < self.expand_single(r).map_err(Some)?,
                    b">" => lv > self.expand_single(r).map_err(Some)?,
                    b"-eq" | b"-ne" | b"-lt" | b"-le" | b"-gt" | b"-ge" => {
                        let rv = self.expand_single(r).map_err(Some)?;
                        let (Ok(a), Ok(b)) = (crate::arith::eval(&lv, self), crate::arith::eval(&rv, self)) else {
                            return Err(None);
                        };
                        match op.as_slice() {
                            b"-eq" => a == b,
                            b"-ne" => a != b,
                            b"-lt" => a < b,
                            b"-le" => a <= b,
                            b"-gt" => a > b,
                            _ => a >= b,
                        }
                    }
                    _ => {
                        let rv = self.expand_single(r).map_err(Some)?;
                        match slate_coreutils::test::run(&[lv, op.clone(), rv]) {
                            0 => true,
                            1 => false,
                            _ => return Err(None),
                        }
                    }
                }
            }
        })
    }

    /// An expansion error: non-interactive shells leave (§2.8.1).
    pub fn expand_failed(&mut self, e: ExpandError) -> Res {
        match e {
            ExpandError::Flow(f) => Err(f),
            ExpandError::Fatal if !self.interactive => Err(Flow::Exit(1)),
            ExpandError::Fatal => Ok(1),
        }
    }

    pub fn trace(&mut self, words: &[Vec<u8>]) {
        let ps4 = self.get_var(b"PS4").unwrap_or_default();
        let mut line = ps4;
        for (i, w) in words.iter().enumerate() {
            if i > 0 {
                line.push(b' ');
            }
            line.extend_from_slice(&crate::builtins::quote(w));
        }
        line.push(b'\n');
        io::err(&line);
    }

    // --- simple commands ------------------------------------------------

    fn simple(&mut self, assigns: &[Assign], words: &[Word], redirs: &[Redir]) -> Res {
        self.cmdsub_status = None;
        let in_place = core::mem::take(&mut self.exec_in_place);
        let argv = match self.expand_command_words(words) {
            Ok(a) => a,
            Err(e) => return self.expand_failed(e),
        };
        // Plain assignments (name=, name+=) can be temporary for a
        // command; array forms always set the variable.
        let mut values = Vec::new();
        let mut direct = Vec::new();
        for a in assigns {
            let (lhs, v) = match self.expand_assign(a) {
                Ok(x) => x,
                Err(e) => return self.expand_failed(e),
            };
            if a.index.is_none() && crate::arrays::decode(&v).is_none() {
                values.push(self.assignment_value(&lhs, v));
            } else {
                direct.push((lhs, v));
            }
        }
        for (lhs, v) in &direct {
            if !self.assign_lhs(lhs, v) && !self.interactive && argv.is_empty() {
                return Err(Flow::Exit(1));
            }
        }
        if self.opts.xtrace {
            let mut t: Vec<Vec<u8>> = values
                .iter()
                .map(|(n, v)| {
                    let mut a = n.clone();
                    a.push(b'=');
                    a.extend_from_slice(&crate::builtins::quote(v));
                    a
                })
                .collect();
            t.extend(argv.iter().cloned());
            if !t.is_empty() {
                self.trace(&t);
            }
        }
        if argv.is_empty() {
            let mut st = self.cmdsub_status.unwrap_or(0);
            for (n, v) in &values {
                if !self.set_var(n, v) {
                    st = 1;
                    if !self.interactive {
                        return Err(Flow::Exit(1));
                    }
                }
            }
            let mut saved = Saved::new();
            if !redirs.is_empty() {
                if self.redirect(redirs, Some(&mut saved)).is_err() {
                    st = 1;
                }
                self.restore(saved);
            }
            return self.check_errexit(st);
        }
        let name = argv[0].as_slice();
        if let Some(b) = builtins::find(name)
            && builtins::is_special(name)
        {
            // Special built-ins keep their assignments (§2.14).
            for (n, v) in &values {
                self.set_var(n, v);
            }
            let st = self.builtin(b, &argv, redirs, true)?;
            return self.check_errexit(st);
        }
        if let Some(f) = self.functions.get(name).cloned() {
            let saved = self.push_temp(&values);
            let r = self.call_function(&f, &argv, redirs);
            self.pop_temp(saved);
            let st = r?;
            return self.check_errexit(st);
        }
        if let Some(b) = builtins::find(name) {
            let saved = self.push_temp(&values);
            let r = self.builtin(b, &argv, redirs, false);
            self.pop_temp(saved);
            let st = r?;
            return self.check_errexit(st);
        }
        // The only command of a child: the program replaces it.
        if in_place && self.traps.values().all(|a| a.is_empty()) {
            if self.redirect(redirs, None).is_err() {
                return Ok(1);
            }
            return Ok(self.exec(&argv, &values));
        }
        let st = self.external(&argv, &values, redirs);
        self.check_errexit(st)
    }

    /// `name+=value` appends (bash), or adds for a `-i` variable.
    fn assignment_value(&mut self, name: &[u8], v: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        if let Some(n) = name.strip_suffix(b"+") {
            if self.vars.get(n).is_some_and(|x| x.integer) {
                let sum = self.attribute_value(n, &v, true);
                return (n.to_vec(), sum);
            }
            let mut old = self.get_var(n).unwrap_or_default();
            old.extend_from_slice(&v);
            return (n.to_vec(), old);
        }
        (name.to_vec(), v)
    }

    /// Assignments in front of a function or built-in: exported for the
    /// command's duration.
    fn push_temp(&mut self, values: &[(Vec<u8>, Vec<u8>)]) -> Vec<(Vec<u8>, Option<crate::shell::Var>)> {
        let mut saved = Vec::new();
        for (n, v) in values {
            saved.push((n.clone(), self.vars.get(n).cloned()));
            if self.set_var(n, v) {
                self.export(n);
            }
        }
        saved
    }

    fn pop_temp(&mut self, saved: Vec<(Vec<u8>, Option<crate::shell::Var>)>) {
        for (n, old) in saved.into_iter().rev() {
            match old {
                Some(v) => {
                    self.vars.insert(n, v);
                }
                None => {
                    self.vars.remove(&n);
                }
            }
        }
    }

    fn builtin(&mut self, b: builtins::Builtin, argv: &[Vec<u8>], redirs: &[Redir], special: bool) -> Res {
        let mut saved = Saved::new();
        if self.redirect(redirs, Some(&mut saved)).is_err() {
            self.restore(saved);
            if special && !self.interactive {
                return Err(Flow::Exit(1));
            }
            return Ok(1);
        }
        let mut r = b(self, argv);
        if let Some(e) = io::reset_stdout() {
            crate::error(format_args!("{}: write error: {e}", text(&argv[0])));
            if r == Ok(0) {
                r = Ok(1);
            }
        }
        // `exec` with only redirections keeps them.
        if argv[0] == b"exec" && argv.len() == 1 {
            for (_, d) in saved {
                if d >= 0 {
                    let _ = io::close(d);
                }
            }
        } else {
            self.restore(saved);
        }
        r
    }

    pub fn call_function(&mut self, f: &Command, argv: &[Vec<u8>], redirs: &[Redir]) -> Res {
        let mut saved = Saved::new();
        if self.redirect(redirs, Some(&mut saved)).is_err() {
            self.restore(saved);
            return Ok(1);
        }
        if self.func_depth > 1000 {
            crate::error(format_args!("{}: maximum function nesting level exceeded", text(&argv[0])));
            self.restore(saved);
            return Ok(1);
        }
        let old = core::mem::replace(&mut self.positional, argv[1..].to_vec());
        let old_loops = core::mem::replace(&mut self.loop_depth, 0);
        self.func_depth += 1;
        self.locals.push(Vec::new());
        self.funcnames.insert(0, argv[0].clone());
        let line = self.lineno;
        self.call_lines.push(line);
        let r = self.run(f);
        self.call_lines.pop();
        self.funcnames.remove(0);
        self.set_line(line);
        let frame = self.locals.pop().unwrap_or_default();
        for (n, v) in frame.into_iter().rev() {
            match v {
                Some(v) => {
                    self.vars.insert(n, v);
                }
                None => {
                    self.vars.remove(&n);
                }
            }
        }
        self.func_depth -= 1;
        self.loop_depth = old_loops;
        self.positional = old;
        self.restore(saved);
        match r {
            Err(Flow::Return(s)) => Ok(s),
            r => r,
        }
    }

    /// Run a program: fork, then exec in the child.
    fn external(&mut self, argv: &[Vec<u8>], values: &[(Vec<u8>, Vec<u8>)], redirs: &[Redir]) -> i32 {
        let label = || {
            let mut s = String::new();
            for (i, a) in argv.iter().enumerate() {
                if i > 0 {
                    s.push(' ');
                }
                s.push_str(&text(a));
            }
            s
        };
        self.fork_job(
            &|sh: &mut Shell| {
                if sh.redirect(redirs, None).is_err() {
                    return Ok(1);
                }
                Ok(sh.exec(argv, values))
            },
            &label,
        )
    }

    /// Replace the shell with `argv` (in a child, or for `exec`). Returns
    /// the status to exit with on failure.
    pub fn exec(&mut self, argv: &[Vec<u8>], values: &[(Vec<u8>, Vec<u8>)]) -> i32 {
        for (n, v) in values {
            if self.set_var(n, v) {
                self.export(n);
            }
        }
        let Some(path) = self.lookup(&argv[0]) else {
            crate::error(format_args!("{}: command not found", text(&argv[0])));
            return 127;
        };
        self.reset_signals_for_exec();
        let env = self.environ();
        let e = process::execve(&path, argv, &env);
        match e {
            Errno::ENOEXEC => self.run_script_in_place(&path, argv),
            Errno::ENOENT => {
                crate::error(format_args!("{}: No such file or directory", text(&argv[0])));
                127
            }
            e => {
                crate::error(format_args!("{}: {}", text(&argv[0]), e));
                126
            }
        }
    }

    /// A file without a known format runs as a shell script (§2.9.1.1).
    fn run_script_in_place(&mut self, path: &[u8], argv: &[Vec<u8>]) -> i32 {
        let Ok(src) = fs::read_file(path) else { return 126 };
        if src.iter().take(512).any(|&c| c == 0) {
            crate::error(format_args!("{}: cannot execute binary file", text(path)));
            return 126;
        }
        self.functions.clear();
        self.aliases.clear();
        self.arg0 = path.to_vec();
        self.positional = argv[1..].to_vec();
        self.run_source(&src)
    }

    /// The program `name` runs, from `$PATH`.
    pub fn lookup(&mut self, name: &[u8]) -> Option<Vec<u8>> {
        if name.contains(&b'/') {
            return Some(name.to_vec());
        }
        let path = self.get_var(b"PATH").unwrap_or_else(|| b"/bin:/sbin:/usr/bin:/usr/sbin".to_vec());
        for dir in path.split(|&c| c == b':') {
            let dir = if dir.is_empty() { &b"."[..] } else { dir };
            let cand = fs::join(dir, name);
            if let Ok(st) = fs::stat(&cand)
                && !st.is_dir()
                && st.mode & 0o111 != 0
            {
                return Some(cand);
            }
        }
        None
    }

    // --- processes --------------------------------------------------------

    /// Fork, setting the child up as a subshell. `None` if fork failed.
    pub fn fork(&mut self) -> Option<i32> {
        io::flush_stdout();
        match process::fork() {
            Ok(0) => {
                self.enter_subshell();
                Some(0)
            }
            Ok(pid) => Some(pid),
            Err(e) => {
                crate::error(format_args!("fork: {e}"));
                None
            }
        }
    }

    /// In a new subshell: traps other than ignored signals reset (§2.12),
    /// no job control.
    fn enter_subshell(&mut self) {
        if self.parent_traps.is_none() && !self.traps.is_empty() {
            self.parent_traps = Some(self.traps.clone());
        }
        let caught: Vec<i32> = self.traps.iter().filter(|(_, a)| !a.is_empty()).map(|(&s, _)| s).collect();
        for s in caught {
            self.traps.remove(&s);
            if s > 0 {
                let _ = signal::set(s, signal::Disposition::Default);
            }
        }
        if self.interactive {
            for s in
                [signal::SIGINT, signal::SIGQUIT, signal::SIGTERM, signal::SIGTSTP, signal::SIGTTIN, signal::SIGTTOU]
            {
                if !self.traps.contains_key(&s) {
                    let _ = signal::set(s, signal::Disposition::Default);
                }
            }
        }
        signal::take();
        self.subshell = true;
        self.interactive = false;
        self.opts.monitor = false;
        self.jobs.clear();
        self.tty = None;
    }

    /// Dispositions a program starts with: caught signals become default
    /// on exec anyway; job-control ignores must not leak.
    fn reset_signals_for_exec(&mut self) {
        if self.tty.is_some() {
            for s in
                [signal::SIGINT, signal::SIGQUIT, signal::SIGTERM, signal::SIGTSTP, signal::SIGTTIN, signal::SIGTTOU]
            {
                let _ = signal::set(s, signal::Disposition::Default);
            }
        }
    }

    /// Give the terminal to `pgid` from a new job's child. The child is in
    /// its own process group already and may run before its parent has
    /// made that group the foreground; tcsetpgrp from a background group
    /// raises SIGTTOU unless it is ignored (tcsetpgrp(3)), so it is
    /// ignored for the call. Without this, a child scheduled first stopped
    /// the job ("Stopped pipeline", the rare flake in docs/GAPS.md).
    fn take_terminal(&self, tty: i32, pgid: i32) {
        let _ = signal::set(signal::SIGTTOU, signal::Disposition::Ignore);
        let _ = slate_rt::term::set_foreground(tty, pgid);
        if !self.traps.contains_key(&signal::SIGTTOU) {
            let _ = signal::set(signal::SIGTTOU, signal::Disposition::Default);
        }
    }

    /// Run `f` in a child as a foreground job and wait for it.
    pub fn fork_job(&mut self, f: &dyn Fn(&mut Shell) -> Res, label: &dyn Fn() -> String) -> i32 {
        let monitor = self.opts.monitor && self.tty.is_some();
        let tty = self.tty;
        let Some(pid) = self.fork() else { return 1 };
        if pid == 0 {
            if monitor {
                let _ = process::setpgid(0, 0);
                if let Some(t) = tty {
                    self.take_terminal(t, process::getpid());
                }
            }
            let r = f(self);
            self.child_exit(r);
        }
        let pgid = if monitor {
            let _ = process::setpgid(pid, pid);
            pid
        } else {
            0
        };
        self.wait_fg(&[pid], pgid, label)
    }

    /// Leave a child with the status `r` gives.
    pub fn child_exit(&mut self, r: Res) -> ! {
        let code = match r {
            Ok(s) | Err(Flow::Exit(s)) | Err(Flow::Return(s)) => s,
            Err(_) => self.status,
        };
        self.exit_shell(code)
    }

    /// Leave the shell: the EXIT trap runs first.
    pub fn exit_shell(&mut self, code: i32) -> ! {
        self.status = code;
        if let Some(action) = self.traps.remove(&0) {
            let _ = self.eval(&action);
        }
        io::flush_stdout();
        if let Some(lineedit) = self.editor.as_mut() {
            lineedit.save_history(&self.history);
        }
        process::exit(code)
    }

    /// Wait for a foreground job's processes; the status is the last
    /// one's (with `pipefail`, the last failing one's).
    pub fn wait_fg(&mut self, pids: &[i32], pgid: i32, label: &dyn Fn() -> String) -> i32 {
        if pgid != 0
            && let Some(t) = self.tty
        {
            let _ = slate_rt::term::set_foreground(t, pgid);
        }
        let mut statuses: Vec<Option<i32>> = alloc::vec![None; pids.len()];
        let mut stopped = false;
        let opts = if pgid != 0 { process::WUNTRACED } else { 0 };
        while statuses.iter().any(Option::is_none) {
            let target = if pgid != 0 { -pgid } else { pids[statuses.iter().position(Option::is_none).unwrap()] };
            match process::wait(target, opts) {
                Ok((p, s)) => {
                    if process::stopped(s).is_some() {
                        stopped = true;
                        break;
                    }
                    if let Some(i) = pids.iter().position(|&x| x == p) {
                        statuses[i] = Some(s);
                    }
                }
                Err(_) => break,
            }
        }
        if pgid != 0
            && let Some(t) = self.tty
        {
            let _ = slate_rt::term::set_foreground(t, self.pgid);
            // A job that stopped or was killed may have left the terminal
            // in its own mode; one that exited set what it meant to (stty).
            let killed = statuses.iter().flatten().any(|&s| process::signaled(s).is_some());
            if (stopped || killed)
                && let Some(ed) = self.editor.as_ref()
            {
                ed.restore_modes();
            }
        }
        if stopped {
            let id = self.jobs.add(pgid, pids, label(), true);
            io::err(alloc::format!("\n[{id}]+  Stopped                 {}\n", label()).as_bytes());
            return 128 + signal::SIGTSTP;
        }
        let codes: Vec<i32> = statuses.iter().map(|s| s.map_or(127, |s| self.report(s))).collect();
        self.pipestatus = codes.clone();
        if self.opts.pipefail {
            codes.iter().rev().find(|&&c| c != 0).copied().unwrap_or(0)
        } else {
            codes.last().copied().unwrap_or(0)
        }
    }

    /// The status of a wait status, reporting deaths by signal.
    pub fn report(&self, s: i32) -> i32 {
        if let Some(sig) = process::signaled(s) {
            if sig != signal::SIGPIPE && sig != signal::SIGINT {
                let core = if s & 0x80 != 0 { " (core dumped)" } else { "" };
                io::err(alloc::format!("{}{core}\n", signal::describe(sig)).as_bytes());
            } else if sig == signal::SIGINT && self.interactive {
                io::err(b"\n");
            }
        }
        process::exit_code(s)
    }

    /// Start the first `forked` commands of a pipeline, each reading the
    /// one before: their pids, the process group (with job control) and
    /// the read end left for a last command run here. In the
    /// `background` (`a | b &`), they take no terminal and, without job
    /// control, ignore SIGINT and SIGQUIT, the first reading /dev/null.
    fn spawn_pipeline(
        &mut self,
        cmds: &[Command],
        forked: usize,
        monitor: bool,
        background: bool,
    ) -> (Vec<i32>, i32, Option<i32>) {
        let tty = self.tty;
        let mut pids = Vec::new();
        let mut pgid = 0;
        let mut prev: Option<i32> = None;
        for (i, c) in cmds[..forked].iter().enumerate() {
            let last = i + 1 == cmds.len();
            let pipe = if last {
                None
            } else {
                match process::pipe(fs::O_CLOEXEC) {
                    Ok(p) => Some(p),
                    Err(e) => {
                        crate::error(format_args!("pipe: {e}"));
                        break;
                    }
                }
            };
            let Some(pid) = self.fork() else { break };
            if pid == 0 {
                if monitor {
                    let _ = process::setpgid(0, pgid);
                    if pgid == 0
                        && !background
                        && let Some(t) = tty
                    {
                        self.take_terminal(t, process::getpid());
                    }
                } else if background {
                    // §2.9.3: without job control, asynchronous commands
                    // ignore SIGINT and SIGQUIT, and read /dev/null.
                    let _ = signal::set(signal::SIGINT, signal::Disposition::Ignore);
                    let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
                    if prev.is_none()
                        && let Ok(fd) = fs::open(b"/dev/null", fs::O_RDONLY, 0)
                    {
                        let _ = process::dup2(fd, 0);
                        let _ = io::close(fd);
                    }
                }
                if let Some(r) = prev {
                    let _ = process::dup2(r, 0);
                    let _ = io::close(r);
                }
                if let Some((r, w)) = pipe {
                    let _ = process::dup2(w, 1);
                    let _ = io::close(w);
                    let _ = io::close(r);
                }
                self.exec_in_place = matches!(c, Command::Simple { .. });
                let r = self.run(c);
                self.child_exit(r);
            }
            if monitor {
                if pgid == 0 {
                    pgid = pid;
                }
                let _ = process::setpgid(pid, pgid);
            }
            if let Some(r) = prev.take() {
                let _ = io::close(r);
            }
            if let Some((r, w)) = pipe {
                let _ = io::close(w);
                prev = Some(r);
            }
            pids.push(pid);
        }
        (pids, pgid, prev)
    }

    fn pipeline(&mut self, cmds: &[Command]) -> Res {
        if cmds.len() == 1 {
            return self.run(&cmds[0]);
        }
        let monitor = self.opts.monitor && self.tty.is_some();
        // `lastpipe`: the last command runs in this shell (bash, without
        // job control).
        let lastpipe = !monitor && self.shopt("lastpipe");
        let forked = if lastpipe { cmds.len() - 1 } else { cmds.len() };
        let (pids, pgid, mut prev) = self.spawn_pipeline(cmds, forked, monitor, false);
        let mut last = None;
        if lastpipe && let Some(r) = prev.take() {
            let saved = process::fcntl(0, process::F_DUPFD_CLOEXEC, SAVE_FD).map_or(-1, |d| d as i32);
            let _ = process::dup2(r, 0);
            let _ = io::close(r);
            let res = self.run(&cmds[forked]);
            self.restore(alloc::vec![(0, saved)]);
            last = Some(res);
        }
        if let Some(r) = prev {
            let _ = io::close(r);
        }
        let label = || String::from("pipeline");
        let st = self.wait_fg(&pids, pgid, &label);
        match last {
            Some(r) => {
                let st = r?;
                self.pipestatus.push(st);
                Ok(if self.opts.pipefail && st == 0 {
                    self.pipestatus.iter().rev().copied().find(|&c| c != 0).unwrap_or(0)
                } else {
                    st
                })
            }
            None => Ok(st),
        }
    }

    /// An asynchronous list (`cmd &`).
    fn background(&mut self, c: &Command) -> i32 {
        let monitor = self.opts.monitor && self.tty.is_some();
        // A pipeline's commands are this shell's children, as bash starts
        // them: `$!` is the last one's.
        if let Command::Pipeline { bang: false, cmds } = c
            && cmds.len() > 1
        {
            let (pids, pgid, prev) = self.spawn_pipeline(cmds, cmds.len(), monitor, true);
            if let Some(r) = prev {
                let _ = io::close(r);
            }
            let Some(&last) = pids.last() else { return 1 };
            self.last_bg = last;
            let id = self.jobs.add(if monitor { pgid } else { 0 }, &pids, crate::builtins::describe(c), false);
            if self.interactive {
                io::err(alloc::format!("[{id}] {last}\n").as_bytes());
            }
            return 0;
        }
        let Some(pid) = self.fork() else { return 1 };
        if pid == 0 {
            self.exec_in_place = matches!(c, Command::Simple { .. });
            if monitor {
                let _ = process::setpgid(0, 0);
            } else {
                // §2.9.3: without job control, background commands ignore
                // SIGINT and SIGQUIT and read /dev/null.
                let _ = signal::set(signal::SIGINT, signal::Disposition::Ignore);
                let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
                if let Ok(fd) = fs::open(b"/dev/null", fs::O_RDONLY, 0) {
                    let _ = process::dup2(fd, 0);
                    let _ = io::close(fd);
                }
            }
            let r = self.run(c);
            self.child_exit(r);
        }
        if monitor {
            let _ = process::setpgid(pid, pid);
        }
        self.last_bg = pid;
        let label = crate::builtins::describe(c);
        let id = self.jobs.add(if monitor { pid } else { 0 }, &[pid], label, false);
        if self.interactive {
            io::err(alloc::format!("[{id}] {pid}\n").as_bytes());
        }
        0
    }

    /// `$(...)`: the output of `prog` run in a subshell, without
    /// trailing newlines.
    pub fn command_output(&mut self, prog: &Program) -> Vec<u8> {
        let (r, w) = match process::pipe(fs::O_CLOEXEC) {
            Ok(p) => p,
            Err(e) => {
                crate::error(format_args!("pipe: {e}"));
                return Vec::new();
            }
        };
        let Some(pid) = self.fork() else {
            let _ = io::close(r);
            let _ = io::close(w);
            return Vec::new();
        };
        if pid == 0 {
            let _ = io::close(r);
            let _ = process::dup2(w, 1);
            let _ = io::close(w);
            if !self.shopt("inherit_errexit") {
                self.opts.errexit = false;
            }
            self.exec_in_place = only_simple(prog);
            let res = self.run_program(prog);
            self.child_exit(res);
        }
        let _ = io::close(w);
        let mut out = io::read_to_end(r).unwrap_or_default();
        let _ = io::close(r);
        let st = process::wait(pid, 0).map_or(1, |(_, s)| process::exit_code(s));
        self.cmdsub_status = Some(st);
        self.status = st;
        while out.last() == Some(&b'\n') {
            out.pop();
        }
        out
    }

    // --- redirections -----------------------------------------------------

    /// Run `f` with `redirs` in effect.
    fn with_redirs(&mut self, redirs: &[Redir], f: impl FnOnce(&mut Shell) -> Res) -> Res {
        if redirs.is_empty() {
            return f(self);
        }
        let mut saved = Saved::new();
        if self.redirect(redirs, Some(&mut saved)).is_err() {
            self.restore(saved);
            return Ok(1);
        }
        let r = f(self);
        self.restore(saved);
        r
    }

    /// Apply redirections, saving what they replace when `save` is given.
    pub fn redirect(&mut self, redirs: &[Redir], mut save: Option<&mut Saved>) -> Result<(), RedirError> {
        io::flush_stdout();
        for r in redirs {
            let default_fd = match r.kind {
                RedirKind::In
                | RedirKind::ReadWrite
                | RedirKind::DupIn
                | RedirKind::HereDoc
                | RedirKind::HereString => 0,
                _ => 1,
            };
            let fd = r.fd.unwrap_or(default_fd);
            let new = self.redir_source(r, fd)?;
            let targets: &[i32] = if matches!(r.kind, RedirKind::OutErr | RedirKind::AppendErr) || new.1 {
                &[1, 2]
            } else {
                core::slice::from_ref(&fd)
            };
            for &t in targets {
                if let Some(s) = save.as_deref_mut()
                    && !s.iter().any(|x| x.0 == t)
                {
                    let copy = process::fcntl(t, process::F_DUPFD_CLOEXEC, SAVE_FD).map_or(-1, |d| d as i32);
                    s.push((t, copy));
                }
                match new.0 {
                    Some(src) if src != t => {
                        if let Err(e) = process::dup2(src, t) {
                            crate::error(format_args!("{t}: {e}"));
                            return Err(RedirError);
                        }
                    }
                    Some(_) => {
                        // The new descriptor landed on its target: it must
                        // survive exec.
                        let _ = process::fcntl(t, process::F_SETFD, 0);
                    }
                    None => {
                        let _ = io::close(t);
                    }
                }
            }
            if let Some(src) = new.0
                && new.2
                && !targets.contains(&src)
            {
                let _ = io::close(src);
            }
        }
        Ok(())
    }

    /// The descriptor a redirection installs: (fd or None to close, also
    /// on stderr, close the source afterwards).
    fn redir_source(&mut self, r: &Redir, fd: i32) -> Result<(Option<i32>, bool, bool), RedirError> {
        let open = |sh: &mut Shell, flags: u32| -> Result<(Option<i32>, bool, bool), RedirError> {
            let path = sh.expand_target(&r.target).map_err(|_| RedirError)?;
            if flags & fs::O_TRUNC != 0
                && sh.opts.noclobber
                && r.kind == RedirKind::Out
                && fs::stat(&path).is_ok_and(|s| s.is_file())
            {
                crate::error(format_args!("{}: cannot overwrite existing file", text(&path)));
                return Err(RedirError);
            }
            match fs::open(&path, flags | fs::O_CLOEXEC, 0o666) {
                Ok(n) => Ok((Some(n), false, true)),
                Err(e) => {
                    crate::error(format_args!("{}: {}", text(&path), e));
                    Err(RedirError)
                }
            }
        };
        let w = fs::O_WRONLY | fs::O_CREAT;
        match r.kind {
            RedirKind::In => open(self, fs::O_RDONLY),
            RedirKind::Out | RedirKind::Clobber | RedirKind::OutErr => open(self, w | fs::O_TRUNC),
            RedirKind::Append | RedirKind::AppendErr => open(self, w | fs::O_APPEND),
            RedirKind::ReadWrite => open(self, fs::O_RDWR | fs::O_CREAT),
            RedirKind::DupIn | RedirKind::DupOut => {
                let t = self.expand_target(&r.target).map_err(|_| RedirError)?;
                if t == b"-" {
                    return Ok((None, false, false));
                }
                let (num, mv) = match t.strip_suffix(b"-") {
                    Some(n) => (n, true),
                    None => (&t[..], false),
                };
                if let Some(n) = slate_coreutils::util::parse_num::<i32>(num) {
                    if process::fcntl(n, process::F_GETFD, 0).is_err() {
                        crate::error(format_args!("{n}: Bad file descriptor"));
                        return Err(RedirError);
                    }
                    return Ok((Some(n), false, mv));
                }
                if r.kind == RedirKind::DupOut && r.fd.is_none() {
                    // `>&file` is `&>file`.
                    let (n, _, c) = open(self, w | fs::O_TRUNC)?;
                    return Ok((n, true, c));
                }
                crate::error(format_args!("{}: ambiguous redirect", text(&t)));
                Err(RedirError)
            }
            RedirKind::HereDoc | RedirKind::HereString => {
                let mut body = if r.kind == RedirKind::HereString {
                    let mut b = self.expand_single(&r.target).map_err(|_| RedirError)?;
                    b.push(b'\n');
                    b
                } else {
                    let h = r.heredoc.as_ref().map(|h| h.borrow().body.clone()).unwrap_or_default();
                    self.expand_single(&h).map_err(|_| RedirError)?
                };
                let _ = fd;
                self.here_pipe(core::mem::take(&mut body)).map(|n| (Some(n), false, true))
            }
        }
    }

    /// A pipe that reads back `body`: written at once when it fits in the
    /// pipe, else by a child.
    fn here_pipe(&mut self, body: Vec<u8>) -> Result<i32, RedirError> {
        let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| {
            crate::error(format_args!("pipe: {e}"));
            RedirError
        })?;
        if body.len() <= 16 * 1024 {
            let _ = io::write_all(w, &body);
            let _ = io::close(w);
            return Ok(r);
        }
        match process::fork() {
            Ok(0) => {
                let _ = io::close(r);
                let _ = io::write_all(w, &body);
                process::exit_now(0);
            }
            Ok(_) => {
                let _ = io::close(w);
                Ok(r)
            }
            Err(e) => {
                crate::error(format_args!("fork: {e}"));
                let _ = io::close(r);
                let _ = io::close(w);
                Err(RedirError)
            }
        }
    }

    /// Undo saved redirections.
    pub fn restore(&mut self, saved: Saved) {
        io::flush_stdout();
        for (fd, copy) in saved.into_iter().rev() {
            if copy < 0 {
                let _ = io::close(fd);
            } else {
                let _ = process::dup2(copy, fd);
                let _ = io::close(copy);
            }
        }
    }

    // --- traps and sources ------------------------------------------------

    /// Run the actions of trapped signals that arrived.
    pub fn run_traps(&mut self) -> Result<(), Flow> {
        let caught = signal::take();
        if caught == 0 {
            return Ok(());
        }
        for sig in 1..64 {
            if caught & (1 << sig) == 0 {
                continue;
            }
            if sig == signal::SIGINT && self.interactive && !self.traps.contains_key(&sig) {
                return Err(Flow::Interrupt);
            }
            if let Some(action) = self.traps.get(&sig).cloned()
                && !action.is_empty()
            {
                let st = self.status;
                self.eval(&action)?;
                self.status = st;
            }
        }
        Ok(())
    }

    /// Parse and run `src` (eval, trap actions).
    pub fn eval(&mut self, src: &[u8]) -> Res {
        let mut p = self.parser(src);
        p.set_line(self.lineno);
        match p.program() {
            Ok(prog) => self.run_program(&prog),
            Err(e) => {
                crate::syntax_error(&e);
                if self.interactive { Ok(2) } else { Err(Flow::Exit(2)) }
            }
        }
    }

    /// Run a script line by line (scripts, `.`). Returns the status.
    pub fn run_source(&mut self, src: &[u8]) -> i32 {
        match self.source(src) {
            Ok(s) => s,
            Err(Flow::Exit(s)) => self.exit_shell(s),
            Err(_) => self.status,
        }
    }

    /// Run `src` line by line, passing control flow out.
    pub fn source(&mut self, src: &[u8]) -> Res {
        let mut p = self.parser(src);
        let mut alias_gen = self.alias_gen;
        let mut st = 0;
        loop {
            if alias_gen != self.alias_gen {
                alias_gen = self.alias_gen;
                p.set_aliases(if self.shopt("expand_aliases") { self.aliases.clone() } else { Default::default() });
            }
            p.extglob = self.shopt("extglob");
            let start = p.pos();
            match p.line() {
                Ok(Some(prog)) => {
                    if self.opts.verbose {
                        io::err(&p.input()[start..p.pos()]);
                    }
                    st = self.run_program(&prog)?;
                }
                Ok(None) => return Ok(st),
                Err(e) => {
                    // bash names the line it stopped on and shows it.
                    let (line, text_of_line) = p.error_context();
                    if !self.interactive {
                        crate::set_error_line(line);
                    }
                    crate::syntax_error(&e);
                    if let crate::parser::ParseError::Syntax(_) = e {
                        crate::error(format_args!("'{}'", text(&text_of_line)));
                    }
                    return if self.interactive { Ok(2) } else { Err(Flow::Exit(2)) };
                }
            }
        }
    }
}

/// A program that is one simple command in the foreground.
fn only_simple(p: &Program) -> bool {
    matches!(p.0.as_slice(), [(Command::Simple { .. }, false)])
}

/// `select`'s menu: numbered words one a line, or in columns (down, then
/// across) when they need more than one row. The layout is bash's, as
/// observed: columns as wide as the widest entry plus two, tabs where
/// they fit, numbers right-aligned except in the first column.
pub fn select_menu(items: &[Vec<u8>], cols: usize) -> Vec<u8> {
    let n = items.len();
    let digits = alloc::format!("{n}").len();
    let widest = items.iter().map(|w| String::from_utf8_lossy(w).chars().count()).max().unwrap_or(0);
    let width = widest + digits + 4;
    let per_row = (cols / width).max(1);
    let mut rows = n.div_ceil(per_row);
    if rows == 1 {
        rows = n;
    }
    let ncols = n.div_ceil(rows);
    let mut out = Vec::new();
    for r in 0..rows {
        let mut pos = 0;
        for c in 0..ncols {
            let i = c * rows + r;
            if i >= n {
                break;
            }
            if c > 0 {
                // Tabs to the column, then blanks.
                let target = c * width;
                while (pos / 8 + 1) * 8 <= target {
                    out.push(b'\t');
                    pos = (pos / 8 + 1) * 8;
                }
                while pos < target {
                    out.push(b' ');
                    pos += 1;
                }
            }
            let num = if c == 0 && ncols > 1 {
                alloc::format!("{}) ", i + 1)
            } else {
                alloc::format!("{:>digits$}) ", i + 1)
            };
            out.extend_from_slice(num.as_bytes());
            out.extend_from_slice(&items[i]);
            pos += num.len() + String::from_utf8_lossy(&items[i]).chars().count();
        }
        out.push(b'\n');
    }
    out
}

/// TIMEFORMAT's `%[p][l]R`, `U`, `S`, `P` and `%%` (bash).
pub fn time_format(fmt: &[u8], real: u64, user: u64, sys: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        if fmt[i] != b'%' {
            out.push(fmt[i]);
            i += 1;
            continue;
        }
        i += 1;
        let mut prec = 3usize;
        if let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
            prec = usize::from(d - b'0').min(3);
            i += 1;
        }
        let long = fmt.get(i) == Some(&b'l');
        if long {
            i += 1;
        }
        let ns = match fmt.get(i) {
            Some(b'R') => real,
            Some(b'U') => user,
            Some(b'S') => sys,
            Some(b'P') => {
                let pct = if real == 0 { 0 } else { (user + sys) as u128 * 10_000 / real as u128 };
                out.extend_from_slice(alloc::format!("{}.{:02}", pct / 100, pct % 100).as_bytes());
                i += 1;
                continue;
            }
            Some(b'%') => {
                out.push(b'%');
                i += 1;
                continue;
            }
            _ => {
                out.push(b'%');
                continue;
            }
        };
        i += 1;
        let ms = ns / 1_000_000;
        let (whole, frac) = (ms / 1000, ms % 1000);
        let frac = match prec {
            0 => String::new(),
            p => alloc::format!(".{:0p$}", frac / 10u64.pow(3 - p as u32)),
        };
        let s =
            if long { alloc::format!("{}m{}{frac}s", whole / 60, whole % 60) } else { alloc::format!("{whole}{frac}") };
        out.extend_from_slice(s.as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_layout() {
        let w = |v: &[&str]| v.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>();
        // As bash 5.3 prints them.
        assert_eq!(select_menu(&w(&["a", "b", "c"]), 80), b"1) a\n2) b\n3) c\n");
        let ten = w(&["w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10"]);
        assert_eq!(
            select_menu(&ten, 80),
            b"1) w1\t  3) w3\t   5) w5    7) w7    9) w9\n2) w2\t  4) w4\t   6) w6    8) w8   10) w10\n"
        );
        let eleven = w(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]);
        assert!(select_menu(&eleven, 10).starts_with(b" 1) a\n 2) b\n"));
        assert!(select_menu(&eleven, 30).starts_with(b"1) a    4) d   7) g  10) j\n"));
    }

    #[test]
    fn timeformat() {
        let f = |s: &str| String::from_utf8(time_format(s.as_bytes(), 101_000_000, 0, 1_000_000)).unwrap();
        assert_eq!(f("\nreal\t%3lR\nuser\t%3lU\nsys\t%3lS"), "\nreal\t0m0.101s\nuser\t0m0.000s\nsys\t0m0.001s");
        assert_eq!(f("real %2R"), "real 0.10");
        assert_eq!(f("%0R|%%"), "0|%");
    }
}
