// SPDX-License-Identifier: MIT OR Apache-2.0

//! The command printer: a function's definition as `declare -f` and
//! `type` show it. The layout is bash's, as observed (`declare -f` in
//! bash 5.3): four spaces per level, one command a line ending in `;`,
//! `name () ` and `{ ` with a trailing blank, `elif` as a nested `if`,
//! here-document bodies after the line that uses them.

use alloc::vec::Vec;

use crate::ast::*;

/// `name () { ...; }` as bash prints it.
pub fn function(name: &[u8], body: &Command) -> Vec<u8> {
    let mut p = Printer::default();
    p.out.extend_from_slice(name);
    p.out.extend_from_slice(b" () \n");
    match body {
        Command::Group(list, redirs) => {
            p.out.extend_from_slice(b"{ \n");
            p.list(list, 4, true);
            p.out.extend_from_slice(b"\n}");
            p.redirs(redirs);
        }
        other => {
            p.out.extend_from_slice(b"{ \n    ");
            p.command(other, 4);
            p.flush_heredocs();
            p.out.extend_from_slice(b"\n}");
        }
    }
    p.flush_heredocs();
    p.out
}

/// A command on one line where possible (job labels, `$(...)`).
pub fn command(c: &Command) -> Vec<u8> {
    let mut p = Printer::default();
    p.command(c, 0);
    p.flush_heredocs();
    p.out
}

/// A word as written.
pub fn word(w: &Word) -> Vec<u8> {
    let mut p = Printer::default();
    p.word(w);
    p.out
}

#[derive(Default)]
struct Printer {
    out: Vec<u8>,
    /// Here-documents of the command being printed: (body, delimiter).
    heredocs: Vec<(Vec<u8>, Vec<u8>)>,
    /// The last command printed had here-documents (its `;` is dropped).
    after_heredoc: bool,
    /// Bodies were written since this was last cleared.
    flushed: bool,
    /// Inside `$(...)`: groups stay on one line.
    flat: usize,
}

fn spaces(out: &mut Vec<u8>, n: usize) {
    out.resize(out.len() + n, b' ');
}

impl Printer {
    /// Write the pending here-document bodies after a newline.
    fn flush_heredocs(&mut self) -> bool {
        if self.heredocs.is_empty() {
            return false;
        }
        self.out.push(b'\n');
        for (body, delim) in core::mem::take(&mut self.heredocs) {
            self.out.extend_from_slice(&body);
            self.out.extend_from_slice(&delim);
            self.out.push(b'\n');
        }
        self.flushed = true;
        true
    }

    /// A list at `level`: one command a line, `;` between, ` & ` after
    /// background ones. `first`: indent the first command too.
    fn list(&mut self, p: &Program, level: usize, first: bool) {
        for (i, (c, bg)) in p.0.iter().enumerate() {
            if i > 0 {
                let (_, prev_bg) = p.0[i - 1];
                if prev_bg {
                    self.out.push(b' ');
                } else {
                    if !self.after_heredoc {
                        self.out.push(b';');
                    }
                    self.out.push(b'\n');
                    spaces(&mut self.out, level);
                }
            } else if first {
                spaces(&mut self.out, level);
            }
            self.flushed = false;
            self.command(c, level);
            if *bg {
                self.out.extend_from_slice(b" &");
            }
            self.flush_heredocs();
            self.after_heredoc = self.flushed;
        }
    }

    /// A list inside `$(...)`: `; ` between commands.
    fn flat(&mut self, p: &Program) {
        self.flat += 1;
        self.flat_list(p);
        self.flat -= 1;
    }

    fn flat_list(&mut self, p: &Program) {
        for (i, (c, bg)) in p.0.iter().enumerate() {
            if i > 0 && !p.0[i - 1].1 {
                self.out.extend_from_slice(b"; ");
            } else if i > 0 {
                self.out.push(b' ');
            }
            self.command(c, 0);
            if *bg {
                self.out.extend_from_slice(b" &");
            }
            if self.flush_heredocs() {
                self.out.pop();
            }
        }
    }

    fn command(&mut self, c: &Command, level: usize) {
        match c {
            Command::Simple { assigns, words, redirs, .. } => {
                let mut first = true;
                for a in assigns {
                    if !first {
                        self.out.push(b' ');
                    }
                    first = false;
                    self.assign(a);
                }
                for w in words {
                    if !first {
                        self.out.push(b' ');
                    }
                    first = false;
                    self.word(w);
                }
                if first {
                    self.redirs_from(redirs, false);
                } else {
                    self.redirs(redirs);
                }
            }
            Command::Pipeline { bang, cmds } => {
                if *bang {
                    self.out.extend_from_slice(b"! ");
                }
                for (i, c) in cmds.iter().enumerate() {
                    if i > 0 {
                        if self.flush_heredocs() {
                            spaces(&mut self.out, 2);
                        } else {
                            self.out.push(b' ');
                        }
                    }
                    self.command(c, level);
                    if i + 1 < cmds.len() {
                        self.out.extend_from_slice(b" |");
                    }
                }
            }
            Command::And(a, b) | Command::Or(a, b) => {
                self.command(a, level);
                self.out.extend_from_slice(if matches!(c, Command::And(..)) { b" && " } else { b" || " });
                self.command(b, level);
            }
            Command::Subshell(p, redirs) => {
                self.out.extend_from_slice(b"( ");
                self.list(p, level, false);
                self.after_heredoc = false;
                self.out.extend_from_slice(b" )");
                self.redirs(redirs);
            }
            Command::Group(p, redirs) if self.flat > 0 => {
                self.out.extend_from_slice(b"{ ");
                self.flat_list(p);
                self.out.extend_from_slice(b"; }");
                self.redirs(redirs);
            }
            Command::Group(p, redirs) => {
                self.out.extend_from_slice(b"{ \n");
                self.list(p, level + 4, true);
                self.after_heredoc = false;
                self.out.push(b'\n');
                spaces(&mut self.out, level);
                self.out.push(b'}');
                self.redirs(redirs);
            }
            Command::If { arms, otherwise, redirs } => {
                self.if_arms(arms, otherwise.as_ref(), level);
                self.redirs(redirs);
            }
            Command::Loop { until, cond, body, redirs } => {
                self.out.extend_from_slice(if *until { b"until " } else { b"while " });
                self.list(cond, level, false);
                self.out.extend_from_slice(b"; do\n");
                self.body(body, level);
                self.out.extend_from_slice(b"done");
                self.redirs(redirs);
            }
            Command::For { var, words, body, redirs, .. } | Command::Select { var, words, body, redirs, .. } => {
                self.out.extend_from_slice(if matches!(c, Command::For { .. }) { b"for " } else { b"select " });
                self.out.extend_from_slice(var);
                self.out.extend_from_slice(b" in");
                match words {
                    Some(ws) => {
                        for w in ws {
                            self.out.push(b' ');
                            self.word(w);
                        }
                    }
                    None => self.out.extend_from_slice(b" \"$@\""),
                }
                self.out.extend_from_slice(b";\n");
                self.do_done(body, level);
                self.redirs(redirs);
            }
            Command::ArithFor { exprs, body, redirs, .. } => {
                self.out.extend_from_slice(b"for ((");
                for (i, e) in exprs.iter().enumerate() {
                    if i > 0 {
                        self.out.extend_from_slice(b"; ");
                    }
                    let t = word(e);
                    let t = t.trim_ascii_start();
                    self.out.extend_from_slice(if t.is_empty() { b"1" } else { t });
                }
                self.out.extend_from_slice(b"))\n");
                self.do_done(body, level);
                self.redirs(redirs);
            }
            Command::Case { word, arms, redirs, .. } => {
                self.out.extend_from_slice(b"case ");
                self.word(word);
                self.out.extend_from_slice(b" in \n");
                for arm in arms {
                    spaces(&mut self.out, level + 4);
                    for (i, p) in arm.patterns.iter().enumerate() {
                        if i > 0 {
                            self.out.extend_from_slice(b" | ");
                        }
                        self.word(p);
                    }
                    self.out.extend_from_slice(b")\n");
                    self.list(&arm.body, level + 8, true);
                    self.after_heredoc = false;
                    self.out.push(b'\n');
                    spaces(&mut self.out, level + 4);
                    self.out.extend_from_slice(match arm.end {
                        CaseEnd::Break => b";;",
                        CaseEnd::FallThrough => b";&",
                        CaseEnd::Continue => b";;&",
                    });
                    self.out.push(b'\n');
                }
                spaces(&mut self.out, level);
                self.out.extend_from_slice(b"esac");
                self.redirs(redirs);
            }
            Command::FuncDef { name, body } => {
                self.out.extend_from_slice(name);
                self.out.extend_from_slice(b" () \n");
                spaces(&mut self.out, level);
                match &**body {
                    Command::Group(..) => self.command(body, level),
                    other => {
                        self.out.extend_from_slice(b"{ \n");
                        spaces(&mut self.out, level + 4);
                        self.command(other, level + 4);
                        self.flush_heredocs();
                        self.out.push(b'\n');
                        spaces(&mut self.out, level);
                        self.out.push(b'}');
                    }
                }
            }
            Command::Cond(cond, redirs, _) => {
                self.out.extend_from_slice(b"[[ ");
                self.cond(cond);
                self.out.extend_from_slice(b" ]]");
                self.redirs(redirs);
            }
            Command::Arith(w, redirs, _) => {
                self.out.extend_from_slice(b"((");
                self.word(w);
                self.out.extend_from_slice(b"))");
                self.redirs(redirs);
            }
            Command::Coproc { name, body } => {
                self.out.extend_from_slice(b"coproc ");
                if !matches!(**body, Command::Simple { .. }) {
                    self.out.extend_from_slice(name);
                    self.out.push(b' ');
                }
                self.command(body, level);
            }
            Command::Time { posix, cmd } => {
                self.out.extend_from_slice(if *posix { b"time -p" } else { b"time" });
                if let Some(c) = cmd {
                    self.out.push(b' ');
                    self.command(c, level);
                }
            }
        }
    }

    /// `if`/`elif`/`else` (elif printed as an `if` inside `else`).
    fn if_arms(&mut self, arms: &[(Program, Program)], otherwise: Option<&Program>, level: usize) {
        let (cond, body) = &arms[0];
        self.out.extend_from_slice(b"if ");
        self.list(cond, level, false);
        self.out.extend_from_slice(b"; then\n");
        self.body(body, level);
        if arms.len() > 1 {
            self.out.extend_from_slice(b"else\n");
            spaces(&mut self.out, level + 4);
            self.if_arms(&arms[1..], otherwise, level + 4);
            self.out.extend_from_slice(b";\n");
            spaces(&mut self.out, level);
        } else if let Some(o) = otherwise {
            self.out.extend_from_slice(b"else\n");
            self.body(o, level);
        }
        self.out.extend_from_slice(b"fi");
    }

    /// A compound command's body: its lines one level in, then the
    /// indentation for the closing word.
    fn body(&mut self, p: &Program, level: usize) {
        self.list(p, level + 4, true);
        if !self.after_heredoc {
            self.out.push(b';');
        }
        self.after_heredoc = false;
        self.out.push(b'\n');
        spaces(&mut self.out, level);
    }

    /// `do` on its own line, the body, `done` (for and select).
    fn do_done(&mut self, body: &Program, level: usize) {
        spaces(&mut self.out, level);
        self.out.extend_from_slice(b"do\n");
        self.body(body, level);
        self.out.extend_from_slice(b"done");
    }

    fn cond(&mut self, c: &Cond) {
        match c {
            Cond::And(a, b) => {
                self.cond(a);
                self.out.extend_from_slice(b" && ");
                self.cond(b);
            }
            Cond::Or(a, b) => {
                self.cond(a);
                self.out.extend_from_slice(b" || ");
                self.cond(b);
            }
            Cond::Not(a) => {
                self.out.extend_from_slice(b"! ");
                self.cond(a);
            }
            Cond::Paren(a) => {
                self.out.extend_from_slice(b"( ");
                self.cond(a);
                self.out.extend_from_slice(b" )");
            }
            Cond::Unary(op, w) => {
                self.out.extend_from_slice(op);
                self.out.push(b' ');
                self.word(w);
            }
            Cond::Binary(l, op, r) => {
                self.word(l);
                self.out.push(b' ');
                self.out.extend_from_slice(op);
                self.out.push(b' ');
                self.word(r);
            }
            Cond::Word(w) => {
                self.out.extend_from_slice(b"-n ");
                self.word(w);
            }
        }
    }

    fn redirs(&mut self, redirs: &[Redir]) {
        self.redirs_from(redirs, true);
    }

    /// Redirections, each after a blank (`lead`: the first one too).
    fn redirs_from(&mut self, redirs: &[Redir], lead: bool) {
        for (i, r) in redirs.iter().enumerate() {
            if lead || i > 0 {
                self.out.push(b' ');
            }
            self.redir(r);
        }
    }

    fn redir(&mut self, r: &Redir) {
        let default_fd = match r.kind {
            RedirKind::In | RedirKind::ReadWrite | RedirKind::DupIn | RedirKind::HereDoc | RedirKind::HereString => 0,
            _ => 1,
        };
        if let Some(fd) = r.fd.filter(|&f| f != default_fd) {
            self.out.extend_from_slice(alloc::format!("{fd}").as_bytes());
        }
        let (op, space): (&[u8], bool) = match r.kind {
            RedirKind::In => (b"<", true),
            RedirKind::Out => (b">", true),
            RedirKind::Clobber => (b">|", true),
            RedirKind::Append => (b">>", true),
            RedirKind::ReadWrite => (b"<>", true),
            RedirKind::DupIn => (b"<&", false),
            RedirKind::DupOut => (b">&", false),
            RedirKind::HereString => (b"<<<", true),
            RedirKind::OutErr => (b"&>", true),
            RedirKind::AppendErr => (b"&>>", true),
            RedirKind::HereDoc => {
                let h = r.heredoc.as_ref().map(|h| h.borrow().clone());
                let strip = h.as_ref().is_some_and(|h| h.strip);
                (if strip { b"<<-" } else { b"<<" }, false)
            }
        };
        self.out.extend_from_slice(op);
        if space {
            self.out.push(b' ');
        }
        self.word(&r.target);
        if r.kind == RedirKind::HereDoc
            && let Some(h) = &r.heredoc
        {
            let h = h.borrow();
            self.heredocs.push((h.raw.clone(), crate::expand::word_text(&r.target)));
        }
    }

    fn assign(&mut self, a: &Assign) {
        self.out.extend_from_slice(&a.name);
        if let Some(i) = &a.index {
            self.out.push(b'[');
            self.word(i);
            self.out.push(b']');
        }
        if a.append {
            self.out.push(b'+');
        }
        self.out.push(b'=');
        self.word(&a.value);
    }

    fn word(&mut self, w: &Word) {
        for p in w {
            self.part(p, false);
        }
    }

    fn part(&mut self, p: &WordPart, dquoted: bool) {
        match p {
            WordPart::Lit(l) => self.out.extend_from_slice(l),
            WordPart::Escaped(c) => {
                self.out.push(b'\\');
                self.out.push(*c);
            }
            WordPart::Quoted(q) if dquoted => {
                for (i, &c) in q.iter().enumerate() {
                    let special = matches!(c, b'"' | b'$' | b'`')
                        || c == b'\\' && q.get(i + 1).is_none_or(|n| matches!(n, b'"' | b'$' | b'`' | b'\\' | b'\n'));
                    if special {
                        self.out.push(b'\\');
                    }
                    self.out.push(c);
                }
            }
            WordPart::Quoted(q) => {
                self.out.push(b'\'');
                for &c in q {
                    if c == b'\'' {
                        self.out.extend_from_slice(b"'\\''");
                    } else {
                        self.out.push(c);
                    }
                }
                self.out.push(b'\'');
            }
            WordPart::DQuote(inner) => {
                self.out.push(b'"');
                for p in inner {
                    self.part(p, true);
                }
                self.out.push(b'"');
            }
            WordPart::Param(p) => self.param(p),
            WordPart::CmdSub(prog, backquote) => {
                self.out.extend_from_slice(if *backquote { b"`" } else { b"$(" });
                self.flat(prog);
                self.out.extend_from_slice(if *backquote { b"`" } else { b")" });
            }
            WordPart::Arith(w) => {
                self.out.extend_from_slice(b"$((");
                self.word(w);
                self.out.extend_from_slice(b"))");
            }
            WordPart::ArrayLit(elems) => {
                self.out.push(b'(');
                for (i, e) in elems.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b' ');
                    }
                    self.word(e);
                }
                self.out.push(b')');
            }
            WordPart::ProcSub(prog, out) => {
                self.out.extend_from_slice(if *out { b">(" } else { b"<(" });
                self.flat(prog);
                self.out.push(b')');
            }
        }
    }

    fn param(&mut self, p: &Param) {
        if !p.braced {
            self.out.push(b'$');
            self.out.extend_from_slice(&p.name);
            return;
        }
        self.out.extend_from_slice(b"${");
        if p.op == ParamOp::Length {
            self.out.push(b'#');
        }
        if p.indirect {
            self.out.push(b'!');
        }
        self.out.extend_from_slice(&p.name);
        if let Some(i) = &p.index {
            self.out.push(b'[');
            self.word(i);
            self.out.push(b']');
        }
        let colon: &[u8] = if p.colon { b":" } else { b"" };
        match &p.op {
            ParamOp::Get | ParamOp::Length => {}
            ParamOp::Names(star) => self.out.push(if *star { b'*' } else { b'@' }),
            ParamOp::Default(w) | ParamOp::Assign(w) | ParamOp::Error(w) | ParamOp::Alt(w) => {
                self.out.extend_from_slice(colon);
                self.out.push(match p.op {
                    ParamOp::Default(_) => b'-',
                    ParamOp::Assign(_) => b'=',
                    ParamOp::Error(_) => b'?',
                    _ => b'+',
                });
                self.word(w);
            }
            ParamOp::RemoveSuffix(w, longest) | ParamOp::RemovePrefix(w, longest) => {
                let c = if matches!(p.op, ParamOp::RemoveSuffix(..)) { b'%' } else { b'#' };
                self.out.push(c);
                if *longest {
                    self.out.push(c);
                }
                self.word(w);
            }
            ParamOp::Replace { pat, rep, all, anchor } => {
                self.out.push(b'/');
                if *all {
                    self.out.push(b'/');
                } else if *anchor != 0 {
                    self.out.push(*anchor);
                }
                self.word(pat);
                if !rep.is_empty() {
                    self.out.push(b'/');
                    self.word(rep);
                }
            }
            ParamOp::Substr(off, len) => {
                self.out.push(b':');
                self.word(off);
                if let Some(l) = len {
                    self.out.push(b':');
                    self.word(l);
                }
            }
            ParamOp::Case(upper, all) => {
                let c = if *upper { b'^' } else { b',' };
                self.out.push(c);
                if *all {
                    self.out.push(c);
                }
            }
        }
        self.out.push(b'}');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn show(src: &str) -> String {
        let p = crate::parser::parse(src.as_bytes()).unwrap();
        let Command::FuncDef { name, body } = &p.0[0].0 else { panic!("not a function") };
        String::from_utf8(function(name, body)).unwrap()
    }

    #[test]
    fn bash_layout() {
        assert_eq!(show("f() { echo hi; }"), "f () \n{ \n    echo hi\n}");
        assert_eq!(
            show("f() { if a; then b; elif c; then d; else e; fi; }"),
            "f () \n{ \n    if a; then\n        b;\n    else\n        if c; then\n            d;\n        else\n            e;\n        fi;\n    fi\n}"
        );
        assert_eq!(
            show("f() { for i in 1 2; do echo $i; done; while a && b; do x | y; done; }"),
            "f () \n{ \n    for i in 1 2;\n    do\n        echo $i;\n    done;\n    while a && b; do\n        x | y;\n    done\n}"
        );
        assert_eq!(
            show("f() { case $x in a|b) one;; *) two ;& esac; }"),
            "f () \n{ \n    case $x in \n        a | b)\n            one\n        ;;\n        *)\n            two\n        ;&\n    esac\n}"
        );
        assert_eq!(
            show("f() { (cd /; ls) > o; { a; b; } 2>/dev/null; a & b; c & }"),
            "f () \n{ \n    ( cd /;\n    ls ) > o;\n    { \n        a;\n        b\n    } 2> /dev/null;\n    a & b;\n    c &\n}"
        );
        assert_eq!(
            show("f() { cat <<E\nx $y\nE\necho after; }"),
            "f () \n{ \n    cat <<E\nx $y\nE\n\n    echo after\n}"
        );
        assert_eq!(
            show("f() { a=1 b=\"x y\" cmd 'q' \"d$x\" $(ls -l) `pwd` $((1+2)) ${v:-d} a\\ b >out 2>&1 <in; }"),
            "f () \n{ \n    a=1 b=\"x y\" cmd 'q' \"d$x\" $(ls -l) `pwd` $((1+2)) ${v:-d} a\\ b > out 2>&1 < in\n}"
        );
        assert_eq!(
            show("f() { [[ -n $x && ( $y == a* || z ) ]]; ((i++)); for ((i=0;i<3;i++)); do :; done; }"),
            "f () \n{ \n    [[ -n $x && ( $y == a* || -n z ) ]];\n    ((i++));\n    for ((i=0; i<3; i++))\n    do\n        :;\n    done\n}"
        );
        assert_eq!(show("f() ( echo sub )"), "f () \n{ \n    ( echo sub )\n}");
        assert_eq!(show("function f { g() { echo; }; }"), "f () \n{ \n    g () \n    { \n        echo\n    }\n}");
        assert_eq!(
            show("f() { echo \"${x%%b*}\" ${#a[@]} ${!p*} ${x//a/b} ${x:1:2} ${x^^} \"a\\\"b\" $'q\\n'; }"),
            "f () \n{ \n    echo \"${x%%b*}\" ${#a[@]} ${!p*} ${x//a/b} ${x:1:2} ${x^^} \"a\\\"b\" 'q\n'\n}"
        );
    }
}
