// SPDX-License-Identifier: MIT OR Apache-2.0

//! sed, the stream editor (POSIX.1-2017 XCU sed, plus the GNU extensions
//! scripts use: -E, -i, -s, -z, `0,/re/`, `first~step`, `addr,+N`,
//! `addr,~N`, one-line `a`/`i`/`c`, `T`, `Q`, `R`, `W`, `F`, `z`, `l N`,
//! `\L \U \l \u \E` in replacements, `I` and `M` flags, the `e` command and
//! flag, and the `\dNNN \oNNN \xHH \cX` escapes).

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use slate_regex::{Options, Regex, Syntax};
use slate_rt::{fs, io, lossy};

use crate::util::{Opt, Parser, error};

#[derive(Clone, Debug)]
enum Addr {
    Line(u64),
    Last,
    /// `None`: the last regular expression used.
    Re(Option<Rc<Regex>>),
    Step(u64, u64),
    /// `0` in `0,/re/`.
    Zero,
}

#[derive(Clone, Debug)]
enum Addr2 {
    Addr(Addr),
    /// `addr,+N`
    Plus(u64),
    /// `addr,~N`
    Multiple(u64),
}

#[derive(Clone, Debug)]
enum Repl {
    Lit(Vec<u8>),
    /// `&` is group 0.
    Group(usize),
    Case(CaseOp),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CaseOp {
    Lower,
    Upper,
    LowerOne,
    UpperOne,
    End,
}

#[derive(Debug)]
struct Subst {
    re: Option<Rc<Regex>>,
    repl: Vec<Repl>,
    global: bool,
    nth: usize,
    print: bool,
    write: Option<usize>,
    /// `e`: run the result as a command, the output its new value.
    exec: bool,
}

#[derive(Debug)]
enum Kind {
    /// `{`: the index after the matching `}`.
    Block(usize),
    EndBlock,
    LineNumber,
    Append(Vec<u8>),
    Insert(Vec<u8>),
    Change(Vec<u8>),
    Branch(Option<usize>),
    BranchIf(Option<usize>),
    BranchUnless(Option<usize>),
    Delete,
    DeleteFirst,
    Get,
    GetAppend,
    Hold,
    HoldAppend,
    List(Option<usize>),
    Next,
    NextAppend,
    Print,
    PrintFirst,
    Quit(i32),
    QuitSilent(i32),
    ReadFile(Vec<u8>),
    ReadLine(usize),
    Subst(Box<Subst>),
    Write(usize),
    WriteFirst(usize),
    Exchange,
    Translate(Box<[u8; 256]>),
    Label,
    Zap,
    FileName,
    /// `e [command]`: without a command, run the pattern space.
    Exec(Option<Vec<u8>>),
}

/// GNU's character escapes: `\dNNN` (decimal), `\oNNN` (octal), `\xHH`
/// (hexadecimal) and `\cX` (control-X). `s[i]` is the letter after the
/// backslash; returns the byte and how many bytes the escape used after
/// the backslash.
fn char_escape(s: &[u8], i: usize) -> Option<(u8, usize)> {
    let digits = |radix: u32, max: usize| -> Option<(u32, usize)> {
        let mut v = 0u32;
        let mut n = 0;
        while n < max && i + 1 + n < s.len() && (s[i + 1 + n] as char).is_digit(radix) {
            v = v * radix + (s[i + 1 + n] as char).to_digit(radix)?;
            n += 1;
        }
        (n > 0).then_some((v, n))
    };
    match s.get(i)? {
        b'd' => digits(10, 3).filter(|(v, _)| *v < 256).map(|(v, n)| (v as u8, n + 1)),
        b'o' => digits(8, 3).filter(|(v, _)| *v < 256).map(|(v, n)| (v as u8, n + 1)),
        b'x' => digits(16, 2).map(|(v, n)| (v as u8, n + 1)),
        b'c' => {
            let x = *s.get(i + 1)?;
            Some((x.to_ascii_uppercase() ^ 0x40, 2))
        }
        _ => None,
    }
}

/// Run `cmd` with the shell and return what it wrote to standard output.
fn shell_output(cmd: &[u8]) -> Vec<u8> {
    use slate_rt::process;
    io::flush_stdout();
    let sh = process::find_in_path(b"sh").unwrap_or_else(|| b"/bin/sh".to_vec());
    let Ok((r, w)) = process::pipe(fs::O_CLOEXEC) else { return Vec::new() };
    match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 1);
            let argv = [b"sh".to_vec(), b"-c".to_vec(), cmd.to_vec()];
            let e = process::execve(&sh, &argv, slate_rt::env::vars());
            error(alloc::format!("couldn't run {}: {e}", lossy(&sh)));
            process::exit_now(127);
        }
        Ok(pid) => {
            let _ = io::close(w);
            let out = io::read_to_end(r).unwrap_or_default();
            let _ = io::close(r);
            let _ = process::wait(pid, 0);
            out
        }
        Err(e) => {
            let _ = io::close(r);
            let _ = io::close(w);
            error(alloc::format!("fork: {e}"));
            Vec::new()
        }
    }
}

#[derive(Debug)]
struct Cmd {
    a1: Option<Addr>,
    a2: Option<Addr2>,
    negate: bool,
    kind: Kind,
    /// Range state: active, and the line a `+N`/number range ends at.
    active: bool,
    end: u64,
}

/// An output file (`w`, `s///w`).
#[derive(Debug)]
struct OutFile {
    name: Vec<u8>,
    fd: i32,
}

struct Script {
    cmds: Vec<Cmd>,
    labels: Vec<(Vec<u8>, usize)>,
    pending: Vec<(usize, Vec<u8>)>,
    files: Vec<OutFile>,
    readers: Vec<(Vec<u8>, Option<io::Reader>)>,
    syntax: Syntax,
    quiet_marker: bool,
}

/// A script syntax error: (message, character position).
struct ParseErr(String, usize);

struct ScriptParser<'a> {
    s: &'a [u8],
    i: usize,
}

impl ScriptParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }
    fn err<T>(&self, m: &str) -> Result<T, ParseErr> {
        Err(ParseErr(String::from(m), self.i))
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    fn skip_ws_nl(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b';')) {
            self.i += 1;
        }
    }
    fn number(&mut self) -> Option<u64> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if start == self.i {
            return None;
        }
        core::str::from_utf8(&self.s[start..self.i]).ok()?.parse().ok()
    }

    /// Text up to an unescaped `delim`, with `\delim` unescaped; `\n`
    /// becomes a newline when `newline_escape`.
    fn delimited(&mut self, delim: u8, what: &str, regex: bool) -> Result<Vec<u8>, ParseErr> {
        let mut out = Vec::new();
        let mut in_bracket = false;
        loop {
            let Some(c) = self.bump() else { return self.err(what) };
            if c == b'\n' {
                // A literal newline ends the command (GNU: unterminated).
                return self.err(what);
            }
            if regex && c == b'[' && !in_bracket {
                in_bracket = true;
                out.push(c);
                // `[]` and `[^]` start with a literal `]`.
                if self.peek() == Some(b'^') {
                    out.push(b'^');
                    self.i += 1;
                }
                if self.peek() == Some(b']') {
                    out.push(b']');
                    self.i += 1;
                }
                continue;
            }
            if in_bracket {
                if regex
                    && c == b'\\'
                    && let Some((b, n)) = char_escape(self.s, self.i)
                {
                    out.push(b);
                    self.i += n;
                    continue;
                }
                if c == b']' {
                    in_bracket = false;
                }
                if c == b'\n' {
                    return self.err(what);
                }
                out.push(c);
                continue;
            }
            if c == delim {
                return Ok(out);
            }
            if c == b'\\' {
                if regex && let Some((b, n)) = char_escape(self.s, self.i) {
                    // The byte itself, special characters included (as
                    // GNU's sed: `\x5e` is an anchor).
                    out.push(b);
                    self.i += n;
                    continue;
                }
                let Some(n) = self.bump() else { return self.err(what) };
                if n == delim {
                    out.push(n);
                } else if n == b'n' && regex {
                    out.extend_from_slice(b"\\n");
                } else if n == b'\n' {
                    out.push(b'\n');
                } else {
                    out.push(b'\\');
                    out.push(n);
                }
                continue;
            }
            out.push(c);
        }
    }

    /// Text for a/i/c: GNU one-line form or `\` newline lines.
    fn text(&mut self) -> Result<Vec<u8>, ParseErr> {
        self.skip_ws();
        if self.peek() == Some(b'\\') {
            self.i += 1;
            if self.peek() == Some(b'\n') {
                self.i += 1;
            }
        }
        let mut out = Vec::new();
        while let Some(c) = self.bump() {
            match c {
                b'\\' => match self.bump() {
                    Some(n) => out.push(n),
                    None => break,
                },
                b'\n' => break,
                c => out.push(c),
            }
        }
        Ok(out)
    }

    /// A label or file name: the rest of the line (labels also end at `;`).
    fn word(&mut self, semicolon: bool) -> Vec<u8> {
        self.skip_ws();
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'\n' || (semicolon && c == b';') {
                break;
            }
            self.i += 1;
        }
        let mut w = self.s[start..self.i].to_vec();
        if semicolon {
            while w.last().is_some_and(|c| *c == b' ' || *c == b'\t') {
                w.pop();
            }
        }
        w
    }
}

fn compile_re(pat: &[u8], syntax: Syntax, flags: &[u8]) -> Result<Option<Rc<Regex>>, String> {
    if pat.is_empty() {
        return Ok(None);
    }
    let icase = flags.contains(&b'I') || flags.contains(&b'i');
    let newline = flags.contains(&b'M') || flags.contains(&b'm');
    let opts =
        Options { syntax, icase, newline, escapes: true, utf8: crate::util::utf8_locale(), ..Options::default() };
    Regex::new(pat, opts).map(|r| Some(Rc::new(r))).map_err(|e| e.0)
}

fn parse_repl(r: &[u8], groups: Option<usize>) -> Result<Vec<Repl>, String> {
    let mut out = Vec::new();
    let mut lit = Vec::new();
    let mut i = 0;
    let flush = |out: &mut Vec<Repl>, lit: &mut Vec<u8>| {
        if !lit.is_empty() {
            out.push(Repl::Lit(core::mem::take(lit)));
        }
    };
    while i < r.len() {
        let c = r[i];
        i += 1;
        match c {
            b'&' => {
                flush(&mut out, &mut lit);
                out.push(Repl::Group(0));
            }
            b'\\' if i < r.len() => {
                let e = r[i];
                i += 1;
                match e {
                    b'0'..=b'9' => {
                        let n = (e - b'0') as usize;
                        if groups.is_some_and(|g| n > g) {
                            return Err(alloc::format!("invalid reference \\{n} on `s' command's RHS"));
                        }
                        flush(&mut out, &mut lit);
                        out.push(Repl::Group(n));
                    }
                    b'n' => lit.push(b'\n'),
                    b't' => lit.push(b'\t'),
                    b'r' => lit.push(b'\r'),
                    b'a' => lit.push(7),
                    b'f' => lit.push(12),
                    b'v' => lit.push(11),
                    b'd' | b'o' | b'x' | b'c' if char_escape(r, i - 1).is_some() => {
                        // A literal byte, even `&` or a backslash.
                        let (b, n) = char_escape(r, i - 1).unwrap_or((e, 1));
                        lit.push(b);
                        i += n - 1;
                    }
                    b'L' | b'U' | b'l' | b'u' | b'E' => {
                        flush(&mut out, &mut lit);
                        out.push(Repl::Case(match e {
                            b'L' => CaseOp::Lower,
                            b'U' => CaseOp::Upper,
                            b'l' => CaseOp::LowerOne,
                            b'u' => CaseOp::UpperOne,
                            _ => CaseOp::End,
                        }));
                    }
                    other => lit.push(other),
                }
            }
            c => lit.push(c),
        }
    }
    flush(&mut out, &mut lit);
    Ok(out)
}

impl Script {
    fn open_out(&mut self, name: Vec<u8>) -> Result<usize, String> {
        if let Some(i) = self.files.iter().position(|f| f.name == name) {
            return Ok(i);
        }
        let fd = match name.as_slice() {
            b"/dev/stdout" => 1,
            b"/dev/stderr" => 2,
            _ => fs::open(&name, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o666)
                .map_err(|e| alloc::format!("couldn't open file {}: {e}", lossy(&name)))?,
        };
        self.files.push(OutFile { name, fd });
        Ok(self.files.len() - 1)
    }

    fn parse(&mut self, src: &[u8]) -> Result<(), ParseErr> {
        let mut p = ScriptParser { s: src, i: 0 };
        if src.starts_with(b"#n\n") || src == b"#n" {
            self.quiet_marker = true;
        }
        let mut blocks: Vec<usize> = Vec::new();
        loop {
            p.skip_ws_nl();
            let Some(_) = p.peek() else { break };
            let a1 = self.address(&mut p)?;
            let mut a2 = None;
            if a1.is_some() && p.peek() == Some(b',') {
                p.i += 1;
                p.skip_ws();
                a2 = Some(match p.peek() {
                    Some(b'+') => {
                        p.i += 1;
                        Addr2::Plus(p.number().ok_or(ParseErr(String::from("expected newer version of sed"), p.i))?)
                    }
                    Some(b'~') => {
                        p.i += 1;
                        Addr2::Multiple(p.number().ok_or(ParseErr(String::from("expected newer version of sed"), p.i))?)
                    }
                    _ => match self.address(&mut p)? {
                        Some(a) => Addr2::Addr(a),
                        None => return p.err("unexpected `,'"),
                    },
                });
            }
            if matches!(a1, Some(Addr::Zero)) && !matches!(a2, Some(Addr2::Addr(Addr::Re(_)))) {
                return p.err("invalid usage of line address 0");
            }
            p.skip_ws();
            let mut negate = false;
            while p.peek() == Some(b'!') {
                p.i += 1;
                negate = true;
                p.skip_ws();
            }
            let Some(c) = p.bump() else { return p.err("missing command") };
            let one_addr = |p: &ScriptParser<'_>| -> Result<(), ParseErr> {
                if a2.is_some() { p.err("command only uses one address") } else { Ok(()) }
            };
            let kind = match c {
                b'{' => {
                    blocks.push(self.cmds.len());
                    Kind::Block(0)
                }
                b'}' => {
                    if a1.is_some() {
                        return p.err("unexpected `}'");
                    }
                    let Some(open) = blocks.pop() else { return p.err("unexpected `}'") };
                    let here = self.cmds.len();
                    self.cmds[open].kind = Kind::Block(here + 1);
                    Kind::EndBlock
                }
                b'=' => Kind::LineNumber,
                b'a' => Kind::Append(p.text()?),
                b'i' => Kind::Insert(p.text()?),
                b'c' => Kind::Change(p.text()?),
                b'b' | b't' | b'T' => {
                    let l = p.word(true);
                    if !l.is_empty() {
                        self.pending.push((self.cmds.len(), l));
                    }
                    match c {
                        b'b' => Kind::Branch(None),
                        b't' => Kind::BranchIf(None),
                        _ => Kind::BranchUnless(None),
                    }
                }
                b':' => {
                    if a1.is_some() {
                        return p.err(": doesn't want any addresses");
                    }
                    let l = p.word(true);
                    if l.is_empty() {
                        return p.err("\":\" lacks a label");
                    }
                    self.labels.push((l, self.cmds.len()));
                    Kind::Label
                }
                b'#' => {
                    if a1.is_some() {
                        return p.err("comments don't accept any addresses");
                    }
                    while p.peek().is_some_and(|c| c != b'\n') {
                        p.i += 1;
                    }
                    continue;
                }
                b'd' => Kind::Delete,
                b'D' => Kind::DeleteFirst,
                b'g' => Kind::Get,
                b'G' => Kind::GetAppend,
                b'h' => Kind::Hold,
                b'H' => Kind::HoldAppend,
                b'l' => {
                    p.skip_ws();
                    Kind::List(p.number().map(|n| n as usize))
                }
                b'n' => Kind::Next,
                b'N' => Kind::NextAppend,
                b'p' => Kind::Print,
                b'P' => Kind::PrintFirst,
                b'q' | b'Q' => {
                    one_addr(&p)?;
                    p.skip_ws();
                    let code = p.number().unwrap_or(0) as i32;
                    if c == b'q' { Kind::Quit(code) } else { Kind::QuitSilent(code) }
                }
                b'r' => Kind::ReadFile(p.word(false)),
                b'R' => {
                    let name = p.word(false);
                    let idx = match self.readers.iter().position(|r| r.0 == name) {
                        Some(i) => i,
                        None => {
                            let reader = fs::open(&name, fs::O_RDONLY | fs::O_CLOEXEC, 0).ok().map(io::Reader::new);
                            self.readers.push((name, reader));
                            self.readers.len() - 1
                        }
                    };
                    Kind::ReadLine(idx)
                }
                b'w' | b'W' => {
                    let name = p.word(false);
                    let idx = self.open_out(name).map_err(|m| ParseErr(m, p.i))?;
                    if c == b'w' { Kind::Write(idx) } else { Kind::WriteFirst(idx) }
                }
                b'x' => Kind::Exchange,
                b'z' => Kind::Zap,
                b'F' => Kind::FileName,
                b's' => self.subst(&mut p)?,
                b'y' => {
                    let Some(d) = p.bump() else { return p.err("unterminated `y' command") };
                    let unesc = |v: Vec<u8>| -> Vec<u8> {
                        let mut o = Vec::new();
                        let mut k = 0;
                        while k < v.len() {
                            if v[k] == b'\\'
                                && let Some((b, n)) = char_escape(&v, k + 1)
                            {
                                o.push(b);
                                k += 1 + n;
                                continue;
                            }
                            if v[k] == b'\\' && k + 1 < v.len() {
                                o.push(match v[k + 1] {
                                    b'n' => b'\n',
                                    b't' => b'\t',
                                    b'\\' => b'\\',
                                    x => x,
                                });
                                k += 2;
                            } else {
                                o.push(v[k]);
                                k += 1;
                            }
                        }
                        o
                    };
                    let src = unesc(p.delimited(d, "unterminated `y' command", false)?);
                    let dst = unesc(p.delimited(d, "unterminated `y' command", false)?);
                    if src.len() != dst.len() {
                        return p.err("strings for `y' command are different lengths");
                    }
                    let mut map = [0u8; 256];
                    for (k, m) in map.iter_mut().enumerate() {
                        *m = k as u8;
                    }
                    for (a, b) in src.iter().zip(&dst) {
                        map[*a as usize] = *b;
                    }
                    Kind::Translate(Box::new(map))
                }
                b'e' => {
                    let cmd = p.word(false);
                    Kind::Exec(if cmd.is_empty() { None } else { Some(cmd) })
                }
                other => {
                    return Err(ParseErr(alloc::format!("unknown command: `{}'", other as char), p.i));
                }
            };
            self.cmds.push(Cmd { a1, a2, negate, kind, active: false, end: 0 });
            // After a command: blanks, then `;`, `}`, `#`, newline or the end.
            p.skip_ws();
            match p.peek() {
                None | Some(b'\n' | b';') => {}
                Some(b'}' | b'#') => {}
                Some(_)
                    if matches!(
                        c,
                        b'{' | b'a' | b'i' | b'c' | b'r' | b'R' | b'w' | b'W' | b':' | b'b' | b't' | b'T'
                    ) => {}
                Some(_) => return Err(ParseErr(String::from("extra characters after command"), p.i + 1)),
            }
        }
        if !blocks.is_empty() {
            return Err(ParseErr(String::from("unmatched `{'"), 0));
        }
        Ok(())
    }

    fn address(&mut self, p: &mut ScriptParser<'_>) -> Result<Option<Addr>, ParseErr> {
        match p.peek() {
            Some(b'0'..=b'9') => {
                let n = p.number().unwrap_or(0);
                if p.peek() == Some(b'~') {
                    p.i += 1;
                    let step = p.number().unwrap_or(0);
                    return Ok(Some(Addr::Step(n, step)));
                }
                Ok(Some(if n == 0 { Addr::Zero } else { Addr::Line(n) }))
            }
            Some(b'$') => {
                p.i += 1;
                Ok(Some(Addr::Last))
            }
            Some(c @ (b'/' | b'\\')) => {
                p.i += 1;
                let delim = if c == b'\\' { p.bump().unwrap_or(b'/') } else { b'/' };
                let pat = p.delimited(delim, "unterminated address regex", true)?;
                let mut flags = Vec::new();
                while let Some(f @ (b'I' | b'M')) = p.peek() {
                    flags.push(f);
                    p.i += 1;
                }
                let re = compile_re(&pat, self.syntax, &flags).map_err(|m| ParseErr(m, p.i))?;
                Ok(Some(Addr::Re(re)))
            }
            _ => Ok(None),
        }
    }

    fn subst(&mut self, p: &mut ScriptParser<'_>) -> Result<Kind, ParseErr> {
        let Some(d) = p.bump() else { return p.err("unterminated `s' command") };
        if d == b'\n' || d == b'\\' {
            return p.err("unterminated `s' command");
        }
        let pat = p.delimited(d, "unterminated `s' command", true)?;
        let repl = p.delimited(d, "unterminated `s' command", false)?;
        let mut s = Subst { re: None, repl: Vec::new(), global: false, nth: 1, print: false, write: None, exec: false };
        let mut flags = Vec::new();
        let mut have_nth = false;
        loop {
            match p.peek() {
                Some(b'g') => {
                    if s.global {
                        return p.err("multiple `g' options to `s' command");
                    }
                    s.global = true;
                }
                Some(b'p') => {
                    if s.print {
                        return p.err("multiple `p' options to `s' command");
                    }
                    s.print = true;
                }
                Some(f @ (b'i' | b'I' | b'm' | b'M')) => flags.push(f),
                Some(b'0'..=b'9') => {
                    if have_nth {
                        return p.err("multiple number options to `s' command");
                    }
                    let n = p.number().unwrap_or(0);
                    if n == 0 {
                        return p.err("number option to `s' command may not be zero");
                    }
                    s.nth = n as usize;
                    have_nth = true;
                    continue;
                }
                Some(b'w') => {
                    p.i += 1;
                    let name = p.word(false);
                    s.write = Some(self.open_out(name).map_err(|m| ParseErr(m, p.i))?);
                    break;
                }
                Some(b'e') => s.exec = true,
                Some(b' ' | b'\t' | b'\n' | b';' | b'}' | b'#') | None => break,
                Some(_) => return p.err("unknown option to `s'"),
            }
            p.i += 1;
        }
        s.re = compile_re(&pat, self.syntax, &flags).map_err(|m| ParseErr(m, p.i))?;
        s.repl = parse_repl(&repl, s.re.as_ref().map(|r| r.groups())).map_err(|m| ParseErr(m, p.i))?;
        Ok(Kind::Subst(Box::new(s)))
    }

    fn resolve(&mut self) -> Result<(), String> {
        for (idx, label) in core::mem::take(&mut self.pending) {
            let Some(&(_, target)) = self.labels.iter().find(|(l, _)| *l == label) else {
                return Err(alloc::format!("can't find label for jump to `{}'", lossy(&label)));
            };
            match &mut self.cmds[idx].kind {
                Kind::Branch(t) | Kind::BranchIf(t) | Kind::BranchUnless(t) => *t = Some(target),
                _ => {}
            }
        }
        Ok(())
    }
}

/// Lines from the input files, one ahead (for `$`).
struct Input {
    files: Vec<Vec<u8>>,
    next_file: usize,
    reader: Option<io::Reader>,
    fd: i32,
    /// Shared with each line read from it (no copy per line).
    name: Rc<[u8]>,
    /// The file the line being edited came from (`F`).
    current: Rc<[u8]>,
    /// The next line, whether it ended in the delimiter, and its file.
    ahead: Option<(Vec<u8>, bool, Rc<[u8]>)>,
    delim: u8,
    /// -s / -i: each file is its own input (`$` is each file's last line).
    separate: bool,
    status: i32,
    line: u64,
}

impl Input {
    fn open_next(&mut self) -> bool {
        while self.next_file < self.files.len() {
            let f = self.files[self.next_file].clone();
            self.next_file += 1;
            if self.fd > 0 {
                let _ = io::close(self.fd);
            }
            let fd = if f == b"-" {
                0
            } else {
                match fs::stat(&f) {
                    Ok(s) if s.is_dir() => {
                        error(alloc::format!("couldn't edit {}: not a regular file", lossy(&f)));
                        self.status = 2;
                        continue;
                    }
                    _ => {}
                }
                match fs::open(&f, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
                    Ok(fd) => fd,
                    Err(e) => {
                        error(alloc::format!("can't read {}: {e}", lossy(&f)));
                        self.status = 2;
                        continue;
                    }
                }
            };
            self.fd = fd;
            self.name = Rc::from(f);
            self.reader = Some(io::Reader::new(fd));
            return true;
        }
        self.reader = None;
        false
    }

    /// Read the next raw line from the current file (or the next one,
    /// unless separate).
    fn raw(&mut self, cross_files: bool) -> Option<(Vec<u8>, bool)> {
        loop {
            if let Some(r) = self.reader.as_mut()
                && let Ok(Some(mut l)) = r.split(self.delim)
            {
                let nl = l.last() == Some(&self.delim);
                if nl {
                    l.pop();
                }
                return Some((l, nl));
            }
            if !cross_files || !self.open_next() {
                return None;
            }
        }
    }

    fn fill(&mut self) {
        if self.ahead.is_none() {
            self.ahead = self.raw(!self.separate).map(|(l, nl)| (l, nl, self.name.clone()));
        }
    }

    fn next(&mut self) -> Option<(Vec<u8>, bool)> {
        self.fill();
        let (l, nl, name) = self.ahead.take()?;
        self.current = name;
        self.line += 1;
        Some((l, nl))
    }

    fn is_last(&mut self) -> bool {
        self.fill();
        self.ahead.is_none()
    }
}

struct Run {
    script: Script,
    quiet: bool,
    ps: Vec<u8>,
    hs: Vec<u8>,
    /// The current line ended without a newline.
    no_newline: bool,
    append: Vec<Vec<u8>>,
    tflag: bool,
    last_re: Option<Rc<Regex>>,
    wrap: usize,
    out: Vec<u8>,
    out_missing_nl: bool,
    delim: u8,
    /// -i: output collects for the file instead of going to stdout.
    capture: bool,
}

/// What the script decided at the end of a cycle.
enum End {
    /// Autoprint, then next cycle.
    Cycle,
    /// Next cycle without autoprint (d).
    Delete,
    /// Restart without reading (D with a newline).
    Restart,
    Quit(i32, bool),
}

impl Run {
    fn emit(&mut self, data: &[u8], newline: bool) {
        if self.out_missing_nl {
            self.out.push(self.delim);
            self.out_missing_nl = false;
        }
        self.out.extend_from_slice(data);
        if newline {
            self.out.push(self.delim);
        } else {
            self.out_missing_nl = true;
        }
        if self.out.len() > 32 * 1024 {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if !self.out.is_empty() && !self.capture {
            io::out(&self.out);
            self.out.clear();
        }
    }

    fn print_ps(&mut self) {
        let ps = core::mem::take(&mut self.ps);
        let nl = !self.no_newline;
        self.emit(&ps, nl);
        self.ps = ps;
    }

    fn write_file(&mut self, idx: usize, data: &[u8]) {
        let fd = self.script.files[idx].fd;
        if fd == 1 {
            self.emit(data, true);
            return;
        }
        let mut v = data.to_vec();
        v.push(self.delim);
        let _ = io::write_all(fd, &v);
    }

    fn regex(&mut self, r: &Option<Rc<Regex>>) -> Option<Rc<Regex>> {
        match r {
            Some(r) => {
                self.last_re = Some(r.clone());
                Some(r.clone())
            }
            None => {
                if self.last_re.is_none() {
                    error("no previous regular expression");
                    slate_rt::process::exit(4);
                }
                self.last_re.clone()
            }
        }
    }

    fn addr_matches(&mut self, a: &Addr, input: &mut Input) -> bool {
        match a {
            Addr::Line(n) => input.line == *n,
            Addr::Last => input.is_last() && (input.separate || input.next_file >= input.files.len()),
            Addr::Re(r) => {
                let re = self.regex(r);
                re.is_some_and(|re| re.is_match(&self.ps))
            }
            Addr::Step(first, step) => {
                if *step == 0 {
                    input.line == *first
                } else {
                    input.line >= *first && (input.line - first) % step == 0
                }
            }
            Addr::Zero => false,
        }
    }

    fn selected(&mut self, i: usize, input: &mut Input) -> bool {
        let (a1, a2) = {
            let c = &self.script.cmds[i];
            (c.a1.clone(), c.a2.clone())
        };
        let hit = match (&a1, &a2) {
            (None, _) => true,
            (Some(a), None) => self.addr_matches(a, input),
            (Some(a), Some(b)) => {
                let line = input.line;
                if self.script.cmds[i].active {
                    let ends = match b {
                        Addr2::Addr(Addr::Line(n)) => line >= *n,
                        Addr2::Plus(_) => line >= self.script.cmds[i].end,
                        Addr2::Multiple(m) => *m == 0 || line % m == 0,
                        Addr2::Addr(x) => self.addr_matches(x, input),
                    };
                    if ends {
                        self.script.cmds[i].active = false;
                    }
                    // A number already passed ends the range before this line.
                    if let Addr2::Addr(Addr::Line(n)) = b
                        && line > *n
                    {
                        return self.script.cmds[i].negate;
                    }
                    true
                } else {
                    let starts = match a {
                        Addr::Zero => line == 1,
                        _ => self.addr_matches(a, input),
                    };
                    if starts {
                        let mut active = true;
                        match b {
                            Addr2::Addr(Addr::Line(n)) => active = *n > line,
                            Addr2::Plus(n) => {
                                self.script.cmds[i].end = line + n;
                                active = *n > 0;
                            }
                            Addr2::Multiple(m) => active = *m != 0 && line % m != 0,
                            Addr2::Addr(Addr::Re(_)) if matches!(a, Addr::Zero) => {
                                // 0,/re/: the regex may end the range on line 1.
                                active = !self.addr_matches(&b.as_addr(), input);
                            }
                            Addr2::Addr(Addr::Last) => active = !self.addr_matches(&Addr::Last, input),
                            Addr2::Addr(_) => {}
                        }
                        self.script.cmds[i].active = active;
                    }
                    starts
                }
            }
        };
        hit != self.script.cmds[i].negate
    }

    fn substitute(&mut self, i: usize) -> bool {
        let Kind::Subst(s) = &self.script.cmds[i].kind else { return false };
        let (re, global, nth, print, write, exec) = (s.re.clone(), s.global, s.nth, s.print, s.write, s.exec);
        let Some(re) = self.regex(&re) else { return false };
        // Most lines don't match: they cost one pass of the DFA, nothing more.
        if !re.is_match(&self.ps) {
            return false;
        }
        let repl = match &self.script.cmds[i].kind {
            Kind::Subst(s) => s.repl.clone(),
            _ => return false,
        };
        let text = core::mem::take(&mut self.ps);
        let mut out = Vec::with_capacity(text.len());
        let mut pos = 0;
        let mut copied = 0;
        let mut count = 0;
        let mut done = false;
        let mut last_end: Option<usize> = None;
        while pos <= text.len() {
            let Some(c) = re.find_at(&text, pos) else { break };
            let (a, b) = c[0].unwrap_or((pos, pos));
            if a == b && last_end == Some(a) {
                // No empty match right after the previous match.
                if a >= text.len() {
                    break;
                }
                pos = a + 1;
                continue;
            }
            count += 1;
            if count >= nth {
                out.extend_from_slice(&text[copied..a]);
                expand(&repl, &text, &c, &mut out);
                copied = b;
                done = true;
                if !global {
                    break;
                }
            }
            last_end = Some(b);
            pos = if b > a { b } else { b + 1 };
        }
        if !done {
            self.ps = text;
            return false;
        }
        out.extend_from_slice(&text[copied.min(text.len())..]);
        self.ps = out;
        if exec {
            self.flush();
            let mut o = shell_output(&self.ps);
            if o.last() == Some(&b'\n') {
                o.pop();
            }
            self.ps = o;
        }
        if print {
            self.print_ps();
        }
        if let Some(w) = write {
            let ps = self.ps.clone();
            self.write_file(w, &ps);
        }
        true
    }

    /// `l`: the pattern space unambiguously, wrapped.
    fn list(&mut self, width: usize) {
        let mut line = Vec::new();
        let mut col = 0;
        let mut out = Vec::new();
        for &c in &self.ps {
            let piece: Vec<u8> = match c {
                b'\\' => b"\\\\".to_vec(),
                7 => b"\\a".to_vec(),
                8 => b"\\b".to_vec(),
                12 => b"\\f".to_vec(),
                b'\n' => b"\\n".to_vec(),
                b'\r' => b"\\r".to_vec(),
                b'\t' => b"\\t".to_vec(),
                11 => b"\\v".to_vec(),
                c if !(32..127).contains(&c) => alloc::format!("\\{c:03o}").into_bytes(),
                c => alloc::vec![c],
            };
            if width > 1 && col + piece.len() > width - 1 {
                line.extend_from_slice(b"\\");
                out.push(core::mem::take(&mut line));
                col = 0;
            }
            col += piece.len();
            line.extend_from_slice(&piece);
        }
        line.push(b'$');
        out.push(line);
        for l in out {
            self.emit(&l, true);
        }
    }

    fn flush_append(&mut self) {
        for a in core::mem::take(&mut self.append) {
            self.emit(&a, true);
        }
    }

    /// Run the script on the pattern space.
    fn cycle(&mut self, input: &mut Input) -> End {
        let mut pc = 0;
        while pc < self.script.cmds.len() {
            if !self.selected(pc, input) {
                pc = match self.script.cmds[pc].kind {
                    Kind::Block(after) => after,
                    _ => pc + 1,
                };
                continue;
            }
            let mut next = pc + 1;
            match &self.script.cmds[pc].kind {
                Kind::Block(_) | Kind::EndBlock | Kind::Label => {}
                Kind::LineNumber => {
                    let l = alloc::format!("{}", input.line);
                    self.emit(l.as_bytes(), true);
                }
                Kind::Append(t) => self.append.push(t.clone()),
                Kind::Insert(t) => {
                    let t = t.clone();
                    self.emit(&t, true);
                }
                Kind::Change(t) => {
                    let t = t.clone();
                    let c = &self.script.cmds[pc];
                    // In a range, the text replaces the whole range.
                    if c.a2.is_none() || !c.active || c.negate {
                        self.emit(&t, true);
                    }
                    return End::Delete;
                }
                Kind::Branch(t) => next = t.unwrap_or(usize::MAX),
                Kind::BranchIf(t) => {
                    if self.tflag {
                        self.tflag = false;
                        next = t.unwrap_or(usize::MAX);
                    }
                }
                Kind::BranchUnless(t) => {
                    if !self.tflag {
                        next = t.unwrap_or(usize::MAX);
                    } else {
                        self.tflag = false;
                    }
                }
                Kind::Delete => return End::Delete,
                Kind::DeleteFirst => match self.ps.iter().position(|&c| c == b'\n') {
                    Some(n) => {
                        self.ps.drain(..=n);
                        return End::Restart;
                    }
                    None => return End::Delete,
                },
                Kind::Get => self.ps = self.hs.clone(),
                Kind::GetAppend => {
                    self.ps.push(b'\n');
                    let h = self.hs.clone();
                    self.ps.extend_from_slice(&h);
                }
                Kind::Hold => self.hs = self.ps.clone(),
                Kind::HoldAppend => {
                    self.hs.push(b'\n');
                    let p = self.ps.clone();
                    self.hs.extend_from_slice(&p);
                }
                Kind::List(w) => {
                    let w = w.unwrap_or(self.wrap);
                    self.list(w);
                }
                Kind::Next => {
                    if input.is_last() && (input.separate || input.next_file >= input.files.len()) {
                        // GNU: without a next line, quit (autoprinting).
                        return End::Quit(0, true);
                    }
                    if !self.quiet {
                        self.print_ps();
                    }
                    self.flush_append();
                    match input.next() {
                        Some((l, nl)) => {
                            self.ps = l;
                            self.no_newline = !nl;
                        }
                        None => return End::Quit(0, false),
                    }
                }
                Kind::NextAppend => {
                    if input.is_last() && (input.separate || input.next_file >= input.files.len()) {
                        return End::Quit(0, true);
                    }
                    self.flush_append();
                    if let Some((l, nl)) = input.next() {
                        self.ps.push(b'\n');
                        self.ps.extend_from_slice(&l);
                        self.no_newline = !nl;
                    }
                }
                Kind::Print => self.print_ps(),
                Kind::PrintFirst => {
                    let end = self.ps.iter().position(|&c| c == b'\n');
                    let first = self.ps[..end.unwrap_or(self.ps.len())].to_vec();
                    self.emit(&first, end.is_some() || !self.no_newline);
                }
                Kind::Quit(code) => return End::Quit(*code, true),
                Kind::QuitSilent(code) => return End::Quit(*code, false),
                Kind::ReadFile(f) => {
                    if let Ok(d) = fs::read_file(f) {
                        let d = d.strip_suffix(b"\n").unwrap_or(&d).to_vec();
                        self.append.push(d);
                    }
                }
                Kind::ReadLine(idx) => {
                    let idx = *idx;
                    if let Some(r) = self.script.readers[idx].1.as_mut()
                        && let Ok(Some(mut l)) = r.line()
                    {
                        if l.last() == Some(&b'\n') {
                            l.pop();
                        }
                        self.append.push(l);
                    }
                }
                Kind::Subst(_) => {
                    if self.substitute(pc) {
                        self.tflag = true;
                    }
                }
                Kind::Write(idx) => {
                    let (idx, ps) = (*idx, self.ps.clone());
                    self.write_file(idx, &ps);
                }
                Kind::WriteFirst(idx) => {
                    let idx = *idx;
                    let end = self.ps.iter().position(|&c| c == b'\n').unwrap_or(self.ps.len());
                    let first = self.ps[..end].to_vec();
                    self.write_file(idx, &first);
                }
                Kind::Exchange => core::mem::swap(&mut self.ps, &mut self.hs),
                Kind::Translate(map) => {
                    for c in self.ps.iter_mut() {
                        *c = map[*c as usize];
                    }
                }
                Kind::Zap => self.ps.clear(),
                Kind::FileName => {
                    let n = input.current.clone();
                    self.emit(&n, true);
                }
                Kind::Exec(cmd) => {
                    let cmd = cmd.clone();
                    self.flush();
                    match cmd {
                        // The command's output goes out first.
                        Some(c) => {
                            let o = shell_output(&c);
                            self.out.extend_from_slice(&o);
                        }
                        None => {
                            let mut o = shell_output(&self.ps);
                            if o.last() == Some(&b'\n') {
                                o.pop();
                            }
                            self.ps = o;
                        }
                    }
                }
            }
            pc = next;
        }
        End::Cycle
    }
}

impl Addr2 {
    fn as_addr(&self) -> Addr {
        match self {
            Addr2::Addr(a) => a.clone(),
            _ => Addr::Zero,
        }
    }
}

/// Expand a replacement for one match.
fn expand(repl: &[Repl], text: &[u8], caps: &slate_regex::Captures, out: &mut Vec<u8>) {
    let mut mode: Option<CaseOp> = None;
    let mut one: Option<CaseOp> = None;
    let put = |out: &mut Vec<u8>, bytes: &[u8], mode: Option<CaseOp>, one: &mut Option<CaseOp>| {
        for &b in bytes {
            let mut c = match mode {
                Some(CaseOp::Lower) => b.to_ascii_lowercase(),
                Some(CaseOp::Upper) => b.to_ascii_uppercase(),
                _ => b,
            };
            match one.take() {
                Some(CaseOp::LowerOne) => c = c.to_ascii_lowercase(),
                Some(CaseOp::UpperOne) => c = c.to_ascii_uppercase(),
                _ => {}
            }
            out.push(c);
        }
    };
    for r in repl {
        match r {
            Repl::Lit(l) => put(out, l, mode, &mut one),
            Repl::Group(g) => {
                if let Some(Some((a, b))) = caps.get(*g) {
                    put(out, &text[*a..*b], mode, &mut one);
                }
            }
            Repl::Case(CaseOp::End) => {
                mode = None;
                one = None;
            }
            Repl::Case(op @ (CaseOp::Lower | CaseOp::Upper)) => mode = Some(*op),
            Repl::Case(op) => one = Some(*op),
        }
    }
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut quiet = false;
    let mut scripts: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut syntax = Syntax::Basic;
    let mut in_place: Option<Vec<u8>> = None;
    let mut separate = false;
    let mut delim = b'\n';
    let mut wrap = 70;
    let mut operands = Vec::new();
    let mut p = Parser::new(args, b"efl");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'n') => quiet = true,
            Opt::Short(b'e') => match p.value() {
                Some(v) => scripts.push((v, false)),
                None => return crate::util::missing_value('e'),
            },
            Opt::Short(b'f') => match p.value() {
                Some(f) => match crate::util::read_input(&f) {
                    Ok(mut d) => {
                        if d.last() == Some(&b'\n') {
                            d.pop();
                        }
                        scripts.push((d, true));
                    }
                    Err(e) => {
                        error(alloc::format!("couldn't open file {}: {e}", lossy(&f)));
                        return 1;
                    }
                },
                None => return crate::util::missing_value('f'),
            },
            Opt::Short(b'E' | b'r') => syntax = Syntax::Extended,
            Opt::Short(b'i') => in_place = Some(p.inline_bundle()),
            Opt::Short(b's') => separate = true,
            Opt::Short(b'z') => delim = 0,
            Opt::Short(b'u') => {}
            Opt::Short(b'l') => wrap = p.value().and_then(|v| crate::util::parse_num(&v)).unwrap_or(70),
            Opt::Long(l) => match l.as_str() {
                "quiet" | "silent" => quiet = true,
                "regexp-extended" => syntax = Syntax::Extended,
                "in-place" => in_place = Some(p.inline_value().unwrap_or_default()),
                "separate" => separate = true,
                "null-data" => delim = 0,
                "expression" => match p.value() {
                    Some(v) => scripts.push((v, false)),
                    None => return crate::util::missing_value("expression"),
                },
                "posix" | "unbuffered" | "follow-symlinks" | "sandbox" | "debug" => {}
                "line-length" => wrap = p.value().and_then(|v| crate::util::parse_num(&v)).unwrap_or(70),
                _ => return crate::util::bad_option(&Opt::Long(l)),
            },
            Opt::Operand(v) => operands.push(v),
            o => return crate::util::bad_option(&o),
        }
    }
    if scripts.is_empty() {
        if operands.is_empty() {
            error("usage: sed [OPTION]... {script} [input-file]...");
            return 1;
        }
        scripts.push((operands.remove(0), false));
    }
    let mut script = Script {
        cmds: Vec::new(),
        labels: Vec::new(),
        pending: Vec::new(),
        files: Vec::new(),
        readers: Vec::new(),
        syntax,
        quiet_marker: false,
    };
    // -e pieces join with newlines into one script (GNU numbers them).
    for (n, (s, from_file)) in scripts.iter().enumerate() {
        if let Err(ParseErr(m, pos)) = script.parse(s) {
            if *from_file {
                error(alloc::format!("file: {m}"));
            } else {
                error(alloc::format!("-e expression #{}, char {pos}: {m}", n + 1));
            }
            return 1;
        }
    }
    if let Err(m) = script.resolve() {
        error(m);
        return 4;
    }
    let quiet = quiet || script.quiet_marker;
    if operands.is_empty() {
        operands.push(b"-".to_vec());
    }
    let mut run = Run {
        script,
        quiet,
        ps: Vec::new(),
        hs: Vec::new(),
        no_newline: false,
        append: Vec::new(),
        tflag: false,
        last_re: None,
        wrap,
        out: Vec::new(),
        out_missing_nl: false,
        delim,
        capture: false,
    };
    match in_place {
        None => {
            let mut input = Input {
                files: operands,
                next_file: 0,
                reader: None,
                fd: -1,
                name: Rc::from(&b""[..]),
                current: Rc::from(&b""[..]),
                ahead: None,
                delim,
                separate,
                status: 0,
                line: 0,
            };
            input.open_next();
            let code = process(&mut run, &mut input);
            run.flush();
            if code != 0 { code } else { input.status }
        }
        Some(suffix) => {
            let mut status = 0;
            for f in operands {
                let mut input = Input {
                    files: alloc::vec![f.clone()],
                    next_file: 0,
                    reader: None,
                    fd: -1,
                    name: Rc::from(&b""[..]),
                    current: Rc::from(&b""[..]),
                    ahead: None,
                    delim,
                    separate: true,
                    status: 0,
                    line: 0,
                };
                if !input.open_next() {
                    status = 4;
                    continue;
                }
                run.flush();
                run.capture = true;
                run.out_missing_nl = false;
                let code = process(&mut run, &mut input);
                run.capture = false;
                let data = core::mem::take(&mut run.out);
                let mut data = data;
                if run.out_missing_nl {
                    run.out_missing_nl = false;
                }
                let mode = fs::stat(&f).map_or(0o644, |s| s.mode & 0o7777);
                if !suffix.is_empty() {
                    let backup = if suffix.contains(&b'*') {
                        let base = fs::basename(&f);
                        let mut b = Vec::new();
                        for &c in &suffix {
                            if c == b'*' {
                                b.extend_from_slice(base);
                            } else {
                                b.push(c);
                            }
                        }
                        fs::join(fs::dirname(&f), &b)
                    } else {
                        [f.as_slice(), &suffix].concat()
                    };
                    let _ = fs::rename(&f, &backup);
                }
                // A new file renamed over the old one, like GNU (so read-only
                // files can be edited in a writable directory).
                let mut tmp = fs::dirname(&f).to_vec();
                tmp.extend_from_slice(alloc::format!("/.sed{}", slate_rt::process::getpid()).as_bytes());
                let r = fs::write_file(&tmp, &data, mode)
                    .and_then(|()| fs::chmod(&tmp, mode))
                    .and_then(|()| fs::rename(&tmp, &f));
                if let Err(e) = r {
                    let _ = fs::unlink(&tmp);
                    error(alloc::format!("couldn't edit {}: {e}", lossy(&f)));
                    status = 4;
                }
                data.clear();
                if code != 0 {
                    return code;
                }
            }
            status
        }
    }
}

fn process(run: &mut Run, input: &mut Input) -> i32 {
    let mut restart = false;
    loop {
        if !restart {
            match input.next() {
                Some((l, nl)) => {
                    run.ps = l;
                    run.no_newline = !nl;
                }
                None => {
                    if !input.separate || !input.open_next() {
                        return 0;
                    }
                    // -s: line numbers count from each file's start.
                    input.line = 0;
                    continue;
                }
            }
            run.tflag = false;
        }
        restart = false;
        match run.cycle(input) {
            End::Cycle => {
                if !run.quiet {
                    run.print_ps();
                }
            }
            End::Delete => {}
            // D: no autoprint; the next cycle starts on what is left.
            End::Restart => restart = true,
            End::Quit(code, print) => {
                if print && !run.quiet {
                    run.print_ps();
                }
                run.flush_append();
                return code;
            }
        }
        run.flush_append();
    }
}
