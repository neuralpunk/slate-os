// SPDX-License-Identifier: MIT OR Apache-2.0

//! grep (POSIX.1-2017 XCU grep, plus the GNU options people use: -o, -w,
//! -r, -A/-B/-C, -m, -H/-h, -Z, -z, --include/--exclude/--exclude-from,
//! --color with GREP_COLORS, -P for Perl's patterns), on slate-regex. Like GNU grep, it warns of a
//! stray backslash and of an ERE operator with nothing before it.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use slate_regex::{Options, Regex, Syntax, Whole};
use slate_rt::{fs, io, lossy};

use crate::util::{Opt, Parser, error, parse_num};

/// GREP_COLORS (the GNU grep manual): the SGR parameters of each part of
/// the output (`None`: not coloured), `rv` and `ne`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Colors {
    pub ms: Option<Vec<u8>>,
    pub mc: Option<Vec<u8>>,
    pub sl: Option<Vec<u8>>,
    pub cx: Option<Vec<u8>>,
    pub fname: Option<Vec<u8>>,
    pub ln: Option<Vec<u8>>,
    pub bn: Option<Vec<u8>>,
    pub se: Option<Vec<u8>>,
    pub rv: bool,
    pub ne: bool,
}

impl Default for Colors {
    fn default() -> Colors {
        let c = |v: &[u8]| Some(v.to_vec());
        Colors {
            ms: c(b"01;31"),
            mc: c(b"01;31"),
            sl: None,
            cx: None,
            fname: c(b"35"),
            ln: c(b"32"),
            bn: c(b"32"),
            se: c(b"36"),
            rv: false,
            ne: false,
        }
    }
}

impl Colors {
    /// GREP_COLORS' `name=value:...` over these colours. A value that
    /// isn't digits and `;` ends the reading (what came before stays);
    /// names it doesn't know are skipped.
    pub fn apply(&mut self, spec: &[u8]) {
        for item in spec.split(|&c| c == b':') {
            let (name, value) = match item.iter().position(|&c| c == b'=') {
                Some(i) => (&item[..i], Some(&item[i + 1..])),
                None => (item, None),
            };
            match (name, value) {
                (b"", None) => continue,
                (b"rv", _) => self.rv = true,
                (b"ne", _) => self.ne = true,
                (_, None) => return,
                (_, Some(v)) if !v.iter().all(|c| c.is_ascii_digit() || *c == b';') => return,
                (_, Some(v)) => {
                    let v = (!v.is_empty()).then(|| v.to_vec());
                    match name {
                        b"mt" => {
                            self.ms = v.clone();
                            self.mc = v;
                        }
                        b"ms" => self.ms = v,
                        b"mc" => self.mc = v,
                        b"sl" => self.sl = v,
                        b"cx" => self.cx = v,
                        b"fn" => self.fname = v,
                        b"ln" => self.ln = v,
                        b"bn" => self.bn = v,
                        b"se" => self.se = v,
                        _ => {}
                    }
                }
            }
        }
    }

    fn start(&self, sgr: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(b"\x1b[");
        out.extend_from_slice(sgr);
        out.push(b'm');
        if !self.ne {
            out.extend_from_slice(b"\x1b[K");
        }
    }

    fn end(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(if self.ne { b"\x1b[m".as_slice() } else { b"\x1b[m\x1b[K" });
    }

    /// `text` in colour `sgr` (as it is without one).
    fn paint(&self, sgr: &Option<Vec<u8>>, text: &[u8], out: &mut Vec<u8>) {
        match sgr {
            Some(c) => {
                self.start(c, out);
                out.extend_from_slice(text);
                self.end(out);
            }
            None => out.extend_from_slice(text),
        }
    }
}

/// What a printed line is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Text {
    Selected,
    Context,
    /// A match on its own (-o).
    Match,
}

/// A warning GNU grep gives for `pat`, or an error for a bracket
/// expression written as a class (`[:space:]`). Stray backslashes are
/// told of only when there is one pattern, as GNU does; an ERE operator
/// at the start of an expression, after `(` or `|`, always.
pub fn check_syntax(pat: &[u8], syntax: Syntax, single: bool) -> Result<Option<Vec<u8>>, &'static str> {
    let ere = syntax == Syntax::Extended;
    let mut warning: Option<Vec<u8>> = None;
    let mut i = 0;
    let mut at_start = true;
    while i < pat.len() {
        let c = pat[i];
        if ere && at_start && warning.is_none() {
            match c {
                b'*' | b'+' | b'?' => {
                    warning = Some(alloc::format!("{} at start of expression", c as char).into_bytes())
                }
                b'{' if interval_at(&pat[i + 1..]) => warning = Some(b"{...} at start of expression".to_vec()),
                _ => {}
            }
        }
        // An expression starts after `(` and `|`, and still after `^`.
        at_start = ere && (matches!(c, b'(' | b'|') || (at_start && c == b'^'));
        match c {
            b'[' => {
                // A bracket expression: its backslashes are its own.
                let mut j = i + 1;
                if pat.get(j) == Some(&b'^') {
                    j += 1;
                }
                let body = j;
                if pat.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < pat.len() && pat[j] != b']' {
                    if pat[j] == b'[' && matches!(pat.get(j + 1), Some(b':' | b'=' | b'.')) {
                        let delim = pat[j + 1];
                        j += 2;
                        while j + 1 < pat.len() && !(pat[j] == delim && pat[j + 1] == b']') {
                            j += 1;
                        }
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                let inner = &pat[body.min(pat.len())..j.min(pat.len())];
                if inner.len() >= 2 && inner.starts_with(b":") && inner.ends_with(b":") {
                    return Err("character class syntax is [[:space:]], not [:space:]");
                }
                i = j + 1;
            }
            b'\\' => {
                let Some(&n) = pat.get(i + 1) else { break };
                let ok = b"\\.[]^$*(){}|+?123456789wWsSbB<>`'".contains(&n);
                if !ok && single && warning.is_none() {
                    let what = if !(0x20..0x7f).contains(&n) {
                        alloc::string::String::from("unprintable character")
                    } else if n == b' ' {
                        alloc::string::String::from("white space")
                    } else {
                        alloc::string::String::from(n as char)
                    };
                    warning = Some(alloc::format!("stray \\ before {what}").into_bytes());
                }
                at_start = !ere && n == b'(';
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(warning)
}

/// Whether `p` (after a `{`) is an interval: `m}`, `m,}`, `m,n}` or `,n}`.
fn interval_at(p: &[u8]) -> bool {
    let digits = |p: &[u8]| p.iter().take_while(|c| c.is_ascii_digit()).count();
    let m = digits(p);
    let rest = &p[m..];
    match rest.first() {
        Some(b'}') => m > 0,
        Some(b',') => rest[1 + digits(&rest[1..])..].first() == Some(&b'}'),
        _ => false,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BinaryFiles {
    /// Report "binary file matches" (the default).
    Report,
    /// -a: treat as text.
    Text,
    /// -I: binary files never match.
    NoMatch,
}

struct Grep {
    pats: Vec<Regex>,
    invert: bool,
    count: bool,
    files_with: bool,
    files_without: bool,
    max: Option<u64>,
    only: bool,
    quiet: bool,
    silent: bool,
    byte_offset: bool,
    names: bool,
    line_numbers: bool,
    after: usize,
    before: usize,
    null_name: bool,
    delim: u8,
    binary: BinaryFiles,
    label: Vec<u8>,
    recursive: bool,
    deref: bool,
    include: Vec<Vec<u8>>,
    exclude: Vec<Vec<u8>>,
    exclude_dir: Vec<Vec<u8>>,
    matched: bool,
    errors: bool,
    out: Vec<u8>,
    /// --color: what to colour, and how.
    colors: Option<Colors>,
}

/// The selection status of a line and where the matches are.
impl Grep {
    fn line_matches(&self, line: &[u8]) -> bool {
        self.pats.iter().any(|r| r.is_match(line))
    }

    /// The leftmost-longest match among all patterns at or after `pos`.
    fn next_match(&self, line: &[u8], pos: usize) -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None;
        for r in &self.pats {
            if let Some(c) = r.find_at(line, pos)
                && let Some((a, b)) = c[0]
                && best.is_none_or(|(ba, bb)| a < ba || a == ba && b > bb)
            {
                best = Some((a, b));
            }
        }
        best
    }

    fn flush(&mut self) {
        if !self.out.is_empty() {
            io::out(&self.out);
            self.out.clear();
        }
    }

    /// `text` in colour `pick` chooses, if colouring.
    fn paint(&mut self, pick: fn(&Colors) -> &Option<Vec<u8>>, text: &[u8]) {
        match &self.colors {
            Some(c) => c.paint(pick(c), text, &mut self.out),
            None => self.out.extend_from_slice(text),
        }
    }

    fn prefix(&mut self, name: &[u8], lineno: u64, offset: u64, sep: u8) {
        if self.names {
            self.paint(|c| &c.fname, name);
            if self.null_name {
                self.out.push(0);
            } else {
                self.paint(|c| &c.se, &[sep]);
            }
        }
        if self.line_numbers {
            self.paint(|c| &c.ln, alloc::format!("{lineno}").as_bytes());
            self.paint(|c| &c.se, &[sep]);
        }
        if self.byte_offset {
            self.paint(|c| &c.bn, alloc::format!("{offset}").as_bytes());
            self.paint(|c| &c.se, &[sep]);
        }
    }

    /// The line's text, coloured as GNU grep does: the whole line in `sl`
    /// (selected) or `cx` (context), swapped by `rv` with -v; each match
    /// in a matching line in `ms` (selected) or `mc` (context).
    fn body(&mut self, line: &[u8], kind: Text) {
        let Some(c) = self.colors.clone() else {
            self.out.extend_from_slice(line);
            return;
        };
        if kind == Text::Match {
            c.paint(&c.ms, line, &mut self.out);
            return;
        }
        let selected = kind == Text::Selected;
        let (sl, cx) = if c.rv && self.invert { (&c.cx, &c.sl) } else { (&c.sl, &c.cx) };
        let lc = if selected { sl } else { cx };
        let mc = if selected { &c.ms } else { &c.mc };
        let mut spans = Vec::new();
        if selected != self.invert && mc.is_some() {
            let mut pos = 0;
            while pos <= line.len() {
                let Some((a, b)) = self.next_match(line, pos) else { break };
                if b > a {
                    spans.push((a, b));
                    pos = b;
                } else {
                    pos = a + 1;
                }
            }
        }
        if let Some(l) = lc {
            c.start(l, &mut self.out);
        }
        let mut pos = 0;
        for &(a, b) in &spans {
            self.out.extend_from_slice(&line[pos..a]);
            c.paint(mc, &line[a..b], &mut self.out);
            pos = b;
            if pos < line.len()
                && let Some(l) = lc
            {
                c.start(l, &mut self.out);
            }
        }
        self.out.extend_from_slice(&line[pos..]);
        if lc.is_some() && (spans.is_empty() || pos < line.len()) {
            c.end(&mut self.out);
        }
    }

    fn emit_line(&mut self, name: &[u8], lineno: u64, offset: u64, line: &[u8], kind: Text) {
        let sep = if kind == Text::Context { b'-' } else { b':' };
        self.prefix(name, lineno, offset, sep);
        self.body(line, kind);
        self.out.push(self.delim);
        if self.out.len() > 32 * 1024 {
            self.flush();
        }
    }

    /// Search one open input; returns the number of selected lines.
    fn search(&mut self, fd: i32, name: &[u8]) -> u64 {
        let mut reader = io::Reader::new(fd);
        let mut lineno = 0u64;
        let mut offset = 0u64;
        let mut selected = 0u64;
        let mut before: VecDeque<(u64, u64, Vec<u8>)> = VecDeque::new();
        let mut after_left = 0usize;
        let mut last_out: Option<u64> = None;
        let context = (self.after > 0 || self.before > 0) && !self.only;
        let listing = self.count || self.files_with || self.files_without || self.quiet;
        let mut binary = false;
        loop {
            let line = match reader.split_ref(self.delim) {
                Ok(Some(l)) => l,
                Ok(None) => break,
                Err(e) => {
                    if !self.silent {
                        error(alloc::format!("{}: {e}", lossy(name)));
                    }
                    self.errors = true;
                    break;
                }
            };
            lineno += 1;
            let start = offset;
            offset += line.len() as u64;
            let mut body = line;
            if body.last() == Some(&self.delim) {
                body = &body[..body.len() - 1];
            }
            if self.binary != BinaryFiles::Text && !binary && slate_regex::memchr(0, body).is_some() {
                binary = true;
                if self.binary == BinaryFiles::NoMatch {
                    return 0;
                }
            }
            let done = self.max.is_some_and(|m| selected >= m);
            if done {
                // After -m's last match only trailing context remains.
                if after_left > 0 && !self.invert_matches(body) && !listing {
                    self.emit_line(name, lineno, start, body, Text::Context);
                    after_left -= 1;
                    continue;
                }
                break;
            }
            let hit = self.invert_matches(body);
            if !hit {
                if listing {
                    continue;
                }
                if after_left > 0 {
                    self.emit_line(name, lineno, start, body, Text::Context);
                    last_out = Some(lineno);
                    after_left -= 1;
                } else if self.before > 0 {
                    before.push_back((lineno, start, body.to_vec()));
                    if before.len() > self.before {
                        before.pop_front();
                    }
                }
                continue;
            }
            selected += 1;
            self.matched = true;
            if self.quiet || self.files_with {
                break;
            }
            if listing {
                continue;
            }
            if binary {
                self.flush();
                io::flush_stdout();
                io::err(alloc::format!("grep: {}: binary file matches\n", lossy(name)).as_bytes());
                return selected;
            }
            if context {
                let first = before.front().map_or(lineno, |b| b.0);
                if last_out.is_some_and(|l| first > l + 1) {
                    self.paint(|c| &c.se, b"--");
                    self.out.push(b'\n');
                }
                while let Some((n, o, l)) = before.pop_front() {
                    self.emit_line(name, n, o, &l, Text::Context);
                }
                after_left = self.after;
            }
            if self.only {
                if !self.invert {
                    let mut pos = 0;
                    while pos <= body.len() {
                        let Some((a, b)) = self.next_match(body, pos) else { break };
                        if b > a {
                            let m = body[a..b].to_vec();
                            self.emit_line(name, lineno, start + a as u64, &m, Text::Match);
                            pos = b;
                        } else {
                            pos = a + 1;
                        }
                    }
                }
            } else {
                self.emit_line(name, lineno, start, body, Text::Selected);
            }
            last_out = Some(lineno);
        }
        selected
    }

    fn invert_matches(&self, body: &[u8]) -> bool {
        self.line_matches(body) != self.invert
    }

    fn report(&mut self, name: &[u8], selected: u64) {
        if self.count {
            if self.names {
                self.paint(|c| &c.fname, name);
                if self.null_name {
                    self.out.push(0);
                } else {
                    self.paint(|c| &c.se, b":");
                }
            }
            self.out.extend_from_slice(alloc::format!("{selected}\n").as_bytes());
        }
        if (self.files_with && selected > 0) || (self.files_without && selected == 0) {
            self.paint(|c| &c.fname, name);
            self.out.push(if self.null_name { 0 } else { b'\n' });
        }
        self.flush();
    }

    fn file(&mut self, path: &[u8], top: bool) {
        if path == b"-" {
            let label = self.label.clone();
            let n = self.search(0, &label);
            self.report(&label, n);
            return;
        }
        let st = if self.deref || top { fs::stat(path) } else { fs::lstat(path) };
        match st {
            Ok(s) if s.is_dir() => {
                if !self.recursive {
                    if !self.silent {
                        error(alloc::format!("{}: Is a directory", lossy(path)));
                    }
                    self.errors = true;
                    return;
                }
                let base = fs::basename(path);
                if !top && self.exclude_dir.iter().any(|g| slate_regex::fnmatch(g, base)) {
                    return;
                }
                let entries = match fs::read_dir(path) {
                    Ok(e) => e,
                    Err(e) => {
                        if !self.silent {
                            error(alloc::format!("{}: {e}", lossy(path)));
                        }
                        self.errors = true;
                        return;
                    }
                };
                for e in entries {
                    if e.name == b"." || e.name == b".." {
                        continue;
                    }
                    let child = if path == b"." && !top { e.name.clone() } else { fs::join(path, &e.name) };
                    self.file(&child, false);
                }
                return;
            }
            Ok(s) if !top && s.is_symlink() => return,
            Ok(s) if !top && !s.is_file() => return,
            Ok(_) => {}
            Err(e) => {
                if !self.silent {
                    error(alloc::format!("{}: {e}", lossy(path)));
                }
                self.errors = true;
                return;
            }
        }
        let base = fs::basename(path);
        if (!self.include.is_empty() && !self.include.iter().any(|g| slate_regex::fnmatch(g, base)))
            || self.exclude.iter().any(|g| slate_regex::fnmatch(g, base))
        {
            return;
        }
        let fd = match fs::open(path, fs::O_RDONLY | fs::O_CLOEXEC, 0) {
            Ok(fd) => fd,
            Err(e) => {
                if !self.silent {
                    error(alloc::format!("{}: {e}", lossy(path)));
                }
                self.errors = true;
                return;
            }
        };
        let n = self.search(fd, path);
        let _ = io::close(fd);
        self.report(path, n);
    }
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut syntax = Syntax::Basic;
    let mut fixed = false;
    let mut perl = false;
    // -E, -F, -G and -P: one of them (GNU refuses two different ones).
    let mut matcher: Option<u8> = None;
    let mut choose = |m: u8| -> bool {
        if matcher.is_some_and(|x| x != m) {
            error("conflicting matchers specified");
            return false;
        }
        matcher = Some(m);
        true
    };
    let mut icase = false;
    let mut whole = Whole::Any;
    let mut patterns: Vec<Vec<u8>> = Vec::new();
    let mut have_patterns = false;
    let mut operands = Vec::new();
    let mut names: Option<bool> = None;
    let mut g = Grep {
        pats: Vec::new(),
        invert: false,
        count: false,
        files_with: false,
        files_without: false,
        max: None,
        only: false,
        quiet: false,
        silent: false,
        byte_offset: false,
        names: false,
        line_numbers: false,
        after: 0,
        before: 0,
        null_name: false,
        delim: b'\n',
        binary: BinaryFiles::Report,
        label: b"(standard input)".to_vec(),
        recursive: false,
        deref: false,
        include: Vec::new(),
        exclude: Vec::new(),
        exclude_dir: Vec::new(),
        matched: false,
        errors: false,
        out: Vec::new(),
        colors: None,
    };
    let mut color: &[u8] = b"never";
    let mut p = Parser::new(args, b"efmABCd");
    p.numeric = true;
    let add_patterns = |patterns: &mut Vec<Vec<u8>>, v: &[u8]| {
        for l in v.split(|&c| c == b'\n') {
            patterns.push(l.to_vec());
        }
    };
    let num = |v: Option<Vec<u8>>, what: &str| -> Result<usize, i32> {
        match v.as_deref().and_then(parse_num::<usize>) {
            Some(n) => Ok(n),
            None => {
                error(alloc::format!("{}: invalid {what} argument", lossy(&v.unwrap_or_default())));
                Err(2)
            }
        }
    };
    while let Some(o) = p.next() {
        match o {
            Opt::Short(m @ (b'E' | b'G' | b'F' | b'P')) => {
                if !choose(m) {
                    return 2;
                }
                match m {
                    b'E' => syntax = Syntax::Extended,
                    b'G' => syntax = Syntax::Basic,
                    b'F' => fixed = true,
                    _ => perl = true,
                }
            }
            Opt::Short(b'e') => {
                let Some(v) = p.value() else { return crate::util::missing_value('e') };
                add_patterns(&mut patterns, &v);
                have_patterns = true;
            }
            Opt::Short(b'f') => {
                let Some(v) = p.value() else { return crate::util::missing_value('f') };
                match crate::util::read_input(&v) {
                    Ok(d) => {
                        let d = d.strip_suffix(b"\n").unwrap_or(&d);
                        if !d.is_empty() {
                            add_patterns(&mut patterns, d);
                        }
                        have_patterns = true;
                    }
                    Err(e) => {
                        error(alloc::format!("{}: {e}", lossy(&v)));
                        return 2;
                    }
                }
            }
            Opt::Short(b'i' | b'y') => icase = true,
            Opt::Short(b'v') => g.invert = true,
            Opt::Short(b'w') => whole = Whole::Word,
            Opt::Short(b'x') => whole = Whole::Line,
            Opt::Short(b'c') => g.count = true,
            Opt::Short(b'l') => g.files_with = true,
            Opt::Short(b'L') => g.files_without = true,
            Opt::Short(b'm') => match num(p.value(), "max count") {
                Ok(n) => g.max = Some(n as u64),
                Err(s) => return s,
            },
            Opt::Short(b'o') => g.only = true,
            Opt::Short(b'q') => g.quiet = true,
            Opt::Short(b's') => g.silent = true,
            Opt::Short(b'b') => g.byte_offset = true,
            Opt::Short(b'H') => names = Some(true),
            Opt::Short(b'h') => names = Some(false),
            Opt::Short(b'n') => g.line_numbers = true,
            Opt::Short(b'Z') => g.null_name = true,
            Opt::Short(b'z') => g.delim = 0,
            Opt::Short(b'a') => g.binary = BinaryFiles::Text,
            Opt::Short(b'I') => g.binary = BinaryFiles::NoMatch,
            Opt::Short(b'r') => g.recursive = true,
            Opt::Short(b'R') => {
                g.recursive = true;
                g.deref = true;
            }
            Opt::Short(b'U') | Opt::Short(b'T') => {}
            Opt::Short(c @ (b'A' | b'B' | b'C')) => match num(p.value(), "context length") {
                Ok(n) => {
                    if c != b'B' {
                        g.after = n;
                    }
                    if c != b'A' {
                        g.before = n;
                    }
                }
                Err(s) => return s,
            },
            Opt::Long(l) if l.bytes().all(|c| c.is_ascii_digit()) => {
                let n = parse_num::<usize>(l.as_bytes()).unwrap_or(0);
                g.after = n;
                g.before = n;
            }
            Opt::Long(l) => match l.as_str() {
                "extended-regexp" | "basic-regexp" | "fixed-strings" | "perl-regexp" => {
                    let m = match l.as_str() {
                        "extended-regexp" => b'E',
                        "basic-regexp" => b'G',
                        "fixed-strings" => b'F',
                        _ => b'P',
                    };
                    if !choose(m) {
                        return 2;
                    }
                    match m {
                        b'E' => syntax = Syntax::Extended,
                        b'G' => syntax = Syntax::Basic,
                        b'F' => fixed = true,
                        _ => perl = true,
                    }
                }
                "ignore-case" => icase = true,
                "no-ignore-case" => icase = false,
                "invert-match" => g.invert = true,
                "word-regexp" => whole = Whole::Word,
                "line-regexp" => whole = Whole::Line,
                "count" => g.count = true,
                "files-with-matches" => g.files_with = true,
                "files-without-match" => g.files_without = true,
                "only-matching" => g.only = true,
                "quiet" | "silent" => g.quiet = true,
                "no-messages" => g.silent = true,
                "byte-offset" => g.byte_offset = true,
                "with-filename" => names = Some(true),
                "no-filename" => names = Some(false),
                "line-number" => g.line_numbers = true,
                "null" => g.null_name = true,
                "null-data" => g.delim = 0,
                "text" => g.binary = BinaryFiles::Text,
                "recursive" => g.recursive = true,
                "dereference-recursive" => {
                    g.recursive = true;
                    g.deref = true;
                }
                "color" | "colour" => {
                    color = match p.inline_value().as_deref() {
                        None | Some(b"auto" | b"tty" | b"if-tty") => b"auto",
                        Some(b"always" | b"yes" | b"force") => b"always",
                        Some(b"never" | b"no" | b"none") => b"never",
                        Some(v) => {
                            error(alloc::format!("invalid argument '{}' for '--color'", lossy(v)));
                            return 2;
                        }
                    }
                }
                "line-buffered" | "binary" => {}
                "regexp" => {
                    let Some(v) = p.value() else { return crate::util::missing_value("regexp") };
                    add_patterns(&mut patterns, &v);
                    have_patterns = true;
                }
                "file" => {
                    let Some(v) = p.value() else { return crate::util::missing_value("file") };
                    match crate::util::read_input(&v) {
                        Ok(d) => {
                            let d = d.strip_suffix(b"\n").unwrap_or(&d);
                            if !d.is_empty() {
                                add_patterns(&mut patterns, d);
                            }
                            have_patterns = true;
                        }
                        Err(e) => {
                            error(alloc::format!("{}: {e}", lossy(&v)));
                            return 2;
                        }
                    }
                }
                "max-count" => match num(p.value(), "max count") {
                    Ok(n) => g.max = Some(n as u64),
                    Err(s) => return s,
                },
                "after-context" | "before-context" | "context" => match num(p.value(), "context length") {
                    Ok(n) => {
                        if l != "before-context" {
                            g.after = n;
                        }
                        if l != "after-context" {
                            g.before = n;
                        }
                    }
                    Err(s) => return s,
                },
                "label" => g.label = p.value().unwrap_or_default(),
                "include" => g.include.push(p.value().unwrap_or_default()),
                "exclude" => g.exclude.push(p.value().unwrap_or_default()),
                "exclude-from" => {
                    let Some(v) = p.value() else { return crate::util::missing_value("exclude-from") };
                    match crate::util::read_input(&v) {
                        Ok(d) => {
                            g.exclude.extend(d.split(|&c| c == b'\n').filter(|l| !l.is_empty()).map(<[u8]>::to_vec))
                        }
                        Err(e) => {
                            error(alloc::format!("{}: {e}", lossy(&v)));
                            return 2;
                        }
                    }
                }
                "exclude-dir" => g.exclude_dir.push(p.value().unwrap_or_default()),
                "binary-files" => {
                    g.binary = match p.value().as_deref() {
                        Some(b"text") => BinaryFiles::Text,
                        Some(b"without-match") => BinaryFiles::NoMatch,
                        _ => BinaryFiles::Report,
                    }
                }
                _ => return crate::util::bad_option(&Opt::Long(l)),
            },
            Opt::Operand(v) => {
                if !have_patterns {
                    add_patterns(&mut patterns, &v);
                    have_patterns = true;
                } else {
                    operands.push(v);
                }
            }
            o => return crate::util::bad_option(&o),
        }
    }
    if !have_patterns {
        error("usage: grep [OPTION]... PATTERNS [FILE]...");
        return 2;
    }
    let opts = Options { syntax, icase, whole, utf8: crate::util::utf8_locale(), ..Options::default() };
    let single = patterns.len() == 1;
    if perl && patterns.len() > 1 {
        error("the -P option only supports a single pattern");
        return 2;
    }
    for pat in &patterns {
        if !fixed && !perl {
            match check_syntax(pat, syntax, single) {
                Ok(Some(w)) => io::err(&[b"grep: warning: ".as_slice(), &w, b"\n"].concat()),
                Ok(None) => {}
                Err(e) => {
                    error(e);
                    return 2;
                }
            }
        }
        let r = if fixed {
            Ok(Regex::literal(pat, opts))
        } else if perl {
            Regex::perl(pat, opts)
        } else {
            Regex::new(pat, opts)
        };
        match r {
            Ok(r) => g.pats.push(r),
            Err(e) => {
                error(e);
                return 2;
            }
        }
    }
    let on = match color {
        b"always" => true,
        b"auto" => slate_rt::term::isatty(1) && slate_rt::env::var(b"TERM").is_some_and(|t| t != b"dumb"),
        _ => false,
    };
    if on {
        let mut c = Colors::default();
        // GREP_COLOR is the old way to say mt.
        if let Some(old) = slate_rt::env::var(b"GREP_COLOR").filter(|v| !v.is_empty()) {
            io::err(
                alloc::format!(
                    "grep: warning: GREP_COLOR='{0}' is deprecated; use GREP_COLORS='mt={0}'\n",
                    lossy(&old)
                )
                .as_bytes(),
            );
            c.apply(&[b"mt=".as_slice(), &old].concat());
        }
        if let Some(spec) = slate_rt::env::var(b"GREP_COLORS") {
            c.apply(&spec);
        }
        g.colors = Some(c);
    }
    if operands.is_empty() {
        operands.push(if g.recursive { b".".to_vec() } else { b"-".to_vec() });
        if g.recursive {
            // `grep -r x` names files without a "./" prefix.
            g.names = names.unwrap_or(true);
            let entries = fs::read_dir(b".").unwrap_or_default();
            for e in entries {
                if e.name != b"." && e.name != b".." {
                    g.file(&e.name, false);
                }
            }
            return finish(&g);
        }
    }
    g.names = names.unwrap_or(operands.len() > 1 || g.recursive);
    for f in &operands {
        g.file(f, true);
        if g.quiet && g.matched {
            break;
        }
    }
    finish(&g)
}

/// `egrep`: `grep -E`.
pub fn egrep(args: &[Vec<u8>]) -> i32 {
    with_flag(args, b"-E")
}

/// `fgrep`: `grep -F`.
pub fn fgrep(args: &[Vec<u8>]) -> i32 {
    with_flag(args, b"-F")
}

fn with_flag(args: &[Vec<u8>], flag: &[u8]) -> i32 {
    let name = slate_rt::prog_name();
    io::err(alloc::format!("{name}: warning: {name} is obsolescent; using grep {}\n", lossy(flag)).as_bytes());
    let mut a = Vec::with_capacity(args.len() + 1);
    a.push(b"grep".to_vec());
    a.push(flag.to_vec());
    a.extend_from_slice(&args[1..]);
    main(&a)
}

fn finish(g: &Grep) -> i32 {
    if g.quiet && g.matched {
        return 0;
    }
    if g.errors {
        2
    } else if g.matched {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grep_colors() {
        let mut c = Colors::default();
        c.apply(b"ms=7:fn=3x:ln=4");
        assert_eq!((c.ms.as_deref(), c.ln.as_deref()), (Some(b"7".as_slice()), Some(b"32".as_slice())));
        let mut c = Colors::default();
        c.apply(b"zz=1::mt=01;32:se=:ne:rv");
        assert_eq!((c.ms.as_deref(), c.mc.as_deref()), (Some(b"01;32".as_slice()), Some(b"01;32".as_slice())));
        assert!(c.se.is_none() && c.ne && c.rv);
        let mut out = Vec::new();
        Colors::default().paint(&Some(b"35".to_vec()), b"f", &mut out);
        assert_eq!(out, b"\x1b[35m\x1b[Kf\x1b[m\x1b[K".to_vec());
    }

    #[test]
    fn syntax_checks() {
        let w = |p: &str, s, single| {
            check_syntax(p.as_bytes(), s, single).map(|w| w.map(|w| String::from_utf8(w).unwrap()))
        };
        use alloc::string::String;
        let (b, e) = (Syntax::Basic, Syntax::Extended);
        assert_eq!(w("a\\-b\\-", b, true), Ok(Some("stray \\ before -".into())));
        assert_eq!(w("a\\-b", b, false), Ok(None));
        assert_eq!(w("a\\ b", b, true), Ok(Some("stray \\ before white space".into())));
        assert_eq!(w("a\\\tb", b, true), Ok(Some("stray \\ before unprintable character".into())));
        assert_eq!(w("\\(x\\)\\{1\\}\\1\\w\\.\\]", b, true), Ok(None));
        assert_eq!(w("[a\\-z]", b, true), Ok(None));
        assert_eq!(w("[]\\-]x", b, true), Ok(None));
        assert_eq!(w("[[:alpha:]\\]", b, true), Ok(None));
        assert_eq!(w("x[:alpha:]", b, true), Err("character class syntax is [[:space:]], not [:space:]"));
        assert_eq!(w("[:alpha]", b, true), Ok(None));
        assert_eq!(w("*a", e, false), Ok(Some("* at start of expression".into())));
        assert_eq!(w("a|(+b)", e, false), Ok(Some("+ at start of expression".into())));
        assert_eq!(w("{1}a", e, true), Ok(Some("{...} at start of expression".into())));
        assert_eq!(w("^{1,2}a", e, true), Ok(Some("{...} at start of expression".into())));
        assert_eq!(w("{a", e, true), Ok(None));
        assert_eq!(w("{1", e, true), Ok(None));
        assert_eq!(w("*a", b, true), Ok(None));
        assert_eq!(w("a**", e, true), Ok(None));
    }
}
