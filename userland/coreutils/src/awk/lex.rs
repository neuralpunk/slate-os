// SPDX-License-Identifier: MIT OR Apache-2.0

//! awk lexical conventions (XCU awk, "Lexical Conventions"): a `/` starts
//! a regular expression where an operand may begin, otherwise it divides;
//! a name directly followed by `(` is a function call.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Num(f64),
    Str(Vec<u8>),
    Regex(Vec<u8>),
    /// gawk's typed regexp constant `@/re/`.
    TypedRegex(Vec<u8>),
    /// An integer constant too long for a double to hold exactly (`-M`).
    BigNum(Vec<u8>),
    Name(Vec<u8>),
    /// A user function name followed directly by `(`.
    FuncName(Vec<u8>),
    Builtin(&'static str),
    Kw(&'static str),
    Op(&'static str),
    Newline,
    Eof,
}

pub const BUILTINS: &[&str] = &[
    "and",
    "asort",
    "asorti",
    "atan2",
    "close",
    "compl",
    "cos",
    "exp",
    "fflush",
    "gensub",
    "gsub",
    "index",
    "int",
    "isarray",
    "length",
    "log",
    "lshift",
    "match",
    "mktime",
    "or",
    "patsplit",
    "rand",
    "rshift",
    "sin",
    "split",
    "sprintf",
    "sqrt",
    "srand",
    "strftime",
    "strtonum",
    "sub",
    "substr",
    "system",
    "systime",
    "tolower",
    "toupper",
    "typeof",
    "xor",
    "dcgettext",
    "dcngettext",
    "bindtextdomain",
];

/// The extensions `@load` gives (gawk's bundled ones that Slate's awk
/// has built in, ADR 0165), and the functions each adds.
pub const EXTENSIONS: &[(&str, &[&str])] = &[
    ("ordchr", &["ord", "chr"]),
    ("time", &["gettimeofday", "sleep", "strptime"]),
    ("filefuncs", &["stat", "chdir", "statvfs"]),
    ("readfile", &["readfile"]),
    ("fnmatch", &["fnmatch"]),
    ("fork", &["fork", "waitpid", "wait"]),
    ("readdir", &[]),
    ("inplace", &["inplace::begin", "inplace::end"]),
];

const KEYWORDS: &[&str] = &[
    "BEGIN",
    "BEGINFILE",
    "END",
    "ENDFILE",
    "break",
    "case",
    "continue",
    "default",
    "delete",
    "do",
    "else",
    "exit",
    "for",
    "func",
    "function",
    "getline",
    "if",
    "in",
    "next",
    "nextfile",
    "print",
    "printf",
    "return",
    "switch",
    "while",
];

const OPS: &[&str] = &[
    "**=", "&&", "||", "==", "<=", ">=", "!=", "++", "--", "+=", "-=", "*=", "/=", "%=", "^=", ">>", "!~", "**", "{",
    "}", "(", ")", "[", "]", ";", ",", "+", "-", "*", "/", "%", "^", "!", ">", "<", "|", "?", ":", "~", "$", "=",
];

pub struct Lexer<'a> {
    s: &'a [u8],
    pub pos: usize,
    pub line: usize,
    /// Whether the previous token ends an operand (so `/` divides).
    operand_before: bool,
    /// The namespace names are read in (`@namespace`; gawk's "awk" is the
    /// default, where names stay as they are).
    namespace: Vec<u8>,
    /// Extensions `@load` asked for (their functions are builtins after).
    pub loaded: Vec<&'static str>,
}

/// A name as gawk's namespaces read it (gawk manual, "Namespaces"):
/// `awk::x` is `x`; in namespace `ns` other than awk, a simple name is
/// `ns::x` unless it is all capitals (the special variables' kind).
fn qualify(namespace: &[u8], name: &[u8]) -> Vec<u8> {
    if let Some(i) = name.windows(2).position(|w| w == b"::") {
        return if &name[..i] == b"awk" { name[i + 2..].to_vec() } else { name.to_vec() };
    }
    let capitals = name.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_');
    if namespace == b"awk" || capitals {
        return name.to_vec();
    }
    [namespace, b"::", name].concat()
}

/// The value of a string escape (`\n`, `\t`, `\ddd`, ...) at `s[i]` (after
/// the backslash): (byte(s), length consumed).
pub fn escape(s: &[u8], i: usize) -> (Vec<u8>, usize) {
    let Some(&c) = s.get(i) else { return (alloc::vec![b'\\'], 0) };
    let b = match c {
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'\\' => b'\\',
        b'"' => b'"',
        b'/' => b'/',
        b'a' => 7,
        b'b' => 8,
        b'f' => 12,
        b'v' => 11,
        b'0'..=b'7' => {
            let mut v = 0u32;
            let mut n = 0;
            while n < 3 && s.get(i + n).is_some_and(|d| (b'0'..=b'7').contains(d)) {
                v = v * 8 + (s[i + n] - b'0') as u32;
                n += 1;
            }
            return (alloc::vec![v as u8], n);
        }
        // Unknown escapes keep the backslash (gawk warns).
        other => return (alloc::vec![b'\\', other], 1),
    };
    (alloc::vec![b], 1)
}

impl<'a> Lexer<'a> {
    pub fn new(s: &'a [u8]) -> Lexer<'a> {
        Lexer { s, pos: 0, line: 1, operand_before: false, namespace: b"awk".to_vec(), loaded: Vec::new() }
    }

    fn at(&self, k: usize) -> Option<u8> {
        self.s.get(self.pos + k).copied()
    }

    pub fn next(&mut self) -> Result<Tok, String> {
        let t = self.lex()?;
        self.operand_before = matches!(
            t,
            Tok::Num(_)
                | Tok::Str(_)
                | Tok::Regex(_)
                | Tok::TypedRegex(_)
                | Tok::BigNum(_)
                | Tok::Name(_)
                | Tok::Builtin(_)
                | Tok::Op(")" | "]" | "++" | "--" | "$")
        );
        // `$` is followed by an operand, never a division.
        if t == Tok::Op("$") {
            self.operand_before = false;
        }
        Ok(t)
    }

    fn lex(&mut self) -> Result<Tok, String> {
        loop {
            match self.at(0) {
                Some(b' ' | b'\t' | b'\r') => self.pos += 1,
                Some(b'\\') if self.at(1) == Some(b'\n') => {
                    self.pos += 2;
                    self.line += 1;
                }
                Some(b'\\') if self.at(1) == Some(b'\r') && self.at(2) == Some(b'\n') => {
                    self.pos += 3;
                    self.line += 1;
                }
                Some(b'#') => {
                    while self.at(0).is_some_and(|c| c != b'\n') {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
        let Some(c) = self.at(0) else { return Ok(Tok::Eof) };
        if c == b'\n' {
            self.pos += 1;
            self.line += 1;
            return Ok(Tok::Newline);
        }
        if c == b'"' {
            self.pos += 1;
            let mut v = Vec::new();
            loop {
                match self.at(0) {
                    None | Some(b'\n') => return Err(String::from("unterminated string")),
                    Some(b'"') => {
                        self.pos += 1;
                        return Ok(Tok::Str(v));
                    }
                    Some(b'\\') => {
                        if self.at(1) == Some(b'\n') {
                            self.pos += 2;
                            self.line += 1;
                            continue;
                        }
                        let (b, n) = escape(self.s, self.pos + 1);
                        v.extend_from_slice(&b);
                        self.pos += 1 + n;
                    }
                    Some(c) => {
                        v.push(c);
                        self.pos += 1;
                    }
                }
            }
        }
        if c == b'/' && !self.operand_before {
            return self.regex();
        }
        if c.is_ascii_digit() || (c == b'.' && self.at(1).is_some_and(|d| d.is_ascii_digit())) {
            // A long integer keeps its digits, for -M.
            let digits = self.s[self.pos..].iter().take_while(|c| c.is_ascii_digit()).count();
            let after = self.s.get(self.pos + digits).copied();
            if digits > 15 && !matches!(after, Some(b'.' | b'e' | b'E' | b'x' | b'X')) && c != b'0' {
                let t = self.s[self.pos..self.pos + digits].to_vec();
                self.pos += digits;
                return Ok(Tok::BigNum(t));
            }
            return Ok(Tok::Num(self.number()));
        }
        if c == b'@' && self.at(1) == Some(b'/') {
            self.pos += 1;
            return match self.regex()? {
                Tok::Regex(r) => Ok(Tok::TypedRegex(r)),
                t => Ok(t),
            };
        }
        // `_"text"`: a string to translate (gettext); with no catalogs, as
        // it is.
        if c == b'_' && self.at(1) == Some(b'"') {
            self.pos += 1;
            return self.lex();
        }
        if c == b'@' {
            // `@namespace "name"` changes how names read from here on.
            let start = self.pos + 1;
            let mut end = start;
            while self.s.get(end).is_some_and(|c| c.is_ascii_alphabetic()) {
                end += 1;
            }
            let word = &self.s[start..end];
            self.pos = end;
            match word {
                b"namespace" => {
                    let Tok::Str(ns) = self.lex()? else {
                        return Err(String::from("@namespace needs a name in quotes"));
                    };
                    if ns.is_empty() || !ns.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_') {
                        return Err(alloc::format!("`{}' is not a valid namespace name", String::from_utf8_lossy(&ns)));
                    }
                    self.namespace = ns;
                    return self.lex();
                }
                b"include" => return Err(String::from("@include must be at the start of a line")),
                b"load" => {
                    let Tok::Str(name) = self.lex()? else {
                        return Err(String::from("@load needs a name in quotes"));
                    };
                    let base = name.strip_suffix(b".so").unwrap_or(&name);
                    match EXTENSIONS.iter().find(|(e, _)| e.as_bytes() == base) {
                        Some((e, _)) => {
                            if !self.loaded.contains(e) {
                                self.loaded.push(e);
                            }
                        }
                        None => {
                            return Err(alloc::format!(
                                "load_ext: library `{}': not built into this awk (no dynamic extensions)",
                                String::from_utf8_lossy(&name)
                            ));
                        }
                    }
                    return self.lex();
                }
                _ => return Err(alloc::format!("`@{}' is not a known directive", String::from_utf8_lossy(word))),
            }
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = self.pos;
            loop {
                while self.at(0).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_') {
                    self.pos += 1;
                }
                // `ns::name`.
                if self.at(0) == Some(b':')
                    && self.at(1) == Some(b':')
                    && self.at(2).is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                {
                    self.pos += 2;
                    continue;
                }
                break;
            }
            let name = &self.s[start..self.pos];
            let text = core::str::from_utf8(name).unwrap_or("");
            if let Some(k) = KEYWORDS.iter().find(|k| **k == text) {
                return Ok(Tok::Kw(k));
            }
            if let Some(b) = BUILTINS.iter().find(|k| **k == text) {
                return Ok(Tok::Builtin(b));
            }
            let name = qualify(&self.namespace, name);
            // A loaded extension's functions (by their names in the
            // namespace: `begin` in @namespace "inplace" is inplace::begin).
            for (e, funcs) in EXTENSIONS {
                if self.loaded.contains(e)
                    && let Some(f) = funcs.iter().find(|f| f.as_bytes() == name.as_slice())
                {
                    return Ok(Tok::Builtin(f));
                }
            }
            if self.at(0) == Some(b'(') {
                return Ok(Tok::FuncName(name));
            }
            return Ok(Tok::Name(name));
        }
        for op in OPS {
            if self.s[self.pos..].starts_with(op.as_bytes()) {
                self.pos += op.len();
                return Ok(Tok::Op(op));
            }
        }
        Err(alloc::format!("invalid char '{}' in expression", c as char))
    }

    fn regex(&mut self) -> Result<Tok, String> {
        self.pos += 1;
        let mut v = Vec::new();
        let mut in_bracket = false;
        loop {
            match self.at(0) {
                None | Some(b'\n') => return Err(String::from("unterminated regexp")),
                Some(b'/') if !in_bracket => {
                    self.pos += 1;
                    return Ok(Tok::Regex(v));
                }
                Some(b'\\') => {
                    match self.at(1) {
                        Some(b'/') => v.push(b'/'),
                        Some(b'\n') => {
                            self.line += 1;
                        }
                        Some(n) => {
                            v.push(b'\\');
                            v.push(n);
                        }
                        None => return Err(String::from("unterminated regexp")),
                    }
                    self.pos += 2;
                }
                Some(c) => {
                    if c == b'[' && !in_bracket {
                        in_bracket = true;
                        v.push(c);
                        self.pos += 1;
                        if self.at(0) == Some(b'^') {
                            v.push(b'^');
                            self.pos += 1;
                        }
                        if self.at(0) == Some(b']') {
                            v.push(b']');
                            self.pos += 1;
                        }
                        continue;
                    }
                    if c == b']' {
                        in_bracket = false;
                    }
                    v.push(c);
                    self.pos += 1;
                }
            }
        }
    }

    fn number(&mut self) -> f64 {
        let s = self.s;
        let start = self.pos;
        // Hexadecimal and octal constants in program text (gawk).
        if s[start] == b'0'
            && matches!(s.get(start + 1), Some(b'x' | b'X'))
            && s.get(start + 2).is_some_and(u8::is_ascii_hexdigit)
        {
            self.pos += 2;
            let mut v = 0f64;
            while let Some(d) = self.at(0).and_then(|c| (c as char).to_digit(16)) {
                v = v * 16.0 + d as f64;
                self.pos += 1;
            }
            return v;
        }
        while self.at(0).is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        let int_end = self.pos;
        if self.at(0) == Some(b'.') {
            self.pos += 1;
            while self.at(0).is_some_and(|c| c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.at(0), Some(b'e' | b'E')) {
            let save = self.pos;
            self.pos += 1;
            if matches!(self.at(0), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if self.at(0).is_some_and(|c| c.is_ascii_digit()) {
                while self.at(0).is_some_and(|c| c.is_ascii_digit()) {
                    self.pos += 1;
                }
            } else {
                self.pos = save;
            }
        }
        let text = &s[start..self.pos];
        if int_end == self.pos && text.len() > 1 && text[0] == b'0' && text.iter().all(|c| (b'0'..=b'7').contains(c)) {
            let mut v = 0f64;
            for &c in &text[1..] {
                v = v * 8.0 + (c - b'0') as f64;
            }
            return v;
        }
        core::str::from_utf8(text).ok().and_then(|t| t.parse().ok()).unwrap_or(0.0)
    }
}
