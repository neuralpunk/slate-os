// SPDX-License-Identifier: MIT OR Apache-2.0

//! The shell parser: lexing and parsing together, as the shell grammar
//! needs (reserved words only in command position, here-documents read at
//! the next newline, `$(...)` parsed in place). Follows POSIX.1-2017 XCU
//! §2.3 (token recognition), §2.6 (word expansions' syntax) and §2.10
//! (grammar).

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::ast::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The input ended inside a construct: an interactive shell asks for
    /// more lines.
    Incomplete,
    Syntax(String),
}

type Result<T> = core::result::Result<T, ParseError>;

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(Word),
    /// Digits right before `<` or `>`.
    IoNumber(i32),
    Op(&'static str),
    Newline,
    Eof,
}

const OPS: &[&str] = &[
    "&>>", ";;&", "<<-", "<<<", "&&", "||", ";;", ";&", "<<", ">>", "<&", ">&", "<>", ">|", "&>", "|&", "&", "|", ";",
    "<", ">", "(", ")",
];

pub fn is_name(s: &[u8]) -> bool {
    !s.is_empty() && !s[0].is_ascii_digit() && s.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// A word that is a plain unquoted literal.
pub fn literal(w: &Word) -> Option<&[u8]> {
    match w.as_slice() {
        [WordPart::Lit(l)] => Some(l),
        _ => None,
    }
}

/// A here-document waiting for its body: delimiter, quoted, strip tabs.
type PendingHereDoc = (Vec<u8>, bool, bool, Rc<RefCell<HereBody>>);

pub struct Parser {
    s: Vec<u8>,
    pos: usize,
    peeked: Option<(Token, usize)>,
    heredocs: Vec<PendingHereDoc>,
    aliases: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Alias expansions in progress (end position, name), against loops.
    expanding: Vec<(usize, Vec<u8>)>,
    /// `shopt -s extglob`: `?(...)`, `*(...)`, `+(...)`, `@(...)` and
    /// `!(...)` are patterns, not syntax.
    pub extglob: bool,
    /// Inside `[[ ]]`, where patterns are always extended (bash).
    in_cond: bool,
    /// The line the input starts at, and the last position whose line was
    /// counted (lines are counted forward from there).
    line_base: usize,
    counted: (usize, usize),
}

impl core::fmt::Debug for Parser {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Parser").field("pos", &self.pos).finish()
    }
}

impl Parser {
    pub fn new(s: &[u8]) -> Parser {
        Parser {
            s: s.to_vec(),
            pos: 0,
            peeked: None,
            heredocs: Vec::new(),
            aliases: BTreeMap::new(),
            expanding: Vec::new(),
            extglob: false,
            in_cond: false,
            line_base: 1,
            counted: (0, 0),
        }
    }

    /// Number lines from `line` (the input is part of a script).
    pub fn set_line(&mut self, line: usize) {
        self.line_base = line.max(1);
    }

    /// The line of input position `pos`.
    fn line_at(&mut self, pos: usize) -> usize {
        let pos = pos.min(self.s.len());
        let (mut at, mut n) = self.counted;
        if pos < at {
            (at, n) = (0, 0);
        }
        n += self.s[at..pos].iter().filter(|&&c| c == b'\n').count();
        self.counted = (pos, n);
        self.line_base + n
    }

    /// Where parsing stopped: its line's number and text (for messages).
    pub fn error_context(&mut self) -> (usize, Vec<u8>) {
        let pos = self.pos.min(self.s.len());
        let n = self.line_at(pos);
        let start = self.s[..pos].iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);
        let start = if start == pos && pos > 0 && self.s[pos - 1] == b'\n' {
            self.s[..pos - 1].iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1)
        } else {
            start
        };
        let end = self.s[start..].iter().position(|&c| c == b'\n').map_or(self.s.len(), |i| start + i);
        let n = if start < pos && self.s[start..pos].contains(&b'\n') { n - 1 } else { n };
        (n, self.s[start..end].to_vec())
    }

    /// The line of the next token.
    fn next_line(&mut self) -> Result<usize> {
        self.peek()?;
        let start = self.peeked.as_ref().map_or(self.pos, |p| p.1);
        // The token's own start, past blanks and comments.
        let mut i = start;
        while i < self.s.len() && matches!(self.s[i], b' ' | b'\t') {
            i += 1;
        }
        Ok(self.line_at(i))
    }

    /// A parser for text inside this input (backquotes), starting at `pos`.
    fn sub_parser(&mut self, text: &[u8], pos: usize) -> Parser {
        let mut p = Parser::new(text);
        p.aliases = self.aliases.clone();
        p.extglob = self.extglob;
        p.in_cond = self.in_cond;
        p.line_base = self.line_at(pos);
        p
    }

    /// Aliases to expand from here on.
    pub fn set_aliases(&mut self, aliases: BTreeMap<Vec<u8>, Vec<u8>>) {
        self.aliases = aliases;
    }

    /// Append more input (an interactive shell's continuation lines).
    pub fn feed(&mut self, more: &[u8]) {
        self.s.extend_from_slice(more);
    }

    /// The input (with aliases expanded so far).
    pub fn input(&self) -> &[u8] {
        &self.s
    }

    /// The input position after the last consumed token.
    pub fn pos(&self) -> usize {
        self.peeked.as_ref().map_or(self.pos, |p| p.1)
    }

    fn unexpected<T>(t: Token) -> Result<T> {
        match t {
            Token::Eof => Err(ParseError::Incomplete),
            Token::Op(o) => Err(ParseError::Syntax(alloc::format!("syntax error near unexpected token '{o}'"))),
            Token::Word(w) => Err(ParseError::Syntax(alloc::format!(
                "syntax error near unexpected token '{}'",
                String::from_utf8_lossy(&crate::expand::word_text(&w))
            ))),
            _ => Err(ParseError::Syntax(String::from("syntax error"))),
        }
    }

    /// The commands of the next line (a shell runs a script line by line,
    /// so aliases defined on one line apply to the next), or `None` at the
    /// end of the input.
    pub fn line(&mut self) -> Result<Option<Program>> {
        self.skip_newlines()?;
        if *self.peek()? == Token::Eof {
            return Ok(None);
        }
        let mut items = Vec::new();
        loop {
            // A closing word with nothing open is an error, not a command.
            let t = self.peek()?.clone();
            if Self::is_reserved(&t, &[b"then", b"else", b"elif", b"fi", b"do", b"done", b"esac", b"}"]) {
                return Self::unexpected(t);
            }
            let cmd = self.and_or()?;
            match self.next()? {
                Token::Op("&") => items.push((cmd, true)),
                Token::Op(";") => items.push((cmd, false)),
                Token::Newline | Token::Eof => {
                    items.push((cmd, false));
                    return Ok(Some(Program(items)));
                }
                t => return Self::unexpected(t),
            }
            match self.peek()? {
                Token::Newline => {
                    self.next()?;
                    return Ok(Some(Program(items)));
                }
                Token::Eof => return Ok(Some(Program(items))),
                _ => {}
            }
        }
    }

    fn err<T>(&self, msg: &str) -> Result<T> {
        if self.pos >= self.s.len() {
            return Err(ParseError::Incomplete);
        }
        Err(ParseError::Syntax(String::from(msg)))
    }

    fn at(&self, i: usize) -> Option<u8> {
        self.s.get(self.pos + i).copied()
    }

    /// Parse a whole program.
    pub fn program(&mut self) -> Result<Program> {
        let p = self.list(&[])?;
        match self.next()? {
            Token::Eof => Ok(p),
            t => Self::unexpected(t),
        }
    }

    // --- lexing ----------------------------------------------------------

    fn skip_blanks(&mut self) {
        loop {
            match self.at(0) {
                Some(b' ' | b'\t') => self.pos += 1,
                Some(b'\\') if self.at(1) == Some(b'\n') => self.pos += 2,
                Some(b'#') => {
                    while self.at(0).is_some_and(|c| c != b'\n') {
                        self.pos += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn peek(&mut self) -> Result<&Token> {
        if self.peeked.is_none() {
            let start = self.pos;
            let t = self.lex()?;
            self.peeked = Some((t, start));
        }
        Ok(&self.peeked.as_ref().unwrap().0)
    }

    fn next(&mut self) -> Result<Token> {
        self.peek()?;
        Ok(self.peeked.take().unwrap().0)
    }

    fn lex(&mut self) -> Result<Token> {
        self.skip_blanks();
        // Leaving an alias's text ends its expansion.
        self.expanding.retain(|(end, _)| self.pos < *end);
        let Some(c) = self.at(0) else { return Ok(Token::Eof) };
        if c == b'\n' {
            self.pos += 1;
            self.read_heredocs()?;
            return Ok(Token::Newline);
        }
        // <(...) and >(...): process substitution (bash), before the
        // operators take the `<`.
        if matches!(c, b'<' | b'>') && self.at(1) == Some(b'(') {
            let out = c == b'>';
            self.pos += 2;
            let prog = self.list(&[])?;
            return match self.next()? {
                Token::Op(")") => Ok(Token::Word(alloc::vec![WordPart::ProcSub(Rc::new(prog), out)])),
                Token::Eof => Err(ParseError::Incomplete),
                _ => self.err("expected ')'"),
            };
        }
        for op in OPS {
            if self.s[self.pos..].starts_with(op.as_bytes()) {
                self.pos += op.len();
                return Ok(Token::Op(op));
            }
        }
        // An IO number: digits right before a redirection operator.
        let digits = self.s[self.pos..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits > 0 && matches!(self.at(digits), Some(b'<' | b'>')) {
            let n = core::str::from_utf8(&self.s[self.pos..self.pos + digits]).unwrap().parse().unwrap_or(-1);
            self.pos += digits;
            return Ok(Token::IoNumber(n));
        }
        Ok(Token::Word(self.word(None)?))
    }

    fn is_meta(c: u8) -> bool {
        matches!(c, b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' | b'(' | b')')
    }

    /// Read a word: up to an unquoted metacharacter, or (for `${...}`
    /// operands) up to the unquoted `term` byte, blanks included.
    fn word(&mut self, term: Option<u8>) -> Result<Word> {
        let mut parts: Word = Vec::new();
        let mut lit: Vec<u8> = Vec::new();
        fn flush(parts: &mut Word, lit: &mut Vec<u8>) {
            if !lit.is_empty() {
                parts.push(WordPart::Lit(core::mem::take(lit)));
            }
        }
        loop {
            let Some(c) = self.at(0) else {
                // Term 0: the whole rest of the input (arithmetic text).
                if term.is_some_and(|t| t != 0) {
                    return Err(ParseError::Incomplete);
                }
                break;
            };
            match term {
                Some(t) if c == t => break,
                // `name=(...)` / `name+=(...)`: an array literal (bash).
                None if c == b'(' && parts.is_empty() && is_array_head(&lit) => {
                    self.pos += 1;
                    let elems = self.array_elems()?;
                    flush(&mut parts, &mut lit);
                    parts.push(WordPart::ArrayLit(elems));
                    continue;
                }
                // `@(a|b)` and friends: one literal run up to the `)`.
                None if (self.extglob || self.in_cond)
                    && matches!(c, b'?' | b'*' | b'+' | b'@' | b'!')
                    && self.at(1) == Some(b'(') =>
                {
                    let end = self.ext_pattern_end(self.pos + 1)?;
                    lit.extend_from_slice(&self.s[self.pos..end]);
                    self.pos = end;
                    continue;
                }
                None if Self::is_meta(c) => break,
                _ => {}
            }
            match c {
                b'\\' => {
                    match self.at(1) {
                        Some(b'\n') => {}
                        Some(n) => {
                            flush(&mut parts, &mut lit);
                            parts.push(WordPart::Escaped(n));
                        }
                        None => {
                            self.pos += 1;
                            return Err(ParseError::Incomplete);
                        }
                    }
                    self.pos += 2;
                }
                b'\'' => {
                    flush(&mut parts, &mut lit);
                    let start = self.pos + 1;
                    let Some(end) = self.s[start..].iter().position(|&c| c == b'\'') else {
                        self.pos = self.s.len();
                        return Err(ParseError::Incomplete);
                    };
                    parts.push(WordPart::Quoted(self.s[start..start + end].to_vec()));
                    self.pos = start + end + 1;
                }
                b'"' => {
                    flush(&mut parts, &mut lit);
                    self.pos += 1;
                    let inner = self.dquoted()?;
                    parts.push(WordPart::DQuote(inner));
                }
                b'$' => {
                    if self.at(1) == Some(b'\'') {
                        flush(&mut parts, &mut lit);
                        self.pos += 2;
                        let q = self.ansi_c()?;
                        parts.push(WordPart::Quoted(q));
                        continue;
                    }
                    match self.dollar(false)? {
                        Some(p) => {
                            flush(&mut parts, &mut lit);
                            parts.push(p);
                        }
                        None => {
                            lit.push(b'$');
                            self.pos += 1;
                        }
                    }
                }
                b'`' => {
                    flush(&mut parts, &mut lit);
                    let p = self.backquote()?;
                    parts.push(p);
                }
                _ => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        flush(&mut parts, &mut lit);
        Ok(parts)
    }

    /// The end of an extended pattern group whose `(` is at `open`: just
    /// past its matching `)`.
    fn ext_pattern_end(&self, open: usize) -> Result<usize> {
        let mut depth = 0;
        let mut i = open;
        while let Some(&c) = self.s.get(i) {
            match c {
                b'\\' => i += 1,
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(i + 1);
                    }
                }
                b'\'' => match self.s[i + 1..].iter().position(|&q| q == b'\'') {
                    Some(e) => i += e + 1,
                    None => return Err(ParseError::Incomplete),
                },
                _ => {}
            }
            i += 1;
        }
        Err(ParseError::Incomplete)
    }

    /// An array literal's words, after its `(`, up to the `)`.
    fn array_elems(&mut self) -> Result<Vec<Word>> {
        let mut elems = Vec::new();
        loop {
            // Blanks, newlines and comments separate elements.
            loop {
                match self.at(0) {
                    Some(b' ' | b'\t' | b'\n') => self.pos += 1,
                    Some(b'#') => {
                        while self.at(0).is_some_and(|c| c != b'\n') {
                            self.pos += 1;
                        }
                    }
                    _ => break,
                }
            }
            match self.at(0) {
                None => return Err(ParseError::Incomplete),
                Some(b')') => {
                    self.pos += 1;
                    return Ok(elems);
                }
                Some(c) if Self::is_meta(c) => {
                    return self.err(&alloc::format!("syntax error near unexpected token '{}'", c as char));
                }
                _ => elems.push(self.word(None)?),
            }
        }
    }

    /// Inside double quotes, after the opening `"`.
    fn dquoted(&mut self) -> Result<Word> {
        let mut parts = Vec::new();
        let mut lit = Vec::new();
        loop {
            let Some(c) = self.at(0) else { return Err(ParseError::Incomplete) };
            match c {
                b'"' => {
                    self.pos += 1;
                    break;
                }
                b'\\' => {
                    match self.at(1) {
                        Some(n @ (b'$' | b'`' | b'"' | b'\\')) => lit.push(n),
                        Some(b'\n') => {}
                        Some(n) => {
                            lit.push(b'\\');
                            lit.push(n);
                        }
                        None => return Err(ParseError::Incomplete),
                    }
                    self.pos += 2;
                }
                b'$' => match self.dollar(true)? {
                    Some(p) => {
                        if !lit.is_empty() {
                            parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                        }
                        parts.push(p);
                    }
                    None => {
                        lit.push(b'$');
                        self.pos += 1;
                    }
                },
                b'`' => {
                    if !lit.is_empty() {
                        parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                    }
                    let p = self.backquote()?;
                    parts.push(p);
                }
                _ => {
                    lit.push(c);
                    self.pos += 1;
                }
            }
        }
        if !lit.is_empty() {
            parts.push(WordPart::Quoted(lit));
        }
        Ok(parts)
    }

    /// `$'...'` (bash): backslash escapes, after the `$'`.
    fn ansi_c(&mut self) -> Result<Vec<u8>> {
        let start = self.pos;
        let mut i = start;
        while i < self.s.len() && self.s[i] != b'\'' {
            if self.s[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        if i >= self.s.len() {
            self.pos = self.s.len();
            return Err(ParseError::Incomplete);
        }
        let raw = self.s[start..i].to_vec();
        self.pos = i + 1;
        let mut out = Vec::new();
        let mut k = 0;
        while k < raw.len() {
            if raw[k] == b'\\' && k + 1 < raw.len() {
                match raw[k + 1] {
                    b'\'' => {
                        out.push(b'\'');
                        k += 2;
                        continue;
                    }
                    b'"' => {
                        out.push(b'"');
                        k += 2;
                        continue;
                    }
                    _ => {}
                }
                // Reuse printf's escapes for the rest.
                let mut j = k + 2;
                if raw[k + 1].is_ascii_digit() || raw[k + 1] == b'x' {
                    while j < raw.len() && j < k + 5 && raw[j].is_ascii_hexdigit() {
                        j += 1;
                    }
                }
                let (b, _) = slate_coreutils::util::unescape(&raw[k..j], true);
                out.extend_from_slice(&b);
                k = j;
            } else {
                out.push(raw[k]);
                k += 1;
            }
        }
        Ok(out)
    }

    /// A `$` expansion at the current position, or `None` if `$` is literal.
    fn dollar(&mut self, quoted: bool) -> Result<Option<WordPart>> {
        let _ = quoted;
        match self.at(1) {
            Some(b'(') if self.at(2) == Some(b'(') => {
                // $(( arithmetic )): the text up to the matching "))".
                let start = self.pos + 3;
                let mut depth = 0;
                let mut i = start;
                loop {
                    match self.s.get(i) {
                        None => {
                            self.pos = self.s.len();
                            return Err(ParseError::Incomplete);
                        }
                        Some(b'(') => depth += 1,
                        Some(b')') if depth == 0 && self.s.get(i + 1) == Some(&b')') => break,
                        Some(b')') => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                let text = self.s[start..i].to_vec();
                self.pos = i + 2;
                let mut sub = Parser::new(&text);
                let w = sub.word(Some(0))?;
                Ok(Some(WordPart::Arith(w)))
            }
            Some(b'(') => {
                self.pos += 2;
                let saved = self.peeked.take();
                debug_assert!(saved.is_none());
                let prog = self.list(&[])?;
                match self.next()? {
                    Token::Op(")") => Ok(Some(WordPart::CmdSub(Rc::new(prog), false))),
                    Token::Eof => Err(ParseError::Incomplete),
                    _ => self.err("expected ')'"),
                }
            }
            Some(b'{') => {
                self.pos += 2;
                self.brace_param().map(Some)
            }
            // `$[...]`: old arithmetic (bash).
            Some(b'[') => {
                let start = self.pos + 2;
                let mut depth = 0;
                let mut i = start;
                loop {
                    match self.s.get(i) {
                        None => {
                            self.pos = self.s.len();
                            return Err(ParseError::Incomplete);
                        }
                        Some(b'[') => depth += 1,
                        Some(b']') if depth == 0 => break,
                        Some(b']') => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                let text = self.s[start..i].to_vec();
                self.pos = i + 1;
                let w = Parser::new(&text).word(Some(0))?;
                Ok(Some(WordPart::Arith(w)))
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let start = self.pos + 1;
                let n = self.s[start..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_').count();
                self.pos = start + n;
                Ok(Some(param(self.s[start..start + n].to_vec(), ParamOp::Get)))
            }
            Some(c) if c.is_ascii_digit() || b"?#$!@*-".contains(&c) => {
                self.pos += 2;
                Ok(Some(param(alloc::vec![c], ParamOp::Get)))
            }
            _ => Ok(None),
        }
    }

    /// `${...}` after the `${`.
    fn brace_param(&mut self) -> Result<WordPart> {
        // ${#name}: length (but ${#} is the argument count, and ${#-...}).
        let length = self.at(0) == Some(b'#') && self.at(1).is_some_and(|c| c != b'}');
        if length {
            self.pos += 1;
        }
        // ${!name}: indirection (bash); ${!} alone is the last job's pid.
        let indirect =
            !length && self.at(0) == Some(b'!') && self.at(1).is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
        if indirect {
            self.pos += 1;
        }
        let name: Vec<u8> = match self.at(0) {
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let n = self.s[self.pos..].iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_').count();
                self.s[self.pos..self.pos + n].to_vec()
            }
            Some(c) if c.is_ascii_digit() => {
                let n = self.s[self.pos..].iter().take_while(|c| c.is_ascii_digit()).count();
                self.s[self.pos..self.pos + n].to_vec()
            }
            Some(c) if b"?#$!@*-".contains(&c) => alloc::vec![c],
            None => return Err(ParseError::Incomplete),
            _ => return self.err("bad substitution"),
        };
        self.pos += name.len();
        // ${name[subscript]...} (bash arrays).
        let mut index = None;
        if self.at(0) == Some(b'[') && name.first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') {
            self.pos += 1;
            let w = self.word_until(b"]")?;
            self.pos += 1;
            index = Some(w);
        }
        let mk = |name: Vec<u8>, op: ParamOp, colon: bool, index: Option<Word>| {
            WordPart::Param(alloc::boxed::Box::new(Param { name, op, colon, index, indirect, braced: true }))
        };
        if length {
            if self.at(0) != Some(b'}') {
                return self.err("bad substitution");
            }
            self.pos += 1;
            return Ok(mk(name, ParamOp::Length, false, index));
        }
        let Some(c) = self.at(0) else { return Err(ParseError::Incomplete) };
        if indirect && index.is_none() && matches!(c, b'*' | b'@') && self.at(1) == Some(b'}') {
            self.pos += 2;
            return Ok(mk(name, ParamOp::Names(c == b'*'), false, None));
        }
        let (op, colon) = match c {
            b'}' => {
                self.pos += 1;
                return Ok(mk(name, ParamOp::Get, false, index));
            }
            b':' if matches!(self.at(1), Some(b'-' | b'=' | b'?' | b'+')) => {
                let o = self.at(1).unwrap();
                self.pos += 2;
                let w = self.word(Some(b'}'))?;
                self.pos += 1;
                (simple_op(o, w), true)
            }
            b':' => {
                self.pos += 1;
                let off = self.word_until(b":}")?;
                let len = if self.at(0) == Some(b':') {
                    self.pos += 1;
                    Some(self.word(Some(b'}'))?)
                } else {
                    None
                };
                self.pos += 1;
                (ParamOp::Substr(off, len), false)
            }
            b'-' | b'=' | b'?' | b'+' => {
                self.pos += 1;
                let w = self.word(Some(b'}'))?;
                self.pos += 1;
                (simple_op(c, w), false)
            }
            b'%' | b'#' => {
                let longest = self.at(1) == Some(c);
                self.pos += if longest { 2 } else { 1 };
                let w = self.word(Some(b'}'))?;
                self.pos += 1;
                (if c == b'%' { ParamOp::RemoveSuffix(w, longest) } else { ParamOp::RemovePrefix(w, longest) }, false)
            }
            b'/' => {
                self.pos += 1;
                let (all, anchor) = match self.at(0) {
                    Some(b'/') => (true, 0),
                    Some(b'#') => (false, b'#'),
                    Some(b'%') => (false, b'%'),
                    _ => (false, 0),
                };
                if all || anchor != 0 {
                    self.pos += 1;
                }
                let pat = self.word_until(b"/}")?;
                let rep = if self.at(0) == Some(b'/') {
                    self.pos += 1;
                    self.word(Some(b'}'))?
                } else {
                    Vec::new()
                };
                self.pos += 1;
                (ParamOp::Replace { pat, rep, all, anchor }, false)
            }
            b'^' | b',' => {
                let all = self.at(1) == Some(c);
                self.pos += if all { 2 } else { 1 };
                if self.at(0) != Some(b'}') {
                    return self.err("bad substitution");
                }
                self.pos += 1;
                (ParamOp::Case(c == b'^', all), false)
            }
            _ => return self.err("bad substitution"),
        };
        Ok(mk(name, op, colon, index))
    }

    /// A word ending at the first of `ends` (not consumed).
    fn word_until(&mut self, ends: &[u8]) -> Result<Word> {
        // Find the first unquoted end byte at nesting depth zero.
        let mut i = self.pos;
        let mut depth = 0;
        while i < self.s.len() {
            match self.s[i] {
                b'\\' => i += 1,
                b'{' => depth += 1,
                b'}' if depth > 0 => depth -= 1,
                c if depth == 0 && ends.contains(&c) => break,
                _ => {}
            }
            i += 1;
        }
        if i >= self.s.len() {
            return Err(ParseError::Incomplete);
        }
        let end_byte = self.s[i];
        self.word(Some(end_byte))
    }

    fn backquote(&mut self) -> Result<WordPart> {
        // The text up to the next unescaped backquote, with \` \\ \$ unescaped.
        let mut i = self.pos + 1;
        let mut text = Vec::new();
        loop {
            match self.s.get(i) {
                None => {
                    self.pos = self.s.len();
                    return Err(ParseError::Incomplete);
                }
                Some(b'`') => break,
                Some(b'\\') => {
                    match self.s.get(i + 1) {
                        Some(&n @ (b'`' | b'\\' | b'$')) => text.push(n),
                        Some(&n) => {
                            text.push(b'\\');
                            text.push(n);
                        }
                        None => {
                            self.pos = self.s.len();
                            return Err(ParseError::Incomplete);
                        }
                    }
                    i += 2;
                    continue;
                }
                Some(&c) => text.push(c),
            }
            i += 1;
        }
        let start = self.pos;
        self.pos = i + 1;
        let mut sub = self.sub_parser(&text, start);
        let prog = sub.program()?;
        Ok(WordPart::CmdSub(Rc::new(prog), true))
    }

    /// Read pending here-document bodies (after a newline).
    fn read_heredocs(&mut self) -> Result<()> {
        let pending = core::mem::take(&mut self.heredocs);
        for (delim, quoted, strip, body) in pending {
            let mut text: Vec<u8> = Vec::new();
            loop {
                if self.pos >= self.s.len() {
                    return Err(ParseError::Incomplete);
                }
                let end = self.s[self.pos..].iter().position(|&c| c == b'\n').map_or(self.s.len(), |i| self.pos + i);
                let mut line = &self.s[self.pos..end];
                if strip {
                    while line.first() == Some(&b'\t') {
                        line = &line[1..];
                    }
                }
                let at_eof = end >= self.s.len();
                if line == delim.as_slice() {
                    self.pos = (end + 1).min(self.s.len());
                    break;
                }
                text.extend_from_slice(line);
                text.push(b'\n');
                self.pos = end + 1;
                if at_eof {
                    return Err(ParseError::Incomplete);
                }
            }
            let w = if quoted { alloc::vec![WordPart::Quoted(text.clone())] } else { heredoc_word(&text)? };
            let mut b = body.borrow_mut();
            b.body = w;
            b.filled = true;
            b.raw = text;
        }
        Ok(())
    }

    // --- grammar ------------------------------------------------------------

    fn is_reserved(t: &Token, words: &[&[u8]]) -> bool {
        match t {
            Token::Word(w) => literal(w).is_some_and(|l| words.contains(&l)),
            _ => false,
        }
    }

    fn skip_newlines(&mut self) -> Result<()> {
        while *self.peek()? == Token::Newline {
            self.next()?;
        }
        Ok(())
    }

    fn expect_word(&mut self, w: &[u8]) -> Result<()> {
        self.skip_newlines()?;
        let t = self.next()?;
        if Self::is_reserved(&t, &[w]) {
            Ok(())
        } else if t == Token::Eof {
            Err(ParseError::Incomplete)
        } else {
            Err(ParseError::Syntax(alloc::format!("syntax error: expected '{}'", String::from_utf8_lossy(w))))
        }
    }

    /// A compound list, until one of the reserved words `ends` (or `)`,
    /// `;;`-style tokens, or the end).
    fn list(&mut self, ends: &[&[u8]]) -> Result<Program> {
        let mut items = Vec::new();
        loop {
            self.skip_newlines()?;
            let t = self.peek()?.clone();
            match &t {
                Token::Eof => break,
                Token::Op(o) if matches!(*o, ")" | ";;" | ";&" | ";;&") => break,
                Token::Op(o)
                    if *o != "("
                        && *o != "<"
                        && *o != ">"
                        && *o != "<<"
                        && *o != ">>"
                        && *o != "<&"
                        && *o != ">&"
                        && *o != "<>"
                        && *o != ">|"
                        && *o != "&>"
                        && *o != "&>>"
                        && *o != "<<<" =>
                {
                    return Err(ParseError::Syntax(alloc::format!("syntax error near unexpected token '{o}'")));
                }
                _ if Self::is_reserved(&t, ends) => break,
                _ if Self::is_reserved(
                    &t,
                    &[b"then", b"else", b"elif", b"fi", b"do", b"done", b"esac", b"}", b"in"],
                ) =>
                {
                    break;
                }
                _ => {}
            }
            let cmd = self.and_or()?;
            let mut background = false;
            match self.peek()? {
                Token::Op("&") => {
                    self.next()?;
                    background = true;
                }
                Token::Op(";") | Token::Newline => {
                    self.next()?;
                }
                _ => {}
            }
            items.push((cmd, background));
        }
        Ok(Program(items))
    }

    fn and_or(&mut self) -> Result<Command> {
        let mut left = self.pipeline()?;
        loop {
            let op = match self.peek()? {
                Token::Op("&&") => true,
                Token::Op("||") => false,
                _ => return Ok(left),
            };
            self.next()?;
            self.skip_newlines()?;
            let right = self.pipeline()?;
            left = if op { Command::And(left.into(), right.into()) } else { Command::Or(left.into(), right.into()) };
        }
    }

    fn pipeline(&mut self) -> Result<Command> {
        // `time [-p] pipeline` (bash); `time` alone times nothing.
        if Self::is_reserved(self.peek()?, &[b"time"]) {
            self.next()?;
            let mut posix = false;
            if let Token::Word(w) = self.peek()?
                && literal(w) == Some(b"-p")
            {
                self.next()?;
                posix = true;
            }
            let cmd = match self.peek()? {
                Token::Newline | Token::Eof | Token::Op(";" | "&" | "&&" | "||" | ")" | ";;") => None,
                _ => Some(alloc::boxed::Box::new(self.pipeline()?)),
            };
            return Ok(Command::Time { posix, cmd });
        }
        let mut bang = false;
        while Self::is_reserved(self.peek()?, &[b"!"]) {
            self.next()?;
            bang = !bang;
        }
        let mut cmds = alloc::vec![self.command()?];
        loop {
            match self.peek()? {
                Token::Op("|") => {}
                Token::Op("|&") => {
                    // cmd |& next = cmd 2>&1 | next.
                    if let Some(Command::Simple { redirs, .. }) = cmds.last_mut() {
                        redirs.push(Redir {
                            fd: Some(2),
                            kind: RedirKind::DupOut,
                            target: alloc::vec![WordPart::Lit(b"1".to_vec())],
                            heredoc: None,
                        });
                    }
                }
                _ => break,
            }
            self.next()?;
            self.skip_newlines()?;
            cmds.push(self.command()?);
        }
        if cmds.len() == 1 && !bang {
            return Ok(cmds.pop().unwrap());
        }
        Ok(Command::Pipeline { bang, cmds })
    }

    fn redirection(&mut self, fd: Option<i32>) -> Result<Redir> {
        let Token::Op(op) = self.next()? else { return self.err("expected a redirection") };
        let kind = match op {
            "<" => RedirKind::In,
            ">" => RedirKind::Out,
            ">|" => RedirKind::Clobber,
            ">>" => RedirKind::Append,
            "<>" => RedirKind::ReadWrite,
            "<&" => RedirKind::DupIn,
            ">&" => RedirKind::DupOut,
            "<<" | "<<-" => RedirKind::HereDoc,
            "<<<" => RedirKind::HereString,
            "&>" => RedirKind::OutErr,
            "&>>" => RedirKind::AppendErr,
            _ => return self.err("bad redirection"),
        };
        let target = match self.next()? {
            Token::Word(w) => w,
            Token::Eof => return Err(ParseError::Incomplete),
            _ => return self.err("syntax error near redirection"),
        };
        let mut heredoc = None;
        if kind == RedirKind::HereDoc {
            let quoted = target.iter().any(|p| !matches!(p, WordPart::Lit(_)));
            let delim = crate::expand::word_text(&target);
            let body = Rc::new(RefCell::new(HereBody {
                body: Vec::new(),
                filled: false,
                raw: Vec::new(),
                strip: op == "<<-",
            }));
            self.heredocs.push((delim, quoted, op == "<<-", body.clone()));
            heredoc = Some(body);
        }
        Ok(Redir { fd, kind, target, heredoc })
    }

    fn redir_token(t: &Token) -> bool {
        matches!(t, Token::IoNumber(_))
            || matches!(t, Token::Op(o) if matches!(*o, "<" | ">" | ">|" | ">>" | "<>" | "<&" | ">&" | "<<" | "<<-" | "<<<" | "&>" | "&>>"))
    }

    /// Redirections after a compound command.
    fn trailing_redirs(&mut self) -> Result<Vec<Redir>> {
        let mut v = Vec::new();
        loop {
            let t = self.peek()?.clone();
            if !Self::redir_token(&t) {
                return Ok(v);
            }
            let fd = if let Token::IoNumber(n) = t {
                self.next()?;
                Some(n)
            } else {
                None
            };
            v.push(self.redirection(fd)?);
        }
    }

    fn command(&mut self) -> Result<Command> {
        let t = self.peek()?.clone();
        if let Token::Word(w) = &t
            && let Some(l) = literal(w)
        {
            match l {
                b"if" => return self.if_clause(),
                b"while" | b"until" => return self.loop_clause(l == b"until"),
                b"for" => return self.for_clause(false),
                b"select" => return self.for_clause(true),
                b"coproc" => return self.coproc(),
                b"case" => return self.case_clause(),
                b"{" => {
                    self.next()?;
                    let body = self.list(&[b"}"])?;
                    self.expect_word(b"}")?;
                    let r = self.trailing_redirs()?;
                    return Ok(Command::Group(body, r));
                }
                b"[[" => return self.cond_command(),
                b"function" => {
                    self.next()?;
                    let Token::Word(n) = self.next()? else { return self.err("expected a function name") };
                    let name = crate::expand::word_text(&n);
                    if *self.peek()? == Token::Op("(") {
                        self.next()?;
                        if self.next()? != Token::Op(")") {
                            return self.err("expected ')'");
                        }
                    }
                    self.skip_newlines()?;
                    let body = self.command()?;
                    return Ok(Command::FuncDef { name, body: Rc::new(body) });
                }
                _ => {}
            }
        }
        if t == Token::Op("(") {
            self.next()?;
            // (( arithmetic )) as a command.
            if self.at(0) == Some(b'(') {
                let start = self.pos + 1;
                if let Some(end) = find_double_close(&self.s, start, false) {
                    let line = self.line_at(start);
                    let text = self.s[start..end].to_vec();
                    self.pos = end + 2;
                    let mut sub = Parser::new(&text);
                    let w = sub.word(Some(0))?;
                    let r = self.trailing_redirs()?;
                    return Ok(Command::Arith(w, r, line));
                }
            }
            let body = self.list(&[])?;
            match self.next()? {
                Token::Op(")") => {}
                Token::Eof => return Err(ParseError::Incomplete),
                _ => return self.err("expected ')'"),
            }
            let r = self.trailing_redirs()?;
            return Ok(Command::Subshell(body, r));
        }
        self.simple()
    }

    fn simple(&mut self) -> Result<Command> {
        let line = self.next_line()?;
        let mut assigns = Vec::new();
        let mut words: Vec<Word> = Vec::new();
        let mut redirs = Vec::new();
        loop {
            let t = self.peek()?.clone();
            match t {
                Token::IoNumber(n) => {
                    self.next()?;
                    redirs.push(self.redirection(Some(n))?);
                }
                ref r if Self::redir_token(r) => redirs.push(self.redirection(None)?),
                Token::Word(w) => {
                    // A function definition: NAME ( ) body.
                    if words.is_empty()
                        && assigns.is_empty()
                        && let Some(name) = literal(&w).filter(|n| is_name(n) || n.iter().all(|c| !Parser::is_meta(*c)))
                    {
                        let name = name.to_vec();
                        let save = self.peeked.as_ref().map_or(self.pos, |p| p.1);
                        self.next()?;
                        self.skip_blanks();
                        if self.at(0) == Some(b'(') {
                            let mut j = self.pos + 1;
                            while matches!(self.s.get(j), Some(b' ' | b'\t')) {
                                j += 1;
                            }
                            if self.s.get(j) == Some(&b')') {
                                self.pos = j + 1;
                                self.skip_newlines()?;
                                let body = self.command()?;
                                return Ok(Command::FuncDef { name, body: Rc::new(body) });
                            }
                        }
                        self.pos = save;
                        self.peeked = None;
                        self.peek()?;
                        // Alias expansion of the command word.
                        if self.try_alias(&name)? {
                            continue;
                        }
                    }
                    self.next()?;
                    if words.is_empty()
                        && let Some(a) = split_assign(&w)
                    {
                        assigns.push(a);
                        continue;
                    }
                    words.push(w);
                }
                _ => break,
            }
        }
        if words.is_empty() && assigns.is_empty() && redirs.is_empty() {
            return match self.peek()? {
                Token::Eof => Err(ParseError::Incomplete),
                Token::Op(o) => Err(ParseError::Syntax(alloc::format!("syntax error near unexpected token '{o}'"))),
                Token::Newline => Err(ParseError::Syntax(String::from("syntax error near unexpected newline"))),
                Token::Word(w) => Err(ParseError::Syntax(alloc::format!(
                    "syntax error near unexpected token '{}'",
                    String::from_utf8_lossy(&crate::expand::word_text(w))
                ))),
                _ => Err(ParseError::Syntax(String::from("syntax error"))),
            };
        }
        Ok(Command::Simple { assigns, words, redirs, line })
    }

    /// `coproc [NAME] command`: a name only before a compound command.
    fn coproc(&mut self) -> Result<Command> {
        self.next()?;
        let mut name = b"COPROC".to_vec();
        let save = self.peeked.as_ref().map_or(self.pos, |p| p.1);
        if let Token::Word(w) = self.peek()?.clone()
            && let Some(n) = literal(&w).filter(|n| is_name(n))
            && !Self::is_reserved(self.peek()?, &[b"{", b"while", b"until", b"if", b"for", b"case", b"select"])
        {
            let n = n.to_vec();
            self.next()?;
            let t = self.peek()?.clone();
            let compound = t == Token::Op("(")
                || Self::is_reserved(&t, &[b"{", b"while", b"until", b"if", b"for", b"case", b"select", b"[["]);
            if compound {
                name = n;
            } else {
                self.pos = save;
                self.peeked = None;
            }
        }
        let body = self.command()?;
        Ok(Command::Coproc { name, body: Rc::new(body) })
    }

    /// Replace an alias at the current token with its value (re-lexed).
    fn try_alias(&mut self, name: &[u8]) -> Result<bool> {
        let Some(value) = self.aliases.get(name).cloned() else { return Ok(false) };
        if self.expanding.iter().any(|(_, n)| n == name) {
            return Ok(false);
        }
        let Some((_, start)) = self.peeked.take() else { return Ok(false) };
        let end = self.pos;
        let mut new = self.s[..start].to_vec();
        new.extend_from_slice(&value);
        let value_end = new.len();
        new.extend_from_slice(&self.s[end..]);
        let delta = value_end as isize - end as isize;
        for e in &mut self.expanding {
            e.0 = (e.0 as isize + delta) as usize;
        }
        self.s = new;
        self.pos = start;
        self.expanding.push((value_end, name.to_vec()));
        Ok(true)
    }

    fn if_clause(&mut self) -> Result<Command> {
        self.next()?;
        let mut arms = Vec::new();
        let mut otherwise = None;
        loop {
            let cond = self.list(&[b"then"])?;
            self.expect_word(b"then")?;
            let body = self.list(&[b"elif", b"else", b"fi"])?;
            arms.push((cond, body));
            self.skip_newlines()?;
            let t = self.next()?;
            if Self::is_reserved(&t, &[b"elif"]) {
                continue;
            }
            if Self::is_reserved(&t, &[b"else"]) {
                otherwise = Some(self.list(&[b"fi"])?);
                self.expect_word(b"fi")?;
                break;
            }
            if Self::is_reserved(&t, &[b"fi"]) {
                break;
            }
            return if t == Token::Eof { Err(ParseError::Incomplete) } else { self.err("syntax error: expected 'fi'") };
        }
        let redirs = self.trailing_redirs()?;
        Ok(Command::If { arms, otherwise, redirs })
    }

    fn loop_clause(&mut self, until: bool) -> Result<Command> {
        self.next()?;
        let cond = self.list(&[b"do"])?;
        self.expect_word(b"do")?;
        let body = self.list(&[b"done"])?;
        self.expect_word(b"done")?;
        let redirs = self.trailing_redirs()?;
        Ok(Command::Loop { until, cond, body, redirs })
    }

    /// `for` and `select` (whose grammar is the same).
    fn for_clause(&mut self, select: bool) -> Result<Command> {
        let line = self.next_line()?;
        self.next()?;
        if !select && *self.peek()? == Token::Op("(") && self.at(0) == Some(b'(') {
            return self.arith_for(line);
        }
        let var = match self.next()? {
            Token::Word(w) => match literal(&w) {
                Some(n) if is_name(n) => n.to_vec(),
                _ => return self.err("bad for loop variable"),
            },
            Token::Eof => return Err(ParseError::Incomplete),
            _ => return self.err("bad for loop variable"),
        };
        let mut words = None;
        // Optional newlines, then `in words... ;` or `;`/`do` directly.
        self.skip_newlines()?;
        if Self::is_reserved(self.peek()?, &[b"in"]) {
            self.next()?;
            let mut ws = Vec::new();
            loop {
                match self.peek()? {
                    Token::Word(_) => {
                        if let Token::Word(w) = self.next()? {
                            ws.push(w);
                        }
                    }
                    Token::Op(";") | Token::Newline => {
                        self.next()?;
                        break;
                    }
                    Token::Eof => return Err(ParseError::Incomplete),
                    _ => return self.err("syntax error in for loop"),
                }
            }
            words = Some(ws);
        } else if *self.peek()? == Token::Op(";") {
            self.next()?;
        }
        let body = self.loop_body()?;
        let redirs = self.trailing_redirs()?;
        if select {
            return Ok(Command::Select { var, words, body, redirs, line });
        }
        Ok(Command::For { var, words, body, redirs, line })
    }

    /// A loop's `do list done`, or (bash, for `for` and `select`) a group.
    fn loop_body(&mut self) -> Result<Program> {
        self.skip_newlines()?;
        if Self::is_reserved(self.peek()?, &[b"{"]) {
            self.next()?;
            let body = self.list(&[b"}"])?;
            self.expect_word(b"}")?;
            return Ok(body);
        }
        self.expect_word(b"do")?;
        let body = self.list(&[b"done"])?;
        self.expect_word(b"done")?;
        Ok(body)
    }

    /// `for ((init; cond; step))` after `for`, at its first `(`.
    fn arith_for(&mut self, line: usize) -> Result<Command> {
        self.next()?;
        let start = self.pos + 1;
        let Some(end) = find_double_close(&self.s, start, true) else {
            return if self.s[start..].contains(&b')') {
                self.err("syntax error in arithmetic for loop")
            } else {
                Err(ParseError::Incomplete)
            };
        };
        let text = self.s[start..end].to_vec();
        self.pos = end + 2;
        let parts: Vec<&[u8]> = text.split(|&c| c == b';').collect();
        if parts.len() != 3 {
            return self.err("syntax error: arithmetic expression required");
        }
        let mut exprs: [Word; 3] = Default::default();
        for (e, t) in exprs.iter_mut().zip(parts) {
            *e = Parser::new(t).word(Some(0))?;
        }
        // An optional `;` or newlines, then the body.
        if *self.peek()? == Token::Op(";") {
            self.next()?;
        }
        let body = self.loop_body()?;
        let redirs = self.trailing_redirs()?;
        Ok(Command::ArithFor { exprs, body, redirs, line })
    }

    fn case_clause(&mut self) -> Result<Command> {
        let line = self.next_line()?;
        self.next()?;
        let word = match self.next()? {
            Token::Word(w) => w,
            Token::Eof => return Err(ParseError::Incomplete),
            _ => return self.err("syntax error in case"),
        };
        self.expect_word(b"in")?;
        let mut arms = Vec::new();
        loop {
            self.skip_newlines()?;
            if Self::is_reserved(self.peek()?, &[b"esac"]) {
                self.next()?;
                break;
            }
            if *self.peek()? == Token::Op("(") {
                self.next()?;
            }
            let mut patterns = Vec::new();
            loop {
                match self.next()? {
                    Token::Word(w) => patterns.push(w),
                    Token::Eof => return Err(ParseError::Incomplete),
                    _ => return self.err("syntax error in case pattern"),
                }
                match self.next()? {
                    Token::Op("|") => continue,
                    Token::Op(")") => break,
                    Token::Eof => return Err(ParseError::Incomplete),
                    _ => return self.err("syntax error in case pattern"),
                }
            }
            let body = self.list(&[b"esac"])?;
            let end = match self.peek()? {
                Token::Op(";;") => CaseEnd::Break,
                Token::Op(";&") => CaseEnd::FallThrough,
                Token::Op(";;&") => CaseEnd::Continue,
                _ => {
                    // The last arm may omit ;;.
                    arms.push(CaseArm { patterns, body, end: CaseEnd::Break });
                    self.expect_word(b"esac")?;
                    break;
                }
            };
            self.next()?;
            arms.push(CaseArm { patterns, body, end });
        }
        let redirs = self.trailing_redirs()?;
        Ok(Command::Case { word, arms, redirs, line })
    }

    // --- [[ ]] ------------------------------------------------------------

    fn cond_command(&mut self) -> Result<Command> {
        let line = self.next_line()?;
        self.next()?;
        self.in_cond = true;
        let c = self.cond_or();
        self.in_cond = false;
        let c = c?;
        let t = self.next()?;
        if !Self::is_reserved(&t, &[b"]]"]) {
            return if t == Token::Eof { Err(ParseError::Incomplete) } else { self.err("expected ']]'") };
        }
        let r = self.trailing_redirs()?;
        Ok(Command::Cond(c, r, line))
    }

    fn cond_or(&mut self) -> Result<Cond> {
        let mut l = self.cond_and()?;
        while *self.peek()? == Token::Op("||") {
            self.next()?;
            self.skip_newlines()?;
            let r = self.cond_and()?;
            l = Cond::Or(l.into(), r.into());
        }
        Ok(l)
    }

    fn cond_and(&mut self) -> Result<Cond> {
        let mut l = self.cond_not()?;
        while *self.peek()? == Token::Op("&&") {
            self.next()?;
            self.skip_newlines()?;
            let r = self.cond_not()?;
            l = Cond::And(l.into(), r.into());
        }
        Ok(l)
    }

    fn cond_not(&mut self) -> Result<Cond> {
        if Self::is_reserved(self.peek()?, &[b"!"]) {
            self.next()?;
            return Ok(Cond::Not(self.cond_not()?.into()));
        }
        self.cond_primary()
    }

    fn cond_word(&mut self) -> Result<Word> {
        self.skip_newlines()?;
        match self.next()? {
            Token::Word(w) => Ok(w),
            Token::Op(o @ ("<" | ">")) => Ok(alloc::vec![WordPart::Lit(o.as_bytes().to_vec())]),
            Token::Eof => Err(ParseError::Incomplete),
            _ => self.err("syntax error in conditional expression"),
        }
    }

    fn cond_primary(&mut self) -> Result<Cond> {
        self.skip_newlines()?;
        if *self.peek()? == Token::Op("(") {
            self.next()?;
            let c = self.cond_or()?;
            if self.next()? != Token::Op(")") {
                return self.err("expected ')'");
            }
            return Ok(Cond::Paren(c.into()));
        }
        let first = self.cond_word()?;
        if let Some(op) = literal(&first)
            && op.len() == 2
            && op[0] == b'-'
            && !matches!(self.peek()?, Token::Op(_))
            && !Self::is_reserved(self.peek()?, &[b"]]"])
        {
            // A unary test, unless what follows is a binary operator.
            let op = op.to_vec();
            let operand = self.cond_word()?;
            let next_is_binop = match self.peek()? {
                Token::Word(w) => literal(w).is_some_and(is_cond_binop),
                Token::Op("<" | ">") => true,
                _ => false,
            };
            if !next_is_binop {
                return Ok(Cond::Unary(op, operand));
            }
            // It was "-x OP y" with -x as a string.
            let binop = self.cond_binop()?;
            let right = self.cond_word()?;
            let _ = operand;
            return Ok(Cond::Binary(first, binop, right));
        }
        let binop = match self.peek()? {
            Token::Word(w) if literal(w).is_some_and(is_cond_binop) => true,
            Token::Op("<" | ">") => true,
            _ => false,
        };
        if binop {
            let op = self.cond_binop()?;
            // The right side of =~ is read up to the next unquoted blank,
            // so ( ) | belong to the regular expression.
            let right = if op == b"=~" { self.cond_regex()? } else { self.cond_word()? };
            return Ok(Cond::Binary(first, op, right));
        }
        Ok(Cond::Word(first))
    }

    fn cond_regex(&mut self) -> Result<Word> {
        self.skip_blanks();
        let mut w: Word = Vec::new();
        let mut depth = 0usize;
        loop {
            match self.at(0) {
                None => break,
                Some(b' ' | b'\t' | b'\n' | b';' | b'&') if depth == 0 => break,
                Some(c @ (b'(' | b')' | b'|' | b'<' | b'>' | b'&' | b';' | b' ' | b'\t')) => {
                    if c == b'(' {
                        depth += 1;
                    } else if c == b')' {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    w.push(WordPart::Lit(alloc::vec![c]));
                    self.pos += 1;
                }
                Some(_) => {
                    let start = self.pos;
                    let part = self.word(None)?;
                    if self.pos == start {
                        break;
                    }
                    w.extend(part);
                }
            }
        }
        if w.is_empty() {
            return self.err("expected a regular expression");
        }
        Ok(w)
    }

    fn cond_binop(&mut self) -> Result<Vec<u8>> {
        match self.next()? {
            Token::Word(w) => Ok(literal(&w).unwrap_or_default().to_vec()),
            Token::Op(o) => Ok(o.as_bytes().to_vec()),
            _ => self.err("expected an operator"),
        }
    }
}

fn is_cond_binop(op: &[u8]) -> bool {
    matches!(
        op,
        b"=" | b"==" | b"!=" | b"=~" | b"-eq" | b"-ne" | b"-lt" | b"-le" | b"-gt" | b"-ge" | b"-nt" | b"-ot" | b"-ef"
    )
}

fn param(name: Vec<u8>, op: ParamOp) -> WordPart {
    WordPart::Param(alloc::boxed::Box::new(Param {
        name,
        op,
        colon: false,
        index: None,
        indirect: false,
        braced: false,
    }))
}

/// Whether the literal text before a `(` is `name=` or `name+=`.
fn is_array_head(lit: &[u8]) -> bool {
    let head = lit.strip_suffix(b"=").map(|h| h.strip_suffix(b"+").unwrap_or(h));
    head.is_some_and(is_name)
}

/// A word as an assignment (`name=`, `name+=`, `name[sub]=`, `name[sub]+=`
/// at its start), or None.
pub fn split_assign(w: &Word) -> Option<Assign> {
    let WordPart::Lit(first) = w.first()? else { return None };
    let n = first.iter().take_while(|c| c.is_ascii_alphanumeric() || **c == b'_').count();
    if n == 0 || first[0].is_ascii_digit() {
        return None;
    }
    let name = first[..n].to_vec();
    let rest = &first[n..];
    let value_of = |lit: &[u8], more: &[WordPart]| -> Word {
        let mut v: Word = Vec::new();
        if !lit.is_empty() {
            v.push(WordPart::Lit(lit.to_vec()));
        }
        v.extend(more.iter().cloned());
        v
    };
    if let Some(r) = rest.strip_prefix(b"=") {
        return Some(Assign { name, index: None, append: false, value: value_of(r, &w[1..]) });
    }
    if let Some(r) = rest.strip_prefix(b"+=") {
        return Some(Assign { name, index: None, append: true, value: value_of(r, &w[1..]) });
    }
    if rest.first() != Some(&b'[') {
        return None;
    }
    let (index, after, part) = subscript_end(w, 0, n + 1)?;
    let WordPart::Lit(l) = &w[part] else { return None };
    let tail = &l[after..];
    let (append, r) = match (tail.strip_prefix(b"="), tail.strip_prefix(b"+=")) {
        (Some(r), _) => (false, r),
        (None, Some(r)) => (true, r),
        _ => return None,
    };
    Some(Assign { name, index: Some(index), append, value: value_of(r, &w[part + 1..]) })
}

/// The subscript of a word from part `part`, byte `off` (just after a
/// `[`) to its matching `]` in a literal part: the subscript, and where
/// the text after the `]` starts (byte, part).
pub fn subscript_end(w: &Word, part: usize, off: usize) -> Option<(Word, usize, usize)> {
    let mut index: Word = Vec::new();
    let mut depth = 0;
    let mut start = off;
    for (k, p) in w.iter().enumerate().skip(part) {
        match p {
            WordPart::Lit(l) => {
                let from = if k == part { start } else { 0 };
                for (j, &c) in l.iter().enumerate().skip(from) {
                    match c {
                        b'[' => depth += 1,
                        b']' if depth == 0 => {
                            if j > from {
                                index.push(WordPart::Lit(l[from..j].to_vec()));
                            }
                            return Some((index, j + 1, k));
                        }
                        b']' => depth -= 1,
                        _ => {}
                    }
                }
                if l.len() > from {
                    index.push(WordPart::Lit(l[from..].to_vec()));
                }
                start = 0;
            }
            other => index.push(other.clone()),
        }
    }
    None
}

fn simple_op(c: u8, w: Word) -> ParamOp {
    match c {
        b'-' => ParamOp::Default(w),
        b'=' => ParamOp::Assign(w),
        b'?' => ParamOp::Error(w),
        _ => ParamOp::Alt(w),
    }
}

/// The end of `((...))` content starting at `start`: the index of the
/// first `)` of the closing `))` at depth zero. `for ((...))` takes
/// semicolons and newlines inside (`lists`).
fn find_double_close(s: &[u8], start: usize, lists: bool) -> Option<usize> {
    let mut depth = 0;
    let mut i = start;
    while i < s.len() {
        match s[i] {
            b'(' => depth += 1,
            b')' if depth == 0 => return (s.get(i + 1) == Some(&b')')).then_some(i),
            b')' => depth -= 1,
            b'\n' | b';' if depth == 0 && !lists => return None,
            _ => {}
        }
        i += 1;
    }
    None
}

/// A here-document body with expansions: `$`, backquotes and backslash
/// escapes of `$ \` \\ newline` work; quotes are ordinary characters.
/// Also used for prompts.
pub fn heredoc_word(text: &[u8]) -> Result<Word> {
    let mut p = Parser::new(text);
    let mut parts = Vec::new();
    let mut lit = Vec::new();
    while let Some(c) = p.at(0) {
        match c {
            b'\\' if matches!(p.at(1), Some(b'$' | b'`' | b'\\')) => {
                lit.push(p.at(1).unwrap());
                p.pos += 2;
            }
            b'\\' if p.at(1) == Some(b'\n') => p.pos += 2,
            b'$' => match p.dollar(true)? {
                Some(part) => {
                    if !lit.is_empty() {
                        parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                    }
                    parts.push(part);
                }
                None => {
                    lit.push(b'$');
                    p.pos += 1;
                }
            },
            b'`' => {
                if !lit.is_empty() {
                    parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                }
                parts.push(p.backquote()?);
            }
            _ => {
                lit.push(c);
                p.pos += 1;
            }
        }
    }
    if !lit.is_empty() {
        parts.push(WordPart::Quoted(lit));
    }
    Ok(alloc::vec![WordPart::DQuote(parts)])
}

pub fn parse(s: &[u8]) -> Result<Program> {
    Parser::new(s).program()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(s: &str) -> Word {
        alloc::vec![WordPart::Lit(s.as_bytes().to_vec())]
    }

    #[test]
    fn simple_commands_and_lists() {
        let p = parse(b"echo a b; ls -l && pwd || true &").unwrap();
        assert_eq!(p.0.len(), 2);
        assert!(p.0[1].1);
        match &p.0[0].0 {
            Command::Simple { words, .. } => assert_eq!(words, &alloc::vec![lit("echo"), lit("a"), lit("b")]),
            c => panic!("{c:?}"),
        }
    }

    #[test]
    fn quoting_and_expansions() {
        let p = parse(b"echo 'a b' \"x $HOME ${y:-z}\" \\$ $(date) `id` $((1+2))").unwrap();
        let Command::Simple { words, .. } = &p.0[0].0 else { panic!() };
        assert_eq!(words[1], alloc::vec![WordPart::Quoted(b"a b".to_vec())]);
        assert!(matches!(&words[2][0], WordPart::DQuote(v) if v.len() == 4));
        assert_eq!(words[3], alloc::vec![WordPart::Escaped(b'$')]);
        assert!(matches!(words[4][0], WordPart::CmdSub(..)));
        assert!(matches!(words[5][0], WordPart::CmdSub(..)));
        assert!(matches!(words[6][0], WordPart::Arith(_)));
    }

    #[test]
    fn compound_commands() {
        let src = b"if a; then b; elif c; then d; else e; fi\nwhile x; do y; done\nfor i in 1 2; do echo $i; done\ncase $x in a|b) one;; *) two;; esac\nf() { echo hi; }\n(cd /; ls) > out\n[[ -n $x && $y == a* ]]\n((i++))\n";
        let p = parse(src).unwrap();
        assert_eq!(p.0.len(), 8);
        assert!(matches!(p.0[0].0, Command::If { ref arms, otherwise: Some(_), .. } if arms.len() == 2));
        assert!(matches!(p.0[3].0, Command::Case { ref arms, .. } if arms.len() == 2));
        assert!(matches!(p.0[4].0, Command::FuncDef { .. }));
        assert!(matches!(p.0[5].0, Command::Subshell(_, ref r) if r.len() == 1));
        assert!(matches!(p.0[6].0, Command::Cond(Cond::And(..), _, _)));
        assert!(matches!(p.0[7].0, Command::Arith(..)));
    }

    #[test]
    fn heredocs_and_redirections() {
        let p = parse(b"cat <<EOF >out 2>&1\nhello $USER\nEOF\ncat <<'X'\n$literal\nX\n").unwrap();
        let Command::Simple { redirs, .. } = &p.0[0].0 else { panic!() };
        assert_eq!(redirs.len(), 3);
        assert!(redirs[0].heredoc.as_ref().unwrap().borrow().filled);
        assert_eq!(redirs[2].fd, Some(2));
        let Command::Simple { redirs, .. } = &p.0[1].0 else { panic!() };
        let b = redirs[0].heredoc.as_ref().unwrap().borrow();
        assert_eq!(b.body, alloc::vec![WordPart::Quoted(b"$literal\n".to_vec())]);
    }

    #[test]
    fn incomplete_input() {
        for s in [&b"if true; then"[..], b"echo 'abc", b"for i in a", b"cat <<E\nx\n", b"echo $(ls", b"f() {"] {
            assert_eq!(parse(s), Err(ParseError::Incomplete), "{}", String::from_utf8_lossy(s));
        }
        assert!(matches!(parse(b"echo )"), Err(ParseError::Syntax(_))));
        assert!(matches!(parse(b"fi"), Err(ParseError::Syntax(_))));
        assert!(matches!(Parser::new(b"echo ok\nfi\n").line(), Ok(Some(_))));
        let mut p = Parser::new(b"echo ok\nfi\n");
        p.line().unwrap();
        assert!(matches!(p.line(), Err(ParseError::Syntax(_))));
    }

    #[test]
    fn assignments_and_aliases() {
        let p = parse(b"A=1 B=$x cmd arg").unwrap();
        let Command::Simple { assigns, words, .. } = &p.0[0].0 else { panic!() };
        assert_eq!(assigns.len(), 2);
        assert_eq!(words.len(), 2);
        let mut al = BTreeMap::new();
        al.insert(b"ll".to_vec(), b"ls -l".to_vec());
        let mut p = Parser::new(b"ll /tmp");
        p.set_aliases(al);
        let p = p.program().unwrap();
        let Command::Simple { words, .. } = &p.0[0].0 else { panic!() };
        assert_eq!(words, &alloc::vec![lit("ls"), lit("-l"), lit("/tmp")]);
    }
}
