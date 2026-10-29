// SPDX-License-Identifier: MIT OR Apache-2.0

//! The awk grammar (XCU awk, "Grammar") into a syntax tree, with names
//! resolved to global and local slots.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use super::lex::{Lexer, Tok};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Var {
    Global(usize),
    Local(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpOp {
    Lt,
    Le,
    Eq,
    Ne,
    Gt,
    Ge,
}

#[derive(Debug)]
pub enum GetSrc {
    Main,
    File(Box<Expr>),
    Cmd(Box<Expr>),
}

#[derive(Debug)]
pub enum Expr {
    Num(f64),
    Str(Vec<u8>),
    /// A regex literal (index into the program's regex table); as a value
    /// it matches `$0`.
    Regex(usize),
    Var(Var),
    /// `a[i]`, and gawk's arrays of arrays `a[i][j]`: a subscript list per
    /// level.
    Index(Var, Vec<Vec<Expr>>),
    Field(Box<Expr>),
    /// `(i, j) in a`, or `in a[x]` (the path to a subarray).
    In(Vec<Expr>, Var, Vec<Vec<Expr>>),
    /// gawk's typed regexp constant `@/re/` (its pattern).
    TypedRegex(Vec<u8>),
    /// A long integer constant's digits (exact with `-M`).
    BigNum(Vec<u8>),
    Assign(Option<BinOp>, Box<Expr>, Box<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Cmp(CmpOp, Box<Expr>, Box<Expr>),
    Neg(Box<Expr>),
    Plus(Box<Expr>),
    Concat(Box<Expr>, Box<Expr>),
    Match(bool, Box<Expr>, Box<Expr>),
    IncDec {
        pre: bool,
        inc: bool,
        lv: Box<Expr>,
    },
    Builtin(&'static str, Vec<Expr>),
    Call(usize, Vec<Expr>),
    Getline {
        src: GetSrc,
        lv: Option<Box<Expr>>,
    },
    /// `(a, b)`: only valid as print's argument list or before `in`.
    Group(Vec<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redir {
    File,
    Append,
    Pipe,
}

/// A `case` label (gawk's switch): a constant or a regex.
#[derive(Debug)]
pub enum Case {
    Num(f64),
    Str(Vec<u8>),
    Regex(usize),
    Default,
}

#[derive(Debug)]
pub enum Stmt {
    Expr(Expr),
    Print(Vec<Expr>, Option<(Redir, Expr)>),
    Printf(Vec<Expr>, Option<(Redir, Expr)>),
    If(Expr, Box<Stmt>, Option<Box<Stmt>>),
    While(Expr, Box<Stmt>),
    Do(Box<Stmt>, Expr),
    For(Option<Box<Stmt>>, Option<Expr>, Option<Box<Stmt>>, Box<Stmt>),
    /// `for (k in a)`, or `in a[x]` (the path to a subarray).
    ForIn(Var, Var, Vec<Vec<Expr>>, Box<Stmt>),
    Block(Vec<Stmt>),
    Next,
    NextFile,
    Exit(Option<Expr>),
    Return(Option<Expr>),
    Break,
    Continue,
    /// `delete a` (an empty path) or `delete a[i]`, `a[i][j]`, ...
    Delete(Var, Vec<Vec<Expr>>),
    /// gawk's `switch`: cases in order, each with the statements up to
    /// the next label (control falls through to them).
    Switch(Expr, Vec<(Case, Vec<Stmt>)>),
}

#[derive(Debug)]
pub enum Pattern {
    All,
    Expr(Expr),
    Range(Expr, Expr),
}

#[derive(Debug)]
pub struct Rule {
    pub pattern: Pattern,
    pub action: Option<Vec<Stmt>>,
}

#[derive(Debug, Default)]
pub struct Func {
    pub name: Vec<u8>,
    pub params: Vec<Vec<u8>>,
    pub body: Vec<Stmt>,
    pub defined: bool,
    /// Parameters used as arrays.
    pub arrays: Vec<bool>,
}

#[derive(Debug, Default)]
pub struct Program {
    pub begin: Vec<Stmt>,
    pub end: Vec<Stmt>,
    /// gawk's BEGINFILE and ENDFILE rules, run around each input file.
    pub beginfile: Vec<Stmt>,
    pub endfile: Vec<Stmt>,
    pub rules: Vec<Rule>,
    pub funcs: Vec<Func>,
    pub globals: Vec<Vec<u8>>,
    pub regexes: Vec<Vec<u8>>,
    /// Extensions `@load` asked for.
    pub loaded: Vec<&'static str>,
}

/// Special variables, at fixed global slots.
pub const SPECIALS: &[&str] = &[
    "NR",
    "NF",
    "FNR",
    "FS",
    "OFS",
    "ORS",
    "RS",
    "FILENAME",
    "SUBSEP",
    "RSTART",
    "RLENGTH",
    "CONVFMT",
    "OFMT",
    "ENVIRON",
    "ARGC",
    "ARGV",
    "RT",
    "PROCINFO",
    "IGNORECASE",
    "FIELDWIDTHS",
    "FPAT",
    "ERRNO",
];

pub const NR: usize = 0;
pub const NF: usize = 1;
pub const FNR: usize = 2;
pub const FS: usize = 3;
pub const OFS: usize = 4;
pub const ORS: usize = 5;
pub const RS: usize = 6;
pub const FILENAME: usize = 7;
pub const SUBSEP: usize = 8;
pub const RSTART: usize = 9;
pub const RLENGTH: usize = 10;
pub const CONVFMT: usize = 11;
pub const OFMT: usize = 12;
pub const ENVIRON: usize = 13;
pub const ARGC: usize = 14;
pub const ARGV: usize = 15;
pub const RT: usize = 16;
pub const PROCINFO: usize = 17;
pub const IGNORECASE: usize = 18;
pub const FIELDWIDTHS: usize = 19;
pub const FPAT: usize = 20;
pub const ERRNO: usize = 21;

pub struct Parser<'a> {
    lx: Lexer<'a>,
    toks: VecDeque<Tok>,
    prog: Program,
    globals: BTreeMap<Vec<u8>, usize>,
    funcs: BTreeMap<Vec<u8>, usize>,
    /// The parameters of the function being parsed.
    locals: Option<Vec<Vec<u8>>>,
    /// `>` is a redirection here (print arguments outside parentheses).
    no_gt: bool,
    /// `in` is not an operator here (for (x in a)).
    no_in: bool,
}

pub type R<T> = Result<T, String>;

/// print's arguments and output redirection.
type PrintArgs = (Vec<Expr>, Option<(Redir, Expr)>);

impl<'a> Parser<'a> {
    pub fn new(src: &'a [u8]) -> Parser<'a> {
        let mut p = Parser {
            lx: Lexer::new(src),
            toks: VecDeque::new(),
            prog: Program::default(),
            globals: BTreeMap::new(),
            funcs: BTreeMap::new(),
            locals: None,
            no_gt: false,
            no_in: false,
        };
        for s in SPECIALS {
            p.global(s.as_bytes());
        }
        p
    }

    fn global(&mut self, name: &[u8]) -> usize {
        if let Some(&i) = self.globals.get(name) {
            return i;
        }
        let i = self.prog.globals.len();
        self.prog.globals.push(name.to_vec());
        self.globals.insert(name.to_vec(), i);
        i
    }

    fn var(&mut self, name: &[u8]) -> Var {
        if let Some(l) = &self.locals
            && let Some(i) = l.iter().position(|p| p == name)
        {
            return Var::Local(i);
        }
        Var::Global(self.global(name))
    }

    fn func(&mut self, name: &[u8]) -> usize {
        if let Some(&i) = self.funcs.get(name) {
            return i;
        }
        let i = self.prog.funcs.len();
        self.prog.funcs.push(Func { name: name.to_vec(), ..Func::default() });
        self.funcs.insert(name.to_vec(), i);
        i
    }

    fn peek_n(&mut self, n: usize) -> R<&Tok> {
        while self.toks.len() <= n {
            let t = self.lx.next()?;
            self.toks.push_back(t);
        }
        Ok(&self.toks[n])
    }

    fn peek(&mut self) -> R<&Tok> {
        self.peek_n(0)
    }

    fn next(&mut self) -> R<Tok> {
        self.peek()?;
        Ok(self.toks.pop_front().unwrap())
    }

    fn is(&mut self, t: &Tok) -> R<bool> {
        Ok(self.peek()? == t)
    }

    fn eat(&mut self, t: &Tok) -> R<bool> {
        if self.is(t)? {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn expect(&mut self, t: &Tok) -> R<()> {
        let got = self.next()?;
        if &got == t {
            return Ok(());
        }
        Err(alloc::format!("syntax error: expected {}, got {}", describe(t), describe(&got)))
    }

    fn opt_newlines(&mut self) -> R<()> {
        while self.eat(&Tok::Newline)? {}
        Ok(())
    }

    // --- program -----------------------------------------------------------

    pub fn program(mut self) -> R<Program> {
        loop {
            while matches!(self.peek()?, Tok::Newline | Tok::Op(";")) {
                self.next()?;
            }
            match self.peek()?.clone() {
                Tok::Eof => break,
                Tok::Kw("function" | "func") => self.function()?,
                Tok::Kw("BEGIN") => {
                    self.next()?;
                    self.opt_newlines()?;
                    let a = self.action()?;
                    self.prog.begin.extend(a);
                }
                Tok::Kw("END") => {
                    self.next()?;
                    self.opt_newlines()?;
                    let a = self.action()?;
                    self.prog.end.extend(a);
                }
                Tok::Kw(k @ ("BEGINFILE" | "ENDFILE")) => {
                    self.next()?;
                    self.opt_newlines()?;
                    let a = self.action()?;
                    if k == "BEGINFILE" { &mut self.prog.beginfile } else { &mut self.prog.endfile }.extend(a);
                }
                Tok::Op("{") => {
                    let a = self.action()?;
                    self.prog.rules.push(Rule { pattern: Pattern::All, action: Some(a) });
                }
                _ => {
                    let e = self.expr()?;
                    let pattern = if self.eat(&Tok::Op(","))? {
                        self.opt_newlines()?;
                        Pattern::Range(e, self.expr()?)
                    } else {
                        Pattern::Expr(e)
                    };
                    let action = if self.is(&Tok::Op("{"))? { Some(self.action()?) } else { None };
                    self.prog.rules.push(Rule { pattern, action });
                }
            }
        }
        for f in &self.prog.funcs {
            if !f.defined {
                return Err(alloc::format!("function `{}' called but never defined", String::from_utf8_lossy(&f.name)));
            }
        }
        let mut prog = self.prog;
        prog.loaded = self.lx.loaded.clone();
        array_params(&mut prog);
        Ok(prog)
    }

    fn function(&mut self) -> R<()> {
        self.next()?;
        let name = match self.next()? {
            Tok::Name(n) | Tok::FuncName(n) => n,
            t => return Err(alloc::format!("syntax error: bad function name {}", describe(&t))),
        };
        let idx = self.func(&name);
        if self.prog.funcs[idx].defined {
            return Err(alloc::format!("function `{}' previously defined", String::from_utf8_lossy(&name)));
        }
        self.expect(&Tok::Op("("))?;
        let mut params = Vec::new();
        loop {
            self.opt_newlines()?;
            match self.next()? {
                Tok::Op(")") => break,
                Tok::Name(n) => {
                    params.push(n);
                    self.opt_newlines()?;
                    if !self.eat(&Tok::Op(","))? {
                        self.expect(&Tok::Op(")"))?;
                        break;
                    }
                }
                t => return Err(alloc::format!("syntax error: unexpected {} in parameter list", describe(&t))),
            }
        }
        self.opt_newlines()?;
        self.locals = Some(params.clone());
        let body = self.action()?;
        self.locals = None;
        let f = &mut self.prog.funcs[idx];
        f.arrays = alloc::vec![false; params.len()];
        f.params = params;
        f.body = body;
        f.defined = true;
        Ok(())
    }

    fn action(&mut self) -> R<Vec<Stmt>> {
        self.expect(&Tok::Op("{"))?;
        let mut v = Vec::new();
        loop {
            while matches!(self.peek()?, Tok::Newline | Tok::Op(";")) {
                self.next()?;
            }
            if self.eat(&Tok::Op("}"))? {
                return Ok(v);
            }
            if self.is(&Tok::Eof)? {
                return Err(String::from("syntax error: unexpected end of program, expected `}'"));
            }
            v.push(self.stmt()?);
        }
    }

    // --- statements ----------------------------------------------------------

    /// After a simple statement: `;`, a newline, or (implicitly) `}`.
    fn terminator(&mut self) -> R<()> {
        match self.peek()? {
            Tok::Op(";") | Tok::Newline => {
                self.next()?;
                Ok(())
            }
            Tok::Op("}") | Tok::Eof => Ok(()),
            t => Err(alloc::format!("syntax error: unexpected {}", describe(&t.clone()))),
        }
    }

    fn stmt(&mut self) -> R<Stmt> {
        let t = self.peek()?.clone();
        match t {
            Tok::Op("{") => Ok(Stmt::Block(self.action()?)),
            Tok::Op(";") => {
                self.next()?;
                Ok(Stmt::Block(Vec::new()))
            }
            Tok::Kw("if") => {
                self.next()?;
                self.expect(&Tok::Op("("))?;
                let c = self.expr()?;
                self.expect(&Tok::Op(")"))?;
                self.opt_newlines()?;
                let then = self.stmt()?;
                // `else` may follow terminators.
                let mut k = 0;
                while matches!(self.peek_n(k)?, Tok::Newline | Tok::Op(";")) {
                    k += 1;
                }
                if *self.peek_n(k)? == Tok::Kw("else") {
                    for _ in 0..=k {
                        self.next()?;
                    }
                    self.opt_newlines()?;
                    let e = self.stmt()?;
                    return Ok(Stmt::If(c, Box::new(then), Some(Box::new(e))));
                }
                Ok(Stmt::If(c, Box::new(then), None))
            }
            Tok::Kw("while") => {
                self.next()?;
                self.expect(&Tok::Op("("))?;
                let c = self.expr()?;
                self.expect(&Tok::Op(")"))?;
                if self.eat(&Tok::Op(";"))? {
                    return Ok(Stmt::While(c, Box::new(Stmt::Block(Vec::new()))));
                }
                self.opt_newlines()?;
                let body = self.stmt()?;
                Ok(Stmt::While(c, Box::new(body)))
            }
            Tok::Kw("do") => {
                self.next()?;
                self.opt_newlines()?;
                let body = self.stmt()?;
                while matches!(self.peek()?, Tok::Newline | Tok::Op(";")) {
                    self.next()?;
                }
                if !self.eat(&Tok::Kw("while"))? {
                    return Err(String::from("syntax error: expected `while' after do body"));
                }
                self.expect(&Tok::Op("("))?;
                let c = self.expr()?;
                self.expect(&Tok::Op(")"))?;
                self.terminator()?;
                Ok(Stmt::Do(Box::new(body), c))
            }
            Tok::Kw("switch") => self.switch(),
            Tok::Kw("for") => {
                self.next()?;
                self.expect(&Tok::Op("("))?;
                if let (Tok::Name(v), Tok::Kw("in"), Tok::Name(a), Tok::Op(")" | "[")) =
                    (self.peek_n(0)?.clone(), self.peek_n(1)?.clone(), self.peek_n(2)?.clone(), self.peek_n(3)?.clone())
                {
                    for _ in 0..3 {
                        self.next()?;
                    }
                    let path = self.subscripts()?;
                    self.expect(&Tok::Op(")"))?;
                    self.opt_newlines()?;
                    let (v, a) = (self.var(&v), self.var(&a));
                    let body = self.stmt()?;
                    return Ok(Stmt::ForIn(v, a, path, Box::new(body)));
                }
                let init = if self.is(&Tok::Op(";"))? { None } else { Some(Box::new(self.simple_stmt()?)) };
                self.expect(&Tok::Op(";"))?;
                self.opt_newlines()?;
                let cond = if self.is(&Tok::Op(";"))? { None } else { Some(self.expr()?) };
                self.expect(&Tok::Op(";"))?;
                self.opt_newlines()?;
                let step = if self.is(&Tok::Op(")"))? { None } else { Some(Box::new(self.simple_stmt()?)) };
                self.expect(&Tok::Op(")"))?;
                if self.eat(&Tok::Op(";"))? {
                    return Ok(Stmt::For(init, cond, step, Box::new(Stmt::Block(Vec::new()))));
                }
                self.opt_newlines()?;
                let body = self.stmt()?;
                Ok(Stmt::For(init, cond, step, Box::new(body)))
            }
            _ => {
                let s = self.simple_stmt()?;
                self.terminator()?;
                Ok(s)
            }
        }
    }

    /// `switch (e) { case c: ... default: ... }` (gawk manual, "The switch
    /// Statement").
    fn switch(&mut self) -> R<Stmt> {
        self.next()?;
        self.expect(&Tok::Op("("))?;
        let e = self.expr()?;
        self.expect(&Tok::Op(")"))?;
        self.opt_newlines()?;
        self.expect(&Tok::Op("{"))?;
        let mut cases: Vec<(Case, Vec<Stmt>)> = Vec::new();
        loop {
            while matches!(self.peek()?, Tok::Newline | Tok::Op(";")) {
                self.next()?;
            }
            let label = match self.peek()? {
                Tok::Op("}") => {
                    self.next()?;
                    break;
                }
                Tok::Kw("default") => {
                    self.next()?;
                    if cases.iter().any(|(c, _)| matches!(c, Case::Default)) {
                        return Err(String::from("duplicate `default' detected in switch body"));
                    }
                    Case::Default
                }
                Tok::Kw("case") => {
                    self.next()?;
                    let negative = self.eat(&Tok::Op("-"))?;
                    match self.next()? {
                        Tok::Num(n) => Case::Num(if negative { -n } else { n }),
                        Tok::Str(s) if !negative => Case::Str(s),
                        Tok::Regex(r) | Tok::TypedRegex(r) if !negative => {
                            self.prog.regexes.push(r);
                            Case::Regex(self.prog.regexes.len() - 1)
                        }
                        t => return Err(alloc::format!("syntax error: unexpected {} after `case'", describe(&t))),
                    }
                }
                t => {
                    if cases.is_empty() {
                        return Err(alloc::format!("syntax error: unexpected {} in switch body", describe(&t.clone())));
                    }
                    let st = self.stmt()?;
                    cases.last_mut().expect("a case").1.push(st);
                    continue;
                }
            };
            // As in gawk, two labels that read the same are an error.
            let text = |c: &Case, p: &Program| match c {
                Case::Num(n) => Some(super::value::num_to_str(*n, b"%.6g")),
                Case::Str(s) => Some(s.clone()),
                Case::Regex(i) => Some(p.regexes[*i].clone()),
                Case::Default => None,
            };
            if let Some(t) = text(&label, &self.prog)
                && cases.iter().any(|(o, _)| text(o, &self.prog).as_ref() == Some(&t))
            {
                return Err(alloc::format!("duplicate case values in switch body: {}", String::from_utf8_lossy(&t)));
            }
            cases.push((label, Vec::new()));
            self.expect(&Tok::Op(":"))?;
        }
        Ok(Stmt::Switch(e, cases))
    }

    fn simple_stmt(&mut self) -> R<Stmt> {
        let t = self.peek()?.clone();
        Ok(match t {
            Tok::Kw("print") | Tok::Kw("printf") => {
                self.next()?;
                let (args, redir) = self.print_args()?;
                if t == Tok::Kw("print") {
                    Stmt::Print(args, redir)
                } else {
                    if args.is_empty() {
                        return Err(String::from("syntax error: printf: no format"));
                    }
                    Stmt::Printf(args, redir)
                }
            }
            Tok::Kw("delete") => {
                self.next()?;
                let Tok::Name(n) = self.next()? else {
                    return Err(String::from("syntax error: delete needs an array"));
                };
                let v = self.var(&n);
                Stmt::Delete(v, self.subscripts()?)
            }
            Tok::Kw("next") => {
                self.next()?;
                Stmt::Next
            }
            Tok::Kw("nextfile") => {
                self.next()?;
                Stmt::NextFile
            }
            Tok::Kw("break") => {
                self.next()?;
                Stmt::Break
            }
            Tok::Kw("continue") => {
                self.next()?;
                Stmt::Continue
            }
            Tok::Kw("exit") | Tok::Kw("return") => {
                self.next()?;
                let e = if matches!(self.peek()?, Tok::Op(";" | "}") | Tok::Newline | Tok::Eof) {
                    None
                } else {
                    Some(self.expr()?)
                };
                if t == Tok::Kw("exit") { Stmt::Exit(e) } else { Stmt::Return(e) }
            }
            _ => Stmt::Expr(self.expr()?),
        })
    }

    fn print_args(&mut self) -> R<PrintArgs> {
        let mut args = Vec::new();
        if !matches!(self.peek()?, Tok::Op(";" | "}" | ">" | ">>" | "|") | Tok::Newline | Tok::Eof) {
            let old = self.no_gt;
            self.no_gt = true;
            loop {
                args.push(self.expr()?);
                if !self.eat(&Tok::Op(","))? {
                    break;
                }
                self.opt_newlines()?;
            }
            self.no_gt = old;
            if args.len() == 1
                && let Some(Expr::Group(_)) = args.first()
            {
                let Some(Expr::Group(list)) = args.pop() else { unreachable!() };
                args = list;
            }
        }
        let redir = match self.peek()? {
            Tok::Op(">") => Some(Redir::File),
            Tok::Op(">>") => Some(Redir::Append),
            Tok::Op("|") => Some(Redir::Pipe),
            _ => None,
        };
        let redir = match redir {
            Some(r) => {
                self.next()?;
                let old = self.no_gt;
                self.no_gt = true;
                let target = self.concat()?;
                self.no_gt = old;
                Some((r, target))
            }
            None => None,
        };
        Ok((args, redir))
    }

    /// `[i]` lists, one per level (none: an empty path).
    fn subscripts(&mut self) -> R<Vec<Vec<Expr>>> {
        let mut path = Vec::new();
        while self.is(&Tok::Op("["))? {
            self.next()?;
            let subs = self.expr_list(&Tok::Op("]"))?;
            if subs.is_empty() {
                return Err(String::from("syntax error: empty subscript"));
            }
            path.push(subs);
        }
        Ok(path)
    }

    fn expr_list(&mut self, close: &Tok) -> R<Vec<Expr>> {
        let (old_gt, old_in) = (self.no_gt, self.no_in);
        self.no_gt = false;
        self.no_in = false;
        let mut v = Vec::new();
        self.opt_newlines()?;
        if !self.eat(close)? {
            loop {
                v.push(self.expr()?);
                self.opt_newlines()?;
                if self.eat(close)? {
                    break;
                }
                self.expect(&Tok::Op(","))?;
                self.opt_newlines()?;
            }
        }
        self.no_gt = old_gt;
        self.no_in = old_in;
        Ok(v)
    }

    // --- expressions ---------------------------------------------------------

    fn is_lvalue(e: &Expr) -> bool {
        matches!(e, Expr::Var(_) | Expr::Index(..) | Expr::Field(_))
    }

    pub fn expr(&mut self) -> R<Expr> {
        let lhs = self.ternary()?;
        let op = match self.peek()? {
            Tok::Op("=") => Some(None),
            Tok::Op("+=") => Some(Some(BinOp::Add)),
            Tok::Op("-=") => Some(Some(BinOp::Sub)),
            Tok::Op("*=") => Some(Some(BinOp::Mul)),
            Tok::Op("/=") => Some(Some(BinOp::Div)),
            Tok::Op("%=") => Some(Some(BinOp::Mod)),
            Tok::Op("^=" | "**=") => Some(Some(BinOp::Pow)),
            _ => None,
        };
        if let Some(op) = op
            && Self::is_lvalue(&lhs)
        {
            self.next()?;
            self.opt_newlines()?;
            let rhs = self.expr()?;
            return Ok(Expr::Assign(op, Box::new(lhs), Box::new(rhs)));
        }
        Ok(lhs)
    }

    fn ternary(&mut self) -> R<Expr> {
        let c = self.or()?;
        if self.eat(&Tok::Op("?"))? {
            self.opt_newlines()?;
            let a = self.expr()?;
            self.opt_newlines()?;
            self.expect(&Tok::Op(":"))?;
            self.opt_newlines()?;
            let b = self.expr()?;
            return Ok(Expr::Cond(Box::new(c), Box::new(a), Box::new(b)));
        }
        Ok(c)
    }

    fn or(&mut self) -> R<Expr> {
        let mut l = self.and()?;
        while self.eat(&Tok::Op("||"))? {
            self.opt_newlines()?;
            let r = self.and()?;
            l = Expr::Or(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn and(&mut self) -> R<Expr> {
        let mut l = self.in_expr()?;
        while self.eat(&Tok::Op("&&"))? {
            self.opt_newlines()?;
            let r = self.in_expr()?;
            l = Expr::And(Box::new(l), Box::new(r));
        }
        Ok(l)
    }

    fn in_expr(&mut self) -> R<Expr> {
        let mut l = self.match_expr()?;
        while !self.no_in && self.is(&Tok::Kw("in"))? {
            self.next()?;
            let Tok::Name(n) = self.next()? else { return Err(String::from("syntax error: `in' needs an array name")) };
            let v = self.var(&n);
            l = Expr::In(alloc::vec![l], v, self.subscripts()?);
        }
        Ok(l)
    }

    fn match_expr(&mut self) -> R<Expr> {
        let mut l = self.cmp()?;
        loop {
            let neg = match self.peek()? {
                Tok::Op("~") => false,
                Tok::Op("!~") => true,
                _ => return Ok(l),
            };
            self.next()?;
            let r = self.cmp()?;
            l = Expr::Match(neg, Box::new(l), Box::new(r));
        }
    }

    fn cmp(&mut self) -> R<Expr> {
        let l = self.concat()?;
        let no_gt = self.no_gt;
        let op = match self.peek()? {
            Tok::Op("<") => CmpOp::Lt,
            Tok::Op("<=") => CmpOp::Le,
            Tok::Op("==") => CmpOp::Eq,
            Tok::Op("!=") => CmpOp::Ne,
            Tok::Op(">") if !no_gt => CmpOp::Gt,
            Tok::Op(">=") => CmpOp::Ge,
            _ => return Ok(l),
        };
        self.next()?;
        let r = self.concat()?;
        Ok(Expr::Cmp(op, Box::new(l), Box::new(r)))
    }

    fn starts_operand(t: &Tok) -> bool {
        matches!(
            t,
            Tok::Num(_)
                | Tok::Str(_)
                | Tok::Regex(_)
                | Tok::TypedRegex(_)
                | Tok::BigNum(_)
                | Tok::Name(_)
                | Tok::FuncName(_)
                | Tok::Builtin(_)
                | Tok::Op("$" | "!" | "(" | "++" | "--" | "-" | "+")
        )
    }

    fn concat(&mut self) -> R<Expr> {
        let mut l = self.additive()?;
        loop {
            let t = self.peek()?.clone();
            // `cmd | getline [var]`
            if t == Tok::Op("|") && *self.peek_n(1)? == Tok::Kw("getline") {
                self.next()?;
                self.next()?;
                let lv = self.getline_lvalue()?;
                l = Expr::Getline { src: GetSrc::Cmd(Box::new(l)), lv };
                continue;
            }
            if !Self::starts_operand(&t) || matches!(t, Tok::Op("-" | "+")) || (self.no_in && t == Tok::Kw("in")) {
                return Ok(l);
            }
            if matches!(t, Tok::Kw(_)) {
                return Ok(l);
            }
            let r = self.additive()?;
            l = Expr::Concat(Box::new(l), Box::new(r));
        }
    }

    fn additive(&mut self) -> R<Expr> {
        let mut l = self.mul()?;
        loop {
            let op = match self.peek()? {
                Tok::Op("+") => BinOp::Add,
                Tok::Op("-") => BinOp::Sub,
                _ => return Ok(l),
            };
            self.next()?;
            let r = self.mul()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
    }

    fn mul(&mut self) -> R<Expr> {
        let mut l = self.unary()?;
        loop {
            let op = match self.peek()? {
                Tok::Op("*") => BinOp::Mul,
                Tok::Op("/") => BinOp::Div,
                Tok::Op("%") => BinOp::Mod,
                _ => return Ok(l),
            };
            self.next()?;
            let r = self.unary()?;
            l = Expr::Bin(op, Box::new(l), Box::new(r));
        }
    }

    fn unary(&mut self) -> R<Expr> {
        match self.peek()? {
            Tok::Op("!") => {
                self.next()?;
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Tok::Op("-") => {
                self.next()?;
                Ok(Expr::Neg(Box::new(self.unary()?)))
            }
            Tok::Op("+") => {
                self.next()?;
                Ok(Expr::Plus(Box::new(self.unary()?)))
            }
            _ => self.pow(),
        }
    }

    fn pow(&mut self) -> R<Expr> {
        let base = self.postfix()?;
        if matches!(self.peek()?, Tok::Op("^" | "**")) {
            self.next()?;
            // Right-associative; the exponent may be negated.
            let e = match self.peek()? {
                Tok::Op("-") => {
                    self.next()?;
                    Expr::Neg(Box::new(self.pow()?))
                }
                Tok::Op("+") => {
                    self.next()?;
                    self.pow()?
                }
                Tok::Op("!") => {
                    self.next()?;
                    Expr::Not(Box::new(self.pow()?))
                }
                _ => self.pow()?,
            };
            return Ok(Expr::Bin(BinOp::Pow, Box::new(base), Box::new(e)));
        }
        Ok(base)
    }

    fn postfix(&mut self) -> R<Expr> {
        let e = self.primary()?;
        if Self::is_lvalue(&e) {
            match self.peek()? {
                Tok::Op("++") => {
                    self.next()?;
                    return Ok(Expr::IncDec { pre: false, inc: true, lv: Box::new(e) });
                }
                Tok::Op("--") => {
                    self.next()?;
                    return Ok(Expr::IncDec { pre: false, inc: false, lv: Box::new(e) });
                }
                _ => {}
            }
        }
        Ok(e)
    }

    fn getline_lvalue(&mut self) -> R<Option<Box<Expr>>> {
        match self.peek()?.clone() {
            Tok::Name(_) | Tok::Op("$") => {
                let e = self.primary()?;
                if !Self::is_lvalue(&e) {
                    return Err(String::from("syntax error: getline needs a variable"));
                }
                Ok(Some(Box::new(e)))
            }
            _ => Ok(None),
        }
    }

    fn primary(&mut self) -> R<Expr> {
        let t = self.next()?;
        Ok(match t {
            Tok::Num(n) => Expr::Num(n),
            Tok::Str(s) => Expr::Str(s),
            Tok::Regex(r) => {
                self.prog.regexes.push(r);
                Expr::Regex(self.prog.regexes.len() - 1)
            }
            Tok::TypedRegex(r) => Expr::TypedRegex(r),
            Tok::BigNum(t) => Expr::BigNum(t),
            Tok::Op("$") => {
                // `$` binds tighter than everything but grouping and ++/--.
                let operand = match self.peek()? {
                    Tok::Op("++" | "--") => self.primary()?,
                    Tok::Op("-") => {
                        self.next()?;
                        Expr::Neg(Box::new(self.primary()?))
                    }
                    _ => self.primary()?,
                };
                Expr::Field(Box::new(operand))
            }
            Tok::Op(op @ ("++" | "--")) => {
                let lv = self.primary()?;
                if !Self::is_lvalue(&lv) {
                    return Err(alloc::format!("syntax error: {op} needs a variable"));
                }
                Expr::IncDec { pre: true, inc: op == "++", lv: Box::new(lv) }
            }
            Tok::Op("(") => {
                let (old_gt, old_in) = (self.no_gt, self.no_in);
                self.no_gt = false;
                self.no_in = false;
                self.opt_newlines()?;
                let first = self.expr()?;
                let mut list = alloc::vec![first];
                self.opt_newlines()?;
                while self.eat(&Tok::Op(","))? {
                    self.opt_newlines()?;
                    list.push(self.expr()?);
                    self.opt_newlines()?;
                }
                self.expect(&Tok::Op(")"))?;
                self.no_gt = old_gt;
                self.no_in = old_in;
                if list.len() > 1 {
                    if self.is(&Tok::Kw("in"))? {
                        self.next()?;
                        let Tok::Name(n) = self.next()? else {
                            return Err(String::from("syntax error: `in' needs an array name"));
                        };
                        let v = self.var(&n);
                        return Ok(Expr::In(list, v, self.subscripts()?));
                    }
                    return Ok(Expr::Group(list));
                }
                // A parenthesized expression is no lvalue: wrap it.
                let e = list.pop().unwrap();
                if Self::is_lvalue(&e) { Expr::Group(alloc::vec![e]) } else { e }
            }
            Tok::Name(n) => {
                let path = self.subscripts()?;
                if path.is_empty() { Expr::Var(self.var(&n)) } else { Expr::Index(self.var(&n), path) }
            }
            Tok::FuncName(n) => {
                let f = self.func(&n);
                self.expect(&Tok::Op("("))?;
                let args = self.expr_list(&Tok::Op(")"))?;
                Expr::Call(f, args)
            }
            Tok::Builtin(b) => {
                let args = if self.is(&Tok::Op("("))? {
                    self.next()?;
                    self.expr_list(&Tok::Op(")"))?
                } else if b == "length" {
                    Vec::new()
                } else {
                    return Err(alloc::format!("syntax error: {b} needs arguments"));
                };
                Expr::Builtin(b, args)
            }
            Tok::Kw("getline") => {
                let lv = self.getline_lvalue()?;
                if self.is(&Tok::Op("<"))? {
                    self.next()?;
                    let f = self.postfix()?;
                    Expr::Getline { src: GetSrc::File(Box::new(f)), lv }
                } else {
                    Expr::Getline { src: GetSrc::Main, lv }
                }
            }
            Tok::Op("-") => Expr::Neg(Box::new(self.unary()?)),
            Tok::Op("+") => Expr::Plus(Box::new(self.unary()?)),
            Tok::Op("!") => Expr::Not(Box::new(self.unary()?)),
            t => return Err(alloc::format!("syntax error: unexpected {}", describe(&t))),
        })
    }
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Num(n) => alloc::format!("number {n}"),
        Tok::Str(_) => String::from("string"),
        Tok::Regex(_) | Tok::TypedRegex(_) => String::from("regular expression"),
        Tok::BigNum(t) => String::from_utf8_lossy(t).into_owned(),
        Tok::Name(n) | Tok::FuncName(n) => alloc::format!("`{}'", String::from_utf8_lossy(n)),
        Tok::Builtin(b) => alloc::format!("`{b}'"),
        Tok::Kw(k) => alloc::format!("`{k}'"),
        Tok::Op(o) => alloc::format!("`{o}'"),
        Tok::Newline => String::from("newline"),
        Tok::Eof => String::from("end of program"),
    }
}

/// Work out which function parameters are arrays: used with a subscript,
/// in `in`, delete or for-in, as split's second argument, or passed to a
/// parameter that is (to a fixed point).
fn array_params(p: &mut Program) {
    fn walk_e(e: &Expr, f: &mut dyn FnMut(Var), calls: &mut Vec<(usize, usize, Var)>) {
        match e {
            Expr::Index(v, path) => {
                f(*v);
                for s in path.iter().flatten() {
                    walk_e(s, f, calls);
                }
            }
            Expr::In(subs, v, path) => {
                f(*v);
                for s in subs.iter().chain(path.iter().flatten()) {
                    walk_e(s, f, calls);
                }
            }
            Expr::Builtin(name, args) => {
                for (i, a) in args.iter().enumerate() {
                    let array = (*name == "split" && i == 1)
                        || (*name == "match" && i == 2)
                        || (*name == "patsplit" && (i == 1 || i == 3))
                        || (*name == "split" && i == 3)
                        || (matches!(*name, "asort" | "asorti") && i < 2)
                        || (matches!(*name, "stat" | "statvfs") && i == 1);
                    // typeof() and isarray() take arrays and scalars alike.
                    if matches!(*name, "typeof" | "isarray") && matches!(a, Expr::Var(_)) {
                        continue;
                    }
                    if (array || (*name == "length" && args.len() == 1))
                        && let Expr::Var(v) = a
                    {
                        if array {
                            f(*v);
                        }
                        continue;
                    }
                    walk_e(a, f, calls);
                }
            }
            Expr::Call(fi, args) => {
                for (i, a) in args.iter().enumerate() {
                    if let Expr::Var(v) = a {
                        calls.push((*fi, i, *v));
                    } else {
                        walk_e(a, f, calls);
                    }
                }
            }
            Expr::Field(a) | Expr::Not(a) | Expr::Neg(a) | Expr::Plus(a) => walk_e(a, f, calls),
            Expr::IncDec { lv, .. } => walk_e(lv, f, calls),
            Expr::Assign(_, a, b)
            | Expr::And(a, b)
            | Expr::Or(a, b)
            | Expr::Bin(_, a, b)
            | Expr::Cmp(_, a, b)
            | Expr::Concat(a, b)
            | Expr::Match(_, a, b) => {
                walk_e(a, f, calls);
                walk_e(b, f, calls);
            }
            Expr::Cond(a, b, c) => {
                walk_e(a, f, calls);
                walk_e(b, f, calls);
                walk_e(c, f, calls);
            }
            Expr::Getline { src, lv } => {
                match src {
                    GetSrc::File(x) | GetSrc::Cmd(x) => walk_e(x, f, calls),
                    GetSrc::Main => {}
                }
                if let Some(l) = lv {
                    walk_e(l, f, calls);
                }
            }
            Expr::Group(v) => {
                for x in v {
                    walk_e(x, f, calls);
                }
            }
            _ => {}
        }
    }
    fn walk_s(s: &Stmt, f: &mut dyn FnMut(Var), calls: &mut Vec<(usize, usize, Var)>) {
        match s {
            Stmt::Expr(e) => walk_e(e, f, calls),
            Stmt::Print(a, r) | Stmt::Printf(a, r) => {
                for x in a {
                    walk_e(x, f, calls);
                }
                if let Some((_, t)) = r {
                    walk_e(t, f, calls);
                }
            }
            Stmt::If(c, a, b) => {
                walk_e(c, f, calls);
                walk_s(a, f, calls);
                if let Some(b) = b {
                    walk_s(b, f, calls);
                }
            }
            Stmt::While(c, b) | Stmt::Do(b, c) => {
                walk_e(c, f, calls);
                walk_s(b, f, calls);
            }
            Stmt::For(i, c, st, b) => {
                if let Some(i) = i {
                    walk_s(i, f, calls);
                }
                if let Some(c) = c {
                    walk_e(c, f, calls);
                }
                if let Some(st) = st {
                    walk_s(st, f, calls);
                }
                walk_s(b, f, calls);
            }
            Stmt::ForIn(_, a, path, b) => {
                f(*a);
                for s in path.iter().flatten() {
                    walk_e(s, f, calls);
                }
                walk_s(b, f, calls);
            }
            Stmt::Block(v) => {
                for x in v {
                    walk_s(x, f, calls);
                }
            }
            Stmt::Exit(Some(e)) | Stmt::Return(Some(e)) => walk_e(e, f, calls),
            Stmt::Delete(v, path) => {
                f(*v);
                for x in path.iter().flatten() {
                    walk_e(x, f, calls);
                }
            }
            Stmt::Switch(e, cases) => {
                walk_e(e, f, calls);
                for (_, body) in cases {
                    for x in body {
                        walk_s(x, f, calls);
                    }
                }
            }
            _ => {}
        }
    }
    let n = p.funcs.len();
    let mut calls: Vec<Vec<(usize, usize, Var)>> = alloc::vec![Vec::new(); n];
    for (fi, func) in p.funcs.iter_mut().enumerate() {
        let mut arrays = core::mem::take(&mut func.arrays);
        let mut mark = |v: Var| {
            if let Var::Local(i) = v
                && i < arrays.len()
            {
                arrays[i] = true;
            }
        };
        for s in &func.body {
            walk_s(s, &mut mark, &mut calls[fi]);
        }
        func.arrays = arrays;
    }
    // Propagate through calls: a local passed to an array parameter is one.
    loop {
        let mut changed = false;
        for fi in 0..n {
            for &(callee, arg, v) in &calls[fi].clone() {
                if let Var::Local(i) = v
                    && p.funcs[callee].arrays.get(arg).copied().unwrap_or(false)
                    && !p.funcs[fi].arrays[i]
                {
                    p.funcs[fi].arrays[i] = true;
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
}
