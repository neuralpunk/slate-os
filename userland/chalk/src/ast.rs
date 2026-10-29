// SPDX-License-Identifier: MIT OR Apache-2.0

//! The syntax tree of shell programs (POSIX.1-2017 XCU §2.10 grammar, plus
//! the bash extensions chalk accepts).

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

/// A word: parts that expand and concatenate.
pub type Word = Vec<WordPart>;

#[derive(Clone, Debug, PartialEq)]
pub enum WordPart {
    /// Unquoted text: subject to globbing (and, from expansions only, to
    /// field splitting).
    Lit(Vec<u8>),
    /// Single-quoted (or `$'...'`) text: literal.
    Quoted(Vec<u8>),
    /// A byte escaped with a backslash outside quotes: literal.
    Escaped(u8),
    /// A double-quoted region.
    DQuote(Vec<WordPart>),
    Param(Box<Param>),
    /// `$(...)`, or backquotes (true).
    CmdSub(Rc<Program>, bool),
    /// `$((...))`: the expression text after expansion.
    Arith(Word),
    /// `(...)` after `name=` (bash): an array's elements, each a word
    /// (`[key]=value` ones keyed).
    ArrayLit(Vec<Word>),
    /// `<(...)` (false) or `>(...)` (true), bash: a pipe to or from the
    /// program, named `/dev/fd/N`.
    ProcSub(Rc<Program>, bool),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParamOp {
    /// `$x`, `${x}`
    Get,
    /// `${#x}`
    Length,
    /// `${x-w}` / `${x:-w}`
    Default(Word),
    /// `${x=w}` / `${x:=w}`
    Assign(Word),
    /// `${x?w}` / `${x:?w}`
    Error(Word),
    /// `${x+w}` / `${x:+w}`
    Alt(Word),
    /// `${x%w}` (`longest`: `%%`)
    RemoveSuffix(Word, bool),
    /// `${x#w}` (`longest`: `##`)
    RemovePrefix(Word, bool),
    /// `${x/pat/rep}`: all (`//`), anchored at the start (`/#`) or end (`/%`).
    Replace { pat: Word, rep: Word, all: bool, anchor: u8 },
    /// `${x:off}` / `${x:off:len}`
    Substr(Word, Option<Word>),
    /// `${x^}` `${x^^}` `${x,}` `${x,,}`: (upper, all)
    Case(bool, bool),
    /// `${!prefix*}` / `${!prefix@}`: the names of the variables that
    /// start with the prefix (star: `*`).
    Names(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    /// A variable name, a positional number, or a special (`?`, `#`, `@`...).
    pub name: Vec<u8>,
    pub op: ParamOp,
    /// The `:` forms also treat an empty value as unset.
    pub colon: bool,
    /// `${name[subscript]}` (bash arrays).
    pub index: Option<Word>,
    /// `${!name}`: the variable `name`'s value names (with `[@]`: the
    /// array's keys).
    pub indirect: bool,
    /// Written with braces (`${x}` rather than `$x`).
    pub braced: bool,
}

/// An assignment: `name=value`, `name+=value`, `name[sub]=value`, or an
/// array literal as the value.
#[derive(Clone, Debug, PartialEq)]
pub struct Assign {
    pub name: Vec<u8>,
    pub index: Option<Word>,
    pub append: bool,
    pub value: Word,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedirKind {
    /// `<`
    In,
    /// `>`
    Out,
    /// `>|`
    Clobber,
    /// `>>`
    Append,
    /// `<>`
    ReadWrite,
    /// `<&`
    DupIn,
    /// `>&`
    DupOut,
    /// `<<`, `<<-`
    HereDoc,
    /// `<<<` (bash)
    HereString,
    /// `&>` (bash: stdout and stderr)
    OutErr,
    /// `&>>`
    AppendErr,
}

/// A here-document's body, filled in when the parser reaches it.
#[derive(Clone, Debug, PartialEq)]
pub struct HereBody {
    pub body: Word,
    pub filled: bool,
    /// The body as read (after `<<-` took the leading tabs), for printing.
    pub raw: Vec<u8>,
    /// `<<-`.
    pub strip: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Redir {
    pub fd: Option<i32>,
    pub kind: RedirKind,
    pub target: Word,
    pub heredoc: Option<Rc<RefCell<HereBody>>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CaseEnd {
    /// `;;`
    Break,
    /// `;&`: run the next arm's body too.
    FallThrough,
    /// `;;&`: keep matching.
    Continue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Program,
    pub end: CaseEnd,
}

/// `[[ ... ]]` expressions.
#[derive(Clone, Debug, PartialEq)]
pub enum Cond {
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
    Not(Box<Cond>),
    /// `( ... )`, kept for printing.
    Paren(Box<Cond>),
    Unary(Vec<u8>, Word),
    Binary(Word, Vec<u8>, Word),
    Word(Word),
}

/// Commands that report errors carry their line in the script (`line`),
/// which `$LINENO` and error messages show.
#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    Simple {
        assigns: Vec<Assign>,
        words: Vec<Word>,
        redirs: Vec<Redir>,
        line: usize,
    },
    Pipeline {
        bang: bool,
        cmds: Vec<Command>,
    },
    And(Box<Command>, Box<Command>),
    Or(Box<Command>, Box<Command>),
    Subshell(Program, Vec<Redir>),
    Group(Program, Vec<Redir>),
    If {
        arms: Vec<(Program, Program)>,
        otherwise: Option<Program>,
        redirs: Vec<Redir>,
    },
    Loop {
        until: bool,
        cond: Program,
        body: Program,
        redirs: Vec<Redir>,
    },
    For {
        var: Vec<u8>,
        words: Option<Vec<Word>>,
        body: Program,
        redirs: Vec<Redir>,
        line: usize,
    },
    /// `for ((init; cond; step))` (bash): the three expressions' text.
    ArithFor {
        exprs: [Word; 3],
        body: Program,
        redirs: Vec<Redir>,
        line: usize,
    },
    /// `select name [in words]` (bash): a numbered menu on standard error.
    Select {
        var: Vec<u8>,
        words: Option<Vec<Word>>,
        body: Program,
        redirs: Vec<Redir>,
        line: usize,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
        redirs: Vec<Redir>,
        line: usize,
    },
    FuncDef {
        name: Vec<u8>,
        body: Rc<Command>,
    },
    Cond(Cond, Vec<Redir>, usize),
    Arith(Word, Vec<Redir>, usize),
    /// `coproc [name] command` (bash): the command in the background with
    /// pipes to and from the shell.
    Coproc {
        name: Vec<u8>,
        body: Rc<Command>,
    },
    /// `time [-p] pipeline` (bash): the pipeline's times on standard error
    /// (none: the shell's own).
    Time {
        posix: bool,
        cmd: Option<Box<Command>>,
    },
}

/// A list of commands, each run in the background when its flag is set.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Program(pub Vec<(Command, bool)>);
