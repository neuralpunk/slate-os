// SPDX-License-Identifier: MIT OR Apache-2.0

//! test(1) and `[`: file tests, string and integer comparisons, `!`, `-a`,
//! `-o` and parentheses, with POSIX's rules for 0 to 4 arguments.

use alloc::vec::Vec;

use slate_rt::{fs, process};

use crate::util::error;

pub fn test(args: &[Vec<u8>]) -> i32 {
    run(&args[1..])
}

pub fn bracket(args: &[Vec<u8>]) -> i32 {
    if args.last().map(Vec::as_slice) != Some(b"]") {
        error("missing ']'");
        return 2;
    }
    run(&args[1..args.len() - 1])
}

/// Evaluate a test expression: 0 true, 1 false, 2 error.
pub fn run(a: &[Vec<u8>]) -> i32 {
    let r = match a.len() {
        0 => Ok(false),
        1 => Ok(!a[0].is_empty()),
        2 if a[0] == b"!" => Ok(a[1].is_empty()),
        2 => unary(&a[0], &a[1]),
        3 if is_binary(&a[1]) => binary(&a[0], &a[1], &a[2]),
        3 | 4 if a[0] == b"!" => match run(&a[1..]) {
            2 => Err(()),
            r => Ok(r != 0),
        },
        3 if a[0] == b"(" && a[2] == b")" => Ok(!a[1].is_empty()),
        _ => {
            let mut p = Expr { a, i: 0 };
            let r = p.or();
            if p.i != a.len() { Err(()) } else { r }
        }
    };
    match r {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(()) => 2,
    }
}

fn is_binary(op: &[u8]) -> bool {
    matches!(
        op,
        b"=" | b"=="
            | b"!="
            | b"<"
            | b">"
            | b"-eq"
            | b"-ne"
            | b"-lt"
            | b"-le"
            | b"-gt"
            | b"-ge"
            | b"-nt"
            | b"-ot"
            | b"-ef"
            | b"-a"
            | b"-o"
    )
}

fn int(s: &[u8]) -> Result<i64, ()> {
    let t = core::str::from_utf8(s).map_err(|_| ())?.trim();
    t.parse().map_err(|_| {
        error(format_args!("{t}: integer expression expected"));
    })
}

fn unary(op: &[u8], f: &[u8]) -> Result<bool, ()> {
    let st = || fs::stat(f).ok();
    Ok(match op {
        b"-n" => !f.is_empty(),
        b"-z" => f.is_empty(),
        b"-e" => st().is_some(),
        b"-f" => st().is_some_and(|s| s.is_file()),
        b"-d" => st().is_some_and(|s| s.is_dir()),
        b"-h" | b"-L" => fs::lstat(f).is_ok_and(|s| s.is_symlink()),
        b"-b" => st().is_some_and(|s| s.kind() == fs::S_IFBLK),
        b"-c" => st().is_some_and(|s| s.kind() == fs::S_IFCHR),
        b"-p" => st().is_some_and(|s| s.kind() == fs::S_IFIFO),
        b"-S" => st().is_some_and(|s| s.kind() == fs::S_IFSOCK),
        b"-s" => st().is_some_and(|s| s.size > 0),
        b"-r" => fs::access(f, 4).is_ok(),
        b"-w" => fs::access(f, 2).is_ok(),
        b"-x" => fs::access(f, 1).is_ok(),
        b"-u" => st().is_some_and(|s| s.mode & 0o4000 != 0),
        b"-g" => st().is_some_and(|s| s.mode & 0o2000 != 0),
        b"-k" => st().is_some_and(|s| s.mode & 0o1000 != 0),
        b"-O" => st().is_some_and(|s| s.uid == process::geteuid()),
        b"-G" => st().is_some_and(|s| s.gid == process::getegid()),
        b"-t" => slate_rt::term::isatty(int(f)? as i32),
        _ => {
            error(format_args!("{}: unary operator expected", slate_rt::lossy(op)));
            return Err(());
        }
    })
}

fn binary(l: &[u8], op: &[u8], r: &[u8]) -> Result<bool, ()> {
    let mtime = |p: &[u8]| fs::stat(p).ok().map(|s| (s.mtime, s.mtime_nsec));
    Ok(match op {
        b"=" | b"==" => l == r,
        b"!=" => l != r,
        b"<" => l < r,
        b">" => l > r,
        b"-eq" => int(l)? == int(r)?,
        b"-ne" => int(l)? != int(r)?,
        b"-lt" => int(l)? < int(r)?,
        b"-le" => int(l)? <= int(r)?,
        b"-gt" => int(l)? > int(r)?,
        b"-ge" => int(l)? >= int(r)?,
        b"-nt" => match (mtime(l), mtime(r)) {
            (Some(a), Some(b)) => a > b,
            (Some(_), None) => true,
            _ => false,
        },
        b"-ot" => match (mtime(l), mtime(r)) {
            (Some(a), Some(b)) => a < b,
            (None, Some(_)) => true,
            _ => false,
        },
        b"-ef" => match (fs::stat(l), fs::stat(r)) {
            (Ok(a), Ok(b)) => a.dev == b.dev && a.ino == b.ino,
            _ => false,
        },
        b"-a" => !l.is_empty() && !r.is_empty(),
        b"-o" => !l.is_empty() || !r.is_empty(),
        _ => return Err(()),
    })
}

/// The general grammar: or := and (-o and)*; and := not (-a not)*;
/// not := ! not | primary; primary := ( or ) | unary | binary | string.
struct Expr<'a> {
    a: &'a [Vec<u8>],
    i: usize,
}

impl Expr<'_> {
    fn peek(&self, k: usize) -> Option<&[u8]> {
        self.a.get(self.i + k).map(Vec::as_slice)
    }

    fn or(&mut self) -> Result<bool, ()> {
        let mut v = self.and()?;
        while self.peek(0) == Some(b"-o") {
            self.i += 1;
            let r = self.and()?;
            v = v || r;
        }
        Ok(v)
    }

    fn and(&mut self) -> Result<bool, ()> {
        let mut v = self.not()?;
        while self.peek(0) == Some(b"-a") {
            self.i += 1;
            let r = self.not()?;
            v = v && r;
        }
        Ok(v)
    }

    fn not(&mut self) -> Result<bool, ()> {
        if self.peek(0) == Some(b"!") {
            self.i += 1;
            return Ok(!self.not()?);
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<bool, ()> {
        let Some(t) = self.peek(0).map(<[u8]>::to_vec) else { return Err(()) };
        let t = t.as_slice();
        if t == b"(" {
            self.i += 1;
            let v = self.or()?;
            if self.peek(0) != Some(b")") {
                error("')' expected");
                return Err(());
            }
            self.i += 1;
            return Ok(v);
        }
        if let (Some(op), Some(r)) = (self.peek(1), self.peek(2))
            && is_binary(op)
            && op != b"-a"
            && op != b"-o"
        {
            let (l, op, r) = (t.to_vec(), op.to_vec(), r.to_vec());
            self.i += 3;
            return binary(&l, &op, &r);
        }
        if t.len() == 2 && t[0] == b'-' && self.peek(1).is_some() && t != b"-a" && t != b"-o" {
            let (op, f) = (t.to_vec(), self.peek(1).unwrap().to_vec());
            self.i += 2;
            return unary(&op, &f);
        }
        self.i += 1;
        Ok(!t.is_empty())
    }
}
