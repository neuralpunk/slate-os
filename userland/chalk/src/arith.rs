// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shell arithmetic (POSIX.1-2017 XCU §2.6.4, with the C operators bash
//! adds): signed 64-bit integers, variables by name, assignments,
//! `++`/`--`, `?:`, `,`, and decimal, octal (`0NN`), hex (`0xNN`) and
//! `BASE#NUM` constants; array elements as `name[subscript]`.

use alloc::string::String;
use alloc::vec::Vec;

/// Variable access for the evaluator.
pub trait Vars {
    fn get(&mut self, name: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, name: &[u8], value: i64);
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Num(i64),
    Name(Vec<u8>),
    Op(&'static str),
}

const OPS: &[&str] = &[
    "<<=", ">>=", "**", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=",
    "^=", "|=", "+", "-", "*", "/", "%", "<", ">", "&", "^", "|", "!", "~", "?", ":", "=", "(", ")", ",",
];

fn parse_num(s: &[u8]) -> Result<i64, String> {
    let t = core::str::from_utf8(s).map_err(|_| String::from("bad number"))?;
    let bad = || alloc::format!("{t}: value too great for base (error token is \"{t}\")");
    if let Some((base, digits)) = t.split_once('#') {
        let b: u32 = base.parse().map_err(|_| bad())?;
        if !(2..=64).contains(&b) {
            return Err(alloc::format!("{t}: invalid arithmetic base"));
        }
        return i64::from_str_radix(digits, b.min(36)).map_err(|_| bad());
    }
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).map_err(|_| bad());
    }
    if t.len() > 1 && t.starts_with('0') {
        return i64::from_str_radix(&t[1..], 8).map_err(|_| bad());
    }
    t.parse::<i64>().or_else(|_| t.parse::<u64>().map(|v| v as i64)).map_err(|_| bad())
}

fn lex(s: &[u8]) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'#' || s[i] == b'_' || s[i] == b'@') {
                i += 1;
            }
            out.push(Tok::Num(parse_num(&s[start..i])?));
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < s.len() && (s[i].is_ascii_alphanumeric() || s[i] == b'_') {
                i += 1;
            }
            // `a[expr]`: the element, subscript and all, as one name.
            if s.get(i) == Some(&b'[') {
                let mut depth = 0;
                while i < s.len() {
                    match s[i] {
                        b'[' => depth += 1,
                        b']' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                if depth != 0 {
                    return Err(String::from("bad array subscript"));
                }
            }
            out.push(Tok::Name(s[start..i].to_vec()));
            continue;
        }
        match OPS.iter().find(|op| s[i..].starts_with(op.as_bytes())) {
            Some(op) => {
                out.push(Tok::Op(op));
                i += op.len();
            }
            None => {
                return Err(alloc::format!(
                    "syntax error: invalid arithmetic operator (error token is \"{}\")",
                    String::from_utf8_lossy(&s[i..])
                ));
            }
        }
    }
    Ok(out)
}

struct Eval<'a, V: Vars> {
    t: Vec<Tok>,
    i: usize,
    vars: &'a mut V,
    /// Inside the untaken side of `&&`, `||` or `?:`: parse, do not assign.
    skip: u32,
}

/// Evaluate an expression.
pub fn eval<V: Vars>(expr: &[u8], vars: &mut V) -> Result<i64, String> {
    let t = lex(expr)?;
    if t.is_empty() {
        return Ok(0);
    }
    let mut e = Eval { t, i: 0, vars, skip: 0 };
    let v = e.comma()?;
    if e.i < e.t.len() {
        return Err(String::from("syntax error in expression"));
    }
    Ok(v)
}

impl<V: Vars> Eval<'_, V> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn is_op(&self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(o)) if *o == op)
    }
    fn var(&mut self, name: &[u8]) -> Result<i64, String> {
        let v = self.vars.get(name).unwrap_or_default();
        let t = core::str::from_utf8(&v).unwrap_or("").trim();
        if t.is_empty() {
            return Ok(0);
        }
        // A variable's value is itself an expression (bash).
        if t.as_bytes() == name {
            return Ok(0);
        }
        eval(t.as_bytes(), self.vars)
    }

    fn comma(&mut self) -> Result<i64, String> {
        let mut v = self.assign()?;
        while self.is_op(",") {
            self.i += 1;
            v = self.assign()?;
        }
        Ok(v)
    }

    fn assign(&mut self) -> Result<i64, String> {
        if let (Some(Tok::Name(n)), Some(Tok::Op(op))) = (self.t.get(self.i).cloned(), self.t.get(self.i + 1).cloned())
            && matches!(op, "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "^=" | "|=")
        {
            self.i += 2;
            let rhs = self.assign()?;
            let v = if op == "=" { rhs } else { binop(&op[..op.len() - 1], self.var(&n)?, rhs)? };
            if self.skip == 0 {
                self.vars.set(&n, v);
            }
            return Ok(v);
        }
        self.ternary()
    }

    fn ternary(&mut self) -> Result<i64, String> {
        let c = self.binary(0)?;
        if !self.is_op("?") {
            return Ok(c);
        }
        self.i += 1;
        if c == 0 {
            self.skip += 1;
        }
        let a = self.comma()?;
        if c == 0 {
            self.skip -= 1;
        }
        if !self.is_op(":") {
            return Err(String::from("expected ':' in conditional expression"));
        }
        self.i += 1;
        if c != 0 {
            self.skip += 1;
        }
        let b = self.ternary()?;
        if c != 0 {
            self.skip -= 1;
        }
        Ok(if c != 0 { a } else { b })
    }

    fn binary(&mut self, min: u8) -> Result<i64, String> {
        let mut l = self.unary()?;
        loop {
            let Some(Tok::Op(op)) = self.peek().cloned() else { return Ok(l) };
            let Some(prec) = precedence(op) else { return Ok(l) };
            if prec < min {
                return Ok(l);
            }
            self.i += 1;
            if op == "&&" || op == "||" {
                let short = (op == "&&" && l == 0) || (op == "||" && l != 0);
                if short {
                    self.skip += 1;
                }
                let r = self.binary(prec + 1)?;
                if short {
                    self.skip -= 1;
                }
                l = i64::from(if op == "&&" { l != 0 && r != 0 } else { l != 0 || r != 0 });
                continue;
            }
            // ** is right-associative.
            let r = if op == "**" { self.binary(prec)? } else { self.binary(prec + 1)? };
            l = if self.skip > 0 { 0 } else { binop(op, l, r)? };
        }
    }

    fn unary(&mut self) -> Result<i64, String> {
        match self.peek().cloned() {
            Some(Tok::Op(op @ ("++" | "--"))) => {
                self.i += 1;
                let Some(Tok::Name(n)) = self.peek().cloned() else {
                    return Err(String::from("expected a variable after ++/--"));
                };
                self.i += 1;
                let v = self.var(&n)? + if op == "++" { 1 } else { -1 };
                if self.skip == 0 {
                    self.vars.set(&n, v);
                }
                Ok(v)
            }
            Some(Tok::Op("-")) => {
                self.i += 1;
                Ok(self.unary()?.wrapping_neg())
            }
            Some(Tok::Op("+")) => {
                self.i += 1;
                self.unary()
            }
            Some(Tok::Op("!")) => {
                self.i += 1;
                Ok(i64::from(self.unary()? == 0))
            }
            Some(Tok::Op("~")) => {
                self.i += 1;
                Ok(!self.unary()?)
            }
            _ => self.postfix(),
        }
    }

    fn postfix(&mut self) -> Result<i64, String> {
        match self.peek().cloned() {
            Some(Tok::Num(n)) => {
                self.i += 1;
                Ok(n)
            }
            Some(Tok::Name(n)) => {
                self.i += 1;
                let v = self.var(&n)?;
                if let Some(Tok::Op(op @ ("++" | "--"))) = self.peek().cloned() {
                    self.i += 1;
                    if self.skip == 0 {
                        self.vars.set(&n, v + if op == "++" { 1 } else { -1 });
                    }
                }
                Ok(v)
            }
            Some(Tok::Op("(")) => {
                self.i += 1;
                let v = self.comma()?;
                if !self.is_op(")") {
                    return Err(String::from("missing ')'"));
                }
                self.i += 1;
                Ok(v)
            }
            Some(Tok::Op(o)) => Err(alloc::format!("syntax error: operand expected (error token is \"{o}\")")),
            None => Err(String::from("syntax error: operand expected")),
        }
    }
}

fn precedence(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | ">" | "<=" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        "**" => 11,
        _ => return None,
    })
}

fn binop(op: &str, a: i64, b: i64) -> Result<i64, String> {
    Ok(match op {
        "+" => a.wrapping_add(b),
        "-" => a.wrapping_sub(b),
        "*" => a.wrapping_mul(b),
        "/" | "%" if b == 0 => return Err(String::from("division by 0")),
        "/" => a.wrapping_div(b),
        "%" => a.wrapping_rem(b),
        "**" if b < 0 => return Err(String::from("exponent less than 0")),
        "**" => a.wrapping_pow(b.min(u32::MAX as i64) as u32),
        "<<" => a.wrapping_shl(b as u32),
        ">>" => a.wrapping_shr(b as u32),
        "<" => i64::from(a < b),
        ">" => i64::from(a > b),
        "<=" => i64::from(a <= b),
        ">=" => i64::from(a >= b),
        "==" => i64::from(a == b),
        "!=" => i64::from(a != b),
        "&" => a & b,
        "^" => a ^ b,
        "|" => a | b,
        _ => return Err(alloc::format!("bad operator {op}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct M(BTreeMap<Vec<u8>, Vec<u8>>);
    impl Vars for M {
        fn get(&mut self, n: &[u8]) -> Option<Vec<u8>> {
            self.0.get(n).cloned()
        }
        fn set(&mut self, n: &[u8], v: i64) {
            self.0.insert(n.to_vec(), alloc::format!("{v}").into_bytes());
        }
    }

    #[test]
    fn evaluates() {
        let mut m = M(BTreeMap::new());
        let mut e = |s: &str| eval(s.as_bytes(), &mut m).unwrap();
        assert_eq!(e("1 + 2 * 3"), 7);
        assert_eq!(e("(1 + 2) * 3"), 9);
        assert_eq!(e("2 ** 3 ** 2"), 512);
        assert_eq!(e("x = 5, x += 2, x"), 7);
        assert_eq!(e("x++ + ++x"), 16);
        assert_eq!(e("x"), 9);
        assert_eq!(e("0x10 + 010 + 2#101"), 16 + 8 + 5);
        assert_eq!(e("1 < 2 && 3 > 4 || !0"), 1);
        assert_eq!(e("0 && (y = 1)"), 0);
        assert_eq!(e("y"), 0);
        assert_eq!(e("1 ? 10 : 20"), 10);
        assert_eq!(e("-7 / 2"), -3);
        assert_eq!(e("-7 % 2"), -1);
        assert_eq!(e("~0"), -1);
        assert!(eval(b"1 / 0", &mut m).is_err());
    }
}
