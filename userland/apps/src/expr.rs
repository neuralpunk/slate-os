// SPDX-License-Identifier: MIT OR Apache-2.0

//! The calculator's arithmetic (ADR 0104): expressions as people type
//! them, evaluated in double precision with slate-math's functions.
//!
//! - Numbers: `12`, `0.5`, `.5`, `1.5e3`; whole numbers in other bases,
//!   `0x1f`, `0o17`, `0b101`; the constants `π` (or `pi`) and `e`; `ans`,
//!   the last answer, and `mem`, the memory.
//! - Operators, loosest first: `+ -`; `× ÷ * /` and implied
//!   multiplication (`2π`, `3(1+2)`, `2 sin 30`); unary `-`; `^`, right
//!   to left (`2^3^2` is 2^9); postfix `!` (factorial) and `%` (hundredths).
//! - Functions, with or without brackets around one argument: `sin cos
//!   tan asin acos atan` (in degrees or radians), `sinh cosh tanh asinh
//!   acosh atanh`, `ln log` (base 10), `sqrt` or `√`, `exp abs`.
//! - Unclosed brackets close at the end, so `2(3+4` is 14.

use alloc::string::String;
use alloc::vec::Vec;

use slate_math as m;

/// Why an expression has no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing typed.
    Empty,
    /// Not an expression ("2 +", "×3", an unknown name).
    Syntax,
    DivideByZero,
    /// Outside a function's domain: √ of a negative, ln 0, 2.5!, asin 2.
    Domain,
    /// Too large for a double.
    Overflow,
}

impl Error {
    pub fn text(self) -> &'static str {
        match self {
            Error::Empty => "",
            Error::Syntax => "Not a complete expression",
            Error::DivideByZero => "Can't divide by zero",
            Error::Domain => "Outside what the function takes",
            Error::Overflow => "Too large",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Angle {
    Degrees,
    Radians,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Tok {
    Num(f64),
    Op(char),
    Open,
    Close,
    Bang,
    Percent,
    Func(Func),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Func {
    Sin,
    Cos,
    Tan,
    Asin,
    Acos,
    Atan,
    Sinh,
    Cosh,
    Tanh,
    Asinh,
    Acosh,
    Atanh,
    Ln,
    Log,
    Sqrt,
    Exp,
    Abs,
}

/// Longest first where one name starts another ("asinh", "asin", "sin").
const NAMES: [(&str, Func); 17] = [
    ("asinh", Func::Asinh),
    ("acosh", Func::Acosh),
    ("atanh", Func::Atanh),
    ("sinh", Func::Sinh),
    ("cosh", Func::Cosh),
    ("tanh", Func::Tanh),
    ("asin", Func::Asin),
    ("acos", Func::Acos),
    ("atan", Func::Atan),
    ("sin", Func::Sin),
    ("cos", Func::Cos),
    ("tan", Func::Tan),
    ("sqrt", Func::Sqrt),
    ("exp", Func::Exp),
    ("abs", Func::Abs),
    ("log", Func::Log),
    ("ln", Func::Ln),
];

fn tokens(s: &str, ans: f64, mem: f64) -> Result<Vec<Tok>, Error> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        // 0x1f, 0o17, 0b101: whole numbers in base 16, 8 or 2.
        if ch == '0'
            && let Some(radix) = c.get(i + 1).and_then(|b| match b.to_ascii_lowercase() {
                'x' => Some(16),
                'o' => Some(8),
                'b' => Some(2),
                _ => None,
            })
            && c.get(i + 2).is_some_and(|d| d.is_digit(radix))
        {
            let mut j = i + 2;
            let mut v = 0.0f64;
            while let Some(d) = c.get(j).and_then(|d| d.to_digit(radix)) {
                v = v * f64::from(radix) + f64::from(d);
                j += 1;
            }
            out.push(Tok::Num(v));
            i = j;
            continue;
        }
        if ch.is_ascii_digit() || ch == '.' {
            let start = i;
            while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
                i += 1;
            }
            // An exponent: e followed by digits (else `e` is the constant).
            if i < c.len() && (c[i] == 'e' || c[i] == 'E') {
                let mut j = i + 1;
                if j < c.len() && (c[j] == '-' || c[j] == '+') {
                    j += 1;
                }
                if j < c.len() && c[j].is_ascii_digit() {
                    while j < c.len() && c[j].is_ascii_digit() {
                        j += 1;
                    }
                    i = j;
                }
            }
            let text: String = c[start..i].iter().collect();
            out.push(Tok::Num(number(&text).ok_or(Error::Syntax)?));
            continue;
        }
        if ch.is_alphabetic() && ch != 'π' {
            let start = i;
            while i < c.len() && c[i].is_ascii_alphabetic() {
                i += 1;
            }
            let word: String = c[start..i].iter().map(|c| c.to_ascii_lowercase()).collect();
            // Names run together ("sinpi"): the longest known one first.
            let mut rest = word.as_str();
            while !rest.is_empty() {
                if let Some(r) = rest.strip_prefix("ans") {
                    out.push(Tok::Num(ans));
                    rest = r;
                } else if let Some(r) = rest.strip_prefix("mem") {
                    out.push(Tok::Num(mem));
                    rest = r;
                } else if let Some(r) = rest.strip_prefix("pi") {
                    out.push(Tok::Num(core::f64::consts::PI));
                    rest = r;
                } else if let Some((n, f)) = NAMES.iter().find(|(n, _)| rest.starts_with(n)) {
                    out.push(Tok::Func(*f));
                    rest = &rest[n.len()..];
                } else if let Some(r) = rest.strip_prefix('e') {
                    out.push(Tok::Num(core::f64::consts::E));
                    rest = r;
                } else {
                    return Err(Error::Syntax);
                }
            }
            continue;
        }
        out.push(match ch {
            '+' => Tok::Op('+'),
            '-' | '−' => Tok::Op('-'),
            '*' | '×' | '·' => Tok::Op('*'),
            '/' | '÷' => Tok::Op('/'),
            '^' => Tok::Op('^'),
            '(' => Tok::Open,
            ')' => Tok::Close,
            '!' => Tok::Bang,
            '%' => Tok::Percent,
            'π' => Tok::Num(core::f64::consts::PI),
            '√' => Tok::Func(Func::Sqrt),
            _ => return Err(Error::Syntax),
        });
        i += 1;
    }
    Ok(out)
}

/// A decimal number with an optional exponent, digit by digit (exact for
/// up to 15 significant digits, as a person types them).
fn number(s: &str) -> Option<f64> {
    let (mant, exp) = match s.find(['e', 'E']) {
        Some(i) => (&s[..i], s[i + 1..].parse::<i32>().ok()?),
        None => (s, 0),
    };
    if mant.matches('.').count() > 1 || mant == "." || mant.is_empty() {
        return None;
    }
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    let digits: String = int.chars().chain(frac.chars()).collect();
    let mut v = 0.0f64;
    for d in digits.chars() {
        v = v * 10.0 + f64::from(d.to_digit(10)?);
    }
    Some(scale10(v, exp - frac.len() as i32))
}

/// x × 10^n, by exact powers of ten where it can.
fn scale10(x: f64, n: i32) -> f64 {
    let p = |k: i32| m::pow_(10.0, f64::from(k));
    if n >= 0 { x * p(n) } else { x / p(-n) }
}

struct Parser {
    toks: Vec<Tok>,
    at: usize,
    angle: Angle,
}

impl Parser {
    fn peek(&self) -> Option<Tok> {
        self.toks.get(self.at).copied()
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.peek();
        self.at += 1;
        t
    }

    fn expr(&mut self) -> Result<f64, Error> {
        let mut v = self.term()?;
        while let Some(Tok::Op(o @ ('+' | '-'))) = self.peek() {
            self.at += 1;
            let r = self.term()?;
            v = if o == '+' { v + r } else { v - r };
        }
        Ok(v)
    }

    /// Whether the next token starts a value, for implied multiplication.
    fn starts_value(&self) -> bool {
        matches!(self.peek(), Some(Tok::Num(_) | Tok::Open | Tok::Func(_)))
    }

    fn term(&mut self) -> Result<f64, Error> {
        let mut v = self.unary()?;
        loop {
            match self.peek() {
                Some(Tok::Op(o @ ('*' | '/'))) => {
                    self.at += 1;
                    let r = self.unary()?;
                    if o == '/' && r == 0.0 {
                        return Err(Error::DivideByZero);
                    }
                    v = if o == '*' { v * r } else { v / r };
                }
                _ if self.starts_value() => v *= self.power()?,
                _ => return Ok(v),
            }
        }
    }

    fn unary(&mut self) -> Result<f64, Error> {
        match self.peek() {
            Some(Tok::Op('-')) => {
                self.at += 1;
                Ok(-self.unary()?)
            }
            Some(Tok::Op('+')) => {
                self.at += 1;
                self.unary()
            }
            _ => self.power(),
        }
    }

    fn power(&mut self) -> Result<f64, Error> {
        let base = self.postfix()?;
        if self.peek() == Some(Tok::Op('^')) {
            self.at += 1;
            let e = self.unary()?;
            if base == 0.0 && e < 0.0 {
                return Err(Error::DivideByZero);
            }
            let v = m::pow_(base, e);
            return if v.is_nan() { Err(Error::Domain) } else { Ok(v) };
        }
        Ok(base)
    }

    fn postfix(&mut self) -> Result<f64, Error> {
        let mut v = self.primary()?;
        loop {
            match self.peek() {
                Some(Tok::Bang) => {
                    self.at += 1;
                    v = factorial(v)?;
                }
                Some(Tok::Percent) => {
                    self.at += 1;
                    v /= 100.0;
                }
                _ => return Ok(v),
            }
        }
    }

    fn primary(&mut self) -> Result<f64, Error> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(n),
            Some(Tok::Open) => {
                let v = self.expr()?;
                // Brackets left open close at the end.
                match self.next() {
                    Some(Tok::Close) | None => Ok(v),
                    Some(_) => Err(Error::Syntax),
                }
            }
            Some(Tok::Func(f)) => {
                // `sin(30)`: the bracket is the argument, so `√(2)^2` is
                // 2. Without brackets a power binds to the argument:
                // `sin 2^2` is sin 4.
                let x = if self.peek() == Some(Tok::Open) { self.primary()? } else { self.power_of_primary()? };
                apply(f, x, self.angle)
            }
            _ => Err(Error::Syntax),
        }
    }

    /// A function's argument: a primary with its postfix operators and a
    /// power, but no implied multiplication beyond it.
    fn power_of_primary(&mut self) -> Result<f64, Error> {
        if self.peek() == Some(Tok::Op('-')) {
            self.at += 1;
            return Ok(-self.power_of_primary()?);
        }
        self.power()
    }
}

fn factorial(x: f64) -> Result<f64, Error> {
    if x < 0.0 || m::trunc_(x) != x {
        return Err(Error::Domain);
    }
    if x > 170.0 {
        return Err(Error::Overflow);
    }
    Ok((1..=x as u32).fold(1.0, |a, k| a * f64::from(k)))
}

fn apply(f: Func, x: f64, angle: Angle) -> Result<f64, Error> {
    let to_rad = |x: f64| if angle == Angle::Degrees { x * core::f64::consts::PI / 180.0 } else { x };
    let from_rad = |x: f64| if angle == Angle::Degrees { x * 180.0 / core::f64::consts::PI } else { x };
    // Degrees land exactly on the values people expect (sin 180 is 0,
    // tan 45 is 1), not a rounding error away from them.
    let exact = |deg: f64| -> Option<f64> {
        if angle != Angle::Degrees || m::trunc_(deg) != deg {
            return None;
        }
        let d = m::fmod_(deg, 360.0);
        let d = if d < 0.0 { d + 360.0 } else { d };
        Some(d)
    };
    let v = match f {
        Func::Sin => match exact(x) {
            Some(d) if d % 180.0 == 0.0 => 0.0,
            Some(30.0 | 150.0) => 0.5,
            Some(210.0 | 330.0) => -0.5,
            Some(90.0) => 1.0,
            Some(270.0) => -1.0,
            _ => m::sin_(to_rad(x)),
        },
        Func::Cos => match exact(x) {
            Some(90.0 | 270.0) => 0.0,
            Some(60.0 | 300.0) => 0.5,
            Some(120.0 | 240.0) => -0.5,
            Some(0.0) => 1.0,
            Some(180.0) => -1.0,
            _ => m::cos_(to_rad(x)),
        },
        Func::Tan => match exact(x) {
            Some(90.0 | 270.0) => return Err(Error::Domain),
            Some(d) if d % 180.0 == 0.0 => 0.0,
            Some(45.0 | 225.0) => 1.0,
            Some(135.0 | 315.0) => -1.0,
            _ => m::tan_(to_rad(x)),
        },
        Func::Asin | Func::Acos if !(-1.0..=1.0).contains(&x) => return Err(Error::Domain),
        Func::Asin => from_rad(m::asin_(x)),
        Func::Acos => from_rad(m::acos_(x)),
        Func::Atan => from_rad(m::atan_(x)),
        Func::Sinh => m::sinh_(x),
        Func::Cosh => m::cosh_(x),
        Func::Tanh => m::tanh_(x),
        Func::Asinh => m::asinh_(x),
        Func::Acosh if x < 1.0 => return Err(Error::Domain),
        Func::Acosh => m::acosh_(x),
        Func::Atanh if x <= -1.0 || x >= 1.0 => return Err(Error::Domain),
        Func::Atanh => m::atanh_(x),
        Func::Ln | Func::Log if x <= 0.0 => return Err(Error::Domain),
        Func::Ln => m::log_(x),
        Func::Log => m::log10_(x),
        Func::Sqrt if x < 0.0 => return Err(Error::Domain),
        Func::Sqrt => m::sqrt_(x),
        Func::Exp => m::exp_(x),
        Func::Abs => m::fabs_(x),
    };
    Ok(v)
}

/// The value of `s`, with `ans` the last answer.
pub fn eval(s: &str, ans: f64, angle: Angle) -> Result<f64, Error> {
    eval_with(s, ans, 0.0, angle)
}

/// The value of `s`, with `ans` the last answer and `mem` the memory.
pub fn eval_with(s: &str, ans: f64, mem: f64, angle: Angle) -> Result<f64, Error> {
    let toks = tokens(s, ans, mem)?;
    if toks.is_empty() {
        return Err(Error::Empty);
    }
    let mut p = Parser { toks, at: 0, angle };
    let v = p.expr()?;
    // Closing brackets with nothing open to close are a mistake.
    if p.at < p.toks.len() {
        return Err(Error::Syntax);
    }
    if v.is_nan() {
        return Err(Error::Domain);
    }
    if v.is_infinite() {
        return Err(Error::Overflow);
    }
    Ok(if v == 0.0 { 0.0 } else { v })
}

/// `v` as people read it: up to 12 significant digits, no trailing zeros,
/// and scientific notation (`1.5e-9`, `6.02e23`) outside 10^-6 to 10^15.
pub fn format(v: f64) -> String {
    if v == 0.0 {
        return String::from("0");
    }
    if !v.is_finite() {
        return String::from(if v.is_nan() { "NaN" } else { "∞" });
    }
    // The 12 significant digits and the exponent, from core's formatting.
    let sci = alloc::format!("{:.11e}", v);
    let (mant, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if (-6..15).contains(&exp) {
        if exp < 0 {
            out.push_str("0.");
            for _ in 0..(-exp - 1) {
                out.push('0');
            }
            out.push_str(digits);
        } else {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                out.push_str(digits);
                for _ in digits.len()..int_len {
                    out.push('0');
                }
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push_str(&alloc::format!("{exp}"));
    }
    out
}

/// A whole `v` in base 16, 8 or 2 (`0x1F`, `-0o17`, `0b101`); None if it
/// isn't whole or is too large to be exact (2^53).
pub fn format_base(v: f64, base: u32) -> Option<String> {
    if m::trunc_(v) != v || m::fabs_(v) > 9_007_199_254_740_992.0 {
        return None;
    }
    let n = m::fabs_(v) as u64;
    let digits = match base {
        16 => alloc::format!("0x{n:X}"),
        8 => alloc::format!("0o{n:o}"),
        2 => alloc::format!("0b{n:b}"),
        _ => return None,
    };
    Some(if v < 0.0 { alloc::format!("-{digits}") } else { digits })
}

/// [`format`]'s text with the whole part's digits in threes
/// (`1,234,567.5`), for the eyes; copies and pastes keep [`format`]'s.
pub fn grouped(text: &str) -> String {
    if text.contains('e') {
        return String::from(text);
    }
    let (sign, rest) = text.strip_prefix('-').map_or(("", text), |r| ("-", r));
    let (int, frac) = rest.split_once('.').map_or((rest, None), |(i, f)| (i, Some(f)));
    let mut out = String::from(sign);
    for (i, d) in int.chars().enumerate() {
        if i > 0 && (int.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(d);
    }
    if let Some(f) = frac {
        out.push('.');
        out.push_str(f);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(s: &str) -> Result<f64, Error> {
        eval(s, 42.0, Angle::Degrees)
    }

    #[test]
    fn arithmetic() {
        assert_eq!(ev("1+2*3"), Ok(7.0));
        assert_eq!(ev("(1+2)×3"), Ok(9.0));
        assert_eq!(ev("10 ÷ 4"), Ok(2.5));
        assert_eq!(ev("-3^2"), Ok(-9.0));
        assert_eq!(ev("2^3^2"), Ok(512.0));
        assert_eq!(ev("2^-1"), Ok(0.5));
        assert_eq!(ev("5!"), Ok(120.0));
        assert_eq!(ev("50%"), Ok(0.5));
        assert_eq!(ev("2(3+4"), Ok(14.0));
        assert_eq!(ev("3(1+2)2"), Ok(18.0));
        assert_eq!(ev("ans/2"), Ok(21.0));
        assert_eq!(ev("1.5e3 + .5"), Ok(1500.5));
        assert_eq!(ev("0.1+0.2").map(format).as_deref(), Ok("0.3"));
    }

    #[test]
    fn functions_and_constants() {
        assert_eq!(ev("sin 30"), Ok(0.5));
        assert_eq!(ev("sin(180)"), Ok(0.0));
        assert_eq!(ev("cos 60"), Ok(0.5));
        assert_eq!(ev("tan 45"), Ok(1.0));
        assert_eq!(ev("√16"), Ok(4.0));
        assert_eq!(ev("sqrt(2)^2").map(format).as_deref(), Ok("2"));
        assert_eq!(ev("log 1000"), Ok(3.0));
        assert_eq!(ev("ln e"), Ok(1.0));
        assert_eq!(ev("2π").map(format).as_deref(), Ok("6.28318530718"));
        assert_eq!(ev("asin 1"), Ok(90.0));
        assert_eq!(ev("abs -4"), Ok(4.0));
        assert_eq!(ev("sin 2^2"), ev("sin 4"));
        assert_eq!(eval("sin(pi/2)", 0.0, Angle::Radians), Ok(1.0));
        assert_eq!(eval("cos π", 0.0, Angle::Radians), Ok(-1.0));
        assert_eq!(ev("sinh 0"), Ok(0.0));
        assert_eq!(ev("cosh 0"), Ok(1.0));
        assert_eq!(ev("tanh(1)").map(format).as_deref(), Ok("0.761594155956"));
        assert_eq!(ev("asinh(sinh 2)").map(format).as_deref(), Ok("2"));
        assert_eq!(ev("acosh 1"), Ok(0.0));
        assert_eq!(ev("acosh 0.5"), Err(Error::Domain));
        assert_eq!(ev("atanh 1"), Err(Error::Domain));
        assert_eq!(eval_with("mem/2 + ans", 1.0, 42.0, Angle::Degrees), Ok(22.0));
    }

    #[test]
    fn bases_and_grouping() {
        assert_eq!(ev("0x1f + 1"), Ok(32.0));
        assert_eq!(ev("0b101 × 0o10"), Ok(40.0));
        assert_eq!(ev("0xFF"), Ok(255.0));
        assert_eq!(ev("0x"), Err(Error::Syntax), "no digits");
        assert_eq!(ev("10 0b1"), Ok(10.0), "implied multiplication");
        assert_eq!(format_base(255.0, 16).as_deref(), Some("0xFF"));
        assert_eq!(format_base(-15.0, 8).as_deref(), Some("-0o17"));
        assert_eq!(format_base(5.0, 2).as_deref(), Some("0b101"));
        assert_eq!(format_base(2.5, 16), None);
        assert_eq!(format_base(1e20, 16), None);
        assert_eq!(grouped("1234567.25"), "1,234,567.25");
        assert_eq!(grouped("-1234"), "-1,234");
        assert_eq!(grouped("123"), "123");
        assert_eq!(grouped("6.02e23"), "6.02e23");
    }

    #[test]
    fn errors() {
        assert_eq!(ev(""), Err(Error::Empty));
        assert_eq!(ev("2+"), Err(Error::Syntax));
        assert_eq!(ev("2)"), Err(Error::Syntax));
        assert_eq!(ev("×3"), Err(Error::Syntax));
        assert_eq!(ev("foo"), Err(Error::Syntax));
        assert_eq!(ev("1/0"), Err(Error::DivideByZero));
        assert_eq!(ev("√-1"), Err(Error::Domain));
        assert_eq!(ev("ln 0"), Err(Error::Domain));
        assert_eq!(ev("2.5!"), Err(Error::Domain));
        assert_eq!(ev("tan 90"), Err(Error::Domain));
        assert_eq!(ev("171!"), Err(Error::Overflow));
        assert_eq!(ev("10^400"), Err(Error::Overflow));
    }

    #[test]
    fn formatting() {
        assert_eq!(format(0.0), "0");
        assert_eq!(format(-2.5), "-2.5");
        assert_eq!(format(1.0 / 3.0), "0.333333333333");
        assert_eq!(format(1234567.0), "1234567");
        assert_eq!(format(120.0), "120");
        assert_eq!(format(0.000015), "0.000015");
        assert_eq!(format(1.5e-9), "1.5e-9");
        assert_eq!(format(6.02e23), "6.02e23");
        assert_eq!(format(1e15), "1e15");
        assert_eq!(format(123456789012.0), "123456789012");
    }
}
