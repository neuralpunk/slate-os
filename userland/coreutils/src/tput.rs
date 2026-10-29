// SPDX-License-Identifier: MIT OR Apache-2.0

//! tput: print a terminal capability for `$TERM` (or `-T`). The
//! description comes from the terminfo database when there is one (the
//! compiled entries term(5) documents, legacy and 32-bit-number formats,
//! with user_caps(5)'s extended capabilities; ADR 0144), else from the
//! descriptions here of the terminals Slate itself provides (the
//! console, `linux`; its terminal, `xterm-256color`) and a few common
//! ones, in terminfo(5)'s notation, from the control functions of
//! ECMA-48 and xterm's documented sequences. Parameters go through a
//! terminfo(5) `%` interpreter of Slate's own. Exit status as tput(1): 1
//! for a capability the terminal lacks, 2 for usage, 3 for an unknown
//! terminal, 4 for an unknown capability.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{env, io, lossy, println, term};

use crate::util::error;

/// One terminal description: names, booleans, numbers, strings.
struct Desc {
    names: &'static [&'static str],
    long: &'static str,
    bools: &'static [&'static str],
    nums: &'static [(&'static str, i32)],
    strs: &'static [(&'static str, &'static str)],
    /// Shared ANSI sequences this terminal lacks.
    absent: &'static [&'static str],
    /// Another description this one adds to.
    base: Option<&'static Desc>,
}

// ECMA-48 control sequences shared by every ANSI terminal below:
// CUP, CUU/CUD/CUF/CUB, ED, EL, SGR, DECSTBM, IL/DL, ICH/DCH.
const ANSI: &[(&str, &str)] = &[
    ("bel", "^G"),
    ("cr", "\\r"),
    ("ht", "^I"),
    ("ind", "\\n"),
    ("cud1", "\\n"),
    ("cub1", "^H"),
    ("cuf1", "\\E[C"),
    ("cuu1", "\\E[A"),
    ("cup", "\\E[%i%p1%d;%p2%dH"),
    ("cuu", "\\E[%p1%dA"),
    ("cud", "\\E[%p1%dB"),
    ("cuf", "\\E[%p1%dC"),
    ("cub", "\\E[%p1%dD"),
    ("home", "\\E[H"),
    ("ed", "\\E[J"),
    ("el", "\\E[K"),
    ("el1", "\\E[1K"),
    ("csr", "\\E[%i%p1%d;%p2%dr"),
    ("sc", "\\E7"),
    ("rc", "\\E8"),
    ("ri", "\\EM"),
    ("bold", "\\E[1m"),
    ("smul", "\\E[4m"),
    ("rmul", "\\E[24m"),
    ("blink", "\\E[5m"),
    ("rev", "\\E[7m"),
    ("smso", "\\E[7m"),
    ("rmso", "\\E[27m"),
    ("smam", "\\E[?7h"),
    ("rmam", "\\E[?7l"),
    ("kcuu1", "\\EOA"),
    ("kcud1", "\\EOB"),
    ("kcuf1", "\\EOC"),
    ("kcub1", "\\EOD"),
    ("kf1", "\\EOP"),
];

// The editing functions and colours of xterm-like terminals (ECMA-48
// IL/DL/ICH/DCH/ECH/HPA/VPA, SGR 30-49).
const EDITING: &[(&str, &str)] = &[
    ("il1", "\\E[L"),
    ("il", "\\E[%p1%dL"),
    ("dl1", "\\E[M"),
    ("dl", "\\E[%p1%dM"),
    ("ich", "\\E[%p1%d@"),
    ("dch1", "\\E[P"),
    ("dch", "\\E[%p1%dP"),
    ("hpa", "\\E[%i%p1%dG"),
    ("vpa", "\\E[%i%p1%dd"),
    ("op", "\\E[39;49m"),
    ("setaf", "\\E[3%p1%dm"),
    ("setab", "\\E[4%p1%dm"),
    ("kbs", "^?"),
    ("kich1", "\\E[2~"),
    ("kdch1", "\\E[3~"),
    ("kpp", "\\E[5~"),
    ("knp", "\\E[6~"),
    ("kf12", "\\E[24~"),
];

static VT100: Desc = Desc {
    names: &["vt100", "vt100-am"],
    long: "DEC VT100 (w/advanced video)",
    bools: &["am", "msgr", "xenl"],
    nums: &[("cols", 80), ("lines", 24), ("it", 8)],
    strs: &[
        ("clear", "\\E[H\\E[J"),
        ("sgr0", "\\E[m^O"),
        ("sgr", "\\E[0%?%p6%t;1%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;m%?%p9%t^N%e^O%;"),
        ("kbs", "^H"),
        ("smkx", "\\E[?1h\\E="),
        ("rmkx", "\\E[?1l\\E>"),
        ("kf5", "\\EOt"),
        ("rs2", "\\E<\\E>\\E[?3;4;5l\\E[?7;8h\\E[r"),
    ],
    absent: &[],
    base: None,
};

static XTERM: Desc = Desc {
    names: &["xterm", "xterm-new"],
    long: "xterm terminal emulator (X Window System)",
    bools: &["am", "bce", "km", "mir", "msgr", "xenl"],
    nums: &[("cols", 80), ("lines", 24), ("it", 8), ("colors", 8), ("pairs", 64)],
    strs: &[
        ("clear", "\\E[H\\E[2J"),
        ("E3", "\\E[3J"),
        ("sgr0", "\\E(B\\E[m"),
        ("sgr", "\\E[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;%?%p7%t;8%;m%?%p9%t\\E(0%e\\E(B%;"),
        ("dim", "\\E[2m"),
        ("sitm", "\\E[3m"),
        ("ritm", "\\E[23m"),
        ("invis", "\\E[8m"),
        ("civis", "\\E[?25l"),
        ("cnorm", "\\E[?12l\\E[?25h"),
        ("smcup", "\\E[?1049h\\E[22;0;0t"),
        ("rmcup", "\\E[?1049l\\E[23;0;0t"),
        ("ech", "\\E[%p1%dX"),
        ("flash", "\\E[?5h$<100/>\\E[?5l"),
        ("smkx", "\\E[?1h\\E="),
        ("rmkx", "\\E[?1l\\E>"),
        ("is2", "\\E[!p\\E[?3;4l\\E[4l\\E>"),
        ("rs1", "\\Ec\\E]104^G"),
        ("rs2", "\\E[!p\\E[?3;4l\\E[4l\\E>"),
        ("khome", "\\EOH"),
        ("kend", "\\EOF"),
        ("kf5", "\\E[15~"),
    ],
    absent: &[],
    base: None,
};

static XTERM_256: Desc = Desc {
    names: &["xterm-256color"],
    long: "xterm with 256 colors",
    bools: &[],
    nums: &[("colors", 256), ("pairs", 65536)],
    strs: &[
        ("clear", "\\E[H\\E[2J"),
        ("E3", "\\E[3J"),
        ("setaf", "\\E[%?%p1%{8}%<%t3%p1%d%e%p1%{16}%<%t9%p1%{8}%-%d%e38;5;%p1%d%;m"),
        ("setab", "\\E[%?%p1%{8}%<%t4%p1%d%e%p1%{16}%<%t10%p1%{8}%-%d%e48;5;%p1%d%;m"),
    ],
    absent: &[],
    base: Some(&XTERM),
};

static LINUX: Desc = Desc {
    names: &["linux", "linux-16color"],
    long: "Linux console",
    bools: &["am", "bce", "eo", "mir", "msgr", "xenl"],
    nums: &[("cols", 80), ("lines", 24), ("it", 8), ("colors", 8), ("pairs", 64)],
    strs: &[
        ("clear", "\\E[H\\E[J"),
        ("E3", "\\E[3J"),
        ("sgr0", "\\E[m^O"),
        // terminfo(5)'s sgr parameters: standout, underline, reverse,
        // blink, dim, bold, invisible, protect, alternate characters.
        ("sgr", "\\E[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;m%?%p9%t^N%e^O%;"),
        ("dim", "\\E[2m"),
        ("civis", "\\E[?25l\\E[?1c"),
        ("cnorm", "\\E[?25h\\E[?0c"),
        ("ech", "\\E[%p1%dX"),
        ("flash", "\\E[?5h\\E[?5l$<200/>"),
        ("rs1", "\\Ec\\E]R"),
        ("kcuu1", "\\E[A"),
        ("kcud1", "\\E[B"),
        ("kcuf1", "\\E[C"),
        ("kcub1", "\\E[D"),
        ("khome", "\\E[1~"),
        ("kend", "\\E[4~"),
        ("kf1", "\\E[[A"),
        ("kf5", "\\E[[E"),
    ],
    absent: &[],
    base: None,
};

static SCREEN: Desc = Desc {
    names: &["screen", "tmux"],
    absent: &["smam", "rmam", "ech"],
    long: "VT 100/ANSI X3.64 virtual terminal",
    bools: &["am", "km", "mir", "msgr", "xenl"],
    nums: &[("cols", 80), ("lines", 24), ("it", 8), ("colors", 8), ("pairs", 64)],
    strs: &[
        ("clear", "\\E[H\\E[J"),
        ("sgr0", "\\E[m^O"),
        ("sgr", "\\E[0%?%p6%t;1%;%?%p5%t;2%;%?%p2%t;4%;%?%p1%p3%|%t;7%;%?%p4%t;5%;m%?%p9%t^N%e^O%;"),
        ("dim", "\\E[2m"),
        ("civis", "\\E[?25l"),
        ("cnorm", "\\E[34h\\E[?25h"),
        ("smcup", "\\E[?1049h"),
        ("rmcup", "\\E[?1049l"),
        ("flash", "\\Eg"),
        ("smkx", "\\E[?1h\\E="),
        ("rmkx", "\\E[?1l\\E>"),
        ("is2", "\\E)0"),
        ("rs2", "\\Ec\\E[?1000l\\E[?25h"),
        ("khome", "\\E[1~"),
        ("kend", "\\E[4~"),
        ("kf5", "\\E[15~"),
    ],
    base: None,
};

static DUMB: Desc = Desc {
    names: &["dumb"],
    long: "80-column dumb tty",
    bools: &["am"],
    nums: &[("cols", 80)],
    strs: &[("bel", "^G"), ("cr", "\\r"), ("cud1", "\\n"), ("ind", "\\n")],
    absent: &[],
    base: None,
};

static ALL: [&Desc; 6] = [&XTERM_256, &XTERM, &LINUX, &VT100, &SCREEN, &DUMB];

fn lookup(term: &str) -> Option<&'static Desc> {
    ALL.iter().copied().find(|d| d.names.contains(&term)).or_else(|| {
        // Variants of a known family: xterm-*, screen-*, tmux-*.
        let base = term.split('-').next()?;
        let d = ALL.iter().copied().find(|d| d.names.contains(&base))?;
        Some(if term.ends_with("256color") && base == "xterm" { &XTERM_256 } else { d })
    })
}

fn has_bool(d: &Desc, c: &str) -> bool {
    d.bools.contains(&c) || d.base.is_some_and(|b| has_bool(b, c))
}

fn num(d: &Desc, c: &str) -> Option<i32> {
    d.nums.iter().find(|(n, _)| *n == c).map(|(_, v)| *v).or_else(|| d.base.and_then(|b| num(b, c)))
}

fn string(d: &Desc, c: &str) -> Option<&'static str> {
    if d.absent.contains(&c) {
        return None;
    }
    let own = d.strs.iter().find(|(n, _)| *n == c).map(|(_, v)| *v);
    own.or_else(|| d.base.and_then(|b| string(b, c)))
        .or_else(|| {
            // ANSI terminals share ECMA-48's sequences; xterm-likes the
            // editing functions too.
            if core::ptr::eq(d, &DUMB) {
                return None;
            }
            let ansi = ANSI.iter().find(|(n, _)| *n == c).map(|(_, v)| *v);
            let editing = !core::ptr::eq(d, &VT100);
            ansi.or_else(|| if editing { EDITING.iter().find(|(n, _)| *n == c).map(|(_, v)| *v) } else { None })
        })
        .filter(|v| !v.is_empty())
}

/// terminfo(5) escapes: `\E`, `^X`, `\n`, `\r`, `\t`, `\b`, `\f`, `\s`,
/// `\0`, `\NNN`, `\\`, `\^`, `\,`, `\:`.
fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                i += 1;
                match b[i] {
                    b'E' | b'e' => out.push(27),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b's' => out.push(b' '),
                    b'0'..=b'7' => {
                        let mut v = 0u32;
                        let mut n = 0;
                        while n < 3 && i < b.len() && (b'0'..=b'7').contains(&b[i]) {
                            v = v * 8 + u32::from(b[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        // \0 is a null that does not end the string (0200).
                        out.push(if v == 0 { 0x80 } else { v as u8 });
                        continue;
                    }
                    c => out.push(c),
                }
                i += 1;
            }
            b'^' if i + 1 < b.len() => {
                let c = b[i + 1];
                out.push(if c == b'?' { 127 } else { c & 0x1f });
                i += 2;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

#[derive(Clone, Debug)]
pub enum Val {
    Int(i64),
    Str(Vec<u8>),
}

impl Val {
    fn int(&self) -> i64 {
        match self {
            Val::Int(n) => *n,
            Val::Str(_) => 0,
        }
    }
}

/// A capability as sent without parameters: `$<...>` padding dropped,
/// `%` codes left as they are (as tput does when given no parameters).
pub fn unpadded(cap: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cap.len() {
        if cap[i] == b'$'
            && cap.get(i + 1) == Some(&b'<')
            && let Some(end) = cap[i..].iter().position(|&x| x == b'>')
        {
            i += end + 1;
            continue;
        }
        out.push(cap[i]);
        i += 1;
    }
    out
}

/// Expand a capability's `%` codes with `params` (terminfo(5),
/// "Parameterized Strings"), dropping `$<...>` padding.
pub fn tparm(cap: &[u8], params: &[Val]) -> Vec<u8> {
    let mut p: [Val; 9] = core::array::from_fn(|i| params.get(i).cloned().unwrap_or(Val::Int(0)));
    let mut stack: Vec<Val> = Vec::new();
    let mut dynamic: [i64; 26] = [0; 26];
    let mut statics: [i64; 26] = [0; 26];
    let mut out = Vec::new();
    let pop = |s: &mut Vec<Val>| s.pop().unwrap_or(Val::Int(0));
    let mut i = 0;
    while i < cap.len() {
        let c = cap[i];
        if c == b'$' && cap.get(i + 1) == Some(&b'<') {
            match cap[i..].iter().position(|&x| x == b'>') {
                Some(end) => {
                    i += end + 1;
                    continue;
                }
                None => {
                    out.push(c);
                    i += 1;
                    continue;
                }
            }
        }
        if c != b'%' || i + 1 >= cap.len() {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        let op = cap[i];
        i += 1;
        match op {
            b'%' => out.push(b'%'),
            b'd' | b'o' | b'x' | b'X' | b's' => {
                let v = pop(&mut stack);
                out.extend_from_slice(&format_one(b"", op, &v));
            }
            b'c' => out.push(pop(&mut stack).int() as u8),
            b'i' => {
                for v in p.iter_mut().take(2) {
                    if let Val::Int(n) = v {
                        *n += 1;
                    }
                }
            }
            b'p' => {
                let k = cap.get(i).map(|d| d.wrapping_sub(b'1') as usize).unwrap_or(9);
                i += 1;
                stack.push(p.get(k).cloned().unwrap_or(Val::Int(0)));
            }
            b'P' | b'g' => {
                let v = cap.get(i).copied().unwrap_or(b'a');
                i += 1;
                let (slot, idx) = if v.is_ascii_uppercase() {
                    (&mut statics, usize::from(v - b'A'))
                } else {
                    (&mut dynamic, usize::from(v.wrapping_sub(b'a')).min(25))
                };
                if op == b'P' {
                    slot[idx.min(25)] = pop(&mut stack).int();
                } else {
                    stack.push(Val::Int(slot[idx.min(25)]));
                }
            }
            b'\'' => {
                let ch = cap.get(i).copied().unwrap_or(0);
                i += 2;
                stack.push(Val::Int(i64::from(ch)));
            }
            b'{' => {
                let end = cap[i..].iter().position(|&x| x == b'}').map(|e| i + e).unwrap_or(cap.len());
                let n = core::str::from_utf8(&cap[i..end]).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                stack.push(Val::Int(n));
                i = end + 1;
            }
            b'l' => {
                let n = match pop(&mut stack) {
                    Val::Str(s) => s.len() as i64,
                    Val::Int(_) => 0,
                };
                stack.push(Val::Int(n));
            }
            b'+' | b'-' | b'*' | b'/' | b'm' | b'&' | b'|' | b'^' | b'=' | b'>' | b'<' | b'A' | b'O' => {
                let b = pop(&mut stack).int();
                let a = pop(&mut stack).int();
                let r = match op {
                    b'+' => a.wrapping_add(b),
                    b'-' => a.wrapping_sub(b),
                    b'*' => a.wrapping_mul(b),
                    b'/' => a.checked_div(b).unwrap_or(0),
                    b'm' => a.checked_rem(b).unwrap_or(0),
                    b'&' => a & b,
                    b'|' => a | b,
                    b'^' => a ^ b,
                    b'=' => i64::from(a == b),
                    b'>' => i64::from(a > b),
                    b'<' => i64::from(a < b),
                    b'A' => i64::from(a != 0 && b != 0),
                    _ => i64::from(a != 0 || b != 0),
                };
                stack.push(Val::Int(r));
            }
            b'!' => {
                let a = pop(&mut stack).int();
                stack.push(Val::Int(i64::from(a == 0)));
            }
            b'~' => {
                let a = pop(&mut stack).int();
                stack.push(Val::Int(!a));
            }
            b'?' | b';' => {}
            b't' => {
                if pop(&mut stack).int() == 0 {
                    // Skip to the matching %e or %; at this nesting level.
                    i = skip_branch(cap, i, true);
                }
            }
            b'e' => {
                // Reached the end of a taken branch: skip the else part.
                i = skip_branch(cap, i, false);
            }
            _ => {
                // %[[:]flags][width[.precision]][doxXs]
                let start = i - 1;
                let mut j = start;
                if cap.get(j) == Some(&b':') {
                    j += 1;
                }
                while j < cap.len() && !matches!(cap[j], b'd' | b'o' | b'x' | b'X' | b's') {
                    j += 1;
                }
                if j >= cap.len() {
                    break;
                }
                let spec = &cap[start..j];
                let conv = cap[j];
                i = j + 1;
                let v = pop(&mut stack);
                out.extend_from_slice(&format_one(spec, conv, &v));
            }
        }
    }
    out
}

/// After `%t` (false) or `%e`: skip to the matching `%e` (only after a
/// false `%t`) or `%;`.
fn skip_branch(cap: &[u8], mut i: usize, stop_at_else: bool) -> usize {
    let mut depth = 0;
    while i + 1 < cap.len() {
        if cap[i] == b'%' {
            match cap[i + 1] {
                b'?' => depth += 1,
                b';' if depth == 0 => return i + 2,
                b';' => depth -= 1,
                b'e' if depth == 0 && stop_at_else => return i + 2,
                _ => {}
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    cap.len()
}

fn format_one(spec: &[u8], conv: u8, v: &Val) -> Vec<u8> {
    let spec = spec.strip_prefix(b":").unwrap_or(spec);
    let (mut left, mut plus, mut space, mut alt, mut zero) = (false, false, false, false, false);
    let mut k = 0;
    while k < spec.len() && b"-+ #0".contains(&spec[k]) {
        match spec[k] {
            b'-' => left = true,
            b'+' => plus = true,
            b' ' => space = true,
            b'#' => alt = true,
            _ => zero = true,
        }
        k += 1;
    }
    let rest = core::str::from_utf8(&spec[k..]).unwrap_or("");
    let (w, prec) = match rest.split_once('.') {
        Some((a, b)) => (a.parse().unwrap_or(0), b.parse::<usize>().ok()),
        None => (rest.parse().unwrap_or(0), None),
    };
    let mut body = match (conv, v) {
        (b's', Val::Str(s)) => s.clone(),
        (b's', Val::Int(n)) => alloc::format!("{n}").into_bytes(),
        _ => {
            let n = v.int();
            let mut digits = match conv {
                b'o' => alloc::format!("{n:o}"),
                b'x' => alloc::format!("{n:x}"),
                b'X' => alloc::format!("{n:X}"),
                _ => alloc::format!("{}", n.unsigned_abs()),
            };
            if let Some(p) = prec {
                while digits.len() < p {
                    digits.insert(0, '0');
                }
            }
            let mut s = String::new();
            if conv == b'd' {
                if n < 0 {
                    s.push('-');
                } else if plus {
                    s.push('+');
                } else if space {
                    s.push(' ');
                }
            }
            if alt {
                match conv {
                    b'o' if !digits.starts_with('0') => s.push('0'),
                    b'x' => s.push_str("0x"),
                    b'X' => s.push_str("0X"),
                    _ => {}
                }
            }
            if zero && !left && prec.is_none() {
                while s.len() + digits.len() < w {
                    digits.insert(0, '0');
                }
            }
            s.push_str(&digits);
            s.into_bytes()
        }
    };
    if conv == b's'
        && let Some(p) = prec
    {
        body.truncate(p);
    }
    while body.len() < w {
        if left {
            body.push(b' ');
        } else {
            body.insert(0, b' ');
        }
    }
    body
}

/// A capability's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Bool,
    Num,
    Str,
}

/// A terminal's description: from the terminfo database, or one of the
/// descriptions here. Strings are as sent (escapes interpreted).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Terminal {
    pub names: Vec<String>,
    bools: Vec<String>,
    nums: Vec<(String, i32)>,
    strs: Vec<(String, Vec<u8>)>,
    /// The extended capabilities it names (user_caps(5)), with kinds.
    extended: Vec<(String, Kind)>,
}

impl Terminal {
    fn has(&self, c: &str) -> bool {
        self.bools.iter().any(|b| b == c)
    }

    fn num(&self, c: &str) -> Option<i32> {
        self.nums.iter().find(|(n, _)| n == c).map(|(_, v)| *v)
    }

    fn string(&self, c: &str) -> Option<&[u8]> {
        self.strs.iter().find(|(n, _)| n == c).map(|(_, v)| v.as_slice())
    }

    /// What kind `c` is: a standard capability, or one of this entry's
    /// extended ones; `None` is unknown.
    fn kind(&self, c: &str) -> Option<Kind> {
        use crate::terminfo_caps::{BOOLEANS, NUMBERS, STRINGS};
        if BOOLEANS.contains(&c) {
            Some(Kind::Bool)
        } else if NUMBERS.contains(&c) {
            Some(Kind::Num)
        } else if STRINGS.contains(&c) {
            Some(Kind::Str)
        } else {
            self.extended.iter().find(|(n, _)| n == c).map(|(_, k)| *k)
        }
    }

    /// The long name: the last of the names (term(5)).
    fn long_name(&self) -> &str {
        self.names.last().map_or("", String::as_str)
    }

    /// One of the descriptions here, every capability resolved.
    fn from_desc(d: &Desc) -> Terminal {
        use crate::terminfo_caps::{BOOLEANS, NUMBERS, STRINGS};
        let mut names: Vec<String> = d.names.iter().map(|n| String::from(*n)).collect();
        names.push(String::from(d.long));
        let mut t = Terminal { names, ..Default::default() };
        t.bools = BOOLEANS.iter().filter(|b| has_bool(d, b)).map(|b| String::from(*b)).collect();
        t.nums = NUMBERS.iter().filter_map(|n| Some((String::from(*n), num(d, n)?))).collect();
        t.strs = STRINGS.iter().filter_map(|c| Some((String::from(*c), unescape(string(d, c)?)))).collect();
        // Extended strings (E3), from this description or its base.
        let mut at = Some(d);
        while let Some(x) = at {
            for (n, v) in x.strs.iter().filter(|(n, _)| !STRINGS.contains(n)) {
                if t.string(n).is_none() {
                    t.strs.push((String::from(*n), unescape(v)));
                    t.extended.push((String::from(*n), Kind::Str));
                }
            }
            at = x.base;
        }
        t
    }

    /// A compiled entry (term(5)): the legacy format (magic 0432, 16-bit
    /// numbers) or the extended number format (01036, 32-bit), each
    /// maybe followed by the extended capabilities. Cancelled (-2) and
    /// absent (-1) capabilities are left out.
    pub fn parse(d: &[u8]) -> Option<Terminal> {
        use crate::terminfo_caps::{BOOLEANS, NUMBERS, STRINGS};
        let short = |at: usize| -> Option<i16> { Some(i16::from_le_bytes([*d.get(at)?, *d.get(at + 1)?])) };
        let count = |at: usize| -> Option<usize> { usize::try_from(short(at)?).ok() };
        let width = match short(0)? {
            0o432 => 2,
            0o1036 => 4,
            _ => return None,
        };
        let (names, bools, nums, strs, table) = (count(2)?, count(4)?, count(6)?, count(8)?, count(10)?);
        let mut t = Terminal::default();
        let mut at = 12;
        let name_bytes = d.get(at..at + names)?;
        let name_text = name_bytes.split(|&c| c == 0).next()?;
        t.names = name_text.split(|&c| c == b'|').map(|n| String::from(lossy(n))).collect();
        at += names;
        for (i, &b) in d.get(at..at + bools)?.iter().enumerate() {
            if b == 1
                && let Some(n) = BOOLEANS.get(i)
            {
                t.bools.push(String::from(*n));
            }
        }
        at += bools;
        at += at % 2;
        let number = |p: usize| -> Option<i32> {
            if width == 4 {
                Some(i32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?))
            } else {
                short(p).map(i32::from)
            }
        };
        for i in 0..nums {
            let v = number(at + i * width)?;
            if v >= 0
                && let Some(n) = NUMBERS.get(i)
            {
                t.nums.push((String::from(*n), v));
            }
        }
        at += nums * width;
        let offsets = at;
        at += strs * 2;
        let strings = d.get(at..at + table)?;
        let cstr = |tab: &[u8], off: usize| -> Option<Vec<u8>> {
            let s = tab.get(off..)?;
            Some(s[..s.iter().position(|&c| c == 0)?].to_vec())
        };
        for i in 0..strs {
            let off = short(offsets + 2 * i)?;
            if off >= 0
                && let Some(n) = STRINGS.get(i)
            {
                t.strs.push((String::from(*n), cstr(strings, off as usize)?));
            }
        }
        at += table;
        // The extended part (term(5), "Extended Storage Format"), on an
        // even offset: five counts, the Booleans, the numbers, the
        // values' offsets, the names' offsets, then the values and the
        // names.
        at += at % 2;
        if d.len() < at + 10 {
            return Some(t);
        }
        let (xb, xn, xs, items, xtable) = (count(at)?, count(at + 2)?, count(at + 4)?, count(at + 6)?, count(at + 8)?);
        at += 10;
        let xbools = d.get(at..at + xb)?.to_vec();
        at += xb;
        at += at % 2;
        let xnums: Vec<i32> = (0..xn).map(|i| number(at + i * width)).collect::<Option<_>>()?;
        at += xn * width;
        let value_offsets: Vec<i16> = (0..xs).map(|i| short(at + 2 * i)).collect::<Option<_>>()?;
        at += xs * 2;
        let name_count = items.checked_sub(xs)?;
        let name_offsets: Vec<i16> = (0..name_count).map(|i| short(at + 2 * i)).collect::<Option<_>>()?;
        at += name_count * 2;
        let xstrings = d.get(at..at + xtable)?;
        // The names follow the last value.
        let mut names_at = 0;
        for &o in value_offsets.iter().filter(|&&o| o >= 0) {
            let end = o as usize + cstr(xstrings, o as usize)?.len() + 1;
            names_at = names_at.max(end);
        }
        let name = |i: usize| -> Option<String> {
            let o = usize::try_from(*name_offsets.get(i)?).ok()?;
            Some(String::from(lossy(&cstr(xstrings, names_at + o)?)))
        };
        for (i, &b) in xbools.iter().enumerate() {
            let n = name(i)?;
            if b == 1 {
                t.bools.push(n.clone());
            }
            t.extended.push((n, Kind::Bool));
        }
        for (i, &v) in xnums.iter().enumerate() {
            let n = name(xb + i)?;
            if v >= 0 {
                t.nums.push((n.clone(), v));
            }
            t.extended.push((n, Kind::Num));
        }
        for (i, &o) in value_offsets.iter().enumerate() {
            let n = name(xb + xn + i)?;
            if o >= 0 {
                t.strs.push((n.clone(), cstr(xstrings, o as usize)?));
            }
            t.extended.push((n, Kind::Str));
        }
        Some(t)
    }
}

/// The terminfo directories, in the order they are searched (terminfo(5),
/// "Fetching Compiled Descriptions"): `$TERMINFO`, `~/.terminfo`, each of
/// `$TERMINFO_DIRS` (an empty one standing for the system's), then the
/// system's.
fn search_path() -> Vec<Vec<u8>> {
    const SYSTEM: [&[u8]; 3] = [b"/etc/terminfo", b"/lib/terminfo", b"/usr/share/terminfo"];
    let mut dirs = Vec::new();
    if let Some(t) = env::var(b"TERMINFO").filter(|t| !t.is_empty()) {
        dirs.push(t);
    }
    if let Some(h) = env::var(b"HOME").filter(|h| !h.is_empty()) {
        dirs.push(slate_rt::fs::join(&h, b".terminfo"));
    }
    if let Some(list) = env::var(b"TERMINFO_DIRS") {
        for d in list.split(|&c| c == b':') {
            if d.is_empty() {
                dirs.extend(SYSTEM.iter().map(|s| s.to_vec()));
            } else {
                dirs.push(d.to_vec());
            }
        }
    }
    dirs.extend(SYSTEM.iter().map(|s| s.to_vec()));
    dirs
}

/// `name`'s compiled entry from the database: `DIR/c/name`, or with the
/// first character as two hexadecimal digits (term(5)).
fn from_database(name: &str) -> Option<Terminal> {
    let first = *name.as_bytes().first()?;
    if name.contains('/') || name.starts_with('.') {
        return None;
    }
    for dir in search_path() {
        for sub in [alloc::vec![first], alloc::format!("{first:02x}").into_bytes()] {
            let path = slate_rt::fs::join(&slate_rt::fs::join(&dir, &sub), name.as_bytes());
            if let Ok(data) = slate_rt::fs::read_file(&path)
                && let Some(t) = Terminal::parse(&data)
            {
                return Some(t);
            }
        }
    }
    None
}

/// `name`'s description: the database's, else one of ours.
pub fn load(name: &str) -> Option<Terminal> {
    from_database(name).or_else(|| lookup(name).map(Terminal::from_desc))
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut i = 1;
    let mut term_name: Option<Vec<u8>> = None;
    let mut from_stdin = false;
    let mut no_scrollback = false;
    while i < args.len() {
        let a = &args[i];
        if a == b"--" {
            i += 1;
            break;
        } else if let Some(t) = a.strip_prefix(b"-T") {
            if t.is_empty() {
                i += 1;
                term_name = args.get(i).cloned();
            } else {
                term_name = Some(t.to_vec());
            }
        } else if a == b"-S" {
            from_stdin = true;
        } else if a == b"-x" {
            no_scrollback = true;
        } else if a == b"-V" {
            println!("slate tput");
            return 0;
        } else {
            break;
        }
        i += 1;
    }
    let term_name_given = term_name.is_some();
    let Some(name) = term_name.or_else(|| env::var(b"TERM")) else {
        error("No value for $TERM and no -T specified");
        return 2;
    };
    let name = String::from_utf8_lossy(&name).into_owned();
    let explicit = term_name_given;
    let Some(t) = load(&name) else {
        error(format_args!("unknown terminal \"{name}\""));
        return 3;
    };
    let lines: Vec<Vec<Vec<u8>>> = if from_stdin {
        let data = io::read_to_end(io::STDIN).unwrap_or_default();
        crate::util::lines(&data, b'\n')
            .iter()
            .map(|l| l.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).map(<[u8]>::to_vec).collect())
            .filter(|w: &Vec<Vec<u8>>| !w.is_empty())
            .collect()
    } else if i < args.len() {
        alloc::vec![args[i..].to_vec()]
    } else {
        error("usage: tput [-T term] [-x] capname [parameters...]");
        return 2;
    };
    let mut status = 0;
    for words in &lines {
        status = run(&t, words, explicit, no_scrollback);
        if status > 1 {
            break;
        }
    }
    io::flush_stdout();
    status
}

/// `explicit`: the terminal came from `-T`, so the window's size is not
/// asked for (as tput(1) does). `no_scrollback`: `-x`, `clear` without
/// E3 (clearing the scrollback too).
fn run(t: &Terminal, words: &[Vec<u8>], explicit: bool, no_scrollback: bool) -> i32 {
    let cap = String::from_utf8_lossy(&words[0]).into_owned();
    match cap.as_str() {
        "longname" => {
            io::out(t.long_name().as_bytes());
            return 0;
        }
        "init" | "reset" => {
            let names: [&str; 3] = if cap == "init" { ["is1", "is2", "is3"] } else { ["rs1", "rs2", "rs3"] };
            for n in names {
                if let Some(s) = t.string(n) {
                    io::out(&unpadded(s));
                }
            }
            return 0;
        }
        _ => {}
    }
    match t.kind(&cap) {
        Some(Kind::Bool) => i32::from(!t.has(&cap)),
        Some(Kind::Num) => {
            // The window's size comes first, from the environment or the tty.
            let size = || term::size(io::STDOUT).or_else(|| term::size(io::STDERR));
            let env_num = |v: &[u8]| env::var(v).and_then(|s| crate::util::parse_num::<i32>(&s));
            let v = match cap.as_str() {
                _ if explicit => None,
                "cols" => env_num(b"COLUMNS").or_else(|| size().map(|(_, c)| i32::from(c))),
                "lines" => env_num(b"LINES").or_else(|| size().map(|(r, _)| i32::from(r))),
                _ => None,
            }
            .or_else(|| t.num(&cap))
            .unwrap_or(-1);
            println!("{v}");
            0
        }
        Some(Kind::Str) => {
            let Some(s) = t.string(&cap) else { return 1 };
            let params: Vec<Val> = words[1..]
                .iter()
                .map(|w| match crate::util::parse_num::<i64>(w) {
                    Some(n) => Val::Int(n),
                    None => Val::Str(w.clone()),
                })
                .collect();
            // Given no parameters, the string goes as it is stored.
            io::out(&if params.is_empty() { unpadded(s) } else { tparm(s, &params) });
            // clear empties the scrollback too, with E3, unless -x.
            if cap == "clear"
                && !no_scrollback
                && let Some(e3) = t.string("E3")
            {
                io::out(&unpadded(e3));
            }
            0
        }
        None => {
            error(format_args!("unknown terminfo capability '{}'", lossy(&words[0])));
            4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(term: &str, c: &str, p: &[i64]) -> Vec<u8> {
        let t = Terminal::from_desc(lookup(term).unwrap());
        let v: Vec<Val> = p.iter().map(|&n| Val::Int(n)).collect();
        tparm(t.string(c).unwrap(), &v)
    }

    /// `zz|t, am, cols#80, bel=^G, AX, XT, U8#1, E3=\E[3J,
    /// Smulx=\E[4:%p1%dm,` as the host's tic compiles it (tic -x).
    const COMPILED: &[u8] = &[
        0x1a, 0x01, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x7a, 0x7a, 0x7c, 0x74, 0x00, 0x00,
        0x01, 0x00, 0x50, 0x00, 0xff, 0xff, 0x00, 0x00, 0x07, 0x00, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x07, 0x00,
        0x22, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x09, 0x00,
        0x0c, 0x00, 0x1b, 0x5b, 0x33, 0x4a, 0x00, 0x1b, 0x5b, 0x34, 0x3a, 0x25, 0x70, 0x31, 0x25, 0x64, 0x6d, 0x00,
        0x41, 0x58, 0x00, 0x58, 0x54, 0x00, 0x55, 0x38, 0x00, 0x45, 0x33, 0x00, 0x53, 0x6d, 0x75, 0x6c, 0x78, 0x00,
    ];

    #[test]
    fn compiled_entries() {
        let t = Terminal::parse(COMPILED).unwrap();
        assert_eq!(t.names, ["zz", "t"]);
        assert!(t.has("am") && t.has("AX") && t.has("XT") && !t.has("bw"));
        assert_eq!((t.num("cols"), t.num("U8"), t.num("lines")), (Some(80), Some(1), None));
        assert_eq!(t.string("bel"), Some(&b"\x07"[..]));
        assert_eq!(t.string("E3"), Some(&b"\x1b[3J"[..]));
        assert_eq!(tparm(t.string("Smulx").unwrap(), &[Val::Int(3)]), b"\x1b[4:3m");
        assert_eq!(
            (t.kind("Smulx"), t.kind("XT"), t.kind("cup"), t.kind("nope")),
            (Some(Kind::Str), Some(Kind::Bool), Some(Kind::Str), None)
        );
        assert_eq!(t.long_name(), "t");
        // Cut short anywhere, it is refused or read as far as it goes.
        for n in 0..COMPILED.len() {
            let _ = Terminal::parse(&COMPILED[..n]);
        }
        assert_eq!(Terminal::parse(b"\x1a\x02"), None);
    }

    #[test]
    fn compiled_by_tic() {
        // Both number formats, as the host's tic writes them (pairs over
        // 32767 need the 32-bit one); skipped without tic.
        let dir = std::env::temp_dir().join(std::format!("slate-tput-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let src = dir.join("t.ti");
        std::fs::write(&src, "big|wide,\n\tbce, colors#256, pairs#65536, cup=\\E[%i%p1%d;%p2%dH, Tc,\n").unwrap();
        let Ok(out) = std::process::Command::new("tic").arg("-x").arg("-o").arg(&dir).arg(&src).output() else {
            return;
        };
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let data = std::fs::read(dir.join("b/big")).unwrap();
        assert_eq!(&data[..2], &[0x1e, 0x02], "the 32-bit format");
        let t = Terminal::parse(&data).unwrap();
        assert_eq!((t.num("colors"), t.num("pairs")), (Some(256), Some(65536)));
        assert!(t.has("bce") && t.has("Tc"));
        assert_eq!(tparm(t.string("cup").unwrap(), &[Val::Int(1), Val::Int(2)]), b"\x1b[2;3H");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parameters() {
        assert_eq!(cap("xterm-256color", "cup", &[5, 10]), b"\x1b[6;11H");
        assert_eq!(cap("xterm-256color", "setaf", &[1]), b"\x1b[31m");
        assert_eq!(cap("xterm-256color", "setaf", &[9]), b"\x1b[91m");
        assert_eq!(cap("xterm-256color", "setab", &[200]), b"\x1b[48;5;200m");
        assert_eq!(cap("xterm-256color", "flash", &[]), b"\x1b[?5h\x1b[?5l");
        assert_eq!(cap("linux", "sgr0", &[]), b"\x1b[m\x0f");
        assert_eq!(cap("vt100", "kbs", &[]), b"\x08");
        assert_eq!(cap("xterm", "kbs", &[]), b"\x7f");
        assert!(string(lookup("vt100").unwrap(), "setaf").is_none());
        assert!(lookup("dumb").is_some_and(|d| string(d, "clear").is_none()));
        assert_eq!(tparm(b"%p1%02d|%p2%x|%p1%{3}%*%d", &[Val::Int(7), Val::Int(255)]), b"07|ff|21");
        assert_eq!(tparm(b"%?%p1%t1%e0%;", &[Val::Int(0)]), b"0");
    }
}
