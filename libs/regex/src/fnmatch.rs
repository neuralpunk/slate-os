// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pattern matching notation for file names (XCU §2.13, fnmatch(3)):
//! `*`, `?`, bracket expressions and backslash escapes.

/// fnmatch flags.
#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    /// FNM_PATHNAME: wildcards do not match `/`.
    pub pathname: bool,
    /// FNM_PERIOD: a leading `.` must be matched explicitly.
    pub period: bool,
    /// FNM_CASEFOLD (GNU).
    pub casefold: bool,
}

fn eq(a: u8, b: u8, fold: bool) -> bool {
    if fold { a.eq_ignore_ascii_case(&b) } else { a == b }
}

/// A bracket expression at `p[i] == '['` against `c`: (matched, index
/// after `]`), or `None` if it is not one (the `[` is then literal).
fn bracket(p: &[u8], i: usize, c: u8, fold: bool) -> Option<(bool, usize)> {
    let mut j = i + 1;
    let negate = matches!(p.get(j), Some(b'!' | b'^'));
    if negate {
        j += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let b = *p.get(j)?;
        if b == b']' && !first {
            return Some((matched != negate, j + 1));
        }
        first = false;
        if b == b'[' && p.get(j + 1) == Some(&b':') {
            let end = p[j + 2..].windows(2).position(|w| w == b":]")? + j + 2;
            let name = &p[j + 2..end];
            let hit = match name {
                b"alpha" => c.is_ascii_alphabetic(),
                b"digit" => c.is_ascii_digit(),
                b"alnum" => c.is_ascii_alphanumeric(),
                b"upper" => c.is_ascii_uppercase() || fold && c.is_ascii_lowercase(),
                b"lower" => c.is_ascii_lowercase() || fold && c.is_ascii_uppercase(),
                b"space" => matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 11 | 12),
                b"blank" => c == b' ' || c == b'\t',
                b"punct" => c.is_ascii_punctuation(),
                b"print" => (32..127).contains(&c),
                b"graph" => (33..127).contains(&c),
                b"cntrl" => c < 32 || c == 127,
                b"xdigit" => c.is_ascii_hexdigit(),
                _ => false,
            };
            matched |= hit;
            j = end + 2;
            continue;
        }
        let (lo, next) = if b == b'\\' && j + 1 < p.len() { (p[j + 1], j + 2) } else { (b, j + 1) };
        if p.get(next) == Some(&b'-') && p.get(next + 1).is_some_and(|&e| e != b']') {
            let (hi, after) = if p[next + 1] == b'\\' && next + 2 < p.len() {
                (p[next + 2], next + 3)
            } else {
                (p[next + 1], next + 2)
            };
            let in_range = |x: u8| lo <= x && x <= hi;
            matched |= in_range(c) || fold && (in_range(c.to_ascii_lowercase()) || in_range(c.to_ascii_uppercase()));
            j = after;
            continue;
        }
        matched |= eq(lo, c, fold);
        j = next;
    }
}

/// Whether `name` matches `pattern`.
pub fn fnmatch_with(pattern: &[u8], name: &[u8], f: Flags) -> bool {
    let (p, s) = (pattern, name);
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    let leading_period =
        |si: usize| f.period && s.get(si) == Some(&b'.') && (si == 0 || f.pathname && s[si - 1] == b'/');
    loop {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    if leading_period(si) {
                        // A leading period never matches a wildcard.
                    } else {
                        while p.get(pi) == Some(&b'*') {
                            pi += 1;
                        }
                        star = Some((pi, si));
                        continue;
                    }
                }
                b'?' if si < s.len() && !(f.pathname && s[si] == b'/') && !leading_period(si) => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                b'[' if si < s.len() && !(f.pathname && s[si] == b'/') && !leading_period(si) => {
                    if let Some((hit, next)) = bracket(p, pi, s[si], f.casefold) {
                        if hit {
                            pi = next;
                            si += 1;
                            continue;
                        }
                    } else if s[si] == b'[' {
                        pi += 1;
                        si += 1;
                        continue;
                    }
                }
                b'\\' if pi + 1 < p.len() => {
                    if si < s.len() && eq(p[pi + 1], s[si], f.casefold) {
                        pi += 2;
                        si += 1;
                        continue;
                    }
                }
                c if c != b'?' && c != b'[' && si < s.len() && eq(c, s[si], f.casefold) => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        } else if si == s.len() {
            return true;
        }
        // Mismatch: let the last `*` take one more byte.
        match star {
            Some((sp, ss)) if ss < s.len() && !(f.pathname && s[ss] == b'/') => {
                star = Some((sp, ss + 1));
                pi = sp;
                si = ss + 1;
            }
            _ => return false,
        }
    }
}

/// fnmatch with no flags.
pub fn fnmatch(pattern: &[u8], name: &[u8]) -> bool {
    fnmatch_with(pattern, name, Flags::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert!(fnmatch(b"*.c", b"a.c"));
        assert!(!fnmatch(b"*.c", b"a.h"));
        assert!(fnmatch(b"a?c", b"abc"));
        assert!(fnmatch(b"[a-c]x", b"bx"));
        assert!(fnmatch(b"[!a-c]x", b"dx"));
        assert!(fnmatch(b"\\*", b"*"));
        assert!(!fnmatch(b"\\*", b"a"));
        assert!(fnmatch(b"*", b""));
        assert!(fnmatch(b"a*b*c", b"aXbYbc"));
        assert!(fnmatch(b"[[:digit:]]*", b"7up"));
        assert!(fnmatch(b"[", b"["));
        let path = Flags { pathname: true, ..Flags::default() };
        assert!(!fnmatch_with(b"*", b"a/b", path));
        assert!(fnmatch_with(b"*/*", b"a/b", path));
        let period = Flags { period: true, ..Flags::default() };
        assert!(!fnmatch_with(b"*", b".x", period));
        assert!(fnmatch_with(b".*", b".x", period));
        let fold = Flags { casefold: true, ..Flags::default() };
        assert!(fnmatch_with(b"*.TXT", b"a.txt", fold));
    }
}
