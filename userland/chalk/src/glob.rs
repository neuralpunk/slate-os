// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pattern matching notation (POSIX.1-2017 XCU §2.13): `*`, `?`, bracket
//! expressions with ranges, negation and character classes; bash's
//! extended patterns (`?(a|b)`, `*(...)`, `+(...)`, `@(...)`, `!(...)`)
//! when asked for; and pathname expansion with bash's `dotglob`,
//! `nocaseglob` and `globstar`. Pattern bytes carry a "quoted" flag:
//! quoted bytes match only themselves.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use slate_rt::fs;

/// A pattern: bytes and whether each was quoted.
pub type Pat = [(u8, bool)];

/// `shopt -s extglob`: extended patterns everywhere patterns are matched.
pub static EXTGLOB: AtomicBool = AtomicBool::new(false);

/// How a pattern matches.
#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    /// Extended patterns.
    pub ext: bool,
    /// Letters match either case.
    pub nocase: bool,
}

impl Flags {
    /// The shell's setting (`extglob`), case-sensitive.
    pub fn shell() -> Flags {
        Flags { ext: EXTGLOB.load(Ordering::Relaxed), nocase: false }
    }
}

/// Pathname expansion's options (bash's `shopt`).
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobOpts {
    pub flags: Flags,
    /// `dotglob`: `*` and `?` match a leading dot.
    pub dotglob: bool,
    /// `globstar`: `**` alone in a component matches any directories.
    pub globstar: bool,
}

/// Whether a pattern has special characters (a `[` only counts when it
/// starts a valid bracket expression: `[ x ]` is no pattern).
pub fn has_magic(p: &Pat) -> bool {
    p.iter().enumerate().any(|(i, &(c, q))| {
        !q && (matches!(c, b'*' | b'?')
            || c == b'[' && bracket(p, i, 0, false).is_some()
            || EXTGLOB.load(Ordering::Relaxed) && ext_group(p, i).is_some())
    })
}

/// An extended group at `p[i]` (`@(` and the others): the index after its
/// `)` and the alternatives' ranges.
fn ext_group(p: &Pat, i: usize) -> Option<(usize, Vec<(usize, usize)>)> {
    let &(c, q) = p.get(i)?;
    if q || !matches!(c, b'?' | b'*' | b'+' | b'@' | b'!') || p.get(i + 1) != Some(&(b'(', false)) {
        return None;
    }
    let mut depth = 0;
    let mut alts = Vec::new();
    let mut start = i + 2;
    let mut j = i + 1;
    while j < p.len() {
        match p[j] {
            (b'(', false) => depth += 1,
            (b')', false) => {
                depth -= 1;
                if depth == 0 {
                    alts.push((start, j));
                    return Some((j + 1, alts));
                }
            }
            (b'|', false) if depth == 1 => {
                alts.push((start, j));
                start = j + 1;
            }
            _ => {}
        }
        j += 1;
    }
    None
}

fn has_ext(p: &Pat) -> bool {
    (0..p.len()).any(|i| ext_group(p, i).is_some())
}

fn same(a: u8, b: u8, nocase: bool) -> bool {
    a == b || nocase && a.eq_ignore_ascii_case(&b)
}

fn class(name: &[u8], c: u8) -> bool {
    match name {
        b"alpha" => c.is_ascii_alphabetic(),
        b"digit" => c.is_ascii_digit(),
        b"alnum" => c.is_ascii_alphanumeric(),
        b"upper" => c.is_ascii_uppercase(),
        b"lower" => c.is_ascii_lowercase(),
        b"space" => c.is_ascii_whitespace() || c == 11,
        b"blank" => c == b' ' || c == b'\t',
        b"punct" => c.is_ascii_punctuation(),
        b"print" => (32..127).contains(&c),
        b"graph" => c.is_ascii_graphic(),
        b"cntrl" => c.is_ascii_control(),
        b"xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}

/// Match a bracket expression starting at `p[i]` (`[`) against `c`;
/// returns (matched, index after `]`) or `None` if it is not a valid
/// bracket expression (then `[` is literal).
fn bracket(p: &Pat, i: usize, c: u8, nocase: bool) -> Option<(bool, usize)> {
    if nocase && c.is_ascii_alphabetic() {
        let a = bracket_one(p, i, c.to_ascii_lowercase())?;
        let b = bracket_one(p, i, c.to_ascii_uppercase())?;
        return Some((a.0 || b.0, a.1));
    }
    bracket_one(p, i, c)
}

fn bracket_one(p: &Pat, i: usize, c: u8) -> Option<(bool, usize)> {
    let mut j = i + 1;
    let negate = matches!(p.get(j), Some(&(b'!' | b'^', false)));
    if negate {
        j += 1;
    }
    let mut matched = false;
    let mut first = true;
    loop {
        let &(b, q) = p.get(j)?;
        if b == b']' && !q && !first {
            return Some((matched != negate, j + 1));
        }
        first = false;
        if b == b'[' && !q && p.get(j + 1) == Some(&(b':', false)) {
            let start = j + 2;
            let mut k = start;
            while k + 1 < p.len() && !(p[k] == (b':', false) && p[k + 1] == (b']', false)) {
                k += 1;
            }
            if k + 1 < p.len() {
                let name: Vec<u8> = p[start..k].iter().map(|x| x.0).collect();
                matched |= class(&name, c);
                j = k + 2;
                continue;
            }
        }
        if p.get(j + 1) == Some(&(b'-', false)) && p.get(j + 2).is_some_and(|&(e, eq)| !(e == b']' && !eq)) {
            let hi = p[j + 2].0;
            matched |= b <= c && c <= hi;
            j += 3;
            continue;
        }
        matched |= b == c;
        j += 1;
    }
}

/// Whether `s` matches `p` entirely (with the shell's `extglob`).
pub fn matches(p: &Pat, s: &[u8]) -> bool {
    matches_with(p, s, Flags::shell())
}

/// Whether `s` matches `p` entirely, with `f`'s rules.
pub fn matches_with(p: &Pat, s: &[u8], f: Flags) -> bool {
    if f.ext && has_ext(p) {
        return ext_match(p, s, f);
    }
    simple_match(p, s, f.nocase)
}

/// Matching with extended groups: backtracking over every split.
fn ext_match(p: &Pat, s: &[u8], f: Flags) -> bool {
    let Some(&(c, q)) = p.first() else { return s.is_empty() };
    if let Some((after, alts)) = ext_group(p, 0) {
        let rest = &p[after..];
        let any_alt = |t: &[u8]| alts.iter().any(|&(a, b)| ext_match(&p[a..b], t, f));
        return match c {
            b'@' => (0..=s.len()).any(|k| any_alt(&s[..k]) && ext_match(rest, &s[k..], f)),
            b'?' => (0..=s.len()).any(|k| (k == 0 || any_alt(&s[..k])) && ext_match(rest, &s[k..], f)),
            b'!' => (0..=s.len()).any(|k| !any_alt(&s[..k]) && ext_match(rest, &s[k..], f)),
            // `*(...)` and `+(...)`: repetitions, each matching something.
            _ => {
                let mut reach = alloc::vec![false; s.len() + 1];
                reach[0] = c == b'*';
                let mut frontier = alloc::vec![0usize];
                let mut seen = alloc::vec![false; s.len() + 1];
                while let Some(i) = frontier.pop() {
                    for k in i + 1..=s.len() {
                        if !seen[k] && any_alt(&s[i..k]) {
                            seen[k] = true;
                            reach[k] = true;
                            frontier.push(k);
                        }
                    }
                }
                (0..=s.len()).any(|k| reach[k] && ext_match(rest, &s[k..], f))
            }
        };
    }
    if !q && c == b'*' {
        return (0..=s.len()).any(|k| ext_match(&p[1..], &s[k..], f));
    }
    let Some(&b) = s.first() else { return false };
    if !q && c == b'?' {
        return ext_match(&p[1..], &s[1..], f);
    }
    if !q && c == b'[' {
        match bracket(p, 0, b, f.nocase) {
            Some((true, next)) => return ext_match(&p[next..], &s[1..], f),
            Some((false, _)) => return false,
            None => {}
        }
    }
    same(c, b, f.nocase) && ext_match(&p[1..], &s[1..], f)
}

fn simple_match(p: &Pat, s: &[u8], nocase: bool) -> bool {
    // Iterative matching with backtracking to the last `*`.
    let (mut pi, mut si) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() {
            let (c, q) = p[pi];
            if !q && c == b'*' {
                star = Some((pi, si));
                pi += 1;
                continue;
            }
            if !q && c == b'?' {
                pi += 1;
                si += 1;
                continue;
            }
            if !q && c == b'[' {
                if let Some((ok, next)) = bracket(p, pi, s[si], nocase) {
                    if ok {
                        pi = next;
                        si += 1;
                        continue;
                    }
                } else if s[si] == b'[' {
                    pi += 1;
                    si += 1;
                    continue;
                }
            } else if same(c, s[si], nocase) {
                pi += 1;
                si += 1;
                continue;
            }
        }
        match star {
            Some((sp, ss)) => {
                pi = sp + 1;
                si = ss + 1;
                star = Some((sp, ss + 1));
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == (b'*', false) {
        pi += 1;
    }
    pi == p.len()
}

/// The directories under `base` (itself first), for `**`.
fn subdirs(base: &[u8], dotglob: bool, out: &mut Vec<Vec<u8>>) {
    out.push(base.to_vec());
    let dir = if base.is_empty() { &b"."[..] } else { base };
    let Ok(entries) = fs::read_dir(dir) else { return };
    let mut names: Vec<Vec<u8>> = entries
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n != b"." && n != b".." && (dotglob || !n.starts_with(b".")))
        .collect();
    names.sort();
    for n in names {
        let path = if base.is_empty() { n } else { fs::join(base, &n) };
        // Symbolic links to directories are not followed (bash).
        if fs::lstat(&path).is_ok_and(|s| s.is_dir()) {
            subdirs(&path, dotglob, out);
        }
    }
}

/// Pathname expansion of one field; empty if nothing matches.
pub fn expand(p: &Pat) -> Vec<Vec<u8>> {
    expand_with(p, GlobOpts { flags: Flags::shell(), ..Default::default() })
}

/// Pathname expansion with bash's options.
pub fn expand_with(p: &Pat, o: GlobOpts) -> Vec<Vec<u8>> {
    let absolute = p.first().map(|x| x.0) == Some(b'/');
    let comps: Vec<&Pat> = p.split(|x| x.0 == b'/').filter(|c| !c.is_empty()).collect();
    let mut paths: Vec<Vec<u8>> = alloc::vec![if absolute { b"/".to_vec() } else { Vec::new() }];
    for (k, comp) in comps.iter().enumerate() {
        let last = k + 1 == comps.len();
        let mut next = Vec::new();
        if o.globstar && *comp == [(b'*', false), (b'*', false)] {
            // `**`: these directories and every one below; last, the
            // files in them too (only directories before a final `/`).
            let files_too = last && p.last().map(|x| x.0) != Some(b'/');
            for base in &paths {
                let mut dirs = Vec::new();
                subdirs(base, o.dotglob, &mut dirs);
                for d in dirs {
                    if last {
                        if d != *base {
                            next.push(d.clone());
                        } else if !d.is_empty() && files_too {
                            // bash lists the directory itself as `dir/`.
                            next.push([d.as_slice(), b"/"].concat());
                        }
                    }
                    if files_too {
                        let dir = if d.is_empty() { &b"."[..] } else { d.as_slice() };
                        let mut files: Vec<Vec<u8>> = fs::read_dir(dir)
                            .unwrap_or_default()
                            .into_iter()
                            .map(|e| e.name)
                            .filter(|n| n != b"." && n != b".." && (o.dotglob || !n.starts_with(b".")))
                            .map(|n| if d.is_empty() { n } else { fs::join(&d, &n) })
                            .filter(|p| !fs::lstat(p).is_ok_and(|s| s.is_dir()))
                            .collect();
                        files.sort();
                        next.extend(files);
                    } else if !last {
                        next.push(d);
                    }
                }
            }
            if last {
                next.sort();
                next.dedup();
            }
            paths = next;
            if paths.is_empty() {
                break;
            }
            continue;
        }
        for base in &paths {
            if !has_magic(comp) {
                let lit: Vec<u8> = comp.iter().map(|x| x.0).collect();
                let path = if base.is_empty() { lit } else { fs::join(base, &lit) };
                // The last name must exist (a dangling link counts).
                if last && fs::lstat(&path).is_ok() || fs::stat(&path).is_ok_and(|s| s.is_dir()) {
                    next.push(path);
                }
                continue;
            }
            let dir = if base.is_empty() { &b"."[..] } else { base.as_slice() };
            let Ok(entries) = fs::read_dir(dir) else { continue };
            let dot_ok = o.dotglob || comp.first().is_some_and(|x| x.0 == b'.');
            // `.` and `..` only by name (bash's globskipdots).
            let mut names: Vec<Vec<u8>> = entries
                .into_iter()
                .map(|e| e.name)
                .filter(|n| n != b"." && n != b"..")
                .filter(|n| (dot_ok || !n.starts_with(b".")) && matches_with(comp, n, o.flags))
                .collect();
            names.sort();
            for n in names {
                let path = if base.is_empty() { n } else { fs::join(base, &n) };
                if last || fs::stat(&path).is_ok_and(|s| s.is_dir()) {
                    next.push(path);
                }
            }
        }
        paths = next;
        if paths.is_empty() {
            break;
        }
    }
    // A pattern that is only literals (no magic anywhere) is not expanded.
    let trailing_slash = p.last().map(|x| x.0) == Some(b'/');
    if trailing_slash {
        for x in &mut paths {
            x.push(b'/');
        }
    }
    paths
}

pub fn unquoted(s: &[u8]) -> Vec<(u8, bool)> {
    s.iter().map(|&c| (c, false)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        matches(&unquoted(p.as_bytes()), s.as_bytes())
    }

    #[test]
    fn patterns() {
        assert!(m("*", ""));
        assert!(m("a*c", "abbbc"));
        assert!(!m("a*c", "abbb"));
        assert!(m("?.txt", "a.txt"));
        assert!(m("[abc]x", "bx"));
        assert!(!m("[!abc]x", "bx"));
        assert!(m("[a-z]*[0-9]", "foo7"));
        assert!(m("[[:upper:]]*", "Hello"));
        assert!(m("*.[ch]", "main.c"));
        assert!(m("[]]", "]"));
        assert!(m("a[", "a["));
        let q = [(b'*', true)];
        assert!(matches(&q, b"*") && !matches(&q, b"x"));
    }

    #[test]
    fn extended_and_caseless() {
        let x =
            |p: &str, s: &str| matches_with(&unquoted(p.as_bytes()), s.as_bytes(), Flags { ext: true, nocase: false });
        assert!(x("@(a|b).c", "b.c"));
        assert!(!x("@(a|b).c", "ab.c"));
        assert!(x("*(ab)", "") && x("*(ab)", "abab") && !x("*(ab)", "aba"));
        assert!(!x("+(ab)", "") && x("+(ab|c)", "abcab"));
        assert!(x("?(x)y", "y") && x("?(x)y", "xy") && !x("?(x)y", "xxy"));
        assert!(x("!(*.txt)", "a.c") && !x("!(*.txt)", "a.txt"));
        assert!(x("a@(b|*(c))d", "accd"));
        let n = Flags { ext: false, nocase: true };
        assert!(matches_with(&unquoted(b"A*[x]"), b"abX", n));
        assert!(!matches_with(&unquoted(b"A*"), b"b", n));
    }
}
