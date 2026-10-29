// SPDX-License-Identifier: MIT OR Apache-2.0

//! less's prompt strings (less(1), PROMPTS; ADR 0149): `%` items that
//! expand to what is being shown, and `?x...:...` conditionals ending at
//! a `.`. The defaults are the ones less(1) lists.

use alloc::string::String;
use alloc::vec::Vec;

/// The short prompt (the default).
pub const SHORT: &str = "?n?f%f .?m(%T %i of %m) ..?e(END) ?x- Next\\: %x..%t";
/// `-m`'s.
pub const MEDIUM: &str = "?n?f%f .?m(%T %i of %m) ..?e(END) ?x- Next\\: %x.:?pB%pB\\%:byte %bB?s/%s...%t";
/// `-M`'s.
pub const LONG: &str = "?f%f .?n?m(%T %i of %m) ..?ltlines %lt-%lb?L/%L. :byte %bB?s/%s. .?e(END) ?x- Next\\: %x.:?pB%pB\\%..?c (column %c).%t";
/// The `=` command's message.
pub const EQUALS: &str =
    "?f%f .?m(%T %i of %m) .?ltlines %lt-%lb?L/%L. .byte %bB?s/%s. ?e(END) :?pB%pB\\%..?c (column %c).%t";
/// The `v` command's default (LESSEDIT).
pub const EDIT: &str = "%E ?lm+%lm. %g";

/// A line a `%bX`, `%lX`, `%pX`, `%PX` or `%dX` item is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Top,
    Middle,
    Bottom,
    /// The line after the bottom one.
    After,
    /// `-j`'s target line.
    Target,
}

/// What a prompt can tell (the source asks for each line's facts).
pub trait Facts {
    /// The current file's name; None for a pipe.
    fn name(&self) -> Option<Vec<u8>>;
    /// 1-based index and count of the files, and the next one's name.
    fn index(&self) -> usize;
    fn files(&self) -> usize;
    fn next_name(&self) -> Option<Vec<u8>>;
    /// The 0-based line number of `which`, if there is such a line.
    fn line(&self, which: Which) -> Option<usize>;
    /// Where a line starts, if read that far.
    fn offset(&self, line: usize) -> Option<u64>;
    /// The size in bytes, the number of lines, when known.
    fn size(&self) -> Option<u64>;
    fn lines(&self) -> Option<usize>;
    fn at_end(&self) -> bool;
    /// The first prompt since this file was opened.
    fn first(&self) -> bool;
    /// Rows a page has.
    fn page(&self) -> usize;
    /// Viewing files through tags (`%T` is `tag`).
    fn tags(&self) -> bool;
    fn editor(&self) -> Vec<u8>;
}

fn which(c: Option<&u8>) -> Option<Which> {
    Some(match c? {
        b't' => Which::Top,
        b'm' => Which::Middle,
        b'b' => Which::Bottom,
        b'B' => Which::After,
        b'j' => Which::Target,
        _ => return None,
    })
}

/// A name quoted with backslashes for the shell (`%g`).
fn escaped(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &c in name {
        if !(c.is_ascii_alphanumeric() || b"/._-+,".contains(&c)) {
            out.push(b'\\');
        }
        out.push(c);
    }
    out
}

fn last_component(name: &[u8]) -> &[u8] {
    name.rsplit(|&c| c == b'/').find(|p| !p.is_empty()).unwrap_or(name)
}

/// An item's text, or None when unknown (shown as `?`).
fn item(c: u8, w: Option<Which>, f: &dyn Facts) -> Option<Vec<u8>> {
    let num = |n: u64| alloc::format!("{n}").into_bytes();
    let line = || w.and_then(|w| f.line(w));
    Some(match c {
        b'b' => num(f.offset(line()?)?),
        b'B' | b's' => num(f.size()?),
        b'c' => num(1),
        b'd' => num((line()? / f.page().max(1) + 1) as u64),
        b'D' => num((f.lines()?.saturating_sub(1) / f.page().max(1) + 1) as u64),
        b'E' => f.editor(),
        b'f' => f.name()?,
        b'F' => last_component(&f.name()?).to_vec(),
        b'g' => escaped(&f.name()?),
        b'G' => escaped(last_component(&f.name()?)),
        b'i' => num(f.index() as u64),
        b'l' => num(line()? as u64 + 1),
        b'L' => num(f.lines()? as u64),
        b'm' => num(f.files() as u64),
        b'p' => {
            let size = f.size()?;
            let at = f.offset(line()?)?;
            // Rounded to the nearest, as less shows them.
            num((at * 100 + size / 2).checked_div(size).unwrap_or(100))
        }
        b'P' => {
            let total = f.lines()?;
            num(((line()? + 1) * 100 + total / 2).checked_div(total).unwrap_or(100) as u64)
        }
        b'T' => (if f.tags() { "tag" } else { "file" }).as_bytes().to_vec(),
        b'x' => f.next_name()?,
        b'y' => escaped(&f.next_name()?),
        b'%' => b"%".to_vec(),
        _ => return None,
    })
}

fn condition(c: u8, w: Option<Which>, f: &dyn Facts, so_far: &[u8]) -> bool {
    let line = || w.and_then(|w| f.line(w));
    match c {
        b'a' => !so_far.is_empty(),
        b'b' => line().and_then(|l| f.offset(l)).is_some(),
        b'B' | b's' => f.size().is_some(),
        b'c' => false,
        b'd' => line().is_some(),
        b'e' => f.at_end(),
        b'f' => f.name().is_some(),
        b'l' => line().is_some(),
        b'L' => f.lines().is_some(),
        b'm' => f.files() > 1,
        b'n' => f.first(),
        b'p' => f.size().is_some() && line().and_then(|l| f.offset(l)).is_some(),
        b'P' => f.lines().is_some() && line().is_some(),
        b'x' => f.next_name().is_some(),
        _ => false,
    }
}

/// Items and conditions that name a line after them.
fn takes_line(c: u8) -> bool {
    matches!(c, b'b' | b'd' | b'l' | b'p' | b'P')
}

/// From `i` (inside a conditional), past its `:` when `to_else` (else its
/// `.`), nested conditionals skipped whole.
fn skip(p: &[u8], mut i: usize, to_else: bool) -> usize {
    let mut depth = 0;
    while i < p.len() {
        match p[i] {
            b'\\' => i += 2,
            b'%' => i += if p.get(i + 1).is_some_and(|&c| takes_line(c)) { 3 } else { 2 },
            b'?' => {
                depth += 1;
                i += if p.get(i + 1).is_some_and(|&c| takes_line(c)) { 3 } else { 2 };
            }
            b':' if depth == 0 && to_else => return i + 1,
            b'.' if depth == 0 => return i + 1,
            b'.' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

/// Expand prompt string `p`.
pub fn expand(p: &[u8], f: &dyn Facts) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        match p[i] {
            b'\\' => {
                if let Some(&c) = p.get(i + 1) {
                    out.push(c);
                }
                i += 2;
            }
            b'%' => {
                let Some(&c) = p.get(i + 1) else { break };
                let w = if takes_line(c) { which(p.get(i + 2)) } else { None };
                i += if takes_line(c) { 3 } else { 2 };
                if c == b't' {
                    while out.last() == Some(&b' ') {
                        out.pop();
                    }
                    continue;
                }
                match item(c, w, f) {
                    Some(t) => out.extend(t),
                    None => out.push(b'?'),
                }
            }
            b'?' => {
                let Some(&c) = p.get(i + 1) else { break };
                let w = if takes_line(c) { which(p.get(i + 2)) } else { None };
                i += if takes_line(c) { 3 } else { 2 };
                if !condition(c, w, f, &out) {
                    i = skip(p, i, true);
                }
            }
            // The end of a true branch: its else part is skipped.
            b':' => i = skip(p, i + 1, false),
            b'.' => i += 1,
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// A string for a message line.
pub fn text(p: &[u8], f: &dyn Facts) -> String {
    String::from_utf8_lossy(&expand(p, f)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct F {
        name: Option<&'static str>,
        index: usize,
        files: usize,
        end: bool,
        first: bool,
        lines: Option<usize>,
    }

    impl Facts for F {
        fn name(&self) -> Option<Vec<u8>> {
            self.name.map(|n| n.as_bytes().to_vec())
        }
        fn index(&self) -> usize {
            self.index
        }
        fn files(&self) -> usize {
            self.files
        }
        fn next_name(&self) -> Option<Vec<u8>> {
            (self.index < self.files).then(|| b"next.txt".to_vec())
        }
        fn line(&self, w: Which) -> Option<usize> {
            Some(match w {
                Which::Top => 9,
                Which::Middle => 20,
                Which::Bottom => 32,
                Which::After => 33,
                Which::Target => 9,
            })
        }
        fn offset(&self, line: usize) -> Option<u64> {
            Some(line as u64 * 10)
        }
        fn size(&self) -> Option<u64> {
            self.lines.map(|l| l as u64 * 10)
        }
        fn lines(&self) -> Option<usize> {
            self.lines
        }
        fn at_end(&self) -> bool {
            self.end
        }
        fn first(&self) -> bool {
            self.first
        }
        fn page(&self) -> usize {
            23
        }
        fn tags(&self) -> bool {
            false
        }
        fn editor(&self) -> Vec<u8> {
            b"etch".to_vec()
        }
    }

    fn f() -> F {
        F { name: Some("notes.txt"), index: 1, files: 2, end: false, first: true, lines: Some(100) }
    }

    #[test]
    fn default_prompts() {
        assert_eq!(text(SHORT.as_bytes(), &f()), "notes.txt (file 1 of 2)");
        let end = F { first: false, end: true, ..f() };
        assert_eq!(text(SHORT.as_bytes(), &end), "(END) - Next: next.txt");
        let middle = F { first: false, files: 1, ..f() };
        assert_eq!(text(SHORT.as_bytes(), &middle), "");
        assert_eq!(text(MEDIUM.as_bytes(), &middle), "33%");
        assert_eq!(text(LONG.as_bytes(), &middle), "notes.txt lines 10-33/100 33%");
        let pipe = F { name: None, lines: None, first: false, files: 1, ..f() };
        assert_eq!(text(LONG.as_bytes(), &pipe), "lines 10-33");
        assert_eq!(text(EQUALS.as_bytes(), &f()), "notes.txt (file 1 of 2) lines 10-33/100 byte 330/1000 33%");
        assert_eq!(text(EDIT.as_bytes(), &f()), "etch +21 notes.txt");
    }

    #[test]
    fn items_and_escapes() {
        let x = f();
        assert_eq!(
            text(b"%F|%i/%m|%lt-%lb|%pb\\%|%dt/%D|%x|?a yes:no.|%Q", &x),
            "notes.txt|1/2|10-33|32%|1/5|next.txt| yes|?"
        );
        let odd = F { name: Some("my file's.txt"), ..f() };
        assert_eq!(text(b"%g", &odd), "my\\ file\\'s.txt");
        assert_eq!(text(b"?e?x1:2.:3.", &x), "3");
        assert_eq!(text(b"a   %t|", &x), "a|");
    }
}
