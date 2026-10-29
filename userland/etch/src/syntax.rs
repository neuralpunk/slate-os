// SPDX-License-Identifier: MIT OR Apache-2.0

//! Syntax colours: a few kinds of file, found by name, extension or the
//! `#!` line, each with its comments, strings and keywords. A line is
//! coloured on its own, but for block comments, whose state comes from the
//! lines before.

/// The colours (SGR 30 + n).
pub const COMMENT: u8 = 6;
pub const STRING: u8 = 3;
pub const KEYWORD: u8 = 2;
pub const NUMBER: u8 = 5;

/// A kind of file.
#[derive(Debug)]
pub struct Syntax {
    pub name: &'static str,
    exts: &'static [&'static str],
    names: &'static [&'static str],
    shebang: &'static [&'static str],
    line_comment: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    quotes: &'static [u8],
    keywords: &'static [&'static str],
    /// Lines starting with this are keywords whole (Markdown's headings).
    heading: Option<u8>,
}

pub static SYNTAXES: &[Syntax] = &[
    Syntax {
        name: "sh",
        exts: &["sh", "bash"],
        names: &[".profile", ".bashrc", "profile", ".chalkrc", "rc.sysinit", "rc.local"],
        shebang: &["sh", "bash", "chalk", "dash", "ash"],
        line_comment: &["#"],
        block: None,
        quotes: b"\"'",
        keywords: &[
            "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac", "in",
            "function", "return", "local", "export", "readonly", "shift", "exit", "break", "continue", "set", "unset",
            "trap", "eval", "exec", "source",
        ],
        heading: None,
    },
    Syntax {
        name: "c",
        exts: &["c", "h", "cc", "cpp", "hpp"],
        names: &[],
        shebang: &[],
        line_comment: &["//"],
        block: Some(("/*", "*/")),
        quotes: b"\"'",
        keywords: &[
            "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern",
            "float", "for", "goto", "if", "inline", "int", "long", "register", "return", "short", "signed", "sizeof",
            "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "bool", "true",
            "false", "NULL", "#include", "#define", "#if", "#ifdef", "#ifndef", "#endif", "#else", "#elif",
        ],
        heading: None,
    },
    Syntax {
        name: "rust",
        exts: &["rs"],
        names: &[],
        shebang: &[],
        line_comment: &["//"],
        block: Some(("/*", "*/")),
        quotes: b"\"",
        keywords: &[
            "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false",
            "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
            "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where", "while",
        ],
        heading: None,
    },
    Syntax {
        name: "python",
        exts: &["py"],
        names: &[],
        shebang: &["python", "python3"],
        line_comment: &["#"],
        block: None,
        quotes: b"\"'",
        keywords: &[
            "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
            "except", "False", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "None",
            "nonlocal", "not", "or", "pass", "raise", "return", "True", "try", "while", "with", "yield",
        ],
        heading: None,
    },
    Syntax {
        name: "make",
        exts: &["mk"],
        names: &["Makefile", "makefile", "GNUmakefile"],
        shebang: &[],
        line_comment: &["#"],
        block: None,
        quotes: b"",
        keywords: &["ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include", "define", "endef", "export"],
        heading: None,
    },
    Syntax {
        name: "markdown",
        exts: &["md", "markdown"],
        names: &[],
        shebang: &[],
        line_comment: &[],
        block: None,
        quotes: b"`",
        keywords: &[],
        heading: Some(b'#'),
    },
    Syntax {
        name: "config",
        exts: &["conf", "cfg", "ini", "toml", "etchrc"],
        names: &["etchrc", "inittab", "fstab", "passwd", "group"],
        shebang: &[],
        line_comment: &["#", ";"],
        block: None,
        quotes: b"\"",
        keywords: &["true", "false", "yes", "no", "on", "off", "set", "unset"],
        heading: Some(b'['),
    },
];

/// The syntax for a file: by its name, its extension, or its `#!` line.
pub fn find(path: Option<&[u8]>, first_line: &[u8]) -> Option<&'static Syntax> {
    let base = path.map(|p| p.rsplit(|&c| c == b'/').next().unwrap_or(p)).unwrap_or_default();
    let base = core::str::from_utf8(base).unwrap_or("");
    if let Some(s) = SYNTAXES.iter().find(|s| s.names.contains(&base)) {
        return Some(s);
    }
    if let Some((_, ext)) = base.rsplit_once('.')
        && let Some(s) = SYNTAXES.iter().find(|s| s.exts.contains(&ext))
    {
        return Some(s);
    }
    let first = core::str::from_utf8(first_line).unwrap_or("");
    let prog = first.strip_prefix("#!")?.split_whitespace().collect::<alloc::vec::Vec<_>>();
    // `#!/usr/bin/env python3` names the program second.
    let name = match prog.as_slice() {
        [env, p, ..] if env.ends_with("/env") => p,
        [p, ..] => p.rsplit('/').next().unwrap_or(p),
        [] => return None,
    };
    SYNTAXES.iter().find(|s| s.shebang.contains(&name))
}

fn word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'#'
}

impl Syntax {
    /// Whether a block comment is still open after `line`, given whether
    /// one was open before it.
    pub fn block_after(&self, line: &[u8], mut open: bool) -> bool {
        let Some((start, end)) = self.block else { return false };
        let mut i = 0;
        let mut quote: Option<u8> = None;
        while i < line.len() {
            let rest = &line[i..];
            if open {
                if rest.starts_with(end.as_bytes()) {
                    open = false;
                    i += end.len();
                    continue;
                }
            } else if let Some(q) = quote {
                if rest[0] == b'\\' {
                    i += 1;
                } else if rest[0] == q {
                    quote = None;
                }
            } else if self.line_comment.iter().any(|c| rest.starts_with(c.as_bytes())) {
                return false;
            } else if rest.starts_with(start.as_bytes()) {
                open = true;
                i += start.len();
                continue;
            } else if self.quotes.contains(&rest[0]) {
                quote = Some(rest[0]);
            }
            i += 1;
        }
        open
    }

    /// The colour of each byte of `line` (`None`: the terminal's own),
    /// a block comment open before it or not.
    pub fn colors(&self, line: &[u8], mut open: bool) -> alloc::vec::Vec<Option<u8>> {
        let mut out = alloc::vec![None; line.len()];
        if let Some(h) = self.heading
            && line.first() == Some(&h)
        {
            out.fill(Some(KEYWORD));
            return out;
        }
        let mut i = 0;
        while i < line.len() {
            let rest = &line[i..];
            if open {
                let (_, end) = self.block.unwrap_or(("", ""));
                let close = rest.windows(end.len().max(1)).position(|w| w == end.as_bytes());
                let stop = close.map_or(line.len(), |k| i + k + end.len());
                out[i..stop].fill(Some(COMMENT));
                i = stop;
                open = false;
                continue;
            }
            // A comment starts a line or follows a blank or `;` (the
            // shell's `$#` is no comment).
            if self.line_comment.iter().any(|c| rest.starts_with(c.as_bytes()))
                && (i == 0 || line[i - 1].is_ascii_whitespace() || line[i - 1] == b';')
            {
                out[i..].fill(Some(COMMENT));
                break;
            }
            if let Some((start, _)) = self.block
                && rest.starts_with(start.as_bytes())
            {
                out[i..i + start.len()].fill(Some(COMMENT));
                i += start.len();
                open = true;
                continue;
            }
            if self.quotes.contains(&rest[0]) {
                let q = rest[0];
                let mut j = i + 1;
                while j < line.len() && line[j] != q {
                    if line[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let stop = (j + 1).min(line.len());
                out[i..stop].fill(Some(STRING));
                i = stop;
                continue;
            }
            if word_byte(rest[0]) && (i == 0 || !word_byte(line[i - 1])) {
                let len = rest.iter().take_while(|&&b| word_byte(b)).count();
                let word = &rest[..len];
                if word[0].is_ascii_digit() {
                    out[i..i + len].fill(Some(NUMBER));
                } else if self.keywords.iter().any(|k| k.as_bytes() == word) {
                    out[i..i + len].fill(Some(KEYWORD));
                }
                i += len;
                continue;
            }
            i += 1;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn found_by_name_extension_and_shebang() {
        assert_eq!(find(Some(b"/x/run.sh"), b"").map(|s| s.name), Some("sh"));
        assert_eq!(find(Some(b"Makefile"), b"").map(|s| s.name), Some("make"));
        assert_eq!(find(Some(b"tool"), b"#!/usr/bin/env python3").map(|s| s.name), Some("python"));
        assert_eq!(find(Some(b"tool"), b"#!/bin/sh -e").map(|s| s.name), Some("sh"));
        assert_eq!(find(Some(b"notes.txt"), b"hello").map(|s| s.name), None);
        assert_eq!(find(None, b"").map(|s| s.name), None);
    }

    #[test]
    fn colours() {
        let sh = find(Some(b"a.sh"), b"").unwrap();
        let c = sh.colors(b"if x; then echo \"a#b\" # note", false);
        assert_eq!(c[0], Some(KEYWORD));
        assert_eq!(c[3], None);
        assert_eq!(c[16], Some(STRING), "the quote");
        assert_eq!(c[18], Some(STRING), "# inside a string");
        assert_eq!(c[c.len() - 1], Some(COMMENT));
        let rs = find(Some(b"m.rs"), b"").unwrap();
        let c = rs.colors(b"let x = 42; /* a */ fn", false);
        assert_eq!((c[0], c[8], c[12], c[20]), (Some(KEYWORD), Some(NUMBER), Some(COMMENT), Some(KEYWORD)));
        // A block comment across lines.
        assert!(rs.block_after(b"x /* open", false));
        assert!(rs.block_after(b"still", true));
        assert!(!rs.block_after(b"done */ y", true));
        assert!(!rs.block_after(b"\"/*\" // /*", false), "in a string, after a line comment");
        let c = rs.colors(b"done */ fn", true);
        assert_eq!((c[0], c[6], c[8]), (Some(COMMENT), Some(COMMENT), Some(KEYWORD)));
        let md = find(Some(b"r.md"), b"").unwrap();
        assert!(md.colors(b"# Title", false).iter().all(|c| *c == Some(KEYWORD)));
    }
}
