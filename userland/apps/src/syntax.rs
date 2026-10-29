// SPDX-License-Identifier: MIT OR Apache-2.0

//! The editor's colouring (ADR 0107), WM_STYLE §7's monochrome theme:
//! keywords bright and heavier, types and numbers a step down,
//! identifiers and punctuation quieter, comments muted and slanted.
//! A line is split into runs of a [`Token`] kind, by a small lexer per
//! language: comments (line and block), strings, numbers, words and
//! punctuation. Block comments carry from line to line ([`State`]).

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    Keyword,
    /// Types (capitalised words) and numbers.
    Type,
    Ident,
    Punct,
    Comment,
    String,
    /// Markdown's headings.
    Heading,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    Plain,
    Rust,
    C,
    Python,
    Shell,
    JavaScript,
    Go,
    Toml,
    Markdown,
}

/// Whether a line starts inside a block comment.
pub type State = bool;

impl Lang {
    /// The language of a file, by its name.
    pub fn of(name: &str) -> Lang {
        let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
        match ext.as_str() {
            "rs" => Lang::Rust,
            "c" | "h" | "cc" | "cpp" | "hpp" | "cxx" => Lang::C,
            "py" => Lang::Python,
            "sh" | "bash" => Lang::Shell,
            "js" | "ts" | "mjs" | "json" => Lang::JavaScript,
            "go" => Lang::Go,
            "toml" | "ini" | "conf" | "cfg" => Lang::Toml,
            "md" | "markdown" => Lang::Markdown,
            _ if name.ends_with("Makefile") || name.ends_with("Dockerfile") => Lang::Shell,
            _ => Lang::Plain,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Lang::Plain => "plain text",
            Lang::Rust => "Rust",
            Lang::C => "C",
            Lang::Python => "Python",
            Lang::Shell => "shell",
            Lang::JavaScript => "JavaScript",
            Lang::Go => "Go",
            Lang::Toml => "TOML",
            Lang::Markdown => "Markdown",
        }
    }

    fn keywords(self) -> &'static [&'static str] {
        match self {
            Lang::Rust => &[
                "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
                "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
                "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
                "where", "while",
            ],
            Lang::C => &[
                "auto",
                "break",
                "case",
                "char",
                "const",
                "continue",
                "default",
                "do",
                "double",
                "else",
                "enum",
                "extern",
                "float",
                "for",
                "goto",
                "if",
                "inline",
                "int",
                "long",
                "return",
                "short",
                "signed",
                "sizeof",
                "static",
                "struct",
                "switch",
                "typedef",
                "union",
                "unsigned",
                "void",
                "volatile",
                "while",
                "class",
                "namespace",
                "template",
                "public",
                "private",
                "true",
                "false",
                "NULL",
                "nullptr",
                "bool",
            ],
            Lang::Python => &[
                "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif", "else",
                "except", "False", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "None",
                "nonlocal", "not", "or", "pass", "raise", "return", "True", "try", "while", "with", "yield",
            ],
            Lang::Shell => &[
                "case", "do", "done", "elif", "else", "esac", "export", "fi", "for", "function", "if", "in", "local",
                "return", "then", "until", "while", "readonly", "set", "unset", "shift", "exit",
            ],
            Lang::JavaScript => &[
                "async",
                "await",
                "break",
                "case",
                "catch",
                "class",
                "const",
                "continue",
                "default",
                "delete",
                "do",
                "else",
                "export",
                "extends",
                "false",
                "finally",
                "for",
                "function",
                "if",
                "import",
                "in",
                "instanceof",
                "let",
                "new",
                "null",
                "return",
                "switch",
                "this",
                "throw",
                "true",
                "try",
                "typeof",
                "undefined",
                "var",
                "void",
                "while",
                "yield",
            ],
            Lang::Go => &[
                "break",
                "case",
                "chan",
                "const",
                "continue",
                "default",
                "defer",
                "else",
                "fallthrough",
                "for",
                "func",
                "go",
                "goto",
                "if",
                "import",
                "interface",
                "map",
                "package",
                "range",
                "return",
                "select",
                "struct",
                "switch",
                "type",
                "var",
                "true",
                "false",
                "nil",
            ],
            Lang::Toml => &["true", "false"],
            Lang::Plain | Lang::Markdown => &[],
        }
    }

    fn line_comment(self) -> Option<&'static str> {
        match self {
            Lang::Rust | Lang::C | Lang::JavaScript | Lang::Go => Some("//"),
            Lang::Python | Lang::Shell | Lang::Toml => Some("#"),
            Lang::Plain | Lang::Markdown => None,
        }
    }

    fn block_comments(self) -> bool {
        matches!(self, Lang::Rust | Lang::C | Lang::JavaScript | Lang::Go)
    }
}

/// `line`'s runs as (start, end, token) in characters, and the state the
/// next line starts in.
pub fn tokens(lang: Lang, line: &[char], mut in_comment: State) -> (Vec<(usize, usize, Token)>, State) {
    let mut out: Vec<(usize, usize, Token)> = Vec::new();
    let push = |out: &mut Vec<(usize, usize, Token)>, s: usize, e: usize, t: Token| {
        if e > s {
            match out.last_mut() {
                Some(last) if last.2 == t && last.1 == s => last.1 = e,
                _ => out.push((s, e, t)),
            }
        }
    };
    let n = line.len();
    if lang == Lang::Plain {
        push(&mut out, 0, n, Token::Ident);
        return (out, false);
    }
    if lang == Lang::Markdown {
        let t = if line.first() == Some(&'#') {
            Token::Heading
        } else if line.starts_with(&['`', '`', '`']) || line.starts_with(&[' ', ' ', ' ', ' ']) {
            Token::String
        } else {
            Token::Ident
        };
        push(&mut out, 0, n, t);
        return (out, false);
    }
    let starts = |i: usize, s: &str| s.chars().enumerate().all(|(k, c)| line.get(i + k) == Some(&c));
    let lc = lang.line_comment();
    let mut i = 0;
    while i < n {
        if in_comment {
            let start = i;
            while i < n && !starts(i, "*/") {
                i += 1;
            }
            if i < n {
                i += 2;
                in_comment = false;
            }
            push(&mut out, start, i, Token::Comment);
            continue;
        }
        let c = line[i];
        if lang.block_comments() && starts(i, "/*") {
            in_comment = true;
            continue;
        }
        if let Some(l) = lc
            && starts(i, l)
        {
            push(&mut out, i, n, Token::Comment);
            break;
        }
        if c == '"' || (c == '\'' && lang != Lang::Rust) || (c == '\'' && line.get(i + 2) == Some(&'\'')) {
            let start = i;
            i += 1;
            while i < n && line[i] != c {
                if line[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(n);
            push(&mut out, start, i, Token::String);
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < n && (line[i].is_ascii_alphanumeric() || line[i] == '.' || line[i] == '_') {
                i += 1;
            }
            push(&mut out, start, i, Token::Type);
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < n && (line[i].is_alphanumeric() || line[i] == '_') {
                i += 1;
            }
            let word: alloc::string::String = line[start..i].iter().collect();
            let t = if lang.keywords().contains(&word.as_str()) {
                Token::Keyword
            } else if c.is_uppercase() {
                Token::Type
            } else {
                Token::Ident
            };
            push(&mut out, start, i, t);
            continue;
        }
        push(&mut out, i, i + 1, if c.is_whitespace() { Token::Ident } else { Token::Punct });
        i += 1;
    }
    (out, in_comment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn runs(lang: Lang, s: &str, st: State) -> (Vec<(String, Token)>, State) {
        let chars: Vec<char> = s.chars().collect();
        let (t, next) = tokens(lang, &chars, st);
        let runs = t
            .iter()
            .map(|&(a, b, k)| (chars[a..b].iter().collect::<String>().trim().into(), k))
            .filter(|(s, _): &(String, Token)| !s.is_empty())
            .collect();
        (runs, next)
    }

    #[test]
    fn rust_and_c() {
        let (r, st) = runs(Lang::Rust, "pub fn main() -> u32 { 42 } // done", false);
        let kinds: Vec<Token> = r.iter().map(|x| x.1).collect();
        assert_eq!(r[0], ("pub".into(), Token::Keyword));
        assert_eq!(r[1], ("fn".into(), Token::Keyword));
        assert_eq!(r[2], ("main".into(), Token::Ident));
        assert!(kinds.contains(&Token::Type) && kinds.contains(&Token::Punct));
        assert_eq!(r.last().unwrap(), &("// done".into(), Token::Comment));
        assert!(!st);
        let (r, st) = runs(Lang::C, "int x = 1; /* starts", false);
        assert!(st && r.last().unwrap().1 == Token::Comment);
        let (r, st) = runs(Lang::C, "still */ char *s = \"a\\\"b\";", true);
        assert!(!st);
        assert_eq!(r[0], ("still */".into(), Token::Comment));
        assert!(r.contains(&("\"a\\\"b\"".into(), Token::String)));
        // A Rust lifetime is no string; a character is.
        let (r, _) = runs(Lang::Rust, "fn f<'a>(c: char) { let x = 'y'; }", false);
        assert!(r.contains(&("'y'".into(), Token::String)) && !r.iter().any(|x| x.0.starts_with("'a")));
    }

    #[test]
    fn languages() {
        assert_eq!(
            (Lang::of("main.rs"), Lang::of("x.H"), Lang::of("README.md")),
            (Lang::Rust, Lang::C, Lang::Markdown)
        );
        assert_eq!((Lang::of("Makefile"), Lang::of("notes")), (Lang::Shell, Lang::Plain));
        let (r, _) = runs(Lang::Python, "def f(): return None  # why", false);
        assert_eq!((r[0].1, r.last().unwrap().1), (Token::Keyword, Token::Comment));
        let (r, _) = runs(Lang::Markdown, "## Keys", false);
        assert_eq!(r[0].1, Token::Heading);
    }
}
