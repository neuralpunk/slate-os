// SPDX-License-Identifier: MIT OR Apache-2.0

//! Key bindings (ADR 0149): lesskey source files (lesskey(5)) and less's
//! own commands, written in the same form. A key sequence is a list of
//! symbols: bytes, and the special keys lesskey writes `\kX`.

use alloc::vec::Vec;

/// A key: a byte (0-255), or a special key (`\kX`), 256 + its letter.
pub type Sym = u16;

pub const K_UP: Sym = 256 + b'u' as Sym;
pub const K_DOWN: Sym = 256 + b'd' as Sym;
pub const K_LEFT: Sym = 256 + b'l' as Sym;
pub const K_RIGHT: Sym = 256 + b'r' as Sym;
pub const K_PAGE_UP: Sym = 256 + b'U' as Sym;
pub const K_PAGE_DOWN: Sym = 256 + b'D' as Sym;
pub const K_HOME: Sym = 256 + b'h' as Sym;
pub const K_END: Sym = 256 + b'e' as Sym;
pub const K_INSERT: Sym = 256 + b'i' as Sym;
pub const K_DELETE: Sym = 256 + b'x' as Sym;
pub const K_BACKSPACE: Sym = 256 + b'b' as Sym;

/// What a key sequence does (lesskey(5)'s action names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    ForwLine,
    BackLine,
    ForwScroll,
    BackScroll,
    ForwScreen,
    BackScreen,
    ForwWindow,
    BackWindow,
    ForwForever,
    Repaint,
    RepaintFlush,
    GotoLine,
    Percent,
    GotoEnd,
    Status,
    ForwSearch,
    BackSearch,
    RepeatSearch,
    ReverseSearch,
    SetMark,
    GotoMark,
    NextFile,
    PrevFile,
    IndexFile,
    Examine,
    NextTag,
    PrevTag,
    ToggleOption,
    Visual,
    Shell,
    Pshell,
    Pipe,
    Help,
    Version,
    Digit,
    Quit,
    /// `_`: an option's setting, unchanged.
    DisplayOption,
    /// `&`: only lines that match (or don't).
    Filter,
    /// `{ ( [` and `} ) ]`, the extra string the pair (else typed).
    ForwBracket,
    BackBracket,
    /// Horizontal scrolling (ESC-( ESC-) ESC-] ESC-{ ESC-}).
    LeftScroll,
    RightScroll,
    RightLimitScroll,
    NoScroll,
    EndScroll,
    /// OSC 8 hyperlinks (^O^N ^O^P ^O^L ^O^O).
    Osc8Forw,
    Osc8Back,
    Osc8Jump,
    Osc8Open,
    /// Bound to nothing, with a beep (`invalid`) or without (`noaction`).
    Invalid,
    Nothing,
}

fn action(name: &[u8]) -> Option<Action> {
    use Action::*;
    Some(match name {
        b"forw-line" | b"forw-line-force" | b"forw-newline" => ForwLine,
        b"back-line" | b"back-line-force" | b"back-newline" => BackLine,
        b"forw-scroll" => ForwScroll,
        b"back-scroll" => BackScroll,
        b"forw-screen" | b"forw-screen-force" => ForwScreen,
        b"back-screen" | b"back-screen-force" => BackScreen,
        b"forw-window" => ForwWindow,
        b"back-window" => BackWindow,
        b"forw-forever" => ForwForever,
        b"repaint" => Repaint,
        b"repaint-flush" => RepaintFlush,
        b"goto-line" => GotoLine,
        b"percent" => Percent,
        b"goto-end" | b"goto-end-buffered" => GotoEnd,
        b"status" => Status,
        b"forw-search" => ForwSearch,
        b"back-search" => BackSearch,
        b"repeat-search" | b"repeat-search-all" => RepeatSearch,
        b"reverse-search" | b"reverse-search-all" => ReverseSearch,
        b"set-mark" => SetMark,
        b"goto-mark" => GotoMark,
        b"next-file" => NextFile,
        b"prev-file" => PrevFile,
        b"index-file" => IndexFile,
        b"examine" => Examine,
        b"next-tag" => NextTag,
        b"prev-tag" => PrevTag,
        b"toggle-option" => ToggleOption,
        b"visual" => Visual,
        b"shell" => Shell,
        b"pshell" => Pshell,
        b"pipe" => Pipe,
        b"help" => Help,
        b"version" => Version,
        b"digit" => Digit,
        b"quit" => Quit,
        b"display-option" => DisplayOption,
        b"filter" => Filter,
        b"forw-bracket" => ForwBracket,
        b"back-bracket" => BackBracket,
        b"left-scroll" => LeftScroll,
        b"right-scroll" => RightScroll,
        b"right-limit-scroll" => RightLimitScroll,
        b"no-scroll" => NoScroll,
        b"end-scroll" => EndScroll,
        b"osc8-forw-search" => Osc8Forw,
        b"osc8-back-search" => Osc8Back,
        b"osc8-jump" => Osc8Jump,
        b"osc8-open" => Osc8Open,
        b"invalid" => Invalid,
        b"noaction" => Nothing,
        _ => return None,
    })
}

/// A binding: the keys, what they do, and the extra string typed after.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub keys: Vec<Sym>,
    pub action: Action,
    pub extra: Vec<u8>,
}

/// A line-editing command (lesskey(5), LINE EDITING SECTION).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    ForwComplete,
    BackComplete,
    Expand,
    Literal,
    Right,
    Left,
    WordLeft,
    WordRight,
    Insert,
    Delete,
    WordDelete,
    WordBackspace,
    Home,
    End,
    Up,
    Down,
    Abort,
    Nothing,
}

fn edit_action(name: &[u8]) -> Option<Edit> {
    use Edit::*;
    Some(match name {
        b"forw-complete" => ForwComplete,
        b"back-complete" => BackComplete,
        b"expand" => Expand,
        b"literal" => Literal,
        b"right" => Right,
        b"left" => Left,
        b"word-left" => WordLeft,
        b"word-right" => WordRight,
        b"insert" => Insert,
        b"delete" => Delete,
        b"word-delete" => WordDelete,
        b"word-backspace" => WordBackspace,
        b"home" => Home,
        b"end" => End,
        b"up" => Up,
        b"down" => Down,
        b"abort" => Abort,
        b"noaction" => Nothing,
        _ => return None,
    })
}

/// A line-editing binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EditBinding {
    pub keys: Vec<Sym>,
    pub edit: Edit,
}

/// What a lesskey source gives: its command bindings (and whether it
/// ends with `#stop`, dropping the defaults), its line-editing bindings
/// and its environment.
#[derive(Debug, Default)]
pub struct Lesskey {
    pub bindings: Vec<Binding>,
    pub stop: bool,
    pub edits: Vec<EditBinding>,
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
}

/// One lesskey key string (lesskey(5)): literal characters, `^X`, octal
/// `\NNN`, `\b \e \n \r \t`, `\kX` keys, `\` before anything else.
fn key_string(s: &[u8]) -> Option<Vec<Sym>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'^' if i + 1 < s.len() => {
                out.push(Sym::from(s[i + 1] & 0x1f));
                i += 2;
            }
            b'\\' if i + 1 < s.len() => {
                let c = s[i + 1];
                i += 2;
                match c {
                    b'0'..=b'7' => {
                        let mut v = u16::from(c - b'0');
                        let mut n = 1;
                        while n < 3 && i < s.len() && (b'0'..=b'7').contains(&s[i]) {
                            v = v * 8 + u16::from(s[i] - b'0');
                            i += 1;
                            n += 1;
                        }
                        out.push(v & 0xff);
                    }
                    b'b' => out.push(8),
                    b'e' => out.push(0x1b),
                    b'n' => out.push(b'\n'.into()),
                    b'r' => out.push(b'\r'.into()),
                    b't' => out.push(b'\t'.into()),
                    b'k' => {
                        // Modified keys (\k^d, \k+d) are taken as the key.
                        while matches!(s.get(i), Some(b'^' | b'+')) {
                            i += 1;
                        }
                        let k = *s.get(i)?;
                        i += 1;
                        out.push(256 + Sym::from(k));
                    }
                    c => out.push(c.into()),
                }
            }
            c => {
                out.push(c.into());
                i += 1;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The words of a line: whitespace separates them, `\` escapes a space,
/// and an unescaped `#` starts a comment.
fn words(line: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut cur: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < line.len() {
        let c = line[i];
        match c {
            b'\\' if i + 1 < line.len() => {
                // Kept escaped: the key string's own parse reads it.
                let w = cur.get_or_insert_with(Vec::new);
                w.extend_from_slice(&line[i..i + 2]);
                i += 2;
                continue;
            }
            b'#' if cur.is_none() || out.len() < 2 => break,
            b' ' | b'\t' => {
                if let Some(w) = cur.take() {
                    out.push(w);
                }
            }
            _ => cur.get_or_insert_with(Vec::new).push(c),
        }
        i += 1;
    }
    if let Some(w) = cur {
        out.push(w);
    }
    out
}

/// `${NAME}` and `${NAME/STRING/REPL}` in an #env value.
fn substitute(v: &[u8], lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'$'
            && v.get(i + 1) == Some(&b'{')
            && let Some(end) = v[i..].iter().position(|&c| c == b'}')
        {
            let inner = &v[i + 2..i + end];
            let parts: Vec<&[u8]> = inner.splitn(3, |&c| c == b'/').collect();
            let mut val = lookup(parts[0]).unwrap_or_default();
            if let [_, from, to] = parts[..]
                && !from.is_empty()
            {
                let mut r = Vec::new();
                let mut k = 0;
                while k < val.len() {
                    if val[k..].starts_with(from) {
                        r.extend_from_slice(to);
                        k += from.len();
                    } else {
                        r.push(val[k]);
                        k += 1;
                    }
                }
                val = r;
            }
            out.extend(val);
            i += end + 1;
            continue;
        }
        out.push(v[i]);
        i += 1;
    }
    out
}

/// Parse a lesskey source file.
pub fn parse(text: &[u8], lookup: &dyn Fn(&[u8]) -> Option<Vec<u8>>) -> Lesskey {
    #[derive(PartialEq)]
    enum Section {
        Command,
        LineEdit,
        Env,
    }
    let mut k = Lesskey::default();
    let mut section = Section::Command;
    for line in text.split(|&c| c == b'\n') {
        let t = line.trim_ascii();
        match t {
            b"#command" => section = Section::Command,
            b"#line-edit" => section = Section::LineEdit,
            b"#env" => section = Section::Env,
            b"#stop" => k.stop = true,
            _ if t.is_empty() || (t.starts_with(b"#") && section == Section::Env) => {}
            _ => match section {
                Section::Command => {
                    let w = words(t);
                    let (Some(keys), Some(a)) =
                        (w.first().and_then(|s| key_string(s)), w.get(1).and_then(|a| action(a)))
                    else {
                        continue;
                    };
                    let extra = w.get(2).map(|e| unescape(e)).unwrap_or_default();
                    k.bindings.push(Binding { keys, action: a, extra });
                }
                Section::LineEdit => {
                    let w = words(t);
                    if let (Some(keys), Some(edit)) =
                        (w.first().and_then(|s| key_string(s)), w.get(1).and_then(|a| edit_action(a)))
                    {
                        k.edits.push(EditBinding { keys, edit });
                    }
                }
                Section::Env => {
                    let Some(eq) = t.iter().position(|&c| c == b'=') else { continue };
                    let (name, append) = match t[..eq].trim_ascii() {
                        n if n.ends_with(b"+") => (n[..n.len() - 1].trim_ascii(), true),
                        n => (n, false),
                    };
                    let local = |n: &[u8]| {
                        k.env.iter().rev().find(|(a, _)| a == n).map(|(_, v)| v.clone()).or_else(|| lookup(n))
                    };
                    let value = substitute(t[eq + 1..].trim_ascii(), &local);
                    match (append, k.env.iter_mut().rev().find(|(a, _)| a == name)) {
                        (true, Some((_, v))) => v.extend(value),
                        _ => k.env.push((name.to_vec(), value)),
                    }
                }
            },
        }
    }
    k
}

/// An extra string's escapes (`\n` and the rest, as key strings have).
fn unescape(e: &[u8]) -> Vec<u8> {
    key_string(e).unwrap_or_default().into_iter().filter_map(|s| u8::try_from(s).ok()).collect()
}

/// less's own commands, as a lesskey source (lesskey(5)'s list, the
/// ones Slate's less has).
pub const DEFAULTS: &str = r"#command
\r forw-line
\n forw-line
e forw-line
j forw-line
^E forw-line
^N forw-line
\kd forw-line
J forw-line-force
k back-line
y back-line
^Y back-line
^K back-line
^P back-line
\ku back-line
K back-line-force
Y back-line-force
d forw-scroll
^D forw-scroll
u back-scroll
^U back-scroll
\40 forw-screen
f forw-screen
^F forw-screen
^V forw-screen
\kD forw-screen
b back-screen
^B back-screen
\ev back-screen
\kU back-screen
z forw-window
w back-window
\e\40 forw-screen-force
\eb back-screen-force
F forw-forever
R repaint-flush
r repaint
^R repaint
^L repaint
g goto-line
<	goto-line
\e< goto-line
\kh goto-line
p percent
% percent
G goto-end
\e> goto-end
> goto-end
\ke goto-end
= status
^G status
:f status
/ forw-search
? back-search
n repeat-search
\en repeat-search-all
N reverse-search
\eN reverse-search-all
m set-mark
' goto-mark
^X^X goto-mark
E examine
:e examine
:n next-file
:p prev-file
:x index-file
t next-tag
T prev-tag
- toggle-option
:t toggle-option t
_ display-option
s toggle-option o
& filter
{ forw-bracket {}
} back-bracket {}
( forw-bracket ()
) back-bracket ()
[ forw-bracket []
] back-bracket []
\e^F forw-bracket
\e^B back-bracket
\e( left-scroll
\e) right-scroll
\e] right-limit-scroll
\e{ no-scroll
\e} end-scroll
\kl left-scroll
\kr right-scroll
^O^N osc8-forw-search
^On osc8-forw-search
^O^P osc8-back-search
^Op osc8-back-search
^O^O osc8-open
^Oo osc8-open
^O^L osc8-jump
^Ol osc8-jump
| pipe
v visual
! shell
\# pshell
H help
h help
V version
0 digit
1 digit
2 digit
3 digit
4 digit
5 digit
6 digit
7 digit
8 digit
9 digit
q quit
Q quit
:q quit
:Q quit
ZZ quit
";

/// less's own line-editing keys (lesskey(5)'s list, those a terminal
/// sends Slate's less).
pub const EDIT_DEFAULTS: &str = r"#line-edit
\t forw-complete
\e\t back-complete
^L expand
^V literal
^A literal
\el right
\kr right
\eh left
\kl left
\eb word-left
\ew word-right
\ei insert
\ki insert
\ex delete
\kx delete
\eX word-delete
\e\b word-backspace
\e0 home
\kh home
\e$ end
\ke end
\ek up
\ku up
\ej down
\kd down
^G abort
";

/// The line-editing bindings in force: the files' first, then the
/// defaults.
pub fn edit_table(files: &[Lesskey]) -> Vec<EditBinding> {
    let none = |_: &[u8]| None;
    let mut out: Vec<EditBinding> = files.iter().flat_map(|f| f.edits.iter().cloned()).collect();
    out.extend(parse(EDIT_DEFAULTS.as_bytes(), &none).edits);
    out
}

/// What the keys typed so far select among line-editing bindings.
pub fn lookup_edit(table: &[EditBinding], keys: &[Sym]) -> Option<Option<Edit>> {
    if let Some(b) = table.iter().find(|b| b.keys == keys) {
        return Some(Some(b.edit));
    }
    table.iter().any(|b| b.keys.len() > keys.len() && b.keys.starts_with(keys)).then_some(None)
}

/// The bindings in force: a file's first (user, then system), then the
/// defaults unless one said `#stop`.
pub fn table(files: &[Lesskey]) -> Vec<Binding> {
    let none = |_: &[u8]| None;
    let mut out: Vec<Binding> = files.iter().flat_map(|f| f.bindings.iter().cloned()).collect();
    if !files.iter().any(|f| f.stop) {
        out.extend(parse(DEFAULTS.as_bytes(), &none).bindings);
    }
    out
}

/// What the keys typed so far select: a binding, more keys needed, or
/// nothing.
pub enum Lookup<'a> {
    Found(&'a Binding),
    More,
    None,
}

pub fn lookup<'a>(table: &'a [Binding], keys: &[Sym]) -> Lookup<'a> {
    if let Some(b) = table.iter().find(|b| b.keys == keys) {
        return Lookup::Found(b);
    }
    if table.iter().any(|b| b.keys.len() > keys.len() && b.keys.starts_with(keys)) {
        return Lookup::More;
    }
    Lookup::None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources() {
        let env = |n: &[u8]| (n == b"HOME").then(|| b"/home/ada".to_vec());
        let k = parse(
            b"# mine\n#command\nx quit\n\\kd back-line\n^Xa set-mark b/next\\n\nB set-mark b\n\
              \\# shell\nqq invalid  # comment\n#stop\n#env\nLESS = -R\nLESS += S\nHIST=${HOME}/x\n\
              SUB=${HOME/ada/bob}\n",
            &env,
        );
        assert!(k.stop);
        assert_eq!(
            k.bindings[0],
            Binding { keys: alloc::vec![b'x'.into()], action: Action::Quit, extra: alloc::vec![] }
        );
        assert_eq!(k.bindings[1].keys, [K_DOWN]);
        assert_eq!(k.bindings[2].keys, [0x18, b'a'.into()]);
        assert_eq!(k.bindings[2].extra, b"b/next\n");
        assert_eq!(k.bindings[4].keys, [b'#'.into()]);
        assert_eq!(k.bindings[5].action, Action::Invalid);
        assert_eq!(
            k.env,
            [
                (b"LESS".to_vec(), b"-RS".to_vec()),
                (b"HIST".to_vec(), b"/home/ada/x".to_vec()),
                (b"SUB".to_vec(), b"/home/bob".to_vec())
            ]
        );
        // #stop drops the defaults.
        assert_eq!(table(&[k]).len(), 6);
    }

    #[test]
    fn defaults_and_lookup() {
        let t = table(&[]);
        let sym = |s: &str| s.bytes().map(Sym::from).collect::<Vec<_>>();
        assert!(matches!(lookup(&t, &sym("q")), Lookup::Found(b) if b.action == Action::Quit));
        assert!(matches!(lookup(&t, &sym(":")), Lookup::More));
        assert!(matches!(lookup(&t, &sym(":t")), Lookup::Found(b) if b.extra == b"t"));
        assert!(matches!(lookup(&t, &sym("Z")), Lookup::More));
        assert!(matches!(lookup(&t, &sym("@")), Lookup::None));
        assert!(matches!(lookup(&t, &[0x1b, b'v'.into()]), Lookup::Found(b) if b.action == Action::BackScreen));
        assert!(matches!(lookup(&t, &sym(" ")), Lookup::Found(b) if b.action == Action::ForwScreen));
    }
}
