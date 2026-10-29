// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask keymaps`: the keyboard layouts (ADR 0117), made from
//! xkeyboard-config's symbols files (MIT; the data ADR 0033 and ADR 0039
//! already take keys from) into `libs/term/src/layouts.rs`, with the
//! dead keys' compositions from the Unicode Character Database.
//!
//! - **Layouts:** each of [`LAYOUTS`] read from `SLATE_XKB` (default
//!   `/usr/share/X11/xkb/symbols`, Fedora's `xkeyboard-config`) after
//!   `pc`, as XKB's rules read them: its
//!   variant's `key` statements after the files it includes, level by
//!   level as xkbcomp merges them (a later symbol replaces an earlier one,
//!   `NoSymbol` keeps it). The main block's keys only, four levels each;
//!   the right Alt key is AltGr when the layout includes
//!   `level3(ralt_switch)`.
//! - **Keysyms** become characters by `SLATE_KEYSYMDEF` (default
//!   `/usr/include/X11/keysymdef.h`, the X.Org protocol headers): the
//!   `U+XXXX` its comments give, `UXXXX` names, and dead keys as the
//!   combining marks they put on the next letter.
//! - **Compositions:** UnicodeData.txt's canonical decompositions of one
//!   character into a base and one of those marks (`SLATE_UCD`, as for
//!   `cargo xtask unicode`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::{Result, root};

/// The layouts Slate has: (name, symbols file, variant).
const LAYOUTS: &[(&str, &str, &str)] = &[
    ("us", "us", "basic"),
    ("us(intl)", "us", "intl"),
    ("gb", "gb", "basic"),
    ("de", "de", "basic"),
    ("ch", "ch", "basic"),
    ("fr", "fr", "basic"),
    ("be", "be", "basic"),
    ("es", "es", "basic"),
    ("latam", "latam", "basic"),
    ("it", "it", "basic"),
    ("pt", "pt", "basic"),
    ("se", "se", "basic"),
    ("no", "no", "basic"),
    ("dk", "dk", "basic"),
    ("fi", "fi", "classic"),
    ("pl", "pl", "basic"),
];

/// The main block's keys: XKB names and evdev codes (input-event-codes.h).
const KEYS: &[(&str, u16)] = &[
    ("TLDE", 41),
    ("AE01", 2),
    ("AE02", 3),
    ("AE03", 4),
    ("AE04", 5),
    ("AE05", 6),
    ("AE06", 7),
    ("AE07", 8),
    ("AE08", 9),
    ("AE09", 10),
    ("AE10", 11),
    ("AE11", 12),
    ("AE12", 13),
    ("AD01", 16),
    ("AD02", 17),
    ("AD03", 18),
    ("AD04", 19),
    ("AD05", 20),
    ("AD06", 21),
    ("AD07", 22),
    ("AD08", 23),
    ("AD09", 24),
    ("AD10", 25),
    ("AD11", 26),
    ("AD12", 27),
    ("AC01", 30),
    ("AC02", 31),
    ("AC03", 32),
    ("AC04", 33),
    ("AC05", 34),
    ("AC06", 35),
    ("AC07", 36),
    ("AC08", 37),
    ("AC09", 38),
    ("AC10", 39),
    ("AC11", 40),
    ("BKSL", 43),
    ("AB01", 44),
    ("AB02", 45),
    ("AB03", 46),
    ("AB04", 47),
    ("AB05", 48),
    ("AB06", 49),
    ("AB07", 50),
    ("AB08", 51),
    ("AB09", 52),
    ("AB10", 53),
    ("LSGT", 86),
    ("SPCE", 57),
];

/// Dead keysyms and the combining marks they put on the next letter (the
/// marks UnicodeData.txt names: COMBINING GRAVE ACCENT and on).
const DEAD: &[(&str, u32)] = &[
    ("dead_grave", 0x300),
    ("dead_acute", 0x301),
    ("dead_circumflex", 0x302),
    ("dead_tilde", 0x303),
    ("dead_perispomeni", 0x342),
    ("dead_macron", 0x304),
    ("dead_breve", 0x306),
    ("dead_abovedot", 0x307),
    ("dead_diaeresis", 0x308),
    ("dead_hook", 0x309),
    ("dead_abovering", 0x30A),
    ("dead_doubleacute", 0x30B),
    ("dead_caron", 0x30C),
    ("dead_horn", 0x31B),
    ("dead_belowdot", 0x323),
    ("dead_belowcomma", 0x326),
    ("dead_cedilla", 0x327),
    ("dead_ogonek", 0x328),
    ("dead_belowmacron", 0x331),
];

/// A level: nothing, a character, or a dead key's mark (bit 31 set), as
/// the generated table stores them.
const DEAD_BIT: u32 = 1 << 31;

/// Keysym names to characters, from keysymdef.h.
fn keysyms(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("#define XK_") else { continue };
        let mut w = rest.split_whitespace();
        let (Some(name), Some(value)) = (w.next(), w.next()) else { continue };
        let Some(v) = value.strip_prefix("0x").and_then(|v| u32::from_str_radix(v, 16).ok()) else { continue };
        let named = rest.split_once("/* U+").and_then(|(_, u)| u32::from_str_radix(u.get(..4)?, 16).ok());
        let c = match named {
            Some(u) => u,
            None if (0x20..=0x7E).contains(&v) || (0xA0..=0xFF).contains(&v) => v,
            None if (0x0100_0100..=0x0110_FFFF).contains(&v) => v - 0x0100_0000,
            None => continue,
        };
        out.insert(name.to_string(), c);
    }
    out
}

/// A symbol's value: None for `NoSymbol` (keeps what is there), Some(0)
/// for one Slate cannot type.
fn symbol(name: &str, syms: &BTreeMap<String, u32>) -> Option<u32> {
    let name = name.trim();
    if name.is_empty() || name == "NoSymbol" {
        return None;
    }
    if let Some((_, mark)) = DEAD.iter().find(|(d, _)| *d == name) {
        return Some(DEAD_BIT | mark);
    }
    if let Some(hex) = name.strip_prefix('U').filter(|h| h.len() >= 4 && h.chars().all(|c| c.is_ascii_hexdigit())) {
        return Some(u32::from_str_radix(hex, 16).unwrap_or(0));
    }
    if let Some(hex) = name.strip_prefix("0x") {
        let v = u32::from_str_radix(hex, 16).unwrap_or(0);
        return Some(if v >= 0x0100_0000 { v - 0x0100_0000 } else { v });
    }
    if name.len() == 1 && name.as_bytes()[0].is_ascii_digit() {
        return Some(u32::from(name.as_bytes()[0]));
    }
    Some(syms.get(name).copied().unwrap_or(0))
}

/// What a layout's reading found: its description, its keys' four levels
/// and whether the right Alt key is AltGr.
#[derive(Default)]
struct Read {
    name: Option<String>,
    keys: BTreeMap<String, [Option<u32>; 4]>,
    altgr: bool,
}

/// The text after the comments are gone.
fn uncomment(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("//") {
            rest = r.find('\n').map_or("", |i| &r[i..]);
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = r.find("*/").map_or("", |i| &r[i + 2..]);
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    out
}

/// The body of variant `variant` (the file's default with None) of a
/// symbols file.
fn variant_body(text: &str, variant: Option<&str>) -> Option<String> {
    let text = uncomment(text);
    let mut at = 0;
    let mut first: Option<String> = None;
    while let Some(i) = text[at..].find("xkb_symbols") {
        let start = at + i;
        let head = &text[..start];
        // The flags before it, back to the previous block's end.
        let flags = &head[head.rfind("};").map_or(0, |e| e + 2)..];
        let name_at = text[start..].find('"')? + start + 1;
        let name_end = text[name_at..].find('"')? + name_at;
        let name = &text[name_at..name_end];
        let open = text[name_end..].find('{')? + name_end;
        let mut depth = 0;
        let mut close = open;
        for (j, c) in text[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + j;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = text[open + 1..close].to_string();
        match variant {
            Some(v) if v == name => return Some(body),
            None if flags.split_whitespace().any(|f| f == "default") => return Some(body),
            _ => {}
        }
        first.get_or_insert(body);
        at = close;
    }
    if variant.is_none() { first } else { None }
}

/// Read `file(variant)` into `r`, its includes first where they stand.
fn read(
    dir: &PathBuf,
    file: &str,
    variant: Option<&str>,
    syms: &BTreeMap<String, u32>,
    r: &mut Read,
    depth: u32,
) -> Result {
    if depth > 16 {
        return Err(format!("{file}: includes too deep"));
    }
    let text = std::fs::read_to_string(dir.join(file)).map_err(|e| format!("{}: {e}", dir.join(file).display()))?;
    let body = variant_body(&text, variant).ok_or_else(|| format!("{file}: no variant {variant:?}"))?;
    let mut rest = body.as_str();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            return Ok(());
        }
        let word: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        match word.as_str() {
            "include" | "augment" | "override" | "replace" if rest[word.len()..].trim_start().starts_with('"') => {
                let s = rest[word.len()..].trim_start();
                let end = s[1..].find('"').ok_or("an unterminated include")? + 1;
                for part in s[1..end].split(['+', '|']) {
                    let (f, v) = match part.split_once('(') {
                        Some((f, v)) => (f, Some(v.trim_end_matches(')'))),
                        None => (part, None),
                    };
                    if f == "level3" && v.is_some_and(|v| v.starts_with("ralt_switch")) {
                        r.altgr = true;
                    }
                    // Only the files that type characters.
                    if !["level3", "level5", "kpdl", "keypad", "eurosign", "compose", "nbsp"].contains(&f) {
                        read(dir, f, v, syms, r, depth + 1)?;
                    }
                }
                rest = &s[end + 1..];
            }
            _ => {
                // A statement, to its `;` at depth 0.
                let mut depth = 0;
                let mut end = rest.len();
                for (j, c) in rest.char_indices() {
                    match c {
                        '{' | '[' | '(' => depth += 1,
                        '}' | ']' | ')' => depth -= 1,
                        ';' if depth == 0 => {
                            end = j;
                            break;
                        }
                        _ => {}
                    }
                }
                statement(&rest[..end], syms, r);
                rest = rest.get(end + 1..).unwrap_or("");
            }
        }
    }
}

/// One statement: a key's symbols, or the layout's name.
fn statement(s: &str, syms: &BTreeMap<String, u32>, r: &mut Read) {
    let s = s.trim();
    let s = ["replace ", "override ", "augment "].iter().fold(s, |s, p| s.strip_prefix(p).unwrap_or(s)).trim();
    if let Some(n) = s.strip_prefix("name[") {
        if r.name.is_none()
            && let Some(v) = n.split_once('"').and_then(|(_, v)| v.split_once('"'))
        {
            r.name = Some(v.0.to_string());
        }
        return;
    }
    let Some(k) = s.strip_prefix("key").map(str::trim_start).and_then(|k| k.strip_prefix('<')) else { return };
    let Some((name, body)) = k.split_once('>') else { return };
    // The symbols: `symbols[Group1] = [ ... ]`, or the first list that is
    // not an index (`type[Group1]`).
    let mut list = None;
    let mut at = 0;
    while let Some(i) = body[at..].find('[') {
        let open = at + i;
        let close = body[open..].find(']').map_or(body.len(), |j| open + j);
        let inner = &body[open + 1..close];
        let before = body[..open].trim_end();
        let index = inner.trim().to_ascii_lowercase().starts_with("group");
        if !index && !before.ends_with("type") && !before.ends_with("actions") && !before.ends_with("vmods") {
            list = Some(inner.to_string());
            break;
        }
        at = close + 1;
    }
    let Some(list) = list else { return };
    let levels = r.keys.entry(name.to_string()).or_default();
    for (i, sym) in list.split(',').take(4).enumerate() {
        if let Some(v) = symbol(sym, syms) {
            levels[i] = Some(v);
        }
    }
}

/// The compositions: (mark, base, composed), sorted.
fn compositions(data: &str) -> Vec<(u32, u32, u32)> {
    let marks: Vec<u32> = DEAD.iter().map(|d| d.1).collect();
    let mut out = Vec::new();
    for line in data.lines() {
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 6 || f[5].is_empty() || f[5].starts_with('<') {
            continue;
        }
        let parts: Vec<u32> = f[5].split_whitespace().filter_map(|h| u32::from_str_radix(h, 16).ok()).collect();
        let Ok(c) = u32::from_str_radix(f[0], 16) else { continue };
        if let [base, mark] = parts[..]
            && marks.contains(&mark)
            && base < 0x2000
            && c <= 0xFFFF
        {
            out.push((mark, base, c));
        }
    }
    out.sort_unstable();
    out
}

pub fn generate() -> Result {
    let dir = PathBuf::from(std::env::var("SLATE_XKB").unwrap_or_else(|_| "/usr/share/X11/xkb/symbols".into()));
    let def = std::env::var("SLATE_KEYSYMDEF").unwrap_or_else(|_| "/usr/include/X11/keysymdef.h".into());
    let ucd = PathBuf::from(std::env::var("SLATE_UCD").unwrap_or_else(|_| "/usr/share/unicode/ucd".into()));
    let syms = keysyms(&std::fs::read_to_string(&def).map_err(|e| format!("{def}: {e}"))?);
    let data = std::fs::read_to_string(ucd.join("UnicodeData.txt")).map_err(|e| format!("UnicodeData.txt: {e}"))?;
    let mut s = String::from(
        "// SPDX-License-Identifier: MIT OR Apache-2.0\n\n\
         //! Generated by `cargo xtask keymaps` (ADR 0117) from xkeyboard-config's\n\
         //! symbols files (MIT) and the Unicode Character Database: do not edit.\n\n\
         /// The main block's keys, by evdev code, in the order of each layout's\n\
         /// table.\n",
    );
    s += &format!(
        "pub(crate) const KEYS: [u16; {}] = [{}];\n\n",
        KEYS.len(),
        KEYS.iter().map(|k| k.1.to_string()).collect::<Vec<_>>().join(", ")
    );
    s += "/// A level: 0 nothing, a character, or a dead key's combining mark with\n/// bit 31 set.\n";
    s += &format!(
        "pub(crate) struct Data {{\n    pub name: &'static str,\n    pub description: &'static str,\n    pub altgr: bool,\n    pub keys: [[u32; 4]; {}],\n}}\n\n",
        KEYS.len()
    );
    s += "pub(crate) const LAYOUTS: &[Data] = &[\n";
    for (name, file, variant) in LAYOUTS {
        // `pc` first, as XKB's rules put it before every layout
        // (`pc+us`): the 102nd key's `<` and `>` come from it.
        let mut r = Read::default();
        read(&dir, "pc", None, &syms, &mut r, 0)?;
        read(&dir, file, Some(variant), &syms, &mut r, 0)?;
        // xkeyboard-config's names, one shortened to fit the installer's
        // list.
        let description = match *name {
            "us(intl)" => String::from("English (US, international)"),
            _ => r.name.clone().ok_or_else(|| format!("{name}: no name"))?,
        };
        s += &format!(
            "    Data {{\n        name: {name:?},\n        description: {description:?},\n        altgr: {},\n        keys: [\n",
            r.altgr
        );
        for (key, code) in KEYS {
            let mut levels = r.keys.get(*key).copied().unwrap_or_default().map(|l| l.unwrap_or(0));
            if *key == "SPCE" {
                levels = [0x20, 0x20, 0x20, 0x20];
            }
            // Without AltGr, levels three and four cannot be reached.
            if !r.altgr {
                levels[2] = 0;
                levels[3] = 0;
            }
            let shown: Vec<String> = levels.iter().map(|l| format!("0x{l:X}")).collect();
            s += &format!("            [{}], // {key} ({code})\n", shown.join(", "));
        }
        s += "        ],\n    },\n";
    }
    s += "];\n\n";
    let comp = compositions(&data);
    s += "/// Dead keys' compositions: (combining mark, base, composed), sorted.\n";
    s += &format!("pub(crate) const COMPOSE: [(u16, u16, u16); {}] = [\n", comp.len());
    for chunk in comp.chunks(4) {
        let items: Vec<String> = chunk.iter().map(|(m, b, c)| format!("(0x{m:04X}, 0x{b:04X}, 0x{c:04X})")).collect();
        s += &format!("    {},\n", items.join(", "));
    }
    s += "];\n";
    let out = root().join("libs/term/src/layouts.rs");
    std::fs::write(&out, s).map_err(|e| format!("{}: {e}", out.display()))?;
    // As `cargo fmt` would have it (rustfmt.toml), so the check passes.
    crate::run_cmd(std::process::Command::new("rustfmt").args(["--edition", "2024"]).arg(&out))?;
    println!("xtask: wrote {} ({} layouts, {} compositions)", out.display(), LAYOUTS.len(), comp.len());
    Ok(())
}
