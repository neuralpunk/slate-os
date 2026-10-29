// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask unicode`: the terminal's character widths (ADR 0099),
//! made from the Unicode Character Database (UAX #44) into
//! `libs/term/src/width_table.rs`. The database is read from
//! `SLATE_UCD` (default `/usr/share/unicode/ucd`, Fedora's
//! `unicode-ucd`).
//!
//! - Two columns: East_Asian_Width W or F (UAX #11), and the unassigned
//!   code points EastAsianWidth.txt says default to W.
//! - No columns: General_Category Mn, Me and Cf (except U+00AD SOFT
//!   HYPHEN, which shows), and the Hangul jamo vowels and final
//!   consonants (U+1160–U+11FF, U+D7B0–U+D7FF), which join the syllable
//!   before them.
//! - One column: everything else (controls are the emulator's business).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::{Result, root};

/// Code point ranges from a UCD file's first field (`X` or `X..Y`).
fn range(field: &str) -> Option<(u32, u32)> {
    let field = field.trim();
    let (a, b) = field.split_once("..").unwrap_or((field, field));
    Some((u32::from_str_radix(a, 16).ok()?, u32::from_str_radix(b, 16).ok()?))
}

/// Merge touching or overlapping ranges.
fn merge(mut v: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    v.sort_unstable();
    let mut out: Vec<(u32, u32)> = Vec::new();
    for (a, b) in v {
        match out.last_mut() {
            Some(last) if a <= last.1 + 1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

fn table(name: &str, v: &[(u32, u32)]) -> String {
    let mut s = format!("pub(crate) const {name}: &[(u32, u32)] = &[\n");
    for chunk in v.chunks(4) {
        let items: Vec<String> = chunk.iter().map(|(a, b)| format!("(0x{a:05X}, 0x{b:05X})")).collect();
        s.push_str(&format!("    {},\n", items.join(", ")));
    }
    s.push_str("];\n");
    s
}

pub fn generate() -> Result {
    let dir = PathBuf::from(std::env::var("SLATE_UCD").unwrap_or_else(|_| "/usr/share/unicode/ucd".into()));
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).map_err(|e| format!("{}: {e}", dir.join(n).display()));
    let eaw = read("EastAsianWidth.txt")?;
    let data = read("UnicodeData.txt")?;
    let version = eaw
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# EastAsianWidth-"))
        .and_then(|l| l.strip_suffix(".txt"))
        .ok_or("EastAsianWidth.txt has no version line")?
        .to_string();

    // UAX #11: unassigned code points in these default to W.
    let mut wide: Vec<(u32, u32)> =
        vec![(0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x2FFFD), (0x30000, 0x3FFFD)];
    // Listed values override the defaults: collect them per code point.
    let mut listed: BTreeMap<u32, bool> = BTreeMap::new();
    for line in eaw.lines() {
        let line = line.split('#').next().unwrap_or("");
        let Some((cp, value)) = line.split_once(';') else { continue };
        let Some((a, b)) = range(cp) else { continue };
        let w = matches!(value.trim(), "W" | "F");
        for c in a..=b {
            listed.insert(c, w);
        }
    }
    let mut narrow_listed = Vec::new();
    for (&c, &w) in &listed {
        if w {
            wide.push((c, c));
        } else {
            narrow_listed.push(c);
        }
    }
    // Remove listed narrow code points from the default ranges.
    let mut wide = merge(wide);
    for c in narrow_listed {
        if let Some(i) = wide.iter().position(|&(a, b)| a <= c && c <= b) {
            let (a, b) = wide.remove(i);
            if c > a {
                wide.insert(i, (a, c - 1));
            }
            if c < b {
                wide.insert(i + usize::from(c > a), (c + 1, b));
            }
        }
    }

    let mut zero: Vec<(u32, u32)> = vec![(0x1160, 0x11FF), (0xD7B0, 0xD7FF)];
    let mut first: Option<u32> = None;
    for line in data.lines() {
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 3 {
            continue;
        }
        let Ok(c) = u32::from_str_radix(f[0], 16) else { continue };
        // Ranges are given as a First and a Last line.
        let (a, b) = if f[1].ends_with(", First>") {
            first = Some(c);
            continue;
        } else if f[1].ends_with(", Last>") {
            (first.take().unwrap_or(c), c)
        } else {
            (c, c)
        };
        if matches!(f[2], "Mn" | "Me" | "Cf") && c != 0xAD {
            zero.push((a, b));
        }
    }
    let zero = merge(zero);
    let wide = merge(wide);

    let mut out = String::from("// SPDX-License-Identifier: MIT OR Apache-2.0\n\n");
    out.push_str(&format!(
        "//! Character widths from the Unicode Character Database {version} (UAX #11\n\
         //! East_Asian_Width, UAX #44 General_Category), made by `cargo xtask\n\
         //! unicode` (tools/xtask/src/unicode.rs, ADR 0099). Do not edit.\n\n"
    ));
    out.push_str(&format!("/// The database's version.\npub const UNICODE_VERSION: &str = \"{version}\";\n\n"));
    out.push_str("/// Code points that take no column (combining marks, format characters).\n");
    out.push_str(&table("ZERO", &zero));
    out.push_str("\n/// Code points that take two columns.\n");
    out.push_str(&table("WIDE", &wide));
    let path = root().join("libs/term/src/width_table.rs");
    std::fs::write(&path, out).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "xtask: wrote {} (Unicode {version}: {} zero-width and {} wide ranges)",
        path.display(),
        zero.len(),
        wide.len()
    );
    Ok(())
}
