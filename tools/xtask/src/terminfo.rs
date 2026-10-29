// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask terminfo`: the standard terminfo capability names in the
//! order compiled entries store them (term(5): "the same order as in the
//! header file term.h", which we do not read), into
//! `userland/coreutils/src/terminfo_caps.rs` for tput (ADR 0144).
//!
//! The names come from terminfo(5)'s three tables (the host's man page,
//! `man -P cat 5 terminfo`); each name's place is then confirmed by
//! compiling an entry with that capability alone with the host's `tic`
//! and finding which slot it filled. A table whose order differs from
//! the compiled one stops the generator.

use std::path::Path;
use std::process::Command;

use crate::{Result, root};

/// The capability names of terminfo(5)'s Boolean, numeric and string
/// tables, in the tables' order.
fn from_man_page() -> Result<[Vec<String>; 3]> {
    let out = Command::new("man")
        .args(["-P", "cat", "5", "terminfo"])
        .env("MANWIDTH", "220")
        .env_remove("MAN_KEEP_FORMATTING")
        .output()
        .map_err(|e| format!("man: {e}"))?;
    // Overstrikes (X backspace X) and SGR sequences as plain text.
    let mut text = Vec::new();
    let mut i = 0;
    let o = &out.stdout;
    while i < o.len() {
        match o[i] {
            8 => {
                text.pop();
            }
            0x1b if o.get(i + 1) == Some(&b'[') => {
                i += 2;
                while i < o.len() && !o[i].is_ascii_alphabetic() {
                    i += 1;
                }
            }
            b => text.push(b),
        }
        i += 1;
    }
    let text = String::from_utf8_lossy(&text);
    let mut tables: [Vec<String>; 3] = Default::default();
    let mut current: Option<usize> = None;
    for line in text.lines() {
        let t = line.trim_start();
        if line.starts_with("   ") && !line.starts_with("    ") {
            // A section heading ends the tables' part.
            if current.is_some() && t.starts_with("User-Defined Capabilities") {
                break;
            }
        }
        for (i, kind) in ["Boolean", "Numeric", "String"].iter().enumerate() {
            if t.starts_with(&format!("{kind} Capability Name")) || t.starts_with(&format!("{kind}       Capability")) {
                current = Some(i);
            }
        }
        let Some(k) = current else { continue };
        // A row: variable name, capname, termcap code, description; the
        // rows start at the table's indentation (continuations deeper).
        let indent = line.len() - t.len();
        if indent != 7 {
            continue;
        }
        let w: Vec<&str> = t.split_whitespace().collect();
        if w.len() >= 3
            && w[0].len() > 2
            && w[0].chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && w[1].chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && (1..=2).contains(&w[2].len())
        {
            tables[k].push(w[1].to_string());
        }
    }
    if tables.iter().any(Vec::is_empty) {
        return Err("terminfo(5) has no capability tables that could be read".into());
    }
    Ok(tables)
}

/// The slot `name` (of table `kind`: 0 Boolean, 1 numeric, 2 string)
/// fills in an entry `tic` compiles with it alone.
fn slot(dir: &Path, kind: usize, name: &str) -> Result<Vec<usize>> {
    let value = match kind {
        0 => name.to_string(),
        1 => format!("{name}#1"),
        _ => format!("{name}=X"),
    };
    let src = dir.join("one.ti");
    std::fs::write(&src, format!("zz|probe,\n\t{value},\n")).map_err(|e| e.to_string())?;
    let out = Command::new("tic").arg("-o").arg(dir).arg(&src).output().map_err(|e| format!("tic: {e}"))?;
    if !out.status.success() {
        return Err(format!("tic refused {name}: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let d = std::fs::read(dir.join("z/zz")).map_err(|e| e.to_string())?;
    let short = |at: usize| i16::from_le_bytes([d[at], d[at + 1]]);
    let (magic, names, bools, nums, strs) =
        (short(0), short(2) as usize, short(4) as usize, short(6) as usize, short(8) as usize);
    let width = if magic == 0o1036 { 4 } else { 2 };
    let mut at = 12 + names;
    let b = &d[at..at + bools];
    at += bools + (at + bools) % 2;
    let n: Vec<i32> = (0..nums)
        .map(|i| {
            let p = at + i * width;
            if width == 4 { i32::from_le_bytes([d[p], d[p + 1], d[p + 2], d[p + 3]]) } else { i32::from(short(p)) }
        })
        .collect();
    at += nums * width;
    let s: Vec<i16> = (0..strs).map(|i| short(at + 2 * i)).collect();
    Ok(match kind {
        0 => b.iter().enumerate().filter(|(_, v)| **v == 1).map(|(i, _)| i).collect(),
        1 => n.iter().enumerate().filter(|(_, v)| **v == 1).map(|(i, _)| i).collect(),
        _ => s.iter().enumerate().filter(|(_, v)| **v >= 0).map(|(i, _)| i).collect(),
    })
}

pub fn generate() -> Result {
    let tables = from_man_page()?;
    let dir = root().join("target/terminfo-probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for (kind, names) in tables.iter().enumerate() {
        for (i, name) in names.iter().enumerate() {
            let got = slot(&dir, kind, name)?;
            if got != [i] {
                return Err(format!("{name}: terminfo(5) lists it at {i}, tic stores it at {got:?}"));
            }
        }
    }
    let list = |v: &[String]| {
        let mut s = String::new();
        for chunk in v.chunks(10) {
            s.push_str("    ");
            s.push_str(&chunk.iter().map(|n| format!("{n:?},")).collect::<Vec<_>>().join(" "));
            s.push('\n');
        }
        s
    };
    let out = format!(
        "// SPDX-License-Identifier: MIT OR Apache-2.0\n\n\
         //! The standard terminfo capabilities in the order compiled entries\n\
         //! store them (term(5)): made by `cargo xtask terminfo` from terminfo(5)'s\n\
         //! tables, each place confirmed with the host's tic. Do not edit.\n\n\
         pub const BOOLEANS: &[&str] = &[\n{}];\n\n\
         pub const NUMBERS: &[&str] = &[\n{}];\n\n\
         pub const STRINGS: &[&str] = &[\n{}];\n",
        list(&tables[0]),
        list(&tables[1]),
        list(&tables[2])
    );
    let path = root().join("userland/coreutils/src/terminfo_caps.rs");
    std::fs::write(&path, out).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "xtask: {} Boolean, {} numeric and {} string capabilities, each checked with tic -> {}",
        tables[0].len(),
        tables[1].len(),
        tables[2].len(),
        path.display()
    );
    Ok(())
}
