// SPDX-License-Identifier: MIT OR Apache-2.0

//! awk (POSIX.1-2017 XCU awk, with the gawk extensions scripts commonly
//! use: `**`, `nextfile`, `delete arr`, `length(arr)`, `gensub`, regex RS,
//! `match(s, re, arr)`, `systime`/`strftime`, octal and hex constants).

mod big;
mod interp;
mod lex;
mod math;
mod parse;
mod value;

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::lossy;

use crate::util::error;

/// `@include "file"` lines (and `-i`) replaced by the files' text, each
/// file once, found as given or in AWKPATH (default `.:/usr/share/awk`),
/// with `.awk` added if need be (as gawk looks for them).
fn include(src: &[u8], seen: &mut Vec<Vec<u8>>, depth: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (n, line) in src.split(|&c| c == b'\n').enumerate() {
        if n > 0 {
            out.push(b'\n');
        }
        let t = line.trim_ascii_start();
        let Some(rest) = t.strip_prefix(b"@include") else {
            out.extend_from_slice(line);
            continue;
        };
        let rest = rest.trim_ascii_start();
        let name = match rest.strip_prefix(b"\"").and_then(|r| r.iter().position(|&c| c == b'"').map(|e| &r[..e])) {
            Some(n) if !n.is_empty() => n.to_vec(),
            _ => return Err(String::from("@include needs a file name in quotes")),
        };
        if depth > 32 {
            return Err(String::from("@include: too deeply nested"));
        }
        // `-i inplace` with no inplace.awk on AWKPATH: Slate's own (ADR
        // 0165), the built-in extension around each file.
        if find_source(&name).is_none() && matches!(name.as_slice(), b"inplace" | b"inplace.awk") {
            if !seen.iter().any(|s| s == b"\0inplace") {
                seen.push(b"\0inplace".to_vec());
                out.extend_from_slice(INPLACE);
            }
            continue;
        }
        let path = find_source(&name).ok_or_else(|| {
            alloc::format!("cannot open source file `{}' for reading: No such file or directory", lossy(&name))
        })?;
        if seen.contains(&path) {
            continue;
        }
        seen.push(path.clone());
        let text = crate::util::read_input(&path)
            .map_err(|e| alloc::format!("can't open source file `{}': {e}", lossy(&path)))?;
        out.extend(include(&text, seen, depth + 1)?);
    }
    Ok(out)
}

/// What `-i inplace` adds: each file's output written to a new file that
/// replaces it (a backup kept when INPLACE_SUFFIX is set).
const INPLACE: &[u8] = b"@load \"inplace\"; BEGINFILE { inplace::begin(FILENAME, INPLACE_SUFFIX) } \
ENDFILE { inplace::end(FILENAME, INPLACE_SUFFIX) }";

fn find_source(name: &[u8]) -> Option<Vec<u8>> {
    let with = [name, b".awk"].concat();
    if name.contains(&b'/') {
        return [name.to_vec(), with].into_iter().find(|p| slate_rt::fs::exists(p));
    }
    let path = slate_rt::env::var(b"AWKPATH").unwrap_or_else(|| b".:/usr/share/awk".to_vec());
    for dir in path.split(|&c| c == b':') {
        let dir: &[u8] = if dir.is_empty() { b"." } else { dir };
        for n in [name, &with] {
            let p = slate_rt::fs::join(dir, n);
            if slate_rt::fs::exists(&p) {
                return Some(p);
            }
        }
    }
    None
}

/// What --version and PROCINFO["version"] say.
pub const VERSION: &[u8] = b"0.1";

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut fs: Option<Vec<u8>> = None;
    let mut assigns: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut progs: Vec<Vec<u8>> = Vec::new();
    let mut includes: Vec<Vec<u8>> = Vec::new();
    let mut i = 1;
    while let Some(a) = args.get(i) {
        if a.len() < 2 || a[0] != b'-' {
            break;
        }
        if a == b"--" {
            i += 1;
            break;
        }
        let (opt, attached) = (a[1], &a[2..]);
        let value = |i: &mut usize| -> Option<Vec<u8>> {
            if !attached.is_empty() {
                return Some(attached.to_vec());
            }
            *i += 1;
            args.get(*i).cloned()
        };
        match opt {
            b'F' => match value(&mut i) {
                Some(v) => fs = Some(if v == b"t" { b"\t".to_vec() } else { interp::process_escapes(&v) }),
                None => {
                    error("option requires an argument -- F");
                    return 2;
                }
            },
            b'v' => match value(&mut i) {
                Some(v) => match v.iter().position(|&c| c == b'=') {
                    Some(eq) if crate::util::is_name(&v[..eq]) => {
                        assigns.push((v[..eq].to_vec(), v[eq + 1..].to_vec()))
                    }
                    _ => {
                        error(alloc::format!("`{}' argument to `-v' not in `var=value' form", lossy(&v)));
                        return 2;
                    }
                },
                None => {
                    error("option requires an argument -- v");
                    return 2;
                }
            },
            b'f' => match value(&mut i) {
                Some(f) => match crate::util::read_input(&f) {
                    Ok(src) => progs.push(src),
                    Err(e) => {
                        error(alloc::format!("fatal: can't open source file `{}' for reading: {e}", lossy(&f)));
                        return 2;
                    }
                },
                None => {
                    error("option requires an argument -- f");
                    return 2;
                }
            },
            b'i' => match value(&mut i) {
                Some(f) => includes.push(f),
                None => {
                    error("option requires an argument -- i");
                    return 2;
                }
            },
            b'-' if a.starts_with(b"--include=") => includes.push(a[10..].to_vec()),
            // Exact integers (ADR 0165).
            b'M' => value::BIGNUM.store(true, core::sync::atomic::Ordering::Relaxed),
            b'-' if a == b"--bignum" => value::BIGNUM.store(true, core::sync::atomic::Ordering::Relaxed),
            b'-' if a == b"--version" => {
                slate_rt::io::out(&[b"awk (Slate) ", VERSION, b"\n"].concat());
                return 0;
            }
            _ => {
                error(alloc::format!("invalid option -- '{}'", opt as char));
                return 2;
            }
        }
        i += 1;
    }
    let src = if progs.is_empty() {
        let Some(p) = args.get(i) else {
            error("usage: awk [-F fs][-v var=value][prog | -f progfile][file ...]");
            return 2;
        };
        i += 1;
        p.clone()
    } else {
        progs.join(&b'\n')
    };
    // -i files first, then @include lines, each file once.
    let mut seen = Vec::new();
    let mut head = Vec::new();
    for f in &includes {
        head.extend_from_slice(b"@include \"");
        head.extend_from_slice(f);
        head.extend_from_slice(b"\"\n");
    }
    let src = match include(&[head.as_slice(), &src].concat(), &mut seen, 0) {
        Ok(s) => s,
        Err(m) => {
            error(alloc::format!("fatal: {m}"));
            return 2;
        }
    };
    let parser = parse::Parser::new(&src);
    let prog = match parser.program() {
        Ok(p) => p,
        Err(m) => {
            error(alloc::format!("cmd. line: {m}"));
            // gawk's status for a program that does not parse.
            return 1;
        }
    };
    let mut argv = alloc::vec![b"awk".to_vec()];
    argv.extend_from_slice(&args[i..]);
    if let Some(fs) = fs {
        assigns.insert(
            0,
            (
                b"FS".to_vec(),
                fs.iter().flat_map(|&c| if c == b'\\' { alloc::vec![b'\\', b'\\'] } else { alloc::vec![c] }).collect(),
            ),
        );
    }
    let mut it = match interp::Interp::new(&prog, &argv, &assigns) {
        Ok(it) => it,
        Err(m) => {
            error(alloc::format!("fatal: {m}"));
            return 2;
        }
    };
    it.run()
}
