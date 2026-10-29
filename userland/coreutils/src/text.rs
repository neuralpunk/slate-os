// SPDX-License-Identifier: MIT OR Apache-2.0

//! Text filters: head, tail, wc, sort, uniq, cut, tr, tac, rev, nl, paste,
//! fold, comm, expand.

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use slate_rt::{fs, io, lossy, println};

use crate::util::{Opt, Parser, bad_option, error, error_path, lines, parse_num, read_input, stream_lines};

fn inputs(files: &mut Vec<Vec<u8>>) {
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
}

/// `-n` style counts: `N`, `-N` (all but the last N for head), `+N`
/// (from line N for tail), with K/M suffixes.
fn count(v: &[u8]) -> Option<(i64, bool)> {
    let (sign, digits) = match v.first() {
        Some(b'+') => (true, &v[1..]),
        Some(b'-') => (false, &v[1..]),
        _ => (false, v),
    };
    let n = crate::fileops::parse_size(digits)? as i64;
    Some((if v.first() == Some(&b'-') { -n } else { n }, sign))
}

pub fn head(args: &[Vec<u8>]) -> i32 {
    let mut n: i64 = 10;
    let mut bytes = false;
    let (mut quiet, mut verbose) = (false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"nc");
    p.numeric = true;
    while let Some(o) = p.next() {
        match o {
            Opt::Short(c @ (b'n' | b'c')) => {
                let v = p.value().unwrap_or_default();
                let Some((v, _)) = count(&v) else {
                    error(format_args!("invalid number of lines: '{}'", lossy(&v)));
                    return 1;
                };
                n = v;
                bytes = c == b'c';
            }
            Opt::Short(b'q') => quiet = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Long(l) if l == "lines" || l == "bytes" => {
                let v = p.value().unwrap_or_default();
                n = count(&v).map_or(10, |c| c.0);
                bytes = l == "bytes";
            }
            Opt::Long(l) if l.bytes().all(|c| c.is_ascii_digit()) => n = l.parse().unwrap_or(10),
            Opt::Long(l) if l == "quiet" || l == "silent" => quiet = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    let headers = (files.len() > 1 && !quiet) || verbose;
    let mut status = 0;
    for (k, f) in files.iter().enumerate() {
        if headers {
            if k > 0 {
                io::out(b"\n");
            }
            println!("==> {} <==", if f == b"-" { "standard input".into() } else { lossy(f) });
        }
        // Counting from the start streams and stops early (`yes | head`);
        // "all but the last N" has to see the end first.
        let r = if n >= 0 {
            let mut left = n as usize;
            if bytes {
                crate::util::stream_chunks(f, |c| {
                    let take = left.min(c.len());
                    io::out(&c[..take]);
                    left -= take;
                    left > 0
                })
            } else if left == 0 {
                Ok(())
            } else {
                crate::util::stream_lines(f, b'\n', |l, had| {
                    io::out(l);
                    if had {
                        io::out(b"\n");
                    }
                    left -= 1;
                    left > 0
                })
            }
        } else {
            read_input(f).map(|data| {
                if bytes {
                    io::out(&data[..data.len().saturating_sub((-n) as usize)]);
                } else {
                    let ends: Vec<usize> =
                        data.iter().enumerate().filter(|(_, c)| **c == b'\n').map(|(i, _)| i + 1).collect();
                    let total = ends.len() + usize::from(!data.is_empty() && data.last() != Some(&b'\n'));
                    let keep = total.saturating_sub((-n) as usize);
                    let end = if keep == 0 { 0 } else { ends.get(keep - 1).copied().unwrap_or(data.len()) };
                    io::out(&data[..end]);
                }
            })
        };
        if let Err(e) = r {
            error(format_args!("cannot open '{}' for reading: {e}", lossy(f)));
            status = 1;
        }
    }
    status
}

pub fn tail(args: &[Vec<u8>]) -> i32 {
    let mut n: i64 = 10;
    let mut from_start = false;
    let mut bytes = false;
    let (mut follow, mut quiet, mut verbose) = (false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"ncs");
    p.numeric = true;
    while let Some(o) = p.next() {
        match o {
            Opt::Short(c @ (b'n' | b'c')) => {
                let v = p.value().unwrap_or_default();
                let Some((v, plus)) = count(&v) else {
                    error(format_args!("invalid number of lines: '{}'", lossy(&v)));
                    return 1;
                };
                (n, from_start, bytes) = (v.abs(), plus, c == b'c');
            }
            Opt::Short(b'f' | b'F') => follow = true,
            Opt::Short(b'q') => quiet = true,
            Opt::Short(b'v') => verbose = true,
            Opt::Short(b's') => {
                let _ = p.value();
            }
            Opt::Long(l) if l == "lines" || l == "bytes" => {
                let v = p.value().unwrap_or_default();
                if let Some((v, plus)) = count(&v) {
                    (n, from_start, bytes) = (v.abs(), plus, l == "bytes");
                }
            }
            Opt::Long(l) if l == "follow" => follow = true,
            Opt::Long(l) if l.bytes().all(|c| c.is_ascii_digit()) => n = l.parse().unwrap_or(10),
            Opt::Operand(f) if f.starts_with(b"+") && f.len() > 1 && f[1..].iter().all(u8::is_ascii_digit) => {
                (n, from_start) = (parse_num(&f[1..]).unwrap_or(1), true)
            }
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    let headers = (files.len() > 1 && !quiet) || verbose;
    let mut status = 0;
    for (k, f) in files.iter().enumerate() {
        if headers {
            if k > 0 {
                io::out(b"\n");
            }
            println!("==> {} <==", if f == b"-" { "standard input".into() } else { lossy(f) });
        }
        let n = n as usize;
        // Streams: memory stays bounded by N (lines or bytes), however long
        // the input is.
        let r = if from_start {
            let mut skip = n.saturating_sub(1);
            if bytes {
                crate::util::stream_chunks(f, |c| {
                    let s = skip.min(c.len());
                    skip -= s;
                    io::out(&c[s..]);
                    true
                })
            } else {
                crate::util::stream_lines(f, b'\n', |l, had| {
                    if skip > 0 {
                        skip -= 1;
                    } else {
                        io::out(l);
                        if had {
                            io::out(b"\n");
                        }
                    }
                    true
                })
            }
        } else if bytes {
            let mut keep: alloc::collections::VecDeque<u8> = alloc::collections::VecDeque::new();
            let r = crate::util::stream_chunks(f, |c| {
                keep.extend(c);
                let excess = keep.len().saturating_sub(n);
                keep.drain(..excess);
                true
            });
            let v: Vec<u8> = keep.into_iter().collect();
            io::out(&v);
            r
        } else {
            let mut keep: alloc::collections::VecDeque<(Vec<u8>, bool)> = alloc::collections::VecDeque::new();
            let r = crate::util::stream_lines(f, b'\n', |l, had| {
                if n > 0 {
                    if keep.len() == n {
                        keep.pop_front();
                    }
                    keep.push_back((l.to_vec(), had));
                }
                true
            });
            for (l, had) in keep {
                io::out(&l);
                if had {
                    io::out(b"\n");
                }
            }
            r
        };
        if let Err(e) = r {
            error(format_args!("cannot open '{}' for reading: {e}", lossy(f)));
            status = 1;
        }
    }
    if follow && files.len() == 1 && files[0] != b"-" {
        // Poll for growth.
        let f = &files[0];
        let mut size = fs::stat(f).map_or(0, |s| s.size);
        loop {
            io::flush_stdout();
            slate_rt::time::sleep_ns(250_000_000);
            let Ok(st) = fs::stat(f) else { continue };
            if st.size < size {
                size = 0;
            }
            if st.size > size
                && let Ok(fd) = fs::open(f, fs::O_RDONLY, 0)
            {
                let _ = io::lseek(fd, size, 0);
                let mut buf = alloc::vec![0u8; (st.size - size) as usize];
                if let Ok(n) = io::read(fd, &mut buf) {
                    io::out(&buf[..n]);
                }
                let _ = io::close(fd);
                size = st.size;
            }
        }
    }
    status
}

pub fn wc(args: &[Vec<u8>]) -> i32 {
    let (mut l, mut w, mut c, mut m, mut longest) = (false, false, false, false, false);
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'l') => l = true,
            Opt::Short(b'w') => w = true,
            Opt::Short(b'c') => c = true,
            Opt::Short(b'm') => m = true,
            Opt::Short(b'L') => longest = true,
            Opt::Long(x) if x == "lines" => l = true,
            Opt::Long(x) if x == "words" => w = true,
            Opt::Long(x) if x == "bytes" => c = true,
            Opt::Long(x) if x == "chars" => m = true,
            Opt::Long(x) if x == "max-line-length" => longest = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if !(l || w || c || m || longest) {
        (l, w, c) = (true, true, true);
    }
    let named = !files.is_empty();
    inputs(&mut files);
    let mut rows: Vec<([u64; 5], Option<Vec<u8>>)> = Vec::new();
    let mut total = [0u64; 5];
    let mut status = 0;
    for f in &files {
        let (mut lines, mut words, mut chars, mut bytes_n, mut max, mut cur) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
        let mut in_word = false;
        let r = crate::util::stream_chunks(f, |c| {
            bytes_n += c.len() as u64;
            for &b in c {
                if b == b'\n' {
                    lines += 1;
                    max = max.max(cur);
                    cur = 0;
                } else {
                    cur += 1;
                }
                if b.is_ascii_whitespace() {
                    in_word = false;
                } else if !in_word {
                    in_word = true;
                    words += 1;
                }
                if b & 0xC0 != 0x80 {
                    chars += 1;
                }
            }
            true
        });
        if let Err(e) = r {
            error_path(f, e);
            status = 1;
            continue;
        }
        let max = max.max(cur);
        let counts = [lines, words, chars, bytes_n, max];
        for i in 0..4 {
            total[i] += counts[i];
        }
        total[4] = total[4].max(max);
        rows.push((counts, named.then(|| f.clone())));
    }
    if rows.len() > 1 {
        rows.push((total, Some(b"total".to_vec())));
    }
    let shown = [l, w, m, c, longest];
    let single = shown.iter().filter(|&&x| x).count() == 1 && !named;
    // GNU pads to the width of the largest number (at least 7 for stdin).
    let width = if single {
        1
    } else {
        rows.iter().flat_map(|r| r.0).max().unwrap_or(0).to_string_len().max(if named { 1 } else { 7 })
    };
    for (counts, name) in &rows {
        let mut parts: Vec<String> = Vec::new();
        for i in 0..5 {
            if shown[i] {
                parts.push(alloc::format!("{:>width$}", counts[i]));
            }
        }
        let mut line = parts.join(" ");
        if let Some(n) = name {
            line.push(' ');
            line.push_str(&lossy(n));
        }
        println!("{line}");
    }
    status
}

trait DigitLen {
    fn to_string_len(self) -> usize;
}

impl DigitLen for u64 {
    fn to_string_len(self) -> usize {
        alloc::format!("{self}").len()
    }
}

// --- sort ---------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Key {
    start_field: usize,
    start_char: usize,
    end_field: usize,
    end_char: usize,
    numeric: bool,
    human: bool,
    general: bool,
    reverse: bool,
    fold: bool,
    blanks: bool,
    version: bool,
    month: bool,
    dict: bool,
}

fn parse_key(spec: &[u8], global: &Key) -> Option<Key> {
    let s = core::str::from_utf8(spec).ok()?;
    let (a, b) = s.split_once(',').map_or((s, None), |(a, b)| (a, Some(b)));
    let mut k = global.clone();
    let pos = |p: &str, k: &mut Key| -> Option<(usize, usize)> {
        let digits = p.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(p.len());
        let (num, flags) = p.split_at(digits);
        for f in flags.chars() {
            match f {
                'n' => k.numeric = true,
                'h' => k.human = true,
                'g' => k.general = true,
                'r' => k.reverse = true,
                'f' => k.fold = true,
                'b' => k.blanks = true,
                'V' => k.version = true,
                'M' => k.month = true,
                'd' => k.dict = true,
                _ => return None,
            }
        }
        let (f, c) = num.split_once('.').map_or((num, "0"), |(f, c)| (f, c));
        Some((f.parse().ok()?, c.parse().ok()?))
    };
    let has_flags = |p: &str| p.chars().any(|c| c.is_ascii_alphabetic());
    if has_flags(a) || b.is_some_and(has_flags) {
        k = Key::default();
    }
    (k.start_field, k.start_char) = pos(a, &mut k)?;
    if let Some(b) = b {
        (k.end_field, k.end_char) = pos(b, &mut k)?;
    }
    Some(k)
}

/// The part of `line` a key selects (fields split by `sep`, or by runs of
/// blanks with leading blanks belonging to the field).
fn key_slice<'a>(line: &'a [u8], k: &Key, sep: Option<u8>) -> &'a [u8] {
    if k.start_field == 0 {
        return line;
    }
    let fields: Vec<(usize, usize)> = match sep {
        Some(s) => {
            let mut v = Vec::new();
            let mut start = 0;
            for (i, &c) in line.iter().enumerate() {
                if c == s {
                    v.push((start, i));
                    start = i + 1;
                }
            }
            v.push((start, line.len()));
            v
        }
        None => {
            let mut v = Vec::new();
            let mut i = 0;
            while i < line.len() {
                let start = i;
                while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                    i += 1;
                }
                while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
                    i += 1;
                }
                v.push((start, i));
            }
            v
        }
    };
    let Some(&(fs_, fe)) = fields.get(k.start_field - 1) else { return &[] };
    let mut start = fs_;
    if k.blanks || sep.is_none() && k.start_char > 0 {
        while start < fe && (line[start] == b' ' || line[start] == b'\t') {
            start += 1;
        }
    }
    if k.start_char > 0 {
        start = (start + k.start_char - 1).min(fe.max(start));
    }
    let end = if k.end_field == 0 {
        line.len()
    } else {
        match fields.get(k.end_field - 1) {
            Some(&(es, ee)) => {
                if k.end_char == 0 {
                    ee
                } else {
                    let mut s = es;
                    if k.blanks {
                        while s < ee && (line[s] == b' ' || line[s] == b'\t') {
                            s += 1;
                        }
                    }
                    (s + k.end_char).min(ee)
                }
            }
            None => line.len(),
        }
    };
    if start >= end { &[] } else { &line[start..end] }
}

fn trim_blanks(b: &[u8]) -> &[u8] {
    let s = b.iter().position(|c| *c != b' ' && *c != b'\t').unwrap_or(b.len());
    &b[s..]
}

/// Numeric value of a leading number (sort -n): sign, digits, decimal point.
fn num_value(b: &[u8]) -> f64 {
    let b = trim_blanks(b);
    let mut end = 0;
    if b.first() == Some(&b'-') {
        end = 1;
    }
    let mut seen_dot = false;
    while end < b.len() && (b[end].is_ascii_digit() || (b[end] == b'.' && !seen_dot)) {
        seen_dot |= b[end] == b'.';
        end += 1;
    }
    core::str::from_utf8(&b[..end]).ok().and_then(|s| s.parse().ok()).unwrap_or(0.0)
}

fn human_value(b: &[u8]) -> f64 {
    let b = trim_blanks(b);
    let v = num_value(b);
    let end = b.iter().position(|c| !(c.is_ascii_digit() || *c == b'.' || *c == b'-')).unwrap_or(b.len());
    let m = match b.get(end) {
        Some(b'K' | b'k') => 1e3,
        Some(b'M') => 1e6,
        Some(b'G') => 1e9,
        Some(b'T') => 1e12,
        Some(b'P') => 1e15,
        _ => 1.0,
    };
    v * m
}

/// Version order (sort -V): digit runs compare numerically.
pub fn version_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i].is_ascii_digit() && b[j].is_ascii_digit() {
            let si = i;
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            let sj = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let na = trim_zeros(&a[si..i]);
            let nb = trim_zeros(&b[sj..j]);
            let o = na.len().cmp(&nb.len()).then_with(|| na.cmp(nb));
            if o != Ordering::Equal {
                return o;
            }
        } else {
            if a[i] != b[j] {
                return a[i].cmp(&b[j]);
            }
            i += 1;
            j += 1;
        }
    }
    (a.len() - i).cmp(&(b.len() - j))
}

fn trim_zeros(d: &[u8]) -> &[u8] {
    let s = d.iter().position(|&c| c != b'0').unwrap_or(d.len());
    &d[s..]
}

fn month_value(b: &[u8]) -> usize {
    let t = trim_blanks(b);
    let up: Vec<u8> = t.iter().take(3).map(u8::to_ascii_uppercase).collect();
    ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"]
        .iter()
        .position(|m| m.as_bytes() == up.as_slice())
        .map_or(0, |i| i + 1)
}

fn compare_key(a: &[u8], b: &[u8], k: &Key) -> Ordering {
    let o = if k.numeric {
        num_value(a).partial_cmp(&num_value(b)).unwrap_or(Ordering::Equal)
    } else if k.human {
        human_value(a).partial_cmp(&human_value(b)).unwrap_or(Ordering::Equal)
    } else if k.general {
        let g = |x: &[u8]| {
            lossy(trim_blanks(x)).split_whitespace().next().and_then(|s| s.parse::<f64>().ok()).unwrap_or(f64::MIN)
        };
        g(a).partial_cmp(&g(b)).unwrap_or(Ordering::Equal)
    } else if k.month {
        month_value(a).cmp(&month_value(b))
    } else if k.version {
        version_cmp(a, b)
    } else {
        let prep = |x: &[u8]| -> Vec<u8> {
            let x = if k.blanks { trim_blanks(x) } else { x };
            x.iter()
                .filter(|c| !k.dict || c.is_ascii_alphanumeric() || **c == b' ' || **c == b'\t')
                .map(|c| if k.fold { c.to_ascii_uppercase() } else { *c })
                .collect()
        };
        prep(a).cmp(&prep(b))
    };
    if k.reverse { o.reverse() } else { o }
}

pub fn sort(args: &[Vec<u8>]) -> i32 {
    let mut global = Key::default();
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let (mut unique, mut stable, mut check, mut zero, mut merge) = (false, false, false, false, false);
    let mut quiet_check = false;
    let mut sep: Option<u8> = None;
    let mut output: Option<Vec<u8>> = None;
    let mut buffer: Option<usize> = None;
    let mut tmpdir: Option<Vec<u8>> = None;
    let mut batch = MERGE_BATCH;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"ktoST");
    let size_arg = |v: &[u8]| -> Option<usize> {
        // -S: bytes with K/M/G/T suffixes (K by default), or a percentage
        // of memory.
        if let Some(pct) = v.strip_suffix(b"%") {
            let total = crate::procs::mem_total() as usize * 1024;
            return parse_num::<usize>(pct).map(|p| total / 100 * p.min(100));
        }
        match v.last() {
            Some(c) if c.is_ascii_digit() => parse_num::<usize>(v).map(|n| n * 1024),
            Some(b'b') => parse_num::<usize>(&v[..v.len() - 1]),
            _ => crate::od::parse_size(v).map(|n| n as usize),
        }
    };
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'n') => global.numeric = true,
            Opt::Short(b'h') => global.human = true,
            Opt::Short(b'g') => global.general = true,
            Opt::Short(b'r') => global.reverse = true,
            Opt::Short(b'f') => global.fold = true,
            Opt::Short(b'b') => global.blanks = true,
            Opt::Short(b'V') => global.version = true,
            Opt::Short(b'M') => global.month = true,
            Opt::Short(b'd') => global.dict = true,
            Opt::Short(b'u') => unique = true,
            Opt::Short(b's') => stable = true,
            Opt::Short(b'c') => check = true,
            Opt::Short(b'C') => {
                check = true;
                quiet_check = true;
            }
            Opt::Short(b'm') => merge = true,
            Opt::Short(b'z') => zero = true,
            Opt::Short(b'k') => keys.push(p.value().unwrap_or_default()),
            Opt::Short(b't') => sep = p.value().and_then(|v| v.first().copied()),
            Opt::Short(b'o') => output = p.value(),
            Opt::Short(b'S') => {
                let v = p.value().unwrap_or_default();
                match size_arg(&v) {
                    Some(n) => buffer = Some(n.max(64 * 1024)),
                    None => {
                        error(format_args!("invalid -S argument '{}'", lossy(&v)));
                        return 2;
                    }
                }
            }
            Opt::Short(b'T') => tmpdir = p.value(),
            Opt::Long(l) => match l.as_str() {
                "numeric-sort" => global.numeric = true,
                "human-numeric-sort" => global.human = true,
                "general-numeric-sort" => global.general = true,
                "reverse" => global.reverse = true,
                "ignore-case" => global.fold = true,
                "version-sort" => global.version = true,
                "unique" => unique = true,
                "stable" => stable = true,
                "zero-terminated" => zero = true,
                "key" => keys.push(p.value().unwrap_or_default()),
                "field-separator" => sep = p.value().and_then(|v| v.first().copied()),
                "output" => output = p.value(),
                "check" => {
                    check = true;
                    quiet_check = p.inline_value().is_some_and(|v| v == b"quiet" || v == b"silent");
                }
                "merge" => merge = true,
                "buffer-size" => {
                    let v = p.value().unwrap_or_default();
                    match size_arg(&v) {
                        Some(n) => buffer = Some(n.max(64 * 1024)),
                        None => {
                            error(format_args!("invalid --buffer-size argument '{}'", lossy(&v)));
                            return 2;
                        }
                    }
                }
                "temporary-directory" => tmpdir = p.value(),
                "batch-size" => {
                    let v = p.value().unwrap_or_default();
                    match lossy(&v).parse::<usize>() {
                        Ok(n) if n >= 2 => batch = n,
                        _ => {
                            error(format_args!("invalid --batch-size argument '{}'", lossy(&v)));
                            error("minimum --batch-size argument is '2'");
                            return 2;
                        }
                    }
                }
                // A speed hint; the output is the same either way.
                "parallel" => {
                    let _ = p.inline_value().or_else(|| p.value());
                }
                _ => return bad_option(&Opt::Long(l)),
            },
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let mut parsed = Vec::new();
    for k in &keys {
        match parse_key(k, &global) {
            Some(k) => parsed.push(k),
            None => {
                error(format_args!("invalid field specification '{}'", lossy(k)));
                return 2;
            }
        }
    }
    let delim = if zero { 0 } else { b'\n' };
    inputs(&mut files);
    let cmp = |a: &[u8], b: &[u8]| -> Ordering {
        for k in &parsed {
            let o = compare_key(key_slice(a, k, sep), key_slice(b, k, sep), k);
            if o != Ordering::Equal {
                return o;
            }
        }
        if parsed.is_empty() {
            let o = compare_key(a, b, &global);
            if o != Ordering::Equal || stable || unique {
                return o;
            }
        } else if stable || unique {
            return Ordering::Equal;
        }
        // Last resort: the whole line, bytewise (reversed with -r).
        let o = a.cmp(b);
        if global.reverse { o.reverse() } else { o }
    };
    if check {
        if files.len() > 1 {
            error(format_args!("extra operand '{}' not allowed with -c", lossy(&files[1])));
            return 2;
        }
        let name = files[0].clone();
        let mut prev: Option<Vec<u8>> = None;
        let mut n = 0u64;
        let mut bad = None;
        let r = stream_lines(&name, delim, |l, _| {
            n += 1;
            if let Some(p) = &prev {
                let o = cmp(p, l);
                if o == Ordering::Greater || (unique && o == Ordering::Equal) {
                    bad = Some((n, l.to_vec()));
                    return false;
                }
            }
            prev = Some(l.to_vec());
            true
        });
        if let Err(e) = r {
            error(format_args!("cannot read: {}: {e}", lossy(&name)));
            return 2;
        }
        if let Some((n, l)) = bad {
            if !quiet_check {
                error(format_args!("{}:{n}: disorder: {}", lossy(&name), lossy(&l)));
            }
            return 1;
        }
        return 0;
    }
    let mut out = SortOut::new();
    out.to_file = output.is_some();
    let mut sources: Vec<i32> = Vec::new();
    if merge {
        // -m: the inputs are sorted already.
        for f in &files {
            match crate::util::open_input(f) {
                Ok(fd) => sources.push(fd),
                Err(e) => {
                    error(format_args!("cannot read: {}: {e}", lossy(f)));
                    return 2;
                }
            }
        }
    } else {
        // Read in pieces of at most `limit` bytes; each full piece is
        // sorted and kept in an unlinked temporary file, to be merged.
        let limit = buffer.unwrap_or(64 << 20);
        let dir = tmpdir.clone().or_else(|| slate_rt::env::var(b"TMPDIR")).unwrap_or_else(|| b"/tmp".to_vec());
        let mut chunk: Vec<u8> = Vec::new();
        let mut failed = None;
        let spill = |chunk: &mut Vec<u8>, sources: &mut Vec<i32>| -> Result<(), String> {
            let mut ls: Vec<&[u8]> = lines(chunk, delim);
            ls.sort_by(|a, b| cmp(a, b));
            if unique {
                ls.dedup_by(|a, b| cmp(a, b) == Ordering::Equal);
            }
            let fd = temp_file(&dir)
                .map_err(|e| alloc::format!("cannot create temporary file in '{}': {e}", lossy(&dir)))?;
            let mut buf = Vec::with_capacity(chunk.len());
            for l in ls {
                buf.extend_from_slice(l);
                buf.push(delim);
            }
            io::write_all(fd, &buf).map_err(|e| alloc::format!("write failed: {e}"))?;
            let _ = io::lseek(fd, 0, io::SEEK_SET);
            sources.push(fd);
            chunk.clear();
            Ok(())
        };
        for f in &files {
            let r = stream_lines(f, delim, |l, _| {
                chunk.extend_from_slice(l);
                chunk.push(delim);
                if chunk.len() >= limit
                    && let Err(e) = spill(&mut chunk, &mut sources)
                {
                    failed = Some(e);
                    return false;
                }
                true
            });
            if let Err(e) = r {
                error(format_args!("cannot read: {}: {e}", lossy(f)));
                return 2;
            }
            if let Some(e) = failed.take() {
                error(e);
                return 2;
            }
        }
        if sources.is_empty() {
            // Everything fit: sort in memory.
            let mut ls: Vec<&[u8]> = lines(&chunk, delim);
            ls.sort_by(|a, b| cmp(a, b));
            if unique {
                ls.dedup_by(|a, b| cmp(a, b) == Ordering::Equal);
            }
            for l in ls {
                out.line(l, delim);
            }
            return out.finish(output.as_deref());
        }
        if !chunk.is_empty()
            && let Err(e) = spill(&mut chunk, &mut sources)
        {
            error(e);
            return 2;
        }
    }
    // Merge the sorted sources, earlier sources first among equals. With
    // more than `batch` of them, groups are merged into new runs first, so
    // that no more descriptors are open at once than that.
    let dir = tmpdir.or_else(|| slate_rt::env::var(b"TMPDIR")).unwrap_or_else(|| b"/tmp".to_vec());
    while sources.len() > batch {
        let mut next = Vec::new();
        for group in sources.chunks(batch) {
            let fd = match temp_file(&dir) {
                Ok(fd) => fd,
                Err(e) => {
                    error(format_args!("cannot create temporary file in '{}': {e}", lossy(&dir)));
                    return 2;
                }
            };
            let mut buf = Vec::new();
            let mut written = Ok(());
            merge_runs(group, delim, unique, &cmp, &mut |l| {
                buf.extend_from_slice(l);
                buf.push(delim);
                if buf.len() >= 1 << 20 && written.is_ok() {
                    written = io::write_all(fd, &buf);
                    buf.clear();
                }
            });
            if let Err(e) = written.and_then(|()| io::write_all(fd, &buf)) {
                error(format_args!("write failed: {e}"));
                return 2;
            }
            let _ = io::lseek(fd, 0, io::SEEK_SET);
            for &s in group {
                crate::util::close_input(s);
            }
            next.push(fd);
        }
        sources = next;
    }
    merge_runs(&sources, delim, unique, &cmp, &mut |l| out.line(l, delim));
    for fd in sources {
        crate::util::close_input(fd);
    }
    out.finish(output.as_deref())
}

/// How many sorted runs are merged at once (sort --batch-size; GNU's
/// default).
const MERGE_BATCH: usize = 16;

/// Merge the sorted runs `fds` (earlier ones first among equals; with
/// `unique`, the first of equal records only), each record to `emit`.
fn merge_runs(
    fds: &[i32],
    delim: u8,
    unique: bool,
    cmp: &dyn Fn(&[u8], &[u8]) -> Ordering,
    emit: &mut dyn FnMut(&[u8]),
) {
    let mut readers: Vec<io::Reader> = fds.iter().map(|&fd| io::Reader::new(fd)).collect();
    let mut heads: Vec<Option<Vec<u8>>> = readers.iter_mut().map(|r| next_record(r, delim)).collect();
    let mut last: Option<Vec<u8>> = None;
    loop {
        let mut best: Option<usize> = None;
        for (i, h) in heads.iter().enumerate() {
            if let Some(l) = h
                && best.is_none_or(|b| cmp(l, heads[b].as_deref().unwrap_or_default()) == Ordering::Less)
            {
                best = Some(i);
            }
        }
        let Some(b) = best else { break };
        let l = heads[b].take().unwrap_or_default();
        heads[b] = next_record(&mut readers[b], delim);
        if unique && last.as_deref().is_some_and(|p| cmp(p, &l) == Ordering::Equal) {
            continue;
        }
        emit(&l);
        if unique {
            last = Some(l);
        }
    }
}

/// One record from a sorted source, without its delimiter.
fn next_record(r: &mut io::Reader, delim: u8) -> Option<Vec<u8>> {
    let mut l = r.split(delim).ok()??;
    if l.last() == Some(&delim) {
        l.pop();
    }
    Some(l)
}

/// A temporary file for a sorted run, unlinked at once (only the
/// descriptor keeps it).
fn temp_file(dir: &[u8]) -> Result<i32, slate_rt::Errno> {
    let pid = slate_rt::process::getpid();
    for n in 0..1000u32 {
        let name = fs::join(dir, alloc::format!("sort{pid}.{n}").as_bytes());
        match fs::open(&name, fs::O_RDWR | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600) {
            Ok(fd) => {
                let _ = fs::unlink(&name);
                return Ok(fd);
            }
            Err(slate_rt::Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Err(slate_rt::Errno::EEXIST)
}

/// sort's output: to standard output as it comes, or (with -o, which
/// may name an input) to the file at the end.
struct SortOut {
    buf: Vec<u8>,
    to_file: bool,
}

impl SortOut {
    fn new() -> SortOut {
        SortOut { buf: Vec::new(), to_file: false }
    }

    fn line(&mut self, l: &[u8], delim: u8) {
        self.buf.extend_from_slice(l);
        self.buf.push(delim);
        if !self.to_file && self.buf.len() > 64 * 1024 {
            io::out(&self.buf);
            self.buf.clear();
        }
    }

    fn finish(mut self, output: Option<&[u8]>) -> i32 {
        match output {
            Some(o) => match fs::write_file(o, &self.buf, 0o666) {
                Ok(()) => 0,
                Err(e) => {
                    error_path(o, e);
                    2
                }
            },
            None => {
                io::out(&self.buf);
                self.buf.clear();
                0
            }
        }
    }
}

pub fn uniq(args: &[Vec<u8>]) -> i32 {
    let (mut count, mut dups, mut uniques, mut fold, mut all_dups) = (false, false, false, false, false);
    let (mut skip_fields, mut skip_chars, mut check_chars) = (0usize, 0usize, usize::MAX);
    let mut ops = Vec::new();
    let mut p = Parser::new(args, b"fsw");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'c') => count = true,
            Opt::Short(b'd') => dups = true,
            Opt::Short(b'D') => all_dups = true,
            Opt::Short(b'u') => uniques = true,
            Opt::Short(b'i') => fold = true,
            Opt::Short(b'f') => skip_fields = p.value().and_then(|v| parse_num(&v)).unwrap_or(0),
            Opt::Short(b's') => skip_chars = p.value().and_then(|v| parse_num(&v)).unwrap_or(0),
            Opt::Short(b'w') => check_chars = p.value().and_then(|v| parse_num(&v)).unwrap_or(usize::MAX),
            Opt::Long(l) if l == "count" => count = true,
            Opt::Long(l) if l == "repeated" => dups = true,
            Opt::Long(l) if l == "unique" => uniques = true,
            Opt::Long(l) if l == "ignore-case" => fold = true,
            Opt::Operand(f) => ops.push(f),
            o => return bad_option(&o),
        }
    }
    let input = ops.first().cloned().unwrap_or_else(|| b"-".to_vec());
    let key = |l: &[u8]| -> Vec<u8> {
        let mut i = 0;
        for _ in 0..skip_fields {
            while i < l.len() && (l[i] == b' ' || l[i] == b'\t') {
                i += 1;
            }
            while i < l.len() && l[i] != b' ' && l[i] != b'\t' {
                i += 1;
            }
        }
        let rest = &l[(i + skip_chars).min(l.len())..];
        let rest = &rest[..rest.len().min(check_chars)];
        if fold { rest.to_ascii_lowercase() } else { rest.to_vec() }
    };
    let out_fd = match ops.get(1) {
        Some(o) => match fs::open(o, fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o666) {
            Ok(fd) => Some(fd),
            Err(e) => {
                error_path(o, e);
                return 1;
            }
        },
        None => None,
    };
    let emit = |b: &[u8]| match out_fd {
        Some(fd) => {
            let _ = io::write_all(fd, b);
        }
        None => io::out(b),
    };
    // The current group of adjacent equal lines: its key, lines (all of
    // them only for -D) and size.
    let mut group: Option<(Vec<u8>, Vec<Vec<u8>>, usize)> = None;
    let flush = |g: &(Vec<u8>, Vec<Vec<u8>>, usize)| {
        let n = g.2;
        let show = (!dups && !uniques && !all_dups) || (dups && n > 1) || (uniques && n == 1) || (all_dups && n > 1);
        if show {
            for l in &g.1 {
                let mut line = Vec::new();
                if count {
                    line.extend_from_slice(alloc::format!("{n:7} ").as_bytes());
                }
                line.extend_from_slice(l);
                line.push(b'\n');
                emit(&line);
            }
        }
    };
    let r = crate::util::stream_lines(&input, b'\n', |l, _| {
        let k = key(l);
        match &mut group {
            Some(g) if g.0 == k => {
                g.2 += 1;
                if all_dups {
                    g.1.push(l.to_vec());
                }
            }
            _ => {
                if let Some(g) = group.take() {
                    flush(&g);
                }
                group = Some((k, alloc::vec![l.to_vec()], 1));
            }
        }
        true
    });
    if let Some(g) = group.take() {
        flush(&g);
    }
    if let Some(fd) = out_fd {
        let _ = io::close(fd);
    }
    match r {
        Ok(()) => 0,
        Err(e) => {
            error_path(&input, e);
            1
        }
    }
}

/// A list like `1,3-5,7-` (1-based, sorted and merged).
fn ranges(spec: &[u8]) -> Option<Vec<(usize, usize)>> {
    let mut v = Vec::new();
    for part in spec.split(|&c| c == b',') {
        let s = core::str::from_utf8(part).ok()?;
        let (a, b) = match s.split_once('-') {
            Some((a, b)) => (
                if a.is_empty() { 1 } else { a.parse().ok()? },
                if b.is_empty() { usize::MAX } else { b.parse().ok()? },
            ),
            None => {
                let n: usize = s.parse().ok()?;
                (n, n)
            }
        };
        if a == 0 || b < a {
            return None;
        }
        v.push((a, b));
    }
    v.sort();
    Some(v)
}

pub fn cut(args: &[Vec<u8>]) -> i32 {
    let mut list: Option<(u8, Vec<(usize, usize)>)> = None;
    let mut delim = b'\t';
    let (mut only_delimited, mut complement) = (false, false);
    let mut out_delim: Option<Vec<u8>> = None;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"bcfd");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(c @ (b'b' | b'c' | b'f')) => {
                let v = p.value().unwrap_or_default();
                match ranges(&v) {
                    Some(r) => list = Some((c, r)),
                    None => {
                        error(format_args!("invalid field value '{}'", lossy(&v)));
                        return 1;
                    }
                }
            }
            Opt::Short(b'd') => delim = p.value().and_then(|v| v.first().copied()).unwrap_or(b'\t'),
            Opt::Short(b's') => only_delimited = true,
            Opt::Short(b'n') => {}
            Opt::Long(l) if l == "complement" => complement = true,
            Opt::Long(l) if l == "output-delimiter" => out_delim = p.value(),
            Opt::Long(l) if l == "only-delimited" => only_delimited = true,
            Opt::Long(l) if l == "delimiter" => delim = p.value().and_then(|v| v.first().copied()).unwrap_or(b'\t'),
            Opt::Long(l) if l == "fields" || l == "bytes" || l == "characters" => {
                let v = p.value().unwrap_or_default();
                list = ranges(&v).map(|r| (if l == "fields" { b'f' } else { b'b' }, r));
            }
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    let Some((mode, rs)) = list else {
        error("you must specify a list of bytes, characters, or fields");
        return 1;
    };
    let selected = |i: usize| rs.iter().any(|&(a, b)| i >= a && i <= b) != complement;
    inputs(&mut files);
    let mut status = 0;
    for f in &files {
        let r = crate::util::stream_lines(f, b'\n', |line, _| {
            let mut out = Vec::with_capacity(line.len() + 1);
            if mode == b'f' {
                if !line.contains(&delim) {
                    if !only_delimited {
                        out.extend_from_slice(line);
                        out.push(b'\n');
                        io::out(&out);
                    }
                    return true;
                }
                let od = out_delim.clone().unwrap_or_else(|| alloc::vec![delim]);
                let picked: Vec<&[u8]> =
                    line.split(|&c| c == delim).enumerate().filter(|(i, _)| selected(i + 1)).map(|(_, f)| f).collect();
                out.extend_from_slice(&picked.join(od.as_slice()));
            } else {
                let mut prev_sel = false;
                for (i, &c) in line.iter().enumerate() {
                    let s = selected(i + 1);
                    if s {
                        if let Some(od) = &out_delim
                            && !prev_sel
                            && !out.is_empty()
                        {
                            out.extend_from_slice(od);
                        }
                        out.push(c);
                    }
                    prev_sel = s;
                }
            }
            out.push(b'\n');
            io::out(&out);
            true
        });
        if let Err(e) = r {
            error_path(f, e);
            status = 1;
        }
    }
    status
}

/// Expand a tr(1) set: ranges, escapes, `[:class:]`, `[c*n]`.
fn tr_set(s: &[u8]) -> Vec<u8> {
    let (s, _) = crate::util::unescape(s, true);
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'['
            && s.get(i + 1) == Some(&b':')
            && let Some(end) = s[i + 2..].windows(2).position(|w| w == b":]")
        {
            {
                let class = &s[i + 2..i + 2 + end];
                let test: fn(&u8) -> bool = match class {
                    b"alpha" => u8::is_ascii_alphabetic,
                    b"digit" => u8::is_ascii_digit,
                    b"alnum" => u8::is_ascii_alphanumeric,
                    b"upper" => u8::is_ascii_uppercase,
                    b"lower" => u8::is_ascii_lowercase,
                    b"space" => |c: &u8| c.is_ascii_whitespace() || *c == 11,
                    b"blank" => |c: &u8| *c == b' ' || *c == b'\t',
                    b"punct" => u8::is_ascii_punctuation,
                    b"print" => |c: &u8| (32..127).contains(c),
                    b"graph" => u8::is_ascii_graphic,
                    b"cntrl" => u8::is_ascii_control,
                    b"xdigit" => u8::is_ascii_hexdigit,
                    _ => |_: &u8| false,
                };
                out.extend((0u8..=255).filter(test));
                i += end + 4;
                continue;
            }
        }
        if s[i] == b'['
            && s.get(i + 2) == Some(&b'*')
            && let Some(end) = s[i + 3..].iter().position(|&c| c == b']')
        {
            {
                let n: usize =
                    core::str::from_utf8(&s[i + 3..i + 3 + end]).ok().and_then(|x| x.parse().ok()).unwrap_or(0);
                // n = 0: fill to the length of SET1 (handled by the caller's padding).
                out.extend(core::iter::repeat_n(s[i + 1], n.max(1)));
                i += end + 4;
                continue;
            }
        }
        if s.get(i + 1) == Some(&b'-') && i + 2 < s.len() {
            let (a, b) = (s[i], s[i + 2]);
            if a <= b {
                out.extend(a..=b);
            }
            i += 3;
            continue;
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

pub fn tr(args: &[Vec<u8>]) -> i32 {
    let (mut delete, mut squeeze, mut complement) = (false, false, false);
    let mut sets = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'd') => delete = true,
            Opt::Short(b's') => squeeze = true,
            Opt::Short(b'c' | b'C') => complement = true,
            Opt::Short(b't') => {}
            Opt::Long(l) if l == "delete" => delete = true,
            Opt::Long(l) if l == "squeeze-repeats" => squeeze = true,
            Opt::Long(l) if l == "complement" => complement = true,
            Opt::Operand(s) => sets.push(s),
            o => return bad_option(&o),
        }
    }
    if sets.is_empty() {
        error("missing operand");
        return 1;
    }
    let mut set1 = tr_set(&sets[0]);
    if complement {
        let mut c: Vec<u8> = (0u8..=255).filter(|b| !set1.contains(b)).collect();
        c.sort();
        set1 = c;
    }
    let set2 = sets.get(1).map(|s| tr_set(s));
    let mut map: [u16; 256] = core::array::from_fn(|i| i as u16);
    let mut in1 = [false; 256];
    for &c in &set1 {
        in1[usize::from(c)] = true;
    }
    if !delete && let Some(s2) = &set2 {
        if s2.is_empty() {
            error("when not truncating set1, string2 must be non-empty");
            return 1;
        }
        for (i, &c) in set1.iter().enumerate() {
            map[usize::from(c)] = u16::from(*s2.get(i).unwrap_or(s2.last().unwrap()));
        }
    }
    let squeeze_set: [bool; 256] = {
        let mut s = [false; 256];
        let src = match &set2 {
            Some(s2) if !delete => s2,
            _ => &set1,
        };
        for &c in src {
            s[usize::from(c)] = true;
        }
        if delete && let Some(s2) = &set2 {
            s = [false; 256];
            for &c in s2 {
                s[usize::from(c)] = true;
            }
        }
        s
    };
    let mut last: Option<u8> = None;
    let r = crate::util::stream_chunks(b"-", |chunk| {
        let mut out = Vec::with_capacity(chunk.len());
        for &c in chunk {
            if delete && in1[usize::from(c)] {
                continue;
            }
            let m = if delete { c } else { map[usize::from(c)] as u8 };
            if squeeze && squeeze_set[usize::from(m)] && last == Some(m) {
                continue;
            }
            out.push(m);
            last = Some(m);
        }
        io::out(&out);
        true
    });
    match r {
        Ok(()) => 0,
        Err(e) => {
            error(e);
            1
        }
    }
}

pub fn tac(args: &[Vec<u8>]) -> i32 {
    let mut files: Vec<Vec<u8>> = args[1..].to_vec();
    inputs(&mut files);
    let mut status = 0;
    for f in &files {
        match read_input(f) {
            Ok(d) => {
                let mut out = Vec::with_capacity(d.len());
                for l in lines(&d, b'\n').iter().rev() {
                    out.extend_from_slice(l);
                    out.push(b'\n');
                }
                io::out(&out);
            }
            Err(e) => {
                error_path(f, e);
                status = 1;
            }
        }
    }
    status
}

pub fn rev(args: &[Vec<u8>]) -> i32 {
    let mut files: Vec<Vec<u8>> = args[1..].to_vec();
    inputs(&mut files);
    let mut status = 0;
    for f in &files {
        let r = crate::util::stream_lines(f, b'\n', |l, had| {
            let mut out: Vec<u8> = lossy(l).chars().rev().collect::<String>().into_bytes();
            if had {
                out.push(b'\n');
            }
            io::out(&out);
            true
        });
        if let Err(e) = r {
            error_path(f, e);
            status = 1;
        }
    }
    status
}

pub fn nl(args: &[Vec<u8>]) -> i32 {
    let mut body = b't';
    let (mut width, mut sep, mut start, mut incr) = (6usize, b"\t".to_vec(), 1i64, 1i64);
    let mut format = b"rn".to_vec();
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"bwsvin");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'b') => body = p.value().and_then(|v| v.first().copied()).unwrap_or(b't'),
            Opt::Short(b'w') => width = p.value().and_then(|v| parse_num(&v)).unwrap_or(6),
            Opt::Short(b's') => sep = p.value().unwrap_or_default(),
            Opt::Short(b'v') => start = p.value().and_then(|v| parse_num(&v)).unwrap_or(1),
            Opt::Short(b'i') => incr = p.value().and_then(|v| parse_num(&v)).unwrap_or(1),
            Opt::Short(b'n') => format = p.value().unwrap_or_default(),
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    let mut n = start;
    for f in &files {
        let _ = crate::util::stream_lines(f, b'\n', |l, _| {
            let mut out = Vec::new();
            let number = match body {
                b'a' => true,
                b'n' => false,
                _ => !l.is_empty(),
            };
            if number {
                let s = match format.as_slice() {
                    b"ln" => alloc::format!("{n:<width$}"),
                    b"rz" => alloc::format!("{n:0width$}"),
                    _ => alloc::format!("{n:>width$}"),
                };
                out.extend_from_slice(s.as_bytes());
                out.extend_from_slice(&sep);
                n += incr;
            } else {
                out.extend(core::iter::repeat_n(b' ', width + sep.len()));
            }
            out.extend_from_slice(l);
            out.push(b'\n');
            io::out(&out);
            true
        });
    }
    0
}

pub fn paste(args: &[Vec<u8>]) -> i32 {
    let mut delims = b"\t".to_vec();
    let mut serial = false;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"d");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'd') => delims = crate::util::unescape(&p.value().unwrap_or_default(), true).0,
            Opt::Short(b's') => serial = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    let datas: Vec<Vec<u8>> = files.iter().map(|f| read_input(f).unwrap_or_default()).collect();
    let cols: Vec<Vec<&[u8]>> = datas.iter().map(|d| lines(d, b'\n')).collect();
    let d = |i: usize| if delims.is_empty() { None } else { Some(delims[i % delims.len()]) };
    let mut out = Vec::new();
    if serial {
        for c in &cols {
            for (i, l) in c.iter().enumerate() {
                if i > 0
                    && let Some(x) = d(i - 1)
                {
                    out.push(x);
                }
                out.extend_from_slice(l);
            }
            out.push(b'\n');
        }
    } else {
        let rows = cols.iter().map(Vec::len).max().unwrap_or(0);
        for r in 0..rows {
            for (i, c) in cols.iter().enumerate() {
                if i > 0
                    && let Some(x) = d(i - 1)
                {
                    out.push(x);
                }
                if let Some(l) = c.get(r) {
                    out.extend_from_slice(l);
                }
            }
            out.push(b'\n');
        }
    }
    io::out(&out);
    0
}

pub fn fold(args: &[Vec<u8>]) -> i32 {
    let mut width = 80usize;
    let mut spaces = false;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"w");
    p.numeric = true;
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'w') => width = p.value().and_then(|v| parse_num(&v)).unwrap_or(80),
            Opt::Short(b's') => spaces = true,
            Opt::Short(b'b') => {}
            Opt::Long(l) if l.bytes().all(|c| c.is_ascii_digit()) => width = l.parse().unwrap_or(80),
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    for f in &files {
        let _ = crate::util::stream_lines(f, b'\n', |l, had| {
            let mut out = Vec::new();
            let mut rest = l;
            while rest.len() > width {
                let mut cut = width;
                if spaces && let Some(sp) = rest[..width].iter().rposition(|&c| c == b' ') {
                    cut = sp + 1;
                }
                out.extend_from_slice(&rest[..cut]);
                out.push(b'\n');
                rest = &rest[cut..];
            }
            out.extend_from_slice(rest);
            if had {
                out.push(b'\n');
            }
            io::out(&out);
            true
        });
    }
    0
}

pub fn comm(args: &[Vec<u8>]) -> i32 {
    let mut hide = [false; 3];
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(c @ b'1'..=b'3') => hide[usize::from(c - b'1')] = true,
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.len() != 2 {
        error("missing operand");
        return 1;
    }
    let (a, b) = (read_input(&files[0]).unwrap_or_default(), read_input(&files[1]).unwrap_or_default());
    let (la, lb) = (lines(&a, b'\n'), lines(&b, b'\n'));
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    let emit = |col: usize, l: &[u8], out: &mut Vec<u8>| {
        if hide[col] {
            return;
        }
        for h in &hide[..col] {
            if !h {
                out.push(b'\t');
            }
        }
        out.extend_from_slice(l);
        out.push(b'\n');
    };
    // Like GNU's default --check-order: report unsorted input once per file.
    let mut unsorted = [false; 2];
    let check = |which: usize, l: &[&[u8]], k: usize, unsorted: &mut [bool; 2]| {
        if k > 0 && l[k] < l[k - 1] && !unsorted[which] {
            unsorted[which] = true;
            error(format_args!("file {} is not in sorted order", which + 1));
        }
    };
    while i < la.len() || j < lb.len() {
        if i < la.len() {
            check(0, &la, i, &mut unsorted);
        }
        if j < lb.len() {
            check(1, &lb, j, &mut unsorted);
        }
        match (la.get(i), lb.get(j)) {
            (Some(x), Some(y)) if x == y => {
                emit(2, x, &mut out);
                i += 1;
                j += 1;
            }
            (Some(x), Some(y)) if x < y => {
                emit(0, x, &mut out);
                i += 1;
            }
            (Some(_), Some(y)) => {
                emit(1, y, &mut out);
                j += 1;
            }
            (Some(x), None) => {
                emit(0, x, &mut out);
                i += 1;
            }
            (None, Some(y)) => {
                emit(1, y, &mut out);
                j += 1;
            }
            (None, None) => break,
        }
    }
    io::out(&out);
    if unsorted.iter().any(|&u| u) {
        io::flush_stdout();
        error("input is not in sorted order");
        return 1;
    }
    0
}

pub fn expand(args: &[Vec<u8>]) -> i32 {
    let mut tab = 8usize;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"t");
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b't') => tab = p.value().and_then(|v| parse_num(&v)).unwrap_or(8).max(1),
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    inputs(&mut files);
    for f in &files {
        let mut col = 0;
        let _ = crate::util::stream_chunks(f, |d| {
            let mut out = Vec::with_capacity(d.len());
            for &c in d {
                match c {
                    b'\t' => {
                        let n = tab - col % tab;
                        out.extend(core::iter::repeat_n(b' ', n));
                        col += n;
                    }
                    b'\n' => {
                        out.push(c);
                        col = 0;
                    }
                    _ => {
                        out.push(c);
                        col += 1;
                    }
                }
            }
            io::out(&out);
            true
        });
    }
    0
}
