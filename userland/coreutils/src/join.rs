// SPDX-License-Identifier: MIT OR Apache-2.0

//! join: join the lines of two sorted files on a common field (POSIX
//! join, with GNU's `-i`, `--header`, `-o auto` and order checking).

use alloc::vec::Vec;

use slate_rt::{io, lossy};

use crate::util::{Opt, Parser, bad_option, error, error_path, missing_value, parse_num, read_input};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    Default,
    Fatal,
    Off,
}

/// An `-o` item: the join field, or file N's field F (1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    Key,
    Field(usize, usize),
}

struct Opts {
    sep: Option<u8>,
    field: [usize; 2],
    unpaired: [bool; 2],
    only_unpaired: bool,
    empty: Option<Vec<u8>>,
    format: Option<Vec<Item>>,
    auto: bool,
    ignore_case: bool,
    check: Check,
    header: bool,
}

fn fields(line: &[u8], sep: Option<u8>) -> Vec<&[u8]> {
    match sep {
        Some(t) => line.split(|&c| c == t).collect(),
        None => line.split(|&c| c == b' ' || c == b'\t').filter(|f| !f.is_empty()).collect(),
    }
}

fn cmp_keys(a: &[u8], b: &[u8], ic: bool) -> core::cmp::Ordering {
    if ic { a.iter().map(u8::to_ascii_lowercase).cmp(b.iter().map(u8::to_ascii_lowercase)) } else { a.cmp(b) }
}

struct Input<'a> {
    name: &'a [u8],
    lines: Vec<&'a [u8]>,
    pos: usize,
    field: usize,
    warned: bool,
}

impl<'a> Input<'a> {
    fn key(&self, i: usize, sep: Option<u8>) -> &'a [u8] {
        fields(self.lines[i], sep).get(self.field).copied().unwrap_or(b"")
    }
}

fn line_out(out: &mut Vec<u8>, parts: &[&[u8]], sep: u8) {
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(sep);
        }
        out.extend_from_slice(p);
    }
    out.push(b'\n');
}

/// Output one joined (or unpaired) line. `l` holds each file's line, or
/// None for the missing side.
fn emit(out: &mut Vec<u8>, o: &Opts, l: [Option<&[u8]>; 2], auto_n: [usize; 2]) {
    let sep = o.sep.unwrap_or(b' ');
    let f: [Vec<&[u8]>; 2] =
        [l[0].map(|x| fields(x, o.sep)).unwrap_or_default(), l[1].map(|x| fields(x, o.sep)).unwrap_or_default()];
    let side = if l[0].is_some() { 0 } else { 1 };
    let key = f[side].get(o.field[side]).copied().unwrap_or(b"");
    let empty: &[u8] = o.empty.as_deref().unwrap_or(b"");
    let mut parts: Vec<&[u8]> = Vec::new();
    let format: Option<Vec<Item>> = if o.auto {
        let mut v = alloc::vec![Item::Key];
        for (n, &count) in auto_n.iter().enumerate() {
            v.extend((0..count).filter(|&i| i != o.field[n]).map(|i| Item::Field(n, i)));
        }
        Some(v)
    } else {
        o.format.clone()
    };
    match format {
        Some(items) => {
            for it in items {
                parts.push(match it {
                    Item::Key => key,
                    Item::Field(n, i) => f[n].get(i).copied().filter(|_| l[n].is_some()).unwrap_or(empty),
                });
            }
        }
        None => {
            parts.push(key);
            for (n, fs) in f.iter().enumerate() {
                parts.extend(fs.iter().enumerate().filter(|&(i, _)| i != o.field[n]).map(|(_, v)| *v));
            }
        }
    }
    line_out(out, &parts, sep);
}

fn parse_format(v: &[u8]) -> Option<Vec<Item>> {
    let mut items = Vec::new();
    for tok in v.split(|&c| c == b',' || c == b' ' || c == b'\t').filter(|t| !t.is_empty()) {
        if tok == b"0" {
            items.push(Item::Key);
            continue;
        }
        let dot = tok.iter().position(|&c| c == b'.')?;
        let n: usize = parse_num(&tok[..dot])?;
        let i: usize = parse_num(&tok[dot + 1..])?;
        if !(1..=2).contains(&n) || i == 0 {
            return None;
        }
        items.push(Item::Field(n - 1, i - 1));
    }
    Some(items)
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut o = Opts {
        sep: None,
        field: [0, 0],
        unpaired: [false, false],
        only_unpaired: false,
        empty: None,
        format: None,
        auto: false,
        ignore_case: false,
        check: Check::Default,
        header: false,
    };
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"12jtaveo");
    while let Some(opt) = p.next() {
        let c = match &opt {
            Opt::Short(c @ (b'1' | b'2' | b'j' | b't' | b'a' | b'v' | b'e' | b'o')) => *c,
            Opt::Short(b'i') => {
                o.ignore_case = true;
                continue;
            }
            Opt::Long(l) if l == "ignore-case" => {
                o.ignore_case = true;
                continue;
            }
            Opt::Long(l) if l == "check-order" => {
                o.check = Check::Fatal;
                continue;
            }
            Opt::Long(l) if l == "nocheck-order" => {
                o.check = Check::Off;
                continue;
            }
            Opt::Long(l) if l == "header" => {
                o.header = true;
                continue;
            }
            Opt::Operand(x) => {
                files.push(x.clone());
                continue;
            }
            _ => return bad_option(&opt),
        };
        let Some(v) = p.value() else { return missing_value(c as char) };
        match c {
            b'1' | b'2' | b'j' => match parse_num::<usize>(&v) {
                Some(n) if n > 0 => {
                    if c != b'2' {
                        o.field[0] = n - 1;
                    }
                    if c != b'1' {
                        o.field[1] = n - 1;
                    }
                }
                _ => {
                    error(format_args!("invalid field number: '{}'", lossy(&v)));
                    return 1;
                }
            },
            b't' => match v.as_slice() {
                [t] => o.sep = Some(*t),
                [] => o.sep = Some(b'\n'),
                _ => {
                    error(format_args!("multi-character tab '{}'", lossy(&v)));
                    return 1;
                }
            },
            b'a' | b'v' => match v.as_slice() {
                [n @ (b'1' | b'2')] => {
                    o.unpaired[usize::from(n - b'1')] = true;
                    if c == b'v' {
                        o.only_unpaired = true;
                    }
                }
                _ => {
                    error(format_args!("invalid field number: '{}'", lossy(&v)));
                    return 1;
                }
            },
            b'e' => o.empty = Some(v),
            _ => {
                if v == b"auto" {
                    o.auto = true;
                } else {
                    match parse_format(&v) {
                        Some(f) => o.format.get_or_insert_default().extend(f),
                        None => {
                            error(format_args!("invalid field specifier: '{}'", lossy(&v)));
                            return 1;
                        }
                    }
                }
            }
        }
    }
    if files.len() != 2 {
        if files.len() < 2 {
            match files.first() {
                Some(f) => error(format_args!("missing operand after '{}'", lossy(f))),
                None => error("missing operand"),
            }
        } else {
            error(format_args!("extra operand '{}'", lossy(&files[2])));
        }
        slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
        return 1;
    }
    let mut data = Vec::new();
    for f in &files {
        match read_input(f) {
            Ok(d) => data.push(d),
            Err(e) => {
                error_path(f, e);
                return 1;
            }
        }
    }
    let mk = |i: usize| Input {
        name: &files[i],
        lines: crate::util::lines(&data[i], b'\n'),
        pos: 0,
        field: o.field[i],
        warned: false,
    };
    let mut inp = [mk(0), mk(1)];
    let auto_n = [
        inp[0].lines.first().map(|l| fields(l, o.sep).len()).unwrap_or(0),
        inp[1].lines.first().map(|l| fields(l, o.sep).len()).unwrap_or(0),
    ];
    let mut out = Vec::new();
    if o.header && (!inp[0].lines.is_empty() || !inp[1].lines.is_empty()) {
        let (a, b) = (inp[0].lines.first().copied(), inp[1].lines.first().copied());
        emit(&mut out, &o, [a.or(Some(b"")), b], auto_n);
        inp[0].pos = usize::from(a.is_some());
        inp[1].pos = usize::from(b.is_some());
    }
    let mut disorder = false;
    // The group of lines in file `n` that share the key at `pos`; checks
    // the line after it is not smaller.
    let mut group = |inp: &mut Input, out: &mut Vec<u8>| -> Result<usize, ()> {
        let start = inp.pos;
        let key = inp.key(start, o.sep);
        let mut end = start + 1;
        while end < inp.lines.len() && cmp_keys(inp.key(end, o.sep), key, o.ignore_case).is_eq() {
            end += 1;
        }
        if end < inp.lines.len()
            && o.check != Check::Off
            && !inp.warned
            && cmp_keys(inp.key(end, o.sep), key, o.ignore_case).is_lt()
        {
            io::out(out);
            out.clear();
            io::flush_stdout();
            error(format_args!("{}:{}: is not sorted: {}", lossy(inp.name), end + 1, lossy(inp.lines[end])));
            inp.warned = true;
            disorder = true;
            if o.check == Check::Fatal {
                return Err(());
            }
        }
        Ok(end)
    };
    loop {
        let (more0, more1) = (inp[0].pos < inp[0].lines.len(), inp[1].pos < inp[1].lines.len());
        if !more0 && !more1 {
            break;
        }
        let ord = if more0 && more1 {
            cmp_keys(inp[0].key(inp[0].pos, o.sep), inp[1].key(inp[1].pos, o.sep), o.ignore_case)
        } else if more0 {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Greater
        };
        let side = match ord {
            core::cmp::Ordering::Less => Some(0),
            core::cmp::Ordering::Greater => Some(1),
            core::cmp::Ordering::Equal => None,
        };
        match side {
            Some(n) => {
                let Ok(end) = group(&mut inp[n], &mut out) else {
                    io::out(&out);
                    io::flush_stdout();
                    return 1;
                };
                if o.unpaired[n] {
                    for &l in &inp[n].lines[inp[n].pos..end] {
                        emit(&mut out, &o, if n == 0 { [Some(l), None] } else { [None, Some(l)] }, auto_n);
                    }
                }
                inp[n].pos = end;
            }
            None => {
                let (Ok(e0), Ok(e1)) = (group(&mut inp[0], &mut out), group(&mut inp[1], &mut out)) else {
                    io::out(&out);
                    io::flush_stdout();
                    return 1;
                };
                if !o.only_unpaired {
                    for i in inp[0].pos..e0 {
                        for j in inp[1].pos..e1 {
                            emit(&mut out, &o, [Some(inp[0].lines[i]), Some(inp[1].lines[j])], auto_n);
                        }
                    }
                }
                inp[0].pos = e0;
                inp[1].pos = e1;
            }
        }
    }
    io::out(&out);
    io::flush_stdout();
    if disorder {
        error("input is not in sorted order");
        return 1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(parse_format(b"0,1.2 2.3"), Some(alloc::vec![Item::Key, Item::Field(0, 1), Item::Field(1, 2)]));
        assert_eq!(parse_format(b"3.1"), None);
        assert_eq!(fields(b"  a  b\tc", None), [b"a" as &[u8], b"b", b"c"]);
        assert_eq!(fields(b"a::c", Some(b':')), [b"a" as &[u8], b"", b"c"]);
    }
}
