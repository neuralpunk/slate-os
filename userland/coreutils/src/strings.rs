// SPDX-License-Identifier: MIT OR Apache-2.0

//! strings(1): printable character runs of at least N (default 4) bytes,
//! with `-n`, `-t d|o|x` offsets, `-f` file names, and `-a` (accepted:
//! whole files are always scanned).

use alloc::vec::Vec;

use slate_rt::{io, lossy};

use crate::util::{Opt, Parser, bad_option, error_path, parse_num, read_input};

fn printable(c: u8) -> bool {
    (32..127).contains(&c) || c == b'\t'
}

pub fn main(args: &[Vec<u8>]) -> i32 {
    let mut min = 4usize;
    let mut radix: Option<u8> = None;
    let mut names = false;
    let mut files = Vec::new();
    let mut p = Parser::new(args, b"nt");
    p.numeric = true;
    while let Some(o) = p.next() {
        match o {
            Opt::Short(b'n') => min = p.value().and_then(|v| parse_num(&v)).unwrap_or(4).max(1),
            Opt::Short(b't') => radix = p.value().and_then(|v| v.first().copied()),
            Opt::Short(b'o') => radix = Some(b'o'),
            Opt::Short(b'f') => names = true,
            Opt::Short(b'a') => {}
            Opt::Long(l) if l.bytes().all(|c| c.is_ascii_digit()) => min = l.parse().unwrap_or(4).max(1),
            Opt::Long(l) if l == "bytes" => min = p.value().and_then(|v| parse_num(&v)).unwrap_or(4).max(1),
            Opt::Long(l) if l == "radix" => radix = p.value().and_then(|v| v.first().copied()),
            Opt::Long(l) if l == "print-file-name" => names = true,
            Opt::Long(l) if l == "all" => {}
            Opt::Operand(f) => files.push(f),
            o => return bad_option(&o),
        }
    }
    if files.is_empty() {
        files.push(b"-".to_vec());
    }
    let mut status = 0;
    let mut out = Vec::new();
    for f in &files {
        let data = match read_input(f) {
            Ok(d) => d,
            Err(e) => {
                error_path(f, e);
                status = 1;
                continue;
            }
        };
        let mut start = 0;
        let mut i = 0;
        while i <= data.len() {
            let end_of_run = i == data.len() || !printable(data[i]);
            if end_of_run {
                if i - start >= min {
                    if names {
                        out.extend_from_slice(alloc::format!("{}: ", lossy(f)).as_bytes());
                    }
                    match radix {
                        Some(b'd') => out.extend_from_slice(alloc::format!("{start:7} ").as_bytes()),
                        Some(b'o') => out.extend_from_slice(alloc::format!("{start:7o} ").as_bytes()),
                        Some(b'x') => out.extend_from_slice(alloc::format!("{start:7x} ").as_bytes()),
                        _ => {}
                    }
                    out.extend_from_slice(&data[start..i]);
                    out.push(b'\n');
                }
                start = i + 1;
            }
            i += 1;
        }
        if out.len() > 64 * 1024 {
            io::out(&out);
            out.clear();
        }
    }
    io::out(&out);
    status
}
