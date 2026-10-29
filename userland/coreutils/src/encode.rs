// SPDX-License-Identifier: MIT OR Apache-2.0

//! base64, base32 and basenc (RFC 4648's base64, base64url, base32,
//! base32hex and base16; bits as text, most or least significant first;
//! ZeroMQ's Z85, RFC 32): encode with lines wrapped at 76 columns, or
//! decode (`-d`), skipping newlines and, with `-i`, anything else outside
//! the alphabet (ADR 0148).

use alloc::vec::Vec;

use slate_rt::{io, lossy};

use crate::util::{Opt, Parser, bad_option, error, error_path, missing_value, parse_num, read_input};

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32HEX: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
const Z85: &[u8; 85] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// An encoding basenc knows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Coding {
    /// RFC 4648's padded ones: the alphabet and the bits per symbol.
    Rfc(&'static [u8], u32),
    Base16,
    /// Eight `0`/`1` per byte, most (true) or least significant first.
    Base2(bool),
    Z85,
}

impl Coding {
    fn encode(self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        Ok(match self {
            Coding::Rfc(a, bits) => encode(data, a, bits),
            Coding::Base16 => data
                .iter()
                .flat_map(|b| [b"0123456789ABCDEF"[usize::from(b >> 4)], b"0123456789ABCDEF"[usize::from(b & 15)]])
                .collect(),
            Coding::Base2(msb) => data
                .iter()
                .flat_map(|&b| {
                    (0..8).map(move |i| if (b >> if msb { 7 - i } else { i }) & 1 == 1 { b'1' } else { b'0' })
                })
                .collect(),
            Coding::Z85 => {
                if data.len() % 4 != 0 {
                    return Err("invalid input (length must be multiple of 4 characters)");
                }
                let mut out = Vec::with_capacity(data.len() / 4 * 5);
                for c in data.as_chunks::<4>().0 {
                    let mut v = u32::from_be_bytes(*c);
                    let mut five = [0u8; 5];
                    for d in five.iter_mut().rev() {
                        *d = Z85[(v % 85) as usize];
                        v /= 85;
                    }
                    out.extend_from_slice(&five);
                }
                out
            }
        })
    }

    /// The decoded bytes, and whether all of the input was valid.
    fn decode(self, data: &[u8], garbage: bool) -> (Vec<u8>, bool) {
        let (digits, per): (Vec<u8>, usize) = match self {
            Coding::Rfc(a, bits) => return decode(data, a, bits, garbage),
            Coding::Base16 => (b"0123456789abcdef".to_vec(), 2),
            Coding::Base2(_) => (b"01".to_vec(), 8),
            Coding::Z85 => (Z85.to_vec(), 5),
        };
        let mut out = Vec::new();
        let mut group: Vec<u32> = Vec::new();
        for &c in data {
            if c == b'\n' {
                continue;
            }
            let c = if self == Coding::Base16 { c.to_ascii_lowercase() } else { c };
            let Some(v) = digits.iter().position(|&d| d == c) else {
                if garbage {
                    continue;
                }
                return (out, false);
            };
            group.push(v as u32);
            if group.len() == per {
                match self {
                    Coding::Base16 => out.push((group[0] * 16 + group[1]) as u8),
                    Coding::Base2(msb) => out.push(
                        group
                            .iter()
                            .enumerate()
                            .fold(0u8, |b, (i, &bit)| b | ((bit as u8) << if msb { 7 - i } else { i })),
                    ),
                    _ => {
                        let v = group.iter().fold(0u64, |v, &d| v * 85 + u64::from(d));
                        if v > u64::from(u32::MAX) {
                            return (out, false);
                        }
                        out.extend_from_slice(&(v as u32).to_be_bytes());
                    }
                }
                group.clear();
            }
        }
        let whole = group.is_empty();
        (out, whole)
    }
}

/// Encode `data`: `bits` per symbol (6 or 5), groups of `group` bytes.
fn encode(data: &[u8], alphabet: &[u8], bits: u32) -> Vec<u8> {
    let (group, syms) = if bits == 6 { (3, 4) } else { (5, 8) };
    let mut out = Vec::with_capacity(data.len() * 2);
    for chunk in data.chunks(group) {
        let mut v: u64 = 0;
        for i in 0..group {
            v = (v << 8) | u64::from(chunk.get(i).copied().unwrap_or(0));
        }
        let used = (chunk.len() * 8).div_ceil(bits as usize);
        for i in 0..syms {
            if i < used {
                let shift = (group * 8) as u32 - bits * (i as u32 + 1);
                out.push(alphabet[((v >> shift) & ((1 << bits) - 1)) as usize]);
            } else {
                out.push(b'=');
            }
        }
    }
    out
}

/// Decode `data`, returning the bytes and whether all of it was valid.
/// Bytes of complete groups before a bad character are kept.
fn decode(data: &[u8], alphabet: &[u8], bits: u32, ignore_garbage: bool) -> (Vec<u8>, bool) {
    let syms = if bits == 6 { 4 } else { 8 };
    let mut out = Vec::new();
    let (mut acc, mut nbits, mut in_group, mut padding) = (0u64, 0u32, 0usize, false);
    for &c in data {
        if c == b'\n' {
            continue;
        }
        if c == b'=' {
            padding = true;
            in_group += 1;
            if in_group == syms {
                in_group = 0;
                acc = 0;
                nbits = 0;
                padding = false;
            }
            continue;
        }
        let Some(v) = alphabet.iter().position(|&a| a == c) else {
            if ignore_garbage {
                continue;
            }
            return (out, false);
        };
        if padding {
            // Data after padding within one group.
            return (out, false);
        }
        acc = (acc << bits) | v as u64;
        nbits += bits;
        in_group += 1;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
        if in_group == syms {
            in_group = 0;
            acc = 0;
            nbits = 0;
        }
    }
    // An unpadded last group must be whole bytes: less than a symbol's
    // bits left over, and those zero (as GNU's decoders were seen to
    // require).
    let canonical = in_group == 0 || padding || (nbits < bits && acc & ((1 << nbits) - 1) == 0);
    (out, canonical)
}

fn run(args: &[Vec<u8>], coding: Option<Coding>) -> i32 {
    let (mut dec, mut garbage, mut wrap) = (false, false, 76usize);
    let mut files = Vec::new();
    let mut coding = coding;
    let basenc = coding.is_none();
    let mut p = Parser::new(args, b"w");
    while let Some(o) = p.next() {
        match o {
            Opt::Long(l) if basenc && l.starts_with("base") || basenc && l == "z85" => {
                coding = Some(match l.as_str() {
                    "base64" => Coding::Rfc(B64, 6),
                    "base64url" => Coding::Rfc(B64URL, 6),
                    "base32" => Coding::Rfc(B32, 5),
                    "base32hex" => Coding::Rfc(B32HEX, 5),
                    "base16" => Coding::Base16,
                    "base2msbf" => Coding::Base2(true),
                    "base2lsbf" => Coding::Base2(false),
                    "z85" => Coding::Z85,
                    _ => return bad_option(&Opt::Long(l)),
                });
            }
            Opt::Short(b'd') => dec = true,
            Opt::Long(l) if l == "decode" => dec = true,
            Opt::Short(b'i') => garbage = true,
            Opt::Long(l) if l == "ignore-garbage" => garbage = true,
            Opt::Short(b'w') => {
                let Some(v) = p.value() else { return missing_value('w') };
                match parse_num(&v) {
                    Some(n) => wrap = n,
                    None => {
                        error(format_args!("invalid wrap size: '{}'", lossy(&v)));
                        return 1;
                    }
                }
            }
            Opt::Long(l) if l == "wrap" => {
                let Some(v) = p.value() else { return missing_value(l) };
                match parse_num(&v) {
                    Some(n) => wrap = n,
                    None => {
                        error(format_args!("invalid wrap size: '{}'", lossy(&v)));
                        return 1;
                    }
                }
            }
            Opt::Operand(x) => files.push(x),
            o => return bad_option(&o),
        }
    }
    let Some(coding) = coding else {
        error("missing encoding type");
        slate_rt::eprintln!("Try '{} --help' for more information.", slate_rt::prog_name());
        return 1;
    };
    if files.len() > 1 {
        error(format_args!("extra operand '{}'", lossy(&files[1])));
        return 1;
    }
    let file = files.pop().unwrap_or_else(|| b"-".to_vec());
    let data = match read_input(&file) {
        Ok(d) => d,
        Err(e) => {
            error_path(&file, e);
            return 1;
        }
    };
    if dec {
        let (out, ok) = coding.decode(&data, garbage);
        io::out(&out);
        io::flush_stdout();
        if !ok {
            error("invalid input");
            return 1;
        }
        return 0;
    }
    let enc = match coding.encode(&data) {
        Ok(e) => e,
        Err(why) => {
            error(why);
            return 1;
        }
    };
    let mut out = Vec::with_capacity(enc.len() + enc.len() / 64 + 1);
    if wrap == 0 {
        out.extend_from_slice(&enc);
    } else {
        for line in enc.chunks(wrap) {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    io::out(&out);
    io::flush_stdout();
    0
}

pub fn base64(args: &[Vec<u8>]) -> i32 {
    run(args, Some(Coding::Rfc(B64, 6)))
}

pub fn base32(args: &[Vec<u8>]) -> i32 {
    run(args, Some(Coding::Rfc(B32, 5)))
}

pub fn basenc(args: &[Vec<u8>]) -> i32 {
    run(args, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10's test vectors.
    #[test]
    fn rfc_vectors() {
        let cases: [(&[u8], &[u8], &[u8]); 7] = [
            (b"", b"", b""),
            (b"f", b"Zg==", b"MY======"),
            (b"fo", b"Zm8=", b"MZXQ===="),
            (b"foo", b"Zm9v", b"MZXW6==="),
            (b"foob", b"Zm9vYg==", b"MZXW6YQ="),
            (b"fooba", b"Zm9vYmE=", b"MZXW6YTB"),
            (b"foobar", b"Zm9vYmFy", b"MZXW6YTBOI======"),
        ];
        for (plain, b64, b32) in cases {
            assert_eq!(encode(plain, B64, 6), b64);
            assert_eq!(encode(plain, B32, 5), b32);
            assert_eq!(decode(b64, B64, 6, false), (plain.to_vec(), true));
            assert_eq!(decode(b32, B32, 5, false), (plain.to_vec(), true));
        }
    }

    #[test]
    fn other_codings() {
        // RFC 32's example: 86 4F D2 6F B5 59 F7 5B is HelloWorld.
        let z = Coding::Z85;
        assert_eq!(z.encode(&[0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B]).unwrap(), b"HelloWorld");
        assert_eq!(z.decode(b"HelloWorld", false), (alloc::vec![0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B], true));
        assert!(z.encode(b"abc").is_err());
        assert_eq!(Coding::Base16.encode(b"hi").unwrap(), b"6869");
        assert_eq!(Coding::Base16.decode(b"6a6B", false), (b"jk".to_vec(), true));
        assert_eq!(Coding::Base2(true).encode(b"A").unwrap(), b"01000001");
        assert_eq!(Coding::Base2(false).encode(b"A").unwrap(), b"10000010");
        assert_eq!(Coding::Base2(false).decode(b"10000010", false), (b"A".to_vec(), true));
        assert_eq!(Coding::Base16.decode(b"686", false), (b"h".to_vec(), false));
    }

    #[test]
    fn bad_input_keeps_whole_groups() {
        assert_eq!(decode(b"aGVs*bG8=", B64, 6, false), (b"hel".to_vec(), false));
        assert_eq!(decode(b"aGVs*bG8=", B64, 6, true), (b"hello".to_vec(), true));
        assert_eq!(decode(b"aGVsbG8=aGk=", B64, 6, false), (b"hellohi".to_vec(), true));
    }
}
