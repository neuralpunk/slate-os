// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use std::io::Write;
use std::process::{Command, Stdio};

fn samples() -> std::vec::Vec<std::vec::Vec<u8>> {
    let text: std::vec::Vec<u8> =
        (0..30000).flat_map(|i| std::format!("line {i}: the quick brown fox {}\n", i % 7).into_bytes()).collect();
    let mut noise = std::vec::Vec::new();
    let mut x = 0x1234_5678u32;
    for _ in 0..250_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise.push(x as u8);
    }
    let mut runs = std::vec::Vec::new();
    for (i, len) in [1usize, 3, 4, 5, 250, 255, 256, 259, 260, 1000].iter().enumerate() {
        runs.extend(std::iter::repeat_n(b'a' + i as u8, *len));
        runs.push(b'z');
    }
    std::vec![
        std::vec::Vec::new(),
        b"a".to_vec(),
        b"banana".to_vec(),
        (0..=255u8).collect(),
        std::vec![7u8; 1_000_000],
        runs,
        text,
        noise,
    ]
}

#[test]
fn crc() {
    // CRC-32/BZIP2's check value.
    assert_eq!(crc32(0, b"123456789"), 0xFC89_1918);
    assert_eq!(crc32(crc32(0, b"1234"), b"56789"), 0xFC89_1918);
}

#[test]
fn rotations() {
    let s = b"banana";
    let p = sort_rotations(s);
    let rots: std::vec::Vec<std::vec::Vec<u8>> =
        p.iter().map(|&r| [&s[r as usize..], &s[..r as usize]].concat()).collect();
    let mut sorted = rots.clone();
    sorted.sort();
    assert_eq!(rots, sorted);
    // Equal rotations of a periodic block.
    assert_eq!(sort_rotations(b"abab").len(), 4);
}

#[test]
fn round_trips() {
    for (n, s) in samples().iter().enumerate() {
        for level in [1, 9] {
            let z = compress(s, level);
            assert_eq!(&decompress(&z).unwrap(), s, "sample {n} level {level}");
        }
    }
    // Two streams one after the other read as one.
    let mut two = compress(b"one ", 9);
    two.extend(compress(b"two", 9));
    assert_eq!(decompress(&two).unwrap(), b"one two");
}

fn host(args: &[&str], input: &[u8]) -> Option<std::vec::Vec<u8>> {
    let mut c = Command::new("bzip2").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
    let mut stdin = c.stdin.take()?;
    let data = input.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let o = c.wait_with_output().ok()?;
    let _ = t.join();
    assert!(o.status.success(), "bzip2 {args:?} failed");
    Some(o.stdout)
}

/// Ours read by the host's bzip2, and the host's read by ours. Skipped
/// without bzip2.
#[test]
fn against_host() {
    for (n, s) in samples().iter().enumerate() {
        let ours = compress(s, 9);
        let Some(back) = host(&["-dc"], &ours) else { return };
        assert_eq!(&back, s, "host read of our sample {n}");
        for level in ["-1", "-9"] {
            let theirs = host(&[level, "-c"], s).unwrap();
            assert_eq!(&decompress(&theirs).unwrap(), s, "our read of host {level} sample {n}");
        }
    }
    // Our sizes are close to the host's.
    let text = &samples()[6];
    let (ours, theirs) = (compress(text, 9).len(), host(&["-9", "-c"], text).unwrap().len());
    assert!(ours * 100 <= theirs * 110, "ours {ours} theirs {theirs}");
}

#[test]
fn bad_data() {
    assert_eq!(decompress(b"not bzip2"), Err(Error::NotBzip2));
    let mut z = compress(b"hello hello hello", 9);
    let n = z.len();
    z[n / 2] ^= 0x10;
    assert!(decompress(&z).is_err());
    let z = compress(b"hello hello hello", 9);
    assert_eq!(decompress(&z[..z.len() - 3]), Err(Error::Truncated));
}
