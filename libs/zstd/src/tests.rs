// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use std::io::Write;
use std::process::{Command, Stdio};

fn samples() -> std::vec::Vec<std::vec::Vec<u8>> {
    let text: std::vec::Vec<u8> =
        (0..30000).flat_map(|i| std::format!("line {i}: the quick brown fox {}\n", i % 7).into_bytes()).collect();
    let mut noise = std::vec::Vec::new();
    let mut x = 0x1234_5678u32;
    for _ in 0..300_000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise.push(x as u8);
    }
    let mut bin = std::vec::Vec::new();
    for i in 0..200_000u32 {
        bin.extend_from_slice(&(i.wrapping_mul(2_654_435_761) >> (i % 23)).to_le_bytes()[..2]);
        if i % 5 == 0 {
            bin.push(0xE8);
        }
    }
    let mut mixed = text.clone();
    mixed.extend_from_slice(&noise);
    mixed.extend_from_slice(&text);
    mixed.extend(std::iter::repeat_n(b'q', 300_000));
    std::vec![
        std::vec::Vec::new(),
        b"a".to_vec(),
        b"abcabcabcabcabcabcabcabcabcabc".to_vec(),
        (0..=255u8).collect(),
        text,
        noise,
        bin,
        mixed
    ]
}

#[test]
fn hashes() {
    // XXH64's published check values.
    assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
    assert_eq!(xxh64(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
    assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
    let long: std::vec::Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    let mut x = Xxh64::new(0);
    for c in long.chunks(7) {
        x.update(c);
    }
    assert_eq!(x.finish(), xxh64(&long, 0));
}

#[test]
fn round_trips() {
    for (n, s) in samples().iter().enumerate() {
        for level in [1, 3, 19] {
            let z = compress(s, level);
            assert_eq!(&decompress(&z).unwrap(), s, "sample {n} level {level}");
        }
    }
    let mut two = compress(b"one ", 3);
    two.extend(compress(b"two", 3));
    assert_eq!(decompress(&two).unwrap(), b"one two");
}

fn host(args: &[&str], input: &[u8]) -> Option<std::vec::Vec<u8>> {
    let mut c = Command::new("zstd")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = c.stdin.take()?;
    let data = input.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let o = c.wait_with_output().ok()?;
    let _ = t.join();
    assert!(o.status.success(), "zstd {args:?} failed");
    Some(o.stdout)
}

/// Ours read by the host's zstd, and the host's (several levels, with
/// and without checksums and sizes) read by ours. Skipped without zstd.
#[test]
fn against_host() {
    for (n, s) in samples().iter().enumerate() {
        let Some(back) = host(&["-dc"], &compress(s, 3)) else { return };
        assert_eq!(&back, s, "host read of our sample {n}");
        for args in [
            &["-1", "-c"][..],
            &["-3", "-c"],
            &["-19", "-c"],
            &["--no-check", "-c"],
            &["--ultra", "-22", "-c"],
            &["--fast=5", "-c"],
        ] {
            let theirs = host(args, s).unwrap();
            assert_eq!(&decompress(&theirs).unwrap(), s, "our read of host {args:?} sample {n}");
        }
    }
    let text = &samples()[4];
    let (ours, theirs) = (compress(text, 3).len(), host(&["-3", "-c"], text).unwrap().len());
    assert!(ours * 100 <= theirs * 150, "ours {ours} theirs {theirs}");
}

#[test]
fn bad_data() {
    assert_eq!(decompress(b"not zstd at all"), Err(Error::NotZstd));
    let mut z = compress(b"hello hello hello hello hello", 3);
    let n = z.len();
    z[n - 6] ^= 0x10;
    assert!(decompress(&z).is_err());
    let z = compress(b"hello", 3);
    assert!(decompress(&z[..z.len() - 2]).is_err());
}
