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
    // Text, then noise, then the text again (far back), past 2 MiB.
    let mut mixed = text.clone();
    mixed.extend_from_slice(&noise);
    mixed.extend_from_slice(&text);
    mixed.extend(std::iter::repeat_n(b'q', 1 << 21));
    std::vec![
        std::vec::Vec::new(),
        b"a".to_vec(),
        b"abababababababababab".to_vec(),
        (0..=255u8).collect(),
        text,
        noise,
        mixed
    ]
}

#[test]
fn checks() {
    // CRC-64/XZ's check value.
    assert_eq!(crc64(0, b"123456789"), 0x995D_C9BB_DF19_39FA);
    assert_eq!(dict_size(0).unwrap(), 4096);
    assert_eq!(dict_size(1).unwrap(), 6144);
    assert_eq!(dict_size(22).unwrap(), 8 << 20);
}

#[test]
fn round_trips() {
    for (n, s) in samples().iter().enumerate() {
        for level in [0, 6] {
            let z = compress(s, level);
            assert_eq!(&decompress(&z).unwrap(), s, "xz sample {n} level {level}");
            let l = compress_lzma(s, level);
            assert_eq!(&decompress_lzma(&l).unwrap(), s, "lzma sample {n} level {level}");
        }
    }
    let mut two = compress(b"one ", 6);
    two.extend_from_slice(&[0; 8]);
    two.extend(compress(b"two", 6));
    assert_eq!(decompress(&two).unwrap(), b"one two");
}

fn host(args: &[&str], input: &[u8]) -> Option<std::vec::Vec<u8>> {
    let mut c = Command::new("xz").args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().ok()?;
    let mut stdin = c.stdin.take()?;
    let data = input.to_vec();
    let t = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let o = c.wait_with_output().ok()?;
    let _ = t.join();
    assert!(o.status.success(), "xz {args:?} failed");
    Some(o.stdout)
}

/// Ours read by the host's xz, and the host's (each check, delta, lzma,
/// several levels) read by ours. Skipped without xz.
#[test]
fn against_host() {
    for (n, s) in samples().iter().enumerate() {
        let Some(back) = host(&["-dc"], &compress(s, 6)) else { return };
        assert_eq!(&back, s, "host read of our xz sample {n}");
        let back = host(&["-dc", "--format=lzma"], &compress_lzma(s, 6)).unwrap();
        assert_eq!(&back, s, "host read of our lzma sample {n}");
        for args in [
            &["-0", "-c"][..],
            &["-6", "-c"],
            &["-9e", "-c"],
            &["-c", "-C", "crc32"],
            &["-c", "-C", "sha256"],
            &["-c", "-C", "none"],
            &["-c", "--filters=delta:dist=4 lzma2"],
            &["-c", "--block-size=100000"],
        ] {
            let theirs = host(args, s).unwrap();
            assert_eq!(&decompress(&theirs).unwrap(), s, "our read of host {args:?} sample {n}");
        }
        let theirs = host(&["-c", "--format=lzma"], s).unwrap();
        assert_eq!(&decompress_lzma(&theirs).unwrap(), s, "our read of host lzma sample {n}");
    }
    // Ours within reach of the host's size.
    let text = &samples()[4];
    let (ours, theirs) = (compress(text, 6).len(), host(&["-6", "-c"], text).unwrap().len());
    assert!(ours * 100 <= theirs * 130, "ours {ours} theirs {theirs}");
}

#[test]
fn bad_data() {
    assert_eq!(decompress(b"not xz at all"), Err(Error::NotXz));
    let mut z = compress(b"hello hello hello hello", 6);
    let n = z.len();
    z[n / 2] ^= 0x10;
    assert!(decompress(&z).is_err());
    let z = compress(b"hello", 6);
    assert!(decompress(&z[..z.len() - 5]).is_err());
}
