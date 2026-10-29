// SPDX-License-Identifier: MIT OR Apache-2.0

use super::*;
use std::process::Command;

fn samples() -> std::vec::Vec<std::vec::Vec<u8>> {
    let text: std::vec::Vec<u8> =
        (0..20000).flat_map(|i| std::format!("line {i}: the quick brown fox {}\n", i % 7).into_bytes()).collect();
    let mut noise = std::vec::Vec::new();
    let mut x = 0x1234_5678u32;
    for _ in 0..70000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        noise.push(x as u8);
    }
    std::vec![
        std::vec::Vec::new(),
        b"a".to_vec(),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        text,
        noise
    ]
}

#[test]
fn crc() {
    // RFC 1952's CRC-32 of "123456789" (the standard check value).
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32_update(crc32(b"1234"), b"56789"), 0xCBF4_3926);
}

#[test]
fn round_trips() {
    for s in samples() {
        let z = deflate(&s);
        assert_eq!(inflate(&z).unwrap(), s);
        let g = gzip(&s, &Header { name: Some(b"x.txt".to_vec()), mtime: 7 });
        let (back, h) = gunzip(&g).unwrap();
        assert_eq!(back, s);
        assert_eq!(h, Header { name: Some(b"x.txt".to_vec()), mtime: 7 });
    }
    // Text compresses.
    let text = &samples()[3];
    assert!(deflate(text).len() < text.len() / 4);
}

/// Streams made by the host's gzip (dynamic codes, several levels) read
/// back; ours read back by the host's gzip. Skipped without gzip.
#[test]
fn against_host_gzip() {
    let dir = std::env::temp_dir().join(std::format!("flate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (n, s) in samples().iter().enumerate() {
        let plain = dir.join(std::format!("s{n}"));
        std::fs::write(&plain, s).unwrap();
        for level in ["-1", "-6", "-9"] {
            let Ok(o) = Command::new("gzip").args([level, "-c", "-n"]).arg(&plain).output() else { return };
            assert!(o.status.success());
            assert_eq!(&gunzip(&o.stdout).unwrap().0, s, "gzip {level} sample {n}");
        }
        let ours = dir.join(std::format!("s{n}.gz"));
        std::fs::write(&ours, gzip(s, &Header::default())).unwrap();
        let o = Command::new("gzip").args(["-d", "-c"]).arg(&ours).output().unwrap();
        assert!(o.status.success(), "host gzip refused our sample {n}");
        assert_eq!(&o.stdout, s);
    }
    // Two members concatenated read as one.
    let mut two = gzip(b"one ", &Header::default());
    two.extend(gzip(b"two", &Header::default()));
    assert_eq!(gunzip(&two).unwrap().0, b"one two");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bad_data() {
    assert_eq!(gunzip(b"not gzip at all, really"), Err(Error::NotGzip));
    let mut g = gzip(b"hello world", &Header::default());
    let n = g.len();
    g[n - 5] ^= 1;
    assert_eq!(gunzip(&g), Err(Error::Checksum));
    g.truncate(12);
    assert!(gunzip(&g).is_err());
    // Block type 3 is reserved.
    assert_eq!(inflate(&[0b111]), Err(Error::Invalid));
}

#[test]
fn limited_inflate() {
    // A megabyte of zeros deflates to little; a smaller limit stops it.
    let big = std::vec![0u8; 1 << 20];
    let d = deflate(&big);
    assert!(d.len() < 16 << 10);
    assert_eq!(inflate_raw_limited(&d, 1 << 20).unwrap().0, big);
    assert_eq!(inflate_raw_limited(&d, (1 << 20) - 1), Err(Error::TooLarge));
    assert_eq!(inflate_raw_limited(&d, 1000), Err(Error::TooLarge));
}

/// Every level reads back, and higher levels are no larger than lower
/// ones by much; level 6 comes within 3% of the host's gzip -6.
#[test]
fn levels_and_size() {
    let text = &samples()[3];
    let mut sizes = std::vec::Vec::new();
    for level in 0..=9 {
        let z = deflate_level(text, level);
        assert_eq!(&inflate(&z).unwrap(), text, "level {level}");
        sizes.push(z.len());
    }
    assert!(sizes[9] <= sizes[1]);
    assert!(sizes[0] >= text.len(), "level 0 stores");
    let Ok(o) = Command::new("gzip")
        .args(["-6", "-c", "-n"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    else {
        return;
    };
    let mut o = o;
    use std::io::Write;
    o.stdin.take().unwrap().write_all(text).unwrap();
    let host = o.wait_with_output().unwrap().stdout.len() - 18;
    assert!(sizes[6] * 100 <= host * 103, "ours {} host {}", sizes[6], host);
}

/// Streaming: fed in odd pieces, read through a source that gives a few
/// bytes at a time, written to a sink.
#[test]
fn streaming() {
    struct Trickle<'a>(&'a [u8], usize);
    impl Source for Trickle<'_> {
        fn fill(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            let n = buf.len().min(7).min(self.0.len() - self.1);
            buf[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        }
    }
    for s in samples() {
        let mut w = GzipWriter::new(&Header::default(), 6);
        let mut z = std::vec::Vec::new();
        for piece in s.chunks(1000) {
            w.write(piece, &mut z);
        }
        w.finish(&mut z);
        let mut out = std::vec::Vec::new();
        let g = gunzip_stream(Trickle(&z, 0), &mut out).unwrap();
        assert_eq!(out, s);
        assert_eq!(g.size, s.len() as u64);
        assert_eq!(g.used, z.len() as u64);
    }
    // A long run of one byte and long-distance repeats cross the window.
    let mut big = std::vec::Vec::new();
    for i in 0..300_000u32 {
        big.push((i % 251) as u8 ^ (i / 70_000) as u8);
    }
    let z = deflate(&big);
    let mut out = std::vec::Vec::new();
    inflate_stream(Trickle(&z, 0), &mut out).unwrap();
    assert_eq!(out, big);
}
