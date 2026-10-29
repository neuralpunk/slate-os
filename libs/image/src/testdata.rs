// SPDX-License-Identifier: MIT OR Apache-2.0

//! The test images in tests/fixtures: synthetic pictures made with
//! ImageMagick by tests/fixtures/make.sh, each beside `NAME.rgba`,
//! ImageMagick's reading of it as 8-bit RGBA, to compare with ours.

use std::format;
use std::string::String;
use std::vec::Vec;

use crate::{Error, Image};

fn dir() -> String {
    format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
}

pub fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/{name}", dir())).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The fixtures with extension `ext`, by name.
pub fn fixtures(ext: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(&format!(".{ext}")))
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no .{ext} fixtures");
    v
}

/// Decode `name` and compare with ImageMagick's pixels: no channel
/// further than `tolerance` from it, and on average within a quarter of
/// that (decoders may round an IDCT differently, never draw differently).
pub fn check(name: &str, decode: fn(&[u8]) -> Result<Image, Error>, tolerance: u8) {
    let img = decode(&load(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let want = load(&format!("{name}.rgba"));
    assert_eq!(img.pixels.len() * 4, want.len(), "{name}: {}x{} pixels", img.width, img.height);
    let (mut worst, mut total) = (0u8, 0u64);
    for (i, (p, w)) in img.pixels.iter().zip(want.as_chunks::<4>().0).enumerate() {
        let got = [(p >> 16) as u8, (p >> 8) as u8, *p as u8, (p >> 24) as u8];
        // Fully transparent pixels have no colour to compare.
        let n = if got[3] == 0 && w[3] == 0 { 0 } else { 4 };
        for k in 0..n {
            let d = got[k].abs_diff(w[k]);
            total += u64::from(d);
            if d > worst {
                worst = d;
                assert!(
                    d <= tolerance,
                    "{name}: pixel {i} ({}, {}) channel {k}: {} for {}",
                    i % img.width as usize,
                    i / img.width as usize,
                    got[k],
                    w[k]
                );
            }
        }
    }
    let mean = total as f64 / want.len() as f64;
    assert!(mean <= f64::from(tolerance) / 4.0 + 0.01, "{name}: mean difference {mean:.3}");
}

/// Every prefix of `name` (and some damaged copies) reads as an error or
/// an image, never a panic.
pub fn truncations(name: &str, decode: fn(&[u8]) -> Result<Image, Error>) {
    let data = load(name);
    let step = (data.len() / 400).max(1);
    for n in (0..data.len()).step_by(step) {
        let _ = decode(&data[..n]);
    }
    let mut x = 0x2545_F491u32;
    for _ in 0..200 {
        let mut d = data.clone();
        for _ in 0..4 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let at = x as usize % d.len();
            d[at] ^= (x >> 8) as u8 | 1;
        }
        let _ = decode(&d);
    }
}
