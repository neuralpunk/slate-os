// SPDX-License-Identifier: MIT OR Apache-2.0

//! Word counting and a parallel checksum, the parts the tests cover.

use std::collections::BTreeMap;
use std::thread;

/// How often each word occurs (lowercased, split on non-letters).
pub fn word_counts(text: &str) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for w in text.split(|c: char| !c.is_alphabetic()).filter(|w| !w.is_empty()) {
        *m.entry(w.to_lowercase()).or_insert(0) += 1;
    }
    m
}

/// A checksum of `data` computed by `threads` threads over equal parts.
pub fn parallel_checksum(data: &[u8], threads: usize) -> u64 {
    let chunk = data.len().div_ceil(threads.max(1)).max(1);
    thread::scope(|s| {
        let handles: Vec<_> = data
            .chunks(chunk)
            .enumerate()
            .map(|(i, part)| {
                s.spawn(move || part.iter().map(|&b| u64::from(b)).sum::<u64>() * (i as u64 + 1))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).sum()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_words() {
        let m = word_counts("The slate, the chalk; THE end.");
        assert_eq!(m["the"], 3);
        assert_eq!(m["chalk"], 1);
        assert_eq!(m.len(), 4);
    }

    #[test]
    fn checksum_is_deterministic() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(parallel_checksum(&data, 4), parallel_checksum(&data, 4));
        assert_eq!(parallel_checksum(&[1, 2, 3], 1), 6);
    }
}
