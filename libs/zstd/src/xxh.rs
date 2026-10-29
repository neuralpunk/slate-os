// SPDX-License-Identifier: MIT OR Apache-2.0

//! XXH64 (as RFC 8878 §2.1.1 refers to it; the algorithm's published
//! description), fed in pieces.

const P1: u64 = 11_400_714_785_074_694_791;
const P2: u64 = 14_029_467_366_897_019_727;
const P3: u64 = 1_609_587_929_392_839_161;
const P4: u64 = 9_650_029_242_287_828_579;
const P5: u64 = 2_870_177_450_012_600_261;

fn round(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1)
}

fn merge(acc: u64, v: u64) -> u64 {
    (acc ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4)
}

fn lane(d: &[u8]) -> u64 {
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
}

#[derive(Clone, Debug)]
pub struct Xxh64 {
    v: [u64; 4],
    buf: [u8; 32],
    buffered: usize,
    total: u64,
    seed: u64,
}

impl Xxh64 {
    pub fn new(seed: u64) -> Xxh64 {
        Xxh64 {
            v: [seed.wrapping_add(P1).wrapping_add(P2), seed.wrapping_add(P2), seed, seed.wrapping_sub(P1)],
            buf: [0; 32],
            buffered: 0,
            total: 0,
            seed,
        }
    }

    fn stripe(&mut self, d: &[u8]) {
        for (k, v) in self.v.iter_mut().enumerate() {
            *v = round(*v, lane(&d[k * 8..]));
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total += data.len() as u64;
        if self.buffered > 0 {
            let n = (32 - self.buffered).min(data.len());
            self.buf[self.buffered..self.buffered + n].copy_from_slice(&data[..n]);
            self.buffered += n;
            data = &data[n..];
            if self.buffered < 32 {
                return;
            }
            let b = self.buf;
            self.stripe(&b);
            self.buffered = 0;
        }
        while data.len() >= 32 {
            self.stripe(&data[..32]);
            data = &data[32..];
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buffered = data.len();
    }

    pub fn finish(&self) -> u64 {
        let mut h = if self.total >= 32 {
            let [a, b, c, d] = self.v;
            let mut h = a
                .rotate_left(1)
                .wrapping_add(b.rotate_left(7))
                .wrapping_add(c.rotate_left(12))
                .wrapping_add(d.rotate_left(18));
            for v in self.v {
                h = merge(h, v);
            }
            h
        } else {
            self.seed.wrapping_add(P5)
        };
        h = h.wrapping_add(self.total);
        let mut rest = &self.buf[..self.buffered];
        while rest.len() >= 8 {
            h ^= round(0, lane(rest));
            h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
            rest = &rest[8..];
        }
        if rest.len() >= 4 {
            h ^= u64::from(u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]])).wrapping_mul(P1);
            h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
            rest = &rest[4..];
        }
        for &b in rest {
            h ^= u64::from(b).wrapping_mul(P5);
            h = h.rotate_left(11).wrapping_mul(P1);
        }
        h ^= h >> 33;
        h = h.wrapping_mul(P2);
        h ^= h >> 29;
        h = h.wrapping_mul(P3);
        h ^ (h >> 32)
    }
}

pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut x = Xxh64::new(seed);
    x.update(data);
    x.finish()
}
