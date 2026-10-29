// SPDX-License-Identifier: MIT OR Apache-2.0

//! Password hashing for /etc/shadow: SHA-512 crypt (`$6$`), as specified in
//! "Unix crypt using SHA-256 and SHA-512" (Ulrich Drepper, 2007, public
//! specification), the format shadow(5) files use.

use alloc::string::String;
use alloc::vec::Vec;

use crate::sums::sha512;

const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const DEFAULT_ROUNDS: u32 = 5000;

/// `len` bytes of `src` repeated.
fn repeat(src: &[u8], len: usize) -> Vec<u8> {
    src.iter().copied().cycle().take(len).collect()
}

/// The SHA-512 crypt of `password` with a setting like `$6$salt` or
/// `$6$rounds=N$salt` (anything after a third `$` is ignored). `None`
/// for other methods.
pub fn crypt(password: &[u8], setting: &[u8]) -> Option<String> {
    let rest = setting.strip_prefix(b"$6$")?;
    let (rounds, custom, rest) = match rest.strip_prefix(b"rounds=") {
        Some(r) => {
            let end = r.iter().position(|&c| c == b'$')?;
            let n: u64 = core::str::from_utf8(&r[..end]).ok()?.parse().ok()?;
            (n.clamp(1000, 999_999_999) as u32, true, &r[end + 1..])
        }
        None => (DEFAULT_ROUNDS, false, rest),
    };
    let salt_end = rest.iter().position(|&c| c == b'$').unwrap_or(rest.len()).min(16);
    let salt = &rest[..salt_end];
    let p = password;

    // Digest B: password, salt, password.
    let b = sha512(&[p, salt, p].concat());
    // Digest A.
    let mut a_in = Vec::new();
    a_in.extend_from_slice(p);
    a_in.extend_from_slice(salt);
    a_in.extend_from_slice(&repeat(&b, p.len()));
    let mut n = p.len();
    while n > 0 {
        if n & 1 == 1 {
            a_in.extend_from_slice(&b);
        } else {
            a_in.extend_from_slice(p);
        }
        n >>= 1;
    }
    let a = sha512(&a_in);
    // Digest DP: the password once per password byte; P is its prefix.
    let dp = sha512(&repeat(p, p.len() * p.len()));
    let pp = repeat(&dp, p.len());
    // Digest DS: the salt 16 + A[0] times; S is its prefix.
    let ds = sha512(&repeat(salt, salt.len() * (16 + a[0] as usize)));
    let sp = repeat(&ds, salt.len());
    // The rounds.
    let mut c = a;
    let mut buf = Vec::with_capacity(64 + 2 * p.len() + salt.len() + 64);
    for i in 0..rounds {
        buf.clear();
        if i & 1 == 1 {
            buf.extend_from_slice(&pp);
        } else {
            buf.extend_from_slice(&c);
        }
        if i % 3 != 0 {
            buf.extend_from_slice(&sp);
        }
        if i % 7 != 0 {
            buf.extend_from_slice(&pp);
        }
        if i & 1 == 1 {
            buf.extend_from_slice(&c);
        } else {
            buf.extend_from_slice(&pp);
        }
        c = sha512(&buf);
    }
    let mut out = String::from("$6$");
    if custom {
        out.push_str(&alloc::format!("rounds={rounds}$"));
    }
    out.push_str(&String::from_utf8_lossy(salt));
    out.push('$');
    // The byte order the specification lists for SHA-512.
    const ORDER: [(usize, usize, usize); 21] = [
        (0, 21, 42),
        (22, 43, 1),
        (44, 2, 23),
        (3, 24, 45),
        (25, 46, 4),
        (47, 5, 26),
        (6, 27, 48),
        (28, 49, 7),
        (50, 8, 29),
        (9, 30, 51),
        (31, 52, 10),
        (53, 11, 32),
        (12, 33, 54),
        (34, 55, 13),
        (56, 14, 35),
        (15, 36, 57),
        (37, 58, 16),
        (59, 17, 38),
        (18, 39, 60),
        (40, 61, 19),
        (62, 20, 41),
    ];
    let mut put = |b2: u8, b1: u8, b0: u8, n: usize| {
        let mut w = (u32::from(b2) << 16) | (u32::from(b1) << 8) | u32::from(b0);
        for _ in 0..n {
            out.push(B64[(w & 63) as usize] as char);
            w >>= 6;
        }
    };
    for (x, y, z) in ORDER {
        put(c[x], c[y], c[z], 4);
    }
    put(0, 0, c[63], 2);
    Some(out)
}

/// Check `password` against a shadow hash. Empty hashes accept only the
/// empty password; `!`/`*` hashes (locked) accept nothing.
pub fn verify(password: &[u8], hash: &[u8]) -> bool {
    if hash.is_empty() {
        return password.is_empty();
    }
    match crypt(password, hash) {
        // Compare without an early exit.
        Some(h) => h.len() == hash.len() && h.bytes().zip(hash).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0,
        None => false,
    }
}

/// A new `$6$` salt from 12 random bytes.
pub fn new_salt(random: &[u8; 12]) -> String {
    let mut s = String::from("$6$");
    for chunk in random.chunks(3) {
        let mut w = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        for _ in 0..4 {
            s.push(B64[(w & 63) as usize] as char);
            w >>= 6;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_vectors() {
        assert_eq!(
            crypt(b"Hello world!", b"$6$saltstring").unwrap(),
            "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
        );
        assert_eq!(
            crypt(b"Hello world!", b"$6$rounds=10000$saltstringsaltstring").unwrap(),
            "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."
        );
        let h = crypt(b"secret", b"$6$abcdefgh").unwrap();
        assert!(verify(b"secret", h.as_bytes()));
        assert!(!verify(b"Secret", h.as_bytes()));
        assert!(!verify(b"", b"!"));
        assert!(verify(b"", b""));
        assert_eq!(new_salt(&[0; 12]), "$6$................");
    }
}
