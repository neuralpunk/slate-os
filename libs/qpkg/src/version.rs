// SPDX-License-Identifier: MIT OR Apache-2.0

//! Version comparison (ADR 0025): runs of digits compare as numbers, other
//! runs as bytes, and a `-release` suffix compares after the rest.

use core::cmp::Ordering;

/// Compare two versions such as `1.10.2-3`.
pub fn compare(a: &str, b: &str) -> Ordering {
    let (av, ar) = a.rsplit_once('-').unwrap_or((a, ""));
    let (bv, br) = b.rsplit_once('-').unwrap_or((b, ""));
    compare_part(av, bv).then_with(|| compare_part(ar, br))
}

fn compare_part(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
    loop {
        match (a.is_empty(), b.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            _ => {}
        }
        let (ra, rest_a) = run(a);
        let (rb, rest_b) = run(b);
        let digits = |r: &[u8]| r.first().is_some_and(u8::is_ascii_digit);
        let o = match (digits(ra), digits(rb)) {
            (true, true) => {
                let strip = |r: &'_ [u8]| -> usize { r.iter().take_while(|&&c| c == b'0').count() };
                let (ta, tb) = (&ra[strip(ra)..], &rb[strip(rb)..]);
                ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb))
            }
            // A number sorts after a non-number run ("1.0" < "1.0a" < "1.01b").
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => ra.cmp(rb),
        };
        if o != Ordering::Equal {
            return o;
        }
        a = rest_a;
        b = rest_b;
    }
}

/// The leading run of digits or of non-digits.
fn run(s: &[u8]) -> (&[u8], &[u8]) {
    let digit = s[0].is_ascii_digit();
    let n = s.iter().take_while(|c| c.is_ascii_digit() == digit).count();
    s.split_at(n)
}

/// A dependency's version requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Any,
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

impl Op {
    pub fn allows(self, have: &str, want: &str) -> bool {
        let o = compare(have, want);
        match self {
            Op::Any => true,
            Op::Ge => o != Ordering::Less,
            Op::Gt => o == Ordering::Greater,
            Op::Le => o != Ordering::Greater,
            Op::Lt => o == Ordering::Less,
            Op::Eq => o == Ordering::Equal,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Op::Any => "",
            Op::Ge => ">=",
            Op::Gt => ">>",
            Op::Le => "<=",
            Op::Lt => "<<",
            Op::Eq => "=",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_versions() {
        let ordered = ["0.9", "1.0", "1.0-1", "1.0-2", "1.0.1", "1.2", "1.9", "1.10", "2", "10"];
        for w in ordered.windows(2) {
            assert_eq!(compare(w[0], w[1]), Ordering::Less, "{} < {}", w[0], w[1]);
            assert_eq!(compare(w[1], w[0]), Ordering::Greater, "{} > {}", w[1], w[0]);
        }
        assert_eq!(compare("1.01", "1.1"), Ordering::Equal);
        assert!(Op::Ge.allows("1.10", "1.9") && !Op::Lt.allows("2", "1.9") && Op::Eq.allows("1.0-1", "1.0-1"));
    }
}
