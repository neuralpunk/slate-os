// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the terminal has yet to write to the program (ADR 0099): keys,
//! pastes and replies, in order. The pseudo-terminal is non-blocking, so
//! a long paste into a program that doesn't read waits here while the
//! window keeps drawing; it is written as the program takes it.

use alloc::collections::VecDeque;

use slate_rt::Errno;

/// The most kept waiting; more is dropped (a program that never reads
/// must not make the terminal grow without end).
pub const LIMIT: usize = 4 << 20;

#[derive(Debug, Default)]
pub struct Outbox {
    pending: VecDeque<u8>,
    /// Bytes dropped at the limit, ever.
    pub dropped: usize,
}

impl Outbox {
    pub fn push(&mut self, bytes: &[u8]) {
        let room = LIMIT.saturating_sub(self.pending.len());
        self.pending.extend(&bytes[..bytes.len().min(room)]);
        self.dropped += bytes.len().saturating_sub(room);
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Write what `write` takes; stops when it would block. An error other
    /// than EAGAIN (or EINTR, retried) is returned, the bytes kept.
    pub fn flush(&mut self, mut write: impl FnMut(&[u8]) -> Result<usize, Errno>) -> Result<(), Errno> {
        while !self.pending.is_empty() {
            let (front, _) = self.pending.as_slices();
            match write(front) {
                Ok(0) | Err(Errno::EAGAIN) => break,
                Ok(n) => {
                    self.pending.drain(..n);
                }
                Err(Errno::EINTR) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn writes_what_is_taken_in_order() {
        let mut o = Outbox::default();
        o.push(b"paste ");
        o.push(b"then a key");
        // The program takes four bytes, then would block.
        let mut got = Vec::new();
        let mut room = 4;
        o.flush(|b| {
            if room == 0 {
                return Err(Errno::EAGAIN);
            }
            let n = b.len().min(room);
            room -= n;
            got.extend_from_slice(&b[..n]);
            Ok(n)
        })
        .unwrap();
        assert_eq!(got, b"past");
        assert!(!o.is_empty());
        o.flush(|b| {
            got.extend_from_slice(b);
            Ok(b.len())
        })
        .unwrap();
        assert_eq!(got, b"paste then a key");
        assert!(o.is_empty());
        // Other errors are returned; the bytes stay.
        o.push(b"x");
        assert_eq!(o.flush(|_| Err(Errno::EIO)), Err(Errno::EIO));
        assert!(!o.is_empty());
    }

    #[test]
    fn a_limit() {
        let mut o = Outbox::default();
        o.push(&std::vec![0u8; LIMIT - 1]);
        o.push(b"ab");
        assert_eq!(o.dropped, 1);
    }
}
