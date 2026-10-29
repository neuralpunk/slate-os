// SPDX-License-Identifier: MIT OR Apache-2.0

//! Resource templates (§6.4): what `_CRS` and `_PRS` return. Only the
//! interrupt descriptors so far, for interrupt link devices (§6.2.16).

use alloc::vec::Vec;

/// One interrupt a template names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interrupt {
    /// The IRQ (IRQ descriptor) or GSI (Extended Interrupt descriptor).
    pub number: u32,
    pub level: bool,
    pub active_low: bool,
}

/// The descriptors of a template, as (tag, whole descriptor), up to the
/// end tag.
fn descriptors(b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let tag = b[i];
        let (name, total) = if tag & 0x80 == 0 {
            ((tag >> 3) & 0xF, 1 + usize::from(tag & 7))
        } else {
            let Some(len) = b.get(i + 1..i + 3) else { break };
            (tag & 0x7F | 0x80, 3 + usize::from(u16::from_le_bytes([len[0], len[1]])))
        };
        if name == 0xF {
            break;
        }
        let Some(d) = b.get(i..i + total) else { break };
        out.push((name, d));
        i += total;
    }
    out
}

/// Small IRQ descriptor (§6.4.2.1) and large Extended Interrupt
/// descriptor (§6.4.3.6), by the names `descriptors` gives them.
const IRQ: u8 = 0x4;
const EXTENDED_INTERRUPT: u8 = 0x89;

/// Every interrupt in a template: the IRQ descriptor's mask (edge and
/// active high when it has no information byte; else bit 0 edge, bit 3
/// active low) and the Extended Interrupt descriptor's list (flags bit 1
/// edge, bit 2 active low).
pub fn interrupts(b: &[u8]) -> Vec<Interrupt> {
    let mut out = Vec::new();
    for (name, d) in descriptors(b) {
        match name {
            IRQ if d.len() >= 3 => {
                let mask = u16::from_le_bytes([d[1], d[2]]);
                let flags = d.get(3).copied().unwrap_or(1);
                for bit in (0..16).filter(|k| mask & (1 << k) != 0) {
                    out.push(Interrupt { number: bit, level: flags & 1 == 0, active_low: flags & 8 != 0 });
                }
            }
            EXTENDED_INTERRUPT if d.len() >= 5 => {
                let (flags, count) = (d[3], usize::from(d[4]));
                for k in 0..count {
                    let Some(v) = d.get(5 + 4 * k..9 + 4 * k) else { break };
                    out.push(Interrupt {
                        number: u32::from_le_bytes(v.try_into().unwrap()),
                        level: flags & 2 == 0,
                        active_low: flags & 4 != 0,
                    });
                }
            }
            _ => {}
        }
    }
    out
}

/// The first interrupt descriptor of a template (`_PRS`), cut down to its
/// first interrupt, for `_SRS` (without the end tag).
pub fn first_interrupt(b: &[u8]) -> Option<Vec<u8>> {
    for (name, d) in descriptors(b) {
        match name {
            IRQ if d.len() >= 3 => {
                let mask = u16::from_le_bytes([d[1], d[2]]);
                let bit = (0..16).find(|&k| mask & (1 << k) != 0)?;
                let mut v = d.to_vec();
                v[1..3].copy_from_slice(&(1u16 << bit).to_le_bytes());
                return Some(v);
            }
            EXTENDED_INTERRUPT if d.len() >= 9 && d[4] >= 1 => {
                let mut v = d[..9].to_vec();
                v[1..3].copy_from_slice(&6u16.to_le_bytes());
                v[4] = 1;
                return Some(v);
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn irq_descriptors() {
        // IRQNoFlags() {5, 10, 11}: edge, active high.
        assert_eq!(
            interrupts(&[0x22, 0x20, 0x0C, 0x79, 0x00]),
            alloc::vec![
                Interrupt { number: 5, level: false, active_low: false },
                Interrupt { number: 10, level: false, active_low: false },
                Interrupt { number: 11, level: false, active_low: false },
            ]
        );
        // IRQ (Level, ActiveLow, Shared) {9}: information byte 0x18.
        assert_eq!(
            interrupts(&[0x23, 0x00, 0x02, 0x18, 0x79, 0x00]),
            alloc::vec![Interrupt { number: 9, level: true, active_low: true }]
        );
        assert_eq!(first_interrupt(&[0x23, 0x20, 0x0C, 0x18, 0x79, 0x00]), Some(alloc::vec![0x23, 0x20, 0x00, 0x18]));
    }

    #[test]
    fn extended_interrupt_descriptors() {
        // Interrupt (ResourceConsumer, Level, ActiveHigh, Shared) {16, 17}:
        // flags 0x09 (consumer, shared).
        let t = [0x89, 0x0A, 0x00, 0x09, 2, 16, 0, 0, 0, 17, 0, 0, 0, 0x79, 0x00];
        assert_eq!(
            interrupts(&t),
            alloc::vec![
                Interrupt { number: 16, level: true, active_low: false },
                Interrupt { number: 17, level: true, active_low: false },
            ]
        );
        assert_eq!(first_interrupt(&t), Some(alloc::vec![0x89, 0x06, 0x00, 0x09, 1, 16, 0, 0, 0]));
        assert!(interrupts(&[0x79, 0x00]).is_empty());
    }
}
