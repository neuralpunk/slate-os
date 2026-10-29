// SPDX-License-Identifier: MIT OR Apache-2.0

//! ACL data and L2CAP's basic frames on LE links (Core 5.4, Vol 4, Part
//! E, §5.4.2; Vol 3, Part A, §3.1), and the LE signalling channel's
//! connection parameter update (Vol 3, Part A, §4.20, §4.21) that devices
//! such as mice send (ADR 0176). LE links use fixed channels only here:
//! ATT (4), signalling (5) and SMP (6).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::*;

/// The LE signalling channel's CID (Vol 3, Part A, §2.1).
pub const CID_LE_SIGNALLING: u16 = 0x0005;

/// Packet boundary flags (Vol 4, Part E, §5.4.2): the first fragment of a
/// non-flushable packet (host to controller on LE), a continuing one, the
/// first of a flushable one (controller to host).
const PB_FIRST_NON_FLUSHABLE: u16 = 0b00;
const PB_CONTINUING: u16 = 0b01;
const PB_FIRST_FLUSHABLE: u16 = 0b10;

// LE signalling codes (Vol 3, Part A, §4).
pub const SIG_COMMAND_REJECT: u8 = 0x01;
pub const SIG_PARAM_UPDATE_REQUEST: u8 = 0x12;
pub const SIG_PARAM_UPDATE_RESPONSE: u8 = 0x13;

/// An L2CAP basic frame for channel `cid`, cut into ACL packets of at
/// most `max` bytes of data each (the controller's LE buffer size),
/// framed. `from_controller` marks the first one as a controller marks
/// it (the simulator).
pub fn acl_packets(handle: u16, cid: u16, payload: &[u8], max: usize, from_controller: bool) -> Vec<Vec<u8>> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    frame.extend_from_slice(&cid.to_le_bytes());
    frame.extend_from_slice(payload);
    let first = if from_controller { PB_FIRST_FLUSHABLE } else { PB_FIRST_NON_FLUSHABLE };
    frame
        .chunks(max.max(1))
        .enumerate()
        .map(|(i, chunk)| {
            let pb = if i == 0 { first } else { PB_CONTINUING };
            let mut p = alloc::vec![H4_ACL];
            p.extend_from_slice(&((handle & 0x0FFF) | (pb << 12)).to_le_bytes());
            p.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            p.extend_from_slice(chunk);
            p
        })
        .collect()
}

/// An ACL packet's connection handle and data, framed as /dev/hci0 has it.
pub fn parse_acl(p: &[u8]) -> Option<(u16, u16, &[u8])> {
    if p.len() < 5 || p[0] != H4_ACL {
        return None;
    }
    let hf = u16::from_le_bytes([p[1], p[2]]);
    let n = usize::from(u16::from_le_bytes([p[3], p[4]]));
    Some((hf & 0x0FFF, (hf >> 12) & 0b11, p.get(5..5 + n)?))
}

/// L2CAP frames put back together from ACL packets, per connection.
#[derive(Debug, Default)]
pub struct Reassembler {
    partial: BTreeMap<u16, Vec<u8>>,
}

impl Reassembler {
    /// Take an ACL packet: a whole frame's (handle, channel, payload) when
    /// it completes one. A frame that doesn't fit together is dropped.
    pub fn take(&mut self, packet: &[u8]) -> Option<(u16, u16, Vec<u8>)> {
        let (handle, pb, data) = parse_acl(packet)?;
        let buf = if pb == PB_CONTINUING {
            let b = self.partial.get_mut(&handle)?;
            b.extend_from_slice(data);
            b
        } else {
            self.partial.insert(handle, data.to_vec());
            self.partial.get_mut(&handle)?
        };
        if buf.len() < 4 {
            return None;
        }
        let len = usize::from(u16::from_le_bytes([buf[0], buf[1]]));
        match buf.len().cmp(&(len + 4)) {
            core::cmp::Ordering::Less => None,
            core::cmp::Ordering::Greater => {
                self.partial.remove(&handle);
                None
            }
            core::cmp::Ordering::Equal => {
                let b = self.partial.remove(&handle)?;
                Some((handle, u16::from_le_bytes([b[2], b[3]]), b[4..].to_vec()))
            }
        }
    }

    /// Connection `handle` closed.
    pub fn forget(&mut self, handle: u16) {
        self.partial.remove(&handle);
    }
}

/// What a device asked of the central on the signalling channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// A Connection Parameter Update Request: interval min and max,
    /// latency, supervision timeout; and the reply to send.
    ParamUpdate { min: u16, max: u16, latency: u16, timeout: u16, reply: Vec<u8> },
    /// Something else: the Command Reject to send (or nothing, for a
    /// response or reject).
    Other(Option<Vec<u8>>),
}

/// A command on the LE signalling channel, from the peripheral.
pub fn signal(payload: &[u8]) -> Signal {
    let (Some(&code), Some(&id)) = (payload.first(), payload.get(1)) else { return Signal::Other(None) };
    let field = |i: usize| payload.get(4 + 2 * i..6 + 2 * i).map(|b| u16::from_le_bytes([b[0], b[1]]));
    match code {
        SIG_PARAM_UPDATE_REQUEST => {
            let (Some(min), Some(max), Some(latency), Some(timeout)) = (field(0), field(1), field(2), field(3)) else {
                return Signal::Other(None);
            };
            // Accepted (result 0) when they make sense (§4.20: intervals
            // 7.5 ms to 4 s, the timeout longer than an interval with its
            // latency); else rejected (1).
            let ok = (6..=3200).contains(&min)
                && (min..=3200).contains(&max)
                && latency < 500
                && (10..=3200).contains(&timeout)
                && u32::from(timeout) * 4 > (1 + u32::from(latency)) * u32::from(max);
            let reply = alloc::vec![SIG_PARAM_UPDATE_RESPONSE, id, 2, 0, u8::from(!ok), 0];
            if ok { Signal::ParamUpdate { min, max, latency, timeout, reply } } else { Signal::Other(Some(reply)) }
        }
        // Responses, rejects and credits need nothing back (§4: Command
        // Reject, Disconnection Response, the update's response, the
        // credit-based connections' responses, Flow Control Credit).
        0x01 | 0x07 | 0x13 | 0x15 | 0x16 | 0x18 | 0x1A => Signal::Other(None),
        // Command not understood (reason 0).
        _ => Signal::Other(Some(alloc::vec![SIG_COMMAND_REJECT, id, 2, 0, 0, 0])),
    }
}

/// A Connection Parameter Update Request (the simulated devices ask).
pub fn param_update_request(id: u8, min: u16, max: u16, latency: u16, timeout: u16) -> Vec<u8> {
    let mut p = alloc::vec![SIG_PARAM_UPDATE_REQUEST, id, 8, 0];
    for v in [min, max, latency, timeout] {
        p.extend_from_slice(&v.to_le_bytes());
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_and_frames() {
        let payload: Vec<u8> = (0..60).collect();
        let packets = acl_packets(0x40, 4, &payload, 27, true);
        assert_eq!(packets.len(), 3);
        let mut r = Reassembler::default();
        assert_eq!(r.take(&packets[0]), None);
        assert_eq!(r.take(&packets[1]), None);
        assert_eq!(r.take(&packets[2]), Some((0x40, 4, payload.clone())));
        // A continuation with no start is dropped; so is a frame that runs
        // past its length.
        assert_eq!(r.take(&packets[1]), None);
        let mut long = acl_packets(0x40, 4, &[1, 2], 27, false)[0].clone();
        long.push(9);
        long[3] += 1;
        assert_eq!(r.take(&long), None);
        assert_eq!(parse_acl(&packets[0]).map(|p| (p.0, p.1)), Some((0x40, PB_FIRST_FLUSHABLE)));
    }

    #[test]
    fn parameter_updates() {
        let req = param_update_request(7, 6, 9, 44, 216);
        let Signal::ParamUpdate { min, max, latency, timeout, reply } = signal(&req) else { panic!() };
        assert_eq!((min, max, latency, timeout), (6, 9, 44, 216));
        assert_eq!(reply, [SIG_PARAM_UPDATE_RESPONSE, 7, 2, 0, 0, 0]);
        // A timeout shorter than the interval allows: rejected.
        assert_eq!(
            signal(&param_update_request(8, 100, 200, 4, 50)),
            Signal::Other(Some(alloc::vec![0x13, 8, 2, 0, 1, 0]))
        );
        // An unknown command: rejected; a response: nothing.
        assert_eq!(signal(&[0x40, 3, 0, 0]), Signal::Other(Some(alloc::vec![SIG_COMMAND_REJECT, 3, 2, 0, 0, 0])));
        assert_eq!(signal(&[SIG_PARAM_UPDATE_RESPONSE, 3, 2, 0, 0, 0]), Signal::Other(None));
    }
}
