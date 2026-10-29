// SPDX-License-Identifier: MIT OR Apache-2.0

//! IPv4 fragmentation and reassembly (RFC 791 §2.3, §3.2; the hole
//! bookkeeping of RFC 815 kept as a map of pieces): datagrams bigger than
//! the link are sent in pieces when they may be fragmented, and pieces
//! that arrive for the host are put back together within 30 seconds.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{IfIndex, Stack};
use crate::wire::*;

/// How long pieces wait (RFC 1122 §3.3.2 suggests 60 s to 120 s at most;
/// 30 s is what most hosts use) and how much they may take altogether.
const REASSEMBLY_MS: u64 = 30_000;
const REASSEMBLY_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub(super) struct Reassembly4 {
    /// The first piece's header (options included), and the interface the
    /// pieces came in on.
    header: Option<Vec<u8>>,
    iface: IfIndex,
    pieces: BTreeMap<usize, Vec<u8>>,
    total: Option<usize>,
    bytes: usize,
    pub(super) deadline: u64,
}

/// Split an IPv4 packet (or a piece of one) into pieces that fit `mtu`:
/// data in multiples of eight bytes, offsets counted from the packet's
/// own, More Fragments on all but the last (which keeps the packet's).
/// Pieces after the first carry only the options marked to be copied
/// (the kind's high bit: source routes, security; RFC 791 §3.1).
pub(super) fn fragment4(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let first_hl = usize::from(packet[0] & 0xF) * 4;
    let data = &packet[first_hl..];
    let frag = get16(packet, 6);
    let base = usize::from(frag & 0x1FFF) * 8;
    let last_more = frag & 0x2000;
    let mut later = packet[..IP_HEADER].to_vec();
    let field = &packet[IP_HEADER..first_hl];
    for o in ipv4_options(field).unwrap_or_default().iter().filter(|o| o.kind & 0x80 != 0) {
        later.extend_from_slice(&field[o.at..o.at + o.len]);
    }
    later.resize(later.len().next_multiple_of(4), IPOPT_END);
    later[0] = 0x40 | (later.len() / 4) as u8;
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let header = if at == 0 && base == 0 { &packet[..first_hl] } else { &later[..] };
        let hl = header.len();
        let room = (mtu - hl) / 8 * 8;
        let end = (at + room).min(data.len());
        let mut f = Vec::with_capacity(hl + end - at);
        f.extend_from_slice(header);
        f.extend_from_slice(&data[at..end]);
        put16(&mut f, 2, (hl + end - at) as u16);
        let more = if end < data.len() { 0x2000 } else { last_more };
        put16(&mut f, 6, more | ((base + at) / 8) as u16);
        f[10..12].fill(0);
        let c = checksum(&f[..hl]);
        put16(&mut f, 10, c);
        out.push(f);
        at = end;
    }
    out
}

impl Stack {
    /// Add a piece; the whole packet (header from the first piece, no
    /// fragment fields) once all are in.
    pub(super) fn reassemble4(&mut self, iface: IfIndex, h: &Ipv4Header, packet: &[u8]) -> Option<Vec<u8>> {
        let frag = get16(packet, 6);
        let offset = usize::from(frag & 0x1FFF) * 8;
        let more = frag & 0x2000 != 0;
        let data = &packet[h.header_len..];
        if more && data.len() % 8 != 0 {
            return None;
        }
        let key = (h.src, h.dst, h.proto, h.id);
        let pending: usize = self.reassembly4.values().map(|r| r.bytes).sum();
        if pending + data.len() > REASSEMBLY_BYTES && !self.reassembly4.contains_key(&key) {
            return None;
        }
        let now = self.now;
        let r = self.reassembly4.entry(key).or_insert_with(|| Reassembly4 {
            header: None,
            iface,
            pieces: BTreeMap::new(),
            total: None,
            bytes: 0,
            deadline: now + REASSEMBLY_MS,
        });
        if offset == 0 {
            r.header = Some(packet[..h.header_len].to_vec());
        }
        if !more {
            r.total = Some(offset + data.len());
        }
        if r.pieces.insert(offset, data.to_vec()).is_none() {
            r.bytes += data.len();
        }
        let total = r.total?;
        r.header.as_ref()?;
        let mut have = 0;
        for (o, d) in &r.pieces {
            if *o > have {
                return None;
            }
            have = have.max(o + d.len());
        }
        let mut header = r.header.clone()?;
        if have < total || header.len() + total > usize::from(u16::MAX) {
            return None;
        }
        let r = self.reassembly4.remove(&key)?;
        let hl = header.len();
        let mut p = alloc::vec![0u8; hl + total];
        for (o, d) in r.pieces {
            let end = (o + d.len()).min(total);
            p[hl + o..hl + end].copy_from_slice(&d[..end - o]);
        }
        put16(&mut header, 2, (hl + total) as u16);
        put16(&mut header, 6, 0);
        header[10..12].fill(0);
        let c = checksum(&header);
        put16(&mut header, 10, c);
        p[..hl].copy_from_slice(&header);
        Some(p)
    }

    /// Drop what waited too long; when the first piece had come, tell the
    /// sender (time exceeded in reassembly, RFC 792, RFC 1122 §3.3.2),
    /// quoting that piece.
    pub(super) fn expire_reassembly4(&mut self, now: u64) {
        let late: Vec<_> = self.reassembly4.iter().filter(|(_, r)| r.deadline <= now).map(|(k, _)| *k).collect();
        for k in late {
            let Some(r) = self.reassembly4.remove(&k) else { continue };
            let (Some(header), Some(first)) = (r.header, r.pieces.get(&0)) else { continue };
            let mut quoted = header;
            quoted.extend_from_slice(&first[..first.len().min(8)]);
            if let Some(h) = Ipv4Header::parse_unchecked(&quoted) {
                self.icmp_error(r.iface, &h, &quoted, ICMP_TIME_EXCEEDED, ICMP_REASSEMBLY_TIMEOUT, [0; 4]);
            }
        }
    }
}
