// SPDX-License-Identifier: MIT OR Apache-2.0

//! TCP (RFC 9293), with retransmission timing from RFC 6298, congestion
//! control (slow start, congestion avoidance, fast retransmit) from RFC
//! 5681, the MSS and window scale options (RFC 9293 §3.7.1, RFC 7323 §2),
//! RST/SYN hardening from RFC 5961 §3-4, and (ADR 0051) timestamps with
//! PAWS (RFC 7323 §3-5), selective acknowledgments (RFC 2018), delayed
//! ACKs (RFC 9293 §3.8.6.3), Nagle's algorithm (RFC 896, RFC 1122
//! §4.2.3.4) and keep-alives (RFC 1122 §4.2.3.6).
//!
//! Each connection is a [`Tcb`] in the stack's TCP table. Sockets the
//! owner has closed stay there ("orphans") until their FIN exchange and
//! TIME-WAIT finish.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use super::{Endpoint, Error, Handle, IfIndex, IpOptions, OptionField, Result, Stack};
use crate::wire::*;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const TCP_HEADER: usize = 20;
/// Bytes buffered for sending and for receiving, per connection.
const SEND_BUFFER: usize = 256 * 1024;
const RECV_BUFFER: usize = 256 * 1024;
/// Our window scale shift: RECV_BUFFER >> 3 fits the 16-bit field.
const OUR_WSCALE: u8 = 3;
const DEFAULT_MSS: usize = 536;
/// Segment size for connections to our own addresses.
const LOOPBACK_MSS: usize = 32 * 1024;
const RTO_MIN_MS: u64 = 200;
const RTO_MAX_MS: u64 = 60_000;
const RTO_INITIAL_MS: u64 = 1000;
const SYN_RETRIES: u32 = 6;
const DATA_RETRIES: u32 = 15;
const TIME_WAIT_MS: u64 = 30_000;
const FIN_WAIT2_MS: u64 = 60_000;
/// Out-of-order bytes kept per connection.
const OOO_LIMIT: usize = 256 * 1024;
/// An emptied buffer that grew past this gives its memory back.
const SHRINK_ABOVE: usize = 16 * 1024;
/// A delayed ACK waits at most this long (RFC 9293 §3.8.6.3 allows 500 ms;
/// a short wait keeps request-response traffic quick).
const DELACK_MS: u64 = 40;
/// Keep-alive defaults (RFC 1122 §4.2.3.6: idle at least two hours; the
/// interval and count tcp(7) documents).
const KEEP_IDLE_MS: u64 = 7200 * 1000;
const KEEP_INTVL_MS: u64 = 75 * 1000;
const KEEP_CNT: u32 = 9;
/// The timestamp option with its two NOPs, in every segment once agreed.
const TS_OPTION: usize = 12;
/// Option kinds (RFC 9293 §3.2, RFC 2018 §2-3, RFC 7323 §3).
const OPT_SACK_PERMITTED: u8 = 4;
const OPT_SACK: u8 = 5;
const OPT_TIMESTAMPS: u8 = 8;

/// TCP options a socket sets (tcp(7), socket(7)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpOptions {
    pub nodelay: bool,
    pub cork: bool,
    pub keepalive: bool,
    /// Keep-alive idle time and interval (seconds), and probe count.
    pub keep_idle: u32,
    pub keep_intvl: u32,
    pub keep_cnt: u32,
    /// TCP_MAXSEG (tcp(7)): a cap on the MSS, taken when the connection
    /// is made (a listener passes it to what it accepts).
    pub max_seg: Option<u16>,
    /// IP_TOS (ip(7)) for the connection's IPv4 packets.
    pub tos: u8,
    /// IP_OPTIONS (ip(7)): the option field its IPv4 packets carry, taken
    /// out of the segment size.
    pub ip_options: OptionField,
}

/// What an ICMP error about one of a connection's segments does to it.
pub(super) enum IcmpEffect {
    /// Ends an attempt to connect at once; an established connection
    /// keeps it as a soft error (RFC 5927 §4.1: hard errors are soft in
    /// synchronized states).
    Fatal(Error),
    /// Reported if the connection later times out, instead of ETIMEDOUT
    /// (RFC 1122 §4.2.3.9).
    Soft(Error),
    /// The path's MTU fell (it is already learned): smaller segments.
    Mtu,
}

/// What TCP_INFO reports (tcp(7)).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpInfo {
    pub rto_ms: u64,
    pub rtt_ms: u64,
    pub rttvar_ms: u64,
    pub mss: usize,
    pub cwnd: usize,
    pub ssthresh: usize,
    pub unacked: usize,
    pub retransmits: u32,
    pub sack: bool,
    pub timestamps: bool,
    pub snd_wscale: u8,
    pub rcv_wscale: u8,
    pub snd_wnd: u32,
}

/// Give back an empty buffer's memory if it grew large.
fn shrink_if_empty(b: &mut VecDeque<u8>) {
    if b.is_empty() && b.capacity() > SHRINK_ABOVE {
        *b = VecDeque::new();
    }
}

fn lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
fn le(a: u32, b: u32) -> bool {
    !lt(b, a)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// Readiness of a TCP socket, for poll(2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub readable: bool,
    pub writable: bool,
    /// Both directions are finished (or the connection was reset).
    pub hangup: bool,
    /// The peer finished sending (POLLRDHUP).
    pub read_hangup: bool,
    pub error: bool,
}

#[derive(Debug)]
pub struct Tcb {
    state: State,
    local: Option<Endpoint>,
    remote: Option<Endpoint>,
    /// An AF_INET6 socket, and IPV6_V6ONLY.
    v6: bool,
    v6only: bool,
    // Send side: `send` holds bytes from snd_una on.
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    /// Highest sequence number sent: retransmission rewinds `snd_nxt`, and
    /// ACKs up to here are still valid.
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    send: VecDeque<u8>,
    /// The user shut down writing: a FIN follows the data.
    fin_queued: bool,
    fin_sent: bool,
    /// Where our FIN is in sequence space, once sent.
    fin_seq: Option<u32>,
    // Receive side.
    irs: u32,
    rcv_nxt: u32,
    recv: VecDeque<u8>,
    ooo: BTreeMap<u32, Vec<u8>>,
    ooo_bytes: usize,
    /// Sequence number of a FIN seen ahead of missing data.
    ooo_fin: Option<u32>,
    fin_received: bool,
    read_shutdown: bool,
    // Options.
    mss: usize,
    /// TCP_MAXSEG, and the IPv4 header settings (IP_TOS).
    max_seg: Option<u16>,
    ip: IpOptions,
    snd_wscale: u8,
    rcv_wscale: u8,
    // Timers and congestion control.
    rto: u64,
    srtt: Option<u64>,
    rttvar: u64,
    rtx_deadline: Option<u64>,
    retries: u32,
    timing: Option<(u32, u64)>,
    cwnd: usize,
    ssthresh: usize,
    dup_acks: u32,
    deadline: Option<u64>,
    // Listening sockets.
    backlog: usize,
    accept_queue: VecDeque<Handle>,
    parent: Option<Handle>,
    error: Option<Error>,
    /// The last soft ICMP error, given instead of ETIMEDOUT on a timeout.
    soft_error: Option<Error>,
    /// The owner closed this socket; the stack frees it when done.
    orphan: bool,
    // Socket options.
    nodelay: bool,
    cork: bool,
    /// TCP_QUICKACK: the next ACK goes at once.
    quickack: bool,
    keepalive: bool,
    keep_idle: u64,
    keep_intvl: u64,
    keep_cnt: u32,
    /// Keep-alive probes sent since the peer was last heard, and when.
    keep_sent: u32,
    last_heard: u64,
    /// Segments received and not yet acknowledged, and when the delayed
    /// ACK is due.
    ack_pending: u32,
    delack: Option<u64>,
    /// A segment carrying an ACK went out (since this was last cleared).
    acked: bool,
    // Agreed options.
    sack_ok: bool,
    ts_ok: bool,
    /// Added to our clock for TSval (RFC 7323 §5.4: random per connection).
    ts_offset: u32,
    /// TS.Recent and the last ACK sent (RFC 7323 §4.3).
    ts_recent: u32,
    last_ack_sent: u32,
    /// What the peer reported received beyond snd_una (SACK blocks).
    sacked: Vec<(u32, u32)>,
    /// Where the most recent out-of-order segment starts (its block goes
    /// first, RFC 2018 §4).
    last_ooo: Option<u32>,
    /// SO_BINDTODEVICE.
    device: Option<IfIndex>,
}

impl Tcb {
    /// The owner is gone: nothing will read what arrives (the connection
    /// only finishes its FIN exchange), so its receive memory goes.
    fn release_receive(&mut self) {
        self.recv = VecDeque::new();
        self.ooo.clear();
        self.ooo_bytes = 0;
    }

    fn new() -> Tcb {
        Tcb {
            state: State::Closed,
            local: None,
            remote: None,
            v6: false,
            v6only: false,
            iss: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_max: 0,
            snd_wnd: 0,
            snd_wl1: 0,
            snd_wl2: 0,
            send: VecDeque::new(),
            fin_queued: false,
            fin_sent: false,
            fin_seq: None,
            irs: 0,
            rcv_nxt: 0,
            recv: VecDeque::new(),
            ooo: BTreeMap::new(),
            ooo_bytes: 0,
            ooo_fin: None,
            fin_received: false,
            read_shutdown: false,
            mss: DEFAULT_MSS,
            max_seg: None,
            ip: IpOptions::default(),
            snd_wscale: 0,
            rcv_wscale: 0,
            rto: RTO_INITIAL_MS,
            srtt: None,
            rttvar: 0,
            rtx_deadline: None,
            retries: 0,
            timing: None,
            cwnd: 0,
            ssthresh: usize::MAX,
            dup_acks: 0,
            deadline: None,
            backlog: 0,
            accept_queue: VecDeque::new(),
            parent: None,
            error: None,
            soft_error: None,
            orphan: false,
            nodelay: false,
            cork: false,
            quickack: false,
            keepalive: false,
            keep_idle: KEEP_IDLE_MS,
            keep_intvl: KEEP_INTVL_MS,
            keep_cnt: KEEP_CNT,
            keep_sent: 0,
            last_heard: 0,
            ack_pending: 0,
            delack: None,
            acked: false,
            sack_ok: false,
            ts_ok: false,
            ts_offset: 0,
            ts_recent: 0,
            last_ack_sent: 0,
            sacked: Vec::new(),
            last_ooo: None,
            device: None,
        }
    }

    /// Data per segment: the MSS less the timestamp option.
    fn eff_mss(&self) -> usize {
        self.mss - if self.ts_ok { TS_OPTION } else { 0 }
    }

    /// The options of a segment that is not a SYN: timestamps, and SACK
    /// blocks for out-of-order data (an ACK only, `with_sack`).
    fn options(&self, now: u64, with_sack: bool) -> Vec<u8> {
        let mut o = Vec::new();
        if self.ts_ok {
            o.extend_from_slice(&[1, 1, OPT_TIMESTAMPS, 10]);
            o.extend_from_slice(&(now as u32).wrapping_add(self.ts_offset).to_be_bytes());
            o.extend_from_slice(&self.ts_recent.to_be_bytes());
        }
        if with_sack && self.sack_ok && !self.ooo.is_empty() {
            // Contiguous runs of what is held, the latest one's first.
            let mut runs: Vec<(u32, u32)> = Vec::new();
            let mut keys: Vec<u32> = self.ooo.keys().copied().collect();
            keys.sort_by_key(|k| k.wrapping_sub(self.rcv_nxt));
            for k in keys {
                let end = k.wrapping_add(self.ooo[&k].len() as u32);
                match runs.last_mut() {
                    Some(r) if le(k, r.1) => {
                        if lt(r.1, end) {
                            r.1 = end;
                        }
                    }
                    _ => runs.push((k, end)),
                }
            }
            if let Some(l) = self.last_ooo
                && let Some(i) = runs.iter().position(|r| le(r.0, l) && lt(l, r.1))
            {
                let r = runs.remove(i);
                runs.insert(0, r);
            }
            let max = if self.ts_ok { 3 } else { 4 };
            runs.truncate(max);
            o.extend_from_slice(&[1, 1, OPT_SACK, (2 + 8 * runs.len()) as u8]);
            for (a, b) in runs {
                o.extend_from_slice(&a.to_be_bytes());
                o.extend_from_slice(&b.to_be_bytes());
            }
        }
        o
    }

    /// Where sending from `seq` should skip to: past a SACKed block that
    /// starts there.
    fn skip_sacked(&self, seq: u32) -> u32 {
        self.sacked.iter().find(|&&(a, b)| le(a, seq) && lt(seq, b)).map_or(seq, |&(_, b)| b)
    }
}

/// Merge SACK blocks into a scoreboard (RFC 2018 §5), dropping what is
/// below `una`.
fn merge_sacks(board: &mut Vec<(u32, u32)>, blocks: &[(u32, u32)], una: u32) {
    for &(a, b) in blocks {
        if !lt(a, b) {
            continue;
        }
        board.push((a, b));
    }
    board.retain(|&(_, b)| lt(una, b));
    for r in board.iter_mut() {
        if lt(r.0, una) {
            r.0 = una;
        }
    }
    board.sort_by_key(|r| r.0.wrapping_sub(una));
    let mut out: Vec<(u32, u32)> = Vec::new();
    for r in board.drain(..) {
        match out.last_mut() {
            Some(l) if le(r.0, l.1) => {
                if lt(l.1, r.1) {
                    l.1 = r.1;
                }
            }
            _ => out.push(r),
        }
    }
    *board = out;
}

impl Tcb {
    fn synchronized(&self) -> bool {
        !matches!(self.state, State::Closed | State::Listen | State::SynSent)
    }

    fn rcv_wnd(&self) -> u32 {
        (RECV_BUFFER - self.recv.len().min(RECV_BUFFER)) as u32
    }

    /// Bytes sent but not acknowledged, counting a sent FIN.
    fn in_flight(&self) -> usize {
        self.snd_nxt.wrapping_sub(self.snd_una) as usize
    }

    fn can_send_data(&self) -> bool {
        matches!(self.state, State::Established | State::CloseWait)
    }
}

/// A parsed segment.
struct Segment<'a> {
    src: Endpoint,
    dst: Endpoint,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: Option<u16>,
    wscale: Option<u8>,
    sack_permitted: bool,
    /// (TSval, TSecr).
    ts: Option<(u32, u32)>,
    sacks: Vec<(u32, u32)>,
    data: &'a [u8],
}

impl Segment<'_> {
    /// Sequence space the segment occupies (data plus SYN and FIN).
    fn len(&self) -> u32 {
        self.data.len() as u32 + u32::from(self.flags & SYN != 0) + u32::from(self.flags & FIN != 0)
    }
}

fn parse(src: IpAddr, dst: IpAddr, d: &[u8]) -> Option<Segment<'_>> {
    if d.len() < TCP_HEADER || finish(sum(pseudo_sum_ip(src, dst, PROTO_TCP, d.len()), d)) != 0 {
        return None;
    }
    let off = usize::from(d[12] >> 4) * 4;
    if off < TCP_HEADER || off > d.len() {
        return None;
    }
    let (mut mss, mut wscale, mut sack_permitted, mut ts) = (None, None, false, None);
    let mut sacks = Vec::new();
    let mut i = TCP_HEADER;
    while i < off {
        match d[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = usize::from(*d.get(i + 1)?);
                if len < 2 || i + len > off {
                    break;
                }
                match (kind, len) {
                    (2, 4) => mss = Some(get16(d, i + 2)),
                    (3, 3) => wscale = Some(d[i + 2].min(14)),
                    (OPT_SACK_PERMITTED, 2) => sack_permitted = true,
                    (OPT_TIMESTAMPS, 10) => ts = Some((get32(d, i + 2), get32(d, i + 6))),
                    (OPT_SACK, l) if l >= 10 && (l - 2) % 8 == 0 => {
                        for b in (i + 2..i + l).step_by(8) {
                            sacks.push((get32(d, b), get32(d, b + 4)));
                        }
                    }
                    _ => {}
                }
                i += len;
            }
        }
    }
    Some(Segment {
        src: (src, get16(d, 0)),
        dst: (dst, get16(d, 2)),
        seq: get32(d, 4),
        ack: get32(d, 8),
        flags: d[13],
        window: get16(d, 14),
        mss,
        wscale,
        sack_permitted,
        ts,
        sacks,
        data: &d[off..],
    })
}

/// Build a segment with its checksum.
#[allow(clippy::too_many_arguments)]
fn build(
    src: Endpoint,
    dst: Endpoint,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let hlen = TCP_HEADER + options.len();
    let mut s = Vec::with_capacity(hlen + data.len());
    s.extend_from_slice(&src.1.to_be_bytes());
    s.extend_from_slice(&dst.1.to_be_bytes());
    s.extend_from_slice(&seq.to_be_bytes());
    s.extend_from_slice(&ack.to_be_bytes());
    s.push(((hlen / 4) as u8) << 4);
    s.push(flags);
    s.extend_from_slice(&window.to_be_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(options);
    s.extend_from_slice(data);
    let c = finish(sum(pseudo_sum_ip(src.0, dst.0, PROTO_TCP, s.len()), &s));
    put16(&mut s, 16, c);
    s
}

impl Stack {
    fn tcb(&mut self, h: Handle) -> Result<&mut Tcb> {
        self.tcp.get_mut(h).and_then(Option::as_mut).ok_or(Error::BadHandle)
    }

    fn tcp_alloc(&mut self, t: Tcb) -> Handle {
        match self.tcp.iter().position(Option::is_none) {
            Some(i) => {
                self.tcp[i] = Some(t);
                i
            }
            None => {
                self.tcp.push(Some(t));
                self.tcp.len() - 1
            }
        }
    }

    fn tcp_port_in_use(&self, port: u16, addr: IpAddr, v6only: bool) -> bool {
        self.tcp.iter().flatten().any(|t| {
            t.parent.is_none()
                && t.state != State::TimeWait
                && t.local.is_some_and(|l| l.1 == port && super::overlap(l.0, t.v6only, addr, v6only))
        })
    }

    fn tcp_ephemeral(&mut self) -> Result<u16> {
        for _ in 0..super::EPHEMERAL.len() {
            let p = self.next_port;
            self.next_port = if p == *super::EPHEMERAL.end() { *super::EPHEMERAL.start() } else { p + 1 };
            let busy = self.tcp.iter().flatten().any(|t| t.local.is_some_and(|l| l.1 == p));
            if !busy {
                return Ok(p);
            }
        }
        Err(Error::AddrInUse)
    }

    fn mss_for(&self, remote: IpAddr) -> usize {
        match remote {
            _ if self.is_local_ip(remote) => LOOPBACK_MSS,
            IpAddr::V4(r) => self.path_mtu(r) - IP_HEADER - TCP_HEADER,
            IpAddr::V6(r) => self.path_mtu6(r) - IP6_HEADER - TCP_HEADER,
        }
    }

    pub fn tcp_open(&mut self) -> Handle {
        self.tcp_alloc(Tcb::new())
    }

    /// The options a socket set (tcp(7): TCP_NODELAY, TCP_CORK,
    /// SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT).
    pub fn tcp_options(&mut self, h: Handle) -> Result<TcpOptions> {
        let t = self.tcb(h)?;
        Ok(TcpOptions {
            nodelay: t.nodelay,
            cork: t.cork,
            keepalive: t.keepalive,
            keep_idle: (t.keep_idle / 1000) as u32,
            keep_intvl: (t.keep_intvl / 1000) as u32,
            keep_cnt: t.keep_cnt,
            max_seg: t.max_seg,
            tos: t.ip.tos,
            ip_options: t.ip.options,
        })
    }

    /// Set the options; turning off Nagle or uncorking sends what waited.
    pub fn tcp_set_options(&mut self, h: Handle, o: TcpOptions) -> Result<()> {
        if o.keep_idle == 0 || o.keep_intvl == 0 || o.keep_cnt == 0 || o.keep_idle > 32767 || o.keep_intvl > 32767 {
            return Err(Error::InvalidInput);
        }
        let now = self.now;
        let t = self.tcb(h)?;
        if o.keepalive && !t.keepalive {
            t.last_heard = now;
            t.keep_sent = 0;
        }
        t.nodelay = o.nodelay;
        t.cork = o.cork;
        t.max_seg = o.max_seg;
        t.ip.tos = o.tos;
        t.ip.options = o.ip_options;
        t.keepalive = o.keepalive;
        t.keep_idle = u64::from(o.keep_idle) * 1000;
        t.keep_intvl = u64::from(o.keep_intvl) * 1000;
        t.keep_cnt = o.keep_cnt;
        self.tcp_output(h);
        self.events += 1;
        Ok(())
    }

    /// TCP_QUICKACK: acknowledge what came in now, and the next segment
    /// at once too.
    pub fn tcp_quickack(&mut self, h: Handle) -> Result<()> {
        let t = self.tcb(h)?;
        let pending = t.ack_pending > 0 || t.delack.is_some();
        t.quickack = true;
        if pending {
            self.send_ack(h);
            self.tcb(h)?.quickack = true;
        }
        Ok(())
    }

    /// SO_BINDTODEVICE for a TCP socket.
    pub fn tcp_bind_device(&mut self, h: Handle, dev: Option<IfIndex>) -> Result<()> {
        if let Some(d) = dev {
            self.iface(d)?;
        }
        self.tcb(h)?.device = dev;
        Ok(())
    }

    pub fn tcp_device(&mut self, h: Handle) -> Result<Option<IfIndex>> {
        Ok(self.tcb(h)?.device)
    }

    /// TCP_INFO's figures.
    pub fn tcp_info(&mut self, h: Handle) -> Result<TcpInfo> {
        let t = self.tcb(h)?;
        Ok(TcpInfo {
            rto_ms: t.rto,
            rtt_ms: t.srtt.unwrap_or(0),
            rttvar_ms: t.rttvar,
            mss: t.eff_mss(),
            cwnd: t.cwnd,
            ssthresh: t.ssthresh,
            unacked: t.in_flight(),
            retransmits: t.retries,
            sack: t.sack_ok,
            timestamps: t.ts_ok,
            snd_wscale: t.snd_wscale,
            rcv_wscale: t.rcv_wscale,
            snd_wnd: t.snd_wnd,
        })
    }

    /// (AF_INET6, IPV6_V6ONLY).
    pub fn tcp_family(&mut self, h: Handle) -> Result<(bool, bool)> {
        let t = self.tcb(h)?;
        Ok((t.v6, t.v6only))
    }

    /// An AF_INET6 socket (IPV6_V6ONLY: no IPv4 on it), before it is bound.
    pub fn tcp_set_family(&mut self, h: Handle, v6: bool, v6only: bool) -> Result<()> {
        let t = self.tcb(h)?;
        if t.local.is_some() {
            return Err(Error::InvalidInput);
        }
        (t.v6, t.v6only) = (v6, v6only);
        Ok(())
    }

    pub fn tcp_bind(&mut self, h: Handle, addr: impl Into<IpAddr>, port: u16) -> Result<Endpoint> {
        let addr = addr.into();
        let (v6, v6only) = {
            let t = self.tcb(h)?;
            if t.local.is_some() {
                return Err(Error::InvalidInput);
            }
            (t.v6, t.v6only)
        };
        if addr.is_v6() != v6 {
            return Err(Error::InvalidInput);
        }
        if !addr.is_unspecified() && !self.is_local_ip(addr) {
            return Err(Error::AddrNotAvailable);
        }
        let port = if port == 0 {
            self.tcp_ephemeral()?
        } else if self.tcp_port_in_use(port, addr, v6only) {
            return Err(Error::AddrInUse);
        } else {
            port
        };
        self.tcb(h)?.local = Some((addr, port));
        Ok((addr, port))
    }

    pub fn tcp_listen(&mut self, h: Handle, backlog: usize) -> Result<()> {
        if self.tcb(h)?.local.is_none() {
            let any = if self.tcb(h)?.v6 { IpAddr::V6(Ipv6::UNSPECIFIED) } else { IpAddr::V4(Ipv4::UNSPECIFIED) };
            self.tcp_bind(h, any, 0)?;
        }
        let t = self.tcb(h)?;
        if !matches!(t.state, State::Closed | State::Listen) {
            return Err(Error::InvalidInput);
        }
        t.state = State::Listen;
        t.backlog = backlog.clamp(1, 4096);
        Ok(())
    }

    /// A connection from the accept queue.
    pub fn tcp_accept(&mut self, h: Handle) -> Result<Handle> {
        let t = self.tcb(h)?;
        if t.state != State::Listen {
            return Err(Error::InvalidInput);
        }
        let c = t.accept_queue.pop_front().ok_or(Error::WouldBlock)?;
        self.tcb(c)?.parent = None;
        Ok(c)
    }

    /// Start connecting; completion shows in [`Stack::tcp_status`].
    pub fn tcp_connect(&mut self, h: Handle, remote: Endpoint) -> Result<()> {
        let (state, has_error) = {
            let t = self.tcb(h)?;
            (t.state, t.error.is_some())
        };
        match state {
            State::Closed if !has_error => {}
            State::SynSent => return Err(Error::InProgress),
            State::Listen => return Err(Error::InvalidInput),
            _ => return Err(Error::AlreadyConnected),
        }
        if remote.1 == 0 || remote.0.is_unspecified() {
            return Err(Error::InvalidInput);
        }
        let local = match self.tcb(h)?.local {
            Some(l) => l,
            None => {
                let port = self.tcp_ephemeral()?;
                (IpAddr::V4(Ipv4::UNSPECIFIED), port)
            }
        };
        let src = if local.0.is_unspecified() { self.source_for_ip(remote.0, None) } else { local.0 };
        if src.is_v6() != remote.0.is_v6() {
            return Err(Error::InvalidInput);
        }
        if src.is_unspecified() {
            return Err(Error::NetUnreachable);
        }
        let iss = self.rand();
        let ts_offset = self.rand();
        let mss = self.mss_for(remote.0);
        let now = self.now;
        let t = self.tcb(h)?;
        let mss = t.max_seg.map_or(mss, |m| mss.min(usize::from(m).max(64)));
        let mss = mss - if matches!(remote.0, IpAddr::V4(_)) { t.ip.options.header_bytes() } else { 0 };
        t.ts_offset = ts_offset;
        t.local = Some((src, local.1));
        t.remote = Some(remote);
        t.iss = iss;
        t.snd_una = iss;
        t.snd_nxt = iss.wrapping_add(1);
        t.snd_max = t.snd_nxt;
        t.mss = mss;
        t.state = State::SynSent;
        t.rtx_deadline = Some(now + t.rto);
        t.timing = Some((iss, now));
        t.last_heard = now;
        self.send_syn(h, false);
        self.events += 1;
        Ok(())
    }

    fn send_syn(&mut self, h: Handle, with_ack: bool) {
        let now = self.now;
        let Ok(t) = self.tcb(h) else { return };
        let (Some(l), Some(r)) = (t.local, t.remote) else { return };
        let mss = t.mss.min(65535) as u16;
        // Options: MSS, SACK permitted, timestamps, NOP, window scale (a
        // SYN-ACK offers SACK and timestamps only if the SYN did).
        let mut opts = alloc::vec![2, 4];
        opts.extend_from_slice(&mss.to_be_bytes());
        let (offer_sack, offer_ts) = if with_ack { (t.sack_ok, t.ts_ok) } else { (true, true) };
        if offer_sack {
            opts.extend_from_slice(&[OPT_SACK_PERMITTED, 2]);
        }
        if offer_ts {
            opts.extend_from_slice(&[OPT_TIMESTAMPS, 10]);
            opts.extend_from_slice(&(now as u32).wrapping_add(t.ts_offset).to_be_bytes());
            opts.extend_from_slice(&(if with_ack { t.ts_recent } else { 0 }).to_be_bytes());
        }
        opts.extend_from_slice(&[1, 3, 3, OUR_WSCALE]);
        while opts.len() % 4 != 0 {
            opts.push(1);
        }
        let (seq, ack) = (t.iss, t.rcv_nxt);
        let flags = if with_ack { SYN | ACK } else { SYN };
        let window = RECV_BUFFER.min(65535) as u16;
        let (dev, ip) = (t.device, t.ip);
        let s = build(l, r, seq, if with_ack { ack } else { 0 }, flags, window, &opts, &[]);
        let _ = self.send_ipx_opt(l.0, r.0, PROTO_TCP, &s, dev, ip);
    }

    fn send_ack(&mut self, h: Handle) {
        self.send_flags(h, ACK);
    }

    fn send_flags(&mut self, h: Handle, flags: u8) {
        let now = self.now;
        let Ok(t) = self.tcb(h) else { return };
        let (Some(l), Some(r)) = (t.local, t.remote) else { return };
        let window = (t.rcv_wnd() >> t.rcv_wscale).min(65535) as u16;
        let opts = t.options(now, flags & RST == 0);
        // Whatever goes out acknowledges what came in.
        t.ack_pending = 0;
        t.delack = None;
        t.quickack = false;
        t.acked = true;
        t.last_ack_sent = t.rcv_nxt;
        let (dev, ip) = (t.device, t.ip);
        let s = build(l, r, t.snd_nxt, t.rcv_nxt, flags, window, &opts, &[]);
        let _ = self.send_ipx_opt(l.0, r.0, PROTO_TCP, &s, dev, ip);
    }

    /// A keep-alive probe: an ACK one before the next sequence number,
    /// which the peer answers with an ACK (RFC 1122 §4.2.3.6).
    fn send_keepalive(&mut self, h: Handle) {
        let now = self.now;
        let Ok(t) = self.tcb(h) else { return };
        let (Some(l), Some(r)) = (t.local, t.remote) else { return };
        let window = (t.rcv_wnd() >> t.rcv_wscale).min(65535) as u16;
        let opts = t.options(now, false);
        let (dev, ip) = (t.device, t.ip);
        let s = build(l, r, t.snd_una.wrapping_sub(1), t.rcv_nxt, ACK, window, &opts, &[]);
        let _ = self.send_ipx_opt(l.0, r.0, PROTO_TCP, &s, dev, ip);
    }

    /// Answer the TCP segment `d` (from `src` to `dst`) with a reset, as
    /// for a segment no connection takes (RFC 793 §3.4): a firewall's
    /// reject.
    pub(super) fn reset_reply(&mut self, src: IpAddr, dst: IpAddr, d: &[u8]) {
        if let Some(seg) = parse(src, dst, d) {
            self.send_reset_for(&seg);
        }
    }

    fn send_reset_for(&mut self, seg: &Segment<'_>) {
        if seg.flags & RST != 0 {
            return;
        }
        let s = if seg.flags & ACK != 0 {
            build(seg.dst, seg.src, seg.ack, 0, RST, 0, &[], &[])
        } else {
            build(seg.dst, seg.src, 0, seg.seq.wrapping_add(seg.len()), RST | ACK, 0, &[], &[])
        };
        let _ = self.send_ipx(seg.dst.0, seg.src.0, PROTO_TCP, &s);
    }

    /// Send whatever the windows allow: new data, then a queued FIN.
    /// The TCP segmentation offload of connection `h`'s route (0: none).
    fn tcp_route_tso(&self, h: Handle) -> usize {
        let Some(Some(t)) = self.tcp.get(h) else { return 0 };
        match t.remote {
            Some((IpAddr::V4(dst), _)) => self.tso_for(dst, t.device),
            _ => 0,
        }
    }

    /// Send what acknowledgements opened room for (see `segment_arrives`).
    pub(crate) fn tcp_output_later(&mut self) {
        for h in core::mem::take(&mut self.tcp_later) {
            self.tcp_output(h);
        }
    }

    fn tcp_output(&mut self, h: Handle) {
        loop {
            let now = self.now;
            let Ok(t) = self.tcb(h) else { return };
            if !t.synchronized() || matches!(t.state, State::SynReceived) {
                return;
            }
            let (Some(l), Some(r)) = (t.local, t.remote) else { return };
            // Retransmitting: skip what the peer already holds (SACK), and
            // resend only holes below the highest block; what lies above
            // it may still be on its way (RFC 6675 §4).
            if t.sack_ok && lt(t.snd_nxt, t.snd_max) {
                let to = t.skip_sacked(t.snd_nxt);
                if to != t.snd_nxt {
                    t.snd_nxt = if lt(t.snd_max, to) { t.snd_max } else { to };
                    continue;
                }
                let highest = t.sacked.iter().map(|r| r.1).max_by_key(|e| e.wrapping_sub(t.snd_una));
                if let Some(hi) = highest
                    && le(hi, t.snd_nxt)
                {
                    t.snd_nxt = t.snd_max;
                    continue;
                }
            }
            let sent_data = t.in_flight().saturating_sub(usize::from(t.fin_sent));
            let unsent = t.send.len().saturating_sub(sent_data);
            let window = (t.snd_wnd as usize).min(t.cwnd.max(t.mss));
            let room = window.saturating_sub(t.in_flight());
            let mss = t.eff_mss();
            let device = t.device;
            // A card that segments TCP itself takes sends of many segments
            // (ADR 0083): a whole number of them, up to its limit.
            let tso = match r.0 {
                IpAddr::V4(dst) => self.tso_for(dst, device),
                IpAddr::V6(_) => 0,
            };
            let limit = if tso >= 2 * mss { tso / mss * mss } else { mss };
            let Ok(t) = self.tcb(h) else { return };
            let mut n = unsent.min(room).min(limit);
            let mut hole = false;
            if t.sack_ok && lt(t.snd_nxt, t.snd_max) {
                // A retransmission stops at the next SACKed block.
                if let Some(&(a, _)) = t.sacked.iter().find(|&&(a, _)| lt(t.snd_nxt, a)) {
                    let to_block = a.wrapping_sub(t.snd_nxt) as usize;
                    if to_block <= n {
                        n = to_block;
                        hole = true;
                    }
                }
            }
            // Nagle (RFC 1122 §4.2.3.4): a small segment waits while data
            // is unacknowledged, unless TCP_NODELAY; with TCP_CORK, small
            // segments wait (until uncorked or the FIN).
            let resend = lt(t.snd_nxt, t.snd_max);
            let last_before_fin = t.fin_queued && n == unsent;
            let nagle = !resend && !last_before_fin && (t.cork || (!t.nodelay && t.in_flight() > 0));
            // Silly window avoidance (RFC 9293 §3.8.6.2.1): no sliver of a
            // segment because the window is nearly used up, while data is
            // in flight to open it.
            let sliver = n < unsent.min(mss) && !hole && t.in_flight() > 0;
            let hold = n > 0 && n < mss && (nagle || sliver);
            if unsent > 0 && room > 0 && !t.fin_sent && n > 0 && !hold {
                let data: Vec<u8> = t.send.range(sent_data..sent_data + n).copied().collect();
                let seq = t.snd_nxt;
                t.snd_nxt = t.snd_nxt.wrapping_add(n as u32);
                if lt(t.snd_max, t.snd_nxt) {
                    t.snd_max = t.snd_nxt;
                }
                if t.rtx_deadline.is_none() {
                    t.rtx_deadline = Some(now + t.rto);
                }
                if t.timing.is_none() {
                    t.timing = Some((seq, now));
                }
                let window = (t.rcv_wnd() >> t.rcv_wscale).min(65535) as u16;
                let flags = if n == unsent { ACK | PSH } else { ACK };
                let opts = t.options(now, false);
                t.ack_pending = 0;
                t.delack = None;
                t.acked = true;
                t.last_ack_sent = t.rcv_nxt;
                let (dev, mut ip) = (t.device, t.ip);
                if n > mss {
                    ip.tso = mss as u16;
                }
                let s = build(l, r, seq, t.rcv_nxt, flags, window, &opts, &data);
                let _ = self.send_ipx_opt(l.0, r.0, PROTO_TCP, &s, dev, ip);
                continue;
            }
            if hold {
                return;
            }
            // Peer's window is closed with data waiting: probe later.
            if unsent > 0 && t.snd_wnd == 0 && t.in_flight() == 0 && t.rtx_deadline.is_none() {
                t.rtx_deadline = Some(now + t.rto);
            }
            if t.fin_queued && !t.fin_sent && unsent == 0 {
                t.fin_sent = true;
                let seq = t.snd_nxt;
                t.fin_seq.get_or_insert(seq);
                t.snd_nxt = t.snd_nxt.wrapping_add(1);
                if lt(t.snd_max, t.snd_nxt) {
                    t.snd_max = t.snd_nxt;
                }
                if t.rtx_deadline.is_none() {
                    t.rtx_deadline = Some(now + t.rto);
                }
                t.state = match t.state {
                    State::CloseWait => State::LastAck,
                    State::Established => State::FinWait1,
                    s => s,
                };
                let window = (t.rcv_wnd() >> t.rcv_wscale).min(65535) as u16;
                let opts = t.options(now, false);
                t.last_ack_sent = t.rcv_nxt;
                let (dev, ip) = (t.device, t.ip);
                let s = build(l, r, seq, t.rcv_nxt, FIN | ACK, window, &opts, &[]);
                let _ = self.send_ipx_opt(l.0, r.0, PROTO_TCP, &s, dev, ip);
            }
            return;
        }
    }

    /// Queue data; returns how much fit.
    pub fn tcp_send(&mut self, h: Handle, data: &[u8]) -> Result<usize> {
        let t = self.tcb(h)?;
        if let Some(e) = t.error.take() {
            return Err(e);
        }
        match t.state {
            State::Established | State::CloseWait if !t.fin_queued => {}
            State::SynSent | State::SynReceived => return Err(Error::WouldBlock),
            State::Closed | State::Listen if t.remote.is_none() => return Err(Error::NotConnected),
            _ => return Err(Error::BrokenPipe),
        }
        let n = data.len().min(SEND_BUFFER - t.send.len());
        if n == 0 {
            return Err(Error::WouldBlock);
        }
        t.send.extend(&data[..n]);
        self.tcp_output(h);
        Ok(n)
    }

    /// Read received data; `Ok(0)` is end of stream.
    pub fn tcp_recv(&mut self, h: Handle, buf: &mut [u8], peek: bool) -> Result<usize> {
        self.tcp_recv_at(h, buf, peek, 0)
    }

    /// Like [`Stack::tcp_recv`], but a peek starts `offset` bytes into
    /// what is waiting (SO_PEEK_OFF, socket(7)); nothing waits beyond it:
    /// as an empty buffer.
    pub fn tcp_recv_at(&mut self, h: Handle, buf: &mut [u8], peek: bool, offset: usize) -> Result<usize> {
        let t = self.tcb(h)?;
        let offset = if peek { offset } else { 0 };
        if t.recv.len() <= offset {
            if let Some(e) = t.error.take() {
                return Err(e);
            }
            if t.fin_received || t.read_shutdown || t.state == State::Closed && t.remote.is_some() {
                return Ok(0);
            }
            return match t.state {
                State::Closed | State::Listen => Err(Error::NotConnected),
                _ => Err(Error::WouldBlock),
            };
        }
        let before = t.rcv_wnd();
        let n = buf.len().min(t.recv.len() - offset);
        for (d, s) in buf.iter_mut().zip(t.recv.iter().skip(offset)) {
            *d = *s;
        }
        if !peek {
            t.recv.drain(..n);
            shrink_if_empty(&mut t.recv);
        }
        // Tell the peer when the window opens up substantially.
        let after = t.rcv_wnd();
        if !peek && before < (RECV_BUFFER / 4) as u32 && after >= (RECV_BUFFER / 4) as u32 && t.synchronized() {
            self.send_ack(h);
        }
        Ok(n)
    }

    pub fn tcp_recv_pending(&mut self, h: Handle) -> Result<usize> {
        Ok(self.tcb(h)?.recv.len())
    }

    /// shutdown(2): stop reading, writing (send a FIN), or both.
    pub fn tcp_shutdown(&mut self, h: Handle, read: bool, write: bool) -> Result<()> {
        let t = self.tcb(h)?;
        if !t.synchronized() && t.state != State::SynSent {
            return Err(Error::NotConnected);
        }
        if read {
            t.read_shutdown = true;
            t.recv.clear();
        }
        if write && !t.fin_queued {
            t.fin_queued = true;
            self.tcp_output(h);
        }
        self.events += 1;
        Ok(())
    }

    /// The owner closed the socket: finish gracefully in the background
    /// (or reset, if received data was never read).
    pub fn tcp_close(&mut self, h: Handle) {
        let Ok(t) = self.tcb(h) else { return };
        let children: Vec<Handle> = t.accept_queue.drain(..).collect();
        match t.state {
            State::Closed | State::Listen | State::SynSent | State::TimeWait => {
                self.tcp[h] = None;
            }
            _ if !t.recv.is_empty() => {
                self.send_flags(h, RST | ACK);
                self.tcp[h] = None;
            }
            State::CloseWait | State::Established | State::SynReceived => {
                t.orphan = true;
                t.fin_queued = true;
                t.release_receive();
                self.tcp_output(h);
            }
            _ => {
                t.orphan = true;
                t.release_receive();
            }
        }
        // Connections nobody accepted are reset, and half-open ones too.
        for c in children {
            self.send_flags(c, RST | ACK);
            self.tcp[c] = None;
        }
        let orphans: Vec<Handle> =
            (0..self.tcp.len()).filter(|&i| self.tcp[i].as_ref().is_some_and(|t| t.parent == Some(h))).collect();
        for c in orphans {
            self.send_flags(c, RST | ACK);
            self.tcp[c] = None;
        }
        self.events += 1;
    }

    #[cfg(test)]
    pub fn tcp_dump(&mut self, h: Handle) -> alloc::string::String {
        let t = self.tcb(h).unwrap();
        alloc::format!(
            "{:?} una={} nxt={} wnd={} cwnd={} sendbuf={} fin_q={} fin_s={} rcv_nxt={} recv={} ooo={}/{} rtx={:?} rto={} retries={} dup={}",
            t.state,
            t.snd_una.wrapping_sub(t.iss),
            t.snd_nxt.wrapping_sub(t.iss),
            t.snd_wnd,
            t.cwnd,
            t.send.len(),
            t.fin_queued,
            t.fin_sent,
            t.rcv_nxt.wrapping_sub(t.irs),
            t.recv.len(),
            t.ooo.len(),
            t.ooo_bytes,
            t.rtx_deadline,
            t.rto,
            t.retries,
            t.dup_acks
        )
    }

    /// The TCP sockets with an address, for /proc/net/tcp and tcp6.
    pub(super) fn tcp_entries(&self, out: &mut Vec<super::SocketEntry>) {
        for (handle, t) in self.tcp.iter().enumerate().filter_map(|(h, t)| Some((h, t.as_ref()?))) {
            let Some(local) = t.local else { continue };
            let listening = t.state == State::Listen;
            out.push(super::SocketEntry {
                tcp: true,
                v6: t.v6,
                local,
                remote: if listening { None } else { t.remote },
                state: Some(t.state),
                // For a listener: connections waiting, and the backlog.
                tx_queue: if listening { t.backlog } else { t.send.len() },
                rx_queue: if listening { t.accept_queue.len() } else { t.recv.len() },
                handle,
            });
        }
    }

    pub fn tcp_local(&mut self, h: Handle) -> Result<Option<Endpoint>> {
        Ok(self.tcb(h)?.local)
    }

    pub fn tcp_remote(&mut self, h: Handle) -> Result<Option<Endpoint>> {
        let t = self.tcb(h)?;
        Ok(if t.synchronized() { t.remote } else { None })
    }

    pub fn tcp_state(&mut self, h: Handle) -> Result<State> {
        Ok(self.tcb(h)?.state)
    }

    pub fn tcp_take_error(&mut self, h: Handle) -> Result<Option<Error>> {
        Ok(self.tcb(h)?.error.take())
    }

    pub fn tcp_status(&mut self, h: Handle) -> Result<Status> {
        let t = self.tcb(h)?;
        let dead = t.state == State::Closed && t.remote.is_some();
        Ok(match t.state {
            State::Listen => Status { readable: !t.accept_queue.is_empty(), ..Default::default() },
            _ => Status {
                readable: !t.recv.is_empty() || t.fin_received || t.read_shutdown || t.error.is_some() || dead,
                writable: (t.can_send_data() && !t.fin_queued && t.send.len() < SEND_BUFFER)
                    || t.error.is_some()
                    || dead,
                hangup: dead || (t.fin_received && t.fin_queued && matches!(t.state, State::TimeWait | State::Closed)),
                read_hangup: t.fin_received || dead,
                error: t.error.is_some(),
            },
        })
    }

    // --- input ---------------------------------------------------------------

    pub(super) fn receive_tcp(&mut self, index: IfIndex, src: IpAddr, dst: IpAddr, d: &[u8]) {
        let Some(seg) = parse(src, dst, d) else { return };
        self.events += 1;
        // A socket bound to a card takes only what comes in on it.
        let on = |t: &Tcb| t.device.is_none_or(|dev| dev == index || index == super::LOOPBACK);
        // An established connection with this 4-tuple, else a listener.
        let conn = self.tcp.iter().position(|t| {
            t.as_ref().is_some_and(|t| {
                t.state != State::Listen
                    && on(t)
                    && t.local.is_some_and(|l| l.1 == seg.dst.1 && super::takes(l.0, t.v6only, seg.dst.0))
                    && t.remote == Some(seg.src)
            })
        });
        if let Some(c) = conn {
            return self.segment_arrives(c, &seg);
        }
        let listener = self.tcp.iter().position(|t| {
            t.as_ref().is_some_and(|t| {
                t.state == State::Listen
                    && on(t)
                    && t.local.is_some_and(|l| l.1 == seg.dst.1 && super::takes(l.0, t.v6only, seg.dst.0))
            })
        });
        match listener {
            Some(l) if seg.flags & (SYN | ACK | RST) == SYN => self.passive_open(l, &seg),
            _ => self.send_reset_for(&seg),
        }
    }

    fn passive_open(&mut self, listener: Handle, seg: &Segment<'_>) {
        let pending = self.tcp.iter().flatten().filter(|t| t.parent == Some(listener)).count();
        let Ok(l) = self.tcb(listener) else { return };
        if pending >= l.backlog {
            return; // Full: the client will retry its SYN.
        }
        let (v6, v6only) = (l.v6, l.v6only);
        let inherited = (l.nodelay, l.keepalive, l.keep_idle, l.keep_intvl, l.keep_cnt, l.device);
        let (max_seg, ip) = (l.max_seg, l.ip);
        let iss = self.rand();
        let ts_offset = self.rand();
        let mut t = Tcb::new();
        (t.v6, t.v6only) = (v6, v6only);
        (t.nodelay, t.keepalive, t.keep_idle, t.keep_intvl, t.keep_cnt, t.device) = inherited;
        (t.max_seg, t.ip) = (max_seg, ip);
        t.sack_ok = seg.sack_permitted;
        if let Some((val, _)) = seg.ts {
            t.ts_ok = true;
            t.ts_recent = val;
            t.ts_offset = ts_offset;
        }
        t.last_heard = self.now;
        t.state = State::SynReceived;
        t.local = Some(seg.dst);
        t.remote = Some(seg.src);
        t.parent = Some(listener);
        t.irs = seg.seq;
        t.rcv_nxt = seg.seq.wrapping_add(1);
        t.last_ack_sent = t.rcv_nxt;
        t.iss = iss;
        t.snd_una = iss;
        t.snd_nxt = iss.wrapping_add(1);
        t.snd_max = t.snd_nxt;
        t.mss = self.mss_for(seg.src.0).min(usize::from(seg.mss.unwrap_or(DEFAULT_MSS as u16)));
        if let Some(m) = t.max_seg {
            t.mss = t.mss.min(usize::from(m).max(64));
        }
        if matches!(seg.src.0, IpAddr::V4(_)) {
            t.mss -= t.ip.options.header_bytes();
        }
        if let Some(ws) = seg.wscale {
            t.snd_wscale = ws;
            t.rcv_wscale = OUR_WSCALE;
        }
        t.snd_wnd = u32::from(seg.window); // SYN windows are never scaled.
        t.snd_wl1 = seg.seq;
        t.rtx_deadline = Some(self.now + t.rto);
        let h = self.tcp_alloc(t);
        self.send_syn(h, true);
    }

    fn segment_arrives(&mut self, h: Handle, seg: &Segment<'_>) {
        let now = self.now;
        let state = self.tcb(h).map(|t| t.state).unwrap_or(State::Closed);
        if state == State::SynSent {
            return self.syn_sent_arrives(h, seg);
        }
        if state == State::Closed {
            return self.send_reset_for(seg);
        }
        let Ok(t) = self.tcb(h) else { return };
        // PAWS and TS.Recent come first (RFC 7323 §5.3 R1, R3): an older
        // timestamp marks an old duplicate; TS.Recent follows the segment
        // the next ACK covers, retransmissions of what is held included.
        if t.ts_ok
            && let Some((val, _)) = seg.ts
        {
            if lt(val, t.ts_recent) && seg.flags & RST == 0 {
                self.send_ack(h);
                return;
            }
            if le(seg.seq, t.last_ack_sent) {
                t.ts_recent = val;
            }
        }
        // 1. Is the segment in the receive window?
        let wnd = t.rcv_wnd();
        let len = seg.len();
        let in_window = |s: u32| le(t.rcv_nxt, s) && lt(s, t.rcv_nxt.wrapping_add(wnd));
        let acceptable = match (len, wnd) {
            (0, 0) => seg.seq == t.rcv_nxt,
            (0, _) => in_window(seg.seq),
            (_, 0) => false,
            _ => in_window(seg.seq) || in_window(seg.seq.wrapping_add(len - 1)),
        };
        if !acceptable {
            if seg.flags & RST == 0 {
                self.send_ack(h);
            }
            return;
        }
        // 2. RST: only an exact match resets (RFC 5961 §3.2).
        if seg.flags & RST != 0 {
            if seg.seq != t.rcv_nxt {
                self.send_ack(h);
                return;
            }
            if t.parent.is_some() {
                self.tcp[h] = None;
                return;
            }
            t.error = Some(if state == State::SynReceived { Error::ConnectionRefused } else { Error::ConnectionReset });
            t.state = State::Closed;
            t.send.clear();
            t.rtx_deadline = None;
            if t.orphan {
                self.tcp[h] = None;
            }
            return;
        }
        // 3. A SYN in a synchronized state: challenge ACK (RFC 5961 §4).
        if seg.flags & SYN != 0 {
            self.send_ack(h);
            return;
        }
        // Heard from the peer: keep-alive starts over.
        t.last_heard = now;
        t.keep_sent = 0;
        // 4.-5. ACK processing.
        if seg.flags & ACK == 0 {
            return;
        }
        if state == State::SynReceived {
            if !(lt(t.snd_una, seg.ack) && le(seg.ack, t.snd_nxt)) {
                self.send_reset_for(seg);
                return;
            }
            t.state = State::Established;
            t.snd_una = seg.ack;
            t.snd_wnd = u32::from(seg.window) << t.snd_wscale;
            t.snd_wl1 = seg.seq;
            t.snd_wl2 = seg.ack;
            t.rtx_deadline = None;
            t.retries = 0;
            t.cwnd = 10 * t.mss;
            if let Some(p) = t.parent
                && let Ok(listener) = self.tcb(p)
            {
                listener.accept_queue.push_back(h);
            }
        }
        let Ok(t) = self.tcb(h) else { return };
        if lt(t.snd_max, seg.ack) {
            self.send_ack(h); // Acknowledges something not yet sent.
            return;
        }
        if lt(t.snd_una, seg.ack) {
            let acked = seg.ack.wrapping_sub(t.snd_una) as usize;
            let data_acked = acked.min(t.send.len());
            t.send.drain(..data_acked);
            shrink_if_empty(&mut t.send);
            let fin_acked = t.fin_seq.is_some_and(|f| lt(f, seg.ack));
            if fin_acked {
                t.fin_sent = true;
            }
            t.snd_una = seg.ack;
            // Data sent before a retransmission rewind may be acked now.
            if lt(t.snd_nxt, seg.ack) {
                t.snd_nxt = seg.ack;
            }
            t.retries = 0;
            t.dup_acks = 0;
            // RTT sample: from the echoed timestamp (RFC 7323 §4), else
            // from a timed segment (Karn: only one sent once).
            let echoed = seg
                .ts
                .filter(|&(_, ecr)| t.ts_ok && ecr != 0)
                .map(|(_, ecr)| u64::from((now as u32).wrapping_add(t.ts_offset).wrapping_sub(ecr)));
            let timed = t.timing.filter(|&(tseq, _)| le(tseq, seg.ack)).map(|(_, sent)| now.saturating_sub(sent));
            if let Some(r) = echoed.filter(|r| *r < 60_000).or(timed) {
                t.timing = None;
                match t.srtt {
                    None => {
                        t.srtt = Some(r);
                        t.rttvar = r / 2;
                    }
                    Some(s) => {
                        t.rttvar = (3 * t.rttvar + s.abs_diff(r)) / 4;
                        t.srtt = Some((7 * s + r) / 8);
                    }
                }
                t.rto = (t.srtt.unwrap() + (4 * t.rttvar).max(10)).clamp(RTO_MIN_MS, RTO_MAX_MS);
            }
            // Congestion window growth.
            if t.cwnd < t.ssthresh {
                t.cwnd += data_acked.min(t.mss);
            } else {
                t.cwnd += (t.mss * t.mss / t.cwnd.max(1)).max(1);
            }
            t.rtx_deadline = if t.in_flight() > 0 { Some(now + t.rto) } else { None };
            if fin_acked {
                match t.state {
                    State::FinWait1 => {
                        t.state = State::FinWait2;
                        if t.orphan {
                            t.deadline = Some(now + FIN_WAIT2_MS);
                        }
                    }
                    State::Closing => {
                        t.state = State::TimeWait;
                        t.deadline = Some(now + TIME_WAIT_MS);
                    }
                    State::LastAck => {
                        t.state = State::Closed;
                        if t.orphan {
                            self.tcp[h] = None;
                            return;
                        }
                    }
                    _ => {}
                }
            }
        } else if seg.ack == t.snd_una
            && seg.data.is_empty()
            && seg.flags & FIN == 0
            && t.in_flight() > 0
            && u32::from(seg.window) << t.snd_wscale == t.snd_wnd
        {
            t.dup_acks += 1;
            if t.dup_acks == 3 {
                // Fast retransmit (RFC 5681 §3.2).
                t.ssthresh = (t.in_flight() / 2).max(2 * t.mss);
                t.cwnd = t.ssthresh + 3 * t.mss;
                self.retransmit_first(h);
            }
        }
        let Ok(t) = self.tcb(h) else { return };
        if t.sack_ok {
            let una = t.snd_una;
            let max = t.snd_max;
            let blocks: Vec<(u32, u32)> =
                seg.sacks.iter().copied().filter(|&(a, b)| lt(una, b) && le(b, max) && lt(a, b)).collect();
            merge_sacks(&mut t.sacked, &blocks, una);
        }
        // Window update (RFC 9293 §3.10.7.4).
        if lt(t.snd_wl1, seg.seq) || (t.snd_wl1 == seg.seq && le(t.snd_wl2, seg.ack)) {
            t.snd_wnd = u32::from(seg.window) << t.snd_wscale;
            t.snd_wl1 = seg.seq;
            t.snd_wl2 = seg.ack;
        }
        // 7. Data.
        let mut need_ack = false;
        let mut delay = false;
        if !seg.data.is_empty() && matches!(t.state, State::Established | State::FinWait1 | State::FinWait2) {
            // In order and no holes: the ACK may wait (RFC 9293 §3.8.6.3:
            // at least every second segment, within the timeout); out of
            // order, or filling a hole: at once (RFC 5681 §4.2).
            let in_order = seg.seq == t.rcv_nxt && t.ooo.is_empty();
            need_ack = true;
            self.accept_data(h, seg.seq, seg.data);
            let Ok(t) = self.tcb(h) else { return };
            if in_order && t.ooo.is_empty() && !t.quickack {
                t.ack_pending += 1;
                delay = t.ack_pending < 2;
            }
        }
        // 8. FIN.
        let Ok(t) = self.tcb(h) else { return };
        if seg.flags & FIN != 0 {
            need_ack = true;
            delay = false;
            let fin_seq = seg.seq.wrapping_add(seg.data.len() as u32);
            if fin_seq == t.rcv_nxt {
                self.fin_arrives(h);
            } else if lt(t.rcv_nxt, fin_seq) {
                t.ooo_fin = Some(fin_seq);
            }
        }
        if let Ok(t) = self.tcb(h) {
            t.acked = false;
        }
        // An acknowledgement alone, on a route whose card segments TCP
        // (ADR 0083): send once every frame that came in together has been
        // taken (`poll`), so the window they opened goes out as one large
        // send instead of a segment per acknowledgement.
        if !need_ack && self.tcp_route_tso(h) > 0 {
            if !self.tcp_later.contains(&h) {
                self.tcp_later.push(h);
            }
            return;
        }
        self.tcp_output(h);
        let Ok(t) = self.tcb(h) else { return };
        // Data that just went out carried the ACK; else an ACK is due, a
        // duplicate one too for out-of-order data (RFC 5681 §4.2).
        if need_ack && !t.acked {
            if delay {
                if t.delack.is_none() {
                    t.delack = Some(now + DELACK_MS);
                }
            } else {
                self.send_ack(h);
            }
        }
    }

    fn accept_data(&mut self, h: Handle, seq: u32, data: &[u8]) {
        let Ok(t) = self.tcb(h) else { return };
        let mut seq = seq;
        let mut data = data;
        // Trim what was already received.
        if lt(seq, t.rcv_nxt) {
            let skip = t.rcv_nxt.wrapping_sub(seq) as usize;
            if skip >= data.len() {
                return;
            }
            data = &data[skip..];
            seq = t.rcv_nxt;
        }
        let room = t.rcv_wnd() as usize;
        if seq == t.rcv_nxt {
            let n = data.len().min(room);
            if !t.read_shutdown {
                t.recv.extend(&data[..n]);
            }
            t.rcv_nxt = t.rcv_nxt.wrapping_add(n as u32);
            // Out-of-order data that now follows on.
            // Map order is numeric, not sequence order (which wraps):
            // look for any segment that now starts at or before rcv_nxt.
            while let Some(s) = t.ooo.keys().copied().find(|&s| le(s, t.rcv_nxt)) {
                let d = t.ooo.remove(&s).unwrap();
                t.ooo_bytes -= d.len();
                let skip = t.rcv_nxt.wrapping_sub(s) as usize;
                if skip < d.len() {
                    let n = (d.len() - skip).min(t.rcv_wnd() as usize);
                    if !t.read_shutdown {
                        t.recv.extend(&d[skip..skip + n]);
                    }
                    t.rcv_nxt = t.rcv_nxt.wrapping_add(n as u32);
                }
            }
            if t.ooo_fin == Some(t.rcv_nxt) {
                t.ooo_fin = None;
                self.fin_arrives(h);
            }
        } else if t.ooo_bytes + data.len() <= OOO_LIMIT && !t.ooo.contains_key(&seq) {
            t.ooo_bytes += data.len();
            t.ooo.insert(seq, data.to_vec());
            t.last_ooo = Some(seq);
        }
    }

    fn fin_arrives(&mut self, h: Handle) {
        let now = self.now;
        let Ok(t) = self.tcb(h) else { return };
        t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
        t.fin_received = true;
        t.state = match t.state {
            State::SynReceived | State::Established => State::CloseWait,
            State::FinWait1 if t.fin_sent && t.snd_una == t.snd_nxt => {
                t.deadline = Some(now + TIME_WAIT_MS);
                State::TimeWait
            }
            State::FinWait1 => State::Closing,
            State::FinWait2 | State::TimeWait => {
                t.deadline = Some(now + TIME_WAIT_MS);
                State::TimeWait
            }
            s => s,
        };
    }

    fn syn_sent_arrives(&mut self, h: Handle, seg: &Segment<'_>) {
        let now = self.now;
        let Ok(t) = self.tcb(h) else { return };
        let ack_ok = seg.flags & ACK != 0 && lt(t.iss, seg.ack) && le(seg.ack, t.snd_nxt);
        if seg.flags & ACK != 0 && !ack_ok {
            self.send_reset_for(seg);
            return;
        }
        if seg.flags & RST != 0 {
            if ack_ok {
                t.error = Some(Error::ConnectionRefused);
                t.state = State::Closed;
                t.rtx_deadline = None;
            }
            return;
        }
        if seg.flags & SYN == 0 {
            return;
        }
        t.irs = seg.seq;
        t.rcv_nxt = seg.seq.wrapping_add(1);
        t.last_ack_sent = t.rcv_nxt;
        t.sack_ok = seg.sack_permitted;
        t.ts_ok = seg.ts.is_some();
        if let Some((val, _)) = seg.ts {
            t.ts_recent = val;
        }
        t.last_heard = now;
        if let Some(m) = seg.mss {
            t.mss = t.mss.min(usize::from(m).max(64));
        } else {
            t.mss = t.mss.min(DEFAULT_MSS);
        }
        if let Some(ws) = seg.wscale {
            t.snd_wscale = ws;
            t.rcv_wscale = OUR_WSCALE;
        }
        t.snd_wnd = u32::from(seg.window);
        t.snd_wl1 = seg.seq;
        t.snd_wl2 = seg.ack;
        if ack_ok {
            t.snd_una = seg.ack;
            t.state = State::Established;
            t.rtx_deadline = None;
            t.retries = 0;
            t.cwnd = 10 * t.mss;
            if let Some((_, sent)) = t.timing.take() {
                let r = self.now.saturating_sub(sent);
                let t = self.tcb(h).unwrap();
                t.srtt = Some(r);
                t.rttvar = r / 2;
                t.rto = (r + (2 * r).max(10)).clamp(RTO_MIN_MS, RTO_MAX_MS);
            }
            self.send_ack(h);
            self.tcp_output(h);
        } else {
            // Simultaneous open.
            t.state = State::SynReceived;
            self.send_syn(h, true);
        }
    }

    /// An ICMP error about a segment from `local` to `remote` carrying
    /// sequence number `seq`. Only an error quoting a segment still in
    /// flight counts (RFC 5927 §4.1: a blind attacker rarely guesses one).
    pub(super) fn tcp_icmp_error(&mut self, local: Endpoint, remote: Endpoint, seq: u32, effect: IcmpEffect) {
        let found = self.tcp.iter().position(|t| {
            t.as_ref().is_some_and(|t| t.state != State::Listen && t.local == Some(local) && t.remote == Some(remote))
        });
        let Some(h) = found else { return };
        let mss = self.mss_for(remote.0);
        let Ok(t) = self.tcb(h) else { return };
        if !(le(t.snd_una, seq) && lt(seq, t.snd_max)) {
            return;
        }
        match effect {
            IcmpEffect::Mtu => {
                let mss = mss - if matches!(remote.0, IpAddr::V4(_)) { t.ip.options.header_bytes() } else { 0 };
                if mss < t.mss {
                    t.mss = mss.max(64);
                    // What was lost was too big: again, smaller.
                    self.retransmit_first(h);
                }
            }
            IcmpEffect::Fatal(e) if matches!(t.state, State::SynSent | State::SynReceived) => {
                t.error = Some(e);
                t.state = State::Closed;
                t.rtx_deadline = None;
                if t.parent.is_some() || t.orphan {
                    self.tcp[h] = None;
                }
            }
            IcmpEffect::Fatal(e) | IcmpEffect::Soft(e) => t.soft_error = Some(e),
        }
        self.events += 1;
    }

    // --- timers --------------------------------------------------------------

    fn retransmit_first(&mut self, h: Handle) {
        let Ok(t) = self.tcb(h) else { return };
        // Go back: everything after snd_una is resent as the window allows.
        t.snd_nxt = t.snd_una;
        t.fin_sent = false;
        t.timing = None;
        let probe = t.snd_wnd == 0 && !t.send.is_empty();
        if probe {
            // Zero-window probe: one byte past the window.
            t.snd_wnd = 1;
        }
        self.tcp_output(h);
    }

    /// TCP timers; returns the earliest next deadline.
    pub(super) fn tcp_timers(&mut self, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        for h in 0..self.tcp.len() {
            let Some(t) = self.tcp[h].as_mut() else { continue };
            if let Some(d) = t.deadline
                && now >= d
            {
                // TIME-WAIT or an orphan's FIN-WAIT-2 ran out.
                if t.orphan || t.state == State::TimeWait {
                    if t.orphan {
                        self.tcp[h] = None;
                    } else {
                        t.state = State::Closed;
                        t.deadline = None;
                    }
                    self.events += 1;
                    continue;
                }
            }
            if let Some(d) = t.rtx_deadline
                && now >= d
            {
                t.retries += 1;
                let limit =
                    if matches!(t.state, State::SynSent | State::SynReceived) { SYN_RETRIES } else { DATA_RETRIES };
                if t.retries > limit {
                    t.error = Some(t.soft_error.take().unwrap_or(Error::TimedOut));
                    t.state = State::Closed;
                    t.rtx_deadline = None;
                    t.send.clear();
                    if t.orphan || t.parent.is_some() {
                        self.tcp[h] = None;
                    }
                    self.events += 1;
                    continue;
                }
                t.rto = (t.rto * 2).min(RTO_MAX_MS);
                t.rtx_deadline = Some(now + t.rto);
                t.ssthresh = (t.in_flight() / 2).max(2 * t.mss);
                t.cwnd = t.mss;
                // The receiver may have dropped what it reported (RFC 2018 §8).
                t.sacked.clear();
                match t.state {
                    State::SynSent => self.send_syn(h, false),
                    State::SynReceived => self.send_syn(h, true),
                    _ => self.retransmit_first(h),
                }
            }
            let Some(t) = self.tcp[h].as_mut() else { continue };
            if t.delack.is_some_and(|d| now >= d) {
                self.send_ack(h);
            }
            let Some(t) = self.tcp[h].as_mut() else { continue };
            // Keep-alive: probes after the idle time, then every interval;
            // too many unanswered end the connection.
            let keep = t.keepalive
                && matches!(t.state, State::Established | State::CloseWait)
                && t.send.is_empty()
                && t.in_flight() == 0;
            let keep_due = keep.then(|| t.last_heard + t.keep_idle + u64::from(t.keep_sent) * t.keep_intvl);
            if let Some(due) = keep_due
                && now >= due
            {
                if t.keep_sent >= t.keep_cnt {
                    t.error = Some(Error::TimedOut);
                    t.state = State::Closed;
                    self.send_flags(h, RST | ACK);
                    if self.tcp[h].as_ref().is_some_and(|t| t.orphan) {
                        self.tcp[h] = None;
                    }
                    self.events += 1;
                    continue;
                }
                t.keep_sent += 1;
                self.send_keepalive(h);
            }
            let Some(t) = self.tcp[h].as_ref() else { continue };
            let keep_next = keep.then(|| t.last_heard + t.keep_idle + u64::from(t.keep_sent) * t.keep_intvl);
            for d in [t.deadline, t.rtx_deadline, t.delack, keep_next].into_iter().flatten() {
                next = Some(next.map_or(d, |n| n.min(d)));
            }
        }
        next
    }
}
