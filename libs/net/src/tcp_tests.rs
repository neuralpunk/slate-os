// SPDX-License-Identifier: MIT OR Apache-2.0

//! TCP between stacks on a simulated (optionally lossy) Ethernet segment.

use alloc::vec::Vec;

use crate::tests::quiet_v6;
use crate::wire::*;
use crate::{Config, Error, PROTO_BOOT, Stack, TcpOptions, TcpState};

/// The one card each test host has.
const ETH: u32 = 2;

const A_IP: Ipv4 = Ipv4([10, 0, 0, 1]);
const B_IP: Ipv4 = Ipv4([10, 0, 0, 2]);

fn host(n: u8) -> Stack {
    let ip = Ipv4([10, 0, 0, n]);
    let mut s = Stack::new(u32::from(n) * 7919);
    s.add_interface(ETH, Mac([2, 0, 0, 0, 0, n]), 1500).unwrap();
    quiet_v6(&mut s, ETH);
    s.set_config(ETH, Some(Config { addr: ip, prefix_len: 24, gateway: None, dns: Vec::new() }), PROTO_BOOT).unwrap();
    s
}

/// A wire that drops every `drop_every`th frame (0: none).
struct Wire {
    now: u64,
    count: u64,
    drop_every: u64,
    /// Deliver each burst of frames in reverse order.
    reorder: bool,
}

impl Wire {
    fn new(drop_every: u64) -> Wire {
        Wire { now: 0, count: 0, drop_every, reorder: false }
    }

    /// Exchange frames until quiet, then advance the clock by `step` ms.
    fn run(&mut self, a: &mut Stack, b: &mut Stack, step: u64) {
        for _ in 0..200 {
            a.poll(self.now);
            b.poll(self.now);
            let (mut fa, mut fb) = (a.take_tx(), b.take_tx());
            if self.reorder {
                fa.reverse();
                fb.reverse();
            }
            if fa.is_empty() && fb.is_empty() {
                break;
            }
            for f in fa {
                self.count += 1;
                if self.drop_every == 0 || self.count % self.drop_every != 0 {
                    b.receive(f.0, &f.1, self.now);
                }
            }
            for f in fb {
                self.count += 1;
                if self.drop_every == 0 || self.count % self.drop_every != 0 {
                    a.receive(f.0, &f.1, self.now);
                }
            }
        }
        self.now += step;
    }
}

/// A connected pair: (client handle on a, server-side handle on b).
fn connect(a: &mut Stack, b: &mut Stack, w: &mut Wire, port: u16) -> (usize, usize) {
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, port).unwrap();
    b.tcp_listen(l, 8).unwrap();
    let c = a.tcp_open();
    a.tcp_connect(c, (B_IP.into(), port)).unwrap();
    for _ in 0..100 {
        w.run(a, b, 10);
        if let Ok(s) = b.tcp_accept(l) {
            assert_eq!(a.tcp_state(c).unwrap(), TcpState::Established);
            return (c, s);
        }
    }
    panic!("no connection");
}

fn same(got: &[u8], want: &[u8]) {
    let diff = got.iter().zip(want).position(|(a, b)| a != b);
    assert!(got == want, "got {} bytes, want {}; first difference at {diff:?}", got.len(), want.len());
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

/// Send `data` from (s1, h1) to (s2, h2) through the wire, reading in
/// `chunk`-sized pieces.
fn transfer(a: &mut Stack, ha: usize, b: &mut Stack, hb: usize, w: &mut Wire, data: &[u8], chunk: usize) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = alloc::vec![0u8; chunk];
    for _ in 0..200_000 {
        if sent < data.len()
            && let Ok(n) = a.tcp_send(ha, &data[sent..])
        {
            sent += n;
        }
        w.run(a, b, 5);
        while let Ok(n) = b.tcp_recv(hb, &mut buf, false) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
    }
    if got.len() != data.len() {
        std::eprintln!("sender: {}\nreceiver: {}\nnow={}", a.tcp_dump(ha), b.tcp_dump(hb), w.now);
    }
    got
}

#[test]
fn handshake_and_echo() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    assert_eq!(a.tcp_remote(c).unwrap(), Some((B_IP.into(), 80)));
    assert_eq!(b.tcp_remote(s).unwrap().unwrap().0, A_IP.into());
    assert_eq!(a.tcp_send(c, b"hello").unwrap(), 5);
    w.run(&mut a, &mut b, 1);
    let mut buf = [0u8; 64];
    assert!(b.tcp_status(s).unwrap().readable);
    assert_eq!(b.tcp_recv(s, &mut buf, true).unwrap(), 5);
    assert_eq!(b.tcp_recv(s, &mut buf, false).unwrap(), 5);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(b.tcp_recv(s, &mut buf, false), Err(Error::WouldBlock));
    b.tcp_send(s, b"world").unwrap();
    w.run(&mut a, &mut b, 1);
    assert_eq!(a.tcp_recv(c, &mut buf, false).unwrap(), 5);
    assert_eq!(&buf[..5], b"world");
}

#[test]
fn bulk_transfer_with_flow_control() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    let data = pattern(2 << 20);
    // A slow reader: small reads exercise the receive window.
    same(&transfer(&mut a, c, &mut b, s, &mut w, &data, 3000), &data);
}

#[test]
fn survives_loss() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    w.drop_every = 7;
    let data = pattern(400_000);
    same(&transfer(&mut a, c, &mut b, s, &mut w, &data, 65536), &data);
    let back = pattern(100_000);
    same(&transfer(&mut b, s, &mut a, c, &mut w, &back, 65536), &back);
    // Closing works under loss too.
    a.tcp_shutdown(c, false, true).unwrap();
    let mut buf = [0u8; 16];
    let mut eof = false;
    for _ in 0..2000 {
        w.run(&mut a, &mut b, 50);
        if b.tcp_recv(s, &mut buf, false) == Ok(0) {
            eof = true;
            break;
        }
    }
    assert!(eof);
    b.tcp_shutdown(s, false, true).unwrap();
    for _ in 0..2000 {
        w.run(&mut a, &mut b, 50);
    }
    assert_eq!(b.tcp_state(s).unwrap(), TcpState::Closed);
    assert!(matches!(a.tcp_state(c).unwrap(), TcpState::TimeWait | TcpState::Closed));
}

#[test]
fn survives_reordering() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    w.reorder = true;
    let data = pattern(500_000);
    same(&transfer(&mut a, c, &mut b, s, &mut w, &data, 65536), &data);
    w.drop_every = 11;
    same(&transfer(&mut b, s, &mut a, c, &mut w, &data, 65536), &data);
}

#[test]
fn graceful_close_and_time_wait() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    a.tcp_send(c, b"last words").unwrap();
    a.tcp_close(c); // Orphaned: FIN after the data.
    w.run(&mut a, &mut b, 1);
    let mut buf = [0u8; 64];
    assert_eq!(b.tcp_recv(s, &mut buf, false).unwrap(), 10);
    assert_eq!(b.tcp_recv(s, &mut buf, false).unwrap(), 0, "end of stream");
    assert!(b.tcp_status(s).unwrap().read_hangup);
    assert_eq!(b.tcp_state(s).unwrap(), TcpState::CloseWait);
    b.tcp_shutdown(s, false, true).unwrap();
    w.run(&mut a, &mut b, 1);
    assert_eq!(b.tcp_state(s).unwrap(), TcpState::Closed);
    // The client side sits in TIME-WAIT, then disappears.
    assert_eq!(a.tcp_state(c).unwrap(), TcpState::TimeWait);
    w.now += 31_000;
    w.run(&mut a, &mut b, 1);
    assert_eq!(a.tcp_state(c), Err(Error::BadHandle));
    // Writing after the peer is gone fails.
    assert_eq!(b.tcp_send(s, b"x"), Err(Error::BrokenPipe));
}

#[test]
fn refused_and_timed_out() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let c = a.tcp_open();
    a.tcp_connect(c, (B_IP.into(), 81)).unwrap();
    w.run(&mut a, &mut b, 1);
    let st = a.tcp_status(c).unwrap();
    assert!(st.error && st.writable);
    assert_eq!(a.tcp_take_error(c).unwrap(), Some(Error::ConnectionRefused));
    // Nobody answers at all.
    let mut lonely = host(1);
    let d = lonely.tcp_open();
    lonely.tcp_connect(d, (Ipv4([10, 0, 0, 99]).into(), 80)).unwrap();
    let mut t = 0;
    while lonely.tcp_state(d).unwrap() == TcpState::SynSent && t < 400_000 {
        lonely.poll(t);
        lonely.take_tx();
        // Make ARP succeed so SYNs go out (and are lost).
        t += 500;
    }
    assert_eq!(lonely.tcp_take_error(d).unwrap(), Some(Error::TimedOut));
}

#[test]
fn loopback_connection() {
    let mut s = Stack::new(5);
    s.add_interface(ETH, Mac([2, 0, 0, 0, 0, 1]), 1500).unwrap();
    quiet_v6(&mut s, ETH);
    let l = s.tcp_open();
    s.tcp_bind(l, Ipv4::LOCALHOST, 8080).unwrap();
    s.tcp_listen(l, 4).unwrap();
    let c = s.tcp_open();
    s.tcp_connect(c, (Ipv4::LOCALHOST.into(), 8080)).unwrap();
    s.poll(0);
    let srv = s.tcp_accept(l).unwrap();
    let data = pattern(1 << 20);
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = alloc::vec![0u8; 100_000];
    for t in 0..10_000 {
        if sent < data.len()
            && let Ok(n) = s.tcp_send(c, &data[sent..])
        {
            sent += n;
        }
        s.poll(t);
        while let Ok(n) = s.tcp_recv(srv, &mut buf, false) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
    }
    same(&got, &data);
    assert!(s.take_tx().is_empty(), "loopback traffic reached the wire");
}

#[test]
fn reset_when_closed_with_unread_data() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 80);
    a.tcp_send(c, b"unread").unwrap();
    w.run(&mut a, &mut b, 1);
    b.tcp_close(s);
    w.run(&mut a, &mut b, 1);
    assert_eq!(a.tcp_send(c, b"more"), Err(Error::ConnectionReset));
}

#[test]
fn several_connections_on_one_listener() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, 22).unwrap();
    b.tcp_listen(l, 16).unwrap();
    let clients: Vec<usize> = (0..5)
        .map(|_| {
            let c = a.tcp_open();
            a.tcp_connect(c, (B_IP.into(), 22)).unwrap();
            c
        })
        .collect();
    w.run(&mut a, &mut b, 1);
    let servers: Vec<usize> = (0..5).map(|_| b.tcp_accept(l).unwrap()).collect();
    assert_eq!(b.tcp_accept(l), Err(Error::WouldBlock));
    for (i, &c) in clients.iter().enumerate() {
        a.tcp_send(c, &[i as u8; 3]).unwrap();
    }
    w.run(&mut a, &mut b, 1);
    let mut seen: Vec<u8> = servers
        .iter()
        .map(|&s| {
            let mut buf = [0u8; 8];
            assert_eq!(b.tcp_recv(s, &mut buf, false).unwrap(), 3);
            buf[0]
        })
        .collect();
    seen.sort();
    assert_eq!(seen, [0, 1, 2, 3, 4]);
    // A second bind to the listening port fails.
    let dup = b.tcp_open();
    assert_eq!(b.tcp_bind(dup, Ipv4::UNSPECIFIED, 22), Err(Error::AddrInUse));
}

// --- ADR 0051: timestamps, SACK, delayed ACKs, Nagle, keep-alives ----------

/// Frames from `from` that carry TCP data (beyond the headers).
fn data_frames(frames: &[(u32, Vec<u8>)]) -> usize {
    frames
        .iter()
        .filter(|(_, f)| {
            get16(f, 12) == ETHERTYPE_IPV4 && {
                let h = Ipv4Header::parse(&f[ETH_HEADER..]).unwrap();
                let tcp = &f[ETH_HEADER + h.header_len..ETH_HEADER + h.total_len];
                h.proto == PROTO_TCP && tcp.len() > usize::from(tcp[12] >> 4) * 4
            }
        })
        .count()
}

fn deliver(frames: Vec<(u32, Vec<u8>)>, to: &mut Stack, now: u64) {
    for (i, f) in frames {
        to.receive(i, &f, now);
    }
}

#[test]
fn syn_options_negotiated() {
    let (mut a, mut b) = (host(1), host(2));
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, 80).unwrap();
    b.tcp_listen(l, 2).unwrap();
    let c = a.tcp_open();
    a.tcp_connect(c, (B_IP.into(), 80)).unwrap();
    a.poll(0);
    // The SYN (after the ARP exchange) offers MSS, SACK, timestamps and
    // window scaling in 20 bytes of options.
    let mut w = Wire::new(0);
    w.run(&mut a, &mut b, 10);
    let s = b.tcp_accept(l).unwrap();
    let (ia, ib) = (a.tcp_info(c).unwrap(), b.tcp_info(s).unwrap());
    assert!(ia.sack && ia.timestamps && ib.sack && ib.timestamps);
    assert_eq!(ia.mss, 1460 - 12, "the timestamp option comes out of each segment");
    assert_eq!((ia.snd_wscale, ia.rcv_wscale), (3, 3));
}

#[test]
fn maxseg_and_tos() {
    // TCP_MAXSEG before the connection caps the MSS used and announced; a
    // listener passes its cap (and IP_TOS) to what it accepts (tcp(7)).
    let (mut a, mut b) = (host(1), host(2));
    let l = b.tcp_open();
    b.tcp_bind(l, Ipv4::UNSPECIFIED, 80).unwrap();
    let mut o = b.tcp_options(l).unwrap();
    o.max_seg = Some(900);
    b.tcp_set_options(l, o).unwrap();
    b.tcp_listen(l, 2).unwrap();
    let c = a.tcp_open();
    let mut o = a.tcp_options(c).unwrap();
    (o.max_seg, o.tos) = (Some(1000), 0x10);
    a.tcp_set_options(c, o).unwrap();
    a.tcp_connect(c, (B_IP.into(), 80)).unwrap();
    let mut w = Wire::new(0);
    w.run(&mut a, &mut b, 10);
    let s = b.tcp_accept(l).unwrap();
    let (ia, ib) = (a.tcp_info(c).unwrap(), b.tcp_info(s).unwrap());
    assert_eq!((ia.mss, ib.mss), (900 - 12, 900 - 12), "the smaller cap, less the timestamp option");
    assert_eq!(b.tcp_options(s).unwrap().max_seg, Some(900));
    // The connection's segments carry the TOS byte.
    a.tcp_send(c, b"x").unwrap();
    a.poll(w.now);
    let tx = a.take_tx();
    let ip = tx.iter().map(|f| f.1.as_slice()).find(|f| f[12..14] == [0x08, 0x00]).expect("a segment");
    assert_eq!(ip[14 + 1], 0x10);
}

#[test]
fn delayed_acks() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 81);
    let now = w.now;
    // One small segment: B's ACK waits.
    a.tcp_send(c, b"one").unwrap();
    a.poll(now);
    deliver(a.take_tx(), &mut b, now);
    b.poll(now);
    assert!(b.take_tx().is_empty(), "the ACK waits for a second segment or the timer");
    b.poll(now + 39);
    assert!(b.take_tx().is_empty());
    b.poll(now + 40);
    assert_eq!(b.take_tx().len(), 1, "then it goes");
    // Two full segments: acknowledged at once.
    let now = now + 50;
    let o = a.tcp_options(c).unwrap();
    a.tcp_set_options(c, TcpOptions { nodelay: true, ..o }).unwrap();
    a.tcp_send(c, &[7u8; 2 * 1448]).unwrap();
    a.poll(now);
    let tx = a.take_tx();
    assert_eq!(data_frames(&tx), 2);
    deliver(tx, &mut b, now);
    b.poll(now);
    assert_eq!(b.take_tx().len(), 1);
    let mut buf = [0u8; 4096];
    assert_eq!(b.tcp_recv(s, &mut buf, false).unwrap(), 3 + 2 * 1448);
}

#[test]
fn nagle_and_nodelay() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, _s) = connect(&mut a, &mut b, &mut w, 82);
    let now = w.now;
    // Nagle: the second small piece waits while the first is unacknowledged.
    a.tcp_send(c, b"first").unwrap();
    a.tcp_send(c, b"second").unwrap();
    a.poll(now);
    let tx = a.take_tx();
    assert_eq!(data_frames(&tx), 1);
    deliver(tx, &mut b, now);
    b.poll(now + 40); // B's delayed ACK.
    deliver(b.take_tx(), &mut a, now + 40);
    a.poll(now + 40);
    assert_eq!(data_frames(&a.take_tx()), 1, "sent once the first was acknowledged");
    // TCP_NODELAY: small pieces go at once.
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, _s) = connect(&mut a, &mut b, &mut w, 83);
    let o = a.tcp_options(c).unwrap();
    a.tcp_set_options(c, TcpOptions { nodelay: true, ..o }).unwrap();
    a.tcp_send(c, b"first").unwrap();
    a.tcp_send(c, b"second").unwrap();
    a.poll(w.now);
    assert_eq!(data_frames(&a.take_tx()), 2);
    // TCP_CORK: small pieces wait until uncorked.
    let o = a.tcp_options(c).unwrap();
    a.tcp_set_options(c, TcpOptions { cork: true, ..o }).unwrap();
    let mut w2 = Wire::new(0);
    w2.now = w.now;
    w2.run(&mut a, &mut b, 100);
    a.tcp_send(c, b"corked").unwrap();
    a.poll(w2.now);
    assert_eq!(data_frames(&a.take_tx()), 0);
    a.tcp_set_options(c, TcpOptions { cork: false, ..o }).unwrap();
    assert_eq!(data_frames(&a.take_tx()), 1);
}

#[test]
fn keepalive_probes() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, _s) = connect(&mut a, &mut b, &mut w, 84);
    let o = a.tcp_options(c).unwrap();
    assert!(!o.keepalive && (o.keep_idle, o.keep_intvl, o.keep_cnt) == (7200, 75, 9));
    a.tcp_set_options(c, TcpOptions { keepalive: true, keep_idle: 2, keep_intvl: 1, keep_cnt: 3, ..o }).unwrap();
    // A peer that answers: probes come and go, the connection stays.
    for _ in 0..100 {
        w.run(&mut a, &mut b, 100);
    }
    assert_eq!(a.tcp_state(c).unwrap(), TcpState::Established);
    // A peer that is gone: after the idle time and three probes, the
    // connection ends with ETIMEDOUT.
    let start = w.now;
    let mut probes = 0;
    let mut t = start;
    while t < start + 10_000 {
        a.poll(t);
        probes += a.take_tx().len();
        t += 100;
    }
    assert_eq!(probes, 4, "three probes, then a reset");
    assert_eq!(a.tcp_take_error(c).unwrap(), Some(Error::TimedOut));
}

#[test]
fn sack_resends_only_the_hole() {
    let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
    let (c, s) = connect(&mut a, &mut b, &mut w, 85);
    let o = a.tcp_options(c).unwrap();
    a.tcp_set_options(c, TcpOptions { nodelay: true, ..o }).unwrap();
    let data = pattern(20 * 1448);
    let mut now = w.now;
    let mut sent = 0;
    let mut data_out = 0;
    let mut first = true;
    let mut got = Vec::new();
    let mut buf = alloc::vec![0u8; 65536];
    for _ in 0..2000 {
        if sent < data.len()
            && let Ok(n) = a.tcp_send(c, &data[sent..])
        {
            sent += n;
        }
        a.poll(now);
        let mut tx = a.take_tx();
        data_out += data_frames(&tx);
        if first && data_frames(&tx) > 3 {
            // Lose the third data segment once.
            let mut k = 0;
            tx.retain(|f| {
                let d = data_frames(core::slice::from_ref(f)) == 1;
                if d {
                    k += 1;
                }
                !(d && k == 3)
            });
            first = false;
        }
        deliver(tx, &mut b, now);
        b.poll(now);
        deliver(b.take_tx(), &mut a, now);
        while let Ok(n) = b.tcp_recv(s, &mut buf, false) {
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
        now += 10;
    }
    same(&got, &data);
    assert_eq!(data_out, 21, "twenty segments and the one that was lost again");
}

#[test]
fn socket_table_lists_tcp_and_udp() {
    let (mut a, mut b) = (host(1), host(2));
    let mut w = Wire::new(0);
    let (c, s) = connect(&mut a, &mut b, &mut w, 22);
    a.tcp_send(c, b"hello").unwrap();
    assert_eq!(a.socket_table().iter().find(|e| e.tcp).map(|e| e.tx_queue), Some(5));
    for _ in 0..5 {
        w.run(&mut a, &mut b, 50); // past the delayed ACK
    }
    let t = b.socket_table();
    let listener = t.iter().find(|e| e.state == Some(TcpState::Listen)).unwrap();
    assert_eq!((listener.local, listener.remote, listener.tx_queue), ((Ipv4::UNSPECIFIED.into(), 22), None, 8));
    let conn = t.iter().find(|e| e.state == Some(TcpState::Established)).unwrap();
    assert_eq!(conn.local, (B_IP.into(), 22));
    assert_eq!(conn.remote.map(|r| r.0), Some(A_IP.into()));
    assert_eq!(conn.rx_queue, 5);
    b.tcp_close(s);
    let u = a.udp_open();
    a.bind(u, Ipv4::UNSPECIFIED, 53).unwrap();
    let t = a.socket_table();
    assert!(t.iter().any(|e| !e.tcp && e.local == (Ipv4::UNSPECIFIED.into(), 53) && e.state.is_none()));
    assert!(t.iter().any(|e| e.tcp && e.state == Some(TcpState::Established) && e.tx_queue == 0));
}

/// TCP segmentation offload (ADR 0083): with a card that segments up to
/// 64000 bytes, a's sends leave as large segments marked with the MSS;
/// cut up as the card would ([`segment_tcp4`]), every frame fits the wire
/// with valid checksums, and b receives the data in order (also with
/// losses, which are retransmitted).
#[test]
fn segmentation_offload() {
    for drop_every in [0, 23] {
        let (mut a, mut b, mut w) = (host(1), host(2), Wire::new(0));
        let (c, s) = connect(&mut a, &mut b, &mut w, 80);
        a.set_offload(ETH, 64_000).unwrap();
        let data = pattern(300_000);
        assert_eq!(a.tcp_send(c, &data[..60_000]).unwrap(), 60_000);
        a.poll(w.now);
        let large = a.take_tx_offload();
        assert!(
            large.iter().any(|f| f.2 > 0 && f.1.len() > 1514),
            "no large segment: {:?}",
            large.iter().map(|f| (f.1.len(), f.2)).collect::<Vec<_>>()
        );
        let mut delivered = 0;
        for (i, f, tso) in large {
            for piece in segment_tcp4(&f, usize::from(tso)) {
                assert!(piece.len() <= 1514, "a {}-byte frame", piece.len());
                let ip = &piece[ETH_HEADER..];
                assert_eq!(checksum(&ip[..20]), 0, "IPv4 header checksum");
                let tcp = &ip[20..];
                let src = Ipv4(ip[12..16].try_into().unwrap());
                let dst = Ipv4(ip[16..20].try_into().unwrap());
                assert_eq!(finish(sum(pseudo_sum(src, dst, PROTO_TCP, tcp.len()), tcp)), 0, "TCP checksum");
                delivered += 1;
                b.receive(i, &piece, w.now);
            }
        }
        // Slow start: the first window is ten segments (RFC 6928).
        assert!(delivered >= 10, "{delivered} frames");
        // The rest through the (lossy) wire, which cuts up as take_tx does.
        w.drop_every = drop_every;
        let mut got = Vec::new();
        let mut buf = alloc::vec![0u8; 100_000];
        for _ in 0..10_000 {
            w.run(&mut a, &mut b, 5);
            while let Ok(n) = b.tcp_recv(s, &mut buf, false) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if got.len() >= 60_000 {
                break;
            }
        }
        same(&got, &data[..60_000]);
        let rest = transfer(&mut a, c, &mut b, s, &mut w, &data[60_000..], 8192);
        same(&rest, &data[60_000..]);
    }
}
