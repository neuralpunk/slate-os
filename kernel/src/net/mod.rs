// SPDX-License-Identifier: MIT OR Apache-2.0

//! Networking: the slate-net protocol stack on the network cards, run by
//! a kernel thread (ADR 0017, ADR 0048).
//!
//! There is one stack per network namespace (ADR 0028). Each has the
//! loopback interface (index 1) and the namespace's other interfaces
//! (link.rs, ADR 0131): network cards start in the initial namespace
//! (`eth0` is index 2, then in the order the cards registered), and taps,
//! veth pairs, bridges and dummies are made where they are asked for.
//! Sockets use the stack of the namespace they were created in.
//!
//! User space (netd) configures the cards over netlink. Until it first
//! does, the kernel configures one card itself as a fallback: DHCP or
//! `slate.ip=`, on the card `slate.net=` names or the first with a link,
//! like Linux's `ip=dhcp` autoconfiguration (the results appear in
//! /proc/net/pnp).
//!
//! Driver interrupts and socket calls wake the network thread, which feeds
//! received frames to the stack and runs its timers.

mod ioctl;
pub mod link;
pub mod netlink;
pub mod packet;
pub mod socket;
pub mod tcp;
pub mod tun;
pub mod uevent;
pub mod unix;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use slate_net::{Change, IfIndex, IfInfo, Ipv4, LOOPBACK, Mac, Stack};

use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;
use crate::{log_info, time};

/// A network interface driver.
pub trait NetDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mac(&self) -> Mac;
    fn mtu(&self) -> usize;
    /// Queue a frame for transmission (dropped if the device is full).
    fn send(&self, frame: &[u8]);
    /// Frames received since the last call.
    fn receive(&self) -> Vec<Vec<u8>>;
    /// A cable is plugged in and the link negotiated.
    fn link_up(&self) -> bool {
        true
    }
    /// The largest TCP payload the card segments itself (TCP segmentation
    /// offload, ADR 0083); 0 if it does not.
    fn tso(&self) -> usize {
        0
    }
    /// Queue a large TCP segment over IPv4 for the card to cut into
    /// segments of `mss` payload bytes; false if it cannot (it is then cut
    /// up in software).
    fn send_large(&self, _frame: &[u8], _mss: u16) -> bool {
        false
    }
}

/// A namespace's stack, and its event count when sockets were last told.
struct NsStack {
    stack: Stack,
    last_events: u64,
}

/// The stacks, by network namespace id (0: the initial namespace).
static STACKS: IrqSpinLock<BTreeMap<u64, NsStack>> = IrqSpinLock::new(BTreeMap::new());
/// Network cards registered so far (for their names: eth0, eth1...).
static CARD_COUNT: AtomicU32 = AtomicU32::new(0);
/// Whether the kernel still configures a card itself (until user space
/// changes the initial namespace's configuration).
static AUTO: AtomicBool = AtomicBool::new(true);
/// The card the kernel configured (0: none).
static AUTO_CARD: AtomicU32 = AtomicU32::new(0);
static PENDING: AtomicBool = AtomicBool::new(false);
/// A card's link may have changed (a device went away, a notification
/// came): the network thread checks links now rather than at its next
/// half-second check.
static LINKS_CHANGED: AtomicBool = AtomicBool::new(false);
static WORKER: WaitQueue = WaitQueue::new();

/// The stacks' clock (ms; what `RecvMeta::at` counts).
pub(crate) fn now_ms() -> u64 {
    time::monotonic_ns() / 1_000_000
}

fn seed() -> u32 {
    let mut b = [0u8; 4];
    crate::random::fill(&mut b);
    u32::from_le_bytes(b) | 1
}

/// The calling process's network namespace.
pub fn current_ns() -> Arc<crate::proc::ns::NetNs> {
    crate::proc::current().map_or_else(|| crate::proc::ns::initial().net, |p| p.namespaces().net)
}

/// Run `f` on the calling process's namespace's stack.
pub fn with_stack<R>(f: impl FnOnce(&mut Stack) -> R) -> R {
    with_stack_in(current_ns().id, f)
}

/// The initial namespace's card with index `index`.
fn card(index: IfIndex) -> Option<Arc<link::Link>> {
    link::find(0, index).filter(|l| l.is_card())
}

/// Every card, wherever it is.
fn cards() -> Vec<Arc<link::Link>> {
    link::all().into_iter().filter(|l| l.is_card()).collect()
}

/// Run `f` on namespace `ns`'s stack, then transmit what it produced,
/// announce configuration changes and wake anyone waiting on sockets if
/// something changed.
pub fn with_stack_in<R>(ns: u64, f: impl FnOnce(&mut Stack) -> R) -> R {
    let (r, tx, changes, changed) = {
        let mut guard = STACKS.lock();
        // A new namespace's loopback starts down, as on Linux (ADR 0114).
        let e = guard.entry(ns).or_insert_with(|| NsStack {
            stack: if ns == 0 { Stack::new(seed()) } else { Stack::new_namespace(seed()) },
            last_events: 0,
        });
        let r = f(&mut e.stack);
        // Deliver loopback traffic right away.
        e.stack.clock_ns = crate::time::monotonic_ns();
        e.stack.wall_ms = wall_ms();
        e.stack.poll(now_ms());
        let changed = e.last_events != e.stack.events;
        e.last_events = e.stack.events;
        // Changes go out with the interface as it is now.
        let changes: Vec<(Change, Option<IfInfo>)> = e
            .stack
            .take_changes()
            .into_iter()
            .map(|c| {
                let info = match c {
                    Change::Link(i) => e.stack.interface(i),
                    _ => None,
                };
                (c, info)
            })
            .collect();
        // Cards may segment TCP themselves (only theirs get large ones).
        let tx: Vec<(IfIndex, Vec<u8>, u16)> = e.stack.take_tx_offload();
        (r, tx, changes, changed)
    };
    // Each frame leaves through its interface.
    let mut last: Option<Arc<link::Link>> = None;
    for (index, frame, tso) in tx {
        if last.as_ref().is_none_or(|l| l.place() != (ns, index)) {
            last = link::find(ns, index);
        }
        if let Some(l) = &last {
            l.transmit(frame, tso);
        }
    }
    if !changes.is_empty() {
        netlink::announce(ns, &changes);
    }
    if changed {
        crate::fs::poll_notify();
        // New activity may have armed a timer earlier than the thread's.
        wake();
    }
    r
}

/// The name of interface `index` in namespace `ns`.
pub fn name_of(ns: u64, index: IfIndex) -> Option<String> {
    if index == LOOPBACK {
        return Some("lo".into());
    }
    link::find(ns, index).map(|l| l.name())
}

/// The index of the interface called `name` in namespace `ns`.
pub fn index_of(ns: u64, name: &str) -> Option<IfIndex> {
    if name == "lo" {
        return Some(LOOPBACK);
    }
    link::by_name(ns, name).map(|l| l.index())
}

/// Bring interface `index` of namespace `ns` up or down (netlink,
/// SIOCSIFFLAGS).
pub fn set_up(ns: u64, index: IfIndex, up: bool) -> Result<(), slate_net::Error> {
    with_stack_in(ns, |st| st.set_up(index, up))?;
    if let Some(l) = link::find(ns, index) {
        link::set_up(&l, up);
    }
    Ok(())
}

/// Tell netlink's listeners about interface `index` of namespace `ns` as
/// it is now (a change the stack doesn't see: a name, a bridge).
pub fn announce_link(ns: u64, index: IfIndex) {
    if let Some(info) = with_stack_in(ns, |st| st.interface(index)) {
        netlink::announce(ns, &[(Change::Link(index), Some(info))]);
    }
}

/// A network namespace ended: its interfaces go or move back to the
/// initial namespace, then its stack goes.
pub fn drop_ns(ns: u64) {
    link::namespace_ended(ns);
    let gone = STACKS.lock().remove(&ns);
    drop(gone);
}

/// Wake the network thread (from interrupt handlers too).
pub fn wake() {
    PENDING.store(true, Ordering::Release);
    WORKER.wake_all();
}

/// A card's link may have changed: check the links now.
pub fn links_changed() {
    LINKS_CHANGED.store(true, Ordering::Release);
    wake();
}

/// Start the network thread (loopback works without any device; TCP
/// needs its timers either way).
pub fn init() {
    with_stack(|_| ());
    // SlateOS's default-deny inbound firewall (ADR 0134), from the first
    // packet on: nothing new comes in but what slate-firewall opens.
    let off = crate::arch::boot::info().cmdline.split_ascii_whitespace().any(|w| w == "slate.firewall=off");
    if !off {
        let answers = with_stack_in(0, |st| st.firewall.netlink(&slate_net::inbound::table(), 0, 0, b"kernel"));
        match slate_net::inbound::first_error(&answers.concat()) {
            0 => log_info!("net: inbound firewall on (ADR 0134)"),
            e => crate::log_warn!("net: the inbound firewall didn't load (errno {e})"),
        }
    }
    crate::sched::spawn("net", worker);
}

/// The name the next card gets.
pub fn next_name() -> String {
    alloc::format!("eth{}", CARD_COUNT.load(Ordering::Relaxed))
}

/// The card `slate.net=` on the command line asks for.
fn pinned() -> Option<&'static str> {
    crate::arch::boot::info().cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.net="))
}

/// A network card appeared: it becomes an interface of the initial
/// namespace. The kernel configures the first one (or the pinned one)
/// unless user space has taken over.
pub fn register(dev: Arc<dyn NetDevice>, interrupts: bool) {
    if !interrupts {
        POLLED.store(true, Ordering::Relaxed);
    }
    CARD_COUNT.fetch_add(1, Ordering::Relaxed);
    with_stack_in(0, |st| st.set_hostname(b"slate"));
    let (name, mac, mtu) = (String::from(dev.name()), dev.mac(), dev.mtu());
    let card = match link::create(link::Kind::Card(dev), 0, &name, mac, mtu, true) {
        Ok(c) => c,
        Err(e) => {
            crate::log_warn!("net: no interface for {name}: {e:?}");
            return;
        }
    };
    let take = match pinned() {
        Some(p) => p == name,
        None => AUTO_CARD.load(Ordering::Relaxed) == 0,
    };
    if take {
        autoconfigure(card.index());
    }
    wake();
}

/// The kernel's fallback: configure card `index` (DHCP, or `slate.ip=`),
/// moving its configuration off the card it configured before.
fn autoconfigure(index: IfIndex) {
    if !AUTO.load(Ordering::Acquire) {
        return;
    }
    let old = AUTO_CARD.swap(index, Ordering::AcqRel);
    // `slate.ip=ADDR/PREFIX[,GATEWAY[,DNS...]]`: a fixed address instead
    // of DHCP (networks without a DHCP server).
    let fixed =
        crate::arch::boot::info().cmdline.split_ascii_whitespace().find_map(|w| w.strip_prefix("slate.ip=")).and_then(
            |v| {
                let c = slate_net::Config::parse_static(v);
                if c.is_none() {
                    crate::log_warn!("net: ignoring slate.ip={v} (want ADDR/PREFIX[,GATEWAY[,DNS...]])");
                }
                c
            },
        );
    with_stack_in(0, |st| {
        if old != 0 {
            st.stop_dhcp(old);
            let _ = st.set_config(old, None, slate_net::PROTO_DHCP);
        }
        match fixed {
            Some(c) => {
                let _ = st.set_config(index, Some(c), slate_net::PROTO_BOOT);
            }
            None => {
                let _ = st.start_dhcp(index, now_ms());
            }
        }
    });
}

/// User space changed the initial namespace's configuration: the kernel
/// stops configuring cards (its DHCP client ends; addresses stay until
/// user space changes them).
pub fn user_configured(ns: u64) {
    if ns != 0 || !AUTO.swap(false, Ordering::AcqRel) {
        return;
    }
    let index = AUTO_CARD.load(Ordering::Acquire);
    if index != 0 {
        with_stack_in(0, |st| st.stop_dhcp(index));
    }
    log_info!("net: user space configures the network now");
}

/// Move the kernel's configuration to a card with a link when its card
/// has none (unless a card is pinned). Returns whether the card changed.
fn follow_link() -> bool {
    if pinned().is_some() || !AUTO.load(Ordering::Acquire) {
        return false;
    }
    let Some(cur) = card(AUTO_CARD.load(Ordering::Acquire)) else { return false };
    if cur.carrier() {
        return false;
    }
    let next = cards().into_iter().find(|c| c.place() != cur.place() && c.ns() == 0 && c.carrier());
    match next {
        Some(c) => {
            log_info!("{} has no link; using {}", cur.name(), c.name());
            autoconfigure(c.index());
            true
        }
        None => false,
    }
}

/// Some card has no interrupts: the network thread polls them.
static POLLED: AtomicBool = AtomicBool::new(false);

/// A card registered with interrupts found that they don't come: the
/// network thread polls it from now on.
pub fn poll_cards() {
    POLLED.store(true, Ordering::Relaxed);
    wake();
}

fn worker() {
    let mut announced = 0;
    let mut last_link_check = 0;
    loop {
        PENDING.store(false, Ordering::Release);
        let now = now_ms();
        let cards = cards();
        if LINKS_CHANGED.swap(false, Ordering::AcqRel) || now.saturating_sub(last_link_check) >= 500 {
            last_link_check = now;
            for c in &cards {
                let link::Kind::Card(dev) = &c.kind else { continue };
                let up = dev.link_up();
                if c.carrier() != up {
                    link::card_carrier(c, up);
                }
            }
            if follow_link() {
                announced = 0;
            }
        }
        for c in &cards {
            let link::Kind::Card(dev) = &c.kind else { continue };
            link::input(c, dev.receive());
        }
        link::drain();
        // Every namespace's timers.
        let mut next: Option<u64> = None;
        let stacks: Vec<u64> = STACKS.lock().keys().copied().collect();
        for ns in stacks {
            if let Some(t) = with_stack_in(ns, |st| st.poll(now)) {
                next = Some(next.map_or(t, |n: u64| n.min(t)));
            }
        }
        let auto = AUTO_CARD.load(Ordering::Acquire);
        if announced != auto
            && AUTO.load(Ordering::Acquire)
            && let Some(c) = with_stack_in(0, |st| st.config(auto).cloned())
        {
            announced = auto;
            let name = name_of(0, auto).unwrap_or_default();
            log_info!("{} is {}/{} via {:?}, DNS {:?}", name, c.addr, c.prefix_len, c.gateway, c.dns);
        }
        // Sleep until the next timer (at most half a second, to follow
        // links), or 10 ms when a device must be polled.
        let mut wait_ms = next.map_or(500, |t| t.saturating_sub(now).clamp(1, 500));
        if POLLED.load(Ordering::Relaxed) {
            wait_ms = wait_ms.min(10);
        }
        let deadline = time::monotonic_ns() + wait_ms * 1_000_000;
        WORKER.wait_until_deadline(|| PENDING.load(Ordering::Acquire), deadline);
    }
}

/// The inode number an internet socket's file shows (fstat, /proc/PID/fd
/// as `socket:[N]`, /proc/net's inode column): TCP and the others count
/// their handles apart.
pub fn socket_ino(tcp: bool, handle: usize) -> u64 {
    if tcp { 0x10000 + handle as u64 } else { handle as u64 + 1 }
}

/// The user each socket of namespace `ns` belongs to, by inode: the
/// effective user of a process holding it (as the reader sees it).
fn socket_owners(ns: u64) -> BTreeMap<u64, u32> {
    let me = crate::proc::cred::current();
    let mut owners = BTreeMap::new();
    for p in crate::proc::all() {
        if p.is_zombie() || p.namespaces().net.id != ns {
            continue;
        }
        let uid = me.uid_out(p.cred().euid);
        let files: Vec<_> = p.files.lock().iter().map(|(_, f)| f.clone()).collect();
        for f in files {
            if let Ok(m) = f.stat()
                && m.mode & crate::fs::vfs::S_IFMT == crate::fs::vfs::S_IFSOCK
            {
                owners.entry(m.ino).or_insert(uid);
            }
        }
    }
    owners
}

/// /proc/net/tcp, tcp6, udp and udp6 (proc_net(5)), laid out as observed
/// on Linux: addresses as 32-bit words in host (little-endian) order in
/// hex, ports in hex, the state as Linux numbers it (observed: 01
/// established ... 0A listen, 0B closing; UDP 07 unconnected, 01
/// connected), the queues, timer fields Slate leaves at zero, then the
/// uid of a process holding the socket and its inode (0 for both when no
/// process holds it, as a connection waiting to be accepted). An AF_INET6
/// socket's IPv4 peers show as `::ffff:a.b.c.d`.
fn sockets_file(ns: u64, name: &str, s: &mut String) {
    use slate_net::{IpAddr, TcpState};
    let (tcp, v6) = (name.starts_with("tcp"), name.ends_with('6'));
    let word = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let addr = |a: IpAddr, port: u16| -> String {
        match (a, v6) {
            (IpAddr::V4(a), false) => alloc::format!("{:08X}:{port:04X}", word(&a.0)),
            (a, _) => {
                let b = match a {
                    IpAddr::V4(a) => slate_net::Ipv6::mapped(a).0,
                    IpAddr::V6(a) => a.0,
                };
                let w: String = b.chunks(4).map(|c| alloc::format!("{:08X}", word(c))).collect();
                alloc::format!("{w}:{port:04X}")
            }
        }
    };
    let unspecified = if v6 { IpAddr::V6(slate_net::Ipv6::UNSPECIFIED) } else { IpAddr::V4(Ipv4::UNSPECIFIED) };
    if v6 {
        s.push_str("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    } else {
        s.push_str(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n",
        );
    }
    let entries = with_stack_in(ns, |st| st.socket_table());
    let owners = socket_owners(ns);
    for (sl, e) in entries.iter().filter(|e| e.tcp == tcp && e.v6 == v6).enumerate() {
        let st = match e.state {
            Some(TcpState::Established) => 0x01,
            Some(TcpState::SynSent) => 0x02,
            Some(TcpState::SynReceived) => 0x03,
            Some(TcpState::FinWait1) => 0x04,
            Some(TcpState::FinWait2) => 0x05,
            Some(TcpState::TimeWait) => 0x06,
            Some(TcpState::Closed) => 0x07,
            Some(TcpState::CloseWait) => 0x08,
            Some(TcpState::LastAck) => 0x09,
            Some(TcpState::Listen) => 0x0A,
            Some(TcpState::Closing) => 0x0B,
            None if e.remote.is_some() => 0x01,
            None => 0x07,
        };
        let (ra, rp) = e.remote.unwrap_or((unspecified, 0));
        let ino = socket_ino(e.tcp, e.handle);
        let (uid, ino) = owners.get(&ino).map_or((0, 0), |&u| (u, ino));
        let _ = writeln!(
            s,
            "{sl:4}: {} {} {st:02X} {:08X}:{:08X} 00:00000000 00000000 {uid:5}        0 {ino}",
            addr(e.local.0, e.local.1),
            addr(ra, rp),
            e.tx_queue,
            e.rx_queue
        );
    }
}

/// Contents of /proc/net files.
pub fn proc_file(name: &str, s: &mut String) {
    let ns = current_ns().id;
    match name {
        "pnp" => {
            // The kernel's own configuration (ADR 0029), as Linux's ipconfig.
            if ns != 0 {
                return;
            }
            let auto = AUTO_CARD.load(Ordering::Acquire);
            let (config, lease) = with_stack_in(0, |st| (st.config(auto).cloned(), st.lease(auto).cloned()));
            if let Some(c) = &config {
                let _ = writeln!(s, "#PROTO: {}", if lease.is_some() { "DHCP" } else { "MANUAL" });
                if let Some(l) = &lease
                    && !l.domain.is_empty()
                {
                    let _ = writeln!(s, "domain {}", String::from_utf8_lossy(&l.domain));
                }
                for d in &c.dns {
                    let _ = writeln!(s, "nameserver {d}");
                }
                if let Some(l) = &lease
                    && let Some(srv) = l.server
                {
                    let _ = writeln!(s, "bootserver {srv}");
                }
            }
        }
        "dev" => {
            s.push_str("Inter-|   Receive                                                |  Transmit\n");
            s.push_str(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
            for i in with_stack_in(ns, |st| st.interfaces()) {
                let c = link::find(ns, i.index);
                let n = |k: usize| c.as_ref().map_or(0, |c| c.counters[k].load(Ordering::Relaxed));
                let _ = writeln!(
                    s,
                    "{:>6}: {:7} {:7}    0    0    0     0          0         0 {:8} {:7}    0    0    0     0       0          0",
                    name_of(ns, i.index).unwrap_or_default(),
                    n(1),
                    n(0),
                    n(3),
                    n(2)
                );
            }
        }
        "arp" => {
            // proc_net(5): address, hardware type, flags (ATF_COM 0x2 for a
            // known address, ATF_PERM 0x4 for one set by hand), hardware
            // address, mask, device; the columns as Linux aligns them.
            s.push_str("IP address       HW type     Flags       HW address            Mask     Device\n");
            for n in with_stack_in(ns, |st| st.neighbours()) {
                let flags = match (n.mac.is_some(), n.permanent) {
                    (false, _) => 0,
                    (true, false) => 2,
                    (true, true) => 6,
                };
                let mac = n.mac.map_or_else(|| alloc::format!("{:?}", Mac::default()), |m| alloc::format!("{m:?}"));
                let _ = writeln!(
                    s,
                    "{:<16} {:<11} {:<11} {:<21} {:<8} {}",
                    alloc::format!("{}", n.ip),
                    "0x1",
                    alloc::format!("{flags:#x}"),
                    mac,
                    "*",
                    name_of(ns, n.iface).unwrap_or_default()
                );
            }
        }
        "tcp" | "tcp6" | "udp" | "udp6" => sockets_file(ns, name, s),
        "if_inet6" => {
            // Every IPv6 address: the address in hex, the interface index,
            // the prefix length, the scope (0x20 link, 0x10 host, 0 global)
            // and the flags (IFA_F_*) in hex, the name (the layout observed
            // on Linux).
            for i in with_stack_in(ns, |st| st.interfaces()) {
                let name = name_of(ns, i.index).unwrap_or_default();
                for a in &i.addrs6 {
                    let hex: String = a.addr.0.iter().map(|b| alloc::format!("{b:02x}")).collect();
                    let scope = if a.addr.is_loopback() {
                        0x10
                    } else if a.addr.is_link_local() {
                        0x20
                    } else {
                        0
                    };
                    let mut flags = match a.state {
                        slate_net::AddrState::Tentative => 0x40,
                        slate_net::AddrState::Deprecated => 0x20,
                        slate_net::AddrState::Preferred => 0,
                    };
                    if a.origin != slate_net::AddrOrigin::Slaac {
                        flags |= 0x80;
                    }
                    let _ = writeln!(s, "{hex} {:02x} {:02x} {scope:02x} {flags:02x} {name:>8}", i.index, a.prefix_len);
                }
            }
        }
        "ipv6_route" => {
            // Destination and length, source and length, next hop, metric,
            // reference and use counts, flags (RTF_UP, RTF_GATEWAY), device.
            let hex = |a: slate_net::Ipv6| a.0.iter().map(|b| alloc::format!("{b:02x}")).collect::<String>();
            let zero = hex(slate_net::Ipv6::UNSPECIFIED);
            for r in with_stack_in(ns, |st| st.routes6().to_vec()) {
                let _ = writeln!(
                    s,
                    "{} {:02x} {zero} 00 {} {:08x} 00000001 00000000 {:08x} {:>8}",
                    hex(r.dst),
                    r.prefix_len,
                    r.gateway.map_or_else(|| zero.clone(), hex),
                    r.metric,
                    if r.gateway.is_some() { 3 } else { 1 },
                    name_of(ns, r.iface).unwrap_or_default()
                );
            }
        }
        "route" => {
            // Hex addresses in host (little-endian) byte order, as Linux;
            // flags RTF_UP 1, RTF_GATEWAY 2 (route(8)).
            let hex = |ip: Ipv4| u32::from_le_bytes(ip.0);
            s.push_str("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
            let routes = with_stack_in(ns, |st| st.routes().to_vec());
            for r in routes {
                let mask =
                    Ipv4::from_u32(if r.prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(r.prefix_len)) });
                let _ = writeln!(
                    s,
                    "{}\t{:08X}\t{:08X}\t{:04X}\t0\t0\t{}\t{:08X}\t0\t0\t0",
                    name_of(ns, r.iface).unwrap_or_default(),
                    hex(r.dst),
                    hex(r.gateway.unwrap_or(Ipv4::UNSPECIFIED)),
                    if r.gateway.is_some() { 3 } else { 1 },
                    r.metric,
                    hex(mask)
                );
            }
        }
        _ => {}
    }
}

/// The time of day for the stack's Timestamp options: milliseconds since
/// the Unix epoch.
pub(crate) fn wall_ms() -> u64 {
    u64::try_from(crate::time::realtime_ns() / 1_000_000).unwrap_or(0)
}
