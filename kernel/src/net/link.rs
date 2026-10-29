// SPDX-License-Identifier: MIT OR Apache-2.0

//! Network interfaces besides loopback (ADR 0131): network cards, taps
//! (tun.rs), veth pairs, bridges and dummies. Each belongs to one network
//! namespace at a time, under an index unique there (loopback is 1 in
//! every namespace, the others count up from 2), and is an interface of
//! that namespace's stack. Interfaces move between namespaces (keeping
//! their index when it is free there); a namespace that ends gives its
//! cards back to the initial one and takes its virtual interfaces with it.
//!
//! What a veth end sends, its peer receives. Those frames wait in an
//! inbox that the network thread empties, so two namespaces answering
//! each other never recurse. A bridge is a switch between its ports
//! (interfaces of its namespace whose master it is): it learns which port
//! each source address is behind, sends a frame for a known address out
//! of that port only and floods the others, and passes frames for its own
//! address (and broadcasts) up to its own interface, which the stack
//! sends through it. A port's own interface receives nothing.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use slate_net::{IfIndex, LOOPBACK, Mac};

use super::NetDevice;
use crate::abi::linux::errno::*;
use crate::sync::IrqSpinLock;

/// What an interface is.
pub enum Kind {
    /// A network card, through its driver.
    Card(Arc<dyn NetDevice>),
    /// A tap: its other end is an open /dev/net/tun.
    Tap(Arc<super::tun::Tap>),
    /// One end of a veth pair.
    Veth(IrqSpinLock<Weak<Link>>),
    /// A bridge, with where it saw each source address: the port's index
    /// and when (ms).
    Bridge(IrqSpinLock<BTreeMap<[u8; 6], (IfIndex, u64)>>),
    /// Sends nowhere, receives nothing.
    Dummy,
}

impl Kind {
    /// The kind's name, as IFLA_INFO_KIND gives it (none for cards).
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Kind::Card(_) => None,
            Kind::Tap(_) => Some("tun"),
            Kind::Veth(_) => Some("veth"),
            Kind::Bridge(_) => Some("bridge"),
            Kind::Dummy => Some("dummy"),
        }
    }
}

/// A network interface.
pub struct Link {
    pub kind: Kind,
    /// Its namespace and its index there (they change together).
    place: IrqSpinLock<(u64, IfIndex)>,
    name: IrqSpinLock<String>,
    mac: IrqSpinLock<Mac>,
    /// The bridge it is a port of (the bridge's index), 0 for none.
    master: AtomicU32,
    /// IFF_UP.
    up: AtomicBool,
    /// It has a link (a card's as last seen).
    carrier: AtomicBool,
    /// Deleted, or its namespace ended.
    gone: AtomicBool,
    /// For /proc/net/dev: rx frames, rx bytes, tx frames, tx bytes.
    pub counters: [AtomicU64; 4],
}

impl Link {
    pub fn place(&self) -> (u64, IfIndex) {
        *self.place.lock()
    }
    pub fn ns(&self) -> u64 {
        self.place().0
    }
    pub fn index(&self) -> IfIndex {
        self.place().1
    }
    pub fn name(&self) -> String {
        self.name.lock().clone()
    }
    pub fn mac(&self) -> Mac {
        *self.mac.lock()
    }
    pub fn master(&self) -> IfIndex {
        self.master.load(Ordering::Acquire)
    }
    pub fn up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
    pub fn carrier(&self) -> bool {
        self.carrier.load(Ordering::Acquire)
    }
    fn gone(&self) -> bool {
        self.gone.load(Ordering::Acquire)
    }
    /// The other end of a veth pair.
    pub fn peer(&self) -> Option<Arc<Link>> {
        match &self.kind {
            Kind::Veth(p) => p.lock().upgrade().filter(|p| !p.gone()),
            _ => None,
        }
    }
    pub fn is_card(&self) -> bool {
        matches!(self.kind, Kind::Card(_))
    }
    fn count(&self, rx: bool, bytes: usize) {
        let k = if rx { 0 } else { 2 };
        self.counters[k].fetch_add(1, Ordering::Relaxed);
        self.counters[k + 1].fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Send a frame out of this interface: the stack's (`tso`, a large
    /// TCP segment's payload size for a card to cut up, or 0), or one a
    /// bridge passes on.
    pub fn transmit(self: &Arc<Self>, frame: Vec<u8>, tso: u16) {
        if self.gone() {
            return;
        }
        match &self.kind {
            Kind::Card(dev) => {
                if tso > 0 && dev.tso() > 0 && dev.send_large(&frame, tso) {
                    // Counted as the frames the card makes of it.
                    let (frames, bytes) = slate_net::wire::segmented_size(&frame, usize::from(tso));
                    self.counters[2].fetch_add(frames as u64, Ordering::Relaxed);
                    self.counters[3].fetch_add(bytes as u64, Ordering::Relaxed);
                    return;
                }
                for f in pieces(frame, tso) {
                    self.count(false, f.len());
                    dev.send(&f);
                }
            }
            Kind::Tap(tap) => {
                let frames = pieces(frame, tso);
                for f in &frames {
                    self.count(false, f.len());
                }
                tap.queue(frames);
            }
            Kind::Veth(_) => {
                let Some(peer) = self.peer() else { return };
                if !self.up() || !peer.up() {
                    return;
                }
                let frames = pieces(frame, tso);
                {
                    let mut inbox = INBOX.lock();
                    for f in frames {
                        if inbox.len() >= INBOX_MAX {
                            break;
                        }
                        self.count(false, f.len());
                        inbox.push_back((peer.clone(), f));
                    }
                }
                super::wake();
            }
            Kind::Bridge(fdb) => {
                for f in pieces(frame, tso) {
                    self.count(false, f.len());
                    let to = (f[0] & 1 == 0)
                        .then(|| fdb.lock().get(&dst_of(&f)).filter(|e| fresh(e.1)).map(|e| e.0))
                        .flatten();
                    match to.and_then(|i| port(self, i)) {
                        Some(p) => p.transmit(f, 0),
                        None => flood(self, None, &f),
                    }
                }
            }
            Kind::Dummy => self.count(false, frame.len()),
        }
    }
}

/// A frame as the wire carries it: a large TCP segment cut up.
fn pieces(frame: Vec<u8>, tso: u16) -> Vec<Vec<u8>> {
    if tso > 0 { slate_net::wire::segment_tcp4(&frame, usize::from(tso)) } else { alloc::vec![frame] }
}

fn dst_of(f: &[u8]) -> [u8; 6] {
    f[..6].try_into().unwrap()
}

/// How long a bridge remembers where an address is (ms; Linux's default
/// ageing time, 300 s, as `ip -d link` shows it).
const AGEING_MS: u64 = 300_000;
fn fresh(seen: u64) -> bool {
    super::now_ms().saturating_sub(seen) < AGEING_MS
}

/// Frames veth ends passed to their peers, for the network thread.
static INBOX: IrqSpinLock<VecDeque<(Arc<Link>, Vec<u8>)>> = IrqSpinLock::new(VecDeque::new());
/// Most frames waiting in the inbox; more are dropped.
const INBOX_MAX: usize = 4096;

/// Every interface but loopback.
static LINKS: IrqSpinLock<Vec<Arc<Link>>> = IrqSpinLock::new(Vec::new());
/// The next index to give out, by namespace (from 2).
static NEXT: IrqSpinLock<BTreeMap<u64, IfIndex>> = IrqSpinLock::new(BTreeMap::new());

pub fn all() -> Vec<Arc<Link>> {
    LINKS.lock().clone()
}

pub fn find(ns: u64, index: IfIndex) -> Option<Arc<Link>> {
    LINKS.lock().iter().find(|l| l.place() == (ns, index)).cloned()
}

pub fn by_name(ns: u64, name: &str) -> Option<Arc<Link>> {
    LINKS.lock().iter().find(|l| l.ns() == ns && *l.name.lock() == name).cloned()
}

pub fn in_ns(ns: u64) -> Vec<Arc<Link>> {
    LINKS.lock().iter().filter(|l| l.ns() == ns).cloned().collect()
}

/// A bridge's port by index.
fn port(br: &Link, index: IfIndex) -> Option<Arc<Link>> {
    let (ns, bi) = br.place();
    find(ns, index).filter(|p| p.master() == bi)
}

/// A bridge's ports.
fn ports(br: &Link) -> Vec<Arc<Link>> {
    let (ns, bi) = br.place();
    LINKS.lock().iter().filter(|l| l.ns() == ns && l.master() == bi).cloned().collect()
}

/// Send `frame` out of every port of bridge `br` that is up, but `except`.
fn flood(br: &Link, except: Option<IfIndex>, frame: &[u8]) {
    for p in ports(br) {
        if Some(p.index()) != except && p.up() {
            p.transmit(frame.to_vec(), 0);
        }
    }
}

/// Whether `name` can name an interface (netdevice(7): up to 15 bytes,
/// no slash, colon or white space; not `.` or `..`).
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && !name.bytes().any(|b| b == b'/' || b == b':' || b.is_ascii_whitespace())
}

/// `want` as a name free in namespace `ns`: a `%d` in it becomes the
/// smallest number that makes it free (as `ip link add name veth%d`).
fn free_name(links: &[Arc<Link>], ns: u64, want: &str, skip: Option<&Arc<Link>>) -> Result<String, Errno> {
    let taken = |n: &str| {
        n == "lo"
            || links.iter().any(|l| l.ns() == ns && *l.name.lock() == n && !skip.is_some_and(|s| Arc::ptr_eq(s, l)))
    };
    if want.matches("%d").count() == 1 {
        for i in 0..1024 {
            let n = want.replace("%d", &alloc::format!("{i}"));
            if !valid_name(&n) {
                return Err(EINVAL);
            }
            if !taken(&n) {
                return Ok(n);
            }
        }
        return Err(ENFILE);
    }
    if !valid_name(want) || want.contains('%') {
        return Err(EINVAL);
    }
    if taken(want) { Err(EEXIST) } else { Ok(String::from(want)) }
}

/// An index free in namespace `ns`: `want` if it is.
fn free_index(links: &[Arc<Link>], ns: u64, want: Option<IfIndex>) -> IfIndex {
    let used = |i: IfIndex| i == LOOPBACK || links.iter().any(|l| l.place() == (ns, i));
    let mut next = NEXT.lock();
    let n = next.entry(ns).or_insert(2);
    let index = match want {
        Some(w) if w > LOOPBACK && !used(w) => w,
        _ => {
            while used(*n) {
                *n += 1;
            }
            *n
        }
    };
    *n = (*n).max(index + 1);
    index
}

/// Make an interface in namespace `ns` (down unless `up`).
pub fn create(kind: Kind, ns: u64, name: &str, mac: Mac, mtu: usize, up: bool) -> Result<Arc<Link>, Errno> {
    let link = {
        let mut links = LINKS.lock();
        let name = free_name(&links, ns, name, None)?;
        let index = free_index(&links, ns, None);
        let l = Arc::new(Link {
            kind,
            place: IrqSpinLock::new((ns, index)),
            name: IrqSpinLock::new(name),
            mac: IrqSpinLock::new(mac),
            master: AtomicU32::new(0),
            up: AtomicBool::new(up),
            carrier: AtomicBool::new(false),
            gone: AtomicBool::new(false),
            counters: [const { AtomicU64::new(0) }; 4],
        });
        links.push(l.clone());
        l
    };
    let (index, name) = (link.index(), link.name());
    let tso = if let Kind::Card(d) = &link.kind { d.tso() } else { 0 };
    super::with_stack_in(ns, |st| {
        let _ = st.add_interface(index, mac, mtu);
        let _ = st.set_ifname(index, name.as_bytes());
        let _ = st.set_offload(index, tso);
        let _ = st.set_up(index, up);
    });
    if let Kind::Tap(t) = &link.kind {
        t.up.store(up, Ordering::Release);
    }
    refresh(&link);
    Ok(link)
}

/// Make a veth pair: `a` in namespace `ns_a`, its peer `b` in `ns_b`.
pub fn create_veth(
    a: (u64, &str, Option<Mac>, usize, bool),
    b: (u64, &str, Option<Mac>, usize, bool),
) -> Result<(Arc<Link>, Arc<Link>), Errno> {
    let first = create(Kind::Veth(IrqSpinLock::new(Weak::new())), a.0, a.1, a.2.unwrap_or_else(random_mac), a.3, a.4)?;
    let second = match create(
        Kind::Veth(IrqSpinLock::new(Arc::downgrade(&first))),
        b.0,
        b.1,
        b.2.unwrap_or_else(random_mac),
        b.3,
        b.4,
    ) {
        Ok(s) => s,
        Err(e) => {
            remove(&first);
            return Err(e);
        }
    };
    if let Kind::Veth(p) = &first.kind {
        *p.lock() = Arc::downgrade(&second);
    }
    refresh(&first);
    refresh(&second);
    Ok((first, second))
}

/// A locally administered unicast address for a new interface.
pub fn random_mac() -> Mac {
    let mut m = [0u8; 6];
    crate::random::fill(&mut m);
    m[0] = (m[0] & 0xFE) | 0x02;
    Mac(m)
}

/// Take an interface out of the list and its stack.
fn remove(link: &Arc<Link>) {
    if link.gone.swap(true, Ordering::AcqRel) {
        return;
    }
    LINKS.lock().retain(|l| !Arc::ptr_eq(l, link));
    let (ns, index) = link.place();
    super::with_stack_in(ns, |st| st.remove_interface(index));
    if let Some(p) = link.peer() {
        refresh(&p);
    }
    if let Some(b) = master_of(link) {
        refresh(&b);
    }
}

/// Delete an interface (`ip link del`): a veth pair goes whole, a
/// bridge's ports are let go first; a tap goes (its file, if one is
/// open, reads and writes nothing more). Cards can't be deleted.
pub fn delete(link: &Arc<Link>) -> Result<(), Errno> {
    match &link.kind {
        Kind::Card(_) => return Err(EOPNOTSUPP),
        Kind::Tap(_) => remove(link),
        Kind::Veth(_) => {
            let peer = link.peer();
            remove(link);
            if let Some(p) = peer {
                remove(&p);
            }
        }
        Kind::Bridge(_) => {
            for p in ports(link) {
                p.master.store(0, Ordering::Release);
            }
            remove(link);
        }
        Kind::Dummy => remove(link),
    }
    Ok(())
}

/// The tap's file was closed.
pub fn close_tap(link: &Arc<Link>) {
    remove(link);
}

fn master_of(link: &Link) -> Option<Arc<Link>> {
    match link.master() {
        0 => None,
        m => find(link.ns(), m).filter(|b| matches!(b.kind, Kind::Bridge(_))),
    }
}

/// Make `link` a port of the bridge with index `master` in its namespace
/// (0: of none).
pub fn set_master(link: &Arc<Link>, master: IfIndex) -> Result<(), Errno> {
    if master == 0 {
        let old = master_of(link);
        link.master.store(0, Ordering::Release);
        if let Some(b) = old {
            refresh(&b);
        }
        return Ok(());
    }
    let br = find(link.ns(), master).ok_or(ENODEV)?;
    if !matches!(br.kind, Kind::Bridge(_)) {
        return Err(EOPNOTSUPP);
    }
    if Arc::ptr_eq(&br, link) || matches!(link.kind, Kind::Bridge(_)) {
        return Err(ELOOP);
    }
    let old = master_of(link);
    link.master.store(master, Ordering::Release);
    if let Some(b) = old {
        refresh(&b);
    }
    refresh(&br);
    Ok(())
}

/// Rename an interface (only while it is down, as on Linux).
pub fn rename(link: &Arc<Link>, name: &str) -> Result<(), Errno> {
    if *link.name.lock() == name {
        return Ok(());
    }
    if link.up() {
        return Err(EBUSY);
    }
    let name = {
        let links = LINKS.lock();
        let n = free_name(&links, link.ns(), name, Some(link))?;
        *link.name.lock() = n.clone();
        n
    };
    let (ns, index) = link.place();
    super::with_stack_in(ns, |st| st.set_ifname(index, name.as_bytes())).ok();
    super::announce_link(ns, index);
    Ok(())
}

/// A new hardware address for a virtual interface.
pub fn set_mac(link: &Arc<Link>, mac: Mac) -> Result<(), Errno> {
    if link.is_card() || mac.0[0] & 1 != 0 {
        return Err(if link.is_card() { EOPNOTSUPP } else { EADDRNOTAVAIL });
    }
    *link.mac.lock() = mac;
    let (ns, index) = link.place();
    super::with_stack_in(ns, |st| {
        let mtu = st.mtu(index).unwrap_or(1500);
        st.set_link(index, mac, mtu)
    })
    .map_err(super::socket::errno)
}

/// Move `link` to namespace `ns` (as `ip link set X netns N`), named
/// `name` there if given. It arrives down, keeping its index if that is
/// free there; it stops being a bridge's port (and a bridge loses its
/// ports).
pub fn move_to(link: &Arc<Link>, ns: u64, name: Option<&str>) -> Result<(), Errno> {
    let (old_ns, old_index) = link.place();
    if old_ns == ns {
        return name.map_or(Ok(()), |n| rename(link, n));
    }
    let mtu = super::with_stack_in(old_ns, |st| st.mtu(old_index)).unwrap_or(1500);
    let (index, name) = {
        let links = LINKS.lock();
        let want = name.map_or_else(|| link.name(), String::from);
        let name = free_name(&links, ns, &want, Some(link))?;
        let index = free_index(&links, ns, Some(old_index));
        *link.place.lock() = (ns, index);
        *link.name.lock() = name.clone();
        (index, name)
    };
    let old_master = link.master.swap(0, Ordering::AcqRel);
    if matches!(link.kind, Kind::Bridge(_)) {
        for p in LINKS.lock().iter().filter(|l| l.ns() == old_ns && l.master() == old_index) {
            p.master.store(0, Ordering::Release);
        }
    }
    link.up.store(false, Ordering::Release);
    if let Kind::Tap(t) = &link.kind {
        t.up.store(false, Ordering::Release);
    }
    super::with_stack_in(old_ns, |st| st.remove_interface(old_index));
    let (mac, tso) = (link.mac(), if let Kind::Card(d) = &link.kind { d.tso() } else { 0 });
    super::with_stack_in(ns, |st| {
        let _ = st.add_interface(index, mac, mtu);
        let _ = st.set_ifname(index, name.as_bytes());
        let _ = st.set_offload(index, tso);
        let _ = st.set_up(index, false);
    });
    refresh(link);
    if let Some(p) = link.peer() {
        refresh(&p);
    }
    if old_master != 0
        && let Some(b) = find(old_ns, old_master)
    {
        refresh(&b);
    }
    Ok(())
}

/// Bring an interface up or down (IFF_UP); its peer's and its bridge's
/// links follow.
pub fn set_up(link: &Arc<Link>, up: bool) {
    link.up.store(up, Ordering::Release);
    if let Kind::Tap(t) = &link.kind {
        t.up.store(up, Ordering::Release);
    }
    refresh(link);
    if let Some(p) = link.peer() {
        refresh(&p);
    }
    if let Some(b) = master_of(link) {
        refresh(&b);
    }
}

/// Work out whether `link` has a link (a veth end when both ends are up, a
/// bridge when a port has one) and tell its stack.
pub fn refresh(link: &Arc<Link>) {
    if link.gone() {
        return;
    }
    let carrier = match &link.kind {
        Kind::Card(d) => d.link_up(),
        Kind::Tap(_) | Kind::Dummy => true,
        Kind::Veth(_) => link.up() && link.peer().is_some_and(|p| p.up()),
        Kind::Bridge(_) => ports(link).iter().any(|p| p.up() && p.carrier()),
    };
    let was = link.carrier.swap(carrier, Ordering::AcqRel);
    let (ns, index) = link.place();
    super::with_stack_in(ns, |st| st.set_carrier(index, carrier)).ok();
    // A port's link is part of its bridge's.
    if was != carrier
        && let Some(b) = master_of(link)
    {
        refresh(&b);
    }
}

/// A card's link changed: its bridge's may have too.
pub fn card_carrier(link: &Arc<Link>, up: bool) {
    link.carrier.store(up, Ordering::Release);
    let (ns, index) = link.place();
    super::with_stack_in(ns, |st| st.set_carrier(index, up)).ok();
    if let Some(b) = master_of(link) {
        refresh(&b);
    }
}

/// Frames that arrived on `link`: to the bridge it is a port of, or to its
/// namespace's stack. Nothing arrives on an interface that is down.
pub fn input(link: &Arc<Link>, frames: Vec<Vec<u8>>) {
    if frames.is_empty() || link.gone() || !link.up() {
        return;
    }
    for f in &frames {
        link.count(true, f.len());
    }
    if let Some(br) = master_of(link) {
        for f in frames {
            bridge_in(&br, link, f);
        }
        return;
    }
    let (ns, index) = link.place();
    let now = super::now_ms();
    super::with_stack_in(ns, |st| {
        // Arrival times for SO_TIMESTAMPNS, finer than the stack's ms.
        st.clock_ns = crate::time::monotonic_ns();
        st.wall_ms = super::wall_ms();
        for f in &frames {
            st.receive(index, f, now);
        }
    });
}

/// A frame that arrived on `port` of bridge `br`.
fn bridge_in(br: &Arc<Link>, port: &Arc<Link>, frame: Vec<u8>) {
    let Kind::Bridge(fdb) = &br.kind else { return };
    if frame.len() < 14 || !br.up() {
        return;
    }
    let (dst, src) = (dst_of(&frame), <[u8; 6]>::try_from(&frame[6..12]).unwrap());
    if src[0] & 1 == 0 {
        fdb.lock().insert(src, (port.index(), super::now_ms()));
    }
    let group = dst[0] & 1 != 0;
    let mine = dst == br.mac().0;
    if !mine {
        let to = if group { None } else { fdb.lock().get(&dst).filter(|e| fresh(e.1)).map(|e| e.0) };
        match to {
            // It stays on the segment it came from.
            Some(i) if i == port.index() => {}
            Some(i) => {
                if let Some(p) = self::port(br, i) {
                    p.transmit(frame.clone(), 0);
                }
            }
            None => flood(br, Some(port.index()), &frame),
        }
    }
    if mine || group {
        br.count(true, frame.len());
        let (ns, index) = br.place();
        let now = super::now_ms();
        super::with_stack_in(ns, |st| st.receive(index, &frame, now));
    }
}

/// Deliver what veth ends passed to their peers (the network thread).
pub fn drain() {
    for _ in 0..64 {
        let batch: Vec<(Arc<Link>, Vec<u8>)> = INBOX.lock().drain(..).collect();
        if batch.is_empty() {
            return;
        }
        // Frames in a row for one interface go in together.
        let mut run: Option<(Arc<Link>, Vec<Vec<u8>>)> = None;
        for (l, f) in batch {
            match &mut run {
                Some((r, frames)) if Arc::ptr_eq(r, &l) => frames.push(f),
                _ => {
                    if let Some((r, frames)) = run.take() {
                        input(&r, frames);
                    }
                    run = Some((l, alloc::vec![f]));
                }
            }
        }
        if let Some((r, frames)) = run {
            input(&r, frames);
        }
    }
    // Still more: come back after the others had their turn.
    if !INBOX.lock().is_empty() {
        super::wake();
    }
}

/// Network namespace `ns` ended: its cards go back to the initial
/// namespace (renamed `dev%d` if their name is taken there), its other
/// interfaces go (a veth with its peer).
pub fn namespace_ended(ns: u64) {
    for l in in_ns(ns) {
        match &l.kind {
            Kind::Card(_) => {
                if move_to(&l, 0, None).is_err() {
                    let _ = move_to(&l, 0, Some("dev%d"));
                }
            }
            Kind::Veth(_) => {
                let _ = delete(&l);
            }
            _ => remove(&l),
        }
    }
    NEXT.lock().remove(&ns);
}
