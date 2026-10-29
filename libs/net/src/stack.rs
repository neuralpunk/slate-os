// SPDX-License-Identifier: MIT OR Apache-2.0

//! A network namespace's protocol state (ADR 0017, ADR 0048, ADR 0049): its
//! interfaces (loopback and Ethernet cards), each with its addresses, ARP
//! cache and DHCP client; the routing table; IPv4 input, output and
//! forwarding between interfaces; ICMP, UDP and ICMP sockets, TCP, and
//! packet sockets.
//!
//! The stack does no I/O and keeps no clock: the owner feeds it received
//! frames with [`Stack::receive`], calls [`Stack::poll`] with the current
//! time (milliseconds) for timers, and sends whatever [`Stack::take_tx`]
//! returns out of the interface each frame names.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use slate_bpf::SockFilter;

use crate::dhcp;
use crate::wire::*;

mod filter;
mod frag;
mod ipv6;
mod tcp;
use frag::Reassembly4;
pub use ipv6::{AddrOrigin, AddrState, If6Addr, PROTO_RA, Route6};
pub use tcp::{State as TcpState, Status as TcpStatus, TcpInfo, TcpOptions};

/// Errors from socket and configuration operations (mapped to errno by
/// the kernel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    AddrInUse,
    AddrNotAvailable,
    NetUnreachable,
    InvalidInput,
    NotConnected,
    WouldBlock,
    MessageTooLong,
    ConnectionRefused,
    ConnectionReset,
    TimedOut,
    BrokenPipe,
    AlreadyConnected,
    InProgress,
    BadHandle,
    /// No interface with that index.
    NoDevice,
    /// The address or route is already there.
    Exists,
    /// No such route.
    NotFound,
    /// An ICMP error said the host can't be reached (EHOSTUNREACH).
    HostUnreachable,
    /// An ICMP error said the protocol isn't served there (ENOPROTOOPT).
    ProtocolUnavailable,
    /// The firewall dropped what was sent (EPERM).
    NotPermitted,
}

/// Where and how a datagram arrived, for IP_PKTINFO, IP_RECVTOS and
/// IP_RECVTTL (ip(7)) and their IPv6 forms (ipv6(7)): the destination
/// address in its header, the interface, the TOS byte or traffic class,
/// the TTL or hop limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecvMeta {
    pub to: Option<IpAddr>,
    pub ifindex: IfIndex,
    pub tos: u8,
    pub ttl: u8,
    /// When it arrived, in nanoseconds on the embedder's clock
    /// ([`Stack::clock_ns`]; SO_TIMESTAMPNS), or the stack's own
    /// millisecond clock in nanoseconds when it gives none.
    pub at: u64,
}

/// UDP_SEGMENT's most segments in one send (udp(7); as Linux was seen to
/// allow: 128, and EINVAL past them).
const UDP_MAX_SEGMENTS: usize = 128;

/// An ICMP error about one of a socket's datagrams, queued for
/// IP_RECVERR (ip(7), `struct sock_extended_err`): the error, where it
/// came from (SO_EE_ORIGIN_ICMP or _ICMP6), the ICMP type and code, the
/// MTU for EMSGSIZE, the node that sent it, the datagram's destination and
/// as much of its payload as was quoted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedError {
    pub error: Error,
    pub origin: u8,
    pub kind: u8,
    pub code: u8,
    pub info: u32,
    pub offender: IpAddr,
    pub dest: Endpoint,
    pub payload: Vec<u8>,
}

/// `ee_origin` values (ip(7)).
pub const ORIGIN_ICMP: u8 = 2;
pub const ORIGIN_ICMP6: u8 = 3;
/// Errors kept per socket before more are dropped.
const ERRQ_LIMIT: usize = 32;

pub type Result<T> = core::result::Result<T, Error>;

/// An interface index (rtnetlink(7) `ifi_index`): loopback is 1.
pub type IfIndex = u32;
/// The loopback interface.
pub const LOOPBACK: IfIndex = 1;

/// Route protocols: who made a route (rtnetlink(7) `rtm_protocol`).
pub const PROTO_KERNEL: u8 = 2;
pub const PROTO_BOOT: u8 = 3;
pub const PROTO_STATIC: u8 = 4;
pub const PROTO_DHCP: u8 = 16;

/// An address on an interface, with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub addr: Ipv4,
    pub prefix_len: u8,
}

fn mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix_len.min(32))) }
}

fn within(net: Ipv4, prefix_len: u8, ip: Ipv4) -> bool {
    let m = mask(prefix_len);
    ip.to_u32() & m == net.to_u32() & m
}

impl IfAddr {
    pub fn netmask(&self) -> Ipv4 {
        Ipv4::from_u32(mask(self.prefix_len))
    }
    pub fn network(&self) -> Ipv4 {
        Ipv4::from_u32(self.addr.to_u32() & mask(self.prefix_len))
    }
    pub fn broadcast(&self) -> Ipv4 {
        Ipv4::from_u32(self.addr.to_u32() | !mask(self.prefix_len))
    }
    pub fn contains(&self, ip: Ipv4) -> bool {
        within(self.addr, self.prefix_len, ip)
    }
}

/// A route: packets to `dst/prefix_len` leave through `iface`, to
/// `gateway` or (without one) straight to their destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub dst: Ipv4,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4>,
    pub iface: IfIndex,
    pub metric: u32,
    /// `PROTO_*`.
    pub protocol: u8,
    /// The source address to prefer.
    pub src: Option<Ipv4>,
}

impl Route {
    pub fn covers(&self, ip: Ipv4) -> bool {
        within(self.dst, self.prefix_len, ip)
    }
}

/// A change to the configuration, for the owner to announce (netlink).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// An interface appeared, or its state, carrier, address or MTU changed.
    Link(IfIndex),
    /// An interface went away.
    LinkGone(IfIndex),
    NewAddr(IfIndex, IfAddr),
    DelAddr(IfIndex, IfAddr),
    NewRoute(Route),
    DelRoute(Route),
    /// A neighbour was learned or set, or its address changed.
    NewNeigh(Neighbour),
    DelNeigh(Neighbour),
    /// An IPv6 address was added or changed state, or went.
    NewAddr6(IfIndex, If6Addr),
    DelAddr6(IfIndex, If6Addr),
    NewRoute6(Route6),
    DelRoute6(Route6),
}

/// An ARP or IPv6 neighbour cache entry (a neighbour in rtnetlink(7)'s
/// words).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub iface: IfIndex,
    pub ip: IpAddr,
    /// None while it is being resolved.
    pub mac: Option<Mac>,
    /// Set by hand, never expires.
    pub permanent: bool,
}

/// Every protocol, for packet sockets (packet(7) ETH_P_ALL).
pub const ETH_P_ALL: u16 = 0x0003;
// Packet types (packet(7) `sll_pkttype`).
pub const PACKET_HOST: u8 = 0;
pub const PACKET_BROADCAST: u8 = 1;
pub const PACKET_MULTICAST: u8 = 2;
pub const PACKET_OUTGOING: u8 = 4;

/// A link-level address and what a frame was (packet(7) `sockaddr_ll`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkAddr {
    pub iface: IfIndex,
    /// The ethertype.
    pub protocol: u16,
    pub pkttype: u8,
    pub mac: Mac,
}

/// An interface as the owner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfInfo {
    pub index: IfIndex,
    pub mac: Mac,
    pub mtu: usize,
    /// Administratively up (IFF_UP).
    pub up: bool,
    /// A link is present (IFF_RUNNING, IFF_LOWER_UP).
    pub carrier: bool,
    pub addrs: Vec<IfAddr>,
    pub addrs6: Vec<If6Addr>,
}

/// An interface's address configuration from DHCP or the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub addr: Ipv4,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4>,
    pub dns: Vec<Ipv4>,
}

impl Config {
    /// A static configuration written `ADDR/PREFIX[,GATEWAY[,DNS...]]`, as
    /// in `slate.ip=192.168.1.20/24,192.168.1.1,9.9.9.9` on the kernel
    /// command line (ADR 0029).
    pub fn parse_static(text: &str) -> Option<Config> {
        let mut fields = text.split(',');
        let (addr, prefix) = fields.next()?.split_once('/')?;
        let prefix_len: u8 = prefix.parse().ok().filter(|&p| (1..=32).contains(&p))?;
        let gateway = match fields.next() {
            Some(g) if !g.is_empty() => Some(Ipv4::parse(g)?),
            _ => None,
        };
        let dns = fields.map(Ipv4::parse).collect::<Option<Vec<_>>>()?;
        Some(Config { addr: Ipv4::parse(addr)?, prefix_len, gateway, dns })
    }

    pub fn netmask(&self) -> Ipv4 {
        Ipv4::from_u32(mask(self.prefix_len))
    }
    pub fn broadcast(&self) -> Ipv4 {
        Ipv4::from_u32(self.addr.to_u32() | !mask(self.prefix_len))
    }
}

/// An endpoint: address and port.
pub type Endpoint = (IpAddr, u16);

/// A TCP or UDP socket, as /proc/net/tcp, tcp6, udp and udp6 list them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketEntry {
    pub tcp: bool,
    /// An AF_INET6 socket (listed in the `6` files).
    pub v6: bool,
    pub local: Endpoint,
    pub remote: Option<Endpoint>,
    /// TCP's state; None for UDP.
    pub state: Option<TcpState>,
    /// Bytes queued to send and received but not read; for a listener,
    /// its backlog and the connections waiting to be accepted.
    pub tx_queue: usize,
    pub rx_queue: usize,
    /// The socket's handle (a TCP one among TCP sockets, a UDP one among
    /// the others).
    pub handle: Handle,
}

/// Identifies a socket in the stack.
pub type Handle = usize;

/// Most bytes queued for reading on one datagram socket.
const RX_LIMIT: usize = 256 * 1024;
const EPHEMERAL: core::ops::RangeInclusive<u16> = 49152..=65535;
const ARP_RETRY_MS: u64 = 1000;
const ARP_TRIES: u32 = 3;
const ARP_TTL_MS: u64 = 20 * 60 * 1000;
/// The expiry of an ARP entry set by hand.
const PERMANENT: u64 = u64::MAX;
/// ICMP errors the host sends: this many at once, then one more every
/// `ICMP_REFILL_MS` (RFC 1812 §4.3.2.8, RFC 1122 §3.2.2).
const ICMP_BURST: u32 = 50;
const ICMP_REFILL_MS: u64 = 20;

#[derive(Debug)]
struct Datagram {
    data: Vec<u8>,
    from: Endpoint,
    meta: RecvMeta,
}

/// A socket's IPv4 header settings (ip(7)): IP_TOS, IP_MTU_DISCOVER's
/// IP_PMTUDISC_DO or PROBE (no fragments: EMSGSIZE), and IP_OPTIONS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpOptions {
    pub tos: u8,
    pub dont_fragment: bool,
    /// A TCP segment larger than the path allows, for the card to cut into
    /// segments of this many payload bytes (TCP segmentation offload, ADR
    /// 0083); 0 for an ordinary packet.
    pub tso: u16,
    /// The option field every packet carries.
    pub options: OptionField,
}

/// An IPv4 option field (RFC 791 §3.1): at most 40 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionField {
    bytes: [u8; IP_OPTIONS_MAX],
    len: u8,
}

impl Default for OptionField {
    fn default() -> OptionField {
        OptionField { bytes: [0; IP_OPTIONS_MAX], len: 0 }
    }
}

impl OptionField {
    /// The field `b` holds, if it is well formed: `Err` for a malformed
    /// or oversized one (ip(7): EINVAL).
    pub fn new(b: &[u8]) -> Result<OptionField> {
        if b.len() > IP_OPTIONS_MAX || ipv4_options(b).is_err() {
            return Err(Error::InvalidInput);
        }
        // Kept padded to whole words with end-of-list bytes, as ip(7)'s
        // readback gives it.
        let mut f = OptionField::default();
        f.bytes[..b.len()].copy_from_slice(b);
        f.len = b.len().next_multiple_of(4) as u8;
        Ok(f)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The header bytes it takes (padded to a multiple of four).
    pub fn header_bytes(&self) -> usize {
        usize::from(self.len).next_multiple_of(4)
    }
}

#[derive(Debug, Default)]
struct DgramSocket {
    local: Option<Endpoint>,
    /// IP_TOS and IP_MTU_DISCOVER (ip(7)).
    ip: IpOptions,
    /// SO_DONTROUTE (socket(7)): only directly attached networks.
    dontroute: bool,
    remote: Option<Endpoint>,
    /// An AF_INET6 socket (it binds `::` by default), and IPV6_V6ONLY (no
    /// IPv4 traffic on it).
    v6: bool,
    v6only: bool,
    /// ICMP6_FILTER (RFC 3542 §3.2): the ICMPv6 types a raw socket blocks.
    blocked6: [u32; 8],
    /// SO_BINDTODEVICE: only this interface.
    device: Option<IfIndex>,
    rx: VecDeque<Datagram>,
    rx_bytes: usize,
    /// An ICMP error for a connected socket, or any socket with
    /// IP_RECVERR (SO_ERROR, and the next receive).
    error: Option<Error>,
    /// IP_RECVERR: ICMP errors are also queued, for MSG_ERRQUEUE.
    recverr: bool,
    errq: VecDeque<QueuedError>,
    /// The local address was chosen by connect (the route's source), not
    /// bound: disconnecting gives the wildcard back.
    local_by_connect: bool,
}

#[derive(Debug)]
enum Kind {
    Udp,
    /// SOCK_DGRAM/IPPROTO_ICMP "ping" sockets: echo requests with the
    /// socket's identifier; replies matching it, without the IP header.
    Ping,
    /// SOCK_RAW/IPPROTO_ICMP: whole ICMP messages out, whole IP packets in.
    RawIcmp,
    /// SOCK_RAW/IPPROTO_RAW: whole IP packets out, nothing in (raw(7)).
    RawIp,
    /// SOCK_DGRAM/IPPROTO_ICMPV6: echo requests out, matching replies in.
    Ping6,
    /// SOCK_RAW/IPPROTO_ICMPV6: ICMPv6 messages both ways, without the IP
    /// header; the stack fills in the checksum (RFC 3542 §3.1).
    RawIcmp6,
}

/// Whether a socket whose local address is `local` takes traffic to `dst`:
/// the same address, or a wildcard of the family (an IPv6 wildcard also
/// takes IPv4 unless `v6only`).
fn takes(local: IpAddr, v6only: bool, dst: IpAddr) -> bool {
    match (local, dst) {
        _ if local == dst => true,
        (IpAddr::V4(l), IpAddr::V4(_)) => l.is_unspecified(),
        (IpAddr::V6(l), IpAddr::V6(_)) => l.is_unspecified(),
        (IpAddr::V6(l), IpAddr::V4(_)) => l.is_unspecified() && !v6only,
        _ => false,
    }
}

/// The families a local address takes: (IPv4, IPv6).
fn families(local: IpAddr, v6only: bool) -> (bool, bool) {
    match local {
        IpAddr::V4(_) => (true, false),
        IpAddr::V6(a) => (a.is_unspecified() && !v6only, true),
    }
}

/// Whether two sockets' local addresses on one port overlap (a specific
/// address and the wildcard of its family do; RFC-wise, bind(2) EADDRINUSE).
fn overlap(a: IpAddr, a_only: bool, b: IpAddr, b_only: bool) -> bool {
    let ((a4, a6), (b4, b6)) = (families(a, a_only), families(b, b_only));
    let same_family = (a4 && b4) || (a6 && b6);
    same_family && (a == b || a.is_unspecified() || b.is_unspecified())
}

#[derive(Debug)]
struct Socket {
    kind: Kind,
    d: DgramSocket,
}

#[derive(Debug)]
enum DhcpState {
    Selecting { xid: u32, next: u64, tries: u32 },
    Requesting { xid: u32, offer: dhcp::Reply, next: u64, tries: u32 },
    Bound { renew_at: u64 },
}

/// What DHCP last obtained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Lease {
    pub server: Option<Ipv4>,
    pub lease_secs: u32,
    pub domain: Vec<u8>,
}

#[derive(Debug)]
struct Pending {
    next_hop: Ipv4,
    packet: Vec<u8>,
    /// Its TCP segmentation size, if it is a large segment.
    tso: u16,
}

#[derive(Debug)]
struct Iface {
    mac: Mac,
    mtu: usize,
    up: bool,
    carrier: bool,
    addrs: Vec<IfAddr>,
    /// What [`Stack::set_config`] (DHCP, the command line) put here.
    config: Option<Config>,
    v6: ipv6::Iface6,
    lease: Option<Lease>,
    dhcp: Option<DhcpState>,
    arp: BTreeMap<Ipv4, (Mac, u64)>,
    /// Next hops being resolved: (last request time, requests sent).
    resolving: BTreeMap<Ipv4, (u64, u32)>,
    pending: Vec<Pending>,
    /// The largest TCP payload its card takes to segment itself (0: none;
    /// ADR 0083).
    tso: usize,
    /// Its name (eth0), for the firewall's rules.
    name: Vec<u8>,
}

impl Iface {
    fn new(mac: Mac, mtu: usize) -> Iface {
        Iface {
            mac,
            mtu,
            up: true,
            carrier: true,
            addrs: Vec::new(),
            config: None,
            v6: ipv6::Iface6::default(),
            lease: None,
            dhcp: None,
            arp: BTreeMap::new(),
            resolving: BTreeMap::new(),
            pending: Vec::new(),
            tso: 0,
            name: Vec::new(),
        }
    }
    fn usable(&self) -> bool {
        self.up && self.carrier
    }
    /// The address to send from towards `next_hop` on this link.
    fn source_towards(&self, next_hop: Ipv4) -> Option<Ipv4> {
        self.addrs.iter().find(|a| a.contains(next_hop)).or(self.addrs.first()).map(|a| a.addr)
    }
}

/// A packet socket (packet(7)): whole frames (`cooked` false, SOCK_RAW) or
/// their payloads (SOCK_DGRAM) of one ethertype or all.
#[derive(Debug)]
struct PacketSock {
    /// 0: none yet (receives nothing).
    protocol: u16,
    cooked: bool,
    device: Option<IfIndex>,
    rx: VecDeque<(Vec<u8>, LinkAddr)>,
    rx_bytes: usize,
    filter: Option<Vec<SockFilter>>,
}

#[derive(Debug)]
pub struct Stack {
    ifaces: BTreeMap<IfIndex, Iface>,
    routes: Vec<Route>,
    /// Frames to send: the interface, the frame, and for a large TCP
    /// segment its segmentation size (0 for others).
    tx: Vec<(IfIndex, Vec<u8>, u16)>,
    /// TCP connections to send on at the next `poll` (acknowledgements
    /// arrived on a route with segmentation offload).
    tcp_later: Vec<Handle>,
    changes: Vec<Change>,
    /// Packets to our own addresses, delivered by the next `poll`, with
    /// their connections.
    looped: VecDeque<(Vec<u8>, filter::Conn)>,
    sockets: Vec<Option<Socket>>,
    tcp: Vec<Option<tcp::Tcb>>,
    packets: Vec<Option<PacketSock>>,
    /// IPv4 forwarding between interfaces (/proc/sys/net/ipv4/ip_forward).
    forwarding: bool,
    routes6: Vec<Route6>,
    forwarding6: bool,
    /// Path MTUs learned from "packet too big", with their expiry.
    pmtu6: BTreeMap<Ipv6, (usize, u64)>,
    /// Path MTUs learned from "fragmentation needed" (RFC 1191), with when
    /// each is forgotten.
    pmtu4: BTreeMap<Ipv4, (usize, u64)>,
    reassembly6: BTreeMap<(Ipv6, Ipv6, u32), ipv6::Reassembly6>,
    reassembly4: BTreeMap<(Ipv4, Ipv4, u8, u16), Reassembly4>,
    frag_id: u32,
    next_port: u16,
    ip_id: u16,
    now: u64,
    /// The embedder's finer clock (nanoseconds; 0 for none), set before
    /// frames are given in: datagrams' arrival times (RecvMeta::at).
    pub clock_ns: u64,
    /// The time of day (milliseconds since the Unix epoch; 0 when not
    /// known), for Timestamp options.
    pub wall_ms: u64,
    /// When each kind of ICMP error was last sent, and how many may still
    /// go before the next refill (RFC 1812 §4.3.2.8: a rate limit).
    icmp_tokens: (u64, u32),
    hostname: Vec<u8>,
    seed: u32,
    /// Moves whenever socket readiness may have changed.
    pub events: u64,
    /// The namespace's firewall (nf_tables, ADR 0129), its connections,
    /// and the link-layer header of the frame being taken in.
    pub firewall: slate_nft::Ruleset,
    pub conntrack: slate_nft::Conntrack,
    arriving_ll: Option<[u8; ETH_HEADER]>,
}

impl Stack {
    /// A stack with only the loopback interface; `seed` varies identifiers
    /// (DHCP transaction IDs, the first ephemeral port).
    pub fn new(seed: u32) -> Stack {
        let mut lo = Iface::new(Mac::default(), 65536);
        lo.addrs.push(IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 });
        lo.name = b"lo".to_vec();
        let mut ifaces = BTreeMap::new();
        ifaces.insert(LOOPBACK, lo);
        let mut st = Stack {
            ifaces,
            routes: Vec::new(),
            tx: Vec::new(),
            tcp_later: Vec::new(),
            changes: Vec::new(),
            looped: VecDeque::new(),
            sockets: Vec::new(),
            tcp: Vec::new(),
            packets: Vec::new(),
            forwarding: false,
            routes6: Vec::new(),
            forwarding6: false,
            pmtu6: BTreeMap::new(),
            pmtu4: BTreeMap::new(),
            reassembly6: BTreeMap::new(),
            reassembly4: BTreeMap::new(),
            frag_id: seed,
            next_port: *EPHEMERAL.start() + (seed % 16384) as u16,
            ip_id: seed as u16,
            now: 0,
            clock_ns: 0,
            wall_ms: 0,
            icmp_tokens: (0, ICMP_BURST),
            firewall: slate_nft::Ruleset::default(),
            conntrack: slate_nft::Conntrack::default(),
            arriving_ll: None,
            hostname: Vec::new(),
            seed,
            events: 0,
        };
        st.start_v6(LOOPBACK);
        st
    }

    /// A new network namespace's stack: as Linux makes one (observed with
    /// `unshare -n ip addr`), its loopback is down and has no address
    /// until it is brought up ([`Stack::set_up`] then gives it 127.0.0.1/8
    /// and ::1). Sandboxes such as bubblewrap add 127.0.0.1 themselves
    /// and fail if it is already there (ADR 0114).
    pub fn new_namespace(seed: u32) -> Stack {
        let mut st = Stack::new(seed);
        if let Some(lo) = st.ifaces.get_mut(&LOOPBACK) {
            lo.up = false;
            lo.addrs.clear();
            lo.v6.addrs.clear();
        }
        st
    }

    // --- interfaces ----------------------------------------------------------

    /// Add an Ethernet interface (up, with a carrier, no address).
    pub fn add_interface(&mut self, index: IfIndex, mac: Mac, mtu: usize) -> Result<()> {
        if index <= LOOPBACK || self.ifaces.contains_key(&index) {
            return Err(Error::Exists);
        }
        self.ifaces.insert(index, Iface::new(mac, mtu));
        self.changes.push(Change::Link(index));
        self.start_v6(index);
        self.events += 1;
        Ok(())
    }

    /// Remove an interface with its addresses and routes.
    pub fn remove_interface(&mut self, index: IfIndex) {
        if index == LOOPBACK || !self.ifaces.contains_key(&index) {
            return;
        }
        self.clear_addresses(index);
        let gone: Vec<Route> = self.routes.iter().filter(|r| r.iface == index).copied().collect();
        self.routes.retain(|r| r.iface != index);
        self.changes.extend(gone.into_iter().map(Change::DelRoute));
        let gone6: Vec<Route6> = self.routes6.iter().filter(|r| r.iface == index).copied().collect();
        self.routes6.retain(|r| r.iface != index);
        self.changes.extend(gone6.into_iter().map(Change::DelRoute6));
        for s in self.sockets.iter_mut().flatten() {
            if s.d.device == Some(index) {
                s.d.error = Some(Error::NetUnreachable);
            }
        }
        self.ifaces.remove(&index);
        self.changes.push(Change::LinkGone(index));
        self.events += 1;
    }

    fn iface(&self, index: IfIndex) -> Result<&Iface> {
        self.ifaces.get(&index).ok_or(Error::NoDevice)
    }
    fn iface_mut(&mut self, index: IfIndex) -> Result<&mut Iface> {
        self.ifaces.get_mut(&index).ok_or(Error::NoDevice)
    }

    /// A new hardware address or MTU for an interface.
    pub fn set_link(&mut self, index: IfIndex, mac: Mac, mtu: usize) -> Result<()> {
        let i = self.iface_mut(index)?;
        if (i.mac, i.mtu) != (mac, mtu) {
            (i.mac, i.mtu) = (mac, mtu);
            i.arp.retain(|_, (_, exp)| *exp == PERMANENT);
            self.changes.push(Change::Link(index));
            self.events += 1;
        }
        Ok(())
    }

    /// Whether the interface has a link.
    pub fn set_carrier(&mut self, index: IfIndex, carrier: bool) -> Result<()> {
        let i = self.iface_mut(index)?;
        if i.carrier != carrier {
            i.carrier = carrier;
            if !carrier {
                i.arp.retain(|_, (_, exp)| *exp == PERMANENT);
                i.v6.nd.retain(|_, (_, exp)| *exp == u64::MAX);
            }
            self.changes.push(Change::Link(index));
            self.events += 1;
            if carrier {
                self.link_up_v6(index);
            }
        }
        Ok(())
    }

    /// Bring an interface up or down (IFF_UP). A down interface sends and
    /// receives nothing; its routes are not used.
    pub fn set_up(&mut self, index: IfIndex, up: bool) -> Result<()> {
        if index == LOOPBACK && up {
            // Up, the loopback has its addresses (those taken away stay
            // away only while it is down).
            let lo = self.iface_mut(LOOPBACK)?;
            let was = lo.up;
            lo.up = true;
            if !lo.addrs.iter().any(|a| a.addr == Ipv4::LOCALHOST) {
                lo.addrs.push(IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 });
                self.changes.push(Change::NewAddr(LOOPBACK, IfAddr { addr: Ipv4::LOCALHOST, prefix_len: 8 }));
            }
            if !self.ifaces.get(&LOOPBACK).is_some_and(|l| l.v6.addrs.iter().any(|a| a.addr == Ipv6::LOCALHOST)) {
                self.start_v6(LOOPBACK);
            }
            if !was {
                self.changes.push(Change::Link(LOOPBACK));
                self.events += 1;
            }
            return Ok(());
        }
        let i = self.iface_mut(index)?;
        if i.up != up {
            i.up = up;
            if !up {
                i.arp.retain(|_, (_, exp)| *exp == PERMANENT);
                i.pending.clear();
                i.resolving.clear();
            }
            self.changes.push(Change::Link(index));
            self.events += 1;
        }
        Ok(())
    }

    /// Every interface, in index order.
    pub fn interfaces(&self) -> Vec<IfInfo> {
        self.ifaces
            .iter()
            .map(|(&index, i)| IfInfo {
                index,
                mac: i.mac,
                mtu: i.mtu,
                up: i.up,
                carrier: i.carrier,
                addrs: i.addrs.clone(),
                addrs6: i.v6.addrs.clone(),
            })
            .collect()
    }

    pub fn interface(&self, index: IfIndex) -> Option<IfInfo> {
        self.interfaces().into_iter().find(|i| i.index == index)
    }

    pub fn mac(&self, index: IfIndex) -> Option<Mac> {
        self.ifaces.get(&index).map(|i| i.mac)
    }
    pub fn mtu(&self, index: IfIndex) -> Option<usize> {
        self.ifaces.get(&index).map(|i| i.mtu)
    }

    /// Changes since the last call, for the owner to announce.
    pub fn take_changes(&mut self) -> Vec<Change> {
        core::mem::take(&mut self.changes)
    }

    // --- addresses and routes -------------------------------------------------

    /// Add an address to an interface, and the route to its subnet.
    pub fn add_address(&mut self, index: IfIndex, a: IfAddr) -> Result<()> {
        if a.prefix_len > 32 || a.addr.is_unspecified() || a.addr.is_multicast() || a.addr == Ipv4::BROADCAST {
            return Err(Error::InvalidInput);
        }
        let i = self.iface_mut(index)?;
        if i.addrs.iter().any(|x| x.addr == a.addr) {
            return Err(Error::Exists);
        }
        i.addrs.push(a);
        self.changes.push(Change::NewAddr(index, a));
        if index != LOOPBACK && a.prefix_len < 32 {
            let r = Route {
                dst: a.network(),
                prefix_len: a.prefix_len,
                gateway: None,
                iface: index,
                metric: 0,
                protocol: PROTO_KERNEL,
                src: Some(a.addr),
            };
            if !self.routes.iter().any(|x| x.iface == index && x.dst == r.dst && x.prefix_len == r.prefix_len) {
                self.routes.push(r);
                self.changes.push(Change::NewRoute(r));
            }
        }
        self.events += 1;
        Ok(())
    }

    /// Remove an address, its subnet route, and routes through gateways
    /// only it reached.
    pub fn del_address(&mut self, index: IfIndex, addr: Ipv4) -> Result<()> {
        let i = self.iface_mut(index)?;
        let at = i.addrs.iter().position(|x| x.addr == addr).ok_or(Error::AddrNotAvailable)?;
        let a = i.addrs.remove(at);
        let left = i.addrs.clone();
        self.changes.push(Change::DelAddr(index, a));
        let reachable = |g: Ipv4| left.iter().any(|x| x.contains(g));
        let gone: Vec<Route> = self
            .routes
            .iter()
            .filter(|r| {
                r.iface == index
                    && ((r.gateway.is_none()
                        && r.dst == a.network()
                        && r.prefix_len == a.prefix_len
                        && !reachable(r.dst))
                        || r.gateway.is_some_and(|g| a.contains(g) && !reachable(g))
                        || r.src == Some(addr))
            })
            .copied()
            .collect();
        self.routes.retain(|r| !gone.contains(r));
        self.changes.extend(gone.into_iter().map(Change::DelRoute));
        self.events += 1;
        Ok(())
    }

    /// Remove every address of an interface.
    pub fn clear_addresses(&mut self, index: IfIndex) {
        let addrs: Vec<Ipv4> =
            self.ifaces.get(&index).map(|i| i.addrs.iter().map(|a| a.addr).collect()).unwrap_or_default();
        for a in addrs {
            let _ = self.del_address(index, a);
        }
    }

    pub fn addresses(&self, index: IfIndex) -> Vec<IfAddr> {
        self.ifaces.get(&index).map(|i| i.addrs.clone()).unwrap_or_default()
    }

    /// Add a route. A gateway must be on a subnet of the interface.
    pub fn add_route(&mut self, r: Route) -> Result<()> {
        if r.prefix_len > 32 {
            return Err(Error::InvalidInput);
        }
        let i = self.iface(r.iface)?;
        if let Some(g) = r.gateway
            && !i.addrs.iter().any(|a| a.contains(g))
        {
            return Err(Error::NetUnreachable);
        }
        let dst = Ipv4::from_u32(r.dst.to_u32() & mask(r.prefix_len));
        let r = Route { dst, ..r };
        if self.routes.iter().any(|x| x.dst == dst && x.prefix_len == r.prefix_len && x.metric == r.metric) {
            return Err(Error::Exists);
        }
        self.routes.push(r);
        self.changes.push(Change::NewRoute(r));
        self.events += 1;
        Ok(())
    }

    /// Remove the first route to `dst/prefix_len` that matches the given
    /// interface, gateway and metric (each only when given).
    pub fn del_route(
        &mut self,
        dst: Ipv4,
        prefix_len: u8,
        iface: Option<IfIndex>,
        gateway: Option<Ipv4>,
        metric: Option<u32>,
    ) -> Result<Route> {
        let dst = Ipv4::from_u32(dst.to_u32() & mask(prefix_len));
        let at = self
            .routes
            .iter()
            .position(|r| {
                r.dst == dst
                    && r.prefix_len == prefix_len
                    && iface.is_none_or(|i| r.iface == i)
                    && gateway.is_none_or(|g| r.gateway == Some(g))
                    && metric.is_none_or(|m| r.metric == m)
            })
            .ok_or(Error::NotFound)?;
        let r = self.routes.remove(at);
        self.changes.push(Change::DelRoute(r));
        self.events += 1;
        Ok(r)
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// The route for `dst` (longest prefix, then lowest metric) over usable
    /// interfaces, only `dev` if given.
    pub fn lookup(&self, dst: Ipv4, dev: Option<IfIndex>) -> Option<Route> {
        self.routes
            .iter()
            .filter(|r| r.covers(dst) && dev.is_none_or(|d| r.iface == d))
            .filter(|r| self.ifaces.get(&r.iface).is_some_and(Iface::usable))
            .max_by_key(|r| (r.prefix_len, core::cmp::Reverse(r.metric)))
            .copied()
    }

    /// Configure an interface from DHCP or the command line (or remove
    /// that configuration): its address, a default route through the
    /// gateway, and name servers to report.
    pub fn set_config(&mut self, index: IfIndex, c: Option<Config>, protocol: u8) -> Result<()> {
        let old = self.iface_mut(index)?.config.take();
        if let Some(o) = &old {
            if let Some(g) = o.gateway {
                let _ = self.del_route(Ipv4::UNSPECIFIED, 0, Some(index), Some(g), None);
            }
            if c.as_ref().is_none_or(|n| n.addr != o.addr || n.prefix_len != o.prefix_len) {
                let _ = self.del_address(index, o.addr);
            }
        }
        if let Some(n) = &c {
            let a = IfAddr { addr: n.addr, prefix_len: n.prefix_len };
            match self.add_address(index, a) {
                Ok(()) | Err(Error::Exists) => {}
                Err(e) => return Err(e),
            }
            if let Some(g) = n.gateway {
                let r = Route {
                    dst: Ipv4::UNSPECIFIED,
                    prefix_len: 0,
                    gateway: Some(g),
                    iface: index,
                    metric: 0,
                    protocol,
                    src: Some(n.addr),
                };
                // Another interface's default route may hold metric 0.
                if self.add_route(r) == Err(Error::Exists) {
                    let _ = self.add_route(Route { metric: 100 + index, ..r });
                }
            }
        }
        self.iface_mut(index)?.config = c;
        self.events += 1;
        Ok(())
    }

    /// The configuration [`Stack::set_config`] gave the interface.
    pub fn config(&self, index: IfIndex) -> Option<&Config> {
        self.ifaces.get(&index).and_then(|i| i.config.as_ref())
    }
    pub fn lease(&self, index: IfIndex) -> Option<&Lease> {
        self.ifaces.get(&index).and_then(|i| i.lease.as_ref())
    }
    pub fn set_hostname(&mut self, h: &[u8]) {
        self.hostname = h.to_vec();
    }

    /// Frames to transmit, each with the interface to send it from.
    /// Frames to send, each one the wire can carry: large TCP segments are
    /// cut up here ([`wire::segment_tcp4`]).
    pub fn take_tx(&mut self) -> Vec<(IfIndex, Vec<u8>)> {
        let mut out = Vec::with_capacity(self.tx.len());
        for (i, f, tso) in core::mem::take(&mut self.tx) {
            if tso == 0 {
                out.push((i, f));
            } else {
                out.extend(crate::wire::segment_tcp4(&f, usize::from(tso)).into_iter().map(|s| (i, s)));
            }
        }
        out
    }

    /// Frames to send as they are, large TCP segments whole with their
    /// segmentation size, for cards that cut them up themselves (ADR 0083).
    pub fn take_tx_offload(&mut self) -> Vec<(IfIndex, Vec<u8>, u16)> {
        core::mem::take(&mut self.tx)
    }

    /// Say that interface `index`'s card segments TCP sends of up to `tso`
    /// payload bytes itself (0: it does not).
    pub fn set_offload(&mut self, index: IfIndex, tso: usize) -> Result<()> {
        self.iface_mut(index)?.tso = tso;
        Ok(())
    }

    /// The TCP segmentation offload for sending to `dst` (out of `dev` if
    /// given): the card's largest payload, or 0.
    fn tso_for(&self, dst: Ipv4, dev: Option<IfIndex>) -> usize {
        if self.is_local(dst) {
            return 0;
        }
        self.next_hop(dst, dev)
            .ok()
            .and_then(|(out, _, broadcast)| (!broadcast).then_some(out))
            .and_then(|o| self.ifaces.get(&o))
            .map_or(0, |i| i.tso)
    }

    fn rand(&mut self) -> u32 {
        // xorshift: identifiers only need to differ between boots.
        let mut x = self.seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.seed = x;
        x
    }

    /// Whether `ip` is one of the host's addresses (on any interface).
    fn is_local(&self, ip: Ipv4) -> bool {
        ip.is_loopback() || self.ifaces.values().any(|i| i.addrs.iter().any(|a| a.addr == ip))
    }

    /// Whether `ip` is the broadcast address of a subnet of `index`.
    fn is_broadcast_on(&self, index: IfIndex, ip: Ipv4) -> bool {
        ip == Ipv4::BROADCAST
            || self.ifaces.get(&index).is_some_and(|i| i.addrs.iter().any(|a| a.prefix_len < 31 && a.broadcast() == ip))
    }

    // --- input -------------------------------------------------------------

    /// Process an Ethernet frame received on interface `index`.
    pub fn receive(&mut self, index: IfIndex, frame: &[u8], now: u64) {
        self.now = now;
        let Some(i) = self.ifaces.get(&index) else { return };
        if frame.len() < ETH_HEADER || !i.up {
            return;
        }
        let dst = Mac(frame[0..6].try_into().unwrap());
        let pkttype = if dst == i.mac {
            PACKET_HOST
        } else if dst == Mac::BROADCAST {
            PACKET_BROADCAST
        } else if dst.0[0] & 1 != 0 {
            PACKET_MULTICAST
        } else {
            return; // Another host's (the card filters these anyway).
        };
        self.tap(index, frame, pkttype, None);
        let payload = &frame[ETH_HEADER..];
        self.arriving_ll = self.filtering().then(|| frame[..ETH_HEADER].try_into().unwrap());
        match get16(frame, 12) {
            // No IPv4 multicast yet.
            ETHERTYPE_ARP if pkttype != PACKET_MULTICAST => self.receive_arp(index, payload),
            ETHERTYPE_IPV4 if pkttype != PACKET_MULTICAST => self.receive_ip(index, payload, false, None),
            ETHERTYPE_IPV6 => self.receive_ip6(index, payload, false, None),
            _ => {}
        }
        self.arriving_ll = None;
    }

    fn receive_arp(&mut self, index: IfIndex, b: &[u8]) {
        let Some(a) = Arp::parse(b) else { return };
        let i = &self.ifaces[&index];
        let ours = i.addrs.iter().any(|x| x.addr == a.target_ip);
        // Learn the sender if it is talking to us or we asked for it.
        if ours || i.arp.contains_key(&a.sender_ip) || i.resolving.contains_key(&a.sender_ip) {
            self.learn(index, a.sender_ip, a.sender_mac);
        }
        if a.op == ARP_REQUEST && ours {
            let mac = self.ifaces[&index].mac;
            let reply = Arp {
                op: ARP_REPLY,
                sender_mac: mac,
                sender_ip: a.target_ip,
                target_mac: a.sender_mac,
                target_ip: a.sender_ip,
            };
            self.emit(index, ethernet(a.sender_mac, mac, ETHERTYPE_ARP, &reply.build()), None);
        }
    }

    fn learn(&mut self, index: IfIndex, ip: Ipv4, mac: Mac) {
        if ip.is_unspecified() {
            return;
        }
        let now = self.now;
        let Some(i) = self.ifaces.get_mut(&index) else { return };
        let old = i.arp.get(&ip).copied();
        if old.is_some_and(|(_, exp)| exp == PERMANENT) {
            return; // Set by hand: kept as it is.
        }
        i.arp.insert(ip, (mac, now + ARP_TTL_MS));
        if old.is_none_or(|(m, _)| m != mac) {
            self.changes.push(Change::NewNeigh(Neighbour {
                iface: index,
                ip: ip.into(),
                mac: Some(mac),
                permanent: false,
            }));
        }
        self.flush_pending(index, ip, mac);
    }

    /// Send the packets that waited for `ip`'s hardware address.
    fn flush_pending(&mut self, index: IfIndex, ip: Ipv4, mac: Mac) {
        let Some(i) = self.ifaces.get_mut(&index) else { return };
        i.resolving.remove(&ip);
        let (ready, waiting): (Vec<_>, Vec<_>) =
            core::mem::take(&mut i.pending).into_iter().partition(|p| p.next_hop == ip);
        i.pending = waiting;
        let own = i.mac;
        for p in ready {
            self.emit_tso(index, ethernet(mac, own, ETHERTYPE_IPV4, &p.packet), None, p.tso);
        }
    }

    fn receive_ip(&mut self, index: IfIndex, b: &[u8], looped: bool, conn: filter::Conn) {
        let Some(h) = Ipv4Header::parse(b) else { return };
        if !self.options_ok(index, &h, &b[..h.total_len]) {
            return;
        }
        if h.fragmented {
            // Only the host's own packets are put back together; forwarded
            // ones go on in pieces, unless a firewall is to judge them
            // (whole, as Linux's connection tracking does).
            let ours = (looped && (h.dst.is_loopback() || self.is_local(h.dst)))
                || (self.is_local(h.dst) && !h.dst.is_loopback())
                || self.is_broadcast_on(index, h.dst);
            if ours || self.filtering() {
                if let Some(whole) = self.reassemble4(index, &h, &b[..h.total_len]) {
                    self.receive_ip(index, &whole, looped, conn);
                }
            } else if self.forwarding && !looped && !h.dst.is_multicast() && !self.is_local(h.src) {
                self.forward(index, &h, &b[..h.total_len], None);
            }
            return;
        }
        if self.filtering() {
            // Prerouting may give it a new destination (NAT).
            let (mut p, mut conn) = (b[..h.total_len].to_vec(), conn);
            if !self.arriving(filter::NF_INET_PRE_ROUTING, &mut p, index, None, &mut conn) {
                return;
            }
            return self.receive_ip_routed(index, &p, looped, conn);
        }
        self.receive_ip_routed(index, &b[..h.total_len], looped, conn)
    }

    /// An IPv4 packet past prerouting: to this host, or forwarded.
    fn receive_ip_routed(&mut self, index: IfIndex, b: &[u8], looped: bool, mut conn: filter::Conn) {
        let Some(h) = Ipv4Header::parse(b) else { return };
        let payload = &b[h.header_len..h.total_len];
        // The DHCP client port takes datagrams before the interface has an
        // address (the server may send them to the offered one).
        let dhcp_client = h.proto == PROTO_UDP
            && payload.len() >= 4
            && get16(payload, 2) == dhcp::CLIENT_PORT
            && self.ifaces.get(&index).is_some_and(|i| i.addrs.is_empty() || i.dhcp.is_some());
        // Any of the host's addresses, whichever interface it came in on
        // (RFC 1122 §3.3.4.2); 127/8 only from loopback.
        let for_us = (looped && (h.dst.is_loopback() || self.is_local(h.dst)))
            || (self.is_local(h.dst) && !h.dst.is_loopback())
            || self.is_broadcast_on(index, h.dst)
            || dhcp_client;
        if !for_us {
            if self.forwarding && !looped && !h.dst.is_multicast() && !h.src.is_unspecified() && !self.is_local(h.src) {
                self.forward(index, &h, &b[..h.total_len], conn);
            }
            return;
        }
        // The stack's own DHCP client is not filtered (on Linux it uses a
        // packet socket, which netfilter does not see). Input may give the
        // packet a new source (NAT).
        let owned;
        let (h, b) = if !dhcp_client && self.filtering() {
            let mut p = b[..h.total_len].to_vec();
            if !self.arriving(filter::NF_INET_LOCAL_IN, &mut p, index, None, &mut conn) {
                return;
            }
            owned = p;
            match Ipv4Header::parse(&owned) {
                Some(h) => (h, &owned[..]),
                None => return,
            }
        } else {
            (h, b)
        };
        let payload = &b[h.header_len..h.total_len];
        let broadcast = self.is_broadcast_on(index, h.dst);
        match h.proto {
            PROTO_ICMP => self.receive_icmp(index, &h, &b[..h.total_len], payload),
            PROTO_UDP => self.receive_udp(index, &h, payload),
            PROTO_TCP if !broadcast => self.receive_tcp(index, h.src.into(), h.dst.into(), payload),
            PROTO_TCP => {}
            // No socket takes any other protocol (RFC 1122 §3.2.2.1).
            _ => self.icmp_error(index, &h, &b[..h.total_len], ICMP_DEST_UNREACHABLE, ICMP_PROTO_UNREACHABLE, [0; 4]),
        }
    }

    /// Check a packet's options (RFC 791 §3.1, RFC 1122 §3.2.1.8): a
    /// malformed field draws a Parameter Problem pointing at the bad byte;
    /// source-routed packets are dropped, as Linux does unless told
    /// otherwise (accept_source_route), since they let a sender pick a
    /// path through the host. Returns whether the packet may go on.
    fn options_ok(&mut self, index: IfIndex, h: &Ipv4Header, packet: &[u8]) -> bool {
        if h.header_len == IP_HEADER {
            return true;
        }
        match ipv4_options(&packet[IP_HEADER..h.header_len]) {
            Err(at) => {
                let pointer = (IP_HEADER + at) as u8;
                self.icmp_error(index, h, packet, ICMP_PARAMETER_PROBLEM, 0, [pointer, 0, 0, 0]);
                false
            }
            Ok(list) => !list.iter().any(|o| matches!(o.kind, IPOPT_LSRR | IPOPT_SSRR)),
        }
    }

    /// Add `addr` (and the time) to the Record Route and Timestamp options
    /// in option field `f`.
    fn stamp_options(&self, f: &mut [u8], addr: Ipv4) {
        let Ok(list) = ipv4_options(f) else { return };
        for o in list {
            let opt = &mut f[o.at..o.at + o.len];
            match o.kind {
                IPOPT_RR => record_route(opt, addr),
                IPOPT_TS => record_timestamp(opt, addr, self.timestamp_ms()),
                _ => {}
            }
        }
    }

    /// The time for a Timestamp option: milliseconds since midnight UT, or
    /// with the high bit set when the time of day isn't known (RFC 791).
    fn timestamp_ms(&self) -> u32 {
        if self.wall_ms != 0 {
            (self.wall_ms % 86_400_000) as u32
        } else {
            0x8000_0000 | (self.now as u32 & 0x7FFF_FFFF)
        }
    }

    fn receive_icmp(&mut self, index: IfIndex, h: &Ipv4Header, packet: &[u8], m: &[u8]) {
        if m.len() < 8 || checksum(m) != 0 {
            return;
        }
        for s in self.sockets.iter_mut().flatten() {
            if matches!(s.kind, Kind::RawIcmp) && s.d.device.is_none_or(|d| d == index) {
                push_dgram(&mut s.d, packet.to_vec(), (h.src.into(), 0));
            }
        }
        match m[0] {
            ICMP_ECHO_REQUEST if !self.is_broadcast_on(index, h.dst) => {
                let reply = icmp(ICMP_ECHO_REPLY, 0, m[4..8].try_into().unwrap(), &m[8..]);
                // Record Route and Timestamp come back in the reply, this
                // host's entry added (RFC 1122 §3.2.2.6).
                let field = &packet[IP_HEADER..h.header_len];
                let mut kept = Vec::new();
                for o in ipv4_options(field).unwrap_or_default() {
                    if matches!(o.kind, IPOPT_RR | IPOPT_TS) {
                        kept.extend_from_slice(&field[o.at..o.at + o.len]);
                    }
                }
                let ip = IpOptions { options: OptionField::new(&kept).unwrap_or_default(), ..IpOptions::default() };
                let _ = self.send_ip_opt(h.dst, h.src, PROTO_ICMP, &reply, None, ip);
            }
            ICMP_ECHO_REPLY => {
                let ident = get16(m, 4);
                let at = if self.clock_ns != 0 { self.clock_ns } else { self.now.saturating_mul(1_000_000) };
                let meta = RecvMeta { to: Some(h.dst.into()), ifindex: index, tos: h.tos, ttl: h.ttl, at };
                for s in self.sockets.iter_mut().flatten() {
                    if matches!(s.kind, Kind::Ping)
                        && s.d.local.is_some_and(|l| l.1 == ident)
                        && s.d.device.is_none_or(|d| d == index)
                    {
                        push_dgram_meta(&mut s.d, m.to_vec(), (h.src.into(), 0), meta);
                    }
                }
            }
            ICMP_DEST_UNREACHABLE | ICMP_TIME_EXCEEDED | ICMP_PARAMETER_PROBLEM if m.len() >= 8 + IP_HEADER + 4 => {
                // The offending datagram's header follows: tell its socket.
                let inner = &m[8..];
                let quoted = Ipv4Header::parse_unchecked(inner).filter(|ih| self.is_local(ih.src));
                let frag_needed = m[0] == ICMP_DEST_UNREACHABLE && m[1] == ICMP_FRAG_NEEDED;
                if let Some(ih) = &quoted
                    && frag_needed
                {
                    // A smaller path MTU (RFC 1191 §6.1): kept 10 minutes.
                    let mtu = usize::from(get16(m, 6));
                    if mtu >= 68 && mtu < self.path_mtu(ih.dst) {
                        self.pmtu4.insert(ih.dst, (mtu, self.now + 10 * 60 * 1000));
                    }
                }
                if let Some(ih) = &quoted
                    && ih.proto == PROTO_TCP
                    && inner.len() >= ih.header_len + 8
                {
                    let t = &inner[ih.header_len..];
                    let effect = match (m[0], m[1]) {
                        _ if frag_needed => tcp::IcmpEffect::Mtu,
                        // Unreachable but for a source route or a precedence
                        // matter: the attempt is hopeless (RFC 1122
                        // §4.2.3.9); the rest are soft.
                        (ICMP_DEST_UNREACHABLE, 0..=3 | 6..=13) => tcp::IcmpEffect::Fatal(icmp4_error(m[0], m[1])),
                        _ => tcp::IcmpEffect::Soft(icmp4_error(m[0], m[1])),
                    };
                    let (local, remote) = ((ih.src.into(), get16(t, 0)), (ih.dst.into(), get16(t, 2)));
                    self.tcp_icmp_error(local, remote, get32(t, 4), effect);
                }
                if let Some(ih) = quoted.filter(|ih| ih.proto == PROTO_UDP) {
                    let (sport, dport) = (get16(inner, ih.header_len), get16(inner, ih.header_len + 2));
                    let payload = inner.get(ih.header_len + UDP_HEADER..).unwrap_or(&[]);
                    // Fragmentation needed carries the next hop's MTU (RFC 1191 §4).
                    let info = if m[0] == ICMP_DEST_UNREACHABLE && m[1] == ICMP_FRAG_NEEDED {
                        u32::from(get16(m, 6))
                    } else {
                        0
                    };
                    let e = QueuedError {
                        error: icmp4_error(m[0], m[1]),
                        origin: ORIGIN_ICMP,
                        kind: m[0],
                        code: m[1],
                        info,
                        offender: h.src.into(),
                        dest: (ih.dst.into(), dport),
                        payload: payload.to_vec(),
                    };
                    self.udp_error(ih.src.into(), sport, e);
                }
            }
            _ => {}
        }
        self.events += 1;
    }

    fn receive_udp(&mut self, index: IfIndex, h: &Ipv4Header, d: &[u8]) {
        let Some((sport, dport, payload)) = parse_udp(h.src, h.dst, d) else { return };
        if dport == dhcp::CLIENT_PORT && self.ifaces.get(&index).is_some_and(|i| i.dhcp.is_some()) {
            self.dhcp_input(index, payload);
            return;
        }
        let broadcast = self.is_broadcast_on(index, h.dst);
        let delivered =
            self.deliver_udp(index, h.src.into(), h.dst.into(), sport, dport, payload, broadcast, (h.tos, h.ttl));
        if !delivered && !broadcast && !h.dst.is_multicast() && self.is_local(h.dst) {
            // RFC 1122 §4.1.3.1: port unreachable, quoting the datagram, as
            // much of it as keeps the message within 576 bytes (RFC 1812
            // §4.3.2.3; a socket with IP_RECVERR gets the payload back).
            let mut quoted = ipv4(h.src, h.dst, PROTO_UDP, h.id, h.ttl, d);
            quoted.truncate(576 - IP_HEADER - 8);
            let m = icmp(ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE, [0; 4], &quoted);
            let _ = self.send_ip(h.dst, h.src, PROTO_ICMP, &m);
        }
    }

    /// UDP over IPv6 (the v4 path checks its DHCP and errors first): whether
    /// a socket took it.
    pub(super) fn receive_udp_ip(
        &mut self,
        index: IfIndex,
        src: IpAddr,
        dst: IpAddr,
        d: &[u8],
        group: bool,
        (tclass, hops): (u8, u8),
    ) -> bool {
        let Some((sport, dport, payload)) = parse_udp_ip(src, dst, d) else { return true };
        self.deliver_udp(index, src, dst, sport, dport, payload, group, (tclass, hops))
    }

    /// Give a datagram to the UDP socket bound to its address and port
    /// (`wide`: a broadcast or multicast, which any address of the family
    /// on that port takes).
    #[allow(clippy::too_many_arguments)]
    fn deliver_udp(
        &mut self,
        index: IfIndex,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        payload: &[u8],
        wide: bool,
        (tos, ttl): (u8, u8),
    ) -> bool {
        for s in self.sockets.iter_mut().flatten() {
            if !matches!(s.kind, Kind::Udp) || s.d.device.is_some_and(|dev| dev != index) {
                continue;
            }
            let Some((laddr, lport)) = s.d.local else { continue };
            let (f4, f6) = families(laddr, s.d.v6only);
            let family_ok = takes(laddr, s.d.v6only, dst) || (wide && if dst.is_v6() { f6 } else { f4 });
            if lport != dport || !family_ok {
                continue;
            }
            if s.d.remote.is_some_and(|r| r != (src, sport)) {
                continue;
            }
            let at = if self.clock_ns != 0 { self.clock_ns } else { self.now.saturating_mul(1_000_000) };
            let meta = RecvMeta { to: Some(dst), ifindex: index, tos, ttl, at };
            push_dgram_meta(&mut s.d, payload.to_vec(), (src, sport), meta);
            self.events += 1;
            return true;
        }
        false
    }

    /// Raw ICMPv6 sockets get a copy of every ICMPv6 message their filter
    /// lets through (RFC 3542 §3.1-3.2).
    pub(super) fn deliver_raw6(&mut self, index: IfIndex, h: &Ipv6Header, m: &[u8]) {
        let t = usize::from(m[0]);
        for s in self.sockets.iter_mut().flatten() {
            if matches!(s.kind, Kind::RawIcmp6)
                && s.d.device.is_none_or(|d| d == index)
                && s.d.blocked6[t / 32] & (1 << (t % 32)) == 0
            {
                push_dgram(&mut s.d, m.to_vec(), (h.src.into(), 0));
            }
        }
    }

    pub(super) fn deliver_echo_reply6(&mut self, index: IfIndex, h: &Ipv6Header, m: &[u8]) {
        let ident = get16(m, 4);
        let at = if self.clock_ns != 0 { self.clock_ns } else { self.now.saturating_mul(1_000_000) };
        let meta = RecvMeta { to: Some(h.dst.into()), ifindex: index, tos: h.tclass, ttl: h.hop_limit, at };
        for s in self.sockets.iter_mut().flatten() {
            if matches!(s.kind, Kind::Ping6)
                && s.d.local.is_some_and(|l| l.1 == ident)
                && s.d.device.is_none_or(|d| d == index)
            {
                push_dgram_meta(&mut s.d, m.to_vec(), (h.src.into(), 0), meta);
            }
        }
    }

    /// An ICMPv6 error about a UDP datagram (destination unreachable, time
    /// exceeded, packet too big): its socket hears of it.
    pub(super) fn udp_error6(&mut self, from: Ipv6, m: &[u8]) {
        let inner = &m[8..];
        let Some(ih) = Ipv6Header::parse_quoted(inner) else { return };
        if ih.next != PROTO_UDP || inner.len() < IP6_HEADER + 4 {
            return;
        }
        let (sport, dport) = (get16(inner, IP6_HEADER), get16(inner, IP6_HEADER + 2));
        // Packet too big carries the MTU (RFC 4443 §3.2).
        let info = if m[0] == ICMP6_PACKET_TOO_BIG { get32(m, 4) } else { 0 };
        let e = QueuedError {
            error: icmp6_error_of(m[0], m[1]),
            origin: ORIGIN_ICMP6,
            kind: m[0],
            code: m[1],
            info,
            offender: from.into(),
            dest: (ih.dst.into(), dport),
            payload: inner.get(IP6_HEADER + UDP_HEADER..).unwrap_or(&[]).to_vec(),
        };
        self.udp_error(ih.src.into(), sport, e);
    }

    /// An ICMP error about a datagram sent from `src` port `sport`: a
    /// socket connected to its destination hears of it (SO_ERROR, the next
    /// receive); an unconnected one only with IP_RECVERR, which also
    /// queues it (ip(7); as Linux was seen to).
    fn udp_error(&mut self, src: IpAddr, sport: u16, e: QueuedError) {
        for s in self.sockets.iter_mut().flatten() {
            if !matches!(s.kind, Kind::Udp)
                || !s.d.local.is_some_and(|l| l.1 == sport && (l.0.is_unspecified() || l.0 == src))
            {
                continue;
            }
            let connected = s.d.remote == Some(e.dest);
            if s.d.remote.is_some() && !connected {
                continue;
            }
            if connected || s.d.recverr {
                s.d.error = Some(e.error);
            }
            if s.d.recverr && s.d.errq.len() < ERRQ_LIMIT {
                s.d.errq.push_back(e.clone());
            }
        }
    }

    // --- output ------------------------------------------------------------

    /// Where a packet to `dst` goes: (interface, next hop, link broadcast).
    fn next_hop(&self, dst: Ipv4, dev: Option<IfIndex>) -> Result<(IfIndex, Ipv4, bool)> {
        if dst == Ipv4::BROADCAST {
            // The limited broadcast leaves through the bound interface, else
            // the first usable card.
            let out = dev
                .or_else(|| self.ifaces.iter().find(|(k, i)| **k != LOOPBACK && i.usable()).map(|(k, _)| *k))
                .ok_or(Error::NetUnreachable)?;
            return Ok((out, dst, true));
        }
        if let Some((&k, _)) = self.ifaces.iter().find(|(k, i)| {
            **k != LOOPBACK && dev.is_none_or(|d| d == **k) && i.usable() && self.is_broadcast_on(**k, dst)
        }) {
            return Ok((k, dst, true));
        }
        let r = self.lookup(dst, dev).ok_or(Error::NetUnreachable)?;
        Ok((r.iface, r.gateway.unwrap_or(dst), false))
    }

    /// Send a packet whose IP header the caller wrote (IPPROTO_RAW): as
    /// raw(7) says, the total length and the header checksum are always
    /// filled in, the source address and the identification when zero.
    fn send_raw_ip(&mut self, data: &[u8], dev: Option<IfIndex>) -> Result<()> {
        if data.len() < IP_HEADER || data[0] >> 4 != 4 {
            return Err(Error::InvalidInput);
        }
        let hl = usize::from(data[0] & 0xF) * 4;
        if hl < IP_HEADER || hl > data.len() || data.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidInput);
        }
        let mut p = data.to_vec();
        let dst = ip_at(&p, 16);
        let total = p.len() as u16;
        put16(&mut p, 2, total);
        if get16(&p, 4) == 0 {
            self.ip_id = self.ip_id.wrapping_add(1);
            put16(&mut p, 4, self.ip_id);
        }
        if ip_at(&p, 12).is_unspecified() {
            let src = self.source_for(dst, dev);
            p[12..16].copy_from_slice(&src.0);
        }
        p[10..12].fill(0);
        let c = checksum(&p[..hl]);
        put16(&mut p, 10, c);
        let mut conn = None;
        if self.is_local(dst) {
            self.leaving(&mut p, LOOPBACK, &mut conn)?;
            self.looped.push_back((p, conn));
            return Ok(());
        }
        let (out, next_hop, broadcast) = self.next_hop(dst, dev)?;
        let (mtu, mac) = {
            let i = self.iface(out)?;
            (i.mtu, i.mac)
        };
        if p.len() > mtu {
            return Err(Error::MessageTooLong);
        }
        self.leaving(&mut p, out, &mut conn)?;
        if broadcast {
            self.emit(out, ethernet(Mac::BROADCAST, mac, ETHERTYPE_IPV4, &p), None);
        } else {
            self.transmit(out, next_hop, p, 0);
        }
        Ok(())
    }

    /// Send an IPv4 packet from `src` to `dst`.
    fn send_ip(&mut self, src: Ipv4, dst: Ipv4, proto: u8, payload: &[u8]) -> Result<()> {
        self.send_ip_dev(src, dst, proto, payload, None)
    }

    /// Send an IPv4 packet, out of `dev` only if given.
    fn send_ip_dev(&mut self, src: Ipv4, dst: Ipv4, proto: u8, payload: &[u8], dev: Option<IfIndex>) -> Result<()> {
        self.send_ip_opt(src, dst, proto, payload, dev, IpOptions::default())
    }

    fn send_ip_opt(
        &mut self,
        src: Ipv4,
        dst: Ipv4,
        proto: u8,
        payload: &[u8],
        dev: Option<IfIndex>,
        ip: IpOptions,
    ) -> Result<()> {
        // The options go out with this host's own entry in Record Route
        // and Timestamp, as a router would add one (RFC 791).
        let mut opts = ip.options;
        self.stamp_options(&mut opts.bytes[..usize::from(opts.len)], src);
        let header = IP_HEADER + opts.header_bytes();
        if self.is_local(dst) {
            self.ip_id = self.ip_id.wrapping_add(1);
            let mut p = ipv4_full(src, dst, proto, self.ip_id, DEFAULT_TTL, ip.tos, opts.as_slice(), payload);
            let mut conn = None;
            self.leaving(&mut p, LOOPBACK, &mut conn)?;
            self.looped.push_back((p, conn));
            return Ok(());
        }
        let (out, next_hop, broadcast) = self.next_hop(dst, dev)?;
        let (mtu, mac) = {
            let i = self.iface(out)?;
            (i.mtu.min(self.learned_mtu(dst)), i.mac)
        };
        // TCP's segments always fit (its MSS), but for a large one the card
        // cuts up itself (ADR 0083); other datagrams that do not go in
        // pieces (RFC 791 §2.3), unless the socket asked for none
        // (IP_PMTUDISC_DO, ip(7): EMSGSIZE instead).
        let too_big = header + payload.len() > mtu;
        let tso = if proto == PROTO_TCP && !broadcast { ip.tso } else { 0 };
        if (too_big && tso == 0 && (proto == PROTO_TCP || ip.dont_fragment))
            || header + payload.len() > usize::from(u16::MAX)
        {
            return Err(Error::MessageTooLong);
        }
        self.ip_id = self.ip_id.wrapping_add(1);
        let mut packet = ipv4_full(src, dst, proto, self.ip_id, DEFAULT_TTL, ip.tos, opts.as_slice(), payload);
        let mut conn = None;
        self.output(&mut packet, out, &mut conn)?;
        // NAT in output gave it another destination: its way is that one's.
        let to = ip_at(&packet, 16);
        if to != dst {
            if self.is_local(to) {
                self.postrouting(&mut packet, LOOPBACK, &mut conn)?;
                self.looped.push_back((packet, conn));
                return Ok(());
            }
            let (out, next_hop, _) = self.next_hop(to, None)?;
            self.postrouting(&mut packet, out, &mut conn)?;
            let mtu = self.iface(out)?.mtu.min(self.learned_mtu(to));
            let pieces = if packet.len() > mtu {
                if tso > 0 {
                    return Err(Error::MessageTooLong);
                }
                frag::fragment4(&packet, mtu)
            } else {
                alloc::vec![packet]
            };
            for p in pieces {
                self.transmit(out, next_hop, p, 0);
            }
            return Ok(());
        }
        self.postrouting(&mut packet, out, &mut conn)?;
        if tso > 0 && too_big {
            // The pieces take the identifications after this one.
            let pieces = payload.len().div_ceil(usize::from(tso)).max(1) as u16;
            self.ip_id = self.ip_id.wrapping_add(pieces - 1);
            self.transmit(out, next_hop, packet, tso);
            return Ok(());
        }
        let pieces = if packet.len() > mtu { frag::fragment4(&packet, mtu) } else { alloc::vec![packet] };
        for p in pieces {
            if broadcast {
                self.emit(out, ethernet(Mac::BROADCAST, mac, ETHERTYPE_IPV4, &p), None);
            } else {
                self.transmit(out, next_hop, p, 0);
            }
        }
        Ok(())
    }

    /// Send an IPv4 packet out of `out` to `next_hop`, resolving its
    /// hardware address first if need be.
    fn transmit(&mut self, out: IfIndex, next_hop: Ipv4, packet: Vec<u8>, tso: u16) {
        let now = self.now;
        let Some(i) = self.ifaces.get_mut(&out) else { return };
        let mac = i.mac;
        match i.arp.get(&next_hop) {
            Some(&(hw, _)) => self.emit_tso(out, ethernet(hw, mac, ETHERTYPE_IPV4, &packet), None, tso),
            None => {
                i.pending.push(Pending { next_hop, packet, tso });
                if let alloc::collections::btree_map::Entry::Vacant(e) = i.resolving.entry(next_hop) {
                    e.insert((now, 1));
                    self.arp_request(out, next_hop);
                }
            }
        }
    }

    /// Forward a packet that came in on `from` for another host (RFC 1812
    /// §5.2, §5.3): one less TTL, out by the routing table; ICMP errors
    /// back to the sender when its time ran out, there is no route, or it
    /// is too big for the next link and may not be fragmented.
    fn forward(&mut self, from: IfIndex, h: &Ipv4Header, packet: &[u8], mut conn: filter::Conn) {
        if h.ttl <= 1 {
            self.icmp_error(from, h, packet, ICMP_TIME_EXCEEDED, 0, [0; 4]);
            return;
        }
        let Some(r) = self.lookup(h.dst, None) else {
            self.icmp_error(from, h, packet, ICMP_DEST_UNREACHABLE, ICMP_NET_UNREACHABLE, [0; 4]);
            return;
        };
        // Postrouting may give it a new source (NAT); errors to the sender
        // quote it as it came.
        let mut p = packet.to_vec();
        if self.filtering()
            && (!self.arriving(filter::NF_INET_FORWARD, &mut p, from, Some(r.iface), &mut conn)
                || self.filter(filter::NF_INET_POST_ROUTING, &mut p, None, Some(r.iface), &mut conn)
                    != slate_nft::Outcome::Accept)
        {
            return;
        }
        let mtu = self.ifaces.get(&r.iface).map_or(1500, |i| i.mtu);
        if packet.len() > mtu && packet[6] & 0x40 != 0 {
            // Don't Fragment: tell the sender the next hop's MTU.
            let m = (mtu as u16).to_be_bytes();
            self.icmp_error(from, h, packet, ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED, [0, 0, m[0], m[1]]);
            return;
        }
        p[8] -= 1;
        if h.header_len > IP_HEADER {
            let out = self.ifaces.get(&r.iface).and_then(|i| i.source_towards(r.gateway.unwrap_or(h.dst)));
            if let Some(addr) = out {
                self.stamp_options(&mut p[IP_HEADER..h.header_len], addr);
            }
        }
        p[10..12].fill(0);
        let c = checksum(&p[..h.header_len]);
        put16(&mut p, 10, c);
        // Too big but may be fragmented: in pieces (RFC 1812 §5.2.6). Pieces
        // of pieces keep their offsets.
        let pieces = if p.len() > mtu { frag::fragment4(&p, mtu) } else { alloc::vec![p] };
        for p in pieces {
            self.transmit(r.iface, r.gateway.unwrap_or(h.dst), p, 0);
        }
    }

    /// An ICMP error about `packet` (which came in on `from`) to its sender,
    /// quoting its header and first 8 bytes (RFC 792). None about ICMP
    /// errors or broadcasts (RFC 1122 §3.2.2).
    fn icmp_error(&mut self, from: IfIndex, h: &Ipv4Header, packet: &[u8], kind: u8, code: u8, rest: [u8; 4]) {
        let inner = &packet[h.header_len..];
        let about_error =
            h.proto == PROTO_ICMP && !matches!(inner.first(), Some(&ICMP_ECHO_REQUEST | &ICMP_ECHO_REPLY));
        if about_error || self.is_broadcast_on(from, h.dst) || h.dst.is_multicast() || !self.icmp_allowed() {
            return;
        }
        let quoted = &packet[..(h.header_len + 8).min(packet.len())];
        let src = self
            .ifaces
            .get(&from)
            .and_then(|i| i.source_towards(h.src))
            .unwrap_or_else(|| self.source_for(h.src, None));
        let m = icmp(kind, code, rest, quoted);
        let _ = self.send_ip(src, h.src, PROTO_ICMP, &m);
    }

    /// Whether another ICMP error may go now (a token bucket of
    /// `ICMP_BURST`, one token back every `ICMP_REFILL_MS`), taking it.
    pub(super) fn icmp_allowed(&mut self) -> bool {
        let (last, tokens) = self.icmp_tokens;
        let back = (self.now.saturating_sub(last) / ICMP_REFILL_MS) as u32;
        let tokens = tokens.saturating_add(back).min(ICMP_BURST);
        let last = if back > 0 { self.now } else { last };
        if tokens == 0 {
            self.icmp_tokens = (last, 0);
            return false;
        }
        self.icmp_tokens = (last, tokens - 1);
        true
    }

    /// Queue a frame for interface `index`; packet sockets that take every
    /// protocol see it too (except `sender`, the socket that sent it).
    fn emit(&mut self, index: IfIndex, frame: Vec<u8>, sender: Option<Handle>) {
        self.emit_tso(index, frame, sender, 0);
    }

    /// Queue a frame, a large TCP segment if `tso` is not 0. Packet sockets
    /// see the frames the wire carries.
    fn emit_tso(&mut self, index: IfIndex, frame: Vec<u8>, sender: Option<Handle>, tso: u16) {
        if self.packets.iter().flatten().any(|p| p.protocol == ETH_P_ALL) {
            if tso == 0 {
                self.tap(index, &frame, PACKET_OUTGOING, sender);
            } else {
                for f in crate::wire::segment_tcp4(&frame, usize::from(tso)) {
                    self.tap(index, &f, PACKET_OUTGOING, sender);
                }
            }
        }
        self.tx.push((index, frame, tso));
    }

    /// Give a frame to the packet sockets that want it.
    fn tap(&mut self, index: IfIndex, frame: &[u8], pkttype: u8, sender: Option<Handle>) {
        if frame.len() < ETH_HEADER || self.packets.is_empty() {
            return;
        }
        let protocol = get16(frame, 12);
        let src = Mac(frame[6..12].try_into().unwrap());
        let mut delivered = false;
        for (h, p) in self.packets.iter_mut().enumerate() {
            let Some(p) = p else { continue };
            let wants = p.protocol == ETH_P_ALL || (p.protocol == protocol && pkttype != PACKET_OUTGOING);
            if !wants || p.device.is_some_and(|d| d != index) || sender == Some(h) {
                continue;
            }
            let data = if p.cooked { &frame[ETH_HEADER..] } else { frame };
            let keep = match &p.filter {
                Some(f) => slate_bpf::run_socket_filter(f, data) as usize,
                None => data.len(),
            };
            if keep == 0 || p.rx_bytes + data.len() > RX_LIMIT {
                continue;
            }
            let data = data[..keep.min(data.len())].to_vec();
            p.rx_bytes += data.len();
            p.rx.push_back((data, LinkAddr { iface: index, protocol, pkttype, mac: src }));
            delivered = true;
        }
        if delivered {
            self.events += 1;
        }
    }

    fn arp_request(&mut self, index: IfIndex, ip: Ipv4) {
        let Some(i) = self.ifaces.get(&index) else { return };
        let sender_ip = i.source_towards(ip).unwrap_or(Ipv4::UNSPECIFIED);
        let a = Arp { op: ARP_REQUEST, sender_mac: i.mac, sender_ip, target_mac: Mac::default(), target_ip: ip };
        let frame = ethernet(Mac::BROADCAST, i.mac, ETHERTYPE_ARP, &a.build());
        self.emit(index, frame, None);
    }

    /// The source address for packets to `dst` (out of `dev` if given).
    fn source_for(&self, dst: Ipv4, dev: Option<IfIndex>) -> Ipv4 {
        if dst.is_loopback() {
            return Ipv4::LOCALHOST;
        }
        if self.is_local(dst) {
            return dst;
        }
        let Ok((out, next_hop, _)) = self.next_hop(dst, dev) else { return Ipv4::UNSPECIFIED };
        if let Some(src) = self.lookup(dst, dev).and_then(|r| r.src).filter(|s| self.is_local(*s)) {
            return src;
        }
        self.ifaces.get(&out).and_then(|i| i.source_towards(next_hop)).unwrap_or(Ipv4::UNSPECIFIED)
    }

    /// The MTU of the way to `dst`.
    fn path_mtu(&self, dst: Ipv4) -> usize {
        let link = match self.next_hop(dst, None) {
            Ok((out, _, _)) => self.ifaces.get(&out).map_or(1500, |i| i.mtu),
            Err(_) => 1500,
        };
        link.min(self.learned_mtu(dst))
    }

    /// What "fragmentation needed" taught about the path to `dst`.
    fn learned_mtu(&self, dst: Ipv4) -> usize {
        self.pmtu4.get(&dst).map_or(usize::MAX, |(m, _)| *m)
    }

    // --- timers ------------------------------------------------------------

    /// A packet to the host's own address, by IP version.
    fn receive_looped(&mut self, p: &[u8], conn: filter::Conn) {
        match p.first().map(|b| b >> 4) {
            Some(6) => self.receive_ip6(LOOPBACK, p, true, conn),
            _ => self.receive_ip(LOOPBACK, p, true, conn),
        }
    }

    /// Run timers and deliver looped-back packets. Returns when it next
    /// needs to run (milliseconds), if it has a timer pending.
    pub fn poll(&mut self, now: u64) -> Option<u64> {
        self.now = now;
        self.tcp_output_later();
        let mut guard = 0;
        while let Some((p, conn)) = self.looped.pop_front() {
            self.receive_looped(&p, conn);
            guard += 1;
            if guard > 1024 {
                break;
            }
        }
        let mut next: Option<u64> = None;
        let mut soonest = |t: u64| next = Some(next.map_or(t, |n: u64| n.min(t)));
        let indices: Vec<IfIndex> = self.ifaces.keys().copied().collect();
        for index in indices {
            // ARP retries; give up on hops that never answer.
            let i = self.ifaces.get_mut(&index).unwrap();
            let due: Vec<Ipv4> =
                i.resolving.iter().filter(|(_, (t, _))| now >= t + ARP_RETRY_MS).map(|(ip, _)| *ip).collect();
            let mut ask = Vec::new();
            for ip in due {
                let tries = i.resolving[&ip].1;
                if tries >= ARP_TRIES {
                    i.resolving.remove(&ip);
                    i.pending.retain(|p| p.next_hop != ip);
                } else {
                    i.resolving.insert(ip, (now, tries + 1));
                    ask.push(ip);
                }
            }
            for (t, _) in i.resolving.values() {
                soonest(t + ARP_RETRY_MS);
            }
            let expired: Vec<(Ipv4, Mac)> =
                i.arp.iter().filter(|(_, (_, exp))| *exp <= now).map(|(ip, (m, _))| (*ip, *m)).collect();
            for (ip, mac) in expired {
                i.arp.remove(&ip);
                self.changes.push(Change::DelNeigh(Neighbour {
                    iface: index,
                    ip: ip.into(),
                    mac: Some(mac),
                    permanent: false,
                }));
            }
            for ip in ask {
                self.arp_request(index, ip);
            }
            if let Some(d) = self.dhcp_timer(index, now) {
                soonest(d);
            }
            if let Some(d) = self.timers6(index, now) {
                soonest(d);
            }
        }
        if let Some(d) = self.expire_routes6(now) {
            soonest(d);
        }
        self.expire_reassembly4(now);
        if let Some(d) = self.tcp_timers(now) {
            soonest(d);
        }
        // Timers may have queued looped-back segments.
        while let Some((p, conn)) = self.looped.pop_front() {
            self.receive_looped(&p, conn);
            guard += 1;
            if guard > 4096 {
                break;
            }
        }
        if !self.looped.is_empty() {
            soonest(now);
        }
        next
    }

    // --- DHCP --------------------------------------------------------------

    /// Start acquiring an address for an interface with DHCP.
    pub fn start_dhcp(&mut self, index: IfIndex, now: u64) -> Result<()> {
        self.now = now;
        let xid = self.rand();
        self.iface_mut(index)?.dhcp = Some(DhcpState::Selecting { xid, next: now, tries: 0 });
        self.dhcp_timer(index, now);
        Ok(())
    }

    /// Stop the interface's DHCP client (its address stays).
    pub fn stop_dhcp(&mut self, index: IfIndex) {
        if let Some(i) = self.ifaces.get_mut(&index) {
            i.dhcp = None;
        }
    }

    pub fn dhcp_bound(&self, index: IfIndex) -> bool {
        self.ifaces.get(&index).is_some_and(|i| matches!(i.dhcp, Some(DhcpState::Bound { .. })))
    }

    fn dhcp_send(&mut self, index: IfIndex, kind: u8, xid: u32, requested: Option<Ipv4>, server: Option<Ipv4>) {
        let Some(mac) = self.mac(index) else { return };
        let m = dhcp::client_message(kind, xid, mac, requested, server, &self.hostname.clone());
        let d = udp(Ipv4::UNSPECIFIED, dhcp::CLIENT_PORT, Ipv4::BROADCAST, dhcp::SERVER_PORT, &m);
        self.ip_id = self.ip_id.wrapping_add(1);
        let p = ipv4(Ipv4::UNSPECIFIED, Ipv4::BROADCAST, PROTO_UDP, self.ip_id, DEFAULT_TTL, &d);
        self.emit(index, ethernet(Mac::BROADCAST, mac, ETHERTYPE_IPV4, &p), None);
    }

    /// Retransmission backoff: 1, 2, 4, 8, then 16 seconds.
    fn backoff(tries: u32) -> u64 {
        1000 << tries.min(4)
    }

    fn dhcp_timer(&mut self, index: IfIndex, now: u64) -> Option<u64> {
        let state = self.ifaces.get_mut(&index)?.dhcp.take()?;
        let (state, next) = match state {
            DhcpState::Selecting { xid, next, tries } if now >= next => {
                self.dhcp_send(index, dhcp::DISCOVER, xid, None, None);
                let next = now + Self::backoff(tries);
                (DhcpState::Selecting { xid, next, tries: tries + 1 }, next)
            }
            DhcpState::Requesting { xid, offer, next, tries } if now >= next => {
                if tries >= 4 {
                    // No answer to the request: start over.
                    let xid = self.rand();
                    (DhcpState::Selecting { xid, next: now, tries: 0 }, now)
                } else {
                    self.dhcp_send(index, dhcp::REQUEST, xid, Some(offer.your_ip), offer.server);
                    let next = now + Self::backoff(tries);
                    (DhcpState::Requesting { xid, offer, next, tries: tries + 1 }, next)
                }
            }
            DhcpState::Bound { renew_at } if now >= renew_at => {
                // Renew by going through the exchange again, keeping the
                // current address meanwhile.
                let xid = self.rand();
                self.ifaces.get_mut(&index)?.dhcp = Some(DhcpState::Selecting { xid, next: now, tries: 0 });
                return self.dhcp_timer(index, now);
            }
            s => {
                let next = state_next(&s);
                (s, next)
            }
        };
        self.ifaces.get_mut(&index)?.dhcp = Some(state);
        Some(next)
    }

    fn dhcp_input(&mut self, index: IfIndex, m: &[u8]) {
        let Some(mac) = self.mac(index) else { return };
        let Some(r) = dhcp::parse_reply(m, mac) else { return };
        let now = self.now;
        let Some(state) = self.ifaces.get_mut(&index).and_then(|i| i.dhcp.take()) else { return };
        let state = match state {
            DhcpState::Selecting { xid, .. } if r.xid == xid && r.kind == dhcp::OFFER => {
                self.dhcp_send(index, dhcp::REQUEST, xid, Some(r.your_ip), r.server);
                DhcpState::Requesting { xid, offer: r, next: now + 1000, tries: 1 }
            }
            DhcpState::Requesting { xid, .. } if r.xid == xid && r.kind == dhcp::ACK => {
                let mask = r.subnet.unwrap_or(Ipv4([255, 255, 255, 0])).to_u32();
                let config = Config {
                    addr: r.your_ip,
                    prefix_len: mask.leading_ones() as u8,
                    gateway: r.router,
                    dns: r.dns.clone(),
                };
                let lease_secs = r.lease_secs.unwrap_or(86400);
                if let Some(i) = self.ifaces.get_mut(&index) {
                    i.lease = Some(Lease { server: r.server, lease_secs, domain: r.domain.clone() });
                }
                let _ = self.set_config(index, Some(config), PROTO_DHCP);
                // Renew at half the lease (T1, RFC 2131 §4.4.5).
                DhcpState::Bound { renew_at: now + u64::from(lease_secs) * 500 }
            }
            DhcpState::Requesting { xid, .. } if r.xid == xid && r.kind == dhcp::NAK => {
                DhcpState::Selecting { xid: self.rand(), next: now, tries: 0 }
            }
            other => other,
        };
        if let Some(i) = self.ifaces.get_mut(&index) {
            i.dhcp = Some(state);
        }
    }

    // --- sockets -----------------------------------------------------------

    fn alloc(&mut self, kind: Kind) -> Handle {
        let s = Some(Socket { kind, d: DgramSocket::default() });
        match self.sockets.iter().position(Option::is_none) {
            Some(i) => {
                self.sockets[i] = s;
                i
            }
            None => {
                self.sockets.push(s);
                self.sockets.len() - 1
            }
        }
    }

    pub fn udp_open(&mut self) -> Handle {
        self.alloc(Kind::Udp)
    }

    /// An ICMP socket: `raw` for SOCK_RAW, else a ping socket.
    pub fn icmp_open(&mut self, raw: bool) -> Handle {
        self.alloc(if raw { Kind::RawIcmp } else { Kind::Ping })
    }

    /// An ICMPv6 socket (AF_INET6): `raw` for SOCK_RAW, else a ping socket.
    pub fn icmp6_open(&mut self, raw: bool) -> Handle {
        let h = self.alloc(if raw { Kind::RawIcmp6 } else { Kind::Ping6 });
        if let Ok(s) = self.sock(h) {
            s.d.v6 = true;
            s.d.v6only = true;
        }
        h
    }

    /// A send-only raw IP socket (IPPROTO_RAW, raw(7)): the caller writes
    /// the IP header.
    pub fn raw_ip_open(&mut self) -> Handle {
        self.alloc(Kind::RawIp)
    }

    pub fn close(&mut self, h: Handle) {
        if let Some(s) = self.sockets.get_mut(h) {
            *s = None;
        }
    }

    /// The TCP and UDP sockets that have an address, TCP first.
    pub fn socket_table(&self) -> Vec<SocketEntry> {
        let mut v = Vec::new();
        self.tcp_entries(&mut v);
        for (handle, s) in self.sockets.iter().enumerate().filter_map(|(h, s)| Some((h, s.as_ref()?))) {
            if let (Kind::Udp, Some(local)) = (&s.kind, s.d.local) {
                v.push(SocketEntry {
                    tcp: false,
                    v6: s.d.v6,
                    local,
                    remote: s.d.remote,
                    state: None,
                    tx_queue: 0,
                    rx_queue: s.d.rx_bytes,
                    handle,
                });
            }
        }
        v
    }

    fn sock(&mut self, h: Handle) -> Result<&mut Socket> {
        self.sockets.get_mut(h).and_then(Option::as_mut).ok_or(Error::BadHandle)
    }

    /// SO_BINDTODEVICE: send and receive only on `dev` (`None`: any).
    pub fn bind_device(&mut self, h: Handle, dev: Option<IfIndex>) -> Result<()> {
        if let Some(d) = dev {
            self.iface(d)?;
        }
        self.sock(h)?.d.device = dev;
        Ok(())
    }

    pub fn device(&mut self, h: Handle) -> Result<Option<IfIndex>> {
        Ok(self.sock(h)?.d.device)
    }

    /// AF_INET6 (and IPV6_V6ONLY), before the socket is bound.
    pub fn set_family(&mut self, h: Handle, v6: bool, v6only: bool) -> Result<()> {
        let s = self.sock(h)?;
        if s.d.local.is_some() {
            return Err(Error::InvalidInput);
        }
        (s.d.v6, s.d.v6only) = (v6, v6only);
        Ok(())
    }

    /// (AF_INET6, IPV6_V6ONLY).
    pub fn family(&mut self, h: Handle) -> Result<(bool, bool)> {
        let s = self.sock(h)?;
        Ok((s.d.v6, s.d.v6only))
    }

    /// ICMP6_FILTER: the ICMPv6 types a raw ICMPv6 socket blocks (bit set:
    /// blocked, RFC 3542 §3.2).
    pub fn set_icmp6_filter(&mut self, h: Handle, blocked: [u32; 8]) -> Result<()> {
        self.sock(h)?.d.blocked6 = blocked;
        Ok(())
    }

    pub fn icmp6_filter(&mut self, h: Handle) -> Result<[u32; 8]> {
        Ok(self.sock(h)?.d.blocked6)
    }

    /// Whether a socket of this kind holds `port` in a way that conflicts
    /// with one bound to `addr` on `dev` (sockets on different interfaces
    /// or different families do not).
    fn port_in_use(&self, port: u16, kind: u8, addr: IpAddr, v6only: bool, dev: Option<IfIndex>) -> bool {
        self.sockets.iter().flatten().any(|s| {
            kind_class(&s.kind) == kind
                && s.d.local.is_some_and(|l| l.1 == port && overlap(l.0, s.d.v6only, addr, v6only))
                && (s.d.device.is_none() || dev.is_none() || s.d.device == dev)
        })
    }

    fn ephemeral(&mut self, kind: u8, addr: IpAddr, v6only: bool) -> Result<u16> {
        for _ in 0..EPHEMERAL.len() {
            let p = self.next_port;
            self.next_port = if p == *EPHEMERAL.end() { *EPHEMERAL.start() } else { p + 1 };
            if !self.port_in_use(p, kind, addr, v6only, None) {
                return Ok(p);
            }
        }
        Err(Error::AddrInUse)
    }

    /// bind(2): port 0 picks an ephemeral port. An AF_INET6 socket may
    /// bind an IPv4 address (a mapped one, from the caller).
    pub fn bind(&mut self, h: Handle, addr: impl Into<IpAddr>, port: u16) -> Result<Endpoint> {
        let addr = addr.into();
        let (kind, dev, v6, v6only) = {
            let s = self.sock(h)?;
            if s.d.local.is_some() {
                return Err(Error::InvalidInput);
            }
            (kind_class(&s.kind), s.d.device, s.d.v6, s.d.v6only)
        };
        if (addr.is_v6() && !v6) || (!addr.is_v6() && v6 && v6only) {
            return Err(Error::InvalidInput);
        }
        if !self.can_bind(addr) {
            return Err(Error::AddrNotAvailable);
        }
        let port = if kind == RAW {
            0
        } else if port == 0 {
            self.ephemeral(kind, addr, v6only)?
        } else if self.port_in_use(port, kind, addr, v6only, dev) {
            return Err(Error::AddrInUse);
        } else {
            port
        };
        self.sock(h)?.d.local = Some((addr, port));
        Ok((addr, port))
    }

    fn auto_bind(&mut self, h: Handle) -> Result<Endpoint> {
        let s = self.sock(h)?;
        match s.d.local {
            Some(l) => Ok(l),
            None => {
                let any = if s.d.v6 { IpAddr::V6(Ipv6::UNSPECIFIED) } else { IpAddr::V4(Ipv4::UNSPECIFIED) };
                self.bind(h, any, 0)
            }
        }
    }

    /// Whether a socket may bind to `ip`: any, one of ours, or the IPv4
    /// broadcast address.
    pub fn can_bind(&self, ip: impl Into<IpAddr>) -> bool {
        match ip.into() {
            IpAddr::V4(a) => a.is_unspecified() || a == Ipv4::BROADCAST || self.is_local(a),
            IpAddr::V6(a) => a.is_unspecified() || self.is_local6(a, None),
        }
    }

    /// Whether packets to `dst` can go anywhere (out of `dev` if given).
    fn routable(&self, dst: IpAddr, dev: Option<IfIndex>) -> bool {
        match dst {
            IpAddr::V4(d) => self.is_local(d) || self.next_hop(d, dev).is_ok(),
            IpAddr::V6(d) => self.is_local6(d, dev) || d.is_loopback() || self.next_hop6(d, dev).is_ok(),
        }
    }

    /// Whether `ip` is one of the host's addresses.
    fn is_local_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => self.is_local(a),
            IpAddr::V6(a) => self.is_local6(a, None),
        }
    }

    /// The source address for packets to `dst`, of its family.
    fn source_for_ip(&self, dst: IpAddr, dev: Option<IfIndex>) -> IpAddr {
        match dst {
            IpAddr::V4(d) => self.source_for(d, dev).into(),
            IpAddr::V6(d) => self.source_for6(d, dev).into(),
        }
    }

    /// Send a packet of either family.
    fn send_ipx(&mut self, src: IpAddr, dst: IpAddr, proto: u8, payload: &[u8]) -> Result<()> {
        self.send_ipx_dev(src, dst, proto, payload, None)
    }

    fn send_ipx_dev(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        payload: &[u8],
        dev: Option<IfIndex>,
    ) -> Result<()> {
        self.send_ipx_opt(src, dst, proto, payload, dev, IpOptions::default())
    }

    /// Send with a socket's IP settings: IPv4's, and for IPv6 the traffic
    /// class (IPV6_TCLASS, kept in `tos`).
    fn send_ipx_opt(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        proto: u8,
        payload: &[u8],
        dev: Option<IfIndex>,
        ip: IpOptions,
    ) -> Result<()> {
        match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => self.send_ip_opt(s, d, proto, payload, dev, ip),
            (IpAddr::V6(s), IpAddr::V6(d)) => self.send_ip6_tc(s, d, proto, payload, dev, ip.tos),
            _ => Err(Error::InvalidInput),
        }
    }

    /// connect(2) for datagram sockets: the default destination and the
    /// only peer datagrams are accepted from. An unspecified address
    /// disconnects.
    /// IP_TOS and IP_MTU_DISCOVER for a datagram socket.
    pub fn set_ip_options(&mut self, h: Handle, o: IpOptions) -> Result<()> {
        self.sock(h)?.d.ip = o;
        Ok(())
    }

    /// A datagram socket's IPv4 header settings.
    pub fn ip_options(&mut self, h: Handle) -> Result<IpOptions> {
        Ok(self.sock(h)?.d.ip)
    }

    /// SO_DONTROUTE for a datagram socket.
    pub fn set_dontroute(&mut self, h: Handle, on: bool) -> Result<()> {
        self.sock(h)?.d.dontroute = on;
        Ok(())
    }

    /// Whether `dst` is on a directly attached network (or this host), so
    /// no gateway is needed (SO_DONTROUTE).
    fn on_link(&self, dst: IpAddr, dev: Option<IfIndex>) -> bool {
        match dst {
            _ if self.is_local_ip(dst) => true,
            IpAddr::V4(d) => self.next_hop(d, dev).is_ok_and(|(_, hop, _)| hop == d),
            IpAddr::V6(d) => self.next_hop6(d, dev).is_ok_and(|(_, hop)| hop == d),
        }
    }

    pub fn connect(&mut self, h: Handle, remote: Endpoint) -> Result<()> {
        let (dev, v6, v6only, dontroute) = {
            let s = self.sock(h)?;
            (s.d.device, s.d.v6, s.d.v6only, s.d.dontroute)
        };
        if (remote.0.is_v6() && !v6) || (!remote.0.is_v6() && v6 && v6only && !remote.0.is_unspecified()) {
            return Err(Error::InvalidInput);
        }
        // A destination with no route fails now, as udp(7) connect does;
        // with SO_DONTROUTE, so does one behind a gateway.
        if !remote.0.is_unspecified() && (!self.routable(remote.0, dev) || (dontroute && !self.on_link(remote.0, dev)))
        {
            return Err(Error::NetUnreachable);
        }
        let (port_local, udp) = {
            let l = self.auto_bind(h)?;
            (l, matches!(self.sock(h)?.kind, Kind::Udp))
        };
        // udp(7): connect also sets the local address, the source the
        // route would use, which getsockname then reports. Resolvers
        // order a name's addresses by it (RFC 6724's destination address
        // selection, as musl's and glibc's getaddrinfo do): a wildcard
        // there looks like a global source and puts IPv6 first even with
        // only a site- or link-local address to send from. No source for
        // the destination at all: EADDRNOTAVAIL.
        let mut local = port_local;
        let by_connect = self.sock(h)?.d.local_by_connect;
        if udp && !remote.0.is_unspecified() && remote.0.is_v6() == local.0.is_v6() {
            if local.0.is_unspecified() {
                let src = self.source_for_ip(remote.0, dev);
                if src.is_unspecified() {
                    return Err(Error::AddrNotAvailable);
                }
                local.0 = src;
                let s = self.sock(h)?;
                s.d.local = Some(local);
                s.d.local_by_connect = true;
            } else if by_connect {
                // Connected again elsewhere: the source for there.
                let src = self.source_for_ip(remote.0, dev);
                if !src.is_unspecified() {
                    self.sock(h)?.d.local = Some((src, local.1));
                }
            }
        }
        let s = self.sock(h)?;
        if remote.0.is_unspecified() && s.d.local_by_connect {
            // Disconnected: back to the wildcard (and the same port).
            let any = if local.0.is_v6() { IpAddr::V6(Ipv6::UNSPECIFIED) } else { IpAddr::V4(Ipv4::UNSPECIFIED) };
            s.d.local = Some((any, local.1));
            s.d.local_by_connect = false;
        }
        s.d.remote = if remote.0.is_unspecified() { None } else { Some(remote) };
        s.d.error = None;
        Ok(())
    }

    pub fn local(&mut self, h: Handle) -> Result<Option<Endpoint>> {
        Ok(self.sock(h)?.d.local)
    }

    pub fn remote(&mut self, h: Handle) -> Result<Option<Endpoint>> {
        Ok(self.sock(h)?.d.remote)
    }

    /// Send a datagram to `to` (or the connected peer).
    /// UDP_SEGMENT (udp(7), generic segmentation offload): `data` sent as
    /// datagrams of `segment` bytes each (the last shorter). Each must fit
    /// the path's MTU with its headers (EMSGSIZE), and at most
    /// [`UDP_MAX_SEGMENTS`] go at once (EINVAL), as Linux was seen to
    /// check. A send no longer than one segment is an ordinary one.
    pub fn send_segments(&mut self, h: Handle, data: &[u8], to: Option<Endpoint>, segment: usize) -> Result<usize> {
        if segment == 0 || data.len() <= segment {
            return self.send_to(h, data, to);
        }
        let s = self.sock(h)?;
        if !matches!(s.kind, Kind::Udp) {
            return Err(Error::InvalidInput);
        }
        if data.len().div_ceil(segment) > UDP_MAX_SEGMENTS {
            return Err(Error::InvalidInput);
        }
        let (dst, _) = to.or(s.d.remote).ok_or(Error::NotConnected)?;
        let dev = s.d.device;
        let (mtu, ip) = match dst {
            IpAddr::V4(d) => (self.next_hop(d, dev).ok().and_then(|(i, _, _)| self.mtu(i)), IP_HEADER),
            IpAddr::V6(d) => (Some(self.path_mtu6(d)), IP6_HEADER),
        };
        if mtu.is_some_and(|m| segment + UDP_HEADER + ip > m) {
            return Err(Error::MessageTooLong);
        }
        for chunk in data.chunks(segment) {
            self.send_to(h, chunk, to)?;
        }
        Ok(data.len())
    }

    pub fn send_to(&mut self, h: Handle, data: &[u8], to: Option<Endpoint>) -> Result<usize> {
        let (laddr, lport) = self.auto_bind(h)?;
        let s = self.sock(h)?;
        if let Some(e) = s.d.error.take() {
            return Err(e);
        }
        let (dst, dport) = to.or(s.d.remote).ok_or(Error::NotConnected)?;
        let (dev, v6, v6only, ip, dontroute) = (s.d.device, s.d.v6, s.d.v6only, s.d.ip, s.d.dontroute);
        if (dst.is_v6() && !v6) || (!dst.is_v6() && v6 && v6only) {
            return Err(Error::InvalidInput);
        }
        if dontroute && !self.on_link(dst, dev) {
            return Err(Error::NetUnreachable);
        }
        let wildcard = laddr.is_unspecified() || laddr == IpAddr::V4(Ipv4::BROADCAST);
        let src = if wildcard { self.source_for_ip(dst, dev) } else { laddr };
        if src.is_v6() != dst.is_v6() {
            return Err(Error::InvalidInput); // Bound to the other family.
        }
        match self.sock(h)?.kind {
            Kind::Udp => {
                if dport == 0 {
                    return Err(Error::InvalidInput);
                }
                let d = udp_ip(src, lport, dst, dport, data);
                self.send_ipx_opt(src, dst, PROTO_UDP, &d, dev, ip)?;
            }
            Kind::Ping => {
                let (IpAddr::V4(s4), IpAddr::V4(d4)) = (src, dst) else { return Err(Error::InvalidInput) };
                if data.len() < 8 || data[0] != ICMP_ECHO_REQUEST {
                    return Err(Error::InvalidInput);
                }
                // The identifier is the socket's "port".
                let mut rest: [u8; 4] = data[4..8].try_into().unwrap();
                rest[..2].copy_from_slice(&lport.to_be_bytes());
                let m = icmp(ICMP_ECHO_REQUEST, data[1], rest, &data[8..]);
                self.send_ip_opt(s4, d4, PROTO_ICMP, &m, dev, ip)?;
            }
            Kind::Ping6 => {
                let (IpAddr::V6(s6), IpAddr::V6(d6)) = (src, dst) else { return Err(Error::InvalidInput) };
                if data.len() < 8 || data[0] != ICMP6_ECHO_REQUEST {
                    return Err(Error::InvalidInput);
                }
                let mut rest: [u8; 4] = data[4..8].try_into().unwrap();
                rest[..2].copy_from_slice(&lport.to_be_bytes());
                let m = icmpv6(s6, d6, ICMP6_ECHO_REQUEST, data[1], rest, &data[8..]);
                self.send_ip6_dev(s6, d6, PROTO_ICMPV6, &m, dev)?;
            }
            Kind::RawIcmp => {
                let (IpAddr::V4(s4), IpAddr::V4(d4)) = (src, dst) else { return Err(Error::InvalidInput) };
                self.send_ip_opt(s4, d4, PROTO_ICMP, data, dev, ip)?
            }
            Kind::RawIcmp6 => {
                let (IpAddr::V6(s6), IpAddr::V6(d6)) = (src, dst) else { return Err(Error::InvalidInput) };
                if data.len() < 4 {
                    return Err(Error::InvalidInput);
                }
                // The checksum is the stack's to fill in (RFC 3542 §3.1).
                let m = icmpv6(
                    s6,
                    d6,
                    data[0],
                    data[1],
                    data.get(4..8).map_or([0; 4], |r| r.try_into().unwrap()),
                    data.get(8..).unwrap_or(&[]),
                );
                self.send_ip6_dev(s6, d6, PROTO_ICMPV6, &m, dev)?
            }
            Kind::RawIp => self.send_raw_ip(data, dev)?,
        }
        Ok(data.len())
    }

    /// Receive a datagram: (data, sender).
    pub fn recv_from(&mut self, h: Handle) -> Result<(Vec<u8>, Endpoint)> {
        let s = self.sock(h)?;
        match s.d.rx.pop_front() {
            Some(d) => {
                s.d.rx_bytes -= d.data.len();
                Ok((d.data, d.from))
            }
            None => Err(s.d.error.take().unwrap_or(Error::WouldBlock)),
        }
    }

    /// Receive a datagram with where and how it arrived.
    pub fn recv_meta(&mut self, h: Handle) -> Result<(Vec<u8>, Endpoint, RecvMeta)> {
        let s = self.sock(h)?;
        match s.d.rx.pop_front() {
            Some(d) => {
                s.d.rx_bytes -= d.data.len();
                Ok((d.data, d.from, d.meta))
            }
            None => Err(s.d.error.take().unwrap_or(Error::WouldBlock)),
        }
    }

    /// [`Stack::recv_meta`], the datagram left queued (MSG_PEEK).
    pub fn peek_meta(&mut self, h: Handle) -> Result<(Vec<u8>, Endpoint, RecvMeta)> {
        let s = self.sock(h)?;
        match s.d.rx.front() {
            Some(d) => Ok((d.data.clone(), d.from, d.meta)),
            None => Err(s.d.error.unwrap_or(Error::WouldBlock)),
        }
    }

    /// IP_RECVERR on or off (off empties the queue).
    pub fn set_recverr(&mut self, h: Handle, on: bool) -> Result<()> {
        let s = self.sock(h)?;
        s.d.recverr = on;
        if !on {
            s.d.errq.clear();
        }
        Ok(())
    }

    /// The oldest queued ICMP error (MSG_ERRQUEUE), or WouldBlock.
    pub fn recv_error(&mut self, h: Handle, peek: bool) -> Result<QueuedError> {
        let s = self.sock(h)?;
        let e = if peek { s.d.errq.front().cloned() } else { s.d.errq.pop_front() };
        e.ok_or(Error::WouldBlock)
    }

    /// Whether errors are queued (poll's POLLERR).
    pub fn errors_queued(&mut self, h: Handle) -> bool {
        self.sock(h).is_ok_and(|s| !s.d.errq.is_empty())
    }

    /// The next datagram, left queued (MSG_PEEK).
    pub fn peek_from(&mut self, h: Handle) -> Result<(Vec<u8>, Endpoint)> {
        let s = self.sock(h)?;
        match s.d.rx.front() {
            Some(d) => Ok((d.data.clone(), d.from)),
            None => Err(s.d.error.unwrap_or(Error::WouldBlock)),
        }
    }

    /// The pending error, cleared (SO_ERROR).
    pub fn take_error(&mut self, h: Handle) -> Result<Option<Error>> {
        Ok(self.sock(h)?.d.error.take())
    }

    /// Size of the next datagram, if any (FIONREAD).
    pub fn peek_len(&mut self, h: Handle) -> Result<Option<usize>> {
        Ok(self.sock(h)?.d.rx.front().map(|d| d.data.len()))
    }

    /// (readable, writable, error pending).
    pub fn readiness(&mut self, h: Handle) -> Result<(bool, bool, bool)> {
        let s = self.sock(h)?;
        // An error alone is POLLERR, not POLLIN (as Linux was seen to);
        // select(2) counts it as readable all the same.
        Ok((!s.d.rx.is_empty(), true, s.d.error.is_some() || !s.d.errq.is_empty()))
    }
}

/// When a DHCP state's timer is due.
fn state_next(s: &DhcpState) -> u64 {
    match s {
        DhcpState::Selecting { next, .. } | DhcpState::Requesting { next, .. } => *next,
        DhcpState::Bound { renew_at } => *renew_at,
    }
}

// Port spaces: UDP, ping identifiers per family, and raw sockets (none).
const UDP: u8 = 0;
const PING: u8 = 1;
const PING6: u8 = 2;
const RAW: u8 = 3;

fn kind_class(k: &Kind) -> u8 {
    match k {
        Kind::Udp => UDP,
        Kind::Ping => PING,
        Kind::Ping6 => PING6,
        Kind::RawIcmp | Kind::RawIcmp6 | Kind::RawIp => RAW,
    }
}

fn push_dgram(d: &mut DgramSocket, data: Vec<u8>, from: Endpoint) {
    push_dgram_meta(d, data, from, RecvMeta::default());
}

fn push_dgram_meta(d: &mut DgramSocket, data: Vec<u8>, from: Endpoint, meta: RecvMeta) {
    if d.rx_bytes + data.len() > RX_LIMIT {
        return; // Full: datagrams may be dropped.
    }
    d.rx_bytes += data.len();
    d.rx.push_back(Datagram { data, from, meta });
}

/// The error an ICMPv4 message about a datagram means (RFC 792's types
/// and codes, with RFC 1122 §4.2.3.9's grouping: net, protocol, port,
/// fragmentation needed; the rest, and time exceeded, say the host
/// can't be reached).
fn icmp4_error(kind: u8, code: u8) -> Error {
    match (kind, code) {
        (ICMP_DEST_UNREACHABLE, 0 | 6 | 11) => Error::NetUnreachable,
        (ICMP_DEST_UNREACHABLE, 2) => Error::ProtocolUnavailable,
        (ICMP_DEST_UNREACHABLE, ICMP_PORT_UNREACHABLE) => Error::ConnectionRefused,
        (ICMP_DEST_UNREACHABLE, ICMP_FRAG_NEEDED) => Error::MessageTooLong,
        _ => Error::HostUnreachable,
    }
}

/// The same for ICMPv6 (RFC 4443 §3): no route, port unreachable, packet
/// too big; the rest say the host can't be reached.
fn icmp6_error_of(kind: u8, code: u8) -> Error {
    match (kind, code) {
        (ICMP6_DEST_UNREACHABLE, ICMP6_NO_ROUTE) => Error::NetUnreachable,
        (ICMP6_DEST_UNREACHABLE, ICMP6_PORT_UNREACHABLE) => Error::ConnectionRefused,
        (ICMP6_PACKET_TOO_BIG, _) => Error::MessageTooLong,
        _ => Error::HostUnreachable,
    }
}

// --- the ARP table, forwarding, packet sockets (ADR 0049) ---------------------

impl Stack {
    /// Every ARP and IPv6 neighbour cache entry, and the addresses being
    /// resolved.
    pub fn neighbours(&self) -> Vec<Neighbour> {
        let mut out = Vec::new();
        for (&iface, i) in &self.ifaces {
            for (&ip, &(mac, exp)) in &i.arp {
                out.push(Neighbour { iface, ip: ip.into(), mac: Some(mac), permanent: exp == PERMANENT });
            }
            for &ip in i.resolving.keys() {
                out.push(Neighbour { iface, ip: ip.into(), mac: None, permanent: false });
            }
            for (&ip, &(mac, exp)) in &i.v6.nd {
                out.push(Neighbour { iface, ip: ip.into(), mac: Some(mac), permanent: exp == u64::MAX });
            }
            for &ip in i.v6.resolving.keys() {
                out.push(Neighbour { iface, ip: ip.into(), mac: None, permanent: false });
            }
        }
        out
    }

    /// Set an entry by hand (it never expires; arp(8) `-s`, `ip neigh add`).
    pub fn add_neighbour(&mut self, iface: IfIndex, ip: IpAddr, mac: Mac) -> Result<()> {
        let ip = match ip {
            IpAddr::V6(a) => return self.add_neighbour6(iface, a, mac),
            IpAddr::V4(a) => a,
        };
        if ip.is_unspecified() || ip.is_multicast() || ip == Ipv4::BROADCAST || iface == LOOPBACK {
            return Err(Error::InvalidInput);
        }
        self.iface_mut(iface)?.arp.insert(ip, (mac, PERMANENT));
        self.changes.push(Change::NewNeigh(Neighbour { iface, ip: ip.into(), mac: Some(mac), permanent: true }));
        self.flush_pending(iface, ip, mac);
        self.events += 1;
        Ok(())
    }

    /// Remove an entry (learned or set by hand).
    pub fn del_neighbour(&mut self, iface: IfIndex, ip: IpAddr) -> Result<()> {
        let ip = match ip {
            IpAddr::V6(a) => return self.del_neighbour6(iface, a),
            IpAddr::V4(a) => a,
        };
        let i = self.iface_mut(iface)?;
        let (mac, exp) = i.arp.remove(&ip).ok_or(Error::NotFound)?;
        self.changes.push(Change::DelNeigh(Neighbour {
            iface,
            ip: ip.into(),
            mac: Some(mac),
            permanent: exp == PERMANENT,
        }));
        Ok(())
    }

    pub fn forwarding(&self) -> bool {
        self.forwarding
    }
    pub fn set_forwarding(&mut self, on: bool) {
        self.forwarding = on;
    }

    /// A packet socket for ethertype `protocol` (ETH_P_ALL: every one, 0:
    /// none until bound); `cooked` (SOCK_DGRAM) strips the Ethernet header.
    pub fn packet_open(&mut self, protocol: u16, cooked: bool) -> Handle {
        let p = Some(PacketSock { protocol, cooked, device: None, rx: VecDeque::new(), rx_bytes: 0, filter: None });
        match self.packets.iter().position(Option::is_none) {
            Some(i) => {
                self.packets[i] = p;
                i
            }
            None => {
                self.packets.push(p);
                self.packets.len() - 1
            }
        }
    }

    pub fn packet_close(&mut self, h: Handle) {
        if let Some(p) = self.packets.get_mut(h) {
            *p = None;
        }
    }

    fn packet(&mut self, h: Handle) -> Result<&mut PacketSock> {
        self.packets.get_mut(h).and_then(Option::as_mut).ok_or(Error::BadHandle)
    }

    /// bind(2): the ethertype (0 keeps it) and the interface (None: any).
    pub fn packet_bind(&mut self, h: Handle, protocol: u16, dev: Option<IfIndex>) -> Result<()> {
        if let Some(d) = dev {
            self.iface(d)?;
        }
        let p = self.packet(h)?;
        if protocol != 0 {
            p.protocol = protocol;
        }
        p.device = dev;
        Ok(())
    }

    /// (ethertype, interface) as bound.
    pub fn packet_local(&mut self, h: Handle) -> Result<(u16, Option<IfIndex>)> {
        let p = self.packet(h)?;
        Ok((p.protocol, p.device))
    }

    /// SO_ATTACH_FILTER (a classic BPF program; checked here) or, with
    /// None, SO_DETACH_FILTER.
    pub fn packet_filter(&mut self, h: Handle, prog: Option<Vec<SockFilter>>) -> Result<()> {
        if let Some(f) = &prog {
            slate_bpf::check_socket_filter(f).map_err(|_| Error::InvalidInput)?;
        }
        self.packet(h)?.filter = prog;
        Ok(())
    }

    /// Send a frame (raw: the whole frame; cooked: the payload, with the
    /// header built for `to`'s address and protocol). Out of `to`'s
    /// interface, else the bound one.
    pub fn packet_send(&mut self, h: Handle, data: &[u8], to: Option<LinkAddr>) -> Result<usize> {
        let (cooked, protocol, device) = {
            let p = self.packet(h)?;
            (p.cooked, p.protocol, p.device)
        };
        let dev = to.map(|t| t.iface).filter(|&i| i != 0).or(device).ok_or(Error::NoDevice)?;
        let (mac, mtu, up) = {
            let i = self.iface(dev)?;
            (i.mac, i.mtu, i.up)
        };
        if !up {
            return Err(Error::NetUnreachable);
        }
        let frame = if cooked {
            let to = to.ok_or(Error::NotConnected)?;
            if data.len() > mtu {
                return Err(Error::MessageTooLong);
            }
            let proto = if to.protocol != 0 { to.protocol } else { protocol };
            ethernet(to.mac, mac, proto, data)
        } else {
            if data.len() < ETH_HEADER {
                return Err(Error::InvalidInput);
            }
            if data.len() > mtu + ETH_HEADER {
                return Err(Error::MessageTooLong);
            }
            data.to_vec()
        };
        self.emit(dev, frame, Some(h));
        Ok(data.len())
    }

    /// The next frame (left queued with `peek`).
    pub fn packet_recv(&mut self, h: Handle, peek: bool) -> Result<(Vec<u8>, LinkAddr)> {
        let p = self.packet(h)?;
        if peek {
            return p.rx.front().cloned().ok_or(Error::WouldBlock);
        }
        let (d, a) = p.rx.pop_front().ok_or(Error::WouldBlock)?;
        p.rx_bytes -= d.len();
        Ok((d, a))
    }

    /// Size of the next frame, if any (FIONREAD).
    pub fn packet_peek_len(&mut self, h: Handle) -> Result<Option<usize>> {
        Ok(self.packet(h)?.rx.front().map(|(d, _)| d.len()))
    }

    pub fn packet_readable(&mut self, h: Handle) -> Result<bool> {
        Ok(!self.packet(h)?.rx.is_empty())
    }
}
