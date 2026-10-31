// SPDX-License-Identifier: MIT OR Apache-2.0

//! Socket system calls (socket(2), ip(7), tcp(7), udp(7), icmp(7), raw(7),
//! unix(7), netlink(7), packet(7)). Constants from musl `sys/socket.h`,
//! `netinet/in.h`, `sys/un.h` (ADR 0009) and the man pages.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use super::errno::*;
use super::{Args, Result};
use crate::arch::uaccess::{copy_from_user, copy_to_user, read_user, write_user};
use crate::fs::{File, O_CLOEXEC, O_NONBLOCK, vfs};
use crate::net::netlink::NetlinkSocket;
use crate::net::packet::{AF_PACKET, PacketSocket, sockaddr_ll};
use crate::net::socket::{AF_INET, InetSocket, Kind, SockOpts, encode, parse_sockaddr};
use crate::net::tcp::TcpSocket;
use crate::net::uevent::{NETLINK_KOBJECT_UEVENT, UeventSocket};
use crate::net::unix::{self, Address, UnixSocket};

const AF_UNIX: u64 = 1;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_SEQPACKET: u64 = 5;
const SOCK_TYPE_MASK: u64 = 0xF;
const IPPROTO_ICMP: u64 = 1;
const IPPROTO_TCP: u64 = 6;
// TCP options (tcp(7); numbers from musl `netinet/tcp.h`).
const TCP_NODELAY: u64 = 1;
const TCP_MAXSEG: u64 = 2;
const TCP_CORK: u64 = 3;
const TCP_KEEPIDLE: u64 = 4;
const TCP_KEEPINTVL: u64 = 5;
const TCP_KEEPCNT: u64 = 6;
const TCP_INFO: u64 = 11;
const TCP_QUICKACK: u64 = 12;
// TCP_INFO's option bits (musl `netinet/tcp.h` TCPI_OPT_*).
const TCPI_OPT_TIMESTAMPS: u8 = 1;
const TCPI_OPT_SACK: u8 = 2;
const TCPI_OPT_WSCALE: u8 = 4;
const IPPROTO_UDP: u64 = 17;
/// IPPROTO_IPV6, IPPROTO_ICMPV6, and their options IPV6_V6ONLY and
/// ICMP6_FILTER (ipv6(7), RFC 3542; numbers from musl `netinet/in.h` and
/// `netinet/icmp6.h`).
const IPPROTO_IPV6: u64 = 41;
const IPPROTO_ICMPV6: u64 = 58;
const IPV6_V6ONLY: u64 = 26;
const ICMP6_FILTER: u64 = 1;
/// IPPROTO_RAW (raw(7), musl `netinet/in.h`).
const IPPROTO_RAW: u64 = 255;

const MSG_PEEK: u64 = 0x2;
pub(crate) const MSG_CTRUNC: i32 = 0x8;
pub(crate) const MSG_TRUNC: u64 = 0x20;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
pub(crate) const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
/// recvmmsg(2): block for the first message only.
const MSG_WAITFORONE: u64 = 0x1_0000;
/// `sizeof(struct mmsghdr)`: a msghdr and the message's length, padded.
const MMSGHDR_SIZE: u64 = 64;
/// UIO_MAXIOV: the most messages one call handles.
const MAX_MMSG: u64 = 1024;

const SOL_SOCKET: u64 = 1;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_PEERCRED: u64 = 17;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const SO_ACCEPTCONN: u64 = 30;
const SO_PROTOCOL: u64 = 38;
const SO_DOMAIN: u64 = 39;
/// SO_BINDTODEVICE (socket(7); the number from musl `sys/socket.h`).
const SO_BINDTODEVICE: u64 = 25;
const SO_KEEPALIVE: u64 = 9;
/// SO_ATTACH_FILTER, SO_DETACH_FILTER (socket(7), musl `sys/socket.h`).
const SO_ATTACH_FILTER: u64 = 26;
const SO_DETACH_FILTER: u64 = 27;
/// SO_LOCK_FILTER (socket(7), musl `sys/socket.h`).
const SO_LOCK_FILTER: u64 = 44;
/// SOL_PACKET and its options (packet(7); numbers from musl
/// `netpacket/packet.h`).
const SOL_PACKET: u64 = 263;
const PACKET_ADD_MEMBERSHIP: u64 = 1;
const PACKET_DROP_MEMBERSHIP: u64 = 2;
const PACKET_AUXDATA: u64 = 8;
const SCM_RIGHTS: i32 = 1;
const SCM_CREDENTIALS: i32 = 2;
const SO_PASSCRED: u64 = 16;
/// SO_REUSEPORT (socket(7); the value from musl `sys/socket.h`).
const SO_REUSEPORT: u64 = 15;
/// SO_PEEK_OFF (socket(7); the value from musl `sys/socket.h`).
const SO_PEEK_OFF: u64 = 42;
/// SO_REUSEADDR, SO_DONTROUTE, SO_BROADCAST, SO_SNDBUFFORCE, SO_RCVBUFFORCE
/// (socket(7); musl `sys/socket.h`).
const SO_REUSEADDR: u64 = 2;
const SO_DONTROUTE: u64 = 5;
/// SO_PRIORITY (socket(7); musl `sys/socket.h`).
const SO_PRIORITY: u64 = 12;
const SO_BROADCAST: u64 = 6;
const SO_SNDBUFFORCE: u64 = 32;
const SO_RCVBUFFORCE: u64 = 33;
/// IPPROTO_IP's IP_TOS and IP_MTU_DISCOVER, and IP_PMTUDISC_PROBE, the
/// highest mode (ip(7); musl `netinet/in.h`).
const IPPROTO_IP: u64 = 0;
const IP_TOS: u64 = 1;
/// IP_OPTIONS (ip(7)) and SO_LINGER (socket(7), read only).
const IP_OPTIONS: u64 = 4;
const SO_LINGER: u64 = 13;
const IP_MTU_DISCOVER: u64 = 10;
/// IP_RECVERR and IPV6_RECVERR (ip(7), ipv6(7); musl `netinet/in.h`):
/// glibc's resolver turns them on for its queries and gives up if it
/// can't. MSG_ERRQUEUE (recv(2)) reads the error queue. The control
/// messages that carry an error have the same numbers.
const IP_RECVERR: u64 = 11;
const IPV6_RECVERR: u64 = 25;
/// IP_PKTINFO and IP_RECVTOS (ip(7)), IPV6_RECVPKTINFO, IPV6_PKTINFO,
/// IPV6_RECVTCLASS and IPV6_TCLASS (ipv6(7); musl `netinet/in.h`): a
/// datagram's destination, interface and TOS with each receive. The
/// control messages are IP_PKTINFO and IP_TOS (IP_TOS above), and
/// IPV6_PKTINFO and IPV6_TCLASS.
const IP_PKTINFO: u64 = 8;
const IP_RECVTOS: u64 = 13;
const IPV6_RECVPKTINFO: u64 = 49;
const IPV6_PKTINFO: u64 = 50;
const IPV6_RECVTCLASS: u64 = 66;
const IPV6_TCLASS: u64 = 67;
/// IP_RECVTTL (ip(7)) and IPV6_RECVHOPLIMIT (ipv6(7); musl
/// `netinet/in.h`): a datagram's TTL or hop limit with each receive, as an
/// int in an IP_TTL or IPV6_HOPLIMIT control message.
const IP_RECVTTL: u64 = 12;
const IP_TTL_CMSG: u64 = 2;
const IPV6_RECVHOPLIMIT: u64 = 51;
const IPV6_HOPLIMIT: u64 = 52;
/// UDP_SEGMENT and UDP_GRO (udp(7); musl `netinet/udp.h`): segmentation
/// of sends, and receive coalescing (never done, so only kept).
const UDP_SEGMENT: u64 = 103;
const UDP_GRO: u64 = 104;
/// SO_TIMESTAMP and SO_TIMESTAMPNS (socket(7); musl `sys/socket.h`), and
/// their control messages, SCM_TIMESTAMP (a timeval) and SCM_TIMESTAMPNS
/// (a timespec), of the same numbers.
const SO_TIMESTAMP: u64 = 29;
const SO_TIMESTAMPNS: u64 = 35;
const MSG_ERRQUEUE: u64 = 0x2000;
const IP_PMTUDISC_PROBE: u8 = 3;
/// SOL_NETLINK and its NETLINK_ADD_MEMBERSHIP/NETLINK_DROP_MEMBERSHIP
/// options (netlink(7)).
const SOL_NETLINK: u64 = 270;
const NETLINK_ADD_MEMBERSHIP: u64 = 1;
const NETLINK_DROP_MEMBERSHIP: u64 = 2;
const NETLINK_CAP_ACK: u64 = 10;
const NETLINK_EXT_ACK: u64 = 11;

/// Most bytes one call moves.
pub(crate) const MAX_IO: usize = 256 * 1024;
/// Most descriptors in one SCM_RIGHTS message (SCM_MAX_FD).
pub(crate) const MAX_RIGHTS: usize = 253;

fn me() -> core::result::Result<Arc<crate::proc::Process>, Errno> {
    crate::proc::current().ok_or(ESRCH)
}

pub(crate) fn file(fd: i32) -> core::result::Result<Arc<dyn File>, Errno> {
    me()?.files.lock().get(fd)
}

pub(crate) fn install(f: Arc<dyn File>, cloexec: bool) -> core::result::Result<i32, Errno> {
    me()?.files.lock().insert(f, cloexec)
}

/// A socket of any family.
enum Sock<'a> {
    Dgram(&'a InetSocket),
    Stream(&'a TcpSocket),
    Unix(&'a UnixSocket),
    Netlink(&'a NetlinkSocket),
    Uevent(&'a UeventSocket),
    Packet(&'a PacketSocket),
}

fn kind(f: &Arc<dyn File>) -> Option<Sock<'_>> {
    let any: &dyn core::any::Any = &**f;
    if let Some(s) = any.downcast_ref::<InetSocket>() {
        Some(Sock::Dgram(s))
    } else if let Some(s) = any.downcast_ref::<TcpSocket>() {
        Some(Sock::Stream(s))
    } else if let Some(s) = any.downcast_ref::<UnixSocket>() {
        Some(Sock::Unix(s))
    } else if let Some(s) = any.downcast_ref::<NetlinkSocket>() {
        Some(Sock::Netlink(s))
    } else if let Some(s) = any.downcast_ref::<PacketSocket>() {
        Some(Sock::Packet(s))
    } else {
        any.downcast_ref::<UeventSocket>().map(Sock::Uevent)
    }
}

pub(crate) fn is_unix(f: &Arc<dyn File>) -> bool {
    matches!(kind(f), Some(Sock::Unix(_)))
}

/// The socket behind `fd` (ENOTSOCK for other files).
pub(crate) fn sock(fd: i32) -> core::result::Result<Arc<dyn File>, Errno> {
    let f = file(fd)?;
    if kind(&f).is_none() {
        return Err(ENOTSOCK);
    }
    Ok(f)
}

pub(crate) fn read_raw(addr: u64, len: u64) -> core::result::Result<Vec<u8>, Errno> {
    let len = (len as usize).min(128);
    let mut b = vec![0u8; len];
    copy_from_user(&mut b, addr).map_err(|_| EFAULT)?;
    Ok(b)
}

/// Store a socket address at `addr`, its length at `len_ptr` (truncating
/// to the caller's buffer, reporting the full length).
fn write_raw(addr: u64, len_ptr: u64, sa: &[u8]) -> core::result::Result<(), Errno> {
    if addr == 0 || len_ptr == 0 {
        return Ok(());
    }
    let room: u32 = read_user(len_ptr).map_err(|_| EFAULT)?;
    let n = (room as usize).min(sa.len());
    copy_to_user(addr, &sa[..n]).map_err(|_| EFAULT)?;
    write_user(len_ptr, &(sa.len() as u32)).map_err(|_| EFAULT)
}

// --- AF_UNIX addresses -------------------------------------------------------

/// Parse a `struct sockaddr_un`; `None` for an address of family only.
fn parse_unix(b: &[u8]) -> core::result::Result<Option<UnixName>, Errno> {
    if b.len() < 2 || u16::from_ne_bytes([b[0], b[1]]) != AF_UNIX as u16 {
        return Err(EINVAL);
    }
    let path = &b[2..];
    if path.is_empty() {
        return Ok(None);
    }
    if path[0] == 0 {
        return Ok(Some(UnixName::Abstract(path[1..].to_vec())));
    }
    let end = path.iter().position(|&c| c == 0).unwrap_or(path.len());
    let p = core::str::from_utf8(&path[..end]).map_err(|_| EINVAL)?;
    Ok(Some(UnixName::Path(alloc::string::String::from(p))))
}

enum UnixName {
    Path(alloc::string::String),
    Abstract(Vec<u8>),
}

/// The address an existing socket file names (connect, sendto).
fn unix_target(name: UnixName) -> core::result::Result<Address, Errno> {
    match name {
        UnixName::Abstract(n) => Ok(Address::Abstract(n)),
        UnixName::Path(p) => {
            let cwd = me()?.cwd();
            let d = vfs::resolve(&cwd, &p, true)?;
            let m = d.metadata();
            if m.mode & vfs::S_IFMT != vfs::S_IFSOCK {
                return Err(ECONNREFUSED);
            }
            Ok(Address::Path(p.into_bytes(), (m.dev, m.ino)))
        }
    }
}

/// bind(2) for AF_UNIX: create the socket file (or claim the abstract
/// name). An address of family only autobinds an abstract name.
fn unix_bind(s: &Arc<UnixSocket>, name: Option<UnixName>) -> core::result::Result<(), Errno> {
    let addr = match name {
        None => {
            let mut r = [0u8; 4];
            crate::random::fill(&mut r);
            Address::Abstract(alloc::format!("{:05x}", u32::from_le_bytes(r) & 0xFFFFF).into_bytes())
        }
        Some(UnixName::Abstract(n)) => Address::Abstract(n),
        Some(UnixName::Path(p)) => {
            let me = me()?;
            let cwd = me.cwd();
            let (parent, leaf) = vfs::resolve_parent(&cwd, &p)?;
            if parent.child(&leaf).is_ok() {
                return Err(EADDRINUSE);
            }
            // Like any new file: write access to the directory, and owned
            // by the caller (unix(7)).
            vfs::writable(&parent)?;
            me.cred().permission(&parent.metadata(), crate::proc::cred::MAY_WRITE | crate::proc::cred::MAY_EXEC)?;
            let umask = me.umask();
            let inode = parent.inode.create(&leaf, vfs::S_IFSOCK | (0o777 & !umask), 0)?;
            if let Ok(d) = parent.child(&leaf) {
                crate::fs::own_new(&parent, &d);
            }
            let m = inode.metadata();
            Address::Path(p.into_bytes(), (m.dev, m.ino))
        }
    };
    s.bind(addr)
}

fn unix_arc(f: &Arc<dyn File>) -> Arc<UnixSocket> {
    let any: Arc<dyn core::any::Any + Send + Sync> = f.clone();
    any.downcast::<UnixSocket>().ok().unwrap()
}

// --- calls -----------------------------------------------------------------

/// Ping sockets are for the groups in /proc/sys/net/ipv4/ping_group_range
/// (icmp(7)): the effective or a supplementary group, as seen from the
/// network namespace's user namespace, must be in it; EACCES otherwise.
fn ping_allowed() -> core::result::Result<(), Errno> {
    let ns = crate::net::current_ns();
    let range = crate::fs::procfs::sysctl("sys/net/ipv4/ping_group_range", crate::fs::procfs::PING_GROUPS);
    let mut it = range.split_whitespace().map(|v| v.parse::<u32>().unwrap_or(0));
    let (lo, hi) = (it.next().unwrap_or(1), it.next().unwrap_or(0));
    let cred = crate::proc::cred::current();
    let ok = core::iter::once(cred.egid)
        .chain(cred.groups.iter().copied())
        .filter_map(|g| ns.owner.gid_from_kernel(g))
        .any(|g| (lo..=hi).contains(&g));
    if ok { Ok(()) } else { Err(EACCES) }
}

pub fn socket(a: Args) -> Result {
    let [domain, ty, proto, ..] = a.0;
    let flags = ty as u32;
    let (nonblock, cloexec) = (flags & O_NONBLOCK, flags & O_CLOEXEC != 0);
    // A type socket(2) doesn't know, or flags other than SOCK_NONBLOCK and
    // SOCK_CLOEXEC, is EINVAL whatever the domain (as Linux was seen to
    // refuse it): STREAM 1, DGRAM 2, RAW 3, RDM 4, SEQPACKET 5, DCCP 6,
    // PACKET 10.
    if !matches!(ty & SOCK_TYPE_MASK, 1..=6 | 10)
        || ty & !(SOCK_TYPE_MASK | u64::from(O_NONBLOCK) | u64::from(O_CLOEXEC)) != 0
    {
        return Err(EINVAL);
    }
    // Internet and packet sockets need a confined app's network
    // permission (ADR 0130): AF_INET 2, AF_INET6 10, AF_PACKET 17.
    if matches!(domain, 2 | 10 | 17) && !crate::proc::apps::allows(crate::proc::apps::NETWORK) {
        return Err(EACCES);
    }
    let s: Arc<dyn File> = match (domain, ty & SOCK_TYPE_MASK, proto) {
        (2, SOCK_DGRAM, 0 | IPPROTO_UDP) => InetSocket::new(Kind::Udp, nonblock, false),
        (2, SOCK_DGRAM, IPPROTO_ICMP) => {
            ping_allowed()?;
            InetSocket::new(Kind::Ping, nonblock, false)
        }
        (2, SOCK_RAW, IPPROTO_ICMP) => {
            let owner = crate::net::current_ns().owner.clone();
            if !crate::proc::cred::current().ns_capable(&owner, crate::proc::cred::CAP_NET_RAW) {
                return Err(EPERM);
            }
            InetSocket::new(Kind::RawIcmp, nonblock, false)
        }
        (2, SOCK_RAW, IPPROTO_RAW) => {
            let owner = crate::net::current_ns().owner.clone();
            if !crate::proc::cred::current().ns_capable(&owner, crate::proc::cred::CAP_NET_RAW) {
                return Err(EPERM);
            }
            InetSocket::new(Kind::RawIp, nonblock, false)
        }
        (2, SOCK_STREAM, 0 | IPPROTO_TCP) => TcpSocket::new(nonblock, false),
        (2, _, _) => return Err(EPROTONOSUPPORT),
        // ipv6(7), icmp6 sockets (RFC 3542).
        (AF_INET6, SOCK_DGRAM, 0 | IPPROTO_UDP) => InetSocket::new(Kind::Udp, nonblock, true),
        (AF_INET6, SOCK_STREAM, 0 | IPPROTO_TCP) => TcpSocket::new(nonblock, true),
        (AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6) => {
            ping_allowed()?;
            InetSocket::new(Kind::Ping6, nonblock, true)
        }
        (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6) => {
            let owner = crate::net::current_ns().owner.clone();
            if !crate::proc::cred::current().ns_capable(&owner, crate::proc::cred::CAP_NET_RAW) {
                return Err(EPERM);
            }
            InetSocket::new(Kind::RawIcmp6, nonblock, true)
        }
        (AF_INET6, _, _) => return Err(EPROTONOSUPPORT),
        (AF_UNIX, SOCK_STREAM, 0) => UnixSocket::new(unix::Kind::Stream, nonblock),
        (AF_UNIX, SOCK_DGRAM, 0) => UnixSocket::new(unix::Kind::Dgram, nonblock),
        (AF_UNIX, SOCK_SEQPACKET, 0) => UnixSocket::new(unix::Kind::SeqPacket, nonblock),
        (AF_UNIX, _, _) => return Err(EPROTONOSUPPORT),
        (AF_NETLINK, SOCK_RAW | SOCK_DGRAM, p) if p == u64::from(NETLINK_KOBJECT_UEVENT) => UeventSocket::new(nonblock),
        (AF_NETLINK, SOCK_RAW | SOCK_DGRAM, p) => NetlinkSocket::new(p as u32, nonblock)?,
        // packet(7): the protocol comes in network byte order; CAP_NET_RAW.
        (d, SOCK_RAW | SOCK_DGRAM, p) if d == u64::from(AF_PACKET) => {
            let owner = crate::net::current_ns().owner.clone();
            if !crate::proc::cred::current().ns_capable(&owner, crate::proc::cred::CAP_NET_RAW) {
                return Err(EPERM);
            }
            PacketSocket::new(u16::from_be(p as u16), ty & SOCK_TYPE_MASK == SOCK_DGRAM, nonblock)
        }
        _ => return Err(EAFNOSUPPORT),
    };
    Ok(install(s, cloexec)? as u64)
}

pub fn socketpair(a: Args) -> Result {
    let [domain, ty, proto, sv, ..] = a.0;
    // socketpair(2): IP sockets have no pairs (EOPNOTSUPP); a family Slate
    // doesn't know is EAFNOSUPPORT.
    match domain {
        AF_UNIX => {}
        d if d == AF_INET as u64 || d == AF_INET6 => return Err(EOPNOTSUPP),
        _ => return Err(EAFNOSUPPORT),
    }
    if proto != 0 {
        return Err(EPROTONOSUPPORT);
    }
    let k = match ty & SOCK_TYPE_MASK {
        SOCK_STREAM => unix::Kind::Stream,
        SOCK_DGRAM => unix::Kind::Dgram,
        SOCK_SEQPACKET => unix::Kind::SeqPacket,
        _ => return Err(EPROTONOSUPPORT),
    };
    let flags = ty as u32;
    let (x, y) = UnixSocket::pair(k, flags & O_NONBLOCK);
    let cloexec = flags & O_CLOEXEC != 0;
    let fx = install(x, cloexec)?;
    let fy = match install(y, cloexec) {
        Ok(f) => f,
        Err(e) => {
            let _ = me()?.files.lock().close(fx);
            return Err(e);
        }
    };
    write_user(sv, &[fx, fy]).map_err(|_| EFAULT)?;
    Ok(0)
}

pub fn bind(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let raw = read_raw(a.0[1], a.0[2])?;
    // Ports below net.ipv4.ip_unprivileged_port_start (1024) need
    // CAP_NET_BIND_SERVICE over the network namespace (ip(7)): the
    // socket's, which needn't be the caller's now (setns(2) after
    // socket(2)).
    let inet =
        |raw: &[u8], v6: bool, ns: &crate::proc::ns::NetNs| -> core::result::Result<slate_net::Endpoint, Errno> {
            let (ep, _) = parse_sockaddr(raw, v6)?.ok_or(EINVAL)?;
            // An address that isn't ours fails first (ip(7) EADDRNOTAVAIL).
            if !crate::net::with_stack_in(ns.id, |st| st.can_bind(ep.0)) {
                return Err(EADDRNOTAVAIL);
            }
            let start: u32 = ns
                .sysctl
                .lock()
                .get("sys/net/ipv4/ip_unprivileged_port_start")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024);
            let owner = ns.owner.clone();
            if ep.1 != 0
                && u32::from(ep.1) < start
                && !crate::proc::cred::current().ns_capable(&owner, crate::proc::cred::CAP_NET_BIND_SERVICE)
            {
                return Err(EACCES);
            }
            Ok(ep)
        };
    match kind(&f).unwrap() {
        Sock::Dgram(s) => s.bind(inet(&raw, s.v6, s.netns())?)?,
        Sock::Stream(s) => s.bind(inet(&raw, s.v6, s.netns())?)?,
        Sock::Unix(_) => unix_bind(&unix_arc(&f), parse_unix(&raw)?)?,
        Sock::Netlink(s) => s.bind(&raw)?,
        Sock::Uevent(s) => s.bind(&raw)?,
        Sock::Packet(s) => s.bind(&raw)?,
    }
    Ok(0)
}

pub fn listen(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    match kind(&f).unwrap() {
        Sock::Stream(s) => s.listen(a.0[1] as usize)?,
        Sock::Unix(s) => s.listen(a.0[1] as usize)?,
        _ => return Err(EOPNOTSUPP),
    }
    Ok(0)
}

pub fn accept(a: Args) -> Result {
    accept4(Args([a.0[0], a.0[1], a.0[2], 0, 0, 0]))
}

pub fn accept4(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let flags = a.0[3] as u32;
    let (conn, peer): (Arc<dyn File>, Vec<u8>) = match kind(&f).unwrap() {
        Sock::Stream(s) => {
            let c = s.accept(flags & O_NONBLOCK, false)?;
            let peer = c.remote().map(|p| encode(p, c.v6, 0)).unwrap_or_default();
            (c, peer)
        }
        Sock::Unix(s) => {
            let c = s.accept(flags & O_NONBLOCK, false)?;
            let peer = c.peer().unwrap_or(Address::Unnamed).encode();
            (c, peer)
        }
        _ => return Err(EOPNOTSUPP),
    };
    write_raw(a.0[1], a.0[2], &peer)?;
    Ok(install(conn, flags & O_CLOEXEC != 0)? as u64)
}

pub fn connect(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let raw = read_raw(a.0[1], a.0[2])?;
    match kind(&f).unwrap() {
        // AF_UNSPEC dissolves a datagram association (connect(2)).
        Sock::Dgram(s) => match parse_sockaddr(&raw, s.v6)? {
            Some((ep, scope)) => {
                s.use_scope(scope)?;
                s.connect(ep)?
            }
            None => s.connect(Default::default())?,
        },
        Sock::Stream(s) => {
            let (ep, scope) = parse_sockaddr(&raw, s.v6)?.ok_or(EAFNOSUPPORT)?;
            let _ = scope; // TCP follows routes (a GAP for link-local peers on several cards).
            s.connect(ep)?
        }
        Sock::Unix(_) => {
            let target = unix_target(parse_unix(&raw)?.ok_or(EINVAL)?)?;
            unix_arc(&f).connect(&target)?
        }
        Sock::Netlink(_) | Sock::Uevent(_) => {}
        Sock::Packet(_) => return Err(EOPNOTSUPP),
    }
    Ok(0)
}

pub fn getsockname(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let sa = match kind(&f).unwrap() {
        Sock::Dgram(s) => encode(s.local(), s.v6, s.scope()),
        Sock::Stream(s) => encode(s.local(), s.v6, 0),
        Sock::Unix(s) => s.local().encode(),
        Sock::Netlink(s) => s.address(),
        Sock::Uevent(s) => s.address(),
        Sock::Packet(s) => sockaddr_ll(&s.local()).to_vec(),
    };
    write_raw(a.0[1], a.0[2], &sa)?;
    Ok(0)
}

pub fn getpeername(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let sa = match kind(&f).unwrap() {
        Sock::Dgram(s) => encode(s.remote().ok_or(ENOTCONN)?, s.v6, s.scope()),
        Sock::Stream(s) => encode(s.remote().ok_or(ENOTCONN)?, s.v6, 0),
        Sock::Unix(s) => s.peer()?.encode(),
        Sock::Netlink(_) | Sock::Uevent(_) | Sock::Packet(_) => return Err(ENOTCONN),
    };
    write_raw(a.0[1], a.0[2], &sa)?;
    Ok(0)
}

/// Send on any socket; `to` is a raw socket address (ignored for TCP).
pub(crate) fn send_on(f: &Arc<dyn File>, data: &[u8], to: Option<Vec<u8>>, flags: u64, rights: unix::Rights) -> Result {
    let dontwait = flags & MSG_DONTWAIT != 0;
    let r = match kind(f).unwrap() {
        Sock::Dgram(s) => {
            let to = to.map(|t| parse_sockaddr(&t, s.v6)).transpose()?.flatten();
            if let Some((_, scope)) = to {
                s.use_scope(scope)?;
            }
            s.send_to(data, to.map(|t| t.0))
        }
        Sock::Stream(s) => s.send(data, dontwait, flags & MSG_NOSIGNAL != 0),
        Sock::Unix(s) => {
            let target = match to {
                Some(t) => Some(unix_target(parse_unix(&t)?.ok_or(EINVAL)?)?),
                None => None,
            };
            let r = s.send(data, target.as_ref(), rights, dontwait);
            if r == Err(EPIPE)
                && flags & MSG_NOSIGNAL == 0
                && let Ok(p) = me()
            {
                crate::proc::signal::send_to_process(&p, crate::proc::signal::SIGPIPE);
            }
            r
        }
        Sock::Netlink(s) => s.send(data),
        Sock::Uevent(s) => s.send(data, to.as_deref()),
        Sock::Packet(s) => s.send_to(data, to.as_deref()),
    };
    Ok(r? as u64)
}

/// What a receive produced: (bytes copied, full length, sender address,
/// passed descriptors, the sender's credentials for SCM_CREDENTIALS).
pub(crate) type Recv = (usize, usize, Option<Vec<u8>>, unix::Rights, Option<unix::Cred>);

/// [`recv_on`], with an internet datagram's TTL or hop limit (0 for
/// anything else), for the native recvmsg's `Msg::ttl`.
pub(crate) fn recv_on_ttl(f: &Arc<dyn File>, buf: &mut [u8], flags: u64) -> core::result::Result<(Recv, u8), Errno> {
    match kind(f) {
        Some(Sock::Dgram(s)) if flags & MSG_ERRQUEUE == 0 => {
            let r = s.recv(buf, flags & MSG_PEEK != 0, flags & MSG_DONTWAIT != 0)?;
            Ok(((r.copied, r.len, Some(encode(r.from, s.v6, s.scope())), Vec::new(), None), r.meta.ttl))
        }
        _ => Ok((recv_on(f, buf, flags)?, 0)),
    }
}

pub(crate) fn recv_on(f: &Arc<dyn File>, buf: &mut [u8], flags: u64) -> core::result::Result<Recv, Errno> {
    let (peek, dontwait) = (flags & MSG_PEEK != 0, flags & MSG_DONTWAIT != 0);
    // The error queue (IP_RECVERR): a UDP socket's queued ICMP errors,
    // their payload as the data; any other socket's is empty (EAGAIN, as
    // Linux answers, TCP's included).
    if flags & MSG_ERRQUEUE != 0 {
        let Some(Sock::Dgram(s)) = kind(f) else { return Err(EAGAIN) };
        let e = s.recv_error(peek)?;
        let n = e.payload.len().min(buf.len());
        buf[..n].copy_from_slice(&e.payload[..n]);
        return Ok((n, e.payload.len(), Some(encode(e.dest, s.v6, s.scope())), Vec::new(), None));
    }
    Ok(match kind(f).unwrap() {
        Sock::Dgram(s) => {
            let r = s.recv(buf, peek, dontwait)?;
            (r.copied, r.len, Some(encode(r.from, s.v6, s.scope())), Vec::new(), None)
        }
        Sock::Stream(s) => {
            let n = s.recv(buf, peek, dontwait)?;
            (n, n, None, Vec::new(), None)
        }
        Sock::Unix(s) => {
            let r = s.recv(buf, peek, dontwait)?;
            let from = (s.kind == unix::Kind::Dgram).then(|| r.from.encode());
            let cred = s.passcred.load(core::sync::atomic::Ordering::Relaxed).then_some(r.cred);
            (r.len, r.full, from, r.rights, cred)
        }
        Sock::Netlink(s) => {
            let (n, full) = s.recv(buf, peek, dontwait)?;
            (n, full, Some(s.kernel_address()), Vec::new(), None)
        }
        Sock::Uevent(s) => {
            let r = s.recv(buf, peek, dontwait)?;
            (r.copied, r.len, Some(r.from), Vec::new(), r.cred)
        }
        Sock::Packet(s) => {
            let (n, full, from) = s.recv(buf, peek, dontwait)?;
            (n, full, Some(sockaddr_ll(&from).to_vec()), Vec::new(), None)
        }
    })
}

pub fn sendto(a: Args) -> Result {
    let [_, buf, len, flags, addr, alen] = a.0;
    let f = sock(a.fd(0))?;
    let mut data = vec![0u8; (len as usize).min(MAX_IO)];
    copy_from_user(&mut data, buf).map_err(|_| EFAULT)?;
    let to = if addr != 0 { Some(read_raw(addr, alen)?) } else { None };
    send_on(&f, &data, to, flags, Vec::new())
}

pub fn recvfrom(a: Args) -> Result {
    let [_, buf, len, flags, addr, alen] = a.0;
    let f = sock(a.fd(0))?;
    let mut data = vec![0u8; (len as usize).min(MAX_IO)];
    let (copied, full, from, _, _) = recv_on(&f, &mut data, flags)?;
    // On a TCP socket MSG_TRUNC throws the data away (tcp(7)); the buffer
    // may be NULL then.
    let discard = flags & MSG_TRUNC != 0 && matches!(kind(&f), Some(Sock::Stream(_)));
    if !discard {
        copy_to_user(buf, &data[..copied]).map_err(|_| EFAULT)?;
    }
    if let Some(from) = from {
        write_raw(addr, alen, &from)?;
    }
    Ok((if flags & MSG_TRUNC != 0 { full } else { copied }) as u64)
}

/// `struct msghdr` (x86-64).
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct MsgHdr {
    name: u64,
    namelen: u32,
    _pad: u32,
    iov: u64,
    iovlen: u64,
    control: u64,
    controllen: u64,
    flags: i32,
    _pad2: u32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Iovec {
    base: u64,
    len: u64,
}

fn iovecs(m: &MsgHdr) -> core::result::Result<Vec<Iovec>, Errno> {
    if m.iovlen > 1024 {
        return Err(EMSGSIZE);
    }
    (0..m.iovlen).map(|i| read_user::<Iovec>(m.iov + i * 16).map_err(|_| EFAULT)).collect()
}

/// Drop the passed descriptors a Linux-domain receiver may not have (ADR
/// 0098); true if any went (the receiver sees MSG_CTRUNC).
pub(crate) fn keep_from_linux(rights: &mut alloc::vec::Vec<alloc::sync::Arc<dyn crate::fs::File>>) -> bool {
    if !crate::proc::current().is_some_and(|p| p.domain() == crate::proc::domain::Domain::Linux) {
        return false;
    }
    let before = rights.len();
    rights.retain(|r| !crate::fs::stays_in_slate(r));
    rights.len() < before
}

/// Descriptors from SCM_RIGHTS control messages (`struct cmsghdr`: a
/// size_t length, level, type, then data; aligned to 8 bytes).
fn read_rights(m: &MsgHdr) -> core::result::Result<unix::Rights, Errno> {
    let mut rights = Vec::new();
    if m.control == 0 || m.controllen < 16 {
        return Ok(rights);
    }
    let len = (m.controllen as usize).min(4096);
    let mut c = vec![0u8; len];
    copy_from_user(&mut c, m.control).map_err(|_| EFAULT)?;
    let mut at = 0;
    while at + 16 <= len {
        let clen = u64::from_ne_bytes(c[at..at + 8].try_into().unwrap()) as usize;
        let level = i32::from_ne_bytes(c[at + 8..at + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(c[at + 12..at + 16].try_into().unwrap());
        if clen < 16 || at + clen > len {
            return Err(EINVAL);
        }
        if level == SOL_SOCKET as i32 && ty == SCM_RIGHTS {
            for fd in c[at + 16..at + clen].as_chunks::<4>().0 {
                if rights.len() >= MAX_RIGHTS {
                    return Err(EINVAL);
                }
                rights.push(file(i32::from_ne_bytes(*fd))?);
            }
        }
        at += clen.next_multiple_of(8);
    }
    Ok(rights)
}

/// recvmmsg(2): receive up to `vlen` messages into the `struct mmsghdr`
/// array; after the first, only what is already there (and none of them
/// waits with MSG_DONTWAIT). The timeout argument isn't used (a GAP).
pub fn recvmmsg(a: Args) -> Result {
    let [fd, vec, vlen, flags, ..] = a.0;
    let mut n = 0;
    while n < vlen.min(MAX_MMSG) {
        let first_flags = if n == 0 && flags & MSG_WAITFORONE == 0 { flags } else { flags | MSG_DONTWAIT };
        let msg = vec + n * MMSGHDR_SIZE;
        match recvmsg(Args([fd, msg, first_flags & !MSG_WAITFORONE, 0, 0, 0])) {
            Ok(len) => write_user(msg + 56, &(len as u32)).map_err(|_| EFAULT)?,
            Err(e) if n > 0 && (e == EAGAIN || e == EINTR) => break,
            Err(e) => return Err(e),
        }
        n += 1;
    }
    Ok(n)
}

/// sendmmsg(2): send the messages in order; stop at the first error after
/// at least one went out.
pub fn sendmmsg(a: Args) -> Result {
    let [fd, vec, vlen, flags, ..] = a.0;
    let mut n = 0;
    while n < vlen.min(MAX_MMSG) {
        let msg = vec + n * MMSGHDR_SIZE;
        match sendmsg(Args([fd, msg, flags, 0, 0, 0])) {
            Ok(len) => write_user(msg + 56, &(len as u32)).map_err(|_| EFAULT)?,
            Err(_) if n > 0 => break,
            Err(e) => return Err(e),
        }
        n += 1;
    }
    Ok(n)
}

pub fn sendmsg(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let m: MsgHdr = read_user(a.0[1]).map_err(|_| EFAULT)?;
    let mut data = Vec::new();
    for v in iovecs(&m)? {
        let n = (v.len as usize).min(MAX_IO - data.len());
        let start = data.len();
        data.resize(start + n, 0);
        copy_from_user(&mut data[start..], v.base).map_err(|_| EFAULT)?;
    }
    let to = if m.name != 0 && m.namelen != 0 { Some(read_raw(m.name, u64::from(m.namelen))?) } else { None };
    let rights = read_rights(&m)?;
    if !rights.is_empty() && !is_unix(&f) {
        return Err(EOPNOTSUPP);
    }
    // A UDP_SEGMENT control message sets this send's segment size.
    if let (Some(segment), Some(Sock::Dgram(d))) = (udp_segment(&m)?, kind(&f)) {
        let to = to.map(|t| parse_sockaddr(&t, d.v6)).transpose()?.flatten();
        if let Some((_, scope)) = to {
            d.use_scope(scope)?;
        }
        return Ok(d.send_segments(&data, to.map(|t| t.0), usize::from(segment))? as u64);
    }
    send_on(&f, &data, to, a.0[2], rights)
}

/// sendmsg's UDP_SEGMENT control message (udp(7)): a u16 segment size.
fn udp_segment(m: &MsgHdr) -> core::result::Result<Option<u16>, Errno> {
    if m.control == 0 || m.controllen < 16 {
        return Ok(None);
    }
    let len = (m.controllen as usize).min(4096);
    let mut c = vec![0u8; len];
    copy_from_user(&mut c, m.control).map_err(|_| EFAULT)?;
    let mut at = 0;
    while at + 16 <= len {
        let clen = u64::from_ne_bytes(c[at..at + 8].try_into().unwrap()) as usize;
        let level = i32::from_ne_bytes(c[at + 8..at + 12].try_into().unwrap());
        let ty = i32::from_ne_bytes(c[at + 12..at + 16].try_into().unwrap());
        if clen < 16 || at + clen > len {
            return Err(EINVAL);
        }
        if level == IPPROTO_UDP as i32 && ty == UDP_SEGMENT as i32 && clen >= 18 {
            return Ok(Some(u16::from_ne_bytes([c[at + 16], c[at + 17]])));
        }
        at += clen.next_multiple_of(8);
    }
    Ok(None)
}

pub fn recvmsg(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let flags = a.0[2];
    let mut m: MsgHdr = read_user(a.0[1]).map_err(|_| EFAULT)?;
    let iov = iovecs(&m)?;
    let total: usize = iov.iter().map(|v| v.len as usize).sum::<usize>().min(MAX_IO);
    let mut data = vec![0u8; total];
    // A UDP socket's own control messages (ADR 0115): the queued error with
    // MSG_ERRQUEUE, else where and how the datagram arrived.
    let (copied, full, from, mut rights, cred, extra, errq) = match kind(&f) {
        Some(Sock::Dgram(d)) => {
            let r = dgram_recvmsg(d, &mut data, flags)?;
            (r.copied, r.full, r.from, Vec::new(), None, r.control, r.errq)
        }
        // A Unix datagram's arrival time (socket(7)'s SO_TIMESTAMP).
        Some(Sock::Unix(u)) => {
            // A Unix socket's error queue is empty (as recv_on answers).
            if flags & MSG_ERRQUEUE != 0 {
                return Err(EAGAIN);
            }
            let r = u.recv(&mut data, flags & MSG_PEEK != 0, flags & MSG_DONTWAIT != 0)?;
            let from = (u.kind == unix::Kind::Dgram).then(|| r.from.encode());
            let cred = u.passcred.load(core::sync::atomic::Ordering::Relaxed).then_some(r.cred);
            let mut c = Vec::new();
            if let Some(at) = r.at {
                push_timestamp(&mut c, &u.opts, at);
            }
            (r.len, r.full, from, r.rights, cred, c, false)
        }
        _ => {
            let (copied, full, from, rights, cred) = recv_on(&f, &mut data, flags)?;
            (copied, full, from, rights, cred, Vec::new(), false)
        }
    };
    let mut done = 0;
    for v in iov {
        let n = (v.len as usize).min(copied - done);
        copy_to_user(v.base, &data[done..done + n]).map_err(|_| EFAULT)?;
        done += n;
    }
    match from {
        Some(sa) if m.name != 0 => {
            let n = (m.namelen as usize).min(sa.len());
            copy_to_user(m.name, &sa[..n]).map_err(|_| EFAULT)?;
            m.namelen = sa.len() as u32;
        }
        _ => m.namelen = 0,
    }
    m.flags = if full > copied { MSG_TRUNC as i32 } else { 0 };
    // Passed descriptors become new descriptors of the receiver; a Linux
    // receiver does not get those the Slate domain keeps (ADR 0098).
    let mut used = 0usize;
    if keep_from_linux(&mut rights) {
        m.flags |= MSG_CTRUNC;
    }
    if !rights.is_empty() {
        let need = 16 + 4 * rights.len();
        let fit = if (m.controllen as usize) < 16 { 0 } else { ((m.controllen as usize - 16) / 4).min(rights.len()) };
        if fit < rights.len() {
            m.flags |= MSG_CTRUNC;
        }
        let mut fds = Vec::new();
        for r in rights.into_iter().take(fit) {
            fds.push(install(r, flags & MSG_CMSG_CLOEXEC != 0)?);
        }
        if fit > 0 {
            let mut c = Vec::with_capacity(need);
            c.extend_from_slice(&((16 + 4 * fit) as u64).to_ne_bytes());
            c.extend_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
            c.extend_from_slice(&SCM_RIGHTS.to_ne_bytes());
            for fd in fds {
                c.extend_from_slice(&fd.to_ne_bytes());
            }
            copy_to_user(m.control, &c).map_err(|_| EFAULT)?;
            used = (16 + 4 * fit).next_multiple_of(8).min(m.controllen as usize);
        }
    }
    // SCM_CREDENTIALS: a `struct ucred` (pid, uid, gid; unix(7)).
    if let Some(c) = cred {
        let room = (m.controllen as usize).saturating_sub(used);
        if room < 28 {
            m.flags |= MSG_CTRUNC;
        } else {
            let mut b = Vec::with_capacity(28);
            b.extend_from_slice(&28u64.to_ne_bytes());
            b.extend_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
            b.extend_from_slice(&SCM_CREDENTIALS.to_ne_bytes());
            b.extend_from_slice(&c.pid.to_ne_bytes());
            b.extend_from_slice(&c.uid.to_ne_bytes());
            b.extend_from_slice(&c.gid.to_ne_bytes());
            copy_to_user(m.control + used as u64, &b).map_err(|_| EFAULT)?;
            used = (used + 32).min(m.controllen as usize);
        }
    }
    if !extra.is_empty() {
        let room = (m.controllen as usize).saturating_sub(used);
        // Whole messages only; what doesn't fit is cut (MSG_CTRUNC). The
        // last one's padding may go past the room.
        let mut fit = 0;
        let mut at = 0;
        while at < extra.len() {
            let len = u64::from_ne_bytes(extra[at..at + 8].try_into().unwrap()) as usize;
            if at + len > room {
                m.flags |= MSG_CTRUNC;
                break;
            }
            at += len.next_multiple_of(8);
            fit = at.min(room);
        }
        if fit > 0 {
            copy_to_user(m.control + used as u64, &extra[..fit]).map_err(|_| EFAULT)?;
            used += fit;
        }
    }
    if errq {
        m.flags |= MSG_ERRQUEUE as i32;
    }
    m.controllen = used as u64;
    write_user(a.0[1], &m).map_err(|_| EFAULT)?;
    Ok((if flags & MSG_TRUNC != 0 { full } else { copied }) as u64)
}

/// A control message (cmsg(3)): `struct cmsghdr` (u64 length, i32 level,
/// i32 type), the data, padded to 8 bytes.
fn push_cmsg(out: &mut Vec<u8>, level: u64, kind: u64, data: &[u8]) {
    out.extend_from_slice(&((16 + data.len()) as u64).to_ne_bytes());
    out.extend_from_slice(&(level as i32).to_ne_bytes());
    out.extend_from_slice(&(kind as i32).to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().next_multiple_of(8), 0);
}

/// SCM_TIMESTAMP or SCM_TIMESTAMPNS (socket(7)) for a datagram that
/// arrived at `at` (monotonic nanoseconds), on the wall clock, if the
/// socket asked for one.
fn push_timestamp(c: &mut Vec<u8>, o: &SockOpts, at: u64) {
    if !(o.flag(SockOpts::TIMESTAMPNS) || o.flag(SockOpts::TIMESTAMP)) {
        return;
    }
    let ago_ns = crate::time::monotonic_ns().saturating_sub(at) as i128;
    let wall = crate::time::realtime_ns() - ago_ns;
    let (sec, ns) = (wall.div_euclid(1_000_000_000) as i64, wall.rem_euclid(1_000_000_000) as i64);
    let mut t = Vec::with_capacity(16);
    t.extend_from_slice(&sec.to_ne_bytes());
    if o.flag(SockOpts::TIMESTAMPNS) {
        t.extend_from_slice(&ns.to_ne_bytes());
        push_cmsg(c, SOL_SOCKET, SO_TIMESTAMPNS, &t);
    } else {
        t.extend_from_slice(&(ns / 1000).to_ne_bytes());
        push_cmsg(c, SOL_SOCKET, SO_TIMESTAMP, &t);
    }
}

/// What recvmsg got from a UDP socket.
struct DgramMsg {
    copied: usize,
    /// The datagram's (or the error's payload's) full length.
    full: usize,
    from: Option<Vec<u8>>,
    /// Its control messages, ready to copy out.
    control: Vec<u8>,
    /// Read from the error queue (MSG_ERRQUEUE).
    errq: bool,
}

/// recvmsg on a UDP socket. Shapes as Linux was seen to give them (ADR
/// 0115).
fn dgram_recvmsg(
    d: &crate::net::socket::InetSocket,
    buf: &mut [u8],
    flags: u64,
) -> core::result::Result<DgramMsg, Errno> {
    use slate_net::IpAddr;
    let (peek, dontwait) = (flags & MSG_PEEK != 0, flags & MSG_DONTWAIT != 0);
    let mut c = Vec::new();
    if flags & MSG_ERRQUEUE != 0 {
        // `struct sock_extended_err` (ip(7)): errno, origin, type, code, a
        // pad byte, info, data; then the offender's address.
        let e = d.recv_error(peek)?;
        let n = e.payload.len().min(buf.len());
        buf[..n].copy_from_slice(&e.payload[..n]);
        let mut ee = Vec::with_capacity(44);
        ee.extend_from_slice(&(crate::net::socket::errno(e.error).0 as u32).to_ne_bytes());
        ee.extend_from_slice(&[e.origin, e.kind, e.code, 0]);
        ee.extend_from_slice(&e.info.to_ne_bytes());
        ee.extend_from_slice(&0u32.to_ne_bytes());
        let v6 = e.origin == slate_net::ORIGIN_ICMP6;
        ee.extend_from_slice(&encode((e.offender, 0), v6, 0));
        let (level, kind) = if v6 { (IPPROTO_IPV6, IPV6_RECVERR) } else { (IPPROTO_IP, IP_RECVERR) };
        push_cmsg(&mut c, level, kind, &ee);
        let from = Some(encode(e.dest, d.v6, d.scope()));
        return Ok(DgramMsg { copied: n, full: e.payload.len(), from, control: c, errq: true });
    }
    let r = d.recv(buf, peek, dontwait)?;
    let o = &d.opts;
    push_timestamp(&mut c, o, r.meta.at);
    match r.meta.to {
        // `struct in_pktinfo`: the interface, the local address, the
        // header's destination.
        Some(IpAddr::V4(to)) => {
            if o.flag(SockOpts::PKTINFO) {
                let mut p = Vec::with_capacity(12);
                p.extend_from_slice(&(r.meta.ifindex as i32).to_ne_bytes());
                p.extend_from_slice(&to.0);
                p.extend_from_slice(&to.0);
                push_cmsg(&mut c, IPPROTO_IP, IP_PKTINFO, &p);
            }
            if o.flag(SockOpts::RECVTOS) {
                push_cmsg(&mut c, IPPROTO_IP, IP_TOS, &[r.meta.tos]);
            }
            if o.flag(SockOpts::RECVTTL) {
                push_cmsg(&mut c, IPPROTO_IP, IP_TTL_CMSG, &i32::from(r.meta.ttl).to_ne_bytes());
            }
            // On a dual-stack IPv6 socket, the IPv6 forms too, with the
            // address mapped (ipv6(7): ::ffff:a.b.c.d).
            if d.v6 && o.flag(SockOpts::PKTINFO6) {
                let mut p = Vec::with_capacity(20);
                p.extend_from_slice(&[0; 10]);
                p.extend_from_slice(&[0xFF, 0xFF]);
                p.extend_from_slice(&to.0);
                p.extend_from_slice(&r.meta.ifindex.to_ne_bytes());
                push_cmsg(&mut c, IPPROTO_IPV6, IPV6_PKTINFO, &p);
            }
            if d.v6 && o.flag(SockOpts::RECVTCLASS6) {
                push_cmsg(&mut c, IPPROTO_IPV6, IPV6_TCLASS, &i32::from(r.meta.tos).to_ne_bytes());
            }
        }
        // `struct in6_pktinfo`: the address, the interface; the traffic
        // class as an int.
        Some(IpAddr::V6(to)) => {
            if o.flag(SockOpts::PKTINFO6) {
                let mut p = Vec::with_capacity(20);
                p.extend_from_slice(&to.0);
                p.extend_from_slice(&r.meta.ifindex.to_ne_bytes());
                push_cmsg(&mut c, IPPROTO_IPV6, IPV6_PKTINFO, &p);
            }
            if o.flag(SockOpts::RECVTCLASS6) {
                push_cmsg(&mut c, IPPROTO_IPV6, IPV6_TCLASS, &i32::from(r.meta.tos).to_ne_bytes());
            }
            if o.flag(SockOpts::RECVHOPLIMIT6) {
                push_cmsg(&mut c, IPPROTO_IPV6, IPV6_HOPLIMIT, &i32::from(r.meta.ttl).to_ne_bytes());
            }
        }
        None => {}
    }
    Ok(DgramMsg { copied: r.copied, full: r.len, from: Some(encode(r.from, d.v6, d.scope())), control: c, errq: false })
}

/// Options reported as refused or ignored, so each is logged once.
static OPTIONS_REPORTED: crate::sync::IrqSpinLock<Vec<(bool, u64, u64)>> = crate::sync::IrqSpinLock::new(Vec::new());

/// A `struct sock_fprog` at `val` (`len` bytes): the program's length (an
/// unsigned short), then a pointer to its `struct sock_filter`s (socket(7),
/// bpf(4)).
fn read_sock_fprog(val: u64, len: u64) -> core::result::Result<Vec<slate_bpf::SockFilter>, Errno> {
    if len < 16 {
        return Err(EINVAL);
    }
    let n = usize::from(read_user::<u16>(val).map_err(|_| EFAULT)?);
    let ptr: u64 = read_user(val + 8).map_err(|_| EFAULT)?;
    if n == 0 || n > slate_bpf::CBPF_MAX_INSNS {
        return Err(EINVAL);
    }
    let mut raw = vec![0u8; n * 8];
    copy_from_user(&mut raw, ptr).map_err(|_| EFAULT)?;
    Ok(raw.as_chunks::<8>().0.iter().map(|c| slate_bpf::SockFilter::from_bytes(*c)).collect())
}

/// Log an option once (per call, level and name) with the program that
/// asked for it.
fn report_option(set: bool, level: u64, name: u64, what: &str) {
    let mut seen = OPTIONS_REPORTED.lock();
    if seen.iter().any(|&(s, l, n)| s == set && l == level && n == name) {
        return;
    }
    if seen.len() < 256 {
        seen.push((set, level, name));
    }
    drop(seen);
    let (pid, comm) = crate::proc::current().map_or((0, Default::default()), |p| (p.pid, p.name.lock().clone()));
    let call = if set { "setsockopt" } else { "getsockopt" };
    crate::log_warn!("pid {pid} ({comm}): {call} level {level} option {name}: {what}");
}

/// An option Slate does not have (ADR 0077): refused, and logged once.
fn refuse(set: bool, level: u64, name: u64, err: Errno) -> Result {
    report_option(
        set,
        level,
        name,
        if err == EOPNOTSUPP { "not supported (EOPNOTSUPP)" } else { "not supported (ENOPROTOOPT)" },
    );
    Err(err)
}

/// setsockopt(2). Every option is done, accepted because Slate already
/// behaves as it asks, or refused (ADR 0077).
pub fn setsockopt(a: Args) -> Result {
    use core::sync::atomic::Ordering::Relaxed;
    let [_, level, name, val, len, _] = a.0;
    let f = sock(a.fd(0))?;
    let s = kind(&f).ok_or(ENOTSOCK)?;
    let int = || -> core::result::Result<i32, Errno> {
        if len < 4 {
            return Err(EINVAL);
        }
        read_user::<i32>(val).map_err(|_| EFAULT)
    };
    // Unix sockets have only the socket level (observed on Linux:
    // EOPNOTSUPP for any other).
    if matches!(s, Sock::Unix(_)) && level != SOL_SOCKET {
        return refuse(true, level, name, EOPNOTSUPP);
    }
    // IP_OPTIONS (ip(7)): the option field every IPv4 packet carries (at
    // most 40 bytes, well formed: EINVAL otherwise); an empty one clears it.
    if level == IPPROTO_IP && name == IP_OPTIONS && matches!(s, Sock::Dgram(_) | Sock::Stream(_)) {
        let n = usize::try_from(len).ok().filter(|&n| n <= 40).ok_or(EINVAL)?;
        let mut b = alloc::vec![0u8; n];
        copy_from_user(&mut b, val).map_err(|_| EFAULT)?;
        let field = slate_net::OptionField::new(&b).map_err(|_| EINVAL)?;
        match s {
            Sock::Dgram(d) => d.set_option_field(field)?,
            Sock::Stream(t) => t.set_options(slate_net::TcpOptions { ip_options: field, ..t.options()? })?,
            _ => {}
        }
        return Ok(0);
    }
    // SO_PEEK_OFF: TCP only so far; others say so rather than ignore it
    // (programs such as pasta trust the offset once it is accepted).
    if level == SOL_SOCKET && name == SO_PEEK_OFF {
        let Sock::Stream(t) = s else { return Err(EOPNOTSUPP) };
        t.peek_off.store(i64::from(int()?.max(-1)), Relaxed);
        return Ok(0);
    }
    // struct timeval (socket(7)): sockets whose sends never block keep
    // SO_SNDTIMEO only to read it back.
    if level == SOL_SOCKET && (name == SO_RCVTIMEO || name == SO_SNDTIMEO) {
        if len < 16 {
            return Err(EINVAL);
        }
        let (sec, usec): (i64, i64) = (read_user(val).map_err(|_| EFAULT)?, read_user(val + 8).map_err(|_| EFAULT)?);
        let ns = (sec.max(0) as u64) * 1_000_000_000 + (usec.max(0) as u64) * 1000;
        timeout_slot(&s, name).store(ns, Relaxed);
        return Ok(0);
    }
    if level == IPPROTO_IPV6 && name == IPV6_V6ONLY {
        let on = int()? != 0;
        return match s {
            Sock::Dgram(d) => d.set_v6only(on).map(|_| 0),
            Sock::Stream(t) => t.set_v6only(on).map(|_| 0),
            _ => refuse(true, level, name, ENOPROTOOPT),
        };
    }
    if level == IPPROTO_ICMPV6 && name == ICMP6_FILTER {
        let Sock::Dgram(d) = s else { return refuse(true, level, name, ENOPROTOOPT) };
        if d.kind != Kind::RawIcmp6 || len < 32 {
            return Err(EINVAL);
        }
        let raw = read_raw(val, 32)?;
        let words: [u32; 8] = core::array::from_fn(|i| u32::from_ne_bytes(raw[4 * i..4 * i + 4].try_into().unwrap()));
        return d.set_icmp6_filter(words).map(|_| 0);
    }
    if level == SOL_SOCKET && name == SO_BINDTODEVICE {
        // The interface's name (empty: any), at most IFNAMSIZ bytes.
        let raw = read_raw(val, len.min(16))?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        let name = core::str::from_utf8(&raw[..end]).map_err(|_| EINVAL)?;
        return match s {
            Sock::Dgram(d) => d.bind_device(name).map(|_| 0),
            Sock::Stream(t) => t.bind_device(name).map(|_| 0),
            _ => refuse(true, level, SO_BINDTODEVICE, ENOPROTOOPT),
        };
    }
    // TCP's options (tcp(7)), SO_KEEPALIVE and IP_TOS.
    if let Sock::Stream(t) = s
        && ((level == SOL_SOCKET && name == SO_KEEPALIVE)
            || (level == IPPROTO_IP && name == IP_TOS)
            || (level == IPPROTO_TCP
                && matches!(
                    name,
                    TCP_NODELAY | TCP_MAXSEG | TCP_CORK | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT | TCP_QUICKACK
                )))
    {
        let v = int()?;
        let mut o = t.options()?;
        let secs = || u32::try_from(v).ok().filter(|v| (1..=32767).contains(v)).ok_or(EINVAL);
        match (level, name) {
            (SOL_SOCKET, _) => o.keepalive = v != 0,
            (IPPROTO_IP, _) => o.tos = v as u8,
            (_, TCP_NODELAY) => o.nodelay = v != 0,
            (_, TCP_CORK) => o.cork = v != 0,
            (_, TCP_KEEPIDLE) => o.keep_idle = secs()?,
            (_, TCP_KEEPINTVL) => o.keep_intvl = secs()?,
            (_, TCP_KEEPCNT) => o.keep_cnt = u32::try_from(v).ok().filter(|v| (1..=127).contains(v)).ok_or(EINVAL)?,
            (_, TCP_QUICKACK) => {
                if v != 0 {
                    t.quickack()?;
                }
                return Ok(0);
            }
            // A cap on the MSS for the connection still to be made (0: none).
            _ => o.max_seg = Some(u16::try_from(v).map_err(|_| EINVAL)?).filter(|&m| m != 0),
        }
        t.set_options(o)?;
        return Ok(0);
    }
    if let Sock::Packet(p) = s {
        match (level, name) {
            // struct sock_fprog: the length (unsigned short), then a
            // pointer to `struct sock_filter`s (socket(7), bpf(4)).
            (SOL_SOCKET, SO_ATTACH_FILTER) => {
                p.set_filter(Some(read_sock_fprog(val, len)?))?;
                return Ok(0);
            }
            (SOL_SOCKET, SO_DETACH_FILTER) => {
                p.set_filter(None)?;
                return Ok(0);
            }
            // Multicast and promiscuous membership: the cards take every
            // multicast frame and no other host's (a GAP); auxiliary data
            // would only say checksums are complete, which they are.
            (SOL_PACKET, PACKET_ADD_MEMBERSHIP | PACKET_DROP_MEMBERSHIP | PACKET_AUXDATA) => return Ok(0),
            _ => {}
        }
    }
    if let Sock::Netlink(n) = s
        && level == SOL_NETLINK
        && (name == NETLINK_ADD_MEMBERSHIP || name == NETLINK_DROP_MEMBERSHIP)
    {
        n.membership(int()? as u32, name == NETLINK_ADD_MEMBERSHIP)?;
        return Ok(0);
    }
    if let Sock::Netlink(n) = s
        && level == SOL_NETLINK
        && (name == NETLINK_CAP_ACK || name == NETLINK_EXT_ACK)
    {
        let on = int()? != 0;
        let flag = if name == NETLINK_CAP_ACK { &n.cap_ack } else { &n.ext_ack };
        flag.store(on, Relaxed);
        return Ok(0);
    }
    if let Sock::Uevent(u) = s {
        match (level, name) {
            (SOL_SOCKET, SO_PASSCRED) => {
                u.passcred.store(int()? != 0, Relaxed);
                return Ok(0);
            }
            (SOL_NETLINK, NETLINK_ADD_MEMBERSHIP) => {
                u.membership(int()? as u32, true)?;
                return Ok(0);
            }
            (SOL_NETLINK, NETLINK_DROP_MEMBERSHIP) => {
                u.membership(int()? as u32, false)?;
                return Ok(0);
            }
            (SOL_SOCKET, SO_ATTACH_FILTER) => {
                u.set_filter(Some(read_sock_fprog(val, len)?))?;
                return Ok(0);
            }
            (SOL_SOCKET, SO_DETACH_FILTER) => {
                u.set_filter(None)?;
                return Ok(0);
            }
            (SOL_SOCKET, SO_LOCK_FILTER) => {
                u.lock_filter(int()? != 0)?;
                return Ok(0);
            }
            _ => {}
        }
    }
    // SO_PASSCRED (unix(7)): the sender's credentials with each message.
    // SO_REUSEPORT is refused on Unix sockets (observed on Linux:
    // EOPNOTSUPP).
    if let Sock::Unix(u) = s {
        match (level, name) {
            (SOL_SOCKET, SO_PASSCRED) => {
                u.passcred.store(int()? != 0, Relaxed);
                return Ok(0);
            }
            (SOL_SOCKET, SO_REUSEPORT) => return refuse(true, level, name, EOPNOTSUPP),
            _ => {}
        }
    }
    let opts = sock_opts(&s);
    match (level, name, &s) {
        // A TCP connection in TIME-WAIT never holds its port against bind;
        // Unix sockets have no use for it (as on Linux). UDP still refuses
        // a second bind of a port (EADDRINUSE).
        (SOL_SOCKET, SO_REUSEADDR, Sock::Dgram(_) | Sock::Stream(_) | Sock::Unix(_)) => {
            opts.set_flag(SockOpts::REUSEADDR, int()? != 0)
        }
        // Broadcast sends are allowed without it.
        (SOL_SOCKET, SO_BROADCAST, Sock::Dgram(_)) => opts.set_flag(SockOpts::BROADCAST, int()? != 0),
        // 0 to 6 for anyone, others with CAP_NET_ADMIN (socket(7); EPERM
        // otherwise, -1 included, as Linux was seen to answer).
        (SOL_SOCKET, SO_PRIORITY, _) => {
            let v = int()?;
            if !(0..=6).contains(&v) && !crate::proc::cred::current().capable(crate::proc::cred::CAP_NET_ADMIN) {
                return Err(super::errno::EPERM);
            }
            opts.set_priority(v as u8)
        }
        (SOL_SOCKET, SO_DONTROUTE, Sock::Dgram(d)) => d.set_dontroute(int()? != 0)?,
        (IPPROTO_IP, IP_RECVERR, Sock::Dgram(_) | Sock::Stream(_))
        | (IPPROTO_IPV6, IPV6_RECVERR, Sock::Dgram(_) | Sock::Stream(_)) => {
            let on = int()? != 0;
            if let Sock::Dgram(d) = s {
                d.set_recverr(on)?;
            }
            opts.set_flag(SockOpts::RECVERR, on)
        }
        // UDP's own (udp(7)): a segment size up to 65535 (EINVAL past it, as
        // Linux was seen to answer); TCP sockets have neither (ENOPROTOOPT).
        (IPPROTO_UDP, UDP_SEGMENT, Sock::Dgram(d)) if d.kind == Kind::Udp => {
            let v = u32::try_from(int()?).ok().filter(|v| *v <= 65535).ok_or(EINVAL)?;
            d.gso.store(v, core::sync::atomic::Ordering::Relaxed);
        }
        (IPPROTO_UDP, UDP_GRO, Sock::Dgram(d)) if d.kind == Kind::Udp => opts.set_flag(SockOpts::GRO, int()? != 0),
        // Arrival times: kept for any socket (Linux takes them on all);
        // UDP's datagrams carry them.
        (SOL_SOCKET, SO_TIMESTAMP, _) => opts.set_flag(SockOpts::TIMESTAMP, int()? != 0),
        (SOL_SOCKET, SO_TIMESTAMPNS, _) => opts.set_flag(SockOpts::TIMESTAMPNS, int()? != 0),
        (IPPROTO_IP, IP_PKTINFO, Sock::Dgram(_)) => opts.set_flag(SockOpts::PKTINFO, int()? != 0),
        (IPPROTO_IP, IP_RECVTOS, Sock::Dgram(_)) => opts.set_flag(SockOpts::RECVTOS, int()? != 0),
        (IPPROTO_IP, IP_RECVTTL, Sock::Dgram(_)) => opts.set_flag(SockOpts::RECVTTL, int()? != 0),
        (IPPROTO_IPV6, IPV6_RECVHOPLIMIT, Sock::Dgram(_)) => opts.set_flag(SockOpts::RECVHOPLIMIT6, int()? != 0),
        (IPPROTO_IPV6, IPV6_RECVPKTINFO, Sock::Dgram(_)) => opts.set_flag(SockOpts::PKTINFO6, int()? != 0),
        (IPPROTO_IPV6, IPV6_RECVTCLASS, Sock::Dgram(_)) => opts.set_flag(SockOpts::RECVTCLASS6, int()? != 0),
        // The stack's buffers have fixed sizes; getsockopt says which.
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF | SO_SNDBUFFORCE | SO_RCVBUFFORCE, _) => {
            int()?;
        }
        (IPPROTO_IP, IP_TOS, Sock::Dgram(d)) => {
            d.opts.set_tos(int()? as u8);
            d.apply_ip_options()?;
        }
        // The traffic class of what an IPv6 socket sends (ipv6(7): -1 is
        // the default, 0).
        (IPPROTO_IPV6, IPV6_TCLASS, Sock::Dgram(d)) if d.v6 => {
            let tc = match int()? {
                -1 => 0,
                v @ 0..=255 => v as u8,
                _ => return Err(EINVAL),
            };
            d.opts.set_tos(tc);
            d.apply_ip_options()?;
        }
        (IPPROTO_IP, IP_MTU_DISCOVER, Sock::Dgram(_) | Sock::Stream(_)) => {
            let v = u8::try_from(int()?).ok().filter(|&v| v <= IP_PMTUDISC_PROBE).ok_or(EINVAL)?;
            opts.set_pmtudisc(v);
            // TCP's segments never exceed the path's MTU anyway.
            if let Sock::Dgram(d) = s {
                d.apply_ip_options()?;
            }
        }
        _ => return refuse(true, level, name, ENOPROTOOPT),
    }
    Ok(0)
}

/// Where a socket keeps SO_RCVTIMEO or SO_SNDTIMEO.
fn timeout_slot<'a>(s: &'a Sock<'a>, name: u64) -> &'a core::sync::atomic::AtomicU64 {
    match (s, name == SO_RCVTIMEO) {
        (Sock::Dgram(d), true) => &d.rcvtimeo_ns,
        (Sock::Stream(t), true) => &t.rcvtimeo_ns,
        (Sock::Stream(t), false) => &t.sndtimeo_ns,
        (Sock::Unix(u), true) => &u.rcvtimeo_ns,
        (Sock::Uevent(u), true) => &u.rcvtimeo_ns,
        (Sock::Netlink(n), true) => &n.rcvtimeo_ns,
        (Sock::Packet(p), true) => &p.rcvtimeo_ns,
        (other, false) => &sock_opts(other).sndtimeo_ns,
    }
}

fn sock_opts<'a>(s: &'a Sock<'a>) -> &'a SockOpts {
    match s {
        Sock::Dgram(d) => &d.opts,
        Sock::Stream(t) => &t.opts,
        Sock::Unix(u) => &u.opts,
        Sock::Netlink(n) => &n.opts,
        Sock::Uevent(u) => &u.opts,
        Sock::Packet(p) => &p.opts,
    }
}

pub fn getsockopt(a: Args) -> Result {
    let [_, level, name, val, len_ptr, _] = a.0;
    let f = sock(a.fd(0))?;
    let s = kind(&f).unwrap();
    if matches!(s, Sock::Unix(_)) && level != SOL_SOCKET {
        return refuse(false, level, name, EOPNOTSUPP);
    }
    // The option field IP_OPTIONS set; lingering on close is never on
    // (`struct linger`: l_onoff, l_linger).
    if level == IPPROTO_IP && name == IP_OPTIONS && matches!(s, Sock::Dgram(_) | Sock::Stream(_)) {
        let field = match &s {
            Sock::Dgram(d) => d.option_field()?,
            Sock::Stream(t) => t.options()?.ip_options,
            _ => slate_net::OptionField::default(),
        };
        write_raw(val, len_ptr, field.as_slice())?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_LINGER {
        write_raw(val, len_ptr, &[0u8; 8])?;
        return Ok(0);
    }
    if level == SOL_SOCKET && (name == SO_RCVTIMEO || name == SO_SNDTIMEO) {
        // struct timeval: seconds, then microseconds.
        let ns = timeout_slot(&s, name).load(core::sync::atomic::Ordering::Relaxed);
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
        b[8..].copy_from_slice(&((ns % 1_000_000_000 / 1000) as i64).to_ne_bytes());
        write_raw(val, len_ptr, &b)?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_PEEK_OFF {
        let Some(Sock::Stream(t)) = kind(&f) else { return Err(EOPNOTSUPP) };
        let v = t.peek_off.load(core::sync::atomic::Ordering::Relaxed).clamp(-1, i64::from(i32::MAX)) as i32;
        write_raw(val, len_ptr, &v.to_ne_bytes())?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_LOCK_FILTER {
        let Sock::Uevent(u) = &s else { return Err(ENOPROTOOPT) };
        write_raw(val, len_ptr, &i32::from(u.filter_locked()).to_ne_bytes())?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_PASSCRED {
        let on = match &s {
            Sock::Unix(u) => u.passcred.load(core::sync::atomic::Ordering::Relaxed),
            Sock::Uevent(u) => u.passcred.load(core::sync::atomic::Ordering::Relaxed),
            _ => false,
        };
        write_raw(val, len_ptr, &i32::from(on).to_ne_bytes())?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_PEERCRED {
        let c = match s {
            Sock::Unix(u) => u.peer_cred(),
            _ => return Err(ENOPROTOOPT),
        };
        let mut b = [0u8; 12];
        b[0..4].copy_from_slice(&c.pid.to_ne_bytes());
        b[4..8].copy_from_slice(&c.uid.to_ne_bytes());
        b[8..12].copy_from_slice(&c.gid.to_ne_bytes());
        write_raw(val, len_ptr, &b)?;
        return Ok(0);
    }
    if level == IPPROTO_ICMPV6 && name == ICMP6_FILTER {
        let Sock::Dgram(d) = &s else { return Err(ENOPROTOOPT) };
        let b: Vec<u8> = d.icmp6_filter().iter().flat_map(|w| w.to_ne_bytes()).collect();
        write_raw(val, len_ptr, &b)?;
        return Ok(0);
    }
    if level == SOL_SOCKET && name == SO_BINDTODEVICE {
        let name = match &s {
            Sock::Dgram(d) => d.device_name(),
            Sock::Stream(t) => t.device_name(),
            _ => return Err(ENOPROTOOPT),
        };
        let mut b = name.into_bytes();
        b.push(0);
        write_raw(val, len_ptr, &b)?;
        return Ok(0);
    }
    // TCP_INFO: `struct tcp_info` (musl `netinet/tcp.h`, 232 bytes): the
    // state, options, timers (microseconds), segment size and window
    // (segments), from the connection; what the stack does not count
    // stays zero.
    if level == IPPROTO_TCP && name == TCP_INFO {
        let Sock::Stream(t) = &s else { return Err(ENOPROTOOPT) };
        use slate_net::TcpState as S;
        // Linux's state numbers (musl `netinet/tcp.h` TCP_ESTABLISHED...).
        let state: u8 = match t.state() {
            Some(S::Established) => 1,
            Some(S::SynSent) => 2,
            Some(S::SynReceived) => 3,
            Some(S::FinWait1) => 4,
            Some(S::FinWait2) => 5,
            Some(S::TimeWait) => 6,
            Some(S::CloseWait) => 8,
            Some(S::LastAck) => 9,
            Some(S::Listen) => 10,
            Some(S::Closing) => 11,
            Some(S::Closed) | None => 7,
        };
        let i = t.info().unwrap_or_default();
        let mss = i.mss.max(1);
        let mut b = [0u8; 232];
        b[0] = state;
        b[2] = i.retransmits.min(255) as u8;
        b[5] = (if i.timestamps { TCPI_OPT_TIMESTAMPS } else { 0 })
            | (if i.sack { TCPI_OPT_SACK } else { 0 })
            | (if i.snd_wscale != 0 || i.rcv_wscale != 0 { TCPI_OPT_WSCALE } else { 0 });
        // tcpi_snd_wscale and tcpi_rcv_wscale: four bits each, in that order.
        b[6] = (i.snd_wscale & 0xF) | (i.rcv_wscale << 4);
        let mut put =
            |off: usize, v: u64| b[off..off + 4].copy_from_slice(&(v.min(u64::from(u32::MAX)) as u32).to_ne_bytes());
        put(8, i.rto_ms * 1000); // rto (us)
        put(16, mss as u64); // snd_mss
        put(20, mss as u64); // rcv_mss
        put(24, i.unacked.div_ceil(mss) as u64); // unacked (segments)
        put(60, 1500); // pmtu
        put(68, i.rtt_ms * 1000); // rtt (us)
        put(72, i.rttvar_ms * 1000); // rttvar (us)
        put(76, if i.ssthresh == usize::MAX { u64::from(u32::MAX) } else { (i.ssthresh / mss) as u64 }); // snd_ssthresh
        put(80, (i.cwnd / mss) as u64); // snd_cwnd (segments)
        put(84, mss as u64); // advmss
        put(100, u64::from(i.retransmits)); // total_retrans
        put(148, i.rtt_ms * 1000); // min_rtt (us)
        put(228, u64::from(i.snd_wnd)); // snd_wnd
        write_raw(val, len_ptr, &b)?;
        return Ok(0);
    }
    let (domain, ty, proto, error, listening) = match s {
        Sock::Dgram(d) => (
            if d.v6 { AF_INET6 } else { AF_INET as u64 },
            if matches!(d.kind, Kind::RawIcmp | Kind::RawIp | Kind::RawIcmp6) { SOCK_RAW } else { SOCK_DGRAM },
            match d.kind {
                Kind::Udp => IPPROTO_UDP,
                Kind::RawIp => IPPROTO_RAW,
                Kind::Ping6 | Kind::RawIcmp6 => IPPROTO_ICMPV6,
                _ => IPPROTO_ICMP,
            },
            if name == SO_ERROR { d.take_error() } else { 0 },
            false,
        ),
        Sock::Stream(t) => {
            let domain = if t.v6 { AF_INET6 } else { AF_INET as u64 };
            (domain, SOCK_STREAM, IPPROTO_TCP, if name == SO_ERROR { t.take_error() } else { 0 }, t.listening())
        }
        Sock::Unix(u) => (
            AF_UNIX,
            match u.kind {
                unix::Kind::Stream => SOCK_STREAM,
                unix::Kind::Dgram => SOCK_DGRAM,
                unix::Kind::SeqPacket => SOCK_SEQPACKET,
            },
            0,
            0,
            u.listening(),
        ),
        Sock::Netlink(n) => (AF_NETLINK, SOCK_RAW, u64::from(n.protocol), 0, false),
        Sock::Uevent(_) => (AF_NETLINK, SOCK_RAW, u64::from(NETLINK_KOBJECT_UEVENT), 0, false),
        Sock::Packet(p) => (u64::from(AF_PACKET), if p.cooked { SOCK_DGRAM } else { SOCK_RAW }, 0, 0, false),
    };
    let v: i32 = match (level, name) {
        (SOL_SOCKET, SO_TYPE) => ty as i32,
        (SOL_SOCKET, SO_ERROR) => error,
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => 262_144,
        (SOL_SOCKET, SO_DOMAIN) => domain as i32,
        (SOL_SOCKET, SO_PROTOCOL) => proto as i32,
        (SOL_SOCKET, SO_ACCEPTCONN) => i32::from(listening),
        (SOL_SOCKET, SO_KEEPALIVE) => match s {
            Sock::Stream(t) => i32::from(t.options()?.keepalive),
            _ => 0,
        },
        (SOL_SOCKET, SO_REUSEADDR) => i32::from(sock_opts(&s).flag(SockOpts::REUSEADDR)),
        (SOL_SOCKET, SO_BROADCAST) => i32::from(sock_opts(&s).flag(SockOpts::BROADCAST)),
        (SOL_SOCKET, SO_DONTROUTE) => i32::from(sock_opts(&s).flag(SockOpts::DONTROUTE)),
        (SOL_SOCKET, SO_PRIORITY) => i32::from(sock_opts(&s).priority()),
        (IPPROTO_IP, IP_RECVERR) | (IPPROTO_IPV6, IPV6_RECVERR) if matches!(s, Sock::Dgram(_) | Sock::Stream(_)) => {
            i32::from(sock_opts(&s).flag(SockOpts::RECVERR))
        }
        (IPPROTO_IP, IP_PKTINFO) if matches!(s, Sock::Dgram(_)) => i32::from(sock_opts(&s).flag(SockOpts::PKTINFO)),
        (IPPROTO_UDP, UDP_SEGMENT) => match &s {
            Sock::Dgram(d) if d.kind == Kind::Udp => d.gso.load(core::sync::atomic::Ordering::Relaxed) as i32,
            _ => return refuse(false, level, name, ENOPROTOOPT),
        },
        (IPPROTO_UDP, UDP_GRO) => match &s {
            Sock::Dgram(d) if d.kind == Kind::Udp => i32::from(d.opts.flag(SockOpts::GRO)),
            _ => return refuse(false, level, name, ENOPROTOOPT),
        },
        (SOL_SOCKET, SO_TIMESTAMP) => i32::from(sock_opts(&s).flag(SockOpts::TIMESTAMP)),
        (SOL_SOCKET, SO_TIMESTAMPNS) => i32::from(sock_opts(&s).flag(SockOpts::TIMESTAMPNS)),
        (IPPROTO_IP, IP_RECVTOS) if matches!(s, Sock::Dgram(_)) => i32::from(sock_opts(&s).flag(SockOpts::RECVTOS)),
        (IPPROTO_IP, IP_RECVTTL) if matches!(s, Sock::Dgram(_)) => i32::from(sock_opts(&s).flag(SockOpts::RECVTTL)),
        (IPPROTO_IPV6, IPV6_RECVHOPLIMIT) if matches!(s, Sock::Dgram(_)) => {
            i32::from(sock_opts(&s).flag(SockOpts::RECVHOPLIMIT6))
        }
        (IPPROTO_IPV6, IPV6_RECVPKTINFO) if matches!(s, Sock::Dgram(_)) => {
            i32::from(sock_opts(&s).flag(SockOpts::PKTINFO6))
        }
        (IPPROTO_IPV6, IPV6_RECVTCLASS) if matches!(s, Sock::Dgram(_)) => {
            i32::from(sock_opts(&s).flag(SockOpts::RECVTCLASS6))
        }
        (IPPROTO_IPV6, IPV6_TCLASS) if matches!(&s, Sock::Dgram(d) if d.v6) => match &s {
            Sock::Dgram(d) => i32::from(d.opts.tos()),
            _ => 0,
        },
        (IPPROTO_IP, IP_TOS) => match &s {
            Sock::Dgram(d) => i32::from(d.opts.tos()),
            Sock::Stream(t) => i32::from(t.options()?.tos),
            _ => return refuse(false, level, name, ENOPROTOOPT),
        },
        (IPPROTO_IP, IP_MTU_DISCOVER) => match &s {
            Sock::Dgram(_) | Sock::Stream(_) => i32::from(sock_opts(&s).pmtudisc()),
            _ => return refuse(false, level, name, ENOPROTOOPT),
        },
        (
            IPPROTO_TCP,
            TCP_NODELAY | TCP_CORK | TCP_KEEPIDLE | TCP_KEEPINTVL | TCP_KEEPCNT | TCP_MAXSEG | TCP_QUICKACK,
        ) => {
            let Sock::Stream(t) = &s else { return Err(ENOPROTOOPT) };
            let o = t.options()?;
            match name {
                TCP_NODELAY => i32::from(o.nodelay),
                TCP_CORK => i32::from(o.cork),
                TCP_KEEPIDLE => o.keep_idle as i32,
                TCP_KEEPINTVL => o.keep_intvl as i32,
                TCP_KEEPCNT => o.keep_cnt as i32,
                TCP_MAXSEG => t.info().map_or(536, |i| i.mss as i32),
                _ => 0,
            }
        }
        (IPPROTO_IPV6, IPV6_V6ONLY) => match s {
            Sock::Dgram(d) if d.v6 => i32::from(d.v6only()),
            Sock::Stream(t) if t.v6 => i32::from(t.v6only()),
            _ => return Err(ENOPROTOOPT),
        },
        _ => return refuse(false, level, name, ENOPROTOOPT),
    };
    if len_ptr != 0 {
        let room: u32 = read_user(len_ptr).map_err(|_| EFAULT)?;
        if room < 4 {
            return Err(EINVAL);
        }
        write_user(val, &v).map_err(|_| EFAULT)?;
        write_user(len_ptr, &4u32).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

pub fn shutdown(a: Args) -> Result {
    let f = sock(a.fd(0))?;
    let how = a.0[1];
    match kind(&f).unwrap() {
        Sock::Stream(s) => s.shutdown(how)?,
        Sock::Unix(s) => {
            if how > 2 {
                return Err(EINVAL);
            }
            s.shutdown(how != 1, how != 0)?
        }
        _ => {}
    }
    Ok(0)
}
