// SPDX-License-Identifier: MIT OR Apache-2.0

//! AF_UNIX stream sockets (unix(7)) with abstract names, for local
//! control channels (slinit), and peer credentials; IPv4 TCP and UDP
//! sockets (ip(7), tcp(7), udp(7)) for quarry's HTTP and DNS clients and
//! netd's DHCP client; route netlink sockets for netd.

use alloc::vec::Vec;

use slate_abi::nr;

use crate::errno::{Errno, Result};
use crate::sys;

const AF_UNIX: usize = 1;
const SOCK_STREAM: usize = 1;
const SOCK_CLOEXEC: usize = 0o2000000;
const SOL_SOCKET: usize = 1;
const SO_PEERCRED: usize = 17;

/// `struct sockaddr_un` for an abstract name (a leading NUL byte).
fn abstract_addr(name: &[u8]) -> Result<(Vec<u8>, usize)> {
    if name.len() > 106 {
        return Err(Errno::ENAMETOOLONG);
    }
    let mut a = Vec::with_capacity(110);
    a.extend_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    a.push(0);
    a.extend_from_slice(name);
    let len = a.len();
    Ok((a, len))
}

/// socket(2) with SOCK_CLOEXEC. The kinds (stream 1, datagram 2) have
/// the same numbers natively, where the flags are a separate argument.
fn new_socket(family: usize, kind: usize) -> Result<i32> {
    if sys::native() {
        return crate::syscall!(nr::SOCKET as usize, family, kind, 0, slate_abi::open::CLOEXEC).map(|fd| fd as i32);
    }
    crate::syscall!(sys::SOCKET, family, kind | SOCK_CLOEXEC, 0).map(|fd| fd as i32)
}

/// accept4(2) with SOCK_CLOEXEC.
fn accept_cloexec(fd: i32, addr: *mut u8, len: *mut u32) -> Result<usize> {
    if sys::native() {
        return crate::syscall!(nr::ACCEPT as usize, fd, addr, len, slate_abi::open::CLOEXEC);
    }
    crate::syscall!(sys::ACCEPT4, fd, addr, len, SOCK_CLOEXEC)
}

fn socket() -> Result<i32> {
    new_socket(AF_UNIX, SOCK_STREAM)
}

/// A listening socket at the abstract name `name`.
pub fn listen(name: &[u8]) -> Result<i32> {
    let fd = socket()?;
    let (addr, len) = abstract_addr(name)?;
    let r = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), len)
        .and_then(|_| crate::syscall!(sys::pick(sys::LISTEN, nr::LISTEN), fd, 16));
    if let Err(e) = r {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// Connect to the abstract name `name`.
pub fn connect(name: &[u8]) -> Result<i32> {
    let fd = socket()?;
    let (addr, len) = abstract_addr(name)?;
    if let Err(e) = crate::syscall!(sys::pick(sys::CONNECT, nr::CONNECT), fd, addr.as_ptr(), len) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// Accept a connection.
pub fn accept(fd: i32) -> Result<i32> {
    accept_cloexec(fd, core::ptr::null_mut(), core::ptr::null_mut()).map(|c| c as i32)
}

/// The peer's (pid, uid, gid) (SO_PEERCRED's `struct ucred`).
pub fn peer_cred(fd: i32) -> Result<(i32, u32, u32)> {
    let mut cred = [0u32; 3];
    let mut len: u32 = 12;
    crate::syscall!(
        sys::pick(sys::GETSOCKOPT, nr::GETSOCKOPT),
        fd,
        SOL_SOCKET,
        SO_PEERCRED,
        cred.as_mut_ptr(),
        &mut len as *mut u32
    )?;
    Ok((cred[0] as i32, cred[1], cred[2]))
}

// Address families and socket options. Source: musl `sys/socket.h`,
// `netinet/in.h`.
const AF_INET: usize = 2;
const SOCK_DGRAM: usize = 2;
const SO_ERROR: usize = 4;
const F_GETFL: u32 = 3;
const F_SETFL: u32 = 4;

/// `struct sockaddr_in` (ip(7)): family, port (network order), address.
fn inet_addr(ip: [u8; 4], port: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[4..8].copy_from_slice(&ip);
    a
}

/// Connect a TCP socket to `ip:port`, giving up after `timeout_ms`.
pub fn tcp_connect(ip: [u8; 4], port: u16, timeout_ms: i32) -> Result<i32> {
    let fd = new_socket(AF_INET, SOCK_STREAM)?;
    let r = (|| -> Result<()> {
        let flags = crate::process::fcntl(fd, F_GETFL, 0)?;
        crate::process::fcntl(fd, F_SETFL, flags | crate::fs::O_NONBLOCK as usize)?;
        let addr = inet_addr(ip, port);
        match crate::syscall!(sys::pick(sys::CONNECT, nr::CONNECT), fd, addr.as_ptr(), addr.len()) {
            Ok(_) => {}
            Err(Errno::EINPROGRESS) => {
                let mut pfd = [crate::io::PollFd { fd, events: crate::io::POLLOUT, revents: 0 }];
                if crate::io::poll(&mut pfd, timeout_ms)? == 0 {
                    return Err(Errno::ETIMEDOUT);
                }
                let mut err: i32 = 0;
                let mut len: u32 = 4;
                crate::syscall!(
                    sys::pick(sys::GETSOCKOPT, nr::GETSOCKOPT),
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    &mut err as *mut i32,
                    &mut len as *mut u32
                )?;
                if err != 0 {
                    return Err(Errno(err));
                }
            }
            Err(e) => return Err(e),
        }
        crate::process::fcntl(fd, F_SETFL, flags).map(|_| ())
    })();
    match r {
        Ok(()) => Ok(fd),
        Err(e) => {
            let _ = crate::io::close(fd);
            Err(e)
        }
    }
}

const SO_REUSEADDR: usize = 2;

/// A TCP socket listening on `port` of every address, with SO_REUSEADDR.
pub fn tcp_listen(port: u16, backlog: usize) -> Result<i32> {
    let fd = new_socket(AF_INET, SOCK_STREAM)?;
    let one: i32 = 1;
    let addr = inet_addr([0; 4], port);
    let r = crate::syscall!(
        sys::pick(sys::SETSOCKOPT, nr::SETSOCKOPT),
        fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &one as *const i32,
        4
    )
    .and_then(|_| crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()))
    .and_then(|_| crate::syscall!(sys::pick(sys::LISTEN, nr::LISTEN), fd, backlog));
    if let Err(e) = r {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// Accept a TCP connection: the socket and the peer's address and port.
pub fn tcp_accept(fd: i32) -> Result<(i32, [u8; 4], u16)> {
    let mut addr = [0u8; 16];
    let mut len: u32 = 16;
    let c = accept_cloexec(fd, addr.as_mut_ptr(), &mut len as *mut u32)? as i32;
    Ok((c, [addr[4], addr[5], addr[6], addr[7]], u16::from_be_bytes([addr[2], addr[3]])))
}

/// An unbound UDP socket.
pub fn udp_socket() -> Result<i32> {
    new_socket(AF_INET, SOCK_DGRAM)
}

/// Send a datagram to `ip:port`.
pub fn send_to(fd: i32, buf: &[u8], ip: [u8; 4], port: u16) -> Result<usize> {
    let addr = inet_addr(ip, port);
    crate::syscall!(sys::pick(sys::SENDTO, nr::SENDTO), fd, buf.as_ptr(), buf.len(), 0, addr.as_ptr(), addr.len())
}

/// Receive a datagram (from anyone).
pub fn recv(fd: i32, buf: &mut [u8]) -> Result<usize> {
    crate::syscall!(sys::pick(sys::RECVFROM, nr::RECVFROM), fd, buf.as_mut_ptr(), buf.len(), 0, 0, 0)
}

/// SOL_SOCKET options (socket(7); numbers from musl `sys/socket.h`).
pub const SO_BROADCAST: usize = 6;
pub const SO_BINDTODEVICE: usize = 25;

/// setsockopt(2) at SOL_SOCKET with a raw value.
pub fn set_option(fd: i32, name: usize, value: &[u8]) -> Result<()> {
    crate::syscall!(sys::pick(sys::SETSOCKOPT, nr::SETSOCKOPT), fd, SOL_SOCKET, name, value.as_ptr(), value.len())
        .map(|_| ())
}

/// A UDP socket bound to `port` of every address, sending and receiving
/// only on the interface `device` (SO_BINDTODEVICE), allowed to broadcast:
/// what a DHCP client on one card needs.
pub fn udp_on_device(device: &[u8], port: u16) -> Result<i32> {
    let fd = udp_socket()?;
    let one = 1i32.to_ne_bytes();
    let r = set_option(fd, SO_BINDTODEVICE, device).and_then(|_| set_option(fd, SO_BROADCAST, &one)).and_then(|_| {
        let addr = inet_addr([0; 4], port);
        crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()).map(|_| ())
    });
    if let Err(e) = r {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

// IPv6 (ipv6(7), RFC 3542; numbers from musl `sys/socket.h`,
// `netinet/in.h`, `netinet/icmp6.h`).
const AF_INET6: usize = 10;
const IPPROTO_ICMPV6: usize = 58;
const ICMP6_FILTER: usize = 1;

/// A raw ICMPv6 socket on interface `device` that passes only the ICMPv6
/// message types in `types` (ICMP6_FILTER: a set bit blocks a type).
pub fn icmp6_on_device(device: &[u8], types: &[u8]) -> Result<i32> {
    let fd = new_socket_proto(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)?;
    let mut filter = [u32::MAX; 8];
    for &t in types {
        filter[usize::from(t) / 32] &= !(1 << (t % 32));
    }
    let bytes: Vec<u8> = filter.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let r = crate::syscall!(
        sys::pick(sys::SETSOCKOPT, nr::SETSOCKOPT),
        fd,
        IPPROTO_ICMPV6,
        ICMP6_FILTER,
        bytes.as_ptr(),
        bytes.len()
    )
    .and_then(|_| set_option(fd, SO_BINDTODEVICE, device));
    if let Err(e) = r {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// A socket address of either family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    V4([u8; 4], u16),
    /// Address, port, scope ID (the interface, for link-local addresses).
    V6([u8; 16], u16, u32),
}

impl Peer {
    pub fn port(&self) -> u16 {
        match self {
            Peer::V4(_, p) | Peer::V6(_, p, _) => *p,
        }
    }
    pub fn with_port(self, port: u16) -> Peer {
        match self {
            Peer::V4(a, _) => Peer::V4(a, port),
            Peer::V6(a, _, s) => Peer::V6(a, port, s),
        }
    }
    pub fn family(&self) -> usize {
        match self {
            Peer::V4(..) => AF_INET,
            Peer::V6(..) => AF_INET6,
        }
    }
    /// `struct sockaddr_in` or `struct sockaddr_in6` (ip(7), ipv6(7)).
    pub fn encode(&self) -> Vec<u8> {
        match *self {
            Peer::V4(a, port) => inet_addr(a, port).to_vec(),
            Peer::V6(a, port, scope) => {
                let mut b = alloc::vec![0u8; 28];
                b[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
                b[2..4].copy_from_slice(&port.to_be_bytes());
                b[8..24].copy_from_slice(&a);
                b[24..28].copy_from_slice(&scope.to_ne_bytes());
                b
            }
        }
    }
    pub fn decode(b: &[u8]) -> Option<Peer> {
        let family = usize::from(u16::from_ne_bytes([*b.first()?, *b.get(1)?]));
        let port = u16::from_be_bytes([*b.get(2)?, *b.get(3)?]);
        match family {
            AF_INET => Some(Peer::V4(b.get(4..8)?.try_into().ok()?, port)),
            AF_INET6 => Some(Peer::V6(
                b.get(8..24)?.try_into().ok()?,
                port,
                b.get(24..28).map_or(0, |s| u32::from_ne_bytes(s.try_into().unwrap())),
            )),
            _ => None,
        }
    }
}

/// A socket of `peer`'s family: SOCK_DGRAM (2) or SOCK_STREAM (1), with
/// `protocol`.
pub fn socket_for(peer: &Peer, kind: usize, protocol: usize) -> Result<i32> {
    new_socket_proto(peer.family(), kind, protocol)
}

/// sendto(2) to `peer`.
pub fn send_to_peer(fd: i32, buf: &[u8], peer: &Peer) -> Result<usize> {
    let a = peer.encode();
    crate::syscall!(sys::pick(sys::SENDTO, nr::SENDTO), fd, buf.as_ptr(), buf.len(), 0, a.as_ptr(), a.len())
}

/// recvfrom(2): the length and the sender.
pub fn recv_from_peer(fd: i32, buf: &mut [u8]) -> Result<(usize, Option<Peer>)> {
    let mut addr = [0u8; 28];
    let mut len: u32 = 28;
    let n = crate::syscall!(
        sys::pick(sys::RECVFROM, nr::RECVFROM),
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        0,
        addr.as_mut_ptr(),
        &mut len as *mut u32
    )?;
    Ok((n, Peer::decode(&addr[..len.min(28) as usize])))
}

// The TTL and hop limit with each datagram (ip(7), ipv6(7); musl
// `netinet/in.h`): IP_RECVTTL and IPV6_RECVHOPLIMIT, and their control
// messages IP_TTL and IPV6_HOPLIMIT.
const IPPROTO_IP: usize = 0;
const IPPROTO_IPV6: usize = 41;
const IP_RECVTTL: usize = 12;
const IP_TTL: i32 = 2;
const IPV6_RECVHOPLIMIT: usize = 51;
const IPV6_HOPLIMIT: i32 = 52;

/// Ask for each datagram's TTL or hop limit ([`recv_with_ttl`]).
pub fn want_ttl(fd: i32, v6: bool) -> Result<()> {
    let (level, name) = if v6 { (IPPROTO_IPV6, IPV6_RECVHOPLIMIT) } else { (IPPROTO_IP, IP_RECVTTL) };
    let one = 1i32.to_ne_bytes();
    crate::syscall!(sys::pick(sys::SETSOCKOPT, nr::SETSOCKOPT), fd, level, name, one.as_ptr(), one.len()).map(|_| ())
}

/// recvfrom(2), with the datagram's TTL or hop limit when one came
/// ([`want_ttl`] asks for it on Linux; the native call always gives it).
pub fn recv_with_ttl(fd: i32, buf: &mut [u8]) -> Result<(usize, Option<Peer>, Option<u8>)> {
    let mut addr = [0u8; 28];
    let iov = Iovec { base: buf.as_mut_ptr() as usize, len: buf.len() };
    if sys::native() {
        let b = slate_abi::Str { ptr: buf.as_mut_ptr() as u64, len: buf.len() as u64 };
        let mut m = slate_abi::Msg {
            bufs: &b as *const slate_abi::Str as u64,
            bufs_len: 1,
            addr: addr.as_mut_ptr() as u64,
            addr_len: 28,
            ..Default::default()
        };
        let n = crate::syscall!(nr::RECVMSG as usize, fd, &mut m as *mut slate_abi::Msg, 0)?;
        let ttl = (m.ttl != 0).then_some(m.ttl as u8);
        return Ok((n, Peer::decode(&addr[..(m.addr_len as usize).min(28)]), ttl));
    }
    let mut control = [0u64; 8];
    let mut m = MsgHdr {
        name: addr.as_mut_ptr() as usize,
        namelen: 28,
        iov: &iov as *const Iovec as usize,
        iovlen: 1,
        control: control.as_mut_ptr() as usize,
        controllen: core::mem::size_of_val(&control),
        flags: 0,
    };
    let n = crate::syscall!(sys::RECVMSG, fd, &mut m as *mut MsgHdr, 0)?;
    let bytes: Vec<u8> = control.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let mut ttl = None;
    let mut at = 0;
    while at + 16 <= m.controllen.min(bytes.len()) {
        let len = u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
        let (level, ty) = (
            i32::from_ne_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
            i32::from_ne_bytes(bytes[at + 12..at + 16].try_into().unwrap()),
        );
        if len < 20 || at + len > bytes.len() {
            break;
        }
        if (level, ty) == (IPPROTO_IP as i32, IP_TTL) || (level, ty) == (IPPROTO_IPV6 as i32, IPV6_HOPLIMIT) {
            ttl = Some(i32::from_ne_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as u8);
        }
        at += len.next_multiple_of(8);
    }
    Ok((n, Peer::decode(&addr[..(m.namelen as usize).min(28)]), ttl))
}

/// bind(2) to `peer`.
pub fn bind_peer(fd: i32, peer: &Peer) -> Result<()> {
    let a = peer.encode();
    crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, a.as_ptr(), a.len()).map(|_| ())
}

/// connect(2) to `peer` (for datagram sockets: the default destination).
pub fn connect_peer(fd: i32, peer: &Peer) -> Result<()> {
    let a = peer.encode();
    crate::syscall!(sys::pick(sys::CONNECT, nr::CONNECT), fd, a.as_ptr(), a.len()).map(|_| ())
}

/// Connect a TCP socket to `peer`, giving up after `timeout_ms`.
pub fn tcp_connect_peer(peer: &Peer, timeout_ms: i32) -> Result<i32> {
    let fd = socket_for(peer, SOCK_STREAM, 0)?;
    let r = (|| -> Result<()> {
        let flags = crate::process::fcntl(fd, F_GETFL, 0)?;
        crate::process::fcntl(fd, F_SETFL, flags | crate::fs::O_NONBLOCK as usize)?;
        match connect_peer(fd, peer) {
            Ok(()) => {}
            Err(Errno::EINPROGRESS) => {
                let mut pfd = [crate::io::PollFd { fd, events: crate::io::POLLOUT, revents: 0 }];
                if crate::io::poll(&mut pfd, timeout_ms)? == 0 {
                    return Err(Errno::ETIMEDOUT);
                }
                let mut err: i32 = 0;
                let mut len: u32 = 4;
                crate::syscall!(
                    sys::pick(sys::GETSOCKOPT, nr::GETSOCKOPT),
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    &mut err as *mut i32,
                    &mut len as *mut u32
                )?;
                if err != 0 {
                    return Err(Errno(err));
                }
            }
            Err(e) => return Err(e),
        }
        crate::process::fcntl(fd, F_SETFL, flags).map(|_| ())
    })();
    match r {
        Ok(()) => Ok(fd),
        Err(e) => {
            let _ = crate::io::close(fd);
            Err(e)
        }
    }
}

/// socket(2) with a protocol, close-on-exec.
fn new_socket_proto(family: usize, kind: usize, protocol: usize) -> Result<i32> {
    if sys::native() {
        return crate::syscall!(nr::SOCKET as usize, family, kind, protocol, slate_abi::open::CLOEXEC)
            .map(|fd| fd as i32);
    }
    crate::syscall!(sys::SOCKET, family, kind | SOCK_CLOEXEC, protocol).map(|fd| fd as i32)
}

/// Send a datagram to `[ip]:port` on an IPv6 socket.
pub fn send_to6(fd: i32, buf: &[u8], ip: [u8; 16], port: u16) -> Result<usize> {
    // struct sockaddr_in6 (ipv6(7)): family, port, flow information,
    // address, scope ID.
    let mut a = [0u8; 28];
    a[..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[8..24].copy_from_slice(&ip);
    crate::syscall!(sys::pick(sys::SENDTO, nr::SENDTO), fd, buf.as_ptr(), buf.len(), 0, a.as_ptr(), a.len())
}

/// Receive a datagram: its length, and the sender's address and port.
pub fn recv_from(fd: i32, buf: &mut [u8]) -> Result<(usize, [u8; 4], u16)> {
    let mut addr = [0u8; 16];
    let mut len: u32 = 16;
    let n = crate::syscall!(
        sys::pick(sys::RECVFROM, nr::RECVFROM),
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        0,
        addr.as_mut_ptr(),
        &mut len as *mut u32
    )?;
    Ok((n, [addr[4], addr[5], addr[6], addr[7]], u16::from_be_bytes([addr[2], addr[3]])))
}

/// A route netlink socket (rtnetlink(7), NETLINK_ROUTE 0) that joined the
/// multicast groups in `groups` (RTMGRP_* masks).
pub fn route_socket(groups: u32) -> Result<i32> {
    let fd = if sys::native() {
        crate::syscall!(nr::SOCKET as usize, AF_NETLINK, SOCK_RAW, 0, slate_abi::open::CLOEXEC)
    } else {
        crate::syscall!(sys::SOCKET, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 0)
    }? as i32;
    let addr = netlink_addr(0, groups);
    if let Err(e) = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// An nf_tables socket (netlink(7): NETLINK_NETFILTER 12), the firewall's
/// interface (ADR 0129).
pub fn netfilter_socket() -> Result<i32> {
    const NETLINK_NETFILTER: usize = 12;
    let fd = if sys::native() {
        crate::syscall!(nr::SOCKET as usize, AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER, slate_abi::open::CLOEXEC)
    } else {
        crate::syscall!(sys::SOCKET, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER)
    }? as i32;
    let addr = netlink_addr(0, 0);
    if let Err(e) = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

// Netlink uevent sockets (netlink(7)): AF_NETLINK 16, SOCK_RAW,
// NETLINK_KOBJECT_UEVENT 15; `struct sockaddr_nl` is family, pad, port
// ID, group mask.
const AF_NETLINK: usize = 16;
const SOCK_RAW: usize = 3;
const NETLINK_KOBJECT_UEVENT: usize = 15;

fn netlink_addr(port: u32, groups: u32) -> [u8; 12] {
    let mut a = [0u8; 12];
    a[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    a[4..8].copy_from_slice(&port.to_ne_bytes());
    a[8..12].copy_from_slice(&groups.to_ne_bytes());
    a
}

/// A uevent socket listening to the multicast groups in `groups`.
pub fn uevent_listen(groups: u32) -> Result<i32> {
    let fd = if sys::native() {
        crate::syscall!(nr::SOCKET as usize, AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT, slate_abi::open::CLOEXEC)
    } else {
        crate::syscall!(sys::SOCKET, AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_KOBJECT_UEVENT)
    }? as i32;
    let addr = netlink_addr(0, groups);
    if let Err(e) = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// Receive one uevent message: its length and the sender's port (0: the
/// kernel).
pub fn uevent_recv(fd: i32, buf: &mut [u8]) -> Result<(usize, u32)> {
    let mut addr = [0u8; 12];
    let mut len: u32 = 12;
    let n = crate::syscall!(
        sys::pick(sys::RECVFROM, nr::RECVFROM),
        fd,
        buf.as_mut_ptr(),
        buf.len(),
        0,
        addr.as_mut_ptr(),
        &mut len as *mut u32
    )?;
    Ok((n, u32::from_ne_bytes(addr[4..8].try_into().unwrap())))
}

/// `struct sockaddr_un` for a path in the file system.
fn path_addr(path: &[u8]) -> Result<Vec<u8>> {
    if path.len() > 107 {
        return Err(Errno::ENAMETOOLONG);
    }
    let mut a = Vec::with_capacity(110);
    a.extend_from_slice(&(AF_UNIX as u16).to_ne_bytes());
    a.extend_from_slice(path);
    a.push(0);
    Ok(a)
}

/// A listening Unix stream socket at `path` (an old socket file there is
/// replaced).
pub fn listen_path(path: &[u8], backlog: usize) -> Result<i32> {
    let addr = path_addr(path)?;
    let _ = crate::fs::unlink(path);
    let fd = socket()?;
    let r = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len())
        .and_then(|_| crate::syscall!(sys::pick(sys::LISTEN, nr::LISTEN), fd, backlog));
    if let Err(e) = r {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// A Unix datagram socket bound to `path` (an old socket file there is
/// replaced), for receiving.
pub fn dgram_bind_path(path: &[u8]) -> Result<i32> {
    let addr = path_addr(path)?;
    let _ = crate::fs::unlink(path);
    let fd = new_socket(AF_UNIX, SOCK_DGRAM)?;
    if let Err(e) = crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

/// An unbound Unix datagram socket, for sending.
pub fn dgram_socket() -> Result<i32> {
    new_socket(AF_UNIX, SOCK_DGRAM)
}

/// Send one datagram to the Unix socket at `path`.
pub fn dgram_send_path(fd: i32, path: &[u8], data: &[u8]) -> Result<usize> {
    let addr = path_addr(path)?;
    crate::syscall!(sys::pick(sys::SENDTO, nr::SENDTO), fd, data.as_ptr(), data.len(), 0, addr.as_ptr(), addr.len())
}

/// Connect to the Unix stream socket at `path`.
pub fn connect_path(path: &[u8]) -> Result<i32> {
    let addr = path_addr(path)?;
    let fd = socket()?;
    if let Err(e) = crate::syscall!(sys::pick(sys::CONNECT, nr::CONNECT), fd, addr.as_ptr(), addr.len()) {
        let _ = crate::io::close(fd);
        return Err(e);
    }
    Ok(fd)
}

// Descriptor passing (unix(7)): SCM_RIGHTS in a SOL_SOCKET control
// message on Linux (musl `sys/socket.h`: `struct msghdr`, `struct
// cmsghdr` with a size_t length, 8-byte alignment); natively a plain
// descriptor array in `slate_abi::Msg`.
const SCM_RIGHTS: i32 = 1;
/// Received descriptors are close-on-exec (send(2) MSG_CMSG_CLOEXEC).
const MSG_CMSG_CLOEXEC: usize = 0x4000_0000;
/// Most descriptors one message carries here.
pub const MAX_FDS: usize = 16;

/// `struct msghdr` (x86-64).
#[repr(C)]
struct MsgHdr {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
    flags: i32,
}

#[repr(C)]
struct Iovec {
    base: usize,
    len: usize,
}

/// Send `data` on a Unix socket with the descriptors `fds`.
pub fn send_fds(fd: i32, data: &[u8], fds: &[i32]) -> Result<usize> {
    if fds.len() > MAX_FDS {
        return Err(Errno::EINVAL);
    }
    if sys::native() {
        let buf = slate_abi::Str::new(data);
        let m = slate_abi::Msg {
            bufs: &buf as *const slate_abi::Str as u64,
            bufs_len: 1,
            fds: fds.as_ptr() as u64,
            fds_len: fds.len() as u32,
            ..Default::default()
        };
        return crate::syscall!(nr::SENDMSG as usize, fd, &m as *const slate_abi::Msg, 0);
    }
    let iov = Iovec { base: data.as_ptr() as usize, len: data.len() };
    let mut control = [0u8; 16 + 4 * MAX_FDS];
    let clen = if fds.is_empty() { 0 } else { 16 + 4 * fds.len() };
    control[..8].copy_from_slice(&(clen as u64).to_ne_bytes());
    control[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
    control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    for (i, f) in fds.iter().enumerate() {
        control[16 + 4 * i..20 + 4 * i].copy_from_slice(&f.to_ne_bytes());
    }
    let m = MsgHdr {
        name: 0,
        namelen: 0,
        iov: &iov as *const Iovec as usize,
        iovlen: 1,
        control: if clen == 0 { 0 } else { control.as_ptr() as usize },
        controllen: clen.next_multiple_of(8),
        flags: 0,
    };
    crate::syscall!(sys::SENDMSG, fd, &m as *const MsgHdr, 0)
}

/// Receive into `buf` and the descriptors that came with it (at most
/// [`MAX_FDS`]; close-on-exec).
pub fn recv_fds(fd: i32, buf: &mut [u8]) -> Result<(usize, Vec<i32>)> {
    let mut fds = [0i32; MAX_FDS];
    if sys::native() {
        let b = slate_abi::Str { ptr: buf.as_mut_ptr() as u64, len: buf.len() as u64 };
        let mut m = slate_abi::Msg {
            bufs: &b as *const slate_abi::Str as u64,
            bufs_len: 1,
            fds: fds.as_mut_ptr() as u64,
            fds_len: MAX_FDS as u32,
            ..Default::default()
        };
        let n = crate::syscall!(nr::RECVMSG as usize, fd, &mut m as *mut slate_abi::Msg, MSG_CMSG_CLOEXEC)?;
        return Ok((n, fds[..m.fds_len as usize].to_vec()));
    }
    let iov = Iovec { base: buf.as_mut_ptr() as usize, len: buf.len() };
    let mut control = [0u64; (16 + 4 * MAX_FDS) / 8];
    let mut m = MsgHdr {
        name: 0,
        namelen: 0,
        iov: &iov as *const Iovec as usize,
        iovlen: 1,
        control: control.as_mut_ptr() as usize,
        controllen: core::mem::size_of_val(&control),
        flags: 0,
    };
    let n = crate::syscall!(sys::RECVMSG, fd, &mut m as *mut MsgHdr, MSG_CMSG_CLOEXEC)?;
    let bytes: Vec<u8> = control.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= m.controllen {
        let len = u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
        let ty = i32::from_ne_bytes(bytes[at + 12..at + 16].try_into().unwrap());
        if len < 16 || at + len > bytes.len() {
            break;
        }
        if ty == SCM_RIGHTS {
            out.extend(bytes[at + 16..at + len].as_chunks::<4>().0.iter().map(|c| i32::from_ne_bytes(*c)));
        }
        at += len.next_multiple_of(8);
    }
    Ok((n, out))
}

/// The socket calls with C's arguments, for slate-libc (ADR 0075):
/// addresses are bytes in Linux's layouts, which the native interface
/// shares, and kinds and flags are Linux's (`SOCK_*`, socket(2)), turned
/// into the native ones here.
pub mod raw {
    use slate_abi::nr;

    use crate::errno::{Errno, Result};
    use crate::sys;

    /// SOCK_NONBLOCK and SOCK_CLOEXEC (musl `sys/socket.h`, ADR 0009).
    const SOCK_NONBLOCK: i32 = 0o4000;
    const SOCK_CLOEXEC: i32 = 0o2000000;
    const SOCK_TYPE_MASK: i32 = 0xf;

    /// The native `open::*` flags for C's SOCK_* flags.
    fn native_flags(f: i32) -> Result<u32> {
        if f & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(Errno::EINVAL);
        }
        Ok(if f & SOCK_NONBLOCK != 0 { slate_abi::open::NONBLOCK } else { 0 }
            | if f & SOCK_CLOEXEC != 0 { slate_abi::open::CLOEXEC } else { 0 })
    }

    pub fn socket(family: i32, kind: i32, protocol: i32) -> Result<i32> {
        if sys::native() {
            let flags = native_flags(kind & !SOCK_TYPE_MASK)?;
            return crate::syscall!(nr::SOCKET as usize, family, kind & SOCK_TYPE_MASK, protocol, flags)
                .map(|fd| fd as i32);
        }
        crate::syscall!(sys::SOCKET, family, kind, protocol).map(|fd| fd as i32)
    }

    pub fn socketpair(family: i32, kind: i32, protocol: i32) -> Result<[i32; 2]> {
        let mut fds = [0i32; 2];
        if sys::native() {
            let flags = native_flags(kind & !SOCK_TYPE_MASK)?;
            crate::syscall!(nr::SOCKETPAIR as usize, family, kind & SOCK_TYPE_MASK, protocol, flags, fds.as_mut_ptr())?;
        } else {
            crate::syscall!(sys::SOCKETPAIR, family, kind, protocol, fds.as_mut_ptr())?;
        }
        Ok(fds)
    }

    pub fn bind(fd: i32, addr: &[u8]) -> Result<()> {
        crate::syscall!(sys::pick(sys::BIND, nr::BIND), fd, addr.as_ptr(), addr.len()).map(|_| ())
    }

    pub fn connect(fd: i32, addr: &[u8]) -> Result<()> {
        crate::syscall!(sys::pick(sys::CONNECT, nr::CONNECT), fd, addr.as_ptr(), addr.len()).map(|_| ())
    }

    pub fn listen(fd: i32, backlog: i32) -> Result<()> {
        crate::syscall!(sys::pick(sys::LISTEN, nr::LISTEN), fd, backlog).map(|_| ())
    }

    /// accept4(2): the new descriptor and the peer address's full length
    /// (what fits is in `addr`).
    pub fn accept(fd: i32, addr: &mut [u8], flags: i32) -> Result<(i32, usize)> {
        let mut len = addr.len() as u32;
        let f = if sys::native() { native_flags(flags)? as usize } else { flags as usize };
        let c = crate::syscall!(sys::pick(sys::ACCEPT4, nr::ACCEPT), fd, addr.as_mut_ptr(), &mut len as *mut u32, f)?;
        Ok((c as i32, len as usize))
    }

    pub fn send_to(fd: i32, buf: &[u8], flags: i32, addr: Option<&[u8]>) -> Result<usize> {
        let (a, l) = addr.map_or((core::ptr::null(), 0), |a| (a.as_ptr(), a.len()));
        crate::syscall!(sys::pick(sys::SENDTO, nr::SENDTO), fd, buf.as_ptr(), buf.len(), flags, a, l)
    }

    /// recvfrom(2): the bytes received and the sender's full address length.
    pub fn recv_from(fd: i32, buf: &mut [u8], flags: i32, addr: Option<&mut [u8]>) -> Result<(usize, usize)> {
        let mut len: u32 = 0;
        let (a, lp) = match addr {
            Some(a) => {
                len = a.len() as u32;
                (a.as_mut_ptr(), &mut len as *mut u32)
            }
            None => (core::ptr::null_mut(), core::ptr::null_mut()),
        };
        let n = crate::syscall!(sys::pick(sys::RECVFROM, nr::RECVFROM), fd, buf.as_mut_ptr(), buf.len(), flags, a, lp)?;
        Ok((n, len as usize))
    }

    pub fn set_opt(fd: i32, level: i32, name: i32, value: &[u8]) -> Result<()> {
        crate::syscall!(sys::pick(sys::SETSOCKOPT, nr::SETSOCKOPT), fd, level, name, value.as_ptr(), value.len())
            .map(|_| ())
    }

    /// getsockopt(2): the value's length.
    pub fn get_opt(fd: i32, level: i32, name: i32, value: &mut [u8]) -> Result<usize> {
        let mut len = value.len() as u32;
        crate::syscall!(
            sys::pick(sys::GETSOCKOPT, nr::GETSOCKOPT),
            fd,
            level,
            name,
            value.as_mut_ptr(),
            &mut len as *mut u32
        )?;
        Ok(len as usize)
    }

    /// shutdown(2); `how` is SHUT_RD 0, SHUT_WR 1, SHUT_RDWR 2, the native
    /// values too.
    pub fn shutdown(fd: i32, how: i32) -> Result<()> {
        crate::syscall!(sys::pick(sys::SHUTDOWN, nr::SHUTDOWN), fd, how).map(|_| ())
    }

    /// getsockname(2) or getpeername(2): the address's full length.
    pub fn name(fd: i32, addr: &mut [u8], peer: bool) -> Result<usize> {
        let mut len = addr.len() as u32;
        let n = if peer {
            sys::pick(sys::GETPEERNAME, nr::GETPEERNAME)
        } else {
            sys::pick(sys::GETSOCKNAME, nr::GETSOCKNAME)
        };
        crate::syscall!(n, fd, addr.as_mut_ptr(), &mut len as *mut u32)?;
        Ok(len as usize)
    }
}
