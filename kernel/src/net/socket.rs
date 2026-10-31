// SPDX-License-Identifier: MIT OR Apache-2.0

//! AF_INET datagram sockets (UDP, ping, raw ICMP and send-only raw IP) as
//! files.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use alloc::vec::Vec;

use slate_net::{Endpoint, Error, Handle, IpAddr};

use super::with_stack_in;
use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLERR, POLLIN, POLLOUT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Udp,
    Ping,
    RawIcmp,
    /// IPPROTO_RAW: whole IP packets out only (raw(7)).
    RawIp,
    /// AF_INET6 IPPROTO_ICMPV6 sockets: ping and raw.
    Ping6,
    RawIcmp6,
}

/// Socket options kept for getsockopt(2), with the flags the kernel acts on
/// itself (ADR 0077). Every kind of socket has one.
#[derive(Debug, Default)]
pub struct SockOpts {
    /// SO_REUSEADDR, SO_BROADCAST, SO_DONTROUTE, IP_RECVERR and the
    /// control-message options (bits 0 to 7), IP_TOS
    /// (bits 8 to 15) and IP_MTU_DISCOVER plus one (bits 16 to 23; 0: not
    /// set, which reads back as IP_PMTUDISC_WANT), more flags (24 to 28),
    /// SO_PRIORITY (bits 32 to 39).
    bits: AtomicU64,
    /// SO_SNDTIMEO in nanoseconds, for sockets that keep it here (Unix
    /// sockets wait by it; the others' sends never block).
    pub sndtimeo_ns: AtomicU64,
}

impl SockOpts {
    pub const REUSEADDR: u64 = 1;
    pub const BROADCAST: u64 = 2;
    pub const DONTROUTE: u64 = 4;
    /// IP_RECVERR or IPV6_RECVERR (ip(7), ipv6(7)); the stack queues the
    /// errors.
    pub const RECVERR: u64 = 8;
    /// IP_PKTINFO, IP_RECVTOS, IPV6_RECVPKTINFO, IPV6_RECVTCLASS (ip(7),
    /// ipv6(7)): control messages with each datagram.
    pub const PKTINFO: u64 = 0x10;
    pub const RECVTOS: u64 = 0x20;
    pub const PKTINFO6: u64 = 0x40;
    pub const RECVTCLASS6: u64 = 0x80;
    /// SO_TIMESTAMP and SO_TIMESTAMPNS (socket(7)): each datagram's arrival
    /// time; UDP_GRO (udp(7)), kept (datagrams arrive one by one).
    pub const TIMESTAMP: u64 = 1 << 24;
    pub const TIMESTAMPNS: u64 = 1 << 25;
    pub const GRO: u64 = 1 << 26;
    /// IP_RECVTTL and IPV6_RECVHOPLIMIT (ip(7), ipv6(7)): each datagram's
    /// TTL or hop limit.
    pub const RECVTTL: u64 = 1 << 27;
    pub const RECVHOPLIMIT6: u64 = 1 << 28;
    /// IP_PMTUDISC_WANT (ip(7); musl `netinet/in.h`).
    const PMTUDISC_WANT: u8 = 1;

    pub fn flag(&self, f: u64) -> bool {
        self.bits.load(Ordering::Relaxed) & f != 0
    }

    pub fn set_flag(&self, f: u64, on: bool) {
        if on {
            self.bits.fetch_or(f, Ordering::Relaxed);
        } else {
            self.bits.fetch_and(!f, Ordering::Relaxed);
        }
    }

    fn field(&self, shift: u32) -> u8 {
        (self.bits.load(Ordering::Relaxed) >> shift) as u8
    }

    fn set_field(&self, shift: u32, v: u8) {
        let _ = self.bits.try_update(Ordering::Relaxed, Ordering::Relaxed, |b| {
            Some((b & !(0xFF << shift)) | (u64::from(v) << shift))
        });
    }

    pub fn tos(&self) -> u8 {
        self.field(8)
    }

    pub fn set_tos(&self, tos: u8) {
        self.set_field(8, tos);
    }

    /// SO_PRIORITY (socket(7)): kept and read back; Slate's interfaces
    /// have one queue each, so it orders nothing.
    pub fn priority(&self) -> u8 {
        self.field(32)
    }

    pub fn set_priority(&self, p: u8) {
        self.set_field(32, p);
    }

    pub fn pmtudisc(&self) -> u8 {
        self.field(16).checked_sub(1).unwrap_or(Self::PMTUDISC_WANT)
    }

    pub fn set_pmtudisc(&self, mode: u8) {
        self.set_field(16, mode + 1);
    }
}

pub struct InetSocket {
    pub kind: Kind,
    /// SO_REUSEADDR, SO_BROADCAST, IP_TOS... (ADR 0077).
    pub opts: SockOpts,
    /// AF_INET6.
    pub v6: bool,
    handle: Handle,
    flags: AtomicU32,
    /// SO_RCVTIMEO in nanoseconds (0: none).
    pub rcvtimeo_ns: AtomicU64,
    /// The network namespace it was created in (its stack).
    ns: Arc<crate::proc::ns::NetNs>,
    /// UDP_SEGMENT (udp(7)): sends split into datagrams of this size
    /// (0: whole).
    pub gso: AtomicU32,
}

pub fn errno(e: Error) -> Errno {
    match e {
        Error::AddrInUse => EADDRINUSE,
        Error::AddrNotAvailable => EADDRNOTAVAIL,
        Error::NetUnreachable => ENETUNREACH,
        Error::InvalidInput => EINVAL,
        Error::NotConnected => EDESTADDRREQ,
        Error::WouldBlock => EAGAIN,
        Error::MessageTooLong => EMSGSIZE,
        Error::ConnectionRefused => ECONNREFUSED,
        Error::ConnectionReset => ECONNRESET,
        Error::TimedOut => ETIMEDOUT,
        Error::BrokenPipe => EPIPE,
        Error::AlreadyConnected => EISCONN,
        Error::InProgress => EALREADY,
        Error::BadHandle => EBADF,
        Error::NoDevice => ENODEV,
        Error::Exists => EEXIST,
        Error::NotFound => ESRCH,
        Error::HostUnreachable => EHOSTUNREACH,
        Error::ProtocolUnavailable => ENOPROTOOPT,
        Error::NotPermitted => EPERM,
    }
}

/// What a received datagram turned into.
pub struct Received {
    /// Bytes copied into the buffer.
    pub copied: usize,
    /// The datagram's full length (MSG_TRUNC).
    pub len: usize,
    pub from: Endpoint,
    /// Where and how it arrived (IP_PKTINFO, IP_RECVTOS; ADR 0115).
    pub meta: slate_net::RecvMeta,
}

impl InetSocket {
    /// A socket of `kind`; `v6` for AF_INET6 (UDP; the ICMPv6 kinds are).
    pub fn new(kind: Kind, flags: u32, v6: bool) -> Arc<InetSocket> {
        let ns = super::current_ns();
        let handle = with_stack_in(ns.id, |st| {
            let h = match kind {
                Kind::Udp => st.udp_open(),
                Kind::Ping => st.icmp_open(false),
                Kind::RawIcmp => st.icmp_open(true),
                Kind::RawIp => st.raw_ip_open(),
                Kind::Ping6 => st.icmp6_open(false),
                Kind::RawIcmp6 => st.icmp6_open(true),
            };
            if v6 && kind == Kind::Udp {
                let _ = st.set_family(h, true, false);
            }
            h
        });
        Arc::new(InetSocket {
            kind,
            v6,
            handle,
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            rcvtimeo_ns: AtomicU64::new(0),
            opts: SockOpts::default(),
            ns,
            gso: AtomicU32::new(0),
        })
    }

    pub fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    pub fn bind(&self, ep: Endpoint) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.bind(self.handle, ep.0, ep.1)).map(|_| ()).map_err(errno)
    }

    /// The network namespace it belongs to (where it was made, whichever
    /// one its caller is in now).
    pub fn netns(&self) -> &Arc<crate::proc::ns::NetNs> {
        &self.ns
    }

    /// SO_BINDTODEVICE: only the interface called `name` ("": any).
    pub fn bind_device(&self, name: &str) -> Result<()> {
        if !name.is_empty() && !crate::proc::cred::current().ns_capable(&self.ns.owner, crate::proc::cred::CAP_NET_RAW)
        {
            return Err(EPERM);
        }
        let dev = if name.is_empty() { None } else { Some(super::index_of(self.ns.id, name).ok_or(ENODEV)?) };
        with_stack_in(self.ns.id, |st| st.bind_device(self.handle, dev)).map_err(errno)
    }

    /// The interface SO_BINDTODEVICE named ("" if none).
    pub fn device_name(&self) -> alloc::string::String {
        let dev = with_stack_in(self.ns.id, |st| st.device(self.handle)).ok().flatten();
        dev.and_then(|d| super::name_of(self.ns.id, d)).unwrap_or_default()
    }

    pub fn connect(&self, ep: Endpoint) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.connect(self.handle, ep)).map_err(errno)
    }

    pub fn local(&self) -> Endpoint {
        let any = if self.v6 { IpAddr::V6(slate_net::Ipv6::UNSPECIFIED) } else { IpAddr::default() };
        with_stack_in(self.ns.id, |st| st.local(self.handle)).ok().flatten().unwrap_or((any, 0))
    }

    /// IPV6_V6ONLY (before bind).
    /// IP_TOS and IP_MTU_DISCOVER, as kept in `opts`, go to the stack (the
    /// option field set there stays).
    pub fn apply_ip_options(&self) -> Result<()> {
        with_stack_in(self.ns.id, |st| {
            let options = st.ip_options(self.handle)?.options;
            let o = slate_net::IpOptions {
                tos: self.opts.tos(),
                dont_fragment: self.opts.pmtudisc() >= 2,
                options,
                ..slate_net::IpOptions::default()
            };
            st.set_ip_options(self.handle, o)
        })
        .map_err(errno)
    }

    /// IP_OPTIONS: the option field every IPv4 packet carries.
    pub fn set_option_field(&self, f: slate_net::OptionField) -> Result<()> {
        with_stack_in(self.ns.id, |st| {
            let o = st.ip_options(self.handle)?;
            st.set_ip_options(self.handle, slate_net::IpOptions { options: f, ..o })
        })
        .map_err(errno)
    }

    pub fn option_field(&self) -> Result<slate_net::OptionField> {
        with_stack_in(self.ns.id, |st| st.ip_options(self.handle)).map(|o| o.options).map_err(errno)
    }

    /// SO_DONTROUTE.
    pub fn set_dontroute(&self, on: bool) -> Result<()> {
        self.opts.set_flag(SockOpts::DONTROUTE, on);
        with_stack_in(self.ns.id, |st| st.set_dontroute(self.handle, on)).map_err(errno)
    }

    pub fn set_v6only(&self, on: bool) -> Result<()> {
        if !self.v6 {
            return Err(ENOPROTOOPT);
        }
        with_stack_in(self.ns.id, |st| st.set_family(self.handle, true, on)).map_err(errno)
    }

    pub fn v6only(&self) -> bool {
        with_stack_in(self.ns.id, |st| st.family(self.handle)).is_ok_and(|f| f.1)
    }

    /// ICMP6_FILTER.
    pub fn set_icmp6_filter(&self, blocked: [u32; 8]) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.set_icmp6_filter(self.handle, blocked)).map_err(errno)
    }

    pub fn icmp6_filter(&self) -> [u32; 8] {
        with_stack_in(self.ns.id, |st| st.icmp6_filter(self.handle)).unwrap_or([0; 8])
    }

    /// The interface link-local peers are reached on (sin6_scope_id): the
    /// bound one.
    pub fn scope(&self) -> u32 {
        with_stack_in(self.ns.id, |st| st.device(self.handle)).ok().flatten().unwrap_or(0)
    }

    /// A scope ID given with a link-local destination binds the socket to
    /// that interface, if it is not bound to one (ipv6(7)).
    pub fn use_scope(&self, scope: u32) -> Result<()> {
        if scope == 0 || self.scope() != 0 {
            return Ok(());
        }
        with_stack_in(self.ns.id, |st| st.bind_device(self.handle, Some(scope))).map_err(|_| ENODEV)
    }

    pub fn remote(&self) -> Option<Endpoint> {
        with_stack_in(self.ns.id, |st| st.remote(self.handle)).ok().flatten()
    }

    pub fn send_to(&self, data: &[u8], to: Option<Endpoint>) -> Result<usize> {
        self.send_segments(data, to, self.gso.load(Ordering::Relaxed) as usize)
    }

    /// A send split into datagrams of `segment` bytes (UDP_SEGMENT; 0:
    /// whole).
    pub fn send_segments(&self, data: &[u8], to: Option<Endpoint>, segment: usize) -> Result<usize> {
        with_stack_in(self.ns.id, |st| st.send_segments(self.handle, data, to, segment)).map_err(errno)
    }

    /// Receive one datagram into `buf`; blocks unless non-blocking (or
    /// `dontwait`). With `peek` the datagram stays queued.
    pub fn recv(&self, buf: &mut [u8], peek: bool, dontwait: bool) -> Result<Received> {
        let timeout = self.rcvtimeo_ns.load(Ordering::Relaxed);
        let deadline = (timeout != 0).then(|| crate::time::monotonic_ns() + timeout);
        loop {
            let seen = crate::fs::poll_generation();
            let r = with_stack_in(
                self.ns.id,
                |st| if peek { st.peek_meta(self.handle) } else { st.recv_meta(self.handle) },
            );
            match r {
                Ok((data, from, meta)) => {
                    let copied = data.len().min(buf.len());
                    buf[..copied].copy_from_slice(&data[..copied]);
                    return Ok(Received { copied, len: data.len(), from, meta });
                }
                Err(Error::WouldBlock) if !(self.nonblocking() || dontwait) => {
                    use crate::sched::wait::WaitResult;
                    match crate::fs::poll_wait(seen, deadline) {
                        WaitResult::Interrupted => return Err(EINTR),
                        WaitResult::TimedOut => return Err(EAGAIN),
                        WaitResult::Ready => {}
                    }
                }
                Err(e) => return Err(errno(e)),
            }
        }
    }

    /// Bytes in the next datagram (FIONREAD).
    pub fn pending(&self) -> usize {
        with_stack_in(self.ns.id, |st| st.peek_len(self.handle)).ok().flatten().unwrap_or(0)
    }

    /// IP_RECVERR (ip(7)): ICMP errors queued for MSG_ERRQUEUE.
    pub fn set_recverr(&self, on: bool) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.set_recverr(self.handle, on)).map_err(errno)
    }

    /// The oldest queued error (MSG_ERRQUEUE); never waits (EAGAIN).
    pub fn recv_error(&self, peek: bool) -> Result<slate_net::QueuedError> {
        with_stack_in(self.ns.id, |st| st.recv_error(self.handle, peek)).map_err(errno)
    }

    pub fn take_error(&self) -> i32 {
        // Reading SO_ERROR clears it; recv_from reports and clears too.
        with_stack_in(self.ns.id, |st| st.take_error(self.handle)).ok().flatten().map_or(0, |e| errno(e).0)
    }
}

impl Drop for InetSocket {
    fn drop(&mut self) {
        let h = self.handle;
        with_stack_in(self.ns.id, |st| st.close(h));
    }
}

// FIONREAD (musl `bits/ioctl.h`).
const FIONREAD: u32 = 0x541B;

impl File for InetSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.recv(buf, false, false)?.copied)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send_to(buf, None)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        match cmd {
            FIONREAD => {
                crate::arch::uaccess::write_user(arg, &(self.pending() as i32)).map_err(|_| EFAULT)?;
                Ok(0)
            }
            _ => super::ioctl::interface_ioctl(cmd, arg),
        }
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata {
            mode: S_IFSOCK | 0o777,
            nlink: 1,
            ino: super::socket_ino(false, self.handle),
            ..Default::default()
        })
    }
    fn poll(&self) -> u16 {
        let (r, w, e) = with_stack_in(self.ns.id, |st| st.readiness(self.handle)).unwrap_or((false, false, true));
        (if r { POLLIN } else { 0 }) | (if w { POLLOUT } else { 0 }) | (if e { POLLERR } else { 0 })
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}

/// Encode/decode `struct sockaddr_in` (ip(7)): family (native u16), port
/// (big-endian), address, 8 zero bytes.
pub fn sockaddr_in(ep: (slate_net::Ipv4, u16)) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
    b[2..4].copy_from_slice(&ep.1.to_be_bytes());
    b[4..8].copy_from_slice(&ep.0.0);
    b
}

pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// `struct sockaddr_in6` (ipv6(7)): family, port (big-endian), flow
/// information, address, scope ID.
pub fn sockaddr_in6(addr: slate_net::Ipv6, port: u16, scope: u32) -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[8..24].copy_from_slice(&addr.0);
    b[24..28].copy_from_slice(&scope.to_ne_bytes());
    b
}

/// An endpoint as a socket of the given family shows it: IPv4 on an IPv6
/// socket as a mapped address (ipv6(7)); link-local IPv6 with `scope`.
pub fn encode(ep: Endpoint, v6: bool, scope: u32) -> Vec<u8> {
    match ep.0 {
        IpAddr::V4(a) if !v6 => sockaddr_in((a, ep.1)).to_vec(),
        IpAddr::V4(a) => sockaddr_in6(slate_net::Ipv6::mapped(a), ep.1, 0).to_vec(),
        IpAddr::V6(a) => sockaddr_in6(a, ep.1, if a.is_link_local() { scope } else { 0 }).to_vec(),
    }
}

/// A socket address from user space for a socket of the given family:
/// (endpoint, scope ID), None for AF_UNSPEC. An IPv6 socket takes mapped
/// IPv4 addresses as IPv4.
pub fn parse_sockaddr(b: &[u8], v6: bool) -> Result<Option<(Endpoint, u32)>> {
    if b.len() < 2 {
        return Err(EINVAL);
    }
    match u16::from_ne_bytes([b[0], b[1]]) {
        AF_UNSPEC => Ok(None),
        AF_INET if !v6 && b.len() >= 8 => {
            Ok(Some(((slate_net::Ipv4([b[4], b[5], b[6], b[7]]).into(), u16::from_be_bytes([b[2], b[3]])), 0)))
        }
        AF_INET6 if v6 && b.len() >= 24 => {
            let a = slate_net::Ipv6(b[8..24].try_into().unwrap());
            let port = u16::from_be_bytes([b[2], b[3]]);
            let scope = b.get(24..28).map_or(0, |s| u32::from_ne_bytes(s.try_into().unwrap()));
            let ip = a.to_mapped_v4().map_or(IpAddr::V6(a), IpAddr::V4);
            Ok(Some(((ip, port), scope)))
        }
        AF_INET | AF_INET6 => Err(EINVAL),
        _ => Err(EAFNOSUPPORT),
    }
}
