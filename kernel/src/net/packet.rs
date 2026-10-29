// SPDX-License-Identifier: MIT OR Apache-2.0

//! Packet sockets (packet(7), ADR 0049) as files: whole Ethernet frames
//! (SOCK_RAW) or their payloads (SOCK_DGRAM), of one ethertype or all,
//! on one interface or every one, through the stack's packet sockets.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use slate_net::{Handle, LinkAddr, Mac};

use super::socket::errno;
use super::with_stack_in;
use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLIN, POLLOUT};
use crate::sched::wait::WaitResult;

/// AF_PACKET (packet(7); the number from musl `sys/socket.h`).
pub const AF_PACKET: u16 = 17;
/// ARPHRD_ETHER, the hardware type of every card (netdevice(7)).
const ARPHRD_ETHER: u16 = 1;

pub struct PacketSocket {
    handle: Handle,
    /// SOCK_DGRAM: payloads, with the Ethernet header built on send.
    pub cooked: bool,
    flags: AtomicU32,
    pub rcvtimeo_ns: AtomicU64,
    /// SO_SNDTIMEO and the other options kept for getsockopt (ADR 0077).
    pub opts: crate::net::socket::SockOpts,
    ns: Arc<crate::proc::ns::NetNs>,
}

/// `struct sockaddr_ll` (packet(7)): family, protocol (network order),
/// interface index, hardware type, packet type, address length, address
/// (8 bytes).
pub fn sockaddr_ll(a: &LinkAddr) -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..2].copy_from_slice(&AF_PACKET.to_ne_bytes());
    b[2..4].copy_from_slice(&a.protocol.to_be_bytes());
    b[4..8].copy_from_slice(&(a.iface as i32).to_ne_bytes());
    b[8..10].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
    b[10] = a.pkttype;
    b[11] = 6;
    b[12..18].copy_from_slice(&a.mac.0);
    b
}

pub fn parse_sockaddr_ll(b: &[u8]) -> Result<LinkAddr> {
    if b.len() < 12 || u16::from_ne_bytes([b[0], b[1]]) != AF_PACKET {
        return Err(EINVAL);
    }
    let iface = i32::from_ne_bytes(b[4..8].try_into().unwrap());
    let halen = usize::from(b[11]).min(8);
    let mut mac = Mac::default();
    if halen >= 6 && b.len() >= 18 {
        mac.0.copy_from_slice(&b[12..18]);
    }
    Ok(LinkAddr {
        iface: u32::try_from(iface).map_err(|_| EINVAL)?,
        protocol: u16::from_be_bytes([b[2], b[3]]),
        pkttype: b[10],
        mac,
    })
}

impl PacketSocket {
    /// `protocol` in host order (socket(2) passes it in network order).
    pub fn new(protocol: u16, cooked: bool, flags: u32) -> Arc<PacketSocket> {
        let ns = super::current_ns();
        let handle = with_stack_in(ns.id, |st| st.packet_open(protocol, cooked));
        Arc::new(PacketSocket {
            handle,
            cooked,
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            rcvtimeo_ns: AtomicU64::new(0),
            opts: crate::net::socket::SockOpts::default(),
            ns,
        })
    }

    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    /// bind(2) with a `sockaddr_ll`: the protocol (0 keeps it) and the
    /// interface (0: every one).
    pub fn bind(&self, raw: &[u8]) -> Result<()> {
        let a = parse_sockaddr_ll(raw)?;
        let dev = (a.iface != 0).then_some(a.iface);
        with_stack_in(self.ns.id, |st| st.packet_bind(self.handle, a.protocol, dev)).map_err(errno)
    }

    pub fn local(&self) -> LinkAddr {
        let (protocol, dev) = with_stack_in(self.ns.id, |st| st.packet_local(self.handle)).unwrap_or((0, None));
        let iface = dev.unwrap_or(0);
        let mac = with_stack_in(self.ns.id, |st| st.mac(iface)).unwrap_or_default();
        LinkAddr { iface, protocol, pkttype: 0, mac }
    }

    /// SO_ATTACH_FILTER / SO_DETACH_FILTER.
    pub fn set_filter(&self, prog: Option<Vec<slate_bpf::SockFilter>>) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.packet_filter(self.handle, prog)).map_err(errno)
    }

    pub fn send_to(&self, data: &[u8], to: Option<&[u8]>) -> Result<usize> {
        let to = to.map(parse_sockaddr_ll).transpose()?;
        with_stack_in(self.ns.id, |st| st.packet_send(self.handle, data, to)).map_err(|e| match e {
            slate_net::Error::NoDevice => ENXIO,
            slate_net::Error::NotConnected => EDESTADDRREQ,
            e => errno(e),
        })
    }

    /// One frame: (bytes copied, its length, where it came from).
    pub fn recv(&self, buf: &mut [u8], peek: bool, dontwait: bool) -> Result<(usize, usize, LinkAddr)> {
        let timeout = self.rcvtimeo_ns.load(Ordering::Relaxed);
        let deadline = (timeout != 0).then(|| crate::time::monotonic_ns() + timeout);
        loop {
            let seen = crate::fs::poll_generation();
            match with_stack_in(self.ns.id, |st| st.packet_recv(self.handle, peek)) {
                Ok((data, from)) => {
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    return Ok((n, data.len(), from));
                }
                Err(slate_net::Error::WouldBlock) if !(self.nonblocking() || dontwait) => {
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
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        let h = self.handle;
        with_stack_in(self.ns.id, |st| st.packet_close(h));
    }
}

// FIONREAD (musl `bits/ioctl.h`).
const FIONREAD: u32 = 0x541B;

impl File for PacketSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.recv(buf, false, false)?.0)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send_to(buf, None)
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        match cmd {
            FIONREAD => {
                let n = with_stack_in(self.ns.id, |st| st.packet_peek_len(self.handle)).ok().flatten().unwrap_or(0);
                crate::arch::uaccess::write_user(arg, &(n as i32)).map_err(|_| EFAULT)?;
                Ok(0)
            }
            _ => super::ioctl::interface_ioctl(cmd, arg),
        }
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFSOCK | 0o777, nlink: 1, ino: 0x20000 + self.handle as u64, ..Default::default() })
    }
    fn poll(&self) -> u16 {
        let readable = with_stack_in(self.ns.id, |st| st.packet_readable(self.handle)).unwrap_or(false);
        POLLOUT | if readable { POLLIN } else { 0 }
    }
    fn event_count(&self) -> u64 {
        with_stack_in(self.ns.id, |st| st.events)
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}
