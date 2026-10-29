// SPDX-License-Identifier: MIT OR Apache-2.0

//! TCP sockets (tcp(7)) as files, on the stack's TCP (ADR 0017).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use slate_net::{Endpoint, Error, Handle, TcpState, TcpStatus};

use super::socket::errno;
use super::with_stack_in;
use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP};
use crate::sched::wait::WaitResult;

pub struct TcpSocket {
    handle: Handle,
    /// AF_INET6.
    pub v6: bool,
    flags: AtomicU32,
    /// SO_RCVTIMEO and SO_SNDTIMEO in nanoseconds (0: none).
    pub rcvtimeo_ns: AtomicU64,
    pub sndtimeo_ns: AtomicU64,
    /// SO_PEEK_OFF (socket(7)): where the next MSG_PEEK starts; -1: off.
    pub peek_off: core::sync::atomic::AtomicI64,
    /// SO_REUSEADDR, IP_MTU_DISCOVER... for getsockopt (ADR 0077).
    pub opts: super::socket::SockOpts,
    /// The network namespace it was created in (its stack).
    ns: Arc<crate::proc::ns::NetNs>,
}

/// Largest piece handed to the stack at once.
const SEND_CHUNK: usize = 64 * 1024;

impl TcpSocket {
    pub fn new(flags: u32, v6: bool) -> Arc<TcpSocket> {
        let ns = super::current_ns();
        let h = with_stack_in(ns.id, |st| {
            let h = st.tcp_open();
            if v6 {
                let _ = st.tcp_set_family(h, true, false);
            }
            h
        });
        Self::wrap(h, flags, ns, v6)
    }

    fn wrap(handle: Handle, flags: u32, ns: Arc<crate::proc::ns::NetNs>, v6: bool) -> Arc<TcpSocket> {
        Arc::new(TcpSocket {
            ns,
            handle,
            v6,
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            rcvtimeo_ns: AtomicU64::new(0),
            sndtimeo_ns: AtomicU64::new(0),
            peek_off: core::sync::atomic::AtomicI64::new(-1),
            opts: super::socket::SockOpts::default(),
        })
    }

    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    fn status(&self) -> TcpStatus {
        with_stack_in(self.ns.id, |st| st.tcp_status(self.handle)).unwrap_or(TcpStatus {
            error: true,
            hangup: true,
            ..Default::default()
        })
    }

    /// Wait until `ready` holds for the socket's status (or a signal or
    /// timeout ends the wait).
    fn wait(&self, timeout_ns: u64, ready: impl Fn(&TcpStatus) -> bool) -> Result<()> {
        let deadline = (timeout_ns != 0).then(|| crate::time::monotonic_ns() + timeout_ns);
        loop {
            let seen = crate::fs::poll_generation();
            if ready(&self.status()) {
                return Ok(());
            }
            match crate::fs::poll_wait(seen, deadline) {
                WaitResult::Interrupted => return Err(EINTR),
                WaitResult::TimedOut => return Err(EAGAIN),
                WaitResult::Ready => {}
            }
        }
    }

    /// The network namespace it belongs to (where it was made, whichever
    /// one its caller is in now).
    pub fn netns(&self) -> &Arc<crate::proc::ns::NetNs> {
        &self.ns
    }

    pub fn bind(&self, ep: Endpoint) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.tcp_bind(self.handle, ep.0, ep.1)).map(|_| ()).map_err(errno)
    }

    pub fn listen(&self, backlog: usize) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.tcp_listen(self.handle, backlog)).map_err(errno)
    }

    pub fn accept(&self, flags: u32, nonblock_call: bool) -> Result<Arc<TcpSocket>> {
        loop {
            match with_stack_in(self.ns.id, |st| st.tcp_accept(self.handle)) {
                Ok(h) => return Ok(Self::wrap(h, flags, self.ns.clone(), self.v6)),
                Err(Error::WouldBlock) if !(self.nonblocking() || nonblock_call) => {
                    self.wait(0, |s| s.readable)?;
                }
                Err(Error::InvalidInput) => return Err(EINVAL),
                Err(e) => return Err(errno(e)),
            }
        }
    }

    pub fn connect(&self, ep: Endpoint) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.tcp_connect(self.handle, ep)).map_err(errno)?;
        if self.nonblocking() {
            return Err(EINPROGRESS);
        }
        self.wait(0, |s| s.writable || s.error || s.hangup)?;
        match with_stack_in(self.ns.id, |st| st.tcp_take_error(self.handle)) {
            Ok(Some(e)) => Err(errno(e)),
            _ => Ok(()),
        }
    }

    pub fn local(&self) -> Endpoint {
        let any = if self.v6 { slate_net::IpAddr::V6(slate_net::Ipv6::UNSPECIFIED) } else { Default::default() };
        with_stack_in(self.ns.id, |st| st.tcp_local(self.handle)).ok().flatten().unwrap_or((any, 0))
    }

    /// IPV6_V6ONLY (before bind).
    pub fn set_v6only(&self, on: bool) -> Result<()> {
        if !self.v6 {
            return Err(ENOPROTOOPT);
        }
        with_stack_in(self.ns.id, |st| st.tcp_set_family(self.handle, true, on)).map_err(errno)
    }

    pub fn v6only(&self) -> bool {
        with_stack_in(self.ns.id, |st| st.tcp_family(self.handle)).is_ok_and(|f| f.1)
    }

    pub fn remote(&self) -> Option<Endpoint> {
        with_stack_in(self.ns.id, |st| st.tcp_remote(self.handle)).ok().flatten()
    }

    /// The connection's state (TCP_INFO), if the socket still exists.
    pub fn state(&self) -> Option<TcpState> {
        with_stack_in(self.ns.id, |st| st.tcp_state(self.handle)).ok()
    }

    pub fn listening(&self) -> bool {
        with_stack_in(self.ns.id, |st| st.tcp_state(self.handle)) == Ok(TcpState::Listen)
    }

    /// Send all of `data` (a blocking socket) or what fits (non-blocking).
    pub fn send(&self, data: &[u8], dontwait: bool, nosignal: bool) -> Result<usize> {
        let mut sent = 0;
        while sent < data.len() {
            let end = (sent + SEND_CHUNK).min(data.len());
            match with_stack_in(self.ns.id, |st| st.tcp_send(self.handle, &data[sent..end])) {
                Ok(n) => sent += n,
                Err(Error::WouldBlock) => {
                    if self.nonblocking() || dontwait {
                        return if sent > 0 { Ok(sent) } else { Err(EAGAIN) };
                    }
                    match self.wait(self.sndtimeo_ns.load(Ordering::Relaxed), |s| s.writable || s.error || s.hangup) {
                        Ok(()) => {}
                        Err(_) if sent > 0 => return Ok(sent),
                        Err(e) => return Err(e),
                    }
                }
                Err(_) if sent > 0 => return Ok(sent),
                Err(e) => {
                    if matches!(e, Error::BrokenPipe | Error::ConnectionReset)
                        && !nosignal
                        && let Some(me) = crate::proc::current()
                    {
                        crate::proc::signal::send_to_process(&me, crate::proc::signal::SIGPIPE);
                    }
                    return Err(errno(e));
                }
            }
        }
        Ok(sent)
    }

    pub fn recv(&self, buf: &mut [u8], peek: bool, dontwait: bool) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // SO_PEEK_OFF (socket(7)): a peek starts at the offset and moves
            // it on; a read takes what it consumes off it.
            let off = self.peek_off.load(Ordering::Relaxed);
            let at = if peek && off > 0 { off as usize } else { 0 };
            match with_stack_in(self.ns.id, |st| st.tcp_recv_at(self.handle, buf, peek, at)) {
                Ok(n) => {
                    if off >= 0 {
                        let next = if peek { off + n as i64 } else { (off - n as i64).max(0) };
                        self.peek_off.store(next, Ordering::Relaxed);
                    }
                    return Ok(n);
                }
                Err(Error::WouldBlock) if !(self.nonblocking() || dontwait) => {
                    self.wait(self.rcvtimeo_ns.load(Ordering::Relaxed), |s| s.readable || s.hangup)?;
                }
                Err(e) => return Err(errno(e)),
            }
        }
    }

    pub fn shutdown(&self, how: u64) -> Result<()> {
        // SHUT_RD 0, SHUT_WR 1, SHUT_RDWR 2 (shutdown(2)).
        let (read, write) = match how {
            0 => (true, false),
            1 => (false, true),
            2 => (true, true),
            _ => return Err(EINVAL),
        };
        with_stack_in(self.ns.id, |st| st.tcp_shutdown(self.handle, read, write)).map_err(|e| match e {
            Error::NotConnected => ENOTCONN,
            e => errno(e),
        })
    }

    /// The socket's TCP options (tcp(7)).
    pub fn options(&self) -> Result<slate_net::TcpOptions> {
        with_stack_in(self.ns.id, |st| st.tcp_options(self.handle)).map_err(errno)
    }

    pub fn set_options(&self, o: slate_net::TcpOptions) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.tcp_set_options(self.handle, o)).map_err(errno)
    }

    /// TCP_QUICKACK.
    pub fn quickack(&self) -> Result<()> {
        with_stack_in(self.ns.id, |st| st.tcp_quickack(self.handle)).map_err(errno)
    }

    pub fn info(&self) -> Option<slate_net::TcpInfo> {
        with_stack_in(self.ns.id, |st| st.tcp_info(self.handle)).ok()
    }

    /// SO_BINDTODEVICE: only the interface called `name` ("": any).
    pub fn bind_device(&self, name: &str) -> Result<()> {
        if !name.is_empty() && !crate::proc::cred::current().ns_capable(&self.ns.owner, crate::proc::cred::CAP_NET_RAW)
        {
            return Err(EPERM);
        }
        let dev = if name.is_empty() { None } else { Some(super::index_of(self.ns.id, name).ok_or(ENODEV)?) };
        with_stack_in(self.ns.id, |st| st.tcp_bind_device(self.handle, dev)).map_err(errno)
    }

    pub fn device_name(&self) -> alloc::string::String {
        let dev = with_stack_in(self.ns.id, |st| st.tcp_device(self.handle)).ok().flatten();
        dev.and_then(|d| super::name_of(self.ns.id, d)).unwrap_or_default()
    }

    pub fn take_error(&self) -> i32 {
        with_stack_in(self.ns.id, |st| st.tcp_take_error(self.handle)).ok().flatten().map_or(0, |e| errno(e).0)
    }

    pub fn pending(&self) -> usize {
        with_stack_in(self.ns.id, |st| st.tcp_recv_pending(self.handle)).unwrap_or(0)
    }
}

impl Drop for TcpSocket {
    fn drop(&mut self) {
        let h = self.handle;
        with_stack_in(self.ns.id, |st| st.tcp_close(h));
    }
}

const FIONREAD: u32 = 0x541B;

impl File for TcpSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.recv(buf, false, false)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send(buf, false, false)
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
            ino: super::socket_ino(true, self.handle),
            ..Default::default()
        })
    }
    fn poll(&self) -> u16 {
        let s = self.status();
        let mut r = 0;
        if s.readable {
            r |= POLLIN;
        }
        if s.writable {
            r |= POLLOUT;
        }
        if s.hangup {
            r |= POLLHUP;
        }
        if s.read_hangup {
            r |= POLLRDHUP;
        }
        if s.error {
            r |= POLLERR;
        }
        r
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
