// SPDX-License-Identifier: MIT OR Apache-2.0

//! Netlink uevent sockets (NETLINK_KOBJECT_UEVENT, netlink(7)): the kernel
//! announces devices that come and go to multicast group 1, and the device
//! manager (Slate's devd, ADR 0033) re-announces them, with what it knows
//! about them, to the groups libudev monitors listen on.
//!
//! What netlink(7) describes is what is here: `struct sockaddr_nl`
//! (family, pad, port ID, group mask), ports assigned on bind (the first
//! socket of a process gets its process ID), multicast to the groups in a
//! destination's mask (sending to groups needs CAP_NET_ADMIN), unicast to
//! a port, the sender's address with each message, SO_PASSCRED's
//! SCM_CREDENTIALS, ENOBUFS once after messages were dropped because a
//! receiver's queue was full, and socket filters (socket(7)'s
//! SO_ATTACH_FILTER, SO_DETACH_FILTER and SO_LOCK_FILTER: a classic BPF
//! program over each message decides whether it is queued and how much of
//! it; libudev attaches one, ADR 0100). The kernel's messages are the
//! "ACTION@DEVPATH" header followed by the device's NUL-separated
//! KEY=value environment (ACTION, DEVPATH, SUBSYSTEM, the device's uevent
//! file, SEQNUM), as the sysfs-rules and udev(7) documentation shows them.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use super::unix::Cred;
use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLIN, POLLOUT, poll_notify};
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;

/// The protocol number (netlink(7)).
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
const AF_NETLINK: u16 = 16;
/// The group the kernel's own announcements go to.
const KERNEL_GROUP: u32 = 1;
/// Most messages waiting for one socket before new ones are dropped.
const QUEUE: usize = 512;
/// Most bytes one message carries.
const MAX_MESSAGE: usize = 64 * 1024;

struct Message {
    data: Vec<u8>,
    /// The sender's port (0: the kernel).
    from: u32,
    /// The group it went to (0: unicast).
    group: u32,
    cred: Cred,
}

pub struct UeventSocket {
    port: AtomicU32,
    groups: AtomicU32,
    queue: IrqSpinLock<VecDeque<Message>>,
    /// Messages were dropped since the last receive.
    overrun: AtomicBool,
    pub passcred: AtomicBool,
    flags: AtomicU32,
    pub rcvtimeo_ns: AtomicU64,
    /// SO_SNDTIMEO and the other options kept for getsockopt (ADR 0077).
    pub opts: crate::net::socket::SockOpts,
    /// The socket filter, and whether SO_LOCK_FILTER fixed it.
    filter: IrqSpinLock<Option<Arc<Vec<slate_bpf::SockFilter>>>>,
    filter_locked: AtomicBool,
}

/// Every open uevent socket, for delivery.
static SOCKETS: IrqSpinLock<Vec<Weak<UeventSocket>>> = IrqSpinLock::new(Vec::new());
/// Ports handed out after a process's first socket took its process ID.
static NEXT_PORT: AtomicU32 = AtomicU32::new(0x8000_0000);
static SEQNUM: AtomicU64 = AtomicU64::new(1);

fn live() -> Vec<Arc<UeventSocket>> {
    let mut all = SOCKETS.lock();
    all.retain(|w| w.strong_count() > 0);
    all.iter().filter_map(Weak::upgrade).collect()
}

/// `struct sockaddr_nl`: family, pad, port ID, groups.
fn sockaddr(port: u32, groups: u32) -> Vec<u8> {
    let mut b = Vec::from(AF_NETLINK.to_ne_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&port.to_ne_bytes());
    b.extend_from_slice(&groups.to_ne_bytes());
    b
}

fn parse(raw: &[u8]) -> Result<(u32, u32)> {
    if raw.len() < 12 || u16::from_ne_bytes([raw[0], raw[1]]) != AF_NETLINK {
        return Err(EINVAL);
    }
    Ok((u32::from_ne_bytes(raw[4..8].try_into().unwrap()), u32::from_ne_bytes(raw[8..12].try_into().unwrap())))
}

/// What a receive produced.
pub struct Received {
    pub copied: usize,
    pub len: usize,
    pub from: Vec<u8>,
    pub cred: Option<Cred>,
}

impl UeventSocket {
    pub fn new(flags: u32) -> Arc<UeventSocket> {
        let s = Arc::new(UeventSocket {
            port: AtomicU32::new(0),
            groups: AtomicU32::new(0),
            queue: IrqSpinLock::new(VecDeque::new()),
            overrun: AtomicBool::new(false),
            passcred: AtomicBool::new(false),
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            rcvtimeo_ns: AtomicU64::new(0),
            opts: crate::net::socket::SockOpts::default(),
            filter: IrqSpinLock::new(None),
            filter_locked: AtomicBool::new(false),
        });
        SOCKETS.lock().push(Arc::downgrade(&s));
        s
    }

    /// A port of our own: the process ID if no socket has it, else a
    /// fresh one.
    fn autobind(&self) -> u32 {
        let p = self.port.load(Ordering::Relaxed);
        if p != 0 {
            return p;
        }
        let pid = crate::proc::current().map_or(0, |p| p.pid);
        let taken = |port: u32| live().iter().any(|s| s.port.load(Ordering::Relaxed) == port);
        let port = if pid != 0 && !taken(pid) {
            pid
        } else {
            loop {
                let p = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
                if p != 0 && !taken(p) {
                    break p;
                }
            }
        };
        self.port.store(port, Ordering::Relaxed);
        port
    }

    pub fn bind(&self, raw: &[u8]) -> Result<()> {
        // Anyone may listen to any group: device events are public.
        let (port, groups) = parse(raw)?;
        if port != 0 {
            let mine = self.port.load(Ordering::Relaxed);
            if mine != 0 && mine != port {
                return Err(EINVAL);
            }
            if mine == 0 && live().iter().any(|s| s.port.load(Ordering::Relaxed) == port) {
                return Err(EADDRINUSE);
            }
            self.port.store(port, Ordering::Relaxed);
        } else {
            self.autobind();
        }
        self.groups.store(groups, Ordering::Relaxed);
        Ok(())
    }

    /// NETLINK_ADD_MEMBERSHIP / NETLINK_DROP_MEMBERSHIP: group numbers
    /// from 1.
    pub fn membership(&self, group: u32, add: bool) -> Result<()> {
        if group == 0 || group > 32 {
            return Err(EINVAL);
        }
        let bit = 1 << (group - 1);
        if add {
            self.groups.fetch_or(bit, Ordering::Relaxed);
        } else {
            self.groups.fetch_and(!bit, Ordering::Relaxed);
        }
        Ok(())
    }

    pub fn address(&self) -> Vec<u8> {
        sockaddr(self.port.load(Ordering::Relaxed), self.groups.load(Ordering::Relaxed))
    }

    /// SO_ATTACH_FILTER (`Some`) or SO_DETACH_FILTER (`None`): EINVAL for
    /// a program that doesn't check, EPERM once the filter is locked, ENOENT
    /// detaching none.
    pub fn set_filter(&self, prog: Option<Vec<slate_bpf::SockFilter>>) -> Result<()> {
        if self.filter_locked.load(Ordering::Relaxed) {
            return Err(EPERM);
        }
        let mut f = self.filter.lock();
        match prog {
            Some(p) => {
                slate_bpf::check_socket_filter(&p).map_err(|_| EINVAL)?;
                *f = Some(Arc::new(p));
            }
            None => {
                f.take().ok_or(ENOENT)?;
            }
        }
        Ok(())
    }

    /// SO_LOCK_FILTER: the filter (or its absence) can no longer change.
    pub fn lock_filter(&self, on: bool) -> Result<()> {
        if !on && self.filter_locked.load(Ordering::Relaxed) {
            return Err(EPERM);
        }
        self.filter_locked.store(on, Ordering::Relaxed);
        Ok(())
    }

    pub fn filter_locked(&self) -> bool {
        self.filter_locked.load(Ordering::Relaxed)
    }

    /// Queue `m` for this socket (dropped if its queue is full), as its
    /// filter says: not at all, or its first bytes.
    fn deliver(&self, mut m: Message) {
        let filter = self.filter.lock().clone();
        if let Some(prog) = filter {
            let keep = slate_bpf::run_socket_filter(&prog, &m.data) as usize;
            if keep == 0 {
                return;
            }
            m.data.truncate(keep);
        }
        let mut q = self.queue.lock();
        if q.len() >= QUEUE {
            self.overrun.store(true, Ordering::Relaxed);
            return;
        }
        q.push_back(m);
    }

    /// Send `data` to `to` (a sockaddr_nl; none or port 0 and no groups:
    /// the kernel, which takes nothing on this protocol).
    pub fn send(&self, data: &[u8], to: Option<&[u8]>) -> Result<usize> {
        if data.len() > MAX_MESSAGE {
            return Err(EMSGSIZE);
        }
        let (port, groups) = match to {
            Some(raw) => parse(raw)?,
            None => (0, 0),
        };
        let from = self.autobind();
        let c = crate::proc::cred::current();
        let cred = Cred { pid: crate::proc::current().map_or(0, |p| p.pid as i32), uid: c.euid, gid: c.egid };
        if groups != 0 {
            if !c.capable(crate::proc::cred::CAP_NET_ADMIN) {
                return Err(EPERM);
            }
            for s in live() {
                let mask = s.groups.load(Ordering::Relaxed) & groups;
                if mask != 0 && !core::ptr::eq(&*s, self) {
                    s.deliver(Message { data: data.to_vec(), from, group: mask, cred });
                }
            }
        }
        if port != 0 {
            let target = live().into_iter().find(|s| s.port.load(Ordering::Relaxed) == port).ok_or(ECONNREFUSED)?;
            target.deliver(Message { data: data.to_vec(), from, group: 0, cred });
        }
        poll_notify();
        Ok(data.len())
    }

    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    pub fn recv(&self, buf: &mut [u8], peek: bool, dontwait: bool) -> Result<Received> {
        let timeout = self.rcvtimeo_ns.load(Ordering::Relaxed);
        let deadline = (timeout != 0).then(|| crate::time::monotonic_ns() + timeout);
        loop {
            let seen = crate::fs::poll_generation();
            if self.overrun.swap(false, Ordering::Relaxed) {
                return Err(ENOBUFS);
            }
            {
                let mut q = self.queue.lock();
                let m = if peek { q.front().map(|m| Message { data: m.data.clone(), ..*m }) } else { q.pop_front() };
                if let Some(m) = m {
                    let n = buf.len().min(m.data.len());
                    buf[..n].copy_from_slice(&m.data[..n]);
                    let cred = self.passcred.load(Ordering::Relaxed).then_some(m.cred);
                    return Ok(Received { copied: n, len: m.data.len(), from: sockaddr(m.from, m.group), cred });
                }
            }
            if dontwait || self.nonblocking() {
                return Err(EAGAIN);
            }
            match crate::fs::poll_wait(seen, deadline) {
                WaitResult::Interrupted => return Err(EINTR),
                WaitResult::TimedOut => return Err(EAGAIN),
                WaitResult::Ready => {}
            }
        }
    }
}

impl File for UeventSocket {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.recv(buf, false, false)?.copied)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        self.send(buf, None)
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFSOCK | 0o777, nlink: 1, ..Default::default() })
    }
    fn poll(&self) -> u16 {
        POLLOUT | if self.queue.lock().is_empty() && !self.overrun.load(Ordering::Relaxed) { 0 } else { POLLIN }
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}

/// The kernel announces `action` ("add", "remove", "change") for the
/// device at `devpath` (under /sys, with a leading '/') to group 1;
/// `env` is the rest of its environment (SUBSYSTEM, its uevent file's
/// lines).
pub fn announce(action: &str, devpath: &str, env: &[String]) {
    let seq = SEQNUM.fetch_add(1, Ordering::Relaxed);
    let mut data = Vec::new();
    let mut put = |s: &str| {
        data.extend_from_slice(s.as_bytes());
        data.push(0);
    };
    put(&alloc::format!("{action}@{devpath}"));
    put(&alloc::format!("ACTION={action}"));
    put(&alloc::format!("DEVPATH={devpath}"));
    for e in env {
        put(e);
    }
    put(&alloc::format!("SEQNUM={seq}"));
    let bit = 1 << (KERNEL_GROUP - 1);
    let mut any = false;
    for s in live() {
        if s.groups.load(Ordering::Relaxed) & bit != 0 {
            s.deliver(Message { data: data.clone(), from: 0, group: bit, cred: Cred::default() });
            any = true;
        }
    }
    if any {
        poll_notify();
    }
}
