// SPDX-License-Identifier: MIT OR Apache-2.0

//! /dev/net/tun in tap mode (ADR 0028): TUNSETIFF gives the caller's
//! network namespace an Ethernet interface whose other end is the file.
//! Frames the namespace's stack sends are read from it, frames written to
//! it are what the stack receives. This is how pasta and slirp4netns
//! connect a container's namespace to the outside. A tap is an interface
//! like the others (link.rs): it can move, or be a bridge's port. Without
//! IFF_NO_PI each frame comes with `struct tun_pi` (flags, then the
//! ethertype, as the tuntap documentation lays it out). A persistent tap
//! (TUNSETPERSIST) stays when its file is closed, and TUNSETIFF of its name
//! takes it up again; `ip link del` removes one. TUN (layer 3) mode isn't
//! supported.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::abi::linux::errno::*;
use crate::arch::uaccess::{copy_from_user, copy_to_user};
use crate::fs::vfs::{Metadata, Result, S_IFCHR};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLIN, POLLOUT};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

// tun ioctls and flags (the requests are _IOW('T', 202, int) and
// _IOR('T', 210, unsigned int); flag values from musl's `net/if.h` and the
// tuntap documentation's examples).
const TUNSETIFF: u32 = 0x4004_54ca;
const TUNGETIFF: u32 = 0x8004_54d2;
const TUNSETPERSIST: u32 = 0x4004_54cb;
const TUNSETOFFLOAD: u32 = 0x4004_54d0;
const TUNGETFEATURES: u32 = 0x8004_54cf;
const IFF_TUN: u16 = 0x0001;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;
/// Frames waiting to be read before new ones are dropped.
const QUEUE: usize = 1024;

/// A tap interface's file side.
pub struct Tap {
    rx: IrqSpinLock<VecDeque<Vec<u8>>>,
    waiters: WaitQueue,
    events: AtomicU64,
    /// IFF_UP, set with netlink or SIOCSIFFLAGS.
    pub up: AtomicBool,
    /// Frames come and go with `struct tun_pi` (IFF_NO_PI not given).
    pi: AtomicBool,
    /// It stays when its file is closed (TUNSETPERSIST).
    persist: AtomicBool,
    /// A file has it now.
    attached: AtomicBool,
}

impl Tap {
    /// Frames the stack sent: queue them for the reader.
    pub fn queue(&self, frames: Vec<Vec<u8>>) {
        if !self.up.load(Ordering::Acquire) || frames.is_empty() {
            return;
        }
        {
            let mut q = self.rx.lock();
            for f in frames {
                if q.len() < QUEUE {
                    q.push_back(f);
                }
            }
        }
        self.events.fetch_add(1, Ordering::Release);
        self.waiters.wake_all();
        crate::fs::poll_notify();
    }
}

/// An open /dev/net/tun, and the interface it made.
pub struct TunFile {
    tap: IrqSpinLock<Option<(Arc<Tap>, Arc<super::link::Link>)>>,
    flags: AtomicU32,
}

pub fn open(flags: u32) -> Result<Arc<dyn File>> {
    Ok(Arc::new(TunFile { tap: IrqSpinLock::new(None), flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)) }))
}

impl TunFile {
    fn tap(&self) -> Result<(Arc<Tap>, Arc<super::link::Link>)> {
        self.tap.lock().clone().ok_or(EBADFD)
    }

    fn set_iff(&self, arg: u64) -> Result<u64> {
        // struct ifreq: the name (16 bytes), then ifr_flags.
        let mut req = [0u8; 18];
        copy_from_user(&mut req, arg).map_err(|_| EFAULT)?;
        let flags = u16::from_ne_bytes([req[16], req[17]]);
        if flags & IFF_TUN != 0 || flags & IFF_TAP == 0 {
            return Err(EINVAL);
        }
        let pi = flags & IFF_NO_PI == 0;
        if self.tap.lock().is_some() {
            return Err(EBUSY);
        }
        let ns = super::current_ns();
        if !crate::proc::cred::current().ns_capable(&ns.owner, crate::proc::cred::CAP_NET_ADMIN) {
            return Err(EPERM);
        }
        let end = req[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let mut name = String::from(core::str::from_utf8(&req[..end]).map_err(|_| EINVAL)?);
        if name.is_empty() {
            name = String::from("tap%d");
        }
        // A tap of that name with no file: take it up (a persistent one).
        if let Some(l) = super::link::by_name(ns.id, &name)
            && let super::link::Kind::Tap(t) = &l.kind
            && !t.attached.swap(true, Ordering::AcqRel)
        {
            t.pi.store(pi, Ordering::Release);
            let tap = t.clone();
            *self.tap.lock() = Some((tap, l.clone()));
            return self.answer(arg, &name);
        }
        let tap = Arc::new(Tap {
            rx: IrqSpinLock::new(VecDeque::new()),
            waiters: WaitQueue::new(),
            events: AtomicU64::new(0),
            up: AtomicBool::new(false),
            pi: AtomicBool::new(pi),
            persist: AtomicBool::new(false),
            attached: AtomicBool::new(true),
        });
        let link = super::link::create(
            super::link::Kind::Tap(tap.clone()),
            ns.id,
            &name,
            super::link::random_mac(),
            1500,
            false,
        )
        .map_err(|e| if e == EEXIST { EBUSY } else { e })?;
        let name = link.name();
        *self.tap.lock() = Some((tap, link));
        self.answer(arg, &name)
    }

    /// The name the interface got goes back to the caller.
    fn answer(&self, arg: u64, name: &str) -> Result<u64> {
        let mut out = [0u8; 16];
        out[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
        copy_to_user(arg, &out).map_err(|_| EFAULT)?;
        Ok(0)
    }
}

impl File for TunFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let (tap, _) = self.tap()?;
        loop {
            if let Some(f) = tap.rx.lock().pop_front() {
                // struct tun_pi: flags (TUN_PKT_STRIP 1 if cut short), then
                // the frame's ethertype.
                let mut f = f;
                if tap.pi.load(Ordering::Acquire) {
                    let strip: u16 = if buf.len() < f.len() + 4 { 1 } else { 0 };
                    let mut pi = alloc::vec::Vec::with_capacity(f.len() + 4);
                    pi.extend_from_slice(&strip.to_ne_bytes());
                    pi.extend_from_slice(f.get(12..14).unwrap_or(&[0, 0]));
                    pi.extend_from_slice(&f);
                    f = pi;
                }
                let n = buf.len().min(f.len());
                buf[..n].copy_from_slice(&f[..n]);
                return Ok(n);
            }
            if self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if tap.waiters.wait_until_interruptible(|| !tap.rx.lock().is_empty()) {
                return Err(EINTR);
            }
        }
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let (tap, link) = self.tap()?;
        let frame = if tap.pi.load(Ordering::Acquire) { buf.get(4..).ok_or(EINVAL)? } else { buf };
        if frame.len() < 14 {
            return Err(EINVAL);
        }
        super::link::input(&link, alloc::vec![frame.to_vec()]);
        Ok(buf.len())
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        match cmd {
            TUNSETIFF => self.set_iff(arg),
            TUNGETIFF => {
                let (tap, link) = self.tap()?;
                let name = link.name();
                let mut out = [0u8; 18];
                out[..name.len().min(15)].copy_from_slice(&name.as_bytes()[..name.len().min(15)]);
                let pi = if tap.pi.load(Ordering::Acquire) { 0 } else { IFF_NO_PI };
                out[16..].copy_from_slice(&(IFF_TAP | pi).to_ne_bytes());
                copy_to_user(arg, &out).map_err(|_| EFAULT)?;
                Ok(0)
            }
            TUNGETFEATURES => {
                crate::arch::uaccess::write_user(arg, &u32::from(IFF_TAP | IFF_NO_PI)).map_err(|_| EFAULT)?;
                Ok(0)
            }
            // The interface stays after close (the argument is the value).
            TUNSETPERSIST => {
                self.tap()?.0.persist.store(arg != 0, Ordering::Release);
                Ok(0)
            }
            // Offloads: accepted, nothing done.
            TUNSETOFFLOAD => Ok(0),
            _ => super::ioctl::interface_ioctl(cmd, arg),
        }
    }
    fn poll(&self) -> u16 {
        match self.tap.lock().as_ref() {
            Some((t, _)) if !t.rx.lock().is_empty() => POLLIN | POLLOUT,
            _ => POLLOUT,
        }
    }
    fn event_count(&self) -> u64 {
        self.tap.lock().as_ref().map_or(0, |(t, _)| t.events.load(Ordering::Acquire))
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFCHR | 0o666, nlink: 1, ..Default::default() })
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}

impl Drop for TunFile {
    fn drop(&mut self) {
        let tap = self.tap.lock().take();
        if let Some((t, link)) = tap {
            t.attached.store(false, Ordering::Release);
            if !t.persist.load(Ordering::Acquire) {
                super::link::close_tap(&link);
            }
        }
    }
}
