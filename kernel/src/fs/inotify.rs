// SPDX-License-Identifier: MIT OR Apache-2.0

//! inotify(7): watches on files and directories, and the events the file
//! system calls report to them.
//!
//! A watch names an inode by (device, inode number). The calls that change
//! the tree report events through [`report`] (with the parent directory and
//! the entry's name) and [`report_self`] (on the inode itself); a global
//! count of watches keeps them free when nothing is watched. Reading an
//! inotify descriptor gives `struct inotify_event { int wd; u32 mask; u32
//! cookie; u32 len; char name[]; }` records, the name NUL-padded to a
//! multiple of 4 bytes (inotify(7)).
//!
//! Event and flag values from musl's `sys/inotify.h` (ADR 0009).
//! Reported: IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE, IN_CLOSE_NOWRITE,
//! IN_OPEN, IN_MOVED_FROM/TO (with a cookie), IN_CREATE, IN_DELETE,
//! IN_DELETE_SELF, IN_MOVE_SELF, IN_IGNORED, IN_Q_OVERFLOW; IN_ACCESS and
//! IN_UNMOUNT are not (docs/GAPS.md).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use super::vfs::{Dentry, Metadata, Result};
use super::{File, O_NONBLOCK, POLLIN, poll_generation, poll_notify, poll_wait};
use crate::abi::linux::errno::{EAGAIN, EINVAL};
use crate::proc::signal::ERESTARTSYS;
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;

pub const IN_MODIFY: u32 = 0x2;
pub const IN_ATTRIB: u32 = 0x4;
pub const IN_CLOSE_WRITE: u32 = 0x8;
pub const IN_CLOSE_NOWRITE: u32 = 0x10;
pub const IN_OPEN: u32 = 0x20;
pub const IN_MOVED_FROM: u32 = 0x40;
pub const IN_MOVED_TO: u32 = 0x80;
pub const IN_CREATE: u32 = 0x100;
pub const IN_DELETE: u32 = 0x200;
pub const IN_DELETE_SELF: u32 = 0x400;
pub const IN_MOVE_SELF: u32 = 0x800;
const IN_Q_OVERFLOW: u32 = 0x4000;
const IN_IGNORED: u32 = 0x8000;
const IN_ALL_EVENTS: u32 = 0xFFF;
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;
const IN_MASK_CREATE: u32 = 0x1000_0000;
const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ISDIR: u32 = 0x4000_0000;
const IN_ONESHOT: u32 = 0x8000_0000;

/// Queued events per descriptor before IN_Q_OVERFLOW (inotify(7)'s
/// /proc/sys/fs/inotify/max_queued_events default).
const MAX_QUEUED: usize = 16384;

/// An inode, as watches name it.
pub type Key = (u64, u64);

pub fn key_of(m: &Metadata) -> Key {
    (m.dev, m.ino)
}

#[derive(Debug)]
struct Event {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

#[derive(Debug)]
struct Watch {
    wd: i32,
    key: Key,
    mask: u32,
}

/// An inotify instance.
#[derive(Debug)]
pub struct Inotify {
    watches: IrqSpinLock<Vec<Watch>>,
    queue: IrqSpinLock<VecDeque<Event>>,
    next_wd: AtomicI32,
    flags: AtomicU32,
    events: AtomicU64,
}

/// Every instance with watches.
static INSTANCES: IrqSpinLock<Vec<Weak<Inotify>>> = IrqSpinLock::new(Vec::new());
/// Watches in all instances: the hooks return at once when there are none.
static WATCHES: AtomicUsize = AtomicUsize::new(0);
static COOKIE: AtomicU32 = AtomicU32::new(1);

/// Whether anything is watched (the callers' cheap first check).
pub fn active() -> bool {
    WATCHES.load(Ordering::Relaxed) != 0
}

/// A cookie tying an IN_MOVED_FROM to its IN_MOVED_TO.
pub fn cookie() -> u32 {
    COOKIE.fetch_add(1, Ordering::Relaxed)
}

impl Inotify {
    pub fn new(flags: u32) -> Arc<Inotify> {
        Arc::new(Inotify {
            watches: IrqSpinLock::new(Vec::new()),
            queue: IrqSpinLock::new(VecDeque::new()),
            next_wd: AtomicI32::new(1),
            flags: AtomicU32::new(flags & O_NONBLOCK),
            events: AtomicU64::new(1),
        })
    }

    /// inotify_add_watch(2) on the inode `m` describes; its watch
    /// descriptor.
    pub fn add_watch(self: &Arc<Self>, m: &Metadata, mask: u32) -> Result<i32> {
        if mask & IN_ALL_EVENTS == 0 || (mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0) {
            return Err(EINVAL);
        }
        let key = key_of(m);
        let mut w = self.watches.lock();
        if let Some(existing) = w.iter_mut().find(|x| x.key == key) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(crate::abi::linux::errno::EEXIST);
            }
            existing.mask = if mask & IN_MASK_ADD != 0 { existing.mask | mask } else { mask };
            return Ok(existing.wd);
        }
        let wd = self.next_wd.fetch_add(1, Ordering::Relaxed);
        w.push(Watch { wd, key, mask });
        WATCHES.fetch_add(1, Ordering::Relaxed);
        drop(w);
        let mut all = INSTANCES.lock();
        all.retain(|i| i.strong_count() > 0);
        if !all.iter().any(|i| core::ptr::eq(i.as_ptr(), Arc::as_ptr(self))) {
            all.push(Arc::downgrade(self));
        }
        Ok(wd)
    }

    /// inotify_rm_watch(2).
    pub fn rm_watch(&self, wd: i32) -> Result<()> {
        let mut w = self.watches.lock();
        let at = w.iter().position(|x| x.wd == wd).ok_or(EINVAL)?;
        w.remove(at);
        WATCHES.fetch_sub(1, Ordering::Relaxed);
        drop(w);
        self.push(Event { wd, mask: IN_IGNORED, cookie: 0, name: String::new() });
        Ok(())
    }

    fn push(&self, e: Event) {
        let mut q = self.queue.lock();
        if q.len() >= MAX_QUEUED {
            if !q.back().is_some_and(|b| b.mask == IN_Q_OVERFLOW) {
                q.push_back(Event { wd: -1, mask: IN_Q_OVERFLOW, cookie: 0, name: String::new() });
            }
        } else if !q.back().is_some_and(|b| b.wd == e.wd && b.mask == e.mask && b.name == e.name && e.cookie == 0) {
            // Identical consecutive events coalesce (inotify(7)).
            q.push_back(e);
        }
        drop(q);
        self.events.fetch_add(1, Ordering::Relaxed);
        poll_notify();
    }

    /// Queue `mask` for watches on `key`; `self_event` for events on the
    /// watched inode itself (no name).
    fn deliver(&self, key: Key, mask: u32, cookie: u32, name: &str, self_event: bool) {
        let mut out = Vec::new();
        {
            let mut w = self.watches.lock();
            let mut gone = Vec::new();
            for watch in w.iter().filter(|x| x.key == key) {
                if watch.mask & mask & IN_ALL_EVENTS == 0 {
                    continue;
                }
                out.push(Event {
                    wd: watch.wd,
                    mask,
                    cookie,
                    name: if self_event { String::new() } else { String::from(name) },
                });
                // A deleted inode's watches end; IN_ONESHOT ones after one.
                if watch.mask & IN_ONESHOT != 0 || mask & IN_DELETE_SELF != 0 {
                    gone.push(watch.wd);
                }
            }
            if !gone.is_empty() {
                w.retain(|x| !gone.contains(&x.wd));
                WATCHES.fetch_sub(gone.len(), Ordering::Relaxed);
            }
            for wd in gone {
                out.push(Event { wd, mask: IN_IGNORED, cookie: 0, name: String::new() });
            }
        }
        for e in out {
            self.push(e);
        }
    }
}

fn instances() -> Vec<Arc<Inotify>> {
    INSTANCES.lock().iter().filter_map(Weak::upgrade).collect()
}

/// An event on `name` in directory `dir` (IN_CREATE, IN_DELETE, IN_MOVED_*,
/// IN_MODIFY of a child...); `isdir` when the entry is a directory.
pub fn report(dir: &Dentry, mask: u32, cookie: u32, name: &str, isdir: bool) {
    if !active() {
        return;
    }
    let key = key_of(&dir.metadata());
    let mask = mask | if isdir { IN_ISDIR } else { 0 };
    for i in instances() {
        i.deliver(key, mask, cookie, name, false);
    }
}

/// An event on the inode `d` itself, and the same on it as an entry of
/// its parent directory (as inotify(7) reports children's events to
/// watches on their directory).
pub fn report_self(d: &Dentry, mask: u32) {
    if !active() {
        return;
    }
    let m = d.metadata();
    let isdir = m.mode & super::vfs::S_IFMT == super::vfs::S_IFDIR;
    let flag = if isdir { IN_ISDIR } else { 0 };
    for i in instances() {
        i.deliver(key_of(&m), mask | flag, 0, "", true);
    }
    // The child events a directory watch sees (not the *_SELF ones).
    if mask & (IN_DELETE_SELF | IN_MOVE_SELF) == 0
        && let Some(parent) = &d.parent
    {
        report(parent, mask, 0, &d.name, isdir);
    }
}

impl File for Inotify {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let nonblock = self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0;
        loop {
            let seen = poll_generation();
            {
                let mut q = self.queue.lock();
                if let Some(first) = q.front() {
                    let rec = |e: &Event| if e.name.is_empty() { 16 } else { 16 + (e.name.len() + 1).div_ceil(4) * 4 };
                    if buf.len() < rec(first) {
                        return Err(EINVAL);
                    }
                    let mut n = 0;
                    while let Some(e) = q.front() {
                        let len = rec(e);
                        if n + len > buf.len() {
                            break;
                        }
                        let name_len = (len - 16) as u32;
                        buf[n..n + 4].copy_from_slice(&e.wd.to_ne_bytes());
                        buf[n + 4..n + 8].copy_from_slice(&e.mask.to_ne_bytes());
                        buf[n + 8..n + 12].copy_from_slice(&e.cookie.to_ne_bytes());
                        buf[n + 12..n + 16].copy_from_slice(&name_len.to_ne_bytes());
                        buf[n + 16..n + len].fill(0);
                        buf[n + 16..n + 16 + e.name.len()].copy_from_slice(e.name.as_bytes());
                        n += len;
                        q.pop_front();
                    }
                    return Ok(n);
                }
            }
            if nonblock {
                return Err(EAGAIN);
            }
            if poll_wait(seen, None) == WaitResult::Interrupted {
                return Err(ERESTARTSYS);
            }
        }
    }

    fn poll(&self) -> u16 {
        if self.queue.lock().is_empty() { 0 } else { POLLIN }
    }

    fn event_count(&self) -> u64 {
        self.events.load(Ordering::Relaxed)
    }

    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        // FIONREAD (ioctl_list(2)): the bytes ready to read.
        const FIONREAD: u32 = 0x541B;
        if cmd != FIONREAD {
            return Err(crate::abi::linux::errno::ENOTTY);
        }
        let n: usize = self
            .queue
            .lock()
            .iter()
            .map(|e| if e.name.is_empty() { 16 } else { 16 + (e.name.len() + 1).div_ceil(4) * 4 })
            .sum();
        crate::arch::uaccess::write_user(arg, &(n as i32)).map_err(|_| crate::abi::linux::errno::EFAULT)?;
        Ok(0)
    }

    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: 0o600, nlink: 1, ino: 2, dev: 0xFFFE, ..Default::default() })
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed) | super::O_RDONLY
    }

    fn set_status_flags(&self, flags: u32) {
        self.flags.store(flags & O_NONBLOCK, Ordering::Relaxed);
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let n = self.watches.lock().len();
        WATCHES.fetch_sub(n, Ordering::Relaxed);
    }
}

/// IN_EXCL_UNLINK is accepted (events after unlink are not reported here
/// anyway, as unlinked entries have no name in their directory).
pub const ACCEPTED_FLAGS: u32 =
    IN_ALL_EVENTS | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ONESHOT;
