// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pipes (pipe(7)): a 64 KiB in-kernel buffer with a read end and a write
//! end. Reading an empty pipe blocks until data arrives or every writer is
//! gone (end of file); writing to a pipe with no readers raises SIGPIPE and
//! fails with EPIPE. Named pipes (fifo(7)) are the same buffer, shared by
//! everyone who opens the FIFO file while it is open anywhere.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

use super::vfs::{Dentry, Metadata, Result, S_IFIFO};
use super::{File, O_ACCMODE, O_NONBLOCK, O_RDONLY, O_WRONLY, POLLERR, POLLHUP, POLLIN, POLLOUT, poll_notify};
use crate::abi::linux::errno::{EAGAIN, ENXIO, EPIPE};
use crate::proc::signal::{self, ERESTARTSYS, SIGPIPE};
use crate::sched::wait::WaitQueue;
use crate::sync::IrqSpinLock;

/// Pipe capacity (pipe(7): 16 pages by default).
pub const CAPACITY: usize = 65536;
/// Writes up to this size are atomic (PIPE_BUF).
pub const PIPE_BUF: usize = 4096;

#[derive(Debug)]
struct Inner {
    buf: VecDeque<u8>,
    readers: usize,
    writers: usize,
    /// Opens of each end so far: a FIFO opened for reading waits until a
    /// writer has opened it (and the other way round).
    reader_opens: u64,
    writer_opens: u64,
}

#[derive(Debug)]
pub struct Pipe {
    inner: IrqSpinLock<Inner>,
    wq: WaitQueue,
    ino: u64,
    /// Readiness events, for edge-triggered epoll.
    events: core::sync::atomic::AtomicU64,
}

impl Pipe {
    fn event(&self) {
        self.events.fetch_add(1, Ordering::Relaxed);
        self.wq.wake_all();
        poll_notify();
    }
}

static NEXT_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// One end of a pipe (both ends for a FIFO opened O_RDWR).
#[derive(Debug)]
pub struct PipeEnd {
    pipe: Arc<Pipe>,
    read: bool,
    write: bool,
    flags: AtomicU32,
    /// The FIFO file, for a named pipe.
    dentry: Option<Arc<Dentry>>,
}

fn new_pipe(readers: usize, writers: usize) -> Arc<Pipe> {
    Arc::new(Pipe {
        inner: IrqSpinLock::new(Inner {
            buf: VecDeque::new(),
            readers,
            writers,
            reader_opens: readers as u64,
            writer_opens: writers as u64,
        }),
        wq: WaitQueue::new(),
        ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        events: core::sync::atomic::AtomicU64::new(1),
    })
}

/// Create a pipe; returns (read end, write end).
pub fn new(flags: u32) -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let pipe = new_pipe(1, 1);
    let nb = flags & O_NONBLOCK;
    (
        Arc::new(PipeEnd {
            pipe: pipe.clone(),
            read: true,
            write: false,
            flags: AtomicU32::new(O_RDONLY | nb),
            dentry: None,
        }),
        Arc::new(PipeEnd { pipe, read: false, write: true, flags: AtomicU32::new(O_WRONLY | nb), dentry: None }),
    )
}

/// The buffers of FIFOs that are open, by (device, inode).
static FIFOS: IrqSpinLock<BTreeMap<(u64, u64), Weak<Pipe>>> = IrqSpinLock::new(BTreeMap::new());

/// Open the FIFO file `dentry` (fifo(7)). Opening one end blocks until the
/// other end is opened too, except with O_NONBLOCK: a reader then opens at
/// once, and a writer fails with ENXIO if there is no reader. O_RDWR never
/// blocks.
pub fn open_fifo(dentry: Arc<Dentry>, flags: u32) -> Result<Arc<dyn File>> {
    let meta = dentry.metadata();
    let pipe = {
        let mut fifos = FIFOS.lock();
        fifos.retain(|_, p| p.strong_count() > 0);
        match fifos.get(&(meta.dev, meta.ino)).and_then(Weak::upgrade) {
            Some(p) => p,
            None => {
                let p = new_pipe(0, 0);
                fifos.insert((meta.dev, meta.ino), Arc::downgrade(&p));
                p
            }
        }
    };
    let (read, write) = match flags & O_ACCMODE {
        O_RDONLY => (true, false),
        O_WRONLY => (false, true),
        _ => (true, true),
    };
    let nonblock = flags & O_NONBLOCK != 0;
    let seen = {
        let mut i = pipe.inner.lock();
        if write && !read && nonblock && i.readers == 0 {
            return Err(ENXIO);
        }
        if read {
            i.readers += 1;
            i.reader_opens += 1;
        }
        if write {
            i.writers += 1;
            i.writer_opens += 1;
        }
        (i.reader_opens, i.writer_opens)
    };
    pipe.event();
    let end = Arc::new(PipeEnd {
        pipe: pipe.clone(),
        read,
        write,
        flags: AtomicU32::new(flags & (O_ACCMODE | O_NONBLOCK)),
        dentry: Some(dentry),
    });
    // Wait for the other side; dropping `end` undoes the open if a signal
    // interrupts the wait.
    if read != write && !nonblock {
        let interrupted = pipe.wq.wait_until_interruptible(|| {
            let i = pipe.inner.lock();
            if read { i.writers > 0 || i.writer_opens > seen.1 } else { i.readers > 0 || i.reader_opens > seen.0 }
        });
        if interrupted {
            return Err(ERESTARTSYS);
        }
    }
    Ok(end)
}

impl PipeEnd {
    fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }
}

impl File for PipeEnd {
    /// FIONREAD (pipe(7)): the bytes waiting to be read.
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if cmd != crate::abi::linux::ioctl::FIONREAD {
            return Err(crate::abi::linux::errno::ENOTTY);
        }
        let n = self.pipe.inner.lock().buf.len() as i32;
        crate::arch::uaccess::write_user(arg, &n).map_err(|_| crate::abi::linux::errno::EFAULT)?;
        Ok(0)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.read {
            return Err(crate::abi::linux::errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let p = &self.pipe;
        loop {
            {
                let mut i = p.inner.lock();
                if !i.buf.is_empty() {
                    let n = buf.len().min(i.buf.len());
                    for (dst, src) in buf.iter_mut().zip(i.buf.drain(..n)) {
                        *dst = src;
                    }
                    drop(i);
                    p.event();
                    return Ok(n);
                }
                if i.writers == 0 {
                    return Ok(0);
                }
            }
            if self.nonblock() {
                return Err(EAGAIN);
            }
            let interrupted = p.wq.wait_until_interruptible(|| {
                let i = p.inner.lock();
                !i.buf.is_empty() || i.writers == 0
            });
            if interrupted {
                return Err(ERESTARTSYS);
            }
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.write {
            return Err(crate::abi::linux::errno::EBADF);
        }
        let p = &self.pipe;
        let mut done = 0;
        while done < buf.len() {
            {
                let mut i = p.inner.lock();
                if i.readers == 0 {
                    drop(i);
                    if let Some(me) = crate::proc::current() {
                        signal::send_to_process(&me, SIGPIPE);
                    }
                    return if done > 0 { Ok(done) } else { Err(EPIPE) };
                }
                let space = CAPACITY - i.buf.len();
                let left = buf.len() - done;
                // Small writes go in whole or not at all (atomicity).
                if space > 0 && (left > PIPE_BUF || space >= left) {
                    let n = space.min(left);
                    i.buf.extend(&buf[done..done + n]);
                    done += n;
                    drop(i);
                    p.event();
                    continue;
                }
            }
            if self.nonblock() {
                return if done > 0 { Ok(done) } else { Err(EAGAIN) };
            }
            let interrupted = p.wq.wait_until_interruptible(|| {
                let i = p.inner.lock();
                i.readers == 0 || CAPACITY - i.buf.len() >= (buf.len() - done).min(PIPE_BUF)
            });
            if interrupted {
                return if done > 0 { Ok(done) } else { Err(ERESTARTSYS) };
            }
        }
        Ok(done)
    }

    fn stat(&self) -> Result<Metadata> {
        if let Some(d) = &self.dentry {
            return Ok(d.metadata());
        }
        Ok(Metadata { mode: S_IFIFO | 0o600, nlink: 1, ino: self.pipe.ino, dev: 0xFFFF, ..Default::default() })
    }

    fn dentry(&self) -> Option<Arc<Dentry>> {
        self.dentry.clone()
    }

    fn poll(&self) -> u16 {
        let i = self.pipe.inner.lock();
        let mut r = 0;
        if self.write {
            if i.readers == 0 {
                r |= POLLERR;
            } else if i.buf.len() < CAPACITY {
                r |= POLLOUT;
            }
        }
        if self.read {
            if !i.buf.is_empty() {
                r |= POLLIN;
            }
            // A FIFO nobody has written to yet is not hung up.
            if i.writers == 0 && i.writer_opens > 0 {
                r |= POLLHUP;
            }
        }
        r
    }

    fn event_count(&self) -> u64 {
        self.pipe.events.load(Ordering::Relaxed)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        {
            let mut i = self.pipe.inner.lock();
            if self.write {
                i.writers -= 1;
            }
            if self.read {
                i.readers -= 1;
            }
        }
        self.pipe.event();
    }
}
