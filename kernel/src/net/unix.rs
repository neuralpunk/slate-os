// SPDX-License-Identifier: MIT OR Apache-2.0

//! AF_UNIX sockets (unix(7)): stream and datagram, named in the file
//! system or in the abstract namespace, socketpair(2), descriptor passing
//! (SCM_RIGHTS), peer credentials (SO_PEERCRED) and the sender's with
//! each message (SO_PASSCRED, SCM_CREDENTIALS).
//!
//! A connected stream pair shares two [`Channel`]s, one per direction.
//! Descriptors passed with a message are attached to the byte offset the
//! message starts at; a receive that reaches them takes them (recvmsg) or
//! drops them (read), and never reads past the next attachment.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::abi::linux::errno::*;
use crate::fs::vfs::{Metadata, Result, S_IFSOCK};
use crate::fs::{File, O_NONBLOCK, O_RDWR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, poll_notify};
use crate::sched::wait::WaitResult;
use crate::sync::IrqSpinLock;

/// Bytes buffered per direction of a stream connection, and per datagram
/// socket.
const BUFFER: usize = 256 * 1024;

/// A socket's address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address {
    Unnamed,
    /// A path, and the (device, inode) of the socket file it names.
    Path(Vec<u8>, (u64, u64)),
    /// The abstract namespace (`sun_path` starting with a NUL byte).
    Abstract(Vec<u8>),
}

impl Address {
    fn key(&self) -> Option<Key> {
        match self {
            Address::Unnamed => None,
            Address::Path(_, id) => Some(Key::Inode(*id)),
            Address::Abstract(n) => Some(Key::Abstract(n.clone())),
        }
    }

    /// `struct sockaddr_un`: family, then the path (NUL-terminated for
    /// paths, raw for abstract names); returns the bytes and their length.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::from(1u16.to_ne_bytes());
        match self {
            Address::Unnamed => {}
            Address::Path(p, _) => {
                b.extend_from_slice(p);
                b.push(0);
            }
            Address::Abstract(n) => {
                b.push(0);
                b.extend_from_slice(n);
            }
        }
        b
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Inode((u64, u64)),
    Abstract(Vec<u8>),
}

/// Bound sockets that can be connected or sent to.
static NAMES: IrqSpinLock<BTreeMap<Key, Weak<UnixSocket>>> = IrqSpinLock::new(BTreeMap::new());

/// Credentials of a process (SO_PEERCRED's `struct ucred`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Cred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

fn my_cred() -> Cred {
    let c = crate::proc::cred::current();
    Cred { pid: crate::proc::current().map_or(0, |p| p.pid as i32), uid: c.euid, gid: c.egid }
}

/// Descriptors in flight.
pub type Rights = Vec<Arc<dyn File>>;

/// A shared direction of a stream connection.
type Pipe = Arc<IrqSpinLock<Channel>>;

/// One direction of a stream connection.
#[derive(Default)]
struct Channel {
    data: VecDeque<u8>,
    /// Offset (counting every byte ever written) where attached
    /// descriptors start.
    rights: VecDeque<(u64, Rights)>,
    written: u64,
    read: u64,
    /// The writer is gone or shut down writing.
    eof: bool,
    /// The reader is gone (writes fail with EPIPE).
    reader_gone: bool,
    /// SOCK_SEQPACKET: where each queued message ends (in `written`
    /// terms), oldest first.
    marks: VecDeque<u64>,
}

struct Datagram {
    data: Vec<u8>,
    from: Address,
    rights: Rights,
    /// The sender's, when it sent it (SCM_CREDENTIALS).
    cred: Cred,
    /// When it was sent (monotonic nanoseconds; SO_TIMESTAMP).
    at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Stream,
    Dgram,
    SeqPacket,
}

enum State {
    Unconnected,
    Listening { backlog: usize, queue: VecDeque<Arc<UnixSocket>> },
    Connected { rx: Pipe, tx: Pipe, peer: Address, cred: Cred },
}

struct Inner {
    state: State,
    local: Address,
    // Datagram sockets.
    queue: VecDeque<Datagram>,
    queued: usize,
    peer: Option<Weak<UnixSocket>>,
    peer_name: Address,
    /// A listener made by a Slate-domain process, or a client's end
    /// connected to one (ADR 0098): such a server trusts the credentials
    /// the connection was made with, so the end stays out of the Linux
    /// domain.
    slate_server: bool,
}

pub struct UnixSocket {
    pub kind: Kind,
    inner: IrqSpinLock<Inner>,
    flags: AtomicU32,
    events: AtomicU64,
    pub rcvtimeo_ns: AtomicU64,
    /// SO_PASSCRED (unix(7)): each message comes with its sender's
    /// credentials (SCM_CREDENTIALS).
    pub passcred: AtomicBool,
    /// SO_SNDTIMEO and the other options kept for getsockopt (ADR 0077).
    pub opts: crate::net::socket::SockOpts,
}

fn notify(s: &UnixSocket) {
    s.events.fetch_add(1, Ordering::Relaxed);
    poll_notify();
}

/// What a receive produced.
pub struct Received {
    pub len: usize,
    /// The full datagram length (MSG_TRUNC), for datagram sockets.
    pub full: usize,
    pub from: Address,
    pub rights: Rights,
    /// Who sent it: a datagram's sender, a connection's peer (as it was
    /// when it connected).
    pub cred: Cred,
    /// When a datagram arrived (monotonic nanoseconds); None for streams.
    pub at: Option<u64>,
}

impl UnixSocket {
    pub fn new(kind: Kind, flags: u32) -> Arc<UnixSocket> {
        Arc::new(UnixSocket {
            kind,
            inner: IrqSpinLock::new(Inner {
                state: State::Unconnected,
                local: Address::Unnamed,
                queue: VecDeque::new(),
                queued: 0,
                peer: None,
                peer_name: Address::Unnamed,
                slate_server: false,
            }),
            flags: AtomicU32::new(O_RDWR | (flags & O_NONBLOCK)),
            events: AtomicU64::new(0),
            rcvtimeo_ns: AtomicU64::new(0),
            passcred: AtomicBool::new(false),
            opts: crate::net::socket::SockOpts::default(),
        })
    }

    /// socketpair(2): two connected sockets.
    pub fn pair(kind: Kind, flags: u32) -> (Arc<UnixSocket>, Arc<UnixSocket>) {
        let (a, b) = (Self::new(kind, flags), Self::new(kind, flags));
        if kind == Kind::Dgram {
            a.inner.lock().peer = Some(Arc::downgrade(&b));
            b.inner.lock().peer = Some(Arc::downgrade(&a));
        } else {
            let (ab, ba) =
                (Arc::new(IrqSpinLock::new(Channel::default())), Arc::new(IrqSpinLock::new(Channel::default())));
            let cred = my_cred();
            a.inner.lock().state = State::Connected { rx: ba.clone(), tx: ab.clone(), peer: Address::Unnamed, cred };
            b.inner.lock().state = State::Connected { rx: ab, tx: ba, peer: Address::Unnamed, cred };
        }
        (a, b)
    }

    fn nonblocking(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0
    }

    fn wait(&self, ready: impl Fn() -> bool, nonblock: bool) -> Result<()> {
        self.wait_by(&self.rcvtimeo_ns, ready, nonblock)
    }

    /// Wait for room to send, by SO_SNDTIMEO.
    fn wait_send(&self, ready: impl Fn() -> bool, nonblock: bool) -> Result<()> {
        self.wait_by(&self.opts.sndtimeo_ns, ready, nonblock)
    }

    fn wait_by(&self, timeout: &AtomicU64, ready: impl Fn() -> bool, nonblock: bool) -> Result<()> {
        let timeout = timeout.load(Ordering::Relaxed);
        let deadline = (timeout != 0).then(|| crate::time::monotonic_ns() + timeout);
        loop {
            let seen = crate::fs::poll_generation();
            if ready() {
                return Ok(());
            }
            if nonblock || self.nonblocking() {
                return Err(EAGAIN);
            }
            match crate::fs::poll_wait(seen, deadline) {
                WaitResult::Interrupted => return Err(EINTR),
                WaitResult::TimedOut => return Err(EAGAIN),
                WaitResult::Ready => {}
            }
        }
    }

    pub fn local(&self) -> Address {
        self.inner.lock().local.clone()
    }

    pub fn peer(&self) -> Result<Address> {
        let i = self.inner.lock();
        match &i.state {
            State::Connected { peer, .. } => Ok(peer.clone()),
            _ if i.peer.is_some() => Ok(i.peer_name.clone()),
            _ => Err(ENOTCONN),
        }
    }

    pub fn peer_cred(&self) -> Cred {
        match &self.inner.lock().state {
            State::Connected { cred, .. } => *cred,
            _ => Cred::default(),
        }
    }

    /// bind(2) to `addr`.
    pub fn bind(self: &Arc<Self>, addr: Address) -> Result<()> {
        let key = addr.key().ok_or(EINVAL)?;
        let mut names = NAMES.lock();
        if names.get(&key).is_some_and(|w| w.strong_count() > 0) {
            return Err(EADDRINUSE);
        }
        let mut i = self.inner.lock();
        if i.local != Address::Unnamed {
            return Err(EINVAL);
        }
        i.local = addr;
        names.insert(key, Arc::downgrade(self));
        Ok(())
    }

    pub fn listen(&self, backlog: usize) -> Result<()> {
        if self.kind == Kind::Dgram {
            return Err(EOPNOTSUPP);
        }
        let mut i = self.inner.lock();
        match i.state {
            State::Unconnected => {
                i.state = State::Listening { backlog: backlog.clamp(1, 4096), queue: VecDeque::new() };
                i.slate_server =
                    crate::proc::current().is_some_and(|p| p.domain() == crate::proc::domain::Domain::Slate);
                Ok(())
            }
            State::Listening { backlog: ref mut b, .. } => {
                *b = backlog.clamp(1, 4096);
                Ok(())
            }
            _ => Err(EINVAL),
        }
    }

    fn lookup(addr: &Address) -> Result<Arc<UnixSocket>> {
        let key = addr.key().ok_or(EINVAL)?;
        NAMES.lock().get(&key).and_then(Weak::upgrade).ok_or(ECONNREFUSED)
    }

    /// connect(2): streams join a listener's queue; datagram sockets set
    /// their default destination.
    pub fn connect(self: &Arc<Self>, addr: &Address) -> Result<()> {
        if let Address::Abstract(name) = addr {
            crate::proc::apps::may_connect_abstract(name)?;
        }
        let target = Self::lookup(addr)?;
        if target.kind != self.kind {
            return Err(EPROTOTYPE);
        }
        if self.kind == Kind::Dgram {
            let mut i = self.inner.lock();
            i.peer = Some(Arc::downgrade(&target));
            i.peer_name = addr.clone();
            return Ok(());
        }
        if !matches!(self.inner.lock().state, State::Unconnected) {
            return Err(EISCONN);
        }
        // The server's end of the new connection.
        let (up, down) =
            (Arc::new(IrqSpinLock::new(Channel::default())), Arc::new(IrqSpinLock::new(Channel::default())));
        let server = Self::new(self.kind, 0);
        let me = my_cred();
        let slate_server;
        {
            let mut t = target.inner.lock();
            slate_server = t.slate_server;
            let server_name = t.local.clone();
            let State::Listening { backlog, queue } = &mut t.state else { return Err(ECONNREFUSED) };
            if queue.len() >= *backlog {
                return Err(EAGAIN);
            }
            let mut s = server.inner.lock();
            s.local = server_name;
            s.state = State::Connected { rx: up.clone(), tx: down.clone(), peer: self.local(), cred: me };
            drop(s);
            queue.push_back(server);
        }
        {
            let mut i = self.inner.lock();
            i.state = State::Connected { rx: down, tx: up, peer: addr.clone(), cred: Cred { pid: 0, uid: 0, gid: 0 } };
            i.slate_server = slate_server;
        }
        notify(&target);
        Ok(())
    }

    pub fn accept(&self, flags: u32, nonblock: bool) -> Result<Arc<UnixSocket>> {
        let take = || {
            let mut i = self.inner.lock();
            match &mut i.state {
                State::Listening { queue, .. } => Ok(queue.pop_front()),
                _ => Err(EINVAL),
            }
        };
        loop {
            if let Some(s) = take()? {
                s.flags.store(O_RDWR | (flags & O_NONBLOCK), Ordering::Relaxed);
                return Ok(s);
            }
            self.wait(
                || matches!(&self.inner.lock().state, State::Listening { queue, .. } if !queue.is_empty()),
                nonblock,
            )?;
        }
    }

    // --- streams -------------------------------------------------------------

    fn channels(&self) -> Result<(Pipe, Pipe)> {
        match &self.inner.lock().state {
            State::Connected { rx, tx, .. } => Ok((rx.clone(), tx.clone())),
            _ => Err(ENOTCONN),
        }
    }

    /// Send on a stream: all of `data` unless non-blocking; `rights` ride
    /// with the first byte.
    fn stream_send(&self, data: &[u8], rights: Rights, nonblock: bool) -> Result<usize> {
        let (_, tx) = self.channels()?;
        let mut sent = 0;
        let mut rights = Some(rights).filter(|r| !r.is_empty());
        loop {
            {
                let mut c = tx.lock();
                if c.reader_gone || c.eof {
                    return if sent > 0 { Ok(sent) } else { Err(EPIPE) };
                }
                let room = BUFFER.saturating_sub(c.data.len());
                if room > 0 || data.is_empty() {
                    let n = room.min(data.len() - sent);
                    if let Some(r) = rights.take() {
                        let at = c.written;
                        c.rights.push_back((at, r));
                    }
                    c.data.extend(&data[sent..sent + n]);
                    c.written += n as u64;
                    sent += n;
                }
            }
            poll_notify();
            if sent == data.len() {
                return Ok(sent);
            }
            match self.wait_send(
                || {
                    let c = tx.lock();
                    c.data.len() < BUFFER || c.reader_gone
                },
                nonblock,
            ) {
                Ok(()) => {}
                Err(_) if sent > 0 => return Ok(sent),
                Err(e) => return Err(e),
            }
        }
    }

    fn stream_recv(&self, buf: &mut [u8], peek: bool, nonblock: bool) -> Result<Received> {
        let (rx, _) = self.channels()?;
        self.wait(
            || {
                let c = rx.lock();
                !c.data.is_empty() || c.eof
            },
            nonblock,
        )?;
        let mut c = rx.lock();
        // Do not read past the next attachment boundary.
        let mut limit = buf.len().min(c.data.len());
        let mut rights = Vec::new();
        let pos = c.read;
        if let Some(&(at, _)) = c.rights.front() {
            if at <= pos {
                if !peek {
                    rights = c.rights.pop_front().unwrap().1;
                }
                if let Some(&(next, _)) = c.rights.front() {
                    limit = limit.min((next - pos) as usize);
                }
            } else {
                limit = limit.min((at - pos) as usize);
            }
        }
        for (d, s) in buf.iter_mut().zip(c.data.iter()).take(limit) {
            *d = *s;
        }
        if !peek {
            c.data.drain(..limit);
            c.read += limit as u64;
        }
        drop(c);
        if !peek {
            poll_notify();
        }
        Ok(Received { len: limit, full: limit, from: Address::Unnamed, rights, cred: self.peer_cred(), at: None })
    }

    // --- datagrams -------------------------------------------------------------

    fn dgram_send(&self, data: &[u8], to: Option<&Address>, rights: Rights, nonblock: bool) -> Result<usize> {
        let target = match to {
            Some(a) => Self::lookup(a)?,
            None => self.inner.lock().peer.as_ref().and_then(Weak::upgrade).ok_or(ENOTCONN)?,
        };
        if target.kind != Kind::Dgram {
            return Err(EPROTOTYPE);
        }
        if data.len() > BUFFER {
            return Err(EMSGSIZE);
        }
        let from = self.local();
        let cred = my_cred();
        let mut rights = Some(rights);
        loop {
            {
                let mut t = target.inner.lock();
                if t.queued + data.len() <= BUFFER {
                    t.queued += data.len();
                    t.queue.push_back(Datagram {
                        data: data.to_vec(),
                        from: from.clone(),
                        rights: rights.take().unwrap(),
                        cred,
                        at: crate::time::monotonic_ns(),
                    });
                    drop(t);
                    notify(&target);
                    return Ok(data.len());
                }
            }
            self.wait_send(|| target.inner.lock().queued + data.len() <= BUFFER, nonblock)?;
        }
    }

    fn dgram_recv(&self, buf: &mut [u8], peek: bool, nonblock: bool) -> Result<Received> {
        self.wait(|| !self.inner.lock().queue.is_empty(), nonblock)?;
        let mut i = self.inner.lock();
        let d = if peek {
            let d = i.queue.front().unwrap();
            Datagram { data: d.data.clone(), from: d.from.clone(), rights: Vec::new(), cred: d.cred, at: d.at }
        } else {
            let d = i.queue.pop_front().unwrap();
            i.queued -= d.data.len();
            d
        };
        drop(i);
        let n = buf.len().min(d.data.len());
        buf[..n].copy_from_slice(&d.data[..n]);
        poll_notify();
        Ok(Received { len: n, full: d.data.len(), from: d.from, rights: d.rights, cred: d.cred, at: Some(d.at) })
    }

    // --- both ----------------------------------------------------------------

    pub fn send(&self, data: &[u8], to: Option<&Address>, rights: Rights, nonblock: bool) -> Result<usize> {
        match self.kind {
            Kind::Dgram => self.dgram_send(data, to, rights, nonblock),
            Kind::SeqPacket => self.packet_send(data, rights, nonblock),
            Kind::Stream => self.stream_send(data, rights, nonblock),
        }
    }

    pub fn recv(&self, buf: &mut [u8], peek: bool, nonblock: bool) -> Result<Received> {
        match self.kind {
            Kind::Dgram => self.dgram_recv(buf, peek, nonblock),
            Kind::SeqPacket => self.packet_recv(buf, peek, nonblock),
            Kind::Stream => self.stream_recv(buf, peek, nonblock),
        }
    }

    // --- sequenced packets ------------------------------------------------------

    /// Send one message on a SOCK_SEQPACKET connection: all of it at once
    /// (EMSGSIZE if it can never fit), its descriptors with it.
    fn packet_send(&self, data: &[u8], rights: Rights, nonblock: bool) -> Result<usize> {
        if data.len() > BUFFER {
            return Err(EMSGSIZE);
        }
        let (_, tx) = self.channels()?;
        let mut rights = Some(rights).filter(|r| !r.is_empty());
        loop {
            {
                let mut c = tx.lock();
                if c.reader_gone || c.eof {
                    return Err(EPIPE);
                }
                if c.data.len() + data.len() <= BUFFER {
                    if let Some(r) = rights.take() {
                        let at = c.written;
                        c.rights.push_back((at, r));
                    }
                    c.data.extend(data);
                    c.written += data.len() as u64;
                    let end = c.written;
                    c.marks.push_back(end);
                    break;
                }
            }
            self.wait_send(
                || {
                    let c = tx.lock();
                    c.data.len() + data.len() <= BUFFER || c.reader_gone
                },
                nonblock,
            )?;
        }
        poll_notify();
        Ok(data.len())
    }

    /// Receive one message: what fits in `buf` (the rest of it is dropped
    /// unless peeking); `full` is its whole length. 0 bytes and no message
    /// at the end of the connection.
    fn packet_recv(&self, buf: &mut [u8], peek: bool, nonblock: bool) -> Result<Received> {
        let (rx, _) = self.channels()?;
        self.wait(
            || {
                let c = rx.lock();
                !c.marks.is_empty() || c.eof
            },
            nonblock,
        )?;
        let mut c = rx.lock();
        let Some(&end) = c.marks.front() else {
            return Ok(Received {
                len: 0,
                full: 0,
                from: Address::Unnamed,
                rights: Vec::new(),
                cred: Cred::default(),
                at: None,
            });
        };
        let start = c.read;
        let full = (end - start) as usize;
        let n = buf.len().min(full);
        for (d, s) in buf.iter_mut().zip(c.data.iter()).take(n) {
            *d = *s;
        }
        let mut rights = Vec::new();
        if !peek {
            if c.rights.front().is_some_and(|&(at, _)| at >= start && at < end.max(start + 1)) {
                rights = c.rights.pop_front().unwrap().1;
            }
            c.data.drain(..full);
            c.read = end;
            c.marks.pop_front();
        }
        drop(c);
        if !peek {
            poll_notify();
        }
        Ok(Received { len: n, full, from: Address::Unnamed, rights, cred: self.peer_cred(), at: None })
    }

    pub fn shutdown(&self, read: bool, write: bool) -> Result<()> {
        let (rx, tx) = self.channels()?;
        if write {
            tx.lock().eof = true;
        }
        if read {
            rx.lock().reader_gone = true;
        }
        poll_notify();
        Ok(())
    }

    pub fn listening(&self) -> bool {
        matches!(self.inner.lock().state, State::Listening { .. })
    }

    pub fn pending(&self) -> usize {
        match &self.inner.lock().state {
            State::Connected { rx, .. } => rx.lock().data.len(),
            _ => 0,
        }
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        let mut i = self.inner.lock();
        if let State::Connected { rx, tx, .. } = &i.state {
            tx.lock().eof = true;
            rx.lock().reader_gone = true;
        }
        if let State::Listening { queue, .. } = &mut i.state {
            queue.clear();
        }
        if let Some(k) = i.local.key() {
            let mut names = NAMES.lock();
            if names.get(&k).is_some_and(|w| w.strong_count() == 0) {
                names.remove(&k);
            }
        }
        poll_notify();
    }
}

const FIONREAD: u32 = 0x541B;

impl File for UnixSocket {
    fn slate_only(&self) -> bool {
        let i = self.inner.lock();
        i.slate_server && matches!(i.state, State::Connected { .. })
    }
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // Passed descriptors reaching a plain read are dropped (unix(7)).
        Ok(self.recv(buf, false, false)?.len)
    }
    fn write(&self, buf: &[u8]) -> Result<usize> {
        let r = self.send(buf, None, Vec::new(), false);
        if r == Err(EPIPE)
            && let Some(me) = crate::proc::current()
        {
            crate::proc::signal::send_to_process(&me, crate::proc::signal::SIGPIPE);
        }
        r
    }
    fn ioctl(&self, cmd: u32, arg: u64) -> Result<u64> {
        if cmd == FIONREAD {
            crate::arch::uaccess::write_user(arg, &(self.pending() as i32)).map_err(|_| EFAULT)?;
            return Ok(0);
        }
        // Interface ioctls work on any socket (musl's if_nametoindex uses
        // an AF_UNIX one).
        super::ioctl::interface_ioctl(cmd, arg)
    }
    fn stat(&self) -> Result<Metadata> {
        Ok(Metadata { mode: S_IFSOCK | 0o777, nlink: 1, ino: self as *const Self as u64 >> 4, ..Default::default() })
    }
    fn poll(&self) -> u16 {
        let i = self.inner.lock();
        match &i.state {
            State::Listening { queue, .. } => {
                if queue.is_empty() {
                    0
                } else {
                    POLLIN
                }
            }
            State::Connected { rx, tx, .. } => {
                // One direction at a time: the peer takes them in the
                // other order.
                let (readable, eof) = {
                    let r = rx.lock();
                    (!r.data.is_empty() || !r.marks.is_empty() || r.eof, r.eof)
                };
                let (reader_gone, room) = {
                    let t = tx.lock();
                    (t.reader_gone, t.data.len() < BUFFER)
                };
                let mut m = 0;
                if readable {
                    m |= POLLIN;
                }
                if eof {
                    m |= POLLRDHUP;
                }
                // A peer that stopped reading still reports writable (the
                // write fails with EPIPE), never an error (observed Linux
                // behaviour).
                if reader_gone || room {
                    m |= POLLOUT;
                }
                if eof && reader_gone {
                    m |= POLLHUP;
                }
                m
            }
            State::Unconnected if self.kind == Kind::Dgram => (if i.queue.is_empty() { 0 } else { POLLIN }) | POLLOUT,
            State::Unconnected => POLLOUT,
        }
    }
    fn event_count(&self) -> u64 {
        crate::fs::poll_generation()
    }
    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_status_flags(&self, flags: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !O_NONBLOCK) | (flags & O_NONBLOCK), Ordering::Relaxed);
    }
}
