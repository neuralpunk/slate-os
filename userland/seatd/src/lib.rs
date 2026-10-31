// SPDX-License-Identifier: MIT OR Apache-2.0

//! seatd (ADR 0033, ADR 0012: ours): Slate's seat daemon. A compositor
//! asks it, through libseat's `seatd` backend, for the seat and for the
//! devices it needs (DRM cards, input event nodes); seatd opens them and
//! passes the descriptors over its socket, `/run/seatd.sock`. Only the
//! active session gets devices; when it closes the seat or goes away, its
//! input devices are revoked (EVIOCREVOKE) and its DRM master dropped,
//! and the next waiting session becomes active.
//!
//! The protocol's message layouts are interface facts from seatd's
//! `include/protocol.h` (MIT license, seatd 0.9.1; no code taken): a
//! header of a 16-bit opcode and a 16-bit body size, then the body;
//! client requests 1-7 and server events 1-9 and 0x7FFF with bit 15
//! set; error codes are errno values. Slate offers one seat, `seat0`.
//!
//! Sessions (ADR 0185) are virtual consoles: a client's is the VT of its
//! controlling terminal (the VT in front if it has none). seatd takes the
//! VTs of its clients in VT_PROCESS mode, KD_GRAPHICS and K_OFF
//! (console_ioctl(2)). A switch, asked for with SWITCH_SESSION or with
//! Alt+Fn on a text console, comes as the kernel's release signal
//! (SIGUSR1): the client in front is sent DISABLE_SEAT, and once it
//! answers with DISABLE_SEAT (or after 2 s) its input devices are revoked
//! and its DRM master dropped, and the VT is let go (VT_RELDISP). The
//! acquire signal (SIGUSR2) gives the client of the new VT its cards'
//! master back and ENABLE_SEAT; it opens its input devices again. A VT
//! whose last client goes is given back to the console (VT_AUTO,
//! KD_TEXT). SWITCH_SESSION and DISABLE_SEAT have no reply.
//!
//! Who may use the seat: root and the members of the `seat` group.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use slate_login::db;
use slate_rt::errno::Errno;
use slate_rt::{eprintln, fs, io, net, process};

pub const SOCKET: &[u8] = b"/run/seatd.sock";
pub const SEAT_NAME: &[u8] = b"seat0";

// Opcodes (seatd's protocol.h).
pub const CLIENT_OPEN_SEAT: u16 = 1;
pub const CLIENT_CLOSE_SEAT: u16 = 2;
pub const CLIENT_OPEN_DEVICE: u16 = 3;
pub const CLIENT_CLOSE_DEVICE: u16 = 4;
pub const CLIENT_DISABLE_SEAT: u16 = 5;
pub const CLIENT_SWITCH_SESSION: u16 = 6;
pub const CLIENT_PING: u16 = 7;
const SERVER: u16 = 1 << 15;
pub const SERVER_SEAT_OPENED: u16 = SERVER + 1;
pub const SERVER_SEAT_CLOSED: u16 = SERVER + 2;
pub const SERVER_DEVICE_OPENED: u16 = SERVER + 3;
pub const SERVER_DEVICE_CLOSED: u16 = SERVER + 4;
pub const SERVER_DISABLE_SEAT: u16 = SERVER + 5;
pub const SERVER_ENABLE_SEAT: u16 = SERVER + 6;
pub const SERVER_PONG: u16 = SERVER + 7;
pub const SERVER_ERROR: u16 = SERVER + 0x7FFF;
/// MAX_PATH_LEN: the longest device path, NUL included.
const MAX_PATH: usize = 256;

/// EVIOCREVOKE, `_IOW('E', 0x91, int)` (input.h numbers, ADR 0033).
const EVIOCREVOKE: u32 = 0x4004_4591;
/// DRM_IOCTL_SET_MASTER and DRM_IOCTL_DROP_MASTER, `_IO('d', 0x1e/0x1f)`
/// (libdrm drm.h).
const DRM_SET_MASTER: u32 = 0x641e;
const DRM_DROP_MASTER: u32 = 0x641f;

// console_ioctl(2) (ADR 0185).
const KDSETMODE: u32 = 0x4B3A;
const KDSKBMODE: u32 = 0x4B45;
const KD_TEXT: u64 = 0x00;
const KD_GRAPHICS: u64 = 0x01;
const K_UNICODE: u64 = 0x03;
const K_OFF: u64 = 0x04;
const VT_SETMODE: u32 = 0x5602;
const VT_GETSTATE: u32 = 0x5603;
const VT_RELDISP: u32 = 0x5605;
const VT_ACTIVATE: u32 = 0x5606;
const VT_AUTO: u8 = 0x00;
const VT_PROCESS: u8 = 0x01;
const VT_ACKACQ: usize = 0x02;
/// The signals the kernel sends: release and acquire.
const RELEASE: i32 = slate_rt::signal::SIGUSR1;
const ACQUIRE: i32 = slate_rt::signal::SIGUSR2;
/// How long a client has to acknowledge DISABLE_SEAT.
const DISABLE_GRACE_NS: u64 = 2_000_000_000;

/// The VT a process's controlling terminal is, from /proc/PID/stat's
/// `tty_nr` (proc(5): the minor in bits 31-20 and 7-0, the major in
/// 15-8): /dev/ttyN (4:N) is VT N, /dev/console (5:1) VT 1.
pub fn vt_of_stat(stat: &[u8]) -> Option<u32> {
    let close = stat.iter().rposition(|&c| c == b')')?;
    let fields: Vec<&[u8]> = stat[close + 1..].split(|&c| c == b' ').filter(|f| !f.is_empty()).collect();
    // After the name: state, ppid, pgrp, session, tty_nr.
    let nr: u32 = core::str::from_utf8(fields.get(4)?).ok()?.parse::<i64>().ok()? as u32;
    let major = (nr >> 8) & 0xFFF;
    let minor = (nr & 0xFF) | ((nr >> 12) & 0xF_FF00);
    match (major, minor) {
        (4, n @ 1..=63) => Some(n),
        (5, 1) => Some(1),
        _ => None,
    }
}

/// A client's request.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    OpenSeat,
    CloseSeat,
    OpenDevice(Vec<u8>),
    CloseDevice(i32),
    DisableSeat,
    SwitchSession(i32),
    Ping,
}

/// A malformed request: the client is disconnected.
#[derive(Debug, PartialEq, Eq)]
pub struct Malformed;

/// The first request in `buf` and the bytes it took; `Ok(None)` while it
/// is incomplete.
pub fn parse(buf: &[u8]) -> Result<Option<(Request, usize)>, Malformed> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let op = u16::from_ne_bytes([buf[0], buf[1]]);
    let size = usize::from(u16::from_ne_bytes([buf[2], buf[3]]));
    if size > 2 + MAX_PATH {
        return Err(Malformed);
    }
    if buf.len() < 4 + size {
        return Ok(None);
    }
    let body = &buf[4..4 + size];
    let int = || body.try_into().map(i32::from_ne_bytes).map_err(|_| Malformed);
    let empty = || if size == 0 { Ok(()) } else { Err(Malformed) };
    let r = match op {
        CLIENT_OPEN_SEAT => empty().map(|_| Request::OpenSeat)?,
        CLIENT_CLOSE_SEAT => empty().map(|_| Request::CloseSeat)?,
        CLIENT_DISABLE_SEAT => empty().map(|_| Request::DisableSeat)?,
        CLIENT_PING => empty().map(|_| Request::Ping)?,
        CLIENT_CLOSE_DEVICE => Request::CloseDevice(int()?),
        CLIENT_SWITCH_SESSION => Request::SwitchSession(int()?),
        CLIENT_OPEN_DEVICE => {
            let len =
                usize::from(u16::from_ne_bytes([*body.first().ok_or(Malformed)?, *body.get(1).ok_or(Malformed)?]));
            let path = &body[2..];
            if len != path.len() || len == 0 || path[len - 1] != 0 || path[..len - 1].contains(&0) {
                return Err(Malformed);
            }
            Request::OpenDevice(path[..len - 1].to_vec())
        }
        _ => return Err(Malformed),
    };
    Ok(Some((r, 4 + size)))
}

/// A server message: header and body.
pub fn message(op: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(4 + body.len());
    m.extend_from_slice(&op.to_ne_bytes());
    m.extend_from_slice(&(body.len() as u16).to_ne_bytes());
    m.extend_from_slice(body);
    m
}

pub fn seat_opened() -> Vec<u8> {
    let mut body = Vec::from(((SEAT_NAME.len() + 1) as u16).to_ne_bytes());
    body.extend_from_slice(SEAT_NAME);
    body.push(0);
    message(SERVER_SEAT_OPENED, &body)
}

pub fn error(code: i32) -> Vec<u8> {
    message(SERVER_ERROR, &code.to_ne_bytes())
}

/// What a session may open: DRM cards and input event nodes.
pub fn allowed_device(path: &[u8]) -> Option<bool> {
    let ok_name = |name: &[u8], prefix: &[u8]| {
        name.strip_prefix(prefix).is_some_and(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit))
    };
    if let Some(name) = path.strip_prefix(b"/dev/dri/")
        && ok_name(name, b"card")
    {
        return Some(true);
    }
    if let Some(name) = path.strip_prefix(b"/dev/input/")
        && ok_name(name, b"event")
    {
        return Some(false);
    }
    None
}

struct Device {
    id: i32,
    fd: i32,
    drm: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Has not opened the seat.
    Idle,
    /// Opened it; waits its turn (the number orders the waiters) and its
    /// VT.
    Waiting(u64),
    Active,
    /// Sent DISABLE_SEAT; waits for the acknowledgement until the time
    /// given (monotonic ns), keeping its turn.
    Disabling(u64, u64),
}

struct Client {
    fd: i32,
    buf: Vec<u8>,
    state: State,
    devices: Vec<Device>,
    next_id: i32,
    /// Its session: a virtual console (0 until it opens the seat).
    vt: u32,
}

/// Take a device back: revoke an input device for every holder, drop DRM
/// master, close our descriptor.
fn revoke(d: &Device) {
    if d.drm {
        let _ = io::ioctl(d.fd, DRM_DROP_MASTER, 0);
    } else {
        let _ = io::ioctl(d.fd, EVIOCREVOKE, 0);
    }
    let _ = io::close(d.fd);
}

/// `struct vt_mode` (console_ioctl(2)).
fn vt_mode(mode: u8, relsig: i32, acqsig: i32) -> [u8; 8] {
    let mut m = [0u8; 8];
    m[0] = mode;
    m[2..4].copy_from_slice(&(relsig as i16).to_ne_bytes());
    m[4..6].copy_from_slice(&(acqsig as i16).to_ne_bytes());
    m
}

struct Seat {
    clients: Vec<Client>,
    turn: u64,
    /// /dev/tty0, for VT_GETSTATE and VT_ACTIVATE (none without VTs).
    tty0: Option<i32>,
    /// The VTs seatd holds (VT_PROCESS), with their descriptors.
    vts: Vec<(u32, i32)>,
    /// The VT in front.
    front: u32,
    /// The kernel waits for seatd to let the VT in front go.
    releasing: bool,
}

impl Seat {
    fn send(&self, i: usize, m: &[u8]) {
        let _ = io::write_all(self.clients[i].fd, m);
    }

    fn release(&mut self, i: usize) {
        for d in self.clients[i].devices.drain(..) {
            revoke(&d);
        }
    }

    /// The VT in front, as the kernel says.
    fn read_front(&mut self) {
        if let Some(t) = self.tty0 {
            let mut st = [0u16; 3];
            if io::ioctl(t, VT_GETSTATE, st.as_mut_ptr() as usize).is_ok() {
                self.front = u32::from(st[0]);
            }
        }
    }

    /// Take VT `vt` for seatd's clients: VT_PROCESS with seatd's signals,
    /// graphics, no console keyboard.
    fn hold_vt(&mut self, vt: u32) {
        if self.tty0.is_none() || self.vts.iter().any(|(v, _)| *v == vt) {
            return;
        }
        let path = alloc::format!("/dev/tty{vt}");
        let Ok(fd) = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CLOEXEC | fs::O_NOCTTY, 0) else { return };
        let mode = vt_mode(VT_PROCESS, RELEASE, ACQUIRE);
        let _ = io::ioctl(fd, VT_SETMODE, mode.as_ptr() as usize);
        let _ = io::ioctl(fd, KDSETMODE, KD_GRAPHICS as usize);
        let _ = io::ioctl(fd, KDSKBMODE, K_OFF as usize);
        self.vts.push((vt, fd));
    }

    /// Give VT `vt` back to the console once no client is on it.
    fn let_vt_go(&mut self, vt: u32) {
        if self.clients.iter().any(|c| c.vt == vt && c.state != State::Idle) {
            return;
        }
        let Some(k) = self.vts.iter().position(|(v, _)| *v == vt) else { return };
        let (_, fd) = self.vts.remove(k);
        let _ = io::ioctl(fd, KDSKBMODE, K_UNICODE as usize);
        let _ = io::ioctl(fd, KDSETMODE, KD_TEXT as usize);
        // Back to VT_AUTO: a switch the kernel was waiting on goes ahead.
        let mode = vt_mode(VT_AUTO, 0, 0);
        let _ = io::ioctl(fd, VT_SETMODE, mode.as_ptr() as usize);
        let _ = io::close(fd);
        if vt == self.front {
            self.releasing = false;
        }
    }

    fn vt_fd(&self, vt: u32) -> Option<i32> {
        self.vts.iter().find(|(v, _)| *v == vt).map(|(_, fd)| *fd)
    }

    /// Make the longest-waiting session on the VT in front active if none
    /// is (and no switch is under way).
    fn activate_next(&mut self) {
        if self.releasing || self.clients.iter().any(|c| matches!(c.state, State::Active | State::Disabling(..))) {
            return;
        }
        let front = self.front;
        let next = self
            .clients
            .iter()
            .enumerate()
            .filter(|(_, c)| c.vt == front || self.tty0.is_none())
            .filter_map(|(i, c)| if let State::Waiting(t) = c.state { Some((t, i)) } else { None })
            .min();
        if let Some((_, i)) = next {
            // Its cards' master back (kept while it was switched away).
            for d in self.clients[i].devices.iter().filter(|d| d.drm) {
                let _ = io::ioctl(d.fd, DRM_SET_MASTER, 0);
            }
            self.clients[i].state = State::Active;
            self.send(i, &message(SERVER_ENABLE_SEAT, &[]));
        }
    }

    /// The kernel asks to let the VT in front go (the release signal).
    fn release_requested(&mut self) {
        self.releasing = true;
        let now = slate_rt::time::monotonic_ns();
        match self.clients.iter().position(|c| c.state == State::Active) {
            Some(i) => {
                // It waits again behind those already waiting on its VT.
                let turn = self.next_turn();
                self.clients[i].state = State::Disabling(turn, now + DISABLE_GRACE_NS);
                self.send(i, &message(SERVER_DISABLE_SEAT, &[]));
            }
            None => self.let_go(),
        }
    }

    fn next_turn(&mut self) -> u64 {
        self.turn += 1;
        self.turn
    }

    /// Client `i` stepped aside (or took too long): its input devices
    /// revoked, its cards' master dropped (kept, for when it comes back).
    fn disabled(&mut self, i: usize) {
        let State::Disabling(turn, _) = self.clients[i].state else { return };
        let c = &mut self.clients[i];
        c.devices.retain(|d| {
            if d.drm {
                let _ = io::ioctl(d.fd, DRM_DROP_MASTER, 0);
                true
            } else {
                revoke(d);
                false
            }
        });
        c.state = State::Waiting(turn);
        if self.releasing {
            self.let_go();
        }
    }

    /// Let the VT in front go: the kernel switches.
    fn let_go(&mut self) {
        self.releasing = false;
        if let Some(fd) = self.vt_fd(self.front) {
            let _ = io::ioctl(fd, VT_RELDISP, 1);
        }
    }

    /// A VT came to the front (the acquire signal).
    fn acquired(&mut self) {
        self.read_front();
        if let Some(fd) = self.vt_fd(self.front) {
            let _ = io::ioctl(fd, VT_RELDISP, VT_ACKACQ);
        }
        self.activate_next();
    }

    /// Clients that didn't acknowledge DISABLE_SEAT in time.
    fn overdue(&mut self) {
        let now = slate_rt::time::monotonic_ns();
        for i in 0..self.clients.len() {
            if let State::Disabling(_, until) = self.clients[i].state
                && now >= until
            {
                self.disabled(i);
            }
        }
    }

    fn handle(&mut self, i: usize, r: Request) {
        match r {
            Request::OpenSeat => {
                if self.clients[i].state != State::Idle {
                    return self.send(i, &error(Errno::EBUSY.0));
                }
                self.read_front();
                let vt = net::peer_cred(self.clients[i].fd)
                    .ok()
                    .and_then(|(pid, _, _)| fs::read_file(alloc::format!("/proc/{pid}/stat").as_bytes()).ok())
                    .and_then(|st| vt_of_stat(&st))
                    .unwrap_or(self.front);
                self.clients[i].vt = vt;
                self.hold_vt(vt);
                self.turn += 1;
                self.clients[i].state = State::Waiting(self.turn);
                self.send(i, &seat_opened());
                self.activate_next();
            }
            Request::CloseSeat => {
                if self.clients[i].state == State::Idle {
                    return self.send(i, &error(Errno::EINVAL.0));
                }
                let was_disabling = matches!(self.clients[i].state, State::Disabling(..));
                self.release(i);
                self.clients[i].state = State::Idle;
                self.send(i, &message(SERVER_SEAT_CLOSED, &[]));
                let vt = self.clients[i].vt;
                self.let_vt_go(vt);
                if was_disabling && self.releasing {
                    self.let_go();
                }
                self.activate_next();
            }
            Request::OpenDevice(path) => {
                let r = self.open_device(i, &path);
                match r {
                    Ok((id, fd)) => {
                        let _ =
                            net::send_fds(self.clients[i].fd, &message(SERVER_DEVICE_OPENED, &id.to_ne_bytes()), &[fd]);
                    }
                    Err(e) => self.send(i, &error(e.0)),
                }
            }
            Request::CloseDevice(id) => {
                let c = &mut self.clients[i];
                match c.devices.iter().position(|d| d.id == id) {
                    Some(k) => {
                        revoke(&c.devices.remove(k));
                        self.send(i, &message(SERVER_DEVICE_CLOSED, &[]));
                    }
                    None => self.send(i, &error(Errno::ENOENT.0)),
                }
            }
            // The acknowledgement of DISABLE_SEAT (no reply).
            Request::DisableSeat => match self.clients[i].state {
                State::Disabling(..) => self.disabled(i),
                _ => self.send(i, &error(Errno::EINVAL.0)),
            },
            // Only the session in front may switch (no reply).
            Request::SwitchSession(n) => {
                if self.clients[i].state != State::Active {
                    return self.send(i, &error(Errno::EPERM.0));
                }
                match self.tty0 {
                    Some(t) if (1..=12).contains(&n) => {
                        if let Err(e) = io::ioctl(t, VT_ACTIVATE, n as usize) {
                            self.send(i, &error(e.0));
                        }
                    }
                    _ => self.send(i, &error(Errno::EINVAL.0)),
                }
            }
            Request::Ping => self.send(i, &message(SERVER_PONG, &[])),
        }
    }

    fn open_device(&mut self, i: usize, path: &[u8]) -> Result<(i32, i32), Errno> {
        if self.clients[i].state != State::Active {
            return Err(Errno::EPERM);
        }
        let drm = allowed_device(path).ok_or(Errno::EPERM)?;
        let fd = fs::open(path, fs::O_RDWR | fs::O_CLOEXEC | fs::O_NOCTTY | fs::O_NONBLOCK | fs::O_NOFOLLOW, 0)?;
        if drm && let Err(e) = io::ioctl(fd, DRM_SET_MASTER, 0) {
            let _ = io::close(fd);
            return Err(e);
        }
        let c = &mut self.clients[i];
        c.next_id += 1;
        let id = c.next_id;
        c.devices.push(Device { id, fd, drm });
        Ok((id, fd))
    }

    fn drop_client(&mut self, i: usize) {
        let was_disabling = matches!(self.clients[i].state, State::Disabling(..));
        self.release(i);
        let c = self.clients.remove(i);
        let _ = io::close(c.fd);
        self.let_vt_go(c.vt);
        if was_disabling && self.releasing {
            self.let_go();
        }
        self.activate_next();
    }

    /// Bytes arrived from client `i`; false if it must go.
    fn input(&mut self, i: usize, data: &[u8]) -> bool {
        self.clients[i].buf.extend_from_slice(data);
        loop {
            match parse(&self.clients[i].buf) {
                Ok(Some((r, used))) => {
                    self.clients[i].buf.drain(..used);
                    self.handle(i, r);
                }
                Ok(None) => return true,
                Err(Malformed) => return false,
            }
        }
    }
}

/// The `seat` group's ID, from /etc/group.
fn seat_gid() -> Option<u32> {
    let data = fs::read_file(db::GROUP).ok()?;
    data.split(|&c| c == b'\n').find_map(|l| {
        let mut f = l.split(|&c| c == b':');
        if f.next()? != b"seat" {
            return None;
        }
        core::str::from_utf8(f.nth(1)?).ok()?.parse().ok()
    })
}

/// Root, and members of the `seat` group, may use the seat.
fn allowed(fd: i32) -> bool {
    let Ok((_, uid, gid)) = net::peer_cred(fd) else { return false };
    if uid == 0 {
        return true;
    }
    let Some(seat) = seat_gid() else { return false };
    gid == seat || db::user_by_uid(uid).is_some_and(|u| db::groups_of(&u).contains(&seat))
}

pub fn main() -> i32 {
    if process::geteuid() != 0 {
        eprintln!("seatd: must run as root");
        return 1;
    }
    let listener = match net::listen_path(SOCKET, 16) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("seatd: {}: {e}", slate_rt::lossy(SOCKET));
            return 1;
        }
    };
    // Anyone may connect; `allowed` decides.
    let _ = fs::chmod(SOCKET, 0o666);
    // The kernel's release and acquire signals interrupt the wait.
    let _ = slate_rt::signal::set(RELEASE, slate_rt::signal::Disposition::CatchInterrupt);
    let _ = slate_rt::signal::set(ACQUIRE, slate_rt::signal::Disposition::CatchInterrupt);
    let tty0 = fs::open(b"/dev/tty0", fs::O_RDWR | fs::O_CLOEXEC | fs::O_NOCTTY, 0).ok();
    let mut seat = Seat { clients: Vec::new(), turn: 0, tty0, vts: Vec::new(), front: 1, releasing: false };
    seat.read_front();
    let mut buf = [0u8; 1024];
    loop {
        let caught = slate_rt::signal::take();
        if caught & (1 << RELEASE) != 0 {
            seat.release_requested();
        }
        if caught & (1 << ACQUIRE) != 0 {
            seat.acquired();
        }
        seat.overdue();
        let mut fds: Vec<io::PollFd> = core::iter::once(listener)
            .chain(seat.clients.iter().map(|c| c.fd))
            .map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 })
            .collect();
        // A signal between `take` and the wait is seen a quarter second
        // later at worst.
        if io::poll(&mut fds, 250).is_err() {
            continue;
        }
        // Clients first, last to first, so removals keep indices valid.
        for i in (0..seat.clients.len()).rev() {
            if fds[i + 1].revents == 0 {
                continue;
            }
            let keep = match io::read(seat.clients[i].fd, &mut buf) {
                Ok(0) | Err(_) => false,
                Ok(n) => seat.input(i, &buf[..n]),
            };
            if !keep {
                seat.drop_client(i);
            }
        }
        if fds[0].revents & io::POLLIN != 0
            && let Ok(fd) = net::accept(listener)
        {
            if allowed(fd) {
                seat.clients.push(Client {
                    fd,
                    buf: Vec::new(),
                    state: State::Idle,
                    devices: Vec::new(),
                    next_id: 0,
                    vt: 0,
                });
            } else {
                let _ = io::write_all(fd, &error(Errno::EACCES.0));
                let _ = io::close(fd);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(op: u16, body: &[u8]) -> Vec<u8> {
        message(op, body)
    }

    #[test]
    fn requests() {
        assert_eq!(parse(&req(CLIENT_OPEN_SEAT, &[])), Ok(Some((Request::OpenSeat, 4))));
        assert_eq!(parse(&req(CLIENT_PING, &[])[..3]), Ok(None));
        assert_eq!(parse(&req(CLIENT_CLOSE_DEVICE, &7i32.to_ne_bytes())), Ok(Some((Request::CloseDevice(7), 8))));
        let mut body = Vec::from(15u16.to_ne_bytes());
        body.extend_from_slice(b"/dev/dri/card0\0");
        assert_eq!(
            parse(&req(CLIENT_OPEN_DEVICE, &body)),
            Ok(Some((Request::OpenDevice(b"/dev/dri/card0".to_vec()), 4 + 17)))
        );
        // A path without its NUL, a wrong length, an unknown opcode, a
        // body where none belongs.
        let mut bad = Vec::from(14u16.to_ne_bytes());
        bad.extend_from_slice(b"/dev/dri/card0");
        assert_eq!(parse(&req(CLIENT_OPEN_DEVICE, &bad)), Err(Malformed));
        assert_eq!(parse(&req(CLIENT_OPEN_DEVICE, &[9, 0, b'x', 0])), Err(Malformed));
        assert_eq!(parse(&req(99, &[])), Err(Malformed));
        assert_eq!(parse(&req(CLIENT_OPEN_SEAT, &[1])), Err(Malformed));
        // Two requests back to back: the first.
        let mut two = req(CLIENT_PING, &[]);
        two.extend(req(CLIENT_CLOSE_SEAT, &[]));
        assert_eq!(parse(&two), Ok(Some((Request::Ping, 4))));
    }

    #[test]
    fn replies() {
        assert_eq!(seat_opened(), [1, 0x80, 8, 0, 6, 0, b's', b'e', b'a', b't', b'0', 0]);
        assert_eq!(error(13), [0xff, 0xff, 4, 0, 13, 0, 0, 0]);
        assert_eq!(message(SERVER_ENABLE_SEAT, &[]), [6, 0x80, 0, 0]);
    }

    #[test]
    fn sessions_from_stat() {
        // tty_nr 1025: 4:1, /dev/tty1; 1031 /dev/tty7; 1281 /dev/console;
        // 34816 a pty (136:0); 0 none.
        let stat = |nr: u32| alloc::format!("42 (strata (x)) S 1 42 42 {nr} 42 0").into_bytes();
        assert_eq!(vt_of_stat(&stat(1025)), Some(1));
        assert_eq!(vt_of_stat(&stat(1031)), Some(7));
        assert_eq!(vt_of_stat(&stat(1281)), Some(1));
        assert_eq!(vt_of_stat(&stat(34816)), None);
        assert_eq!(vt_of_stat(&stat(0)), None);
    }

    #[test]
    fn devices() {
        assert_eq!(allowed_device(b"/dev/dri/card0"), Some(true));
        assert_eq!(allowed_device(b"/dev/input/event12"), Some(false));
        assert_eq!(allowed_device(b"/dev/input/event"), None);
        assert_eq!(allowed_device(b"/dev/input/../sda"), None);
        assert_eq!(allowed_device(b"/dev/dri/card0/../../sda"), None);
        assert_eq!(allowed_device(b"/dev/sda"), None);
    }
}
