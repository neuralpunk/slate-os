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
//! set; error codes are errno values. Slate offers one seat, `seat0`,
//! and no session switching (EOPNOTSUPP).
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
/// EOPNOTSUPP (musl `bits/errno.h`).
const EOPNOTSUPP: i32 = 95;

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
    /// Opened it; waits its turn (the number orders the waiters).
    Waiting(u64),
    Active,
}

struct Client {
    fd: i32,
    buf: Vec<u8>,
    state: State,
    devices: Vec<Device>,
    next_id: i32,
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

struct Seat {
    clients: Vec<Client>,
    turn: u64,
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

    /// Make the longest-waiting session active if none is.
    fn activate_next(&mut self) {
        if self.clients.iter().any(|c| c.state == State::Active) {
            return;
        }
        let next = self
            .clients
            .iter()
            .enumerate()
            .filter_map(|(i, c)| if let State::Waiting(t) = c.state { Some((t, i)) } else { None })
            .min();
        if let Some((_, i)) = next {
            self.clients[i].state = State::Active;
            self.send(i, &message(SERVER_ENABLE_SEAT, &[]));
        }
    }

    fn handle(&mut self, i: usize, r: Request) {
        match r {
            Request::OpenSeat => {
                if self.clients[i].state != State::Idle {
                    return self.send(i, &error(Errno::EBUSY.0));
                }
                self.turn += 1;
                self.clients[i].state = State::Waiting(self.turn);
                self.send(i, &seat_opened());
                self.activate_next();
            }
            Request::CloseSeat => {
                if self.clients[i].state == State::Idle {
                    return self.send(i, &error(Errno::EINVAL.0));
                }
                self.release(i);
                self.clients[i].state = State::Idle;
                self.send(i, &message(SERVER_SEAT_CLOSED, &[]));
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
            // seatd never asks a session to step aside (no switching), so
            // there is nothing to acknowledge.
            Request::DisableSeat => self.send(i, &error(Errno::EINVAL.0)),
            Request::SwitchSession(_) => self.send(i, &error(EOPNOTSUPP)),
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
        self.release(i);
        let c = self.clients.remove(i);
        let _ = io::close(c.fd);
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
    let mut seat = Seat { clients: Vec::new(), turn: 0 };
    let mut buf = [0u8; 1024];
    loop {
        let mut fds: Vec<io::PollFd> = core::iter::once(listener)
            .chain(seat.clients.iter().map(|c| c.fd))
            .map(|fd| io::PollFd { fd, events: io::POLLIN, revents: 0 })
            .collect();
        if io::poll(&mut fds, -1).is_err() {
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
                seat.clients.push(Client { fd, buf: Vec::new(), state: State::Idle, devices: Vec::new(), next_id: 0 });
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
    fn devices() {
        assert_eq!(allowed_device(b"/dev/dri/card0"), Some(true));
        assert_eq!(allowed_device(b"/dev/input/event12"), Some(false));
        assert_eq!(allowed_device(b"/dev/input/event"), None);
        assert_eq!(allowed_device(b"/dev/input/../sda"), None);
        assert_eq!(allowed_device(b"/dev/dri/card0/../../sda"), None);
        assert_eq!(allowed_device(b"/dev/sda"), None);
    }
}
