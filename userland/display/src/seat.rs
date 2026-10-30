// SPDX-License-Identifier: MIT OR Apache-2.0

//! A client of Slate's seatd (ADR 0033): a program that is not root asks
//! it for the seat, then for the DRM card and the input devices, which it
//! opens and passes over its socket. Only members of the `seat` group may.
//!
//! The messages are seatd's protocol (libseat's `seatd` backend; the
//! layouts are in userland/seatd/src/lib.rs): a 16-bit opcode and a 16-bit
//! body size in native byte order, then the body.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{io, net, process};

const SOCKET: &[u8] = b"/run/seatd.sock";
const CLIENT_OPEN_SEAT: u16 = 1;
const CLIENT_OPEN_DEVICE: u16 = 3;
const SERVER: u16 = 1 << 15;
const SERVER_SEAT_OPENED: u16 = SERVER + 1;
const SERVER_DEVICE_OPENED: u16 = SERVER + 3;
const SERVER_ENABLE_SEAT: u16 = SERVER + 6;
const SERVER_ERROR: u16 = SERVER + 0x7FFF;

/// The seat, held open while its devices are in use.
#[derive(Debug)]
pub struct Seat {
    fd: i32,
    buf: Vec<u8>,
    fds: VecDeque<i32>,
}

fn message(op: u16, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::from(op.to_ne_bytes());
    m.extend_from_slice(&(body.len() as u16).to_ne_bytes());
    m.extend_from_slice(body);
    m
}

impl Seat {
    /// Open the seat and wait until seatd makes this session active.
    pub fn open() -> Result<Seat, String> {
        let fd = net::connect_path(SOCKET).map_err(|e| format!("seatd ({}): {e}", "/run/seatd.sock"))?;
        let mut s = Seat { fd, buf: Vec::new(), fds: VecDeque::new() };
        io::write_all(fd, &message(CLIENT_OPEN_SEAT, &[])).map_err(|e| format!("seatd: {e}"))?;
        let (mut opened, mut enabled) = (false, false);
        while !(opened && enabled) {
            match s.next(5000)? {
                (SERVER_SEAT_OPENED, _) => opened = true,
                (SERVER_ENABLE_SEAT, _) => enabled = true,
                (SERVER_ERROR, b) if errno(&b) == slate_rt::Errno::EACCES.0 => {
                    return Err(String::from(
                        "this account may not use the desktop: an administrator can allow it in Settings › \
                         Users (\"Can use the desktop\"), or with `gpasswd -a NAME seat`",
                    ));
                }
                (SERVER_ERROR, b) => return Err(format!("seatd refused the seat (error {})", errno(&b))),
                _ => {}
            }
        }
        Ok(s)
    }

    /// Open `path` through seatd; the descriptor is non-blocking.
    pub fn open_device(&mut self, path: &[u8]) -> Result<i32, String> {
        let mut body = Vec::from(((path.len() + 1) as u16).to_ne_bytes());
        body.extend_from_slice(path);
        body.push(0);
        io::write_all(self.fd, &message(CLIENT_OPEN_DEVICE, &body)).map_err(|e| format!("seatd: {e}"))?;
        loop {
            match self.next(5000)? {
                (SERVER_DEVICE_OPENED, _) => {
                    let fd = self.fds.pop_front().ok_or("seatd sent no descriptor")?;
                    let flags = process::fcntl(fd, process::F_GETFL, 0).unwrap_or(0);
                    let _ = process::fcntl(fd, process::F_SETFL, flags | slate_rt::fs::O_NONBLOCK as usize);
                    return Ok(fd);
                }
                (SERVER_ERROR, b) => return Err(format!("seatd would not open the device (error {})", errno(&b))),
                _ => {}
            }
        }
    }

    /// The next message, within `timeout_ms`.
    fn next(&mut self, timeout_ms: i32) -> Result<(u16, Vec<u8>), String> {
        loop {
            if self.buf.len() >= 4 {
                let op = u16::from_ne_bytes([self.buf[0], self.buf[1]]);
                let size = usize::from(u16::from_ne_bytes([self.buf[2], self.buf[3]]));
                if self.buf.len() >= 4 + size {
                    let body: Vec<u8> = self.buf.drain(..4 + size).skip(4).collect();
                    return Ok((op, body));
                }
            }
            let mut p = [io::PollFd { fd: self.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, timeout_ms).unwrap_or(0) == 0 {
                return Err("seatd did not answer".into());
            }
            let mut chunk = [0u8; 512];
            let (n, fds) = net::recv_fds(self.fd, &mut chunk).map_err(|e| format!("seatd: {e}"))?;
            if n == 0 && fds.is_empty() {
                return Err("seatd closed the connection".into());
            }
            self.fds.extend(fds);
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }
}

fn errno(body: &[u8]) -> i32 {
    body.get(..4).map_or(0, |b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

impl Drop for Seat {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}
