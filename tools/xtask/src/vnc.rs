// SPDX-License-Identifier: MIT OR Apache-2.0

//! Just enough of a VNC client (RFB 3.8, RFC 6143, and the
//! ExtendedDesktopSize extension's SetDesktopSize message from the RFB
//! community's protocol documentation) to ask QEMU's VNC server for a
//! display size: QEMU passes it to the guest's display device as a
//! display change (ADR 0100), which is how scenarios resize and plug in
//! virtio-gpu's outputs without a window.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::Result;

/// A connection, kept open: QEMU may undo the size when it closes.
pub struct Vnc {
    s: UnixStream,
}

fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|e| format!("VNC: {e}"))
}

impl Vnc {
    /// Connect to the VNC server on Unix socket `path` (no
    /// authentication), as a shared client.
    pub fn connect(path: &Path) -> Result<Vnc> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut s = loop {
            match UnixStream::connect(path) {
                Ok(s) => break s,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(format!("VNC {}: {e}", path.display())),
            }
        };
        io(s.set_read_timeout(Some(Duration::from_secs(10))))?;
        let mut version = [0u8; 12];
        io(s.read_exact(&mut version))?;
        if !version.starts_with(b"RFB 003.") {
            return Err(format!("VNC: not an RFB server ({:?})", String::from_utf8_lossy(&version)));
        }
        io(s.write_all(b"RFB 003.008\n"))?;
        // Security types: one byte of count, then the types; 1 is None.
        let mut n = [0u8; 1];
        io(s.read_exact(&mut n))?;
        let mut types = vec![0u8; usize::from(n[0])];
        io(s.read_exact(&mut types))?;
        if !types.contains(&1) {
            return Err(format!("VNC: no unauthenticated access (types {types:?})"));
        }
        io(s.write_all(&[1]))?;
        let mut result = [0u8; 4];
        io(s.read_exact(&mut result))?;
        if result != [0; 4] {
            return Err("VNC: the security handshake failed".into());
        }
        // ClientInit (shared), then ServerInit: width, height, a 16-byte
        // pixel format, and the name.
        io(s.write_all(&[1]))?;
        let mut init = [0u8; 24];
        io(s.read_exact(&mut init))?;
        let name_len = u32::from_be_bytes(init[20..24].try_into().unwrap()) as usize;
        let mut name = vec![0u8; name_len];
        io(s.read_exact(&mut name))?;
        // SetEncodings: raw, and the pseudo-encodings for desktop sizes
        // (-223 DesktopSize, -308 ExtendedDesktopSize).
        let mut m = vec![2u8, 0];
        let encodings: [i32; 3] = [0, -223, -308];
        m.extend_from_slice(&(encodings.len() as u16).to_be_bytes());
        for e in encodings {
            m.extend_from_slice(&e.to_be_bytes());
        }
        io(s.write_all(&m))?;
        Ok(Vnc { s })
    }

    /// SetDesktopSize: one screen of `width` × `height`.
    pub fn set_size(&mut self, width: u16, height: u16) -> Result {
        let mut m = vec![251u8, 0];
        m.extend_from_slice(&width.to_be_bytes());
        m.extend_from_slice(&height.to_be_bytes());
        m.extend_from_slice(&[1, 0]);
        // The screen: id, x, y, width, height, flags.
        m.extend_from_slice(&0u32.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&0u16.to_be_bytes());
        m.extend_from_slice(&width.to_be_bytes());
        m.extend_from_slice(&height.to_be_bytes());
        m.extend_from_slice(&0u32.to_be_bytes());
        io(self.s.write_all(&m))
    }
}
