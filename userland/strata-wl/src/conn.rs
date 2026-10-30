// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Wayland connection as a client sees it: object ids handed out in
//! order from 2 (1 is wl_display), each remembered with what it is so
//! its events can be read, messages out, and messages in with the file
//! descriptors that came beside them (the Wayland protocol
//! documentation, "Wire Format").

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, net, process};

use crate::wire::{self, Msg, Out};

/// The connection; `K` says what each object is.
#[derive(Debug)]
pub struct Wl<K: Copy> {
    pub fd: i32,
    inbuf: Vec<u8>,
    next: u32,
    pub kinds: BTreeMap<u32, K>,
    /// Descriptors that came with events, in order.
    pub fds: VecDeque<i32>,
}

impl<K: Copy> Wl<K> {
    /// Connect to the compositor's socket at `path`; `display` is what
    /// object 1 is.
    pub fn connect(path: &[u8], display: K) -> Result<Wl<K>, String> {
        let fd = net::connect_path(path).map_err(|e| format!("{}: {e}", lossy(path)))?;
        let mut kinds = BTreeMap::new();
        kinds.insert(1, display);
        Ok(Wl { fd, inbuf: Vec::new(), next: 2, kinds, fds: VecDeque::new() })
    }

    /// A new object of kind `k`.
    pub fn id(&mut self, k: K) -> u32 {
        let id = self.next;
        self.next += 1;
        self.kinds.insert(id, k);
        id
    }

    pub fn send(&mut self, m: Out) -> Result<(), String> {
        io::write_all(self.fd, &m.done()).map_err(|e| format!("talking to the compositor: {e}"))
    }

    pub fn send_fd(&mut self, m: Out, fd: i32) -> Result<(), String> {
        net::send_fds(self.fd, &m.done(), &[fd]).map(|_| ()).map_err(|e| format!("talking to the compositor: {e}"))
    }

    /// Read what has arrived; Err when the compositor has gone.
    pub fn read(&mut self) -> Result<Vec<Msg>, String> {
        let mut buf = [0u8; 8192];
        let (n, fds) = net::recv_fds(self.fd, &mut buf).map_err(|e| format!("reading from the compositor: {e}"))?;
        self.fds.extend(fds);
        if n == 0 {
            return Err("the compositor has gone".into());
        }
        self.inbuf.extend_from_slice(&buf[..n]);
        let mut out = Vec::new();
        while let Some(m) = wire::next(&mut self.inbuf).map_err(|_| String::from("the compositor sent garbage"))? {
            out.push(m);
        }
        Ok(out)
    }
}

/// Milliseconds on the monotonic clock.
pub fn now_ms() -> i64 {
    (slate_rt::time::monotonic_ns() / 1_000_000) as i64
}

/// Microseconds on the monotonic clock.
pub fn now_us() -> i64 {
    (slate_rt::time::monotonic_ns() / 1000) as i64
}

/// When the program being started was asked for: `SLATE_LINUX_T0`
/// (nanoseconds on the monotonic clock, set by slate-linux-app), else
/// now. Start-up stages are timed from it (M31 phase 1).
pub fn t0_ns() -> u64 {
    slate_rt::env::var(b"SLATE_LINUX_T0")
        .and_then(|v| lossy(&v).trim().parse().ok())
        .unwrap_or_else(slate_rt::time::monotonic_ns)
}

/// Milliseconds since `t0` (from [`t0_ns`]).
pub fn since_ms(t0: u64) -> u64 {
    slate_rt::time::monotonic_ns().saturating_sub(t0) / 1_000_000
}

/// A file in shared memory, `len` bytes: created in the runtime
/// directory and unlinked at once.
pub fn shm_file(len: usize) -> Result<i32, String> {
    static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
    let dir = slate_rt::env::var(b"XDG_RUNTIME_DIR").unwrap_or_else(|| b"/tmp".to_vec());
    let n = N.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let path = format!("{}/.strata-wl-{}-{}-{n}", lossy(&dir), process::getpid(), now_ms());
    let fd = fs::open(path.as_bytes(), fs::O_RDWR | fs::O_CREAT | fs::O_EXCL | fs::O_CLOEXEC, 0o600)
        .map_err(|e| format!("{path}: {e}"))?;
    let _ = fs::unlink(path.as_bytes());
    fs::ftruncate(fd, len as u64).map_err(|e| format!("{path}: {e}"))?;
    Ok(fd)
}

/// Whether `name` is a Wayland display socket's (`wayland-N`).
pub fn display_socket(name: &[u8]) -> bool {
    name.strip_prefix(b"wayland-").is_some_and(|n| !n.is_empty() && n.iter().all(u8::is_ascii_digit))
}

/// The compositor's socket: `$WAYLAND_DISPLAY` (a name in `dir`, or a
/// path), else the first display socket in `dir`.
pub fn socket_path(dir: &[u8]) -> Option<Vec<u8>> {
    let join = |name: &[u8]| if name.starts_with(b"/") { name.to_vec() } else { [dir, b"/", name].concat() };
    if let Some(d) = slate_rt::env::var(b"WAYLAND_DISPLAY")
        && fs::exists(&join(&d))
    {
        return Some(join(&d));
    }
    let mut names: Vec<Vec<u8>> =
        fs::read_dir(dir).unwrap_or_default().into_iter().map(|e| e.name).filter(|n| display_socket(n)).collect();
    names.sort();
    names.first().map(|n| join(n))
}

/// The p-th percentile (0..=100) of `v` (sorted in place); 0 if empty.
pub fn percentile(v: &mut [i64], p: usize) -> i64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    v[((v.len() - 1) * p).div_ceil(100).min(v.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockets() {
        assert!(display_socket(b"wayland-1"));
        assert!(!display_socket(b"wayland-1.lock"));
        assert!(!display_socket(b"wayland-"));
        assert!(!display_socket(b"sway-ipc.0.30.sock"));
    }

    #[test]
    fn percentiles() {
        let mut v = alloc::vec![5, 1, 4, 2, 3];
        assert_eq!(percentile(&mut v, 50), 3);
        assert_eq!(percentile(&mut v, 95), 5);
        assert_eq!(percentile(&mut v, 0), 1);
        assert_eq!(percentile(&mut [], 50), 0);
    }
}
