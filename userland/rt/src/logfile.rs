// SPDX-License-Identifier: MIT OR Apache-2.0

//! The system's text logs (ADR 0060): lines appended to a file, which is
//! renamed to `NAME.1` once it passes a size (the one before is dropped).
//! Lines that cannot be written yet (no /var/log during early boot) wait
//! in memory, up to a limit, oldest dropped first.

use alloc::vec::Vec;

use crate::{fs, io};

#[derive(Debug)]
pub struct LogFile {
    path: Vec<u8>,
    fd: i32,
    size: u64,
    /// Rotate past this many bytes.
    limit: u64,
    mode: u32,
    pending: Vec<u8>,
    /// Most bytes kept while the file cannot be written.
    pending_max: usize,
    /// Closed for good (the system is going down).
    closed: bool,
}

impl LogFile {
    pub fn new(path: &[u8], limit: u64, mode: u32) -> LogFile {
        LogFile {
            path: path.to_vec(),
            fd: -1,
            size: 0,
            limit,
            mode,
            pending: Vec::new(),
            pending_max: 64 * 1024,
            closed: false,
        }
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Add whole lines (each ending in a newline) and write what can be.
    pub fn append(&mut self, lines: &[u8]) {
        if self.closed {
            return;
        }
        self.pending.extend_from_slice(lines);
        if self.pending.len() > self.pending_max {
            // Drop the oldest whole lines.
            let over = self.pending.len() - self.pending_max;
            let cut =
                self.pending[over..].iter().position(|&c| c == b'\n').map_or(self.pending.len(), |p| over + p + 1);
            self.pending.drain(..cut);
        }
        self.flush();
    }

    /// Write what is waiting; false if it must wait longer.
    pub fn flush(&mut self) -> bool {
        if self.pending.is_empty() || self.closed {
            return true;
        }
        if self.fd < 0 && !self.open() {
            return false;
        }
        if io::write_all(self.fd, &self.pending).is_err() {
            let _ = io::close(self.fd);
            self.fd = -1;
            return false;
        }
        self.size += self.pending.len() as u64;
        self.pending.clear();
        if self.size >= self.limit {
            self.rotate();
        }
        true
    }

    fn open(&mut self) -> bool {
        let dir = fs::dirname(&self.path).to_vec();
        if !fs::exists(&dir) {
            let _ = fs::mkdir(fs::dirname(&dir), 0o755);
            let _ = fs::mkdir(&dir, 0o755);
        }
        match fs::open(&self.path, fs::O_WRONLY | fs::O_APPEND | fs::O_CREAT | fs::O_CLOEXEC, self.mode) {
            Ok(fd) => {
                self.fd = fd;
                self.size = fs::fstat(fd).map_or(0, |s| s.size.max(0) as u64);
                true
            }
            Err(_) => false,
        }
    }

    fn rotate(&mut self) {
        let _ = io::close(self.fd);
        self.fd = -1;
        self.size = 0;
        let old = [self.path.as_slice(), b".1"].concat();
        let _ = fs::rename(&self.path, &old);
    }

    /// Close the file (its file system is about to go); lines that come
    /// later are dropped.
    pub fn close(&mut self) {
        self.flush();
        if self.fd >= 0 {
            let _ = io::close(self.fd);
        }
        self.fd = -1;
        self.closed = true;
    }
}

/// One log line: the timestamp, the text, a newline.
pub fn line(text: &[u8]) -> Vec<u8> {
    let mut l = crate::tz::stamp(crate::time::unix()).into_bytes();
    l.push(b' ');
    l.extend_from_slice(text);
    l.push(b'\n');
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_rotates_and_waits() {
        let dir = std::env::temp_dir().join(std::format!("slate-logfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The directory is made on first write.
        let path = dir.join("svc.log");
        let mut l = LogFile::new(path.to_str().unwrap().as_bytes(), 32, 0o600);
        l.append(b"first line\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"first line\n");
        // Past 32 bytes: renamed to .1, the next line starts a new file.
        l.append(b"second line, longer one\n");
        assert!(!path.exists());
        assert_eq!(std::fs::read(dir.join("svc.log.1")).unwrap(), b"first line\nsecond line, longer one\n");
        l.append(b"third\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"third\n");
        l.close();
        l.append(b"dropped\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"third\n");
        // Unwritable: lines wait, oldest dropped past the limit.
        let mut w = LogFile::new(b"/proc/nonexistent/x.log", 1 << 20, 0o600);
        w.pending_max = 8;
        w.append(b"aaaa\n");
        w.append(b"bbbb\n");
        assert_eq!(w.pending, b"bbbb\n");
        assert!(line(b"x").ends_with(b" x\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
