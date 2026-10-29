// SPDX-License-Identifier: MIT OR Apache-2.0

//! Login records (ADR 0057): /run/utmp (who is logged in now),
//! /var/log/wtmp (every login, logout, boot and shutdown) and
//! /var/log/lastlog (each user's last login, indexed by UID). The record
//! layouts are the x86-64 ones utmp(5) and lastlog(8) document, so Linux
//! programs read the same files.

use alloc::vec::Vec;

use crate::{fs, io, process, time};

pub const UTMP: &[u8] = b"/run/utmp";
pub const WTMP: &[u8] = b"/var/log/wtmp";
pub const LASTLOG: &[u8] = b"/var/log/lastlog";

// ut_type values (utmp(5)).
pub const EMPTY: i16 = 0;
pub const RUN_LVL: i16 = 1;
pub const BOOT_TIME: i16 = 2;
pub const INIT_PROCESS: i16 = 5;
pub const LOGIN_PROCESS: i16 = 6;
pub const USER_PROCESS: i16 = 7;
pub const DEAD_PROCESS: i16 = 8;

/// `struct utmp` on x86-64: 384 bytes (utmp(5)).
pub const SIZE: usize = 384;
/// `struct lastlog`: a 32-bit time, then the line and the host.
pub const LASTLOG_SIZE: usize = 292;

/// One utmp/wtmp record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: i16,
    pub pid: i32,
    /// The terminal without `/dev/` (`ttyS0`, `pts/2`), or `~` for boot
    /// and run-level records.
    pub line: Vec<u8>,
    /// The line's last four characters (utmp(5) `ut_id`).
    pub id: Vec<u8>,
    pub user: Vec<u8>,
    pub host: Vec<u8>,
    pub session: i32,
    pub secs: i64,
    pub usecs: i32,
}

fn field(b: &[u8]) -> Vec<u8> {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b[..end].to_vec()
}

fn put(out: &mut [u8], v: &[u8]) {
    let n = v.len().min(out.len());
    out[..n].copy_from_slice(&v[..n]);
}

impl Entry {
    /// A record for `kind` on `line` now.
    pub fn new(kind: i16, pid: i32, line: &[u8], user: &[u8], host: &[u8]) -> Entry {
        let (secs, nsec) = time::now(time::CLOCK_REALTIME);
        let id = if line.len() > 4 { line[line.len() - 4..].to_vec() } else { line.to_vec() };
        Entry {
            kind,
            pid,
            line: line.to_vec(),
            id,
            user: user.to_vec(),
            host: host.to_vec(),
            session: process::getsid(0).unwrap_or(0),
            secs,
            usecs: (nsec / 1000) as i32,
        }
    }

    pub fn decode(b: &[u8; SIZE]) -> Entry {
        let i32_at = |o: usize| i32::from_le_bytes(b[o..o + 4].try_into().unwrap_or_default());
        Entry {
            kind: i16::from_le_bytes([b[0], b[1]]),
            pid: i32_at(4),
            line: field(&b[8..40]),
            id: field(&b[40..44]),
            user: field(&b[44..76]),
            host: field(&b[76..332]),
            session: i32_at(336),
            secs: i64::from(i32_at(340)),
            usecs: i32_at(344),
        }
    }

    pub fn encode(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        b[0..2].copy_from_slice(&self.kind.to_le_bytes());
        b[4..8].copy_from_slice(&self.pid.to_le_bytes());
        put(&mut b[8..40], &self.line);
        put(&mut b[40..44], &self.id);
        put(&mut b[44..76], &self.user);
        put(&mut b[76..332], &self.host);
        // ut_exit (332..336) stays zero.
        b[336..340].copy_from_slice(&self.session.to_le_bytes());
        b[340..344].copy_from_slice(&(self.secs as i32).to_le_bytes());
        b[344..348].copy_from_slice(&self.usecs.to_le_bytes());
        b
    }
}

/// Every record of a utmp or wtmp file.
pub fn read(path: &[u8]) -> Vec<Entry> {
    let data = fs::read_file(path).unwrap_or_default();
    data.as_chunks::<SIZE>().0.iter().map(Entry::decode).collect()
}

/// Open `path` for writing, locked against other writers.
fn open_locked(path: &[u8], extra: u32) -> Option<i32> {
    let _ = fs::mkdir(fs::dirname(path), 0o755);
    let fd = fs::open(path, fs::O_RDWR | fs::O_CREAT | fs::O_CLOEXEC | extra, 0o644).ok()?;
    let _ = fs::flock(fd, fs::LOCK_EX);
    Some(fd)
}

/// Append a record to wtmp.
pub fn append_wtmp(e: &Entry) {
    if let Some(fd) = open_locked(WTMP, fs::O_APPEND) {
        let _ = io::write_all(fd, &e.encode());
        let _ = io::close(fd);
    }
}

/// Put `e` in utmp: over the record with the same `id` (or the same pid),
/// else in the first free slot, else at the end.
pub fn write_utmp(e: &Entry) {
    let Some(fd) = open_locked(UTMP, 0) else { return };
    let data = io::read_to_end(fd).unwrap_or_default();
    let records = data.as_chunks::<SIZE>().0;
    let same = |r: &Entry| {
        (!e.id.is_empty() && r.id == e.id && matches!(r.kind, INIT_PROCESS..=DEAD_PROCESS))
            || (e.pid != 0 && r.pid == e.pid && r.kind != BOOT_TIME && r.kind != RUN_LVL)
            || (matches!(e.kind, BOOT_TIME | RUN_LVL) && r.kind == e.kind)
    };
    let slot = records
        .iter()
        .position(|r| same(&Entry::decode(r)))
        .or_else(|| records.iter().position(|r| matches!(Entry::decode(r).kind, EMPTY | DEAD_PROCESS)))
        .unwrap_or(records.len());
    let _ = io::pwrite(fd, &e.encode(), (slot * SIZE) as u64);
    let _ = io::close(fd);
}

/// A login: utmp, wtmp and lastlog.
pub fn login(pid: i32, line: &[u8], user: &[u8], uid: u32, host: &[u8]) {
    let e = Entry::new(USER_PROCESS, pid, line, user, host);
    write_utmp(&e);
    append_wtmp(&e);
    set_lastlog(uid, e.secs, line, host);
}

/// The end of the session whose process was `pid`: its utmp record
/// becomes DEAD_PROCESS, and wtmp gets a logout record. Nothing happens
/// if `pid` had no login record.
pub fn logout(pid: i32) {
    let Some(r) = read(UTMP).into_iter().find(|r| r.pid == pid && r.kind == USER_PROCESS) else { return };
    let mut e = Entry::new(DEAD_PROCESS, pid, &r.line, b"", b"");
    e.id = r.id;
    write_utmp(&e);
    append_wtmp(&e);
}

/// Boot: an empty utmp with a boot record, and the same in wtmp.
pub fn boot() {
    let _ = fs::write_file(UTMP, &[], 0o644);
    let e = Entry::new(BOOT_TIME, 0, b"~", b"reboot", b"");
    write_utmp(&e);
    append_wtmp(&e);
}

/// A run-level change (`level` as a character), and at shutdown (`0` or
/// `6`) the record `last -x` shows.
pub fn run_level(level: u8, previous: u8) {
    let mut e = Entry::new(RUN_LVL, i32::from(level) + 256 * i32::from(previous), b"~", b"runlevel", b"");
    if matches!(level, b'0' | b'6') {
        e.user = b"shutdown".to_vec();
    }
    write_utmp(&e);
    append_wtmp(&e);
}

/// Users logged in now: USER_PROCESS records whose process still lives.
pub fn current() -> Vec<Entry> {
    read(UTMP)
        .into_iter()
        .filter(|r| r.kind == USER_PROCESS && (r.pid <= 0 || fs::exists(alloc::format!("/proc/{}", r.pid).as_bytes())))
        .collect()
}

/// `uid`'s last login: (time, line, host), if any.
pub fn lastlog(uid: u32) -> Option<(i64, Vec<u8>, Vec<u8>)> {
    let fd = fs::open(LASTLOG, fs::O_RDONLY | fs::O_CLOEXEC, 0).ok()?;
    let mut b = [0u8; LASTLOG_SIZE];
    let n = io::pread(fd, &mut b, u64::from(uid) * LASTLOG_SIZE as u64).unwrap_or(0);
    let _ = io::close(fd);
    let t = i32::from_le_bytes(b[0..4].try_into().ok()?);
    (n == LASTLOG_SIZE && t != 0).then(|| (i64::from(t), field(&b[4..36]), field(&b[36..292])))
}

pub fn set_lastlog(uid: u32, secs: i64, line: &[u8], host: &[u8]) {
    let Some(fd) = open_locked(LASTLOG, 0) else { return };
    let mut b = [0u8; LASTLOG_SIZE];
    b[0..4].copy_from_slice(&(secs as i32).to_le_bytes());
    put(&mut b[4..36], line);
    put(&mut b[36..292], host);
    let _ = io::pwrite(fd, &b, u64::from(uid) * LASTLOG_SIZE as u64);
    let _ = io::close(fd);
}

/// The terminal of standard input without `/dev/` (`ttyS0`, `pts/1`).
pub fn tty_line() -> Option<Vec<u8>> {
    let t = process::ttyname(0)?;
    Some(t.strip_prefix(b"/dev/").map_or_else(|| t.clone(), <[u8]>::to_vec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        let e = Entry {
            kind: USER_PROCESS,
            pid: 42,
            line: b"pts/3".to_vec(),
            id: b"ts/3".to_vec(),
            user: b"alex".to_vec(),
            host: b"10.0.2.2".to_vec(),
            session: 42,
            secs: 1_792_683_045,
            usecs: 7,
        };
        let b = e.encode();
        assert_eq!(b.len(), 384);
        assert_eq!(&b[44..48], b"alex");
        assert_eq!(Entry::decode(&b), e);
    }
}
