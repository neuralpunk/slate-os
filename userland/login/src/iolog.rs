// SPDX-License-Identifier: MIT OR Apache-2.0

//! sudo's I/O logs (ADR 0159), laid out as sudoers(5) describes them: a
//! directory per session under /var/log/sudo-io, named by a base-36
//! sequence number split in three (`00/00/01`), holding `log` (what ran),
//! `timing` (an event a line) and the streams (`ttyin`, `ttyout`,
//! `stdin`, `stdout`, `stderr`).
//!
//! The broker makes the session (it is root) and hands sudo the open
//! files; sudo records into them as the command runs; sudoreplay reads
//! them back.
//!
//! `log` is three lines: `TIME:USER:RUNAS_USER:RUNAS_GROUP:TTY:ROWS:COLS`,
//! the working directory, the command. A `timing` line is `TYPE DELAY
//! SIZE` for data (0 stdin, 1 stdout, 2 stderr, 3 ttyin, 4 ttyout), `5
//! DELAY ROWS COLS` for a window change and `6 DELAY SIGNAL` for the
//! command stopping or going on; DELAY is the seconds since the event
//! before.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io};

/// Where sessions are kept.
pub const DIR: &[u8] = b"/var/log/sudo-io";

/// The streams, in the order of their `timing` types.
pub const STREAMS: [&str; 5] = ["stdin", "stdout", "stderr", "ttyin", "ttyout"];

/// A data stream's `timing` type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
    TtyIn = 3,
    TtyOut = 4,
}

/// What a session's `log` says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub time: i64,
    pub user: Vec<u8>,
    pub runas_user: Vec<u8>,
    pub runas_group: Vec<u8>,
    pub tty: Vec<u8>,
    pub rows: u32,
    pub cols: u32,
    pub cwd: Vec<u8>,
    pub command: Vec<u8>,
}

impl Info {
    pub fn encode(&self) -> Vec<u8> {
        let clean =
            |b: &[u8]| -> Vec<u8> { b.iter().map(|&c| if c == b'\n' || c == b':' { b'?' } else { c }).collect() };
        let mut out = format!("{}:", self.time).into_bytes();
        for f in [&self.user, &self.runas_user, &self.runas_group, &self.tty] {
            out.extend(clean(f));
            out.push(b':');
        }
        out.extend(format!("{}:{}\n", self.rows, self.cols).bytes());
        out.extend(self.cwd.iter().map(|&c| if c == b'\n' { b'?' } else { c }));
        out.push(b'\n');
        out.extend(escape_newlines(&self.command));
        out.push(b'\n');
        out
    }

    pub fn decode(b: &[u8]) -> Option<Info> {
        let mut lines = b.split(|&c| c == b'\n');
        let first: Vec<&[u8]> = lines.next()?.split(|&c| c == b':').collect();
        let num = |w: &[u8]| core::str::from_utf8(w).ok()?.parse().ok();
        let [time, user, ru, rg, tty, rows, cols] = first[..] else { return None };
        Some(Info {
            time: num(time)?,
            user: user.to_vec(),
            runas_user: ru.to_vec(),
            runas_group: rg.to_vec(),
            tty: tty.to_vec(),
            rows: num(rows).unwrap_or(0) as u32,
            cols: num(cols).unwrap_or(0) as u32,
            cwd: lines.next()?.to_vec(),
            command: lines.next().unwrap_or_default().to_vec(),
        })
    }
}

/// `b` with each newline written `\n` (and each backslash `\\`), for a
/// one-line log.
pub fn escape_newlines(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    for &c in b {
        match c {
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            c => out.push(c),
        }
    }
    out
}

/// A session's id from its sequence number: six base-36 digits.
pub fn id_of(n: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut d = [b'0'; 6];
    let mut n = n % 36u64.pow(6);
    for slot in d.iter_mut().rev() {
        *slot = DIGITS[(n % 36) as usize];
        n /= 36;
    }
    String::from_utf8_lossy(&d).into_owned()
}

/// The sequence number of an id (`000001`, or `00/00/01`).
pub fn number_of(id: &str) -> Option<u64> {
    let digits: String = id.chars().filter(|&c| c != '/').collect();
    if digits.len() != 6 {
        return None;
    }
    digits.chars().try_fold(0u64, |n, c| Some(n * 36 + u64::from(c.to_digit(36)?)))
}

/// A session's directory under `dir`.
pub fn path_of(dir: &[u8], id: &str) -> Vec<u8> {
    let d = id.as_bytes();
    [dir, b"/", &d[..2], b"/", &d[2..4], b"/", &d[4..]].concat()
}

/// A `timing` line for an event `delay_ns` after the one before.
pub fn timing_line(kind: u8, delay_ns: u64, rest: &str) -> String {
    format!("{kind} {}.{:06} {rest}\n", delay_ns / 1_000_000_000, delay_ns % 1_000_000_000 / 1000)
}

/// One `timing` event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Data { stream: usize, delay_ns: u64, size: usize },
    Size { delay_ns: u64, rows: u32, cols: u32 },
    Signal { delay_ns: u64, name: String },
}

/// Parse a `timing` line.
pub fn parse_timing(line: &str) -> Option<Event> {
    let mut w = line.split_ascii_whitespace();
    let kind: u8 = w.next()?.parse().ok()?;
    let delay = w.next()?;
    let (s, frac) = delay.split_once('.').unwrap_or((delay, ""));
    let mut ns: u64 = s.parse::<u64>().ok()?.checked_mul(1_000_000_000)?;
    if !frac.is_empty() {
        let digits = &frac[..frac.len().min(9)];
        ns += digits.parse::<u64>().ok()? * 10u64.pow(9 - digits.len() as u32);
    }
    match kind {
        0..=4 => Some(Event::Data { stream: kind as usize, delay_ns: ns, size: w.next()?.parse().ok()? }),
        5 => Some(Event::Size { delay_ns: ns, rows: w.next()?.parse().ok()?, cols: w.next()?.parse().ok()? }),
        6 => Some(Event::Signal { delay_ns: ns, name: String::from(w.next()?) }),
        _ => None,
    }
}

/// The open files of a session being recorded: `timing`, then the five
/// streams, and which of them to record.
#[derive(Debug)]
pub struct Recorder {
    timing: i32,
    streams: [i32; 5],
    pub input: bool,
    pub output: bool,
    last: u64,
}

impl Recorder {
    /// Take the broker's descriptors (`timing` and the five streams) and
    /// its `log=` word (`i` input, `o` output).
    pub fn new(fds: &[i32], what: &[u8]) -> Option<Recorder> {
        let [timing, a, b, c, d, e] = fds[..] else { return None };
        Some(Recorder {
            timing,
            streams: [a, b, c, d, e],
            input: what.contains(&b'i'),
            output: what.contains(&b'o'),
            last: slate_rt::time::monotonic_ns(),
        })
    }

    /// Whether `s` is recorded.
    pub fn wants(&self, s: Stream) -> bool {
        match s {
            Stream::Stdin | Stream::TtyIn => self.input,
            _ => self.output,
        }
    }

    fn delay(&mut self) -> u64 {
        let now = slate_rt::time::monotonic_ns();
        let d = now.saturating_sub(self.last);
        self.last = now;
        d
    }

    /// Record `data` on `s`, if that stream is recorded.
    pub fn data(&mut self, s: Stream, data: &[u8]) {
        if data.is_empty() || !self.wants(s) {
            return;
        }
        let d = self.delay();
        let _ = io::write_all(self.streams[s as usize], data);
        let _ = io::write_all(self.timing, timing_line(s as u8, d, &format!("{}", data.len())).as_bytes());
    }

    /// The terminal's size changed.
    pub fn size(&mut self, rows: u32, cols: u32) {
        let d = self.delay();
        let _ = io::write_all(self.timing, timing_line(5, d, &format!("{rows} {cols}")).as_bytes());
    }

    /// The command stopped or went on (`SIGTSTP`, `SIGCONT`).
    pub fn signal(&mut self, name: &str) {
        let d = self.delay();
        let _ = io::write_all(self.timing, timing_line(6, d, name).as_bytes());
    }

    /// Close the files (before the command runs, in its process).
    pub fn close(&self) {
        let _ = io::close(self.timing);
        for &fd in &self.streams {
            let _ = io::close(fd);
        }
    }
}

/// Make a new session for `info` (as root): its directory and files.
/// Returns its id and the open `timing` and stream files, to hand over.
pub fn create(info: &Info) -> Result<(String, Vec<i32>), String> {
    use fs::{O_APPEND, O_CLOEXEC, O_CREAT, O_EXCL, O_WRONLY};
    let _ = fs::mkdir(b"/var/log", 0o755);
    let _ = fs::mkdir(DIR, 0o700);
    let seq_path = [DIR, b"/seq"].concat();
    let mut n =
        fs::read_file(&seq_path).ok().and_then(|s| number_of(core::str::from_utf8(&s).ok()?.trim())).unwrap_or(0);
    // Requests are served side by side: the session's directory, made
    // exclusively, decides who has a number.
    let (id, path) = loop {
        n += 1;
        let id = id_of(n);
        let path = path_of(DIR, &id);
        let parent = fs::dirname(&path).to_vec();
        let _ = fs::mkdir(fs::dirname(&parent), 0o700);
        let _ = fs::mkdir(&parent, 0o700);
        match fs::mkdir(&path, 0o700) {
            Ok(()) => break (id, path),
            Err(slate_rt::errno::Errno::EEXIST) if n % 36u64.pow(6) != 0 => continue,
            Err(e) => return Err(format!("cannot make the I/O log {}: {e}", String::from_utf8_lossy(&path))),
        }
    };
    let _ = fs::write_file(&seq_path, format!("{id}\n").as_bytes(), 0o600);
    fs::write_file(&fs::join(&path, b"log"), &info.encode(), 0o600).map_err(|e| format!("writing the I/O log: {e}"))?;
    let mut fds = Vec::new();
    for name in core::iter::once("timing").chain(STREAMS) {
        match fs::open(&fs::join(&path, name.as_bytes()), O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0o600) {
            Ok(fd) => fds.push(fd),
            Err(e) => {
                for fd in fds {
                    let _ = io::close(fd);
                }
                return Err(format!("writing the I/O log: {e}"));
            }
        }
    }
    Ok((id, fds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert_eq!(id_of(1), "000001");
        assert_eq!(id_of(36), "000010");
        assert_eq!(id_of(36 * 36 * 36 + 35), "00100Z");
        assert_eq!(number_of("00/00/1Z"), Some(71));
        assert_eq!(number_of("0001"), None);
        assert_eq!(path_of(DIR, "0000AB"), b"/var/log/sudo-io/00/00/AB".to_vec());
    }

    #[test]
    fn log_and_timing() {
        let info = Info {
            time: 1_800_000_000,
            user: b"ann".to_vec(),
            runas_user: b"root".to_vec(),
            runas_group: b"root".to_vec(),
            tty: b"/dev/pts/0".to_vec(),
            rows: 24,
            cols: 80,
            cwd: b"/home/ann".to_vec(),
            command: b"/bin/echo a\nb".to_vec(),
        };
        let text = info.encode();
        assert_eq!(text, b"1800000000:ann:root:root:/dev/pts/0:24:80\n/home/ann\n/bin/echo a\\nb\n".to_vec());
        let back = Info::decode(&text).unwrap();
        assert_eq!(back.command, b"/bin/echo a\\nb".to_vec());
        assert_eq!(Info { command: info.command.clone(), ..back }, info);
        let line = timing_line(4, 1_500_000_000, "12");
        assert_eq!(line, "4 1.500000 12\n");
        assert_eq!(parse_timing(&line), Some(Event::Data { stream: 4, delay_ns: 1_500_000_000, size: 12 }));
        assert_eq!(parse_timing("5 0.25 30 100"), Some(Event::Size { delay_ns: 250_000_000, rows: 30, cols: 100 }));
        assert_eq!(
            parse_timing("6 2 SIGTSTP"),
            Some(Event::Signal { delay_ns: 2_000_000_000, name: "SIGTSTP".into() })
        );
        assert_eq!(parse_timing("9 1 1"), None);
        assert_eq!(escape_newlines(b"a\\b\nc"), b"a\\\\b\\nc".to_vec());
    }
}
