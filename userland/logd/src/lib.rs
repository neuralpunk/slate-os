// SPDX-License-Identifier: MIT OR Apache-2.0

//! logd, Slate's system log (ADR 0060), and its tools:
//!
//! - `logd` receives syslog(3) datagrams on /dev/log and follows the
//!   kernel log, writing both to /var/log/messages (renamed to
//!   `messages.1` past 1 MiB);
//! - `logread [-f] [-n N] [-k] [-s SERVICE]` shows it, or a service's log
//!   that slinit keeps;
//! - `logger [-i] [-s] [-t TAG] [-p PRIORITY] [message...]` writes to it
//!   (POSIX logger, with util-linux's common options).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

use slate_rt::logfile::{self, LogFile};
use slate_rt::{fs, io, lossy, net, process, syslog, time};

const MESSAGES: &[u8] = b"/var/log/messages";
const SERVICE_LOGS: &[u8] = b"/var/log/services";
const LIMIT: u64 = 1024 * 1024;
/// How far logd has read the kernel log (survives a restart of logd,
/// not a reboot).
const KERNEL_POS: &[u8] = b"/run/logd.kpos";

fn fail(msg: impl core::fmt::Display) -> i32 {
    io::err(alloc::format!("{}: {msg}\n", slate_rt::prog_name()).as_bytes());
    1
}

pub fn main() -> i32 {
    let args = slate_rt::env::args();
    match slate_rt::prog_name().as_str() {
        "logread" => logread(args),
        "logger" => logger(args),
        _ => daemon(),
    }
}

// --- the daemon ---------------------------------------------------------------

/// A syslog datagram as a log line's text: `HOST TAG[PID]: MESSAGE`.
/// The `<PRI>` and the sender's timestamp go (the log has its own);
/// newlines and other control characters become spaces.
pub fn datagram_text(d: &[u8], host: &[u8]) -> Vec<u8> {
    let mut rest = d;
    if rest.first() == Some(&b'<')
        && let Some(end) = rest.iter().take(5).position(|&c| c == b'>')
    {
        rest = &rest[end + 1..];
    }
    // `Mmm dd hh:mm:ss ` (RFC 3164's TIMESTAMP).
    if rest.len() >= 16
        && rest[..3].iter().all(u8::is_ascii_alphabetic)
        && rest[3] == b' '
        && rest[6] == b' '
        && rest[9] == b':'
        && rest[12] == b':'
        && rest[15] == b' '
    {
        rest = &rest[16..];
    }
    while rest.last().is_some_and(|&c| c == b'\n' || c == 0) {
        rest = &rest[..rest.len() - 1];
    }
    let mut out = host.to_vec();
    out.push(b' ');
    out.extend(rest.iter().map(|&c| if c < 0x20 || c == 0x7f { b' ' } else { c }));
    out
}

fn host() -> Vec<u8> {
    process::uname()[1].clone()
}

fn daemon() -> i32 {
    let fd = match net::dgram_bind_path(syslog::PATH) {
        Ok(fd) => fd,
        Err(e) => return fail(alloc::format!("{}: {e}", lossy(syslog::PATH))),
    };
    // Everyone may log.
    let _ = fs::chmod(syslog::PATH, 0o666);
    let _ = process::fcntl(fd, process::F_SETFL, fs::O_NONBLOCK as usize);
    let mut log = LogFile::new(MESSAGES, LIMIT, 0o600);
    let mut kpos: u64 =
        fs::read_file(KERNEL_POS).ok().and_then(|t| core::str::from_utf8(&t).ok()?.trim().parse().ok()).unwrap_or(0);
    log.append(&logfile::line(&[host().as_slice(), b" logd: started"].concat()));
    let mut buf = alloc::vec![0u8; 8192];
    loop {
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        let _ = io::poll(&mut p, 1000);
        let h = host();
        let mut lines = Vec::new();
        while let Ok(n) = net::recv(fd, &mut buf) {
            if n == 0 {
                break;
            }
            lines.extend(logfile::line(&datagram_text(&buf[..n], &h)));
        }
        // The kernel's lines since last time.
        let before = kpos;
        while let Ok(n) = process::kernel_log_from(&mut buf, &mut kpos) {
            if n == 0 {
                break;
            }
            for l in buf[..n].split(|&c| c == b'\n').filter(|l| !l.is_empty()) {
                lines.extend(logfile::line(&[h.as_slice(), b" kernel: ", l].concat()));
            }
        }
        if kpos != before {
            let _ = fs::write_file(KERNEL_POS, alloc::format!("{kpos}\n").as_bytes(), 0o600);
        }
        if lines.is_empty() {
            log.flush();
        } else {
            log.append(&lines);
        }
    }
}

// --- logread ---------------------------------------------------------------

/// The last `n` lines of `text` (all of them for None).
pub fn last_lines(text: &[u8], n: Option<usize>) -> &[u8] {
    let Some(n) = n else { return text };
    if n == 0 {
        return &[];
    }
    let body = text.strip_suffix(b"\n").unwrap_or(text);
    let mut seen = 0;
    for (i, &c) in body.iter().enumerate().rev() {
        if c == b'\n' {
            seen += 1;
            if seen == n {
                return &text[i + 1..];
            }
        }
    }
    text
}

/// Whether a line of /var/log/messages came from the kernel.
fn is_kernel(line: &[u8]) -> bool {
    line.split(|&c| c == b' ').nth(2) == Some(b"kernel:")
}

fn filter(text: &[u8], kernel: bool) -> Vec<u8> {
    if !kernel {
        return text.to_vec();
    }
    let mut out = Vec::new();
    for l in text.split_inclusive(|&c| c == b'\n') {
        if is_kernel(l) {
            out.extend_from_slice(l);
        }
    }
    out
}

fn logread(args: &[Vec<u8>]) -> i32 {
    let (mut follow, mut kernel, mut count, mut service) = (false, false, None, None::<Vec<u8>>);
    let mut i = 1;
    while i < args.len() {
        match args[i].as_slice() {
            b"-f" => follow = true,
            b"-k" => kernel = true,
            b"-n" | b"-s" => {
                let Some(v) = args.get(i + 1) else { return usage_logread() };
                if args[i] == b"-n" {
                    match core::str::from_utf8(v).ok().and_then(|t| t.parse().ok()) {
                        Some(n) => count = Some(n),
                        None => return usage_logread(),
                    }
                } else {
                    service = Some(v.clone());
                }
                i += 1;
            }
            _ => return usage_logread(),
        }
        i += 1;
    }
    let path = match &service {
        Some(s) if s.contains(&b'/') || s.starts_with(b".") => return fail("bad service name"),
        Some(s) => [SERVICE_LOGS, b"/", s, b".log"].concat(),
        None => MESSAGES.to_vec(),
    };
    let old = fs::read_file(&[path.as_slice(), b".1"].concat()).unwrap_or_default();
    let now = match fs::read_file(&path) {
        Ok(t) => t,
        Err(slate_rt::Errno::ENOENT) if !old.is_empty() || follow => Vec::new(),
        Err(slate_rt::Errno::ENOENT) if service.is_some() => {
            return fail(alloc::format!("no log for {}", lossy(service.as_deref().unwrap_or_default())));
        }
        Err(e) => return fail(alloc::format!("{}: {e}", lossy(&path))),
    };
    let all = filter(&[old.as_slice(), &now].concat(), kernel);
    io::out(last_lines(&all, count));
    if !follow {
        return 0;
    }
    // Follow: what is added, from the start again after a rotation.
    let mut offset = now.len();
    let mut partial: Vec<u8> = Vec::new();
    loop {
        io::flush_stdout();
        time::sleep_ns(300_000_000);
        let size = fs::stat(&path).map_or(0, |s| s.size.max(0) as usize);
        if size < offset {
            offset = 0;
        }
        if size == offset {
            continue;
        }
        let Ok(fd) = fs::open(&path, fs::O_RDONLY | fs::O_CLOEXEC, 0) else { continue };
        let mut chunk = alloc::vec![0u8; size - offset];
        let n = io::pread(fd, &mut chunk, offset as u64).unwrap_or(0);
        let _ = io::close(fd);
        offset += n;
        partial.extend_from_slice(&chunk[..n]);
        if let Some(end) = partial.iter().rposition(|&c| c == b'\n') {
            let whole: Vec<u8> = partial.drain(..=end).collect();
            io::out(&filter(&whole, kernel));
        }
    }
}

fn usage_logread() -> i32 {
    io::err(b"usage: logread [-f] [-k] [-n LINES] [-s SERVICE]\n");
    2
}

// --- logger --------------------------------------------------------------

/// `facility.level`, a level alone (facility `user`), or a number
/// (syslog(3)'s names, as logger(1) takes them).
pub fn parse_priority(p: &[u8]) -> Option<u8> {
    if let Some(n) = core::str::from_utf8(p).ok().and_then(|t| t.parse::<u8>().ok()) {
        return Some(n);
    }
    const FACILITIES: [(&[u8], u8); 20] = [
        (b"kern", syslog::LOG_KERN),
        (b"user", syslog::LOG_USER),
        (b"mail", syslog::LOG_MAIL),
        (b"daemon", syslog::LOG_DAEMON),
        (b"auth", syslog::LOG_AUTH),
        (b"security", syslog::LOG_AUTH),
        (b"syslog", syslog::LOG_SYSLOG),
        (b"lpr", syslog::LOG_LPR),
        (b"news", syslog::LOG_NEWS),
        (b"uucp", syslog::LOG_UUCP),
        (b"cron", syslog::LOG_CRON),
        (b"authpriv", syslog::LOG_AUTHPRIV),
        (b"ftp", syslog::LOG_FTP),
        (b"local0", syslog::LOG_LOCAL0),
        (b"local1", syslog::LOG_LOCAL0 + 8),
        (b"local2", syslog::LOG_LOCAL0 + 16),
        (b"local3", syslog::LOG_LOCAL0 + 24),
        (b"local4", syslog::LOG_LOCAL0 + 32),
        (b"local5", syslog::LOG_LOCAL0 + 40),
        (b"local6", syslog::LOG_LOCAL0 + 48),
    ];
    const LEVELS: [(&[u8], u8); 11] = [
        (b"emerg", syslog::LOG_EMERG),
        (b"panic", syslog::LOG_EMERG),
        (b"alert", syslog::LOG_ALERT),
        (b"crit", syslog::LOG_CRIT),
        (b"err", syslog::LOG_ERR),
        (b"error", syslog::LOG_ERR),
        (b"warning", syslog::LOG_WARNING),
        (b"warn", syslog::LOG_WARNING),
        (b"notice", syslog::LOG_NOTICE),
        (b"info", syslog::LOG_INFO),
        (b"debug", syslog::LOG_DEBUG),
    ];
    let (fac, lev) = match p.iter().position(|&c| c == b'.') {
        Some(d) => (&p[..d], &p[d + 1..]),
        None => (&b"user"[..], p),
    };
    let fac = if fac == b"local7" { syslog::LOG_LOCAL0 + 56 } else { FACILITIES.iter().find(|f| f.0 == fac)?.1 };
    Some(fac | LEVELS.iter().find(|l| l.0 == lev)?.1)
}

fn logger(args: &[Vec<u8>]) -> i32 {
    let mut tag: Option<Vec<u8>> = None;
    let mut priority = syslog::LOG_USER | syslog::LOG_NOTICE;
    let (mut with_pid, mut stderr) = (false, false);
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        match a.as_slice() {
            b"--" => {
                i += 1;
                break;
            }
            b"-i" => with_pid = true,
            b"-s" => stderr = true,
            b"-t" | b"-p" => {
                let Some(v) = args.get(i + 1) else { return usage_logger() };
                if a == b"-t" {
                    tag = Some(v.clone());
                } else {
                    match parse_priority(v) {
                        Some(p) => priority = p,
                        None => return fail(alloc::format!("unknown priority name: {}", lossy(v))),
                    }
                }
                i += 1;
            }
            _ if a.len() > 1 && a[0] == b'-' => return usage_logger(),
            _ => break,
        }
        i += 1;
    }
    let tag = tag.unwrap_or_else(|| {
        slate_rt::env::var(b"LOGNAME").or_else(|| slate_rt::env::var(b"USER")).unwrap_or_else(|| b"logger".to_vec())
    });
    let messages: Vec<Vec<u8>> = if i < args.len() {
        alloc::vec![args[i..].join(&b' ')]
    } else {
        io::read_to_end(io::STDIN)
            .unwrap_or_default()
            .split(|&c| c == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    };
    let fd = match net::dgram_socket() {
        Ok(fd) => fd,
        Err(e) => return fail(e),
    };
    let pid = with_pid.then(process::getpid);
    let mut st = 0;
    for m in messages {
        if stderr {
            io::err(&[tag.as_slice(), b": ", &m, b"\n"].concat());
        }
        if let Err(e) = net::dgram_send_path(fd, syslog::PATH, &syslog::format(priority, &tag, pid, &m)) {
            st = fail(alloc::format!("{}: {e}", lossy(syslog::PATH)));
            break;
        }
    }
    let _ = io::close(fd);
    st
}

fn usage_logger() -> i32 {
    io::err(b"usage: logger [-i] [-s] [-t TAG] [-p PRIORITY] [message...]\n");
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagrams() {
        assert_eq!(datagram_text(b"<13>Oct 22 14:03:01 sshd[42]: hello\n", b"slate"), b"slate sshd[42]: hello");
        assert_eq!(datagram_text(b"<30>Oct  2 04:03:01 netd: up", b"h"), b"h netd: up");
        // No timestamp, and control characters.
        assert_eq!(datagram_text(b"<14>app: a\nb\x07c\0", b"h"), b"h app: a b c");
        assert_eq!(datagram_text(b"plain text", b"h"), b"h plain text");
    }

    #[test]
    fn priorities() {
        assert_eq!(parse_priority(b"user.notice"), Some(13));
        assert_eq!(parse_priority(b"err"), Some(11));
        assert_eq!(parse_priority(b"daemon.warning"), Some(28));
        assert_eq!(parse_priority(b"local7.debug"), Some(191));
        assert_eq!(parse_priority(b"auth.info"), Some(38));
        assert_eq!(parse_priority(b"30"), Some(30));
        assert_eq!(parse_priority(b"bogus.info"), None);
        assert_eq!(parse_priority(b"user.loud"), None);
    }

    #[test]
    fn tails() {
        let t = b"a\nb\nc\n";
        assert_eq!(last_lines(t, None), t);
        assert_eq!(last_lines(t, Some(2)), b"b\nc\n");
        assert_eq!(last_lines(t, Some(5)), t);
        assert_eq!(last_lines(t, Some(0)), b"");
        let k = b"2026-10-22T10:00:00+00:00 h kernel: [ 0.1] info x\n2026-10-22T10:00:01+00:00 h sshd[1]: y\n";
        assert_eq!(filter(k, true), b"2026-10-22T10:00:00+00:00 h kernel: [ 0.1] info x\n");
    }
}
