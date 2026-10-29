// SPDX-License-Identifier: MIT OR Apache-2.0

//! syslog(3) for Slate's programs: one datagram to /dev/log, in the
//! format musl's and glibc's syslog send, `<PRI>Mmm dd hh:mm:ss
//! TAG[PID]: MESSAGE` (RFC 3164 describes it), read by logd (ADR 0060).

use alloc::vec::Vec;

// Levels and facilities (musl `syslog.h`).
pub const LOG_EMERG: u8 = 0;
pub const LOG_ALERT: u8 = 1;
pub const LOG_CRIT: u8 = 2;
pub const LOG_ERR: u8 = 3;
pub const LOG_WARNING: u8 = 4;
pub const LOG_NOTICE: u8 = 5;
pub const LOG_INFO: u8 = 6;
pub const LOG_DEBUG: u8 = 7;
pub const LOG_KERN: u8 = 0 << 3;
pub const LOG_USER: u8 = 1 << 3;
pub const LOG_MAIL: u8 = 2 << 3;
pub const LOG_DAEMON: u8 = 3 << 3;
pub const LOG_AUTH: u8 = 4 << 3;
pub const LOG_SYSLOG: u8 = 5 << 3;
pub const LOG_LPR: u8 = 6 << 3;
pub const LOG_NEWS: u8 = 7 << 3;
pub const LOG_UUCP: u8 = 8 << 3;
pub const LOG_CRON: u8 = 9 << 3;
pub const LOG_AUTHPRIV: u8 = 10 << 3;
pub const LOG_FTP: u8 = 11 << 3;
pub const LOG_LOCAL0: u8 = 16 << 3;

/// Where the log listens.
pub const PATH: &[u8] = b"/dev/log";

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// The datagram for `priority` (facility | level), `tag` and `msg`.
pub fn format(priority: u8, tag: &[u8], pid: Option<i32>, msg: &[u8]) -> Vec<u8> {
    let tm = crate::tz::localtime(crate::time::unix());
    let mut d = alloc::format!(
        "<{priority}>{} {:2} {:02}:{:02}:{:02} ",
        MONTHS[(tm.month.clamp(1, 12) - 1) as usize],
        tm.day,
        tm.hour,
        tm.min,
        tm.sec
    )
    .into_bytes();
    d.extend_from_slice(tag);
    if let Some(pid) = pid {
        d.extend_from_slice(alloc::format!("[{pid}]").as_bytes());
    }
    d.extend_from_slice(b": ");
    d.extend_from_slice(msg);
    d
}

/// Send one message to the system log (dropped if logd is not running).
pub fn syslog(priority: u8, tag: &[u8], msg: &[u8]) -> crate::Result<()> {
    let fd = crate::net::dgram_socket()?;
    let r = crate::net::dgram_send_path(fd, PATH, &format(priority, tag, Some(crate::process::getpid()), msg));
    let _ = crate::io::close(fd);
    r.map(|_| ())
}
