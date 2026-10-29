// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strata's link to `slate-brokerd` (ADR 0037): it registers as the
//! session's approval agent, so a program asking the broker for a system
//! action gets Strata's dialog, and it asks for Strata's own launcher
//! actions. The messages are the broker's: newline-separated fields ending
//! with an empty line (userland/login/src/broker.rs).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{io, lossy, net};

pub const BROKER: &[u8] = b"slate-broker";

/// What the broker says to the agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Show the dialog: the action, who asks (program and pid), for which
    /// user, and the last try's error.
    Ask { action: String, requester: String, pid: i32, user: String, error: Option<String> },
    /// The request is over: close the dialog.
    Done,
}

/// Parse one message's fields.
pub fn parse(msg: &[u8]) -> Option<Message> {
    let text = String::from(lossy(msg));
    let f: Vec<&str> = text.split('\n').collect();
    match f[..] {
        ["ask", action, requester, pid, user, error] => Some(Message::Ask {
            action: String::from(action),
            requester: String::from(requester),
            pid: pid.parse().unwrap_or(0),
            user: String::from(user),
            error: (error != "-").then(|| String::from(error)),
        }),
        ["done"] => Some(Message::Done),
        _ => None,
    }
}

#[derive(Debug)]
pub struct Agent {
    fd: i32,
    buf: Vec<u8>,
}

impl Agent {
    /// Register with the broker; None if it is not running or refuses.
    pub fn register() -> Option<Agent> {
        let fd = net::connect(BROKER).ok()?;
        io::write_all(fd, b"agent\n\n").ok()?;
        let mut p = [io::PollFd { fd, events: io::POLLIN, revents: 0 }];
        let mut reply = [0u8; 64];
        let n = if io::poll(&mut p, 2000).unwrap_or(0) > 0 { io::read(fd, &mut reply).unwrap_or(0) } else { 0 };
        if reply[..n].starts_with(b"ok") {
            Some(Agent { fd, buf: Vec::new() })
        } else {
            let _ = io::close(fd);
            None
        }
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Read what the broker sent; None when the link broke.
    pub fn read(&mut self) -> Option<Vec<Message>> {
        let mut chunk = [0u8; 1024];
        let n = io::read(self.fd, &mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        self.buf.extend_from_slice(&chunk[..n]);
        let mut out = Vec::new();
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let msg: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
            out.extend(parse(&msg));
        }
        Some(out)
    }

    /// Answer an `ask` with the password typed.
    pub fn answer(&self, password: &str) {
        let mut m = b"password\n".to_vec();
        m.extend(password.bytes().filter(|&b| b != b'\n'));
        m.extend_from_slice(b"\n\n");
        let _ = io::write_all(self.fd, &m);
    }

    pub fn cancel(&self) {
        let _ = io::write_all(self.fd, b"cancel\n\n");
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = io::close(self.fd);
    }
}

/// Send the broker a request of these fields; its answer.
pub fn ask(fields: &[&[u8]]) -> Result<(), String> {
    let fd = net::connect(BROKER).map_err(|e| alloc::format!("the privilege broker is not running ({e})"))?;
    let mut m = fields.join(&b'\n');
    m.extend_from_slice(b"\n\n");
    let r = io::write_all(fd, &m).and_then(|()| io::read_to_end(fd));
    let _ = io::close(fd);
    let reply = r.map_err(|e| alloc::format!("{e}"))?;
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]);
    if line == b"ok" { Ok(()) } else { Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(line)))) }
}

/// Ask the broker for an action: with the password Strata's dialog took,
/// with an account change's new password (ADR 0110), or with none (the
/// broker then asks the agent).
pub fn request(action: &str, password: &str) -> Result<(), String> {
    let fd = net::connect(BROKER).map_err(|e| alloc::format!("the privilege broker is not running ({e})"))?;
    let mut m = alloc::format!("action\n{action}").into_bytes();
    // Without a password the field is left out, so the broker asks the
    // agent.
    if !password.is_empty() {
        m.push(b'\n');
        m.extend(password.bytes().filter(|&b| b != b'\n'));
    }
    m.extend_from_slice(b"\n\n");
    let r = io::write_all(fd, &m).and_then(|()| io::read_to_end(fd));
    let _ = io::close(fd);
    let reply = r.map_err(|e| alloc::format!("{e}"))?;
    let line = reply.split(|&c| c == b'\n').next().unwrap_or(&[]);
    if line == b"ok" { Ok(()) } else { Err(String::from(lossy(line.strip_prefix(b"error: ").unwrap_or(line)))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages() {
        assert_eq!(
            parse(b"ask\nrestart\nslate-approve\n42\ntester\n-"),
            Some(Message::Ask {
                action: "restart".into(),
                requester: "slate-approve".into(),
                pid: 42,
                user: "tester".into(),
                error: None
            })
        );
        assert!(matches!(
            parse(b"ask\nrollback\n?\n7\nada\nThat password didn't work."),
            Some(Message::Ask { error: Some(_), .. })
        ));
        assert_eq!(parse(b"done"), Some(Message::Done));
        assert_eq!(parse(b"nonsense"), None);
    }
}
