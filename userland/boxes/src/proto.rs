// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-boxd's protocol: one request per connection, a line of fields
//! separated by tabs; the answer is lines, each a word, a tab and the
//! rest: `say TEXT` (what to show while it works), `is KEY\tVALUE` (a
//! fact), and last `ok` or `error TEXT`.
//!
//! Requests: `distros`; `create NAME DISTRO FROM MIRROR` (empty when not
//! given); `list`; `open
//! NAME`; `map PID NAME`; `remove NAME`.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{io, net};

/// A request's line.
pub fn line(fields: &[&str]) -> String {
    let mut s = fields.iter().map(|f| f.replace(['\t', '\n'], " ")).collect::<Vec<_>>().join("\t");
    s.push('\n');
    s
}

/// A request's fields.
pub fn fields(line: &str) -> Vec<String> {
    line.trim_end_matches('\n').split('\t').map(String::from).collect()
}

/// One line of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    Say(String),
    Is(String, String),
    Ok,
    Error(String),
}

impl Answer {
    pub fn parse(line: &str) -> Option<Answer> {
        let (word, rest) = line.split_once('\t').unwrap_or((line, ""));
        Some(match word {
            "say" => Answer::Say(String::from(rest)),
            "is" => {
                let (k, v) = rest.split_once('\t').unwrap_or((rest, ""));
                Answer::Is(String::from(k), String::from(v))
            }
            "ok" => Answer::Ok,
            "error" => Answer::Error(String::from(rest)),
            _ => return None,
        })
    }

    pub fn text(&self) -> String {
        let clean = |s: &str| s.replace('\n', " ");
        match self {
            Answer::Say(s) => format!("say\t{}\n", clean(s)),
            Answer::Is(k, v) => format!("is\t{}\t{}\n", clean(k), clean(v)),
            Answer::Ok => String::from("ok\n"),
            Answer::Error(e) => format!("error\t{}\n", clean(e)),
        }
    }
}

/// The facts of an answer.
pub type Facts = Vec<(String, String)>;

/// The value of fact `key`.
pub fn fact<'a>(facts: &'a Facts, key: &str) -> Option<&'a str> {
    facts.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// Ask slate-boxd: its facts, each `say` passed to `say` as it comes.
pub fn ask(fields: &[&str], say: &mut dyn FnMut(&str)) -> Result<Facts, String> {
    let fd = net::connect_path(crate::SOCKET.as_bytes()).map_err(|e| {
        format!("slate-boxd isn't answering ({e}); is the service running? (service slate-boxd status)")
    })?;
    let r = (|| {
        io::write_all(fd, line(fields).as_bytes()).map_err(|e| format!("slate-boxd: {e}"))?;
        let mut facts = Vec::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            while let Some(at) = pending.iter().position(|&b| b == b'\n') {
                let l: Vec<u8> = pending.drain(..=at).collect();
                match Answer::parse(slate_rt::lossy(&l[..l.len() - 1]).as_ref()) {
                    Some(Answer::Say(s)) => say(&s),
                    Some(Answer::Is(k, v)) => facts.push((k, v)),
                    Some(Answer::Ok) => return Ok(facts),
                    Some(Answer::Error(e)) => return Err(e),
                    None => {}
                }
            }
            match io::read(fd, &mut buf) {
                Ok(0) => {
                    return Err(String::from("slate-boxd ended without an answer (its log: service slate-boxd log)"));
                }
                Ok(n) => pending.extend_from_slice(&buf[..n]),
                Err(slate_rt::Errno::EINTR) => {}
                Err(e) => return Err(format!("slate-boxd: {e}")),
            }
        }
    })();
    let _ = io::close(fd);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines() {
        assert_eq!(line(&["create", "dev", "arch"]), "create\tdev\tarch\n");
        assert_eq!(fields("map\t42\tdev\n"), ["map", "42", "dev"]);
        assert_eq!(line(&["a\tb", "c\nd"]), "a b\tc d\n");
        for a in [
            Answer::Say("fetching 12 MB".into()),
            Answer::Is("root".into(), "/var/lib/slate/boxes/1000/dev".into()),
            Answer::Ok,
            Answer::Error("no such box".into()),
        ] {
            assert_eq!(Answer::parse(a.text().trim_end_matches('\n')), Some(a));
        }
        assert_eq!(Answer::parse("hello"), None);
    }
}
