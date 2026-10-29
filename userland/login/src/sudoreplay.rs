// SPDX-License-Identifier: MIT OR Apache-2.0

//! sudoreplay (ADR 0159): list sudo's I/O logs, or play one back at the
//! pace it was recorded, as sudoreplay(8) does. `-l` lists the sessions,
//! narrowed by `user`, `runas`, `tty`, `cwd` and `command` (a part of
//! the command) pairs, all of which must hold; `ID` plays a session's
//! output (`-f` picks the streams: stdin, stdout, stderr, ttyin, ttyout;
//! stdout, stderr and ttyout by default), `-s` divides its pauses, `-m`
//! caps them (seconds), `-d` reads another directory.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{env, fs, io, lossy};

use crate::iolog::{self, Event, Info, STREAMS};

const USAGE: &str = "usage: sudoreplay [-d dir] [-f filter] [-m max_wait] [-s speed_factor] ID
       sudoreplay [-d dir] -l [user NAME] [runas NAME] [tty TTY] [cwd DIR] [command TEXT]
";

fn fail(code: i32, msg: impl core::fmt::Display) -> i32 {
    slate_rt::eprintln!("sudoreplay: {msg}");
    code
}

/// What the command line asks for.
#[derive(Debug, PartialEq)]
pub struct Options {
    pub dir: Vec<u8>,
    pub list: bool,
    /// The streams played, by `timing` type.
    pub streams: [bool; 5],
    pub max_wait: Option<f64>,
    pub speed: f64,
    /// The session's id, or the `-l` search's words.
    pub rest: Vec<Vec<u8>>,
}

pub fn parse(args: &[Vec<u8>]) -> Result<Options, String> {
    let mut o = Options {
        dir: iolog::DIR.to_vec(),
        list: false,
        streams: [false, true, true, false, true],
        max_wait: None,
        speed: 1.0,
        rest: Vec::new(),
    };
    let mut i = 0;
    let float = |v: Option<&Vec<u8>>| -> Result<f64, String> {
        let v = v.ok_or("an option needs a value")?;
        let s = core::str::from_utf8(v).map_err(|_| "not a number")?;
        s.parse::<f64>().ok().filter(|f| *f >= 0.0).ok_or_else(|| format!("{s}: not a number"))
    };
    while i < args.len() {
        let a = args[i].as_slice();
        match a {
            b"-l" | b"--list" => o.list = true,
            b"-d" | b"--directory" => {
                i += 1;
                o.dir = args.get(i).ok_or("-d needs a directory")?.clone();
            }
            b"-f" | b"--filter" => {
                i += 1;
                let f = args.get(i).ok_or("-f needs streams")?;
                o.streams = [false; 5];
                for name in f.split(|&c| c == b',') {
                    let k = STREAMS
                        .iter()
                        .position(|s| s.as_bytes() == name)
                        .ok_or_else(|| format!("{}: not a stream", lossy(name)))?;
                    o.streams[k] = true;
                }
            }
            b"-m" | b"--max-wait" => {
                i += 1;
                o.max_wait = Some(float(args.get(i))?);
            }
            b"-s" | b"--speed" => {
                i += 1;
                o.speed = float(args.get(i))?;
                if o.speed == 0.0 {
                    return Err("the speed factor must be more than 0".into());
                }
            }
            b"--" => {
                o.rest.extend(args[i + 1..].iter().cloned());
                break;
            }
            _ if a.starts_with(b"-") && a.len() > 1 => return Err(format!("unknown option {}", lossy(a))),
            _ => o.rest.push(a.to_vec()),
        }
        i += 1;
    }
    if !o.list && o.rest.len() != 1 {
        return Err("one session ID, or -l".into());
    }
    Ok(o)
}

/// Whether a session's `log` matches the `-l` search's pairs.
pub fn matches(info: &Info, search: &[Vec<u8>]) -> Result<bool, String> {
    let mut ok = true;
    for pair in search.chunks(2) {
        let [key, value] = pair else { return Err("a search word needs a value".into()) };
        let hit = match key.as_slice() {
            b"user" => info.user == *value,
            b"runas" => info.runas_user == *value,
            b"tty" => info.tty == *value || info.tty.strip_prefix(b"/dev/") == Some(value.as_slice()),
            b"cwd" => info.cwd == *value,
            b"command" => info.command.windows(value.len().max(1)).any(|w| w == value.as_slice()),
            k => return Err(format!("{}: not a search word", lossy(k))),
        };
        ok &= hit;
    }
    Ok(ok)
}

/// A listing's line, as sudoreplay(8) shows sessions.
pub fn listing(id: &str, info: &Info) -> String {
    let tm = slate_rt::tz::localtime(info.time);
    let mut when = String::new();
    slate_rt::time::format(&tm, "%b %e %H:%M:%S %Y", &mut when);
    format!(
        "{when} : {} : TTY={} ; CWD={} ; USER={} ; GROUP={} ; TSID={id} ; COMMAND={}\n",
        lossy(&info.user),
        lossy(info.tty.strip_prefix(b"/dev/").unwrap_or(&info.tty)),
        lossy(&info.cwd),
        lossy(&info.runas_user),
        lossy(&info.runas_group),
        lossy(&info.command)
    )
}

/// Every session under `dir`, oldest first: (id, its `log`).
fn sessions(dir: &[u8]) -> Vec<(String, Info)> {
    let mut out = Vec::new();
    let names = |d: &[u8]| -> Vec<Vec<u8>> {
        let mut v: Vec<Vec<u8>> = fs::read_dir(d)
            .map(|e| e.into_iter().map(|e| e.name).filter(|n| n.len() == 2).collect())
            .unwrap_or_default();
        v.sort();
        v
    };
    for a in names(dir) {
        let da = fs::join(dir, &a);
        for b in names(&da) {
            let db_ = fs::join(&da, &b);
            for c in names(&db_) {
                let id = String::from(lossy(&[a.as_slice(), &b, &c].concat()));
                if let Ok(log) = fs::read_file(&fs::join(&fs::join(&db_, &c), b"log"))
                    && let Some(info) = Info::decode(&log)
                {
                    out.push((id, info));
                }
            }
        }
    }
    out.sort_by_key(|(id, _)| iolog::number_of(id));
    out
}

/// Play the session at `path`: its chosen streams in their order, with
/// the recorded pauses.
fn replay(o: &Options, path: &[u8]) -> Result<(), String> {
    let timing = fs::read_file(&fs::join(path, b"timing")).map_err(|e| format!("{}: {e}", lossy(path)))?;
    let mut streams: Vec<Vec<u8>> = Vec::new();
    for name in STREAMS {
        streams.push(fs::read_file(&fs::join(path, name.as_bytes())).unwrap_or_default());
    }
    let mut at = [0usize; 5];
    for line in String::from(lossy(&timing)).lines() {
        let Some(ev) = iolog::parse_timing(line) else { continue };
        let delay = match &ev {
            Event::Data { delay_ns, .. } | Event::Size { delay_ns, .. } | Event::Signal { delay_ns, .. } => *delay_ns,
        };
        let mut secs = delay as f64 / 1e9 / o.speed;
        if let Some(m) = o.max_wait {
            secs = secs.min(m);
        }
        if secs > 0.0 {
            slate_rt::time::sleep_ns((secs * 1e9) as u64);
        }
        if let Event::Data { stream, size, .. } = ev {
            let data = &streams[stream];
            let end = (at[stream] + size).min(data.len());
            if o.streams[stream] {
                let _ = io::write_all(1, &data[at[stream]..end]);
            }
            at[stream] = end;
        }
    }
    Ok(())
}

pub fn main() -> i32 {
    let args = env::args();
    let rest = args.get(1..).unwrap_or_default();
    if rest.iter().any(|a| a == b"-h" || a == b"--help") {
        io::out(USAGE.as_bytes());
        return 0;
    }
    if rest.iter().any(|a| a == b"-V" || a == b"--version") {
        io::out(b"Slate sudoreplay\n");
        return 0;
    }
    let o = match parse(rest) {
        Ok(o) => o,
        Err(e) => {
            slate_rt::eprintln!("sudoreplay: {e}");
            let _ = io::write_all(2, USAGE.as_bytes());
            return 1;
        }
    };
    if o.list {
        let mut out = String::new();
        for (id, info) in sessions(&o.dir) {
            match matches(&info, &o.rest) {
                Ok(true) => out.push_str(&listing(&id, &info)),
                Ok(false) => {}
                Err(e) => return fail(1, e),
            }
        }
        io::out(out.as_bytes());
        return 0;
    }
    let id = String::from(lossy(&o.rest[0]));
    let Some(n) = iolog::number_of(&id) else { return fail(1, format!("{id}: not a session ID")) };
    match replay(&o, &iolog::path_of(&o.dir, &iolog::id_of(n))) {
        Ok(()) => 0,
        Err(e) => fail(1, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<Vec<u8>> {
        s.iter().map(|a| a.as_bytes().to_vec()).collect()
    }

    #[test]
    fn options_and_search() {
        let o = parse(&args(&["-m", "0", "-s", "2", "-f", "stdout,ttyout", "00/00/01"])).unwrap();
        assert_eq!(o.max_wait, Some(0.0));
        assert_eq!(o.speed, 2.0);
        assert_eq!(o.streams, [false, true, false, false, true]);
        assert_eq!(o.rest, args(&["00/00/01"]));
        assert!(parse(&args(&["-f", "video", "1"])).is_err());
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["-l", "user", "ann"])).unwrap().list);
        let info = Info {
            user: b"ann".to_vec(),
            runas_user: b"root".to_vec(),
            tty: b"/dev/pts/1".to_vec(),
            command: b"/bin/sh -c echo hi".to_vec(),
            ..Info::default()
        };
        assert_eq!(matches(&info, &args(&["user", "ann", "command", "echo"])), Ok(true));
        assert_eq!(matches(&info, &args(&["tty", "pts/1", "runas", "bob"])), Ok(false));
        assert!(matches(&info, &args(&["user"])).is_err());
        assert!(matches(&info, &args(&["host", "x"])).is_err());
    }
}
