// SPDX-License-Identifier: MIT OR Apache-2.0

//! Being told when the files Strata follows change: the person's settings
//! (ADR 0039), the time zone, the desktop folder (ADR 0102's third
//! addendum) and the Clock's alarms (ADR 0104's addendum). A watch descriptor (inotify(7), the native interface's
//! watches: ADR 0149) is told of changes in their directories, so nothing
//! is looked at until something changes. A directory that can't be
//! watched (it isn't there, or there is no descriptor) is looked at every
//! two seconds instead, as before (ADR 0067), and its watch tried again.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use slate_abi::watch as w;
use slate_rt::{fs, io};

/// What changed (bits).
pub const SETTINGS: u8 = 1;
pub const ZONE: u8 = 2;
pub const DESKTOP: u8 = 4;
pub const ALARMS: u8 = 8;
/// The displays' arrangement (ADR 0170).
pub const DISPLAYS: u8 = 16;
pub const ALL: u8 = SETTINGS | ZONE | DESKTOP | ALARMS | DISPLAYS;

/// The entry changes a directory reports: made, removed, renamed in or
/// out, or written and closed.
const MASK: u32 = w::CREATE | w::DELETE | w::MOVED_FROM | w::MOVED_TO | w::CLOSE_WRITE | w::ONLYDIR;
/// For files rewritten in place (`echo lock=0 > settings`), each write
/// too: Slate reports IN_CLOSE_WRITE on every close(2), so a shell that
/// moves the file onto its output and closes the first descriptor says
/// so before writing (GAPS.md). Not for the desktop folder, whose icons
/// change only with its entries.
const FILES: u32 = MASK | w::MODIFY;

#[derive(Debug)]
struct Dir {
    path: Vec<u8>,
    /// The names in it that matter; empty: any.
    names: Vec<&'static [u8]>,
    what: u8,
    mask: u32,
    wd: Option<i32>,
}

#[derive(Debug)]
pub struct Watcher {
    fd: Option<i32>,
    dirs: Vec<Dir>,
}

impl Watcher {
    /// Watch for `what` (bits), with the settings and the desktop folder
    /// under `home`.
    pub fn new(home: &[u8], what: u8) -> Watcher {
        let mut dirs = Vec::new();
        let mut want = |path: Vec<u8>, names: Vec<&'static [u8]>, bit: u8| {
            if what & bit != 0 && !path.is_empty() {
                let mask = if bit == DESKTOP { MASK } else { FILES };
                dirs.push(Dir { path, names, what: bit, mask, wd: None });
            }
        };
        let home = if home.is_empty() { None } else { Some(home) };
        want(home.map_or(Vec::new(), |h| fs::join(h, b".config/strata")), vec![b"settings"], SETTINGS);
        want(home.map_or(Vec::new(), |h| fs::join(h, b"Desktop")), Vec::new(), DESKTOP);
        // (The same directory as the settings: one watch, two names.)
        want(home.map_or(Vec::new(), |h| fs::join(h, b".config/strata")), vec![b"clock"], ALARMS);
        want(home.map_or(Vec::new(), |h| fs::join(h, b".config/strata")), vec![b"displays"], DISPLAYS);
        // The zone's setting and the link to its table (slate_rt::tz).
        let (dir, name) = split(slate_rt::tz::SETTING);
        want(dir.to_vec(), vec![name], ZONE);
        want(b"/etc".to_vec(), vec![b"localtime"], ZONE);
        let mut watcher = Watcher { fd: fs::watch_open(true).ok(), dirs };
        watcher.retry();
        watcher
    }

    /// The descriptor to wait on with the others: readable when there are
    /// events ([`Watcher::read`]).
    pub fn fd(&self) -> Option<i32> {
        self.fd
    }

    /// What can't be watched now, to be looked at the old way.
    pub fn unwatched(&self) -> u8 {
        self.dirs.iter().filter(|d| d.wd.is_none()).fold(0, |a, d| a | d.what)
    }

    /// What is watched and what is looked at, for the log
    /// ("watched: settings zone desktop alarms displays; looked at: none").
    pub fn describe(&self) -> String {
        let names = |bits: u8| {
            let n: Vec<&str> = [
                (SETTINGS, "settings"),
                (ZONE, "zone"),
                (DESKTOP, "desktop"),
                (ALARMS, "alarms"),
                (DISPLAYS, "displays"),
            ]
            .iter()
            .filter(|(b, _)| bits & b != 0)
            .map(|(_, n)| *n)
            .collect();
            if n.is_empty() { String::from("none") } else { n.join(" ") }
        };
        let all = self.dirs.iter().fold(0, |a, d| a | d.what);
        let looked = self.unwatched();
        alloc::format!("watched: {}; looked at: {}", names(all & !looked), names(looked))
    }

    /// Watch again what isn't watched (every two seconds, while anything
    /// isn't): what may have changed meanwhile.
    pub fn retry(&mut self) -> u8 {
        let Some(fd) = self.fd else { return 0 };
        let mut got = 0;
        for d in self.dirs.iter_mut().filter(|d| d.wd.is_none()) {
            if let Ok(wd) = fs::watch_add(fd, &d.path, d.mask) {
                d.wd = Some(wd);
                got |= d.what;
            }
        }
        got
    }

    /// The events that have come: what changed.
    pub fn read(&mut self) -> u8 {
        let Some(fd) = self.fd else { return 0 };
        let mut buf = [0u8; 4096];
        let mut out = 0;
        while let Ok(n) = io::read(fd, &mut buf) {
            if n == 0 {
                break;
            }
            for (wd, mask, name) in events(&buf[..n]) {
                out |= self.event(wd, mask, name);
            }
        }
        out
    }

    fn event(&mut self, wd: i32, mask: u32, name: &[u8]) -> u8 {
        if mask & w::OVERFLOW != 0 {
            return self.dirs.iter().fold(0, |a, d| a | d.what);
        }
        let mut out = 0;
        for d in self.dirs.iter_mut().filter(|d| d.wd == Some(wd)) {
            // The directory went (removed or renamed): looked at the old
            // way until it can be watched again.
            if mask & (w::IGNORED | w::DELETE_SELF | w::MOVE_SELF) != 0 {
                d.wd = None;
                out |= d.what;
            } else if d.names.is_empty() || d.names.contains(&name) {
                out |= d.what;
            }
        }
        out
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            let _ = io::close(fd);
        }
    }
}

/// A path's directory and last name.
fn split(path: &'static [u8]) -> (&'static [u8], &'static [u8]) {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) => (b"/", &path[1..]),
        Some(i) => (&path[..i], &path[i + 1..]),
        None => (b".", path),
    }
}

/// The events in what a watch descriptor gave (inotify(7)'s `struct
/// inotify_event`: wd, mask, cookie, the name's length, the name padded
/// with NULs): (watch, mask, name).
fn events(mut buf: &[u8]) -> Vec<(i32, u32, &[u8])> {
    let mut out = Vec::new();
    let word = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    while buf.len() >= 16 {
        let len = word(buf, 12) as usize;
        let Some(name) = buf.get(16..16 + len) else { break };
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(len)];
        out.push((word(buf, 0) as i32, word(buf, 4), name));
        buf = &buf[16 + len..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn event(wd: i32, mask: u32, name: &[u8], pad: usize) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&wd.to_le_bytes());
        e.extend_from_slice(&mask.to_le_bytes());
        e.extend_from_slice(&0u32.to_le_bytes());
        e.extend_from_slice(&((name.len() + pad) as u32).to_le_bytes());
        e.extend_from_slice(name);
        e.extend(core::iter::repeat_n(0, pad));
        e
    }

    #[test]
    fn events_are_read() {
        let mut buf = event(1, w::MOVED_TO, b"settings", 8);
        buf.extend(event(-1, w::OVERFLOW, b"", 0));
        buf.extend(event(2, w::CREATE, b"x", 3));
        buf.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            events(&buf),
            [
                (1, w::MOVED_TO, b"settings".as_slice()),
                (-1, w::OVERFLOW, b"".as_slice()),
                (2, w::CREATE, b"x".as_slice())
            ]
        );
        assert_eq!(split(b"/etc/slate/timezone"), (b"/etc/slate".as_slice(), b"timezone".as_slice()));
        assert_eq!(split(b"/x"), (b"/".as_slice(), b"x".as_slice()));
    }

    fn scratch(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("slate-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }

    #[test]
    fn changes_are_told() {
        let home = scratch("told");
        std::fs::create_dir_all(format!("{home}/.config/strata")).unwrap();
        let mut watcher = Watcher::new(home.as_bytes(), SETTINGS | DESKTOP);
        // No Desktop folder yet: looked at the old way.
        assert_eq!(watcher.unwatched(), DESKTOP);
        assert_eq!(watcher.describe(), "watched: settings; looked at: desktop");
        assert_eq!(watcher.read(), 0);
        // Settings writes a new file and renames it over the old one; only
        // the name that matters counts.
        std::fs::write(format!("{home}/.config/strata/other"), "x").unwrap();
        assert_eq!(watcher.read(), 0);
        std::fs::write(format!("{home}/.config/strata/settings.new"), "light=1\n").unwrap();
        std::fs::rename(format!("{home}/.config/strata/settings.new"), format!("{home}/.config/strata/settings"))
            .unwrap();
        assert_eq!(watcher.read(), SETTINGS);
        assert_eq!(watcher.read(), 0);
        // The Clock's file, in the same directory.
        std::fs::write(format!("{home}/.config/strata/clock"), "alarm=07:30 on\n").unwrap();
        assert_eq!(watcher.read(), 0, "not asked for");
        let mut both = Watcher::new(home.as_bytes(), SETTINGS | ALARMS);
        std::fs::write(format!("{home}/.config/strata/clock"), "alarm=07:45 on\n").unwrap();
        assert_eq!(both.read(), ALARMS);
        drop(both);
        // Rewritten in place: told by the write.
        std::fs::write(format!("{home}/.config/strata/settings"), "lock=0\n").unwrap();
        assert_eq!(watcher.read(), SETTINGS);
        // The folder made: watched from the next try, any name in it.
        std::fs::create_dir(format!("{home}/Desktop")).unwrap();
        assert_eq!(watcher.retry(), DESKTOP);
        assert_eq!(watcher.unwatched(), 0);
        std::fs::write(format!("{home}/Desktop/a.txt"), "a").unwrap();
        assert_eq!(watcher.read(), DESKTOP);
        // Removed: said, and looked at the old way again.
        std::fs::remove_file(format!("{home}/Desktop/a.txt")).unwrap();
        std::fs::remove_dir(format!("{home}/Desktop")).unwrap();
        assert_eq!(watcher.read(), DESKTOP);
        assert_eq!(watcher.unwatched(), DESKTOP);
        let _ = std::fs::remove_dir_all(&home);
    }
}
