// SPDX-License-Identifier: MIT OR Apache-2.0

//! Configuration: /etc/inittab (`id:runlevels:action:process`, the SysV
//! inittab(5) format) and LSB init script headers (LSB Core 5.0,
//! "Comment Conventions for Init Scripts") with the start order they imply.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Sysinit,
    Boot,
    Bootwait,
    Wait,
    Once,
    Respawn,
    Off,
    Initdefault,
    Ctrlaltdel,
    Powerfail,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: Vec<u8>,
    /// Runlevel characters (empty: all).
    pub levels: Vec<u8>,
    pub action: Action,
    pub process: Vec<u8>,
}

impl Entry {
    pub fn in_level(&self, level: u8) -> bool {
        self.levels.is_empty() || self.levels.contains(&level) || (level == b'S' && self.levels.contains(&b's'))
    }
}

/// Parse inittab; bad lines are reported in the error list.
pub fn parse_inittab(text: &[u8]) -> (Vec<Entry>, Vec<String>) {
    let mut entries = Vec::new();
    let mut errors = Vec::new();
    for (n, line) in text.split(|&c| c == b'\n').enumerate() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let t = line.trim_ascii_start();
        if t.is_empty() || t.starts_with(b"#") {
            continue;
        }
        let f: Vec<&[u8]> = line.splitn(4, |&c| c == b':').collect();
        if f.len() < 4 {
            errors.push(alloc::format!("inittab line {}: not id:runlevels:action:process", n + 1));
            continue;
        }
        let action = match f[2] {
            b"sysinit" => Action::Sysinit,
            b"boot" => Action::Boot,
            b"bootwait" => Action::Bootwait,
            b"wait" => Action::Wait,
            b"once" => Action::Once,
            b"respawn" => Action::Respawn,
            b"off" => Action::Off,
            b"initdefault" => Action::Initdefault,
            b"ctrlaltdel" => Action::Ctrlaltdel,
            b"powerfail" | b"powerwait" => Action::Powerfail,
            other => {
                errors.push(alloc::format!(
                    "inittab line {}: unknown action '{}'",
                    n + 1,
                    String::from_utf8_lossy(other)
                ));
                continue;
            }
        };
        entries.push(Entry { id: f[0].to_vec(), levels: f[1].to_vec(), action, process: f[3].trim_ascii().to_vec() });
    }
    (entries, errors)
}

/// The default runlevel inittab names (3 if none).
pub fn default_level(entries: &[Entry]) -> u8 {
    entries.iter().find(|e| e.action == Action::Initdefault).and_then(|e| e.levels.first().copied()).unwrap_or(b'3')
}

/// An init script's LSB header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Service {
    pub name: Vec<u8>,
    pub provides: Vec<Vec<u8>>,
    pub required_start: Vec<Vec<u8>>,
    pub required_stop: Vec<Vec<u8>>,
    pub should_start: Vec<Vec<u8>>,
    pub should_stop: Vec<Vec<u8>>,
    pub default_start: Vec<u8>,
    pub default_stop: Vec<u8>,
    pub description: Vec<u8>,
    /// `X-Slate-Exec`: slinit runs and supervises this command itself.
    pub exec: Option<Vec<u8>>,
}

fn words(v: &[u8]) -> Vec<Vec<u8>> {
    v.split(|c| c.is_ascii_whitespace()).filter(|w| !w.is_empty()).map(<[u8]>::to_vec).collect()
}

/// The LSB block of script `name`, if it has one.
pub fn parse_lsb(name: &[u8], text: &[u8]) -> Option<Service> {
    let mut s = Service { name: name.to_vec(), ..Service::default() };
    let mut inside = false;
    let mut seen = false;
    for line in text.split(|&c| c == b'\n') {
        let line = line.trim_ascii();
        if line.starts_with(b"### BEGIN INIT INFO") {
            inside = true;
            seen = true;
            continue;
        }
        if line.starts_with(b"### END INIT INFO") {
            break;
        }
        if !inside {
            continue;
        }
        let Some(body) = line.strip_prefix(b"#") else { break };
        let body = body.trim_ascii_start();
        let Some(colon) = body.iter().position(|&c| c == b':') else { continue };
        let (key, value) = (&body[..colon], body[colon + 1..].trim_ascii());
        match key {
            b"Provides" => s.provides = words(value),
            b"Required-Start" => s.required_start = words(value),
            b"Required-Stop" => s.required_stop = words(value),
            b"Should-Start" => s.should_start = words(value),
            b"Should-Stop" => s.should_stop = words(value),
            b"Default-Start" => s.default_start = words(value).into_iter().filter_map(|w| w.first().copied()).collect(),
            b"Default-Stop" => s.default_stop = words(value).into_iter().filter_map(|w| w.first().copied()).collect(),
            b"Short-Description" => s.description = value.to_vec(),
            b"X-Slate-Exec" => s.exec = Some(value.to_vec()),
            _ => {}
        }
    }
    if !seen {
        return None;
    }
    if s.provides.is_empty() {
        s.provides.push(name.to_vec());
    }
    Some(s)
}

/// Order `services` so each comes after what it requires (and after what
/// it should follow, when present). `stop` orders by the stop
/// dependencies and reverses (dependents stop first). `$all` goes last;
/// cycles are broken by name. Returns indices and warnings.
pub fn order(services: &[Service], stop: bool) -> (Vec<usize>, Vec<String>) {
    let mut warnings = Vec::new();
    let n = services.len();
    let provider = |fac: &[u8]| -> Vec<usize> {
        (0..n)
            .filter(|&i| services[i].provides.iter().any(|p| p == fac || (p.first() == Some(&b'$') && &p[1..] == fac)))
            .collect()
    };
    // deps[i]: the services i must follow.
    let mut deps: Vec<BTreeSet<usize>> = alloc::vec![BTreeSet::new(); n];
    let mut last: Vec<bool> = alloc::vec![false; n];
    for (i, s) in services.iter().enumerate() {
        let (req, should) =
            if stop { (&s.required_stop, &s.should_stop) } else { (&s.required_start, &s.should_start) };
        for (dep, required) in req.iter().map(|d| (d, true)).chain(should.iter().map(|d| (d, false))) {
            if dep == b"$all" {
                last[i] = true;
                continue;
            }
            let p = provider(dep);
            if p.is_empty() && required && !dep.starts_with(b"$") {
                warnings.push(alloc::format!(
                    "{}: required '{}' is not provided",
                    String::from_utf8_lossy(&s.name),
                    String::from_utf8_lossy(dep)
                ));
            }
            deps[i].extend(p.into_iter().filter(|&x| x != i));
        }
    }
    let mut done: Vec<bool> = alloc::vec![false; n];
    let mut out = Vec::new();
    // Kahn's algorithm, smallest name first; `$all` services after the rest.
    let mut by_name: Vec<usize> = (0..n).collect();
    by_name.sort_by(|&a, &b| services[a].name.cmp(&services[b].name));
    while out.len() < n {
        let ready = by_name.iter().copied().find(|&i| {
            !done[i] && deps[i].iter().all(|&d| done[d]) && (!last[i] || (0..n).all(|j| done[j] || last[j]))
        });
        let pick = match ready {
            Some(i) => i,
            None => {
                let i = by_name.iter().copied().find(|&i| !done[i]).unwrap_or(0);
                if !last[i] || (0..n).any(|j| !done[j] && !last[j]) {
                    warnings.push(alloc::format!("dependency cycle at {}", String::from_utf8_lossy(&services[i].name)));
                }
                i
            }
        };
        done[pick] = true;
        out.push(pick);
    }
    if stop {
        out.reverse();
    }
    (out, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inittab() {
        let (e, errs) = parse_inittab(b"# comment\nid:3:initdefault:\nsi::sysinit:/etc/rc.d/rc.sysinit\nc1:2345:respawn:/bin/getty console\nbad\nx:1:frob:y\n");
        assert_eq!(e.len(), 3);
        assert_eq!(errs.len(), 2);
        assert_eq!(default_level(&e), b'3');
        assert!(e[1].in_level(b'5'));
        assert!(e[2].in_level(b'3') && !e[2].in_level(b'1'));
        assert_eq!(e[2].process, b"/bin/getty console");
    }

    fn svc(name: &str, req: &str, should: &str) -> Service {
        let text = alloc::format!(
            "#!/bin/sh\n### BEGIN INIT INFO\n# Provides: {name}\n# Required-Start: {req}\n# Should-Start: {should}\n# Required-Stop: {req}\n# Default-Start: 2 3 4 5\n# Default-Stop: 0 1 6\n### END INIT INFO\n"
        );
        parse_lsb(name.as_bytes(), text.as_bytes()).unwrap()
    }

    #[test]
    fn ordering() {
        let s = alloc::vec![
            svc("web", "net db", ""),
            svc("net", "", ""),
            svc("db", "net", "log"),
            svc("log", "", ""),
            svc("late", "$all", "")
        ];
        let (o, w) = order(&s, false);
        let names: Vec<&[u8]> = o.iter().map(|&i| s[i].name.as_slice()).collect();
        assert_eq!(names, [&b"log"[..], b"net", b"db", b"web", b"late"]);
        assert!(w.is_empty(), "{w:?}");
        let (stop, _) = order(&s, true);
        assert_eq!(s[stop[0]].name, b"late");
        // Dependents stop before what they depend on.
        let at = |n: &[u8]| stop.iter().position(|&i| s[i].name == n).unwrap();
        assert!(at(b"web") < at(b"db") && at(b"db") < at(b"net"));
        assert_eq!(s[0].default_start, b"2345");
        let (_, w) = order(&[svc("a", "missing", "")], false);
        assert_eq!(w.len(), 1);
        let (o, w) = order(&[svc("a", "b", ""), svc("b", "a", "")], false);
        assert_eq!(o.len(), 2);
        assert!(!w.is_empty());
        assert!(parse_lsb(b"plain", b"#!/bin/sh\necho hi\n").is_none());
    }
}
