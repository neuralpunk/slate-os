// SPDX-License-Identifier: MIT OR Apache-2.0

//! The portal on the bus: it connects to `DBUS_SESSION_BUS_ADDRESS`
//! (`unix:path=`), authenticates as its user (the D-Bus Specification's
//! EXTERNAL mechanism: the user ID's digits in hex), says Hello, takes
//! `org.freedesktop.portal.Desktop`, and answers:
//!
//! - `org.freedesktop.portal.Settings`: `ReadAll(as)`, `ReadOne(ss)` and
//!   the older `Read(ss)` (its value in one more variant); a key it
//!   doesn't have is `org.freedesktop.portal.Error.NotFound`;
//! - `org.freedesktop.DBus.Properties`: Settings' `version`, 2; another
//!   portal's interface is unknown, which tells toolkits to do without
//!   it (their own file chooser, for one);
//! - `org.freedesktop.DBus.Introspectable` and `org.freedesktop.DBus.Peer`.
//!
//! It watches the person's Strata settings and sends `SettingChanged`
//! for each value that changed. It ends when the bus does.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, lossy, net};

use crate::settings::{Look, SETTINGS};
use crate::wire::{METHOD_CALL, Message, NO_REPLY, Value};

pub const NAME: &str = "org.freedesktop.portal.Desktop";
pub const PATH: &str = "/org/freedesktop/portal/desktop";
pub const SETTINGS_IFACE: &str = "org.freedesktop.portal.Settings";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

const INTROSPECTION: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.freedesktop.portal.Settings">
  <method name="ReadAll"><arg type="as" name="namespaces" direction="in"/><arg type="a{sa{sv}}" name="value" direction="out"/></method>
  <method name="Read"><arg type="s" name="namespace" direction="in"/><arg type="s" name="key" direction="in"/><arg type="v" name="value" direction="out"/></method>
  <method name="ReadOne"><arg type="s" name="namespace" direction="in"/><arg type="s" name="key" direction="in"/><arg type="v" name="value" direction="out"/></method>
  <signal name="SettingChanged"><arg type="s" name="namespace"/><arg type="s" name="key"/><arg type="v" name="value"/></signal>
  <property name="version" type="u" access="read"/>
 </interface>
 <interface name="org.freedesktop.DBus.Properties"/>
 <interface name="org.freedesktop.DBus.Introspectable"/>
 <interface name="org.freedesktop.DBus.Peer"/>
</node>
"#;

/// The answer to `call` (serial `serial`), if it wants one.
pub fn answer(look: &Look, serial: u32, call: &Message) -> Option<Message> {
    if call.kind != METHOD_CALL || call.flags & NO_REPLY != 0 {
        return None;
    }
    let s = |i: usize| call.body.get(i).and_then(Value::str).unwrap_or("");
    let err = |name: &str, text: &str| Some(Message::error(serial, call, name, text));
    let ok = |body: Vec<Value>| Some(Message::reply(serial, call, body));
    let iface = call.interface.as_deref().unwrap_or("");
    let member = call.member.as_deref().unwrap_or("");
    if iface == "org.freedesktop.DBus.Peer" {
        return match member {
            "Ping" => ok(Vec::new()),
            "GetMachineId" => {
                let id = fs::read_file(b"/etc/machine-id").map(|t| String::from(lossy(&t).trim())).unwrap_or_default();
                ok(alloc::vec![Value::Str(id)])
            }
            _ => err("org.freedesktop.DBus.Error.UnknownMethod", member),
        };
    }
    if call.path.as_deref() != Some(PATH) {
        return err("org.freedesktop.DBus.Error.UnknownObject", call.path.as_deref().unwrap_or(""));
    }
    match (iface, member) {
        (SETTINGS_IFACE, "ReadAll") => {
            let globs: Vec<String> = match call.body.first() {
                Some(Value::Array(_, items)) => items.iter().filter_map(Value::str).map(String::from).collect(),
                _ => Vec::new(),
            };
            ok(alloc::vec![look.read_all(&globs)])
        }
        (SETTINGS_IFACE, m @ ("Read" | "ReadOne")) => match look.get(s(0), s(1)) {
            // Read's value comes wrapped once more (the portal's older form).
            Some(v) if m == "Read" => ok(alloc::vec![Value::variant(Value::variant(v))]),
            Some(v) => ok(alloc::vec![Value::variant(v)]),
            None => err("org.freedesktop.portal.Error.NotFound", &format!("no {} {}", s(0), s(1))),
        },
        (PROPERTIES, "Get") if s(0) == SETTINGS_IFACE && s(1) == "version" => {
            ok(alloc::vec![Value::variant(Value::U32(2))])
        }
        (PROPERTIES, "GetAll") if s(0) == SETTINGS_IFACE => ok(alloc::vec![Value::Array(
            "{sv}".into(),
            alloc::vec![Value::Entry(
                alloc::boxed::Box::new(Value::Str("version".into())),
                alloc::boxed::Box::new(Value::variant(Value::U32(2))),
            )],
        )]),
        (PROPERTIES, _) if s(0) == SETTINGS_IFACE => err("org.freedesktop.DBus.Error.UnknownProperty", s(1)),
        // Another portal: not here.
        (PROPERTIES, _) => err("org.freedesktop.DBus.Error.UnknownInterface", s(0)),
        ("org.freedesktop.DBus.Introspectable", "Introspect") => ok(alloc::vec![Value::Str(INTROSPECTION.into())]),
        _ => err("org.freedesktop.DBus.Error.UnknownMethod", &format!("{iface}.{member}")),
    }
}

/// The bus's socket path from an address (`unix:path=/x,guid=...`).
pub fn bus_path(address: &str) -> Option<&str> {
    address.split(';').find_map(|a| {
        let rest = a.strip_prefix("unix:")?;
        rest.split(',').find_map(|kv| kv.strip_prefix("path="))
    })
}

/// EXTERNAL's initial response: the user ID's decimal digits, in hex.
pub fn external_id(uid: u32) -> String {
    format!("{uid}").bytes().map(|b| format!("{b:02x}")).collect()
}

/// The connection.
struct Bus {
    fd: i32,
    inbuf: Vec<u8>,
    serial: u32,
}

impl Bus {
    fn next_serial(&mut self) -> u32 {
        self.serial += 1;
        self.serial
    }

    fn send(&mut self, m: &Message) -> Result<(), String> {
        io::write_all(self.fd, &m.encode()).map_err(|e| format!("writing to the bus: {e}"))
    }

    /// Messages that have come; Err when the bus has gone.
    fn read(&mut self) -> Result<Vec<Message>, String> {
        let mut buf = [0u8; 8192];
        let n = io::read(self.fd, &mut buf).map_err(|e| format!("reading the bus: {e}"))?;
        if n == 0 {
            return Err("the bus has gone".into());
        }
        self.inbuf.extend_from_slice(&buf[..n]);
        let mut out = Vec::new();
        while let Some((m, len)) = Message::decode(&self.inbuf).map_err(|_| String::from("the bus sent garbage"))? {
            self.inbuf.drain(..len);
            out.push(m);
        }
        Ok(out)
    }

    /// Call the bus itself and wait for its answer (messages meanwhile are
    /// dropped: nothing calls before the name is ours).
    fn call_bus(&mut self, member: &str, body: Vec<Value>) -> Result<Message, String> {
        let serial = self.next_serial();
        let m = Message::call(
            serial,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            member,
            body,
        );
        self.send(&m)?;
        loop {
            for r in self.read()? {
                if r.reply_to == Some(serial) {
                    return match r.error {
                        Some(e) => Err(format!("{member}: {e}")),
                        None => Ok(r),
                    };
                }
            }
        }
    }
}

fn connect(address: &str) -> Result<Bus, String> {
    let path = bus_path(address).ok_or_else(|| format!("{address}: not a unix:path= address"))?;
    let fd = net::connect_path(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    let uid = slate_rt::process::geteuid();
    let hello = format!("\0AUTH EXTERNAL {}\r\n", external_id(uid));
    io::write_all(fd, hello.as_bytes()).map_err(|e| format!("authenticating: {e}"))?;
    let mut line = Vec::new();
    let mut b = [0u8; 256];
    while !line.ends_with(b"\r\n") {
        let n = io::read(fd, &mut b).map_err(|e| format!("authenticating: {e}"))?;
        if n == 0 {
            return Err("the bus closed while authenticating".into());
        }
        line.extend_from_slice(&b[..n]);
    }
    if !line.starts_with(b"OK ") {
        return Err(format!("the bus refused: {}", lossy(&line).trim()));
    }
    io::write_all(fd, b"BEGIN\r\n").map_err(|e| format!("authenticating: {e}"))?;
    Ok(Bus { fd, inbuf: Vec::new(), serial: 0 })
}

fn home() -> String {
    slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_else(|| String::from("/"))
}

fn load() -> Look {
    let path = format!("{}/{SETTINGS}", home());
    Look::parse(&fs::read_file(path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default())
}

pub fn main() -> i32 {
    match run() {
        Ok(()) => 0,
        Err(e) => {
            slate_rt::eprintln!("slate-portal: {e}");
            1
        }
    }
}

fn run() -> Result<(), String> {
    let address = slate_rt::env::var(b"DBUS_SESSION_BUS_ADDRESS")
        .map(|a| String::from(lossy(&a)))
        .ok_or("DBUS_SESSION_BUS_ADDRESS is not set")?;
    // The bus may still be starting (slate-linux-app starts both at once).
    let mut tries = 0;
    let mut bus = loop {
        match connect(&address) {
            Ok(b) => break b,
            Err(e) if tries >= 400 => return Err(e),
            Err(_) => {
                tries += 1;
                slate_rt::time::sleep_ns(5_000_000);
            }
        }
    };
    let me = bus.call_bus("Hello", Vec::new())?;
    let unique = me.body.first().and_then(Value::str).map(String::from).unwrap_or_default();
    // DO_NOT_QUEUE (4): ours now, or not at all. 1: the primary owner.
    let got = bus.call_bus("RequestName", alloc::vec![Value::Str(NAME.into()), Value::U32(4)])?;
    if got.body.first() != Some(&Value::U32(1)) {
        return Err(format!("{NAME} is someone else's"));
    }
    // On the bus: the program slate-linux-app starts may go on (it waits
    // for this file, `PORTAL_READY` there).
    if let Some(dir) = slate_rt::env::var(b"XDG_RUNTIME_DIR") {
        let ready = [dir.as_slice(), b"/.slate-portal-ready"].concat();
        let _ = fs::write_file(&ready, b"", 0o600);
    }
    let mut look = load();
    slate_rt::eprintln!("slate-portal: {NAME} as {unique}: Settings ({})", look.theme.key());
    // Strata's settings: their directory watched (inotify(7)), or looked
    // at every two seconds without.
    let dir = format!("{}/.config/strata", home());
    let watch = fs::watch_open(true).ok().filter(|&fd| {
        use slate_abi::watch as w;
        let ok = fs::watch_add(fd, dir.as_bytes(), w::CLOSE_WRITE | w::MOVED_TO | w::CREATE | w::MODIFY).is_ok();
        if !ok {
            let _ = io::close(fd);
        }
        ok
    });
    loop {
        let mut fds = [
            io::PollFd { fd: bus.fd, events: io::POLLIN, revents: 0 },
            io::PollFd { fd: watch.unwrap_or(-1), events: io::POLLIN, revents: 0 },
        ];
        let _ = io::poll(&mut fds, if watch.is_some() { -1 } else { 2000 });
        if fds[0].revents != 0 {
            let msgs = match bus.read() {
                Ok(m) => m,
                // The session is over.
                Err(_) => return Ok(()),
            };
            for m in msgs {
                let serial = bus.serial + 1;
                if let Some(r) = answer(&look, serial, &m) {
                    bus.serial = serial;
                    bus.send(&r)?;
                }
            }
        }
        if let Some(fd) = watch
            && fds[1].revents != 0
        {
            let mut buf = [0u8; 1024];
            while io::read(fd, &mut buf).is_ok_and(|n| n > 0) {}
        }
        let now = load();
        for (ns, key, value) in now.changes(&look) {
            let serial = bus.next_serial();
            let sig = Message::signal(
                serial,
                PATH,
                SETTINGS_IFACE,
                "SettingChanged",
                alloc::vec![Value::Str(ns.into()), Value::Str(key.into()), Value::variant(value)],
            );
            bus.send(&sig)?;
            slate_rt::eprintln!("slate-portal: {ns} {key} changed");
        }
        look = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(iface: &str, member: &str, body: Vec<Value>) -> Message {
        let mut m = Message::call(5, NAME, PATH, iface, member, body);
        m.sender = Some(":1.9".into());
        m
    }

    #[test]
    fn settings_answered() {
        let look = Look::parse("theme=light");
        let s = |t: &str| Value::Str(t.into());
        let r = answer(
            &look,
            10,
            &call(SETTINGS_IFACE, "ReadOne", alloc::vec![s("org.freedesktop.appearance"), s("color-scheme")]),
        )
        .unwrap();
        assert_eq!((r.kind, r.reply_to, r.destination.as_deref()), (crate::wire::METHOD_RETURN, Some(5), Some(":1.9")));
        assert_eq!(r.body, alloc::vec![Value::variant(Value::U32(2))]);
        let r = answer(
            &look,
            11,
            &call(SETTINGS_IFACE, "Read", alloc::vec![s("org.freedesktop.appearance"), s("color-scheme")]),
        )
        .unwrap();
        assert_eq!(r.body, alloc::vec![Value::variant(Value::variant(Value::U32(2)))]);
        let r =
            answer(&look, 12, &call(SETTINGS_IFACE, "ReadOne", alloc::vec![s("org.kde.kdeglobals.General"), s("x")]))
                .unwrap();
        assert_eq!(r.error.as_deref(), Some("org.freedesktop.portal.Error.NotFound"));
        let all =
            answer(&look, 13, &call(SETTINGS_IFACE, "ReadAll", alloc::vec![Value::Array("s".into(), alloc::vec![])]))
                .unwrap();
        assert_eq!(all.body[0].signature(), "a{sa{sv}}");
        // Each answer is a message the bus can read back.
        assert!(Message::decode(&all.encode()).unwrap().is_some());
    }

    #[test]
    fn other_portals_are_unknown() {
        let look = Look::parse("");
        let s = |t: &str| Value::Str(t.into());
        let v = answer(&look, 1, &call(PROPERTIES, "Get", alloc::vec![s(SETTINGS_IFACE), s("version")])).unwrap();
        assert_eq!(v.body, alloc::vec![Value::variant(Value::U32(2))]);
        let fc = answer(
            &look,
            2,
            &call(PROPERTIES, "Get", alloc::vec![s("org.freedesktop.portal.FileChooser"), s("version")]),
        )
        .unwrap();
        assert_eq!(fc.error.as_deref(), Some("org.freedesktop.DBus.Error.UnknownInterface"));
        let open = answer(&look, 3, &call("org.freedesktop.portal.FileChooser", "OpenFile", alloc::vec![])).unwrap();
        assert_eq!(open.error.as_deref(), Some("org.freedesktop.DBus.Error.UnknownMethod"));
        let mut quiet = call(SETTINGS_IFACE, "ReadAll", alloc::vec![]);
        quiet.flags = NO_REPLY;
        assert!(answer(&look, 4, &quiet).is_none());
        let mut elsewhere = call(SETTINGS_IFACE, "ReadAll", alloc::vec![]);
        elsewhere.path = Some("/x".into());
        assert_eq!(
            answer(&look, 5, &elsewhere).unwrap().error.as_deref(),
            Some("org.freedesktop.DBus.Error.UnknownObject")
        );
        assert!(answer(&look, 6, &call("org.freedesktop.DBus.Introspectable", "Introspect", alloc::vec![])).is_some());
    }

    /// Against the host's own bus daemon (when it has one): our messages
    /// and its answers, then dbus-send asking the portal as an app would.
    #[test]
    fn on_a_real_bus() {
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("slate-portal-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let sock = dir.join("bus");
        let address = format!("unix:path={}", sock.display());
        let Ok(mut daemon) = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", &format!("--address={address}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            std::eprintln!("no dbus-daemon on this host: skipped");
            return;
        };
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut bus = connect(&address).unwrap();
        let me = bus.call_bus("Hello", Vec::new()).unwrap();
        assert!(me.body.first().and_then(Value::str).is_some_and(|n| n.starts_with(':')));
        let got = bus.call_bus("RequestName", alloc::vec![Value::Str(NAME.into()), Value::U32(4)]).unwrap();
        assert_eq!(got.body.first(), Some(&Value::U32(1)));
        let addr = address.clone();
        let asker = std::thread::spawn(move || {
            Command::new("dbus-send")
                .env("DBUS_SESSION_BUS_ADDRESS", &addr)
                .args([
                    "--session",
                    "--print-reply",
                    "--reply-timeout=5000",
                    &format!("--dest={NAME}"),
                    PATH,
                    "org.freedesktop.portal.Settings.ReadOne",
                    "string:org.freedesktop.appearance",
                    "string:color-scheme",
                ])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default()
        });
        let look = Look::parse("theme=graphite");
        while !asker.is_finished() {
            let mut p = [io::PollFd { fd: bus.fd, events: io::POLLIN, revents: 0 }];
            if io::poll(&mut p, 100).unwrap_or(0) > 0 {
                for m in bus.read().unwrap() {
                    let serial = bus.next_serial();
                    if let Some(r) = answer(&look, serial, &m) {
                        bus.send(&r).unwrap();
                    }
                }
            }
        }
        let out = asker.join().unwrap();
        let _ = daemon.kill();
        let _ = daemon.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.contains("uint32 1"), "dbus-send got: {out}");
    }

    #[test]
    fn addresses_and_identity() {
        assert_eq!(bus_path("unix:path=/tmp/xdg-1000/bus,guid=ab"), Some("/tmp/xdg-1000/bus"));
        assert_eq!(bus_path("unix:abstract=/tmp/dbus-x;unix:path=/b"), Some("/b"));
        assert_eq!(bus_path("tcp:host=x"), None);
        assert_eq!(external_id(1000), "31303030");
        assert_eq!(external_id(0), "30");
    }
}
