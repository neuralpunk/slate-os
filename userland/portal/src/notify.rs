// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Desktop Notifications Specification's server (version 1.2), on
//! the app's session bus as `org.freedesktop.Notifications` at
//! `/org/freedesktop/Notifications` (ADR 0186): what a Linux app says
//! goes to Strata as its protocol's `Notify`, Strata showing it as its
//! own. Methods, from the specification: `Notify(susssasa{sv}i) → u`,
//! `CloseNotification(u)`, `GetCapabilities() → as` (the body only: no
//! actions, markup, icons or sounds yet), `GetServerInformation() →
//! ssss`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::wire::{METHOD_CALL, Message, NO_REPLY, Value};

pub const NAME: &str = "org.freedesktop.Notifications";
pub const PATH: &str = "/org/freedesktop/Notifications";
pub const IFACE: &str = "org.freedesktop.Notifications";

const INTROSPECTION: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.freedesktop.Notifications">
  <method name="Notify"><arg type="s" direction="in"/><arg type="u" direction="in"/><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="as" direction="in"/><arg type="a{sv}" direction="in"/><arg type="i" direction="in"/><arg type="u" direction="out"/></method>
  <method name="CloseNotification"><arg type="u" direction="in"/></method>
  <method name="GetCapabilities"><arg type="as" direction="out"/></method>
  <method name="GetServerInformation"><arg type="s" direction="out"/><arg type="s" direction="out"/><arg type="s" direction="out"/><arg type="s" direction="out"/></method>
  <signal name="NotificationClosed"><arg type="u"/><arg type="u"/></signal>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable"/>
</node>
"#;

/// What Strata is to be told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forward {
    /// A notification, numbered `key`.
    Notify {
        key: u32,
        app: String,
        summary: String,
        body: String,
        urgency: u8,
    },
    Close {
        key: u32,
    },
}

/// The ids given out.
#[derive(Debug, Default)]
pub struct Server {
    next: u32,
}

/// The specification's `urgency` hint (a byte: 0 low, 1 normal, 2
/// critical) among `hints`.
fn urgency(hints: Option<&Value>) -> u8 {
    let Some(Value::Array(_, entries)) = hints else { return 1 };
    for e in entries {
        if let Value::Entry(k, v) = e
            && k.str() == Some("urgency")
        {
            let v = match &**v {
                Value::Variant(inner) => &**inner,
                other => other,
            };
            return match v {
                Value::Byte(b) => (*b).min(2),
                Value::U32(n) => (*n).min(2) as u8,
                Value::I32(n) => (*n).clamp(0, 2) as u8,
                _ => 1,
            };
        }
    }
    1
}

impl Server {
    /// Answer `call` (with reply serial `serial`), and what Strata is to
    /// hear; None for a call that isn't this server's.
    pub fn answer(&mut self, serial: u32, call: &Message) -> Option<(Option<Message>, Option<Forward>)> {
        if call.path.as_deref() != Some(PATH) || call.kind != METHOD_CALL {
            return None;
        }
        let quiet = call.flags & NO_REPLY != 0;
        let reply = |body: Vec<Value>| (!quiet).then(|| Message::reply(serial, call, body));
        let s = |i: usize| call.body.get(i).and_then(Value::str).unwrap_or("");
        let iface = call.interface.as_deref().unwrap_or(IFACE);
        let member = call.member.as_deref().unwrap_or("");
        Some(match (iface, member) {
            ("org.freedesktop.DBus.Introspectable", "Introspect") => {
                (reply(alloc::vec![Value::Str(INTROSPECTION.into())]), None)
            }
            (IFACE, "Notify") => {
                let replaces = match call.body.get(1) {
                    Some(Value::U32(n)) => *n,
                    _ => 0,
                };
                let key = if replaces != 0 {
                    replaces
                } else {
                    self.next += 1;
                    self.next
                };
                let fwd = Forward::Notify {
                    key,
                    app: String::from(s(0)),
                    summary: String::from(s(3)),
                    body: String::from(s(4)),
                    urgency: urgency(call.body.get(6)),
                };
                (reply(alloc::vec![Value::U32(key)]), Some(fwd))
            }
            (IFACE, "CloseNotification") => {
                let key = match call.body.first() {
                    Some(Value::U32(n)) => *n,
                    _ => 0,
                };
                (reply(Vec::new()), Some(Forward::Close { key }))
            }
            (IFACE, "GetCapabilities") => {
                (reply(alloc::vec![Value::Array("s".into(), alloc::vec![Value::Str("body".into())])]), None)
            }
            (IFACE, "GetServerInformation") => {
                let info = ["Strata", "SlateOS", env!("CARGO_PKG_VERSION"), "1.2"];
                (reply(info.iter().map(|v| Value::Str((*v).into())).collect()), None)
            }
            _ => (
                (!quiet).then(|| {
                    Message::error(
                        serial,
                        call,
                        "org.freedesktop.DBus.Error.UnknownMethod",
                        &alloc::format!("{iface}.{member}"),
                    )
                }),
                None,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(member: &str, body: Vec<Value>) -> Message {
        let mut m = Message::call(5, NAME, PATH, IFACE, member, body);
        m.sender = Some(":1.4".into());
        m
    }

    fn notify(replaces: u32, hints: Vec<Value>) -> Message {
        let s = |x: &str| Value::Str(x.into());
        call(
            "Notify",
            alloc::vec![
                s("Firefox"),
                Value::U32(replaces),
                s(""),
                s("Download finished"),
                s("report.pdf"),
                Value::Array("s".into(), Vec::new()),
                Value::Array("{sv}".into(), hints),
                Value::I32(-1),
            ],
        )
    }

    #[test]
    fn notify_and_close() {
        let mut srv = Server::default();
        let (r, f) = srv.answer(9, &notify(0, Vec::new())).unwrap();
        assert_eq!(r.unwrap().body, alloc::vec![Value::U32(1)]);
        assert_eq!(
            f,
            Some(Forward::Notify {
                key: 1,
                app: "Firefox".into(),
                summary: "Download finished".into(),
                body: "report.pdf".into(),
                urgency: 1
            })
        );
        // Replacing keeps the id; the urgency hint is read.
        let hint = Value::Entry(
            alloc::boxed::Box::new(Value::Str("urgency".into())),
            alloc::boxed::Box::new(Value::variant(Value::Byte(2))),
        );
        let (r, f) = srv.answer(10, &notify(1, alloc::vec![hint])).unwrap();
        assert_eq!(r.unwrap().body, alloc::vec![Value::U32(1)]);
        assert!(matches!(f, Some(Forward::Notify { key: 1, urgency: 2, .. })));
        let (_, f) = srv.answer(11, &call("CloseNotification", alloc::vec![Value::U32(1)])).unwrap();
        assert_eq!(f, Some(Forward::Close { key: 1 }));
        // The server's facts.
        let (r, _) = srv.answer(12, &call("GetServerInformation", Vec::new())).unwrap();
        assert_eq!(r.unwrap().body[0], Value::Str("Strata".into()));
        let (r, _) = srv.answer(13, &call("GetCapabilities", Vec::new())).unwrap();
        assert_eq!(r.unwrap().body, alloc::vec![Value::Array("s".into(), alloc::vec![Value::Str("body".into())])]);
        // Another path isn't this server's.
        let mut other = call("Notify", Vec::new());
        other.path = Some("/elsewhere".into());
        assert!(srv.answer(14, &other).is_none());
    }
}
