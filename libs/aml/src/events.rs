// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the firmware's events need from the namespace: the
//! general-purpose event handlers in `\_GPE` (§5.6.4), the wake events
//! among them (`_PRW`, chapter 7), devices by identification (`_HID` and
//! `_CID`, §6.1) and thermal zones (chapter 11).

use alloc::vec::Vec;

use crate::{Host, Interpreter, NodeId, Object, ROOT, Value};

/// A handler method in `\_GPE`: `_Lxx` for a level-triggered event,
/// `_Exx` for an edge-triggered one, `xx` the event's number in hex
/// (§5.6.4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GpeHandler {
    pub number: u8,
    pub edge: bool,
    pub method: NodeId,
}

/// The handlers `\_GPE` has, by event number.
pub fn gpe_handlers<H: Host>(i: &Interpreter<H>) -> Vec<GpeHandler> {
    let Some(gpe) = i.find("\\_GPE") else { return Vec::new() };
    let mut out: Vec<GpeHandler> = i
        .children(gpe)
        .into_iter()
        .filter(|&c| matches!(i.object(c), Object::Method(_)))
        .filter_map(|c| {
            let path = i.path(c);
            let seg = path.rsplit('.').next()?.as_bytes();
            let edge = match seg {
                [b'_', b'L', ..] => false,
                [b'_', b'E', ..] => true,
                _ => return None,
            };
            let digits = core::str::from_utf8(seg.get(2..4)?).ok()?;
            let number = u8::from_str_radix(digits, 16).ok()?;
            Some(GpeHandler { number, edge, method: c })
        })
        .collect();
    out.sort_by_key(|h| h.number);
    out
}

/// Every device, depth first from the root.
fn devices<H: Host>(i: &Interpreter<H>) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut todo = alloc::vec![ROOT];
    while let Some(n) = todo.pop() {
        for c in i.children(n) {
            if i.object(c).is_scope() {
                todo.push(c);
            }
            if matches!(i.object(c), Object::Device) {
                out.push(c);
            }
        }
    }
    out.sort_unstable();
    out
}

/// The events in the `\_GPE` block that devices wake the system with
/// (`_PRW`'s first element, chapter 7; a package there names another
/// GPE block device, which is left out). They stay off while the system
/// runs: their handlers are for waking (§5.6.4: the OS enables the wake
/// events of the devices it arms before it sleeps).
pub fn wake_gpes<H: Host>(i: &mut Interpreter<H>) -> Vec<u8> {
    let mut out = Vec::new();
    for d in devices(i) {
        let Ok(Some(Value::Package(p))) = i.evaluate_child(d, "_PRW", Vec::new()) else { continue };
        let first = p.borrow().first().and_then(Value::as_int);
        if let Some(n) = first.and_then(|n| u8::try_from(n).ok())
            && !out.contains(&n)
        {
            out.push(n);
        }
    }
    out.sort_unstable();
    out
}

/// Whether `dev`'s `_HID` or one of its `_CID`s is `id` (`PNP0C0C`), as
/// a string or a compressed EISA ID (§6.1.2, §6.1.5).
pub fn has_id<H: Host>(i: &mut Interpreter<H>, dev: NodeId, id: &[u8]) -> bool {
    let eisa = crate::eisa_id(id).map(u64::from);
    let is = |v: &Value| match v {
        Value::Integer(n) => Some(*n) == eisa,
        Value::String(s) => s.borrow().as_slice() == id,
        _ => false,
    };
    ["_HID", "_CID"].iter().any(|m| match i.evaluate_child(dev, m, Vec::new()) {
        Ok(Some(Value::Package(p))) => p.borrow().iter().any(is),
        Ok(Some(v)) => is(&v),
        _ => false,
    })
}

/// The devices with `id`.
pub fn devices_with_id<H: Host>(i: &mut Interpreter<H>, id: &[u8]) -> Vec<NodeId> {
    devices(i).into_iter().filter(|&d| has_id(i, d, id)).collect()
}

/// The thermal zones (§11.4), in namespace order.
pub fn thermal_zones<H: Host>(i: &Interpreter<H>) -> Vec<NodeId> {
    let mut out = Vec::new();
    let mut todo = alloc::vec![ROOT];
    while let Some(n) = todo.pop() {
        let mut kids = i.children(n);
        kids.reverse();
        for c in kids {
            if matches!(i.object(c), Object::ThermalZone) {
                out.push(c);
            } else if i.object(c).is_scope() && !matches!(i.object(c), Object::Method(_)) {
                todo.push(c);
            }
        }
    }
    out.sort_unstable();
    out
}

/// A temperature as `_TMP`, `_CRT` and the other thermal objects give it,
/// in tenths of a kelvin (chapter 11), in thousandths of a degree
/// Celsius; ACPI's tables put 0 °C at 2732.
pub fn millicelsius(tenths_kelvin: u64) -> i64 {
    (tenths_kelvin as i64 - 2732) * 100
}
