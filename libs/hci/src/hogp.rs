// SPDX-License-Identifier: MIT OR Apache-2.0

//! An HID host over GATT (HID over GATT Profile 1.0, HID Service 1.0;
//! ADR 0176): on an encrypted LE link, find the HID service, read its
//! report map and which report each characteristic carries, turn the input
//! reports' notifications on, and from then on turn each notification
//! into the report the kernel takes (/dev/slate-hid). The device's name
//! (GAP) and its PnP ID (Device Information) name it.
//!
//! It holds no I/O: it is given each ATT PDU from the device and answers
//! with the requests to send, one at a time (ATT has one request
//! outstanding, Vol 3, Part F, §3.3.2).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

use crate::att::{self, Uuid};

/// What the device is, once read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HidDevice {
    pub descriptor: Vec<u8>,
    pub name: Option<String>,
    /// From the PnP ID (vendor ID source, vendor, product, version).
    pub vendor: u16,
    pub product: u16,
    pub version: u16,
    /// Input report value handles and their report IDs.
    pub inputs: Vec<(u16, u8)>,
    /// Output report value handles and their report IDs (a keyboard's
    /// lights).
    pub outputs: Vec<(u16, u8)>,
}

impl HidDevice {
    /// Whether its report map names report IDs (an ID byte then goes
    /// first in each report: HID 1.11 §6.2.2.7).
    pub fn uses_ids(&self) -> bool {
        let d = &self.descriptor;
        let mut i = 0;
        while i < d.len() {
            let b = d[i];
            if b == 0xFE {
                // A long item: its size is the next byte.
                i += 3 + usize::from(*d.get(i + 1).unwrap_or(&0));
                continue;
            }
            if b & 0xFC == 0x84 {
                return true;
            }
            i += 1 + [0, 1, 2, 4][usize::from(b & 3)];
        }
        false
    }
}

/// What to do next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// Send this ATT PDU.
    Send(Vec<u8>),
    /// The device is ready: make its HID device.
    Ready(HidDevice),
    /// An input report, its ID byte first when the map names IDs.
    Report(Vec<u8>),
    /// It can't be used, and why.
    Failed(String),
}

/// A characteristic found: its declaration, properties, value handle,
/// type, and the last handle its descriptors may have.
#[derive(Clone, Copy, Debug)]
struct Char {
    decl: u16,
    props: u8,
    value: u16,
    kind: Uuid,
    end: u16,
}

/// A report characteristic's descriptors once found.
#[derive(Clone, Copy, Debug, Default)]
struct ReportChar {
    value: u16,
    props: u8,
    reference: Option<u16>,
    cccd: Option<u16>,
    id: u8,
    /// 1 input, 2 output, 3 feature (HID Service §3.6.1.1).
    kind: u8,
}

/// The step under way, with what it waits for.
#[derive(Clone, Debug)]
enum Stage {
    Mtu,
    /// The services, page by page.
    Services,
    /// Characteristics of service `n` (of `services`).
    Chars(usize),
    /// Descriptors of report `n`.
    Descriptors(usize),
    /// The reads and writes queued.
    Requests,
    Ready,
    Failed,
}

/// A queued read or write and what it is for.
#[derive(Clone, Copy, Debug)]
enum Job {
    /// The report map, from this offset.
    ReportMap(u16, u16),
    /// Report `n`'s reference.
    Reference(usize, u16),
    Pnp(u16),
    Name(u16),
    /// Notifications on (the CCCD's handle).
    Notify(u16),
}

#[derive(Debug)]
pub struct Client {
    stage: Stage,
    mtu: u16,
    services: Vec<(u16, u16, Uuid)>,
    chars: Vec<Char>,
    reports: Vec<ReportChar>,
    jobs: VecDeque<Job>,
    device: HidDevice,
    uses_ids: bool,
    /// The input reports' notifications are queued (after the reads).
    notify_queued: bool,
}

impl Client {
    /// Start on an encrypted link: the first request to send.
    pub fn start() -> (Client, Vec<u8>) {
        let c = Client {
            stage: Stage::Mtu,
            mtu: att::DEFAULT_MTU,
            services: Vec::new(),
            chars: Vec::new(),
            reports: Vec::new(),
            jobs: VecDeque::new(),
            device: HidDevice::default(),
            uses_ids: false,
            notify_queued: false,
        };
        (c, att::exchange_mtu(att::OUR_MTU))
    }

    pub fn ready(&self) -> bool {
        matches!(self.stage, Stage::Ready)
    }

    /// The device, once ready.
    pub fn device(&self) -> Option<&HidDevice> {
        self.ready().then_some(&self.device)
    }

    fn fail(&mut self, why: &str) -> Vec<Out> {
        self.stage = Stage::Failed;
        alloc::vec![Out::Failed(String::from(why))]
    }

    /// An ATT PDU from the device.
    pub fn received(&mut self, pdu: &[u8]) -> Vec<Out> {
        let Some(&op) = pdu.first() else { return Vec::new() };
        match op {
            att::HANDLE_VALUE_NTF => return self.notification(pdu),
            // Indications are confirmed, whatever they say.
            att::HANDLE_VALUE_IND => return alloc::vec![Out::Send(alloc::vec![att::HANDLE_VALUE_CFM])],
            // A request from the device (Slate's GATT server is empty).
            op if op & 1 == 0 && op != att::HANDLE_VALUE_CFM && op & 0x40 == 0 => {
                return alloc::vec![Out::Send(att::error(op, 0, att::ERR_REQUEST_NOT_SUPPORTED))];
            }
            _ => {}
        }
        let err = att::parse_error(pdu);
        match self.stage.clone() {
            Stage::Mtu => {
                if op == att::EXCHANGE_MTU_RSP
                    && let Some(m) = pdu.get(1..3)
                {
                    self.mtu = u16::from_le_bytes([m[0], m[1]]).clamp(att::DEFAULT_MTU, att::OUR_MTU);
                }
                // An error (MTU exchange not supported) keeps 23.
                self.stage = Stage::Services;
                alloc::vec![Out::Send(att::read_by_group_type(1, 0xFFFF, att::PRIMARY_SERVICE))]
            }
            Stage::Services => {
                if let Some(groups) = att::parse_groups(pdu) {
                    let last = groups.last().map_or(0xFFFF, |g| g.1);
                    self.services.extend(groups);
                    if last < 0xFFFF {
                        self.stage = Stage::Services;
                        return alloc::vec![Out::Send(att::read_by_group_type(last + 1, 0xFFFF, att::PRIMARY_SERVICE))];
                    }
                } else if err.is_none_or(|e| e.2 != att::ERR_ATTRIBUTE_NOT_FOUND) {
                    return self.fail("its services couldn't be read");
                }
                // Only the services the host reads characteristics of.
                self.services.retain(|s| {
                    [att::SERVICE_HID, att::SERVICE_DEVICE_INFORMATION, att::SERVICE_GAP].iter().any(|&u| s.2.is(u))
                });
                if !self.services.iter().any(|s| s.2.is(att::SERVICE_HID)) {
                    return self.fail("it has no HID service");
                }
                self.next_chars(0, self.services[0].0)
            }
            Stage::Chars(n) => {
                let end = self.services[n].1;
                if let Some(found) = att::parse_by_type(pdu) {
                    let mut last = 0;
                    for (decl, v) in found {
                        last = decl;
                        if let Some((props, value, kind)) = att::parse_characteristic(&v) {
                            self.chars.push(Char { decl, props, value, kind, end });
                        }
                    }
                    if last < end && last != 0 {
                        return self.next_chars(n, last + 1);
                    }
                } else if err.is_none_or(|e| e.2 != att::ERR_ATTRIBUTE_NOT_FOUND) {
                    return self.fail("its characteristics couldn't be read");
                }
                if n + 1 < self.services.len() {
                    return self.next_chars(n + 1, self.services[n + 1].0);
                }
                self.chars_found()
            }
            Stage::Descriptors(n) => {
                let end = self.char_end(self.reports[n].value);
                if let Some(found) = att::parse_information(pdu) {
                    let mut last = 0;
                    for (h, kind) in found {
                        last = h;
                        if kind.is(att::REPORT_REFERENCE) {
                            self.reports[n].reference = Some(h);
                        } else if kind.is(att::CCCD) {
                            self.reports[n].cccd = Some(h);
                        }
                    }
                    if last < end && last != 0 {
                        self.stage = Stage::Descriptors(n);
                        return alloc::vec![Out::Send(att::find_information(last + 1, end))];
                    }
                } else if err.is_none_or(|e| e.2 != att::ERR_ATTRIBUTE_NOT_FOUND) {
                    return self.fail("its reports' descriptors couldn't be read");
                }
                self.next_descriptors(n + 1)
            }
            Stage::Requests => self.job_done(pdu, err),
            Stage::Ready | Stage::Failed => Vec::new(),
        }
    }

    fn next_chars(&mut self, n: usize, from: u16) -> Vec<Out> {
        let end = self.services[n].1;
        if from > end {
            if n + 1 < self.services.len() {
                return self.next_chars(n + 1, self.services[n + 1].0);
            }
            return self.chars_found();
        }
        self.stage = Stage::Chars(n);
        alloc::vec![Out::Send(att::read_by_type(from, end, att::CHARACTERISTIC))]
    }

    /// The last handle characteristic `value`'s descriptors may have: up
    /// to the next declaration, or its service's end.
    fn char_end(&self, value: u16) -> u16 {
        let c = self.chars.iter().find(|c| c.value == value);
        let end = c.map_or(value, |c| c.end);
        self.chars.iter().filter(|o| o.decl > value).map(|o| o.decl - 1).min().unwrap_or(end).min(end)
    }

    fn chars_found(&mut self) -> Vec<Out> {
        let hid = self.services.iter().find(|s| s.2.is(att::SERVICE_HID)).copied();
        let Some((hs, he, _)) = hid else { return self.fail("it has no HID service") };
        let in_hid = |c: &Char| c.decl >= hs && c.decl <= he;
        self.reports = self
            .chars
            .iter()
            .filter(|c| in_hid(c) && c.kind.is(att::REPORT))
            .map(|c| ReportChar { value: c.value, props: c.props, ..ReportChar::default() })
            .collect();
        if !self.chars.iter().any(|c| in_hid(c) && c.kind.is(att::REPORT_MAP)) {
            return self.fail("its HID service has no report map");
        }
        self.next_descriptors(0)
    }

    fn next_descriptors(&mut self, n: usize) -> Vec<Out> {
        let Some(r) = self.reports.get(n) else { return self.queue_jobs() };
        let (from, end) = (r.value + 1, self.char_end(r.value));
        if from > end {
            return self.next_descriptors(n + 1);
        }
        self.stage = Stage::Descriptors(n);
        alloc::vec![Out::Send(att::find_information(from, end))]
    }

    fn queue_jobs(&mut self) -> Vec<Out> {
        let find = |kind: u16| self.chars.iter().find(|c| c.kind.is(kind)).map(|c| c.value);
        if let Some(h) = find(att::REPORT_MAP) {
            self.jobs.push_back(Job::ReportMap(h, 0));
        }
        for (n, r) in self.reports.iter().enumerate() {
            if let Some(h) = r.reference {
                self.jobs.push_back(Job::Reference(n, h));
            }
        }
        if let Some(h) = find(att::PNP_ID) {
            self.jobs.push_back(Job::Pnp(h));
        }
        if let Some(h) = find(att::DEVICE_NAME) {
            self.jobs.push_back(Job::Name(h));
        }
        self.stage = Stage::Requests;
        self.next_job()
    }

    fn job_request(job: Job) -> Vec<u8> {
        match job {
            Job::ReportMap(h, 0) => att::read(h),
            Job::ReportMap(h, off) => att::read_blob(h, off),
            Job::Reference(_, h) | Job::Pnp(h) | Job::Name(h) => att::read(h),
            Job::Notify(h) => att::write(h, &[1, 0]),
        }
    }

    fn next_job(&mut self) -> Vec<Out> {
        // The reads done: the reports' kinds are known, so notifications
        // go on.
        if self.jobs.is_empty() && !self.notify_queued {
            self.notify_queued = true;
            self.queue_notifications();
        }
        match self.jobs.front() {
            Some(&j) => alloc::vec![Out::Send(Self::job_request(j))],
            None => self.ready_now(),
        }
    }

    fn job_done(&mut self, pdu: &[u8], err: Option<(u8, u16, u8)>) -> Vec<Out> {
        let Some(job) = self.jobs.pop_front() else { return Vec::new() };
        let value = (err.is_none() && matches!(pdu.first(), Some(&att::READ_RSP | &att::READ_BLOB_RSP)))
            .then(|| pdu[1..].to_vec());
        if let Some((_, _, code)) = err
            && matches!(code, att::ERR_INSUFFICIENT_ENCRYPTION | att::ERR_INSUFFICIENT_AUTHENTICATION)
        {
            return self.fail("it wants an encrypted link");
        }
        match job {
            Job::ReportMap(h, off) => {
                let Some(v) = value else { return self.fail("its report map couldn't be read") };
                let full = v.len() == usize::from(self.mtu) - 1;
                self.device.descriptor.extend_from_slice(&v);
                if full && self.device.descriptor.len() < 4096 {
                    self.jobs.push_front(Job::ReportMap(h, off + v.len() as u16));
                }
            }
            Job::Reference(n, _) => {
                if let Some(v) = value.filter(|v| v.len() >= 2) {
                    self.reports[n].id = v[0];
                    self.reports[n].kind = v[1];
                }
            }
            Job::Pnp(_) => {
                if let Some(v) = value.filter(|v| v.len() >= 7) {
                    let w = |i: usize| u16::from_le_bytes([v[i], v[i + 1]]);
                    (self.device.vendor, self.device.product, self.device.version) = (w(1), w(3), w(5));
                }
            }
            Job::Name(_) => {
                self.device.name = value.map(|v| String::from(String::from_utf8_lossy(&v).trim_end_matches('\0')));
            }
            // A CCCD refused leaves that report quiet; the others go on.
            Job::Notify(_) => {}
        }
        self.next_job()
    }

    /// Notifications on for every input report that has them, once the
    /// reports' kinds are known.
    fn queue_notifications(&mut self) {
        self.device.inputs.clear();
        self.device.outputs.clear();
        for r in &self.reports {
            match r.kind {
                1 => {
                    self.device.inputs.push((r.value, r.id));
                    if let Some(c) = r.cccd.filter(|_| r.props & att::PROP_NOTIFY != 0) {
                        self.jobs.push_back(Job::Notify(c));
                    }
                }
                2 => self.device.outputs.push((r.value, r.id)),
                _ => {}
            }
        }
    }

    fn ready_now(&mut self) -> Vec<Out> {
        if self.device.inputs.is_empty() {
            return self.fail("it has no input reports");
        }
        self.uses_ids = self.device.uses_ids();
        self.stage = Stage::Ready;
        alloc::vec![Out::Ready(self.device.clone())]
    }

    fn notification(&self, pdu: &[u8]) -> Vec<Out> {
        if !self.ready() || pdu.len() < 3 {
            return Vec::new();
        }
        let h = u16::from_le_bytes([pdu[1], pdu[2]]);
        let Some(&(_, id)) = self.device.inputs.iter().find(|(v, _)| *v == h) else { return Vec::new() };
        let mut r = Vec::with_capacity(pdu.len() - 2);
        if self.uses_ids {
            r.push(id);
        }
        r.extend_from_slice(&pdu[3..]);
        alloc::vec![Out::Report(r)]
    }

    /// The output report `id` as a write to its characteristic (a
    /// keyboard's lights), if it has one.
    pub fn output(&self, id: u8, report: &[u8]) -> Option<Vec<u8>> {
        let &(h, _) = self.device.outputs.iter().find(|(_, i)| *i == id)?;
        let data = if self.uses_ids { report.get(1..)? } else { report };
        let mut p = alloc::vec![att::WRITE_CMD];
        p.extend_from_slice(&h.to_le_bytes());
        p.extend_from_slice(data);
        Some(p)
    }
}

/// A mouse's GATT database as a device would have it (the simulator's):
/// GAP's name, Device Information's PnP ID, Battery, and HID with a
/// report map whose report 1 is three buttons, 8-bit X, Y and wheel.
/// The input report's value handle is returned with it.
pub fn mouse_server(name: &str, vendor: u16, product: u16) -> (att::Server, u16) {
    let mut s = att::Server::new();
    s.service(att::SERVICE_GAP);
    s.characteristic(att::DEVICE_NAME, att::PROP_READ, name.as_bytes(), false);
    s.service(att::SERVICE_DEVICE_INFORMATION);
    let mut pnp = alloc::vec![2];
    for v in [vendor, product, 0x0013] {
        pnp.extend_from_slice(&v.to_le_bytes());
    }
    s.characteristic(att::PNP_ID, att::PROP_READ, &pnp, false);
    s.service(att::SERVICE_BATTERY);
    s.characteristic(att::BATTERY_LEVEL, att::PROP_READ | att::PROP_NOTIFY, &[95], false);
    s.service(att::SERVICE_HID);
    s.characteristic(att::HID_INFORMATION, att::PROP_READ, &[0x11, 0x01, 0, 2], true);
    s.characteristic(att::REPORT_MAP, att::PROP_READ, &MOUSE_REPORT_MAP, true);
    let input = s.characteristic(att::REPORT, att::PROP_READ | att::PROP_NOTIFY, &[0, 0, 0, 0], true);
    s.descriptor(att::REPORT_REFERENCE, &[1, 1], true);
    s.characteristic(att::PROTOCOL_MODE, att::PROP_READ | att::PROP_WRITE_NO_RSP, &[1], true);
    (s, input)
}

/// HID 1.11 appendix E.10's mouse with report ID 1 and a wheel.
pub const MOUSE_REPORT_MAP: [u8; 54] = [
    0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x85, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15,
    0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30,
    0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xC0, 0xC0,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The host against a mouse's server, MTU 23 so the map comes in
    /// pieces: ready with the right map, names and report, notifications
    /// on, and a notification turned into a report.
    #[test]
    fn a_mouse() {
        let (mut server, input) = mouse_server("Logi M650 L B", 0x046D, 0xB032);
        server.max_mtu = 23;
        let (mut c, first) = Client::start();
        let mut pdu = first;
        let mut ready = None;
        for _ in 0..60 {
            let (rsp, _) = server.serve(&pdu, true);
            let outs = c.received(&rsp.unwrap());
            let mut next = None;
            for o in outs {
                match o {
                    Out::Send(p) => next = Some(p),
                    Out::Ready(d) => ready = Some(d),
                    o => panic!("{o:?}"),
                }
            }
            match next {
                Some(p) => pdu = p,
                None => break,
            }
        }
        let d = ready.expect("ready");
        assert_eq!(d.descriptor, MOUSE_REPORT_MAP);
        assert_eq!((d.name.as_deref(), d.vendor, d.product), (Some("Logi M650 L B"), 0x046D, 0xB032));
        assert_eq!(d.inputs, [(input, 1)]);
        assert!(d.uses_ids());
        assert_eq!(server.get(input + 1).unwrap().value, [1, 0], "notifications on");
        assert_eq!(
            c.received(&att::notification(input, &[1, 5, 0xFD, 0])),
            [Out::Report(alloc::vec![1, 1, 5, 0xFD, 0])]
        );
        // Another handle's notification (the battery) is no report.
        assert_eq!(c.received(&att::notification(input - 3, &[50])), []);
        // An indication is confirmed.
        assert_eq!(c.received(&[att::HANDLE_VALUE_IND, 1, 0]), [Out::Send(alloc::vec![att::HANDLE_VALUE_CFM])]);
    }

    #[test]
    fn not_a_hid_device() {
        let mut s = att::Server::new();
        s.service(att::SERVICE_GAP);
        s.characteristic(att::DEVICE_NAME, att::PROP_READ, b"Watch", false);
        let (mut c, first) = Client::start();
        let (r, _) = s.serve(&first, true);
        let Out::Send(p) = c.received(&r.unwrap()).remove(0) else { panic!() };
        let (r, _) = s.serve(&p, true);
        let Out::Send(p) = c.received(&r.unwrap()).remove(0) else { panic!() };
        let (r, _) = s.serve(&p, true);
        assert_eq!(c.received(&r.unwrap()), [Out::Failed(String::from("it has no HID service"))]);
    }
}
