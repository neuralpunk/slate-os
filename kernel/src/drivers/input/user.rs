// SPDX-License-Identifier: MIT OR Apache-2.0

//! /dev/slate-hid (ADR 0176): HID devices whose transport is in user space,
//! such as Bluetooth's (slate-btd speaks HID over GATT and hands the
//! reports here). Each open is one device; its messages are
//! `slate_hid::user`'s. The report descriptor is read as USB's are and its
//! reports become evdev events the same way (`input::hid`).
//!
//! Slate's own interface: misc major 10, minor 248 (devices.txt's local-use
//! range, after the Bluetooth controllers' 240-247), root only.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use slate_hid::user;

use super::hid::{Ident, Reports};
use crate::abi::linux::errno::*;
use crate::fs::vfs::{self, Metadata, Result};
use crate::fs::{File, O_NONBLOCK, POLLIN, POLLOUT};
use crate::sched::wait::{Mutex, WaitQueue};
use crate::sync::IrqSpinLock;

pub const USER_HID_MINOR: u32 = 248;

/// Output reports waiting to be read, at most this many.
const OUTPUT_QUEUE: usize = 16;

struct Shared {
    out: IrqSpinLock<VecDeque<Vec<u8>>>,
    wait: WaitQueue,
    count: AtomicU64,
}

pub struct UserHid {
    reports: Mutex<Option<Arc<Reports>>>,
    shared: Arc<Shared>,
    flags: AtomicU32,
}

/// Open /dev/slate-hid: a new device, made by its first write.
pub fn open(flags: u32) -> Result<Arc<dyn File>> {
    Ok(Arc::new(UserHid {
        reports: Mutex::new(None),
        shared: Arc::new(Shared {
            out: IrqSpinLock::new(VecDeque::new()),
            wait: WaitQueue::new(),
            count: AtomicU64::new(0),
        }),
        flags: AtomicU32::new(flags),
    }))
}

impl UserHid {
    /// Its pointer's evdev device (the in-kernel tests).
    pub fn pointer(&self) -> Option<Arc<super::Device>> {
        self.reports.lock().as_ref().and_then(|r| r.pointer.clone())
    }

    fn create(&self, c: &user::Create<'_>) -> Result<()> {
        let mut slot = self.reports.lock();
        if slot.is_some() {
            return Err(EEXIST);
        }
        let desc = slate_hid::parse(c.descriptor).map_err(|_| EINVAL)?;
        let id = Ident {
            name: String::from(c.name),
            phys: String::from(c.phys),
            bustype: c.bus,
            vendor: c.vendor,
            product: c.product,
            version: c.version,
        };
        // Nothing Slate supports (neither keys nor a pointer).
        let pointer_only = c.flags & user::FLAG_POINTER_ONLY != 0;
        let reports = Arc::new(Reports::with(Arc::new(desc), &id, pointer_only).ok_or(EOPNOTSUPP)?);
        if let Some(kbd) = &reports.keyboard {
            // The lights go back as output reports to read (weakly: the
            // keyboard's handler must not keep its device alive).
            let (r, sh) = (Arc::downgrade(&reports), Arc::downgrade(&self.shared));
            kbd.set_led_handler(alloc::boxed::Box::new(move |leds| {
                let (Some(r), Some(sh)): (Option<Arc<Reports>>, Option<Arc<Shared>>) =
                    (Weak::upgrade(&r), sh.upgrade())
                else {
                    return;
                };
                let Some((id, report)) = r.led_report(leds as u8) else { return };
                let mut q = sh.out.lock();
                if q.len() < OUTPUT_QUEUE {
                    q.push_back(user::output(id, &report));
                }
                drop(q);
                sh.count.fetch_add(1, Ordering::Release);
                sh.wait.wake_all();
                crate::fs::poll_notify();
            }));
        }
        crate::log_info!("input: {} from user space ({} report fields)", c.name, reports.desc.fields.len());
        *slot = Some(reports);
        Ok(())
    }
}

impl Drop for UserHid {
    fn drop(&mut self) {
        if let Some(r) = self.reports.lock().take() {
            r.unregister();
        }
    }
}

impl File for UserHid {
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    /// One message: [`user::CREATE`] first, then [`user::INPUT`]s.
    fn write(&self, buf: &[u8]) -> Result<usize> {
        match buf.first() {
            Some(&user::CREATE) => self.create(&user::Create::decode(buf).ok_or(EINVAL)?)?,
            Some(&user::INPUT) if buf.len() - 1 <= user::MAX_REPORT => {
                let r = self.reports.lock().clone().ok_or(EINVAL)?;
                r.report(&buf[1..]);
            }
            _ => return Err(EINVAL),
        }
        Ok(buf.len())
    }

    /// One [`user::OUTPUT`] message.
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let sh = &self.shared;
        loop {
            {
                let mut q = sh.out.lock();
                if let Some(m) = q.front() {
                    if m.len() > buf.len() {
                        return Err(EINVAL);
                    }
                    let m = q.pop_front().unwrap_or_default();
                    buf[..m.len()].copy_from_slice(&m);
                    return Ok(m.len());
                }
            }
            if self.flags.load(Ordering::Relaxed) & O_NONBLOCK != 0 {
                return Err(EAGAIN);
            }
            if sh.wait.wait_until_interruptible(|| !sh.out.lock().is_empty()) {
                return Err(EINTR);
            }
        }
    }

    fn poll(&self) -> u16 {
        if self.shared.out.lock().is_empty() { POLLOUT } else { POLLIN | POLLOUT }
    }

    fn event_count(&self) -> u64 {
        self.shared.count.load(Ordering::Acquire)
    }

    fn status_flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, flags: u32) {
        let keep = self.flags.load(Ordering::Relaxed) & !O_NONBLOCK;
        self.flags.store(keep | (flags & O_NONBLOCK), Ordering::Relaxed);
    }

    fn stat(&self) -> Result<Metadata> {
        let rdev = vfs::makedev(crate::fs::devices::MISC_MAJOR, USER_HID_MINOR);
        Ok(Metadata { mode: vfs::S_IFCHR | 0o600, rdev, nlink: 1, ..Metadata::default() })
    }
}

pub const TESTS: &[crate::ktest::Test] = &[crate::ktest::Test { name: "input::user_hid", run: test_user_hid }];

/// A device made through /dev/slate-hid: a mouse whose reports become
/// events, and which goes when it is closed.
fn test_user_hid() -> core::result::Result<(), &'static str> {
    // A mouse (HID 1.11 appendix E.10's, with a wheel).
    let mouse_only: [u8; 52] = [
        0x05, 0x01, 0x09, 0x02, 0xA1, 0x01, 0x09, 0x01, 0xA1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x03, 0x15, 0x00,
        0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x30,
        0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7F, 0x75, 0x08, 0x95, 0x03, 0x81, 0x06, 0xC0, 0xC0,
    ];
    let f = open(O_NONBLOCK).map_err(|_| "no device")?;
    let hid = f.as_any().and_then(|a| a.downcast_ref::<UserHid>()).ok_or("not a UserHid")?;
    if f.write(&user::input(&[0, 1, 1, 0])).is_ok() {
        return Err("a report before the device was made was taken");
    }
    let create = user::Create {
        bus: super::BUS_BLUETOOTH,
        vendor: 0x046D,
        product: 0xB032,
        version: 1,
        flags: 0,
        name: "Test BT",
        phys: "bt-test",
        descriptor: &mouse_only,
    };
    f.write(&create.encode()).map_err(|_| "create refused")?;
    if f.write(&create.encode()).is_ok() {
        return Err("made twice");
    }
    let p = hid.pointer().ok_or("no pointer")?;
    let c = super::test_client(&p);
    f.write(&user::input(&[0x02, 0, 7, 0])).map_err(|_| "a report refused")?;
    let want = [(super::EV_REL, super::REL_Y, 7), (super::EV_KEY, super::BTN_RIGHT, 1), (super::EV_SYN, 0, 0)];
    if c.taken() != want {
        return Err("the report became the wrong events");
    }
    let mut buf = [0u8; 16];
    if f.read(&mut buf) != Err(EAGAIN) {
        return Err("a mouse has output to read");
    }
    let index = p.index;
    drop(c);
    drop(p);
    drop(f);
    if super::exists(index) {
        return Err("the pointer stayed after the close");
    }
    // A keyboard (HID 1.11 appendix E.6) may not type when made pointer
    // only: nothing is left to make.
    const KEYBOARD: [u8; 63] = [
        0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
        0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01, 0x05, 0x08, 0x19, 0x01,
        0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06, 0x75, 0x08, 0x15, 0x00, 0x25, 0x65,
        0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0,
    ];
    let kbd = user::Create { descriptor: &KEYBOARD, flags: user::FLAG_POINTER_ONLY, ..create };
    let f = open(O_NONBLOCK).map_err(|_| "no device")?;
    if f.write(&kbd.encode()) != Err(EOPNOTSUPP) {
        return Err("a pointer-only keyboard was made");
    }
    let f = open(O_NONBLOCK).map_err(|_| "no device")?;
    f.write(&user::Create { flags: 0, ..kbd }.encode()).map_err(|_| "a keyboard refused")?;
    Ok(())
}
