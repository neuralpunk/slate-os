// SPDX-License-Identifier: MIT OR Apache-2.0

//! Firmware files for drivers (ADR 0171): a driver asks for a file under
//! `/lib/firmware` and is called back with its contents (or `None`) on a
//! kernel thread once the root file system is there. Drivers probe before
//! the root is mounted, so requests made then wait for it.
//!
//! Firmware is never part of Slate's base (ADR 0012's firmware exception;
//! ADR 0157: `slate-firmware-gpu`, installed on request); a driver without
//! its file carries on without what the file would have given it.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::vfs;
use crate::sync::IrqSpinLock;
use crate::{log_info, log_warn};

/// The largest file a driver may ask for.
const MAX: u64 = 16 << 20;

type Then = Box<dyn FnOnce(Option<Vec<u8>>) + Send>;

/// Requests made before the root was mounted; `None` once it is.
static WAITING: IrqSpinLock<Option<Vec<(String, Then)>>> = IrqSpinLock::new(Some(Vec::new()));

/// Ask for `/lib/firmware/NAME`; `then` gets its contents on a kernel
/// thread of its own.
pub fn request(name: &str, then: impl FnOnce(Option<Vec<u8>>) + Send + 'static) {
    let then: Then = Box::new(then);
    let mut w = WAITING.lock();
    match w.as_mut() {
        Some(list) => list.push((String::from(name), then)),
        None => {
            drop(w);
            run(String::from(name), then);
        }
    }
}

/// The root file system is mounted: answer the requests made so far.
pub fn root_ready() {
    let list = WAITING.lock().take().unwrap_or_default();
    for (name, then) in list {
        run(name, then);
    }
}

fn run(name: String, then: Then) {
    crate::sched::spawn("firmware", move || then(read(&name)));
}

/// Read `/lib/firmware/NAME` now (once the root is mounted: from a
/// request's callback, say).
pub fn read(name: &str) -> Option<Vec<u8>> {
    let path = alloc::format!("/lib/firmware/{name}");
    let d = match vfs::resolve(&vfs::root(), &path, true) {
        Ok(d) => d,
        Err(e) => {
            log_info!("firmware: no {path} ({e:?})");
            return None;
        }
    };
    let size = d.metadata().size;
    if size > MAX {
        log_warn!("firmware: {path} is {size} bytes, more than a driver may load");
        return None;
    }
    let mut data = alloc::vec![0u8; size as usize];
    let mut done = 0;
    while done < data.len() {
        match d.inode.read_at(done as u64, &mut data[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) => {
                log_warn!("firmware: reading {path}: {e:?}");
                return None;
            }
        }
    }
    data.truncate(done);
    log_info!("firmware: {path}, {done} bytes");
    Some(data)
}
