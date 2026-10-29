// SPDX-License-Identifier: MIT OR Apache-2.0

//! MediaTek's MT79xx USB Bluetooth controllers (ADR 0176's phase 4): their
//! firmware goes down before the controller is handed to the Bluetooth
//! daemon, as nothing answers HCI until it has. What the steps are, the
//! file's layout and the commands' bytes are `slate_hci::mtk`'s (read
//! from Linux's btmtk as documentation, the owner's exception); this is
//! the USB side:
//!
//! 1. the chip's ID, firmware version and flavour, from its registers;
//! 2. the file it wants, from /lib/firmware (`slate-firmware-bt`);
//! 3. each section: its map, then (unless the chip says it has it) its
//!    data, 250 bytes a command, each answered by an event read from the
//!    control endpoint;
//! 4. the endpoint reset option set, then Bluetooth turned on.
//!
//! A chip already set up (a warm restart from another system) says each
//! section is there. Without its file, or when a step fails, the
//! controller is handed over as it is: the daemon then reports it not
//! starting.

use alloc::sync::Arc;
use alloc::vec::Vec;

use slate_hci::mtk::{self, Wmt};

use super::xhci::UsbDevice;
use crate::drivers::dma::delay_ms;
use crate::{log_info, log_warn};

/// MediaTek's USB vendor ID: its own controllers (btusb's
/// `USB_VENDOR_AND_INTERFACE_INFO(0x0e8d, ...)` entry).
pub const VENDOR: u16 = 0x0E8D;

/// How long an answer may take (ms), polled every millisecond.
const ANSWER_MS: u64 = 3000;

/// Class request 0 to the device: an HCI command (Vol 4, Part B, §2.2).
const RT_CLASS_DEVICE_OUT: u8 = 0x20;

fn reg_read(dev: &UsbDevice, reg: u32) -> Option<u32> {
    let mut b = [0u8; 4];
    let (rt, req) = mtk::REQ_REG_READ;
    dev.control(rt, req, (reg >> 16) as u16, reg as u16, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

fn uhw_write(dev: &UsbDevice, reg: u32, value: u32) -> bool {
    let mut b = value.to_le_bytes();
    let (rt, req) = mtk::REQ_UHW_WRITE;
    dev.control(rt, req, (reg >> 16) as u16, reg as u16, &mut b).is_ok()
}

/// Send a WMT command and wait for its event; what it says.
fn wmt(dev: &UsbDevice, op: u8, flag: u8, data: &[u8]) -> Option<Wmt> {
    let mut cmd = mtk::wmt_command(op, flag, data);
    // Without the UART framing's type byte.
    dev.control(RT_CLASS_DEVICE_OUT, 0, 0, 0, &mut cmd[1..]).ok()?;
    let (rt, req, value, len) = mtk::REQ_WMT_EVENT;
    let mut buf = alloc::vec![0u8; len];
    for _ in 0..ANSWER_MS {
        // The answer is asked for until it comes (btmtk.c,
        // `btmtk_usb_wmt_recv`: an empty answer means not yet).
        if let Ok(n) = dev.control(rt, req, value, 0, &mut buf)
            && n > 0
        {
            return mtk::parse_wmt_event(&buf[..n], op);
        }
        delay_ms(1);
    }
    None
}

/// Set the controller on `dev` up; whether it is ready for HCI. Runs on
/// a thread of its own: the firmware waits for the root file system.
pub fn setup(dev: &Arc<UsbDevice>, then: impl FnOnce(bool) + Send + 'static) {
    let (Some(chip), Some(version), Some(flavor)) =
        (reg_read(dev, mtk::REG_CHIP_ID), reg_read(dev, mtk::REG_FW_VERSION), reg_read(dev, mtk::REG_FW_FLAVOR))
    else {
        log_warn!("USB port {}: MediaTek Bluetooth: its chip doesn't answer", dev.port);
        return then(false);
    };
    let Some(name) = mtk::firmware_name(chip, version, flavor) else {
        log_warn!("USB port {}: MediaTek Bluetooth MT{chip:04x}: not supported", dev.port);
        return then(false);
    };
    log_info!("USB port {}: MediaTek Bluetooth MT{chip:04x}, wants {name}", dev.port);
    let d = dev.clone();
    let wanted = name.clone();
    crate::drivers::firmware::request(&wanted, move |file| {
        let Some(file) = file else {
            log_warn!("USB port {}: no /lib/firmware/{name}: Bluetooth stays off (slate-firmware-bt)", d.port);
            return then(false);
        };
        then(download(&d, chip, &file));
    });
}

fn download(dev: &UsbDevice, chip: u32, file: &[u8]) -> bool {
    let Some(sections) = mtk::sections(file) else {
        log_warn!("USB port {}: MT{chip:04x}: the firmware file is damaged", dev.port);
        return false;
    };
    log_info!("USB port {}: MT{chip:04x}: firmware {}", dev.port, mtk::describe(file).unwrap_or_default());
    let mut sent = 0;
    for (i, s) in sections.iter().enumerate() {
        // The section's map first: whether the chip wants its data.
        let mut ask = Vec::with_capacity(53);
        ask.push(0);
        ask.extend_from_slice(&s.map);
        let mut state = None;
        for _ in 0..20 {
            state = wmt(dev, mtk::WMT_PATCH_DOWNLOAD, 0, &ask);
            if state != Some(Wmt::InProgress) {
                break;
            }
            delay_ms(100);
        }
        match state {
            Some(Wmt::Done) => continue,
            Some(Wmt::Undone) => {}
            other => {
                log_warn!("USB port {}: MT{chip:04x}: section {i} refused ({other:?})", dev.port);
                return false;
            }
        }
        for (flag, r) in mtk::blocks(s.data.len()) {
            match wmt(dev, mtk::WMT_PATCH_DOWNLOAD, flag, &s.data[r]) {
                Some(Wmt::InProgress) | None => {
                    log_warn!("USB port {}: MT{chip:04x}: section {i} wasn't taken", dev.port);
                    return false;
                }
                Some(_) => {}
            }
        }
        sent += 1;
    }
    // A moment for the firmware to start (btmtk.c: 100 to 120 ms).
    delay_ms(110);
    if !uhw_write(dev, mtk::REG_EP_RST_OPT, mtk::EP_RST_IN_OUT) {
        log_warn!("USB port {}: MT{chip:04x}: the endpoint reset option wasn't set", dev.port);
        return false;
    }
    match wmt(dev, mtk::WMT_FUNC_CTRL, 0, &[1]) {
        Some(Wmt::On | Wmt::TurningOn | Wmt::Done) => {
            log_info!("USB port {}: MT{chip:04x}: Bluetooth on ({sent} sections sent)", dev.port);
            true
        }
        other => {
            log_warn!("USB port {}: MT{chip:04x}: Bluetooth didn't turn on ({other:?})", dev.port);
            false
        }
    }
}
