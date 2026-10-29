// SPDX-License-Identifier: MIT OR Apache-2.0

//! "SlateOS only" or "full graphics" (ADR 0173): whether this machine has
//! a card Slate's AMD driver drives, whether AMD's firmware for it is
//! installed (the `slate-firmware-gpu` package), and the notice shown
//! before it is turned on. For Settings › Displays, About and the
//! installer.

use slate_rt::fs;

/// The package that brings AMD's firmware.
pub const PACKAGE: &str = "slate-firmware-gpu";

/// quarry's record of it when it is installed (ADR 0069).
const RECORD: &[u8] = b"/usr/lib/quarry/db/slate-firmware-gpu";

/// Where the AMD driver's PCI functions are (one link each, by address).
const AMD_DRIVER: &[u8] = b"/sys/bus/pci/drivers/amd-display";

/// The notice's title and text (ADR 0157's, with what full graphics
/// brings today).
pub const TITLE: &str = "Full graphics for your AMD Radeon card";
pub const NOTICE: &str = "SlateOS runs every graphics card on its own, with one display at the resolution your \
    computer starts with. For your monitor at its own resolution, smooth updates and a pointer drawn by the card, \
    SlateOS's driver loads AMD's firmware: software from AMD that runs on the card itself, which SlateOS didn't \
    write and can't inspect. The driver is SlateOS's own, written from AMD's documentation and from what the \
    open-source Linux drivers show about the hardware. You can turn this off again in Settings, Displays.";

/// How many AMD cards Slate's driver has (PCI functions bound to it).
pub fn amd_cards() -> usize {
    fs::read_dir(AMD_DRIVER).map_or(0, |d| d.iter().filter(|e| is_pci_address(&e.name)).count())
}

/// Whether AMD's firmware is installed (in this system: it takes effect
/// at a start).
pub fn full_graphics() -> bool {
    fs::exists(RECORD)
}

/// Whether the system's own repository has the package to install
/// (the media's, ADR 0071).
pub fn available() -> bool {
    fs::read_dir(b"/var/lib/quarry/install/pkgs")
        .is_ok_and(|d| d.iter().any(|e| e.name.starts_with(PACKAGE.as_bytes())))
}

/// `0000:15:00.0`, as sysfs names a PCI function.
fn is_pci_address(n: &[u8]) -> bool {
    n.len() == 12 && n[4] == b':' && n[7] == b':' && n[10] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert!(is_pci_address(b"0000:15:00.0"));
        assert!(!is_pci_address(b"bind"));
        assert!(!is_pci_address(b"new_id"));
    }
}
