// SPDX-License-Identifier: MIT OR Apache-2.0

//! MediaTek's Bluetooth controllers' firmware (ADR 0176's phase 4): the
//! files the kernel downloads to MT79xx controllers, from linux-firmware
//! on the build machine (Fedora's `mt7xxx-firmware`, xz-compressed in
//! /usr/lib/firmware; another directory with `SLATE_LINUX_FIRMWARE`),
//! decompressed once into target/bt/firmware, never committed (ADR 0012's
//! firmware exception), for the `slate-firmware-bt` package: on the
//! install media's live system, and installed on machines with such a
//! controller (the owner, 2026-10-29).

/// The files, by their names under /lib/firmware (`slate_hci::mtk`'s
/// names: MT7961 and its 1a flavour, MT7922, MT7902, MT7925).
pub const FILES: [&str; 5] = [
    "mediatek/BT_RAM_CODE_MT7961_1_2_hdr.bin",
    "mediatek/BT_RAM_CODE_MT7961_1a_2_hdr.bin",
    "mediatek/BT_RAM_CODE_MT7922_1_1_hdr.bin",
    "mediatek/BT_RAM_CODE_MT7902_1_1_hdr.bin",
    "mediatek/mt7925/BT_RAM_CODE_MT7925_1_1_hdr.bin",
];

/// MediaTek's licence for them, as linux-firmware ships it.
const LICENSES: [&str; 2] =
    ["/usr/share/licenses/mt7xxx-firmware/LICENCE.mediatek", "/usr/share/licenses/linux-firmware/LICENCE.mediatek"];

/// The package's directories.
pub const DIRS: [&str; 7] = [
    "lib",
    "lib/firmware",
    "lib/firmware/mediatek",
    "lib/firmware/mediatek/mt7925",
    "usr",
    "usr/share/licenses",
    "usr/share/licenses/slate-firmware-bt",
];

/// Every file and the licence (its path in the package, its bytes), or
/// none if any is missing.
pub fn files() -> Option<Vec<(String, Vec<u8>)>> {
    let mut v: Vec<(String, Vec<u8>)> = FILES
        .iter()
        .map(|n| crate::gpufw::linux_firmware(n, "bt/firmware").map(|d| (format!("lib/firmware/{n}"), d)))
        .collect::<Option<_>>()?;
    let licence = LICENSES.iter().find_map(|p| std::fs::read(p).ok())?;
    v.push(("usr/share/licenses/slate-firmware-bt/LICENCE.mediatek".into(), licence));
    Some(v)
}
