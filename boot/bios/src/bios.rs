// SPDX-License-Identifier: MIT OR Apache-2.0

//! The BIOS services the loader calls, through [`rm::int`]. Sources: the
//! ACPI specification's INT 15h E820h (ACPI 6.5 §15.1), the Enhanced Disk
//! Drive specification 3.0 (INT 13h AH=41h, 42h), VESA BIOS Extension
//! Core Functions 3.0 (INT 10h AX=4F00h, 4F01h, 4F02h) and VBE/DDC 1.1
//! (AX=4F15h, an EDID block, E-EDID 1.3 §3.10), and the IBM PC BIOS's
//! keyboard (INT 16h AH=10h, 11h) and wait (INT 15h AH=86h) services.

use alloc::vec::Vec;

use crate::rm::{self, LOW, Regs};
use slate_loader::memmap::Region;
use slate_loader::proto::memtype;

/// The ACPI address range types (ACPI 6.5 table 15.1) as the kernel's.
fn kind(t: u32) -> u64 {
    match t {
        1 => memtype::USABLE,
        3 => memtype::ACPI_RECLAIMABLE,
        4 => memtype::ACPI_NVS,
        5 => memtype::BAD_MEMORY,
        _ => memtype::RESERVED,
    }
}

fn read<T: Copy>(addr: usize) -> T {
    // SAFETY: Low memory the BIOS just wrote, reachable one to one.
    unsafe { core::ptr::read_unaligned(addr as *const T) }
}

// The VBE blocks (512 and 256 bytes) and the EDID (128) fit the buffer.
const _: () = assert!(768 + 128 <= crate::rm::LOW_LEN);

/// The most memory map entries read.
pub const MAX_E820: usize = 256;

/// The memory map (INT 15h EAX=E820h), without the heap: the heap is
/// made from it. Returns the entries and how many there are.
pub fn memory_map() -> ([Region; MAX_E820], usize) {
    const SMAP: u32 = 0x534d_4150;
    let mut out = [Region { base: 0, len: 0, kind: 0 }; MAX_E820];
    let mut n = 0;
    let mut next = 0;
    while n < MAX_E820 {
        // SAFETY: `LOW` is the loader's scratch buffer.
        unsafe { core::ptr::write_bytes(LOW as *mut u8, 0, 24) };
        // A valid entry unless the BIOS clears it (ACPI 3.0 attributes).
        // SAFETY: As above.
        unsafe { core::ptr::write((LOW + 20) as *mut u32, 1) };
        let r =
            rm::int(0x15, Regs { eax: 0xe820, ebx: next, ecx: 24, edx: SMAP, edi: LOW as u32, ..Default::default() });
        if r.carry() || r.eax != SMAP {
            break;
        }
        let (base, len, t, attr): (u64, u64, u32, u32) = (read(LOW), read(LOW + 8), read(LOW + 16), read(LOW + 20));
        if len > 0 && (r.ecx < 24 || attr & 1 != 0) {
            out[n] = Region { base, len, kind: kind(t) };
            n += 1;
        }
        next = r.ebx;
        if next == 0 {
            break;
        }
    }
    (out, n)
}

/// Whether the drive has the extended disk calls.
pub fn extended_disk(drive: u8) -> bool {
    let r = rm::int(0x13, Regs { eax: 0x4100, ebx: 0x55aa, edx: u32::from(drive), ..Default::default() });
    !r.carry() && r.ebx & 0xffff == 0xaa55
}

/// Read `count` sectors (at most 64) from `lba` into the disk buffer.
pub fn read_sectors(drive: u8, lba: u64, count: u16) -> Result<(), ()> {
    let (seg, off) = rm::far(rm::DISK_BUFFER);
    let mut dap = [0u8; 16];
    dap[0] = 16;
    dap[2..4].copy_from_slice(&count.to_le_bytes());
    dap[4..6].copy_from_slice(&off.to_le_bytes());
    dap[6..8].copy_from_slice(&seg.to_le_bytes());
    dap[8..16].copy_from_slice(&lba.to_le_bytes());
    // SAFETY: `LOW` is the loader's scratch buffer.
    unsafe { core::ptr::copy_nonoverlapping(dap.as_ptr(), LOW as *mut u8, 16) };
    let r = rm::int(0x13, Regs { eax: 0x4200, edx: u32::from(drive), esi: LOW as u32, ..Default::default() });
    if r.carry() { Err(()) } else { Ok(()) }
}

/// Write `count` sectors (at most 64) from the disk buffer to `lba`
/// (INT 13h AH=43h, without verification).
pub fn write_sectors(drive: u8, lba: u64, count: u16) -> Result<(), ()> {
    let (seg, off) = rm::far(rm::DISK_BUFFER);
    let mut dap = [0u8; 16];
    dap[0] = 16;
    dap[2..4].copy_from_slice(&count.to_le_bytes());
    dap[4..6].copy_from_slice(&off.to_le_bytes());
    dap[6..8].copy_from_slice(&seg.to_le_bytes());
    dap[8..16].copy_from_slice(&lba.to_le_bytes());
    // SAFETY: `LOW` is the loader's scratch buffer.
    unsafe { core::ptr::copy_nonoverlapping(dap.as_ptr(), LOW as *mut u8, 16) };
    let r = rm::int(0x13, Regs { eax: 0x4300, edx: u32::from(drive), esi: LOW as u32, ..Default::default() });
    if r.carry() { Err(()) } else { Ok(()) }
}

/// A key, if one was pressed: (scan code, character).
pub fn key() -> Option<(u8, u8)> {
    let r = rm::int(0x16, Regs { eax: 0x1100, ..Default::default() });
    // ZF set: no key waiting.
    if r.eflags & (1 << 6) != 0 {
        return None;
    }
    let r = rm::int(0x16, Regs { eax: 0x1000, ..Default::default() });
    Some(((r.eax >> 8) as u8, r.eax as u8))
}

/// Wait `us` microseconds.
pub fn wait_us(us: u32) {
    rm::int(0x15, Regs { eax: 0x8600, ecx: us >> 16, edx: us & 0xffff, ..Default::default() });
}

/// A linear 32-bit direct-colour graphics mode.
#[derive(Clone, Copy, Debug)]
pub struct Mode {
    pub number: u16,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub base: u64,
    /// (size, position) of red, green and blue.
    pub masks: [(u8, u8); 3],
}

/// The 32-bit linear modes the VBE offers.
pub fn modes() -> Vec<Mode> {
    let info = LOW;
    // SAFETY: `LOW` is the loader's scratch buffer: "VBE2" asks for the
    // VBE 2.0 block.
    unsafe {
        core::ptr::write_bytes(info as *mut u8, 0, 512);
        core::ptr::copy_nonoverlapping(b"VBE2".as_ptr(), info as *mut u8, 4);
    }
    let r = rm::int(0x10, Regs { eax: 0x4f00, edi: info as u32, ..Default::default() });
    if r.eax & 0xffff != 0x004f || read::<[u8; 4]>(info) != *b"VESA" {
        return Vec::new();
    }
    let (off, seg): (u16, u16) = (read(info + 14), read(info + 16));
    let list = usize::from(seg) * 16 + usize::from(off);
    let numbers: Vec<u16> = (0..256).map(|i| read::<u16>(list + 2 * i)).take_while(|&m| m != 0xffff).collect();
    let mi = LOW + 512;
    numbers
        .into_iter()
        .filter_map(|number| {
            // SAFETY: The scratch buffer, after the controller block.
            unsafe { core::ptr::write_bytes(mi as *mut u8, 0, 256) };
            let r = rm::int(0x10, Regs { eax: 0x4f01, ecx: u32::from(number), edi: mi as u32, ..Default::default() });
            if r.eax & 0xffff != 0x004f {
                return None;
            }
            let attrs: u16 = read(mi);
            let (bpp, model): (u8, u8) = (read(mi + 25), read(mi + 27));
            // Supported, graphics, linear framebuffer; 32 bits, direct colour.
            if attrs & 0x99 != 0x99 || bpp != 32 || model != 6 {
                return None;
            }
            let lin: u16 = read(mi + 50);
            let pitch = if lin != 0 { lin } else { read::<u16>(mi + 16) };
            Some(Mode {
                number,
                width: u32::from(read::<u16>(mi + 18)),
                height: u32::from(read::<u16>(mi + 20)),
                pitch: u32::from(pitch),
                base: u64::from(read::<u32>(mi + 40)),
                masks: [(read(mi + 31), read(mi + 32)), (read(mi + 33), read(mi + 34)), (read(mi + 35), read(mi + 36))],
            })
        })
        .filter(|m| m.base != 0 && m.width > 0 && m.height > 0)
        .collect()
}

/// The display's preferred resolution, from its EDID (the first detailed
/// timing descriptor, E-EDID 1.3 §3.10.2).
pub fn preferred() -> Option<(u32, u32)> {
    let e = LOW + 768;
    let r = rm::int(0x10, Regs { eax: 0x4f15, ebx: 1, edi: e as u32, ..Default::default() });
    if r.eax & 0xffff != 0x004f || read::<[u8; 8]>(e) != [0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0] {
        return None;
    }
    let d = |o: usize| u32::from(read::<u8>(e + 54 + o));
    let (w, h) = (d(2) | (d(4) >> 4) << 8, d(5) | (d(7) >> 4) << 8);
    (w > 0 && h > 0).then_some((w, h))
}

/// The mode to use: the display's preferred size if offered, else the
/// largest up to 1920 by 1200.
pub fn choose(modes: &[Mode], preferred: Option<(u32, u32)>) -> Option<Mode> {
    if let Some((w, h)) = preferred
        && let Some(m) = modes.iter().find(|m| m.width == w && m.height == h)
    {
        return Some(*m);
    }
    let area = |m: &&Mode| m.width * m.height;
    modes
        .iter()
        .filter(|m| m.width <= 1920 && m.height <= 1200)
        .max_by_key(area)
        .or(modes.iter().min_by_key(area))
        .copied()
}

/// Set a mode, its framebuffer linear (bit 14).
pub fn set_mode(m: &Mode) -> bool {
    let r = rm::int(0x10, Regs { eax: 0x4f02, ebx: u32::from(m.number) | 1 << 14, ..Default::default() });
    r.eax & 0xffff == 0x004f
}

/// Back to 80 by 25 text (INT 10h AH=00h, mode 3), the cursor hidden.
pub fn text_mode() {
    rm::int(0x10, Regs { eax: 0x0003, ..Default::default() });
    rm::int(0x10, Regs { eax: 0x0100, ecx: 0x2000, ..Default::default() });
}
