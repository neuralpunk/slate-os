// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pipe 0 once it shows a surface (ADR 0171, M32 phase 4, step 8): flips
//! between scanout buffers, the hardware cursor, and where OTG0 is in its
//! frame (for the DRM's vblank clock).
//!
//! Facts from DC (Linux v7.2.12, read as documentation, ADR 0157's
//! addendum; Slate's own code):
//!
//! - flips: hubp/dcn20/dcn20_hubp.c, `hubp2_program_surface_flip_and_addr`
//!   (with SURFACE_UPDATE_LOCK clear, writing the address's low word
//!   latches it, the high word first; a vsync flip, SURFACE_FLIP_TYPE 0,
//!   takes at the next VUPDATE) and `hubp2_is_flip_pending` (pending until
//!   SURFACE_FLIP_PENDING clears and the earliest address in use is the
//!   one asked for);
//! - the cursor: `hubp2_cursor_set_attributes` and `_set_position`,
//!   hubp/dcn31/dcn31_hubp.c (CURSOR_REQ_MODE 1 on DCN 3.1),
//!   dpp/dcn30/dcn30_dpp.c `dpp3_set_cursor_attributes` and
//!   dpp/dcn10/dcn10_dpp.c `dpp1_set_cursor_position` (the DPP's own
//!   enable), mpc/dcn10/dcn10_mpc.c `mpc1_cursor_lock` (updates held until
//!   unlocked); amdgpu_dm's `get_cursor_position` for a cursor partly off
//!   the top or left (the position clamped to 0, the hot spot the part
//!   hidden);
//! - with an overlay, the cursor on each pipe in that pipe's own place
//!   (`dcn10_set_cursor_position`: the position less the plane's recout
//!   start, for every pipe of the stream), so that the plane above shows
//!   it too;
//! - the position: OTG_STATUS_POSITION's vertical and horizontal counts
//!   (optc/dcn10/dcn10_optc.c, `optc1_get_position`), counted from the
//!   start of sync as the timing is (`otg`), so vertical blank starts at
//!   line V_TOTAL less the front porch.
//!
//! Registers: dcn_3_1_5_offset.h and dcn_3_1_5_sh_mask.h.

use crate::interp::Card;
use crate::mode::{Place, on_pipe};
use crate::otg::Timing;

/// Register words (dcn_3_1_5_offset.h).
pub mod reg {
    /// Segment 2: HUBP0's request block and cursor, DPP0's cursor.
    pub const PRIMARY_SURFACE_ADDRESS: u32 = 0x60A;
    pub const PRIMARY_SURFACE_ADDRESS_HIGH: u32 = 0x60B;
    pub const FLIP_CONTROL: u32 = 0x61B;
    pub const EARLIEST_INUSE: u32 = 0x625;
    pub const EARLIEST_INUSE_HIGH: u32 = 0x626;
    pub const CURSOR_SETTINGS: u32 = 0x65C;
    pub const CURSOR_CONTROL: u32 = 0x678;
    pub const CURSOR_SURFACE_ADDRESS: u32 = 0x679;
    pub const CURSOR_SURFACE_ADDRESS_HIGH: u32 = 0x67A;
    pub const CURSOR_SIZE: u32 = 0x67B;
    pub const CURSOR_POSITION: u32 = 0x67C;
    pub const CURSOR_HOT_SPOT: u32 = 0x67D;
    pub const CURSOR_DST_OFFSET: u32 = 0x67F;
    pub const CUR0_CONTROL: u32 = 0xCF1;
    pub const OTG_STATUS_POSITION: u32 = 0x1B4A;
    /// Segment 3: the MPC's cursor lock for OPP0.
    pub const CUR_VUPDATE_LOCK_SET0: u32 = 0x513;
}

/// FLIP_CONTROL's SURFACE_FLIP_PENDING.
const FLIP_PENDING: u32 = 1 << 8;
/// The hub's reference clock (as `mode`'s deadlines use it).
const REF_KHZ: i64 = 24_000;

/// Show the surface at GPU address `address` on pipe `pipe` from the
/// next VUPDATE.
pub fn flip(card: &mut impl Card, seg2: u32, pipe: u32, address: u64) {
    card.write(seg2 + on_pipe(reg::PRIMARY_SURFACE_ADDRESS_HIGH, pipe), (address >> 32) as u32);
    card.write(seg2 + on_pipe(reg::PRIMARY_SURFACE_ADDRESS, pipe), address as u32);
}

/// Whether pipe `pipe`'s flip to `address` has taken: the surface shown
/// before it is no longer read.
pub fn flipped(card: &mut impl Card, seg2: u32, pipe: u32, address: u64) -> bool {
    if card.read(seg2 + on_pipe(reg::FLIP_CONTROL, pipe)) & FLIP_PENDING != 0 {
        return false;
    }
    let low = card.read(seg2 + on_pipe(reg::EARLIEST_INUSE, pipe));
    let high = card.read(seg2 + on_pipe(reg::EARLIEST_INUSE_HIGH, pipe));
    (u64::from(high & 0xFFFF) << 32 | u64::from(low)) == address
}

/// A frame's length in nanoseconds at timing `t`.
pub fn frame_ns(t: &Timing) -> u64 {
    u64::from(t.htotal) * u64::from(t.vtotal) * 1_000_000 / u64::from(t.clock_khz.max(1))
}

/// How long ago (in nanoseconds) the last vertical blank began, from
/// OTG_STATUS_POSITION's value `position` at timing `t`.
pub fn since_vblank_ns(t: &Timing, position: u32) -> u64 {
    let (v, h) = (position & 0x7FFF, (position >> 16) & 0x7FFF);
    let start = t.vtotal - (t.vsync_start - t.vactive);
    let lines = (v + t.vtotal - start) % t.vtotal;
    let pixels = u64::from(lines) * u64::from(t.htotal) + u64::from(h.min(t.htotal - 1));
    pixels * 1_000_000 / u64::from(t.clock_khz.max(1))
}

/// OTG0's position now (OTG_STATUS_POSITION).
pub fn position(card: &mut impl Card, seg2: u32) -> u32 {
    card.read(seg2 + reg::OTG_STATUS_POSITION)
}

/// Largest cursor image (the surface's pitch, CURSOR_PITCH 0).
pub const CURSOR_PITCH: u32 = 64;

/// A cursor image in the GPU's memory: premultiplied ARGB8888, rows
/// [`CURSOR_PITCH`] pixels apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub address: u64,
    pub width: u32,
    pub height: u32,
}

/// `dc_cursor_color_format`'s premultiplied alpha (dc_hw_types.h).
const MODE_PREMULTIPLIED: u32 = 2;

/// The cursor's image registers (segment 2), the enables clear: HUBP0's
/// address, size, control and settings, DPP0's control.
pub fn cursor_registers(c: &Cursor) -> [(u32, u32); 6] {
    // `cursor_lines_per_chunk` for 32-bit images (hubp/dcn20's
    // `hubp2_get_lines_per_chunk`): 16 up to 32 pixels wide, else 8.
    let lines_per_chunk = if c.width <= 32 { 4 } else { 3 };
    let control = (1 << 2) | (MODE_PREMULTIPLIED << 8) | (lines_per_chunk << 24);
    [
        (reg::CURSOR_SURFACE_ADDRESS_HIGH, (c.address >> 32) as u32),
        (reg::CURSOR_SURFACE_ADDRESS, c.address as u32),
        (reg::CURSOR_SIZE, (c.width << 16) | c.height),
        (reg::CURSOR_CONTROL, control),
        // CURSOR0_CHUNK_HDL_ADJUST 3, as DC sets it.
        (reg::CURSOR_SETTINGS, 3 << 8),
        (reg::CUR0_CONTROL, MODE_PREMULTIPLIED << 4),
    ]
}

/// Where a `c`-sized cursor whose top left corner is at (`x`, `y`) goes
/// on a `t` screen: its position, hot spot and destination offset
/// registers, and whether any of it shows.
pub fn position_registers(t: &Timing, c: &Cursor, x: i32, y: i32) -> ([(u32, u32); 3], bool) {
    position_in(t, c, x, y, (t.hactive, t.vactive))
}

/// [`position_registers`] in a plane `size` big, (`x`, `y`) from its
/// top left corner.
fn position_in(t: &Timing, c: &Cursor, x: i32, y: i32, size: (u32, u32)) -> ([(u32, u32); 3], bool) {
    let (w, h) = (c.width as i32, c.height as i32);
    let hot_x = (-x).clamp(0, w - 1);
    let hot_y = (-y).clamp(0, h - 1);
    let visible = x < size.0 as i32 && x + w > 0 && y < size.1 as i32 && y + h > 0;
    // The left edge in the hub's reference clocks.
    let dst_x = i64::from(x.max(0)) * REF_KHZ / i64::from(t.clock_khz.max(1));
    let (x, y) = (x.max(0), y.max(0));
    (
        [
            (reg::CURSOR_POSITION, ((x as u32 & 0x3FFF) << 16) | (y as u32 & 0x3FFF)),
            (reg::CURSOR_HOT_SPOT, ((hot_x as u32) << 16) | hot_y as u32),
            (reg::CURSOR_DST_OFFSET, dst_x as u32 & 0x1FFF),
        ],
        visible,
    )
}

/// Pipe 0's place: the whole screen.
pub fn screen(t: &Timing) -> Place {
    Place { pipe: 0, at: (0, 0), size: (t.hactive, t.vactive) }
}

/// Show `c` with its top left corner at `at`, or no cursor, on
/// each of `pipes` (pipe 0's [`screen`] first, then any overlay's); held
/// with the MPC's cursor lock so that it changes in one frame.
pub fn cursor(
    card: &mut impl Card,
    seg2: u32,
    seg3: u32,
    t: &Timing,
    c: Option<&Cursor>,
    at: (i32, i32),
    pipes: &[Place],
) {
    let (x, y) = at;
    card.write(seg3 + reg::CUR_VUPDATE_LOCK_SET0, 1);
    for p in pipes {
        let on = match c {
            Some(c) => {
                for (r, v) in cursor_registers(c) {
                    card.write(seg2 + on_pipe(r, p.pipe), v);
                }
                place(card, seg2, t, c, x, y, p)
            }
            None => false,
        };
        enable(card, seg2, p.pipe, on);
    }
    card.write(seg3 + reg::CUR_VUPDATE_LOCK_SET0, 0);
}

/// Move `c` (already shown by [`cursor`] on `pipes`) to `at`.
pub fn move_cursor(
    card: &mut impl Card,
    seg2: u32,
    seg3: u32,
    t: &Timing,
    c: &Cursor,
    at: (i32, i32),
    pipes: &[Place],
) {
    let (x, y) = at;
    card.write(seg3 + reg::CUR_VUPDATE_LOCK_SET0, 1);
    for p in pipes {
        let on = place(card, seg2, t, c, x, y, p);
        enable(card, seg2, p.pipe, on);
    }
    card.write(seg3 + reg::CUR_VUPDATE_LOCK_SET0, 0);
}

fn place(card: &mut impl Card, seg2: u32, t: &Timing, c: &Cursor, x: i32, y: i32, p: &Place) -> bool {
    let (regs, visible) = position_in(t, c, x - p.at.0 as i32, y - p.at.1 as i32, p.size);
    for (r, v) in regs {
        card.write(seg2 + on_pipe(r, p.pipe), v);
    }
    visible
}

/// A pipe's HUBP and DPP cursor enables.
fn enable(card: &mut impl Card, seg2: u32, pipe: u32, on: bool) {
    for r in [reg::CURSOR_CONTROL, reg::CUR0_CONTROL] {
        let r = seg2 + on_pipe(r, pipe);
        let v = card.read(r);
        card.write(r, (v & !1) | u32::from(on));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    const P1080: Timing = Timing {
        clock_khz: 148_500,
        hactive: 1920,
        hsync_start: 2008,
        hsync_end: 2052,
        htotal: 2200,
        vactive: 1080,
        vsync_start: 1084,
        vsync_end: 1089,
        vtotal: 1125,
        hsync_positive: true,
        vsync_positive: true,
    };
    const SEG2: u32 = 0x34C0;
    const SEG3: u32 = 0x9000;
    const C: Cursor = Cursor { address: 0xF4_0A00_0000, width: 64, height: 64 };

    #[derive(Default)]
    struct Regs {
        r: BTreeMap<u32, u32>,
        writes: Vec<(u32, u32)>,
    }
    impl Card for Regs {
        fn read(&mut self, r: u32) -> u32 {
            self.r.get(&r).copied().unwrap_or(0)
        }
        fn write(&mut self, r: u32, v: u32) {
            self.r.insert(r, v);
            self.writes.push((r, v));
        }
        fn delay_us(&mut self, _: u32) {}
    }

    #[test]
    fn flips_high_word_first_and_waits_for_the_address() {
        let mut c = Regs::default();
        flip(&mut c, SEG2, 0, 0xF4_0600_0000);
        assert_eq!(c.writes, [(SEG2 + 0x60B, 0xF4), (SEG2 + 0x60A, 0x0600_0000)]);
        c.r.insert(SEG2 + reg::FLIP_CONTROL, FLIP_PENDING);
        assert!(!flipped(&mut c, SEG2, 0, 0xF4_0600_0000));
        c.r.insert(SEG2 + reg::FLIP_CONTROL, 0);
        c.r.insert(SEG2 + reg::EARLIEST_INUSE, 0x0400_0000);
        c.r.insert(SEG2 + reg::EARLIEST_INUSE_HIGH, 0xF4);
        assert!(!flipped(&mut c, SEG2, 0, 0xF4_0600_0000));
        c.r.insert(SEG2 + reg::EARLIEST_INUSE, 0x0600_0000);
        assert!(flipped(&mut c, SEG2, 0, 0xF4_0600_0000));
    }

    #[test]
    fn where_the_frame_is() {
        // 1125 lines of 2200 pixels at 148.5 MHz: 16.67 ms.
        assert_eq!(frame_ns(&P1080), 16_666_666);
        // Blank starts at line 1125 - 4 = 1121 (counted from sync).
        assert_eq!(since_vblank_ns(&P1080, 1121), 0);
        // A line (2200 pixels) later: 14.8 us.
        assert_eq!(since_vblank_ns(&P1080, 1122), 14_814);
        // Line 0 (sync) is four lines in; half a line more.
        assert_eq!(since_vblank_ns(&P1080, 1100 << 16), 66_666);
        // The last line of active is just before the next blank.
        let last = since_vblank_ns(&P1080, (2199 << 16) | 1120);
        assert!(last < frame_ns(&P1080) && frame_ns(&P1080) - last < 10, "{last}");
    }

    #[test]
    fn cursor_image_registers() {
        assert_eq!(
            cursor_registers(&C),
            [
                (reg::CURSOR_SURFACE_ADDRESS_HIGH, 0xF4),
                (reg::CURSOR_SURFACE_ADDRESS, 0x0A00_0000),
                (reg::CURSOR_SIZE, 0x0040_0040),
                (reg::CURSOR_CONTROL, 0x0300_0204),
                (reg::CURSOR_SETTINGS, 0x300),
                (reg::CUR0_CONTROL, 0x20),
            ]
        );
        let small = Cursor { width: 24, height: 24, ..C };
        assert_eq!(cursor_registers(&small)[3].1 >> 24, 4);
    }

    #[test]
    fn positions_and_the_edges() {
        let (r, on) = position_registers(&P1080, &C, 100, 50);
        assert!(on);
        // 100 pixels at 148.5 MHz in 24 MHz clocks.
        assert_eq!(
            r,
            [(reg::CURSOR_POSITION, (100 << 16) | 50), (reg::CURSOR_HOT_SPOT, 0), (reg::CURSOR_DST_OFFSET, 16)]
        );
        // Off the top left: clamped to 0, the hidden part as the hot spot.
        let (r, on) = position_registers(&P1080, &C, -10, -20);
        assert!(on);
        assert_eq!(r[0].1, 0);
        assert_eq!(r[1].1, (10 << 16) | 20);
        assert_eq!(r[2].1, 0);
        // Gone past any edge.
        for (x, y) in [(-64, 0), (0, -64), (1920, 0), (0, 1080)] {
            assert!(!position_registers(&P1080, &C, x, y).1, "{x},{y}");
        }
        assert!(position_registers(&P1080, &C, 1919, 1079).1);
    }

    #[test]
    fn cursor_changes_are_locked_and_enable_both_blocks() {
        let mut c = Regs::default();
        cursor(&mut c, SEG2, SEG3, &P1080, Some(&C), (10, 10), &[screen(&P1080)]);
        assert_eq!(c.writes.first(), Some(&(SEG3 + reg::CUR_VUPDATE_LOCK_SET0, 1)));
        assert_eq!(c.writes.last(), Some(&(SEG3 + reg::CUR_VUPDATE_LOCK_SET0, 0)));
        assert_eq!(c.r[&(SEG2 + reg::CURSOR_CONTROL)] & 1, 1);
        assert_eq!(c.r[&(SEG2 + reg::CUR0_CONTROL)], 0x21);
        move_cursor(&mut c, SEG2, SEG3, &P1080, &C, (5000, 10), &[screen(&P1080)]);
        assert_eq!(c.r[&(SEG2 + reg::CURSOR_CONTROL)] & 1, 0);
        assert_eq!(c.r[&(SEG2 + reg::CUR0_CONTROL)] & 1, 0);
        move_cursor(&mut c, SEG2, SEG3, &P1080, &C, (30, 40), &[screen(&P1080)]);
        assert_eq!(c.r[&(SEG2 + reg::CUR0_CONTROL)] & 1, 1);
        cursor(&mut c, SEG2, SEG3, &P1080, None, (0, 0), &[screen(&P1080)]);
        assert_eq!(c.r[&(SEG2 + reg::CURSOR_CONTROL)] & 1, 0);
        assert_eq!(c.r[&(SEG2 + reg::CUR0_CONTROL)] & 1, 0);
    }

    #[test]
    fn the_cursor_on_an_overlay_too() {
        let mut c = Regs::default();
        let over = Place { pipe: 1, at: (100, 200), size: (640, 480) };
        let pipes = [screen(&P1080), over];
        // Over the overlay: on both pipes, pipe 1's in its own place.
        cursor(&mut c, SEG2, SEG3, &P1080, Some(&C), (110, 230), &pipes);
        let p1 = |c: &Regs, r: u32| c.r[&(SEG2 + on_pipe(r, 1))];
        assert_eq!(c.r[&(SEG2 + reg::CURSOR_POSITION)], (110 << 16) | 230);
        assert_eq!(p1(&c, reg::CURSOR_POSITION), (10 << 16) | 30);
        assert_eq!(p1(&c, reg::CURSOR_SURFACE_ADDRESS), C.address as u32);
        assert_eq!(p1(&c, reg::CURSOR_CONTROL) & 1, 1);
        assert_eq!(p1(&c, reg::CUR0_CONTROL) & 1, 1);
        // dcn_3_1_5_offset.h: CURSOR0_1_CURSOR_CONTROL, CNVC_CUR1_CURSOR0_CONTROL.
        assert_eq!(on_pipe(reg::CURSOR_CONTROL, 1), 0x754);
        assert_eq!(on_pipe(reg::CUR0_CONTROL, 1), 0xE5C);
        // Partly off the overlay's top left: clamped there, as at the
        // screen's edge.
        move_cursor(&mut c, SEG2, SEG3, &P1080, &C, (90, 190), &pipes);
        assert_eq!(p1(&c, reg::CURSOR_POSITION), 0);
        assert_eq!(p1(&c, reg::CURSOR_HOT_SPOT), (10 << 16) | 10);
        assert_eq!(p1(&c, reg::CURSOR_CONTROL) & 1, 1);
        // Off the overlay: pipe 0's only.
        move_cursor(&mut c, SEG2, SEG3, &P1080, &C, (10, 10), &pipes);
        assert_eq!(p1(&c, reg::CURSOR_CONTROL) & 1, 0);
        assert_eq!(c.r[&(SEG2 + reg::CURSOR_CONTROL)] & 1, 1);
    }
}
