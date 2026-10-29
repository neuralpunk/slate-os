// SPDX-License-Identifier: MIT OR Apache-2.0

//! USB HID report descriptors (ADR 0039): what each report holds, and the
//! values in a report.
//!
//! Source: the Device Class Definition for HID 1.11: the item format
//! (§6.2.2.2, short items; long items are skipped), main items (§6.2.2.4-
//! §6.2.2.6: Input, Output, Feature and their flags; Collection and End
//! Collection), global items (§6.2.2.7: Usage Page, Logical Minimum and
//! Maximum, Report Size, Report ID, Report Count, Push, Pop) and local
//! items (§6.2.2.8: Usage, Usage Minimum and Maximum), and how reports are
//! laid out (§8: a report ID byte first when the descriptor names IDs,
//! then the fields in order, little-endian bit order). Usage numbers from
//! the HID Usage Tables 1.4.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::vec::Vec;

/// Usage pages (HID Usage Tables §3).
pub const PAGE_GENERIC_DESKTOP: u16 = 0x01;
pub const PAGE_KEYBOARD: u16 = 0x07;
pub const PAGE_LED: u16 = 0x08;
pub const PAGE_BUTTON: u16 = 0x09;
pub const PAGE_CONSUMER: u16 = 0x0C;
pub const PAGE_DIGITIZER: u16 = 0x0D;

/// Generic Desktop usages (§4).
pub const GD_POINTER: u16 = 0x01;
pub const GD_MOUSE: u16 = 0x02;
pub const GD_KEYBOARD: u16 = 0x06;
pub const GD_X: u16 = 0x30;
pub const GD_Y: u16 = 0x31;
pub const GD_WHEEL: u16 = 0x38;
/// Consumer page: horizontal scrolling (AC Pan, §15).
pub const CONSUMER_AC_PAN: u16 = 0x238;

/// A full usage: page in the high half, ID in the low.
pub const fn usage(page: u16, id: u16) -> u32 {
    (page as u32) << 16 | id as u32
}

/// Which report a field is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Input,
    Output,
    Feature,
}

/// Main item flags (§6.2.2.5).
pub const CONSTANT: u32 = 1 << 0;
pub const VARIABLE: u32 = 1 << 1;
pub const RELATIVE: u32 = 1 << 2;

/// One main item's data: `count` values of `size` bits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub kind: Kind,
    pub report_id: u8,
    /// Where it starts, in bits from the start of the report's data (after
    /// the report ID byte).
    pub offset: u32,
    pub size: u32,
    pub count: u32,
    pub flags: u32,
    /// For a variable field, the usage of each value (the last repeats);
    /// for an array, the usages its values index from `logical_min`.
    pub usages: Vec<u32>,
    pub logical_min: i32,
    pub logical_max: i32,
}

impl Field {
    pub fn is_variable(&self) -> bool {
        self.flags & VARIABLE != 0
    }
    pub fn is_relative(&self) -> bool {
        self.flags & RELATIVE != 0
    }
    pub fn is_constant(&self) -> bool {
        self.flags & CONSTANT != 0
    }

    /// The usage of value `i` of a variable field.
    pub fn usage_of(&self, i: u32) -> Option<u32> {
        self.usages.get((i as usize).min(self.usages.len().checked_sub(1)?)).copied()
    }

    /// Value `i` of this field in `data` (a report without its ID byte):
    /// sign-extended when the logical minimum is negative.
    pub fn value(&self, data: &[u8], i: u32) -> Option<i32> {
        if i >= self.count || self.size == 0 || self.size > 32 {
            return None;
        }
        let start = self.offset + i * self.size;
        let mut v: u64 = 0;
        for b in 0..self.size {
            let bit = start + b;
            let byte = *data.get((bit / 8) as usize)?;
            v |= u64::from((byte >> (bit % 8)) & 1) << b;
        }
        if self.logical_min < 0 && self.size < 32 && v & (1 << (self.size - 1)) != 0 {
            v |= !0u64 << self.size;
        }
        Some(v as u32 as i32)
    }
}

/// What a descriptor describes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    pub fields: Vec<Field>,
    /// Reports start with an ID byte.
    pub report_ids: bool,
    /// The usage of each top-level application collection.
    pub applications: Vec<u32>,
}

impl Descriptor {
    /// The first input field holding `usage` as a variable value, and the
    /// value's index.
    pub fn find_input(&self, usage: u32) -> Option<(&Field, u32)> {
        self.fields
            .iter()
            .filter(|f| f.kind == Kind::Input && f.is_variable() && !f.is_constant())
            .find_map(|f| (0..f.count).find(|&i| f.usage_of(i) == Some(usage)).map(|i| (f, i)))
    }

    /// The input fields of report `id`.
    pub fn inputs(&self, id: u8) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.kind == Kind::Input && f.report_id == id)
    }

    /// The usages input report `id` holds down (`data` without its ID
    /// byte): each one-bit variable value that is set (modifier keys,
    /// key bitmaps, buttons) and each array value that names a usage
    /// (§6.2.2.5: a value outside the logical range is none). `None` for a
    /// keyboard's phantom state (every key slot reading ErrorRollOver,
    /// usage 01h of the keyboard page, HID Usage Tables §10).
    pub fn pressed(&self, id: u8, data: &[u8]) -> Option<Vec<u32>> {
        let mut out = Vec::new();
        for f in self.inputs(id).filter(|f| !f.is_constant()) {
            if f.is_variable() {
                if f.size != 1 || f.is_relative() {
                    continue;
                }
                for i in 0..f.count {
                    if f.value(data, i) == Some(1)
                        && let Some(u) = f.usage_of(i)
                    {
                        out.push(u);
                    }
                }
                continue;
            }
            let mut slots = 0;
            let mut rollover = 0;
            for i in 0..f.count {
                let Some(v) = f.value(data, i) else { continue };
                slots += 1;
                if v < f.logical_min || v > f.logical_max {
                    continue;
                }
                let Some(&u) = f.usages.get((v - f.logical_min) as usize) else { continue };
                if u == usage(PAGE_KEYBOARD, 1) {
                    rollover += 1;
                } else if u & 0xFFFF != 0 {
                    out.push(u);
                }
            }
            if slots > 0 && rollover == slots {
                return None;
            }
        }
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    /// The bytes of report `id` of `kind` (without its ID byte).
    pub fn report_len(&self, kind: Kind, id: u8) -> usize {
        let bits = self
            .fields
            .iter()
            .filter(|f| f.kind == kind && f.report_id == id)
            .map(|f| f.offset + f.size * f.count)
            .max()
            .unwrap_or(0);
        bits.div_ceil(8) as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An item runs past the end.
    Truncated,
    /// Pop without Push, End Collection without Collection, a report
    /// bigger than this parser takes.
    Malformed,
}

#[derive(Clone, Copy, Debug, Default)]
struct Globals {
    page: u16,
    logical_min: i32,
    logical_max: i32,
    size: u32,
    count: u32,
    id: u8,
}

/// The most usages a range may expand to, and the most values a field may
/// hold (more is surely a broken descriptor).
const MAX_USAGES: u32 = 1024;
const MAX_COUNT: u32 = 4096;

/// Parse a report descriptor.
pub fn parse(desc: &[u8]) -> Result<Descriptor, Error> {
    let mut out = Descriptor::default();
    let mut g = Globals::default();
    let mut stack: Vec<Globals> = Vec::new();
    // Locals: usages (with their page if given in full), a range.
    let mut usages: Vec<u32> = Vec::new();
    let (mut umin, mut umax): (Option<u32>, Option<u32>) = (None, None);
    let mut depth = 0u32;
    // Next free bit of each (kind, report ID).
    let mut offsets: Vec<(Kind, u8, u32)> = Vec::new();
    let mut i = 0;
    while i < desc.len() {
        let prefix = desc[i];
        if prefix == 0xFE {
            // A long item: size, tag, data (§6.2.2.3).
            let size = usize::from(*desc.get(i + 1).ok_or(Error::Truncated)?);
            i += 3 + size;
            continue;
        }
        let size = [0, 1, 2, 4][usize::from(prefix & 3)];
        let data = desc.get(i + 1..i + 1 + size).ok_or(Error::Truncated)?;
        i += 1 + size;
        let unsigned = data.iter().rev().fold(0u32, |v, &b| v << 8 | u32::from(b));
        let signed = match size {
            1 => i32::from(data[0] as i8),
            2 => i32::from(i16::from_le_bytes([data[0], data[1]])),
            4 => unsigned as i32,
            _ => 0,
        };
        match prefix & 0xFC {
            // Main items.
            0x80 | 0x90 | 0xB0 => {
                let kind = match prefix & 0xFC {
                    0x80 => Kind::Input,
                    0x90 => Kind::Output,
                    _ => Kind::Feature,
                };
                if g.count > MAX_COUNT || g.size > 32 {
                    return Err(Error::Malformed);
                }
                let mut list: Vec<u32> = usages.iter().map(|&u| full_usage(u, g.page)).collect();
                if let (Some(a), Some(b)) = (umin, umax) {
                    let (a, b) = (full_usage(a, g.page), full_usage(b, g.page));
                    if b >= a && b - a < MAX_USAGES {
                        list.extend(a..=b);
                    }
                }
                let slot = match offsets.iter().position(|o| o.0 == kind && o.1 == g.id) {
                    Some(p) => p,
                    None => {
                        offsets.push((kind, g.id, 0));
                        offsets.len() - 1
                    }
                };
                let offset = offsets[slot].2;
                offsets[slot].2 += g.size * g.count;
                out.fields.push(Field {
                    kind,
                    report_id: g.id,
                    offset,
                    size: g.size,
                    count: g.count,
                    flags: unsigned,
                    usages: list,
                    logical_min: g.logical_min,
                    logical_max: g.logical_max,
                });
                usages.clear();
                (umin, umax) = (None, None);
            }
            0xA0 => {
                // An application collection (type 1) at the top: what the
                // device is.
                if depth == 0
                    && unsigned == 1
                    && let Some(&u) = usages.first()
                {
                    out.applications.push(full_usage(u, g.page));
                }
                depth += 1;
                usages.clear();
                (umin, umax) = (None, None);
            }
            0xC0 => {
                depth = depth.checked_sub(1).ok_or(Error::Malformed)?;
                usages.clear();
                (umin, umax) = (None, None);
            }
            // Global items.
            0x04 => g.page = unsigned as u16,
            0x14 => g.logical_min = signed,
            0x24 => {
                // A maximum is signed only when the minimum is.
                g.logical_max = if g.logical_min < 0 { signed } else { unsigned as i32 };
            }
            0x74 => g.size = unsigned,
            0x84 => {
                g.id = unsigned as u8;
                out.report_ids = true;
            }
            0x94 => g.count = unsigned,
            0xA4 => stack.push(g),
            0xB4 => g = stack.pop().ok_or(Error::Malformed)?,
            // Local items.
            0x08 => usages.push(mark(unsigned, size)),
            0x18 => umin = Some(mark(unsigned, size)),
            0x28 => umax = Some(mark(unsigned, size)),
            _ => {} // Units, physical ranges, designators, strings, delimiters.
        }
    }
    Ok(out)
}

/// Local usages are kept as given: a 4-byte one with its page, a 1- or
/// 2-byte one as an ID with this flag, resolved against the usage page in
/// effect at the main item (§6.2.2.8). Vendor pages lose their top bit.
const SHORT: u32 = 1 << 31;

fn mark(v: u32, size: usize) -> u32 {
    if size == 4 { v & !SHORT } else { v | SHORT }
}

fn full_usage(u: u32, page: u16) -> u32 {
    if u & SHORT != 0 { usage(page, u as u16) } else { u }
}

#[cfg(test)]
mod tests;
