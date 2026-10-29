// SPDX-License-Identifier: MIT OR Apache-2.0

//! The screen mode to boot in (ADR 0111). Firmware leaves the screen in a
//! mode of its own choosing, often a low one (the reference PC's RTX 3080 left a
//! 1080p monitor at a fraction of it), and the kernel's firmware
//! framebuffer keeps whatever the loader hands over. So the loader picks:
//! the display's own resolution (its EDID's preferred timing) when the
//! firmware offers it; else the largest mode that fits the display, of
//! its shape if there is one. Without an EDID the firmware's mode stays:
//! a guess could be one the display can't show.

/// A mode the firmware offers (UEFI §12.9, QueryMode): its number, its
/// size, and whether its pixels are 32-bit ones the loader can draw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub number: u32,
    pub width: u32,
    pub height: u32,
    pub usable: bool,
}

impl Mode {
    fn area(&self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// The display's resolution from its EDID: the preferred timing's active
/// area, or a larger mode its DisplayID extension gives (a display past
/// what the base block can hold, 5K or 8K, says its own size there; ADR
/// 0168).
pub fn native(edid: &[u8]) -> Option<(u32, u32)> {
    let info = slate_edid::read(edid)?;
    let base = info.base.preferred?;
    let area = |t: &slate_edid::Timing| u64::from(t.hactive) * u64::from(t.vactive);
    let t = info
        .modes()
        .iter()
        .filter(|m| m.source == slate_edid::Source::DisplayId)
        .map(|m| m.timing)
        .filter(|t| area(t) > area(&base))
        .max_by_key(area)
        .unwrap_or(base);
    (t.hactive > 0 && t.vactive > 0).then_some((t.hactive, t.vactive))
}

/// The mode to set, or None to keep `current`.
pub fn choose(modes: &[Mode], current: Option<Mode>, display: Option<(u32, u32)>) -> Option<u32> {
    let (w, h) = display?;
    let best = match modes.iter().find(|m| m.usable && (m.width, m.height) == (w, h)) {
        Some(m) => *m,
        // Same shape first (w:h as the display's), then the area.
        None => *modes
            .iter()
            .filter(|m| m.usable && m.width <= w && m.height <= h)
            .max_by_key(|m| (u64::from(m.width) * u64::from(h) == u64::from(m.height) * u64::from(w), m.area()))?,
    };
    match current {
        Some(c) if c.number == best.number => None,
        // Never smaller than a usable mode already set that fits.
        Some(c) if c.usable && c.width <= w && c.height <= h && c.area() > best.area() => None,
        _ => Some(best.number),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes(list: &[(u32, u32)]) -> std::vec::Vec<Mode> {
        list.iter()
            .enumerate()
            .map(|(i, &(width, height))| Mode { number: i as u32, width, height, usable: true })
            .collect()
    }

    #[test]
    fn the_displays_own_resolution() {
        let m = modes(&[(640, 480), (800, 600), (1024, 768), (1280, 1024), (1920, 1080), (2560, 1440)]);
        // The reference PC: left at 1024 x 768 on a 1080p monitor.
        assert_eq!(choose(&m, Some(m[2]), Some((1920, 1080))), Some(4));
        assert_eq!(choose(&m, Some(m[4]), Some((1920, 1080))), None, "already there");
        // Not offered: the largest that fits, of the display's shape first.
        let m = modes(&[(1024, 768), (1280, 720), (1280, 1024), (1600, 900)]);
        assert_eq!(choose(&m, Some(m[0]), Some((1920, 1080))), Some(3));
        // None of its shape: the largest that fits.
        let m = modes(&[(800, 600), (1280, 1024)]);
        assert_eq!(choose(&m, Some(m[0]), Some((1920, 1080))), Some(1));
    }

    #[test]
    fn without_an_edid_the_mode_stays() {
        let m = modes(&[(800, 600), (1024, 768), (1920, 1080), (3840, 2160)]);
        assert_eq!(choose(&m, Some(m[0]), None), None);
        // Modes the loader can't draw are passed over.
        let mut m = modes(&[(1024, 768), (1920, 1080)]);
        m[1].usable = false;
        assert_eq!(choose(&m, Some(m[0]), Some((1920, 1080))), None);
        assert_eq!(choose(&[], None, Some((1920, 1080))), None);
    }

    #[test]
    fn edid_preferred_timing() {
        // CEA-861's 1080p60 timing.
        let block = slate_edid::Display {
            vendor: *b"SLT",
            product: 1,
            serial: 0,
            year: 2026,
            name: "monitor",
            size_mm: (527, 296),
            timing: slate_edid::Timing {
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
            },
        };
        let b = slate_edid::build(&block);
        assert_eq!(native(&b), Some((1920, 1080)));
        assert_eq!(native(&[0u8; 16]), None);
        // An 8K display: 3840x2160 in its base block, its own 7680x4320
        // in a DisplayID 2.0 extension (Type IX, CVT-RB2 at 60).
        let mut e = std::vec::Vec::from(b);
        e[126] = 1;
        e[127] = e[127].wrapping_sub(1);
        let mut ext = [0u8; 128];
        ext[0] = 0x70;
        let mut s = std::vec::Vec::from([0x20u8, 0, 0, 0, 0x24, 0x00, 6, 0x02]);
        s.extend_from_slice(&(7680u16 - 1).to_le_bytes());
        s.extend_from_slice(&(4320u16 - 1).to_le_bytes());
        s.push(59);
        s[1] = (s.len() - 4) as u8;
        let sum = s.iter().fold(0u8, |a, &v| a.wrapping_add(v));
        s.push(0u8.wrapping_sub(sum));
        ext[1..1 + s.len()].copy_from_slice(&s);
        let sum = ext[..127].iter().fold(0u8, |a, &v| a.wrapping_add(v));
        ext[127] = 0u8.wrapping_sub(sum);
        e.extend_from_slice(&ext);
        assert_eq!(native(&e), Some((7680, 4320)));
    }
}
