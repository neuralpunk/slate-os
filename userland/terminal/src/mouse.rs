// SPDX-License-Identifier: MIT OR Apache-2.0

//! Mouse reports (ADR 0099): what the terminal sends a program that asked
//! for the mouse (DECSET 9, 1000, 1002, 1003), in xterm's encodings
//! (ctlseqs, "Mouse Tracking"): `CSI M Cb Cx Cy` with each value plus 32
//! (positions up to 223), with DECSET 1005 the same as UTF-8 characters
//! (up to 2015), with DECSET 1006 `CSI < Cb ; Cx ; Cy M`, `m` for a
//! release, and with DECSET 1015 (urxvt's) `CSI Cb ; Cx ; Cy M` in
//! decimal, Cb plus 32. Cb is the button (0 left, 1 middle, 2 right, 3 a
//! release in the old encoding, 64 and 65 the wheel), plus 4 for shift, 8
//! for alt (meta) and 16 for ctrl, plus 32 for a move.

use alloc::vec::Vec;

use slate_strata_client::mods::{ALT, CTRL, SHIFT};
use slate_term::vt::{MouseEncoding, MouseMode};

/// What the mouse did, at a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// A button went down or up: Strata's numbers (1 left, 2 middle, 3
    /// right).
    Press(u8),
    Release(u8),
    /// The pointer moved to another cell, with a button held or not.
    Move(Option<u8>),
    /// A notch of the wheel: up (back) or down.
    Wheel {
        up: bool,
    },
}

/// The report for `action` at (`col`, `row`) (0-based) with modifiers
/// `mods`, if the mode wants one.
pub fn report(
    mode: MouseMode,
    encoding: MouseEncoding,
    action: Action,
    col: usize,
    row: usize,
    mods: u8,
) -> Option<Vec<u8>> {
    let sgr = encoding == MouseEncoding::Sgr;
    let button = |b: u8| match b {
        1 => Some(0),
        2 => Some(1),
        3 => Some(2),
        _ => None,
    };
    let (mut cb, release) = match (mode, action) {
        (MouseMode::Off, _) => return None,
        (_, Action::Press(b)) => (button(b)?, false),
        (MouseMode::Press, _) => return None,
        (_, Action::Release(b)) => (if sgr { button(b)? } else { 3 }, true),
        (MouseMode::Drag, Action::Move(Some(b))) | (MouseMode::Motion, Action::Move(Some(b))) => {
            (button(b)? + 32, false)
        }
        (MouseMode::Motion, Action::Move(None)) => (3 + 32, false),
        (_, Action::Move(_)) => return None,
        (_, Action::Wheel { up }) => (if up { 64 } else { 65 }, false),
    };
    // X10 mode (DECSET 9) reports no modifiers.
    if mode != MouseMode::Press {
        cb += 4 * u8::from(mods & SHIFT != 0) + 8 * u8::from(mods & ALT != 0) + 16 * u8::from(mods & CTRL != 0);
    }
    let (x, y) = (col + 1, row + 1);
    match encoding {
        MouseEncoding::Sgr => {
            Some(alloc::format!("\x1b[<{cb};{x};{y}{}", if release { 'm' } else { 'M' }).into_bytes())
        }
        MouseEncoding::Urxvt => Some(alloc::format!("\x1b[{};{x};{y}M", u32::from(cb) + 32).into_bytes()),
        // Each value plus 32 as a character: UTF-8 when it takes more
        // than one byte (up to 2047, so positions up to 2015).
        MouseEncoding::Utf8 => {
            if x > 2015 || y > 2015 {
                return None;
            }
            let mut out = alloc::vec![0x1B, b'[', b'M'];
            for v in [usize::from(cb), x, y] {
                let c = char::from_u32((v + 32) as u32)?;
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
            Some(out)
        }
        // The old encoding puts each value in one byte.
        MouseEncoding::X10 => {
            if x > 223 || y > 223 {
                return None;
            }
            Some(alloc::vec![0x1B, b'[', b'M', 32 + cb, 32 + x as u8, 32 + y as u8])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports() {
        use MouseEncoding::*;
        use MouseMode::*;
        // A left press at (0, 0) and its release, old and SGR forms.
        assert_eq!(report(Click, X10, Action::Press(1), 0, 0, 0).unwrap(), b"\x1b[M !!");
        assert_eq!(report(Click, X10, Action::Release(1), 4, 2, 0).unwrap(), b"\x1b[M#%#");
        assert_eq!(report(Click, Sgr, Action::Press(3), 9, 19, 0).unwrap(), b"\x1b[<2;10;20M");
        assert_eq!(report(Click, Sgr, Action::Release(3), 9, 19, 0).unwrap(), b"\x1b[<2;10;20m");
        // Modifiers: shift + ctrl with the middle button.
        assert_eq!(report(Click, Sgr, Action::Press(2), 0, 0, SHIFT | CTRL).unwrap(), b"\x1b[<21;1;1M");
        // X10 mode: presses only, without modifiers.
        assert_eq!(report(Press, Sgr, Action::Press(1), 0, 0, CTRL).unwrap(), b"\x1b[<0;1;1M");
        assert_eq!(report(Press, Sgr, Action::Release(1), 0, 0, 0), None);
        // Moves: with a button in 1002 and 1003, without only in 1003.
        assert_eq!(report(Click, Sgr, Action::Move(Some(1)), 1, 1, 0), None);
        assert_eq!(report(Drag, Sgr, Action::Move(Some(1)), 1, 1, 0).unwrap(), b"\x1b[<32;2;2M");
        assert_eq!(report(Drag, Sgr, Action::Move(None), 1, 1, 0), None);
        assert_eq!(report(Motion, Sgr, Action::Move(None), 1, 1, 0).unwrap(), b"\x1b[<35;2;2M");
        // The wheel.
        assert_eq!(report(Click, Sgr, Action::Wheel { up: true }, 0, 0, 0).unwrap(), b"\x1b[<64;1;1M");
        assert_eq!(report(Click, X10, Action::Wheel { up: false }, 0, 0, 0).unwrap(), b"\x1b[Ma!!");
        // Beyond column 223 only SGR can say where.
        assert_eq!(report(Click, X10, Action::Press(1), 223, 0, 0), None);
        assert!(report(Click, Sgr, Action::Press(1), 223, 0, 0).is_some());
        assert_eq!(report(Off, Sgr, Action::Press(1), 0, 0, 0), None);
        // UTF-8 (1005): one byte below 96, two from there; urxvt (1015):
        // decimal, Cb plus 32, releases as button 3.
        assert_eq!(report(Click, Utf8, Action::Press(1), 0, 0, 0).unwrap(), b"\x1b[M !!");
        assert_eq!(report(Click, Utf8, Action::Press(1), 299, 0, 0).unwrap(), "\x1b[M \u{14c}!".as_bytes());
        assert_eq!(report(Click, Utf8, Action::Press(1), 2015, 0, 0), None);
        assert_eq!(report(Click, Urxvt, Action::Press(3), 9, 19, 0).unwrap(), b"\x1b[34;10;20M");
        assert_eq!(report(Click, Urxvt, Action::Release(3), 300, 2, 0).unwrap(), b"\x1b[35;301;3M");
    }
}
