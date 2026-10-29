// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loader's count of a trial boot (ADR 0089): `slate-update commit`
//! leaves `boot/slate/tries` (`libs/esp`) naming the new default and the
//! boots it gets. Each boot of it counts one down; with none left (the
//! new system failed before it could confirm itself, even before its
//! kernel reached the root), the loader starts the previous system
//! instead, with `slate.boot=rollback`, and the kernel makes the rollback
//! last.

use alloc::string::String;

use crate::config::Menu;

/// What the kernel is told when the trial's boots ran out.
pub const ROLLBACK: &str = "slate.boot=rollback";

/// What to do with the count in `tries` (the file's contents): the text to
/// write back for one more boot of the default, or None. With no boots
/// left, the menu's default becomes the previous system, told to roll
/// back. A count for a system that is not the default is stale and left
/// alone.
pub fn apply(menu: &mut Menu, tries: Option<&[u8]>) -> Option<String> {
    let (system, left) = slate_esp::parse_tries(tries?)?;
    if menu.entries[menu.default].system() != Some(system.as_str()) {
        return None;
    }
    if left > 0 {
        return Some(slate_esp::tries_text(&system, left - 1));
    }
    let previous = menu
        .entries
        .iter()
        .position(|e| e.system().is_some_and(|s| s != system) && e.cmdline.contains("slate.system="))?;
    menu.default = previous;
    let e = &mut menu.entries[previous];
    e.cmdline = alloc::format!("{} {ROLLBACK}", e.cmdline).trim().into();
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    const MENU: &str = "timeout: 0\n/Slate\n path: boot():/boot/slate/system-3/kernel\n cmdline: root=x\n\
        /Slate (previous system)\n path: boot():/boot/slate/system-2/kernel\n cmdline: root=x slate.system=system-2\n";

    #[test]
    fn counts_down_then_falls_back() {
        let mut m = parse(MENU).unwrap();
        assert_eq!(apply(&mut m, Some(b"system-3 1\n")).as_deref(), Some("system-3 0\n"));
        assert_eq!(m.default, 0);
        assert_eq!(apply(&mut m, Some(b"system-3 0\n")), None);
        assert_eq!(m.default, 1);
        assert_eq!(m.entries[1].cmdline, "root=x slate.system=system-2 slate.boot=rollback");
    }

    #[test]
    fn stale_or_missing_counts_change_nothing() {
        let want = parse(MENU).unwrap();
        for tries in [None, Some(&b"system-2 0\n"[..]), Some(b"nonsense")] {
            let mut m = parse(MENU).unwrap();
            assert_eq!(apply(&mut m, tries), None);
            assert_eq!(m, want);
        }
        // No previous system to fall back to: the default it is.
        let mut alone = parse("/Slate\n path: boot():/boot/slate/system-3/kernel\n").unwrap();
        assert_eq!(apply(&mut alone, Some(b"system-3 0")), None);
        assert_eq!(alone.default, 0);
    }
}
