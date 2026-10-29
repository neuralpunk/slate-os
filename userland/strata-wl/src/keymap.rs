// SPDX-License-Identifier: MIT OR Apache-2.0

//! The keymap the virtual keyboard sends (virtual-keyboard-unstable-v1
//! wants one before any key): an XKB keymap in the text format
//! xkbcommon reads (its documentation's "The XKB keymap text format, V1"),
//! made from slate-display's layout tables, so keys type what they type
//! in Strata.
//!
//! Keycodes are evdev's plus 8 (the XKB convention); the key names are
//! ours (`<K030>` for evdev code 30). Characters become keysyms by the X
//! protocol's encoding (X Window System Protocol, appendix A: Latin-1
//! characters are their own keysym, other characters 0x01000000 plus the
//! code point); keys without a character have their standard keysym
//! names there; dead keys are the `dead_*` keysyms (keysymdef.h), which
//! the Linux program composes itself (ADR 0117). Layouts with AltGr have
//! four levels, the right Alt key `ISO_Level3_Shift` on Mod5. Modifiers
//! are the eight real ones, so their indices are fixed: Shift 0, Lock 1,
//! Control 2, Mod1 (Alt) 3, Mod4 (logo) 6, Mod5 (AltGr) 7.

use alloc::format;
use alloc::string::String;

use slate_display::input::Layout;
use slate_term::keymap::Sym;

/// Keys without a character: evdev code (input-event-codes.h, ADR 0033)
/// and keysym name.
const NAMED: &[(u16, &str)] = &[
    (1, "Escape"),
    (14, "BackSpace"),
    (15, "Tab"),
    (28, "Return"),
    (29, "Control_L"),
    (42, "Shift_L"),
    (54, "Shift_R"),
    (56, "Alt_L"),
    (58, "Caps_Lock"),
    (59, "F1"),
    (60, "F2"),
    (61, "F3"),
    (62, "F4"),
    (63, "F5"),
    (64, "F6"),
    (65, "F7"),
    (66, "F8"),
    (67, "F9"),
    (68, "F10"),
    (87, "F11"),
    (88, "F12"),
    (96, "KP_Enter"),
    (97, "Control_R"),
    (100, "Alt_R"),
    (102, "Home"),
    (103, "Up"),
    (104, "Prior"),
    (105, "Left"),
    (106, "Right"),
    (107, "End"),
    (108, "Down"),
    (109, "Next"),
    (110, "Insert"),
    (111, "Delete"),
    (125, "Super_L"),
    (126, "Super_R"),
];

/// Modifier masks (real modifiers' bits).
pub const SHIFT: u32 = 1 << 0;
pub const LOCK: u32 = 1 << 1;
pub const CONTROL: u32 = 1 << 2;
pub const ALT: u32 = 1 << 3;
pub const LOGO: u32 = 1 << 6;
pub const MOD5: u32 = 1 << 7;

/// Dead keys' combining marks and their keysyms (keysymdef.h).
const DEAD: &[(char, &str)] = &[
    ('\u{300}', "dead_grave"),
    ('\u{301}', "dead_acute"),
    ('\u{302}', "dead_circumflex"),
    ('\u{303}', "dead_tilde"),
    ('\u{342}', "dead_perispomeni"),
    ('\u{304}', "dead_macron"),
    ('\u{306}', "dead_breve"),
    ('\u{307}', "dead_abovedot"),
    ('\u{308}', "dead_diaeresis"),
    ('\u{309}', "dead_hook"),
    ('\u{30A}', "dead_abovering"),
    ('\u{30B}', "dead_doubleacute"),
    ('\u{30C}', "dead_caron"),
    ('\u{31B}', "dead_horn"),
    ('\u{323}', "dead_belowdot"),
    ('\u{326}', "dead_belowcomma"),
    ('\u{327}', "dead_cedilla"),
    ('\u{328}', "dead_ogonek"),
    ('\u{331}', "dead_belowmacron"),
];

/// A level's keysym, as the keymap text writes it.
fn sym_text(s: Option<Sym>) -> String {
    match s {
        Some(Sym::Char(' ')) => String::from("space"),
        Some(Sym::Char(c)) => format!("{:#x}", keysym(c)),
        Some(Sym::Dead(m)) => String::from(DEAD.iter().find(|d| d.0 == m).map_or("NoSymbol", |d| d.1)),
        None => String::from("NoSymbol"),
    }
}

/// A character's keysym.
pub fn keysym(c: char) -> u32 {
    let u = c as u32;
    if (0x20..=0x7E).contains(&u) || (0xA0..=0xFF).contains(&u) { u } else { 0x0100_0000 + u }
}

/// The keymap for `layout`.
pub fn keymap(layout: Layout) -> String {
    let altgr = layout.has_altgr();
    let mut codes = String::new();
    let mut symbols = String::new();
    for code in 1u16..128 {
        let named = NAMED.iter().find(|(c, _)| *c == code).map(|(_, n)| *n);
        let named = if code == 100 && altgr { Some("ISO_Level3_Shift") } else { named };
        let levels = slate_term::keymap::levels(layout, code);
        let entry = match (named, levels) {
            (Some(n), _) => format!("[ {n} ]"),
            (None, Some(l)) => {
                let letter = match (l[0], l[1]) {
                    (Some(Sym::Char(a)), Some(Sym::Char(b))) => a.is_alphabetic() && a != b && a.to_uppercase().eq([b]),
                    _ => false,
                };
                let four = altgr && (l[2].is_some() || l[3].is_some());
                let (kind, n) = match (four, letter) {
                    (true, true) => ("FOUR_LEVEL_ALPHABETIC", 4),
                    (true, false) => ("FOUR_LEVEL", 4),
                    (false, true) => ("ALPHABETIC", 2),
                    (false, false) if l[1].is_some() && l[1] != l[0] => ("TWO_LEVEL", 2),
                    (false, false) => ("ONE_LEVEL", 1),
                };
                let syms: alloc::vec::Vec<String> = l[..n].iter().map(|s| sym_text(*s)).collect();
                if n == 1 { format!("[ {} ]", syms[0]) } else { format!("type = \"{kind}\", [ {} ]", syms.join(", ")) }
            }
            (None, None) => continue,
        };
        codes += &format!("    <K{code:03}> = {};\n", code + 8);
        symbols += &format!("    key <K{code:03}> {{ {entry} }};\n");
    }
    // The right Alt key is AltGr, on Mod5, in layouts that have it.
    let (alt_keys, level3) =
        if altgr { ("<K056>", "    modifier_map Mod5 { <K100> };\n") } else { ("<K056>, <K100>", "") };
    format!(
        "xkb_keymap {{\n\
         xkb_keycodes \"slate\" {{\n    minimum = 8;\n    maximum = 255;\n{codes}}};\n\
         xkb_types \"slate\" {{\n\
         \x20   type \"ONE_LEVEL\" {{ modifiers = none; level_name[Level1] = \"Any\"; }};\n\
         \x20   type \"TWO_LEVEL\" {{ modifiers = Shift; map[Shift] = Level2; \
         level_name[Level1] = \"Base\"; level_name[Level2] = \"Shift\"; }};\n\
         \x20   type \"ALPHABETIC\" {{ modifiers = Shift+Lock; map[Shift] = Level2; map[Lock] = Level2; \
         level_name[Level1] = \"Base\"; level_name[Level2] = \"Caps\"; }};\n\
         \x20   type \"FOUR_LEVEL\" {{ modifiers = Shift+Mod5; map[Shift] = Level2; map[Mod5] = Level3; \
         map[Shift+Mod5] = Level4; level_name[Level1] = \"Base\"; level_name[Level2] = \"Shift\"; \
         level_name[Level3] = \"AltGr\"; level_name[Level4] = \"Shift AltGr\"; }};\n\
         \x20   type \"FOUR_LEVEL_ALPHABETIC\" {{ modifiers = Shift+Lock+Mod5; map[Shift] = Level2; \
         map[Lock] = Level2; map[Mod5] = Level3; map[Shift+Mod5] = Level4; map[Lock+Mod5] = Level3; \
         map[Shift+Lock+Mod5] = Level4; level_name[Level1] = \"Base\"; level_name[Level2] = \"Shift\"; \
         level_name[Level3] = \"AltGr\"; level_name[Level4] = \"Shift AltGr\"; }};\n\
         }};\n\
         xkb_compatibility \"slate\" {{\n\
         \x20   interpret Shift_L {{ action = SetMods(modifiers=Shift); }};\n\
         \x20   interpret Shift_R {{ action = SetMods(modifiers=Shift); }};\n\
         \x20   interpret Control_L {{ action = SetMods(modifiers=Control); }};\n\
         \x20   interpret Control_R {{ action = SetMods(modifiers=Control); }};\n\
         \x20   interpret Alt_L {{ action = SetMods(modifiers=Mod1); }};\n\
         \x20   interpret Alt_R {{ action = SetMods(modifiers=Mod1); }};\n\
         \x20   interpret Super_L {{ action = SetMods(modifiers=Mod4); }};\n\
         \x20   interpret Super_R {{ action = SetMods(modifiers=Mod4); }};\n\
         \x20   interpret Caps_Lock {{ action = LockMods(modifiers=Lock); }};\n\
         \x20   interpret ISO_Level3_Shift {{ action = SetMods(modifiers=Mod5); }};\n\
         }};\n\
         xkb_symbols \"slate\" {{\n{symbols}\
         \x20   modifier_map Shift {{ <K042>, <K054> }};\n\
         \x20   modifier_map Lock {{ <K058> }};\n\
         \x20   modifier_map Control {{ <K029>, <K097> }};\n\
         \x20   modifier_map Mod1 {{ {alt_keys} }};\n\
         \x20   modifier_map Mod4 {{ <K125>, <K126> }};\n\
         {level3}\
         }};\n\
         }};\n"
    )
}

/// The modifier masks (depressed, locked) for a key Strata passed with
/// `mods` (strata-proto's bits) typing `ch`: Caps Lock is inferred from
/// an upper-case letter typed without Shift.
pub fn masks(mods: u8, ch: Option<char>) -> (u32, u32) {
    use slate_strata_client::mods as m;
    let mut d = 0;
    for (bit, mask) in [(m::SHIFT, SHIFT), (m::CTRL, CONTROL), (m::ALT, ALT), (m::LOGO, LOGO), (m::ALTGR, MOD5)] {
        if mods & bit != 0 {
            d |= mask;
        }
    }
    let caps = mods & m::SHIFT == 0 && ch.is_some_and(|c| c.is_uppercase());
    (d, if caps { LOCK } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keymaps() {
        let us = keymap(Layout::US);
        assert!(us.starts_with("xkb_keymap {\nxkb_keycodes \"slate\" {"));
        assert!(us.contains("    <K030> = 38;\n"));
        assert!(us.contains("    key <K030> { type = \"ALPHABETIC\", [ 0x61, 0x41 ] };\n"));
        assert!(us.contains("    key <K003> { type = \"TWO_LEVEL\", [ 0x32, 0x40 ] };\n"));
        assert!(us.contains("    key <K057> { [ space ] };\n"));
        assert!(us.contains("    key <K028> { [ Return ] };\n"));
        assert!(us.contains("    key <K100> { [ Alt_R ] };\n") && !us.contains("Mod5 {"));
        // The UK layout: shift 2 is ", shift 3 is £ (Latin-1); AltGr on
        // Mod5, with four levels and dead keys.
        let gb = keymap(Layout::named("gb"));
        assert!(gb.contains("    key <K003> { type = \"FOUR_LEVEL\", [ 0x32, 0x22, 0xb2, 0x100215b ] };\n"));
        assert!(gb.contains("    key <K030> { type = \"FOUR_LEVEL_ALPHABETIC\", [ 0x61, 0x41, 0xe6, 0xc6 ] };\n"));
        assert!(
            gb.contains("    key <K026> { type = \"FOUR_LEVEL\", [ 0x5b, 0x7b, dead_diaeresis, dead_abovering ] };\n")
        );
        assert!(gb.contains("    key <K100> { [ ISO_Level3_Shift ] };\n"));
        assert!(gb.contains("    modifier_map Mod5 { <K100> };\n"));
        // German: dead keys on the first level.
        let de = keymap(Layout::named("de"));
        assert!(de.contains(
            "    key <K013> { type = \"FOUR_LEVEL\", [ dead_acute, dead_grave, dead_cedilla, dead_ogonek ] };\n"
        ));
        assert_eq!(keysym('€'), 0x0100_20AC);
        // Braces balance.
        assert_eq!(us.matches('{').count(), us.matches('}').count());
        // `SLATE_KEYMAP_OUT=DIR` saves them, to check with xkbcommon.
        if let Ok(dir) = std::env::var("SLATE_KEYMAP_OUT") {
            std::fs::write(std::format!("{dir}/us.xkb"), &us).unwrap();
            std::fs::write(std::format!("{dir}/gb.xkb"), &gb).unwrap();
            std::fs::write(std::format!("{dir}/de.xkb"), &de).unwrap();
        }
    }

    #[test]
    fn modifier_masks() {
        use slate_strata_client::mods as m;
        assert_eq!(masks(m::CTRL | m::SHIFT, Some('T')), (CONTROL | SHIFT, 0));
        assert_eq!(masks(0, Some('A')), (0, LOCK));
        assert_eq!(masks(m::ALT, None), (ALT, 0));
        assert_eq!(masks(m::ALTGR, Some('@')), (MOD5, 0));
    }
}
