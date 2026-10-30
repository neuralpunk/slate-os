// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the Settings portal says (the XDG Desktop Portal documentation,
//! org.freedesktop.portal.Settings, and its list of standardized keys),
//! from the person's Strata settings (`~/.config/strata/settings`,
//! `theme=` and `contrast=`; ADR 0039, ADR 0167):
//!
//! - `org.freedesktop.appearance`: `color-scheme` (1 dark, 2 light),
//!   `accent-color` (red, green and blue from 0 to 1: the theme's
//!   accent) and `contrast` (1 high), which GTK 4, libadwaita and Qt
//!   read;
//! - `org.gnome.desktop.interface`: the same as GNOME's settings name them
//!   (`color-scheme`, `gtk-theme`, `accent-color`), Strata's fonts and the
//!   cursor, which GTK 3 and GNOME's apps read;
//! - `org.gnome.desktop.a11y.interface`: `high-contrast`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use slate_ui::themes::Theme;

use crate::wire::Value;

/// Where the person's Strata settings are, from their home.
pub const SETTINGS: &str = ".config/strata/settings";

/// Strata's interface fonts, as fontconfig names them, with their sizes
/// for GTK (points).
pub const FONT: &str = "Host Grotesk 11";
pub const MONO_FONT: &str = "DM Mono 10";

/// What Strata's settings say that the portal passes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub theme: Theme,
    pub high_contrast: bool,
}

impl Look {
    /// From the settings file's text (missing or unknown: Strata's own
    /// defaults, Graphite at normal contrast).
    pub fn parse(text: &str) -> Look {
        let mut l = Look { theme: Theme::Graphite, high_contrast: false };
        for line in text.lines() {
            match line.trim().split_once('=') {
                Some(("theme", v)) => l.theme = Theme::from_key(v.trim()).unwrap_or(l.theme),
                Some(("contrast", v)) => l.high_contrast = v.trim() == "high",
                _ => {}
            }
        }
        l
    }

    /// The theme's accent: (r, g, b), 0 to 1.
    pub fn accent(&self) -> (f64, f64, f64) {
        let c = self.theme.palette(self.high_contrast).accent.0;
        let f = |shift: u32| f64::from((c >> shift) & 0xFF) / 255.0;
        (f(16), f(8), f(0))
    }

    /// The nearest of GNOME's named accents (GNOME 47's list) to the
    /// theme's.
    pub fn accent_name(&self) -> &'static str {
        // Hues, in degrees, of the named colours.
        const NAMED: &[(&str, f64)] = &[
            ("red", 355.0),
            ("orange", 25.0),
            ("yellow", 45.0),
            ("green", 140.0),
            ("teal", 175.0),
            ("blue", 215.0),
            ("purple", 275.0),
            ("pink", 325.0),
        ];
        let (r, g, b) = self.accent();
        let (max, min) = (r.max(g).max(b), r.min(g).min(b));
        // Hardly a colour at all: GNOME's grey one.
        if max - min < 0.08 {
            return "slate";
        }
        let d = max - min;
        let h = if max == r {
            60.0 * (((g - b) / d) % 6.0)
        } else if max == g {
            60.0 * ((b - r) / d + 2.0)
        } else {
            60.0 * ((r - g) / d + 4.0)
        };
        let h = if h < 0.0 { h + 360.0 } else { h };
        let dist = |x: f64| {
            let d = (x - h).abs();
            if d > 180.0 { 360.0 - d } else { d }
        };
        NAMED.iter().min_by(|a, b| dist(a.1).total_cmp(&dist(b.1))).map_or("blue", |n| n.0)
    }

    /// The settings, by namespace: (namespace, [(key, value)]).
    pub fn all(&self) -> Vec<(&'static str, Vec<(&'static str, Value)>)> {
        let dark = !self.theme.light();
        let (r, g, b) = self.accent();
        let s = |t: &str| Value::Str(t.into());
        alloc::vec![
            (
                "org.freedesktop.appearance",
                alloc::vec![
                    ("color-scheme", Value::U32(if dark { 1 } else { 2 })),
                    ("accent-color", Value::Struct(alloc::vec![Value::Double(r), Value::Double(g), Value::Double(b)])),
                    ("contrast", Value::U32(u32::from(self.high_contrast))),
                ],
            ),
            (
                "org.gnome.desktop.interface",
                alloc::vec![
                    ("color-scheme", s(if dark { "prefer-dark" } else { "prefer-light" })),
                    ("gtk-theme", s(if dark { "Adwaita-dark" } else { "Adwaita" })),
                    ("accent-color", s(self.accent_name())),
                    ("font-name", s(FONT)),
                    ("document-font-name", s(FONT)),
                    ("monospace-font-name", s(MONO_FONT)),
                    ("cursor-theme", s("Adwaita")),
                    ("cursor-size", Value::I32(24)),
                    ("icon-theme", s("Adwaita")),
                ],
            ),
            ("org.gnome.desktop.a11y.interface", alloc::vec![("high-contrast", Value::Bool(self.high_contrast))]),
        ]
    }

    /// One setting.
    pub fn get(&self, namespace: &str, key: &str) -> Option<Value> {
        self.all().into_iter().find(|(n, _)| *n == namespace)?.1.into_iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// ReadAll's answer: the namespaces matching `globs` (an empty list,
    /// or an empty pattern, is every one; a pattern may end in `*`).
    pub fn read_all(&self, globs: &[String]) -> Value {
        let matches = |n: &str| {
            globs.is_empty()
                || globs.iter().any(|g| g.is_empty() || g == n || g.strip_suffix('*').is_some_and(|p| n.starts_with(p)))
        };
        let entries = self
            .all()
            .into_iter()
            .filter(|(n, _)| matches(n))
            .map(|(n, kv)| {
                let dict = kv
                    .into_iter()
                    .map(|(k, v)| Value::Entry(Box::new(Value::Str(k.into())), Box::new(Value::variant(v))))
                    .collect();
                Value::Entry(Box::new(Value::Str(n.into())), Box::new(Value::Array("{sv}".into(), dict)))
            })
            .collect();
        Value::Array("{sa{sv}}".into(), entries)
    }

    /// The settings that differ from `old`'s: (namespace, key, value).
    pub fn changes(&self, old: &Look) -> Vec<(&'static str, &'static str, Value)> {
        let before = old.all();
        let mut out = Vec::new();
        for (n, kv) in self.all() {
            for (k, v) in kv {
                let was = before.iter().find(|b| b.0 == n).and_then(|b| b.1.iter().find(|x| x.0 == k)).map(|x| &x.1);
                if was != Some(&v) {
                    out.push((n, k, v));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_stratas_settings() {
        let l = Look::parse("theme=light\ncontrast=normal\n");
        assert_eq!(l.get("org.freedesktop.appearance", "color-scheme"), Some(Value::U32(2)));
        assert_eq!(l.get("org.gnome.desktop.interface", "gtk-theme"), Some(Value::Str("Adwaita".into())));
        let d = Look::parse("");
        assert_eq!(d.theme, Theme::Graphite);
        assert_eq!(d.get("org.freedesktop.appearance", "color-scheme"), Some(Value::U32(1)));
        assert_eq!(d.get("org.gnome.desktop.interface", "font-name"), Some(Value::Str(FONT.into())));
        assert_eq!(d.get("org.example", "x"), None);
        // Copper Noir's copper is an orange; its accent goes as it is.
        let c = Look::parse("theme=copper-noir");
        assert_eq!(c.accent_name(), "orange");
        let (r, g, b) = c.accent();
        assert!((r - f64::from(0xD3) / 255.0).abs() < 1e-9 && g < r && b < g);
        let hc = Look::parse("theme=sediment\ncontrast=high");
        assert_eq!(hc.get("org.freedesktop.appearance", "contrast"), Some(Value::U32(1)));
        assert_eq!(hc.get("org.gnome.desktop.a11y.interface", "high-contrast"), Some(Value::Bool(true)));
    }

    #[test]
    fn read_all_and_changes() {
        let l = Look::parse("theme=light");
        let Value::Array(sig, all) = l.read_all(&[]) else { panic!() };
        assert_eq!(sig, "{sa{sv}}");
        assert_eq!(all.len(), 3);
        let Value::Array(_, some) = l.read_all(&["org.freedesktop.*".into()]) else { panic!() };
        assert_eq!(some.len(), 1);
        let Value::Array(_, none) = l.read_all(&["org.kde.kdeglobals".into()]) else { panic!() };
        assert!(none.is_empty());
        // Light to Graphite: the scheme, the theme, the accent change.
        let ch = Look::parse("theme=graphite").changes(&l);
        let keys: Vec<(&str, &str)> = ch.iter().map(|c| (c.0, c.1)).collect();
        assert!(keys.contains(&("org.freedesktop.appearance", "color-scheme")));
        assert!(keys.contains(&("org.gnome.desktop.interface", "gtk-theme")));
        assert!(!keys.contains(&("org.gnome.desktop.interface", "font-name")));
        assert!(l.changes(&l).is_empty());
    }
}
