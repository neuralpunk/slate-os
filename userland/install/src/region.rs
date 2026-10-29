// SPDX-License-Identifier: MIT OR Apache-2.0

//! Countries for the installers' time zone step (ADR 0151): which
//! countries each zone serves (from `/usr/share/slate/countries`, made by
//! `cargo xtask zones` from tzdata's iso3166.tab and zone1970.tab), and
//! the zone to suggest: the one a DHCP server named (RFC 4833, written by
//! netd), else the keyboard layout's country's.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

/// Where the table is.
pub const COUNTRIES: &[u8] = b"/usr/share/slate/countries";
/// The zone a DHCP server gave netd.
pub const NETWORK_ZONE: &[u8] = b"/run/netd/timezone";

/// Countries with several zones whose first in zone1970.tab is not where
/// most people live (tzdata orders a country's zones by place, not size).
const MAIN_ZONE: &[(&str, &str)] =
    &[("AU", "Australia/Sydney"), ("BR", "America/Sao_Paulo"), ("CA", "America/Toronto"), ("RU", "Europe/Moscow")];

#[derive(Clone, Debug, Default)]
pub struct Countries {
    /// Code to name.
    names: BTreeMap<String, String>,
    /// Zone to the codes of the countries it serves, the first its own.
    zones: BTreeMap<String, Vec<String>>,
    /// Zones in the table's order.
    order: Vec<String>,
}

impl Countries {
    pub fn parse(text: &str) -> Countries {
        let mut c = Countries::default();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let Some((first, rest)) = line.split_once(' ') else { continue };
            if first.contains('/') {
                c.zones.insert(String::from(first), rest.split(',').map(String::from).collect());
                c.order.push(String::from(first));
            } else {
                c.names.insert(String::from(first), String::from(rest));
            }
        }
        c
    }

    /// The installed table (empty if it is missing).
    pub fn load() -> Countries {
        let text = slate_rt::fs::read_file(COUNTRIES).unwrap_or_default();
        Countries::parse(&String::from_utf8_lossy(&text))
    }

    /// The code of the country a zone is first for ("DE" for Berlin).
    pub fn code(&self, zone: &str) -> Option<&str> {
        self.zones.get(zone)?.first().map(String::as_str)
    }

    /// A country's name.
    pub fn name(&self, code: &str) -> Option<&str> {
        self.names.get(code).map(String::as_str)
    }

    /// The code of the country called exactly `name` (any case).
    pub fn named(&self, name: &str) -> Option<&str> {
        self.names.iter().find(|(_, n)| n.eq_ignore_ascii_case(name.trim())).map(|(c, _)| c.as_str())
    }

    /// Whether `zone` serves country `code`.
    pub fn serves(&self, zone: &str, code: &str) -> bool {
        self.zones.get(zone).is_some_and(|c| c.iter().any(|f| f == code))
    }

    /// Whether a country `zone` serves has `filter` (lower case) in its
    /// name, or is that code.
    pub fn matches(&self, zone: &str, filter: &str) -> bool {
        let Some(codes) = self.zones.get(zone) else { return false };
        codes.iter().any(|c| {
            c.eq_ignore_ascii_case(filter) || self.names.get(c).is_some_and(|n| n.to_ascii_lowercase().contains(filter))
        })
    }

    /// The zone to suggest for a country: its main one, else the first
    /// zone that is the country's own, else the first that serves it.
    pub fn zone_for(&self, code: &str) -> Option<&str> {
        if let Some((_, z)) = MAIN_ZONE.iter().find(|(c, _)| *c == code)
            && self.zones.contains_key(*z)
        {
            return Some(z);
        }
        let serves = |z: &&String, first: bool| {
            self.zones
                .get(*z)
                .is_some_and(|c| if first { c.first().is_some_and(|f| f == code) } else { c.iter().any(|f| f == code) })
        };
        self.order
            .iter()
            .find(|z| serves(z, true))
            .or_else(|| self.order.iter().find(|z| serves(z, false)))
            .map(String::as_str)
    }
}

/// The country a keyboard layout is named for (`de`, `fr`, `us`), or None
/// for layouts that are not one country's (`latam`, `us(intl)`).
pub fn keyboard_country(layout: &str) -> Option<String> {
    (layout.len() == 2 && layout.bytes().all(|c| c.is_ascii_lowercase())).then(|| layout.to_ascii_uppercase())
}

/// The zone to start the time zone step at, if any: the network's, else
/// the keyboard's country's; only names in `known`.
pub fn guess(network: Option<&str>, layout: Option<&str>, countries: &Countries, known: &[String]) -> Option<String> {
    let known = |z: &str| known.iter().any(|k| k == z);
    if let Some(z) = network.map(str::trim).filter(|z| known(z)) {
        return Some(String::from(z));
    }
    let code = keyboard_country(layout?)?;
    countries.zone_for(&code).filter(|z| known(z)).map(String::from)
}

/// The zone netd heard from a DHCP server, if it did.
pub fn network_zone() -> Option<String> {
    let text = slate_rt::fs::read_file(NETWORK_ZONE).ok()?;
    let z = String::from_utf8_lossy(&text).trim().into();
    Some(z).filter(|z: &String| !z.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "# comment\nAU Australia\nDE Germany\nNO Norway\nUS United States\nCA Canada\n\
                         Australia/Lord_Howe AU\nAustralia/Sydney AU\nEurope/Berlin DE,DK,NO,SE,SJ\n\
                         America/New_York US\nAmerica/Chicago US\nAmerica/St_Johns CA\nAmerica/Toronto CA,BS\n";

    fn known() -> Vec<String> {
        ["UTC", "Australia/Lord_Howe", "Australia/Sydney", "Europe/Berlin", "America/New_York", "America/Chicago"]
            .iter()
            .map(|s| String::from(*s))
            .collect()
    }

    #[test]
    fn countries_and_guesses() {
        let c = Countries::parse(TABLE);
        assert_eq!(c.code("Europe/Berlin"), Some("DE"));
        assert!(c.matches("Europe/Berlin", "norw") && c.matches("Europe/Berlin", "no"));
        assert!(!c.matches("America/Chicago", "germany"));
        assert_eq!(c.zone_for("US"), Some("America/New_York"));
        assert_eq!(c.zone_for("NO"), Some("Europe/Berlin"));
        assert_eq!(c.zone_for("AU"), Some("Australia/Sydney"));
        assert_eq!(c.zone_for("XX"), None);
        let k = known();
        assert_eq!(guess(Some("America/Chicago\n"), Some("de"), &c, &k).as_deref(), Some("America/Chicago"));
        assert_eq!(guess(Some("Mars/Olympus"), Some("de"), &c, &k).as_deref(), Some("Europe/Berlin"));
        assert_eq!(guess(None, Some("no"), &c, &k).as_deref(), Some("Europe/Berlin"));
        // Not one country's layout, or a zone the system lacks.
        assert_eq!(guess(None, Some("us(intl)"), &c, &k), None);
        assert_eq!(guess(None, Some("latam"), &c, &k), None);
        assert_eq!(guess(None, Some("ca"), &c, &k), None);
        assert_eq!(keyboard_country("gb").as_deref(), Some("GB"));
    }

    #[test]
    fn the_shipped_table() {
        let text =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../rootfs/usr/share/slate/countries"))
                .expect("rootfs/usr/share/slate/countries");
        let c = Countries::parse(&text);
        for (code, zone) in [
            ("US", "America/New_York"),
            ("GB", "Europe/London"),
            ("DE", "Europe/Berlin"),
            ("BR", "America/Sao_Paulo"),
            ("CA", "America/Toronto"),
            ("RU", "Europe/Moscow"),
            ("AU", "Australia/Sydney"),
            ("IN", "Asia/Kolkata"),
            ("NO", "Europe/Berlin"),
        ] {
            assert_eq!(c.zone_for(code), Some(zone), "{code}");
        }
        // Every keyboard layout named for a country finds a zone.
        for l in slate_term::keymap::Layout::all() {
            if let Some(code) = keyboard_country(l.name()) {
                assert!(c.zone_for(&code).is_some(), "{}", l.name());
            }
        }
    }
}
