// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask zones`: the time zone table (`rootfs/usr/share/slate/zones`,
//! ADR 0141) from the tz database (public domain), read as the compiled
//! TZif files in `SLATE_TZDIR` (default `/usr/share/zoneinfo`, Fedora's
//! `tzdata`). The zones are those of its `zone1970.tab`, and UTC.
//! It also writes `rootfs/usr/share/slate/countries` (ADR 0151) from
//! `iso3166.tab` and `zone1970.tab`: `CODE Name` lines, then `ZONE
//! CODE[,CODE...]` lines in zone1970.tab's order, for the installers.
//!
//! A line is `NAME RULE [TYPES TRANSITIONS]`:
//! - RULE: the POSIX TZ rule of the TZif footer (RFC 8536 §3.3), in force
//!   after the last transition;
//! - TYPES: the local time types (§3.2), `ABBR=OFFSET` with `d` after the
//!   offset for summer time, separated by commas; the first is the type
//!   before the first transition;
//! - TRANSITIONS: each transition before [`CUTOFF`] as its distance from
//!   the one before (from the epoch for the first) in lowercase base 36,
//!   `-` for a negative first one, then the type it changes to as a
//!   capital letter (`A` the first type).
//!
//! Transitions from [`CUTOFF`] on are left to the rule, except in zones
//! whose later years change more than twice (Gaza's and Hebron's summer
//! time pauses for Ramadan, which no POSIX rule can say): those keep every
//! transition listed. slate-rt's `shipped_history` test checks, against
//! the TZif files of the same tzdata version, that the table gives the
//! same answers at every transition they list.

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::{Result, root};

/// 2027-01-01 00:00 UTC: later transitions come from each zone's rule.
const CUTOFF: i64 = 1_798_761_600;

/// A TZif file's version 2 data block and footer (RFC 8536 §3).
struct Tzif {
    transitions: Vec<(i64, u8)>,
    /// (UT offset, is DST, abbreviation)
    types: Vec<(i32, bool, String)>,
    footer: String,
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

fn parse(d: &[u8]) -> Option<Tzif> {
    // §3.1: "TZif", a version, 15 unused bytes, six counts.
    let header = |at: usize| -> Option<[usize; 6]> {
        if d.get(at..at + 4)? != b"TZif" {
            return None;
        }
        let mut c = [0; 6];
        for (i, n) in c.iter_mut().enumerate() {
            *n = be32(d, at + 20 + 4 * i)? as usize;
        }
        Some(c)
    };
    let [isut, isstd, leap, time, typ, chars] = header(0)?;
    if !matches!(d.get(4), Some(b'2'..=b'9')) {
        return None;
    }
    // Skip the version 1 block (32-bit times) to the version 2 header.
    let v2 = 44 + time * 5 + typ * 6 + chars + leap * 8 + isstd + isut;
    let [_, _, leap, time, typ, chars] = header(v2)?;
    let mut at = v2 + 44;
    let mut transitions = Vec::with_capacity(time);
    for i in 0..time {
        let t = i64::from_be_bytes(d.get(at + 8 * i..at + 8 * i + 8)?.try_into().ok()?);
        transitions.push((t, *d.get(at + 8 * time + i)?));
    }
    at += 9 * time;
    let abbrevs = d.get(at + 6 * typ..at + 6 * typ + chars)?;
    let mut types = Vec::with_capacity(typ);
    for i in 0..typ {
        let e = &d[at + 6 * i..at + 6 * i + 6];
        let off = i32::from_be_bytes(e[..4].try_into().ok()?);
        let start = usize::from(e[5]);
        let len = abbrevs.get(start..)?.iter().position(|&c| c == 0)?;
        types.push((off, e[4] != 0, String::from_utf8(abbrevs[start..start + len].to_vec()).ok()?));
    }
    if leap != 0 {
        return None; // the "right/" zones: leap seconds are not kept
    }
    let body = d.strip_suffix(b"\n")?;
    let nl = body.iter().rposition(|&c| c == b'\n')?;
    let footer = String::from_utf8(body[nl + 1..].to_vec()).ok()?;
    Some(Tzif { transitions, types, footer })
}

fn base36(mut n: u64, out: &mut String) {
    let mut digits = Vec::new();
    loop {
        digits.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    digits.reverse();
    out.push_str(std::str::from_utf8(&digits).expect("ASCII"));
}

/// The transitions a zone's line lists.
fn kept(z: &Tzif) -> Vec<&(i64, u8)> {
    let mut per_year = std::collections::BTreeMap::new();
    for (t, _) in z.transitions.iter().filter(|(t, _)| *t >= CUTOFF) {
        *per_year.entry(t.div_euclid(31_556_952)).or_insert(0) += 1;
    }
    let irregular = per_year.values().any(|&n| n > 2);
    z.transitions.iter().filter(|(t, _)| irregular || *t < CUTOFF).collect()
}

/// One zone's line.
fn line(name: &str, z: &Tzif) -> Result<String> {
    if z.footer.is_empty() {
        return Err(format!("{name}: no rule in the TZif footer"));
    }
    let mut l = format!("{name} {}", z.footer);
    let kept = kept(z);
    if kept.is_empty() {
        return Ok(l);
    }
    if z.types.len() > 26 {
        return Err(format!("{name}: more than 26 local time types"));
    }
    l.push(' ');
    for (i, (off, dst, abbr)) in z.types.iter().enumerate() {
        if abbr.is_empty() || !abbr.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-') {
            return Err(format!("{name}: abbreviation {abbr:?}"));
        }
        let _ = write!(l, "{}{abbr}={off}{}", if i > 0 { "," } else { "" }, if *dst { "d" } else { "" });
    }
    l.push(' ');
    let mut prev = 0i64;
    for (i, &&(t, ty)) in kept.iter().enumerate() {
        if usize::from(ty) >= z.types.len() || (i > 0 && t <= prev) {
            return Err(format!("{name}: bad transition at {t}"));
        }
        let delta = t - prev;
        if delta < 0 {
            l.push('-');
        }
        base36(delta.unsigned_abs(), &mut l);
        l.push(char::from(b'A' + ty));
        prev = t;
    }
    Ok(l)
}

pub fn generate() -> Result {
    let dir = PathBuf::from(std::env::var("SLATE_TZDIR").unwrap_or_else(|_| "/usr/share/zoneinfo".into()));
    let read = |n: &str| std::fs::read(dir.join(n)).map_err(|e| format!("{}: {e}", dir.join(n).display()));
    let version = String::from_utf8_lossy(&read("tzdata.zi")?)
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("# version "))
        .map(str::to_string)
        .ok_or("tzdata.zi has no version line")?;
    let tab = String::from_utf8_lossy(&read("zone1970.tab")?).into_owned();
    let mut names: Vec<&str> =
        tab.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split('\t').nth(2)).collect();
    names.sort_unstable();
    names.push("UTC");

    let mut out = format!(
        "# Time zones (ADR 0141), one per line: the name, the POSIX TZ rule in\n\
         # force after the last transition listed (IEEE 1003.1 §8.3), then the\n\
         # local time types and the transitions before 2027 (and later ones\n\
         # no rule can give; see tools/xtask/src/zones.rs). From tzdata {version} (public domain,\n\
         # https://www.iana.org/time-zones), the zones of its zone1970.tab;\n\
         # made by `cargo xtask zones`. Read by slate-rt (userland/rt/src/tz.rs).\n"
    );
    let mut transitions = 0;
    for name in &names {
        let z = parse(&read(name)?).ok_or_else(|| format!("{name}: not a TZif version 2+ file"))?;
        transitions += kept(&z).len();
        out.push_str(&line(name, &z)?);
        out.push('\n');
    }
    let path = root().join("rootfs/usr/share/slate/zones");
    std::fs::write(&path, &out).map_err(|e| format!("{}: {e}", path.display()))?;

    let iso = String::from_utf8_lossy(&read("iso3166.tab")?).into_owned();
    let mut countries = format!(
        "# Countries and their time zones (ADR 0151): `CODE Name`, then\n\
         # `ZONE CODE[,CODE...]` in zone1970.tab's order. From tzdata {version}'s\n\
         # iso3166.tab and zone1970.tab (public domain); made by `cargo xtask\n\
         # zones`. Read by the installers (userland/install/src/region.rs).\n"
    );
    for l in iso.lines().filter(|l| !l.starts_with('#')) {
        if let Some((code, name)) = l.split_once('\t') {
            let _ = writeln!(countries, "{code} {name}");
        }
    }
    for l in tab.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = l.split('\t').collect();
        if let [codes, _, zone, ..] = f.as_slice() {
            let _ = writeln!(countries, "{zone} {codes}");
        }
    }
    let cpath = root().join("rootfs/usr/share/slate/countries");
    std::fs::write(&cpath, &countries).map_err(|e| format!("{}: {e}", cpath.display()))?;
    println!(
        "xtask: {} zones, {transitions} transitions, {} bytes (tzdata {version}) -> {}",
        names.len(),
        out.len(),
        path.display()
    );
    Ok(())
}
