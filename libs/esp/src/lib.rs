// SPDX-License-Identifier: MIT OR Apache-2.0

//! The EFI System Partition as Slate lays it out (ADR 0086): a kernel per
//! bootable system, the Limine configuration naming them, and how the
//! partition follows the SlateFS boot state.
//!
//! ```text
//! EFI/BOOT/BOOTX64.EFI          Limine (UEFI)
//! boot/limine/limine-bios.sys   Limine (BIOS)
//! boot/limine/limine.conf       the configuration, or
//! boot/limine.conf              the configuration
//! boot/slate/system-N/kernel    a system's kernel
//! boot/slate/system-N/unlock    its unlock archive (encrypted roots)
//! ```
//!
//! Limine reads the first of `boot/limine/limine.conf` and
//! `boot/limine.conf` it finds (Limine's CONFIG.md), so the configuration
//! changes by creating or deleting one directory entry ([`switch`]).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_fat::edit::{Disk, Fs};

/// Limine's configuration, the one it prefers.
pub const CONF_FIRST: &str = "boot/limine/limine.conf";
/// The one it reads when the first is not there.
pub const CONF_SECOND: &str = "boot/limine.conf";
/// Where the kernel was before ADR 0086 (one for every system).
pub const LEGACY_KERNEL: &str = "boot/slate/kernel";
pub const LEGACY_UNLOCK: &str = "boot/slate/unlock";
/// The kernel in a system's tree.
pub const SYSTEM_KERNEL: &str = "boot/slate/kernel";

/// The loader's count of a trial boot (ADR 0089): `system-N K`, the system
/// on trial (the menu's default) and the boots slate-loader still gives it
/// before it starts the previous system with `slate.boot=rollback`. There
/// while an update is on trial, gone once it is confirmed or rolled back.
pub const TRIES: &str = "boot/slate/tries";
/// The boots a new system gets from the loader.
pub const TRIAL_BOOTS: u32 = 1;
/// A one-shot choice for the next boot (ADR 0116): the title of the menu
/// entry to start once, without waiting (`slate-update next`). The loader
/// empties it as it boots.
pub const NEXT: &str = "boot/slate/next";

/// The tries file's text.
pub fn tries_text(system: &str, left: u32) -> String {
    format!("{system} {left}\n")
}

/// The tries file: the system and the boots it has left.
pub fn parse_tries(t: &[u8]) -> Option<(String, u32)> {
    let t = core::str::from_utf8(t).ok()?;
    let (system, left) = t.trim().split_once(' ')?;
    Some((String::from(system), left.trim().parse().ok()?))
}

/// The unlock program in the system (ADR 0038).
pub const UNLOCK_PROGRAM: &str = "bin/slate-unlock";
/// The fonts its screen uses (Strata's, `userland/strata/src/fonts.rs`);
/// without them it asks on the console only.
pub const UNLOCK_FONTS: &[&str] = &[
    "usr/share/fonts/slate/HostGrotesk-400.ttf",
    "usr/share/fonts/slate/HostGrotesk-500.ttf",
    "usr/share/fonts/slate/HostGrotesk-600.ttf",
    "usr/share/fonts/slate/DMMono-Regular.ttf",
    "usr/share/fonts/slate/DMMono-Medium.ttf",
];

/// A system's directory on the partition.
pub fn system_dir(system: &str) -> String {
    format!("boot/slate/{system}")
}

/// The boot's unlock archive (ADR 0038), a cpio (newc) archive Limine
/// loads as the `unlock` module: the unlock program and its fonts, read
/// from the system with `get` (a path without the leading slash).
pub fn unlock_archive(get: &mut dyn FnMut(&str) -> Option<Vec<u8>>) -> Result<Vec<u8>, String> {
    let program = get(UNLOCK_PROGRAM).ok_or_else(|| format!("the system has no /{UNLOCK_PROGRAM}"))?;
    let mut w = slate_cpio::Writer::new();
    w.dir("bin", 0o755);
    w.file(UNLOCK_PROGRAM, 0o755, &program);
    let fonts: Vec<(&str, Vec<u8>)> = UNLOCK_FONTS.iter().filter_map(|p| get(p).map(|d| (*p, d))).collect();
    if fonts.len() == UNLOCK_FONTS.len() {
        for d in ["usr", "usr/share", "usr/share/fonts", "usr/share/fonts/slate"] {
            w.dir(d, 0o755);
        }
        for (p, d) in fonts {
            w.file(p, 0o644, &d);
        }
    }
    Ok(w.finish())
}

/// The fonts in an unlock archive already on the partition, by path: a
/// system without them (one installed without Strata, whose installer
/// took the fonts from its payload) keeps the screen it had.
pub fn archive_fonts(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    slate_cpio::entries(archive)
        .filter_map(Result::ok)
        .filter(|e| UNLOCK_FONTS.contains(&e.name))
        .map(|e| (String::from(e.name), e.data.to_vec()))
        .collect()
}

/// The unlock archive a system had on `fs` (its own directory, else the
/// layout from before ADR 0086), if any.
pub fn current_unlock<D: Disk>(fs: &mut Fs<D>, system: &str) -> Option<Vec<u8>> {
    fs.read(&format!("{}/unlock", system_dir(system))).ok().or_else(|| fs.read(LEGACY_UNLOCK).ok())
}

/// The `Slate` notes of an ELF file.
fn slate_notes(elf: &[u8]) -> Vec<(u32, Vec<u8>)> {
    let Ok(e) = slate_elf::Elf::parse(elf) else { return Vec::new() };
    let mut out = Vec::new();
    for ph in e.program_headers().filter(|p| p.kind == slate_elf::PT_NOTE) {
        let Some(data) = elf.get(ph.offset as usize..(ph.offset + ph.filesz) as usize) else { continue };
        for n in slate_elf::notes(data, ph.align).filter(|n| n.name == slate_abi::NOTE_NAME) {
            out.push((n.kind, n.desc.to_vec()));
        }
    }
    out
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The native interface versions a kernel serves: its `Slate` note of type
/// `NT_SLATE_KERNEL_ABI` (oldest, newest). None for a kernel without it
/// (one built before ADR 0086, which serves version 1).
pub fn kernel_range(kernel: &[u8]) -> Option<(u32, u32)> {
    slate_notes(kernel)
        .into_iter()
        .find(|(k, _)| *k == slate_abi::NT_SLATE_KERNEL_ABI)
        .and_then(|(_, d)| Some((u32_le(&d, 0)?, u32_le(&d, 4)?)))
}

/// The native interface version a program was built for (its
/// `NT_SLATE_ABI` note); None for a Linux program.
pub fn program_version(program: &[u8]) -> Option<u32> {
    slate_notes(program).into_iter().find(|(k, _)| *k == slate_abi::NT_SLATE_ABI).and_then(|(_, d)| u32_le(&d, 0))
}

/// Whether `kernel` can run `unlock` (the unlock program): its interface
/// version is one the kernel serves.
pub fn check_unlock(kernel: &[u8], unlock: &[u8]) -> Result<(), String> {
    let want = program_version(unlock).ok_or("the unlock program is not a native Slate program")?;
    let (oldest, newest) = kernel_range(kernel).unwrap_or((1, 1));
    if (oldest..=newest).contains(&want) {
        Ok(())
    } else {
        Err(format!(
            "the kernel serves native interface versions {oldest} to {newest}, but the unlock program needs {want}"
        ))
    }
}

/// One system the partition boots: its name, its kernel and unlock
/// archive (None for a system made before ADR 0086, which boots the
/// partition's legacy kernel).
#[derive(Clone, Debug)]
pub struct Boot {
    pub system: String,
    pub kernel: Option<Vec<u8>>,
    pub unlock: Option<Vec<u8>>,
    /// What the files were made from, recorded beside them ([`SOURCE`])
    /// so that a later sync can tell they are current without reading
    /// them ([`current_from`]).
    pub source: Option<String>,
    /// The partition has the files already, from `source` (with an
    /// unlock archive, or not): none were read, none are written.
    pub kept: Option<bool>,
    /// The system has a GPU maker's firmware (full graphics, ADR 0173):
    /// the menu gets an entry that starts it with standard graphics.
    pub full_graphics: bool,
}

/// The menu entry that starts a system with full graphics on standard
/// graphics instead (ADR 0173): its title, and the words it adds to the
/// command line (the AMD driver off, the display the firmware's).
pub const STANDARD_TITLE: &str = "Slate (standard graphics)";
pub const STANDARD_WORDS: &str = "slate.disable=amd-display";

/// The record of what a system's boot files were made from: the source
/// (a line its maker chooses), then the files' sizes.
pub const SOURCE: &str = "source";

/// Whether the partition's files for `system` were made from `source`
/// and are whole (their sizes as recorded); then, whether it has an
/// unlock archive.
pub fn current_from<D: Disk>(fs: &mut Fs<D>, system: &str, source: &str) -> Option<bool> {
    let dir = system_dir(system);
    let rec = fs.read(&format!("{dir}/{SOURCE}")).ok()?;
    let rec = core::str::from_utf8(&rec).ok()?;
    let (made_from, sizes) = rec.split_once('\n')?;
    if made_from != source {
        return None;
    }
    let (mut kernel, mut unlock) = (None, None);
    for w in sizes.split_ascii_whitespace() {
        match w.split_once('=')? {
            ("kernel", n) => kernel = Some(n),
            ("unlock", n) => unlock = Some(n),
            _ => return None,
        }
    }
    let files = fs.list(&dir).ok()?;
    let size = |name: &str| files.iter().find(|e| !e.dir && e.name == name).map(|e| e.size.to_string());
    if size("kernel").as_deref() != Some(kernel?) {
        return None;
    }
    match unlock? {
        "-" => size("unlock").is_none().then_some(false),
        n => (size("unlock").as_deref() == Some(n)).then_some(true),
    }
}

/// The kernel command line without the words that choose a system (they
/// are the configuration's to add).
pub fn base_cmdline(cmdline: &str) -> String {
    cmdline
        .split_ascii_whitespace()
        .filter(|w| !w.starts_with("slate.system=") && *w != "slate.boot=fallback" && *w != "slate.boot=rollback")
        .collect::<Vec<_>>()
        .join(" ")
}

/// A menu entry: title, system, kernel and unlock archive paths on the
/// partition (`boot():/...`).
struct Entry<'a> {
    title: &'a str,
    system: &'a str,
    kernel: String,
    unlock: Option<String>,
    /// Words added to the command line.
    extra: &'static str,
}

fn entry_of<'a>(b: &'a Boot, title: &'a str, legacy_unlock: bool) -> Entry<'a> {
    let dir = system_dir(&b.system);
    match (&b.kernel, b.kept) {
        (Some(_), _) | (None, Some(_)) => Entry {
            title,
            system: &b.system,
            kernel: format!("{dir}/kernel"),
            unlock: (b.unlock.is_some() || b.kept == Some(true)).then(|| format!("{dir}/unlock")),
            extra: "",
        },
        (None, None) => Entry {
            title,
            system: &b.system,
            kernel: String::from(LEGACY_KERNEL),
            unlock: legacy_unlock.then(|| String::from(LEGACY_UNLOCK)),
            extra: "",
        },
    }
}

/// The menu's wait before booting the first entry, in seconds.
const TIMEOUT: &str = "3";

/// The `timeout:` a configuration sets (CONFIG.md: a global option).
fn timeout_of(conf: &str) -> Option<&str> {
    conf.lines().find_map(|l| l.trim().strip_prefix("timeout:")).map(str::trim)
}

/// The Limine configuration for `entries` (Limine's CONFIG.md syntax):
/// each boots its own kernel. The first boots by the boot state (the
/// kernel picks the system, ADR 0027), so a menu not yet synced after a
/// change of the boot state still boots the right system; the others pass
/// `slate.system=NAME`, but the first's standard-graphics twin (ADR 0173),
/// which follows it as it is.
fn config(cmdline: &str, entries: &[Entry<'_>], timeout: &str) -> String {
    let mut s = format!("timeout: {timeout}\n");
    for (i, e) in entries.iter().enumerate() {
        let twin = i == 1 && e.title == STANDARD_TITLE;
        let cmd = if i == 0 || twin { String::from(cmdline) } else { format!("{cmdline} slate.system={}", e.system) };
        let cmd = if e.extra.is_empty() { cmd } else { format!("{cmd} {}", e.extra) };
        s += &format!(
            "\n/{}\n    protocol: limine\n    path: boot():/{}\n    cmdline: {}\n",
            e.title,
            e.kernel,
            cmd.trim()
        );
        if let Some(u) = &e.unlock {
            s += &format!("    module_path: boot():/{u}\n    module_cmdline: unlock\n");
        }
    }
    s
}

/// Another system's EFI loader on the menu (ADR 0116), chainloaded by
/// slate-loader (Limine's `protocol: efi`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Other {
    pub title: String,
    /// Its partition's GPT unique GUID; None for the menu's own partition.
    pub volume: Option<String>,
    /// The loader's path on its partition (`EFI/fedora/shimx64.efi`).
    pub path: String,
}

/// `conf` with entries for `others` after its own.
pub fn with_others(conf: &str, others: &[Other]) -> String {
    let mut s = String::from(conf);
    for o in others {
        let at = o.volume.as_deref().map_or_else(|| String::from("boot()"), |g| format!("guid({g})"));
        s += &format!("\n/{}\n    protocol: efi\n    path: {at}:/{}\n", o.title, o.path);
    }
    s
}

/// Whether an entry's text (after its `/`) starts another system.
fn starts_other(entry: &str) -> bool {
    entry.lines().any(|l| matches!(l.trim().strip_prefix("protocol:").map(str::trim), Some("efi" | "efi_chainload")))
}

/// The entries of `conf` that start other systems, as they are written:
/// a menu written anew keeps them.
fn others_of(conf: &str) -> String {
    conf.split("\n/").skip(1).filter(|e| starts_other(e)).map(|e| format!("\n/{}\n", e.trim_end())).collect()
}

/// The titles on a menu, in order.
pub fn titles(conf: &str) -> Vec<String> {
    conf.split("\n/").skip(1).filter_map(|e| e.lines().next()).map(|t| String::from(t.trim())).collect()
}

/// The configuration a freshly installed system boots with: one entry, its
/// kernel and unlock archive in `boot/slate/system-1/` (paths for
/// [`slate_fat::Volume`]).
pub fn first_config(cmdline: &str, system: &str, unlock: bool) -> String {
    first_config_with(cmdline, system, unlock, false)
}

/// [`first_config`] for a system installed with full graphics (ADR 0173):
/// with its standard-graphics entry.
pub fn first_config_with(cmdline: &str, system: &str, unlock: bool, full_graphics: bool) -> String {
    let b = Boot {
        system: String::from(system),
        kernel: Some(Vec::new()),
        unlock: unlock.then(Vec::new),
        source: None,
        kept: None,
        full_graphics,
    };
    config(cmdline, &entries_of(&b, None, &[], false), TIMEOUT)
}

/// The menu's entries: the default system, its standard-graphics twin if
/// it has full graphics (ADR 0173), the fallback, the older systems.
fn entries_of<'a>(
    default: &'a Boot,
    fallback: Option<&'a Boot>,
    older: &[&'a Boot],
    legacy_unlock: bool,
) -> Vec<Entry<'a>> {
    let mut entries = alloc::vec![entry_of(default, "Slate", legacy_unlock)];
    if default.full_graphics {
        entries.push(Entry {
            title: STANDARD_TITLE,
            extra: STANDARD_WORDS,
            ..entry_of(default, STANDARD_TITLE, legacy_unlock)
        });
    }
    if let Some(f) = fallback {
        entries.push(entry_of(f, "Slate (previous system)", legacy_unlock));
    }
    entries.extend(older.iter().map(|b| entry_of(b, OLDER_TITLE, false)));
    entries
}

fn fat(what: &str) -> impl Fn(slate_fat::Error) -> String + '_ {
    move |e| format!("boot partition: {what}: {e:?}")
}

/// The configuration Limine uses now: its path and text.
pub fn active<D: Disk>(fs: &mut Fs<D>) -> Option<(&'static str, String)> {
    [CONF_FIRST, CONF_SECOND].into_iter().find_map(|p| {
        let t = fs.read(p).ok()?;
        Some((p, String::from_utf8_lossy(&t).into_owned()))
    })
}

/// Make `conf` the configuration Limine reads, in one directory-entry
/// write: from the first file, write the second and delete the first;
/// from the second (or none), create the first, then delete the second.
pub fn switch<D: Disk>(fs: &mut Fs<D>, conf: &str) -> Result<(), String> {
    let first = fs.exists(CONF_FIRST);
    if first {
        if fs.read(CONF_FIRST).ok().as_deref() == Some(conf.as_bytes()) && !fs.exists(CONF_SECOND) {
            return Ok(());
        }
        fs.write(CONF_SECOND, conf.as_bytes()).map_err(fat(CONF_SECOND))?;
        fs.remove(CONF_FIRST).map_err(fat(CONF_FIRST))
    } else {
        if fs.read(CONF_SECOND).ok().as_deref() == Some(conf.as_bytes()) {
            return Ok(());
        }
        fs.mkdir("boot/limine").map_err(fat("boot/limine"))?;
        fs.write(CONF_FIRST, conf.as_bytes()).map_err(fat(CONF_FIRST))?;
        if fs.exists(CONF_SECOND) {
            fs.remove(CONF_SECOND).map_err(fat(CONF_SECOND))?;
        }
        Ok(())
    }
}

/// Whether the partition already boots `default` first and `fallback`
/// second, then the `older` systems, with the loader's count for `trial`
/// (the system on trial, if any): the configuration's entries name their kernels (in the
/// systems' directories, or the legacy kernel), and the kernels are
/// there. Cheap (no kernel is read), for a check at every boot.
pub fn in_step<D: Disk>(
    fs: &mut Fs<D>,
    default: &str,
    fallback: Option<&str>,
    older: &[&str],
    trial: Option<&str>,
) -> bool {
    let tries = fs.read(TRIES).ok().and_then(|t| parse_tries(&t)).map(|(s, _)| s);
    if tries.as_deref() != trial {
        return false;
    }
    let Some((_, conf)) = active(fs) else { return false };
    let entries: Vec<(&str, &str)> = conf
        .split("\n/")
        .skip(1)
        .filter(|e| !starts_other(e))
        .map(|e| {
            let field = |k: &str| e.lines().find_map(|l| l.trim().strip_prefix(k)).unwrap_or("").trim();
            (field("path: boot():/"), field("cmdline:"))
        })
        .collect();
    let wanted: Vec<&str> = core::iter::once(default).chain(fallback).chain(older.iter().copied()).collect();
    if entries.len() != wanted.len() {
        return false;
    }
    wanted.iter().zip(&entries).enumerate().all(|(i, (system, (path, cmdline)))| {
        let own = format!("{}/kernel", system_dir(system));
        let named = i == 0 || cmdline.split_ascii_whitespace().any(|w| w == format!("slate.system={system}"));
        let kernel_ok = *path == own || (*path == LEGACY_KERNEL && !fs.exists(&own));
        named && kernel_ok && fs.exists(path)
    })
}

/// What [`sync`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Files written (their contents had changed).
    pub written: Vec<String>,
    /// Systems' directories deleted.
    pub removed: Vec<String>,
    /// The configuration changed.
    pub switched: bool,
}

/// Write a system's kernel and unlock archive to its directory (only what
/// changed).
fn put_system<D: Disk>(fs: &mut Fs<D>, b: &Boot, kernel: &[u8], report: &mut Report) -> Result<(), String> {
    let dir = system_dir(&b.system);
    fs.mkdir(&dir).map_err(fat(&dir))?;
    // The record goes first and comes back last: files half written are
    // never taken for current.
    let record = format!("{dir}/{SOURCE}");
    let wanted = b.source.as_ref().map(|s| {
        let unlock = b.unlock.as_ref().map_or_else(|| String::from("-"), |u| u.len().to_string());
        format!("{s}\nkernel={} unlock={unlock}\n", kernel.len())
    });
    let had = fs.read(&record).ok();
    if had.is_some() && had.as_deref() != wanted.as_ref().map(String::as_bytes) {
        fs.remove(&record).map_err(fat(&record))?;
    }
    let mut put = |name: &str, data: &[u8]| -> Result<(), String> {
        let path = format!("{dir}/{name}");
        if fs.read(&path).ok().as_deref() != Some(data) {
            fs.write(&path, data).map_err(fat(&path))?;
            report.written.push(path);
        }
        Ok(())
    };
    put("kernel", kernel)?;
    match &b.unlock {
        Some(u) => put("unlock", u)?,
        None => {
            let path = format!("{dir}/unlock");
            if fs.exists(&path) {
                fs.remove(&path).map_err(fat(&path))?;
            }
        }
    }
    if let Some(w) = wanted
        && had.as_deref() != Some(w.as_bytes())
    {
        fs.write(&record, w.as_bytes()).map_err(fat(&record))?;
    }
    Ok(())
}

/// The title of an older system's entry.
pub const OLDER_TITLE: &str = "Slate (older system)";

/// Make the partition boot `default` first and `fallback` second, then
/// list the `older` systems, newest first, from `cmdline` (the kernel
/// arguments, without the words that choose a system): their kernels and
/// unlock archives in their directories (only what changed is written),
/// the configuration switched in one write, and the directories of other
/// systems deleted. An older system without a kernel of its own, or that
/// does not fit on the partition, is left off the menu. `trial` is the
/// system on trial, which gets the loader's count ([`TRIES`]).
pub fn sync<D: Disk>(
    fs: &mut Fs<D>,
    cmdline: &str,
    default: &Boot,
    fallback: Option<&Boot>,
    older: &[Boot],
    trial: Option<&str>,
) -> Result<Report, String> {
    let mut report = Report::default();
    let main: Vec<&Boot> = core::iter::once(default).chain(fallback).collect();
    let legacy_unlock = fs.exists(LEGACY_UNLOCK);
    for b in &main {
        if b.kept.is_some() {
            continue;
        }
        let Some(kernel) = &b.kernel else {
            if !fs.exists(LEGACY_KERNEL) {
                return Err(format!("{} has no kernel, and the boot partition has none for it", b.system));
            }
            continue;
        };
        put_system(fs, b, kernel, &mut report)?;
    }
    let mut listed: Vec<&Boot> = Vec::new();
    for b in older.iter().filter(|b| !main.iter().any(|m| m.system == b.system)) {
        if b.kept.is_some() {
            listed.push(b);
            continue;
        }
        let Some(kernel) = &b.kernel else { continue };
        if put_system(fs, b, kernel, &mut report).is_err() {
            // Full: this one and the older ones stay off the menu.
            break;
        }
        listed.push(b);
    }
    let entries = entries_of(default, fallback, &listed, legacy_unlock);
    // The menu keeps the wait it has (test images boot at once).
    let current = active(fs).map(|(_, t)| t);
    let timeout = current.as_deref().and_then(timeout_of).unwrap_or(TIMEOUT).to_string();
    // Other systems' entries stay, after Slate's (ADR 0116).
    let conf = config(cmdline, &entries, &timeout) + &current.as_deref().map(others_of).unwrap_or_default();
    report.switched = current.as_deref() != Some(conf.as_str()) || fs.exists(CONF_FIRST) && fs.exists(CONF_SECOND);
    switch(fs, &conf)?;
    // The loader's count: set for a new trial (a count already running for
    // the same system goes on), gone without one.
    let tries = fs.read(TRIES).ok().and_then(|t| parse_tries(&t));
    match trial {
        Some(t) if tries.as_ref().map(|(s, _)| s.as_str()) != Some(t) => {
            fs.write(TRIES, tries_text(t, TRIAL_BOOTS).as_bytes()).map_err(fat(TRIES))?;
            report.written.push(String::from(TRIES));
        }
        None if fs.exists(TRIES) => {
            fs.remove(TRIES).map_err(fat(TRIES))?;
            report.removed.push(String::from(TRIES));
        }
        _ => {}
    }
    // Other systems' directories, and the legacy kernel once no entry
    // needs it.
    let keep: Vec<&str> = main.iter().chain(&listed).map(|b| b.system.as_str()).collect();
    for e in fs.list("boot/slate").unwrap_or_default() {
        let other_system = e.dir && e.name.starts_with("system-") && !keep.contains(&e.name.as_str());
        if other_system {
            let path = format!("boot/slate/{}", e.name);
            fs.remove_tree(&path).map_err(fat(&path))?;
            report.removed.push(e.name);
        }
    }
    if main.iter().all(|b| b.kernel.is_some() || b.kept.is_some()) {
        for legacy in [LEGACY_KERNEL, LEGACY_UNLOCK] {
            if fs.exists(legacy) {
                fs.remove(legacy).map_err(fat(legacy))?;
                report.removed.push(legacy.to_string());
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests;
