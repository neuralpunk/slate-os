// SPDX-License-Identifier: MIT OR Apache-2.0

//! The menu file (ADR 0089): the part of Limine's configuration syntax
//! that Slate writes (`libs/esp`, the image builders). Global options come
//! first as `key: value` lines (`timeout:`, `default_entry:`), then the
//! entries, each a `/Title` line followed by its options (`protocol:`,
//! `path:`, `cmdline:`, and `module_path:` with its `module_cmdline:`).
//! `#` starts a comment line. Paths are `boot():/...`, a file on the
//! partition the loader came from. An entry with `protocol: efi` starts
//! another system's EFI loader instead (ADR 0116), from the loader's
//! partition or from the one `guid(GUID):/...` names by its GPT unique
//! GUID; the BIOS loader leaves such entries off its menu.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// The two places the menu file can be, in the order they are read (ADR
/// 0086's switch: the first wins when both are there).
pub const FILES: [&str; 2] = ["boot/limine/limine.conf", "boot/limine.conf"];

/// A boot module: a file loaded next to the kernel, and its name for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// On the partition, without `boot():/`.
    pub path: String,
    pub cmdline: String,
}

/// The partition a path is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Volume {
    /// The loader's own (`boot()`).
    Boot,
    /// The partition with this GPT unique GUID, in its on-disk byte order
    /// (`guid(...)`, UEFI 2.10 §5.3.1's mixed-endian form).
    Guid([u8; 16]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub title: String,
    /// The kernel, on the partition; for a chainloaded system, its EFI
    /// loader on `volume`.
    pub kernel: String,
    /// Another system's EFI loader rather than a Limine-protocol kernel
    /// (`protocol: efi`).
    pub efi: bool,
    /// Where `kernel` is: always the loader's partition for a kernel.
    pub volume: Volume,
    pub cmdline: String,
    pub modules: Vec<Module>,
    /// `kaslr: no` turns the kernel's random placement off (Limine's
    /// CONFIG.md option); so does `nokaslr` on its command line.
    pub kaslr: bool,
}

impl Entry {
    /// Whether a position-independent kernel goes at a random place.
    pub fn randomized(&self) -> bool {
        self.kaslr && !self.cmdline.split_ascii_whitespace().any(|w| w == "nokaslr")
    }

    /// The system an entry boots, from its kernel's directory
    /// (`boot/slate/system-2/kernel`), if it names one.
    pub fn system(&self) -> Option<&str> {
        let dir = self.kernel.strip_prefix("boot/slate/")?.strip_suffix("/kernel")?;
        (!dir.contains('/')).then_some(dir)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Menu {
    /// Seconds before the default boots; None waits for a choice.
    pub timeout: Option<u32>,
    /// The default entry, from 0.
    pub default: usize,
    pub entries: Vec<Entry>,
    /// `interface_resolution: WxH`: the screen mode to use, when the
    /// display's EDID doesn't say (ADR 0111). Limine sizes only its menu
    /// with it; slate-loader keeps the mode for the kernel too.
    pub resolution: Option<(u32, u32)>,
}

impl Menu {
    /// The menu without the entries that chainload EFI loaders (for the
    /// BIOS loader), the default following its entry; None if nothing is
    /// left.
    pub fn without_efi(mut self) -> Option<Menu> {
        let default = self.entries.get(self.default).map(|e| e.title.clone());
        self.entries.retain(|e| !e.efi);
        if self.entries.is_empty() {
            return None;
        }
        self.default = self.entries.iter().position(|e| Some(&e.title) == default.as_ref()).unwrap_or(0);
        Some(self)
    }

    /// Boot the entry titled as the one-shot file says (`slate_esp::NEXT`,
    /// ADR 0116) this once, without waiting. Whether the file asked for
    /// anything (and should be cleared).
    pub fn apply_next(&mut self, next: Option<&[u8]>) -> bool {
        let Some(title) = next.map(|n| String::from_utf8_lossy(n).trim().to_string()) else { return false };
        if title.is_empty() {
            return false;
        }
        if let Some(i) = self.entries.iter().position(|e| e.title == title) {
            self.default = i;
            self.timeout = Some(0);
        }
        true
    }
}

/// A GUID's text (`8-4-4-4-12` hex digits) as its 16 bytes on disk: the
/// first three fields little-endian (UEFI 2.10 appendix A).
pub fn guid_bytes(text: &str) -> Option<[u8; 16]> {
    let parts: Vec<&str> = text.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    if parts.len() != 5 || parts.iter().zip(lens).any(|(p, n)| p.len() != n) {
        return None;
    }
    let hex: String = parts.concat();
    let mut b = [0u8; 16];
    for (i, out) in b.iter_mut().enumerate() {
        *out = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    b[0..4].reverse();
    b[4..6].reverse();
    b[6..8].reverse();
    Some(b)
}

/// What is wrong with a menu file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub what: String,
}

fn path_of(value: &str, line: usize) -> Result<String, Error> {
    match located(value, line)? {
        (Volume::Boot, p) => Ok(p),
        _ => Err(Error { line, what: alloc::format!("only boot():/ paths are read here, not {value:?}") }),
    }
}

/// A path and its partition: `boot():/...` or `guid(GUID):/...`.
fn located(value: &str, line: usize) -> Result<(Volume, String), Error> {
    // A hash after the path (`#...`) checks the file; Slate writes none.
    let value = value.split('#').next().unwrap_or("").trim();
    let bad = || Error { line, what: alloc::format!("only boot():/ and guid(...):/ paths are read, not {value:?}") };
    let (volume, rest) = if let Some(p) = value.strip_prefix("boot():/") {
        (Volume::Boot, p)
    } else {
        let (g, p) = value.strip_prefix("guid(").and_then(|r| r.split_once("):/")).ok_or_else(bad)?;
        (Volume::Guid(guid_bytes(g).ok_or_else(bad)?), p)
    };
    if rest.is_empty() {
        return Err(bad());
    }
    Ok((volume, rest.to_string()))
}

/// Read a menu file. The menu is the entries that have a kernel; the first
/// error stops the reading.
pub fn parse(text: &str) -> Result<Menu, Error> {
    let mut menu = Menu { timeout: Some(5), default: 0, entries: Vec::new(), resolution: None };
    let mut default = 1usize;
    let mut current: Option<(Entry, usize)> = None;
    let finish = |current: &mut Option<(Entry, usize)>, entries: &mut Vec<Entry>| -> Result<(), Error> {
        if let Some((e, line)) = current.take() {
            if e.kernel.is_empty() {
                return Err(Error { line, what: alloc::format!("the entry {:?} has no path", e.title) });
            }
            if !e.efi && e.volume != Volume::Boot {
                return Err(Error {
                    line,
                    what: alloc::format!("the entry {:?}: a kernel comes from boot():/", e.title),
                });
            }
            entries.push(e);
        }
        Ok(())
    };
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let l = raw.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if let Some(title) = l.strip_prefix('/') {
            finish(&mut current, &mut menu.entries)?;
            // Sub-entries (`//`) are not written by Slate.
            if title.starts_with('/') {
                return Err(Error { line: n, what: "sub-entries are not read".into() });
            }
            let entry = Entry {
                title: title.trim().into(),
                kernel: String::new(),
                efi: false,
                volume: Volume::Boot,
                cmdline: String::new(),
                modules: Vec::new(),
                kaslr: true,
            };
            current = Some((entry, n));
            continue;
        }
        let Some((key, value)) = l.split_once(':') else {
            return Err(Error { line: n, what: alloc::format!("not an option: {l:?}") });
        };
        let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
        match (&mut current, key.as_str()) {
            (None, "timeout") => {
                menu.timeout = if value == "no" {
                    None
                } else {
                    Some(value.parse().map_err(|_| Error { line: n, what: "timeout: a number or no".into() })?)
                };
            }
            (None, "interface_resolution") => {
                // WxH, or WxHxBPP as Limine also takes it.
                let mut it = value.split('x').map(|v| v.trim().parse::<u32>().ok());
                menu.resolution = match (it.next().flatten(), it.next().flatten()) {
                    (Some(w), Some(h)) if w > 0 && h > 0 => Some((w, h)),
                    _ => return Err(Error { line: n, what: "interface_resolution: like 1920x1080".into() }),
                };
            }
            (None, "default_entry") => {
                default = value.parse().map_err(|_| Error { line: n, what: "default_entry: a number".into() })?;
            }
            (None, _) => {}
            // Limine's names for chainloading: `efi`, and the older
            // `efi_chainload` (CONFIG.md).
            (Some((e, _)), "protocol") if matches!(value, "efi" | "efi_chainload") => e.efi = true,
            (Some((_, _)), "protocol") if value != "limine" => {
                return Err(Error {
                    line: n,
                    what: alloc::format!("protocol {value:?}: only limine and efi are spoken"),
                });
            }
            (Some((e, _)), "path" | "kernel_path" | "image_path") => (e.volume, e.kernel) = located(value, n)?,
            (Some((e, _)), "cmdline" | "kernel_cmdline") => e.cmdline = value.into(),
            (Some((e, _)), "kaslr") => e.kaslr = value != "no",
            (Some((e, _)), "module_path") => {
                e.modules.push(Module { path: path_of(value, n)?, cmdline: String::new() })
            }
            (Some((e, _)), "module_cmdline" | "module_string") => match e.modules.last_mut() {
                Some(m) => m.cmdline = value.into(),
                None => return Err(Error { line: n, what: "module_cmdline before any module_path".into() }),
            },
            (Some(_), _) => {}
        }
    }
    finish(&mut current, &mut menu.entries)?;
    if menu.entries.is_empty() {
        return Err(Error { line: 0, what: "no entries".into() });
    }
    menu.default = default.clamp(1, menu.entries.len()) - 1;
    Ok(menu)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `libs/esp` writes after an update (ADR 0086).
    const UPDATED: &str = "timeout: 3\n\
        \n\
        /Slate\n    protocol: limine\n    path: boot():/boot/slate/system-2/kernel\n    cmdline: root=PARTUUID=x quiet\n    \
        module_path: boot():/boot/slate/system-2/unlock\n    module_cmdline: unlock\n\
        \n\
        /Slate (previous system)\n    protocol: limine\n    path: boot():/boot/slate/system-1/kernel\n    \
        cmdline: root=PARTUUID=x quiet slate.system=system-1\n";

    #[test]
    fn reads_what_slate_writes() {
        let m = parse(UPDATED).unwrap();
        assert_eq!(m.timeout, Some(3));
        assert_eq!(m.default, 0);
        assert_eq!(m.entries.len(), 2);
        let e = &m.entries[0];
        assert_eq!((e.title.as_str(), e.kernel.as_str()), ("Slate", "boot/slate/system-2/kernel"));
        assert_eq!(e.cmdline, "root=PARTUUID=x quiet");
        assert_eq!(e.modules, [Module { path: "boot/slate/system-2/unlock".into(), cmdline: "unlock".into() }]);
        assert_eq!(e.system(), Some("system-2"));
        assert_eq!(m.entries[1].cmdline, "root=PARTUUID=x quiet slate.system=system-1");
        assert!(m.entries[1].modules.is_empty());
    }

    #[test]
    fn install_media_and_test_images() {
        let media = "timeout: 3\ndefault_entry: 2\n\n/Install Slate\n    protocol: limine\n    \
            path: boot():/boot/slate/kernel\n    cmdline: slate.live quiet\n\n/Install Slate (text mode)\n    \
            protocol: limine\n    path: boot():/boot/slate/kernel\n    cmdline: slate.live quiet slate.installer=text\n";
        let m = parse(media).unwrap();
        assert_eq!((m.default, m.entries[1].title.as_str()), (1, "Install Slate (text mode)"));
        assert_eq!(m.entries[0].system(), None);
        let test =
            "timeout: 0\n\n/Slate\n    protocol: limine\n    path: boot():/boot/slate/kernel\n    cmdline: test\n";
        assert_eq!(parse(test).unwrap().timeout, Some(0));
        assert_eq!(parse("timeout: no\n/A\n path: boot():/k\n").unwrap().timeout, None);
        assert_eq!(
            parse("interface_resolution: 1920x1080\n/A\n path: boot():/k\n").unwrap().resolution,
            Some((1920, 1080))
        );
        assert_eq!(
            parse("interface_resolution: 2560x1440x32\n/A\n path: boot():/k\n").unwrap().resolution,
            Some((2560, 1440))
        );
        assert!(parse("interface_resolution: big\n/A\n path: boot():/k\n").is_err());
    }

    /// Another system's loader, chainloaded (ADR 0116).
    #[test]
    fn other_systems() {
        let text = "timeout: 3\n/Slate\n protocol: limine\n path: boot():/boot/slate/system-1/kernel\n\
            /Windows Boot Manager\n protocol: efi\n path: boot():/EFI/Microsoft/Boot/bootmgfw.efi\n\
            /Fedora\n protocol: efi\n path: guid(01234567-89ab-cdef-0123-456789abcdef):/EFI/fedora/shimx64.efi\n";
        let m = parse(text).unwrap();
        assert!(!m.entries[0].efi && m.entries[1].efi && m.entries[2].efi);
        assert_eq!(
            (m.entries[1].volume, m.entries[1].kernel.as_str()),
            (Volume::Boot, "EFI/Microsoft/Boot/bootmgfw.efi")
        );
        let g = [0x67, 0x45, 0x23, 0x01, 0xab, 0x89, 0xef, 0xcd, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(m.entries[2].volume, Volume::Guid(g));
        assert_eq!(m.entries[1].system(), None);
        // The BIOS loader's menu: Slate alone, still the default.
        let mut m = parse(text).unwrap();
        m.default = 0;
        let bios = m.clone().without_efi().unwrap();
        assert_eq!((bios.entries.len(), bios.default), (1, 0));
        assert_eq!(parse("/W\n protocol: efi\n path: boot():/w.efi\n").unwrap().without_efi(), None);
        // A one-shot choice: booted at once; blank or unknown, nothing.
        assert!(m.apply_next(Some(b"Fedora\n")));
        assert_eq!((m.default, m.timeout), (2, Some(0)));
        let mut m = parse(text).unwrap();
        assert!(!m.apply_next(Some(b"   \n")) && !m.apply_next(None));
        assert!(m.apply_next(Some(b"Gone")));
        assert_eq!((m.default, m.timeout), (0, Some(3)));
    }

    #[test]
    fn refuses_what_it_cannot_boot() {
        assert_eq!(parse("timeout: 3\n").unwrap_err().what, "no entries");
        assert_eq!(parse("/A\n cmdline: x\n").unwrap_err().line, 1);
        assert!(parse("/A\n path: guid(1234):/k\n").unwrap_err().what.contains("boot():/"));
        let other = "/A\n path: guid(01234567-89ab-cdef-0123-456789abcdef):/k\n";
        assert!(parse(other).unwrap_err().what.contains("a kernel comes from boot():/"));
        assert!(parse("/A\n protocol: linux\n path: boot():/k\n").unwrap_err().what.contains("limine"));
        assert!(parse("/A\n module_cmdline: x\n path: boot():/k\n").is_err());
        assert!(parse("/A\n path: boot():/k\n//B\n").is_err());
    }
}
