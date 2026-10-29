// SPDX-License-Identifier: MIT OR Apache-2.0

//! The kernel's sampling profiles (`/proc/slate_profile`, ADR 0062) made
//! readable on the host: each sampled address becomes the function it is
//! in, from the kernel's symbols or those of a program built again with
//! its symbol table (`userland::build_with_symbols`), counted per process.
//! Function names come from the host's `nm`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

/// A program's functions by address.
#[derive(Debug, Default)]
pub struct Symbols {
    /// Start address and name, sorted.
    funcs: Vec<(u64, String)>,
}

impl Symbols {
    pub fn load(elf: &Path) -> Result<Symbols> {
        let out = Command::new("nm")
            .args(["-n", "-C", "--defined-only"])
            .arg(elf)
            .output()
            .map_err(|e| format!("nm {}: {e}", elf.display()))?;
        if !out.status.success() {
            return Err(format!("nm {} failed", elf.display()));
        }
        Ok(Symbols::parse(&String::from_utf8_lossy(&out.stdout)))
    }

    /// `nm -n -C` output: `ADDRESS TYPE NAME`; text symbols only.
    fn parse(text: &str) -> Symbols {
        let mut funcs: Vec<(u64, String)> = text
            .lines()
            .filter_map(|l| {
                let mut w = l.splitn(3, ' ');
                let addr = u64::from_str_radix(w.next()?, 16).ok()?;
                let kind = w.next()?;
                let name = w.next()?;
                matches!(kind, "t" | "T" | "w" | "W").then(|| (addr, name.to_string()))
            })
            .collect();
        funcs.sort();
        Symbols { funcs }
    }

    /// The function `addr` is in.
    pub fn name(&self, addr: u64) -> Option<&str> {
        let i = self.funcs.partition_point(|(a, _)| *a <= addr);
        (i > 0).then(|| self.funcs[i - 1].1.as_str())
    }
}

/// Whether two ELF files load the same bytes at the same addresses, the
/// headers aside (a stripped program and its copy with symbols).
pub fn same_code(a: &Path, b: &Path) -> bool {
    fn segments(path: &Path) -> Option<Vec<(u64, Vec<u8>)>> {
        let d = std::fs::read(path).ok()?;
        let u16_at = |o: usize| Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?));
        let u32_at = |o: usize| Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?));
        let u64_at = |o: usize| Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?));
        // ELF-64: e_phoff at 0x20, e_phentsize and e_phnum at 0x36, 0x38;
        // a program header's p_type, p_offset, p_vaddr, p_filesz (the
        // System V ABI's gABI, "Program Header").
        let (phoff, phentsize, phnum) = (u64_at(0x20)? as usize, u16_at(0x36)? as usize, u16_at(0x38)? as usize);
        let headers_end = (phoff + phentsize * phnum) as u64;
        let mut out = Vec::new();
        for i in 0..phnum {
            let ph = phoff + i * phentsize;
            if u32_at(ph)? != 1 {
                continue; // PT_LOAD only
            }
            let (off, vaddr, size) = (u64_at(ph + 8)?, u64_at(ph + 16)?, u64_at(ph + 32)?);
            // Skip the headers the first segment carries.
            let skip = headers_end.saturating_sub(off).min(size);
            let bytes = d.get((off + skip) as usize..(off + size) as usize)?.to_vec();
            out.push((vaddr + skip, bytes));
        }
        Some(out)
    }
    matches!((segments(a), segments(b)), (Some(x), Some(y)) if x == y)
}

/// Where the symbols are: the kernel, and for each program installed in
/// the image (by its path's last part) its copy with symbols.
pub struct Sources {
    pub kernel: PathBuf,
    pub stripped: PathBuf,
    pub with_symbols: PathBuf,
}

/// One process's samples, by function.
#[derive(Debug, Default, PartialEq)]
pub struct Process {
    pub name: String,
    pub user: u64,
    pub kernel: u64,
    pub functions: Vec<(String, u64)>,
}

/// Read a `/proc/slate_profile` report into each process's functions,
/// most samples first. `lookup` names an address: (exe, is_user, addr).
pub fn summarize(text: &str, mut lookup: impl FnMut(&str, bool, u64) -> String) -> Vec<Process> {
    let mut names: HashMap<u32, (String, String, u64)> = HashMap::new();
    let mut per: BTreeMap<u32, (u64, u64, HashMap<String, u64>)> = BTreeMap::new();
    let mut kernel_slide = 0u64;
    for l in text.lines() {
        // Where KASLR put the kernel (ADR 0095).
        if let Some(s) = l.strip_prefix("# kernel ") {
            kernel_slide = u64::from_str_radix(s.trim(), 16).unwrap_or(0);
            continue;
        }
        if let Some(rest) = l.strip_prefix("# pid ") {
            // The load bias (ADR 0092) is last; older reports lack it.
            let w: Vec<&str> = rest.split(' ').collect();
            let (pid, name, exe, bias) = match w[..] {
                [pid, name, exe] => (pid, name, exe, "0"),
                [pid, name, exe, bias] => (pid, name, exe, bias),
                _ => continue,
            };
            if let (Ok(pid), Ok(bias)) = (pid.parse(), u64::from_str_radix(bias, 16)) {
                names.insert(pid, (name.to_string(), exe.to_string(), bias));
            }
            continue;
        }
        let w: Vec<&str> = l.split(' ').collect();
        let [n, pid, mode, addr] = w[..] else { continue };
        let (Ok(n), Ok(pid), Ok(addr)) = (n.parse::<u64>(), pid.parse::<u32>(), u64::from_str_radix(addr, 16)) else {
            continue;
        };
        let user = mode == "u";
        let (exe, bias) = names.get(&pid).map_or(("-", 0), |(_, e, b)| (e.as_str(), *b));
        let f = lookup(exe, user, addr.wrapping_sub(if user { bias } else { kernel_slide }));
        let e = per.entry(pid).or_default();
        if user {
            e.0 += n;
        } else {
            e.1 += n;
        }
        *e.2.entry(f).or_default() += n;
    }
    let mut out: Vec<Process> = per
        .into_iter()
        .map(|(pid, (user, kernel, funcs))| {
            let mut functions: Vec<(String, u64)> = funcs.into_iter().collect();
            functions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let name = names.get(&pid).map_or_else(|| format!("pid {pid}"), |(n, _, _)| format!("{n} (pid {pid})"));
            Process { name, user, kernel, functions }
        })
        .collect();
    out.sort_by_key(|p| std::cmp::Reverse(p.user + p.kernel));
    out
}

/// The report as text: each process, then its `top` functions with their
/// share of its samples; kernel functions are marked `[k]`.
pub fn render(text: &str, src: &Sources, top: usize) -> Result<String> {
    let kernel = Symbols::load(&src.kernel)?;
    let mut programs: HashMap<String, Option<Symbols>> = HashMap::new();
    let procs = summarize(text, |exe, user, addr| {
        if !user {
            return format!("[k] {}", kernel.name(addr).unwrap_or("?"));
        }
        let base = exe.rsplit('/').next().unwrap_or(exe).to_string();
        let syms = programs.entry(base.clone()).or_insert_with(|| {
            let (a, b) = (src.stripped.join(&base), src.with_symbols.join(&base));
            if same_code(&a, &b) { Symbols::load(&b).ok() } else { None }
        });
        match syms.as_ref().and_then(|s| s.name(addr)) {
            Some(n) => n.to_string(),
            None => format!("{base}+{addr:#x}"),
        }
    });
    let mut s = String::new();
    let header = text.lines().next().unwrap_or("");
    s.push_str(&format!("{header}\n"));
    for p in procs {
        let total = (p.user + p.kernel).max(1);
        s.push_str(&format!(
            "\n{}: {} samples, {:.1}% user, {:.1}% kernel\n",
            p.name,
            p.user + p.kernel,
            p.user as f64 * 100.0 / total as f64,
            p.kernel as f64 * 100.0 / total as f64
        ));
        for (f, n) in p.functions.iter().take(top) {
            s.push_str(&format!("  {:5.1}% {n:6}  {f}\n", *n as f64 * 100.0 / total as f64));
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbols_by_address() {
        let s = Symbols::parse(
            "0000000000201000 T main\n0000000000201100 t helper\n0000000000300000 d DATA\n\
             0000000000201200 T core::fmt::write\n",
        );
        assert_eq!(s.name(0x200fff), None);
        assert_eq!(s.name(0x201000), Some("main"));
        assert_eq!(s.name(0x2010ff), Some("main"));
        assert_eq!(s.name(0x201150), Some("helper"));
        assert_eq!(s.name(0x400000), Some("core::fmt::write"));
    }

    #[test]
    fn reports_by_process_and_function() {
        // The terminal's samples come with its load bias.
        let text = "# samples 9 dropped 0 running no\n# kernel 10000\n# pid 7 strata /bin/strata\n\
                    # pid 9 terminal /bin/terminal 5550000\n\
                    4 7 u 201010\n2 7 u 201110\n1 7 k ffffffff80011000\n1 7 u 201020\n1 9 u 5751010\n";
        let p = summarize(text, |exe, user, addr| {
            if !user {
                assert_eq!(addr, 0xffffffff80001000, "the kernel's slide is taken off");
                "[k] k".into()
            } else if addr < 0x201100 {
                format!("{exe}:a")
            } else {
                format!("{exe}:b")
            }
        });
        assert_eq!(p.len(), 2);
        assert_eq!(
            p[0],
            Process {
                name: "strata (pid 7)".into(),
                user: 7,
                kernel: 1,
                functions: vec![("/bin/strata:a".into(), 5), ("/bin/strata:b".into(), 2), ("[k] k".into(), 1)],
            }
        );
        assert_eq!(p[1].functions, vec![("/bin/terminal:a".into(), 1)]);
    }
}
