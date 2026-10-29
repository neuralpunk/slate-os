// SPDX-License-Identifier: MIT OR Apache-2.0

//! SlateFS subvolumes of a mounted file system (ADR 0027), through the
//! kernel's `SLATEFS_IOC_CTL` ioctl: snapshots, the boot state, mounting a
//! subvolume. slate-update and quarry's transactions (ADR 0070) use it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{fs, io};

/// `SLATEFS_IOC_CTL` (kernel/src/fs/slatefs.rs, Slate's own range).
const SLATEFS_IOC_CTL: u32 = 0xC020_F501;

/// A subvolume: its id, name and flags (`default`, `fallback`,
/// `mounted-here`, ...).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subvol {
    pub id: u64,
    pub name: String,
    pub flags: Vec<String>,
}

impl Subvol {
    pub fn has(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }
}

/// Send a control command to the SlateFS holding `path`; its answer.
pub fn ctl(path: &str, cmd: &str) -> Result<String, String> {
    let fd = fs::open(path.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let mut out = alloc::vec![0u8; 8192];
    let args: [u64; 4] = [cmd.as_ptr() as u64, cmd.len() as u64, out.as_mut_ptr() as u64, out.len() as u64];
    let r = io::ioctl(fd, SLATEFS_IOC_CTL, args.as_ptr() as usize);
    let _ = io::close(fd);
    match r {
        Ok(n) => {
            out.truncate(n);
            Ok(String::from_utf8_lossy(&out).into_owned())
        }
        Err(crate::Errno::ENOTTY) => Err("the root file system is not SlateFS".into()),
        Err(e) => Err(format!("{cmd}: {e}")),
    }
}

/// The subvolumes of the root file system.
pub fn list() -> Result<Vec<Subvol>, String> {
    Ok(parse_list(&ctl("/", "list")?))
}

fn parse_list(text: &str) -> Vec<Subvol> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(' ');
            let id = f.next()?.parse().ok()?;
            let name = f.next()?.to_string();
            let flags = f.next().unwrap_or("").split(',').filter(|s| !s.is_empty()).map(String::from).collect();
            Some(Subvol { id, name, flags })
        })
        .collect()
}

/// The first subvolume with `flag`.
pub fn flagged(list: &[Subvol], flag: &str) -> Option<String> {
    list.iter().find(|s| s.has(flag)).map(|s| s.name.clone())
}

/// The subvolume the root is.
pub fn running(list: &[Subvol]) -> Result<String, String> {
    flagged(list, "mounted-here").ok_or_else(|| "cannot tell which subvolume is running".into())
}

/// `system-N`'s number.
pub fn system_number(name: &str) -> Option<u64> {
    name.strip_prefix("system-")?.parse().ok()
}

/// The next free `system-N` name, `ahead` numbers past the highest.
pub fn next_system(list: &[Subvol], ahead: u64) -> String {
    let n = list.iter().filter_map(|s| system_number(&s.name)).max().unwrap_or(0) + ahead;
    format!("system-{n}")
}

/// The device the root is mounted from, if the root is SlateFS
/// (/proc/mounts).
pub fn root_device() -> Result<String, String> {
    let m = fs::read_file(b"/proc/mounts").map_err(|e| format!("/proc/mounts: {e}"))?;
    String::from_utf8_lossy(&m)
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            (f.get(1) == Some(&"/") && f.get(2) == Some(&"slatefs")).then(|| f[0].to_string())
        })
        .ok_or_else(|| "the root file system is not SlateFS".into())
}

/// Mount subvolume `name` of the root's device at `at`.
pub fn mount(name: &str, at: &str) -> Result<(), String> {
    let dev = root_device()?;
    let _ = fs::mkdir(at.as_bytes(), 0o755);
    fs::mount(dev.as_bytes(), at.as_bytes(), b"slatefs", 0, format!("subvol={name}").as_bytes())
        .map_err(|e| format!("mounting {name} at {at}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists() {
        let l = parse_list("1 system-1 fallback\n2 home \n4 system-3 default,mounted-here\n");
        assert_eq!(l.len(), 3);
        assert_eq!(running(&l).unwrap(), "system-3");
        assert_eq!(flagged(&l, "fallback").as_deref(), Some("system-1"));
        assert_eq!(next_system(&l, 1), "system-4");
        assert_eq!(next_system(&l, 2), "system-5");
        assert!(l[1].flags.is_empty());
    }
}
