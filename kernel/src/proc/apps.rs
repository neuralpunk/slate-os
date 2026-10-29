// SPDX-License-Identifier: MIT OR Apache-2.0

//! Per-app permissions (ADR 0022's third point, ADR 0130): a native program
//! that quarry installed, listed in the image's `/usr/lib/quarry/apps`
//! with what its manifest declared, runs in the Slate domain limited to
//! that: internet and packet sockets (network), the users' files under
//! /home and /root (home), Strata's socket (display), the device nodes of
//! GPUs, input devices and sound cards (gpu, input, audio), and code
//! generation (jit). The limits pass to whatever it runs and never widen.
//! A confined process can't change what paths mean: no mounts, chroot,
//! pivot_root or new namespaces. Programs signed by a key the kernel
//! trusts, the user's shell and tools among them, run unconfined.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::abi::linux::errno::{EACCES, EPERM, Errno};
use crate::fs::vfs::{self, Dentry, FileType};
use crate::sync::IrqSpinLock;

pub const NETWORK: u32 = 1 << 0;
pub const HOME: u32 = 1 << 1;
pub const DISPLAY: u32 = 1 << 2;
pub const GPU: u32 = 1 << 3;
pub const INPUT: u32 = 1 << 4;
pub const AUDIO: u32 = 1 << 5;
pub const JIT: u32 = 1 << 6;
/// Set on every confined process: what it may do is the bits above.
pub const CONFINED: u32 = 1 << 31;

/// The permissions' names, as manifests and /proc show them.
pub const NAMES: &[(&str, u32)] = &[
    ("network", NETWORK),
    ("home", HOME),
    ("display", DISPLAY),
    ("gpu", GPU),
    ("input", INPUT),
    ("audio", AUDIO),
    ("jit", JIT),
];

/// The registry quarry keeps in the image: `PATH PERMISSION,...` per line
/// (`none` for none).
pub const REGISTRY: &str = "/usr/lib/quarry/apps";

/// Device majors of the classes a permission opens (devices.txt): DRM,
/// input, sound.
const DRM_MAJOR: u32 = 226;
const INPUT_MAJOR: u32 = 13;
const SOUND_MAJOR: u32 = 116;

/// The registry as last read, under the file's identity (device, inode,
/// size, modification time).
type Key = (u64, u64, u64, (i64, i64));
type Registry = Arc<BTreeMap<String, u32>>;
static CACHE: IrqSpinLock<Option<(Key, Registry)>> = IrqSpinLock::new(None);

fn parse(text: &str) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut words = line.split_whitespace();
        let (Some(path), list) = (words.next(), words.next().unwrap_or("none")) else { continue };
        let bits = list.split(',').filter_map(|n| NAMES.iter().find(|(name, _)| *name == n.trim()).map(|(_, b)| *b));
        out.insert(String::from(path), bits.fold(0, |a, b| a | b));
    }
    out
}

fn registry() -> Option<Registry> {
    let root = vfs::root();
    let d = vfs::resolve_in(&root, &root, REGISTRY, true).ok()?;
    let m = d.metadata();
    let key: Key = (m.dev, m.ino, m.size, (m.mtime.sec, m.mtime.nsec));
    if let Some((k, map)) = CACHE.lock().as_ref()
        && *k == key
    {
        return Some(map.clone());
    }
    if m.size > 1 << 20 {
        return None;
    }
    let mut buf = alloc::vec![0u8; m.size as usize];
    let mut at = 0;
    while at < buf.len() {
        let n = d.inode.read_at(at as u64, &mut buf[at..]).ok()?;
        if n == 0 {
            break;
        }
        at += n;
    }
    let map = Arc::new(parse(core::str::from_utf8(&buf[..at]).ok()?));
    *CACHE.lock() = Some((key, map.clone()));
    Some(map)
}

/// What the registry declares for program `d`, if it lists it: only a
/// file of the system image (on the boot root, where quarry installs).
pub fn declared(d: &Arc<Dentry>) -> Option<u32> {
    if !vfs::in_image(d) {
        return None;
    }
    let path = vfs::path_seen(d, &vfs::root());
    registry()?.get(&path).copied()
}

/// The permissions after an exec: a confined caller's limits only narrow
/// (to what the new program declares, if it is listed); an unconfined one
/// takes the program's, if listed.
pub fn after_exec(inherited: u32, declared: Option<u32>) -> u32 {
    match (inherited & CONFINED != 0, declared) {
        (true, Some(d)) => inherited & (d | CONFINED),
        (true, None) => inherited,
        (false, Some(d)) => d | CONFINED,
        (false, None) => 0,
    }
}

/// The calling process's mask (0: unconfined; the kernel is).
pub fn current() -> u32 {
    super::current().map_or(0, |p| p.app())
}

/// Whether the caller may use `bit`.
pub fn allows(bit: u32) -> bool {
    let a = current();
    a & CONFINED == 0 || a & bit != 0
}

/// EPERM for a confined caller: what would let it change what paths mean
/// (mount, umount, pivot_root, chroot, unshare, setns).
pub fn unconfined() -> Result<(), Errno> {
    if current() & CONFINED != 0 { Err(EPERM) } else { Ok(()) }
}

/// Whether a confined caller may reach `d`, a path it resolved (EACCES if
/// not): the users' files need `home`, the device nodes of each class
/// their permission.
pub fn may_reach(d: &Arc<Dentry>) -> Result<(), Errno> {
    let a = current();
    if a & CONFINED == 0 {
        return Ok(());
    }
    let m = d.metadata();
    if m.file_type() == FileType::CharDevice {
        let need = match crate::fs::vfs::major(m.rdev) {
            DRM_MAJOR => GPU,
            INPUT_MAJOR => INPUT,
            SOUND_MAJOR => AUDIO,
            _ => 0,
        };
        if need != 0 && a & need == 0 {
            return Err(EACCES);
        }
    }
    if a & HOME == 0 {
        let p = vfs::path_seen(d, &vfs::root());
        let under = |top: &str| p == top || p.strip_prefix(top).is_some_and(|rest| rest.starts_with('/'));
        if under("/home") || under("/root") {
            return Err(EACCES);
        }
    }
    Ok(())
}

/// Whether a confined caller may connect to the abstract Unix socket
/// `name`: Strata's (`strata-UID`, strata-client) needs `display`.
pub fn may_connect_abstract(name: &[u8]) -> Result<(), Errno> {
    if name.starts_with(b"strata") && !allows(DISPLAY) { Err(EACCES) } else { Ok(()) }
}

/// The permissions of mask `a`, for /proc/PID/status: none when
/// unconfined.
pub fn describe(a: u32) -> Option<String> {
    if a & CONFINED == 0 {
        return None;
    }
    let names: Vec<&str> = NAMES.iter().filter(|(_, b)| a & b != 0).map(|(n, _)| *n).collect();
    Some(if names.is_empty() { String::from("none") } else { names.join(", ") })
}

pub const TESTS: &[crate::ktest::Test] = &[
    crate::ktest::Test { name: "apps::registry_parse", run: test_parse },
    crate::ktest::Test { name: "apps::limits_never_widen", run: test_never_widen },
];

/// The registry's lines: names known and unknown, `none`, comments.
fn test_parse() -> Result<(), &'static str> {
    let m = parse("# a comment\n/usr/bin/a network,home\n/usr/bin/b none\n/usr/bin/c gpu,teleport\n\n");
    if m.get("/usr/bin/a") != Some(&(NETWORK | HOME))
        || m.get("/usr/bin/b") != Some(&0)
        || m.get("/usr/bin/c") != Some(&GPU)
    {
        return Err("the registry was misread");
    }
    if describe(CONFINED | NETWORK | JIT).as_deref() != Some("network, jit")
        || describe(CONFINED).as_deref() != Some("none")
    {
        return Err("permissions described wrongly");
    }
    Ok(())
}

/// An exec never widens a confined process's limits: a listed program
/// narrows them, an unlisted (system) one keeps them; an unconfined caller
/// takes a listed program's.
fn test_never_widen() -> Result<(), &'static str> {
    let app = CONFINED | NETWORK;
    let ok = after_exec(app, Some(NETWORK | HOME)) == app
        && after_exec(app, Some(HOME)) == CONFINED
        && after_exec(app, None) == app
        && after_exec(0, Some(DISPLAY)) == CONFINED | DISPLAY
        && after_exec(0, None) == 0;
    if ok { Ok(()) } else { Err("an exec widened the limits") }
}
