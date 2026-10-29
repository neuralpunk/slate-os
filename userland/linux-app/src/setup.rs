// SPDX-License-Identifier: MIT OR Apache-2.0

//! `slate-linux setup [--root DIR] [--mirror URL] [--from FILE|URL]
//! [PACKAGE...]` (ADR 0039): make the Linux runtime on Slate itself.
//!
//! 1. Alpine's minirootfs, pinned by version and SHA-256, comes from the
//!    mirror over plain HTTP (or from FILE or URL) and is checked against
//!    the pin; Slate's own gzip and tar unpack it into the runtime.
//!    `--mirror` also becomes apk's repository.
//! 2. Slate's resolv.conf goes in, for apk, and a machine-id of the
//!    runtime's own.
//! 3. apk, in the runtime, installs the packages (Sway, Xwayland, Firefox
//!    and a font unless others are named); apk checks their signatures
//!    against the keys in the pinned minirootfs.
//!
//! An unpacked runtime is kept: setup again only adds packages. It needs
//! root (it writes the runtime and mounts /dev and /proc for apk).
//!
//! `slate-linux upgrade [--root DIR] [--branch vX.Y] [--simulate]` (ADR
//! 0102) brings a runtime up to date: apk updates its indexes and
//! upgrades every package, to the newest of its Alpine branch, or with
//! `--branch` of another (its repositories are rewritten to name it);
//! `--simulate` shows what would change and changes nothing.
//!
//! On a SlateFS root the runtime is a subvolume of its own, `linux`,
//! mounted at its folder (rc.sysinit mounts it at start; ADR 0102's
//! addendum). `setup` makes it so for a new runtime, and `upgrade` moves
//! an older one there first (a snapshot of the subvolume it was on, with
//! everything else taken out). Before upgrading, `upgrade` keeps the
//! runtime as it is, read-only, as `linux.before`; if apk fails, that is
//! put back, so a failed upgrade changes nothing. After a good one it
//! stays until the next: `slate-linux rollback` returns to it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, println, process};

use crate::DEFAULT_ROOT;

/// The pinned minirootfs (tools/xtask/src/alpine.rs pins the same one for
/// the tests).
pub const ALPINE_BRANCH: &str = "v3.22";
pub const ALPINE_VERSION: &str = "3.22.6";
pub const ALPINE_SHA256: &str = "27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2";
pub const DEFAULT_MIRROR: &str = "http://dl-cdn.alpinelinux.org/alpine";
/// What a graphical runtime needs: the kiosk compositor, Xwayland for X
/// programs, the browser and a font.
pub const DEFAULT_PACKAGES: &[&str] = &["sway", "xwayland", "firefox", "font-dejavu"];
/// What Flatpak's apps need beside it (ADR 0114): their windows go
/// through the kiosk compositor, and Flatpak wants a session bus.
pub const FLATPAK_NEEDS: &[&str] = &["sway", "xwayland", "font-dejavu", "dbus"];

/// `setup`'s command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Setup {
    pub root: String,
    pub mirror: Option<String>,
    pub from: Option<String>,
    pub packages: Vec<String>,
}

pub fn parse(args: &[String]) -> Result<Setup, String> {
    let mut s = Setup { root: String::from(DEFAULT_ROOT), mirror: None, from: None, packages: Vec::new() };
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let value = || args.get(i + 1).cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--root" => s.root = value()?,
            "--mirror" => s.mirror = Some(String::from(value()?.trim_end_matches('/'))),
            "--from" => s.from = Some(value()?),
            o if o.starts_with('-') => {
                return Err(format!(
                    "unknown option {o}\nusage: slate-linux setup [--root DIR] [--mirror URL] [--from FILE|URL] [PACKAGE...]"
                ));
            }
            p => {
                s.packages.push(String::from(p));
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    if s.packages.is_empty() {
        s.packages = DEFAULT_PACKAGES.iter().map(|p| String::from(*p)).collect();
    }
    if s.packages.iter().any(|p| p == "flatpak") {
        for n in FLATPAK_NEEDS {
            if !s.packages.iter().any(|p| p == n) {
                s.packages.push(String::from(*n));
            }
        }
    }
    Ok(s)
}

/// The minirootfs's URL on `mirror`.
pub fn minirootfs_url(mirror: &str) -> String {
    format!("{mirror}/{ALPINE_BRANCH}/releases/x86_64/alpine-minirootfs-{ALPINE_VERSION}-x86_64.tar.gz")
}

/// apk's repositories on `mirror`.
pub fn repositories(mirror: &str) -> String {
    format!("{mirror}/{ALPINE_BRANCH}/main\n{mirror}/{ALPINE_BRANCH}/community\n")
}

/// Check the tarball against the pin.
pub fn verify(tarball: &[u8]) -> Result<(), String> {
    let sum = slate_hash::hex(&slate_hash::sha256(tarball));
    if sum != ALPINE_SHA256 {
        return Err(format!("the minirootfs's SHA-256 is {sum}, not the pinned {ALPINE_SHA256}"));
    }
    Ok(())
}

/// Unpack the minirootfs into `root`.
fn unpack(s: &Setup) -> Result<(), String> {
    let mirror = s.mirror.as_deref().unwrap_or(DEFAULT_MIRROR);
    let url = s.from.clone().unwrap_or_else(|| minirootfs_url(mirror));
    println!("slate-linux: fetching {url}");
    // quarry's fetch reads http:// URLs and local files.
    let tarball = slate_quarry::fetch(&url)?;
    verify(&tarball)?;
    let (tar, _) = slate_flate::gunzip(&tarball).map_err(|e| format!("the minirootfs: {e:?}"))?;
    let entries = slate_tar::entries(&tar).map_err(|e| format!("the minirootfs: {e:?}"))?;
    println!("slate-linux: unpacking Alpine {ALPINE_VERSION} ({} files) into {}", entries.len(), s.root);
    let o = slate_coreutils::archive::ExtractOptions { same_owner: true, same_permissions: true, verbose: false };
    let failed = slate_coreutils::archive::extract_bytes(&tar, s.root.as_bytes(), &o);
    if failed > 0 {
        return Err(format!("{failed} files of the minirootfs could not be unpacked"));
    }
    Ok(())
}

/// Where setup says how far it is, for the windows that wait on it (App
/// Center, the Web Browser): one line, `STAGE STEP STEPS TEXT`, replaced
/// whole as it goes, removed at the end. Stages: `base` (Alpine's base
/// fetched and unpacked), `lists` (apk's indexes), `packages` (STEP of
/// STEPS, TEXT the package), `finishing` (apk's triggers).
pub const PROGRESS: &str = "/run/slate-linux-progress";

/// Say how far setup is.
fn note(stage: &str, step: usize, steps: usize, text: &str) {
    let tmp = format!("{PROGRESS}.new");
    let line = format!("{stage} {step} {steps} {}\n", text.replace('\n', " "));
    if fs::write_file(tmp.as_bytes(), line.as_bytes(), 0o644).is_ok() {
        let _ = fs::rename(tmp.as_bytes(), PROGRESS.as_bytes());
    }
}

/// What a line of apk's says of how far it is: `(3/159) Installing mesa
/// (25.1.9-r0)` is a package (step, steps, name), `Executing x.trigger`
/// the finishing.
pub fn apk_step(line: &str) -> Option<(&'static str, usize, usize, String)> {
    if let Some(rest) = line.strip_prefix('(')
        && let Some((count, what)) = rest.split_once(") ")
        && let Some((n, of)) = count.split_once('/')
        && let (Ok(n), Ok(of)) = (n.parse(), of.parse())
    {
        let name = what.split_whitespace().nth(1).unwrap_or("");
        return Some(("packages", n, of, String::from(name)));
    }
    let trigger = line.strip_prefix("Executing ")?.strip_suffix(".trigger")?;
    // `fontconfig-2.15.0-r3`: the package's name, without its version.
    let name = trigger.rsplitn(3, '-').nth(2).unwrap_or(trigger);
    Some(("finishing", 0, 0, String::from(name)))
}

/// Run `argv` in the runtime, as root, with /dev and /proc; Ok when it
/// succeeds.
fn in_runtime(root: &str, argv: &[&str]) -> Result<(), String> {
    in_runtime_lines(root, argv, |_| {})
}

/// [`in_runtime`], each line it writes to standard output passed on and
/// shown to `line`.
fn in_runtime_lines(root: &str, argv: &[&str], mut line: impl FnMut(&str)) -> Result<(), String> {
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("a pipe: {e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 1);
            let r = (|| -> Result<(), String> {
                process::unshare(process::CLONE_NEWNS).map_err(|e| format!("a mount namespace: {e}"))?;
                let m = |src: &str, at: &str, fstype: &str, flags: usize| {
                    fs::mount(src.as_bytes(), at.as_bytes(), fstype.as_bytes(), flags, b"")
                        .map_err(|e| format!("mounting {at}: {e}"))
                };
                m("/dev", &format!("{root}/dev"), "", fs::MS_BIND | fs::MS_REC)?;
                m("proc", &format!("{root}/proc"), "proc", 0)?;
                fs::chroot(root.as_bytes()).map_err(|e| format!("entering {root}: {e}"))?;
                let _ = fs::chdir(b"/");
                let args: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
                let env = [b"PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_vec(), b"HOME=/root".to_vec()];
                Err(format!("{}: {}", argv[0], process::execve(argv[0].as_bytes(), &args, &env)))
            })();
            if let Err(e) = r {
                slate_rt::eprintln!("slate-linux: {e}");
            }
            process::exit_now(127)
        }
        Ok(pid) => {
            let _ = slate_rt::io::close(w);
            let mut pending: Vec<u8> = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = slate_rt::io::read(r, &mut buf) {
                if n == 0 {
                    break;
                }
                let _ = slate_rt::io::write_all(1, &buf[..n]);
                pending.extend_from_slice(&buf[..n]);
                while let Some(at) = pending.iter().position(|&b| b == b'\n') {
                    let l: Vec<u8> = pending.drain(..=at).collect();
                    line(slate_rt::lossy(&l).trim_end());
                }
            }
            let _ = slate_rt::io::close(r);
            match process::wait(pid, 0) {
                Ok((_, 0)) => Ok(()),
                Ok((_, st)) => Err(format!("{} failed (status {st:#x})", argv.join(" "))),
                Err(e) => Err(format!("waiting for {}: {e}", argv[0])),
            }
        }
        Err(e) => {
            let _ = slate_rt::io::close(r);
            let _ = slate_rt::io::close(w);
            Err(format!("starting {}: {e}", argv[0]))
        }
    }
}

/// `upgrade`'s command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Upgrade {
    pub root: String,
    pub branch: Option<String>,
    pub simulate: bool,
}

pub fn parse_upgrade(args: &[String]) -> Result<Upgrade, String> {
    let mut u = Upgrade { root: String::from(DEFAULT_ROOT), branch: None, simulate: false };
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let value = || args.get(i + 1).cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--root" => u.root = value()?,
            "--branch" => {
                let b = value()?;
                // An Alpine branch: v3.22, or edge.
                let ok = b == "edge"
                    || b.strip_prefix('v').is_some_and(|v| {
                        let mut parts = v.split('.');
                        parts.next().is_some_and(|m| m.parse::<u32>().is_ok())
                            && parts.next().is_some_and(|m| m.parse::<u32>().is_ok())
                            && parts.next().is_none()
                    });
                if !ok {
                    return Err(format!("{b} is not an Alpine branch (like v3.23, or edge)"));
                }
                u.branch = Some(b);
            }
            "--simulate" => {
                u.simulate = true;
                i += 1;
                continue;
            }
            o => {
                return Err(format!(
                    "unknown argument {o}\nusage: slate-linux upgrade [--root DIR] [--branch vX.Y] [--simulate]"
                ));
            }
        }
        i += 2;
    }
    Ok(u)
}

/// apk's repositories with their branch (the path part after the mirror,
/// `v3.22` or `edge`) changed to `branch`.
pub fn with_branch(repositories: &str, branch: &str) -> String {
    let mut out = String::new();
    for line in repositories.lines() {
        let words: Vec<&str> = line.split('/').collect();
        let at = words.iter().position(|w| *w == "edge" || (w.starts_with('v') && w[1..].contains('.')));
        match at {
            Some(i) if !line.trim_start().starts_with('#') => {
                let mut w = words.clone();
                w[i] = branch;
                out.push_str(&w.join("/"));
            }
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

/// The runtime's subvolume, and its state before the last upgrade.
pub const SUBVOL: &str = "linux";
pub const BEFORE: &str = "linux.before";
/// Where subvolumes are mounted for a moment.
const SCRATCH: &str = "/run/slate-linux";

/// The SlateFS mounts in /proc/mounts' text: (where, device).
fn slatefs_mounts() -> Vec<(String, String)> {
    let text = fs::read_file(b"/proc/mounts").map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split(' ').collect();
            (w.len() > 2 && w[2] == "slatefs").then(|| (w[1].replace("\\040", " "), String::from(w[0])))
        })
        .collect()
}

/// Whether a SlateFS is mounted at `root` itself (the runtime's own
/// subvolume).
fn mounted_at(root: &str) -> bool {
    slatefs_mounts().iter().any(|(at, _)| at == root)
}

/// The mounts in /proc/mounts' text: (where, device, type).
fn mounts() -> Vec<(String, String, String)> {
    let text = fs::read_file(b"/proc/mounts").map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split(' ').collect();
            (w.len() > 2).then(|| (w[1].replace("\\040", " "), String::from(w[0]), String::from(w[2])))
        })
        .collect()
}

/// The mount `path` is on: the longest mount point that holds it.
pub fn mount_of<'a>(mounts: &'a [(String, String, String)], path: &str) -> Option<&'a (String, String, String)> {
    mounts
        .iter()
        .filter(|(at, _, _)| at == "/" || path == at || path.starts_with(&format!("{}/", at.trim_end_matches('/'))))
        .max_by_key(|(at, _, _)| at.len())
}

/// Where `path` really is: its deepest existing folder with links
/// followed (as getcwd(3) sees it there), and the rest as written.
fn real_path(path: &str) -> String {
    let mut existing = path.trim_end_matches('/');
    let mut rest = String::new();
    while !existing.is_empty() && !fs::stat(existing.as_bytes()).is_ok_and(|s| s.mode & fs::S_IFMT == fs::S_IFDIR) {
        let (parent, last) = existing.rsplit_once('/').unwrap_or(("", existing));
        rest = if rest.is_empty() { String::from(last) } else { format!("{last}/{rest}") };
        existing = parent;
    }
    let here = fs::getcwd().ok();
    let real = (fs::chdir(if existing.is_empty() { b"/" } else { existing.as_bytes() }).is_ok())
        .then(|| fs::getcwd().ok().map(|c| String::from(slate_rt::lossy(&c))))
        .flatten();
    if let Some(h) = here {
        let _ = fs::chdir(&h);
    }
    match real {
        Some(r) if rest.is_empty() => r,
        Some(r) => format!("{}/{rest}", r.trim_end_matches('/')),
        None => String::from(path),
    }
}

/// Whether the runtime at `root` can have subvolumes of its own: it is
/// on the root file system's SlateFS (not a disk of its own, nor reached
/// through a link to one).
fn on_root_slatefs(root: &str) -> bool {
    let m = mounts();
    let real = real_path(root);
    match (mount_of(&m, "/"), mount_of(&m, &real)) {
        (Some(r), Some(here)) => r.2 == "slatefs" && here.2 == "slatefs" && here.1 == r.1,
        _ => false,
    }
}

/// The free space a new runtime asks for (MiB): its packages take about
/// 400 MiB, and Flatpak's runtimes and apps come after.
pub const NEED_MIB: u64 = 1024;

/// The space free where `root` would be (MiB; all of it: setup runs as
/// root).
fn free_mib(root: &str) -> Option<u64> {
    let real = real_path(root);
    let mut at = real.as_str();
    loop {
        if let Ok(s) = fs::statfs(at.as_bytes()) {
            return Some(s.free.saturating_mul(s.block_size.max(0) as u64) >> 20);
        }
        at = at.rsplit_once('/').map(|(p, _)| if p.is_empty() { "/" } else { p })?;
        if at == "/" {
            return fs::statfs(b"/").ok().map(|s| s.free.saturating_mul(s.block_size.max(0) as u64) >> 20);
        }
    }
}

/// Refuse a new runtime that can't fit, before fetching anything.
pub fn room_for(free: Option<u64>) -> Result<(), String> {
    match free {
        Some(f) if f < NEED_MIB => Err(format!(
            "the Linux runtime needs about {} GB of free space, and this disk has {} MB free",
            NEED_MIB / 1024,
            f
        )),
        _ => Ok(()),
    }
}

/// Whether the root file system has subvolume `name`; None when it isn't
/// SlateFS.
fn has_subvol(name: &str) -> Option<bool> {
    slate_rt::subvol::list().ok().map(|l| l.iter().any(|s| s.name == name))
}

/// Remove `path` and everything in it (links not followed).
fn remove_tree(path: &str) -> Result<(), String> {
    let st = fs::lstat(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    if st.mode & fs::S_IFMT == fs::S_IFDIR {
        for e in fs::read_dir(path.as_bytes()).map_err(|e| format!("{path}: {e}"))? {
            remove_tree(&format!("{path}/{}", slate_rt::lossy(&e.name)))?;
        }
        fs::rmdir(path.as_bytes()).map_err(|e| format!("{path}: {e}"))
    } else {
        fs::unlink(path.as_bytes()).map_err(|e| format!("{path}: {e}"))
    }
}

/// Mount subvolume `name` at a scratch folder for a moment: its path.
fn scratch(name: &str) -> Result<String, String> {
    let at = format!("{SCRATCH}.{name}");
    let _ = fs::mkdir(at.as_bytes(), 0o700);
    slate_rt::subvol::mount(name, &at)?;
    Ok(at)
}

fn unscratch(at: &str) {
    let _ = fs::umount(at.as_bytes());
    let _ = fs::rmdir(at.as_bytes());
}

/// Put the runtime at `root` on its own subvolume, once: Ok(false) when
/// the root isn't SlateFS (the runtime stays a folder, upgraded in
/// place).
pub fn adopt(root: &str) -> Result<bool, String> {
    if mounted_at(root) {
        return Ok(true);
    }
    // Elsewhere (another disk, or a link to one) it stays a folder there.
    if !on_root_slatefs(root) {
        return Ok(false);
    }
    let Some(made) = has_subvol(SUBVOL) else { return Ok(false) };
    let _ = fs::mkdir(root.as_bytes(), 0o755);
    let empty = fs::read_dir(root.as_bytes()).map(|e| e.is_empty()).unwrap_or(true);
    if !made && empty {
        // A new runtime: an empty subvolume.
        slate_rt::subvol::ctl("/", &format!("create {SUBVOL}"))?;
    } else if !made {
        println!("slate-linux: moving the runtime in {root} onto a subvolume of its own (once)");
        // A snapshot of the subvolume it is on shares its blocks: then
        // everything but the runtime goes from it, and the runtime moves
        // to its top (renames, in one subvolume).
        let (on, _) = slatefs_mounts()
            .into_iter()
            .filter(|(at, _)| at == "/" || root.starts_with(&format!("{at}/")))
            .max_by_key(|(at, _)| at.len())
            .ok_or("the runtime isn't on a SlateFS")?;
        let rel = root.strip_prefix(on.trim_end_matches('/')).unwrap_or(root).trim_start_matches('/');
        let first = rel.split('/').next().unwrap_or("");
        slate_rt::subvol::ctl(root, &format!("snapshot {SUBVOL}"))?;
        let tmp = scratch(SUBVOL)?;
        let r = (|| -> Result<(), String> {
            let aside = format!("{tmp}/.slate-runtime");
            fs::rename(format!("{tmp}/{first}").as_bytes(), aside.as_bytes()).map_err(|e| format!("{e}"))?;
            for e in fs::read_dir(tmp.as_bytes()).map_err(|e| format!("{tmp}: {e}"))? {
                if e.name != b".slate-runtime" {
                    remove_tree(&format!("{tmp}/{}", slate_rt::lossy(&e.name)))?;
                }
            }
            let inside = format!("{aside}{}", rel.strip_prefix(first).unwrap_or(""));
            for e in fs::read_dir(inside.as_bytes()).map_err(|e| format!("{inside}: {e}"))? {
                let n = slate_rt::lossy(&e.name);
                fs::rename(format!("{inside}/{n}").as_bytes(), format!("{tmp}/{n}").as_bytes())
                    .map_err(|e| format!("{n}: {e}"))?;
            }
            remove_tree(&aside)
        })();
        unscratch(&tmp);
        r?;
        // The folder's own copy goes: the subvolume is mounted over it.
        for e in fs::read_dir(root.as_bytes()).map_err(|e| format!("{root}: {e}"))? {
            remove_tree(&format!("{root}/{}", slate_rt::lossy(&e.name)))?;
        }
    }
    slate_rt::subvol::mount(SUBVOL, root)?;
    Ok(true)
}

/// Put back the runtime as it was before the last upgrade.
fn restore(root: &str) -> Result<(), String> {
    if has_subvol(BEFORE) != Some(true) {
        return Err(String::from("there is no runtime from before an upgrade to go back to"));
    }
    fs::umount(root.as_bytes()).map_err(|e| match e {
        slate_rt::Errno::EBUSY => {
            String::from("the runtime is in use: close its programs, then run slate-linux rollback")
        }
        e => format!("{root}: {e}"),
    })?;
    slate_rt::subvol::ctl("/", &format!("delete {SUBVOL}"))?;
    let tmp = scratch(BEFORE)?;
    let r = slate_rt::subvol::ctl(&tmp, &format!("snapshot {SUBVOL}"));
    unscratch(&tmp);
    r?;
    slate_rt::subvol::mount(SUBVOL, root)
}

/// `slate-linux rollback [--root DIR]`: back to the runtime from before
/// the last upgrade.
pub fn rollback(args: &[String]) -> Result<(), String> {
    let root = match args {
        [] => String::from(DEFAULT_ROOT),
        [o, r] if o == "--root" => r.clone(),
        _ => return Err("usage: slate-linux rollback [--root DIR]".into()),
    };
    if !mounted_at(&root) {
        return Err(format!("{root} isn't a runtime on a subvolume of its own (upgrade it once first)"));
    }
    restore(&root)?;
    let release = fs::read_file(format!("{root}/etc/alpine-release").as_bytes()).unwrap_or_default();
    println!("slate-linux: the runtime in {root} is back to Alpine {}", slate_rt::lossy(&release).trim());
    Ok(())
}

/// `slate-linux upgrade`.
pub fn upgrade(args: &[String]) -> Result<(), String> {
    let u = parse_upgrade(args)?;
    let root = u.root.as_str();
    let release = || fs::read_file(format!("{root}/etc/alpine-release").as_bytes()).ok();
    if release().is_none() {
        return Err(format!("{root} has no Linux runtime; make one with slate-linux setup"));
    }
    // On its own subvolume, kept as it is before anything changes.
    let kept = !u.simulate && adopt(root)?;
    if kept {
        if has_subvol(BEFORE) == Some(true) {
            slate_rt::subvol::ctl("/", &format!("delete {BEFORE}"))?;
        }
        slate_rt::subvol::ctl(root, &format!("snapshot {BEFORE} ro"))?;
    } else if !u.simulate {
        println!("slate-linux: the root isn't SlateFS: upgrading in place, with nothing kept to go back to");
    }
    let Some(before) = release() else {
        return Err(format!("{root} has no Linux runtime; make one with slate-linux setup"));
    };
    let before = String::from(slate_rt::lossy(&before).trim());
    println!("slate-linux: the runtime in {root} is Alpine {before}");
    // apk needs the name servers as they are now.
    let resolv = fs::read_file(b"/etc/resolv.conf").unwrap_or_default();
    let at = format!("{root}/etc/resolv.conf");
    let _ = fs::unlink(at.as_bytes());
    fs::write_file(at.as_bytes(), &resolv, 0o644).map_err(|e| format!("{at}: {e}"))?;
    if let Some(b) = &u.branch {
        let at = format!("{root}/etc/apk/repositories");
        let old = fs::read_file(at.as_bytes()).map_err(|e| format!("{at}: {e}"))?;
        let new = with_branch(&slate_rt::lossy(&old), b);
        if u.simulate {
            println!("slate-linux: would use {}", new.trim().replace('\n', ", "));
        } else {
            fs::write_file(at.as_bytes(), new.as_bytes(), 0o644).map_err(|e| format!("{at}: {e}"))?;
            println!("slate-linux: the repositories now name {b}");
        }
    }
    let mut argv = alloc::vec!["/sbin/apk", "upgrade", "--no-progress", "--available"];
    if u.simulate {
        argv.push("--simulate");
    }
    let done = in_runtime(root, &["/sbin/apk", "update", "--no-progress"]).and_then(|()| in_runtime(root, &argv));
    if let Err(e) = done {
        if !kept {
            return Err(e);
        }
        slate_rt::eprintln!("slate-linux: {e}");
        return match restore(root) {
            Ok(()) => Err(format!("the upgrade failed; the runtime in {root} is as it was (Alpine {before})")),
            Err(r) => Err(format!("the upgrade failed, and putting the runtime back did too: {r}")),
        };
    }
    let after = release().map(|r| String::from(slate_rt::lossy(&r).trim())).unwrap_or_default();
    if u.simulate {
        println!("slate-linux: nothing was changed (--simulate)");
    } else {
        println!("slate-linux: the runtime in {root} is up to date: Alpine {after}");
        if kept {
            println!("slate-linux: the runtime before is kept: slate-linux rollback returns to it");
        }
    }
    Ok(())
}

pub fn main(args: &[String]) -> Result<(), String> {
    let s = parse(args)?;
    let r = setup(&s);
    let _ = fs::unlink(PROGRESS.as_bytes());
    r
}

fn setup(s: &Setup) -> Result<(), String> {
    let root = s.root.as_str();
    for d in [root.rsplit_once('/').map_or("", |(p, _)| p), root] {
        if !d.is_empty() {
            let _ = fs::mkdir(d.as_bytes(), 0o755);
        }
    }
    if fs::exists(format!("{root}/etc/alpine-release").as_bytes()) {
        println!("slate-linux: {root} has a runtime already; adding packages");
    } else {
        room_for(free_mib(root))?;
        note("base", 0, 0, "Alpine");
        // A new runtime goes on a subvolume of its own (on SlateFS).
        adopt(root)?;
        unpack(s)?;
    }
    let resolv = fs::read_file(b"/etc/resolv.conf").unwrap_or_default();
    let at = format!("{root}/etc/resolv.conf");
    let _ = fs::unlink(at.as_bytes());
    fs::write_file(at.as_bytes(), &resolv, 0o644).map_err(|e| format!("{at}: {e}"))?;
    // D-Bus, which Firefox asks for, wants the machine's ID (machine-id(5)):
    // the runtime gets one of its own.
    let id = format!("{root}/etc/machine-id");
    if !fs::exists(id.as_bytes()) {
        let mut bytes = [0u8; 16];
        process::random(&mut bytes).map_err(|e| format!("random bytes: {e}"))?;
        let text = format!("{}\n", slate_hash::hex(&bytes));
        fs::write_file(id.as_bytes(), text.as_bytes(), 0o444).map_err(|e| format!("{id}: {e}"))?;
    }
    if let Some(m) = &s.mirror {
        let at = format!("{root}/etc/apk/repositories");
        fs::write_file(at.as_bytes(), repositories(m).as_bytes(), 0o644).map_err(|e| format!("{at}: {e}"))?;
    }
    println!("slate-linux: installing {}", s.packages.join(" "));
    note("lists", 0, 0, "");
    in_runtime(root, &["/sbin/apk", "update", "--no-progress"])?;
    let mut add = alloc::vec!["/sbin/apk", "add", "--no-progress"];
    add.extend(s.packages.iter().map(String::as_str));
    in_runtime_lines(root, &add, |l| {
        if let Some((stage, n, of, name)) = apk_step(l) {
            note(stage, n, of, &name);
        }
    })?;
    println!("slate-linux: the Linux runtime in {root} is ready");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn apk_lines() {
        assert_eq!(apk_step("(34/159) Installing mesa (25.1.9-r0)"), Some(("packages", 34, 159, String::from("mesa"))));
        assert_eq!(apk_step("Executing fontconfig-2.15.0-r3.trigger"), Some(("finishing", 0, 0, "fontconfig".into())));
        assert_eq!(apk_step("Executing gtk-update-icon-cache-3.24.50-r0.trigger").unwrap().3, "gtk-update-icon-cache");
        assert_eq!(apk_step("OK: 398 MiB in 159 packages"), None);
        assert_eq!(apk_step("(x/y) nothing"), None);
    }

    #[test]
    fn mounts_and_room() {
        let m = |at: &str, dev: &str, ty: &str| (String::from(at), String::from(dev), String::from(ty));
        let ms = alloc::vec![
            m("/", "/dev/vda3", "slatefs"),
            m("/var", "/dev/vda3", "slatefs"),
            m("/mnt/workbench", "/dev/vdb", "ext4"),
            m("/mnt/workbench2", "/dev/vdc", "ext4"),
        ];
        assert_eq!(mount_of(&ms, "/var/lib/slate/linux").unwrap().0, "/var");
        assert_eq!(mount_of(&ms, "/mnt/workbench/t4").unwrap().0, "/mnt/workbench");
        assert_eq!(mount_of(&ms, "/mnt/workbench2").unwrap().0, "/mnt/workbench2");
        assert_eq!(mount_of(&ms, "/mnt/workbenchx").unwrap().0, "/");
        assert!(room_for(Some(5000)).is_ok() && room_for(None).is_ok());
        let e = room_for(Some(300)).unwrap_err();
        assert!(e.contains("1 GB") && e.contains("300 MB"), "{e}");
    }

    #[test]
    fn command_lines() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = parse(&a(&[])).unwrap();
        assert_eq!(s.packages, a(DEFAULT_PACKAGES));
        assert_eq!((s.root.as_str(), s.mirror.as_deref()), (DEFAULT_ROOT, None));
        let s = parse(&a(&["--mirror", "http://10.0.2.2:8080/alpine/", "--root", "/w", "foot"])).unwrap();
        assert_eq!(s.mirror.as_deref(), Some("http://10.0.2.2:8080/alpine"));
        assert_eq!((s.root.as_str(), s.packages.clone()), ("/w", a(&["foot"])));
        assert_eq!(
            parse(&a(&["flatpak", "dbus"])).unwrap().packages,
            a(&["flatpak", "dbus", "sway", "xwayland", "font-dejavu"])
        );
        assert!(parse(&a(&["--mirror"])).is_err());
        assert!(parse(&a(&["-x"])).is_err());
        assert_eq!(
            minirootfs_url("http://m/alpine"),
            "http://m/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.6-x86_64.tar.gz"
        );
        assert_eq!(repositories("http://m/alpine"), "http://m/alpine/v3.22/main\nhttp://m/alpine/v3.22/community\n");
        assert!(verify(b"not alpine").is_err());
    }

    #[test]
    fn upgrades() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let u = parse_upgrade(&a(&["--simulate", "--branch", "v3.23"])).unwrap();
        assert_eq!((u.root.as_str(), u.branch.as_deref(), u.simulate), (DEFAULT_ROOT, Some("v3.23"), true));
        assert!(parse_upgrade(&a(&["--branch", "3.23"])).is_err());
        assert!(parse_upgrade(&a(&["--branch", "v3"])).is_err());
        assert!(parse_upgrade(&a(&["--branch", "edge"])).is_ok());
        assert!(parse_upgrade(&a(&["firefox"])).is_err());
        let repos = "http://m/alpine/v3.22/main\nhttp://m/alpine/v3.22/community\n#http://m/alpine/v3.22/testing\n";
        assert_eq!(
            with_branch(repos, "v3.23"),
            "http://m/alpine/v3.23/main\nhttp://m/alpine/v3.23/community\n#http://m/alpine/v3.22/testing\n"
        );
        assert_eq!(with_branch("https://dl/alpine/edge/main\n", "v3.23"), "https://dl/alpine/v3.23/main\n");
    }
}
