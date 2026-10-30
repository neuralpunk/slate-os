// SPDX-License-Identifier: MIT OR Apache-2.0

//! The root file system's contents: the files in `rootfs/`, Slate's own
//! programs (userland/: /bin/coreutils and a link per tool), BusyBox for
//! the tools Slate does not have yet (a test load, ADR 0012), the test
//! programs under /test and the Alpine test load under /alpine. They go into the initramfs (a cpio newc archive) or into
//! a staging directory for the ext4 root partition.

use std::path::{Path, PathBuf};

use slate_cpio::Writer;

use crate::{Result, busybox, root, target_dir};

const DIRS: &[&str] = &[
    "bin", "sbin", "usr", "usr/bin", "usr/sbin", "etc", "root", "tmp", "dev", "proc", "sys", "var", "var/tmp", "home",
    "mnt", "run",
];

/// Where the tree is written.
pub trait Sink {
    fn dir(&mut self, path: &str, perm: u32) -> Result;
    fn file(&mut self, path: &str, perm: u32, data: &[u8]) -> Result;
    fn symlink(&mut self, path: &str, target: &str) -> Result;
}

impl Sink for Writer {
    fn dir(&mut self, path: &str, perm: u32) -> Result {
        Writer::dir(self, path, perm);
        Ok(())
    }
    fn file(&mut self, path: &str, perm: u32, data: &[u8]) -> Result {
        Writer::file(self, path, perm, data);
        Ok(())
    }
    fn symlink(&mut self, path: &str, target: &str) -> Result {
        Writer::symlink(self, path, target);
        Ok(())
    }
}

/// A directory on the host. Directories stay writable while it is filled
/// and get their real permissions at the end (`finish`).
struct Staging(PathBuf, Vec<(PathBuf, u32)>);

impl Staging {
    fn finish(self) -> Result {
        use std::os::unix::fs::PermissionsExt;
        for (p, perm) in self.1.iter().rev() {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(*perm)).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

impl Sink for Staging {
    fn dir(&mut self, path: &str, perm: u32) -> Result {
        let p = self.0.join(path);
        std::fs::create_dir_all(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        self.1.push((p, perm));
        Ok(())
    }
    fn file(&mut self, path: &str, perm: u32, data: &[u8]) -> Result {
        use std::os::unix::fs::PermissionsExt;
        let p = self.0.join(path);
        std::fs::write(&p, data).map_err(|e| format!("{}: {e}", p.display()))?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(perm)).map_err(|e| e.to_string())
    }
    fn symlink(&mut self, path: &str, target: &str) -> Result {
        let p = self.0.join(path);
        let _ = std::fs::remove_file(&p);
        std::os::unix::fs::symlink(target, &p).map_err(|e| format!("{}: {e}", p.display()))
    }
}

/// Add the directory tree under `base/rel` at `prefix/rel`, keeping
/// symlinks and permission bits.
/// Files of rootfs/ whose mode git cannot keep.
const MODES: &[(&str, u32)] = &[("etc/shadow", 0o600)];

fn add_tree(w: &mut dyn Sink, base: &Path, rel: &str, prefix: &str) -> Result {
    use std::os::unix::fs::PermissionsExt;
    let dir = base.join(rel);
    let mut entries: Vec<_> = std::fs::read_dir(&dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
        let dest = if prefix.is_empty() { path.clone() } else { format!("{prefix}/{path}") };
        let meta = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
        let perm = meta.permissions().mode() & 0o7777;
        let perm = if prefix.is_empty() { MODES.iter().find(|(p, _)| *p == path).map_or(perm, |m| m.1) } else { perm };
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(e.path()).map_err(|e| e.to_string())?;
            w.symlink(&dest, &target.to_string_lossy())?;
        } else if meta.is_dir() {
            w.dir(&dest, perm)?;
            add_tree(w, base, &path, prefix)?;
        } else if meta.is_file() {
            w.file(&dest, perm, &std::fs::read(e.path()).map_err(|e| e.to_string())?)?;
        }
    }
    Ok(())
}

/// The fonts Strata loads from /usr/share/fonts/slate, with the OFL texts
/// that must go with them.
const STRATA_FONTS: [&str; 14] = [
    "HostGrotesk-400.ttf",
    "HostGrotesk-500.ttf",
    "HostGrotesk-600.ttf",
    "DMMono-Regular.ttf",
    "DMMono-Medium.ttf",
    "DMMono-Italic.ttf",
    "DMMono-MediumItalic.ttf",
    // The themes' serifs (ADR 0175).
    "InstrumentSerif-Italic.ttf",
    "Fraunces-600.ttf",
    "Fraunces-Italic-400.ttf",
    "OFL-HostGrotesk.txt",
    "OFL-DMMono.txt",
    "OFL-InstrumentSerif.txt",
    "OFL-Fraunces.txt",
];

/// Fill a root tree: Slate itself (ADR 0012: only our code), as the base
/// system's packages install it (ADR 0071), and with a test load also
/// BusyBox, the Alpine minirootfs and the test programs.
fn populate(w: &mut dyn Sink, test_load: Option<&[(String, PathBuf)]>) -> Result {
    crate::basepkg::system()?.emit(w)?;
    let Some(user) = test_load else { return Ok(()) };
    let mut ours = std::collections::HashSet::new();
    for p in crate::userland::build()?.iter().filter(|p| p.system) {
        ours.insert(p.name.clone());
        ours.extend(p.links.iter().cloned());
    }
    populate_test_load(w, user, &ours)
}

/// Slate's own system: the tree the base system's packages are made of.
/// The guides in the image: (in the checkout, in /usr/share/doc/slate/guides).
const GUIDES: &[(&str, &str)] =
    &[("guides/getting-started.md", "getting-started.md"), ("guides/INSTALL.md", "installing.md")];

pub fn populate_system(w: &mut dyn Sink) -> Result {
    let own = crate::userland::build()?;
    for d in DIRS {
        // The temporary directories are sticky and open to all (FHS 3.0
        // §3.18 and §5.15: /tmp and /var/tmp).
        w.dir(d, if *d == "tmp" || *d == "var/tmp" { 0o1777 } else { 0o755 })?;
    }
    add_tree(w, &root().join("rootfs"), "", "")?;
    for d in ["usr/lib", "usr/lib/slate"] {
        w.dir(d, 0o755)?;
    }
    for p in own.iter().filter(|p| p.system) {
        w.file(&format!("{}/{}", p.dir, p.name), p.mode, &std::fs::read(&p.path).map_err(|e| e.to_string())?)?;
        for tool in &p.links {
            w.symlink(&format!("bin/{tool}"), &p.name)?;
        }
    }
    // Strata's fonts and their licences (ADR 0037).
    for d in ["usr/share", "usr/share/fonts", "usr/share/fonts/slate"] {
        w.dir(d, 0o755)?;
    }
    for f in STRATA_FONTS {
        let data = std::fs::read(root().join("assets/fonts").join(f)).map_err(|e| format!("{f}: {e}"))?;
        w.file(&format!("usr/share/fonts/slate/{f}"), 0o644, &data)?;
    }
    // quarry trusts this checkout's development key (ADR 0025), from the
    // system image (ADR 0090).
    for d in ["usr/share/quarry", "usr/share/quarry/keys"] {
        w.dir(d, 0o755)?;
    }
    w.file("usr/share/quarry/keys/dev.pub", 0o644, &crate::quarry::dev_public_key()?)?;
    // Which release this is (the base package's version).
    w.dir("usr/share/slate", 0o755)?;
    w.file("usr/share/slate/release", 0o644, format!("Slate {}\n", crate::basepkg::version()).as_bytes())?;
    // The user guides the Help app shows (ADR 0104).
    for d in ["usr/share/doc", "usr/share/doc/slate", "usr/share/doc/slate/guides"] {
        w.dir(d, 0o755)?;
    }
    for (from, to) in GUIDES {
        let data = std::fs::read(root().join(from)).map_err(|e| format!("{from}: {e}"))?;
        w.file(&format!("usr/share/doc/slate/guides/{to}"), 0o644, &data)?;
    }
    Ok(())
}

/// The test load, over the system.
fn populate_test_load(
    w: &mut dyn Sink,
    user: &[(String, PathBuf)],
    ours: &std::collections::HashSet<String>,
) -> Result {
    // Test runs keep off the internet's clocks (scenarios that test NTP
    // name their own server); the later file wins.
    w.file("etc/slate/ntp", 0o644, TEST_NTP)?;
    // Test load: the Alpine minirootfs (dynamically linked, musl), for
    // chroot and dynamic-linking tests, and BusyBox for the tools Slate
    // does not have yet.
    w.dir("alpine", 0o755)?;
    add_tree(w, &crate::alpine::fetch()?, "", "alpine")?;
    w.dir("test", 0o755)?;
    let bb = busybox::fetch()?;
    w.file("bin/busybox", 0o755, &std::fs::read(&bb).map_err(|e| e.to_string())?)?;
    for applet in busybox::applets()? {
        // Slate's own tool wins wherever it has one.
        let base = applet.rsplit('/').next().unwrap_or(&applet);
        if applet != "bin/busybox" && !ours.contains(base) {
            w.symlink(&applet, "/bin/busybox")?;
        }
    }
    for (name, path) in user {
        w.file(&format!("test/{name}"), 0o755, &std::fs::read(path).map_err(|e| e.to_string())?)?;
    }
    // Slate's own test programs (wl-probe).
    for p in crate::userland::build()?.iter().filter(|p| p.dir == "test") {
        w.file(&format!("test/{}", p.name), p.mode, &std::fs::read(&p.path).map_err(|e| e.to_string())?)?;
    }
    // A signed copy of a native test program (ADR 0090): it runs in the
    // Slate domain from /test, where the unsigned one runs in the Linux
    // domain.
    // Another holds the JIT permission (ADR 0093).
    if let Some((_, path)) = user.iter().find(|(n, _)| n == "native-abi") {
        let program = std::fs::read(path).map_err(|e| e.to_string())?;
        let key = crate::quarry::dev_secret()?;
        w.dir("test/signed", 0o755)?;
        w.file("test/signed/native-abi", 0o755, &slate_elfsign::sign(&program, slate_elfsign::ANYWHERE, &key))?;
        let jit = slate_elfsign::sign(&program, slate_elfsign::ANYWHERE | slate_elfsign::JIT, &key);
        w.file("test/signed/native-abi-jit", 0o755, &jit)?;
    }
    let shell_dir = root().join("tests/shell");
    let mut scripts: Vec<_> =
        std::fs::read_dir(&shell_dir).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    scripts.sort_by_key(|e| e.file_name());
    for e in scripts {
        let name = e.file_name().to_string_lossy().into_owned();
        w.file(&format!("test/{name}"), 0o755, &std::fs::read(e.path()).map_err(|e| e.to_string())?)?;
    }
    // The LTP subset (ADR 0047) and its runner.
    w.dir("test/ltp", 0o755)?;
    let mut list = String::new();
    for (name, path, helper) in crate::ltp::build()? {
        w.file(&format!("test/ltp/{name}"), 0o755, &std::fs::read(&path).map_err(|e| e.to_string())?)?;
        if !helper {
            list.push_str(&name);
            list.push('\n');
        }
    }
    w.file("test/ltp/LIST", 0o644, list.as_bytes())?;
    let runner = std::fs::read(root().join("tests/ltp/run.sh")).map_err(|e| e.to_string())?;
    w.file("test/ltp.sh", 0o755, &runner)?;
    // quarry's test repositories (served by xtask, also over HTTPS with a
    // test authority the image trusts) and packages to refuse.
    crate::quarry::test_repos()?;
    if let Some(tls) = crate::quarry::test_tls()? {
        let ca = std::fs::read(tls.join("ca.pem")).map_err(|e| e.to_string())?;
        w.file("etc/ssl/certs/slate-test-ca.pem", 0o644, &ca)?;
    }
    w.dir("test/quarry", 0o755)?;
    for (name, data) in crate::quarry::rejects()? {
        w.file(&format!("test/quarry/{name}"), 0o644, &data)?;
    }
    Ok(())
}

/// The installed system alone (no test load, no installer) as a cpio
/// archive: the install media's payload (ADR 0029).
pub fn system_archive() -> Result<Vec<u8>> {
    let mut w = Writer::new();
    populate(&mut w, None)?;
    Ok(w.finish())
}

/// Drops the paths that the live system replaces.
struct Except<'a> {
    inner: &'a mut Writer,
    skip: &'a [&'a str],
}

impl Sink for Except<'_> {
    fn dir(&mut self, path: &str, perm: u32) -> Result {
        Sink::dir(self.inner, path, perm)
    }
    fn file(&mut self, path: &str, perm: u32, data: &[u8]) -> Result {
        if self.skip.contains(&path) { Ok(()) } else { Sink::file(self.inner, path, perm, data) }
    }
    fn symlink(&mut self, path: &str, target: &str) -> Result {
        Sink::symlink(self.inner, path, target)
    }
}

/// The install media's initramfs: the system, with rootfs-live/'s files
/// over it (the console runs the installer), the installers, and `extra`
/// files (the payload under /install).
pub fn live_archive(extra: &[(&str, u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let live = root().join("rootfs-live");
    let mut overlay = Vec::new();
    collect(&live, "", &mut overlay)?;
    let skip: Vec<&str> = overlay.iter().map(|(p, _)| p.as_str()).collect();
    let mut w = Writer::new();
    populate(&mut Except { inner: &mut w, skip: &skip }, None)?;
    for (path, data) in &overlay {
        w.file(path, 0o644, data);
    }
    let built = crate::userland::build()?;
    for name in ["slate-install", "slate-install-gui"] {
        let p = built.iter().find(|p| p.name == name).ok_or_else(|| format!("no {name}"))?;
        w.file(&format!("bin/{name}"), 0o755, &std::fs::read(&p.path).map_err(|e| e.to_string())?);
    }
    // The live system has MediaTek's Bluetooth firmware, so a Bluetooth
    // mouse works there (ADR 0176; installs take it only on machines
    // with such a controller).
    let bt: Vec<(String, u32, Vec<u8>)> =
        crate::btfw::files().unwrap_or_default().into_iter().map(|(p, d)| (p, 0o644, d)).collect();
    let bt: Vec<(&str, u32, Vec<u8>)> = bt.iter().map(|(p, m, d)| (p.as_str(), *m, d.clone())).collect();
    let mut made = std::collections::HashSet::new();
    for (path, mode, data) in extra.iter().chain(bt.iter()) {
        if let Some((dir, _)) = path.rsplit_once('/') {
            let mut at = String::new();
            for part in dir.split('/') {
                at = if at.is_empty() { part.to_string() } else { format!("{at}/{part}") };
                if made.insert(at.clone()) {
                    w.dir(&at, 0o755);
                }
            }
        }
        w.file(path, *mode, data);
    }
    Ok(w.finish())
}

/// Every file under `base/rel`, with its path relative to `base`.
fn collect(base: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) -> Result {
    let mut entries: Vec<_> =
        std::fs::read_dir(base.join(rel)).map_err(|e| e.to_string())?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
        if e.path().is_dir() {
            collect(base, &path, out)?;
        } else {
            out.push((path, std::fs::read(e.path()).map_err(|e| e.to_string())?));
        }
    }
    Ok(())
}

/// `/etc/slate/ntp` in test images: no servers, so netd leaves the clock
/// alone (ADR 0052 §3).
pub const TEST_NTP: &[u8] = b"# Test image: no time servers (scenarios that test NTP name their own).\n";

/// Build `target/initramfs.cpio` (with the test load) and return its path.
pub fn build(user: &[(String, PathBuf)]) -> Result<PathBuf> {
    // One per run: every caller passes the test programs of user::build.
    static BUILT: std::sync::OnceLock<Result<PathBuf>> = std::sync::OnceLock::new();
    crate::once(&BUILT, || build_now(user))
}

fn build_now(user: &[(String, PathBuf)]) -> Result<PathBuf> {
    let mut w = Writer::new();
    populate(&mut w, Some(user))?;
    let out = target_dir().join("initramfs.cpio");
    std::fs::write(&out, w.finish()).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Fill `target/rootfs-stage` for the ext4 root: Slate alone, or with
/// the test load.
pub fn stage(test_load: Option<&[(String, PathBuf)]>) -> Result<PathBuf> {
    let dir = target_dir().join("rootfs-stage");
    if dir.exists() {
        // Make everything writable again so it can be removed.
        let _ = std::process::Command::new("chmod").args(["-R", "u+w"]).arg(&dir).status();
        std::fs::remove_dir_all(&dir).map_err(|e| format!("removing {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut st = Staging(dir.clone(), Vec::new());
    populate(&mut st, test_load)?;
    st.finish()?;
    Ok(dir)
}
