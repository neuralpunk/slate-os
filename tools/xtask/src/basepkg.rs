// SPDX-License-Identifier: MIT OR Apache-2.0

//! The base system as packages (M21 phase 6, ADR 0071). Slate's own tree
//! (`initramfs::populate_system`) is split into four signed packages:
//! `slate-desktop`, Strata and what only it uses; `slate-apps`, Slate's
//! apps for Strata (ADR 0104); `ca-certificates`, Mozilla's certificate
//! authorities, versioned by Mozilla's date so that a newer list can be
//! updated on its own (ADR 0072's addendum); and `slate-base`, everything
//! else. Every
//! image is that tree plus quarry's record of the packages, so an
//! installed system knows what it is made of and can upgrade, roll back,
//! and add or remove Strata and its apps. It also carries `slate-desktop`
//! and `slate-apps` in a repository of its own (/var/lib/quarry/install),
//! so they come back without a network.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use slate_qpkg::{Abi, Dep, Entry, Kind, Manifest, archive, index};

use crate::initramfs::Sink;
use crate::{Result, target_dir};

/// Strata's paths: the desktop package's files (and everything under
/// these directories).
const DESKTOP: &[&str] = &[
    "bin/strata",
    "bin/strata-keys",
    "bin/strata-settings",
    "bin/strata-login",
    "bin/terminal",
    "bin/slate-linux-app",
    "usr/lib/slate/strata-wl",
    "usr/share/fonts/slate",
    "usr/share/strata",
];

/// Where quarry keeps its record of installed packages (ADR 0069).
const DB: &str = "usr/lib/quarry/db";
/// The repository every system carries.
const MEDIA_REPO: &str = "var/lib/quarry/install";

/// The apps' paths (ADR 0104): their programs, launcher entries and
/// guides; the games' too (ADR 0177).
const APPS: &[&str] = &[
    "bin/calculator",
    "bin/clock",
    "bin/slate-help",
    "bin/image-viewer",
    "bin/archive-manager",
    "bin/text-editor",
    "bin/files",
    "bin/calendar",
    "bin/contacts",
    "bin/system-monitor",
    "bin/disks",
    "bin/software-updater",
    "bin/web-browser",
    "bin/app-center",
    "bin/solitaire",
    "bin/mines",
    "usr/share/strata/apps/calculator.app",
    "usr/share/strata/apps/solitaire.app",
    "usr/share/strata/apps/mines.app",
    "usr/share/strata/apps/images.app",
    "usr/share/strata/apps/archives.app",
    "usr/share/strata/apps/editor.app",
    "usr/share/strata/apps/files.app",
    "usr/share/strata/apps/calendar.app",
    "usr/share/strata/apps/contacts.app",
    "usr/share/strata/apps/clock.app",
    "usr/share/strata/apps/help.app",
    "usr/share/strata/apps/monitor.app",
    "usr/share/strata/apps/disks.app",
    "usr/share/strata/apps/updater.app",
    "usr/share/strata/apps/browser.app",
    "usr/share/strata/apps/appcenter.app",
    "usr/share/doc/slate/guides",
];

/// The certificate authorities' package's file.
const CA_BUNDLE: &str = "etc/ssl/certs/ca-certificates.crt";

fn is_ca(path: &str) -> bool {
    path == CA_BUNDLE
}

/// The certificate authorities' version: the date of Mozilla's data,
/// from the bundle's header ("Certificate data from Mozilla as of: Tue
/// Oct 20 13:32:40 2026 GMT" is 2026.10.20).
pub fn ca_version(bundle: &str) -> Option<String> {
    let line = bundle.lines().find_map(|l| l.split_once("Certificate data from Mozilla as of:"))?.1;
    let w: Vec<&str> = line.split_whitespace().collect();
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let (month, day, year) = match w[..] {
        [_, m, d, _, y, ..] => {
            (months.iter().position(|x| *x == m)? + 1, d.parse::<u32>().ok()?, y.parse::<u32>().ok()?)
        }
        _ => return None,
    };
    Some(format!("{year}.{month:02}.{day:02}"))
}

fn under(list: &[&str], path: &str) -> bool {
    list.iter().any(|p| path == *p || path.strip_prefix(p).is_some_and(|r| r.starts_with('/')))
}

fn is_apps(path: &str) -> bool {
    under(APPS, path)
}

fn is_desktop(path: &str) -> bool {
    !is_apps(path) && under(DESKTOP, path)
}

/// Paths in other subvolumes (ADR 0027): not the system's to package.
fn outside_system(path: &str) -> bool {
    path.starts_with("var/") || path.starts_with("home/")
}

/// The base packages' version: the workspace's, with the number of
/// commits so that later builds upgrade earlier ones.
pub fn version() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| {
        let n = std::process::Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(crate::root())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "0".into());
        format!("{}-{n}", env!("CARGO_PKG_VERSION"))
    })
}

/// One node of the tree, in the order it was written (a later one with
/// the same path replaces an earlier one, as initramfs unpacking does).
#[derive(Clone, Debug)]
struct Node {
    path: String,
    kind: Kind,
    mode: u32,
    data: Vec<u8>,
}

#[derive(Default)]
struct Collector {
    nodes: Vec<Node>,
    at: BTreeMap<String, usize>,
}

impl Collector {
    fn put(&mut self, n: Node) {
        match self.at.get(&n.path) {
            Some(&i) => self.nodes[i] = n,
            None => {
                self.at.insert(n.path.clone(), self.nodes.len());
                self.nodes.push(n);
            }
        }
    }
}

impl Sink for Collector {
    fn dir(&mut self, path: &str, perm: u32) -> Result {
        self.put(Node { path: path.into(), kind: Kind::Dir, mode: perm, data: Vec::new() });
        Ok(())
    }
    fn file(&mut self, path: &str, perm: u32, data: &[u8]) -> Result {
        self.put(Node { path: path.into(), kind: Kind::File, mode: perm, data: data.to_vec() });
        Ok(())
    }
    fn symlink(&mut self, path: &str, target: &str) -> Result {
        self.put(Node { path: path.into(), kind: Kind::Symlink, mode: 0o777, data: target.as_bytes().to_vec() });
        Ok(())
    }
}

/// A built package.
pub struct Built {
    pub manifest: Manifest,
    entries: Vec<Entry>,
    pub qpk: Vec<u8>,
}

impl Built {
    fn new(manifest: Manifest, entries: Vec<Entry>) -> Result<Built> {
        let key = crate::quarry::dev_secret()?;
        let mut manifest = manifest;
        manifest.installed_size = entries.iter().map(|e| e.data.len() as u64).sum();
        let qpk = archive::write(&manifest, &entries, &key).map_err(|e| format!("{}: {e}", manifest.id()))?;
        Ok(Built { manifest, entries, qpk })
    }

    /// quarry's record of the package as installed (ADR 0069): kind
    /// (`c` configuration), mode, SHA-256 and path of each entry.
    fn files_record(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            let (kind, sha) = match e.kind {
                Kind::Dir => ('d', "-".to_string()),
                Kind::Symlink => ('l', "-".to_string()),
                Kind::File => {
                    let c = if self.manifest.config.contains(&e.path) { 'c' } else { 'f' };
                    (c, slate_hash::hex(&slate_hash::sha256(&e.data)))
                }
            };
            let mode = if e.kind == Kind::Symlink { 0o777 } else { e.mode };
            s.push_str(&format!("{kind} {mode:o} {sha} {}\n", e.path));
        }
        s
    }

    /// The index entry for this package stored as `file`.
    fn indexed(&self, file: &str) -> Manifest {
        let mut m = self.manifest.clone();
        m.file = file.into();
        m.size = self.qpk.len() as u64;
        m.sha256 = slate_hash::hex(&slate_hash::sha256(&self.qpk));
        m
    }
}

/// The system and its packages, made once per run.
pub struct System {
    tree: Vec<Node>,
    pub base: Built,
    pub desktop: Built,
    pub apps: Built,
    pub ca: Built,
    /// AMD's firmware for full graphics (ADR 0173), in the media's
    /// repository only, when the build machine has it.
    pub firmware: Option<Built>,
    /// MediaTek's Bluetooth firmware (ADR 0176), in the media's repository
    /// (and on its live system), when the build machine has it.
    pub firmware_bt: Option<Built>,
}

pub fn system() -> Result<&'static System> {
    static S: OnceLock<std::result::Result<System, String>> = OnceLock::new();
    S.get_or_init(build).as_ref().map_err(Clone::clone)
}

fn manifest(name: &str, summary: &str) -> Manifest {
    let mut m = Manifest::new(name, version());
    m.arch = "x86_64".into();
    m.abi = Abi::Slate;
    m.summary = summary.into();
    m.license = "MIT OR Apache-2.0".into();
    m
}

fn entry(n: &Node) -> Entry {
    Entry { path: n.path.clone(), kind: n.kind, mode: n.mode, data: n.data.clone() }
}

fn build() -> Result<System> {
    let mut c = Collector::default();
    crate::initramfs::populate_system(&mut c)?;
    let packaged = || c.nodes.iter().filter(|n| !outside_system(&n.path));
    let base_entries: Vec<Entry> =
        packaged().filter(|n| !is_desktop(&n.path) && !is_apps(&n.path) && !is_ca(&n.path)).map(entry).collect();
    let ca_entries: Vec<Entry> = packaged().filter(|n| is_ca(&n.path)).map(entry).collect();
    let bundle = ca_entries.first().map(|e| String::from_utf8_lossy(&e.data).into_owned()).unwrap_or_default();
    let ca_version =
        ca_version(&bundle).ok_or(format!("{CA_BUNDLE}: no \"Certificate data from Mozilla as of\" date"))?;
    let desktop_entries: Vec<Entry> = packaged().filter(|n| is_desktop(&n.path)).map(entry).collect();
    let apps_entries: Vec<Entry> = packaged().filter(|n| is_apps(&n.path)).map(entry).collect();
    // Not configuration: a newer list replaces it. An administrator's own
    // authorities go beside it (any *.pem in /etc/ssl/certs, ADR 0072).
    let mut ca = manifest("ca-certificates", "Mozilla's certificate authorities, as curl publishes them");
    ca.version = ca_version.clone();
    ca.license = "MPL-2.0".into();
    ca.essential = true;
    let mut base = manifest("slate-base", "Slate's base system");
    base.essential = true;
    base.depends = vec![Dep::parse(&format!("ca-certificates (>= {ca_version})")).map_err(|e| e.to_string())?];
    // The system's settings are the administrator's to change (ADR 0069).
    base.config = base_entries
        .iter()
        .filter(|e| e.kind == Kind::File && e.path.starts_with("etc/"))
        .map(|e| e.path.clone())
        .collect();
    let mut desktop = manifest("slate-desktop", "Strata, Slate's desktop");
    desktop.depends = vec![Dep::parse(&format!("slate-base (>= {})", version())).map_err(|e| e.to_string())?];
    let mut apps = manifest("slate-apps", "Slate's apps for Strata, and its system tools");
    apps.depends = vec![Dep::parse(&format!("slate-desktop (>= {})", version())).map_err(|e| e.to_string())?];
    let firmware = match crate::gpufw::files() {
        Some(files) => {
            let mut m = manifest("slate-firmware-gpu", "AMD's firmware for full graphics on AMD cards (ADR 0173)");
            m.license = "LicenseRef-amdgpu".into();
            m.depends = vec![Dep::parse(&format!("slate-base (>= {})", version())).map_err(|e| e.to_string())?];
            let mut entries = Vec::new();
            for d in [
                "lib",
                "lib/firmware",
                "lib/firmware/amdgpu",
                "usr",
                "usr/share",
                "usr/share/licenses",
                "usr/share/licenses/slate-firmware-gpu",
            ] {
                entries.push(Entry { path: d.into(), kind: Kind::Dir, mode: 0o755, data: Vec::new() });
            }
            for (path, data) in files {
                entries.push(Entry { path, kind: Kind::File, mode: 0o644, data });
            }
            Some(Built::new(m, entries)?)
        }
        None => None,
    };
    let firmware_bt = match crate::btfw::files() {
        Some(files) => {
            let mut m = manifest("slate-firmware-bt", "MediaTek's firmware for their Bluetooth controllers (ADR 0176)");
            m.license = "LicenseRef-mediatek".into();
            m.depends = vec![Dep::parse(&format!("slate-base (>= {})", version())).map_err(|e| e.to_string())?];
            let mut entries: Vec<Entry> = crate::btfw::DIRS
                .iter()
                .map(|d| Entry { path: (*d).into(), kind: Kind::Dir, mode: 0o755, data: Vec::new() })
                .collect();
            for (path, data) in files {
                entries.push(Entry { path, kind: Kind::File, mode: 0o644, data });
            }
            Some(Built::new(m, entries)?)
        }
        None => None,
    };
    Ok(System {
        firmware,
        firmware_bt,
        tree: c.nodes,
        base: Built::new(base, base_entries)?,
        desktop: Built::new(desktop, desktop_entries)?,
        apps: Built::new(apps, apps_entries)?,
        ca: Built::new(ca, ca_entries)?,
    })
}

/// A signed repository's INDEX and INDEX.sig for `pkgs` (stored under
/// `pkgs/`).
fn repo_index(pkgs: &[(&str, &Built)]) -> Result<(Vec<u8>, Vec<u8>)> {
    let list: Vec<Manifest> = pkgs.iter().map(|(file, b)| b.indexed(&format!("pkgs/{file}"))).collect();
    let text = index::to_text(&list);
    let sig = archive::sign_trailer(text.as_bytes(), &crate::quarry::dev_secret()?);
    Ok((text.into_bytes(), sig))
}

impl System {
    /// The tree, quarry's record of both packages, and the repository
    /// holding `slate-desktop` and `slate-apps`.
    pub fn emit(&self, w: &mut dyn Sink) -> Result {
        for n in &self.tree {
            match n.kind {
                Kind::Dir => w.dir(&n.path, n.mode)?,
                Kind::File => w.file(&n.path, n.mode, &n.data)?,
                Kind::Symlink => w.symlink(&n.path, &String::from_utf8_lossy(&n.data))?,
            }
        }
        for d in ["usr/lib/quarry", DB] {
            w.dir(d, 0o755)?;
        }
        for b in [&self.base, &self.desktop, &self.apps, &self.ca] {
            let dir = format!("{DB}/{}", b.manifest.name);
            w.dir(&dir, 0o755)?;
            w.file(&format!("{dir}/manifest"), 0o644, b.manifest.to_text().as_bytes())?;
            w.file(&format!("{dir}/files"), 0o644, b.files_record().as_bytes())?;
            w.file(&format!("{dir}/reason"), 0o644, b"explicit\n")?;
        }
        for d in ["var/lib", "var/lib/quarry", MEDIA_REPO, &format!("{MEDIA_REPO}/pkgs")] {
            w.dir(d, 0o755)?;
        }
        let mut listed = Vec::new();
        for b in [&self.desktop, &self.apps].into_iter().chain(self.firmware.as_ref()).chain(self.firmware_bt.as_ref())
        {
            let file = b.manifest.file_name();
            w.file(&format!("{MEDIA_REPO}/pkgs/{file}"), 0o644, &b.qpk)?;
            listed.push((file, b));
        }
        let listed: Vec<(&str, &Built)> = listed.iter().map(|(f, b)| (f.as_str(), *b)).collect();
        let (text, sig) = repo_index(&listed)?;
        w.file(&format!("{MEDIA_REPO}/INDEX"), 0o644, &text)?;
        w.file(&format!("{MEDIA_REPO}/INDEX.sig"), 0o644, &sig)?;
        Ok(())
    }
}

/// A repository under target/quarry/www/base-next with `slate-base` one
/// release newer than the system's (its release file says so), for the
/// packages scenario's upgrade and rollback.
pub fn base_next_repo() -> Result<PathBuf> {
    // Once a run: scenarios side by side serve it while another asks.
    static BUILT: OnceLock<Result<PathBuf>> = OnceLock::new();
    crate::once(&BUILT, make_base_next_repo)
}

fn make_base_next_repo() -> Result<PathBuf> {
    let s = system()?;
    let next = format!("{}.1", version());
    let mut m = s.base.manifest.clone();
    m.version = next.clone();
    let entries: Vec<Entry> = s
        .base
        .entries
        .iter()
        .map(|e| {
            let mut e = e.clone();
            if e.path == "usr/share/slate/release" {
                e.data = format!("Slate {next}\n").into_bytes();
            }
            e
        })
        .collect();
    let built = Built::new(m, entries)?;
    let dir = target_dir().join("quarry/www/base-next");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("pkgs")).map_err(|e| e.to_string())?;
    let file = built.manifest.file_name();
    std::fs::write(dir.join("pkgs").join(&file), &built.qpk).map_err(|e| e.to_string())?;
    let (text, sig) = repo_index(&[(&file, &built)])?;
    std::fs::write(dir.join("INDEX"), text).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("INDEX.sig"), sig).map_err(|e| e.to_string())?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_the_desktop_off() {
        assert!(is_desktop("bin/strata"));
        assert!(is_desktop("usr/share/fonts/slate/DMMono-Regular.ttf"));
        assert!(!is_desktop("bin/strata-other"));
        assert!(!is_desktop("usr/share/fonts"));
        assert!(is_apps("bin/clock") && !is_desktop("bin/clock"));
        assert!(is_apps("usr/share/strata/apps/help.app") && !is_desktop("usr/share/strata/apps/help.app"));
        assert!(is_desktop("usr/share/strata/apps/terminal.app"));
        assert!(is_apps("usr/share/doc/slate/guides/installing.md") && !is_apps("usr/share/doc/slate"));
        assert!(outside_system("var/lib/x") && outside_system("home/a") && !outside_system("var"));
        assert!(is_ca("etc/ssl/certs/ca-certificates.crt") && !is_ca("etc/ssl/certs/mine.pem"));
    }

    #[test]
    fn ca_versions() {
        let h = "##\n## Certificate data from Mozilla as of: Tue Oct 20 13:32:40 2026 GMT\n##\n";
        assert_eq!(ca_version(h).as_deref(), Some("2026.10.20"));
        assert_eq!(
            ca_version("## Certificate data from Mozilla as of: Sat Feb  7 01:02:03 2027 GMT").as_deref(),
            Some("2027.02.07")
        );
        assert_eq!(ca_version("no date here"), None);
        let ours = std::fs::read_to_string(crate::root().join("rootfs").join(CA_BUNDLE)).unwrap();
        assert!(ca_version(&ours).is_some());
    }
}
