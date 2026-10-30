// SPDX-License-Identifier: MIT OR Apache-2.0

//! quarry, Slate's package manager (ADR 0025, ADR 0069): signed packages
//! from signed repository indexes, dependency resolution, and installs
//! that never run scripts. Packages are read as they arrive: each file is
//! written under a temporary name and put in place only once the whole
//! package has proved signed (and matches its index). Configuration files
//! the administrator changed are kept; packages installed only as
//! dependencies are removed when nothing needs them (`autoremove`). The
//! same program builds packages and repositories on the host (`keygen`,
//! `pack`, `index`).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_qpkg::archive::{Item, Stream};
use slate_qpkg::{Dep, Entry, Keyring, Kind, Manifest, PublicKey, SecretKey, archive, index, resolve};
use slate_rt::{Errno, eprintln, fs, lossy, println, subvol};
use slate_web::http;
use slate_web::resolve::Family;

const USAGE: &str = "usage: quarry [--root DIR] [--direct] COMMAND [ARGS]

  On a SlateFS root, install, upgrade, remove and autoremove change a
  snapshot of the system first, which boots next time with the system as
  it was as the fallback, then the running system (--direct: only the
  running system).

  update                    fetch and verify the repository indexes
  search [TERM]             list available packages (matching TERM)
  info NAME                 show a package
  install NAME|FILE.qpk...  install packages and their dependencies
  upgrade [NAME...]         upgrade installed packages (all by default)
  upgrades                  what upgrade would install, changing nothing:
                            NAME OLD NEW SIZE SUMMARY, tab-separated (OLD
                            is - for a package new to the system)
  remove NAME...            remove packages
  autoremove                remove packages installed only for others that nothing needs now
  list                      list installed packages
  files NAME                list a package's files
  verify [NAME...]          check installed files against their hashes

  keygen SECRET PUBLIC      make a signing key pair
  pack DIR MANIFEST SECRET OUT.qpk   build a signed package from DIR
  index REPO SECRET         write REPO/INDEX and INDEX.sig for REPO/pkgs/*.qpk
";

/// Where quarry works: a root directory (`/` normally; another one for
/// building images, or a snapshot of the system in a transaction).
struct Ctx {
    root: String,
    /// Where quarry's own state in /var is (the verified indexes, the
    /// package cache): under `root`, unless a transaction works on a
    /// snapshot, whose /var is the running system's (ADR 0070).
    var_root: Option<String>,
    /// Keep downloaded packages in /var/cache/quarry for the transaction's
    /// second pass.
    cache: bool,
}

impl Ctx {
    fn new(root: &str) -> Ctx {
        Ctx { root: root.into(), var_root: None, cache: false }
    }

    fn path(&self, rel: &str) -> String {
        under(&self.root, rel)
    }

    /// A path in quarry's state under /var.
    fn var(&self, rel: &str) -> String {
        under(self.var_root.as_deref().unwrap_or(&self.root), rel)
    }
}

fn under(root: &str, rel: &str) -> String {
    let rel = rel.trim_start_matches('/');
    if root.is_empty() { format!("/{rel}") } else { format!("{root}/{rel}") }
}

/// Quiet: the second pass of a transaction repeats what the first said.
static QUIET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What a change says as it goes (not in a transaction's second pass).
macro_rules! say {
    ($($t:tt)*) => {
        if !QUIET.load(core::sync::atomic::Ordering::Relaxed) {
            println!($($t)*);
        }
    };
}

type Res<T = ()> = Result<T, String>;

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| lossy(a).into_owned()).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("quarry: {e}");
            1
        }
    }
}

fn run(args: &[String]) -> Res {
    let mut root = String::new();
    let mut direct = false;
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "--root" => {
                root = args.get(i + 1).ok_or("--root needs a directory")?.trim_end_matches('/').into();
                i += 2;
            }
            "--direct" => {
                direct = true;
                i += 1;
            }
            "-h" | "--help" => {
                slate_rt::print!("{USAGE}");
                return Ok(());
            }
            _ => break,
        }
    }
    let ctx = Ctx::new(&root);
    let (cmd, rest) = args[i..].split_first().ok_or_else(|| USAGE.to_string())?;
    match (cmd.as_str(), rest) {
        ("update", []) => update(&ctx),
        ("search", r) if r.len() <= 1 => search(&ctx, r.first().map(String::as_str)),
        ("info", [name]) => info(&ctx, name),
        ("install", r) if !r.is_empty() => atomically(&ctx, direct, &|c| registered(c, install(c, r))),
        ("upgrade", r) => atomically(&ctx, direct, &|c| registered(c, upgrade(c, r))),
        ("upgrades", []) => upgrades(&ctx),
        ("remove", r) if !r.is_empty() => atomically(&ctx, direct, &|c| registered(c, remove(c, r))),
        ("autoremove", []) => atomically(&ctx, direct, &|c| registered(c, autoremove(c))),
        ("list", []) => list(&ctx),
        ("files", [name]) => files(&ctx, name),
        ("verify", r) => verify(&ctx, r),
        ("keygen", [secret, public]) => keygen(secret, public),
        ("pack", [dir, manifest, secret, out]) => pack(dir, manifest, secret, out),
        ("index", [repo, secret]) => make_index(repo, secret),
        _ => Err(USAGE.trim_end().to_string()),
    }
}

// --- State: keys, repositories, indexes, the installed database ---------

/// Where the installed packages are recorded: in the system itself, so a
/// snapshot or rollback of the system takes its record along (ADR 0069).
const DB: &str = "usr/lib/quarry/db";
/// Where quarry kept it before (in /var, which rollbacks leave alone).
const OLD_DB: &str = "var/lib/quarry/db";

/// The trusted keys in /usr/share/quarry/keys/*.pub: the system image's
/// (ADR 0090), which root cannot change, not /etc's.
fn keyring(ctx: &Ctx) -> Res<Keyring> {
    let dir = ctx.path("usr/share/quarry/keys");
    let mut keys = Vec::new();
    for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
        if e.name.ends_with(b".pub") {
            let p = format!("{dir}/{}", lossy(&e.name));
            let text = read_text(&p)?;
            keys.push(PublicKey::parse(&text).map_err(|e| format!("{p}: {e}"))?);
        }
    }
    if keys.is_empty() {
        return Err(format!("no trusted keys in {dir}"));
    }
    Ok(Keyring::new(keys))
}

fn read_text(path: &str) -> Res<String> {
    let b = fs::read_file(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    String::from_utf8(b).map_err(|_| format!("{path}: not UTF-8"))
}

/// `name url` lines of /etc/quarry/repos.
fn repos(ctx: &Ctx) -> Res<Vec<(String, String)>> {
    let p = ctx.path("etc/quarry/repos");
    let text = read_text(&p)?;
    let list: Vec<(String, String)> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            l.split_once(char::is_whitespace).map(|(n, u)| (n.into(), u.trim().trim_end_matches('/').into()))
        })
        .collect();
    if list.is_empty() {
        return Err(format!("no repositories in {p}"));
    }
    Ok(list)
}

/// An available package and the repository URL it comes from.
struct Available {
    manifest: Manifest,
    url: String,
}

/// The packages in the saved indexes, whose signatures are checked again
/// on every use.
fn available(ctx: &Ctx, keys: &Keyring) -> Res<Vec<Available>> {
    let mut out = Vec::new();
    for (name, url) in repos(ctx)? {
        let base = ctx.var(&format!("var/lib/quarry/index/{name}"));
        let Ok(text) = fs::read_file(format!("{base}.INDEX").as_bytes()) else { continue };
        let sig = fs::read_file(format!("{base}.INDEX.sig").as_bytes()).unwrap_or_default();
        archive::verify_detached(&text, &sig, keys).map_err(|e| format!("saved index of {name}: {e}"))?;
        let text = String::from_utf8(text).map_err(|_| format!("index of {name} is not UTF-8"))?;
        for m in index::parse(&text).map_err(|e| format!("index of {name}: {e}"))? {
            out.push(Available { manifest: m, url: url.clone() });
        }
    }
    Ok(out)
}

/// One installed file: kind (`f` a file, `c` a configuration file, `d`,
/// `l`), mode, SHA-256 (files) and path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Owned {
    kind: char,
    mode: u32,
    sha256: String,
    path: String,
}

fn parse_files(text: &str) -> Vec<Owned> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.splitn(4, ' ');
            let kind = f.next()?.chars().next()?;
            let mode = u32::from_str_radix(f.next()?, 8).ok()?;
            let sha256 = f.next()?.to_string();
            let path = f.next()?.to_string();
            Some(Owned { kind, mode, sha256, path })
        })
        .collect()
}

fn files_text(files: &[Owned]) -> String {
    files.iter().map(|o| format!("{} {:o} {} {}\n", o.kind, o.mode, o.sha256, o.path)).collect()
}

/// Why a package is installed: asked for, or only for another's sake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    Explicit,
    Dependency,
}

/// An installed package.
#[derive(Clone, Debug)]
struct Installed {
    manifest: Manifest,
    files: Vec<Owned>,
    reason: Reason,
}

type Db = BTreeMap<String, Installed>;

/// Move a database kept in /var to the system (once, by the first command
/// that changes anything).
fn migrate_db(ctx: &Ctx) -> Res {
    let old = ctx.path(OLD_DB);
    let new = ctx.path(DB);
    if !fs::exists(old.as_bytes()) || fs::exists(new.as_bytes()) {
        return Ok(());
    }
    mkdir_p(&new, 0o755)?;
    for e in fs::read_dir(old.as_bytes()).unwrap_or_default() {
        let name = lossy(&e.name).into_owned();
        if name.starts_with('.') {
            continue;
        }
        mkdir_p(&format!("{new}/{name}"), 0o755)?;
        for f in ["manifest", "files", "reason"] {
            let from = format!("{old}/{name}/{f}");
            match fs::read_file(from.as_bytes()) {
                Ok(data) => write_atomic(&format!("{new}/{name}/{f}"), &data, 0o644)?,
                // Older databases have no reasons.
                Err(_) if f == "reason" => continue,
                Err(e) => return Err(format!("{from}: {e}")),
            }
            let _ = fs::unlink(from.as_bytes());
        }
        let _ = fs::rmdir(format!("{old}/{name}").as_bytes());
    }
    let _ = fs::rmdir(old.as_bytes());
    Ok(())
}

// --- The apps' registry (ADR 0130) ------------------------------------------

/// Where the kernel looks for apps' permissions: in the system itself.
const APPS: &str = "usr/lib/quarry/apps";

/// After a change that went through (`changed`), the registry again.
fn registered(ctx: &Ctx, changed: Res<bool>) -> Res<bool> {
    if changed? {
        write_registry(ctx)?;
        return Ok(true);
    }
    Ok(false)
}

/// Write the registry from the installed packages: every native program
/// (a file with the Slate ABI note) of a package not built for Linux, with
/// its package's permissions. The kernel runs a listed program that no
/// trusted key signed in the Slate domain, confined to them.
fn write_registry(ctx: &Ctx) -> Res {
    let mut lines = String::from("# Written by quarry: native programs and their permissions (ADR 0130).\n");
    for p in installed(ctx)?.values().filter(|p| p.manifest.abi != slate_qpkg::manifest::Abi::Linux) {
        let perms: Vec<&str> = p.manifest.permissions.iter().map(String::as_str).filter(|n| *n != "none").collect();
        let perms = if perms.is_empty() { String::from("none") } else { perms.join(",") };
        for f in p.files.iter().filter(|o| o.kind == 'f') {
            if native_program(&ctx.path(&f.path)) {
                lines.push_str(&format!("/{} {perms}\n", f.path.trim_start_matches('/')));
            }
        }
    }
    let path = ctx.path(APPS);
    if let Some((dir, _)) = path.rsplit_once('/') {
        mkdir_p(dir, 0o755)?;
    }
    write_atomic(&path, lines.as_bytes(), 0o644)
}

/// Whether the file at `path` is a native program: an ELF executable with
/// the Slate ABI note (ADR 0031), as the kernel decides at exec.
pub fn native_program(path: &str) -> bool {
    let Ok(data) = fs::read_file(path.as_bytes()) else { return false };
    let Ok(elf) = slate_elf::Elf::parse_prefix(&data, data.len() as u64) else { return false };
    elf.program_headers().filter(|p| p.kind == slate_elf::PT_NOTE).any(|ph| {
        let note = data.get(ph.offset as usize..(ph.offset + ph.filesz) as usize).unwrap_or(&[]);
        slate_elf::notes(note, ph.align).any(|n| {
            n.name == slate_abi::NOTE_NAME
                && n.kind == slate_abi::NT_SLATE_ABI
                && n.desc.get(..4).is_some_and(|v| u32::from_le_bytes([v[0], v[1], v[2], v[3]]) >= 1)
        })
    })
}

/// Installed packages.
fn installed(ctx: &Ctx) -> Res<Db> {
    let dir = if fs::exists(ctx.path(DB).as_bytes()) { ctx.path(DB) } else { ctx.path(OLD_DB) };
    let mut out = BTreeMap::new();
    for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
        let name = lossy(&e.name).into_owned();
        if name.starts_with('.') {
            continue;
        }
        let manifest =
            Manifest::parse(&read_text(&format!("{dir}/{name}/manifest"))?).map_err(|e| format!("{name}: {e}"))?;
        let files = parse_files(&read_text(&format!("{dir}/{name}/files"))?);
        // Packages recorded before reasons were are taken as asked for.
        let reason = match fs::read_file(format!("{dir}/{name}/reason").as_bytes()) {
            Ok(r) if r.starts_with(b"dependency") => Reason::Dependency,
            _ => Reason::Explicit,
        };
        out.insert(name, Installed { manifest, files, reason });
    }
    Ok(out)
}

fn record(ctx: &Ctx, p: &Installed) -> Res {
    let dir = ctx.path(&format!("{DB}/{}", p.manifest.name));
    mkdir_p(&dir, 0o755)?;
    write_atomic(&format!("{dir}/files"), files_text(&p.files).as_bytes(), 0o644)?;
    let reason: &[u8] = if p.reason == Reason::Dependency { b"dependency\n" } else { b"explicit\n" };
    write_atomic(&format!("{dir}/reason"), reason, 0o644)?;
    write_atomic(&format!("{dir}/manifest"), p.manifest.to_text().as_bytes(), 0o644)
}

fn manifests(db: &Db) -> BTreeMap<String, Manifest> {
    db.iter().map(|(k, p)| (k.clone(), p.manifest.clone())).collect()
}

fn mkdir_p(path: &str, mode: u32) -> Res {
    let mut at = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        at.push('/');
        at.push_str(part);
        match fs::mkdir(at.as_bytes(), mode) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(format!("{at}: {e}")),
        }
    }
    Ok(())
}

/// Write a file through a temporary name and a rename.
fn write_atomic(path: &str, data: &[u8], mode: u32) -> Res {
    let tmp = format!("{path}.quarry-new");
    fs::write_file(tmp.as_bytes(), data, mode).map_err(|e| format!("{tmp}: {e}"))?;
    fs::chmod(tmp.as_bytes(), mode).map_err(|e| format!("{tmp}: {e}"))?;
    fs::rename(tmp.as_bytes(), path.as_bytes()).map_err(|e| format!("{path}: {e}"))
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

fn sha256_of(path: &str) -> Option<String> {
    fs::read_file(path.as_bytes()).ok().map(|d| slate_hash::hex(&slate_hash::sha256(&d)))
}

// --- Fetching ----------------------------------------------------------

const AGENT: &str = concat!("quarry/", env!("CARGO_PKG_VERSION"));

/// Where repository files come from: `http://`, `https://`, `file://` or
/// a plain path. `sink` gets the bytes as they arrive, with no size limit
/// (slate-boxd fetches distributions with it, ADR 0183).
pub fn fetch_into(url: &str, sink: &mut dyn FnMut(&[u8]) -> Res) -> Res {
    let local = url.strip_prefix("file://").or_else(|| (!url.contains("://")).then_some(url));
    if let Some(path) = local {
        let fd = fs::open(path.as_bytes(), fs::O_RDONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
        let mut buf = alloc::vec![0u8; 256 * 1024];
        let r = loop {
            match slate_rt::io::read(fd, &mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = sink(&buf[..n]) {
                        break Err(e);
                    }
                }
                Err(Errno::EINTR) => {}
                Err(e) => break Err(format!("{path}: {e}")),
            }
        };
        let _ = slate_rt::io::close(fd);
        return r;
    }
    let u = http::Url::parse(url).map_err(|_| format!("{url}: not a URL quarry can fetch"))?;
    struct To<'a>(&'a mut dyn FnMut(&[u8]) -> Res);
    impl http::Body for To<'_> {
        fn data(&mut self, b: &[u8]) -> Result<(), String> {
            (self.0)(b)
        }
    }
    let opts = http::Opts { family: Family::Any, agent: AGENT, ca: None, from: 0 };
    match http::get(&u, &opts, &mut To(sink), &mut |_, _| {}) {
        Ok((_, http::Got::Body(_))) => Ok(()),
        Ok((last, http::Got::Status(code, reason))) => Err(format!("{}: HTTP {code} {reason}", last.text())),
        Err(f) => Err(format!("{}: {}", f.url.text(), f.why)),
    }
}

/// A file of at most 64 MiB (an index, a small archive), whole, from any
/// place quarry fetches from (slate-linux uses it too).
pub fn fetch(url: &str) -> Res<Vec<u8>> {
    let mut out = Vec::new();
    fetch_into(url, &mut |b| {
        if out.len() + b.len() > 64 << 20 {
            return Err(format!("{url}: larger than 64 MiB"));
        }
        out.extend_from_slice(b);
        Ok(())
    })?;
    Ok(out)
}

// --- Commands ---------------------------------------------------------

fn update(ctx: &Ctx) -> Res {
    let keys = keyring(ctx)?;
    let dir = ctx.var("var/lib/quarry/index");
    mkdir_p(&dir, 0o755)?;
    for (name, url) in repos(ctx)? {
        let text = fetch(&format!("{url}/INDEX"))?;
        let sig = fetch(&format!("{url}/INDEX.sig")).map_err(|e| format!("{name}: INDEX.sig: {e}"))?;
        archive::verify_detached(&text, &sig, &keys).map_err(|e| format!("{name}: index rejected: {e}"))?;
        let parsed = core::str::from_utf8(&text).map_err(|_| format!("{name}: index is not UTF-8"))?;
        let n = index::parse(parsed).map_err(|e| format!("{name}: {e}"))?.len();
        write_atomic(&format!("{dir}/{name}.INDEX"), &text, 0o644)?;
        write_atomic(&format!("{dir}/{name}.INDEX.sig"), &sig, 0o644)?;
        println!("{name}: {n} packages");
    }
    Ok(())
}

fn search(ctx: &Ctx, term: Option<&str>) -> Res {
    let keys = keyring(ctx)?;
    let db = installed(ctx)?;
    let mut avail = available(ctx, &keys)?;
    avail.sort_by(|a, b| {
        a.manifest
            .name
            .cmp(&b.manifest.name)
            .then(slate_qpkg::version::compare(&b.manifest.version, &a.manifest.version))
    });
    avail.dedup_by(|a, b| a.manifest.name == b.manifest.name);
    for a in avail {
        let m = &a.manifest;
        if term.is_none_or(|t| m.name.contains(t) || m.summary.to_lowercase().contains(&t.to_lowercase())) {
            let mark = if db.contains_key(&m.name) { " [installed]" } else { "" };
            println!("{} {} - {}{mark}", m.name, m.version, m.summary);
        }
    }
    Ok(())
}

fn info(ctx: &Ctx, name: &str) -> Res {
    let db = installed(ctx)?;
    let keys = keyring(ctx)?;
    let avail = available(ctx, &keys)?;
    let newest = avail
        .iter()
        .map(|a| &a.manifest)
        .filter(|m| m.name == name)
        .max_by(|a, b| slate_qpkg::version::compare(&a.version, &b.version));
    let m = db.get(name).map(|p| &p.manifest).or(newest).ok_or_else(|| format!("{name}: no such package"))?;
    slate_rt::print!("{}", m.to_text());
    if let Some(p) = db.get(name) {
        let why = if p.reason == Reason::Dependency { " (for other packages)" } else { "" };
        println!("installed: {}{why}", p.manifest.version);
    }
    if let Some(n) = newest {
        println!("available: {}", n.version);
    }
    Ok(())
}

fn list(ctx: &Ctx) -> Res {
    for p in installed(ctx)?.values() {
        println!("{} {} - {}", p.manifest.name, p.manifest.version, p.manifest.summary);
    }
    Ok(())
}

fn files(ctx: &Ctx, name: &str) -> Res {
    let db = installed(ctx)?;
    let p = db.get(name).ok_or_else(|| format!("{name} is not installed"))?;
    for o in &p.files {
        println!("/{}", o.path);
    }
    Ok(())
}

/// A local package's manifest, once the whole package has proved signed
/// (before anything is installed for it).
fn local_manifest(path: &str, keys: &Keyring) -> Res<Manifest> {
    let mut s = Stream::new();
    let mut manifest = None;
    fetch_into(path, &mut |piece| {
        let mut items = Vec::new();
        s.feed(piece, keys, &mut items).map_err(|e| format!("{path}: {e}; refusing it"))?;
        for it in items {
            if let Item::Manifest(m) = it {
                manifest = Some(*m);
            }
        }
        Ok(())
    })?;
    s.finish().map_err(|e| format!("{path}: {e}; refusing it"))?;
    manifest.ok_or_else(|| format!("{path}: no manifest"))
}

fn install(ctx: &Ctx, args: &[String]) -> Res<bool> {
    migrate_db(ctx)?;
    let keys = keyring(ctx)?;
    let mut db = installed(ctx)?;
    let mut wanted = Vec::new();
    let mut local = Vec::new();
    for a in args {
        if a.ends_with(".qpk") {
            let m = local_manifest(a, &keys)?;
            wanted.extend(m.depends.iter().cloned());
            local.push(a);
        } else {
            wanted.push(Dep::parse(a).map_err(|e| format!("{a}: {e}"))?);
        }
    }
    let named: BTreeSet<String> = args.iter().filter(|a| !a.ends_with(".qpk")).map(|a| dep_name(a)).collect();
    let avail = if wanted.is_empty() { Vec::new() } else { available(ctx, &keys)? };
    let plan = plan(&avail, &db, &wanted, &BTreeSet::new())?;
    let mut changed = !plan.is_empty() || !local.is_empty();
    for a in plan {
        let reason = if named.contains(&a.manifest.name) { Reason::Explicit } else { Reason::Dependency };
        install_one(ctx, &mut db, &keys, &format!("{}/{}", a.url, a.manifest.file), Some(&a.manifest), reason)?;
    }
    for path in local {
        install_one(ctx, &mut db, &keys, path, None, Reason::Explicit)?;
    }
    // Asked for by name though already there (as a dependency): now wanted.
    for n in &named {
        if let Some(p) = db.get_mut(n)
            && p.reason == Reason::Dependency
        {
            p.reason = Reason::Explicit;
            record(ctx, p)?;
            changed = true;
        }
    }
    Ok(changed)
}

/// The package name in `name` or `name (>= 1)`.
fn dep_name(a: &str) -> String {
    a.split('(').next().unwrap_or(a).trim().to_string()
}

fn plan<'a>(avail: &'a [Available], db: &Db, wanted: &[Dep], upgrade: &BTreeSet<String>) -> Res<Vec<&'a Available>> {
    let ms: Vec<Manifest> = avail.iter().map(|a| a.manifest.clone()).collect();
    let order = resolve::plan(&ms, &manifests(db), wanted, upgrade).map_err(|e| e.to_string())?;
    Ok(order
        .iter()
        .filter_map(|m| avail.iter().find(|a| a.manifest.name == m.name && a.manifest.version == m.version))
        .collect())
}

/// What `upgrade` with no names would install (ADR 0112: the Software
/// Updater lists it). Anyone may ask: it reads the verified indexes and
/// the installed database, and changes nothing.
fn upgrades(ctx: &Ctx) -> Res {
    for l in upgrade_list(ctx)? {
        println!("{l}");
    }
    Ok(())
}

fn upgrade_list(ctx: &Ctx) -> Res<Vec<String>> {
    let keys = keyring(ctx)?;
    let db = installed(ctx)?;
    let avail = available(ctx, &keys)?;
    let names: BTreeSet<String> = db.keys().filter(|n| avail.iter().any(|a| &a.manifest.name == *n)).cloned().collect();
    let wanted: Vec<Dep> = names.iter().map(|n| resolve::any(n)).collect();
    Ok(plan(&avail, &db, &wanted, &names)?
        .iter()
        .map(|a| {
            let m = &a.manifest;
            let old = db.get(&m.name).map_or("-", |p| p.manifest.version.as_str());
            format!("{}\t{old}\t{}\t{}\t{}", m.name, m.version, m.size, m.summary.replace('\t', " "))
        })
        .collect())
}

fn upgrade(ctx: &Ctx, args: &[String]) -> Res<bool> {
    migrate_db(ctx)?;
    let keys = keyring(ctx)?;
    let mut db = installed(ctx)?;
    let avail = available(ctx, &keys)?;
    // Everything: what the repositories offer (packages from elsewhere
    // stay as they are). Named: each must be installed.
    let names: Vec<String> = if args.is_empty() {
        db.keys().filter(|n| avail.iter().any(|a| &a.manifest.name == *n)).cloned().collect()
    } else {
        args.to_vec()
    };
    for n in &names {
        if !db.contains_key(n) {
            return Err(format!("{n} is not installed"));
        }
    }
    let set: BTreeSet<String> = names.iter().cloned().collect();
    let wanted: Vec<Dep> = names.iter().map(|n| resolve::any(n)).collect();
    let plan = plan(&avail, &db, &wanted, &set)?;
    if plan.is_empty() {
        say!("everything is up to date");
    }
    let changed = !plan.is_empty();
    let total = plan.len();
    // The last pass's last line stays, so a reader that looked late still
    // sees where it ended; an earlier upgrade's goes.
    if !QUIET.load(core::sync::atomic::Ordering::Relaxed) {
        let _ = fs::unlink(PROGRESS.as_bytes());
    }
    for (i, a) in plan.into_iter().enumerate() {
        // A package new to the system comes in for another's sake.
        let reason = db.get(&a.manifest.name).map_or(Reason::Dependency, |p| p.reason);
        STEP.store(i + 1, core::sync::atomic::Ordering::Relaxed);
        STEPS.store(total, core::sync::atomic::Ordering::Relaxed);
        progress(&a.manifest.name, 0, a.manifest.size);
        let r = install_one(ctx, &mut db, &keys, &format!("{}/{}", a.url, a.manifest.file), Some(&a.manifest), reason);
        if r.is_err() {
            let _ = fs::unlink(PROGRESS.as_bytes());
        }
        r?;
    }
    Ok(changed)
}

/// Whether this system runs Linux programs: Linux compatibility mode is
/// on (ADR 0032), or this is not Slate (the host tools).
fn linux_allowed() -> bool {
    fs::read_file(b"/proc/sys/slate/linux_compat").map_or(true, |v| v.starts_with(b"1"))
}

/// One thing the package brings, written beside its place until the
/// package has proved good.
#[derive(Debug)]
enum Staged {
    Dir { path: String, mode: u32 },
    File { path: String, mode: u32, tmp: String, sha256: String },
    Link { path: String, tmp: String },
}

/// A package being read and installed.
struct Installer<'a> {
    ctx: &'a Ctx,
    db: &'a Db,
    /// Who owns each path now.
    owner: BTreeMap<String, String>,
    manifest: Option<Manifest>,
    staged: Vec<Staged>,
    /// The file being written: its descriptor, staged name and hash.
    open: Option<(i32, String, slate_hash::Sha256)>,
    /// Directories made so far (to take back if the package fails).
    made: Vec<String>,
}

impl Installer<'_> {
    fn item(&mut self, it: Item, expected: Option<&Manifest>) -> Res {
        match it {
            Item::Manifest(m) => {
                if let Some(e) = expected
                    && (m.name != e.name || m.version != e.version)
                {
                    return Err(format!("{}: the package inside is {}", e.id(), m.id()));
                }
                if m.abi == slate_qpkg::manifest::Abi::Linux && !linux_allowed() {
                    return Err(format!("{} is a Linux package: {}", m.id(), slate_rt::Errno::LINUX_OFF));
                }
                self.manifest = Some(*m);
            }
            Item::Dir { path, mode } => {
                self.dir(&path, mode)?;
                self.staged.push(Staged::Dir { path, mode });
            }
            Item::Symlink { path, target } => {
                self.check_owner(&path)?;
                let full = self.ctx.path(&path);
                self.dir(parent(&path), 0o755)?;
                let tmp = format!("{full}.quarry-new");
                let _ = fs::unlink(tmp.as_bytes());
                fs::symlink(&target, tmp.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
                self.staged.push(Staged::Link { path, tmp });
            }
            Item::File { path, mode, .. } => {
                self.check_owner(&path)?;
                self.dir(parent(&path), 0o755)?;
                let tmp = format!("{}.quarry-new", self.ctx.path(&path));
                let fd = fs::open(tmp.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o600)
                    .map_err(|e| format!("{tmp}: {e}"))?;
                self.staged.push(Staged::File { path, mode, tmp: tmp.clone(), sha256: String::new() });
                self.open = Some((fd, tmp, slate_hash::Sha256::default()));
            }
            Item::Data(d) => {
                let (fd, tmp, h) = self.open.as_mut().ok_or("data outside a file")?;
                h.update(&d);
                slate_rt::io::write_all(*fd, &d).map_err(|e| format!("{tmp}: {e}"))?;
            }
            Item::FileEnd => {
                let (fd, tmp, h) = self.open.take().ok_or("a file's end outside a file")?;
                let _ = slate_rt::io::close(fd);
                if let Some(Staged::File { mode, sha256, .. }) = self.staged.last_mut() {
                    fs::chmod(tmp.as_bytes(), *mode).map_err(|e| format!("{tmp}: {e}"))?;
                    *sha256 = slate_hash::hex(&h.finish());
                }
            }
            Item::End { .. } => {}
        }
        Ok(())
    }

    /// Make a directory under the root (and remember what was made).
    fn dir(&mut self, rel: &str, mode: u32) -> Res {
        let mut at = self.ctx.root.clone();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            at.push('/');
            at.push_str(part);
            match fs::mkdir(at.as_bytes(), mode) {
                Ok(()) => self.made.push(at.clone()),
                Err(Errno::EEXIST) => {}
                Err(e) => return Err(format!("{at}: {e}")),
            }
        }
        Ok(())
    }

    /// No two packages may own one file, and files that belong to no
    /// package are not overwritten.
    fn check_owner(&self, path: &str) -> Res {
        let me = self.manifest.as_ref().map(|m| m.name.as_str()).unwrap_or("");
        match self.owner.get(path) {
            Some(who) if who != me => Err(format!("/{path} belongs to {who}")),
            Some(_) => Ok(()),
            // A configuration file already there is the administrator's:
            // it is kept (the package's goes beside it).
            None if self.manifest.as_ref().is_some_and(|m| m.config.iter().any(|c| c == path)) => Ok(()),
            None if fs::lstat(self.ctx.path(path).as_bytes()).is_ok() => {
                Err(format!("/{path} exists and belongs to no package"))
            }
            None => Ok(()),
        }
    }

    /// The package failed: take back what was written.
    fn undo(&mut self) {
        if let Some((fd, _, _)) = self.open.take() {
            let _ = slate_rt::io::close(fd);
        }
        for s in &self.staged {
            if let Staged::File { tmp, .. } | Staged::Link { tmp, .. } = s {
                let _ = fs::unlink(tmp.as_bytes());
            }
        }
        for d in self.made.iter().rev() {
            let _ = fs::rmdir(d.as_bytes());
        }
    }

    /// The package proved good: put everything in place. Configuration
    /// files the administrator changed stay, the package's version going
    /// beside them as `NAME.quarry-new`.
    fn commit(&self, old: Option<&Installed>, m: &Manifest) -> Vec<Owned> {
        let recorded: BTreeMap<&str, &str> =
            old.map(|o| o.files.iter().map(|f| (f.path.as_str(), f.sha256.as_str())).collect()).unwrap_or_default();
        let mut owned = Vec::new();
        for s in &self.staged {
            match s {
                Staged::Dir { path, mode } => {
                    owned.push(Owned { kind: 'd', mode: *mode, sha256: "-".into(), path: path.clone() })
                }
                Staged::Link { path, tmp } => {
                    let _ = fs::rename(tmp.as_bytes(), self.ctx.path(path).as_bytes());
                    owned.push(Owned { kind: 'l', mode: 0o777, sha256: "-".into(), path: path.clone() });
                }
                Staged::File { path, mode, tmp, sha256 } => {
                    let target = self.ctx.path(path);
                    let config = m.config.iter().any(|c| c == path);
                    let current = if config { sha256_of(&target) } else { None };
                    let changed = current.as_deref().is_some_and(|now| {
                        now != sha256.as_str() && recorded.get(path.as_str()).is_none_or(|was| *was != now)
                    });
                    if changed {
                        say!("kept /{path} (changed here); the package's version is /{path}.quarry-new");
                    } else {
                        let _ = fs::rename(tmp.as_bytes(), target.as_bytes());
                    }
                    let kind = if config { 'c' } else { 'f' };
                    owned.push(Owned { kind, mode: *mode, sha256: sha256.clone(), path: path.clone() });
                }
            }
        }
        owned
    }
}

/// A file's SHA-256 and size, read in pieces.
fn hash_file(path: &str) -> Option<(String, u64)> {
    let (mut h, mut n) = (slate_hash::Sha256::default(), 0u64);
    fetch_into(path, &mut |b| {
        h.update(b);
        n += b.len() as u64;
        Ok(())
    })
    .ok()?;
    Some((slate_hash::hex(&h.finish()), n))
}

/// In a transaction, a remote package is downloaded once into
/// /var/cache/quarry, and both passes install from that copy (checked
/// against its index each time, as any package is).
fn cached(ctx: &Ctx, url: &str, expected: Option<&Manifest>) -> Res<String> {
    let remote = url.contains("://") && !url.starts_with("file://");
    let Some(e) = expected.filter(|_| ctx.cache && remote) else { return Ok(url.into()) };
    let dir = ctx.var(CACHE);
    mkdir_p(&dir, 0o755)?;
    let path = format!("{dir}/{}", e.file_name());
    if hash_file(&path).is_some_and(|(h, n)| h == e.sha256 && n == e.size) {
        return Ok(path);
    }
    let tmp = format!("{path}.part");
    let fd = fs::open(tmp.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o644)
        .map_err(|err| format!("{tmp}: {err}"))?;
    // How far the download is, every 256 KiB.
    let (mut got, mut said) = (0u64, 0u64);
    let r = fetch_into(url, &mut |b| {
        got += b.len() as u64;
        if got - said >= 256 << 10 {
            said = got;
            progress(&e.name, got, e.size);
        }
        slate_rt::io::write_all(fd, b).map_err(|err| format!("{tmp}: {err}"))
    });
    let _ = slate_rt::io::close(fd);
    r?;
    fs::rename(tmp.as_bytes(), path.as_bytes()).map_err(|err| format!("{path}: {err}"))?;
    Ok(path)
}

/// Where an upgrade says how far it is, for the Software Updater (ADR
/// 0112): `PASS STEP STEPS GOT SIZE NAME`, PASS `new` (the new system,
/// downloading) or `running` (the running system, from the cache). It is
/// cleared when an upgrade starts and keeps its last line after.
pub const PROGRESS: &str = "/run/quarry-progress";
static STEP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static STEPS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Say how far the upgrade is (only while one runs: STEPS is set).
fn progress(name: &str, got: u64, size: u64) {
    use core::sync::atomic::Ordering::Relaxed;
    let steps = STEPS.load(Relaxed);
    if steps == 0 {
        return;
    }
    let pass = if QUIET.load(Relaxed) { "running" } else { "new" };
    let line = format!("{pass} {} {steps} {got} {size} {name}\n", STEP.load(Relaxed));
    let _ = fs::write_file(PROGRESS.as_bytes(), line.as_bytes(), 0o644);
}

/// Where a transaction keeps the packages it downloaded.
const CACHE: &str = "var/cache/quarry";

fn clear_cache(ctx: &Ctx) {
    let dir = ctx.var(CACHE);
    for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
        let _ = fs::unlink(format!("{dir}/{}", lossy(&e.name)).as_bytes());
    }
}

/// Where a transaction mounts the system it changes.
const SNAPSHOT_AT: &str = "/run/quarry";
/// Left when the running system missed a transaction's change: a later
/// snapshot of it would lose that change, so none is made before a
/// restart (/run starts empty).
const DIVERGED: &str = "/run/quarry-diverged";

/// Run a change atomically (ADR 0070). On a SlateFS root, two snapshots
/// of the running system are taken: one as it is (the fallback), one that
/// the change is made in. Only if the change works does that one become
/// the next boot; then the running system is changed as well, from the
/// same packages, so programs are there at once. A crash at any point
/// boots either the old system or the whole new one. Elsewhere (another
/// root, other file systems, `--direct`) the change is made in place.
fn atomically(ctx: &Ctx, direct: bool, op: &dyn Fn(&Ctx) -> Res<bool>) -> Res {
    let list = (!direct && ctx.root.is_empty())
        .then(|| subvol::list().ok())
        .flatten()
        .filter(|l| subvol::running(l).is_ok_and(|r| subvol::system_number(&r).is_some()));
    let Some(list) = list else { return op(ctx).map(|_| ()) };
    if fs::exists(b"/run/slate-update") {
        return Err("an update is in progress (slate-update): commit or abort it first".into());
    }
    if fs::exists(DIVERGED.as_bytes()) {
        return Err("the running system missed an earlier change: restart first".into());
    }
    migrate_db(ctx)?;
    // Systems nothing runs or boots any more.
    let keep = [subvol::running(&list).ok(), subvol::flagged(&list, "default"), subvol::flagged(&list, "fallback")];
    for v in &list {
        if subvol::system_number(&v.name).is_some() && !keep.iter().any(|k| k.as_deref() == Some(v.name.as_str())) {
            let _ = subvol::ctl("/", &format!("delete {}", v.name));
        }
    }
    let list = subvol::list()?;
    let (before, after) = (subvol::next_system(&list, 1), subvol::next_system(&list, 2));
    subvol::ctl("/", &format!("snapshot {before}"))?;
    let drop = || {
        let _ = subvol::ctl("/", &format!("delete {after}"));
        let _ = subvol::ctl("/", &format!("delete {before}"));
    };
    if let Err(e) = subvol::ctl("/", &format!("snapshot {after}")).and_then(|_| subvol::mount(&after, SNAPSHOT_AT)) {
        drop();
        return Err(e);
    }
    let snap = Ctx { root: SNAPSHOT_AT.into(), var_root: Some(String::new()), cache: true };
    let r = op(&snap);
    // The new system's base (ADR 0087): its /etc as it starts, so a later
    // rollback carries back what changed while it ran (and not the
    // transaction's own changes).
    let r = r.and_then(|c| slate_etcsync::save_base(&after, &before, &format!("{SNAPSHOT_AT}/etc")).map(|()| c));
    let _ = fs::umount(SNAPSHOT_AT.as_bytes());
    let changed = match r {
        Ok(c) => c,
        Err(e) => {
            drop();
            clear_cache(ctx);
            return Err(e);
        }
    };
    if !changed {
        drop();
        return Ok(());
    }
    if let Err(e) = subvol::ctl("/", &format!("boot default={after} fallback={before} tries=1 pending=1")) {
        drop();
        clear_cache(ctx);
        return Err(e);
    }
    // The boot partition follows the boot state: the new system's kernel
    // and the menu (ADR 0086). A failure here is not the transaction's:
    // the next boot syncs again.
    if fs::exists(b"/bin/slate-update")
        && slate_rt::process::run(b"/bin/slate-update", &[b"slate-update".to_vec(), b"sync-boot".to_vec()])
            .is_ok_and(|status| status != 0)
    {
        eprintln!("quarry: the boot partition was not brought up to date; the next boot does it");
    }
    // The running system too, quietly: it was all said once.
    QUIET.store(true, core::sync::atomic::Ordering::Relaxed);
    let live = Ctx { root: ctx.root.clone(), var_root: None, cache: true };
    let r = op(&live);
    QUIET.store(false, core::sync::atomic::Ordering::Relaxed);
    clear_cache(ctx);
    match r {
        Ok(_) => println!(
            "{after} has the change and boots next time; {before} is the system as it was (slate-update rollback)"
        ),
        Err(e) => {
            let _ = fs::write_file(DIVERGED.as_bytes(), after.as_bytes(), 0o644);
            eprintln!("quarry: the running system was not changed ({e}); {after} has the change from the next boot");
        }
    }
    Ok(())
}

/// Fetch, verify and install one package from `url` (an index's entry
/// `expected` says what it must be).
fn install_one(ctx: &Ctx, db: &mut Db, keys: &Keyring, url: &str, expected: Option<&Manifest>, reason: Reason) -> Res {
    let url = &cached(ctx, url, expected)?;
    let mut owner = BTreeMap::new();
    for (name, p) in db.iter() {
        for o in p.files.iter().filter(|o| o.kind != 'd') {
            owner.insert(o.path.clone(), name.clone());
        }
    }
    let mut ins = Installer { ctx, db, owner, manifest: None, staged: Vec::new(), open: None, made: Vec::new() };
    let mut stream = Stream::new();
    let mut end = None;
    let mut announced = false;
    // The whole download's hash and size, kept even after the package
    // stops making sense: a package that does not match its index is
    // reported as that.
    let (mut whole, mut size, mut broken) = (slate_hash::Sha256::default(), 0u64, None::<String>);
    let mut feed = |bytes: &[u8]| -> Res {
        whole.update(bytes);
        size += bytes.len() as u64;
        if broken.is_some() {
            return Ok(());
        }
        let mut items = Vec::new();
        if let Err(e) = stream.feed(bytes, keys, &mut items) {
            broken = Some(format!("{e}; refusing it"));
            return if expected.is_some() { Ok(()) } else { Err(broken.clone().unwrap_or_default()) };
        }
        for it in items {
            if let Item::Manifest(m) = &it
                && !announced
            {
                // Permissions Slate doesn't know: refused (ADR 0130).
                let unknown = m.unknown_permissions();
                if !unknown.is_empty() {
                    let known = slate_qpkg::manifest::PERMISSIONS.join(", ");
                    return Err(format!("unknown permission '{}' (known: {known}); refusing it", unknown.join("', '")));
                }
                match ins.db.get(&m.name) {
                    Some(o) => say!("upgrading {} {} -> {}", m.name, o.manifest.version, m.version),
                    None => say!("installing {}", m.id()),
                }
                announced = true;
            }
            if let Item::End { sha256, size, .. } = &it {
                end = Some((*sha256, *size));
            }
            ins.item(it, expected)?;
        }
        Ok(())
    };
    // A download that failed says so first; then a package that does not
    // match its index; then one that is broken or unsigned.
    let fetched = fetch_into(url, &mut feed);
    let mismatch = expected.is_some_and(|e| size != e.size || slate_hash::hex(&whole.finish()) != e.sha256);
    let r = if fetched.is_ok() && mismatch {
        Err("does not match the index (size or SHA-256); refusing it".to_string())
    } else {
        fetched
            .and_then(|()| broken.map_or(Ok(()), Err))
            .and_then(|()| stream.finish().map_err(|e| format!("{e}; refusing it")))
            .and_then(|()| if end.is_some() { Ok(()) } else { Err("not signed; refusing it".into()) })
    };
    let what = expected.map_or_else(|| url.to_string(), Manifest::id);
    if let Err(e) = r {
        ins.undo();
        return Err(format!("{what}: {e}"));
    }
    let m = ins.manifest.clone().ok_or_else(|| format!("{what}: no manifest"))?;
    let old = ins.db.get(&m.name).cloned();
    let owned = ins.commit(old.as_ref(), &m);
    // Files of the old version that the new one no longer has.
    if let Some(o) = &old {
        let keep: BTreeSet<&str> = owned.iter().map(|o| o.path.as_str()).collect();
        let gone: Vec<Owned> = o.files.iter().filter(|f| !keep.contains(f.path.as_str())).cloned().collect();
        delete_files(ctx, &gone, db, &m.name);
    }
    let p = Installed { manifest: m.clone(), files: owned, reason: old.map_or(reason, |o| o.reason) };
    record(ctx, &p)?;
    db.insert(m.name.clone(), p);
    Ok(())
}

/// Remove files and symlinks, then directories (deepest first) that are
/// empty and that no other package owns. Configuration files changed here
/// stay.
fn delete_files(ctx: &Ctx, files: &[Owned], db: &Db, me: &str) {
    for o in files.iter().filter(|o| o.kind != 'd') {
        let p = ctx.path(&o.path);
        if o.kind == 'c' && sha256_of(&p).is_some_and(|h| h != o.sha256) {
            say!("kept /{} (changed here)", o.path);
            continue;
        }
        let _ = fs::unlink(p.as_bytes());
    }
    let others: BTreeSet<&str> = db
        .iter()
        .filter(|(n, _)| n.as_str() != me)
        .flat_map(|(_, p)| p.files.iter().map(|o| o.path.as_str()))
        .collect();
    let mut dirs: Vec<&Owned> = files.iter().filter(|o| o.kind == 'd' && !others.contains(o.path.as_str())).collect();
    dirs.sort_by_key(|o| core::cmp::Reverse(o.path.matches('/').count()));
    for d in dirs {
        let _ = fs::rmdir(ctx.path(&d.path).as_bytes());
    }
}

fn remove(ctx: &Ctx, names: &[String]) -> Res<bool> {
    migrate_db(ctx)?;
    let mut db = installed(ctx)?;
    let going: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let ms = manifests(&db);
    for n in names {
        let Some(p) = db.get(n) else { return Err(format!("{n} is not installed")) };
        if p.manifest.essential {
            return Err(format!("{n} is the system itself and cannot be removed"));
        }
        let needed: Vec<String> =
            resolve::dependents(&ms, n).into_iter().filter(|d| !going.contains(d.as_str())).collect();
        if !needed.is_empty() {
            return Err(format!("{n} is needed by {}", needed.join(", ")));
        }
    }
    for n in names {
        remove_one(ctx, &mut db, n);
    }
    let left = unneeded(&db);
    if !left.is_empty() {
        say!("no longer needed: {} (quarry autoremove removes them)", left.join(", "));
    }
    Ok(true)
}

fn remove_one(ctx: &Ctx, db: &mut Db, n: &str) {
    let Some(p) = db.get(n).cloned() else { return };
    say!("removing {}", p.manifest.id());
    delete_files(ctx, &p.files, db, n);
    for dir in [DB, OLD_DB] {
        let dir = ctx.path(&format!("{dir}/{n}"));
        for f in ["files", "manifest", "reason"] {
            let _ = fs::unlink(format!("{dir}/{f}").as_bytes());
        }
        let _ = fs::rmdir(dir.as_bytes());
    }
    db.remove(n);
}

/// Packages installed for others' sake that no installed package needs.
fn unneeded(db: &Db) -> Vec<String> {
    let ms = manifests(db);
    let mut gone: BTreeSet<String> = BTreeSet::new();
    loop {
        let more: Vec<String> = db
            .iter()
            .filter(|(n, p)| p.reason == Reason::Dependency && !gone.contains(*n))
            .filter(|(n, _)| resolve::dependents(&ms, n).iter().all(|d| gone.contains(d)))
            .map(|(n, _)| n.clone())
            .collect();
        if more.is_empty() {
            return gone.into_iter().collect();
        }
        gone.extend(more);
    }
}

fn autoremove(ctx: &Ctx) -> Res<bool> {
    migrate_db(ctx)?;
    let mut db = installed(ctx)?;
    let gone = unneeded(&db);
    if gone.is_empty() {
        say!("nothing to remove");
    }
    let changed = !gone.is_empty();
    for n in gone {
        remove_one(ctx, &mut db, &n);
    }
    Ok(changed)
}

fn verify(ctx: &Ctx, names: &[String]) -> Res {
    let db = installed(ctx)?;
    let mut bad = 0;
    for (name, p) in &db {
        if !names.is_empty() && !names.contains(name) {
            continue;
        }
        for o in p.files.iter().filter(|o| o.kind == 'f' || o.kind == 'c') {
            match fs::read_file(ctx.path(&o.path).as_bytes()) {
                Ok(d) if slate_hash::hex(&slate_hash::sha256(&d)) == o.sha256 => {}
                // Configuration is the administrator's to change.
                Ok(_) if o.kind == 'c' => println!("{name}: /{}: changed (configuration)", o.path),
                Ok(_) => {
                    println!("{name}: /{}: modified", o.path);
                    bad += 1;
                }
                Err(e) => {
                    println!("{name}: /{}: {e}", o.path);
                    bad += 1;
                }
            }
        }
    }
    if bad > 0 { Err(format!("{bad} files differ")) } else { Ok(()) }
}

// --- Building (on the host) ------------------------------------------

fn keygen(secret: &str, public: &str) -> Res {
    let mut seed = [0u8; 32];
    slate_rt::process::random(&mut seed).map_err(|e| format!("random: {e}"))?;
    let k = SecretKey::from_seed(seed);
    fs::write_file(secret.as_bytes(), k.to_text().as_bytes(), 0o600).map_err(|e| format!("{secret}: {e}"))?;
    fs::write_file(public.as_bytes(), k.public().to_text().as_bytes(), 0o644).map_err(|e| format!("{public}: {e}"))?;
    println!("key {}", slate_hash::hex(&k.public().id()));
    Ok(())
}

fn secret_key(path: &str) -> Res<SecretKey> {
    SecretKey::parse(&read_text(path)?).map_err(|e| format!("{path}: {e}"))
}

/// Every entry under `dir`, sorted, as package entries.
fn walk(dir: &str, rel: &str, out: &mut Vec<Entry>) -> Res {
    let here = if rel.is_empty() { dir.to_string() } else { format!("{dir}/{rel}") };
    let mut names: Vec<String> = fs::read_dir(here.as_bytes())
        .map_err(|e| format!("{here}: {e}"))?
        .iter()
        .map(|e| lossy(&e.name).into_owned())
        .collect();
    names.sort();
    for n in names {
        let r = if rel.is_empty() { n.clone() } else { format!("{rel}/{n}") };
        let full = format!("{dir}/{r}");
        let st = fs::lstat(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
        let mode = st.mode & 0o7777;
        if st.is_dir() {
            out.push(Entry { path: r.clone(), kind: Kind::Dir, mode, data: Vec::new() });
            walk(dir, &r, out)?;
        } else if st.is_symlink() {
            let t = fs::readlink(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
            out.push(Entry { path: r, kind: Kind::Symlink, mode: 0o777, data: t });
        } else if st.is_file() {
            let d = fs::read_file(full.as_bytes()).map_err(|e| format!("{full}: {e}"))?;
            out.push(Entry { path: r, kind: Kind::File, mode, data: d });
        } else {
            return Err(format!("{full}: only files, directories and symlinks can be packaged"));
        }
    }
    Ok(())
}

fn pack(dir: &str, manifest: &str, secret: &str, out: &str) -> Res {
    let mut m = Manifest::parse(&read_text(manifest)?).map_err(|e| format!("{manifest}: {e}"))?;
    let mut entries = Vec::new();
    walk(dir.trim_end_matches('/'), "", &mut entries)?;
    m.installed_size = entries.iter().map(|e| e.data.len() as u64).sum();
    let bytes = archive::write(&m, &entries, &secret_key(secret)?).map_err(|e| e.to_string())?;
    fs::write_file(out.as_bytes(), &bytes, 0o644).map_err(|e| format!("{out}: {e}"))?;
    println!("{}: {} entries, {} bytes", m.id(), entries.len(), bytes.len());
    Ok(())
}

fn make_index(repo: &str, secret: &str) -> Res {
    let key = secret_key(secret)?;
    let ring = Keyring::new(alloc::vec![key.public()]);
    let pkgs = format!("{repo}/pkgs");
    let mut names: Vec<String> = fs::read_dir(pkgs.as_bytes())
        .map_err(|e| format!("{pkgs}: {e}"))?
        .iter()
        .map(|e| lossy(&e.name).into_owned())
        .filter(|n| n.ends_with(".qpk"))
        .collect();
    names.sort();
    let mut list = Vec::new();
    for n in names {
        let bytes = fs::read_file(format!("{pkgs}/{n}").as_bytes()).map_err(|e| format!("{n}: {e}"))?;
        // Only packages this key signed go into its index.
        let p = archive::read(&bytes, &ring).map_err(|e| format!("{n}: {e}"))?;
        let mut m = p.manifest;
        m.file = format!("pkgs/{n}");
        m.size = bytes.len() as u64;
        m.sha256 = slate_hash::hex(&slate_hash::sha256(&bytes));
        list.push(m);
    }
    let text = index::to_text(&list);
    fs::write_file(format!("{repo}/INDEX").as_bytes(), text.as_bytes(), 0o644).map_err(|e| e.to_string())?;
    let sig = archive::sign_trailer(text.as_bytes(), &key);
    fs::write_file(format!("{repo}/INDEX.sig").as_bytes(), &sig, 0o644).map_err(|e| e.to_string())?;
    println!("{repo}: {} packages", list.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root and a repository in a fresh temporary directory, with the
    /// key that signs the repository trusted.
    struct World {
        dir: std::path::PathBuf,
        key: SecretKey,
    }

    impl World {
        fn new(name: &str) -> World {
            let dir = std::env::temp_dir().join(format!("quarry-test-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("root/usr/share/quarry/keys")).unwrap();
            std::fs::create_dir_all(dir.join("root/etc/quarry")).unwrap();
            std::fs::create_dir_all(dir.join("repo/pkgs")).unwrap();
            let key = SecretKey::from_seed([9; 32]);
            std::fs::write(dir.join("root/usr/share/quarry/keys/test.pub"), key.public().to_text()).unwrap();
            std::fs::write(dir.join("root/etc/quarry/repos"), format!("test {}\n", dir.join("repo").display()))
                .unwrap();
            World { dir, key }
        }

        fn ctx(&self) -> Ctx {
            Ctx::new(&self.dir.join("root").display().to_string())
        }

        /// Put `name` `version` (with `files`, `depends` and `config`) in
        /// the repository and index it.
        fn publish(&self, name: &str, version: &str, files: &[(&str, &str)], depends: &str, config: &str) {
            let mut m = Manifest::new(name, version);
            m.depends = depends.split(',').filter(|d| !d.trim().is_empty()).map(|d| Dep::parse(d).unwrap()).collect();
            m.config = config.split(',').filter(|c| !c.is_empty()).map(String::from).collect();
            let mut entries =
                alloc::vec![Entry { path: "etc".into(), kind: Kind::Dir, mode: 0o755, data: alloc::vec![] }];
            for (p, d) in files {
                entries.push(Entry { path: (*p).into(), kind: Kind::File, mode: 0o644, data: d.as_bytes().to_vec() });
            }
            let bytes = archive::write(&m, &entries, &self.key).unwrap();
            std::fs::write(self.dir.join("repo/pkgs").join(m.file_name()), bytes).unwrap();
            let secret = self.dir.join("secret");
            std::fs::write(&secret, self.key.to_text()).unwrap();
            make_index(&self.dir.join("repo").display().to_string(), &secret.display().to_string()).unwrap();
            update(&self.ctx()).unwrap();
        }

        fn read(&self, rel: &str) -> Option<String> {
            std::fs::read_to_string(self.dir.join("root").join(rel)).ok()
        }

        fn write(&self, rel: &str, text: &str) {
            std::fs::write(self.dir.join("root").join(rel), text).unwrap();
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn installs_with_reasons_and_removes_what_nothing_needs() {
        let w = World::new("reasons");
        w.publish("lib", "1", &[("etc/lib.txt", "lib")], "", "");
        w.publish("app", "1", &[("etc/app.txt", "app")], "lib", "");
        let ctx = w.ctx();
        install(&ctx, &args(&["app"])).unwrap();
        assert_eq!(w.read("etc/app.txt").as_deref(), Some("app"));
        assert_eq!(w.read("usr/lib/quarry/db/app/reason").as_deref(), Some("explicit\n"));
        assert_eq!(w.read("usr/lib/quarry/db/lib/reason").as_deref(), Some("dependency\n"));
        remove(&ctx, &args(&["app"])).unwrap();
        assert_eq!(w.read("etc/app.txt"), None);
        assert_eq!(w.read("etc/lib.txt").as_deref(), Some("lib"), "a dependency stays until autoremove");
        autoremove(&ctx).unwrap();
        assert_eq!(w.read("etc/lib.txt"), None);
        assert!(installed(&ctx).unwrap().is_empty());
    }

    #[test]
    fn keeps_changed_configuration() {
        let w = World::new("config");
        w.publish(
            "svc",
            "1",
            &[("etc/svc.conf", "port 1\n"), ("etc/svc.default", "a\n")],
            "",
            "etc/svc.conf,etc/svc.default",
        );
        let ctx = w.ctx();
        install(&ctx, &args(&["svc"])).unwrap();
        // The administrator changes one; the other is left as shipped.
        w.write("etc/svc.conf", "port 2\n");
        w.publish(
            "svc",
            "2",
            &[("etc/svc.conf", "port 3\n"), ("etc/svc.default", "b\n")],
            "",
            "etc/svc.conf,etc/svc.default",
        );
        let pending = upgrade_list(&ctx).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].starts_with("svc\t1\t2\t"), "{pending:?}");
        upgrade(&ctx, &[]).unwrap();
        assert!(upgrade_list(&ctx).unwrap().is_empty());
        assert_eq!(w.read("etc/svc.conf").as_deref(), Some("port 2\n"));
        assert_eq!(w.read("etc/svc.conf.quarry-new").as_deref(), Some("port 3\n"));
        assert_eq!(w.read("etc/svc.default").as_deref(), Some("b\n"));
        assert!(verify(&ctx, &[]).is_ok(), "changed configuration is not a fault");
        // Removing the package keeps the changed file only.
        remove(&ctx, &args(&["svc"])).unwrap();
        assert_eq!(w.read("etc/svc.conf").as_deref(), Some("port 2\n"));
        assert_eq!(w.read("etc/svc.default"), None);
    }

    #[test]
    fn refuses_a_package_that_does_not_match_its_index_and_leaves_nothing() {
        let w = World::new("tamper");
        w.publish("big", "1", &[("etc/big.txt", &"x".repeat(3 << 20))], "", "");
        // Swap the package for another, validly signed one of a different
        // content: its hash no longer matches the signed index.
        let pkgs = w.dir.join("repo/pkgs");
        let f = std::fs::read_dir(&pkgs).unwrap().next().unwrap().unwrap().path();
        let mut m = Manifest::new("big", "1");
        m.abi = slate_qpkg::Abi::Any;
        let e =
            alloc::vec![Entry { path: "etc/big.txt".into(), kind: Kind::File, mode: 0o644, data: b"evil".to_vec() }];
        std::fs::write(&f, archive::write(&m, &e, &w.key).unwrap()).unwrap();
        let err = install(&w.ctx(), &args(&["big"])).unwrap_err();
        assert!(err.contains("does not match the index"), "{err}");
        assert_eq!(w.read("etc/big.txt"), None);
        assert_eq!(w.read("etc/big.txt.quarry-new"), None);
        assert!(installed(&w.ctx()).unwrap().is_empty());
    }

    #[test]
    fn moves_an_old_database_into_the_system() {
        let w = World::new("migrate");
        w.publish("one", "1", &[("etc/one", "1")], "", "");
        let ctx = w.ctx();
        install(&ctx, &args(&["one"])).unwrap();
        // As quarry used to keep it: in /var.
        let root = w.dir.join("root");
        std::fs::create_dir_all(root.join("var/lib/quarry")).unwrap();
        std::fs::rename(root.join("usr/lib/quarry/db"), root.join("var/lib/quarry/db")).unwrap();
        assert!(installed(&ctx).unwrap().contains_key("one"));
        remove(&ctx, &args(&["one"])).unwrap();
        assert!(!root.join("var/lib/quarry/db").exists());
        assert!(installed(&ctx).unwrap().is_empty());
    }

    #[test]
    fn file_lists_round_trip() {
        let f = alloc::vec![
            Owned { kind: 'd', mode: 0o755, sha256: "-".into(), path: "usr/share/x".into() },
            Owned { kind: 'f', mode: 0o644, sha256: "ab".repeat(32), path: "usr/share/x/a file".into() },
        ];
        assert_eq!(parse_files(&files_text(&f)), f);
        assert_eq!(Ctx::new("").path("etc/x"), "/etc/x");
        assert_eq!(Ctx::new("/mnt").path("/etc/x"), "/mnt/etc/x");
        let snap = Ctx { root: "/run/quarry".into(), var_root: Some(String::new()), cache: true };
        assert_eq!(
            (snap.path("usr/bin"), snap.var("var/lib/quarry")),
            ("/run/quarry/usr/bin".into(), "/var/lib/quarry".into())
        );
    }
}
