// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux boxes (M33, ADR 0183): Linux distributions in boxes of their
//! own, where software published as source builds with its usual
//! commands.
//!
//! `cargo xtask box` keeps a workbench (target/box/workbench.img): a
//! SlateFS disk mounted at /var/lib/slate/boxes, where a person (`ada`)
//! has made the box `dev` with `slate-box create dev`, so Arch's base came
//! from Arch's mirrors and was checked on Slate (made once; `--fresh`
//! makes it again). `SLATE_BOX_TRY=FILE cargo xtask box` runs FILE's
//! lines on a copy of it, one command each (as root; `ada` with `su ada
//! -c`; `{mirror}` is the caching mirror's URL, which serves the sources
//! at `{mirror}/sources/FILE`), the transcript in target/box/try.log.
//!
//! `SLATE_BOX_PROBE=FILE cargo xtask box --probe` runs FILE's lines, one
//! command each, in a Slate machine with Arch Linux's bootstrap root
//! unpacked on a disk of its own (/dev/vdb, ext4, mounted at /mnt/arch;
//! unpacked on the host from the pinned, signature-checked tarball). The
//! transcript (target/box/probe.log) ends with what the kernel did not
//! implement: how the boxes' needs are found.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::{Result, run_cmd, target_dir};

/// Arch Linux's bootstrap root, pinned (the release of 2026-10-01; its
/// SHA-256 from the release's sha256sums.txt, its OpenPGP signature by
/// Arch's release key checked on the build machine).
pub const ARCH_RELEASE: &str = "2026.10.01";
pub const ARCH_SHA256: &str = "0c9c97b7a58a8a023c9e07f84cb307a9e8006e65d8fc4c17b83ddc8010b45c10";
pub const ARCH_MIRROR: &str = "https://geo.mirror.pkgbuild.com";

/// The day of the Arch Linux Archive the workbench's packages come from:
/// the same files every time, so each is fetched once and kept.
pub const ARCH_ARCHIVE_DAY: &str = "2026/10/29";
pub const ARCH_ARCHIVE: &str = "https://archive.archlinux.org/repos";

fn dir() -> PathBuf {
    target_dir().join("box")
}

/// A caching mirror on the host for the guests' downloads (the owner,
/// 2026-10-30: never fetch the same thing twice from the projects'
/// servers). `iso/...` is Arch's release folder (the pinned bootstrap,
/// from target/box/dl); every other path is a package of the pinned
/// archive day. A file is fetched once into target/box/mirror and served
/// from there after; while it is first fetched it streams to the guest
/// too.
pub struct CachingMirror {
    pub port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl CachingMirror {
    pub fn start() -> Result<CachingMirror> {
        use std::io::{Read, Write};
        let cache = dir().join("mirror");
        // The bootstrap and its signature, from the pinned download.
        let iso = cache.join("iso").join(ARCH_RELEASE);
        std::fs::create_dir_all(&iso).map_err(|e| e.to_string())?;
        let tarball = arch_tarball()?;
        for f in [tarball.clone(), tarball.with_file_name(format!("{}.sig", arch_tarball_name()))] {
            let to = iso.join(f.file_name().unwrap());
            if !to.exists() {
                std::fs::copy(&f, &to).map_err(|e| e.to_string())?;
            }
        }
        let (ls, port) = crate::hostnet::listeners("caching mirror")?;
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = crate::hostnet::serve_tcp(ls, stop.clone(), move |mut s| {
            let Some(line) = crate::hostnet::read_request(&mut s) else { return };
            let mut parts = line.split_whitespace();
            let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
            let path = target.split('?').next().unwrap_or("/").trim_start_matches('/').to_string();
            let bad = method != "GET" || path.is_empty() || path.split('/').any(|c| c == ".." || c.is_empty());
            if bad {
                let _ = s.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            let file = cache.join(&path);
            if let Ok(data) = std::fs::read(&file) {
                let head = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
                    data.len()
                );
                let _ = s.write_all(head.as_bytes()).and_then(|()| s.write_all(&data));
                return;
            }
            let url = if path.starts_with("iso/") {
                format!("{ARCH_MIRROR}/{path}")
            } else {
                format!("{ARCH_ARCHIVE}/{ARCH_ARCHIVE_DAY}/{path}")
            };
            let Ok(mut child) = Command::new("curl")
                .args(["-fsSL", "--retry", "3"])
                .arg(&url)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
            else {
                return;
            };
            let mut out = child.stdout.take().unwrap();
            let mut buf = vec![0u8; 1 << 16];
            let first = out.read(&mut buf).unwrap_or(0);
            if first == 0 {
                let _ = child.wait();
                let _ = s.write_all(b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            let _ = std::fs::create_dir_all(file.parent().unwrap());
            let part = file.with_extension(format!("part{}", std::process::id()));
            let mut keep = std::fs::File::create(&part).ok();
            let mut to_guest =
                s.write_all(b"HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n").is_ok();
            let mut n = first;
            loop {
                if let Some(k) = keep.as_mut()
                    && k.write_all(&buf[..n]).is_err()
                {
                    keep = None;
                }
                if to_guest && s.write_all(&buf[..n]).is_err() {
                    to_guest = false;
                }
                n = match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
            }
            let fetched = child.wait().is_ok_and(|st| st.success());
            match keep {
                Some(_) if fetched => {
                    let _ = std::fs::rename(&part, &file);
                }
                _ => {
                    let _ = std::fs::remove_file(&part);
                }
            }
        });
        Ok(CachingMirror { port, stop, thread })
    }

    /// The mirror as the guest reaches it.
    pub fn url(&self) -> String {
        format!("http://10.0.2.2:{}", self.port)
    }

    /// The bootstrap's URL on it.
    pub fn bootstrap(&self) -> String {
        format!("{}/iso/{ARCH_RELEASE}/{}", self.url(), arch_tarball_name())
    }

    pub fn stop(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.thread.join();
    }
}

/// Point the box `dev`'s pacman at `mirror` (the port changes each run).
pub fn use_mirror(mirror: &CachingMirror) -> String {
    format!(
        "slate-box run dev --root -- sh -c 'echo \"Server = {}/\\$repo/os/\\$arch\" > /etc/pacman.d/mirrorlist' && echo mirrored$((1+1))",
        mirror.url()
    )
}

/// The bootstrap tarball's name.
pub fn arch_tarball_name() -> String {
    format!("archlinux-bootstrap-{ARCH_RELEASE}-x86_64.tar.zst")
}

/// The bootstrap tarball, fetched once into target/box/dl and checked
/// against the pin.
pub fn arch_tarball() -> Result<PathBuf> {
    let dl = dir().join("dl");
    std::fs::create_dir_all(&dl).map_err(|e| e.to_string())?;
    let name = arch_tarball_name();
    let path = dl.join(&name);
    for file in [name.clone(), format!("{name}.sig")] {
        if !dl.join(&file).exists() {
            let url = format!("{ARCH_MIRROR}/iso/{ARCH_RELEASE}/{file}");
            println!("xtask: box: fetching {url}");
            run_cmd(Command::new("curl").args(["-fsSL", "--retry", "3", "-o"]).arg(dl.join(&file)).arg(&url))?;
        }
    }
    let out = Command::new("sha256sum").arg(&path).output().map_err(|e| e.to_string())?;
    let sum = String::from_utf8_lossy(&out.stdout);
    if !sum.starts_with(ARCH_SHA256) {
        let _ = std::fs::remove_file(&path);
        return Err(format!("box: {name}'s SHA-256 isn't the pinned one ({})", sum.trim()));
    }
    Ok(path)
}

/// An ext4 disk with the bootstrap root unpacked at its top
/// (root.x86_64/), made once.
fn probe_disk() -> Result<PathBuf> {
    let img = dir().join("probe.img");
    if img.exists() {
        return Ok(img);
    }
    let tarball = arch_tarball()?;
    let tree = dir().join("probe-tree");
    // (A tree left by a failed run has folders the host's user can't change.)
    let _ = Command::new("chmod").arg("-R").arg("u+rwX").arg(&tree).status();
    let _ = std::fs::remove_dir_all(&tree);
    std::fs::create_dir_all(&tree).map_err(|e| e.to_string())?;
    run_cmd(
        Command::new("tar").args(["--zstd", "--delay-directory-restore", "-xf"]).arg(&tarball).arg("-C").arg(&tree),
    )?;
    // Files the host's user can't read (a probe needs no exact modes).
    run_cmd(Command::new("chmod").arg("-R").arg("u+rwX").arg(&tree))?;
    let building = dir().join("probe-building.img");
    let _ = std::fs::remove_file(&building);
    run_cmd(
        Command::new("mkfs.ext4")
            .args(["-q", "-F", "-b", "4096", "-L", "arch", "-E", "root_owner=0:0", "-d"])
            .arg(&tree)
            .arg(&building)
            .arg("16G"),
    )?;
    std::fs::rename(&building, &img).map_err(|e| e.to_string())?;
    let _ = Command::new("chmod").arg("-R").arg("u+w").arg(&tree).status();
    let _ = std::fs::remove_dir_all(&tree);
    Ok(img)
}

/// The person the workbench's boxes are for.
pub const PERSON: &str = "ada";

/// Mount the workbench at the boxes' folder, start slate-boxd again on it,
/// and add the person.
pub const MOUNT: &str = "mkdir -p /var/lib/slate/boxes && mount -t slatefs /dev/vdb /var/lib/slate/boxes && \
    service slate-boxd restart >/dev/null && useradd -m -d /home/ada ada && echo mounted$((1+1))";

/// `cmd` run by the person: written to a script (so its quotes stay as
/// they are), then run with `su`.
pub fn as_person(cmd: &str) -> String {
    format!(
        "printf '%s\\n' '{}' > /home/{PERSON}/.step.sh && su {PERSON} -c 'sh /home/{PERSON}/.step.sh'",
        cmd.replace('\'', "'\\''")
    )
}

/// The workbench's layout, in its stamp.
const LAYOUT: &str = "layout 2: SlateFS, ada's box dev from Arch, packages of the archive's 2026/10/29";

/// The workbench: made once (needs the internet).
pub fn workbench(fresh: bool) -> Result<PathBuf> {
    let img = dir().join("workbench.img");
    let distro = std::fs::read_to_string(crate::root().join("rootfs/usr/share/slate/boxes/arch.distro"))
        .map_err(|e| e.to_string())?;
    let stamp = format!("{LAYOUT}\n{distro}");
    let same = std::fs::read_to_string(dir().join("stamp")).is_ok_and(|s| s == stamp);
    if img.exists() && same && !fresh {
        return Ok(img);
    }
    let _ = std::fs::remove_file(&img);
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    let building = dir().join("building.img");
    crate::slatefsimg::empty(&building, "48G", "boxes")?;
    let started = Instant::now();
    let mirror = CachingMirror::start()?;
    let mut con = crate::desktop::boot(&building, None, false)?;
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 60)?;
        let create = format!(
            "slate-box create dev --from {} --mirror {} && echo created$((1+1))",
            mirror.bootstrap(),
            mirror.url()
        );
        con.run(&as_person(&create), "created2", 3600)?;
        con.run("service slate-boxd log | tail -n 20", "", 20)?;
        con.run("sync; umount /var/lib/slate/boxes/1000/dev /var/lib/slate/boxes/.base/arch; service slate-boxd stop; umount /var/lib/slate/boxes", "", 60)?;
        con.poweroff()
    })();
    mirror.stop();
    std::fs::write(dir().join("setup.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("box: making the workbench: {e} (transcript in target/box/setup.log)"));
    }
    crate::slatefsimg::fsck(&building, 0, "the boxes' workbench")?;
    std::fs::rename(&building, &img).map_err(|e| e.to_string())?;
    std::fs::write(dir().join("stamp"), stamp).map_err(|e| e.to_string())?;
    println!("xtask: box: made the workbench in {:.0}s", started.elapsed().as_secs_f64());
    Ok(img)
}

/// Run `file`'s lines on `disk` (the workbench mounted): the transcript
/// in target/box/`log`.
fn try_lines(disk: &Path, text: &str, log: &str) -> Result {
    let mirror = CachingMirror::start()?;
    let mut con = crate::desktop::boot(disk, None, false)?;
    let log = dir().join(log);
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 60)?;
        con.run(&as_person(&use_mirror(&mirror)), "mirrored2", 60)?;
        let secs = std::env::var("SLATE_BOX_LINE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900);
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            // `{mirror}`: the caching mirror (it serves the sources too).
            let line = line.replace("{mirror}", &mirror.url());
            let marker = "tr''ied";
            if let Err(e) = con.run(&format!("{line}; echo {marker}-$?"), "tried-", secs) {
                con.log.push_str(&format!("\n[xtask: {e}]\n"));
                let _ = con.send("\x03\r");
            }
            let _ = std::fs::write(&log, crate::qemu::strip_ansi(&con.log));
        }
        crate::flatpak::kernel_notes(&mut con)?;
        con.run("service slate-boxd log | tail -n 30", "", 20)?;
        con.poweroff()
    })();
    mirror.stop();
    std::fs::write(&log, crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("box: {e} (transcript in {})", log.display()));
    }
    Ok(())
}

/// `cargo xtask box`: the workbench, and SLATE_BOX_TRY's commands on it.
pub fn run(fresh: bool) -> Result {
    let wb = workbench(fresh)?;
    let Ok(file) = std::env::var("SLATE_BOX_TRY") else {
        println!("xtask: box: the workbench is {} (SLATE_BOX_TRY=FILE runs commands on it)", wb.display());
        return Ok(());
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
    let copy = dir().join("try.img");
    if std::env::var_os("SLATE_BOX_KEEP").is_none() || !copy.exists() {
        let _ = std::fs::remove_file(&copy);
        run_cmd(Command::new("cp").arg("--sparse=always").arg(&wb).arg(&copy))?;
    }
    let started = Instant::now();
    try_lines(&copy, &text, "try.log")?;
    println!("xtask: box: tried {file} ({:.0}s); transcript in target/box/try.log", started.elapsed().as_secs_f64());
    Ok(())
}

/// `cargo xtask box --probe`: SLATE_BOX_PROBE's commands on a copy of the
/// probe disk.
pub fn probe() -> Result {
    let started = Instant::now();
    let file = std::env::var("SLATE_BOX_PROBE").map_err(|_| "box --probe: set SLATE_BOX_PROBE=FILE")?;
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
    let disk = probe_disk()?;
    // SLATE_BOX_KEEP=1 goes on from the last probe's disk.
    let copy = dir().join("probe-run.img");
    if std::env::var_os("SLATE_BOX_KEEP").is_none() || !copy.exists() {
        let _ = std::fs::remove_file(&copy);
        run_cmd(Command::new("cp").arg("--sparse=always").arg(&disk).arg(&copy))?;
    }
    let mut con = crate::desktop::boot(Path::new(&copy), None, false)?;
    let log = dir().join("probe.log");
    let r = (|| -> Result {
        con.login()?;
        con.run("mkdir -p /mnt/arch && mount -t ext4 /dev/vdb /mnt/arch && echo mounted$((1+1))", "mounted2", 30)?;
        let secs = std::env::var("SLATE_BOX_LINE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(900);
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let marker = "pro''bed";
            if let Err(e) = con.run(&format!("{line}; echo {marker}-$?"), "probed-", secs) {
                con.log.push_str(&format!("\n[xtask: {e}]\n"));
                let _ = con.send("\x03\r");
            }
            let _ = std::fs::write(&log, crate::qemu::strip_ansi(&con.log));
        }
        crate::flatpak::kernel_notes(&mut con)?;
        con.run("sync; umount -l /mnt/arch", "", 60)?;
        con.poweroff()
    })();
    std::fs::write(&log, crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("box: {e} (transcript in target/box/probe.log)"));
    }
    println!("xtask: box: probed {file} ({:.0}s); transcript in target/box/probe.log", started.elapsed().as_secs_f64());
    Ok(())
}

// --- The boxes scenario (`cargo xtask test`) ---------------------------

/// The scenario's image: it carries the test distribution's file.
pub const IMAGE: &str = "slate-boxes.img";

/// The test distribution's signing key: a fixed seed, for tests only (its
/// public half is in the scenario image's test.distro alone).
const TEST_SEED: [u8; 32] = *b"slate-boxes-test-distribution-k1";
/// When the test key was "made" (the key packet's creation time).
const TEST_KEY_TIME: u32 = 1_793_000_000;

/// The test distribution: BusyBox as a tiny Linux root, its tarball
/// signed with the test key, under `root/` (so `strip 1`).
fn test_distribution() -> Result<(Vec<u8>, Vec<u8>)> {
    let tree = dir().join("test-distro");
    let _ = std::fs::remove_dir_all(&tree);
    let root = tree.join("root");
    for d in [
        "bin",
        "sbin",
        "usr/bin",
        "usr/sbin",
        "etc/profile.d",
        "etc/skel",
        "root",
        "home",
        "tmp",
        "proc",
        "dev",
        "run",
        "var",
    ] {
        std::fs::create_dir_all(root.join(d)).map_err(|e| e.to_string())?;
    }
    std::fs::copy(crate::busybox::fetch()?, root.join("bin/busybox")).map_err(|e| e.to_string())?;
    for a in crate::busybox::applets()? {
        let at = root.join(a.trim_start_matches('/'));
        if at.ends_with("bin/busybox") || at.exists() {
            continue;
        }
        std::os::unix::fs::symlink("/bin/busybox", &at).map_err(|e| format!("{}: {e}", at.display()))?;
    }
    let files: [(&str, &str, u32); 8] = [
        ("usr/bin/hello-linux", "#!/bin/sh\necho \"hello-linux from $(hostname) in $PWD as $(id -u)\"\n", 0o755),
        ("etc/passwd", "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n", 0o644),
        ("etc/group", "root:x:0:\nwheel:x:10:\nnobody:x:65534:\n", 0o644),
        ("etc/shadow", "root:*:20000::::::\nnobody:*:20000::::::\n", 0o600),
        ("etc/profile", "for f in /etc/profile.d/*.sh; do [ -r \"$f\" ] && . \"$f\"; done\n", 0o644),
        ("etc/os-release", "NAME=\"Slate test distribution\"\nID=slate-test\n", 0o644),
        ("etc/skel/.profile", "# The test distribution's starting file.\n", 0o644),
        ("etc/hosts", "127.0.0.1 localhost\n", 0o644),
    ];
    for (p, text, mode) in files {
        std::fs::write(root.join(p), text).map_err(|e| e.to_string())?;
        std::fs::set_permissions(root.join(p), std::os::unix::fs::PermissionsExt::from_mode(mode))
            .map_err(|e| e.to_string())?;
    }
    let tarball = tree.join("test-root.tar.zst");
    run_cmd(
        Command::new("tar")
            .args(["--zstd", "--owner=0", "--group=0", "--numeric-owner", "--sort=name", "-cf"])
            .arg(&tarball)
            .arg("-C")
            .arg(&tree)
            .arg("root"),
    )?;
    let data = std::fs::read(&tarball).map_err(|e| e.to_string())?;
    let sig = slate_pgp::sign(&data, &TEST_SEED, TEST_KEY_TIME);
    Ok((data, sig))
}

/// The test distribution's description (in the scenario's image only).
fn test_distro_file() -> String {
    let packet = slate_pgp::public_key(&TEST_SEED, TEST_KEY_TIME);
    let key = slate_pgp::Key::parse(&packet).expect("our own key packet");
    let hex: String = packet.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "# A test distribution for the boxes scenario (xtask's boxes.rs): BusyBox,\n\
         # signed with a test key. Only test images have it.\n\
         title Slate test distribution\nrelease 1\nurl http://invalid.example/test-root.tar.zst\n\
         fingerprint {}\nkey {hex}\nstrip 1\nmirror http://invalid.example\nshell /bin/sh\n\
         setup echo set up > /etc/slate-test-setup\n",
        key.fingerprint_hex()
    )
}

/// Put the test distribution's description in the image's stage.
pub fn stage_test_distro(stage: &Path) -> Result {
    let d = stage.join("usr/share/slate/boxes");
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    std::fs::write(d.join("test.distro"), test_distro_file()).map_err(|e| e.to_string())
}

/// The scenario's SlateFS disk, with the test distribution's tarball, its
/// signature, and a tampered copy beside it in `.test`.
fn scenario_disk() -> Result<PathBuf> {
    let (data, sig) = test_distribution()?;
    let src = dir().join("scenario-src");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(src.join("test")).map_err(|e| e.to_string())?;
    std::fs::write(src.join("test/test-root.tar.zst"), &data).map_err(|e| e.to_string())?;
    std::fs::write(src.join("test/test-root.tar.zst.sig"), &sig).map_err(|e| e.to_string())?;
    let mut bad = data.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    std::fs::write(src.join("test/tampered.tar.zst"), &bad).map_err(|e| e.to_string())?;
    std::fs::write(src.join("test/tampered.tar.zst.sig"), &sig).map_err(|e| e.to_string())?;
    let img = dir().join("scenario.img");
    crate::slatefsimg::with_files(&img, "4G", "boxes", &src)?;
    Ok(img)
}

/// A hostile build script (phase 5): run as the box's root, it tries to
/// get out of its box; each attempt says whether it got through. $1 is a
/// SlateOS process's pid (slate-boxd's), as SlateOS sees it.
const HOSTILE: &str = r#"#!/bin/sh
try() { what=$1; shift; if "$@" > /dev/null 2>&1; then echo "$what: GOT THROUGH"; else echo "$what: refused"; fi; }
try read-unshared-file cat /home/ada/secret.txt
try list-unshared-folder ls /home/ada/private
try reach-other-boxes ls /var/lib/slate/boxes
try reach-slate-root ls /run/.slate-old
try make-a-disk mknod /tmp/disk b 254 0
try mount-sysfs mount -t sysfs sysfs /mnt
try compat-off sh -c 'echo 0 > /proc/sys/slate/linux_compat'
try devmode-on sh -c 'echo 1 > /proc/sys/slate/devmode'
try kill-slate-process kill -9 "$1"
try see-slate-process test -e /proc/$1
try reboot reboot -f
echo evil > /usr/bin/slate-evil 2>/dev/null && echo "write-box-usr: its own /usr only"
hostname evil-host 2>/dev/null
echo hostile-done
"#;

/// The boxes scenario (M33 phase 1): a box of the test distribution made,
/// entered and removed; who is who in it, what it sees, what it is
/// tagged with, and what is refused.
pub fn boxes_scenario(o: &crate::Opts) -> Result {
    let started = Instant::now();
    let disk = scenario_disk()?;
    let img = crate::image::build(o, "slate.compat=on", IMAGE, crate::image::Root::Disk)?;
    let mon = target_dir().join("boxes-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = crate::qemu::base_command(o, &img)?;
    crate::qemu::add_disk(&mut c, 0, &disk);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = crate::qemu::Console::start(c)?;
    let test = "/var/lib/slate/boxes/test";
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 60)?;
        con.run(&as_person("slate-box distros"), "Slate test distribution", 20)?;
        // A tampered tarball is refused, and nothing is left of it.
        con.run(
            &as_person(&format!("slate-box create bad --distro test --from {test}/tampered.tar.zst")),
            "what was fetched isn't Slate test distribution's own",
            60,
        )?;
        con.run(
            &as_person(&format!("slate-box create t --distro test --from {test}/test-root.tar.zst")),
            "Made the Linux box t",
            120,
        )?;
        con.run(&as_person("slate-box list"), "t                    Slate test distribution", 20)?;
        // The base's setup ran as the base's root.
        con.run(&as_person("slate-box run t -- cat /etc/slate-test-setup"), "set up", 30)?;
        // Who the person is in the box, and its host name.
        con.run(&as_person("slate-box run t -- id"), "uid=1000(ada) gid=1000(ada) groups=1000(ada),10(wheel)", 30)?;
        con.run(&as_person("echo host=$(slate-box run t -- hostname)"), "host=t\n", 30)?;
        con.run(&as_person("echo root=$(slate-box run --root t -- id -u)"), "root=0\n", 30)?;
        // The kernel's tag, seen from inside and from Slate.
        con.run(&as_person("slate-box run t -- grep Box: /proc/self/status"), "Box:\tt", 30)?;
        // Its own processes only, and its own home: not the person's.
        con.run("echo slate-secret > /home/ada/secret.txt && chown ada /home/ada/secret.txt", "", 10)?;
        con.run(&as_person("slate-box run t -- cat /home/ada/secret.txt; echo st=$?"), "st=1", 30)?;
        con.run(
            &as_person("echo seen=$(slate-box run t -- ps -o comm | grep -c -e slinit -e getty -e slate-boxd)"),
            "seen=0\n",
            30,
        )?;
        con.run(&as_person("slate-box run t -- ls /run/slate-boxd.sock; echo st=$?"), "st=1", 30)?;
        // Its PID 1 is slate-host, a Linux program its root can see (only
        // root sees other users' processes on Slate);
        // a pipe reopened through /dev/fd works for its root.
        con.run(&as_person("echo one=$(slate-box run --root t -- cat /proc/1/comm)"), "one=slate-host\n", 30)?;
        con.run(&as_person("slate-box run --root t -- sh -c \"cat /dev/fd/5 5<<EOF\nfd-ok\nEOF\""), "fd-ok", 30)?;
        // Its own pseudo-terminals only: the person's others aren't there.
        con.run("(sleep 30 < /dev/ptmx &) ; ls /dev/pts | tr '\\n' ' '", "", 10)?;
        con.run(&as_person("echo pts=$(slate-box run t -- ls /dev/pts)"), "pts=ptmx\n", 30)?;
        // Exit statuses come through.
        con.run(&as_person("slate-box run t -- sh -c \"exit 7\"; echo st=$?"), "st=7", 30)?;
        // On disk: the box's root is an ID of its own; the person's home
        // in it is theirs.
        con.run(
            "stat -c %u /var/lib/slate/boxes/1000/t/root /var/lib/slate/boxes/1000/t/home/ada | tr '\\n' ' '",
            "1073807360 1000 ",
            10,
        )?;
        con.run("stat -c %a /var/lib/slate/boxes/1000", "700", 10)?;
        // An interactive shell, with the box named in its prompt.
        con.send(&format!("{}\r", as_person("slate-box enter t")))?;
        con.wait_for("[box t]", 30)?;
        con.send("echo in-$(hostname)-$((40+2)); exit\r")?;
        con.wait_for("in-t-42", 30)?;
        con.run("", "Back in SlateOS.", 30)?;
        // In Strata's terminal, the window says it: "linux box t".
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        std::thread::sleep(std::time::Duration::from_millis(800));
        crate::qemu::monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
        std::thread::sleep(std::time::Duration::from_millis(1200));
        crate::qemu::type_keys(&mon, "su ada\n")?;
        std::thread::sleep(std::time::Duration::from_millis(1000));
        crate::qemu::type_keys(&mon, "slate-box enter t\n")?;
        con.wait_for("(linux box t)", 20)?;
        crate::qemu::type_keys(&mon, "exit\n")?;
        con.wait_for("shows \"sh\" (slate)", 20)?;
        con.run("kill %1; wait", "", 20)?;
        // Transparent (phase 3): the person's own Linux system, its
        // programs as SlateOS commands, where the person is.
        let farm = "export PATH=$PATH:$HOME/.local/share/slate/linux/bin";
        con.run(
            &as_person(&format!("slate-box setup --distro test --from {test}/test-root.tar.zst")),
            "Linux commands are ready",
            120,
        )?;
        con.run(&as_person("ls ~/.local/share/slate/linux/bin | grep -c -x -e ls -e cat -e sh"), "\n0\n", 20)?;
        con.run(
            &as_person(&format!("{farm}; mkdir -p ~/proj && cd ~/proj && hello-linux")),
            "hello-linux from linux in /home/ada/proj as 1000",
            30,
        )?;
        // A Linux source folder: its configure runs in Linux, writing the
        // person's own files there.
        con.run(
            &as_person(&format!(
                "{farm}; cd ~/proj && printf \"#!/bin/sh\\nuname -s > made-by.txt\\necho configured\\n\" > configure \
                 && chmod +x configure && slate-box here && ./configure && echo made=$(cat made-by.txt) $(stat -c %U made-by.txt)"
            )),
            "made=Linux ada",
            30,
        )?;
        // sudo of a Linux command: the Linux system's root, not SlateOS's.
        con.run(&as_person(&format!("{farm}; cd ~/proj && sudo hello-linux")), "in /home/ada/proj as 0", 30)?;
        // Asked once in a folder with a build file, at a prompt.
        con.run("mkdir -p /home/ada/proj2 && printf \"#!/bin/sh\\necho built-in-\\$(uname -s)\\n\" > /home/ada/proj2/build.sh && touch /home/ada/proj2/Makefile && chmod +x /home/ada/proj2/build.sh && chown -R ada /home/ada/proj2 && echo ready$((1+1))", "ready2", 10)?;
        con.send("su ada\r")?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        con.send("cd /home/ada/proj2 && ./build.sh\r")?;
        con.wait_for("Build and run it with Linux tools", 20)?;
        con.send("y\r")?;
        con.wait_for("built-in-Linux", 30)?;
        con.send("exit\r")?;
        con.run("grep -c proj2 /home/ada/.config/slate/linux-folders", "1", 10)?;
        // Install receipts (phase 4): what a command as the box's root
        // changed, kept; undone in order, the box is as it was.
        let listing = "(cd /var/lib/slate/boxes/1000/t && echo list=$( (find usr etc -xdev | sort; md5sum etc/hosts) | md5sum | cut -c1-12))";
        con.run(listing, "list=", 20)?;
        let before = con.last_line_with("list=").unwrap_or_default();
        con.run(
            &as_person("cd ~/proj && slate-box run --root --here t -- sh -c \"mkdir -p /usr/local/share/demo && echo one > /usr/local/share/demo/a && echo changed >> /etc/hosts\""),
            "kept a receipt of what this changed: \"proj\" (",
            60,
        )?;
        con.run(&as_person("slate-box installs t"), "proj", 20)?;
        con.run(
            &as_person("cd ~/proj && slate-box run --root --here t -- sh -c \"echo two > /usr/local/share/demo/a\""),
            "\"proj (2)\" (1 files)",
            60,
        )?;
        con.run(
            &as_person("slate-box undo t proj"),
            "can't be undone on its own: proj (2) changed the same files",
            30,
        )?;
        con.run(&as_person("slate-box undo t \"proj (2)\" && slate-box undo t proj"), "Undid \"proj\":", 60)?;
        con.run(listing, "list=", 20)?;
        let after = con.last_line_with("list=").unwrap_or_default();
        if before.is_empty() || before != after {
            return Err(format!("after undoing its receipts the box isn't as it was ({before:?}, then {after:?})"));
        }
        con.run(&as_person("slate-box installs t"), "Nothing has been installed in t", 20)?;
        // Rolled back to before a receipt.
        con.run(&as_person("cd ~/proj && slate-box run --root --here t -- sh -c \"mkdir -p /usr/local/share && touch /usr/local/share/rolled\""), "kept a receipt", 60)?;
        con.run(&as_person("slate-box rollback t proj --yes"), "back to before \"proj\"", 60)?;
        con.run("test -e /var/lib/slate/boxes/1000/t/usr/local/share/rolled; echo st=$?", "st=1", 10)?;
        // The channel: Slate's word on what the box is; a forged and a
        // replayed message refused, and logged.
        con.run(&as_person("slate-box run t -- /run/slate-box/slate-host info"), "distro Slate test distribution", 30)?;
        con.run(&as_person("slate-box run t -- /run/slate-box/slate-host check-channel"), "replayed: refused", 30)?;
        con.run(&as_person("grep forged -c ~/.local/state/slate/boxes/t.log"), "\n2\n", 10)?;
        // Permissions (phase 5): grants kept outside the box; the network
        // per box; a folder shared for good.
        con.run(
            "mkdir -p /home/ada/shared && echo for-the-box > /home/ada/shared/note && chown -R ada /home/ada/shared",
            "",
            10,
        )?;
        con.run(
            &as_person("slate-box share t ~/shared && slate-box network t off && slate-box show t"),
            "folder: /home/ada/shared",
            20,
        )?;
        con.run(&as_person("slate-box run t -- cat /home/ada/shared/note"), "for-the-box", 30)?;
        con.run(&as_person("echo links=$(slate-box run t -- ls /sys/class/net 2>/dev/null; slate-box run t -- cat /proc/net/dev | grep -c :)"), "links=1", 30)?;
        con.run(&as_person("slate-box unshare t ~/shared && slate-box network t on && slate-box run t -- cat /home/ada/shared/note; echo st=$?"), "st=1", 30)?;
        // The hostile Makefile: as the box's root (sudo from Slate's shell
        // in a Linux source folder), it tries to get out. Every attempt is
        // refused; SlateOS is as it was; what the kernel refused is logged.
        con.run("mkdir -p /home/ada/private /home/ada/evil && echo secret > /home/ada/private/x && touch /home/ada/evil/Makefile && chown -R ada /home/ada/private /home/ada/evil", "", 10)?;
        put_file(&mut con, "/home/ada/evil/hostile.sh", HOSTILE, "ada", 0o755)?;
        con.run("echo boxd=$(for p in /proc/[0-9]*; do grep -q '^Name:.slate-boxd$' $p/status 2>/dev/null && basename $p; done | head -n 1) host=$(hostname) other=$( (cd /var/lib/slate/boxes/1000/t && find usr etc | sort | md5sum) | cut -c1-12)", "boxd=", 10)?;
        let slate_before = con.last_line_with("boxd=").unwrap_or_default();
        let boxd =
            slate_before.split_whitespace().next().and_then(|w| w.strip_prefix("boxd=")).unwrap_or("").to_string();
        if boxd.parse::<u32>().is_err() {
            return Err(format!("slate-boxd's pid wasn't found ({slate_before:?})"));
        }
        con.run(
            &as_person(&format!("cd ~/evil && slate-box here > /dev/null && sudo ./hostile.sh {boxd}")),
            "hostile-done",
            60,
        )?;
        let out = crate::qemu::strip_ansi(&con.log);
        let tail = &out[out.rfind("hostile.sh").unwrap_or(0)..];
        if tail.contains("GOT THROUGH") || tail.matches(": refused").count() < 11 {
            return Err(format!(
                "the hostile Makefile wasn't kept in: {}",
                tail.lines().filter(|l| l.contains(": ")).collect::<Vec<_>>().join("; ")
            ));
        }
        con.run("echo boxd=$(for p in /proc/[0-9]*; do grep -q '^Name:.slate-boxd$' $p/status 2>/dev/null && basename $p; done | head -n 1) host=$(hostname) other=$( (cd /var/lib/slate/boxes/1000/t && find usr etc | sort | md5sum) | cut -c1-12)", "boxd=", 10)?;
        let slate_after = con.last_line_with("boxd=").unwrap_or_default();
        if slate_before != slate_after {
            return Err(format!("SlateOS changed under the hostile Makefile: {slate_before:?}, then {slate_after:?}"));
        }
        con.run(
            "test -e /usr/bin/slate-evil; echo st=$? compat=$(cat /proc/sys/slate/linux_compat)",
            "st=1 compat=1",
            10,
        )?;
        con.run("echo logged=$(dmesg | grep -c 'box linux: .* refused')", "logged=", 10)?;
        let logged: usize = con
            .last_line_with("logged=")
            .and_then(|l| l.strip_prefix("logged=").and_then(|n| n.trim().parse().ok()))
            .unwrap_or(0);
        if logged < 4 {
            return Err(format!("only {logged} of the hostile Makefile's refusals were logged"));
        }
        con.run("dmesg | grep 'box linux: .* refused' | tail -n 8", "", 10)?;
        // Boxes are for people.
        con.run("slate-box create r --distro test", "for people's own accounts", 20)?;
        con.run(&as_person("slate-box create t --distro test"), "you have a box named t already", 20)?;
        // Space (phase 6): what a box takes as its own, and removing it
        // frees about that (the disk's free space read exactly, df -k).
        let free_kb = "echo freekb=$(df -k /var/lib/slate/boxes | tail -n 1 | awk '{print $4}')";
        con.run(
            &as_person("slate-box run --root t -- dd if=/dev/urandom of=/var/big bs=1048576 count=400 2>/dev/null; slate-box list"),
            "Free on their disk",
            120,
        )?;
        let out = crate::qemu::strip_ansi(&con.log);
        let own_line = out.lines().rev().find(|l| l.starts_with("t ")).unwrap_or_default().to_string();
        con.run(free_kb, "freekb=", 10)?;
        let kb = |c: &crate::qemu::Console| -> f64 {
            c.last_line_with("freekb=")
                .and_then(|l| l.strip_prefix("freekb=").and_then(|v| v.trim().parse().ok()))
                .unwrap_or(0.0)
        };
        let before = kb(&con) / 1024.0;
        con.run(&as_person("slate-box remove t --yes"), "Removed the box t", 60)?;
        con.run(free_kb, "freekb=", 10)?;
        let after = kb(&con) / 1024.0;
        let w: Vec<&str> = own_line.split("distribution").nth(1).unwrap_or("").split_whitespace().collect();
        let own: f64 =
            w.first().and_then(|v| v.parse().ok()).unwrap_or(0.0) * if w.get(1) == Some(&"GB") { 1024.0 } else { 1.0 };
        if own < 400.0 || (after - before - own).abs() > 16.0 {
            return Err(format!(
                "removing t: it said {own} MB of its own ({own_line:?}), the disk had {before:.1} MB free, then {after:.1} MB"
            ));
        }
        con.log
            .push_str(&format!("\n[xtask: t had {own} MB of its own; removing it freed {:.1} MB]\n", after - before));
        con.run(&as_person("slate-box list"), "linux                Slate test distribution", 20)?;
        con.run("service slate-boxd log | tail -n 8", "", 10)?;
        con.poweroff()
    })();
    let log = target_dir().join("boxes-scenario.log");
    std::fs::write(&log, crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("boxes: {e} (transcript in {})", log.display()));
    }
    println!("xtask: boxes: passed ({:.0}s)", started.elapsed().as_secs_f64());
    Ok(())
}

// --- Phase 2: source packages measured (`cargo xtask box --accept`) ----

/// A source package the acceptance builds: its tarball (pinned, fetched
/// once into target/box/sources), the Arch packages it needs, and the
/// steps, each run in the box as the person, in their box's home.
pub struct SourcePackage {
    pub name: &'static str,
    pub file: &'static str,
    pub url: &'static str,
    pub sha256: &'static str,
    /// (step, shell commands) in order: `build`, `test`, `install`, `run`.
    pub steps: &'static [(&'static str, &'static str)],
}

/// The longest a step may take (s): a step that hangs is killed in the
/// box, and fails, rather than holding the run up.
const STEP_SECS: u64 = 1200;

/// What the packages need from Arch beyond base-devel.
/// (json-c's tests write a malformed file with xxd.)
pub const NEEDS: &str =
    "cmake meson ninja rust python-pip python-setuptools python-setuptools-scm python-wheel python-pytest tinyxxd";

pub const SOURCES: &[SourcePackage] = &[
    SourcePackage {
        name: "GNU hello 2.12.3 (autotools, C)",
        file: "hello-2.12.3.tar.gz",
        url: "https://ftp.gnu.org/gnu/hello/hello-2.12.3.tar.gz",
        sha256: "0d5f60154382fee10b114a1c34e785d8b1f492073ae2d3a6f7b147687b366aa0",
        steps: &[
            ("build", "tar xf hello-2.12.3.tar.gz && cd hello-2.12.3 && ./configure && make -j4"),
            ("test", "cd hello-2.12.3 && make check"),
            ("install", "cd hello-2.12.3 && sudo make install"),
            ("run", "hello --greeting=from-slate"),
        ],
    },
    SourcePackage {
        name: "GNU nano 9.3 (autotools, ncurses)",
        file: "nano-9.3.tar.xz",
        url: "https://www.nano-editor.org/dist/latest/nano-9.3.tar.xz",
        sha256: "a9affc52c9596ee0682bcdd4ceb3c0b235eb221d83d733dfd9b0dff45897cb0d",
        steps: &[
            ("build", "tar xf nano-9.3.tar.xz && cd nano-9.3 && ./configure && make -j4"),
            ("test", "cd nano-9.3 && make check"),
            ("install", "cd nano-9.3 && sudo make install"),
            ("run", "/usr/local/bin/nano --version"),
        ],
    },
    SourcePackage {
        name: "htop 3.5.3 (autotools, ncurses, /proc)",
        file: "htop-3.5.3.tar.xz",
        url: "https://github.com/htop-dev/htop/releases/download/3.5.3/htop-3.5.3.tar.xz",
        sha256: "a8b164386494cb85bb255a415a3f5f80afe7a0c4491da5d113b3a0f951087e65",
        steps: &[
            ("build", "tar xf htop-3.5.3.tar.xz && cd htop-3.5.3 && ./configure && make -j4"),
            ("test", "cd htop-3.5.3 && make check"),
            ("install", "cd htop-3.5.3 && sudo make install"),
            (
                "run",
                // Its screen for three seconds in a terminal of its own, then
                // stopped (timeout says 124 when it stopped it).
                "htop --version && { TERM=xterm-256color timeout -s INT 3 script -qec htop /dev/null > /dev/null || test $? -eq 124; }",
            ),
        ],
    },
    SourcePackage {
        name: "json-c 0.19 (CMake, a C library)",
        file: "json-c-0.19-20260627.tar.gz",
        url: "https://github.com/json-c/json-c/archive/refs/tags/json-c-0.19-20260627.tar.gz",
        sha256: "f17a6d7d265cf840dfd8f0f46a606d98c6b5b26dc7cfe27275d1546a213086c8",
        steps: &[
            (
                "build",
                "tar xf json-c-0.19-20260627.tar.gz && mkdir -p jc-build && cd jc-build && cmake ../json-c-json-c-0.19-20260627 -DCMAKE_BUILD_TYPE=Release && make -j4",
            ),
            ("test", "cd jc-build && ctest --output-on-failure -j4"),
            ("install", "cd jc-build && sudo make install && sudo ldconfig"),
            // Ours in /usr/local (Arch's own json-c is in /usr).
            (
                "run",
                "test \"$(PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --variable=prefix json-c)\" = /usr/local",
            ),
        ],
    },
    SourcePackage {
        name: "inih r62 (Meson, a C library)",
        file: "r62.tar.gz",
        url: "https://github.com/benhoyt/inih/archive/refs/tags/r62.tar.gz",
        sha256: "9c15fa751bb8093d042dae1b9f125eb45198c32c6704cd5481ccde460d4f8151",
        steps: &[
            (
                "build",
                "tar xf r62.tar.gz && cd inih-r62 && meson setup build -Ddistro_install=true && meson compile -C build",
            ),
            ("test", "cd inih-r62 && meson test -C build"),
            ("install", "cd inih-r62 && sudo meson install -C build && sudo ldconfig"),
            ("run", "PKG_CONFIG_PATH=/usr/local/lib/pkgconfig pkg-config --modversion inih"),
        ],
    },
    SourcePackage {
        name: "ripgrep 15.2.0 (Cargo, Rust)",
        file: "ripgrep-15.2.0-vendored.tar.gz",
        url: "https://github.com/BurntSushi/ripgrep/archive/refs/tags/15.2.0.tar.gz",
        sha256: "7605249d3eb0d5f170e3414498e3344e26b1e7a147aec518b57090b80036a562",
        steps: &[
            ("build", "tar xf ripgrep-15.2.0-vendored.tar.gz && cd ripgrep-15.2.0 && cargo build --release --offline"),
            ("test", "cd ripgrep-15.2.0 && cargo test --release --offline"),
            ("install", "cd ripgrep-15.2.0 && sudo install -m 755 target/release/rg /usr/local/bin/rg"),
            ("run", "rg --version && echo needle-in-slate | rg -c needle"),
        ],
    },
    SourcePackage {
        name: "tabulate 0.10.0 (Python, setuptools)",
        file: "tabulate-0.10.0.tar.gz",
        url: "https://files.pythonhosted.org/packages/46/58/8c37dea7bbf769b20d58e7ace7e5edfe65b849442b00ffcdd56be88697c6/tabulate-0.10.0.tar.gz",
        sha256: "e2cfde8f79420f6deeffdeda9aaec3b6bc5abce947655d17ac662b126e48a60d",
        steps: &[
            (
                "build",
                "tar xf tabulate-0.10.0.tar.gz && cd tabulate-0.10.0 && python -m pip wheel --no-build-isolation --no-deps -w dist .",
            ),
            ("test", "cd tabulate-0.10.0 && python -m pytest -q test"),
            (
                "install",
                "cd tabulate-0.10.0 && sudo python -m pip install --no-deps --break-system-packages dist/*.whl",
            ),
            ("run", "printf \"a b\\n1 2\\n\" | tabulate"),
        ],
    },
];

/// The sources, fetched once into target/box/sources and checked against
/// their pins; ripgrep's with its crates vendored once on the build
/// machine (cargo vendor), so building it needs no crates.io.
pub fn sources() -> Result<PathBuf> {
    let dir = dir().join("sources");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    for s in SOURCES {
        let upstream = s.url.rsplit('/').next().unwrap();
        let at = dir.join(upstream);
        if !at.exists() {
            println!("xtask: box: fetching {} (once)", s.url);
            run_cmd(Command::new("curl").args(["-fsSL", "--retry", "3", "-o"]).arg(&at).arg(s.url))?;
        }
        let out = Command::new("sha256sum").arg(&at).output().map_err(|e| e.to_string())?;
        if !String::from_utf8_lossy(&out.stdout).starts_with(s.sha256) {
            let _ = std::fs::remove_file(&at);
            return Err(format!("box: {upstream} isn't the pinned {}", s.sha256));
        }
    }
    let vendored = dir.join("ripgrep-15.2.0-vendored.tar.gz");
    if !vendored.exists() {
        let work = dir.join("ripgrep-vendor");
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
        run_cmd(Command::new("tar").arg("xf").arg(dir.join("15.2.0.tar.gz")).arg("-C").arg(&work))?;
        let src = work.join("ripgrep-15.2.0");
        let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .args(["vendor", "--locked", "vendor"])
            .current_dir(&src)
            .env("CARGO_HOME", dir.join("cargo-home"))
            .env_remove("RUSTUP_TOOLCHAIN")
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("box: cargo vendor: {}", String::from_utf8_lossy(&out.stderr)));
        }
        std::fs::create_dir_all(src.join(".cargo")).map_err(|e| e.to_string())?;
        std::fs::write(src.join(".cargo/config.toml"), out.stdout).map_err(|e| e.to_string())?;
        run_cmd(Command::new("tar").arg("czf").arg(&vendored).arg("-C").arg(&work).arg("ripgrep-15.2.0"))?;
        let _ = std::fs::remove_dir_all(&work);
    }
    Ok(dir)
}

/// Write `text` at `path` on the guest (through base64), owned by `owner`.
fn put_file(con: &mut crate::qemu::Console, path: &str, text: &str, owner: &str, mode: u32) -> Result {
    use std::io::Write;
    let mut c = Command::new("base64")
        .arg("-w0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    c.stdin.take().unwrap().write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    let enc = String::from_utf8_lossy(&c.wait_with_output().map_err(|e| e.to_string())?.stdout).into_owned();
    con.run(
        &format!(
            "echo {enc} | base64 -d > {path} && chown {owner} {path} && chmod {mode:o} {path} && echo put$((1+1))"
        ),
        "put2",
        20,
    )
}

/// Write `text` as `name` in the person's box home (through base64: the
/// console's line editor takes no newlines in quotes).
fn put_script(con: &mut crate::qemu::Console, name: &str, text: &str) -> Result {
    use std::io::Write;
    let mut enc = Vec::new();
    {
        let mut c = Command::new("base64")
            .arg("-w0")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;
        c.stdin.take().unwrap().write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        enc.extend(c.wait_with_output().map_err(|e| e.to_string())?.stdout);
    }
    let home = "/var/lib/slate/boxes/1000/dev/home/ada";
    con.run(
        &format!(
            "echo {} | base64 -d > {home}/{name} && chown ada {home}/{name} && echo put$((1+1))",
            String::from_utf8_lossy(&enc)
        ),
        "put2",
        20,
    )
}

/// Each step's name, whether it passed, and how long it took (s).
type Steps = Vec<(&'static str, bool, f64)>;

/// One run of all four steps at once (the transparent build): its row.
fn alloc_steps(ok: bool, secs: f64) -> Steps {
    ["build", "test", "install", "run"].iter().map(|s| (*s, ok, if *s == "build" { secs } else { 0.0 })).collect()
}

/// `cargo xtask box --accept`: each source package built with its usual
/// commands in ada's Arch box, its own tests run, installed and run; the
/// results in target/box/accept.md. What fails is the kernel's work list.
pub fn accept() -> Result {
    let started = Instant::now();
    let wb = workbench(false)?;
    let src = sources()?;
    let mirror = CachingMirror::start()?;
    // The sources are on the mirror too.
    let served = dir().join("mirror/sources");
    std::fs::create_dir_all(&served).map_err(|e| e.to_string())?;
    for s in SOURCES {
        let from = if s.file.ends_with("-vendored.tar.gz") { s.file } else { s.url.rsplit('/').next().unwrap() };
        let to = served.join(s.file);
        if !to.exists() {
            std::fs::copy(src.join(from), &to).map_err(|e| e.to_string())?;
        }
    }
    let copy = dir().join("accept.img");
    let _ = std::fs::remove_file(&copy);
    run_cmd(Command::new("cp").arg("--sparse=always").arg(&wb).arg(&copy))?;
    let mut con = crate::desktop::boot(&copy, None, false)?;
    let mut rows: Vec<(String, Steps)> = Vec::new();
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 60)?;
        con.run(&as_person(&use_mirror(&mirror)), "mirrored2", 60)?;
        con.run(
            &as_person(&format!(
                "slate-box run dev -- sudo pacman -S --needed --noconfirm {NEEDS} > /dev/null && echo needs$((1+1))"
            )),
            "needs2",
            1800,
        )?;
        // How long a command in the box takes to start (ten, end to end).
        con.run(
            &as_person(
                "s=$(date +%s%N); for i in 1 2 3 4 5 6 7 8 9 10; do slate-box run dev -- true || echo bad-run; done; \
                 e=$(date +%s%N); echo per-run-ms=$(( (e - s) / 10000000 ))",
            ),
            "per-run-ms=",
            120,
        )?;
        for (n, s) in SOURCES.iter().enumerate() {
            let mut fetch = format!("curl -fsSLO {}/sources/{}", mirror.url(), s.file);
            if n == 0 {
                fetch = format!("cd && {fetch}");
            }
            put_script(&mut con, "fetch.sh", &format!("set -e\ncd\n{fetch}\n"))?;
            con.run(&as_person("slate-box run dev -- bash fetch.sh && echo fetched$((1+1))"), "fetched2", 120)?;
            let mut results = Vec::new();
            for (step, cmd) in s.steps {
                put_script(&mut con, "step.sh", &format!("set -e\ncd\n{cmd}\n"))?;
                let t = Instant::now();
                let ok = con
                    .run(
                        &as_person(&format!(
                            "slate-box run dev -- timeout -s KILL {STEP_SECS} bash step.sh > /tmp/step.log 2>&1; echo st\"\"ep-$?; tail -n 15 /tmp/step.log"
                        )),
                        "step-",
                        STEP_SECS + 120,
                    )
                    .is_ok()
                    && con.log.rsplit("step-").next().is_some_and(|rest| rest.starts_with('0'));
                results.push((*step, ok, t.elapsed().as_secs_f64()));
                let _ = std::fs::write(dir().join("accept.log"), crate::qemu::strip_ansi(&con.log));
                if !ok && *step == "build" {
                    break;
                }
            }
            rows.push((String::from(s.name), results));
        }
        // Transparent (phase 3): from SlateOS's own shell, no box entered:
        // the person's Linux system made by itself, then GNU hello fetched
        // (Linux's curl), unpacked (Slate's tar), configured, built and
        // installed with its usual commands, and run by name.
        con.run(&as_person("slate-box setup && echo set-up$((1+1))"), "set-up2", 600)?;
        let farm = "export PATH=$PATH:$HOME/.local/share/slate/linux/bin";
        let t = Instant::now();
        let built = con
            .run(
                &as_person(&format!(
                    "{farm}; mkdir -p ~/src && cd ~/src && curl -fsSLO {}/sources/hello-2.12.3.tar.gz \
                     && tar xf hello-2.12.3.tar.gz && cd hello-2.12.3 && slate-box here && ./configure > /dev/null \
                     && make > /dev/null && make check > /dev/null && echo built$((1+1))",
                    mirror.url()
                )),
                "built2",
                1800,
            )
            .is_ok();
        // The Linux system's files, as a fingerprint (the indexes tools
        // rebuild left out, as receipts leave them out).
        let listing = "(cd /var/lib/slate/boxes/1000/linux && echo list=$(find usr etc opt -xdev | grep -v -e '^etc/ld.so.cache$' \
             -e '^usr/share/info/dir$' -e '^etc/pacman.d/gnupg' | sort | md5sum | cut -c1-12))";
        con.run(listing, "list=", 120)?;
        let before = con.last_line_with("list=").unwrap_or_default();
        let installed = built
            && con
                .run(
                    &as_person(&format!(
                        "{farm}; cd ~/src/hello-2.12.3 && sudo make install > /dev/null && cd && hello --greeting=from-slate-terminal && command -v hello"
                    )),
                    "/.local/share/slate/linux/bin/hello",
                    600,
                )
                .is_ok();
        rows.push((
            String::from("From SlateOS's terminal: GNU hello (curl, tar, ./configure, make, sudo make install, hello)"),
            alloc_steps(installed, t.elapsed().as_secs_f64()),
        ));
        // Its receipt, undone: every file it installed gone, the system as
        // it was.
        let t = Instant::now();
        let mut undone = con.run(&as_person("slate-box installs"), "hello-2.12.3", 30).is_ok()
            && con
                .run(
                    &as_person(&format!(
                        "{farm}; slate-box undo hello-2.12.3 && (command -v hello || echo hello-gone)"
                    )),
                    "hello-gone",
                    300,
                )
                .is_ok();
        con.run(listing, "list=", 120)?;
        let after = con.last_line_with("list=").unwrap_or_default();
        undone &= !before.is_empty() && before == after;
        if before != after {
            con.log.push_str(&format!(
                "\n[xtask: after the undo the listing is {after:?}, before the install {before:?}]\n"
            ));
        }
        // sudo inside the Linux system: its receipt asked for over the
        // session's sealed channel, then undone too.
        undone &= con
            .run(
                &as_person(
                    "cd ~/src/hello-2.12.3 && slate-box run --here linux -- sh -c \"sudo make install > /dev/null\"",
                ),
                "kept a receipt of what this changed: \"hello-2.12.3\"",
                600,
            )
            .is_ok()
            && con.run(&as_person("slate-box undo hello-2.12.3"), "Undid", 300).is_ok();
        con.run(listing, "list=", 120)?;
        undone &= con.last_line_with("list=").unwrap_or_default() == before;
        rows.push((
            String::from("Install receipts: hello's undone, the Linux system's files as before (twice, the second through sudo inside)"),
            alloc_steps(undone, t.elapsed().as_secs_f64()),
        ));
        crate::flatpak::kernel_notes(&mut con)?;
        con.poweroff()
    })();
    mirror.stop();
    std::fs::write(dir().join("accept.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    let mut md = String::from("| Package | build | test | install | run |\n|---|---|---|---|---|\n");
    let mut all = true;
    for (name, res) in &rows {
        let cell = |step: &str| match res.iter().find(|(s, _, _)| *s == step) {
            Some((_, true, t)) => format!("pass ({t:.0}s)"),
            Some((_, false, _)) => String::from("**fail**"),
            None => String::from("-"),
        };
        all &= res.len() == 4 && res.iter().all(|(_, ok, _)| *ok);
        md.push_str(&format!(
            "| {name} | {} | {} | {} | {} |\n",
            cell("build"),
            cell("test"),
            cell("install"),
            cell("run")
        ));
    }
    std::fs::write(dir().join("accept.md"), &md).map_err(|e| e.to_string())?;
    println!("{md}");
    if let Err(e) = r {
        con.kill();
        return Err(format!("box: accept: {e} (transcript in target/box/accept.log)"));
    }
    println!("xtask: box: accept done in {:.0}s (target/box/accept.md, accept.log)", started.elapsed().as_secs_f64());
    if all { Ok(()) } else { Err("box: accept: not every package passed (target/box/accept.md)".into()) }
}
