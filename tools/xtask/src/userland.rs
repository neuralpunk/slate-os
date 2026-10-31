// SPDX-License-Identifier: MIT OR Apache-2.0

//! Building Slate's own programs (userland/, ADR 0018) and checking them
//! against GNU tools on the host (`cargo xtask difftest`).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, USER_TARGET, root, run_cmd, target_dir, user_target_args};

/// One of Slate's programs.
#[derive(Debug)]
pub struct Program {
    pub package: &'static str,
    pub binary: &'static str,
    /// The names linked to it in /bin; `None` for a multicall program,
    /// which lists its tools itself (`--list`).
    pub links: Option<&'static [&'static str]>,
    /// File mode in the image (set-user-ID root for su and passwd).
    pub mode: u32,
    /// The directory it goes in: /bin, or /usr/lib/slate for the Linux
    /// programs that are copied into a Linux runtime (ADR 0038); `test`
    /// for a test program, in the test load's /test only.
    pub dir: &'static str,
    /// Part of the installed system; the installer is only on the install
    /// media (ADR 0023, ADR 0029).
    pub system: bool,
}

/// The programs that make up Slate's userland.
pub const PROGRAMS: &[Program] = &[
    Program { package: "slate-coreutils", binary: "coreutils", links: None, mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-chalk", binary: "chalk", links: Some(&["sh"]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-slinit",
        binary: "slinit",
        links: Some(&["telinit", "runlevel", "shutdown", "reboot", "poweroff", "halt", "service"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-etch", binary: "etch", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-less", binary: "less", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-quarry", binary: "quarry", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-slatefs", binary: "slatefs", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-slatefs",
        binary: "slate-update",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-login",
        binary: "login",
        links: Some(&["getty", "nologin"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    // Not set-user-ID: the privilege broker grants root (ADR 0032).
    Program { package: "slate-login", binary: "su", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // sg is newgrp running a command (sg(1)).
    Program { package: "slate-login", binary: "newgrp", links: Some(&["sg"]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-login", binary: "passwd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-login", binary: "useradd", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "usermod", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "userdel", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "groupadd", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "groupmod", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "groupdel", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "chpasswd", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program { package: "slate-login", binary: "gpasswd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-login", binary: "chage", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-login", binary: "chsh", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-login",
        binary: "sudo",
        links: Some(&["sudoedit"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    // sudo's I/O logs, played back (ADR 0159).
    Program { package: "slate-login", binary: "sudoreplay", links: Some(&[]), mode: 0o755, dir: "sbin", system: true },
    Program {
        package: "slate-login",
        binary: "slate-brokerd",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-login",
        binary: "slate-approve",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-sshd", binary: "sshd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-devd", binary: "devd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Full graphics' first start (ADR 0173): run by slinit before the
    // console's login.
    Program {
        package: "slate-graphics-trial",
        binary: "slate-graphics-trial",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-logd",
        binary: "logd",
        links: Some(&["logread", "logger"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-seatd", binary: "seatd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Bluetooth (ADR 0113): the daemon and its command line.
    Program {
        package: "slate-bluetooth",
        binary: "slate-btd",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-bluetooth", binary: "slate-bt", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Linux boxes (ADR 0183): the service and the person's command.
    Program { package: "slate-boxes", binary: "slate-boxd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-boxes", binary: "slate-box", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Copied into a box's /run, where it runs as a Linux program (its PID 1).
    Program {
        package: "slate-boxes",
        binary: "slate-host",
        links: Some(&[]),
        mode: 0o755,
        dir: "usr/lib/slate",
        system: true,
    },
    Program { package: "slate-netd", binary: "netd", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-nettools", binary: "lookup", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-nettools", binary: "ip", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-hwtools", binary: "lspci", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Sound (ADR 0184): the cards, and Settings › Sound's self-test.
    Program { package: "slate-sound", binary: "slate-sound", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-hwtools", binary: "lsusb", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-nettools",
        binary: "ping",
        links: Some(&["ping6"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-nettools", binary: "ss", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-nettools", binary: "fetch", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-nettools",
        binary: "slate-network",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-nettools",
        binary: "slate-firewall",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-strata", binary: "strata", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-strata", binary: "strata-keys", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-strata",
        binary: "strata-notify",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-strata",
        binary: "strata-settings",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-strata",
        binary: "strata-login",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-terminal", binary: "terminal", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // Slate's apps (M28, ADR 0104).
    Program { package: "slate-apps", binary: "calculator", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "solitaire", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "mines", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "clock", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "slate-help", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "image-viewer", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "text-editor", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "files", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "calendar", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "contacts", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    // The system tools (ADR 0112).
    Program {
        package: "slate-apps",
        binary: "system-monitor",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-apps", binary: "disks", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "web-browser", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program { package: "slate-apps", binary: "app-center", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-apps",
        binary: "software-updater",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-diskutil",
        binary: "slate-disk",
        links: Some(&[]),
        mode: 0o755,
        dir: "sbin",
        system: true,
    },
    Program {
        package: "slate-apps",
        binary: "archive-manager",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program { package: "slate-crypt", binary: "slate-crypt", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-unlock",
        binary: "slate-unlock",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    // Linux programs (ADR 0038): the door into the Linux runtime, and the
    // bridge it copies there.
    Program {
        package: "slate-linux-app",
        binary: "slate-linux-app",
        links: Some(&["slate-linux", "slate-flatpak", "slate-appimage"]),
        mode: 0o755,
        dir: "bin",
        system: true,
    },
    Program {
        package: "slate-strata-wl",
        binary: "strata-wl",
        links: Some(&[]),
        mode: 0o755,
        dir: "usr/lib/slate",
        system: true,
    },
    // The Settings portal it starts in the runtime for an app (M31 phase 4).
    Program {
        package: "slate-portal",
        binary: "slate-portal",
        links: Some(&[]),
        mode: 0o755,
        dir: "usr/lib/slate",
        system: true,
    },
    // The Wayland test client (M31 phase 1): only in the test load's
    // /test, and copied into a runtime by the measurements.
    Program {
        package: "slate-strata-wl",
        binary: "wl-probe",
        links: Some(&[]),
        mode: 0o755,
        dir: "test",
        system: false,
    },
    Program { package: "slate-install", binary: "slate-boot", links: Some(&[]), mode: 0o755, dir: "bin", system: true },
    Program {
        package: "slate-install",
        binary: "slate-install",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: false,
    },
    Program {
        package: "slate-install",
        binary: "slate-install-gui",
        links: Some(&[]),
        mode: 0o755,
        dir: "bin",
        system: false,
    },
];

/// A built program: its binary name, path and the names linked to it.
#[derive(Debug, Clone)]
pub struct Built {
    pub name: String,
    pub path: PathBuf,
    pub links: Vec<String>,
    pub mode: u32,
    pub dir: &'static str,
    pub system: bool,
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

/// Build slate-libc (ADR 0031) and assemble the sysroot `tools/slate-cc`
/// compiles against: `target/slate-sysroot/{include,lib/libslate-c.a}`.
/// Built once per run: scenarios side by side ask for it (the test
/// programs, quarry's test packages), and rebuilding it under one that is
/// linking against it removed the library mid-link (2026-10-28).
pub fn sysroot() -> Result<PathBuf> {
    static BUILT: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
    let mut built = BUILT.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(p) = built.as_ref() {
        return Ok(p.clone());
    }
    let p = build_sysroot()?;
    *built = Some(p.clone());
    Ok(p)
}

fn build_sysroot() -> Result<PathBuf> {
    let mut c = cargo();
    user_target_args(c.args(["build", "--release", "--package", "slate-libc"]));
    c.env("CARGO_PROFILE_RELEASE_DEBUG", "false");
    c.env("CARGO_TARGET_DIR", target_dir().join("userland"));
    run_cmd(&mut c)?;
    let sysroot = target_dir().join("slate-sysroot");
    let _ = std::fs::remove_dir_all(&sysroot);
    let lib = sysroot.join("lib");
    std::fs::create_dir_all(&lib).map_err(|e| e.to_string())?;
    let built = target_dir().join("userland").join(USER_TARGET).join("release").join("libslate_libc.a");
    std::fs::copy(&built, lib.join("libslate-c.a")).map_err(|e| format!("{}: {e}", built.display()))?;
    copy_tree(&root().join("libs/libc/include"), &sysroot.join("include"))?;
    Ok(sysroot)
}

fn copy_tree(from: &Path, to: &Path) -> Result {
    std::fs::create_dir_all(to).map_err(|e| e.to_string())?;
    for e in std::fs::read_dir(from).map_err(|e| e.to_string())? {
        let e = e.map_err(|e| e.to_string())?;
        let dest = to.join(e.file_name());
        if e.path().is_dir() {
            copy_tree(&e.path(), &dest)?;
        } else {
            std::fs::copy(e.path(), &dest).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Run the slate-libc test programs (tests/native) on the host, where
/// slate-rt makes Linux calls: the same binaries pass on both systems.
/// Capped like difftest cases (20 s, 512 MiB).
pub fn native_on_host() -> Result {
    let work = target_dir().join("native-host");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let progs = crate::user::build_native_libc()?;
    for (name, path) in &progs {
        let capped = format!("ulimit -v {}\nexec {}", 512 * 1024, path.display());
        let out = Command::new("timeout")
            .args(["-s", "KILL", "20", "/bin/sh", "-c", &capped])
            .current_dir(&work)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let failed: Vec<&str> = text.lines().filter(|l| l.contains("FAIL")).collect();
            return Err(format!("{name} failed on the host ({}): {}", out.status, failed.join("; ")));
        }
    }
    println!("xtask: slate-libc programs passed on the host ({})", progs.len());
    Ok(())
}

/// Build every program (release, with its symbol table for the bench's
/// profiles, ADR 0062) and make the stripped copies the images get, in
/// `target/userland/stripped`.
pub fn build() -> Result<Vec<Built>> {
    static BUILT: std::sync::OnceLock<Result<Vec<Built>>> = std::sync::OnceLock::new();
    crate::once(&BUILT, build_now)
}

fn build_now() -> Result<Vec<Built>> {
    let mut c = cargo();
    user_target_args(c.args(["build", "--release"]));
    let mut packages: Vec<&str> = PROGRAMS.iter().map(|p| p.package).collect();
    packages.dedup();
    for p in packages {
        c.args(["--package", p]);
    }
    // Without debug information, unlike the kernel's release profile; set
    // here so the workspace profile stays the kernel's. The symbols stay
    // (stripping in the build would change the code's layout from a build
    // that keeps them), and are taken off the copies below.
    c.env("CARGO_PROFILE_RELEASE_STRIP", "none").env("CARGO_PROFILE_RELEASE_DEBUG", "false");
    c.env("CARGO_TARGET_DIR", target_dir().join("userland"));
    run_cmd(&mut c)?;
    let dir = symbols_dir();
    let stripped = target_dir().join("userland").join("stripped");
    std::fs::create_dir_all(&stripped).map_err(|e| e.to_string())?;
    let key = crate::quarry::dev_secret()?;
    PROGRAMS
        .iter()
        .map(|p| {
            let path = stripped.join(p.binary);
            strip(&dir.join(p.binary), &path, Some((sign_flags(p.binary), &key)))?;
            let links = match p.links {
                Some(l) => l.iter().map(|s| s.to_string()).collect(),
                None => applets(&path)?,
            };
            Ok(Built { name: p.binary.to_string(), path, links, mode: p.mode, dir: p.dir, system: p.system })
        })
        .collect()
}

/// Where [`build`] leaves the programs with their symbols.
pub fn symbols_dir() -> PathBuf {
    target_dir().join("userland").join(USER_TARGET).join("release")
}

/// How a program is signed (ADR 0090): `ANYWHERE` but for the bridge
/// copied into a Linux runtime, `UPDATER` for quarry and slate-update.
pub fn sign_flags(binary: &str) -> u32 {
    use slate_elfsign::{ANYWHERE, KEYSLOTS, UPDATER};
    match binary {
        // Copied out of the system tree to run as Linux programs (in the
        // Linux runtime, in boxes): never Slate's there.
        "strata-wl" | "wl-probe" | "slate-portal" | "slate-host" => 0,
        "quarry" | "slate-update" => ANYWHERE | UPDATER,
        // They keep the encrypted root's key slots with passwords (ADR 0130).
        "slate-brokerd" | "login" | "passwd" | "chpasswd" | "slate-crypt" => ANYWHERE | KEYSLOTS,
        _ => ANYWHERE,
    }
}

/// Copy the ELF executable `src` to `dst` with only what loading it needs:
/// the file up to the end of its last segment, without section headers
/// (the symbols, the debug information, the section names), signed with
/// `sign`'s flags and key when given (ADR 0090). Programs are loaded by
/// their program headers alone (ELF gABI, "Program Loading").
pub fn strip(src: &Path, dst: &Path, sign: Option<(u32, &slate_qpkg::SecretKey)>) -> Result {
    let d = std::fs::read(src).map_err(|e| format!("{}: {e}", src.display()))?;
    let end = loaded_end(&d).ok_or_else(|| format!("{}: not an ELF-64 executable", src.display()))?;
    let mut out = d[..end].to_vec();
    // e_shoff (0x28), e_shnum (0x3c), e_shstrndx (0x3e): none.
    out[0x28..0x30].fill(0);
    out[0x3c..0x40].fill(0);
    if let Some((flags, key)) = sign {
        out = slate_elfsign::sign(&out, flags, key);
    }
    let same = std::fs::read(dst).is_ok_and(|old| old == out);
    if !same {
        let tmp = dst.with_extension("new");
        std::fs::write(&tmp, &out).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, dst).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The end of the last part of an ELF-64 file that a program header
/// covers (headers included); `None` if it is not ELF-64.
fn loaded_end(d: &[u8]) -> Option<usize> {
    if d.get(..5)? != b"\x7fELF\x02" {
        return None;
    }
    let u16_at = |o: usize| Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?) as usize);
    let u64_at = |o: usize| Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?) as usize);
    // e_phoff, e_phentsize, e_phnum; each header's p_offset and p_filesz.
    let (phoff, phentsize, phnum) = (u64_at(0x20)?, u16_at(0x36)?, u16_at(0x38)?);
    let mut end = phoff + phentsize * phnum;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        end = end.max(u64_at(ph + 8)? + u64_at(ph + 32)?);
    }
    (end <= d.len()).then_some(end)
}

/// The tool names a multicall program provides (`PROGRAM --list`; our own
/// binaries also run on the host).
fn applets(program: &Path) -> Result<Vec<String>> {
    let out = Command::new(program).arg("--list").output().map_err(|e| format!("{}: {e}", program.display()))?;
    if !out.status.success() {
        return Err(format!("{} --list failed", program.display()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect())
}

/// Run each command line in tests/difftest/cases.txt with our tools and
/// with the host's GNU tools, in a fixture made by tests/difftest/setup.sh,
/// and require identical output and exit status.
pub fn difftest() -> Result {
    let progs = build()?;
    let work = target_dir().join("difftest");
    let _ = std::fs::remove_dir_all(&work);
    let bin = work.join("bin");
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    for p in &progs {
        for a in &p.links {
            std::os::unix::fs::symlink(&p.path, bin.join(a)).map_err(|e| e.to_string())?;
        }
        // Programs of their own (less) under their names too.
        if !bin.join(&p.name).exists() {
            std::os::unix::fs::symlink(&p.path, bin.join(&p.name)).map_err(|e| e.to_string())?;
        }
    }
    // Each side gets its own copy of the fixture: cases may change it.
    let (fix_ours, fix_gnu) = (work.join("ours"), work.join("gnu"));
    for f in [&fix_ours, &fix_gnu] {
        std::fs::create_dir_all(f).map_err(|e| e.to_string())?;
        run_cmd(Command::new("/bin/sh").arg(root().join("tests/difftest/setup.sh")).current_dir(f))?;
    }
    let cases = std::fs::read_to_string(root().join("tests/difftest/cases.txt")).map_err(|e| e.to_string())?;
    let run = |path: &str, fixture: &Path, cmd: &str| -> Result<(Vec<u8>, i32)> {
        // Every case is capped: 10 seconds and 512 MiB of address space, so
        // a runaway tool (ours or not) cannot take the host down.
        let capped = format!("ulimit -v {}\n{cmd}", 512 * 1024);
        let out = Command::new("timeout")
            .args(["-s", "KILL", "10", "/bin/sh", "-c", &capped])
            .current_dir(fixture)
            .env_clear()
            .env("PATH", path)
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("HOME", fixture)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        let mut o = out.stdout;
        o.extend_from_slice(&out.stderr);
        // Absolute paths name the side's own fixture directory.
        let o = String::from_utf8_lossy(&o).replace(&*fixture.to_string_lossy(), "$FIXTURE").into_bytes();
        Ok((o, out.status.code().unwrap_or(-1)))
    };
    let (mut pass, mut fail) = (0, Vec::new());
    for line in cases.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let ours = run(&format!("{}:/usr/bin:/bin", bin.display()), &fix_ours, line)?;
        let gnu = run("/usr/bin:/bin", &fix_gnu, line)?;
        if ours == gnu {
            pass += 1;
        } else {
            fail.push(format!(
                "  {line}\n    ours ({}): {:?}\n    gnu  ({}): {:?}",
                ours.1,
                String::from_utf8_lossy(&ours.0),
                gnu.1,
                String::from_utf8_lossy(&gnu.0)
            ));
        }
    }
    if !fail.is_empty() {
        return Err(format!(
            "difftest: {} of {} cases differ from GNU:\n{}",
            fail.len(),
            pass + fail.len(),
            fail.join("\n")
        ));
    }
    println!("xtask: difftest passed ({pass} cases match GNU)");
    let chalk = progs.iter().find(|p| p.name == "chalk").ok_or("chalk was not built")?;
    shell_difftest(&chalk.path, &work)?;
    // less on a pseudo-terminal: keys typed, prompts read back (ADR 0149).
    let less = progs.iter().find(|p| p.name == "less").ok_or("less was not built")?;
    let dir = work.join("less");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = Command::new("timeout")
        .arg("120")
        .arg("python3")
        .arg("-I")
        .arg(root().join("tests/less/pty.py"))
        .arg(&less.path)
        .arg(&dir)
        .output()
        .map_err(|e| format!("python3: {e}"))?;
    if !out.status.success() {
        return Err(format!("less on a pty failed:\n{}", String::from_utf8_lossy(&out.stdout)));
    }
    let n = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("ok:")).count();
    println!("xtask: less on a pseudo-terminal passed ({n} checks)");
    // top too: its fields screen, threads, settings file (ADR 0152).
    let coreutils = progs.iter().find(|p| p.name == "coreutils").ok_or("coreutils was not built")?;
    let dir = work.join("top");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = Command::new("timeout")
        .arg("120")
        .arg("python3")
        .arg("-I")
        .arg(root().join("tests/top/pty.py"))
        .arg(&coreutils.path)
        .arg(&dir)
        .output()
        .map_err(|e| format!("python3: {e}"))?;
    if !out.status.success() {
        return Err(format!("top on a pty failed:\n{}", String::from_utf8_lossy(&out.stdout)));
    }
    let n = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("ok:")).count();
    println!("xtask: top on a pseudo-terminal passed ({n} checks)");
    // etch: its buffers, justify, backups, mouse, colours (g214).
    let etch = progs.iter().find(|p| p.name == "etch").ok_or("etch was not built")?;
    let dir = work.join("etch");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out = Command::new("timeout")
        .arg("120")
        .arg("python3")
        .arg("-I")
        .arg(root().join("tests/etch/pty.py"))
        .arg(&etch.path)
        .arg(&dir)
        .output()
        .map_err(|e| format!("python3: {e}"))?;
    if !out.status.success() {
        return Err(format!("etch on a pty failed:\n{}", String::from_utf8_lossy(&out.stdout)));
    }
    let n = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("ok:")).count();
    println!("xtask: etch on a pseudo-terminal passed ({n} checks)");
    Ok(())
}

/// Run each script in tests/difftest/shell with chalk and with
/// `bash --posix`; standard output and exit status must match. Both use
/// the host's tools, so only the shells differ.
fn shell_difftest(chalk: &Path, work: &Path) -> Result {
    if Command::new("bash").arg("--version").output().is_err() {
        println!("xtask: bash not found; skipping the shell comparison");
        return Ok(());
    }
    let dir = root().join("tests/difftest/shell");
    let mut scripts: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sh"))
        .collect();
    scripts.sort();
    let run = |shell: &str, script: &Path, side: &str| -> Result<(String, i32)> {
        let d = work.join("shell").join(side);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
        // Capped like the tool cases: 10 seconds, 512 MiB.
        let capped = format!("ulimit -v {}; exec {shell} \"$0\"", 512 * 1024);
        let out = Command::new("timeout")
            .args(["-s", "KILL", "10", "/bin/sh", "-c", &capped])
            .arg(script)
            .current_dir(&d)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .env("HOME", &d)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| e.to_string())?;
        let o = String::from_utf8_lossy(&out.stdout).replace(&*d.to_string_lossy(), "$FIXTURE");
        Ok((o, out.status.code().unwrap_or(-1)))
    };
    let mut fail = Vec::new();
    for s in &scripts {
        let ours = run(&chalk.to_string_lossy(), s, "ours")?;
        let bash = run("bash --posix", s, "bash")?;
        if ours != bash {
            let (o, b): (Vec<&str>, Vec<&str>) = (ours.0.lines().collect(), bash.0.lines().collect());
            let first = (0..o.len().max(b.len())).find(|&i| o.get(i) != b.get(i)).unwrap_or(0);
            fail.push(format!(
                "  {}: status {} vs {}; first difference at line {}:\n    chalk: {:?}\n    bash:  {:?}",
                s.file_name().unwrap_or_default().to_string_lossy(),
                ours.1,
                bash.1,
                first + 1,
                o.get(first),
                b.get(first)
            ));
        }
    }
    if !fail.is_empty() {
        return Err(format!(
            "shell difftest: {} of {} scripts differ from bash:\n{}",
            fail.len(),
            scripts.len(),
            fail.join("\n")
        ));
    }
    println!("xtask: shell difftest passed ({} scripts match bash --posix)", scripts.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::loaded_end;

    #[test]
    fn loaded_end_covers_every_segment() {
        // An ELF-64 header, two program headers at 0x40 (56 bytes each),
        // then the file goes on past the second segment's end.
        let mut d = vec![0u8; 0x400];
        d[..5].copy_from_slice(b"\x7fELF\x02");
        d[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        d[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        d[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
        for (i, (off, size)) in [(0u64, 0x100u64), (0x180, 0x80)].into_iter().enumerate() {
            let ph = 0x40 + i * 56;
            d[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
            d[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
            d[ph + 32..ph + 40].copy_from_slice(&size.to_le_bytes());
        }
        assert_eq!(loaded_end(&d), Some(0x200));
        assert_eq!(loaded_end(&d[..0x1ff]), None);
        assert_eq!(loaded_end(b"#!/bin/sh\n"), None);
    }
}
