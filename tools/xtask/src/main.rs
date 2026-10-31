// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask`: Slate's build driver.
//!
//! ```text
//! cargo xtask build  [--release]                  build the kernel
//! cargo xtask image  [--release] [--cmdline S] [--test-load]
//!                                                 build a bootable GPT disk image
//! cargo xtask iso    [--release]                  build the install media (target/slate.iso; ADR 0029)
//! cargo xtask usb    [--release]                  the install media as a USB disk image (target/slate-usb.img)
//! cargo xtask run    [--release] [--bios] [--headless] [--cmdline S] [--test-load]
//!                                                 boot to a login (QEMU window + this terminal);
//!                                                 --test-load adds BusyBox, Alpine and /test
//! cargo xtask debug  [--release] [--bios]         run, paused, with a GDB stub on :1234
//! cargo xtask try-install [--release] [--disk] [--new-disk] [--headless]
//!                                                 the installer in a QEMU window, on a virtual disk
//!                                                 that is kept (target/try-install-disk.img);
//!                                                 --disk boots the installed system instead,
//!                                                 --new-disk starts from an empty disk;
//!                                                 SLATE_USB_HOST=VID:PID hands it a host USB device
//! cargo xtask test   [--release] [--bios] [--timeout SECS] [--scenarios=NAME,...|none]
//! cargo xtask bench  [--release] [--bios]         the budgets: boot, RAM, size, shell start (ADR 0047), the desktop (ADR 0062),
//!                                                 at 4K too (ADR 0157); SLATE_BENCH=system|desktop|4k for one part
//! cargo xtask gpu-bench [--release] [--cmdline S] [--give-back]
//!                                                 Slate in a QEMU guest on the reference PC with its iGPU passed through
//!                                                 (VFIO, ADR 0168); --give-back returns the iGPU to Fedora
//! cargo xtask gpu-sources                         the GPU drivers' sources, pinned, into target/gpu/sources
//!                                                 (docs/gpu/SOURCES.md; SLATE_GPU_SOURCES=amd,nvidia,intel,dp)
//! cargo xtask soak   [--minutes N]                hours of mixed load, checked for leaks (ADR 0047)
//! cargo xtask check                               fmt, clippy (host + kernel + userland), host tests, difftest
//! cargo xtask difftest                            compare Slate's tools with GNU's on the host
//! cargo xtask sysroot                             slate-libc and its headers for tools/slate-cc (target/slate-sysroot)
//! cargo xtask accept   [--release]                acceptance runs (needs the internet; ADR 0024)
//! cargo xtask desktop  [--fresh] [--seat=B] [--accept]
//!                                                 Sway on Slate in QEMU (M18a; needs the internet once);
//!                                                 --accept runs only M18a's acceptance
//! cargo xtask linuxapp [--fresh]                  a Linux GUI program on Strata (M18d; needs the internet once)
//! cargo xtask flatpak  [--fresh] [--accept] [--measure]  Flatpak on Slate (ADR 0114; the internet): SLATE_FLATPAK_TRY=FILE
//!                                                 runs FILE's commands; --accept runs only its acceptance; --measure
//!                                                 times Linux apps' start-up, frames, keys and installs (M31);
//!                                                 --browser: Firefox in one click on a fresh system (M31);
//!                                                 --themed: a GTK app following Strata's theme (M31)
//! cargo xtask box      [--fresh] [--probe]        Linux boxes (M33, ADR 0183; the internet): the workbench (an Arch box);
//!                                                 SLATE_BOX_TRY=FILE runs FILE's commands on it; SLATE_BOX_PROBE=FILE
//!                                                 with --probe runs them beside Arch Linux's bootstrap root
//! cargo xtask sound    [--fresh] [--accept]       PipeWire on Slate (M30, ADR 0184; the internet once): alsa-lib's tools,
//!                                                 PipeWire and the PulseAudio server play into QEMU's recording
//! cargo xtask unicode                             the terminal's character widths from the UCD in $SLATE_UCD
//! cargo xtask keymaps                             the keyboard layouts from xkeyboard-config ($SLATE_XKB)
//! cargo xtask zones                               the time zone table from the tz database ($SLATE_TZDIR)
//! cargo xtask terminfo                            tput's capability order, from terminfo(5) and the host's tic
//! cargo xtask cacerts                             Mozilla's certificate authorities from curl.se (the internet)
//! ```

mod accept;
mod alongside;
mod alpine;
mod apps;
mod basepkg;
mod bench;
mod bluetooth;
mod boxes;
mod btfw;
mod btredir;
mod busybox;
mod cacerts;
mod desktop;
mod displays;
mod ext4img;
mod flatpak;
mod gpufw;
mod gpusources;
mod hostnet;
mod image;
mod initramfs;
mod iso;
mod keymaps;
mod limine;
mod linuxapp;
mod loader;
mod ltp;
mod packages;
mod profile;
mod qemu;
mod quarry;
mod refpc;
mod slatefsimg;
mod soak;
mod sound;
mod sshtest;
mod stress;
mod systools;
mod terminal;
mod terminfo;
mod tlstest;
mod trylive;
mod unicode;
mod user;
mod userland;
mod vnc;
mod wlmeasure;
mod zones;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::OnceLock;

/// The kernel's own core and alloc (KCFI, ADR 0096).
const KERNEL_BUILD_STD: &[&str] = &["-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem"];

/// Target triple the kernel is built for.
pub const KERNEL_TARGET: &str = "x86_64-unknown-none";
/// Slate's own programs' target (ADR 0063): the kernel's, with SSE2 and
/// the hardware floating-point ABI; core and alloc are built for it.
pub const USER_TARGET: &str = "x86_64-slate";

/// Arguments that make cargo build for [`USER_TARGET`].
pub fn user_target_args(c: &mut Command) -> &mut Command {
    c.arg("--target").arg(root().join("tools/x86_64-slate.json")).args([
        "-Zjson-target-spec",
        "-Zbuild-std=core,alloc",
        "-Zbuild-std-features=compiler-builtins-mem",
    ])
}

type Result<T = ()> = std::result::Result<T, String>;

#[derive(Clone, Debug, Default)]
struct Opts {
    release: bool,
    bios: bool,
    headless: bool,
    cmdline: Option<String>,
    timeout_secs: Option<u64>,
    /// Put the test load (BusyBox, Alpine, /test) in the disk image.
    test_load: bool,
    /// `desktop`: remake the cached workbench.
    fresh: bool,
    /// `desktop`: the libseat backend Sway uses.
    seat: Option<String>,
    /// `desktop`, `flatpak`: run the acceptance only.
    accept: bool,
    /// `flatpak`: measure Linux apps' start-up, frames and installs (M31).
    measure: bool,
    /// `flatpak`: Firefox in one click on a fresh system (M31).
    browser: bool,
    /// `flatpak`: a GTK app themed by Strata (M31).
    themed: bool,
    /// `box`: run SLATE_BOX_PROBE's commands beside Arch's root (M33).
    probe: bool,
    /// `try-install`: boot the virtual disk, not the install media.
    disk_only: bool,
    /// `try-install`: start from an empty virtual disk.
    new_disk: bool,
    /// `soak`: how long the load runs.
    minutes: Option<u64>,
    /// `test`: only these scenarios (`--scenarios=a,b`; `none` for the
    /// in-kernel tests and crash cases alone).
    scenarios: Option<Vec<String>>,
    /// `gpu-bench`: give the reference PC's iGPU back to Fedora's amdgpu.
    give_back: bool,
}

fn usage() -> String {
    let doc = include_str!("main.rs");
    let usage: Vec<&str> = doc
        .lines()
        .skip_while(|l| !l.starts_with("//! ```text"))
        .skip(1)
        .take_while(|l| !l.starts_with("//! ```"))
        .map(|l| l.trim_start_matches("//! "))
        .collect();
    format!("usage:\n  {}", usage.join("\n  "))
}

fn parse(args: &[String]) -> Result<(String, Opts)> {
    let mut it = args.iter();
    let cmd = it.next().ok_or_else(usage)?.clone();
    let mut o = Opts::default();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--release" => o.release = true,
            "--bios" => o.bios = true,
            "--headless" => o.headless = true,
            "--test-load" => o.test_load = true,
            "--fresh" => o.fresh = true,
            "--accept" => o.accept = true,
            "--measure" => o.measure = true,
            "--probe" => o.probe = true,
            "--browser" => o.browser = true,
            "--themed" => o.themed = true,
            "--disk" => o.disk_only = true,
            "--new-disk" => o.new_disk = true,
            "--give-back" => o.give_back = true,
            s if s.starts_with("--seat=") => o.seat = Some(s["--seat=".len()..].to_string()),
            s if s.starts_with("--scenarios=") => {
                let list: Vec<String> =
                    s["--scenarios=".len()..].split(',').filter(|n| !n.is_empty()).map(String::from).collect();
                o.scenarios = Some(list);
            }
            "--cmdline" => o.cmdline = Some(it.next().ok_or("--cmdline needs a value")?.clone()),
            "--minutes" => {
                let v = it.next().ok_or("--minutes needs a value")?;
                o.minutes = Some(v.parse().map_err(|_| format!("bad --minutes {v:?}"))?);
            }
            "--timeout" => {
                let v = it.next().ok_or("--timeout needs a value")?;
                o.timeout_secs = Some(v.parse().map_err(|_| format!("bad --timeout {v:?}"))?);
            }
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown option {other:?}\n{}", usage())),
        }
    }
    Ok((cmd, o))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = parse(&args).and_then(|(cmd, o)| match cmd.as_str() {
        "build" => build_kernel(o.release).map(|_| ()),
        "image" => {
            let img = image::build(&o, o.cmdline.as_deref().unwrap_or(""), "slate.img", image::Root::Disk)?;
            println!("{}", img.display());
            Ok(())
        }
        "iso" => iso::build(&o).map(|p| println!("{}", p.display())),
        "usb" => iso::usb(&o, false).and_then(|a| {
            let b = iso::usb(&o, true)?;
            println!("{}\n{}", a.display(), b.display());
            Ok(())
        }),
        "run" => qemu::run(&o, false),
        "debug" => qemu::run(&o, true),
        "try-install" => qemu::try_install(&o),
        "test" => qemu::test(&o),
        "check" => check(),
        "bench" => bench::bench(&o),
        "gpu-bench" => refpc::run(&o),
        "gpu-sources" => gpusources::fetch(),
        "soak" => soak::soak(&o),
        "difftest" => userland::difftest(),
        "sshtest" => {
            userland::build()?;
            sshtest::interop()
        }
        "tlstest" => {
            userland::build()?;
            tlstest::interop()
        }
        "sysroot" => userland::sysroot().map(|p| println!("{}", p.display())),
        "accept" => accept::run(&o),
        "desktop" if o.accept => desktop::accept(),
        "desktop" => desktop::run(o.fresh, o.seat.as_deref().unwrap_or("seatd")),
        "linuxapp" => linuxapp::run(o.fresh),
        "flatpak" if o.accept => flatpak::accept(),
        "flatpak" if o.measure => wlmeasure::measure(o.fresh),
        "flatpak" if o.browser => flatpak::browser_fresh(),
        "flatpak" if o.themed => flatpak::themed(),
        "flatpak" => flatpak::run(o.fresh),
        "box" if o.probe => boxes::probe(),
        "box" if o.accept => boxes::accept(),
        "box" => boxes::run(o.fresh),
        "sound" => sound::pipewire(o.fresh, o.accept),
        "unicode" => unicode::generate(),
        "keymaps" => keymaps::generate(),
        "zones" => zones::generate(),
        "terminfo" => terminfo::generate(),
        "cacerts" => cacerts::update(),
        _ => Err(usage()),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The workspace root (the parent of `tools/xtask`).
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2).unwrap().to_path_buf()
}

pub fn target_dir() -> PathBuf {
    root().join("target")
}

/// Run a command, failing with its description if it does not succeed.
pub fn run_cmd(cmd: &mut Command) -> Result {
    let status = cmd.status().map_err(|e| format!("failed to start {cmd:?}: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("{cmd:?} failed: {status}")) }
}

fn cargo() -> Command {
    let mut c = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

/// Build the kernel and return the path of the ELF file.
pub fn build_kernel(release: bool) -> Result<PathBuf> {
    static BUILT: [OnceLock<Result<PathBuf>>; 2] = [const { OnceLock::new() }; 2];
    once(&BUILT[release as usize], || {
        let mut c = cargo();
        c.args(["build", "--package", "slate-kernel", "--target", KERNEL_TARGET]);
        // core and alloc with the kernel's flags: KCFI must cover them
        // (ADR 0096).
        c.args(KERNEL_BUILD_STD);
        // The keys signed programs are checked against (ADR 0090).
        c.env("SLATE_TRUSTED_KEYS", quarry::dev_public_key_path()?);
        if release {
            c.arg("--release");
        }
        run_cmd(&mut c)?;
        let profile = if release { "release" } else { "debug" };
        Ok(target_dir().join(KERNEL_TARGET).join(profile).join("slate-kernel"))
    })
}

/// Builds of files that scenarios share (images, the install media, the
/// staging tree they come from) take turns: the gate runs scenarios side
/// by side (`qemu::test`), and two builds of the staging
/// tree at once would mix (ADR 0120). A thread that holds it may take it
/// again.
static BUILD: std::sync::Mutex<()> = std::sync::Mutex::new(());
thread_local! {
    static BUILD_HELD: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Held while a shared file is built (or built and copied).
#[derive(Debug)]
pub struct BuildGuard(#[allow(dead_code)] Option<std::sync::MutexGuard<'static, ()>>);

pub fn build_lock() -> BuildGuard {
    let held = BUILD_HELD.get();
    BUILD_HELD.set(held + 1);
    if held > 0 {
        return BuildGuard(None);
    }
    BuildGuard(Some(BUILD.lock().unwrap_or_else(|e| e.into_inner())))
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        BUILD_HELD.set(BUILD_HELD.get() - 1);
    }
}

/// What `f` gives the first time a run asks for it. Builds go through
/// this: every image of a test run takes the same kernel, programs and
/// loaders, and building them again (cargo, stripping, signing) is most
/// of what an image costs.
pub fn once<T: Clone + Send + Sync>(cell: &OnceLock<Result<T>>, f: impl FnOnce() -> Result<T>) -> Result<T> {
    cell.get_or_init(f).clone()
}

/// The kernel as images carry it: without its debug information (68 MB
/// in a debug build, which the ESP has no room for next to the test load).
/// Backtraces are resolved on the host with the unstripped file.
pub fn boot_kernel(release: bool) -> Result<PathBuf> {
    static BUILT: [OnceLock<Result<PathBuf>>; 2] = [const { OnceLock::new() }; 2];
    once(&BUILT[release as usize], || {
        let full = build_kernel(release)?;
        let boot = full.with_file_name("slate-kernel.boot");
        let fresh = match (std::fs::metadata(&full), std::fs::metadata(&boot)) {
            (Ok(f), Ok(b)) => b.modified().ok() >= f.modified().ok(),
            _ => false,
        };
        if !fresh {
            run_cmd(Command::new("objcopy").arg("--strip-debug").arg(&full).arg(&boot))?;
        }
        Ok(boot)
    })
}

/// Formatting, lints for both the host crates and the kernel target, and the
/// host unit tests. This is what "main stays green" means before a commit.
fn check() -> Result {
    run_cmd(cargo().args(["fmt", "--all", "--check"]))?;
    run_cmd(cargo().args(["clippy", "--all-targets", "--", "-D", "warnings"]))?;
    run_cmd(
        cargo()
            .args(["clippy", "--package", "slate-kernel", "--target", KERNEL_TARGET])
            .args(KERNEL_BUILD_STD)
            .args(["--", "-D", "warnings"]),
    )?;
    // The vDSO is a Linux user-space shared object (built by kernel/build.rs).
    run_cmd(cargo().args([
        "clippy",
        "--package",
        "slate-vdso",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--",
        "-D",
        "warnings",
        "-C",
        "panic=abort",
    ]))?;
    // slate-loader for UEFI (ADR 0089).
    run_cmd(cargo().args(["clippy", "--package", "slate-loader-uefi", "--target", loader::UEFI_TARGET]).args([
        "-Zbuild-std=core,alloc",
        "-Zbuild-std-features=compiler-builtins-mem",
        "--",
        "-D",
        "warnings",
    ]))?;
    // slate-loader for BIOS, on the userland's target made static.
    run_cmd(
        cargo()
            .args(["clippy", "--package", "slate-loader-bios", "--target"])
            .arg(root().join("tools/x86_64-slate-loader.json"))
            .args(["-Zjson-target-spec", "-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem"])
            .args(["--", "-D", "warnings"]),
    )?;
    run_cmd(cargo().args(["test", "--quiet"]))?;
    // Slate's own programs: lints for their target, unit tests of their
    // pure parts on the host, and the comparison with GNU tools.
    let mut clippy = cargo();
    user_target_args(clippy.arg("clippy"));
    let mut tests = cargo();
    tests.args(["test", "--quiet", "--package", "slate-rt", "--lib"]);
    let mut packages: Vec<&str> = userland::PROGRAMS.iter().map(|p| p.package).collect();
    packages.dedup();
    // Userland libraries that are no program of their own.
    packages.push("slate-tui");
    packages.push("slate-ui");
    packages.push("slate-strata");
    packages.push("slate-display");
    packages.push("slate-strata-client");
    packages.push("slate-sysinfo");
    packages.push("slate-terminal");
    for p in packages {
        clippy.args(["--package", p]);
        tests.args(["--package", p]);
    }
    // slate-libc builds for Slate too (its host tests ran with the
    // workspace's).
    clippy.args(["--package", "slate-libc"]);
    run_cmd(clippy.args(["--", "-D", "warnings"]))?;
    run_cmd(&mut tests)?;
    userland::difftest()?;
    userland::native_on_host()?;
    sshtest::interop()?;
    tlstest::interop()
}
