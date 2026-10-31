// SPDX-License-Identifier: MIT OR Apache-2.0

//! Sway on Slate (M18a, ADR 0033). An Alpine workbench disk with Sway,
//! swaybg, foot, a font and D-Bus (made once, cached in target/desktop;
//! `--fresh` remakes it; needs the internet) is mounted in a Slate machine
//! in Linux compatibility mode, and Sway starts there with the pixman
//! renderer through Slate's seatd and opens foot.
//!
//! `cargo xtask desktop` reports what Sway logged, what the kernel did not
//! implement, and a screenshot. `accept` is M18a's acceptance (part of
//! `cargo xtask accept`): on virtio-gpu, foot must be in Sway's tree and on
//! the screen, typing must reach its shell, and both D-Bus buses must
//! answer. The firmware framebuffer is run and reported too, but a known
//! bug there (foot's first start sometimes crashes) does not fail it
//! (ADR 0033, docs/GAPS.md).
//!
//! Debugging switches for `cargo xtask desktop`: `SLATE_DESKTOP_GPU=1`
//! uses virtio-gpu instead of the firmware framebuffer,
//! `SLATE_DESKTOP_CMDLINE` adds kernel arguments (`quiet
//! slate.strace=foot`), `SLATE_DESKTOP_DMESG=N` prints the kernel log's
//! last N lines, `SLATE_DESKTOP_SETUP` runs a command after mounting the
//! workbench (for example a foot.ini under /w/root/.config/foot).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::qemu::{Console, monitor, ppm_pixel, screendump, type_keys};
use crate::{Opts, Result, image, run_cmd, target_dir};

/// Alpine packages for the desktop check.
pub const PACKAGES: &str = "sway swaybg foot font-dejavu dbus";

/// Sway's configuration for the check: open foot, nothing else.
pub const SWAY_CONFIG: &str = "# M18a check (ADR 0033)\n\
    xwayland disable\n\
    output * bg #204060 solid_color\n\
    exec foot\n";

/// Mount the workbench (/dev/vdb) at /w with what a chroot needs; /run
/// is shared, for devd's device database.
pub const MOUNT_WORKBENCH: &str = "mkdir -p /w && mount -t ext4 /dev/vdb /w && mount -t proc proc /w/proc \
    && mount -t devtmpfs dev /w/dev && mount -t devpts devpts /w/dev/pts && mount -t tmpfs tmpfs /w/tmp \
    && mount -o bind /run /w/run && mount -t sysfs sys /w/sys && cp /etc/resolv.conf /w/etc/";

/// Start Sway in the workbench; its log goes to /w/tmp/sway.log.
pub const START_SWAY: &str = "chroot /w /bin/sh -c 'mkdir -p -m 0700 /tmp/xdg; \
    XDG_RUNTIME_DIR=/tmp/xdg WLR_RENDERER=pixman LIBSEAT_BACKEND=${SEAT:-seatd} \
    sway -d -c /root/sway.conf > /tmp/sway.log 2>&1 &'";

fn workbench(fresh: bool) -> Result<PathBuf> {
    make_workbench("desktop", PACKAGES, &[("root/sway.conf", SWAY_CONFIG)], fresh)
}

/// An Alpine workbench disk with `packages` and `files` (path in the
/// root, contents), made once in target/`name` (`fresh` remakes it; needs
/// the internet): apk runs inside a Slate machine.
pub fn make_workbench(name: &str, packages: &str, files: &[(&str, &str)], fresh: bool) -> Result<PathBuf> {
    let dir = target_dir().join(name);
    let img = dir.join("workbench.img");
    // What the workbench was made from: another list remakes it.
    let mut stamp = format!("{packages}\n");
    for (path, contents) in files {
        stamp += &format!("{path}\n{contents}\n");
    }
    let same = std::fs::read_to_string(dir.join("stamp")).is_ok_and(|s| s == stamp);
    if img.exists() && same && !fresh {
        return Ok(img);
    }
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stage = dir.join("root");
    run_cmd(Command::new("cp").arg("-a").arg(crate::alpine::fetch()?).arg(&stage))?;
    let setup = format!("#!/bin/sh\nset -e\napk update -q\napk add -q {packages}\necho setup-ok\n");
    std::fs::write(stage.join("setup.sh"), setup).map_err(|e| e.to_string())?;
    for (path, contents) in files {
        std::fs::write(stage.join(path), contents).map_err(|e| e.to_string())?;
    }
    let building = dir.join("building.img");
    run_cmd(
        Command::new("unshare")
            .args(["-r", "mkfs.ext4", "-q", "-F", "-b", "4096", "-L", "workbench", "-d"])
            .arg(&stage)
            .arg(&building)
            .arg("4G"),
    )?;
    let mut con = boot(&building, None, false)?;
    let r = (|| -> Result {
        con.login()?;
        con.run(&format!("{MOUNT_WORKBENCH} && chroot /w /bin/sh /setup.sh"), "setup-ok", 900)?;
        con.run("sync; umount -l /w", "", 30)?;
        con.poweroff()
    })();
    if let Err(e) = r {
        con.kill();
        return Err(format!("{name}: making the workbench: {e}"));
    }
    std::fs::rename(&building, &img).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("stamp"), stamp).map_err(|e| e.to_string())?;
    Ok(img)
}

/// A Slate machine with compatibility mode on, the workbench as /dev/vdb
/// and, if given, its monitor at `mon`; the display is virtio-gpu when
/// `gpu`, else the firmware framebuffer.
pub fn boot(workbench: &Path, mon: Option<&Path>, gpu: bool) -> Result<Console> {
    boot_with(workbench, mon, gpu, "")
}

/// [`boot`], with `extra` on the kernel's command line too.
pub fn boot_with(workbench: &Path, mon: Option<&Path>, gpu: bool, extra: &str) -> Result<Console> {
    boot_full(workbench, mon, gpu, extra, None)
}

/// [`boot`] with an HD Audio card recording to `wav` (never the host's
/// speakers).
pub fn boot_with_sound(workbench: &Path, mon: Option<&Path>, wav: &Path) -> Result<Console> {
    boot_full(workbench, mon, false, "", Some(wav))
}

fn boot_full(workbench: &Path, mon: Option<&Path>, gpu: bool, extra: &str, wav: Option<&Path>) -> Result<Console> {
    let o = Opts::default();
    let cmdline = format!("slate.compat=on {extra} {}", std::env::var("SLATE_DESKTOP_CMDLINE").unwrap_or_default());
    let img = image::build(&o, cmdline.trim(), "slate-desktop.img", image::Root::Disk)?;
    let mut c = crate::qemu::base_command(&o, &img)?;
    crate::qemu::add_disk(&mut c, 0, workbench);
    if gpu {
        c.args(["-vga", "none", "-device", "virtio-gpu-pci"]);
    }
    match wav {
        Some(w) => {
            c.arg("-audiodev")
                .arg(format!("wav,id=snd0,path={},out.frequency=48000,out.channels=2,out.format=s16", w.display()));
            c.args(["-device", "intel-hda,id=sound0", "-device", "hda-duplex,audiodev=snd0,bus=sound0.0"]);
        }
        None => crate::qemu::sound_card(&mut c)?,
    }
    c.args(["-device", "virtio-tablet-pci", "-display", "none", "-serial", "stdio", "-monitor"]);
    match mon {
        Some(m) => c.arg(format!("unix:{},server,nowait", m.display())),
        None => c.arg("none"),
    };
    Console::start(c)
}

/// How many foot windows Sway's tree has, as `tree<N>`.
const FOOT_WINDOWS: &str = "echo tree$(chroot /w /bin/sh -c 'XDG_RUNTIME_DIR=/tmp/xdg \
    SWAYSOCK=$(ls /tmp/xdg/sway-ipc.*.sock 2>/dev/null) swaymsg -t get_tree 2>/dev/null' \
    | grep -c '\"app_id\": \"foot\"')";

/// D-Bus in the Linux domain: start the system bus and a session bus;
/// prints `dbus-ok2` when the system bus tells its ID and the session
/// bus lists its names.
const DBUS: &str = "chroot /w /bin/sh -c 'mkdir -p /run/dbus; dbus-daemon --system --fork; \
    export DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --session --fork --print-address=1); \
    s=$(dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.GetId | grep -c string); \
    t=$(dbus-send --session --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus \
    org.freedesktop.DBus.ListNames | grep -c org.freedesktop.DBus); \
    echo system $s session $t; [ $s = 1 ] && [ $t -gt 0 ] && echo dbus-ok$((1+1))'";

/// Start Sway with libseat backend `seat` and wait (up to 20 s) for foot.
fn start(con: &mut Console, seat: &str) -> Result {
    con.run(&format!("{MOUNT_WORKBENCH} && echo mounted$((1+1))"), "mounted2", 30)?;
    if let Ok(setup) = std::env::var("SLATE_DESKTOP_SETUP") {
        con.run(&setup, "", 30)?;
    }
    con.run(&format!("SEAT={seat} {START_SWAY}; echo started$((1+1))"), "started2", 30)?;
    con.run(
        &format!("for i in $(seq 40); do {FOOT_WINDOWS} | grep -q tree1 && break; sleep 0.5; done; {FOOT_WINDOWS}"),
        "tree",
        60,
    )
}

/// Run Sway with libseat backend `seat` and report what happened.
pub fn run(fresh: bool, seat: &str) -> Result {
    let started = Instant::now();
    let wb = workbench(fresh)?;
    let mon = target_dir().join("desktop-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = boot(&wb, Some(&mon), std::env::var("SLATE_DESKTOP_GPU").is_ok())?;
    let r = (|| -> Result {
        con.login()?;
        start(&mut con, seat)?;
        con.run("head -n 20 /run/udev/data/*", "", 10)?;
        con.run("grep -a 'libseat\\|ERROR' /w/tmp/sway.log | head -n 20; tail -n 25 /w/tmp/sway.log", "", 10)?;
        con.run("grep -a 'backend/drm' /w/tmp/sway.log | head -n 40", "", 10)?;
        con.run("dmesg | grep -ai 'unimplemented\\|drm: \\|enotty\\|einval' | tail -n 30", "", 10)?;
        con.run("dmesg | grep -a -A1 ': SIG' | tail -n 10", "", 10)?;
        if let Ok(n) = std::env::var("SLATE_DESKTOP_DMESG") {
            con.run(&format!("dmesg | tail -n {n}"), "", 120)?;
        }
        // foot's anonymous mappings, to place addresses from a fault log.
        con.run(
            "for d in /proc/[0-9]*; do grep -q '^Name:.foot' $d/status 2>/dev/null && cat $d/maps; done \
             | grep -v ' /'",
            "",
            10,
        )?;
        con.run(DBUS, "system", 20)?;
        con.run(&format!("ps | grep -c '[f]oot'; {FOOT_WINDOWS}"), "tree", 15)?;
        con.run("grep -h -A0 '^Threads' $(grep -l '^Name:.foot' /proc/[0-9]*/status)", "", 10)?;
        let shot = screendump(&mon, "desktop.ppm")?;
        println!("xtask: desktop: screenshot in {}", shot.display());
        monitor(&mon, &[])?;
        con.poweroff()
    })();
    std::fs::write(target_dir().join("desktop.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("desktop: {e} (transcript in target/desktop.log)"));
    }
    println!("xtask: desktop run done ({:.0}s); transcript in target/desktop.log", started.elapsed().as_secs_f64());
    Ok(())
}

/// Sway's default colour for a focused window's title bar, and foot's
/// default background.
const TITLE_FOCUSED: [u8; 3] = [0x28, 0x55, 0x77];
const FOOT_BACKGROUND: [u8; 3] = [0x24, 0x24, 0x24];

/// M18a's acceptance on one display; returns the names of failed checks.
fn accept_on(wb: &Path, gpu: bool, dir: &Path) -> Result<Vec<String>> {
    let display = if gpu { "virtio_gpu" } else { "framebuffer" };
    let mon = dir.join(format!("{display}.sock"));
    let _ = std::fs::remove_file(&mon);
    let mut con = boot(wb, Some(&mon), gpu)?;
    let mut failed = Vec::new();
    // The firmware framebuffer is not part of the acceptance (ADR 0033):
    // foot sometimes crashes at its first start there (docs/GAPS.md), so
    // its failures are reported as known, not counted.
    let mut report = |name: String, ok: bool| {
        let verdict = match (ok, gpu) {
            (true, _) => "PASS",
            (false, true) => "FAIL",
            (false, false) => "KNOWN",
        };
        println!("ACCEPT: {verdict} m18a::{name}");
        if !ok && gpu {
            failed.push(name);
        }
    };
    let r = (|| -> Result {
        con.login()?;
        start(&mut con, "seatd")?;
        let seatd = con.run("echo seatd$(grep -c \"Seat opened with backend 'seatd'\" /w/tmp/sway.log)", "seatd1", 10);
        report(format!("{display}_seatd"), seatd.is_ok());
        // M26 (ADR 0100): wlroots drives the card through atomic KMS.
        let atomic = con.run("echo atomic$(grep -c 'Using atomic DRM interface' /w/tmp/sway.log)", "atomic1", 10);
        report(format!("{display}_atomic_kms"), atomic.is_ok());
        report(format!("{display}_foot_window"), con.run(FOOT_WINDOWS, "tree1", 15).is_ok());
        let shot = screendump(&mon, &format!("accept/{display}.ppm"))?;
        let title = ppm_pixel(&shot, 640, 5)?;
        let inside = ppm_pixel(&shot, 640, 400)?;
        report(format!("{display}_foot_on_screen"), title == TITLE_FOCUSED && inside == FOOT_BACKGROUND);
        // Keys from QEMU's keyboard reach foot's shell through evdev,
        // libinput and Sway.
        type_keys(&mon, "touch /tmp/typed\n")?;
        let typed = con.run(
            "for i in $(seq 50); do [ -e /w/tmp/typed ] && break; sleep 0.1; done; [ -e /w/tmp/typed ] && echo typed$((1+1))",
            "typed2",
            15,
        );
        report(format!("{display}_typing"), typed.is_ok());
        if gpu {
            report("dbus".into(), con.run(DBUS, "dbus-ok2", 20).is_ok());
        }
        con.run("tail -n 5 /w/tmp/sway.log", "", 10)?;
        con.poweroff()
    })();
    std::fs::write(dir.join(format!("{display}.log")), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("m18a on the {display}: {e}"));
    }
    Ok(failed)
}

/// M18a's acceptance: Sway with software rendering in compatibility mode
/// opens foot on virtio-gpu (a fresh workbench; needs the internet). The
/// firmware framebuffer runs too, reported but not counted (ADR 0033).
pub fn accept() -> Result {
    let dir = target_dir().join("accept");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    println!("xtask: accept: M18a: making the desktop workbench ({PACKAGES})");
    let wb = workbench(true)?;
    let mut failed = accept_on(&wb, true, &dir)?;
    // A crash there can stop the run early: report it, don't fail on it.
    match accept_on(&wb, false, &dir) {
        Ok(known) => failed.extend(known),
        Err(e) => println!("ACCEPT: KNOWN m18a::framebuffer ({e})"),
    }
    if !failed.is_empty() {
        return Err(format!("M18a acceptance checks failed: {} (logs in {})", failed.join(", "), dir.display()));
    }
    println!(
        "xtask: accept: M18a passed (Sway and foot through seatd on virtio-gpu, typing, D-Bus; the firmware \
         framebuffer is a known open bug, docs/GAPS.md)"
    );
    Ok(())
}
