// SPDX-License-Identifier: MIT OR Apache-2.0

//! Flatpak and AppImage on Slate (M28 phase 7, ADR 0114). Flatpak is
//! Linux software (ADR 0022): `flatpak`, `bwrap` and OSTree come from
//! Alpine into the Linux runtime, as Firefox does (ADR 0038), and run in
//! the Linux domain with their own sandbox.
//!
//! The workbench is the Linux runtime made by `slate-linux setup` with
//! Flatpak's packages, on a disk of its own (made once, cached in
//! target/flatpak; `--fresh` remakes it; needs the internet). Each run
//! works on a copy, so installs start from the same place.
//!
//! `SLATE_FLATPAK_TRY=FILE cargo xtask flatpak` runs FILE's lines in a
//! Slate machine with the workbench mounted, one command each, and keeps
//! the transcript (target/flatpak/try.log) with what the kernel did not
//! implement: how Flatpak's needs are found.
//!
//! `accept` (part of `cargo xtask accept`) is the phase's acceptance: an
//! app from Flathub installed, downgraded to its parent commit, offered
//! as an update, updated and rolled back with `slate-flatpak`; its window
//! in the person's own Strata session (a console login) from Flatpak's
//! sandbox, opened from the launcher; its launcher entry exported; an
//! AppImage run with `slate-appimage`; the app removed; then installed
//! for everyone by root (`--system`), seen by the person with its
//! launcher entry, and removed. Then the Web
//! Browser (ADR 0115): Firefox fetched from Flathub on first use (its
//! description checked against the pinned key), a page loaded in it in
//! Strata with every Firefox process under seccomp (its own sandbox,
//! inside Flatpak's), and a background update run once and not again.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use crate::hostnet::StaticServer;
use crate::qemu::{Console, PROMPT};
use crate::{Result, run_cmd, target_dir};

/// Alpine packages for the Flatpak workbench: Flatpak (with bubblewrap
/// and OSTree), D-Bus for its session bus, Sway for its windows, and the
/// person's sound server (ADR 0185).
pub const PACKAGES: &str = "sway xwayland font-dejavu flatpak dbus pipewire wireplumber pipewire-pulse";

/// The app the acceptance installs: small, and a window of its own.
const APP: &str = "fi.skyjake.Lagrange";
/// The AppImage it runs (a pinned release; a command-line one).
const APPIMAGE: &str = "https://github.com/AppImage/appimagetool/releases/download/1.9.0/appimagetool-x86_64.AppImage";
/// The person the acceptance runs as, and their home.
const PERSON: &str = "ada";
const PERSON_HOME: &str = "/home/fp/ada";
/// The person's password, for their console login.
const PERSON_PASSWORD: &str = "fp-ada-pw";
/// The big disk's home directory (the root is small for runtimes).
const HOME: &str =
    "mkdir -p /mnt/workbench/fphome /home/fp && mount -o bind /mnt/workbench/fphome /home/fp && echo bound$((1+1))";

/// The workbench disk, with the runtime in a directory of it, reached
/// through a link: as on an installed system, the runtime is not a
/// mount point of its own (bubblewrap's pivot_root needs slate-linux to
/// make it one; a disk mounted at the runtime hid that).
pub const MOUNT: &str = "mkdir -p /mnt/workbench /var/lib/slate && mount -t ext4 /dev/vdb /mnt/workbench && \
    mkdir -p /mnt/workbench/linux && ln -sfn /mnt/workbench/linux /var/lib/slate/linux && echo mounted$((1+1))";

/// The workbench's layout, in its stamp: a new one makes it again.
const LAYOUT: &str = "layout 2: the runtime in linux/";

fn dir() -> PathBuf {
    target_dir().join("flatpak")
}

/// The runtime with Flatpak's packages, made once.
pub fn workbench(fresh: bool) -> Result<PathBuf> {
    let dir = dir();
    let img = dir.join("workbench.img");
    let stamp = format!("slate-linux setup {PACKAGES}\n{LAYOUT}\n");
    let same = std::fs::read_to_string(dir.join("stamp")).is_ok_and(|s| s == stamp);
    if img.exists() && same && !fresh {
        return Ok(img);
    }
    let _ = std::fs::remove_file(&img);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let building = dir.join("building.img");
    let _ = std::fs::remove_file(&building);
    // 24 GiB, sparse: Flatpak's runtimes are large.
    run_cmd(Command::new("mkfs.ext4").args(["-q", "-F", "-b", "4096", "-L", "linux"]).arg(&building).arg("24G"))?;
    let mirror = dir.join("mirror");
    std::fs::create_dir_all(&mirror).map_err(|e| e.to_string())?;
    std::fs::copy(crate::alpine::tarball()?, mirror.join("minirootfs.tar.gz")).map_err(|e| e.to_string())?;
    let server = StaticServer::start(mirror)?;
    let mut con = crate::desktop::boot(&building, None, false)?;
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 30)?;
        con.run(
            &format!(
                "slate-linux setup --from http://10.0.2.2:{}/minirootfs.tar.gz {PACKAGES} && echo setup-ok$((1+1))",
                server.port
            ),
            "setup-ok2",
            1500,
        )?;
        con.run("sync; umount -l /mnt/workbench", "", 30)?;
        con.poweroff()
    })();
    server.stop();
    std::fs::write(dir.join("setup.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak: slate-linux setup: {e} (transcript in target/flatpak/setup.log)"));
    }
    std::fs::rename(&building, &img).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("stamp"), stamp).map_err(|e| e.to_string())?;
    Ok(img)
}

/// A copy of the workbench to change (sparse, so quick).
pub fn scratch_copy(wb: &PathBuf, name: &str) -> Result<PathBuf> {
    let copy = dir().join(name);
    let _ = std::fs::remove_file(&copy);
    run_cmd(Command::new("cp").arg("--sparse=always").arg(wb).arg(&copy))?;
    Ok(copy)
}

/// What the kernel left out, at the end of a transcript.
pub fn kernel_notes(con: &mut Console) -> Result {
    con.run("dmesg | grep -ai 'unimplemented\\|unsupported\\|not implemented' | sort | uniq -c | tail -n 40", "", 10)?;
    con.run("dmesg | grep -a ': SIG' | tail -n 10", "", 10)?;
    Ok(())
}

/// `cargo xtask flatpak`: with SLATE_FLATPAK_TRY=FILE, FILE's commands.
pub fn run(fresh: bool) -> Result {
    let started = Instant::now();
    let wb = workbench(fresh)?;
    let Ok(file) = std::env::var("SLATE_FLATPAK_TRY") else {
        println!("xtask: flatpak: the workbench is {} (SLATE_FLATPAK_TRY=FILE runs commands on it)", wb.display());
        return Ok(());
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
    // SLATE_FLATPAK_KEEP=1 tries on from the last try's disk.
    let kept = dir().join("try.img");
    let disk = if std::env::var_os("SLATE_FLATPAK_KEEP").is_some() && kept.exists() {
        kept
    } else {
        scratch_copy(&wb, "try.img")?
    };
    let mut con = crate::desktop::boot(&disk, None, false)?;
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 30)?;
        // SLATE_FLATPAK_LINE_SECS limits each command (600 s by default).
        let secs = std::env::var("SLATE_FLATPAK_LINE_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(600);
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            // Each command ends with a marker its echo doesn't show.
            // (A line that ends in `&` already ends its command.)
            let marker = "tr''ied";
            let sep = if line.ends_with('&') { " " } else { "; " };
            if let Err(e) = con.run(&format!("{line}{sep}echo {marker}-$?"), "tried-", secs) {
                con.log.push_str(&format!("\n[xtask: {e}]\n"));
                // Ctrl-C, and on with the next one.
                let _ = con.send("\x03\r");
            }
            // The transcript so far, in case a later command hangs.
            let _ = std::fs::write(dir().join("try.log"), crate::qemu::strip_ansi(&con.log));
        }
        kernel_notes(&mut con)?;
        con.poweroff()
    })();
    std::fs::write(dir().join("try.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak: {e} (transcript in target/flatpak/try.log)"));
    }
    println!(
        "xtask: flatpak: tried {file} ({:.0}s); transcript in target/flatpak/try.log",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// `cmd` run by the person, not root: written to a script in their home
/// (so its quotes stay as they are), then run with `su`.
fn as_person(cmd: &str) -> String {
    format!(
        "printf '%s\\n' '{}' > {PERSON_HOME}/.step.sh && su {PERSON} -c 'sh {PERSON_HOME}/.step.sh'",
        cmd.replace('\'', "'\\''")
    )
}

/// The acceptance's checks, in order; each one's name and outcome. They
/// run as a person (Flatpak installs are theirs), with their home on the
/// workbench's big disk.
fn checks(con: &mut Console, mon: &std::path::Path) -> Result<Vec<(&'static str, bool)>> {
    let mut out = Vec::new();
    con.run(HOME, "bound2", 30)?;
    con.run(&format!("useradd -m -d {PERSON_HOME} {PERSON} && echo added$((1+1))"), "added2", 30)?;
    // Installed from Flathub (the remote added on the way).
    let ok = con
        .run(&as_person(&format!("slate-flatpak install {APP} && echo installed$((1+1))")), "installed2", 2400)
        .is_ok();
    out.push(("install", ok));
    if !ok {
        return Ok(out);
    }
    // Its entry, where the launcher looks.
    out.push((
        "launcher-entry",
        con.run(
            &format!("ls {PERSON_HOME}/.local/share/flatpak/exports/share/applications/"),
            &format!("{APP}.desktop"),
            20,
        )
        .is_ok(),
    ));
    // Back to the commit before, so that an update is on offer.
    let flatpak = "mkdir -p /tmp/xdg-$(id -u) && chmod 700 /tmp/xdg-$(id -u); /usr/bin/flatpak --user";
    let parent = con
        .send(&format!(
            "{}\r",
            as_person(&format!(
                "slate-linux run /bin/sh -c '{flatpak} remote-info flathub {APP} | grep Parent: | sed \"s/.*: *//\" | xargs printf \"%s=%s\\n\" older'"
            ))
        ))
        .and_then(|()| con.line_after("older=", 300));
    con.wait_for(PROMPT, 30)?;
    let parent = parent.ok().filter(|p| p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    out.push(("parent-commit", parent.is_some()));
    let Some(parent) = parent else { return Ok(out) };
    out.push((
        "downgrade",
        con.run(
            &as_person(&format!(
                "slate-linux run /bin/sh -c '{flatpak} update -y --noninteractive --commit={parent} {APP}' && echo downgraded$((1+1))"
            )),
            "downgraded2",
            1200,
        )
        .is_ok(),
    ));
    // On offer: the status line's fourth field isn't "-".
    let offered = con
        .send(&format!("{}\r", as_person("slate-flatpak status")))
        .and_then(|()| con.line_after(&format!("{APP}\t"), 300))
        .is_ok_and(|l| l.split('\t').nth(2).is_some_and(|n| n != "-"));
    con.wait_for(PROMPT, 30)?;
    out.push(("update-offered", offered));
    out.push(("update", con.run(&as_person("slate-flatpak update && echo updated$((1+1))"), "updated2", 1200).is_ok()));
    // The update kept the version before; the rollback returns to it.
    out.push((
        "rollback",
        con.run(&as_person(&format!("slate-flatpak rollback {APP}")), &format!("back to {parent}"), 1200).is_ok(),
    ));
    out.push(("rolled-back", con.run(&as_person("slate-flatpak list"), &parent[..12], 120).is_ok()));
    out.push(("sound", sound_check(con)?));
    // Its window in the person's own Strata, from Flatpak's sandbox,
    // titled by the app: root logs out, the person logs in on the console
    // (a console session, which seatd gives the display), their profile
    // starts Strata (where the desktop is installed: /etc/slate/session),
    // and the launcher opens the app from its exported entry. Strata's
    // output is the console's.
    con.run(
        &format!("touch /etc/slate/session && usermod -aG seat {PERSON} && printf '{PERSON_PASSWORD}\\n' | passwd --stdin {PERSON} > /dev/null && echo pw$((1+1))"),
        "pw2",
        30,
    )?;
    con.send("exit\r")?;
    con.wait_for("login: ", 60)?;
    con.send(&format!("{PERSON}\r"))?;
    con.wait_for("Password: ", 15)?;
    con.send(&format!("{PERSON_PASSWORD}\r"))?;
    let session = con.wait_for(" at scale ", 90);
    let window = session.and_then(|()| {
        std::thread::sleep(std::time::Duration::from_millis(2000));
        crate::qemu::monitor(mon, &["sendkey meta_l-spc"])?;
        std::thread::sleep(std::time::Duration::from_millis(600));
        crate::qemu::type_keys(mon, "lagrange\n")?;
        con.wait_for_all(&["(linux, sandboxed)", "title \"Lagrange"], 240)
    });
    out.push(("window", window.is_ok()));
    // Leave Strata (super + shift + e): the person's session ends, and
    // root logs in again for the rest. (If Strata never started, the
    // person's shell is still there: it is left too.)
    let _ = crate::qemu::monitor(mon, &["sendkey meta_l-shift-e"]);
    if con.wait_for("login: ", 20).is_err() {
        con.send("\rexit\r")?;
        con.wait_for("login: ", 60)?;
    }
    // With the desktop installed, the console's login asks for a password
    // even when there is none (root's here): an empty line answers it, or
    // is an empty command.
    con.send("root\r")?;
    std::thread::sleep(std::time::Duration::from_millis(1500));
    con.send("\r")?;
    con.wait_for(PROMPT, 30)?;
    // An AppImage on the terminal.
    let fetched = con
        .run(
            &as_person(&format!(
                "slate-linux run wget -q -O {PERSON_HOME}/tool.AppImage {APPIMAGE} && echo fetched$((1+1))"
            )),
            "fetched2",
            300,
        )
        .is_ok();
    out.push((
        "appimage",
        fetched
            && con
                .run(
                    &as_person(&format!("slate-appimage {PERSON_HOME}/tool.AppImage --version")),
                    "appimagetool, ",
                    900,
                )
                .is_ok(),
    ));
    out.push((
        "remove",
        con.run(&as_person(&format!("slate-flatpak remove {APP} && echo removed$((1+1))")), "removed2", 300).is_ok(),
    ));
    system_checks(con, &mut out)?;
    browser_checks(con, &mut out)?;
    Ok(out)
}

/// The person's sound server (ADR 0185) as Strata starts it at login,
/// and the app's sandbox playing a 660 Hz tone through it for 2 s (Flatpak
/// hands the sandbox its PulseAudio socket; the tone is looked for in
/// QEMU's recording afterwards). The server stops after.
fn sound_check(con: &mut Console) -> Result<bool> {
    con.run(
        &format!(
            "usermod -aG seat {PERSON} && mkdir -p -m 0755 /run/user && \
             install -d -m 0700 -o {PERSON} -g {PERSON} /run/user/$(id -u {PERSON}) && echo rundir$((1+1))"
        ),
        "rundir2",
        30,
    )?;
    con.run(
        &format!(
            "su {PERSON} -c 'slate-linux sound' > /tmp/person-sound.log 2>&1 & \
             for i in $(seq 100); do [ -S /run/user/$(id -u {PERSON})/pulse/native ] && break; sleep 0.2; done; \
             ls /run/user/$(id -u {PERSON})/pulse"
        ),
        "native",
        40,
    )?;
    let played = con
        .run(
            &as_person(&format!(
                "slate-linux run flatpak run --command=sh {APP} -c 'pactl info | grep -i server.name; \
                 gst-launch-1.0 -q audiotestsrc freq=660 num-buffers=86 ! audio/x-raw,rate=44100 ! pulsesink \
                 && echo played-$((600+60))'"
            )),
            "played-660",
            180,
        )
        .is_ok();
    con.run("kill %1; wait; echo quiet$((1+1))", "quiet2", 20)?;
    Ok(played)
}

/// The system installation (ADR 0114's addendum): root installs the app
/// for everyone; the person sees it and its launcher entry (read through
/// the exported link, as Strata does); a person's change goes to the
/// broker, which has no approval agent on a console (the person's
/// Strata has ended: "did not answer" once, then "no approval agent");
/// root removes it.
fn system_checks(con: &mut Console, out: &mut Vec<(&'static str, bool)>) -> Result {
    let ok = con
        .run(&format!("slate-flatpak --system install {APP} && echo sysinstalled$((1+1))"), "sysinstalled2", 2400)
        .is_ok();
    out.push(("system-install", ok));
    let entry = format!("/var/lib/slate/linux/var/lib/flatpak/exports/share/applications/{APP}.desktop");
    out.push((
        "system-entry",
        ok && con
            .run(
                &as_person(&format!(
                    "slate-flatpak --system list | grep -q {APP} && grep -q ^Exec= {entry} && echo sysentry$((1+1))"
                )),
                "sysentry2",
                300,
            )
            .is_ok(),
    ));
    out.push((
        "system-asks",
        ok && con.run(&as_person(&format!("slate-flatpak --system remove {APP}")), "approval agent", 120).is_ok(),
    ));
    out.push((
        "system-remove",
        ok && con
            .run(&format!("slate-flatpak --system remove {APP} && echo sysremoved$((1+1))"), "sysremoved2", 300)
            .is_ok(),
    ));
    Ok(())
}

/// Firefox's processes counted, and those without a seccomp filter
/// (proc(5): `Seccomp: 2` is filter mode).
const SANDBOX_CHECK: &str = r#"n=0; bad=0; for p in /proc/[0-9]*; do case "$(cat $p/comm 2>/dev/null)" in *Content*|*Isolated*|firefox*|*Socket*|*RDD*|*Utility*|*Privileged*|*WebExt*) n=$((n+1)); grep -q 'Seccomp:.2' $p/status || bad=$((bad+1));; esac; done; echo "fire""fox=$n unsandboxed=$bad""#;

/// The Web Browser (ADR 0115), as root with its home on the big disk
/// (a window needs root's Strata, as above).
fn browser_checks(con: &mut Console, out: &mut Vec<(&'static str, bool)>) -> Result {
    let h = "HOME=/home/fp";
    // First use, on the terminal: Flathub's description fetched and
    // checked, Firefox installed, the choice kept.
    let ok = con.run(&format!("{h} web-browser --get"), "web-browser: Firefox is ready", 1800).is_ok();
    out.push(("browser-get", ok));
    if !ok {
        return Ok(());
    }
    out.push((
        "flathub-pinned",
        con.run("grep -c '^GPGKey=' /home/fp/.cache/slate/flathub.flatpakrepo | sed 's/^/pinned-/'", "pinned-1", 10)
            .is_ok(),
    ));
    // "Web Browser" opens it, and a page loads.
    con.run("strata > /tmp/strata.log 2>&1 & sleep 4", "", 30)?;
    con.run(&format!("{h} web-browser https://example.com/ > /tmp/ff.log 2>&1 & sleep 1"), "", 30)?;
    let page = con
        .send("sleep 90; cat /tmp/strata.log /tmp/ff.log /home/fp/.cache/slate/browser.log | grep -a 'from pid\\|strata-wl: title'\r")
        .and_then(|()| con.wait_for_all(&["(linux, sandboxed)", "title \"Example Domain"], 240));
    con.wait_for(PROMPT, 60)?;
    out.push(("browser-page", page.is_ok()));
    // Firefox's own sandbox inside the bubble: every one of its processes
    // filters its system calls (proc(5): Seccomp 2), several of them.
    let sandboxed = con.send(&format!("{SANDBOX_CHECK}\r")).and_then(|()| con.line_after("firefox=", 30));
    con.wait_for(PROMPT, 30)?;
    out.push((
        "browser-sandbox",
        sandboxed.is_ok_and(|l| {
            let mut f = l.split(" unsandboxed=");
            let n: u32 = f.next().and_then(|n| n.trim().parse().ok()).unwrap_or(0);
            n >= 3 && f.next().map(str::trim) == Some("0")
        }),
    ));
    con.run("kill %2 %1; sleep 2", "", 30)?;
    // A background update: run once, then not due.
    out.push((
        "auto-update",
        con.run(
            &format!(
                "{h} slate-flatpak update --auto; {h} slate-flatpak update --auto; wc -l < /home/fp/.cache/slate/app-updates.log | sed 's/^ */runs-/'"
            ),
            "runs-1",
            1200,
        )
        .is_ok(),
    ));
    Ok(())
}

/// M31's "Firefox in one click" (ADR 0155; part of `cargo xtask accept`,
/// or `cargo xtask flatpak --browser`): on a system with no Linux runtime
/// (an empty disk where it goes) and Linux compatibility on, as root in
/// Strata: the Web Browser opened, one key on "Get Firefox", one on the
/// approval if one is asked (root's isn't), and nothing else. The runtime is set up, Firefox fetched
/// with its progress shown as a percentage, and opened on a page whose
/// title comes back through strata-wl. The time from the click to the
/// page goes to target/flatpak/browser.txt.
pub fn browser_fresh() -> Result {
    let started = Instant::now();
    println!("xtask: accept: Firefox in one click on a system without a Linux runtime (M31)");
    let disk = dir().join("fresh.img");
    let _ = std::fs::remove_file(&disk);
    std::fs::create_dir_all(dir()).map_err(|e| e.to_string())?;
    run_cmd(Command::new("mkfs.ext4").args(["-q", "-F", "-b", "4096", "-L", "linux"]).arg(&disk).arg("24G"))?;
    let mon = dir().join("browser-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = crate::desktop::boot(&disk, Some(&mon), false)?;
    let mut checks: Vec<(&str, bool)> = Vec::new();
    let mut took = None;
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 30)?;
        con.run("mkdir -p /mnt/workbench/fphome /home/fp && mount -o bind /mnt/workbench/fphome /home/fp && echo bound$((1+1))", "bound2", 30)?;
        con.run("ls /var/lib/slate/linux | wc -l | sed 's/^ */entries-/'", "entries-0", 10)?;
        con.run("strata > /tmp/strata.log 2>&1 & sleep 3", "", 30)?;
        con.run("HOME=/home/fp SLATE_APPS_TRACE=1 web-browser https://example.com/ > /tmp/wb.log 2>&1 &", "", 10)?;
        let offered = con.run(
            "for i in $(seq 100); do grep -q 'web-browser: offering' /tmp/wb.log && break; sleep 0.2; done; grep -a 'web-browser: offering' /tmp/wb.log",
            "(set up: needed, fetch: needed)",
            40,
        );
        checks.push(("offered", offered.is_ok()));
        offered?;
        std::thread::sleep(std::time::Duration::from_millis(1500));
        // The one click: Enter on "Get Firefox".
        crate::qemu::monitor(&mon, &["sendkey ret"])?;
        let clicked = Instant::now();
        // Root's request is granted without a dialog (the broker asks only
        // other people, ADR 0035); one that comes is answered.
        std::thread::sleep(std::time::Duration::from_millis(3000));
        if con
            .run("grep -ac 'strata: approval: browser=setup' /tmp/strata.log | sed 's/^/asked-/'", "asked-1", 10)
            .is_ok()
        {
            crate::qemu::monitor(&mon, &["sendkey ret"])?;
        }
        let _ = std::fs::write(dir().join("browser.log"), crate::qemu::strip_ansi(&con.log));
        // Set up, fetched with a percentage, and the page: its title.
        let page = con.run(
            "for i in $(seq 3600); do grep -q 'strata-wl: title \"Example Domain' /tmp/wb.log /home/fp/.cache/slate/browser.log 2>/dev/null && break; sleep 0.5; done; \
             grep -ac 'strata-wl: title \"Example Domain' /home/fp/.cache/slate/browser.log | sed 's/^/pa''ge-/'",
            "page-",
            1900,
        );
        took = Some(clicked.elapsed().as_secs_f64());
        // What the Web Browser said besides setup's steps, for the transcript.
        con.run("grep -av 'web-browser: setup:' /tmp/wb.log | tail -n 40", "", 30)?;
        let shown = con.output(
            "grep -a 'web-browser: setup:\\|web-browser: fetching\\|web-browser: starting' /tmp/wb.log | tail -n 40",
            30,
        )?;
        let setup_seen = shown.iter().filter(|l| l.contains("web-browser: setup:")).count();
        let pcts: Vec<u32> = shown
            .iter()
            .filter_map(|l| l.split("web-browser: fetching ").nth(1)?.split('%').next()?.parse().ok())
            .collect();
        println!("xtask: accept: setup said {setup_seen} steps; fetching said {pcts:?}");
        checks.push(("setup-progress", setup_seen >= 3));
        checks.push(("fetch-percentages", pcts.len() >= 3 && pcts.windows(2).all(|w| w[0] <= w[1])));
        checks.push(("started", shown.iter().any(|l| l.contains("web-browser: starting org.mozilla.firefox"))));
        // No more than one question was asked.
        let asked = con.output("grep -ac 'strata: approval:' /tmp/strata.log", 10)?;
        checks.push(("at-most-one-approval", asked.iter().any(|l| l.trim() == "0" || l.trim() == "1")));
        checks.push(("page-loads", page.is_ok() && con.last_line_with("page-").is_some_and(|l| l != "page-0")));
        kernel_notes(&mut con)?;
        con.poweroff()
    })();
    std::fs::write(dir().join("browser.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&disk);
    if let Some(t) = took {
        let _ = std::fs::write(dir().join("browser.txt"), format!("click to page: {t:.0} s\n"));
        println!("xtask: accept: from the click to the page: {t:.0} s");
    }
    for (name, ok) in &checks {
        println!("ACCEPT: {} m31::browser::{name}", if *ok { "PASS" } else { "FAIL" });
    }
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak --browser: {e} (transcript in target/flatpak/browser.log)"));
    }
    let failed: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
    if !failed.is_empty() {
        return Err(format!(
            "M31's browser checks failed: {} (transcript in target/flatpak/browser.log)",
            failed.join(", ")
        ));
    }
    println!("xtask: accept: Firefox in one click passed ({:.0}s)", started.elapsed().as_secs_f64());
    Ok(())
}

/// The mean brightness (0 to 1) of the screenshot `shot` in the
/// rectangle (x, y, w, h), every fourth pixel.
fn brightness(shot: &std::path::Path, (x, y, w, h): (usize, usize, usize, usize)) -> Result<f64> {
    let (mut sum, mut n) = (0.0, 0.0);
    for py in (y..y + h).step_by(4) {
        for px in (x..x + w).step_by(4) {
            let [r, g, b] = crate::qemu::ppm_pixel(shot, px, py)?;
            sum += (0.2126 * f64::from(r) + 0.7152 * f64::from(g) + 0.0722 * f64::from(b)) / 255.0;
            n += 1.0;
        }
    }
    Ok(if n > 0.0 { sum / n } else { 0.0 })
}

/// M31's theming (ADR 0182; part of `cargo xtask accept`, or `cargo xtask
/// flatpak --themed`): GNOME's Calculator (GTK 4 and libadwaita) from
/// Flathub, in root's Strata on the workbench. With Graphite it is dark;
/// with Strata's theme changed to Light, while it runs, it turns light
/// (the Settings portal's `SettingChanged`); its window has its own name
/// and icon; Strata's fonts are inside its sandbox.
pub fn themed() -> Result {
    const CALC: &str = "org.gnome.Calculator";
    let started = Instant::now();
    println!("xtask: accept: a GTK app themed by Strata (M31)");
    let wb = workbench(false)?;
    let disk = scratch_copy(&wb, "themed.img")?;
    let mon = dir().join("themed-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = crate::desktop::boot(&disk, Some(&mon), false)?;
    let mut checks: Vec<(&str, bool)> = Vec::new();
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 30)?;
        con.run(HOME, "bound2", 30)?;
        // Strata's fonts go into a runtime as it is set up (again).
        con.run("slate-linux setup flatpak > /tmp/setup.log 2>&1; echo setup-$?", "setup-0", 900)?;
        con.run("mkdir -p /home/fp/.config/strata && echo theme=graphite > /home/fp/.config/strata/settings", "", 10)?;
        con.run("HOME=/home/fp strata > /tmp/strata.log 2>&1 & sleep 3", "", 30)?;
        con.run(
            &format!("HOME=/home/fp slate-flatpak install {CALC} > /tmp/install.log 2>&1; echo inst-$?"),
            "inst-0",
            2400,
        )?;
        // Flathub's catalog, fetched after the install in the background,
        // has the icon GNOME's apps export only as SVG.
        con.run(
            "for i in $(seq 240); do [ -e /home/fp/.local/share/flatpak/appstream/flathub/x86_64/active/appstream.xml.gz ] && break; sleep 0.5; done; echo catalog-done",
            "catalog-done",
            150,
        )?;
        con.run(&format!("HOME=/home/fp slate-flatpak run {CALC} > /tmp/calc.log 2>&1 & app=$!"), "", 10)?;
        con.run(
            "for i in $(seq 300); do grep -q 'strata-wl: timing' /tmp/calc.log && break; sleep 0.2; done; grep -a 'strata-wl: timing' /tmp/calc.log",
            "first frame",
            90,
        )?;
        std::thread::sleep(std::time::Duration::from_secs(5));
        let lines = con.output("grep -a 'from pid\\|own icon\\|placed at' /tmp/strata.log | tail -n 6", 20)?;
        checks.push(("own-name-and-icon", lines.iter().any(|l| l.contains("\"Calculator\" has its own icon"))));
        let at = lines
            .iter()
            .rev()
            .find_map(|l| {
                let v: Vec<f64> = l.split(" placed at ").nth(1)?.split(' ').filter_map(|n| n.parse().ok()).collect();
                (v.len() == 4).then(|| (v[0], v[1], v[2], v[3]))
            })
            .ok_or("no window placed")?;
        // The window's content, away from its edges and the title bar.
        let area =
            ((at.0 + at.2 * 0.15) as usize, (at.1 + 60.0) as usize, (at.2 * 0.7) as usize, (at.3 * 0.6) as usize);
        let dark = brightness(&crate::qemu::screendump(&mon, "themed-dark.ppm")?, area)?;
        con.run("echo theme=light > /home/fp/.config/strata/settings; sleep 4", "", 30)?;
        let light = brightness(&crate::qemu::screendump(&mon, "themed-light.ppm")?, area)?;
        println!("xtask: accept: the Calculator's brightness: {dark:.2} with Graphite, {light:.2} with Light");
        checks.push(("dark-with-graphite", dark < 0.4));
        checks.push(("light-when-changed", light > 0.6));
        let portal = con.output("grep -a 'slate-portal' /tmp/calc.log", 10)?;
        checks.push(("portal", portal.iter().any(|l| l.contains("org.freedesktop.portal.Desktop"))));
        checks.push(("setting-changed", portal.iter().any(|l| l.contains("color-scheme changed"))));
        con.run(
            "for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = sway ] && kill ${p#/proc/}; done; sleep 2",
            "",
            30,
        )?;
        let fonts = con.output(
            &format!("HOME=/home/fp slate-linux-app /usr/bin/flatpak run --command=fc-list {CALC} 2>/dev/null | grep -c 'Host Grotesk'"),
            120,
        )?;
        checks.push(("strata-fonts-inside", fonts.iter().any(|l| l.trim().parse::<u32>().is_ok_and(|n| n > 0))));
        kernel_notes(&mut con)?;
        con.poweroff()
    })();
    std::fs::write(dir().join("themed.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&disk);
    for (name, ok) in &checks {
        println!("ACCEPT: {} m31::themed::{name}", if *ok { "PASS" } else { "FAIL" });
    }
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak --themed: {e} (transcript in target/flatpak/themed.log)"));
    }
    let failed: Vec<&str> = checks.iter().filter(|c| !c.1).map(|c| c.0).collect();
    if !failed.is_empty() {
        return Err(format!(
            "M31's theming checks failed: {} (transcript in target/flatpak/themed.log)",
            failed.join(", ")
        ));
    }
    println!("xtask: accept: a GTK app themed by Strata passed ({:.0}s)", started.elapsed().as_secs_f64());
    Ok(())
}

/// M28 phase 7's acceptance (part of `cargo xtask accept`; ADR 0114).
pub fn accept() -> Result {
    let started = Instant::now();
    println!("xtask: accept: Flatpak and AppImage ({PACKAGES})");
    let wb = workbench(false)?;
    let disk = scratch_copy(&wb, "accept.img")?;
    // A monitor, for the keys typed into the person's Strata.
    let mon = dir().join("accept-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    // The person's sound server plays into a recording (ADR 0185).
    let wav = dir().join("accept-sound.wav");
    let _ = std::fs::remove_file(&wav);
    let mut con = crate::desktop::boot_with_sound(&disk, Some(&mon), &wav)?;
    let mut failed = Vec::new();
    let r = (|| -> Result {
        con.login()?;
        con.run(MOUNT, "mounted2", 30)?;
        for (name, ok) in checks(&mut con, &mon)? {
            println!("ACCEPT: {} m28::flatpak::{name}", if ok { "PASS" } else { "FAIL" });
            if !ok {
                failed.push(name);
            }
        }
        kernel_notes(&mut con)?;
        con.poweroff()
    })();
    std::fs::write(dir().join("accept.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&disk);
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak: {e} (transcript in target/flatpak/accept.log)"));
    }
    let heard = crate::sound::find_tones(&wav, &[660.0]).map(|t| t[0]).unwrap_or(0.0);
    let ok = heard >= 1.5;
    println!("ACCEPT: {} m30::sound::flatpak_app_heard ({heard:.2} s of 660 Hz)", if ok { "PASS" } else { "FAIL" });
    if !ok {
        failed.push("flatpak_app_heard");
    }
    if !failed.is_empty() {
        return Err(format!(
            "M28 Flatpak acceptance checks failed: {} (transcript in target/flatpak/accept.log)",
            failed.join(", ")
        ));
    }
    println!(
        "xtask: accept: Flatpak and AppImage passed (install, update, rollback, a window in Strata, an AppImage; an app for everyone; \
         Firefox from Flathub through the Web Browser, a page under its own sandbox, a background update; the app's \
         sound through the person's sound server; {:.0}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
