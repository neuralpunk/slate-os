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
/// and OSTree), D-Bus for its session bus, and Sway for its windows.
pub const PACKAGES: &str = "sway xwayland font-dejavu flatpak dbus";

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

/// M28 phase 7's acceptance (part of `cargo xtask accept`; ADR 0114).
pub fn accept() -> Result {
    let started = Instant::now();
    println!("xtask: accept: Flatpak and AppImage ({PACKAGES})");
    let wb = workbench(false)?;
    let disk = scratch_copy(&wb, "accept.img")?;
    // A monitor, for the keys typed into the person's Strata.
    let mon = dir().join("accept-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = crate::desktop::boot(&disk, Some(&mon), false)?;
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
    if !failed.is_empty() {
        return Err(format!(
            "M28 Flatpak acceptance checks failed: {} (transcript in target/flatpak/accept.log)",
            failed.join(", ")
        ));
    }
    println!(
        "xtask: accept: Flatpak and AppImage passed (install, update, rollback, a window in Strata, an AppImage; an app for everyone; \
         Firefox from Flathub through the Web Browser, a page under its own sandbox, a background update; {:.0}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
