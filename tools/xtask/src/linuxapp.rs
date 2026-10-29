// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux GUI programs on Strata (M18d phase 6, ADR 0038; M18e, ADR 0039).
//! The Linux runtime workbench is made by `slate-linux setup` on Slate:
//! the pinned minirootfs is served from the host (fetched once into
//! target/), unpacked by Slate's own tools, and apk installs Sway,
//! Xwayland, Firefox and a font from Alpine's repositories (made once,
//! cached in target/linuxapp; `--fresh` remakes it; needs the internet).
//! It is mounted at /var/lib/slate/linux in a Slate machine in Linux
//! compatibility mode. Strata starts, and `slate-linux-app firefox` shows
//! a test page in a Strata window through Sway and strata-wl.
//!
//! The checks: the window is Linux-tagged and shows the page and its
//! title; hover, a click and a key reach it (the page changes colour);
//! ctrl+c in the page reaches Strata's clipboard, and what a Strata
//! terminal copies reaches the page (pasted twice with ctrl+v, copied
//! back with ctrl+a, ctrl+c); Firefox's sandboxes are
//! on; `slate-linux run` runs a program with the person in the runtime's
//! passwd; `slate-linux upgrade` brings the runtime up to date (simulated
//! by `cargo xtask linuxapp`, which then needs the internet for apk's
//! indexes; done by accept, ADR 0102). `cargo xtask linuxapp` prints them
//! and what the kernel did not implement; `accept` (part of `cargo xtask accept`) fails on a failed
//! check.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::hostnet::StaticServer;
use crate::qemu::{Console, monitor, mouse_index, ppm_has, screendump, type_keys};
use crate::{Result, run_cmd, target_dir};

/// Alpine packages for the Linux runtime: `slate-linux setup`'s defaults.
pub const PACKAGES: &str = "sway xwayland firefox font-dejavu";

/// A page whose colour tells what reached it: blue as loaded, purple
/// when the pointer moves over it with no button, red after a click,
/// green after the key x. Its text area holds selected text for ctrl+c.
pub const TEST_PAGE: &str = "<!doctype html><html><head><title>Slate test page</title></head>\
    <body style=\"margin:0;height:100vh;background:#3060a0\" \
    onload=\"t.focus();t.select()\" \
    onmousemove=\"if(!window.c)document.body.style.background='#6030a0'\" \
    onclick=\"window.c=1;document.body.style.background='#a03060';t.focus();t.select()\" \
    onkeydown=\"if(event.key=='x'){document.body.style.background='#30a060';event.preventDefault()}\">\
    <h1 style=\"font-family:sans-serif;color:#fff\">Slate</h1>\
    <textarea id=\"t\" rows=\"1\">slate-clip</textarea></body></html>\n";

const BLUE: [u8; 3] = [0x30, 0x60, 0xa0];
const PURPLE: [u8; 3] = [0x60, 0x30, 0xa0];
const RED: [u8; 3] = [0xa0, 0x30, 0x60];
const GREEN: [u8; 3] = [0x30, 0xa0, 0x60];
/// Inside the first window (centred, 768 x 538 at (256, 147)), below
/// Firefox's toolbar.
const PAGE: (usize, usize, usize, usize) = (420, 420, 860, 600);

const MOUNT: &str =
    "mkdir -p /var/lib/slate/linux && mount -t ext4 /dev/vdb /var/lib/slate/linux && echo mounted$((1+1))";

/// The runtime, made by `slate-linux setup` in a Slate machine onto a
/// disk holding only the test page.
fn workbench(fresh: bool) -> Result<std::path::PathBuf> {
    let dir = target_dir().join("linuxapp");
    let img = dir.join("workbench.img");
    let stamp = format!("slate-linux setup {PACKAGES}\n{TEST_PAGE}");
    let same = std::fs::read_to_string(dir.join("stamp")).is_ok_and(|s| s == stamp);
    if img.exists() && same && !fresh {
        return Ok(img);
    }
    let _ = std::fs::remove_dir_all(&dir);
    let stage = dir.join("stage");
    std::fs::create_dir_all(stage.join("srv")).map_err(|e| e.to_string())?;
    std::fs::write(stage.join("srv/test.html"), TEST_PAGE).map_err(|e| e.to_string())?;
    let building = dir.join("building.img");
    run_cmd(
        Command::new("unshare")
            .args(["-r", "mkfs.ext4", "-q", "-F", "-b", "4096", "-L", "linux", "-d"])
            .arg(&stage)
            .arg(&building)
            .arg("4G"),
    )?;
    // The minirootfs, served to the machine as a mirror would.
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
        con.run("sync; umount -l /var/lib/slate/linux", "", 30)?;
        con.poweroff()
    })();
    server.stop();
    std::fs::write(dir.join("setup.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("linuxapp: slate-linux setup: {e} (transcript in target/linuxapp/setup.log)"));
    }
    std::fs::rename(&building, &img).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("stamp"), stamp).map_err(|e| e.to_string())?;
    Ok(img)
}

/// Wait up to `secs` for `rgb` in the page area of the screen.
fn wait_colour(mon: &Path, name: &str, rgb: [u8; 3], secs: u64) -> Result<bool> {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        let shot = screendump(mon, name)?;
        if ppm_has(&shot, PAGE, rgb)? {
            return Ok(true);
        }
        if Instant::now() > until {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// Run the checks; their names and results.
fn checks(con: &mut Console, mon: &Path, real_upgrade: bool) -> Result<Vec<(&'static str, bool)>> {
    let mut out = Vec::new();
    con.login()?;
    con.run(MOUNT, "mounted2", 30)?;
    // A program on the terminal, with the person in the runtime's passwd
    // and Slate's name servers.
    let run = con
        .run(
            "slate-linux run /bin/sh -c 'grep -q \" /etc/passwd \" /proc/mounts && \
             [ $(grep -c ^root: /etc/passwd) = 1 ] && grep -q ^nameserver /etc/resolv.conf && \
             cat /etc/alpine-release' && echo ran$((1+1))",
            "ran2",
            30,
        )
        .is_ok();
    out.push(("slate_linux_run", run));
    con.send("strata &\r")?;
    con.wait_for("strata: 1280x800 at scale 1", 30)?;
    std::thread::sleep(Duration::from_millis(800));
    con.send("slate-linux-app firefox --kiosk file:///srv/test.html &\r")?;
    // Strata sees it in the Linux domain and in the runtime's sandbox,
    // and tags its title bar "linux sandbox".
    let window = con.wait_for("\"firefox\" from pid", 60).is_ok() && con.wait_for("(linux, sandboxed)", 5).is_ok();
    out.push(("window_tagged_sandbox", window));
    let shown = con.wait_for("strata-wl: showing firefox", 30).is_ok();
    let protocols = shown && con.wait_for(", clipboard, titles", 5).is_ok();
    out.push(("bridge_started", shown));
    out.push(("bridge_clipboard_and_titles", protocols));
    out.push(("page_shown", wait_colour(mon, "linuxapp-page.ppm", BLUE, 90)?));
    out.push(("title_shown", con.wait_for("strata-wl: title \"Slate test page", 20).is_ok()));
    // Hover: the pointer moves over the page with no button (the PS/2
    // mouse starts in the middle).
    let mouse = mouse_index(mon, "PS/2 Mouse")?;
    monitor(mon, &[&format!("mouse_set {mouse}"), "mouse_move 0 100"])?;
    out.push(("hover_reaches_page", wait_colour(mon, "linuxapp-hover.ppm", PURPLE, 20)?));
    monitor(mon, &["mouse_button 1", "mouse_button 0"])?;
    out.push(("click_reaches_page", wait_colour(mon, "linuxapp-click.ppm", RED, 20)?));
    type_keys(mon, "x")?;
    out.push(("key_reaches_page", wait_colour(mon, "linuxapp-key.ppm", GREEN, 20)?));
    // ctrl+c copies the selected text to Strata's clipboard.
    monitor(mon, &["sendkey ctrl-c"])?;
    out.push(("copy_reaches_strata", con.wait_for("strata-wl: 10 bytes to Strata's clipboard", 20).is_ok()));
    // The other way (M26 phase 1): a Strata terminal selects all its text,
    // "strata-to-linux", and copies it; back in the page, ctrl+v pastes it
    // over the text area's selection, and again after it; ctrl+a, ctrl+c
    // copy both back to Strata: 30 bytes. (strata-wl doesn't copy back
    // text it offered unchanged.)
    con.run(
        "printf 'printf \"\\033[2J\\033[3J\\033[H\"; echo strata-to-linux; sleep 60\\n' > /tmp/s.sh && echo s-$((1+1))",
        "s-2",
        10,
    )?;
    monitor(mon, &["sendkey meta_l-ret"])?;
    let terminal = con.wait_for("\"terminal\" from pid", 15).is_ok();
    std::thread::sleep(Duration::from_millis(1500));
    type_keys(mon, "sh /tmp/s.sh\n")?;
    std::thread::sleep(Duration::from_millis(1500));
    monitor(mon, &["sendkey ctrl-shift-a", "sendkey ctrl-shift-c"])?;
    std::thread::sleep(Duration::from_millis(500));
    monitor(mon, &["sendkey alt-tab"])?;
    std::thread::sleep(Duration::from_millis(1500));
    monitor(mon, &["sendkey ctrl-v"])?;
    std::thread::sleep(Duration::from_millis(800));
    monitor(mon, &["sendkey ctrl-v"])?;
    std::thread::sleep(Duration::from_millis(800));
    monitor(mon, &["sendkey ctrl-a", "sendkey ctrl-c"])?;
    let back = terminal
        && con.wait_for("strata-wl: 15 bytes from Strata's clipboard", 5).is_ok()
        && con.wait_for("strata-wl: 30 bytes to Strata's clipboard", 20).is_ok();
    out.push(("strata_clipboard_reaches_linux", back));
    // Firefox's own sandboxes are on (ADR 0039): its content processes run
    // under seccomp filters, chrooted into an empty directory.
    let sandboxed = con
        .run(
            "n=0; for d in /proc/[0-9]*; do grep -q '^Seccomp:.2' $d/status 2>/dev/null && \
             [ \"$(readlink $d/root)\" != /var/lib/slate/linux ] && grep -q '^Name:.*Content' $d/status && \
             n=$((n+1)); done; echo $n content processes sandboxed; [ $n -gt 0 ] && echo boxed-$((1+1))",
            "boxed-2",
            15,
        )
        .is_ok();
    out.push(("firefox_sandboxes_on", sandboxed));
    // The runtime's upgrade (ADR 0102): apk's indexes from Alpine, then
    // every package to its newest (or what that would do).
    let cmd = if real_upgrade { "slate-linux upgrade" } else { "slate-linux upgrade --simulate" };
    let upgraded = con.run(&format!("{cmd} && echo upgraded$((1+1))"), "upgraded2", 900).is_ok();
    out.push(("runtime_upgrade", upgraded));
    Ok(out)
}

fn session(fresh: bool, real_upgrade: bool, report: &mut dyn FnMut(&str, bool)) -> Result {
    let wb = workbench(fresh)?;
    let mon = target_dir().join("linuxapp-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = crate::desktop::boot(&wb, Some(&mon), false)?;
    let r = checks(&mut con, &mon, real_upgrade).and_then(|results| {
        for (name, ok) in results {
            report(name, ok);
        }
        con.run("dmesg | grep -ai 'unimplemented\\|unsupported' | tail -n 30", "", 10)?;
        con.run("dmesg | grep -a ': SIG' | tail -n 10", "", 10)?;
        con.run("dmesg | grep -ai -A12 'fault' | tail -n 40", "", 10)?;
        con.poweroff()
    });
    std::fs::write(target_dir().join("linuxapp.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if let Err(e) = r {
        con.kill();
        return Err(format!("linuxapp: {e} (transcript in target/linuxapp.log)"));
    }
    Ok(())
}

/// `cargo xtask linuxapp`: run the checks and report them.
pub fn run(fresh: bool) -> Result {
    let started = Instant::now();
    session(fresh, false, &mut |name, ok| println!("linuxapp: {} {name}", if ok { "PASS" } else { "FAIL" }))?;
    println!("xtask: linuxapp run done ({:.0}s); transcript in target/linuxapp.log", started.elapsed().as_secs_f64());
    Ok(())
}

/// M18d's Linux-program acceptance (part of `cargo xtask accept`): a
/// fresh runtime, and every check must pass.
pub fn accept() -> Result {
    println!("xtask: accept: M18d: making the Linux runtime ({PACKAGES})");
    let mut failed = Vec::new();
    session(true, true, &mut |name, ok| {
        println!("ACCEPT: {} m18d::{name}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            failed.push(name.to_string());
        }
    })?;
    if !failed.is_empty() {
        return Err(format!(
            "M18d acceptance checks failed: {} (transcript in target/linuxapp.log)",
            failed.join(", ")
        ));
    }
    println!(
        "xtask: accept: M18d passed (Firefox in a Strata window through Sway and strata-wl: hover, a click, a key, the clipboard)"
    );
    Ok(())
}
