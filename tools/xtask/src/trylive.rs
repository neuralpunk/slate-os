// SPDX-License-Identifier: MIT OR Apache-2.0

//! The "Try SlateOS" scenario (M27 phase 3): the install medium's Welcome
//! screen's "Try SlateOS" starts the live system's Strata desktop as the
//! live user (no password, not root), from RAM; its "Install SlateOS"
//! brings the installer back: once from the launcher, once from the
//! button on the top bar, after trying again.

use std::time::{Duration, Instant};

use crate::qemu::{Console, monitor, mouse_index, ppm_pixel, reference_pc, screendump, strip_ansi, type_keys};
use crate::{Opts, Result, target_dir};

/// Strata's graphite desktop (docs/design/WM_STYLE.md) at a point of the
/// wallpaper, and the installer's window.
const DESKTOP: [u8; 3] = [0x12, 0x12, 0x11];
const INSTALLER: [u8; 3] = [0xF3, 0xF2, 0xF2];

pub fn try_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    // The stick starts the entry that keeps the live session's files.
    let stick = crate::iso::usb_copy_keeping(o, &target_dir().join("try-stick.img"))?;
    let disk = target_dir().join("try-target.img");
    let _ = std::fs::remove_file(&disk);
    std::fs::File::create(&disk).and_then(|f| f.set_len(16 << 30)).map_err(|e| e.to_string())?;
    let mon = target_dir().join("try-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    // The stick is writable here: leaving the live session keeps its files
    // on it.
    let ro = reference_pc(o, &disk, Some(&stick), &mon, None)?;
    let mut cmd = std::process::Command::new(ro.get_program());
    cmd.args(ro.get_args().map(|a| {
        let a = a.to_string_lossy();
        if a.contains("id=stick,") { a.replace(",readonly=on", "") } else { a.into_owned() }
    }));
    cmd.args(["-device", "usb-mouse,bus=xhci.0"]);
    let mut con = Console::start(cmd)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let result = (|| -> Result {
        // The installer, then "Try SlateOS": the third control in the tab
        // order (the language, accessibility, Try).
        let welcome = |con: &mut Console, again: bool| -> Result {
            con.wait_for("slate-install-gui: ", 90)?;
            con.wait_for(" at scale ", 10)?;
            pause(1500);
            let shot = screendump(&mon, "try-welcome.ppm")?;
            if ppm_pixel(&shot, 640, 400)? != INSTALLER {
                return Err("the installer is not on the screen".into());
            }
            monitor(&mon, &["sendkey tab", "sendkey tab", "sendkey tab", "sendkey ret"])?;
            // The live desktop, as the live user, with what the first
            // session kept on the stick put back the second time.
            con.wait_for("slate-install-gui: trying SlateOS as live", 20)?;
            if again {
                con.wait_for("slate-install-gui: the live session's files restored from the stick (", 20)?;
            } else {
                con.wait_for("slate-install-gui: no live session's files on the stick yet", 20)?;
            }
            con.wait_for("strata: 1280x800 at scale 1", 60)?;
            con.wait_for("strata: live session for live", 10)?;
            pause(1500);
            let shot = screendump(&mon, "try-desktop.ppm")?;
            if ppm_pixel(&shot, 640, 300)? != DESKTOP {
                return Err("no Strata desktop".into());
            }
            Ok(())
        };
        welcome(&mut con, false)?;
        // The launcher's "Install SlateOS": the installer again.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(500);
        type_keys(&mon, "install")?;
        pause(300);
        screendump(&mon, "try-launcher.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata: to the installer", 10)?;
        con.wait_for("slate-install-gui: the live session's files kept on the stick (", 30)?;
        // Again, and the top bar's button (left of slate mode, at about
        // 903, 16 on a 1280 × 800 screen; the pointer starts mid-screen).
        welcome(&mut con, true)?;
        let mouse = mouse_index(&mon, "HID Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}"), "mouse_move 131 -192", "mouse_move 132 -192"])?;
        pause(300);
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: to the installer", 10)?;
        con.wait_for("slate-install-gui: ", 60)?;
        con.wait_for(" at scale ", 10)?;
        Ok(())
    })();
    con.kill();
    let _ = std::fs::write(target_dir().join("try.log"), strip_ansi(&con.log));
    result.map_err(|e| format!("try scenario: {e}"))?;
    // The kept files are on the stick, gzip'd.
    match crate::iso::usb_read(&stick, "LIVE/HOME.TGZ")? {
        Some(d) if d.starts_with(&[0x1f, 0x8b]) => {}
        Some(_) => return Err("try scenario: LIVE/HOME.TGZ on the stick is not gzip".into()),
        None => return Err("try scenario: nothing kept on the stick".into()),
    }
    println!(
        "xtask: try scenario passed (\"Try SlateOS\" to the live desktop as the live user, back to the installer \
         from the launcher and from the top bar, the session's files kept on the stick and put back; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
