// SPDX-License-Identifier: MIT OR Apache-2.0

//! The displays scenario (ADR 0170, M32 phase 3): Strata on two of
//! virtio-gpu's outputs. The second is plugged in while Strata runs (QEMU
//! gives it a size through its VNC server, as the gpu scenario does), and
//! Strata lights it beside the first, with its own wallpaper; a window
//! dragged across is maximised there; Settings › Displays puts it on the
//! left (the displays file Settings writes and Strata follows); resized,
//! Strata follows. Settings' report (`~/.cache/strata/displays-now`) says each
//! time what is lit.

use std::time::{Duration, Instant};

use crate::qemu::{Console, base_command, monitor, monitor_paced, mouse_index, ppm_pixel, screendump, screendump_head};
use crate::{Opts, Result, image, target_dir};

pub fn displays_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-displays.img", image::Root::Disk)?;
    let mon = target_dir().join("displays-monitor.sock");
    let vnc = target_dir().join("displays-vnc.sock");
    for p in [&mon, &vnc] {
        let _ = std::fs::remove_file(p);
    }
    let mut c = base_command(o, &img)?;
    c.args(["-vga", "none", "-device", "virtio-gpu-pci,max_outputs=2,id=gpu", "-display", "none"]);
    c.arg("-vnc").arg(format!("unix:{},display=gpu,head=1", vnc.display()));
    c.args(["-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let desktop = [0x12, 0x12, 0x11];
    let result = (|| -> Result {
        con.login()?;
        con.send("strata &\r")?;
        con.wait_for("strata: displays: Virtual-1 1280x800@60 at 0,0 (primary) at scale 1", 30)?;
        // The second display comes: Strata lights it on the right.
        let mut client = crate::vnc::Vnc::connect(&vnc)?;
        client.set_size(1024, 768)?;
        con.wait_for(
            "strata: displays: Virtual-1 1280x800@60 at 0,0 (primary), Virtual-2 1024x768@60 at 1280,0 at scale 1",
            15,
        )?;
        pause(1000);
        let first = screendump(&mon, "displays-first.ppm")?;
        let second = screendump_head(&mon, "displays-second.ppm", "gpu", 1)?;
        let (bar, middle, other) =
            (ppm_pixel(&first, 600, 16)?, ppm_pixel(&first, 640, 300)?, ppm_pixel(&second, 512, 300)?);
        if bar != desktop || middle != desktop || other != desktop {
            return Err(format!("the desktop is not on both displays ({bar:02x?}, {middle:02x?}; {other:02x?})"));
        }
        con.run("cat ~/.cache/strata/displays-now", "Virtual-2 lit 1280,0 1024x768@60 modes 1024x768@60", 10)?;
        // A terminal, dragged by its title bar 1000 px right (onto the
        // second display), then maximised there with super + up. Its
        // window (the tab strip included) is placed at y 87, its title
        // bar above that: the pointer goes from the middle to y 70.
        monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
        pause(1500);
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}"), "mouse_move 0 -330"])?;
        pause(300);
        let mut drag = vec!["mouse_button 1".to_string()];
        drag.extend(std::iter::repeat_n("mouse_move 100 0".to_string(), 10));
        drag.push("mouse_button 0".into());
        monitor_paced(&mon, &drag, 40)?;
        pause(500);
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(800);
        let first = screendump(&mon, "displays-moved-first.ppm")?;
        let second = screendump_head(&mon, "displays-moved-second.ppm", "gpu", 1)?;
        let (left, right) = (ppm_pixel(&first, 640, 400)?, ppm_pixel(&second, 5, 700)?);
        if left != desktop || right == desktop {
            return Err(format!(
                "the terminal isn't maximised on the second display (first {left:02x?}, second {right:02x?})"
            ));
        }
        // Settings › Displays (the ninth section): the second display's
        // page, its position once along: left of the primary. Settings
        // writes the arrangement, Strata takes it up.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(400);
        crate::qemu::type_keys(&mon, "settings\n")?;
        con.wait_for("\"settings\" from pid", 15)?;
        pause(800);
        monitor_paced(&mon, &vec!["sendkey down".to_string(); 8], 60)?;
        monitor_paced(&mon, &["right", "down", "ret", "down", "down", "ret"].map(|k| format!("sendkey {k}")), 150)?;
        con.wait_for(
            "strata-settings: displays: scale=auto; Virtual-1 on 0,0 1280x800@60 primary; Virtual-2 on -1024,0 1024x768@60",
            15,
        )?;
        con.wait_for(
            "strata: displays: Virtual-1 1280x800@60 at 1024,0 (primary), Virtual-2 1024x768@60 at 0,0 at scale 1",
            15,
        )?;
        let _ = screendump(&mon, "displays-settings.ppm")?;
        // Resized: Strata follows (where the person put it).
        client.set_size(800, 600)?;
        con.wait_for("Virtual-1 1280x800@60 at 1024,0 (primary), Virtual-2 800x600@60 at 0,0 at scale 1", 15)?;
        con.run("cat ~/.cache/strata/displays-now", "Virtual-2 lit -1024,0 800x600@60", 10)?;
        pause(800);
        let second = screendump_head(&mon, "displays-resized-second.ppm", "gpu", 1)?;
        if ppm_pixel(&second, 400, 300)? == [0, 0, 0] {
            return Err("nothing on the resized second display".into());
        }
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("displays-scenario.log"), crate::qemu::strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("displays scenario: {e} (transcript in target/displays-scenario.log)"));
    }
    println!(
        "xtask: displays scenario passed (Strata on two virtio-gpu displays: the second plugged in and lit beside the first, a window dragged across and maximised there, rearranged from Settings › Displays, a display resized; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
