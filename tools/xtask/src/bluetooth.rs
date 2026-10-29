// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Bluetooth scenario (M28 phase 6, ADR 0113): a USB Bluetooth
//! adapter on QEMU's xHCI (`btredir`, through usb-redir) with a phone and
//! a keyboard nearby.
//!
//! - The kernel finds the controller (/dev/hci0) and slate-btd starts it.
//! - `slate-bt scan` finds both devices by name; the keyboard pairs from
//!   the command line, by a passkey typed on it.
//! - Settings' Bluetooth page finds the phone and pairs it by numeric
//!   comparison, then forgets the keyboard.
//! - The phone connects again with the kept key, after the daemon
//!   restarted; Bluetooth goes off and on.
//! - Unplugging the adapter takes /dev/hci0 away.

use std::time::{Duration, Instant};

use crate::btredir::Adapter;
use crate::qemu::{Console, base_command, monitor, type_keys};
use crate::{Opts, Result, image, target_dir};

pub fn bluetooth_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let adapter = Adapter::start()?;
    let img = image::build(o, "", "slate-bluetooth.img", image::Root::Disk)?;
    let mon = target_dir().join("bluetooth-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-device", "qemu-xhci,id=xhci"]);
    c.arg("-chardev").arg(format!("socket,id=bt,host=127.0.0.1,port={}", adapter.port));
    c.args(["-device", "usb-redir,chardev=bt,bus=xhci.0,id=bt0"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let (phone, keyboard) = ("5C:F3:70:11:22:33", "00:1F:20:44:55:66");
    let result = (|| -> Result {
        con.login()?;
        // The daemon has started the controller.
        con.run(
            "for i in 1 2 3 4 5 6 7 8 9 10; do slate-bt | grep -q ': on' && break; sleep 1; done; slate-bt",
            &format!("controller {} \"slate\": on", crate::btredir::ADDRESS),
            20,
        )?;
        con.run("ls -l /dev/hci0 | cut -c1-10", "crw-------", 10)?;
        con.run("slate-bt scan", "Slate Keyboard", 40)?;
        con.run("slate-bt | grep -c nearby", "2", 10)?;
        // The keyboard: a passkey shown here, typed there (the stand-in
        // types it at once, so the daemon's log has it).
        con.run(&format!("slate-bt pair {keyboard}"), "Paired with Slate Keyboard.", 30)?;
        con.run("service slate-btd log | grep -c 'passkey 00:1F:20:44:55:66 007351'", "1", 10)?;
        // Settings: the Bluetooth page finds the phone; pairing it asks
        // whether the numbers match.
        con.send("export SLATE_APPS_TRACE=1; strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(400);
        type_keys(&mon, "settings\n")?;
        con.wait_for("\"settings\" from pid", 15)?;
        pause(800);
        for _ in 0..4 {
            monitor(&mon, &["sendkey down"])?;
        }
        con.wait_for_all(&["strata-settings: bluetooth: on", "strata-settings: bluetooth: found Ada's Phone"], 15)?;
        pause(1500);
        // The switch, the keyboard (paired), the phone.
        monitor(&mon, &["sendkey right", "sendkey down", "sendkey down", "sendkey ret"])?;
        con.wait_for(&format!("strata-settings: bluetooth: asked: pair {phone}"), 10)?;
        con.wait_for("strata-settings: bluetooth: confirm 482913 for Ada's Phone", 15)?;
        pause(400);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata-settings: bluetooth: Paired with Ada's Phone.", 15)?;
        con.run("ls /var/lib/slate/bluetooth/devices | tr '\\n' ,", &format!("{keyboard},{phone},"), 10)?;
        con.run("stat -c %a /var/lib/slate/bluetooth/devices/*", "600", 10)?;
        // Forget the keyboard: now second among the paired (by name),
        // where the keyboard's row stays; Delete asks, Enter does it.
        pause(1200);
        monitor(&mon, &["sendkey delete"])?;
        pause(300);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata-settings: bluetooth: Slate Keyboard is forgotten.", 15)?;
        con.run("ls /var/lib/slate/bluetooth/devices | tr '\\n' ,", &format!("{phone},"), 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The phone again, with the kept key, after the daemon restarted.
        con.run("service slate-btd restart; sleep 2; slate-bt | grep -c paired", "1", 20)?;
        con.run(&format!("slate-bt connect {phone}"), "Connected to Ada's Phone.", 20)?;
        // Off and on.
        con.run("slate-bt power off", "\"slate\": off", 10)?;
        con.run(&format!("slate-bt connect {phone} || echo re''fused"), "refused", 10)?;
        con.run("slate-bt power on; sleep 1; slate-bt", "\"slate\": on", 15)?;
        // The adapter unplugged: /dev/hci0 goes, the daemon says so.
        monitor(&mon, &["device_del bt0"])?;
        con.wait_for("hci0: removed", 15)?;
        con.run(
            "for i in 1 2 3 4 5; do slate-bt | grep -q 'no Bluetooth' && break; sleep 1; done; slate-bt; ls /dev/hci0 2>&1",
            "No such file",
            20,
        )?;
        monitor(&mon, &["sendkey meta_l-shift-e"])?;
        con.wait_for("strata: leaving", 15)?;
        con.poweroff()
    })();
    if result.is_err() {
        con.drain(500);
    }
    let mut transcript = crate::qemu::strip_ansi(&con.log);
    transcript.push_str("\n--- the adapter ---\n");
    transcript.push_str(&adapter.log().join("\n"));
    let _ = std::fs::write(target_dir().join("bluetooth-scenario.log"), transcript);
    con.kill();
    let log = adapter.log();
    if let Err(e) = result {
        return Err(format!("Bluetooth scenario: {e} (transcript in target/bluetooth-scenario.log)"));
    }
    // The adapter's side: both pairings, and the kept key accepted.
    for want in [format!("paired {keyboard}"), format!("paired {phone}"), format!("right key for {phone}")] {
        if !log.contains(&want) {
            return Err(format!(
                "Bluetooth scenario: the adapter never logged {want:?} (target/bluetooth-scenario.log)"
            ));
        }
    }
    println!(
        "xtask: Bluetooth scenario passed (a USB controller found; a phone and a keyboard found by name, paired by \
         numeric comparison in Settings and by passkey from slate-bt, one forgotten, the other connected again with \
         its key after a restart; off and on; unplugged; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
