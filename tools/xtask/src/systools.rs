// SPDX-License-Identifier: MIT OR Apache-2.0

//! The system tools scenario (M28 phase 5, ADR 0112): the System Monitor,
//! Disks and the Software Updater in Strata, driven with QEMU's keyboard
//! as root (the broker grants root's actions without the dialog; the
//! Strata scenario shows the dialog). The apps say what they do on the
//! serial console (`SLATE_APPS_TRACE`).
//!
//! - **System Monitor:** a `sleep` found by typing, its details shown
//!   and its priority lowered, the tree shown, and it ended from the
//!   table; the resources and file systems tabs read the machine.
//! - **Disks:** a blank 256 MiB disk erased to a new GPT, a FAT32
//!   partition added, formatted again as SlateFS, a second partition
//!   added and deleted; the SlateFS mounted in /run/media, unmounted and
//!   renamed, devd's udev entry following; /sys/block follows each
//!   change, and `slatefs fsck` checks the SlateFS on the host
//!   afterwards.
//! - **The Linux runtime's upgrades:** a runtime of our own, moved onto
//!   its own subvolume; a failed upgrade puts it back, a good one keeps
//!   the one before for `slate-linux rollback`.
//! - **Software Updater:** a newer `slate-base` found; Strata's power
//!   dialog restarts "installing the updates first" (ADR 0110's addendum),
//!   which the Software Updater does in its window as a new system (the
//!   running one changes too); the new system starts, and the Software
//!   Updater rolls it back.

use std::time::{Duration, Instant};

use crate::apps::launch;
use crate::qemu::{Console, add_disk, base_command, monitor, screendump, type_keys};
use crate::{Opts, Result, image, target_dir};

/// The blank disk Disks works on.
const DISK_BYTES: u64 = 256 << 20;

pub fn tools_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    crate::quarry::test_repos()?;
    crate::basepkg::base_next_repo()?;
    let v = crate::basepkg::version();
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let img = image::build(o, "", "slate-tools.img", image::Root::Disk)?;
    let disk = target_dir().join("tools-disk.img");
    let f = std::fs::File::create(&disk).map_err(|e| format!("{}: {e}", disk.display()))?;
    f.set_len(DISK_BYTES).map_err(|e| e.to_string())?;
    drop(f);
    let mon = target_dir().join("tools-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    add_disk(&mut c, 1, &disk);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let result = (|| -> Result<String> {
        con.login()?;
        // The repositories: the system's own, and one with a newer base.
        con.run(
            &format!(
                "printf 'install file:///var/lib/quarry/install\\nnext http://10.0.2.2:{}/base-next\\n' > /etc/quarry/repos",
                repos.port
            ),
            "",
            10,
        )?;
        con.run("sleep 4242 & SL=$!; echo \"sl\"\"eeper-$((1+1))\"", "sleeper-2", 10)?;
        con.send("export SLATE_APPS_TRACE=1; strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        // The System Monitor: the sleep found and ended; the other tabs.
        launch(&mon, &mut con, "monitor", "monitor")?;
        type_keys(&mon, "sleep")?;
        con.wait_for("system-monitor: chosen sleep (pid ", 10)?;
        // Its details (ctrl + i): its thread and files; + lowers its
        // priority (/proc/PID/stat's nice). Then the tree (ctrl + t).
        monitor(&mon, &["sendkey ctrl-i"])?;
        con.wait_for("system-monitor: details of sleep (pid ", 10)?;
        con.wait_for(" 1 threads, ", 5)?;
        monitor(&mon, &["sendkey shift-equal"])?;
        con.wait_for(" is now nice 1", 10)?;
        con.run("cut -d' ' -f19 /proc/$SL/stat", "1", 10)?;
        monitor(&mon, &["sendkey esc", "sendkey ctrl-t"])?;
        con.wait_for("system-monitor: the tree shown", 10)?;
        monitor(&mon, &["sendkey delete"])?;
        pause(300);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("system-monitor: ended sleep (pid ", 10)?;
        // Not sleeping any more: gone, or a zombie until the shell
        // reaps it.
        con.run(
            "[ \"$(cut -d' ' -f3 /proc/$SL/stat 2>/dev/null)\" = S ] || echo \"en\"\"ded-$((1+1))\"",
            "ended-2",
            10,
        )?;
        type_keys(&mon, "\t")?;
        // As many processors as the machine has (SLATE_SHAPE=refpc: 32).
        con.wait_for("system-monitor: resources: ", 10)?;
        con.wait_for(" processors at ", 5)?;
        type_keys(&mon, "\t")?;
        con.wait_for(" file systems", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // Disks: the blank disk erased, partitioned and formatted.
        con.send("disks &\r")?;
        con.wait_for_all(
            &["(system), gpt: ", "disks: vdb 256 MiB, no table: no partitions", "\"disks\" from pid"],
            15,
        )?;
        pause(1200);
        type_keys(&mon, "e")?;
        pause(300);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("disks: done: table vdb", 20)?;
        con.wait_for("disks: vdb 256 MiB, gpt: no partitions", 10)?;
        con.run("cat /sys/block/vdb/slate_table", "gpt", 10)?;
        // A 100 MiB FAT32 partition, named Data.
        type_keys(&mon, "n")?;
        pause(300);
        for _ in 0..6 {
            monitor(&mon, &["sendkey backspace"])?;
        }
        type_keys(&mon, "100\n")?;
        con.wait_for("disks: done: add vdb 1 100 fat32 Data", 30)?;
        con.wait_for("disks: vdb 256 MiB, gpt: vdb1 FAT32", 10)?;
        con.run("cat /sys/block/vdb/vdb1/slate_fs_label /sys/block/vdb/vdb1/size | tr '\\n' ,", "DATA,204800,", 10)?;
        // Formatted again, as SlateFS.
        type_keys(&mon, "f")?;
        pause(300);
        type_keys(&mon, "\t")?;
        monitor(&mon, &["sendkey right"])?;
        type_keys(&mon, "\n")?;
        pause(300);
        type_keys(&mon, "\n")?;
        con.wait_for("disks: done: format vdb1 slatefs", 30)?;
        con.wait_for("disks: vdb 256 MiB, gpt: vdb1 SlateFS", 10)?;
        con.run("cat /sys/block/vdb/vdb1/slate_fs", "slatefs", 10)?;
        // Mounted in /run/media for the person asking (ADR 0112's
        // addendum), without set-user-ID programs; unmounted; renamed. The
        // udev database knows what it holds (devd looks every 5 s).
        type_keys(&mon, "m")?;
        con.wait_for("disks: done: mount vdb1", 20)?;
        con.run("grep -c '^/dev/vdb1 /run/media/root/vdb1 slatefs rw,nosuid,nodev' /proc/mounts", "1", 10)?;
        type_keys(&mon, "m")?;
        con.wait_for("disks: done: unmount vdb1", 20)?;
        con.run("echo m$(grep -c /run/media /proc/mounts)-$(ls /run/media/root | wc -l)", "m0-0", 10)?;
        type_keys(&mon, "r")?;
        pause(300);
        type_keys(&mon, "Stuff\n")?;
        con.wait_for("disks: done: name vdb1 Stuff", 20)?;
        con.run("grep PARTNAME /sys/block/vdb/vdb1/uevent", "PARTNAME=Stuff", 10)?;
        con.run(
            "sleep 6; grep -l 'E:ID_PART_ENTRY_NAME=Stuff' /run/udev/data/b* | xargs grep -c 'E:ID_FS_TYPE=slatefs'",
            "1",
            15,
        )?;
        // A second partition, with nothing on it, then deleted.
        monitor(&mon, &["sendkey right"])?;
        type_keys(&mon, "n")?;
        pause(300);
        type_keys(&mon, "\t\t")?;
        monitor(&mon, &["sendkey left"])?;
        type_keys(&mon, "\n")?;
        con.wait_for("disks: done: add vdb 101 ", 30)?;
        con.wait_for("vdb1 SlateFS, vdb2 nothing known", 10)?;
        monitor(&mon, &["sendkey delete"])?;
        pause(300);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("disks: done: delete vdb2", 30)?;
        con.wait_for("disks: vdb 256 MiB, gpt: vdb1 SlateFS", 10)?;
        con.run("ls /dev | grep -c '^vdb' ", "2", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // The Linux runtime's upgrades (ADR 0102's addendum), with a
        // runtime of our own whose apk writes a mark: moved onto its own
        // subvolume, a failed upgrade puts it back as it was, a good one
        // keeps the one before for slate-linux rollback.
        con.run(
            "slate-compat on && R=/var/lib/slate/linux && mkdir -p $R/etc $R/bin $R/sbin $R/dev $R/proc \
             && echo 3.22.6 > $R/etc/alpine-release && echo before > $R/etc/mark && cp /bin/sh $R/bin/sh \
             && printf '#!/bin/sh\\necho during > /etc/mark\\nexit 1\\n' > $R/sbin/apk && chmod 755 $R/sbin/apk \
             && echo runtime-$((1+1))",
            "runtime-2",
            10,
        )?;
        con.run("slate-linux upgrade; cat /var/lib/slate/linux/etc/mark", "is as it was (Alpine 3.22.6)", 60)?;
        con.run(
            "echo $(cat /var/lib/slate/linux/etc/mark)-$(grep -c ' /var/lib/slate/linux slatefs' /proc/mounts)",
            "before-1",
            10,
        )?;
        con.run(
            "printf '#!/bin/sh\\necho after > /etc/mark\\n' > /var/lib/slate/linux/sbin/apk && slate-linux upgrade",
            "the runtime before is kept",
            60,
        )?;
        con.run("cat /var/lib/slate/linux/etc/mark", "after", 10)?;
        con.run("slate-linux rollback && cat /var/lib/slate/linux/etc/mark", "before", 30)?;
        // Strata's background check (ADR 0112): the indexes and the count
        // for the top bar.
        con.run(
            "software-updater --check && cat ~/.cache/slate/updates",
            "software-updater: background check: 1 updates",
            60,
        )?;
        // The Software Updater: checks (c) and finds the newer base.
        con.send("software-updater &\r")?;
        con.wait_for_all(&["software-updater: Slate ", "\"updater\" from pid"], 15)?;
        pause(600);
        type_keys(&mon, "c")?;
        con.wait_for(&format!("software-updater: checked: 1 updates: slate-base {v} -> {v}.1"), 60)?;
        pause(600);
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        // Restart from the launcher's power dialog, installing the update
        // first: the Software Updater installs it in its window, saying
        // how far it is, closes it, and Strata restarts.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        type_keys(&mon, "restart\n")?;
        pause(600);
        monitor(&mon, &["sendkey down", "sendkey tab", "sendkey tab", "sendkey tab", "sendkey tab", "sendkey spc"])?;
        pause(300);
        screendump(&mon, "tools-power-updates.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata: power: closing 0 windows to Restart", 10)?;
        con.wait_for("strata: power: installing the updates first", 10)?;
        con.wait_for("software-updater: installing before the session ends", 15)?;
        con.wait_for("software-updater: Bringing the running system up to date: 1 of 1", 240)?;
        let next = con.line_after("software-updater: installed; ", 240)?;
        let next = next.trim_end_matches(" starts next").to_string();
        con.wait_for("strata: power: the updates are installed", 30)?;
        con.wait_for("strata: power: restart", 10)?;
        con.wait_exit(60)?;
        Ok(next)
    })();
    // The first boot's transcript, before the second's.
    let mut first = String::new();
    let result = result.and_then(|next| {
        first = crate::qemu::strip_ansi(&con.log);
        // The new system starts (on trial), and the Software Updater rolls
        // it back.
        let mut c = base_command(o, &img)?;
        add_disk(&mut c, 1, &disk);
        c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
        c.arg(format!("unix:{},server,nowait", mon.display()));
        con = Console::start(c)?;
        con.wait_for(&format!("trying {next}"), 60)?;
        con.login()?;
        con.run("cat /usr/share/slate/release", &format!("Slate {v}.1"), 10)?;
        con.run(&format!("grep '^kernel:' /proc/slate_boot | grep -c /boot/slate/{next}/"), "1", 10)?;
        con.send("export SLATE_APPS_TRACE=1; strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        con.send("software-updater &\r")?;
        con.wait_for_all(&["software-updater: Slate ", "\"updater\" from pid"], 15)?;
        pause(600);
        type_keys(&mon, "r")?;
        pause(300);
        type_keys(&mon, "\n")?;
        let back = con.line_after("software-updater: rolled back; ", 60)?;
        let back = back.trim_end_matches(" starts next").to_string();
        con.run("slate-update status | tail -1", &format!("default={back}"), 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-shift-e"])?;
        con.wait_for("strata: leaving", 15)?;
        con.poweroff()
    });
    if result.is_err() {
        con.drain(500);
    }
    let log = first + &crate::qemu::strip_ansi(&con.log);
    let _ = std::fs::write(target_dir().join("tools-scenario.log"), log);
    if let Err(e) = result {
        con.kill();
        return Err(format!("system tools scenario: {e} (transcript in target/tools-scenario.log)"));
    }
    // The partition Disks formatted, and the root after the updates.
    crate::slatefsimg::fsck(&disk, 1 << 20, "the SlateFS Disks made")?;
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "SlateFS root after the system tools scenario")?;
    println!(
        "xtask: system tools scenario passed (a process found, its details shown and its priority lowered, the tree, the process ended, the resources read; a disk erased, \
         partitioned, formatted as FAT32 and SlateFS, mounted, unmounted and renamed, a partition deleted; a Linux runtime's failed upgrade undone and a good one rolled back; a newer base found, installed by \
         restarting from the power dialog with the updates first, started and rolled back; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
