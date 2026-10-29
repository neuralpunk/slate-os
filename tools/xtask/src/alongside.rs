// SPDX-License-Identifier: MIT OR Apache-2.0

//! The alongside scenario (M27 phase 1, ADR 0116): SlateOS installed
//! beside another system on the same disk.
//!
//! The other system is a SlateOS image as `cargo xtask image` makes it
//! (slate-loader on its own EFI System Partition, a SlateFS root found by
//! `root=PARTLABEL=slate-root`), on a 64 GiB disk with a data partition
//! after it and free space after that. The text installer, from the USB
//! stick, offers to go beside it and does, encrypted; the host then finds
//! the other system's partitions, their table entries and the boot code
//! byte for byte as they were. The new system boots (the installer's boot
//! entry), lists the other on its menu, and chooses it for the next boot
//! (`slate-update next`); the next boot chainloads the other system's
//! loader, which boots it; the boot after that is the new system's again.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use slate_gpt::{Guid, Partition};

use crate::qemu::{
    Console, INSTALL_PASSWORD, PROMPT, disk_partitions, partition_offset, reference_pc, strip_ansi, type_keys,
};
use crate::{Opts, Result, image, target_dir};

const DISK: u64 = 64 << 30;
const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;
/// The data partition after the other system: 256 MiB from 512 MiB.
const DATA: (u64, u64) = (512 * MIB / SECTOR, 768 * MIB / SECTOR - 1);
/// The other system's entry on the new menu.
const OTHER: &str = "SlateOS (another installation)";

/// The other system's disk: the image's partitions in their slots on a
/// bigger disk (a new table for its size, the boot code kept), and the
/// data partition, with a pattern in it.
fn other_disk(o: &Opts) -> Result<PathBuf> {
    let img = image::build(o, "", "alongside-other.img", image::Root::Disk)?;
    let disk = target_dir().join("alongside-disk.img");
    let _ = std::fs::remove_file(&disk);
    std::fs::copy(&img, &disk).map_err(|e| e.to_string())?;
    let old = disk_partitions(&disk)?;
    let names: Vec<String> =
        old.iter().map(|e| String::from_utf16_lossy(&e.name_utf16).trim_end_matches('\0').to_string()).collect();
    let mut parts: Vec<(u32, Partition<'_>)> = old
        .iter()
        .zip(&names)
        .map(|(e, name)| {
            let p = Partition {
                type_guid: e.type_guid,
                unique_guid: e.unique_guid,
                first_lba: e.first_lba,
                last_lba: e.last_lba,
                attributes: e.attributes,
                name,
            };
            (e.index, p)
        })
        .collect();
    let data = Partition {
        type_guid: Guid::BASIC_DATA,
        unique_guid: crate::image::guid_for("alongside-data"),
        first_lba: DATA.0,
        last_lba: DATA.1,
        attributes: 0,
        name: "data",
    };
    parts.push((3, data));
    let gpt = slate_gpt::encode_slots(DISK / SECTOR, crate::image::guid_for("slate-disk"), &parts)
        .map_err(|e| format!("GPT: {e:?}"))?;
    let mut f = std::fs::OpenOptions::new().read(true).write(true).open(&disk).map_err(|e| e.to_string())?;
    f.set_len(DISK).map_err(|e| e.to_string())?;
    let mut write = |at: u64, data: &[u8]| -> Result {
        f.seek(SeekFrom::Start(at)).and_then(|_| f.write_all(data)).map_err(|e| e.to_string())
    };
    // The protective record for the new size; slate-loader's boot code
    // stays.
    let mut s0 = [0u8; 512];
    {
        let mut r = std::fs::File::open(&disk).map_err(|e| e.to_string())?;
        r.read_exact(&mut s0).map_err(|e| e.to_string())?;
    }
    s0[446..512].copy_from_slice(&gpt.protective_mbr[446..512]);
    write(0, &s0)?;
    write(SECTOR, &gpt.primary_header)?;
    write(2 * SECTOR, &gpt.entries)?;
    write(gpt.backup_entries_lba * SECTOR, &gpt.entries)?;
    write(gpt.backup_header_lba * SECTOR, &gpt.backup_header)?;
    let pattern: Vec<u8> = (0..(DATA.1 + 1 - DATA.0) * SECTOR).map(|i| (i % 251) as u8).collect();
    write(DATA.0 * SECTOR, &pattern)?;
    Ok(disk)
}

/// What must stay as it was: the boot sector, the table's entries in
/// slots 0 to 3, and those partitions' bytes.
fn kept(disk: &Path) -> Result<Vec<Vec<u8>>> {
    let mut f = std::fs::File::open(disk).map_err(|e| e.to_string())?;
    let mut read = |at: u64, len: u64| -> Result<Vec<u8>> {
        let mut b = vec![0u8; len as usize];
        f.seek(SeekFrom::Start(at)).and_then(|_| f.read_exact(&mut b)).map_err(|e| e.to_string())?;
        Ok(b)
    };
    let mut out = vec![read(0, SECTOR)?];
    let table = read(2 * SECTOR, 4 * 128)?;
    out.push(table);
    for e in disk_partitions(disk)?.iter().filter(|e| e.index < 4) {
        out.push(read(e.first_lba * SECTOR, (e.last_lba + 1 - e.first_lba) * SECTOR)?);
    }
    Ok(out)
}

pub fn alongside_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let stick = crate::iso::usb_copy(o, true, &target_dir().join("alongside-stick.img"))?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&stick)
        .and_then(|f| f.set_len(15 << 30))
        .map_err(|e| e.to_string())?;
    let disk = other_disk(o)?;
    let before = kept(&disk)?;
    let mon = target_dir().join("alongside-monitor.sock");
    let _ = std::fs::remove_file(&mon);

    // The text installer, beside the other system.
    let mut con = Console::start(reference_pc(o, &disk, Some(&stick), &mon, None)?)?;
    let typed = (|| -> Result {
        con.wait_for("Install on which disk? [1]: ", 90)?;
        // The USB keyboard may still be coming up (as in the install
        // scenario): 'r' until the list comes again.
        let mut listed = false;
        for _ in 0..15 {
            type_keys(&mon, "r\n")?;
            if con.wait_for("Install on which disk? [1]: ", 2).is_ok() {
                listed = true;
                break;
            }
        }
        if !listed {
            return Err("the installer never saw a key from the USB keyboard".into());
        }
        type_keys(&mon, "\n")?;
        con.wait_for("sda holds:", 20)?;
        con.wait_for_all(&["EFI System Partition", "SlateFS", "BIOS boot", "Free space"], 5)?;
        con.wait_for("1) Install beside them, in the free space", 5)?;
        con.wait_for("How should SlateOS be installed? [1]: ", 10)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Which layout? [1]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Time zone [America/New_York]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Your name: ", 20)?;
        type_keys(&mon, "Ada Lovelace\n")?;
        con.wait_for("Username [ada]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Computer name [ada-slate]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Password: ", 20)?;
        type_keys(&mon, &format!("{INSTALL_PASSWORD}\n"))?;
        con.wait_for("Again:", 20)?;
        type_keys(&mon, &format!("{INSTALL_PASSWORD}\n"))?;
        con.wait_for("Encrypt the disk? [Y/n]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Install the Strata desktop? [Y/n]: ", 20)?;
        type_keys(&mon, "n\n")?;
        con.wait_for("Turn on Linux compatibility mode? [y/N]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Use a fixed address? [y/N]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Remove the USB stick, then press Enter to restart.", 300)?;
        type_keys(&mon, "\n")?;
        con.wait_exit(60).map(|_| ())
    })();
    let _ = std::fs::write(target_dir().join("alongside-live.log"), strip_ansi(&con.log));
    if let Err(e) = typed {
        con.kill();
        return Err(format!("alongside scenario (installing): {e}"));
    }
    let installed = started.elapsed().as_secs_f64();
    if kept(&disk)? != before {
        return Err("alongside scenario: the other system's partitions, their entries or the boot code changed".into());
    }
    let numbers: Vec<u32> = disk_partitions(&disk)?.iter().map(|e| e.index + 1).collect();
    if numbers != [1, 2, 3, 4, 5, 6] {
        return Err(format!("alongside scenario: the disk has partitions {numbers:?}, not 1 to 6"));
    }
    let root = partition_offset(&disk, "slate-root-2")?;
    crate::slatefsimg::fsck_with(&disk, root, "the new root", Some(INSTALL_PASSWORD))?;

    // The new system: the installer's boot entry starts it.
    let _ = std::fs::remove_file(&mon);
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, None)?)?;
    let first = (|| -> Result {
        con.wait_for("Password to unlock /dev/sda6: ", 60)?;
        std::thread::sleep(std::time::Duration::from_millis(1500));
        type_keys(&mon, &format!("{INSTALL_PASSWORD}\n"))?;
        con.wait_for("unlocked as /dev/dm-0", 30)?;
        con.wait_for("login: ", 90)?;
        con.send("ada\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{INSTALL_PASSWORD}\r"))?;
        con.wait_for("ada@slate:~$ ", 15)?;
        con.send("su -\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{INSTALL_PASSWORD}\r"))?;
        con.wait_for(PROMPT, 15)?;
        con.wait_for("# ", 5)?;
        con.run("grep -c 'root=PARTUUID=' /proc/cmdline", "1", 10)?;
        con.run(
            "c=$(slate-boot list | grep '^BootCurrent' | cut -c14-17); echo entry-$(slate-boot list | grep \"^Boot$c \" \
             | grep -c ' Slate ')",
            "entry-1",
            10,
        )?;
        // Its menu: SlateOS, then the other system.
        con.run("echo \"menu:$(slate-update next | tr '\\n' '|')end\"", &format!("menu:Slate|{OTHER}|end"), 10)?;
        con.run(&format!("slate-update next '{OTHER}'"), &format!("{OTHER} starts at the next boot"), 10)?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("alongside-new.log"), strip_ansi(&con.log));
    if let Err(e) = first {
        con.kill();
        return Err(format!("alongside scenario (the new system): {e}"));
    }

    // The other system, chainloaded once.
    let _ = std::fs::remove_file(&mon);
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, None)?)?;
    let other = (|| -> Result {
        con.wait_for(&format!("slate-loader: booting {OTHER} (EFI/BOOT/BOOTX64.EFI)"), 60)?;
        con.login()?;
        con.run("echo \"[$(grep -o 'root=PARTLABEL=[a-z0-9-]*' /proc/cmdline)]\"", "[root=PARTLABEL=slate-root]", 10)?;
        // Its own menu, which its boot left alone.
        con.run("echo \"menu:$(slate-update next | tr '\\n' '|')end\"", "menu:Slate|end", 10)?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("alongside-other.log"), strip_ansi(&con.log));
    if let Err(e) = other {
        con.kill();
        return Err(format!("alongside scenario (the other system): {e}"));
    }
    crate::slatefsimg::fsck(&disk, partition_offset(&disk, "slate-root")?, "the other system's root")?;

    // Once only: the new system is the default again.
    let _ = std::fs::remove_file(&mon);
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, None)?)?;
    let again = con.wait_for("Password to unlock /dev/sda6: ", 60);
    con.kill();
    let _ = std::fs::write(target_dir().join("alongside-again.log"), strip_ansi(&con.log));
    again.map_err(|e| format!("alongside scenario (the boot after): {e}"))?;
    println!(
        "xtask: alongside scenario passed (installed beside another system in {installed:.1}s, which stayed byte for \
         byte; both boot, the other once from the new menu; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
