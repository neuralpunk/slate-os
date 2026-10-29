// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-update: atomic system updates with rollback (ADR 0027), on a
//! SlateFS root through the kernel's `SLATEFS_IOC_CTL` ioctl.
//!
//! `begin` snapshots the running `system-N` as `system-N+1` and mounts it
//! at /run/update; anything (quarry --root /run/update, a script) changes
//! it there; `commit` makes it the next boot, with the running system as
//! the fallback. A new system that fails to boot rolls back by itself; one
//! that boots is confirmed by `boot-ok` (slinit runs it).
//!
//! Each system carries its own kernel (`/boot/slate/kernel`), and the EFI
//! System Partition follows the boot state (ADR 0086): after every change
//! of it, and after every boot, the default's and the fallback's kernels
//! are put there and the boot menu switched to them ([`crate::esp`]).
//!
//! `/etc` crosses over too (ADR 0087): each new system's base (`/etc` as
//! it was when it was made) is kept in `/var`, and `commit` and
//! `rollback` merge what the running system changed since into the
//! system that boots next (`slate_etcsync`).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use slate_rt::subvol::{self, Subvol, ctl, flagged, running, system_number};
use slate_rt::{eprintln, fs, lossy, println};

const USAGE: &str = "usage: slate-update COMMAND

  status     subvolumes and the boot state
  begin      snapshot the running system and mount the copy at /run/update
  commit     boot the updated system next time (the running one is the fallback)
  abort      drop the update in progress
  rollback   boot the fallback system next time
  boot-ok    confirm the running system (slinit does this after booting)
  prune      delete system subvolumes that are neither running, default nor fallback
  sync-boot  put the default's and the fallback's kernels on the boot partition
  next [TITLE]  list the boot menu, or start its entry TITLE at the next boot, once
";

const MOUNT_AT: &str = "/run/update";
const STATE: &str = "/run/slate-update";

type Res<T = ()> = Result<T, String>;

/// Full graphics on trial (ADR 0173): the broker leaves this after
/// `graphics=full`; `boot-ok` waits while it is there.
pub const GRAPHICS_TRIAL: &str = "/var/lib/slate/graphics-trial";

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| lossy(a).into_owned()).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("slate-update: {e}");
            1
        }
    }
}

fn subvols() -> Res<Vec<Subvol>> {
    subvol::list()
}

fn run(args: &[String]) -> Res {
    // The one-shot choice of what boots next (ADR 0116).
    if args.first().map(String::as_str) == Some("next") {
        crate::esp::lock()?;
        let title = (args.len() > 1).then(|| args[1..].join(" "));
        let titles = crate::esp::next(title.as_deref())?;
        match title {
            Some(t) => println!("{t} starts at the next boot"),
            None => titles.iter().for_each(|t| println!("{t}")),
        }
        return Ok(());
    }
    let [cmd] = args else { return Err(USAGE.trim_end().into()) };
    if matches!(cmd.as_str(), "begin" | "commit" | "abort" | "rollback" | "boot-ok" | "prune" | "sync-boot") {
        crate::esp::lock()?;
    }
    match cmd.as_str() {
        "status" => {
            let list = subvols()?;
            for v in &list {
                println!("{} {} {}", v.id, v.name, v.flags.join(","));
            }
            slate_rt::print!("{}", ctl("/", "boot")?);
            Ok(())
        }
        "begin" => begin(),
        "commit" => commit(),
        "abort" => abort(),
        "rollback" => {
            let list = subvols()?;
            let fallback = flagged(&list, "fallback").ok_or("there is no fallback system")?;
            let current = running(&list)?;
            if fallback != current {
                carry_into(&current, &fallback)?;
            }
            ctl("/", &format!("boot default={fallback} fallback={current} tries=0 pending=0"))?;
            println!("{fallback} boots next time");
            sync_boot()
        }
        // A system with full graphics on trial (ADR 0173) waits for its
        // person: slate-graphics-trial takes the mark away and confirms
        // it, or takes AMD's firmware away again.
        "boot-ok" if fs::exists(GRAPHICS_TRIAL.as_bytes()) => {
            slate_rt::println!("slate-update: full graphics is on trial; slate-graphics-trial confirms it");
            Ok(())
        }
        "boot-ok" => match ctl("/", "boot-ok") {
            // The boot partition follows the boot state (a crash between
            // the two, or a rollback at boot, heals here).
            Ok(_) => sync_boot_quietly(),
            // Nothing to confirm on other root file systems.
            Err(e) if e.contains("not SlateFS") => Ok(()),
            Err(e) => Err(e),
        },
        "sync-boot" => sync_boot(),
        "prune" => {
            let list = subvols()?;
            let keep = [running(&list).ok(), flagged(&list, "default"), flagged(&list, "fallback")];
            for v in &list {
                if system_number(&v.name).is_some() && !keep.iter().any(|k| k.as_deref() == Some(v.name.as_str())) {
                    ctl("/", &format!("delete {}", v.name))?;
                    println!("deleted {}", v.name);
                }
            }
            let left: Vec<String> = subvols()?.into_iter().map(|v| v.name).collect();
            slate_etcsync::prune_bases(&left);
            sync_boot()
        }
        "-h" | "--help" => {
            slate_rt::print!("{USAGE}");
            Ok(())
        }
        _ => Err(USAGE.trim_end().into()),
    }
}

fn begin() -> Res {
    if fs::exists(STATE.as_bytes()) {
        return Err(format!("an update is already in progress (see {MOUNT_AT}; commit or abort it)"));
    }
    let list = subvols()?;
    let name = subvol::next_system(&list, 1);
    ctl("/", &format!("snapshot {name}"))?;
    // The base for the commit's merge: /etc as both have it now.
    let r = subvol::mount(&name, MOUNT_AT).and_then(|()| slate_etcsync::save_base(&name, &running(&list)?, "/etc"));
    if let Err(e) = r {
        let _ = fs::umount(MOUNT_AT.as_bytes());
        let _ = ctl("/", &format!("delete {name}"));
        return Err(e);
    }
    fs::write_file(STATE.as_bytes(), name.as_bytes(), 0o644).map_err(|e| format!("{STATE}: {e}"))?;
    println!("{name} is mounted at {MOUNT_AT}; change it, then run slate-update commit");
    Ok(())
}

fn unmount() -> Res {
    fs::umount(MOUNT_AT.as_bytes()).map_err(|e| format!("{MOUNT_AT}: {e}"))
}

fn in_progress() -> Res<String> {
    let b = fs::read_file(STATE.as_bytes()).map_err(|_| "no update in progress (slate-update begin)".to_string())?;
    Ok(String::from_utf8_lossy(&b).trim().to_string())
}

fn commit() -> Res {
    let name = in_progress()?;
    let current = running(&subvols()?)?;
    // A kernel that cannot run the new system's unlock program is refused
    // before anything changes (ADR 0086).
    let mounts = lossy(&fs::read_file(b"/proc/mounts").unwrap_or_default()).into_owned();
    let encrypted = mounts.lines().any(|l| l.starts_with("/dev/dm-") && l.split(' ').nth(1) == Some("/"));
    crate::esp::boot_files(&name, MOUNT_AT, encrypted, &[])?;
    // What the running system changed in /etc since `begin` goes along
    // (ADR 0087).
    let new_etc = format!("{MOUNT_AT}/etc");
    match slate_etcsync::carry(&name, Some(&current), "/etc", &new_etc)? {
        Some(o) => println!("{}", slate_etcsync::describe(&o)),
        None => println!("/etc: no record of {name}'s start; it keeps /etc as the update left it"),
    }
    // The base for a later rollback: the new system's /etc as it starts,
    // so a rollback carries back only what changed while it ran, not the
    // update's own changes.
    slate_etcsync::save_base(&name, &current, &new_etc)?;
    unmount()?;
    ctl("/", &format!("boot default={name} fallback={current} tries=1 pending=1"))?;
    let _ = fs::unlink(STATE.as_bytes());
    println!("{name} boots next time; {current} stays as the fallback");
    sync_boot()
}

/// Put the boot state's systems on the boot partition (ADR 0086).
fn sync_boot() -> Res {
    if let Some(d) = crate::esp::sync(&subvols()?, false)? {
        println!("{}", crate::esp::describe(&d));
    }
    Ok(())
}

/// The same after a boot: a line only when something changed.
fn sync_boot_quietly() -> Res {
    if let Some(d) = crate::esp::sync(&subvols()?, true)?
        && d.report != slate_esp::Report::default()
    {
        println!("slate-update: {}", crate::esp::describe(&d));
    }
    Ok(())
}

/// Before a rollback from `current` to `target`: what `current` changed
/// in /etc since it was made from `target` goes there (ADR 0087).
fn carry_into(current: &str, target: &str) -> Res {
    const AT: &str = "/run/slate-update-etc";
    subvol::mount(target, AT)?;
    let r = slate_etcsync::carry(current, Some(target), "/etc", &format!("{AT}/etc"));
    let _ = fs::umount(AT.as_bytes());
    match r? {
        Some(o) => println!("{}", slate_etcsync::describe(&o)),
        None => println!("/etc: {current} was not made from {target}; {target} keeps its own /etc"),
    }
    Ok(())
}

fn abort() -> Res {
    let name = in_progress()?;
    unmount()?;
    ctl("/", &format!("delete {name}"))?;
    slate_etcsync::drop_base(&name);
    let _ = fs::unlink(STATE.as_bytes());
    println!("dropped {name}");
    Ok(())
}
