// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask gpu-bench [--release] [--cmdline S] [--give-back]`: the
//! GPU test bench (ADR 0157, M32 phase 1; ADR 0168): Slate in a QEMU guest
//! on the reference PC's Fedora with one of the reference PC's GPUs passed through (VFIO),
//! driven from the development machine over SSH, so a driver meets a real card without
//! anyone at the reference PC's keyboard.
//!
//! - The card is the reference PC's Raphael iGPU (1002:164e at 0000:15:00.0), alone
//!   in its IOMMU group. Fedora's own display is on the RTX 3080, which
//!   the bench refuses to take.
//! - The bench binds the iGPU to vfio-pci (amdgpu lets it go; Fedora's
//!   desktop doesn't use it), streams the image from the development machine into the reference PC's
//!   /run (a tmpfs: nothing is written to Fedora's drive, ADR 0076), and
//!   boots it with KVM, the serial console coming back over SSH.
//! - The guest lists the card (`lspci`) and its configuration space
//!   (the BARs); Slate's AMD display driver reads its IP discovery table
//!   and its VBIOS (QEMU gives the guest the host's VFCT table) and says
//!   what is connected (ADR 0171); then it powers off.
//!   Later phases add what their drivers do with it.
//! - `SLATE_GPU_RUN=COMMAND` runs a command in the guest (after the
//!   checks; it ends in `;` or `&`), `SLATE_GPU_HOLD=SECONDS` keeps the
//!   guest up that long before it
//!   powers off (to look at what the iGPU's outputs show).
//! - `--give-back` hands the iGPU back to amdgpu. Linux 7.2.12's amdgpu
//!   can't take it again without a reboot (it leaves its `ip_discovery`
//!   directory in sysfs when it lets go, and the second probe fails,
//!   observed 2026-10-28); the card then has no driver until the reference PC
//!   restarts, which is harmless: Fedora's display is on the RTX.
//!   Run it before rebooting the reference PC: once, rebooting with the iGPU still
//!   on vfio-pci hung the reference PC after Fedora's shutdown, until a reset
//!   (2026-10-28).
//!
//! The iGPU has no reset of its own (only its bus's, shared with
//! the reference PC's USB controllers), so each guest finds it as the last one left
//! it. A monitor on the board's HDMI or DisplayPort output lets a driver
//! light it (the owner plugs one in when a phase needs it).

use std::process::{Command, Stdio};

use crate::qemu::Console;
use crate::{Opts, Result, image, target_dir};

/// A setting for reaching the reference PC: from the environment, else
/// from `refpc.conf` at the checkout's root (`NAME=value` lines, kept out
/// of git): `SLATE_REFPC` (`user@host`, required), `SLATE_REFPC_PORT`
/// (22 if unset) and `SLATE_REFPC_KEY` (an identity file; ssh's own
/// choice if unset).
fn setting(name: &str) -> Option<String> {
    if let Ok(v) = std::env::var(name) {
        return Some(v);
    }
    let conf = std::fs::read_to_string(crate::root().join("refpc.conf")).ok()?;
    conf.lines().filter_map(|l| l.trim().split_once('=')).find(|(k, _)| k.trim() == name).map(|(_, v)| {
        let v = v.trim();
        match (v.strip_prefix("~/"), std::env::var("HOME")) {
            (Some(rest), Ok(home)) => format!("{home}/{rest}"),
            _ => v.to_string(),
        }
    })
}

/// The reference PC over SSH, with keys only.
fn ssh() -> Result<Command> {
    let host = setting("SLATE_REFPC")
        .ok_or("gpu-bench: say where the reference PC is: SLATE_REFPC=user@host (or refpc.conf)")?;
    let port = setting("SLATE_REFPC_PORT").unwrap_or_else(|| "22".into());
    let mut c = Command::new("ssh");
    c.args([
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-p",
        &port,
    ]);
    if let Some(key) = setting("SLATE_REFPC_KEY") {
        c.args(["-o", "IdentitiesOnly=yes", "-i", &key]);
    }
    c.arg(host);
    Ok(c)
}

/// Run `script` on the reference PC with `sh -e`; its output.
fn remote(script: &str) -> Result<String> {
    let out =
        ssh()?.arg(format!("sh -ec '{}'", script.replace('\'', "'\\''"))).output().map_err(|e| format!("ssh: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        return Err(format!("on the reference PC: {}{}", text, String::from_utf8_lossy(&out.stderr)));
    }
    Ok(text)
}

/// The card: its PCI address and vendor:device, checked before anything
/// is done to it.
const CARD: &str = "0000:15:00.0";
const CARD_ID: &str = "1002:164e";
/// Where the guest's files live on the reference PC: a tmpfs.
const DIR: &str = "/run/slate-gpu-bench";
/// The bench's image.
pub const IMAGE: &str = "slate-gpu-bench.img";
/// AMD's firmware for the iGPU's display (DCN 3.1.5's DMCUB, and the
/// PSP's TOC it is loaded with), as Fedora's linux-firmware has it on
/// the reference PC (xz), kept in target/ (ADR 0171).
/// And GC 10.3.6's and SDMA 5.2.6's, for 2D acceleration (ADR 0172).
const FIRMWARE: [&str; 9] = [
    "amdgpu/dcn_3_1_5_dmcub.bin",
    "amdgpu/psp_13_0_5_toc.bin",
    "amdgpu/sdma_5_2_6.bin",
    "amdgpu/gc_10_3_6_ce.bin",
    "amdgpu/gc_10_3_6_pfp.bin",
    "amdgpu/gc_10_3_6_me.bin",
    "amdgpu/gc_10_3_6_mec.bin",
    "amdgpu/gc_10_3_6_mec2.bin",
    "amdgpu/gc_10_3_6_rlc.bin",
];

fn firmware_copy(name: &str) -> std::path::PathBuf {
    target_dir().join("gpu/refpc").join(name.rsplit('/').next().unwrap_or(name))
}

/// The reference PC's copies of the firmware into target/, once.
fn fetch_firmware() -> Result {
    for name in FIRMWARE {
        let to = firmware_copy(name);
        if to.exists() {
            continue;
        }
        std::fs::create_dir_all(to.parent().unwrap_or(&to)).map_err(|e| e.to_string())?;
        let out = ssh()?.arg(format!("xz -dc /lib/firmware/{name}.xz")).output().map_err(|e| format!("ssh: {e}"))?;
        if !out.status.success() || out.stdout.is_empty() {
            return Err(format!("gpu-bench: the reference PC has no {name}: {}", String::from_utf8_lossy(&out.stderr)));
        }
        std::fs::write(&to, &out.stdout).map_err(|e| format!("{}: {e}", to.display()))?;
    }
    Ok(())
}

/// The firmware into an image's /lib/firmware.
pub fn stage_firmware(stage: &std::path::Path) -> Result {
    for name in FIRMWARE {
        let to = stage.join("lib/firmware").join(name);
        std::fs::create_dir_all(to.parent().unwrap_or(&to)).map_err(|e| e.to_string())?;
        std::fs::copy(firmware_copy(name), &to).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

pub fn run(o: &Opts) -> Result {
    if o.give_back {
        return give_back();
    }
    fetch_firmware()?;
    // GC's firmware only on a GPU fresh from amdgpu (ADR 0172): a guest
    // that shut down with GC wedged twice hung the reference PC when its iGPU was
    // reset, so the reference PC is rebooted first when a guest has had it.
    if o.cmdline.as_deref().unwrap_or("").contains("slate.amd.gcfw") {
        fresh_gpu()?;
    }
    let img = image::build(o, o.cmdline.as_deref().unwrap_or(""), IMAGE, image::Root::Disk)?;
    let size = std::fs::metadata(&img).map_err(|e| e.to_string())?.len();
    // The card is the one expected, alone in its group; /run is a tmpfs
    // with room; then the card goes to vfio-pci.
    let info = remote(&format!(
        "d=/sys/bus/pci/devices/{CARD}
         id=$(printf %04x:%04x $(cat $d/vendor) $(cat $d/device) 2>/dev/null || true)
         id=$(echo $id | sed s/0x//g)
         [ \"$id\" = {CARD_ID} ] || {{ echo \"{CARD} is $id, not {CARD_ID}\"; exit 1; }}
         n=$(ls $d/iommu_group/devices | wc -l)
         [ $n = 1 ] || {{ echo \"{CARD} shares its IOMMU group\"; exit 1; }}
         [ \"$(stat -f -c %T /run)\" = tmpfs ] || {{ echo \"/run is not a tmpfs\"; exit 1; }}
         avail=$(df --output=avail -B1 /run | tail -1)
         [ $avail -gt $(({size} + (1 << 30))) ] || {{ echo \"/run has $avail bytes free\"; exit 1; }}
         modprobe vfio-pci
         drv=$(basename $(readlink $d/driver) 2>/dev/null || echo none)
         if [ $drv != vfio-pci ]; then
           echo vfio-pci > $d/driver_override
           [ $drv = none ] || echo {CARD} > $d/driver/unbind
           echo {CARD} > /sys/bus/pci/drivers_probe
         fi
         echo driver: $(basename $(readlink $d/driver)) was: $drv
         pkill -f \"[q]emu-system-x86_64 -name slate-gpu-bench\" || true
         mkdir -p {DIR}
         cp /usr/share/edk2/ovmf/OVMF_VARS.fd {DIR}/vars.fd
         cp /sys/firmware/acpi/tables/VFCT {DIR}/VFCT.bin
         ls /usr/share/edk2/ovmf/OVMF_CODE.fd"
    ))?;
    print!("xtask: gpu-bench: the reference PC: {info}");
    if !info.contains("driver: vfio-pci") {
        return Err("gpu-bench: the card didn't go to vfio-pci".into());
    }
    // The image, streamed into the reference PC's memory.
    println!("xtask: gpu-bench: sending {} ({} MB) to the reference PC", img.display(), size >> 20);
    let file = std::fs::File::open(&img).map_err(|e| e.to_string())?;
    let st =
        ssh()?.arg(format!("cat > {DIR}/slate.img")).stdin(Stdio::from(file)).status().map_err(|e| e.to_string())?;
    if !st.success() {
        return Err(format!("gpu-bench: sending the image: {st}"));
    }
    let mut c = ssh()?;
    // At most 15 minutes (and any hold), whatever happens to this end.
    let hold = std::env::var("SLATE_GPU_HOLD").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
    c.arg(format!(
        "exec timeout {} qemu-system-x86_64 -name slate-gpu-bench -machine q35 -accel kvm -cpu host \
         -smp 4 -m 4G -no-reboot \
         -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd \
         -drive if=pflash,format=raw,file={DIR}/vars.fd \
         -drive file={DIR}/slate.img,format=raw,if=none,id=disk0 -device virtio-blk-pci,drive=disk0,bootindex=0 \
         -netdev user,id=net0 -device virtio-net-pci,netdev=net0 \
         -device vfio-pci,host={CARD} -acpitable file={DIR}/VFCT.bin \
         -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
         -display none -serial stdio",
        900 + hold
    ));
    let mut con = Console::start(c)?;
    let r = (|| -> Result {
        con.login()?;
        con.run("lspci -nn -k; echo listed$((1+1))", "listed2", 30)?;
        // Its configuration space: the BARs at 10h to 27h.
        con.run("lspci -d 1002: -x; echo config$((1+1))", "config2", 30)?;
        // Slate's AMD display driver (ADR 0171): the IP discovery table
        // read from the card's memory, the VBIOS from the host's VFCT
        // table (given to the guest), the connectors and their HPD, and
        // the GPU's memory (the carve-out, BAR 0).
        // DMCUB starts on a thread of its own once the root is there.
        con.run(
            "for i in $(seq 30); do dmesg | grep -q -e 'amd 00:04.0: card' -e 'DMCUB trace' -e 'no DMCUB' -e \"didn't light\" -e 'nothing lit' && break; \
             grep -q slate.amd.bars /proc/cmdline && dmesg | grep -q 'colour squares' && break; \
             grep -q slate.amd=off /proc/cmdline && dmesg | grep -q 'init commands' && break; sleep 1; done; \
             dmesg | grep -e 'amd 00:04.0' -e firmware:; echo amd$((1+1))",
            "amd2",
            60,
        )?;
        let log = crate::qemu::strip_ansi(&con.log);
        for want in [
            "1002:164e",
            "DCN 3.1.5, GC 10.3.6",
            "Raphael Generic VBIOS",
            "HDMI-A-1 on PHY A, HPD Some(1)",
            "memory: 512 MiB at GPU 0xf400000000, system 0x2040000000",
        ] {
            if !log.contains(want) {
                return Err(format!("the AMD display driver didn't say {want:?}"));
            }
        }
        // The owner's monitor, when it is on the reference PC's HDMI (M32 phase 4;
        // phase 6 runs without it).
        let monitor = log.contains("HDMI-A-1 on PHY A, HPD Some(1), DDC 0x90: connected");
        let forced = log.contains("lit at 1920x1080 at 60 Hz anyway");
        if monitor && !log.contains("HDMI-A-1: EDID 256 bytes, AUS 27ad \"VG278\"") {
            return Err("the AMD display driver didn't read the monitor's EDID".into());
        }
        // DMCUB's firmware, loaded by the PSP, runs and says it is ready
        // (ADR 0171).
        for want in [
            "firmware: /lib/firmware/amdgpu/dcn_3_1_5_dmcub.bin",
            "PSP loaded DMCUB's firmware",
            // Its boot status: 43h after amdgpu, 0Bh ("restore
            // required") after an earlier guest; `dmub::start` checks the
            // ready bits.
            "DMCUB running firmware 0x05003700",
        ] {
            if !log.contains(want) {
                return Err(format!("the AMD display driver didn't say {want:?}"));
            }
        }
        // M32 phase 6 (ADR 0172): with `slate.amd.sdma`, SDMA0 fills,
        // copies and writes in the carve-out, and its fence comes.
        if o.cmdline.as_deref().unwrap_or("").contains("slate.amd.sdma") {
            let want = "fence came after";
            let done = "filled true, copied true, written true";
            if !log.contains(want) || !log.contains(done) {
                return Err(format!("SDMA0 didn't say {want:?} and {done:?}"));
            }
            // And through the GART, to and from the system's memory.
            let gart = "RAM to the carve-out true, the carve-out to RAM true";
            if !log.contains(gart) {
                return Err(format!("SDMA0 didn't say {gart:?}"));
            }
        }
        // With `slate.amd.gcfw slate.amd.compute`, GC's firmware through
        // the PSP and a WRITE_DATA on MEC1's queue (ADR 0172, step 5).
        if o.cmdline.as_deref().unwrap_or("").contains("slate.amd.compute") {
            for want in [
                "the RLC's autoload completed",
                "WRITE_DATA came after",
                "1024 of 1024 dwords filled, 1024 of 1024 after them untouched",
                "0 of 16384 pixels differ from the CPU's",
            ] {
                if !log.contains(want) {
                    return Err(format!("the AMD driver didn't say {want:?}"));
                }
            }
        }
        // Unless told otherwise, it lights the HDMI monitor and offers it
        // as a card with flips, the hardware cursor and an overlay plane
        // (step 8).
        let cmdline = o.cmdline.as_deref().unwrap_or("");
        let lights = !cmdline.contains("slate.amd.bars") && !cmdline.contains("slate.amd=off") && (monitor || forced);
        let card = "at 60 Hz on HDMI-A-1 (flips, hardware cursor, overlay)";
        if lights && !log.contains(card) {
            return Err(format!("the AMD display driver didn't say {card:?}"));
        }
        // And SDMA0 copies for it (M32 phase 6, step 4).
        let engine = "SDMA0 copies for the card";
        if lights && !cmdline.contains("slate.amd.copy=cpu") && !log.contains(engine) {
            return Err(format!("the AMD display driver didn't say {engine:?}"));
        }
        let log = crate::qemu::strip_ansi(&con.log);
        if !log.contains(&format!("[{CARD_ID}]")) && !log.contains(CARD_ID) {
            return Err(format!("the guest doesn't list {CARD_ID}"));
        }
        // SLATE_GPU_RUN=COMMAND runs in the guest first (Strata, say).
        if let Ok(cmd) = std::env::var("SLATE_GPU_RUN") {
            // COMMAND ends in `;` or `&`.
            con.run(&format!("{cmd} sleep 5; echo ran$((1+1))"), "ran2", 60)?;
        }
        // SLATE_GPU_HOLD=SECONDS keeps the guest (and what it shows) up
        // before it powers off, for someone to look at the monitor.
        if let Some(secs) = std::env::var("SLATE_GPU_HOLD").ok().and_then(|v| v.parse::<u32>().ok()) {
            println!("xtask: gpu-bench: holding the guest for {secs} s");
            // The log so far, to read while the guest holds.
            let _ = std::fs::write(target_dir().join("gpu-bench.log"), crate::qemu::strip_ansi(&con.log));
            con.run(&format!("sleep {secs}; echo held$((1+1))"), "held2", u64::from(secs) + 30)?;
        }
        con.poweroff()
    })();
    let log = target_dir().join("gpu-bench.log");
    std::fs::write(&log, crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    if r.is_err() {
        // A clean power-off first, so the driver switches the display off
        // (a DMCUB loaded later can't switch off a link left lit).
        let _ = con.poweroff();
        con.kill();
        let _ = remote("pkill -f \"[q]emu-system-x86_64 -name slate-gpu-bench\" || true");
    }
    let _ = remote(&format!("rm -rf {DIR}"));
    r.map_err(|e| format!("gpu-bench: {e} (log in {})", log.display()))?;
    println!("xtask: gpu-bench: the guest saw {CARD_ID}; log in {}", log.display());
    Ok(())
}

/// The iGPU as amdgpu leaves it after the reference PC boots: if it isn't on
/// amdgpu now (a guest has had it), the reference PC is rebooted (the iGPU given
/// back first, as CLAUDE.md asks) and waited for, up to six minutes.
fn fresh_gpu() -> Result {
    let driver =
        || remote(&format!("basename $(readlink /sys/bus/pci/devices/{CARD}/driver) 2>/dev/null || echo none"));
    if driver()?.trim() == "amdgpu" {
        return Ok(());
    }
    println!(
        "xtask: gpu-bench: the reference PC's iGPU has been in a guest since it booted; rebooting the reference PC for a fresh one"
    );
    let _ = give_back();
    let _ = ssh()?.arg("systemctl reboot").output();
    std::thread::sleep(std::time::Duration::from_secs(20));
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(360) {
        if let Ok(d) = driver()
            && d.trim() == "amdgpu"
        {
            println!("xtask: gpu-bench: the reference PC is back after {} s", start.elapsed().as_secs() + 20);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    Err("gpu-bench: the reference PC didn't come back with its iGPU on amdgpu within six minutes".into())
}

/// The iGPU back to amdgpu.
fn give_back() -> Result {
    let out = remote(&format!(
        "d=/sys/bus/pci/devices/{CARD}
         drv=$(basename $(readlink $d/driver) 2>/dev/null || echo none)
         [ $drv = vfio-pci ] && echo {CARD} > $d/driver/unbind
         echo > $d/driver_override
         echo {CARD} > /sys/bus/pci/drivers_probe
         echo driver: $(basename $(readlink $d/driver) 2>/dev/null || echo none)"
    ))?;
    print!("xtask: gpu-bench: the reference PC: {out}");
    if !out.contains("driver: amdgpu") {
        return Err("gpu-bench: amdgpu didn't take the iGPU back (it can't without a reboot of the reference PC, \
                    which returns it; until then it has no driver, and the bench can still use it)"
            .into());
    }
    Ok(())
}
