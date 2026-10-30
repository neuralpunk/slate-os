// SPDX-License-Identifier: MIT OR Apache-2.0

//! Running Slate in QEMU, interactively or as a test harness.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use crate::{Opts, Result, image, run_cmd, target_dir};

/// QEMU exit statuses produced by the kernel through `isa-debug-exit`
/// (`(value << 1) | 1`; see kernel/src/arch/x86_64/qemu.rs).
const EXIT_SUCCESS: i32 = (0x10 << 1) | 1;
const EXIT_FAILURE: i32 = (0x11 << 1) | 1;

const DEFAULT_TEST_TIMEOUT: u64 = 300;

/// Paths searched for the OVMF firmware pair (Fedora's edk2-ovmf first).
/// Override with `SLATE_OVMF_CODE` and `SLATE_OVMF_VARS`.
const OVMF_CANDIDATES: &[(&str, &str)] = &[
    ("/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
];

fn ovmf() -> Result<(PathBuf, PathBuf)> {
    if let (Ok(c), Ok(v)) = (std::env::var("SLATE_OVMF_CODE"), std::env::var("SLATE_OVMF_VARS")) {
        return Ok((c.into(), v.into()));
    }
    OVMF_CANDIDATES
        .iter()
        .map(|(c, v)| (PathBuf::from(c), PathBuf::from(v)))
        .find(|(c, v)| c.exists() && v.exists())
        .ok_or_else(|| "OVMF not found; install edk2-ovmf or set SLATE_OVMF_CODE/SLATE_OVMF_VARS".into())
}

/// The QEMU command line shared by every mode: q35, 4 CPUs, 4 GiB, the image
/// on virtio-blk, the debug-exit device, and no reboot on triple fault.
pub fn base_command(o: &Opts, img: &Path) -> Result<Command> {
    base_command_net(o, img, "")
}

/// [`base_command`] with extra user-network options (`netdev` appended
/// after `user,id=net0`, such as `,hostfwd=tcp:127.0.0.1:2222-:22`).
pub fn base_command_net(o: &Opts, img: &Path, netdev: &str) -> Result<Command> {
    Ok(with_disk_and_net(machine(o)?, img, netdev))
}

/// [`base_command`] with its own copy of the UEFI variables, for machines
/// that run beside others (QEMU locks the file).
fn base_command_vars(o: &Opts, img: &Path, vars: &Path) -> Result<Command> {
    Ok(with_disk_and_net(machine_vars(o, "q35", vars, true)?, img, ""))
}

fn with_disk_and_net(mut c: Command, img: &Path, netdev: &str) -> Command {
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "virtio-blk-pci,drive=disk0,bootindex=0"]);
    // User-mode networking: DHCP gives 10.0.2.15, the host is 10.0.2.2.
    c.arg("-netdev").arg(format!("user,id=net0{netdev}"));
    c.args(["-device", "virtio-net-pci,netdev=net0"]);
    if let Ok(dump) = std::env::var("SLATE_PCAP") {
        c.arg("-object").arg(format!("filter-dump,id=dump0,netdev=net0,file={dump}"));
    }
    c
}

/// The machine without disks or network cards: q35, 4 CPUs, 4 GiB (see
/// SLATE_SHAPE, SLATE_SMP and SLATE_MEM), the
/// firmware, the debug-exit device, no reboot on triple fault.
pub fn machine(o: &Opts) -> Result<Command> {
    machine_of(o, "q35")
}

/// [`machine`] with another QEMU machine type (and its options).
pub fn machine_of(o: &Opts, kind: &str) -> Result<Command> {
    // A copy of the variables per machine: QEMU locks the file, and the
    // gate runs machines side by side (ADR 0120).
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = target_dir().join("ovmf-vars");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    machine_vars(o, kind, &dir.join(format!("{n}.fd")), true)
}

/// [`machine_of`] with the UEFI variables in `vars`: fresh ones when
/// `fresh` (or none are there yet), else those a previous boot left.
fn machine_vars(o: &Opts, kind: &str, vars_copy: &Path, fresh: bool) -> Result<Command> {
    let mut c = Command::new("qemu-system-x86_64");
    // SLATE_SHAPE=refpc: the reference PC's shape (ADR 0076) as far as
    // QEMU on the development host goes: 32 CPUs and 32 GiB, allocated
    // before the guest starts (-mem-prealloc), so the guest does not pay
    // for the host allocating memory on first touch (1.5 s of boot at 40
    // GiB; under 1 ms on the reference PC itself). SLATE_SMP and SLATE_MEM still win.
    let (mem, refpc) = guest_memory();
    let smp_default = if refpc { "32" } else { "4" };
    // SLATE_SMP overrides the CPU count.
    let smp = std::env::var("SLATE_SMP").unwrap_or_else(|_| smp_default.into());
    c.args(["-machine", kind, "-smp", &smp, "-m", &mem, "-no-reboot"]);
    if refpc {
        // All of it is taken at once: never more than the host can spare
        // (a run once took the development machine out of memory, 2026-10-23).
        let want = size_bytes(&mem).ok_or_else(|| format!("SLATE_MEM={mem}: not a size QEMU takes"))?;
        let spare = mem_available().unwrap_or(0).saturating_sub(HOST_RESERVE);
        if want > spare {
            return Err(format!(
                "a guest with {mem} preallocated needs {} GiB the host does not have ({} GiB free besides {} GiB \
                 kept for the host)",
                want >> 30,
                spare >> 30,
                HOST_RESERVE >> 30
            ));
        }
        c.arg("-mem-prealloc");
    }
    // SLATE_CPU picks another CPU model (QEMU -cpu syntax), for example
    // one without AVX like the reference PC's Celeron.
    if let Ok(cpu) = std::env::var("SLATE_CPU") {
        c.args(["-accel", if kvm_available() { "kvm" } else { "tcg" }, "-cpu", &cpu]);
    } else if kvm_available() {
        c.args(["-accel", "kvm", "-cpu", "host,migratable=no,+invtsc"]);
    } else {
        c.args(["-accel", "tcg", "-cpu", "max"]);
    }
    if !o.bios {
        let (code, vars) = ovmf()?;
        if fresh || !vars_copy.exists() {
            std::fs::copy(&vars, vars_copy).map_err(|e| format!("copying {}: {e}", vars.display()))?;
        }
        c.arg("-drive").arg(format!("if=pflash,format=raw,readonly=on,file={}", code.display()));
        c.arg("-drive").arg(format!("if=pflash,format=raw,file={}", vars_copy.display()));
    }
    c.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    Ok(c)
}

/// SLATE_RES=WxH for the machines people use (`run`, `try-install`): a
/// standard VGA card whose EDID offers that size as its own (QEMU's default
/// is 1280x800); slate-loader sets the firmware to it (ADR 0111) and the
/// desktop comes up at that size. The default card takes no `-global`, so
/// this one replaces it.
fn screen_size(c: &mut Command) -> Result {
    let Ok(res) = std::env::var("SLATE_RES") else { return Ok(()) };
    let (w, h) = parse_res(&res).ok_or_else(|| format!("SLATE_RES={res}: want WIDTHxHEIGHT, like 1920x1080"))?;
    // The card's 16 MiB holds 1920x1080 and a little more; bigger screens
    // get a power of two that fits one frame of 32-bit pixels.
    let mib = (u64::from(w) * u64::from(h) * 4).div_ceil(1 << 20).next_power_of_two().max(16);
    c.args(["-vga", "none", "-device"]).arg(format!("VGA,xres={w},yres={h},vgamem_mb={mib}"));
    Ok(())
}

/// `WxH` (`1920x1080`) as a width and a height, each from 480 to 8192.
fn parse_res(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let (w, h) = (w.trim().parse::<u32>().ok()?, h.trim().parse::<u32>().ok()?);
    let fits = |n: u32| (480..=8192).contains(&n);
    (fits(w) && fits(h)).then_some((w, h))
}

/// Send monitor commands to a QEMU started with `-monitor unix:PATH`,
/// waiting for the socket to appear.
pub fn monitor(path: &Path, commands: &[&str]) -> Result {
    use std::os::unix::net::UnixStream;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut s = loop {
        match UnixStream::connect(path) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("QEMU monitor {}: {e}", path.display())),
        }
    };
    for c in commands {
        s.write_all(format!("{c}\n").as_bytes()).map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// [`monitor`], `gap_ms` between the commands.
pub fn monitor_paced(path: &Path, commands: &[String], gap_ms: u64) -> Result {
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(path).map_err(|e| format!("QEMU monitor {}: {e}", path.display()))?;
    for c in commands {
        s.write_all(format!("{c}\n").as_bytes()).map_err(|e| e.to_string())?;
        std::thread::sleep(Duration::from_millis(gap_ms));
    }
    Ok(())
}

/// Storage plugged in and taken out while Slate runs (M23 phase 4): an
/// NVMe drive added behind an empty PCIe root port, read, and removed.
fn hotplug_scenario(o: &Opts) -> Result {
    let img = target_dir().join("slate-session.img");
    let disk = target_dir().join("hotplug-nvme.img");
    let data: Vec<u8> = (0..(8u32 << 20)).map(|i| (i % 253) as u8).collect();
    std::fs::write(&disk, &data).map_err(|e| format!("writing {}: {e}", disk.display()))?;
    let mon = target_dir().join("hotplug-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = machine(o)?;
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "virtio-blk-pci,drive=disk0,bootindex=0"]);
    c.args(["-device", "pcie-root-port,id=hp0,chassis=30,slot=30"]);
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=hpdisk", disk.display()));
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        let wait = |present: bool| {
            format!(
                "for i in $(seq 100); do {} [ -e /dev/nvme0n1 ] && break; sleep 0.1; done; ",
                if present { "" } else { "!" }
            )
        };
        for round in 1..=2 {
            // Plugged in: an ACPI device check (GPE 1, _E01), the slot's BARs
            // from the root port's window, the NVMe driver, the disk.
            monitor(&mon, &["device_add nvme,id=hpnvme,serial=hot0,drive=hpdisk,bus=hp0"])?;
            con.run(
                &format!("{}head -c 4 /dev/nvme0n1 | od -An -tx1 | tr -d ' ' | sed 's/^/data-/'", wait(true)),
                "data-00010203",
                20,
            )?;
            con.run("grep -c 'bound' /proc/slate_drivers | sed 's/^/drivers-/'; echo", "drivers-", 10)?;
            // In sysfs behind its root port (M23 phase 7), and in lspci.
            let nested = "for l in /sys/bus/pci/devices/*; do readlink $l; done | grep -c '/0000:00:[0-9a-f.]*/0000:'";
            con.run(&format!("echo nested-$({nested})-$(lspci -n -d 1b36:0010 -s 01: | wc -l)"), "nested-1-1", 10)?;
            // Taken out: an eject request, the driver lets go, _EJ0; QEMU
            // drops the device (the next round's device_add would fail with
            // the same id otherwise).
            monitor(&mon, &["device_del hpnvme"])?;
            con.run(
                &format!("{}echo gone-{round}-$(grep -c nvme0n1 /proc/partitions)", wait(false)),
                &format!("gone-{round}-0"),
                20,
            )?;
            // Only its own entries go: the root bus's functions stay.
            con.run(
                &format!("echo unlisted-$({nested})-$(lspci -s 01: | wc -l)-$(lspci -s 00:00.0 | wc -l)"),
                "unlisted-0-0-1",
                10,
            )?;
            std::thread::sleep(Duration::from_millis(500));
        }
        con.run("dmesg | grep -c 'eject request' | sed 's/^/ejects-/'", "ejects-2", 10)?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("hotplug-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("hot-plug scenario: {e} (transcript in target/hotplug-scenario.log)"));
    }
    println!(
        "xtask: hot-plug scenario passed (an NVMe drive plugged in, read and ejected through ACPI, twice; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The QEMU device type of the CPUs `machine_of` gives (for device_add).
fn cpu_type() -> String {
    let model = match std::env::var("SLATE_CPU") {
        Ok(cpu) => cpu.split(',').next().unwrap_or("max").to_string(),
        Err(_) if kvm_available() => "host".into(),
        Err(_) => "max".into(),
    };
    format!("{model}-x86_64-cpu")
}

/// Two Intel gigabit cards (QEMU's igb, each behind its own PCIe port as on
/// the reference PC) with no virtio network: the first has no cable, so
/// the network must move to the second (ADR 0029), then DHCP and an HTTP
/// exchange (quarry fetching an index) must work over it.
fn nic_scenario(o: &Opts) -> Result {
    // With the test programs (/test/netsend).
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-nic.img", image::Root::Disk)?;
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let mon = target_dir().join("nic-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = machine(o)?;
    // Room for a fifth CPU, plugged in later (a general-purpose event).
    c.args(["-smp", "4,sockets=1,cores=5,threads=1,maxcpus=5"]);
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "virtio-blk-pci,drive=disk0,bootindex=0"]);
    for i in 0..2 {
        c.args(["-netdev", &format!("user,id=n{i}")]);
        c.args(["-device", &format!("pcie-root-port,id=rp{i},chassis={},slot={}", i + 1, i + 1)]);
        c.args(["-device", &format!("igb,netdev=n{i},bus=rp{i},id=nic{i}")]);
    }
    c.args(["-display", "none", "-serial", "stdio", "-S", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let mut rate: Option<String> = None;
    let result = (|| -> Result {
        monitor(&mon, &["set_link nic0 off", "cont"])?;
        con.login()?;
        // netd (ADR 0048) configures the card with a link and leaves the
        // other alone.
        con.run(
            "for i in $(seq 100); do grep -q 'eth1 up dhcp 10.0.2.15/24' /run/netd/status && break; sleep 0.2; done; \
             grep -q '^eth0 down' /run/netd/status && grep -q 'eth1 up dhcp 10.0.2.15/24' /run/netd/status && echo link$((1+1))",
            "link2",
            30,
        )?;
        con.run(&format!("echo 'main http://10.0.2.2:{}/v1' > /etc/quarry/repos", repos.port), "", 10)?;
        con.run("quarry update", "main: 3 packages", 30)?;
        // 256 MiB over TCP to the host through the igb card, every byte
        // checked there (phase 6: what segmentation offload changes).
        let sink = crate::hostnet::TcpSink::start()?;
        con.run(&format!("/test/netsend 10.0.2.2 {} 256", sink.port), "netsend: 268435456 bytes", 120)?;
        match sink.finish() {
            Some((268_435_456, true)) => {}
            other => return Err(format!("the host received {other:?} from netsend")),
        }
        rate = con.log.rsplit("netsend: 268435456 bytes in ").next().and_then(|l| l.lines().next()).map(String::from);

        // Device interrupts are spread over the CPUs (ADR 0079): the igb
        // cards' MSIs arrive away from CPU0.
        con.run(
            "awk '/PCI-MSI/ && /igb/ { for (i = 3; i <= 5; i++) away += $i } END { print \"away-\" (away > 0) }' \
             /proc/interrupts",
            "away-1",
            10,
        )?;
        // Their interrupts carried the traffic: no card fell back to
        // polling.
        if con.log.contains("polling the card") {
            return Err("an igb card took frames without interrupts".into());
        }
        // A CPU plugged in: QEMU raises general-purpose event 2, whose
        // _E02 method (run by the acpi thread, ADR 0079) notifies the CPU.
        monitor(&mon, &[&format!("device_add {},id=cpu4,socket-id=0,core-id=4,thread-id=0", cpu_type())])?;
        con.wait_for(": device check; hot-plug is not handled yet", 15)?;
        // The ACPI power button: a clean shutdown through init.
        monitor(&mon, &["system_powerdown"])?;
        con.wait_for("power button pressed", 15)?;
        match con.wait_exit(60)? {
            Some(0) => Ok(()),
            code => Err(format!("QEMU exited with {code:?} after the power button")),
        }
    })();
    repos.stop();
    if let Err(e) = result {
        con.kill();
        return Err(format!("NIC scenario: {e}"));
    }
    println!(
        "xtask: NIC scenario passed (igb, link failover, DHCP, HTTP, 256 MiB sent in {}, a CPU plugged in (GPE), \
         power button; {:.2}s)",
        rate.as_deref().unwrap_or("?"),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// USB Ethernet (ADR 0046): the only network card is QEMU's `usb-net`, a
/// CDC Ethernet device on the xHCI controller. Slate must pick its CDC
/// configuration, take its MAC address, get an address by DHCP and fetch
/// over HTTP through it.
fn usb_net_scenario(o: &Opts) -> Result {
    let img = target_dir().join("slate-session.img");
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let mon = target_dir().join("usbnet-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = machine(o)?;
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "virtio-blk-pci,drive=disk0,bootindex=0"]);
    c.args(["-device", "qemu-xhci,id=xhci", "-netdev", "user,id=u0"]);
    c.args(["-device", "usb-net,netdev=u0,bus=xhci.0,id=usbnet0,mac=52:54:00:5c:0e:01"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run(
            "for i in $(seq 100); do grep -q 'eth0 up dhcp 10.0.2.15/24' /run/netd/status && break; sleep 0.2; done; \
             dmesg | grep -q 'Ethernet eth0 (52:54:00:5c:0e:01)' && grep -q 'eth0 up dhcp 10.0.2.15' /run/netd/status && echo usbnet$((1+1))",
            "usbnet2",
            40,
        )?;
        con.run(&format!("echo 'main http://10.0.2.2:{}/v1' > /etc/quarry/repos", repos.port), "", 10)?;
        con.run("quarry update", "main: 3 packages", 30)?;
        // Packages fetched over the adapter, installed, run.
        con.run("quarry install hello >/dev/null 2>&1; hello", "hello 1.0: greetings", 30)?;
        // Pulled out and plugged in again: the new adapter takes over.
        monitor(&mon, &["device_del usbnet0"])?;
        con.run(
            "for i in $(seq 50); do dmesg | grep -q 'device removed' && break; sleep 0.1; done; echo gone$((1+1))",
            "gone2",
            15,
        )?;
        monitor(&mon, &["device_add usb-net,netdev=u0,bus=xhci.0,id=usbnet1,mac=52:54:00:5c:0e:02"])?;
        con.run(
            "for i in $(seq 100); do grep -q '^eth0 down' /run/netd/status && grep -q 'eth1 up dhcp 10.0.2.' /run/netd/status \
             && break; sleep 0.2; done; \
             grep -q '^eth0 down' /run/netd/status && grep -q 'eth1 up dhcp 10.0.2.' /run/netd/status && echo back$((1+1)) || \
             { cat /run/netd/status; dmesg | tail -n 25; }",
            "back2",
            40,
        )?;
        con.run("quarry update", "main: 3 packages", 30)?;
        con.poweroff()
    })();
    repos.stop();
    if let Err(e) = result {
        con.kill();
        return Err(format!("USB Ethernet scenario: {e}"));
    }
    println!(
        "xtask: USB Ethernet scenario passed (usb-net: CDC configuration, MAC string, DHCP, HTTP, unplugged and plugged again; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// netd (ADR 0048): two cards on two networks (QEMU user networking on
/// 10.0.2.0/24 and 10.0.3.0/24): DHCP on both, then a fixed address on
/// the second from /etc/slate/network; the name servers of both in
/// /etc/resolv.conf; HTTP through each; the first card's link going down
/// (its configuration goes, the second card carries on) and up again.
fn netd_scenario(o: &Opts) -> Result {
    // A fresh image of its own: the scenario changes /etc/slate/network,
    // and the session image is only made fresh by the session scenario.
    let img = image::build(o, "", "slate-netd.img", image::Root::Disk)?;
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let dns = crate::hostnet::UdpServer::dns()?;
    let sntp = crate::hostnet::UdpServer::sntp()?;
    let mon = target_dir().join("netd-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = machine(o)?;
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "virtio-blk-pci,drive=disk0,bootindex=0"]);
    for (i, net) in ["", ",net=10.0.3.0/24,dhcpstart=10.0.3.50,ipv6-net=fec1::/64"].iter().enumerate() {
        c.args(["-netdev", &format!("user,id=n{i}{net}")]);
        c.args(["-device", &format!("pcie-root-port,id=rp{i},chassis={},slot={}", i + 1, i + 1)]);
        c.args(["-device", &format!("igb,netdev=n{i},bus=rp{i},id=nic{i}")]);
    }
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let started = Instant::now();
    let mut con = Console::start(c)?;
    // Wait until /run/netd/status has `line`, then print `tag`2.
    let until = |line: &str, tag: &str| {
        format!(
            "for i in $(seq 150); do grep -q '{line}' /run/netd/status 2>/dev/null && break; sleep 0.2; done; \
             grep -q '{line}' /run/netd/status && echo {tag}$((1+1))"
        )
    };
    let result = (|| -> Result {
        con.login()?;
        con.run(&until("eth0 up dhcp 10.0.2.15/24 via 10.0.2.2.* dns 10.0.2.3", "first"), "first2", 40)?;
        con.run(&until("eth1 up dhcp 10.0.3.50/24 via 10.0.3.2.* dns 10.0.3.3", "second"), "second2", 40)?;
        // The kernel's own configuration stepped aside.
        con.run("dmesg | grep -q 'user space configures the network now' && echo handed$((1+1))", "handed2", 10)?;
        // IPv6 from QEMU's routers (ADR 0050): an address on each card's
        // prefix (EUI-64 of 52:54:00:12:34:56 and :57). Their advertisements
        // name no DNS server (no RDNSS option), so IPv6 DNS is set by hand
        // below.
        con.run(&until("eth0 up dhcp .* inet6 fec0::5054:ff:fe12:3456/64", "slaac"), "slaac2", 40)?;
        con.run(&until("eth1 up dhcp .* inet6 fec1::5054:ff:fe12:3457/64", "slaac1"), "slaac12", 40)?;
        // A fixed address on the second card; the first card's name server
        // is xtask's test server (ADR 0052), ahead of DHCP's.
        con.run(
            &format!(
                "printf '[eth0]\\ndns = 10.0.2.2:{}\\n[eth1]\\nmethod = static\\naddress = 10.0.3.20/24\\n\
                 gateway = 10.0.3.2\\ndns = 10.0.3.3 fec1::3\\naddress6 = fec1::20/64\\ngateway6 = fec1::2\\n' \
                 > /etc/slate/network && service netd restart && echo restarted$((1+1))",
                dns.port
            ),
            "restarted2",
            20,
        )?;
        con.run(&until("eth1 up static 10.0.3.20/24 via 10.0.3.2.* dns 10.0.3.3", "fixed"), "fixed2", 40)?;
        con.run(&until("eth1 up static .* inet6 fec1::20/64.* dns 10.0.3.3 fec1::3", "fixed6"), "fixed62", 40)?;
        // Name lookups go through netd's cache on 127.0.0.53.
        con.run("grep -q '^nameserver 127.0.0.53$' /etc/resolv.conf && echo cache$((1+1))", "cache2", 10)?;
        con.run(
            // The default route through fec1::2, metric 100 + index 3.
            "awk '$1 == \"00000000000000000000000000000000\" && $5 == \"fec10000000000000000000000000002\" \
             && $6 == \"00000067\" { print \"gw6\" 2 }' /proc/net/ipv6_route",
            "gw62",
            10,
        )?;
        con.run(&until("eth0 up dhcp 10.0.2.15/24", "again"), "again2", 40)?;
        con.run("[ $(awk '$2 == \"00000000\"' /proc/net/route | wc -l) = 2 ] && echo both$((1+1))", "both2", 10)?;
        // Slate's own tools (ADR 0052): names looked up through the cache,
        // and straight from the server over IPv6.
        con.run("lookup www.slate.test", "www.slate.test has address 10.0.2.2", 20)?;
        con.run("lookup www.slate.test", "www.slate.test has IPv6 address fec0::2", 20)?;
        con.run(
            &format!("lookup -6 -s '[fec0::2]:{}' v6.slate.test", dns.port),
            "v6.slate.test has IPv6 address fec0::2",
            20,
        )?;
        con.run("lookup no.such.invalid; echo rc=$?", "rc=1", 20)?;
        // ping over each card, IPv4 and IPv6, and by name (user::net checks
        // that ping sockets need no privilege).
        con.run("ping -c 2 -W 2 10.0.2.2", "2 packets transmitted, 2 received", 20)?;
        con.run("ping -c 1 -W 2 10.0.3.2", "1 packets transmitted, 1 received", 20)?;
        con.run("ping -6 -c 1 -W 3 fec1::2", "1 packets transmitted, 1 received", 20)?;
        con.run("ping6 -c 1 -W 3 fec0::2", "1 packets transmitted, 1 received", 20)?;
        con.run("ping -c 1 -W 2 www.slate.test", "bytes from 10.0.2.2", 20)?;
        // ip shows and changes addresses, routes and links.
        con.run("ip -4 addr show eth1", "inet 10.0.3.20/24 brd 10.0.3.255 scope global eth1", 10)?;
        con.run("ip -6 addr show dev eth1", "inet6 fec1::20/64 scope global", 10)?;
        con.run("ip route", "default via 10.0.3.2 dev eth1", 10)?;
        // The bare forms (no subcommand) once panicked (M23, on the reference PC).
        con.run(
            "ip addr | grep -c 'inet 10.0.3.20/24'; ip link | grep -c '^[0-9]*: eth1:'; echo bare$((1+1))",
            "bare2",
            10,
        )?;
        con.run("ip neigh >/dev/null && ip link >/dev/null && echo bare-ok$((1+1))", "bare-ok2", 10)?;
        con.run(
            "ip addr add 10.0.3.99/24 dev eth1 && ip route add 192.0.2.0/24 via 10.0.3.2 dev eth1 && \
             ip link set eth1 mtu 1400 && echo set$(ip addr show eth1 | grep -c -e 'inet 10.0.3.99/24' -e 'mtu 1400')\
             $(ip route | grep -c '^192.0.2.0/24 via 10.0.3.2 dev eth1')",
            "set21",
            10,
        )?;
        con.run(
            "ip addr del 10.0.3.99/24 dev eth1 && ip route del 192.0.2.0/24 via 10.0.3.2 && ip link set eth1 mtu 1500 \
             && echo unset$(ip addr show eth1 | grep -c -e 10.0.3.99 -e 'mtu 1400')$(ip route | grep -c 192.0.2.0)",
            "unset00",
            10,
        )?;
        con.run("ip route add 192.0.2.0/24 dev nosuch", "Cannot find device", 10)?;
        con.run(
            "ip addr add 10.0.3.20/24 dev eth1 2>/tmp/ip.err; echo rc=$? $(cat /tmp/ip.err)",
            "rc=2 RTNETLINK answers: File exists",
            10,
        )?;
        // ss lists the SSH server's socket, with the process holding it
        // and its user and inode, and by state.
        con.run("ss -tlnH | awk '$4 ~ /:22$/ { print \"ssh\" 2 }'", "ssh2", 10)?;
        con.run(
            "echo sshd$(ss -tlnpeH | grep ':22 ' | grep -c 'users:((\"sshd\",pid=[0-9]*,fd=[0-9]*).* uid:0 ino:[1-9]')",
            "sshd1",
            10,
        )?;
        con.run("echo listen$(ss -tnH state listening | grep -c ':22 ')", "listen1", 10)?;
        // ip's other forms: brief and one-line, the route an address takes,
        // and a flush (netd puts eth1's address back when it restarts).
        con.run("echo brief$(ip -br addr show eth1 | grep -c '^eth1  .* 10.0.3.20/24 ')", "brief1", 10)?;
        con.run("ip -o -4 addr show eth1", "eth1    inet 10.0.3.20/24 brd 10.0.3.255 scope global eth1\\", 10)?;
        con.run("ip route get 10.0.3.2", "10.0.3.2 dev eth1 src 10.0.3.20 uid 0", 10)?;
        con.run("echo stats$(ip -s link show eth1 | grep -c 'RX:  bytes')", "stats1", 10)?;
        con.run(
            "ip addr add 10.0.3.98/24 dev eth1 && ip -4 addr flush dev eth1 && echo flushed$(ip -4 addr show eth1 | grep -c inet)",
            "flushed0",
            10,
        )?;
        // NTP (ADR 0052): a clock far in the past is stepped to the host's.
        con.run(
            &format!(
                "date -s '2001-02-03 04:05:06' > /dev/null && printf 'server 10.0.2.2:{}\\n' > /etc/slate/ntp && \
                 service netd restart && echo ntp$((1+1))",
                sntp.port
            ),
            "ntp2",
            20,
        )?;
        con.run(&until("ntp synced 10.0.2.2 10.0.2.2 offset +[0-9]*.[0-9]*s stepped", "synced"), "synced2", 40)?;
        let year = std::process::Command::new("date").arg("+%Y").output().map_err(|e| e.to_string())?;
        let year = String::from_utf8_lossy(&year.stdout).trim().to_string();
        con.run(&format!("[ $(date +%Y) = {year} ] && echo year$((1+1))"), "year2", 10)?;
        // HTTP through each card.
        for gw in ["10.0.2.2", "10.0.3.2"] {
            con.run(&format!("echo 'main http://{gw}:{}/v1' > /etc/quarry/repos", repos.port), "", 10)?;
            con.run("quarry update", "main: 3 packages", 30)?;
        }
        // The first card loses its link: its address and routes go; the
        // second card carries on.
        monitor(&mon, &["set_link nic0 off"])?;
        con.run(&until("eth0 down", "down"), "down2", 30)?;
        con.run("grep -q '^eth0' /proc/net/route || echo noroute$((1+1))", "noroute2", 10)?;
        con.run("quarry update", "main: 3 packages", 30)?;
        monitor(&mon, &["set_link nic0 on"])?;
        con.run(&until("eth0 up dhcp 10.0.2.15/24 via 10.0.2.2", "up"), "up2", 40)?;
        con.run(&until("eth0 up dhcp .* dns 10.0.2.2:[0-9]* 10.0.2.3", "dns"), "dns2", 10)?;
        // The settings from the command line (ADR 0054): slate-network as
        // root, then the broker's network= action.
        con.run("slate-network eth1 static 10.0.3.21/24 gateway 10.0.3.2 dns 10.0.3.3", "", 20)?;
        con.run(&until("eth1 up static 10.0.3.21/24 via 10.0.3.2", "cli"), "cli2", 40)?;
        con.run("slate-network show", "eth1  static 10.0.3.21/24 gateway 10.0.3.2 dns 10.0.3.3", 10)?;
        con.run("slate-approve 'network=eth1 dhcp' && echo approved$((1+1))", "approved2", 20)?;
        con.run(&until("eth1 up dhcp 10.0.3.50/24 via 10.0.3.2", "broker"), "broker2", 40)?;
        con.run("grep -c 'address = 10.0.3' /etc/slate/network", "0", 10)?;
        con.poweroff()
    })();
    repos.stop();
    dns.stop();
    sntp.stop();
    if let Err(e) = result {
        con.kill();
        return Err(format!("netd scenario: {e}"));
    }
    println!(
        "xtask: netd scenario passed (two cards: DHCP, SLAAC, fixed IPv4 and IPv6 addresses, IPv4 and IPv6 DNS, ping, ip and ss, the clock set over NTP, slate-network and the broker's network action, HTTP through each, a link down and up; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// KVM unless `SLATE_NO_KVM` is set (to test under TCG, as CI without
/// nested virtualization would).
fn kvm_available() -> bool {
    std::env::var_os("SLATE_NO_KVM").is_none()
        && std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok()
}

/// Boot interactively: a QEMU window shows the screen and takes keyboard
/// input, and the serial console is on this terminal. `exit` in the shell
/// powers off; Ctrl-A X in the terminal quits QEMU.
/// With `debug`, QEMU waits for GDB on localhost:1234 before running.
pub fn run(o: &Opts, debug: bool) -> Result {
    // Under GDB the kernel stays at its link address, where the symbols
    // say it is (KASLR, ADR 0095).
    let cmdline = o.cmdline.as_deref().unwrap_or("");
    let cmdline = if debug { format!("{cmdline} nokaslr") } else { cmdline.to_string() };
    let img = image::build(o, cmdline.trim(), "slate.img", image::Root::Disk)?;
    let mut c = base_command(o, &img)?;
    screen_size(&mut c)?;
    // The console is on both the QEMU window (screen and PS/2 keyboard) and
    // this terminal (serial). --headless skips the window.
    if o.headless {
        c.args(["-display", "none"]);
    }
    c.args(["-serial", "mon:stdio"]);
    if debug {
        c.args(["-s", "-S"]);
        eprintln!("xtask: QEMU is waiting for GDB: target remote :1234");
    }
    match c.status() {
        Ok(s) if s.code() == Some(EXIT_SUCCESS) || s.success() => Ok(()),
        Ok(s) => Err(format!("QEMU exited with {s}")),
        Err(e) => Err(format!("failed to start QEMU: {e}")),
    }
}

/// The installer for a person to try (`cargo xtask try-install`): the USB
/// install media and a 32 GiB virtual SATA disk, kept between runs, in a
/// QEMU window with a USB keyboard and an absolute pointer (virtio tablet:
/// no mouse grab). The serial console is in this terminal. QEMU exits when
/// the installed system restarts; `--disk` then boots it from the disk.
/// ssh to it on localhost port 2222.
pub fn try_install(o: &Opts) -> Result {
    let disk = target_dir().join("try-install-disk.img");
    if o.new_disk || !disk.exists() {
        let _ = std::fs::remove_file(&disk);
        std::fs::File::create(&disk).and_then(|f| f.set_len(32 << 30)).map_err(|e| e.to_string())?;
    }
    let mut c = machine(o)?;
    screen_size(&mut c)?;
    c.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0", "-device", "virtio-tablet-pci"]);
    // A host USB device handed to the guest, `VENDOR:PRODUCT` in hex (a
    // Bluetooth controller, ADR 0176): the host loses it meanwhile, and
    // QEMU needs read and write on its /dev/bus/usb node.
    if let Ok(id) = std::env::var("SLATE_USB_HOST")
        && let Some((v, p)) = id.split_once(':')
    {
        c.args(["-device", &format!("usb-host,bus=xhci.0,vendorid=0x{v},productid=0x{p}")]);
    }
    if !o.disk_only {
        let stick = crate::iso::usb(o, false)?;
        // A copy: the image is rebuilt by other commands.
        let copy = target_dir().join("try-install-stick.img");
        std::fs::copy(&stick, &copy).map_err(|e| e.to_string())?;
        c.arg("-drive").arg(format!("file={},format=raw,if=none,id=stick,readonly=on", copy.display()));
        c.args(["-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=0"]);
    }
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=sata", disk.display()));
    c.args(["-device", "ide-hd,drive=sata,bus=ide.0,bootindex=1"]);
    c.args([
        "-netdev",
        "user,id=n0,hostfwd=tcp:127.0.0.1:2222-:22",
        "-device",
        "pcie-root-port,id=rp0,chassis=1,slot=1",
    ]);
    c.args(["-device", "igb,netdev=n0,bus=rp0", "-serial", "mon:stdio"]);
    if o.headless {
        c.args(["-display", "none"]);
    }
    if o.disk_only {
        eprintln!("xtask: booting {} (ssh -p 2222 USER@localhost)", disk.display());
    } else {
        eprintln!(
            "xtask: the installer in a QEMU window, installing to {}; when it restarts QEMU exits: \
             then `cargo xtask try-install --disk`",
            disk.display()
        );
    }
    match c.status() {
        Ok(s) if s.code() == Some(EXIT_SUCCESS) || s.success() => Ok(()),
        Ok(s) => Err(format!("QEMU exited with {s}")),
        Err(e) => Err(format!("failed to start QEMU: {e}")),
    }
}

/// Outcome of parsing the kernel's test output.
#[derive(Debug, Default, PartialEq, Eq)]
struct Report {
    passed: Vec<String>,
    failed: Vec<String>,
    done: bool,
}

impl Report {
    fn line(&mut self, line: &str) {
        let Some(rest) = line.trim_end().strip_prefix("SLATE-TEST: ") else { return };
        if let Some(name) = rest.strip_prefix("PASS ") {
            self.passed.push(name.to_string());
        } else if let Some(name) = rest.strip_prefix("FAIL ") {
            self.failed.push(name.to_string());
        } else if rest.starts_with("DONE") {
            self.done = true;
        }
    }
}

/// Deliberate kernel crashes and shutdowns (`ktest.crash=<name>`), the text
/// their output must contain, and the QEMU exit status they must produce
/// (the panic path's debug-exit code, or 0 when the machine turns off or
/// resets under `-no-reboot`).
const CRASH_CASES: &[(&str, &[&str], i32)] = &[
    (
        "page_fault",
        &["KERNEL PANIC: page fault (#PF) in kernel mode", "read of 0x7fff00000040 (page not present)"],
        EXIT_FAILURE,
    ),
    ("double_fault", &["KERNEL PANIC: double fault (#DF) in kernel mode"], EXIT_FAILURE),
    ("stack_overflow", &["KERNEL PANIC: double fault (#DF) in kernel mode"], EXIT_FAILURE),
    ("power_off", &[], 0),
    ("reboot", &[], 0),
    ("cfi", &["KERNEL PANIC: control-flow integrity check failed", "(KCFI)"], EXIT_FAILURE),
];

/// Lines the normal test run must print (output of user programs that the
/// kernel cannot check itself).
const REQUIRED_OUTPUT: &[&str] = &["Hello from musl on Slate!", "nvme0: shut down"];

/// The interactive shell session check: commands typed on the serial
/// console, and text their output must contain.
const SESSION: &[(&str, &str)] = &[
    ("echo hello-$((6*7))", "hello-42"),
    ("uname -sm", "Slate x86_64"),
    ("echo abc | tr a-z A-Z", "ABC"),
    // Many foreground pipelines. A job's child that ran before its parent
    // stopped the job (SIGTTOU from its tcsetpgrp, ADR 0039); the parent
    // nearly always runs first, so this guards rather than reproduces.
    ("n=0; for i in $(seq 300); do echo a | tr a b > /dev/null; n=$((n+1)); done; echo pipes-$n", "pipes-300"),
    // The base system: Slate's programs and nothing else.
    ("[ -e /bin/busybox ] || [ -e /test ] || [ -e /alpine ] || echo only-sla''te", "only-slate"),
    ("cd /tmp && echo saved > f && cat f && pwd", "/tmp"),
    ("cat /proc/self/comm", "cat"),
    ("sleep 0.2 && echo slept", "slept"),
    // The session boots from the SlateFS root partition (system-1, with
    // home and var as their own subvolumes); this file is checked on the
    // host after power-off.
    ("grep -c ' / slatefs' /proc/mounts", "1"),
    ("grep -c ' /home slatefs' /proc/mounts", "1"),
    ("slate-update status | tail -1", "default=system-1 fallback=- tries=0 pending=0"),
    ("echo persisted > /root/session.txt && cat /root/session.txt", "persisted"),
    // slinit is pid 1, in runlevel 3, with getty and login before us.
    ("runlevel", "N 3"),
    ("cat /proc/1/comm", "init"),
    ("id -un", "root"),
    // stty on the console, ps's columns and top's batch mode (M21).
    (
        "stty -icanon && stty | grep -q -- -icanon && stty icanon && ! stty | grep -q -- -icanon && echo stty-o''k",
        "stty-ok",
    ),
    ("set -- $(stty size); [ $# -eq 2 ] && echo size-o''k", "size-ok"),
    // Input and output speeds apart, and -g's 32 control characters
    // (ADR 0146).
    (
        "stty ispeed 9600; a=$(stty | head -1 | cut -d';' -f1,2); stty ispeed 115200; echo \"$a/$(stty speed)\"",
        "ispeed 9600 baud; ospeed 115200 baud/115200",
    ),
    ("stty -g | tr : '\\n' | wc -l | sed s/^/fiel''ds-/", "fields-36"),
    // sudo on a terminal runs the command on a pty of its own, the
    // window's size passed on (ADR 0142).
    ("sudo tty | sed 's|^/dev/pts/[0-9]*$|sudo-p''ty|'", "sudo-pty"),
    ("[ \"$(sudo stty size)\" = \"$(stty size)\" ] && echo sudo-si''ze", "sudo-size"),
    // What the pty shows is recorded when the policy asks, and played
    // back (ADR 0159).
    (
        "cp /etc/slate/broker.conf /tmp/bc; echo 'defaults log_output' >> /etc/slate/broker.conf; \
         sudo printf 'io-%s\\n' logged; cp /tmp/bc /etc/slate/broker.conf; \
         sudoreplay -m 0 $(sudoreplay -l | tail -1 | sed 's/.*TSID=\\([0-9A-Z]*\\) .*/\\1/') | tr -d '\\r' | sed 's/^/replay-/'",
        "replay-io-logged",
    ),
    // A terminal's times are when it was last read and written (ADR
    // 0143): this console was just read, so w shows it active.
    ("[ $(( $(date +%s) - $(stat -c %X /dev/console) )) -lt 20 ] && echo tty-ti''me", "tty-time"),
    ("w -h | awk '$1 == \"root\" {print \"idle-\" $5; exit}'", "idle-."),
    ("ps -o pid,comm -p 1 | tail -1 | awk '{print \"pid1-\" $2}'", "pid1-init"),
    ("ps aux | head -1 | awk '{print $3 $4}'", "%CPU%MEM"),
    ("top -b -n 1 -d 0.1 | grep -c '^Tasks:' | sed 's/^/top-/'", "top-1"),
    // Login records (M21 phase 2, ADR 0057): this session is in utmp,
    // wtmp and lastlog.
    ("who | awk '$1 == \"root\" {n++} END {print \"who-root-\" n}'", "who-root-1"),
    ("last -n 1 | head -1 | awk '{print \"last-\" $1 \"-\" $NF}'", "last-root-in"),
    ("last -x | grep -c 'system boot' | awk '{print ($1 >= 1) ? \"boot-seen\" : \"no-boot\"}'", "boot-seen"),
    ("lastlog -u root | tail -1 | awk '{print \"lastlog-\" $1}'", "lastlog-root"),
    // A service started through slinit's control socket.
    (
        "printf '#!/bin/sh\\n### BEGIN INIT INFO\\n# Provides: demo\\n# Default-Start: 3\\n### END INIT INFO\\necho demo-$1\\n' > /etc/init.d/demo && chmod 755 /etc/init.d/demo && service demo start",
        "demo-start",
    ),
    ("service demo status", "demo-status"),
    // Services and logs (M21 phase 4, ADR 0060): a user added, the
    // system log written and read, a service's log, and a daemon whose
    // escaped child stops with it.
    ("useradd -m sessuser && id -un sessuser | sed s/^/added-/", "added-sessuser"),
    ("service logd status | awk '{print \"logd-\" $3}'", "logd-running"),
    (
        "logger -t sess hello-from-logger; sleep 0.3; logread | grep -c 'sess: hello-from-l[o]gger' | sed s/^/logged-/",
        "logged-1",
    ),
    ("logread -k -n 1 | grep -c ' kernel: ' | sed s/^/klog-/", "klog-1"),
    ("service demo log -n 1 | awk '{print \"log-\" $2}'", "log-demo-status"),
    (
        "printf '#!/bin/sh\\necho spawned\\nsetsid sleep 1000 &\\nexec sleep 1000\\n' > /root/spawner.sh && printf '#!/bin/sh\\n### BEGIN INIT INFO\\n# Provides: spawner\\n# Default-Start: 3\\n# X-Slate-Exec: /bin/sh /root/spawner.sh\\n### END INIT INFO\\n' > /etc/init.d/spawner && chmod 755 /etc/init.d/spawner && service spawner start && sleep 0.5 && grep -l 'Service:.spawner' /proc/[0-9]*/status | wc -l | awk '{print ($1 >= 2) ? \"tagged-\" \"ok\" : \"tagged-\" $1}'",
        "tagged-ok",
    ),
    ("service spawner status | sed 's/(pids [0-9 ]*)/(some pids)/'", "spawner is running (some pids)"),
    ("service spawner log | awk '{print \"out-\" $2}'", "out-spawned"),
    (
        "service spawner stop; grep -l 'Service:.spawner' /proc/[0-9]*/status 2>/dev/null | wc -l | sed s/^/left-/",
        "left-0",
    ),
    ("ls -l /var/log/services/spawner.log | cut -c1-10", "-rw-------"),
    // A scheduled shutdown, announced, then cancelled; under five minutes
    // left, only root may log in.
    ("shutdown -r +10 maintenance > /dev/null && shutdown --show | awk '{print \"sched-\" $1}'", "sched-reboot"),
    ("test -e /run/nologin || echo nologin-n''ot-yet", "nologin-not-yet"),
    ("shutdown -c && shutdown --show", "no shutdown is scheduled"),
    ("shutdown -h +4 > /dev/null && test -e /run/nologin && echo nologin-s''et", "nologin-set"),
    ("shutdown -c && test ! -e /run/nologin && echo nologin-g''one", "nologin-gone"),
    ("shutdown -c 2>&1", "no shutdown is scheduled"),
    ("userdel -r sessuser && echo remo''ved", "removed"),
    // sshd_config (ADR 0061): checked, and the settings in effect.
    ("sshd -t && echo config-o''k", "config-ok"),
    (
        "sshd -T | grep -E '^(permitrootlogin|subsystem|kexalgorithms) ' | cut -d' ' -f1-2 | tr '\\n' ' '",
        "permitrootlogin without-password kexalgorithms mlkem768x25519-sha256,curve25519-sha256,curve25519-sha256@libssh.org subsystem sftp ",
    ),
];

/// Remove ANSI escape sequences (BusyBox asks for the cursor position and
/// colors `ls` output).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// Boot normally into BusyBox (pid 1 runs /init, which execs `sh`), type
/// commands on the serial console like a user, interrupt a running command
/// with Ctrl-C, and `exit` (which powers the machine off).
fn shell_session(o: &Opts) -> Result {
    use std::io::{Read, Write};
    let img = image::build(o, "", "slate-session.img", image::Root::Disk)?;
    let monitor_path = target_dir().join("session-monitor.sock");
    let _ = std::fs::remove_file(&monitor_path);
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", monitor_path.display()));
    c.stdout(Stdio::piped()).stdin(Stdio::piped());
    let mut child = c.spawn().map_err(|e| format!("failed to start QEMU: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut log = String::new();
    let wait_for = |needle: &str, from: usize, secs: u64, log: &mut String| -> Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let clean = strip_ansi(log);
            if let Some(i) = clean[from.min(clean.len())..].find(needle) {
                return Ok(from + i + needle.len());
            }
            if Instant::now() > deadline {
                return Err(format!("shell session: timed out waiting for {needle:?}; output so far:\n{clean}"));
            }
            if let Ok(b) = rx.recv_timeout(Duration::from_millis(50)) {
                log.push_str(&String::from_utf8_lossy(&b));
            }
        }
    };
    let prompt = "root@slate:";
    let started = Instant::now();
    let result = (|| -> Result {
        // getty asks for a name; root has no password on the dev image.
        let mut pos = wait_for("login: ", 0, 60, &mut log)?;
        stdin.write_all(b"root\r").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        pos = wait_for(prompt, pos, 10, &mut log)?;
        pos = wait_for("# ", pos, 5, &mut log)?;
        for (cmd, want) in SESSION {
            stdin.write_all(format!("{cmd}\r").as_bytes()).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())?;
            let after_echo = wait_for(cmd, pos, 10, &mut log)?;
            let after_out = wait_for(want, after_echo, 10, &mut log)?;
            pos = wait_for(prompt, after_out, 10, &mut log)?;
            pos = wait_for("# ", pos, 5, &mut log)?;
        }
        // Ctrl-C reaches the foreground job, and the shell comes back.
        stdin.write_all(b"sleep 30\r").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        let p = wait_for("sleep 30", pos, 10, &mut log)?;
        std::thread::sleep(Duration::from_millis(500));
        stdin.write_all(b"\x03").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        let p = wait_for("^C", p, 5, &mut log)?;
        let p = wait_for(prompt, p, 5, &mut log)?;
        let p = wait_for("# ", p, 5, &mut log)?;
        // Job control: Ctrl-Z stops the job, fg resumes it, Ctrl-C ends it.
        let mut send = |bytes: &[u8]| -> Result {
            stdin.write_all(bytes).map_err(|e| e.to_string())?;
            stdin.flush().map_err(|e| e.to_string())
        };
        send(b"sleep 30\r")?;
        let p = wait_for("sleep 30", p, 10, &mut log)?;
        std::thread::sleep(Duration::from_millis(500));
        send(b"\x1a")?;
        let p = wait_for("Stopped", p, 5, &mut log)?;
        let p = wait_for("# ", p, 5, &mut log)?;
        send(b"fg\r")?;
        let p = wait_for("sleep 30", p, 5, &mut log)?;
        std::thread::sleep(Duration::from_millis(500));
        send(b"\x03")?;
        let p = wait_for("^C", p, 5, &mut log)?;
        let p = wait_for(prompt, p, 5, &mut log)?;
        wait_for("# ", p, 5, &mut log)?;
        // Type on the emulated PS/2 keyboard (QEMU monitor `sendkey`).
        let mut monitor = std::os::unix::net::UnixStream::connect(&monitor_path).map_err(|e| e.to_string())?;
        let keys = ["e", "c", "h", "o", "spc", "k", "b", "d", "minus", "shift-o", "shift-k", "ret"];
        for k in keys {
            monitor.write_all(format!("sendkey {k}\n").as_bytes()).map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(30));
        }
        let p = wait_for("kbd-OK", p, 10, &mut log)?;
        wait_for("# ", p, 5, &mut log)?;
        // The screen shows text: a screenshot has plenty of non-background pixels.
        let shot = target_dir().join("session-screen.ppm");
        let _ = std::fs::remove_file(&shot);
        monitor.write_all(format!("screendump {}\n", shot.display()).as_bytes()).map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::metadata(&shot).map_or(true, |m| m.len() < 1000) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        std::thread::sleep(Duration::from_millis(200));
        check_screenshot(&shot)?;
        // Logging out brings getty back; then power off through slinit.
        stdin.write_all(b"exit\r").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        let p = wait_for("login: ", p, 10, &mut log)?;
        stdin.write_all(b"root\r").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        let p = wait_for(prompt, p, 10, &mut log)?;
        wait_for("# ", p, 5, &mut log)?;
        stdin.write_all(b"poweroff\r").map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err(format!(
                "shell session: QEMU did not power off after `poweroff`; output:\n{}",
                strip_ansi(&log)
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if status.code() != Some(0) {
        return Err(format!("shell session: QEMU exited with {status} after `poweroff`"));
    }
    crate::slatefsimg::check_root(&img, image::ROOT_OFFSET, "/root/session.txt", b"persisted\n")?;
    println!(
        "xtask: shell session passed ({} commands, Ctrl-C, Ctrl-Z/fg, PS/2 keyboard, screen, login, logout, poweroff, SlateFS root checked; {:.2}s)",
        SESSION.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Atomic updates with rollback across reboots (ADR 0027), on a SlateFS
/// root: a good update boots and is confirmed; the boot menu's previous
/// system boots on request; a broken update fails its trial boot and the
/// next boot rolls back. /home keeps its data throughout.
fn update_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    // Developer mode (ADR 0090): the scenario changes updates by hand, as
    // root, which the system image otherwise refuses.
    let img = image::build(o, "slate.devmode", "slate-update.img", image::Root::Disk)?;
    let boot = || -> Result<Console> {
        let mut c = base_command(o, &img)?;
        c.args(["-display", "none", "-monitor", "none", "-serial", "stdio"]);
        Console::start(c)
    };
    let fail = |c: &mut Console, e: String| -> String {
        c.kill();
        let _ = std::fs::write(target_dir().join("update-scenario.log"), strip_ansi(&c.log));
        format!("update scenario: {e} (log in target/update-scenario.log)")
    };
    // 1: write data, update to system-2, reboot.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("echo v1 > /etc/slate-version && echo keep > /home/data && cat /home/data", "keep", 10)?;
        // While the update is open, the running system changes /etc (an
        // account, a file) and the update adds an account of its own: the
        // commit merges them (ADR 0087).
        c.run(
            "slate-update begin && echo v2 > /run/update/etc/slate-version \
             && echo 'svc:x:900:900::/var/empty:/bin/false' >> /run/update/etc/passwd \
             && echo 'ada:x:1100:1100::/home/ada:/bin/sh' >> /etc/passwd && echo hello > /etc/motd-test \
             && echo merging",
            "merging",
            60,
        )?;
        // Its kernel goes to the boot partition, and the menu with it (ADR
        // 0086).
        // The loader's count of the trial goes with it (ADR 0089).
        c.run("slate-update commit", "wrote boot/slate/system-2/kernel, boot/slate/tries; switched the boot menu", 60)?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 2: system-2 on trial boots and is confirmed.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.wait_for("trying system-2", 60)?;
        c.login()?;
        // Limine loaded system-2's own kernel.
        c.run("grep '^kernel:' /proc/slate_boot", "/boot/slate/system-2/kernel", 10)?;
        // Both sides' /etc changes are here, and the data; slinit's `once`
        // entry confirmed the boot.
        c.run(
            "echo etc-$(grep -c '^ada:' /etc/passwd)$(grep -c '^svc:' /etc/passwd)-$(cat /etc/motd-test)",
            "etc-11-hello",
            10,
        )?;
        c.run("cat /etc/slate-version /home/data | tr '\\n' ,", "v2,keep,", 10)?;
        c.run("sleep 1; slate-update status | tail -1", "default=system-2 fallback=system-1 tries=0 pending=0", 10)?;
        // A rollback by hand carries this system's /etc changes back.
        c.run(
            "sleep 1; echo 'bob:x:1101:1101::/home/bob:/bin/sh' >> /etc/passwd && echo changed > /etc/motd-test \
             && slate-update rollback",
            "system-1 boots next time",
            60,
        )?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 2b: system-1 has system-2's /etc changes, and its own version; back
    // to system-2 for the rest.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        // The update's own account did not come back with them.
        c.run(
            "echo back-$(cat /etc/slate-version)-$(grep -c '^bob:' /etc/passwd)$(grep -c '^ada:' /etc/passwd)\
             $(grep -c '^svc:' /etc/passwd)-$(cat /etc/motd-test)",
            "back-v1-110-changed",
            10,
        )?;
        c.run("slate-update rollback", "system-2 boots next time", 60)?;
        c.run("slate-update status | tail -1", "default=system-2 fallback=system-1 tries=0 pending=0", 10)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 3: the boot menu's "previous system" entry.
    image::edit_cmdline(&img, |cmd| format!("{cmd} slate.boot=fallback"))?;
    let mut c = boot()?;
    let r = (|| -> Result {
        c.wait_for("booting the previous system system-1 (requested)", 60)?;
        c.login()?;
        c.run("cat /etc/slate-version /home/data | tr '\\n' ,", "v1,keep,", 10)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    image::edit_cmdline(&img, |cmd| cmd.replace(" slate.boot=fallback", ""))?;
    // 4: back on system-2; a broken update (no /init) as system-3.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("cat /etc/slate-version", "v2", 10)?;
        // A broken update whose kernel changed too (one byte more: a
        // different file that still boots).
        c.run(
            "slate-update begin && rm /run/update/init && printf x >> /run/update/boot/slate/kernel && slate-update commit",
            "wrote boot/slate/system-3/kernel, boot/slate/tries; switched the boot menu",
            60,
        )?;
        c.send("reboot\r")?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // Every system version is on the menu (ADR 0089): the new default,
    // the fallback, and system-1 as an older system.
    let kernels = image::menu_kernels(&img)?;
    let want = ["boot/slate/system-3/kernel", "boot/slate/system-2/kernel", "boot/slate/system-1/kernel"];
    if kernels != want {
        return Err(format!("update scenario: the boot menu lists {kernels:?}, not {want:?}"));
    }
    // 5: system-3's trial boot fails and the kernel reboots.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.wait_for("kernel /boot/slate/system-3/kernel", 60)?;
        c.wait_for("trying system-3 (0 more tries", 60)?;
        c.wait_for("failed before it was confirmed; rebooting", 60)?;
        c.wait_exit(30).map(|_| ())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 6: the next boot rolls back to system-2, data intact: slate-loader
    // counted the trial's boot (ADR 0089) and starts system-2's kernel,
    // asking for the rollback.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.wait_for("the new system did not start; starting the previous one", 60)?;
        c.wait_for("system-3 did not boot; rolling back to system-2", 60)?;
        // boot-ok put system-2 first on the menu (a sync after it, which
        // waits for its lock, finds nothing to do).
        c.login()?;
        c.run("slate-update sync-boot", "is up to date", 60)?;
        c.run("cat /etc/slate-version /home/data | tr '\\n' ,", "v2,keep,", 10)?;
        c.run("slate-update status | tail -1", "default=system-2", 10)?;
        c.run("grep '^kernel:' /proc/slate_boot", "/boot/slate/system-2/kernel", 10)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    // 7: the rollback brought back system-2's kernel as well.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("grep '^kernel:' /proc/slate_boot", "/boot/slate/system-2/kernel", 10)?;
        c.run("cat /etc/slate-version", "v2", 10)?;
        // Out of developer mode, the image and the root's disk refuse root
        // (ADR 0090); slate-update still keeps the boot partition, through
        // the system grant.
        c.run("echo 0 > /proc/sys/slate/devmode; cat /proc/sys/slate/devmode", "0", 10)?;
        c.run(
            "echo img-$(touch /usr/slate-was-here 2>/dev/null && echo yes || echo no)-disk-$(sh -c ': >> /dev/vda' \
             2>/dev/null && echo yes || echo no)-ctl-$(slatefs ctl / snapshot system-2 planted >/dev/null 2>&1 \
             && echo yes || echo no)",
            "img-no-disk-no-ctl-no",
            10,
        )?;
        c.run("slate-update sync-boot", "is up to date", 60)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    image::fsck_esp(&img)?;
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "SlateFS root after the update scenario")?;
    println!(
        "xtask: update scenario passed (update with its kernel, confirmed boot, boot-menu fallback, broken update and \
         its kernel rolled back; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Heavy writes in the background, on the ext4 disk and the SlateFS root:
/// files created, copied, renamed and removed, one left open after its
/// name is gone (an orphan), a sync now and then.
const CHURN: &str = "(i=0; exec 3>/mnt/e/held; rm /mnt/e/held; while :; do i=$((i+1)); d=/mnt/e/d$((i%7)); \
     mkdir -p $d; head -c $(( (i%9+1)*20000 )) /dev/urandom > $d/f$i; cp $d/f$i /home/copy$((i%13)); \
     mv $d/f$i /mnt/e/m$((i%31)); rm -f /mnt/e/d$(((i+3)%7))/f$((i-40)); \
     [ $((i%25)) = 0 ] && sync; echo $i > /mnt/e/progress; done) >/dev/null 2>&1 &";

/// The power goes during heavy writes (M19): e2fsck recovers the ext4
/// disk's journal to a clean file system, the SlateFS root checks clean, and
/// the next boot replays the journal itself, leaving it clean too.
fn power_cut_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-powercut.img", image::Root::Disk)?;
    let ext4 = target_dir().join("powercut-ext4.img");
    let src = target_dir().join("powercut-ext4-src");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&ext4);
    crate::ext4img::mkfs(&ext4, "64M", "powercut", &src)?;
    let boot = || -> Result<Console> {
        let mut c = base_command(o, &img)?;
        add_disk(&mut c, 1, &ext4);
        c.args(["-display", "none", "-monitor", "none", "-serial", "stdio"]);
        Console::start(c)
    };
    let fail = |c: &mut Console, e: String| -> String {
        c.kill();
        let _ = std::fs::write(target_dir().join("powercut-scenario.log"), strip_ansi(&c.log));
        format!("power-cut scenario: {e} (log in target/powercut-scenario.log)")
    };
    // 1: churn on both file systems, then pull the plug.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("mkdir -p /mnt/e && mount -t ext4 -o discard /dev/vdb /mnt/e && echo mounted-o''k", "mounted-ok", 20)?;
        c.run(CHURN, "", 10)?;
        c.run("sleep 8; echo churned-$(cat /mnt/e/progress)-fi''les", "-files", 30)?;
        c.kill();
        Ok(())
    })();
    r.map_err(|e| fail(&mut c, e))?;
    crate::ext4img::recover_and_check(&ext4, "ext4 after the power cut")?;
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "the SlateFS root after the power cut")?;
    // 2: Slate replays the journal itself.
    let mut c = boot()?;
    let r = (|| -> Result {
        c.login()?;
        c.run("mkdir -p /mnt/e && mount -t ext4 /dev/vdb /mnt/e && echo mounted-o''k", "mounted-ok", 20)?;
        c.run("echo replays-$(dmesg | grep -c 'journal replayed after an unclean shutdown')", "replays-1", 10)?;
        c.run("cat /mnt/e/m* /home/copy* > /dev/null && echo read-o''k", "read-ok", 30)?;
        c.run("umount /mnt/e && echo unmounted-o''k", "unmounted-ok", 20)?;
        c.poweroff()
    })();
    r.map_err(|e| fail(&mut c, e))?;
    crate::ext4img::check(&ext4, "ext4 after Slate's own recovery")?;
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "the SlateFS root after the second boot")?;
    println!(
        "xtask: power-cut scenario passed (heavy writes cut off: ext4's journal recovered by e2fsck and by Slate, \
         SlateFS clean; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Check a PPM screenshot of the console: the most common color is the
/// background, and at least 1% of the pixels differ from it (text).
pub fn check_screenshot(path: &Path) -> Result {
    let data = std::fs::read(path).map_err(|e| format!("screenshot: {e}"))?;
    let mut fields = Vec::new();
    let mut i = 0;
    while fields.len() < 4 {
        while data.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let start = i;
        while data.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
            i += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..i]).into_owned());
    }
    let pixels = &data[i + 1..];
    if fields[0] != "P6" || pixels.len() < 3 {
        return Err("screenshot: not a P6 PPM".into());
    }
    let mut counts = std::collections::HashMap::new();
    for p in pixels.as_chunks::<3>().0 {
        *counts.entry(*p).or_insert(0usize) += 1;
    }
    let total = pixels.len() / 3;
    let background = counts.values().max().copied().unwrap_or(0);
    if (total - background) * 100 < total {
        return Err(format!("screenshot: only {} of {total} pixels are text", total - background));
    }
    Ok(())
}

/// A screendump of head `head` of display device `device` (its QEMU id).
pub fn screendump_head(mon: &Path, name: &str, device: &str, head: u32) -> Result<PathBuf> {
    let shot = target_dir().join(name);
    let _ = std::fs::remove_file(&shot);
    monitor(mon, &[&format!("screendump {} {device} {head}", shot.display())])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::metadata(&shot).map_or(true, |m| m.len() < 1000) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(200));
    Ok(shot)
}

/// A screendump through the QEMU monitor at `mon`, waited for.
pub fn screendump(mon: &Path, name: &str) -> Result<PathBuf> {
    let shot = target_dir().join(name);
    let _ = std::fs::remove_file(&shot);
    monitor(mon, &[&format!("screendump {}", shot.display())])?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::fs::metadata(&shot).map_or(true, |m| m.len() < 1000) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(200));
    Ok(shot)
}

/// The colour of pixel (x, y) in a P6 PPM.
pub fn ppm_pixel(path: &Path, x: usize, y: usize) -> Result<[u8; 3]> {
    let data = std::fs::read(path).map_err(|e| format!("screenshot: {e}"))?;
    let mut fields = Vec::new();
    let mut i = 0;
    while fields.len() < 4 {
        while data.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        let start = i;
        while data.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
            i += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..i]).into_owned());
    }
    let width: usize = fields[1].parse().map_err(|_| "screenshot: bad width")?;
    let at = i + 1 + (y * width + x) * 3;
    data.get(at..at + 3).map(|p| [p[0], p[1], p[2]]).ok_or_else(|| "screenshot: pixel outside".into())
}

/// Ask the QEMU monitor at `mon` and return what it answered.
fn monitor_query(mon: &Path, cmd: &str) -> Result<String> {
    use std::io::Read;
    let mut s = std::os::unix::net::UnixStream::connect(mon).map_err(|e| format!("QEMU monitor: {e}"))?;
    s.set_read_timeout(Some(Duration::from_millis(200))).map_err(|e| e.to_string())?;
    s.write_all(format!("{cmd}\n").as_bytes()).map_err(|e| e.to_string())?;
    // The banner ends with a prompt, and so does the answer: wait for the
    // second one.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline && String::from_utf8_lossy(&out).matches("(qemu)").count() < 2 {
        if let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// The index `info mice` gives the mouse whose name contains `name`.
pub fn mouse_index(mon: &Path, name: &str) -> Result<String> {
    let info = monitor_query(mon, "info mice")?;
    info.lines()
        .find(|l| l.contains(name))
        .and_then(|l| l.split("Mouse #").nth(1))
        .and_then(|r| r.split(':').next())
        .map(|i| i.trim().to_string())
        .ok_or_else(|| format!("no mouse {name:?} in `info mice`:\n{info}"))
}

/// evdev (ADR 0033): a PS/2 keyboard and mouse, a virtio tablet and a USB
/// mouse appear as /dev/input/event*, and events QEMU injects reach each.
/// A machine like GNOME Boxes makes for systems it doesn't know (libvirt's
/// i440fx): plain PCI with no MCFG table, so configuration space is read
/// through I/O ports, and no HPET, so the clocks are calibrated against
/// the ACPI PM timer. The virtio disk and network card are found, and two
/// seconds of sleep take two seconds.
/// The machine GNOME Boxes and libvirt make for systems they don't know
/// (ADR 0039): i440fx without an HPET (PCI through the configuration
/// ports, the ACPI PM timer for calibration), the root disk on IDE and an
/// rtl8139 network card.
fn no_hpet_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-nohpet.img", image::Root::Disk)?;
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let mut c = machine_of(o, "pc,hpet=off")?;
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=disk0", img.display()));
    c.args(["-device", "ide-hd,drive=disk0,bus=ide.0,bootindex=0"]);
    c.args(["-netdev", "user,id=net0", "-device", "rtl8139,netdev=net0"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor", "none"]);
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run(
            "dmesg | grep -c 'through I/O ports'; dmesg | grep -o 'IDE .*/dev/sda.*'; \
             echo disks-$(ls /sys/block | grep -c sda)-$(grep -c ' / ' /proc/mounts)",
            "disks-1-1",
            10,
        )?;
        // Writes to the IDE disk (the root), checked by fsck on the host.
        con.run("seq 20000 > /root/ide-test && sync && echo w$(wc -l < /root/ide-test)", "w20000", 20)?;
        con.run(
            "for i in $(seq 50); do dmesg | grep -q 'is 10.0.2.15/24' && break; sleep 0.2; done; \
             dmesg | grep -o 'rtl8139 .*link up.*'; dmesg | grep -c 'eth0 is 10.0.2.15/24' | sed 's/^/net-/'",
            "net-1",
            20,
        )?;
        // Its interrupt, through the firmware's _PRT and link devices (ADR
        // 0079): no longer polled.
        con.run("dmesg | grep -c 'rtl8139 .*INTx on GSI' | sed 's/^/intx-/'", "intx-1", 10)?;
        // Enough traffic to go round the 8 KiB receive ring several times.
        con.run(&format!("echo 'main http://10.0.2.2:{}/v1' > /etc/quarry/repos", repos.port), "", 10)?;
        con.run(
            "n=0; for i in $(seq 20); do quarry update >/dev/null 2>&1 && n=$((n+1)); done; \
             echo fetched-$n-$(dmesg | grep -c 'bad receive header')",
            "fetched-20-0",
            90,
        )?;
        con.run("dmesg | grep -c 'HPET'; dmesg | grep -o 'TSC [0-9.]* MHz.*clock [a-z]*'", "clock tsc", 10)?;
        con.run(
            "a=$(cut -d' ' -f1 /proc/uptime); sleep 2; b=$(cut -d' ' -f1 /proc/uptime); \
             awk -v a=$a -v b=$b 'BEGIN { d = b - a; if (d > 1.8 && d < 2.5) print \"slept-\" \"ok\"; else print \"slept \" d }'",
            "slept-ok",
            15,
        )?;
        con.poweroff()
    })();
    repos.stop();
    let _ = std::fs::write(target_dir().join("nohpet-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("no-HPET scenario: {e} (transcript in target/nohpet-scenario.log)"));
    }
    crate::slatefsimg::fsck(&img, image::ROOT_OFFSET, "the IDE disk's root")?;
    println!(
        "xtask: no-HPET scenario passed (i440fx as GNOME Boxes makes it: PCI through I/O ports, PM-timer \
         calibration, the root on IDE (fsck clean), rtl8139 on INTx through _PRT, DHCP and HTTP, a 2 s sleep; \
         {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn input_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-gpu.img", image::Root::Disk)?;
    let mon = target_dir().join("input-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-device", "virtio-tablet-pci", "-device", "qemu-xhci,id=xhci", "-device", "usb-mouse,bus=xhci.0"]);
    // A USB tablet: report protocol, absolute axes (ADR 0039).
    c.args(["-device", "usb-tablet,bus=xhci.0"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run(
            "for i in $(seq 50); do [ \"$(/test/evdev | grep -c ': ok')\" -ge 5 ] && break; sleep 0.1; done; \
             /test/evdev; ev() { /test/evdev | grep \"$1\" | head -n 1 | cut -d: -f1 | tr -dc 0-9; }",
            "devices: 5",
            15,
        )?;
        for want in [
            "keyboard",
            "ImPS/2 Generic Wheel Mouse\" bus 0011 buttons rel",
            "Tablet",
            "USB Mouse",
            "USB Tablet\" bus 0003 buttons abs",
        ] {
            if !strip_ansi(&con.log).contains(want) {
                return Err(format!("no input device matching {want:?}"));
            }
        }
        // The keyboard: Ctrl (code 29) pressed and released.
        con.send("/test/evdev watch $(ev keyboard) 2\r")?;
        con.wait_for("watching", 10)?;
        monitor(&mon, &["sendkey ctrl"])?;
        con.wait_for("event 1 29 1", 5)?;
        con.wait_for("event 1 29 0", 5)?;
        con.wait_for("# ", 10)?;
        // Held, a key repeats (EV_REP, value 2) from the kernel's timer.
        con.send("/test/evdev watch $(ev keyboard) 3\r")?;
        con.wait_for("watching", 10)?;
        monitor(&mon, &["sendkey a 1000"])?;
        con.wait_for("event 1 30 2", 5)?;
        con.wait_for("event 1 30 0", 5)?;
        con.wait_for("# ", 10)?;
        // Caps Lock on the console lights the keyboard's Caps Lock (bit 1);
        // a program writes Num Lock (bit 0); the keyboard, past the Set
        // LEDs handshake, still types.
        monitor(&mon, &["sendkey caps_lock"])?;
        con.run("sleep 0.3; /test/evdev leds $(ev keyboard)", "leds 0x2 repeat 250 33", 10)?;
        con.run("/test/evdev setled $(ev keyboard) 0 1", "leds 0x3", 10)?;
        monitor(&mon, &["sendkey caps_lock"])?;
        con.run("sleep 0.3; /test/evdev setled $(ev keyboard) 0 0", "leds 0x0", 10)?;
        con.send("/test/evdev watch $(ev keyboard) 2\r")?;
        con.wait_for("watching", 10)?;
        monitor(&mon, &["sendkey ctrl"])?;
        con.wait_for("event 1 29 1", 5)?;
        con.wait_for("# ", 10)?;
        // Each mouse in turn: QEMU sends moves and clicks to the one picked.
        // Headless QEMU has no screen size to place absolute moves on, so
        // the tablet is checked by its buttons (its axis ranges were in the
        // listing; virtio-input passes every event the same way).
        // (QEMU's name for the mouse, the guest's device name, what to wait for)
        for (name, dev, want) in [
            ("PS/2 Mouse", "ImPS", "event 2 0 20"),
            ("Virtio Tablet", "Tablet", "watching"),
            ("HID Mouse", "USB Mouse", "event 2 0 "),
            ("HID Tablet", "USB Tablet", "watching"),
        ] {
            let i = mouse_index(&mon, name)?;
            monitor(&mon, &[&format!("mouse_set {i}")])?;
            con.send(&format!("/test/evdev watch $(ev '{dev}') 2\r"))?;
            con.wait_for("watching", 10)?;
            monitor(&mon, &["mouse_move 20 10", "mouse_button 1", "mouse_button 0"])?;
            if want != "watching" {
                con.wait_for(want, 5).map_err(|e| format!("{name}: {e}"))?;
            }
            con.wait_for("event 1 272 1", 5).map_err(|e| format!("{name}: {e}"))?;
            con.wait_for("# ", 10)?;
        }
        // Ctrl-Alt-Del reaches init (ADR 0060), which runs inittab's
        // ctrlaltdel entry: here a power-off, so the scenario ends.
        con.run(
            "sed -i 's|^ca::ctrlaltdel:.*|ca::ctrlaltdel:/bin/poweroff|' /etc/inittab && telinit q && echo cad-r''eady",
            "cad-ready",
            10,
        )?;
        monitor(&mon, &["sendkey ctrl-alt-delete"])?;
        con.wait_for("slinit: powering off", 15)?;
        match con.wait_exit(60)? {
            Some(0) => Ok(()),
            other => Err(format!("QEMU exited with {other:?} after Ctrl-Alt-Del")),
        }
    })();
    let _ = std::fs::write(target_dir().join("input-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("input scenario: {e} (transcript in target/input-scenario.log)"));
    }
    println!(
        "xtask: input scenario passed (PS/2 keyboard with repeat and lights, PS/2 mouse, virtio tablet, USB mouse, USB \
         tablet, Ctrl-Alt-Del; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Whether any pixel in the rectangle `(x0, y0)`-`(x1, y1)` of a P6 PPM
/// has colour `rgb`.
pub fn ppm_has(path: &Path, (x0, y0, x1, y1): (usize, usize, usize, usize), rgb: [u8; 3]) -> Result<bool> {
    for y in y0..y1 {
        for x in x0..x1 {
            if ppm_pixel(path, x, y)? == rgb {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Strata (ADR 0037) on the firmware framebuffer, started from a root
/// shell:
/// - super + enter opens the terminal, a Strata app running a shell;
/// - a copy of an app outside the system tree runs in the Linux domain,
///   and its window carries the "linux" tag;
/// - windows float (ADR 0038): super + up maximises and restores, a
///   mouse drag on the title bar moves a window, super + down minimises
///   it (with its fade), the panel's window list brings it back, alt + tab
///   raises the next;
/// - typing in the terminal runs commands; a Linux program in its
///   foreground turns the window's domain to linux, and back;
/// - workspaces switch, exit closes the terminal, super + q the other
///   window;
/// - the launcher opens a terminal, and its "Log out" leaves Strata;
/// - a wheel user's `slate-approve restart` brings up the approval
///   dialog: a wrong password is refused there, the right one restarts
///   the machine.
fn strata_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    // The test load has BusyBox: a Linux program to run in the terminal.
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-strata.img", image::Root::Disk)?;
    let mon = target_dir().join("strata-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let desktop = [0x12, 0x12, 0x11];
    let result = (|| -> Result {
        con.login()?;
        // The Linux-domain programs below need compatibility mode.
        con.run("slate-compat on", "", 10)?;
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(1000);
        // The empty desktop: graphite's wallpaper and its top bar.
        let empty = screendump(&mon, "strata-empty.ppm")?;
        let (bar, middle) = (ppm_pixel(&empty, 600, 16)?, ppm_pixel(&empty, 640, 300)?);
        if bar != desktop || middle != desktop {
            return Err(format!("no desktop on the screen (bar {bar:02x?}, middle {middle:02x?})"));
        }
        // Whether a point shows the wallpaper as on the empty desktop
        // (whatever the design draws there).
        let bare = |shot: &Path, x: usize, y: usize| -> Result<bool> {
            Ok(ppm_pixel(shot, x, y)? == ppm_pixel(&empty, x, y)?)
        };
        // super + enter: the terminal. Then a Linux-domain copy of an app:
        // one byte more, and its signature no longer holds (ADR 0090).
        monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
        con.wait_for("(slate)", 5)?;
        con.send("cp /bin/strata-keys /tmp/keys && printf x >> /tmp/keys && /tmp/keys &\r")?;
        con.wait_for("\"keys\" from pid", 15)?;
        con.wait_for("(linux)", 5)?;
        pause(800);
        // Floating windows (ADR 0038): centred and cascading; the keys
        // window on top at (220, 111), 768 x 538.
        let window = [0x1A, 0x1A, 0x19];
        let shot = screendump(&mon, "strata-windows.ppm")?;
        if ppm_pixel(&shot, 640, 400)? != window || !bare(&shot, 1100, 700)? {
            return Err("the windows are not where floating windows open".into());
        }
        // super + up maximises the focused window, and restores it.
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(500);
        if ppm_pixel(&screendump(&mon, "strata-maximised.ppm")?, 5, 760)? != window {
            return Err("super + up did not maximise the window".into());
        }
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(500);
        // Dragging its title bar with the mouse moves it by (200, 100); the
        // pointer starts in the middle of the screen.
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}"), "mouse_move -320 -274"])?;
        pause(300);
        monitor(&mon, &["mouse_button 1"])?;
        pause(200);
        monitor(&mon, &["mouse_move 100 50"])?;
        pause(200);
        monitor(&mon, &["mouse_move 100 50"])?;
        pause(200);
        monitor(&mon, &["mouse_button 0"])?;
        pause(500);
        if ppm_pixel(&screendump(&mon, "strata-dragged.ppm")?, 1100, 700)? != window {
            return Err("dragging the title bar did not move the window".into());
        }
        // super + down minimises it (after its fade-out); its button in the
        // panel's window list (the second, at x 432-608) brings it back.
        monitor(&mon, &["sendkey meta_l-down"])?;
        pause(600);
        if !bare(&screendump(&mon, "strata-minimised.ppm")?, 1100, 700)? {
            return Err("super + down did not minimise the window".into());
        }
        monitor(&mon, &["mouse_move 0 -210"])?;
        pause(200);
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        pause(600);
        if ppm_pixel(&screendump(&mon, "strata-restored.ppm")?, 1100, 700)? != window {
            return Err("the window list did not bring the window back".into());
        }
        // Its bottom-right corner (the frame is 768 x 538 at (420, 211);
        // the resize band reaches 6 px out) dragged 100 left and 80 up
        // makes it smaller. The pointer is at (520, 16); PS/2 moves go in
        // steps, as QEMU sends at most 255 a packet at the sampling rate.
        for step in ["mouse_move 200 200", "mouse_move 200 200", "mouse_move 200 200", "mouse_move 70 135"] {
            monitor(&mon, &[step])?;
            pause(150);
        }
        pause(300);
        monitor(&mon, &["mouse_button 1"])?;
        pause(200);
        monitor(&mon, &["mouse_move -50 -40"])?;
        pause(200);
        monitor(&mon, &["mouse_move -50 -40"])?;
        pause(200);
        monitor(&mon, &["mouse_button 0"])?;
        pause(500);
        let shot = screendump(&mon, "strata-resized.ppm")?;
        if ppm_pixel(&shot, 1150, 720)? == window || ppm_pixel(&shot, 1050, 640)? != window {
            return Err("dragging the corner did not resize the window".into());
        }
        // Its title bar (now 668 px wide at (420, 211)) dragged to the left
        // edge snaps it to the left half (ADR 0039); super + up takes it to
        // the top-left quarter, super + down back to the half, super + left
        // back to its own size (ADR 0102). The pointer is at about
        // (1090, 671).
        for step in ["mouse_move -200 -200", "mouse_move -190 -200", "mouse_move 0 -46"] {
            monitor(&mon, &[step])?;
            pause(150);
        }
        monitor(&mon, &["mouse_button 1"])?;
        pause(200);
        for _ in 0..4 {
            monitor(&mon, &["mouse_move -200 0"])?;
            pause(150);
        }
        monitor(&mon, &["mouse_button 0"])?;
        pause(500);
        let shot = screendump(&mon, "strata-snapped.ppm")?;
        if ppm_pixel(&shot, 5, 700)? != window || ppm_pixel(&shot, 635, 700)? != window {
            return Err("dragging the window to the left edge did not snap it to the left half".into());
        }
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(500);
        let shot = screendump(&mon, "strata-quarter.ppm")?;
        if ppm_pixel(&shot, 5, 100)? != window || !bare(&shot, 5, 700)? {
            return Err("super + up from the left half did not make the top-left quarter".into());
        }
        monitor(&mon, &["sendkey meta_l-down"])?;
        pause(500);
        let shot = screendump(&mon, "strata-half.ppm")?;
        if ppm_pixel(&shot, 5, 100)? != window || ppm_pixel(&shot, 5, 700)? != window {
            return Err("super + down from the top-left quarter did not go back to the left half".into());
        }
        monitor(&mon, &["sendkey meta_l-left"])?;
        pause(500);
        // The pointer stopped at the left edge (0, 225): back to (1090, 671)
        // for the steps below, which move it from there.
        for step in [
            "mouse_move 200 200",
            "mouse_move 200 200",
            "mouse_move 200 46",
            "mouse_move 200 0",
            "mouse_move 200 0",
            "mouse_move 90 0",
        ] {
            monitor(&mon, &[step])?;
            pause(150);
        }
        // The terminal, below: alt + tab brings it up. A command, then a
        // Linux program in its foreground.
        monitor(&mon, &["sendkey alt-tab"])?;
        pause(300);
        type_keys(&mon, "touch /tmp/from-terminal\n")?;
        pause(800);
        con.run("test -e /tmp/from-terminal && echo typed-$((3*3))", "typed-9", 10)?;
        type_keys(&mon, "/bin/busybox sleep 3\n")?;
        con.wait_for("shows \"busybox\" (linux)", 10)?;
        con.wait_for("shows \"terminal\" (slate)", 10)?;
        // etch, full screen: write a line, ^X, save under its name.
        type_keys(&mon, "etch /tmp/note\n")?;
        pause(1000);
        type_keys(&mon, "hi there\n")?;
        monitor(&mon, &["sendkey ctrl-x"])?;
        pause(500);
        type_keys(&mon, "y")?;
        pause(500);
        type_keys(&mon, "\n")?;
        pause(800);
        con.run("cat /tmp/note", "hi there", 10)?;
        pause(500);
        // Its prompt, in graphite's chalk.
        let shot = screendump(&mon, "strata-terminal.ppm")?;
        if !ppm_has(&shot, (200, 120, 600, 220), [0xE3, 0xE1, 0xDC])? {
            return Err("no chalk prompt in the terminal".into());
        }
        // Scrollback and the clipboards (ADR 0038). A script clears the
        // screen and the scrollback, then prints 60 commands; maximised,
        // the terminal has 33 rows, so the first 28 scroll off.
        con.run(
            "echo 'printf \"\\033[2J\\033[3J\\033[H\"; i=1; while [ $i -le 60 ]; do echo touch /tmp/sb$i; \
             i=$((i+1)); done' > /tmp/sb.sh && echo written",
            "written",
            10,
        )?;
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(400);
        type_keys(&mon, "sh /tmp/sb.sh\n")?;
        pause(1000);
        // Over row 0 (y 74-95; the pointer was left at (1090, 671) by the
        // resize), the wheel goes all the way back: row 0 shows "touch
        // /tmp/sb1", row 1 "touch /tmp/sb2".
        for step in [
            "mouse_move -200 -200",
            "mouse_move -200 -200",
            "mouse_move -200 -187",
            "mouse_move -200 0",
            "mouse_move -90 0",
        ] {
            monitor(&mon, &[step])?;
            pause(150);
        }
        pause(300);
        let wheel: Vec<&str> = std::iter::repeat_n("mouse_move 0 0 1", 12).collect();
        monitor(&mon, &wheel)?;
        pause(300);
        // A triple click selects row 0's line; ctrl + shift + c copies it.
        monitor(&mon, &["mouse_button 1", "mouse_button 0", "mouse_button 1", "mouse_button 0"])?;
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        pause(300);
        screendump(&mon, "strata-scrollback.ppm")?;
        monitor(&mon, &["sendkey ctrl-shift-c"])?;
        pause(200);
        // Row 1's line becomes the selection; the middle button pastes it.
        monitor(&mon, &["mouse_move 0 21"])?;
        pause(600);
        monitor(&mon, &["mouse_button 1", "mouse_button 0", "mouse_button 1", "mouse_button 0"])?;
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        pause(300);
        monitor(&mon, &["mouse_button 4", "mouse_button 0"])?;
        pause(300);
        type_keys(&mon, "\n")?;
        pause(600);
        con.run("test -e /tmp/sb2 && echo has-sb$((1+1))", "has-sb2", 10)?;
        // Another terminal pastes the clipboard: "touch /tmp/sb1".
        monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
        pause(1500);
        monitor(&mon, &["sendkey ctrl-shift-v"])?;
        pause(300);
        type_keys(&mon, "\n")?;
        pause(600);
        con.run("test -e /tmp/sb1 && test ! -e /tmp/sb3 && echo clip-$((2*2))", "clip-4", 10)?;
        type_keys(&mon, "exit\n")?;
        con.wait_for("disconnected", 10)?;
        pause(500);
        monitor(&mon, &["sendkey meta_l-up"])?;
        pause(300);
        // super + 2: an empty workspace; super + 1 back.
        monitor(&mon, &["sendkey meta_l-2"])?;
        pause(500);
        if !bare(&screendump(&mon, "strata-ws2.ppm")?, 300, 300)? {
            return Err("workspace 2 is not empty".into());
        }
        monitor(&mon, &["sendkey meta_l-1"])?;
        pause(300);
        // exit ends the shell, which closes the terminal; super + q the rest.
        type_keys(&mon, "exit\n")?;
        con.wait_for("disconnected", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(800);
        let shot = screendump(&mon, "strata-closed.ppm")?;
        if !bare(&shot, 640, 400)? || !bare(&shot, 1100, 700)? {
            return Err("the windows did not close".into());
        }
        // The launcher: "term" and Enter open a terminal.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(600);
        let shot = screendump(&mon, "strata-launcher.ppm")?;
        if ppm_pixel(&shot, 640, 175)? != [0x1C, 0x1C, 0x1B] {
            return Err("super + space did not open the launcher".into());
        }
        type_keys(&mon, "term\n")?;
        con.wait_for("\"terminal\" from pid", 15)?;
        // Its "Log out" leaves Strata.
        pause(500);
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(400);
        type_keys(&mon, "log\n")?;
        con.wait_for("strata: leaving", 10)?;
        con.run("echo back-$((1+1))", "back-2", 10)?;
        // System approval: a wheel user with a password asks to restart.
        con.run(
            "echo 'tester:x:1000:1000::/tmp:/bin/sh' >> /etc/passwd && echo 'tester:x:1000:' >> /etc/group && \
             sed -i 's/^wheel:x:10:root$/wheel:x:10:root,tester/' /etc/group && \
             printf 'slate-pw\\n' | passwd --stdin tester >/dev/null && echo made-$(grep -c '^wheel:.*tester' /etc/group)",
            "made-1",
            10,
        )?;
        // The lock screen (ADR 0039): root gets a password; super + L locks,
        // a wrong password is refused, the right one unlocks.
        con.run("printf 'root-pw\\n' | passwd --stdin root >/dev/null && echo rootpw$((1+1))", "rootpw2", 10)?;
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-l"])?;
        con.wait_for("strata: locked", 10)?;
        pause(400);
        // Inside the password field (`well`), under the clock (ADR 0124).
        if ppm_pixel(&screendump(&mon, "strata-locked.ppm")?, 300, 537)? != [0x16, 0x16, 0x15] {
            return Err("super + L showed no lock screen".into());
        }
        type_keys(&mon, "nope\n")?;
        con.wait_for("strata: the lock screen refused", 15)?;
        type_keys(&mon, "root-pw\n")?;
        con.wait_for("strata: unlocked", 15)?;
        // Locking by itself after a while without input (ADR 0102): three
        // seconds here; then never again for the rest of the run.
        con.run(
            "mkdir -p $HOME/.config/strata && echo lock=3 > $HOME/.config/strata/settings && echo idle-$((1+1))",
            "idle-2",
            10,
        )?;
        con.wait_for("strata: locked (idle)", 20)?;
        type_keys(&mon, "root-pw\n")?;
        con.wait_for("strata: unlocked", 15)?;
        // (Strata is told at once: before the prompt, or after.)
        con.run_seeing(
            "echo lock=0 > $HOME/.config/strata/settings && echo never-$((1+1))",
            "never-2",
            "lock: 0, wallpaper",
            10,
        )?;
        // "Switch person" on the lock screen: Tab to it, Enter, Enter again;
        // the session ends for the login screen (here, the shell).
        monitor(&mon, &["sendkey meta_l-l"])?;
        con.wait_for("strata: locked", 10)?;
        pause(400);
        monitor(&mon, &["sendkey tab", "sendkey ret"])?;
        pause(300);
        screendump(&mon, "strata-switch-person.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata: switching person", 10)?;
        con.wait_for("strata: leaving", 10)?;
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        pause(800);
        // The Applications menu (ADR 0110): the pointer to its button,
        // a click, "clo" and Enter open the Clock; a click outside an open
        // menu closes it. The pointer starts where the last strata left it,
        // so it goes to the top left corner first.
        monitor(&mon, &["mouse_move -300 -300"; 8])?;
        pause(200);
        monitor(&mon, &["mouse_move 40 14", "mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the applications menu", 10)?;
        pause(500);
        let shot = screendump(&mon, "strata-applications-menu.ppm")?;
        if ppm_pixel(&shot, 560, 480)? != [0x1C, 0x1C, 0x1B] {
            return Err("the Applications button opened no menu".into());
        }
        type_keys(&mon, "clo\n")?;
        con.wait_for("\"clock\" from pid", 15)?;
        pause(800);
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(500);
        // Settings (ADR 0110), from the launcher: Appearance's Light, then
        // the Dunes wallpaper (under Light is Contours, Dunes beside it),
        // which Strata takes up from the settings file.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        pause(400);
        type_keys(&mon, "settings\n")?;
        con.wait_for("\"settings\" from pid", 15)?;
        pause(800);
        monitor(&mon, &["sendkey right", "sendkey right", "sendkey spc"])?;
        con.wait_for("strata: settings changed: Settings { theme: Light", 10)?;
        pause(500);
        let p = ppm_pixel(&screendump(&mon, "strata-light.ppm")?, 600, 16)?;
        if p != [0xDC, 0xDB, 0xDB] {
            return Err(format!("the light variant is not on the screen (bar {p:02x?})"));
        }
        // The themes in colour (ADR 0167): Copper Noir, then Sediment, whose
        // top bar is dark ink; then back to Light.
        monitor(&mon, &["sendkey right", "sendkey spc"])?;
        con.wait_for("strata: settings changed: Settings { theme: CopperNoir", 10)?;
        monitor(&mon, &["sendkey right", "sendkey spc"])?;
        con.wait_for("strata: settings changed: Settings { theme: Sediment", 10)?;
        pause(500);
        let shot = screendump(&mon, "strata-sediment.ppm")?;
        let p = ppm_pixel(&shot, 600, 16)?;
        if p != [0x2B, 0x26, 0x22] {
            return Err(format!("Sediment is not on the screen (bar {p:02x?})"));
        }
        // Its own wallpaper came with it: the ink stratum, bluish, at the
        // bottom.
        let p = ppm_pixel(&shot, 40, 795)?;
        if p[2] < p[0] + 8 {
            return Err(format!("Sediment's wallpaper is not on the screen ({p:02x?})"));
        }
        monitor(&mon, &["sendkey left", "sendkey left", "sendkey spc"])?;
        con.wait_for("strata: settings changed: Settings { theme: Light", 10)?;
        pause(500);
        let p = ppm_pixel(&screendump(&mon, "strata-light-again.ppm")?, 600, 16)?;
        if p != [0xDC, 0xDB, 0xDB] {
            return Err(format!("the light variant did not come back (bar {p:02x?})"));
        }
        monitor(&mon, &["sendkey down", "sendkey right", "sendkey ret"])?;
        con.wait_for("wallpaper: Dunes, picture: false }", 10)?;
        pause(500);
        let p = ppm_pixel(&screendump(&mon, "strata-wallpaper.ppm")?, 40, 790)?;
        if p == [0xDC, 0xDB, 0xDB] {
            return Err("the Dunes wallpaper is not on the screen".into());
        }
        // Users: an account added (an administrator), through the broker.
        // Root needs no approval; the account's files say what was done.
        monitor(&mon, &["sendkey esc"])?;
        // Past Date and time, Network and Bluetooth.
        for _ in 0..5 {
            monitor(&mon, &["sendkey down"])?;
        }
        monitor(&mon, &["sendkey right", "sendkey down", "sendkey ret"])?;
        pause(300);
        type_keys(&mon, "Ada Lovelace")?;
        monitor(&mon, &["sendkey tab", "sendkey tab"])?;
        type_keys(&mon, "ada-pw\nada-pw")?;
        monitor(&mon, &["sendkey tab", "sendkey spc"])?;
        pause(300);
        screendump(&mon, "strata-settings-add-account.ppm")?;
        monitor(&mon, &["sendkey tab", "sendkey ret"])?;
        con.wait_for("strata-settings: account change: add ada admin Ada Lovelace", 20)?;
        con.run(
            "echo acct-$(grep -c '^ada:x:1001:1001:Ada Lovelace:/home/ada:' /etc/passwd)-$(grep -c '^wheel:.*ada' /etc/group)-$(grep -c '^ada:[$]' /etc/shadow)-$(test -d /home/ada && echo home)",
            "acct-1-1-1-home",
            10,
        )?;
        // The time zone: Date and time, its row, the list, "london". The
        // system's zone and TZ then decide what date says.
        monitor(&mon, &["sendkey esc", "sendkey up", "sendkey up", "sendkey up", "sendkey right", "sendkey ret"])?;
        pause(300);
        type_keys(&mon, "london\n")?;
        // Strata is told by its watches (not by looking every 2 s), and
        // works the zone out again.
        con.wait_for_all(
            &["strata-settings: the time zone is now Europe/London", "strata: the time zone changed: "],
            15,
        )?;
        match con.last_line_with("strata: watched: ") {
            Some(l) if l.ends_with("watched: settings zone desktop alarms displays; looked at: none") => {}
            l => return Err(format!("Strata doesn't watch all it follows: {l:?}")),
        }
        con.run("cat /etc/slate/timezone; case $(date +%Z) in GMT|BST) echo zone-ok;; esac", "zone-ok", 10)?;
        con.run("TZ=Asia/Kolkata date +%Z%z", "IST+0530", 10)?;
        // The network (ADR 0054): its section, its page, a fixed address
        // (QEMU's own, so nothing breaks), through the broker. The fields
        // are edited (ADR 0101): the address typed after a caret moved
        // home, the gateway selected with shift + Home and copied to
        // Strata's clipboard, pasted into the name servers and changed.
        monitor(&mon, &["sendkey esc", "sendkey down", "sendkey right", "sendkey ret"])?;
        pause(300);
        monitor(&mon, &["sendkey right", "sendkey tab"])?;
        type_keys(&mon, "/24")?;
        monitor(&mon, &["sendkey home"])?;
        type_keys(&mon, "10.0.2.15")?;
        monitor(&mon, &["sendkey tab"])?;
        type_keys(&mon, "10.0.2.2")?;
        monitor(&mon, &["sendkey shift-home", "sendkey ctrl-c", "sendkey tab", "sendkey ctrl-v"])?;
        pause(500);
        monitor(&mon, &["sendkey backspace"])?;
        type_keys(&mon, "3")?;
        pause(300);
        screendump(&mon, "strata-settings-network.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata-settings: the network is now * static 10.0.2.15/24 gateway 10.0.2.2 dns 10.0.2.3", 20)?;
        con.run("grep -c 'address = 10.0.2.15/24' /etc/slate/network", "1", 10)?;
        // Back to graphite and Lineation (under it, the default; ADR
        // 0124), and the window closed.
        monitor(&mon, &["sendkey esc", "sendkey up", "sendkey up", "sendkey up", "sendkey right", "sendkey spc"])?;
        con.wait_for("strata: settings changed: Settings { theme: Graphite", 10)?;
        monitor(&mon, &["sendkey down", "sendkey ret"])?;
        con.wait_for("wallpaper: Lineation, picture: false }", 10)?;
        monitor(&mon, &["sendkey meta_l-q"])?;
        pause(500);
        // A picture of one's own (ADR 0110's second addendum): a blue BMP
        // as the wallpaper, as Settings leaves it, drawn over the screen.
        con.run_seeing(
            "printf '\\102\\115\\106\\000\\000\\000\\000\\000\\000\\000\\066\\000\\000\\000\\050\\000\\000\\000\\002\\000\\000\\000\\002\\000\\000\\000\\001\\000\\030\\000\\000\\000\\000\\000\\020\\000\\000\\000\\023\\013\\000\\000\\023\\013\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\231\\146\\063\\231\\146\\063\\000\\000\\231\\146\\063\\231\\146\\063\\000\\000' > /tmp/blue.bmp \
             && cp /tmp/blue.bmp $HOME/.config/strata/wallpaper && echo wallpaper=picture >> $HOME/.config/strata/settings \
             && echo pic-$((1+1))",
            "pic-2",
            "picture: true }",
            10,
        )?;
        pause(600);
        if ppm_pixel(&screendump(&mon, "strata-picture.ppm")?, 1270, 790)? != [0x33, 0x66, 0x99] {
            return Err("the picture isn't the wallpaper".into());
        }
        con.run_seeing("echo wallpaper=lineation >> $HOME/.config/strata/settings", "", "picture: false }", 10)?;
        // Account pictures: the broker made their folder sticky; root's
        // shows on the lock screen below. A full name changed through the
        // broker (as Settings asks).
        con.run("stat -c %a /var/lib/slate/faces", "1777", 10)?;
        con.run("cp /tmp/blue.bmp /var/lib/slate/faces/root.png && echo face-$((1+1))", "face-2", 10)?;
        con.run("slate-approve 'user=name ada Ada King' && grep -c '^ada:x:1001:1001:Ada King:' /etc/passwd", "1", 15)?;
        con.send("su tester -c '/bin/slate-approve restart' &\r")?;
        con.wait_for("strata: approval: restart for tester (by slate-approve", 15)?;
        pause(600);
        let shot = screendump(&mon, "strata-approval.ppm")?;
        if ppm_pixel(&shot, 640, 190)? != [0x1C, 0x1C, 0x1B] {
            return Err("no approval dialog on the screen".into());
        }
        // The broker answers others while the dialog waits (ADR 0039).
        con.run("printf 'root-pw\\n' | passwd --stdin root >/dev/null && echo parallel-$((2+2))", "parallel-4", 10)?;
        type_keys(&mon, "nope\n")?;
        con.wait_for("strata: approval: try again", 15)?;
        pause(300);
        screendump(&mon, "strata-approval-retry.ppm")?;
        // Cancelled: the request fails, and nothing restarts.
        monitor(&mon, &["sendkey esc"])?;
        con.wait_for("slate-approve: cancelled", 15)?;
        // The power dialog (ADR 0110): the button at the top right; Lock,
        // then again and Shut down.
        monitor(&mon, &["mouse_move 300 -300"; 8])?;
        pause(200);
        monitor(&mon, &["mouse_move -20 14", "mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the power dialog", 10)?;
        pause(500);
        let shot = screendump(&mon, "strata-power.ppm")?;
        if ppm_pixel(&shot, 640, 470)? != [0x1C, 0x1C, 0x1B] {
            return Err("the power button opened no dialog".into());
        }
        monitor(&mon, &["sendkey left", "sendkey left", "sendkey left", "sendkey ret"])?;
        con.wait_for("strata: locked", 10)?;
        pause(1000);
        // root's picture in the person's tile.
        if ppm_pixel(&screendump(&mon, "strata-locked-face.ppm")?, 127, 474)? != [0x33, 0x66, 0x99] {
            return Err("the lock screen doesn't show root's picture".into());
        }
        type_keys(&mon, "root-pw\n")?;
        con.wait_for("strata: unlocked", 15)?;
        pause(400);
        // Later (ADR 0110's addendum): shutting down in 15 minutes, which
        // the top bar shows in ochre, then called off in the dialog.
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the power dialog", 10)?;
        pause(300);
        monitor(&mon, &["sendkey down", "sendkey right", "sendkey ret"])?;
        con.wait_for("strata: power: poweroff at ", 10)?;
        pause(1500);
        let shot = screendump(&mon, "strata-power-later.ppm")?;
        if !(800..1180).any(|x| ppm_pixel(&shot, x, 16).is_ok_and(|p| p == [0x33, 0x2F, 0x27])) {
            return Err("the top bar doesn't show the shut down set for later".into());
        }
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the power dialog", 10)?;
        pause(300);
        monitor(&mon, &["sendkey down", "sendkey ret"])?;
        con.wait_for(" called off", 10)?;
        // Unsaved work: shutting down asks every window to close; the Text
        // Editor with a change keeps its own and asks, and the dialog names
        // it. Shut down anyway.
        con.send("text-editor /tmp/plans.txt &\r")?;
        con.wait_for("\"plans.txt\" from pid", 15)?;
        pause(1200);
        type_keys(&mon, "unsaved")?;
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the power dialog", 10)?;
        pause(300);
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata: power: closing ", 10)?;
        let open = con.line_after("strata: power: still open: ", 15)?;
        // (The Text Editor marks unsaved changes in its title.)
        if open != "plans.txt • · /tmp" {
            return Err(format!("the dialog names {open:?}, not the Text Editor alone"));
        }
        pause(600);
        screendump(&mon, "strata-power-unsaved.ppm")?;
        monitor(&mon, &["sendkey right", "sendkey ret"])?;
        con.wait_for("strata: power: Shut down anyway", 10)?;
        con.wait_for("strata: power: poweroff", 10)?;
        // Shut down: QEMU ends.
        con.wait_exit(60).map(|_| ())
    })();
    if result.is_err() {
        con.drain(500);
    }
    let _ = std::fs::write(target_dir().join("strata-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("strata scenario: {e} (transcript in target/strata-scenario.log)"));
    }
    println!(
        "xtask: strata scenario passed (the terminal with chalk and etch, apps' windows, the linux tag following \
         the foreground program, floating windows (moved, resized, snapped, maximised, minimised), scrollback and the clipboards, workspaces, launcher, log out, the lock \
         screen (also by itself after idle time, and switching person), windows in quarters, the Applications menu, settings by sections (style, wallpaper, an account added, the time zone, the network with its fields edited: caret, selection, the clipboard), system approval with the broker answering others meanwhile, a picture wallpaper and an account picture on the lock screen, a full name changed, the power dialog locking, setting a shut down for later and calling it off, and shutting down past an app's \
         unsaved work; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The firmware framebuffer's card (ADR 0100): `/test/drm` on it, its
/// cursor plane blended in by the kernel and its gamma table applied as it
/// copies: with the test's inverting table, the green screen shows
/// magenta, the blue strip yellow and the white cursor black.
fn kms_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-kms.img", image::Root::Disk)?;
    let mon = target_dir().join("kms-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run("(/test/drm hold 3 > /tmp/drm.log 2>&1 &); sleep 1.5; echo shown", "shown", 15)?;
        let shot = screendump(&mon, "kms-drm.ppm")?;
        let (screen, strip, cursor) =
            (ppm_pixel(&shot, 40, 40)?, ppm_pixel(&shot, 40, 8)?, ppm_pixel(&shot, 230, 230)?);
        if screen != [255, 0, 255] || strip != [255, 255, 0] {
            return Err(format!("gamma: the screen is {screen:?}, the strip {strip:?} (want magenta and yellow)"));
        }
        if cursor != [0, 0, 0] || ppm_pixel(&shot, 280, 230)? != [255, 0, 255] {
            return Err(format!("the cursor plane is not at (200, 200) (pixel {cursor:?})"));
        }
        con.run("sleep 2.5; tail -n 1 /tmp/drm.log", "drm: ok drop_master", 15)?;
        con.run("grep -v ' ok ' /tmp/drm.log; echo fails-$(grep -c FAIL /tmp/drm.log)", "fails-0", 10)?;
        check_screenshot(&screendump(&mon, "kms-console-back.ppm")?)
            .map_err(|e| format!("console after the client: {e}"))?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("kms-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("KMS scenario: {e} (transcript in target/kms-scenario.log)"));
    }
    println!(
        "xtask: KMS scenario passed (the firmware framebuffer through atomic KMS: the cursor plane and gamma in \
         software, console back; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// virtio-gpu (ADR 0033, ADR 0100) with two outputs as the only display:
/// the console shows through it; `/test/drm` lights both (the first with
/// its legacy and atomic checks, DIRTYFB's damage and the cursor plane,
/// the second red through an atomic modeset); the console comes back
/// when the client exits.
fn gpu_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-gpu.img", image::Root::Disk)?;
    let mon = target_dir().join("gpu-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    // The second head has a VNC server of its own, through which it is
    // given a size: QEMU's way of plugging in a display.
    let vnc = target_dir().join("gpu-vnc.sock");
    let _ = std::fs::remove_file(&vnc);
    c.args(["-vga", "none", "-device", "virtio-gpu-pci,max_outputs=2,id=gpu", "-display", "none"]);
    c.arg("-vnc").arg(format!("unix:{},display=gpu,head=1", vnc.display()));
    c.args(["-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run(
            "dmesg | grep -i 'virtio-gpu\\|drm'; echo cards: $(ls /dev/dri)",
            "virtio-gpu: 2 scanouts, 1280x800, console, EDID, cursor, MSI-X",
            10,
        )?;
        // The second display comes on: a display event, and a hotplug
        // uevent that reaches user space.
        con.run("(/test/drm hotplug-wait 15 > /tmp/hp.log 2>&1 &); sleep 0.5; cat /tmp/hp.log", "drm: listening", 10)?;
        let mut client = crate::vnc::Vnc::connect(&vnc)?;
        client.set_size(1024, 768)?;
        con.wait_for("virtio-gpu: displays now 1280x800, 1024x768", 10)?;
        con.wait_for("drm: card0: displays changed", 5)?;
        con.run("sleep 0.5; cat /tmp/hp.log", "drm: hotplug change@/devices/", 10)?;
        // Each output's connector in /sys, as it is now: the second one
        // connected with its mode, and an EDID of 128 bytes or more.
        con.run(
            "c=/sys/class/drm/card0-Virtual-2; echo conn-$(cat $c/status)-$(head -n 1 $c/modes)-$(test $(wc -c < $c/edid) -ge 128 && echo edid)",
            "conn-connected-1024x768-edid",
            10,
        )?;
        check_screenshot(&screendump(&mon, "gpu-console.ppm")?)
            .map_err(|e| format!("console through virtio-gpu: {e}"))?;
        con.run("(/test/drm hold 3 > /tmp/drm.log 2>&1 &); sleep 1.5; echo shown", "shown", 15)?;
        let shot = screendump(&mon, "gpu-drm.ppm")?;
        let p = ppm_pixel(&shot, 40, 40)?;
        if p != [0, 255, 0] {
            return Err(format!("the DRM client's picture is not on screen (pixel {p:?})"));
        }
        // DIRTYFB sent the strip it named, and only that (ADR 0039).
        let (dirty, clean) = (ppm_pixel(&shot, 40, 8)?, ppm_pixel(&shot, 40, 108)?);
        if dirty != [0, 0, 255] || clean != [0, 255, 0] {
            return Err(format!("DIRTYFB: the dirty strip is {dirty:?}, the one never marked {clean:?}"));
        }
        // The second head: red.
        let second = screendump_head(&mon, "gpu-drm-head1.ppm", "gpu", 1)?;
        let p = ppm_pixel(&second, 40, 40)?;
        if p != [255, 0, 0] {
            return Err(format!("the second output is not red (pixel {p:?})"));
        }
        con.run("sleep 2.5; tail -n 1 /tmp/drm.log", "drm: ok drop_master", 15)?;
        con.run("grep -v ' ok ' /tmp/drm.log; echo fails-$(grep -c FAIL /tmp/drm.log)", "fails-0", 10)?;
        // A display resized: the card follows.
        client.set_size(800, 600)?;
        con.wait_for("virtio-gpu: displays now 1280x800, 800x600", 10)?;
        con.wait_for("drm: card0: displays changed", 5)?;
        check_screenshot(&screendump(&mon, "gpu-console-back.ppm")?)
            .map_err(|e| format!("console after the client: {e}"))?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("gpu-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("GPU scenario: {e} (transcript in target/gpu-scenario.log)"));
    }
    println!(
        "xtask: GPU scenario passed (virtio-gpu console, a second display plugged in (a hotplug uevent) and resized, two outputs lit through legacy and atomic KMS, only the damage sent, console back; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// One headless boot: serial lines and how QEMU ended (`None` on timeout).
struct Boot {
    lines: Vec<String>,
    status: Option<std::process::ExitStatus>,
    elapsed: f64,
}

/// Attach `disk` as another virtio-blk device (the guest sees them in
/// order: the boot image is /dev/vda, the first extra disk /dev/vdb...).
pub fn add_disk(c: &mut Command, id: usize, disk: &Path) {
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=extra{id},discard=unmap", disk.display()));
    c.arg("-device").arg(format!("virtio-blk-pci,drive=extra{id}"));
}

/// Where the test machine's AHCI disk fails one read (sector 24 MiB in,
/// once): the ahci::recovers test reads there (keep in sync).
const AHCI_BAD_SECTOR: u64 = (24 << 20) / 512;

/// The AHCI test disk on port `port` of q35's built-in SATA controller,
/// through QEMU's blkdebug driver with one injected
/// read error (EIO at `AHCI_BAD_SECTOR`, once), so the driver's error
/// recovery runs.
fn add_ahci_disk_with_error(c: &mut Command, port: usize, disk: &Path) -> Result {
    let conf = target_dir().join("ahci-blkdebug.conf");
    let rule =
        format!("[inject-error]\nevent = \"read_aio\"\nerrno = \"5\"\nsector = \"{AHCI_BAD_SECTOR}\"\nonce = \"on\"\n");
    std::fs::write(&conf, rule).map_err(|e| format!("writing {}: {e}", conf.display()))?;
    c.arg("-drive").arg(format!(
        "driver=raw,file.driver=blkdebug,file.config={},file.image.filename={},if=none,id=ahci{port},discard=unmap",
        conf.display(),
        disk.display()
    ));
    c.arg("-device").arg(format!("ide-hd,drive=ahci{port},bus=ide.{port}"));
    Ok(())
}

/// An NVMe controller with `disk` as namespace 1.
pub fn add_nvme_disk(c: &mut Command, id: usize, disk: &Path) {
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=nvme{id},discard=unmap", disk.display()));
    c.arg("-device").arg(format!("nvme,serial=slate{id},drive=nvme{id}"));
}

/// The NVMe namespaces of `nvme::metadata` and `nvme::namespaces`
/// (`nvme1nN`): a second controller, in a subsystem so the kernel can
/// attach namespaces, with one namespace per metadata layout and one
/// left detached.
const NVME_META_NAMESPACES: &[&str] = &[
    // Extended: 16 bytes after each block's data, no protection.
    "nsid=1,ms=16,mset=1",
    // Separate: 16 bytes apart, protection information type 1, 4 KiB blocks.
    "nsid=2,ms=16,mset=0,pi=1,logical_block_size=4096,physical_block_size=4096",
    // Only protection information (type 3): the controller strips it.
    "nsid=3,ms=8,mset=1,pi=3",
    // Attached and detached by the kernel's test.
    "nsid=4,detached=on",
];

/// Add the controller with the namespaces above, `disks` their images.
fn add_nvme_meta(c: &mut Command, disks: &[PathBuf]) {
    c.args(["-device", "nvme-subsys,id=nvmesub,nqn=slate-meta"]);
    c.args(["-device", "nvme,id=nvmem,serial=slatemeta,subsys=nvmesub"]);
    for (i, (d, opts)) in disks.iter().zip(NVME_META_NAMESPACES).enumerate() {
        c.arg("-drive").arg(format!("file={},format=raw,if=none,id=nvmeta{i}", d.display()));
        c.arg("-device").arg(format!("nvme-ns,drive=nvmeta{i},bus=nvmem,{opts}"));
    }
}

/// Boot `img` headless, echoing serial output, killing QEMU after `timeout`.
/// `extra` are virtio disks; `hw` gets the real-hardware test disks.
fn boot_headless(
    mut c: Command,
    extra: &[PathBuf],
    hw: Option<&HwDisks>,
    timeout: Duration,
    echo: bool,
) -> Result<Boot> {
    for (i, d) in extra.iter().enumerate() {
        add_disk(&mut c, i, d);
    }
    if let Some(hw) = hw {
        // An AMD IOMMU, so the NVMe driver runs in a domain (ADR 0127).
        // dma-remap: QEMU translates emulated devices' DMA only with it.
        c.args(["-device", "amd-iommu,dma-remap=on"]);
        add_ahci_disk_with_error(&mut c, 2, &hw.ahci)?;
        add_nvme_disk(&mut c, 0, &hw.nvme);
        add_nvme_meta(&mut c, &hw.meta);
    }
    c.args(["-display", "none", "-monitor", "none", "-serial", "stdio"]);
    c.stdout(Stdio::piped()).stdin(Stdio::null());
    let mut child = c.spawn().map_err(|e| format!("failed to start QEMU: {e}"))?;

    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(std::io::Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let started = Instant::now();
    let mut lines = Vec::new();
    let mut take = |line: String| {
        if echo {
            println!("{line}");
        }
        lines.push(line);
    };
    let status = loop {
        while let Ok(line) = rx.try_recv() {
            take(line);
        }
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if started.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = reader.join();
    rx.try_iter().for_each(&mut take);
    Ok(Boot { lines, status, elapsed: started.elapsed().as_secs_f64() })
}

/// Boot headless with `test` on the kernel command line and pass only if
/// every test passed, the run completed, and QEMU left through the
/// debug-exit device with the success code. Then run each crash case and
/// check its panic report.
pub fn test(o: &Opts) -> Result {
    // A focused run of one scenario (it needs the images an earlier full
    // run built): SLATE_SCENARIO=session|nic|hotplug|usb|uas|usbnet|netd|update|powercut|terminal|...
    if let Ok(name) = std::env::var("SLATE_SCENARIO") {
        return match name.as_str() {
            "session" => shell_session(o),
            "nic" => nic_scenario(o),
            "hotplug" => hotplug_scenario(o),
            "uas" => uas_scenario(o),
            "usb" => usb_scenario(o),
            "usbnet" => usb_net_scenario(o),
            "netd" => netd_scenario(o),
            "gpu" => gpu_scenario(o),
            "displays" => crate::displays::displays_scenario(o),
            "kms" => kms_scenario(o),
            "input" => input_scenario(o),
            "nohpet" => no_hpet_scenario(o),
            "install" => install_scenario(o),
            "alongside" => crate::alongside::alongside_scenario(o),
            "try" => crate::trylive::try_scenario(o),
            "media" => media_scenario(o),
            "graphical" => graphical_scenario(o),
            "strata" => strata_scenario(o),
            "terminal" => crate::terminal::terminal_scenario(o),
            "apps" => crate::apps::apps_scenario(o),
            "tools" => crate::systools::tools_scenario(o),
            "bluetooth" => crate::bluetooth::bluetooth_scenario(o),
            "stress" => crate::stress::strata_stress(o),
            "packages" => crate::packages::packages_scenario(o),
            "update" => update_scenario(o),
            "powercut" => power_cut_scenario(o),
            "bench" => crate::bench::bench(o),
            _ => Err(format!("unknown scenario {name:?}")),
        };
    }
    let run_started = Instant::now();
    // Where each boot's kernel was put (KASLR, ADR 0095).
    let mut slides: Vec<u64> = Vec::new();
    let timeout = Duration::from_secs(o.timeout_secs.unwrap_or(DEFAULT_TEST_TIMEOUT));
    if o.cmdline.is_some() {
        // Custom command lines are for focused runs.
        return kernel_tests(o, timeout).map(|_| ());
    }
    // The gate, timed (the summary says where a run's time went): the
    // in-kernel tests' boot beside the scenarios (ADR 0120). Under BIOS
    // only what the firmware changes runs again: the boot paths (the
    // shell session, the media, an install, updates through the boot
    // menu) and the crash reports; the drivers' and the desktop's
    // scenarios run the same on either (ADR 0091).
    let mut times: Vec<(String, Duration)> = Vec::new();
    let both = !o.bios;
    // Lanes of scenarios that share files (an image another one builds,
    // the test repositories' base-next), each in its order; lanes run side
    // by side, the longest first (ADR 0120). The ones that measure time
    // run last, alone.
    let lanes: Vec<Vec<(&str, bool, Scenario)>> = vec![
        vec![("apps", both, crate::apps::apps_scenario)],
        vec![("strata", both, strata_scenario)],
        vec![("install", true, install_scenario)],
        vec![("graphical", both, graphical_scenario)],
        // UEFI only: SlateOS goes beside other systems on UEFI (ADR 0116).
        vec![("alongside", both, crate::alongside::alongside_scenario)],
        // The shell session's image is the next ones' too.
        vec![
            ("session", true, shell_session),
            ("hotplug", both, hotplug_scenario),
            ("uas", both, uas_scenario),
            ("usbnet", both, usb_net_scenario),
            ("netd", both, netd_scenario),
        ],
        vec![("media", true, media_scenario)],
        vec![("terminal", both, crate::terminal::terminal_scenario)],
        vec![("packages", both, crate::packages::packages_scenario), ("tools", both, crate::systools::tools_scenario)],
        vec![("input", both, input_scenario), ("gpu", both, gpu_scenario)],
        vec![("displays", both, crate::displays::displays_scenario)],
        vec![("try", both, crate::trylive::try_scenario)],
        vec![("nohpet", true, no_hpet_scenario)],
        vec![("bluetooth", both, crate::bluetooth::bluetooth_scenario)],
        vec![("update", true, update_scenario)],
        vec![("powercut", both, power_cut_scenario)],
        vec![("nic", both, nic_scenario)],
        vec![("kms", both, kms_scenario)],
        vec![("usb", both, usb_scenario)],
    ];
    // The budgets (ADR 0047), and the desktop's measured (ADR 0062).
    let alone: Vec<(&str, bool, Scenario)> =
        vec![("stress", both, crate::stress::strata_stress), ("bench", both, crate::bench::gate)];
    let wanted = |name: &str| o.scenarios.as_ref().is_none_or(|l| l.iter().any(|n| n == name));
    if let Some(l) = &o.scenarios {
        let known: Vec<&str> = lanes.iter().flatten().chain(alone.iter()).map(|(n, _, _)| *n).collect();
        if let Some(bad) = l.iter().find(|n| *n != "none" && !known.contains(&n.as_str())) {
            return Err(format!("--scenarios: no scenario {bad:?} (there are {})", known.join(", ")));
        }
    }
    let lanes: Vec<Vec<(&str, Scenario)>> = lanes
        .into_iter()
        .map(|l| l.into_iter().filter(|(n, run, _)| *run && wanted(n)).map(|(n, _, f)| (n, f)).collect())
        .filter(|l: &Vec<_>| !l.is_empty())
        .collect();
    // SLATE_JOBS lanes at once (default: four, fewer if memory is short).
    let jobs =
        std::env::var("SLATE_JOBS").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| guests_at_once(4)).max(1);
    let queue = std::sync::Mutex::new(lanes.into_iter().collect::<std::collections::VecDeque<_>>());
    let done = std::sync::Mutex::new((Vec::new(), Vec::new()));
    let kernel = std::thread::scope(|sc| {
        let kernel = sc.spawn(|| {
            let t = Instant::now();
            let r = kernel_tests(o, timeout);
            let mut d = done.lock().unwrap_or_else(|e| e.into_inner());
            d.0.insert(0, (String::from("build and in-kernel tests"), t.elapsed()));
            match r {
                Ok(slides) => slides,
                Err(e) => {
                    d.1.insert(0, e);
                    Vec::new()
                }
            }
        });
        for _ in 0..jobs {
            sc.spawn(|| {
                loop {
                    // After a failure, no lane starts.
                    if !done.lock().unwrap_or_else(|e| e.into_inner()).1.is_empty() {
                        return;
                    }
                    let Some(lane) = queue.lock().unwrap_or_else(|e| e.into_inner()).pop_front() else { return };
                    for (name, stage) in lane {
                        let t = Instant::now();
                        let r = stage(o);
                        let mut d = done.lock().unwrap_or_else(|e| e.into_inner());
                        d.0.push((String::from(name), t.elapsed()));
                        if let Err(e) = r {
                            d.1.push(e);
                            return;
                        }
                    }
                }
            });
        }
        kernel.join().unwrap_or_default()
    });
    slides.extend(kernel);
    let (ran, failed) = done.into_inner().unwrap_or_else(|e| e.into_inner());
    times.extend(ran);
    if !failed.is_empty() {
        return Err(failed.join("\nxtask: "));
    }
    for (name, run, stage) in alone {
        if run && wanted(name) {
            let t = Instant::now();
            stage(o)?;
            times.push((String::from(name), t.elapsed()));
        }
    }
    let t = Instant::now();
    slides.extend(crash_cases(o, timeout)?);
    times.push((String::from("crash cases"), t.elapsed()));
    kaslr_report(&slides)?;
    let list: Vec<String> = times.iter().map(|(n, d)| format!("{n} {:.0}s", d.as_secs_f64())).collect();
    println!("xtask: times: {} (total {:.0}s)", list.join(", "), run_started.elapsed().as_secs_f64());
    Ok(())
}

/// The in-kernel tests (with the shell scripts and test programs they
/// run): one headless boot from the initramfs with the test disks, then
/// the disks checked on the host. The kernel's placement, for the KASLR
/// report.
fn kernel_tests(o: &Opts, timeout: Duration) -> Result<Vec<u64>> {
    // Servers on the host, reachable from the guest at 10.0.2.2.
    let servers = crate::hostnet::HostServers::start()?;
    // quarry's test repositories (built with the image below), over HTTP
    // and, with the host's OpenSSL, over HTTPS (ADR 0053).
    let www = crate::quarry::test_repos()?;
    let repos = crate::hostnet::StaticServer::start(www.clone())?;
    let tls = match crate::quarry::test_tls()? {
        Some(d) => Some(crate::tlstest::serve(&www, d.join("repo.pem"), &[])?),
        None => None,
    };
    let tls_arg = tls.as_ref().map_or(String::new(), |(_, port)| format!(" slate.repo_tls={port}"));
    let cmdline = match &o.cmdline {
        // slate.disable names a driver the machine has no device for: the
        // drivers::registry test checks it was read (ADR 0081).
        Some(extra) => {
            format!("test {} slate.repo={}{tls_arg} slate.disable=rtl8139 {extra}", servers.cmdline, repos.port)
        }
        None => format!("test {} slate.repo={}{tls_arg} slate.disable=rtl8139", servers.cmdline, repos.port),
    };
    let img = image::build(o, &cmdline, "slate-test.img", image::Root::Initramfs)?;
    let scratch = scratch_disk()?;
    let ext4 = crate::ext4img::test_disk()?;
    let sfs = crate::slatefsimg::test_disk()?;
    let hw = hw_disks()?;
    // /dev/vde: an empty disk for slate-crypt (tests/shell/crypt.sh).
    let crypt = target_dir().join("crypt-test.img");
    std::fs::File::create(&crypt).and_then(|f| f.set_len(8 << 20)).map_err(|e| e.to_string())?;
    let disks = [scratch.clone(), ext4.clone(), sfs.clone(), crypt];
    let boot = boot_headless(base_command(o, &img)?, &disks, Some(&hw), timeout, true);
    servers.stop();
    repos.stop();
    let boot = boot?;
    let mut report = Report::default();
    boot.lines.iter().for_each(|l| report.line(l));

    let summary = format!("{} passed, {} failed, {:.2}s", report.passed.len(), report.failed.len(), boot.elapsed);
    match boot.status {
        None => Err(format!("test run timed out after {}s ({summary})", timeout.as_secs())),
        Some(s) if !report.failed.is_empty() => {
            Err(format!("failed: {} ({summary}, QEMU {s})", report.failed.join(", ")))
        }
        Some(s) if s.code() == Some(EXIT_FAILURE) => Err(format!("kernel reported failure ({summary})")),
        Some(s) if !report.done || s.code() != Some(EXIT_SUCCESS) => {
            Err(format!("kernel stopped before finishing the tests ({summary}, QEMU {s})"))
        }
        Some(_) => {
            let missing: Vec<&str> =
                REQUIRED_OUTPUT.iter().copied().filter(|r| !boot.lines.iter().any(|l| l.contains(r))).collect();
            if !missing.is_empty() {
                return Err(format!("expected output missing: {missing:?}"));
            }
            check_scratch_disk(&scratch)?;
            crate::ext4img::check_test_disk(&ext4)?;
            crate::slatefsimg::check_test_disk(&sfs)?;
            check_hw_disks(&hw)?;
            println!("xtask: all tests passed ({summary})");
            Ok(boot.lines.iter().filter_map(|l| slide_in(l, "kaslr: slide ")).collect())
        }
    }
}

/// A stage of the gate: a scenario run on its own machines.
type Scenario = fn(&Opts) -> Result;

/// How many crash cases boot at most at once: each panics within seconds,
/// and its CPUs halt after.
const CRASH_PARALLEL: usize = 8;

/// Memory left to the host when guests are sized against it.
const HOST_RESERVE: u64 = 4 << 30;

/// A guest's memory (QEMU's `-m`: SLATE_MEM, else 32G for SLATE_SHAPE=refpc
/// or 4G), and whether it is preallocated (the reference PC's shape).
fn guest_memory() -> (String, bool) {
    let refpc = std::env::var("SLATE_SHAPE").is_ok_and(|s| s == "refpc");
    let mem = std::env::var("SLATE_MEM").unwrap_or_else(|_| if refpc { "32G" } else { "4G" }.into());
    (mem, refpc)
}

/// Bytes in a QEMU size (`4G`, `512M`; a plain number is MiB).
fn size_bytes(s: &str) -> Option<u64> {
    let (n, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&s[..i], &s[i..]),
        None => (s, "M"),
    };
    let shift = match unit.to_ascii_uppercase().as_str() {
        "K" => 10,
        "M" => 20,
        "G" => 30,
        "T" => 40,
        _ => return None,
    };
    n.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// The host's available memory (MemAvailable in /proc/meminfo, proc(5)).
fn mem_available() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kib = info.lines().find_map(|l| l.strip_prefix("MemAvailable:"))?.trim().strip_suffix("kB")?;
    kib.trim().parse::<u64>().ok().map(|k| k << 10)
}

/// How many guests boot at once: one when each takes all its memory up
/// front, else as many (up to `most`) as half the host's free memory
/// holds at their full size.
fn guests_at_once(most: usize) -> usize {
    let (mem, prealloc) = guest_memory();
    if prealloc {
        return 1;
    }
    let each = size_bytes(&mem).unwrap_or(4 << 30).max(1);
    let fit = mem_available().unwrap_or(0).saturating_sub(HOST_RESERVE) / 2 / each;
    (fit as usize).clamp(1, most)
}

/// A slide a boot reported after `prefix` (hexadecimal, `0x` first).
fn slide_in(line: &str, prefix: &str) -> Option<u64> {
    let hex = line.split(prefix).nth(1)?.trim().strip_prefix("0x")?;
    u64::from_str_radix(hex.split_whitespace().next()?, 16).ok()
}

/// The kernel's placement over a run's boots (KASLR, ADR 0095): the
/// in-kernel tests' boot and the crash cases', each moved by a page count
/// below 2^18; any two the same fails (by chance: about once in 17,000
/// runs of six).
fn kaslr_report(slides: &[u64]) -> Result {
    let mut sorted = slides.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != slides.len() || slides.len() < 2 {
        return Err(format!("KASLR: the kernel's slides over {} boots were {slides:x?}", slides.len()));
    }
    println!("xtask: KASLR: {} boots, {} different places for the kernel", slides.len(), sorted.len());
    Ok(())
}

/// Boot each crash case and check its panic report, several at a time,
/// each with its own image and UEFI variables. Returns the slides the
/// panics reported.
fn crash_cases(o: &Opts, timeout: Duration) -> Result<Vec<u64>> {
    let dir = target_dir().join("crash");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let next = std::sync::atomic::AtomicUsize::new(0);
    let failed = std::sync::Mutex::new(Vec::new());
    let slides = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..guests_at_once(CRASH_PARALLEL) {
            s.spawn(|| {
                while let Some((name, expected, status)) =
                    CRASH_CASES.get(next.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                {
                    match crash_case(o, &dir, name, expected, *status, timeout) {
                        Ok((secs, slide)) => {
                            println!("xtask: crash case {name} reported correctly ({secs:.2}s)");
                            slides.lock().unwrap().extend(slide);
                        }
                        Err(e) => failed.lock().unwrap().push(e),
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().unwrap();
    if failed.is_empty() { Ok(slides.into_inner().unwrap()) } else { Err(failed.join("; ")) }
}

fn crash_case(
    o: &Opts,
    dir: &Path,
    name: &str,
    expected: &[&str],
    status: i32,
    timeout: Duration,
) -> Result<(f64, Option<u64>)> {
    let file = format!("crash/{name}.img");
    let img = image::build(o, &format!("test ktest.crash={name}"), &file, image::Root::Initramfs)?;
    let boot = boot_headless(base_command_vars(o, &img, &dir.join(format!("{name}.vars")))?, &[], None, timeout, false);
    let _ = std::fs::remove_file(&img);
    let boot = boot?;
    let out = boot.lines.join("\n");
    let started = out.contains(&format!("SLATE-TEST: CRASH {name}"));
    let missing: Vec<&str> = expected.iter().copied().filter(|e| !out.contains(e)).collect();
    let code = boot.status.and_then(|s| s.code());
    if !started || !missing.is_empty() || code != Some(status) {
        println!("{out}");
        return Err(format!("crash case {name}: started={started} exit={code:?} (want {status}) missing={missing:?}"));
    }
    Ok((boot.elapsed, boot.lines.iter().find_map(|l| slide_in(l, "kernel slide "))))
}

/// The AHCI and NVMe disks of tests/user/disks.c (/dev/sda, /dev/nvme0n1).
pub struct HwDisks {
    ahci: PathBuf,
    nvme: PathBuf,
    /// The namespaces of `NVME_META_NAMESPACES`.
    meta: Vec<PathBuf>,
}

const HW_DISK_SIZE: u64 = 32 << 20;
// Where tests/user/disks.c writes its patterns (keep in sync).
const SDA_OFFSET: usize = (1 << 20) + 7;
const SDA_LEN: usize = 700_000;
const NVME_PART_START: u64 = 9 << 20;
const NVME_OFFSET: usize = NVME_PART_START as usize + 12388;
const NVME_LEN: usize = 600_000;

/// An empty disk for AHCI, and one with a two-partition GPT for NVMe.
fn hw_disks() -> Result<HwDisks> {
    let ahci = target_dir().join("ahci-test.img");
    let nvme = target_dir().join("nvme-test.img");
    for p in [&ahci, &nvme] {
        let _ = std::fs::remove_file(p);
        let f = std::fs::File::create(p).map_err(|e| format!("creating {}: {e}", p.display()))?;
        f.set_len(HW_DISK_SIZE).map_err(|e| e.to_string())?;
    }
    write_gpt(&nvme, HW_DISK_SIZE, &[("alpha", 2048, NVME_PART_START / 512 - 1), ("beta", NVME_PART_START / 512, 0)])?;
    let mut meta = Vec::new();
    for i in 1..=NVME_META_NAMESPACES.len() {
        let p = target_dir().join(format!("nvme-meta{i}.img"));
        let _ = std::fs::remove_file(&p);
        let f = std::fs::File::create(&p).map_err(|e| format!("creating {}: {e}", p.display()))?;
        f.set_len(4 << 20).map_err(|e| e.to_string())?;
        meta.push(p);
    }
    Ok(HwDisks { ahci, nvme, meta })
}

/// Write a GPT with Linux-data partitions `(name, first, last)` (a last
/// LBA of 0 means the end of the disk) into the image at `path`.
fn write_gpt(path: &Path, size: u64, parts: &[(&'static str, u64, u64)]) -> Result {
    let blocks = size / 512;
    let layout = slate_gpt::Layout::for_disk(blocks).map_err(|e| format!("{e:?}"))?;
    let parts: Vec<slate_gpt::Partition> = parts
        .iter()
        .map(|&(name, first, last)| slate_gpt::Partition {
            type_guid: slate_gpt::Guid::LINUX_FILESYSTEM,
            unique_guid: image::guid_for(name),
            first_lba: first,
            last_lba: if last == 0 { layout.last_usable } else { last },
            attributes: 0,
            name,
        })
        .collect();
    let gpt = slate_gpt::encode(blocks, image::guid_for(&path.display().to_string()), &parts)
        .map_err(|e| format!("{e:?}"))?;
    let mut data = std::fs::read(path).map_err(|e| e.to_string())?;
    let at = |lba: u64| (lba * 512) as usize;
    data[..512].copy_from_slice(&gpt.protective_mbr);
    data[512..1024].copy_from_slice(&gpt.primary_header);
    data[1024..1024 + gpt.entries.len()].copy_from_slice(&gpt.entries);
    data[at(gpt.backup_entries_lba)..at(gpt.backup_entries_lba) + gpt.entries.len()].copy_from_slice(&gpt.entries);
    data[at(gpt.backup_header_lba)..at(gpt.backup_header_lba) + 512].copy_from_slice(&gpt.backup_header);
    std::fs::write(path, data).map_err(|e| e.to_string())
}

/// Type `text` on the guest's keyboard through the QEMU monitor.
pub fn type_keys(mon: &Path, text: &str) -> Result {
    let keys: Vec<String> = text
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' => c.to_string(),
            'A'..='Z' => format!("shift-{}", c.to_ascii_lowercase()),
            ' ' => "spc".into(),
            '\n' => "ret".into(),
            '/' => "slash".into(),
            '-' => "minus".into(),
            '.' => "dot".into(),
            '=' => "equal".into(),
            ',' => "comma".into(),
            '\t' => "tab".into(),
            // Shifted on a US keyboard.
            '!' => "shift-1".into(),
            '%' => "shift-5".into(),
            '^' => "shift-6".into(),
            '*' => "shift-8".into(),
            '(' => "shift-9".into(),
            ')' => "shift-0".into(),
            '+' => "shift-equal".into(),
            '>' => "shift-dot".into(),
            '<' => "shift-comma".into(),
            _ => "spc".into(),
        })
        .map(|k| format!("sendkey {k}"))
        .collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    monitor(mon, &refs)
}

/// Two USB Attached SCSI disks (ADR 0082): one on a controller with USB 3
/// ports (SuperSpeed, streams), one on a controller with USB 2 ports only
/// (Read Ready and Write Ready). Each is read, written, and checked on the
/// host.
fn uas_scenario(o: &Opts) -> Result {
    const SIZE: usize = 16 << 20;
    let img = target_dir().join("slate-session.img");
    let disks = [target_dir().join("uas-super.img"), target_dir().join("uas-high.img")];
    for (k, d) in disks.iter().enumerate() {
        let mut data = vec![0u8; SIZE];
        let text = format!("uas disk {k}\n");
        data[..text.len()].copy_from_slice(text.as_bytes());
        // A pattern across several transfers, for the read-back.
        for (i, b) in data[1 << 20..(1 << 20) + 300_000].iter_mut().enumerate() {
            *b = ((i * 7 + k * 3) % 251) as u8;
        }
        std::fs::write(d, &data).map_err(|e| format!("writing {}: {e}", d.display()))?;
    }
    let mut c = base_command(o, &img)?;
    c.args(["-device", "qemu-xhci,id=xs", "-device", "qemu-xhci,id=xh,p3=0"]);
    for (k, (bus, d)) in ["xs", "xh"].iter().zip(&disks).enumerate() {
        c.arg("-drive").arg(format!("file={},format=raw,if=none,id=uasdisk{k}", d.display()));
        c.args(["-device", &format!("usb-uas,id=uas{k},bus={bus}.0")]);
        c.args(["-device", &format!("scsi-hd,bus=uas{k}.0,scsi-id=0,lun=0,drive=uasdisk{k}")]);
    }
    c.args(["-display", "none", "-serial", "stdio", "-monitor", "none"]);
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        con.run(
            "for i in $(seq 100); do [ -e /dev/sdb ] && break; sleep 0.1; done; \
             echo uas-$(dmesg | grep -c 'UAS with streams')-$(dmesg | grep -c ': UAS$')",
            "uas-1-1",
            20,
        )?;
        // Each disk: its first line, its pattern, and a write.
        for dev in ["sda", "sdb"] {
            con.run(&format!("head -c 11 /dev/{dev}; echo"), "uas disk", 10)?;
            con.run(
                &format!("dd if=/dev/{dev} bs=1M skip=1 count=1 2>/dev/null | head -c 300000 | cksum | cut -d' ' -f2"),
                "300000",
                15,
            )?;
            con.run(
                &format!("echo written-over-uas | dd of=/dev/{dev} bs=512 seek=4096 conv=notrunc 2>/dev/null; sync; echo w-ok"),
                "w-ok",
                15,
            )?;
        }
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("uas-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("UAS scenario: {e} (transcript in target/uas-scenario.log)"));
    }
    for (k, d) in disks.iter().enumerate() {
        let data = std::fs::read(d).map_err(|e| e.to_string())?;
        let at = 4096 * 512;
        if &data[at..at + 17] != b"written-over-uas\n" {
            return Err(format!("UAS scenario: the write is not on disk {k}"));
        }
        let pattern_ok =
            data[1 << 20..(1 << 20) + 300_000].iter().enumerate().all(|(i, &b)| b == ((i * 7 + k * 3) % 251) as u8);
        if !pattern_ok {
            return Err(format!("UAS scenario: disk {k}'s pattern changed"));
        }
    }
    println!(
        "xtask: UAS scenario passed (SuperSpeed with streams and high speed with Read/Write Ready: read, written; \
         {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// A USB keyboard behind a hub and a USB stick on QEMU's xHCI controller:
/// the keyboard types at the shell, the stick's partitions are read and written, and
/// the host finds the write on the stick image.
fn usb_scenario(o: &Opts) -> Result {
    const STICK_SIZE: u64 = 32 << 20;
    const PART2: u64 = 9 << 20;
    // Its own image: usb.stall_test makes each device stall a request
    // first (a stalled control transfer must leave endpoint 0 usable).
    let img = image::build(o, "usb.stall_test", "slate-usb-scenario.img", image::Root::Disk)?;
    let stick = target_dir().join("usb-stick.img");
    let _ = std::fs::remove_file(&stick);
    let f = std::fs::File::create(&stick).map_err(|e| e.to_string())?;
    f.set_len(STICK_SIZE).map_err(|e| e.to_string())?;
    drop(f);
    write_gpt(&stick, STICK_SIZE, &[("stick-a", 2048, PART2 / 512 - 1), ("stick-b", PART2 / 512, 0)])?;
    let mut data = std::fs::read(&stick).map_err(|e| e.to_string())?;
    data[1 << 20..(1 << 20) + 21].copy_from_slice(b"hello from the stick\n");
    std::fs::write(&stick, data).map_err(|e| e.to_string())?;

    // A second stick, powered off from Slate (ADR 0108's second addendum).
    let stick2 = target_dir().join("usb-stick2.img");
    std::fs::write(&stick2, vec![0u8; 8 << 20]).map_err(|e| e.to_string())?;

    let mon = target_dir().join("usb-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    // The keyboard behind a hub, as keyboards with one built in are.
    c.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-hub,bus=xhci.0,port=1"]);
    c.args(["-device", "usb-kbd,bus=xhci.0,port=1.2"]);
    // A second keyboard: keys typed on one must not show on the other's
    // evdev device (the reference PC's G900 has a keyboard interface, and every key
    // typed on its real keyboard came twice).
    c.args(["-device", "usb-kbd,bus=xhci.0,port=3"]);
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=stick", stick.display()));
    c.args(["-device", "usb-storage,bus=xhci.0,port=2,drive=stick,id=stickdev"]);
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=stick2", stick2.display()));
    c.args(["-device", "usb-storage,bus=xhci.0,port=4,drive=stick2,id=stick2dev,removable=on"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let result = (|| -> Result {
        con.login()?;
        // Every device stalled the refused request and answered the next
        // one at once (no 10 s timeout on a halted endpoint 0).
        con.run(
            "for i in $(seq 100); do [ $(dmesg | grep -c 'stall test') -ge 3 ] && break; sleep 0.1; done; \
             a=$(dmesg | grep -c 'stall test'); \
             b=$(dmesg | grep -c 'stall test: interface descriptor stalled, then the device descriptor read'); \
             echo stall-$a-$b-$([ $a -ge 3 ] && [ $a -eq $b ] && echo recovered)",
            "-recovered",
            20,
        )?;
        con.run(
            "for i in $(seq 100); do dmesg | grep -q 'hid: USB port .*: keyboard$' && [ -e /dev/sda2 ] && break; \
             sleep 0.1; done; sleep 0.5; echo kbd$(dmesg | grep -c 'hid: USB port .*: keyboard$')",
            "kbd2",
            20,
        )?;
        // Each keyboard's evdev device, read while keys are typed.
        con.run(
            "rm -f /tmp/cap-*; for e in /dev/input/event*; do cat $e > /tmp/cap-${e##*/} & echo $! >> /tmp/cap-pids; \
             done; echo capturing",
            "capturing",
            10,
        )?;
        // Typed on the USB keyboard; the output is not in the command.
        type_keys(&mon, "uname\n")?;
        con.wait_for("Slate", 10)?;
        con.wait_for("# ", 5)?;
        con.run(
            "sleep 0.3; kill $(cat /tmp/cap-pids); n=0; for f in /tmp/cap-event*; do [ -s $f ] && n=$((n+1)); done; \
             echo typed-on-$n",
            "typed-on-1",
            10,
        )?;
        // Caps Lock lights the USB keyboard's Caps Lock (SET_REPORT).
        monitor(&mon, &["sendkey caps_lock"])?;
        con.run(
            "sleep 0.3; echo lights-$(dmesg | grep -c 'lights set (0x2)')-$(dmesg | grep -c 'lights failed')",
            // Both keyboards: the console's lock lights are on every one.
            "lights-2-0",
            10,
        )?;
        monitor(&mon, &["sendkey caps_lock"])?;
        // A mouse plugged into the hub, then taken out: the hub's
        // status-change endpoint tells (it is not polled).
        con.run("dmesg | grep -c 'hub with 8 ports$' | sed 's/^/listening-/'", "listening-1", 10)?;
        monitor(&mon, &["device_add usb-mouse,bus=xhci.0,port=1.3,id=hubmouse"])?;
        con.run(
            "for i in $(seq 50); do dmesg | grep -q 'USB port [0-9]*\\.3: mouse' && break; sleep 0.1; done; \
             echo plugged-$(dmesg | grep -c 'USB port [0-9]*\\.3: mouse')",
            "plugged-1",
            15,
        )?;
        monitor(&mon, &["device_del hubmouse"])?;
        con.run(
            "for i in $(seq 50); do dmesg | grep -q 'USB port [0-9]*\\.3: device removed' && break; sleep 0.1; done; \
             echo unplugged-$(dmesg | grep -c 'USB port [0-9]*\\.3: device removed')",
            "unplugged-1",
            15,
        )?;
        // The second stick (8 MiB, 16384 sectors), powered off: it leaves
        // /dev, its port is disabled, and it doesn't come back while it
        // stays plugged in.
        con.run(
            "for i in $(seq 100); do s2=$(for d in /sys/block/sd*; do [ $(cat $d/size) = 16384 ] && echo ${d##*/}; \
             done); [ -n \"$s2\" ] && break; sleep 0.1; done; /sbin/slate-disk poweroff $s2; \
             for i in $(seq 50); do [ ! -e /dev/$s2 ] && break; sleep 0.1; done; sleep 1; \
             echo off-$(ls /dev | grep -c \"^$s2\")-$(dmesg | grep -c 'disabled; unplug the device')",
            "off-0-1",
            20,
        )?;
        // In sysfs and lsusb (M23 phase 7): two root hubs, the hub with
        // the keyboard behind it, the stick; the mouse gone again.
        con.run("lsusb; lsusb -t; ls /sys/bus/usb/devices; echo listed", "listed", 10)?;
        con.run(
            "echo usb-$(lsusb -d 1d6b: | wc -l)-$(lsusb -t | grep -c 'Class=Hub, Driver=usb-hub/8p')\
             -$(lsusb -t | grep -c 'Class=Human Interface Device, Driver=usb-hid')\
             -$(lsusb -t | grep -c 'Class=Mass Storage, Driver=usb-storage')\
             -$(ls /sys/bus/usb/devices | grep -c '[.]3$')\
             -$(cat /sys/bus/usb/devices/*/product 2>/dev/null | grep -c 'QEMU USB Keyboard')",
            "usb-2-1-2-1-0-2",
            10,
        )?;
        con.run("head -c 20 /dev/sda1; echo", "hello from the stick", 10)?;
        con.run("cat /sys/block/sda/removable /sys/block/sda/device/model", "QEMU QEMU HARDDISK", 10)?;
        con.run("echo written-by-slate > /dev/sda2; sync; echo ok$((1+1))", "ok2", 10)?;
        // Unplugged: the disk and its partitions leave /dev and /proc.
        monitor(&mon, &["device_del stickdev"])?;
        con.run(
            "for i in $(seq 100); do [ ! -e /dev/sda ] && break; sleep 0.1; done; \
             echo unplugged-$(ls /dev | grep -c '^sda')-$(grep -c sda /proc/partitions)",
            "unplugged-0-0",
            20,
        )?;
        // And /sys and lsusb (the hub and keyboard stay).
        con.run("echo gone-$(ls /sys/bus/usb/devices | grep -c '^2-2')-$(lsusb | wc -l)", "gone-0-5", 10)?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("usb-scenario.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("USB scenario: {e} (transcript in target/usb-scenario.log)"));
    }
    let data = std::fs::read(&stick).map_err(|e| e.to_string())?;
    if &data[PART2 as usize..PART2 as usize + 17] != b"written-by-slate\n" {
        return Err("USB scenario: the guest's write is not on the stick image".into());
    }
    println!(
        "xtask: USB scenario passed (xHCI, hub with its status-change endpoint, keyboard, a mouse plugged into \
         the hub and out, mass storage, a stick powered off, unplugged; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The machine of the install scenario, shaped like the reference PC
/// (ADR 0029): no virtio, an empty SATA disk, an Intel igb card behind a
/// PCIe port, a USB keyboard, and (when given) the ISO on a USB stick
/// that the firmware boots.
pub(crate) fn reference_pc(
    o: &Opts,
    disk: &Path,
    iso: Option<&Path>,
    mon: &Path,
    ssh_port: Option<u16>,
) -> Result<Command> {
    // Booting the install medium starts with fresh UEFI variables; the
    // installed system's boots keep them, with the boot entry the
    // installer made (ADR 0088).
    let mut c = machine_vars(o, "q35", &disk.with_extension("vars.fd"), iso.is_some())?;
    c.args(["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd,bus=xhci.0"]);
    if let Some(iso) = iso {
        c.arg("-drive").arg(format!("file={},format=raw,if=none,id=stick,readonly=on", iso.display()));
        c.args(["-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=0"]);
    }
    c.arg("-drive").arg(format!("file={},format=raw,if=none,id=sata", disk.display()));
    c.args(["-device", "ide-hd,drive=sata,bus=ide.0,bootindex=1"]);
    let fwd = ssh_port.map_or(String::new(), |p| format!(",hostfwd=tcp:127.0.0.1:{p}-:22"));
    c.args(["-netdev", &format!("user,id=n0{fwd}"), "-device", "pcie-root-port,id=rp0,chassis=1,slot=1"]);
    c.args(["-device", "igb,netdev=n0,bus=rp0"]);
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    Ok(c)
}

/// A TCP port on the host that is free right now.
fn free_port() -> Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    Ok(l.local_addr().map_err(|e| e.to_string())?.port())
}

/// The host's OpenSSH client against slate-sshd on the installed system
/// (ADR 0030): password login with the password the installer set, a key
/// installed through that session, key login, exit status, and stdin.
/// The first account's password in the install scenario.
pub(crate) const INSTALL_PASSWORD: &str = "slate-pw";
/// The graphical scenario's: it types on the German layout (ADR 0117),
/// so its keys are where they are on the US one.
const GRAPHICAL_PASSWORD: &str = "slatepw7";
/// What the first account's password becomes (passwd, in the install
/// scenario).
const NEW_PASSWORD: &str = "slate-pw-2";
/// The password root sets for ada afterwards (ADR 0058).
const RESET_PASSWORD: &str = "Reset-pw-7";

/// Log in over ssh as `user` with `password`, install a key, and use it.
fn ssh_checks(port: u16, user: &str, password: &str) -> Result {
    let account_password = password.to_string();
    let dir = target_dir().join("ssh-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = dir.join("id");
    run_cmd(Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", ""]).arg("-f").arg(&key))?;
    let askpass = dir.join("askpass");
    std::fs::write(&askpass, format!("#!/bin/sh\necho {password}\n")).map_err(|e| e.to_string())?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let ssh = |extra: &[&str], cmd: &str, stdin: Option<&Path>| -> Result<(i32, String)> {
        let mut c = Command::new("timeout");
        c.args(["30", "ssh", "-F", "/dev/null", "-p", &port.to_string()]);
        c.args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]);
        c.args(extra).arg(format!("{user}@127.0.0.1"));
        if !cmd.is_empty() {
            c.arg(cmd);
        }
        c.env("SSH_ASKPASS", &askpass).env("SSH_ASKPASS_REQUIRE", "force").env("DISPLAY", ":0");
        c.stdin(match stdin {
            Some(p) => Stdio::from(std::fs::File::open(p).map_err(|e| e.to_string())?),
            None => Stdio::null(),
        });
        let out = c.output().map_err(|e| format!("ssh: {e}"))?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    };
    let password = ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password"];
    // The installed system's network may still be coming up: retry.
    let mut last = String::new();
    let mut ok = false;
    for _ in 0..20 {
        let (rc, out) = ssh(&password, "echo pw-$((40+2)); uname -s", None)?;
        if rc == 0 && out.contains("pw-42") && out.contains("Slate") {
            ok = true;
            break;
        }
        last = out;
        std::thread::sleep(Duration::from_millis(500));
    }
    if !ok {
        return Err(format!("ssh with the password failed: {last}"));
    }
    let pubkey = key.with_extension("pub");
    let (rc, out) = ssh(
        &password,
        "mkdir -p ~/.ssh && cat > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",
        Some(&pubkey),
    )?;
    if rc != 0 {
        return Err(format!("installing the key over ssh failed ({rc}): {out}"));
    }
    let with_key = ["-i", key.to_str().unwrap_or(""), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"];
    let (rc, out) = ssh(&with_key, "echo key-$((1+1)); echo to-stderr >&2; exit 7", None)?;
    if rc != 7 || !out.contains("key-2") || !out.contains("to-stderr") {
        return Err(format!("ssh with the key: status {rc}, output {out:?}"));
    }
    // The session has the account's groups: the first account is in wheel
    // (10, ADR 0035; the reference PC's install got only its own group over SSH).
    let (rc, out) = ssh(&with_key, "echo groups-$(id -G | tr ' ' '\\n' | grep -cx 10)", None)?;
    if rc != 0 || !out.contains("groups-1") {
        return Err(format!("the ssh session is not in wheel: status {rc}, output {out:?}"));
    }
    // An interactive session on a pseudo-terminal.
    let script = dir.join("typed");
    // Its login is recorded (by the monitor, for the session process).
    std::fs::write(&script, "tty\necho pty-$((2+3))\necho who-$(who -m | grep -c pts/)\nexit 4\n")
        .map_err(|e| e.to_string())?;
    let tty = [&with_key[..], &["-tt"]].concat();
    let (rc, out) = ssh(&tty, "", Some(&script))?;
    if rc != 4 || !out.contains("pty-5") || !out.contains("/dev/pts/") || !out.contains("who-1") {
        return Err(format!("interactive ssh: status {rc}, output {out:?}"));
    }
    // After authentication the session runs in sshd-session with the
    // account's IDs: no process of root's handles what the client sends.
    let (rc, out) = ssh(&with_key, "ps -eo user,args | grep '[s]shd-session' | head -1", None)?;
    if rc != 0 || out.split_whitespace().collect::<Vec<_>>() != [user, "sshd-session"] {
        return Err(format!("the session process: status {rc}, {out:?}"));
    }
    // Privilege separation (ADR 0061): a connection that has not logged
    // in is handled by sshd-preauth as the sshd user.
    {
        use std::io::Read;
        let mut idle = std::net::TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
        idle.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
        let mut hello = [0u8; 64];
        let n = idle.read(&mut hello).map_err(|e| format!("reading the server's version: {e}"))?;
        if !hello[..n].starts_with(b"SSH-2.0-") {
            return Err(format!("no SSH version line: {:?}", String::from_utf8_lossy(&hello[..n])));
        }
        // Other users' processes are hidden: ask as root (ADR 0058's sudo).
        let ps =
            format!("echo {account_password} | sudo -S ps -eo user,args 2>/dev/null | grep '[s]shd-preauth' | head -1");
        let (rc, out) = ssh(&with_key, &ps, None)?;
        if rc != 0 || out.split_whitespace().collect::<Vec<_>>() != ["sshd", "sshd-preauth"] {
            return Err(format!("the pre-authentication process: status {rc}, {out:?}"));
        }
    }
    // Files both ways with OpenSSH's scp and sftp (M21 phase 5, ADR 0061).
    let payload = dir.join("payload");
    let data: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 11) as u8).collect();
    std::fs::write(&payload, &data).map_err(|e| e.to_string())?;
    let copy = |tool: &str, args: &[String]| -> Result<(i32, String)> {
        let mut c = Command::new("timeout");
        c.args(["60", tool, "-q", "-F", "/dev/null", "-P", &port.to_string()]);
        c.args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"]);
        c.args(with_key).args(args).stdin(Stdio::null());
        let out = c.output().map_err(|e| format!("{tool}: {e}"))?;
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        Ok((out.status.code().unwrap_or(-1), text))
    };
    let back = dir.join("back");
    let (rc, out) = copy("scp", &[payload.display().to_string(), format!("{user}@127.0.0.1:copied.bin")])?;
    if rc != 0 {
        return Err(format!("scp to Slate: status {rc}: {out}"));
    }
    let batch = dir.join("batch");
    std::fs::write(&batch, format!("get copied.bin {}\nrename copied.bin kept.bin\nls\n", back.display()))
        .map_err(|e| e.to_string())?;
    let (rc, out) = copy("sftp", &["-b".into(), batch.display().to_string(), format!("{user}@127.0.0.1")])?;
    if rc != 0 || !out.contains("kept.bin") || std::fs::read(&back).ok().as_deref() != Some(data.as_slice()) {
        return Err(format!("sftp from Slate: status {rc}: {out}"));
    }
    let (rc, out) = ssh(&with_key, "wc -c < kept.bin", None)?;
    if rc != 0 || out.trim() != "300000" {
        return Err(format!("the copied file on Slate: status {rc}: {out}"));
    }
    // A wrong password is refused.
    std::fs::write(&askpass, "#!/bin/sh\necho wrong\n").map_err(|e| e.to_string())?;
    let (rc, _) = ssh(&[&password[..], &["-o", "NumberOfPasswordPrompts=1"]].concat(), "true", None)?;
    if rc == 0 {
        return Err("ssh accepted a wrong password".into());
    }
    Ok(())
}

/// The byte offset of the partition named `label` in a GPT disk image.
/// The GPT entries of a disk image.
pub(crate) fn disk_partitions(img: &Path) -> Result<Vec<slate_gpt::Entry>> {
    let mut f = std::fs::File::open(img).map_err(|e| e.to_string())?;
    let mut header = [0u8; 512];
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(512)).map_err(|e| e.to_string())?;
    f.read_exact(&mut header).map_err(|e| e.to_string())?;
    let h = slate_gpt::parse_header(&header).map_err(|e| format!("{}: no GPT ({e:?})", img.display()))?;
    let mut array = vec![0u8; h.entry_count as usize * h.entry_size as usize];
    f.seek(std::io::SeekFrom::Start(h.entries_lba * 512)).map_err(|e| e.to_string())?;
    f.read_exact(&mut array).map_err(|e| e.to_string())?;
    Ok(slate_gpt::parse_entries(&h, &array).map_err(|e| format!("{e:?}"))?.collect())
}

pub(crate) fn partition_offset(img: &Path, label: &str) -> Result<u64> {
    disk_partitions(img)?
        .iter()
        .find(|e| String::from_utf16_lossy(&e.name_utf16).trim_end_matches('\0') == label)
        .map(|e| e.first_lba * 512)
        .ok_or_else(|| format!("{}: no partition {label:?}", img.display()))
}

/// Unlock the encrypted root at boot on the USB keyboard (ADR 0036, the
/// unlock screen of ADR 0038). The
/// keyboard may come up just after the prompt and lose the first keys, so
/// a refused password is typed again.
fn unlock_root(con: &mut Console, mon: &Path, password: &str) -> Result {
    con.wait_for("Password to unlock /dev/sda2: ", 60)?;
    for _ in 0..3 {
        type_keys(mon, &format!("{password}\n"))?;
        if con.wait_for_any(&["unlocked as /dev/dm-0", "does not unlock the disk"], 20)? == 0 {
            return Ok(());
        }
        con.wait_for("Password to unlock /dev/sda2: ", 10)?;
    }
    Err("the password never unlocked the disk".into())
}

/// The graphical installer on the install media (ADR 0034), driven as a
/// person would: the USB keyboard and a USB mouse through QEMU's monitor.
/// It comes up on the firmware's framebuffer; Esc asks before quitting;
/// the language list chooses UK English; a click goes on; the keyboard
/// answers the rest: Berlin's time zone and the German layout (ADR 0117),
/// an old partition deleted for SlateOS's 20 GB (ADR 0116); it installs,
/// encrypted, and restarts. The installed system then unlocks with the
/// password, logs in as the new user and has the German layout with its
/// dead keys, Berlin's time and the computer's name; the host checks its
/// disk.
/// The ISO boots to the installer (ADR 0039): as a CD, through El
/// Torito's BIOS or UEFI entry, and written to a USB stick, through the
/// MBR's EFI partition or Limine's BIOS stages.
fn media_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let iso = crate::iso::build(o)?;
    for how in ["cd", "stick"] {
        let mut c = machine(o)?;
        let drive =
            |id: &str, extra: &str| format!("file={},format=raw,if=none,id={id},readonly=on{extra}", iso.display());
        if how == "cd" {
            c.arg("-drive").arg(drive("cd", ",media=cdrom"));
            c.args(["-device", "ide-cd,drive=cd,bus=ide.0,bootindex=0"]);
        } else {
            c.args(["-device", "qemu-xhci,id=xhci"]);
            c.arg("-drive").arg(drive("stick", ""));
            c.args(["-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=0"]);
        }
        c.args(["-display", "none", "-serial", "stdio", "-monitor", "none"]);
        let mut con = Console::start(c)?;
        let r = con.wait_for("slate-install-gui: ", 120);
        let _ = std::fs::write(target_dir().join(format!("media-{how}.log")), strip_ansi(&con.log));
        con.kill();
        r.map_err(|e| format!("media scenario: the ISO as a {how}: {e} (transcript in target/media-{how}.log)"))?;
    }
    // The release USB image, as it goes onto sticks: the release kernel
    // is built differently (optimised, so functions may be folded: the
    // KCFI panic the reference PC found, 2026-10-24), and nothing else boots it.
    // Its menu waits for a choice: Enter takes the first.
    if !o.release {
        let release = Opts { release: true, ..o.clone() };
        let stick = crate::iso::usb_copy(&release, false, &target_dir().join("media-release-stick.img"))?;
        let mon = target_dir().join("media-monitor.sock");
        let _ = std::fs::remove_file(&mon);
        let mut c = machine(o)?;
        c.args(["-device", "qemu-xhci,id=xhci"]);
        c.arg("-drive").arg(format!("file={},format=raw,if=none,id=stick", stick.display()));
        c.args(["-device", "usb-storage,bus=xhci.0,drive=stick,bootindex=0"]);
        c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
        c.arg(format!("unix:{},server,nowait", mon.display()));
        let mut con = Console::start(c)?;
        std::thread::sleep(Duration::from_secs(8));
        let r = monitor(&mon, &["sendkey ret"]).and_then(|()| con.wait_for("slate-install-gui: ", 120));
        let _ = std::fs::write(target_dir().join("media-release.log"), strip_ansi(&con.log));
        con.kill();
        r.map_err(|e| format!("media scenario: the release USB image: {e} (transcript in target/media-release.log)"))?;
    }
    let fw = if o.bios { "BIOS" } else { "UEFI" };
    let release = if o.release { "" } else { ", and the release USB image" };
    println!(
        "xtask: media scenario passed ({fw}: the ISO as a CD and as a USB stick{release}, {:.0}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn graphical_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    let stick = crate::iso::usb_copy(o, false, &target_dir().join("graphical-stick.img"))?;
    let disk = target_dir().join("graphical-target.img");
    let _ = std::fs::remove_file(&disk);
    std::fs::File::create(&disk).and_then(|f| f.set_len(64 << 30)).map_err(|e| e.to_string())?;
    // An old partition on it, which manual partitioning deletes (ADR 0116).
    {
        use std::os::unix::fs::FileExt;
        let old = slate_gpt::Partition {
            type_guid: slate_gpt::Guid::BASIC_DATA,
            unique_guid: crate::image::guid_for("graphical-old"),
            first_lba: 2048,
            last_lba: (4 << 21) + 2047,
            attributes: 0,
            name: "old data",
        };
        let gpt = slate_gpt::encode((64 << 30) / 512, crate::image::guid_for("graphical-disk"), &[old])
            .map_err(|e| format!("{e:?}"))?;
        let f = std::fs::OpenOptions::new().write(true).open(&disk).map_err(|e| e.to_string())?;
        let w = |at: u64, b: &[u8]| f.write_all_at(b, at).map_err(|e| e.to_string());
        w(0, &gpt.protective_mbr)?;
        w(512, &gpt.primary_header)?;
        w(1024, &gpt.entries)?;
        w(gpt.backup_entries_lba * 512, &gpt.entries)?;
        w(gpt.backup_header_lba * 512, &gpt.backup_header)?;
    }
    let mon = target_dir().join("graphical-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut cmd = reference_pc(o, &disk, Some(&stick), &mon, None)?;
    cmd.args(["-device", "usb-mouse,bus=xhci.0"]);
    let mut con = Console::start(cmd)?;
    // The window's colour (style guide §2) at a screen point.
    let window_at = |shot: &Path, x: usize, y: usize| ppm_pixel(shot, x, y).map(|p| p == [0xF3, 0xF2, 0xF2]);
    let pause = |ms: u64| std::thread::sleep(Duration::from_millis(ms));
    let result = (|| -> Result {
        con.wait_for("slate-install-gui: ", 90)?;
        con.wait_for(" at scale ", 5)?;
        pause(1500);
        let shot = screendump(&mon, "graphical-welcome.ppm")?;
        let desk = ppm_pixel(&shot, 4, 4)?;
        if desk != [0xDC, 0xDB, 0xDB] || !window_at(&shot, 640, 400)? {
            return Err(format!("the installer is not on the screen (desktop {desk:02x?})"));
        }
        // Esc asks; Enter keeps installing.
        monitor(&mon, &["sendkey esc"])?;
        pause(600);
        let quit = screendump(&mon, "graphical-quit.ppm")?;
        // The quit screen has no language menu where Welcome has one.
        if !window_at(&quit, 500, 505)? {
            return Err("Esc did not ask about quitting".into());
        }
        monitor(&mon, &["sendkey ret"])?;
        pause(600);
        // The language: Tab to the menu, open it, choose UK, close it.
        monitor(&mon, &["sendkey tab", "sendkey down", "sendkey down", "sendkey ret"])?;
        pause(600);
        screendump(&mon, "graphical-language.ppm")?;
        // A click on "Install SlateOS" (1280 x 800 at scale 1: the window
        // at 210, 120; the button's middle at 974, 644). The pointer starts
        // in the middle of the screen.
        let mouse = mouse_index(&mon, "HID Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}"), "mouse_move 334 244"])?;
        pause(300);
        monitor(&mon, &["mouse_button 1", "mouse_button 0"])?;
        pause(800);
        let shot = screendump(&mon, "graphical-region.ppm")?;
        // The Region screen: the sidebar's colour where Welcome had window.
        if ppm_pixel(&shot, 300, 600)? != [0xEE, 0xED, 0xED] {
            return Err("the click did not go on to the Region screen".into());
        }
        // Berlin's time, and the German layout, apart from the language
        // (ADR 0117): from here on the keys type German.
        type_keys(&mon, "berlin")?;
        monitor(&mon, &["sendkey tab", "sendkey tab"])?;
        type_keys(&mon, "german")?;
        pause(300);
        screendump(&mon, "graphical-region-chosen.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        screendump(&mon, "graphical-disk.ppm")?;
        // Disk (sda, encrypted by default); the disk has a partition:
        // choose partitions yourself, delete it, and give SlateOS 20 GB
        // of the free space (ADR 0116).
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        screendump(&mon, "graphical-way.ppm")?;
        monitor(&mon, &["sendkey down", "sendkey down", "sendkey ret"])?;
        pause(500);
        monitor(&mon, &["sendkey up", "sendkey delete", "sendkey tab"])?;
        type_keys(&mon, "20")?;
        pause(300);
        screendump(&mon, "graphical-partitions.ppm")?;
        // Mode (Slate mode), Desktop (Strata), Network (DHCP): Enter four
        // times.
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        screendump(&mon, "graphical-mode.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        screendump(&mon, "graphical-desktop.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        screendump(&mon, "graphical-network.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        pause(500);
        type_keys(&mon, "Ada Lovelace")?;
        monitor(&mon, &["sendkey tab", "sendkey tab", "sendkey tab"])?;
        type_keys(&mon, GRAPHICAL_PASSWORD)?;
        monitor(&mon, &["sendkey tab"])?;
        type_keys(&mon, GRAPHICAL_PASSWORD)?;
        pause(300);
        screendump(&mon, "graphical-account.ppm")?;
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("slate-install-gui: installed on sda", 300)?;
        pause(800);
        let done = screendump(&mon, "graphical-done.ppm")?;
        if !window_at(&done, 640, 400)? {
            return Err("no Done screen".into());
        }
        // "Restart now".
        monitor(&mon, &["sendkey ret"])?;
        con.wait_exit(60).map(|_| ())
    })();
    let _ = std::fs::write(target_dir().join("graphical.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("graphical installer scenario (installing): {e}"));
    }
    let installed = started.elapsed().as_secs_f64();
    // The old partition went; SlateOS's ESP and its 20 GB root came.
    let parts = disk_partitions(&disk)?;
    let mib = |lba: u64| lba / 2048;
    let shape: Vec<(u32, u64, u64)> =
        parts.iter().map(|e| (e.index + 1, mib(e.first_lba), mib(e.last_lba + 1 - e.first_lba))).collect();
    if shape != [(1, 1, 512), (2, 513, 19_073)] || parts[0].type_guid != slate_gpt::Guid::EFI_SYSTEM {
        return Err(format!("graphical installer scenario: the disk's partitions are {shape:?} (number, MiB at, MiB)"));
    }
    let root = partition_offset(&disk, "slate-root")?;
    crate::slatefsimg::fsck_with(&disk, root, "graphically installed root", Some(GRAPHICAL_PASSWORD))?;

    // The installed system.
    let _ = std::fs::remove_file(&mon);
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, None)?)?;
    let result = (|| -> Result {
        // The unlock screen (ADR 0038, ADR 0124): its password field
        // (`well`) in the column at the left.
        con.wait_for("slate-unlock: asking for the password of /dev/sda2 on the screen", 60)?;
        std::thread::sleep(Duration::from_millis(800));
        let shot = screendump(&mon, "graphical-unlock.ppm")?;
        if ppm_pixel(&shot, 300, 428)? != [0x16, 0x16, 0x15] {
            return Err("no unlock screen".into());
        }
        unlock_root(&mut con, &mon, GRAPHICAL_PASSWORD)?;
        // The login screen (ADR 0038): a wrong password, then the right
        // one, typed on the screen for its only person.
        con.wait_for("strata-login: showing the login screen (1 to choose from)", 90)?;
        std::thread::sleep(Duration::from_millis(1000));
        let shot = screendump(&mon, "graphical-login.ppm")?;
        // Inside the password field, under the people (scenes: login-one).
        if ppm_pixel(&shot, 300, 560)? != [0x16, 0x16, 0x15] {
            return Err("no login screen".into());
        }
        type_keys(&mon, "nope\n")?;
        con.wait_for("strata-login: ada: Login incorrect", 20)?;
        type_keys(&mon, &format!("{GRAPHICAL_PASSWORD}\n"))?;
        con.wait_for("strata-login: session for ada", 20)?;
        // Strata starts in the session, for a user who is not root:
        // through seatd (ADR 0037).
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        std::thread::sleep(Duration::from_millis(1500));
        let shot = screendump(&mon, "graphical-strata.ppm")?;
        if ppm_pixel(&shot, 640, 300)? != [0x12, 0x12, 0x11] {
            return Err("Strata did not start at the login".into());
        }
        // Log out: back to the login screen. Then a login typed on the
        // console (the serial line), which it takes too.
        monitor(&mon, &["sendkey meta_l-spc"])?;
        std::thread::sleep(Duration::from_millis(500));
        type_keys(&mon, "log\n")?;
        con.wait_for("strata: leaving", 10)?;
        con.wait_for("strata-login: showing the login screen", 30)?;
        // Again, and super + shift + e: from the login screen that ends the
        // session too, with no console shell left behind (ADR 0039).
        std::thread::sleep(Duration::from_millis(1000));
        type_keys(&mon, &format!("{GRAPHICAL_PASSWORD}\n"))?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        std::thread::sleep(Duration::from_millis(1000));
        monitor(&mon, &["sendkey meta_l-shift-e"])?;
        con.wait_for("strata: leaving", 10)?;
        con.wait_for("strata-login: showing the login screen", 30)?;
        con.wait_for("login: ", 10)?;
        con.send("ada\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{GRAPHICAL_PASSWORD}\r"))?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        std::thread::sleep(Duration::from_millis(1000));
        // super + shift + e: back to the console's shell.
        monitor(&mon, &["sendkey meta_l-shift-e"])?;
        con.wait_for("strata: leaving", 10)?;
        con.wait_for("ada@slate:~$ ", 15)?;
        con.send(
            "echo $(id -un)-$(id -Gn | tr ' ' ,)-$(hostname)-$(cat /etc/slate/keyboard)-$(grep -c LANG=en_GB \
             /etc/locale.conf)-$(cat /etc/slate/timezone)\r",
        )?;
        con.wait_for("ada-ada,wheel,seat-ada-slate-de-1-Europe/Berlin", 10)?;
        // Local time: Berlin's (CET or CEST, ADR 0117).
        con.send("date +%Z | sed 's/.*/[&]/'\r")?;
        con.wait_for_any(&["[CET]", "[CEST]"], 10)?;
        // The console types with the installed layout (de): the dead acute
        // then e is é, AltGr q is @, the dead circumflex then Space is ^,
        // Shift and the 102nd key is > (ADR 0117).
        let keys = [
            "e",
            "c",
            "h",
            "o",
            "spc",
            "equal",
            "e",
            "alt_r-q",
            "grave_accent",
            "spc",
            "spc",
            "shift-less",
            "spc",
            "k",
            "ret",
        ];
        let keys: Vec<String> = keys.iter().map(|k| format!("sendkey {k}")).collect();
        monitor(&mon, &keys.iter().map(String::as_str).collect::<Vec<_>>())?;
        con.wait_for("ada@slate:~$ ", 10)?;
        con.send("sed s/^/got:/ k\r")?;
        con.wait_for("got:é@^", 10)?;
        // Everyone may write /tmp (it once came up as 0755).
        con.send("echo hi > /tmp/ada-was-here && echo tmp$((1+1))\r")?;
        con.wait_for("tmp2", 10)?;
        con.send("su -\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{GRAPHICAL_PASSWORD}\r"))?;
        con.wait_for(PROMPT, 15)?;
        con.wait_for("# ", 5)?;
        con.run("slate-compat status", "Linux compatibility mode is off", 10)?;
        // Back to ada, out, and in again on the console: Strata starts,
        // and its power dialog shuts the computer down. ada is no root:
        // the broker grants it to the session's own Strata (ADR 0110).
        con.send("exit\r")?;
        con.wait_for("ada@slate:~$ ", 10)?;
        con.send("exit\r")?;
        con.wait_for("login: ", 20)?;
        con.send("ada\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{GRAPHICAL_PASSWORD}\r"))?;
        con.wait_for("strata: 1280x800 at scale 1", 30)?;
        std::thread::sleep(Duration::from_millis(1000));
        // The installed system's machine has the PS/2 mouse only.
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}")])?;
        // To the top right corner in steps (PS/2 packets carry ±255).
        monitor(&mon, &["mouse_move 300 -300"; 8])?;
        std::thread::sleep(Duration::from_millis(200));
        monitor(&mon, &["mouse_move -20 14", "mouse_button 1", "mouse_button 0"])?;
        con.wait_for("strata: the power dialog", 10)?;
        std::thread::sleep(Duration::from_millis(400));
        monitor(&mon, &["sendkey ret"])?;
        con.wait_for("strata: power: poweroff", 10)?;
        con.wait_exit(60).map(|_| ())
    })();
    let _ = std::fs::write(target_dir().join("graphical-installed.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("graphical installer scenario (installed system): {e}"));
    }
    crate::slatefsimg::fsck_with(&disk, root, "graphically installed root after use", Some(GRAPHICAL_PASSWORD))?;
    println!(
        "xtask: graphical installer scenario passed (framebuffer, USB keyboard and mouse, UK English, encrypted \
         install with Strata in {installed:.1}s, the unlock and login screens, log out, leaving with nothing behind, Berlin's time zone, a console login typing \
         with the German layout, its dead keys and AltGr, su, shutting down from Strata's power dialog; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The whole install, as a person would do it on the reference PC: boot
/// the install image from a USB stick, answer the installer on the USB keyboard,
/// restart from the SATA disk, log in with the new password, and use the
/// network over the igb card; then check the disk on the host.
fn install_scenario(o: &Opts) -> Result {
    let started = Instant::now();
    // The USB disk image: what goes on a stick (guides/INSTALL.md), with the
    // text installer as the menu's default (ADR 0034).
    // On a 15 GiB stick, as real ones are: big enough to be offered unless
    // the installer recognises its own medium.
    let iso = crate::iso::usb_copy(o, true, &target_dir().join("install-stick.img"))?;
    std::fs::OpenOptions::new().write(true).open(&iso).and_then(|f| f.set_len(15 << 30)).map_err(|e| e.to_string())?;
    let disk = target_dir().join("install-target.img");
    let _ = std::fs::remove_file(&disk);
    // 256 GiB (sparse), the reference PC's SSD size: big file systems once
    // needed more than the kernel heap's largest block at mount.
    std::fs::File::create(&disk).and_then(|f| f.set_len(256 << 30)).map_err(|e| e.to_string())?;
    let mon = target_dir().join("install-monitor.sock");
    let _ = std::fs::remove_file(&mon);

    let mut con = Console::start(reference_pc(o, &disk, Some(&iso), &mon, None)?)?;
    let typed = (|| -> Result {
        con.wait_for("Install on which disk? [1]: ", 90)?;
        // The USB keyboard may still be coming up: press 'r' (look for
        // disks again) until the list is shown anew. By then the stick is
        // there too, and must not be offered.
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
        let screen = strip_ansi(&con.log);
        let last = &screen[screen.rfind("Disks:").unwrap_or(0)..];
        if last.contains("2) sdb") || !last.contains("1) sda") {
            return Err(format!("the installer offered the wrong disks: {last}"));
        }
        type_keys(&mon, "\n")?;
        con.wait_for("or press Enter to go back: ", 10)?;
        type_keys(&mon, "erase\n")?;
        // The layout (US, the first), then a time zone found by its
        // country's name (ADR 0117), offered the layout's country's first
        // (ADR 0151).
        con.wait_for("Which layout? [1]: ", 20)?;
        type_keys(&mon, "\n")?;
        con.wait_for("Time zone [America/New_York]: ", 20)?;
        type_keys(&mon, "india\n")?;
        // The first account; root gets no password (ADR 0035).
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
        // The default: Slate mode only (ADR 0032).
        // The default: an encrypted disk (ADR 0036).
        con.wait_for("Encrypt the disk? [Y/n]: ", 20)?;
        type_keys(&mon, "\n")?;
        // The command line only, without Strata (ADR 0037).
        con.wait_for("Install the Strata desktop? [Y/n]: ", 20)?;
        type_keys(&mon, "n\n")?;
        con.wait_for("Turn on Linux compatibility mode? [y/N]: ", 20)?;
        type_keys(&mon, "\n")?;
        // A fixed address (ADR 0054), the one QEMU's network would give.
        con.wait_for("Use a fixed address? [y/N]: ", 20)?;
        type_keys(&mon, "y\n")?;
        con.wait_for("(like 192.168.1.20/24): ", 20)?;
        type_keys(&mon, "10.0.2.15/24\n")?;
        con.wait_for("Gateway (Enter for none): ", 20)?;
        type_keys(&mon, "10.0.2.2\n")?;
        con.wait_for("(Enter for none): ", 20)?;
        type_keys(&mon, "10.0.2.3\n")?;
        con.wait_for("Remove the USB stick, then press Enter to restart.", 300)?;
        type_keys(&mon, "\n")?;
        con.wait_exit(60).map(|_| ())
    })();
    // The transcripts stay in target/ for a look at the screens.
    let _ = std::fs::write(target_dir().join("install-live.log"), strip_ansi(&con.log));
    if let Err(e) = typed {
        con.kill();
        return Err(format!("install scenario (installing): {e}"));
    }
    let root = partition_offset(&disk, "slate-root")?;
    crate::slatefsimg::fsck_with(&disk, root, "installed root", Some(INSTALL_PASSWORD))?;
    if crate::slatefsimg::fsck(&disk, root, "installed root without its password").is_ok() {
        return Err("install scenario: the installed root is not encrypted".into());
    }
    // Damage the encryption header's first copy (a key slot's bytes): the
    // boot must read its second copy (ADR 0039).
    {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().read(true).write(true).open(&disk).map_err(|e| e.to_string())?;
        let mut b = [0u8; 1];
        f.read_exact_at(&mut b, root + 200).map_err(|e| e.to_string())?;
        f.write_all_at(&[b[0] ^ 0xFF], root + 200).map_err(|e| e.to_string())?;
    }
    let installed = started.elapsed().as_secs_f64();

    // The installed system, without the stick.
    let repos = crate::hostnet::StaticServer::start(target_dir().join("quarry/www"))?;
    let _ = std::fs::remove_file(&mon);
    let ssh_port = free_port()?;
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, Some(ssh_port))?)?;
    let result = (|| -> Result {
        // The encrypted root asks for its password on the unlock screen
        // (ADR 0038), typed on the USB keyboard once it is up (it comes
        // up during boot): a wrong one first.
        con.wait_for("Password to unlock /dev/sda2: ", 60)?;
        std::thread::sleep(Duration::from_millis(1500));
        type_keys(&mon, "wrong\n")?;
        con.wait_for("That password does not unlock the disk.", 20)?;
        con.wait_for("Password to unlock /dev/sda2: ", 10)?;
        type_keys(&mon, &format!("{INSTALL_PASSWORD}\n"))?;
        con.wait_for("unlocked as /dev/dm-0", 20)?;
        con.wait_for("Network address: 10.0.2.15", 90)?;
        con.wait_for("login: ", 30)?;
        ssh_checks(ssh_port, "ada", INSTALL_PASSWORD)?;
        // Root has no password: logging in as root fails, and the first
        // user becomes root with su and their own password (ADR 0035).
        con.send("root\r")?;
        con.wait_for("Password: ", 15)?;
        con.send("anything\r")?;
        con.wait_for("Login incorrect", 15)?;
        con.wait_for("login: ", 15)?;
        con.send("ada\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{INSTALL_PASSWORD}\r"))?;
        con.wait_for("ada@slate:~$ ", 15)?;
        con.send("echo $(id -un)-$(hostname)-$(cat /etc/slate/keyboard)-$(cat /etc/slate/timezone)\r")?;
        con.wait_for("ada-ada-slate-us-Asia/Kolkata", 10)?;
        con.send("date +%Z | sed 's/.*/[&]/'\r")?;
        con.wait_for("[IST]", 10)?;
        con.send("su -\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{INSTALL_PASSWORD}\r"))?;
        con.wait_for(PROMPT, 15)?;
        con.wait_for("# ", 5)?;
        con.run("grep -c '^root:!:' /etc/shadow", "1", 10)?;
        con.run("echo strata-$(ls /bin | grep -c '^strata$')-$(ls /etc/slate | grep -c session)", "strata-0-0", 10)?;
        con.run("grep -o 'root=PARTUUID=[0-9a-f-]*' /proc/cmdline", "root=PARTUUID=", 10)?;
        // The unlock stage (ADR 0038) left no mounts behind, and init is
        // still pid 1.
        con.run(
            "echo mnt-$(grep -c ' / ' /proc/mounts)-$(grep -c '^/dev/dm-0 / ' /proc/mounts)-$(grep -c unlock \
             /proc/mounts)-$(readlink /proc/1/exe | grep -c slinit)",
            "mnt-1-1-0-1",
            10,
        )?;
        con.run("echo log$(grep -c 'kernel: boot: ' /var/log/install.log)", "log1", 10)?;
        // slate-loader booted it (ADR 0089), and on UEFI the installer's
        // boot entry (ADR 0088) is what the firmware booted.
        con.run("grep '^loader:' /proc/slate_boot", "loader: Slate", 10)?;
        // The system image and the disk under the root refuse root (ADR
        // 0090), on an encrypted root on a real disk; the encrypted
        // partition takes writes to its header only (the key slots, which
        // passwd changes below).
        con.run(
            "echo img-$(touch /usr/slate-was-here 2>/dev/null && echo yes || echo no)-disk-$(sh -c ': >> /dev/sda' \
             2>/dev/null && echo yes || echo no)-map-$(sh -c ': >> /dev/dm-0' 2>/dev/null && echo yes || echo no)-data-$(\
             printf x | dd of=/dev/sda2 bs=512 seek=4096 conv=notrunc 2>/dev/null && echo yes || echo no)",
            "img-no-disk-no-map-no-data-no",
            10,
        )?;
        if !o.bios {
            con.run(
                "c=$(slate-boot list | grep '^BootCurrent' | cut -c14-17); echo entry-$(slate-boot list | grep \"^Boot$c \" \
                 | grep -c ' Slate ')-first-$(slate-boot list | grep -c \"^BootOrder    $c\")",
                "entry-1-first-1",
                10,
            )?;
        }
        // /var/tmp, in the var subvolume (the reference PC's first install had none).
        con.run("echo vartmp-$(ls -ld /var/tmp | cut -c1-10)", "vartmp-drwxrwxrwt", 10)?;
        con.run("echo inst$(ls /bin | grep -c slate-install)", "inst0", 10)?;
        // netd runs the fixed address the installer wrote.
        con.run(
            "for i in $(seq 100); do grep -q 'eth0 up static 10.0.2.15/24 via 10.0.2.2 dns 10.0.2.3' \
             /run/netd/status && break; sleep 0.2; done; grep -c 'method = static' /etc/slate/network",
            "1",
            30,
        )?;
        con.run("slate-compat status", "Linux compatibility mode is off", 10)?;
        // slinit runs the privilege broker (ADR 0032): one, once the child
        // that answered su a moment ago has gone (ADR 0039).
        con.run(
            "n() { cat /proc/*/status 2>/dev/null | grep -c 'Name:.slate-brokerd'; }; for i in $(seq 20); do \
             [ $(n) = 1 ] && break; sleep 0.1; done; echo broker$(n)",
            "broker1",
            10,
        )?;
        // ... and devd, whose database marks the keyboard (ADR 0033).
        con.run(
            "for i in $(seq 50); do cat /run/udev/data/c13:* 2>/dev/null | grep -q ID_INPUT_KEYBOARD=1 && break; \
             sleep 0.1; done; cat /run/udev/data/c13:* | grep -q ID_INPUT_KEYBOARD=1 && echo kbd-$((1+1))",
            "kbd-2",
            10,
        )?;
        con.run("for i in $(seq 100); do dmesg | grep -q 'is 10.0.2.15/24' && break; sleep 0.2; done", "", 30)?;
        con.run(&format!("echo 'main http://10.0.2.2:{}/v1' > /etc/quarry/repos", repos.port), "", 10)?;
        con.run("quarry update", "main: 3 packages", 30)?;
        // The disk's password follows the account's (ADR 0039): ada
        // changes hers, and the disk opens with the new one only.
        con.send("exit\r")?;
        con.wait_for("ada@slate:~$ ", 10)?;
        con.send("passwd\r")?;
        con.wait_for("Current password: ", 10)?;
        con.send(&format!("{INSTALL_PASSWORD}\r"))?;
        con.wait_for("New password: ", 10)?;
        con.send(&format!("{NEW_PASSWORD}\r"))?;
        con.wait_for("Retype new password: ", 10)?;
        con.send(&format!("{NEW_PASSWORD}\r"))?;
        con.wait_for("ada@slate:~$ ", 30)?;
        con.send("su -\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{NEW_PASSWORD}\r"))?;
        con.wait_for(PROMPT, 15)?;
        con.wait_for("# ", 5)?;
        con.run(&format!("printf '{NEW_PASSWORD}\\n' | slate-crypt check root"), "That opens slot 0 (password).", 30)?;
        con.run(&format!("printf '{INSTALL_PASSWORD}\\n' | slate-crypt check root"), "does not unlock the disk", 30)?;
        // The slot is ada's (the installer marked it, ADR 0058), so root
        // resetting her password without the old one moves the disk to
        // the new one too.
        con.run("slate-crypt status root", "slot 0: password (UID 1000)", 10)?;
        con.run(&format!("printf '{RESET_PASSWORD}\\n' | passwd --stdin ada"), "password updated successfully", 120)?;
        con.run(
            &format!("printf '{RESET_PASSWORD}\\n' | slate-crypt check root"),
            "That opens slot 0 (password).",
            30,
        )?;
        con.run(&format!("printf '{NEW_PASSWORD}\\n' | slate-crypt check root"), "does not unlock the disk", 30)?;
        // A recovery key for the root, and the open root is busy.
        con.run(
            &format!("printf '{RESET_PASSWORD}\\n' | slate-crypt add-recovery-key root"),
            "Recovery key (slot 1)",
            30,
        )?;
        con.run("slate-crypt status root", "slot 1: recovery key", 10)?;
        con.poweroff()
    })();
    repos.stop();
    let _ = std::fs::write(target_dir().join("install-installed.log"), strip_ansi(&con.log));
    if let Err(e) = result {
        con.kill();
        return Err(format!("install scenario (installed system): {e}"));
    }
    crate::slatefsimg::fsck_with(&disk, root, "installed root after use", Some(RESET_PASSWORD))?;
    // Another boot, unlocked on the screen with the recovery key: Tab, then
    // the key typed in lower case (ADR 0039).
    let log = strip_ansi(&con.log);
    let key = log
        .split_whitespace()
        .find(|w| w.len() == 39 && w.split('-').count() == 8 && w.split('-').all(|g| g.len() == 4))
        .ok_or("install scenario: no recovery key was shown")?
        .to_string();
    let _ = std::fs::remove_file(&mon);
    let mut con = Console::start(reference_pc(o, &disk, None, &mon, None)?)?;
    let second = (|| -> Result {
        con.wait_for("Password to unlock /dev/sda2: ", 60)?;
        std::thread::sleep(Duration::from_millis(1500));
        monitor(&mon, &["sendkey tab"])?;
        type_keys(&mon, &format!("{}\n", key.to_lowercase()))?;
        con.wait_for("unlocked as /dev/dm-0", 30)?;
        con.wait_for("login: ", 60)?;
        con.send("ada\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{RESET_PASSWORD}\r"))?;
        con.wait_for("ada@slate:~$ ", 15)?;
        con.send("su -\r")?;
        con.wait_for("Password: ", 15)?;
        con.send(&format!("{RESET_PASSWORD}\r"))?;
        con.wait_for(PROMPT, 15)?;
        con.wait_for("# ", 5)?;
        con.poweroff()
    })();
    let _ = std::fs::write(target_dir().join("install-recovery.log"), strip_ansi(&con.log));
    if let Err(e) = second {
        con.kill();
        return Err(format!("install scenario (unlocking with the recovery key): {e}"));
    }
    println!(
        "xtask: install scenario passed (USB boot, installer on the USB keyboard, SATA install in {installed:.1}s, \
         reboot, login, igb network with the fixed address chosen, ssh with scp, sftp and privilege separation, the disk's password following the account's and a reset by root, a recovery key on the \
         unlock screen; {:.2}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The patterns tests/user/disks.c wrote reached the host images.
fn check_hw_disks(hw: &HwDisks) -> Result {
    let check = |path: &Path, at: usize, len: usize, f: &dyn Fn(usize) -> u8, what: &str| -> Result {
        let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let ok =
            data[at..at + len].iter().enumerate().all(|(i, &b)| b == f(i)) && data[at - 1] == 0 && data[at + len] == 0;
        if ok { Ok(()) } else { Err(format!("{what}: the guest's writes are not on the host image")) }
    };
    check(&hw.ahci, SDA_OFFSET, SDA_LEN, &|i| ((i * 13 + 5) % 253) as u8, "AHCI disk")?;
    check(&hw.nvme, NVME_OFFSET, NVME_LEN, &|i| ((i * 11 + 1) % 241) as u8, "NVMe disk")
}

/// Size of the scratch disk the block device tests write to (/dev/vdb).
const SCRATCH_SIZE: u64 = 16 << 20;

/// What `tests/user/block.c` writes at `SCRATCH_PATTERN_OFFSET`: byte `i`
/// is `(i * 7 + 3) % 251`.
const SCRATCH_PATTERN_OFFSET: u64 = 12345;
const SCRATCH_PATTERN_LEN: usize = 300_000;

fn scratch_disk() -> Result<PathBuf> {
    let path = target_dir().join("scratch.img");
    let f = std::fs::File::create(&path).map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.set_len(SCRATCH_SIZE).map_err(|e| e.to_string())?;
    Ok(path)
}

/// The guest's writes reached the disk image.
fn check_scratch_disk(path: &Path) -> Result {
    let data = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let at = SCRATCH_PATTERN_OFFSET as usize;
    let ok = data.len() as u64 == SCRATCH_SIZE
        && data[at..at + SCRATCH_PATTERN_LEN].iter().enumerate().all(|(i, &b)| b as usize == (i * 7 + 3) % 251)
        && data[at - 1] == 0
        && data[at + SCRATCH_PATTERN_LEN] == 0;
    if ok { Ok(()) } else { Err("scratch disk: the guest's block writes are not on the host image".into()) }
}

/// The guest's serial console: commands typed at the shell, output read
/// back. The whole output is kept in `log`.
pub struct Console {
    child: Child,
    stdin: ChildStdin,
    rx: Receiver<Vec<u8>>,
    pub log: String,
    pos: usize,
    /// The start of a UTF-8 character whose other bytes have not come yet
    /// (the serial line brings a byte at a time).
    partial: Vec<u8>,
}

pub const PROMPT: &str = "root@slate:";

impl Console {
    pub fn start(mut c: Command) -> Result<Console> {
        c.stdout(Stdio::piped()).stdin(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("failed to start QEMU: {e}"))?;
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Ok(Console { child, stdin, rx, log: String::new(), pos: 0, partial: Vec::new() })
    }

    /// Add what came to the log, as UTF-8, keeping a character that is
    /// not whole yet for the next bytes.
    fn take(&mut self, b: &[u8]) {
        self.partial.extend_from_slice(b);
        loop {
            match std::str::from_utf8(&self.partial) {
                Ok(text) => {
                    self.log.push_str(text);
                    self.partial.clear();
                    return;
                }
                Err(e) => {
                    let good = e.valid_up_to();
                    self.log.push_str(std::str::from_utf8(&self.partial[..good]).unwrap_or(""));
                    match e.error_len() {
                        None => {
                            self.partial.drain(..good);
                            return;
                        }
                        Some(n) => {
                            self.log.push('\u{fffd}');
                            self.partial.drain(..good + n);
                        }
                    }
                }
            }
        }
    }

    /// Wait until `needle` appears after the current position; move past it.
    pub fn wait_for(&mut self, needle: &str, secs: u64) -> Result {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let clean = strip_ansi(&self.log);
            if let Some(i) = clean.get(self.pos..).and_then(|s| s.find(needle)) {
                self.pos += i + needle.len();
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "console: timed out after {secs}s waiting for {needle:?}; last output:\n{}",
                    tail(&clean, 3000)
                ));
            }
            if let Ok(b) = self.rx.recv_timeout(Duration::from_millis(50)) {
                self.take(&b);
            }
        }
    }

    /// Wait for `needle`, then return the rest of its line.
    pub fn line_after(&mut self, needle: &str, secs: u64) -> Result<String> {
        self.wait_for(needle, secs)?;
        let start = self.pos;
        self.wait_for("\n", 10)?;
        Ok(strip_ansi(&self.log)[start..self.pos - 1].trim().to_string())
    }

    /// The last whole line so far that holds `needle`, wherever the
    /// position is (for a line that may have come before what was waited
    /// for).
    pub fn last_line_with(&self, needle: &str) -> Option<String> {
        let clean = strip_ansi(&self.log);
        let whole = &clean[..clean.rfind('\n').unwrap_or(0)];
        whole.lines().rev().find(|l| l.contains(needle)).map(|l| l.trim().to_string())
    }

    /// Wait until every one of `needles` has appeared after the current
    /// position, in any order; move past the last of them.
    pub fn wait_for_all(&mut self, needles: &[&str], secs: u64) -> Result {
        let start = self.pos;
        let mut end = start;
        for n in needles {
            self.pos = start;
            self.wait_for(n, secs)?;
            end = end.max(self.pos);
        }
        self.pos = end;
        Ok(())
    }

    /// Wait for whichever of `needles` comes first; its index.
    pub fn wait_for_any(&mut self, needles: &[&str], secs: u64) -> Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let clean = strip_ansi(&self.log);
            let rest = clean.get(self.pos..).unwrap_or("");
            let first = needles.iter().enumerate().filter_map(|(n, s)| rest.find(s).map(|i| (i, n, s.len()))).min();
            if let Some((i, n, len)) = first {
                self.pos += i + len;
                return Ok(n);
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "console: timed out after {secs}s waiting for one of {needles:?}; last output:\n{}",
                    tail(&clean, 3000)
                ));
            }
            if let Ok(b) = self.rx.recv_timeout(Duration::from_millis(50)) {
                self.take(&b);
            }
        }
    }

    pub fn send(&mut self, text: &str) -> Result {
        self.stdin.write_all(text.as_bytes()).and_then(|()| self.stdin.flush()).map_err(|e| e.to_string())
    }

    pub fn login(&mut self) -> Result {
        self.wait_for("login: ", 60)?;
        self.send("root\r")?;
        self.wait_for(PROMPT, 15)?;
        self.wait_for("# ", 5)
    }

    /// Type `cmd`, wait for `want` in its output and the next prompt.
    /// Take in what has arrived and not been read yet (for a transcript
    /// written after a failure), waiting up to `ms` for more.
    pub fn drain(&mut self, ms: u64) {
        let until = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < until {
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok(b) => self.take(&b),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break,
            }
        }
    }

    pub fn run(&mut self, cmd: &str, want: &str, secs: u64) -> Result {
        self.send(&format!("{cmd}\r"))?;
        self.wait_for(want, secs)?;
        self.wait_for(PROMPT, 30)?;
        self.wait_for("# ", 5)
    }

    /// [`Console::run`], and wait for `also` too, which another program
    /// says once the command has run: before or after `want`, before or
    /// after the prompt comes back.
    pub fn run_seeing(&mut self, cmd: &str, want: &str, also: &str, secs: u64) -> Result {
        // `also` may come before `want`: what the command set off can
        // answer before the shell does (2026-10-28, Strata counting the
        // desktop's icons before the echo).
        let start = self.pos;
        self.send(&format!("{cmd}\r"))?;
        self.wait_for(want, secs)?;
        self.wait_for(PROMPT, 30)?;
        self.wait_for("# ", 5)?;
        let end = self.pos;
        self.pos = start;
        self.wait_for(also, secs)?;
        self.pos = self.pos.max(end);
        Ok(())
    }

    pub fn poweroff(&mut self) -> Result {
        self.send("poweroff\r")?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            while let Ok(b) = self.rx.try_recv() {
                self.take(&b);
            }
            if let Some(s) = self.child.try_wait().map_err(|e| e.to_string())? {
                return if s.code() == Some(0) { Ok(()) } else { Err(format!("QEMU exited with {s} after poweroff")) };
            }
            if Instant::now() > deadline {
                return Err("the guest did not power off".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait for QEMU to end (the guest powered off or rebooted under
    /// `-no-reboot`); returns its exit code.
    pub fn wait_exit(&mut self, secs: u64) -> Result<Option<i32>> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            while let Ok(b) = self.rx.try_recv() {
                self.take(&b);
            }
            if let Some(s) = self.child.try_wait().map_err(|e| e.to_string())? {
                while let Ok(b) = self.rx.recv_timeout(Duration::from_millis(100)) {
                    self.take(&b);
                }
                return Ok(s.code());
            }
            if Instant::now() > deadline {
                return Err(format!("QEMU did not exit; last output:\n{}", tail(&strip_ansi(&self.log), 3000)));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tail(s: &str, n: usize) -> &str {
    let mut start = s.len().saturating_sub(n);
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::Report;

    #[test]
    fn sizes() {
        assert_eq!(super::size_bytes("4G"), Some(4 << 30));
        assert_eq!(super::size_bytes("512M"), Some(512 << 20));
        assert_eq!(super::size_bytes("2048"), Some(2048 << 20));
        assert_eq!(super::size_bytes("4X"), None);
    }

    #[test]
    fn resolutions() {
        assert_eq!(super::parse_res("1920x1080"), Some((1920, 1080)));
        assert_eq!(super::parse_res("2560X1440"), Some((2560, 1440)));
        assert_eq!(super::parse_res("1080p"), None);
        assert_eq!(super::parse_res("100x100"), None);
        assert_eq!(super::parse_res("1920x"), None);
    }

    #[test]
    fn parses_report_lines() {
        let mut r = Report::default();
        for l in ["noise", "SLATE-TEST: PASS boot\r", "SLATE-TEST: FAIL pf (bad)", "SLATE-TEST: DONE 1/2"] {
            r.line(l);
        }
        assert_eq!(r.passed, ["boot"]);
        assert_eq!(r.failed, ["pf (bad)"]);
        assert!(r.done);
    }
}
