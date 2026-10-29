// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask bench`: the handoff's performance and size budgets (§1)
//! as tests (ADR 0047). One boot of the installed system shape (the
//! SlateFS root on a disk, no test load) measures:
//!
//! - boot to the login prompt, from the kernel's first line on the serial
//!   console (after the bootloader hands over);
//! - memory in use at the prompt after logging in (MemTotal - MemFree -
//!   Cached in /proc/meminfo: the kernel, the services, the shell);
//! - shell start-up: `sh -c :` run 200 times in a loop, timed by the
//!   guest's /proc/uptime;
//!
//! and on the host the size of the base install (the installed system's
//! archive plus the kernel).
//!
//! Then the desktop (ADR 0062), once on virtio-gpu and once on the
//! firmware framebuffer: Strata with `strata.stats` prints its frame
//! timings after each action QEMU's monitor drives (the launcher, keys
//! typed into the terminal, a window dragged, a workspace switch, 3000
//! lines scrolled), while the kernel's profiler samples Strata and the
//! terminal; `target/bench-profile-DISPLAY.txt` says where their time
//! went, by function.
//!
//! At 4K (ADR 0157, M32): the same cases on a 3840x2160 firmware
//! framebuffer (Strata at scale 2), within one refresh at 60 Hz as well
//! (ADR 0168; met since M32's phase 2, ADR 0169: [`FOUR_K_FAILS`]).
//!
//! Any number over its budget fails; the results go to `target/bench.txt`.
//! `SLATE_BENCH=system`, `desktop` or `4k` runs one part only;
//! `SLATE_BENCH_SHOT=1` saves the screen once the terminal is open. `cargo xtask
//! test` runs the system's part and the desktop's on the framebuffer,
//! at 1280x800 and at 4K ([`gate`]).

use std::collections::HashMap;
use std::time::Instant;

use crate::qemu::{Console, base_command, monitor, monitor_paced, mouse_index};
use crate::{Opts, Result, image, target_dir};

struct Budget {
    name: &'static str,
    unit: &'static str,
    limit: f64,
}

const BOOT: Budget = Budget { name: "boot to login prompt", unit: "s", limit: 1.0 };
const RAM: Budget = Budget { name: "memory in use at the prompt", unit: "MiB", limit: 64.0 };
const SIZE: Budget = Budget { name: "base install size", unit: "MB", limit: 150.0 };
const SHELL: Budget = Budget { name: "shell start-up", unit: "ms", limit: 5.0 };

// The desktop's (ADR 0062), on each display. A frame should take no more
// than one refresh at 60 Hz, and what the person did should be on the
// screen by the next refresh (or the one after, for a window being
// dragged and a launcher being opened).
const LAUNCHER_OPEN: Budget = Budget { name: "launcher: key to first frame", unit: "ms", limit: 33.0 };
const LAUNCHER_FRAME: Budget = Budget { name: "launcher: frame (p95)", unit: "ms", limit: 16.7 };
const KEY: Budget = Budget { name: "key to glyph (p95)", unit: "ms", limit: 16.7 };
const POINTER: Budget = Budget { name: "pointer: move to screen (p95)", unit: "ms", limit: 16.7 };
const DRAG_FRAME: Budget = Budget { name: "window drag: frame (p95)", unit: "ms", limit: 16.7 };
const DRAG_INPUT: Budget = Budget { name: "window drag: move to screen (p95)", unit: "ms", limit: 25.0 };
const SWITCH_FRAME: Budget = Budget { name: "workspace switch: frame (p95)", unit: "ms", limit: 16.7 };
const SCROLL: Budget = Budget { name: "terminal: 3000 lines on the screen", unit: "s", limit: 0.5 };
// The same with every CPU busy (four programs that never sleep): the
// desktop must stay as quick (ADR 0067).
const KEY_LOADED: Budget = Budget { name: "under load: key to glyph (p95)", unit: "ms", limit: 16.7 };
const POINTER_LOADED: Budget = Budget { name: "under load: pointer to screen (p95)", unit: "ms", limit: 16.7 };

/// A /proc/meminfo field in KiB.
fn meminfo(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|l| l.strip_prefix(key)?.trim().strip_suffix("kB")?.trim().parse().ok())
}

/// Whether the 4K desktop's budgets fail the bench: since M32's phase 2
/// met them (ADR 0169).
const FOUR_K_FAILS: bool = true;

/// Whether `cargo xtask test` fails on the desktop's budgets: since M22
/// met them (ADR 0062, ADR 0068); `cargo xtask bench` always does.
const DESKTOP_IN_TEST_GATE: bool = true;

pub fn bench(o: &Opts) -> Result {
    let part = std::env::var("SLATE_BENCH").unwrap_or_default();
    let screens: &[Screen] = match part.as_str() {
        "system" => &[],
        "4k" => &[Screen::Firmware4k],
        _ => &[Screen::Virtio, Screen::Firmware, Screen::Firmware4k],
    };
    measure(o, part.is_empty() || part == "system", screens, true)
}

/// What `cargo xtask test` runs: the system's budgets, and the desktop's
/// cases on the firmware framebuffer under UEFI, which must run but fail
/// on their budgets only once [`DESKTOP_IN_TEST_GATE`] says so.
pub fn gate(o: &Opts) -> Result {
    let screens: &[Screen] = if o.bios { &[] } else { &[Screen::Firmware, Screen::Firmware4k] };
    measure(o, true, screens, DESKTOP_IN_TEST_GATE)
}

fn measure(o: &Opts, with_system: bool, screens: &[Screen], desktop_fails: bool) -> Result {
    let mut results: Vec<(String, &Budget, f64, bool)> = Vec::new();
    if with_system {
        for (b, v) in system(o)? {
            results.push((b.name.to_string(), b, v, true));
        }
    }
    for &screen in screens {
        let fails = desktop_fails && (FOUR_K_FAILS || !matches!(screen, Screen::Firmware4k));
        for (b, v) in desktop(o, screen)? {
            results.push((format!("{}: {}", screen.name(), b.name), b, v, fails));
        }
    }
    let mut report = String::new();
    let mut over = Vec::new();
    let mut reported = Vec::new();
    for (name, b, v, fails) in &results {
        let ok = *v <= b.limit;
        report.push_str(&format!(
            "{:<50} {:>9.3} {:<3} (budget {} {}) {}\n",
            name,
            v,
            b.unit,
            b.limit,
            b.unit,
            if ok { "ok" } else { "OVER" }
        ));
        if !ok && *fails {
            over.push(name.clone());
        } else if !ok {
            reported.push(name.clone());
        }
    }
    print!("{report}");
    std::fs::write(target_dir().join("bench.txt"), &report).map_err(|e| e.to_string())?;
    if !over.is_empty() {
        return Err(format!("bench: over budget: {}", over.join(", ")));
    }
    if reported.is_empty() {
        println!("xtask: bench passed (every budget met)");
    } else {
        println!("xtask: bench passed (over budget, reported only: {})", reported.join(", "));
    }
    Ok(())
}

/// The system's budgets: boot, memory, shell start-up, size.
fn system(o: &Opts) -> Result<Vec<(&'static Budget, f64)>> {
    let img = image::build(o, "", "slate-bench.img", image::Root::Disk)?;
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio"]);
    let mut con = Console::start(c)?;
    let measured = (|| -> Result<(f64, f64, f64)> {
        con.wait_for("Slate kernel", 60)?;
        let entered = Instant::now();
        con.wait_for("login: ", 30)?;
        let boot = entered.elapsed().as_secs_f64();
        con.send("root\r")?;
        con.wait_for("# ", 15)?;
        // Let the services settle, then read the memory in use.
        con.run("sleep 2; echo settled$((1+1))", "settled2", 10)?;
        con.run("cat /proc/meminfo; echo meminfo$((1+1))", "meminfo2", 10)?;
        let log = con.log.clone();
        let at = log.rfind("MemTotal:").ok_or("no /proc/meminfo output")?;
        let info = &log[at..];
        let total = meminfo(info, "MemTotal:").ok_or("no MemTotal")?;
        let free = meminfo(info, "MemFree:").ok_or("no MemFree")?;
        let cached = meminfo(info, "Cached:").unwrap_or(0);
        let ram = total.saturating_sub(free).saturating_sub(cached) as f64 / 1024.0;
        con.run(
            "a=$(cut -d' ' -f1 /proc/uptime); i=0; while [ $i -lt 200 ]; do sh -c :; i=$((i+1)); done; \
             b=$(cut -d' ' -f1 /proc/uptime); echo \"SHELL-TIMES $a $b end\"",
            "end",
            60,
        )?;
        let log = con.log.clone();
        let at = log.rfind("SHELL-TIMES ").ok_or("no shell timing")?;
        let mut w = log[at..].split_whitespace().skip(1);
        let a: f64 = w.next().and_then(|v| v.parse().ok()).ok_or("bad shell timing")?;
        let b: f64 = w.next().and_then(|v| v.parse().ok()).ok_or("bad shell timing")?;
        let shell = (b - a) * 1000.0 / 200.0;
        con.poweroff()?;
        Ok((boot, ram, shell))
    })();
    let (boot, ram, shell) = match measured {
        Ok(m) => m,
        Err(e) => {
            con.kill();
            return Err(format!("bench: {e}"));
        }
    };
    let kernel = std::fs::metadata(crate::boot_kernel(o.release)?).map_err(|e| e.to_string())?.len();
    let size = (crate::initramfs::system_archive()?.len() as u64 + kernel) as f64 / 1e6;
    Ok(vec![(&BOOT, boot), (&RAM, ram), (&SIZE, size), (&SHELL, shell)])
}

#[derive(Clone, Copy, Debug)]
enum Screen {
    Virtio,
    Firmware,
    /// The firmware framebuffer at 3840x2160 (a standard VGA card with
    /// 64 MiB; the menu asks slate-loader for the mode, ADR 0111).
    Firmware4k,
}

impl Screen {
    fn name(self) -> &'static str {
        match self {
            Screen::Virtio => "virtio-gpu",
            Screen::Firmware => "framebuffer",
            Screen::Firmware4k => "framebuffer 4K",
        }
    }

    fn size(self) -> (u32, u32) {
        match self {
            Screen::Firmware4k => (3840, 2160),
            _ => (1280, 800),
        }
    }

    /// The pointer's way from the middle of the screen to the first
    /// window's title bar: so many moves of so many pixels up. At
    /// 1280x800 the terminal's title bar is at 87–117; at 4K (scale 2,
    /// the terminal's window sized in its cells) at 430–498, as
    /// `SLATE_BENCH_SHOT` showed it.
    fn to_title(self) -> (usize, i32) {
        match self {
            Screen::Firmware4k => (44, -14),
            _ => (20, -15),
        }
    }
}

/// A `strata-stats:` line's fields (microseconds and counts).
fn fields(line: &str) -> HashMap<String, i64> {
    line.split_whitespace()
        .filter_map(|w| w.split_once('='))
        .filter_map(|(k, v)| Some((k.into(), v.parse().ok()?)))
        .collect()
}

/// A field in milliseconds; 0 if the line has none.
fn ms(f: &HashMap<String, i64>, key: &str) -> f64 {
    f.get(key).copied().unwrap_or(0) as f64 / 1000.0
}

/// QEMU key names for typing `text` (lower case, digits, a few signs).
pub fn keys(text: &str) -> Vec<String> {
    text.chars()
        .map(|c| {
            let k = match c {
                ' ' => "spc".to_string(),
                '/' => "slash".to_string(),
                '.' => "dot".to_string(),
                '-' => "minus".to_string(),
                c => c.to_string(),
            };
            format!("sendkey {k}")
        })
        .collect()
}

/// The desktop's cases on one display.
fn desktop(o: &Opts, screen: Screen) -> Result<Vec<(&'static Budget, f64)>> {
    let img = match screen {
        Screen::Firmware4k => {
            let img = image::build(o, "strata.stats", "slate-bench-desktop-4k.img", image::Root::Disk)?;
            // QEMU's firmware offers 3840x2160 but publishes no EDID, so
            // the menu asks for it.
            let (w, h) = screen.size();
            image::set_resolution(&img, w, h)?;
            img
        }
        _ => image::build(o, "strata.stats", "slate-bench-desktop.img", image::Root::Disk)?,
    };
    let mon = target_dir().join("bench-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    match screen {
        Screen::Virtio => {
            c.args(["-vga", "none", "-device", "virtio-gpu-pci"]);
        }
        Screen::Firmware4k => {
            let (w, h) = screen.size();
            c.args(["-vga", "none", "-device"]).arg(format!("VGA,xres={w},yres={h},vgamem_mb=64"));
        }
        Screen::Firmware => {}
    }
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let pause = |ms: u64| std::thread::sleep(std::time::Duration::from_millis(ms));
    let measured = (|| -> Result<(Vec<(&'static Budget, f64)>, String)> {
        con.login()?;
        // Run in the terminal: 3000 lines, timed by the guest's clock.
        con.run(
            "echo 'a=$(cut -d\" \" -f1 /proc/uptime); seq 1 3000; b=$(cut -d\" \" -f1 /proc/uptime); \
             echo \"$a $b\" > /tmp/scroll.out' > /tmp/scroll",
            "",
            10,
        )?;
        con.run("echo strata,terminal > /proc/slate_profile", "", 10)?;
        con.send("strata &\r")?;
        let (sw, sh) = screen.size();
        con.wait_for(&format!("strata: {sw}x{sh}"), 30)?;
        let stats = |con: &mut Console, what: &str| -> Result<HashMap<String, i64>> {
            let line = con.line_after("strata-stats:", 15).map_err(|e| format!("{what}: {e}"))?;
            println!("xtask: bench: {}: {what}: {line}", screen.name());
            Ok(fields(&line))
        };
        stats(&mut con, "first frame")?;
        let mut out = Vec::new();
        // The launcher: its key to the first frame, and the frames of its
        // fade (all drawn whole).
        monitor(&mon, &["sendkey meta_l-spc"])?;
        let f = stats(&mut con, "launcher")?;
        out.push((&LAUNCHER_OPEN, ms(&f, "input_max_us")));
        out.push((&LAUNCHER_FRAME, ms(&f, "frame_p95_us")));
        monitor(&mon, &["sendkey esc"])?;
        stats(&mut con, "launcher closed")?;
        // A terminal, then 20 keys typed into it and taken back.
        monitor(&mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
        stats(&mut con, "terminal opened")?;
        // SLATE_BENCH_SHOT=1: the screen now, to see where the window is.
        if std::env::var_os("SLATE_BENCH_SHOT").is_some() {
            let shot = target_dir().join(format!("bench-{}.ppm", screen.name().replace(' ', "-")));
            monitor(&mon, &[&format!("screendump {}", shot.display())])?;
            println!("xtask: bench: {}: the screen in {}", screen.name(), shot.display());
        }
        // Time for the shell in it to start (1 s was once too little, and
        // the keys went before anything read them; 2 s once too, so a
        // second try follows a short one).
        pause(2000);
        monitor_paced(&mon, &vec!["sendkey x".to_string(); 20], 150)?;
        let mut f = stats(&mut con, "keys")?;
        let mut typed = 20;
        if f.get("key_n").copied().unwrap_or(0) < 15 {
            println!("xtask: bench: {:?} of 20 keys came back; once more", f.get("key_n"));
            pause(2000);
            monitor_paced(&mon, &vec!["sendkey x".to_string(); 20], 150)?;
            typed += 20;
            f = stats(&mut con, "keys")?;
        }
        if f.get("key_n").copied().unwrap_or(0) < 15 {
            return Err(format!("keys: only {:?} of 20 keys came back from the terminal", f.get("key_n")));
        }
        out.push((&KEY, ms(&f, "key_p95_us")));
        monitor_paced(&mon, &vec!["sendkey backspace".to_string(); typed], 150)?;
        stats(&mut con, "backspaces")?;
        // The pointer from the middle of the screen to the terminal's
        // title bar ([`Screen::to_title`]), one move every 16 ms; then the
        // window dragged 240 right and 120 down in 40 moves.
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        monitor(&mon, &[&format!("mouse_set {mouse}")])?;
        let (n, dy) = screen.to_title();
        monitor_paced(&mon, &vec![format!("mouse_move 0 {dy}"); n], 16)?;
        out.push((&POINTER, ms(&stats(&mut con, "pointer")?, "input_p95_us")));
        let mut drag = vec!["mouse_button 1".to_string()];
        drag.extend(std::iter::repeat_n("mouse_move 6 3".to_string(), 40));
        drag.push("mouse_button 0".into());
        monitor_paced(&mon, &drag, 16)?;
        let f = stats(&mut con, "drag")?;
        out.push((&DRAG_FRAME, ms(&f, "frame_p95_us")));
        out.push((&DRAG_INPUT, ms(&f, "input_p95_us")));
        // A workspace switch and back: slides drawn whole.
        let mut worst: f64 = 0.0;
        for k in ["sendkey meta_l-2", "sendkey meta_l-1"] {
            monitor(&mon, &[k])?;
            worst = worst.max(ms(&stats(&mut con, k)?, "frame_p95_us"));
        }
        out.push((&SWITCH_FRAME, worst));
        // 3000 lines through the terminal: from the Enter key to the last
        // frame they changed.
        monitor_paced(&mon, &keys("sh /tmp/scroll"), 60)?;
        stats(&mut con, "scroll typed")?;
        monitor(&mon, &["sendkey ret"])?;
        let f = stats(&mut con, "scroll")?;
        out.push((&SCROLL, (ms(&f, "key_max_us") + ms(&f, "span_us")) / 1000.0));
        con.run(
            "i=0; while [ ! -s /tmp/scroll.out ] && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; \
             echo scroll-ran $(wc -w < /tmp/scroll.out)",
            "scroll-ran 2",
            30,
        )?;
        // Every CPU busy: keys into the terminal, and the pointer moved
        // down and back up over the desktop.
        con.run(
            "for i in 1 2 3 4; do (while :; do :; done) & echo $! >> /tmp/hogs; done; echo hogs$((1+1))",
            "hogs2",
            10,
        )?;
        pause(500);
        monitor_paced(&mon, &vec!["sendkey x".to_string(); 20], 150)?;
        let f = stats(&mut con, "keys under load")?;
        out.push((&KEY_LOADED, ms(&f, "key_p95_us")));
        let mut moves = vec!["mouse_move 0 15".to_string(); 10];
        moves.extend(std::iter::repeat_n("mouse_move 0 -15".to_string(), 10));
        monitor_paced(&mon, &moves, 16)?;
        out.push((&POINTER_LOADED, ms(&stats(&mut con, "pointer under load")?, "input_p95_us")));
        con.run("kill $(cat /tmp/hogs); echo unloaded$((1+1))", "unloaded2", 10)?;
        // Where the time went.
        con.run("echo > /proc/slate_profile; cat /proc/slate_profile; echo profile-end$((1+1))", "profile-end2", 60)?;
        let log = crate::qemu::strip_ansi(&con.log);
        let start = log.rfind("# samples ").ok_or("no profile")?;
        let end = log[start..].find("profile-end2").map_or(log.len(), |e| start + e);
        let profile = log[start..end].replace('\r', "");
        con.poweroff()?;
        Ok((out, profile))
    })();
    let (out, profile) = match measured {
        Ok(m) => m,
        Err(e) => {
            con.kill();
            return Err(format!("bench: {}: {e}", screen.name()));
        }
    };
    let src = crate::profile::Sources {
        kernel: crate::boot_kernel(o.release)?,
        stripped: target_dir().join("userland").join("stripped"),
        with_symbols: crate::userland::symbols_dir(),
    };
    let text = crate::profile::render(&profile, &src, 30)?;
    let path = target_dir().join(format!("bench-profile-{}.txt", screen.name()));
    std::fs::write(&path, &text).map_err(|e| e.to_string())?;
    println!("xtask: bench: {}: profile in {}", screen.name(), path.display());
    Ok(out)
}
