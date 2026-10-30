// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask flatpak --measure` (M31 phase 1, ADR 0155): where a
//! Linux app's time goes, on the Flatpak workbench (needs the internet).
//! One boot, with `strata.stats` on, Strata running as root on the
//! console, and wl-probe (Slate's Wayland test client) copied into the
//! runtime:
//!
//! - Strata's warm-up of the runtime at the session's start (phase 2);
//! - entering the runtime (`slate-linux run /bin/true`, five times);
//! - starting a window (30 frames, so it stays long enough to be timed),
//!   stage by stage, three times: the runtime entered,
//!   Strata's window, Sway's socket, the bridge bound, the app's window,
//!   its first frame (slate-linux-app's and strata-wl's `timing:` lines);
//! - in a window: frame times for 300 frames changing all of it and 300
//!   changing a small square (wl-probe's pacing, strata-wl's copies,
//!   Strata's frames), and key to screen for 20 keys typed through QEMU's
//!   monitor (Strata's `key_` figures);
//! - installing an app (Lagrange) from Flathub: its time and size;
//!   Flathub's 12 MB summary fetched on the host, by Slate's `fetch`, and
//!   inside the runtime, for the download speed; small files written with
//!   and without fsync on SlateFS (the root) and ext4 (the workbench), for
//!   OSTree's write cost;
//! - starting the app twice (the same stages), and `flatpak run
//!   --command=true` for bubblewrap's part.
//!
//! The figures go to target/flatpak/measure.txt, the transcript to
//! target/flatpak/measure.log.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use crate::hostnet::StaticServer;
use crate::qemu::Console;
use crate::{Result, target_dir};

/// The app installed and started.
const APP: &str = "fi.skyjake.Lagrange";
/// A file on Flathub's server big enough to time (about 12 MB).
const BIG: &str = "https://dl.flathub.org/repo/summary";
/// Wait (up to a minute) for the program started last in the background
/// (`app=$!`) to end; a plain `wait` would wait for Strata too.
const GONE: &str = "for i in $(seq 300); do kill -0 $app 2>/dev/null || break; sleep 0.2; done";
/// Root's Flatpak home, on the workbench's big disk.
const H: &str = "HOME=/home/fp";

/// Milliseconds between `$(date +%s%N)` values `a` and now, in shell.
fn ms_since(var: &str) -> String {
    format!("$(( ($(date +%s%N) - {var}) / 1000000 ))")
}

/// The numbers after `key ` in `line` (`key 12 ms` -> 12).
fn number_after(line: &str, key: &str) -> Option<f64> {
    let rest = &line[line.find(key)? + key.len()..];
    let rest = rest.trim_start_matches([' ', '=']);
    let n: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    n.parse().ok()
}

/// The budgets (ADR 0180, tightened in phase 2), in QEMU/KVM at
/// 1280x800: each a figure's name, the start of the report entries it is
/// read from (the first with a number after the word), the word, the
/// largest value allowed, and its unit.
const BUDGETS: &[(&str, &str, &str, f64, &str)] = &[
    ("runtime entry", "runtime entry", "median", 20_000.0, "us"),
    ("window start-up, the first after warming (first frame)", "probe start 1", "first frame", 300.0, "ms"),
    ("window start-up, warm (first frame)", "probe start 3", "first frame", 150.0, "ms"),
    ("frames: interval p95 (60 Hz)", "frames full", "us, p95", 17_500.0, "us"),
    // One pass over the window's pixels a frame: the compositor's copy
    // into Strata's buffer (a 770x500 window is 1.5 MB).
    ("the bridge's bytes per frame, all of it changing", "frames full", "bytes_per_frame=", 1_600_000.0, "bytes"),
    ("key to screen p95", "keys: strata", "key_p95_us=", 16_700.0, "us"),
    ("app start-up, warm (first frame)", "app start 2", "first frame", 2_000.0, "ms"),
    ("sandbox around true, warm", "flatpak run --command=true 2", "sandbox", 300.0, "ms"),
];

/// The figures, in order, for measure.txt.
struct Report(Vec<(String, String)>);

impl Report {
    fn add(&mut self, name: &str, value: impl Into<String>) {
        let v = value.into();
        println!("xtask: measure: {name}: {v}");
        self.0.push((name.into(), v));
    }
    fn lines(&mut self, prefix: &str, lines: &[String]) {
        for (i, l) in lines.iter().enumerate() {
            self.add(&format!("{prefix} {}", i + 1), l.clone());
        }
    }
}

/// The steps; each adds what it measured. Failures end the run, with
/// what was measured until then.
fn steps(con: &mut Console, mon: &std::path::Path, port: u16, r: &mut Report) -> Result {
    con.run(crate::flatpak::MOUNT, "mounted2", 30)?;
    con.run(
        "mkdir -p /mnt/workbench/fphome /home/fp && mount -o bind /mnt/workbench/fphome /home/fp && echo bound$((1+1))",
        "bound2",
        30,
    )?;
    con.run(
        &format!(
            "fetch -q -o /var/lib/slate/linux/usr/local/bin/wl-probe http://10.0.2.2:{port}/wl-probe && \
             chmod 755 /var/lib/slate/linux/usr/local/bin/wl-probe && echo probe$((1+1))"
        ),
        "probe2",
        60,
    )?;
    con.run("strata > /tmp/strata.log 2>&1 & sleep 1", "", 30)?;
    // Strata warms the runtime a few seconds in (M31 phase 2).
    let warm = con.output(
        "for i in $(seq 100); do grep -q 'slate-linux: warm' /tmp/strata.log && break; sleep 0.2; done; grep -a 'slate-linux: warm' /tmp/strata.log",
        60,
    )?;
    r.lines("warm-up", &warm);
    // Strata's own lines since the last mark.
    let strata_since = |con: &mut Console| -> Result<Vec<String>> {
        let l = con.output("tail -n +$((mark+1)) /tmp/strata.log | grep -a 'strata-stats:'", 30)?;
        con.run("mark=$(wc -l < /tmp/strata.log)", "", 10)?;
        Ok(l)
    };
    con.run("mark=$(wc -l < /tmp/strata.log)", "", 10)?;

    // Entering the runtime.
    let enter = con.output("for i in 1 2 3 4 5; do SLATE_LINUX_TIMING=1 slate-linux run /bin/true; done", 120)?;
    let mut us: Vec<f64> = enter.iter().filter_map(|l| number_after(l, "entered")).collect();
    let all = format!("{us:?}");
    us.sort_by(f64::total_cmp);
    r.add("runtime entry (us, 5 runs)", format!("{all} median {}", us.get(us.len() / 2).copied().unwrap_or(-1.0)));

    // A window's start-up, stage by stage.
    for i in 1..=3 {
        let l = con.output("slate-linux-app wl-probe --frames 30 2>&1 | grep -a 'timing:\\|first frame'", 120)?;
        r.lines(&format!("probe start {i}"), &l);
    }

    // Frames: all of the window, then a small square.
    for (what, args) in [("full", "--frames 300"), ("small", "--frames 300 --damage small")] {
        let l = con.output(
            &format!("slate-linux-app wl-probe {args} 2>&1 | grep -a 'wl-probe: [0-9]* frames\\|strata-wl-stats:'"),
            300,
        )?;
        r.lines(&format!("frames {what}"), &l);
        std::thread::sleep(Duration::from_millis(800));
        let s = strata_since(con)?;
        // The burst with the most frames is the animation's.
        if let Some(best) = s.iter().max_by_key(|l| number_after(l, "frames").unwrap_or(0.0) as u64) {
            r.add(&format!("frames {what}: strata"), best.clone());
        }
    }

    // Key to screen.
    con.run("slate-linux-app wl-probe --keys 20 > /tmp/keys.log 2>&1 & app=$!", "", 10)?;
    con.run(
        "for i in $(seq 150); do grep -q 'strata-wl: timing' /tmp/keys.log && break; sleep 0.2; done; echo up$((1+1))",
        "up2",
        60,
    )?;
    std::thread::sleep(Duration::from_millis(1500));
    con.run("mark=$(wc -l < /tmp/strata.log)", "", 10)?;
    let keys: Vec<String> = (0..20).map(|_| String::from("sendkey a")).collect();
    crate::qemu::monitor_paced(mon, &keys, 250)?;
    let l = con.output(&format!("{GONE}; grep -a 'wl-probe: [0-9]* keys\\|strata-wl-stats' /tmp/keys.log"), 60)?;
    r.lines("keys", &l);
    std::thread::sleep(Duration::from_millis(800));
    for s in strata_since(con)? {
        if number_after(&s, "key_n").unwrap_or(0.0) > 0.0 {
            r.add("keys: strata", s);
        }
    }

    // Download speed: the host, Slate's fetch, the runtime.
    let host = std::process::Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{speed_download}", BIG])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map_or("?".into(), |b| format!("{:.1} MB/s", b / 1e6));
    r.add("download: host", host);
    let l = con.output(
        &format!(
            "t=$(date +%s%N); fetch -q -o /tmp/big {BIG}; echo fetch {} ms $(wc -c < /tmp/big) bytes; rm -f /tmp/big",
            ms_since("t")
        ),
        300,
    )?;
    r.lines("download: slate fetch", &l);
    let l = con.output(
        &format!(
            "t=$(date +%s%N); slate-linux run /bin/sh -c 'command -v curl > /dev/null && curl -s -o /dev/null {BIG} || wget -q -O /dev/null {BIG}'; echo runtime {} ms",
            ms_since("t")
        ),
        300,
    )?;
    r.lines("download: runtime", &l);

    // Small files, written plainly and with fsync, on each file system.
    for (fs, dir) in [("slatefs", "/root/m31"), ("ext4", "/home/fp/m31")] {
        let l = con.output(
            &format!(
                "mkdir -p {dir} && cd {dir} && t=$(date +%s%N); for i in $(seq 200); do dd if=/dev/zero of=p.$i bs=16k count=1 2>/dev/null; done; \
                 a={}; t=$(date +%s%N); for i in $(seq 200); do dd if=/dev/zero of=s.$i bs=16k count=1 conv=fsync 2>/dev/null; done; \
                 echo plain $a ms fsync {} ms; cd /; rm -r {dir}",
                ms_since("t"),
                ms_since("t")
            ),
            600,
        )?;
        r.lines(&format!("200 files of 16 KiB on {fs}"), &l);
    }

    // Installing the app from Flathub.
    let l = con.output(
        &format!(
            "t=$(date +%s%N); {H} slate-flatpak install {APP} > /tmp/install.log 2>&1; echo status $? {} ms; du -sk /home/fp/.local/share/flatpak",
            ms_since("t")
        ),
        3600,
    )?;
    r.lines("install", &l);

    // Bubblewrap's part: the sandbox around `true`.
    for i in 1..=2 {
        let l = con.output(
            &format!(
                "t=$(date +%s%N); {H} slate-linux run /bin/sh -c 'mkdir -p /tmp/xdg-0 && chmod 700 /tmp/xdg-0; XDG_RUNTIME_DIR=/tmp/xdg-0 flatpak --user run --command=true {APP}'; echo sandbox {} ms",
                ms_since("t")
            ),
            300,
        )?;
        r.lines(&format!("flatpak run --command=true {i}"), &l);
    }

    // The app's start-up, twice; Sway is stopped after (the app's window
    // closes with it).
    for i in 1..=2 {
        con.run(&format!("{H} slate-flatpak run {APP} > /tmp/app.log 2>&1 & app=$!"), "", 10)?;
        let l = con.output(
            "for i in $(seq 600); do grep -q 'strata-wl: timing' /tmp/app.log && break; sleep 0.2; done; grep -a 'timing:' /tmp/app.log",
            200,
        )?;
        r.lines(&format!("app start {i}"), &l);
        con.run(
            &format!(
                "for p in /proc/[0-9]*; do [ \"$(cat $p/comm 2>/dev/null)\" = sway ] && kill ${{p#/proc/}}; done; {GONE}; echo stopped$((1+1))"
            ),
            "stopped2",
            60,
        )?;
    }
    Ok(())
}

pub fn measure(fresh: bool) -> Result {
    let started = Instant::now();
    let wb = crate::flatpak::workbench(fresh)?;
    let disk = crate::flatpak::scratch_copy(&wb, "measure.img")?;
    let dir = target_dir().join("flatpak");
    let serve = dir.join("serve");
    std::fs::create_dir_all(&serve).map_err(|e| e.to_string())?;
    let probe =
        crate::userland::build()?.into_iter().find(|p| p.name == "wl-probe").ok_or("wl-probe was not built")?.path;
    std::fs::copy(&probe, serve.join("wl-probe")).map_err(|e| e.to_string())?;
    let server = StaticServer::start(serve)?;
    let mon = dir.join("measure-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut con = crate::desktop::boot_with(&disk, Some(&mon), false, "strata.stats")?;
    let mut report = Report(Vec::new());
    let r = con.login().and_then(|()| steps(&mut con, &mon, server.port, &mut report));
    let _ = crate::flatpak::kernel_notes(&mut con);
    let _ = con.poweroff();
    server.stop();
    std::fs::write(dir.join("measure.log"), crate::qemu::strip_ansi(&con.log)).map_err(|e| e.to_string())?;
    let mut text = String::from("# cargo xtask flatpak --measure (M31 phase 1)\n");
    for (k, v) in &report.0 {
        let _ = writeln!(text, "{k}: {v}");
    }
    let mut over = Vec::new();
    for (name, figure, word, limit, unit) in BUDGETS {
        let got = report.0.iter().filter(|(k, _)| k.starts_with(figure)).find_map(|(_, v)| number_after(v, word));
        let ok = got.is_some_and(|g| g <= *limit);
        let line = format!(
            "MEASURE: {} {name}: {} {unit} (budget {limit} {unit})",
            if ok { "PASS" } else { "FAIL" },
            got.map_or("?".into(), |g| g.to_string())
        );
        println!("{line}");
        let _ = writeln!(text, "{line}");
        if !ok {
            over.push(*name);
        }
    }
    std::fs::write(dir.join("measure.txt"), text).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&disk);
    if let Err(e) = r {
        con.kill();
        return Err(format!("flatpak --measure: {e} (transcript in target/flatpak/measure.log)"));
    }
    if !over.is_empty() {
        return Err(format!("flatpak --measure: over budget: {}", over.join(", ")));
    }
    println!(
        "xtask: flatpak: measured ({:.0}s); target/flatpak/measure.txt, transcript in target/flatpak/measure.log",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_in_lines() {
        assert_eq!(number_after("slate-linux: timing: runtime entered 1234 us", "entered"), Some(1234.0));
        assert_eq!(number_after("strata-stats: frames=12 full=0", "frames"), Some(12.0));
        assert_eq!(number_after("x key_n=3 key_avg_us=9", "key_n"), Some(3.0));
        assert_eq!(number_after("nothing", "frames"), None);
        assert_eq!(number_after("[1.0, 3.0] median 1234", "median"), Some(1234.0));
        assert_eq!(number_after("x, first frame 125 ms", "first frame"), Some(125.0));
    }
}
