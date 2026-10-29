// SPDX-License-Identifier: MIT OR Apache-2.0

//! `cargo xtask soak [--minutes N]` (ADR 0047): hours of mixed load on the
//! installed system shape with the test load, checked for leaks and
//! failures. `tests/shell/soak.sh` runs the load; this side boots the
//! machine, serves the downloads, and judges the samples:
//!
//! - no kernel panic, and no failure listed by the load;
//! - after the load stops, memory in use (without the page cache) and the
//!   kernel heap are back within a margin of where they started idle, and
//!   so is the number of processes;
//! - while the load runs, memory in use does not keep growing: the last
//!   quarter of the run's samples is no higher than the first quarter's
//!   plus the margin.

use std::time::{Duration, Instant};

use crate::qemu::{Console, base_command};
use crate::{Opts, Result, image, target_dir};

/// The default length: an hour (the owner's choice, 2026-10-21).
const DEFAULT_MINUTES: u64 = 60;
/// How much memory in use or kernel heap may grow over the run (KiB).
const MARGIN_KIB: i64 = 16 * 1024;

#[derive(Debug, Clone, Copy)]
struct Sample {
    used: i64,
    heap: i64,
    procs: i64,
}

fn parse(line: &str) -> Option<(String, Sample)> {
    let rest = line.split("SOAK-SAMPLE ").nth(1)?;
    let mut w = rest.split_whitespace();
    let label = w.next()?.to_string();
    let field = |w: &mut std::str::SplitWhitespace, k: &str| -> Option<i64> { w.next()?.strip_prefix(k)?.parse().ok() };
    let used = field(&mut w, "used=")?;
    let heap = field(&mut w, "heap=")?;
    let procs = field(&mut w, "procs=")?;
    Some((label, Sample { used, heap, procs }))
}

pub fn soak(o: &Opts) -> Result {
    let minutes = o.minutes.unwrap_or(DEFAULT_MINUTES);
    let www = target_dir().join("soak-www");
    std::fs::create_dir_all(&www).map_err(|e| e.to_string())?;
    // A 3 MiB file of pseudo-random bytes to download.
    let mut x = 0x9E37_79B9u32;
    let big: Vec<u8> = (0..3 << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect();
    std::fs::write(www.join("big"), big).map_err(|e| e.to_string())?;
    let server = crate::hostnet::StaticServer::start(www)?;
    let opts = Opts { test_load: true, ..o.clone() };
    let img = image::build(&opts, "", "slate-soak.img", image::Root::Disk)?;
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio"]);
    let started = Instant::now();
    let mut con = Console::start(c)?;
    let log_path = target_dir().join("soak.log");
    let result = (|| -> Result {
        con.login()?;
        // SLATE_SOAK_WORKERS runs only some of the load (to find what grows).
        let workers = std::env::var("SLATE_SOAK_WORKERS").unwrap_or_default();
        con.send(&format!("sh /test/soak.sh {minutes} {} {workers}\r", server.port))?;
        // Report progress as the samples come.
        let end = Instant::now() + Duration::from_secs(minutes * 60 + 900);
        let mut seen = 0;
        loop {
            match con.wait_for_any(&["SOAK-DONE", "KERNEL PANIC", "SOAK-SAMPLE minute-"], 120) {
                Ok(0) => break,
                Ok(1) => return Err("kernel panic".into()),
                Ok(_) => {
                    seen += 1;
                    if seen % 10 == 0 {
                        println!("xtask: soak: {seen} of {minutes} minutes");
                    }
                }
                Err(e) if Instant::now() > end => return Err(e),
                Err(_) => {}
            }
        }
        con.wait_for("# ", 60)?;
        con.run("dmesg | grep -c -E ' (warn|error) ' ; echo dmesg$((1+1))", "dmesg2", 30)?;
        con.poweroff()
    })();
    server.stop();
    let _ = std::fs::write(&log_path, &con.log);
    if let Err(e) = result {
        con.kill();
        return Err(format!("soak: {e} (log in {})", log_path.display()));
    }
    let log = con.log.clone();
    let fails: i64 = log
        .split("SOAK-DONE fails=")
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .ok_or("soak: no SOAK-DONE line")?;
    let samples: Vec<(String, Sample)> = log.lines().filter_map(parse).collect();
    let get = |l: &str| samples.iter().find(|(k, _)| k == l).map(|(_, s)| *s);
    let before = get("idle-before").ok_or("soak: no idle-before sample")?;
    let after = get("idle-after").ok_or("soak: no idle-after sample")?;
    let running: Vec<Sample> = samples.iter().filter(|(k, _)| k.starts_with("minute-")).map(|(_, s)| *s).collect();
    let mut problems = Vec::new();
    if fails != 0 {
        problems.push(format!("{fails} failures in the load (see {})", log_path.display()));
    }
    if after.used - before.used > MARGIN_KIB {
        problems.push(format!("memory in use grew from {} to {} KiB", before.used, after.used));
    }
    if after.heap - before.heap > MARGIN_KIB {
        problems.push(format!("the kernel heap grew from {} to {} KiB", before.heap, after.heap));
    }
    if after.procs > before.procs {
        problems.push(format!("{} processes before, {} after", before.procs, after.procs));
    }
    if running.len() >= 8 {
        let q = running.len() / 4;
        let avg = |s: &[Sample]| s.iter().map(|x| x.used).sum::<i64>() / s.len() as i64;
        let (first, last) = (avg(&running[..q]), avg(&running[running.len() - q..]));
        if last - first > MARGIN_KIB {
            problems.push(format!("memory in use under load grew from {first} to {last} KiB"));
        }
    }
    println!(
        "xtask: soak: {} minutes; idle before {before:?}, after {after:?}; {} samples under load",
        minutes,
        running.len()
    );
    if !problems.is_empty() {
        return Err(format!("soak failed: {}", problems.join("; ")));
    }
    println!("xtask: soak passed ({:.0} min, log in {})", started.elapsed().as_secs_f64() / 60.0, log_path.display());
    Ok(())
}
