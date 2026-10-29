// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Strata stress scenario (M22 phase 7, ADR 0068): a minute of use,
//! checked for crashes, leaks and growth. Each round opens three
//! terminals, types into them, snaps and maximises them, sweeps the
//! pointer over them, opens and searches the launcher, switches
//! workspaces and back, and closes the terminals again. After two rounds
//! to warm up, Strata's resident memory, its open descriptors, the
//! number of processes and the system's memory in use are noted; after
//! the last round they must be where they were (within small margins),
//! Strata must be the same process, and the kernel must have logged no
//! fault.

use std::time::{Duration, Instant};

use crate::bench::keys;
use crate::qemu::{Console, base_command, monitor, monitor_paced, mouse_index};
use crate::{Opts, Result, image, target_dir};

/// Rounds after the warm-up.
const ROUNDS: usize = 8;
/// How much Strata's resident memory may grow (KiB): allocator slack.
const RSS_SLACK_KIB: i64 = 512;
/// How much the system's memory in use may grow (KiB): page cache
/// metadata, the kernel's own caches.
const SYSTEM_SLACK_KIB: i64 = 2048;

/// What is noted after the warm-up and at the end.
#[derive(Debug, PartialEq)]
struct Sample {
    rss_kib: i64,
    fds: i64,
    used_kib: i64,
    /// The processes (`ps -e`'s pid and name, but `ps`).
    processes: Vec<String>,
}

fn sample(con: &mut Console, pid: &str) -> Result<Sample> {
    con.run(
        &format!(
            "echo SAMPLE $(grep VmRSS /proc/{pid}/status | tr -s ' \\t' ' ' | cut -d' ' -f2) $(ls /proc/{pid}/fd | wc -l) \
             $(awk '/^MemTotal/{{t=$2}} /^MemFree/{{f=$2}} /^Cached/{{c=$2}} END{{print t-f-c}}' \
             /proc/meminfo) end"
        ),
        " end",
        20,
    )?;
    let log = crate::qemu::strip_ansi(&con.log);
    let at = log.rfind("SAMPLE ").ok_or("no sample")?;
    let v: Vec<i64> = log[at + 7..].split_whitespace().take(3).filter_map(|w| w.parse().ok()).collect();
    let [rss_kib, fds, used_kib] = v[..] else {
        return Err(format!("a bad sample: {}", log[at..].lines().next().unwrap_or("")));
    };
    con.run("ps -e; echo ps-end$((1+1))", "ps-end2", 20)?;
    let log = crate::qemu::strip_ansi(&con.log);
    let end = log.rfind("ps-end2").ok_or("no ps")?;
    let start = log[..end].rfind("ps -e;").map_or(end, |s| s + 6);
    // PID TTY TIME CMD: the pid and the name.
    let processes = log[start..end]
        .lines()
        .skip(1)
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (w.len() >= 4 && w[3] != "ps").then(|| format!("{} {}", w[0], w[3]))
        })
        .collect();
    Ok(Sample { rss_kib, fds, used_kib, processes })
}

/// One round of use; the terminals it opens are closed again.
fn round(con: &mut Console, mon: &std::path::Path, mouse: &str) -> Result {
    for _ in 0..3 {
        monitor(mon, &["sendkey meta_l-ret"])?;
        con.wait_for("\"terminal\" from pid", 15)?;
    }
    std::thread::sleep(Duration::from_millis(500));
    monitor_paced(mon, &keys("echo stress"), 30)?;
    monitor(mon, &["sendkey ret"])?;
    for k in ["sendkey meta_l-left", "sendkey meta_l-right", "sendkey meta_l-up", "sendkey meta_l-up"] {
        monitor(mon, &[k])?;
    }
    let mut sweep = vec![format!("mouse_set {mouse}")];
    sweep.extend(std::iter::repeat_n("mouse_move 20 10".to_string(), 15));
    sweep.extend(std::iter::repeat_n("mouse_move -20 -10".to_string(), 15));
    monitor_paced(mon, &sweep, 16)?;
    monitor(mon, &["sendkey meta_l-spc"])?;
    monitor_paced(mon, &keys("te"), 60)?;
    monitor(mon, &["sendkey esc", "sendkey meta_l-2", "sendkey meta_l-1"])?;
    for _ in 0..3 {
        monitor(mon, &["sendkey meta_l-q"])?;
    }
    // The terminals and their shells are gone.
    con.run(
        "i=0; while ps -e | grep -q ' terminal$' && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done; \
         echo left $(ps -e | grep -c ' terminal$') end",
        "left 0 end",
        20,
    )
}

pub fn strata_stress(o: &Opts) -> Result {
    let started = Instant::now();
    let img = image::build(o, "", "slate-stress.img", image::Root::Disk)?;
    let mon = target_dir().join("stress-monitor.sock");
    let _ = std::fs::remove_file(&mon);
    let mut c = base_command(o, &img)?;
    c.args(["-display", "none", "-serial", "stdio", "-monitor"]);
    c.arg(format!("unix:{},server,nowait", mon.display()));
    let mut con = Console::start(c)?;
    let result = (|| -> Result<(Sample, Sample)> {
        con.login()?;
        con.send("strata &\r")?;
        con.wait_for("strata: 1280x800", 30)?;
        // Strata's own pid (`$!` would be the job's shell).
        con.run("echo strata-pid=$(ps -e | grep ' strata$' | tr -s ' ' | sed 's/^ //' | cut -d' ' -f1)", "", 10)?;
        let log = crate::qemu::strip_ansi(&con.log);
        let at = log.rfind("strata-pid=").ok_or("no pid for Strata")?;
        let pid: String = log[at + 11..].chars().take_while(char::is_ascii_digit).collect();
        if pid.is_empty() {
            return Err("Strata is not running".into());
        }
        let mouse = mouse_index(&mon, "PS/2 Mouse")?;
        for _ in 0..2 {
            round(&mut con, &mon, &mouse)?;
        }
        let before = sample(&mut con, &pid)?;
        for _ in 0..ROUNDS {
            round(&mut con, &mon, &mouse)?;
        }
        let after = sample(&mut con, &pid)?;
        // Strata is the same process, still running.
        con.run(&format!("echo alive $(grep -c strata /proc/{pid}/comm) end"), "alive 1 end", 10)?;
        con.poweroff()?;
        Ok((before, after))
    })();
    let (before, after) = match result {
        Ok(s) => s,
        Err(e) => {
            con.kill();
            return Err(format!("stress scenario: {e}"));
        }
    };
    let log = crate::qemu::strip_ansi(&con.log);
    // A kernel panic, a fatal fault in a program, the out-of-memory
    // killer, a signal that could not be delivered, a program's panic.
    let bad = ["KERNEL PANIC", " at rip ", "out of memory", "cannot deliver", ": internal error: "];
    if let Some(l) = log.lines().find(|l| bad.iter().any(|b| l.contains(b))) {
        return Err(format!("stress scenario: the kernel logged: {l}"));
    }
    let mut wrong = Vec::new();
    if after.rss_kib - before.rss_kib > RSS_SLACK_KIB {
        wrong.push(format!("Strata's memory grew from {} to {} KiB", before.rss_kib, after.rss_kib));
    }
    if after.fds != before.fds {
        wrong.push(format!("Strata had {} descriptors open, then {}", before.fds, after.fds));
    }
    if after.processes != before.processes {
        let new: Vec<&String> = after.processes.iter().filter(|l| !before.processes.contains(l)).collect();
        let gone: Vec<&String> = before.processes.iter().filter(|l| !after.processes.contains(l)).collect();
        wrong.push(format!("processes came or went (new: {new:?}; gone: {gone:?})"));
    }
    if after.used_kib - before.used_kib > SYSTEM_SLACK_KIB {
        wrong.push(format!("memory in use grew from {} to {} KiB", before.used_kib, after.used_kib));
    }
    if !wrong.is_empty() {
        return Err(format!("stress scenario: {}", wrong.join("; ")));
    }
    println!(
        "xtask: stress scenario passed ({} rounds of three terminals; Strata {} -> {} KiB, {} descriptors, {} processes, \
         memory in use {} -> {} KiB; {:.1}s)",
        ROUNDS + 2,
        before.rss_kib,
        after.rss_kib,
        after.fds,
        after.processes.len(),
        before.used_kib,
        after.used_kib,
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
