// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-box, the person's command for Linux boxes (ADR 0183):
//!
//! ```text
//! slate-box create NAME [--distro D] [--from URL] [--mirror URL]
//! slate-box enter NAME
//! slate-box run NAME [--root] [--here] [--] COMMAND [ARGUMENT...]
//! slate-box list
//! slate-box remove NAME [--yes]
//! slate-box distros
//! slate-box setup [--distro D] [--from URL] [--mirror URL]
//! slate-box sync
//! slate-box here | not-here
//! slate-box installs [NAME]
//! slate-box undo [NAME] RECEIPT
//! slate-box rollback [NAME] RECEIPT [--yes]
//! slate-box show [NAME]
//! slate-box share [NAME] FOLDER | unshare [NAME] FOLDER
//! slate-box network [NAME] on|off
//! slate-box clean [NAME]
//! slate-box remove-base DISTRO
//! ```
//!
//! `list` shows each box's own disk use (what removing it frees, its
//! receipts' snapshots counted in), the bases' and the disk's free space,
//! and warns when that runs low; `clean` empties a box's package cache;
//! `remove-base` removes a distribution's base no box uses (phase 6).
//!
//! `show` lists what a box may reach (phase 5): folders shared for good
//! (`share`, `unshare`; in the person's home, at their own paths), the
//! network (`network off` leaves it only a loopback); everything else of
//! SlateOS's stays out of its sight.
//!
//! `installs` lists a box's install receipts (the person's Linux system's
//! unless NAME), `undo` takes one back, `rollback` returns the box to
//! before one (ADR 0183's phase 4).
//!
//! `setup` makes the person's own Linux system (the box `linux`; ADR
//! 0183's phase 3), `sync` brings its commands' links up to date, `here`
//! marks the current folder as Linux source (`not-here` as SlateOS's).
//! Started under another name (a link in the farm, [`crate::native`]),
//! slate-box runs that program in the person's Linux system, in the
//! folder they're in.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, println, process, signal};

use crate::proto::{self, Facts, fact};
use crate::session::{self, Spec};

const USAGE: &str = "usage: slate-box create NAME [--distro D] [--from URL] [--mirror URL]
       slate-box enter NAME
       slate-box run NAME [--root] [--here] [--] COMMAND [ARGUMENT...]
       slate-box list
       slate-box remove NAME [--yes]
       slate-box distros
       slate-box setup [--distro D] [--from URL] [--mirror URL]
       slate-box sync
       slate-box here | not-here
       slate-box installs [NAME]
       slate-box undo [NAME] RECEIPT
       slate-box rollback [NAME] RECEIPT [--yes]
       slate-box show [NAME]
       slate-box share [NAME] FOLDER | unshare [NAME] FOLDER
       slate-box network [NAME] on|off
       slate-box clean [NAME]
       slate-box remove-base DISTRO";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Cmd {
    Create { name: String, distro: String, from: Option<String>, mirror: Option<String> },
    Enter { name: String },
    Run { name: String, root: bool, here: bool, argv: Vec<String> },
    Setup { distro: String, from: Option<String>, mirror: Option<String> },
    Sync,
    Here { linux: bool },
    Installs { name: String },
    Undo { name: String, which: String },
    Rollback { name: String, which: String, yes: bool },
    Show { name: String },
    Share { name: String, folder: String, on: bool },
    Network { name: String, on: bool },
    Clean { name: String },
    RemoveBase { distro: String },
    List,
    Remove { name: String, yes: bool },
    Distros,
}

pub fn parse(args: &[String]) -> Result<Cmd, String> {
    let usage = || String::from(USAGE);
    let (cmd, rest) = args.split_first().ok_or_else(usage)?;
    let name = || rest.first().filter(|n| !n.starts_with('-')).cloned().ok_or_else(usage);
    Ok(match cmd.as_str() {
        "create" | "setup" => {
            let setup = cmd == "setup";
            let n = if setup { String::from(crate::native::DEFAULT) } else { name()? };
            let (mut distro, mut from, mut mirror) = (String::from(crate::distro::DEFAULT), None, None);
            let mut i = usize::from(!setup);
            while let Some(a) = rest.get(i) {
                let v = rest.get(i + 1).cloned().ok_or_else(|| format!("{a} needs a value"))?;
                match a.as_str() {
                    "--distro" => distro = v,
                    "--from" => from = Some(v),
                    "--mirror" => mirror = Some(v),
                    _ => return Err(usage()),
                }
                i += 2;
            }
            if setup { Cmd::Setup { distro, from, mirror } } else { Cmd::Create { name: n, distro, from, mirror } }
        }
        "enter" if rest.len() == 1 => Cmd::Enter { name: name()? },
        "run" => {
            // `--root` and `--here` before or after the box's name; `--`
            // ends them.
            let (mut root, mut here) = (false, false);
            let mut name = None;
            let mut i = 0;
            while let Some(a) = rest.get(i) {
                match a.as_str() {
                    "--root" => root = true,
                    "--here" => here = true,
                    "--" => {
                        i += 1;
                        break;
                    }
                    s if s.starts_with('-') => return Err(usage()),
                    _ if name.is_none() => name = Some(a.clone()),
                    _ => break,
                }
                i += 1;
            }
            let argv = rest[i.min(rest.len())..].to_vec();
            match name {
                Some(n) if !argv.is_empty() => Cmd::Run { name: n, root, here, argv },
                _ => return Err(usage()),
            }
        }
        "list" | "ls" if rest.is_empty() => Cmd::List,
        "remove" | "rm" => {
            let n = name()?;
            let yes = match &rest[1..] {
                [] => false,
                [y] if y == "--yes" || y == "-y" => true,
                _ => return Err(usage()),
            };
            Cmd::Remove { name: n, yes }
        }
        "distros" if rest.is_empty() => Cmd::Distros,
        "sync" if rest.is_empty() => Cmd::Sync,
        "installs" => match rest {
            [] => Cmd::Installs { name: String::from(crate::native::DEFAULT) },
            [n] => Cmd::Installs { name: n.clone() },
            _ => return Err(usage()),
        },
        "show" => match rest {
            [] => Cmd::Show { name: String::from(crate::native::DEFAULT) },
            [n] => Cmd::Show { name: n.clone() },
            _ => return Err(usage()),
        },
        "share" | "unshare" => {
            let (name, folder) = match rest {
                [f] => (String::from(crate::native::DEFAULT), f.clone()),
                [n, f] => (n.clone(), f.clone()),
                _ => return Err(usage()),
            };
            Cmd::Share { name, folder, on: cmd == "share" }
        }
        "clean" => match rest {
            [] => Cmd::Clean { name: String::from(crate::native::DEFAULT) },
            [n] => Cmd::Clean { name: n.clone() },
            _ => return Err(usage()),
        },
        "remove-base" => match rest {
            [d] => Cmd::RemoveBase { distro: d.clone() },
            _ => return Err(usage()),
        },
        "network" => {
            let (name, v) = match rest {
                [v] => (String::from(crate::native::DEFAULT), v.as_str()),
                [n, v] => (n.clone(), v.as_str()),
                _ => return Err(usage()),
            };
            match v {
                "on" | "off" => Cmd::Network { name, on: v == "on" },
                _ => return Err(usage()),
            }
        }
        "undo" | "rollback" => {
            let yes = rest.iter().any(|a| a == "--yes" || a == "-y");
            let words: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
            let (name, which) = match words.as_slice() {
                [w] => (String::from(crate::native::DEFAULT), (*w).clone()),
                [n, w] => ((*n).clone(), (*w).clone()),
                _ => return Err(usage()),
            };
            if cmd == "undo" { Cmd::Undo { name, which } } else { Cmd::Rollback { name, which, yes } }
        }
        "here" if rest.is_empty() => Cmd::Here { linux: true },
        "not-here" if rest.is_empty() => Cmd::Here { linux: false },
        _ => return Err(usage()),
    })
}

pub fn main() -> i32 {
    let all = slate_rt::env::args();
    let args: Vec<String> = all.iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    // Started from the farm: the program of that name, in Linux, here.
    let me = all.first().map(|a| String::from(slate_rt::lossy(fs::basename(a)))).unwrap_or_default();
    if !me.is_empty() && me != "slate-box" {
        let mut argv = alloc::vec![me];
        argv.extend(args);
        return match run(crate::native::DEFAULT, false, true, &argv) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("{}: {e}", argv[0]);
                126
            }
        };
    }
    let r = parse(&args).and_then(|c| match c {
        Cmd::Create { name, distro, from, mirror } => {
            create(&name, &distro, from.as_deref(), mirror.as_deref()).map(|()| 0)
        }
        Cmd::Enter { name } => enter(&name),
        Cmd::Run { name, root, here, argv } => run(&name, root, here, &argv),
        Cmd::Setup { distro, from, mirror } => setup(&distro, from.as_deref(), mirror.as_deref()).map(|()| 0),
        Cmd::Sync => sync(true).map(|()| 0),
        Cmd::Installs { name } => installs(&name).map(|()| 0),
        Cmd::Undo { name, which } => undo(&name, &which).map(|()| 0),
        Cmd::Rollback { name, which, yes } => rollback(&name, &which, yes).map(|()| 0),
        Cmd::Show { name } => show_grants(&name).map(|()| 0),
        Cmd::Clean { name } => clean(&name).map(|()| 0),
        Cmd::RemoveBase { distro } => proto::ask(&["remove-base", &distro], &mut |s| show(s)).map(|_| 0),
        Cmd::Share { name, folder, on } => share(&name, &folder, on).map(|()| 0),
        Cmd::Network { name, on } => {
            proto::ask(&["set", &name, "network", if on { "on" } else { "off" }], &mut |s| show(s))?;
            show(&format!("The box {name} {} the network", if on { "has" } else { "doesn't have" }));
            Ok(0)
        }
        Cmd::Here { linux } => {
            let cwd = fs::getcwd().map(|c| String::from(slate_rt::lossy(&c))).map_err(|e| format!("{e}"))?;
            crate::native::mark(&cwd, linux)?;
            show(&if linux {
                format!("{cwd} is a Linux source folder: its programs and scripts run in Linux")
            } else {
                format!("{cwd} is SlateOS's: its programs and scripts run in SlateOS")
            });
            Ok(0)
        }
        Cmd::List => list().map(|()| 0),
        Cmd::Remove { name, yes } => remove(&name, yes).map(|()| 0),
        Cmd::Distros => distros().map(|()| 0),
    });
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("slate-box: {e}");
            if e.starts_with("usage") { 2 } else { 1 }
        }
    }
}

fn show(s: &str) {
    println!("{s}");
    let _ = slate_rt::io::flush_stdout();
}

/// Make the person's own Linux system unless it is there, and its
/// commands' links.
fn setup(distro: &str, from: Option<&str>, mirror: Option<&str>) -> Result<(), String> {
    let facts = proto::ask(&["list"], &mut |s| show(s))?;
    let there = facts.iter().any(|(k, v)| k == "box" && v.split('\t').next() == Some(crate::native::DEFAULT));
    if !there {
        eprintln!("slate-box: setting up your Linux system (once), for Linux programs in SlateOS's terminal");
        let fields = ["create", crate::native::DEFAULT, distro, from.unwrap_or(""), mirror.unwrap_or("")];
        proto::ask(&fields, &mut |s| eprintln!("slate-box: {s}"))?;
    }
    sync(!there)
}

/// Bring the person's Linux system's command links up to date (`first`:
/// right after it was made); say what is new.
fn sync(first: bool) -> Result<(), String> {
    let facts = proto::ask(&["open", crate::native::DEFAULT], &mut |_| {})?;
    let added = crate::native::sync(fact(&facts, "root").unwrap_or(""))?;
    if let Some(note) = crate::native::added_note(&added, first) {
        eprintln!("{note}");
    }
    Ok(())
}

fn create(name: &str, distro: &str, from: Option<&str>, mirror: Option<&str>) -> Result<(), String> {
    let fields = ["create", name, distro, from.unwrap_or(""), mirror.unwrap_or("")];
    proto::ask(&fields, &mut |s| show(s))?;
    show(&format!("Made the Linux box {name}. Enter it with: slate-box enter {name}"));
    Ok(())
}

/// Bytes for people: `1.2 GB`, `350 MB`, `12 KB`.
pub fn human(b: u64) -> String {
    match b {
        b if b >= 1 << 30 => format!("{}.{} GB", b >> 30, ((b & ((1 << 30) - 1)) * 10) >> 30),
        b if b >= 1 << 20 => format!("{} MB", b >> 20),
        b => format!("{} KB", b.div_ceil(1024)),
    }
}

/// Whether the disk is low: under a tenth free.
pub fn low(free: u64, size: u64) -> bool {
    size > 0 && free < size / 10
}

/// Warn before an install or a shell when the boxes' disk runs low.
fn warn_if_low() {
    if let Ok(s) = fs::statfs(crate::BOXES.as_bytes()) {
        let b = s.block_size.max(0) as u64;
        let (free, size) = (s.available.saturating_mul(b), s.blocks.saturating_mul(b));
        if low(free, size) {
            eprintln!(
                "slate-box: warning: the disk your Linux boxes are on has {} free of {}; `slate-box list` shows what they take",
                human(free),
                human(size)
            );
        }
    }
}

fn list() -> Result<(), String> {
    let facts = proto::ask(&["usage"], &mut |s| show(s))?;
    let boxes: Vec<&String> = facts.iter().filter(|(k, _)| k == "box").map(|(_, v)| v).collect();
    if boxes.is_empty() {
        show(
            "You have no Linux boxes. `slate-box setup` makes your Linux system; `slate-box create NAME` another box.",
        );
    }
    for b in boxes {
        let f: Vec<&str> = b.split('\t').collect();
        if let [name, title, own, _] = f.as_slice() {
            show(&format!("{name:<20} {title:<26} {:>9} its own", human(own.parse().unwrap_or(0))));
        }
    }
    for b in facts.iter().filter(|(k, _)| k == "base").map(|(_, v)| v) {
        let f: Vec<&str> = b.split('\t').collect();
        if let [_, title, own, _, users] = f.as_slice() {
            show(&format!(
                "{:<47} {:>9} shared by {users} boxes",
                format!("{title} (the base)"),
                human(own.parse().unwrap_or(0))
            ));
        }
    }
    if let Some(d) = fact(&facts, "disk") {
        let (free, size) = d.split_once('\t').unwrap_or(("0", "0"));
        let (free, size) = (free.parse().unwrap_or(0), size.parse().unwrap_or(0));
        show(&format!("Free on their disk: {} of {}", human(free), human(size)));
        if low(free, size) {
            show(
                "Warning: under a tenth of the disk is free. `slate-box clean` empties a box's package cache; `slate-box remove NAME` removes one.",
            );
        }
    }
    Ok(())
}

/// Empty box `name`'s package cache; say what that freed.
fn clean(name: &str) -> Result<(), String> {
    let own = |facts: &Facts| -> u64 {
        facts
            .iter()
            .filter(|(k, _)| k == "box")
            .find_map(|(_, v)| {
                let f: Vec<&str> = v.split('\t').collect();
                (f.first() == Some(&name)).then(|| f.get(2).and_then(|o| o.parse().ok()).unwrap_or(0))
            })
            .unwrap_or(0)
    };
    let before = own(&proto::ask(&["usage"], &mut |_| {})?);
    let facts = proto::ask(&["open", name], &mut |_| {})?;
    let cmd = fact(&facts, "clean").unwrap_or("");
    if cmd.is_empty() {
        return Err(format!("{name}'s distribution has no package cache to clean"));
    }
    let s = spec(name, &facts, true, alloc::vec![b"/bin/sh".to_vec(), b"-c".to_vec(), cmd.as_bytes().to_vec()]);
    let (code, _) = session(name, fact(&facts, "title").unwrap_or(""), &s)?;
    if code != 0 {
        return Err(format!("`{cmd}` failed (exit status {code})"));
    }
    let after = own(&proto::ask(&["usage"], &mut |_| {})?);
    show(&format!("Cleaned {name}'s package cache: {} freed", human(before.saturating_sub(after))));
    Ok(())
}

fn distros() -> Result<(), String> {
    for (_, v) in proto::ask(&["distros"], &mut |s| show(s))? {
        let f: Vec<&str> = v.split('\t').collect();
        show(&format!("{:<12} {} {}", f[0], f.get(1).unwrap_or(&""), f.get(2).unwrap_or(&"")));
    }
    Ok(())
}

fn remove(name: &str, yes: bool) -> Result<(), String> {
    if !yes {
        if !slate_rt::term::isatty(0) {
            return Err(format!("removing the box {name} deletes everything in it: add --yes"));
        }
        slate_rt::print!("Remove the Linux box {name} and everything in it? [y/N] ");
        let _ = slate_rt::io::flush_stdout();
        let mut b = [0u8; 64];
        let n = slate_rt::io::read(0, &mut b).unwrap_or(0);
        if !matches!(b[..n].first(), Some(b'y' | b'Y')) {
            return Err(String::from("not removed"));
        }
    }
    proto::ask(&["remove", name], &mut |s| show(s)).map(|_| ())
}

/// Linux programs need Linux compatibility mode (ADR 0032).
fn compat_on() -> Result<(), String> {
    match fs::read_file(b"/proc/sys/slate/linux_compat") {
        Ok(v) if v.first() == Some(&b'1') => Ok(()),
        _ => Err(String::from(
            "a Linux box runs Linux programs, which need Linux compatibility mode: turn it on with `slate-compat on` (as root)",
        )),
    }
}

/// The session for box `name`, as its user (or its root), running `argv`.
fn spec(name: &str, facts: &Facts, root: bool, argv: Vec<Vec<u8>>) -> Spec {
    let get = |k: &str| String::from(fact(facts, k).unwrap_or(""));
    let (user, home) = if root { (String::from("root"), String::from("/root")) } else { (get("user"), get("home")) };
    let mut env: Vec<String> = alloc::vec![
        format!("HOME={home}"),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
        format!("SHELL={}", get("shell")),
        format!("PATH={}", session::BOX_PATH),
        format!("SLATE_BOX={name}"),
        format!("SLATE_BOX_DISTRO={}", get("title")),
    ];
    let lang = slate_rt::env::var(b"LANG").map(|l| String::from(slate_rt::lossy(&l)));
    env.push(format!("LANG={}", lang.unwrap_or_else(|| String::from("C.UTF-8"))));
    // The person's time zone (Slate's setting; the box has the zones).
    if let Ok(z) = fs::read_file(slate_rt::tz::SETTING) {
        let z = String::from(slate_rt::lossy(&z).trim());
        if !z.is_empty() {
            env.push(format!("TZ={z}"));
        }
    }
    for keep in ["TERM", "COLORTERM"] {
        if let Some(v) = slate_rt::env::var(keep.as_bytes()) {
            env.push(format!("{keep}={}", slate_rt::lossy(&v)));
        }
    }
    let groups: Vec<u32> =
        if root { alloc::vec![0] } else { get("groups").split(',').filter_map(|g| g.parse().ok()).collect() };
    let id = if root { 0 } else { crate::ids::PERSON };
    Spec {
        name: String::from(name),
        root: get("root"),
        uid: id,
        gid: id,
        groups,
        cwd: home,
        argv,
        env: env.into_iter().map(String::into_bytes).collect(),
        network: fact(facts, "network") != Some("off"),
        tty: if slate_rt::term::isatty(0) { process::ttyname(0) } else { None },
        output: None,
        share: None,
        // The folders shared for good, still folders of the person's.
        shares: facts
            .iter()
            .filter(|(k, v)| k == "share" && fs::stat(v.as_bytes()).is_ok_and(|s| s.is_dir()))
            .map(|(_, v)| v.clone())
            .collect(),
        host_dir: None,
    }
}

/// Run a session of box `name` (`title` its distribution), with its
/// channel's agent: its exit status, and whether something was installed
/// through the channel.
fn session(name: &str, title: &str, s: &Spec) -> Result<(i32, bool), String> {
    // The box's command takes Ctrl-C; this waits for it.
    let _ = signal::set(signal::SIGINT, signal::Disposition::Ignore);
    let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
    let about = crate::agent::About { name: String::from(name), title: String::from(title), shared: s.share.clone() };
    let agent = crate::agent::Agent::start(&about)?;
    let mut s = s.clone();
    s.host_dir = Some(agent.dir.clone());
    let r = session::run(&s, &mut |pid| proto::ask(&["map", &format!("{pid}"), name], &mut |_| {}).map(|_| ()));
    let installed = agent.installed();
    agent.stop();
    r.map(|code| (code, installed))
}

/// Say what an install receipt kept, in box `name`.
fn receipt_note(name: &str, fact: &str) {
    let f: Vec<&str> = fact.split('\t').collect();
    if let [_, label, count] = f.as_slice() {
        let undo = if name == crate::native::DEFAULT {
            format!("slate-box undo {label}")
        } else {
            format!("slate-box undo {name} {label}")
        };
        eprintln!(
            "slate-box: kept a receipt of what this changed: \"{label}\" ({count} files); `{undo}` takes it back"
        );
    }
}

/// What box `name` may reach.
fn show_grants(name: &str) -> Result<(), String> {
    let facts = proto::ask(&["open", name], &mut |_| {})?;
    show(&format!("{name}: {}", fact(&facts, "title").unwrap_or("")));
    show(&format!(
        "  network: {}",
        if fact(&facts, "network") == Some("off") {
            "off (loopback only)"
        } else {
            "on (outbound; nothing can reach in)"
        }
    ));
    let shares: Vec<&String> = facts.iter().filter(|(k, _)| k == "share").map(|(_, v)| v).collect();
    if shares.is_empty() {
        show("  folders: none shared for good (a command run from SlateOS's terminal sees the folder it was run in)");
    }
    for s in shares {
        show(&format!("  folder: {s}"));
    }
    show("  everything else of SlateOS's: not in its sight");
    Ok(())
}

/// Share `folder` with box `name` for good, or stop.
fn share(name: &str, folder: &str, on: bool) -> Result<(), String> {
    let cwd = fs::getcwd().map(|c| String::from(slate_rt::lossy(&c))).unwrap_or_default();
    let full =
        if folder.starts_with('/') { String::from(folder) } else { format!("{}/{folder}", cwd.trim_end_matches('/')) };
    // As the person sees it (links followed), so the box gets that folder.
    let real = if fs::chdir(full.as_bytes()).is_ok() {
        let r = fs::getcwd().map(|c| String::from(slate_rt::lossy(&c))).unwrap_or(full.clone());
        let _ = fs::chdir(cwd.as_bytes());
        r
    } else {
        full
    };
    proto::ask(&["set", name, "share", &format!("{}{real}", if on { '+' } else { '-' })], &mut |s| show(s))?;
    show(&if on {
        format!("{real} is shared with the box {name}")
    } else {
        format!("{real} isn't shared with the box {name} any more")
    });
    Ok(())
}

fn installs(name: &str) -> Result<(), String> {
    let facts = proto::ask(&["installs", name], &mut |s| show(s))?;
    let rows: Vec<&String> = facts.iter().filter(|(k, _)| k == "receipt").map(|(_, v)| v).collect();
    if rows.is_empty() {
        show(&format!("Nothing has been installed in {name} since it was made."));
    }
    for r in rows {
        let f: Vec<&str> = r.split('\t').collect();
        if let [n, label, when, count] = f.as_slice() {
            let tm = slate_rt::time::gmtime(when.parse().unwrap_or(0));
            show(&format!(
                "{n:>3}  {label:<32} {:04}-{:02}-{:02} {:02}:{:02} UTC  {count} files",
                tm.year, tm.month, tm.day, tm.hour, tm.min
            ));
        }
    }
    Ok(())
}

/// After an undo or rollback in the person's Linux system: its library
/// cache and its commands' links follow.
fn after_change(name: &str) {
    if name != crate::native::DEFAULT {
        return;
    }
    if let Ok(facts) = proto::ask(&["open", name], &mut |_| {}) {
        let s = spec(name, &facts, true, alloc::vec![b"ldconfig".to_vec()]);
        let _ = session(name, fact(&facts, "title").unwrap_or(""), &s);
    }
    let _ = sync(false);
}

fn undo(name: &str, which: &str) -> Result<(), String> {
    let facts = proto::ask(&["undo", name, which], &mut |s| show(s))?;
    if let Some(u) = fact(&facts, "undone") {
        let (label, count) = u.split_once('\t').unwrap_or((u, "?"));
        show(&format!("Undid \"{label}\": {count} files as they were before it"));
    }
    after_change(name);
    Ok(())
}

fn rollback(name: &str, which: &str, yes: bool) -> Result<(), String> {
    if !yes {
        if !slate_rt::term::isatty(0) {
            return Err(format!("rolling back undoes {which} and every install after it: add --yes"));
        }
        slate_rt::print!("Take {name} back to before \"{which}\", undoing it and every install after it? [y/N] ");
        let _ = slate_rt::io::flush_stdout();
        let mut b = [0u8; 64];
        let n = slate_rt::io::read(0, &mut b).unwrap_or(0);
        if !matches!(b[..n].first(), Some(b'y' | b'Y')) {
            return Err(String::from("not rolled back"));
        }
    }
    proto::ask(&["rollback", name, which], &mut |s| show(s))?;
    after_change(name);
    Ok(())
}

fn enter(name: &str) -> Result<i32, String> {
    compat_on()?;
    warn_if_low();
    let facts = proto::ask(&["open", name], &mut |s| show(s))?;
    let shell = String::from(fact(&facts, "shell").unwrap_or("/bin/sh"));
    let s = spec(name, &facts, false, alloc::vec![shell.into_bytes(), b"-l".to_vec()]);
    eprintln!(
        "Entering the Linux box {name} ({}): Linux programs, apart from SlateOS. Type exit to come back.",
        fact(&facts, "title").unwrap_or("Linux")
    );
    let (code, installed) = session(name, fact(&facts, "title").unwrap_or(""), &s)?;
    eprintln!("Back in SlateOS.");
    if installed && name == crate::native::DEFAULT {
        let _ = sync(false);
    }
    Ok(code)
}

fn run(name: &str, root: bool, here: bool, argv: &[String]) -> Result<i32, String> {
    compat_on()?;
    let default = name == crate::native::DEFAULT;
    let facts = match proto::ask(&["open", name], &mut |s| show(s)) {
        // The person's own Linux system is made the first time it is needed.
        Err(e) if default && e.starts_with("you have no box") => {
            setup(crate::distro::DEFAULT, None, None)?;
            proto::ask(&["open", name], &mut |s| show(s))?
        }
        r => r?,
    };
    let mut s = spec(name, &facts, root, argv.iter().map(|a| a.clone().into_bytes()).collect());
    let cwd = fs::getcwd().map(|c| String::from(slate_rt::lossy(&c))).unwrap_or_default();
    let box_root = fact(&facts, "root").unwrap_or("\0");
    if let Some(inside) = cwd.strip_prefix(box_root) {
        // In the box's own files (from Slate): that folder, inside.
        s.cwd = if inside.is_empty() { String::from("/") } else { String::from(inside) };
    } else if here && let Some(dir) = crate::native::share(&cwd, &crate::native::home()) {
        // The folder the person is in, at the same path.
        s.cwd = dir.clone();
        s.share = Some(dir);
    }
    // A command as the box's root is kept as an install receipt.
    if root {
        warn_if_low();
    }
    let receipt = if root {
        let label = crate::receipts::label_for(argv, &s.cwd);
        let command = argv.join(" ");
        proto::ask(&["begin", name, &label, &command], &mut |_| {})
            .map(|f| fact(&f, "receipt").is_some())
            .unwrap_or_else(|e| {
                eprintln!("slate-box: no install receipt for this ({e})");
                false
            })
    } else {
        false
    };
    let r = session(name, fact(&facts, "title").unwrap_or(""), &s);
    if receipt {
        match proto::ask(&["end", name], &mut |_| {}) {
            Ok(f) => {
                if let Some(r) = fact(&f, "receipt") {
                    receipt_note(name, r);
                }
            }
            Err(e) => eprintln!("slate-box: the install receipt: {e}"),
        }
    }
    let (code, installed) = r?;
    // What was installed: the Linux system's new commands.
    if (root || installed) && default {
        let _ = sync(false);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sizes() {
        assert_eq!(human(1288490189), "1.2 GB");
        assert_eq!(human(350 << 20), "350 MB");
        assert_eq!(human(5000), "5 KB");
        assert!(low(9, 100) && !low(10, 100) && !low(0, 0));
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            parse(&a(&["create", "dev"])).unwrap(),
            Cmd::Create { name: "dev".into(), distro: "arch".into(), from: None, mirror: None }
        );
        assert_eq!(
            parse(&a(&["create", "t", "--distro", "test", "--from", "http://x/r.tar.zst", "--mirror", "http://m"]))
                .unwrap(),
            Cmd::Create {
                name: "t".into(),
                distro: "test".into(),
                from: Some("http://x/r.tar.zst".into()),
                mirror: Some("http://m".into())
            }
        );
        assert_eq!(parse(&a(&["enter", "dev"])).unwrap(), Cmd::Enter { name: "dev".into() });
        assert_eq!(
            parse(&a(&["run", "dev", "--root", "--", "pacman", "-Syu"])).unwrap(),
            Cmd::Run { name: "dev".into(), root: true, here: false, argv: a(&["pacman", "-Syu"]) }
        );
        assert_eq!(
            parse(&a(&["run", "--root", "dev", "id"])).unwrap(),
            Cmd::Run { name: "dev".into(), root: true, here: false, argv: a(&["id"]) }
        );
        assert_eq!(
            parse(&a(&["run", "dev", "make", "--root"])).unwrap(),
            Cmd::Run { name: "dev".into(), root: false, here: false, argv: a(&["make", "--root"]) }
        );
        assert_eq!(
            parse(&a(&["run", "--here", "linux", "--", "./configure"])).unwrap(),
            Cmd::Run { name: "linux".into(), root: false, here: true, argv: a(&["./configure"]) }
        );
        assert_eq!(
            parse(&a(&["setup", "--distro", "test"])).unwrap(),
            Cmd::Setup { distro: "test".into(), from: None, mirror: None }
        );
        assert_eq!(parse(&a(&["here"])).unwrap(), Cmd::Here { linux: true });
        assert_eq!(parse(&a(&["sync"])).unwrap(), Cmd::Sync);
        assert_eq!(parse(&a(&["rm", "dev", "--yes"])).unwrap(), Cmd::Remove { name: "dev".into(), yes: true });
        assert_eq!(parse(&a(&["list"])).unwrap(), Cmd::List);
        for bad in [&[][..], &["enter"], &["run", "dev"], &["create", "dev", "--distro"], &["frob"], &["enter", "-x"]] {
            assert!(parse(&a(bad)).is_err(), "{bad:?}");
        }
    }
}
