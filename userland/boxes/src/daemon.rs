// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-boxd (ADR 0183), a slinit service: root, in the Slate domain. It
//! answers [`proto`](crate::proto)'s requests on /run/slate-boxd.sock, a
//! process for each connection, from Slate's own programs only (the
//! peer's domain, from /proc): no Linux program, and so nothing in a box,
//! can ask it anything. Each request acts for the asker's own boxes (the
//! peer's user ID); boxes are for people (IDs from 1000), not root or the
//! system's accounts.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, net, process, signal};

use crate::base::{self, Say};
use crate::proto::{self, Answer};
use crate::{BASES, BOXES, STATE, distro, ids, receipts};

/// The space a new base asks for (MiB): Arch's bootstrap and base-devel
/// take about 1.2 GB, and the tarball is kept while it is unpacked.
pub const BASE_NEEDS_MIB: u64 = 2048;
/// The space a new box asks for (MiB), beyond its base.
pub const BOX_NEEDS_MIB: u64 = 256;

/// Whether the program at `pid` is Slate's own (the Slate domain).
fn slate_domain(pid: i32) -> bool {
    status_field(pid, "Domain:").as_deref() == Some("slate")
}

/// A field of /proc/PID/status.
fn status_field(pid: i32, key: &str) -> Option<String> {
    let status = fs::read_file(format!("/proc/{pid}/status").as_bytes()).ok()?;
    slate_rt::lossy(&status).lines().find_map(|l| Some(String::from(l.strip_prefix(key)?.trim())))
}

/// Space free for the boxes (MiB).
fn free_mib() -> Option<u64> {
    let s = fs::statfs(BOXES.as_bytes()).ok()?;
    Some(s.available.saturating_mul(s.block_size.max(0) as u64) >> 20)
}

/// Refuse to start what needs `need` MiB when less is free.
pub fn room_for(free: Option<u64>, need: u64, what: &str) -> Result<(), String> {
    match free {
        Some(f) if f < need => Err(format!(
            "{what} needs about {} of free space, and this disk has {} free",
            human_mib(need),
            human_mib(f)
        )),
        _ => Ok(()),
    }
}

/// MiB for people: `2.0 GB`, `300 MB`.
pub fn human_mib(m: u64) -> String {
    if m >= 1024 { format!("{}.{} GB", m / 1024, (m % 1024) * 10 / 1024) } else { format!("{m} MB") }
}

fn ready_folders() {
    for (d, mode) in [(BOXES, 0o755), (STATE, 0o700), (BASES, 0o700)] {
        let _ = fs::mkdir(d.as_bytes(), mode);
        let _ = fs::chmod(d.as_bytes(), mode);
    }
}

/// Mount every box and base that isn't (after a boot).
fn mount_all() {
    for n in base::numbers().0 {
        let (sv, at) = match n.kind.as_str() {
            "base" => (format!("box-base.{}", n.name), format!("{BASES}/{}", n.name)),
            _ => (format!("box.{}.{}", n.owner, n.name), format!("{BOXES}/{}/{}", n.owner, n.name)),
        };
        if base::has_subvol(&sv)
            && let Err(e) = base::mount_subvol(&sv, &at)
        {
            eprintln!("slate-boxd: {e}");
        }
    }
}

pub fn main() -> i32 {
    ready_folders();
    if let Err(e) = base::device() {
        eprintln!("slate-boxd: {e}; boxes can't be made here");
    } else {
        mount_all();
    }
    let l = match net::listen_path(crate::SOCKET.as_bytes(), 16) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("slate-boxd: {}: {e}", crate::SOCKET);
            return 1;
        }
    };
    let _ = fs::chmod(crate::SOCKET.as_bytes(), 0o666);
    // Children are reaped by the kernel.
    let _ = signal::set(signal::SIGCHLD, signal::Disposition::Ignore);
    eprintln!("slate-boxd: answering on {}", crate::SOCKET);
    loop {
        let c = match net::accept(l) {
            Ok(c) => c,
            Err(slate_rt::Errno::EINTR) => continue,
            Err(e) => {
                eprintln!("slate-boxd: accept: {e}");
                continue;
            }
        };
        match process::fork() {
            Ok(0) => {
                let _ = io::close(l);
                let _ = signal::set(signal::SIGCHLD, signal::Disposition::Default);
                serve(c);
                process::exit_now(0)
            }
            Ok(_) => {}
            Err(e) => eprintln!("slate-boxd: fork: {e}"),
        }
        let _ = io::close(c);
    }
}

/// Read a request's line (at most 4 KiB).
fn request(fd: i32) -> Option<String> {
    let mut line = Vec::new();
    let mut b = [0u8; 512];
    while !line.contains(&b'\n') && line.len() < 4096 {
        match io::read(fd, &mut b) {
            Ok(0) => break,
            Ok(n) => line.extend_from_slice(&b[..n]),
            Err(slate_rt::Errno::EINTR) => {}
            Err(_) => return None,
        }
    }
    let end = line.iter().position(|&c| c == b'\n')?;
    Some(String::from(slate_rt::lossy(&line[..end])))
}

fn serve(fd: i32) {
    let send = |a: Answer| {
        let _ = io::write_all(fd, a.text().as_bytes());
    };
    let Ok((pid, uid, gid)) = net::peer_cred(fd) else { return };
    let Some(line) = request(fd) else { return };
    let f = proto::fields(&line);
    if !slate_domain(pid) {
        eprintln!("slate-boxd: refused {:?} from pid {pid}: not a program of SlateOS's own", f.first());
        send(Answer::Error(String::from("slate-boxd answers SlateOS's own programs only")));
        return;
    }
    let mut say = |s: &str| send(Answer::Say(String::from(s)));
    let mut facts = Vec::new();
    let r = handle(&f, pid, uid, gid, &mut say, &mut facts);
    for (k, v) in facts {
        send(Answer::Is(k, v));
    }
    match r {
        Ok(()) => send(Answer::Ok),
        Err(e) => {
            eprintln!("slate-boxd: {} for uid {uid}: {e}", f.first().map(String::as_str).unwrap_or("?"));
            send(Answer::Error(e));
        }
    }
}

type Facts = Vec<(String, String)>;

fn handle(f: &[String], pid: i32, uid: u32, gid: u32, say: Say, facts: &mut Facts) -> Result<(), String> {
    let arg = |i: usize| f.get(i).map(String::as_str).ok_or_else(|| String::from("a request is missing a field"));
    match f.first().map(String::as_str) {
        Some("distros") => {
            for n in distro::all() {
                if let Ok(d) = distro::load(&n) {
                    facts.push((String::from("distro"), format!("{n}\t{}\t{}", d.title, d.release)));
                }
            }
            Ok(())
        }
        Some("list") => {
            for n in base::numbers().0.iter().filter(|n| n.kind == "box" && n.owner == uid) {
                let d = base::box_facts(uid, &n.name);
                let title = d.iter().find(|(k, _)| k == "title").map(|(_, v)| v.clone()).unwrap_or_default();
                facts.push((String::from("box"), format!("{}\t{title}", n.name)));
            }
            Ok(())
        }
        Some("create") => {
            let given = |i: usize| f.get(i).map(String::as_str).filter(|v| !v.is_empty());
            create(arg(1)?, arg(2)?, given(3), given(4), uid, gid, say)
        }
        Some("open") => open(arg(1)?, uid, facts),
        Some("map") => map(arg(1)?, arg(2)?, pid, uid, gid),
        Some("remove") => remove(arg(1)?, uid, say),
        Some("set") => set(arg(1)?, arg(2)?, arg(3)?, uid),
        Some("usage") => usage(uid, facts),
        Some("remove-base") => remove_base(arg(1)?, uid, say),
        Some("begin") => begin(arg(1)?, arg(2)?, arg(3)?, uid, facts),
        Some("end") => end(arg(1)?, uid, facts),
        Some("installs") => installs(arg(1)?, uid, facts),
        Some("undo") => undo(arg(1)?, arg(2)?, uid, facts),
        Some("rollback") => rollback(arg(1)?, arg(2)?, uid, say),
        _ => Err(String::from("unknown request")),
    }
}

/// Boxes are for people's accounts.
fn person(uid: u32) -> Result<String, String> {
    if uid < 1000 {
        return Err(String::from(
            "Linux boxes are for people's own accounts, not root's or the system's: log in as your own \
             account to build and run Linux software (an administrator makes one with `useradd -m NAME`, \
             or in Settings › Users)",
        ));
    }
    crate::account(uid).map(|(n, _)| n).ok_or_else(|| format!("user {uid} has no account in /etc/passwd"))
}

/// A local `--from` must be a file the asker could read themselves:
/// slate-boxd reads it as root.
fn readable_by(from: &str, uid: u32) -> Result<(), String> {
    let Some(path) = from.strip_prefix("file://").or_else(|| (!from.contains("://")).then_some(from)) else {
        return Ok(());
    };
    let st = fs::stat(path.as_bytes()).map_err(|e| format!("{path}: {e}"))?;
    if st.is_file() && (st.mode & 0o004 != 0 || (st.uid == uid && st.mode & 0o400 != 0)) {
        Ok(())
    } else {
        Err(format!("{path}: you can't read it, so slate-boxd won't either"))
    }
}

fn box_subvol(uid: u32, name: &str) -> String {
    format!("box.{uid}.{name}")
}

fn box_root(uid: u32, name: &str) -> String {
    format!("{BOXES}/{uid}/{name}")
}

fn create(
    name: &str,
    distro_name: &str,
    from: Option<&str>,
    mirror: Option<&str>,
    uid: u32,
    gid: u32,
    say: Say,
) -> Result<(), String> {
    let slate_name = person(uid)?;
    if !crate::valid_name(name) {
        return Err(format!("{name} can't name a box: use up to {} lower-case letters, digits and -", crate::NAME_MAX));
    }
    let mut d = distro::load(distro_name)?;
    // Another mirror for the base's packages (when the base is made now).
    if let Some(m) = mirror {
        if !(m.starts_with("http://") || m.starts_with("https://")) || m.contains(char::is_whitespace) {
            return Err(format!("{m} isn't a mirror's http: or https: URL"));
        }
        d.mirror = String::from(m.trim_end_matches('/'));
    }
    base::device()?;
    if let Some(f) = from {
        readable_by(f, uid)?;
    }
    if base::numbers().find("box", uid, name).is_some() {
        return Err(format!("you have a box named {name} already"));
    }
    let need = if fs::exists(format!("{STATE}/base-{}.ok", d.name).as_bytes()) { 0 } else { BASE_NEEDS_MIB };
    room_for(free_mib(), need + BOX_NEEDS_MIB, &format!("A new {} box", d.title))?;
    let base_k = base::ensure(&d, from, say)?;
    let k = {
        let _n = base::lock("numbers")?;
        let mut n = base::numbers();
        if n.find("box", uid, name).is_some() {
            return Err(format!("you have a box named {name} already"));
        }
        let k = n.give("box", uid, name)?;
        base::save_numbers(&n)?;
        k
    };
    let sv = box_subvol(uid, name);
    let at = box_root(uid, name);
    let made = (|| -> Result<String, String> {
        let mine = format!("{BOXES}/{uid}");
        let _ = fs::mkdir(mine.as_bytes(), 0o700);
        fs::chown(mine.as_bytes(), uid, gid).map_err(|e| format!("{mine}: {e}"))?;
        fs::chmod(mine.as_bytes(), 0o700).map_err(|e| format!("{mine}: {e}"))?;
        say(&format!("Making the box {name} from {} {}", d.title, d.release));
        slate_rt::subvol::ctl(&format!("{BASES}/{}", d.name), &format!("snapshot {sv}"))?;
        base::mount_subvol(&sv, &at)?;
        ids::shift_tree(&at, &|id| ids::moved(id, base_k, k))?;
        base::personalize(&at, &d, name, &slate_name, uid, gid, k)
    })();
    let user = match made {
        Ok(u) => u,
        Err(e) => {
            let _ = base::drop_subvol(&sv, &at);
            let _n = base::lock("numbers")?;
            let mut n = base::numbers();
            n.take_back("box", uid, name);
            let _ = base::save_numbers(&n);
            return Err(e);
        }
    };
    let facts = format!("distro {}\ntitle {}\nuser {user}\n", d.name, d.title);
    let at_facts = format!("{STATE}/box.{uid}.{name}");
    fs::write_file(at_facts.as_bytes(), facts.as_bytes(), 0o600).map_err(|e| format!("{at_facts}: {e}"))?;
    eprintln!("slate-boxd: uid {uid} made the box {name} ({}, number {k})", d.title);
    Ok(())
}

fn open(name: &str, uid: u32, facts: &mut Facts) -> Result<(), String> {
    person(uid)?;
    let n = base::numbers();
    let Some(num) = n.find("box", uid, name) else {
        return Err(format!("you have no box named {name} (slate-box list shows yours)"));
    };
    let at = box_root(uid, name);
    base::mount_subvol(&box_subvol(uid, name), &at)?;
    let kept = base::box_facts(uid, name);
    let get = |k: &str| kept.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let d = distro::load(&get("distro")).ok();
    let user = get("user");
    let group = String::from(slate_rt::lossy(&fs::read_file(format!("{at}/etc/group").as_bytes()).unwrap_or_default()));
    let groups: Vec<String> = base::groups_of(&group, &user).iter().map(|g| format!("{g}")).collect();
    for (k, v) in [
        ("root", at.clone()),
        ("number", format!("{}", num.k)),
        ("title", get("title")),
        ("user", user.clone()),
        ("home", format!("/home/{user}")),
        ("shell", d.as_ref().map(|d| d.shell.clone()).unwrap_or_else(|| String::from("/bin/sh"))),
        ("clean", d.as_ref().and_then(|d| d.clean.clone()).unwrap_or_default()),
        ("groups", groups.join(",")),
        ("network", if get("network") == "off" { String::from("off") } else { String::from("on") }),
    ] {
        facts.push((String::from(k), v));
    }
    for (k, v) in &kept {
        if k == "share" {
            facts.push((String::from("share"), v.clone()));
        }
    }
    Ok(())
}

/// `set NAME KEY VALUE`: a box's grants (ADR 0183's phase 5), kept here,
/// out of the box's reach: `network on|off`; `share +PATH` or `-PATH`, a
/// folder of the person's own home shared with the box at its own path.
fn set(name: &str, key: &str, value: &str, uid: u32) -> Result<(), String> {
    own_box(name, uid)?;
    let at = format!("{STATE}/box.{uid}.{name}");
    let mut kept = base::box_facts(uid, name);
    match (key, value) {
        ("network", "on" | "off") => {
            kept.retain(|(k, _)| k != "network");
            kept.push((String::from("network"), String::from(value)));
        }
        ("share", v) if v.starts_with('+') || v.starts_with('-') => {
            let path = v[1..].trim_end_matches('/');
            let home = crate::home_of(uid).ok_or("no home folder")?;
            let home = home.trim_end_matches('/');
            let inside = path == home || path.starts_with(&format!("{home}/"));
            if !inside || path.split('/').any(|c| c == ".." || c == ".") || path.contains(char::is_control) {
                return Err(format!("{path}: only folders of your own home ({home}) can be shared"));
            }
            kept.retain(|(k, p)| !(k == "share" && p == path));
            if v.starts_with('+') {
                if !fs::stat(path.as_bytes()).is_ok_and(|s| s.is_dir()) {
                    return Err(format!("{path} isn't a folder"));
                }
                kept.push((String::from("share"), String::from(path)));
            }
        }
        _ => return Err(format!("unknown setting {key} {value}")),
    }
    let text: String = kept.iter().map(|(k, v)| format!("{k} {v}\n")).collect();
    fs::write_file(at.as_bytes(), text.as_bytes(), 0o600).map_err(|e| format!("{at}: {e}"))?;
    eprintln!("slate-boxd: uid {uid}, box {name}: {key} {value}");
    Ok(())
}

/// Write the maps of the asker's session child `pid` for box `name`: the
/// child must be the asker's own (its parent), tagged with the box's name,
/// in a user namespace with no maps yet.
fn map(pid: &str, name: &str, asker: i32, uid: u32, gid: u32) -> Result<(), String> {
    person(uid)?;
    let pid: i32 = pid.parse().map_err(|_| String::from("not a process ID"))?;
    let refuse = |why: &str| {
        eprintln!("slate-boxd: refused to map pid {pid} for uid {uid} (box {name}): {why}");
        Err(format!("refused: {why}"))
    };
    if status_field(pid, "PPid:").and_then(|p| p.parse::<i32>().ok()) != Some(asker) {
        return refuse("the process isn't the asker's child");
    }
    if status_field(pid, "Box:").as_deref() != Some(name) {
        return refuse("the process isn't tagged with the box's name");
    }
    let uids = status_field(pid, "Uid:").unwrap_or_default();
    if uids.split_whitespace().next().and_then(|u| u.parse::<u32>().ok()) != Some(uid) {
        return refuse("the process isn't the asker's");
    }
    let unmapped = fs::read_file(format!("/proc/{pid}/uid_map").as_bytes()).is_ok_and(|m| m.trim_ascii().is_empty());
    if !unmapped {
        return refuse("the process's user namespace isn't new");
    }
    let Some(num) = base::numbers().find("box", uid, name).cloned() else {
        return refuse("no such box");
    };
    base::write_maps(pid, num.k, Some((uid, gid)))
}

fn remove(name: &str, uid: u32, say: Say) -> Result<(), String> {
    person(uid)?;
    if base::numbers().find("box", uid, name).is_none() {
        return Err(format!("you have no box named {name}"));
    }
    let at = box_root(uid, name);
    base::drop_subvol(&box_subvol(uid, name), &at).map_err(|e| {
        if e == "it is in use" {
            format!("the box {name} is in use: leave its shells and end its programs first")
        } else {
            e
        }
    })?;
    // Its receipts and their snapshots go with it.
    let dir = receipts_dir(uid, name);
    for r in load_receipts(uid, name) {
        let _ = slate_rt::subvol::ctl(BOXES, &format!("delete {}", snapshot_name(uid, name, r.n)));
    }
    for e in fs::read_dir(dir.as_bytes()).unwrap_or_default() {
        let _ = fs::unlink(format!("{dir}/{}", slate_rt::lossy(&e.name)).as_bytes());
    }
    let _ = fs::rmdir(dir.as_bytes());
    let _n = base::lock("numbers")?;
    let mut n = base::numbers();
    n.take_back("box", uid, name);
    base::save_numbers(&n)?;
    let _ = fs::unlink(format!("{STATE}/box.{uid}.{name}").as_bytes());
    say(&format!("Removed the box {name} and everything in it"));
    eprintln!("slate-boxd: uid {uid} removed the box {name}");
    Ok(())
}

// --- Install receipts (ADR 0183's phase 4) -------------------------------

/// A box's receipts' folder.
fn receipts_dir(uid: u32, name: &str) -> String {
    format!("{STATE}/receipts/{uid}.{name}")
}

/// A receipt's snapshot.
fn snapshot_name(uid: u32, name: &str, n: u32) -> String {
    format!("box.{uid}.{name}.r{n}")
}

/// A box's receipts, oldest first.
fn load_receipts(uid: u32, name: &str) -> Vec<receipts::Receipt> {
    let dir = receipts_dir(uid, name);
    let mut out: Vec<receipts::Receipt> = fs::read_dir(dir.as_bytes())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            let n: u32 = slate_rt::lossy(&e.name).parse().ok()?;
            let text = fs::read_file(format!("{dir}/{n}").as_bytes()).ok()?;
            Some(receipts::Receipt::parse(n, &slate_rt::lossy(&text)))
        })
        .collect();
    out.sort_by_key(|r| r.n);
    out
}

/// The asker's box `name`: its number (it must be theirs).
fn own_box(name: &str, uid: u32) -> Result<u32, String> {
    person(uid)?;
    base::numbers().find("box", uid, name).map(|n| n.k).ok_or_else(|| format!("you have no box named {name}"))
}

/// Mount a receipt's snapshot for a moment: where.
fn mount_snapshot(uid: u32, name: &str, n: u32) -> Result<String, String> {
    let at = format!("{STATE}/snap.{uid}.{name}.{n}");
    base::mount_subvol(&snapshot_name(uid, name, n), &at)?;
    Ok(at)
}

fn unmount(at: &str) {
    let _ = fs::umount(at.as_bytes());
    let _ = fs::rmdir(at.as_bytes());
}

/// `begin NAME LABEL COMMAND`: keep the box as it is before a command as
/// its root. `receipt` is its number, or nothing when one is being kept
/// already (a command inside another's).
fn begin(name: &str, label: &str, command: &str, uid: u32, facts: &mut Facts) -> Result<(), String> {
    own_box(name, uid)?;
    let dir = receipts_dir(uid, name);
    let _ = fs::mkdir(format!("{STATE}/receipts").as_bytes(), 0o700);
    let _ = fs::mkdir(dir.as_bytes(), 0o700);
    let _held = base::lock(&format!("receipts.{uid}.{name}"))?;
    let open = format!("{dir}/open");
    if fs::exists(open.as_bytes()) {
        return Ok(());
    }
    let all = load_receipts(uid, name);
    let n = all.iter().map(|r| r.n).max().unwrap_or(0) + 1;
    let snap = snapshot_name(uid, name, n);
    if base::has_subvol(&snap) {
        slate_rt::subvol::ctl(BOXES, &format!("delete {snap}"))?;
    }
    slate_rt::subvol::ctl(&box_root(uid, name), &format!("snapshot {snap} ro"))?;
    let label = receipts::unique_label(&all, label.trim());
    let text = format!("{n}\n{label}\n{command}\n");
    fs::write_file(open.as_bytes(), text.as_bytes(), 0o600).map_err(|e| format!("{open}: {e}"))?;
    facts.push((String::from("receipt"), format!("{n}")));
    Ok(())
}

/// `end NAME`: compare the box with the snapshot `begin` kept; keep what
/// changed as a receipt (`receipt` N, label, how many paths), or drop the
/// snapshot when nothing did.
fn end(name: &str, uid: u32, facts: &mut Facts) -> Result<(), String> {
    own_box(name, uid)?;
    let dir = receipts_dir(uid, name);
    let _held = base::lock(&format!("receipts.{uid}.{name}"))?;
    let open = format!("{dir}/open");
    let text = String::from(slate_rt::lossy(&fs::read_file(open.as_bytes()).map_err(|_| "no receipt is being kept")?));
    let mut lines = text.lines();
    let n: u32 = lines.next().and_then(|l| l.parse().ok()).ok_or("a broken receipt")?;
    let label = String::from(lines.next().unwrap_or(""));
    let command = String::from(lines.next().unwrap_or(""));
    let _ = fs::unlink(open.as_bytes());
    let snap = mount_snapshot(uid, name, n)?;
    let r = receipts::scan(&snap).and_then(|before| Ok((before, receipts::scan(&box_root(uid, name))?)));
    unmount(&snap);
    let (before, after) = r?;
    let entries = receipts::diff(&before, &after);
    if entries.is_empty() {
        slate_rt::subvol::ctl(BOXES, &format!("delete {}", snapshot_name(uid, name, n)))?;
        return Ok(());
    }
    let r = receipts::Receipt { n, label: label.clone(), when: slate_rt::time::unix() as u64, command, entries };
    let at = format!("{dir}/{n}");
    fs::write_file(at.as_bytes(), r.text().as_bytes(), 0o600).map_err(|e| format!("{at}: {e}"))?;
    eprintln!("slate-boxd: uid {uid}, box {name}: receipt {n} \"{label}\" ({} paths)", r.entries.len());
    facts.push((String::from("receipt"), format!("{n}\t{label}\t{}", r.entries.len())));
    Ok(())
}

/// `installs NAME`: the receipts, `receipt` N, label, when, paths.
fn installs(name: &str, uid: u32, facts: &mut Facts) -> Result<(), String> {
    own_box(name, uid)?;
    for r in load_receipts(uid, name) {
        facts.push((String::from("receipt"), format!("{}\t{}\t{}\t{}", r.n, r.label, r.when, r.entries.len())));
    }
    Ok(())
}

/// Copy `rel` from the snapshot at `snap` into the box at `root` as it was
/// (contents, mode, owners, a link's target, times).
fn put_back(snap: &str, root: &str, rel: &str) -> Result<(), String> {
    let (from, to) = (format!("{snap}{rel}"), format!("{root}{rel}"));
    let st = fs::lstat(from.as_bytes()).map_err(|e| format!("{rel}: {e}"))?;
    if st.is_dir() {
        let _ = fs::mkdir(to.as_bytes(), st.mode & 0o7777);
    } else {
        if let Ok(old) = fs::lstat(to.as_bytes())
            && !old.is_dir()
        {
            let _ = fs::unlink(to.as_bytes());
        }
        if st.is_symlink() {
            let target = fs::readlink(from.as_bytes()).map_err(|e| format!("{rel}: {e}"))?;
            fs::symlink(&target, to.as_bytes()).map_err(|e| format!("{rel}: {e}"))?;
        } else {
            let data = fs::read_file(from.as_bytes()).map_err(|e| format!("{rel}: {e}"))?;
            fs::write_file(to.as_bytes(), &data, st.mode & 0o7777).map_err(|e| format!("{rel}: {e}"))?;
        }
    }
    fs::lchown(to.as_bytes(), st.uid, st.gid).map_err(|e| format!("{rel}: {e}"))?;
    if !st.is_symlink() {
        fs::chmod(to.as_bytes(), st.mode & 0o7777).map_err(|e| format!("{rel}: {e}"))?;
        let _ = fs::set_times(
            to.as_bytes(),
            Some(Some((st.atime, st.atime_nsec))),
            Some(Some((st.mtime, st.mtime_nsec))),
            true,
        );
    }
    Ok(())
}

/// `undo NAME WHICH`: take receipt WHICH (its number or label) back.
fn undo(name: &str, which: &str, uid: u32, facts: &mut Facts) -> Result<(), String> {
    own_box(name, uid)?;
    let _held = base::lock(&format!("receipts.{uid}.{name}"))?;
    let all = load_receipts(uid, name);
    let r = receipts::find(&all, which)
        .ok_or_else(|| format!("the box {name} has no receipt {which} (slate-box installs lists them)"))?
        .clone();
    let clash = receipts::conflicts(&all, r.n);
    if !clash.is_empty() {
        let later: Vec<String> = all
            .iter()
            .filter(|l| l.n > r.n && l.entries.iter().any(|(_, p)| clash.contains(p)))
            .map(|l| l.label.clone())
            .collect();
        let shown: Vec<&str> = clash.iter().take(3).map(String::as_str).collect();
        return Err(format!(
            "\"{}\" can't be undone on its own: {} changed the same files since ({}{}); undo that first, or roll back to before \"{}\"",
            r.label,
            later.join(", "),
            shown.join(", "),
            if clash.len() > 3 { ", ..." } else { "" },
            r.label
        ));
    }
    let root = box_root(uid, name);
    let snap = mount_snapshot(uid, name, r.n)?;
    let done = (|| -> Result<(), String> {
        // What it changed or removed, as it was (folders first, from the top).
        for (k, p) in r.entries.iter().filter(|(k, _)| *k != 'A') {
            let _ = k;
            put_back(&snap, &root, p)?;
        }
        // What it added: files and links, then folders from the deepest.
        let added: Vec<&String> = r.entries.iter().filter(|(k, _)| *k == 'A').map(|(_, p)| p).collect();
        for p in &added {
            let at = format!("{root}{p}");
            if fs::lstat(at.as_bytes()).is_ok_and(|s| !s.is_dir()) {
                fs::unlink(at.as_bytes()).map_err(|e| format!("{p}: {e}"))?;
            }
        }
        for p in added.iter().rev() {
            let at = format!("{root}{p}");
            if fs::lstat(at.as_bytes()).is_ok_and(|s| s.is_dir()) {
                let _ = fs::rmdir(at.as_bytes());
            }
        }
        Ok(())
    })();
    unmount(&snap);
    done?;
    slate_rt::subvol::ctl(BOXES, &format!("delete {}", snapshot_name(uid, name, r.n)))?;
    let _ = fs::unlink(format!("{}/{}", receipts_dir(uid, name), r.n).as_bytes());
    eprintln!("slate-boxd: uid {uid}, box {name}: receipt {} \"{}\" undone", r.n, r.label);
    facts.push((String::from("undone"), format!("{}\t{}", r.label, r.entries.len())));
    Ok(())
}

/// `rollback NAME WHICH`: the box as it was before receipt WHICH; it and
/// every later receipt go.
fn rollback(name: &str, which: &str, uid: u32, say: Say) -> Result<(), String> {
    own_box(name, uid)?;
    let _held = base::lock(&format!("receipts.{uid}.{name}"))?;
    let all = load_receipts(uid, name);
    let r = receipts::find(&all, which)
        .ok_or_else(|| format!("the box {name} has no receipt {which} (slate-box installs lists them)"))?
        .clone();
    let root = box_root(uid, name);
    let sv = box_subvol(uid, name);
    if base::mounted(&root) {
        fs::umount(root.as_bytes()).map_err(|e| match e {
            slate_rt::Errno::EBUSY => format!("the box {name} is in use: end its programs first"),
            e => format!("{root}: {e}"),
        })?;
    }
    slate_rt::subvol::ctl(BOXES, &format!("delete {sv}"))?;
    let snap = mount_snapshot(uid, name, r.n)?;
    let made = slate_rt::subvol::ctl(&snap, &format!("snapshot {sv}"));
    unmount(&snap);
    made?;
    base::mount_subvol(&sv, &root)?;
    for later in all.iter().filter(|l| l.n >= r.n) {
        let _ = slate_rt::subvol::ctl(BOXES, &format!("delete {}", snapshot_name(uid, name, later.n)));
        let _ = fs::unlink(format!("{}/{}", receipts_dir(uid, name), later.n).as_bytes());
    }
    let _ = fs::unlink(format!("{}/open", receipts_dir(uid, name)).as_bytes());
    say(&format!("The box {name} is back to before \"{}\"", r.label));
    eprintln!("slate-boxd: uid {uid}, box {name}: rolled back to before receipt {}", r.n);
    Ok(())
}

// --- Space (ADR 0183's phase 6) ----------------------------------------

/// A subvolume's (all, own) bytes, from SlateFS.
fn subvol_usage(name: &str) -> Option<(u64, u64)> {
    let out = slate_rt::subvol::ctl(BOXES, &format!("usage {name}")).ok()?;
    let mut w = out.split_whitespace().map(|v| v.parse::<u64>().ok());
    Some((w.next()??, w.next()??))
}

/// `usage`: the asker's boxes (`box` NAME, TITLE, OWN, ALL: own counting
/// their receipts' snapshots), the bases (`base` NAME, TITLE, OWN, ALL,
/// how many boxes of anyone's use it), the disk (`disk` FREE, SIZE).
fn usage(uid: u32, facts: &mut Facts) -> Result<(), String> {
    person(uid)?;
    let numbers = base::numbers();
    for n in numbers.0.iter().filter(|n| n.kind == "box" && n.owner == uid) {
        let (mut all, mut own) = subvol_usage(&box_subvol(uid, &n.name)).unwrap_or((0, 0));
        for r in load_receipts(uid, &n.name) {
            if let Some((_, o)) = subvol_usage(&snapshot_name(uid, &n.name, r.n)) {
                own += o;
                all += o;
            }
        }
        let kept = base::box_facts(uid, &n.name);
        let title = kept.iter().find(|(k, _)| k == "title").map(|(_, v)| v.clone()).unwrap_or_default();
        facts.push((String::from("box"), format!("{}\t{title}\t{own}\t{all}", n.name)));
    }
    for n in numbers.0.iter().filter(|n| n.kind == "base") {
        let Some((all, own)) = subvol_usage(&format!("box-base.{}", n.name)) else { continue };
        let title = distro::load(&n.name).map(|d| d.title).unwrap_or_else(|_| n.name.clone());
        let users = boxes_of_distro(&numbers, &n.name);
        facts.push((String::from("base"), format!("{}\t{title}\t{own}\t{all}\t{users}", n.name)));
    }
    if let Ok(s) = fs::statfs(BOXES.as_bytes()) {
        let b = s.block_size.max(0) as u64;
        facts
            .push((String::from("disk"), format!("{}\t{}", s.available.saturating_mul(b), s.blocks.saturating_mul(b))));
    }
    Ok(())
}

/// How many boxes (anyone's) are made from distribution `name`'s base.
fn boxes_of_distro(numbers: &ids::Numbers, name: &str) -> usize {
    numbers
        .0
        .iter()
        .filter(|n| n.kind == "box")
        .filter(|n| base::box_facts(n.owner, &n.name).iter().any(|(k, v)| k == "distro" && v == name))
        .count()
}

/// `remove-base NAME`: a distribution's base, when no box uses it (it
/// comes back from its makers the next time a box needs it).
fn remove_base(name: &str, uid: u32, say: Say) -> Result<(), String> {
    person(uid)?;
    let _held = base::lock(&format!("base-{name}"))?;
    let numbers = base::numbers();
    if numbers.find("base", 0, name).is_none() {
        return Err(format!("there is no {name} base"));
    }
    let users = boxes_of_distro(&numbers, name);
    if users > 0 {
        return Err(format!("{users} boxes are made from the {name} base; remove them first"));
    }
    base::drop_subvol(&format!("box-base.{name}"), &format!("{BASES}/{name}"))?;
    let _ = fs::unlink(format!("{STATE}/base-{name}.ok").as_bytes());
    let _n = base::lock("numbers")?;
    let mut n = base::numbers();
    n.take_back("base", 0, name);
    base::save_numbers(&n)?;
    say(&format!("Removed the {name} base"));
    eprintln!("slate-boxd: uid {uid} removed the {name} base");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room() {
        assert!(room_for(Some(5000), 2048, "x").is_ok());
        assert!(room_for(None, 2048, "x").is_ok());
        let e = room_for(Some(300), 2304, "A new Arch Linux box").unwrap_err();
        assert_eq!(e, "A new Arch Linux box needs about 2.2 GB of free space, and this disk has 300 MB free");
        assert_eq!(human_mib(1536), "1.5 GB");
    }
}
