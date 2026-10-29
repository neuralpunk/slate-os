// SPDX-License-Identifier: MIT OR Apache-2.0

//! The Linux runtime (ADRs 0038, 0039): an Alpine root, by default
//! /var/lib/slate/linux, whose programs run on Slate's Linux layer.
//!
//! - `slate-linux-app [--root DIR] PROGRAM [ARGUMENT...]` runs a graphical
//!   program of the runtime in a Strata window.
//! - `slate-linux run [--root DIR] PROGRAM [ARGUMENT...]` runs any program
//!   of the runtime, on the terminal.
//! - `slate-linux setup [--root DIR] [--mirror URL] [--from FILE|URL]
//!   [PACKAGE...]` makes the runtime (see [`setup`]).
//!
//! It is itself a Linux program, so it runs in the Linux domain (which
//! needs Linux compatibility mode), and running programs needs no
//! privilege: in a user namespace of its own, with the person's IDs mapped
//! to themselves, and a mount namespace, it makes the runtime a root: the
//! devices and the person's home bound in, /proc, a /tmp of its own, and
//! the runtime's passwd and group with the person in them and Slate's
//! resolv.conf bound over its own. For a graphical program it starts Sway
//! as a kiosk (one program, no bars or borders) on wlroots' headless
//! backend with software rendering, and `strata-wl`, which shows Sway's
//! output in Strata. When either ends, the other is stopped.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, lossy, process};

pub mod flatpak;
pub mod setup;

/// Where the runtime is unless `--root` says otherwise.
pub const DEFAULT_ROOT: &str = "/var/lib/slate/linux";
/// The bridge, copied into the runtime's /tmp to run there.
const BRIDGE: &[u8] = b"/usr/lib/slate/strata-wl";
/// SIGTERM (signal(7)).
const SIGTERM: i32 = 15;

/// The command line: the runtime and the program with its arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct Command {
    pub root: String,
    pub program: Vec<String>,
}

pub fn parse(args: &[String]) -> Result<Command, String> {
    let mut root = String::from(DEFAULT_ROOT);
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "--root" => {
                root = args.get(i + 1).cloned().ok_or("--root needs a directory")?;
                i += 2;
            }
            "--" => {
                i += 1;
                break;
            }
            _ => break,
        }
    }
    let program = args[i.min(args.len())..].to_vec();
    if program.is_empty() {
        return Err("usage: slate-linux-app [--root DIR] PROGRAM [ARGUMENT...]".into());
    }
    Ok(Command { root, program })
}

/// The environment of the programs in the runtime.
pub fn environment(uid: u32, home: &str, user: &str, keyboard: Option<&str>) -> Vec<Vec<u8>> {
    let mut env: Vec<String> = alloc::vec![
        format!("HOME={home}"),
        format!("USER={user}"),
        format!("LOGNAME={user}"),
        String::from("PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"),
        format!("XDG_RUNTIME_DIR=/tmp/xdg-{uid}"),
        // Sway on wlroots: the headless backend, software rendering, no
        // input devices of its own (strata-wl brings virtual ones).
        String::from("WLR_BACKENDS=headless"),
        String::from("WLR_RENDERER=pixman"),
        String::from("WLR_HEADLESS_OUTPUTS=1"),
        String::from("WLR_LIBINPUT_NO_DEVICES=1"),
        // Toolkits use Wayland.
        String::from("MOZ_ENABLE_WAYLAND=1"),
        String::from("GDK_BACKEND=wayland"),
        String::from("QT_QPA_PLATFORM=wayland"),
        String::from("LANG=C.UTF-8"),
        // Flatpak's exported entries and icons, the system's and the
        // person's, before the runtime's own (Flatpak warns without them).
        format!(
            "XDG_DATA_DIRS=/var/lib/flatpak/exports/share:{home}/.local/share/flatpak/exports/share:/usr/local/share:/usr/share"
        ),
    ];
    if let Some(k) = keyboard {
        env.push(format!("SLATE_KEYBOARD={k}"));
    }
    for keep in [b"STRATA_SOCKET".as_slice(), b"TERM"] {
        if let Some(v) = slate_rt::env::var(keep) {
            env.push(format!("{}={}", lossy(keep), lossy(&v)));
        }
    }
    env.into_iter().map(String::into_bytes).collect()
}

pub fn main() -> i32 {
    let argv = slate_rt::env::args();
    let name = argv.first().map(|a| String::from(lossy(fs::basename(a)))).unwrap_or_default();
    let args: Vec<String> = argv.iter().skip(1).map(|a| String::from(lossy(a))).collect();
    let r = if name == "slate-flatpak" {
        flatpak::parse_scoped(&args).and_then(|(c, system)| flatpak_main(&c, system, &args))
    } else if name == "slate-appimage" {
        appimage_main(&args)
    } else if name == "slate-linux" {
        match args.first().map(String::as_str) {
                Some("setup") => setup::main(&args[1..]).map(|()| 0),
                Some("upgrade") => setup::upgrade(&args[1..]).map(|()| 0),
                Some("rollback") => setup::rollback(&args[1..]).map(|()| 0),
                Some("run") => parse(&args[1..]).and_then(|c| run_plain(&c)),
                _ => Err("usage: slate-linux setup|upgrade|rollback|run ... (see /usr/share/doc/slate/guides/installing.md, \"Linux programs\")"
                    .into()),
            }
    } else {
        parse(&args).and_then(|c| run(&c))
    };
    match r {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{name}: {e}");
            1
        }
    }
}

/// `text` (a passwd or group file) with `line` in place of any line naming
/// the same name or number (the first and third fields).
pub fn with_entry(text: &str, line: &str) -> String {
    let key = |l: &str| {
        let f: Vec<&str> = l.split(':').collect();
        (String::from(f[0]), f.get(2).map(|x| String::from(*x)))
    };
    let (name, id) = key(line);
    let mut out = String::new();
    for l in text.lines().filter(|l| !l.is_empty()) {
        let (n, i) = key(l);
        if n != name && i != id {
            out += l;
            out.push('\n');
        }
    }
    out += line;
    out.push('\n');
    out
}

/// The line for `id` (the third field) in a passwd or group file.
fn entry_for(text: &str, id: u32) -> Option<Vec<String>> {
    let id = format!("{id}");
    text.lines().map(|l| l.split(':').map(String::from).collect::<Vec<_>>()).find(|f| f.get(2) == Some(&id))
}

/// The person's passwd and group lines for the runtime: Slate's, with the
/// runtime's shell.
pub fn person_entries(passwd: &str, group: &str, uid: u32, gid: u32, user: &str, home: &str) -> (String, String) {
    let p = match entry_for(passwd, uid) {
        Some(f) if f.len() >= 6 => format!("{}:x:{uid}:{gid}:{}:{}:/bin/sh", f[0], f[4], f[5]),
        _ => format!("{user}:x:{uid}:{gid}::{home}:/bin/sh"),
    };
    let name = p.split(':').next().unwrap_or(user);
    let g = match entry_for(group, gid) {
        Some(f) => format!("{}:x:{gid}:{name}", f[0]),
        None => format!("{name}:x:{gid}:"),
    };
    (p, g)
}

/// `s` quoted for the shell.
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Sway's configuration as a kiosk for one program: no borders or bars,
/// and Sway ends when the program does (through `script`).
pub fn sway_config(script: &str) -> String {
    format!(
        "# Written by slate-linux-app: Sway as a kiosk for one program.\n\
         swaybg_command -\n\
         default_border none\n\
         default_floating_border none\n\
         focus_follows_mouse no\n\
         xwayland enable\n\
         exec /bin/sh {script}\n"
    )
}

/// Where the kiosk script leaves the program's exit status.
const KIOSK_STATUS: &str = "/tmp/.slate/status";

/// The script Sway runs: the program, its exit status kept in
/// `KIOSK_STATUS` (Sway's own is lost), then Sway's own end.
pub fn kiosk_script(program: &[String]) -> String {
    let cmd: Vec<String> = program.iter().map(|a| quote(a)).collect();
    format!("{}\necho $? > {KIOSK_STATUS}\nswaymsg exit\n", cmd.join(" "))
}

/// The status a kiosk run reports: 0 when the window was closed (the
/// bridge ended first), else the program's own, from what the kiosk
/// script kept (`status`); a compositor that ended without it failed.
pub fn kiosk_outcome(window_closed: bool, status: Option<&str>) -> i32 {
    if window_closed {
        return 0;
    }
    status.and_then(|s| s.trim().parse().ok()).unwrap_or(1)
}

fn write(path: &str, text: &str) -> Result<(), String> {
    let fd = fs::open(path.as_bytes(), fs::O_WRONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{path}: {e}"))?;
    let r = io::write_all(fd, text.as_bytes()).map_err(|e| format!("{path}: {e}"));
    let _ = io::close(fd);
    r
}

fn mount(source: &str, target: &str, fstype: &str, flags: usize, data: &str) -> Result<(), String> {
    fs::mount(source.as_bytes(), target.as_bytes(), fstype.as_bytes(), flags, data.as_bytes())
        .map_err(|e| format!("mounting {fstype} on {target}: {e}"))
}

/// Write `text` to `path` (a new file of the person's).
fn create(path: &str, text: &str) -> Result<(), String> {
    fs::write_file(path.as_bytes(), text.as_bytes(), 0o644).map_err(|e| format!("{path}: {e}"))
}

/// Bind files made in the runtime's /tmp over its passwd, group and
/// resolv.conf (where the runtime has them).
fn bind_files(root: &str, uid: u32, gid: u32, user: &str, home: &str) -> Result<(), String> {
    let read = |p: &str| fs::read_file(p.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let (p, g) = person_entries(&read("/etc/passwd"), &read("/etc/group"), uid, gid, user, home);
    let dir = format!("{root}/tmp/.slate");
    fs::mkdir(dir.as_bytes(), 0o755).map_err(|e| format!("{dir}: {e}"))?;
    let files = [
        ("passwd", with_entry(&read(&format!("{root}/etc/passwd")), &p)),
        ("group", with_entry(&read(&format!("{root}/etc/group")), &g)),
        ("resolv.conf", read("/etc/resolv.conf")),
    ];
    for (name, text) in files {
        let target = format!("{root}/etc/{name}");
        if !fs::exists(target.as_bytes()) {
            continue;
        }
        let made = format!("{dir}/{name}");
        create(&made, &text)?;
        mount(&made, &target, "", fs::MS_BIND, "")?;
    }
    Ok(())
}

/// Make the runtime this process's root, in namespaces of its own.
fn enter(root: &str, uid: u32, gid: u32, user: &str, home: &str) -> Result<(), String> {
    if uid == 0 {
        // Root needs no user namespace for its mounts, and must not have
        // one: its capabilities there would not reach files whose owners
        // the namespace doesn't map (user_namespaces(7)), such as the
        // runtime's /var/lib/flatpak (Alpine's flatpak account owns it).
        // Slate's mounts are all private (ADR 0028), so none of these
        // reaches the system's.
        process::unshare(process::CLONE_NEWNS)
            .map_err(|e| format!("making a mount namespace: {e} (is Linux compatibility mode on?)"))?;
    } else {
        process::unshare(process::CLONE_NEWUSER | process::CLONE_NEWNS)
            .map_err(|e| format!("making namespaces: {e} (is Linux compatibility mode on?)"))?;
        // user_namespaces(7): deny setgroups before writing gid_map.
        write("/proc/self/setgroups", "deny")?;
        write("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
        write("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;
    }
    // The runtime becomes a mount of its own: pivot_root(2) refuses a
    // root that isn't a mount point (EINVAL), and bubblewrap pivots from
    // it. The runtime is a plain directory of /var on most systems.
    mount(root, root, "", fs::MS_BIND | fs::MS_REC, "")?;
    mount("/dev", &format!("{root}/dev"), "", fs::MS_BIND | fs::MS_REC, "")?;
    mount("proc", &format!("{root}/proc"), "proc", 0, "")?;
    mount("tmpfs", &format!("{root}/tmp"), "tmpfs", 0, "mode=1777")?;
    bind_files(root, uid, gid, user, home)?;
    // The person's home, at the same path: /home gets a tmpfs to hold the
    // mount point, since the runtime's own /home isn't theirs to change.
    if let Some(rest) = home.strip_prefix("/home/") {
        mount("tmpfs", &format!("{root}/home"), "tmpfs", 0, "mode=0755")?;
        let point = format!("{root}/home/{rest}");
        // Each level of a deeper home (/home/team/ada) too.
        let mut at = format!("{root}/home");
        for part in rest.split('/').filter(|p| !p.is_empty()) {
            at = format!("{at}/{part}");
            if !fs::exists(at.as_bytes()) {
                fs::mkdir(at.as_bytes(), 0o755).map_err(|e| format!("{at}: {e}"))?;
            }
        }
        mount(home, &point, "", fs::MS_BIND, "")?;
    } else if fs::exists(format!("{root}{home}").as_bytes()) {
        mount(home, &format!("{root}{home}"), "", fs::MS_BIND, "")?;
    }
    fs::chroot(root.as_bytes()).map_err(|e| format!("entering {root}: {e}"))?;
    let _ = fs::chdir(home.as_bytes()).or_else(|_| fs::chdir(b"/"));
    Ok(())
}

/// Start `argv`; in a process group of its own when `group` (to be
/// stopped with it), else in ours (keeping the terminal).
fn spawn(argv: &[Vec<u8>], env: &[Vec<u8>], group: bool) -> Result<i32, String> {
    match process::fork() {
        Ok(0) => {
            if group {
                let _ = process::setpgid(0, 0);
            }
            let path =
                if argv[0].contains(&b'/') { argv[0].clone() } else { [b"/usr/bin/".as_slice(), &argv[0]].concat() };
            let e = process::execve(&path, argv, env);
            eprintln!("slate-linux-app: {}: {e}", lossy(&path));
            process::exit_now(127)
        }
        Ok(pid) => Ok(pid),
        Err(e) => Err(format!("starting {}: {e}", lossy(&argv[0]))),
    }
}

/// Who runs the program: (uid, gid, user name, home).
fn person() -> (u32, u32, String, String) {
    let (uid, gid) = (process::getuid(), process::getgid());
    let home = slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_else(|| String::from("/"));
    let user = slate_rt::env::var(b"USER").map(|u| String::from(lossy(&u))).unwrap_or_else(|| format!("{uid}"));
    (uid, gid, user, home)
}

fn no_runtime(root: &str) -> String {
    format!(
        "no Linux runtime in {root}; `slate-linux setup` makes one (see /usr/share/doc/slate/guides/installing.md, \"Linux programs\")"
    )
}

/// `slate-linux run`: the program on the terminal, in the runtime; its
/// exit status.
fn run_plain(c: &Command) -> Result<i32, String> {
    if !fs::exists(format!("{}/etc/alpine-release", c.root).as_bytes()) {
        return Err(no_runtime(&c.root));
    }
    let (uid, gid, user, home) = person();
    enter(&c.root, uid, gid, &user, &home)?;
    let env = environment(uid, &home, &user, None);
    let argv: Vec<Vec<u8>> = c.program.iter().map(|a| a.clone().into_bytes()).collect();
    let pid = spawn(&argv, &env, false)?;
    let status = process::wait(pid, 0).map(|(_, s)| s).unwrap_or(0);
    Ok(if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) })
}

/// The program's exit status from a wait status.
fn exit_code(status: i32) -> i32 {
    if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) }
}

/// Start `argv` (in the runtime) and wait: its status.
fn spawn_wait(argv: &[String], env: &[Vec<u8>]) -> Result<i32, String> {
    let argv: Vec<Vec<u8>> = argv.iter().map(|a| a.clone().into_bytes()).collect();
    let pid = spawn(&argv, env, false)?;
    Ok(exit_code(process::wait(pid, 0).map(|(_, s)| s).unwrap_or(0)))
}

/// Start `argv` and wait, with its standard output: (status, output).
fn spawn_output(argv: &[String], env: &[Vec<u8>]) -> Result<(i32, String), String> {
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("{e}"))?;
    let bytes: Vec<Vec<u8>> = argv.iter().map(|a| a.clone().into_bytes()).collect();
    let pid = match process::fork() {
        Ok(0) => {
            let _ = process::dup2(w, 1);
            let e = process::execve(&bytes[0], &bytes, env);
            eprintln!("slate-flatpak: {}: {e}", argv[0]);
            process::exit_now(127)
        }
        Ok(pid) => pid,
        Err(e) => return Err(format!("{e}")),
    };
    let _ = io::close(w);
    let out = io::read_to_end(r).unwrap_or_default();
    let _ = io::close(r);
    let status = exit_code(process::wait(pid, 0).map(|(_, s)| s).unwrap_or(0));
    Ok((status, String::from(lossy(&out))))
}

/// Into the runtime for Flatpak's commands (not a window's): the
/// environment, with the runtime directory Flatpak needs made.
fn enter_for_flatpak(root: &str, system: bool) -> Result<(Vec<Vec<u8>>, String), String> {
    if !fs::exists(format!("{root}/usr/bin/flatpak").as_bytes()) {
        return Err(format!("no Flatpak in the Linux runtime {root}; `slate-linux setup flatpak` adds it (ADR 0114)"));
    }
    let (uid, gid, user, home) =
        if system { (0, 0, String::from("root"), String::from(SYSTEM_HOME)) } else { person() };
    enter(root, uid, gid, &user, &home)?;
    let xdg = format!("/tmp/xdg-{uid}");
    let _ = fs::mkdir(xdg.as_bytes(), 0o700);
    Ok((environment(uid, &home, &user, None), home))
}

/// The commit before `current` in `id`'s remote's history (an app
/// updated outside slate-flatpak has none kept).
fn remote_before(env: &[Vec<u8>], id: &str, current: &str) -> Result<Option<String>, String> {
    let (status, origin) = spawn_output(&flatpak::argv::origin(id), env)?;
    if status != 0 {
        return Ok(None);
    }
    let (status, log) = spawn_output(&flatpak::argv::remote_log(origin.trim(), id), env)?;
    if status != 0 {
        return Err(format!("couldn't read {id}'s history on {}", origin.trim()));
    }
    Ok(flatpak::before_in_log(&flatpak::parse_log(&log), current))
}

/// Make the app history's directory, and read it.
fn history(home: &str) -> (String, Vec<(String, String, i64)>) {
    for d in [".local", ".local/share", ".local/share/slate"] {
        let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
    }
    let path = format!("{home}/.local/share/slate/flatpak-history");
    let text = fs::read_file(path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let h = flatpak::parse_history(&text);
    (path, h)
}

fn now_s() -> i64 {
    slate_rt::time::now(slate_rt::time::CLOCK_REALTIME).0
}

/// The installed apps with their whole commits (a rollback names one);
/// flatpak's status if it couldn't list them.
fn installed(env: &[Vec<u8>]) -> Result<Result<Vec<flatpak::Installed>, i32>, String> {
    let (status, out) = spawn_output(&flatpak::argv::list(), env)?;
    if status != 0 {
        return Ok(Err(status));
    }
    let mut apps = flatpak::parse_list(&out);
    for a in &mut apps {
        if let Ok((0, full)) = spawn_output(&flatpak::argv::show_commit(&a.id), env) {
            let full = full.trim();
            if full.len() == 64 && full.starts_with(a.commit.as_str()) {
                a.commit = String::from(full);
            }
        }
    }
    Ok(Ok(apps))
}

/// Flathub's description, fetched by Slate (its own TLS) and checked
/// against the pinned key (ADR 0115), kept in the person's cache: its
/// path, the same inside the runtime. Before entering the runtime.
fn flathub_description(home: &str) -> Result<String, String> {
    for d in [".cache", ".cache/slate"] {
        let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
    }
    let path = format!("{home}/.cache/slate/flathub.flatpakrepo");
    let read = || fs::read_file(path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let also = flathub_keys(home);
    if flatpak::check_flathub(&read(), &also).is_err() {
        let fetch = [String::from("/bin/fetch"), "-q".into(), "-o".into(), path.clone(), flatpak::FLATHUB.into()];
        let env: Vec<Vec<u8>> = slate_rt::env::vars().to_vec();
        if spawn_wait(&fetch, &env)? != 0 {
            return Err(format!("couldn't fetch Flathub's description from {}", flatpak::FLATHUB));
        }
    }
    flatpak::check_flathub(&read(), &also).inspect_err(|_| {
        let _ = fs::unlink(path.as_bytes());
    })?;
    Ok(path)
}

/// Another remote's description, from a URL (fetched by Slate) or a
/// file, checked ([`flatpak::check_description`]) and kept in the
/// person's cache: its path, the same inside the runtime. Before entering
/// the runtime.
fn remote_description(home: &str, name: &str, at: &str) -> Result<String, String> {
    for d in [".cache", ".cache/slate"] {
        let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
    }
    let path = format!("{home}/.cache/slate/remote-{name}.flatpakrepo");
    if at.contains("://") {
        let fetch = [String::from("/bin/fetch"), "-q".into(), "-o".into(), path.clone(), at.into()];
        if spawn_wait(&fetch, slate_rt::env::vars())? != 0 {
            return Err(format!("couldn't fetch {at}"));
        }
    } else {
        let text = fs::read_file(at.as_bytes()).map_err(|e| format!("{at}: {e}"))?;
        fs::write_file(path.as_bytes(), &text, 0o644).map_err(|e| format!("{path}: {e}"))?;
    }
    let text = fs::read_file(path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    let (url, fp) = flatpak::check_description(&text).inspect_err(|_| {
        let _ = fs::unlink(path.as_bytes());
    })?;
    slate_rt::println!("slate-flatpak: {name}: {url}, signed by the key {fp}");
    Ok(path)
}

/// The fingerprints trusted for Flathub's key besides the pinned one:
/// the administrator's and the person's.
fn flathub_keys(home: &str) -> Vec<String> {
    let person = format!("{home}/{}", flatpak::FLATHUB_KEYS_PERSON);
    [String::from(flatpak::FLATHUB_KEYS_SYSTEM), person]
        .iter()
        .filter_map(|p| fs::read_file(p.as_bytes()).ok())
        .flat_map(|t| flatpak::parse_keys(&lossy(&t)))
        .collect()
}

/// `slate-flatpak trust-key`: the fingerprint added to the person's file.
fn trust_key(home: &str, fp: &str) -> Result<i32, String> {
    for d in [".config", ".config/slate"] {
        let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
    }
    let path = format!("{home}/{}", flatpak::FLATHUB_KEYS_PERSON);
    let mut text = fs::read_file(path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    if !flatpak::parse_keys(&text).iter().any(|k| k == fp) {
        if text.is_empty() {
            text.push_str("# Fingerprints trusted for Flathub's key besides Slate's (slate-flatpak trust-key).\n");
        }
        text.push_str(&format!("{fp}\n"));
        fs::write_file(path.as_bytes(), text.as_bytes(), 0o644).map_err(|e| format!("{path}: {e}"))?;
    }
    slate_rt::println!("slate-flatpak: Flathub's descriptions signed with {fp} are trusted for your apps");
    Ok(0)
}

/// Root's home: the system installation's Flathub description is kept
/// there (the broker starts slate-flatpak with no HOME).
const SYSTEM_HOME: &str = "/root";

/// `slate-flatpak` (ADR 0114); `system` for the system installation, as
/// `args` ask.
fn flatpak_main(c: &flatpak::Cmd, system: bool, args: &[String]) -> Result<i32, String> {
    use flatpak::{Cmd, argv};
    let root = String::from(DEFAULT_ROOT);
    if let Cmd::Run(args) = c {
        return run(&Command { root, program: argv::run(args) });
    }
    if let Cmd::TrustKey(fp) = c {
        return trust_key(&person().3, fp);
    }
    if system && process::geteuid() != 0 {
        return match c {
            // Changes go through the broker, which runs this as root once
            // they are approved (ADR 0114's addendum).
            Cmd::Install(..) | Cmd::Remove(_) | Cmd::Update(_) => {
                let words = args[1..].join(" ");
                spawn_wait(&[String::from("/bin/slate-approve"), format!("flatpak={words}")], slate_rt::env::vars())
            }
            Cmd::RemoteAdd(..) | Cmd::RemoteDelete(_) => {
                Err(String::from("the system installation's remotes are root's to change (su -)"))
            }
            // Anyone may look.
            _ => {
                let (env, _) = enter_for_flatpak(&root, false)?;
                let v = match c {
                    Cmd::List => argv::list(),
                    Cmd::Updates => argv::updates(),
                    _ => argv::remotes(),
                };
                spawn_wait(&argv::system(v), &env)
            }
        };
    }
    let me = if system { String::from(SYSTEM_HOME) } else { person().3 };
    if system {
        let _ = fs::mkdir(SYSTEM_HOME.as_bytes(), 0o700);
    }
    let description = match c {
        Cmd::Install(from, _) if from == flatpak::FLATHUB_NAME => flathub_description(&me)?,
        Cmd::Catalog => flathub_description(&me)?,
        Cmd::RemoteAdd(name, at) => remote_description(&me, name, at)?,
        Cmd::AutoUpdate => {
            // Nothing to do unless it is on and due, and there are apps.
            let home = me.clone();
            let read = |rel: &str| {
                fs::read_file(format!("{home}/{rel}").as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default()
            };
            let apps = format!("{home}/.local/share/flatpak/app");
            if !flatpak::auto_due(&read(flatpak::AUTO_SETTINGS), &read(flatpak::AUTO_LOG), now_s())
                || fs::read_dir(apps.as_bytes()).map_or(true, |e| e.is_empty())
            {
                return Ok(0);
            }
            String::new()
        }
        _ => String::new(),
    };
    if system {
        // Alpine's package makes the system repository without the
        // directory where OSTree marks a commit only partly fetched, so an
        // interrupted download could pass for whole.
        let _ = fs::mkdir(format!("{root}/var/lib/flatpak/repo/state").as_bytes(), 0o755);
    }
    let (env, home) = enter_for_flatpak(&root, system)?;
    if system {
        return match c {
            Cmd::Install(from, ids) => {
                if from == flatpak::FLATHUB_NAME {
                    let s = spawn_wait(&argv::system(argv::add_flathub(&description)), &env)?;
                    if s != 0 {
                        return Ok(s);
                    }
                }
                spawn_wait(&argv::system(argv::install(from, ids)), &env)
            }
            Cmd::RemoteAdd(name, _) => spawn_wait(&argv::system(argv::add_remote(name, &description)), &env),
            Cmd::Remotes => spawn_wait(&argv::system(argv::remotes()), &env),
            Cmd::RemoteDelete(name) => spawn_wait(&argv::system(argv::remote_delete(name)), &env),
            Cmd::List => spawn_wait(&argv::system(argv::list()), &env),
            Cmd::Updates => spawn_wait(&argv::system(argv::updates()), &env),
            Cmd::Remove(ids) => spawn_wait(&argv::system(argv::remove(ids)), &env),
            Cmd::Update(ids) => spawn_wait(&argv::system(argv::update(ids)), &env),
            _ => Err(String::from("--system: for your own apps only")),
        };
    }
    match c {
        Cmd::Install(from, ids) => {
            if from == flatpak::FLATHUB_NAME {
                let s = spawn_wait(&argv::add_flathub(&description), &env)?;
                if s != 0 {
                    return Ok(s);
                }
            }
            spawn_wait(&argv::install(from, ids), &env)
        }
        Cmd::RemoteAdd(name, _) => spawn_wait(&argv::add_remote(name, &description), &env),
        Cmd::Remotes => spawn_wait(&argv::remotes(), &env),
        Cmd::RemoteDelete(name) => spawn_wait(&argv::remote_delete(name), &env),
        Cmd::List => spawn_wait(&argv::list(), &env),
        Cmd::Updates => spawn_wait(&argv::updates(), &env),
        Cmd::Status => {
            let installed = match installed(&env)? {
                Ok(i) => i,
                Err(status) => return Ok(status),
            };
            // What is on offer (none if the remote can't be reached).
            let updates = match spawn_output(&argv::updates(), &env)? {
                (0, text) => flatpak::parse_list(&text),
                _ => Vec::new(),
            };
            let (_, h) = history(&home);
            // Apps with no version kept may still go back on their remote.
            let remote_back: Vec<String> = installed
                .iter()
                .filter(|i| flatpak::rollback_target(&h, &i.id, &i.commit).is_none())
                .filter(|i| matches!(remote_before(&env, &i.id, &i.commit), Ok(Some(_))))
                .map(|i| i.id.clone())
                .collect();
            slate_rt::print!("{}", flatpak::status(&installed, &updates, &h, &remote_back));
            Ok(0)
        }
        Cmd::Remove(ids) => spawn_wait(&argv::remove(ids), &env),
        Cmd::Catalog => {
            let s = spawn_wait(&argv::add_flathub(&description), &env)?;
            if s != 0 {
                return Ok(s);
            }
            spawn_wait(&argv::catalog(), &env)
        }
        Cmd::AutoUpdate => {
            // As `update` does, each app's version kept first; the outcome
            // logged for the Software Updater.
            if let Ok(apps) = installed(&env)? {
                let (path, h) = history(&home);
                let text = flatpak::record(&h, &apps, now_s());
                let _ = fs::write_file(path.as_bytes(), text.as_bytes(), 0o644);
            }
            // Its progress isn't for anyone's eyes (Strata started it).
            let (status, _) = spawn_output(&argv::update(&[]), &env)?;
            let what = if status == 0 { String::from("updated") } else { format!("failed: flatpak said {status}") };
            for d in [".cache", ".cache/slate"] {
                let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
            }
            let log_path = format!("{home}/{}", flatpak::AUTO_LOG);
            let log = fs::read_file(log_path.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
            let _ = fs::write_file(log_path.as_bytes(), flatpak::auto_logged(&log, now_s(), &what).as_bytes(), 0o644);
            Ok(status)
        }
        Cmd::Update(ids) => {
            // Each app's version first, for a rollback.
            if let Ok(apps) = installed(&env)? {
                let (path, h) = history(&home);
                let text = flatpak::record(&h, &apps, now_s());
                let _ = fs::write_file(path.as_bytes(), text.as_bytes(), 0o644);
            }
            spawn_wait(&argv::update(ids), &env)
        }
        Cmd::Rollback(id) => {
            let apps = match installed(&env)? {
                Ok(i) => i,
                Err(status) => return Ok(status),
            };
            let name = id.split("//").next().unwrap_or(id);
            let current = apps.into_iter().find(|a| a.id == name).ok_or(format!("{name} isn't installed"))?;
            let (_, h) = history(&home);
            let to = match flatpak::rollback_target(&h, name, &current.commit) {
                Some(c) => c,
                None => remote_before(&env, name, &current.commit)?
                    .ok_or(format!("no earlier version of {name} is known, here or on its remote"))?,
            };
            slate_rt::println!("{name}: back to {to}");
            spawn_wait(&argv::update_to(name, &to), &env)
        }
        Cmd::Run(_) | Cmd::TrustKey(_) => unreachable!(),
    }
}

/// `slate-appimage FILE [ARG...]` (ADR 0114): extracted once, then run on
/// the freedesktop runtime in Flatpak's sandbox, in a Strata window.
/// `slate-appimage` (ADR 0114): run one, or manage the extracted ones and
/// their launcher entries.
fn appimage_main(args: &[String]) -> Result<i32, String> {
    let (_, _, _, home) = person();
    match args.first().map(String::as_str) {
        Some("--list") => return appimage_list(&home),
        Some("--clean") => return appimage_clean(&home),
        Some("--remove") => {
            let what = args.get(1).ok_or("usage: slate-appimage --remove FILE|ID")?;
            return appimage_remove(&home, what);
        }
        Some("--add") => {
            let file = args.get(1).ok_or("usage: slate-appimage --add FILE")?;
            let (app, _, id) = appimage_extract(&home, file)?;
            let desktop = desktop_of(&app).unwrap_or_default();
            let fallback = String::from(lossy(fs::basename(file.as_bytes())));
            // A launcher entry has no terminal to give it.
            if flatpak::desktop_terminal(&desktop) {
                return Err(format!("{file} runs in a terminal: run it there (slate-appimage {file})"));
            }
            let dir = format!("{home}/{}", flatpak::PERSON_APPS);
            for d in [".local", ".local/share", ".local/share/strata", flatpak::PERSON_APPS] {
                let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
            }
            let entry = format!("{dir}/appimage-{id}.app");
            let text = flatpak::appimage_entry(&id, &desktop, &fallback);
            fs::write_file(entry.as_bytes(), text.as_bytes(), 0o644).map_err(|e| format!("{entry}: {e}"))?;
            slate_rt::println!(
                "slate-appimage: {} is in the launcher",
                flatpak::desktop_value(&desktop, "Name").unwrap_or(&fallback)
            );
            return Ok(0);
        }
        Some("--entry") => {
            let id = args.get(1).ok_or("usage: slate-appimage --entry ID")?;
            let src = format!("{home}/.cache/slate/appimages/{id}/{}", flatpak::APPIMAGE_SOURCE);
            let file = fs::read_file(src.as_bytes()).map_err(|_| format!("no AppImage known as {id}"))?;
            let mut run_args = alloc::vec![String::from(lossy(&file).trim())];
            run_args.extend(args[2..].iter().cloned());
            return appimage_run(&home, &run_args);
        }
        _ => {}
    }
    appimage_run(&home, args)
}

/// The desktop entry an extracted AppImage carries, if any.
fn desktop_of(app: &str) -> Option<String> {
    fs::read_dir(app.as_bytes()).ok().and_then(|es| {
        es.iter()
            .find(|e| e.name.ends_with(b".desktop"))
            .and_then(|e| fs::read_file(&fs::join(app.as_bytes(), &e.name)).ok())
            .map(|t| String::from(lossy(&t)))
    })
}

fn tree_size(path: &[u8]) -> u64 {
    match fs::lstat(path) {
        Ok(st) if st.is_dir() => {
            fs::read_dir(path).unwrap_or_default().iter().map(|e| tree_size(&fs::join(path, &e.name))).sum()
        }
        Ok(st) => st.size.max(0) as u64,
        Err(_) => 0,
    }
}

fn remove_tree(path: &[u8]) {
    if let Ok(st) = fs::lstat(path) {
        if st.is_dir() {
            for e in fs::read_dir(path).unwrap_or_default() {
                remove_tree(&fs::join(path, &e.name));
            }
            let _ = fs::rmdir(path);
        } else {
            let _ = fs::unlink(path);
        }
    }
}

/// The extracted AppImages: (ID, the AppImage's path).
fn appimages(home: &str) -> Vec<(String, String)> {
    let dir = format!("{home}/.cache/slate/appimages");
    fs::read_dir(dir.as_bytes())
        .unwrap_or_default()
        .iter()
        .filter(|e| e.name != b"." && e.name != b"..")
        .map(|e| {
            let id = String::from(lossy(&e.name));
            let src = fs::read_file(format!("{dir}/{id}/{}", flatpak::APPIMAGE_SOURCE).as_bytes())
                .map(|t| String::from(lossy(&t).trim()))
                .unwrap_or_default();
            (id, src)
        })
        .collect()
}

/// `--list`: each extraction, its size, its AppImage (or that it is gone)
/// and whether it has a launcher entry.
fn appimage_list(home: &str) -> Result<i32, String> {
    for (id, src) in appimages(home) {
        let size = tree_size(format!("{home}/.cache/slate/appimages/{id}").as_bytes());
        let entry = fs::exists(format!("{home}/{}/appimage-{id}.app", flatpak::PERSON_APPS).as_bytes());
        let file = if src.is_empty() { String::from("?") } else { src.clone() };
        let gone = if !src.is_empty() && !fs::exists(src.as_bytes()) { " (gone)" } else { "" };
        slate_rt::println!(
            "{id}\t{} MB\t{}{gone}{}",
            size.div_ceil(1 << 20),
            file,
            if entry { "\tin the launcher" } else { "" }
        );
    }
    Ok(0)
}

/// `--remove FILE|ID`: the extraction and its launcher entry.
fn appimage_remove(home: &str, what: &str) -> Result<i32, String> {
    let id = if fs::exists(format!("{home}/.cache/slate/appimages/{what}").as_bytes()) && !what.contains('/') {
        String::from(what)
    } else {
        let data = fs::read_file(what.as_bytes()).map_err(|e| format!("{what}: {e}"))?;
        let dir = flatpak::extract_dir(home, &slate_hash::sha256(&data));
        String::from(dir.rsplit('/').next().unwrap_or_default())
    };
    let dir = format!("{home}/.cache/slate/appimages/{id}");
    if !fs::exists(dir.as_bytes()) {
        return Err(format!("{what}: not extracted"));
    }
    remove_tree(dir.as_bytes());
    let _ = fs::unlink(format!("{home}/{}/appimage-{id}.app", flatpak::PERSON_APPS).as_bytes());
    slate_rt::println!("slate-appimage: removed {id}");
    Ok(0)
}

/// `--clean`: the extractions whose AppImage is gone.
fn appimage_clean(home: &str) -> Result<i32, String> {
    for (id, src) in appimages(home) {
        if src.is_empty() || !fs::exists(src.as_bytes()) {
            appimage_remove(home, &id)?;
        }
    }
    Ok(0)
}

/// Extract `file` once (by its contents' hash), recording where it came
/// from: (the extracted tree, its absolute path, the ID).
fn appimage_extract(home: &str, file: &str) -> Result<(String, String, String), String> {
    let data = fs::read_file(file.as_bytes()).map_err(|e| format!("{file}: {e}"))?;
    if !flatpak::is_appimage(&data[..data.len().min(16)]) {
        return Err(format!("{file}: not an AppImage"));
    }
    // An absolute path, as the runtime sees it (the home is at the same
    // path there).
    let file = if file.starts_with('/') {
        String::from(file)
    } else {
        let cwd = fs::getcwd().map(|c| String::from(lossy(&c))).unwrap_or_default();
        format!("{cwd}/{file}")
    };
    let home = String::from(home);
    let dir = flatpak::extract_dir(&home, &slate_hash::sha256(&data));
    let id = String::from(dir.rsplit('/').next().unwrap_or_default());
    let app = format!("{dir}/squashfs-root");
    let root = String::from(DEFAULT_ROOT);
    if !fs::exists(format!("{app}/AppRun").as_bytes()) {
        // In a child: into the runtime, the freedesktop runtime installed
        // if missing, the AppImage extracted by itself.
        let pid = process::fork().map_err(|e| format!("{e}"))?;
        if pid == 0 {
            let r = (|| -> Result<i32, String> {
                let description = flathub_description(&home)?;
                let (env, _) = enter_for_flatpak(&root, false)?;
                let installed = spawn_output(
                    &["/usr/bin/flatpak".into(), "--user".into(), "info".into(), flatpak::APPIMAGE_RUNTIME.into()],
                    &env,
                )?;
                if installed.0 != 0 {
                    eprintln!("slate-appimage: installing {} from Flathub (once)", flatpak::APPIMAGE_RUNTIME);
                    spawn_wait(&flatpak::argv::add_flathub(&description), &env)?;
                    let s = spawn_wait(
                        &flatpak::argv::install(flatpak::FLATHUB_NAME, &[flatpak::APPIMAGE_RUNTIME.into()]),
                        &env,
                    )?;
                    if s != 0 {
                        return Ok(s);
                    }
                }
                for d in
                    [".cache", ".cache/slate", ".cache/slate/appimages", dir.trim_start_matches(&format!("{home}/"))]
                {
                    let _ = fs::mkdir(format!("{home}/{d}").as_bytes(), 0o755);
                }
                fs::chdir(dir.as_bytes()).map_err(|e| format!("{dir}: {e}"))?;
                let _ = fs::chmod(file.as_bytes(), 0o755);
                spawn_wait(&[file.clone(), "--appimage-extract".into()], &env)
            })();
            process::exit_now(match r {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("slate-appimage: {e}");
                    1
                }
            });
        }
        let s = exit_code(process::wait(pid, 0).map(|(_, s)| s).unwrap_or(0));
        if s != 0 || !fs::exists(format!("{app}/AppRun").as_bytes()) {
            return Err(format!("couldn't unpack {file} (status {s})"));
        }
    }
    let _ = fs::write_file(format!("{dir}/{}", flatpak::APPIMAGE_SOURCE).as_bytes(), file.as_bytes(), 0o644);
    Ok((app, file, id))
}

/// Run an AppImage (extracted first if need be).
fn appimage_run(home: &str, args: &[String]) -> Result<i32, String> {
    let (file, rest) = args
        .split_first()
        .ok_or("usage: slate-appimage FILE [ARG...] | --add FILE | --list | --remove FILE|ID | --clean")?;
    let (app, _, _) = appimage_extract(home, file)?;
    let root = String::from(DEFAULT_ROOT);
    let program = flatpak::argv::appimage(&app, rest);
    // A command-line AppImage runs on this terminal.
    if desktop_of(&app).is_some_and(|d| flatpak::desktop_terminal(&d)) {
        let (env, _) = enter_for_flatpak(&root, false)?;
        return spawn_wait(&program, &env);
    }
    run(&Command { root, program })
}

fn run(c: &Command) -> Result<i32, String> {
    if !fs::exists(format!("{}/usr/bin/sway", c.root).as_bytes()) {
        return Err(no_runtime(&c.root));
    }
    let (uid, gid, user, home) = person();
    let bridge = fs::read_file(BRIDGE).map_err(|e| format!("{}: {e}", lossy(BRIDGE)))?;
    let keyboard = fs::read_file(b"/etc/slate/keyboard").ok().map(|k| String::from(lossy(&k).trim()));
    enter(&c.root, uid, gid, &user, &home)?;
    let xdg = format!("/tmp/xdg-{uid}");
    fs::mkdir(xdg.as_bytes(), 0o700).map_err(|e| format!("{xdg}: {e}"))?;
    let wl = "/tmp/strata-wl";
    let fd =
        fs::open(wl.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_CLOEXEC, 0o755).map_err(|e| format!("{wl}: {e}"))?;
    io::write_all(fd, &bridge).map_err(|e| format!("{wl}: {e}"))?;
    let _ = io::close(fd);
    let env = environment(uid, &home, &user, keyboard.as_deref());
    let title = c.program[0].rsplit('/').next().unwrap_or(&c.program[0]);
    create("/tmp/.slate/kiosk.sh", &kiosk_script(&c.program))?;
    create("/tmp/.slate/sway.conf", &sway_config("/tmp/.slate/kiosk.sh"))?;
    let sway = [b"sway".to_vec(), b"--config".to_vec(), b"/tmp/.slate/sway.conf".to_vec()];
    let compositor = spawn(&sway, &env, true)?;
    let bridge = spawn(&[wl.as_bytes().to_vec(), title.as_bytes().to_vec()], &env, true)?;
    // Whichever ends first, the other goes too.
    let first = process::wait(-1, 0).map(|(p, _)| p).unwrap_or(compositor);
    let _ = process::kill(-compositor, SIGTERM);
    let _ = process::kill(bridge, SIGTERM);
    while process::wait(-1, 0).is_ok() {}
    // The program's own status, so a program that fails to start says so
    // (the Web Browser shows it, ADR 0115).
    let status = fs::read_file(KIOSK_STATUS.as_bytes()).ok().map(|t| String::from(lossy(&t)));
    let code = kiosk_outcome(first == bridge, status.as_deref());
    if code != 0 {
        eprintln!("slate-linux-app: {} ended with status {code}", c.program[0]);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn command_lines() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse(&a(&["firefox", "--kiosk"])).unwrap(),
            Command { root: DEFAULT_ROOT.into(), program: a(&["firefox", "--kiosk"]) }
        );
        assert_eq!(
            parse(&a(&["--root", "/w", "--", "foot"])).unwrap(),
            Command { root: "/w".into(), program: a(&["foot"]) }
        );
        assert!(parse(&a(&["--root", "/w"])).is_err());
        let env = environment(1000, "/home/ada", "ada", Some("gb"));
        assert!(env.contains(&b"XDG_RUNTIME_DIR=/tmp/xdg-1000".to_vec()));
        assert!(env.contains(&b"WLR_BACKENDS=headless".to_vec()));
        assert!(env.contains(&b"SLATE_KEYBOARD=gb".to_vec()));
    }

    #[test]
    fn accounts() {
        let runtime = "root:x:0:0:root:/root:/bin/sh\nada:x:1000:1000::/home/old:/bin/ash\nnobody:x:65534:65534::/:/sbin/nologin\n";
        let slate = "root:x:0:0::/root:/bin/chalk\nada:x:1000:100:Ada L:/home/ada:/bin/chalk\n";
        let groups = "root:x:0:\nusers:x:100:\n";
        let (p, g) = person_entries(slate, groups, 1000, 100, "ada", "/home/ada");
        assert_eq!(p, "ada:x:1000:100:Ada L:/home/ada:/bin/sh");
        assert_eq!(g, "users:x:100:ada");
        assert_eq!(
            with_entry(runtime, &p),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\nada:x:1000:100:Ada L:/home/ada:/bin/sh\n"
        );
        // Someone Slate's files don't name.
        let (p, g) = person_entries("", "", 1001, 1001, "bo", "/home/bo");
        assert_eq!((p.as_str(), g.as_str()), ("bo:x:1001:1001::/home/bo:/bin/sh", "bo:x:1001:"));
    }

    #[test]
    fn kiosk() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            kiosk_script(&a(&["firefox", "it's"])),
            "'firefox' 'it'\\''s'\necho $? > /tmp/.slate/status\nswaymsg exit\n"
        );
        assert_eq!(kiosk_outcome(true, None), 0);
        assert_eq!(kiosk_outcome(false, Some("0\n")), 0);
        assert_eq!(kiosk_outcome(false, Some("127\n")), 127);
        assert_eq!(kiosk_outcome(false, None), 1);
        assert!(sway_config("/tmp/k.sh").contains("exec /bin/sh /tmp/k.sh\n"));
    }
}
