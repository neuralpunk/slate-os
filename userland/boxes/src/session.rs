// SPDX-License-Identifier: MIT OR Apache-2.0

//! Entering a box (ADR 0183). The caller forks a child, which tags itself
//! with the box's name (the kernel's `box_tag`: once, inherited, shown in
//! /proc/PID/status) and moves into new user, mount, PID, UTS and IPC
//! namespaces (and a network namespace without the network). The caller
//! has its ID maps written (by slate-boxd for a person's box, which checks
//! the tag) and lets it go on. The child becomes box root, and forks the
//! box's PID 1, which is Slate's own code: it mounts /proc, a /dev of the
//! box's own, tmpfs on /tmp and /run and Slate's resolv.conf, pivots into
//! the box's root, sets the host name, then starts the command as the
//! box's user and reaps orphans until it ends. When the command ends, the
//! rest of the box's processes end with it, and its status is the
//! session's.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, fs, io, process, signal};

/// What a session runs.
#[derive(Clone, Debug, Default)]
pub struct Spec {
    /// The box's name: its processes' tag and its host name.
    pub name: String,
    /// The box's root (its mounted subvolume).
    pub root: String,
    /// Who the command runs as, inside the box.
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    /// Where it starts (inside); `/` when that isn't there.
    pub cwd: String,
    pub argv: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
    /// Whether the box shares Slate's network (otherwise a namespace with
    /// only a loopback interface).
    pub network: bool,
    /// The session's terminal (`/dev/pts/N`): bound into the box's /dev as
    /// itself and as /dev/console.
    pub tty: Option<Vec<u8>>,
    /// Where the command's output goes (its standard input is /dev/null);
    /// the caller's own descriptors otherwise.
    pub output: Option<i32>,
    /// A folder of the person's bound into the box at the same path for
    /// this session (the one they ran the command from; ADR 0183).
    pub share: Option<String>,
    /// The folders the person shares with the box for good (`slate-box
    /// share`), bound at their own paths too.
    pub shares: Vec<String>,
    /// The session's channel folder (key and socket, [`crate::agent`]),
    /// bound into the box at `/run/slate-host`.
    pub host_dir: Option<String>,
}

/// Devices a box gets, bound from Slate's /dev.
pub const DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// Where the box's PATH looks for a command named without a folder.
pub const BOX_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin";

/// Start a session: the child's pid, once `map` has written its ID maps.
/// Wait for it with [`finish`].
pub fn start(spec: &Spec, map: &mut dyn FnMut(i32) -> Result<(), String>) -> Result<i32, String> {
    let (ready_r, ready_w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("a pipe: {e}"))?;
    let (go_r, go_w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("a pipe: {e}"))?;
    match process::fork() {
        Ok(0) => {
            let _ = io::close(ready_r);
            let _ = io::close(go_w);
            let code = child(spec, ready_w, go_r);
            process::exit_now(code)
        }
        Ok(c) => {
            let _ = io::close(ready_w);
            let _ = io::close(go_r);
            let mut b = [0u8; 1];
            let ready = io::read(ready_r, &mut b) == Ok(1);
            let _ = io::close(ready_r);
            let r = if ready { map(c) } else { Err(String::from("the box's namespaces couldn't be made")) };
            if r.is_ok() {
                let _ = io::write_all(go_w, b"g");
            }
            let _ = io::close(go_w);
            match r {
                Ok(()) => Ok(c),
                Err(e) => {
                    let _ = process::wait(c, 0);
                    Err(e)
                }
            }
        }
        Err(e) => Err(format!("starting the box: {e}")),
    }
}

/// Wait for a session started with [`start`]: its exit status (128 + the
/// signal when one ended it).
pub fn finish(pid: i32) -> i32 {
    loop {
        match process::wait(pid, 0) {
            Ok((_, st)) => return exit_code(st),
            Err(slate_rt::Errno::EINTR) => {}
            Err(_) => return 1,
        }
    }
}

/// [`start`] and [`finish`].
pub fn run(spec: &Spec, map: &mut dyn FnMut(i32) -> Result<(), String>) -> Result<i32, String> {
    start(spec, map).map(finish)
}

/// A wait status as an exit status.
pub fn exit_code(st: i32) -> i32 {
    if st & 0x7f == 0 { (st >> 8) & 0xff } else { 128 + (st & 0x7f) }
}

/// The child: tagged, in its namespaces, waiting to be mapped; then the
/// box's PID 1 runs in it.
fn child(spec: &Spec, ready: i32, go: i32) -> i32 {
    // What goes wrong on the way is said where the command's output goes.
    if let Some(out) = spec.output {
        let _ = process::dup2(out, 2);
    }
    if let Err(e) = process::box_tag(spec.name.as_bytes()) {
        eprintln!("slate-box: tagging the box's processes: {e}");
        return 126;
    }
    let mut flags = process::CLONE_NEWUSER
        | process::CLONE_NEWNS
        | process::CLONE_NEWPID
        | process::CLONE_NEWUTS
        | process::CLONE_NEWIPC;
    if !spec.network {
        flags |= process::CLONE_NEWNET;
    }
    if let Err(e) = process::unshare(flags) {
        eprintln!("slate-box: making the box's namespaces: {e}");
        return 126;
    }
    let _ = io::write_all(ready, b"r");
    let _ = io::close(ready);
    let mut b = [0u8; 1];
    if io::read(go, &mut b) != Ok(1) {
        return 126;
    }
    let _ = io::close(go);
    // The person's folder, bound in while this is still the person (who
    // may pass through their own home's folders).
    // (Shorter paths first, so a folder inside another shared one lands
    // on top of it.)
    let mut dirs: Vec<&String> = spec.shares.iter().chain(spec.share.iter()).collect();
    dirs.sort_by_key(|d| d.len());
    dirs.dedup();
    for dir in dirs {
        let at = format!("{}{dir}", spec.root.trim_end_matches('/'));
        let made = mkdir_p(&at).and_then(|()| mount(dir, &at, "", fs::MS_BIND, ""));
        if let Err(e) = made {
            eprintln!("slate-box: {dir} isn't shared with the box ({e})");
        }
    }
    // Into the box's root while still who we were: as the box's root, the
    // folders above it (the person's, 0700) can't be passed through. The
    // mounts after this are made relative to it.
    if let Err(e) = fs::chdir(spec.root.as_bytes()) {
        eprintln!("slate-box: {}: {e}", spec.root);
        return 126;
    }
    // The box's /run (its root's: tmpfs reads uid= in this namespace),
    // with the channel's folder (the person's) in it.
    let run = folder("run", 0o755)
        .and_then(|()| mount("tmpfs", "run", "tmpfs", fs::MS_NOSUID | fs::MS_NODEV, "mode=0755,uid=0,gid=0"));
    if let Err(e) = run {
        eprintln!("slate-box: {e}");
        return 126;
    }
    if let Some(dir) = &spec.host_dir {
        let bound = folder("run/slate-host", 0o700).and_then(|()| mount(dir, "run/slate-host", "", fs::MS_BIND, ""));
        if let Err(e) = bound {
            eprintln!("slate-box: the channel: {e}");
        }
    }
    // Root of the box (its own IDs), with no groups of Slate's.
    if let Err(e) = process::setgroups(&[]).and_then(|()| process::set_all_ids(0, 0)) {
        eprintln!("slate-box: becoming the box's root: {e}");
        return 126;
    }
    match process::fork() {
        Ok(0) => init(spec),
        Ok(pid) => finish(pid),
        Err(e) => {
            eprintln!("slate-box: starting the box's first process: {e}");
            126
        }
    }
}

fn mount(src: &str, at: &str, fstype: &str, flags: usize, data: &str) -> Result<(), String> {
    fs::mount(src.as_bytes(), at.as_bytes(), fstype.as_bytes(), flags, data.as_bytes())
        .map_err(|e| format!("mounting {} on {at}: {e}", if fstype.is_empty() { src } else { fstype }))
}

/// A folder of the box's, made if it isn't there.
fn folder(path: &str, mode: u32) -> Result<(), String> {
    match fs::mkdir(path.as_bytes(), mode) {
        Ok(()) | Err(slate_rt::Errno::EEXIST) => Ok(()),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

/// A folder and the ones above it, made where missing.
fn mkdir_p(path: &str) -> Result<(), String> {
    let mut at = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        at.push('/');
        at.push_str(part);
        folder(&at, 0o755)?;
    }
    Ok(())
}

/// An empty file to bind something over.
fn spot(path: &str) -> Result<(), String> {
    if fs::lstat(path.as_bytes()).is_ok_and(|s| s.is_symlink()) {
        let _ = fs::unlink(path.as_bytes());
    }
    if !fs::exists(path.as_bytes()) {
        fs::write_file(path.as_bytes(), b"", 0o644).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

/// The box's mounts, then its root: run by its PID 1, in the box's root
/// (a mount point: its subvolume), before the pivot. Paths in the box are
/// relative to it.
fn prepare(spec: &Spec, host: Option<&[u8]>) -> Result<(), String> {
    use fs::{MS_BIND, MS_NODEV, MS_NOEXEC, MS_NOSUID};
    for d in ["proc", "dev", "tmp", "etc"] {
        folder(d, 0o755)?;
    }
    mount("proc", "proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "")?;
    // A /dev of the box's own: a few devices, and the session's terminal.
    mount("tmpfs", "dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755")?;
    for d in DEVICES {
        let at = format!("dev/{d}");
        spot(&at)?;
        mount(&format!("/dev/{d}"), &at, "", MS_BIND, "")?;
    }
    // Its own pseudo-terminals (a devpts instance of its own: sudo,
    // script and tmux make them), showing the session's terminal too but
    // none of the person's others.
    folder("dev/pts", 0o755)?;
    let session_pty = spec
        .tty
        .as_ref()
        .and_then(|t| slate_rt::lossy(t).strip_prefix("/dev/pts/").and_then(|n| n.parse::<u32>().ok()));
    let opts = match session_pty {
        Some(n) => format!("newinstance,ptmxmode=0666,allow={n}"),
        None => String::from("newinstance,ptmxmode=0666"),
    };
    mount("devpts", "dev/pts", "devpts", MS_NOSUID | MS_NOEXEC, &opts)?;
    let _ = fs::symlink(b"pts/ptmx", b"dev/ptmx");
    folder("dev/shm", 0o1777)?;
    mount("tmpfs", "dev/shm", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777")?;
    for (name, to) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        let _ = fs::symlink(to.as_bytes(), format!("dev/{name}").as_bytes());
    }
    if let Some(tty) = &spec.tty {
        let tty = String::from(slate_rt::lossy(tty));
        spot("dev/console")?;
        mount(&tty, "dev/console", "", MS_BIND, "")?;
    }
    mount("tmpfs", "tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777")?;
    if let Some(h) = host {
        folder("run/slate-box", 0o755)?;
        fs::write_file(b"run/slate-box/slate-host", h, 0o755).map_err(|e| format!("slate-host: {e}"))?;
    }
    // Slate's name servers.
    if fs::exists(b"/etc/resolv.conf") {
        spot("etc/resolv.conf")?;
        mount("/etc/resolv.conf", "etc/resolv.conf", "", MS_BIND, "")?;
    }
    // Into the box: its root becomes the root, and Slate's goes.
    folder("run/.slate-old", 0o700)?;
    process::pivot_root(b".", b"run/.slate-old").map_err(|e| format!("entering {}: {e}", spec.root))?;
    let _ = fs::chdir(b"/");
    fs::umount_detach(b"/run/.slate-old").map_err(|e| format!("leaving Slate's root: {e}"))?;
    let _ = fs::rmdir(b"/run/.slate-old");
    process::sethostname(spec.name.as_bytes()).map_err(|e| format!("the host name: {e}"))?;
    Ok(())
}

/// The box's PID 1, as Slate's code: it makes the box's mounts and root,
/// then becomes slate-host (copied into the box's /run before the pivot),
/// a Linux program the box's programs see as their PID 1.
fn init(spec: &Spec) -> ! {
    // slate-host, read while Slate's root is still there.
    let host = fs::read_file(crate::host::ON_SLATE.as_bytes()).ok();
    if let Err(e) = prepare(spec, host.as_deref()) {
        eprintln!("slate-box: {e}");
        process::exit_now(126);
    }
    let groups: Vec<String> = spec.groups.iter().map(|g| format!("{g}")).collect();
    let mut argv: Vec<Vec<u8>> = alloc::vec![
        b"slate-host".to_vec(),
        b"init".to_vec(),
        format!("{}", spec.uid).into_bytes(),
        format!("{}", spec.gid).into_bytes(),
        groups.join(",").into_bytes(),
        spec.cwd.clone().into_bytes(),
        b"--".to_vec(),
    ];
    argv.extend(spec.argv.iter().cloned());
    if host.is_some() {
        if let Some(out) = spec.output {
            if let Ok(null) = fs::open(b"/dev/null", fs::O_RDONLY, 0) {
                let _ = process::dup2(null, 0);
            }
            let _ = process::dup2(out, 1);
            let _ = process::dup2(out, 2);
        }
        let e = process::execve(crate::host::IN_BOX.as_bytes(), &argv, &spec.env);
        eprintln!("slate-box: starting the box's first process: {e}");
        process::exit_now(126);
    }
    // Without slate-host (a system where it isn't installed), this process
    // stays the box's PID 1.
    let cmd = match process::fork() {
        Ok(0) => become_and_exec(spec.uid, spec.gid, &spec.groups, &spec.cwd, &spec.argv, &spec.env, spec.output),
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("slate-box: starting {}: {e}", slate_rt::lossy(&spec.argv[0]));
            process::exit_now(126);
        }
    };
    let status = loop {
        match process::wait(-1, 0) {
            Ok((p, st)) if p == cmd => break st,
            Ok(_) | Err(slate_rt::Errno::EINTR) => {}
            Err(_) => break 0,
        }
    };
    let _ = process::kill(-1, signal::SIGKILL);
    while process::wait(-1, 0).is_ok() {}
    process::exit_now(exit_code(status))
}

/// `name` found in the box's PATH (inside the box).
pub fn find_in_box(name: &[u8], env: &[Vec<u8>]) -> Vec<u8> {
    find(name, env)
}

/// `name` found in the box's PATH.
fn find(name: &[u8], env: &[Vec<u8>]) -> Vec<u8> {
    if name.contains(&b'/') {
        return name.to_vec();
    }
    let path = env.iter().find_map(|e| e.strip_prefix(b"PATH=")).map(|p| p.to_vec()).unwrap_or(BOX_PATH.into());
    for dir in path.split(|&c| c == b':').filter(|d| !d.is_empty()) {
        let full = [dir, b"/", name].concat();
        if fs::stat(&full).is_ok_and(|s| s.is_file() && s.mode & 0o111 != 0) {
            return full;
        }
    }
    name.to_vec()
}

/// Become the box's user (`uid`, `gid`, `groups`, inside), go to `cwd`
/// (else `/`) and run `argv`: the command of a session. Signals are as
/// a program expects them; `output` takes its standard output and error.
pub fn become_and_exec(
    uid: u32,
    gid: u32,
    groups: &[u32],
    cwd: &str,
    argv: &[Vec<u8>],
    env: &[Vec<u8>],
    output: Option<i32>,
) -> ! {
    for s in [signal::SIGINT, signal::SIGQUIT, signal::SIGTSTP, signal::SIGTTIN, signal::SIGTTOU, signal::SIGPIPE] {
        let _ = signal::set(s, signal::Disposition::Default);
    }
    if let Some(out) = output {
        if let Ok(null) = fs::open(b"/dev/null", fs::O_RDONLY, 0) {
            let _ = process::dup2(null, 0);
        }
        let _ = process::dup2(out, 1);
        let _ = process::dup2(out, 2);
    }
    let r = process::setgroups(groups).and_then(|()| process::set_all_ids(uid, gid));
    if let Err(e) = r {
        eprintln!("slate-box: becoming the box's user {uid}: {e}");
        process::exit_now(126);
    }
    if fs::chdir(cwd.as_bytes()).is_err() {
        let _ = fs::chdir(b"/");
    }
    let path = find(&argv[0], env);
    let e = process::execve(&path, argv, env);
    eprintln!("slate-box: {}: {}", slate_rt::lossy(&argv[0]), describe(e));
    process::exit_now(if e == slate_rt::Errno::ENOENT { 127 } else { 126 })
}

/// Why a command couldn't start, for people.
fn describe(e: slate_rt::Errno) -> String {
    match e {
        slate_rt::Errno::ENOENT => String::from("command not found in the box"),
        slate_rt::Errno::EACCES => {
            String::from("permission denied (Linux programs need Linux compatibility mode: slate-compat status)")
        }
        e => format!("{e}"),
    }
}
