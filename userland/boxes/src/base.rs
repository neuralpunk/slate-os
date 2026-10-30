// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bases and boxes on disk (slate-boxd's side; ADR 0183).
//!
//! A distribution's base is a subvolume, `box-base.NAME`, mounted at
//! `.base/NAME`: its root tarball, fetched and checked against the maker's
//! signing key (the signature over the bytes as they arrive), unpacked by
//! Slate's own tar, its files moved into the base's ID range, then the
//! distribution's setup commands run in it as its root (pacman's keyring
//! and base-devel, for Arch). `.state/base-NAME.ok` says it is finished.
//!
//! A box is a snapshot of its base, `box.UID.NAME`, mounted at `UID/NAME`,
//! its files moved into its own range, with the person added: their
//! account (ID 1000, in `wheel`, `sudo` without a password), their home,
//! the box's host name, and the prompt that names the box.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{fs, io, process};

use crate::distro::Distro;
use crate::ids::{self, Numbers};
use crate::session::{self, Spec};
use crate::{BASES, BOXES, STATE};

/// What a long job says as it goes.
pub type Say<'a> = &'a mut dyn FnMut(&str);

/// The numbers given out.
pub fn numbers() -> Numbers {
    let text = fs::read_file(format!("{STATE}/numbers").as_bytes()).unwrap_or_default();
    Numbers::parse(&slate_rt::lossy(&text))
}

pub fn save_numbers(n: &Numbers) -> Result<(), String> {
    let at = format!("{STATE}/numbers");
    let tmp = format!("{at}.new");
    fs::write_file(tmp.as_bytes(), n.text().as_bytes(), 0o600).map_err(|e| format!("{tmp}: {e}"))?;
    fs::rename(tmp.as_bytes(), at.as_bytes()).map_err(|e| format!("{at}: {e}"))
}

/// A held lock: released when dropped.
#[derive(Debug)]
pub struct Lock(i32);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = io::close(self.0);
    }
}

/// Hold `.state/NAME.lock` until the [`Lock`] is dropped: one maker of a
/// base, one changer of the numbers at a time.
pub fn lock(name: &str) -> Result<Lock, String> {
    let at = format!("{STATE}/{name}.lock");
    let fd =
        fs::open(at.as_bytes(), fs::O_RDWR | fs::O_CREAT | fs::O_CLOEXEC, 0o600).map_err(|e| format!("{at}: {e}"))?;
    let held = Lock(fd);
    fs::flock(fd, fs::LOCK_EX).map_err(|e| format!("{at}: {e}"))?;
    Ok(held)
}

/// The mounts: (where, device, type).
fn mounts() -> Vec<(String, String, String)> {
    let text = fs::read_file(b"/proc/mounts").map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split(' ').collect();
            (w.len() > 2).then(|| (w[1].replace("\\040", " "), String::from(w[0]), String::from(w[2])))
        })
        .collect()
}

/// Whether something is mounted at `at`.
pub fn mounted(at: &str) -> bool {
    mounts().iter().any(|(m, _, _)| m == at)
}

/// The SlateFS device the boxes' folder is on.
pub fn device() -> Result<String, String> {
    let m = mounts();
    let (_, dev, ty) = m
        .iter()
        .filter(|(at, _, _)| at == "/" || BOXES == at || BOXES.starts_with(&format!("{}/", at.trim_end_matches('/'))))
        .max_by_key(|(at, _, _)| at.len())
        .ok_or("no file system holds the boxes' folder")?;
    if ty != "slatefs" {
        return Err(format!("Linux boxes need SlateFS, and {BOXES} is on {ty}"));
    }
    Ok(dev.clone())
}

/// Whether subvolume `name` is there.
pub fn has_subvol(name: &str) -> bool {
    slate_rt::subvol::ctl(BOXES, "list").map(|t| t.lines().any(|l| l.split(' ').nth(1) == Some(name))).unwrap_or(false)
}

/// Mount subvolume `name` at `at` (made if needed), unless it is there.
pub fn mount_subvol(name: &str, at: &str) -> Result<(), String> {
    if mounted(at) {
        return Ok(());
    }
    let dev = device()?;
    let _ = fs::mkdir(at.as_bytes(), 0o755);
    fs::mount(dev.as_bytes(), at.as_bytes(), b"slatefs", fs::MS_NODEV, format!("subvol={name}").as_bytes())
        .map_err(|e| format!("mounting {name} at {at}: {e}"))
}

/// Unmount and delete subvolume `name` (mounted at `at`).
pub fn drop_subvol(name: &str, at: &str) -> Result<(), String> {
    if mounted(at) {
        fs::umount(at.as_bytes()).map_err(|e| match e {
            slate_rt::Errno::EBUSY => String::from("it is in use"),
            e => format!("{at}: {e}"),
        })?;
    }
    let _ = fs::rmdir(at.as_bytes());
    if has_subvol(name) {
        slate_rt::subvol::ctl(BOXES, &format!("delete {name}"))?;
    }
    Ok(())
}

/// The tarball's file name in a URL.
fn file_name(url: &str) -> String {
    String::from(url.rsplit('/').next().unwrap_or("root.tar").split('?').next().unwrap_or("root.tar"))
}

/// Fetch the distribution's root tarball into `.state/dl`, checking its
/// signature as it arrives: its path.
fn fetch_checked(d: &Distro, from: Option<&str>, say: Say) -> Result<String, String> {
    let (url, sig_url) = d.urls(from);
    let key = d.signing_key()?;
    let sig_bytes = slate_quarry::fetch(&sig_url).map_err(|e| format!("the signature: {e}"))?;
    let sig = slate_pgp::Signature::parse(&sig_bytes).map_err(|e| format!("{sig_url}: {e}"))?;
    let dl = format!("{STATE}/dl");
    let _ = fs::mkdir(dl.as_bytes(), 0o700);
    let file = format!("{dl}/{}", file_name(&url));
    let part = format!("{file}.part");
    say(&format!("Fetching {} {} from {url}", d.title, d.release));
    let fd = fs::open(part.as_bytes(), fs::O_WRONLY | fs::O_CREAT | fs::O_TRUNC | fs::O_CLOEXEC, 0o600)
        .map_err(|e| format!("{part}: {e}"))?;
    let mut h = sig.hasher();
    let mut got: u64 = 0;
    let mut next: u64 = 16 << 20;
    let r = slate_quarry::fetch_into(&url, &mut |b| {
        h.update(b);
        io::write_all(fd, b).map_err(|e| format!("{part}: {e}"))?;
        got += b.len() as u64;
        if got >= next {
            say(&format!("Fetched {} MB", got >> 20));
            next += 16 << 20;
        }
        Ok(())
    });
    let _ = fs::fsync(fd);
    let _ = io::close(fd);
    let checked = r.and_then(|()| {
        sig.check(h, &key).map_err(|e| format!("what was fetched isn't {}'s own ({e}), so it wasn't used", d.title))
    });
    if let Err(e) = checked {
        let _ = fs::unlink(part.as_bytes());
        return Err(e);
    }
    fs::rename(part.as_bytes(), file.as_bytes()).map_err(|e| format!("{file}: {e}"))?;
    let fp: Vec<&str> = (0..10).map(|i| &d.fingerprint[i * 4..i * 4 + 4]).collect();
    say(&format!("Checked: {} MB signed by {}'s key ({})", got >> 20, d.title, fp.join(" ")));
    Ok(file)
}

/// Unpack `file` into `at` with Slate's own tar, owners and modes kept.
fn unpack(d: &Distro, file: &str, at: &str) -> Result<(), String> {
    let strip = format!("--strip-components={}", d.strip);
    let mut argv: Vec<&str> = alloc::vec!["/bin/tar", "-x", "-p", "--numeric-owner", &strip, "-f", file, "-C", at];
    if file.ends_with(".zst") {
        argv.push("--zstd");
    } else if file.ends_with(".gz") {
        argv.push("-z");
    }
    let args: Vec<Vec<u8>> = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
    let pid = match process::fork() {
        Ok(0) => {
            let e = process::execve(b"/bin/tar", &args, &[b"PATH=/bin:/usr/bin".to_vec()]);
            slate_rt::eprintln!("slate-boxd: /bin/tar: {e}");
            process::exit_now(127)
        }
        Ok(p) => p,
        Err(e) => return Err(format!("starting tar: {e}")),
    };
    match process::wait(pid, 0) {
        Ok((_, 0)) => Ok(()),
        Ok((_, st)) => Err(format!("unpacking {} failed (tar's status {})", d.title, session::exit_code(st))),
        Err(e) => Err(format!("waiting for tar: {e}")),
    }
}

/// Run `cmd` (`/bin/sh -c`) in the base at `at` (number `k`) as its root,
/// with the network; what it writes goes to `say`, line by line. Ok when
/// it succeeds; else its last line.
pub fn run_as_root(name: &str, at: &str, k: u32, cmd: &str, say: Say) -> Result<(), String> {
    let (r, w) = process::pipe(fs::O_CLOEXEC).map_err(|e| format!("a pipe: {e}"))?;
    let spec = Spec {
        name: String::from(name),
        root: String::from(at),
        uid: 0,
        gid: 0,
        groups: alloc::vec![0],
        cwd: String::from("/root"),
        argv: alloc::vec![b"/bin/sh".to_vec(), b"-c".to_vec(), cmd.as_bytes().to_vec()],
        env: [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
            "HOME=/root",
            "LANG=C.UTF-8",
            "TERM=dumb",
        ]
        .iter()
        .map(|e| e.as_bytes().to_vec())
        .collect(),
        network: true,
        tty: None,
        output: Some(w),
        share: None,
        shares: Vec::new(),
        host_dir: None,
    };
    let started = session::start(&spec, &mut |pid| write_maps(pid, k, None));
    let _ = io::close(w);
    let pid = match started {
        Ok(p) => p,
        Err(e) => {
            let _ = io::close(r);
            return Err(e);
        }
    };
    let mut last = String::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match io::read(r, &mut buf) {
            Ok(0) => break,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
            Err(slate_rt::Errno::EINTR) => continue,
            Err(_) => break,
        }
        while let Some(at) = pending.iter().position(|&b| b == b'\n' || b == b'\r') {
            let l: Vec<u8> = pending.drain(..=at).collect();
            let l = String::from(slate_rt::lossy(&l[..l.len() - 1]).trim_end());
            if !l.is_empty() {
                say(&l);
                last = l;
            }
        }
    }
    let _ = io::close(r);
    match session::finish(pid) {
        0 => Ok(()),
        code => Err(format!(
            "`{cmd}` failed (exit status {code}){}",
            if last.is_empty() { String::new() } else { format!(": {last}") }
        )),
    }
}

/// Write process `pid`'s ID maps for number `k` (with `person`, their
/// IDs outside, as 1000): slate-boxd is root in Slate's namespace, which
/// may map any IDs (user_namespaces(7)).
pub fn write_maps(pid: i32, k: u32, person: Option<(u32, u32)>) -> Result<(), String> {
    let put = |file: &str, text: &str| {
        let at = format!("/proc/{pid}/{file}");
        let fd = fs::open(at.as_bytes(), fs::O_WRONLY | fs::O_CLOEXEC, 0).map_err(|e| format!("{at}: {e}"))?;
        let r = io::write_all(fd, text.as_bytes()).map_err(|e| format!("{at}: {e}"));
        let _ = io::close(fd);
        r
    };
    put("gid_map", &ids::map(k, person.map(|p| p.1)))?;
    put("uid_map", &ids::map(k, person.map(|p| p.0)))
}

/// Make distribution `d`'s base unless it is there: its number.
pub fn ensure(d: &Distro, from: Option<&str>, say: Say) -> Result<u32, String> {
    let _held = lock(&format!("base-{}", d.name))?;
    let sv = format!("box-base.{}", d.name);
    let at = format!("{BASES}/{}", d.name);
    let done = format!("{STATE}/base-{}.ok", d.name);
    let k = {
        let _n = lock("numbers")?;
        let mut n = numbers();
        match n.find("base", 0, &d.name) {
            Some(x) => x.k,
            None => {
                let k = n.give("base", 0, &d.name)?;
                save_numbers(&n)?;
                k
            }
        }
    };
    if fs::exists(done.as_bytes()) && has_subvol(&sv) {
        mount_subvol(&sv, &at)?;
        return Ok(k);
    }
    say(&format!("Setting up {} for Linux boxes, once (it is fetched from its makers)", d.title));
    // A base left half made goes.
    drop_subvol(&sv, &at)?;
    slate_rt::subvol::ctl(BOXES, &format!("create {sv}"))?;
    mount_subvol(&sv, &at)?;
    let made = (|| -> Result<(), String> {
        let file = fetch_checked(d, from, say)?;
        say(&format!("Unpacking {} {}", d.title, d.release));
        unpack(d, &file, &at)?;
        let _ = fs::unlink(file.as_bytes());
        let moved = ids::shift_tree(&at, &|id| ids::into_range(id, k))?;
        say(&format!("Gave {moved} files the base's own owners"));
        for cmd in d.setup_commands() {
            say(&format!("Running {cmd}"));
            run_as_root(&format!("{}-base", d.name), &at, k, &cmd, say)?;
        }
        Ok(())
    })();
    if let Err(e) = made {
        let _ = drop_subvol(&sv, &at);
        return Err(e);
    }
    fs::write_file(done.as_bytes(), format!("{}\n", d.release).as_bytes(), 0o600)
        .map_err(|e| format!("{done}: {e}"))?;
    say(&format!("{} {} is ready for boxes", d.title, d.release));
    Ok(k)
}

/// A box's facts kept by slate-boxd: `.state/box.UID.NAME`, `key value`
/// lines (distro, user).
pub fn box_facts(uid: u32, name: &str) -> Vec<(String, String)> {
    let text = fs::read_file(format!("{STATE}/box.{uid}.{name}").as_bytes()).unwrap_or_default();
    slate_rt::lossy(&text)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(k, v)| (String::from(k), String::from(v))))
        .collect()
}

/// A file of the box's root, written and given to the box's root.
fn put_root(at: &str, rel: &str, text: &str, mode: u32, k: u32) -> Result<(), String> {
    let p = format!("{at}{rel}");
    fs::write_file(p.as_bytes(), text.as_bytes(), mode).map_err(|e| format!("{p}: {e}"))?;
    let r = ids::first_of(k);
    fs::lchown(p.as_bytes(), r, r).map_err(|e| format!("{p}: {e}"))?;
    fs::chmod(p.as_bytes(), mode).map_err(|e| format!("{p}: {e}"))
}

fn read(at: &str, rel: &str) -> String {
    String::from(slate_rt::lossy(&fs::read_file(format!("{at}{rel}").as_bytes()).unwrap_or_default()))
}

/// What a person's account in a box is called: their name, unless the
/// distribution has an account of that name (then `NAME-box`).
pub fn user_name(passwd: &str, slate_name: &str) -> String {
    let taken = |n: &str| passwd.lines().any(|l| l.split(':').next() == Some(n));
    if taken(slate_name) { format!("{slate_name}-box") } else { String::from(slate_name) }
}

/// group(5) with `user` added to `group`'s members.
pub fn with_member(groups: &str, group: &str, user: &str) -> String {
    let mut out = String::new();
    for l in groups.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() == 4 && f[0] == group && !f[3].split(',').any(|m| m == user) {
            let members = if f[3].is_empty() { String::from(user) } else { format!("{},{user}", f[3]) };
            out.push_str(&format!("{}:{}:{}:{members}", f[0], f[1], f[2]));
        } else {
            out.push_str(l);
        }
        out.push('\n');
    }
    out
}

/// The in-box IDs of the groups `user` is in (and 1000).
pub fn groups_of(groups: &str, user: &str) -> Vec<u32> {
    let mut out = alloc::vec![ids::PERSON];
    for l in groups.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() == 4
            && f[3].split(',').any(|m| m == user)
            && let Ok(g) = f[2].parse::<u32>()
            && !out.contains(&g)
        {
            out.push(g);
        }
    }
    out
}

/// The prompt's prefix in bash (the box's name, in the `linux` colour's
/// nearest of the 256: STRATA_COLORS.md's graphite `linux` is #8FB2A4).
pub const PROMPT: &str = "# SlateOS: this shell is in a Linux box, apart from SlateOS (ADR 0183).\n\
PS1='\\[\\e[38;5;109m\\][box \\h]\\[\\e[0m\\] '\"${PS1:-\\\\$ }\"\n";

/// The box's sudo: through slate-host when the session has it.
pub const SUDO: &str = "#!/bin/sh\n\
# SlateOS (ADR 0183): what runs as the box's root is kept as an install\n\
# receipt (slate-box installs lists them, slate-box undo takes one back).\n\
if [ -x /run/slate-box/slate-host ]; then exec /run/slate-box/slate-host sudo \"$@\"; fi\n\
exec /usr/bin/sudo \"$@\"\n";

/// The same for other shells, from /etc/profile.d.
pub const PROFILE: &str = "# SlateOS: shells in a Linux box name it (ADR 0183).\n\
if [ -n \"$SLATE_BOX\" ] && [ -z \"$BASH_VERSION\" ]; then\n    PS1=\"[box $SLATE_BOX] ${PS1:-\\$ }\"\nfi\n";

/// Make a new box's own files: the person's account and home, the host
/// name, sudo, the prompt. `at` is the box's root (number `k`), `uid` and
/// `gid` the person's IDs outside. The account's name.
pub fn personalize(
    at: &str,
    d: &Distro,
    name: &str,
    slate_name: &str,
    uid: u32,
    gid: u32,
    k: u32,
) -> Result<String, String> {
    let passwd = read(at, "/etc/passwd");
    let user = user_name(&passwd, slate_name);
    let home = format!("/home/{user}");
    let p = ids::PERSON;
    put_root(
        at,
        "/etc/passwd",
        &format!("{passwd}{user}:x:{p}:{p}:{slate_name} (SlateOS):{home}:{}\n", d.shell),
        0o644,
        k,
    )?;
    let group = read(at, "/etc/group");
    let group = with_member(&format!("{group}{user}:x:{p}:\n"), "wheel", &user);
    put_root(at, "/etc/group", &group, 0o644, k)?;
    if fs::exists(format!("{at}/etc/shadow").as_bytes()) {
        let shadow = read(at, "/etc/shadow");
        put_root(at, "/etc/shadow", &format!("{shadow}{user}:!*:20000::::::\n"), 0o600, k)?;
    }
    put_root(at, "/etc/hostname", &format!("{name}\n"), 0o644, k)?;
    // A machine ID of the box's own (machine-id(5)): systemd's tools treat
    // /etc without one as unset up.
    let mut id = [0u8; 16];
    process::random(&mut id).map_err(|e| format!("random bytes: {e}"))?;
    put_root(at, "/etc/machine-id", &format!("{}\n", slate_hash::hex(&id)), 0o444, k)?;
    let hosts = read(at, "/etc/hosts");
    if !hosts.lines().any(|l| l.split_whitespace().skip(1).any(|h| h == name)) {
        put_root(at, "/etc/hosts", &format!("{hosts}127.0.1.1 {name}\n"), 0o644, k)?;
    }
    if fs::stat(format!("{at}/etc/sudoers.d").as_bytes()).is_ok_and(|s| s.is_dir()) {
        put_root(
            at,
            "/etc/sudoers.d/10-slate-box",
            "# SlateOS (ADR 0183): the box is its person's; its root isn't SlateOS's.\n%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n",
            0o440,
            k,
        )?;
    }
    // sudo through slate-host, so what runs as the box's root is kept as
    // an install receipt (ADR 0183's phase 4); the distribution's own
    // sudo does the rest. /usr/local/bin comes first on the box's PATH.
    if fs::exists(format!("{at}/usr/bin/sudo").as_bytes()) {
        let _ = fs::mkdir(format!("{at}/usr/local").as_bytes(), 0o755);
        let _ = fs::mkdir(format!("{at}/usr/local/bin").as_bytes(), 0o755);
        put_root(at, "/usr/local/bin/sudo", SUDO, 0o755, k)?;
    }
    if fs::stat(format!("{at}/etc/profile.d").as_bytes()).is_ok_and(|s| s.is_dir()) {
        put_root(at, "/etc/profile.d/slate-box.sh", PROFILE, 0o644, k)?;
    }
    // The person's home in the box: theirs (ID 1000 is them), with the
    // distribution's starting files and the prompt.
    let h = format!("{at}{home}");
    let _ = fs::mkdir(format!("{at}/home").as_bytes(), 0o755);
    fs::mkdir(h.as_bytes(), 0o700).map_err(|e| format!("{h}: {e}"))?;
    for e in fs::read_dir(format!("{at}/etc/skel").as_bytes()).unwrap_or_default() {
        let n = slate_rt::lossy(&e.name);
        let src = format!("{at}/etc/skel/{n}");
        if fs::stat(src.as_bytes()).is_ok_and(|s| s.is_file())
            && let Ok(data) = fs::read_file(src.as_bytes())
        {
            let _ = fs::write_file(format!("{h}/{n}").as_bytes(), &data, 0o644);
        }
    }
    let rc = format!("{h}/.bashrc");
    let old = fs::read_file(rc.as_bytes()).unwrap_or_default();
    let _ = fs::write_file(rc.as_bytes(), &[old.as_slice(), b"\n", PROMPT.as_bytes()].concat(), 0o644);
    for e in fs::read_dir(h.as_bytes()).unwrap_or_default() {
        let _ = fs::lchown(format!("{h}/{}", slate_rt::lossy(&e.name)).as_bytes(), uid, gid);
    }
    fs::lchown(h.as_bytes(), uid, gid).map_err(|e| format!("{h}: {e}"))?;
    // Root's prompt too (`sudo -i`).
    if fs::stat(format!("{at}/root").as_bytes()).is_ok_and(|s| s.is_dir()) {
        let old = read(at, "/root/.bashrc");
        put_root(at, "/root/.bashrc", &format!("{old}\n{PROMPT}"), 0o644, k)?;
    }
    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts() {
        let pw = "root:x:0:0::/root:/bin/bash\ngit:x:971:971::/:/usr/bin/git-shell\n";
        assert_eq!(user_name(pw, "ada"), "ada");
        assert_eq!(user_name(pw, "git"), "git-box");
        let gr = "root:x:0:root\nwheel:x:998:\nada:x:1000:\nvideo:x:985:sam\n";
        let gr2 = with_member(gr, "wheel", "ada");
        assert!(gr2.contains("wheel:x:998:ada\n"));
        assert_eq!(with_member(&gr2, "wheel", "ada"), gr2);
        assert!(with_member(&gr2, "video", "ada").contains("video:x:985:sam,ada\n"));
        assert_eq!(groups_of(&gr2, "ada"), [1000, 998]);
        assert_eq!(
            file_name("https://m/iso/x/archlinux-bootstrap-x86_64.tar.zst"),
            "archlinux-bootstrap-x86_64.tar.zst"
        );
    }

    #[test]
    fn prompts() {
        assert!(PROMPT.contains("PS1='\\[\\e[38;5;109m\\][box \\h]\\[\\e[0m\\] '\"${PS1:-\\\\$ }\""));
        assert!(PROFILE.contains("PS1=\"[box $SLATE_BOX] ${PS1:-\\$ }\""));
    }
}
