// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-host (ADR 0183), Slate's own program inside a Linux box. A
//! session copies it into the box's /run, where it runs as a Linux program
//! (it is outside SlateOS's system tree there, so the Linux domain), and
//! it does what a box needs from Slate:
//!
//! - `slate-host init UID GID GROUPS CWD -- COMMAND...`: the box's PID 1.
//!   It starts the command as the box's user (GROUPS comma separated),
//!   reaps whatever is orphaned, and when the command ends, ends the rest
//!   of the box's processes and passes the command's status on. Being a
//!   Linux program, it is the PID 1 the box's programs see in /proc (a
//!   Slate process would be hidden from them).
//! - `slate-host sudo COMMAND...` (the box's /usr/local/bin/sudo runs it):
//!   the command as the box's root (through the distribution's sudo, or
//!   directly when root already), with an install receipt around it asked
//!   for over the session's channel ([`crate::channel`]).
//! - `slate-host info`: what Slate says this box is.
//! - `slate-host check-channel`: a forged and a replayed message sent on
//!   purpose, each refused (the boxes scenario's check).

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{eprintln, process, signal};

use crate::session;

/// Where a session puts slate-host in the box.
pub const IN_BOX: &str = "/run/slate-box/slate-host";
/// Where Slate keeps it.
pub const ON_SLATE: &str = "/usr/lib/slate/slate-host";

/// `init`'s arguments: (uid, gid, groups, cwd, command).
pub type InitArgs = (u32, u32, Vec<u32>, String, Vec<String>);

pub fn parse_init(args: &[String]) -> Option<InitArgs> {
    let [uid, gid, groups, cwd, dash, cmd @ ..] = args else { return None };
    if dash != "--" || cmd.is_empty() {
        return None;
    }
    let groups = groups.split(',').filter(|g| !g.is_empty()).map(|g| g.parse().ok()).collect::<Option<Vec<u32>>>()?;
    Some((uid.parse().ok()?, gid.parse().ok()?, groups, cwd.clone(), cmd.to_vec()))
}

pub fn main() -> i32 {
    let args: Vec<String> = slate_rt::env::args().iter().skip(1).map(|a| String::from(slate_rt::lossy(a))).collect();
    match args.first().map(String::as_str) {
        Some("init") => match parse_init(&args[1..]) {
            Some((uid, gid, groups, cwd, cmd)) => init(uid, gid, &groups, &cwd, &cmd),
            None => {
                eprintln!("usage: slate-host init UID GID GROUPS CWD -- COMMAND [ARGUMENT...]");
                2
            }
        },
        Some("sudo") => sudo(&args[1..]),
        Some("info") => match crate::channel::ask("info") {
            Ok(a) => {
                slate_rt::println!("{}", a.strip_prefix("ok\t").unwrap_or(&a).replace('\t', "\n"));
                0
            }
            Err(e) => {
                eprintln!("slate-host: {e}");
                1
            }
        },
        Some("check-channel") => check_channel(),
        _ => {
            eprintln!("slate-host: SlateOS's helper in a Linux box (it is started by slate-box)");
            2
        }
    }
}

/// The distribution's own sudo.
const SUDO: &str = "/usr/bin/sudo";

/// `slate-host sudo COMMAND...`: the command as the box's root, kept as an
/// install receipt when the session's channel is there.
fn sudo(args: &[String]) -> i32 {
    // The command, past sudo's own options (for the receipt's label).
    let cmd: Vec<String> = args.iter().skip_while(|a| a.starts_with('-')).cloned().collect();
    let cwd = slate_rt::fs::getcwd().map(|c| String::from(slate_rt::lossy(&c))).unwrap_or_default();
    let channel = slate_rt::fs::exists(alloc::format!("{}/socket", crate::channel::IN_BOX).as_bytes());
    let began = channel
        && !cmd.is_empty()
        && crate::channel::ask(&alloc::format!(
            "begin\t{}\t{}",
            crate::receipts::label_for(&cmd, &cwd),
            cmd.join(" ").replace(['\t', '\n'], " ")
        ))
        .is_ok_and(|a| a.len() > 3 && a.starts_with("ok\t"));
    let argv: Vec<Vec<u8>> = if process::geteuid() == 0 {
        cmd.iter().map(|a| a.clone().into_bytes()).collect()
    } else {
        core::iter::once(SUDO).chain(args.iter().map(String::as_str)).map(|a| a.as_bytes().to_vec()).collect()
    };
    let status = if argv.is_empty() {
        0
    } else {
        let env: Vec<Vec<u8>> = slate_rt::env::vars().to_vec();
        match process::fork() {
            Ok(0) => {
                let path = session::find_in_box(&argv[0], &env);
                let e = process::execve(&path, &argv, &env);
                eprintln!("sudo: {}: {e}", slate_rt::lossy(&argv[0]));
                process::exit_now(127)
            }
            Ok(pid) => session::finish(pid),
            Err(e) => {
                eprintln!("sudo: {e}");
                1
            }
        }
    };
    if began {
        match crate::channel::ask("end") {
            Ok(a) => {
                let f: Vec<&str> = a.split('\t').collect();
                if let ["ok", _, label, count] = f.as_slice() {
                    eprintln!(
                        "slate-box: kept a receipt of what this changed: \"{label}\" ({count} files); `slate-box undo {label}` takes it back"
                    );
                }
            }
            Err(e) => eprintln!("slate-host: the install receipt: {e}"),
        }
    }
    status
}

/// Send a forged and a replayed message on purpose; both must end the
/// connection unanswered.
fn check_channel() -> i32 {
    use crate::channel::{IN_BOX, Sealed, read_exact, read_frame};
    let Ok(secret) = slate_rt::fs::read_file(alloc::format!("{IN_BOX}/key").as_bytes()) else {
        eprintln!("slate-host: no channel here");
        return 1;
    };
    // A connection with its keys agreed.
    let open = || -> Option<(i32, Sealed)> {
        let fd = slate_rt::net::connect_path(alloc::format!("{IN_BOX}/socket").as_bytes()).ok()?;
        let mut mine = [0u8; 32];
        process::random(&mut mine).ok()?;
        slate_rt::io::write_all(fd, &mine).ok()?;
        let mut theirs = [0u8; 32];
        read_exact(fd, &mut theirs).ok()?;
        Some((fd, Sealed::new(&secret, &mine, &theirs, true)))
    };
    let mut ok = true;
    // Forged: a sealed request with a bit changed.
    if let Some((fd, mut s)) = open() {
        let mut f = s.seal(b"info");
        let last = f.len() - 1;
        f[last] ^= 1;
        let _ = slate_rt::io::write_all(fd, &f);
        let refused = read_frame(fd).is_err();
        slate_rt::println!("forged: {}", if refused { "refused" } else { "ANSWERED" });
        ok &= refused;
        let _ = slate_rt::io::close(fd);
    }
    // Replayed: a good request, answered, then the same bytes again.
    if let Some((fd, mut s)) = open() {
        let f = s.seal(b"info");
        let _ = slate_rt::io::write_all(fd, &f);
        let first = read_frame(fd).is_ok();
        let _ = slate_rt::io::write_all(fd, &f);
        let refused = read_frame(fd).is_err();
        slate_rt::println!("first: {}", if first { "answered" } else { "REFUSED" });
        slate_rt::println!("replayed: {}", if refused { "refused" } else { "ANSWERED" });
        ok &= first && refused;
        let _ = slate_rt::io::close(fd);
    }
    if ok { 0 } else { 1 }
}

fn init(uid: u32, gid: u32, groups: &[u32], cwd: &str, cmd: &[String]) -> i32 {
    let _ = signal::set(signal::SIGINT, signal::Disposition::Ignore);
    let _ = signal::set(signal::SIGQUIT, signal::Disposition::Ignore);
    let env: Vec<Vec<u8>> = slate_rt::env::vars().to_vec();
    let argv: Vec<Vec<u8>> = cmd.iter().map(|a| a.clone().into_bytes()).collect();
    let child = match process::fork() {
        Ok(0) => session::become_and_exec(uid, gid, groups, cwd, &argv, &env, None),
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("slate-box: starting {}: {e}", cmd[0]);
            return 126;
        }
    };
    let status = loop {
        match process::wait(-1, 0) {
            Ok((p, st)) if p == child => break st,
            Ok(_) | Err(slate_rt::Errno::EINTR) => {}
            Err(_) => break 0,
        }
    };
    // What the command left running ends with it (the PID namespace's own
    // processes only: this is its first).
    let _ = process::kill(-1, signal::SIGKILL);
    while process::wait(-1, 0).is_ok() {}
    session::exit_code(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn init_args() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_init(&a(&["1000", "1000", "1000,998", "/home/ada", "--", "bash", "-l"])),
            Some((1000, 1000, alloc::vec![1000, 998], "/home/ada".to_string(), a(&["bash", "-l"])))
        );
        assert_eq!(parse_init(&a(&["0", "0", "0", "/root", "--"])), None);
        assert_eq!(parse_init(&a(&["x", "0", "0", "/", "--", "id"])), None);
        assert_eq!(parse_init(&a(&["0", "0", "", "/", "--", "id"])).unwrap().2, alloc::vec![]);
    }
}
