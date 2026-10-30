// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux, transparent in SlateOS (ADR 0183's phase 3).
//!
//! Each person has one Linux system of their own: the box [`DEFAULT`],
//! made the first time it is needed. Its programs are SlateOS commands:
//!
//! - **The link farm** ([`FARM`], `~/.local/share/slate/linux/bin`, on
//!   PATH after Slate's own folders, /etc/profile): a link to
//!   /bin/slate-box for each program of the Linux system that Slate
//!   doesn't have. slate-box started under one of those names runs that
//!   program there, in the folder the person is in ([`share`]), as any
//!   command: no banner, its status passed on. The farm follows what is
//!   installed ([`sync`]) after every command run as the Linux system's
//!   root, and says which commands are new.
//! - **Linux source folders** ([`FOLDERS`], `~/.config/slate/
//!   linux-folders`): `+PATH` a folder whose programs and scripts run in
//!   Linux (`./configure`), `-PATH` one the person keeps SlateOS's.
//!   chalk asks once in a folder with a build file ([`BUILD_FILES`]) and
//!   routes `./x` there, and `sudo` of a Linux command anywhere, through
//!   `slate-box run [--root] --here`.
//! - **The folder you're in** is bound into the Linux system at the same
//!   path for that command (the box's home is at the person's own path),
//!   when it is in the person's home; elsewhere the command starts in its
//!   home in the box.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::fs;

/// The person's own Linux system.
pub const DEFAULT: &str = "linux";
/// The link farm, under the person's home.
pub const FARM: &str = ".local/share/slate/linux/bin";
/// The Linux source folders, under the person's home.
pub const FOLDERS: &str = ".config/slate/linux-folders";
/// What slate-box is, for the farm's links.
pub const SLATE_BOX: &str = "/bin/slate-box";
/// Slate's own command folders: a Linux program never shadows one.
pub const SLATE_PATH: &[&str] = &["/bin", "/sbin", "/usr/bin", "/usr/sbin"];
/// Where the Linux system's commands are (inside it).
pub const LINUX_BIN: &[&str] = &["/usr/local/bin", "/usr/local/sbin", "/usr/bin", "/usr/sbin", "/bin", "/sbin"];
/// Files that say a folder holds source to build (chalk asks there).
pub const BUILD_FILES: &[&str] = &[
    "configure",
    "configure.ac",
    "autogen.sh",
    "Makefile",
    "makefile",
    "GNUmakefile",
    "CMakeLists.txt",
    "meson.build",
    "Cargo.toml",
    "setup.py",
    "pyproject.toml",
];

/// The person's home (from HOME).
pub fn home() -> String {
    slate_rt::env::var(b"HOME").map(|h| String::from(slate_rt::lossy(&h))).unwrap_or_else(|| String::from("/"))
}

/// Which programs, of the Linux system's names, the farm should hold:
/// every name not in `slate`, not a dot file, sorted.
pub fn farm_names(linux: &[String], slate: &[String]) -> Vec<String> {
    let mut out: Vec<String> =
        linux.iter().filter(|n| !n.starts_with('.') && !n.contains('/') && !slate.contains(n)).cloned().collect();
    out.sort();
    out.dedup();
    out
}

/// The executable names in `dirs` under `root` (a folder's entries that
/// are files with an execute bit, or links).
fn programs(root: &str, dirs: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for d in dirs {
        let at = format!("{}{d}", root.trim_end_matches('/'));
        // A merged /bin (a link to usr/bin) is listed once.
        if fs::lstat(at.as_bytes()).is_ok_and(|s| s.is_symlink()) {
            continue;
        }
        for e in fs::read_dir(at.as_bytes()).unwrap_or_default() {
            let n = String::from(slate_rt::lossy(&e.name));
            let ok = fs::stat(format!("{at}/{n}").as_bytes()).is_ok_and(|s| !s.is_dir() && s.mode & 0o111 != 0)
                || fs::lstat(format!("{at}/{n}").as_bytes()).is_ok_and(|s| s.is_symlink());
            if ok {
                out.push(n);
            }
        }
    }
    out
}

/// Bring the farm up to date with the Linux system at `root`: the names
/// added.
pub fn sync(root: &str) -> Result<Vec<String>, String> {
    let farm = format!("{}/{FARM}", home());
    mkdir_p(&farm)?;
    let want = farm_names(&programs(root, LINUX_BIN), &programs("", SLATE_PATH));
    let have: Vec<String> = fs::read_dir(farm.as_bytes())
        .unwrap_or_default()
        .iter()
        .map(|e| String::from(slate_rt::lossy(&e.name)))
        .collect();
    for n in have.iter().filter(|n| !want.contains(n)) {
        let _ = fs::unlink(format!("{farm}/{n}").as_bytes());
    }
    let mut added = Vec::new();
    for n in want.iter().filter(|n| !have.contains(n)) {
        fs::symlink(SLATE_BOX.as_bytes(), format!("{farm}/{n}").as_bytes()).map_err(|e| format!("{farm}/{n}: {e}"))?;
        added.push(n.clone());
    }
    Ok(added)
}

/// What to say of the commands a sync added (nothing on the first one,
/// when there are hundreds).
pub fn added_note(added: &[String], first: bool) -> Option<String> {
    match added.len() {
        0 => None,
        _ if first => Some(format!("slate-box: {} Linux commands are ready in SlateOS's terminal", added.len())),
        1 => Some(format!("slate-box: {} is now a command", added[0])),
        n if n <= 5 => Some(format!("slate-box: {} are now commands", added.join(", "))),
        n => Some(format!("slate-box: {n} new Linux commands, among them {}", added[..3].join(", "))),
    }
}

fn mkdir_p(path: &str) -> Result<(), String> {
    let mut at = String::new();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        at.push('/');
        at.push_str(part);
        match fs::mkdir(at.as_bytes(), 0o755) {
            Ok(()) | Err(slate_rt::Errno::EEXIST) => {}
            Err(e) => return Err(format!("{at}: {e}")),
        }
    }
    Ok(())
}

/// A Linux source folder's mark: whether `path` is in a folder marked
/// `+` (Some(true)) or `-` (Some(false)), the deepest mark deciding.
pub fn marked(folders: &str, path: &str) -> Option<bool> {
    folders
        .lines()
        .filter_map(|l| {
            let (sign, p) = l.split_at_checked(1)?;
            let p = p.trim_end_matches('/');
            let inside = path == p || path.starts_with(&format!("{p}/"));
            (inside && (sign == "+" || sign == "-")).then_some((p.len(), sign == "+"))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, linux)| linux)
}

/// The folders file with `path` marked `linux` (or not), replacing a mark
/// of the same folder.
pub fn with_mark(folders: &str, path: &str, linux: bool) -> String {
    let path = path.trim_end_matches('/');
    let mut out: String = folders
        .lines()
        .filter(|l| l.get(1..).map(|p| p.trim_end_matches('/')) != Some(path))
        .map(|l| format!("{l}\n"))
        .collect();
    out.push_str(&format!("{}{path}\n", if linux { '+' } else { '-' }));
    out
}

/// Mark `path` (a folder) as a Linux source folder, or as SlateOS's.
pub fn mark(path: &str, linux: bool) -> Result<(), String> {
    let at = format!("{}/{FOLDERS}", home());
    mkdir_p(at.rsplit_once('/').map_or("", |(d, _)| d))?;
    let text = fs::read_file(at.as_bytes()).map(|t| String::from(slate_rt::lossy(&t))).unwrap_or_default();
    fs::write_file(at.as_bytes(), with_mark(&text, path, linux).as_bytes(), 0o644).map_err(|e| format!("{at}: {e}"))
}

/// The folder a command shares with the Linux system: `cwd` when it is in
/// `home` (and not just `/`), else None (it starts in its home there).
pub fn share(cwd: &str, home: &str) -> Option<String> {
    let home = home.trim_end_matches('/');
    let cwd = cwd.trim_end_matches('/');
    (!home.is_empty() && (cwd == home || cwd.starts_with(&format!("{home}/")))).then(|| String::from(cwd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn farms() {
        let linux = s(&["make", "gcc", "ls", "hello", ".hidden", "make", "cc"]);
        let slate = s(&["ls", "cat", "sh"]);
        assert_eq!(farm_names(&linux, &slate), s(&["cc", "gcc", "hello", "make"]));
        assert_eq!(added_note(&s(&["hello"]), false).unwrap(), "slate-box: hello is now a command");
        assert_eq!(added_note(&s(&["a", "b"]), false).unwrap(), "slate-box: a, b are now commands");
        assert!(added_note(&s(&["a"; 300]), true).unwrap().contains("300 Linux commands"));
        assert_eq!(added_note(&[], false), None);
    }

    #[test]
    fn folders() {
        let f = "+/home/ada/src\n-/home/ada/src/slate-thing\n";
        assert_eq!(marked(f, "/home/ada/src/hello-2.12.3"), Some(true));
        assert_eq!(marked(f, "/home/ada/src"), Some(true));
        assert_eq!(marked(f, "/home/ada/src/slate-thing/x"), Some(false));
        assert_eq!(marked(f, "/home/ada/srcx"), None);
        assert_eq!(marked("", "/home/ada"), None);
        let g = with_mark(f, "/home/ada/src/", false);
        assert_eq!(g, "-/home/ada/src/slate-thing\n-/home/ada/src\n");
        assert_eq!(marked(&g, "/home/ada/src/hello"), Some(false));
    }

    #[test]
    fn shares() {
        assert_eq!(share("/home/ada/src/hello", "/home/ada").as_deref(), Some("/home/ada/src/hello"));
        assert_eq!(share("/home/ada", "/home/ada/").as_deref(), Some("/home/ada"));
        assert_eq!(share("/home/adam", "/home/ada"), None);
        assert_eq!(share("/etc", "/home/ada"), None);
        assert_eq!(share("/x", "/"), None);
    }
}
