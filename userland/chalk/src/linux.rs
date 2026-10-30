// SPDX-License-Identifier: MIT OR Apache-2.0

//! Linux programs from SlateOS's own shell (ADR 0183's phase 3). The
//! person's Linux system's commands are on PATH already (a farm of links
//! to slate-box); chalk sends two more kinds of command there:
//!
//! - a program or script named by its path (`./configure`) in a **Linux
//!   source folder**, the folders marked `+` in `~/.config/slate/
//!   linux-folders` (`-` keeps one SlateOS's; the deepest mark decides).
//!   In a folder with a build file and no mark, an interactive shell asks
//!   once and marks the project's folder;
//! - `sudo` of a Linux command (one from the farm, or a program in a Linux
//!   source folder), which runs as the Linux system's root.
//!
//! Both become `slate-box run [--root] --here linux -- COMMAND...`. The
//! folders file and its rules are slate-boxes' (`native.rs`); chalk keeps
//! its own copy of the little it needs, so as not to carry slate-box's.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, Ordering};

use slate_rt::{fs, io, lossy};

/// Whether root's shell has been told that it has no Linux system.
static ROOT_TOLD: AtomicBool = AtomicBool::new(false);

/// The link farm and the folders file, under the person's home.
const FARM: &str = ".local/share/slate/linux/bin";
const FOLDERS: &str = ".config/slate/linux-folders";
/// Files that say a folder holds source to build (as slate-boxes').
const BUILD_FILES: &[&str] = &[
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

/// The deepest mark over `path` in the folders file's text.
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

/// The person's home.
fn home() -> String {
    slate_rt::env::var(b"HOME").map(|h| String::from(lossy(&h))).unwrap_or_default()
}

/// `path` made absolute (against the working folder), without `.` parts.
fn absolute(path: &[u8]) -> String {
    let p = String::from(lossy(path));
    let full = if p.starts_with('/') {
        p
    } else {
        let cwd = fs::getcwd().map(|c| String::from(lossy(&c))).unwrap_or_default();
        format!("{}/{p}", cwd.trim_end_matches('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

/// The folder of the nearest build file at or above `dir`, within `home`.
fn project(dir: &str, home: &str) -> Option<String> {
    let mut at = String::from(dir);
    loop {
        if !(at == home || at.starts_with(&format!("{home}/"))) {
            return None;
        }
        if BUILD_FILES.iter().any(|f| fs::exists(format!("{at}/{f}").as_bytes())) {
            return Some(at);
        }
        at = String::from(at.rsplit_once('/')?.0);
    }
}

/// Mark `dir` in the folders file.
fn mark(dir: &str, linux: bool) {
    let home = home();
    let at = format!("{home}/{FOLDERS}");
    let mut parent = String::new();
    for part in at.rsplit_once('/').map_or("", |(d, _)| d).split('/').filter(|p| !p.is_empty()) {
        parent.push('/');
        parent.push_str(part);
        let _ = fs::mkdir(parent.as_bytes(), 0o755);
    }
    let mut text = fs::read_file(at.as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    text.push_str(&format!("{}{dir}\n", if linux { '+' } else { '-' }));
    let _ = fs::write_file(at.as_bytes(), text.as_bytes(), 0o644);
}

/// Whether the program at `path` goes to Linux: in a folder marked as
/// Linux source, or, asked about now (when `ask`), in a project the person
/// says to build with Linux tools; and `linux_file` (checked only then:
/// it reads the file) says it isn't a Slate program.
fn in_linux_folder(path: &[u8], ask: bool, linux_file: &dyn Fn() -> bool) -> bool {
    let home = home();
    if home.is_empty() || home == "/" {
        return false;
    }
    let full = absolute(path);
    let dir = full.rsplit_once('/').map_or("/", |(d, _)| if d.is_empty() { "/" } else { d });
    if !(dir == home || dir.starts_with(&format!("{home}/"))) {
        return false;
    }
    let text =
        fs::read_file(format!("{home}/{FOLDERS}").as_bytes()).map(|t| String::from(lossy(&t))).unwrap_or_default();
    if let Some(linux) = marked(&text, dir) {
        return linux && linux_file();
    }
    let Some(top) = project(dir, &home).filter(|_| ask) else { return false };
    if !linux_file() {
        return false;
    }
    io::err(
        format!(
            "{top} has source code. Build and run it with Linux tools, in your Linux system \
             (apart from SlateOS)? [Y/n] "
        )
        .as_bytes(),
    );
    let mut b = [0u8; 64];
    let n = io::read(0, &mut b).unwrap_or(0);
    let yes = !matches!(b[..n].iter().find(|c| !c.is_ascii_whitespace()), Some(b'n' | b'N'));
    mark(&top, yes);
    yes
}

/// Whether `path` is a Slate program (an ELF file carrying Slate's ABI
/// note, which the shell runs itself wherever it is).
fn slate_program(path: &[u8]) -> bool {
    let Ok(fd) = fs::open(path, fs::O_RDONLY | fs::O_CLOEXEC, 0) else { return false };
    let mut head = alloc::vec![0u8; 64 << 10];
    let n = io::read(fd, &mut head).unwrap_or(0);
    let _ = io::close(fd);
    let head = &head[..n];
    head.starts_with(b"\x7fELF") && head.windows(6).any(|w| w == b"Slate\0")
}

/// What runs instead of `argv` (Some: in the person's Linux system).
/// `lookup` finds a command on PATH; `ask` says the shell may ask.
pub fn route(argv: &[Vec<u8>], lookup: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>, ask: bool) -> Option<Vec<Vec<u8>>> {
    let first = argv.first()?;
    // Root has no Linux system (slate-boxd makes them for people's own
    // accounts): nothing is asked or routed, and an interactive shell
    // says why once, at the first program run in a source folder.
    if slate_rt::process::getuid() == 0 {
        if ask && first.contains(&b'/') && !ROOT_TOLD.swap(true, Ordering::Relaxed) {
            let full = absolute(first);
            let dir = full.rsplit_once('/').map_or("/", |(d, _)| if d.is_empty() { "/" } else { d });
            if BUILD_FILES.iter().any(|f| fs::exists(format!("{dir}/{f}").as_bytes())) {
                io::err(
                    b"SlateOS: Linux software is built in your own account's Linux system, not root's. \
                      Log in as your own account to build this with Linux tools.\n",
                );
            }
        }
        return None;
    }
    let to_linux = |root: bool, rest: &[Vec<u8>]| {
        let mut v: Vec<Vec<u8>> = alloc::vec![b"slate-box".to_vec(), b"run".to_vec()];
        if root {
            v.push(b"--root".to_vec());
        }
        v.extend([b"--here".to_vec(), b"linux".to_vec(), b"--".to_vec()]);
        v.extend(rest.iter().cloned());
        v
    };
    if first.as_slice() == b"sudo" {
        let target = argv.get(1).filter(|t| !t.starts_with(b"-"))?;
        let farm = format!("{}/{FARM}/", home());
        let from_farm = !target.contains(&b'/') && lookup(target).is_some_and(|p| p.starts_with(farm.as_bytes()));
        let in_folder = target.contains(&b'/') && in_linux_folder(target, ask, &|| !slate_program(target));
        return (from_farm || in_folder).then(|| to_linux(true, &argv[1..]));
    }
    if first.contains(&b'/') && fs::exists(first) && in_linux_folder(first, ask, &|| !slate_program(first)) {
        return Some(to_linux(false, argv));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks() {
        let f = "+/home/ada/src\n-/home/ada/src/mine\n";
        assert_eq!(marked(f, "/home/ada/src/hello-2.12.3"), Some(true));
        assert_eq!(marked(f, "/home/ada/src/mine/x"), Some(false));
        assert_eq!(marked(f, "/home/ada/srcx"), None);
    }

    #[test]
    fn sudo_of_slate_commands_stays() {
        let mut none = |_: &[u8]| None;
        assert_eq!(route(&[b"sudo".to_vec(), b"quarry".to_vec()], &mut none, false), None);
        assert_eq!(route(&[b"sudo".to_vec(), b"-i".to_vec()], &mut none, false), None);
        assert_eq!(route(&[b"ls".to_vec()], &mut none, false), None);
    }
}
