// SPDX-License-Identifier: MIT OR Apache-2.0

//! `chattr [-RVf] [+-=FLAGS]... FILE...` and `lsattr [-RVadl] [FILE...]`
//! (e2fsprogs' interface, chattr(1) and lsattr(1)): a file's inode flags,
//! through FS_IOC_GETFLAGS and FS_IOC_SETFLAGS (ioctl_iflags(2)). On
//! SlateOS the only file system with flags is efivarfs, whose variables
//! are immutable (`i`) until root clears the flag (ADR 0088).
//!
//! The flags' bits, their columns in lsattr's 22-column listing and their
//! long names were observed on the host: `chattr +X` on a btrfs file, then
//! FS_IOC_GETFLAGS, `lsattr` and `lsattr -l` (the immutable flag on
//! efivarfs). Letters chattr(1) documents whose bits couldn't be observed
//! that way (`a`, `D`, `j`, `s`, `t`, `T`, `u`...) are refused by name;
//! SlateOS has none of them.

use alloc::string::String;
use alloc::vec::Vec;

use slate_rt::{Errno, eprintln, fs, io, lossy, println};

/// FS_IOC_GETFLAGS and FS_IOC_SETFLAGS, `_IOR('f', 1, long)` and
/// `_IOW('f', 2, long)` (ioctl_iflags(2)); as in kernel/src/fs/efivarfs.rs.
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;

/// lsattr's listing is this many columns wide.
const COLUMNS: usize = 22;

/// A flag: its letter, its bit, its column in the listing, its long name
/// (`lsattr -l`). In column order, which is also `-l`'s order.
const FLAGS: &[(u8, u32, usize, &str)] = &[
    (b'S', 0x8, 2, "Synchronous_Updates"),
    (b'i', 0x10, 4, "Immutable"),
    (b'd', 0x40, 6, "No_Dump"),
    (b'A', 0x80, 7, "No_Atime"),
    (b'c', 0x4, 8, "Compression_Requested"),
    (b'C', 0x80_0000, 15, "No_COW"),
    (b'm', 0x400, 21, "Dont_Compress"),
];

/// Letters chattr(1) documents that SlateOS has no bit for.
const UNKNOWN: &[u8] = b"aDeFjPstTux";

const CHATTR_USAGE: &str = "Usage: chattr [-RVf] [-+=aAcCdDeijPsStTuFx] [-p project] [-v version] files...";
const LSATTR_USAGE: &str = "Usage: lsattr [-RVadlpv] [files...]";

/// `flags` as lsattr lists them: a letter in its column, `-` elsewhere.
pub fn short_form(flags: u32) -> String {
    let mut s = [b'-'; COLUMNS];
    for &(c, bit, col, _) in FLAGS {
        if flags & bit != 0 {
            s[col] = c;
        }
    }
    String::from_utf8_lossy(&s).into_owned()
}

/// `flags` as `lsattr -l` lists them: long names, or `---`.
pub fn long_form(flags: u32) -> String {
    let names: Vec<&str> = FLAGS.iter().filter(|f| flags & f.1 != 0).map(|f| f.3).collect();
    if names.is_empty() { String::from("---") } else { names.join(", ") }
}

/// A chattr mode: flags to add, to remove, or to set exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mode {
    pub add: u32,
    pub remove: u32,
    pub set: Option<u32>,
}

impl Mode {
    /// Add one `+FLAGS`, `-FLAGS` or `=FLAGS` word; the error to print.
    pub fn parse(&mut self, word: &[u8]) -> Result<(), String> {
        let (op, letters) = word.split_first().ok_or_else(|| String::from(CHATTR_USAGE))?;
        let mut bits = 0;
        for &c in letters {
            match FLAGS.iter().find(|f| f.0 == c) {
                Some(f) => bits |= f.1,
                None if UNKNOWN.contains(&c) => {
                    return Err(alloc::format!("chattr: the '{}' flag is not supported on SlateOS", c as char));
                }
                None => return Err(String::from(CHATTR_USAGE)),
            }
        }
        match op {
            b'+' => self.add |= bits,
            b'-' => self.remove |= bits,
            b'=' => self.set = Some(self.set.unwrap_or(0) | bits),
            _ => return Err(String::from(CHATTR_USAGE)),
        }
        if self.set.is_some() && (self.add | self.remove) != 0 {
            return Err(String::from("= is incompatible with - and +"));
        }
        if self.add & self.remove != 0 {
            return Err(String::from("Can't both set and unset same flag."));
        }
        Ok(())
    }

    /// The flags a file with `old` gets.
    pub fn apply(&self, old: u32) -> u32 {
        self.set.unwrap_or((old | self.add) & !self.remove)
    }
}

/// Whether a `-WORD` before the files is chattr's options (`-R`, `-V`,
/// `-f`, `-v`, `-p`) rather than flags to remove.
fn is_option(word: &[u8]) -> bool {
    word.len() > 1 && word[1..].iter().all(|c| b"RVfvp".contains(c))
}

/// e2fsprogs' messages read "...: Operation not supported while ...";
/// a file system without flags answers ENOTTY, which they report so.
fn reason(e: Errno) -> Errno {
    if e == Errno::ENOTTY { Errno::EOPNOTSUPP } else { e }
}

/// A file's flags. Only regular files and directories have them;
/// anything else is not opened (a FIFO would block).
fn get_flags(path: &[u8], st: &fs::Stat) -> Result<u32, Errno> {
    if !st.is_file() && !st.is_dir() {
        return Err(Errno::EOPNOTSUPP);
    }
    let fd = fs::open(path, fs::O_RDONLY | fs::O_NONBLOCK | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0)?;
    let mut flags: u64 = 0;
    let r = io::ioctl(fd, FS_IOC_GETFLAGS, &mut flags as *mut u64 as usize);
    let _ = io::close(fd);
    r.map(|_| flags as u32).map_err(reason)
}

fn set_flags(path: &[u8], flags: u32) -> Result<(), Errno> {
    let fd = fs::open(path, fs::O_RDONLY | fs::O_NONBLOCK | fs::O_NOFOLLOW | fs::O_CLOEXEC, 0)?;
    let mut f = u64::from(flags);
    let r = io::ioctl(fd, FS_IOC_SETFLAGS, &mut f as *mut u64 as usize);
    let _ = io::close(fd);
    r.map(|_| ()).map_err(reason)
}

/// `dir/name`, without doubling a slash.
fn join(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut p = dir.to_vec();
    if !p.ends_with(b"/") {
        p.push(b'/');
    }
    p.extend_from_slice(name);
    p
}

struct Chattr {
    mode: Mode,
    recursive: bool,
    verbose: bool,
    quiet: bool,
}

impl Chattr {
    /// Change one file (and, with -R, what a directory holds); whether
    /// everything went well.
    fn change(&self, path: &[u8]) -> bool {
        let st = match fs::lstat(path) {
            Ok(st) => st,
            Err(e) => {
                if !self.quiet {
                    eprintln!("chattr: {} while trying to stat {}", e, lossy(path));
                }
                return false;
            }
        };
        let mut ok = true;
        let old = if self.mode.set.is_some() {
            Ok(0)
        } else {
            get_flags(path, &st).inspect_err(|e| {
                if !self.quiet {
                    eprintln!("chattr: {} while reading flags on {}", e, lossy(path));
                }
            })
        };
        if let Ok(old) = old {
            let new = self.mode.apply(old);
            let r = if st.is_file() || st.is_dir() { set_flags(path, new) } else { Err(Errno::EOPNOTSUPP) };
            match r {
                Ok(()) if self.verbose => println!("Flags of {} set as {}", lossy(path), short_form(new)),
                Ok(()) => {}
                Err(e) => {
                    if !self.quiet {
                        eprintln!("chattr: {} while setting flags on {}", e, lossy(path));
                    }
                    ok = false;
                }
            }
        } else {
            ok = false;
        }
        if self.recursive && st.is_dir() {
            match fs::read_dir(path) {
                Ok(entries) => {
                    for e in entries {
                        ok &= self.change(&join(path, &e.name));
                    }
                }
                Err(e) => {
                    if !self.quiet {
                        eprintln!("chattr: {} while reading {}", e, lossy(path));
                    }
                    ok = false;
                }
            }
        }
        ok
    }
}

pub fn chattr(args: &[Vec<u8>]) -> i32 {
    let mut c = Chattr { mode: Mode::default(), recursive: false, verbose: false, quiet: false };
    let mut has_mode = false;
    let mut i = 1;
    while i < args.len() {
        let a = &args[i];
        if a == b"--" {
            i += 1;
            break;
        }
        if a.first() == Some(&b'-') && is_option(a) {
            for &o in &a[1..] {
                match o {
                    b'R' => c.recursive = true,
                    b'V' => c.verbose = true,
                    b'f' => c.quiet = true,
                    _ => {
                        eprintln!("chattr: setting a version or project is not supported on SlateOS");
                        return 1;
                    }
                }
            }
        } else if matches!(a.first(), Some(b'+' | b'-' | b'=')) {
            if let Err(msg) = c.mode.parse(a) {
                eprintln!("{msg}");
                return 1;
            }
            has_mode = true;
        } else {
            break;
        }
        i += 1;
    }
    if c.verbose {
        eprintln!("chattr (SlateOS) {}", env!("CARGO_PKG_VERSION"));
    }
    if !has_mode {
        eprintln!("Must use '-v', =, - or +");
        return 1;
    }
    if i >= args.len() {
        eprintln!("{CHATTR_USAGE}");
        return 1;
    }
    let mut ok = true;
    for path in &args[i..] {
        ok &= c.change(path);
    }
    i32::from(!ok)
}

struct Lsattr {
    recursive: bool,
    all: bool,
    dirs: bool,
    long: bool,
}

impl Lsattr {
    /// One line for `path`; whether its flags could be read.
    fn show(&self, path: &[u8], st: &fs::Stat) -> bool {
        match get_flags(path, st) {
            Ok(f) if self.long => {
                println!("{:<28} {}", lossy(path), long_form(f));
                true
            }
            Ok(f) => {
                println!("{} {}", short_form(f), lossy(path));
                true
            }
            Err(e) => {
                eprintln!("lsattr: {} While reading flags on {}", e, lossy(path));
                false
            }
        }
    }

    /// A directory's entries (with -a, `.` and `..` and hidden ones),
    /// then with -R each subdirectory's.
    fn list_dir(&self, dir: &[u8]) {
        let mut entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("lsattr: {} while reading {}", e, lossy(dir));
                return;
            }
        };
        entries.retain(|e| self.all || e.name.first() != Some(&b'.'));
        let mut names: Vec<Vec<u8>> = Vec::new();
        if self.all {
            names.push(b".".to_vec());
            names.push(b"..".to_vec());
        }
        names.extend(entries.into_iter().map(|e| e.name));
        let mut subdirs = Vec::new();
        for name in names {
            let path = join(dir, &name);
            let Ok(st) = fs::lstat(&path) else { continue };
            self.show(&path, &st);
            if self.recursive && st.is_dir() && name != b"." && name != b".." {
                subdirs.push(path);
            }
        }
        for d in subdirs {
            println!("\n{}:", lossy(&d));
            self.list_dir(&d);
            println!();
        }
    }
}

pub fn lsattr(args: &[Vec<u8>]) -> i32 {
    let mut l = Lsattr { recursive: false, all: false, dirs: false, long: false };
    let mut files = Vec::new();
    let mut options = true;
    for a in &args[1..] {
        if options && a == b"--" {
            options = false;
        } else if options && a.len() > 1 && a[0] == b'-' {
            for &o in &a[1..] {
                match o {
                    b'R' => l.recursive = true,
                    b'a' => l.all = true,
                    b'd' => l.dirs = true,
                    b'l' => l.long = true,
                    b'V' => eprintln!("lsattr (SlateOS) {}", env!("CARGO_PKG_VERSION")),
                    b'v' | b'p' => {
                        eprintln!("lsattr: versions and projects are not supported on SlateOS");
                        return 1;
                    }
                    _ => {
                        eprintln!("lsattr: invalid option -- '{}'", o as char);
                        eprintln!("{LSATTR_USAGE}");
                        return 1;
                    }
                }
            }
        } else {
            files.push(a.clone());
        }
    }
    if files.is_empty() {
        files.push(b".".to_vec());
    }
    let mut status = 0;
    for path in &files {
        let st = match fs::lstat(path) {
            Ok(st) => st,
            Err(e) => {
                eprintln!("lsattr: {} while trying to stat {}", e, lossy(path));
                status = 1;
                continue;
            }
        };
        if st.is_dir() && !l.dirs {
            l.list_dir(path);
        } else if !l.show(path, &st) {
            status = 1;
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_columns() {
        assert_eq!(short_form(0), "----------------------");
        assert_eq!(short_form(0x10), "----i-----------------");
        assert_eq!(short_form(0x40 | 0x80), "------dA--------------");
        assert_eq!(short_form(0x80 | 0x80_0000), "-------A-------C------");
        assert_eq!(short_form(0x8 | 0x400), "--S------------------m");
    }

    #[test]
    fn long_names() {
        assert_eq!(long_form(0), "---");
        assert_eq!(long_form(0x10), "Immutable");
        assert_eq!(long_form(0x40 | 0x80), "No_Dump, No_Atime");
    }

    #[test]
    fn modes() {
        let mut m = Mode::default();
        m.parse(b"+A").unwrap();
        m.parse(b"-d").unwrap();
        assert_eq!(m.apply(0x40 | 0x10), 0x80 | 0x10);
        let mut m = Mode::default();
        m.parse(b"=i").unwrap();
        assert_eq!(m.apply(0x80), 0x10);
        assert_eq!(m.parse(b"+A").unwrap_err(), "= is incompatible with - and +");
        let mut m = Mode::default();
        assert!(m.parse(b"+q").unwrap_err().starts_with("Usage: chattr"));
        assert!(m.parse(b"+a").unwrap_err().contains("not supported on SlateOS"));
        let mut m = Mode::default();
        m.parse(b"-A").unwrap();
        assert_eq!(m.parse(b"+A").unwrap_err(), "Can't both set and unset same flag.");
        // `-i` before the files is a flag; `-R`, `-Vf` are options.
        assert!(!is_option(b"-i"));
        assert!(is_option(b"-R"));
        assert!(is_option(b"-Vf"));
    }
}
