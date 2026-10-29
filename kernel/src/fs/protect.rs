// SPDX-License-Identifier: MIT OR Apache-2.0

//! The link and creation restrictions of /proc/sys/fs (proc(5)):
//! `protected_symlinks`, `protected_hardlinks`, `protected_fifos` and
//! `protected_regular`. They keep a program from being led, through a
//! shared sticky directory such as /tmp, to a file another user put
//! there. Slate's defaults are 1 for all four, as common distributions
//! set them (ADR 0121).

use core::sync::atomic::{AtomicU8, Ordering};

use crate::fs::vfs::{FileType, Metadata};
use crate::proc::cred::{CAP_FOWNER, Cred, MAY_READ, MAY_WRITE, S_ISGID, S_ISUID, S_ISVTX};

pub static SYMLINKS: AtomicU8 = AtomicU8::new(1);
pub static HARDLINKS: AtomicU8 = AtomicU8::new(1);
pub static FIFOS: AtomicU8 = AtomicU8::new(1);
pub static REGULAR: AtomicU8 = AtomicU8::new(1);

/// The setting a /proc/sys/fs file names, and its highest value.
pub fn setting(name: &str) -> Option<(&'static AtomicU8, u8)> {
    Some(match name {
        "protected_symlinks" => (&SYMLINKS, 1),
        "protected_hardlinks" => (&HARDLINKS, 1),
        "protected_fifos" => (&FIFOS, 2),
        "protected_regular" => (&REGULAR, 2),
        _ => return None,
    })
}

/// A sticky directory anyone may write to.
fn sticky_world_writable(dir: &Metadata) -> bool {
    dir.mode & S_ISVTX != 0 && dir.mode & 0o002 != 0
}

/// protected_symlinks: a symlink in a sticky world-writable directory is
/// followed only by its owner, or if the directory's owner owns it too.
/// Refused with EACCES.
pub fn may_follow(dir: &Metadata, link: &Metadata, cred: &Cred) -> bool {
    SYMLINKS.load(Ordering::Relaxed) == 0
        || !sticky_world_writable(dir)
        || link.uid == cred.fsuid
        || link.uid == dir.uid
}

/// protected_hardlinks: a hard link to a file is made only by its owner,
/// by someone with CAP_FOWNER over it, or to a regular file that is not
/// set-user-ID nor executable set-group-ID and that the caller may read
/// and write. Refused with EPERM.
pub fn may_link(target: &Metadata, cred: &Cred) -> bool {
    if HARDLINKS.load(Ordering::Relaxed) == 0 || target.uid == cred.fsuid || cred.capable_wrt(target, CAP_FOWNER) {
        return true;
    }
    let set_id = target.mode & S_ISUID != 0 || target.mode & (S_ISGID | 0o010) == S_ISGID | 0o010;
    target.file_type() == FileType::Regular && !set_id && cred.permission(target, MAY_READ | MAY_WRITE).is_ok()
}

/// protected_fifos and protected_regular: an open with O_CREAT of an
/// existing FIFO or regular file in a sticky directory anyone may write
/// to (with 2, one its group may write to too) is refused unless the
/// caller or the directory's owner owns the file. Refused with EACCES.
pub fn may_open_existing(dir: &Metadata, file: &Metadata, cred: &Cred) -> bool {
    let level = match file.file_type() {
        FileType::Fifo => FIFOS.load(Ordering::Relaxed),
        FileType::Regular => REGULAR.load(Ordering::Relaxed),
        _ => return true,
    };
    let shared = dir.mode & S_ISVTX != 0 && (dir.mode & 0o002 != 0 || (level >= 2 && dir.mode & 0o020 != 0));
    level == 0 || !shared || file.uid == cred.fsuid || file.uid == dir.uid
}
