// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unpacking the initramfs (a cpio newc archive) into the root tmpfs.

use alloc::sync::Arc;

use super::vfs::{self, Dentry, S_IFDIR, S_IFLNK, S_IFMT, makedev};
use crate::abi::linux::errno::{EEXIST, Errno};
use crate::log_warn;

/// Create `path`'s parent directories as needed and return the parent and
/// final name.
fn parent_of(root: &Arc<Dentry>, path: &str) -> Result<(Arc<Dentry>, alloc::string::String), Errno> {
    let path = path.trim_start_matches("./").trim_start_matches('/');
    let mut d = root.clone();
    let mut parts: alloc::vec::Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let name = parts.pop().unwrap_or("");
    for p in parts {
        d = match d.child(p) {
            Ok(c) => c,
            Err(_) => {
                d.inode.mkdir(p, 0o755)?;
                d.child(p)?
            }
        };
    }
    Ok((d, alloc::string::String::from(name)))
}

/// Unpack `archive` under `root`. Returns the number of entries created.
pub fn unpack(root: &Arc<Dentry>, archive: &[u8]) -> usize {
    let mut n = 0;
    for e in slate_cpio::entries(archive) {
        let e = match e {
            Ok(e) => e,
            Err(err) => {
                log_warn!("initramfs: stopped at a bad entry: {err:?}");
                break;
            }
        };
        if e.name == "." || e.name.is_empty() {
            continue;
        }
        let r = (|| -> Result<(), Errno> {
            let (parent, name) = parent_of(root, e.name)?;
            let perm = e.mode & 0o7777;
            let inode = match e.mode & S_IFMT {
                S_IFDIR => match parent.inode.mkdir(&name, perm) {
                    Err(err) if err == EEXIST => parent.inode.lookup(&name)?,
                    r => r?,
                },
                S_IFLNK => parent.inode.symlink(&name, core::str::from_utf8(e.data).unwrap_or(""))?,
                vfs::S_IFREG => {
                    let f = parent.inode.create(&name, vfs::S_IFREG | perm, 0)?;
                    f.write_at(0, e.data)?;
                    f
                }
                kind => parent.inode.create(&name, kind | perm, makedev(e.rdev_major, e.rdev_minor))?,
            };
            let _ = inode.set_owner(Some(e.uid), Some(e.gid));
            Ok(())
        })();
        match r {
            Ok(()) => n += 1,
            Err(err) => log_warn!("initramfs: {}: {err:?}", e.name),
        }
    }
    n
}
