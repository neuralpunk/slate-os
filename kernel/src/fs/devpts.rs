// SPDX-License-Identifier: MIT OR Apache-2.0

//! devpts (pts(4)): /dev/pts/N for each pseudo-terminal in use, and
//! /dev/pts/ptmx.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::tty::{PTMX_MAJOR, PTMX_MINOR, PTS_MAJOR, pty_attrs, pty_indices, set_pty_attrs};
use super::vfs::*;
use crate::abi::linux::errno::*;

const DEVPTS_DEV: u64 = 0xF1;

enum Node {
    Root,
    Ptmx,
    Slave(u32),
}

struct PtsInode {
    node: Node,
}

pub fn new() -> Arc<dyn Inode> {
    Arc::new(PtsInode { node: Node::Root })
}

impl Inode for PtsInode {
    fn metadata(&self) -> Metadata {
        let now = Timespec::now();
        let (ino, mode, rdev, uid, gid) = match self.node {
            Node::Root => (1, S_IFDIR | 0o755, 0, 0, 0),
            Node::Ptmx => (2, S_IFCHR | 0o666, makedev(PTMX_MAJOR, PTMX_MINOR), 0, 0),
            Node::Slave(n) => {
                let (uid, gid, perm) = pty_attrs(n).unwrap_or((0, 0, 0o620));
                (u64::from(n) + 3, S_IFCHR | perm, makedev(PTS_MAJOR, n), uid, gid)
            }
        };
        Metadata {
            dev: DEVPTS_DEV,
            ino,
            mode,
            nlink: 1,
            rdev,
            uid,
            gid,
            // A slave's times are its terminal's: last read and written.
            atime: super::tty::times_of(rdev).map_or(now, |t| t.0),
            mtime: super::tty::times_of(rdev).map_or(now, |t| t.1),
            ctime: now,
            ..Default::default()
        }
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        if name == "ptmx" {
            return Ok(Arc::new(PtsInode { node: Node::Ptmx }));
        }
        let n: u32 = name.parse().map_err(|_| ENOENT)?;
        if !pty_indices().contains(&n) {
            return Err(ENOENT);
        }
        Ok(Arc::new(PtsInode { node: Node::Slave(n) }))
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        let mut v = alloc::vec![DirEntry { name: "ptmx".into(), ino: 2, kind: FileType::CharDevice, pos: 0 }];
        for n in pty_indices() {
            let ino = u64::from(n) + 3;
            v.push(DirEntry { name: n.to_string(), ino, kind: FileType::CharDevice, pos: ino });
        }
        Ok(v)
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        match self.node {
            Node::Slave(n) => set_pty_attrs(n, uid, gid, None).ok_or(EIO),
            _ => Err(EPERM),
        }
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        match self.node {
            Node::Slave(n) => set_pty_attrs(n, None, None, Some(mode)).ok_or(EIO),
            _ => Err(EPERM),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
