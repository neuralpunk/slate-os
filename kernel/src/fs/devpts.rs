// SPDX-License-Identifier: MIT OR Apache-2.0

//! devpts (pts(4)): /dev/pts/N for each pseudo-terminal in use, and
//! /dev/pts/ptmx.
//!
//! Instances (ADR 0183): a devpts mounted with `newinstance` is one of
//! its own. Its ptmx makes pseudo-terminals that belong to it, and it
//! lists only those, and the ones its mount named with `allow=N` (a Linux
//! box's session terminal). The system's instance (0) lists them all.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use super::tty::{PTMX_MAJOR, PTMX_MINOR, PTS_MAJOR, pty_attrs, pty_indices, pty_instance, set_pty_attrs};
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
    /// 0: the system's instance, which shows every pseudo-terminal.
    instance: u64,
    /// Pseudo-terminals of other instances this one shows too.
    allow: Arc<Vec<u32>>,
}

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

pub fn new() -> Arc<dyn Inode> {
    Arc::new(PtsInode { node: Node::Root, instance: 0, allow: Arc::new(Vec::new()) })
}

/// A devpts of its own (`newinstance`), showing also `allow`'s.
pub fn new_instance(allow: Vec<u32>) -> Arc<dyn Inode> {
    let instance = NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed);
    Arc::new(PtsInode { node: Node::Root, instance, allow: Arc::new(allow) })
}

impl PtsInode {
    fn child(&self, node: Node) -> Arc<PtsInode> {
        Arc::new(PtsInode { node, instance: self.instance, allow: self.allow.clone() })
    }

    /// Whether this instance shows pseudo-terminal `n`.
    fn shows(&self, n: u32) -> bool {
        self.instance == 0 || self.allow.contains(&n) || pty_instance(n) == Some(self.instance)
    }
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
            return Ok(self.child(Node::Ptmx));
        }
        let n: u32 = name.parse().map_err(|_| ENOENT)?;
        if !pty_indices().contains(&n) || !self.shows(n) {
            return Err(ENOENT);
        }
        Ok(self.child(Node::Slave(n)))
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        if !matches!(self.node, Node::Root) {
            return Err(ENOTDIR);
        }
        let mut v = alloc::vec![DirEntry { name: "ptmx".into(), ino: 2, kind: FileType::CharDevice, pos: 0 }];
        for n in pty_indices().into_iter().filter(|&n| self.shows(n)) {
            let ino = u64::from(n) + 3;
            v.push(DirEntry { name: n.to_string(), ino, kind: FileType::CharDevice, pos: ino });
        }
        Ok(v)
    }

    fn open_special(self: Arc<Self>, flags: u32) -> Option<Result<Arc<dyn crate::fs::File>>> {
        match self.node {
            // An instance's own ptmx makes its own pseudo-terminals.
            Node::Ptmx if self.instance != 0 => Some(super::tty::open_master_in(flags, self.instance)),
            _ => None,
        }
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
