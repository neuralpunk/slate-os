// SPDX-License-Identifier: MIT OR Apache-2.0

//! overlayfs (ADR 0028): a union of read-only lower directories and an
//! optional writable upper directory, with the on-disk conventions that
//! container tools use for it.
//!
//! - The top layer that has a name decides what it is. A directory merges
//!   with the directories of the same name below it, down to the first
//!   non-directory or opaque directory.
//! - A whiteout (a character device 0/0 in a layer) hides the name below.
//!   A directory whose `trusted.overlay.opaque` attribute is "y" hides
//!   everything below it (`user.overlay.opaque` with the `userxattr`
//!   option, for user namespaces).
//! - Changing anything copies the file, and the directories above it, up
//!   into the upper layer first. Removing a name that a lower layer has
//!   leaves a whiteout.
//! - Renaming a merged directory fails with EXDEV, as Linux does without
//!   `redirect_dir`, so tools fall back to copying.
//!
//! Copy-up is not atomic (no work directory dance) and breaks hard links
//! between lower files; both are in docs/GAPS.md.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use super::vfs::*;
use crate::abi::linux::errno::*;
use crate::sched::wait::Mutex;
use crate::sync::IrqSpinLock;

/// OVERLAYFS_SUPER_MAGIC (statfs(2)).
const OVERLAY_MAGIC: i64 = 0x794c_7630;
/// Most lower layers a mount may have.
const MAX_LAYERS: usize = 500;

struct OvlFs {
    dev: u64,
    /// The upper layer's root; `None` for a read-only overlay.
    upper: Option<Arc<Dentry>>,
    /// Serializes changes (copy-up, whiteouts), which may sleep.
    lock: Mutex<()>,
    /// "trusted.overlay." or, with `userxattr`, "user.overlay.".
    prefix: &'static str,
}

impl OvlFs {
    fn is_opaque(&self, i: &dyn Inode) -> bool {
        i.get_xattr(&alloc::format!("{}opaque", self.prefix)).is_ok_and(|v| v == b"y")
    }

    fn set_opaque(&self, i: &dyn Inode) -> Result<()> {
        i.set_xattr(&alloc::format!("{}opaque", self.prefix), b"y", 0)
    }

    /// Attributes that belong to the overlay itself, hidden from users.
    fn private_xattr(&self, name: &str) -> bool {
        name.starts_with("trusted.overlay.") || name.starts_with("user.overlay.")
    }
}

fn is_whiteout(m: &Metadata) -> bool {
    m.file_type() == FileType::CharDevice && m.rdev == 0
}

pub struct OvlInode {
    fs: Arc<OvlFs>,
    me: Weak<OvlInode>,
    parent: Option<Arc<OvlInode>>,
    name: String,
    /// The upper layer's dentry, once there is one (copy-up sets it).
    upper: IrqSpinLock<Option<Arc<Dentry>>>,
    /// The lower layers' inodes for this name, top first, with the
    /// layer's index (for inode numbers).
    lowers: Vec<(usize, Arc<dyn Inode>)>,
}

/// Mount options: `lowerdir=a:b` (top first), `upperdir=`, `workdir=`
/// (required with an upper layer), `userxattr`; the rest are accepted.
/// `resolve` looks the directories up.
pub fn mount(options: &str, resolve: impl Fn(&str) -> Result<Arc<Dentry>>) -> Result<Arc<dyn Inode>> {
    let (mut lower, mut upper, mut work, mut userxattr) = (None, None, None, false);
    for o in options.split(',').filter(|o| !o.is_empty()) {
        match o.split_once('=') {
            Some(("lowerdir", v)) => lower = Some(v),
            Some(("upperdir", v)) => upper = Some(v),
            Some(("workdir", v)) => work = Some(v),
            None if o == "userxattr" => userxattr = true,
            _ => {} // index=, metacopy=, redirect_dir=, volatile, ...
        }
    }
    let dir = |p: &str| -> Result<Arc<Dentry>> {
        let d = resolve(p)?;
        if d.is_dir() { Ok(d) } else { Err(ENOTDIR) }
    };
    let lowers: Vec<Arc<Dentry>> =
        lower.ok_or(EINVAL)?.split(':').filter(|p| !p.is_empty()).map(dir).collect::<Result<_>>()?;
    if lowers.is_empty() || lowers.len() > MAX_LAYERS {
        return Err(EINVAL);
    }
    let upper = match upper {
        Some(u) => {
            // Like Linux's overlay, keep a "work" directory in workdir
            // (tools such as docker expect it there).
            let w = dir(work.ok_or(EINVAL)?)?;
            if w.child("work").is_err() {
                w.inode.mkdir("work", 0)?;
            }
            Some(dir(u)?)
        }
        None => None,
    };
    let fs = Arc::new(OvlFs {
        dev: super::tmpfs::anon_dev(),
        upper: upper.clone(),
        lock: Mutex::new(()),
        prefix: if userxattr { "user.overlay." } else { "trusted.overlay." },
    });
    let lowers = lowers.into_iter().enumerate().map(|(i, d)| (i + 1, d.inode.clone())).collect();
    Ok(Arc::new_cyclic(|me| OvlInode {
        fs,
        me: me.clone(),
        parent: None,
        name: String::new(),
        upper: IrqSpinLock::new(upper),
        lowers,
    }))
}

impl OvlInode {
    fn this(&self) -> Arc<OvlInode> {
        self.me.upgrade().expect("overlay inode in use")
    }

    fn upper(&self) -> Option<Arc<Dentry>> {
        self.upper.lock().clone()
    }

    /// The inode that holds the data and attributes: upper, else top lower.
    fn real(&self) -> Arc<dyn Inode> {
        match self.upper() {
            Some(u) => u.inode.clone(),
            None => self.lowers[0].1.clone(),
        }
    }

    fn downcast(i: &Arc<dyn Inode>) -> Option<&OvlInode> {
        i.as_any().downcast_ref::<OvlInode>()
    }

    /// Copy this file (and its parents) into the upper layer; returns its
    /// upper dentry.
    fn copy_up(&self) -> Result<Arc<Dentry>> {
        if let Some(u) = self.upper() {
            return Ok(u);
        }
        let _g = self.fs.lock.lock();
        self.copy_up_locked()
    }

    fn copy_up_locked(&self) -> Result<Arc<Dentry>> {
        if let Some(u) = self.upper() {
            return Ok(u);
        }
        self.fs.upper.as_ref().ok_or(EROFS)?;
        let parent = self.parent.as_ref().ok_or(EROFS)?;
        let pdir = parent.copy_up_locked()?;
        let src = self.lowers[0].1.clone();
        let m = src.metadata();
        let perm = m.mode & 0o7777;
        match m.file_type() {
            FileType::Directory => {
                pdir.inode.mkdir(&self.name, perm)?;
            }
            FileType::Symlink => {
                pdir.inode.symlink(&self.name, &src.readlink()?)?;
            }
            FileType::Regular => {
                let dst = pdir.inode.create(&self.name, S_IFREG | perm, 0)?;
                let mut buf = alloc::vec![0u8; 64 * 1024];
                let mut off = 0u64;
                loop {
                    let n = src.read_at(off, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    let mut done = 0;
                    while done < n {
                        done += dst.write_at(off + done as u64, &buf[done..n])?;
                    }
                    off += n as u64;
                }
            }
            _ => {
                pdir.inode.create(&self.name, m.mode, m.rdev)?;
            }
        }
        let new = pdir.child(&self.name)?;
        // Owner first: changing it may clear set-ID bits.
        let _ = new.inode.set_owner(Some(m.uid), Some(m.gid));
        if m.file_type() != FileType::Symlink {
            let _ = new.inode.set_mode(perm);
        }
        for name in src.list_xattr().unwrap_or_default() {
            if !self.fs.private_xattr(&name)
                && let Ok(v) = src.get_xattr(&name)
            {
                let _ = new.inode.set_xattr(&name, &v, 0);
            }
        }
        let _ = new.inode.set_times(Some(m.atime), Some(m.mtime));
        *self.upper.lock() = Some(new.clone());
        Ok(new)
    }

    /// Whether a lower layer of this directory has `name`.
    fn lower_has(&self, name: &str) -> bool {
        self.lowers.iter().any(|(_, l)| l.lookup(name).is_ok_and(|c| !is_whiteout(&c.metadata())))
    }

    /// Drop a whiteout called `name` in upper directory `d`, if there is
    /// one; returns whether there was.
    fn clear_whiteout(d: &Arc<Dentry>, name: &str) -> Result<bool> {
        match d.child(name) {
            Ok(c) if is_whiteout(&c.metadata()) => {
                d.inode.unlink(name)?;
                d.forget(name);
                Ok(true)
            }
            Ok(_) => Err(EEXIST),
            Err(e) if e == ENOENT => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn whiteout(d: &Arc<Dentry>, name: &str) -> Result<()> {
        d.inode.create(name, S_IFCHR, 0)?;
        Ok(())
    }

    /// Create `name` in this directory with `make`, over a whiteout if there
    /// is one. New directories that would merge with a lower one are made
    /// opaque.
    fn create_with(
        &self,
        name: &str,
        dir: bool,
        make: impl FnOnce(&Arc<Dentry>) -> Result<()>,
    ) -> Result<Arc<dyn Inode>> {
        {
            let _g = self.fs.lock.lock();
            let d = self.copy_up_locked()?;
            let had_whiteout = Self::clear_whiteout(&d, name)?;
            make(&d)?;
            if dir && (had_whiteout || self.lower_has(name)) {
                let c = d.child(name)?;
                self.fs.set_opaque(&*c.inode)?;
            }
        }
        self.lookup(name)
    }

    /// The merged entries of this directory.
    fn entries(&self) -> Result<BTreeMap<String, Option<DirEntry>>> {
        let mut seen: BTreeMap<String, Option<DirEntry>> = BTreeMap::new();
        let layer = |dir: &Arc<dyn Inode>, idx: usize, seen: &mut BTreeMap<String, Option<DirEntry>>| -> Result<()> {
            for e in dir.readdir()? {
                if e.name == "." || e.name == ".." || seen.contains_key(&e.name) {
                    continue;
                }
                let white =
                    e.kind == FileType::CharDevice && dir.lookup(&e.name).is_ok_and(|c| is_whiteout(&c.metadata()));
                let ino = e.ino ^ ((idx as u64) << 56);
                seen.insert(e.name.clone(), (!white).then_some(DirEntry { ino, ..e }));
            }
            Ok(())
        };
        if let Some(u) = self.upper() {
            layer(&u.inode, 0, &mut seen)?;
        }
        for (i, l) in &self.lowers {
            layer(l, *i, &mut seen)?;
        }
        Ok(seen)
    }
}

/// A stable, increasing-by-name directory position (getdents offsets).
fn name_pos(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    (h >> 2) | 1
}

impl Inode for OvlInode {
    fn metadata(&self) -> Metadata {
        let mut m = self.real().metadata();
        m.dev = self.fs.dev;
        // Keep the lower inode number across copy-up, apart per layer.
        if let Some((i, l)) = self.lowers.first() {
            m.ino = l.metadata().ino ^ ((*i as u64) << 56);
        }
        m
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn Inode>> {
        let mut upper_child = None;
        let mut is_dir = None;
        let mut search_lower = true;
        if let Some(u) = self.upper() {
            match u.child(name) {
                Ok(c) => {
                    let m = c.metadata();
                    if is_whiteout(&m) {
                        return Err(ENOENT);
                    }
                    let dir = m.file_type() == FileType::Directory;
                    search_lower = dir && !self.fs.is_opaque(&*c.inode);
                    is_dir = Some(dir);
                    upper_child = Some(c);
                }
                Err(e) if e == ENOENT => {}
                Err(e) => return Err(e),
            }
        }
        let mut lowers = Vec::new();
        if search_lower {
            for (i, l) in &self.lowers {
                let c = match l.lookup(name) {
                    Ok(c) => c,
                    Err(e) if e == ENOENT => continue,
                    Err(e) => return Err(e),
                };
                let m = c.metadata();
                if is_whiteout(&m) {
                    break;
                }
                let dir = m.file_type() == FileType::Directory;
                match is_dir {
                    None => is_dir = Some(dir),
                    Some(true) if dir => {}
                    // A non-directory under a directory (or anything under a
                    // non-directory) is hidden.
                    _ => break,
                }
                let opaque = dir && self.fs.is_opaque(&*c);
                lowers.push((*i, c));
                if !dir || opaque {
                    break;
                }
            }
        }
        if upper_child.is_none() && lowers.is_empty() {
            return Err(ENOENT);
        }
        Ok(Arc::new_cyclic(|me| OvlInode {
            fs: self.fs.clone(),
            me: me.clone(),
            parent: Some(self.this()),
            name: String::from(name),
            upper: IrqSpinLock::new(upper_child),
            lowers,
        }))
    }

    fn readdir(&self) -> Result<Vec<DirEntry>> {
        let mut out: Vec<DirEntry> =
            self.entries()?.into_values().flatten().map(|e| DirEntry { pos: name_pos(&e.name), ..e }).collect();
        out.sort_by_key(|e| e.pos);
        Ok(out)
    }

    fn create(&self, name: &str, mode: u32, rdev: u64) -> Result<Arc<dyn Inode>> {
        self.create_with(name, false, |d| d.inode.create(name, mode, rdev).map(|_| ()))
    }

    fn mkdir(&self, name: &str, mode: u32) -> Result<Arc<dyn Inode>> {
        self.create_with(name, true, |d| d.inode.mkdir(name, mode).map(|_| ()))
    }

    fn symlink(&self, name: &str, target: &str) -> Result<Arc<dyn Inode>> {
        self.create_with(name, false, |d| d.inode.symlink(name, target).map(|_| ()))
    }

    fn link(&self, name: &str, target: &Arc<dyn Inode>) -> Result<()> {
        let t = Self::downcast(target).ok_or(EXDEV)?;
        let tu = t.copy_up()?;
        self.create_with(name, false, |d| d.inode.link(name, &tu.inode)).map(|_| ())
    }

    fn unlink(&self, name: &str) -> Result<()> {
        let child = self.lookup(name)?;
        let c = Self::downcast(&child).ok_or(EIO)?;
        let _g = self.fs.lock.lock();
        let d = self.copy_up_locked()?;
        if c.upper().is_some() {
            d.inode.unlink(name)?;
            d.forget(name);
        }
        // A copied-up file still hides a lower one: whiteout.
        if self.lower_has(name) {
            Self::whiteout(&d, name)?;
        }
        Ok(())
    }

    fn rmdir(&self, name: &str) -> Result<()> {
        let child = self.lookup(name)?;
        let c = Self::downcast(&child).ok_or(EIO)?;
        if child.metadata().file_type() != FileType::Directory {
            return Err(ENOTDIR);
        }
        if c.entries()?.values().any(|e| e.is_some()) {
            return Err(ENOTEMPTY);
        }
        let _g = self.fs.lock.lock();
        let d = self.copy_up_locked()?;
        if let Some(cu) = c.upper() {
            // Only whiteouts are left in it.
            for e in cu.inode.readdir()? {
                if e.name != "." && e.name != ".." {
                    cu.inode.unlink(&e.name)?;
                    cu.forget(&e.name);
                }
            }
            d.inode.rmdir(name)?;
            d.forget(name);
        }
        if self.lower_has(name) {
            Self::whiteout(&d, name)?;
        }
        Ok(())
    }

    fn rename(&self, name: &str, new_dir: &Arc<dyn Inode>, new_name: &str) -> Result<()> {
        let nd = Self::downcast(new_dir).ok_or(EXDEV)?;
        let child = self.lookup(name)?;
        let c = Self::downcast(&child).ok_or(EIO)?;
        let is_dir = child.metadata().file_type() == FileType::Directory;
        // Merged directories can't move without redirects.
        if is_dir && !c.lowers.is_empty() {
            return Err(EXDEV);
        }
        let target = nd.lookup(new_name).ok();
        if let Some(t) = &target
            && t.metadata().file_type() == FileType::Directory
            && Self::downcast(t).is_some_and(|t| !t.lowers.is_empty())
        {
            return Err(EXDEV);
        }
        c.copy_up()?;
        let _g = self.fs.lock.lock();
        let d = self.copy_up_locked()?;
        let n = nd.copy_up_locked()?;
        // A whiteout at the target goes first (a directory can't replace it).
        let had_whiteout = match n.child(new_name) {
            Ok(x) if is_whiteout(&x.metadata()) => {
                n.inode.unlink(new_name)?;
                n.forget(new_name);
                true
            }
            _ => false,
        };
        d.inode.rename(name, &n.inode, new_name)?;
        d.forget(name);
        n.forget(new_name);
        if is_dir && (had_whiteout || nd.lower_has(new_name)) {
            let moved = n.child(new_name)?;
            self.fs.set_opaque(&*moved.inode)?;
        }
        if self.lower_has(name) {
            Self::whiteout(&d, name)?;
        }
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.real().read_at(offset, buf)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<usize> {
        self.copy_up()?.inode.write_at(offset, buf)
    }

    fn truncate(&self, size: u64) -> Result<()> {
        self.copy_up()?.inode.truncate(size)
    }

    fn readlink(&self) -> Result<String> {
        self.real().readlink()
    }

    fn set_mode(&self, mode: u32) -> Result<()> {
        self.copy_up()?.inode.set_mode(mode)
    }

    fn set_owner(&self, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
        self.copy_up()?.inode.set_owner(uid, gid)
    }

    fn set_times(&self, atime: Option<Timespec>, mtime: Option<Timespec>) -> Result<()> {
        self.copy_up()?.inode.set_times(atime, mtime)
    }

    /// A read's access time goes to the upper copy only: reading never
    /// copies a file up.
    fn touch_atime(&self, atime: Timespec) -> Result<()> {
        self.upper().map_or(Ok(()), |u| u.inode.touch_atime(atime))
    }

    fn get_xattr(&self, name: &str) -> Result<Vec<u8>> {
        if self.fs.private_xattr(name) {
            return Err(ENODATA);
        }
        self.real().get_xattr(name)
    }

    fn set_xattr(&self, name: &str, value: &[u8], flags: u32) -> Result<()> {
        if self.fs.private_xattr(name) {
            return Err(EPERM);
        }
        self.copy_up()?.inode.set_xattr(name, value, flags)
    }

    fn remove_xattr(&self, name: &str) -> Result<()> {
        if self.fs.private_xattr(name) {
            return Err(ENODATA);
        }
        self.copy_up()?.inode.remove_xattr(name)
    }

    fn list_xattr(&self) -> Result<Vec<String>> {
        Ok(self.real().list_xattr()?.into_iter().filter(|n| !self.fs.private_xattr(n)).collect())
    }

    fn statfs(&self) -> Option<StatFs> {
        let base = match &self.fs.upper {
            Some(u) => u.inode.statfs(),
            None => self.lowers.first().and_then(|(_, l)| l.statfs()),
        };
        let mut s = base.unwrap_or(StatFs {
            magic: 0,
            block_size: 4096,
            blocks: 0,
            free_blocks: 0,
            files: 0,
            free_files: 0,
            read_only: false,
        });
        s.magic = OVERLAY_MAGIC;
        s.read_only |= self.fs.upper.is_none();
        Some(s)
    }

    fn sync(&self) -> Result<()> {
        self.real().sync()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
