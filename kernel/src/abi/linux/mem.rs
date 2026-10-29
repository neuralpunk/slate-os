// SPDX-License-Identifier: MIT OR Apache-2.0

//! mmap(2), munmap(2), mprotect(2), mremap(2), brk(2).
//!
//! Every call that removes or downgrades mappings ends with
//! `proc::finish_vm_change`, which shoots down stale TLB entries on the
//! process's other CPUs before freeing frames.

use alloc::sync::Arc;

use crate::mm::aspace::FileBacking;

use super::errno::{EACCES, EEXIST, EFAULT, EINVAL, ENODEV, ENOMEM, ESRCH};
use super::{Args, Result};
use crate::fs::{O_ACCMODE, O_WRONLY};
use crate::mm::aspace::{Error, Prot};
use crate::proc::{self, Process};

// mmap(2) and mremap(2) flags. Source: musl `sys/mman.h` (ADR 0009).
pub(crate) const MAP_SHARED: u64 = 0x01;
pub(crate) const MAP_PRIVATE: u64 = 0x02;
pub(crate) const MAP_FIXED: u64 = 0x10;
pub(crate) const MAP_ANONYMOUS: u64 = 0x20;
pub(crate) const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
const MAP_NORESERVE: u64 = 0x4000;
/// MAP_SHARED_VALIDATE: MAP_SHARED, with unknown flags refused.
const MAP_SHARED_VALIDATE: u64 = 0x03;
/// The flags mmap(2) knows (musl `sys/mman.h`): the types, FIXED,
/// ANONYMOUS, 32BIT, GROWSDOWN, DENYWRITE, EXECUTABLE, LOCKED, NORESERVE,
/// POPULATE, NONBLOCK, STACK, HUGETLB, SYNC, FIXED_NOREPLACE,
/// UNINITIALIZED, and the huge page size bits.
const MAP_KNOWN: u64 = 0x03
    | 0x10
    | 0x20
    | 0x40
    | 0x100
    | 0x800
    | 0x1000
    | 0x2000
    | 0x4000
    | 0x8000
    | 0x1_0000
    | 0x2_0000
    | 0x4_0000
    | 0x8_0000
    | 0x10_0000
    | 0x400_0000
    | 0xFC00_0000;
const MREMAP_MAYMOVE: u64 = 1;
const MREMAP_FIXED: u64 = 2;

fn errno(e: Error) -> super::Errno {
    match e {
        Error::NoMemory => ENOMEM,
        Error::Invalid => EINVAL,
        Error::Exists => EEXIST,
        Error::Access => EACCES,
    }
}

fn me() -> core::result::Result<Arc<Process>, super::Errno> {
    proc::current().ok_or(ESRCH)
}

/// PROT_WRITE | PROT_EXEC (mmap(2)): refused in the Slate domain.
fn check_wx(prot: u64) -> core::result::Result<(), super::Errno> {
    if prot & 6 == 6 && !crate::proc::domain::may_map_wx() { Err(super::errno::EACCES) } else { Ok(()) }
}

/// PROT_EXEC (mmap(2)) in the Slate domain (ADR 0093): never anonymous
/// memory; a file only from the system image, or with the JIT permission
/// (which maps a file executable beside a writable mapping of it).
fn check_exec(
    p: &Process,
    prot: u64,
    file: Option<&Arc<crate::fs::vfs::Dentry>>,
) -> core::result::Result<(), super::Errno> {
    if prot & 4 == 0 || crate::proc::domain::may_map_wx() {
        return Ok(());
    }
    match file {
        Some(d) if p.has_jit() || crate::fs::vfs::in_image(d) => Ok(()),
        _ => Err(EACCES),
    }
}

pub fn mmap(a: Args) -> Result {
    let [addr, len, prot, flags, fd, off] = a.0;
    check_wx(prot)?;
    if len == 0 || (flags & (MAP_SHARED | MAP_PRIVATE)) == 0 || off % 4096 != 0 {
        return Err(EINVAL);
    }
    if flags & MAP_SHARED_VALIDATE == MAP_SHARED_VALIDATE && flags & !MAP_KNOWN != 0 {
        return Err(super::errno::EOPNOTSUPP);
    }
    let p = me()?;
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let hint = if fixed { Some(addr) } else { None };
    let replace = flags & MAP_FIXED != 0;
    // RLIMIT_AS (a MAP_FIXED mapping over others may not grow the space:
    // it is not counted).
    if !replace && !p.may_grow(len.next_multiple_of(4096), false) {
        return Err(ENOMEM);
    }
    // The overcommit policy (ADR 0123): private writable memory is
    // committed.
    if flags & MAP_SHARED == 0 && prot & 2 != 0 && !crate::mm::commit::enough(len, flags & MAP_NORESERVE != 0) {
        return Err(ENOMEM);
    }
    let anonymous = flags & MAP_ANONYMOUS != 0;
    if anonymous {
        check_exec(&p, prot, None)?;
    }
    let linux_prot = prot;
    let prot = Prot::from_linux(prot);
    let r = if anonymous && flags & MAP_SHARED != 0 {
        // Shared anonymous memory is an unnamed tmpfs file (as
        // memfd_create(2) makes): processes sharing the mapping after fork
        // share its pages, also those neither had touched before.
        let inode: alloc::sync::Arc<dyn crate::fs::vfs::Inode> = crate::fs::tmpfs::TmpFs::memfd(0o600, 0);
        inode.truncate(len.next_multiple_of(4096))?;
        let backing = FileBacking { inode, offset: 0, name: Some("/dev/zero (deleted)".into()) };
        proc::with_settled_vm(&p, |a| a.map_file(hint, len, prot, replace, backing, true)).ok_or(ESRCH)?.map_err(errno)
    } else if flags & MAP_ANONYMOUS != 0 {
        proc::with_settled_vm(&p, |a| a.map_with(hint, len, prot, replace, false)).ok_or(ESRCH)?.map_err(errno)
    } else {
        let file = p.files.lock().get(fd as i32)?;
        if file.status_flags() & O_ACCMODE == O_WRONLY {
            return Err(EACCES);
        }
        // Device memory (DRM dumb buffers, dma-bufs): the file's own pages,
        // shared mappings only.
        if let Some(src) = file.mmap_source(off) {
            let src = src?;
            check_exec(&p, linux_prot, None)?;
            if flags & MAP_SHARED == 0 {
                return Err(EINVAL);
            }
            let backing = FileBacking { inode: src, offset: off, name: None };
            let r = proc::with_settled_vm(&p, |a| a.map_file(hint, len, prot, replace, backing, true))
                .ok_or(ESRCH)?
                .map_err(errno);
            if replace {
                proc::finish_vm_change(&p);
            }
            return r;
        }
        let dentry = file.dentry().ok_or(ENODEV)?;
        if !matches!(dentry.metadata().file_type(), crate::fs::vfs::FileType::Regular) {
            return Err(ENODEV);
        }
        check_exec(&p, linux_prot, Some(&dentry))?;
        // A file on a noexec mount is never mapped executable (mmap(2)
        // EPERM), and its mapping never becomes so.
        let noexec = crate::fs::vfs::mount_flags(&dentry) & crate::fs::vfs::MNT_NOEXEC != 0;
        if noexec && prot.exec {
            return Err(super::errno::EPERM);
        }
        // Mapping a file reads it: its access time (ADR 0162).
        if file.status_flags() & crate::fs::O_NOATIME == 0 {
            crate::fs::vfs::accessed(&dentry);
        }
        // Shared mappings map the file's own pages where the file system
        // has them (tmpfs, and the page cache of disk files), else
        // read-only ones map pages read in for them (fs/pagecache.rs).
        // Writable ones of other files need write-back (a GAP): mapping
        // them privately would silently lose writes.
        let shared = flags & MAP_SHARED != 0 && (dentry.inode.shared_mmap() || !prot.write);
        if flags & MAP_SHARED != 0 && prot.write {
            if !shared {
                return Err(ENODEV);
            }
            if file.status_flags() & O_ACCMODE != crate::fs::O_RDWR {
                return Err(EACCES);
            }
        }
        let writable_shared = shared && prot.write;
        let backing = FileBacking {
            inode: dentry.inode.clone(),
            offset: off,
            name: Some(crate::fs::vfs::path_seen(&dentry, &p.root_dir()).into()),
        };
        // The seal is checked under the address space's lock, where the
        // mapping appears: F_ADD_SEALS seals, then looks for writable
        // shared mappings under each lock, so one of the two sees the other.
        proc::with_settled_vm(&p, |a| {
            if writable_shared && crate::fs::tmpfs::write_sealed(&backing.inode) {
                return Err(super::errno::EPERM);
            }
            a.map_file_with(hint, len, prot, replace, backing, shared, noexec).map_err(errno)
        })
        .ok_or(ESRCH)?
    };
    if replace {
        proc::finish_vm_change(&p);
    }
    r
}

// madvise(2) advice values. Source: musl `sys/mman.h`.
const MADV_DONTNEED: u64 = 4;
const MADV_FREE: u64 = 8;
const MADV_REMOVE: u64 = 9;
/// The last advice value madvise(2) documents (MADV_POPULATE_WRITE).
const MADV_LAST: u64 = 23;

/// mlock(2), mlock2(2), munlock(2): Slate has no swap, so every page is
/// in memory already; the range only has to make sense (ADR 0114: gpg
/// locks its secure memory). mlock2's only flag is MLOCK_ONFAULT.
pub fn mlock(a: Args, flags: Option<u64>) -> Result {
    if flags.is_some_and(|f| f & !1 != 0) {
        return Err(EINVAL);
    }
    a.0[0].checked_add(a.0[1]).ok_or(EINVAL)?;
    Ok(0)
}

/// mlockall(2): MCL_CURRENT, MCL_FUTURE, and MCL_ONFAULT with either;
/// as for mlock, nothing to do. munlockall(2) likewise.
pub fn mlockall(a: Args) -> Result {
    let f = a.0[0];
    if f == 0 || f & !7 != 0 || f == 4 {
        return Err(EINVAL);
    }
    Ok(0)
}

/// madvise(2): MADV_DONTNEED (and MADV_FREE, which may behave the same)
/// drop private pages; the other advice is a hint and changes nothing.
pub fn madvise(a: Args) -> Result {
    let [addr, len, advice, ..] = a.0;
    if addr % crate::mm::PAGE_SIZE != 0 || advice > MADV_LAST || advice == MADV_REMOVE {
        return Err(EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    if advice == MADV_DONTNEED || advice == MADV_FREE {
        let p = me()?;
        p.aspace.lock().as_mut().ok_or(ESRCH)?.discard(addr, len).map_err(errno)?;
        proc::finish_vm_change(&p);
    }
    Ok(0)
}

/// mincore(2): which pages of `[addr, addr + len)` are in memory, one
/// byte each. Every mapped page is reported resident (Slate does not
/// swap; pages not yet touched would be read in on access). ENOMEM if part
/// of the range is not mapped.
pub fn mincore(a: Args) -> Result {
    let [addr, len, vec, ..] = a.0;
    let page = crate::mm::PAGE_SIZE;
    if addr % page != 0 {
        return Err(EINVAL);
    }
    let pages = len.div_ceil(page) as usize;
    let end = addr.checked_add(pages as u64 * page).ok_or(ENOMEM)?;
    let p = me()?;
    {
        // Mapping by mapping, not page by page: the lock is held briefly
        // however large the range.
        let g = p.aspace.lock();
        let space = g.as_ref().ok_or(ESRCH)?;
        let mut at = addr;
        while at < end {
            at = space.find(at).ok_or(ENOMEM)?.end;
        }
    }
    // Not under the address space's lock: the copy may fault.
    for chunk in (0..pages).step_by(4096) {
        let n = (pages - chunk).min(4096);
        crate::arch::uaccess::copy_to_user(vec + chunk as u64, &alloc::vec![1u8; n]).map_err(|_| EFAULT)?;
    }
    Ok(0)
}

// msync(2) flags. Source: musl `sys/mman.h`.
const MS_ASYNC: u64 = 1;
const MS_INVALIDATE: u64 = 2;
const MS_SYNC: u64 = 4;

/// msync(2): MS_SYNC makes the files of the shared mappings in the range
/// durable (whole files). Writes through mappings are noticed when they
/// happen, so MS_ASYNC (the flusher writes them back) and MS_INVALIDATE
/// (the mappings are the cache) have nothing to do.
pub fn msync(a: Args) -> Result {
    let [addr, len, flags, ..] = a.0;
    if addr % crate::mm::PAGE_SIZE != 0
        || flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
    {
        return Err(EINVAL);
    }
    let files = {
        let p = me()?;
        let g = p.aspace.lock();
        g.as_ref().ok_or(ESRCH)?.shared_files(addr, len).map_err(|_| ENOMEM)?
    };
    if flags & MS_SYNC != 0 {
        for f in files {
            f.sync()?;
        }
    }
    Ok(0)
}

pub fn munmap(a: Args) -> Result {
    let p = me()?;
    p.aspace.lock().as_mut().ok_or(ESRCH)?.unmap(a.0[0], a.0[1]).map_err(errno)?;
    proc::finish_vm_change(&p);
    Ok(0)
}

pub fn mprotect(a: Args) -> Result {
    check_wx(a.0[2])?;
    let p = me()?;
    // A mapping that has been writable, or was not mapped executable,
    // stays unexecutable in the Slate domain (ADR 0093).
    let strict = !crate::proc::domain::may_map_wx();
    // Private memory made writable is committed (ADR 0123); counted with
    // no address space locked, as the policy reads them all.
    if a.0[2] & 2 != 0 {
        let more = p.aspace.lock().as_ref().map_or(0, |s| s.uncharged_in(a.0[0], a.0[1]));
        if more > 0 && !crate::mm::commit::enough(more, false) {
            return Err(ENOMEM);
        }
    }
    p.aspace.lock().as_mut().ok_or(ESRCH)?.protect(a.0[0], a.0[1], Prot::from_linux(a.0[2]), strict).map_err(errno)?;
    proc::finish_vm_change(&p);
    Ok(0)
}

pub fn mremap(a: Args) -> Result {
    let [old, old_len, new_len, flags, ..] = a.0;
    if flags & MREMAP_FIXED != 0 {
        return Err(EINVAL); // Not supported yet.
    }
    let p = me()?;
    if new_len > old_len
        && (!p.may_grow(new_len - old_len, false) || !crate::mm::commit::enough(new_len - old_len, false))
    {
        return Err(ENOMEM);
    }
    let r = proc::with_settled_vm(&p, |a| a.remap(old, old_len, new_len, flags & MREMAP_MAYMOVE != 0)).ok_or(ESRCH)?;
    proc::finish_vm_change(&p);
    r.map_err(errno)
}

/// brk(2) returns the (possibly unchanged) break, never an error; growing
/// it past RLIMIT_DATA or RLIMIT_AS leaves it where it is.
pub fn brk(a: Args) -> Result {
    let p = me()?;
    let old = p.aspace.lock().as_ref().map_or(0, |a| a.brk);
    if a.0[0] > old && (!p.may_grow(a.0[0] - old, true) || !crate::mm::commit::enough(a.0[0] - old, false)) {
        return Ok(old);
    }
    let r = proc::with_settled_vm(&p, |a2| a2.set_brk(a.0[0])).ok_or(ESRCH)?;
    proc::finish_vm_change(&p);
    Ok(r)
}
