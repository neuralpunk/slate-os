// SPDX-License-Identifier: MIT OR Apache-2.0

//! User address spaces: page tables plus the list of mapped regions (VMAs).
//!
//! Anonymous memory is mapped lazily: a VMA only reserves the range, and
//! the page-fault handler fills pages with zeroed frames on first touch.
//! fork(2) shares every page: private writable pages become read-only in
//! both address spaces and are copied on the first write (copy-on-write);
//! frames carry reference counts (`frame::get_user_page`/`put_user_page`).

use alloc::collections::BTreeMap;

use super::{PAGE_SIZE, PhysAddr, frame};
use crate::arch::paging::{CacheMode, MapFlags, Mapper, PageSize};
use crate::arch::uaccess::USER_END;

/// Access rights of a region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    pub const RW: Prot = Prot { read: true, write: true, exec: false };

    /// From Linux `PROT_*` bits (mmap(2)): READ = 1, WRITE = 2, EXEC = 4.
    pub fn from_linux(p: u64) -> Prot {
        Prot { read: p & 1 != 0, write: p & 2 != 0, exec: p & 4 != 0 }
    }

    fn flags(self) -> MapFlags {
        MapFlags { write: self.write, exec: self.exec, user: true, global: false, cache: CacheMode::WriteBack }
    }
}

/// A mapped region `[start, end)`.
#[derive(Clone, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    /// `MAP_SHARED`: pages stay shared (and writable) across fork.
    pub shared: bool,
    /// File backing: pages are read from the file on first touch (private
    /// mappings get private copies; shared ones of files that support it
    /// map the file's own pages).
    pub file: Option<FileBacking>,
    /// It has been writable (ADR 0093: then it never becomes executable
    /// in the Slate domain).
    pub wrote: bool,
    /// It was made executable when it was mapped, so it may be again.
    pub exec_ok: bool,
    /// Its file is on a noexec mount: it never becomes executable
    /// (mprotect(2) EACCES).
    pub noexec: bool,
}

impl Vma {
    /// Whether writes through this mapping must be noticed: a shared
    /// mapping of a page-cache file, whose pages stay read-only until a
    /// write fault marks them dirty ([`crate::fs::vfs::Inode::mmap_written`]).
    fn tracks_writes(&self) -> bool {
        self.shared && self.file.as_ref().is_some_and(|f| f.inode.mmap_writeback())
    }

    /// Whether it counts as committed memory (mm::commit): private and
    /// writable, or written once.
    fn charged(&self) -> bool {
        !self.shared && (self.prot.write || self.wrote)
    }

    /// The file and offset backing `page`, for file mappings.
    fn page_backing(&self, page: u64) -> Option<FileBacking> {
        let f = self.file.as_ref()?;
        Some(FileBacking { inode: f.inode.clone(), offset: f.offset + (page - self.start), name: None })
    }
}

#[derive(Clone)]
pub struct FileBacking {
    pub inode: alloc::sync::Arc<dyn crate::fs::vfs::Inode>,
    /// File offset of the VMA's first page.
    pub offset: u64,
    /// The file's path when it was mapped, for /proc/<pid>/maps.
    pub name: Option<alloc::sync::Arc<str>>,
}

impl FileBacking {
    /// A fresh frame holding the file's page at `offset` (zeros past the
    /// end of the file). May sleep: call with no spinlock held.
    /// The file's own page at `offset` (a reference for the mapping), for
    /// shared mappings. May sleep: call with no spinlock held.
    pub fn shared_page(&self) -> Option<PhysAddr> {
        if self.inode.shared_mmap() {
            self.inode.shared_page(self.offset).ok()
        } else {
            crate::fs::pagecache::mapped_page(&self.inode, self.offset).ok()
        }
    }

    pub fn read_page(&self) -> Option<PhysAddr> {
        let f = frame::alloc_user_page()?;
        // SAFETY: `f` is a fresh frame in the direct map.
        let buf = unsafe { core::slice::from_raw_parts_mut(f.to_virt(), PAGE_SIZE as usize) };
        let mut done = 0;
        while done < buf.len() {
            match self.inode.read_at(self.offset + done as u64, &mut buf[done..]) {
                Ok(0) | Err(_) => break, // Past the end: the rest stays zero.
                Ok(n) => done += n,
            }
        }
        Some(f)
    }
}

impl core::fmt::Debug for FileBacking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileBacking").field("offset", &self.offset).finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoMemory,
    Invalid,
    Exists,
    /// Writing a shared mapping of a file that can't take it.
    Access,
}

/// Lowest address handed out to user mappings (the first 64 KiB stay
/// unmapped to catch NULL dereferences, like Linux's `mmap_min_addr`).
pub const USER_MIN: u64 = 0x1_0000;
/// Top of the main stack (without randomization; see `proc::aslr`).
pub const STACK_TOP: u64 = 0x7FFF_FFFF_F000;
/// The default main stack size (`RLIMIT_STACK`, 8 MiB).
pub const STACK_MAX: u64 = 8 << 20;
/// The main stack reserved for an RLIMIT_STACK of `limit`: at least 128
/// KiB, at most 1 GiB (also for an unlimited stack).
pub fn stack_size(limit: u64) -> u64 {
    page_ceil(limit.clamp(128 << 10, 1 << 30))
}
/// Mappings without an address are placed top-down below this (without
/// randomization; see `proc::aslr`).
pub const MMAP_TOP: u64 = 0x7F00_0000_0000;

#[derive(Debug)]
pub struct AddressSpace {
    mapper: Mapper,
    vmas: BTreeMap<u64, Vma>,
    pub brk_start: u64,
    pub brk: u64,
    /// Where mappings without an address go, top-down from here, and the
    /// top of the main stack: chosen at exec (`proc::aslr`).
    pub mmap_top: u64,
    pub stack_top: u64,
    /// Frames unmapped but not yet freed, each with the removal (see
    /// `removals`) that unmapped it: other CPUs may still hold stale
    /// translations until a shootdown begun after that removal completes.
    pending_free: alloc::vec::Vec<(u64, PhysAddr)>,
    /// Changes that removed translations, and how many of them a completed
    /// shootdown covers. While they differ, freed addresses must not be
    /// reused: another CPU may still translate them the old way.
    pub removals: u64,
    pub flushed: u64,
}

/// How a copy-on-write split went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cow {
    Done,
    Failed,
    NoMemory,
}

/// What a page fault handler did.
#[derive(Debug)]
pub enum Fault {
    /// Not a fault we can fix: deliver a signal.
    Bad,
    /// Fixed; retry the access.
    Fixed,
    /// Fixed by replacing a frame (copy-on-write): other threads' CPUs need
    /// a shootdown before `take_pending_free` frames can be released.
    FixedReplaced,
    /// The page comes from a file. Reading it may sleep, so the caller
    /// reads it with no lock held ([`FileBacking::read_page`]) and then
    /// calls [`AddressSpace::install_file_page`].
    /// `shared`: map the file's own page ([`FileBacking::shared_page`]).
    NeedsFile { page: u64, file: FileBacking, shared: bool },
    /// A copy-on-write split must wait: pages were write-protected (fork)
    /// and another CPU may still write them through a stale writable
    /// translation, so a copy made now could miss those writes. The caller
    /// finishes the shootdown with no lock held and retries the access.
    NeedsFlush,
    /// No memory for the page, or the process's cgroup is at its
    /// memory.max: the caller runs the out-of-memory killer with no lock
    /// held and retries.
    NoMemory,
}

/// Make a frame's new contents (zeroed, copied or read in, often with
/// fast string instructions, whose stores other CPUs may see out of order)
/// visible everywhere before the page-table entry that maps it: another
/// CPU may walk to the entry the moment it is written and read the page.
fn publish_fence() {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

fn page_floor(a: u64) -> u64 {
    a & !(PAGE_SIZE - 1)
}

fn page_ceil(a: u64) -> u64 {
    a.div_ceil(PAGE_SIZE) * PAGE_SIZE
}

impl AddressSpace {
    pub fn new() -> Result<AddressSpace, Error> {
        Ok(AddressSpace {
            mapper: Mapper::new_user().ok_or(Error::NoMemory)?,
            vmas: BTreeMap::new(),
            brk_start: 0,
            brk: 0,
            mmap_top: MMAP_TOP,
            stack_top: STACK_TOP,
            pending_free: alloc::vec::Vec::new(),
            removals: 0,
            flushed: 0,
        })
    }

    pub fn root(&self) -> PhysAddr {
        self.mapper.root()
    }

    /// The VMA containing `addr`.
    pub fn find(&self, addr: u64) -> Option<&Vma> {
        self.vmas.range(..=addr).next_back().map(|(_, v)| v).filter(|v| addr < v.end)
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.vmas.range(..end).next_back().is_some_and(|(_, v)| v.end > start)
    }

    /// Find a free range of `len` bytes, searching down from `mmap_top`.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        let mut top = self.mmap_top;
        for (_, v) in self.vmas.range(..self.mmap_top).rev() {
            if v.end <= top && top - v.end >= len {
                return Some(top - len);
            }
            top = top.min(v.start);
        }
        (top >= USER_MIN + len).then(|| top - len)
    }

    /// Reserve `[addr, addr + len)` (or a free range when `addr` is `None`)
    /// with `prot`. With `replace`, existing mappings in the range are
    /// removed first (`MAP_FIXED`).
    pub fn map(&mut self, addr: Option<u64>, len: u64, prot: Prot, replace: bool) -> Result<u64, Error> {
        self.map_with(addr, len, prot, replace, false)
    }

    /// [`AddressSpace::map`] with an explicit shared flag.
    pub fn map_with(
        &mut self,
        addr: Option<u64>,
        len: u64,
        prot: Prot,
        replace: bool,
        shared: bool,
    ) -> Result<u64, Error> {
        let len = page_ceil(len);
        if len == 0 {
            return Err(Error::Invalid);
        }
        let start = match addr {
            Some(a) => {
                if a % PAGE_SIZE != 0 || a < USER_MIN || a.checked_add(len).is_none_or(|e| e > USER_END) {
                    return Err(Error::Invalid);
                }
                if self.overlaps(a, a + len) {
                    if !replace {
                        return Err(Error::Exists);
                    }
                    self.unmap(a, len)?;
                }
                a
            }
            None => self.find_free(len).ok_or(Error::NoMemory)?,
        };
        let (wrote, exec_ok) = (prot.write, prot.exec);
        self.vmas
            .insert(start, Vma { start, end: start + len, prot, shared, file: None, wrote, exec_ok, noexec: false });
        Ok(start)
    }

    /// Map `len` bytes of `file` (an inode from an offset) at `addr` (or
    /// anywhere): pages are read in on first touch, or with `shared` are
    /// the file's own pages.
    pub fn map_file(
        &mut self,
        addr: Option<u64>,
        len: u64,
        prot: Prot,
        replace: bool,
        file: FileBacking,
        shared: bool,
    ) -> Result<u64, Error> {
        self.map_file_with(addr, len, prot, replace, file, shared, false)
    }

    /// [`AddressSpace::map_file`] of a file on a noexec mount when
    /// `noexec` (the mapping never becomes executable).
    #[allow(clippy::too_many_arguments)]
    pub fn map_file_with(
        &mut self,
        addr: Option<u64>,
        len: u64,
        prot: Prot,
        replace: bool,
        file: FileBacking,
        shared: bool,
        noexec: bool,
    ) -> Result<u64, Error> {
        let start = self.map_with(addr, len, prot, replace, shared)?;
        if let Some(v) = self.vmas.get_mut(&start) {
            v.file = Some(file);
            v.noexec = noexec;
        }
        Ok(start)
    }

    /// mremap(2): resize the mapping at `old` (which must start a VMA),
    /// moving it if `may_move` and it cannot grow in place.
    pub fn remap(&mut self, old: u64, old_len: u64, new_len: u64, may_move: bool) -> Result<u64, Error> {
        let (old_len, new_len) = (page_ceil(old_len), page_ceil(new_len));
        if old % PAGE_SIZE != 0 || new_len == 0 {
            return Err(Error::Invalid);
        }
        let v = self.vmas.get(&old).cloned().ok_or(Error::Invalid)?;
        if v.end - v.start != old_len {
            return Err(Error::Invalid); // Only whole mappings, for now.
        }
        if new_len <= old_len {
            if new_len < old_len {
                self.unmap(old + new_len, old_len - new_len)?;
            }
            return Ok(old);
        }
        let grow_end = old + new_len;
        if grow_end <= USER_END && !self.overlaps(v.end, grow_end) {
            self.vmas.get_mut(&old).unwrap().end = grow_end;
            return Ok(old);
        }
        if !may_move {
            return Err(Error::NoMemory);
        }
        let new = self.find_free(new_len).ok_or(Error::NoMemory)?;
        self.removals += 1;
        for (page, _, _) in self.mapper.user_pages(v.start, v.end) {
            let flags = self.mapper.leaf_flags(page);
            if let Some((p, _)) = self.mapper.unmap(page) {
                let dest = new + (page - v.start);
                self.mapper
                    .map(dest, p, PageSize::Size4K, flags.unwrap_or(v.prot.flags()))
                    .map_err(|_| Error::NoMemory)?;
            }
        }
        self.vmas.remove(&old);
        self.vmas.insert(new, Vma { start: new, end: new + new_len, ..v });
        Ok(new)
    }

    /// Map the given frames, in order, at `addr` with `prot`, sharing them
    /// (each mapping takes a reference). Used for the vDSO.
    pub fn map_frames(&mut self, addr: u64, frames: &[PhysAddr], prot: Prot) -> Result<(), Error> {
        let start = self.map(Some(addr), frames.len() as u64 * PAGE_SIZE, prot, false)?;
        for (i, &f) in frames.iter().enumerate() {
            frame::get_user_page(f);
            if self.mapper.map(start + i as u64 * PAGE_SIZE, f, PageSize::Size4K, prot.flags()).is_err() {
                frame::put_user_page(f);
                return Err(Error::NoMemory);
            }
        }
        Ok(())
    }

    /// Reserve the main stack region, `size` bytes (pages appear on first
    /// touch).
    pub fn map_stack(&mut self, size: u64) -> Result<(), Error> {
        let (start, end) = (self.stack_top - size, self.stack_top);
        self.vmas.insert(
            start,
            Vma { start, end, prot: Prot::RW, shared: false, file: None, wrote: true, exec_ok: false, noexec: false },
        );
        Ok(())
    }

    /// Split any VMA that straddles `addr` so a VMA boundary falls there.
    fn split_at(&mut self, addr: u64) {
        let Some(v) = self.find(addr).cloned() else { return };
        if v.start == addr {
            return;
        }
        self.vmas.insert(v.start, Vma { end: addr, ..v.clone() });
        let file = v.file.clone().map(|f| FileBacking { offset: f.offset + (addr - v.start), ..f });
        self.vmas.insert(addr, Vma { start: addr, file, ..v });
    }

    /// Unmap `[addr, addr + len)`, freeing its pages.
    pub fn unmap(&mut self, addr: u64, len: u64) -> Result<(), Error> {
        let (start, end) = (addr, addr.checked_add(page_ceil(len)).ok_or(Error::Invalid)?);
        if start % PAGE_SIZE != 0 || end > USER_END {
            return Err(Error::Invalid);
        }
        self.split_at(start);
        self.split_at(end);
        let keys: alloc::vec::Vec<u64> = self.vmas.range(start..end).map(|(&k, _)| k).collect();
        if !keys.is_empty() {
            self.removals += 1;
        }
        for k in keys {
            let v = self.vmas.remove(&k).unwrap();
            for (page, _, _) in self.mapper.user_pages(v.start, v.end) {
                if let Some((p, _)) = self.mapper.unmap(page) {
                    self.pending_free.push((self.removals, p));
                }
            }
        }
        Ok(())
    }

    /// MADV_DONTNEED: drop the pages of `[addr, addr + len)`, which must be
    /// mapped. Private pages come back on the next touch as zeros (anonymous)
    /// or as the file's contents; shared pages are kept (their contents live
    /// only here). Freed frames wait for a shootdown in `pending_free`.
    pub fn discard(&mut self, addr: u64, len: u64) -> Result<(), Error> {
        let end = addr.checked_add(page_ceil(len)).ok_or(Error::Invalid)?;
        if addr % PAGE_SIZE != 0 || end > USER_END {
            return Err(Error::Invalid);
        }
        let mut a = addr;
        while a < end {
            a = self.find(a).ok_or(Error::NoMemory)?.end;
        }
        let ranges: alloc::vec::Vec<(u64, u64)> = self
            .vmas
            .range(..end)
            .map(|(_, v)| v)
            .filter(|v| v.end > addr && !v.shared)
            .map(|v| (v.start.max(addr), v.end.min(end)))
            .collect();
        let mut removed = false;
        let removal = self.removals + 1;
        for (s, e) in ranges {
            for (page, _, _) in self.mapper.user_pages(s, e) {
                if let Some((p, _)) = self.mapper.unmap(page) {
                    self.pending_free.push((removal, p));
                    removed = true;
                }
            }
        }
        if removed {
            self.removals = removal;
        }
        Ok(())
    }

    /// Change protection of `[addr, addr + len)`; every page must be mapped.
    /// With `strict_wx` (the Slate domain, ADR 0093), a mapping that has
    /// been writable, or was not executable when mapped, does not become
    /// executable.
    pub fn protect(&mut self, addr: u64, len: u64, prot: Prot, strict_wx: bool) -> Result<(), Error> {
        let end = addr.checked_add(page_ceil(len)).ok_or(Error::Invalid)?;
        if addr % PAGE_SIZE != 0 || end > USER_END {
            return Err(Error::Invalid);
        }
        let mut a = addr;
        while a < end {
            let v = self.find(a).ok_or(Error::NoMemory)?;
            // Shared mappings of page-cache files stay read-only (no
            // write-back yet).
            if prot.write && v.shared && v.file.as_ref().is_some_and(|f| !f.inode.shared_mmap()) {
                return Err(Error::Access);
            }
            // Nor become writable once the file is sealed against writes
            // (memfd_create(2)).
            if prot.write
                && !v.prot.write
                && v.shared
                && v.file.as_ref().is_some_and(|f| crate::fs::tmpfs::write_sealed(&f.inode))
            {
                return Err(Error::Access);
            }
            if (prot.exec && v.noexec) || (strict_wx && prot.exec && !v.prot.exec && (v.wrote || !v.exec_ok)) {
                return Err(Error::Access);
            }
            a = v.end;
        }
        self.split_at(addr);
        self.split_at(end);
        let keys: alloc::vec::Vec<u64> = self.vmas.range(addr..end).map(|(&k, _)| k).collect();
        for k in keys {
            let v = self.vmas.get_mut(&k).unwrap();
            v.prot = prot;
            v.wrote |= prot.write;
            let (shared, tracked) = (v.shared, v.tracks_writes());
            for (page, p, writable) in self.mapper.user_pages(v.start, v.end) {
                // Shared copy-on-write pages stay read-only until written;
                // so do clean pages of tracked shared mappings.
                let cow = !shared && frame::user_page_refs(p) > 1;
                let ro = cow || (tracked && !writable);
                self.mapper.protect(page, Prot { write: prot.write && !ro, ..prot }.flags());
            }
        }
        Ok(())
    }

    /// Move the program break (brk(2)); returns the new break.
    pub fn set_brk(&mut self, new: u64) -> u64 {
        if new < self.brk_start {
            return self.brk;
        }
        let (old_end, new_end) = (page_ceil(self.brk), page_ceil(new));
        if new_end > old_end {
            if self.overlaps(old_end, new_end) || self.map(Some(old_end), new_end - old_end, Prot::RW, false).is_err() {
                return self.brk;
            }
        } else if new_end < old_end && self.unmap(new_end, old_end - new_end).is_err() {
            return self.brk;
        }
        // Merge consecutive brk VMAs is unnecessary: lookups handle many.
        self.brk = new;
        self.brk
    }

    /// Handle a page fault at `addr`. Returns true if the access can be
    /// retried: a missing page was filled, or a copy-on-write page split.
    pub fn handle_fault(&mut self, addr: u64, write: bool, exec: bool) -> Fault {
        let page = page_floor(addr);
        let vma = match self.find(addr) {
            Some(v) => v.clone(),
            None => return Fault::Bad,
        };
        let allowed = (vma.prot.read || vma.prot.write || vma.prot.exec)
            && (!write || vma.prot.write)
            && (!exec || vma.prot.exec);
        if !allowed {
            return Fault::Bad;
        }
        match self.mapper.lookup(page) {
            None if vma.file.is_some() => {
                Fault::NeedsFile { page, file: vma.page_backing(page).unwrap(), shared: vma.shared }
            }
            None => {
                let Some(f) = self.fill_page(&vma, page) else { return Fault::NoMemory };
                publish_fence();
                if self.mapper.map(page, f, PageSize::Size4K, vma.prot.flags()).is_err() {
                    frame::put_user_page(f);
                    return Fault::NoMemory;
                }
                Fault::Fixed
            }
            // Shared pages are never copied: the mapping just gained write
            // access (mprotect), or the page cache wants to know the page
            // is being written.
            Some(_) if write && vma.shared => {
                if vma.tracks_writes()
                    && let Some(f) = vma.page_backing(page)
                {
                    f.inode.mmap_written(f.offset);
                }
                if self.mapper.protect(page, vma.prot.flags()) { Fault::Fixed } else { Fault::Bad }
            }
            Some(_) if write && self.removals != self.flushed => Fault::NeedsFlush,
            Some((old, writable)) if write && !writable => {
                let replaced = frame::user_page_refs(old) > 1;
                match self.break_cow(page, old, vma.prot) {
                    Cow::NoMemory => Fault::NoMemory,
                    Cow::Failed => Fault::Bad,
                    Cow::Done if replaced => Fault::FixedReplaced,
                    Cow::Done => Fault::Fixed,
                }
            }
            // The page table already allows it: this CPU had a stale
            // translation (another thread changed the mapping). Retry.
            Some(_) => {
                crate::arch::paging::invalidate_page(page);
                Fault::Fixed
            }
        }
    }

    /// A fresh frame for a missing page of `vma`: zeros, or the file's
    /// contents for file mappings.
    fn fill_page(&self, vma: &Vma, page: u64) -> Option<PhysAddr> {
        match vma.page_backing(page) {
            Some(file) => file.read_page(),
            None => frame::alloc_user_page(),
        }
    }

    /// Map `frame`, read for a [`Fault::NeedsFile`] fault, unless the
    /// mapping changed while the lock was dropped (then the caller frees
    /// the frame and the access is retried). Returns whether it was mapped.
    pub fn install_file_page(&mut self, page: u64, frame: PhysAddr, file: &FileBacking) -> bool {
        let Some(vma) = self.find(page) else { return false };
        let same = vma
            .page_backing(page)
            .is_some_and(|b| alloc::sync::Arc::ptr_eq(&b.inode, &file.inode) && b.offset == file.offset);
        if !same || self.mapper.lookup(page).is_some() {
            return false;
        }
        // Pages of tracked mappings start clean: read-only until written.
        let flags = Prot { write: vma.prot.write && !vma.tracks_writes(), ..vma.prot }.flags();
        publish_fence();
        self.mapper.map(page, frame, PageSize::Size4K, flags).is_ok()
    }

    /// Frames a completed shootdown covering removals up to `covered`
    /// made safe to free. Frames of later removals stay: their shootdown
    /// may not have reached every CPU yet.
    pub fn take_pending_free(&mut self, covered: u64) -> alloc::vec::Vec<PhysAddr> {
        let mut out = alloc::vec::Vec::new();
        self.pending_free.retain(|&(removal, p)| {
            if removal <= covered {
                out.push(p);
                false
            } else {
                true
            }
        });
        out
    }

    /// The page-table flags of `addr`'s 4 KiB mapping (diagnostics).
    pub fn leaf_flags(&self, addr: u64) -> Option<crate::arch::paging::MapFlags> {
        self.mapper.leaf_flags(addr & !(PAGE_SIZE - 1))
    }

    /// Physical address `addr` maps to, if present.
    pub fn translate(&self, addr: u64) -> Option<PhysAddr> {
        self.mapper.translate(addr)
    }

    /// Give `page` (mapping the shared frame `old`) a private copy mapped
    /// with `prot`.
    fn break_cow(&mut self, page: u64, old: PhysAddr, prot: Prot) -> Cow {
        if frame::user_page_refs(old) == 1 {
            // Last sharer: just restore the VMA's permissions.
            return if self.mapper.protect(page, prot.flags()) { Cow::Done } else { Cow::Failed };
        }
        let Some(new) = frame::alloc_user_page() else { return Cow::NoMemory };
        // SAFETY: Both frames are mapped in the direct map; `new` is fresh.
        unsafe { core::ptr::copy_nonoverlapping(old.to_virt(), new.to_virt(), PAGE_SIZE as usize) };
        self.mapper.unmap(page);
        // Other CPUs may still read the old frame until a shootdown, so
        // nobody may write the new one before it. A CPU with no cached
        // translation would use a writable entry at once, without a fault:
        // map the copy read-only. Writes fault, wait for the shootdown
        // (this is a removal: `Fault::NeedsFlush`), and then find a page
        // they own alone and make it writable in place.
        let ro = Prot { write: false, ..prot };
        publish_fence();
        if self.mapper.map(page, new, PageSize::Size4K, ro.flags()).is_err() {
            frame::put_user_page(new);
            return Cow::NoMemory;
        }
        self.removals += 1;
        self.pending_free.push((self.removals, old));
        Cow::Done
    }

    /// Duplicate this address space for fork(2). Private writable pages
    /// become copy-on-write in both; the caller flushes the TLB of the CPU
    /// running this address space, and every other CPU running its
    /// threads: until then copy-on-write splits wait ([`Fault::NeedsFlush`]).
    pub fn fork(&mut self) -> Result<AddressSpace, Error> {
        let mut child = AddressSpace::new()?;
        // Write access is being taken away: a removal of translations.
        self.removals += 1;
        child.vmas = self.vmas.clone();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        child.mmap_top = self.mmap_top;
        child.stack_top = self.stack_top;
        let vmas: alloc::vec::Vec<Vma> = self.vmas.values().cloned().collect();
        for v in vmas {
            for (page, p, writable) in self.mapper.user_pages(v.start, v.end) {
                // A private page a device holds stays the parent's: the
                // child gets a copy now (`pins`).
                if !v.shared && v.prot.write && super::pins::is_pinned(p) {
                    let Some(c) = frame::alloc_user_page() else { return Err(Error::NoMemory) };
                    // SAFETY: both are whole frames in the direct map; `c`
                    // is new and nothing else refers to it.
                    unsafe { core::ptr::copy_nonoverlapping(p.to_virt(), c.to_virt(), PAGE_SIZE as usize) };
                    if child.mapper.map(page, c, PageSize::Size4K, v.prot.flags()).is_err() {
                        frame::put_user_page(c);
                        return Err(Error::NoMemory);
                    }
                    continue;
                }
                frame::get_user_page(p);
                let flags = if v.shared || !v.prot.write {
                    // Clean pages of tracked mappings stay read-only.
                    Prot { write: v.prot.write && (writable || !v.tracks_writes()), ..v.prot }.flags()
                } else {
                    let ro = Prot { write: false, ..v.prot }.flags();
                    self.mapper.protect(page, ro);
                    ro
                };
                if child.mapper.map(page, p, PageSize::Size4K, flags).is_err() {
                    frame::put_user_page(p);
                    return Err(Error::NoMemory);
                }
            }
        }
        Ok(child)
    }

    /// Make sure the page at `addr` is present and private (as a write
    /// fault would), and return its frame.
    fn page_frame(&mut self, addr: u64) -> Option<PhysAddr> {
        let page = page_floor(addr);
        match self.mapper.lookup(page) {
            Some((p, true)) => return Some(p),
            Some((p, false)) => {
                if frame::user_page_refs(p) == 1 {
                    return Some(p);
                }
                let prot = self.find(page)?.prot;
                self.break_cow(page, p, prot);
                return self.mapper.lookup(page).map(|(p, _)| p);
            }
            None => {}
        }
        let vma = self.find(page)?.clone();
        let f = self.fill_page(&vma, page)?;
        self.mapper.map(page, f, PageSize::Size4K, vma.prot.flags()).ok()?;
        Some(f)
    }

    /// Make the pages of file `file` (an inode's address) with page indices
    /// in `pages` read-only in every shared mapping of it, so the next
    /// write faults and marks the page dirty again. Returns whether any
    /// entry changed: the caller then shoots down stale translations.
    pub fn write_protect_file(&mut self, file: usize, pages: &alloc::collections::BTreeSet<u64>) -> bool {
        let mut changed = false;
        let vmas: alloc::vec::Vec<Vma> = self
            .vmas
            .values()
            .filter(|v| {
                v.shared
                    && v.file.as_ref().is_some_and(|f| alloc::sync::Arc::as_ptr(&f.inode).cast::<u8>() as usize == file)
            })
            .cloned()
            .collect();
        for v in vmas {
            let base = v.file.as_ref().map_or(0, |f| f.offset);
            for (page, _, writable) in self.mapper.user_pages(v.start, v.end) {
                if writable && pages.contains(&((base + (page - v.start)) / PAGE_SIZE)) {
                    self.mapper.protect(page, Prot { write: false, ..v.prot }.flags());
                    changed = true;
                }
            }
        }
        changed
    }

    /// The files of the shared file mappings in `[addr, addr + len)`
    /// (msync(2)); `Error::NoMemory` if part of the range is unmapped.
    pub fn shared_files(
        &self,
        addr: u64,
        len: u64,
    ) -> Result<alloc::vec::Vec<alloc::sync::Arc<dyn crate::fs::vfs::Inode>>, Error> {
        let end = addr.checked_add(page_ceil(len)).ok_or(Error::NoMemory)?;
        let mut out: alloc::vec::Vec<alloc::sync::Arc<dyn crate::fs::vfs::Inode>> = alloc::vec::Vec::new();
        let mut a = addr;
        while a < end {
            let v = self.find(a).ok_or(Error::NoMemory)?;
            if v.shared
                && let Some(f) = &v.file
                && !out.iter().any(|o| alloc::sync::Arc::ptr_eq(o, &f.inode))
            {
                out.push(f.inode.clone());
            }
            a = v.end;
        }
        Ok(out)
    }

    /// Every mapping, in address order.
    pub fn vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    /// Pages currently backed by memory (RSS).
    pub fn resident_pages(&self) -> u64 {
        self.mapper.resident()
    }

    /// [`AddressSpace::resident_pages`] counted page by page (to check it).
    pub fn count_resident_pages(&self) -> u64 {
        self.vmas.values().map(|v| self.mapper.count_user_pages(v.start, v.end)).sum()
    }

    /// The most pages that were resident at once (getrusage(2)'s maxrss).
    pub fn peak_pages(&self) -> u64 {
        self.mapper.peak()
    }

    /// statm's (proc(5)) shared, text and data, in pages: resident pages
    /// of file and shared mappings; the executable mappings of `exe` (the
    /// program's code); private writable mappings (data and stack).
    pub fn statm_parts(&self, exe: Option<&alloc::sync::Arc<dyn crate::fs::vfs::Inode>>) -> (u64, u64, u64) {
        let pages = |v: &Vma| (v.end - v.start) / PAGE_SIZE;
        let shared = self
            .vmas
            .values()
            .filter(|v| v.shared || v.file.is_some())
            .map(|v| self.mapper.count_user_pages(v.start, v.end))
            .sum();
        let own_code = |v: &&Vma| {
            v.prot.exec && v.file.as_ref().zip(exe).is_some_and(|(f, e)| alloc::sync::Arc::ptr_eq(&f.inode, e))
        };
        let text = self.vmas.values().filter(own_code).map(pages).sum();
        let data = self.vmas.values().filter(|v| v.charged()).map(pages).sum();
        (shared, text, data)
    }

    /// Total size of all mappings (virtual size).
    pub fn mapped_bytes(&self) -> u64 {
        self.vmas.values().map(|v| v.end - v.start).sum()
    }

    /// The memory its mappings may need (Committed_AS, mm::commit).
    pub fn committed_bytes(&self) -> u64 {
        self.vmas.values().filter(|v| v.charged()).map(|v| v.end - v.start).sum()
    }

    /// Bytes of `[addr, addr + len)` that would become committed if made
    /// writable (mprotect(2)): private mappings that aren't yet.
    pub fn uncharged_in(&self, addr: u64, len: u64) -> u64 {
        let end = addr.saturating_add(len);
        self.vmas
            .range(..end)
            .map(|(_, v)| v)
            .filter(|v| v.end > addr && !v.shared && !v.charged())
            .map(|v| v.end.min(end) - v.start.max(addr))
            .sum()
    }

    /// Drop every private page, for the out-of-memory reaper (ADR 0123):
    /// the mappings stay, empty. Returns the pages dropped; the caller
    /// shoots down the owner's TLB entries before they are freed.
    pub fn reap(&mut self) -> u64 {
        let before = self.resident_pages();
        let ranges: alloc::vec::Vec<(u64, u64)> =
            self.vmas.values().filter(|v| !v.shared).map(|v| (v.start, v.end - v.start)).collect();
        for (start, len) in ranges {
            let _ = self.discard(start, len);
        }
        before.saturating_sub(self.resident_pages())
    }

    /// Write `data` at user address `addr` through the direct map (works on
    /// an address space that is not active, and ignores page protection).
    pub fn write_bytes(&mut self, mut addr: u64, mut data: &[u8]) -> Result<(), Error> {
        while !data.is_empty() {
            let off = (addr % PAGE_SIZE) as usize;
            let n = data.len().min(PAGE_SIZE as usize - off);
            let f = self.page_frame(addr).ok_or(Error::NoMemory)?;
            // SAFETY: `f` is a frame of this address space, mapped in the
            // direct map; `off + n` stays within it.
            unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), f.to_virt().add(off), n) };
            addr += n as u64;
            data = &data[n..];
        }
        Ok(())
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // No CPU may be using these tables: callers switch away first
        // (see `proc`), and other CPUs still on them (threads of the
        // process that are leaving) are waited for here.
        crate::sched::wait_root_unused(self.mapper.root().0);
        for (_, p) in self.pending_free.drain(..) {
            frame::put_user_page(p);
        }
        self.mapper.free_user_half(|_, p| frame::put_user_page(p));
        if cfg!(debug_assertions) {
            self.mapper.poison_root();
        }
        frame::free(self.mapper.root(), 0);
    }
}
