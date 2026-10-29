// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared mappings of files and devices: mmap(2) with `MAP_SHARED`, for
//! programs that draw into DRM dumb buffers.

use crate::{Errno, Result, sys};

/// A readable and writable shared mapping, unmapped when dropped.
pub struct Mapping {
    ptr: *mut u8,
    len: usize,
}

impl core::fmt::Debug for Mapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mapping({:p}, {})", self.ptr, self.len)
    }
}

impl Mapping {
    /// Map `len` bytes of `fd` at `offset`, shared.
    pub fn shared(fd: i32, len: usize, offset: u64) -> Result<Mapping> {
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        // PROT_READ|PROT_WRITE and MAP_SHARED (mmap(2), musl sys/mman.h);
        // slate-abi's prot and map flags natively.
        let (prot, flags) = if sys::native() {
            (slate_abi::prot::READ | slate_abi::prot::WRITE, slate_abi::map::SHARED)
        } else {
            (3, 1)
        };
        let p = crate::syscall!(sys::pick(sys::MMAP, slate_abi::nr::MAP), 0, len, prot, flags, fd, offset)?;
        Ok(Mapping { ptr: p as *mut u8, len })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: the kernel mapped `len` readable and writable bytes at
        // `ptr`, which stay mapped until drop; `&mut self` makes this the
        // only reference.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// The mapping as 32-bit words, to read (it is page-aligned).
    pub fn words(&self) -> &[u32] {
        // SAFETY: as in `words_mut`, shared rather than exclusive.
        unsafe { core::slice::from_raw_parts(self.ptr.cast::<u32>(), self.len / 4) }
    }

    /// The mapping as 32-bit words (it is page-aligned).
    pub fn words_mut(&mut self) -> &mut [u32] {
        // SAFETY: as in `as_mut_slice`; mappings start on a page boundary,
        // so the pointer is aligned for u32, and the length is rounded down.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.cast::<u32>(), self.len / 4) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = crate::syscall!(sys::pick(sys::MUNMAP, slate_abi::nr::UNMAP), self.ptr, self.len);
    }
}
