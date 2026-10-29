// SPDX-License-Identifier: MIT OR Apache-2.0

//! Copying between kernel and user memory.
//!
//! User pointers are checked against the user half, then accessed with
//! `rep movsb` under the exception table: a fault (an unmapped page that
//! demand paging cannot fill) becomes `Err(EFAULT)` instead of a panic. With
//! SMAP on, the copy runs between `stac` and `clac`.

use core::arch::asm;

use super::paging::smap_enabled;

/// End of the user half of the address space (canonical lower half).
pub const USER_END: u64 = 0x0000_8000_0000_0000;

/// A failed user access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadAddress;

/// Whether `[addr, addr + len)` lies in user space.
pub fn user_range_ok(addr: u64, len: usize) -> bool {
    addr.checked_add(len as u64).is_some_and(|end| end <= USER_END)
}

/// # Safety
///
/// `dst..dst+len` and `src..src+len` must be valid for writes and reads
/// respectively, except that user addresses may fault (and are reported).
unsafe fn copy(dst: *mut u8, src: *const u8, len: usize) -> Result<(), BadAddress> {
    let faulted: u64;
    // SAFETY: Per the contract; a fault on the `rep movsb` resumes at label 3
    // through the exception table with r11 = 1. `stac`/`clac` are only used
    // when SMAP is enabled (they are invalid otherwise).
    unsafe {
        if smap_enabled() {
            asm!(
                "stac",
                "2: rep movsb",
                "3: clac",
                ".pushsection .slate_extable, \"a\"",
                ".balign 4",
                ".long 2b - ., 3b - .",
                ".popsection",
                inout("rdi") dst => _, inout("rsi") src => _, inout("rcx") len => _,
                inout("r11") 0u64 => faulted, out("rax") _,
                options(nostack),
            );
        } else {
            asm!(
                "2: rep movsb",
                "3:",
                ".pushsection .slate_extable, \"a\"",
                ".balign 4",
                ".long 2b - ., 3b - .",
                ".popsection",
                inout("rdi") dst => _, inout("rsi") src => _, inout("rcx") len => _,
                inout("r11") 0u64 => faulted, out("rax") _,
                options(nostack),
            );
        }
    }
    if faulted == 0 { Ok(()) } else { Err(BadAddress) }
}

/// Copy `dst.len()` bytes from user address `src`.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), BadAddress> {
    if !user_range_ok(src, dst.len()) {
        return Err(BadAddress);
    }
    // SAFETY: `dst` is a valid kernel buffer; `src` is a user range.
    unsafe { copy(dst.as_mut_ptr(), src as *const u8, dst.len()) }
}

/// Copy `src` to user address `dst`.
pub fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), BadAddress> {
    if !user_range_ok(dst, src.len()) {
        return Err(BadAddress);
    }
    // SAFETY: `src` is a valid kernel buffer; `dst` is a user range.
    unsafe { copy(dst as *mut u8, src.as_ptr(), src.len()) }
}

/// Read a plain-data value from user memory.
pub fn read_user<T: Copy + Default>(addr: u64) -> Result<T, BadAddress> {
    let mut v = T::default();
    // SAFETY: `T` is plain data (Copy); viewing it as bytes to overwrite it
    // with user bytes is how the C ABI structs we read are defined.
    let bytes = unsafe { core::slice::from_raw_parts_mut((&raw mut v).cast::<u8>(), size_of::<T>()) };
    copy_from_user(bytes, addr)?;
    Ok(v)
}

/// Write a plain-data value to user memory.
pub fn write_user<T: Copy>(addr: u64, v: &T) -> Result<(), BadAddress> {
    // SAFETY: `T` is plain data; reading its bytes is fine.
    let bytes = unsafe { core::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) };
    copy_to_user(addr, bytes)
}

/// Read a NUL-terminated string of at most `max` bytes (excluding the NUL)
/// from user memory. Reads stop at page boundaries so no byte past the
/// terminator is touched on an unmapped page.
pub fn read_user_cstr(mut addr: u64, max: usize) -> Result<alloc::vec::Vec<u8>, StrError> {
    let mut out = alloc::vec::Vec::new();
    loop {
        let chunk = (4096 - (addr % 4096) as usize).min(256);
        let mut buf = [0u8; 256];
        copy_from_user(&mut buf[..chunk], addr).map_err(|_| StrError::Fault)?;
        if let Some(nul) = buf[..chunk].iter().position(|&b| b == 0) {
            out.extend_from_slice(&buf[..nul]);
            return if out.len() > max { Err(StrError::TooLong) } else { Ok(out) };
        }
        out.extend_from_slice(&buf[..chunk]);
        if out.len() > max {
            return Err(StrError::TooLong);
        }
        addr += chunk as u64;
    }
}

/// Why a user string could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrError {
    Fault,
    TooLong,
}

/// Atomically replace the 32-bit word at user address `addr` with `new` if
/// it holds `old` (`lock cmpxchg`). Returns the value it held; the swap
/// happened if that is `old`. A fault (or a misaligned address) is an
/// error.
pub fn cmpxchg_user_u32(addr: u64, old: u32, new: u32) -> Result<u32, BadAddress> {
    if addr % 4 != 0 || !user_range_ok(addr, 4) {
        return Err(BadAddress);
    }
    let found: u32;
    let faulted: u64;
    // SAFETY: `addr` is an aligned user address; a fault on the `lock
    // cmpxchg` resumes at label 3 through the exception table with r11 = 1
    // (and rax, rcx, rsi clobbered, which are declared). `stac`/`clac`
    // only with SMAP enabled.
    unsafe {
        if smap_enabled() {
            asm!(
                "stac",
                "2: lock cmpxchg dword ptr [rdi], edx",
                "3: clac",
                ".pushsection .slate_extable, \"a\"",
                ".balign 4",
                ".long 2b - ., 3b - .",
                ".popsection",
                in("rdi") addr, in("edx") new, inout("eax") old => found,
                inout("r11") 0u64 => faulted, out("rcx") _, out("rsi") _,
                options(nostack),
            );
        } else {
            asm!(
                "2: lock cmpxchg dword ptr [rdi], edx",
                "3:",
                ".pushsection .slate_extable, \"a\"",
                ".balign 4",
                ".long 2b - ., 3b - .",
                ".popsection",
                in("rdi") addr, in("edx") new, inout("eax") old => found,
                inout("r11") 0u64 => faulted, out("rcx") _, out("rsi") _,
                options(nostack),
            );
        }
    }
    if faulted == 0 { Ok(found) } else { Err(BadAddress) }
}

/// Atomically apply `f` to the 32-bit word at user address `addr`
/// (a compare-and-swap loop). Returns the old value.
pub fn update_user_u32(addr: u64, f: impl Fn(u32) -> u32) -> Result<u32, BadAddress> {
    let mut cur: u32 = read_user(addr)?;
    loop {
        let found = cmpxchg_user_u32(addr, cur, f(cur))?;
        if found == cur {
            return Ok(cur);
        }
        cur = found;
    }
}
