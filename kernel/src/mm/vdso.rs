// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vDSO (vdso(7)): a shared object built from kernel/vdso, embedded in
//! the kernel and mapped into every process with a read-only data page
//! ("vvar") right below it. The vvar page holds the clock parameters, so
//! `clock_gettime` and friends run without entering the kernel when the
//! clock is the (invariant, synchronized) TSC.
//!
//! The frames are allocated once and shared by every process; the kernel
//! keeps its own reference, so they are never freed.

use alloc::vec::Vec;

use slate_elf::{Elf, PT_LOAD};
use slate_sync::Once;

use super::PhysAddr;
use super::aspace::{AddressSpace, Error, Prot};

static IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vdso.so"));

/// Where the vvar page goes without randomization; the vDSO itself
/// follows it. Below the largest main stack an exec reserves (1 GiB,
/// `aspace::stack_size`), so a raised RLIMIT_STACK (GCC asks for 64 MiB)
/// cannot collide with it.
pub const VVAR_ADDR: u64 = 0x7FFF_BFE0_0000;
const _: () = assert!(VVAR_ADDR + 4096 + (1 << 20) <= super::aspace::STACK_TOP - (1 << 30));

/// The vvar page layout, shared with kernel/vdso/src/lib.rs.
#[repr(C)]
struct Vvar {
    magic: u64,
    mode: u64,
    tsc_base: u64,
    mult: u64,
    /// Wall-clock nanoseconds at monotonic zero; changes when the time is
    /// set (one aligned 64-bit store, which readers see whole).
    realtime_offset_ns: i64,
}

const MAGIC: u64 = 0x534C_4154_4556_4452; // "SLATEVDR"

#[derive(Debug)]
struct Frames {
    vvar: PhysAddr,
    code: Vec<PhysAddr>,
}

static FRAMES: Once<Frames> = Once::new();

/// Set up the vDSO frames. Called once the clock is installed.
pub fn init() {
    let elf = Elf::parse_prefix(IMAGE, IMAGE.len() as u64).expect("bad vDSO image");
    for ph in elf.program_headers().filter(|p| p.kind == PT_LOAD) {
        // The image is mapped as is: file layout must equal memory layout.
        assert!(ph.offset == ph.vaddr && ph.filesz == ph.memsz, "vDSO segment not mappable as a file");
        assert!(ph.vaddr + ph.memsz <= IMAGE.len().next_multiple_of(4096) as u64);
    }
    let vvar = super::frame::alloc_user_page().expect("no memory for the vvar page");
    let (mode, tsc_base, mult) = match crate::time::clock_params() {
        Some(("tsc", base, mult)) => (1, base, mult),
        _ => (0, 0, 0),
    };
    let data = Vvar { magic: MAGIC, mode, tsc_base, mult, realtime_offset_ns: crate::time::realtime_offset_ns() };
    // SAFETY: `vvar` is a fresh frame in the direct map, big enough for `Vvar`.
    unsafe { (vvar.to_virt() as *mut Vvar).write(data) };
    let code = IMAGE
        .chunks(4096)
        .map(|chunk| {
            let f = super::frame::alloc_user_page().expect("no memory for the vDSO");
            // SAFETY: `f` is a fresh, zeroed frame in the direct map.
            unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), f.to_virt(), chunk.len()) };
            f
        })
        .collect();
    FRAMES.call_once(|| Frames { vvar, code });
}

/// The wall clock moved: the vDSO follows.
pub fn set_realtime_offset(ns: i64) {
    let Some(f) = FRAMES.get() else { return };
    let field = core::mem::offset_of!(Vvar, realtime_offset_ns);
    // SAFETY: The vvar frame is ours for good (never freed) and in the
    // direct map; the field is 8-byte aligned (offset 32 of a page), so an
    // atomic store there is sound while processes read it.
    let atomic = unsafe { core::sync::atomic::AtomicI64::from_ptr(f.vvar.to_virt().add(field).cast::<i64>()) };
    atomic.store(ns, core::sync::atomic::Ordering::Release);
}

/// Map the vvar page at `vvar` and the vDSO after it into `aspace`;
/// returns the vDSO's address (for `AT_SYSINFO_EHDR`), or `None` before
/// `init`.
pub fn map(aspace: &mut AddressSpace, vvar: u64) -> Result<Option<u64>, Error> {
    let Some(f) = FRAMES.get() else { return Ok(None) };
    aspace.map_frames(vvar, &[f.vvar], Prot { read: true, write: false, exec: false })?;
    aspace.map_frames(vvar + 4096, &f.code, Prot { read: true, write: false, exec: true })?;
    Ok(Some(vvar + 4096))
}
