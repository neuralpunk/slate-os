// SPDX-License-Identifier: MIT OR Apache-2.0

//! x87/SSE/AVX state for user threads (Intel SDM vol. 1 ch. 13, "Managing
//! State Using the XSAVE Feature Set"; vol. 3A §2.5 and §13.1).
//!
//! The kernel itself is built soft-float and never touches these registers,
//! so user state is saved and restored eagerly on context switches between
//! user threads, and nowhere else. The one exception is a kernel FPU
//! section ([`with_vectors`]): AES-NI for disk encryption (ADR 0039).

use alloc::alloc::{Layout, alloc_zeroed, dealloc};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use slate_sync::Once;

use super::cpu::{cpuid, read_cr0, read_cr4, write_cr0, write_cr4};

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;

/// XCR0 components we enable: x87, SSE, AVX, and the three AVX-512 parts.
const WANTED_XCR0: u64 = 0b1110_0111;
const FXSAVE_SIZE: usize = 512;
const ALIGN: usize = 64;

static USE_XSAVE: AtomicBool = AtomicBool::new(false);
static AREA_SIZE: AtomicUsize = AtomicUsize::new(FXSAVE_SIZE);
static INITIAL: Once<FpuState> = Once::new();

/// Enable SSE (and XSAVE with AVX/AVX-512 where present) on this CPU. Call
/// on every CPU; the bootstrap CPU also records the initial state.
pub fn init_cpu() {
    let xsave = cpuid(1, 0).2 & (1 << 26) != 0;
    // SAFETY: Enabling FPU/SSE (and XSAVE if supported) only makes more
    // instructions usable; the kernel uses none of them.
    unsafe {
        write_cr0((read_cr0() & !(CR0_EM | CR0_TS)) | CR0_MP);
        let mut cr4 = read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT;
        if xsave {
            cr4 |= CR4_OSXSAVE;
        }
        write_cr4(cr4);
        if xsave {
            let (lo, _, _, hi) = cpuid(0xD, 0);
            let supported = (u64::from(hi) << 32) | u64::from(lo);
            let xcr0 = supported & WANTED_XCR0;
            asm!("xsetbv", in("ecx") 0, in("eax") xcr0 as u32, in("edx") (xcr0 >> 32) as u32, options(nomem, nostack));
        }
    }
    if xsave {
        USE_XSAVE.store(true, Ordering::Relaxed);
        // EBX: size of the XSAVE area for the components enabled in XCR0.
        AREA_SIZE.store(cpuid(0xD, 0).1 as usize, Ordering::Relaxed);
    }
    INITIAL.call_once(|| {
        let s = FpuState::new_uninit();
        // SAFETY: `fninit` and `ldmxcsr` reset the user-visible FPU state;
        // the kernel does not depend on it. The default MXCSR (0x1F80) masks
        // all SIMD exceptions, as Linux programs expect at startup.
        unsafe {
            let mxcsr: u32 = 0x1F80;
            asm!("fninit", "ldmxcsr [{}]", in(reg) &mxcsr, options(nostack));
        }
        s.save();
        s
    });
}

/// Size in bytes of a saved FPU/SIMD state.
pub fn area_size() -> usize {
    AREA_SIZE.load(Ordering::Relaxed)
}

/// A saved FPU/SIMD register file.
#[derive(Debug)]
pub struct FpuState {
    area: *mut u8,
    size: usize,
}

// SAFETY: The buffer is owned exclusively by this value.
unsafe impl Send for FpuState {}
// SAFETY: Shared access only reads (`restore` reads, `save` needs the owning
// thread's exclusive context, see `context::UserState`).
unsafe impl Sync for FpuState {}

impl FpuState {
    fn new_uninit() -> FpuState {
        let size = AREA_SIZE.load(Ordering::Relaxed);
        // SAFETY: The layout has a non-zero size. XSAVE needs a zeroed header.
        let area = unsafe { alloc_zeroed(Layout::from_size_align(size, ALIGN).unwrap()) };
        assert!(!area.is_null(), "out of memory for FPU state");
        FpuState { area, size }
    }

    /// A copy of the initial (reset) state.
    pub fn new() -> FpuState {
        let s = FpuState::new_uninit();
        let init = INITIAL.get().expect("FPU not initialized");
        // SAFETY: Both buffers are `size` bytes (sizes are fixed at boot).
        unsafe { core::ptr::copy_nonoverlapping(init.area, s.area, s.size) };
        s
    }

    /// The raw saved bytes (the XSAVE or FXSAVE image).
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `area` holds `size` initialized bytes owned by `self`.
        unsafe { core::slice::from_raw_parts(self.area, self.size) }
    }

    /// Replace the saved state with `src` (from a signal frame) if it is a
    /// well-formed image the CPU will accept; otherwise keep the reset
    /// state. A malformed image would make XRSTOR/FXRSTOR fault in the
    /// kernel, so the parts the CPU checks are validated first (Intel SDM
    /// vol. 1 §13.8, "Operation of XRSTOR"; MXCSR reserved bits, §10.5.1).
    pub fn load_bytes(&self, src: &[u8]) {
        let init = INITIAL.get().expect("FPU not initialized");
        let ok = src.len() >= self.size && {
            let mxcsr = u32::from_le_bytes(src[24..28].try_into().unwrap());
            let mxcsr_mask = match u32::from_le_bytes(init.bytes()[28..32].try_into().unwrap()) {
                0 => 0xFFBF,
                m => m,
            };
            let header_ok = if USE_XSAVE.load(Ordering::Relaxed) {
                let xstate_bv = u64::from_le_bytes(src[512..520].try_into().unwrap());
                let xcomp_bv = u64::from_le_bytes(src[520..528].try_into().unwrap());
                // SAFETY: XGETBV with ECX = 0 reads XCR0; OSXSAVE is on.
                let xcr0 = unsafe {
                    let (lo, hi): (u32, u32);
                    asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi, options(nomem, nostack));
                    (u64::from(hi) << 32) | u64::from(lo)
                };
                xstate_bv & !xcr0 == 0 && xcomp_bv == 0 && src[528..576].iter().all(|&b| b == 0)
            } else {
                true
            };
            mxcsr & !mxcsr_mask == 0 && header_ok
        };
        let from = if ok { &src[..self.size] } else { init.bytes() };
        // SAFETY: `area` is `size` bytes owned by `self`.
        unsafe { core::ptr::copy_nonoverlapping(from.as_ptr(), self.area, self.size) };
    }

    /// Save the CPU's current FPU state here.
    pub fn save(&self) {
        // SAFETY: `area` is a 64-byte aligned buffer of the size the CPU
        // reported for the enabled components.
        unsafe {
            if USE_XSAVE.load(Ordering::Relaxed) {
                asm!("xsave64 [{}]", in(reg) self.area, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack));
            } else {
                asm!("fxsave64 [{}]", in(reg) self.area, options(nostack));
            }
        }
    }

    /// Load this state into the CPU.
    pub fn restore(&self) {
        // SAFETY: The area holds a state written by `save` (or a copy of
        // one), so it is well formed.
        unsafe {
            if USE_XSAVE.load(Ordering::Relaxed) {
                asm!("xrstor64 [{}]", in(reg) self.area, in("eax") u32::MAX, in("edx") u32::MAX, options(nostack));
            } else {
                asm!("fxrstor64 [{}]", in(reg) self.area, options(nostack));
            }
        }
    }
}

impl Default for FpuState {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FpuState {
    fn drop(&mut self) {
        // SAFETY: Allocated in `new_uninit` with this layout.
        unsafe { dealloc(self.area, Layout::from_size_align(self.size, ALIGN).unwrap()) };
    }
}

/// An FXSAVE area: 512 bytes, 16-byte aligned (Intel SDM vol. 2, FXSAVE).
#[repr(C, align(16))]
struct FxArea([u8; FXSAVE_SIZE]);

/// Run `f`, which may overwrite the SSE registers (AES-NI), in a kernel
/// FPU section: interrupts masked (so no switch to another thread and no
/// handler runs in between), the x87/SSE state saved before and restored
/// after. Whatever thread's state the registers held is untouched. Keep
/// `f` short: interrupts wait for it.
pub fn with_vectors<R>(f: impl FnOnce() -> R) -> R {
    let _masked = super::cpu::InterruptGuard::new();
    let mut area = FxArea([0; FXSAVE_SIZE]);
    // SAFETY: SSE is enabled (`init`); the area is 512 writable bytes,
    // 16-byte aligned.
    unsafe { asm!("fxsave64 [{}]", in(reg) area.0.as_mut_ptr(), options(nostack)) };
    let r = f();
    // SAFETY: the area holds the image FXSAVE just wrote, valid for
    // FXRSTOR.
    unsafe { asm!("fxrstor64 [{}]", in(reg) area.0.as_ptr(), options(nostack, readonly)) };
    r
}
