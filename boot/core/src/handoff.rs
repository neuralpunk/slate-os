// SPDX-License-Identifier: MIT OR Apache-2.0

//! Answering the kernel's requests and jumping to it (ADR 0089).
//!
//! Responses live in an [`Arena`] of bootloader-reclaimable memory, and
//! every pointer the kernel gets is a direct-map address. The jump loads
//! the tables that also map the loader one to one, continues at its
//! direct-map alias, loads the kernel's tables and the protocol's GDT, and
//! enters the kernel on its stack with interrupts off (the protocol's
//! entry machine state).

use crate::proto::{self, Found, HHDM};

/// A bump allocator over memory the loader owns, reachable one to one.
#[derive(Debug)]
pub struct Arena {
    base: u64,
    len: u64,
    used: u64,
}

impl Arena {
    /// # Safety
    /// `base..base + len` must be memory the loader owns, identity mapped
    /// and in the direct map's types.
    pub unsafe fn new(base: u64, len: u64) -> Arena {
        Arena { base, len, used: 0 }
    }

    /// Room for `len` bytes aligned to `align`: its physical address.
    pub fn take(&mut self, len: u64, align: u64) -> Option<u64> {
        let at = (self.base + self.used).next_multiple_of(align);
        if at + len > self.base + self.len {
            return None;
        }
        self.used = at + len - self.base;
        // SAFETY: The range is the arena's (see `new`) and unused.
        unsafe { core::ptr::write_bytes(at as *mut u8, 0, len as usize) };
        Some(at)
    }

    /// Store `v`: its direct-map address.
    pub fn put<T>(&mut self, v: T) -> Option<u64> {
        let at = self.take(core::mem::size_of::<T>() as u64, core::mem::align_of::<T>() as u64)?;
        // SAFETY: `take` gave room for a T, aligned.
        unsafe { core::ptr::write(at as *mut T, v) };
        Some(HHDM + at)
    }

    /// Store `items` as an array: its direct-map address.
    pub fn array<T: Copy>(&mut self, items: &[T]) -> Option<u64> {
        let at = self.take(core::mem::size_of_val(items) as u64, core::mem::align_of::<T>() as u64)?;
        // SAFETY: As in `put`, for the whole array.
        unsafe { core::ptr::copy_nonoverlapping(items.as_ptr(), at as *mut T, items.len()) };
        Some(HHDM + at)
    }

    /// A NUL-terminated copy of `s`: its direct-map address.
    pub fn str(&mut self, s: &str) -> Option<u64> {
        let at = self.take(s.len() as u64 + 1, 1)?;
        // SAFETY: `take` gave `len + 1` zeroed bytes.
        unsafe { core::ptr::copy_nonoverlapping(s.as_ptr(), at as *mut u8, s.len()) };
        Some(HHDM + at)
    }
}

/// The kernel's requests, in its loaded image.
#[derive(Debug)]
pub struct Requests {
    /// The image's physical address (identity mapped).
    image: u64,
    base_revision: Option<usize>,
    found: alloc::vec::Vec<Found>,
}

impl Requests {
    /// # Safety
    /// `image..image + len` must be the loaded kernel, identity mapped.
    pub unsafe fn find(image: u64, len: u64) -> Requests {
        // SAFETY: The caller's range.
        let bytes = unsafe { core::slice::from_raw_parts(image as *const u8, len as usize) };
        let (base_revision, found) = proto::scan(bytes);
        Requests { image, base_revision, found }
    }

    fn at(&self, id: [u64; 2]) -> Option<u64> {
        self.found.iter().find(|f| f.id == id).map(|f| self.image + f.at as u64)
    }

    /// Whether the kernel makes request `id`.
    pub fn wants(&self, id: [u64; 2]) -> bool {
        self.at(id).is_some()
    }

    /// The word a request carries (`proto::REQ_DATA`): the MP flags.
    pub fn data(&self, id: [u64; 2]) -> Option<u64> {
        // SAFETY: The request lies in the image (`find`).
        self.at(id).map(|r| unsafe { core::ptr::read_unaligned((r + proto::REQ_DATA as u64) as *const u64) })
    }

    /// Point request `id` at a response (a direct-map address).
    pub fn answer(&self, id: [u64; 2], response: u64) {
        if let Some(r) = self.at(id) {
            // SAFETY: The request lies in the image (`find`).
            unsafe { core::ptr::write_unaligned((r + proto::REQ_RESPONSE as u64) as *mut u64, response) };
        }
    }

    /// Tell the kernel its base revision is spoken (or not, when it asks
    /// for a later one). Without the tag, revision 0 is assumed.
    pub fn base_revision(&self) -> Result<u64, u64> {
        let Some(at) = self.base_revision else { return Ok(0) };
        let p = (self.image + at as u64) as *mut u64;
        // SAFETY: The tag's three words lie in the image.
        unsafe {
            let wanted = core::ptr::read_unaligned(p.add(2));
            if wanted > proto::REVISION {
                return Err(wanted);
            }
            core::ptr::write_unaligned(p.add(1), wanted);
            core::ptr::write_unaligned(p.add(2), 0);
            Ok(wanted)
        }
    }
}

/// What the jump needs, read by its code at fixed offsets.
#[repr(C)]
#[derive(Debug)]
pub struct Jump {
    /// The tables with the one-to-one lower half (below 4 GiB not needed).
    pub identity_cr3: u64,
    pub kernel_cr3: u64,
    pub hhdm: u64,
    pub entry: u64,
    /// The stack's top, a direct-map address.
    pub stack: u64,
    pub gdtr: [u16; 8],
}

core::arch::global_asm!(
    ".globl slate_loader_jump",
    "slate_loader_jump:",
    "    cli",
    "    cld",
    "    mov 0(%rdi), %rax",
    "    mov %rax, %cr3",
    "    mov 16(%rdi), %rdx",
    "    add %rdx, %rdi",
    "    lea 1f(%rip), %rax",
    "    add %rdx, %rax",
    "    jmp *%rax",
    "1:",
    "    mov 8(%rdi), %rax",
    "    mov %rax, %cr3",
    "    lgdt 40(%rdi)",
    "    mov 32(%rdi), %rsp",
    "    lea 2f(%rip), %rax",
    "    pushq $0x28",
    "    push %rax",
    "    lretq",
    "2:",
    "    mov $0x30, %eax",
    "    mov %eax, %ds",
    "    mov %eax, %es",
    "    mov %eax, %ss",
    "    mov %eax, %fs",
    "    mov %eax, %gs",
    "    mov 24(%rdi), %rax",
    "    xor %ebp, %ebp",
    "    pushq $0",
    "    jmp *%rax",
    options(att_syntax),
);

const _: () = assert!(core::mem::offset_of!(Jump, gdtr) == 40 && core::mem::offset_of!(Jump, stack) == 32);

// System V's convention on every target: UEFI's "C" is Microsoft's, which
// would pass the argument in rcx.
unsafe extern "sysv64" {
    fn slate_loader_jump(j: *const Jump) -> !;
}

/// Enter the kernel.
///
/// # Safety
/// The loader must run one to one; `j` and the loader's code must be in
/// the direct map of both tables; everything the kernel needs must be in
/// place; boot services must be over.
pub unsafe fn jump(j: &Jump) -> ! {
    // SAFETY: The caller's conditions are the jump code's.
    unsafe {
        // No-execute in the tables needs EFER.NXE.
        crate::cpu::wrmsr(crate::cpu::EFER, crate::cpu::rdmsr(crate::cpu::EFER) | crate::cpu::EFER_NXE);
        slate_loader_jump(j)
    }
}
