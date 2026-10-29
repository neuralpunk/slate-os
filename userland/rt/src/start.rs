// SPDX-License-Identifier: MIT OR Apache-2.0

//! Process start-up: the initial stack (System V AMD64 psABI §3.4.1) holds
//! argc, argv pointers, NULL, environment pointers, NULL, then the
//! auxiliary vector.

use alloc::vec::Vec;

use slate_sync::Once;

pub(crate) struct Startup {
    pub args: Vec<Vec<u8>>,
    pub env: Vec<Vec<u8>>,
}

pub(crate) static STARTUP: Once<Startup> = Once::new();

/// Auxiliary vector entries: the program headers' address and count
/// (System V AMD64 psABI §3.4.3).
const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;

// Dynamic section tags and relocation types (System V gABI, "Dynamic
// Section"; the x86-64 psABI §4.4 for R_X86_64_RELATIVE; DT_RELR from the
// gABI's 2022 addition).
const DT_NULL: u64 = 0;
const DT_PLTRELSZ: u64 = 2;
const DT_JMPREL: u64 = 23;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;
const R_X86_64_NONE: u64 = 0;
const R_X86_64_RELATIVE: u64 = 8;
/// Program header type (gABI): the part to make read-only once relocated
/// (PT_GNU_RELRO, the GNU extension every linker emits).
const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Where the program was loaded relative to its link addresses: 0 for a
/// program linked at a fixed address. Set by [`__slate_relocate`] (an
/// integer static: storing it needs no relocation).
static BIAS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The program's load bias (ADR 0092).
pub fn bias() -> usize {
    BIAS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Apply `len` bytes of Elf64_Rela entries at `table` (offset, info with
/// the type in its low 32 bits, addend).
///
/// # Safety
///
/// As [`__slate_relocate`].
unsafe fn apply_rela(base: usize, table: usize, len: usize, ent: usize) {
    let mut at = 0;
    while ent != 0 && at + 24 <= len {
        let r = (table + at) as *const u64;
        // SAFETY: The table is the program's own, mapped by the kernel; each
        // relative relocation names a word of the program.
        unsafe {
            match *r.add(1) & 0xffff_ffff {
                R_X86_64_NONE => {}
                R_X86_64_RELATIVE => {
                    *(base.wrapping_add(*r as usize) as *mut usize) = base.wrapping_add(*r.add(2) as usize)
                }
                _ => core::arch::asm!("ud2", options(noreturn)),
            }
        }
        at += ent;
    }
}

/// Apply a static position-independent program's own relocations (ADR
/// 0092): `_start` calls this before anything else, with the run-time
/// addresses of `_DYNAMIC` (0 in a program linked at a fixed address)
/// and of the ELF header, which the linker put at address 0. Only
/// relative relocations can occur in a program without dynamic symbols;
/// anything else stops the program. It may touch nothing that needs
/// relocating itself: no statics, no panics.
///
/// # Safety
///
/// Only `_start`, once, with those two addresses.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __slate_relocate(dynamic: *const u64, base: usize) {
    if dynamic.is_null() {
        return;
    }
    let (mut rela, mut relasz, mut relaent, mut relr, mut relrsz) = (0, 0, 24, 0, 0);
    let (mut jmprel, mut pltrelsz) = (0, 0);
    let mut d = dynamic;
    // SAFETY: The dynamic section is an array of (tag, value) pairs ending
    // with DT_NULL, mapped by the kernel; pointers in it are link-time
    // addresses, `base` added at run time.
    unsafe {
        loop {
            let (tag, val) = (*d, *d.add(1));
            match tag {
                DT_NULL => break,
                DT_RELA => rela = base.wrapping_add(val as usize),
                DT_RELASZ => relasz = val as usize,
                DT_RELAENT => relaent = val as usize,
                DT_RELR => relr = base.wrapping_add(val as usize),
                DT_RELRSZ => relrsz = val as usize,
                DT_JMPREL => jmprel = base.wrapping_add(val as usize),
                DT_PLTRELSZ => pltrelsz = val as usize,
                _ => {}
            }
            d = d.add(2);
        }
        apply_rela(base, rela, relasz, relaent);
        // The PLT's relocations (a static program has none that matter).
        apply_rela(base, jmprel, pltrelsz, 24);
        // RELR: an address, then bitmaps of the words after it (odd
        // entries), each word needing the base added.
        let mut word: *mut usize = core::ptr::null_mut();
        let mut at = 0;
        while at + 8 <= relrsz {
            let e = *((relr + at) as *const usize);
            if e & 1 == 0 {
                word = base.wrapping_add(e) as *mut usize;
                *word = (*word).wrapping_add(base);
                word = word.add(1);
            } else {
                let mut bits = e >> 1;
                let mut w = word;
                while bits != 0 {
                    if bits & 1 != 0 {
                        *w = (*w).wrapping_add(base);
                    }
                    bits >>= 1;
                    w = w.add(1);
                }
                word = word.add(63);
            }
            at += 8;
        }
    }
    BIAS.store(base, core::sync::atomic::Ordering::Relaxed);
}

/// The `_start` of Slate's programs: relocate, then call `$entry` with the
/// initial stack pointer.
#[macro_export]
#[doc(hidden)]
macro_rules! start_asm {
    ($entry:path) => {
        core::arch::naked_asm!(
            ".weak _DYNAMIC",
            "xor ebp, ebp",
            "mov r12, rsp",
            "and rsp, -16",
            "lea rdi, [rip + _DYNAMIC]",
            "lea rsi, [rip + __ehdr_start]",
            "call {reloc}",
            "mov rdi, r12",
            "call {entry}",
            "ud2",
            reloc = sym $crate::start::__slate_relocate,
            entry = sym $entry,
        )
    };
}

/// Make the relocated read-only data read-only (PT_GNU_RELRO): whole
/// pages inside it, as the linker aligns its end.
///
/// # Safety
///
/// `phdr`/`phnum` must be the program's own headers (AT_PHDR, AT_PHNUM).
unsafe fn protect_relro(phdr: usize, phnum: usize) {
    let (bias, mut relro) = (bias(), None);
    for i in 0..phnum {
        // SAFETY: The caller vouches for the headers (56 bytes each:
        // type and flags, offset, vaddr, paddr, filesz, memsz, align).
        let h = unsafe { core::slice::from_raw_parts((phdr + i * 56) as *const u64, 7) };
        if h[0] as u32 == PT_GNU_RELRO {
            relro = Some((h[2] as usize, h[5] as usize));
        }
    }
    if let Some((vaddr, memsz)) = relro {
        let start = bias.wrapping_add(vaddr) & !4095;
        let end = bias.wrapping_add(vaddr + memsz) & !4095;
        if end > start {
            // PROT_READ (mmap(2), musl sys/mman.h); slate-abi's natively.
            let read = if crate::sys::native() { slate_abi::prot::READ } else { 1 };
            let _ = crate::syscall!(
                crate::sys::pick(crate::sys::MPROTECT, slate_abi::nr::PROTECT),
                start,
                end - start,
                read
            );
        }
    }
}

/// Read a NUL-terminated string.
///
/// # Safety
///
/// `p` must point to a NUL-terminated string.
pub(crate) unsafe fn cstr(p: *const u8) -> Vec<u8> {
    let mut n = 0;
    // SAFETY: The caller guarantees a terminating NUL.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: `n` bytes before the NUL are readable.
    unsafe { core::slice::from_raw_parts(p, n) }.to_vec()
}

/// Called by `_start` with the initial stack pointer.
///
/// # Safety
///
/// `sp` must be the process's initial stack pointer.
pub unsafe fn run(sp: *const usize, main: fn() -> i32) -> ! {
    // SAFETY: The kernel laid out argc, argv, envp and the auxiliary
    // vector as the psABI says.
    unsafe {
        let argc = *sp;
        let argv = sp.add(1);
        let envp = argv.add(argc + 1);
        // The interface must be known before the first allocation (the
        // allocator makes system calls): the auxiliary vector follows
        // the environment's NULL.
        let mut envc = 0;
        while *envp.add(envc) != 0 {
            envc += 1;
        }
        let mut aux = envp.add(envc + 1);
        let (mut phdr, mut phnum) = (0, 0);
        while *aux != 0 {
            match *aux as u64 {
                slate_abi::AT_SLATE_ABI if *aux.add(1) >= 1 => crate::sys::set_native(),
                AT_PHDR => phdr = *aux.add(1),
                AT_PHNUM => phnum = *aux.add(1),
                _ => {}
            }
            aux = aux.add(2);
        }
        // Thread-local storage before anything uses it (ADR 0073).
        if phdr != 0 {
            crate::thread::init_main(phdr, phnum);
            protect_relro(phdr, phnum);
        }
        let args = (0..argc).map(|i| cstr(*argv.add(i) as *const u8)).collect();
        let env = (0..envc).map(|i| cstr(*envp.add(i) as *const u8)).collect();
        STARTUP.call_once(|| Startup { args, env });
    }
    crate::signal::init();
    let code = main();
    crate::process::exit(code)
}

/// Like [`program!`], without the native note: Slate runs the program in
/// the Linux interface, as it would any Linux program (for programs that
/// live inside a Linux runtime, ADR 0038).
#[macro_export]
macro_rules! linux_program {
    ($main:path) => {
        #[global_allocator]
        static ALLOCATOR: $crate::alloc_impl::Allocator = $crate::alloc_impl::Allocator::new();

        #[panic_handler]
        fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
            $crate::panic(info)
        }

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C" fn _start() -> ! {
            $crate::start_asm!(__slate_entry)
        }

        extern "C" fn __slate_entry(sp: *const usize) -> ! {
            // SAFETY: `_start` passes the initial stack pointer.
            unsafe { $crate::start::run(sp, $main) }
        }
    };
}

/// Define the program's entry point, panic handler and allocator:
/// `slate_rt::program!(main);` with `fn main() -> i32`. The binary also
/// gets the ELF note that asks Slate for the native interface (ADR 0031:
/// owner `Slate`, type 1, version 1); Linux ignores it.
#[macro_export]
macro_rules! program {
    ($main:path) => {
        core::arch::global_asm!(
            ".pushsection .note.slate,\"a\",@note",
            ".balign 4",
            ".long 6",
            ".long 4",
            ".long 1",
            ".asciz \"Slate\"",
            ".balign 4",
            ".long 1",
            ".popsection",
        );

        #[global_allocator]
        static ALLOCATOR: $crate::alloc_impl::Allocator = $crate::alloc_impl::Allocator::new();

        #[panic_handler]
        fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
            $crate::panic(info)
        }

        #[unsafe(no_mangle)]
        #[unsafe(naked)]
        unsafe extern "C" fn _start() -> ! {
            $crate::start_asm!(__slate_entry)
        }

        extern "C" fn __slate_entry(sp: *const usize) -> ! {
            // SAFETY: `_start` passes the initial stack pointer.
            unsafe { $crate::start::run(sp, $main) }
        }
    };
}
