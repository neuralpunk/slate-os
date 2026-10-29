// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real mode (ADR 0089): the loader's entry from the boot sector, which
//! switches to long mode (Intel SDM vol. 3A §9.8, §10.8.5), and the thunk
//! that calls a BIOS interrupt from long mode by going back to real mode
//! and returning (vol. 3A §9.9.2).
//!
//! Low memory while the loader runs:
//!
//! ```text
//! 0x00000-0x004ff  the real-mode interrupt table and the BIOS data area
//! 0x00500-0x00fff  buffers for BIOS calls (`LOW`)
//! 0x01000-0x06fff  the boot page tables: 4 GiB one to one, 2 MiB pages
//! 0x07000-0x07bff  the real-mode stack
//! 0x07c00-0x07dff  the boot sector
//! 0x08000-...      the loader, with its bss (below 0x70000: xtask checks)
//! 0x70000-0x7ffff  free (the other CPUs' trampoline goes here)
//! 0x80000-0x8ffff  the disk buffer (`DISK_BUFFER`)
//! ```

use core::mem::offset_of;

/// A scratch buffer below 1 MiB for BIOS calls, 2.75 KiB.
pub const LOW: usize = 0x500;
pub const LOW_LEN: usize = 0xb00;
/// The disk reads' bounce buffer, 64 KiB.
pub const DISK_BUFFER: usize = 0x8_0000;
pub const DISK_BUFFER_LEN: usize = 0x1_0000;

/// A BIOS call's registers, in and out.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Regs {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eflags: u32,
    pub ds: u16,
    pub es: u16,
    pub int: u32,
}

impl Regs {
    /// The carry flag, which most BIOS calls set on failure.
    pub fn carry(&self) -> bool {
        self.eflags & 1 != 0
    }
}

core::arch::global_asm!(
    ".section .text16, \"ax\"",
    ".code16",
    ".globl slate_bios_entry",
    "slate_bios_entry:",
    "    cli",
    "    xor %ax, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    "    mov $0x7c00, %sp",
    "    mov %dl, boot_drive",
    // A20 through the system control port (fast A20).
    "    in $0x92, %al",
    "    or $2, %al",
    "    and $0xfe, %al",
    "    out %al, $0x92",
    "    lgdtl gdtr",
    "    mov %cr0, %eax",
    "    or $1, %eax",
    "    mov %eax, %cr0",
    "    ljmpl $0x18, $1f",
    ".code32",
    "1:",
    "    mov $0x20, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    // The boot tables at 0x1000: PML4, PDPT, four page directories.
    "    mov $0x1000, %edi",
    "    mov $(6 * 1024), %ecx",
    "    xor %eax, %eax",
    "    rep stosl",
    "    movl $0x2003, 0x1000",
    "    movl $0x3003, 0x2000",
    "    movl $0x4003, 0x2008",
    "    movl $0x5003, 0x2010",
    "    movl $0x6003, 0x2018",
    "    mov $0x3000, %edi",
    "    mov $0x83, %eax",
    "    mov $2048, %ecx",
    "2:",
    "    mov %eax, (%edi)",
    "    add $0x200000, %eax",
    "    add $8, %edi",
    "    loop 2b",
    "    call long_mode",
    "    ljmp $0x28, $3f",
    ".code64",
    "3:",
    "    mov $0x30, %eax",
    "    mov %eax, %ds",
    "    mov %eax, %es",
    "    mov %eax, %ss",
    "    mov %eax, %fs",
    "    mov %eax, %gs",
    "    lea __bss_start(%rip), %rdi",
    "    lea __bss_end(%rip), %rcx",
    "    sub %rdi, %rcx",
    "    xor %eax, %eax",
    "    rep stosb",
    "    lea slate_bios_stack_top(%rip), %rsp",
    "    movzbl boot_drive(%rip), %edi",
    "    call slate_bios_main",
    "4:",
    "    hlt",
    "    jmp 4b",
    // From 32-bit protected mode to long mode: PAE and SSE, the boot
    // tables, long mode and no-execute, paging (with SSE: EM off, MP on).
    ".code32",
    "long_mode:",
    "    mov %cr4, %eax",
    "    or $0x620, %eax",
    "    mov %eax, %cr4",
    "    mov $0x1000, %eax",
    "    mov %eax, %cr3",
    "    mov $0xc0000080, %ecx",
    "    rdmsr",
    "    or $0x900, %eax",
    "    wrmsr",
    "    mov %cr0, %eax",
    "    and $0xfffffffb, %eax",
    "    or $0x80000002, %eax",
    "    mov %eax, %cr0",
    "    ret",
    // slate_bios_int(regs): the System V convention, rdi.
    ".code64",
    ".globl slate_bios_int",
    "slate_bios_int:",
    "    push %rbx",
    "    push %rbp",
    "    push %r12",
    "    push %r13",
    "    push %r14",
    "    push %r15",
    "    mov %rsp, saved_rsp(%rip)",
    "    mov %rdi, saved_regs(%rip)",
    "    mov %rdi, %rsi",
    "    lea regs(%rip), %rdi",
    "    mov ${regs_len}, %ecx",
    "    rep movsb",
    "    mov regs + {int}(%rip), %al",
    "    mov %al, 6f + 1(%rip)",
    // To 32-bit compatibility mode, paging and long mode off, 16-bit
    // protected mode, real mode.
    "    pushq $0x18",
    "    lea 5f(%rip), %rax",
    "    push %rax",
    "    lretq",
    ".code32",
    "5:",
    "    mov $0x20, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    "    mov %cr0, %eax",
    "    and $0x7fffffff, %eax",
    "    mov %eax, %cr0",
    "    mov $0xc0000080, %ecx",
    "    rdmsr",
    "    and $0xfffffeff, %eax",
    "    wrmsr",
    "    ljmp $0x08, $7f",
    ".code16",
    "7:",
    "    mov $0x10, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    "    mov %cr0, %eax",
    "    and $0xfffffffe, %eax",
    "    mov %eax, %cr0",
    "    ljmp $0, $8f",
    "8:",
    "    xor %ax, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %ss",
    "    mov $0x7c00, %sp",
    "    lidtl rm_idtr",
    "    mov regs + {es}, %ax",
    "    mov %ax, %es",
    "    mov regs + {eax}, %eax",
    "    mov regs + {ebx}, %ebx",
    "    mov regs + {ecx}, %ecx",
    "    mov regs + {edx}, %edx",
    "    mov regs + {esi}, %esi",
    "    mov regs + {edi}, %edi",
    "    mov regs + {ebp}, %ebp",
    "    mov regs + {ds}, %ds",
    "    sti",
    "6:",
    "    int $0",
    "    cli",
    "    mov %eax, %cs:regs + {eax}",
    "    mov %ebx, %cs:regs + {ebx}",
    "    mov %ecx, %cs:regs + {ecx}",
    "    mov %edx, %cs:regs + {edx}",
    "    mov %esi, %cs:regs + {esi}",
    "    mov %edi, %cs:regs + {edi}",
    "    mov %ebp, %cs:regs + {ebp}",
    "    mov %ds, %cs:regs + {ds}",
    "    mov %es, %cs:regs + {es}",
    "    pushfl",
    "    popl %cs:regs + {eflags}",
    // Back: protected mode, long mode, the saved stack.
    "    xor %ax, %ax",
    "    mov %ax, %ds",
    "    lgdtl gdtr",
    "    mov %cr0, %eax",
    "    or $1, %eax",
    "    mov %eax, %cr0",
    "    ljmpl $0x18, $9f",
    ".code32",
    "9:",
    "    mov $0x20, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    "    call long_mode",
    "    ljmp $0x28, $10f",
    ".code64",
    "10:",
    "    mov $0x30, %eax",
    "    mov %eax, %ds",
    "    mov %eax, %es",
    "    mov %eax, %ss",
    "    mov %eax, %fs",
    "    mov %eax, %gs",
    "    mov saved_rsp(%rip), %rsp",
    "    lea regs(%rip), %rsi",
    "    mov saved_regs(%rip), %rdi",
    "    mov ${regs_len}, %ecx",
    "    rep movsb",
    "    pop %r15",
    "    pop %r14",
    "    pop %r13",
    "    pop %r12",
    "    pop %rbp",
    "    pop %rbx",
    "    ret",
    ".balign 8",
    // The protocol's GDT (slate_loader::mp::GDT).
    "gdt:",
    "    .quad 0",
    "    .quad 0x00009a000000ffff",
    "    .quad 0x000092000000ffff",
    "    .quad 0x00cf9a000000ffff",
    "    .quad 0x00cf92000000ffff",
    "    .quad 0x00af9a000000ffff",
    "    .quad 0x00cf92000000ffff",
    "gdtr:",
    "    .word 7 * 8 - 1",
    "    .long gdt",
    "rm_idtr:",
    "    .word 0x3ff",
    "    .long 0",
    ".balign 8",
    "saved_rsp: .quad 0",
    "saved_regs: .quad 0",
    "regs: .fill {regs_len}, 1, 0",
    ".globl boot_drive",
    "boot_drive: .byte 0",
    regs_len = const core::mem::size_of::<Regs>(),
    eax = const offset_of!(Regs, eax),
    ebx = const offset_of!(Regs, ebx),
    ecx = const offset_of!(Regs, ecx),
    edx = const offset_of!(Regs, edx),
    esi = const offset_of!(Regs, esi),
    edi = const offset_of!(Regs, edi),
    ebp = const offset_of!(Regs, ebp),
    eflags = const offset_of!(Regs, eflags),
    ds = const offset_of!(Regs, ds),
    es = const offset_of!(Regs, es),
    int = const offset_of!(Regs, int),
    options(att_syntax),
);

unsafe extern "sysv64" {
    fn slate_bios_int(regs: *mut Regs);
}

/// Call BIOS interrupt `int` with `regs`, which come back as the BIOS left
/// them. Pointers in them are real-mode segment and offset; the buffers
/// must be below 1 MiB (`LOW`, `DISK_BUFFER`).
pub fn int(int: u8, mut regs: Regs) -> Regs {
    regs.int = u32::from(int);
    // SAFETY: The thunk saves the long-mode state and comes back to it;
    // the BIOS runs in real mode with its own interrupt table, on the
    // real-mode stack, and touches only the memory the call names.
    unsafe { slate_bios_int(&mut regs) };
    regs
}

/// Real-mode segment and offset of a low address.
pub fn far(addr: usize) -> (u16, u16) {
    ((addr >> 4) as u16, (addr & 0xf) as u16)
}
