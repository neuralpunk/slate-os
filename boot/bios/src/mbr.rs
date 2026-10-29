// SPDX-License-Identifier: MIT OR Apache-2.0

//! slate-loader's boot sector (ADR 0089). The BIOS loads it at 0x7C00 and
//! jumps to it with the drive in DL. It reads the loader from the disk
//! with the BIOS's extended read (INT 13h AH=42h, the EDD specification)
//! to 0x8000 and jumps there, the drive in DL again.
//!
//! The installer fills in where the loader is: its byte offset on the disk
//! (u64 at 0x1A4) and its length in sectors (u16 at 0x1AC). The code stays
//! clear of bytes 218 to 223 (a disk timestamp some systems keep) and of
//! 440 to 509 (the disk signature and the partition table), which the
//! installer keeps from the disk (xtask checks that the code ends before
//! byte 218).

#![no_std]
#![no_main]

core::arch::global_asm!(
    ".section .boot, \"ax\"",
    ".code16",
    ".globl slate_mbr_start",
    "slate_mbr_start:",
    "    cli",
    "    xor %ax, %ax",
    "    mov %ax, %ds",
    "    mov %ax, %es",
    "    mov %ax, %ss",
    "    mov $0x7c00, %sp",
    "    ljmp $0, $1f",
    "1:",
    "    sti",
    "    mov %dl, drive",
    // Extended reads there?
    "    mov $0x41, %ah",
    "    mov $0x55aa, %bx",
    "    int $0x13",
    "    jc fail",
    "    cmp $0xaa55, %bx",
    "    jne fail",
    // The first sector: the byte offset over 512.
    "    mov 0x7c00 + 0x1a4, %eax",
    "    mov 0x7c00 + 0x1a8, %edx",
    "    shrd $9, %edx, %eax",
    "    shr $9, %edx",
    "    mov %eax, dap + 8",
    "    mov %edx, dap + 12",
    "    mov 0x7c00 + 0x1ac, %cx",
    "    movw $0x0800, dap + 6",
    "2:",
    "    mov %cx, %bx",
    "    cmp $64, %bx",
    "    jbe 3f",
    "    mov $64, %bx",
    "3:",
    "    mov %bx, dap + 2",
    "    mov $0x42, %ah",
    "    mov drive, %dl",
    "    mov $dap, %si",
    "    push %cx",
    "    push %bx",
    "    int $0x13",
    "    pop %bx",
    "    pop %cx",
    "    jc fail",
    // 32 paragraphs a sector.
    "    mov %bx, %ax",
    "    shl $5, %ax",
    "    add %ax, dap + 6",
    "    movzx %bx, %eax",
    "    add %eax, dap + 8",
    "    adcl $0, dap + 12",
    "    sub %bx, %cx",
    "    jnz 2b",
    "    mov drive, %dl",
    "    ljmp $0, $0x8000",
    "fail:",
    "    mov $msg, %si",
    "4:",
    "    lodsb",
    "    test %al, %al",
    "    jz 5f",
    "    mov $0x0e, %ah",
    "    mov $7, %bx",
    "    int $0x10",
    "    jmp 4b",
    "5:",
    "    hlt",
    "    jmp 5b",
    "msg: .asciz \"Slate: cannot read the disk\"",
    "drive: .byte 0",
    ".balign 4",
    // The disk address packet (EDD 3.0 §3.1.2): size, count, buffer, LBA.
    "dap: .byte 16, 0",
    "    .word 0, 0, 0",
    "    .quad 0",
    ".org 0x1a4",
    "    .quad 0",
    "    .word 0",
    ".org 0x1fe",
    "    .byte 0x55, 0xaa",
    options(att_syntax),
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
