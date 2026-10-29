/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-loader for BIOS (ADR 0089), loaded at 0x8000 by the boot sector.
   The 16-bit entry and the BIOS thunk come first, inside the first 64 KiB
   of the address space, where real-mode code can reach them. */
ENTRY(slate_bios_entry)
SECTIONS
{
    . = 0x8000;
    .text16 : { KEEP(*(.text16)) }
    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    __stage2_file_end = .;
    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        /* The loader's first stack, 16 KiB, until its memory is set up
           (it then moves to a larger one, boot/bios/src/main.rs). */
        . = ALIGN(16);
        . += 0x4000;
        slate_bios_stack_top = .;
        __bss_end = .;
    }
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
