/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* slate-loader's boot sector (ADR 0089): the BIOS loads it at 0x7C00. */
ENTRY(slate_mbr_start)
SECTIONS
{
    . = 0x7c00;
    .boot : { KEEP(*(.boot)) }
    /DISCARD/ : { *(.text .text.*) *(.rodata .rodata.*) *(.data .data.*) *(.bss .bss.*) *(.eh_frame*) *(.comment) }
}
