/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* Higher-half kernel image for the Limine boot protocol; see docs/adr/0002. */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kernel_entry)

PHDRS
{
    limine_requests PT_LOAD;
    text            PT_LOAD;
    rodata          PT_LOAD;
    data            PT_LOAD;
    note            PT_NOTE;
    dynamic         PT_DYNAMIC;
}

SECTIONS
{
    /* Top 2 GiB of the address space: required by -C code-model=kernel.
       The kernel is position-independent: the bootloader moves it within
       the top 2 GiB and applies its relative relocations (KASLR, ADR
       0095), found through PT_DYNAMIC. */
    . = 0xffffffff80000000;
    __kernel_start = .;

    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :limine_requests

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
    } :rodata

    /* The kernel's Slate note (ADR 0086), also a PT_NOTE for readers. */
    .note.slate : ALIGN(4) {
        KEEP(*(.note.slate))
    } :rodata :note

    /* What a position-independent executable carries for its loader. */
    .dynsym : { *(.dynsym) } :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash : { *(.hash) } :rodata
    .dynstr : { *(.dynstr) } :rodata
    .rela.dyn : { *(.rela.dyn) } :rodata

    /* KCFI's checks (ADR 0096): a 32-bit offset to each check's trap. */
    .kcfi_traps : ALIGN(4) {
        __kcfi_traps_start = .;
        KEEP(*(.kcfi_traps))
        __kcfi_traps_end = .;
    } :rodata

    /* Exception table: (instruction, fixup) pairs; see arch/x86_64/extable.rs. */
    .slate_extable : ALIGN(8) {
        __extable_start = .;
        KEEP(*(.slate_extable))
        __extable_end = .;
        __rodata_end = .;
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data : {
        __data_start = .;
        *(.data .data.*)
    } :data

    .dynamic : { *(.dynamic) } :data :dynamic
    .got : { *(.got) *(.got.plt) } :data

    .bss : {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note .note.*)
    }
}
