/* SPDX-License-Identifier: MIT OR Apache-2.0 */
/* The vDSO's layout (ADR 0014; M31): one loadable segment, read and
   execute, from the file's start, holding everything, the dynamic section
   too; the DYNAMIC header read-only. A C library reads the DYNAMIC
   header's flags to know whether it may relocate the section in place
   (glibc's static PIEs do when it says writable), and the vDSO is mapped
   read-only. Observed: the host's own vDSO is laid out this way. The
   syntax is the GNU ld manual's ("PHDRS Command"), which lld follows. */
PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(4);
    eh_frame_hdr PT_GNU_EH_FRAME FLAGS(4);
}

SECTIONS
{
    . = SIZEOF_HEADERS;
    .hash : { *(.hash) } :text
    .gnu.hash : { *(.gnu.hash) } :text
    .dynsym : { *(.dynsym) } :text
    .dynstr : { *(.dynstr) } :text
    .gnu.version : { *(.gnu.version) } :text
    .gnu.version_d : { *(.gnu.version_d) } :text
    .gnu.version_r : { *(.gnu.version_r) } :text
    .dynamic : { *(.dynamic) } :text :dynamic
    .rodata : { *(.rodata .rodata.*) } :text
    .eh_frame_hdr : { *(.eh_frame_hdr) } :text :eh_frame_hdr
    .eh_frame : { KEEP(*(.eh_frame)) } :text
    .text : { *(.text .text.*) } :text
    .got : { *(.got .got.plt) } :text
    .data : { *(.data .data.* .bss .bss.*) } :text
    /DISCARD/ : { *(.comment .note .note.*) }
}
