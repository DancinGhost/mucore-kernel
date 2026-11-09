/* ============================================================================
 * μCore (mucore-kernel) — Higher-Half x86_64 ELF64 Linker Script
 * ============================================================================
 * Enforces "No Hidden Mechanisms" at Link Time:
 *   Any accidental C++ global constructor (`.init_array` / `.ctors`) or
 *   exception unwinding table (`.eh_frame`) fails or is stripped cleanly.
 * ============================================================================ */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5); /* R + X */
    rodata PT_LOAD FLAGS(4); /* R     */
    data   PT_LOAD FLAGS(6); /* R + W */
}

SECTIONS {
    /* Standard x86_64 -mcmodel=kernel higher-half virtual base (-2 GiB) */
    . = 0xffffffff80000000;

    .text ALIGN(4K) : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    } :text

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    } :rodata

    /* Catch hidden static C++ constructors at link time! */
    .init_array : {
        __init_array_start = .;
        *(.init_array .init_array.* .ctors .ctors.*)
        __init_array_end = .;
    } :rodata
    ASSERT(__init_array_end == __init_array_start,
           "VIOLATION: Hidden global C++ constructors (.init_array) are forbidden in mucore-kernel!")

    .data ALIGN(4K) : {
        KEEP(*(.limine_requests))
        *(.data .data.*)
    } :data

    .bss ALIGN(4K) : {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
    }
}
