/* Relocation-free ET_DYN interpreter. The Rust qualifier patches ONLY the
 * last PT_LOAD p_memsz to the exact held-loader envelope (and validated p_align
 * values if needed), before installing the private seed inode. The active source image is never padded
 * to an arbitrary reservation size. No dynamic loader runs for this image.
 */
ENTRY(seed_bootstrap_entry)
PHDRS {
    code PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    seed_image_start = 0;
    . = SIZEOF_HEADERS;
    .text : { *(.text*) } :code
    /* ELF string tables must have their own output section: the linker
     * writes their required leading NUL, which must not overwrite a constant. */
    .rodata : { *(.rodata*) } :code
    .dynsym : { *(.dynsym) } :code
    .dynstr : { *(.dynstr) } :code
    .hash : { *(.hash) } :code
    .gnu.hash : { *(.gnu.hash) } :code
    /* There is intentionally no PT_DYNAMIC consumer. Do not silently retain
     * a compiler-generated pointer that would need an ELF relocation. */
    .rela.dyn : { *(.rela*) } :code
    .rel.dyn : { *(.rel.*) *(.rel) } :code
    .relr.dyn : { *(.relr*) } :code
    ASSERT(SIZEOF(.rela.dyn) == 0, "seed must not require RELA relocations")
    ASSERT(SIZEOF(.rel.dyn) == 0, "seed must not require REL relocations")
    ASSERT(SIZEOF(.relr.dyn) == 0, "seed must not require RELR relocations")
    . = ALIGN(0x1000);
    seed_code_end = .;
    seed_data_start = .;
    .data : { *(.data*) *(.dynamic) *(.got*) } :data
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } :data
    . = ALIGN(0x1000);
    seed_image_active_end = .;
    ASSERT(seed_image_active_end <= 0x80000, "seed active image exceeds scratch band")
    /* The final noreturn assembly clears every writable byte except its saved
     * frame and sole loader-entry word, then consumes and clears the frame. */
    ASSERT(seed_data_start == seed_code_end, "seed writable start differs from code end")
    ASSERT((seed_data_start & 0xfff) == 0 && (seed_image_active_end & 0xfff) == 0,
           "seed scrub bounds must be page aligned")
    ASSERT(seed_data_start <= seed_frame, "seed frame precedes writable storage")
    ASSERT((seed_frame & 7) == 0 && (seed_transfer_entry & 7) == 0,
           "seed frame and loader-entry word must be aligned")
    ASSERT(seed_frame + 136 <= seed_stack, "seed frame overlaps its C stack")
    ASSERT(seed_stack < seed_stack_end && seed_stack_end <= seed_transfer_entry,
           "seed C stack overlaps its loader-entry word")
    ASSERT(seed_transfer_entry + 8 <= seed_image_active_end,
           "seed loader-entry word exceeds writable storage")
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
