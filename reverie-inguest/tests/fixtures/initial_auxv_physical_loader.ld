/* Test-only ET_DYN interpreter. The RW tail fits the real seed's reservation. */
ENTRY(_start)
PHDRS {
  code PT_LOAD FILEHDR PHDRS FLAGS(5);
  data PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
  . = SIZEOF_HEADERS;
  .text : { *(.text .text.*) } :code
  .rodata : { *(.rodata .rodata.*) } :code
  .dynsym : { *(.dynsym) } :code
  .dynstr : { *(.dynstr) } :code
  .hash : { *(.hash) *(.gnu.hash) } :code
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.dynamic) *(.got .got.*) } :data
  .bss : { *(.bss .bss.*) *(COMMON) . = ALIGN(4096); . += 0x80000; } :data
  ASSERT(initial_auxv_fixture_frame + 136 <= initial_auxv_fixture_fp,
         "fixture entry frame overlaps FP snapshot")
  ASSERT(initial_auxv_fixture_fp + 512 <= initial_auxv_fixture_stack,
         "fixture FP snapshot overlaps private fixture stack")
  ASSERT((initial_auxv_fixture_fp & 15) == 0,
         "fixture FXSAVE snapshot must be 16-byte aligned")
  ASSERT(initial_auxv_fixture_stack < initial_auxv_fixture_stack_end,
         "fixture private stack is empty")
  ASSERT((initial_auxv_fixture_stack_end & 15) == 0,
         "fixture C entry stack must be 16-byte aligned")
  /DISCARD/ : { *(.comment) *(.eh_frame*) *(.note*) }
}
