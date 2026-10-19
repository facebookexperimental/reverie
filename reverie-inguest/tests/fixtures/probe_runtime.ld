/* Mapping contract: parent owns these fixed pages and zeroes BSS. The actual
 * ELF validator must additionally prove W^X, gate-only syscall bytes and the
 * fixture's no-TLS policy; this layout is not an ownership/adoption proof. */
ENTRY(probe_runtime_start)
PHDRS {
  gate PT_LOAD FLAGS(5);
  text PT_LOAD FLAGS(5);
  data PT_LOAD FLAGS(6);
}
SECTIONS {
  . = 0x6000e1000000;
  .gate : { KEEP(*(.gate)) } :gate
  ASSERT(SIZEOF(.gate) <= 4096, "runtime gate exceeds its page")
  . = ALIGN(4096);
  .text : { *(.text .text.*) *(.rodata .rodata.*) } :text
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.got .got.*) } :data
  .bss (NOLOAD) : { *(.bss .bss.*) *(COMMON) } :data
  ASSERT(. <= 0x6000ff000000, "runtime exceeds its window")
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
