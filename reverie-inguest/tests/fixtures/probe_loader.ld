/* Mapping contract: parent owns these fixed pages before replacement. The
 * actual ELF validator, not this script alone, establishes RX/W^X and the gate
 * opcode boundary. No guest entry transfer or runtime state is defined here. */
ENTRY(_start)
PHDRS {
  gate PT_LOAD FLAGS(5);
  text PT_LOAD FLAGS(5);
}
SECTIONS {
  . = 0x6000e0000000;
  .gate : { KEEP(*(.gate)) } :gate
  ASSERT(SIZEOF(.gate) <= 0x100, "loader gate overlaps fixed ready marker")
  . = 0x6000e0000100;
  .ready : { KEEP(*(.ready)) } :gate
  ASSERT(SIZEOF(.ready) == 3, "ready marker must be int3;ud2")
  . = 0x6000e0001000;
  .text : { *(.text .text.*) *(.rodata .rodata.*) } :text
  ASSERT(. <= 0x6000e1000000, "loader exceeds its window")
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) *(.data*) *(.bss*) }
}
