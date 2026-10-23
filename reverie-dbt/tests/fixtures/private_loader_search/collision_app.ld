ENTRY(_start)
PHDRS {
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
  occupied PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
  . = 0x400000 + SIZEOF_HEADERS;
  .text : { *(.text.start) *(.text .text.*) } :text
  .rodata : { *(.rodata .rodata.*) } :text
  . = 0x40000000;
  .occupied : { KEEP(*(.occupied)) } :occupied
  /DISCARD/ : { *(.comment) *(.note*) }
}
