ENTRY(_start)
PHDRS {
  headers PT_PHDR PHDRS;
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
  data PT_LOAD FLAGS(6);
}
SECTIONS {
  . = 0x400000 + SIZEOF_HEADERS;
  .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
  .rodata : { *(.rodata .rodata.*) } :text
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.got .got.*) } :data
  .bss : { *(.bss .bss.*) *(COMMON) } :data
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) }
}
