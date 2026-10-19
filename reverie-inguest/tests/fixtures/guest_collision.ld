ENTRY(_start)
PHDRS {
  headers PT_PHDR PHDRS;
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
}
SECTIONS {
  . = 0x600000000000 + SIZEOF_HEADERS;
  .text : { KEEP(*(.text.entry)) *(.text .text.*) } :text
  .rodata : { *(.rodata .rodata.*) } :text
  /DISCARD/ : { *(.eh_frame*) *(.note*) *(.comment) *(.data*) *(.bss*) *(.got*) }
}
