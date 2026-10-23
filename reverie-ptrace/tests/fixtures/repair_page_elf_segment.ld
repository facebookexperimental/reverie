/* Links repair_page_elf_segment.S with its data segment at 0x71001000. */
ENTRY(_start)
PHDRS
{
  code PT_LOAD FILEHDR PHDRS FLAGS(5);
  guest PT_LOAD FLAGS(6);
  stack PT_GNU_STACK FLAGS(6);
}
SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;
  .text : { *(.text*) *(.rodata*) } :code
  . = 0x71001000;
  .guest : { *(.guest) } :guest
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
