/* ET_EXEC bootstrap interpreter; no TLS, dynamic relocations or executable RW.
 * --defsym=GATE_PAGE=0x500000000000; wrong-page negative stays a real refusal.
 */
ENTRY(_start)
PHDRS {
    gate PT_LOAD FLAGS(5);
    code PT_LOAD FLAGS(5);
    locator PT_LOAD FLAGS(6);
    data PT_LOAD FLAGS(6);
    stack PT_GNU_STACK FLAGS(6);
}
SECTIONS {
    . = GATE_PAGE;
    .gate : { KEEP(*(.gate)) } :gate
    ASSERT(SIZEOF(.gate) == 0x1000, "exact fixed gate page")
    . = GATE_PAGE + 0x10000;
    private_boot_code_start = .;
    .text : { *(.text*) *(.rodata*) } :code
    private_boot_code_end = .;
    ASSERT(. < GATE_PAGE + 0x20000, "bootstrap code exceeds code band")
    . = GATE_PAGE + 0x20000;
    .locator (NOLOAD) : { KEEP(*(.locator)) } :locator
    . = ALIGN(0x1000);
    private_boot_data_start = .;
    .data : { *(.data*) } :data
    .bss (NOLOAD) : { *(.bss*) *(COMMON) } :data
    private_boot_data_end = .;
    ASSERT(. <= GATE_PAGE + 0x80000, "bootstrap data exceeds owned band")
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
