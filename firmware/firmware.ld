MEMORY {
  RAM : ORIGIN = 0x0, LENGTH = 8M
  FLASH: ORIGIN = 0xFFFF20000000, LENGTH = 8M
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);

ENTRY(_start)

SECTIONS {
  .text : {
    . = 0xFFFF20000000;
    *.(.text .text.*);
  } > FLASH

  .rodata : {
    *.(.rodata .rodata.*);
  } > FLASH

  /DISCARD/ : {
    *(.debug_* .debug_*.*);
    *(.comment .comment.*);
  }
}
