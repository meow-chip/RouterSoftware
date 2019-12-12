MEMORY {
  FLASH(RX) : ORIGIN = 0xFFFF20000000, LENGTH = 8M
  RAM(RWX) : ORIGIN = 0x0, LENGTH = 8M
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);

ENTRY(_rst_vec)

SECTIONS {
  .text : {
    . = 0x0;
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
