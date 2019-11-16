MEMORY {
  RAM : ORIGIN = 0x0, LENGTH = 8M
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);

ENTRY(_start)

SECTIONS {
  .vector_table ORIGIN(RAM) : {
    QUAD(LENGTH(RAM));
  } > RAM

  .text : {
    . = 0x1000;
    *.(.text .text.*);
  } > RAM

  .rodata : {
    *.(.rodata .rodata.*);
  } > RAM

  /DISCARD/ : {
    *(.debug_* .debug_*.*);
    *(.comment .comment.*);
  }
}
