MEMORY {
  FLASH(RX) : ORIGIN = 0xFFFF20000000, LENGTH = 8M
  RAM(RWX) : ORIGIN = 0x0, LENGTH = 4M
  CUCKOO(RW) : ORIGIN = 0x400000, LENGTH = 4M
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);
_cuckoo = ORIGIN(CUCKOO);

ENTRY(_rst_vec)

SECTIONS {
  .text : {
    . = 0x0;
    *.(.text .text.*);
  } > FLASH

  .rodata : {
    *.(.rodata .rodata.*);
  } > FLASH

  .data : {
    . = 0x0;
    *.(.sdata .sdata.*);
  } > RAM

  .bss : {
    *.(.sbss .sbss.*);
  } > RAM

  /DISCARD/ : {
    *(.debug_* .debug_*.*);
    *(.comment .comment.*);
  }
}
