.section .text
.globl _rst_vec
_rst_vec:
  # Read Hart ID, use it as the only argument sent to the bootloader
  csrrs a0, mhartid, zero

  # Set sp to the end of RAM
  la sp, _stack_start

  # Jump to _start
  j _start

  # TODO: setup mtvec
