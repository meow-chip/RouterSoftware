.section .text
.globl _rst_vec
_rst_vec:
  # Read Hart ID, use it as the only argument sent to the bootloader
  csrrs a0, mhartid, zero

  # Setup mtvec
  la t0, _trap_vec
  csrrw zero, mtvec, t0

  # Set sp to the end of RAM
  la sp, _stack_start

  # Jump to _start
  j _start

_trap_vec:
  csrrs a0, mepc, zero
  csrrs a1, mcause, zero
  csrrs a2, mtval, zero
  j _trap
