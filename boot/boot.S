.section .text
j _start
printloop:
  sb t0, 4(s0)
  addi a0, a0, 1
print:
  lb t0, 0(a0)
  bne t0, zero, printloop
  ret

printdec:
  li t0, 0
  li t2, 10
loop1:
  rem t1, a0, t2
  div a0, a0, t2
  addi t1, t1, 0x30
  sb t1, 0(t0)
  addi t0, t0, 1
  bne a0, zero, loop1
loop2:
  lb t1, 0(t0)
  sb t1, 4(s0)
  addi t0, t0, -1
  bge t0, zero, loop2
  ret

.globl _start
_start:
  li s0, 0xFFFFF0000000 # Serial
  li s1, 0xFFFFF3000000 # Flash

  la a0, bootmsg
  call print

  # Load data from flash into memory.
  # First 4 bytes in flash should be length

  ld a0, 0(s1)
  mv a1, a0
  call printdec

  mv a0, a1
  li t0, 0
loadloop:
  add t1, t0, s1
  ld t2, 0(t1)
  sd t2, 0(t0)
  addi t0, t0, 4
  bltu t0, a0, loadloop

  li a0, 0x1000 # Skips zero page
  jr a0

bootmsg:
  .string "BOOT\n\r"
