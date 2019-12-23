RouterSoftware
--------------

> Warm kitty, soft kitty, little ball of fur.

This repository contains software source code for the [MeowRouter](https://github.com/meow-chip/MeowRouter).

## Authors

See `AUTHORS` file

## Build

In order to build the firmware, you will need to install the RISC-V toolchain, and rust nightly (with target `riscv64imac-unknown-none-elf` at least).

Then you can just:

```
cd firmware
make
```

Then a `firmware.o` and an `firmware.bin` will be generated at your PWD, which is the ELF and the raw binary.

To show the disassembly, use:

```
make inspect | less
```

## License
All code under this repository is released under the MIT license. See `LICENSE` file.
