.PHONY: clean all inspect

TARGET ?= riscv64imac-unknown-none-elf
PREFIX ?= riscv64-unknown-elf-

SRCS=$(shell find src -type f -name '*.rs')

all: firmware.bin

target/$(TARGET)/release/libfirmware.a: $(SRCS) firmware.ld
	cargo rustc --target $(TARGET) --release

target/$(TARGET)/debug/libfirmware.a: $(SRCS) firmware.ld
	cargo rustc --target $(TARGET)

env.o: env.S
	$(PREFIX)as -march=rv64imac -o env.o env.S

rip/rip.o: rip/rip.cpp
	$(PREFIX)g++ -march=rv64gc -c -nostdlib -o rip/rip.o rip/rip.cpp

firmware.o: target/$(TARGET)/release/libfirmware.a env.o rip/rip.o
	$(PREFIX)ld -T firmware.ld env.o target/$(TARGET)/release/libfirmware.a rip/rip.o -o firmware.o

firmware.bin: firmware.o
	$(PREFIX)objcopy -O binary $< $@
	# ./modifier $@

firmware.hex: firmware.bin
	hexdump -ve '1/1 "%02x" "\n"' firmware.bin > firmware.hex

clean:
	cargo clean
	rm -f *.coe *.bin *.o *.hex

inspect: firmware.o
	riscv64-linux-gnu-objdump -D firmware.o

# modifier: util/modifier.c
#	$(CC) util/modifier.c -o modifier -g
