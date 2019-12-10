.PHONY: clean all inspect

TARGET ?= riscv64imac-unknown-none-elf
PREFIX ?= riscv64-linux-gnu-

SRCS=$(shell find src -type f -name '*.rs')

all: firmware.bin

target/$(TARGET)/release/firmware: $(SRCS) firmware.ld
	cargo rustc --target $(TARGET) --release -- -C link-arg=-Tfirmware.ld

clean:
	cargo clean
	rm -f *.coe *.bin

inspect: target/$(TARGET)/release/firmware
	riscv64-linux-gnu-objdump -D target/$(TARGET)/release/firmware

firmware.bin: target/$(TARGET)/release/firmware modifier
	$(PREFIX)objcopy -O binary $< $@
	# ./modifier $@

modifier: util/modifier.c
	$(CC) util/modifier.c -o modifier -g
