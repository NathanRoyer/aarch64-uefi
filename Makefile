PWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
ROOT := $(PWD)/build/root
UEFI_APP := $(ROOT)/app
UEFI := $(PWD)/uefi
BUILD_STD := -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem
QEMU_FLAGS := -machine virt -cpu cortex-a72 -smp 4 \
	-drive if=pflash,format=raw,file=$(PWD)/qemu_efi.fd \
	-drive file=fat:rw:$(ROOT) \
	-m 1024 \
	-net none# -nographic

.PHONY: clean default build boot.efi run

default: build

boot.efi:

build: boot.efi
	cargo +nightly-2022-07-25 build --manifest-path $(UEFI)/Cargo.toml --release --target aarch64-unknown-uefi $(BUILD_STD)
	mkdir -p $(ROOT)
	cp $(PWD)/target/aarch64-unknown-uefi/release/uefi.efi $(UEFI_APP)

clippy:
	cargo clippy --manifest-path $(UEFI)/Cargo.toml --release --target aarch64-unknown-uefi $(BUILD_STD)

run: build
	qemu-system-aarch64 $(QEMU_FLAGS)
		
debug: build
	qemu-system-aarch64 $(QEMU_FLAGS) -s

clean:
	rm -rf $(PWD)/build
	cargo clean
