# Sorabbyngo Cyberwall — eBPF Makefile
# Compiles bpf_program.c to bpf_program.o for use with libbpf
#
# Requirements:
#   sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)

CLANG    ?= clang
LLC      ?= llc
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_VER ?= $(shell uname -r)
KERN_INC  = /usr/src/linux-headers-$(KERN_VER)/include

BPF_CFLAGS = \
    -g -O2 -target bpf \
    -D__TARGET_ARCH_$(ARCH) \
    -I$(KERN_INC) \
    -I/usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean

all: bpf_program.o

bpf_program.o: bpf_program.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[cyberwall] eBPF program compiled: $@"

clean:
	rm -f bpf_program.o

verify: bpf_program.o
	llvm-objdump -S bpf_program.o | head -60
