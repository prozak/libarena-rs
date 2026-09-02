# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
# Convenience wrapper: the objects come from `cargo bpf --examples` (see
# .cargo/config.toml); this builds the linker and the runner and runs the
# examples on a kernel.
#
#   make              linker + examples + runner
#   make test         run every example object on this kernel (sudo for the runner)
#   make test-vng KERNEL_BZIMAGE=/path/to/bzImage
#
# Environment for the build (see README): LLVM_PREFIX, LIBARENA_VMLINUX_H,
# LIBBPF_INCLUDE, BPF_STREAM_KFUNC, TRAP_MODE, VOID_GLOBALS, ...
-include local.mk
export LLVM_PREFIX LIBARENA_VMLINUX_H LIBBPF_INCLUDE BPF_STREAM_KFUNC TRAP_MODE VOID_GLOBALS
export RUSTC_BOOTSTRAP = 1

LIBBPF_INCLUDE ?= $(shell pkg-config --variable=includedir libbpf 2>/dev/null || echo /usr/include)
LIBBPF_LIBS    ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)
VNG            ?= vng
KERNEL_BZIMAGE ?=
RUNNER_ARGS    ?=
SUDO           ?= $(shell test $$(id -u) -eq 0 || echo sudo)

OBJ_DIR := target/bpfel-unknown-none-v4/release/examples
OBJS    := $(patsubst examples/%.rs,$(OBJ_DIR)/%,$(wildcard examples/*.rs))
LINKER  := target/release/arena-linker
RUNNER  := target/arena-runner

all: $(OBJS) $(RUNNER)

$(LINKER): $(wildcard linker/src/*.rs linker/scripts/*.py) linker/Cargo.toml
	cargo build --release -q -p arena-linker

.PHONY: examples
examples $(OBJS): $(LINKER)
	PATH="$(CURDIR)/target/release:$$PATH" cargo bpf --examples

$(RUNNER): tools/runner/runner.c
	@mkdir -p target
	$(CC) -O2 -o $@ $< -I$(LIBBPF_INCLUDE) $(LIBBPF_LIBS)

test: all
	@for o in $(OBJS); do $(SUDO) $(RUNNER) $(RUNNER_ARGS) $$o || exit 1; done

test-vng: all
	@test -n "$(KERNEL_BZIMAGE)" || { echo "set KERNEL_BZIMAGE=/path/to/bzImage"; exit 1; }
	$(VNG) --run $(KERNEL_BZIMAGE) --cpus 2 --memory 2G --rw -- \
		'cd $(CURDIR) && for o in $(OBJS); do $(RUNNER) $(RUNNER_ARGS) $$o || exit 1; done'

clean:
	cargo clean

.PHONY: all test test-vng clean
