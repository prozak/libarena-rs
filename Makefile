# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
# Builds the example programs under examples/progs and the runner.
#
#   make                  build examples/progs/*.rs -> bld/*.bpf.o
#   make test             run every object on this kernel (needs root; kernel >= 6.17)
#   make test-vng KERNEL_BZIMAGE=/path/to/bzImage   run inside a virtme-ng guest
#
# Toolchain inputs: see mk/libarena.mk (LLVM_PREFIX, RUSTC, VMLINUX_H, ...).

BPF_PROGS_DIR := examples/progs
-include local.mk
include mk/libarena.mk

RUNNER      := $(LIBARENA_RS_BLD)/arena-runner
RUNNER_ARGS ?=
VNG         ?= vng
KERNEL_BZIMAGE ?=

all: $(LIBARENA_RS_PROG_OBJS) $(RUNNER)

test: all
	@for o in $(LIBARENA_RS_PROG_OBJS); do $(RUNNER) $(RUNNER_ARGS) $$o || exit 1; done

test-vng: all
	@test -n "$(KERNEL_BZIMAGE)" || { echo "set KERNEL_BZIMAGE=/path/to/bzImage"; exit 1; }
	$(VNG) --run $(KERNEL_BZIMAGE) --cpus 2 --memory 2G --rw -- \
		'cd $(CURDIR) && for o in $(LIBARENA_RS_PROG_OBJS); do $(RUNNER) $(RUNNER_ARGS) $$o || exit 1; done'

check-toolchain: libarena-rs-check-toolchain
clean: libarena-rs-clean
distclean: libarena-rs-distclean

.PHONY: all test test-vng check-toolchain clean distclean
