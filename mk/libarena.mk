# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
#
# libarena-rs build pipeline. Include this from your own Makefile:
#
#     LIBARENA_RS := vendor/libarena-rs
#     include $(LIBARENA_RS)/mk/libarena.mk
#     all: $(LIBARENA_RS_PROG_OBJS) $(LIBARENA_RS_BLD)/arena-runner
#
# Every progs/<name>.rs becomes bld/<name>.bpf.o. Per object:
#   clang   libarena {common,buddy}.bpf.c + csrc/arena_glue.bpf.c  -> .bc
#   rustc   panic=immediate-abort libcore/liballoc (once per rustc) -> rlibs
#   rustc   libarena-rs crate                                      -> rlib + CGUs
#   rustc   progs/<name>.rs                                        -> .bc
#   llvm-link  prog + arena + crate, then --only-needed core/alloc, + __multi3
#   PRE_INTERNALIZE_PASSES (lower_mem.py) ; opt internalize+globaldce
#   force_inline.py ; opt always-inline + O2 ; POST_O2_PASSES
#   add_ksyms.py (trap -> bpf_throw, .ksyms) ; llc -mcpu=v4 ; btf_rename.py
#
# Inputs you may have to set (all `?=`; see `make libarena-rs-check-toolchain`):
#   LLVM_PREFIX     LLVM >= the LLVM bundled with your rustc, with the BPF
#                   backend (any official release tarball). Default: llvm-config.
#   RUSTC           rustc 1.96+ (RUSTC_BOOTSTRAP=1 is exported) with rust-src.
#   VMLINUX_H       generated from /sys/kernel/btf/vmlinux by default (needs
#                   bpftool); or point at an existing vmlinux.h.
#   LIBBPF_INCLUDE  directory containing bpf/bpf_helpers.h (libbpf-dev).
#   LIBBPF_LIBS     link flags for the runner (default: pkg-config libbpf).

LIBARENA_RS := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
_lrs_default_goal := $(.DEFAULT_GOAL)

# ---- toolchain ----
LLVM_PREFIX    ?= $(shell llvm-config --prefix 2>/dev/null)
RUSTC          ?= rustc
RUST_SRC       ?= $(shell $(RUSTC) --print sysroot)/lib/rustlib/src/rust/library
RUSTBPF        ?= $(LIBARENA_RS)/vendor/rust-bpf
BPF_TARGET_JSON ?= $(RUSTBPF)/bpfel-unknown-none-v4.json
LIBARENA_SRC   ?= $(LIBARENA_RS)/vendor/libarena/libarena
CC             ?= cc
BPFTOOL        ?= bpftool
VMLINUX_BTF    ?= /sys/kernel/btf/vmlinux
LIBBPF_INCLUDE ?= $(shell pkg-config --variable=includedir libbpf 2>/dev/null || echo /usr/include)
LIBBPF_LIBS    ?= $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf -lelf -lz)

ifeq ($(filter clean distclean libarena-rs-clean libarena-rs-distclean,$(MAKECMDGOALS)),)
ifeq ($(shell command -v $(RUSTC) 2>/dev/null),)
$(error rustc not found (RUSTC=$(RUSTC)); if running under sudo, build as your user: `make test` only elevates the runner)
endif
endif

# ---- layout ----
LIBARENA_RS_BLD  ?= $(CURDIR)/bld
BPF_PROGS_DIR    ?= progs
VMLINUX_H        ?= $(LIBARENA_RS_BLD)/vmlinux.h
_lrs_rustc_hash  := $(shell $(RUSTC) -vV 2>/dev/null | sed -n 's/^commit-hash: \(.\{9\}\).*/\1/p')
LIBARENA_RS_DEPS ?= $(LIBARENA_RS_BLD)/deps-$(if $(_lrs_rustc_hash),$(_lrs_rustc_hash),unknown)

# ---- knobs ----
BPF_CPU              ?= v4
BPF_ARCH_DEFINE      ?= $(if $(filter aarch64 arm64,$(shell uname -m)),-D__TARGET_ARCH_arm64,-D__TARGET_ARCH_x86)
TRAP_COOKIE          ?= 0xC0DED
KSYM_BTF_FILES       ?=
LIBARENA_RS_FEATURES ?= panic-handler alloc-error-handler
RUST_EDITION         ?= 2021
RUST_EXTERNS         ?=
EXTRA_BPF_BCS        ?=
KEEP_EXTRA           ?=
# IR passes (each: `python3 SCRIPT in.ll out.ll`), run before internalize
# and after the O2 stage respectively.
PRE_INTERNALIZE_PASSES ?= $(LIBARENA_RS)/scripts/lower_mem.py
POST_O2_PASSES         ?=

# ---- derived ----
export RUSTC_BOOTSTRAP = 1
CLANG        := $(LLVM_PREFIX)/bin/clang
LLC          := $(LLVM_PREFIX)/bin/llc
OPT          := $(LLVM_PREFIX)/bin/opt
LLVM_LINK    := $(LLVM_PREFIX)/bin/llvm-link
LLVM_AS      := $(LLVM_PREFIX)/bin/llvm-as
LLVM_DIS     := $(LLVM_PREFIX)/bin/llvm-dis
LLVM_AR      := $(LLVM_PREFIX)/bin/llvm-ar
LLVM_NM      := $(LLVM_PREFIX)/bin/llvm-nm
LLVM_OBJCOPY := $(LLVM_PREFIX)/bin/llvm-objcopy

B    := $(LIBARENA_RS_BLD)
DEPS := $(LIBARENA_RS_DEPS)
S    := $(LIBARENA_RS)/scripts

# Stream printk kfunc ABI of the target kernel: `impl` for 6.17/6.18
# (bpf_stream_vprintk_impl, extra aux__prog arg), `plain` for later kernels
# (bpf_stream_vprintk). Auto-detected from the running kernel when building
# against its BTF (the default VMLINUX_H); otherwise plain unless set.
ifeq ($(VMLINUX_H),$(B)/vmlinux.h)
BPF_STREAM_KFUNC ?= $(shell grep -q ' bpf_stream_vprintk_impl$$' /proc/kallsyms 2>/dev/null && echo impl || echo plain)
else
BPF_STREAM_KFUNC ?= plain
endif

# How a panic / allocation failure leaves the program: `throw` calls the
# bpf_throw kfunc with TRAP_COOKIE (needs JIT exception support: x86
# CONFIG_UNWINDER_ORC, which WSL2 kernels lack); `ret` returns TRAP_COOKIE
# from the entry program instead (scripts/trap_to_ret.py). Auto-detected for
# the running kernel from /proc/config.gz.
ifeq ($(VMLINUX_H),$(B)/vmlinux.h)
TRAP_MODE ?= $(shell if [ -r /proc/config.gz ] && ! zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_UNWINDER_ORC=y'; then echo ret; else echo throw; fi)
else
TRAP_MODE ?= throw
endif

# Externally visible void-returning functions (libarena's arena_free, the
# glue's arena_free_u64): `internalize` (default) makes them static
# subprograms, still outlined, which every kernel accepts; `keep` leaves
# them global, which kernels before the void-return relaxation reject
# ("Global function X() doesn't return scalar").
VOID_GLOBALS ?= internalize

RUSTC_COMMON := --target $(BPF_TARGET_JSON) -C opt-level=3 -C debuginfo=2 \
                -C panic=immediate-abort -Z unstable-options
BPF_CFLAGS   := --target=bpfel -mcpu=$(BPF_CPU) -O2 -g -DENABLE_ATOMICS_TESTS $(BPF_ARCH_DEFINE) \
                -Wno-incompatible-pointer-types-discards-qualifiers \
                -Wno-missing-declarations -Wno-macro-redefined \
                $(if $(filter impl,$(BPF_STREAM_KFUNC)),-DLIBARENA_RS_STREAM_IMPL) \
                -include $(LIBARENA_RS)/csrc/kfunc_compat.h \
                -I$(LIBARENA_SRC)/include -I$(dir $(VMLINUX_H)) -I$(LIBBPF_INCLUDE)
_lrs_cfgs    := $(foreach f,$(LIBARENA_RS_FEATURES),--cfg 'feature="$(f)"')

ARENA_BCS  := $(B)/arena_common.bc $(B)/arena_buddy.bc $(B)/arena_glue.bc
CRATE_RLIB := $(B)/liblibarena_rs.rlib
CRATE_CGU  := $(B)/libarena_rs_cgu
LIBARENA_RS_PROG_OBJS := $(patsubst $(BPF_PROGS_DIR)/%.rs,$(B)/%.bpf.o,$(wildcard $(BPF_PROGS_DIR)/*.rs))

# ---- toolchain check ----
.PHONY: libarena-rs-check-toolchain
libarena-rs-check-toolchain:
	@test -n "$(LLVM_PREFIX)" || { echo "LLVM_PREFIX is empty: set it to an LLVM install with the BPF backend"; exit 1; }
	@$(LLC) --version | grep -q bpf || { echo "$(LLC) has no BPF target"; exit 1; }
	@rl=$$($(RUSTC) -vV | sed -n 's/^LLVM version: \([0-9]*\).*/\1/p'); \
	 ll=$$($(LLC) --version | sed -n 's/.*LLVM version \([0-9]*\).*/\1/p'); \
	 test "$$ll" -ge "$$rl" || { echo "LLVM $$ll at LLVM_PREFIX is older than rustc's LLVM $$rl; llvm-link cannot read rustc bitcode"; exit 1; }
	@test -f $(RUST_SRC)/core/src/lib.rs || { echo "rust-src not found at $(RUST_SRC): rustup component add rust-src"; exit 1; }
	@test -f $(LIBARENA_SRC)/src/common.bpf.c || { echo "libarena submodule missing: git submodule update --init"; exit 1; }
	@test -f $(RUSTBPF)/add_ksyms.py || { echo "rust-bpf submodule missing: git submodule update --init"; exit 1; }
	@test -f $(LIBBPF_INCLUDE)/bpf/bpf_helpers.h || { echo "bpf/bpf_helpers.h not under LIBBPF_INCLUDE=$(LIBBPF_INCLUDE)"; exit 1; }
	@echo "toolchain OK: $(LLC) / $(RUSTC) $$($(RUSTC) -V) / deps in $(DEPS) / stream kfunc ABI: $(BPF_STREAM_KFUNC) / trap mode: $(TRAP_MODE) / void globals: $(VOID_GLOBALS)"

# ---- vmlinux.h ----
ifeq ($(VMLINUX_H),$(B)/vmlinux.h)
$(B)/vmlinux.h:
	@mkdir -p $(B)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp && mv $@.tmp $@
endif
.PHONY: vmlinux.h
vmlinux.h: $(VMLINUX_H)

# ---- panic=immediate-abort libcore / liballoc ----
# Collection internals carry panic paths whose formatting (core::fmt) the
# BPF backend cannot lower; immediate-abort panics carry no fmt at all.
$(DEPS)/libcore.rlib: $(RUST_SRC)/core/src/lib.rs
	@mkdir -p $(DEPS)
	$(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) --sysroot=/dev/null \
		--cfg 'no_fp_fmt_parse' --crate-name core \
		--emit=link=$@ --emit=metadata=$(DEPS)/libcore.rmeta $<

$(DEPS)/libcompiler_builtins.rlib: $(DEPS)/libcore.rlib
	echo '#![no_std]' '#![feature(compiler_builtins,rustc_attrs)]' '#![compiler_builtins]' '#![allow(internal_features)]' '#[rustc_std_internal_symbol] fn __rust_no_alloc_shim_is_unstable_v2() {}' | \
	$(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) --sysroot=/dev/null -L$(DEPS) \
		--crate-name compiler_builtins \
		--emit=link=$@ --emit=metadata=$(DEPS)/libcompiler_builtins.rmeta -

$(DEPS)/liballoc.rlib: $(RUST_SRC)/alloc/src/lib.rs $(DEPS)/libcompiler_builtins.rlib
	$(RUSTC) --edition 2024 --crate-type rlib $(RUSTC_COMMON) --sysroot=/dev/null -L$(DEPS) \
		--crate-name alloc \
		--emit=link=$@ --emit=metadata=$(DEPS)/liballoc.rmeta $<

$(DEPS)/extracted: $(DEPS)/libcore.rlib $(DEPS)/libcompiler_builtins.rlib $(DEPS)/liballoc.rlib
	@rm -rf $@ && mkdir -p $@/core $@/compiler_builtins $@/alloc
	cd $@/core && $(LLVM_AR) x $(DEPS)/libcore.rlib && rm -f lib.rmeta
	cd $@/compiler_builtins && $(LLVM_AR) x $(DEPS)/libcompiler_builtins.rlib && rm -f lib.rmeta
	cd $@/alloc && $(LLVM_AR) x $(DEPS)/liballoc.rlib && rm -f lib.rmeta

# ---- libarena C -> bitcode ----
$(B)/arena_%.bc: $(LIBARENA_SRC)/src/%.bpf.c $(VMLINUX_H) $(LIBARENA_RS)/csrc/kfunc_compat.h
	@mkdir -p $(B)
	$(CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

$(B)/arena_glue.bc: $(LIBARENA_RS)/csrc/arena_glue.bpf.c $(VMLINUX_H) $(LIBARENA_RS)/csrc/kfunc_compat.h
	@mkdir -p $(B)
	$(CLANG) $(BPF_CFLAGS) -emit-llvm -c $< -o $@

# libarena's functions (global and static) stay outlined: they verify
# standalone and inlining the buddy loops blows the verifier's jump budget.
$(B)/arena_syms.txt: $(ARENA_BCS)
	$(LLVM_NM) --defined-only $(ARENA_BCS) | \
		awk '$$2 ~ /[TtWw]/ {print $$3}' | sort -u | \
		grep -vE '^(bpf_arena_mem(cpy|cmp|set)|memset)$$' > $@

# ---- the crate: rlib for rustc metadata + extracted CGUs for llvm-link
# ---- (its GlobalAlloc impl and handlers are real code, not just generics)
$(CRATE_RLIB): $(wildcard $(LIBARENA_RS)/src/*.rs) $(DEPS)/libcompiler_builtins.rlib
	@mkdir -p $(B)
	$(RUSTC) --edition 2021 --crate-type rlib $(RUSTC_COMMON) --sysroot=/dev/null -L$(DEPS) \
		$(_lrs_cfgs) --crate-name libarena_rs -o $@ $(LIBARENA_RS)/src/lib.rs
	@rm -rf $(CRATE_CGU) && mkdir -p $(CRATE_CGU)
	cd $(CRATE_CGU) && $(LLVM_AR) x $@ && rm -f lib.rmeta

# alloc's checked layout arithmetic calls __multi3; an out-of-line i128-ABI
# function cannot be compiled by the BPF backend, so force it inline.
$(B)/multi3-inline.bc: $(RUSTBPF)/multi3.ll
	@mkdir -p $(B)
	sed 's/^define i128 @__multi3(i128 %a, i128 %b) {/define i128 @__multi3(i128 %a, i128 %b) alwaysinline {/' \
		$< > $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll

# ---- program -> bitcode ----
$(B)/%.bc: $(BPF_PROGS_DIR)/%.rs $(CRATE_RLIB) $(DEPS)/liballoc.rlib
	@mkdir -p $(B)
	$(RUSTC) --edition $(RUST_EDITION) --crate-type rlib $(RUSTC_COMMON) --sysroot=/dev/null -L$(DEPS) \
		--extern alloc=$(DEPS)/liballoc.rlib \
		--extern libarena_rs=$(CRATE_RLIB) $(RUST_EXTERNS) \
		--crate-name $* --emit=llvm-bc -o $@ $<

# ---- merge Rust + libarena, then pull in libcore/liballoc as needed ----
$(B)/%-linked.bc: $(B)/%.bc $(ARENA_BCS) $(EXTRA_BPF_BCS) $(DEPS)/extracted $(B)/multi3-inline.bc
	$(LLVM_LINK) $< $(ARENA_BCS) $(EXTRA_BPF_BCS) $$(find $(CRATE_CGU) -name '*.rcgu.o') -o $@
	@for i in 1 2 3 4 5; do \
		$(LLVM_LINK) --only-needed $@ $$(find $(DEPS)/extracted -name '*.rcgu.o') -o $@.tmp && mv $@.tmp $@; \
	done
	@$(LLVM_LINK) $@ $(B)/multi3-inline.bc -o $@.tmp && mv $@.tmp $@

# %.keep: symbols left global (internalize). %.noinline: functions left
# outlined (force_inline) = keep list + every libarena function.
$(B)/%.keep: $(B)/%-linked.bc $(B)/arena_syms.txt
	$(LLVM_DIS) $< -o $@.ll
	python3 $(S)/keep_syms.py $@.ll --nm-list $(B)/arena_syms.txt --extra $(KEEP_EXTRA) \
		$(if $(filter internalize,$(VOID_GLOBALS)),--drop-void-globals) > $@
	@rm -f $@.ll
	@cat $@ $(B)/arena_syms.txt | sort -u > $(B)/$*.noinline

# Stages: (0) pre-internalize IR passes, (1) internalize + globaldce,
# (2) force-inline every non-kept function + O2, (3) post-O2 IR passes.
$(B)/%-opt.bc: $(B)/%-linked.bc $(B)/%.keep
	$(LLVM_DIS) $< -o $@.stage0.ll
	@$(foreach p,$(PRE_INTERNALIZE_PASSES),python3 $(p) $@.stage0.ll $@.stage0.ll &&) true
	$(OPT) $$(sed 's/^/--internalize-public-api-list=/' $(B)/$*.keep | tr '\n' ' ') \
		--force-remove-attribute=cold \
		-passes='forceattrs,internalize,globaldce' $@.stage0.ll -o $@.stage1
	$(LLVM_DIS) $@.stage1 -o $@.stage1.ll
	$(OPT) $$(python3 $(S)/force_inline.py $@.stage1.ll $@.stage2.ll $(B)/$*.noinline) \
		-passes='forceattrs,always-inline,globaldce,default<O2>' $@.stage2.ll -o $@.stage3
	@if [ -n "$(strip $(POST_O2_PASSES))" ]; then \
		$(LLVM_DIS) $@.stage3 -o $@.stage3.ll && \
		$(foreach p,$(POST_O2_PASSES),python3 $(p) $@.stage3.ll $@.stage3.ll &&) \
		$(LLVM_AS) $@.stage3.ll -o $@; \
	else mv $@.stage3 $@; fi
	@rm -f $@.stage0.ll $@.stage1 $@.stage1.ll $@.stage2.ll $@.stage3 $@.stage3.ll

# ---- trap -> bpf_throw, .ksyms tagging, invoke/unreachable cleanup ----
$(B)/%-ksyms.bc: $(B)/%-opt.bc
	$(LLVM_DIS) $< -o $@.ll
	$(if $(filter ret,$(TRAP_MODE)),python3 $(S)/trap_to_ret.py $@.ll $@.ll $(TRAP_COOKIE))
	KSYM_BTF_FILES="$(KSYM_BTF_FILES)" BPFTOOL="$(BPFTOOL)" \
		$(if $(filter throw,$(TRAP_MODE)),TRAP_TO_BPF_THROW=$(TRAP_COOKIE)) \
		python3 $(RUSTBPF)/add_ksyms.py $@.ll $@.ll
	$(LLVM_AS) $@.ll -o $@
	@rm -f $@.ll

$(B)/%.bpf.o: $(B)/%-ksyms.bc
	$(LLC) -march=bpfel -mcpu=$(BPF_CPU) -filetype=obj -o $@.tmp $<
	$(LLVM_OBJCOPY) \
		--remove-section=.eh_frame --remove-section=.rel.eh_frame \
		--remove-section=.gcc_except_table \
		--strip-symbol=rust_eh_personality $@.tmp $@
	@rm -f $@.tmp
	python3 $(S)/btf_rename.py $@

# ---- userspace runner ----
$(B)/arena-runner: $(LIBARENA_RS)/tools/runner/runner.c
	@mkdir -p $(B)
	$(CC) -O2 -o $@ $< -I$(LIBBPF_INCLUDE) $(LIBBPF_LIBS)

.PHONY: libarena-rs-clean libarena-rs-distclean
libarena-rs-clean:
	rm -rf $(B)/*.bc $(B)/*.keep $(B)/*.noinline $(B)/*.bpf.o $(B)/*.tmp $(B)/*.ll $(B)/*.stage* \
		$(B)/arena_syms.txt $(CRATE_RLIB) $(CRATE_CGU) $(B)/arena-runner
libarena-rs-distclean:
	rm -rf $(B)

.PRECIOUS: $(B)/%.bc $(B)/%-linked.bc $(B)/%.keep $(B)/%-opt.bc $(B)/%-ksyms.bc
.DEFAULT_GOAL := $(_lrs_default_goal)
