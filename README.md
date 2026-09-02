# libarena-rs

Real Rust `alloc` collections (`Box`, `Vec`, `String`, `VecDeque`, ...) inside
BPF programs, backed by a BPF arena through
[libbpf/libarena](https://github.com/libbpf/libarena)'s buddy allocator — for
Rust compiled **straight to BPF by upstream rustc/LLVM** (the
[4ast/rust-bpf](https://github.com/4ast/rust-bpf) idiom: no aya, no
bpf-linker).

```
$ make test-vng KERNEL_BZIMAGE=/path/to/bzImage
OK   test_rs_box
OK   test_rs_grow_shrink
OK   test_rs_sort
OK   test_rs_string
OK   test_rs_vec
OK   test_rs_vecdeque
bld/collections_smoke.bpf.o: 6/6 passed
```

The crate is the thin Rust side (~150 lines): a `GlobalAlloc` over libarena
plus the `addr_space_cast` instruction as inline asm. Everything that makes it
load and verify is the build pipeline in `mk/libarena.mk`, which is why this is
distributed as a git repository with submodules rather than through crates.io.

## Quick start

```
git clone --recursive https://github.com/prozak/libarena-rs
cd libarena-rs
make check-toolchain        # tells you what is missing and how to fix it
make                        # examples/progs/*.rs -> bld/*.bpf.o + bld/arena-runner
sudo make test              # on a kernel >= 6.17 with BTF
make test-vng KERNEL_BZIMAGE=/path/to/bzImage   # or inside a virtme-ng guest
```

### Prerequisites

| Input | Requirement | Makefile variable |
|---|---|---|
| LLVM | Version >= the LLVM bundled with your rustc (`rustc -vV`), with the BPF backend. Any [official release tarball](https://github.com/llvm/llvm-project/releases) works; tested with 22.1.8. | `LLVM_PREFIX` (default: `llvm-config --prefix`) |
| rustc | 1.96 or newer, stable is fine (`RUSTC_BOOTSTRAP=1` is exported by the fragment), with the `rust-src` component (`rustup component add rust-src`). | `RUSTC`, `RUST_SRC` |
| vmlinux.h | Generated from the running kernel by default (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`); or point at an existing one. Kfuncs libarena needs but your kernel's BTF does not declare are supplied by `csrc/kfunc_compat.h`. | `VMLINUX_H`, `VMLINUX_BTF`, `BPFTOOL` |
| libbpf | Headers (`bpf/bpf_helpers.h`) for the C side; the library for the runner. `libbpf-dev` or a libbpf checkout. | `LIBBPF_INCLUDE`, `LIBBPF_LIBS` |
| Kernel (to run) | >= 6.17: arena maps, `addr_space_cast`, `bpf_arena_reserve_pages`, `bpf_throw`, `may_goto`. Tested against bpf-next 520d7d79. Runner needs root and `/proc/config.gz` or `/boot/config-*` (else pass `RUNNER_ARGS="-k CONFIG_NR_CPUS=8"`). | `KERNEL_BZIMAGE`, `VNG`, `RUNNER_ARGS` |

Machine-local values go in `local.mk` (gitignored, see `local.mk.example`).

## Using it from your own project

```make
LIBARENA_RS := vendor/libarena-rs      # git submodule add --recursive https://github.com/prozak/libarena-rs vendor/libarena-rs
LLVM_PREFIX := /opt/llvm-22
include $(LIBARENA_RS)/mk/libarena.mk
all: $(LIBARENA_RS_PROG_OBJS) $(LIBARENA_RS_BLD)/arena-runner
```

Every `progs/<name>.rs` becomes `bld/<name>.bpf.o`. A program:

```rust
#![no_std]
#![no_main]
extern crate alloc;
use alloc::vec::Vec;
use libarena_rs::ArenaAlloc;

#[global_allocator]
static ALLOC: ArenaAlloc = ArenaAlloc;

#[link_section = "syscall"]
#[no_mangle]
extern "C" fn test_hello(_ctx: *const core::ffi::c_void) -> i32 {
    let v: Vec<u32> = (0..10).collect();
    if v.iter().sum::<u32>() != 45 { return 1; }
    0
}
```

The object also contains, from libarena's C: the `arena` map, the
`arena_buddy_reset` init program (userspace must run it once before anything
allocates; `bld/arena-runner` does), `arena_get_info`/`arena_alloc_reserve`,
and the `license` section (`GPL`, required by the arena kfuncs). Your program
must not define those. Panic and allocation-error handlers come from the
crate (features `panic-handler`, `alloc-error-handler`, default on); disable
them in `LIBARENA_RS_FEATURES` if another crate owns them.

Runtime failures (a panic, an allocation failure) exit the program through
`bpf_throw` with cookie `TRAP_COOKIE` (`0xC0DED`), so a test returns that
value instead of hanging or being rejected.

### Crate API

- `ArenaAlloc` — the `GlobalAlloc`. Requests `max(size, align)` bytes;
  buddy blocks are power-of-two sized and aligned (16 B .. 512 KiB).
- `cast_kern(u64) -> u64`, `cast_user(u64) -> u64`, `cast_kern_ptr<T>`,
  `cast_user_ptr<T>` — `addr_space_cast` between the arena (user-form)
  address and the kernel view.
- `arena_malloc(size) -> *mut u8`, `arena_free(ptr)`, `arena_malloc_user`,
  `arena_free_user` — raw libarena entry points for hand-rolled structures.
- Feature `global-allocator` (opt-in): the crate declares the
  `#[global_allocator]` itself. With the allocator shims defined outside the
  program crate rustc only sees `allockind` declarations and legally elides
  allocations whose results it can forward (`Box::new(x)` read straight back
  vanishes), and the generated code differs from the program-owned
  configuration the tests are verified with. Fine for real programs; know
  that it changes what gets exercised.

On non-BPF targets the crate builds for `cargo check`, `cargo doc` and
`cargo test` only (casts are identities, the C symbols are hosted stand-ins).

### Variables

| Variable | Default | Meaning |
|---|---|---|
| `BPF_PROGS_DIR` | `progs` | where `*.rs` programs live |
| `LIBARENA_RS_BLD` | `$(CURDIR)/bld` | build output |
| `LIBARENA_RS_DEPS` | `bld/deps-<rustc hash>` | the panic=immediate-abort libcore/liballoc, built once per rustc |
| `LIBARENA_RS_FEATURES` | `panic-handler alloc-error-handler` | crate features (`--cfg feature=...`) |
| `BPF_CPU` | `v4` | `-mcpu` for clang and llc |
| `BPF_ARCH_DEFINE` | from `uname -m` | `-D__TARGET_ARCH_x86` / `arm64` (libarena's `map_extra`) |
| `TRAP_COOKIE` | `0xC0DED` | `bpf_throw` cookie for panics / OOM |
| `KEEP_EXTRA` | | extra symbols kept global (not inlined, not internalized) |
| `EXTRA_BPF_BCS` | | your own clang-built `.bc` files to link in |
| `RUST_EXTERNS` | | extra `--extern name=path` for programs |
| `PRE_INTERNALIZE_PASSES` | `scripts/lower_mem.py` | IR scripts (`script in.ll out.ll`) run before internalize |
| `POST_O2_PASSES` | | IR scripts run after the O2 stage |
| `KSYM_BTF_FILES` | | optional vmlinux [+ module .ko] for kernel-mirrored kfunc prototypes (not needed for `bpf_throw`) |
| `RUSTBPF` | `vendor/rust-bpf` | rust-bpf checkout (`add_ksyms.py`, target JSON, `multi3.ll`) |

## How it works

One object, one BTF, merged at the LLVM bitcode level (no BPF static
linker):

1. `clang` builds libarena's `common.bpf.c` + `buddy.bpf.c` and
   `csrc/arena_glue.bpf.c` (u64-ABI shims and per-call-site byte loops for
   `memcpy`/`memmove`/`memset`/`memcmp`) to bitcode.
2. `rustc` builds libcore/liballoc with `-C panic=immediate-abort` (once per
   rustc), the crate, and your program, all against the custom
   `bpfel-unknown-none-v4` target.
3. `llvm-link` merges program + arena + crate, then pulls in only the
   libcore/liballoc functions actually needed, plus an inlinable `__multi3`.
4. `opt`: `lower_mem.py`, internalize everything but the keep list
   (`keep_syms.py`: sectioned functions and globals, libarena's symbols),
   `globaldce`; `force_inline.py` marks every remaining Rust function
   `alwaysinline`; `always-inline` + `O2`.
5. `add_ksyms.py` (rust-bpf): `llvm.trap` -> `bpf_throw(cookie)`, extern
   declarations tagged `.ksyms` with BTF-enabling debug info.
6. `llc -mcpu=v4`, strip EH sections, `btf_rename.py` (canonical C int names
   and identifier-safe type names in `.BTF`, so libbpf keeps the BTF).

### What it took (each of these is load-bearing)

1. **panic=immediate-abort libcore/liballoc**: collection internals carry
   panic paths whose formatting (`core::fmt`) the BPF backend cannot lower
   (6-argument calls, stack arguments). immediate-abort panics carry no fmt.
2. **`llvm.trap` -> `bpf_throw`**: immediate-abort lowers panics to
   `llvm.trap` = `__bpf_trap`, and the verifier rejects any *reachable* trap;
   the allocation-failure path is always reachable. `bpf_throw` is the
   sanctioned clean exit, with a loud cookie as the return value.
3. **Force-inlining all Rust code into the entry programs**: arena pointers
   keep their `PTR_TO_ARENA` verifier typing only inside the function that
   performed the cast; returned through a subprogram they degrade to scalars.
   C re-casts at every boundary via the `__arena` address space; rustc has no
   equivalent. rustc also marks cold call *sites* (`RawVec::grow_one`)
   `noinline`, which must be stripped.
4. **libarena's C functions stay global**: they verify standalone; inlining
   the buddy loops into an entry program blows the verifier's jump budget.
   `btf_rename.py` never touches DECL_TAG names (`arg:arena` needs its colon).
5. **mem intrinsics lowered before inlining** (`lower_mem.py`): each call
   site gets its own copy of the byte loop, because the verifier refuses one
   shared instruction reached with different pointer types (arena at one site,
   stack or rodata at another). The backward memmove walk needs the
   `barrier_var` idiom to stay in verifier-provable index form.
6. **`__multi3` force-inlined**: alloc's checked layout math calls it, and an
   out-of-line i128-ABI function cannot be compiled for BPF.

## Known limits

- **Pointer-chasing collections** (`BTreeMap`, `Vec<Vec<_>>`) do not verify
  yet: pointers stored *inside* arena memory come back as scalars on reload.
  A post-O2 IR pass that re-inserts `addr_space_cast` after provably
  arena-derived loads fixes `Vec<Vec<_>>` and `Box<Box<_>>`; it is being
  reviewed for this repository (see rust-selftests PR #35).
- Verifier budgets bound working-set sizes (the sort example uses 24
  elements; `Vec::dedup` on symbolic lengths exceeds 1M instructions).
- Kernel-side only: sharing collection layouts with userspace would need
  `cast_user` discipline on every stored pointer.
- Max single allocation 512 KiB (buddy order limit).

## Layout

    src/                the crate (allocator, casts, raw wrappers, handlers)
    csrc/               arena_glue.bpf.c (u64 shims, mem loops), kfunc_compat.h
    mk/libarena.mk      the pipeline, include it from your Makefile
    scripts/            lower_mem.py, force_inline.py, keep_syms.py, btf_rename.py
    tools/runner/       arena-runner: loads an object, runs arena_buddy_reset,
                        bpf_prog_test_run()s every test_* program
    examples/progs/     collections_smoke.rs (the verified corpus)
    vendor/libarena     libbpf/libarena, pinned
    vendor/rust-bpf     prozak/rust-bpf fork, pinned (add_ksyms.py, target JSON, multi3.ll)

## License

`LGPL-2.1 OR BSD-2-Clause`, the same terms as libarena and libbpf, for
everything in this repository outside `vendor/`. `vendor/libarena` carries
the same license; `vendor/rust-bpf` is a git submodule of an upstream project
that has not yet published a license and is referenced, not redistributed.
The BPF objects you build declare `GPL` to the kernel (libarena's `_license`;
the arena kfuncs are GPL-only), which is a statement about the loaded program,
independent of this repository's license.
