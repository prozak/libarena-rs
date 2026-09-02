# libarena-rs

Real Rust `alloc` collections (`Box`, `Vec`, `String`, `VecDeque`, ...) inside
BPF programs, backed by a BPF arena through
[libbpf/libarena](https://github.com/libbpf/libarena)'s buddy allocator — for
Rust compiled **straight to BPF by upstream rustc/LLVM** (the
[4ast/rust-bpf](https://github.com/4ast/rust-bpf) idiom: no aya, no
bpf-linker), built with plain `cargo`.

```
$ cargo install arena-linker             # once: the linker rustc calls (or --path linker)
$ RUSTC_BOOTSTRAP=1 cargo bpf --examples # examples/*.rs -> target/bpfel-unknown-none-v4/release/examples/*
$ make test-vng KERNEL_BZIMAGE=/path/to/bzImage
OK   test_rs_box
OK   test_rs_grow_shrink
OK   test_rs_sort
OK   test_rs_string
OK   test_rs_vec
OK   test_rs_vecdeque
target/bpfel-unknown-none-v4/release/examples/collections_smoke: 6/6 passed
```

Three parts:

- **`libarena-rs`** (this crate, `no_std`): `ArenaAlloc`, a `GlobalAlloc` over
  libarena, plus the `addr_space_cast` instruction as inline asm. Its
  `build.rs` compiles libarena's C and the glue to BPF bitcode with clang.
- **`arena-linker`** (`linker/`): the linker rustc invokes for the BPF target.
  It merges the program's bitcode, the rlibs and libarena's bitcode and runs
  the IR pipeline that makes `alloc` verify (mem-intrinsic lowering,
  internalize, force-inlining, trap handling, kfunc tagging, BTF renaming)
  with the LLVM tools, then writes the object where rustc asked.
- **`targets/bpfel-unknown-none-v4.json`**: rustc's built-in
  `bpfel-unknown-none` spec with atomic CAS enabled, 8-bit atomics and
  `cpu = v4`.

## Prerequisites

| Input | Requirement | Environment variable |
|---|---|---|
| LLVM | Version >= the LLVM bundled with your rustc (`rustc -vV`), with the BPF backend; any [official release tarball](https://github.com/llvm/llvm-project/releases) works. Tested with 22.1.8. | `LLVM_PREFIX` (else `llvm-config`, then PATH) |
| Rust | 1.96 or newer, stable is fine with `RUSTC_BOOTSTRAP=1` (for `-Zbuild-std`), plus the `rust-src` component. Nightly needs no variable. | |
| python3 | The IR passes are Python scripts embedded in the linker. | `PYTHON` |
| vmlinux.h | For the kernel the object will run on. Default: generated from `/sys/kernel/btf/vmlinux` with `bpftool`. | `LIBARENA_VMLINUX_H`, `VMLINUX_BTF`, `BPFTOOL` |
| libbpf | Headers (`bpf/bpf_helpers.h`) for the C side; the library for the runner (`libbpf-dev`). | `LIBBPF_INCLUDE` |
| Kernel (to run) | >= 6.17: arena maps, `addr_space_cast`, `bpf_arena_reserve_pages`, `may_goto`. Tested against bpf-next 520d7d79 and a stock 6.18. | see knobs below |

Kfuncs that libarena needs but your kernel's BTF does not declare (kernels
built without kfunc decl tags) are supplied by `csrc/kfunc_compat.h`.

## Using it from your own project

`Cargo.toml`:

```toml
[dependencies]
libarena-rs = "0.2"

[profile.release]
opt-level = 3
debug = 2          # BTF comes from debug info; keep it
```

Copy `targets/bpfel-unknown-none-v4.json` next to it, and `.cargo/config.toml`:

```toml
[alias]
bpf = "build --release --target bpfel-unknown-none-v4.json -Zbuild-std=core,alloc -Zjson-target-spec"

[target.bpfel-unknown-none-v4]
linker = "arena-linker"
rustflags = ["-Zunstable-options", "-C", "panic=immediate-abort", "-C", "codegen-units=1", "--cfg", "no_fp_fmt_parse", "-A", "unexpected_cfgs"]

[env]
RUSTC_BOOTSTRAP = "1"
```

`src/main.rs`:

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

`RUSTC_BOOTSTRAP=1 cargo bpf` writes `target/bpfel-unknown-none-v4/release/hello`,
a loadable BPF object. Every `#[link_section]` function is an entry program.

The object also contains, from libarena's C: the `arena` map, the
`arena_buddy_reset` init program (userspace must run it once before anything
allocates; `tools/runner` does), `arena_get_info`/`arena_alloc_reserve`, and
the `license` section (`GPL`, required by the arena kfuncs). Your program
must not define those. Panic and allocation-error handlers come from the
crate (features `panic-handler`, `alloc-error-handler`, default on).

Why the flags: every crate including core and alloc must be built with
`panic=immediate-abort` (panic formatting cannot be lowered by the BPF
backend); `codegen-units=1` stops rustc's per-crate ThinLTO round from
unrolling allocation loops into verifier budget; `no_fp_fmt_parse` drops
float formatting from core.

### Knobs (environment, read by build.rs and the linker)

| Variable | Default | Meaning |
|---|---|---|
| `BPF_STREAM_KFUNC` | auto / `plain` | `impl` for 6.17/6.18 kernels (`bpf_stream_vprintk_impl`), `plain` for newer; auto-detected from the running kernel when `LIBARENA_VMLINUX_H` is unset |
| `TRAP_MODE` | auto / `throw` | how a panic or allocation failure exits: `throw` = `bpf_throw` kfunc (needs JIT exception support, on x86 `CONFIG_UNWINDER_ORC`), `ret` = return the cookie from the entry program (e.g. WSL2 kernels); auto-detected for the running kernel |
| `TRAP_COOKIE` | `0xC0DED` | the return value of a panicked / OOM program |
| `VOID_GLOBALS` | `internalize` | void-returning global functions become static subprograms (`keep` leaves them global; kernels before the void-return relaxation reject that) |
| `BPF_ARCH_DEFINE` | from host arch | `-D__TARGET_ARCH_x86` / `arm64` (libarena's `map_extra`) |
| `BPF_CPU` | `v4` | clang `-mcpu` for the C side (the JSON target sets it for Rust) |
| `KEEP_EXTRA` | | extra symbols kept global (neither inlined nor internalized) |
| `ARENA_PRE_PASSES`, `ARENA_POST_PASSES` | | colon-separated IR scripts (`script in.ll out.ll`) run before internalize / after the O2 stage |
| `ARENA_LINKER_KEEP_TEMPS`, `ARENA_LINKER_VERBOSE` | | keep `<output>.arena-linker/` with every stage; log the commands |

`make` in this repository builds the linker, the examples and the runner;
`make test` runs the objects on this kernel (sudo for the runner only);
`make test-vng KERNEL_BZIMAGE=...` runs them in a virtme-ng guest. Machine
paths go in `local.mk` (see `local.mk.example`).

### Crate API

- `ArenaAlloc` — the `GlobalAlloc`. Requests `max(size, align)` bytes; buddy
  blocks are power-of-two sized and aligned (16 B .. 512 KiB).
- `cast_kern(u64) -> u64`, `cast_user(u64) -> u64`, `cast_kern_ptr<T>`,
  `cast_user_ptr<T>` — `addr_space_cast` between the arena (user-form)
  address and the kernel view.
- `arena_malloc(size) -> *mut u8`, `arena_free(ptr)`, `arena_malloc_user`,
  `arena_free_user` — raw libarena entry points for hand-rolled structures.
- Feature `global-allocator` (opt-in): the crate declares the
  `#[global_allocator]` itself. With the allocator shims defined outside the
  program crate rustc only sees `allockind` declarations and legally elides
  allocations whose results it can forward (`Box::new(x)` read straight back
  vanishes); fine for real programs, but it changes what a test exercises.

On non-BPF targets the crate builds for `cargo check`, `cargo doc` and
`cargo test` only (casts are identities, the C symbols are hosted stand-ins,
`build.rs` does nothing).

## How it works

One object, one BTF, merged at the LLVM bitcode level (no BPF static
linker). `cargo bpf` builds core, alloc, compiler_builtins, the crate and
the program as bitcode; `build.rs` builds libarena's `common.bpf.c` +
`buddy.bpf.c` and `csrc/arena_glue.bpf.c` (u64-ABI shims and per-call-site
byte loops for `memcpy`/`memmove`/`memset`/`memcmp`) into `libarena_c.a`.
rustc then calls `arena-linker`, which:

1. `llvm-link`s everything into one module.
2. Lowers mem intrinsics and libcalls to the glue's loops
   (`lower_mem.py`; compiler_builtins' own mem functions are set aside).
3. Internalizes everything but the keep list — the entry programs from
   rustc's export list, every sectioned function or global (`arena`,
   `_license`), libarena's symbols (`keep_syms.py`) — and runs `globaldce`.
4. Force-inlines every Rust function (`force_inline.py`), then `opt -O2`.
5. Rewrites `llvm.trap` to `bpf_throw(cookie)` or `ret cookie`
   (`trap_to_ret.py`), tags extern kfuncs `.ksyms` with BTF-enabling debug
   info, drops declares of defined symbols, fixes `unreachable`
   (`bpf_finalize.py`).
6. `llc -mcpu=v4`, strips EH sections, and canonicalizes int type names and
   identifier-safety in `.BTF` (`btf_rename.py`) so libbpf keeps the BTF.

### What it took (each of these is load-bearing)

1. **panic=immediate-abort everywhere**: collection internals carry panic
   paths whose formatting (`core::fmt`) the BPF backend cannot lower
   (6-argument calls, stack arguments). immediate-abort panics carry no fmt.
2. **`llvm.trap` -> `bpf_throw` / `ret`**: immediate-abort lowers panics to
   `llvm.trap` = `__bpf_trap`, and the verifier rejects any *reachable* trap;
   the allocation-failure path is always reachable.
3. **Force-inlining all Rust code into the entry programs**: arena pointers
   keep their `PTR_TO_ARENA` verifier typing only inside the function that
   performed the cast; through a global subprogram they degrade to scalars.
   rustc also marks cold call *sites* (`RawVec::grow_one`) `noinline`, which
   must be stripped.
4. **libarena's C functions stay outlined**: inlining the buddy loops into
   an entry program blows the verifier's jump budget.
5. **mem intrinsics lowered before inlining**: each call site gets its own
   copy of the byte loop, because the verifier refuses one shared
   instruction reached with different pointer types (arena at one site,
   stack or rodata at another). The backward memmove walk needs the
   `barrier_var` idiom to stay in verifier-provable index form.
6. **Single codegen unit**: rustc's ThinLTO round over a bin crate's units
   unrolls allocation loops 8-way; the verifier pays for every copy.

## Known limits

- **Pointer-chasing collections** (`BTreeMap`, `Vec<Vec<_>>`) do not verify
  yet: pointers stored *inside* arena memory come back as scalars on reload.
  A post-O2 IR pass that re-inserts `addr_space_cast` after provably
  arena-derived loads fixes `Vec<Vec<_>>` and `Box<Box<_>>`; it is being
  reviewed for this repository (rust-selftests PR #35) and plugs in via
  `ARENA_POST_PASSES`.
- Verifier budgets bound working-set sizes (the sort example uses 24
  elements; `Vec::dedup` on symbolic lengths exceeds 1M instructions).
- Kernel-side only: sharing collection layouts with userspace would need
  `cast_user` discipline on every stored pointer.
- Max single allocation 512 KiB (buddy order limit).

## Layout

    src/                the crate (allocator, casts, raw wrappers, handlers)
    build.rs            clang: libarena + glue -> libarena_c.a (BPF targets only)
    csrc/               arena_glue.bpf.c (u64 shims, mem loops), kfunc_compat.h
    linker/             arena-linker (host binary) + linker/scripts/*.py (embedded)
    targets/            bpfel-unknown-none-v4.json
    examples/           collections_smoke.rs (the verified corpus)
    tools/runner/       arena-runner: loads an object, runs arena_buddy_reset,
                        bpf_prog_test_run()s every test_* program
    vendor/libarena     libbpf/libarena, pinned

## License

`LGPL-2.1 OR BSD-2-Clause`, the same terms as libarena and libbpf, for
everything in this repository outside `vendor/`; `vendor/libarena` carries
the same license. The BPF objects you build declare `GPL` to the kernel
(libarena's `_license`; the arena kfuncs are GPL-only), which is a statement
about the loaded program, independent of this repository's license.
