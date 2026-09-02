# arena-linker

The linker rustc invokes for BPF programs that use
[libarena-rs](https://github.com/prozak/libarena-rs). It receives the
program's bitcode and rlibs from rustc, merges them with libarena's C
bitcode (built by libarena-rs's `build.rs`), runs the IR pipeline that makes
`alloc` verify in BPF (mem-intrinsic lowering, internalize, force-inlining,
trap handling, kfunc tagging, BTF renaming) with the LLVM tools from
`LLVM_PREFIX`, and writes the final object where rustc asked for it.

    cargo install arena-linker

See the libarena-rs README for the environment variables it reads.
