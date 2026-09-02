// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
#![no_std]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]
#![cfg_attr(
    all(target_arch = "bpf", any(feature = "panic-handler", feature = "alloc-error-handler")),
    feature(core_intrinsics)
)]
#![cfg_attr(all(target_arch = "bpf", feature = "alloc-error-handler"), feature(alloc_error_handler))]
#![allow(internal_features)]

//! BPF-arena-backed [`GlobalAlloc`](core::alloc::GlobalAlloc) for Rust compiled
//! straight to BPF by upstream rustc/LLVM (the 4ast/rust-bpf idiom: no aya,
//! no bpf-linker).
//!
//! The allocator is [libbpf/libarena](https://github.com/libbpf/libarena)'s
//! buddy allocator, compiled from C by clang and merged with the Rust program
//! at the LLVM bitcode level; libarena also supplies the `arena` map, the
//! `arena_buddy_reset` init program and the object's `license` section.
//! This crate is the thin Rust side:
//!
//! - [`ArenaAlloc`] implements `GlobalAlloc` over `arena_malloc_internal` /
//!   `arena_free_u64` (an integer-only FFI surface: Rust cannot express the
//!   `__arena` address space). Each fresh allocation is cast once to the
//!   kernel view with [`cast_kern`], so collections hold plain kernel-view
//!   pointers; `dealloc` casts back with [`cast_user`].
//! - [`cast_kern`] / [`cast_user`] are the byte-exact `addr_space_cast`
//!   instruction, hand-encoded as inline asm (rustc has no other way to emit
//!   it).
//! - With the default features the crate also provides the panic and
//!   allocation-error handlers; the program declares the allocator:
//!
//! ```ignore
//! extern crate alloc;
//! #[global_allocator]
//! static ALLOC: libarena_rs::ArenaAlloc = libarena_rs::ArenaAlloc;
//! ```
//!
//!   (The `global-allocator` feature moves that declaration into the crate;
//!   see the feature's note in Cargo.toml for why that is opt-in.)
//!
//! Building a BPF object needs the pipeline in `mk/libarena.mk` (bitcode
//! merge, force-inlining, mem-intrinsic lowering, trap → `bpf_throw`); see
//! the README. On non-BPF targets the crate compiles for `cargo check`,
//! `cargo doc` and unit tests only: the casts are identities and the C
//! symbols are hosted stand-ins.

mod arena_alloc;
mod cast;
#[cfg(target_arch = "bpf")]
mod handlers;
mod raw;

pub use arena_alloc::ArenaAlloc;
pub use cast::{cast_kern, cast_kern_ptr, cast_user, cast_user_ptr};
pub use raw::{arena_free, arena_free_user, arena_malloc, arena_malloc_user};

/// The crate-owned global allocator (feature `global-allocator`, BPF only;
/// see Cargo.toml for the trade-off).
#[cfg(all(target_arch = "bpf", feature = "global-allocator"))]
#[global_allocator]
pub static GLOBAL: ArenaAlloc = ArenaAlloc;
