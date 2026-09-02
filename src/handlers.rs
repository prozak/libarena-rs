// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
//! Panic and allocation-error handlers (BPF only, feature-gated).
//!
//! Under `-C panic=immediate-abort` rustc lowers every panic to `llvm.trap`
//! before these are ever reached, and the pipeline rewrites the trap to
//! `bpf_throw(cookie)` (a clean program exit with a loud return value).
//! They still have to exist for the crate graph to link, and they matter if
//! any crate is built with a different panic strategy. Both abort, taking the
//! same trap path; never `loop {}` (an infinite loop that survives dead-code
//! elimination is rejected by the verifier).

#[cfg(feature = "panic-handler")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::intrinsics::abort()
}

#[cfg(feature = "alloc-error-handler")]
#[alloc_error_handler]
fn oom(_: core::alloc::Layout) -> ! {
    core::intrinsics::abort()
}
