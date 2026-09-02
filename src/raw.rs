// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
//! Raw libarena entry points, for hand-rolled arena data structures.
//!
//! On BPF these resolve at bitcode-link time to libarena's
//! `arena_malloc_internal` and the glue's `arena_free_u64`
//! (`csrc/arena_glue.bpf.c`). On other targets they are hosted stand-ins
//! over `posix_memalign`/`free` so the crate's unit tests can run.

use crate::cast::{cast_kern, cast_user};

#[cfg(target_arch = "bpf")]
extern "C" {
    fn arena_malloc_internal(size: usize) -> u64;
    fn arena_free_u64(ptr: u64);
}

#[cfg(not(target_arch = "bpf"))]
mod hosted {
    use core::ffi::c_void;
    extern "C" {
        fn posix_memalign(memptr: *mut *mut c_void, align: usize, size: usize) -> i32;
        fn free(p: *mut c_void);
    }
    /// Mimics the buddy allocator: power-of-two sized and aligned blocks.
    pub unsafe fn arena_malloc_internal(size: usize) -> u64 {
        let sz = size.max(16).next_power_of_two();
        let mut p: *mut c_void = core::ptr::null_mut();
        if posix_memalign(&mut p, sz.min(4096), sz) != 0 {
            return 0;
        }
        p as usize as u64
    }
    pub unsafe fn arena_free_u64(ptr: u64) {
        free(ptr as usize as *mut c_void)
    }
}
#[cfg(not(target_arch = "bpf"))]
use hosted::{arena_free_u64, arena_malloc_internal};

/// Allocate `size` bytes; returns the user-form (u64) arena address libarena
/// produced, or 0 on failure. Buddy blocks are power-of-two sized and
/// aligned (minimum 16 bytes, maximum 512 KiB).
///
/// # Safety
/// The buddy allocator must have been initialised (`arena_buddy_reset` run).
#[inline(always)]
pub unsafe fn arena_malloc_user(size: usize) -> u64 {
    arena_malloc_internal(size)
}

/// Free a user-form arena address obtained from [`arena_malloc_user`] or
/// [`cast_user`] on a kernel-view pointer.
///
/// # Safety
/// `addr` must be a live allocation from this allocator.
#[inline(always)]
pub unsafe fn arena_free_user(addr: u64) {
    arena_free_u64(addr)
}

/// Allocate `size` bytes and return a kernel-view pointer (null on failure).
///
/// # Safety
/// See [`arena_malloc_user`].
#[inline(always)]
pub unsafe fn arena_malloc(size: usize) -> *mut u8 {
    let ua = arena_malloc_internal(size);
    if ua == 0 {
        return core::ptr::null_mut();
    }
    cast_kern(ua) as usize as *mut u8
}

/// Free a kernel-view pointer from [`arena_malloc`].
///
/// # Safety
/// `ptr` must be a live allocation from this allocator.
#[inline(always)]
pub unsafe fn arena_free(ptr: *mut u8) {
    arena_free_u64(cast_user(ptr as usize as u64))
}
