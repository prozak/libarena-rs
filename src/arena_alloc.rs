// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
use core::alloc::{GlobalAlloc, Layout};

use crate::raw::{arena_free, arena_malloc};

/// `GlobalAlloc` over libarena's buddy allocator.
///
/// Buddy blocks are power-of-two sized *and* aligned, so requesting
/// `max(size, align)` bytes satisfies any `Layout`. `realloc` and
/// `alloc_zeroed` are the `GlobalAlloc` defaults (allocate + copy/zero +
/// free); the pipeline lowers the resulting `memcpy`/`memset` intrinsics to
/// per-call-site byte loops (`scripts/lower_mem.py`).
///
/// The trait methods are deliberately not `#[inline(always)]`: they stay
/// out of line until the bitcode-link stage force-inlines them, which is
/// the code shape the verified test corpus was built with.
pub struct ArenaAlloc;

impl ArenaAlloc {
    /// Bytes to request from the buddy allocator for `layout`.
    #[inline(always)]
    pub const fn request_size(layout: Layout) -> usize {
        let size = layout.size();
        let align = layout.align();
        let sz = if size > align { size } else { align };
        if sz == 0 {
            1
        } else {
            sz
        }
    }
}

unsafe impl GlobalAlloc for ArenaAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        arena_malloc(Self::request_size(layout))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        arena_free(ptr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_size_covers_alignment() {
        let l = Layout::from_size_align(24, 64).unwrap();
        assert_eq!(ArenaAlloc::request_size(l), 64);
        let l = Layout::from_size_align(100, 8).unwrap();
        assert_eq!(ArenaAlloc::request_size(l), 100);
        let l = Layout::from_size_align(0, 1).unwrap();
        assert_eq!(ArenaAlloc::request_size(l), 1);
    }

    #[test]
    fn hosted_alloc_roundtrip() {
        let l = Layout::from_size_align(100, 64).unwrap();
        unsafe {
            let p = ArenaAlloc.alloc(l);
            assert!(!p.is_null());
            assert_eq!(p as usize % 64, 0);
            core::ptr::write_bytes(p, 0xAB, 100);
            assert_eq!(*p.add(99), 0xAB);
            ArenaAlloc.dealloc(p, l);
        }
    }

    #[test]
    fn casts_are_identity_on_host() {
        assert_eq!(crate::cast_kern(0x1234), 0x1234);
        assert_eq!(crate::cast_user(0x1234), 0x1234);
    }
}
