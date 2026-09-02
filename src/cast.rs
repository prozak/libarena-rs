// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
//! `addr_space_cast` wrappers.
//!
//! The BPF instruction `rX = addr_space_cast(rX, dst_as, src_as)` is
//! `BPF_ALU64 | BPF_MOV | BPF_X` with `off = 1` and the address spaces in
//! `imm` (`src_as` low 16 bits, `dst_as` high 16 bits). The encodings below
//! are byte-for-byte what clang emits for `bpf_addr_space_cast()`; the
//! `.ifc {0}, rN` register sniffing is the same trick as libbpf's
//! `bpf_experimental.h` fallback macro.
//!
//! Only the function that performed the cast holds a `PTR_TO_ARENA`-typed
//! register; this is why the build pipeline force-inlines every Rust
//! function into the entry programs, and why every one of these must stay
//! `#[inline(always)]`.

#[cfg(target_arch = "bpf")]
macro_rules! addr_space_cast {
    ($a:ident, $imm:literal) => {
        unsafe {
            core::arch::asm!(
                ".byte 0xBF",
                ".ifc {0}, r0", ".byte 0x00", ".endif",
                ".ifc {0}, r1", ".byte 0x11", ".endif",
                ".ifc {0}, r2", ".byte 0x22", ".endif",
                ".ifc {0}, r3", ".byte 0x33", ".endif",
                ".ifc {0}, r4", ".byte 0x44", ".endif",
                ".ifc {0}, r5", ".byte 0x55", ".endif",
                ".ifc {0}, r6", ".byte 0x66", ".endif",
                ".ifc {0}, r7", ".byte 0x77", ".endif",
                ".ifc {0}, r8", ".byte 0x88", ".endif",
                ".ifc {0}, r9", ".byte 0x99", ".endif",
                ".short 1",
                concat!(".long ", $imm),
                inout(reg) $a,
                options(nostack, preserves_flags),
            );
        }
    };
}

/// `addr_space_cast dst_as=0 src_as=1`: arena (user-form, `map_extra`-based)
/// address to the kernel view. Apply once to every address libarena hands
/// out before dereferencing it.
#[inline(always)]
pub fn cast_kern(addr: u64) -> u64 {
    #[allow(unused_mut)]
    let mut a = addr;
    #[cfg(target_arch = "bpf")]
    addr_space_cast!(a, "1");
    a
}

/// `addr_space_cast dst_as=1 src_as=0`: kernel-view pointer back to the
/// arena (user-form) address libarena and userspace understand.
#[inline(always)]
pub fn cast_user(addr: u64) -> u64 {
    #[allow(unused_mut)]
    let mut a = addr;
    #[cfg(target_arch = "bpf")]
    addr_space_cast!(a, "65536"); // dst_as=1 in the upper 16 bits
    a
}

/// Typed form of [`cast_kern`]. Re-establishes arena typing on a pointer
/// value, e.g. one just loaded from arena memory.
#[inline(always)]
pub fn cast_kern_ptr<T>(p: *mut T) -> *mut T {
    cast_kern(p as usize as u64) as usize as *mut T
}

/// Typed form of [`cast_user`].
#[inline(always)]
pub fn cast_user_ptr<T>(p: *mut T) -> *mut T {
    cast_user(p as usize as u64) as usize as *mut T
}
