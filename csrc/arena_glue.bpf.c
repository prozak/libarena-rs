// SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
/* Plain-u64 ABI shims over libarena for the Rust side.
 *
 * Rust cannot express __arena (addrspace(1)) pointers, so its FFI surface
 * must be integer-only. arena_malloc_internal() is already u64-based;
 * arena_free() takes a __arena pointer, so wrap it. The u64 values are
 * arena (user-form) addresses: the Rust allocator addr_space_casts them to
 * the kernel view right after allocation and back before freeing.
 */
#include <libarena/common.h>

void arena_free_u64(u64 ptr)
{
	arena_free((void __arena *)ptr);
}

/* The rust-bpf pipeline renames LLVM's memcpy/memmove/memcmp/memset
 * lowering to bpf_arena_memcpy / bpf_arena_memcmp / memset symbol
 * references. This kernel has no such kfuncs, so provide them as BPF
 * functions instead. They are deliberately STATIC subprograms: the
 * verifier then checks them per call site with the caller's actual
 * pointer types, which is what allows mixed-provenance copies (arena
 * <-> stack <-> global) that Rust collections do all the time.
 * bpf_arena_memcpy also serves llvm.memmove, so it must be
 * overlap-safe: copy backwards when dst > src. */
static __attribute__((used)) void bpf_arena_memcpy(void *dst, const void *src, u64 n)
{
	u8 *d = dst;
	const u8 *s = src;
	u64 i;

	if (dst < src) {
		for (i = zero; i < n && can_loop; i++)
			d[i] = s[i];
	} else {
		/* index form with an explicit (always-true) bound check:
		 * gives the verifier a direct k < n range and stops LLVM
		 * from strength-reducing to decrementing pointers, whose
		 * possibly-negative offsets it rejects for rodata bases */
		for (i = zero; i < n && can_loop; i++) {
			u64 k = n - 1 - i;
			/* barrier_var idiom: make k opaque so the bound check
			 * below survives optimization and hands the verifier
			 * a direct k < n range */
			asm volatile("" : "+r"(k));
			if (k >= n)
				break;
			d[k] = s[k];
		}
	}
}

static __attribute__((used)) int bpf_arena_memcmp(const void *a, const void *b, u64 n)
{
	const u8 *x = a, *y = b;
	u64 i;

	for (i = zero; i < n && can_loop; i++) {
		if (x[i] != y[i])
			return x[i] < y[i] ? -1 : 1;
	}
	return 0;
}

static __attribute__((used)) void *memset(void *s, int c, u64 n)
{
	u8 *p = s;
	u64 i;

	for (i = zero; i < n && can_loop; i++)
		p[i] = (u8)c;
	return s;
}

static __attribute__((used)) void bpf_arena_memset(void *s, u8 c, u64 n)
{
	u8 *p = s;
	u64 i;

	for (i = zero; i < n && can_loop; i++)
		p[i] = c;
}
