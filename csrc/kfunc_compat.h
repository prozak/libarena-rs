/* SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause */
/* Declarations of the kfuncs libarena calls, for vmlinux.h files generated
 * from kernels whose BTF carries no kfunc decl tags (kernel built with
 * pahole < 1.27, or kfunc tagging off). Force-included ahead of every C
 * translation unit (before bpf_helpers.h, hence the raw attributes and
 * builtin types); a vmlinux.h that does declare them repeats identical
 * prototypes, which C permits. The arena page kfuncs are declared by
 * libarena's own bpf_arena_common.h. */
#ifndef LIBARENA_RS_KFUNC_COMPAT_H
#define LIBARENA_RS_KFUNC_COMPAT_H

#define __lrs_ksym __attribute__((section(".ksyms"))) __attribute__((weak))

extern void bpf_preempt_disable(void) __lrs_ksym;
extern void bpf_preempt_enable(void) __lrs_ksym;
/* The stream printk kfunc changed name and arity between kernels: 6.17/6.18
 * export bpf_stream_vprintk_impl() with a trailing aux__prog argument that
 * programs pass as NULL; later kernels export bpf_stream_vprintk() and fill
 * the implicit argument in the verifier. libbpf's bpf_stream_printk() macro
 * (which libarena's arena_stderr uses) calls the 4-argument name, so remap
 * it here when building for the older ABI (BPF_STREAM_KFUNC=impl). */
#ifdef LIBARENA_RS_STREAM_IMPL
extern int bpf_stream_vprintk_impl(int stream_id, const char *fmt__str, const void *args,
				   unsigned int len__sz, void *aux__prog) __lrs_ksym;
#define bpf_stream_vprintk(stream_id, fmt, args, len) \
	bpf_stream_vprintk_impl(stream_id, fmt, args, len, (void *)0)
#else
extern int bpf_stream_vprintk(int stream_id, const char *fmt__str, const void *args,
			      unsigned int len__sz) __lrs_ksym;
#endif

#undef __lrs_ksym
#endif
