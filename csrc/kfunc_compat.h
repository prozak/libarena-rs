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
extern int bpf_stream_vprintk(int stream_id, const char *fmt__str, const void *args,
			      unsigned int len__sz) __lrs_ksym;

#undef __lrs_ksym
#endif
