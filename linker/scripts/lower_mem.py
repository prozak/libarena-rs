#!/usr/bin/env python3
"""Lower mem intrinsics/libcalls to the glue helpers BEFORE inlining.

llvm.memcpy/memmove/memset (and memcmp/bcmp libcalls) become calls to the
bpf_arena_mem* functions defined in glue/arena_glue.bpf.c. Doing this
before the always-inline stage means every call site gets its own inlined
copy of the byte loop — necessary because the verifier refuses one shared
instruction that is reached with different pointer types (arena at one
call site, stack or rodata at another: "same insn cannot be used with
different pointers").

compiler_builtins (the real crate, under cargo -Zbuild-std) defines weak
memcpy/memmove/memset/memcmp/bcmp of its own. Those are word-wise loops the
verifier does not like and they shadow the glue's per-call-site versions,
so their definitions are renamed out of the way (__cb_*, dead after the
call sites move) and the glue's `memset`, which llvm-link suffixed to avoid
the clash, gets its name back for llc's libcall lowering to find.

Usage: lower_mem.py in.ll out.ll
"""
import re
import sys

in_ll, out_ll = sys.argv[1], sys.argv[2]
text = open(in_ll).read()

MEM = ('memcpy', 'memmove', 'memset', 'memcmp', 'bcmp')
for n in MEM:
    text = re.sub(rf'^(define (?!internal)[^\n]*?@){n}\(', rf'\1__cb_{n}(',
                  text, flags=re.MULTILINE)
    text = re.sub(rf'^(declare [^\n]*?@){n}\(', rf'\1__cb_{n}(',
                  text, flags=re.MULTILINE)
text = re.sub(r'(?<![A-Za-z0-9_.])@memset\.\d+\b', '@memset', text)

# argument matcher tolerating parenthesized attrs containing commas
A = r'(?:[^,()]|\([^()]*\))*'

text = re.sub(
    rf'(?:tail\s+)?call void @llvm\.(?:memcpy|memmove)(?:\.inline)?\.p0\.p0\.i64\((ptr{A}),\s*(ptr{A}),\s*(i64{A}),\s*i1[^)]*\)',
    r'call void @bpf_arena_memcpy(\1, \2, \3)', text)
text = re.sub(
    rf'(?:tail\s+)?call void @llvm\.memset(?:\.inline)?\.p0\.i64\((ptr{A}),\s*(i8{A}),\s*(i64{A}),\s*i1[^)]*\)',
    r'call void @bpf_arena_memset(\1, \2, \3)', text)
for old, new in (('memcmp', 'bpf_arena_memcmp'), ('bcmp', 'bpf_arena_memcmp'),
                 ('memcpy', 'bpf_arena_memcpy'), ('memmove', 'bpf_arena_memcpy')):
    text = re.sub(r'(?<![A-Za-z0-9_.])@' + old + r'\b', '@' + new, text)

# drop declares for symbols the module now defines (the renames above can
# leave a clashing external declare)
defined = set(re.findall(r'^define\s[^\n]*?@([A-Za-z0-9_.$]+)\(',
                         text, re.MULTILINE))
def drop(m):
    n = re.search(r'@([A-Za-z0-9_.$]+)\(', m.group(0))
    if n and n.group(1) in defined:
        return ''
    return m.group(0)
text = re.sub(r'^declare\s[^\n]*\n(?:[ \t]+section[^\n]*\n)?', drop, text,
              flags=re.MULTILINE)

open(out_ll, 'w').write(text)
