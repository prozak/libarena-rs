#!/usr/bin/env python3
"""Lower mem intrinsics/libcalls to the glue helpers BEFORE inlining.

llvm.memcpy/memmove/memset (and memcmp/bcmp libcalls) become calls to the
bpf_arena_mem* functions defined in glue/arena_glue.bpf.c. Doing this
before the always-inline stage means every call site gets its own inlined
copy of the byte loop — necessary because the verifier refuses one shared
instruction that is reached with different pointer types (arena at one
call site, stack or rodata at another: "same insn cannot be used with
different pointers").

Usage: lower_mem.py in.ll out.ll
"""
import re
import sys

in_ll, out_ll = sys.argv[1], sys.argv[2]
text = open(in_ll).read()

# argument matcher tolerating parenthesized attrs containing commas
A = r'(?:[^,()]|\([^()]*\))*'

text = re.sub(
    rf'(?:tail\s+)?call void @llvm\.(?:memcpy|memmove)(?:\.inline)?\.p0\.p0\.i64\((ptr{A}),\s*(ptr{A}),\s*(i64{A}),\s*i1[^)]*\)',
    r'call void @bpf_arena_memcpy(\1, \2, \3)', text)
text = re.sub(
    rf'(?:tail\s+)?call void @llvm\.memset(?:\.inline)?\.p0\.i64\((ptr{A}),\s*(i8{A}),\s*(i64{A}),\s*i1[^)]*\)',
    r'call void @bpf_arena_memset(\1, \2, \3)', text)
for old in ('memcmp', 'bcmp'):
    text = re.sub(r'(?<![A-Za-z0-9_.])@' + old + r'\b', '@bpf_arena_memcmp',
                  text)

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
