#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
"""Rewrite `llvm.trap(); unreachable` into `ret <cookie>` (TRAP_MODE=ret).

Under panic=immediate-abort every panic and allocation failure is an
llvm.trap, and the verifier rejects any reachable __bpf_trap. The default
pipeline turns traps into bpf_throw(cookie), but that kfunc needs JIT
exception support (x86: CONFIG_UNWINDER_ORC; absent in e.g. WSL2 kernels).
Because the pipeline force-inlines all Rust code into the entry programs,
every trap sits inside an entry function, and returning the cookie from it
is the same observable exit as bpf_throw. Traps in void functions become
`ret void` (cookie lost, still a clean exit); an unpaired trap is left for
the verifier to reject loudly.

Usage: trap_to_ret.py in.ll out.ll cookie
"""
import re
import sys

in_ll, out_ll, cookie = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
lines = open(in_ll).read().split('\n')
out = []
ret_ty = None
i = 0
rewritten = 0
while i < len(lines):
    line = lines[i]
    m = re.match(r'^define\s.*?\s(\S+)\s@[A-Za-z0-9_.$"]+\(', line)
    if m:
        ret_ty = m.group(1)
    if (re.match(r'^\s*(?:tail\s+)?call void @llvm\.trap\(\)', line)
            and i + 1 < len(lines) and lines[i + 1].strip().startswith('unreachable')
            and ret_ty is not None):
        if ret_ty == 'void':
            out.append('  ret void')
        elif re.fullmatch(r'i\d+', ret_ty):
            out.append(f'  ret {ret_ty} {cookie}')
        else:
            out.append(line)
            i += 1
            continue
        rewritten += 1
        i += 2
        continue
    out.append(line)
    i += 1
open(out_ll, 'w').write('\n'.join(out))
print(f'[trap_to_ret] {rewritten} trap(s) -> ret {cookie:#x}', file=sys.stderr)
