#!/usr/bin/env python3
"""Force-inline every non-entry function.

Arena pointers only keep their PTR_TO_ARENA typing inside the function
that performed the addr_space_cast; once a pointer round-trips through a
non-inlined subprogram it degrades to a scalar and the verifier rejects
the next dereference. C arena code re-casts at every boundary (the __arena
address space); Rust cannot express that, so every Rust helper is inlined
into the SEC("syscall") entry programs and pointers never cross a call
boundary. libarena's C functions are in the keep list and stay outlined.

Usage: force_inline.py in.ll out.ll keepfile   (prints --force-attribute
args for opt on stdout). Also strips `noinline` from ALL attribute groups:
rustc marks cold-path call SITES (RawVec::grow_one) noinline, which would
override the callee's alwaysinline.
"""
import re
import sys

in_ll, out_ll, keep_path = sys.argv[1], sys.argv[2], sys.argv[3]
keep = set(open(keep_path).read().split())
text = open(in_ll).read()

# strip noinline everywhere (function attrs AND call-site attr groups)
text = re.sub(r'^(attributes #\d+ = \{[^}]*?) ?\bnoinline\b',
              r'\1', text, flags=re.MULTILINE)

args = []
for m in re.finditer(r'^define\s[^\n]*?@([A-Za-z0-9_.$]+)\(',
                     text, re.MULTILINE):
    name = m.group(1)
    if name in keep:
        continue
    args.append(f'--force-attribute={name}:alwaysinline')

open(out_ll, 'w').write(text)
print(' '.join(args))
