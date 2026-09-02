#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
"""Derive the internalize keep-list from the linked IR.

Kept global:
  - every function defined with a `section` attribute: that is every
    #[link_section]/SEC() entry program, Rust or C;
  - every global variable with a section other than llvm.metadata: the
    arena map (.maps), the license string, user .data/.rodata objects;
  - the symbols listed in --nm-list (libarena's functions, global AND
    static: they must stay outlined so the buddy allocator's loops are not
    inlined into every entry program, which blows the verifier's jump
    budget);
  - anything passed via --extra.

--drop-void-globals removes externally visible functions returning void
from the list: kernels before the void-return relaxation reject global
subprograms that do not return a scalar ("Global function X() doesn't
return scalar"), so they are internalized and verified as static
subprograms per call site instead. Keep them outlined by also passing
the nm-list to force_inline.py.

Usage: keep_syms.py linked.ll [--nm-list FILE] [--extra SYM ...]
                              [--drop-void-globals]
"""
import argparse
import re

ap = argparse.ArgumentParser()
ap.add_argument('ll')
ap.add_argument('--nm-list')
ap.add_argument('--extra', nargs='*', default=[])
ap.add_argument('--drop-void-globals', action='store_true')
args = ap.parse_args()

text = open(args.ll).read()
keep = set(args.extra)

for m in re.finditer(r'^define\s[^\n]*?@([A-Za-z0-9_.$]+)\([^\n]*?\bsection "[^"]+"',
                     text, re.MULTILINE):
    keep.add(m.group(1))

for m in re.finditer(r'^@([A-Za-z0-9_.$]+) = [^\n]*?\bsection "([^"]+)"',
                     text, re.MULTILINE):
    if m.group(2) != 'llvm.metadata':
        keep.add(m.group(1))

if args.nm_list:
    keep.update(open(args.nm_list).read().split())

if args.drop_void_globals:
    for m in re.finditer(r'^define\s(?!internal\b|private\b)[^\n]*?\bvoid @([A-Za-z0-9_.$]+)\(',
                         text, re.MULTILINE):
        keep.discard(m.group(1))

print('\n'.join(sorted(keep)))
