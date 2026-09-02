#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1 OR BSD-2-Clause
"""Final IR fix-ups before llc, for a module built with panic=immediate-abort.

1. Every remaining plain `declare` (not an LLVM intrinsic, not already
   carrying a section) is an extern kfunc: tag it `section ".ksyms"` and
   give it a DISubprogram with a prototype derived from the IR signature
   (iN -> signed int of that size, ptr -> untyped pointer), so llc emits a
   BTF FUNC for it and libbpf can resolve the ksym. libbpf's kfunc
   compatibility check compares BTF kinds, not names, so the IR-derived
   prototype is enough for scalar/pointer signatures.
2. --trap-cookie=N: `llvm.trap()` becomes `bpf_throw(N)` (the verifier
   rejects any reachable __bpf_trap), declared as a kfunc like the above.
   Without it, remaining traps are left for the verifier to reject loudly.
3. Late mem libcalls the optimizer may have introduced after the
   pre-internalize lowering: llvm.memcpy/memmove -> bpf_arena_memcpy,
   memcmp/bcmp -> bpf_arena_memcmp (the module defines both, so the calls
   bind locally). llvm.memset is left alone: llc expands constant sizes
   inline and calls the module's own `memset` otherwise.
4. Declares for names the module defines are dropped.
5. `noreturn` is stripped (LLVM would delete the code after the throw),
   `unreachable` becomes a `ret` of the function's zero value (every BPF
   subprogram must end in exit or a jump), and DISubprograms of `internal`
   functions get DISPFlagLocalToUnit so their BTF linkage matches the ELF
   symbol.
6. `invoke` is refused: it means some crate was not built with
   panic=immediate-abort.

Usage: bpf_finalize.py in.ll out.ll [--trap-cookie=N]
"""
import re
import sys

ARGS = sys.argv[1:]
in_ll, out_ll = ARGS[0], ARGS[1]
trap_cookie = None
for a in ARGS[2:]:
    if a.startswith('--trap-cookie='):
        trap_cookie = int(a.split('=', 1)[1], 0)

text = open(in_ll).read()

if re.search(r'^\s+(?:%\S+\s*=\s*)?invoke\s', text, re.MULTILINE):
    sys.exit('[bpf_finalize] module contains `invoke`: build every crate '
             'with panic=immediate-abort (profile `panic = "immediate-abort"`)')

# ---- metadata allocation -------------------------------------------------
next_id = max((int(x[1:]) for x in re.findall(r'!\d+', text)), default=0) + 1
new_md = []


def md(body):
    global next_id
    i = next_id
    next_id += 1
    new_md.append(f'!{i} = {body}')
    return f'!{i}'


m = re.search(r'(!\d+) = !DIFile\(', text)
di_file = m.group(1) if m else '!0'

INT_DI = {'i1': ('char', 8), 'i8': ('char', 8), 'i16': ('short', 16),
          'i32': ('int', 32), 'i64': ('long long', 64),
          'i128': ('__int128', 128)}


def di_type(ir_ty):
    """DI node for one IR parameter/return type, or None for void/unknown."""
    if ir_ty in INT_DI:
        name, bits = INT_DI[ir_ty]
        return md(f'!DIBasicType(name: "{name}", size: {bits}, '
                  f'encoding: DW_ATE_signed)')
    if ir_ty == 'ptr' or ir_ty.startswith('ptr '):
        return md('!DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, '
                  'size: 64)')
    if ir_ty in ('float', 'double'):
        return md(f'!DIBasicType(name: "{ir_ty}", '
                  f'size: {32 if ir_ty == "float" else 64}, '
                  f'encoding: DW_ATE_float)')
    return None


PARAM_ATTRS = {'noundef', 'zeroext', 'signext', 'noalias', 'nonnull',
               'readonly', 'readnone', 'nocapture', 'dso_local',
               'extern_weak', 'local_unnamed_addr', 'unnamed_addr'}


def strip_attrs(s):
    toks = [t for t in s.strip().split() if t not in PARAM_ATTRS
            and not t.startswith('captures(') and not t.startswith('align')]
    return toks[0] if toks else ''


def subprogram_for(name, ret_ir, args_ir):
    ret = di_type(ret_ir) if ret_ir != 'void' else None
    args = []
    for a in args_ir.split(',') if args_ir.strip() else []:
        a = a.strip()
        if a and a != '...':
            args.append(di_type(strip_attrs(a)))
    types = ', '.join([ret or 'null'] + [a or 'null' for a in args])
    sub = md(f'!DISubroutineType(types: !{{{types}}})')
    return md(f'!DISubprogram(name: "{name}", scope: {di_file}, '
              f'file: {di_file}, type: {sub}, flags: DIFlagPrototyped, '
              f'spFlags: DISPFlagOptimized)')


DECL_RE = re.compile(
    r'^declare\s+(?P<pre>(?:[a-z_]+\s+)*?)(?P<ret>[\w.]+(?:\s+addrspace\(\d+\))?)'
    r'\s+@(?P<name>[A-Za-z0-9_.$]+)\((?P<args>[^)]*)\)(?P<post>[^\n]*)$',
    re.MULTILINE)


def tag_declare(m):
    line = m.group(0)
    name = m.group('name')
    if name.startswith('llvm.') or name == 'rust_eh_personality' \
            or 'section "' in line or '!dbg' in line:
        return line
    dbg = subprogram_for(name, m.group('ret'), m.group('args'))
    return (f'declare !dbg {dbg} {m.group("pre")}{m.group("ret")} @{name}'
            f'({m.group("args")}){m.group("post")} section ".ksyms"')


# attribute group shared by extern declares (any existing sectioned one)
am = re.search(r'^declare\s[^\n]*#(\d+)\s+section', text, re.MULTILINE)
attr_num = am.group(1) if am else None
attr_ref = f' #{attr_num}' if attr_num else ''

# ---- 3. late mem libcalls --------------------------------------------------
A = r'(?:[^,()]|\([^()]*\))*'
text = re.sub(
    rf'(?:tail\s+)?call void @llvm\.(?:memcpy|memmove)(?:\.inline)?\.p0\.p0\.i64\((ptr{A}),\s*(ptr{A}),\s*(i64{A}),\s*i1[^)]*\)',
    r'call void @bpf_arena_memcpy(\1, \2, \3)', text)
for old in ('memcmp', 'bcmp'):
    text = re.sub(r'^(?!define|declare)([^\n]*?)(?<![A-Za-z0-9_.])@' + old + r'\b',
                  r'\1@bpf_arena_memcmp', text, flags=re.MULTILINE)

# ---- 2. trap -> bpf_throw ------------------------------------------------
extra_decls = []
if trap_cookie is not None and re.search(r'call void @llvm\.trap\(\)', text):
    text = re.sub(r'(?:tail\s+)?call void @llvm\.trap\(\)',
                  f'call void @bpf_throw(i64 {trap_cookie})', text)
    if not re.search(r'^declare\s[^\n]*@bpf_throw\(', text, re.MULTILINE):
        dbg = subprogram_for('bpf_throw', 'void', 'i64')
        extra_decls.append(f'declare !dbg {dbg} void @bpf_throw(i64)'
                           f'{attr_ref} section ".ksyms"')

# ---- 4. drop declares of defined names ------------------------------------
defined = set(re.findall(r'^define\s[^\n]*?@([A-Za-z0-9_.$]+)\(', text,
                         re.MULTILINE))


def drop_defined(m):
    n = re.search(r'@([A-Za-z0-9_.$]+)\(', m.group(0))
    return '' if n and n.group(1) in defined else m.group(0)


text = re.sub(r'^declare\s[^\n]*\n(?:[ \t]+section[^\n]*\n)?', drop_defined,
              text, flags=re.MULTILINE)

# ---- 1. tag remaining plain declares ---------------------------------------
text = DECL_RE.sub(tag_declare, text)

# ---- 5. noreturn, unreachable, internal DI linkage -------------------------
text = re.sub(r'\bnoreturn\b', '', text)
text = re.sub(r'^(attributes #\d+ = \{)\s*\}$', r'\1 nounwind }', text,
              flags=re.MULTILINE)

for dbg_id in re.findall(r'^define\s+internal\s[^\n]*!dbg\s+(!\d+)', text,
                         re.MULTILINE):
    text = re.sub(r'(' + re.escape(dbg_id) + r' = distinct !DISubprogram\('
                  r'[^\n]*?spFlags: )(?!DISPFlagLocalToUnit)',
                  r'\1DISPFlagLocalToUnit | ', text)

out = []
ret_ty = 'void'
for line in text.split('\n'):
    dm = re.match(r'^define\s.*?\s(\S+)\s@[A-Za-z0-9_.$"]+\(', line)
    if dm:
        ret_ty = dm.group(1)
    um = re.match(r'^(\s+)unreachable\b(.*)$', line)
    if um:
        indent, rest = um.group(1), um.group(2)
        meta = re.search(r'(,\s*!dbg\s+!\d+)', rest)
        meta = meta.group(1) if meta else ''
        if ret_ty == 'void':
            line = f'{indent}ret void{meta}'
        elif re.fullmatch(r'i\d+', ret_ty):
            line = f'{indent}ret {ret_ty} 0{meta}'
        elif ret_ty.startswith('ptr'):
            line = f'{indent}ret {ret_ty} null{meta}'
        else:
            line = f'{indent}ret {ret_ty} zeroinitializer{meta}'
    out.append(line)
text = '\n'.join(out)

if extra_decls:
    text = re.sub(r'^(attributes\s)', '\n'.join(extra_decls) + '\n\n\\1',
                  text, count=1, flags=re.MULTILINE)
if new_md:
    text = text.rstrip() + '\n' + '\n'.join(new_md) + '\n'
open(out_ll, 'w').write(text)
