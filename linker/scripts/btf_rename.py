#!/usr/bin/env python3
"""Normalize Rust-origin BTF integer type names to C canonical names.

rustc's DWARF names primitives "u64", "i32", ... and llc carries those names
into .BTF. bpftool gen skeleton emits struct members using those BTF names
verbatim, so harness C code that expects C integer types ("unsigned long
long" etc., with matching printf formats) breaks. Renaming the base INT
types makes Rust-built objects indistinguishable from clang-built ones at
the skeleton level.

Strings are appended to the BTF string table (offsets of existing strings
never change, so .BTF.ext line-info references stay valid) and the grown
.BTF payload is appended at EOF with its section header repointed — never
via llvm-objcopy --update-section, whose section-table rewrite corrupts
.rel.BTF's sh_info nondeterministically.

Additionally, sanitize type names that are not valid BTF identifiers: the
kernel rejects the whole .BTF blob (-EINVAL at load, libbpf then silently
drops BTF) if any named type contains characters outside [A-Za-z0-9_].
Rust generics reach BTF as e.g. "BpfMap<u32, val, 1, 1>"; type names of
map-def structs are not load-bearing, so they are rewritten to
"BpfMap_u32__val__1__1_". Names that are already valid are never touched.

Usage: btf_rename.py <obj.o>
"""

import os
import re
import struct
import sys

RENAME = {
    "u8": "unsigned char",
    "u16": "unsigned short",
    "u32": "unsigned int",
    "u64": "unsigned long long",
    "usize": "unsigned long",
    "i8": "signed char",
    "i16": "short",
    "i32": "int",
    "i64": "long long",
    "isize": "long",
}

BTF_KIND_INT = 1
# extra bytes after struct btf_type, per kind (vlen-dependent handled below)
FIXED_EXTRA = {1: 4, 2: 0, 3: 12, 4: None, 5: 0, 6: None, 7: 0, 8: 0, 9: 0,
               10: 0, 11: 0, 12: 0, 13: None, 14: 4, 15: None, 16: 0,
               17: 4, 18: 0, 19: None}
PER_VLEN = {4: 12, 6: 8, 13: 8, 15: 12, 19: 12}  # struct/union share kind 4? no:
# kinds: 1 INT, 2 PTR, 3 ARRAY, 4 STRUCT, 5 UNION(=vlen*12), 6 ENUM, 7 FWD,
# 8 TYPEDEF, 9 VOLATILE, 10 CONST, 11 RESTRICT, 12 FUNC, 13 FUNC_PROTO,
# 14 VAR, 15 DATASEC, 16 FLOAT, 17 DECL_TAG, 18 TYPE_TAG, 19 ENUM64
FIXED_EXTRA[5] = None
PER_VLEN[5] = 12


# --- Minimal ELF64-LE section access -----------------------------------
#
# llvm-objcopy's --update-section nondeterministically corrupts the
# rewritten .rel.BTF section header's sh_info (reproduced on
# cgroup_iter_memcg, originally seen on stacktrace_map). ELF section data
# need not be contiguous or ordered, so growing a section safely is just:
# append the new payload at EOF and patch that one section header's
# sh_offset/sh_size — nothing else in the file moves.

def elf_find_section(buf, want):
    assert buf[:4] == b"\x7fELF" and buf[4] == 2 and buf[5] == 1, \
        "not an ELF64-LE object"
    (e_shoff,) = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3A)

    def shdr(i):
        base = e_shoff + i * e_shentsize
        sh_name, = struct.unpack_from("<I", buf, base)
        sh_offset, sh_size = struct.unpack_from("<QQ", buf, base + 24)
        sh_addralign, = struct.unpack_from("<Q", buf, base + 48)
        return base, sh_name, sh_offset, sh_size, sh_addralign

    _, _, stroff, _, _ = shdr(e_shstrndx)
    for i in range(e_shnum):
        base, sh_name, sh_offset, sh_size, sh_addralign = shdr(i)
        end = buf.index(b"\0", stroff + sh_name)
        if buf[stroff + sh_name:end].decode() == want:
            return base, sh_offset, sh_size, sh_addralign
    raise KeyError(f"no section {want}")


def main(path, objcopy=None):
    buf = bytearray(open(path, "rb").read())
    shdr_base, btf_off, btf_size, btf_align = elf_find_section(buf, ".BTF")
    data = bytearray(buf[btf_off:btf_off + btf_size])

    magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
        struct.unpack_from("<HBBIIIII", data, 0)
    assert magic == 0xEB9F, hex(magic)

    types_base = hdr_len + type_off
    str_base = hdr_len + str_off

    def get_str(off):
        end = data.index(b"\0", str_base + off)
        return data[str_base + off:end].decode()

    new_strings = bytearray()
    appended = {}  # name -> new offset

    def intern(name):
        if name not in appended:
            appended[name] = str_len + len(new_strings)
            new_strings.extend(name.encode() + b"\0")
        return appended[name]

    valid_ident = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    pos = types_base
    end = types_base + type_len
    renamed = 0
    sanitized = 0
    while pos < end:
        name_off, info, _ = struct.unpack_from("<III", data, pos)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        if name_off:
            name = get_str(name_off)
            if kind == BTF_KIND_INT and name in RENAME:
                struct.pack_into("<I", data, pos, intern(RENAME[name]))
                renamed += 1
            # DATASEC (15) names are section names (".maps", ".bss", ...):
            # the kernel validates those with section-name rules, dots are
            # legal and load-bearing for libbpf — never touch them. INT
            # names are C type names where spaces are legal ("long
            # unsigned int" is all over vmlinux BTF) — exempt too.
            # DECL_TAG (17) names are kernel-recognized annotations whose
            # syntax includes ':' ("arg:arena", "exception_callback:f") —
            # sanitizing them breaks verifier features that key on them.
            elif kind not in (15, 17, BTF_KIND_INT) and not valid_ident.match(name):
                struct.pack_into(
                    "<I", data, pos, intern(re.sub(r"[^A-Za-z0-9_]", "_", name)))
                sanitized += 1
        extra = FIXED_EXTRA.get(kind)
        if extra is None:
            extra = vlen * PER_VLEN[kind]
        pos += 12 + extra

    if not renamed and not sanitized:
        return

    # string table is the last section in the .BTF blob; append and fix str_len
    assert str_base + str_len == len(data), "string table not at end of .BTF"
    data.extend(new_strings)
    struct.pack_into("<I", data, 20, str_len + len(new_strings))

    # Append the grown .BTF at EOF (aligned) and repoint its header.
    align = max(btf_align, 1)
    pad = (-len(buf)) % align
    new_off = len(buf) + pad
    buf.extend(b"\0" * pad)
    buf.extend(data)
    struct.pack_into("<QQ", buf, shdr_base + 24, new_off, len(data))
    open(path, "wb").write(buf)
    print(f"[btf_rename] {os.path.basename(path)}: "
          f"renamed {renamed} int type(s), sanitized {sanitized} name(s)")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
