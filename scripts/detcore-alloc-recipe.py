#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.
"""Derive a DETCORE_VALIDATE_TEMPLATES fixed_patch_alloc row from a real ELF.

The row's bytes, its TLS cell and its provenance are read from the ELF; the
expected identities are read from reverie-liteinst-artifact/src/lib.rs, so
nothing in the emitted row is typed by hand:

- the INSTALLATION_DEPTH cell follows fixed_tls_cell: exactly one symbol whose
  canonical name is FIXED_TLS_CELL_ROLE, STT_TLS, STB_LOCAL, size 8, 8-aligned,
  absent from .dynsym, in an allocated writable TLS NOBITS section, wholly
  inside the single PT_TLS segment's zero-fill extent, and overlapped by no
  other TLS identity;
- the allocation body is the one function whose canonical name is a
  "fixed_patch_alloc" spelling in lib.rs's role census, read through the
  PT_LOAD segment that maps it, and its little-endian bytes [66..70] must equal
  the cell (the binding the qualifier checks at its TLS boundary);
- the ELF's .comment must name exactly one rustc version, and --toolchain must
  carry that version as one of its words, so the provenance cannot name a
  compiler other than the one that built the image;
- the operand and transfer structure is taken from the existing 241-byte
  fixed_patch_alloc rows: a row matches when every byte outside its declared
  relocation operands and the TLS displacement [66..70] is equal. The new row
  keeps that structure with the ELF's own bytes. Structures that differ only
  in the named callee of a GOT operand are discriminated the way
  fixed_detcore_got_discriminate does: a structure is kept only when every
  differing GOT operand (and every other GOT operand whose key
  FIXED_SUPPORT_ROLE_SYMBOLS names) resolves, through the body's RIP-relative
  slot and that slot's unique R_X86_64_RELATIVE addend, to the local function
  the key names. No match, or more than one structure left, is a refusal
  (exit 3): such a body needs a reviewed operand derivation, not a guess.

Usage:
  detcore-alloc-recipe.py --self-test --lib reverie-liteinst-artifact/src/lib.rs
  detcore-alloc-recipe.py ELF --lib reverie-liteinst-artifact/src/lib.rs \
      --toolchain "$(rustc -vV | head -1)" --profile liteinst-runtime \
      --features exec-native-injection --command "cargo build ..."

Prints the row, preceded by its provenance comment, on stdout. Exit 0: a row
was derived (or the body already has an identical row, which is reported);
2: the ELF fails a derivation constraint; 3: no single operand structure fits.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from pathlib import Path

ROLE = "fixed_patch_alloc"
BODY_LEN = 241
TLS_DISPLACEMENT = (66, 70)
STT_FUNC, STT_TLS, STB_LOCAL = 2, 6, 0
SHT_NOBITS, SHT_NOTE = 8, 7
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, SHF_TLS = 0x1, 0x2, 0x4, 0x400
PT_LOAD, PT_NOTE, PT_TLS = 1, 4, 7
NT_GNU_BUILD_ID = 3
SHN_UNDEF = 0


class Refusal(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


def canonical_rust_symbol(name: str) -> str | None:
    """lib.rs canonical_rust_symbol: drop a numeric .llvm. suffix and every
    crate disambiguator (Cs<alnum>_ -> Cs_); None when malformed."""

    plain = name
    if ".llvm." in name:
        plain, suffix = name.split(".llvm.", 1)
        if not suffix or not suffix.isdigit():
            return None
    out, rest = [], plain
    while (offset := rest.find("Cs")) >= 0:
        out.append(rest[:offset])
        rest = rest[offset + 2:]
        end = 0
        while end < len(rest) and rest[end].isascii() and rest[end].isalnum():
            end += 1
        if end == 0 or rest[end:end + 1] != "_":
            return None
        out.append("Cs_")
        rest = rest[end + 1:]
    out.append(rest)
    return "".join(out)


class Elf:
    def __init__(self, data: bytes) -> None:
        require(data[:4] == b"\x7fELF" and data[4] == 2 and data[5] == 1,
                "not a little-endian ELF64 file")
        self.data = data
        (self.e_phoff, self.e_shoff) = struct.unpack_from("<QQ", data, 0x20)
        (self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = struct.unpack_from("<HHHHH", data, 0x36)
        self.phdrs = [struct.unpack_from("<IIQQQQQQ", data, self.e_phoff + i * self.e_phentsize)
                      for i in range(self.e_phnum)]
        self.shdrs = [struct.unpack_from("<IIQQQQIIQQ", data, self.e_shoff + i * self.e_shentsize)
                      for i in range(self.e_shnum)]
        shstr = self.shdrs[self.e_shstrndx]
        self.shstrtab = data[shstr[4]:shstr[4] + shstr[5]]

    def section_name(self, index: int) -> str:
        return self._cstr(self.shstrtab, self.shdrs[index][0])

    @staticmethod
    def _cstr(table: bytes, offset: int) -> str:
        end = table.index(b"\0", offset)
        return table[offset:end].decode("utf-8", "replace")

    def section(self, name: str):
        hits = [i for i in range(len(self.shdrs)) if self.section_name(i) == name]
        return hits[0] if len(hits) == 1 else None

    def symbols(self, table: str, strings: str):
        """(name, value, size, type, bind, shndx) for every symbol of a table."""

        index, strindex = self.section(table), self.section(strings)
        if index is None or strindex is None:
            return []
        header, strheader = self.shdrs[index], self.shdrs[strindex]
        strtab = self.data[strheader[4]:strheader[4] + strheader[5]]
        out = []
        for offset in range(header[4], header[4] + header[5], 24):
            name, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, offset)
            out.append((self._cstr(strtab, name), value, size, info & 0xF, info >> 4, shndx))
        return out

    def read_va(self, address: int, length: int) -> bytes:
        loads = [p for p in self.phdrs if p[0] == PT_LOAD
                 and p[3] <= address and address + length <= p[3] + p[5]]
        require(len(loads) == 1, f"VA {address:#x}+{length} is not inside exactly one PT_LOAD file extent")
        offset = loads[0][2] + (address - loads[0][3])
        return self.data[offset:offset + length]

    def relative_got(self) -> dict[int, int]:
        """Slot VA -> addend for slots written by exactly one R_X86_64_RELATIVE."""

        seen: dict[int, list[int]] = {}
        for index, header in enumerate(self.shdrs):
            if header[1] != 4:  # SHT_RELA
                continue
            for offset in range(header[4], header[4] + header[5], 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", self.data, offset)
                if r_info & 0xFFFFFFFF == 8 and r_info >> 32 == 0:
                    seen.setdefault(r_offset, []).append(r_addend)
        return {slot: addends[0] for slot, addends in seen.items() if len(addends) == 1}

    def build_id(self) -> str | None:
        """The NT_GNU_BUILD_ID descriptor from any SHT_NOTE section or PT_NOTE
        segment, or None when the image carries no such note."""

        extents = [(h[4], h[5]) for h in self.shdrs if h[1] == SHT_NOTE]
        extents += [(p[2], p[5]) for p in self.phdrs if p[0] == PT_NOTE]
        for start, size in extents:
            offset, end = start, start + size
            while offset + 12 <= end:
                namesz, descsz, kind = struct.unpack_from("<III", self.data, offset)
                name_at = offset + 12
                desc_at = name_at + ((namesz + 3) & ~3)
                if kind == NT_GNU_BUILD_ID and self.data[name_at:name_at + namesz] == b"GNU\0":
                    return self.data[desc_at:desc_at + descsz].hex()
                offset = desc_at + ((descsz + 3) & ~3)
        return None

    def comment(self) -> list[str]:
        index = self.section(".comment")
        if index is None:
            return []
        header = self.shdrs[index]
        raw = self.data[header[4]:header[4] + header[5]]
        return [s.decode("utf-8", "replace") for s in raw.split(b"\0") if s]


def fixed_tls_cell(elf: Elf, role: str) -> tuple[str, int, tuple[int, int]]:
    syms = elf.symbols(".symtab", ".strtab")
    dyns = elf.symbols(".dynsym", ".dynstr")
    candidates = [s for s in syms if canonical_rust_symbol(s[0]) == role]
    require(len(candidates) == 1, "actual exact INSTALLATION_DEPTH TLS cell absent/ambiguous")
    name, value, size, kind, bind, shndx = candidates[0]
    require(kind == STT_TLS and bind == STB_LOCAL and size == 8 and value % 8 == 0
            and not any(d[0] == name for d in dyns),
            "INSTALLATION_DEPTH is not an exact nonpreemptible scalar TLS cell")
    require(0 < shndx < len(elf.shdrs), "TLS cell section absent")
    section = elf.shdrs[shndx]
    want = SHF_ALLOC | SHF_WRITE | SHF_TLS
    require(section[1] == SHT_NOBITS and section[2] & want == want and not section[2] & SHF_EXECINSTR,
            "INSTALLATION_DEPTH is not the actual zero-initialized TLS cell")
    tls = [p for p in elf.phdrs if p[0] == PT_TLS]
    require(len(tls) == 1 and value >= tls[0][5] and value + 8 <= tls[0][6] and tls[0][7] >= 8,
            "INSTALLATION_DEPTH does not join the exact image's TLS zero-fill span")
    for other in syms:
        if other[3] != STT_TLS or (other[1] == value and other[0] == name) or other[2] == 0:
            continue
        require(other[1] >= value + 8 or other[1] + other[2] <= value,
                "INSTALLATION_DEPTH has an unbound overlapping TLS identity")
    for other in dyns:
        if other[3] != STT_TLS or other[5] == SHN_UNDEF or other[2] == 0:
            continue
        require(other[1] >= value + 8 or other[1] + other[2] <= value,
                "INSTALLATION_DEPTH has a dynamic overlapping TLS identity")
    return name, value, (tls[0][5], tls[0][6])


def parse_lib(text: str):
    role = re.search(r'^const FIXED_TLS_CELL_ROLE: &str = "([^"]+)";', text, re.M)
    require(role is not None, "lib.rs: FIXED_TLS_CELL_ROLE not found")
    table = text[text.index("const FIXED_SUPPORT_ROLE_SYMBOLS: &[(&str, &str)] = &["):]
    table = table[:table.index("\n];")]
    support = dict(re.findall(r'\(\s*"([a-z0-9_]+)",\s*"(_R[^"]+)",?\s*\)', table))
    spellings = set(re.findall(r'\(\s*"' + ROLE + r'",\s*"(_R[^"]+)",\s*\)', text))
    require(bool(spellings), f"lib.rs: no {ROLE} role spellings found")
    start = text.index("const DETCORE_VALIDATE_TEMPLATES: &[DetcoreValidateTemplate] = &[")
    rows = []
    pattern = re.compile(
        r'((?:[ \t]*//[^\n]*\n)*)[ \t]*DetcoreValidateTemplate \{\s*role: "' + ROLE + r'",\s*'
        r'hex: "([0-9a-f]+)",\s*operands: &\[(.*?)\],\s*transfers: &\[(.*?)\],\s*\},', re.S)
    for match in pattern.finditer(text, start):
        operands = [(int(d), int(n), k, g == "true") for d, n, k, g in re.findall(
            r'displacement: (\d+),\s*next: (\d+),\s*key: "([^"]+)",\s*got: (true|false),',
            match.group(3))]
        transfers = [(int(a), int(b)) for a, b in re.findall(r"\((\d+), (\d+)\)", match.group(4))]
        rows.append({"comment": match.group(1).strip(), "hex": match.group(2),
                     "operands": operands, "transfers": transfers,
                     "line": text.count("\n", 0, match.start(2)) + 1})
    return role.group(1), spellings, rows, support


def matches(body: bytes, row) -> bool:
    known = bytes.fromhex(row["hex"])
    if len(known) != len(body):
        return False
    masked = set(range(*TLS_DISPLACEMENT))
    for displacement, nxt, _key, _got in row["operands"]:
        masked.update(range(displacement, nxt))
    return all(body[i] == known[i] for i in range(len(body)) if i not in masked)


def got_binds(elf: Elf, address: int, body: bytes, structure, differing: set[int],
              support: dict[str, str], got: dict[int, int]) -> bool:
    functions = {}
    for name, value, size, kind, _bind, _shndx in elf.symbols(".symtab", ".strtab"):
        if kind == STT_FUNC and size > 0:
            functions.setdefault(canonical_rust_symbol(name), set()).add(value)
    for index, (displacement, nxt, key, is_got) in enumerate(structure[0]):
        if not is_got:
            continue
        if key not in support:
            if index in differing:
                return False
            continue
        targets = functions.get(support[key], set())
        rel = struct.unpack_from("<i", body, displacement)[0]
        if len(targets) != 1 or got.get(address + nxt + rel) not in targets:
            return False
    return True


def render(body: bytes, row) -> str:
    lines = ["    DetcoreValidateTemplate {", f'        role: "{ROLE}",', f'        hex: "{body.hex()}",',
             "        operands: &["]
    for displacement, nxt, key, got in row["operands"]:
        lines += ["            DetcoreValidateOperand {", f"                displacement: {displacement},",
                  f"                next: {nxt},", f'                key: "{key}",',
                  f"                got: {'true' if got else 'false'},", "            },"]
    transfers = ", ".join(f"({a}, {b})" for a, b in row["transfers"])
    lines += ["        ],", f"        transfers: &[{transfers}],", "    },"]
    return "\n".join(lines)


def self_test(text: str) -> int:
    """Every existing 241-byte row must re-render to its exact text in lib.rs
    and must be masked-equal to itself and its own TLS read."""

    _role, _spellings, rows, _support = parse_lib(text)
    lines = text.splitlines()
    failed = 0
    for row in rows:
        body = bytes.fromhex(row["hex"])
        start = row["line"] - 3
        rendered = render(body, row).splitlines()
        if len(body) != BODY_LEN:
            continue
        if lines[start:start + len(rendered)] != rendered or not matches(body, row):
            print(f"self-test: row at lib.rs:{row['line']} does not round-trip", file=sys.stderr)
            failed += 1
    count = sum(len(bytes.fromhex(r["hex"])) == BODY_LEN for r in rows)
    print(f"self-test: {count - failed}/{count} {BODY_LEN}-byte {ROLE} rows round-trip")
    return 1 if failed or count == 0 else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("elf", type=Path, nargs="?")
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--toolchain", help="`rustc -vV` first line of the building compiler")
    parser.add_argument("--profile")
    parser.add_argument("--features")
    parser.add_argument("--command", help="the exact command that built the ELF")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test(args.lib.read_text())
    if args.elf is None or None in (args.toolchain, args.profile, args.features, args.command):
        parser.error("ELF, --toolchain, --profile, --features and --command are required")
    data = args.elf.read_bytes()
    try:
        elf = Elf(data)
        tls_role, spellings, rows, support = parse_lib(args.lib.read_text())
        cell_name, cell, (filesz, memsz) = fixed_tls_cell(elf, tls_role)
        funcs = [s for s in elf.symbols(".symtab", ".strtab")
                 if s[3] == STT_FUNC and s[2] > 0 and canonical_rust_symbol(s[0]) in spellings]
        require(len(funcs) == 1, f"{ROLE}: {len(funcs)} symbols carry a census spelling, expected exactly 1")
        name, address, size = funcs[0][0], funcs[0][1], funcs[0][2]
        require(size == BODY_LEN, f"{ROLE} is {size} bytes, not the {BODY_LEN}-byte TLS-arm body")
        body = elf.read_va(address, size)
        encoded = struct.unpack_from("<I", body, TLS_DISPLACEMENT[0])[0]
        require(encoded == cell, f"{ROLE} reads TLS cell {encoded:#x}, but INSTALLATION_DEPTH is {cell:#x}")
        versions = sorted({m.group(1) for c in elf.comment() for m in [re.search(r"rustc version (\S+)", c)] if m})
        require(len(versions) == 1 and versions[0] in args.toolchain.split(),
                f"--toolchain {args.toolchain!r} does not name the ELF's rustc version {versions}")
    except Refusal as refusal:
        print(f"detcore-alloc-recipe: REFUSED: {refusal}", file=sys.stderr)
        return 2
    identical = [r for r in rows if r["hex"] == body.hex()]
    fitting = [r for r in rows if matches(body, r)]
    structures = {(tuple(r["operands"]), tuple(r["transfers"])) for r in fitting}
    callees: list[str] = []
    if len(structures) > 1:
        ordered = sorted(structures)
        differing = {i for i in range(len(ordered[0][0]))
                     if len({s[0][i][2] for s in ordered}) > 1}
        layouts = {tuple((d, n, g) for d, n, _k, g in s[0]) + s[1] for s in ordered}
        if len(layouts) == 1 and all(ordered[0][0][i][3] for i in differing):
            got = elf.relative_got()
            structures = {s for s in ordered if got_binds(elf, address, body, s, differing, support, got)}
            fitting = [r for r in fitting if (tuple(r["operands"]), tuple(r["transfers"])) in structures]
            if len(structures) == 1:
                chosen = next(iter(structures))[0]
                callees = [chosen[i][2] for i in sorted(differing)]
    if identical:
        print(f"detcore-alloc-recipe: body already present verbatim at lib.rs:{identical[0]['line']}",
              file=sys.stderr)
    if len(structures) != 1:
        print(f"detcore-alloc-recipe: REFUSED: {len(structures)} operand structures fit this body "
              f"(rows at lib.rs lines {[r['line'] for r in fitting]}); derive its operands by review",
              file=sys.stderr)
        return 3
    pattern = fitting[0]
    sha = hashlib.sha256(data).hexdigest()
    build_id = elf.build_id() or "none (no NT_GNU_BUILD_ID note)"
    comment = " / ".join(c for c in elf.comment() if "rustc" in c) or "(no rustc .comment)"
    print("\n".join([
        "    // Generated by scripts/detcore-alloc-recipe.py from a real ELF; compare, never hand-edit.",
        f"    // Toolchain: {args.toolchain}; ELF .comment: {comment}.",
        f"    // Profile {args.profile}; features {args.features}.",
        f"    // ELF SHA256 {sha}; build-id: {build_id}.",
        f"    // {ROLE} {name} at VA {address:#x}, {size} bytes; INSTALLATION_DEPTH LOCAL8 cell {cell:#x}"
        f" (PT_TLS filesz {filesz:#x}, memsz {memsz:#x}).",
        f"    // Operands and transfers: those of the masked-equal row with body SHA256"
        f" {hashlib.sha256(bytes.fromhex(pattern['hex'])).hexdigest()}"
        + (f", selected by bound GOT callee {', '.join(callees)}." if callees else "."),
        f"    // Command: {args.command}",
        f"    // Complete {size}-byte body SHA256: {hashlib.sha256(body).hexdigest()}.",
        render(body, pattern),
    ]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
