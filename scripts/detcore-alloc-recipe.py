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
  fixed_detcore_got_discriminate does, by those differing operands;
- whichever structure is used, EVERY one of its GOT operands must resolve,
  through the body's RIP-relative slot and that slot's unique
  R_X86_64_RELATIVE addend, to the one local function lib.rs names for its key
  (FIXED_SUPPORT_ROLE_SYMBOLS or FIXED_EMITTED_ROLE_SYMBOLS). This holds also
  when a single structure fits. No match, more than one structure left, or a
  GOT operand bound to another callee is a refusal (exit 3): such a body needs
  a reviewed operand derivation, not a guess.

--self-test (no ELF needed) checks that every 241-byte row is in the canonical
form the generator prints, and that every generated row agrees with its own
provenance comment: the recorded body SHA256, the recorded INSTALLATION_DEPTH
cell against the encoded read, and the operands and transfers of the cited
masked-equal row (and the cited selecting GOT callee). It then runs controls
that must be refused: a hand-edited encoded cell, operand displacement and
recorded digest; and, on a synthetic ELF built from each generated row, every
GOT operand bound to another callee, and the case where the only masked-equal
structure names a callee the ELF does not bind.

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


def symbol_table(text: str, name: str) -> list[tuple[str, str]]:
    start = text.index(f"const {name}: &[(&str, &str)] = &[")
    table = text[start:text.index("\n];", start)]
    return re.findall(r'\(\s*"([a-z0-9_]+)",\s*"(_R[^"]+)",?\s*\)', table)


def parse_lib(text: str):
    role = re.search(r'^const FIXED_TLS_CELL_ROLE: &str = "([^"]+)";', text, re.M)
    require(role is not None, "lib.rs: FIXED_TLS_CELL_ROLE not found")
    # Key -> every spelling lib.rs gives its function, from both role tables.
    support: dict[str, set[str]] = {}
    for table in ("FIXED_SUPPORT_ROLE_SYMBOLS", "FIXED_EMITTED_ROLE_SYMBOLS"):
        for key, spelling in symbol_table(text, table):
            support.setdefault(key, set()).add(spelling)
    spellings = set(re.findall(r'\(\s*"' + ROLE + r'",\s*"(_R[^"]+)",\s*\)', text))
    require(bool(spellings), f"lib.rs: no {ROLE} role spellings found")
    start = text.index("const DETCORE_VALIDATE_TEMPLATES: &[DetcoreValidateTemplate] = &[")
    end = text.index("\n];", start)
    rows = []
    pattern = re.compile(
        r'((?:[ \t]*//[^\n]*\n)*)[ \t]*DetcoreValidateTemplate \{\s*role: "' + ROLE + r'",\s*'
        r'hex: "([0-9a-f]+)",\s*operands: &\[(.*?)\],\s*transfers: &\[(.*?)\],\s*\},', re.S)
    for match in pattern.finditer(text, start, end):
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


def structure_of(row):
    return (tuple(row["operands"]), tuple(row["transfers"]))


def got_mismatches(elf: Elf, address: int, body: bytes, structure, support: dict[str, set[str]],
                   got: dict[int, int], only: set[int] | None = None) -> list[str]:
    """Every GOT operand of `structure` (or only those indexed by `only`) whose
    RIP-relative slot does not carry a unique R_X86_64_RELATIVE addend equal to
    the one local function lib.rs names for its key. A key lib.rs names no
    function for cannot be verified and is reported too."""

    functions: dict[str | None, set[int]] = {}
    for name, value, size, kind, _bind, _shndx in elf.symbols(".symtab", ".strtab"):
        if kind == STT_FUNC and size > 0:
            functions.setdefault(canonical_rust_symbol(name), set()).add(value)
    bad = []
    for index, (displacement, nxt, key, is_got) in enumerate(structure[0]):
        if not is_got or (only is not None and index not in only):
            continue
        targets = set().union(*(functions.get(s, set()) for s in support.get(key, ())))
        slot = address + nxt + struct.unpack_from("<i", body, displacement)[0]
        if len(targets) != 1 or got.get(slot) not in targets:
            bound = f"{got[slot]:#x}" if slot in got else "no unique RELATIVE"
            bad.append(f"{key}@{displacement} (slot {slot:#x} -> {bound}; "
                       f"lib.rs names {sorted(hex(t) for t in targets) or 'no function in this ELF'})")
    return bad


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


def derive(data: bytes, text: str, toolchain: str, profile: str, features: str,
           command: str) -> tuple[int, str, str]:
    """(exit code, row text, diagnostics) for one ELF against lib.rs."""

    try:
        elf = Elf(data)
        tls_role, spellings, rows, support = parse_lib(text)
        _cell_name, cell, (filesz, memsz) = fixed_tls_cell(elf, tls_role)
        funcs = [s for s in elf.symbols(".symtab", ".strtab")
                 if s[3] == STT_FUNC and s[2] > 0 and canonical_rust_symbol(s[0]) in spellings]
        require(len(funcs) == 1, f"{ROLE}: {len(funcs)} symbols carry a census spelling, expected exactly 1")
        name, address, size = funcs[0][0], funcs[0][1], funcs[0][2]
        require(size == BODY_LEN, f"{ROLE} is {size} bytes, not the {BODY_LEN}-byte TLS-arm body")
        body = elf.read_va(address, size)
        encoded = struct.unpack_from("<I", body, TLS_DISPLACEMENT[0])[0]
        require(encoded == cell, f"{ROLE} reads TLS cell {encoded:#x}, but INSTALLATION_DEPTH is {cell:#x}")
        versions = sorted({m.group(1) for c in elf.comment() for m in [re.search(r"rustc version (\S+)", c)] if m})
        require(len(versions) == 1 and versions[0] in toolchain.split(),
                f"--toolchain {toolchain!r} does not name the ELF's rustc version {versions}")
    except Refusal as refusal:
        return 2, "", f"detcore-alloc-recipe: REFUSED: {refusal}"
    notes = []
    identical = [r for r in rows if r["hex"] == body.hex()]
    if identical:
        notes.append(f"detcore-alloc-recipe: body already present verbatim at lib.rs:{identical[0]['line']}")
    fitting = [r for r in rows if matches(body, r)]
    structures = {structure_of(r) for r in fitting}
    got = elf.relative_got()
    callees: list[str] = []
    if len(structures) > 1:
        ordered = sorted(structures)
        differing = {i for i in range(len(ordered[0][0]))
                     if len({s[0][i][2] for s in ordered}) > 1}
        layouts = {tuple((d, n, g) for d, n, _k, g in s[0]) + s[1] for s in ordered}
        if len(layouts) == 1 and all(ordered[0][0][i][3] for i in differing):
            structures = {s for s in ordered
                          if not got_mismatches(elf, address, body, s, support, got, differing)}
            fitting = [r for r in fitting if structure_of(r) in structures]
            if len(structures) == 1:
                chosen = next(iter(structures))[0]
                callees = [chosen[i][2] for i in sorted(differing)]
    if len(structures) != 1:
        notes.append(f"detcore-alloc-recipe: REFUSED: {len(structures)} operand structures fit this body "
                     f"(rows at lib.rs lines {[r['line'] for r in fitting]}); derive its operands by review")
        return 3, "", "\n".join(notes)
    pattern = fitting[0]
    # The structure that is used, however it was selected, binds every GOT
    # operand to the callee its key names; a lone masked-equal structure that
    # names another callee is refused, never emitted.
    bad = got_mismatches(elf, address, body, structure_of(pattern), support, got)
    if bad:
        notes.append(f"detcore-alloc-recipe: REFUSED: the masked-equal structure at lib.rs:{pattern['line']} "
                     f"names GOT callees the ELF does not bind: {'; '.join(bad)}")
        return 3, "", "\n".join(notes)
    sha = hashlib.sha256(data).hexdigest()
    build_id = elf.build_id() or "none (no NT_GNU_BUILD_ID note)"
    comment = " / ".join(c for c in elf.comment() if "rustc" in c) or "(no rustc .comment)"
    row = "\n".join([
        f"    {GENERATED_MARK} from a real ELF; compare, never hand-edit.",
        f"    // Toolchain: {toolchain}; ELF .comment: {comment}.",
        f"    // Profile {profile}; features {features}.",
        f"    // ELF SHA256 {sha}; build-id: {build_id}.",
        f"    // {ROLE} {name} at VA {address:#x}, {size} bytes; INSTALLATION_DEPTH LOCAL8 cell {cell:#x}"
        f" (PT_TLS filesz {filesz:#x}, memsz {memsz:#x}).",
        f"    // Operands and transfers: those of the masked-equal row with body SHA256"
        f" {hashlib.sha256(bytes.fromhex(pattern['hex'])).hexdigest()}"
        + (f", selected by bound GOT callee {', '.join(callees)}." if callees else "."),
        f"    // Command: {command}",
        f"    // Complete {size}-byte body SHA256: {hashlib.sha256(body).hexdigest()}.",
        render(body, pattern),
    ])
    return 0, row, "\n".join(notes)


GENERATED_MARK = "// Generated by scripts/detcore-alloc-recipe.py"


def provenance_violations(row, rows) -> list[str]:
    """For a generated row, everything its provenance comment claims that its
    own content can be checked against: the body digest, the TLS cell its
    read encodes, and the operand/transfer structure of the cited row."""

    comment, body = row["comment"], bytes.fromhex(row["hex"])
    bad = []
    digest = re.search(r"Complete (\d+)-byte body SHA256: ([0-9a-f]{64})\.", comment)
    if digest is None or int(digest.group(1)) != len(body) \
            or digest.group(2) != hashlib.sha256(body).hexdigest():
        bad.append("body SHA256 differs from the provenance comment")
    cell = re.search(r"INSTALLATION_DEPTH LOCAL8 cell (0x[0-9a-f]+)", comment)
    if cell is None or body[TLS_DISPLACEMENT[0]:TLS_DISPLACEMENT[1]] != int(cell.group(1), 16).to_bytes(4, "little"):
        bad.append("encoded TLS read differs from the recorded INSTALLATION_DEPTH cell")
    cited = re.search(r"masked-equal row with body SHA256 ([0-9a-f]{64})"
                      r"(?:, selected by bound GOT callee ([a-z0-9_, ]+))?\.", comment)
    if cited is None:
        bad.append("no cited masked-equal row")
        return bad
    sources = [r for r in rows if GENERATED_MARK not in r["comment"]
               and hashlib.sha256(bytes.fromhex(r["hex"])).hexdigest() == cited.group(1)]
    same = [r for r in sources if structure_of(r) == structure_of(row) and matches(body, r)]
    if not same:
        bad.append("operands/transfers are not those of the cited masked-equal row")
    elif cited.group(2):
        structures = {structure_of(r) for r in sources}
        differing = sorted({i for i in range(len(row["operands"]))
                            if len({s[0][i][2] for s in structures}) > 1})
        if [row["operands"][i][2] for i in differing] != [k.strip() for k in cited.group(2).split(",")]:
            bad.append("the cited selecting GOT callee is not this row's")
    return bad


def check_rows(text: str) -> tuple[int, list[str]]:
    """(241-byte row count, failures) for every row of the table."""

    _role, _spellings, rows, _support = parse_lib(text)
    lines = text.splitlines()
    failures = []
    count = 0
    for row in rows:
        body = bytes.fromhex(row["hex"])
        if len(body) != BODY_LEN:
            continue
        count += 1
        start = row["line"] - 3
        rendered = render(body, row).splitlines()
        if lines[start:start + len(rendered)] != rendered:
            failures.append(f"row at lib.rs:{row['line']} is not in canonical form")
        if GENERATED_MARK in row["comment"]:
            failures += [f"generated row at lib.rs:{row['line']}: {v}" for v in provenance_violations(row, rows)]
    return count, failures


def synthetic_elf(body: bytes, address: int, structure, support: dict[str, set[str]],
                  bind: dict[str, str], tls_role: str, alloc_spelling: str, rustc: str) -> bytes:
    """A minimal ELF64 carrying `body` as fixed_patch_alloc at `address`, the
    INSTALLATION_DEPTH cell the body reads, and for each GOT operand a unique
    R_X86_64_RELATIVE slot naming the local function `bind[key]` (default:
    the key itself) spells. Crate disambiguators are made non-empty."""

    def spelled(name: str) -> str:
        return name.replace("Cs_", "CsTest_")

    cell = struct.unpack_from("<I", body, TLS_DISPLACEMENT[0])[0]
    strtab, symbols, relocations = bytearray(b"\0"), [], []

    def symbol(name: str, info: int, shndx: int, value: int, size: int) -> None:
        symbols.append(struct.pack("<IBBHQQ", len(strtab), info, 0, shndx, value, size))
        strtab.extend(name.encode() + b"\0")

    symbols.append(bytes(24))
    symbol(spelled(tls_role), (STB_LOCAL << 4) | STT_TLS, 1, cell, 8)
    symbol(spelled(alloc_spelling), (STB_LOCAL << 4) | STT_FUNC, 2, address, len(body))
    placed: dict[str, int] = {}
    for displacement, nxt, key, is_got in structure[0]:
        if not is_got:
            continue
        callee = bind.get(key, key)
        if callee not in placed:
            placed[callee] = 0x10000 + 0x100 * len(placed)
            symbol(spelled(sorted(support[callee])[0]), (STB_LOCAL << 4) | STT_FUNC, 2,
                   placed[callee], 16)
        slot = address + nxt + struct.unpack_from("<i", body, displacement)[0]
        relocations.append(struct.pack("<QQq", slot, 8, placed[callee]))
    comment = f"rustc version {rustc}\0".encode()
    names = b"\0.tbss\0.text\0.symtab\0.strtab\0.rela.dyn\0.comment\0.shstrtab\0"
    blobs = [body, b"".join(symbols), bytes(strtab), b"".join(relocations), comment, names]
    offsets, cursor = [], 64 + 2 * 56
    for blob in blobs:
        cursor = (cursor + 7) & ~7
        offsets.append(cursor)
        cursor += len(blob)
    shoff = (cursor + 7) & ~7

    def name_at(name: bytes) -> int:
        return names.index(b"\0" + name + b"\0") + 1

    sections = [bytes(64)]
    for name, kind, flags, addr, blob, link, entsize in [
        (b".tbss", SHT_NOBITS, SHF_WRITE | SHF_ALLOC | SHF_TLS, 0, None, 0, 0),
        (b".text", 1, SHF_ALLOC | SHF_EXECINSTR, address, 0, 0, 0),
        (b".symtab", 2, 0, 0, 1, 4, 24),
        (b".strtab", 3, 0, 0, 2, 0, 0),
        (b".rela.dyn", 4, SHF_ALLOC, 0, 3, 0, 24),
        (b".comment", 1, 0, 0, 4, 0, 1),
        (b".shstrtab", 3, 0, 0, 5, 0, 0),
    ]:
        offset, size = (offsets[0], 0x20) if blob is None else (offsets[blob], len(blobs[blob]))
        sections.append(struct.pack("<IIQQQQIIQQ", name_at(name), kind, flags, addr, offset, size,
                                    link, 0, 8, entsize))
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 3, 62, 1, 0, 64, shoff, 0, 64, 56, 2, 64,
                     len(sections), len(sections) - 1)
    phdrs = struct.pack("<IIQQQQQQ", PT_LOAD, 5, offsets[0], address, address, len(body), len(body), 0x1000)
    phdrs += struct.pack("<IIQQQQQQ", PT_TLS, 4, offsets[0], 0, 0, cell, cell + 0x20, 8)
    image = bytearray(header + phdrs)
    for offset, blob in zip(offsets, blobs):
        image.extend(bytes(offset - len(image)))
        image.extend(blob)
    image.extend(bytes(shoff - len(image)))
    image.extend(b"".join(sections))
    return bytes(image)


def generated_block(text: str, row) -> str:
    """The generated row's provenance comment plus its template, as in lib.rs."""

    at = text.index(f'hex: "{row["hex"]}"')
    start = text.rindex("\n", 0, text.rindex(GENERATED_MARK, 0, at)) + 1
    return text[start:text.index("\n    },", at) + len("\n    },")]


def self_test(text: str) -> int:
    """Every 241-byte row is in canonical form; every generated row's content
    agrees with its provenance comment; and each control below is refused."""

    count, failures = check_rows(text)
    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    tls_role, spellings, rows, support = parse_lib(text)
    generated = [r for r in rows if GENERATED_MARK in r["comment"] and len(r["hex"]) == 2 * BODY_LEN]
    controls = 0

    def control(ok: bool, message: str) -> None:
        nonlocal controls
        controls += 1
        if not ok:
            failures.append(f"control: {message}")
            print(f"self-test: control: {message}", file=sys.stderr)

    for row in generated:
        body, block = bytes.fromhex(row["hex"]), generated_block(text, row)
        where = f"lib.rs:{row['line']}"
        if provenance_violations(row, rows):
            # Already reported; its controls would test a row that is wrong.
            continue
        # Hand edits the canonical-form check alone accepts; each is refused.
        cell_at = 2 * TLS_DISPLACEMENT[0]
        first = row["operands"][0]
        moved = row["hex"][:cell_at] + f"{(body[66] + 8) & 0xff:02x}" + row["hex"][cell_at + 2:]
        for label, edited in {
            "encoded TLS cell": block.replace(row["hex"], moved),
            # The same edit with its digest re-recorded: only the recorded
            # cell can refuse it.
            "encoded TLS cell, digest re-recorded": block.replace(row["hex"], moved).replace(
                hashlib.sha256(body).hexdigest(), hashlib.sha256(bytes.fromhex(moved)).hexdigest()),
            "operand displacement": block.replace(
                f"displacement: {first[0]},", f"displacement: {first[0] - 1},", 1),
            "recorded body SHA256": re.sub(r"(body SHA256: )[0-9a-f]{64}", r"\g<1>" + "0" * 64, block),
        }.items():
            control(edited != block and bool(check_rows(text.replace(block, edited))[1]),
                    f"a hand-edited {label} in {where} was not refused")
        # The generator derives this row from an ELF whose GOT binds the
        # row's callees, and refuses when it binds any other callee.
        alloc, rustc = sorted(spellings)[0], "0.0.0-selftest"
        args = (rustc, "selftest", "selftest", "selftest")

        def elf_for(bind: dict[str, str]) -> bytes:
            return synthetic_elf(body, 0x1372580, structure_of(row), support, bind, tls_role, alloc, rustc)

        rc, emitted, notes = derive(elf_for({}), text, *args)
        control(rc == 0 and render(body, row) in emitted,
                f"the synthetic ELF for {where} did not derive its row (rc {rc}: {notes})")
        got_keys = [op[2] for op in row["operands"] if op[3]]
        for key in got_keys:
            other = next(k for k in got_keys + sorted(support) if k != key and k in support)
            rc, _emitted, _notes = derive(elf_for({key: other}), text, *args)
            control(rc == 3, f"{where}: GOT operand {key} bound to {other}'s function was not refused (rc {rc})")
        # The reviewed case: the only masked-equal structure names a callee the
        # ELF does not bind. Drop the generated row and rekey its source rows.
        sources = [r for r in rows if r is not row and GENERATED_MARK not in r["comment"]
                   and structure_of(r) == structure_of(row) and matches(body, r)]
        twins = {structure_of(r) for r in rows if r is not row and GENERATED_MARK not in r["comment"]
                 and matches(body, r)} - {structure_of(row)}
        index = next((i for i, op in enumerate(row["operands"]) if op[3]
                      and any(t[0][i][2] != op[2] for t in twins)),
                     max(i for i, op in enumerate(row["operands"]) if op[3]))
        right = row["operands"][index][2]
        wrong = next((t[0][index][2] for t in twins if t[0][index][2] != right),
                     next(k for k in sorted(support) if k != right))
        rekeyed = text.replace(block + "\n", "")
        for source in sources:
            operands = [op if i != index else (op[0], op[1], wrong, op[3]) for i, op in enumerate(source["operands"])]
            original = render(bytes.fromhex(source["hex"]), source)
            rekeyed = rekeyed.replace(original, render(bytes.fromhex(source["hex"]), {**source, "operands": operands}), 1)
        rc, _emitted, notes = derive(elf_for({}), rekeyed, *args)
        control(bool(sources) and rc == 3,
                f"{where}: with {right} rekeyed to {wrong} in every source row, the lone wrong structure "
                f"was not refused (rc {rc})")
    print(f"self-test: {count} {BODY_LEN}-byte {ROLE} rows ({len(generated)} generated), "
          f"{controls} controls, {len(failures)} failure(s)")
    return 1 if failures or count == 0 else 0


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
    rc, row, notes = derive(args.elf.read_bytes(), args.lib.read_text(), args.toolchain,
                            args.profile, args.features, args.command)
    if notes:
        print(notes, file=sys.stderr)
    if row:
        print(row)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
