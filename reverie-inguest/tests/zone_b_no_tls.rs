/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(all(
    feature = "exec-private-init",
    target_arch = "x86_64",
    target_os = "linux"
))]

//! Design-to-prototype producer check for zone B, the code that runs
//! before the FS swap or with guest FS still installed.
//!
//! This implements the recommended own-object design from
//! `2026-11-07-tls-cell-accessor-census-e-vs-c.md` section
//! "Proposed zone-B check": compile the zone-B translation units
//! into their own relocatable objects with the production recipe
//! from Hermit `liteinst-runtime-build/artifact.rs`, then refuse
//! the object set if it contains a TLS relocation, TLS
//! symbol/section, FS-relative memory operand (including the
//! `%fs:0x28` canary), an unresolved outgoing edge other than a
//! recognized swap/gate entry, or an unrecognized indirect
//! branch.
//!
//! The compile recipe below is the production recipe, including
//! `-fno-jump-tables` from https://github.com/rrnewton/hermit/pull/5293
//! (landed as 38111a07), placed immediately after
//! `-mcmodel=large` (minibeads dh-1fz4b); it removes the one
//! compiler jump table in `make_private_stack.constprop.0`. The
//! flag list itself is not duplicated here: the checker compiles
//! with `reverie_inguest::bootstrap_recipe::BOOTSTRAP_RECIPE`,
//! the single source of truth next to the sources. Hermit's
//! producer still carries its own copy today; adopting the export
//! there is a later Hermit pin-bump follow-up.
//!
//! Scope of this prototype, stated plainly:
//!
//! * The C/asm units are the bootstrap image set in
//!   `native_exec/` (`private-bootstrap.c`, `private-entry.S`,
//!   `private-fs.S`, `private-kernel-state.c`, `private-maps.c`).
//! * `private-runner.c` is excluded by name: it is an ordinary GNU
//!   PIE whose `runner_tls` sentinel intentionally validates tool
//!   TLS after the dynamic loader has established it. The checker
//!   is also run on it below to prove the exclusion is load-bearing.
//! * The Rust `global_asm!` bridges and signal entries are checked
//!   as one merged symbol range in the current test binary.
//! * `bootstrap_sigsys` and `install_before_libc` live in
//!   musl-only modules; on this gnu host they are recorded as
//!   skipped musl-only entries, not silently claimed as checked.
//! * Reading the FS segment register itself with `mov` (no
//!   memory operand) is a selector snapshot and does not touch
//!   TLS memory. FS-relative memory operands, FS segment writes
//!   and FS-base instructions refuse everywhere outside the fixed
//!   gate entries inventoried below.
//! * FS can still move through the gate: an `arch_prctl` syscall
//!   made through the fixed native gate can set FS, and a gate
//!   `ARCH_GET_FS` result can be dereferenced afterward. This
//!   checker does not inventory those sites; allowed FS-moving
//!   sites need a separate named inventory.
//! * GS-relative operands and GS-base instructions are not
//!   checked. `push; ret` and `lret`/`iretq` transfer shapes are
//!   not modeled as indirect branches.
//! * Tracked fixed-gate transfers and the three exact gate-leaf
//!   instructions are an inventory, not a control-flow proof.
//! * Callee-saved registers are kept across every call,
//!   unconditionally: the call model clears caller-saved
//!   registers, except that the call-target register, whatever
//!   its class, is kept whenever the computed callee write set
//!   does not cover it; a callee-saved call target is therefore
//!   kept even when the callee writes it (cg2r). A callee —
//!   direct, indirect, or an
//!   internal helper (CG2) — that actually clobbers a
//!   callee-saved register is therefore trusted not to, under the
//!   SysV ABI assumption for hand-written zone-B asm; that
//!   preservation is not proven here.
//! * Register rewrites performed by the kernel or a signal handler
//!   are not modelled: an `int3` in a callee, or a handler that
//!   resumes with altered registers, can change values this checker
//!   treats as preserved.
//! * An fs-prefixed `clzero` (and other instructions whose FS use
//!   iced-x86 does not surface as a memory operand above) is not
//!   refused by the FS-operand check.
//! * Any unit can declare its own `.gate` section; the checker
//!   trusts the section name for the direct-syscall inventory and
//!   does not prove the bytes are the fixed gate.
//! * In the current-exe (PIE test binary) unit, a numeric `movabs`
//!   or absolute `lea` that lands inside the scanned section is
//!   tracked as a section-qualified LocalAddress even though the
//!   PIE load base makes the literal value differ at runtime.
//! * The copies of the fs/kernel-state/maps code linked into the
//!   excluded `private-runner.c` PIE are not scanned; only the
//!   bootstrap-image units above are.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Instruction;
use iced_x86::InstructionInfoFactory;
use iced_x86::InstructionInfoOptions;
use iced_x86::Mnemonic;
use iced_x86::OpAccess;
use iced_x86::OpKind;
use iced_x86::Register;
use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use object::RelocationFlags;
use object::RelocationTarget;
use object::SectionFlags;
use object::SectionKind;
use object::SymbolKind;

const FIXED_NATIVE_ENTRY: u64 = 0x5000_0000_007c;
const FIXED_GUEST_ENTRY: u64 = 0x5000_0000_0100;

const LINKER_SYMBOLS: &[&str] = &[
    "private_boot_code_start",
    "private_boot_code_end",
    "private_boot_data_start",
    "private_boot_data_end",
];

const SWAP_SYMBOLS: &[&str] = &[
    "fixed_native_entry",
    "reverie_inguest_trusted_syscall",
    "reverie_inguest_fixed_trusted_syscall",
];

const TLS_RELOCATIONS: &[object::elf::RelocationType] = &[
    object::elf::R_X86_64_DTPMOD64,
    object::elf::R_X86_64_DTPOFF64,
    object::elf::R_X86_64_TPOFF64,
    object::elf::R_X86_64_TLSGD,
    object::elf::R_X86_64_TLSLD,
    object::elf::R_X86_64_DTPOFF32,
    object::elf::R_X86_64_GOTTPOFF,
    object::elf::R_X86_64_TPOFF32,
    object::elf::R_X86_64_GOTPC32_TLSDESC,
    object::elf::R_X86_64_TLSDESC_CALL,
    object::elf::R_X86_64_TLSDESC,
    object::elf::R_X86_64_CODE_4_GOTTPOFF,
    object::elf::R_X86_64_CODE_4_GOTPC32_TLSDESC,
    object::elf::R_X86_64_CODE_5_GOTTPOFF,
    object::elf::R_X86_64_CODE_5_GOTPC32_TLSDESC,
    object::elf::R_X86_64_CODE_6_GOTTPOFF,
    object::elf::R_X86_64_CODE_6_GOTPC32_TLSDESC,
];

#[derive(Clone, Debug)]
struct Violation {
    unit: String,
    symbol: String,
    offset: u64,
    kind: &'static str,
    detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} @{:#x}: {}",
            self.unit, self.symbol, self.offset, self.detail
        )
    }
}

#[derive(Default)]
struct Report {
    violations: Vec<Violation>,
    instructions: usize,
    recognized_indirect: usize,
    internal_movabs_indirect: usize,
    gate_leaf_uses: BTreeMap<&'static str, usize>,
    internal_edges: usize,
    units: Vec<String>,
    skipped_musl_only: Vec<&'static str>,
}

impl Report {
    fn refuse(
        &mut self,
        unit: &str,
        symbol: &str,
        offset: u64,
        kind: &'static str,
        detail: impl Into<String>,
    ) {
        self.violations.push(Violation {
            unit: unit.to_owned(),
            symbol: symbol.to_owned(),
            offset,
            kind,
            detail: detail.into(),
        });
    }

    fn summary(&self) -> String {
        format!(
            "units={} instructions={} internal_edges={} internal_movabs_indirect={} \
             recognized_indirect={} gate_leaf_uses={:?} violations={} skipped_musl_only={:?}",
            self.units.len(),
            self.instructions,
            self.internal_edges,
            self.internal_movabs_indirect,
            self.recognized_indirect,
            self.gate_leaf_uses,
            self.violations.len(),
            self.skipped_musl_only,
        )
    }
}

#[derive(Clone, Debug)]
struct SymbolInfo {
    name: String,
    address: u64,
    size: u64,
    section: Option<usize>,
    kind: SymbolKind,
    undefined: bool,
    global: bool,
}

#[derive(Clone, Debug)]
struct RelocInfo {
    offset: u64,
    r_type: object::elf::RelocationType,
    target_name: String,
    target_section: Option<usize>,
    target_address: u64,
    target_kind: Option<SymbolKind>,
    target_defined: bool,
    addend: i64,
}

#[derive(Clone, Debug)]
struct SectionInfo {
    index: usize,
    name: String,
    address: u64,
    kind: SectionKind,
    executable: bool,
    data: Vec<u8>,
    relocations: Vec<RelocInfo>,
}

#[derive(Clone, Debug)]
struct UnitSummary {
    label: String,
    relocatable: bool,
    sections: Vec<SectionInfo>,
    symbols: Vec<SymbolInfo>,
}

#[derive(Clone, Debug)]
struct ScanRange {
    unit: usize,
    section: usize,
    start: u64,
    end: u64,
    symbol: String,
}

fn summarize(label: &str, bytes: &[u8]) -> Result<UnitSummary, String> {
    let file = object::File::parse(bytes).map_err(|e| format!("{label}: parse ELF: {e}"))?;
    let relocatable = matches!(file.format(), object::BinaryFormat::Elf)
        && file.architecture().eq(&object::Architecture::X86_64)
        && bytes.get(16..18) == Some(&1_u16.to_le_bytes());
    let mut symbols = Vec::new();
    for symbol in file.symbols() {
        symbols.push(SymbolInfo {
            name: symbol.name().unwrap_or_default().to_owned(),
            address: symbol.address(),
            size: symbol.size(),
            section: symbol.section_index().map(|index| index.0),
            kind: symbol.kind(),
            undefined: symbol.is_undefined(),
            global: symbol.is_global(),
        });
    }
    let mut sections = Vec::new();
    for section in file.sections() {
        let executable = matches!(
            section.flags(),
            SectionFlags::Elf { sh_flags, .. } if sh_flags.0 & 0x4 != 0
        );
        let mut relocations = Vec::new();
        for (offset, relocation) in section.relocations() {
            let r_type = match relocation.flags() {
                RelocationFlags::Elf { r_type } => r_type,
                _ => object::elf::RelocationType(0),
            };
            let (target_name, target_section, target_address, target_kind, target_defined) =
                match relocation.target() {
                    RelocationTarget::Symbol(index) => match file.symbol_by_index(index) {
                        Ok(symbol) => (
                            symbol.name().unwrap_or_default().to_owned(),
                            symbol.section_index().map(|index| index.0),
                            symbol.address(),
                            Some(symbol.kind()),
                            !symbol.is_undefined(),
                        ),
                        Err(_) => (String::new(), None, 0, None, false),
                    },
                    RelocationTarget::Section(index) => {
                        let section = file.section_by_index(index).ok();
                        let name = section
                            .as_ref()
                            .and_then(|section| section.name().ok())
                            .unwrap_or_default()
                            .to_owned();
                        (
                            name,
                            Some(index.0),
                            section.map_or(0, |section| section.address()),
                            Some(SymbolKind::Section),
                            true,
                        )
                    }
                    RelocationTarget::Absolute => (String::new(), None, 0, None, false),
                    _ => (String::new(), None, 0, None, false),
                };
            relocations.push(RelocInfo {
                offset,
                r_type,
                target_name,
                target_section,
                target_address,
                target_kind,
                target_defined,
                addend: relocation.addend(),
            });
        }
        sections.push(SectionInfo {
            index: section.index().0,
            name: section.name().unwrap_or_default().to_owned(),
            address: section.address(),
            kind: section.kind(),
            executable,
            data: section.data().unwrap_or_default().to_vec(),
            relocations,
        });
    }
    Ok(UnitSummary {
        label: label.to_owned(),
        relocatable,
        sections,
        symbols,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tracked {
    Address(u64),
    LocalAddress {
        unit: usize,
        section: usize,
        address: u64,
    },
    Relocated {
        name: String,
        location: Option<(usize, usize, u64)>,
        symbol_start: Option<(usize, usize, u64)>,
    },
    Handler,
}

fn full_register(register: Register) -> Register {
    match register {
        Register::AL | Register::AH | Register::AX | Register::EAX => Register::RAX,
        Register::CL | Register::CH | Register::CX | Register::ECX => Register::RCX,
        Register::DL | Register::DH | Register::DX | Register::EDX => Register::RDX,
        Register::BL | Register::BH | Register::BX | Register::EBX => Register::RBX,
        Register::SPL | Register::SP | Register::ESP => Register::RSP,
        Register::BPL | Register::BP | Register::EBP => Register::RBP,
        Register::SIL | Register::SI | Register::ESI => Register::RSI,
        Register::DIL | Register::DI | Register::EDI => Register::RDI,
        Register::R8L | Register::R8W | Register::R8D => Register::R8,
        Register::R9L | Register::R9W | Register::R9D => Register::R9,
        Register::R10L | Register::R10W | Register::R10D => Register::R10,
        Register::R11L | Register::R11W | Register::R11D => Register::R11,
        Register::R12L | Register::R12W | Register::R12D => Register::R12,
        Register::R13L | Register::R13W | Register::R13D => Register::R13,
        Register::R14L | Register::R14W | Register::R14D => Register::R14,
        Register::R15L | Register::R15W | Register::R15D => Register::R15,
        other => other,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GateKind {
    Native,
    OtherSwap,
}

fn gate_kind_for_location(
    units: &[UnitSummary],
    range: &ScanRange,
    location: (usize, usize, u64),
) -> Option<GateKind> {
    SWAP_SYMBOLS.iter().find_map(|swap| {
        let (unit, symbol) = find_defined_symbol(units, range.unit, swap)?;
        let section = symbol.section?;
        (location == (unit, section, symbol.address)).then(|| {
            if *swap == "fixed_native_entry" {
                GateKind::Native
            } else {
                GateKind::OtherSwap
            }
        })
    })
}

fn tracked_gate_kind(
    units: &[UnitSummary],
    range: &ScanRange,
    target: Option<&Tracked>,
) -> Option<GateKind> {
    match target {
        Some(Tracked::Address(FIXED_NATIVE_ENTRY)) => Some(GateKind::Native),
        Some(Tracked::Address(FIXED_GUEST_ENTRY)) => Some(GateKind::OtherSwap),
        Some(Tracked::Relocated {
            name,
            location: Some(location),
            symbol_start,
        }) => {
            if let Some(kind) = gate_kind_for_location(units, range, *location) {
                Some(kind)
            } else if SWAP_SYMBOLS.contains(&name.as_str()) && *symbol_start == Some(*location) {
                if name == "fixed_native_entry" {
                    Some(GateKind::Native)
                } else {
                    Some(GateKind::OtherSwap)
                }
            } else {
                None
            }
        }
        Some(Tracked::LocalAddress {
            unit,
            section,
            address,
        }) => gate_kind_for_location(units, range, (*unit, *section, *address)),
        _ => None,
    }
}

fn tracked_gate(units: &[UnitSummary], range: &ScanRange, target: Option<&Tracked>) -> bool {
    tracked_gate_kind(units, range, target).is_some()
}

fn native_gate_return_ok(
    units: &[UnitSummary],
    range: &ScanRange,
    tracked: &BTreeMap<Register, Tracked>,
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
) -> bool {
    // A continuation inside the fixed gate template is never a
    // legitimate R12 target: the gate's own syscall/leaf/guest-entry
    // interiors (e.g. template+0x200, after which `wrpkru` runs with
    // attacker-influenced state) must not be reachable as a return
    // address (ps-r1 family). This goes through
    // `is_inside_gate_template` so the `.gate`-section fallback also
    // applies when the bounds symbols are absent or ambiguous; a
    // duplicate bound definition must not switch this check off
    // (ps-x1 family).
    let inside_template =
        |location: (usize, usize, u64)| is_inside_gate_template(units, range, location);
    match tracked.get(&Register::R12) {
        Some(Tracked::LocalAddress {
            unit,
            section,
            address,
        }) => {
            // The unit/section equality is NOT redundant with the exact
            // instruction-starts lookup: a LocalAddress established by a
            // same-section lea in one section and carried across a
            // direct jump into another section distinguishes the two
            // (s-m5z). Dropping the equality (mutant M5) is a sound
            // relaxation — it can only remove this false refusal — but
            // it is not equivalent, and the check stays deliberately.
            *unit == range.unit
                && *section == range.section
                && instruction_starts.contains(&(*unit, *section, *address))
                && !inside_template((*unit, *section, *address))
        }
        Some(Tracked::Relocated {
            location: Some(location),
            ..
        }) => instruction_starts.contains(location) && !inside_template(*location),
        _ => false,
    }
}

fn tracked_internal_movabs(
    target: Option<&Tracked>,
    ranges: &[ScanRange],
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
) -> bool {
    match target {
        Some(Tracked::Relocated {
            location: Some(location),
            ..
        }) => {
            instruction_starts.contains(location)
                && ranges
                    .iter()
                    .any(|range| (range.unit, range.section, range.start) == *location)
        }
        _ => false,
    }
}

fn meet_states(states: Vec<BTreeMap<Register, Tracked>>) -> BTreeMap<Register, Tracked> {
    let mut iter = states.into_iter();
    let Some(mut meet) = iter.next() else {
        return BTreeMap::new();
    };
    for state in iter {
        meet.retain(|register, value| state.get(register) == Some(value));
    }
    meet
}

fn symbol_info_at_unit(unit: &UnitSummary, address: u64) -> Option<&SymbolInfo> {
    unit.symbols.iter().find(|symbol| {
        !symbol.undefined
            && symbol.address == address
            && matches!(
                symbol.kind,
                SymbolKind::Text | SymbolKind::Label | SymbolKind::Unknown
            )
    })
}

fn symbol_at_unit(unit: &UnitSummary, address: u64) -> Option<&str> {
    unit.symbols
        .iter()
        .find(|symbol| {
            !symbol.undefined
                && symbol.address == address
                && matches!(
                    symbol.kind,
                    SymbolKind::Text | SymbolKind::Label | SymbolKind::Unknown
                )
        })
        .map(|symbol| symbol.name.as_str())
}

fn find_defined_symbol<'a>(
    units: &'a [UnitSummary],
    current_unit: usize,
    name: &str,
) -> Option<(usize, &'a SymbolInfo)> {
    if let Some(symbol) = units[current_unit]
        .symbols
        .iter()
        .find(|symbol| !symbol.undefined && symbol.name == name)
    {
        return Some((current_unit, symbol));
    }
    units
        .iter()
        .enumerate()
        .filter(|(_, unit)| unit.relocatable)
        .find_map(|(index, unit)| {
            unit.symbols
                .iter()
                .find(|symbol| symbol.global && !symbol.undefined && symbol.name == name)
                .map(|symbol| (index, symbol))
        })
}

fn check_units(units: &[UnitSummary], ranges: &[ScanRange]) -> Report {
    let mut report = Report {
        units: units.iter().map(|unit| unit.label.clone()).collect(),
        ..Report::default()
    };
    // Cross-unit resolution is only for the relocatable zone-B
    // object set; symbols that happen to exist in the linked test
    // binary never make a zone-B edge internal.
    let global_defined: BTreeSet<&str> = units
        .iter()
        .filter(|unit| unit.relocatable)
        .flat_map(|unit| unit.symbols.iter())
        .filter(|symbol| symbol.global && !symbol.undefined)
        .map(|symbol| symbol.name.as_str())
        .collect();

    // The template bounds are load-bearing for every interior
    // refusal, so their four names must be defined exactly once,
    // in the single relocatable unit that defines the global,
    // sectioned `fixed_native_entry`. Any other definition —
    // weak, COMMON, absolute, strong, a second-spelling pair in
    // another unit, or a unit that makes itself an "owner" with a
    // local `fixed_native_entry` label — could shadow, replace or
    // (by disagreeing) silently disable the bounds, so it refuses
    // outright (ps-x1/ps-x2/ps-n13/ps-n4 families). Only
    // relocatable units participate, matching the bounds lookup;
    // the linked test binary's symbols never define bounds.
    {
        const BOUND_NAMES: [&str; 4] = [
            "fixed_gate_template",
            "fixed_gate_template_end",
            "reverie_inguest_fixed_gate_template",
            "reverie_inguest_fixed_gate_template_end",
        ];
        // Exactly one owner: the relocatable unit holding the
        // global, sectioned `fixed_native_entry`. A local label or
        // a sectionless definition does not make a unit an owner.
        let owners: BTreeSet<usize> = units
            .iter()
            .enumerate()
            .filter(|(_, unit)| unit.relocatable)
            .filter(|(_, unit)| {
                unit.symbols.iter().any(|symbol| {
                    symbol.global
                        && !symbol.undefined
                        && symbol.section.is_some()
                        && symbol.name == "fixed_native_entry"
                })
            })
            .map(|(index, _)| index)
            .collect();
        type BoundLocations<'a> = BTreeMap<&'a str, BTreeSet<(usize, Option<usize>, u64)>>;
        let mut bound_locations: BoundLocations<'_> = BTreeMap::new();
        for (unit_index, unit) in units.iter().enumerate() {
            if !unit.relocatable {
                continue;
            }
            for symbol in &unit.symbols {
                if !symbol.undefined && BOUND_NAMES.contains(&symbol.name.as_str()) {
                    bound_locations
                        .entry(symbol.name.as_str())
                        .or_default()
                        .insert((unit_index, symbol.section, symbol.address));
                }
            }
        }
        for (unit_index, unit) in units.iter().enumerate() {
            if !unit.relocatable {
                continue;
            }
            for symbol in &unit.symbols {
                if symbol.undefined || !BOUND_NAMES.contains(&symbol.name.as_str()) {
                    continue;
                }
                let duplicated = bound_locations
                    .get(symbol.name.as_str())
                    .is_some_and(|locations| locations.len() > 1);
                if duplicated || owners.len() != 1 || !owners.contains(&unit_index) {
                    report.refuse(
                        &unit.label,
                        &symbol.name,
                        symbol.address,
                        "duplicate-gate-bounds",
                        "gate template bound name is duplicated or defined outside the fixed_native_entry unit",
                    );
                }
            }
        }
    }

    for unit in units {
        // Whole-object TLS census applies to the relocatable
        // zone-B objects. A linked test binary contributes only
        // its selected asm symbol ranges below; its std/tool TLS
        // sections are outside those ranges by construction.
        if !unit.relocatable {
            continue;
        }
        for section in &unit.sections {
            if matches!(
                section.kind,
                SectionKind::Tls | SectionKind::UninitializedTls | SectionKind::TlsVariables
            ) {
                report.refuse(
                    &unit.label,
                    &section.name,
                    section.address,
                    "tls-section",
                    "zone-B object contains a TLS section",
                );
            }
            for relocation in &section.relocations {
                if relocation.target_name == "__tls_get_addr"
                    || relocation.target_name == "__tls_get_offset"
                {
                    report.refuse(
                        &unit.label,
                        &section.name,
                        relocation.offset,
                        "tls-get-addr",
                        format!("call/reference to {}", relocation.target_name),
                    );
                } else if TLS_RELOCATIONS.contains(&relocation.r_type)
                    || relocation.target_kind == Some(SymbolKind::Tls)
                {
                    report.refuse(
                        &unit.label,
                        &section.name,
                        relocation.offset,
                        "tls-relocation",
                        format!(
                            "TLS relocation type {:?} targeting {:?}",
                            relocation.r_type, relocation.target_name
                        ),
                    );
                }
            }
        }
        for symbol in &unit.symbols {
            if symbol.kind == SymbolKind::Tls {
                report.refuse(
                    &unit.label,
                    &symbol.name,
                    symbol.address,
                    "tls-symbol",
                    "zone-B object defines a TLS symbol",
                );
            }
            if unit.relocatable && symbol.undefined && !symbol.name.is_empty() {
                if symbol.name == "__tls_get_addr" || symbol.name == "__tls_get_offset" {
                    continue;
                }
                if global_defined.contains(symbol.name.as_str())
                    || LINKER_SYMBOLS.contains(&symbol.name.as_str())
                    || SWAP_SYMBOLS.contains(&symbol.name.as_str())
                {
                    report.internal_edges += 1;
                } else {
                    report.refuse(
                        &unit.label,
                        &symbol.name,
                        0,
                        "unresolved-outgoing",
                        "undefined symbol is neither zone-B internal, linker-defined, nor a recognized swap entry",
                    );
                }
            }
        }
    }

    let starts = instruction_starts(units, ranges);
    let may_write = compute_may_write(units, ranges, &starts);
    let mut branch_sources: BranchSources = BTreeMap::new();
    let mut converged = false;
    for _ in 0..16 {
        let next = collect_branch_sources(units, ranges, &starts, &branch_sources, &may_write);
        if next == branch_sources {
            converged = true;
            break;
        }
        branch_sources = next;
    }
    if !converged && let Some(first) = ranges.first() {
        report.refuse(
            &units[first.unit].label,
            &first.symbol,
            0,
            "branch-state-not-converged",
            "branch source fixed point still changed after 16 rounds",
        );
    }
    for range in ranges {
        scan_range(
            units,
            ranges,
            range,
            &global_defined,
            &starts,
            &branch_sources,
            &may_write,
            &mut report,
        );
    }
    report
}

fn function_ranges(unit_index: usize, unit: &UnitSummary) -> Vec<ScanRange> {
    let mut ranges = Vec::new();
    for section in &unit.sections {
        if !section.executable || section.data.is_empty() {
            continue;
        }
        let mut starts: Vec<&SymbolInfo> = unit
            .symbols
            .iter()
            .filter(|symbol| {
                !symbol.undefined
                    && symbol.section == Some(section.index)
                    && matches!(
                        symbol.kind,
                        SymbolKind::Text | SymbolKind::Label | SymbolKind::Unknown
                    )
                    && !symbol.name.is_empty()
            })
            .collect();
        starts.sort_by_key(|symbol| symbol.address);
        if starts.is_empty() {
            ranges.push(ScanRange {
                unit: unit_index,
                section: section.index,
                start: section.address,
                end: section.address + section.data.len() as u64,
                symbol: section.name.clone(),
            });
            continue;
        }
        // Partition the whole section at symbol starts. A range
        // deliberately extends to the next symbol (or section end)
        // instead of stopping at st_size, so bytes after `.size`
        // are decoded rather than silently skipped.
        let mut unique_starts: Vec<&SymbolInfo> = Vec::new();
        for symbol in starts {
            if symbol.address < section.address
                || symbol.address >= section.address + section.data.len() as u64
            {
                continue;
            }
            match unique_starts
                .last_mut()
                .filter(|current| current.address == symbol.address)
            {
                Some(current)
                    if matches!(current.kind, SymbolKind::Unknown)
                        && !matches!(symbol.kind, SymbolKind::Unknown) =>
                {
                    *current = symbol;
                }
                Some(_) => {}
                None => unique_starts.push(symbol),
            }
        }
        if let Some(first) = unique_starts.first()
            && first.address > section.address
        {
            ranges.push(ScanRange {
                unit: unit_index,
                section: section.index,
                start: section.address,
                end: first.address,
                symbol: section.name.clone(),
            });
        }
        for (position, symbol) in unique_starts.iter().enumerate() {
            let end = unique_starts
                .get(position + 1)
                .map_or(section.address + section.data.len() as u64, |next| {
                    next.address
                });
            if end > symbol.address {
                ranges.push(ScanRange {
                    unit: unit_index,
                    section: section.index,
                    start: symbol.address,
                    end,
                    symbol: symbol.name.clone(),
                });
            }
        }
    }
    ranges
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectEdge {
    Internal,
    RecognizedSwap,
    Outgoing,
    UndecodedTarget,
}

fn relocation_target_location(
    units: &[UnitSummary],
    range: &ScanRange,
    relocation: &RelocInfo,
) -> Option<(usize, usize, u64)> {
    let adjustment = if matches!(
        relocation.r_type,
        object::elf::R_X86_64_PC32 | object::elf::R_X86_64_PLT32
    ) {
        4_i64
    } else {
        0
    };
    let displacement = relocation.addend.wrapping_add(adjustment);
    if relocation.target_defined {
        let section = relocation.target_section?;
        return Some((
            range.unit,
            section,
            relocation.target_address.wrapping_add(displacement as u64),
        ));
    }
    let (unit, symbol) = find_defined_symbol(units, range.unit, &relocation.target_name)?;
    let section = symbol.section?;
    Some((
        unit,
        section,
        symbol.address.wrapping_add(displacement as u64),
    ))
}

fn relocation_symbol_start(
    units: &[UnitSummary],
    range: &ScanRange,
    relocation: &RelocInfo,
) -> Option<(usize, usize, u64)> {
    if relocation.target_defined {
        let section = relocation.target_section?;
        return Some((range.unit, section, relocation.target_address));
    }
    let (unit, symbol) = find_defined_symbol(units, range.unit, &relocation.target_name)?;
    let section = symbol.section?;
    Some((unit, section, symbol.address))
}

fn is_inside_swap_symbol(
    units: &[UnitSummary],
    range: &ScanRange,
    location: (usize, usize, u64),
) -> bool {
    SWAP_SYMBOLS.iter().any(|swap| {
        let Some((swap_unit, symbol)) = find_defined_symbol(units, range.unit, swap) else {
            return false;
        };
        let Some(section) = symbol.section else {
            return false;
        };
        let end = symbol.address + symbol.size.max(1);
        location.0 == swap_unit
            && location.1 == section
            && symbol.address < location.2
            && location.2 < end
    })
}

/// The unique (unit, section, address) of a global defined symbol in a
/// relocatable unit, or None when absent or defined at disagreeing
/// locations. Local symbols never qualify: a unit must not be able to
/// shadow production names with its own labels (ps-t1).
fn find_global_relocatable_symbol(
    units: &[UnitSummary],
    name: &str,
) -> Option<(usize, usize, u64)> {
    let mut found: Option<(usize, usize, u64)> = None;
    for (unit_index, unit) in units.iter().enumerate() {
        if !unit.relocatable {
            continue;
        }
        for symbol in &unit.symbols {
            if symbol.global && !symbol.undefined && symbol.name == name {
                // Sectionless (COMMON/absolute) definitions cannot
                // locate bounds and are skipped here. check_units
                // refuses them when they duplicate another definition
                // or sit outside the owner unit; a unique sectionless
                // definition in the owner unit (s-n9's absolute _end)
                // draws no refusal and simply yields no bounds, so
                // the `.gate` fallback governs instead.
                let Some(section) = symbol.section else {
                    continue;
                };
                let location = (unit_index, section, symbol.address);
                if let Some(existing) = found
                    && existing != location
                {
                    return None;
                }
                found = Some(location);
            }
        }
    }
    found
}

/// Resolved [fixed_gate_template, fixed_gate_template_end) bounds
/// (either spelling), taken only from global symbols in relocatable
/// units. Duplicate disagreeing definitions yield no bounds, in
/// which case the `.gate`-section fallback in
/// `is_inside_gate_template` applies.
fn gate_template_bounds(
    units: &[UnitSummary],
    _range: &ScanRange,
) -> Option<(usize, usize, u64, u64)> {
    for (start_name, end_name) in [
        ("fixed_gate_template", "fixed_gate_template_end"),
        (
            "reverie_inguest_fixed_gate_template",
            "reverie_inguest_fixed_gate_template_end",
        ),
    ] {
        let Some((start_unit, start_section, start_address)) =
            find_global_relocatable_symbol(units, start_name)
        else {
            continue;
        };
        let Some((end_unit, end_section, end_address)) =
            find_global_relocatable_symbol(units, end_name)
        else {
            continue;
        };
        if start_unit == end_unit && start_section == end_section && start_address < end_address {
            return Some((start_unit, start_section, start_address, end_address));
        }
    }
    None
}

/// True when `location` lies inside the fixed gate template but is not a
/// recognized gate start (the caller checks gate starts first). When the
/// template bounds are absent, any target inside a `.gate` section counts:
/// without bounds there is no sound way to admit an interior target.
fn is_inside_gate_template(
    units: &[UnitSummary],
    range: &ScanRange,
    location: (usize, usize, u64),
) -> bool {
    if let Some((unit, section, start, end)) = gate_template_bounds(units, range) {
        return location.0 == unit
            && location.1 == section
            && start <= location.2
            && location.2 < end;
    }
    units[location.0]
        .sections
        .iter()
        .any(|section| section.index == location.1 && section.name == ".gate")
}

fn classify_direct_edge(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    global_defined: &BTreeSet<&str>,
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
) -> DirectEdge {
    if let Some(relocation) = relocations.first() {
        // Classify by resolved (unit, section, address) first: an alias of
        // a gate start (template+0x7c, a same-address local label, a
        // section+addend form) is the gate start, whatever symbol the
        // relocation names.
        if let Some(location) = relocation_target_location(units, range, relocation)
            && gate_kind_for_location(units, range, location).is_some()
        {
            return DirectEdge::RecognizedSwap;
        }
        if SWAP_SYMBOLS.contains(&relocation.target_name.as_str()) {
            let location = relocation_target_location(units, range, relocation);
            let symbol_start = relocation_symbol_start(units, range, relocation);
            return if location.is_some() && location == symbol_start {
                DirectEdge::RecognizedSwap
            } else {
                DirectEdge::Outgoing
            };
        }
        let Some(location) = relocation_target_location(units, range, relocation) else {
            return DirectEdge::Outgoing;
        };
        if !instruction_starts.contains(&location) {
            return DirectEdge::UndecodedTarget;
        }
        // Transfers from outside the template into its interior refuse;
        // the gate's own internal transfers (e.g. the guest entry's jump
        // to its syscall leaf inside the template) stay internal.
        let source = (range.unit, range.section, instruction.ip());
        if (!is_inside_gate_template(units, range, source)
            && is_inside_gate_template(units, range, location))
            || is_inside_swap_symbol(units, range, location)
        {
            return DirectEdge::Outgoing;
        }
        if relocation.target_defined || global_defined.contains(relocation.target_name.as_str()) {
            return DirectEdge::Internal;
        }
        return DirectEdge::Outgoing;
    }

    let target = instruction.near_branch_target();
    if target == FIXED_NATIVE_ENTRY || target == FIXED_GUEST_ENTRY {
        return DirectEdge::RecognizedSwap;
    }
    let target_location = (range.unit, range.section, target);
    if gate_kind_for_location(units, range, target_location).is_some() {
        return DirectEdge::RecognizedSwap;
    }
    let source = (range.unit, range.section, instruction.ip());
    if (!is_inside_gate_template(units, range, source)
        && is_inside_gate_template(units, range, target_location))
        || is_inside_swap_symbol(units, range, target_location)
    {
        return DirectEdge::Outgoing;
    }
    if instruction_starts.contains(&(range.unit, range.section, target)) {
        return DirectEdge::Internal;
    }
    if ranges
        .iter()
        .filter(|candidate| !units[range.unit].relocatable || candidate.unit == range.unit)
        .any(|candidate| candidate.start <= target && target < candidate.end)
    {
        return DirectEdge::UndecodedTarget;
    }
    if let Some(name) = symbol_at_unit(&units[range.unit], target)
        && SWAP_SYMBOLS.contains(&name)
    {
        return DirectEdge::RecognizedSwap;
    }
    DirectEdge::Outgoing
}

fn instruction_starts(
    units: &[UnitSummary],
    ranges: &[ScanRange],
) -> BTreeSet<(usize, usize, u64)> {
    let mut starts = BTreeSet::new();
    for range in ranges {
        let Some(section) = units[range.unit]
            .sections
            .iter()
            .find(|section| section.index == range.section)
        else {
            continue;
        };
        let start = range.start.saturating_sub(section.address) as usize;
        let end = range.end.saturating_sub(section.address) as usize;
        let Some(bytes) = section.data.get(start..end.min(section.data.len())) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                break;
            }
            starts.insert((range.unit, range.section, instruction.ip()));
        }
    }
    starts
}

type BranchSources =
    BTreeMap<(usize, usize, u64), BTreeMap<(usize, usize, u64), BTreeMap<Register, Tracked>>>;

fn after_instruction(
    instruction: &Instruction,
    tracked: &mut BTreeMap<Register, Tracked>,
    gate_jump: bool,
    falls_through: bool,
    keep_after_call: Option<Register>,
) -> bool {
    match instruction.mnemonic() {
        Mnemonic::Ret => {
            tracked.clear();
            false
        }
        Mnemonic::Jmp if gate_jump => {
            tracked.retain(|register, _| {
                matches!(
                    full_register(*register),
                    Register::RBX
                        | Register::RBP
                        | Register::R12
                        | Register::R13
                        | Register::R14
                        | Register::R15
                )
            });
            true
        }
        Mnemonic::Jmp => {
            tracked.clear();
            false
        }
        Mnemonic::Call => {
            let caller_saved = [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::RSI,
                Register::RDI,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ];
            let preserved = keep_after_call.and_then(|register| tracked.remove(&register));
            clear_tracked(tracked, &caller_saved);
            if let (Some(register), Some(value)) = (keep_after_call, preserved) {
                tracked.insert(register, value);
            }
            true
        }
        _ => falls_through,
    }
}

fn collect_branch_sources(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
    previous: &BranchSources,
    may_write: &MayWriteSets,
) -> BranchSources {
    let mut sources: BranchSources = BTreeMap::new();
    let mut info_factory = InstructionInfoFactory::new();
    for range in ranges {
        let unit = &units[range.unit];
        let Some(section) = unit
            .sections
            .iter()
            .find(|section| section.index == range.section)
        else {
            continue;
        };
        let start = range.start.saturating_sub(section.address) as usize;
        let end = range.end.saturating_sub(section.address) as usize;
        let Some(bytes) = section.data.get(start..end.min(section.data.len())) else {
            continue;
        };
        let relocations: Vec<&RelocInfo> = section.relocations.iter().collect();
        let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut tracked: BTreeMap<Register, Tracked> = BTreeMap::new();
        let mut falls_through = true;
        let mut state_known = true;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                break;
            }
            let key = (range.unit, range.section, instruction.ip());
            let mut merged_sources: BTreeMap<_, _> =
                previous.get(&key).cloned().unwrap_or_default();
            if let Some(current_sources) = sources.get(&key) {
                merged_sources.extend(
                    current_sources
                        .iter()
                        .map(|(source, state)| (*source, state.clone())),
                );
            }
            if !merged_sources.is_empty() {
                let mut candidates: Vec<_> = merged_sources.into_values().collect();
                if instruction.ip() == range.start {
                    candidates.push(BTreeMap::new());
                } else if falls_through && state_known {
                    candidates.push(tracked.clone());
                }
                tracked = meet_states(candidates);
                falls_through = true;
                state_known = true;
            }
            let inside = relocation_inside(&relocations, &instruction, section.address);
            let gate_jump = instruction.mnemonic() == Mnemonic::Jmp
                && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::Register
                && tracked_gate(
                    units,
                    range,
                    tracked.get(&full_register(instruction.op_register(0))),
                );
            if instruction.op_count() > 0
                && matches!(
                    instruction.op_kind(0),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
            {
                let target = inside
                    .first()
                    .and_then(|relocation| relocation_target_location(units, range, relocation))
                    .unwrap_or((range.unit, range.section, instruction.near_branch_target()));
                if state_known && instruction_starts.contains(&target) {
                    sources
                        .entry(target)
                        .or_default()
                        .insert(key, tracked.clone());
                }
            }
            // The R12 continuation edge exists for every non-call Native
            // gate transfer (jmp and jcc alike: scan, collection and
            // may-write must use one gate predicate, q1). Call-form
            // native gates are refused in scan_branch (a call pushes a
            // return address the R12 continuation can ret through,
            // which this model does not track), and OtherSwap gates
            // return with `ret`, so an R12 edge for them is spurious
            // and lets dead code verify (CG5).
            let native_gate_jump = gate_jump
                && tracked_gate_kind(
                    units,
                    range,
                    tracked.get(&full_register(instruction.op_register(0))),
                ) == Some(GateKind::Native);
            let direct_native_gate = instruction.mnemonic() != Mnemonic::Call
                && instruction.op_count() > 0
                && matches!(
                    instruction.op_kind(0),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
                && (instruction.near_branch_target() == FIXED_NATIVE_ENTRY
                    || resolved_branch_location(
                        units,
                        ranges,
                        range,
                        &instruction,
                        &inside,
                        &tracked,
                    )
                    .is_some_and(|location| {
                        gate_kind_for_location(units, range, location) == Some(GateKind::Native)
                    }));
            if state_known && (native_gate_jump || direct_native_gate) {
                let return_key = match tracked.get(&Register::R12) {
                    Some(Tracked::LocalAddress {
                        unit,
                        section,
                        address,
                    }) => Some((*unit, *section, *address)),
                    Some(Tracked::Relocated {
                        location: Some(location),
                        ..
                    }) => Some(*location),
                    Some(Tracked::Address(address)) => ranges
                        .iter()
                        .find(|candidate| {
                            candidate.unit == range.unit
                                && candidate.start <= *address
                                && *address < candidate.end
                        })
                        .map(|candidate| (candidate.unit, candidate.section, *address)),
                    _ => None,
                };
                if let Some(return_key) = return_key
                    && instruction_starts.contains(&return_key)
                {
                    let mut return_state = tracked.clone();
                    clear_tracked(
                        &mut return_state,
                        &[Register::RAX, Register::RCX, Register::R11],
                    );
                    sources
                        .entry(return_key)
                        .or_default()
                        .insert(key, return_state);
                }
            }
            update_tracked(
                units,
                range,
                &instruction,
                &inside,
                &mut tracked,
                &mut info_factory,
            );
            let keep_after_call = call_keep_register(
                units,
                ranges,
                range,
                &instruction,
                &inside,
                &tracked,
                may_write,
            );
            falls_through = after_instruction(
                &instruction,
                &mut tracked,
                native_gate_jump,
                falls_through,
                keep_after_call,
            );
            if matches!(instruction.mnemonic(), Mnemonic::Ret)
                || (instruction.mnemonic() == Mnemonic::Jmp && !native_gate_jump)
            {
                state_known = false;
            }
        }
    }
    sources
}

type RangeKey = (usize, usize, u64);
type MayWriteSets = BTreeMap<RangeKey, BTreeSet<Register>>;

fn all_gprs() -> BTreeSet<Register> {
    [
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::RBX,
        Register::RSP,
        Register::RBP,
        Register::RSI,
        Register::RDI,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
        Register::R12,
        Register::R13,
        Register::R14,
        Register::R15,
    ]
    .into_iter()
    .collect()
}

fn resolved_branch_location(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &BTreeMap<Register, Tracked>,
) -> Option<RangeKey> {
    if instruction.op_count() == 0 {
        return None;
    }
    let location = match instruction.op_kind(0) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            if let Some(relocation) = relocations.first() {
                relocation_target_location(units, range, relocation)?
            } else {
                (range.unit, range.section, instruction.near_branch_target())
            }
        }
        OpKind::Register => match tracked.get(&full_register(instruction.op_register(0)))? {
            Tracked::Relocated {
                location: Some(location),
                ..
            } => *location,
            Tracked::LocalAddress {
                unit,
                section,
                address,
            } => (*unit, *section, *address),
            Tracked::Address(address) => ranges
                .iter()
                .find(|candidate| candidate.unit == range.unit && candidate.start == *address)
                .map(|candidate| (candidate.unit, candidate.section, candidate.start))?,
            Tracked::Handler => return None,
            Tracked::Relocated { location: None, .. } => return None,
        },
        _ => return None,
    };
    Some(location)
}

fn tracked_call_target(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &BTreeMap<Register, Tracked>,
) -> Option<RangeKey> {
    let location =
        resolved_branch_location(units, ranges, range, instruction, relocations, tracked)?;
    ranges
        .iter()
        .any(|candidate| (candidate.unit, candidate.section, candidate.start) == location)
        .then_some(location)
}

fn successor_range_key(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &BTreeMap<Register, Tracked>,
) -> Option<RangeKey> {
    let location =
        resolved_branch_location(units, ranges, range, instruction, relocations, tracked)?;
    ranges
        .iter()
        .find(|candidate| {
            candidate.unit == location.0
                && candidate.section == location.1
                && candidate.start <= location.2
                && location.2 < candidate.end
        })
        .map(|candidate| (candidate.unit, candidate.section, candidate.start))
}

fn call_keep_register(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &BTreeMap<Register, Tracked>,
    may_write: &MayWriteSets,
) -> Option<Register> {
    if instruction.mnemonic() != Mnemonic::Call
        || instruction.op_count() == 0
        || instruction.op_kind(0) != OpKind::Register
    {
        return None;
    }
    let register = full_register(instruction.op_register(0));
    let target = tracked_call_target(units, ranges, range, instruction, relocations, tracked)?;
    let writes = may_write.get(&target)?;
    (!writes.contains(&register)).then_some(register)
}

fn compute_may_write(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    instruction_starts: &BTreeSet<RangeKey>,
) -> MayWriteSets {
    let mut writes: MayWriteSets = BTreeMap::new();
    let mut calls: BTreeMap<RangeKey, BTreeSet<RangeKey>> = BTreeMap::new();
    let mut unknown: BTreeSet<RangeKey> = BTreeSet::new();
    let mut info_factory = InstructionInfoFactory::new();

    for range in ranges {
        let key = (range.unit, range.section, range.start);
        let unit = &units[range.unit];
        let Some(section) = unit
            .sections
            .iter()
            .find(|section| section.index == range.section)
        else {
            unknown.insert(key);
            continue;
        };
        let start = range.start.saturating_sub(section.address) as usize;
        let end = range.end.saturating_sub(section.address) as usize;
        let Some(bytes) = section.data.get(start..end.min(section.data.len())) else {
            unknown.insert(key);
            continue;
        };
        let relocations: Vec<&RelocInfo> = section.relocations.iter().collect();
        // In-range direct branch targets are join points: the linear
        // tracked state there is not the meet of the incoming states, so
        // a value established on the fall-through path (including in dead
        // code after an unconditional jump, N6a) must not resolve a
        // direct successor at or after the join. This clear covers only
        // in-range raw targets; relocated and cross-range joins are
        // covered separately by the non-gate-indirect-jmp/call rule
        // below, which writes every register without resolving at all.
        let branch_targets: BTreeSet<u64> = {
            let mut targets = BTreeSet::new();
            let mut pre = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
            let mut pre_instruction = Instruction::default();
            while pre.can_decode() {
                pre.decode_out(&mut pre_instruction);
                if pre_instruction.is_invalid() {
                    break;
                }
                if pre_instruction.op_count() > 0
                    && matches!(
                        pre_instruction.op_kind(0),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    )
                {
                    let target = pre_instruction.near_branch_target();
                    if range.start <= target && target < range.end {
                        targets.insert(target);
                    }
                }
            }
            targets
        };
        let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut tracked: BTreeMap<Register, Tracked> = BTreeMap::new();
        let mut local_writes: BTreeSet<Register> = BTreeSet::new();
        let mut local_calls: BTreeSet<RangeKey> = BTreeSet::new();
        let mut falls_through = true;
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                unknown.insert(key);
                break;
            }
            {
                let info = info_factory
                    .info_options(&instruction, InstructionInfoOptions::NO_MEMORY_USAGE);
                local_writes.extend(
                    info.used_registers()
                        .iter()
                        .filter(|used| {
                            matches!(
                                used.access(),
                                OpAccess::Write
                                    | OpAccess::CondWrite
                                    | OpAccess::ReadWrite
                                    | OpAccess::ReadCondWrite
                            )
                        })
                        .map(|used| full_register(used.register())),
                );
            }
            if matches!(
                instruction.mnemonic(),
                Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int
            ) {
                local_writes.extend([Register::RAX, Register::RCX, Register::R11]);
            }
            let inside = relocation_inside(&relocations, &instruction, section.address);
            if instruction.ip() != range.start && branch_targets.contains(&instruction.ip()) {
                tracked.clear();
            }
            let gate_jump = instruction.mnemonic() == Mnemonic::Jmp
                && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::Register
                && tracked_gate(
                    units,
                    range,
                    tracked.get(&full_register(instruction.op_register(0))),
                );
            let direct_gate_kind = (instruction.op_count() > 0
                && matches!(
                    instruction.op_kind(0),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                ))
            .then(|| {
                resolved_branch_location(units, ranges, range, &instruction, &inside, &tracked)
                    .and_then(|location| gate_kind_for_location(units, range, location))
            })
            .flatten();
            let gate_kind = if gate_jump {
                tracked_gate_kind(
                    units,
                    range,
                    tracked.get(&full_register(instruction.op_register(0))),
                )
            } else {
                direct_gate_kind
            };
            match gate_kind {
                Some(GateKind::Native) => {
                    local_writes.extend([Register::RAX, Register::RCX, Register::R11]);
                }
                Some(GateKind::OtherSwap) => {
                    local_writes.extend(all_gprs());
                }
                None => {}
            }
            // Every non-gate indirect jmp or call in a callee writes
            // every register (EJ): this pass's linear tracked state
            // cannot soundly resolve it at joins entered via relocated
            // or cross-range branches (j1, j2, N6e, jc1, jc2), so
            // resolution is not attempted here. Gate transfers keep
            // their modelled writes.
            if matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
                && instruction.op_count() > 0
                && matches!(instruction.op_kind(0), OpKind::Register | OpKind::Memory)
                && gate_kind.is_none()
            {
                unknown.insert(key);
            }
            let is_call = instruction.mnemonic() == Mnemonic::Call;
            let is_branch = matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
                || (instruction.op_count() > 0
                    && matches!(
                        instruction.op_kind(0),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    ));
            if is_branch {
                match successor_range_key(units, ranges, range, &instruction, &inside, &tracked) {
                    Some(target) if target != key => {
                        local_calls.insert(target);
                    }
                    Some(_) => {}
                    None if is_call || instruction.mnemonic() == Mnemonic::Jmp => {
                        unknown.insert(key);
                    }
                    None => {}
                }
            }
            if gate_kind == Some(GateKind::Native) {
                let return_location = match tracked.get(&Register::R12) {
                    Some(Tracked::LocalAddress {
                        unit,
                        section,
                        address,
                    }) => Some((*unit, *section, *address)),
                    Some(Tracked::Relocated {
                        location: Some(location),
                        ..
                    }) => Some(*location),
                    _ => None,
                };
                if let Some(location) = return_location
                    && instruction_starts.contains(&location)
                    && let Some(target) = ranges
                        .iter()
                        .find(|candidate| {
                            candidate.unit == location.0
                                && candidate.section == location.1
                                && candidate.start <= location.2
                                && location.2 < candidate.end
                        })
                        .map(|candidate| (candidate.unit, candidate.section, candidate.start))
                    && target != key
                {
                    local_calls.insert(target);
                }
            }
            let keep = (instruction.mnemonic() == Mnemonic::Call
                && instruction.op_count() > 0
                && instruction.op_kind(0) == OpKind::Register)
                .then(|| full_register(instruction.op_register(0)));
            update_tracked(
                units,
                range,
                &instruction,
                &inside,
                &mut tracked,
                &mut info_factory,
            );
            falls_through = after_instruction(
                &instruction,
                &mut tracked,
                gate_kind == Some(GateKind::Native),
                falls_through,
                keep,
            );
        }
        if falls_through
            && let Some(next) = ranges
                .iter()
                .find(|candidate| {
                    candidate.unit == range.unit
                        && candidate.section == range.section
                        && candidate.start == range.end
                })
                .map(|candidate| (candidate.unit, candidate.section, candidate.start))
        {
            local_calls.insert(next);
        }
        writes.insert(key, local_writes);
        calls.insert(key, local_calls);
    }

    for key in unknown {
        writes.insert(key, all_gprs());
    }
    loop {
        let mut changed = false;
        for (caller, callees) in &calls {
            let mut merged = writes.get(caller).cloned().unwrap_or_default();
            for callee in callees {
                if let Some(callee_writes) = writes.get(callee) {
                    merged.extend(callee_writes.iter().copied());
                } else {
                    merged.extend(all_gprs());
                }
            }
            if writes.get(caller) != Some(&merged) {
                writes.insert(*caller, merged);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    writes
}

fn relocation_inside<'a>(
    relocations: &'a [&'a RelocInfo],
    instruction: &Instruction,
    section_address: u64,
) -> Vec<&'a RelocInfo> {
    let start = instruction.ip().saturating_sub(section_address);
    let end = start + instruction.len() as u64;
    relocations
        .iter()
        .copied()
        .filter(|relocation| start <= relocation.offset && relocation.offset < end)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn scan_range(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    global_defined: &BTreeSet<&str>,
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
    branch_sources: &BranchSources,
    may_write: &MayWriteSets,
    report: &mut Report,
) {
    let unit = &units[range.unit];
    let Some(section) = unit
        .sections
        .iter()
        .find(|section| section.index == range.section)
    else {
        report.refuse(
            &unit.label,
            &range.symbol,
            range.start,
            "malformed-object",
            "scan range names a missing section",
        );
        return;
    };
    let start = range.start.saturating_sub(section.address) as usize;
    let end = range.end.saturating_sub(section.address) as usize;
    let Some(bytes) = section.data.get(start..end.min(section.data.len())) else {
        report.refuse(
            &unit.label,
            &range.symbol,
            range.start,
            "malformed-object",
            "scan range lies outside its section",
        );
        return;
    };
    let relocations: Vec<&RelocInfo> = section.relocations.iter().collect();
    let mut info_factory = InstructionInfoFactory::new();
    let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut tracked: BTreeMap<Register, Tracked> = BTreeMap::new();
    let mut previous_falls_through = true;
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);
        report.instructions += 1;
        let offset = instruction.ip().saturating_sub(section.address);
        if instruction.is_invalid() {
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                "undecodable-instruction",
                "zone-B range does not decode on instruction boundaries",
            );
            break;
        }
        if let Some(sources) = branch_sources.get(&(range.unit, range.section, instruction.ip())) {
            let mut candidates: Vec<_> = sources.values().cloned().collect();
            if instruction.ip() == range.start {
                candidates.push(BTreeMap::new());
            } else if previous_falls_through {
                candidates.push(tracked.clone());
            }
            tracked = meet_states(candidates);
            previous_falls_through = true;
        }
        let inside = relocation_inside(&relocations, &instruction, section.address);
        let has_memory = (0..instruction.op_count()).any(|index| {
            matches!(
                instruction.op_kind(index),
                OpKind::Memory
                    | OpKind::MemorySegSI
                    | OpKind::MemorySegESI
                    | OpKind::MemorySegRSI
                    | OpKind::MemorySegDI
                    | OpKind::MemorySegEDI
                    | OpKind::MemorySegRDI
                    | OpKind::MemoryESDI
                    | OpKind::MemoryESEDI
                    | OpKind::MemoryESRDI
            )
        });
        if has_memory && instruction.segment_prefix() == Register::FS {
            let canary = instruction.memory_displacement64() == 0x28
                && instruction.memory_base() == Register::None
                && instruction.memory_index() == Register::None;
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                if canary { "stack-canary" } else { "fs-operand" },
                if canary {
                    "stack-protector canary load through %fs:0x28"
                } else {
                    "FS-relative memory operand"
                },
            );
        }
        for index in 0..instruction.op_count() {
            if instruction.op_kind(index) != OpKind::Register
                || instruction.op_register(index) != Register::FS
            {
                continue;
            }
            let selector_read = instruction.mnemonic() == Mnemonic::Mov && index == 1;
            if selector_read {
                continue;
            }
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                if index == 0 {
                    "fs-segment-write"
                } else {
                    "fs-segment-operand"
                },
                "FS segment register operand outside the named selector snapshot",
            );
        }
        if instruction.mnemonic() == Mnemonic::Lfs {
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                "fs-segment-write",
                "lfs implicitly writes the FS segment selector/base",
            );
        }
        if matches!(
            instruction.mnemonic(),
            Mnemonic::Wrfsbase | Mnemonic::Rdfsbase
        ) {
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                "fs-base-instruction",
                "FS-base instruction in zone-B code",
            );
        }
        let direct_kernel_entry = match instruction.mnemonic() {
            Mnemonic::Syscall => Some("syscall"),
            Mnemonic::Sysenter => Some("sysenter"),
            Mnemonic::Int
                if instruction.op_count() > 0
                    && instruction.op_kind(0) == OpKind::Immediate8
                    && instruction.immediate8() == 0x80 =>
            {
                Some("int 0x80")
            }
            _ => None,
        };
        if let Some(entry) = direct_kernel_entry
            && section.name != ".gate"
        {
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                "direct-syscall-outside-gate",
                format!("{entry} instruction outside the fixed gate"),
            );
        }
        let gate_jump = instruction.mnemonic() == Mnemonic::Jmp
            && instruction.op_count() > 0
            && instruction.op_kind(0) == OpKind::Register
            && tracked_gate_kind(
                units,
                range,
                tracked.get(&full_register(instruction.op_register(0))),
            ) == Some(GateKind::Native);
        scan_branch(
            units,
            ranges,
            range,
            section,
            &instruction,
            &inside,
            global_defined,
            instruction_starts,
            &tracked,
            report,
        );
        let keep_after_call = call_keep_register(
            units,
            ranges,
            range,
            &instruction,
            &inside,
            &tracked,
            may_write,
        );
        update_tracked(
            units,
            range,
            &instruction,
            &inside,
            &mut tracked,
            &mut info_factory,
        );
        previous_falls_through = after_instruction(
            &instruction,
            &mut tracked,
            gate_jump,
            previous_falls_through,
            keep_after_call,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_branch(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    section: &SectionInfo,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    global_defined: &BTreeSet<&str>,
    instruction_starts: &BTreeSet<(usize, usize, u64)>,
    tracked: &BTreeMap<Register, Tracked>,
    report: &mut Report,
) {
    let unit = &units[range.unit];
    let offset = instruction.ip().saturating_sub(section.address);
    let branch = matches!(instruction.mnemonic(), Mnemonic::Jmp | Mnemonic::Call)
        || matches!(
            instruction.op_kind(0),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
    if !branch || instruction.op_count() == 0 {
        return;
    }
    match instruction.op_kind(0) {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let edge = classify_direct_edge(
                units,
                ranges,
                range,
                instruction,
                relocations,
                global_defined,
                instruction_starts,
            );
            let native_direct = edge == DirectEdge::RecognizedSwap
                && (instruction.near_branch_target() == FIXED_NATIVE_ENTRY
                    || resolved_branch_location(
                        units,
                        ranges,
                        range,
                        instruction,
                        relocations,
                        tracked,
                    )
                    .is_some_and(|location| {
                        gate_kind_for_location(units, range, location) == Some(GateKind::Native)
                    }));
            if native_direct && instruction.mnemonic() == Mnemonic::Call {
                // A call pushes the post-call address; a `ret` in the R12
                // continuation would land there with the continuation's
                // registers, which the post-call state does not model.
                // Production has no call-form native gate, so refuse the
                // form outright (CG1 family).
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "call-form native-entry gate transfer is refused (unmodelled return path)",
                );
                return;
            }
            if native_direct && !native_gate_return_ok(units, range, tracked, instruction_starts) {
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "native-entry gate jump without r12 tracked as a section-qualified instruction start",
                );
                return;
            }
            match edge {
                DirectEdge::Internal | DirectEdge::RecognizedSwap => {
                    report.internal_edges += 1;
                }
                DirectEdge::UndecodedTarget => report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "direct-target-not-instruction-start",
                    format!(
                        "direct control transfer to {:#x} does not land on a decoded instruction start",
                        instruction.near_branch_target()
                    ),
                ),
                DirectEdge::Outgoing => report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "unrecognized-outgoing-edge",
                    format!(
                        "direct control transfer to {:#x} is neither zone-B internal nor a recognized swap entry",
                        instruction.near_branch_target()
                    ),
                ),
            }
        }
        OpKind::Register | OpKind::Memory => {
            let register_target = (instruction.op_kind(0) == OpKind::Register)
                .then(|| tracked.get(&full_register(instruction.op_register(0))));
            let handler_call = matches!(register_target, Some(Some(Tracked::Handler)));
            let exact_gate_leaf = (instruction.mnemonic() == Mnemonic::Jmp
                && instruction.op_kind(0) == OpKind::Register)
                .then(|| {
                    let symbol_offset = instruction.ip().saturating_sub(range.start);
                    match (
                        range.symbol.as_str(),
                        symbol_offset,
                        instruction.op_register(0),
                    ) {
                        ("fixed_native_entry", 0x6, Register::R12) => Some("fixed_native_entry"),
                        ("private_enter_tool_loader", 0x3a, Register::RAX) => {
                            Some("private_enter_tool_loader")
                        }
                        ("private_runner_resume", 0x108, Register::R13) => {
                            Some("private_runner_resume")
                        }
                        _ => None,
                    }
                })
                .flatten();
            let gate_kind = tracked_gate_kind(units, range, register_target.flatten());
            if instruction.mnemonic() == Mnemonic::Call && gate_kind == Some(GateKind::Native) {
                // Call-form native gate: refused outright, see the direct
                // form above (CG1 family).
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "call-form native-entry gate transfer is refused (unmodelled return path)",
                );
                return;
            }
            let native_gate_return_ok = gate_kind == Some(GateKind::Native)
                && native_gate_return_ok(units, range, tracked, instruction_starts);
            if (gate_kind == Some(GateKind::Native) && native_gate_return_ok)
                || gate_kind == Some(GateKind::OtherSwap)
                || handler_call
                || exact_gate_leaf.is_some()
            {
                report.recognized_indirect += 1;
                if let Some(name) = exact_gate_leaf {
                    *report.gate_leaf_uses.entry(name).or_default() += 1;
                }
            } else if gate_kind == Some(GateKind::Native) {
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "native-entry gate jump without r12 tracked as a section-qualified instruction start",
                );
            } else if register_target
                .flatten()
                .and_then(|target| match target {
                    Tracked::Relocated { location, .. } => *location,
                    Tracked::LocalAddress {
                        unit,
                        section,
                        address,
                    } => Some((*unit, *section, *address)),
                    _ => None,
                })
                .is_some_and(|location| {
                    // An indirect transfer into the template interior (a
                    // non-swap range start such as fixed_signal_restorer,
                    // or the template base itself) reaches gate code
                    // without the gate contract, exactly like the direct
                    // form refused in classify_direct_edge (ps-t2 family,
                    // s-tind). No source exemption: the gate's own leaf
                    // is recognized above, and no production shape needs
                    // an indirect interior transfer from inside either.
                    is_inside_gate_template(units, range, location)
                })
            {
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "indirect branch target lies inside the fixed gate template",
                );
            } else if tracked_internal_movabs(register_target.flatten(), ranges, instruction_starts)
            {
                report.internal_movabs_indirect += 1;
                report.internal_edges += 1;
            } else {
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "indirect branch is not a tracked fixed-gate/internal transfer or exact gate-leaf instruction",
                );
            }
        }
        _ => {}
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-zone-b-{name}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).expect("create zone-B scratch directory");
        Self(directory)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn compile_object(directory: &Path, label: &str, source: &Path, extra: &[&str]) -> Vec<u8> {
    compile_object_with_delta(directory, label, source, extra, true)
}

fn compile_object_with_delta(
    directory: &Path,
    label: &str,
    source: &Path,
    extra: &[&str],
    jump_tables_delta: bool,
) -> Vec<u8> {
    let output_path = directory.join(format!("{label}.o"));
    let compiler = std::env::var_os("CC")
        .filter(|compiler| !compiler.is_empty())
        .unwrap_or_else(|| "cc".into());
    let mut command = Command::new(compiler);
    // The production recipe is reverie-inguest's own exported
    // BOOTSTRAP_RECIPE (single source of truth; Hermit's
    // liteinst-runtime-build/artifact.rs adopts it in a later pin
    // bump). The without-flag form exists only to pin the
    // jump-table violation that dh-1fz4b removes: it is the recipe
    // minus its one -fno-jump-tables flag, in the same order.
    for flag in reverie_inguest::bootstrap_recipe::BOOTSTRAP_RECIPE {
        if !jump_tables_delta && *flag == "-fno-jump-tables" {
            continue;
        }
        command.arg(flag);
    }
    command.arg("-c");
    command.args(extra);
    command.arg(source).arg("-o").arg(&output_path);
    let output = command.output().expect("run zone-B object compiler");
    assert!(
        output.status.success(),
        "compile {label}: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::read(output_path).expect("read zone-B object")
}

fn compile_source(
    directory: &Path,
    label: &str,
    filename: &str,
    contents: &str,
    extra: &[&str],
) -> Vec<u8> {
    let source = directory.join(filename);
    fs::write(&source, contents).expect("write zone-B test source");
    compile_object(directory, label, &source, extra)
}

fn clean_native_units_with(directory: &Path, jump_tables_delta: bool) -> Vec<UnitSummary> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let native = manifest.join("native_exec");
    let specs: Vec<(&str, PathBuf, Vec<&str>)> = vec![
        ("private-entry", native.join("private-entry.S"), Vec::new()),
        (
            "private-bootstrap",
            native.join("private-bootstrap.c"),
            Vec::new(),
        ),
        (
            "private-fs-bootstrap",
            native.join("private-fs.S"),
            Vec::new(),
        ),
        (
            "private-kernel-state",
            native.join("private-kernel-state.c"),
            Vec::new(),
        ),
        ("private-maps", native.join("private-maps.c"), Vec::new()),
    ];
    specs
        .iter()
        .map(|(label, source, extra)| {
            let bytes =
                compile_object_with_delta(directory, label, source, extra, jump_tables_delta);
            summarize(label, &bytes).expect("parse clean zone-B object")
        })
        .collect()
}

fn current_exe_asm_range(unit_index: usize, unit: &UnitSummary) -> Option<ScanRange> {
    const REQUIRED: &[&str] = &[
        "reverie_inguest_private_guest_call",
        "reverie_inguest_private_lifecycle_call",
        "private_sigsys_plain",
        "private_sigsys_pkru",
        "private_instruction_plain",
        "private_instruction_pkru",
    ];
    let required: Vec<&SymbolInfo> = REQUIRED
        .iter()
        .map(|name| {
            unit.symbols
                .iter()
                .find(|symbol| !symbol.undefined && symbol.name == *name)
        })
        .collect::<Option<Vec<_>>>()?;
    let section_index = required.first().and_then(|symbol| symbol.section)?;
    if required
        .iter()
        .any(|symbol| symbol.section != Some(section_index))
    {
        return None;
    }
    let start = required.iter().map(|symbol| symbol.address).min()?;
    let required_end = required
        .iter()
        .map(|symbol| symbol.address + symbol.size)
        .max()?;
    let section = unit
        .sections
        .iter()
        .find(|section| section.index == section_index)?;
    let end = unit
        .symbols
        .iter()
        .filter(|symbol| {
            !symbol.undefined
                && symbol.section == Some(section_index)
                && symbol.address >= required_end
                && matches!(symbol.kind, SymbolKind::Text | SymbolKind::Label)
        })
        .map(|symbol| symbol.address)
        .min()
        .unwrap_or(section.address + section.data.len() as u64);
    Some(ScanRange {
        unit: unit_index,
        section: section_index,
        start,
        end,
        symbol: "exec_private_asm_block".to_owned(),
    })
}

fn clear_tracked(tracked: &mut BTreeMap<Register, Tracked>, registers: &[Register]) {
    for register in registers {
        tracked.remove(&full_register(*register));
    }
}

fn is_64bit_gpr(register: Register) -> bool {
    matches!(
        register,
        Register::RAX
            | Register::RCX
            | Register::RDX
            | Register::RBX
            | Register::RSP
            | Register::RBP
            | Register::RSI
            | Register::RDI
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    )
}

fn update_tracked(
    units: &[UnitSummary],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &mut BTreeMap<Register, Tracked>,
    info_factory: &mut InstructionInfoFactory,
) {
    if matches!(instruction.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
        return;
    }
    let unit = &units[range.unit];
    let mut established: Option<Tracked> = None;
    let mut destination = None;
    if instruction.op_count() > 0 && instruction.op_kind(0) == OpKind::Register {
        destination = Some(full_register(instruction.op_register(0)));
        established = match instruction.mnemonic() {
            Mnemonic::Mov if instruction.op_count() > 1 => {
                if let Some(relocation) = relocations.first() {
                    (instruction.op_kind(1) == OpKind::Immediate64
                        && relocation.r_type == object::elf::R_X86_64_64)
                        .then(|| Tracked::Relocated {
                            name: relocation.target_name.clone(),
                            location: relocation_target_location(units, range, relocation),
                            symbol_start: relocation_symbol_start(units, range, relocation),
                        })
                } else {
                    match instruction.op_kind(1) {
                        OpKind::Immediate64 => {
                            let address = instruction.immediate64();
                            let local = (!unit.relocatable)
                                .then(|| {
                                    unit.sections
                                        .iter()
                                        .find(|section| section.index == range.section)
                                })
                                .flatten()
                                .filter(|section| {
                                    section.address <= address
                                        && address < section.address + section.data.len() as u64
                                });
                            if let Some(section) = local {
                                Some(Tracked::LocalAddress {
                                    unit: range.unit,
                                    section: section.index,
                                    address,
                                })
                            } else {
                                Some(Tracked::Address(address))
                            }
                        }
                        OpKind::Register
                            if is_64bit_gpr(instruction.op_register(0))
                                && is_64bit_gpr(instruction.op_register(1)) =>
                        {
                            tracked
                                .get(&full_register(instruction.op_register(1)))
                                .cloned()
                        }
                        _ => None,
                    }
                }
            }
            Mnemonic::Lea
                if instruction.op_count() > 1 && is_64bit_gpr(instruction.op_register(0)) =>
            {
                // Only a 64-bit destination establishes the tracked
                // address: a 16/32-bit lea truncates (or zero-extends a
                // truncated) value, so the full register does not hold
                // the computed address at an arbitrary load base.
                let base = instruction.memory_base();
                let index = instruction.memory_index();
                let address_forming =
                    matches!(base, Register::None | Register::RIP) && index == Register::None;
                if !address_forming {
                    None
                } else if let Some(relocation) = relocations.first() {
                    let type_ok = match relocation.r_type {
                        object::elf::R_X86_64_PC32 | object::elf::R_X86_64_PLT32 => {
                            base == Register::RIP
                        }
                        object::elf::R_X86_64_32 | object::elf::R_X86_64_32S => {
                            base == Register::None
                        }
                        _ => false,
                    };
                    type_ok.then(|| Tracked::Relocated {
                        name: relocation.target_name.clone(),
                        location: relocation_target_location(units, range, relocation),
                        symbol_start: relocation_symbol_start(units, range, relocation),
                    })
                } else if instruction.is_ip_rel_memory_operand() {
                    let address = instruction.ip_rel_memory_address();
                    if symbol_info_at_unit(unit, address).is_some_and(|symbol| {
                        symbol.section == Some(range.section)
                            && (symbol.name.contains("sigsys_handler")
                                || symbol.name.contains("instruction_sigsegv_handler"))
                    }) {
                        Some(Tracked::Handler)
                    } else {
                        Some(Tracked::LocalAddress {
                            unit: range.unit,
                            section: range.section,
                            address,
                        })
                    }
                } else if base == Register::None {
                    if unit.relocatable {
                        Some(Tracked::Address(instruction.memory_displacement64()))
                    } else {
                        Some(Tracked::LocalAddress {
                            unit: range.unit,
                            section: range.section,
                            address: instruction.memory_displacement64(),
                        })
                    }
                } else {
                    None
                }
            }
            _ => None,
        };
    }

    let writes: Vec<Register> = {
        let info = info_factory.info_options(instruction, InstructionInfoOptions::NO_MEMORY_USAGE);
        info.used_registers()
            .iter()
            .filter(|used| {
                matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
            })
            .map(|used| full_register(used.register()))
            .collect()
    };
    clear_tracked(tracked, &writes);
    if matches!(
        instruction.mnemonic(),
        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int
    ) {
        clear_tracked(tracked, &[Register::RAX, Register::RCX, Register::R11]);
    }
    if let (Some(destination), Some(value)) = (destination, established) {
        tracked.insert(destination, value);
    }
}
fn check_single(label: &str, bytes: &[u8]) -> Report {
    let units = vec![summarize(label, bytes).expect("parse zone-B test object")];
    let ranges = function_ranges(0, &units[0]);
    check_units(&units, &ranges)
}

fn check_clean(directory: &Path, jump_tables_delta: bool) -> Report {
    let mut units = clean_native_units_with(directory, jump_tables_delta);
    let exe_bytes = fs::read(std::env::current_exe().unwrap()).expect("read current test binary");
    let exe =
        summarize("current-exe:exec_private_asm", &exe_bytes).expect("parse current test binary");
    let exe_index = units.len();
    let exe_range = current_exe_asm_range(exe_index, &exe)
        .expect("required exec_private asm symbols must be present in the test binary");
    units.push(exe);

    let mut ranges = Vec::new();
    for (index, unit) in units.iter().enumerate().take(exe_index) {
        ranges.extend(function_ranges(index, unit));
    }
    ranges.push(exe_range);
    let mut report = check_units(&units, &ranges);
    report.skipped_musl_only = vec![
        "bootstrap_sigsys (mapped_initial/libc_relay.rs, loader-private-runtime+musl only)",
        "install_before_libc (private_runtime/tls/abi.rs, loader-private-runtime+musl only)",
    ];
    report
}

#[test]
fn clean_zone_b_objects_pass() {
    // Retain the Rust asm bridges in this test binary for the
    // current-exe symbol-range scan below.
    std::hint::black_box(reverie_inguest::guest::exec_private::physical_syscall as *const ());
    let scratch = Scratch::new("clean");
    let report = check_clean(&scratch.0, true);
    assert!(
        report.violations.is_empty(),
        "clean zone-B objects refused:\n{}",
        report
            .violations
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(report.instructions > 0);
    assert_eq!(
        report.gate_leaf_uses,
        BTreeMap::from([
            ("fixed_native_entry", 1),
            ("private_enter_tool_loader", 1),
            ("private_runner_resume", 1),
        ]),
        "each exact gate-leaf instruction must be used exactly once"
    );
    println!(
        "ZONE-B PASS clean (production recipe, including -fno-jump-tables from https://github.com/rrnewton/hermit/pull/5293 (landed as 38111a07)): {}",
        report.summary()
    );
}

#[test]
fn exact_production_recipe_has_only_the_jump_table_violation() {
    std::hint::black_box(reverie_inguest::guest::exec_private::physical_syscall as *const ());
    let scratch = Scratch::new("clean-exact");
    let report = check_clean(&scratch.0, false);
    println!(
        "ZONE-B EXACT-RECIPE PINNED: {} violations={:?}",
        report.summary(),
        report.violations
    );
    assert_eq!(report.violations.len(), 1, "{:?}", report.violations);
    let violation = &report.violations[0];
    assert_eq!(violation.unit, "private-bootstrap");
    assert!(
        violation.symbol.starts_with("make_private_stack"),
        "{violation:?}"
    );
    assert_eq!(violation.kind, "indirect-branch");
    assert_eq!(violation.offset, 0x112f);
}

#[test]
fn rust_asm_block_patch_refuses_through_current_exe_range() {
    std::hint::black_box(reverie_inguest::guest::exec_private::physical_syscall as *const ());
    let mut bytes = fs::read(std::env::current_exe().unwrap()).expect("read current test binary");
    let original =
        summarize("current-exe:exec_private_asm", &bytes).expect("parse current test binary");
    let range = current_exe_asm_range(0, &original)
        .expect("required exec_private asm symbols must be present in the test binary");
    let section = original
        .sections
        .iter()
        .find(|section| section.index == range.section)
        .expect("asm range section");
    let range_bytes = &section.data
        [(range.start - section.address) as usize..(range.end - section.address) as usize];
    // The three argument loads immediately before the signal
    // common's handler call make the patch site unambiguous.
    let call_context: [u8; 24] = [
        0x48, 0x8b, 0x7c, 0x24, 0x20, 0x48, 0x8b, 0x74, 0x24, 0x18, 0x48, 0x8b, 0x54, 0x24, 0x10,
        0x41, 0xff, 0xd6, 0x49, 0x8b, 0x45, 0x10, 0x49, 0x83,
    ];
    let call_context_offset = range_bytes
        .windows(call_context.len())
        .position(|window| window == call_context)
        .expect("signal common call *%r14 context in merged asm range");
    assert_eq!(
        range_bytes
            .windows(call_context.len())
            .filter(|window| *window == call_context)
            .count(),
        1,
        "signal common call context must be unique in the merged asm range"
    );
    let call_offset = (range.start - section.address) as usize + call_context_offset + 15;
    let file_offset = {
        let file = object::File::parse(&*bytes).expect("parse current test binary for patch");
        let object_section = file
            .section_by_index(object::SectionIndex(range.section))
            .expect("asm range object section");
        let (section_file_offset, _) = object_section
            .file_range()
            .expect("asm range section has a file range");
        section_file_offset as usize + call_offset
    };
    assert_eq!(
        &bytes[file_offset..file_offset + 3],
        &[0x41, 0xff, 0xd6],
        "signal common call encoding changed; update the real-path patch"
    );
    bytes[file_offset..file_offset + 3].copy_from_slice(&[0xff, 0xd7, 0x90]);
    let mutated =
        summarize("current-exe:exec_private_asm", &bytes).expect("parse patched test binary");
    let mutated_range = current_exe_asm_range(0, &mutated)
        .expect("patched asm symbols must still resolve the merged range");
    let units = vec![mutated];
    let report = check_units(&units, &[mutated_range]);
    println!(
        "ZONE-B EXPECTED-FAIL rust-asm-real-path: {} kinds={:?}",
        report.summary(),
        report
            .violations
            .iter()
            .map(|violation| violation.kind)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        report.violations.len(),
        1,
        "patched real asm block must refuse exactly the patched call: {:?}",
        report.violations
    );
    assert_eq!(report.violations[0].kind, "indirect-branch");
    assert_eq!(report.violations[0].symbol, "exec_private_asm_block");
    assert_eq!(report.violations[0].offset, call_offset as u64);
}

#[test]
fn excluded_runner_object_is_refused_if_classified_as_zone_b() {
    let scratch = Scratch::new("runner");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bytes = compile_object(
        &scratch.0,
        "private-runner-excluded",
        &manifest.join("native_exec/private-runner.c"),
        &[],
    );
    let report = check_single("private-runner-excluded", &bytes);
    println!(
        "ZONE-B EXPECTED-FAIL excluded-runner: {} kinds={:?}",
        report.summary(),
        report
            .violations
            .iter()
            .map(|violation| violation.kind)
            .collect::<BTreeSet<_>>()
    );
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.kind.starts_with("tls-")),
        "runner_tls object must be excluded by name, not admitted: {:?}",
        report.violations
    );
}

#[test]
fn checker_refuses_each_injected_tls_and_control_violation() {
    let scratch = Scratch::new("mutants");
    let cases: Vec<(&str, &str, &str, Vec<&str>, &str)> = vec![
        (
            "fs-operand",
            "zone_b_fs_operand.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %fs:0x10,%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "fs-operand",
        ),
        (
            "tls-get-addr",
            "zone_b_tls_call.c",
            "extern _Thread_local int zone_b_tls;\nint zone_b_mutant(void) { return zone_b_tls; }\n",
            vec!["-fpic", "-ftls-model=global-dynamic"],
            "tls-get-addr",
        ),
        (
            "tls-relocation",
            "zone_b_tls_reloc.c",
            "_Thread_local int zone_b_tls = 1;\nint *zone_b_mutant(void) { return &zone_b_tls; }\n",
            vec!["-ftls-model=initial-exec"],
            "tls-relocation",
        ),
        (
            "stack-canary",
            "zone_b_canary.c",
            "extern void zone_b_fill(char *);\nint zone_b_mutant(void) { char buffer[64]; zone_b_fill(buffer); return buffer[0]; }\n",
            vec!["-fstack-protector-strong"],
            "stack-canary",
        ),
        (
            "int80-entry",
            "zone_b_int80.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n int $0x80\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "sysenter-entry",
            "zone_b_sysenter.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n sysenter\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "indirect-branch",
            "zone_b_indirect.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "outgoing-edge",
            "zone_b_outgoing.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n call zone_b_unrecognized_external\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unresolved-outgoing",
        ),
        (
            "plain-syscall",
            "zone_b_plain_syscall.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n syscall\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "fs-segment-write",
            "zone_b_fs_write.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %ax,%fs\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "fs-segment-write",
        ),
        (
            "fs-base-instruction",
            "zone_b_fs_base.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n rdfsbase %rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "fs-base-instruction",
        ),
        (
            "lfs-write",
            "zone_b_lfs.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n lfs (%rsi),%eax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "fs-segment-write",
        ),
        (
            "maskmovdqu-fs",
            "zone_b_maskmovdqu.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n .byte 0x64,0x66,0x0f,0xf7,0xc1\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "fs-operand",
        ),
        (
            "fixed-prefix-syscall",
            "zone_b_fixed_prefix.S",
            ".text\n.globl fixed_zb_evil\n.type fixed_zb_evil,@function\nfixed_zb_evil:\n syscall\n ret\n.size fixed_zb_evil,.-fixed_zb_evil\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "gate-leaf-indirect",
            "zone_b_gate_leaf_indirect.S",
            ".text\n.globl private_enter_tool_loader\n.type private_enter_tool_loader,@function\nprivate_enter_tool_loader:\n jmp *%rdi\n.size private_enter_tool_loader,.-private_enter_tool_loader\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-subregister-clobber",
            "zone_b_tracked_subregister.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n mov $0,%eax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-cpuid-clobber",
            "zone_b_tracked_cpuid.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n cpuid\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-skipped-movabs",
            "zone_b_tracked_skipped.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n test %edi,%edi\n je 1f\n movabs $0x50000000007c,%rax\n1: jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "movabs-outside-zone",
            "zone_b_movabs_outside.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_external,%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "rodata-code-direct-call",
            "zone_b_rodata_code.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n call zone_b_rodata_code\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .rodata.zbcode,\"a\",@progbits\n.globl zone_b_rodata_code\n.type zone_b_rodata_code,@function\nzone_b_rodata_code:\n syscall\n ret\n.size zone_b_rodata_code,.-zone_b_rodata_code\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-target-not-instruction-start",
        ),
        (
            "bytes-past-size",
            "zone_b_past_size.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n syscall\n ret\n.globl zone_b_after\n.type zone_b_after,@function\nzone_b_after:\n ret\n.size zone_b_after,.-zone_b_after\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "mid-instruction-target",
            "zone_b_mid_instruction.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n jmp zone_b_target+1\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n mov $0x12345678,%eax\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-target-not-instruction-start",
        ),
        (
            "tls-section",
            "zone_b_tls_section.S",
            ".section .tbss,\"awT\",@nobits\n.globl zone_b_tls_section\nzone_b_tls_section:\n .zero 8\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "tls-section",
        ),
        (
            "tls-symbol",
            "zone_b_tls_symbol.c",
            "_Thread_local int zone_b_tls_symbol;\nint zone_b_mutant(void) { return 0; }\n",
            Vec::new(),
            "tls-symbol",
        ),
        (
            "tracked-register-copy-subregister",
            "zone_b_tracked_copy.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rcx\n mov %ecx,%eax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-rdtsc-clobber",
            "zone_b_tracked_rdtsc.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n rdtsc\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-mul-clobber",
            "zone_b_tracked_mul.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n mul %rcx\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-cqo-clobber",
            "zone_b_tracked_cqo.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rdx\n cqo\n jmp *%rdx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-cltq-clobber",
            "zone_b_tracked_cltq.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n cltq\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-cmpxchg-clobber",
            "zone_b_tracked_cmpxchg.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n lock cmpxchg %ecx,(%rsi)\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-rep-stosb-clobber",
            "zone_b_tracked_rep_stosb.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rcx\n rep stosb\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-direct-call-clobber",
            "zone_b_tracked_direct_call.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n call zone_b_helper\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "tracked-backward-branch",
            "zone_b_tracked_backward.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n je 2f\n movabs $0x50000000007c,%rax\n ret\n1: call *%rax\n ret\n2: jmp 1b\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "second-gate-leaf-indirect",
            "zone_b_second_gate_leaf.S",
            ".text\n.globl private_enter_tool_loader\n.type private_enter_tool_loader,@function\nprivate_enter_tool_loader:\n .fill 0x3a,1,0x90\n jmp *%rax\n jmp *%rax\n.size private_enter_tool_loader,.-private_enter_tool_loader\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "past-size-gate-leaf",
            "zone_b_past_size_gate_leaf.S",
            ".text\n.globl private_runner_resume\n.type private_runner_resume,@function\nprivate_runner_resume:\n ret\n.size private_runner_resume,.-private_runner_resume\n jmp *%r13\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "fixed-restorer-text-syscall",
            "zone_b_fixed_restorer_text.S",
            ".text\n.globl fixed_signal_restorer\n.type fixed_signal_restorer,@function\nfixed_signal_restorer:\n syscall\n ret\n.size fixed_signal_restorer,.-fixed_signal_restorer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "direct-syscall-outside-gate",
        ),
        (
            "maywrite-gate-continuation",
            "zone_b_maywrite_gate_cont.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea zone_b_writer(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-tail-jmp",
            "zone_b_maywrite_tail.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n jmp zone_b_writer\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-jcc-successor",
            "zone_b_maywrite_jcc.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n test %edi,%edi\n jne zone_b_writer\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-indirect-tail-jmp",
            "zone_b_maywrite_itail.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-fallthrough-next-range",
            "zone_b_maywrite_fallthrough.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n nop\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-local-symbol-split",
            "zone_b_maywrite_split.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n nop\nzb_helper_mid:\n xor %r10d,%r10d\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-gate-jmp-callee",
            "zone_b_maywrite_gate.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%rcx\n call *%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea 1f(%rip),%r12\n movabs $0x50000000007c,%r11\n jmp *%r11\n1: ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-gate-relocated-callee",
            "zone_b_maywrite_gate_reloc.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%rcx\n call *%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea 1f(%rip),%r12\n movabs $fixed_native_entry,%r11\n jmp *%r11\n1: ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-gate-syscallless-callee",
            "zone_b_maywrite_gate_nosyscall.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n ret\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%rcx\n call *%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea 1f(%rip),%r12\n movabs $fixed_native_entry,%r11\n jmp *%r11\n1: ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-gate-relocated-continuation",
            "zone_b_maywrite_gate_reloc_cont.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n ret\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea zone_b_writer(%rip),%r12\n movabs $fixed_native_entry,%r11\n jmp *%r11\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-no-closure",
            "zone_b_maywrite_closure.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n call zone_b_writer\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-unresolved-callee",
            "zone_b_maywrite_unresolved.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n call zone_b_external\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "maywrite-syscall-callee",
            "zone_b_maywrite_syscall.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n nop\n.globl fixed_native_entry\nfixed_native_entry:\n ret\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n syscall\n ret\n.size zone_b_helper,.-zone_b_helper\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%rax\n call *%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "gate-numeric-wrong-r12",
            "zone_b_gate_numeric_wrong.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %rdi,%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "direct-gate-wrong-r12",
            "zone_b_direct_gate_wrong.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_native_entry\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "direct-gate-call-wrong-r12",
            "zone_b_direct_gate_call_wrong.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %rdi,%r12\n call fixed_native_entry\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "gate-template-alias",
            "zone_b_gate_template_alias.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $fixed_gate_template+0x7c,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "handler-cross-section-alias",
            "zone_b_handler_alias.S",
            ".section .text.other,\"ax\",@progbits\n .fill 0x14,1,0x90\n.globl evil_sigsys_handler\n.type evil_sigsys_handler,@function\nevil_sigsys_handler:\n ret\n.size evil_sigsys_handler,.-evil_sigsys_handler\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n lea .Lzb_x(%rip),%rax\n call *%rax\n ret\n .fill 10,1,0x90\n.Lzb_x:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "lea-swap-addend",
            "zone_b_lea_swap_addend.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n lea reverie_inguest_trusted_syscall+7(%rip),%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl reverie_inguest_trusted_syscall\n.type reverie_inguest_trusted_syscall,@function\nreverie_inguest_trusted_syscall:\n .fill 16,1,0x90\n ret\n.size reverie_inguest_trusted_syscall,.-reverie_inguest_trusted_syscall\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "direct-gate-cross-section-addend",
            "zone_b_direct_gate_cross.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n jmp fixed_native_entry+6\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "code-symbol-rip-load",
            "zone_b_code_symbol_rip.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov zone_b_target(%rip),%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "code-symbol-absolute-load",
            "zone_b_code_symbol_abs.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs zone_b_target,%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "wrong-register-fixed-native-entry",
            "zone_b_wrong_fixed_native.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n .fill 6,1,0x90\n jmp *%rdi\n.size fixed_native_entry,.-fixed_native_entry\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "wrong-register-enter-tool-loader",
            "zone_b_wrong_enter_tool.S",
            ".text\n.globl private_enter_tool_loader\n.type private_enter_tool_loader,@function\nprivate_enter_tool_loader:\n .fill 0x3a,1,0x90\n jmp *%rdi\n.size private_enter_tool_loader,.-private_enter_tool_loader\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "wrong-register-runner-resume",
            "zone_b_wrong_runner_resume.S",
            ".text\n.globl private_runner_resume\n.type private_runner_resume,@function\nprivate_runner_resume:\n .fill 0x108,1,0x90\n jmp *%rdi\n.size private_runner_resume,.-private_runner_resume\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "fixed-native-entry-call-offset-zero",
            "zone_b_fixed_native_call0.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n call *%rdi\n.size fixed_native_entry,.-fixed_native_entry\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "one-round-loop",
            "zone_b_one_round_loop.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n1: test %edi,%edi\n je 2f\n xor %eax,%eax\n dec %edi\n jmp 1b\n2: jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "gate-numeric-return-coincidence",
            "zone_b_gate_numeric_return.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $fixed_native_entry,%rcx\n movabs $24,%r12\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "movabs-rodata-global",
            "zone_b_movabs_rodata.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_rodata_code,%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .rodata.zbcode,\"a\",@progbits\n.globl zone_b_rodata_code\n.type zone_b_rodata_code,@function\nzone_b_rodata_code:\n mov %fs:0x10,%rax\n syscall\n ret\n.size zone_b_rodata_code,.-zone_b_rodata_code\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "movabs-rodata-section",
            "zone_b_movabs_rodata_section.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $.Lzone_b_rodata_code,%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .rodata.zbcode,\"a\",@progbits\n.Lzone_b_rodata_code:\n mov %fs:0x10,%rax\n syscall\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "movabs-mid-instruction",
            "zone_b_movabs_mid.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_target+1,%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n mov $0x12345678,%eax\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "fnptr-rip-load",
            "zone_b_fnptr_rip.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov zone_b_fp(%rip),%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.data\n.globl zone_b_fp\nzone_b_fp: .quad zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "fnptr-absolute-load",
            "zone_b_fnptr_abs.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs zone_b_fp,%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.data\n.globl zone_b_fp\nzone_b_fp: .quad zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "lea-base-register",
            "zone_b_lea_base.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n lea zone_b_target(%rdi),%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "lea-index-register",
            "zone_b_lea_index.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n lea zone_b_target(,%rdi,8),%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "movabs-pc64-relocation",
            "zone_b_movabs_pc64.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_target-.-2,%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .text.other,\"ax\",@progbits\n.globl zone_b_target\n.type zone_b_target,@function\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "indirect-call-clobbers-gate",
            "zone_b_indirect_call_clobber.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rdx\n movabs $zone_b_helper,%rax\n call *%rax\n jmp *%rdx\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n xor %edx,%edx\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "indirect-call-same-register",
            "zone_b_indirect_call_same.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n call *%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "midfunction-indirect-target",
            "zone_b_midfunction.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n xor %eax,%eax\n movabs $.Lzone_b_mid,%rcx\n jmp *%rcx\n movabs $0x50000000007c,%rax\n.Lzone_b_mid:\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "gate-syscall-stale-target",
            "zone_b_gate_syscall_stale.S",
            ".section .gate,\"ax\",@progbits\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n syscall\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "gate-int80-stale-target",
            "zone_b_gate_int80_stale.S",
            ".section .gate,\"ax\",@progbits\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n int $0x80\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "swap-symbol-addend",
            "zone_b_swap_addend.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $fixed_native_entry+6,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "direct-swap-addend",
            "zone_b_direct_swap_addend.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n jmp reverie_inguest_trusted_syscall+0x10\n.size zone_b_mutant,.-zone_b_mutant\n.globl reverie_inguest_trusted_syscall\n.type reverie_inguest_trusted_syscall,@function\nreverie_inguest_trusted_syscall:\n .fill 16,1,0x90\n ret\n.size reverie_inguest_trusted_syscall,.-reverie_inguest_trusted_syscall\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "gate-return-register",
            "zone_b_gate_return.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov %rdi,%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "control-rip-load",
            "zone_b_control_load.S",
            ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n mov exec_private_control(%rip),%rax\n call *%rax\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.data\n.globl exec_private_control\nexec_private_control: .quad zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n9a-direct-gate-template-jmp",
            "zone_b_n9a.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x7c\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n9b-direct-gate-template-call",
            "zone_b_n9b.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n call fixed_gate_template+0x7c\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n9c-direct-gate-leaf-jmp",
            "zone_b_n9c.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x82\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "n3c-gate-mid-jmp",
            "zone_b_n3c.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x80\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "n9e-same-section-gate-jmp",
            "zone_b_n9e.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_native_entry\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n9f-local-alias-gate-jmp",
            "zone_b_n9f.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.Lzb_gate_alias:\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.section .text.other,\"ax\",@progbits\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp .Lzb_gate_alias\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "cg1-call-gate-numeric",
            "zone_b_cg1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rbx\n lea .Lzb_cont(%rip),%r12\n movabs $0x50000000007c,%rcx\n call *%rcx\n jmp *%rbx\n.Lzb_cont:\n mov %rdi,%rbx\n ret\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "cg1c-call-gate-relocated",
            "zone_b_cg1c.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rbx\n lea .Lzb_cont(%rip),%r12\n movabs $fixed_native_entry,%rcx\n call *%rcx\n jmp *%rbx\n.Lzb_cont:\n mov %rdi,%rbx\n ret\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "cg1e-call-gate-direct",
            "zone_b_cg1e.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rbx\n lea .Lzb_cont(%rip),%r12\n call fixed_native_entry\n jmp *%rbx\n.Lzb_cont:\n mov %rdi,%rbx\n ret\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "dr1-call-gate-double-return",
            "zone_b_dr1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rax\n lea .Lzb_ret(%rip),%r12\n movabs $0x50000000007c,%rcx\n call *%rcx\n jmp *%rax\n.Lzb_ret:\n ret\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n2-call-gate-continuation",
            "zone_b_n2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rsi,%r10\n lea .Lzb_x(%rip),%r12\n movabs $0x50000000007c,%rcx\n call *%rcx\n ret\n.Lzb_x:\n jmp *%r10\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%r10\n jmp .Lzb_x\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n2b-call-gate-relocated-continuation",
            "zone_b_n2b.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rsi,%r10\n lea .Lzb_x(%rip),%r12\n movabs $fixed_native_entry,%rcx\n call *%rcx\n ret\n.Lzb_x:\n jmp *%r10\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%r10\n jmp .Lzb_x\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n2-jmp-gate-continuation",
            "zone_b_n2jmp.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rsi,%r10\n lea .Lzb_x(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n ret\n.Lzb_x:\n jmp *%r10\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%r10\n jmp .Lzb_x\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "cg5-otherswap-call-spurious-edge",
            "zone_b_cg5.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%r10\n lea .Lzb_x(%rip),%r12\n movabs $0x500000000100,%rcx\n call *%rcx\n ret\n mov %rdi,%r10\n.Lzb_x:\n jmp *%r10\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n6a-maywrite-deadcode-resolve",
            "zone_b_n6a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp 1f\n movabs $zone_b_other,%rax\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n6b-maywrite-join-ret",
            "zone_b_n6b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp 1f\n ret\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n6c-maywrite-gate-after-jmp",
            "zone_b_n6c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%rax\n call *%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n jmp 1f\n1: lea 2f(%rip),%r12\n movabs $0x50000000007c,%r11\n jmp *%r11\n2: ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n6d-maywrite-join-two-values",
            "zone_b_n6d.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n test %edi,%edi\n je 1f\n movabs $zone_b_other,%rax\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n1b-maywrite-gate-next-split",
            "zone_b_n1b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n lea 1f(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n1: xor %r10d,%r10d\nzb_helper_mid:\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n1c-maywrite-gate-earlier-range",
            "zone_b_n1c.S",
            ".text\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_helper\nzone_b_helper:\n lea zone_b_writer(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n8a-maywrite-gate-following-symbol",
            "zone_b_n8a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n lea zb_after(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.globl zb_after\nzb_after:\n xor %r10d,%r10d\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n8b-maywrite-gate-other-function-label",
            "zone_b_n8b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n lea zb_writer_mid(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_other\nzone_b_other:\n ret\nzb_writer_mid:\n xor %r10d,%r10d\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n8c-maywrite-gate-other-section",
            "zone_b_n8c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n lea zone_b_writer(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.section .text.other,\"ax\",@progbits\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n4-maywrite-guest-entry-numeric",
            "zone_b_n4.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $0x500000000100,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n10a-maywrite-guest-entry-relocated",
            "zone_b_n10a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $reverie_inguest_trusted_syscall,%rcx\n jmp *%rcx\n.size zone_b_helper,.-zone_b_helper\n.globl reverie_inguest_trusted_syscall\nreverie_inguest_trusted_syscall:\n .fill 16,1,0x90\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "mw-n1c-join-tail-jmp",
            "zone_b_mwn1c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n test %edi,%edi\n jne 1f\n ret\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "mw-n1d-dead-tail-jmp",
            "zone_b_mwn1d.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp 1f\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "mw-n1e-handler-tail-jmp",
            "zone_b_mwn1e.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n lea zb_sigsys_handler(%rip),%rax\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zb_sigsys_handler\nzb_sigsys_handler:\n xor %r10d,%r10d\n ret\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "l1-lea-r12w",
            "zone_b_l1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n lea .Lzb_next(%rip),%r12w\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.Lzb_next:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "l2-lea-r12d",
            "zone_b_l2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n lea .Lzb_next(%rip),%r12d\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.Lzb_next:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "l3-lea-eax",
            "zone_b_l3.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea zone_b_target(%rip),%eax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "l4-lea-ax",
            "zone_b_l4.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n lea zone_b_target(%rip),%ax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "l5-lea-ecx",
            "zone_b_l5.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rcx\n lea zone_b_target(%rip),%ecx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "b2-lea-absolute-r12",
            "zone_b_b2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea 0x14,%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "k8-lea-size32-reloc",
            "zone_b_k8.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea 0(%rip),%rax\n .reloc .-4, R_X86_64_SIZE32, zone_b_target\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "k8b-lea-pc32-nobase",
            "zone_b_k8b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea 0,%rax\n .reloc .-4, R_X86_64_PC32, zone_b_target-4\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "k8c-lea-gotpcrel",
            "zone_b_k8c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea zone_b_target@GOTPCREL(%rip),%rax\n jmp *%rax\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "k12-r12-mid-instruction",
            "zone_b_k12.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea zone_b_target+1(%rip),%r12\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n.text\n.globl zone_b_target\nzone_b_target:\n mov $0x12345678,%eax\n ret\n.size zone_b_target,.-zone_b_target\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "q1-jcc-gate-continuation",
            "zone_b_q1.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rsi,%r10\n lea .Lzb_x(%rip),%r12\n test %edi,%edi\n je fixed_native_entry\n ret\n.Lzb_x:\n jmp *%r10\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%r10\n jmp .Lzb_x\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "q1b-jcc-gate-rcx",
            "zone_b_q1b.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rcx\n lea .Lzb_x(%rip),%r12\n test %edi,%edi\n je fixed_native_entry\n ret\n.Lzb_x:\n jmp *%rcx\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "j1-maywrite-cross-range-join",
            "zone_b_j1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_entry2,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_entry2\nzone_b_entry2:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_entry2,.-zone_b_entry2\n.globl zone_b_helper\nzone_b_helper:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "j2-maywrite-relocated-jmp",
            "zone_b_j2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n .byte 0xe9\n .long 0\n .reloc .-4, R_X86_64_PC32, .Lzb_join-4\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n6e-maywrite-cross-range-midlabel",
            "zone_b_n6e.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_a\nzone_b_a:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_a,.-zone_b_a\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "s-tind-indirect-template-interior",
            "zone_b_stind.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 8,1,0x90\n.globl zb_inside\nzb_inside:\n ret\n .fill 8,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zb_inside,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "n9e2-same-section-leaf-label",
            "zone_b_n9e2.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n.Lzb_leaf:\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp .Lzb_leaf\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "g1b-gate-no-bounds-fallback",
            "zone_b_g1b.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n.Lzb_leaf:\n jmp *%r12\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp .Lzb_leaf\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "unrecognized-outgoing-edge",
        ),
        (
            "s-onj-otherswap-jmp-edge",
            "zone_b_sonj.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%r10\n lea .Lzb_x(%rip),%r12\n movabs $0x500000000100,%rcx\n jmp *%rcx\n ret\n mov %rdi,%r10\n.Lzb_x:\n jmp *%r10\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "s-cg5j-otherswap-jmp-fallthrough",
            "zone_b_scg5j.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rbx\n movabs $0x500000000100,%rcx\n jmp *%rcx\n jmp *%rbx\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "s-m5z-cross-section-r12",
            "zone_b_sm5z.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea .Lzb_cont(%rip),%r12\n jmp .Lzb_mid\n.Lzb_cont:\n ret\n.section .text.other,\"ax\",@progbits\n.globl zb_other_fn\nzb_other_fn:\n ret\n.Lzb_mid:\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.size zb_other_fn,.-zb_other_fn\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "jc1-call-cross-range-join",
            "zone_b_jc1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_entry2,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_entry2\nzone_b_entry2:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_entry2,.-zone_b_entry2\n.globl zone_b_helper\nzone_b_helper:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n call *%rax\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "jc2-call-relocated-join",
            "zone_b_jc2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n .byte 0xe9\n .long 0\n .reloc .-4, R_X86_64_PC32, .Lzb_join-4\n movabs $zone_b_other,%rax\n.Lzb_join:\n call *%rax\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "jc3-call-direct-control",
            "zone_b_jc3.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n call *%rax\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "z4t-direct-r12-interior",
            "zone_b_z4t.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x80(%rip),%r12\n jmp fixed_native_entry\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "q1b-rev-jcc-gate-rcx",
            "zone_b_q1brev.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea .Lzb_x(%rip),%r12\n test %edi,%edi\n je fixed_native_entry\n ret\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%rcx\n jmp .Lzb_x\n.Lzb_x:\n jmp *%rcx\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "s-n9-abs-end-fallback",
            "zone_b_sn9.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n.globl fixed_gate_template_end\n.set fixed_gate_template_end, 0x2000\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x80(%rip),%r12\n jmp fixed_native_entry\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "indirect-branch",
        ),
        (
            "s-n4-local-owner-only",
            "zone_b_sn4.S",
            ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x82\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            Vec::new(),
            "duplicate-gate-bounds",
        ),
    ];
    let mut missing = Vec::new();
    for (label, filename, contents, extra, expected) in cases {
        let bytes = compile_source(&scratch.0, label, filename, contents, &extra);
        let report = check_single(label, &bytes);
        let kinds: BTreeSet<&str> = report
            .violations
            .iter()
            .map(|violation| violation.kind)
            .collect();
        println!(
            "ZONE-B EXPECTED-FAIL {label}: {} kinds={kinds:?} first={:?}",
            report.summary(),
            report.violations.first()
        );
        if !kinds.contains(expected) {
            missing.push(format!(
                "mutant {label} must refuse with {expected}, got {kinds:?}: {:?}",
                report.violations
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "missing refusals:\n{}",
        missing.join("\n")
    );
}

#[test]
fn production_set_refuses_gate_alias_call_and_deadcode_probes() {
    std::hint::black_box(reverie_inguest::guest::exec_private::physical_syscall as *const ());
    let scratch = Scratch::new("production-set-probes");
    let probes: Vec<(&str, &str, &str, &str)> = vec![
        (
            "ps-n9a-template-jmp",
            "zone_b_ps_n9a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x7c\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-n9c-template-leaf-jmp",
            "zone_b_ps_n9c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_gate_template+0x82\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-cg1c-call-gate-relocated",
            "zone_b_ps_cg1c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_target,%rbx\n lea .Lzb_cont(%rip),%r12\n movabs $fixed_native_entry,%rcx\n call *%rcx\n jmp *%rbx\n.Lzb_cont:\n mov %rdi,%rbx\n ret\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-n6a-deadcode-resolve",
            "zone_b_ps_n6a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp 1f\n movabs $zone_b_other,%rax\n1: jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-l1-lea-r12w",
            "zone_b_ps_l1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n lea .Lzb_next(%rip),%r12w\n movabs $0x50000000007c,%rcx\n jmp *%rcx\n.Lzb_next:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-q1-jcc-gate",
            "zone_b_ps_q1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rsi,%r10\n lea .Lzb_x(%rip),%r12\n test %edi,%edi\n je fixed_native_entry\n ret\n.Lzb_x:\n jmp *%r10\n.globl zone_b_other\nzone_b_other:\n movabs $zone_b_target,%r10\n jmp .Lzb_x\n.globl zone_b_target\nzone_b_target:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-j1-cross-range-join",
            "zone_b_ps_j1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_entry2,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_entry2\nzone_b_entry2:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_entry2,.-zone_b_entry2\n.globl zone_b_helper\nzone_b_helper:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-j2-relocated-jmp",
            "zone_b_ps_j2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n .byte 0xe9\n .long 0\n .reloc .-4, R_X86_64_PC32, .Lzb_join-4\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-n6e-cross-range-midlabel",
            "zone_b_ps_n6e.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_a\nzone_b_a:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n jmp *%rax\n.size zone_b_a,.-zone_b_a\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-t2-restorer-indirect",
            "zone_b_ps_t2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $fixed_signal_restorer,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-t2b-restorer-call",
            "zone_b_ps_t2b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $fixed_signal_restorer,%rcx\n call *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-t2c-template-start-indirect",
            "zone_b_ps_t2c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $fixed_gate_template,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-t2d-restorer-lea",
            "zone_b_ps_t2d.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_signal_restorer(%rip),%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-r1-r12-template-200",
            "zone_b_ps_r1_r12_template_200.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x200(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-r1b-r12-template-309",
            "zone_b_ps_r1b_r12_template_309.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x309(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-r1c-r12-template-80",
            "zone_b_ps_r1c_r12_template_80.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x80(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-r1z-legit-continuation",
            "zone_b_ps_r1z.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea .Lzb_next(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n.Lzb_next:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "",
        ),
        (
            "ps-t1-bounds-hijack",
            "zone_b_ps_t1.S",
            ".section .gate,\"ax\",@progbits\nfixed_gate_template:\n nop\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-t1d-bounds-hijack-rax",
            "zone_b_ps_t1d.S",
            ".section .gate,\"ax\",@progbits\nfixed_gate_template:\n nop\nfixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-t1b-control-no-hijack",
            "zone_b_ps_t1b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-t1c-control-no-hijack-rax",
            "zone_b_ps_t1c.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-x1a-weak-template",
            "zone_b_ps_x1a.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1b-comm-template",
            "zone_b_ps_x1b.S",
            ".comm fixed_gate_template,8,8\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1c-abs-template",
            "zone_b_ps_x1c.S",
            ".globl fixed_gate_template\n.set fixed_gate_template, 0x1234\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1d-strong-template",
            "zone_b_ps_x1d.S",
            ".data\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1e-weak-end",
            "zone_b_ps_x1e.S",
            ".data\n.weak fixed_gate_template_end\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n .quad 0\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1f-weak-r12-309",
            "zone_b_ps_x1f.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x28d(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x1z-no-dup-control",
            "zone_b_ps_x1z.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x184(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-x2a-hijack-syscall",
            "zone_b_ps_x2a.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x2b-hijack-indirect",
            "zone_b_ps_x2b.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $fixed_signal_restorer,%rcx\n jmp *%rcx\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x2c-hijack-leaf",
            "zone_b_ps_x2c.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_signal_restorer-0x27e\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x2d-hijack-r12-309",
            "zone_b_ps_x2d.S",
            ".data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x28d(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-x2e-pair2-control",
            "zone_b_ps_x2e.S",
            ".section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-x2f-leaf-control",
            "zone_b_ps_x2f.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%r12\n jmp fixed_signal_restorer-0x27e\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-z4a-direct-r12-200",
            "zone_b_ps_z4a.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x200(%rip),%r12\n jmp fixed_native_entry\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-z4b-jcc-r12-200",
            "zone_b_ps_z4b.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x200(%rip),%r12\n test %edi,%edi\n je fixed_native_entry\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-z4g-alias-r12-200",
            "zone_b_ps_z4g.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_gate_template+0x200(%rip),%r12\n jmp fixed_gate_template+0x7c\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-jc1-call-cross-range",
            "zone_b_ps_jc1.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_entry2,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_entry2\nzone_b_entry2:\n movabs $zone_b_writer,%rax\n jmp .Lzb_join\n.size zone_b_entry2,.-zone_b_entry2\n.globl zone_b_helper\nzone_b_helper:\n ret\n movabs $zone_b_other,%rax\n.Lzb_join:\n call *%rax\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-jc2-call-relocated",
            "zone_b_ps_jc2.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\nzone_b_helper:\n movabs $zone_b_writer,%rax\n .byte 0xe9\n .long 0\n .reloc .-4, R_X86_64_PC32, .Lzb_join-4\n movabs $zone_b_other,%rax\n.Lzb_join:\n call *%rax\n ret\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\nzone_b_writer:\n mov %rdi,%r10\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_other\nzone_b_other:\n ret\n.size zone_b_other,.-zone_b_other\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
        (
            "ps-n13-owner-duplicate",
            "zone_b_ps_n13.S",
            ".data\nfixed_native_entry:\n .quad 0\n.data\n.weak fixed_gate_template\n.globl fixed_gate_template\nfixed_gate_template:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-n13z-no-weak-control",
            "zone_b_ps_n13z.S",
            ".data\nfixed_native_entry:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "unrecognized-outgoing-edge",
        ),
        (
            "ps-n4-local-owner-pair2",
            "zone_b_ps_n4.S",
            ".data\nfixed_native_entry:\n .quad 0\n.section .gate,\"ax\",@progbits\n.globl reverie_inguest_fixed_gate_template\nreverie_inguest_fixed_gate_template:\n nop\n.globl reverie_inguest_fixed_gate_template_end\nreverie_inguest_fixed_gate_template_end:\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n mov %rdi,%rax\n jmp fixed_signal_restorer+9\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "duplicate-gate-bounds",
        ),
        (
            "ps-r1b2-entry-addend-309",
            "zone_b_ps_r1b2_entry_addend_309.S",
            ".text\n.globl zone_b_mutant\nzone_b_mutant:\n lea fixed_native_entry+0x28d(%rip),%r12\n movabs $fixed_native_entry,%rcx\n jmp *%rcx\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
            "indirect-branch",
        ),
    ];
    let mut missing = Vec::new();
    for (label, filename, contents, expected) in probes {
        let mut units = clean_native_units_with(&scratch.0, true);
        let probe_bytes = compile_source(&scratch.0, label, filename, contents, &[]);
        units.push(summarize(label, &probe_bytes).expect("parse production-set probe"));
        let exe_bytes =
            fs::read(std::env::current_exe().unwrap()).expect("read current test binary");
        let exe = summarize("current-exe:exec_private_asm", &exe_bytes)
            .expect("parse current test binary");
        let exe_index = units.len();
        let exe_range = current_exe_asm_range(exe_index, &exe)
            .expect("required exec_private asm symbols must be present in the test binary");
        units.push(exe);
        let mut ranges = Vec::new();
        for (index, unit) in units.iter().enumerate().take(exe_index) {
            ranges.extend(function_ranges(index, unit));
        }
        ranges.push(exe_range);
        let report = check_units(&units, &ranges);
        let kinds: BTreeSet<&str> = report
            .violations
            .iter()
            .filter(|violation| violation.unit == label)
            .map(|violation| violation.kind)
            .collect();
        println!(
            "ZONE-B EXPECTED-FAIL {label} (production set): {} kinds={kinds:?}",
            report.summary()
        );
        if expected.is_empty() {
            if !kinds.is_empty() {
                missing.push(format!(
                    "production-set positive control {label} must not refuse, got {kinds:?}: {:?}",
                    report.violations
                ));
            }
        } else if !kinds.contains(expected) {
            missing.push(format!(
                "production-set probe {label} must refuse with {expected}, got {kinds:?}: {:?}",
                report.violations
            ));
        }
        assert_eq!(
            report.gate_leaf_uses.get("fixed_native_entry"),
            Some(&1),
            "{label}: production gate leaf must still be counted exactly once"
        );
    }
    assert!(
        missing.is_empty(),
        "missing production-set refusals:\n{}",
        missing.join("\n")
    );
}

#[test]
fn duplicate_bound_symbol_in_owner_unit_refuses() {
    // Genuine duplicate symbol entries for one bound name inside the
    // owner unit cannot be produced by the assembler (one entry per
    // name), so this pins the `duplicated` clause itself: objcopy adds
    // a second global fixed_gate_template in .data to an otherwise
    // clean owner fixture. Removing the duplicated clause (keeping
    // the exactly-one-owner rule) makes this object pass.
    let scratch = Scratch::new("dup-bound");
    let bytes = compile_source(
        &scratch.0,
        "dup-bound-owner",
        "zone_b_dup_bound.S",
        ".section .gate,\"ax\",@progbits\n.globl fixed_gate_template\nfixed_gate_template:\n .fill 0x7c,1,0x90\n.globl fixed_native_entry\nfixed_native_entry:\n syscall\n .fill 4,1,0x90\n jmp *%r12\n .fill 16,1,0x90\n.globl fixed_gate_template_end\nfixed_gate_template_end:\n.data\n.globl zb_data\nzb_data: .quad 0\n.text\n.globl zone_b_mutant\nzone_b_mutant:\n ret\n.size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let baseline = check_single("dup-bound-owner", &bytes);
    assert!(
        baseline
            .violations
            .iter()
            .all(|violation| violation.kind != "duplicate-gate-bounds"),
        "clean owner fixture must not draw the duplicate refusal: {:?}",
        baseline.violations
    );
    let source_object = scratch.0.join("dup-bound-owner.o");
    let duplicated_object = scratch.0.join("dup-bound-owner-dup.o");
    let output = Command::new("objcopy")
        .args(["--add-symbol", "fixed_gate_template=.data:0,global"])
        .arg(&source_object)
        .arg(&duplicated_object)
        .output()
        .expect("run objcopy for duplicate bound symbol");
    assert!(
        output.status.success(),
        "objcopy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let duplicated_bytes = fs::read(&duplicated_object).expect("read duplicated object");
    let report = check_single("dup-bound-owner", &duplicated_bytes);
    println!(
        "ZONE-B EXPECTED-FAIL dup-bound-owner: {} kinds={:?}",
        report.summary(),
        report
            .violations
            .iter()
            .map(|violation| violation.kind)
            .collect::<BTreeSet<_>>()
    );
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.kind == "duplicate-gate-bounds"),
        "duplicate bound symbol in the owner unit must refuse: {:?}",
        report.violations
    );
}

#[test]
fn may_write_unresolved_and_syscall_callees_write_kept_register() {
    let scratch = Scratch::new("maywrite-sets");
    let unresolved = compile_source(
        &scratch.0,
        "maywrite-unresolved-unit",
        "zone_b_maywrite_unresolved_unit.S",
        ".text\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n call zone_b_external\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let units = vec![summarize("maywrite-unresolved-unit", &unresolved).unwrap()];
    let ranges = function_ranges(0, &units[0]);
    let starts = instruction_starts(&units, &ranges);
    let writes = compute_may_write(&units, &ranges, &starts);
    let helper = ranges
        .iter()
        .find(|range| range.symbol == "zone_b_helper")
        .expect("helper range");
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| registers.contains(&Register::R10)),
        "unresolved callee must write every GPR: {writes:?}"
    );

    let syscall = compile_source(
        &scratch.0,
        "maywrite-syscall-unit",
        "zone_b_maywrite_syscall_unit.S",
        ".section .gate,\"ax\",@progbits\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n syscall\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let units = vec![summarize("maywrite-syscall-unit", &syscall).unwrap()];
    let ranges = function_ranges(0, &units[0]);
    let starts = instruction_starts(&units, &ranges);
    let writes = compute_may_write(&units, &ranges, &starts);
    let helper = ranges
        .iter()
        .find(|range| range.symbol == "zone_b_helper")
        .expect("syscall helper range");
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| registers.contains(&Register::RAX)),
        "syscall callee must write RAX: {writes:?}"
    );
}

#[test]
fn may_write_tail_successor_writes_kept_register() {
    let scratch = Scratch::new("maywrite-tail-unit");
    let bytes = compile_source(
        &scratch.0,
        "maywrite-tail-unit",
        "zone_b_maywrite_tail_unit.S",
        ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $zone_b_helper,%r10\n call *%r10\n jmp *%r10\n.size zone_b_mutant,.-zone_b_mutant\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n jmp zone_b_writer\n.size zone_b_helper,.-zone_b_helper\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let units = vec![summarize("maywrite-tail-unit", &bytes).unwrap()];
    let ranges = function_ranges(0, &units[0]);
    let starts = instruction_starts(&units, &ranges);
    let writes = compute_may_write(&units, &ranges, &starts);
    let helper = ranges
        .iter()
        .find(|range| range.symbol == "zone_b_helper")
        .expect("helper range");
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| registers.contains(&Register::R10)),
        "tail successor must contribute writer R10: {writes:?} ranges={ranges:?}"
    );
}

#[test]
fn may_write_gate_extend_and_continuation_successor_write_kept_register() {
    let scratch = Scratch::new("maywrite-gate-sets");
    let syscall_less_gate = compile_source(
        &scratch.0,
        "maywrite-gate-extend-unit",
        "zone_b_maywrite_gate_extend_unit.S",
        ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n ret\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea 1f(%rip),%r12\n movabs $fixed_native_entry,%r11\n jmp *%r11\n1: ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let units = vec![summarize("maywrite-gate-extend-unit", &syscall_less_gate).unwrap()];
    let ranges = function_ranges(0, &units[0]);
    let starts = instruction_starts(&units, &ranges);
    let writes = compute_may_write(&units, &ranges, &starts);
    let helper = ranges
        .iter()
        .find(|range| range.symbol == "zone_b_helper")
        .expect("gate helper range");
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| registers.contains(&Register::RCX)),
        "native gate extend must write RCX even when the gate range has no syscall: {writes:?}"
    );
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| !registers.contains(&Register::R10)),
        "syscall-less gate fixture must not collapse to unknown/all-GPR: {writes:?}"
    );

    let continuation = compile_source(
        &scratch.0,
        "maywrite-gate-continuation-unit",
        "zone_b_maywrite_gate_continuation_unit.S",
        ".section .gate,\"ax\",@progbits\n.globl fixed_native_entry\n.type fixed_native_entry,@function\nfixed_native_entry:\n ret\n.size fixed_native_entry,.-fixed_native_entry\n.text\n.globl zone_b_writer\n.type zone_b_writer,@function\nzone_b_writer:\n xor %r10d,%r10d\n ret\n.size zone_b_writer,.-zone_b_writer\n.globl zone_b_helper\n.type zone_b_helper,@function\nzone_b_helper:\n lea zone_b_writer(%rip),%r12\n movabs $fixed_native_entry,%r11\n jmp *%r11\n ret\n.size zone_b_helper,.-zone_b_helper\n.section .note.GNU-stack,\"\",@progbits\n",
        &[],
    );
    let units = vec![summarize("maywrite-gate-continuation-unit", &continuation).unwrap()];
    let ranges = function_ranges(0, &units[0]);
    let starts = instruction_starts(&units, &ranges);
    let writes = compute_may_write(&units, &ranges, &starts);
    let helper = ranges
        .iter()
        .find(|range| range.symbol == "zone_b_helper")
        .expect("continuation helper range");
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| registers.contains(&Register::R10)),
        "gate continuation successor must contribute writer R10: {writes:?} ranges={ranges:?}"
    );
    assert!(
        writes
            .get(&(helper.unit, helper.section, helper.start))
            .is_some_and(|registers| !registers.contains(&Register::R9)),
        "relocated continuation fixture must not collapse to unknown/all-GPR: {writes:?}"
    );
}

#[test]
fn checker_refuses_17_link_backward_chain() {
    let scratch = Scratch::new("chain17");
    let mut source = String::from(
        ".text\n.globl zone_b_mutant\n.type zone_b_mutant,@function\nzone_b_mutant:\n movabs $0x50000000007c,%rax\n jmp .Lzb17\n.Lzb0:\n jmp *%rax\n",
    );
    for link in 1..=17 {
        source.push_str(&format!(".Lzb{link}:\n jmp .Lzb{}\n", link - 1));
    }
    source
        .push_str(".size zone_b_mutant,.-zone_b_mutant\n.section .note.GNU-stack,\"\",@progbits\n");
    let bytes = compile_source(
        &scratch.0,
        "backward-chain-17",
        "zone_b_chain17.S",
        &source,
        &[],
    );
    let report = check_single("backward-chain-17", &bytes);
    println!(
        "ZONE-B EXPECTED-FAIL backward-chain-17: {} kinds={:?} first={:?}",
        report.summary(),
        report
            .violations
            .iter()
            .map(|violation| violation.kind)
            .collect::<BTreeSet<_>>(),
        report.violations.first()
    );
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation.kind == "branch-state-not-converged"),
        "17-link chain must refuse as not converged: {:?}",
        report.violations
    );
}
