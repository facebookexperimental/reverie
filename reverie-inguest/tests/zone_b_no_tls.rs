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
//! into their own relocatable objects with the stack protector and
//! jump tables disabled, then refuse the object set if it contains
//! a TLS relocation, TLS symbol/section, FS-relative memory
//! operand (including the `%fs:0x28` canary), an unresolved
//! outgoing edge other than a recognized swap/gate entry, or an
//! unrecognized indirect branch.
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
//!   and FS-base instructions refuse everywhere.

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
use iced_x86::Mnemonic;
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

/// Assembly leaves whose indirect transfer is the recognized
/// gate or terminal handoff itself, inventoried by exact symbol.
const INDIRECT_GATE_EXCEPTIONS: &[&str] = &[
    "fixed_gate_template",
    "fixed_native_entry",
    "private_native_syscall",
    "private_native_terminal",
    "private_enter_tool_loader",
    "private_runner_resume",
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
            "units={} instructions={} internal_edges={} recognized_indirect={} \
             violations={} skipped_musl_only={:?}",
            self.units.len(),
            self.instructions,
            self.internal_edges,
            self.recognized_indirect,
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
    target_kind: Option<SymbolKind>,
    target_defined: bool,
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
            let (target_name, target_section, target_kind, target_defined) =
                match relocation.target() {
                    RelocationTarget::Symbol(index) => match file.symbol_by_index(index) {
                        Ok(symbol) => (
                            symbol.name().unwrap_or_default().to_owned(),
                            symbol.section_index().map(|index| index.0),
                            Some(symbol.kind()),
                            !symbol.is_undefined(),
                        ),
                        Err(_) => (String::new(), None, None, false),
                    },
                    RelocationTarget::Section(index) => {
                        let name = file
                            .section_by_index(index)
                            .and_then(|section| section.name().map(str::to_owned))
                            .unwrap_or_default();
                        (name, Some(index.0), Some(SymbolKind::Section), true)
                    }
                    RelocationTarget::Absolute => (String::new(), None, None, false),
                    _ => (String::new(), None, None, false),
                };
            relocations.push(RelocInfo {
                offset,
                r_type,
                target_name,
                target_section,
                target_kind,
                target_defined,
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

#[derive(Clone, Debug)]
enum Tracked {
    Address(u64),
    Symbol(String),
}

fn tracked_gate(target: Option<&Tracked>) -> bool {
    match target {
        Some(Tracked::Address(address)) => {
            *address == FIXED_NATIVE_ENTRY || *address == FIXED_GUEST_ENTRY
        }
        Some(Tracked::Symbol(name)) => SWAP_SYMBOLS.contains(&name.as_str()),
        None => false,
    }
}

fn symbol_at(units: &[UnitSummary], address: u64) -> Option<&str> {
    units
        .iter()
        .flat_map(|unit| unit.symbols.iter())
        .find(|symbol| {
            !symbol.undefined
                && symbol.address == address
                && matches!(symbol.kind, SymbolKind::Text | SymbolKind::Label)
        })
        .map(|symbol| symbol.name.as_str())
}

fn check_units(units: &[UnitSummary], ranges: &[ScanRange]) -> Report {
    let mut report = Report {
        units: units.iter().map(|unit| unit.label.clone()).collect(),
        ..Report::default()
    };
    let global_defined: BTreeSet<&str> = units
        .iter()
        .flat_map(|unit| unit.symbols.iter())
        .filter(|symbol| symbol.global && !symbol.undefined)
        .map(|symbol| symbol.name.as_str())
        .collect();

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

    for range in ranges {
        scan_range(units, ranges, range, &global_defined, &mut report);
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
        for (position, symbol) in starts.iter().enumerate() {
            let end = if symbol.size > 0 {
                symbol.address + symbol.size
            } else if let Some(next) = starts
                .iter()
                .skip(position + 1)
                .find(|next| next.address > symbol.address)
            {
                next.address
            } else {
                section.address + section.data.len() as u64
            };
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
}

fn classify_direct_edge(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    global_defined: &BTreeSet<&str>,
) -> DirectEdge {
    if let Some(relocation) = relocations.first() {
        if SWAP_SYMBOLS.contains(&relocation.target_name.as_str()) {
            return DirectEdge::RecognizedSwap;
        }
        if global_defined.contains(relocation.target_name.as_str()) {
            return DirectEdge::Internal;
        }
        if relocation.target_defined {
            if let Some(section) = relocation.target_section
                && units[range.unit]
                    .sections
                    .iter()
                    .any(|candidate| candidate.index == section)
            {
                return DirectEdge::Internal;
            }
            if relocation.target_kind == Some(SymbolKind::Text)
                || relocation.target_kind == Some(SymbolKind::Label)
            {
                return DirectEdge::Internal;
            }
        }
        return DirectEdge::Outgoing;
    }

    let target = instruction.near_branch_target();
    if target == FIXED_NATIVE_ENTRY || target == FIXED_GUEST_ENTRY {
        return DirectEdge::RecognizedSwap;
    }
    if ranges
        .iter()
        .filter(|candidate| !units[range.unit].relocatable || candidate.unit == range.unit)
        .any(|candidate| candidate.start <= target && target < candidate.end)
    {
        return DirectEdge::Internal;
    }
    if let Some(name) = symbol_at(units, target) {
        if SWAP_SYMBOLS.contains(&name) {
            return DirectEdge::RecognizedSwap;
        }
        if global_defined.contains(name) {
            return DirectEdge::Internal;
        }
    }
    DirectEdge::Outgoing
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

fn scan_range(
    units: &[UnitSummary],
    ranges: &[ScanRange],
    range: &ScanRange,
    global_defined: &BTreeSet<&str>,
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
    let mut decoder = Decoder::with_ip(64, bytes, range.start, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut tracked: BTreeMap<Register, Tracked> = BTreeMap::new();
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
        let inside = relocation_inside(&relocations, &instruction, section.address);
        let has_memory = (0..instruction.op_count()).any(|index| {
            matches!(
                instruction.op_kind(index),
                OpKind::Memory
                    | OpKind::MemorySegSI
                    | OpKind::MemorySegESI
                    | OpKind::MemorySegRSI
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
            && !range.symbol.starts_with("fixed_")
        {
            report.refuse(
                &unit.label,
                &range.symbol,
                offset,
                "direct-syscall-outside-gate",
                format!("{entry} instruction outside the fixed gate"),
            );
        }
        scan_branch(
            units,
            ranges,
            range,
            section,
            &instruction,
            &inside,
            global_defined,
            &tracked,
            report,
        );
        update_tracked(&instruction, &inside, &mut tracked);
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
            match classify_direct_edge(units, ranges, range, instruction, relocations, global_defined) {
                DirectEdge::Internal | DirectEdge::RecognizedSwap => {
                    report.internal_edges += 1;
                }
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
                .then(|| tracked.get(&instruction.op_register(0)));
            let handler_call = matches!(register_target, Some(Some(Tracked::Address(address)))
                if symbol_at(units, *address).is_some_and(|name| name.contains("handler")));
            let gate_leaf = INDIRECT_GATE_EXCEPTIONS.contains(&range.symbol.as_str());
            let post_swap_handler_call = instruction.mnemonic() == Mnemonic::Call
                && (range.symbol == "exec_private_asm_block"
                    || range.symbol.contains("private_lifecycle_call"));
            if tracked_gate(register_target.flatten())
                || handler_call
                || gate_leaf
                || post_swap_handler_call
            {
                report.recognized_indirect += 1;
            } else {
                report.refuse(
                    &unit.label,
                    &range.symbol,
                    offset,
                    "indirect-branch",
                    "indirect branch is not a tracked fixed-gate transfer or named gate leaf",
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
    let output_path = directory.join(format!("{label}.o"));
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut command = Command::new("cc");
    command.args([
        "-std=gnu11",
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-stack-protector",
        "-fno-jump-tables",
        "-fno-builtin",
        "-fno-pie",
        "-fno-pic",
        "-fno-asynchronous-unwind-tables",
        "-ffunction-sections",
        "-fdata-sections",
        "-nostdlib",
        "-c",
    ]);
    command.arg("-I").arg(manifest.join("native_exec"));
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

fn clean_native_units(directory: &Path) -> Vec<UnitSummary> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let native = manifest.join("native_exec");
    let specs: Vec<(&str, PathBuf, Vec<&str>)> = vec![
        (
            "private-bootstrap",
            native.join("private-bootstrap.c"),
            Vec::new(),
        ),
        (
            "private-kernel-state",
            native.join("private-kernel-state.c"),
            Vec::new(),
        ),
        ("private-maps", native.join("private-maps.c"), Vec::new()),
        ("private-entry", native.join("private-entry.S"), Vec::new()),
        (
            "private-fs-bootstrap",
            native.join("private-fs.S"),
            vec!["-DEXEC_PRIVATE_BOOTSTRAP_IMAGE"],
        ),
    ];
    specs
        .iter()
        .map(|(label, source, extra)| {
            let bytes = compile_object(directory, label, source, extra);
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

fn update_tracked(
    instruction: &Instruction,
    relocations: &[&RelocInfo],
    tracked: &mut BTreeMap<Register, Tracked>,
) {
    if instruction.op_count() == 0 || instruction.op_kind(0) != OpKind::Register {
        return;
    }
    let destination = instruction.op_register(0);
    let value = if let Some(relocation) = relocations.first() {
        (!relocation.target_name.is_empty())
            .then(|| Tracked::Symbol(relocation.target_name.clone()))
    } else {
        None
    };
    let value = value.or_else(|| match instruction.mnemonic() {
        Mnemonic::Mov => match instruction.op_kind(1) {
            OpKind::Immediate64 => Some(Tracked::Address(instruction.immediate64())),
            OpKind::Immediate32 => Some(Tracked::Address(u64::from(instruction.immediate32()))),
            OpKind::Register => tracked.get(&instruction.op_register(1)).cloned(),
            _ => None,
        },
        Mnemonic::Lea if instruction.is_ip_rel_memory_operand() => {
            Some(Tracked::Address(instruction.ip_rel_memory_address()))
        }
        _ => None,
    });
    match value {
        Some(value) => {
            tracked.insert(destination, value);
        }
        None => {
            tracked.remove(&destination);
        }
    }
}

fn check_single(label: &str, bytes: &[u8]) -> Report {
    let units = vec![summarize(label, bytes).expect("parse zone-B test object")];
    let ranges = function_ranges(0, &units[0]);
    check_units(&units, &ranges)
}

#[test]
fn clean_zone_b_objects_pass() {
    // Retain the Rust asm bridges in this test binary for the
    // current-exe symbol-range scan below.
    std::hint::black_box(reverie_inguest::guest::exec_private::physical_syscall as *const ());
    let scratch = Scratch::new("clean");
    let mut units = clean_native_units(&scratch.0);
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
    println!("ZONE-B PASS clean: {}", report.summary());
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
    ];
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
        assert!(
            kinds.contains(expected),
            "mutant {label} must refuse with {expected}, got {kinds:?}: {:?}",
            report.violations
        );
    }
}
