// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Production producer of a mapped first image's runtime inputs: the audited
//! private runtime image, one birth's descriptor leases, and the fixed
//! placement its copied inputs and handoff use.
//!
//! The audit checks the image against the embedder's facts about it
//! ([`RuntimeImageFacts`]):
//! - the SHA-256 that binds the facts to these exact bytes;
//! - the runtime window policy and the private runtime metadata;
//! - the exact HLMLAY01 descriptor and the read-only reference page;
//! - the image's one syscall gate, the page HLMLAY01 word 10 names: executable,
//!   byte-identical to the read-only reference page, and holding the exact
//!   native gate encoding at word 11;
//! - an instruction audit: a linear-sweep decode of every executable page,
//!   which refuses any undecodable byte, every `int 0x80` and `sysenter`, and
//!   any decoded `syscall` outside the gate page that is not a declared site of
//!   the facts ([`SyscallCensus`]);
//! - an IP-filter proof ([`FilterCoverage`]): the filter the preparation
//!   installs allows syscalls only at the gate's own template sites, for
//!   `AUDIT_ARCH_X86_64` only (x32 calls included, as Linux reports them),
//!   and traps or kills everything else, including every `0f 05` pair inside
//!   another instruction's bytes, which the sweep does not see.
//!
//! Status (B3): instruction audit and IP-filter proof present; B3(d), the same
//! counts measured on an image built at the current pins, pending. Nothing
//! here claims B3 closed.
//!
//! The producer holds no stop, wait, supervisor, admission or Ready state. The
//! launch route owns every operation on the task; the only task-facing step
//! here is the packet fill, which the route calls with its own stop and
//! admission.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie_loader::artifact::RUNTIME_POLICY;
use reverie_loader::artifact::RUNTIME_WINDOW;
use reverie_loader::artifact::TOOL_REGION;
use reverie_loader::handoff;
use reverie_loader::handoff::Extent;
use reverie_loader::image::ValidatedImage;
use reverie_loader::init_packet::MAX_PACKET_LEN;
use sha2::Digest;

use super::CopiedInitialData;
use super::CopiedInputRequest;
use super::Result;
use super::initial_inputs::CapturedInitialInputs;
use super::physical::Preparation;
use super::physical::RuntimeEntrySpec;

mod claim;
mod filter;
mod wire;

pub use claim::ArmedClaim;
pub use claim::ArtifactAudit;
pub use claim::BINDING_SLOTS;
pub use claim::CLAIM_FOREIGN_PREPARATION;
pub use claim::ClaimRefusal;
pub use claim::ExpectedDigest;
pub use claim::HANDOFF_BINDING_UNBOUND;
pub use claim::HandoffBinding;
pub use claim::LAYOUT_DIGEST_MISMATCH;
pub use claim::MappedLaunchClaim;
pub use claim::MappedLaunchFacts;
pub use claim::QUALIFICATION_GAPS;
pub use claim::QualificationGap;
pub use claim::QualifiedMappedLaunch;
pub use claim::RUNTIME_ARTIFACT_UNAUDITED;
pub use claim::RUNTIME_DIGEST_MISMATCH;
pub use claim::launch_label;
pub use filter::AllowedNumbers;
pub use filter::FilterCoverage;
pub use wire::WIRE_ARCH_AARCH64;
pub use wire::WIRE_ARCH_WORD;
pub use wire::WIRE_ARCH_X86_64;
pub use wire::WireArch;
pub use wire::wire_arch;

const PAGE: u64 = 4096;
/// Bound on a retained runtime image.
const MAX_IMAGE_BYTES: usize = 512 * 1024 * 1024;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
/// The private runtime image's one syscall gate: its second page, which
/// HLMLAY01 word 10 names. The first page is the read-only image header; the
/// measured staged image (2cf43758...) maps no executable byte there.
const NATIVE_GATE: Range<u64> = RUNTIME_WINDOW.start + PAGE..RUNTIME_WINDOW.start + 2 * PAGE;
/// The native gate's instructions at HLMLAY01 word 11 (`NATIVE_GATE.start +
/// 0x7c`): `endbr64; syscall; jmp r12`, as the borrowed-entry handover requires.
const NATIVE_GATE_BYTES: [u8; 9] = [0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x05, 0x41, 0xff, 0xe4];
/// The one data island in a runtime image's text: the message this crate's
/// constructor entry (`guest/tool_region_constructor.rs`) places right after
/// its terminal `endbr64; ud2`. It holds no `0x0f` byte, so no `syscall`
/// encoding. Moving the message to `.rodata` deletes this exemption.
const CONSTRUCTOR_MESSAGE: &[u8] = b"reverie constructor bootstrap failed\n";
/// The constructor entry's symbol and its pinned layout, as the private-static
/// artifact qualifier pins it (`reverie-liteinst-artifact`, the constructor
/// `native_dispatch_bridge` case: 744 bytes, terminal `ud2` at +0x2c1, the
/// message from +0x2c3 to the end). These are code constants, never image
/// facts or runtime input; only the symbol's address comes from the image.
const CONSTRUCTOR_SYMBOL: &[u8] = b"reverie_inguest_constructor_entry";
const CONSTRUCTOR_BYTES: u64 = 744;
const CONSTRUCTOR_LEAD_OFFSET: u64 = 0x2bd;
const CONSTRUCTOR_LEAD: [u8; 6] = [0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x0b];
const CONSTRUCTOR_MESSAGE_OFFSET: u64 = 0x2c3;

fn require(ok: bool, why: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}

/// The embedder's measured facts about its runtime image: the coordinates the
/// image's build published. They are checked against the retained bytes here
/// and used by the handoff; they are DATA, not a qualification by themselves.
///
/// `image_sha256` binds them to the bytes: the audit refuses any other image,
/// so the declared sites it allows are always the ones published for exactly
/// the bytes it scans. That is all the producer can check. It cannot tell an
/// authentic image-and-facts pair from a forged pair that matches itself, and
/// a facts file is not authenticated by being well-formed. AUTHENTICATING the
/// pair is the embedder's job: read both from one package that only the
/// trusted installer writes, check their owner and that neither changes, and
/// retain the opened files for the whole run; never take facts from free-form
/// input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeImageFacts {
    /// SHA-256 of the exact image bytes these facts describe.
    pub image_sha256: [u8; 32],
    /// Address of the 96-byte HLMLAY01 target descriptor.
    pub layout_address: u64,
    /// Address of the read-only reference page.
    pub reference_address: u64,
    /// The four bootstrap syscall sites: `[ip, post, number, operation]`.
    pub sites: [[u64; 4]; 4],
    /// Sorted return addresses of the ordinary (ToolInit) syscall sites.
    pub ordinary_post_ips: Vec<u64>,
    /// Address of the bootstrap SIGSYS handler.
    pub handler_address: u64,
    /// Length of the handler's code.
    pub handler_bytes: u64,
    /// SHA-256 of the handler's code.
    pub handler_sha256: [u8; 32],
    /// Address of the image's `/dev/null\0` literal, in a read-only segment.
    pub dev_null_address: u64,
    /// The runtime entry an initial birth uses, when the image has one.
    pub initial_entry: Option<EntryPoint>,
    /// The runtime entry a successor birth uses, when the image has one.
    pub successor_entry: Option<EntryPoint>,
    /// Data the image's build placed inside executable segments (literal
    /// pools), as address ranges. x86-64 images declare none: this audit
    /// refuses any non-empty value, so on x86-64 the only data stepped over
    /// is the pinned constructor island. The aarch64 audit may admit ranges
    /// only under these conditions: each range starts a run, abuts another
    /// range or the island, or follows an instruction that never falls
    /// through (an unconditional branch, a return, `udf` or `brk`); no range
    /// covers an entry, a terminal trap, the handler, a declared site or the
    /// gate page; no range holds a syscall encoding at any alignment; the
    /// total bytes are bounded as well as the count; the facts come from an
    /// authenticated source; and refusal tests cover fall-through
    /// constructions.
    pub data_ranges: Vec<Range<u64>>,
}

/// A runtime entry: the private C entry and its terminal trap instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPoint {
    /// The entry, called with (handoff pointer, length).
    pub entry: u64,
    /// The `int3` the entry reaches when initialization returns.
    pub terminal_trap: u64,
}

impl RuntimeImageFacts {
    /// First-byte addresses of every declared syscall site outside the gate.
    fn declared_sites(&self) -> Result<Vec<u64>> {
        let mut declared: Vec<u64> = self.sites.iter().map(|site| site[0]).collect();
        for &post in &self.ordinary_post_ips {
            declared.push(post.checked_sub(2).ok_or("ordinary site underflow")?);
        }
        Ok(declared)
    }
}

/// Names the producer's memfds carry. The names show in the guest's
/// `/proc/self/maps`, so an embedder keeps the ones its guests already see.
#[derive(Clone, Copy, Debug)]
pub struct MemfdNames {
    /// The sealed runtime image and the empty handoff.
    pub runtime: &'static std::ffi::CStr,
    /// The input packet lease.
    pub packet: &'static std::ffi::CStr,
}

/// A private runtime image audited once, and its retained bytes. "Audited"
/// is not "qualified": whether a launch of it may be called qualified is
/// [`QualifiedMappedLaunch::claim`]'s question.
pub struct AuditedRuntimeImage {
    bytes: Vec<u8>,
    facts: RuntimeImageFacts,
    descriptor: [u64; 12],
    layout_sha256: [u8; 32],
    census: SyscallCensus,
    filter: FilterCoverage,
}

impl std::fmt::Debug for AuditedRuntimeImage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditedRuntimeImage")
            .field("bytes", &self.bytes.len())
            .field("facts", &self.facts)
            .field("census", &self.census)
            .field("filter", &self.filter)
            .finish_non_exhaustive()
    }
}

impl AuditedRuntimeImage {
    /// Audit `bytes` against `facts`: ELF and window policy, the private
    /// runtime metadata, the exact HLMLAY01 descriptor, the read-only
    /// reference page, the native gate page, every declared site's `syscall`
    /// bytes, no undeclared decoded `syscall`, `int 0x80` or `sysenter`, and
    /// the IP-filter proof, which covers the `0f 05` pairs inside other
    /// instructions. B3: instruction audit and IP-filter proof present; B3(d),
    /// counts on a current-pin image, pending.
    pub fn new(bytes: Vec<u8>, facts: RuntimeImageFacts) -> Result<Self> {
        require(
            !bytes.is_empty() && bytes.len() <= MAX_IMAGE_BYTES,
            "retained image size",
        )?;
        require(
            <[u8; 32]>::from(sha2::Sha256::digest(&bytes)) == facts.image_sha256,
            "runtime image bytes differ from the facts' image_sha256",
        )?;
        let declared = facts.declared_sites()?;
        let (descriptor, layout_sha256, census, filter) = {
            let image = validate(&bytes)?;
            image
                .private_runtime_metadata()
                .map_err(|e| format!("private metadata: {e:?}"))?;
            let raw = exact_ro(&image, facts.layout_address, 96)?;
            let layout_sha256: [u8; 32] = sha2::Sha256::digest(&raw).into();
            let mut descriptor = [0; 12];
            for (out, row) in descriptor.iter_mut().zip(raw.as_chunks::<8>().0) {
                *out = u64::from_le_bytes(*row);
            }
            require(
                descriptor[..6]
                    == [
                        u64::from_le_bytes(*b"HLMLAY01"),
                        1,
                        96,
                        handoff::VERSION,
                        handoff::HEADER_BYTES as u64,
                        handoff::MAX_BYTES as u64,
                    ]
                    && descriptor[6] > 0
                    && descriptor[8] > 0
                    && descriptor[7].is_power_of_two()
                    && descriptor[9].is_power_of_two()
                    && descriptor[10] == NATIVE_GATE.start
                    && descriptor[11] == descriptor[10] + 0x7c,
                "actual layout descriptor",
            )?;
            check_native_gate(&image, facts.reference_address)?;
            for [ip, post, _, _] in facts.sites {
                require(
                    ip.checked_add(2) == Some(post) && exact_rx(&image, ip, 2)? == [0x0f, 0x05],
                    "actual syscall/post instruction bytes",
                )?;
            }
            let mut seen = [false; 4];
            for [_, _, number, operation] in facts.sites {
                let slot = match (operation, number) {
                    (1, 158) => 0,
                    (2, 218) => 1,
                    (3, 7) => 2,
                    (4, 2) => 3,
                    _ => return Err("measured operation/number".into()),
                };
                require(!seen[slot], "duplicate measured role")?;
                seen[slot] = true;
            }
            require(
                !facts.ordinary_post_ips.is_empty()
                    && facts.ordinary_post_ips.len() <= 4096
                    && facts.ordinary_post_ips.windows(2).all(|p| p[0] < p[1]),
                "finite unique sorted ToolInit sites",
            )?;
            require(
                facts.handler_bytes > 0 && facts.handler_bytes <= 64 * 1024,
                "handler observation bounds",
            )?;
            let handler = exact_rx(&image, facts.handler_address, facts.handler_bytes as usize)?;
            require(
                <[u8; 32]>::from(sha2::Sha256::digest(handler)) == facts.handler_sha256,
                "actual handler bytes",
            )?;
            require(
                exact_ro(&image, facts.dev_null_address, 10)? == b"/dev/null\0",
                "actual ELF dev-null literal",
            )?;
            require(
                facts.initial_entry.is_some() || facts.successor_entry.is_some(),
                "no runtime entry",
            )?;
            for entry in [facts.initial_entry, facts.successor_entry]
                .into_iter()
                .flatten()
            {
                exact_rx(&image, entry.entry, 1).map_err(|_| "runtime entry is not executable")?;
                require(
                    exact_rx(&image, entry.terminal_trap, 1).ok() == Some(&[0xcc][..]),
                    "runtime terminal trap is not int3",
                )?;
            }
            let runs = executable_runs(&image)?;
            let island = constructor_island(&image, &bytes)?;
            let census =
                instruction_audit(&runs, &NATIVE_GATE, &declared, island, &facts.data_ranges)?;
            let filter = filter::prove(
                &super::physical::target_recipe(NATIVE_GATE.start)?,
                &runs,
                &NATIVE_GATE,
                &declared,
            )?;
            (descriptor, layout_sha256, census, filter)
        };
        Ok(Self {
            bytes,
            facts,
            descriptor,
            layout_sha256,
            census,
            filter,
        })
    }

    /// The retained bytes, revalidated against the runtime policy (validation
    /// borrows them, so it is not stored). The whole audit already passed on
    /// these exact immutable bytes.
    pub fn validated_image(&self) -> Result<ValidatedImage<'_>> {
        validate(&self.bytes)
    }

    /// What the instruction audit counted.
    pub fn census(&self) -> &SyscallCensus {
        &self.census
    }

    /// What the filter proof established.
    pub fn filter_coverage(&self) -> &FilterCoverage {
        &self.filter
    }

    /// The audited form of [`ArtifactAudit`], for a qualification claim.
    pub fn artifact_audit(&self) -> ArtifactAudit {
        ArtifactAudit::audited(self.census.clone(), self.filter.clone())
    }

    /// SHA-256 of the 96-byte HLMLAY01 descriptor.
    pub fn layout_sha256(&self) -> &[u8; 32] {
        &self.layout_sha256
    }

    /// The exact retained bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The facts the image was audited against.
    pub fn facts(&self) -> &RuntimeImageFacts {
        &self.facts
    }

    /// The `length` bytes at virtual `address`, taken from one initialized
    /// executable segment of this audited image. It returns audited bytes
    /// and does not judge them: what they must be is the caller's check.
    /// Refused, each by name: an empty range; a range whose end overflows;
    /// and a range not wholly inside the initialized bytes of one
    /// executable segment (crossing a segment edge, in a non-executable
    /// segment, or outside every segment).
    pub fn exact_executable(&self, address: u64, length: usize) -> Result<&[u8]> {
        require(length != 0, "executable range is empty")?;
        require(
            address.checked_add(length as u64).is_some(),
            "executable range end overflows",
        )?;
        exact_rx(&validate(&self.bytes)?, address, length)
            .map_err(|_| "executable range is not inside one executable segment".into())
    }

    /// The decoded HLMLAY01 words.
    pub fn descriptor(&self) -> &[u64; 12] {
        &self.descriptor
    }

    /// The copied-input request for a birth of this image at the fixed
    /// placement. The route passes it, with this image's
    /// [`validated_image`](Self::validated_image), to `prepare_copied_inputs`.
    pub fn copied_input_request(&self) -> Result<CopiedInputRequest> {
        let placement = Placement::fixed()?;
        let control = placement.roles[4]
            .start
            .checked_add(PAGE)
            .ok_or("control overflow")?;
        let relay = aligned(
            control
                .checked_add(self.descriptor[6])
                .ok_or("relay overflow")?,
            self.descriptor[9],
        )?;
        let address = placement.roles[3]
            .start
            .checked_add(PAGE)
            .ok_or("handoff address")?;
        let copied_address = address.checked_add(2 * PAGE).ok_or("copied address")?;
        let copied_capacity = usize::try_from(
            placement.roles[3]
                .end
                .checked_sub(PAGE)
                .and_then(|end| end.checked_sub(copied_address))
                .ok_or("copied capacity")?,
        )?;
        Ok(CopiedInputRequest {
            roles: placement.roles,
            free_band: placement.free_band,
            layout_address: self.facts.layout_address,
            copied_address,
            copied_capacity,
            control_address: control,
            relay_address: relay,
            filter_scratch: placement.filter_scratch,
        })
    }
}

fn validate(bytes: &[u8]) -> Result<ValidatedImage<'_>> {
    reverie_loader::image::Image::parse(bytes)
        .map_err(|e| format!("ELF: {e:?}"))?
        .validate(&RUNTIME_POLICY)
        .map_err(|e| format!("ELF policy: {e:?}").into())
}

/// The gate page must lie in one executable, non-writable segment, equal the
/// image's read-only reference page byte for byte, and hold
/// [`NATIVE_GATE_BYTES`] at offset 0x7c.
fn check_native_gate(image: &ValidatedImage<'_>, reference_address: u64) -> Result<()> {
    let reference = exact_ro(image, reference_address, PAGE as usize)?;
    let gate = exact_rx(image, NATIVE_GATE.start, PAGE as usize)
        .map_err(|_| "native gate page is missing or not executable")?;
    require(
        gate.get(0x7c..0x7c + NATIVE_GATE_BYTES.len()) == Some(&NATIVE_GATE_BYTES[..]),
        "native gate encoding differs",
    )?;
    require(
        gate == &reference[..],
        "native gate page differs from its read-only reference page",
    )
}

/// The pinned address of the constructor message island in `bytes`, from the
/// image's own symbol table: `reverie_inguest_constructor_entry` + 0x2c3.
/// Without that symbol there is no exemption (`None`), and the message, if
/// present, is swept as code. With it, the layout must not have drifted: more
/// than one such symbol, a size other than the pinned 744 bytes, or anything
/// but an executable `endbr64; ud2` at +0x2bd is refused by name, so a drift
/// never turns the exemption off silently.
fn constructor_island(image: &ValidatedImage<'_>, bytes: &[u8]) -> Result<Option<u64>> {
    let symbols = symbols_named(bytes, CONSTRUCTOR_SYMBOL)?;
    require(
        symbols.len() <= 1,
        "more than one reverie_inguest_constructor_entry symbol",
    )?;
    let Some(&(value, size)) = symbols.first() else {
        return Ok(None);
    };
    if size != CONSTRUCTOR_BYTES {
        return Err(format!(
            "reverie_inguest_constructor_entry drifted: size {size} != {CONSTRUCTOR_BYTES}"
        )
        .into());
    }
    let lead = value
        .checked_add(CONSTRUCTOR_LEAD_OFFSET)
        .ok_or("constructor lead overflow")?;
    let bytes = exact_rx(image, lead, CONSTRUCTOR_LEAD.len()).map_err(|_| {
        format!(
            "reverie_inguest_constructor_entry drifted: +{CONSTRUCTOR_LEAD_OFFSET:#x} is not executable"
        )
    })?;
    if bytes != CONSTRUCTOR_LEAD {
        return Err(format!(
            "reverie_inguest_constructor_entry drifted: the bytes at +{CONSTRUCTOR_LEAD_OFFSET:#x} are not endbr64; ud2"
        )
        .into());
    }
    Ok(Some(
        value
            .checked_add(CONSTRUCTOR_MESSAGE_OFFSET)
            .ok_or("constructor island overflow")?,
    ))
}

/// `(st_value, st_size)` of every `.symtab` symbol named `name` in the ELF64
/// little-endian `bytes`. No section headers or no symbol table gives none;
/// a malformed table is refused, with every offset computed checked.
fn symbols_named(bytes: &[u8], name: &[u8]) -> Result<Vec<(u64, u64)>> {
    fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
        let end = at
            .checked_add(N)
            .ok_or("ELF section table offset overflow")?;
        Ok(bytes
            .get(at..end)
            .ok_or("ELF section table bounds")?
            .try_into()?)
    }
    let u16_at = |at: usize| {
        Ok::<u64, Box<dyn std::error::Error>>(u16::from_le_bytes(field(bytes, at)?).into())
    };
    let u32_at = |at: usize| {
        Ok::<u64, Box<dyn std::error::Error>>(u32::from_le_bytes(field(bytes, at)?).into())
    };
    let u64_at =
        |at: usize| Ok::<u64, Box<dyn std::error::Error>>(u64::from_le_bytes(field(bytes, at)?));
    let index = |value: u64| usize::try_from(value).map_err(|_| "ELF offset overflow");
    let add = |a: usize, b: usize| a.checked_add(b).ok_or("ELF section table offset overflow");
    let mul = |a: usize, b: usize| a.checked_mul(b).ok_or("ELF section table offset overflow");
    let shoff = index(u64_at(0x28)?)?;
    let shnum = index(u16_at(0x3c)?)?;
    if shoff == 0 || shnum == 0 {
        return Ok(Vec::new());
    }
    require(u16_at(0x3a)? == 64, "ELF section header size")?;
    let header = |i: usize| add(shoff, mul(i, 64)?);
    let mut symbols = Vec::new();
    for i in 0..shnum {
        if u32_at(add(header(i)?, 4)?)? != 2 {
            continue; // not SHT_SYMTAB
        }
        require(
            u64_at(add(header(i)?, 0x38)?)? == 24,
            "ELF symbol entry size",
        )?;
        let table = index(u64_at(add(header(i)?, 0x18)?)?)?;
        let count = index(u64_at(add(header(i)?, 0x20)?)?)? / 24;
        let link = index(u32_at(add(header(i)?, 0x28)?)?)?;
        require(link < shnum, "ELF symbol string table index")?;
        let strings = header(link)?;
        let strtab = index(u64_at(add(strings, 0x18)?)?)?;
        let strsize = index(u64_at(add(strings, 0x20)?)?)?;
        let names = bytes
            .get(strtab..add(strtab, strsize)?)
            .ok_or("ELF string table bounds")?;
        for symbol in 0..count {
            let at = add(table, mul(symbol, 24)?)?;
            let offset = index(u32_at(at)?)?;
            let rest = names.get(offset..).ok_or("ELF symbol name bounds")?;
            if rest.len() > name.len() && &rest[..name.len()] == name && rest[name.len()] == 0 {
                symbols.push((u64_at(add(at, 8)?)?, u64_at(add(at, 16)?)?));
            }
        }
    }
    Ok(symbols)
}

/// What the instruction audit of a runtime image counted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallCensus {
    /// Executable bytes decoded: every byte of every executable page, once.
    pub executable_bytes: u64,
    /// Instructions decoded.
    pub instructions: u64,
    /// Decoded `syscall` instructions inside the gate page.
    pub in_gate: u64,
    /// Decoded `syscall` instructions at declared sites; equal to the number
    /// of distinct declared sites.
    pub at_declared_sites: u64,
    /// Bytes stepped over as the constructor message island (0 or its length).
    pub data_island_bytes: u64,
}

/// One run of abutting executable pages, as the mapping exposes them (the file
/// bytes from the page-aligned offset, then zeros to the end of the last page),
/// and the addresses where one executable segment hands over to the next.
struct Run {
    start: u64,
    bytes: Vec<u8>,
    boundaries: Vec<u64>,
}

/// Every executable page of `image`: segments sorted by address, abutting ones
/// joined into one run, and a page shared by two of them refused.
fn executable_runs(image: &ValidatedImage<'_>) -> Result<Vec<Run>> {
    let mut executable: Vec<_> = image
        .segments()
        .filter(|segment| segment.permissions.execute)
        .collect();
    executable.sort_unstable_by_key(|segment| segment.memory.start);
    let mut runs: Vec<Run> = Vec::new();
    for segment in executable {
        let pages = segment.pages().map_err(|e| format!("pages: {e:?}"))?;
        let length = usize::try_from(pages.end - pages.start)?;
        let file = image
            .mapped_file_bytes(segment)
            .map_err(|e| format!("executable bytes: {e:?}"))?;
        let mut bytes = file[..file.len().min(length)].to_vec();
        bytes.resize(length, 0);
        match runs.last_mut() {
            Some(run) if run.start + run.bytes.len() as u64 == pages.start => {
                run.boundaries.push(pages.start);
                run.bytes.extend_from_slice(&bytes);
            }
            Some(run) if run.start + run.bytes.len() as u64 > pages.start => {
                return Err(
                    format!("executable segments share the page at {:#x}", pages.start).into(),
                );
            }
            _ => runs.push(Run {
                start: pages.start,
                bytes,
                boundaries: Vec::new(),
            }),
        }
    }
    Ok(runs)
}

/// The gate page offsets of its three `syscall` instructions: the native gate,
/// the PKRU gate body and the `rt_sigreturn` restorer, as the gate template
/// pins them (`trap/fixed_gates.rs`).
const GATE_SYSCALL_OFFSETS: [u64; 3] = [0x80, 0x200, 0x309];

/// Linear-sweep decode of the image's executable `runs`, each byte exactly
/// once, with Intel and AMD decoding run in lockstep: the two must agree on
/// every instruction's address, length and form, so no vendor-dependent
/// decoding hides a syscall. Refuses:
/// - any undecodable or truncated instruction (no resync);
/// - an instruction that crosses from one executable segment into the next;
/// - `int 0x80` and `sysenter` anywhere;
/// - a `syscall` that is not the bare two-byte `0f 05`;
/// - a `syscall` in the gate page other than one at each of
///   [`GATE_SYSCALL_OFFSETS`], exactly once each;
/// - a `syscall` outside the gate page that is not in `declared`;
/// - a declared site that is not a decoded `syscall`.
///
/// The only bytes not decoded as instructions are the [`CONSTRUCTOR_MESSAGE`]
/// at `island`, the pinned address [`constructor_island`] found, and only
/// where the sweep reaches it straight after the pinned `endbr64; ud2`. The
/// message anywhere else, a changed message, or the pinned address reached any
/// other way is refused by name.
///
/// Declared `data` ranges are refused on x86-64, by name, before the sweep:
/// a range can start where the instruction before it falls through, and so
/// hide a system call the CPU reaches by straight-line execution.
fn instruction_audit(
    runs: &[Run],
    gate: &Range<u64>,
    declared: &[u64],
    island: Option<u64>,
    data: &[Range<u64>],
) -> Result<SyscallCensus> {
    use iced_x86::Code;
    let mut declared: Vec<u64> = declared.to_vec();
    declared.sort_unstable();
    declared.dedup();
    require(
        data.is_empty(),
        "instruction audit: declared data ranges are not admitted on x86-64",
    )?;
    let mut found = vec![false; declared.len()];
    let mut in_gate = [0_u64; GATE_SYSCALL_OFFSETS.len()];
    let mut census = SyscallCensus::default();
    let mut intel = iced_x86::Instruction::default();
    let mut amd = iced_x86::Instruction::default();
    for run in runs {
        let (start, bytes) = (run.start, &run.bytes[..]);
        let mut decoders = [
            iced_x86::Decoder::with_ip(64, bytes, start, iced_x86::DecoderOptions::NONE),
            iced_x86::Decoder::with_ip(64, bytes, start, iced_x86::DecoderOptions::AMD),
        ];
        let mut previous = Code::INVALID;
        let mut covered = 0_usize;
        while decoders[0].can_decode() {
            let before = previous;
            decoders[0].decode_out(&mut intel);
            decoders[1].decode_out(&mut amd);
            let ip = intel.ip();
            if intel.is_invalid() || amd.is_invalid() {
                return Err(format!(
                    "instruction audit: undecodable bytes at {ip:#x} ({:?})",
                    decoders[0].last_error()
                )
                .into());
            }
            require(
                (amd.ip(), amd.len(), amd.code()) == (ip, intel.len(), intel.code()),
                &format!("instruction audit: Intel and AMD decodings differ at {ip:#x}"),
            )?;
            previous = intel.code();
            covered += intel.len();
            census.instructions += 1;
            let position = decoders[0].position();
            let next_address = start + position as u64;
            if let Some(boundary) = run
                .boundaries
                .iter()
                .find(|&&boundary| ip < boundary && boundary < next_address)
            {
                return Err(format!(
                    "instruction audit: instruction at {ip:#x} crosses the executable segment boundary at {boundary:#x}"
                )
                .into());
            }
            let lead = intel.code() == Code::Ud2 && before == Code::Endbr64;
            if lead && island == Some(next_address) && census.data_island_bytes == 0 {
                require(
                    bytes.get(position..position + CONSTRUCTOR_MESSAGE.len())
                        == Some(CONSTRUCTOR_MESSAGE),
                    "instruction audit: constructor message island differs",
                )?;
                let next = position + CONSTRUCTOR_MESSAGE.len();
                for decoder in &mut decoders {
                    decoder
                        .set_position(next)
                        .map_err(|e| format!("instruction audit: island: {e}"))?;
                    decoder.set_ip(start + next as u64);
                }
                covered += CONSTRUCTOR_MESSAGE.len();
                census.data_island_bytes = CONSTRUCTOR_MESSAGE.len() as u64;
                previous = Code::INVALID;
                continue;
            }
            if let Some(island) = island
                && census.data_island_bytes == 0
                && ip <= island
                && island < next_address
            {
                return Err(format!(
                    "instruction audit: constructor message island at {island:#x} is not preceded by endbr64; ud2"
                )
                .into());
            }
            if lead
                && bytes.get(position..position + CONSTRUCTOR_MESSAGE.len())
                    == Some(CONSTRUCTOR_MESSAGE)
            {
                return Err(format!(
                    "instruction audit: constructor message at {next_address:#x} is not the pinned island"
                )
                .into());
            }
            match intel.code() {
                Code::Sysenter => {
                    return Err(format!("instruction audit: sysenter at {ip:#x}").into());
                }
                Code::Int_imm8 if intel.immediate8() == 0x80 => {
                    return Err(format!("instruction audit: int 0x80 at {ip:#x}").into());
                }
                Code::Syscall => {}
                _ => continue,
            }
            require(
                intel.len() == 2,
                &format!("instruction audit: syscall at {ip:#x} is not the bare 0f 05"),
            )?;
            if gate.contains(&ip) {
                let at = GATE_SYSCALL_OFFSETS
                    .iter()
                    .position(|&offset| gate.start + offset == ip)
                    .ok_or_else(|| {
                        format!(
                            "instruction audit: gate-page syscall at {ip:#x} is not a template site"
                        )
                    })?;
                in_gate[at] += 1;
                census.in_gate += 1;
            } else if let Ok(at) = declared.binary_search(&ip) {
                found[at] = true;
                census.at_declared_sites += 1;
            } else {
                return Err(format!("instruction audit: undeclared syscall at {ip:#x}").into());
            }
        }
        require(
            covered == bytes.len() && decoders[0].position() == bytes.len(),
            "instruction audit did not cover every executable byte exactly once",
        )?;
        census.executable_bytes += bytes.len() as u64;
    }
    require(
        in_gate == [1; GATE_SYSCALL_OFFSETS.len()],
        "instruction audit: the gate page lacks one of its template syscalls",
    )?;
    if let Some(at) = found.iter().position(|found| !found) {
        return Err(format!(
            "instruction audit: declared site {:#x} is not a decoded syscall",
            declared[at]
        )
        .into());
    }
    Ok(census)
}

/// Proposed roles (stack, TLS, bootstrap signal stack, handoff, scalar state;
/// guards included), the shared free band and the filter staging address.
/// These are fallible proposals, not observed mappings: the copied-input and
/// shared validation, then the no-replace injector, check every role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The five roles.
    pub roles: [Extent; 5],
    /// The shared free band, DATA_FIRST = 1 MiB to TOOL_BAND page 65535.
    pub free_band: Extent,
    /// Filter staging, inside the scalar-state role.
    pub filter_scratch: u64,
}

impl Placement {
    /// The fixed placement every birth uses.
    pub fn fixed() -> Result<Self> {
        let first = TOOL_REGION
            .start
            .checked_add(1024 * 1024)
            .ok_or("role start overflow")?;
        let last = TOOL_REGION
            .start
            .checked_add(65535 * PAGE)
            .ok_or("free band overflow")?;
        let mut cursor = first;
        let mut roles = [Extent { start: 0, end: 0 }; 5];
        for (role, pages) in roles.iter_mut().zip([256_u64, 64, 256, 256, 256]) {
            let end = cursor
                .checked_add(pages.checked_mul(PAGE).ok_or("role bytes overflow")?)
                .ok_or("role end overflow")?;
            require(end <= last, "proposed roles exceed shared free band")?;
            *role = Extent { start: cursor, end };
            cursor = end;
        }
        let filter_scratch = roles[4]
            .start
            .checked_add(8 * PAGE)
            .ok_or("filter staging overflow")?;
        Ok(Self {
            roles,
            free_band: Extent {
                start: first,
                end: last,
            },
            filter_scratch,
        })
    }
}

/// `value` rounded up to a power-of-two `alignment`.
pub(crate) fn aligned(value: u64, alignment: u64) -> Result<u64> {
    require(alignment.is_power_of_two(), "numeric alignment")?;
    Ok(value
        .checked_add(alignment - 1)
        .ok_or("alignment overflow")?
        & !(alignment - 1))
}

/// `len` bytes at `address`, which must lie in one initialized, file-backed,
/// read-only segment.
pub(crate) fn exact_ro(image: &ValidatedImage<'_>, address: u64, len: usize) -> Result<Vec<u8>> {
    let end = address
        .checked_add(u64::try_from(len)?)
        .ok_or("RO span overflow")?;
    for segment in image.segments() {
        let initialized = image
            .mapped_file_bytes(segment)
            .map_err(|e| format!("RO load: {e:?}"))?;
        let initialized_end = segment
            .memory
            .start
            .checked_add(u64::try_from(initialized.len())?)
            .ok_or("RO initialized end overflow")?;
        if segment.permissions.read
            && !segment.permissions.write
            && !segment.permissions.execute
            && segment.memory.start <= address
            && end <= initialized_end
        {
            let at = usize::try_from(address - segment.memory.start)?;
            return initialized
                .get(at..at.checked_add(len).ok_or("RO offset overflow")?)
                .map(<[u8]>::to_vec)
                .ok_or_else(|| "RO initialized bytes".into());
        }
    }
    Err("descriptor/reference must come from actual file-backed R-only segment".into())
}

/// `length` bytes at `address`, which must lie in one initialized read-execute
/// segment.
pub(crate) fn exact_rx<'a>(
    image: &ValidatedImage<'a>,
    address: u64,
    length: usize,
) -> Result<&'a [u8]> {
    let end = address
        .checked_add(length as u64)
        .ok_or("RX span overflow")?;
    for load in image.segments() {
        let initialized = image
            .mapped_file_bytes(load)
            .map_err(|e| format!("RX load: {e:?}"))?;
        if load.permissions.read
            && load.permissions.execute
            && !load.permissions.write
            && load.memory.start <= address
            && end
                <= load
                    .memory
                    .start
                    .checked_add(
                        load.file
                            .end
                            .checked_sub(load.file.start)
                            .ok_or("RX file size")?,
                    )
                    .ok_or("RX end overflow")?
        {
            let at = usize::try_from(address - load.memory.start)?;
            return initialized
                .get(at..at.checked_add(length).ok_or("RX offset overflow")?)
                .ok_or_else(|| "RX file bounds".into());
        }
    }
    Err("mapping-only observation outside initialized RX bytes".into())
}

fn new_unsealed_memfd(name: &std::ffi::CStr) -> io::Result<File> {
    // SAFETY: memfd_create takes a valid C string and returns a new descriptor
    // or -1; nothing else owns it.
    let raw =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is the new descriptor memfd_create returned.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw) }))
}

fn seals(file: &File) -> io::Result<i32> {
    // SAFETY: query only, on this retained owned descriptor.
    let value = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

fn offset(file: &File) -> io::Result<i64> {
    // SAFETY: SEEK_CUR with offset zero observes this same retained OFD.
    let value = unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_CUR) };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

/// Add the write, grow, shrink and seal seals to a memfd the caller owns and
/// has finished filling.
pub fn seal_memfd(file: &File) -> io::Result<()> {
    // SAFETY: adds immutable content/size/seal closure to a retained memfd no
    // guest or concurrent writer touches.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A new `MFD_CLOEXEC | MFD_ALLOW_SEALING` memfd holding `bytes`: a
/// positional write (the shared offset stays 0), then `set_len`, then the
/// seals of [`seal_memfd`] when `sealed`. No `sync_all`.
pub fn memfd_bytes(name: &std::ffi::CStr, bytes: &[u8], sealed: bool) -> io::Result<File> {
    let file = new_unsealed_memfd(name)?;
    file.write_all_at(bytes, 0)?;
    file.set_len(bytes.len() as u64)?;
    if sealed {
        seal_memfd(&file)?;
    }
    Ok(file)
}

/// One birth's three inherited descriptors, created before clone:
/// - the input packet lease, empty and unsealed, filled and sealed at the stop
///   after admission ([`BirthLeases::fill_packet`]);
/// - the runtime image, sealed;
/// - the handoff, empty and unsealed, filled and sealed at the stop.
///
/// The launch owner retains this value, and the descriptors it lends, through
/// terminal cleanup, with no close, dup2 or offset change in between.
pub struct BirthLeases {
    packet: File,
    runtime: File,
    handoff: File,
    attempted: AtomicBool,
    poisoned: AtomicBool,
    sealed: std::sync::OnceLock<Vec<u8>>,
}

/// The stop a packet is filled at: proves a descriptor is inherited by this
/// exact birth and returns that birth's pidfd.
pub trait BirthStop {
    /// The birth pidfd, refused unless `fd` is in the retained launch request.
    fn duplicate_birth_pidfd_for_inherited(&self, fd: BorrowedFd<'_>) -> Result<OwnedFd>;
}

impl BirthStop for super::InitialExecStop<'_> {
    fn duplicate_birth_pidfd_for_inherited(&self, fd: BorrowedFd<'_>) -> Result<OwnedFd> {
        super::InitialExecStop::duplicate_birth_pidfd_for_inherited(self, fd)
    }
}

/// The mapping prepared from a birth's stop, still held by its original owner:
/// for re-verifying the packet after mapping ([`BirthLeases::verify_at`]).
impl BirthStop for super::physical::PreparedMapping<'_> {
    fn duplicate_birth_pidfd_for_inherited(&self, fd: BorrowedFd<'_>) -> Result<OwnedFd> {
        super::physical::PreparedMapping::duplicate_birth_pidfd_for_inherited(self, fd)
    }
}

/// The admission a packet comes from, supplied by the embedder.
pub trait PacketAdmission {
    /// Refuse unless `birth` is the admission's watched peer.
    fn require_watched_peer(&self, birth: &OwnedFd) -> Result<()>;
    /// The admitted initial packet.
    fn initial_packet(&self) -> Result<Vec<u8>>;
    /// Record that the fill failed; the admission must not be reused.
    fn fail(&self, error: &dyn std::fmt::Display);
}

impl BirthLeases {
    /// Create the three descriptors for one birth of `image`.
    pub fn new(image: &AuditedRuntimeImage, names: MemfdNames) -> Result<Self> {
        let packet = new_unsealed_memfd(names.packet)?;
        let leases = Self {
            packet,
            runtime: memfd_bytes(names.runtime, image.bytes(), true)?,
            handoff: memfd_bytes(names.runtime, &[], false)?,
            attempted: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            sealed: std::sync::OnceLock::new(),
        };
        leases.packet_empty()?;
        require(
            leases.packet.as_raw_fd() > 2,
            "mapped packet descriptor must not be stdio",
        )?;
        Ok(leases)
    }

    /// The descriptors for the launch request's inherited list, in this order:
    /// packet, runtime, handoff.
    pub fn inherited(&self) -> [BorrowedFd<'_>; 3] {
        [
            self.packet.as_fd(),
            self.runtime.as_fd(),
            self.handoff.as_fd(),
        ]
    }

    /// The runtime image descriptor.
    pub fn runtime(&self) -> BorrowedFd<'_> {
        self.runtime.as_fd()
    }

    /// The handoff descriptor (filled at the stop).
    pub fn handoff(&self) -> &File {
        &self.handoff
    }

    /// The packet descriptor.
    pub fn packet(&self) -> BorrowedFd<'_> {
        self.packet.as_fd()
    }

    fn packet_empty(&self) -> Result<()> {
        require(
            self.packet.metadata()?.len() == 0
                && seals(&self.packet)? == 0
                && offset(&self.packet)? == 0,
            "mapped packet lease is not pristine empty unsealed OFD",
        )
    }

    fn verify_packet(&self, bytes: &[u8]) -> Result<()> {
        require(
            !bytes.is_empty() && bytes.len() <= MAX_PACKET_LEN,
            "mapped packet size outside scalar packet bound",
        )?;
        let sealed = |file: &File| -> Result<bool> {
            Ok(file.metadata()?.len() == bytes.len() as u64
                && seals(file)? == SEALS
                && offset(file)? == 0)
        };
        require(
            sealed(&self.packet)?,
            "mapped packet sealed length/seals/offset differ",
        )?;
        let mut actual = vec![0; bytes.len()];
        self.packet.read_exact_at(&mut actual, 0)?;
        require(actual == bytes, "mapped packet retained OFD bytes differ")?;
        let mut trailing = [0];
        require(
            self.packet.read_at(&mut trailing, bytes.len() as u64)? == 0,
            "mapped packet retained OFD has trailing bytes",
        )?;
        require(
            sealed(&self.packet)?,
            "mapped packet changed across positional verification",
        )
    }

    fn checked<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let result = (|| {
            require(
                !self.poisoned.load(Ordering::Acquire),
                "mapped packet lease is permanently poisoned",
            )?;
            let value = operation()?;
            require(
                !self.poisoned.load(Ordering::Acquire),
                "mapped packet lease is permanently poisoned",
            )?;
            Ok(value)
        })();
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    /// Fill the packet lease once, at `stop`, from `admission`, and seal it.
    /// The admission's watched-peer check brackets the fill, and the packet
    /// must not change while it is sealed. Any failure poisons this lease and
    /// fails the admission; the caller retains and cancels the stopped child.
    /// There is no retry or guest fallback. Returns the sealed bytes.
    pub fn fill_packet(
        &self,
        stop: &dyn BirthStop,
        admission: &dyn PacketAdmission,
    ) -> Result<Vec<u8>> {
        let result = self.checked(|| {
            if self.attempted.swap(true, Ordering::AcqRel) {
                return Err("mapped packet lease fill was already attempted".into());
            }
            self.packet_empty()?;
            let birth = stop.duplicate_birth_pidfd_for_inherited(self.packet.as_fd())?;
            admission.require_watched_peer(&birth)?;
            let bytes = admission.initial_packet()?;
            require(
                !bytes.is_empty() && bytes.len() <= MAX_PACKET_LEN,
                "mapped packet size outside scalar packet bound",
            )?;
            self.packet.write_all_at(&bytes, 0)?;
            self.packet.set_len(bytes.len() as u64)?;
            self.packet.sync_all()?;
            seal_memfd(&self.packet)?;
            self.verify_packet(&bytes)?;
            let after = stop.duplicate_birth_pidfd_for_inherited(self.packet.as_fd())?;
            admission.require_watched_peer(&after)?;
            require(
                admission.initial_packet()? == bytes,
                "actual admission packet changed during sealing",
            )?;
            self.sealed
                .set(bytes.clone())
                .map_err(|_| "mapped packet lease was already sealed")?;
            Ok(bytes)
        });
        if let Err(error) = &result {
            admission.fail(error);
        }
        result
    }
}

impl BirthLeases {
    /// Re-verify the sealed packet at `stop` (the initial stop, or the mapping
    /// prepared from it) against `admission`: the lease is not poisoned; `stop`
    /// is the birth that inherited this exact packet descriptor; that birth is
    /// the admission's watched peer; the retained descriptor holds exactly the
    /// sealed bytes; and the admission still yields those bytes. Any failure
    /// poisons this lease permanently and fails the admission. This grants no
    /// entry or readiness.
    pub fn verify_at(&self, stop: &dyn BirthStop, admission: &dyn PacketAdmission) -> Result<()> {
        let result = self.checked(|| {
            let bytes = self
                .sealed
                .get()
                .ok_or("mapped packet lease is not filled and sealed")?;
            let birth = stop.duplicate_birth_pidfd_for_inherited(self.packet.as_fd())?;
            admission.require_watched_peer(&birth)?;
            self.verify_packet(bytes)?;
            require(
                admission.initial_packet()? == *bytes,
                "mapped packet no longer matches actual admission",
            )
        });
        if let Err(error) = &result {
            admission.fail(error);
        }
        result
    }

    /// The packet sealed by [`fill_packet`](Self::fill_packet), re-verified
    /// against the retained descriptor.
    fn sealed_packet(&self) -> Result<&[u8]> {
        let bytes = self
            .sealed
            .get()
            .ok_or("mapped packet lease is not filled and sealed")?;
        self.checked(|| self.verify_packet(bytes))?;
        Ok(bytes)
    }
}

/// Which runtime entry a birth uses. Nothing else about the producer's work
/// differs between births.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BirthKind {
    /// The first image of a launch.
    Initial,
    /// An image after a watched exec.
    Successor,
}

/// What the launch route observed at the stop, for [`MappedBirthArming::arm`].
/// The pid and the 27 register words come from `captured`, the packet and its
/// descriptor from the producer's own leases, so none can be passed apart.
pub struct ArmingFacts<'a> {
    /// The birth, which selects the runtime entry.
    pub birth: BirthKind,
    /// The stop's captured original inputs (pid, registers, stack, aux).
    pub captured: &'a CapturedInitialInputs,
    /// The copied inputs `prepare_copied_inputs` produced for this image and
    /// its [`copied_input_request`](MappedBirthArming::copied_input_request).
    pub copied: &'a CopiedInitialData,
    /// The stopped task's signal mask.
    pub mask: u64,
    /// The stopped task's PKRU.
    pub pkru: u32,
    /// The signals the tool's subscriptions reserve: SIGSYS always, SIGSEGV
    /// when it intercepts instructions. Nothing else.
    pub reserved_signals: u64,
}

/// One armed birth: the preparation and entry the launch route uses, and
/// what a qualification claim needs.
pub struct Armed<'fd> {
    /// The preparation for `prepare_mapping`.
    pub preparation: Preparation<'fd>,
    /// The entry for the ToolInitialization observation.
    pub entry: RuntimeEntrySpec,
    /// The claim inputs, available only through
    /// [`ArmedClaim::after_prepare`] on the mapping made from `preparation`.
    /// The binding is never bound today: the digests are zero.
    pub claim: ArmedClaim<'fd>,
}

/// The producer side of a mapped birth, as the launch route calls it: the
/// inherited descriptors before clone; then at the stop, the image and request
/// for `prepare_copied_inputs`, the packet fill, and the arming.
pub trait MappedBirthArming {
    /// The descriptors for the launch request's inherited list: packet,
    /// runtime, handoff.
    fn inherited(&self) -> [BorrowedFd<'_>; 3];
    /// The runtime image, for `prepare_copied_inputs`.
    fn validated_image(&self) -> Result<ValidatedImage<'_>>;
    /// The copied-input request, for `prepare_copied_inputs`.
    fn copied_input_request(&self) -> Result<CopiedInputRequest>;
    /// Fill and seal the packet at the stop (see [`BirthLeases::fill_packet`]).
    fn fill_packet(&self, stop: &dyn BirthStop, admission: &dyn PacketAdmission)
    -> Result<Vec<u8>>;
    /// Build, write and seal the handoff, and return the preparation, the
    /// entry and the claim inputs. Once per birth. A qualification gap never
    /// refuses this; it is refused only by the claim, after preparation
    /// ([`ArmedClaim::after_prepare`], [`QualifiedMappedLaunch::claim`]).
    fn arm<'fd>(&'fd self, facts: &ArmingFacts<'_>) -> Result<Armed<'fd>>;
}

/// The producer's [`MappedBirthArming`]: one birth of an audited image.
pub struct MappedBirth<'img> {
    image: &'img AuditedRuntimeImage,
    leases: BirthLeases,
    handoff: std::sync::OnceLock<wire::Wire>,
}

impl<'img> MappedBirth<'img> {
    /// Create one birth's descriptors for `image`.
    pub fn new(image: &'img AuditedRuntimeImage, names: MemfdNames) -> Result<Self> {
        Ok(Self {
            image,
            leases: BirthLeases::new(image, names)?,
            handoff: std::sync::OnceLock::new(),
        })
    }

    /// The leases, for the route's checks of the retained descriptors.
    pub fn leases(&self) -> &BirthLeases {
        &self.leases
    }
}

const SIGSYS_BIT: u64 = 1 << (libc::SIGSYS - 1);
const SIGSEGV_BIT: u64 = 1 << (libc::SIGSEGV - 1);

impl MappedBirthArming for MappedBirth<'_> {
    fn inherited(&self) -> [BorrowedFd<'_>; 3] {
        self.leases.inherited()
    }

    fn validated_image(&self) -> Result<ValidatedImage<'_>> {
        self.image.validated_image()
    }

    fn copied_input_request(&self) -> Result<CopiedInputRequest> {
        self.image.copied_input_request()
    }

    fn fill_packet(
        &self,
        stop: &dyn BirthStop,
        admission: &dyn PacketAdmission,
    ) -> Result<Vec<u8>> {
        self.leases.fill_packet(stop, admission)
    }

    fn arm<'fd>(&'fd self, facts: &ArmingFacts<'_>) -> Result<Armed<'fd>> {
        require(
            self.handoff.get().is_none(),
            "exec_stop_producer_already_armed",
        )?;
        let entry = match facts.birth {
            BirthKind::Initial => self.image.facts.initial_entry,
            BirthKind::Successor => self.image.facts.successor_entry,
        }
        .ok_or("exec_stop_producer_no_entry_for_birth")?;
        require(
            facts.reserved_signals & SIGSYS_BIT != 0
                && facts.reserved_signals & !(SIGSYS_BIT | SIGSEGV_BIT) == 0,
            "exec_stop_producer_reserved_signals",
        )?;
        let packet = self.leases.sealed_packet()?;
        let validated = self.image.validated_image()?;
        let built = wire::build(
            self.image,
            &validated,
            facts.copied,
            packet,
            wire::WireContext {
                pid: facts.captured.pid().as_raw() as u64,
                registers: *facts.captured.registers(),
                mask: facts.mask,
                input_fd: self.leases.packet.as_raw_fd() as u64,
                pkru: facts.pkru,
            },
        )?;
        let handoff = &self.leases.handoff;
        require(
            handoff.metadata()?.len() == 0 && seals(handoff)? == 0,
            "exec_stop_producer_handoff_not_pristine",
        )?;
        handoff.write_all_at(&built.bytes, 0)?;
        handoff.set_len(built.bytes.len() as u64)?;
        handoff.sync_all()?;
        seal_memfd(handoff)?;
        require(
            seals(handoff)? == SEALS && handoff.metadata()?.len() == built.bytes.len() as u64,
            "exec_stop_producer_handoff_seal",
        )?;
        let view = handoff::View::parse(&built.bytes, built.address)
            .map_err(|e| format!("handoff parse: {e:?}"))?;
        let mut binding = [[0; 4]; 5];
        for (index, slot) in binding.iter_mut().enumerate() {
            *slot = view
                .binding(index)
                .map_err(|e| format!("handoff binding: {e:?}"))?;
        }
        // The expected digests come from the bytes this birth sealed and maps.
        let mapped = MappedLaunchFacts::of_mapped(
            sha2::Sha256::digest(self.image.bytes()).into(),
            self.image.layout_sha256,
        );
        let binding = HandoffBinding::of(&binding, &mapped);
        self.handoff
            .set(built)
            .map_err(|_| "exec_stop_producer_already_armed")?;
        let wire = self
            .handoff
            .get()
            .ok_or("exec_stop_producer_already_armed")?;
        let placement = Placement::fixed()?;
        let preparation = Preparation {
            runtime_fd: self.leases.runtime.as_fd(),
            runtime_bytes: self.image.bytes(),
            layout_address: self.image.facts.layout_address,
            handoff_fd: handoff.as_fd(),
            handoff_bytes: &wire.bytes,
            handoff_address: wire.address,
            input_fd: self.leases.packet.as_fd(),
            free_band: placement.free_band,
            filter_scratch: placement.filter_scratch,
        };
        let claim = ArmedClaim::new(binding, self.image.artifact_audit(), &preparation);
        Ok(Armed {
            preparation,
            entry: RuntimeEntrySpec {
                entry: entry.entry,
                terminal_trap: entry.terminal_trap,
                reserved_signals: facts.reserved_signals,
            },
            claim,
        })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Facts with every field empty, for struct-update syntax.
    fn bare_facts() -> RuntimeImageFacts {
        RuntimeImageFacts {
            image_sha256: [0; 32],
            layout_address: 0,
            reference_address: 0,
            sites: [[0; 4]; 4],
            ordinary_post_ips: Vec::new(),
            handler_address: 0,
            handler_bytes: 0,
            handler_sha256: [0; 32],
            dev_null_address: 0,
            initial_entry: None,
            successor_entry: None,
            data_ranges: Vec::new(),
        }
    }

    #[test]
    fn fixed_placement_matches_the_promoted_layout() {
        let placement = Placement::fixed().unwrap();
        let first = TOOL_REGION.start + 1024 * 1024;
        assert_eq!(placement.free_band.start, first);
        assert_eq!(placement.free_band.end, TOOL_REGION.start + 65535 * PAGE);
        let mut cursor = first;
        for (role, pages) in placement.roles.iter().zip([256_u64, 64, 256, 256, 256]) {
            assert_eq!(
                *role,
                Extent {
                    start: cursor,
                    end: cursor + pages * PAGE
                }
            );
            cursor = role.end;
        }
        assert_eq!(
            placement.filter_scratch,
            placement.roles[4].start + 8 * PAGE
        );
    }

    #[test]
    fn aligned_rounds_up_and_refuses_non_powers_of_two() {
        assert_eq!(aligned(0x1001, 0x1000).unwrap(), 0x2000);
        assert_eq!(aligned(0x2000, 0x1000).unwrap(), 0x2000);
        assert!(aligned(5, 3).is_err());
        assert!(aligned(u64::MAX, 2).is_err());
    }

    #[test]
    fn declared_sites_take_bootstrap_ips_and_ordinary_posts_minus_two() {
        let facts = RuntimeImageFacts {
            sites: [
                [10, 12, 158, 1],
                [14, 16, 218, 2],
                [18, 20, 7, 3],
                [22, 24, 2, 4],
            ],
            ordinary_post_ips: vec![102, 202],
            ..bare_facts()
        };
        assert_eq!(
            facts.declared_sites().unwrap(),
            vec![10, 14, 18, 22, 100, 200]
        );
        let underflow = RuntimeImageFacts {
            ordinary_post_ips: vec![1],
            ..facts
        };
        assert!(underflow.declared_sites().is_err());
    }

    fn facts_for(bytes: &[u8]) -> RuntimeImageFacts {
        RuntimeImageFacts {
            image_sha256: sha2::Sha256::digest(bytes).into(),
            ordinary_post_ips: vec![2],
            ..bare_facts()
        }
    }

    #[test]
    fn an_empty_or_garbage_image_is_refused() {
        assert!(AuditedRuntimeImage::new(Vec::new(), facts_for(&[])).is_err());
        let garbage = b"not an elf".to_vec();
        let error = AuditedRuntimeImage::new(garbage.clone(), facts_for(&garbage)).unwrap_err();
        assert!(error.to_string().starts_with("ELF"), "{error}");
    }

    #[test]
    fn facts_for_other_bytes_are_refused_before_any_audit() {
        let error = AuditedRuntimeImage::new(b"image".to_vec(), facts_for(b"other")).unwrap_err();
        assert!(error.to_string().contains("image_sha256"), "{error}");
    }

    const W: u64 = RUNTIME_WINDOW.start;
    const GATE: u64 = W + PAGE;
    const TEXT: u64 = W + 2 * PAGE;
    const REFERENCE: u64 = W + 3 * PAGE;
    const R: u32 = 4;
    const RX: u32 = 4 | 1;
    const RW: u32 = 4 | 2;

    /// A gate page: int3 fill with the native gate at 0x7c.
    /// A gate page: int3 fill with the template's three syscalls: the native
    /// gate at 0x7c (syscall at 0x80), a bare syscall at 0x200, and the
    /// restorer at 0x300 (syscall at 0x309).
    fn gate_page() -> Vec<u8> {
        let mut page = vec![0xcc; PAGE as usize];
        page[0x7c..0x7c + NATIVE_GATE_BYTES.len()].copy_from_slice(&NATIVE_GATE_BYTES);
        page[0x200..0x202].copy_from_slice(&[0x0f, 0x05]);
        page[0x300..0x30d].copy_from_slice(&RESTORER);
        page
    }

    /// `endbr64; mov eax, 15; syscall; ud2`.
    const RESTORER: [u8; 13] = [
        0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 15, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ];

    /// `syscall; nop; nop; syscall; jne rel32` whose rel32 bytes are `0f 05 00
    /// 00`, then zeros: decoded syscalls at TEXT and TEXT+4, and a `0f 05`
    /// pair at TEXT+8 inside the `jne`.
    fn text_page() -> Vec<u8> {
        let mut page = vec![0; PAGE as usize];
        page[..12].copy_from_slice(&[
            0x0f, 0x05, 0x90, 0x90, 0x0f, 0x05, 0x0f, 0x85, 0x0f, 0x05, 0x00, 0x00,
        ]);
        page
    }

    /// An ELF64 ET_EXEC image in the runtime window: header page (R), gate
    /// page (`gate_flags`, omitted when `None`), text page (RX) and reference
    /// page (R), each one page at file offset `(n + 1) * PAGE`.
    fn elf(gate_flags: Option<u32>, gate: &[u8], text: &[u8], reference: &[u8]) -> Vec<u8> {
        let mut phdrs = vec![(R, W, 1_u64)];
        if let Some(flags) = gate_flags {
            phdrs.push((flags, GATE, 2));
        }
        phdrs.push((RX, TEXT, 3));
        phdrs.push((R, REFERENCE, 4));
        let mut bytes = vec![0_u8; 5 * PAGE as usize];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little-endian
        bytes[6] = 1; // EV_CURRENT
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // EM_X86_64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&TEXT.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());
        for (i, &(flags, vaddr, page)) in phdrs.iter().enumerate() {
            let at = 64 + i * 56;
            bytes[at..at + 4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
            bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&(page * PAGE).to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&vaddr.to_le_bytes());
            bytes[at + 24..at + 32].copy_from_slice(&vaddr.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&PAGE.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&PAGE.to_le_bytes());
            bytes[at + 48..at + 56].copy_from_slice(&PAGE.to_le_bytes());
        }
        let page = |n: usize| n * PAGE as usize..(n + 1) * PAGE as usize;
        bytes[page(2)].copy_from_slice(gate);
        bytes[page(3)].copy_from_slice(text);
        bytes[page(4)].copy_from_slice(reference);
        bytes
    }

    fn audit(bytes: &[u8], declared: &[u64]) -> Result<SyscallCensus> {
        audit_with_data(bytes, declared, &[])
    }

    fn audit_with_data(
        bytes: &[u8],
        declared: &[u64],
        data: &[Range<u64>],
    ) -> Result<SyscallCensus> {
        let image = validate(bytes)?;
        let island = constructor_island(&image, bytes)?;
        instruction_audit(
            &executable_runs(&image)?,
            &NATIVE_GATE,
            declared,
            island,
            data,
        )
    }

    /// `bytes` with a `.symtab` holding one FUNC symbol `name` at `value`.
    fn with_symbol(bytes: Vec<u8>, name: &[u8], value: u64, size: u64) -> Vec<u8> {
        with_symbols(bytes, name, &[(value, size)])
    }

    /// `bytes` with a `.symtab` holding a FUNC symbol `name` per `(value, size)`.
    fn with_symbols(mut bytes: Vec<u8>, name: &[u8], symbols: &[(u64, u64)]) -> Vec<u8> {
        let mut strtab = vec![0];
        strtab.extend_from_slice(name);
        strtab.push(0);
        let strtab_at = bytes.len();
        bytes.extend_from_slice(&strtab);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
        let symtab_at = bytes.len();
        bytes.extend_from_slice(&[0; 24]);
        for &(value, size) in symbols {
            let mut symbol = [0_u8; 24];
            symbol[..4].copy_from_slice(&1_u32.to_le_bytes());
            symbol[4] = 2; // STT_FUNC
            symbol[8..16].copy_from_slice(&value.to_le_bytes());
            symbol[16..24].copy_from_slice(&size.to_le_bytes());
            bytes.extend_from_slice(&symbol);
        }
        let symtab_bytes = 24 * (symbols.len() + 1);
        let shoff = bytes.len();
        let section = |kind: u32, offset: usize, size: usize, link: u32, entsize: u64| {
            let mut header = [0_u8; 64];
            header[4..8].copy_from_slice(&kind.to_le_bytes());
            header[0x18..0x20].copy_from_slice(&(offset as u64).to_le_bytes());
            header[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
            header[0x28..0x2c].copy_from_slice(&link.to_le_bytes());
            header[0x38..0x40].copy_from_slice(&entsize.to_le_bytes());
            header
        };
        bytes.extend_from_slice(&[0; 64]);
        bytes.extend_from_slice(&section(2, symtab_at, symtab_bytes, 2, 24));
        bytes.extend_from_slice(&section(3, strtab_at, strtab.len(), 0, 0));
        bytes[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        bytes[0x3a..0x3c].copy_from_slice(&64_u16.to_le_bytes());
        bytes[0x3c..0x3e].copy_from_slice(&3_u16.to_le_bytes());
        bytes
    }

    /// The constructor symbol's address in the island tests.
    const CONSTRUCTOR: u64 = TEXT + 0x100;

    /// A text page with the two declared syscalls, nops up to `lead` (the
    /// address of an `endbr64; ud2` followed by the message, or none), then
    /// int3; plus extra `(address, bytes)` patches.
    fn island_text(lead: Option<u64>, patches: &[(u64, &[u8])]) -> Vec<u8> {
        let mut text = text_page();
        let offset = |address: u64| (address - TEXT) as usize;
        let fill_end = lead.map_or(12, offset);
        text[12..fill_end].fill(0x90);
        text[fill_end..].fill(0xcc);
        if let Some(lead) = lead {
            let at = offset(lead);
            text[at..at + 6].copy_from_slice(&CONSTRUCTOR_LEAD);
            text[at + 6..at + 6 + CONSTRUCTOR_MESSAGE.len()].copy_from_slice(CONSTRUCTOR_MESSAGE);
        }
        for &(address, bytes) in patches {
            let at = offset(address);
            text[at..at + bytes.len()].copy_from_slice(bytes);
        }
        text
    }

    fn island_image(text: &[u8]) -> Vec<u8> {
        with_symbol(
            elf(Some(RX), &gate_page(), text, &gate_page()),
            CONSTRUCTOR_SYMBOL,
            CONSTRUCTOR,
            CONSTRUCTOR_BYTES,
        )
    }

    fn gate_check(bytes: &[u8]) -> Result<()> {
        check_native_gate(&validate(bytes)?, REFERENCE)
    }

    #[test]
    fn the_sweep_counts_gate_and_declared_syscalls_and_covers_every_executable_byte() {
        let bytes = elf(Some(RX), &gate_page(), &text_page(), &gate_page());
        let census = audit(&bytes, &[TEXT, TEXT + 4]).unwrap();
        assert_eq!(census.executable_bytes, 2 * PAGE);
        assert_eq!(census.in_gate, 3);
        assert_eq!(census.at_declared_sites, 2);
        // The `0f 05` inside the `jne` is no instruction, so it is neither
        // counted nor refused. The gate and text pages abut and decode as one
        // run: the int3 fill, the gate, and the text instructions.
        assert_eq!(
            census.instructions,
            // gate page: int3 fill, the native gate (3), the bare syscall (1),
            // the restorer (4); text page: 5 instructions, then zero pairs.
            (PAGE - 9 - 2 - 13) + 3 + 1 + 4 + 5 + (PAGE - 12) / 2
        );
    }

    #[test]
    fn a_declared_list_that_omits_a_real_syscall_is_refused() {
        let bytes = elf(Some(RX), &gate_page(), &text_page(), &gate_page());
        let error = audit(&bytes, &[TEXT]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("instruction audit: undeclared syscall at {:#x}", TEXT + 4)
        );
        let error = audit(&bytes, &[]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("instruction audit: undeclared syscall at {TEXT:#x}")
        );
    }

    #[test]
    fn a_declared_site_that_is_not_a_decoded_syscall_is_refused() {
        let bytes = elf(Some(RX), &gate_page(), &text_page(), &gate_page());
        // TEXT+8 holds `0f 05`, but inside the `jne`.
        let error = audit(&bytes, &[TEXT, TEXT + 4, TEXT + 8]).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "instruction audit: declared site {:#x} is not a decoded syscall",
                TEXT + 8
            )
        );
    }

    #[test]
    fn an_undecodable_or_truncated_instruction_is_refused_without_resync() {
        // 0x06 (push es) is invalid in 64-bit mode.
        let mut text = text_page();
        text[2] = 0x06;
        let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
        let error = audit(&bytes, &[TEXT, TEXT + 4]).unwrap_err();
        assert!(
            error.to_string().starts_with(&format!(
                "instruction audit: undecodable bytes at {:#x}",
                TEXT + 2
            )),
            "{error}"
        );
        // A two-byte opcode cut off by the end of the executable pages.
        let mut text = text_page();
        *text.last_mut().unwrap() = 0x0f;
        // Keep the zero run before it even, so the sweep reaches the last byte
        // on an instruction boundary.
        text[PAGE as usize - 2] = 0x90;
        let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
        let error = audit(&bytes, &[TEXT, TEXT + 4]).unwrap_err();
        assert!(
            error.to_string().starts_with(&format!(
                "instruction audit: undecodable bytes at {:#x}",
                TEXT + PAGE - 1
            )),
            "{error}"
        );
    }

    /// The test text page with `bytes` at `TEXT + at`, in its zero run.
    fn text_with(at: u64, bytes: &[u8]) -> Vec<u8> {
        let mut text = text_page();
        text[at as usize..at as usize + bytes.len()].copy_from_slice(bytes);
        elf(Some(RX), &gate_page(), &text, &gate_page())
    }

    /// Declared data ranges are refused on x86-64 before the sweep. The three
    /// constructions are each a system call the CPU reaches by falling through
    /// from the `add [rax], al` pair at +0x3e into the range: refused as such
    /// with no range, and refused by name, never passed, with the range that
    /// would hide it. A range over harmless bytes is refused the same way.
    #[test]
    #[allow(
        clippy::single_range_in_vec_init,
        reason = "a list holding one declared data range"
    )]
    fn declared_data_ranges_are_refused_on_x86_64() {
        let declared = [TEXT, TEXT + 4];
        let by_name = "instruction audit: declared data ranges are not admitted on x86-64";
        for (bytes, range, without) in [
            (
                [0x90, 0x90, 0x90, 0x0f, 0x05, 0, 0, 0, 0, 0x90],
                TEXT + 0x40..TEXT + 0x44,
                format!(
                    "instruction audit: undeclared syscall at {:#x}",
                    TEXT + 0x43
                ),
            ),
            (
                [0xb8, 0x00, 0x48, 0xb8, 0, 0, 0, 0x0f, 0x05, 0x90],
                TEXT + 0x40..TEXT + 0x42,
                format!(
                    "instruction audit: undeclared syscall at {:#x}",
                    TEXT + 0x47
                ),
            ),
            (
                [0x90, 0x90, 0x90, 0xcd, 0x80, 0, 0, 0, 0, 0x90],
                TEXT + 0x40..TEXT + 0x44,
                format!("instruction audit: int 0x80 at {:#x}", TEXT + 0x43),
            ),
        ] {
            let image = text_with(0x40, &bytes);
            assert_eq!(audit(&image, &declared).unwrap_err().to_string(), without);
            assert_eq!(
                audit_with_data(&image, &declared, std::slice::from_ref(&range))
                    .unwrap_err()
                    .to_string(),
                by_name
            );
        }
        let plain = elf(Some(RX), &gate_page(), &text_page(), &gate_page());
        audit(&plain, &declared).unwrap();
        assert_eq!(
            audit_with_data(&plain, &declared, &[TEXT + 0x40..TEXT + 0x48])
                .unwrap_err()
                .to_string(),
            by_name
        );
    }

    #[test]
    fn only_the_pinned_constructor_message_is_stepped_over() {
        let pinned = CONSTRUCTOR + CONSTRUCTOR_LEAD_OFFSET;
        let message = CONSTRUCTOR + CONSTRUCTOR_MESSAGE_OFFSET;
        let declared = [TEXT, TEXT + 4];
        let census = audit(&island_image(&island_text(Some(pinned), &[])), &declared).unwrap();
        assert_eq!(census.data_island_bytes, CONSTRUCTOR_MESSAGE.len() as u64);
        assert_eq!(census.executable_bytes, 2 * PAGE);

        // The same lead and 37 bytes anywhere else: refused, alone or as a
        // second occurrence.
        let elsewhere = TEXT + 0x500;
        let copy: Vec<u8> = CONSTRUCTOR_LEAD
            .iter()
            .chain(CONSTRUCTOR_MESSAGE)
            .copied()
            .collect();
        let not_pinned = format!(
            "instruction audit: constructor message at {:#x} is not the pinned island",
            elsewhere + 6
        );
        let alone = elf(
            Some(RX),
            &gate_page(),
            &island_text(None, &[(elsewhere, &copy)]),
            &gate_page(),
        );
        assert_eq!(
            audit(&alone, &declared).unwrap_err().to_string(),
            not_pinned
        );
        let second = island_image(&island_text(Some(pinned), &[(elsewhere, &copy)]));
        assert_eq!(
            audit(&second, &declared).unwrap_err().to_string(),
            not_pinned
        );
        // Without the symbol there is no pinned island at all: no exemption,
        // not a refusal, and the message is swept as code.
        let unpinned = elf(
            Some(RX),
            &gate_page(),
            &island_text(Some(pinned), &[]),
            &gate_page(),
        );
        assert_eq!(
            constructor_island(&validate(&unpinned).unwrap(), &unpinned).unwrap(),
            None
        );
        assert_eq!(
            audit(&unpinned, &declared).unwrap_err().to_string(),
            format!(
                "instruction audit: constructor message at {message:#x} is not the pinned island"
            )
        );

        // The island with any one byte changed: refused.
        for index in 0..CONSTRUCTOR_MESSAGE.len() as u64 {
            let changed = island_image(&island_text(Some(pinned), &[(message + index, b"#")]));
            assert_eq!(
                audit(&changed, &declared).unwrap_err().to_string(),
                "instruction audit: constructor message island differs",
                "byte {index}"
            );
        }

        // The symbol's pinned lead is not endbr64; ud2 (here nops), or the
        // lead's first byte alone differs: the layout drifted, refused by
        // name rather than turning the exemption off.
        let lead_mismatch =
            "reverie_inguest_constructor_entry drifted: the bytes at +0x2bd are not endbr64; ud2";
        for lead in [&[0x90_u8; 6][..], &[0xf2][..]] {
            let no_lead = island_image(&island_text(Some(pinned), &[(pinned, lead)]));
            let image = validate(&no_lead).unwrap();
            assert_eq!(
                constructor_island(&image, &no_lead)
                    .unwrap_err()
                    .to_string(),
                lead_mismatch
            );
            assert_eq!(
                audit(&no_lead, &declared).unwrap_err().to_string(),
                lead_mismatch
            );
        }
        // The symbol placed so that +0x2bd is outside every executable
        // segment: refused by name.
        let outside = with_symbol(
            elf(
                Some(RX),
                &gate_page(),
                &island_text(Some(pinned), &[]),
                &gate_page(),
            ),
            CONSTRUCTOR_SYMBOL,
            0x10,
            CONSTRUCTOR_BYTES,
        );
        assert_eq!(
            audit(&outside, &declared).unwrap_err().to_string(),
            "reverie_inguest_constructor_entry drifted: +0x2bd is not executable"
        );
        // With the pin derived (the lead bytes are intact at +0x2bd), a sweep
        // that reaches the island other than straight after the lead is
        // refused by name: here a 10-byte `movabs rax, imm64` starting two
        // bytes before the lead swallows it and runs into the message.
        let swallowed = island_image(&island_text(Some(pinned), &[(pinned - 2, &[0x48, 0xb8])]));
        let image = validate(&swallowed).unwrap();
        assert_eq!(
            constructor_island(&image, &swallowed).unwrap(),
            Some(message)
        );
        assert_eq!(
            audit(&swallowed, &declared).unwrap_err().to_string(),
            format!(
                "instruction audit: constructor message island at {message:#x} is not preceded by endbr64; ud2"
            )
        );
        // The pin needs the exact size and exactly one symbol: any other size
        // is a drift, refused by name.
        for size in [CONSTRUCTOR_BYTES - 1, CONSTRUCTOR_BYTES + 1] {
            let resized = with_symbol(
                elf(
                    Some(RX),
                    &gate_page(),
                    &island_text(Some(pinned), &[]),
                    &gate_page(),
                ),
                CONSTRUCTOR_SYMBOL,
                CONSTRUCTOR,
                size,
            );
            let image = validate(&resized).unwrap();
            assert_eq!(
                constructor_island(&image, &resized)
                    .unwrap_err()
                    .to_string(),
                format!("reverie_inguest_constructor_entry drifted: size {size} != 744"),
            );
            assert_eq!(
                audit(&resized, &declared).unwrap_err().to_string(),
                format!("reverie_inguest_constructor_entry drifted: size {size} != 744"),
                "size {size}"
            );
        }
        let twice = with_symbols(
            elf(
                Some(RX),
                &gate_page(),
                &island_text(Some(pinned), &[]),
                &gate_page(),
            ),
            CONSTRUCTOR_SYMBOL,
            &[
                (CONSTRUCTOR, CONSTRUCTOR_BYTES),
                (CONSTRUCTOR + 0x400, CONSTRUCTOR_BYTES),
            ],
        );
        assert_eq!(
            audit(&twice, &declared).unwrap_err().to_string(),
            "more than one reverie_inguest_constructor_entry symbol"
        );
    }

    #[test]
    fn a_malformed_section_table_is_refused_without_panicking() {
        let mut bytes = island_image(&island_text(None, &[]));
        bytes[0x28..0x30].copy_from_slice(&(u64::MAX - 3).to_le_bytes());
        assert!(symbols_named(&bytes, CONSTRUCTOR_SYMBOL).is_err());
        assert!(audit(&bytes, &[TEXT, TEXT + 4]).is_err());
        let mut link = island_image(&island_text(None, &[]));
        // Point the symbol table's string-table link past the section count.
        let shoff = u64::from_le_bytes(link[0x28..0x30].try_into().unwrap()) as usize;
        link[shoff + 64 + 0x28..shoff + 64 + 0x2c].copy_from_slice(&7_u32.to_le_bytes());
        assert_eq!(
            symbols_named(&link, CONSTRUCTOR_SYMBOL)
                .unwrap_err()
                .to_string(),
            "ELF symbol string table index"
        );
    }

    #[test]
    fn only_the_template_gate_syscalls_and_bare_declared_syscalls_are_admitted() {
        let declared = [TEXT, TEXT + 4];
        // An extra syscall in the gate page, mirrored in the reference page.
        let mut extra = gate_page();
        extra[0x400..0x402].copy_from_slice(&[0x0f, 0x05]);
        let bytes = elf(Some(RX), &extra, &text_page(), &extra);
        gate_check(&bytes).unwrap();
        assert_eq!(
            audit(&bytes, &declared).unwrap_err().to_string(),
            format!(
                "instruction audit: gate-page syscall at {:#x} is not a template site",
                GATE + 0x400
            )
        );
        // A template syscall missing.
        let mut missing = gate_page();
        missing[0x200..0x202].copy_from_slice(&[0xcc, 0xcc]);
        let bytes = elf(Some(RX), &missing, &text_page(), &missing);
        assert_eq!(
            audit(&bytes, &declared).unwrap_err().to_string(),
            "instruction audit: the gate page lacks one of its template syscalls"
        );
        // `66 0f 05` at a declared site.
        let mut text = text_page();
        text[..12].copy_from_slice(&[
            0x66, 0x0f, 0x05, 0x90, 0x0f, 0x05, 0x0f, 0x85, 0x0f, 0x05, 0x00, 0x00,
        ]);
        let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
        assert_eq!(
            audit(&bytes, &declared).unwrap_err().to_string(),
            format!("instruction audit: syscall at {TEXT:#x} is not the bare 0f 05")
        );
    }

    #[test]
    fn int_0x80_and_sysenter_are_refused() {
        let declared = [TEXT, TEXT + 4];
        for (patch, name) in [
            (&[0xcd_u8, 0x80][..], "int 0x80"),
            (&[0x0f, 0x34][..], "sysenter"),
        ] {
            let mut text = text_page();
            // Two nops at TEXT+2..4 become the refused instruction.
            text[2..4].copy_from_slice(patch);
            let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
            assert_eq!(
                audit(&bytes, &declared).unwrap_err().to_string(),
                format!("instruction audit: {name} at {:#x}", TEXT + 2)
            );
        }
        // `int 0x81` is an ordinary instruction here.
        let mut text = text_page();
        text[2..4].copy_from_slice(&[0xcd, 0x81]);
        let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
        audit(&bytes, &declared).unwrap();
    }

    #[test]
    fn a_vendor_dependent_decoding_is_refused() {
        // Intel: a 7-byte `66 je rel32` and a nop. AMD: a 5-byte `je rel16`,
        // then a syscall at +5, then a nop.
        let mut text = text_page();
        text[12..20].copy_from_slice(&[0x66, 0x0f, 0x84, 0x00, 0x00, 0x0f, 0x05, 0x90]);
        let bytes = elf(Some(RX), &gate_page(), &text, &gate_page());
        assert_eq!(
            audit(&bytes, &[TEXT, TEXT + 4]).unwrap_err().to_string(),
            format!(
                "instruction audit: Intel and AMD decodings differ at {:#x}",
                TEXT + 12
            )
        );
    }

    #[test]
    fn an_instruction_crossing_into_the_next_executable_segment_is_refused() {
        // The gate and text segments abut; a `movabs` at the gate page's last
        // two bytes runs eight bytes into the text page.
        let mut gate = gate_page();
        gate[PAGE as usize - 2..].copy_from_slice(&[0x48, 0xb8]);
        let bytes = elf(Some(RX), &gate, &text_page(), &gate);
        assert_eq!(
            audit(&bytes, &[TEXT, TEXT + 4]).unwrap_err().to_string(),
            format!(
                "instruction audit: instruction at {:#x} crosses the executable segment boundary at {TEXT:#x}",
                TEXT - 2
            )
        );
    }

    #[test]
    fn the_gate_page_must_be_executable_exact_and_equal_to_its_reference() {
        let good = elf(Some(RX), &gate_page(), &text_page(), &gate_page());
        gate_check(&good).unwrap();
        for flags in [None, Some(R), Some(RW)] {
            let bytes = elf(flags, &gate_page(), &text_page(), &gate_page());
            assert_eq!(
                gate_check(&bytes).unwrap_err().to_string(),
                "native gate page is missing or not executable"
            );
        }
        // A different gate encoding, mirrored in the reference page.
        let mut wrong = gate_page();
        wrong[0x84] = 0xe3; // jmp rbx
        let bytes = elf(Some(RX), &wrong, &text_page(), &wrong);
        assert_eq!(
            gate_check(&bytes).unwrap_err().to_string(),
            "native gate encoding differs"
        );
        // The right encoding, but another byte differs from the reference.
        let mut other = gate_page();
        other[0x200] = 0x90;
        let bytes = elf(Some(RX), &other, &text_page(), &gate_page());
        assert_eq!(
            gate_check(&bytes).unwrap_err().to_string(),
            "native gate page differs from its read-only reference page"
        );
    }

    /// The real staged private runtime image this audit was measured on,
    /// pinned by its SHA-256. It comes from a private build pair of
    /// 2026-11-03, not from any current release image; a current build must
    /// repeat this measurement. The 39 MB image is not in the repository, so
    /// this is ignored by default and run with `--ignored`, and then it FAILS
    /// unless `REVERIE_PRIVATE_RUNTIME_IMAGE` names the image and
    /// `REVERIE_PRIVATE_RUNTIME_FACTS` its package descriptor. The JSON fields
    /// read: `image.sha256`, `entry`, `terminal_int3`, and
    /// `observed.{layout_address, reference_address, sites, ordinary_post_ips,
    /// handler_address, handler_bytes, handler_sha256, dev_null_address}`, plus
    /// the optional `observed.data_ranges` (absent and `[]` both mean none).
    #[test]
    #[ignore = "needs REVERIE_PRIVATE_RUNTIME_IMAGE and REVERIE_PRIVATE_RUNTIME_FACTS"]
    fn the_measured_staged_image_passes_the_audit_with_its_recorded_counts() {
        const PINNED: &str = "2cf437588ab89fb97ca5a271374739c0e59d9ab4223f95a8d83b7a0e41f31268";
        let image = std::env::var_os("REVERIE_PRIVATE_RUNTIME_IMAGE")
            .expect("REVERIE_PRIVATE_RUNTIME_IMAGE must name the staged image");
        let facts = std::env::var_os("REVERIE_PRIVATE_RUNTIME_FACTS")
            .expect("REVERIE_PRIVATE_RUNTIME_FACTS must name its package descriptor");
        let bytes = std::fs::read(image).unwrap();
        let data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(facts).unwrap()).unwrap();
        assert_eq!(data["image"]["sha256"], PINNED);
        let hex = data["image"]["sha256"].as_str().unwrap();
        let mut image_sha256 = [0; 32];
        for (i, byte) in image_sha256.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        let observed = &data["observed"];
        let number = |value: &serde_json::Value| value.as_u64().unwrap();
        let mut sites = [[0; 4]; 4];
        for (row, value) in sites.iter_mut().zip(observed["sites"].as_array().unwrap()) {
            for (cell, value) in row.iter_mut().zip(value.as_array().unwrap()) {
                *cell = number(value);
            }
        }
        let digest = |value: &serde_json::Value| -> [u8; 32] {
            let hex = value.as_str().unwrap();
            std::array::from_fn(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        };
        let facts = RuntimeImageFacts {
            image_sha256,
            layout_address: number(&observed["layout_address"]),
            reference_address: number(&observed["reference_address"]),
            sites,
            ordinary_post_ips: observed["ordinary_post_ips"]
                .as_array()
                .unwrap()
                .iter()
                .map(number)
                .collect(),
            handler_address: number(&observed["handler_address"]),
            handler_bytes: number(&observed["handler_bytes"]),
            handler_sha256: digest(&observed["handler_sha256"]),
            dev_null_address: number(&observed["dev_null_address"]),
            initial_entry: Some(EntryPoint {
                entry: number(&data["entry"]),
                terminal_trap: number(&data["terminal_int3"]),
            }),
            successor_entry: None,
            data_ranges: data_ranges(observed),
        };
        // `observed.data_ranges` is optional: absent and empty both declare
        // no data, and this package declares none.
        let mut without = observed.clone();
        without.as_object_mut().unwrap().remove("data_ranges");
        let mut empty = observed.clone();
        empty["data_ranges"] = serde_json::json!([]);
        assert_eq!(data_ranges(&without), Vec::new());
        assert_eq!(data_ranges(&empty), Vec::new());
        assert_eq!(facts.data_ranges, Vec::new());
        let image = AuditedRuntimeImage::new(bytes, facts).unwrap();
        let census = image.census();
        eprintln!("{census:?}");
        assert_eq!(census.at_declared_sites, 229);
        assert_eq!(census.data_island_bytes, CONSTRUCTOR_MESSAGE.len() as u64);
        // The gate template's syscalls: the native gate (+0x80), the PKRU
        // gate body (+0x200) and the rt_sigreturn restorer (+0x309).
        assert_eq!(census.in_gate, 3);
        assert_eq!(census.instructions, 2_614_665);
        assert_eq!(census.executable_bytes, 0xac0000);
        image.validated_image().unwrap();
        image.copied_input_request().unwrap();
        let filter = image.filter_coverage();
        eprintln!("{filter:?}");
        let gate = NATIVE_GATE.start;
        let sigreturn = libc::SYS_rt_sigreturn as u32;
        assert_eq!(
            filter.allowed.iter().map(|(ip, _)| *ip).collect::<Vec<_>>(),
            vec![
                gate + 0x80,
                gate + 0x82,
                gate + 0x200,
                gate + 0x202,
                gate + 0x30b
            ]
        );
        assert_eq!(filter.allowed[4].1, AllowedNumbers::Only(vec![sigreturn]));
        assert_eq!(filter.encodings, 300);
        assert_eq!(filter.trapped_encodings, 297);
        assert_eq!(filter.trapped_declared_sites, 229);
        assert_eq!(
            arm_prepare_and_cancel(&image).refusal(),
            Some((0, HANDOFF_BINDING_UNBOUND))
        );
    }
    /// `observed.data_ranges` of a package descriptor, `[[start, end], ...]`;
    /// none when the key is absent.
    fn data_ranges(observed: &serde_json::Value) -> Vec<Range<u64>> {
        observed
            .get("data_ranges")
            .map(|ranges| {
                ranges
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pair| {
                        let pair = pair.as_array().unwrap();
                        assert_eq!(pair.len(), 2);
                        pair[0].as_u64().unwrap()..pair[1].as_u64().unwrap()
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A small image that passes every qualification check: header page
    /// (HLMLAY01 at +512, `/dev/null` at +1024), gate page, text page (four
    /// bootstrap sites, one more ordinary site, entry, terminal int3, handler),
    /// data page with TLS, and the reference page.
    pub(crate) fn qualifying_image() -> (Vec<u8>, RuntimeImageFacts) {
        let base = RUNTIME_WINDOW.start;
        let text = base + 2 * PAGE;
        let mut gate = vec![0xcc_u8; PAGE as usize];
        gate[0x7c..0x85].copy_from_slice(&NATIVE_GATE_BYTES);
        gate[0x200..0x202].copy_from_slice(&[0x0f, 0x05]);
        gate[0x300..0x30d].copy_from_slice(&[
            0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 15, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
        ]);
        let mut code = vec![0xcc_u8; PAGE as usize];
        for at in [0x00, 0x10, 0x20, 0x30, 0x40] {
            code[at..at + 2].copy_from_slice(&[0x0f, 0x05]);
        }
        code[0x100..0x104].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);
        code[0x200..0x20f].fill(0x90);
        code[0x20f] = 0xc3;
        let mut bytes = vec![0_u8; 5 * PAGE as usize];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[24..32].copy_from_slice(&(text + 0x100).to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&7_u16.to_le_bytes());
        for (i, (kind, flags, offset, address, file, memory, align)) in [
            (1_u32, 4_u32, 0_u64, base, PAGE, PAGE, PAGE),
            (1, 5, PAGE, base + PAGE, 2 * PAGE, 2 * PAGE, PAGE),
            (1, 6, 3 * PAGE, base + 3 * PAGE, 512, PAGE, PAGE),
            (7, 4, 3 * PAGE, base + 3 * PAGE, 16, 80, 8),
            (0x6474_e551, 6, 0, 0, 0, 8 * 1024 * 1024, 0),
            (6, 4, 64, base + 64, 392, 392, 8),
            (1, 4, 4 * PAGE, base + 4 * PAGE, PAGE, PAGE, PAGE),
        ]
        .into_iter()
        .enumerate()
        {
            let at = 64 + i * 56;
            bytes[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            for (relative, value) in [
                (8, offset),
                (16, address),
                (32, file),
                (40, memory),
                (48, align),
            ] {
                bytes[at + relative..at + relative + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        for (i, word) in [
            u64::from_le_bytes(*b"HLMLAY01"),
            1,
            96,
            handoff::VERSION,
            handoff::HEADER_BYTES as u64,
            handoff::MAX_BYTES as u64,
            64,
            16,
            128,
            8,
            base + PAGE,
            base + PAGE + 0x7c,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[512 + i * 8..520 + i * 8].copy_from_slice(&word.to_le_bytes());
        }
        bytes[1024..1034].copy_from_slice(b"/dev/null\0");
        let page = |n: u64| (n * PAGE) as usize..((n + 1) * PAGE) as usize;
        bytes[page(1)].copy_from_slice(&gate);
        bytes[page(2)].copy_from_slice(&code);
        bytes[page(4)].copy_from_slice(&gate);
        let facts = RuntimeImageFacts {
            image_sha256: sha2::Sha256::digest(&bytes).into(),
            layout_address: base + 512,
            reference_address: base + 4 * PAGE,
            sites: [
                [text, text + 2, 158, 1],
                [text + 0x10, text + 0x12, 218, 2],
                [text + 0x20, text + 0x22, 7, 3],
                [text + 0x30, text + 0x32, 2, 4],
            ],
            ordinary_post_ips: vec![text + 2, text + 0x12, text + 0x22, text + 0x32, text + 0x42],
            handler_address: text + 0x200,
            handler_bytes: 16,
            handler_sha256: sha2::Sha256::digest(&code[0x200..0x210]).into(),
            dev_null_address: base + 1024,
            initial_entry: Some(EntryPoint {
                entry: text + 0x100,
                terminal_trap: text + 0x104,
            }),
            successor_entry: None,
            data_ranges: Vec::new(),
        };
        (bytes, facts)
    }

    #[test]
    #[allow(
        clippy::single_range_in_vec_init,
        reason = "a list holding one declared data range"
    )]
    fn declared_data_ranges_in_the_facts_are_refused_on_x86_64() {
        let (bytes, facts) = qualifying_image();
        let text = RUNTIME_WINDOW.start + 2 * PAGE;
        AuditedRuntimeImage::new(bytes.clone(), facts.clone()).unwrap();
        // Eight int3 bytes: harmless, and still refused.
        let mut ranged = facts;
        ranged.data_ranges = vec![text + 0x300..text + 0x308];
        assert_eq!(
            AuditedRuntimeImage::new(bytes, ranged)
                .unwrap_err()
                .to_string(),
            "instruction audit: declared data ranges are not admitted on x86-64"
        );
    }

    #[test]
    fn the_qualifying_image_passes_the_audit_with_its_counts() {
        let (bytes, facts) = qualifying_image();
        let image = AuditedRuntimeImage::new(bytes, facts).unwrap();
        assert_eq!(image.census().in_gate, 3);
        assert_eq!(image.census().at_declared_sites, 5);
        let filter = image.filter_coverage();
        assert_eq!(filter.allowed.len(), 5);
        assert_eq!(filter.encodings, 8);
        assert_eq!(filter.trapped_encodings, 5);
        assert_eq!(filter.trapped_declared_sites, 5);
        assert!(image.artifact_audit().counts().is_some());
    }

    #[test]
    fn each_fact_check_refuses_by_name() {
        let (bytes, facts) = qualifying_image();
        let refuse = |facts: RuntimeImageFacts| {
            AuditedRuntimeImage::new(bytes.clone(), facts)
                .unwrap_err()
                .to_string()
        };
        let mut wrong_handler = facts.clone();
        wrong_handler.handler_sha256[0] ^= 1;
        assert_eq!(refuse(wrong_handler), "actual handler bytes");
        let mut no_dev_null = facts.clone();
        no_dev_null.dev_null_address += 1;
        assert_eq!(refuse(no_dev_null), "actual ELF dev-null literal");
        let mut wrong_role = facts.clone();
        wrong_role.sites[0][2] = 159;
        assert_eq!(refuse(wrong_role), "measured operation/number");
        let mut twice = facts.clone();
        twice.sites[1] = [twice.sites[0][0], twice.sites[0][1], 158, 1];
        assert_eq!(refuse(twice), "duplicate measured role");
        let mut no_entry = facts.clone();
        no_entry.initial_entry = None;
        assert_eq!(refuse(no_entry), "no runtime entry");
        let mut not_int3 = facts.clone();
        not_int3.initial_entry.as_mut().unwrap().terminal_trap -= 1;
        assert_eq!(refuse(not_int3), "runtime terminal trap is not int3");
    }

    #[test]
    fn the_fixed_placement_matches_the_guest_tool_region_constants() {
        // The guest's own declarations, read from its source: the data band
        // starts at DATA_FIRST = CONTROL_BYTES / PAGE (1 MiB), and the tool
        // band, which ends the free band, starts at page 65535.
        let region = include_str!("../../guest/tool_region.rs");
        assert!(region.contains("const CONTROL_BYTES: usize = 1024 * 1024;"));
        assert!(region.contains("const DATA_FIRST: usize = CONTROL_BYTES / PAGE;"));
        let arena = include_str!("../../guest/tool_region_arena.rs");
        assert!(arena.contains("assert!(TOOL_BAND.0 == 65535 && TOOL_BAND.1 == 73729);"));
        let placement = Placement::fixed().unwrap();
        assert_eq!(placement.roles[0].start, TOOL_REGION.start + 1024 * 1024);
        assert_eq!(placement.free_band.start, TOOL_REGION.start + 1024 * 1024);
        assert_eq!(placement.free_band.end, TOOL_REGION.start + 65535 * PAGE);
    }

    #[test]
    fn the_fixed_placement_is_the_promoted_literal_layout() {
        let placement = Placement::fixed().unwrap();
        let roles: Vec<(u64, u64)> = placement.roles.iter().map(|r| (r.start, r.end)).collect();
        assert_eq!(
            roles,
            vec![
                (0x6000_0010_0000, 0x6000_0020_0000),
                (0x6000_0020_0000, 0x6000_0024_0000),
                (0x6000_0024_0000, 0x6000_0034_0000),
                (0x6000_0034_0000, 0x6000_0044_0000),
                (0x6000_0044_0000, 0x6000_0054_0000),
            ]
        );
        assert_eq!(
            (placement.free_band.start, placement.free_band.end),
            (0x6000_0010_0000, 0x6000_0ffff000)
        );
        assert_eq!(placement.filter_scratch, 0x6000_0044_8000);
    }

    /// Arm one real birth of `image` on a held `/bin/true` exec stop, prepare
    /// the mapping physically, check it, and cancel. Returns the binding.
    fn arm_prepare_and_cancel(image: &AuditedRuntimeImage) -> HandoffBinding {
        use crate::launcher::exec_stop::CleanupReceipt;
        use crate::launcher::exec_stop::ExecStop;
        use crate::launcher::exec_stop::InitPacketBirthKind;
        use crate::launcher::exec_stop::InitPacketExpectation;
        use crate::launcher::exec_stop::PreparedExec;
        use crate::launcher::exec_stop::build_init_packet;

        let birth = MappedBirth::new(
            image,
            MemfdNames {
                runtime: c"producer-test-runtime",
                packet: c"producer-test-packet",
            },
        )
        .unwrap();
        let request = PreparedExec::new(
            std::path::Path::new("/bin/true"),
            &["producer-arm".into()],
            &[],
            None,
            birth.inherited().to_vec(),
        )
        .unwrap();
        let stop = ExecStop::spawn(request, CleanupReceipt::default()).unwrap();
        let captured = stop.capture_initial_inputs().unwrap();
        let validated = birth.validated_image().unwrap();
        let copied = stop
            .prepare_copied_inputs(
                &captured,
                &validated,
                &birth.copied_input_request().unwrap(),
            )
            .unwrap();
        // SAFETY: the retained EntryContext owns this held stop's real XSAVE
        // capture.
        let pkru = unsafe { stop.entry().xstate().pkru() }.unwrap();
        let facts = ArmingFacts {
            birth: BirthKind::Initial,
            captured: &captured,
            copied: &copied,
            mask: stop.entry().signal_mask(),
            pkru,
            reserved_signals: SIGSYS_BIT,
        };
        assert_eq!(
            birth.arm(&facts).err().unwrap().to_string(),
            "mapped packet lease is not filled and sealed"
        );
        let packet = build_init_packet(
            InitPacketExpectation {
                birth_kind: InitPacketBirthKind::FirstImage,
                expected_config_digest: [0x11; 32],
                expected_state_digest: [0; 32],
            },
            b"producer-test",
        )
        .unwrap();
        let admission = FakeAdmission::new(vec![packet]);
        birth.fill_packet(&stop, &admission).unwrap();
        // Re-verified at the initial stop after the fill.
        birth.leases().verify_at(&stop, &admission).unwrap();
        let successor = ArmingFacts {
            birth: BirthKind::Successor,
            ..facts
        };
        if image.facts().successor_entry.is_none() {
            assert_eq!(
                birth.arm(&successor).err().unwrap().to_string(),
                "exec_stop_producer_no_entry_for_birth"
            );
        }
        // Reserved signals: SIGSYS is required, SIGSEGV is the only other bit
        // allowed.
        for refused in [0, SIGSEGV_BIT, SIGSYS_BIT | 1, SIGSEGV_BIT | 1] {
            let reserved = ArmingFacts {
                reserved_signals: refused,
                ..facts
            };
            assert_eq!(
                birth.arm(&reserved).err().unwrap().to_string(),
                "exec_stop_producer_reserved_signals",
                "{refused:#x}"
            );
        }
        let facts = ArmingFacts {
            reserved_signals: SIGSYS_BIT | SIGSEGV_BIT,
            ..facts
        };
        let armed = birth.arm(&facts).unwrap();
        assert_eq!(
            birth.arm(&facts).err().unwrap().to_string(),
            "exec_stop_producer_already_armed"
        );
        let Armed {
            preparation,
            entry,
            claim,
        } = armed;
        assert_eq!(entry.entry, image.facts().initial_entry.unwrap().entry);
        // The produced wire is x86-64 by its arch tag, word 4 = 0.
        assert_eq!(
            wire_arch(preparation.handoff_bytes).unwrap(),
            WireArch::X86_64
        );
        assert_eq!(
            preparation.handoff_bytes[WIRE_ARCH_WORD * 8..WIRE_ARCH_WORD * 8 + 8],
            [0; 8]
        );
        // A claim minted for another preparation, to show after_prepare
        // refuses a mapping that is not its own.
        let decoy = memfd_bytes(c"producer-test-decoy", b"decoy", true).unwrap();
        let foreign = ArmedClaim::new(
            HandoffBinding::of(
                &[[0; 4]; 5],
                &MappedLaunchFacts::of_mapped([0; 32], [0; 32]),
            ),
            ArtifactAudit::unaudited(),
            &Preparation {
                runtime_fd: decoy.as_fd(),
                runtime_bytes: b"decoy",
                layout_address: preparation.layout_address,
                handoff_fd: decoy.as_fd(),
                handoff_bytes: b"decoy",
                handoff_address: preparation.handoff_address,
                input_fd: decoy.as_fd(),
                free_band: preparation.free_band,
                filter_scratch: preparation.filter_scratch,
            },
        );
        let original_regs = *captured.registers();
        let original_mask = stop.entry().signal_mask();
        // SAFETY: original ptracer thread; the inherited descriptors are the
        // birth's own, retained by the launch request; genuine captured
        // context of this stop. No runtime entry runs: preparation only.
        let prepared = match unsafe { stop.prepare_mapping(preparation) } {
            Ok(prepared) => prepared,
            Err(failure) => panic!(
                "preparation refused: {} cleanup={:?}",
                failure.error,
                failure.cleanup()
            ),
        };
        // Re-verified after mapping, through the prepared mapping that still
        // holds the stop.
        birth.leases().verify_at(&prepared, &admission).unwrap();
        assert!(!admission.failed.get());
        #[cfg(feature = "stage1a-probe")]
        {
            let observed = prepared.diagnostic_observation().unwrap();
            assert_eq!(observed.registers, original_regs);
            assert_eq!(observed.signal_mask, original_mask);
            assert!(observed.runtime_contents_exact);
            assert!(observed.handoff_exact);
        }
        #[cfg(not(feature = "stage1a-probe"))]
        let _ = (original_regs, original_mask);
        let foreign = foreign.after_prepare(&prepared).map(|_| ()).unwrap_err();
        assert_eq!(
            (foreign.gap.key, foreign.slot),
            (CLAIM_FOREIGN_PREPARATION, None)
        );
        // The route labels the launch unqualified; the launch goes on.
        assert_eq!(
            launch_label(&Err(foreign)),
            "mapped-unqualified:exec_stop_claim_foreign_preparation"
        );
        let launch = claim.after_prepare(&prepared).unwrap();
        let binding = *launch.binding();
        let refused = QualifiedMappedLaunch::claim(&launch).unwrap_err();
        assert_eq!(refused.gap.key, HANDOFF_BINDING_UNBOUND);
        assert_eq!(
            launch_label(&Err(refused)),
            "mapped-unqualified:exec_stop_handoff_binding_unbound:launch"
        );
        let cancelled = match prepared.cancel() {
            Ok(cancelled) => cancelled,
            Err(retained) => panic!("preparation cancel unconfirmed: {:?}", retained.cleanup()),
        };
        assert!(cancelled.cleanup.confirmed);
        // The preparation recorded the recipe for the same gate address the
        // proof was run on. (This compares recipes, not the kernel's copy.)
        assert_eq!(
            cancelled.filter_bytes,
            super::super::physical::target_recipe(NATIVE_GATE.start).unwrap()
        );
        binding
    }

    #[test]
    fn a_real_birth_arms_prepares_and_cancels_unbound() {
        let (bytes, facts) = qualifying_image();
        let image = AuditedRuntimeImage::new(bytes, facts).unwrap();
        assert_eq!(
            arm_prepare_and_cancel(&image).refusal(),
            Some((0, HANDOFF_BINDING_UNBOUND))
        );
    }

    struct FakeStop;
    impl BirthStop for FakeStop {
        fn duplicate_birth_pidfd_for_inherited(&self, _fd: BorrowedFd<'_>) -> Result<OwnedFd> {
            // Any owned descriptor stands in for the birth pidfd here; the
            // admission below checks only that it was asked.
            Ok(new_unsealed_memfd(c"fake-birth")?.into())
        }
    }

    /// A stop that refuses to vouch for the descriptor.
    struct ForeignStop;
    impl BirthStop for ForeignStop {
        fn duplicate_birth_pidfd_for_inherited(&self, _fd: BorrowedFd<'_>) -> Result<OwnedFd> {
            Err("descriptor not inherited by this birth".into())
        }
    }

    pub(crate) struct FakeAdmission {
        packets: std::cell::RefCell<Vec<Vec<u8>>>,
        peer_checks: std::cell::Cell<u32>,
        failed: std::cell::Cell<bool>,
        foreign_peer: bool,
    }
    impl FakeAdmission {
        pub(crate) fn new(packets: Vec<Vec<u8>>) -> Self {
            Self {
                packets: std::cell::RefCell::new(packets),
                peer_checks: std::cell::Cell::new(0),
                failed: std::cell::Cell::new(false),
                foreign_peer: false,
            }
        }
    }
    impl PacketAdmission for FakeAdmission {
        fn require_watched_peer(&self, _birth: &OwnedFd) -> Result<()> {
            self.peer_checks.set(self.peer_checks.get() + 1);
            if self.foreign_peer {
                return Err("birth is not the watched peer".into());
            }
            Ok(())
        }
        fn initial_packet(&self) -> Result<Vec<u8>> {
            let mut packets = self.packets.borrow_mut();
            Ok(if packets.len() > 1 {
                packets.remove(0)
            } else {
                packets[0].clone()
            })
        }
        fn fail(&self, _error: &dyn std::fmt::Display) {
            self.failed.set(true);
        }
    }

    #[test]
    fn a_foreign_stop_or_peer_refuses_the_fill_and_fails_the_admission() {
        let leases = leases();
        let admission = FakeAdmission::new(vec![b"packet".to_vec()]);
        assert_eq!(
            leases
                .fill_packet(&ForeignStop, &admission)
                .unwrap_err()
                .to_string(),
            "descriptor not inherited by this birth"
        );
        assert!(admission.failed.get());
        assert_eq!(seals(&leases.packet).unwrap(), 0);
        let leases = self::leases();
        let admission = FakeAdmission {
            foreign_peer: true,
            ..FakeAdmission::new(vec![b"packet".to_vec()])
        };
        assert_eq!(
            leases
                .fill_packet(&FakeStop, &admission)
                .unwrap_err()
                .to_string(),
            "birth is not the watched peer"
        );
        assert!(admission.failed.get());
        // A refused lease stays refused.
        let good = FakeAdmission::new(vec![b"packet".to_vec()]);
        assert!(leases.fill_packet(&FakeStop, &good).is_err());
    }

    #[test]
    fn verify_at_rechecks_poison_birth_peer_bytes_and_admission() {
        let packet = b"packet".to_vec();
        let filled = || {
            let leases = leases();
            leases
                .fill_packet(&FakeStop, &FakeAdmission::new(vec![packet.clone()]))
                .unwrap();
            leases
        };
        // A healthy sealed lease verifies, again and again.
        let healthy = filled();
        let admission = FakeAdmission::new(vec![packet.clone()]);
        healthy.verify_at(&FakeStop, &admission).unwrap();
        healthy.verify_at(&FakeStop, &admission).unwrap();
        assert!(!admission.failed.get());
        assert_eq!(admission.peer_checks.get(), 2);
        // A filled lease whose packet offset has moved: sealing does not
        // forbid seeking, and the birth shares this open file description,
        // so the move is visible through the retained descriptor.
        let moved = || {
            use std::io::Seek as _;
            let leases = filled();
            (&leases.packet).seek(std::io::SeekFrom::Start(1)).unwrap();
            leases
        };
        // Each refusal poisons the lease and fails its admission; a later
        // verification with a good stop and admission is refused as poisoned.
        let refusals: [(BirthLeases, &dyn BirthStop, FakeAdmission, &str); 5] = [
            (
                leases(),
                &FakeStop,
                FakeAdmission::new(vec![packet.clone()]),
                "mapped packet lease is not filled and sealed",
            ),
            (
                filled(),
                &ForeignStop,
                FakeAdmission::new(vec![packet.clone()]),
                "descriptor not inherited by this birth",
            ),
            (
                filled(),
                &FakeStop,
                FakeAdmission {
                    foreign_peer: true,
                    ..FakeAdmission::new(vec![packet.clone()])
                },
                "birth is not the watched peer",
            ),
            (
                moved(),
                &FakeStop,
                FakeAdmission::new(vec![packet.clone()]),
                "mapped packet sealed length/seals/offset differ",
            ),
            (
                filled(),
                &FakeStop,
                FakeAdmission::new(vec![b"other".to_vec()]),
                "mapped packet no longer matches actual admission",
            ),
        ];
        for (leases, stop, admission, why) in refusals {
            assert_eq!(
                leases.verify_at(stop, &admission).unwrap_err().to_string(),
                why
            );
            assert!(admission.failed.get(), "{why}");
            let good = FakeAdmission::new(vec![packet.clone()]);
            assert_eq!(
                leases.verify_at(&FakeStop, &good).unwrap_err().to_string(),
                "mapped packet lease is permanently poisoned",
                "after {why}"
            );
            assert!(good.failed.get());
        }
        // A second fill of a sealed lease poisons it, so the old sealed packet
        // no longer verifies (the poison case the embedder's tests assert).
        let leases = filled();
        let again = FakeAdmission::new(vec![packet.clone()]);
        assert_eq!(
            leases
                .fill_packet(&FakeStop, &again)
                .unwrap_err()
                .to_string(),
            "mapped packet lease fill was already attempted"
        );
        let old = FakeAdmission::new(vec![packet]);
        assert_eq!(
            leases.verify_at(&FakeStop, &old).unwrap_err().to_string(),
            "mapped packet lease is permanently poisoned"
        );
        assert!(old.failed.get());
    }

    #[test]
    fn exact_executable_returns_audited_bytes_and_refuses_by_name() {
        let base = RUNTIME_WINDOW.start;
        let text = base + 2 * PAGE;
        // The executable segment (program header 1) maps two pages at
        // base + PAGE; initialize only the first 2 * PAGE - 16 bytes, so its
        // initialized end is mid-page and the mapped page holds bytes past
        // it. A bound widened by one byte would admit one of them.
        let (mut bytes, mut facts) = qualifying_image();
        let filesz = 64 + 56 + 32;
        bytes[filesz..filesz + 8].copy_from_slice(&(2 * PAGE - 16).to_le_bytes());
        facts.image_sha256 = sha2::Sha256::digest(&bytes).into();
        let image = AuditedRuntimeImage::new(bytes, facts).unwrap();
        let end = base + 3 * PAGE - 16;
        assert_eq!(image.exact_executable(text, 2).unwrap(), [0x0f, 0x05]);
        assert_eq!(image.exact_executable(end - 1, 1).unwrap(), [0xcc]);
        for (address, length, why) in [
            (text, 0, "executable range is empty"),
            (u64::MAX - 1, 2, "executable range end overflows"),
            (
                end - 1,
                2,
                "executable range is not inside one executable segment",
            ),
            (
                end,
                1,
                "executable range is not inside one executable segment",
            ),
            (
                base + 4 * PAGE,
                1,
                "executable range is not inside one executable segment",
            ),
            (
                base - 1,
                2,
                "executable range is not inside one executable segment",
            ),
        ] {
            assert_eq!(
                image
                    .exact_executable(address, length)
                    .unwrap_err()
                    .to_string(),
                why,
                "{address:#x}+{length}"
            );
        }
    }

    /// Leases built without an audited image, for the packet tests only.
    fn leases() -> BirthLeases {
        BirthLeases {
            packet: new_unsealed_memfd(c"test-packet").unwrap(),
            runtime: memfd_bytes(c"test-runtime", b"image", true).unwrap(),
            handoff: memfd_bytes(c"test-runtime", &[], false).unwrap(),
            attempted: AtomicBool::new(false),
            poisoned: AtomicBool::new(false),
            sealed: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn inherited_descriptors_are_packet_runtime_handoff_with_their_seals() {
        let leases = leases();
        let [packet, runtime, handoff] = leases.inherited();
        assert_eq!(packet.as_raw_fd(), leases.packet.as_raw_fd());
        assert_eq!(runtime.as_raw_fd(), leases.runtime.as_raw_fd());
        assert_eq!(handoff.as_raw_fd(), leases.handoff.as_raw_fd());
        assert_eq!(seals(&leases.runtime).unwrap(), SEALS);
        assert_eq!(seals(&leases.packet).unwrap(), 0);
        assert_eq!(seals(&leases.handoff).unwrap(), 0);
        assert_eq!(leases.handoff.metadata().unwrap().len(), 0);
    }

    #[test]
    fn a_packet_fills_once_sealed_and_checked_on_both_sides() {
        let leases = leases();
        let admission = FakeAdmission::new(vec![b"packet".to_vec()]);
        assert_eq!(
            leases.fill_packet(&FakeStop, &admission).unwrap(),
            b"packet"
        );
        assert_eq!(admission.peer_checks.get(), 2);
        assert!(!admission.failed.get());
        assert_eq!(seals(&leases.packet).unwrap(), SEALS);
        // A second fill is refused and poisons the lease.
        assert!(leases.fill_packet(&FakeStop, &admission).is_err());
        assert!(admission.failed.get());
        assert!(leases.poisoned.load(Ordering::Acquire));
    }

    #[test]
    fn a_packet_that_changes_while_sealing_is_refused() {
        let leases = leases();
        let admission = FakeAdmission::new(vec![b"first".to_vec(), b"second".to_vec()]);
        let error = leases.fill_packet(&FakeStop, &admission).unwrap_err();
        assert!(
            error.to_string().contains("changed during sealing"),
            "{error}"
        );
        assert!(admission.failed.get());
    }

    #[test]
    fn an_empty_or_oversized_packet_is_refused() {
        for packet in [Vec::new(), vec![0; MAX_PACKET_LEN + 1]] {
            let leases = leases();
            let admission = FakeAdmission::new(vec![packet]);
            assert!(leases.fill_packet(&FakeStop, &admission).is_err());
            assert!(admission.failed.get());
        }
    }

    /// The packet descriptor keeps its number through a fill: the birth
    /// inherited that number, and nothing closes, dups over or replaces it.
    #[test]
    fn the_packet_descriptor_keeps_its_number_through_a_fill() {
        let leases = leases();
        let raw = leases.packet.as_raw_fd();
        assert_eq!(leases.packet().as_raw_fd(), raw);
        assert_eq!(leases.inherited()[0].as_raw_fd(), raw);
        leases
            .fill_packet(&FakeStop, &FakeAdmission::new(vec![b"packet".to_vec()]))
            .unwrap();
        assert_eq!(leases.packet.as_raw_fd(), raw);
        assert_eq!(leases.packet().as_raw_fd(), raw);
        assert_eq!(leases.inherited()[0].as_raw_fd(), raw);
    }

    /// A sealed packet whose retained bytes differ from the sealed record
    /// (same length, same seals, offset 0) is refused by its bytes, poisons
    /// the lease and fails the admission.
    #[test]
    fn retained_packet_bytes_that_differ_are_refused() {
        let sealed = std::sync::OnceLock::new();
        sealed.set(b"packeX".to_vec()).unwrap();
        let leases = BirthLeases {
            packet: memfd_bytes(c"test-packet", b"packet", true).unwrap(),
            sealed,
            ..leases()
        };
        let admission = FakeAdmission::new(vec![b"packeX".to_vec()]);
        assert_eq!(
            leases
                .verify_at(&FakeStop, &admission)
                .unwrap_err()
                .to_string(),
            "mapped packet retained OFD bytes differ"
        );
        assert!(admission.failed.get());
        assert!(leases.poisoned.load(Ordering::Acquire));
    }

    /// A packet that is not pristine (holding a byte, or at offset 1) refuses
    /// the fill by name; nothing is written or sealed.
    #[test]
    fn a_packet_that_is_not_pristine_refuses_the_fill() {
        use std::io::Seek as _;
        let holding = leases();
        holding.packet.write_all_at(b"x", 0).unwrap();
        let moved = leases();
        (&moved.packet).seek(std::io::SeekFrom::Start(1)).unwrap();
        for (leases, length) in [(holding, 1), (moved, 0)] {
            let admission = FakeAdmission::new(vec![b"packet".to_vec()]);
            assert_eq!(
                leases
                    .fill_packet(&FakeStop, &admission)
                    .unwrap_err()
                    .to_string(),
                "mapped packet lease is not pristine empty unsealed OFD"
            );
            assert!(admission.failed.get());
            assert!(leases.poisoned.load(Ordering::Acquire));
            assert_eq!(leases.packet.metadata().unwrap().len(), length);
            assert_eq!(seals(&leases.packet).unwrap(), 0);
        }
    }

    /// A packet outside the size bound is refused by name before anything
    /// is written: the lease keeps length 0 and no seals.
    #[test]
    fn a_size_refusal_writes_and_seals_nothing() {
        for packet in [Vec::new(), vec![0; MAX_PACKET_LEN + 1]] {
            let leases = leases();
            let admission = FakeAdmission::new(vec![packet]);
            assert_eq!(
                leases
                    .fill_packet(&FakeStop, &admission)
                    .unwrap_err()
                    .to_string(),
                "mapped packet size outside scalar packet bound"
            );
            assert_eq!(leases.packet.metadata().unwrap().len(), 0);
            assert_eq!(seals(&leases.packet).unwrap(), 0);
        }
    }

    /// Moving a sealed packet's shared offset is refused at the next
    /// verification and poisons the lease; moving it back does not repair
    /// the lease.
    #[test]
    fn a_moved_sealed_packet_offset_is_refused_and_not_repaired() {
        use std::io::Seek as _;
        let leases = leases();
        leases
            .fill_packet(&FakeStop, &FakeAdmission::new(vec![b"packet".to_vec()]))
            .unwrap();
        (&leases.packet).seek(std::io::SeekFrom::Start(1)).unwrap();
        let admission = FakeAdmission::new(vec![b"packet".to_vec()]);
        assert_eq!(
            leases
                .verify_at(&FakeStop, &admission)
                .unwrap_err()
                .to_string(),
            "mapped packet sealed length/seals/offset differ"
        );
        assert!(admission.failed.get());
        (&leases.packet).seek(std::io::SeekFrom::Start(0)).unwrap();
        let good = FakeAdmission::new(vec![b"packet".to_vec()]);
        assert_eq!(
            leases.verify_at(&FakeStop, &good).unwrap_err().to_string(),
            "mapped packet lease is permanently poisoned"
        );
        assert!(good.failed.get());
    }

    /// A poison stored while a checked operation runs fails that operation
    /// at its final barrier, though the operation itself succeeded.
    #[test]
    fn a_poison_stored_during_a_checked_operation_fails_it() {
        let leases = leases();
        let result = leases.checked(|| {
            leases.poisoned.store(true, Ordering::Release);
            Ok(())
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "mapped packet lease is permanently poisoned"
        );
    }
}
