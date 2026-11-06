//! Finite machine proofs for data-only preparation identities.
//!
//! Names locate evidence only. Admission comes from the complete actual RX body,
//! an unambiguous private identity and the exact caller/load/RELRO-GOT relation.

use super::*;

const SPILLED_RDI_IDENTITY: &[u8] = &[
    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x89, 0x7c, 0x24, 0xf0, 0x48, 0x8d, 0x44, 0x24, 0xf0, 0x48,
    0x8b, 0x44, 0x24, 0xf0, 0xc3,
];
const REVERSED_SPILLED_RDI_IDENTITY: &[u8] = &[
    0x48, 0x89, 0x7c, 0x24, 0xf0, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x8d, 0x44, 0x24, 0xf8, 0x48,
    0x8b, 0x44, 0x24, 0xf8, 0xc3,
];
const NULL_BRANCH_RDI_IDENTITY: &[u8] = &[
    0x48, 0x89, 0x7c, 0x24, 0xe8, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x83, 0xff, 0x00, 0x74, 0x0c,
    0x48, 0x8b, 0x44, 0x24, 0xe8, 0x48, 0x89, 0x44, 0x24, 0xf0, 0xeb, 0x09, 0x48, 0xc7, 0x44, 0x24,
    0xf0, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x44, 0x24, 0xf0, 0xc3,
];
const REVERSED_NULL_BRANCH_RDI_IDENTITY: &[u8] = &[
    0x48, 0x89, 0x7c, 0x24, 0xe8, 0x48, 0x89, 0x7c, 0x24, 0xf8, 0x48, 0x83, 0xff, 0x00, 0x75, 0x0b,
    0x48, 0xc7, 0x44, 0x24, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x0a, 0x48, 0x8b, 0x44, 0x24, 0xe8,
    0x48, 0x89, 0x44, 0x24, 0xf0, 0x48, 0x8b, 0x44, 0x24, 0xf0, 0xc3,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)] // Rdi names the register every class spills
enum IdentityClass {
    SpilledRdi,
    ReversedSpilledRdi,
    NullBranchRdi,
    ReversedNullBranchRdi,
}
impl IdentityClass {
    fn label(self) -> &'static str {
        match self {
            Self::SpilledRdi => "spilled_rdi_identity",
            Self::ReversedSpilledRdi => "reversed_spilled_rdi_identity",
            Self::NullBranchRdi => "null_branch_rdi_identity",
            Self::ReversedNullBranchRdi => "reversed_null_branch_rdi_identity",
        }
    }
}

fn identity_class(body: &[u8]) -> Result<IdentityClass> {
    // Linux x86-64 SysV call premise: RSP names a real return address and the
    // caller supplies the ordinary 128-byte red zone below entry RSP. None of
    // these complete functions changes RSP, a callee-saved register or foreign
    // memory. The two 21-byte variants spill only to RSP-8/-16, in opposite
    // orders; each address-takes and reloads its second spill, then returns
    // incoming RDI in RAX. The two 43-byte variants spill only to -8/-16/-24.
    // In one, JE +14->+28 chooses a zero spill when RDI=0; otherwise
    // JMP +26->+37 rejoins the incoming value. In the reversed layout,
    // JNE +14->+27 chooses the incoming spill when RDI is nonzero; the zero
    // spill falls through and JMP +25->+37 rejoins the final load. All return
    // exactly the initial 64-bit RDI for every input. RET consumes the
    // unchanged return address. The 43-byte variants change arithmetic flags,
    // which SysV callers may not keep live across an ordinary function call.
    // No source-level pointer validity/Option layout or unmodeled body is
    // proved.
    match body {
        SPILLED_RDI_IDENTITY => Ok(IdentityClass::SpilledRdi),
        REVERSED_SPILLED_RDI_IDENTITY => Ok(IdentityClass::ReversedSpilledRdi),
        NULL_BRANCH_RDI_IDENTITY => Ok(IdentityClass::NullBranchRdi),
        REVERSED_NULL_BRANCH_RDI_IDENTITY => Ok(IdentityClass::ReversedNullBranchRdi),
        _ => Err("unrecognized complete preparation identity ABI body".to_owned()),
    }
}

fn executable_entries(elf: &Elf<'_>) -> BTreeSet<u64> {
    // Include defined function aliases even if their extent is zero. An alias
    // after a defining load must not evade the caller's alternate-entry check.
    elf.syms
        .iter()
        .chain(elf.dynsyms.iter())
        .filter(|symbol| {
            symbol.st_type() == sym::STT_FUNC
                && symbol.st_shndx != section_header::SHN_UNDEF as usize
        })
        .map(|symbol| symbol.st_value)
        .collect()
}

fn identity_symbol(elf: &Elf<'_>, address: u64) -> Result<(String, sym::Sym)> {
    let candidates: Vec<_> = elf
        .syms
        .iter()
        .chain(elf.dynsyms.iter())
        .filter(|symbol| {
            symbol.st_type() == sym::STT_FUNC
                && symbol.st_shndx != section_header::SHN_UNDEF as usize
                && symbol.st_value == address
        })
        .collect();
    require(
        candidates.len() == 1,
        "preparation identity has absent/ambiguous symbol aliases",
    )?;
    let symbol = candidates[0];
    require(
        executable_symbol(elf, &symbol) && symbol.st_bind() == sym::STB_LOCAL,
        "preparation identity is not a complete local executable function",
    )?;
    let name = elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or("preparation identity symbol name is absent")?;
    require(
        !name.is_empty()
            && !elf
                .dynsyms
                .iter()
                .any(|s| elf.dynstrtab.get_at(s.st_name) == Some(name)),
        "preparation identity has a dynamic/preemptible name",
    )?;
    let end = address
        .checked_add(symbol.st_size)
        .ok_or("preparation identity extent overflows")?;
    require(
        executable_entries(elf)
            .range((
                std::ops::Bound::Excluded(address),
                std::ops::Bound::Excluded(end),
            ))
            .next()
            .is_none(),
        "preparation identity has an interior function alias",
    )?;
    for other in elf.syms.iter().chain(elf.dynsyms.iter()).filter(|s| {
        s.st_type() == sym::STT_FUNC
            && s.st_shndx != section_header::SHN_UNDEF as usize
            && s.st_value != address
            && s.st_size != 0
    }) {
        let other_end = other
            .st_value
            .checked_add(other.st_size)
            .ok_or("preparation function alias extent overflows")?;
        require(
            !(other.st_value < end && address < other_end),
            "preparation identity has an overlapping function extent",
        )?;
    }
    Ok((name.to_owned(), symbol))
}

fn calls(
    instructions: &[EncodedConstructorInstruction],
    got: &BTreeMap<u64, u64>,
    entries: &BTreeSet<u64>,
) -> Result<Vec<GotEdge>> {
    let (first, _) = preparation_instruction_boundaries(instructions)?;
    if !instructions.iter().any(|i| i.bytes == [0xff, 0xd0]) {
        return Ok(Vec::new());
    }
    // The same finite full-caller entry vocabulary and defining-load/window
    // proof are shared with strict admission; discovery never grants an edge.
    let entries = preparation_register_entry_targets(instructions, entries)?;
    instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| instruction.bytes == [0xff, 0xd0])
        .map(|(index, _)| {
            preparation_register_got_target(instructions, index, first, &entries, got)
                .map(|(_, edge)| edge)
        })
        .collect()
}

/// Deterministic candidate closure from complete actual adoption functions.
/// Known canonical helpers retain their old authority. Every other candidate
/// needs complete retained bytes and the separate proof below before admission.
pub(super) fn candidate_scope(
    elf: &Elf<'_>,
    text: &str,
    got: &BTreeMap<u64, u64>,
    primary: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<u64, u64>> {
    let known: BTreeSet<_> = preparation_symbols(elf)?
        .values()
        .map(|s| s.st_value)
        .collect();
    let entries = executable_entries(elf);
    let mut targets = BTreeSet::new();
    for name in [CONSTRUCTOR_ADOPTION, GENERIC_ADOPTION] {
        let present = elf.syms.iter().any(|symbol| {
            elf.strtab.get_at(symbol.st_name) == Some(name)
                && primary.contains_key(&symbol.st_value)
        });
        if !present {
            continue;
        }
        let owner = private_function(elf, name)?;
        let instructions = constructor_instructions(text, owner.st_value)?;
        for edge in calls(&instructions, got, &entries)? {
            if !known.contains(&edge.target_function) {
                identity_symbol(elf, edge.target_function)?;
                targets.insert(edge.target_function);
            }
        }
    }
    selected_function_ranges(elf, targets)
}

// Select a preliminary view only to discover the additional candidate scope.
// Keep interior labels inside primary extents so the existing gate-label view
// still checks them. Final verification below always uses the ORIGINAL complete
// text against the full union, rejecting unselected, missing or duplicate chunks.
fn scope_view(text: &str, scope: &BTreeMap<u64, u64>) -> String {
    let mut selected = true;
    let mut view = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let header = trimmed
            .split_once(" <")
            .filter(|(_, suffix)| suffix.ends_with(">:"))
            .and_then(|(address, _)| u64::from_str_radix(address, 16).ok());
        if let Some(address) = header {
            selected = scope.iter().any(|(&start, &size)| {
                start <= address && start.checked_add(size).is_some_and(|end| address < end)
            });
        }
        if selected {
            view.push_str(line);
            view.push('\n');
        }
    }
    view
}

/// Both tool-collecting and retained-evidence paths derive the same closure.
/// The original primary bytes are verified before parsing candidate call sites.
pub(super) fn complete_bytes(
    elf: &Elf<'_>,
    bytes: &[u8],
    initializer: &str,
    text: &str,
    primary: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<u64, Vec<u8>>> {
    let initial = proof_function_bytes(elf, bytes, primary)?;
    let primary_view = scope_view(text, primary);
    verify_constructor_complete_bytes(elf, initializer, &primary_view, &initial)?;
    let got = local_got_targets(elf, bytes)?;
    let extra = candidate_scope(elf, &primary_view, &got, primary)?;
    let mut full = primary.clone();
    for (address, size) in extra {
        if let Some(previous) = full.insert(address, size) {
            require(
                previous == size,
                "preparation identity conflicts with primary extent",
            )?;
        }
    }
    let code = proof_function_bytes(elf, bytes, &full)?;
    verify_constructor_complete_bytes(elf, initializer, text, &code)?;
    Ok(code)
}

struct ProvenIdentity {
    symbol: SymbolEvidence,
    class: IdentityClass,
    body_sha256: String,
}

/// No public/serialized constructor exists. The only populated constructor
/// checks real ELF identity, complete RX/no-writer bytes, retained disassembly,
/// an exact whole-function ABI recipe and every actual caller/GOT relation.
pub(super) struct ProvenIdentities {
    identities: BTreeMap<u64, ProvenIdentity>,
    routes: BTreeSet<(u64, u64, u64, u64)>,
    entries: BTreeSet<u64>,
}
impl ProvenIdentities {
    pub(super) fn proves(&self, edge: &GotEdge) -> bool {
        self.identities.contains_key(&edge.target_function)
            && self.routes.contains(&(
                edge.source_function,
                edge.instruction,
                edge.slot,
                edge.target_function,
            ))
    }

    pub(super) fn entries(&self) -> &BTreeSet<u64> {
        &self.entries
    }

    pub(super) fn append_records(
        &self,
        helpers: &mut BTreeMap<String, SymbolEvidence>,
        hashes: &mut BTreeMap<String, String>,
    ) -> Result<()> {
        for (index, proof) in self.identities.values().enumerate() {
            let key = format!("preparation_identity_{}_{}", proof.class.label(), index);
            require(
                !helpers.contains_key(&key) && !hashes.contains_key(&key),
                "preparation identity evidence key collision",
            )?;
            helpers.insert(key.clone(), proof.symbol.clone());
            hashes.insert(key, proof.body_sha256.clone());
        }
        Ok(())
    }
}

// A current source context and the existing complete native bridge are BOTH
// required, in addition to the leaf/body/GOT proof. No serialized record can
// construct VerifiedCompiledSources or this borrowed typed-entry premise.
struct SysvAdoption<'a> {
    _sources: &'a VerifiedCompiledSources,
    owner: u64,
}

fn require_current_sources(
    sources: Option<&VerifiedCompiledSources>,
) -> Result<&VerifiedCompiledSources> {
    sources.ok_or_else(|| {
        "preparation identity requires independent current compiled sources".to_owned()
    })
}

fn reviewed_entry_source_identity(size: u64, hash: &str) -> Result<()> {
    // This already-reviewed whole source includes the two private C-ABI
    // adoption entries, their scalar arguments and NativeFreshOwner::from_native.
    // It is an additional typed caller premise, never a leaf admission recipe.
    content_catalog_matches(
        "reverie-inguest/src/guest/tool_region_constructor.rs",
        size,
        hash,
    )
}

fn reviewed_entry_source(file: &FileIdentity) -> Result<()> {
    let bytes = fs::read(&file.path).map_err(|e| format!("read typed adoption source: {e}"))?;
    require(
        sha256(&bytes) == file.sha256,
        "typed adoption source bytes differ from independent current source identity",
    )?;
    let size = u64::try_from(bytes.len()).map_err(|_| "typed adoption source length overflows")?;
    reviewed_entry_source_identity(size, &file.sha256)
}

fn owned_entry(owner: u64, route: &NativeDispatchRoute) -> Result<()> {
    // NativeDispatchRoute is produced by the existing COMPLETE byte recipe:
    // successful NOREPLACE mapping/mprotect of the owned stack, exact aligned
    // TOP->RSP switch, scalar RDI preparation and genuine direct CALL/RET pair.
    // The ordinary SysV red zone through entry RSP-24 is inside that mapping;
    // this does not prove arbitrary recursive stack depth or reference lifetime.
    require(
        route.prepare.target == owner
            && route.prepare.local_got_slot.is_none()
            && route.body_save < route.stack_switch
            && route.stack_switch < route.prepare.instruction
            && route.prepare.instruction.checked_add(5) == Some(route.prepare_return),
        "preparation identity lacks its actual owned SysV adoption entry",
    )
}

impl<'a> SysvAdoption<'a> {
    fn resolve(
        sources: Option<&'a VerifiedCompiledSources>,
        owner: u64,
        route: &NativeDispatchRoute,
    ) -> Result<Self> {
        let sources = require_current_sources(sources)?;
        sources.verify_files()?;
        let file = sources
            .record
            .files
            .get("rv:reverie-inguest/src/guest/tool_region_constructor.rs")
            .ok_or("independent current source context lacks typed adoption entry")?;
        file.verify()?;
        reviewed_entry_source(file)?;
        owned_entry(owner, route)?;
        Ok(Self {
            _sources: sources,
            owner,
        })
    }
}

pub(super) struct AdoptionContext<'a> {
    pub(super) sources: Option<&'a VerifiedCompiledSources>,
    pub(super) route: &'a NativeDispatchRoute,
}

pub(super) fn qualify_transfers(
    elf: &Elf<'_>,
    bytes: &[u8],
    text: &str,
    instructions: &[EncodedConstructorInstruction],
    got: &BTreeMap<u64, u64>,
    known: &BTreeSet<u64>,
    context: AdoptionContext<'_>,
) -> Result<(Vec<ConstructorTransfer>, Vec<GotEdge>, ProvenIdentities)> {
    let entries = executable_entries(elf);
    let candidates = calls(instructions, got, &entries)?;
    let targets = candidates
        .iter()
        .filter(|edge| !known.contains(&edge.target_function))
        .map(|edge| edge.target_function)
        .collect();
    let ranges = selected_function_ranges(elf, targets)?;
    let premise = if ranges.is_empty() {
        None
    } else {
        let (owner, _) = preparation_instruction_boundaries(instructions)?;
        Some(SysvAdoption::resolve(
            context.sources,
            owner,
            context.route,
        )?)
    };
    let code = if ranges.is_empty() {
        BTreeMap::new()
    } else {
        require(
            got == &local_got_targets(elf, bytes)?,
            "preparation identity GOT differs from actual immutable loader routes",
        )?;
        proof_function_bytes(elf, bytes, &ranges)?
    };
    if !code.is_empty() {
        verify_disassembly_bytes(&scope_view(text, &ranges), &code)?;
    }
    let mut identities = BTreeMap::new();
    for (&address, body) in &code {
        let (name, symbol) = identity_symbol(elf, address)?;
        let class = identity_class(body)?;
        identities.insert(
            address,
            ProvenIdentity {
                symbol: symbol_evidence(&name, &symbol),
                class,
                body_sha256: sha256(body),
            },
        );
    }
    let routes = candidates
        .iter()
        .filter(|edge| {
            identities.contains_key(&edge.target_function)
                && premise
                    .as_ref()
                    .is_some_and(|p| edge.source_function == p.owner)
        })
        .map(|edge| {
            (
                edge.source_function,
                edge.instruction,
                edge.slot,
                edge.target_function,
            )
        })
        .collect();
    let proofs = ProvenIdentities {
        identities,
        routes,
        entries,
    };
    let (transfers, edges) =
        preparation_transfers_with_identity_proofs(instructions, got, known, false, Some(&proofs))?;
    Ok((transfers, edges, proofs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_wrong_current_source_and_owned_entry_cannot_grant_identity() {
        assert_eq!(
            require_current_sources(None).err().unwrap(),
            "preparation identity requires independent current compiled sources"
        );
        // Data-only catalogue fixtures test the specific source guard; they do
        // not create VerifiedCompiledSources or a physical identity witness.
        let (relative, size, hash) = CONTENT_REVERIE_CATALOG
            .iter()
            .find(|(name, _, _)| *name == "reverie-inguest/src/guest/tool_region_constructor.rs")
            .unwrap();
        assert_eq!(
            *relative,
            "reverie-inguest/src/guest/tool_region_constructor.rs"
        );
        assert!(reviewed_entry_source_identity(*size, hash).is_ok());
        assert!(reviewed_entry_source_identity(*size, &"0".repeat(64)).is_err());
        assert!(reviewed_entry_source_identity(*size + 1, hash).is_err());
        // Reuse the actual existing complete bridge decoder as the positive
        // typed-entry source; no handwritten route substitutes for that decoder.
        let address = 0x1000;
        let initializing = 0x100000;
        let gate = 0x200000;
        let owner = 0x300000;
        let mut bytes = native_template(NativeDispatchOrigin::Constructor);
        for (offset, target, end) in [
            (0x34, initializing, 0x38),
            (0x71, gate, 0x75),
            (0xab, gate, 0xaf),
            (0xd9, gate, 0xdd),
            (0x186, gate, 0x18a),
            (0x1bc, gate, 0x1c0),
            (0x1e0, owner, 0x1e4),
            (0x219, initializing, 0x21e),
            (0x29f, gate, 0x2a3),
            (0x2b9, gate, 0x2bd),
        ] {
            let displacement = (target as i64 - (address + end) as i64) as i32;
            bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        }
        let route = constructor_native_bridge(&bytes, address, initializing, gate, owner).unwrap();
        assert!(owned_entry(owner, &route).is_ok());
        assert_eq!(
            owned_entry(owner + 1, &route).unwrap_err(),
            "preparation identity lacks its actual owned SysV adoption entry"
        );
        bytes[0x1d2] ^= 1;
        assert!(constructor_native_bridge(&bytes, address, initializing, gate, owner).is_err());
    }

    #[test]
    fn all_complete_preparation_identity_classes_have_exact_abi_bodies() {
        assert_eq!(
            identity_class(SPILLED_RDI_IDENTITY).unwrap(),
            IdentityClass::SpilledRdi
        );
        assert_eq!(
            identity_class(REVERSED_SPILLED_RDI_IDENTITY).unwrap(),
            IdentityClass::ReversedSpilledRdi
        );
        assert_eq!(
            identity_class(NULL_BRANCH_RDI_IDENTITY).unwrap(),
            IdentityClass::NullBranchRdi
        );
        assert_eq!(
            identity_class(REVERSED_NULL_BRANCH_RDI_IDENTITY).unwrap(),
            IdentityClass::ReversedNullBranchRdi
        );
        assert_eq!(SPILLED_RDI_IDENTITY.len(), 21);
        assert_eq!(REVERSED_SPILLED_RDI_IDENTITY.len(), 21);
        assert_eq!(NULL_BRANCH_RDI_IDENTITY.len(), 43);
        assert_eq!(REVERSED_NULL_BRANCH_RDI_IDENTITY.len(), 43);
        // Independently fixed spill/return and null-path bytes pin the ABI claim;
        // no identity is inferred from symbol spelling or an observed hash.
        assert_eq!(
            &SPILLED_RDI_IDENTITY[15..],
            &[0x48, 0x8b, 0x44, 0x24, 0xf0, 0xc3]
        );
        assert_eq!(
            &REVERSED_SPILLED_RDI_IDENTITY[..10],
            &[0x48, 0x89, 0x7c, 0x24, 0xf0, 0x48, 0x89, 0x7c, 0x24, 0xf8]
        );
        assert_eq!(
            &REVERSED_SPILLED_RDI_IDENTITY[15..],
            &[0x48, 0x8b, 0x44, 0x24, 0xf8, 0xc3]
        );
        assert_eq!(&NULL_BRANCH_RDI_IDENTITY[14..16], &[0x74, 0x0c]);
        assert_eq!(&NULL_BRANCH_RDI_IDENTITY[26..28], &[0xeb, 0x09]);
        assert_eq!(16 + 12, 28);
        assert_eq!(28 + 9, 37);
        assert_eq!(&REVERSED_NULL_BRANCH_RDI_IDENTITY[14..16], &[0x75, 0x0b]);
        assert_eq!(&REVERSED_NULL_BRANCH_RDI_IDENTITY[25..27], &[0xeb, 0x0a]);
        assert_eq!(16 + 11, 27);
        assert_eq!(27 + 10, 37);
    }

    #[test]
    fn complete_identity_recipes_refuse_every_byte_change_and_extent_change() {
        for original in [
            SPILLED_RDI_IDENTITY,
            REVERSED_SPILLED_RDI_IDENTITY,
            NULL_BRANCH_RDI_IDENTITY,
            REVERSED_NULL_BRANCH_RDI_IDENTITY,
        ] {
            for offset in 0..original.len() {
                let mut changed = original.to_vec();
                changed[offset] ^= 1;
                assert_eq!(
                    identity_class(&changed).unwrap_err(),
                    "unrecognized complete preparation identity ABI body"
                );
            }
            for end in 0..original.len() {
                assert!(identity_class(&original[..end]).is_err());
            }
            let mut extra = original.to_vec();
            extra.push(0x90);
            assert!(identity_class(&extra).is_err());
        }
        // An external CALL/JMP, SP update, wrong result register or foreign
        // memory access cannot earn a proof by keeping a familiar symbol name.
        for prefix in [
            vec![0xe8, 0, 0, 0, 0],
            vec![0xe9, 0, 0, 0, 0],
            vec![0x48, 0x83, 0xec, 8],
            vec![0x48, 0x8b, 0x07],
        ] {
            let mut body = SPILLED_RDI_IDENTITY.to_vec();
            body[..prefix.len()].copy_from_slice(&prefix);
            assert_eq!(
                identity_class(&body).unwrap_err(),
                "unrecognized complete preparation identity ABI body"
            );
        }
    }

    fn instructions(parts: &[&[u8]]) -> Vec<EncodedConstructorInstruction> {
        let mut address = 0x1000;
        parts
            .iter()
            .map(|bytes| {
                let instruction = EncodedConstructorInstruction {
                    address,
                    bytes: bytes.to_vec(),
                };
                address += bytes.len() as u64;
                instruction
            })
            .collect()
    }

    #[test]
    fn candidate_discovery_keeps_exact_load_got_clobber_and_entry_refusals() {
        let load = [0x48, 0x8b, 0x05, 0xf9, 0x2f, 0, 0];
        let call = [0xff, 0xd0];
        let ret = [0xc3];
        let code = instructions(&[&load, &call, &ret]);
        let got = BTreeMap::from([(0x4000, 0x7000)]);
        let expected = GotEdge {
            source_function: 0x1000,
            instruction: 0x1007,
            slot: 0x4000,
            target_function: 0x7000,
        };
        assert_eq!(calls(&code, &got, &BTreeSet::new()).unwrap(), [expected]);
        assert_eq!(
            calls(&code, &BTreeMap::new(), &BTreeSet::new()).unwrap_err(),
            "contextual prepare GOT load is unresolved/preemptible"
        );
        for entry in 0x1001..=0x1007 {
            assert_eq!(
                calls(&code, &got, &BTreeSet::from([entry])).unwrap_err(),
                "contextual CALL RAX has an entry after its defining load"
            );
        }
        for clobber in [&[0x31, 0xc0][..], &[0x48, 0x89, 0xc8], &[0xeb, 0]] {
            assert_eq!(
                calls(
                    &instructions(&[&load, clobber, &call, &ret]),
                    &got,
                    &BTreeSet::new()
                )
                .unwrap_err(),
                "contextual CALL RAX has an unproved/clobbered argument window"
            );
        }
        let mut wrong_load = load;
        wrong_load[2] = 0x0d;
        assert_eq!(
            calls(
                &instructions(&[&wrong_load, &call, &ret]),
                &got,
                &BTreeSet::new()
            )
            .unwrap_err(),
            "contextual CALL RAX has an unproved/clobbered argument window"
        );
        let alternate = instructions(&[&[0xeb, 7], &load, &call, &ret]);
        assert_eq!(
            calls(&alternate, &got, &BTreeSet::new()).unwrap_err(),
            "contextual CALL RAX has an entry after its defining load"
        );
    }

    #[test]
    fn recorded_identity_symbols_and_hashes_do_not_manufacture_proofs() {
        let edge = GotEdge {
            source_function: 0x1000,
            instruction: 0x1007,
            slot: 0x4000,
            target_function: 0x7000,
        };
        let empty = ProvenIdentities {
            identities: BTreeMap::new(),
            routes: BTreeSet::new(),
            entries: BTreeSet::new(),
        };
        assert!(!empty.proves(&edge));
        let route_only = ProvenIdentities {
            identities: BTreeMap::new(),
            routes: BTreeSet::from([(0x1000, 0x1007, 0x4000, 0x7000)]),
            entries: BTreeSet::new(),
        };
        assert!(!route_only.proves(&edge));
        // This deliberately test-private corruption bypasses construction only
        // to reach route equality; a serialized record has no such constructor.
        let identity = ProvenIdentity {
            symbol: SymbolEvidence {
                name: "untrusted-name".to_owned(),
                address: 0x7000,
                size: 21,
                binding: sym::STB_LOCAL,
                visibility: sym::STV_DEFAULT,
            },
            class: IdentityClass::SpilledRdi,
            body_sha256: sha256(SPILLED_RDI_IDENTITY),
        };
        let mut proof = ProvenIdentities {
            identities: BTreeMap::from([(0x7000, identity)]),
            routes: BTreeSet::new(),
            entries: BTreeSet::new(),
        };
        assert!(!proof.proves(&edge));
        proof.routes.insert((0x1000, 0x1007, 0x4000, 0x7000));
        assert!(proof.proves(&edge));
        for changed in [
            GotEdge {
                instruction: 0x1008,
                ..edge.clone()
            },
            GotEdge {
                slot: 0x4008,
                ..edge.clone()
            },
            GotEdge {
                target_function: 0x7001,
                ..edge.clone()
            },
            GotEdge {
                source_function: 0x1001,
                ..edge.clone()
            },
        ] {
            assert!(!proof.proves(&changed));
        }
        let mut helpers = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        proof.append_records(&mut helpers, &mut hashes).unwrap();
        assert_eq!(helpers.len(), 1);
        assert_eq!(
            hashes.values().next().unwrap(),
            &sha256(SPILLED_RDI_IDENTITY)
        );
        assert!(proof.append_records(&mut helpers, &mut hashes).is_err());
    }

    // A physical symbol-table fixture for this new guard, deliberately not a
    // loader-qualified runtime. It cannot construct ProvenIdentities.
    fn symbol_fixture(extra: Option<(u64, u64)>) -> Vec<u8> {
        fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
            b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        let mut b = vec![0u8; 0x800];
        b[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        for (at, width, value) in [
            (16, 2, 3),
            (18, 2, 62),
            (20, 4, 1),
            (32, 8, 64),
            (40, 8, 0x600),
            (52, 2, 64),
            (54, 2, 56),
            (56, 2, 1),
            (58, 2, 64),
            (60, 2, 4),
        ] {
            put(&mut b, at, width, value);
        }
        for (at, width, value) in [
            (64, 4, 1),
            (68, 4, 5),
            (96, 8, 0x800),
            (104, 8, 0x800),
            (112, 8, 0x1000),
        ] {
            put(&mut b, at, width, value);
        }
        for (index, kind, flags, address, offset, size, link, alignment, entry_size) in [
            (1, 1, 6, 0x200, 0x200, 128, 0, 1, 0),
            (2, 3, 0, 0, 0x500, 128, 0, 1, 0),
            (
                3,
                2,
                0,
                0,
                0x400,
                if extra.is_some() { 72 } else { 48 },
                2,
                8,
                24,
            ),
        ] {
            let at = 0x600 + index * 64;
            for (field, width, value) in [
                (4, 4, kind),
                (8, 8, flags),
                (16, 8, address),
                (24, 8, offset),
                (32, 8, size),
                (40, 4, link),
                (48, 8, alignment),
                (56, 8, entry_size),
            ] {
                put(&mut b, at + field, width, value);
            }
        }
        let names = b"\0identity\0alias\0\0";
        b[0x500..0x500 + names.len()].copy_from_slice(names);
        let mut symbols = vec![(0x200, 21)];
        symbols.extend(extra);
        for (index, (address, size)) in symbols.into_iter().enumerate() {
            let at = 0x400 + (index + 1) * 24;
            put(&mut b, at, 4, if index == 0 { 1 } else { 10 });
            b[at + 4] = sym::STT_FUNC;
            put(&mut b, at + 6, 2, 1);
            put(&mut b, at + 8, 8, address);
            put(&mut b, at + 16, 8, size);
        }
        b[0x200..0x200 + SPILLED_RDI_IDENTITY.len()].copy_from_slice(SPILLED_RDI_IDENTITY);
        b
    }

    #[test]
    fn actual_symbol_identity_refuses_alias_preemption_extent_and_nonexecutable_mapping() {
        let good = symbol_fixture(None);
        let elf = Elf::parse(&good).unwrap();
        let (name, symbol) = identity_symbol(&elf, 0x200).unwrap();
        assert_eq!(name, "identity");
        assert_eq!(symbol.st_size, 21);
        let alias = symbol_fixture(Some((0x200, 21)));
        assert_eq!(
            identity_symbol(&Elf::parse(&alias).unwrap(), 0x200).unwrap_err(),
            "preparation identity has absent/ambiguous symbol aliases"
        );
        let interior = symbol_fixture(Some((0x208, 0)));
        assert_eq!(
            identity_symbol(&Elf::parse(&interior).unwrap(), 0x200).unwrap_err(),
            "preparation identity has an interior function alias"
        );
        let covering = symbol_fixture(Some((0x1f8, 16)));
        assert_eq!(
            identity_symbol(&Elf::parse(&covering).unwrap(), 0x200).unwrap_err(),
            "preparation identity has an overlapping function extent"
        );
        for mutation in 0..4 {
            let mut bad = good.clone();
            match mutation {
                0 => bad[0x400 + 24 + 4] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC,
                1 => bad[0x400 + 24 + 16..0x400 + 24 + 24].fill(0),
                2 => {
                    bad[0x400 + 24 + 16..0x400 + 24 + 24].copy_from_slice(&0x1000u64.to_le_bytes())
                }
                3 => bad[68..72].copy_from_slice(&program_header::PF_R.to_le_bytes()),
                _ => unreachable!(),
            }
            assert_eq!(
                identity_symbol(&Elf::parse(&bad).unwrap(), 0x200).unwrap_err(),
                "preparation identity is not a complete local executable function"
            );
        }
    }

    fn body_text(address: u64, body: &[u8], lengths: &[usize]) -> String {
        let mut text = format!("{address:016x} <evidence_only>:\n");
        let mut at = 0;
        for length in lengths {
            let raw = body[at..at + length]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            text.push_str(&format!("{:x}: {raw} instruction\n", address + at as u64));
            at += length;
        }
        assert_eq!(at, body.len());
        text
    }

    #[test]
    fn independent_complete_union_refuses_missing_changed_duplicate_and_unselected_evidence() {
        let first = body_text(0x1000, SPILLED_RDI_IDENTITY, &[5, 5, 5, 5, 1]);
        let second = body_text(
            0x2000,
            NULL_BRANCH_RDI_IDENTITY,
            &[5, 5, 4, 2, 5, 5, 2, 9, 5, 1],
        );
        let all = format!("{first}{second}");
        let expected = BTreeMap::from([
            (0x1000, SPILLED_RDI_IDENTITY.to_vec()),
            (0x2000, NULL_BRANCH_RDI_IDENTITY.to_vec()),
        ]);
        verify_disassembly_bytes(&all, &expected).unwrap();
        let scope = BTreeMap::from([(0x1000, SPILLED_RDI_IDENTITY.len() as u64)]);
        let view = scope_view(&all, &scope);
        assert_eq!(view, first);
        verify_disassembly_bytes(
            &view,
            &BTreeMap::from([(0x1000, SPILLED_RDI_IDENTITY.to_vec())]),
        )
        .unwrap();
        // A preliminary primary-only view never becomes final evidence.
        assert_eq!(
            verify_disassembly_bytes(&view, &expected).unwrap_err(),
            "selected function disassembly is missing a range"
        );
        assert_eq!(
            verify_disassembly_bytes(&format!("{all}{second}"), &expected).unwrap_err(),
            "duplicate disassembly function 0x2000"
        );
        assert_eq!(
            verify_disassembly_bytes(&all.replace("2000: 48", "2000: 49"), &expected).unwrap_err(),
            "instruction 0x2000 raw bytes differ from actual ELF"
        );
        assert_eq!(
            verify_disassembly_bytes(
                &format!("{all}3000 <unselected>:\n3000: c3 ret\n"),
                &expected
            )
            .unwrap_err(),
            "unselected disassembly function 0x3000"
        );
    }

    // Derive only the tested code/symbols from the existing complete loader
    // fixture. Dynamic/hash/relocation construction remains shared verbatim.
    fn transfers_fixture() -> Vec<u8> {
        fn put(b: &mut [u8], at: usize, width: usize, value: u64) {
            b[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        let mut bytes = super::super::tests::loader_writer_fixture::fixture();
        bytes[0x1200..0x1200 + SPILLED_RDI_IDENTITY.len()].copy_from_slice(SPILLED_RDI_IDENTITY);
        bytes[0x1300..0x130a]
            .copy_from_slice(&[0x48, 0x8b, 0x05, 0xf9, 0x1c, 0, 0, 0xff, 0xd0, 0xc3]);
        bytes[0x1400..0x1400 + CONSTRUCTOR_GATE_OWNER_BYTES.len()]
            .copy_from_slice(CONSTRUCTOR_GATE_OWNER_BYTES);
        let required: Vec<_> = FIXED_REQUIRED_ROLES
            .iter()
            .map(|role| {
                FIXED_EMITTED_ROLE_SYMBOLS
                    .iter()
                    .find(|(name, _)| name == role)
                    .unwrap()
                    .1
                    .replace("Cs_", "Cs1_")
            })
            .collect();
        let mut symbols = vec![
            ("identity", 0x1200, 21, sym::STT_FUNC),
            (CONSTRUCTOR_ADOPTION, 0x1300, 10, sym::STT_FUNC),
            (CONSTRUCTOR_GATE_OWNER, 0x1400, 44, sym::STT_FUNC),
            (CONSTRUCTOR_GATE, 0x1420, 0, sym::STT_NOTYPE),
            (CONSTRUCTOR_GATE_RETURN, 0x1422, 0, sym::STT_NOTYPE),
        ];
        for (index, name) in required.iter().enumerate() {
            let address = 0x1500 + index * 0x10;
            bytes[address] = 0xc3;
            symbols.push((name.as_str(), address as u64, 1, sym::STT_FUNC));
        }
        // Keep both larger tables beyond the section headers and inside the
        // existing read-only LOAD; no dynamic/hash/relocation table is moved.
        let symtab = 0x5400;
        let strtab = 0x5600;
        assert!((symbols.len() + 1) * 24 <= strtab - symtab);
        let mut names = vec![0];
        bytes[symtab..strtab].fill(0);
        for (index, (name, address, size, kind)) in symbols.iter().enumerate() {
            let at = symtab + (index + 1) * 24;
            put(&mut bytes, at, 4, names.len() as u64);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
            bytes[at + 4] = *kind;
            bytes[at + 5] = sym::STV_HIDDEN;
            put(&mut bytes, at + 6, 2, 1);
            put(&mut bytes, at + 8, 8, *address);
            put(&mut bytes, at + 16, 8, *size);
        }
        assert!(names.len() <= bytes.len() - strtab);
        bytes[strtab..].fill(0);
        bytes[strtab..strtab + names.len()].copy_from_slice(&names);
        put(&mut bytes, 0x5000 + 64 + 32, 8, 0x400);
        for (section, address, size) in [
            (4, symtab, (symbols.len() + 1) * 24),
            (5, strtab, names.len()),
        ] {
            let header = 0x5000 + section * 64;
            put(&mut bytes, header + 16, 8, address as u64);
            put(&mut bytes, header + 24, 8, address as u64);
            put(&mut bytes, header + 32, 8, size as u64);
        }
        put(
            &mut bytes,
            0x5000 + 4 * 64 + 44,
            4,
            symbols.len() as u64 + 1,
        );
        bytes
    }

    fn transfers_text(bytes: &[u8]) -> String {
        let owner = body_text(0x1300, &bytes[0x1300..0x130a], &[7, 2, 1]);
        let gate = body_text(
            0x1400,
            &bytes[0x1400..0x142c],
            &[2, 7, 3, 3, 3, 3, 3, 3, 5, 2, 3, 4, 2, 1],
        )
        .replace("1420:", &format!("1420 <{CONSTRUCTOR_GATE}>:\n1420:"))
        .replace(
            "1422:",
            &format!("1422 <{CONSTRUCTOR_GATE_RETURN}>:\n1422:"),
        );
        let identity = body_text(0x1200, &bytes[0x1200..0x1215], &[5, 5, 5, 5, 1]);
        format!("{owner}{gate}{identity}")
    }

    fn transfers_route(owner: u64) -> NativeDispatchRoute {
        let address = 0x1000;
        let initializing = 0x100000;
        let gate = 0x200000;
        let mut bytes = native_template(NativeDispatchOrigin::Constructor);
        for (offset, target, end) in [
            (0x34, initializing, 0x38),
            (0x71, gate, 0x75),
            (0xab, gate, 0xaf),
            (0xd9, gate, 0xdd),
            (0x186, gate, 0x18a),
            (0x1bc, gate, 0x1c0),
            (0x1e0, owner, 0x1e4),
            (0x219, initializing, 0x21e),
            (0x29f, gate, 0x2a3),
            (0x2b9, gate, 0x2bd),
        ] {
            let displacement = (target as i64 - (address + end) as i64) as i32;
            bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        }
        constructor_native_bridge(&bytes, address, initializing, gate, owner).unwrap()
    }

    #[test]
    fn qualify_transfers_refuses_nonidentity_missing_sources_and_wrong_owned_entry() {
        // This is a real factory transaction over the independently current,
        // clean workspace. The fixture never constructs opaque source authority.
        // Requires a clean Git checkout, Git and Cargo, and an offline Cargo
        // cache for locked workspace metadata. Missing prerequisites fail; no skip.
        // Cargo spells file!() relative to the workspace root for workspace
        // members, including through #[path] inclusion from another member's
        // tests/support directory; path-included scripts use an absolute
        // spelling, independent of their temporary Cargo package. Normalize
        // lexical parents first so every relative spelling reduces to the
        // workspace-relative source path before any filesystem access: a
        // generated package directory in the spelling may already be gone.
        let raw_source = Path::new(file!());
        let mut source_path = PathBuf::new();
        for component in raw_source.components() {
            match component {
                std::path::Component::ParentDir => assert!(
                    source_path.pop(),
                    "preparation identity test source path escapes its root"
                ),
                std::path::Component::CurDir => {}
                component => source_path.push(component.as_os_str()),
            }
        }
        let workspace = if source_path.is_absolute() {
            fs::canonicalize(
                source_path
                    .ancestors()
                    .nth(3)
                    .expect("preparation identity test source path has no workspace ancestor"),
            )
            .expect("preparation identity test workspace source path cannot be resolved")
        } else {
            // The including crate's manifest dir names a workspace member,
            // not necessarily this crate. Walk its ancestry for the first
            // directory containing the normalized source path.
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            let root = manifest_dir
                .ancestors()
                .find(|ancestor| ancestor.join(&source_path).is_file())
                .expect("preparation identity test source path is not under the workspace");
            fs::canonicalize(root)
                .expect("preparation identity test workspace source path cannot be resolved")
        };
        let scratch = std::env::temp_dir().join(format!(
            "preparation-identity-entry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&scratch).unwrap();
        struct Scratch(PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let scratch = Scratch(scratch);
        let mut runner = Runner::new(
            scratch.0.join("source-factory"),
            Duration::from_secs(30),
            16 * 1024 * 1024,
        )
        .unwrap();
        let pin = runner
            .text(
                "git",
                &["--no-replace-objects", "rev-parse", "HEAD"],
                &workspace,
            )
            .unwrap();
        let manifest = workspace.join("Cargo.toml");
        let expected = CompiledSourceExpectation {
            layout: CompiledSourceLayout::ReverieWorkspace,
            image_kind: FixedImageKind::Standalone,
            workspace_root: &workspace,
            manifest: &manifest,
            reverie_pin: pin.trim(),
        };
        VerifiedCompiledSources::with_resolved(&expected, &mut runner, |sources| {
            let bytes = transfers_fixture();
            let elf = Elf::parse(&bytes).map_err(|error| error.to_string())?;
            let text = transfers_text(&bytes);
            let instructions = constructor_instructions(&text, 0x1300)?;
            let got = local_got_targets(&elf, &bytes)?;
            let primary = BTreeMap::from([(0x1300, 10), (0x1400, 44)]);
            let known = BTreeSet::new();
            let route = transfers_route(0x1300);
            require(
                candidate_scope(&elf, &text, &got, &primary)? == BTreeMap::from([(0x1200, 21)]),
                "entry fixture did not discover the unknown complete identity scope",
            )?;
            let complete = complete_bytes(&elf, &bytes, GENERIC_INITIALIZER, &text, &primary)?;
            require(
                complete.len() == 3 && complete[&0x1200] == SPILLED_RDI_IDENTITY,
                "entry fixture did not authenticate the complete identity union",
            )?;
            let (transfers, edges, proof) = qualify_transfers(
                &elf,
                &bytes,
                &text,
                &instructions,
                &got,
                &known,
                AdoptionContext {
                    sources: Some(sources),
                    route: &route,
                },
            )?;
            let edge = GotEdge {
                source_function: 0x1300,
                instruction: 0x1307,
                slot: 0x3000,
                target_function: 0x1200,
            };
            require(
                transfers
                    == [ConstructorTransfer {
                        instruction: edge.instruction,
                        target: edge.target_function,
                        local_got_slot: Some(edge.slot),
                    }]
                    && edges == [edge.clone()]
                    && proof.proves(&edge),
                "entry fixture did not earn exactly its actual load/GOT/CALL identity proof",
            )?;
            println!("qualify_transfers accepting proof passed");
            // Every negative is paired with the accepting fixture above. The
            // changed body and text agree physically, so only the ABI class can
            // reject it; the two context controls retain the valid body verbatim.
            let mut changed = bytes.clone();
            changed[0x1207] = 0x74; // Return the RSI spill at [RSP-16], not the incoming RDI.
            let changed_elf = Elf::parse(&changed).map_err(|error| error.to_string())?;
            let changed_text = transfers_text(&changed);
            let changed_complete = complete_bytes(
                &changed_elf,
                &changed,
                GENERIC_INITIALIZER,
                &changed_text,
                &primary,
            )?;
            require(
                changed_complete[&0x1200] == changed[0x1200..0x1215],
                "nonidentity mutation did not reach complete physical byte proof",
            )?;
            let result = qualify_transfers(
                &changed_elf,
                &changed,
                &changed_text,
                &instructions,
                &got,
                &known,
                AdoptionContext {
                    sources: Some(sources),
                    route: &route,
                },
            );
            let message = match result {
                Ok(_) => return Err("nonidentity target unexpectedly qualified".to_owned()),
                Err(message) => message,
            };
            require(
                message == "unrecognized complete preparation identity ABI body",
                format!("nonidentity refusal reached the wrong guard: {message}"),
            )?;
            println!("qualify_transfers nonidentity refusal passed: {message}");
            let result = qualify_transfers(
                &elf,
                &bytes,
                &text,
                &instructions,
                &got,
                &known,
                AdoptionContext {
                    sources: None,
                    route: &route,
                },
            );
            let message = match result {
                Ok(_) => return Err("source-less identity unexpectedly qualified".to_owned()),
                Err(message) => message,
            };
            require(
                message == "preparation identity requires independent current compiled sources",
                format!("missing-source refusal reached the wrong guard: {message}"),
            )?;
            println!("qualify_transfers missing-sources refusal passed: {message}");
            let wrong_route = transfers_route(0x1301);
            assert_eq!(wrong_route.prepare.target, 0x1301);
            let result = qualify_transfers(
                &elf,
                &bytes,
                &text,
                &instructions,
                &got,
                &known,
                AdoptionContext {
                    sources: Some(sources),
                    route: &wrong_route,
                },
            );
            let message = match result {
                Ok(_) => return Err("wrong owned entry unexpectedly qualified".to_owned()),
                Err(message) => message,
            };
            require(
                message == "preparation identity lacks its actual owned SysV adoption entry",
                format!("owned-entry refusal reached the wrong guard: {message}"),
            )?;
            println!("qualify_transfers owner-route refusal passed: {message}");
            Ok(())
        })
        .unwrap();
    }
}
