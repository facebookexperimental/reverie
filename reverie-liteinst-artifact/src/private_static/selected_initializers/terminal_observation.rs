//! Finite mapped-entry terminal/observer observations, never entry admission.
use super::*;

const ENTRY_SOURCE: &str = "bc140aaea9d598480cdabddd070ca4bc853ebfa0d7525789c85063988fa91f42";
// The bounded-bootstrap entry keeps the same terminal and observer source
// bodies. Admission of this complete source still requires every actual root,
// owner, body, relocation and local-control check below to pass anew.
const BOOTSTRAP_ENTRY_SOURCE: &str =
    "34e21f21a41f2346889c242c869bc32c74821c625dd5b9cf9bd2181ca2d8d40e";

fn accepted_entry_source(digest: &str) -> bool {
    digest == ENTRY_SOURCE || digest == BOOTSTRAP_ENTRY_SOURCE
}

const PRIVATE_SOURCE: &str = "96005c0878ea34fd94109465db84ad0c66dd2c855c235c4160ce5a76afa86948";
// This complete source adds installed mapped-Tool callback routing. Its terminal
// bodies are unchanged; every emitted role/control check below remains required.
const MAPPED_CALLBACK_PRIVATE_SOURCE: &str =
    "026cecaff9850b3bf916bc0ecb56d0e9021ca5130e7bfc1f64e21a48bc0dd4a9";

fn accepted_private_source(digest: &str) -> bool {
    digest == PRIVATE_SOURCE || digest == MAPPED_CALLBACK_PRIVATE_SOURCE
}

const OBSERVED_LABEL: &str = "detcore_liteinst_mapped_entry_observed_int3";

/// Callback-scoped static observations only. No execution/Ready conversion.
#[derive(Debug, Serialize)]
pub struct MappedTerminalObservation {
    definitions: Vec<(u64, usize, String)>,
    ud2: u64,
    observer_int3: u64,
    expected_post_rip: u64,
    disassembly: FileIdentity,
    // These are persistent open obligations, not successful qualification.
    remaining: Vec<String>,
    scope: &'static str,
}

fn body<'a>(elf: &Elf<'_>, bytes: &'a [u8], role: &RelocatedDefinition) -> Result<&'a [u8]> {
    let (load, offset) = unique_file_mapping(elf, bytes, role.address, role.bytes)?;
    require(load.p_flags == 5, "terminal role is not unique RX")?;
    bytes
        .get(offset..offset + role.bytes)
        .ok_or("terminal body outside file".into())
}

fn rel32(bytes: &[u8], field: usize, address: u64) -> Result<u64> {
    let d = i32::from_le_bytes(
        bytes
            .get(field..field + 4)
            .ok_or("terminal rel32 field")?
            .try_into()
            .map_err(|_| "terminal rel32 width")?,
    );
    address
        .checked_add(field as u64 + 4)
        .and_then(|p| p.checked_add_signed(i64::from(d)))
        .ok_or("terminal rel32 overflow".into())
}

fn terminal_leaf(code: &[u8], address: u64, native: u64) -> Result<()> {
    require(
        code.len() == 34
            && code[..6] == [0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0xe7]
            && code[6..14] == [0, 0, 0, 0xbf, 0x7f, 0, 0, 0]
            && code[14..17] == [0x4c, 0x8d, 0x25]
            && code[21..23] == [0x49, 0xbb]
            && code[31..] == [0x41, 0xff, 0xe3],
        "terminal complete exit/backstop shape differs",
    )?;
    require(
        rel32(code, 17, address)? == address.checked_add(4).ok_or("terminal reload overflow")?
            && u64::from_le_bytes(code[23..31].try_into().unwrap()) == native,
        "terminal native entry or reload edge differs",
    )
}

fn observer(code: &[u8], address: u64, failed: u64) -> Result<()> {
    require(
        code.len() == 12 && code[..8] == [0xf3, 0x0f, 0x1e, 0xfa, 0xcc, 0x31, 0xff, 0xe9],
        "observer complete INT3/tail shape differs",
    )?;
    require(
        rel32(code, 8, address)? == failed,
        "observer terminal tail differs",
    )
}

fn terminal_slot(flags: u32, target: u64, failed: u64) -> Result<()> {
    require(
        flags == 4 && target == failed,
        "mapped terminal RO slot differs",
    )
}
fn observer_label(s: sym::Sym, address: u64, input: bool) -> Result<()> {
    require(
        s.st_type() == sym::STT_NOTYPE
            && s.st_size == 0
            && s.st_value == address + 4
            && s.st_visibility() == sym::STV_HIDDEN
            && s.st_bind()
                == if input {
                    sym::STB_GLOBAL
                } else {
                    sym::STB_LOCAL
                },
        "observer label alias differs",
    )
}

fn wrappers(
    elf: &Elf<'_>,
    bytes: &[u8],
    mapped: &RelocatedDefinition,
    failed: &RelocatedDefinition,
    terminal: &RelocatedDefinition,
) -> Result<()> {
    let m = body(elf, bytes, mapped)?;
    require(
        m.len() == 9 && m[..5] == [0x50, 0x31, 0xff, 0xff, 0x15],
        "mapped terminal wrapper shape differs",
    )?;
    let slot = rel32(m, 5, mapped.address)?;
    let (load, _) = unique_file_mapping(elf, bytes, slot, 8)?;
    terminal_slot(
        load.p_flags,
        u64::from_le_bytes(
            readonly_loaded_bytes(elf, bytes, slot, 8)?
                .try_into()
                .map_err(|_| "terminal slot width")?,
        ),
        failed.address,
    )?;
    let f = body(elf, bytes, failed)?;
    require(
        f.len() == 6 && f[..2] == [0x50, 0xe8] && rel32(f, 2, failed.address)? == terminal.address,
        "initialization_failed complete target differs",
    )
}

fn aliases(
    elf: &Elf<'_>,
    input: bool,
    role: InitializerRole,
    owner_name: &str,
    section: usize,
    address: u64,
    bytes: usize,
) -> Result<()> {
    let end = address
        .checked_add(bytes as u64)
        .ok_or("terminal alias end")?;
    let found = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_shndx == section
                && s.st_value >= address
                && s.st_value < end
                && s.st_type() != sym::STT_SECTION
        })
        .collect::<Vec<_>>();
    let is_observer = matches!(role, InitializerRole::MappedObserver);
    require(
        found.len() == if is_observer { 2 } else { 1 },
        "terminal alias set differs",
    )?;
    for s in found {
        let name = elf.strtab.get_at(s.st_name).ok_or("terminal alias name")?;
        if name == owner_name {
            require(
                s.st_type() == sym::STT_FUNC
                    && s.st_value == address
                    && s.st_size == bytes as u64
                    && role.binding(s, input),
                "terminal owner alias differs",
            )?;
        } else {
            require(
                is_observer && name == OBSERVED_LABEL,
                "extra terminal alias",
            )?;
            observer_label(s, address, input)?;
        }
    }
    // Another section/alias must not impersonate the owner or the trap label.
    for name in std::iter::once(owner_name).chain(is_observer.then_some(OBSERVED_LABEL)) {
        require(
            elf.syms
                .iter()
                .filter(|s| elf.strtab.get_at(s.st_name) == Some(name) && s.st_shndx != 0)
                .count()
                == 1,
            "terminal global alias ambiguity",
        )?;
    }
    Ok(())
}

pub(super) fn exact_terminal_output(elf: &Elf<'_>, actual_name: &str) -> Result<sym::Sym> {
    let found = elf
        .syms
        .iter()
        .filter(|s| s.st_shndx != 0 && elf.strtab.get_at(s.st_name) == Some(actual_name))
        .collect::<Vec<_>>();
    require(
        found.len() == 1,
        "terminal exact output owner absent/duplicate",
    )?;
    Ok(found[0])
}

fn joined_role(
    role: InitializerRole,
    objects: &[ObjectInput<'_>],
    map: &str,
    runtime: &Path,
    elf: &Elf<'_>,
    bytes: &[u8],
) -> Result<RelocatedDefinition> {
    let (selected, actual_name) =
        select_role_named(&role, objects, map, runtime, role.terminal_path().is_some())?;
    let proof =
        join_selected_initializer_named(role, &actual_name, map, selected, objects, elf, bytes)?;
    aliases(
        &selected.elf,
        true,
        role,
        &actual_name,
        proof.section_index,
        0,
        proof.bytes,
    )?;
    let final_symbol = exact_terminal_output(elf, &actual_name)?;
    aliases(
        elf,
        false,
        role,
        &actual_name,
        final_symbol.st_shndx,
        proof.address,
        proof.bytes,
    )?;
    Ok(proof)
}

// Direct local control edges only: exception/LSDA and external runtime
// predecessor proof remains explicitly NOT_PROVEN in the observation.
fn no_other_direct_ud2_predecessor(
    instructions: &[EncodedConstructorInstruction],
    ud2: u64,
    terminal: u64,
) -> Result<()> {
    let (_, boundaries) = preparation_instruction_boundaries(instructions)?;
    let at = instructions
        .iter()
        .position(|i| i.address == ud2)
        .ok_or("terminal UD2 absent")?;
    require(
        at > 0 && instructions[at].bytes == [0x0f, 0x0b],
        "terminal UD2 bytes differ",
    )?;
    let last = instructions.last().ok_or("terminal instructions empty")?;
    let end = last
        .address
        .checked_add(last.bytes.len() as u64)
        .ok_or("terminal instruction end")?;
    let previous = &instructions[at - 1];
    require(
        previous.bytes.first() == Some(&0xe8)
            && previous.bytes.len() == 5
            && previous.address.checked_add(5) == Some(ud2)
            && rel32(&previous.bytes, 1, previous.address)? == terminal,
        "UD2 is not immediately after selected nonreturning terminal",
    )?;
    for i in instructions {
        let op = *i.bytes.first().ok_or("terminal empty instruction")?;
        let field = match op {
            0xe8 | 0xe9 => Some((1, 4)),
            0xeb | 0x70..=0x7f | 0xe0..=0xe3 => Some((1, 1)),
            0x0f if i.bytes.get(1).is_some_and(|b| (0x80..=0x8f).contains(b)) => Some((2, 4)),
            _ => None,
        };
        if let Some((offset, width)) = field {
            let target = if width == 4 {
                rel32(&i.bytes, offset, i.address)?
            } else {
                i.address
                    .checked_add(i.bytes.len() as u64)
                    .and_then(|p| p.checked_add_signed(i64::from(i.bytes[offset] as i8)))
                    .ok_or("terminal short branch overflow")?
            };
            require(target != ud2, "another direct edge enters terminal UD2")?;
            require(
                !(previous.address < target && target < ud2),
                "branch enters terminal call operand",
            )?;
            if instructions[0].address <= target && target < end {
                require(
                    boundaries.contains(&target),
                    "root branch enters instruction operand",
                )?;
            }
        }
    }
    Ok(())
}

impl VerifiedStaticSource {
    /// Observe the finite terminal/observer bodies in this same selected link.
    /// This never returns an entry/image/Ready permission. Unknown root and
    /// exception behavior remains refused, even when these five joins succeed.
    pub fn with_mapped_terminal_observation<T>(
        &self,
        archive: &StaticArchive,
        definitions: &SelectedInitializerDefinitions,
        objdump: &FileIdentity,
        runner: &mut Runner,
        callback: impl FnOnce(&MappedTerminalObservation, &mut Runner) -> Result<T>,
    ) -> Result<T> {
        let admission = self.require_archive_owner(archive).and_then(|_| {
            require(
                Arc::ptr_eq(&self.archive_owner, &definitions.source_owner.0)
                    && definitions.core.runtime == archive.file,
                "terminal definitions belong to another source/archive",
            )
        });
        if let Err(error) = admission {
            return close_result(Err(error), self.guard.close(runner));
        }
        let mut files = definitions.files.clone();
        files.push(objdump.clone());
        let result = self.with_ordinary_trusted_gate(
            archive,
            &definitions.core.artifact,
            &definitions.core.map,
            runner,
            |ordinary, runner| {
                definitions.verify()?;
                objdump.verify()?;
                require(
                    objdump.sha256
                        == "0a1b558f444ed2bca7fb467dede7416a651bc490b1abc77705ab470d99c527c1",
                    "terminal objdump differs",
                )?;
                for (relative, cargo) in [
                    ("detcore-liteinst/src/exec_initial/mapped_entry.rs", false),
                    ("reverie-inguest/src/guest/exec_private.rs", true),
                ] {
                    let roots = self
                        .guard
                        .roots
                        .iter()
                        .filter(|(p, k)| {
                            matches!(k, RootBinding::Cargo(_)) == cargo
                                && p.join(relative).is_file()
                        })
                        .map(|(p, _)| p)
                        .collect::<Vec<_>>();
                    require(roots.len() == 1, "terminal guarded source root ambiguous")?;
                    let file = FileIdentity::read(&roots[0].join(relative))?;
                    require(
                        if cargo {
                            accepted_private_source(&file.sha256)
                        } else {
                            accepted_entry_source(&file.sha256)
                        },
                        "terminal actual source differs",
                    )?;
                    files.push(file);
                }
                let mut backing = extract_objects(&archive.file, 0)?;
                backing.extend(extract_objects(&definitions.core.libc, 1)?);
                let archives = [&archive.file, &definitions.core.libc];
                let objects = backing
                    .iter()
                    .map(|m| {
                        Ok(ObjectInput {
                            archive_path: &archives[m.archive_index].path,
                            member_name: &m.name,
                            ordinal: m.ordinal,
                            header_offset: m.header,
                            bytes: &m.bytes,
                            elf: Elf::parse(&m.bytes).map_err(|e| e.to_string())?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                for o in &objects {
                    checked_object_symbol_authority(&o.elf, o.bytes)?;
                }
                for file in [&definitions.core.artifact, &definitions.core.map] {
                    require(
                        fs::metadata(&file.path).map_err(|e| e.to_string())?.len()
                            <= 128 * 1024 * 1024,
                        "terminal ELF/map exceeds 128 MiB",
                    )?;
                }
                let data = fs::read(&definitions.core.artifact.path).map_err(|e| e.to_string())?;
                let elf = Elf::parse(&data).map_err(|e| e.to_string())?;
                static_image_metadata(&elf, &data)?;
                ordinary.verify_final(&elf, &data)?;
                let map =
                    fs::read_to_string(&definitions.core.map.path).map_err(|e| e.to_string())?;
                let roles = [
                    InitializerRole::MappedRoot,
                    InitializerRole::MappedTerminal,
                    InitializerRole::InitializationFailed,
                    InitializerRole::InitialTerminal,
                    InitializerRole::MappedObserver,
                ];
                let joined = roles
                    .into_iter()
                    .map(|role| joined_role(role, &objects, &map, &archive.file.path, &elf, &data))
                    .collect::<Result<Vec<_>>>()?;
                let [root, mapped, failed, terminal, observed] = joined.as_slice() else {
                    return Err("terminal internal role count".into());
                };
                require(
                    elf.entry == root.address,
                    "terminal root is not actual e_entry",
                )?;
                wrappers(&elf, &data, mapped, failed, terminal)?;
                // Existing complete-page/source/member/map proof, not ordinary44's
                // syscall ABI. The fixed native entry is page+124 in that exact page.
                let native = ordinary.verify_terminal_fixed_page(&objects, &map, &elf, &data)?;
                terminal_leaf(body(&elf, &data, terminal)?, terminal.address, native)?;
                observer(
                    body(&elf, &data, observed)?,
                    observed.address,
                    failed.address,
                )?;
                let end = root
                    .address
                    .checked_add(root.bytes as u64)
                    .ok_or("terminal root end")?;
                let text = runner.run_with_combined_limit(
                    objdump.path.to_str().ok_or("objdump path")?,
                    &[
                        "--disassemble".into(),
                        "--show-raw-insn".into(),
                        "--disassemble-zeroes".into(),
                        "--insn-width=16".into(),
                        "--wide".into(),
                        format!("--start-address={:#x}", root.address),
                        format!("--stop-address={end:#x}"),
                        definitions
                            .core
                            .artifact
                            .path
                            .to_str()
                            .ok_or("terminal artifact path")?
                            .into(),
                    ],
                    definitions
                        .core
                        .artifact
                        .path
                        .parent()
                        .ok_or("terminal artifact parent")?,
                    Some(runner.max_stream_bytes.min(16 * 1024 * 1024)),
                )?;
                let disassembly = runner
                    .commands
                    .last()
                    .ok_or("terminal command absent")?
                    .stdout
                    .clone();
                files.push(disassembly.clone());
                let text = std::str::from_utf8(&text).map_err(|e| e.to_string())?;
                verify_disassembly_bytes(
                    text,
                    &BTreeMap::from([(root.address, body(&elf, &data, root)?.to_vec())]),
                )?;
                let instructions = constructor_instructions(text, root.address)?;
                let traps = instructions
                    .iter()
                    .filter(|i| i.bytes == [0x0f, 0x0b])
                    .collect::<Vec<_>>();
                require(traps.len() == 1, "terminal root UD2 absent/duplicate")?;
                let ud2 = traps[0].address;
                no_other_direct_ud2_predecessor(&instructions, ud2, mapped.address)?;
                let predecessor = instructions
                    .iter()
                    .find(|i| i.address.checked_add(i.bytes.len() as u64) == Some(ud2))
                    .ok_or("terminal call predecessor")?
                    .address;
                // Account for every actual root indirect-control instruction. This
                // establishes only its target exclusion, NOT callee qualification.
                for i in &instructions {
                    let prefix = i
                        .bytes
                        .iter()
                        .take_while(|b| {
                            matches!(
                                **b,
                                0xf0 | 0xf2
                                    | 0xf3
                                    | 0x26
                                    | 0x2e
                                    | 0x36
                                    | 0x3e
                                    | 0x64
                                    | 0x65
                                    | 0x66
                                    | 0x67
                                    | 0x40..=0x4f
                            )
                        })
                        .count();
                    let op = *i
                        .bytes
                        .get(prefix)
                        .ok_or("terminal prefix-only instruction")?;
                    require(
                        !matches!(op, 0xc2 | 0xc3 | 0xca | 0xcb),
                        "mapped root has a return edge",
                    )?;
                    if matches!(op,0xe8 | 0xe9 | 0xeb | 0x70..=0x7f | 0xe0..=0xe3)
                        || op == 0x0f
                            && i.bytes
                                .get(prefix + 1)
                                .is_some_and(|b| (0x80..=0x8f).contains(b))
                    {
                        require(prefix == 0, "prefixed mapped-root branch unsupported")?;
                    }
                    if op == 0xff
                        && i.bytes
                            .get(prefix + 1)
                            .is_some_and(|b| matches!((b >> 3) & 7, 2..=5))
                    {
                        require(
                            prefix == 0
                                && i.bytes.len() == 6
                                && (i.bytes.starts_with(&[0xff, 0x15])
                                    || i.bytes.starts_with(&[0xff, 0x25])),
                            "unknown mapped-root indirect target",
                        )?;
                        let slot = rel32(&i.bytes, 2, i.address)?;
                        let (load, _) = unique_file_mapping(&elf, &data, slot, 8)?;
                        require(
                            load.p_flags == 4,
                            "mapped-root target slot is not immutable RO",
                        )?;
                        let target = u64::from_le_bytes(
                            readonly_loaded_bytes(&elf, &data, slot, 8)?
                                .try_into()
                                .map_err(|_| "mapped-root target width")?,
                        );
                        require(
                            !(predecessor < target && target <= ud2),
                            "indirect edge enters UD2/call operand",
                        )?;
                    }
                }
                // Static aliases and recorded typed relocations can reveal an
                // additional entry. Exception landing pads are NOT discharged here.
                require(
                    !elf.syms
                        .iter()
                        .any(|s| s.st_shndx != 0 && predecessor < s.st_value && s.st_value <= ud2),
                    "symbol enters terminal UD2",
                )?;
                for (_, rows) in &elf.shdr_relocs {
                    for row in rows.iter() {
                        let s = elf
                            .syms
                            .get(row.r_sym)
                            .ok_or("terminal relocation symbol")?;
                        let add = row.r_addend.ok_or("terminal relocation missing addend")?;
                        let target = i128::from(s.st_value) + i128::from(add);
                        let target = match row.r_type {
                            reloc::R_X86_64_PC32 | reloc::R_X86_64_PLT32 => target + 4,
                            reloc::R_X86_64_64 => target,
                            _ => {
                                require(
                                    !(root.address <= s.st_value && s.st_value < end)
                                        && !(i128::from(root.address) <= target
                                            && target < i128::from(end)),
                                    "unknown relocation may enter mapped root",
                                )?;
                                continue;
                            }
                        };
                        require(
                            !(i128::from(predecessor) < target && target <= i128::from(ud2)),
                            "typed relocation enters terminal UD2/call operand",
                        )?;
                    }
                }
                let observation = MappedTerminalObservation {
                    definitions: joined
                        .iter()
                        .map(|p| (p.address, p.bytes, p.member_sha256.clone()))
                        .collect(),
                    ud2,
                    observer_int3: observed.address + 4,
                    expected_post_rip: observed.address + 5,
                    disassembly,
                    remaining: vec![
                        "GENERIC_PREPARATION_REJECTION_UNCHANGED".into(),
                        "UD2_UNREACHABILITY_REQUIRES_EXCEPTION_PREDECESSOR_PROOF".into(),
                        "PANIC_CANNOT_UNWIND_AND_OTHER_CALLEES_NOT_PROVEN".into(),
                        "HOST_GATE_FILTER_SIGNAL_WAIT_AND_CANCEL_NOT_PROVEN".into(),
                        "OBSERVER_SUCCESS_PREDECESSOR_NOT_PROVEN".into(),
                        "PRE_FS_CLOSURE_AND_ENTRY_ADMISSION_NOT_PROVEN".into(),
                    ],
                    scope: "FINITE_TERMINAL_OBSERVER_STATIC_OBSERVATIONS_ONLY",
                };
                let result = callback(&observation, runner);
                close_result(result, observation.disassembly.verify())
            },
        );
        let mut errors = Vec::new();
        for close in [
            archive.verify(),
            definitions.verify(),
            self.guard.close(runner),
        ] {
            if let Err(error) = close {
                errors.push(error);
            }
        }
        for file in &files {
            if let Err(error) = file.verify() {
                errors.push(error);
            }
        }
        close_result(result, require(errors.is_empty(), errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_actual_reload_and_native_entry_are_both_required() {
        let mut code = vec![
            0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 0xe7, 0, 0, 0, 0xbf, 0x7f, 0, 0, 0, 0x4c, 0x8d, 0x25,
            0xef, 0xff, 0xff, 0xff, 0x49, 0xbb,
        ];
        code.extend_from_slice(&0x6000e100107c_u64.to_le_bytes());
        code.extend_from_slice(&[0x41, 0xff, 0xe3]);
        terminal_leaf(&code, 0x4000, 0x6000e100107c).unwrap();
        for offset in [5, 10, 17, 23, 33] {
            let mut changed = code.clone();
            changed[offset] ^= 1;
            assert!(
                terminal_leaf(&changed, 0x4000, 0x6000e100107c).is_err(),
                "offset {offset}"
            );
        }
        assert!(terminal_leaf(&code, 0x4000, 0x6000e100207c).is_err());
        let mut returning = code;
        returning[31..].copy_from_slice(&[0xc3, 0x90, 0x90]);
        assert!(terminal_leaf(&returning, 0x4000, 0x6000e100107c).is_err());
    }
    #[test]
    fn observer_actual_trap_and_nonreturn_tail_are_distinct() {
        let mut code = vec![0xf3, 0x0f, 0x1e, 0xfa, 0xcc, 0x31, 0xff, 0xe9];
        code.extend_from_slice(&0x100_i32.to_le_bytes());
        observer(&code, 0x4000, 0x410c).unwrap();
        for offset in [0, 4, 6, 7, 8] {
            let mut changed = code.clone();
            changed[offset] ^= 1;
            assert!(
                observer(&changed, 0x4000, 0x410c).is_err(),
                "offset {offset}"
            );
        }
        assert!(observer(&code, 0x4000, 0x410d).is_err());
    }
    #[test]
    fn terminal_slot_refuses_writable_executable_or_wrong_actual_target() {
        terminal_slot(4, 0x5000, 0x5000).unwrap();
        for flags in [0, 1, 5, 6, 7] {
            assert!(terminal_slot(flags, 0x5000, 0x5000).is_err());
        }
        assert!(terminal_slot(4, 0x5001, 0x5000).is_err());
    }
    #[test]
    fn observer_label_is_the_exact_post_endbr_trap_not_its_post_rip() {
        let good = sym::Sym {
            st_name: 0,
            st_info: 0,
            st_other: sym::STV_HIDDEN,
            st_shndx: 3,
            st_value: 0x4004,
            st_size: 0,
        };
        observer_label(good, 0x4000, false).unwrap();
        for value in [0x4000, 0x4003, 0x4005, 0x400c] {
            let mut bad = good;
            bad.st_value = value;
            assert!(observer_label(bad, 0x4000, false).is_err());
        }
        let mut bad = good;
        bad.st_size = 1;
        assert!(observer_label(bad, 0x4000, false).is_err());
        bad = good;
        bad.st_info = 2;
        assert!(observer_label(bad, 0x4000, false).is_err());
        bad = good;
        bad.st_other = 0;
        assert!(observer_label(bad, 0x4000, false).is_err());
        assert!(observer_label(good, 0x4000, true).is_err());
    }
    #[test]
    fn actual_noreturn_call_cut_refuses_another_branch_into_ud2() {
        let i = |address, bytes| EncodedConstructorInstruction { address, bytes };
        let valid = vec![
            i(0x4000, vec![0xe8, 0xfb, 0x0f, 0, 0]),
            i(0x4005, vec![0x0f, 0x0b]),
            i(0x4007, vec![0xeb, 0xf7]),
        ];
        no_other_direct_ud2_predecessor(&valid, 0x4005, 0x5000).unwrap();
        let mut changed = valid.clone();
        changed[2].bytes[1] = 0xfc;
        assert!(no_other_direct_ud2_predecessor(&changed, 0x4005, 0x5000).is_err());
        assert!(no_other_direct_ud2_predecessor(&valid, 0x4005, 0x5001).is_err());
        changed = valid.clone();
        changed[2].bytes[1] = 0xff;
        assert!(no_other_direct_ud2_predecessor(&changed, 0x4005, 0x5000).is_err());
        changed = valid;
        changed[1].bytes = vec![0xcc, 0x90];
        assert!(no_other_direct_ud2_predecessor(&changed, 0x4005, 0x5000).is_err());
    }

    #[test]
    fn mapped_terminal_entry_sources_remain_exact_closed_declarations() {
        for digest in [ENTRY_SOURCE, BOOTSTRAP_ENTRY_SOURCE] {
            assert!(accepted_entry_source(digest));
            for refused in [
                "0".repeat(64),
                digest[..63].to_owned(),
                format!("{digest}0"),
                digest.to_ascii_uppercase(),
                format!("sha256:{digest}"),
            ] {
                assert!(!accepted_entry_source(&refused));
            }
            for index in 0..digest.len() {
                let mut modified = digest.as_bytes().to_vec();
                modified[index] = if modified[index] == b'0' { b'1' } else { b'0' };
                assert!(!accepted_entry_source(
                    &String::from_utf8(modified).unwrap()
                ));
            }
        }
        assert!(!accepted_entry_source(PRIVATE_SOURCE));
    }
    #[test]
    fn terminal_private_sources_remain_exact_closed_declarations() {
        for digest in [PRIVATE_SOURCE, MAPPED_CALLBACK_PRIVATE_SOURCE] {
            assert!(accepted_private_source(digest));
            for refused in [
                "0".repeat(64),
                digest[..63].to_owned(),
                format!("{digest}0"),
                digest.to_ascii_uppercase(),
                format!("sha256:{digest}"),
            ] {
                assert!(!accepted_private_source(&refused));
            }
            for index in 0..digest.len() {
                let mut modified = digest.as_bytes().to_vec();
                modified[index] = if modified[index] == b'0' { b'1' } else { b'0' };
                assert!(!accepted_private_source(
                    &String::from_utf8(modified).unwrap()
                ));
            }
        }
        for digest in [ENTRY_SOURCE, BOOTSTRAP_ENTRY_SOURCE] {
            assert!(!accepted_private_source(digest));
        }
        assert!(!accepted_entry_source(MAPPED_CALLBACK_PRIVATE_SOURCE));
    }
}
