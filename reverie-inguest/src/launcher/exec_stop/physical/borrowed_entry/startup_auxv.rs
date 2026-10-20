//! Original guest auxv canonicalization before genuine InitialImage callbacks.
//! Same retained ptracer/wait driver; no public injection or readiness API.
use reverie::vdso::CANONICAL_VDSO_ADDRESS;
use reverie::vdso::CANONICAL_VDSO_SIZE;
use reverie::vdso::canonical_vdso_image;

use super::*;
use crate::launcher::exec_stop::initial_stack_inputs::ParsedInitial;
use crate::launcher::exec_stop::trace;

#[derive(Debug)]
struct Update {
    address: u64,
    old: u64,
    new: u64,
}

// Pure plan from the SAME captured guest stack, not the copied private TLS auxv.
fn updates(base: u64, bytes: &[u8], rsp: u64) -> Result<(Vec<Update>, bool)> {
    let parsed = ParsedInitial::parse(base, bytes, rsp)
        .map_err(|error| format!("mapped_startup_auxv: {error:?}"))?;
    let mut result = Vec::new();
    let mut vdso = false;
    for (address, aux) in parsed.auxiliary_value_slots() {
        if aux.kind == reverie::AT_MINSIGSTKSZ {
            reverie::check_host_minsigstksz(aux.value)?;
        }
        let selected = if aux.kind == libc::AT_SYSINFO_EHDR {
            vdso = true;
            Some(CANONICAL_VDSO_ADDRESS)
        } else {
            reverie::canonical_auxv_value(aux.kind)
        };
        if let Some(new) = selected {
            result.push(Update {
                address,
                old: aux.value,
                new,
            });
        }
    }
    Ok((result, vdso))
}

fn canonical_mapping_bytes(image: &[u8]) -> Result<Vec<u8>> {
    if image.is_empty() {
        return Err("mapped_startup_shared_vdso_empty".into());
    }
    let mut mapping = vec![0; CANONICAL_VDSO_SIZE as usize];
    mapping
        .get_mut(..image.len())
        .ok_or("mapped_startup_shared_vdso_extent")?
        .copy_from_slice(image);
    Ok(mapping)
}

impl PreparedMapping<'_> {
    pub(super) async fn canonicalize_guest_startup(
        &mut self,
        coordinates: &BootstrapEntryCoordinates,
        deadline: Instant,
    ) -> Result<()> {
        self.entry_thread()?;
        let base = self.context.stack_start();
        let mut expected = self.context.stack_bytes().to_vec();
        let (plan, vdso) = updates(base, &expected, self.context.regs().rsp)?;
        let task = self.task.as_ref().ok_or("mapped_startup_missing_stop")?;
        self.check_entry_generation(task)?;
        if trace::read(task, base, expected.len())? != expected {
            return Err("mapped_startup_original_stack_changed".into());
        }
        // Bound native instructions through the actual retained RO descriptor.
        let mut descriptor = [0; 96];
        exact(task, self._inputs.layout_address, &mut descriptor)?;
        let layout = super::super::decode_target_layout(&descriptor)?;
        super::super::target_recipe(layout.gate)?;
        let native = layout
            .gate
            .checked_add(0x7c)
            .ok_or("mapped_startup_gate_overflow")?;
        let mut gate = [0; 9];
        exact(task, native, &mut gate)?;
        if gate != [0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x05, 0x41, 0xff, 0xe4] {
            return Err("mapped_startup_gate_bytes".into());
        }
        if vdso {
            let image = canonical_vdso_image();
            // The shared ELF file is shorter than its page-rounded mapping.
            // Match ptrace: copy exactly that file into a fresh zero-filled map.
            let expected_image = canonical_mapping_bytes(image)?;
            let mapped = self
                .startup_gate(
                    libc::SYS_mmap as u64,
                    [
                        CANONICAL_VDSO_ADDRESS,
                        CANONICAL_VDSO_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE)
                            as u64,
                        u64::MAX,
                        0,
                    ],
                    native,
                    coordinates.terminal_int3,
                    deadline,
                )
                .await?;
            if mapped != CANONICAL_VDSO_ADDRESS {
                return Err("mapped_startup_vdso_no_replace_return".into());
            }
            let task = self.task.as_mut().ok_or("mapped_startup_missing_stop")?;
            trace::write(task, mapped, image)?;
            if trace::read(task, mapped, expected_image.len())? != expected_image {
                return Err("mapped_startup_vdso_bytes".into());
            }
            if self
                .startup_gate(
                    libc::SYS_mprotect as u64,
                    [
                        mapped,
                        CANONICAL_VDSO_SIZE,
                        (libc::PROT_READ | libc::PROT_EXEC) as u64,
                        0,
                        0,
                        0,
                    ],
                    native,
                    coordinates.terminal_int3,
                    deadline,
                )
                .await?
                != 0
            {
                return Err("mapped_startup_vdso_protection_return".into());
            }
        }
        let task = self.task.as_mut().ok_or("mapped_startup_missing_stop")?;
        for update in plan {
            let mut old = [0; 8];
            exact(task, update.address, &mut old)?;
            if u64::from_le_bytes(old) != update.old {
                return Err("mapped_startup_auxv_value_changed".into());
            }
            let offset = usize::try_from(
                update
                    .address
                    .checked_sub(base)
                    .ok_or("mapped_startup_auxv_slot")?,
            )?;
            let end = offset.checked_add(8).ok_or("mapped_startup_auxv_slot")?;
            expected
                .get_mut(offset..end)
                .ok_or("mapped_startup_auxv_slot")?
                .copy_from_slice(&update.new.to_le_bytes());
            trace::write(task, update.address, &update.new.to_le_bytes())?;
        }
        if trace::read(task, base, expected.len())? != expected {
            return Err("mapped_startup_stack_readback".into());
        }
        // Restore only actual regs/xstate/mask. The deliberate value-word
        // updates survive; no historical stack or AT_RANDOM bytes are copied back.
        self.context
            .restore_after_initializer(task, self.context.signal_mask())?;
        Ok(())
    }

    // Two closed native call sites above, before runtime entry. No Guest code,
    // replay of uncertain calls, alternate task or temporary wait owner.
    async fn startup_gate(
        &mut self,
        nr: u64,
        args: [u64; 6],
        native: u64,
        int3: u64,
        deadline: Instant,
    ) -> Result<u64> {
        self.entry_thread()?;
        let task = self.task.as_ref().ok_or("mapped_startup_missing_stop")?;
        self.check_entry_generation(task)?;
        let mut regs = *self.context.regs();
        regs.rip = native;
        regs.r12 = int3;
        regs.rax = nr;
        regs.orig_rax = u64::MAX;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        task.setregs(&regs)?;
        if super::super::super::register_words(&task.getregs()?)
            != super::super::super::register_words(&regs)
        {
            return Err("mapped_startup_gate_launch_readback".into());
        }
        self.resume_entry(None, deadline)?;
        self.handover_wait_next(deadline).await?;
        let task = self.task.as_ref().ok_or("mapped_startup_gate_exited")?;
        self.check_entry_generation(task)?;
        let actual = task.getregs()?;
        if !matches!(self.entry.event, Some(Event::Signal(Signal::SIGTRAP)))
            || !terminal(&task.getsiginfo_bytes()?, actual.rip, int3)
            || actual.rsp != self.context.regs().rsp
            || actual.fs_base != self.context.regs().fs_base
            || actual.gs_base != self.context.regs().gs_base
            || task.getsigmask()? != self.context.signal_mask()
            || task.getxstate()? != *self.context.xstate()
        {
            return Err("mapped_startup_gate_return_state".into());
        }
        if actual.rax >= (-4095_i64) as u64 {
            return Err(format!(
                "mapped_startup_native_errno nr={nr} result={:#x}",
                actual.rax
            )
            .into());
        }
        Ok(actual.rax)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stack(aux: &[(u64, u64)]) -> Vec<u8> {
        // argc0, argvNULL, envNULL, then genuine aux words and terminal pair.
        let mut words = vec![0_u64, 0, 0];
        for &(k, v) in aux {
            words.extend([k, v]);
        }
        words.extend([0, 0]);
        words.into_iter().flat_map(u64::to_le_bytes).collect()
    }
    #[test]
    fn actual_shared_vdso_file_has_exact_bytes_and_zero_filled_mapping_tail() {
        let image = canonical_vdso_image();
        let mapping = canonical_mapping_bytes(image).unwrap();
        assert_eq!(mapping.len() as u64, CANONICAL_VDSO_SIZE);
        assert_eq!(&mapping[..image.len()], image);
        assert!(mapping[image.len()..].iter().all(|byte| *byte == 0));
        assert!(canonical_mapping_bytes(&[]).is_err());
        assert!(canonical_mapping_bytes(&vec![0; CANONICAL_VDSO_SIZE as usize + 1]).is_err());
    }

    #[test]
    fn shared_values_and_only_original_value_slots_are_selected() {
        let original = stack(&[
            (libc::AT_RANDOM, 0x2222),
            (reverie::AT_RSEQ_FEATURE_SIZE, 33),
            (libc::AT_HWCAP, u64::MAX),
            (libc::AT_HWCAP2, 2),
            (reverie::AT_RSEQ_ALIGN, 64),
            (reverie::AT_MINSIGSTKSZ, 11952),
            (libc::AT_SYSINFO_EHDR, 0x9000),
            (libc::AT_ENTRY, 0x1234),
        ]);
        let (plan, vdso) = updates(0x1000, &original, 0x1000).unwrap();
        assert!(vdso);
        assert_eq!(plan.len(), 6);
        let mut changed = original.clone();
        for update in plan {
            let offset = (update.address - 0x1000) as usize;
            assert_eq!(
                u64::from_le_bytes(original[offset..offset + 8].try_into().unwrap()),
                update.old
            );
            let kind = u64::from_le_bytes(original[offset - 8..offset].try_into().unwrap());
            assert_eq!(
                update.new,
                if kind == libc::AT_SYSINFO_EHDR {
                    CANONICAL_VDSO_ADDRESS
                } else {
                    reverie::canonical_auxv_value(kind).unwrap()
                }
            );
            changed[offset..offset + 8].copy_from_slice(&update.new.to_le_bytes());
        }
        let parsed = ParsedInitial::parse(0x1000, &changed, 0x1000).unwrap();
        assert_eq!(parsed.original_aux()[0].value, 0x2222);
        assert_eq!(parsed.original_aux().last().unwrap().value, 0x1234);
        assert_eq!(parsed.original_aux()[1].value, 28);
    }
    #[test]
    fn absent_sysinfo_stays_absent_and_unknown_aux_is_not_rewritten() {
        let (plan, vdso) = updates(0x1000, &stack(&[(0x9999, 7)]), 0x1000).unwrap();
        assert!(!vdso);
        assert!(plan.is_empty());
    }
    #[test]
    fn oversized_host_frame_is_refused_before_any_mutation() {
        assert!(updates(0x1000, &stack(&[(reverie::AT_MINSIGSTKSZ, 16385)]), 0x1000).is_err());
    }
    #[test]
    fn duplicate_truncated_and_overflowed_original_vectors_refuse() {
        assert!(
            updates(
                0x1000,
                &stack(&[(libc::AT_HWCAP, 1), (libc::AT_HWCAP, 2)]),
                0x1000
            )
            .is_err()
        );
        let mut bytes = stack(&[(libc::AT_HWCAP, 1)]);
        bytes.truncate(bytes.len() - 1);
        assert!(updates(0x1000, &bytes, 0x1000).is_err());
        assert!(updates(u64::MAX - 7, &stack(&[]), u64::MAX - 7).is_err());
    }
}
