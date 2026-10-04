/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Real KVM controls for generation-bound host-backing publication. These keep
/// the existing identity placement and slot 0; they do not activate guest mmap
/// or claim virtual-address parity.
pub(crate) mod memory_publication_tests {
    use super::*;

    const HOST_PAGE_SIZE: usize = 4096;

    fn close_mapping(gate: &Arc<crate::entry::EntryGate>) -> crate::entry::Closed {
        futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap()
    }

    fn run_load(backend: &mut KvmBackend, port: u16, expected: u8) {
        match backend.vcpu.run().unwrap().expect("vCPU entered KVM") {
            VcpuExit::IoOut(actual_port, bytes) => {
                assert_eq!(actual_port, port);
                assert_eq!(bytes, &[expected]);
            }
            exit => panic!("expected byte IO exit, got {exit:?}"),
        }
    }

    #[test]
    fn closed_page_publication_invalidates_populated_translations_in_two_vms() {
        const ENTRY: u64 = 0x1000;
        const DATA: u64 = 0x2000;
        let memory = GuestMemory::new(0, 4 * HOST_PAGE_SIZE).unwrap();
        memory.write_raw(DATA, &[0x11]).unwrap();

        // mov bx,DATA; load/out three times; hlt
        let [data_low, data_high] = (DATA as u16).to_le_bytes();
        let program = [
            0xbb, data_low, data_high, 0x8a, 0x07, 0xe6, 0x80, 0x8a, 0x07, 0xe6, 0x81, 0x8a, 0x07,
            0xe6, 0x82, HLT,
        ];
        let mut first = KvmBackend::new_with_memory_and_cpuid_policy(
            memory.clone(),
            CpuidPolicy::default(),
            None,
        )
        .expect("first VM requires /dev/kvm");
        let mut second = KvmBackend::new_with_memory_and_cpuid_policy(
            memory.clone(),
            CpuidPolicy::default(),
            None,
        )
        .expect("second VM requires /dev/kvm");
        first.install_real_mode_program(ENTRY, &program).unwrap();
        second.install_real_mode_program(ENTRY, &program).unwrap();

        // Both distinct VMs first populate a translation to the original slot-0
        // HVA page. Recreating either VM after publication would not test KVM's
        // mmap/MMU-notifier invalidation contract.
        run_load(&mut first, 0x80, 0x11);
        run_load(&mut second, 0x80, 0x11);

        let mut replacement = vec![0; HOST_PAGE_SIZE];
        replacement[0] = 0x22;
        let pending = memory.stage_backing_page(DATA, &replacement).unwrap();
        let gate = memory.entry_gate();
        let before = gate.test_state();
        assert_eq!(before.generation.get(), 0);
        assert_eq!(before.members.len(), 2);
        assert!(
            before
                .members
                .iter()
                .all(|member| member.generation == Some(before.generation))
        );
        let mut closed = close_mapping(&gate);
        let generation = pending.publish(&mut closed).unwrap();
        assert_eq!(generation.get(), 1);
        let published = gate.test_state();
        assert!(published.closed);
        assert_eq!(published.generation, generation);
        assert_eq!(published.retained_operands, 0);
        assert_eq!(memory.separately_backed_pages(), 1);
        drop(closed);

        // Neither VM is reconstructed. Both must observe the new marker through
        // the translations they populated before the MAP_FIXED replacement.
        run_load(&mut first, 0x81, 0x22);
        run_load(&mut second, 0x81, 0x22);
        let after = gate.test_state();
        assert!(after.open);
        assert_eq!(after.generation, generation);
        assert!(
            after
                .members
                .iter()
                .all(|member| member.generation == Some(generation) && member.run == 2)
        );
        let mut byte = [0];
        memory.read_raw(DATA, &mut byte).unwrap();
        assert_eq!(byte, [0x22]);

        // Replacing an already split-out page must retain the new backing, retire
        // the prior backing, and invalidate both populated translations again.
        replacement[0] = 0x44;
        let pending = memory.stage_backing_page(DATA, &replacement).unwrap();
        let mut closed = close_mapping(&gate);
        let generation = pending.publish(&mut closed).unwrap();
        assert_eq!(generation.get(), 2);
        assert_eq!(memory.separately_backed_pages(), 1);
        drop(closed);
        run_load(&mut first, 0x82, 0x44);
        run_load(&mut second, 0x82, 0x44);
        memory.read_raw(DATA, &mut byte).unwrap();
        assert_eq!(byte, [0x44]);

        // A private snapshot copies the installed HVA bytes into its own original
        // backing and starts a new generation history; it must not retain metadata
        // for page views that were never installed in the snapshot HVA.
        let snapshot = memory.snapshot().unwrap();
        assert_eq!(snapshot.backing_generation().get(), 0);
        assert_eq!(snapshot.separately_backed_pages(), 0);
        snapshot.read_raw(DATA, &mut byte).unwrap();
        assert_eq!(byte, [0x44]);
        snapshot.write_raw(DATA, &[0x33]).unwrap();
        memory.read_raw(DATA, &mut byte).unwrap();
        assert_eq!(byte, [0x44]);
    }

    #[test]
    fn retained_host_operand_refuses_publication_before_mapping_changes() {
        let memory = GuestMemory::new(0, 2 * HOST_PAGE_SIZE).unwrap();
        memory
            .map_user_range(0, HOST_PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        memory.write_raw(0, &[0x41]).unwrap();
        let operand = memory.user().host_operand(0, 1).unwrap();
        let gate = memory.entry_gate();
        assert_eq!(gate.test_state().retained_operands, 1);

        let mut replacement = vec![0; HOST_PAGE_SIZE];
        replacement[0] = 0x99;
        let pending = memory.stage_backing_page(0, &replacement).unwrap();
        let mut closed = close_mapping(&gate);
        assert_eq!(gate.test_state().copies, 0);
        let error = pending.publish(&mut closed).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("mapping publication has retained host operands"),
            "unexpected error: {error}"
        );
        let refused = gate.test_state();
        assert!(refused.closed);
        assert_eq!(refused.generation.get(), 0);
        assert_eq!(memory.separately_backed_pages(), 0);
        // SAFETY: no VM or other host thread can write this control byte. Refusal
        // happened before MAP_FIXED, and the helper uses the retained view's exact
        // mmap pointer rather than reconstructing one from its numeric address.
        assert_eq!(unsafe { operand.read_volatile::<u8>() }, 0x41);
        drop(operand);
        assert_eq!(gate.test_state().retained_operands, 0);
        drop(closed);
        assert!(memory.read_raw(0, &mut [0]).is_err());
    }

    #[test]
    fn unrelated_close_token_refuses_publication_without_poisoning_either_mapping() {
        let first = GuestMemory::new(0, 2 * HOST_PAGE_SIZE).unwrap();
        let second = GuestMemory::new(0, 2 * HOST_PAGE_SIZE).unwrap();
        first.write_raw(0, &[0x51]).unwrap();
        let mut replacement = vec![0; HOST_PAGE_SIZE];
        replacement[0] = 0x61;
        let pending = first.stage_backing_page(0, &replacement).unwrap();
        let first_gate = first.entry_gate();
        let second_gate = second.entry_gate();
        let mut unrelated = close_mapping(&second_gate);
        assert!(matches!(
            pending.publish(&mut unrelated),
            Err(Error::MappingPublicationGateMismatch)
        ));
        assert!(first_gate.pending_failure().is_none());
        assert!(second_gate.pending_failure().is_none());
        assert_eq!(first.backing_generation().get(), 0);
        assert_eq!(second.backing_generation().get(), 0);
        assert_eq!(first.separately_backed_pages(), 0);
        let mut byte = [0];
        first.read_raw(0, &mut byte).unwrap();
        assert_eq!(byte, [0x51]);
        drop(unrelated);
        assert!(second.read_raw(0, &mut byte).is_ok());
    }

    #[test]
    fn host_access_splits_at_installed_page_boundaries() {
        let memory = GuestMemory::new(0, 3 * HOST_PAGE_SIZE).unwrap();
        memory
            .map_user_range(0, (3 * HOST_PAGE_SIZE) as u64, false)
            .unwrap();
        memory.enable_user_access();
        let stable_hva = memory.host_address();
        let replacement = vec![0x22; HOST_PAGE_SIZE];
        let pending = memory
            .stage_backing_page(HOST_PAGE_SIZE as u64, &replacement)
            .unwrap();
        let gate = memory.entry_gate();
        let mut closed = close_mapping(&gate);
        pending.publish(&mut closed).unwrap();
        drop(closed);
        assert_eq!(memory.host_address(), stable_hva);

        let address = (HOST_PAGE_SIZE - 1) as u64;
        let source = (0..HOST_PAGE_SIZE + 2)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        assert_eq!(
            memory.user().copy_to_user_prefix(address, &source).unwrap(),
            source.len()
        );
        let mut actual = vec![0; source.len()];
        memory.user().read(address, &mut actual).unwrap();
        assert_eq!(actual, source);

        memory.zero_raw(address, source.len()).unwrap();
        memory.read_raw(address, &mut actual).unwrap();
        assert_eq!(actual, vec![0; source.len()]);

        memory
            .write_raw(HOST_PAGE_SIZE as u64, &replacement)
            .unwrap();
        memory
            .discard_pages(HOST_PAGE_SIZE as u64, HOST_PAGE_SIZE)
            .unwrap();
        let mut discarded = vec![0xff; HOST_PAGE_SIZE];
        memory
            .read_raw(HOST_PAGE_SIZE as u64, &mut discarded)
            .unwrap();
        assert_eq!(discarded, vec![0; HOST_PAGE_SIZE]);
    }

    #[test]
    fn abandoned_stage_and_unchanged_close_preserve_generation_and_bytes() {
        let memory = GuestMemory::new(0, 2 * HOST_PAGE_SIZE).unwrap();
        memory.write_raw(0, &[0x51]).unwrap();
        let mut replacement = vec![0; HOST_PAGE_SIZE];
        replacement[0] = 0x61;
        drop(memory.stage_backing_page(0, &replacement).unwrap());

        let gate = memory.entry_gate();
        let generation = gate.test_state().generation;
        drop(close_mapping(&gate));
        assert_eq!(gate.test_state().generation, generation);
        assert_eq!(memory.separately_backed_pages(), 0);
        let mut byte = [0];
        memory.read_raw(0, &mut byte).unwrap();
        assert_eq!(byte, [0x51]);
    }
}
