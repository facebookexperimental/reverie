/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Exercise the actual constructor shared by both CLONE_THREAD execution paths.
// This does not claim that a guest clone syscall or a Tool callback was run.
mod entry_construction_tests {
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);
    const CHILD_TID: i32 = 72;

    struct Constructor {
        closed: Option<crate::entry::Closed>,
        worker: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for Constructor {
        fn drop(&mut self) {
            // The full constructor needs gated memory. Never wait for its host
            // thread while retaining the token that prevents its first copy.
            drop(self.closed.take());
            if let Some(worker) = self.worker.take() {
                let result = worker.join();
                if !std::thread::panicking() {
                    result.unwrap();
                }
            }
        }
    }

    struct Constructed {
        parent: KvmBackend,
        child: KvmBackend,
        gate: Arc<crate::entry::EntryGate>,
        parent_member: crate::entry::TestMemberState,
        child_id: u64,
        data: u64,
        owners: Box<dyn Fn() -> usize + Send + Sync>,
    }

    fn construct_while_closed() -> Constructed {
        let mut parent = KvmBackend::new(16 * 1024 * 1024)
            .expect("thread construction control requires actual /dev/kvm");
        // inc byte [rsp-8]; mov eax,SYS_getpid; syscall; ud2.
        // A real return-park Hlt will stop before the deliberately invalid tail.
        let mut code = vec![0xfe, 0x44, 0x24, 0xf8, 0xb8];
        code.extend_from_slice(&(libc::SYS_getpid as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        parent
            .install_static_elf(&minimal_test_elf(&code), "/bin/entry-construction")
            .unwrap();
        let registers = parent.vcpu.get_regs().unwrap();
        let data = registers.rsp - 8;
        parent.memory.write_raw(data, &[0]).unwrap();
        let xsave = parent.vcpu.get_xsave().unwrap();
        let cpuid = parent.cpuid_policy;
        let group = parent.thread_group.clone();
        let gate = parent.memory.entry_gate();
        let owners = Box::new(parent.memory.test_mapping_owners());
        assert_eq!(owners(), 2, "backend and CountedVcpu own the same Mapping");
        let before = gate.test_state();
        assert!(before.open);
        assert_eq!(before.members.len(), 1);
        let parent_member = before.members[0].clone();
        assert!(parent_member.stopped);
        assert_eq!(parent_member.run, 0);
        let closed = gate
            .try_close()
            .unwrap()
            .unwrap()
            .finish()
            .now_or_never()
            .expect("stopped parent must close without executing it")
            .unwrap();
        let memory = parent.memory.clone();
        let (send, receive) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = KvmBackend::from_thread_state(
                memory, registers, xsave, None, cpuid, CHILD_TID, group,
            );
            let _ = send.send(result);
        });
        let host_thread = worker.thread().id();
        let mut constructor = Constructor {
            closed: Some(closed),
            worker: Some(worker),
        };
        let deadline = Instant::now() + WAIT;
        let blocked = loop {
            let state = gate.test_state();
            if state.copy_waiters.contains(&host_thread) {
                break state;
            }
            assert!(
                Instant::now() < deadline,
                "actual constructor did not reach copy admission"
            );
            std::thread::yield_now();
        };
        assert!(blocked.closed);
        assert!(!blocked.open);
        assert_eq!(blocked.copies, 0);
        assert_eq!(blocked.copy_waiters, vec![host_thread]);
        assert!(blocked.copy_waits >= 1);
        assert_eq!(blocked.members.len(), 2);
        assert_eq!(blocked.members[0], parent_member);
        let child_member = &blocked.members[1];
        let child_id = child_member.id;
        assert!(child_id > parent_member.id);
        assert_eq!(child_member.run, 0);
        assert!(child_member.stopped);
        assert_eq!(owners(), 4, "both actual vCPUs retain the shared Mapping");
        assert!(matches!(receive.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(gate.pending_failure().is_none());

        // Registration was observed through the same mutex that the actual
        // first gated constructor copy released in Condvar::wait. Reopen before
        // asking for completion; no constructor latency claim is involved.
        drop(constructor.closed.take());
        let child = receive.recv_timeout(WAIT).unwrap().unwrap();
        constructor.worker.take().unwrap().join().unwrap();
        let after = gate.test_state();
        assert!(after.open);
        assert_eq!(after.members, blocked.members);
        assert!(after.copy_waiters.is_empty());
        assert_eq!(after.copies, 0);
        assert!(child.is_guest_thread);
        assert!(child.thread_slot.is_some());
        assert!(Arc::ptr_eq(&child.memory.entry_gate(), &gate));
        assert_eq!(child.memory.host_address(), parent.memory.host_address());
        assert_eq!(owners(), 4);
        Constructed {
            parent,
            child,
            gate,
            parent_member,
            child_id,
            data,
            owners,
        }
    }

    fn assert_parent_only(
        gate: &crate::entry::EntryGate,
        parent: &crate::entry::TestMemberState,
        owners: &dyn Fn() -> usize,
    ) {
        let state = gate.test_state();
        assert_eq!(state.members, vec![parent.clone()]);
        assert_eq!(state.copies, 0);
        assert!(state.copy_waiters.is_empty());
        assert!(gate.pending_failure().is_none());
        assert_eq!(
            owners(),
            2,
            "retired child must release both Mapping owners"
        );
    }

    #[test]
    fn thread_constructor_registers_while_closed_then_enters_and_retires() {
        for tracked in [false, true] {
            let Constructed {
                parent,
                mut child,
                gate,
                parent_member,
                child_id,
                data,
                owners,
            } = construct_while_closed();
            let probe = Arc::new(crate::clock::RunProbe::default());
            child.vcpu.set_run_probe(probe.clone());
            if tracked {
                child.vcpu.track_clock().unwrap();
            }
            assert_eq!(
                try_set_syscall_return_park(
                    &mut child.memory,
                    child.hypercall_instruction,
                    child.syscall_trampoline_address,
                    child.syscall_frame_address,
                    true,
                )
                .unwrap(),
                Some(())
            );
            let expected_halt = syscall_hypercall_address(
                child.hypercall_instruction,
                child.syscall_trampoline_address,
                child.syscall_frame_address,
            ) + child.hypercall_instruction.len() as u64
                + 1;
            probe.arm();
            let request = match child.vcpu.run().unwrap().expect("reopened constructor") {
                VcpuExit::Hypercall(exit) => {
                    assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                    assert_eq!(exit.args[0], child.syscall_frame_address);
                    let request = SyscallRequest::read_from(&child.memory, exit.args[0]).unwrap();
                    *exit.ret = 37;
                    request
                }
                exit => panic!("expected actual getpid hypercall, got {exit:?}"),
            };
            assert_eq!(request.number(), libc::SYS_getpid as u64);
            assert!(matches!(child.vcpu.run().unwrap(), Some(VcpuExit::Hlt)));
            let load = |counter: &std::sync::atomic::AtomicUsize| counter.load(Ordering::SeqCst);
            assert_eq!(load(&probe.untracked_runs), if tracked { 0 } else { 2 });
            assert_eq!(load(&probe.tracked_runs), if tracked { 2 } else { 0 });
            assert_eq!(load(&probe.prepare.mask_installs), 2);
            assert_eq!(load(&probe.clock_begins), if tracked { 2 } else { 0 });
            assert_eq!(load(&probe.intervals_created), if tracked { 2 } else { 0 });
            let registers = child.vcpu.get_regs().unwrap();
            assert_eq!(
                registers.rip, expected_halt,
                "Hlt must be the real return park"
            );
            assert_eq!(
                registers.rax, 37,
                "the private response was consumed exactly"
            );
            let mut byte = [0xff];
            parent.memory.read_raw(data, &mut byte).unwrap();
            assert_eq!(byte, [1], "the finite guest effect executed once");
            let stopped = gate.test_state();
            assert_eq!(stopped.members[1].id, child_id);
            assert_eq!(stopped.members[1].run, 2);
            assert!(stopped.members[1].stopped);
            let closed = gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .unwrap()
                .unwrap();
            drop(child);
            assert_parent_only(&gate, &parent_member, owners.as_ref());
            assert!(gate.test_state().closed);
            drop(closed);

            // An ordinary fresh constructor receives a new participant identity
            // and can retire unentered without reusing the old stopped target.
            let fresh = KvmBackend::from_thread_state(
                parent.memory.clone(),
                parent.vcpu.get_regs().unwrap(),
                parent.vcpu.get_xsave().unwrap(),
                None,
                parent.cpuid_policy,
                CHILD_TID + 1,
                parent.thread_group.clone(),
            )
            .unwrap();
            let state = gate.test_state();
            assert_eq!(state.members[1].id, child_id + 1);
            assert_eq!(state.members[1].run, 0);
            assert!(state.members[1].stopped);
            drop(fresh);
            assert_parent_only(&gate, &parent_member, owners.as_ref());
            drop(parent);
            assert!(gate.test_state().members.is_empty());
            assert_eq!(owners(), 0, "no stopped backend retains the Mapping");
        }
    }

    fn unentered_retirement(refuse_spawn: bool) {
        let Constructed {
            parent,
            child,
            gate,
            parent_member,
            child_id,
            data,
            owners,
        } = construct_while_closed();
        let closed = gate
            .try_close()
            .unwrap()
            .unwrap()
            .finish()
            .now_or_never()
            .unwrap()
            .unwrap();
        let child = if refuse_spawn {
            let probe = Arc::new(crate::failure::spawn_refusal::Probe::default());
            let refusal = crate::failure::spawn_refusal::Guard::arm(probe.clone());
            let result = crate::failure::spawn_owned::<_, (), _>(
                std::thread::Builder::new(),
                child,
                |_child| panic!("refused OS spawn must never enter its child closure"),
            );
            let (error, child) = match result {
                Err(refused) => refused,
                Ok(worker) => {
                    let _ = worker.join();
                    panic!("actual OS thread creation did not refuse");
                }
            };
            assert_eq!(probe.consumed(), 1);
            assert_eq!(
                probe.error().unwrap(),
                crate::failure::spawn_refusal::ObservedError::read(&error)
            );
            drop(refusal);
            child
        } else {
            child
        };
        let state = gate.test_state();
        assert!(state.closed);
        assert_eq!(state.members[1].id, child_id);
        assert_eq!(state.members[1].run, 0);
        assert!(state.members[1].stopped);
        assert_eq!(
            owners(),
            4,
            "refusal preserves the actual unentered child owner"
        );
        drop(child);
        assert_parent_only(&gate, &parent_member, owners.as_ref());
        assert!(gate.test_state().closed);
        drop(closed);
        let mut byte = [0xff];
        parent.memory.read_raw(data, &mut byte).unwrap();
        assert_eq!(
            byte,
            [0],
            "never-started guest must have no instruction effect"
        );
        drop(parent);
        assert!(gate.test_state().members.is_empty());
        assert_eq!(owners(), 0);
    }

    #[test]
    fn never_entered_thread_constructor_retires_while_closed() {
        unentered_retirement(false);
    }

    #[test]
    fn refused_real_thread_spawn_preserves_then_retires_unentered_participant() {
        unentered_retirement(true);
    }
}
