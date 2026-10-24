/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Real KVM controls for reusing a syscall exit's first copy as its completed
/// boundary's copy: reuse only while the gate admits at the generation the
/// exit read saw, with every other check of a fresh capture unchanged.
pub(crate) mod exit_read_reuse_tests {
    use std::task::Context;
    use std::task::Poll;

    use super::*;

    struct Fixture {
        backend: KvmBackend,
        frame_address: u64,
        hypercall_address: u64,
        registers: kvm_regs,
    }

    fn fixture() -> Fixture {
        let backend = KvmBackend::new(0x10000).expect("this control requires /dev/kvm");
        let frame_address = backend.syscall_frame_address;
        backend
            .memory
            .write_raw(frame_address, &[0xa5; FRAME_SIZE])
            .unwrap();
        let hypercall_address = syscall_hypercall_address(
            backend.hypercall_instruction,
            backend.syscall_trampoline_address,
            frame_address,
        );
        backend
            .memory
            .write_raw(hypercall_address, &backend.hypercall_instruction)
            .unwrap();
        let mut registers = backend.vcpu.get_regs().unwrap();
        registers.rip = hypercall_address;
        registers.rax = 0x1234;
        backend.vcpu.set_regs(&registers).unwrap();
        Fixture {
            backend,
            frame_address,
            hypercall_address,
            registers,
        }
    }

    fn admissions(backend: &KvmBackend) -> usize {
        backend.memory.entry_gate().test_state().copy_admissions
    }

    fn fresh(backend: &KvmBackend, frame_address: u64) -> CompletedSyscallBoundary {
        CompletedSyscallBoundary::capture(backend, frame_address, None).unwrap()
    }

    fn assert_same(actual: &CompletedSyscallBoundary, expected: &CompletedSyscallBoundary) {
        assert_eq!(actual.frame_address, expected.frame_address);
        assert_eq!(actual.frame, expected.frame);
        assert_eq!(actual.registers, expected.registers);
        assert_eq!(
            format!("{:?}", actual.special_registers),
            format!("{:?}", expected.special_registers)
        );
        assert_eq!(actual.action_return_registers, expected.action_return_registers);
        assert_eq!(actual.stage_action_outcome, expected.stage_action_outcome);
    }

    fn capture_reusing(
        backend: &mut KvmBackend,
        frame_address: u64,
        exit: Option<(&SyscallExitRead, &GuestMemory)>,
    ) -> Result<Option<CompletedSyscallBoundary>> {
        let mut pending = std::pin::pin!(std::future::pending());
        futures::executor::block_on(CompletedSyscallBoundary::capture_admitted_reusing(
            backend,
            frame_address,
            None,
            pending.as_mut(),
            exit,
        ))
    }

    #[test]
    fn exit_read_decodes_the_request_and_reuse_matches_a_fresh_capture_without_a_copy() {
        let Fixture {
            mut backend,
            frame_address,
            ..
        } = fixture();
        let memory = backend.memory.clone();
        let before = admissions(&backend);
        let (request, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        assert_eq!(admissions(&backend), before + 1, "frame and hypercall: one copy");
        assert_eq!(
            request,
            SyscallRequest::read_from(&memory, frame_address).unwrap()
        );
        assert!(exit.hypercall.is_some());
        let expected = fresh(&backend, frame_address);

        let before = admissions(&backend);
        let actual = capture_reusing(&mut backend, frame_address, Some((&exit, &memory)))
            .unwrap()
            .unwrap();
        assert_eq!(admissions(&backend), before, "reuse admitted a copy");
        assert_same(&actual, &expected);

        // Control: without an exit read the same capture copies once.
        let control = capture_reusing(&mut backend, frame_address, None)
            .unwrap()
            .unwrap();
        assert_eq!(admissions(&backend), before + 1);
        assert_same(&control, &expected);
    }

    #[test]
    fn reuse_is_refused_after_a_publication_and_the_capture_copies_the_new_bytes() {
        let Fixture {
            mut backend,
            frame_address,
            ..
        } = fixture();
        let memory = backend.memory.clone();
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        // A publication between the exit read and the capture, then new
        // frame bytes in the published image.
        let gate = backend.memory.entry_gate();
        let mut closed =
            futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        closed
            .publish(None, exit.generation, |next| {
                Ok(crate::memory::InstalledMapping::gate_control(next))
            })
            .unwrap();
        drop(closed);
        backend
            .memory
            .write_raw(frame_address, &[0x5a; FRAME_SIZE])
            .unwrap();

        let before = admissions(&backend);
        let actual = capture_reusing(&mut backend, frame_address, Some((&exit, &memory)))
            .unwrap()
            .unwrap();
        assert_eq!(admissions(&backend), before + 1, "a stale exit read was reused");
        assert_eq!(actual.frame, [0x5a; FRAME_SIZE]);
        assert_same(&actual, &fresh(&backend, frame_address));
    }

    #[test]
    fn reuse_needs_this_gate_this_frame_and_a_completed_attempt() {
        let Fixture {
            mut backend,
            frame_address,
            hypercall_address,
            ..
        } = fixture();
        let memory = backend.memory.clone();
        let expected = fresh(&backend, frame_address);
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();

        // The attempted hypercall read failed.
        let failed_attempt = SyscallExitRead {
            hypercall: None,
            ..exit_copy(&exit)
        };
        // Read through another mapping (another entry gate), even with the
        // same bytes and generation.
        let other = GuestMemory::new(0, memory.len()).unwrap();
        // A different frame or hypercall address than this capture reads.
        let other_frame = SyscallExitRead {
            frame_address: frame_address + 8,
            ..exit_copy(&exit)
        };
        let other_hypercall = SyscallExitRead {
            hypercall_address: hypercall_address + 1,
            ..exit_copy(&exit)
        };
        for (exit, memory) in [
            (&failed_attempt, &memory),
            (&exit, &other),
            (&other_frame, &memory),
            (&other_hypercall, &memory),
        ] {
            let before = admissions(&backend);
            let actual = capture_reusing(&mut backend, frame_address, Some((exit, memory)))
                .unwrap()
                .unwrap();
            assert_eq!(admissions(&backend), before + 1, "reused an ineligible read");
            assert_same(&actual, &expected);
        }
    }

    fn exit_copy(exit: &SyscallExitRead) -> SyscallExitRead {
        SyscallExitRead {
            frame_address: exit.frame_address,
            frame: exit.frame,
            hypercall_address: exit.hypercall_address,
            hypercall: exit.hypercall,
            generation: exit.generation,
        }
    }

    #[test]
    fn reuse_keeps_the_failure_stop_cancellation_and_boundary_checks() {
        // A gate failure recorded after the exit read is reported exactly as a
        // fresh capture reports it, and nothing is admitted.
        {
            let Fixture {
                mut backend,
                frame_address,
                ..
            } = fixture();
            let memory = backend.memory.clone();
            let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
            let original = Arc::new(Error::UnexpectedVcpuExit("controlled reuse poison".to_owned()));
            backend
                .memory
                .entry_gate()
                .poison(None, Error::SharedFailure(original.clone()));
            let before = admissions(&backend);
            let error = capture_reusing(&mut backend, frame_address, Some((&exit, &memory)))
                .map(drop)
                .unwrap_err();
            assert!(error.retains_primary(&original), "{error:?}");
            let control = capture_reusing(&mut backend, frame_address, None)
                .map(drop)
                .unwrap_err();
            assert_eq!(format!("{error:?}"), format!("{control:?}"));
            assert_eq!(admissions(&backend), before);
        }
        // A stop that already fired, and a requested group exit, end the
        // capture as before, without using the bytes.
        for event in ["stop", "cancellation"] {
            let Fixture {
                mut backend,
                frame_address,
                registers,
                ..
            } = fixture();
            let memory = backend.memory.clone();
            let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
            if event == "cancellation" {
                backend
                    .thread_group
                    .request_exit_group(ExitStatus::Exited(7));
            }
            let mut stop = std::pin::pin!(async {});
            let mut pending = std::pin::pin!(std::future::pending());
            let stop: Pin<&mut (dyn Future<Output = ()> + Send)> = if event == "stop" {
                stop.as_mut()
            } else {
                pending.as_mut()
            };
            let before = admissions(&backend);
            let result = futures::executor::block_on(
                CompletedSyscallBoundary::capture_admitted_reusing(
                    &mut backend,
                    frame_address,
                    None,
                    stop,
                    Some((&exit, &memory)),
                ),
            );
            match (event, result) {
                ("stop", Err(Error::RunAborted)) | ("cancellation", Ok(None)) => {}
                (event, result) => panic!("{event}: {:?}", result.map(|value| value.is_some())),
            }
            assert_eq!(admissions(&backend), before);
            assert_eq!(backend.vcpu.get_regs().unwrap(), registers);
        }
        // The boundary's own checks still run on reused bytes: a RIP that is
        // neither the hypercall nor its return, and a hypercall instruction
        // that does not match (as read at the exit).
        let Fixture {
            mut backend,
            frame_address,
            hypercall_address,
            registers,
        } = fixture();
        let memory = backend.memory.clone();
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        let mut invalid = registers;
        invalid.rip = hypercall_address + 1;
        backend.vcpu.set_regs(&invalid).unwrap();
        assert!(matches!(
            capture_reusing(&mut backend, frame_address, Some((&exit, &memory))),
            Err(Error::UnexpectedVcpuExit(_))
        ));
        backend.vcpu.set_regs(&registers).unwrap();
        backend
            .memory
            .write_raw(hypercall_address, &[0x90; 3])
            .unwrap();
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        assert_eq!(exit.hypercall, Some([0x90; 3]));
        let before = admissions(&backend);
        assert!(matches!(
            capture_reusing(&mut backend, frame_address, Some((&exit, &memory))),
            Err(Error::UnexpectedVcpuExit(_))
        ));
        assert_eq!(admissions(&backend), before);
    }

    /// A shared-file failure deferred behind an open notification scope is
    /// not yet a gate failure, so the gate's own check passes; the copy
    /// failures checked around an admitted copy must still refuse the reuse,
    /// with the same error a fresh capture reports.
    #[test]
    fn reuse_is_refused_by_a_deferred_copy_failure_as_a_fresh_capture_is() {
        let Fixture {
            mut backend,
            frame_address,
            ..
        } = fixture();
        let memory = backend.memory.clone();
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        let scope = memory.defer_notifications();
        let cause = memory.capture_shared_file_error(Error::SharedFileCopy {
            operation: "controlled deferred copy",
            address: frame_address,
            requested: 8,
            transferred: 0,
            prior_transferred: 0,
            source: std::io::Error::from_raw_os_error(libc::EIO),
        });
        assert!(backend.memory.entry_gate().pending_failure().is_none());
        assert!(
            backend
                .memory
                .entry_gate()
                .admit_operation_unchanged(exit.generation)
                .unwrap()
        );
        let before = admissions(&backend);
        let error = capture_reusing(&mut backend, frame_address, Some((&exit, &memory)))
            .map(drop)
            .unwrap_err();
        assert_eq!(admissions(&backend), before, "reuse admitted a copy");
        let control = capture_reusing(&mut backend, frame_address, None)
            .map(drop)
            .unwrap_err();
        assert_eq!(format!("{error:?}"), format!("{control:?}"));
        assert_eq!(format!("{error:?}"), format!("{cause:?}"));
        drop(scope);
    }

    /// A copy failure deferred while the reused bytes are being turned into
    /// a value, after the check that precedes them, still refuses the
    /// capture: the check after them must catch it, as a fresh capture's
    /// checks after its admitted copy catch one deferred during the copy.
    /// The capture returns the failure, so its caller returns before any
    /// Tool callback, and the error is the one a fresh capture returns.
    #[test]
    fn a_copy_failure_deferred_during_reuse_refuses_like_one_during_a_fresh_copy() {
        fn defer(memory: &GuestMemory) {
            let _ = memory.capture_shared_file_error(Error::SharedFileCopy {
                operation: "controlled deferred copy during capture",
                address: 0,
                requested: 8,
                transferred: 0,
                prior_transferred: 0,
                source: std::io::Error::from_raw_os_error(libc::EIO),
            });
        }
        let mut errors = Vec::new();
        for reuse in [true, false] {
            let Fixture {
                mut backend,
                frame_address,
                ..
            } = fixture();
            let memory = backend.memory.clone();
            let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
            let scope = memory.defer_notifications();
            let ran = std::sync::atomic::AtomicBool::new(false);
            let mut pending = std::pin::pin!(std::future::pending());
            let before = admissions(&backend);
            let result = futures::executor::block_on(backend.prepare_action_read_or_reuse(
                pending.as_mut(),
                reuse.then_some((exit.generation, |_: &KvmBackend| {
                        // After the check that precedes the reused bytes.
                        assert!(memory.check_copy_failures().is_ok());
                        defer(&memory);
                        ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(7_u32)
                    })),
                |_, _| {
                    defer(&memory);
                    ran.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(7_u32)
                },
            ));
            assert!(ran.load(std::sync::atomic::Ordering::SeqCst));
            assert_eq!(
                admissions(&backend),
                before + usize::from(!reuse),
                "reuse={reuse}"
            );
            let error = result.unwrap_err();
            assert!(
                matches!(error.primary(), Error::SharedFileCopy { .. }),
                "reuse={reuse}: {error:?}"
            );
            errors.push(format!("{error:?}"));
            drop(scope);
        }
        assert_eq!(errors[0], errors[1]);
    }

    /// A copy failure already deferred when the capture starts refuses it
    /// before the bytes are used, as a fresh capture refuses before its copy
    /// runs: neither the reused closure nor the capturing one is called.
    #[test]
    fn a_copy_failure_deferred_before_reuse_refuses_before_the_bytes_are_used() {
        let mut errors = Vec::new();
        for reuse in [true, false] {
            let Fixture {
                mut backend,
                frame_address,
                ..
            } = fixture();
            let memory = backend.memory.clone();
            let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
            let scope = memory.defer_notifications();
            let _ = memory.capture_shared_file_error(Error::SharedFileCopy {
                operation: "controlled deferred copy before capture",
                address: 0,
                requested: 8,
                transferred: 0,
                prior_transferred: 0,
                source: std::io::Error::from_raw_os_error(libc::EIO),
            });
            let ran = std::sync::atomic::AtomicBool::new(false);
            let mut pending = std::pin::pin!(std::future::pending());
            let before = admissions(&backend);
            let result = futures::executor::block_on(backend.prepare_action_read_or_reuse(
                pending.as_mut(),
                reuse.then_some((exit.generation, |_: &KvmBackend| {
                        ran.store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(7_u32)
                    })),
                |_, _| {
                    ran.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(7_u32)
                },
            ));
            assert!(
                !ran.load(std::sync::atomic::Ordering::SeqCst),
                "reuse={reuse}: the bytes were used after a deferred failure"
            );
            assert_eq!(admissions(&backend), before, "reuse={reuse}");
            errors.push(format!("{:?}", result.unwrap_err()));
            drop(scope);
        }
        assert_eq!(errors[0], errors[1]);
    }

    #[test]
    fn reuse_is_refused_while_closed_and_the_capture_waits_for_the_reopened_image() {
        let Fixture {
            mut backend,
            frame_address,
            ..
        } = fixture();
        let memory = backend.memory.clone();
        let expected = fresh(&backend, frame_address);
        let (_, exit) = backend.read_syscall_exit(&memory, frame_address).unwrap();
        let gate = backend.memory.entry_gate();
        let closed =
            futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        let before = admissions(&backend);
        let mut pending = std::pin::pin!(std::future::pending());
        let mut capture = Box::pin(CompletedSyscallBoundary::capture_admitted_reusing(
            &mut backend,
            frame_address,
            None,
            pending.as_mut(),
            Some((&exit, &memory)),
        ));
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(capture.as_mut().poll(&mut context).is_pending());
        assert!(capture.as_mut().poll(&mut context).is_pending());
        assert_eq!(gate.test_state().copy_admissions, before);
        drop(closed);
        let Poll::Ready(Ok(Some(actual))) = capture.as_mut().poll(&mut context) else {
            panic!("capture did not complete after reopening");
        };
        drop(capture);
        assert_eq!(admissions(&backend), before + 1, "reopened capture did not copy");
        assert_same(&actual, &expected);
    }
}
