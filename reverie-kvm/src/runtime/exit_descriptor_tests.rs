/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;

use super::*;

fn run_isolated(test: &str) -> bool {
    const CHILD_ENV: &str = "REVERIE_EXIT_DESCRIPTOR_TEST";
    let test = format!("runtime::exit_descriptor_tests::{test}");
    if std::env::var(CHILD_ENV).as_deref() == Ok(test.as_str()) {
        return false;
    }
    // Concurrent library tests fork host processes. CLOEXEC endpoints remain
    // inherited until those processes exec, so create our pipe only after
    // entering this exact-test subprocess. Keep the immediate EOF assertions.
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "10s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture"])
        .env(CHILD_ENV, &test)
        .output()
        .expect("failed to run isolated exit descriptor control");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "isolated exit descriptor control {test} failed with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipeObservation {
    WouldBlock,
    Eof,
    Byte(u8),
}

fn observe_pipe(reader: &File) -> PipeObservation {
    let mut byte = 0;
    // SAFETY: reader owns a nonblocking pipe and byte is writable for one byte.
    match unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } {
        0 => PipeObservation::Eof,
        1 => PipeObservation::Byte(byte),
        -1 => {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN),
                "host pipe read failed for a reason other than a live writer"
            );
            PipeObservation::WouldBlock
        }
        result => panic!("one-byte pipe read returned {result}"),
    }
}

fn nonblocking_pipe() -> (File, File) {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for both descriptors returned by pipe2.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}

#[derive(Default)]
struct ExitDescriptorGlobal {
    reader: Option<File>,
    expected: Mutex<Option<(reverie::SignalBoundaryReceipt, PipeObservation)>>,
    receipts: Mutex<Vec<reverie::SignalBoundaryReceipt>>,
}

#[reverie::global_tool]
impl GlobalTool for ExitDescriptorGlobal {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _: Pid, _: ()) {}

    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> std::result::Result<(), reverie::Error> {
        let (expected, pipe) = self.expected.lock().unwrap().take().unwrap();
        assert_eq!(receipt, expected, "the exact reserved boundary must settle");
        // This is the callback that can commit Detcore's Exit and admit the
        // next turn. An observation after finish_signal_boundary returns, or
        // in on_exit_thread, would miss a close performed too late.
        assert_eq!(
            observe_pipe(self.reader.as_ref().unwrap()),
            pipe,
            "descriptor visibility at the consuming boundary receipt"
        );
        self.receipts.lock().unwrap().push(receipt);
        Ok(())
    }
}

struct Fixture {
    backend: KvmBackend,
    executor: ElfExecutor,
    memory: GuestMemory,
    global: Arc<ExitDescriptorGlobal>,
    _failure: Arc<RunFailure>,
}

impl Fixture {
    fn new(stdin: bool) -> Self {
        let (reader, writer) = nonblocking_pipe();
        let mut state = crate::executor::native_loaded_state(&std::env::current_dir().unwrap());
        let reserved_stdin = if stdin {
            state.stdin = Some(writer.try_clone().unwrap());
            Some(writer)
        } else {
            assert!(state.insert_file(3, writer).is_empty());
            None
        };
        // These controls create a VM, as the neighboring runtime controls do,
        // but execute no guest instructions and need no compiled guest image.
        let backend = KvmBackend::new_with_stdin(0x10000, reserved_stdin)
            .expect("exit descriptor controls require /dev/kvm");
        let executor = ElfExecutor::new(state, false);
        let global = Arc::new(ExitDescriptorGlobal {
            reader: Some(reader),
            ..ExitDescriptorGlobal::default()
        });
        let failure = RunFailure::new(&global);
        executor
            .install_signal_control(reverie::BackendSignalControlMode::ToolControlled, &failure);
        assert_eq!(
            observe_pipe(global.reader.as_ref().unwrap()),
            PipeObservation::WouldBlock,
            "the executor starts with an open writer"
        );
        Self {
            backend,
            executor,
            memory: GuestMemory::new(0, 4096).unwrap(),
            global,
            _failure: failure,
        }
    }
}

fn reserve_boundary(executor: &ElfExecutor, sequence: u64) -> reverie::SignalDeliveryPermit {
    let permit = reverie::SignalDeliveryPermit {
        task: executor.signal_task_identity().unwrap(),
        site: None,
        sequence,
    };
    executor
        .backend_signal_control()
        .process
        .reserve_delivery(permit)
        .unwrap();
    assert_eq!(executor.owned_delivery_permit(), Some(permit));
    permit
}

fn settle_boundary(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    global: &Arc<ExitDescriptorGlobal>,
    permit: reverie::SignalDeliveryPermit,
    outcome: reverie::SignalBoundaryOutcome,
    pipe: PipeObservation,
) {
    let receipt = reverie::SignalBoundaryReceipt { permit, outcome };
    let before = global.receipts.lock().unwrap().len();
    assert!(
        global
            .expected
            .lock()
            .unwrap()
            .replace((receipt, pipe))
            .is_none()
    );
    futures::executor::block_on(backend.finish_signal_boundary(executor, global.as_ref(), outcome))
        .unwrap();
    assert!(global.expected.lock().unwrap().is_none());
    assert_eq!(global.receipts.lock().unwrap().len(), before + 1);
    assert_eq!(executor.owned_delivery_permit(), None);
}

fn exit_syscall(executor: &mut ElfExecutor, memory: &GuestMemory, group: bool) -> ProcessExit {
    let number = if group {
        libc::SYS_exit_group
    } else {
        libc::SYS_exit
    };
    assert_eq!(
        executor.execute(
            &SyscallRequest::new(number as u64, [37, 0, 0, 0, 0, 0]),
            memory
        ),
        0
    );
    let exit = executor.take_exit().unwrap();
    assert_eq!(exit.status, ExitStatus::Exited(37));
    assert_eq!(exit.group, group);
    exit
}

#[test]
fn exit_and_exit_group_receipts_observe_descriptor_eof() {
    if run_isolated("exit_and_exit_group_receipts_observe_descriptor_eof") {
        return;
    }
    for group in [false, true] {
        let mut f = Fixture::new(false);
        let permit = reserve_boundary(&f.executor, 7);
        let exit = exit_syscall(&mut f.executor, &f.memory, group);
        settle_boundary(
            &mut f.backend,
            &mut f.executor,
            &f.global,
            permit,
            exit.signal_boundary_outcome(),
            PipeObservation::Eof,
        );
    }
}

#[test]
fn fatal_terminal_receipt_observes_descriptor_eof() {
    if run_isolated("fatal_terminal_receipt_observes_descriptor_eof") {
        return;
    }
    let mut f = Fixture::new(false);
    let permit = reserve_boundary(&f.executor, 7);
    f.executor.force_signal_exit(libc::SIGTERM);
    let exit = f.executor.take_exit().unwrap();
    assert_eq!(exit.status.into_raw(), libc::SIGTERM);
    assert!(exit.group);
    settle_boundary(
        &mut f.backend,
        &mut f.executor,
        &f.global,
        permit,
        exit.signal_boundary_outcome(),
        PipeObservation::Eof,
    );
}

#[test]
fn terminal_receipt_releases_executor_and_backend_stdin_owners() {
    if run_isolated("terminal_receipt_releases_executor_and_backend_stdin_owners") {
        return;
    }
    let mut f = Fixture::new(true);
    let permit = reserve_boundary(&f.executor, 7);
    let exit = exit_syscall(&mut f.executor, &f.memory, true);
    settle_boundary(
        &mut f.backend,
        &mut f.executor,
        &f.global,
        permit,
        exit.signal_boundary_outcome(),
        PipeObservation::Eof,
    );
}

#[test]
fn returning_signal_receipts_preserve_open_descriptors() {
    if run_isolated("returning_signal_receipts_preserve_open_descriptors") {
        return;
    }
    for outcome in [
        reverie::SignalBoundaryOutcome::Caught,
        reverie::SignalBoundaryOutcome::NoHandler,
    ] {
        let mut f = Fixture::new(false);
        let permit = reserve_boundary(&f.executor, 7);
        settle_boundary(
            &mut f.backend,
            &mut f.executor,
            &f.global,
            permit,
            outcome,
            PipeObservation::WouldBlock,
        );
        f.memory.write(0x100, b"r").unwrap();
        assert_eq!(
            f.executor.execute(
                &SyscallRequest::new(libc::SYS_write as u64, [3, 0x100, 1, 0, 0, 0]),
                &f.memory,
            ),
            1,
            "a returning boundary must preserve the usable guest descriptor"
        );
        assert_eq!(
            observe_pipe(f.global.reader.as_ref().unwrap()),
            PipeObservation::Byte(b'r')
        );
    }
}

#[test]
fn image_replaced_cancelled_and_failed_receipts_preserve_open_descriptors() {
    if run_isolated("image_replaced_cancelled_and_failed_receipts_preserve_open_descriptors") {
        return;
    }
    for outcome in [
        reverie::SignalBoundaryOutcome::ImageReplaced,
        reverie::SignalBoundaryOutcome::Cancelled,
        reverie::SignalBoundaryOutcome::Failed,
    ] {
        let mut f = Fixture::new(false);
        let permit = reserve_boundary(&f.executor, 7);
        settle_boundary(
            &mut f.backend,
            &mut f.executor,
            &f.global,
            permit,
            outcome,
            PipeObservation::WouldBlock,
        );
        f.memory.write(0x100, b"n").unwrap();
        assert_eq!(
            f.executor.execute(
                &SyscallRequest::new(libc::SYS_write as u64, [3, 0x100, 1, 0, 0, 0]),
                &f.memory,
            ),
            1,
            "this boundary must preserve the usable guest descriptor"
        );
        assert_eq!(
            observe_pipe(f.global.reader.as_ref().unwrap()),
            PipeObservation::Byte(b'n')
        );
    }
}

#[test]
fn thread_exit_receipt_preserves_the_live_shared_files_owner() {
    if run_isolated("thread_exit_receipt_preserves_the_live_shared_files_owner") {
        return;
    }
    let mut f = Fixture::new(false);
    let mut sibling = f.executor.thread_child(2).unwrap();
    let permit = reserve_boundary(&f.executor, 7);
    let exit = exit_syscall(&mut f.executor, &f.memory, false);
    settle_boundary(
        &mut f.backend,
        &mut f.executor,
        &f.global,
        permit,
        exit.signal_boundary_outcome(),
        PipeObservation::WouldBlock,
    );
    f.memory.write(0x100, b"s").unwrap();
    assert_eq!(
        sibling.execute(
            &SyscallRequest::new(libc::SYS_write as u64, [3, 0x100, 1, 0, 0, 0]),
            &f.memory,
        ),
        1,
        "the live CLONE_FILES sibling must retain its usable writer"
    );
    assert_eq!(
        observe_pipe(f.global.reader.as_ref().unwrap()),
        PipeObservation::Byte(b's')
    );
    let permit = reserve_boundary(&sibling, 8);
    let exit = exit_syscall(&mut sibling, &f.memory, false);
    settle_boundary(
        &mut f.backend,
        &mut sibling,
        &f.global,
        permit,
        exit.signal_boundary_outcome(),
        PipeObservation::Eof,
    );
}

mod unpermitted_retirement {
    use super::*;

    #[derive(Default)]
    struct FaultGlobal {
        boundaries: ExitDescriptorGlobal,
        expected: Mutex<Option<(reverie::BackendProcessRetirement, usize)>>,
        retirements: Mutex<Vec<reverie::BackendProcessRetirement>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for FaultGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _: Pid, _: ()) {}

        async fn on_backend_signal_boundary(
            &self,
            receipt: reverie::SignalBoundaryReceipt,
        ) -> std::result::Result<(), reverie::Error> {
            self.boundaries.on_backend_signal_boundary(receipt).await
        }

        fn on_backend_process_retired(
            &self,
            event: reverie::BackendProcessRetirement,
        ) -> std::result::Result<(), reverie::Error> {
            let (expected, receipts) = self.expected.lock().unwrap().take().unwrap();
            assert_eq!(
                event, expected,
                "retirement must name the exact process and status"
            );
            assert_eq!(self.boundaries.receipts.lock().unwrap().len(), receipts);
            assert_eq!(
                observe_pipe(self.boundaries.reader.as_ref().unwrap()),
                PipeObservation::Eof,
                "an unpermitted fault still retires descriptors before notification"
            );
            self.retirements.lock().unwrap().push(event);
            Ok(())
        }
    }

    #[derive(Default)]
    struct FaultTool;

    #[reverie::tool]
    impl Tool for FaultTool {
        type GlobalState = FaultGlobal;
        type ThreadState = ();
    }

    struct FaultFixture {
        backend: KvmBackend,
        executor: ElfExecutor,
        memory: GuestMemory,
        global: Arc<FaultGlobal>,
        _failure: Arc<RunFailure>,
    }

    impl FaultFixture {
        fn new() -> Self {
            let (reader, writer) = nonblocking_pipe();
            let mut state = crate::executor::native_loaded_state(&std::env::current_dir().unwrap());
            // Model a traced root beneath an outside namespace init, so a
            // fork orphan follows the actual ReapedByNamespaceInit branch.
            state.pid = 3;
            state.pgid = 3;
            state.tid = 3;
            state.ppid = 1;
            state.task_lifecycle = Arc::new(Mutex::new(crate::elf::TaskLifecycleTable::with_root(
                3, 3, 3, true,
            )));
            assert!(state.insert_file(3, writer).is_empty());
            let executor = ElfExecutor::new(state, false);
            let global = Arc::new(FaultGlobal {
                boundaries: ExitDescriptorGlobal {
                    reader: Some(reader),
                    ..ExitDescriptorGlobal::default()
                },
                ..FaultGlobal::default()
            });
            let failure = RunFailure::new(&global);
            executor.install_signal_control(
                reverie::BackendSignalControlMode::ToolControlled,
                &failure,
            );
            Self {
                backend: KvmBackend::new_with_stdin(0x10000, None)
                    .expect("fault retirement controls require /dev/kvm"),
                executor,
                memory: GuestMemory::new(0, 4096).unwrap(),
                global,
                _failure: failure,
            }
        }

        fn finish_fault(
            &mut self,
            child_exit: Option<crate::vm::OwnChildExitContext>,
            earlier_receipts: usize,
        ) -> ExitStatus {
            assert!(self.executor.signal_controlled());
            assert_eq!(self.executor.owned_delivery_permit(), None);
            let process = self.executor.retired_process_identity();
            // Captured synchronous SIGSEGV uses this exact terminal operation
            // without reserving a delivery permit. Exercise real final cleanup,
            // not guest fault admission or a determinism claim for that path.
            self.executor.force_signal_exit(libc::SIGSEGV);
            let exit = self.executor.take_exit().unwrap();
            let status = ExitStatus::from_raw(libc::SIGSEGV | 0x80);
            assert_eq!(exit.status, status);
            assert!(exit.group);
            self.backend.request_guest_thread_group_exit(exit.status);
            assert_eq!(self.executor.owned_delivery_permit(), None);
            assert_eq!(
                observe_pipe(self.global.boundaries.reader.as_ref().unwrap()),
                PipeObservation::WouldBlock
            );
            if child_exit.is_some() {
                assert!(matches!(
                    self.executor.process_family_exit().unwrap(),
                    crate::executor::ProcessFamilyExit::ReapedByNamespaceInit { status: actual }
                        if actual == status
                ));
            } else {
                assert!(matches!(
                    self.executor.process_family_exit().unwrap(),
                    crate::executor::ProcessFamilyExit::Root
                ));
            }
            let expected = reverie::BackendProcessRetirement { process, status };
            assert!(
                self.global
                    .expected
                    .lock()
                    .unwrap()
                    .replace((expected, earlier_receipts))
                    .is_none()
            );
            let (actual, stdout, stderr) =
                futures::executor::block_on(self.backend.finish_tool_process(
                    &mut self.executor,
                    Arc::new(FaultTool),
                    (process.tgid, process.tgid),
                    self.global.as_ref(),
                    &(),
                    (),
                    Ok(exit.into()),
                    true,
                    child_exit,
                ))
                .unwrap();
            assert_eq!(actual, status);
            assert!(stdout.is_empty() && stderr.is_empty());
            assert!(self.global.expected.lock().unwrap().is_none());
            assert_eq!(*self.global.retirements.lock().unwrap(), vec![expected]);
            assert_eq!(
                self.global.boundaries.receipts.lock().unwrap().len(),
                earlier_receipts,
                "fault cleanup must not invent a terminal boundary receipt"
            );
            status
        }
    }

    #[test]
    fn root_fault_without_permit_still_reports_retirement_after_eof() {
        if run_isolated(
            "unpermitted_retirement::root_fault_without_permit_still_reports_retirement_after_eof",
        ) {
            return;
        }
        FaultFixture::new().finish_fault(None, 0);
    }

    #[test]
    fn orphan_fault_without_permit_still_reports_retirement_after_eof() {
        if run_isolated(
            "unpermitted_retirement::orphan_fault_without_permit_still_reports_retirement_after_eof",
        ) {
            return;
        }
        let mut f = FaultFixture::new();
        let parent = f.executor.retired_process_identity();
        let parent_wait = f.executor.fixture_child_wait_context();
        let orphan = f.executor.fork_child(4, false, false).unwrap();
        let child = orphan.retired_process_identity();
        let completion = Arc::new(crate::executor::ChildCompletionSlot::default());
        let context = crate::vm::OwnChildExitContext {
            child,
            _parent_binding: f.executor.retain_signal_process_binding(),
            completion: completion.clone(),
            raw_child_pid: child.tgid.as_raw(),
        };
        exit_syscall(&mut f.executor, &f.memory, true);
        f.executor.release_files_on_exit();
        f.executor = orphan;
        let status = f.finish_fault(Some(context), 0);
        // The family ledger retains the exact orphan generation and frozen
        // completion, but must not make it waitable by the retired parent.
        parent_wait.assert_namespace_reaped_child_for_test(child, status);
        let registry = parent_wait.registry().unwrap();
        assert_eq!(
            registry.registered_child_wait(parent, child.tgid.as_raw()),
            Some(child)
        );
        registry
            .validate_owned_child_wait(
                parent,
                child,
                crate::executor::ChildCompletion::AutoReaped(status),
            )
            .unwrap();
        assert!(!parent_wait.contains_key(&child.tgid.as_raw()));
        assert!(
            !completion.publish(crate::executor::ChildCompletion::AutoReaped(status)),
            "orphan completion must already be published"
        );
    }

    #[test]
    fn final_fault_after_nonfinal_thread_receipt_still_reports_retirement() {
        if run_isolated(
            "unpermitted_retirement::final_fault_after_nonfinal_thread_receipt_still_reports_retirement",
        ) {
            return;
        }
        let mut f = FaultFixture::new();
        let mut worker = f.executor.thread_child(4).unwrap();
        let permit = reserve_boundary(&worker, 7);
        let exit = exit_syscall(&mut worker, &f.memory, false);
        let receipt = reverie::SignalBoundaryReceipt {
            permit,
            outcome: exit.signal_boundary_outcome(),
        };
        assert!(f.executor.process_exit_status().is_none());
        assert!(
            f.global
                .boundaries
                .expected
                .lock()
                .unwrap()
                .replace((receipt, PipeObservation::WouldBlock))
                .is_none()
        );
        futures::executor::block_on(f.backend.finish_signal_boundary(
            &mut worker,
            f.global.as_ref(),
            receipt.outcome,
        ))
        .unwrap();
        assert_eq!(worker.owned_delivery_permit(), None);
        assert_eq!(*f.global.boundaries.receipts.lock().unwrap(), vec![receipt]);
        drop(worker);
        f.finish_fault(None, 1);
    }
}
