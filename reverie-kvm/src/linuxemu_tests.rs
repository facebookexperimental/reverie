/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Unit tests of LinuxEmu (reverie-linuxemu) that need this backend: a
//! `KvmBackend` or its guest thread group. reverie-linuxemu cannot depend on
//! this crate, so these tests live here. Each module holds the tests of the
//! reverie-linuxemu module it is named after, and the fixtures they share with
//! that module's other tests are included from reverie-linuxemu.

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::RawFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::SignalProcessId;

use crate::GuestMemory;
use crate::SyscallRequest;
use crate::error::ErrorExt;
use crate::executor::ChildWaitContext;
use crate::executor::ElfExecutor;
use crate::executor::ProcessFamilyExit;
use crate::executor::capture_identity;
use crate::executor::native_loaded_state;
use crate::executor::process_signal_publication::ChildWaitSelection;
use crate::executor::process_signal_publication::ProcessSignalRegistry;
use crate::executor::process_signal_publication::child_wait::WaitPhase;
use crate::executor::process_signal_publication::process_key;
use crate::executor::test_state;

include!("../../reverie-linuxemu/tests/support/process_signal_publication_fixtures.rs");
include!("../../reverie-linuxemu/tests/support/process_child_wait_fixtures.rs");
include!("../../reverie-linuxemu/tests/support/capture_identity_fixtures.rs");
include!("../../reverie-linuxemu/tests/support/test_dir_fixture.rs");

mod process_signal_publication_tests {
    use super::*;

    #[test]
    fn a_run_returning_before_joining_its_workers_leaves_them_to_its_reaper() {
        let runs = Arc::new(Mutex::new(crate::executor::AbandonedRuns::default()));
        let group = Arc::new(crate::vm::GuestThreadGroup::default());
        let lifetime = Arc::new(());
        let (release, held) = std::sync::mpsc::channel::<()>();
        let worker = {
            let lifetime = lifetime.clone();
            std::thread::spawn(move || {
                let _lifetime = lifetime;
                let _ = held.recv();
                Ok((reverie::ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            })
        };
        group.add_worker_handle(4, worker);

        // An error returned the run before it joined worker 4.
        crate::executor::RunAdmission::begin(&runs)
            .unwrap()
            .finish(&*group);
        assert!(
            matches!(
                crate::executor::AbandonedRuns::admit(&runs),
                Err(crate::Error::AbandonedRunNotRetired)
            ),
            "a backend whose returned run left a worker running admitted another"
        );

        // The backend's drop hands the worker to the run's reaper and does
        // not wait for it.
        let dropping = std::time::Instant::now();
        assert!(crate::executor::AbandonedRuns::retire(&runs, &group));
        assert!(dropping.elapsed() < std::time::Duration::from_secs(5));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(group.has_unjoined_workers());
        assert_eq!(
            Arc::strong_count(&lifetime),
            2,
            "the worker ended while held"
        );
        assert_eq!(
            Arc::strong_count(&group),
            2,
            "the reaper let go of the worker before joining it"
        );

        release.send(()).unwrap();
        wait_until("the reaper never joined the worker", || {
            Arc::strong_count(&group) == 1
        });
        assert!(!group.has_unjoined_workers());
        assert_eq!(Arc::strong_count(&lifetime), 1);
    }
}

mod process_child_wait_tests {
    use super::*;

    #[test]
    fn direct_family_failure_precedes_ready_wait_without_consumption() {
        for (ready_pid, failed_pid) in [(2, 3), (3, 2)] {
            for mode in ["wait4", "waitid", "waitid-nowait"] {
                let mut parent = executor();
                let _ready = ready_family_child(&mut parent, ready_pid);
                let failed_child = parent.fork_child(failed_pid, false, false).unwrap();
                let failed_id = identity(&failed_child);
                let mut failed_worker = failed_child.thread_child(10).unwrap();
                let mut waiter = parent.thread_child(9).unwrap();
                let registry = parent.signal_registry.clone();
                assert!(registry.run_failure.lock().unwrap().upgrade().is_none());
                let group = Arc::new(crate::vm::GuestThreadGroup::default());
                let worker_group = group.clone();
                let cause = Arc::new(crate::Error::GuestClock(
                    "direct child worker failure".to_owned(),
                ));
                let worker_cause = cause.clone();
                let (committed, observed) = std::sync::mpsc::channel();
                let (release, released) = std::sync::mpsc::channel();
                let handle = std::thread::spawn(move || {
                    // Use the real Direct outcome/retirement path, without a Tool
                    // RunFailure. Hold physical return after the family commit.
                    let result: crate::Result<(reverie::ExitStatus, Vec<u8>, Vec<u8>)> =
                        crate::vm::finish_host_worker_outcome(
                            None,
                            reverie::Pid::from_raw(10),
                            Err(crate::Error::SharedFailure(worker_cause)),
                            |failed| {
                                assert!(failed);
                                failed_worker.retire_failed_thread();
                                worker_group.record_worker_failure(10);
                                committed.send(()).unwrap();
                                released.recv().unwrap();
                            },
                        );
                    result
                });
                group.add_worker_handle(10, handle);
                observed
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("worker did not commit its family failure");
                let memory = GuestMemory::new(0, 8192).unwrap();
                memory.map_user_permissions(0, 8192, true, true).unwrap();
                memory.enable_user_access();
                memory.write_raw(0, &[0xa5; 8192]).unwrap();
                let options = libc::WEXITED
                    | if mode == "waitid-nowait" {
                        libc::WNOWAIT
                    } else {
                        0
                    };
                let request = if mode == "wait4" {
                    SyscallRequest::new(libc::SYS_wait4 as u64, [u64::MAX, 0x100, 0, 0x400, 0, 0])
                } else {
                    SyscallRequest::new(
                        libc::SYS_waitid as u64,
                        [libc::P_ALL as u64, 0, 0x100, options as u64, 0x400, 0],
                    )
                };
                let family_state = || {
                    let family = registry.family.lock().unwrap();
                    (
                        family.direct_children.clone(),
                        family.terminal.clone(),
                        family
                            .wait_publications
                            .iter()
                            .map(|(key, publication)| (*key, publication.parent, publication.phase))
                            .collect::<Vec<_>>(),
                        family.wait_receipts.len(),
                        family.wait_failed,
                        family.wait_failure_notified,
                    )
                };
                let before = family_state();
                let result = waiter.execute_checked(&request, &memory);
                let after = family_state();
                let mut actual = [0; 8192];
                memory.read_raw(0, &mut actual).unwrap();
                // Always release and collect the real worker before asserting the
                // wait result, so the old selector's expected failure cannot strand it.
                release.send(()).unwrap();
                group.join_workers();
                let terminal = group.teardown_result().unwrap_err();
                assert!(terminal.retains_primary(&cause));
                assert!(group.teardown_result().unwrap_err().retains_primary(&cause));
                assert!(!group.has_worker_handles());
                assert!(
                    matches!(&result, Err(crate::Error::RunAborted)),
                    "{ready_pid}/{failed_pid} {mode}: {result:?}"
                );
                assert_eq!(
                    actual, [0xa5; 8192],
                    "failure must precede every output write"
                );
                assert_eq!(
                    after, before,
                    "failure must not change eligibility or receipts"
                );
                assert_eq!(before.3, 0);
                assert!(
                    !before.4 && !before.5,
                    "this is the Direct family-failure path"
                );
                assert!(waiter.state.consumed_child_wait.is_none());
                assert!(parent.state.children.has_ready(Some(ready_pid)).unwrap());
                {
                    let family = registry.family.lock().unwrap();
                    assert_eq!(
                        family.terminal[&process_key(failed_id)],
                        ProcessFamilyExit::Failed
                    );
                    assert_eq!(
                        family.wait_publications[&process_key(failed_id)].phase,
                        WaitPhase::Failed
                    );
                }

                // Exact-PID filtering is preserved: an unrelated failed child does
                // not change this narrowly selected child's wait contract.
                let exact = if mode == "wait4" {
                    SyscallRequest::new(
                        libc::SYS_wait4 as u64,
                        [ready_pid as u64, 0x100, 0, 0x400, 0, 0],
                    )
                } else {
                    SyscallRequest::new(
                        libc::SYS_waitid as u64,
                        [
                            libc::P_PID as u64,
                            ready_pid as u64,
                            0x100,
                            options as u64,
                            0x400,
                            0,
                        ],
                    )
                };
                assert_eq!(
                    waiter.execute_checked(&exact, &memory).unwrap(),
                    if mode == "wait4" {
                        i64::from(ready_pid)
                    } else {
                        0
                    }
                );
                let mut expected = [0xa5; 8192];
                if mode == "wait4" {
                    expected[0x100..0x104].copy_from_slice(&(23_i32 << 8).to_le_bytes());
                } else {
                    for (offset, value) in [0, 4, 8, 16, 20, 24].into_iter().zip([
                        libc::SIGCHLD,
                        0,
                        libc::CLD_EXITED,
                        ready_pid,
                        0,
                        23,
                    ]) {
                        expected[0x100 + offset..0x104 + offset]
                            .copy_from_slice(&value.to_le_bytes());
                    }
                }
                expected[0x400..0x400 + std::mem::size_of::<libc::rusage>()].fill(0);
                memory.read_raw(0, &mut actual).unwrap();
                assert_eq!(actual, expected);
                assert_eq!(
                    parent.state.children.has_ready(Some(ready_pid)).unwrap(),
                    mode == "waitid-nowait"
                );
                assert!(waiter.state.consumed_child_wait.is_none());
                assert!(registry.family.lock().unwrap().wait_receipts.is_empty());
            }
        }

        // Completing the scan must not replace the first Ready with a later one.
        let mut parent = executor();
        let _later = ready_family_child(&mut parent, 3);
        let _first = ready_family_child(&mut parent, 2);
        let memory = GuestMemory::new(0, 4096).unwrap();
        let ChildWaitSelection::Ready(peek) =
            parent.state.children.select(None, false, true).unwrap()
        else {
            panic!("two ready children must produce a selection");
        };
        assert_eq!(peek.child.tgid.as_raw(), 2);
        assert!(peek.receipt.is_none());
        assert_eq!(
            parent
                .execute_checked(
                    &SyscallRequest::new(libc::SYS_wait4 as u64, [u64::MAX, 0, 0, 0, 0, 0]),
                    &memory
                )
                .unwrap(),
            2
        );
        assert!(parent.state.children.has_ready(Some(3)).unwrap());
        assert!(!parent.state.children.has_ready(Some(2)).unwrap());
    }

    include!("linuxemu_child_wait_guest_tests.rs");
}

mod capture_identity_tests {
    use super::*;

    #[derive(Debug, Default)]
    struct CaptureSetupMustNotInitialize;

    #[reverie::global_tool]
    impl reverie::GlobalTool for CaptureSetupMustNotInitialize {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn init_global_state(_: &()) -> Self {
            panic!("failed capture setup initialized the Tool");
        }
        async fn receive_rpc(&self, _: reverie::Tid, _: ()) {
            panic!("failed capture setup dispatched an RPC");
        }
    }

    #[derive(Debug, Default)]
    struct CaptureSetupTool;

    #[reverie::tool]
    impl reverie::Tool for CaptureSetupTool {
        type GlobalState = CaptureSetupMustNotInitialize;
        type ThreadState = ();
    }

    #[test]
    fn capture_setup_emfile_preserves_image_and_closes_partial_streams() {
        const TEST: &str = "linuxemu_tests::capture_identity_tests::capture_setup_emfile_preserves_image_and_closes_partial_streams";
        const COMPLETE: &str = "capture setup EMFILE control completed";
        let mut backend = match crate::KvmBackend::new(16 * 1024 * 1024) {
            Ok(backend) => backend,
            Err(crate::Error::Kvm(error))
                if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) =>
            {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "capture setup control requires KVM: {error}"
                );
                eprintln!("capture setup control not executed: KVM unavailable: {error}");
                return;
            }
            Err(error) => panic!("capture setup failed: {error}"),
        };
        if !capture_test_child(TEST, COMPLETE) {
            return;
        }
        let root = TestDir::new();
        backend.static_elf = Some(test_state(&root.0));
        let original_pid = backend.static_elf.as_ref().unwrap().pid;
        let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut original) },
            0
        );
        let highest = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .parse::<u64>()
                    .unwrap()
            })
            .max()
            .unwrap();
        let reduced = libc::rlimit {
            rlim_cur: original.rlim_cur.min(highest + 32),
            rlim_max: original.rlim_max,
        };
        for free_slots in [0, 2] {
            let mut fillers = Vec::new();
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &reduced) }, 0);
            let exhausted = loop {
                match std::fs::File::open("/dev/null") {
                    Ok(file) => fillers.push(file),
                    Err(error) => break error.raw_os_error(),
                }
            };
            for _ in 0..free_slots {
                drop(fillers.pop().expect("descriptor budget has enough fillers"));
            }
            // Two free slots let the first real pipe succeed; its keeper then
            // leaves only one free slot, so the SECOND pipe2 fails atomically.
            let before_prepared = capture_identity::pipes_prepared();
            let error = futures::executor::block_on(
                backend.run_static_elf_with_tool_completion::<CaptureSetupTool>((), true),
            )
            .err()
            .expect("capture setup must fail before Tool initialization");
            let mut recovered = Vec::new();
            let after_error = loop {
                match std::fs::File::open("/dev/null") {
                    Ok(file) => recovered.push(file),
                    Err(error) => break error.raw_os_error(),
                }
            };
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
                0
            );
            assert_eq!(exhausted, Some(libc::EMFILE));
            assert_eq!(after_error, Some(libc::EMFILE));
            assert_eq!(recovered.len(), free_slots);
            assert_eq!(
                capture_identity::pipes_prepared() - before_prepared,
                usize::from(free_slots == 2)
            );
            assert!(
                matches!(error, crate::Error::HostIo(ref io) if io.raw_os_error() == Some(libc::EMFILE))
            );
            assert_eq!(backend.static_elf.as_ref().unwrap().pid, original_pid);
            assert!(backend.tool_failure.is_none());
            drop(recovered);
            drop(fillers);
            let owner = backend.prepare_captured_output(true).unwrap().unwrap();
            for fd in owner.identities.descriptors() {
                assert_eq!(
                    capture_native_stat(fd).st_mode & libc::S_IFMT,
                    libc::S_IFIFO
                );
            }
        }
        // Only closed standard-number slots remain available. pipe2 succeeds in
        // 0/1, its unused end closes, but F_DUPFD_CLOEXEC(min=3) must fail.
        let saved = [0, 1].map(|fd| {
            let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            assert!(copy >= 3);
            unsafe { std::os::fd::OwnedFd::from_raw_fd(copy) }
        });
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &reduced) }, 0);
        let mut fillers = Vec::new();
        let exhausted = loop {
            match std::fs::File::open("/dev/null") {
                Ok(file) => fillers.push(file),
                Err(error) => break error.raw_os_error(),
            }
        };
        for fd in [0, 1] {
            assert_eq!(unsafe { libc::close(fd) }, 0);
        }
        let before_relocation = capture_identity::relocation_failures();
        let error = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<CaptureSetupTool>((), true),
        )
        .err()
        .expect("private descriptor relocation must fail");
        let closed = [0, 1].map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF));
        assert_eq!(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original) },
            0
        );
        for (fd, saved) in [0, 1].into_iter().zip(&saved) {
            assert_eq!(unsafe { libc::dup2(saved.as_raw_fd(), fd) }, fd);
        }
        assert_eq!(exhausted, Some(libc::EMFILE));
        assert_eq!(
            capture_identity::relocation_failures() - before_relocation,
            1
        );
        assert_eq!(closed, [true; 2]);
        assert!(
            matches!(error, crate::Error::HostIo(ref io) if io.raw_os_error() == Some(libc::EMFILE))
        );
        assert_eq!(backend.static_elf.as_ref().unwrap().pid, original_pid);
        assert!(backend.tool_failure.is_none());
        drop(fillers);
        drop(saved);
        let owner = backend.prepare_captured_output(true).unwrap().unwrap();
        for fd in owner.identities.descriptors() {
            assert!(fd >= 3);
        }
        eprintln!("{COMPLETE}");
    }
}
