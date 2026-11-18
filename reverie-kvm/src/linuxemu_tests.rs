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

/// Acceptance for the S2-R4 claim move (option (a)): the synthetic
/// `/proc/self/maps` snapshot surface is served only when a composition
/// installs the procfs extension, so its guest-visible coverage lives
/// here, at `ElfExecutor` level, with the extension installed. The
/// readable `/proc/self/status` seq description is core mechanics
/// (hoisted in S2-R4) and serves with or without the extension; its
/// deep coverage stays in reverie-linuxemu's own tests.
mod procfs_extension_tests {
    use super::*;

    const PATH_ADDR: u64 = 0x100;
    const BUF_ADDR: u64 = 0x400;
    const STAT_ADDR: u64 = 0x1000;
    const PAIR_ADDR: u64 = 0x1400;
    const SEG_ADDR: u64 = 0x1800;
    const IOV_ADDR: u64 = 0x1900;
    const MSG_ADDR: u64 = 0x1a00;
    const CTRL_ADDR: u64 = 0x1c00;
    const CTRL_CAPACITY: usize = 64;
    /// Linux `F_SEAL_EXEC`, added implicitly by some hosts
    /// (`vm.memfd_noexec`); libc does not name it on every target.
    const F_SEAL_EXEC: libc::c_int = 0x0020;
    /// The one guest stack line the extension renders from the core's
    /// facts snapshot (pinned byte-for-byte in the extension's own
    /// render tests as well).
    const MAPS_CONTENT: &[u8] = b"7fffff800000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n";
    const STATUS_CONTENT: &[u8] = b"Name:\ttest\nUmask:\t0022\nState:\tR (running)\n\
        Tgid:\t1\nNgid:\t0\nPid:\t1\nPPid:\t0\nTracerPid:\t0\n\
        Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nFDSize:\t64\nThreads:\t1\n";

    fn guest_memory() -> GuestMemory {
        let memory = GuestMemory::new(0, 0x4000).unwrap();
        memory.map_user_permissions(0, 0x4000, true, true).unwrap();
        memory.enable_user_access();
        memory
    }

    fn executor_with(root: &TestDir, extension: bool, host_timestamps: bool) -> ElfExecutor {
        let mut state = test_state(&root.0);
        state.host_metadata_timestamps = host_timestamps;
        if extension {
            state.install_extension_table(reverie_linuxemu_ext_procfs::extension_table());
        }
        ElfExecutor::new(state, false)
    }

    fn call(executor: &mut ElfExecutor, memory: &GuestMemory, number: i64, args: [u64; 6]) -> i64 {
        executor
            .execute_checked(&SyscallRequest::new(number as u64, args), memory)
            .unwrap()
    }

    fn write_cstr(memory: &GuestMemory, address: u64, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        memory.write_raw(address, &bytes).unwrap();
    }

    fn write_val<T>(memory: &GuestMemory, address: u64, value: &T) {
        // SAFETY: value is live for size_of::<T>() readable bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref(value).cast::<u8>(), size_of::<T>())
        };
        memory.write_raw(address, bytes).unwrap();
    }

    fn read_val<T: Copy>(memory: &GuestMemory, address: u64) -> T {
        let mut value = std::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: value is writable for exactly size_of::<T>() bytes.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size_of::<T>())
        };
        memory.read_raw(address, bytes).unwrap();
        // SAFETY: read_raw filled the zeroed storage.
        unsafe { value.assume_init() }
    }

    fn open_path(
        executor: &mut ElfExecutor,
        memory: &GuestMemory,
        path: &str,
        flags: libc::c_int,
    ) -> i64 {
        write_cstr(memory, PATH_ADDR, path);
        call(
            executor,
            memory,
            libc::SYS_openat,
            [libc::AT_FDCWD as u64, PATH_ADDR, flags as u64, 0, 0, 0],
        )
    }

    fn read_all(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64) -> Vec<u8> {
        let mut content = Vec::new();
        loop {
            let read = call(
                executor,
                memory,
                libc::SYS_read,
                [fd as u64, BUF_ADDR, 64, 0, 0, 0],
            );
            assert!(read >= 0, "read fd {fd}: {read}");
            if read == 0 {
                return content;
            }
            let mut chunk = vec![0; read as usize];
            memory.read_raw(BUF_ADDR, &mut chunk).unwrap();
            content.extend_from_slice(&chunk);
        }
    }

    fn guest_fstat(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i32) -> libc::stat {
        assert_eq!(
            call(
                executor,
                memory,
                libc::SYS_fstat,
                [fd as u64, STAT_ADDR, 0, 0, 0, 0]
            ),
            0,
            "fstat fd {fd}"
        );
        read_val(memory, STAT_ADDR)
    }

    fn close_fd(executor: &mut ElfExecutor, memory: &GuestMemory, fd: i64) {
        assert_eq!(
            call(
                executor,
                memory,
                libc::SYS_close,
                [fd as u64, 0, 0, 0, 0, 0]
            ),
            0,
            "close fd {fd}"
        );
    }

    #[test]
    fn extension_serves_maps_while_core_serves_status_without_it() {
        let root = TestDir::new();
        let memory = guest_memory();

        // No extension: status is core-served, maps refuses by name as
        // real procfs does (EACCES).
        let mut bare = executor_with(&root, false, false);
        let status = open_path(&mut bare, &memory, "/proc/self/status", libc::O_RDONLY);
        assert!(status >= 0, "core status open: {status}");
        assert_eq!(read_all(&mut bare, &memory, status), STATUS_CONTENT);
        assert_eq!(
            open_path(&mut bare, &memory, "/proc/self/maps", libc::O_RDONLY),
            -i64::from(libc::EACCES),
            "unregistered maps must refuse"
        );
        close_fd(&mut bare, &memory, status);

        // With the extension: maps serves the deterministic snapshot,
        // status bytes are unchanged, and closing drops every proc
        // descriptor record.
        let mut executor = executor_with(&root, true, false);
        let maps = open_path(&mut executor, &memory, "/proc/self/maps", libc::O_RDONLY);
        assert!(maps >= 0, "extension maps open: {maps}");
        assert_eq!(read_all(&mut executor, &memory, maps), MAPS_CONTENT);
        let status = open_path(&mut executor, &memory, "/proc/self/status", libc::O_RDONLY);
        assert!(status >= 0, "status open with extension: {status}");
        assert_eq!(read_all(&mut executor, &memory, status), STATUS_CONTENT);
        close_fd(&mut executor, &memory, maps);
        close_fd(&mut executor, &memory, status);
        assert!(
            executor.state.proc_files.is_empty(),
            "closed proc descriptors stay tracked"
        );
    }

    #[test]
    fn backend_installs_extension_table_on_the_loaded_image() {
        // The backend-side setter compositions that load through the
        // backend use: it refuses before an image is installed, and
        // the installed table is what the executor then serves.
        let mut backend = match crate::KvmBackend::new(16 * 1024 * 1024) {
            Ok(backend) => backend,
            Err(crate::Error::Kvm(error))
                if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) =>
            {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "backend extension install requires KVM: {error}"
                );
                eprintln!("backend extension install not executed: KVM unavailable: {error}");
                return;
            }
            Err(error) => panic!("backend setup failed: {error}"),
        };
        assert!(
            matches!(
                backend.install_extension_table(reverie_linuxemu_ext_procfs::extension_table()),
                Err(crate::Error::StaticElfNotInstalled)
            ),
            "installing a table with no loaded image must refuse"
        );
        let root = TestDir::new();
        backend.static_elf = Some(test_state(&root.0));
        backend
            .install_extension_table(reverie_linuxemu_ext_procfs::extension_table())
            .expect("installing a table on the loaded image");
        let state = backend.static_elf.take().expect("loaded image");
        let memory = guest_memory();
        let mut executor = ElfExecutor::new(state, false);
        let maps = open_path(&mut executor, &memory, "/proc/self/maps", libc::O_RDONLY);
        assert!(maps >= 0, "backend-installed maps open: {maps}");
        assert_eq!(read_all(&mut executor, &memory, maps), MAPS_CONTENT);
        close_fd(&mut executor, &memory, maps);
    }

    #[test]
    fn extension_maps_snapshot_identity_seals_and_readonly_refusals() {
        let root = TestDir::new();
        let mut executor = executor_with(&root, true, false);
        // Sized to the layout limit, as the in-crate original was, so
        // the mmap leg reaches the file check instead of failing
        // allocation against a truncated address space.
        let memory = GuestMemory::new(0, executor.state.mm.mmap_limit as usize).unwrap();
        memory.map_user_permissions(0, 0x4000, true, true).unwrap();
        memory.enable_user_access();
        let fd = open_path(
            &mut executor,
            &memory,
            "/proc/self/maps",
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        assert!(fd >= 0, "maps open: {fd}");
        let guest_fd = fd as i32;

        // Descriptor flags: read-only, close-on-exec as opened.
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0]
            ) & i64::from(libc::O_ACCMODE),
            i64::from(libc::O_RDONLY)
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
            ),
            i64::from(libc::FD_CLOEXEC)
        );

        // Fstat identity: synthetic regular file, content-length size,
        // epoch timestamps; the path stat agrees field for field.
        let stat = guest_fstat(&mut executor, &memory, guest_fd);
        assert_eq!(stat.st_mode, libc::S_IFREG | 0o444);
        assert_eq!(stat.st_size, MAPS_CONTENT.len() as libc::off_t);
        assert_eq!((stat.st_uid, stat.st_gid), (0, 0));
        assert_eq!(stat.st_mtime, 0);
        assert_ne!(stat.st_ino, 0);
        write_cstr(&memory, PATH_ADDR, "/proc/self/maps");
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_newfstatat,
                [libc::AT_FDCWD as u64, PATH_ADDR, STAT_ADDR, 0, 0, 0]
            ),
            0
        );
        let path_stat: libc::stat = read_val(&memory, STAT_ADDR);
        assert_eq!(
            (
                path_stat.st_dev,
                path_stat.st_ino,
                path_stat.st_size,
                path_stat.st_mode
            ),
            (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mode)
        );

        // The host carrier: mode 0444 with the required seal set (plus
        // a host-implicit F_SEAL_EXEC where policy adds it).
        let host_fd = executor.state.files.get(&guest_fd).unwrap().as_raw_fd();
        let mut host_stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: host_fd is live and host_stat is writable.
        assert_eq!(unsafe { libc::fstat(host_fd, host_stat.as_mut_ptr()) }, 0);
        // SAFETY: fstat initialized host_stat on success.
        assert_eq!(unsafe { host_stat.assume_init() }.st_mode & 0o777, 0o444);
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        // SAFETY: host_fd is live; F_GET_SEALS takes no third argument.
        let seals = unsafe { libc::fcntl(host_fd, libc::F_GET_SEALS) };
        assert!(
            seals == required || seals == (required | F_SEAL_EXEC),
            "unexpected maps snapshot seals: {seals:#x}"
        );

        // Read-only description refusals, with the in-crate errnos.
        memory.write_raw(BUF_ADDR, b"x").unwrap();
        let high_fd = (1_u64 << 32) | fd as u64;
        for (number, args, errno) in [
            (
                libc::SYS_write,
                [fd as u64, BUF_ADDR, 1, 0, 0, 0],
                libc::EBADF,
            ),
            (
                libc::SYS_pwrite64,
                [high_fd, BUF_ADDR, 1, 0, 0, 0],
                libc::ESPIPE,
            ),
            (libc::SYS_ftruncate, [high_fd, 0, 0, 0, 0, 0], libc::EINVAL),
            (libc::SYS_fallocate, [fd as u64, 0, 0, 1, 0, 0], libc::EBADF),
        ] {
            assert_eq!(
                call(&mut executor, &memory, number, args),
                -i64::from(errno),
                "syscall {number} accepted the read-only snapshot"
            );
        }
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_pwrite64,
                [fd as u64, u64::MAX, 1, u64::MAX, 0, 0]
            ),
            -i64::from(libc::EINVAL),
            "negative offset validation must precede positioning refusal"
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_mmap,
                [
                    0,
                    0x1000,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    libc::MAP_SHARED as u64,
                    fd as u64,
                    0
                ]
            ),
            -i64::from(libc::EACCES)
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_pread64,
                [fd as u64, BUF_ADDR, MAPS_CONTENT.len() as u64, 0, 0, 0]
            ),
            MAPS_CONTENT.len() as i64
        );
        let mut actual = vec![0; MAPS_CONTENT.len()];
        memory.read_raw(BUF_ADDR, &mut actual).unwrap();
        assert_eq!(actual, MAPS_CONTENT);

        // Writable open, access(2) spelling, and vectored read refusal
        // on the served snapshot.
        assert_eq!(
            open_path(&mut executor, &memory, "/proc/self/maps", libc::O_WRONLY),
            -i64::from(libc::EACCES)
        );
        write_cstr(&memory, PATH_ADDR, "/proc/self/maps");
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_access,
                [PATH_ADDR, libc::R_OK as u64, 0, 0, 0, 0]
            ),
            0
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_access,
                [PATH_ADDR, libc::W_OK as u64, 0, 0, 0, 0]
            ),
            -i64::from(libc::EACCES)
        );
        write_val(
            &memory,
            IOV_ADDR,
            &libc::iovec {
                iov_base: BUF_ADDR as usize as *mut libc::c_void,
                iov_len: 1,
            },
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_readv,
                [fd as u64, IOV_ADDR, 1, 0, 0, 0]
            ),
            -i64::from(libc::ENOSYS)
        );

        // The executor's own carrier is never a provided fact.
        assert_eq!(
            executor.descriptor_status(guest_fd),
            Err(reverie::FactError::NotProvided)
        );
        assert_eq!(
            executor.link_path(executor.state.tid, reverie::PathLink::Descriptor(guest_fd)),
            Err(reverie::FactError::NotProvided)
        );
        close_fd(&mut executor, &memory, fd);
    }

    fn rights_control(fds: &[i32]) -> Vec<u8> {
        let align = |value: usize| (value + 7) & !7;
        let header_space = align(size_of::<libc::cmsghdr>());
        let data: Vec<u8> = fds.iter().flat_map(|fd| fd.to_ne_bytes()).collect();
        let length = header_space + data.len();
        let mut control = vec![0; align(length)];
        let header = libc::cmsghdr {
            cmsg_len: length,
            cmsg_level: libc::SOL_SOCKET,
            cmsg_type: libc::SCM_RIGHTS,
        };
        // SAFETY: header is live for its size in readable bytes.
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&header).cast::<u8>(),
                size_of::<libc::cmsghdr>(),
            )
        };
        control[..header_bytes.len()].copy_from_slice(header_bytes);
        control[header_space..length].copy_from_slice(&data);
        control
    }

    fn send_rights(
        executor: &mut ElfExecutor,
        memory: &GuestMemory,
        socket: i32,
        fds: &[i32],
    ) -> i64 {
        memory.write_raw(SEG_ADDR, b"x").unwrap();
        write_val(
            memory,
            IOV_ADDR,
            &libc::iovec {
                iov_base: SEG_ADDR as usize as *mut libc::c_void,
                iov_len: 1,
            },
        );
        let control = rights_control(fds);
        memory.write_raw(CTRL_ADDR, &control).unwrap();
        // SAFETY: msghdr is plain data; a zeroed value is valid.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = IOV_ADDR as usize as *mut libc::iovec;
        message.msg_iovlen = 1;
        message.msg_control = CTRL_ADDR as usize as *mut libc::c_void;
        message.msg_controllen = control.len();
        write_val(memory, MSG_ADDR, &message);
        call(
            executor,
            memory,
            libc::SYS_sendmsg,
            [socket as u64, MSG_ADDR, 0, 0, 0, 0],
        )
    }

    fn receive_rights(executor: &mut ElfExecutor, memory: &GuestMemory, socket: i32) -> Vec<i32> {
        write_val(
            memory,
            IOV_ADDR,
            &libc::iovec {
                iov_base: SEG_ADDR as usize as *mut libc::c_void,
                iov_len: 1,
            },
        );
        memory.write_raw(CTRL_ADDR, &[0_u8; CTRL_CAPACITY]).unwrap();
        // SAFETY: msghdr is plain data; a zeroed value is valid.
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = IOV_ADDR as usize as *mut libc::iovec;
        message.msg_iovlen = 1;
        message.msg_control = CTRL_ADDR as usize as *mut libc::c_void;
        message.msg_controllen = CTRL_CAPACITY;
        write_val(memory, MSG_ADDR, &message);
        let result = call(
            executor,
            memory,
            libc::SYS_recvmsg,
            [socket as u64, MSG_ADDR, 0, 0, 0, 0],
        );
        assert_eq!(result, 1, "recvmsg: {result}");
        let received: libc::msghdr = read_val(memory, MSG_ADDR);
        assert!(received.msg_controllen >= size_of::<libc::cmsghdr>());
        let mut control = vec![0; received.msg_controllen];
        memory.read_raw(CTRL_ADDR, &mut control).unwrap();
        let header_space = (size_of::<libc::cmsghdr>() + 7) & !7;
        let header: libc::cmsghdr = read_val(memory, CTRL_ADDR);
        assert_eq!(
            (header.cmsg_level, header.cmsg_type),
            (libc::SOL_SOCKET, libc::SCM_RIGHTS)
        );
        (header_space..header.cmsg_len)
            .step_by(4)
            .map(|offset| i32::from_ne_bytes(control[offset..offset + 4].try_into().unwrap()))
            .collect()
    }

    fn socket_pair(executor: &mut ElfExecutor, memory: &GuestMemory) -> [i32; 2] {
        assert_eq!(
            call(
                executor,
                memory,
                libc::SYS_socketpair,
                [
                    libc::AF_UNIX as u64,
                    libc::SOCK_DGRAM as u64,
                    0,
                    PAIR_ADDR,
                    0,
                    0
                ]
            ),
            0
        );
        read_val(memory, PAIR_ADDR)
    }

    /// Verbatim port of the in-crate `assert_descriptor_timestamps`
    /// the removed tests used, in this module's spellings: every
    /// stat route to `fd` (fstat, empty-path newfstatat and statx,
    /// and newfstatat and statx through its `/proc/self/fd` link)
    /// must report the fixed epoch, or with `fixed_epoch` off the
    /// kernel's timestamps of the host object, btime included.
    /// Each output buffer is prefilled with 0xa5 so an unwritten
    /// field cannot pass by leftover content.
    fn assert_snapshot_times(
        executor: &mut ElfExecutor,
        memory: &GuestMemory,
        fd: i32,
        fixed_epoch: bool,
        what: &str,
    ) {
        let host_fd = executor.state.files.get(&fd).unwrap().as_raw_fd();
        let mut kernel = std::mem::MaybeUninit::<libc::statx>::zeroed();
        // SAFETY: the path is NUL-terminated, kernel is writable and host_fd is live.
        assert_eq!(
            unsafe {
                libc::statx(
                    host_fd,
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH,
                    libc::STATX_BASIC_STATS | libc::STATX_BTIME,
                    kernel.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: statx initialized kernel on success.
        let kernel = unsafe { kernel.assume_init() };
        let pair =
            |timestamp: libc::statx_timestamp| (timestamp.tv_sec, i64::from(timestamp.tv_nsec));
        let expected_stat = if fixed_epoch {
            [(0, 0); 3]
        } else {
            [kernel.stx_atime, kernel.stx_mtime, kernel.stx_ctime].map(pair)
        };
        let expected_statx = if fixed_epoch {
            [(0, 0); 4]
        } else {
            [
                kernel.stx_atime,
                kernel.stx_btime,
                kernel.stx_ctime,
                kernel.stx_mtime,
            ]
            .map(pair)
        };
        const EMPTY_ADDRESS: u64 = 0x100;
        const LINK_ADDRESS: u64 = 0x180;
        const STAT_ADDRESS: u64 = STAT_ADDR;
        const STATX_ADDRESS: u64 = 0x1200;
        write_cstr(memory, EMPTY_ADDRESS, "");
        write_cstr(memory, LINK_ADDRESS, &format!("/proc/self/fd/{fd}"));
        for (call_name, number, args) in [
            (
                "fstat",
                libc::SYS_fstat,
                [fd as u64, STAT_ADDRESS, 0, 0, 0, 0],
            ),
            (
                "empty-path newfstatat",
                libc::SYS_newfstatat,
                [
                    fd as u64,
                    EMPTY_ADDRESS,
                    STAT_ADDRESS,
                    libc::AT_EMPTY_PATH as u64,
                    0,
                    0,
                ],
            ),
            (
                "/proc/self/fd newfstatat",
                libc::SYS_newfstatat,
                [libc::AT_FDCWD as u64, LINK_ADDRESS, STAT_ADDRESS, 0, 0, 0],
            ),
        ] {
            memory
                .write_raw(STAT_ADDRESS, &[0xa5; std::mem::size_of::<libc::stat>()])
                .unwrap();
            assert_eq!(
                call(executor, memory, number, args),
                0,
                "{what}: {call_name}"
            );
            let stat: libc::stat = read_val(memory, STAT_ADDRESS);
            assert_eq!(
                [
                    (stat.st_atime, stat.st_atime_nsec),
                    (stat.st_mtime, stat.st_mtime_nsec),
                    (stat.st_ctime, stat.st_ctime_nsec),
                ],
                expected_stat,
                "{what}: {call_name} reports the expected timestamps"
            );
        }
        let statx_mask = (libc::STATX_BASIC_STATS | libc::STATX_BTIME) as u64;
        for (call_name, args) in [
            (
                "empty-path statx",
                [
                    fd as u64,
                    EMPTY_ADDRESS,
                    libc::AT_EMPTY_PATH as u64,
                    statx_mask,
                    STATX_ADDRESS,
                    0,
                ],
            ),
            (
                "/proc/self/fd statx",
                [
                    libc::AT_FDCWD as u64,
                    LINK_ADDRESS,
                    0,
                    statx_mask,
                    STATX_ADDRESS,
                    0,
                ],
            ),
        ] {
            memory
                .write_raw(STATX_ADDRESS, &[0xa5; std::mem::size_of::<libc::statx>()])
                .unwrap();
            assert_eq!(
                call(executor, memory, libc::SYS_statx, args),
                0,
                "{what}: {call_name}"
            );
            let extended: libc::statx = read_val(memory, STATX_ADDRESS);
            assert_eq!(
                [
                    extended.stx_atime,
                    extended.stx_btime,
                    extended.stx_ctime,
                    extended.stx_mtime,
                ]
                .map(|timestamp| (timestamp.tv_sec, i64::from(timestamp.tv_nsec))),
                expected_statx,
                "{what}: {call_name} reports the expected timestamps"
            );
        }
    }

    #[test]
    fn extension_received_maps_snapshot_keeps_epoch_and_refusals() {
        for host_timestamps in [true, false] {
            let setting = if host_timestamps {
                "setting on"
            } else {
                "setting off"
            };
            let root = TestDir::new();
            let memory = guest_memory();
            let mut executor = executor_with(&root, true, host_timestamps);
            let maps = open_path(&mut executor, &memory, "/proc/self/maps", libc::O_RDONLY);
            assert!(maps >= 0, "{setting}: maps open: {maps}");
            let maps = maps as i32;
            let [sender, receiver] = socket_pair(&mut executor, &memory);

            // Received while the sender's descriptor is still open, and
            // through a dup of the received descriptor.
            assert_eq!(send_rights(&mut executor, &memory, sender, &[maps]), 1);
            let received = receive_rights(&mut executor, &memory, receiver);
            assert_eq!(received.len(), 1);
            assert_snapshot_times(
                &mut executor,
                &memory,
                received[0],
                host_timestamps,
                &format!("{setting}: maps received while sender open"),
            );
            let duplicate = call(
                &mut executor,
                &memory,
                libc::SYS_dup,
                [received[0] as u64, 0, 0, 0, 0, 0],
            );
            assert!(duplicate >= 0, "{setting}: dup: {duplicate}");
            assert_snapshot_times(
                &mut executor,
                &memory,
                duplicate as i32,
                host_timestamps,
                &format!("{setting}: dup of received maps"),
            );

            // Received after every sender alias closed; the carrier is
            // still not a provided fact and syncfs refuses it without a
            // host call (ENOSYS), in a forked child as well.
            assert_eq!(send_rights(&mut executor, &memory, sender, &[maps]), 1);
            for fd in [maps, received[0], duplicate as i32] {
                close_fd(&mut executor, &memory, i64::from(fd));
            }
            let late = receive_rights(&mut executor, &memory, receiver);
            assert_eq!(late.len(), 1);
            assert_snapshot_times(
                &mut executor,
                &memory,
                late[0],
                host_timestamps,
                &format!("{setting}: maps received after sender closed"),
            );
            assert!(
                !executor.state.proc_files.contains_key(&late[0]),
                "{setting}: real transfer loses fixed metadata"
            );
            assert!(
                !executor.state.fdinfo_files.contains_key(&late[0]),
                "{setting}: received carrier tracked as fdinfo"
            );
            assert_eq!(
                executor.descriptor_status(late[0]),
                Err(reverie::FactError::NotProvided),
                "{setting}: received carrier provided as a fact"
            );
            assert_eq!(
                executor.link_path(executor.state.tid, reverie::PathLink::Descriptor(late[0])),
                Err(reverie::FactError::NotProvided),
                "{setting}: received carrier provided as a link"
            );
            // Syncfs refuses the received snapshot, its dup alias,
            // and both in a forked child (the in-crate syncfs test's
            // maps legs; its exec-inherit leg has no ElfExecutor
            // spelling and is flagged in the S2-R4 report).
            let late_dup = call(
                &mut executor,
                &memory,
                libc::SYS_dup,
                [late[0] as u64, 0, 0, 0, 0, 0],
            );
            assert!(late_dup >= 0, "{setting}: dup of late: {late_dup}");
            assert_eq!(
                executor.descriptor_status(late_dup as i32),
                Err(reverie::FactError::NotProvided),
                "{setting}: dup of received carrier provided as a fact"
            );
            for fd in [late[0], late_dup as i32] {
                assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        libc::SYS_syncfs,
                        [fd as u64, 0, 0, 0, 0, 0]
                    ),
                    -i64::from(libc::ENOSYS),
                    "{setting}: syncfs on received snapshot fd {fd}"
                );
            }
            let mut child = executor.fork_child(2, false, false).unwrap();
            assert_snapshot_times(
                &mut child,
                &memory,
                late[0],
                host_timestamps,
                &format!("{setting}: received maps in forked child"),
            );
            for fd in [late[0], late_dup as i32] {
                assert_eq!(
                    call(
                        &mut child,
                        &memory,
                        libc::SYS_syncfs,
                        [fd as u64, 0, 0, 0, 0, 0]
                    ),
                    -i64::from(libc::ENOSYS),
                    "{setting}: syncfs on received snapshot in fork, fd {fd}"
                );
            }
            drop(child);
            close_fd(&mut executor, &memory, late_dup);

            // An O_PATH snapshot received after its sender closed.
            let path_only = open_path(
                &mut executor,
                &memory,
                "/proc/self/maps",
                libc::O_PATH | libc::O_CLOEXEC,
            );
            assert!(path_only >= 0, "{setting}: O_PATH maps open: {path_only}");
            assert_eq!(
                send_rights(&mut executor, &memory, sender, &[path_only as i32]),
                1
            );
            close_fd(&mut executor, &memory, path_only);
            let received_path = receive_rights(&mut executor, &memory, receiver);
            assert_eq!(received_path.len(), 1);
            assert_snapshot_times(
                &mut executor,
                &memory,
                received_path[0],
                host_timestamps,
                &format!("{setting}: O_PATH maps received after sender closed"),
            );
        }
    }

    #[test]
    fn extension_maps_dup_and_reopen_preserve_description_semantics_and_seals() {
        let root = TestDir::new();
        let memory = guest_memory();
        let mut executor = executor_with(&root, true, false);
        let fd = open_path(
            &mut executor,
            &memory,
            "/proc/self/maps",
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        assert!(fd >= 0, "maps open: {fd}");

        // A dup shares the description (and its offset) but clears
        // the descriptor-local close-on-exec bit.
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_read,
                [fd as u64, BUF_ADDR, 4, 0, 0, 0]
            ),
            4
        );
        let duplicate = call(
            &mut executor,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        );
        assert!(duplicate >= 0, "dup: {duplicate}");
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fcntl,
                [duplicate as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
            ),
            0,
            "dup must clear the descriptor-local close-on-exec bit"
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_read,
                [duplicate as u64, BUF_ADDR, 3, 0, 0, 0]
            ),
            3
        );
        let mut shared_offset = [0; 3];
        memory.read_raw(BUF_ADDR, &mut shared_offset).unwrap();
        assert_eq!(&shared_offset, b"ff8");

        // A reopen through /proc/self/fd starts a fresh description
        // at offset zero, with its own close-on-exec bit.
        write_cstr(&memory, PATH_ADDR, &format!("/proc/self/fd/{fd}"));
        let reopened = call(
            &mut executor,
            &memory,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDR,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        );
        assert!(reopened >= 0, "reopen: {reopened}");
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_read,
                [reopened as u64, BUF_ADDR, 2, 0, 0, 0]
            ),
            2
        );
        let mut fresh_offset = [0; 2];
        memory.read_raw(BUF_ADDR, &mut fresh_offset).unwrap();
        assert_eq!(&fresh_offset, b"7f");
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fcntl,
                [reopened as u64, libc::F_GETFD as u64, 0, 0, 0, 0]
            ),
            i64::from(libc::FD_CLOEXEC)
        );

        // Every alias keeps the synthetic identity, the seal set, and
        // the read-only access mode on the host carrier.
        let inode = executor.state.proc_files[&(fd as i32)];
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        for alias in [duplicate, reopened] {
            assert_eq!(executor.state.proc_files.get(&(alias as i32)), Some(&inode));
            let host_fd = executor
                .state
                .files
                .get(&(alias as i32))
                .unwrap()
                .as_raw_fd();
            // SAFETY: host_fd is live; F_GET_SEALS/F_GETFL take no third argument.
            let seals = unsafe { libc::fcntl(host_fd, libc::F_GET_SEALS) };
            assert!(
                seals == required || seals == (required | F_SEAL_EXEC),
                "unexpected alias seal policy: {seals:#x}"
            );
            // SAFETY: as above.
            assert_eq!(
                unsafe { libc::fcntl(host_fd, libc::F_GETFL) } & libc::O_ACCMODE,
                libc::O_RDONLY
            );
        }

        // Mode changes refuse (EPERM) and leave the carrier at 0444.
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fchmod,
                [(1_u64 << 32) | fd as u64, 0o666, 0, 0, 0, 0]
            ),
            -i64::from(libc::EPERM)
        );
        let host_fd = executor.state.files.get(&(fd as i32)).unwrap().as_raw_fd();
        let mut host_stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: host_fd is live and host_stat is writable.
        assert_eq!(unsafe { libc::fstat(host_fd, host_stat.as_mut_ptr()) }, 0);
        // SAFETY: fstat initialized host_stat on success.
        assert_eq!(unsafe { host_stat.assume_init() }.st_mode & 0o777, 0o444);

        // An O_PATH reopen keeps the identity; O_PATH validation
        // precedes the synthetic guard for fchmod.
        let path_only = call(
            &mut executor,
            &memory,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDR,
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                0,
                0,
                0,
            ],
        );
        assert!(path_only >= 0, "O_PATH reopen: {path_only}");
        assert_eq!(
            executor.state.proc_files.get(&(path_only as i32)),
            Some(&inode)
        );
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_fchmod,
                [path_only as u64, 0o666, 0, 0, 0, 0]
            ),
            -i64::from(libc::EBADF),
            "O_PATH validation must precede the synthetic procfs guard"
        );
        close_fd(&mut executor, &memory, path_only);

        // A writable reopen refuses and allocates no descriptor.
        assert_eq!(
            call(
                &mut executor,
                &memory,
                libc::SYS_openat,
                [
                    libc::AT_FDCWD as u64,
                    PATH_ADDR,
                    (libc::O_RDWR | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0
                ]
            ),
            -i64::from(libc::EACCES),
            "a proc-fd reopen must preserve the synthetic file's read-only mode"
        );
        assert!(!executor.state.files.contains_key(&(path_only as i32)));
        assert_eq!(executor.state.proc_files.len(), 3);
    }
    #[test]
    fn extension_received_maps_snapshot_chmod_matrix() {
        // Ported from reverie-linuxemu's former
        // host_metadata_timestamps_refuse_mode_changes_that_would_hide_a_carrier:
        // with host timestamps on, no chmod route changes the mode
        // of a received snapshot carrier (EPERM, as Linux refuses a
        // mode change on a /proc file); a changed mode would stop
        // the receiver of an O_PATH right from reopening it to read
        // its seals and the carrier would lose its fixed
        // timestamps. With the setting off, fchmod succeeds.
        for host_timestamps in [false, true] {
            let setting = if host_timestamps {
                "setting on"
            } else {
                "setting off"
            };
            let root = TestDir::new();
            let memory = guest_memory();
            let mut executor = executor_with(&root, true, host_timestamps);
            let maps = open_path(&mut executor, &memory, "/proc/self/maps", libc::O_RDONLY);
            assert!(maps >= 0, "{setting}: maps open: {maps}");
            let [sender, receiver] = socket_pair(&mut executor, &memory);

            // A snapshot received after its sender closed has no
            // proc_files entry, only its snapshot identity.
            assert_eq!(
                send_rights(&mut executor, &memory, sender, &[maps as i32]),
                1
            );
            close_fd(&mut executor, &memory, maps);
            let snapshot = receive_rights(&mut executor, &memory, receiver);
            assert_eq!(snapshot.len(), 1);
            let fd = snapshot[0];
            assert!(
                !executor.state.proc_files.contains_key(&fd),
                "{setting}: received carrier tracked in proc_files"
            );
            assert!(
                !executor.state.fdinfo_files.contains_key(&fd),
                "{setting}: received carrier tracked in fdinfo_files"
            );

            if !host_timestamps {
                assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        libc::SYS_fchmod,
                        [fd as u64, 0o400, 0, 0, 0, 0]
                    ),
                    0,
                    "{setting}: fchmod"
                );
                continue;
            }
            write_cstr(&memory, PATH_ADDR, &format!("/proc/self/fd/{fd}"));
            let path_only = call(
                &mut executor,
                &memory,
                libc::SYS_openat,
                [
                    libc::AT_FDCWD as u64,
                    PATH_ADDR,
                    (libc::O_PATH | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                ],
            );
            assert!(path_only >= 0, "{setting}: O_PATH alias: {path_only}");
            assert_eq!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_fchmod,
                    [fd as u64, 0, 0, 0, 0, 0]
                ),
                -i64::from(libc::EPERM),
                "{setting}: fchmod"
            );
            write_cstr(&memory, PATH_ADDR, "");
            for target in [fd, path_only as i32] {
                assert_eq!(
                    call(
                        &mut executor,
                        &memory,
                        libc::SYS_fchmodat2,
                        [
                            target as u64,
                            PATH_ADDR,
                            0,
                            libc::AT_EMPTY_PATH as u64,
                            0,
                            0,
                        ]
                    ),
                    -i64::from(libc::EPERM),
                    "{setting}: empty-path fchmodat2 on fd {target}"
                );
            }
            write_cstr(&memory, PATH_ADDR, &format!("/proc/self/fd/{fd}"));
            assert!(
                call(
                    &mut executor,
                    &memory,
                    libc::SYS_fchmodat,
                    [libc::AT_FDCWD as u64, PATH_ADDR, 0, 0, 0, 0]
                ) < 0,
                "{setting}: chmod through /proc/self/fd"
            );

            // The O_PATH right, received after every sender alias
            // closed, is still recognized as the carrier.
            assert_eq!(
                send_rights(&mut executor, &memory, sender, &[path_only as i32]),
                1
            );
            close_fd(&mut executor, &memory, path_only);
            close_fd(&mut executor, &memory, i64::from(fd));
            let late = receive_rights(&mut executor, &memory, receiver);
            assert_eq!(late.len(), 1);
            assert_snapshot_times(
                &mut executor,
                &memory,
                late[0],
                true,
                &format!("{setting}: received as O_PATH after chmod attempts"),
            );
            close_fd(&mut executor, &memory, i64::from(late[0]));
        }
    }

    #[test]
    fn extension_maps_readable_reopen_keeps_epoch_with_host_timestamps() {
        // The readable-reopen leg of reverie-linuxemu's
        // host_metadata_timestamps_keep_proc_snapshots_fixed_through_every_alias:
        // with host timestamps on, the epoch survives a dup and a
        // readable /proc/self/fd reopen of the maps carrier.
        let root = TestDir::new();
        let memory = guest_memory();
        let mut executor = executor_with(&root, true, true);
        let fd = open_path(&mut executor, &memory, "/proc/self/maps", libc::O_RDONLY);
        assert!(fd >= 0, "maps open: {fd}");
        assert_snapshot_times(&mut executor, &memory, fd as i32, true, "maps");
        let duplicate = call(
            &mut executor,
            &memory,
            libc::SYS_dup,
            [fd as u64, 0, 0, 0, 0, 0],
        );
        assert!(duplicate >= 0, "dup: {duplicate}");
        assert_snapshot_times(&mut executor, &memory, duplicate as i32, true, "maps dup");
        write_cstr(&memory, PATH_ADDR, &format!("/proc/self/fd/{fd}"));
        let reopened = call(
            &mut executor,
            &memory,
            libc::SYS_openat,
            [
                libc::AT_FDCWD as u64,
                PATH_ADDR,
                libc::O_RDONLY as u64,
                0,
                0,
                0,
            ],
        );
        assert!(reopened >= 0, "readable reopen: {reopened}");
        assert_eq!(read_all(&mut executor, &memory, reopened), MAPS_CONTENT);
        assert_snapshot_times(
            &mut executor,
            &memory,
            reopened as i32,
            true,
            "maps /proc/self/fd reopen",
        );
    }
}
