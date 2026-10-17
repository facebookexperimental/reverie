/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the LICENSE file.
 */
//! The pending FS/GS base staged by `arch_prctl` during one Tool handler.
//!
//! These tests drive `KvmGuest::inject` through the real static-ELF adapter
//! and then read, through `staged_segment`, the base the vCPU loop would
//! apply when the handler returns. They pin the rule the vCPU loop relies
//! on: the last base set during a handler wins, and an exec before the
//! handler's return discards it.

use super::*;
use crate::bootstrap::SegmentBase;

const MEMORY_SIZE: usize = 16 * 1024 * 1024;
const ARCH_SET_FS: u64 = 0x1002;

/// The base the vCPU loop would apply when the handler returns, taken as
/// the loop takes it.
fn staged_segment(
    _backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
) -> Option<(SegmentBase, u64)> {
    executor.take_segment()
}

/// A backend with a minimal static ELF installed, and that image's executor.
fn installed() -> (KvmBackend, ElfExecutor) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).expect("segment slot tests require /dev/kvm");
    backend
        .install_static_elf(&crate::vm::minimal_test_elf(&[0xf4]), "/bin/segment-slot")
        .unwrap();
    let executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
    (backend, executor)
}

fn arch_prctl_set_fs(base: u64) -> reverie::syscalls::Syscall {
    SyscallRequest::new(libc::SYS_arch_prctl as u64, [ARCH_SET_FS, base, 0, 0, 0, 0])
        .into_syscall()
        .unwrap()
}

/// Runs `handler` against a KvmGuest built on the static-ELF adapter in a
/// lifecycle callback and returns the handler's outcome.
fn run_handler<F>(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    handler: F,
) -> HandlerOutcome<std::result::Result<i64, Errno>>
where
    F: for<'g, 'k> FnOnce(
        &'g mut KvmGuest<'k, crate::StraceTool>,
    )
        -> Pin<Box<dyn Future<Output = std::result::Result<i64, Errno>> + 'g>>,
{
    let pid = Pid::from_raw(executor.task_tid());
    let memory = backend.memory.clone();
    let tool = Arc::new(crate::StraceTool);
    let global = Arc::new(crate::StraceLog::default());
    let mut state = ();
    let subscriptions = Subscription::none();
    let stack = Arc::new(AtomicBool::new(false));
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut completed = false;
    let top = backend.tool_stack_top();
    let mut adapter = StaticElfSyscallExecutor {
        backend,
        executor,
        memory: memory.clone(),
        process_context: ProcessExecutionContext::Lifecycle,
        last_result: None,
        polled_read_attempt: None,
        process_completed: &mut completed,
        callback_site: None,
        original_syscall: None,
        signal_guard: SignalGuard::Ordinary,
    };
    // No instruction executes in this initialized VM control.
    let registers = unsafe { std::mem::zeroed() };
    let mut guest = KvmGuest::new(
        pid,
        pid,
        tool.clone(),
        memory,
        &[],
        registers,
        &mut state,
        &mut adapter,
        global.as_ref(),
        Some(global.clone()),
        &(),
        &subscriptions,
        signal.clone(),
        starts.clone(),
        top,
        stack,
    );
    futures::executor::block_on(drive_handler(
        handler(&mut guest),
        signal,
        starts,
        std::future::pending(),
    ))
}

/// Two `arch_prctl(ARCH_SET_FS)` injections in one handler: the base the
/// vCPU loop applies when the handler returns is the second one.
#[test]
fn last_fs_base_set_in_a_handler_is_the_one_staged() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move {
            assert_eq!(guest.inject(arch_prctl_set_fs(0x1000)).await, Ok(0));
            guest.inject(arch_prctl_set_fs(0x2000)).await
        })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(
        matches!(staged, Some((SegmentBase::Fs, 0x2000))),
        "staged: {staged:?}"
    );
}

/// `arch_prctl(ARCH_SET_FS)` in a handler, then an exec before the base is
/// applied: no base from the old image survives the exec. The exec here runs
/// right after the handler returns, through `KvmBackend::exec_process`, the
/// function every injected exec reaches (from `complete_injection` in a
/// lifecycle callback, and through the process-action runner at a syscall
/// boundary); it is not an exec injected by the handler itself.
#[test]
fn exec_process_discards_a_staged_fs_base() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move { guest.inject(arch_prctl_set_fs(0x1000)).await })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    backend
        .exec_process(
            &mut executor,
            (std::path::Path::new("/bin/segment-slot-exec"), None),
            None,
            &crate::vm::minimal_test_elf(&[0xf4]),
            &["/bin/segment-slot-exec".to_owned()],
            &[],
        )
        .unwrap();
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(staged.is_none(), "staged: {staged:?}");
}

/// Control for the test above: without the exec, the same handler leaves
/// the base staged, so the exec is what discards it.
#[test]
fn without_an_exec_the_fs_base_set_in_a_handler_stays_staged() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move { guest.inject(arch_prctl_set_fs(0x1000)).await })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(
        matches!(staged, Some((SegmentBase::Fs, 0x1000))),
        "staged: {staged:?}"
    );
}
