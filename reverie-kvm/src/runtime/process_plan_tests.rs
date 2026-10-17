/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the LICENSE file.
 */
//! The lifecycle of a process action that a provider call staged
//! (`ProviderOutcome::Process`). The action stays in the executor until
//! `complete_injection` takes it. On every path where completion does not run
//! (an early return, an error, a dropped outcome) it keeps the executor's
//! lifecycle, as it did before the outcome existed.

use futures::FutureExt;

use super::*;

fn fork() -> SyscallRequest {
    SyscallRequest::new(libc::SYS_fork as u64, [0; 6])
}

fn native_executor() -> ElfExecutor {
    ElfExecutor::new(
        crate::executor::native_loaded_state(std::path::Path::new(".")),
        false,
    )
}

/// A successful call that staged an action returns `Process`, and the action
/// is still in the executor, also after the outcome is dropped. A failed call
/// returns `Return` and leaves the staged action where it is.
#[test]
fn process_outcome_reports_an_action_the_executor_keeps() {
    let mut backend = KvmBackend::new(0x10000).expect("process plan tests require /dev/kvm");
    let mut executor = native_executor();
    let mut memory = GuestMemory::new(0, 4096).unwrap();
    let task = Pid::from_raw(executor.task_tid());
    let mut completed = false;
    let mut e = StaticElfSyscallExecutor {
        backend: &mut backend,
        executor: &mut executor,
        memory: memory.clone(),
        process_context: ProcessExecutionContext::SyscallBoundary(
            CompletedSyscallBoundary::for_test(),
        ),
        callback_site: None,
        original_syscall: None,
        signal_guard: SignalGuard::Ordinary,
        last_result: None,
        polled_read_attempt: None,
        process_completed: &mut completed,
    };
    {
        let staged =
            futures::executor::block_on(<StaticElfSyscallExecutor<'_> as LinuxProvider>::execute(
                &mut e,
                task,
                fork().as_provider(),
                &mut memory,
            ))
            .unwrap();
        assert!(
            matches!(staged, ProviderOutcome::Process { result, .. } if result > 0),
            "{staged:?}"
        );
        assert!(e.executor.has_process_action());
        // The outcome, with its token, goes out of scope here.
    }
    assert!(
        e.executor.has_process_action(),
        "dropping the outcome must not release the staged action"
    );
    // A second fork fails while the first is staged.
    let failed =
        futures::executor::block_on(<StaticElfSyscallExecutor<'_> as LinuxProvider>::execute(
            &mut e,
            task,
            fork().as_provider(),
            &mut memory,
        ))
        .unwrap();
    assert_eq!(failed, ProviderOutcome::Return(-i64::from(libc::EBUSY)));
    assert!(e.executor.has_process_action());
    assert!(matches!(
        e.executor.take_process_action(),
        Some(crate::executor::ProcessAction::Fork { .. })
    ));
}

/// Runs `handler` against a KvmGuest on the static-ELF adapter in `context`
/// and returns the handler's outcome.
fn run_handler<F>(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    context: ProcessExecutionContext,
    handler: F,
) -> HandlerOutcome<std::result::Result<i64, Errno>>
where
    F: for<'g, 'k> FnOnce(
        &'g mut KvmGuest<'k, crate::StraceTool>,
    )
        -> Pin<Box<dyn Future<Output = std::result::Result<i64, Errno>> + 'g>>,
{
    let pid = Pid::from_raw(executor.task_tid());
    let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
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
        process_context: context,
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

/// A Tool's initial-exec callback forwards the synthetic exec without
/// awaiting it, drops that future, and injects a fork. Completion returns
/// early for the completed initial exec, so it does not take the fork's
/// action. The action must stay staged for the vCPU loop's reader, which
/// carries it out, as it did before the Process outcome existed.
#[test]
fn a_fork_after_the_initial_exec_stays_staged_for_the_vcpu_loop() {
    let mut backend = KvmBackend::new(0x10000).expect("process plan tests require /dev/kvm");
    let mut executor = native_executor();
    let initial = SyscallRequest::new(libc::SYS_execve as u64, [0x100, 0x200, 0x300, 0, 0, 0]);
    let outcome = run_handler(
        &mut backend,
        &mut executor,
        ProcessExecutionContext::InitialExec(initial),
        |guest| {
            Box::pin(async move {
                let _ = guest.inject(initial.into_syscall().unwrap()).now_or_never();
                guest.inject(fork().into_syscall().unwrap()).await
            })
        },
    );
    assert!(matches!(outcome, HandlerOutcome::TailInjected { .. }));
    assert!(
        matches!(
            executor.take_process_action(),
            Some(crate::executor::ProcessAction::Fork { .. })
        ),
        "the fork's action must stay staged for the vCPU loop"
    );
}

/// A fork succeeds, then the injection fails before completion (a sibling
/// already failed the signal-dequeue ledger). The staged action must stay in
/// the executor, so terminal cleanup releases whatever it owns in the
/// executor's order instead of the dropped callback releasing it early.
#[test]
fn an_action_staged_before_an_injection_failure_stays_in_the_executor() {
    let mut backend = KvmBackend::new(0x10000).expect("process plan tests require /dev/kvm");
    let state = crate::executor::native_loaded_state(std::path::Path::new("."));
    state.process_signals.lock().unwrap().dequeue_failed = true;
    let mut executor = ElfExecutor::new(state, false);
    let outcome = run_handler(
        &mut backend,
        &mut executor,
        ProcessExecutionContext::Lifecycle,
        |guest| Box::pin(async move { guest.inject(fork().into_syscall().unwrap()).await }),
    );
    assert!(matches!(outcome, HandlerOutcome::RuntimeError(_)));
    assert!(
        matches!(
            executor.take_process_action(),
            Some(crate::executor::ProcessAction::Fork { .. })
        ),
        "the failed injection's staged action must stay in the executor"
    );
}
