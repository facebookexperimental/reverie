/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/// Force only the PIDFD_THREAD open to fail as it does before Linux 6.9.
/// Other ptracer test threads remain on their normal kernel path.
struct LegacyThreadGroup {
    pid: Pid,
    _ptracer: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl LegacyThreadGroup {
    fn new(pid: Pid) -> Self {
        FORCE_LEGACY_THREAD_GROUP.with(|group| {
            assert!(group.get().is_none());
            group.set(Some(pid.into()));
        });
        Self {
            pid,
            _ptracer: std::marker::PhantomData,
        }
    }
}

impl Drop for LegacyThreadGroup {
    fn drop(&mut self) {
        FORCE_LEGACY_THREAD_GROUP.with(|group| {
            if group.get() == Some(self.pid.into()) {
                group.set(None);
            }
        });
    }
}

#[cfg(not(sanitized))]
fn run_legacy_test_outer(name: &str) -> bool {
    run_legacy_test_outer_with_outcome(name, None)
}

#[cfg(not(sanitized))]
fn run_legacy_test_outer_with_outcome(name: &str, marker: Option<&str>) -> bool {
    const INNER: &str = "SAFEPTRACE_LEGACY_THREAD_INNER";
    if env::var(INNER).as_deref() == Ok(name) {
        return false;
    }
    let result = run_exact_test_bounded(
        &format!("notifier::test::{name}"),
        &[(INNER, name)],
        false,
        Duration::from_secs(5),
    )
    .expect("start bounded legacy-thread test");
    assert!(
        !result.timed_out,
        "legacy-thread test timed out: {result:?}"
    );
    assert!(
        result.output.status.success(),
        "legacy-thread test failed: {result:?}"
    );
    if let Some(marker) = marker {
        assert!(
            String::from_utf8_lossy(&result.output.stdout)
                .lines()
                .any(|line| line == marker),
            "legacy-thread test omitted actual outcome marker {marker}: {result:?}"
        );
        emit_completion_marker(marker);
    }
    true
}

#[test]
fn forced_legacy_leader_preserves_pidfd_waits_and_cancellation() {
    let (pid, mut cleanup) = spawn_stopped_process(None).unwrap();
    let _force = LegacyThreadGroup::new(pid);
    let running = Running::new_on_ptracer_thread(pid.into()).unwrap();
    cleanup.bind_running_notifier(&running).unwrap();
    let terminal = running.terminal_cleanup();
    assert_eq!(terminal.has_thread_pidfd(), Ok(false));
    assert!(matches!(
        terminal.event.identity().unwrap().pidfd,
        ThreadHandle::LegacyLeader { .. }
    ));
    terminal.request_sigkill().unwrap();
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
    assert_eq!(terminal.has_thread_pidfd(), Ok(false));
    cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

#[cfg(not(sanitized))]
fn spawn_legacy_thread_tracee(
    pause_thread: bool,
) -> (Pid, Stopped, TraceeCleanupGuard, LegacyThreadGroup) {
    spawn_legacy_thread_tracee_with_options(pause_thread, legacy_thread_options())
}

#[cfg(not(sanitized))]
fn legacy_thread_options() -> Options {
    Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACEEXIT
        | Options::PTRACE_O_EXITKILL
}

#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyAttachMethod {
    Traceme,
    Seize,
    Attach,
}

#[cfg(not(sanitized))]
fn spawn_legacy_thread_tracee_with_options(
    pause_thread: bool,
    options: Options,
) -> (Pid, Stopped, TraceeCleanupGuard, LegacyThreadGroup) {
    spawn_legacy_thread_tracee_with_method(pause_thread, options, LegacyAttachMethod::Traceme)
}

#[cfg(not(sanitized))]
fn spawn_legacy_thread_tracee_with_method(
    pause_thread: bool,
    options: Options,
    method: LegacyAttachMethod,
) -> (Pid, Stopped, TraceeCleanupGuard, LegacyThreadGroup) {
    spawn_legacy_threads(if pause_thread { &[0] } else { &[17, 23] }, options, method)
}

/// A traced process whose main thread runs one pthread per entry of
/// `modes`, each joined before the next starts: 0 pauses forever, 1 spins
/// for about 300 µs between getppid calls forever, 17 raises SIGTRAP and
/// exits 17, a value from 1000 reads one byte at a time from descriptor
/// `value - 1000` forever, and any other value exits with it.
#[cfg(not(sanitized))]
fn spawn_legacy_threads(
    modes: &'static [usize],
    options: Options,
    method: LegacyAttachMethod,
) -> (Pid, Stopped, TraceeCleanupGuard, LegacyThreadGroup) {
    let mut start = [-1, -1];
    if method != LegacyAttachMethod::Traceme {
        assert_eq!(
            unsafe { libc::pipe2(start.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
    }
    let root = match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            if method == LegacyAttachMethod::Traceme {
                crate::traceme_and_stop().unwrap();
            } else {
                unsafe { libc::close(start[1]) };
                let mut byte = 0u8;
                if unsafe { libc::read(start[0], (&mut byte as *mut u8).cast(), 1) } != 1 {
                    unsafe { libc::_exit(125) };
                }
                unsafe { libc::close(start[0]) };
            }
            // Raw pthread creation avoids std's locks inherited across fork
            // from the multithreaded Rust test harness.
            extern "C" fn guest_thread(argument: *mut libc::c_void) -> *mut libc::c_void {
                let mode = argument as usize;
                if mode == 0 {
                    loop {
                        unsafe { libc::pause() };
                    }
                }
                if mode == 1 {
                    let now = || {
                        let mut now = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 0,
                        };
                        // The vDSO answers without a syscall stop.
                        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
                        now.tv_sec * 1_000_000_000 + now.tv_nsec
                    };
                    loop {
                        let start = now();
                        while now() - start < 300_000 {}
                        unsafe { libc::syscall(libc::SYS_getppid) };
                    }
                }
                if mode >= 1000 {
                    let mut byte = 0u8;
                    loop {
                        unsafe {
                            libc::read((mode - 1000) as i32, (&mut byte as *mut u8).cast(), 1)
                        };
                    }
                }
                if mode == 17 {
                    unsafe { libc::raise(libc::SIGTRAP) };
                }
                unsafe { libc::syscall(libc::SYS_exit, mode as i32) };
                std::ptr::null_mut()
            }
            for mode in modes {
                let mut thread = mem::MaybeUninit::<libc::pthread_t>::uninit();
                let created = unsafe {
                    libc::pthread_create(
                        thread.as_mut_ptr(),
                        std::ptr::null(),
                        guest_thread,
                        *mode as *mut libc::c_void,
                    )
                };
                if created != 0 {
                    unsafe { libc::_exit(126) };
                }
                let joined =
                    unsafe { libc::pthread_join(thread.assume_init(), std::ptr::null_mut()) };
                if joined != 0 {
                    unsafe { libc::_exit(127) };
                }
            }
            unsafe { libc::_exit(42) };
        }
    };
    let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
    let force = LegacyThreadGroup::new(root);
    let stopped = if method == LegacyAttachMethod::Traceme {
        let status = waitpid_status_bounded(root, libc::WUNTRACED, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        let stopped = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        stopped.setoptions(options).unwrap();
        stopped
    } else {
        unsafe { libc::close(start[0]) };
        let running = if method == LegacyAttachMethod::Seize {
            let running = Running::seize_on_ptracer_thread(root.into(), options).unwrap();
            running.interrupt().unwrap();
            running
        } else {
            Running::attach_on_ptracer_thread(root.into()).unwrap()
        };
        let (stopped, event) = running
            .wait_sync_on_ptracer_thread()
            .wait()
            .unwrap()
            .assume_stopped();
        if method == LegacyAttachMethod::Seize {
            assert_eq!(event, crate::Event::Stop);
        } else {
            assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
            stopped.setoptions(options).unwrap();
        }
        assert_eq!(unsafe { libc::write(start[1], b"s".as_ptr().cast(), 1) }, 1);
        unsafe { libc::close(start[1]) };
        stopped
    };
    cleanup.bind_notifier(&stopped).unwrap();
    (root, stopped, cleanup, force)
}

#[cfg(not(sanitized))]
fn legacy_child_cleanup(child: &Running) -> TraceeCleanupGuard {
    let identity = child.terminal_cleanup().event.identity().unwrap().clone();
    assert_ne!(
        child.pid(),
        identity.snapshot.tgid,
        "fixture must create a non-leader"
    );
    assert!(matches!(identity.pidfd, ThreadHandle::Procfs { .. }));
    let mut cleanup = TraceeCleanupGuard {
        pid: child.pid().into(),
        pidfd: identity.pidfd.try_clone().unwrap(),
        ownership: TraceeCleanupOwnership::PreRegistration,
        armed: true,
    };
    cleanup.bind_running_notifier(child).unwrap();
    cleanup
}

// The fixtures below have no exec path and keep the same paused pthread
// generation alive until the test's retained wait owner reaps it. This raw
// test stimulus checks notifier stop delivery; production cancellation never
// substitutes a numeric signal for a retained thread lifetime descriptor.
#[cfg(not(sanitized))]
fn request_fixture_thread_sigstop(root: Pid, tid: crate::Pid) {
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_tgkill, root.as_raw(), tid.as_raw(), libc::SIGSTOP) },
        0,
        "send controlled SIGSTOP to the fixture's live original thread"
    );
}

#[cfg(not(sanitized))]
fn assert_no_pending_sigstop(stopped: &Stopped) {
    for flags in [None, Some(crate::PeekSigInfoFlags::SHARED)] {
        assert!(
            stopped
                .peeksiginfo(flags)
                .unwrap()
                .iter()
                .all(|info| info.si_signo != libc::SIGSTOP),
            "refused legacy stop queued a real SIGSTOP"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_nonleader_preserves_stops_exits_and_retirement() {
    if run_legacy_test_outer("forced_legacy_nonleader_preserves_stops_exits_and_retirement") {
        return;
    }
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_thread_tracee(false);
    let root_terminal = stopped.terminal_cleanup();
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing first pthread clone");
    };
    let first_tid = child.pid();
    let mut first_cleanup = legacy_child_cleanup(&child);
    let first_terminal = child.terminal_cleanup();
    let identity = first_terminal.event.identity().unwrap().clone();
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let (child, event) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        child.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGTRAP));
    let mut stale_stop = Stopped::new_unchecked_on_ptracer_thread(first_tid).unwrap();
    let exit = first_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    let running = child.resume(None).unwrap();
    // ExitFuture observes the worker notification without polling wait_owned.
    let exiting = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    first_cleanup.mark_claimed_exit();
    drop(running);
    assert_eq!(exiting.pid(), first_tid);
    assert_eq!(exiting.getevent().unwrap(), 17 << 8);

    // The final status must remain unreaped while an earlier numeric request
    // owns the TID gate. A stop-only consuming wait must not release it.
    let event = Arc::clone(first_terminal.event.event());
    let held = event.hold_tid().unwrap();
    let final_running = exiting.resume_retaining(None).unwrap();
    let terminal_flags = WaitPidFlag::from_bits_retain(
        WaitPidFlag::WEXITED.bits()
            | WaitPidFlag::WNOWAIT.bits()
            | WaitPidFlag::WNOHANG.bits()
            | libc::__WALL,
    );
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    let observed = loop {
        match identity.pidfd.wait_status(terminal_flags).unwrap() {
            Some(status) => break status,
            None => assert!(Instant::now() < deadline, "thread never reached final exit"),
        }
        thread::sleep(Duration::from_millis(1));
    };
    assert!(libc::WIFEXITED(observed));
    assert_eq!(libc::WEXITSTATUS(observed), 17);
    assert!(identity.pidfd_is_live().unwrap());
    assert!(!first_terminal.wait(Duration::ZERO));
    drop(held);
    let exited = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        final_running.wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_exited();
    assert_eq!(exited, (first_tid, crate::ExitStatus::Exited(17)));
    assert!(first_terminal.wait(TRACEE_WAIT_TIMEOUT));
    first_cleanup.disarm();
    assert!(!identity.pidfd_is_live().unwrap());
    // The leader is still held at its clone stop. Thread liveness must not
    // silently become the leader's liveness when the thread exits.
    assert!(
        root_terminal
            .event
            .identity()
            .unwrap()
            .pidfd_is_live()
            .unwrap()
    );

    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        parent.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing second pthread clone");
    };
    let second_tid = child.pid();
    let mut second_cleanup = legacy_child_cleanup(&child);
    let second_terminal = child.terminal_cleanup();
    // Project the stale routing number onto a real live thread while keeping
    // the old proc descriptor. This is a reuse boundary, not a claim that the
    // kernel allocated the same TID in this unprivileged test.
    let mut projected = identity.pidfd.try_clone().unwrap();
    let ThreadHandle::Procfs { pid, .. } = &mut projected else {
        unreachable!()
    };
    *pid = second_tid;
    assert_eq!(projected.wait_status(terminal_flags), Err(Errno::ECHILD));
    assert_eq!(first_terminal.request_sigkill(), Err(Errno::ESRCH));
    stale_stop.0 = second_tid;
    assert!(stale_stop.1.event().hold_tid().is_none());
    let Err(Error::Died(zombie)) = stale_stop.getregs() else {
        panic!("stale stopped token reached the replacement thread");
    };
    assert_eq!(zombie.0.1.event(), &first_terminal.event);
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(
        event,
        crate::Event::Signal(Signal::SIGSTOP),
        "stale wait stole the live stop"
    );
    child
        .getregs()
        .expect("replacement thread remains controllable");
    let second_exit = second_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    let second_running = child.resume(None).unwrap();
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, second_exit)
        .await
        .unwrap()
        .unwrap();
    second_cleanup.mark_claimed_exit();
    drop(second_running);
    assert_eq!(child.getevent().unwrap(), 23 << 8);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (second_tid, crate::ExitStatus::Exited(23)),
    );
    assert!(second_terminal.wait(TRACEE_WAIT_TIMEOUT));
    second_cleanup.disarm();
    // Keep the leader at its clone stop until this thread is reaped. Otherwise
    // the leader's exit_group(42) may replace the pending thread exit status
    // after pthread_join sees its clear_child_tid, before the worker waits.
    let parent_running = parent.resume(None).unwrap();
    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    drop(parent_running);
    assert_eq!(parent.getevent().unwrap(), 42 << 8);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (root.into(), crate::ExitStatus::Exited(42)),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_nonleader_preserves_stop_notifications_and_exit() {
    if run_legacy_test_outer("forced_legacy_nonleader_preserves_stop_notifications_and_exit") {
        return;
    }
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_thread_tracee(true);
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let root_terminal = stopped.terminal_cleanup();
    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing paused pthread clone");
    };
    let child_tid = child.pid();
    let mut child_cleanup = legacy_child_cleanup(&child);
    let terminal = child.terminal_cleanup();
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    assert_eq!(terminal.has_thread_pidfd(), Ok(false));
    assert_no_pending_sigstop(&child);
    for missing in [Options::PTRACE_O_TRACEEXEC, Options::PTRACE_O_TRACEEXIT] {
        child
            .setoptions(legacy_thread_options() & !missing)
            .unwrap();
        assert_eq!(terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
        assert_no_pending_sigstop(&child);
        child
            .getregs()
            .expect("option refusal must preserve the actual stopped child");
    }
    child.setoptions(legacy_thread_options()).unwrap();
    let foreign = TerminalCleanup {
        pid: terminal.pid,
        event: terminal.event.clone(),
    };
    assert_eq!(
        thread::spawn(move || foreign.request_sigstop())
            .join()
            .unwrap(),
        Err(Errno::EOPNOTSUPP),
        "a transferable cleanup handle must not signal from another host thread"
    );
    assert_no_pending_sigstop(&child);
    let child_running = child.resume(None).unwrap();
    let parent_running = parent.resume(None).unwrap();
    assert!(matches!(
        root_terminal.event.identity().unwrap().pidfd,
        ThreadHandle::LegacyLeader { .. }
    ));
    assert_eq!(root_terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
    request_fixture_thread_sigstop(root, root.into());
    let (parent, event) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        parent_running.wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(parent.pid(), root.into());
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let parent_running = parent.resume(None).unwrap();
    assert_eq!(terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
    request_fixture_thread_sigstop(root, child_tid);
    let (child, event) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        child_running.wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(child.pid(), child_tid);
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));

    let mut exit = Box::pin(child_cleanup.exit_event_on_ptracer_thread(&child).unwrap());
    let wakes = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut context = Context::from_waker(&waker);
    assert!(exit.as_mut().poll(&mut context).is_pending());
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    terminal.request_sigkill().unwrap();
    drop(child);
    tokio::time::timeout(TRACEE_WAIT_TIMEOUT, async {
        while wakes.0.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("legacy worker lost the exit notification");
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit.as_mut())
        .await
        .unwrap()
        .unwrap();
    child_cleanup.mark_claimed_exit();
    assert!(
        wakes.0.load(Ordering::SeqCst) >= 1,
        "legacy worker lost the exit notification"
    );
    assert!(
        !terminal.wait(Duration::ZERO),
        "exit stop is not a terminal acknowledgment"
    );
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            child_tid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert_eq!(terminal.request_sigstop(), Err(Errno::ESRCH));
    child_cleanup.disarm();

    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    drop(parent_running);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_nonleader_exec_preserves_epochs_and_exact_wait_owners() {
    if run_legacy_test_outer("forced_legacy_nonleader_exec_preserves_epochs_and_exact_wait_owners")
    {
        return;
    }
    // Reuse every assertion of the native thread-pidfd regression. Only the
    // open result differs: this case must bind the non-leader's proc descriptor.
    actual_nonleader_exec_owned_case(true).await;
}

#[cfg(not(sanitized))]
async fn kill_legacy_family(
    parent: Stopped,
    child: Stopped,
    mut root_cleanup: TraceeCleanupGuard,
    mut child_cleanup: TraceeCleanupGuard,
) {
    let root_terminal = parent.terminal_cleanup();
    let child_terminal = child.terminal_cleanup();
    let root_pid = parent.pid();
    let child_pid = child.pid();
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&parent).unwrap();
    let child_exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    root_terminal.request_sigkill().unwrap();
    drop(parent);
    drop(child);
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child_exit)
        .await
        .unwrap()
        .unwrap();
    child_cleanup.mark_claimed_exit();
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            child_pid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        )
    );
    assert!(child_terminal.wait(TRACEE_WAIT_TIMEOUT));
    assert!(child_terminal.event.hold_tid().is_none());
    child_cleanup.disarm();
    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root_pid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        )
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_child_adoption_preserves_stops_after_option_change() {
    if run_legacy_test_outer("forced_legacy_child_adoption_preserves_stops_after_option_change") {
        return;
    }
    for supported_at_clone in [false, true] {
        let initial = if supported_at_clone {
            legacy_thread_options()
        } else {
            legacy_thread_options() & !Options::PTRACE_O_TRACEEXEC
        };
        let (root, stopped, root_cleanup, _force) =
            spawn_legacy_thread_tracee_with_options(true, initial);
        let root_terminal = stopped.terminal_cleanup();
        let running = stopped.resume(None).unwrap();
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        loop {
            let queued_clone = root_terminal
                .event
                .event()
                .status
                .lock()
                .pending
                .iter()
                .any(|status| (*status >> 16) == libc::PTRACE_EVENT_CLONE);
            if queued_clone {
                break;
            }
            assert!(Instant::now() < deadline, "clone stop was not published");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // This is a real held clone stop, not a fabricated kernel state.
        // Changing parent options here cannot change the already-born child.
        let at_clone = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
        let changed = if supported_at_clone {
            legacy_thread_options() & !Options::PTRACE_O_TRACEEXEC
        } else {
            legacy_thread_options()
        };
        at_clone.setoptions(changed).unwrap();
        drop(at_clone);
        let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped()
        else {
            panic!("missing real clone after parent option change");
        };
        // The explicit mode captures its first original anchor before
        // registration through a distinct Event. Adoption must preserve
        // the same original child generation and wait owner.
        let fresh = TerminalCleanup {
            pid: child.pid(),
            event: EventHandle::with_identity(Arc::new(
                WorkerIdentity::capture_for_policy(child.pid(), WaitPolicy::PtracerThread).unwrap(),
            )),
        };
        fresh.ensure_registered().unwrap();
        assert!(Arc::ptr_eq(child.1.event().event(), fresh.event.event()));
        let child_cleanup = legacy_child_cleanup(&child);
        let terminal = child.terminal_cleanup();
        let (child, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        assert_no_pending_sigstop(&child);
        assert_eq!(terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
        assert_no_pending_sigstop(&child);
        child.getregs().unwrap();
        request_fixture_thread_sigstop(root, child.pid());
        let (child, event) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(child.pid(), terminal.pid);
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        kill_legacy_family(parent, child, root_cleanup, child_cleanup).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_seize_and_attach_preserve_child_stops() {
    if run_legacy_test_outer("forced_legacy_seize_and_attach_preserve_child_stops") {
        return;
    }
    for method in [LegacyAttachMethod::Seize, LegacyAttachMethod::Attach] {
        let (root, stopped, root_cleanup, _force) =
            spawn_legacy_thread_tracee_with_method(true, legacy_thread_options(), method);
        let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped() else {
            panic!("missing clone in {method:?} mode");
        };
        let child_cleanup = legacy_child_cleanup(&child);
        let terminal = child.terminal_cleanup();
        let (child, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(
            event,
            if method == LegacyAttachMethod::Seize {
                crate::Event::Stop
            } else {
                crate::Event::Signal(Signal::SIGSTOP)
            }
        );
        assert_eq!(terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
        assert_no_pending_sigstop(&child);
        request_fixture_thread_sigstop(root, child.pid());
        let (child, event) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(child.pid(), terminal.pid);
        assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
        kill_legacy_family(parent, child, root_cleanup, child_cleanup).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_detach_preserves_cancellation_and_failed_owner() {
    if run_legacy_test_outer("forced_legacy_detach_preserves_cancellation_and_failed_owner") {
        return;
    }
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_thread_tracee(true);
    let terminal = stopped.terminal_cleanup();
    let foreign = Stopped::new_unchecked_on_ptracer_thread(root.into()).unwrap();
    assert!(matches!(
        thread::spawn(move || foreign.detach(None)).join().unwrap(),
        Err(Error::Errno(Errno::EPERM))
    ));
    assert!(terminal.event.hold_tid().is_some());
    stopped.getregs().unwrap();

    let event = Arc::clone(terminal.event.event());
    let identity = Arc::clone(terminal.event.identity().unwrap());
    let (captured, ready) = mpsc::sync_channel(1);
    let (begin, started) = mpsc::sync_channel(1);
    let prior_request = thread::spawn(move || {
        let held = event.hold_tid().unwrap();
        assert!(identity.pidfd_is_live().unwrap());
        captured.send(()).unwrap();
        started.recv().unwrap();
        assert_eq!(
            worker_proc_snapshot(root.into())
                .unwrap()
                .tracer_pid
                .as_raw(),
            0,
            "successful detach preserves the native read-gate facade"
        );
        assert!(identity.pidfd_is_live().unwrap());
        drop(held);
    });
    ready.recv_timeout(TRACEE_WAIT_TIMEOUT).unwrap();
    let running = stopped.detach(None).unwrap();
    begin.send(()).unwrap();
    prior_request.join().unwrap();
    assert_eq!(
        worker_proc_snapshot(root.into())
            .unwrap()
            .tracer_pid
            .as_raw(),
        0
    );
    assert!(
        terminal.event.hold_tid().is_some(),
        "detach must preserve ordinary detached-child waits and reattachment"
    );
    assert_eq!(terminal.request_sigstop(), Err(Errno::EOPNOTSUPP));
    assert!(terminal.event.identity().unwrap().pidfd_is_live().unwrap());
    terminal.request_sigkill().unwrap();
    assert_eq!(
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        )
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

#[cfg(not(sanitized))]
fn legacy_pipe() -> [OwnedFd; 2] {
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    descriptors.map(|descriptor| unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn detach_and_reattach_preserves_live_wait_authority() {
    if run_legacy_test_outer("detach_and_reattach_preserves_live_wait_authority") {
        return;
    }
    for force_legacy in [false, true] {
        for method in [LegacyAttachMethod::Attach, LegacyAttachMethod::Seize] {
            let [start, release] = legacy_pipe();
            let root = match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    unsafe { libc::close(release.as_raw_fd()) };
                    crate::traceme_and_stop().unwrap();
                    let mut byte = 0u8;
                    if unsafe { libc::read(start.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }
                        != 1
                    {
                        unsafe { libc::_exit(125) };
                    }
                    unsafe { libc::_exit(42) };
                }
            };
            drop(start);
            let _force = force_legacy.then(|| LegacyThreadGroup::new(root));
            let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
            let stopped = stopped_tracee_bounded(root, |pid| {
                Stopped::new_unchecked_on_ptracer_thread(pid).unwrap()
            })
            .unwrap();
            stopped.setoptions(legacy_thread_options()).unwrap();
            cleanup.bind_notifier(&stopped).unwrap();
            let old_terminal = stopped.terminal_cleanup();
            let old_event = Arc::clone(old_terminal.event.event());
            let mut exit = Box::pin(cleanup.exit_event_on_ptracer_thread(&stopped).unwrap());
            assert!(
                exit.as_mut()
                    .poll(&mut Context::from_waker(&futures::task::noop_waker()))
                    .is_pending()
            );
            let detached = stopped.detach(None).unwrap();
            assert!(
                old_terminal
                    .event
                    .identity()
                    .unwrap()
                    .pidfd_is_live()
                    .unwrap()
            );
            assert!(old_terminal.event.hold_tid().is_some());
            assert!(!old_terminal.wait(Duration::ZERO));
            assert_eq!(
                worker_proc_snapshot(root.into())
                    .unwrap()
                    .tracer_pid
                    .as_raw(),
                0
            );

            let running = match method {
                LegacyAttachMethod::Attach => {
                    Running::attach_on_ptracer_thread(root.into()).unwrap()
                }
                LegacyAttachMethod::Seize => {
                    let running =
                        Running::seize_on_ptracer_thread(root.into(), legacy_thread_options())
                            .unwrap();
                    running.interrupt().unwrap();
                    running
                }
                LegacyAttachMethod::Traceme => unreachable!(),
            };
            let terminal = running.terminal_cleanup();
            assert!(
                terminal.same_generation(&old_terminal),
                "a detached direct child still has the same live wait owner"
            );
            assert!(Arc::ptr_eq(&old_event, terminal.event.event()));
            assert_eq!(
                SPAWN_WORKER_COUNTS.lock().get(&root.into()).copied(),
                Some(1)
            );
            assert!(
                Running::new_on_ptracer_thread(root.into())
                    .unwrap()
                    .terminal_cleanup()
                    .same_generation(&terminal)
            );
            let (stopped, event) =
                tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                    .await
                    .unwrap()
                    .unwrap()
                    .assume_stopped();
            assert_eq!(stopped.pid(), root.into());
            assert_eq!(
                event,
                if method == LegacyAttachMethod::Attach {
                    crate::Event::Signal(Signal::SIGSTOP)
                } else {
                    crate::Event::Stop
                }
            );
            stopped.setoptions(legacy_thread_options()).unwrap();
            assert_eq!(
                unsafe { libc::write(release.as_raw_fd(), c"x".as_ptr().cast(), 1) },
                1
            );
            let running = stopped.resume(None).unwrap();
            let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit.as_mut())
                .await
                .unwrap()
                .unwrap();
            cleanup.mark_claimed_exit();
            assert!(!terminal.wait(Duration::ZERO));
            assert_eq!(
                tokio::time::timeout(
                    TRACEE_WAIT_TIMEOUT,
                    stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
                )
                .await
                .unwrap()
                .unwrap()
                .assume_exited(),
                (root.into(), crate::ExitStatus::Exited(42))
            );
            assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
            assert!(old_terminal.wait(Duration::ZERO));
            assert!(old_terminal.event.hold_tid().is_none());
            cleanup.disarm();
            drop((detached, running));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn nonchild_detach_reattach_preserves_one_wait_owner() {
    if run_legacy_test_outer("nonchild_detach_reattach_preserves_one_wait_owner") {
        return;
    }
    for force_legacy in [false, true] {
        for method in [LegacyAttachMethod::Attach, LegacyAttachMethod::Seize] {
            let [receipt, send_receipt] = legacy_pipe();
            let [start, release] = legacy_pipe();
            let real_parent = match unsafe { fork() }.unwrap() {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    unsafe {
                        libc::close(receipt.as_raw_fd());
                        libc::close(release.as_raw_fd());
                    }
                    let target = unsafe { libc::fork() };
                    if target < 0 {
                        unsafe { libc::_exit(125) };
                    }
                    if target == 0 {
                        unsafe { libc::close(send_receipt.as_raw_fd()) };
                        let mut byte = 0u8;
                        if unsafe {
                            libc::read(start.as_raw_fd(), (&mut byte as *mut u8).cast(), 1)
                        } != 1
                        {
                            unsafe { libc::_exit(126) };
                        }
                        unsafe { libc::_exit(42) };
                    }
                    unsafe { libc::close(start.as_raw_fd()) };
                    if unsafe {
                        libc::write(
                            send_receipt.as_raw_fd(),
                            (&target as *const i32).cast(),
                            mem::size_of::<i32>(),
                        )
                    } != mem::size_of::<i32>() as isize
                    {
                        unsafe { libc::_exit(127) };
                    }
                    let mut status = 0i32;
                    if unsafe { libc::waitpid(target, &mut status, 0) } != target {
                        unsafe { libc::_exit(128) };
                    }
                    if unsafe {
                        libc::write(
                            send_receipt.as_raw_fd(),
                            (&status as *const i32).cast(),
                            mem::size_of::<i32>(),
                        )
                    } != mem::size_of::<i32>() as isize
                    {
                        unsafe { libc::_exit(129) };
                    }
                    unsafe { libc::_exit(0) };
                }
            };
            drop((send_receipt, start));
            let mut parent_cleanup = TraceeCleanupGuard::new(real_parent).unwrap();
            let mut receipts = fs::File::from(receipt);
            let mut bytes = [0u8; mem::size_of::<i32>()];
            receipts.read_exact(&mut bytes).unwrap();
            let root = Pid::from_raw(i32::from_ne_bytes(bytes));
            let _force = force_legacy.then(|| LegacyThreadGroup::new(root));
            let mut old_cleanup = TraceeCleanupGuard::new(root).unwrap();
            let running =
                Running::seize_on_ptracer_thread(root.into(), legacy_thread_options()).unwrap();
            old_cleanup.bind_running_notifier(&running).unwrap();
            let old_terminal = running.terminal_cleanup();
            running.interrupt().unwrap();
            let (stopped, event) =
                tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                    .await
                    .unwrap()
                    .unwrap()
                    .assume_stopped();
            assert_eq!(event, crate::Event::Stop);
            // The original descriptor waiter may remain blocked after a
            // nonchild detach. It is still the one wait owner, and reattach
            // must either retain it or join an already committed retirement.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let detached = stopped.detach(None).unwrap();
            assert!(
                old_terminal
                    .event
                    .identity()
                    .unwrap()
                    .pidfd_is_live()
                    .unwrap()
            );

            let running = match method {
                LegacyAttachMethod::Attach => {
                    Running::attach_on_ptracer_thread(root.into()).unwrap()
                }
                LegacyAttachMethod::Seize => {
                    let running =
                        Running::seize_on_ptracer_thread(root.into(), legacy_thread_options())
                            .unwrap();
                    running.interrupt().unwrap();
                    running
                }
                LegacyAttachMethod::Traceme => unreachable!(),
            };
            let same_owner = Arc::ptr_eq(running.1.event().event(), old_terminal.event.event());
            let mut cleanup = if same_owner {
                old_cleanup
            } else {
                assert!(old_terminal.wait(Duration::ZERO));
                assert!(old_terminal.event.hold_tid().is_none());
                assert_eq!(
                    old_terminal.event.event().status.lock().terminal,
                    ECHILD_STATUS
                );
                old_cleanup.disarm();
                TraceeCleanupGuard::new(root).unwrap()
            };
            cleanup.bind_running_notifier(&running).unwrap();
            let terminal = running.terminal_cleanup();
            assert_eq!(terminal.same_generation(&old_terminal), same_owner);
            assert_eq!(
                SPAWN_WORKER_COUNTS.lock().get(&root.into()).copied(),
                Some(if same_owner { 1 } else { 2 })
            );
            assert!(
                Running::new_on_ptracer_thread(root.into())
                    .unwrap()
                    .terminal_cleanup()
                    .same_generation(&terminal)
            );
            let (stopped, event) =
                tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                    .await
                    .unwrap()
                    .unwrap()
                    .assume_stopped();
            assert_eq!(stopped.pid(), root.into());
            assert_eq!(
                event,
                if method == LegacyAttachMethod::Attach {
                    crate::Event::Signal(Signal::SIGSTOP)
                } else {
                    crate::Event::Stop
                }
            );
            stopped.setoptions(legacy_thread_options()).unwrap();
            stopped.getregs().unwrap();
            let mut exit = Box::pin(cleanup.exit_event_on_ptracer_thread(&stopped).unwrap());
            assert_eq!(
                unsafe { libc::write(release.as_raw_fd(), c"x".as_ptr().cast(), 1) },
                1
            );
            let running = stopped.resume(None).unwrap();
            let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit.as_mut())
                .await
                .unwrap()
                .unwrap();
            cleanup.mark_claimed_exit();
            assert!(!terminal.wait(Duration::ZERO));
            assert_eq!(
                tokio::time::timeout(
                    TRACEE_WAIT_TIMEOUT,
                    stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
                )
                .await
                .unwrap()
                .unwrap()
                .assume_exited(),
                (root.into(), crate::ExitStatus::Exited(42))
            );
            assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
            cleanup.disarm();
            receipts.read_exact(&mut bytes).unwrap();
            let status = i32::from_ne_bytes(bytes);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 42);
            assert_eq!(
                waitpid_status_bounded(real_parent, 0, TRACEE_WAIT_TIMEOUT).unwrap(),
                0
            );
            parent_cleanup.disarm();
            assert!(old_terminal.wait(Duration::ZERO));
            if !same_owner {
                assert_eq!(
                    old_terminal.event.event().status.lock().terminal,
                    ECHILD_STATUS
                );
            }
            assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
            drop((detached, running));
        }
    }
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_nonleader_reattach_joins_retired_owner() {
    if run_legacy_test_outer("forced_legacy_nonleader_reattach_joins_retired_owner") {
        return;
    }
    for method in [LegacyAttachMethod::Attach, LegacyAttachMethod::Seize] {
        let [receipt, send_receipt] = legacy_pipe();
        let [thread_start, thread_release] = legacy_pipe();
        let [root_start, root_release] = legacy_pipe();
        let root = match unsafe { fork() }.unwrap() {
            ForkResult::Parent { child } => child,
            ForkResult::Child => {
                unsafe {
                    libc::close(receipt.as_raw_fd());
                    libc::close(thread_release.as_raw_fd());
                    libc::close(root_release.as_raw_fd());
                }
                extern "C" fn guest_thread(argument: *mut libc::c_void) -> *mut libc::c_void {
                    let descriptors = unsafe { &*argument.cast::<[i32; 2]>() };
                    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
                    if unsafe {
                        libc::write(
                            descriptors[0],
                            (&tid as *const i32).cast(),
                            mem::size_of::<i32>(),
                        )
                    } != mem::size_of::<i32>() as isize
                    {
                        unsafe { libc::_exit(125) };
                    }
                    let mut byte = 0u8;
                    if unsafe { libc::read(descriptors[1], (&mut byte as *mut u8).cast(), 1) } != 1
                    {
                        unsafe { libc::_exit(126) };
                    }
                    unsafe { libc::syscall(libc::SYS_exit, 23) };
                    std::ptr::null_mut()
                }
                let mut descriptors = [send_receipt.as_raw_fd(), thread_start.as_raw_fd()];
                let mut thread = mem::MaybeUninit::<libc::pthread_t>::uninit();
                if unsafe {
                    libc::pthread_create(
                        thread.as_mut_ptr(),
                        std::ptr::null(),
                        guest_thread,
                        descriptors.as_mut_ptr().cast(),
                    )
                } != 0
                {
                    unsafe { libc::_exit(127) };
                }
                if unsafe { libc::pthread_join(thread.assume_init(), std::ptr::null_mut()) } != 0 {
                    unsafe { libc::_exit(128) };
                }
                // pthread_join's clear-child-TID can precede the ptracer's
                // final wait. Keep the root alive until that actual reap.
                let mut byte = 0u8;
                if unsafe { libc::read(root_start.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) }
                    != 1
                {
                    unsafe { libc::_exit(129) };
                }
                unsafe { libc::_exit(42) };
            }
        };
        drop((send_receipt, thread_start, root_start));
        let mut root_cleanup = TraceeCleanupGuard::new(root).unwrap();
        let mut receipts = fs::File::from(receipt);
        let mut bytes = [0u8; mem::size_of::<i32>()];
        receipts.read_exact(&mut bytes).unwrap();
        let tid = Pid::from_raw(i32::from_ne_bytes(bytes));
        assert_ne!(tid, root);
        let _force = LegacyThreadGroup::new(root);
        let running =
            Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
        let mut old_cleanup = legacy_child_cleanup(&running);
        let old_terminal = running.terminal_cleanup();
        assert!(matches!(
            old_terminal.event.identity().unwrap().pidfd,
            ThreadHandle::Procfs { .. }
        ));
        running.interrupt().unwrap();
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, crate::Event::Stop);
        let detached = stopped.detach(None).unwrap();
        assert!(old_terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert!(old_terminal.event.hold_tid().is_none());
        assert!(
            old_terminal
                .event
                .identity()
                .unwrap()
                .pidfd_is_live()
                .unwrap()
        );
        assert_eq!(
            old_terminal.event.event().status.lock().terminal,
            ECHILD_STATUS
        );
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
            Some(1)
        );
        old_cleanup.disarm();

        let running = match method {
            LegacyAttachMethod::Attach => Running::attach_on_ptracer_thread(tid.into()).unwrap(),
            LegacyAttachMethod::Seize => {
                let running =
                    Running::seize_on_ptracer_thread(tid.into(), legacy_thread_options()).unwrap();
                running.interrupt().unwrap();
                running
            }
            LegacyAttachMethod::Traceme => unreachable!(),
        };
        let mut cleanup = legacy_child_cleanup(&running);
        let terminal = running.terminal_cleanup();
        assert!(!terminal.same_generation(&old_terminal));
        assert!(old_terminal.wait(Duration::ZERO));
        assert!(old_terminal.event.hold_tid().is_none());
        assert_eq!(
            old_terminal.event.event().status.lock().terminal,
            ECHILD_STATUS
        );
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&tid.into()).copied(),
            Some(2)
        );
        assert!(
            Running::new_on_ptracer_thread(tid.into())
                .unwrap()
                .terminal_cleanup()
                .same_generation(&terminal)
        );
        let (stopped, event) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(stopped.pid(), tid.into());
        assert_eq!(
            event,
            if method == LegacyAttachMethod::Attach {
                crate::Event::Signal(Signal::SIGSTOP)
            } else {
                crate::Event::Stop
            }
        );
        stopped.getregs().unwrap();
        stopped.setoptions(legacy_thread_options()).unwrap();
        let mut exit = Box::pin(cleanup.exit_event_on_ptracer_thread(&stopped).unwrap());
        assert_eq!(
            unsafe { libc::write(thread_release.as_raw_fd(), c"x".as_ptr().cast(), 1) },
            1
        );
        let running = stopped.resume(None).unwrap();
        let stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit.as_mut())
            .await
            .unwrap()
            .unwrap();
        cleanup.mark_claimed_exit();
        assert!(!terminal.wait(Duration::ZERO));
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (tid.into(), crate::ExitStatus::Exited(23))
        );
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
        assert_eq!(
            old_terminal.event.event().status.lock().terminal,
            ECHILD_STATUS
        );
        cleanup.disarm();
        assert_eq!(
            unsafe { libc::write(root_release.as_raw_fd(), c"x".as_ptr().cast(), 1) },
            1
        );
        let status = waitpid_status_bounded(root, 0, TRACEE_WAIT_TIMEOUT).unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 42);
        root_cleanup.disarm();
        drop((detached, running));
    }
}

// A legacy non-leader's stops reach its waiter without waiting out the
// worker's poll period. Fast single steps: the ptracer's consume wakes the
// worker to publish. Syscall stops resumed after the ptracer was busy for
// longer than the period, each entry about 300 µs after the resumption:
// the resumption wakes the worker to observe. With 1 ms polling, every one
// of these stops took up to two whole periods.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_nonleader_steps_are_not_paced_by_the_poll_period() {
    if run_legacy_test_outer("forced_legacy_nonleader_steps_are_not_paced_by_the_poll_period") {
        return;
    }
    const FAST_STEPS: usize = 200;
    const BUSY_SYSCALLS: usize = 20;
    let (_root, stopped, _root_cleanup, _force) = spawn_legacy_threads(
        &[1],
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    let (_parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing spinning pthread clone");
    };
    let _child_cleanup = legacy_child_cleanup(&child);
    let event = Arc::clone(child.terminal_cleanup().event.event());
    let (mut child, sigstop) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(sigstop, crate::Event::Signal(Signal::SIGSTOP));
    let late_turns = || event.legacy_late_turns.load(Ordering::Relaxed);
    let before = late_turns();
    for _ in 0..FAST_STEPS {
        let (stepped, trap) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.step(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(trap, crate::Event::Signal(Signal::SIGTRAP));
        child = stepped;
    }
    let fast_late = late_turns() - before;
    assert!(
        fast_late < FAST_STEPS / 4,
        "{fast_late} of {FAST_STEPS} fast steps waited out the poll period"
    );
    let before = late_turns();
    // Entry and exit stops: every entry comes about 300 µs after its resumption.
    for _ in 0..2 * BUSY_SYSCALLS {
        // Long enough for the worker to back off to the whole period.
        thread::sleep(LEGACY_POLL_PERIOD * 3);
        let (next, stop) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.syscall(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        assert_eq!(stop, crate::Event::Syscall);
        child = next;
    }
    let busy_late = late_turns() - before;
    assert!(
        busy_late < BUSY_SYSCALLS,
        "{busy_late} of {} syscall stops after a busy ptracer waited out the poll period",
        2 * BUSY_SYSCALLS
    );
}

/// Counts this thread's retained status reads during each legacy consuming
/// attempt until `done`, asserting that no attempt reads more than once, and
/// returns how many attempts read.
fn legacy_attempt_reads(terminal: &TerminalCleanup, done: impl Fn() -> bool) -> usize {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    let mut attempts_that_read = 0;
    loop {
        let before = RETAINED_STATUS_READS.with(Cell::get);
        terminal.event.try_assist_legacy_wait().unwrap();
        let reads = RETAINED_STATUS_READS.with(Cell::get) - before;
        assert!(
            reads <= 1,
            "one legacy consuming attempt read status {reads} times"
        );
        attempts_that_read += reads;
        if done() {
            return attempts_that_read;
        }
        assert!(
            Instant::now() < deadline,
            "legacy consuming attempts never finished"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// A consuming attempt on the legacy path reads the target's retained status
/// once, whether it finds nothing or consumes a stop: the read follows the
/// numeric observation, so it is both that observation's postcheck and the
/// owner's authentication. The observation worker's turns that find nothing
/// read it at most once per LEGACY_CHECK_PERIOD.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_waits_read_target_status_once_per_attempt_or_period() {
    if run_legacy_test_outer("forced_legacy_waits_read_target_status_once_per_attempt_or_period") {
        return;
    }
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_thread_tracee(true);
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let root_terminal = stopped.terminal_cleanup();
    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing paused pthread clone");
    };
    let child_tid = child.pid();
    let mut child_cleanup = legacy_child_cleanup(&child);
    let terminal = child.terminal_cleanup();
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let parent_running = parent.resume(None).unwrap();
    let child_running = child.resume(None).unwrap();

    // The thread sleeps in pause(), so every worker turn finds nothing.
    // Each turn used to read status; now one read covers LEGACY_CHECK_PERIOD.
    let worker = terminal.event.event().clone();
    let counts = || {
        (
            worker.legacy_worker_turns.load(Ordering::Relaxed),
            worker.legacy_worker_status_reads.load(Ordering::Relaxed),
        )
    };
    let (turns_before, reads_before) = counts();
    let start = Instant::now();
    let deadline = start + TRACEE_WAIT_TIMEOUT;
    loop {
        thread::sleep(Duration::from_millis(20));
        let (turns, reads) = counts();
        let elapsed = start.elapsed();
        let (turns, reads) = (turns - turns_before, reads - reads_before);
        let period_bound = (elapsed.as_millis() / LEGACY_CHECK_PERIOD.as_millis()) as usize + 2;
        assert!(
            reads <= period_bound,
            "empty worker turns read status {reads} times in {turns} turns over {elapsed:?}"
        );
        // More turns than the period allows checks: some turns skipped it.
        if turns > period_bound {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "worker took only {turns} turns over {elapsed:?}"
        );
    }

    // Every ptracer attempt finds nothing as well.
    let attempts = std::cell::Cell::new(0);
    let empty = legacy_attempt_reads(&terminal, || {
        attempts.set(attempts.get() + 1);
        attempts.get() == 32
    });
    assert!(empty > 0, "no empty attempt reached its authentication");
    assert!(terminal.event.event().pending_is_empty());

    let state = || {
        fs::read_to_string(format!("/proc/{root}/task/{child_tid}/stat"))
            .ok()
            .and_then(|stat| {
                Some(
                    stat.rsplit_once(')')?
                        .1
                        .split_whitespace()
                        .next()?
                        .to_owned(),
                )
            })
    };
    request_fixture_thread_sigstop(root, child_tid);
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while state().as_deref() != Some("t") {
        assert!(Instant::now() < deadline, "thread never reached its stop");
        thread::sleep(Duration::from_millis(1));
    }
    let event = terminal.event.event().clone();
    let consumed = || !event.legacy_wait.lock().consumed.is_empty() || !event.pending_is_empty();
    assert!(legacy_attempt_reads(&terminal, consumed) > 0);
    let (child, event) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        child_running.wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(child.pid(), child_tid);
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));

    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    terminal.request_sigkill().unwrap();
    drop(child);
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    child_cleanup.mark_claimed_exit();
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            child_tid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    child_cleanup.disarm();

    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    drop(parent_running);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

/// Waits until the legacy worker of `event` hints at a status that nothing
/// has consumed yet, which only its own turns can do.
fn wait_for_legacy_hint(event: &Event, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while event.legacy_wait.lock().observed.is_none() {
        assert!(Instant::now() < deadline, "{what}: the worker never observed it");
        thread::sleep(Duration::from_micros(200));
    }
}

/// Waits until the legacy worker of `event` has started a held wait after
/// `before` of them.
fn wait_for_held_wait(event: &Event, before: usize, what: &str) {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while event.legacy_held_waits.load(Ordering::Relaxed) <= before {
        assert!(Instant::now() < deadline, "{what}: the worker never held the stop");
        thread::sleep(Duration::from_micros(200));
    }
}

/// Resumes `stopped` to its next syscall stop and returns that stop.
async fn next_syscall_stop(stopped: Stopped) -> Stopped {
    let (next, stop) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.syscall(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(stop, crate::Event::Syscall);
    next
}

// A resumption that races a legacy worker's hold is not lost. The held
// non-leader loops reading a pipe. Each round stops it at a read entry and
// pauses its worker at one of the two points of the race, resumes it into
// the read during the pause, and releases the worker. Only then, after the
// worker has had time to settle into whatever wait it chose, does the pipe
// get a byte: the read's exit stop must reach the worker's own turns
// although the held period outlasts the test, with nothing consuming it in
// between. Even rounds pause right after the worker published the entry
// stop, odd rounds after it decided to wait as held, before it takes the
// lock to do so. Reading the wakeup count after the publish pause, or
// waiting without comparing the counts under that lock, leaves the worker in
// a held wait here. (No pause point can separate the publication from a read
// placed right after it: the read must stay before `event.update`.) A
// cancellation signal then kills the group, and the worker must observe the
// last thread's exit stop by itself.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_resume_racing_a_held_wait_is_not_lost() {
    if run_legacy_test_outer("forced_legacy_resume_racing_a_held_wait_is_not_lost") {
        return;
    }
    const ROUNDS: usize = 10;
    let [read_end, write_end] = legacy_pipe();
    let modes: &'static [usize] = Box::leak(Box::new([1000 + read_end.as_raw_fd() as usize]));
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_threads(
        modes,
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    drop(read_end);
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let root_terminal = stopped.terminal_cleanup();
    let write_byte = || {
        assert_eq!(
            unsafe { libc::write(write_end.as_raw_fd(), b"r".as_ptr().cast(), 1) },
            1
        )
    };
    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing reading pthread clone");
    };
    let child_tid = child.pid();
    let mut child_cleanup = legacy_child_cleanup(&child);
    let terminal = child.terminal_cleanup();
    let event = Arc::clone(terminal.event.event());
    *event.legacy_held_period.lock() = Some(Duration::from_secs(60));
    let (mut child, sigstop) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(sigstop, crate::Event::Signal(Signal::SIGSTOP));
    let parent_running = parent.resume(None).unwrap();
    let read_fd = modes[0] as u64 - 1000;
    let is_read_entry = |stopped: &Stopped| {
        matches!(
            stopped.getsyscallinfo().unwrap().operation,
            crate::SyscallInfoOp::Entry { number, arguments }
                if number == libc::SYS_read as u64 && arguments[0] == read_fd
        )
    };
    // Run the thread's start-up to its first read, then through that read.
    let mut entries = 0;
    while !is_read_entry(&child) {
        entries += 1;
        assert!(entries < 200, "the thread never reached its read");
        child = next_syscall_stop(child).await;
    }
    let mut held = event.legacy_held_waits.load(Ordering::Relaxed);
    let running = child.syscall(None).unwrap();
    write_byte();
    let (mut child, _) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    for round in 0..ROUNDS {
        // At the previous read's exit stop: wait until the worker holds it,
        // so that the pause below can only take the next stop.
        wait_for_held_wait(&event, held, &format!("round {round}: read exit"));
        let (captured, capture) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let pause = BoundedTestPause {
            captured,
            resume: released,
        };
        if round % 2 == 0 {
            *event.legacy_publish_pause.lock() = Some(pause);
        } else {
            *event.legacy_held_wait_pause.lock() = Some(pause);
        }
        let entry = next_syscall_stop(child).await;
        capture
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .unwrap_or_else(|_| panic!("round {round}: the worker never reached the pause"));
        assert!(is_read_entry(&entry), "round {round}: not at the read entry");
        let running = entry.syscall(None).unwrap();
        release.send(()).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(event.legacy_wait.lock().observed.is_none());
        write_byte();
        wait_for_legacy_hint(&event, &format!("round {round}: read exit"));
        held = event.legacy_held_waits.load(Ordering::Relaxed);
        let (exit, stop) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(stop, crate::Event::Syscall);
        child = exit;
    }

    // The signal's wakeup, or the leader's exit-stop probe, brings the held
    // worker to the exit stop. Nothing polls `exit` until it has observed it.
    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    terminal.request_sigkill().unwrap();
    wait_for_legacy_hint(&event, "the cancellation signal");
    drop(child);
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    child_cleanup.mark_claimed_exit();
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            child_tid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    child_cleanup.disarm();
    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    drop(parent_running);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}

// While the ptracer holds a legacy non-leader in a stop, its worker waits
// for a wakeup instead of polling: no turns while held. A group SIGKILL from
// outside, which no request of the ptracer reports, still reaches the
// worker without waiting out the held period: the leader's exit stop
// probes it.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_held_worker_waits_for_a_wakeup_or_probe() {
    if run_legacy_test_outer("forced_legacy_held_worker_waits_for_a_wakeup_or_probe") {
        return;
    }
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_thread_tracee(true);
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let root_terminal = stopped.terminal_cleanup();
    let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
        TRACEE_WAIT_TIMEOUT,
        stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped() else {
        panic!("missing paused pthread clone");
    };
    let child_tid = child.pid();
    let mut child_cleanup = legacy_child_cleanup(&child);
    let terminal = child.terminal_cleanup();
    let worker = terminal.event.event().clone();
    *worker.legacy_held_period.lock() = Some(Duration::from_secs(60));
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let parent_running = parent.resume(None).unwrap();

    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while worker.legacy_held_waits.load(Ordering::Relaxed) == 0 {
        assert!(Instant::now() < deadline, "the worker never held the stop");
        thread::sleep(Duration::from_millis(1));
    }
    let turns = || worker.legacy_worker_turns.load(Ordering::Relaxed);
    let before = turns();
    thread::sleep(Duration::from_millis(200));
    let held_turns = turns() - before;
    assert_eq!(held_turns, 0, "a held worker took {held_turns} turns in 200 ms");

    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    // Neither a ptrace request nor a cancellation signal of this ptracer.
    assert_eq!(unsafe { libc::kill(root.as_raw(), libc::SIGKILL) }, 0);
    // Nothing polls `exit` until the worker has observed the exit stop on
    // its own turns, so that a consume by the ptracer cannot stand in for
    // the probe.
    wait_for_legacy_hint(&worker, "the group kill");
    drop(child);
    let child = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, exit)
        .await
        .unwrap()
        .unwrap();
    child_cleanup.mark_claimed_exit();
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            child.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            child_tid,
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    child_cleanup.disarm();

    let parent = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, root_exit)
        .await
        .unwrap()
        .unwrap();
    root_cleanup.mark_claimed_exit();
    drop(parent_running);
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (
            root.into(),
            crate::ExitStatus::Signaled(Signal::SIGKILL, false)
        ),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
}
