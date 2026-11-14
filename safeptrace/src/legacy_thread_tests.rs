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
    run_legacy_test_outer_checked(name, marker, |_| {})
}

/// [`run_legacy_test_outer_with_outcome`], and `check` then inspects the
/// inner run.
#[cfg(not(sanitized))]
fn run_legacy_test_outer_checked(
    name: &str,
    marker: Option<&str>,
    check: impl FnOnce(&BoundedSubprocess),
) -> bool {
    let Some(result) = run_legacy_test_outer_bounded(name) else {
        return false;
    };
    if let Some(marker) = marker {
        assert!(
            String::from_utf8_lossy(&result.output.stdout)
                .lines()
                .any(|line| line == marker),
            "legacy-thread test omitted actual outcome marker {marker}: {result:?}"
        );
        emit_completion_marker(marker);
    }
    check(&result);
    true
}

/// As [`run_legacy_test_outer`], and re-emits each line of the inner run's
/// stdout that starts with `prefix`, so that a passing run's report reaches
/// the outer log.
#[cfg(not(sanitized))]
fn run_legacy_test_outer_reporting(name: &str, prefix: &str) -> bool {
    let Some(result) = run_legacy_test_outer_bounded(name) else {
        return false;
    };
    for line in String::from_utf8_lossy(&result.output.stdout)
        .lines()
        .filter(|line| line.starts_with(prefix))
    {
        emit_completion_marker(line);
    }
    true
}

/// Runs the test `name` alone in a bounded child process and asserts that it
/// passed, returning its result. In that child process, returns `None`.
#[cfg(not(sanitized))]
fn run_legacy_test_outer_bounded(name: &str) -> Option<BoundedSubprocess> {
    const INNER: &str = "SAFEPTRACE_LEGACY_THREAD_INNER";
    if env::var(INNER).as_deref() == Ok(name) {
        return None;
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
    Some(result)
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
                if mode >= 2000 {
                    // Read one byte, then exit.
                    let mut byte = 0u8;
                    unsafe { libc::read((mode - 2000) as i32, (&mut byte as *mut u8).cast(), 1) };
                    unsafe { libc::syscall(libc::SYS_exit, 0) };
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

/// What one legacy consuming attempt did on this thread.
#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LegacyAttempt {
    /// Retained status reads.
    reads: usize,
    /// Stop proofs that authenticated the owner without a read.
    accepted: usize,
    /// Stop proofs tried for a bound owner that did not complete.
    refused: usize,
    /// Statuses this attempt consumed and queued for the worker.
    consumed: usize,
}

#[cfg(not(sanitized))]
impl LegacyAttempt {
    fn now() -> Self {
        Self {
            reads: RETAINED_STATUS_READS.with(Cell::get),
            accepted: LEGACY_STOP_PROOFS_ACCEPTED.with(Cell::get),
            refused: LEGACY_STOP_PROOFS_REFUSED.with(Cell::get),
            consumed: LEGACY_ASSIST_CONSUMPTIONS.with(Cell::get),
        }
    }

    fn since(before: Self) -> Self {
        let after = Self::now();
        Self {
            reads: after.reads - before.reads,
            accepted: after.accepted - before.accepted,
            refused: after.refused - before.refused,
            consumed: after.consumed - before.consumed,
        }
    }
}

/// Runs legacy consuming attempts on this thread until `done` accepts the
/// latest one, asserting that no attempt reads status or consumes more than
/// once, and returns what each attempt did, in order.
#[cfg(not(sanitized))]
fn legacy_attempts(
    terminal: &TerminalCleanup,
    mut done: impl FnMut(&LegacyAttempt) -> bool,
) -> Vec<LegacyAttempt> {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    let mut attempts = Vec::new();
    loop {
        let before = LegacyAttempt::now();
        terminal.event.try_assist_legacy_wait().unwrap();
        let attempt = LegacyAttempt::since(before);
        assert!(
            attempt.reads <= 1,
            "one legacy consuming attempt read status {} times",
            attempt.reads
        );
        assert!(
            attempt.consumed <= 1,
            "one legacy consuming attempt consumed {} statuses",
            attempt.consumed
        );
        attempts.push(attempt);
        if done(&attempt) {
            return attempts;
        }
        assert!(
            Instant::now() < deadline,
            "legacy consuming attempts never finished"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

/// Runs legacy consuming attempts on this thread until one consumes a
/// status, and returns them all: exactly the last one consumed. The loop
/// ends on this thread's own consumption, never on the worker's publication:
/// from the worker's pop of `consumed` until its `update` returns, neither
/// `consumed` nor `pending` shows the status.
#[cfg(not(sanitized))]
fn legacy_attempts_until_consumed(terminal: &TerminalCleanup) -> Vec<LegacyAttempt> {
    legacy_attempts(terminal, |attempt| attempt.consumed == 1)
}

/// A ptracer attempt on the legacy path that finds nothing reads the target's
/// retained status once: the read follows the numeric observation, so it is
/// both that observation's postcheck and the owner's authentication. An
/// attempt that consumes a stop proves the same two things without reading
/// status: GETEVENTMSG on the number, then signal 0 through the retained
/// descriptor. The observation worker's turns that find nothing read it at
/// most once per LEGACY_CHECK_PERIOD.
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

    // Every ptracer attempt finds nothing as well, so none runs the stop
    // proof, and each authenticates through at most one read.
    let mut attempts = 0;
    let empty = legacy_attempts(&terminal, |_| {
        attempts += 1;
        attempts == 32
    });
    assert!(
        empty
            .iter()
            .all(|attempt| attempt.accepted == 0 && attempt.refused == 0),
        "an attempt that found nothing ran the stop proof: {empty:?}"
    );
    assert!(
        empty.iter().all(|attempt| attempt.consumed == 0),
        "an attempt consumed with nothing to consume: {empty:?}"
    );
    let empty_reads: usize = empty.iter().map(|attempt| attempt.reads).sum();
    assert!(
        empty_reads > 0,
        "no empty attempt reached its authentication"
    );
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
    // The attempt that consumes the stop authenticates its owner itself,
    // through the stop proof and without a read. No earlier attempt proved
    // anything without consuming. The wait below then returns the stop the
    // worker published.
    let mut attempts = legacy_attempts_until_consumed(&terminal);
    let evidence: usize = attempts
        .iter()
        .map(|attempt| attempt.reads + attempt.accepted)
        .sum();
    assert!(evidence > 0, "no consuming-phase attempt authenticated");
    let consuming = attempts.pop().unwrap();
    assert_eq!(
        consuming,
        LegacyAttempt {
            reads: 0,
            accepted: 1,
            refused: 0,
            consumed: 1,
        },
        "the consuming attempt did not prove its owner without a read"
    );
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.accepted == 0 && attempt.consumed == 0),
        "an attempt proved its owner or consumed before the consuming one: {attempts:?}"
    );
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
#[cfg(not(sanitized))]
fn wait_for_legacy_hint(event: &Event, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while event.legacy_wait.lock().observed.is_none() {
        assert!(Instant::now() < deadline, "{what}: the worker never observed it");
        thread::sleep(Duration::from_micros(200));
    }
}

/// Waits until the legacy worker of `event` has started a held wait after
/// `before` of them.
#[cfg(not(sanitized))]
fn wait_for_held_wait(event: &Event, before: usize, what: &str) {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while event.legacy_held_waits.load(Ordering::Relaxed) <= before {
        assert!(Instant::now() < deadline, "{what}: the worker never held the stop");
        thread::sleep(Duration::from_micros(200));
    }
}

/// Waits until the legacy worker of `event` is parked in a held wait that
/// started after `before` of them, and after it had observed every wakeup
/// already delivered to it.
///
/// A count and its notify are separate steps: the notify follows once the
/// notifier has released its locks. A notify for a count that the worker
/// has already acted on can therefore arrive after the worker parked, and
/// end that park with one more turn. Such a held wait is not yet quiescent.
/// Every notify that woke the worker is counted, and so is every wait of the
/// worker that a notify ended, one for one (only the worker waits on
/// `legacy_wake`, and parking_lot's condvar has no spurious wakeups). A held
/// wait that began once the worker had observed as many wakes as had been
/// delivered cannot be ended by any of them. A worker still due a delivered
/// wake takes that turn and parks again, so the wait ends.
///
/// Every notifier of `event` must have returned from
/// [`Event::notify_legacy_worker`] before the call, and no other may start
/// during it: a notify still in flight is not counted yet (see there).
///
/// `while_waiting` runs on each poll that does not see such a park yet.
fn wait_for_fresh_held_wait(
    event: &Event,
    before: usize,
    what: &str,
    mut while_waiting: impl FnMut(),
) {
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    loop {
        let delivered = event.legacy_notify_wakes.load(Ordering::Relaxed);
        if event.legacy_held_waits.load(Ordering::Relaxed) > before
            && event.legacy_held_wait_wakes.load(Ordering::Relaxed) >= delivered
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: the worker never parked held after its last delivered wakeup"
        );
        while_waiting();
        thread::sleep(Duration::from_micros(200));
    }
}

/// Resumes `stopped` to its next syscall stop and returns that stop.
#[cfg(not(sanitized))]
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
    legacy_resume_racing_a_held_wait(None).await;
}

// The order of a failed run of the test above, forced. The consume of a read
// exit notified the worker only after the worker had published that stop
// and parked held, and the next round's sync accepted that park. The late
// wake then gave the worker a turn on the old stop once the round had armed
// its held-wait pause, so the pause took the old stop, not the read entry.
// Here the consume before round 1, an odd round, notifies late: its notify
// waits until the worker parked held, and the woken worker is held at the
// start of the turn the notify gives it. The round's sync must wait that
// turn out.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_resume_racing_a_held_wait_waits_out_a_late_consume_notify() {
    if run_legacy_test_outer(
        "forced_legacy_resume_racing_a_held_wait_waits_out_a_late_consume_notify",
    ) {
        return;
    }
    legacy_resume_racing_a_held_wait(Some(1)).await;
}

/// The body of `forced_legacy_resume_racing_a_held_wait_is_not_lost`. With
/// `late_notify_round`, an odd round, the consume of the read exit before
/// that round notifies late ([`notify_after_held_park`]).
#[cfg(not(sanitized))]
async fn legacy_resume_racing_a_held_wait(late_notify_round: Option<usize>) {
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
    // The turn a late notify gave the worker, paused at its start, and the
    // worker's count of waits a notify ended, once that notify had.
    let mut late_turn: Option<mpsc::SyncSender<()>> = None;
    let mut late_wake: Option<usize> = None;
    for round in 0..ROUNDS {
        // At the previous read's exit stop: wait until the worker holds it
        // after every wake delivered to it, so that the pause below can only
        // take the next stop. The wait that returned that stop ran the
        // consume's notify on this thread, and nothing else notifies the
        // worker until the resume below.
        wait_for_fresh_held_wait(&event, held, &format!("round {round}: read exit"), || {
            if let Some(release) = late_turn.take() {
                release.send(()).unwrap_or_else(|_| {
                    panic!("round {round}: the late turn resumed by itself before the sync released it")
                });
            }
        });
        let (captured, capture) = mpsc::sync_channel(1);
        let (release, released) = mpsc::sync_channel(1);
        let pause = BoundedTestPause {
            captured,
            resume: released,
        };
        // The resume below counts a wakeup before the next publication can
        // read the count, so only a stop published earlier has a count up to
        // this one.
        let armed = event.legacy_wakeup.lock().targeted;
        let slot = if round % 2 == 0 {
            &event.legacy_publish_pause
        } else {
            &event.legacy_held_wait_pause
        };
        *slot.lock() = Some(pause);
        let check_capture = || {
            if round % 2 == 1 {
                let (status, count) = event
                    .legacy_held_wait_paused_on
                    .lock()
                    .take()
                    .unwrap_or_else(|| panic!("round {round}: the held-wait pause recorded nothing"));
                assert!(
                    count > armed,
                    "round {round}: the pause captured the old stop: it held status {status:#x} \
                     published at targeted wakeup count {count}, and the pause was armed at {armed}"
                );
            }
        };
        let mut captured_before_resume = false;
        if let Some(release) = late_turn.take() {
            // The sync returned with the late turn still pending. If the
            // worker parked again after the late wake, that turn resumed by
            // itself and the schedule this test forces did not happen.
            assert!(
                event.legacy_held_wait_wakes.load(Ordering::Relaxed)
                    < event.legacy_notify_wakes.load(Ordering::Relaxed),
                "round {round}: the late turn resumed by itself (its pause's 2 s bound) before the \
                 sync could wait it out; the forced schedule did not happen"
            );
            // The sync accepted the held wait that the late notify ended. As
            // in the failed run, the late turn runs once the pause is armed
            // and before the resume. It must take the pause before anything
            // resumes the thread, so that only the old stop is there to take.
            // The bound is under the turn's own pause bound (2 s), so a turn
            // that never runs is not mistaken for one that ran.
            drop(release);
            capture
                .recv_timeout(Duration::from_secs(1))
                .unwrap_or_else(|_| panic!("round {round}: the late turn never reached the armed pause"));
            check_capture();
            captured_before_resume = true;
        } else if let Some(late_wake) = late_wake.take() {
            // The sync released the late turn and waited for the held wait
            // the worker started after it.
            let held_wait_wakes = event.legacy_held_wait_wakes.load(Ordering::Relaxed);
            assert!(
                held_wait_wakes >= late_wake
                    && event.legacy_worker_wakes.load(Ordering::Relaxed) == held_wait_wakes,
                "round {round}: the sync accepted a held wait that began before the late wake was \
                 observed"
            );
        }
        let entry = next_syscall_stop(child).await;
        if !captured_before_resume {
            capture
                .recv_timeout(TRACEE_WAIT_TIMEOUT)
                .unwrap_or_else(|_| panic!("round {round}: the worker never reached the pause"));
            check_capture();
        }
        assert!(is_read_entry(&entry), "round {round}: not at the read entry");
        let running = entry.syscall(None).unwrap();
        release
            .send(())
            .unwrap_or_else(|_| panic!("round {round}: the pause had already resumed by itself"));
        thread::sleep(Duration::from_millis(20));
        assert!(event.legacy_wait.lock().observed.is_none());
        write_byte();
        wait_for_legacy_hint(&event, &format!("round {round}: read exit"));
        held = event.legacy_held_waits.load(Ordering::Relaxed);
        let late = (late_notify_round == Some(round + 1))
            .then(|| notify_after_held_park(&event, held));
        let (exit, stop) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(stop, crate::Event::Syscall);
        if let Some(late) = late {
            late_turn = Some(late.join().unwrap());
            // The helper saw the late notify end the held wait, and the
            // worker is held at the start of its next turn.
            late_wake = Some(event.legacy_worker_wakes.load(Ordering::Relaxed));
        }
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

// A failing forced-procfs test unwinds through its armed cleanup guards,
// and they must tear the group down promptly. The non-leader's guard kills
// it, and the thread stops at its exit stop. A procfs worker publishes only
// what its ptracer consumes, so a guard that only observed would never see
// that stop, never resume it, and wait out its 2 s bound; the leader's guard
// then waits out its own, since the group cannot finish exiting. The guard
// runs on the ptracer and drives the generation from there instead. The
// guards' lookup of the registered generation must also capture as the
// generation's owner does, not with the native policy, whose refusal on a
// thread without a thread pidfd goes to stderr: the outer run requires the
// inner stderr to omit it.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_cleanup_guards_reap_a_held_nonleader_on_unwind() {
    if run_legacy_test_outer_checked(
        "forced_legacy_cleanup_guards_reap_a_held_nonleader_on_unwind",
        None,
        |result| {
            assert!(
                !result
                    .output
                    .stderr
                    .windows(NATIVE_THREAD_PIDFD_REQUIREMENT.len())
                    .any(|window| window == NATIVE_THREAD_PIDFD_REQUIREMENT),
                "a cleanup guard opened a native thread pidfd for a procfs generation: {result:?}"
            )
        },
    ) {
        return;
    }
    let reached = Arc::new(Mutex::new(None));
    let record = Arc::clone(&reached);
    let unwind = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async move {
        let (root, stopped, _root_cleanup, _force) = spawn_legacy_thread_tracee(true);
        let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) =
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
            )
            .await
            .unwrap()
            .unwrap()
            .assume_stopped()
        else {
            panic!("missing paused pthread clone");
        };
        let _child_cleanup = legacy_child_cleanup(&child);
        *child.terminal_cleanup().event.event().legacy_held_period.lock() =
            Some(Duration::from_secs(60));
        let (_child, sigstop) =
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(sigstop, crate::Event::Signal(Signal::SIGSTOP));
        let _parent_running = parent.resume(None).unwrap();
        *record.lock() = Some((root, Instant::now()));
        panic!("a failure with both cleanup guards armed");
    }))
    .await;
    assert!(unwind.is_err());
    let (root, panicked) = reached
        .lock()
        .take()
        .expect("the fixture failed before its deliberate panic");
    let unwound = panicked.elapsed();
    assert!(
        unwound < Duration::from_secs(1),
        "the armed cleanup guards took {unwound:?} to unwind"
    );
    assert!(
        !std::path::Path::new(&format!("/proc/{root}")).exists(),
        "the cleanup guards left the leader {root}"
    );
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

    wait_for_fresh_held_wait(&worker, 0, "the consumed SIGSTOP", || {});
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

/// Arms `slot` and returns the receiver of its capture signal and the sender
/// that releases it. Dropping the sender also releases it.
#[cfg(not(sanitized))]
fn arm_legacy_pause(
    slot: &Mutex<Option<BoundedTestPause>>,
) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (captured, capture) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    *slot.lock() = Some(BoundedTestPause { captured, resume });
    (capture, release)
}

/// Holds the notify of the ptracer's next consume (in
/// `try_assist_legacy_wait`) for the worker of `event` until that worker has
/// published the consumed stop and parked held after `held_before` held
/// waits, then lets the notify go with the worker's next turn paused at its
/// start. The thread returns the sender that releases that turn; dropping
/// it also does.
#[cfg(not(sanitized))]
fn notify_after_held_park(
    event: &Arc<Event>,
    held_before: usize,
) -> thread::JoinHandle<mpsc::SyncSender<()>> {
    let (notify_caught, notify_release) = arm_legacy_pause(&event.legacy_assist_notify_pause);
    let event = event.clone();
    thread::spawn(move || {
        notify_caught
            .recv_timeout(Duration::from_secs(2))
            .expect("the consume never reached its notify");
        // The ptracer counted, released `legacy_wait` and has not notified:
        // the worker publishes the stop and parks held meanwhile.
        let deadline = Instant::now() + Duration::from_millis(1500);
        while event.legacy_held_waits.load(Ordering::Relaxed) <= held_before {
            assert!(
                Instant::now() < deadline,
                "the worker never parked held before the late notify"
            );
            thread::sleep(Duration::from_micros(200));
        }
        // It counts under `legacy_wakeup` and releases it only once it is
        // queued on `legacy_wake`: holding the lock here means it is parked.
        drop(event.legacy_wakeup.lock());
        let parked = event.legacy_worker_wakes.load(Ordering::Relaxed);
        let (turn_caught, turn_release) = arm_legacy_pause(&event.legacy_worker_cycle_pause);
        notify_release.send(()).unwrap();
        turn_caught
            .recv_timeout(Duration::from_secs(2))
            .expect("the late notify did not wake the parked worker");
        assert_eq!(
            event.legacy_worker_wakes.load(Ordering::Relaxed),
            parked + 1,
            "the late notify did not end the held wait"
        );
        turn_release
    })
}

#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConsumeWakeup {
    /// The worker is parked when the ptracer consumes.
    Parked,
    /// The worker reaches its sleep check after the ptracer released
    /// `legacy_wait` and before it notifies.
    BetweenDropAndNotify,
}

/// The ptracer consumes a stop that the legacy worker hinted, while the
/// worker would otherwise sleep for 60 s, and the wait must resolve within
/// 2 s: the consume's wakeup is not lost. Afterwards the worker holds the
/// published stop, because the wakeup was counted before the publication.
#[cfg(not(sanitized))]
async fn legacy_consume_wakes_the_worker(case: ConsumeWakeup) {
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
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let parent_running = parent.resume(None).unwrap();
    let running = child.resume(None).unwrap();
    // The resume counted a wakeup that ends the hold on the SIGSTOP, so no
    // held wait starts after this read until the next publication.
    let held_before = worker.legacy_held_waits.load(Ordering::Relaxed);

    // From the hint of the next stop, only a wakeup ends the worker's sleep
    // within the test's bounds.
    *worker.legacy_poll_period.lock() = Some(Duration::from_secs(60));
    let deliver = || {
        // SAFETY: tgkill takes integer arguments and touches no memory.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                root.as_raw(),
                child_tid.as_raw(),
                libc::SIGUSR2,
            )
        };
        assert_eq!(sent, 0);
    };
    let coordinator = match case {
        ConsumeWakeup::Parked => {
            let (parked, parking) = mpsc::sync_channel(1);
            *worker.legacy_parking_signal.lock() = Some(parked);
            deliver();
            // Sent while the worker holds `legacy_wakeup` with no new count,
            // right before it waits: the consume counts only after it parked.
            parking
                .recv_timeout(Duration::from_secs(2))
                .expect("the worker never parked after hinting the stop");
            None
        }
        ConsumeWakeup::BetweenDropAndNotify => {
            let (worker_caught, worker_release) =
                arm_legacy_pause(&worker.legacy_sleep_check_pause);
            deliver();
            worker_caught
                .recv_timeout(Duration::from_secs(2))
                .expect("the worker never hinted the stop");
            // Armed while the worker is paused, so its next publication is
            // the stop the ptracer consumes below.
            let (published, publish_release) = arm_legacy_pause(&worker.legacy_publish_pause);
            let (tracer_caught, tracer_release) =
                arm_legacy_pause(&worker.legacy_assist_notify_pause);
            Some(thread::spawn(move || {
                tracer_caught
                    .recv_timeout(Duration::from_secs(2))
                    .expect("the consume never reached its notify");
                // Released first, the worker reaches its sleep check while
                // the ptracer has not notified. The 1.5 s window ends before
                // either pause resumes by itself (2 s).
                worker_release.send(()).unwrap();
                let before_notify = published.recv_timeout(Duration::from_millis(1500)).is_ok();
                if before_notify {
                    publish_release.send(()).unwrap();
                }
                tracer_release.send(()).unwrap();
                if !before_notify {
                    let _ = published.recv_timeout(Duration::from_secs(2));
                    let _ = publish_release.send(());
                }
                before_notify
            }))
        }
    };
    // Its first poll consumes the stop through `try_assist_legacy_wait`.
    let (child, event) = tokio::time::timeout(
        Duration::from_secs(2),
        running.wait_owned_on_ptracer_thread(),
    )
    .await
    .expect("lost wakeup: the consumed stop was not published within 2 s")
    .unwrap()
    .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGUSR2));
    if let Some(coordinator) = coordinator {
        assert!(
            coordinator.join().unwrap(),
            "the worker did not publish before the consume notified: \
             its sleep check did not see the consume's wakeup count"
        );
    }
    *worker.legacy_poll_period.lock() = None;
    wait_for_held_wait(&worker, held_before, "the consumed stop");

    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    assert_eq!(unsafe { libc::kill(root.as_raw(), libc::SIGKILL) }, 0);
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

// T1: the worker is parked, sleeping for 60 s after hinting a stop, when
// the ptracer consumes that stop. The consume counts a wakeup and notifies
// after it released `legacy_wait`; the notify must reach the parked worker.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_consume_wakes_a_parked_worker() {
    if run_legacy_test_outer("forced_legacy_consume_wakes_a_parked_worker") {
        return;
    }
    legacy_consume_wakes_the_worker(ConsumeWakeup::Parked).await;
}

// T2: the worker reaches its sleep check between the consume's release of
// `legacy_wait` and its notify. The wakeup was counted under `legacy_wait`,
// so the worker sees it without the notify and publishes the stop at once,
// before the notify; it then holds that stop.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_consume_counts_its_wakeup_before_the_notify() {
    if run_legacy_test_outer("forced_legacy_consume_counts_its_wakeup_before_the_notify") {
        return;
    }
    legacy_consume_wakes_the_worker(ConsumeWakeup::BetweenDropAndNotify).await;
}

#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeldWaitSkip {
    /// A probe is pending when the worker decides to wait as a held worker.
    PendingProbe,
    /// The ptracer's consume counted its wakeup during the worker's turn,
    /// after the worker had last read the counts.
    CountDuringTurn,
}

/// A held worker whose wakeup counts changed since it last read them does
/// not wait: it takes another turn first. That skipped wait is not a held
/// wait and must not be counted as one. The worker is paused at its first
/// held-wait decision after the published SIGSTOP, with the wakeup pending,
/// and again at its next one: no held wait may have been counted by then.
/// It then parks, and a parked held worker takes no turns.
#[cfg(not(sanitized))]
async fn legacy_skipped_held_wait_is_not_counted(case: HeldWaitSkip) {
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
    // Taken by the first held-wait decision: one after the publication of
    // the SIGSTOP consumed below, since no stop is held before it.
    let (first_caught, first_release) = arm_legacy_pause(&worker.legacy_held_wait_pause);
    let counted = match case {
        HeldWaitSkip::PendingProbe => None,
        HeldWaitSkip::CountDuringTurn => {
            // Hold the worker at the start of a turn, after it read the
            // counts and before it takes `legacy_wait`, while the consume
            // below counts its wakeup.
            wait_for_legacy_hint(&worker, "the SIGSTOP");
            let (turn_caught, turn_release) = arm_legacy_pause(&worker.legacy_worker_cycle_pause);
            turn_caught
                .recv_timeout(Duration::from_secs(2))
                .expect("the worker never started another turn");
            let before = worker.legacy_wakeup.lock().targeted;
            let event = worker.clone();
            Some(thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_millis(1500);
                while event.legacy_wakeup.lock().targeted == before {
                    assert!(
                        Instant::now() < deadline,
                        "the consume never counted its wakeup"
                    );
                    thread::sleep(Duration::from_micros(200));
                }
                turn_release.send(()).unwrap();
            }))
        }
    };
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    if let Some(counted) = counted {
        counted.join().unwrap();
    }
    let parent_running = parent.resume(None).unwrap();
    first_caught
        .recv_timeout(Duration::from_secs(2))
        .expect("the worker never decided to hold the SIGSTOP");
    let held_before = worker.legacy_held_waits.load(Ordering::Relaxed);
    if case == HeldWaitSkip::PendingProbe {
        worker.probe_legacy_worker();
    }
    // Armed while the worker is paused, so its next held-wait decision
    // takes it.
    let (second_caught, second_release) = arm_legacy_pause(&worker.legacy_held_wait_pause);
    let turns = || worker.legacy_worker_turns.load(Ordering::Relaxed);
    let turns_before = turns();
    first_release.send(()).unwrap();
    second_caught
        .recv_timeout(Duration::from_secs(2))
        .expect("the worker never decided to hold the SIGSTOP again");
    assert_eq!(
        worker.legacy_held_waits.load(Ordering::Relaxed),
        held_before,
        "{case:?}: a held wait was counted although the pending wakeup skipped it"
    );
    assert!(
        turns() > turns_before,
        "{case:?}: the pending wakeup did not give the worker another turn"
    );
    second_release.send(()).unwrap();
    wait_for_held_wait(&worker, held_before, "the SIGSTOP");
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

// The worker decides to hold the published SIGSTOP while a probe is
// pending. It polls for the probe instead of waiting, and only the wait it
// parks in afterwards counts as a held wait.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_skipped_held_wait_after_a_probe_is_not_counted() {
    if run_legacy_test_outer("forced_legacy_skipped_held_wait_after_a_probe_is_not_counted") {
        return;
    }
    legacy_skipped_held_wait_is_not_counted(HeldWaitSkip::PendingProbe).await;
}

// The ptracer's consume of the SIGSTOP counts its wakeup during the
// worker's turn, after the worker last read the counts. The worker
// publishes and holds the stop, but its first held-wait decision sees that
// count as new and takes one more turn. That turn does not follow a held
// wait.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_skipped_held_wait_after_a_turn_count_is_not_counted() {
    if run_legacy_test_outer("forced_legacy_skipped_held_wait_after_a_turn_count_is_not_counted") {
        return;
    }
    legacy_skipped_held_wait_is_not_counted(HeldWaitSkip::CountDuringTurn).await;
}

// The consume's notify arrives after the worker published the consumed
// stop and parked held: the ptracer is paused between its count and its
// notify until the worker has parked, and the woken worker is then held at
// the start of the turn that notify gives it. That held wait is not
// quiescent, so the check of a held worker's turns must wait for a held
// wait that started after the late wake was observed. Once there, it takes
// no turns.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_held_turn_check_waits_out_a_late_consume_notify() {
    if run_legacy_test_outer("forced_legacy_held_turn_check_waits_out_a_late_consume_notify") {
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
    let held_before = worker.legacy_held_waits.load(Ordering::Relaxed);
    let delay = notify_after_held_park(&worker, held_before);
    let (child, event) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, child.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(event, crate::Event::Signal(Signal::SIGSTOP));
    let mut turn_release = Some(delay.join().unwrap());
    let parent_running = parent.resume(None).unwrap();

    // The worker is woken and held before its turn. The check must not
    // accept the held wait that the late notify ended; it lets the worker
    // take its turn once it sees that wait is stale.
    wait_for_fresh_held_wait(&worker, held_before, "the late notify", || {
        if let Some(release) = turn_release.take() {
            release.send(()).unwrap();
        }
    });
    assert_eq!(
        worker.legacy_worker_wakes.load(Ordering::Relaxed),
        worker.legacy_held_wait_wakes.load(Ordering::Relaxed),
        "the accepted held wait was already ended by a delivered notify"
    );
    drop(turn_release);
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

/// The legacy worker counters the deferred-wake tests read, at one moment.
#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LegacyWakeCounts {
    /// Observation turns (`legacy_worker_turns`).
    turns: usize,
    /// Turns whose observation found a status.
    hints: usize,
    /// Notifies that woke the worker.
    notify_wakes: usize,
    /// Deferred wakeups that an empty assist notified.
    flushes: usize,
    /// Stops the worker found only after a held wait's timeout.
    expiry_finds: usize,
}

#[cfg(not(sanitized))]
impl LegacyWakeCounts {
    fn of(event: &Event) -> Self {
        Self {
            turns: event.legacy_worker_turns.load(Ordering::Relaxed),
            hints: event.legacy_hint_turns.load(Ordering::Relaxed),
            notify_wakes: event.legacy_notify_wakes.load(Ordering::Relaxed),
            flushes: event.legacy_deferred_flushes.load(Ordering::Relaxed),
            expiry_finds: event.legacy_held_expiry_finds.load(Ordering::Relaxed),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            turns: self.turns - before.turns,
            hints: self.hints - before.hints,
            notify_wakes: self.notify_wakes - before.notify_wakes,
            flushes: self.flushes - before.flushes,
            expiry_finds: self.expiry_finds - before.expiry_finds,
        }
    }
}

/// How a deferred-wake round waits for the pipe-reading thread's read exit.
#[cfg(not(sanitized))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeferredWakePath {
    /// The async ptracer wait. For 20 ms after the resume, no worker turn or
    /// hint; then one poll with a no-op waker, which flushes the deferred
    /// wake, and the parked half ([`deferred_wake_parked_wait`]).
    Async,
    /// [`Self::Async`], also checking for those 20 ms that no notify woke the
    /// worker and that it observed nothing.
    Pinned,
    /// The synchronous ptracer wait, with the byte written 5 ms in.
    Sync,
    /// The cleanup driver's pending reservation, with the byte written 5 ms
    /// in.
    Cleanup,
}

/// How long after its stop arrives a deferred-wake test's wait may return:
/// half the production held period, so that a wakeup that reached the worker
/// only through a held wait's timeout cannot pass. The tests also set the
/// held period to 60 s.
#[cfg(not(sanitized))]
const DEFERRED_WAKE_BOUND: Duration = Duration::from_millis(50);

/// Writes one byte to the fixture thread's pipe.
#[cfg(not(sanitized))]
fn deferred_wake_write(write_end: &OwnedFd) {
    assert_eq!(
        unsafe { libc::write(write_end.as_raw_fd(), b"r".as_ptr().cast(), 1) },
        1
    );
}

/// Writes one byte to `write_end` from another thread 5 ms from now, and
/// returns when it wrote.
#[cfg(not(sanitized))]
fn deferred_wake_write_later(write_end: &Arc<OwnedFd>) -> JoinHandle<Instant> {
    let write_end = Arc::clone(write_end);
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(5));
        let written = Instant::now();
        deferred_wake_write(&write_end);
        written
    })
}

/// The procfs state letter of the fixture thread `tid` in `root`'s group.
#[cfg(not(sanitized))]
fn deferred_wake_thread_state(root: Pid, tid: crate::Pid) -> Option<String> {
    fs::read_to_string(format!("/proc/{root}/task/{tid}/stat"))
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
}

/// Runs a forced-legacy non-leader that loops reading a pipe up to its first
/// read entry, its worker's held period set to 60 s, then runs `rounds`
/// rounds of `round`, then kills and reaps the group. `round` gets the stop
/// at a read entry, with the worker parked in a fresh held wait, and returns
/// the thread's stop at its next read entry, with `legacy_held_waits` as read
/// right before the wait that returned that stop
/// ([`deferred_wake_next_read_entry`]).
#[cfg(not(sanitized))]
async fn with_deferred_wake_pipe_thread<F, R>(rounds: usize, mut round: F)
where
    F: FnMut(usize, Stopped, Arc<Event>, Arc<OwnedFd>, Pid) -> R,
    R: Future<Output = (Stopped, usize)>,
{
    let [read_end, write_end] = legacy_pipe();
    let modes: &'static [usize] = Box::leak(Box::new([1000 + read_end.as_raw_fd() as usize]));
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_threads(
        modes,
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    drop(read_end);
    let write_end = Arc::new(write_end);
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
    let mut entries = 0;
    let mut held = event.legacy_held_waits.load(Ordering::Relaxed);
    while !is_read_entry(&child) {
        entries += 1;
        assert!(entries < 200, "the thread never reached its read");
        held = event.legacy_held_waits.load(Ordering::Relaxed);
        child = next_syscall_stop(child).await;
    }
    for index in 0..rounds {
        wait_for_fresh_held_wait(&event, held, &format!("round {index}: read entry"), || {});
        (child, held) = round(
            index,
            child,
            Arc::clone(&event),
            Arc::clone(&write_end),
            root,
        )
        .await;
        assert!(
            is_read_entry(&child),
            "round {index}: not back at a read entry"
        );
    }

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

/// Resumes the fixture thread from its read exit to its next read entry.
/// Returns that stop, and `legacy_held_waits` as read right before the wait:
/// the worker's held wait for the read entry starts after that count.
#[cfg(not(sanitized))]
async fn deferred_wake_next_read_entry(exit: Stopped, event: &Event) -> (Stopped, usize) {
    let held = event.legacy_held_waits.load(Ordering::Relaxed);
    (next_syscall_stop(exit).await, held)
}

/// The prefix of the deferred-wake tests' report lines, which the outer run
/// re-emits ([`run_legacy_test_outer_reporting`]).
#[cfg(not(sanitized))]
const DEFERRED_WAKE_REPORT: &str = "deferred-wake report: ";

/// What one parked deferred-wake round's counted-wake check found
/// ([`DeferredWakeCounted::check`]): what the round lacked, if anything, how
/// many uncounted wakes the worker had up to the check, and how many of them
/// were late consume notifies.
#[cfg(not(sanitized))]
type DeferredWakeCheck = (Option<String>, usize, usize);

/// The counted-wake evidence of one parked deferred-wake round: the targeted
/// wakeup count just before and just after its request, where its entries
/// start in the worker's wake log ([`Event::legacy_wake_log`]), and
/// `legacy_held_waits` just before the request.
#[cfg(not(sanitized))]
struct DeferredWakeCounted {
    before: u64,
    after: u64,
    log_start: usize,
    held: usize,
}

/// Runs a round's resume or interrupt `request`, reading the targeted wakeup
/// count just before and just after it.
#[cfg(not(sanitized))]
fn deferred_wake_counted_request<T>(
    event: &Event,
    request: impl FnOnce() -> T,
) -> (T, DeferredWakeCounted) {
    let log_start = event.legacy_wake_log.lock().len();
    let held = event.legacy_held_waits.load(Ordering::Relaxed);
    let before = event.legacy_wakeup.lock().targeted;
    let output = request();
    let after = event.legacy_wakeup.lock().targeted;
    (
        output,
        DeferredWakeCounted {
            before,
            after,
            log_start,
            held,
        },
    )
}

/// A wait of the legacy worker that a notify ended, in a round's wake log:
/// the index of its [`LegacyWakeLogEntry::WaitBegin`] (`None` for the wait
/// the round began in, which began before the round's log), the targeted
/// count the worker had acted on, and whether the notify had moved a count.
#[cfg(not(sanitized))]
struct NotifyEndedWait {
    begin: Option<usize>,
    seen: u64,
    counted: bool,
}

/// Names a notify of the legacy worker, with the receipt of the count it
/// stands for.
#[cfg(not(sanitized))]
fn deferred_wake_notify_source(source: LegacyNotifySource) -> String {
    let receipt = |receipt: Option<LegacyCountReceipt>| match receipt {
        Some(receipt) => format!(
            "receipt {} for targeted {}",
            receipt.serial, receipt.targeted
        ),
        None => "no receipt".to_owned(),
    };
    match source {
        LegacyNotifySource::Immediate(r) => format!("an immediate wake ({})", receipt(r)),
        LegacyNotifySource::Flush(r) => format!("a deferred wake's flush ({})", receipt(r)),
        LegacyNotifySource::Probe(count) => format!("a probe (probes {count})"),
        LegacyNotifySource::Consume(r) => format!("a consume ({})", receipt(r)),
        LegacyNotifySource::Unknown => "a notify that named no source".to_owned(),
    }
}

/// Audit (d) of [`DeferredWakeCounted::check`] over a round's wake log, taken
/// once the worker is quiescent.
///
/// Every notify that names a site that counts (an immediate wake, a
/// deferral's flush, a consume) must carry the receipt of that site's own
/// count ([`LegacyCountReceipt`]): minted, and logged as
/// [`LegacyWakeLogEntry::Counted`], inside that count, and used by at most
/// one notify of the round, counted or uncounted. A notify that made no
/// count, a receipt never counted, and a receipt used twice each fail.
///
/// Each wait of the worker that a notify ended is assigned, in order, the
/// earliest unassigned [`LegacyWakeLogEntry::Notified`] entry after its
/// `WaitBegin`: a notify that woke the worker found it parked, so it came
/// after that `WaitBegin`, and in these fixtures every such notify runs on
/// the test thread, in order. An uncounted wake is allowed only as a late
/// consume notify: its notify is a consume whose receipt passed the rules
/// above, whose `Counted` entry precedes the wait's `WaitBegin`, and whose
/// count the worker had acted on (`targeted <= seen`). So the worker began
/// the wait after acting on that consume's own increment, and the consume's
/// notify, sent after it released `legacy_wait`, arrived during it.
/// Anything else is unexplained: an uncounted wake by any other notify, a
/// notify-ended wait with no notify logged, or a notify that woke the worker
/// with no wake logged.
///
/// (d) sees only notifies whose `notify_one` returned true, that is, notifies
/// that found the worker parked. A notify that lands while the worker runs
/// is invisible to it, and has no effect. So whether an extra notify is
/// caught depends on timing, round by round. It is reliable where the worker
/// sits in one long held wait, as in
/// `forced_legacy_deferred_wake_reaches_an_async_wait`. In the mutation runs
/// at the time of writing, that test caught an extra notify after the hint in
/// every round, and the exit-wait and pinned tests in most; that is an
/// observation, not a guarantee for every round.
/// `forced_legacy_counted_wake_check_refuses_extra_notifies_to_a_parked_worker`
/// is the deterministic negative control: it delivers each extra notify to a
/// worker it has proven parked.
///
/// Returns the late consume notifies and what is unexplained. `before` is
/// the targeted count when the round began.
#[cfg(not(sanitized))]
fn deferred_wake_late_consume_audit(
    log: &[LegacyWakeLogEntry],
    before: u64,
) -> (usize, Vec<String>) {
    let mut waits = Vec::new();
    // Each notify: its index, its source, whether a wait took it, and
    // whether its receipt passed (an uncounted wake needs that).
    let mut notifies = Vec::new();
    let mut counted = std::collections::HashMap::new();
    let mut used_receipts = std::collections::HashSet::new();
    let mut open = Some((None, before));
    let mut unexplained = Vec::new();
    for (at, entry) in log.iter().enumerate() {
        match *entry {
            LegacyWakeLogEntry::WaitBegin(seen) => open = Some((Some(at), seen)),
            LegacyWakeLogEntry::CountedWake | LegacyWakeLogEntry::Uncounted => match open.take() {
                Some((begin, seen)) => waits.push(NotifyEndedWait {
                    begin,
                    seen,
                    counted: *entry == LegacyWakeLogEntry::CountedWake,
                }),
                None => unexplained.push(format!("a wake at entry {at} with no wait begun")),
            },
            LegacyWakeLogEntry::Counted(receipt) => {
                counted.insert(receipt.serial, (at, receipt));
            }
            LegacyWakeLogEntry::Notified(source) => {
                let receipt = match source {
                    LegacyNotifySource::Immediate(receipt)
                    | LegacyNotifySource::Flush(receipt)
                    | LegacyNotifySource::Consume(receipt) => Some(receipt),
                    LegacyNotifySource::Probe(_) | LegacyNotifySource::Unknown => None,
                };
                let named = deferred_wake_notify_source(source);
                let receipt_passed = match receipt {
                    None => false,
                    Some(None) => {
                        unexplained.push(format!("{named} made no count"));
                        false
                    }
                    Some(Some(receipt)) => {
                        let minted = counted
                            .get(&receipt.serial)
                            .is_some_and(|(_, minted)| *minted == receipt);
                        if !minted {
                            unexplained.push(format!(
                                "receipt {} was never counted ({named})",
                                receipt.serial
                            ));
                        }
                        let first = used_receipts.insert(receipt.serial);
                        if !first {
                            unexplained.push(format!(
                                "receipt {} used by a second notify ({named})",
                                receipt.serial
                            ));
                        }
                        minted && first
                    }
                };
                notifies.push((at, source, false, receipt_passed));
            }
            _ => {}
        }
    }
    let mut late = 0;
    for wait in &waits {
        let assigned = notifies
            .iter_mut()
            .find(|(at, _, used, _)| !*used && wait.begin.is_none_or(|begin| *at > begin));
        let Some((_, source, used, receipt_passed)) = assigned else {
            unexplained.push(format!(
                "a wait begun at entry {:?} ended by a notify that was not logged",
                wait.begin
            ));
            continue;
        };
        *used = true;
        if wait.counted {
            continue;
        }
        let late_consume = match *source {
            LegacyNotifySource::Consume(Some(receipt)) => {
                *receipt_passed
                    && receipt.targeted <= wait.seen
                    && wait.begin.is_some_and(|begin| {
                        counted
                            .get(&receipt.serial)
                            .is_some_and(|(at, _)| *at < begin)
                    })
            }
            _ => false,
        };
        if late_consume {
            late += 1;
        } else {
            unexplained.push(format!(
                "an uncounted wake of the wait begun at entry {:?} (the worker had acted on \
                 targeted count {}) ended by {}",
                wait.begin,
                wait.seen,
                deferred_wake_notify_source(*source)
            ));
        }
    }
    let extra = notifies.iter().filter(|(_, _, used, _)| !*used).count();
    if extra != 0 {
        unexplained.push(format!(
            "{extra} notify(s) woke the worker with no wake logged"
        ));
    }
    (late, unexplained)
}

// The late-consume audit on synthetic logs, with no tracee. It accepts the
// real late-consume window: a consume counts, the worker acts on that count
// and parks, and only then does the consume's notify reach it. It refuses a
// consume that made no count, a receipt used twice (by two uncounted wakes,
// or by a counted and an uncounted one), a receipt never counted, an
// uncounted wake by a count the worker had not acted on, an uncounted wake
// by a flush, a wake with no notify logged, and a notify with no wake.
#[test]
#[cfg(not(sanitized))]
fn deferred_wake_audit_accepts_only_a_receipted_late_consume_notify() {
    use LegacyNotifySource::Consume;
    use LegacyNotifySource::Flush;
    use LegacyWakeLogEntry::Counted;
    use LegacyWakeLogEntry::CountedWake;
    use LegacyWakeLogEntry::Hint;
    use LegacyWakeLogEntry::Notified;
    use LegacyWakeLogEntry::Uncounted;
    use LegacyWakeLogEntry::WaitBegin;
    let r = |serial, targeted| LegacyCountReceipt { serial, targeted };
    let opening = [
        Counted(r(1, 4)),
        Notified(Flush(Some(r(1, 4)))),
        CountedWake,
        Hint,
    ];
    let with_opening = |rest: &[LegacyWakeLogEntry]| -> Vec<LegacyWakeLogEntry> {
        opening.iter().chain(rest).copied().collect()
    };
    let window = with_opening(&[
        Counted(r(2, 5)),
        WaitBegin(5),
        Notified(Consume(Some(r(2, 5)))),
        Uncounted,
    ]);
    assert_eq!(
        deferred_wake_late_consume_audit(&window, 3),
        (1, Vec::new()),
        "the real late-consume window was not accepted"
    );
    let refused = |log: &[LegacyWakeLogEntry], reason: &str, late: usize| {
        let (accepted, unexplained) = deferred_wake_late_consume_audit(log, 3);
        assert!(
            unexplained.iter().any(|what| what.contains(reason)),
            "no refusal naming {reason:?} in {unexplained:?} for {log:?}"
        );
        assert_eq!(accepted, late, "late consume notifies for {log:?}");
    };
    refused(
        &with_opening(&[WaitBegin(4), Notified(Consume(None)), Uncounted]),
        "a consume (no receipt) made no count",
        0,
    );
    let mut twice = window.clone();
    twice.extend([WaitBegin(5), Notified(Consume(Some(r(2, 5)))), Uncounted]);
    refused(&twice, "receipt 2 used by a second notify", 1);
    refused(
        &with_opening(&[
            Counted(r(2, 5)),
            Notified(Consume(Some(r(2, 5)))),
            CountedWake,
            WaitBegin(5),
            Notified(Consume(Some(r(2, 5)))),
            Uncounted,
        ]),
        "receipt 2 used by a second notify",
        0,
    );
    refused(
        &with_opening(&[WaitBegin(4), Notified(Consume(Some(r(9, 4)))), Uncounted]),
        "receipt 9 was never counted",
        0,
    );
    refused(
        &with_opening(&[
            WaitBegin(4),
            Counted(r(2, 5)),
            Notified(Consume(Some(r(2, 5)))),
            Uncounted,
        ]),
        "an uncounted wake of the wait begun at entry Some(4)",
        0,
    );
    refused(
        &[
            Counted(r(1, 4)),
            WaitBegin(4),
            Notified(Flush(Some(r(1, 4)))),
            Uncounted,
        ],
        "ended by a deferred wake's flush",
        0,
    );
    refused(
        &[WaitBegin(4), Uncounted],
        "ended by a notify that was not logged",
        0,
    );
    refused(
        &[Counted(r(1, 4)), Notified(Flush(Some(r(1, 4))))],
        "1 notify(s) woke the worker with no wake logged",
        0,
    );
}

#[cfg(not(sanitized))]
impl DeferredWakeCounted {
    /// After the round's wait returned, whether the round shows that its
    /// request's counted wakeup is what released the worker, and that every
    /// later wake of the worker is accounted for: (a) the request counted
    /// exactly one targeted wakeup; (b) no uncounted wake came before the
    /// worker's first hint of the round; (c) the round's first hold end
    /// carries exactly the request's count and precedes that hint, which
    /// precedes Ready (only the worker's hint can wake a parked wait after
    /// the byte); (d) through Ready and until the worker is quiescent, every
    /// uncounted wake is a late consume notify, matched one for one to the
    /// consume whose count the worker had already acted on
    /// ([`deferred_wake_late_consume_audit`]).
    ///
    /// The check first waits until the worker is parked held after its last
    /// delivered wake ([`wait_for_fresh_held_wait`]). Every notifier of the
    /// round has returned by then: they ran on this thread, or are the
    /// worker's own probe of itself, which returns before it waits. So the
    /// log it then reads holds the worker's response to every notify sent
    /// before it.
    ///
    /// Before the check ran to quiescence, it stopped its uncounted-wake test
    /// at the first hint, and only reported a count taken from the snapshot
    /// after Ready, `uncounted_at_check`. That count was 0 in all 820 rounds
    /// of the gate runs of 2026-11-13 at
    /// 9e3672ef93012b531fda2ccb1758de524824459e: 400 of
    /// `forced_legacy_deferred_wake_reaches_an_async_wait`, 400 of
    /// `forced_legacy_deferred_wake_reaches_an_exit_wait`, and 20 of
    /// `forced_legacy_resume_does_not_wake_a_parked_worker_until_the_first_empty_assist`.
    /// That snapshot could miss a wake the worker had not logged yet.
    fn check(&self, event: &Event, what: &str) -> DeferredWakeCheck {
        wait_for_fresh_held_wait(
            event,
            self.held,
            &format!("{what}: counted-wake check"),
            || {},
        );
        let log = event.legacy_wake_log.lock()[self.log_start..].to_vec();
        let hint = log
            .iter()
            .position(|entry| *entry == LegacyWakeLogEntry::Hint);
        let first_end = log.iter().enumerate().find_map(|(at, entry)| match entry {
            LegacyWakeLogEntry::HoldEndedByCount(count) => Some((at, *count)),
            _ => None,
        });
        let uncounted = |entries: &[LegacyWakeLogEntry]| {
            entries
                .iter()
                .filter(|entry| **entry == LegacyWakeLogEntry::Uncounted)
                .count()
        };
        let mut lacks = Vec::new();
        let counted = self.after.wrapping_sub(self.before);
        if counted != 1 {
            lacks.push(format!(
                "(a) the request counted {counted} targeted wakeups, not 1"
            ));
        }
        let early = uncounted(&log[..hint.unwrap_or(log.len())]);
        if early != 0 {
            lacks.push(format!(
                "(b) {early} uncounted wake(s) before the worker's hint"
            ));
        }
        if !matches!((first_end, hint), (Some((at, count)), Some(hint)) if count == self.after && at < hint)
        {
            lacks.push(format!(
                "(c) the hold was not ended by the request's count {} before the worker's hint",
                self.after
            ));
        }
        let (late, unexplained) = deferred_wake_late_consume_audit(&log, self.before);
        lacks.extend(unexplained.into_iter().map(|what| format!("(d) {what}")));
        let lacks = (!lacks.is_empty()).then(|| format!("{}; wake log {log:?}", lacks.join("; ")));
        (lacks, uncounted(&log), late)
    }
}

/// Prints a parked deferred-wake test's counted-wake report: its rounds, the
/// rounds that failed the check ([`DeferredWakeCounted::check`]), the
/// worker's uncounted wakes up to each check, and how many of them were late
/// consume notifies. Returns the failed rounds, for
/// [`deferred_wake_assert_counted`].
#[cfg(not(sanitized))]
fn deferred_wake_report_counted(label: &str, checks: &[DeferredWakeCheck]) -> Vec<(usize, String)> {
    let failed: Vec<(usize, String)> = checks
        .iter()
        .enumerate()
        .filter_map(|(round, (lacks, _, _))| lacks.clone().map(|lacks| (round, lacks)))
        .collect();
    let rounds: Vec<usize> = failed.iter().map(|(round, _)| *round).collect();
    let uncounted: usize = checks.iter().map(|(_, uncounted, _)| uncounted).sum();
    let late: usize = checks.iter().map(|(_, _, late)| late).sum();
    println!(
        "{DEFERRED_WAKE_REPORT}{label}: counted-wake n={} failed={} {rounds:?} \
         uncounted_to_quiescence={uncounted} late_consume_notify={late}",
        checks.len(),
        failed.len(),
    );
    failed
}

/// Fails if any of `rounds` rounds failed the counted-wake check, with what
/// each lacked.
#[cfg(not(sanitized))]
fn deferred_wake_assert_counted(label: &str, rounds: usize, failed: &[(usize, String)]) {
    assert!(
        failed.is_empty(),
        "{label}: {} of {rounds} rounds failed the counted-wake check: {failed:?}",
        failed.len(),
    );
}

/// Reports one deferred-wake test's rounds and asserts that none missed its
/// bound. `rounds` holds each round's time from the write to the return, or
/// `None` for a round that missed the bound. The report line gives the
/// missed rounds, and the median (the element at index n/2 of the sorted
/// values) and the maximum of the others.
#[cfg(not(sanitized))]
fn deferred_wake_check_rounds(label: &str, rounds: &[Option<Duration>]) {
    let missed: Vec<usize> = (0..rounds.len()).filter(|&i| rounds[i].is_none()).collect();
    let mut sorted: Vec<Duration> = rounds.iter().flatten().copied().collect();
    sorted.sort();
    let (p50, max) = match sorted.last() {
        Some(max) => (
            sorted[sorted.len() / 2].as_micros().to_string(),
            max.as_micros().to_string(),
        ),
        None => ("-".to_owned(), "-".to_owned()),
    };
    println!(
        "{DEFERRED_WAKE_REPORT}{label}: n={} missed={} {missed:?} p50_us={p50} max_us={max}",
        rounds.len(),
        missed.len(),
    );
    assert!(
        missed.is_empty(),
        "{label}: {} of {} rounds missed the {DEFERRED_WAKE_BOUND:?} bound: rounds {missed:?}",
        missed.len(),
        rounds.len()
    );
}

/// Polls `wait` each time `counter` moves past `seen`, which the caller read
/// before its last poll, until the wait is ready or `deadline` passes. It
/// never polls before the counter moves.
#[cfg(not(sanitized))]
fn deferred_wake_poll_on_wakes<F: Future>(
    mut wait: Pin<&mut F>,
    counter: &WakeCounter,
    cx: &mut Context<'_>,
    mut seen: usize,
    deadline: Instant,
) -> Option<F::Output> {
    loop {
        while counter.0.load(Ordering::SeqCst) == seen {
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_micros(100));
        }
        seen = counter.0.load(Ordering::SeqCst);
        if let Poll::Ready(output) = wait.as_mut().poll(cx) {
            return Some(output);
        }
    }
}

/// The parked half of a deferred-wake round, after the first poll flushed
/// the deferred wake. Polls `wait` a second time with a counting waker and
/// asserts it is still pending and unwoken, so the waiter is parked before
/// its stop can exist. Then writes the byte, and polls only when the counter
/// moves: only the worker, released by the flush, can move it. Returns the
/// wait's output, and its time from the write if it was ready within
/// [`DEFERRED_WAKE_BOUND`] (`None` if not). A round that misses the bound is
/// recovered: the assist consumes the stop, which stays in the kernel.
#[cfg(not(sanitized))]
fn deferred_wake_parked_wait<F: Future>(
    mut wait: Pin<&mut F>,
    write_end: &OwnedFd,
    what: &str,
) -> (F::Output, Option<Duration>) {
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    assert!(
        wait.as_mut().poll(&mut cx).is_pending(),
        "{what}: the second poll returned before the byte"
    );
    assert_eq!(
        counter.0.load(Ordering::SeqCst),
        0,
        "{what}: the parked waiter was woken before the byte"
    );
    let written = Instant::now();
    deferred_wake_write(write_end);
    if let Some(output) = deferred_wake_poll_on_wakes(
        wait.as_mut(),
        &counter,
        &mut cx,
        0,
        written + DEFERRED_WAKE_BOUND,
    ) {
        let latency = written.elapsed();
        assert!(
            counter.0.load(Ordering::SeqCst) >= 1,
            "{what}: ready without a wake"
        );
        return (output, (latency < DEFERRED_WAKE_BOUND).then_some(latency));
    }
    let seen = counter.0.load(Ordering::SeqCst);
    let output = match wait.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => deferred_wake_poll_on_wakes(
            wait.as_mut(),
            &counter,
            &mut cx,
            seen,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap_or_else(|| panic!("{what}: the missed round did not recover its stop")),
    };
    (output, None)
}

/// Checks for 20 ms after a resume that the parked worker stayed asleep: no
/// worker turn and no hint since `before`. With `strict`, also no notify that
/// woke the worker, and no observation.
#[cfg(not(sanitized))]
fn deferred_wake_pin(event: &Event, before: LegacyWakeCounts, strict: bool, what: &str) {
    let deadline = Instant::now() + Duration::from_millis(20);
    loop {
        let moved = LegacyWakeCounts::of(event).since(before);
        assert_eq!(
            (moved.turns, moved.hints),
            (0, 0),
            "{what}: the resume woke the parked worker: {moved:?}"
        );
        if strict {
            assert_eq!(
                moved.notify_wakes, 0,
                "{what}: the resume notified the parked worker: {moved:?}"
            );
            assert!(
                event.legacy_wait.lock().observed.is_none(),
                "{what}: the worker observed a status before any assist"
            );
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// One round of a deferred-wake test on the pipe-reading thread. From a read
/// entry, with the worker parked in a fresh held wait: resumes into the read,
/// waits on `path` for the read's exit, with the byte written as `path`
/// says, then resumes on to the next read entry. Returns that entry and its
/// held-wait count ([`deferred_wake_next_read_entry`]), and how long after
/// the byte's write the wait returned the read's exit.
#[cfg(not(sanitized))]
async fn deferred_wake_round(
    path: DeferredWakePath,
    round: usize,
    entry: Stopped,
    event: &Event,
    write_end: &Arc<OwnedFd>,
) -> (Stopped, usize, Option<Duration>, Option<DeferredWakeCheck>) {
    let what = format!("{path:?} round {round}");
    let before = LegacyWakeCounts::of(event);
    let (exit, latency, counted) = match path {
        DeferredWakePath::Async | DeferredWakePath::Pinned => {
            let (running, counted) =
                deferred_wake_counted_request(event, || entry.syscall(None).unwrap());
            deferred_wake_pin(event, before, path == DeferredWakePath::Pinned, &what);
            let mut wait = std::pin::pin!(running.wait_owned_on_ptracer_thread());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "{what}: the read returned before its byte"
            );
            assert_eq!(
                LegacyWakeCounts::of(event).since(before).flushes,
                1,
                "{what}: the first empty assist did not flush the deferred wake"
            );
            let (wait, latency) = deferred_wake_parked_wait(wait.as_mut(), write_end, &what);
            let check = counted.check(event, &what);
            let (exit, stop) = wait.unwrap().assume_stopped();
            assert_eq!(stop, crate::Event::Syscall);
            (exit, latency, Some(check))
        }
        DeferredWakePath::Sync => {
            let running = entry.syscall(None).unwrap();
            let writer = deferred_wake_write_later(write_end);
            let mut wait = running.wait_sync_on_ptracer_thread();
            let (exit, stop) = wait.wait().unwrap().assume_stopped();
            let returned = Instant::now();
            assert_eq!(stop, crate::Event::Syscall);
            let latency = returned.saturating_duration_since(writer.join().unwrap());
            assert!(
                latency < DEFERRED_WAKE_BOUND,
                "{what}: the wait returned {latency:?} after the byte"
            );
            (exit, Some(latency), None)
        }
        DeferredWakePath::Cleanup => {
            let mut cleanup = entry.terminal_cleanup_on_ptracer_thread().into_driver();
            let running = entry.syscall(None).unwrap();
            let writer = deferred_wake_write_later(write_end);
            let pending = cleanup
                .reserve_pending_on_ptracer_thread(Duration::from_secs(2))
                .unwrap()
                .unwrap_or_else(|| panic!("{what}: no stop within 2 s"));
            let returned = Instant::now();
            let (exit, stop) = pending.decode().unwrap().assume_stopped();
            pending.commit();
            drop(running);
            assert_eq!(stop, crate::Event::Syscall);
            let latency = returned.saturating_duration_since(writer.join().unwrap());
            assert!(
                latency < DEFERRED_WAKE_BOUND,
                "{what}: the wait returned {latency:?} after the byte"
            );
            (exit, Some(latency), None)
        }
    };
    assert_eq!(
        exit.getsyscallinfo().unwrap().operation,
        crate::SyscallInfoOp::Exit {
            return_value: 1,
            is_error: false
        },
        "{what}: not the read's exit"
    );
    assert_eq!(
        event.legacy_held_expiry_finds.load(Ordering::Relaxed),
        0,
        "{what}: the worker found a stop only after a held wait's timeout"
    );
    let (entry, held) = deferred_wake_next_read_entry(exit, event).await;
    (entry, held, latency, counted)
}

/// Runs `plan`'s rounds in order on one pipe-reading thread
/// ([`with_deferred_wake_pipe_thread`]): for each entry, that many rounds of
/// [`deferred_wake_round`] on its path. Returns each entry's rounds, for
/// [`deferred_wake_check_rounds`], and each entry's counted-wake checks, for
/// [`deferred_wake_report_counted`] (the parked paths only).
#[cfg(not(sanitized))]
async fn deferred_wake_rounds(
    plan: &[(DeferredWakePath, usize)],
) -> (Vec<Vec<Option<Duration>>>, Vec<Vec<DeferredWakeCheck>>) {
    let slots: Vec<usize> = plan
        .iter()
        .enumerate()
        .flat_map(|(slot, &(_, rounds))| std::iter::repeat_n(slot, rounds))
        .collect();
    let latencies = Rc::new(std::cell::RefCell::new(vec![Vec::new(); plan.len()]));
    let checks = Rc::new(std::cell::RefCell::new(vec![Vec::new(); plan.len()]));
    with_deferred_wake_pipe_thread(slots.len(), |round, entry, event, write_end, _root| {
        let slot = slots[round];
        let path = plan[slot].0;
        let latencies = Rc::clone(&latencies);
        let checks = Rc::clone(&checks);
        async move {
            let (entry, held, latency, check) =
                deferred_wake_round(path, round, entry, &event, &write_end).await;
            latencies.borrow_mut()[slot].push(latency);
            if let Some(check) = check {
                checks.borrow_mut()[slot].push(check);
            }
            (entry, held)
        }
    })
    .await;
    (latencies.take(), checks.take())
}

/// The voluntary context switches of the fixture thread `tid` in `root`'s
/// group. A thread that enters a ptrace stop switches out voluntarily.
#[cfg(not(sanitized))]
fn deferred_wake_voluntary_switches(root: Pid, tid: crate::Pid) -> u64 {
    fs::read_to_string(format!("/proc/{root}/task/{tid}/status"))
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("voluntary_ctxt_switches:"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// One step of `forced_legacy_stop_found_at_first_poll_takes_one_worker_wake`.
/// Resumes `stopped` to its next syscall stop, writing the byte first if
/// `write_end` is given. Waits until that stop is in the kernel: the thread
/// has switched out voluntarily since the resume, and shows `t`. Only then
/// waits for the stop. Returns it, and `legacy_held_waits` as read before the
/// resume.
#[cfg(not(sanitized))]
async fn deferred_wake_found_step(
    stopped: Stopped,
    event: &Event,
    root: Pid,
    write_end: Option<&OwnedFd>,
    what: &str,
) -> (Stopped, usize) {
    let tid = stopped.pid();
    let held = event.legacy_held_waits.load(Ordering::Relaxed);
    let switches = deferred_wake_voluntary_switches(root, tid);
    if let Some(write_end) = write_end {
        deferred_wake_write(write_end);
    }
    let running = stopped.syscall(None).unwrap();
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while deferred_wake_voluntary_switches(root, tid) <= switches
        || deferred_wake_thread_state(root, tid).as_deref() != Some("t")
    {
        assert!(
            Instant::now() < deadline,
            "{what}: the stop never reached the kernel"
        );
        thread::sleep(Duration::from_micros(200));
    }
    let (next, stop) =
        tokio::time::timeout(TRACEE_WAIT_TIMEOUT, running.wait_owned_on_ptracer_thread())
            .await
            .unwrap()
            .unwrap()
            .assume_stopped();
    assert_eq!(stop, crate::Event::Syscall);
    (next, held)
}

// A stop that is already in the kernel when the ptracer first waits for it
// costs the legacy worker one wake: the consume's notify, after which the
// worker takes one empty turn and parks again. The resume that led to the
// stop defers its wake, and the ptracer's first assist consumes the stop, so
// nothing flushes that wake, and the worker never observes the stop by
// itself. The pipe-reading non-leader is stepped 50 times (read exit, read
// entry, ...), each time with its worker parked in a fresh held wait first;
// for a read exit the byte is written before the resume.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_stop_found_at_first_poll_takes_one_worker_wake() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_stop_found_at_first_poll_takes_one_worker_wake",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    const ROUNDS: usize = 25;
    let start = Rc::new(Cell::new(None));
    let end = Rc::new(Cell::new(None));
    // Status reads by the attachment check on this ptracer thread, and
    // deferrals that woke a status waker, over the 50 steps.
    let extra = Rc::new(Cell::new((0, 0)));
    with_deferred_wake_pipe_thread(ROUNDS, |round, entry, event, write_end, root| {
        let (start, end, extra) = (Rc::clone(&start), Rc::clone(&end), Rc::clone(&extra));
        async move {
            if round == 0 {
                start.set(Some(LegacyWakeCounts::of(&event)));
                extra.set((
                    PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get),
                    event.legacy_deferred_status_wakes.load(Ordering::Relaxed),
                ));
            }
            let what = format!("round {round}: read exit");
            let (exit, held) =
                deferred_wake_found_step(entry, &event, root, Some(&*write_end), &what).await;
            wait_for_fresh_held_wait(&event, held, &what, || {});
            let what = format!("round {round}: read entry");
            let (entry, held) = deferred_wake_found_step(exit, &event, root, None, &what).await;
            if round == ROUNDS - 1 {
                wait_for_fresh_held_wait(&event, held, &what, || {});
                end.set(Some(LegacyWakeCounts::of(&event)));
                let (reads, status_wakes) = extra.get();
                extra.set((
                    PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get) - reads,
                    event.legacy_deferred_status_wakes.load(Ordering::Relaxed) - status_wakes,
                ));
                // No exit waiter is registered here, so no deferral wakes one.
                assert_eq!(
                    event.legacy_deferred_exit_wakes.load(Ordering::Relaxed),
                    0,
                    "a deferral woke an exit waiter, but none was registered"
                );
            }
            (entry, held)
        }
    })
    .await;
    let steps = end.get().unwrap().since(start.get().unwrap());
    let (status_reads, status_wakes) = extra.get();
    println!(
        "{DEFERRED_WAKE_REPORT}stop found at first poll, {} steps: {steps:?}, \
         status reads {status_reads}, deferral status wakes {status_wakes}",
        2 * ROUNDS
    );
    assert_eq!(
        steps,
        LegacyWakeCounts {
            turns: 2 * ROUNDS,
            hints: 0,
            notify_wakes: 2 * ROUNDS,
            flushes: 0,
            expiry_finds: 0,
        },
        "a stop found at the first poll did not cost exactly one worker wake and one turn"
    );
}

// A resume's deferred wake reaches a parked async ptracer wait (W1). Each of
// 20 rounds resumes the pipe-reading non-leader into its read with the
// worker parked held (period 60 s), and checks for 20 ms that no turn or
// hint follows. It polls the wait once (Pending; that empty assist flushes
// the wake), then again with a counting waker (Pending, unwoken), so that
// the waiter is parked before its stop can exist. Only then does it write
// the byte, and it polls again only when the waker is woken, which only the
// worker released by the flush can do. Every round must return the read's
// exit within 50 ms of the write, and the worker must never have found a
// stop through a held wait's timeout.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_deferred_wake_reaches_an_async_wait() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_deferred_wake_reaches_an_async_wait",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    let (rounds, checks) = deferred_wake_rounds(&[(DeferredWakePath::Async, 20)]).await;
    let failed = deferred_wake_report_counted("parked async wait", &checks[0]);
    deferred_wake_check_rounds("parked async wait, write to return", &rounds[0]);
    deferred_wake_assert_counted("parked async wait", checks[0].len(), &failed);
}

// A resume's deferred wake reaches a parked exit wait (W2). Each of 20 fresh
// non-leaders reads one byte and exits. At its read entry, with its worker
// parked held (period 60 s), it is resumed, and for 20 ms no turn or hint
// follows. Its exit wait is polled once (Pending; that empty assist flushes
// the wake), then again with a counting waker (Pending, unwoken), so that
// the waiter is parked before its stop can exist. Only then is the byte
// written, and the wait is polled again only when the waker is woken, which
// only the worker released by the flush can do. Every round's exit wait
// must return within 50 ms of the write, with no stop found through a held
// wait's timeout.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_deferred_wake_reaches_an_exit_wait() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_deferred_wake_reaches_an_exit_wait",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    const ROUNDS: usize = 20;
    let [read_end, write_end] = legacy_pipe();
    let modes: &'static [usize] =
        Box::leak(Box::new([2000 + read_end.as_raw_fd() as usize; ROUNDS]));
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_threads(
        modes,
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    drop(read_end);
    let read_fd = modes[0] as u64 - 2000;
    let is_read_entry = |stopped: &Stopped| {
        matches!(
            stopped.getsyscallinfo().unwrap().operation,
            crate::SyscallInfoOp::Entry { number, arguments }
                if number == libc::SYS_read as u64 && arguments[0] == read_fd
        )
    };
    let root_exit = root_cleanup.exit_event_on_ptracer_thread(&stopped).unwrap();
    let root_terminal = stopped.terminal_cleanup();
    let mut parent_running = stopped.resume(None).unwrap();
    let mut latencies = Vec::new();
    let mut checks = Vec::new();
    for round in 0..ROUNDS {
        let what = format!("exit round {round}");
        let (parent, crate::Event::NewChild(crate::ChildOp::Clone, child)) = tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            parent_running.wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped() else {
            panic!("{what}: missing reading pthread clone");
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
        let mut entries = 0;
        let mut held = event.legacy_held_waits.load(Ordering::Relaxed);
        while !is_read_entry(&child) {
            entries += 1;
            assert!(entries < 200, "{what}: the thread never reached its read");
            held = event.legacy_held_waits.load(Ordering::Relaxed);
            child = next_syscall_stop(child).await;
        }
        wait_for_fresh_held_wait(&event, held, &format!("{what}: read entry"), || {});
        let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
        let before = LegacyWakeCounts::of(&event);
        let (running, counted) =
            deferred_wake_counted_request(&event, || child.resume(None).unwrap());
        deferred_wake_pin(&event, before, false, &what);
        let mut exit = std::pin::pin!(exit);
        assert!(
            exit.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "{what}: the thread exited before its byte"
        );
        assert_eq!(
            LegacyWakeCounts::of(&event).since(before).flushes,
            1,
            "{what}: the first empty assist did not flush the deferred wake"
        );
        let (exiting, latency) = deferred_wake_parked_wait(exit.as_mut(), &write_end, &what);
        checks.push(counted.check(&event, &what));
        let exiting = exiting.unwrap();
        child_cleanup.mark_claimed_exit();
        drop(running);
        assert_eq!(exiting.pid(), child_tid);
        assert_eq!(exiting.getevent().unwrap(), 0);
        assert_eq!(
            event.legacy_held_expiry_finds.load(Ordering::Relaxed),
            0,
            "{what}: the worker found the exit stop only after a held wait's timeout"
        );
        latencies.push(latency);
        assert_eq!(
            tokio::time::timeout(
                TRACEE_WAIT_TIMEOUT,
                exiting.resume(None).unwrap().wait_owned_on_ptracer_thread()
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (child_tid, crate::ExitStatus::Exited(0)),
        );
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        child_cleanup.disarm();
        // The leader stays at its clone stop until the thread is reaped: once
        // its join returns it starts the next thread or, after the last,
        // exits the group, and a thread reaped during a group exit reports
        // the group's exit code.
        parent_running = parent.resume(None).unwrap();
    }
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
        (root.into(), crate::ExitStatus::Exited(42)),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
    let failed = deferred_wake_report_counted("parked exit wait", &checks);
    deferred_wake_check_rounds("parked exit wait, write to return", &latencies);
    deferred_wake_assert_counted("parked exit wait", checks.len(), &failed);
}

// The synchronous ptracer wait (W3) and the cleanup driver's pending
// reservation (W4) meet the same bound after a deferred resume: 20 rounds
// each on the pipe-reading non-leader, its worker parked held (period
// 60 s), with the byte written by another thread 5 ms after the wait
// starts. Each wait must return the read's exit within 50 ms of the write.
// Both paths assist every 1 ms or less by themselves, so this shows their
// bound, not the flush.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_deferred_wake_meets_the_sync_and_cleanup_bounds() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_deferred_wake_meets_the_sync_and_cleanup_bounds",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    let (rounds, _checks) = deferred_wake_rounds(&[
        (DeferredWakePath::Sync, 20),
        (DeferredWakePath::Cleanup, 20),
    ])
    .await;
    deferred_wake_check_rounds("sync wait, write to return", &rounds[0]);
    deferred_wake_check_rounds("cleanup reservation, write to return", &rounds[1]);
}

// A resume of a legacy non-leader whose worker is parked held does not wake
// the worker: for 20 ms after it, the worker takes no turn, observes
// nothing, and no notify wakes it. The resume's count still ends the hold:
// the ptracer's first empty assist flushes the deferred wake, and that alone
// ends a parked wait. The wait is polled again with a counting waker
// (Pending, unwoken) before the byte is written, and not again until the
// waker is woken; it must return the read's exit within 50 ms of the write,
// with no stop found through a held wait's timeout (period 60 s).
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_resume_does_not_wake_a_parked_worker_until_the_first_empty_assist() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_resume_does_not_wake_a_parked_worker_until_the_first_empty_assist",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    let (rounds, checks) = deferred_wake_rounds(&[(DeferredWakePath::Pinned, 1)]).await;
    let failed = deferred_wake_report_counted("pinned parked async wait", &checks[0]);
    deferred_wake_check_rounds("pinned parked async wait, write to return", &rounds[0]);
    deferred_wake_assert_counted("pinned parked async wait", checks[0].len(), &failed);
}

/// The outcome line of `forced_legacy_exit_wait_parked_before_a_resume_gets_its_stop`.
#[cfg(not(sanitized))]
const PARKED_EXIT_WAIT_MARKER: &str =
    "exit wait parked before the resume: woken and ready within the bound";

// An exit wait already parked before a resume still gets its stop, as the
// exit future reverie-ptrace's run loop keeps across every resume must. A
// non-leader reads one byte and exits. At its read entry, with its worker
// parked held (period 60 s), its exit wait is polled once with a counting
// waker, before any resume: Pending. Only then is the thread resumed, with
// the Running handle kept, the leader held at its clone stop so that no
// group exit intervenes, and no other wait or assist. After the byte is
// written, nothing polls until the waker is woken. The exit stop must be
// ready within 50 ms of the write, with no stop found through a held wait's
// timeout. The resume's deferral wakes the parked exit wait, from the
// ptracer thread.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_exit_wait_parked_before_a_resume_gets_its_stop() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_exit_wait_parked_before_a_resume_gets_its_stop",
        Some(PARKED_EXIT_WAIT_MARKER),
    ) {
        return;
    }
    let [read_end, write_end] = legacy_pipe();
    let modes: &'static [usize] = Box::leak(Box::new([2000 + read_end.as_raw_fd() as usize]));
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_threads(
        modes,
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    drop(read_end);
    let read_fd = modes[0] as u64 - 2000;
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
        panic!("missing reading pthread clone");
    };
    // The leader stays at this clone stop until the thread is reaped, so no
    // group exit can end or replace the thread's stops.
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
    let mut entries = 0;
    let mut held = event.legacy_held_waits.load(Ordering::Relaxed);
    while !matches!(
        child.getsyscallinfo().unwrap().operation,
        crate::SyscallInfoOp::Entry { number, arguments }
            if number == libc::SYS_read as u64 && arguments[0] == read_fd
    ) {
        entries += 1;
        assert!(entries < 200, "the thread never reached its read");
        held = event.legacy_held_waits.load(Ordering::Relaxed);
        child = next_syscall_stop(child).await;
    }
    wait_for_fresh_held_wait(&event, held, "read entry", || {});
    // Park the exit wait before the resume: one real poll, with a counting
    // waker, on this ptracer thread.
    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    let mut exit = std::pin::pin!(exit);
    let counter = ThreadWakeCounter::new();
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);
    assert!(
        exit.as_mut().poll(&mut cx).is_pending(),
        "the exit wait returned before the resume"
    );
    let exit_wakes_before = event.legacy_deferred_exit_wakes.load(Ordering::Relaxed);
    let (wakes_before, off_thread_before) = (counter.wakes(), counter.off_thread());
    let running = child.resume(None).unwrap();
    // The resume's deferral wakes the parked exit wait (`defer_legacy_wake`),
    // within the request, on this ptracer thread. The worker parked held
    // wakes nothing meanwhile; its later hint and publication wake the exit
    // wait from its own thread, as before.
    let exit_wakes = event.legacy_deferred_exit_wakes.load(Ordering::Relaxed) - exit_wakes_before;
    let request_wakes = counter.wakes() - wakes_before;
    let request_off_thread = counter.off_thread() - off_thread_before;
    let written = Instant::now();
    assert_eq!(
        unsafe { libc::write(write_end.as_raw_fd(), b"r".as_ptr().cast(), 1) },
        1
    );
    // No poll until the waker is woken; then poll on each wake, all within
    // the bound.
    let deadline = written + DEFERRED_WAKE_BOUND;
    let mut seen = 0;
    let mut ready = None;
    while ready.is_none() && Instant::now() < deadline {
        if counter.wakes() == seen {
            thread::sleep(Duration::from_micros(100));
            continue;
        }
        seen = counter.wakes();
        if let Poll::Ready(output) = exit.as_mut().poll(&mut cx) {
            ready = Some((output, written.elapsed()));
        }
    }
    let woken = counter.wakes();
    let (exiting, latency) = match ready {
        Some((output, latency)) => (output, Some(latency)),
        None => {
            // Recover the stop, which stays in the kernel, so that the group
            // is torn down cleanly before the verdict.
            let deadline = Instant::now() + Duration::from_secs(2);
            let output = loop {
                if let Poll::Ready(output) = exit.as_mut().poll(&mut cx) {
                    break output;
                }
                assert!(Instant::now() < deadline, "the exit stop was not recovered");
                thread::sleep(Duration::from_micros(100));
            };
            (output, None)
        }
    };
    let exiting = exiting.unwrap();
    child_cleanup.mark_claimed_exit();
    drop(running);
    assert_eq!(exiting.pid(), child_tid);
    assert_eq!(exiting.getevent().unwrap(), 0);
    assert_eq!(
        event.legacy_held_expiry_finds.load(Ordering::Relaxed),
        0,
        "the worker found the exit stop only after a held wait's timeout"
    );
    assert_eq!(
        tokio::time::timeout(
            TRACEE_WAIT_TIMEOUT,
            exiting.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (child_tid, crate::ExitStatus::Exited(0)),
    );
    assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
    child_cleanup.disarm();
    let parent_running = parent.resume(None).unwrap();
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
        (root.into(), crate::ExitStatus::Exited(42)),
    );
    assert!(root_terminal.wait(TRACEE_WAIT_TIMEOUT));
    root_cleanup.disarm();
    println!("parked exit wait before the resume: woken {woken} times, write to ready {latency:?}");
    assert!(
        latency.is_some_and(|latency| latency < DEFERRED_WAKE_BOUND),
        "the exit wait parked before the resume was not ready within 50 ms of the byte \
         (woken {woken} times, write to ready {latency:?})"
    );
    assert_eq!(
        exit_wakes, 1,
        "the resume did not wake the parked exit wait"
    );
    assert!(
        request_wakes >= 1,
        "the resume did not wake the parked exit wait's waker"
    );
    assert_eq!(
        request_off_thread, 0,
        "the resume's wake of the parked exit wait came from another thread"
    );
    emit_completion_marker(PARKED_EXIT_WAIT_MARKER);
}

/// A waker that counts its wakes, and those that came from a thread other
/// than the one that made it.
#[cfg(not(sanitized))]
struct ThreadWakeCounter {
    home: ThreadId,
    wakes: AtomicUsize,
    off_thread: AtomicUsize,
}

#[cfg(not(sanitized))]
impl ThreadWakeCounter {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            home: thread::current().id(),
            wakes: AtomicUsize::new(0),
            off_thread: AtomicUsize::new(0),
        })
    }

    fn wakes(&self) -> usize {
        self.wakes.load(Ordering::SeqCst)
    }

    fn off_thread(&self) -> usize {
        self.off_thread.load(Ordering::SeqCst)
    }
}

#[cfg(not(sanitized))]
impl Wake for ThreadWakeCounter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if thread::current().id() != self.home {
            self.off_thread.fetch_add(1, Ordering::SeqCst);
        }
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

// With an exit wait parked across every request, as reverie-ptrace's run
// loop keeps one, a stop found at the first poll still costs the legacy
// worker one wake, and the exit wait's extra polls take nothing from the
// waits. The pipe-reading non-leader is stepped 50 times (read exit, read
// entry, ...). One exit wait is created and polled Pending before the first
// request, and kept to the end. Each step, with the worker parked in a fresh
// held wait: the request (for a read exit, after the byte), then, once the
// stop is in the kernel, the exit wait is polled first, as the task the
// request woke polls it in the run loop's `select_biased!` order. Its assist
// consumes the stop and has the worker publish it; it stays Pending. Once
// the worker has published that ordinary stop, and before anything that
// can claim it has been polled, the exit wait is polled again: it must stay
// Pending and take nothing. Only then is the step's wait polled, and it
// must find its stop at once, in order. All 50 of those checks must run.
// Over the 50 steps the worker counts must be exactly those of
// `forced_legacy_stop_found_at_first_poll_takes_one_worker_wake`, and every
// wake of the exit wait must come from this ptracer thread. The status
// reads of the attachment check and the deferrals' status wakes are
// reported.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_stop_found_at_first_poll_with_a_parked_exit_wait_takes_one_worker_wake() {
    if run_legacy_test_outer_reporting(
        "forced_legacy_stop_found_at_first_poll_with_a_parked_exit_wait_takes_one_worker_wake",
        DEFERRED_WAKE_REPORT,
    ) {
        return;
    }
    const STEPS: usize = 50;
    let [read_end, write_end] = legacy_pipe();
    let modes: &'static [usize] = Box::leak(Box::new([1000 + read_end.as_raw_fd() as usize]));
    let (root, stopped, mut root_cleanup, _force) = spawn_legacy_threads(
        modes,
        legacy_thread_options() | Options::PTRACE_O_TRACESYSGOOD,
        LegacyAttachMethod::Traceme,
    );
    drop(read_end);
    let read_fd = modes[0] as u64 - 1000;
    let is_read_entry = |stopped: &Stopped| {
        matches!(
            stopped.getsyscallinfo().unwrap().operation,
            crate::SyscallInfoOp::Entry { number, arguments }
                if number == libc::SYS_read as u64 && arguments[0] == read_fd
        )
    };
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
    let mut entries = 0;
    let mut held = event.legacy_held_waits.load(Ordering::Relaxed);
    while !is_read_entry(&child) {
        entries += 1;
        assert!(entries < 200, "the thread never reached its read");
        held = event.legacy_held_waits.load(Ordering::Relaxed);
        child = next_syscall_stop(child).await;
    }
    wait_for_fresh_held_wait(&event, held, "read entry", || {});
    // The long-lived exit wait, parked before the first request.
    let exit = child_cleanup.exit_event_on_ptracer_thread(&child).unwrap();
    let mut exit = std::pin::pin!(exit);
    let exit_counter = ThreadWakeCounter::new();
    let exit_waker = Waker::from(Arc::clone(&exit_counter));
    assert!(
        exit.as_mut()
            .poll(&mut Context::from_waker(&exit_waker))
            .is_pending(),
        "the exit wait returned before the first request"
    );
    let start = LegacyWakeCounts::of(&event);
    let exit_wakes_start = event.legacy_deferred_exit_wakes.load(Ordering::Relaxed);
    let status_wakes_start = event.legacy_deferred_status_wakes.load(Ordering::Relaxed);
    // Wakes of the exit wait within the request calls, and how many of them
    // came from another thread. The worker's own later wakes are not counted.
    let (mut request_wakes, mut request_off_thread) = (0, 0);
    let (mut exit_checks, mut status_reads) = (0, 0);
    for step in 0..STEPS {
        let what = format!("step {step}");
        let to_exit = is_read_entry(&child);
        assert_eq!(to_exit, step % 2 == 0, "{what}: out of order");
        let tid = child.pid();
        let held = event.legacy_held_waits.load(Ordering::Relaxed);
        let switches = deferred_wake_voluntary_switches(root, tid);
        if to_exit {
            deferred_wake_write(&write_end);
        }
        let reads_before = PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get);
        let (wakes_before, off_thread_before) = (exit_counter.wakes(), exit_counter.off_thread());
        let running = child.syscall(None).unwrap();
        request_wakes += exit_counter.wakes() - wakes_before;
        request_off_thread += exit_counter.off_thread() - off_thread_before;
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        while deferred_wake_voluntary_switches(root, tid) <= switches
            || deferred_wake_thread_state(root, tid).as_deref() != Some("t")
        {
            assert!(
                Instant::now() < deadline,
                "{what}: the stop never reached the kernel"
            );
            thread::sleep(Duration::from_micros(200));
        }
        // The task the request woke polls the exit wait first: its assist
        // consumes the stop and notifies the worker to publish it.
        assert!(
            exit.as_mut()
                .poll(&mut Context::from_waker(&exit_waker))
                .is_pending(),
            "{what}: the exit wait returned on an ordinary stop"
        );
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        while event.pending_is_empty() {
            assert!(
                Instant::now() < deadline,
                "{what}: the ordinary stop was never published"
            );
            thread::sleep(Duration::from_micros(100));
        }
        // With that stop published, and nothing that can claim it polled
        // yet, the exit wait is polled again: it stays Pending and takes
        // nothing.
        assert!(
            exit.as_mut()
                .poll(&mut Context::from_waker(&exit_waker))
                .is_pending(),
            "{what}: the exit wait returned on a published ordinary stop"
        );
        assert!(
            !event.pending_is_empty(),
            "{what}: the exit wait's poll took the published stop"
        );
        exit_checks += 1;
        // Only now is the run loop's wait polled: it finds its stop at once.
        let mut wait = std::pin::pin!(running.wait_owned_on_ptracer_thread());
        let Poll::Ready(output) = wait.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("{what}: the wait lost its published stop after the exit wait's poll");
        };
        let (next, stop) = output.unwrap().assume_stopped();
        assert_eq!(stop, crate::Event::Syscall, "{what}");
        if to_exit {
            assert_eq!(
                next.getsyscallinfo().unwrap().operation,
                crate::SyscallInfoOp::Exit {
                    return_value: 1,
                    is_error: false
                },
                "{what}: not the read's exit"
            );
        } else {
            assert!(is_read_entry(&next), "{what}: not the next read entry");
        }
        status_reads += PTRACER_ATTACHMENT_STATUS_READS.with(Cell::get) - reads_before;
        child = next;
        wait_for_fresh_held_wait(&event, held, &what, || {});
    }
    let steps = LegacyWakeCounts::of(&event).since(start);
    let exit_wakes = event.legacy_deferred_exit_wakes.load(Ordering::Relaxed) - exit_wakes_start;
    let status_wakes =
        event.legacy_deferred_status_wakes.load(Ordering::Relaxed) - status_wakes_start;
    println!(
        "{DEFERRED_WAKE_REPORT}stop found at first poll with a parked exit wait, {STEPS} steps: \
         {steps:?}, deferral exit wakes {exit_wakes}, request wakes {request_wakes}, \
         request off-thread {request_off_thread}, exit checks {exit_checks}, \
         status reads {status_reads}, deferral status wakes {status_wakes}"
    );
    // The same exit wait gets the exit stop of a group SIGKILL.
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
    assert_eq!(
        steps,
        LegacyWakeCounts {
            turns: STEPS,
            hints: 0,
            notify_wakes: STEPS,
            flushes: 0,
            expiry_finds: 0,
        },
        "with a parked exit wait, a stop found at the first poll did not cost exactly one \
         worker wake and one turn"
    );
    assert_eq!(
        exit_checks, STEPS,
        "not every step polled the exit wait with its ordinary stop published and unclaimed"
    );
    assert_eq!(
        request_off_thread, 0,
        "a request's wake of the exit wait came from another thread"
    );
}

/// The outcome line of
/// `forced_legacy_wait_parked_before_a_rebuilt_controllers_request_gets_its_stop`.
#[cfg(not(sanitized))]
const PARKED_STATUS_WAIT_MARKER: &str =
    "wait parked before a rebuilt controller's request: woken and ready within the bound";

/// What `forced_legacy_wait_parked_before_a_rebuilt_controllers_request_gets_its_stop`
/// saw in its round, for the verdict after the teardown.
#[cfg(not(sanitized))]
#[derive(Debug)]
struct ParkedStatusWaitRound {
    latency: Option<Duration>,
    woken: usize,
    request_wakes: usize,
    request_off_thread: usize,
    status_wakes: usize,
    flushed: usize,
    expiry_finds: usize,
}

// An ordinary wait already parked before a request that another capability
// for the same generation makes still gets its stop.
// `TraceeGeneration::assume_stopped` rebuilds a controller for a tracee the
// caller knows is stopped, while the original capability waits. On the
// pipe-reading non-leader at a read entry, with its worker parked held
// (period 60 s), the controller is rebuilt, and the original capability is
// moved into its wait, which is polled once with a counting waker: Pending,
// unwoken. Only then does the rebuilt controller resume the thread into its
// read, with its Running kept, no exit waiter, and no other wait or assist.
// The wait is polled only when its waker is woken: for the request's wake,
// before the byte (that poll's empty assist sends the deferred notify), then
// after the byte. The read's exit must be ready within 50 ms of the write,
// with no stop found through a held wait's timeout. The request's deferral
// wakes the parked wait, from the ptracer thread.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_wait_parked_before_a_rebuilt_controllers_request_gets_its_stop() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_wait_parked_before_a_rebuilt_controllers_request_gets_its_stop",
        Some(PARKED_STATUS_WAIT_MARKER),
    ) {
        return;
    }
    let seen_round = Rc::new(std::cell::RefCell::new(None));
    with_deferred_wake_pipe_thread(1, |_round, entry, event, write_end, _root| {
        let seen_round = Rc::clone(&seen_round);
        async move {
            let controller = entry.generation().assume_stopped();
            let mut wait = std::pin::pin!(entry.wait_owned_on_ptracer_thread());
            let counter = ThreadWakeCounter::new();
            let waker = Waker::from(Arc::clone(&counter));
            let mut cx = Context::from_waker(&waker);
            assert!(
                wait.as_mut().poll(&mut cx).is_pending(),
                "the wait returned before the request"
            );
            assert_eq!(
                counter.wakes(),
                0,
                "the parked wait was woken before the request"
            );
            let status_wakes_before = event.legacy_deferred_status_wakes.load(Ordering::Relaxed);
            let flushes_before = event.legacy_deferred_flushes.load(Ordering::Relaxed);
            let running = controller.syscall(None).unwrap();
            let status_wakes =
                event.legacy_deferred_status_wakes.load(Ordering::Relaxed) - status_wakes_before;
            let (request_wakes, request_off_thread) = (counter.wakes(), counter.off_thread());
            // The woken task polls the wait, before the byte: Pending, and
            // its empty assist sends the deferred notify.
            let mut seen = counter.wakes();
            if seen > 0 {
                assert!(
                    wait.as_mut().poll(&mut cx).is_pending(),
                    "the read returned before its byte"
                );
            }
            let flushed = event.legacy_deferred_flushes.load(Ordering::Relaxed) - flushes_before;
            let written = Instant::now();
            deferred_wake_write(&write_end);
            let deadline = written + DEFERRED_WAKE_BOUND;
            let mut ready = None;
            while ready.is_none() && Instant::now() < deadline {
                if counter.wakes() == seen {
                    thread::sleep(Duration::from_micros(100));
                    continue;
                }
                seen = counter.wakes();
                if let Poll::Ready(output) = wait.as_mut().poll(&mut cx) {
                    ready = Some((output, written.elapsed()));
                }
            }
            let woken = counter.wakes();
            let (output, latency) = match ready {
                Some((output, latency)) => (output, Some(latency)),
                None => {
                    // Recover the stop, which stays in the kernel, so that
                    // the group is torn down cleanly before the verdict.
                    let deadline = Instant::now() + Duration::from_secs(2);
                    let output = loop {
                        if let Poll::Ready(output) = wait.as_mut().poll(&mut cx) {
                            break output;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "the read's exit was not recovered"
                        );
                        thread::sleep(Duration::from_micros(100));
                    };
                    (output, None)
                }
            };
            drop(running);
            let (exit, stop) = output.unwrap().assume_stopped();
            assert_eq!(stop, crate::Event::Syscall);
            assert_eq!(
                exit.getsyscallinfo().unwrap().operation,
                crate::SyscallInfoOp::Exit {
                    return_value: 1,
                    is_error: false
                },
                "not the read's exit"
            );
            *seen_round.borrow_mut() = Some(ParkedStatusWaitRound {
                latency,
                woken,
                request_wakes,
                request_off_thread,
                status_wakes,
                flushed,
                expiry_finds: event.legacy_held_expiry_finds.load(Ordering::Relaxed),
            });
            deferred_wake_next_read_entry(exit, &event).await
        }
    })
    .await;
    let round = seen_round.borrow_mut().take().unwrap();
    println!("wait parked before a rebuilt controller's request: {round:?}");
    assert!(
        round
            .latency
            .is_some_and(|latency| latency < DEFERRED_WAKE_BOUND),
        "the wait parked before the rebuilt controller's request was not ready within 50 ms \
         of the byte (woken {} times, write to ready {:?})",
        round.woken,
        round.latency,
    );
    assert_eq!(
        round.expiry_finds, 0,
        "the worker found the read's exit only after a held wait's timeout"
    );
    assert_eq!(
        round.status_wakes, 1,
        "the request's deferral did not wake the parked wait"
    );
    assert!(
        round.request_wakes >= 1,
        "the request did not wake the parked wait's waker"
    );
    assert_eq!(
        round.request_off_thread, 0,
        "the request's wake of the parked wait came from another thread"
    );
    assert_eq!(
        round.flushed, 1,
        "the woken poll before the byte did not send the deferred notify"
    );
    emit_completion_marker(PARKED_STATUS_WAIT_MARKER);
}

/// The outcome line of
/// `forced_legacy_counted_wake_check_refuses_extra_notifies_to_a_parked_worker`.
#[cfg(not(sanitized))]
const EXTRA_NOTIFY_MARKER: &str = "counted-wake check: the real round passed, and each extra notify to the parked worker was refused";

/// What a delivered extra notify was, how many notifies the worker counted
/// for it, and the counted-wake check of the round after it.
#[cfg(not(sanitized))]
type ExtraNotifyVerdict = (Option<LegacyNotifySource>, usize, DeferredWakeCheck);

// The counted-wake check refuses an extra notify that reaches the parked
// worker. One parked async round, as in
// `forced_legacy_deferred_wake_reaches_an_async_wait`, must pass the check.
// Then three notifies are delivered to the worker, each while it is proven
// parked in its held wait: after the check's quiescence, the test takes
// `legacy_wakeup`, which the worker releases only inside `wait_for`. Each
// carries a source that no real notify of that round can: a consume reusing
// the receipt of the round's own deferral (already used by its flush), a
// consume with no receipt, and no source. After each, the check of the same
// round must fail, naming that notify.
#[tokio::test(flavor = "current_thread")]
#[cfg(not(sanitized))]
async fn forced_legacy_counted_wake_check_refuses_extra_notifies_to_a_parked_worker() {
    if run_legacy_test_outer_with_outcome(
        "forced_legacy_counted_wake_check_refuses_extra_notifies_to_a_parked_worker",
        Some(EXTRA_NOTIFY_MARKER),
    ) {
        return;
    }
    let verdicts = Rc::new(std::cell::RefCell::new(None));
    with_deferred_wake_pipe_thread(1, |round, entry, event, write_end, _root| {
        let verdicts = Rc::clone(&verdicts);
        async move {
            let what = format!("round {round}");
            let (running, counted) =
                deferred_wake_counted_request(&event, || entry.syscall(None).unwrap());
            let mut wait = std::pin::pin!(running.wait_owned_on_ptracer_thread());
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "{what}: the read returned before its byte"
            );
            let (output, _latency) = deferred_wake_parked_wait(wait.as_mut(), &write_end, &what);
            let real = counted.check(&event, &what);
            let flush_receipt = event.legacy_wake_log.lock()[counted.log_start..]
                .iter()
                .find_map(|entry| match entry {
                    LegacyWakeLogEntry::Notified(LegacyNotifySource::Flush(receipt)) => *receipt,
                    _ => None,
                });
            let mut injected: Vec<ExtraNotifyVerdict> = Vec::new();
            for source in [
                flush_receipt.map(|receipt| LegacyNotifySource::Consume(Some(receipt))),
                Some(LegacyNotifySource::Consume(None)),
                None,
            ] {
                let delivered = event.legacy_notify_wakes.load(Ordering::Relaxed);
                {
                    // The last check left the worker quiescent in its held
                    // wait. It holds this lock until `wait_for` parks it.
                    let _parked = event.legacy_wakeup.lock();
                    if let Some(source) = source {
                        note_legacy_notify_source(source);
                    }
                    event.notify_legacy_worker();
                }
                let delivered = event.legacy_notify_wakes.load(Ordering::Relaxed) - delivered;
                injected.push((source, delivered, counted.check(&event, &what)));
            }
            *verdicts.borrow_mut() = Some((real, flush_receipt, injected));
            let (exit, stop) = output.unwrap().assume_stopped();
            assert_eq!(stop, crate::Event::Syscall);
            deferred_wake_next_read_entry(exit, &event).await
        }
    })
    .await;
    let (real, flush_receipt, injected) = verdicts.borrow_mut().take().unwrap();
    assert!(
        real.0.is_none(),
        "the real round failed the counted-wake check: {:?}",
        real.0
    );
    let flush_receipt = flush_receipt.expect("the round's flush carried no receipt");
    let reasons = [
        format!("receipt {} used by a second notify", flush_receipt.serial),
        "a consume (no receipt) made no count".to_owned(),
        "ended by a notify that named no source".to_owned(),
    ];
    for ((source, delivered, check), reason) in injected.iter().zip(&reasons) {
        assert_eq!(
            *delivered, 1,
            "the extra notify {source:?} did not reach the parked worker"
        );
        let lacks = check.0.as_deref().unwrap_or("");
        assert!(
            lacks.contains(reason.as_str()),
            "the check did not refuse the extra notify {source:?} with {reason:?}: {lacks}"
        );
    }
    println!("extra notifies to a parked worker: {injected:?}");
    emit_completion_marker(EXTRA_NOTIFY_MARKER);
}
