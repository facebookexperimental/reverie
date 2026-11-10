/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[derive(Clone, Copy, Eq, PartialEq)]
enum ManagedForkCallback {
    Clone,
    Drop,
    Wake,
}

struct ManagedWakerFork {
    callback: ManagedForkCallback,
    origin: libc::pid_t,
    armed: AtomicBool,
    fired: AtomicBool,
    read: OwnedFd,
    write: OwnedFd,
}

#[test]
fn guarded_native_reservation_keeps_local_auto_traits() {
    macro_rules! not_trait {
        ($bound:path) => {{
            trait Ambiguous<A> {
                fn witness() {}
            }
            impl<T: ?Sized> Ambiguous<()> for T {}
            struct Forbidden;
            impl<T: ?Sized + $bound> Ambiguous<Forbidden> for T {}
            let _ = <GuardedPendingStatusReservation<'static> as Ambiguous<_>>::witness;
        }};
    }
    not_trait!(Send);
    not_trait!(Sync);
}

impl ManagedWakerFork {
    fn new(callback: ManagedForkCallback) -> Arc<Self> {
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(pipe[0], libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        Arc::new(Self {
            callback,
            origin: unsafe { libc::getpid() },
            armed: AtomicBool::new(false),
            fired: AtomicBool::new(false),
            read: unsafe { OwnedFd::from_raw_fd(pipe[0]) },
            write: unsafe { OwnedFd::from_raw_fd(pipe[1]) },
        })
    }

    fn is_foreign_copy(&self) -> bool {
        (unsafe { libc::getpid() }) != self.origin
    }

    fn callback(&self, callback: ManagedForkCallback) {
        if self.callback != callback
            || !self.armed.load(Ordering::Acquire)
            || self.fired.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Return through the actual waker operation and the SDK poll in
            // the foreign kernel host. The test's post-poll branch reports
            // its real refusal before the original callback is released.
            return;
        }
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        let mut byte = 0_u8;
        loop {
            let read =
                unsafe { libc::read(self.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
            if read == 1 {
                assert_eq!(byte, b'R');
                break;
            }
            assert!(read == -1 && Errno::last() == Errno::EAGAIN);
            assert!(
                Instant::now() < deadline,
                "managed waker child report deadline"
            );
            thread::sleep(Duration::from_millis(1));
        }
        let status = waitpid_status_bounded(
            Pid::from_raw(child),
            0,
            deadline.saturating_duration_since(Instant::now()),
        )
        .unwrap();
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn report_and_exit(&self) -> ! {
        assert_eq!(
            unsafe { libc::write(self.write.as_raw_fd(), b"R".as_ptr().cast(), 1) },
            1
        );
        unsafe { libc::_exit(0) }
    }

    fn waker(self: &Arc<Self>) -> Waker {
        unsafe fn clone(data: *const ()) -> std::task::RawWaker {
            let state = unsafe { &*data.cast::<ManagedWakerFork>() };
            state.callback(ManagedForkCallback::Clone);
            unsafe { Arc::increment_strong_count(data.cast::<ManagedWakerFork>()) };
            std::task::RawWaker::new(data, &VTABLE)
        }
        unsafe fn wake(data: *const ()) {
            let state = unsafe { Arc::from_raw(data.cast::<ManagedWakerFork>()) };
            state.callback(ManagedForkCallback::Wake);
        }
        unsafe fn wake_by_ref(data: *const ()) {
            let state = unsafe { &*data.cast::<ManagedWakerFork>() };
            state.callback(ManagedForkCallback::Wake);
        }
        unsafe fn drop(data: *const ()) {
            let state = unsafe { Arc::from_raw(data.cast::<ManagedWakerFork>()) };
            state.callback(ManagedForkCallback::Drop);
        }
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        let raw = std::task::RawWaker::new(Arc::into_raw(Arc::clone(self)).cast(), &VTABLE);
        unsafe { Waker::from_raw(raw) }
    }
}

fn run_managed_native_outer(name: &str, marker: &str, unavailable: &str) -> bool {
    const INNER: &str = "SAFEPTRACE_MANAGED_NATIVE_INNER";
    if env::var_os(INNER).is_some() {
        return false;
    }
    let output = run_exact_test_bounded(
        &format!("notifier::test::{name}"),
        &[(INNER, "1")],
        false,
        Duration::from_secs(5),
    )
    .unwrap();
    match classify_exact_reuse_output(Some(&output.output), marker, unavailable).unwrap() {
        ExactReuseOutcome::Exercised => emit_completion_marker(marker),
        ExactReuseOutcome::Unavailable => println!("{unavailable}"),
    }
    assert!(!output.timed_out);
    true
}

struct ManagedNativeGuest {
    root: Pid,
    running: Option<Running>,
    guard: PtracerThreadGuard,
    terminal: TerminalCleanup,
    exit: ExitFuture,
    cleanup: TraceeCleanupGuard,
    deadline: Instant,
}

fn managed_native_guest(signal_first: bool, unavailable: &str) -> Option<ManagedNativeGuest> {
    let root = match unsafe { fork() }.unwrap() {
        ForkResult::Parent { child } => child,
        ForkResult::Child => {
            crate::traceme_and_stop().unwrap();
            if signal_first {
                assert_eq!(unsafe { libc::raise(libc::SIGUSR1) }, 0);
            }
            unsafe { libc::_exit(23) };
        }
    };
    let mut cleanup = TraceeCleanupGuard::new(root).unwrap();
    let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
    let running = match Running::try_new(root.into()) {
        Ok(running) => running,
        Err(Errno::EINVAL) => {
            pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL).unwrap();
            let status = waitpid_status_bounded(root, libc::__WALL, TRACEE_WAIT_TIMEOUT).unwrap();
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            cleanup.disarm();
            assert!(!std::path::Path::new(&format!("/proc/{root}")).exists());
            println!("{unavailable}");
            return None;
        }
        Err(error) => panic!("managed original Native capture: {error}"),
    };
    let generation = running.generation();
    let terminal = generation.terminal_cleanup();
    assert_eq!(terminal.has_thread_pidfd(), Ok(true));
    let guard = generation.ptracer_thread_guard_for_wait().unwrap();
    let stopped = generation.assume_stopped();
    drop(running);
    stopped
        .setoptions(Options::PTRACE_O_TRACEEXIT | Options::PTRACE_O_EXITKILL)
        .unwrap();
    let exit = cleanup.exit_event(&stopped).unwrap();
    let running = stopped.resume(None).unwrap();
    let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
    while if signal_first {
        terminal.pending_is_empty()
    } else {
        !terminal.exit_stop_observed()
    } {
        assert!(Instant::now() < deadline, "no actual managed Native report");
        thread::sleep(Duration::from_millis(1));
    }
    Some(ManagedNativeGuest {
        root,
        running: Some(running),
        guard,
        terminal,
        exit,
        cleanup,
        deadline,
    })
}

fn poll_managed_wait_until_ready(
    future: &mut OwnedWaitFuture,
    guard: &PtracerThreadGuard,
    deadline: Instant,
) -> Wait {
    let waker = futures::task::noop_waker();
    loop {
        match future.poll_with_ptracer_guard(&mut Context::from_waker(&waker), guard) {
            Poll::Ready(result) => return result.unwrap(),
            Poll::Pending => {
                assert!(Instant::now() < deadline, "managed Native wait deadline");
                thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

fn finish_managed_native_guest(mut guest: ManagedNativeGuest, stopped: Option<Stopped>) {
    let running = if let Some(stopped) = stopped {
        drop(guest.running.take());
        stopped.resume(None).unwrap()
    } else {
        guest.running.take().unwrap()
    };
    let waker = futures::task::noop_waker();
    let stopped = loop {
        match guest
            .exit
            .poll_with_ptracer_guard(&mut Context::from_waker(&waker), &guest.guard)
        {
            Poll::Ready(result) => break result.unwrap(),
            Poll::Pending => {
                assert!(
                    Instant::now() < guest.deadline,
                    "managed Native EXIT deadline"
                );
                thread::sleep(Duration::from_millis(1));
            }
        }
    };
    guest.cleanup.mark_claimed_exit();
    assert_eq!(stopped.getevent().unwrap(), (23 << 8) as libc::c_long);
    drop(running);
    let running = stopped.resume(None).unwrap();
    let mut final_wait = running.wait_owned();
    assert_eq!(
        poll_managed_wait_until_ready(&mut final_wait, &guest.guard, guest.deadline)
            .assume_exited(),
        (guest.root.into(), crate::ExitStatus::Exited(23))
    );
    assert!(
        guest
            .terminal
            .wait(guest.deadline.saturating_duration_since(Instant::now()))
    );
    assert!(guest.terminal.pending_is_empty());
    assert_eq!(guest.guard.check_current(), Ok(()));
    guest.cleanup.disarm();
    assert!(!std::path::Path::new(&format!("/proc/{}", guest.root)).exists());
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_wait_rechecks_after_waker_callbacks() {
    const NAME: &str = "managed_native_wait_rechecks_after_waker_callbacks";
    const MARKER: &str = "ACTUAL_MANAGED_NATIVE_WAKER_WAIT_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_WAIT_CONTROL";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    for callback in [ManagedForkCallback::Clone, ManagedForkCallback::Drop] {
        let Some(mut guest) = managed_native_guest(true, UNAVAILABLE) else {
            return;
        };
        let generation = guest.running.as_ref().unwrap().generation();
        let handle = guest.running.as_ref().unwrap().1.event().clone();
        let original_fifo = guest.terminal.queued_raw_statuses();
        assert_eq!(original_fifo, [(libc::SIGUSR1 << 8) | 0x7f]);
        let state = ManagedWakerFork::new(callback);
        let callback_waker = state.waker();
        let noop = futures::task::noop_waker();
        let active_waker = if callback == ManagedForkCallback::Drop {
            handle.event().status_waker.register(&callback_waker);
            &noop
        } else {
            &callback_waker
        };
        state.armed.store(true, Ordering::Release);
        let mut owned = guest.running.take().unwrap().wait_owned();
        let result =
            owned.poll_with_ptracer_guard(&mut Context::from_waker(active_waker), &guest.guard);
        if state.is_foreign_copy() {
            assert!(matches!(
                result,
                Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            assert_eq!(owned.generation().unwrap(), generation);
            assert_eq!(guest.terminal.queued_raw_statuses(), original_fifo);
            assert_eq!(
                handle.event().wait_owner.load(Ordering::Acquire),
                WAIT_OWNER_NOTIFIER
            );
            assert!(!owned.observed_death);
            state.report_and_exit();
        }
        assert!(state.fired.load(Ordering::Acquire));
        let stopped = match result {
            Poll::Ready(Ok(Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGUSR1)))) => {
                stopped
            }
            other => panic!("original managed wait did not recover actual SIGUSR1: {other:?}"),
        };
        assert_eq!(stopped.generation(), generation);
        assert!(owned.generation().is_none());
        assert!(guest.terminal.pending_is_empty());
        let guard = guest.guard.clone();
        let mut owned = std::thread::spawn(move || {
            let noop = futures::task::noop_waker();
            let mut cx = Context::from_waker(&noop);
            // Generic Native completion remains sibling-pollable. Managed
            // calls still authenticate the same controller after completion.
            assert!(matches!(
                std::future::Future::poll(std::pin::Pin::new(&mut owned), &mut cx),
                Poll::Ready(Err(OwnedWaitError::Completed))
            ));
            assert!(matches!(
                owned.poll_with_ptracer_guard(&mut cx, &guard),
                Poll::Ready(Err(OwnedWaitError::Errno(Errno::EPERM)))
            ));
            assert!(owned.generation().is_none());
            assert!(Arc::ptr_eq(
                &owned.managed_guard.as_ref().unwrap().owner,
                &guard.owner
            ));
            owned
        })
        .join()
        .unwrap();
        assert!(matches!(
            owned.poll_with_ptracer_guard(&mut Context::from_waker(&noop), &guest.guard),
            Poll::Ready(Err(OwnedWaitError::Completed))
        ));
        assert!(owned.generation().is_none());
        assert!(guest.terminal.pending_is_empty());
        assert_eq!(stopped.generation(), generation);
        finish_managed_native_guest(guest, Some(stopped));
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_exit_preserves_claim_across_waker_callbacks() {
    const NAME: &str = "managed_native_exit_preserves_claim_across_waker_callbacks";
    const MARKER: &str = "ACTUAL_MANAGED_NATIVE_WAKER_EXIT_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_EXIT_CONTROL";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    for callback in [ManagedForkCallback::Clone, ManagedForkCallback::Wake] {
        let Some(mut guest) = managed_native_guest(false, UNAVAILABLE) else {
            return;
        };
        let handle = guest.running.as_ref().unwrap().1.event().clone();
        let epoch = guest.exit.waiter.epoch;
        let state = ManagedWakerFork::new(callback);
        let waker = state.waker();
        state.armed.store(true, Ordering::Release);
        let result = guest
            .exit
            .poll_with_ptracer_guard(&mut Context::from_waker(&waker), &guest.guard);
        if state.is_foreign_copy() {
            assert!(matches!(
                result,
                Poll::Ready(Err(Error::Errno(Errno::EPERM)))
            ));
            assert_eq!(guest.exit.waiter.epoch, epoch);
            if callback == ManagedForkCallback::Clone {
                assert!(guest.exit.managed_delivery.is_none());
                assert_eq!(
                    handle.event().exit_capability.load(Ordering::Acquire),
                    EXIT_CAP_AVAILABLE
                );
            } else {
                let retained = guest.exit.managed_delivery.as_ref().unwrap();
                assert_eq!(
                    retained.generation(),
                    guest.running.as_ref().unwrap().generation()
                );
                assert_eq!(retained.2.0, Some(epoch));
                assert_eq!(
                    handle.event().exit_capability.load(Ordering::Acquire),
                    EXIT_CAP_CLAIMED
                );
            }
            assert!(matches!(
                guest
                    .exit
                    .poll_with_ptracer_guard(&mut Context::from_waker(&waker), &guest.guard),
                Poll::Ready(Err(Error::Errno(Errno::EPERM)))
            ));
            state.report_and_exit();
        }
        assert!(state.fired.load(Ordering::Acquire));
        let stopped = match result {
            Poll::Ready(Ok(stopped)) => stopped,
            other => panic!("original managed EXIT did not transfer actual capability: {other:?}"),
        };
        assert_eq!(stopped.2.0, Some(epoch));
        assert!(guest.exit.managed_delivery.is_none());
        guest.cleanup.mark_claimed_exit();
        assert_eq!(stopped.getevent().unwrap(), (23 << 8) as libc::c_long);
        drop(guest.running.take());
        let mut final_wait = stopped.resume(None).unwrap().wait_owned();
        assert_eq!(
            poll_managed_wait_until_ready(&mut final_wait, &guest.guard, guest.deadline)
                .assume_exited(),
            (guest.root.into(), crate::ExitStatus::Exited(23))
        );
        assert!(
            guest
                .terminal
                .wait(guest.deadline.saturating_duration_since(Instant::now()))
        );
        assert!(guest.terminal.pending_is_empty());
        guest.cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{}", guest.root)).exists());
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_exit_wakes_after_a_contended_poll() {
    const NAME: &str = "managed_native_exit_wakes_after_a_contended_poll";
    const MARKER: &str = "ACTUAL_MANAGED_NATIVE_CONTENDED_EXIT_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_CONTENDED_EXIT";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    let Some(mut guest) = managed_native_guest(false, UNAVAILABLE) else {
        return;
    };
    let handle = guest.running.as_ref().unwrap().1.event().clone();
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&counter));
    // Mechanism test: holding the lock stands in for any contender. The exit
    // stop is already published, so the only wake counted is the contended
    // poll's own.
    let contender = handle.event().exit_publication.lock();
    assert!(
        guest
            .exit
            .poll_with_ptracer_guard(&mut Context::from_waker(&waker), &guest.guard)
            .is_pending()
    );
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert!(guest.exit.managed_delivery.is_none());
    drop(contender);
    finish_managed_native_guest(guest, None);
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_reservation_preserves_front_on_foreign_refusal() {
    const NAME: &str = "managed_native_reservation_preserves_front_on_foreign_refusal";
    const MARKER: &str = "ACTUAL_MANAGED_NATIVE_RESERVATION_RECOVERY_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_RESERVATION_CONTROL";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    let Some(guest) = managed_native_guest(true, UNAVAILABLE) else {
        return;
    };
    let original_fifo = guest.terminal.queued_raw_statuses();
    let mut reservation = guest
        .terminal
        .reserve_pending_for_cleanup_with_guard(Duration::ZERO, &guest.guard)
        .unwrap()
        .unwrap();
    let status = reservation.inner.as_ref().unwrap().status;
    let forked = unsafe { libc::fork() };
    assert!(forked >= 0);
    if forked == 0 {
        assert!(matches!(
            reservation.decode(),
            Err(Error::Errno(Errno::EPERM))
        ));
        assert_eq!(reservation.commit(), Err(Errno::EPERM));
        assert_eq!(reservation.consume_dead_exec(), Err(Errno::EPERM));
        let retained = reservation.inner.as_ref().unwrap();
        assert_eq!(retained.status, status);
        assert_eq!(
            retained.state.pending.iter().copied().collect::<Vec<_>>(),
            original_fifo
        );
        unsafe { libc::_exit(0) };
    }
    let child_status =
        waitpid_status_bounded(Pid::from_raw(forked), 0, TRACEE_WAIT_TIMEOUT).unwrap();
    assert!(libc::WIFEXITED(child_status));
    assert_eq!(libc::WEXITSTATUS(child_status), 0);
    let stopped = match reservation.decode().unwrap() {
        Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGUSR1)) => stopped,
        other => panic!("original guarded reservation did not retain SIGUSR1: {other:?}"),
    };
    reservation.commit().unwrap();
    drop(reservation);
    assert!(guest.terminal.pending_is_empty());
    finish_managed_native_guest(guest, Some(stopped));
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_wait_rechecks_the_host_only_after_waker_callbacks() {
    const NAME: &str = "managed_native_wait_rechecks_the_host_only_after_waker_callbacks";
    const MARKER: &str = "ACTUAL_MANAGED_NATIVE_CALLBACK_RECHECK_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_CALLBACK_RECHECK";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    for fresh_waker in [false, true] {
        let Some(mut guest) = managed_native_guest(true, UNAVAILABLE) else {
            return;
        };
        let handle = guest.running.as_ref().unwrap().1.event().clone();
        let registered = Waker::from(Arc::new(WakeCounter::default()));
        handle.event().status_waker.register(&registered);
        let waker = if fresh_waker {
            Waker::from(Arc::new(WakeCounter::default()))
        } else {
            registered.clone()
        };
        let mut owned = guest.running.take().unwrap().wait_owned();
        let before = WAKER_CALLBACK_RECHECKS.with(Cell::get);
        let result = owned.poll_with_ptracer_guard(&mut Context::from_waker(&waker), &guest.guard);
        let rechecks = WAKER_CALLBACK_RECHECKS.with(Cell::get) - before;
        let stopped = match result {
            Poll::Ready(Ok(Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGUSR1)))) => {
                stopped
            }
            other => panic!("managed wait did not return the queued SIGUSR1: {other:?}"),
        };
        // A fresh waker's registration runs its clone callback and the old
        // waker's drop callback between the poll's entry check and the FIFO
        // reservation, so the host is checked again there. A SIGUSR1 decode
        // adopts no Event, so the decode does not check again.
        assert_eq!(
            rechecks,
            usize::from(fresh_waker),
            "fresh waker: {fresh_waker}"
        );
        finish_managed_native_guest(guest, Some(stopped));
    }
    emit_completion_marker(MARKER);
}

#[test]
#[cfg(not(sanitized))]
fn managed_native_decode_rechecks_the_host_after_child_stops() {
    for child_op in [
        crate::ChildOp::Fork,
        crate::ChildOp::Vfork,
        crate::ChildOp::Clone,
    ] {
        let (pid, stopped, mut cleanup) = spawn_new_child_tracee(child_op).unwrap();
        if stopped.terminal_cleanup().has_thread_pidfd() != Ok(true) {
            cleanup.cleanup().unwrap();
            println!("NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_MANAGED_CHILD_RECHECK");
            return;
        }
        let guard = stopped
            .generation()
            .ptracer_thread_guard_for_wait()
            .unwrap();
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        stopped.1.event().event().status_waker.register(&waker);
        let running = stopped.resume(None).unwrap();
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .unwrap();
        let mut owned = running.wait_owned();
        let mut cx = Context::from_waker(&waker);
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        let (wait, rechecks) = loop {
            let before = WAKER_CALLBACK_RECHECKS.with(Cell::get);
            match owned.poll_with_ptracer_guard(&mut cx, &guard) {
                Poll::Ready(result) => {
                    let rechecks = WAKER_CALLBACK_RECHECKS.with(Cell::get) - before;
                    break (result.unwrap(), rechecks);
                }
                Poll::Pending => {
                    assert!(Instant::now() < deadline, "{child_op:?} stop deadline");
                    thread::sleep(Duration::from_millis(1));
                }
            }
        };
        let (parent, event) = wait.assume_stopped();
        let crate::Event::NewChild(observed, child) = event else {
            cleanup.cleanup().unwrap();
            panic!("expected a {child_op:?} stop, got {event:?}");
        };
        drop(parent);
        reap_new_child_bounded(child).unwrap();
        cleanup.cleanup().unwrap();
        assert_eq!(observed, child_op);
        // The waker was registered before the wait, so only the decode,
        // which adopts the child's Event, checks the host again.
        assert_eq!(rechecks, 1, "{child_op:?}");
    }
}

#[test]
fn waker_slot_records_its_callbacks_after_they_run() {
    // Every callback of this waker clears the flag, as a nested managed poll
    // inside a callback would.
    fn clear() {
        WAKER_CALLBACKS_MAY_HAVE_RUN.with(|flag| flag.set(false));
    }
    unsafe fn clone(data: *const ()) -> std::task::RawWaker {
        clear();
        std::task::RawWaker::new(data, &VTABLE)
    }
    unsafe fn wake(_: *const ()) {
        clear();
    }
    unsafe fn wake_by_ref(_: *const ()) {
        clear();
    }
    unsafe fn drop_waker(_: *const ()) {
        clear();
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);
    let waker = |data: usize| unsafe {
        Waker::from_raw(std::task::RawWaker::new(data as *const (), &VTABLE))
    };
    let flag = || WAKER_CALLBACKS_MAY_HAVE_RUN.with(Cell::get);

    let slot = WakerSlot::default();
    let first = waker(1);
    clear();
    assert!(slot.register(&first));
    assert!(flag(), "storing a waker runs its clone");
    clear();
    assert!(!slot.register(&first));
    assert!(!flag(), "the same waker again runs nothing");
    let second = waker(2);
    clear();
    assert!(slot.register(&second));
    assert!(
        flag(),
        "replacing a waker runs the new one's clone and the old one's drop"
    );
    clear();
    slot.wake();
    assert!(flag(), "a wake runs the waker's clone and wake");
    clear();
    drop(slot);
    assert!(flag(), "dropping the slot runs the waker's drop");
}
