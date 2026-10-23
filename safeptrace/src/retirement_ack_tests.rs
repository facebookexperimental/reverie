/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

fn arm_retirement_pause(
    slot: &Mutex<Option<BoundedTestPause>>,
) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (captured, entered) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    assert!(
        slot.lock()
            .replace(BoundedTestPause { captured, resume })
            .is_none()
    );
    (entered, release)
}

#[test]
fn worker_retirement_ack_follows_registry_and_worker_identity_release() {
    let (pid, mut cleanup) = spawn_stopped_process(None).expect("spawn retirement child");
    let running = Running::new(pid.into());
    cleanup
        .bind_running_notifier(&running)
        .expect("register worker");
    let terminal = cleanup.terminal().unwrap();
    let event = Arc::clone(terminal.event.event());
    let (identity, caller_identity_refs) = {
        let registry = NOTIFIER.pids.lock();
        let entry = registry.get(&pid.into()).unwrap();
        (
            Arc::downgrade(&entry.identity),
            usize::from(Arc::ptr_eq(
                &entry.identity,
                terminal.event.identity().unwrap(),
            )),
        )
    };
    let (before_remove, release_remove) = arm_retirement_pause(&event.registry_retirement_pause);
    let (before_drop, release_drop) = arm_retirement_pause(&event.worker_identity_retirement_pause);
    pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL).expect("terminate exact child");

    before_remove
        .recv_timeout(TRACEE_WAIT_TIMEOUT)
        .expect("worker reached removal");
    let early_registry_ack = terminal.wait(Duration::ZERO);
    let observed = terminal.observed_exit_status();
    // Save observations and release each pause before assertions can unwind.
    release_remove
        .send(())
        .expect("release registry retirement");
    before_drop
        .recv_timeout(TRACEE_WAIT_TIMEOUT)
        .expect("worker reached identity drop");
    let early_identity_ack = terminal.wait(Duration::ZERO);
    let remaining_before_drop = identity.strong_count();
    let registered_after_remove = NOTIFIER.pids.lock().contains_key(&pid.into());
    release_drop.send(()).expect("release worker identity");
    let acknowledged = terminal.wait(TRACEE_WAIT_TIMEOUT);
    let remaining_after_ack = identity.strong_count();
    cleanup.disarm();

    assert!(matches!(
        observed,
        Ok(Some(crate::ExitStatus::Signaled(Signal::SIGKILL, _)))
    ));
    assert!(
        !early_registry_ack,
        "terminal acknowledgment preceded registry retirement"
    );
    assert!(
        !early_identity_ack,
        "terminal acknowledgment preceded worker identity release"
    );
    assert!(!registered_after_remove);
    assert_eq!(remaining_before_drop, caller_identity_refs + 1);
    assert!(acknowledged, "worker did not acknowledge retirement");
    assert_eq!(remaining_after_ack, caller_identity_refs);
    drop(running);
    drop(cleanup);
    assert!(
        identity.upgrade().is_none(),
        "test retained an original worker identity"
    );
}

#[test]
fn synchronous_retirement_ack_follows_registry_release() {
    let (pid, mut cleanup) = spawn_stopped_process(None).expect("spawn synchronous child");
    let running = Running::new(pid.into());
    cleanup
        .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
        .expect("store synchronous cleanup owner");
    let event = Arc::clone(cleanup.terminal().unwrap().event.event());
    let (before_remove, release) = arm_retirement_pause(&event.registry_retirement_pause);
    let observer = thread::spawn(move || {
        before_remove
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .expect("synchronous owner reached removal");
        let early_ack = event.wait_worker_done(Duration::ZERO);
        release.send(()).expect("release synchronous removal");
        early_ack
    });
    // This is still the sole wait owner. SIGCONT lets the real child return 0.
    nix::sys::signal::kill(pid, Signal::SIGCONT).expect("resume synchronous child");
    let result = running.wait();
    let early_ack = observer.join().expect("join retirement observer");
    let acknowledged = cleanup.terminal().unwrap().wait(TRACEE_WAIT_TIMEOUT);
    cleanup.disarm();
    assert!(
        matches!(result, Ok(Wait::Exited(waited, crate::ExitStatus::Exited(0))) if waited == pid.into())
    );
    assert!(
        !early_ack,
        "synchronous acknowledgment preceded registry retirement"
    );
    assert!(acknowledged);
    assert!(!NOTIFIER.pids.lock().contains_key(&pid.into()));
}

fn unstarted_retirement_ack(raw_cleanup: bool) {
    let (pid, child_cleanup) = spawn_stopped_process(None).expect("spawn unstarted child");
    let identity =
        Arc::new(WorkerIdentity::capture_process(pid.into()).expect("capture real identity"));
    let handle = EventHandle::with_identity(Arc::clone(&identity));
    // No notifier/synchronous wait owner has been installed. Reap the real
    // child with its original cleanup owner, then model its stale unstarted
    // registry entry using that same original descriptor-backed identity.
    reap_stopped_process(child_cleanup);
    {
        let mut registry = NOTIFIER.pids.lock();
        match registry.entry(pid.into()) {
            Entry::Vacant(entry) => {
                entry.insert(NotifierEntry {
                    handle: handle.clone(),
                    identity,
                });
            }
            Entry::Occupied(_) => panic!("another generation owns the registry entry"),
        }
    }
    let terminal = TerminalCleanup {
        pid: pid.into(),
        event: handle.clone(),
    };
    if raw_cleanup {
        assert!(handle.event().try_begin_unstarted_completion());
    }
    let event = Arc::clone(handle.event());
    let (before_remove, release) = arm_retirement_pause(&event.registry_retirement_pause);
    let observer = thread::spawn(move || {
        before_remove
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .expect("unstarted owner reached removal");
        // resolve_echild holds the registry lock at this boundary. Observe the
        // acknowledgment only; do not acquire that lock while it is paused.
        let early_ack = event.wait_worker_done(Duration::ZERO);
        release.send(()).expect("release unstarted removal");
        early_ack
    });
    if raw_cleanup {
        terminal.finish_unstarted_raw_cleanup();
    } else {
        NOTIFIER.resolve_echild(pid.into(), &handle);
    }
    let early_ack = observer.join().expect("join unstarted observer");
    assert!(
        !early_ack,
        "unstarted acknowledgment preceded registry retirement"
    );
    assert!(terminal.wait(Duration::ZERO));
    assert_eq!(terminal.observed_exit_status(), Err(Errno::ECHILD));
    assert!(!NOTIFIER.pids.lock().contains_key(&pid.into()));
}

#[test]
fn unstarted_echild_ack_follows_registry_release() {
    unstarted_retirement_ack(false);
}

#[test]
fn unstarted_raw_cleanup_ack_follows_registry_release() {
    unstarted_retirement_ack(true);
}

#[test]
fn wait_after_sigkill_waits_for_retirement_after_terminal_status() {
    let (pid, mut cleanup) = spawn_stopped_process(None).expect("spawn killed child");
    let running = Running::new(pid.into());
    cleanup
        .bind_running_notifier(&running)
        .expect("register worker");
    let terminal = cleanup.terminal().unwrap();
    let event = Arc::clone(terminal.event.event());
    let (before_done, release_done) = arm_retirement_pause(&event.worker_identity_retirement_pause);
    let (parking, parked) = mpsc::sync_channel(1);
    assert!(
        event
            .worker_done_park_signal
            .lock()
            .replace(parking)
            .is_none()
    );
    pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL).expect("terminate exact child");
    before_done
        .recv_timeout(TRACEE_WAIT_TIMEOUT)
        .expect("worker reached identity drop");
    // The worker has published the terminal status and removed the registry
    // entry. It withholds DONE until release_done is sent, or until its own
    // pause bound passes.
    let observed = terminal.observed_exit_status();
    let pending_empty = terminal.pending_is_empty();
    let early_ack = terminal.wait(Duration::ZERO);
    // Release the worker only after the method announces that it will park
    // for DONE with time remaining. A zero-timeout DONE check never reaches
    // that announcement. The Event holds the only announcement sender, and
    // this thread takes it out only after the method returns, so a
    // disconnection means that the method returned without parking.
    let releaser = thread::spawn(move || {
        let parked = parked.recv().is_ok();
        let released = release_done.send(()).is_ok();
        (parked, released)
    });
    let started = Instant::now();
    let result = terminal.wait_after_sigkill();
    let elapsed = started.elapsed();
    drop(event.worker_done_park_signal.lock().take());
    let (parked, released) = releaser.join().expect("join retirement releaser");
    let acknowledged = terminal.wait(TRACEE_WAIT_TIMEOUT);
    cleanup.disarm();
    eprintln!(
        "WAIT_AFTER_SIGKILL_RECEIPT result={result:?} parked={parked} released={released} \
         early_ack={early_ack} pending_empty={pending_empty} elapsed_us={} \
         acknowledged={acknowledged}",
        elapsed.as_micros(),
    );
    assert!(matches!(
        observed,
        Ok(Some(crate::ExitStatus::Signaled(Signal::SIGKILL, _)))
    ));
    assert!(pending_empty, "a nonterminal status was queued after SIGKILL");
    assert!(!early_ack, "DONE was published while the worker was paused");
    assert!(
        result.is_ok(),
        "wait_after_sigkill failed while the worker withheld DONE: {result:?}"
    );
    assert!(
        parked,
        "wait_after_sigkill returned without waiting for DONE with time remaining"
    );
    assert!(acknowledged, "worker did not acknowledge retirement");
    drop(running);
    drop(cleanup);
}
