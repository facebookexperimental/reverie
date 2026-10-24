/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The exit-stop probe of `Stopped::transition_unless_left_for_exit` treats a
// procfs error as an error, never as a lifecycle verdict
// (https://github.com/rrnewton/reverie/issues/1091).

fn set_bound_stat_flags_error(error: Option<ProcStatError>) {
    BOUND_STAT_FLAGS_ERROR_FOR_TEST.with(|slot| *slot.borrow_mut() = error);
}

/// The guest thread's state letter from its stat record.
fn proc_state(pid: Pid) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().next().map(str::to_owned)
}

/// An unreadable stat record (`EMFILE`) and a permission-shaped `ENOENT` with
/// a live pidfd are no verdict: the guarded transition and the pre-write
/// probe refuse with that error, and the held stop is not resumed.
#[test]
#[cfg(not(sanitized))]
fn an_unobservable_exit_probe_refuses_without_resuming() {
    const NAME: &str = "an_unobservable_exit_probe_refuses_without_resuming";
    const MARKER: &str = "ACTUAL_EXIT_PROBE_ERRORS_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_EXIT_PROBE_CONTROL";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    let Some(mut guest) = managed_native_guest(true, UNAVAILABLE) else {
        return;
    };
    let original_fifo = guest.terminal.queued_raw_statuses();
    let generation = guest.running.as_ref().unwrap().generation();
    for (error, expected) in [
        (ProcStatError::Io(Errno::EMFILE), Errno::EMFILE),
        (ProcStatError::Io(Errno::ENOENT), Errno::ENOENT),
    ] {
        set_bound_stat_flags_error(Some(error.clone()));
        let held = generation.assume_stopped();
        assert!(
            matches!(
                held.died_into_exit_stop_before_resume(),
                Some(Error::Errno(errno)) if errno == expected
            ),
            "the pre-write probe gave no {expected} for {error:?}"
        );
        let transition = held.transition_unless_left_for_exit(crate::Transition::Cont(0));
        set_bound_stat_flags_error(None);
        assert!(
            matches!(transition, Err(Error::Errno(errno)) if errno == expected),
            "the guarded transition did not refuse with {expected} for {error:?}: {transition:?}"
        );
        assert_eq!(
            proc_state(guest.root).as_deref(),
            Some("t"),
            "{error:?} let the held stop be resumed"
        );
        assert_eq!(guest.terminal.queued_raw_statuses(), original_fifo);
    }
    let mut owned = guest.running.take().unwrap().wait_owned();
    let stopped = match poll_managed_wait_until_ready(&mut owned, &guest.guard, guest.deadline) {
        Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGUSR1)) => stopped,
        other => panic!("the queued SIGUSR1 was not kept: {other:?}"),
    };
    finish_managed_native_guest(guest, Some(stopped));
    emit_completion_marker(MARKER);
}

/// `ENOENT` from the stat read is decided by the retained pidfd: dead is
/// death (`Died`), and a failed liveness check is that check's error. Both
/// answers are injected; the stop itself stays live and is not resumed.
#[test]
#[cfg(not(sanitized))]
fn an_exit_probe_enoent_is_decided_by_the_pidfd() {
    const NAME: &str = "an_exit_probe_enoent_is_decided_by_the_pidfd";
    const MARKER: &str = "ACTUAL_EXIT_PROBE_PIDFD_EXERCISED";
    const UNAVAILABLE: &str = "NATIVE_THREAD_PIDFD_UNAVAILABLE_FOR_EXIT_PROBE_PIDFD_CONTROL";
    if run_managed_native_outer(NAME, MARKER, UNAVAILABLE) {
        return;
    }
    let Some(mut guest) = managed_native_guest(true, UNAVAILABLE) else {
        return;
    };
    let generation = guest.running.as_ref().unwrap().generation();
    set_bound_stat_flags_error(Some(ProcStatError::Io(Errno::ENOENT)));
    BOUND_PIDFD_LIVE_FOR_TEST.with(|slot| slot.set(Some(Ok(false))));
    let dead = generation
        .assume_stopped()
        .transition_unless_left_for_exit(crate::Transition::Cont(0));
    BOUND_PIDFD_LIVE_FOR_TEST.with(|slot| slot.set(Some(Err(Errno::EPERM))));
    let unknown = generation
        .assume_stopped()
        .transition_unless_left_for_exit(crate::Transition::Cont(0));
    BOUND_PIDFD_LIVE_FOR_TEST.with(|slot| slot.set(None));
    set_bound_stat_flags_error(None);
    assert!(
        matches!(dead, Err(Error::Died(_))),
        "ENOENT with a dead pidfd was not death: {dead:?}"
    );
    assert!(
        matches!(unknown, Err(Error::Errno(Errno::EPERM))),
        "ENOENT with an unanswerable pidfd was not its error: {unknown:?}"
    );
    assert_eq!(proc_state(guest.root).as_deref(), Some("t"));
    let mut owned = guest.running.take().unwrap().wait_owned();
    let stopped = match poll_managed_wait_until_ready(&mut owned, &guest.guard, guest.deadline) {
        Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGUSR1)) => stopped,
        other => panic!("the queued SIGUSR1 was not kept: {other:?}"),
    };
    finish_managed_native_guest(guest, Some(stopped));
    emit_completion_marker(MARKER);
}
