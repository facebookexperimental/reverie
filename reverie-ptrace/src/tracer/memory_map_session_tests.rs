/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod memory_map_session_tests {
    use super::*;

    fn memory_map(session: &FatalSession, tid: Pid) -> Result<reverie::MemoryMap, reverie::FactError> {
        crate::memory_map::read(tid, |tid| session.traced_directories(tid))
    }

    /// A child that the session captured at its parent's fork event, and that
    /// no owner has registered yet, is a task the session traces: its map is
    /// read through the directory captured with it, the kernel's own map of
    /// the child, stopped at its fork. Before the capture, and once the
    /// newborn leaves the session's record, it is ESRCH, and so are the root,
    /// captured but neither registered nor a newborn, and this test's own
    /// thread.
    #[tokio::test(flavor = "current_thread")]
    async fn memory_map_answers_for_a_newborn_no_owner_has_taken() {
        let deadline = Instant::now() + Duration::from_secs(3);
        let stopped = group_fixture_root(GroupFixtureAttach::Traceme, true).await;
        let root = stopped.pid();
        let session = FatalSession::for_test(root);
        session.capture_root(&stopped);
        let exit = stopped.exit_event_on_ptracer_thread();
        let (stopped, event) = tokio::time::timeout_at(
            deadline.into(),
            stopped.resume(None).unwrap().wait_owned_on_ptracer_thread(),
        )
        .await
        .unwrap()
        .unwrap()
        .assume_stopped();
        let Event::NewChild(ChildOp::Fork, child) = event else {
            panic!("actual fork event required, got {event:?}");
        };
        let child_tid = child.pid();
        let child_terminal = child.terminal_cleanup();
        let no_thread = Err(reverie::FactError::Errno(Errno::ESRCH));
        assert_eq!(memory_map(&session, child_tid), no_thread);
        session.capture_for_group_stop_test(root, ChildOp::Fork, &child);
        let text = std::fs::read(format!("/proc/{child_tid}/maps")).unwrap();
        let map = memory_map(&session, child_tid).unwrap();
        assert!(map.complete);
        assert_eq!(Ok(map), reverie::MemoryMap::from_maps(&text));
        // SAFETY: gettid takes no arguments and cannot fail.
        let this_thread = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        for tid in [root, this_thread] {
            assert_eq!(memory_map(&session, tid), no_thread, "{tid}");
        }
        let newborn = session
            .take_group_stop_newborn_for_test(&child_terminal)
            .expect("original captured exit receiver");
        assert_eq!(memory_map(&session, child_tid), no_thread);
        let child_waits = newborn.waits.clone();
        newborn.signal().unwrap();
        let child_exit = tokio::time::timeout_at(deadline.into(), newborn.into_exit())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tokio::time::timeout_at(
                deadline.into(),
                child_waits.wait_running(child_exit.resume(None).unwrap())
            )
            .await
            .unwrap()
            .unwrap()
            .assume_exited(),
            (child_tid, ExitStatus::Signaled(Signal::SIGKILL, false))
        );
        finish_group_fixture_root(stopped.resume(None).unwrap(), exit, deadline).await;
        assert_reaped("memory map newborn", child_tid);
    }
}
