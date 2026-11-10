/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod link_path_session_tests {
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    fn link_path(
        session: &FatalSession,
        tid: Pid,
        link: reverie::PathLink,
    ) -> Result<reverie::LinkPath, reverie::FactError> {
        crate::link_path::read(tid, link, |tid| session.traced_directories(tid))
    }

    /// A child that the session captured at its parent's fork event, and that
    /// no owner has registered yet, is a task the session traces: its links
    /// are read through the directory captured with it. The fixture forks
    /// this test process without an exec, so the child's image and working
    /// directory are this process's. Before the capture, and once the
    /// newborn leaves the session's record, it is ESRCH, and so are the root,
    /// captured but neither registered nor a newborn, and this test's own
    /// thread.
    #[tokio::test(flavor = "current_thread")]
    async fn link_path_answers_for_a_newborn_no_owner_has_taken() {
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
        let links = [
            reverie::PathLink::Executable,
            reverie::PathLink::WorkingDirectory,
            reverie::PathLink::Descriptor(0),
        ];
        for link in links {
            assert_eq!(link_path(&session, child_tid, link), no_thread, "{link:?}");
        }
        session.capture_for_group_stop_test(root, ChildOp::Fork, &child);
        let own = |link: &str| {
            let path = std::fs::read_link(format!("/proc/self/{link}")).unwrap();
            Ok(reverie::LinkPath::Path(path.as_os_str().as_bytes().to_vec()))
        };
        assert_eq!(
            link_path(&session, child_tid, reverie::PathLink::Executable),
            own("exe")
        );
        assert_eq!(
            link_path(&session, child_tid, reverie::PathLink::WorkingDirectory),
            own("cwd")
        );
        // SAFETY: gettid takes no arguments and cannot fail.
        let this_thread = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        for tid in [root, this_thread] {
            for link in links {
                assert_eq!(link_path(&session, tid, link), no_thread, "{tid} {link:?}");
            }
        }
        let newborn = session
            .take_group_stop_newborn_for_test(&child_terminal)
            .expect("original captured exit receiver");
        for link in links {
            assert_eq!(link_path(&session, child_tid, link), no_thread, "{link:?}");
        }
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
        assert_reaped("link path newborn", child_tid);
    }
}
