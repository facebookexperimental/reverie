/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend reports when the kernel publishes a guest child
//! process's exit to its parent (`BackendCapabilities::reports_child_exit_publication`):
//! once per process, after the tracer consumed the leader's final status and
//! before the Tool's exit hooks for that process.

use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Tool;
use reverie_ptrace::testing::test_fn;

/// A process lifecycle event as the global state saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    /// `GlobalTool::on_backend_process_exited`.
    Published(i32),
    /// `Tool::on_exit_process`, reported by RPC.
    ExitProcess(i32),
}

#[derive(Default)]
struct PublicationLog {
    events: Mutex<Vec<Lifecycle>>,
}

#[reverie::global_tool]
impl GlobalTool for PublicationLog {
    type Request = i32;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, pid: i32) {
        self.events
            .lock()
            .expect("publication log lock poisoned")
            .push(Lifecycle::ExitProcess(pid));
    }

    fn on_backend_process_exited(&self, pid: i32) {
        self.events
            .lock()
            .expect("publication log lock poisoned")
            .push(Lifecycle::Published(pid));
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PublicationTool;

#[reverie::tool]
impl Tool for PublicationTool {
    type GlobalState = PublicationLog;
    type ThreadState = ();

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state.send_rpc(pid.as_raw()).await;
        Ok(())
    }
}

#[test]
fn ptrace_reports_child_exit_publication_once_before_exit_hooks() {
    const { assert!(reverie::BackendCapabilities::PTRACE.reports_child_exit_publication) };
    let (output, log) = test_fn::<PublicationTool, _>(|| unsafe {
        let child = libc::fork();
        if child == 0 {
            libc::_exit(7);
        }
        let mut status = 0;
        if libc::waitpid(child, &mut status, 0) != child
            || !libc::WIFEXITED(status)
            || libc::WEXITSTATUS(status) != 7
        {
            libc::_exit(1);
        }
        libc::syscall(libc::SYS_exit_group, 0);
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
    let events = log.events.lock().unwrap().clone();
    // The root's exit hook runs last; every other event is the child's.
    let root = events
        .iter()
        .rev()
        .find_map(|event| match event {
            Lifecycle::ExitProcess(pid) => Some(*pid),
            Lifecycle::Published(_) => None,
        })
        .expect("the root process's exit hook ran");
    let child_events: Vec<_> = events
        .iter()
        .copied()
        .filter(|event| match event {
            Lifecycle::Published(pid) | Lifecycle::ExitProcess(pid) => *pid != root,
        })
        .collect();
    let child = match child_events.first() {
        Some(Lifecycle::Published(pid)) => *pid,
        other => panic!("the child's first lifecycle event was {other:?}, in {events:?}"),
    };
    assert_eq!(
        child_events,
        vec![Lifecycle::Published(child), Lifecycle::ExitProcess(child)],
        "all events: {events:?}"
    );
}
