/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests for parallelism and concurrency

use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Tid;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;
use tokio::time::sleep;
use tokio::time::Duration;

#[derive(Debug, Serialize, Deserialize, Default)]
struct GlobalState {}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TestTool {}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _from: Tid, _threads: Self::Request) -> Self::Response {
        // TODO: replace this with an ivar read:
        for _i in 0..400_000 {
            tokio::task::yield_now().await;
        }
        sleep(Duration::from_millis(1000)).await;
        // Overkill: spin this async task to make sure there are plenty of turns of the
        // other thread.
        for _i in 0..400_000 {
            tokio::task::yield_now().await;
        }
    }
}

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = GlobalState;
    type ThreadState = u64;

    fn init_thread_state(
        &self,
        _tid: Tid,
        parent: Option<(Tid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        match parent {
            None => 0,
            Some((_, n)) => n + 1,
        }
    }

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        if guest.is_root_thread() {
            eprintln!("Root thread starting...");
        } else {
            eprintln!("Delaying child thread!");
            guest.send_rpc(()).await;
            eprintln!("Done delaying child thread!");
        }
        Ok(())
    }
}

/// A test to interleave writes on memory.
#[test]
#[cfg(not(sanitized))]
pub fn delay_childprint_test() {
    use reverie::ExitStatus;
    use reverie_ptrace::testing::print_tracee_output;
    use reverie_ptrace::testing::test_fn;

    let (output, _state) = test_fn::<TestTool, _>(|| {
        let child = std::thread::spawn(move || {
            for _ in 0..2 {
                nix::unistd::write(1, b"a").unwrap();
            }
        });
        for _ in 0..100 {
            nix::unistd::write(1, b"b").unwrap();
        }
        child.join().unwrap();
        nix::unistd::write(1, b"\n").unwrap();
    })
    .unwrap();

    print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout.len(), 103);
    assert_eq!(output.stderr.len(), 0);
    // Because the child was delayed it must finish last:
    assert_eq!(output.stdout[101] as char, 'a');
}

// A test tool that blocks a handler indefinitely.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TestTool2 {}

#[reverie::tool]
impl Tool for TestTool2 {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Gettid(_) = call {
            // Delay forever. When the main thread is killed, this future should
            // get canceled.
            futures::future::pending::<()>().await;
        }

        guest.tail_inject(call).await
    }
}

#[cfg(not(sanitized))]
fn kill_blocked_child() {
    use std::sync::Arc;
    use std::sync::Barrier;

    let barrier = Arc::new(Barrier::new(2));

    let _handle = {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            unsafe { libc::syscall(libc::SYS_gettid, 0) };
        })
    };

    // Wait for the thread to start up.
    barrier.wait();

    // This should cause the handler future for the thread to get dropped the
    // next time it is polled.
    unsafe { libc::syscall(libc::SYS_exit_group, 0) };

    unreachable!()
}

/// Test where handle_syscall_event blocks a child thread forever. The
/// expectation is that calling `exit_group` will cancel the
/// `handle_syscall_event` future.
#[cfg(not(sanitized))]
#[test]
pub fn test_kill_blocked_child() {
    use reverie::ExitStatus;
    use reverie_ptrace::testing::test_fn;

    let (output, _state) = test_fn::<TestTool2, _>(kill_blocked_child).unwrap();
    reverie_ptrace::testing::print_tracee_output(&output);
    assert_eq!(output.status, ExitStatus::Exited(0));
}
