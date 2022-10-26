/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Tests for process and thread state.

use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default)]
struct GlobalState {
    // Map of pids to parent pids and syscall counts. This is only updated when
    // a process exits.
    tree: Mutex<Vec<(i32, Vec<(i32, usize, usize)>)>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ThreadState {
    // Number of syscalls executed by this thread.
    syscalls: usize,

    // Number of children this thread has.
    children: AtomicUsize,
}

#[reverie::global_tool]
impl GlobalTool for GlobalState {
    type Request = Vec<(i32, usize, usize)>;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, threads: Self::Request) -> Self::Response {
        // Merge with global state.
        self.tree.lock().unwrap().push((from.as_raw(), threads));
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TestTool {
    // Vec of thread ids and their syscall counts and children. This is only
    // updated when a thread exits.
    threads: Mutex<Vec<(i32, usize, usize)>>,
}

#[reverie::tool]
impl Tool for TestTool {
    type GlobalState = GlobalState;
    type ThreadState = ThreadState;

    fn init_thread_state(
        &self,
        _tid: Pid,
        parent: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        if let Some((_, parent)) = parent {
            parent.children.fetch_add(1, Ordering::Relaxed);
        }

        ThreadState::default()
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state
            .send_rpc(self.threads.into_inner().unwrap())
            .await;
        Ok(())
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _global_state: &G,
        thread_state: Self::ThreadState,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        self.threads.lock().unwrap().push((
            tid.as_raw(),
            thread_state.syscalls,
            thread_state.children.load(Ordering::Relaxed),
        ));
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.thread_state_mut().syscalls += 1;
        guest.tail_inject(syscall).await
    }
}

#[cfg(not(sanitized))]
#[test]
fn basic_test() {
    use reverie_ptrace::testing::check_fn;

    let state = check_fn::<TestTool, _>(|| {
        // Spawn some top-level threads
        let handles = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    // ...with child threads
                    (0..4)
                        .map(|_| {
                            std::thread::spawn(|| {
                                // ...that call getpid a bunch of times.
                                for _ in 0..100 {
                                    let _ = unsafe { libc::getpid() };
                                }
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();

        for handles in handles {
            for handle in handles.join().unwrap() {
                handle.join().unwrap();
            }
        }
    });

    let mut tree = state.tree.lock().unwrap();
    let threads = tree.pop().unwrap().1;

    // There should have been only a single top-level process.
    assert!(tree.is_empty());

    // We spawned 20 threads and one thread group loader (21 in total).
    // 4 of the threads simply wait on child threads and 16 of the
    // threads do the bogus syscalls.
    assert_eq!(threads.len(), 21);

    // Partition the threads based on how many children they had.
    let (parent_threads, child_threads) = threads
        .into_iter()
        .partition::<Vec<_>, _>(|&(_, _, children)| children > 0);

    assert_eq!(parent_threads.len(), 5);
    assert_eq!(child_threads.len(), 16);

    // The first 4 threads are the ones with 4 children each.
    for (_tid, _count, children) in parent_threads {
        assert_eq!(children, 4);
    }

    // The other 16 threads do the syscalls.
    for (_tid, count, _children) in child_threads {
        assert!(count >= 100);
    }
}
