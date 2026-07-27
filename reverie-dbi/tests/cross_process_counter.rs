/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end verification of the DBI cross-process GlobalState IPC.
//!
//! A coordinator hosts the tokio [`RpcServer`] owning one shared
//! [`SyscallCounterGlobal`]; several `fork(2)` children each connect with the
//! synchronous [`reverie_dbi::sync_rpc`] client (as the injected DBI guest does)
//! and record syscalls. The final histogram in the single global must equal the
//! sum across the whole process tree — the property the in-process `()` global
//! could not provide.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use reverie::Error;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_dbi::DbiSyscallOutcome;
use reverie_dbi::counter::RecordSyscall;
use reverie_dbi::counter::SyscallCounterGlobal;
use reverie_dbi::run_tool_syscall;
use reverie_dbi::sync_rpc;
use reverie_rpc_transport::RpcServer;

/// Syscall numbers the children record. `SHARED` is recorded by every child;
/// `PER_CHILD[i]` is recorded `i + 1` times by child `i`.
const SHARED: i32 = libc::SYS_getpid as i32;
const PARENT_BEFORE_FORK: i32 = libc::SYS_getppid as i32;
const PARENT_AFTER_FORK: i32 = libc::SYS_gettid as i32;
const PER_CHILD: [i32; 5] = [
    libc::SYS_read as i32,
    libc::SYS_write as i32,
    libc::SYS_close as i32,
    libc::SYS_fstat as i32,
    libc::SYS_lseek as i32,
];
const NUM_CHILDREN: usize = PER_CHILD.len();

#[derive(Clone, Copy, Debug, Default)]
struct CounterTool;

#[reverie::tool]
impl Tool for CounterTool {
    type GlobalState = SyscallCounterGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let _ = guest.send_rpc(RecordSyscall(syscall.number().id())).await;
        guest.tail_inject(syscall).await
    }
}

unsafe extern "C" fn unexpected_invoke(_context: usize, _sysnum: i64, _args: *const u64) -> i64 {
    panic!("counter tool unexpectedly injected a syscall")
}

unsafe extern "C" fn registers_unavailable(
    _context: usize,
    _regs: *mut libc::user_regs_struct,
) -> i32 {
    0
}

unsafe extern "C" fn reject_register_write(
    _context: usize,
    _regs: *const libc::user_regs_struct,
) -> i32 {
    0
}

fn record_with_dbi_tool(number: i32) {
    let tid = Pid::from_raw(unsafe { libc::gettid() });
    let pid = Pid::from_raw(unsafe { libc::getpid() });
    let syscall = Syscall::from_raw(Sysno::from(number), SyscallArgs::new(0, 0, 0, 0, 0, 0));
    let mut thread_state = ();
    let local_placeholder = SyscallCounterGlobal::default();
    let outcome = run_tool_syscall(
        &CounterTool,
        0,
        tid,
        pid,
        0,
        &mut thread_state,
        &local_placeholder,
        &(),
        syscall,
        unexpected_invoke,
        registers_unavailable,
        reject_register_write,
    )
    .expect("DBI counter tool dispatch failed");
    match outcome {
        DbiSyscallOutcome::ExecuteOriginal(original) => {
            assert_eq!(original.number().id(), number)
        }
        DbiSyscallOutcome::Suppress(result) => {
            panic!("counter tool unexpectedly suppressed syscall {number} with {result}")
        }
    }
}

#[test]
fn syscall_counter_global_aggregates_across_fork_tree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("dbi-rpc.sock");

    // Coordinator: serve one shared global on a dedicated tokio runtime thread.
    // The parent keeps its own clone of the same `Arc` to read the final total;
    // the bind/serve must run *inside* the runtime (tokio's UnixListener needs a
    // reactor).
    let global = Arc::new(SyscallCounterGlobal::default());
    let served_global = global.clone();
    let server_socket = socket.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            let server = RpcServer::bind(&server_socket, global, ()).expect("bind RpcServer");
            // serve() only returns on listener failure; the test process exits
            // when the test ends, tearing this thread down.
            let _ = server.serve().await;
        });
    });

    // Wait for the listener socket to appear before forking clients.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "server socket never appeared");
        std::thread::sleep(Duration::from_millis(5));
    }

    // The client reads the socket path from the environment at first use. Use
    // it in the parent before forking: every child now inherits an initialized
    // client slot and must detect its changed pid, discard the inherited
    // parent socket, and establish its own connection.
    // SAFETY: single-threaded w.r.t. env here (the server thread does not read
    // this variable), set before any child spawns.
    unsafe { std::env::set_var(sync_rpc::RPC_SOCKET_ENV, &socket) };
    record_with_dbi_tool(PARENT_BEFORE_FORK);

    let mut child_pids = Vec::new();
    for (child_index, child_syscall) in PER_CHILD.into_iter().enumerate() {
        // SAFETY: standard test-time fork; the child only performs
        // async-signal-unsafe work that is acceptable for a test harness and
        // exits via `_exit` without running at-exit handlers.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child process: the first Tool RPC must replace the inherited
                // parent connection before recording this child's events.
                for _ in 0..=child_index {
                    record_with_dbi_tool(child_syscall);
                }
                record_with_dbi_tool(SHARED);
                // Bypass Rust's normal teardown to avoid double-flushing shared
                // buffers inherited from the parent.
                unsafe { libc::_exit(0) };
            }
            pid => child_pids.push(pid),
        }
    }

    // Reap all children and require clean exits.
    for pid in child_pids {
        let mut status = 0i32;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed for child {pid}");
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "child {pid} exited abnormally: status={status}"
        );
    }

    // The parent's original connection remains usable after every child has
    // discarded its inherited copy and reconnected independently.
    record_with_dbi_tool(PARENT_AFTER_FORK);

    // The single shared global must now hold the fork-tree totals.
    let snapshot: std::collections::BTreeMap<i32, u64> =
        served_global.snapshot().into_iter().collect();

    // Every child recorded SHARED exactly once.
    assert_eq!(
        snapshot.get(&SHARED).copied(),
        Some(NUM_CHILDREN as u64),
        "SHARED count wrong; full snapshot: {snapshot:?}"
    );
    assert_eq!(snapshot.get(&PARENT_BEFORE_FORK).copied(), Some(1));
    assert_eq!(snapshot.get(&PARENT_AFTER_FORK).copied(), Some(1));
    // Child i recorded PER_CHILD[i] exactly (i+1) times.
    for (child_index, number) in PER_CHILD.into_iter().enumerate() {
        assert_eq!(
            snapshot.get(&number).copied(),
            Some(child_index as u64 + 1),
            "per-child count wrong for {number}; snapshot: {snapshot:?}"
        );
    }

    // Total = NUM_CHILDREN (shared) + sum_{i=1..=N} i.
    let expected_total = NUM_CHILDREN as u64 + (1..=NUM_CHILDREN as u64).sum::<u64>() + 2;
    assert_eq!(
        served_global.total(),
        expected_total,
        "aggregate total wrong; snapshot: {snapshot:?}"
    );
}
