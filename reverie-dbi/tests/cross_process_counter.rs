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

use reverie::Pid;
use reverie_dbi::counter::RecordSyscall;
use reverie_dbi::counter::SyscallCounterGlobal;
use reverie_dbi::sync_rpc;
use reverie_rpc_transport::RpcServer;

/// Syscall numbers the children record. `SHARED` is recorded by every child;
/// `PER_CHILD_BASE + i` is recorded `i + 1` times by child `i`.
const SHARED: i32 = 999;
const PER_CHILD_BASE: i32 = 100;
const NUM_CHILDREN: usize = 5;

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

    // The client reads the socket path from the environment at first use. Set it
    // BEFORE forking and do NOT touch `sync_rpc` in the parent, so each child's
    // lazy client initializes its own fresh connection (never a shared fd).
    // SAFETY: single-threaded w.r.t. env here (the server thread does not read
    // this variable), set before any child spawns.
    unsafe { std::env::set_var(sync_rpc::RPC_SOCKET_ENV, &socket) };

    let mut child_pids = Vec::new();
    for child_index in 0..NUM_CHILDREN {
        // SAFETY: standard test-time fork; the child only performs
        // async-signal-unsafe work that is acceptable for a test harness and
        // exits via `_exit` without running at-exit handlers.
        match unsafe { libc::fork() } {
            -1 => panic!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child process: this is the only place `sync_rpc` is used, so
                // the client connects fresh here.
                let tid = Pid::from_raw(unsafe { libc::gettid() });
                for _ in 0..=child_index {
                    let () =
                        sync_rpc::send_rpc(tid, RecordSyscall(PER_CHILD_BASE + child_index as i32));
                }
                let () = sync_rpc::send_rpc(tid, RecordSyscall(SHARED));
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

    // The single shared global must now hold the fork-tree totals.
    let snapshot: std::collections::BTreeMap<i32, u64> =
        served_global.snapshot().into_iter().collect();

    // Every child recorded SHARED exactly once.
    assert_eq!(
        snapshot.get(&SHARED).copied(),
        Some(NUM_CHILDREN as u64),
        "SHARED count wrong; full snapshot: {snapshot:?}"
    );
    // Child i recorded PER_CHILD_BASE+i exactly (i+1) times.
    for child_index in 0..NUM_CHILDREN {
        let number = PER_CHILD_BASE + child_index as i32;
        assert_eq!(
            snapshot.get(&number).copied(),
            Some(child_index as u64 + 1),
            "per-child count wrong for {number}; snapshot: {snapshot:?}"
        );
    }

    // Total = NUM_CHILDREN (shared) + sum_{i=1..=N} i.
    let expected_total = NUM_CHILDREN as u64 + (1..=NUM_CHILDREN as u64).sum::<u64>();
    assert_eq!(
        served_global.total(),
        expected_total,
        "aggregate total wrong; snapshot: {snapshot:?}"
    );
}
