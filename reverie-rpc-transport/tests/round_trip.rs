/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! End-to-end round-trip tests for the cross-process GlobalTool RPC over a real
//! Unix-domain socket.
//!
//! The key property under test is the one the DBT backend currently lacks:
//! multiple independent client connections (standing in for the processes of a
//! `fork` tree) all reach **one shared** `GlobalTool` instance, so their effects
//! aggregate instead of fragmenting per-process.

use std::future::Future;
use std::pin::pin;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcClient;
use reverie_rpc_transport::RpcServer;

/// A minimal global tool: it sums the increments it receives (like a syscall
/// counter aggregating across a process tree) and echoes back the originating
/// tid so we can check tid propagation.
#[derive(Default)]
struct Counter {
    total: Mutex<u64>,
    froms: Mutex<Vec<i32>>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Reply {
    running_total: u64,
    from: i32,
}

#[async_trait]
impl GlobalTool for Counter {
    type Request = u64;
    type Response = Reply;
    type Config = String;

    async fn receive_rpc(&self, from: Tid, increment: u64) -> Reply {
        self.froms.lock().unwrap().push(from.as_raw());
        let mut total = self.total.lock().unwrap();
        *total += increment;
        Reply {
            running_total: *total,
            from: from.as_raw(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum GateRequest {
    Wait,
    Release,
}

#[derive(Default)]
struct Gate {
    waiting: AtomicBool,
    release: tokio::sync::Notify,
}

#[async_trait]
impl GlobalTool for Gate {
    type Request = GateRequest;
    type Response = i32;
    type Config = String;

    async fn receive_rpc(&self, from: Tid, request: GateRequest) -> i32 {
        match request {
            GateRequest::Wait => {
                let released = self.release.notified();
                self.waiting.store(true, Ordering::Release);
                released.await;
            }
            GateRequest::Release => self.release.notify_one(),
        }
        from.as_raw()
    }
}

/// Allocate a unique, short-lived socket path under the temp dir.
fn unique_sock_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("reverie-rpc-{tag}-{}-{n}.sock", std::process::id()))
}

#[tokio::test]
async fn aggregates_across_many_connections() {
    let global = std::sync::Arc::new(Counter::default());
    let path = unique_sock_path("aggregate");
    let server = RpcServer::bind(&path, global.clone(), "cfg-value".to_string()).unwrap();
    let server_path = server.path().to_path_buf();
    let handle = tokio::spawn(async move { server.serve().await });

    // Simulate 5 "processes", each performing 100 increments of 1 => 500 total,
    // all landing in one shared Counter behind the coordinator.
    let procs = 5;
    let per_proc = 100u64;
    for p in 0..procs {
        let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(p))
            .await
            .expect("connect");
        // Config handshake delivered the coordinator's config to this "process".
        assert_eq!(client.config(), "cfg-value");
        let mut last = 0;
        for _ in 0..per_proc {
            let reply = client.send_rpc(1).await;
            assert_eq!(reply.from, p);
            last = reply.running_total;
        }
        // Running total is monotonic and reflects prior processes' effects too.
        assert!(last >= per_proc);
    }

    let final_total = *global.total.lock().unwrap();
    assert_eq!(
        final_total,
        procs as u64 * per_proc,
        "all connections must aggregate into one shared global state"
    );
    // Every request carried its originating tid.
    let froms = global.froms.lock().unwrap();
    assert_eq!(froms.len(), (procs as u64 * per_proc) as usize);
    for p in 0..procs {
        assert_eq!(froms.iter().filter(|&&f| f == p).count(), per_proc as usize);
    }

    handle.abort();
}

#[tokio::test]
async fn connection_monitor_wakes_only_after_the_last_client_closes() {
    let global = std::sync::Arc::new(Counter::default());
    let path = unique_sock_path("connection-monitor");
    let server = RpcServer::bind(&path, global, "monitor".to_string()).unwrap();
    let monitor = server.connection_monitor();
    let server_path = server.path().to_path_buf();
    let serving = tokio::spawn(async move { server.serve().await });

    let first = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(1))
        .await
        .unwrap();
    let second = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(2))
        .await
        .unwrap();
    assert_eq!(monitor.active_connections(), 2);

    let mut idle = tokio::spawn({
        let monitor = monitor.clone();
        async move { monitor.wait_for_idle().await }
    });
    tokio::task::yield_now().await;
    assert!(!idle.is_finished(), "an active connection reported idle");

    drop(first);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut idle)
            .await
            .is_err(),
        "the first close woke the idle waiter while a client remained"
    );

    drop(second);
    tokio::time::timeout(Duration::from_secs(1), idle)
        .await
        .expect("the last close did not promptly wake the idle waiter")
        .unwrap();
    assert_eq!(monitor.active_connections(), 0);

    serving.abort();
    let _ = serving.await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn aborting_server_drops_live_connection_tasks() {
    let global = std::sync::Arc::new(Counter::default());
    let path = unique_sock_path("abort-connections");
    let server = RpcServer::bind(&path, global.clone(), "cfg".to_string()).unwrap();
    let server_path = server.path().to_path_buf();
    let handle = tokio::spawn(async move { server.serve().await });

    let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(8))
        .await
        .expect("connect");
    assert_eq!(client.config(), "cfg");
    assert_eq!(std::sync::Arc::strong_count(&global), 3);

    handle.abort();
    assert!(handle.await.unwrap_err().is_cancelled());
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while std::sync::Arc::strong_count(&global) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection task retained the shared global after server shutdown");

    drop(client);
}

#[tokio::test]
async fn single_connection_round_trip_values() {
    let global = std::sync::Arc::new(Counter::default());
    let path = unique_sock_path("single");
    let server = RpcServer::bind(&path, global.clone(), "hello".to_string()).unwrap();
    let server_path = server.path().to_path_buf();
    let handle = tokio::spawn(async move { server.serve().await });

    let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(7))
        .await
        .expect("connect");
    assert_eq!(client.config(), "hello");

    assert_eq!(
        client.send_rpc(10).await,
        Reply {
            running_total: 10,
            from: 7
        }
    );
    assert_eq!(
        client.send_rpc(5).await,
        Reply {
            running_total: 15,
            from: 7
        }
    );

    handle.abort();
}

#[tokio::test]
async fn readiness_is_published_on_first_request() {
    let global = std::sync::Arc::new(Counter::default());
    let readiness = std::sync::Arc::new(AtomicBool::new(false));
    let path = unique_sock_path("readiness");
    let server =
        RpcServer::bind_with_readiness(&path, global, "ready-cfg".to_string(), readiness.clone())
            .unwrap();
    let server_path = server.path().to_path_buf();
    let handle = tokio::spawn(async move { server.serve().await });

    let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(12))
        .await
        .expect("connect");
    assert!(!readiness.load(Ordering::Acquire));
    assert_eq!(client.send_rpc(1).await.running_total, 1);
    assert!(readiness.load(Ordering::Acquire));

    handle.abort();
}

#[tokio::test]
async fn connection_readiness_is_published_after_config_handshake() {
    let global = std::sync::Arc::new(Counter::default());
    let readiness = std::sync::Arc::new(AtomicBool::new(false));
    let path = unique_sock_path("connection-readiness");
    let server = RpcServer::bind_with_connection_readiness(
        &path,
        global,
        "ready-cfg".to_string(),
        readiness.clone(),
    )
    .unwrap();
    let server_path = server.path().to_path_buf();
    let handle = tokio::spawn(async move { server.serve().await });

    let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(13))
        .await
        .expect("connect");
    assert_eq!(client.config(), "ready-cfg");
    assert!(readiness.load(Ordering::Acquire));

    handle.abort();
}

#[tokio::test]
async fn serve_one_then_client_disconnect_is_clean() {
    // `serve_one` serves a single connection until the client closes it, and
    // reports that clean close as `Ok(())`.
    let global = std::sync::Arc::new(Counter::default());
    let path = unique_sock_path("serveone");
    let server = RpcServer::bind(&path, global.clone(), "x".to_string()).unwrap();
    let server_path = server.path().to_path_buf();

    let handle = tokio::spawn(async move { server.serve_one().await });

    {
        let client = RpcClient::<Counter>::connect(&server_path, Tid::from_raw(3))
            .await
            .expect("connect");
        assert_eq!(client.send_rpc(4).await.running_total, 4);
        assert_eq!(client.send_rpc(6).await.running_total, 10);
        // Client dropped here -> connection closes -> serve_one returns Ok.
    }

    let served = handle.await.expect("server task joins");
    assert!(
        served.is_ok(),
        "clean client disconnect => Ok, got {served:?}"
    );
    assert_eq!(*global.total.lock().unwrap(), 10);
}

#[tokio::test]
async fn connect_to_missing_coordinator_errors() {
    // Connecting where no coordinator is listening is a transport error, not a
    // hang or panic.
    let path = unique_sock_path("missing");
    match RpcClient::<Counter>::connect(&path, Tid::from_raw(1)).await {
        Ok(_) => panic!("connect to nonexistent socket must fail"),
        Err(reverie_rpc_transport::RpcError::Io(_)) => {}
        Err(other) => panic!("expected an I/O error, got {other:?}"),
    }
}
#[test]
fn blocking_client_rpc_is_ready_on_its_first_poll() {
    let global = std::sync::Arc::new(Counter::default());
    let server_global = global.clone();
    let path = unique_sock_path("blocking");
    let server_path = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);

    let server_thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let server =
                    RpcServer::bind(&path, server_global, "blocking-cfg".to_string()).unwrap();
                ready_tx.send(()).unwrap();
                server.serve_one().await
            })
    });
    ready_rx.recv().unwrap();

    let client = BlockingRpcClient::<Counter>::connect(&server_path, Tid::from_raw(41)).unwrap();
    assert_eq!(client.config(), "blocking-cfg");

    {
        let mut future = pin!(client.send_rpc(9));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            Future::poll(future.as_mut(), &mut context),
            Poll::Ready(Reply {
                running_total: 9,
                from: 41,
            })
        );
    }
    drop(client);

    assert!(
        server_thread.join().unwrap().is_ok(),
        "server should treat a blocking client disconnect as clean"
    );
    assert_eq!(*global.total.lock().unwrap(), 9);
}

#[test]
fn per_thread_blocking_clients_do_not_serialize_delayed_rpcs() {
    let global = std::sync::Arc::new(Gate::default());
    let server_global = global.clone();
    let path = unique_sock_path("blocking-threads");
    let server_path = path.clone();
    let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);

    let server_thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let server =
                    RpcServer::bind(&path, server_global, "threaded-cfg".to_string()).unwrap();
                ready_tx.send(()).unwrap();
                tokio::try_join!(server.serve_one(), server.serve_one()).map(|_| ())
            })
    });
    ready_rx.recv().unwrap();

    let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(0);
    let wait_path = server_path.clone();
    let wait_thread = std::thread::spawn(move || {
        let client = BlockingRpcClient::<Gate>::connect(&wait_path, Tid::from_raw(101)).unwrap();
        assert_eq!(client.config(), "threaded-cfg");
        wait_tx
            .send(client.try_send_rpc(GateRequest::Wait))
            .unwrap();
    });

    let deadline = Instant::now() + Duration::from_secs(2);
    while !global.waiting.load(Ordering::Acquire) {
        assert!(
            Instant::now() < deadline,
            "first blocking RPC did not reach the coordinator"
        );
        std::thread::yield_now();
    }

    let release_client =
        BlockingRpcClient::<Gate>::connect(&server_path, Tid::from_raw(202)).unwrap();
    assert_eq!(release_client.config(), "threaded-cfg");
    assert_eq!(
        release_client.try_send_rpc(GateRequest::Release).unwrap(),
        202
    );
    drop(release_client);

    assert_eq!(
        wait_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("a second thread connection did not release the first RPC")
            .unwrap(),
        101
    );
    wait_thread.join().unwrap();
    assert!(server_thread.join().unwrap().is_ok());
}
