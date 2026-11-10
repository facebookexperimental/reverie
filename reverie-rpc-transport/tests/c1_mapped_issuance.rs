#![cfg(target_os = "linux")]

//! C1 PR1: server-issued mapped connection round-trip through
//! [`BlockingRpcClient`], plus backpressure over a tiny queue.

use std::io::Read;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::mapped::MappedStream;
use serde::Deserialize;
use serde::Serialize;

const LIMIT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize, Deserialize)]
enum Request {
    Echo(Vec<u8>),
}

#[derive(Default)]
struct Global;

#[async_trait]
impl GlobalTool for Global {
    type Request = Request;
    type Response = Vec<u8>;
    type Config = Vec<u8>;
    async fn receive_rpc(&self, _: Tid, request: Request) -> Vec<u8> {
        match request {
            Request::Echo(bytes) => bytes,
        }
    }
}

#[tokio::test]
async fn issued_mapped_pair_round_trips_through_blocking_client() {
    let dir = std::env::temp_dir().join(format!("c1-mapped-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("coord.sock");
    let server = RpcServer::bind(&path, Arc::new(Global), b"c1-config".to_vec()).unwrap();
    // SAFETY: test exclusively transfers the fd to the single importer below.
    let (guest_fd, handle) = unsafe {
        server.issue_mapped_connection(
            reverie_rpc_transport::transport_select::DEFAULT_MAPPED_CAPACITY,
        )
    }
    .unwrap();
    let echoed = tokio::task::spawn_blocking(move || {
        // SAFETY: sole importer of the issued setup descriptor.
        let stream = unsafe { MappedStream::from_owned_fd(guest_fd) }.unwrap();
        let client =
            BlockingRpcClient::<Global, _>::from_connected_stream(stream, Tid::from_raw(7))
                .unwrap();
        assert_eq!(client.config(), b"c1-config");
        client
            .try_send_rpc(Request::Echo(b"ping".to_vec()))
            .unwrap()
    });
    let echoed = tokio::time::timeout(LIMIT, echoed)
        .await
        .expect("mapped round-trip timed out")
        .unwrap();
    assert_eq!(echoed, b"ping");
    handle.abort();
    drop(server);
}

#[test]
fn mapped_backpressure_blocks_until_reader_drains() {
    // Tiny queue: a payload larger than capacity must not complete its
    // write until the peer reads (SPSC backpressure, mapped.rs contract).
    let (mut a, mut b) = MappedStream::pair(64).unwrap();
    let payload = vec![0x5au8; 4096];
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let writer = std::thread::spawn(move || {
        a.write_all(&payload).unwrap();
        a.flush().unwrap();
        done_tx.send(()).unwrap();
    });
    // 4096 bytes cannot fit a 64-byte queue: writer must still be blocked.
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "writer completed before any drain: no backpressure observed"
    );
    let mut got = vec![0u8; 4096];
    b.read_exact(&mut got).unwrap();
    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    writer.join().unwrap();
    assert_eq!(got, vec![0x5au8; 4096]);
}

#[test]
fn second_import_of_same_backing_is_refused() {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    // SAFETY: both descriptors below are consumed by exactly one import
    // attempt each; no writes go through either descriptor.
    let (_host, guest_fd) = unsafe { MappedStream::create(64) }.unwrap();
    let dup = unsafe { libc::fcntl(guest_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(dup >= 0);
    let dup_fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };
    let first = unsafe { MappedStream::from_owned_fd(guest_fd) };
    assert!(first.is_ok());
    let second = unsafe { MappedStream::from_owned_fd(dup_fd) };
    let err = second.err().expect("second import must refuse");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
}

#[tokio::test]
async fn issued_connection_sets_readiness_and_counts_until_close() {
    let dir = std::env::temp_dir().join(format!("c1-ready-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("coord.sock");
    let ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server = RpcServer::bind_with_connection_readiness(
        &path,
        Arc::new(Global),
        b"c1-config".to_vec(),
        ready.clone(),
    )
    .unwrap();
    let monitor = server.connection_monitor();
    assert_eq!(monitor.active_connections(), 0);
    // SAFETY: sole importer below; see issued-pair test.
    let (guest_fd, handle) = unsafe { server.issue_mapped_connection(4096) }.unwrap();
    // The issued task holds a connection guard for its whole life.
    assert_eq!(monitor.active_connections(), 1);
    assert!(!ready.load(std::sync::atomic::Ordering::Acquire));
    let echoed = tokio::task::spawn_blocking(move || {
        // SAFETY: sole importer of the issued descriptor.
        let stream = unsafe { MappedStream::from_owned_fd(guest_fd) }.unwrap();
        let client =
            BlockingRpcClient::<Global, _>::from_connected_stream(stream, Tid::from_raw(9))
                .unwrap();
        let out = client
            .try_send_rpc(Request::Echo(b"ready?".to_vec()))
            .unwrap();
        // Hold the connection open until the test releases it.
        std::thread::sleep(std::time::Duration::from_millis(400));
        out
    });
    // Readiness flips once the guest receives its config handshake.
    let deadline = std::time::Instant::now() + LIMIT;
    while !ready.load(std::sync::atomic::Ordering::Acquire) {
        assert!(std::time::Instant::now() < deadline, "readiness never set");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Still counted while the client is alive; idle must not complete early.
    assert_eq!(monitor.active_connections(), 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(150),
            monitor.wait_for_idle()
        )
        .await
        .is_err(),
        "wait_for_idle completed while a mapped client was still live"
    );
    let out = tokio::time::timeout(LIMIT, echoed).await.unwrap().unwrap();
    assert_eq!(out, b"ready?");
    // Client dropped at thread end: task ends, count drains to zero.
    let _ = tokio::time::timeout(LIMIT, handle).await;
    tokio::time::timeout(LIMIT, monitor.wait_for_idle())
        .await
        .unwrap();
    let monitor = server.connection_monitor();
    assert_eq!(monitor.active_connections(), 0);
}
