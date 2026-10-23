/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Connection admission: the server hands each accepted connection's
//! `SO_PEERPIDFD` to a [`ConnectionAdmission`] before the configuration
//! handshake, refuses connections it rejects, and requires an admitted
//! connection's first request to come from the admitted process.

use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::Admitted;
use reverie_rpc_transport::ConnectionAdmission;
use reverie_rpc_transport::RpcClient;
use reverie_rpc_transport::RpcServer;

#[derive(Default)]
struct Echo;

#[async_trait]
impl GlobalTool for Echo {
    type Request = u64;
    type Response = i32;
    type Config = String;

    async fn receive_rpc(&self, from: Tid, _request: u64) -> i32 {
        from.as_raw()
    }
}

fn unique_sock_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::path::Path::new("/tmp").join(format!(
        "reverie-rpc-admission-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// The pidfd's process id in this process's `/proc` namespace.
fn pidfd_pid(pidfd: &OwnedFd) -> i32 {
    let fdinfo =
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).unwrap();
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .expect("pidfd fdinfo has a Pid: line")
        .trim()
        .parse()
        .unwrap()
}

/// Admits every connection as this process and records the pid each pidfd
/// names.
#[derive(Default)]
struct RecordingAdmission {
    seen: Mutex<Vec<i32>>,
}

impl ConnectionAdmission for RecordingAdmission {
    fn admit(&self, peer: OwnedFd) -> std::io::Result<Admitted> {
        self.seen.lock().unwrap().push(pidfd_pid(&peer));
        Ok(Admitted {
            process_id: std::process::id() as i32,
        })
    }
}

struct Refusing;

impl ConnectionAdmission for Refusing {
    fn admit(&self, _peer: OwnedFd) -> std::io::Result<Admitted> {
        Err(std::io::Error::other("refused by the test"))
    }
}

fn serve_with(admission: Arc<dyn ConnectionAdmission>, tag: &str) -> std::path::PathBuf {
    let path = unique_sock_path(tag);
    let mut server = RpcServer::bind(&path, Arc::new(Echo), "cfg".to_string()).unwrap();
    server.set_connection_admission(admission);
    let server_path = server.path().to_path_buf();
    tokio::spawn(async move { server.serve().await });
    server_path
}

#[tokio::test]
async fn admitted_connection_gets_the_connecting_process_pidfd() {
    let admission = Arc::new(RecordingAdmission::default());
    let path = serve_with(admission.clone(), "admitted");
    let me = std::process::id() as i32;
    let client = RpcClient::<Echo>::connect(&path, Tid::from_raw(me))
        .await
        .expect("an admitted connection completes its handshake");
    assert_eq!(client.try_send_rpc(1).await.unwrap(), me);
    assert_eq!(client.try_send_rpc(2).await.unwrap(), me);
    assert_eq!(*admission.seen.lock().unwrap(), [me]);
}

#[tokio::test]
async fn refused_connection_is_closed_before_the_handshake() {
    let path = serve_with(Arc::new(Refusing), "refused");
    let result = RpcClient::<Echo>::connect(&path, Tid::from_raw(std::process::id() as i32)).await;
    assert!(
        result.is_err(),
        "a refused connection must not complete the handshake"
    );
}

#[tokio::test]
async fn first_request_from_another_process_closes_the_connection() {
    let admission = Arc::new(RecordingAdmission::default());
    let path = serve_with(admission, "mismatch");
    let me = std::process::id() as i32;
    let impostor = Tid::from_raw(me + 1);
    let client = RpcClient::<Echo>::connect(&path, impostor)
        .await
        .expect("the handshake precedes the sender check");
    assert!(
        client.try_send_rpc(1).await.is_err(),
        "a first request naming another process must be refused"
    );
}
