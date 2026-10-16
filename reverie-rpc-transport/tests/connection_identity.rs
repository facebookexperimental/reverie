/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Per-connection identity (`RpcServer::require_connection_identity`): every
//! request reaches the global tool with the identity of the process that
//! opened its connection, a request's sender is passed through unbound, and a
//! connection from a process reaped before it was accepted is refused
//! (https://github.com/rrnewton/hermit/issues/4362, part 2 step 1).
//!
//! Connections from another process come from this test binary, run again as
//! a child with `CHILD_MODE` set; see `child_entry`.

use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use reverie::ConnectionIdentity;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::RpcClient;
use reverie_rpc_transport::RpcServer;

/// What a child run of this binary does: `send <path>` sends one request
/// and prints the answer; `connect <path>` connects and exits at once.
const CHILD_MODE: &str = "REVERIE_CONNECTION_IDENTITY_CHILD";

/// Answers each request with its sender and the identity's tgid, and records
/// the tgid and the pid its pidfd names.
#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<(i32, i32)>>,
    plain: AtomicU32,
}

#[async_trait]
impl GlobalTool for Recorder {
    type Request = u64;
    type Response = (i32, i32);
    type Config = String;

    async fn receive_rpc(&self, from: Tid, _request: u64) -> (i32, i32) {
        self.plain.fetch_add(1, Ordering::Relaxed);
        (from.as_raw(), 0)
    }

    async fn receive_rpc_with_identity(
        &self,
        from: Tid,
        _request: u64,
        identity: ConnectionIdentity,
    ) -> (i32, i32) {
        let named = pidfd_pid(identity.pidfd().as_raw_fd());
        self.seen.lock().unwrap().push((identity.tgid(), named));
        (from.as_raw(), identity.tgid())
    }
}

/// A tool that does not override `receive_rpc_with_identity`.
#[derive(Default)]
struct Plain;

#[async_trait]
impl GlobalTool for Plain {
    type Request = u64;
    type Response = i32;
    type Config = String;

    async fn receive_rpc(&self, from: Tid, request: u64) -> i32 {
        from.as_raw() + request as i32
    }
}

fn unique_sock_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::path::Path::new("/tmp").join(format!(
        "reverie-rpc-identity-{tag}-{}-{n}.sock",
        std::process::id()
    ))
}

/// The pid a pidfd names, in this process's `/proc` namespace.
fn pidfd_pid(fd: i32) -> i32 {
    let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).unwrap();
    fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .expect("pidfd fdinfo has a Pid: line")
        .trim()
        .parse()
        .unwrap()
}

fn identified_server<G: GlobalTool<Config = String> + 'static>(
    global: Arc<G>,
    tag: &str,
) -> RpcServer<G> {
    let mut server = RpcServer::bind(unique_sock_path(tag), global, "cfg".to_string()).unwrap();
    server
        .require_connection_identity()
        .expect("this kernel supports per-connection identity (Linux 6.13 or later)");
    server
}

/// Runs this test binary again as a child in `mode` against `path`.
fn child(mode: &str, path: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE, format!("{mode} {}", path.display()));
    command
}

/// The child half of the tests below; does nothing in a normal test run.
#[test]
fn child_entry() {
    let Ok(spec) = std::env::var(CHILD_MODE) else {
        return;
    };
    let (mode, path) = spec.split_once(' ').unwrap();
    match mode {
        "send" => {
            let client = BlockingRpcClient::<Recorder>::connect(path, Tid::from_raw(4242)).unwrap();
            let (from, tgid) = client.try_send_rpc(7).unwrap();
            println!("CHILD-ANSWER from={from} tgid={tgid}");
        }
        "connect" => {
            let _stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        }
        other => panic!("unknown child mode {other}"),
    }
}

#[tokio::test]
async fn each_request_carries_the_connecting_process_and_its_sender_unbound() {
    let global = Arc::new(Recorder::default());
    let server = identified_server(Arc::clone(&global), "same");
    let path = server.path().to_path_buf();
    tokio::spawn(server.serve());
    let me = std::process::id() as i32;
    // The sender is not bound to the connection: any `from` is passed through.
    let client = RpcClient::<Recorder>::connect(&path, Tid::from_raw(99_999))
        .await
        .unwrap();
    assert_eq!(client.try_send_rpc(1).await.unwrap(), (99_999, me));
    assert_eq!(client.try_send_rpc(2).await.unwrap(), (99_999, me));
    assert_eq!(*global.seen.lock().unwrap(), [(me, me), (me, me)]);
    assert_eq!(global.plain.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_connection_from_a_non_leader_thread_names_its_whole_process() {
    let global = Arc::new(Recorder::default());
    let server = identified_server(Arc::clone(&global), "thread");
    let path = server.path().to_path_buf();
    tokio::spawn(server.serve());
    let me = std::process::id() as i32;
    let answer = tokio::task::spawn_blocking(move || {
        std::thread::spawn(move || {
            let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
            assert_ne!(
                tid,
                std::process::id() as i32,
                "must run on a non-leader thread"
            );
            let client = BlockingRpcClient::<Recorder>::connect(&path, Tid::from_raw(tid)).unwrap();
            (tid, client.try_send_rpc(3).unwrap())
        })
        .join()
        .unwrap()
    })
    .await
    .unwrap();
    let (tid, (from, tgid)) = answer;
    assert_eq!((from, tgid), (tid, me));
    assert_eq!(*global.seen.lock().unwrap(), [(me, me)]);
}

#[tokio::test]
async fn a_connection_from_another_process_names_that_process() {
    let global = Arc::new(Recorder::default());
    let server = identified_server(Arc::clone(&global), "child");
    let path = server.path().to_path_buf();
    tokio::spawn(server.serve());
    let output = tokio::task::spawn_blocking(move || {
        let child = child("send", &path)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        (pid, child.wait_with_output().unwrap())
    })
    .await
    .unwrap();
    let (pid, output) = output;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "child failed: {output:?}");
    assert!(
        stdout.contains(&format!("CHILD-ANSWER from=4242 tgid={pid}")),
        "the child must see its own process as the connection's: {stdout}"
    );
    assert_eq!(*global.seen.lock().unwrap(), [(pid, pid)]);
}

#[tokio::test]
async fn a_connection_whose_process_was_reaped_before_accept_is_refused() {
    let global = Arc::new(Recorder::default());
    let server = identified_server(Arc::clone(&global), "reaped");
    let path = server.path().to_path_buf();
    // The child connects and exits; it is reaped here before the server
    // accepts its queued connection.
    let status = tokio::task::spawn_blocking(move || child("connect", &path).status().unwrap())
        .await
        .unwrap();
    assert!(status.success());
    let error = server
        .serve_one()
        .await
        .expect_err("a connection from a reaped process must be refused");
    assert!(
        error.to_string().contains("reaped before it was accepted"),
        "the refusal must name its reason: {error}"
    );
    assert!(global.seen.lock().unwrap().is_empty());
    assert_eq!(global.plain.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_tool_without_the_identity_method_is_still_served() {
    let server = identified_server(Arc::new(Plain), "plain");
    let path = server.path().to_path_buf();
    tokio::spawn(server.serve());
    let client = RpcClient::<Plain>::connect(&path, Tid::from_raw(40))
        .await
        .unwrap();
    assert_eq!(client.try_send_rpc(2).await.unwrap(), 42);
}

#[test]
fn identity_cannot_be_combined_with_connection_admission() {
    struct Admit;
    impl reverie_rpc_transport::ConnectionAdmission for Admit {
        fn admit(
            &self,
            _peer: std::os::fd::OwnedFd,
        ) -> std::io::Result<reverie_rpc_transport::Admitted> {
            Ok(reverie_rpc_transport::Admitted { process_id: 1 })
        }
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let mut server = RpcServer::bind(
        unique_sock_path("combined"),
        Arc::new(Plain),
        "cfg".to_string(),
    )
    .unwrap();
    server.set_connection_admission(Arc::new(Admit));
    let error = server
        .require_connection_identity()
        .expect_err("identity and admission are exclusive");
    assert!(error.to_string().contains("cannot be combined"), "{error}");
}
