/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real socket controls for the explicit transport exchange. The authorizer
//! below is test-only; transport ships no launcher authorization policy.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::Admitted;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::ConnectionAdmission;
use reverie_rpc_transport::ConnectionFailure;
use reverie_rpc_transport::RpcClient;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::RpcIssueMonitor;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::codec::encode;
use reverie_rpc_transport::codec::read_message;
use reverie_rpc_transport::codec::write_message;
use reverie_rpc_transport::initial_image::ACK_MAGIC;
use reverie_rpc_transport::initial_image::ConfigDigest;
use reverie_rpc_transport::initial_image::InitialImageAdmission;
use reverie_rpc_transport::initial_image::MAX_FRAME_LEN;
use reverie_rpc_transport::initial_image::MAX_REDEMPTION_LEN;
use reverie_rpc_transport::initial_image::VERSION;
use reverie_rpc_transport::initial_image::config_digest;
use reverie_rpc_transport::initial_image::encode_redemption;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

const CHALLENGE: [u8; 16] = [0x5a; 16];
const CONFIG: &str = "immutable initial config";
const WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Echo(AtomicUsize);
#[async_trait]
impl GlobalTool for Echo {
    type Config = String;
    type Request = u64;
    type Response = u64;
    async fn receive_rpc(&self, _from: Tid, request: u64) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst);
        request + 1
    }
}

fn path(tag: &str) -> std::path::PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    std::path::PathBuf::from(format!(
        "/tmp/rv-initial-{}-{}-{tag}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ))
}

fn peer_pid(peer: &OwnedFd) -> io::Result<i32> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd()))?;
    info.lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .ok_or_else(|| io::Error::other("pidfd has no process"))?
        .trim()
        .parse()
        .map_err(io::Error::other)
}

fn birth(pid: i32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // comm may contain spaces or parentheses. Field 22 follows the final ')'.
    stat.rsplit_once(')')
        .ok_or_else(|| io::Error::other("no stat comm"))?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("no process birth"))?
        .parse()
        .map_err(io::Error::other)
}

fn is_live(peer: &OwnedFd) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: peer.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc == 0)
    }
}

struct Watched {
    peer: OwnedFd,
    pid: i32,
    birth: u64,
}

/// Known launch birth + held watcher pidfd + one-use challenge. All authority
/// lives in this coordinator test object, not the incoming challenge alone.
struct TestAuthorization {
    expected_birth: u64,
    watched: Mutex<Vec<Watched>>,
    consumed: AtomicBool,
    refuse_watch: AtomicBool,
    calls: AtomicUsize,
}
impl TestAuthorization {
    fn new(stale_birth: bool) -> Self {
        let current = birth(std::process::id() as i32).unwrap();
        Self {
            expected_birth: current + u64::from(stale_birth),
            watched: Mutex::new(Vec::new()),
            consumed: AtomicBool::new(false),
            refuse_watch: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        }
    }
}
impl ConnectionAdmission for TestAuthorization {
    fn admit(&self, peer: OwnedFd) -> io::Result<Admitted> {
        if self.refuse_watch.load(Ordering::Acquire) {
            return Err(io::Error::other("watcher refused this process"));
        }
        let pid = peer_pid(&peer)?;
        let birth = birth(pid)?;
        self.watched
            .lock()
            .unwrap()
            .push(Watched { peer, pid, birth });
        Ok(Admitted { process_id: pid })
    }
}
impl InitialImageAdmission for TestAuthorization {
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        redemption: &[u8],
        digest: ConfigDigest,
    ) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let pid = peer_pid(&peer)?;
        let actual_birth = birth(pid)?;
        let watched = self.watched.lock().unwrap();
        let watch = watched
            .iter()
            .find(|watch| watch.pid == pid && watch.birth == actual_birth)
            .ok_or_else(|| io::Error::other("redemption before watcher admission"))?;
        if admitted.process_id != pid
            || actual_birth != self.expected_birth
            || !is_live(&watch.peer)?
            || !is_live(&peer)?
        {
            return Err(io::Error::other("wrong or stale watched launch birth"));
        }
        if redemption != CHALLENGE || digest != config_digest(&encode(&CONFIG.to_string()).unwrap())
        {
            return Err(io::Error::other("wrong challenge or config"));
        }
        if self.consumed.swap(true, Ordering::SeqCst) {
            return Err(io::Error::other("launch authorization already consumed"));
        }
        Ok(())
    }
}

struct Running {
    path: std::path::PathBuf,
    task: tokio::task::JoinHandle<Result<(), RpcError>>,
    issues: RpcIssueMonitor,
    ready: Arc<AtomicBool>,
    global: Arc<Echo>,
}
impl Running {
    fn start(auth: Arc<TestAuthorization>, tag: &str) -> Self {
        let path = path(tag);
        let ready = Arc::new(AtomicBool::new(false));
        let global = Arc::new(Echo::default());
        let mut server = RpcServer::bind_with_connection_readiness(
            &path,
            global.clone(),
            CONFIG.to_string(),
            ready.clone(),
        )
        .unwrap();
        server.set_connection_admission(auth.clone());
        let issues = server.retain_connection_issues();
        server.set_initial_image_admission(auth).unwrap();
        let task = tokio::spawn(server.serve());
        Self {
            path,
            task,
            issues,
            ready,
            global,
        }
    }
    async fn stop(self) {
        self.issues.planned_shutdown();
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn frame(stream: &mut tokio::net::UnixStream) -> Result<Vec<u8>, RpcError> {
    tokio::time::timeout(WAIT, read_message(stream, MAX_FRAME_LEN))
        .await
        .unwrap()
}
fn expected() -> ConfigDigest {
    config_digest(&encode(&CONFIG.to_string()).unwrap())
}
fn ack(digest: ConfigDigest) -> Vec<u8> {
    let mut bytes = ACK_MAGIC.to_vec();
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&digest);
    bytes
}

#[tokio::test]
async fn watcher_then_redemption_then_ack_and_config_then_real_rpc_on_same_socket() {
    let auth = Arc::new(TestAuthorization::new(false));
    let running = Running::start(auth.clone(), "ordering");
    let mut stream = tokio::net::UnixStream::connect(&running.path)
        .await
        .unwrap();
    tokio::time::timeout(WAIT, async {
        while auth.watched.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), stream.read(&mut byte))
            .await
            .is_err(),
        "no ack/config may precede redemption"
    );
    assert!(!running.ready.load(Ordering::Acquire));
    write_message(&mut stream, &encode_redemption(&CHALLENGE).unwrap())
        .await
        .unwrap();
    assert_eq!(frame(&mut stream).await.unwrap(), ack(expected()));
    assert!(auth.consumed.load(Ordering::Acquire));
    assert_eq!(
        frame(&mut stream).await.unwrap(),
        encode(&CONFIG.to_string()).unwrap()
    );
    let request = reverie_rpc_transport::RequestEnvelope {
        from: Tid::from_raw(std::process::id() as i32),
        request: 41u64,
    };
    write_message(&mut stream, &encode(&request).unwrap())
        .await
        .unwrap();
    assert_eq!(
        reverie_rpc_transport::codec::decode::<u64>(&frame(&mut stream).await.unwrap()).unwrap(),
        42
    );
    assert_eq!(running.global.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        auth.watched.lock().unwrap().len(),
        1,
        "RPC must use the accepted connection"
    );
    assert_eq!(auth.calls.load(Ordering::SeqCst), 1);
    drop(stream);
    running.stop().await;
}

#[tokio::test]
async fn blocking_initial_client_continues_rpc_and_duplicate_after_disconnect_is_retained() {
    let auth = Arc::new(TestAuthorization::new(false));
    let running = Running::start(auth.clone(), "duplicate");
    let path = running.path.clone();
    tokio::task::spawn_blocking(move || {
        let client = BlockingRpcClient::<Echo>::connect_initial_image(
            path,
            Tid::from_raw(std::process::id() as i32),
            &CHALLENGE,
            expected(),
        )
        .unwrap();
        assert_eq!(client.config(), CONFIG);
        let client = client.into_client();
        assert_eq!(client.try_send_rpc(8).unwrap(), 9);
        assert_eq!(client.try_send_rpc(9).unwrap(), 10);
        drop(client);
    })
    .await
    .unwrap();
    let path = running.path.clone();
    assert!(
        tokio::task::spawn_blocking(move || BlockingRpcClient::<Echo>::connect_initial_image(
            path,
            Tid::from_raw(std::process::id() as i32),
            &CHALLENGE,
            expected(),
        )
        .is_err())
        .await
        .unwrap()
    );
    tokio::time::timeout(WAIT, running.issues.failed())
        .await
        .unwrap();
    assert_eq!(auth.calls.load(Ordering::SeqCst), 2);
    assert!(auth.consumed.load(Ordering::Acquire));
    assert_eq!(running.global.0.load(Ordering::SeqCst), 2);
    let issues = running.issues.snapshot();
    assert_eq!(issues.len(), 1);
    let ConnectionFailure::Transport(error) = &issues[0].failure else {
        panic!("{issues:?}")
    };
    assert!(error.to_string().contains("already consumed"));
    running.stop().await;
}

#[tokio::test]
async fn wrong_missing_oversize_version_trailing_and_stale_launch_refuse_before_config() {
    for case in [
        "wrong",
        "missing",
        "oversize-frame",
        "oversize-redemption",
        "magic",
        "version",
        "trailing",
        "stale",
    ] {
        let auth = Arc::new(TestAuthorization::new(case == "stale"));
        let running = Running::start(auth.clone(), case);
        let mut stream = tokio::net::UnixStream::connect(&running.path)
            .await
            .unwrap();
        match case {
            "missing" => stream.shutdown().await.unwrap(),
            "oversize-frame" => stream
                .write_all(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes())
                .await
                .unwrap(),
            _ => {
                let mut request = encode_redemption(&CHALLENGE).unwrap();
                match case {
                    "wrong" => request[10] ^= 1,
                    "oversize-redemption" => request.resize(10 + MAX_REDEMPTION_LEN + 1, 0),
                    "magic" => request[0] ^= 1,
                    "version" => request[9] = 2,
                    "trailing" => request.push(0),
                    "stale" => {}
                    _ => unreachable!(),
                }
                write_message(&mut stream, &request).await.unwrap();
            }
        }
        assert!(
            frame(&mut stream).await.is_err(),
            "{case} must deliver no ack/config"
        );
        tokio::time::timeout(WAIT, running.issues.failed())
            .await
            .unwrap();
        assert_eq!(running.issues.snapshot().len(), 1, "{case}");
        assert!(
            !running.ready.load(Ordering::Acquire),
            "{case} must not signal readiness"
        );
        assert!(
            !auth.consumed.load(Ordering::Acquire),
            "{case} must not consume another launch"
        );
        assert_eq!(running.global.0.load(Ordering::SeqCst), 0);
        drop(stream);
        running.stop().await;
    }
}

#[tokio::test]
async fn watcher_refusal_precedes_redemption_and_is_retained_without_readiness() {
    let auth = Arc::new(TestAuthorization::new(false));
    auth.refuse_watch.store(true, Ordering::Release);
    let running = Running::start(auth.clone(), "watcher-refusal");
    let mut stream = tokio::net::UnixStream::connect(&running.path)
        .await
        .unwrap();
    assert!(frame(&mut stream).await.is_err());
    tokio::time::timeout(WAIT, running.issues.failed())
        .await
        .unwrap();
    assert_eq!(auth.calls.load(Ordering::SeqCst), 0);
    assert!(auth.watched.lock().unwrap().is_empty());
    assert!(!running.ready.load(Ordering::Acquire));
    assert_eq!(running.issues.snapshot().len(), 1);
    drop(stream);
    running.stop().await;
}

#[tokio::test]
async fn first_sender_guard_still_refuses_after_initial_image_success() {
    let auth = Arc::new(TestAuthorization::new(false));
    let running = Running::start(auth, "sender");
    let path = running.path.clone();
    tokio::task::spawn_blocking(move || {
        let client = BlockingRpcClient::<Echo>::connect_initial_image(
            path,
            Tid::from_raw(std::process::id() as i32 + 1),
            &CHALLENGE,
            expected(),
        )
        .unwrap();
        assert!(client.into_client().try_send_rpc(1).is_err());
    })
    .await
    .unwrap();
    tokio::time::timeout(WAIT, running.issues.failed())
        .await
        .unwrap();
    assert_eq!(running.global.0.load(Ordering::SeqCst), 0);
    let issues = running.issues.snapshot();
    let ConnectionFailure::Transport(error) = &issues[0].failure else {
        panic!("{issues:?}")
    };
    assert!(error.to_string().contains("sent its first request as"));
    running.stop().await;
}

#[derive(Default, Clone, serde::Serialize)]
struct DecodeBomb;
static DECODES: AtomicUsize = AtomicUsize::new(0);
impl<'de> serde::Deserialize<'de> for DecodeBomb {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        DECODES.fetch_add(1, Ordering::SeqCst);
        Err(serde::de::Error::custom("decode was entered"))
    }
}
#[derive(Default)]
struct BombTool;
#[async_trait]
impl GlobalTool for BombTool {
    type Config = DecodeBomb;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Tid, _: ()) {}
}

#[tokio::test]
async fn acknowledgement_and_raw_config_digest_are_checked_before_guest_decode() {
    DECODES.store(0, Ordering::SeqCst);
    for case in [
        "digest",
        "magic",
        "version",
        "trailing",
        "oversize",
        "raw-config",
        "matching-raw",
    ] {
        let path = path(case);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let expected_digest = if case == "matching-raw" {
            config_digest(&[0xff])
        } else {
            [3; 32]
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                frame(&mut stream).await.unwrap(),
                encode_redemption(&CHALLENGE).unwrap()
            );
            let mut acknowledgement = ack(expected_digest);
            match case {
                "digest" => acknowledgement[10] ^= 1,
                "magic" => acknowledgement[0] ^= 1,
                "version" => acknowledgement[9] = 2,
                "trailing" => acknowledgement.push(0),
                "oversize" => acknowledgement.resize(MAX_FRAME_LEN + 1, 0),
                "raw-config" | "matching-raw" => {}
                _ => unreachable!(),
            }
            if case == "oversize" {
                stream
                    .write_all(&(acknowledgement.len() as u32).to_be_bytes())
                    .await
                    .unwrap();
            } else {
                write_message(&mut stream, &acknowledgement).await.unwrap();
            }
            if case == "raw-config" || case == "matching-raw" {
                write_message(&mut stream, &[0xff]).await.unwrap();
            }
        });
        let client_path = path.clone();
        let error = tokio::task::spawn_blocking(move || {
            match BlockingRpcClient::<BombTool>::connect_initial_image(
                client_path,
                Tid::from_raw(std::process::id() as i32),
                &CHALLENGE,
                expected_digest,
            ) {
                Ok(_) => panic!("invalid {case} accepted"),
                Err(error) => error,
            }
        })
        .await
        .unwrap();
        if case == "matching-raw" {
            assert!(matches!(error, RpcError::Decode(_)), "{case}: {error}");
        } else if case == "oversize" {
            assert!(
                matches!(error, RpcError::FrameTooLarge { .. }),
                "{case}: {error}"
            );
        } else {
            assert!(matches!(error, RpcError::Io(_)), "{case}: {error}");
        }
        assert_eq!(
            DECODES.load(Ordering::SeqCst),
            usize::from(case == "matching-raw"),
            "{case}"
        );
        task.await.unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[tokio::test]
async fn initial_mode_requires_watcher_and_retained_issue_monitor_and_ordinary_is_unchanged() {
    let path = path("requirements");
    let mut server = RpcServer::bind(&path, Arc::new(Echo::default()), CONFIG.to_string()).unwrap();
    let auth = Arc::new(TestAuthorization::new(false));
    assert!(server.set_initial_image_admission(auth.clone()).is_err());
    server.set_connection_admission(auth.clone());
    assert!(server.set_initial_image_admission(auth).is_err());
    let monitor_only_path = self::path("monitor-only");
    let mut monitor_only = RpcServer::bind(
        &monitor_only_path,
        Arc::new(Echo::default()),
        CONFIG.to_string(),
    )
    .unwrap();
    monitor_only.retain_connection_issues();
    assert!(
        monitor_only
            .set_initial_image_admission(Arc::new(TestAuthorization::new(false)))
            .is_err()
    );
    drop(monitor_only);
    let task = tokio::spawn(server.serve());
    let client = RpcClient::<Echo>::connect(&path, Tid::from_raw(std::process::id() as i32))
        .await
        .unwrap();
    assert_eq!(reverie::GlobalRPC::config(&client), CONFIG);
    assert_eq!(client.try_send_rpc(22).await.unwrap(), 23);
    drop(client);
    task.abort();
    let _ = task.await;
}
