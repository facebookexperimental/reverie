/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

//! Real socket tests with test-only one-use admission. No native exec is claimed.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::Admitted;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::ConnectionAdmission;
use reverie_rpc_transport::RequestEnvelope;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::codec::decode;
use reverie_rpc_transport::codec::encode;
use reverie_rpc_transport::codec::read_message;
use reverie_rpc_transport::codec::write_message;
use reverie_rpc_transport::initial_image::ConfigDigest;
use reverie_rpc_transport::initial_image::InitialImageAdmission;
use reverie_rpc_transport::initial_image::config_digest;
use reverie_rpc_transport::successor::ExpectedSuccessor;
use reverie_rpc_transport::successor::MAX_CONTROL_LEN;
use reverie_rpc_transport::successor::NativeImageConnection;
use reverie_rpc_transport::successor::SuccessorAdmission;
use reverie_rpc_transport::successor::SuccessorRequest;
use reverie_rpc_transport::successor::encode_redemption;

const CONFIG: &str = "unchanged native configuration";
const TICKET: &[u8] = b"one-use-issued-transition";
const WAIT: Duration = Duration::from_secs(3);

#[derive(Default)]
struct Echo(AtomicUsize);

#[async_trait::async_trait]
impl GlobalTool for Echo {
    type Config = String;
    type Request = u64;
    type Response = u64;
    async fn receive_rpc(&self, _from: Tid, value: u64) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst);
        value + 1
    }
}

struct SocketPath(PathBuf);
impl SocketPath {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self(std::env::temp_dir().join(format!(
            "rv-successor-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
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

struct Watch;
impl ConnectionAdmission for Watch {
    fn admit(&self, peer: OwnedFd) -> io::Result<Admitted> {
        Ok(Admitted {
            process_id: peer_pid(&peer)?,
        })
    }
}

// Socket-transport lifecycle model only. These records are not physical
// watches, genuine guest Complete acknowledgements or native exec evidence.
#[derive(Clone, Copy, PartialEq)]
enum FixtureIssueStage {
    Prepared,
    Issued,
    Cancelled,
}

struct FixtureIssue {
    nonce: &'static [u8],
    parent_epoch: u64,
    image_epoch: u64,
    stage: FixtureIssueStage,
}

struct FixtureCompleteAck {
    nonce: &'static [u8],
    image_epoch: u64,
    expected: ExpectedSuccessor,
}

struct FixtureLifecycle {
    issues: Vec<FixtureIssue>,
    complete_ack: Option<FixtureCompleteAck>,
    closed_epochs: Vec<u64>,
}

struct Admission {
    expected: ExpectedSuccessor,
    bytes: Vec<u8>,
    initial_used: AtomicBool,
    issued: AtomicBool,
    consumed: AtomicBool,
    corrupt_state: bool,
    lifecycle: Mutex<FixtureLifecycle>,
}

impl Admission {
    fn new(corrupt_state: bool) -> Self {
        let bytes = encode(&(4_713_u64, vec![0x63_u8; 32])).unwrap();
        Self {
            expected: ExpectedSuccessor {
                config: config_digest(&encode(&CONFIG.to_owned()).unwrap()),
                state: config_digest(&bytes),
            },
            bytes,
            initial_used: AtomicBool::new(false),
            issued: AtomicBool::new(true),
            consumed: AtomicBool::new(false),
            corrupt_state,
            lifecycle: Mutex::new(FixtureLifecycle {
                // The existing issued flag models this exact one-use nonce
                // from the initial epoch to the successor epoch.
                issues: vec![FixtureIssue {
                    nonce: TICKET,
                    parent_epoch: 0,
                    image_epoch: 1,
                    stage: FixtureIssueStage::Issued,
                }],
                complete_ack: None,
                closed_epochs: Vec::new(),
            }),
        }
    }

    fn record_complete_ack_for_test(
        &self,
        nonce: &'static [u8],
        expected: ExpectedSuccessor,
    ) -> io::Result<()> {
        let mut history = self.lifecycle.lock().unwrap();
        if nonce != TICKET
            || expected != self.expected
            || !self.consumed.load(Ordering::SeqCst)
            || history.complete_ack.is_some()
        {
            return Err(io::Error::other("fixture Complete ACK binding refused"));
        }
        history.complete_ack = Some(FixtureCompleteAck {
            nonce,
            image_epoch: 1,
            expected,
        });
        Ok(())
    }

    fn prepare_later_issue_for_test(&self, nonce: &'static [u8]) -> io::Result<()> {
        let mut history = self.lifecycle.lock().unwrap();
        let completed = history
            .complete_ack
            .as_ref()
            .ok_or_else(|| io::Error::other("fixture later Issue precedes Complete ACK"))?;
        if completed.nonce != TICKET
            || completed.image_epoch != 1
            || completed.expected != self.expected
            || nonce.is_empty()
            || history.issues.iter().any(|issue| issue.nonce == nonce)
        {
            return Err(io::Error::other("fixture later Issue binding refused"));
        }
        let parent_epoch = completed.image_epoch;
        history.issues.push(FixtureIssue {
            nonce,
            parent_epoch,
            image_epoch: 2,
            stage: FixtureIssueStage::Prepared,
        });
        Ok(())
    }

    fn owner(&self, peer: &OwnedFd, admitted: Admitted) -> io::Result<()> {
        if peer_pid(peer)? != std::process::id() as i32
            || admitted.process_id != std::process::id() as i32
        {
            return Err(io::Error::other("wrong watched process"));
        }
        Ok(())
    }
}

impl InitialImageAdmission for Admission {
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        ticket: &[u8],
        digest: ConfigDigest,
    ) -> io::Result<()> {
        self.owner(&peer, admitted)?;
        if ticket != b"initial-only"
            || digest != self.expected.config
            || self.initial_used.swap(true, Ordering::SeqCst)
        {
            return Err(io::Error::other("initial test authorization refused"));
        }
        Ok(())
    }
}

impl SuccessorAdmission for Admission {
    fn redeem(
        &self,
        peer: OwnedFd,
        admitted: Admitted,
        request: SuccessorRequest<'_>,
    ) -> io::Result<Vec<u8>> {
        self.owner(&peer, admitted)?;
        if !self.issued.load(Ordering::SeqCst)
            || request.ticket != TICKET
            || request.expected != self.expected
            || self.consumed.swap(true, Ordering::SeqCst)
        {
            return Err(io::Error::other("successor test authorization refused"));
        }
        let mut bytes = self.bytes.clone();
        if self.corrupt_state {
            bytes[0] ^= 1;
        }
        Ok(bytes)
    }

    fn connection_closed(
        &self,
        admitted: Admitted,
        image: &NativeImageConnection,
    ) -> io::Result<()> {
        if admitted.process_id != std::process::id() as i32 {
            return Err(io::Error::other("fixture EOF watched process differs"));
        }
        let mut history = self.lifecycle.lock().unwrap();
        let epoch = match image {
            NativeImageConnection::Initial if self.initial_used.load(Ordering::SeqCst) => 0,
            NativeImageConnection::Successor { ticket }
                if ticket.as_slice() == TICKET && self.consumed.load(Ordering::SeqCst) =>
            {
                history
                    .issues
                    .iter()
                    .find(|issue| {
                        issue.nonce == ticket.as_slice() && issue.stage == FixtureIssueStage::Issued
                    })
                    .ok_or_else(|| io::Error::other("fixture EOF image was not issued"))?
                    .image_epoch
            }
            _ => return Err(io::Error::other("fixture EOF image was not admitted")),
        };
        if !self.issued.load(Ordering::SeqCst)
            || history.closed_epochs.contains(&epoch)
            || !history.issues.iter().any(|issue| {
                issue.parent_epoch == epoch
                    && issue.image_epoch != epoch
                    && issue.stage == FixtureIssueStage::Issued
            })
        {
            return Err(io::Error::other("fixture live EOF has no later Issue"));
        }
        history.closed_epochs.push(epoch);
        Ok(())
    }
}

fn server(path: &SocketPath, global: Arc<Echo>, admission: Arc<Admission>) -> RpcServer<Echo> {
    let mut server = RpcServer::bind(&path.0, global, CONFIG.to_owned()).unwrap();
    server.set_connection_admission(Arc::new(Watch));
    server.retain_connection_issues();
    server
        .set_native_image_admission(admission.clone(), admission)
        .unwrap();
    server
}

#[tokio::test]
async fn explicit_initial_then_successor_use_the_same_endpoint_and_live_rpc() {
    let path = SocketPath::new();
    let global = Arc::new(Echo::default());
    let admission = Arc::new(Admission::new(false));
    let server = server(&path, global.clone(), admission.clone());
    let serve = tokio::spawn(async move {
        server.serve_one().await?;
        server.serve_one().await
    });
    let client_path = path.0.clone();
    let expected = admission.expected;
    let state = admission.bytes.clone();
    let client_admission = admission.clone();
    let client = tokio::task::spawn_blocking(move || {
        let tid = Tid::from_raw(std::process::id() as i32);
        let initial = BlockingRpcClient::<Echo>::connect_initial_image(
            &client_path,
            tid,
            b"initial-only",
            expected.config,
        )
        .unwrap();
        assert_eq!(initial.config(), CONFIG);
        let initial = initial.into_client();
        assert_eq!(initial.try_send_rpc(8).unwrap(), 9);
        drop(initial);
        let successor = BlockingRpcClient::<Echo>::connect_successor(
            &client_path,
            tid,
            SuccessorRequest {
                ticket: TICKET,
                expected,
            },
        )
        .unwrap();
        assert_eq!(successor.config(), CONFIG);
        assert_eq!(successor.state().bytes(), state);
        let before = successor.as_raw_fd();
        let (client, restored) = successor.into_parts();
        assert_eq!(client.as_raw_fd(), before);
        assert_eq!(restored.expected(), expected);
        assert_eq!(client.try_send_rpc(23).unwrap(), 24);

        // The real socket/ACK/Config/state/RPC path above remains the positive.
        // Direct hook calls below are negative model controls, not native proof.
        let admitted = Admitted {
            process_id: std::process::id() as i32,
        };
        let image = NativeImageConnection::Successor {
            ticket: TICKET.to_vec(),
        };
        assert!(
            client_admission
                .connection_closed(admitted, &image)
                .is_err()
        );
        assert!(
            client_admission
                .prepare_later_issue_for_test(b"later-one-use-transition")
                .is_err()
        );
        assert!(
            client_admission
                .record_complete_ack_for_test(b"unknown-image", expected)
                .is_err()
        );
        let mut wrong_expected = expected;
        wrong_expected.state[0] ^= 1;
        assert!(
            client_admission
                .record_complete_ack_for_test(TICKET, wrong_expected)
                .is_err()
        );
        client_admission
            .record_complete_ack_for_test(TICKET, expected)
            .unwrap();
        // Its own Complete ACK does not grant a live incarnation's EOF.
        assert!(
            client_admission
                .connection_closed(admitted, &image)
                .is_err()
        );
        client_admission
            .prepare_later_issue_for_test(b"later-one-use-transition")
            .unwrap();
        for (parent, stage) in [
            (1, FixtureIssueStage::Prepared),
            (1, FixtureIssueStage::Cancelled),
            (0, FixtureIssueStage::Issued),
        ] {
            {
                let mut history = client_admission.lifecycle.lock().unwrap();
                let later = history.issues.last_mut().unwrap();
                later.parent_epoch = parent;
                later.stage = stage;
            }
            assert!(
                client_admission
                    .connection_closed(admitted, &image)
                    .is_err()
            );
        }
        {
            let mut history = client_admission.lifecycle.lock().unwrap();
            let later = history.issues.last_mut().unwrap();
            later.parent_epoch = 1;
            later.stage = FixtureIssueStage::Issued;
        }
        assert!(
            client_admission
                .connection_closed(
                    Admitted {
                        process_id: admitted.process_id + 1,
                    },
                    &image,
                )
                .is_err()
        );
        assert!(
            client_admission
                .connection_closed(
                    admitted,
                    &NativeImageConnection::Successor {
                        ticket: b"unknown-image".to_vec(),
                    },
                )
                .is_err()
        );
        // This separate, later Issue names epoch 1 as predecessor. Dropping
        // the actual client now makes the real server observe its allowed EOF.
    });
    tokio::time::timeout(WAIT, client).await.unwrap().unwrap();
    tokio::time::timeout(WAIT, serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(admission.initial_used.load(Ordering::SeqCst));
    assert!(admission.consumed.load(Ordering::SeqCst));
    assert_eq!(global.0.load(Ordering::SeqCst), 2);
    let history = admission.lifecycle.lock().unwrap();
    assert_eq!(history.closed_epochs, [0, 1]);
    let completed = history.complete_ack.as_ref().unwrap();
    assert_eq!(completed.nonce, TICKET);
    assert_eq!(completed.image_epoch, 1);
    assert_eq!(completed.expected, expected);
}

#[tokio::test]
async fn malformed_and_mismatched_requests_never_release_state_or_call_the_tool() {
    let mut cases = Vec::new();
    let correct = Admission::new(false).expected;
    let mut config = correct;
    config.config[0] ^= 1;
    let mut state = correct;
    state.state[0] ^= 1;
    for (ticket, expected) in [
        (TICKET, config),
        (TICKET, state),
        (b"wrong".as_slice(), correct),
    ] {
        cases.push(encode_redemption(SuccessorRequest { ticket, expected }).unwrap());
    }
    let valid = encode_redemption(SuccessorRequest {
        ticket: TICKET,
        expected: correct,
    })
    .unwrap();
    let mut trailing = valid.clone();
    trailing.push(0);
    cases.push(trailing);
    let mut version = valid.clone();
    version[9] ^= 1;
    cases.push(version);
    let mut magic = valid;
    magic[0] ^= 1;
    cases.push(magic);
    cases.push(vec![0; MAX_CONTROL_LEN + 1]);
    for bytes in cases {
        let path = SocketPath::new();
        let global = Arc::new(Echo::default());
        let admission = Arc::new(Admission::new(false));
        let mut server = server(&path, global.clone(), admission.clone());
        let issues = server.retain_connection_issues();
        let serve = tokio::spawn(async move { server.serve_one().await });
        let mut client = tokio::net::UnixStream::connect(&path.0).await.unwrap();
        write_message(&mut client, &bytes).await.unwrap();
        assert!(
            tokio::time::timeout(WAIT, read_message(&mut client, MAX_CONTROL_LEN))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(WAIT, serve)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(!admission.consumed.load(Ordering::SeqCst));
        assert_eq!(global.0.load(Ordering::SeqCst), 0);
        assert!(!issues.snapshot().is_empty());
    }
}

#[tokio::test]
async fn redemption_consumption_survives_a_bad_payload_and_refuses_replay() {
    let path = SocketPath::new();
    let global = Arc::new(Echo::default());
    let admission = Arc::new(Admission::new(true));
    let server = server(&path, global.clone(), admission.clone());
    let serve = tokio::spawn(async move {
        assert!(server.serve_one().await.is_err());
        assert!(server.serve_one().await.is_err());
    });
    for _ in 0..2 {
        let mut client = tokio::net::UnixStream::connect(&path.0).await.unwrap();
        let bytes = encode_redemption(SuccessorRequest {
            ticket: TICKET,
            expected: admission.expected,
        })
        .unwrap();
        write_message(&mut client, &bytes).await.unwrap();
        assert!(
            tokio::time::timeout(WAIT, read_message(&mut client, MAX_CONTROL_LEN))
                .await
                .unwrap()
                .is_err()
        );
        assert!(admission.consumed.load(Ordering::SeqCst));
    }
    tokio::time::timeout(WAIT, serve).await.unwrap().unwrap();
    assert_eq!(global.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_native_rpc_sender_is_bound_to_its_admitted_socket() {
    let path = SocketPath::new();
    let global = Arc::new(Echo::default());
    let admission = Arc::new(Admission::new(false));
    let server = server(&path, global.clone(), admission.clone());
    let serve = tokio::spawn(async move { server.serve_one().await });
    let mut client = tokio::net::UnixStream::connect(&path.0).await.unwrap();
    let request = encode_redemption(SuccessorRequest {
        ticket: TICKET,
        expected: admission.expected,
    })
    .unwrap();
    write_message(&mut client, &request).await.unwrap();
    for _ in 0..3 {
        tokio::time::timeout(WAIT, read_message(&mut client, 1024))
            .await
            .unwrap()
            .unwrap();
    }
    for delta in [0, 1] {
        let request = encode(&RequestEnvelope {
            from: Tid::from_raw(std::process::id() as i32 + delta),
            request: 31_u64,
        })
        .unwrap();
        write_message(&mut client, &request).await.unwrap();
        let response = tokio::time::timeout(WAIT, read_message(&mut client, 1024))
            .await
            .unwrap();
        if delta == 0 {
            assert_eq!(decode::<u64>(&response.unwrap()).unwrap(), 32);
        } else {
            assert!(response.is_err());
        }
    }
    let error = tokio::time::timeout(WAIT, serve)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("connection admitted for process")
    );
    assert_eq!(global.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn prepared_or_initial_only_connections_cannot_redeem_a_successor() {
    for initial_only in [false, true] {
        let path = SocketPath::new();
        let global = Arc::new(Echo::default());
        let admission = Arc::new(Admission::new(false));
        let mut server = server(&path, global.clone(), admission.clone());
        if initial_only {
            server
                .set_initial_image_admission(admission.clone())
                .unwrap();
        } else {
            admission.issued.store(false, Ordering::SeqCst);
        }
        let serve = tokio::spawn(async move { server.serve_one().await });
        let mut client = tokio::net::UnixStream::connect(&path.0).await.unwrap();
        let request = encode_redemption(SuccessorRequest {
            ticket: TICKET,
            expected: admission.expected,
        })
        .unwrap();
        write_message(&mut client, &request).await.unwrap();
        assert!(
            tokio::time::timeout(WAIT, read_message(&mut client, MAX_CONTROL_LEN))
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(WAIT, serve)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(!admission.initial_used.load(Ordering::SeqCst));
        assert!(!admission.consumed.load(Ordering::SeqCst));
        assert_eq!(global.0.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn both_watched_admission_and_issue_retention_are_required() {
    for watch in [false, true] {
        let path = SocketPath::new();
        let mut server =
            RpcServer::bind(&path.0, Arc::new(Echo::default()), CONFIG.to_owned()).unwrap();
        let admission = Arc::new(Admission::new(false));
        if watch {
            server.set_connection_admission(Arc::new(Watch));
        } else {
            server.retain_connection_issues();
        }
        assert!(
            server
                .set_native_image_admission(admission.clone(), admission)
                .is_err()
        );
    }
}

// These controls are additive: the original six socket test IDs and assertions
// above remain. Admissions here are test doubles, not a native Issued registry.
mod negative_controls {
    use std::io::Write;
    use std::net::Shutdown;
    use std::sync::Mutex;
    use std::sync::mpsc;

    use reverie_rpc_transport::ConnectionFailure;
    use reverie_rpc_transport::RpcError;
    use reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN;
    use reverie_rpc_transport::successor::ACK_MAGIC;
    use reverie_rpc_transport::successor::MAX_STATE_LEN;
    use reverie_rpc_transport::successor::VERSION;
    use serde::Deserialize;
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Closed,
        Io(io::ErrorKind),
        Oversize { len: usize, max: usize },
        Decode,
    }

    impl Failure {
        fn assert(self, error: &RpcError, name: &str) {
            match (self, error) {
                (Self::Closed, RpcError::Closed) | (Self::Decode, RpcError::Decode(_)) => {}
                (Self::Io(expected), RpcError::Io(actual)) => {
                    assert_eq!(actual.kind(), expected, "{name}: {error:?}");
                }
                (Self::Oversize { len, max }, RpcError::FrameTooLarge { len: n, max: m }) => {
                    assert_eq!((*n, *m), (len, max), "{name}");
                }
                _ => panic!("{name}: expected {self:?}, got {error:?}"),
            }
        }
    }

    fn frame(bytes: &[u8]) -> Vec<u8> {
        let mut wire = u32::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        wire.extend_from_slice(bytes);
        wire
    }

    fn acknowledgement(expected: ExpectedSuccessor) -> Vec<u8> {
        // Construct the peer response independently of the private ACK encoder.
        let mut bytes = ACK_MAGIC.to_vec();
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.extend_from_slice(&expected.config);
        bytes.extend_from_slice(&expected.state);
        bytes.extend_from_slice(&config_digest(TICKET));
        assert_eq!(bytes.len(), 106);
        bytes
    }

    fn ready_server(
        path: &SocketPath,
        global: Arc<Echo>,
        initial: Arc<Admission>,
        successor: Arc<dyn SuccessorAdmission>,
        ready: Arc<AtomicBool>,
    ) -> RpcServer<Echo> {
        let mut server =
            RpcServer::bind_with_connection_readiness(&path.0, global, CONFIG.to_owned(), ready)
                .unwrap();
        server.set_connection_admission(Arc::new(Watch));
        server.retain_connection_issues();
        server
            .set_native_image_admission(initial, successor)
            .unwrap();
        server
    }

    #[tokio::test]
    async fn empty_and_partial_redemption_eof_is_retained_before_readiness() {
        let request = frame(
            &encode_redemption(SuccessorRequest {
                ticket: TICKET,
                expected: Admission::new(false).expected,
            })
            .unwrap(),
        );
        let mut cases = vec![
            (
                "missing request",
                Vec::new(),
                Failure::Io(io::ErrorKind::InvalidData),
            ),
            (
                "empty request frame",
                frame(&[]),
                Failure::Io(io::ErrorKind::InvalidData),
            ),
        ];
        for length in [1, 2, 3, 4, request.len() - 1] {
            cases.push((
                "partial request",
                request[..length].to_vec(),
                Failure::Io(io::ErrorKind::UnexpectedEof),
            ));
        }
        for (name, wire, failure) in cases {
            let path = SocketPath::new();
            let global = Arc::new(Echo::default());
            let admission = Arc::new(Admission::new(false));
            let ready = Arc::new(AtomicBool::new(false));
            let mut server = ready_server(
                &path,
                global.clone(),
                admission.clone(),
                admission.clone(),
                ready.clone(),
            );
            let issues = server.retain_connection_issues();
            let connections = server.connection_monitor();
            let serve = tokio::spawn(async move { server.serve_one().await });
            let mut client = tokio::net::UnixStream::connect(&path.0).await.unwrap();
            client.write_all(&wire).await.unwrap();
            client.shutdown().await.unwrap();
            let response = tokio::time::timeout(WAIT, read_message(&mut client, MAX_CONTROL_LEN))
                .await
                .unwrap();
            assert!(
                matches!(response, Err(RpcError::Closed)),
                "{name}: {response:?}"
            );
            let result = tokio::time::timeout(WAIT, serve).await.unwrap().unwrap();
            assert!(
                result.is_err(),
                "{name}: an incomplete redemption was accepted"
            );
            let retained = issues.snapshot();
            assert_eq!(retained.len(), 1, "{name}");
            let ConnectionFailure::Transport(error) = &retained[0].failure else {
                panic!("{name}: the actual transport error was not retained");
            };
            failure.assert(error, name);
            if name == "missing request" {
                let RpcError::Io(error) = error.as_ref() else {
                    unreachable!()
                };
                assert_eq!(error.to_string(), "native image redemption is missing");
            }
            assert!(!admission.initial_used.load(Ordering::SeqCst), "{name}");
            assert!(!admission.consumed.load(Ordering::SeqCst), "{name}");
            assert_eq!(global.0.load(Ordering::SeqCst), 0, "{name}");
            assert!(!ready.load(Ordering::Acquire), "{name}");
            assert_eq!(connections.active_connections(), 0, "{name}");
        }
    }

    struct DeliveryBarrier {
        inner: Arc<Admission>,
        entered: mpsc::SyncSender<()>,
        release: Mutex<mpsc::Receiver<()>>,
        entries: AtomicUsize,
    }

    impl SuccessorAdmission for DeliveryBarrier {
        fn redeem(
            &self,
            peer: OwnedFd,
            admitted: Admitted,
            request: SuccessorRequest<'_>,
        ) -> io::Result<Vec<u8>> {
            let bytes = SuccessorAdmission::redeem(self.inner.as_ref(), peer, admitted, request)?;
            // This boundary is after genuine test-hook consumption and before
            // the server can write ACK, Config or state. No scheduling sleep.
            self.entries.fetch_add(1, Ordering::SeqCst);
            self.entered.send(()).map_err(io::Error::other)?;
            self.release
                .lock()
                .unwrap()
                .recv_timeout(WAIT)
                .map_err(io::Error::other)?;
            Ok(bytes)
        }
    }

    #[tokio::test]
    async fn consumed_ticket_survives_real_delivery_disconnect_and_refuses_replay() {
        let path = SocketPath::new();
        let global = Arc::new(Echo::default());
        let admission = Arc::new(Admission::new(false));
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let barrier = Arc::new(DeliveryBarrier {
            inner: admission.clone(),
            entered: entered_tx,
            release: Mutex::new(release_rx),
            entries: AtomicUsize::new(0),
        });
        let ready = Arc::new(AtomicBool::new(false));
        let mut server = ready_server(
            &path,
            global.clone(),
            admission.clone(),
            barrier.clone(),
            ready.clone(),
        );
        let issues = server.retain_connection_issues();
        let connections = server.connection_monitor();
        let server = Arc::new(server);
        let serving = server.clone();
        let serve = tokio::spawn(async move { serving.serve_one().await });
        let client_path = path.0.clone();
        let wire = frame(
            &encode_redemption(SuccessorRequest {
                ticket: TICKET,
                expected: admission.expected,
            })
            .unwrap(),
        );
        let first_wire = wire.clone();
        let observed = admission.clone();
        let disconnect = tokio::task::spawn_blocking(move || {
            let mut client = std::os::unix::net::UnixStream::connect(client_path).unwrap();
            client.write_all(&first_wire).unwrap();
            entered_rx.recv_timeout(WAIT).unwrap();
            assert!(observed.consumed.load(Ordering::SeqCst));
            client.shutdown(Shutdown::Both).unwrap();
            drop(client);
            release_tx.send(()).unwrap();
        });
        tokio::time::timeout(WAIT, disconnect)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(WAIT, serve)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let first = issues.snapshot();
        assert_eq!(first.len(), 1);
        let ConnectionFailure::Transport(error) = &first[0].failure else {
            panic!("the post-consumption socket error was not retained");
        };
        Failure::Io(io::ErrorKind::BrokenPipe).assert(error, "delivery disconnect");
        let RpcError::Io(error) = error.as_ref() else {
            unreachable!()
        };
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
        assert!(!ready.load(Ordering::Acquire));
        assert_eq!(connections.active_connections(), 0);

        let serving = server.clone();
        let serve = tokio::spawn(async move { serving.serve_one().await });
        let mut replay = tokio::net::UnixStream::connect(&path.0).await.unwrap();
        replay.write_all(&wire).await.unwrap();
        let response = tokio::time::timeout(WAIT, read_message(&mut replay, MAX_CONTROL_LEN))
            .await
            .unwrap();
        assert!(matches!(response, Err(RpcError::Closed)), "{response:?}");
        assert!(
            tokio::time::timeout(WAIT, serve)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let retained = issues.snapshot();
        assert_eq!(retained.len(), 2);
        let ConnectionFailure::Transport(original) = &first[0].failure else {
            unreachable!()
        };
        let ConnectionFailure::Transport(still_retained) = &retained[0].failure else {
            unreachable!()
        };
        assert!(Arc::ptr_eq(original, still_retained));
        let ConnectionFailure::Transport(replay_error) = &retained[1].failure else {
            panic!("the replay refusal was not retained");
        };
        Failure::Io(io::ErrorKind::Other).assert(replay_error, "consumed replay");
        let RpcError::Io(replay_error) = replay_error.as_ref() else {
            unreachable!()
        };
        assert_eq!(
            replay_error.to_string(),
            "successor test authorization refused"
        );
        assert!(admission.consumed.load(Ordering::SeqCst));
        assert!(!admission.initial_used.load(Ordering::SeqCst));
        assert_eq!(barrier.entries.load(Ordering::SeqCst), 1);
        assert_eq!(global.0.load(Ordering::SeqCst), 0);
        assert!(!ready.load(Ordering::Acquire));
        assert_eq!(connections.active_connections(), 0);
    }

    static CONFIG_DECODES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug, Default, serde::Serialize)]
    struct DecodeCountedConfig(String);

    impl<'de> Deserialize<'de> for DecodeCountedConfig {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            CONFIG_DECODES.fetch_add(1, Ordering::SeqCst);
            String::deserialize(deserializer).map(Self)
        }
    }

    #[derive(Default)]
    struct DecodeProbe;

    #[async_trait::async_trait]
    impl GlobalTool for DecodeProbe {
        type Config = DecodeCountedConfig;
        type Request = u64;
        type Response = u64;

        async fn receive_rpc(&self, _from: Tid, _value: u64) -> u64 {
            panic!("a fake response peer must never invoke the tool")
        }
    }

    struct ReplyCase {
        name: String,
        expected: ExpectedSuccessor,
        wire: Vec<u8>,
        failure: Option<Failure>,
        decodes: usize,
    }

    fn refused_reply(
        name: impl Into<String>,
        expected: ExpectedSuccessor,
        wire: Vec<u8>,
        failure: Failure,
    ) -> ReplyCase {
        ReplyCase {
            name: name.into(),
            expected,
            wire,
            failure: Some(failure),
            decodes: 0,
        }
    }

    #[tokio::test]
    async fn fake_peer_refusals_verify_both_raw_hashes_before_any_config_decode() {
        // All uses of DecodeCountedConfig are serial in this one matrix, so
        // unrelated concurrently running socket tests cannot change the count.
        let config = encode(&DecodeCountedConfig(CONFIG.to_owned())).unwrap();
        assert_eq!(config, encode(&CONFIG.to_owned()).unwrap());
        let state = Admission::new(false).bytes;
        let expected = ExpectedSuccessor {
            config: config_digest(&config),
            state: config_digest(&state),
        };
        let ack = acknowledgement(expected);
        let ack_wire = frame(&ack);
        let config_wire = frame(&config);
        let state_wire = frame(&state);
        let through_config = [ack_wire.as_slice(), config_wire.as_slice()].concat();
        let mut cases = Vec::new();
        let mut initial_ack = reverie_rpc_transport::initial_image::ACK_MAGIC.to_vec();
        initial_ack.extend_from_slice(&reverie_rpc_transport::initial_image::VERSION.to_be_bytes());
        initial_ack.extend_from_slice(&expected.config);
        for (name, wire) in [
            (
                "ordinary Config-first response is not a fallback",
                config_wire.clone(),
            ),
            (
                "InitialImage response is not a fallback",
                frame(&initial_ack),
            ),
        ] {
            cases.push(refused_reply(
                name,
                expected,
                wire,
                Failure::Io(io::ErrorKind::InvalidData),
            ));
        }
        for (name, index) in [
            ("ACK magic", 0),
            ("ACK version", 9),
            ("ACK Config binding", 10),
            ("ACK state binding", 42),
            ("ACK ticket binding", 74),
        ] {
            let mut bad = ack.clone();
            bad[index] ^= 1;
            cases.push(refused_reply(
                name,
                expected,
                frame(&bad),
                Failure::Io(io::ErrorKind::InvalidData),
            ));
        }
        for (name, bytes) in [
            ("empty ACK", Vec::new()),
            ("short ACK", ack[..ack.len() - 1].to_vec()),
            ("trailing ACK", [ack.as_slice(), &[0]].concat()),
        ] {
            cases.push(refused_reply(
                name,
                expected,
                frame(&bytes),
                Failure::Io(io::ErrorKind::InvalidData),
            ));
        }
        for (name, complete, prefix) in [
            ("ACK", Vec::new(), ack_wire.clone()),
            ("Config", ack_wire.clone(), config_wire.clone()),
            ("state", through_config.clone(), state_wire.clone()),
        ] {
            for length in [0, 1, 2, 3, 4, prefix.len() - 1] {
                let wire = [complete.as_slice(), &prefix[..length]].concat();
                let failure = if length == 0 {
                    Failure::Closed
                } else {
                    Failure::Io(io::ErrorKind::UnexpectedEof)
                };
                cases.push(refused_reply(
                    format!("{name} EOF at {length}"),
                    expected,
                    wire,
                    failure,
                ));
            }
        }
        for (name, complete, max) in [
            ("oversize ACK", Vec::new(), MAX_CONTROL_LEN),
            ("oversize Config", ack_wire.clone(), DEFAULT_MAX_FRAME_LEN),
            ("oversize state", through_config.clone(), MAX_STATE_LEN),
        ] {
            let len = max + 1;
            let header = u32::try_from(len).unwrap().to_be_bytes();
            cases.push(refused_reply(
                name,
                expected,
                [complete.as_slice(), &header].concat(),
                Failure::Oversize { len, max },
            ));
        }
        let mut bad_config = config.clone();
        bad_config[0] ^= 1;
        for (name, bytes) in [
            ("raw Config hash mismatch", bad_config),
            ("empty Config hash mismatch", Vec::new()),
        ] {
            cases.push(refused_reply(
                name,
                expected,
                [ack_wire.clone(), frame(&bytes)].concat(),
                Failure::Io(io::ErrorKind::InvalidData),
            ));
        }
        let mut bad_state = state.clone();
        bad_state[0] ^= 1;
        for (name, bytes) in [
            ("raw state hash mismatch", bad_state.clone()),
            ("empty state", Vec::new()),
        ] {
            cases.push(refused_reply(
                name,
                expected,
                [through_config.clone(), frame(&bytes)].concat(),
                Failure::Io(io::ErrorKind::InvalidData),
            ));
        }
        // Independently expected hashes can match an invalid typed Config.
        // Only a matching state permits reaching its Deserialize implementation.
        let malformed_config = vec![2, 0, 0, 0, 0, 0, 0, 0, b'A'];
        let trailing_config = [config.as_slice(), &[0]].concat();
        for (name, bytes) in [
            ("hash-matched malformed Config", malformed_config.clone()),
            ("hash-matched trailing Config", trailing_config),
        ] {
            let independently_expected = ExpectedSuccessor {
                config: config_digest(&bytes),
                state: expected.state,
            };
            let mut case = refused_reply(
                name,
                independently_expected,
                [
                    frame(&acknowledgement(independently_expected)),
                    frame(&bytes),
                    state_wire.clone(),
                ]
                .concat(),
                Failure::Decode,
            );
            case.decodes = 1;
            cases.push(case);
        }
        let independently_expected = ExpectedSuccessor {
            config: config_digest(&malformed_config),
            state: expected.state,
        };
        cases.push(refused_reply(
            "malformed Config still waits for matching state hash",
            independently_expected,
            [
                frame(&acknowledgement(independently_expected)),
                frame(&malformed_config),
                frame(&bad_state),
            ]
            .concat(),
            Failure::Io(io::ErrorKind::InvalidData),
        ));
        cases.push(ReplyCase {
            name: "both raw hashes match and Config decodes once".to_owned(),
            expected,
            wire: [through_config, state_wire].concat(),
            failure: None,
            decodes: 1,
        });
        for case in cases {
            CONFIG_DECODES.store(0, Ordering::SeqCst);
            let path = SocketPath::new();
            let listener = tokio::net::UnixListener::bind(&path.0).unwrap();
            let client_path = path.0.clone();
            let expected = case.expected;
            let connect = tokio::task::spawn_blocking(move || {
                BlockingRpcClient::<DecodeProbe>::connect_successor(
                    client_path,
                    Tid::from_raw(std::process::id() as i32),
                    SuccessorRequest {
                        ticket: TICKET,
                        expected,
                    },
                )
            });
            let (mut peer, _) = tokio::time::timeout(WAIT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let request = tokio::time::timeout(WAIT, read_message(&mut peer, MAX_CONTROL_LEN))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                request,
                encode_redemption(SuccessorRequest {
                    ticket: TICKET,
                    expected
                })
                .unwrap(),
                "{}",
                case.name
            );
            peer.write_all(&case.wire).await.unwrap();
            // Signal EOF to the client while retaining the read side: any
            // fallback request or RPC bytes remain observable on this socket.
            peer.shutdown().await.unwrap();
            let result = tokio::time::timeout(WAIT, connect).await.unwrap().unwrap();
            if let Some(failure) = case.failure {
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("{}: invalid response was accepted", case.name),
                };
                failure.assert(&error, &case.name);
            } else {
                let successor = match result {
                    Ok(successor) => successor,
                    Err(error) => panic!("{}: qualifying response refused: {error:?}", case.name),
                };
                assert_eq!(successor.config().0, CONFIG);
                assert_eq!(successor.state().expected(), expected);
                assert_eq!(successor.state().ticket_digest(), config_digest(TICKET));
                assert_eq!(successor.state().bytes(), state);
                let descriptor = successor.as_raw_fd();
                let (client, retained) = successor.into_parts();
                assert_eq!(client.as_raw_fd(), descriptor);
                assert_eq!(retained.into_bytes(), state);
            }
            assert_eq!(
                CONFIG_DECODES.load(Ordering::SeqCst),
                case.decodes,
                "{}",
                case.name
            );
            let extra = tokio::time::timeout(WAIT, read_message(&mut peer, MAX_CONTROL_LEN))
                .await
                .unwrap();
            assert!(
                matches!(extra, Err(RpcError::Closed)),
                "{}: unexpected follow-up bytes: {extra:?}",
                case.name
            );
            // The completed connect task cannot hide a fallback reconnect in
            // the listener's backlog. This is an immediate kernel observation.
            let extra_connection = listener.into_std().unwrap().accept();
            assert!(
                matches!(extra_connection, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock),
                "{}: unexpected fallback connection: {extra_connection:?}",
                case.name
            );
        }
    }
}
