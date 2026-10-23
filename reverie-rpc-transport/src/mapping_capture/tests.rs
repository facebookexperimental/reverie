/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real connected-peer authorization before native Requested. These controls
//! do not establish native parking, exclusion, or whole-runtime containment.

use std::io::Write;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use async_trait::async_trait;
use reverie::GlobalTool;
use reverie::MappingCaptureIdentity;
use reverie::MappingCaptureRunOwner;
use reverie::MappingCaptureToken;
use reverie::Tid;
use serde::Deserialize;
use serde::Serialize;

use super::encode_request;
use super::is_ack;
use crate::RequestEnvelope;
use crate::RpcServer;
use crate::codec;

const CHILD: &str = "REVERIE_MAPPING_CAPTURE_TRANSPORT_TEST_CHILD";
const CONFIG: &str = "unchanged ordinary config";
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Echo(AtomicUsize);

#[async_trait]
impl GlobalTool for Echo {
    type Config = String;
    type Request = u64;
    type Response = (i32, u64);

    async fn receive_rpc(&self, from: Tid, value: u64) -> Self::Response {
        self.0.fetch_add(1, Ordering::SeqCst);
        (from.as_raw(), value)
    }
}

#[derive(Serialize, Deserialize)]
struct Packet {
    socket: String,
    // Each bool is the independently specified expected authorization result.
    requests: Vec<(Vec<u8>, bool)>,
}

async fn ordinary(stream: &mut tokio::net::UnixStream, value: u64) {
    let pid = i32::try_from(std::process::id()).unwrap();
    let request = codec::encode(&RequestEnvelope {
        from: Tid::from_raw(pid),
        request: value,
    })
    .unwrap();
    codec::write_message(stream, &request).await.unwrap();
    let response = codec::read_message(stream, codec::DEFAULT_MAX_FRAME_LEN)
        .await
        .unwrap();
    assert_eq!(
        codec::decode_exact::<(i32, u64)>(&response).unwrap(),
        (pid, value)
    );
}

fn client(name: &str) -> bool {
    let Some(selected) = std::env::var_os(CHILD) else {
        return false;
    };
    assert_eq!(selected, name);
    // The child waits here until its actual Child handle has been bound. This
    // carries test inputs, not an alternate authorization channel to the server.
    let bytes = crate::read_config_frame(&mut std::io::stdin()).unwrap();
    let packet: Option<Packet> = codec::decode_exact(&bytes).unwrap();
    if let Some(packet) = packet {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                tokio::time::timeout(DEADLINE, async {
                    let mut stream = tokio::net::UnixStream::connect(&packet.socket)
                        .await
                        .unwrap();
                    let config = codec::read_message(&mut stream, codec::DEFAULT_MAX_FRAME_LEN)
                        .await
                        .unwrap();
                    assert_eq!(config, codec::encode(CONFIG).unwrap());
                    assert_eq!(codec::decode_exact::<String>(&config).unwrap(), CONFIG);
                    ordinary(&mut stream, 41).await;
                    for (ordinal, (request, accepted)) in packet.requests.iter().enumerate() {
                        assert_eq!(request.len(), 80, "fixed control payload changed");
                        codec::write_message(&mut stream, request).await.unwrap();
                        let response =
                            codec::read_message(&mut stream, codec::DEFAULT_MAX_FRAME_LEN)
                                .await
                                .expect("a refusal must be an explicit framed response");
                        assert_eq!(response.len(), request.len(), "fixed reply payload changed");
                        assert_eq!(is_ack(request, &response), *accepted, "control {ordinal}");
                        if *accepted {
                            assert!(!is_ack(request, request), "request accepted as its own ACK");
                            assert!(!is_ack(request, &response[..response.len() - 1]));
                            // Bind the client-side decision to every byte of
                            // the real response, including all token fields.
                            for index in 0..response.len() {
                                let mut altered = response.clone();
                                altered[index] ^= 1;
                                assert!(!is_ack(request, &altered), "ACK ignored byte {index}");
                            }
                        }
                        // Refused controls also leave the original config and
                        // normal request framing usable on this same socket.
                        ordinary(&mut stream, 100 + ordinal as u64).await;
                    }
                })
                .await
                .expect("connected control exchange exceeded its test bound");
            });
    }
    println!("mapping-capture-transport-complete:{name}");
    true
}

/// Own and reap every real child even if a parent assertion panics.
struct TestChild(Option<Child>);

impl TestChild {
    fn spawn(name: &str) -> Self {
        let exact = format!("mapping_capture::tests::{name}");
        Self(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
                .env(CHILD, name)
                .env("RUST_BACKTRACE", "0")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }

    fn child(&self) -> &Child {
        self.0.as_ref().unwrap()
    }

    fn release(&mut self, packet: Option<Packet>) {
        let bytes = codec::encode(&packet).unwrap();
        let mut stdin = self.0.as_mut().unwrap().stdin.take().unwrap();
        stdin
            .write_all(&u32::try_from(bytes.len()).unwrap().to_be_bytes())
            .unwrap();
        stdin.write_all(&bytes).unwrap();
    }

    fn wait(&mut self, name: &str) -> Output {
        let deadline = Instant::now() + DEADLINE + Duration::from_secs(2);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "child did not finish its real exchange"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
        assert!(output.status.success(), "child control failed: {output:?}");
        let marker = format!("mapping-capture-transport-complete:{name}");
        assert!(
            output
                .stdout
                .windows(marker.len())
                .any(|bytes| bytes == marker.as_bytes()),
            "selected child did not execute its checks: {output:?}"
        );
        output
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    ExactOnce,
    NoServerOwner,
    UnboundRun,
    NoPending,
    AlteredPending,
    WrongPeer,
}

fn exercise(name: &str, case: Case) {
    if client(name) {
        return;
    }
    let mut root = TestChild::spawn(name);
    let (owner, run) = MappingCaptureRunOwner::new();
    if case != Case::UnboundRun {
        owner.bind_root(root.child()).unwrap();
    }
    let pid = i32::try_from(root.child().id()).unwrap();
    let identity = MappingCaptureIdentity {
        process: pid,
        thread: pid,
        address_space: [7, 11],
        private_owner: [13, 17, 19, 23],
        private_version: 29,
    };
    let token = if matches!(case, Case::UnboundRun | Case::NoPending) {
        if case == Case::UnboundRun {
            assert!(run.prepare(identity).is_none());
        }
        // A client can spell these fields, but cannot manufacture Pending or
        // the launcher's actual-root binding by sending them on a socket.
        MappingCaptureToken { nonce: 1, identity }
    } else {
        run.prepare(identity).unwrap()
    };
    assert!(
        !run.begin_observation(token),
        "Pending alone authorized a read"
    );
    let exact = encode_request(token).unwrap();
    let requests = match case {
        Case::ExactOnce => vec![(exact.clone(), true), (exact, false)],
        Case::AlteredPending => {
            let mut altered = Vec::new();
            let mut changed = token;
            changed.nonce += 1;
            altered.push(changed);
            let mut changed = token;
            changed.identity.process = i32::try_from(std::process::id()).unwrap();
            altered.push(changed);
            let mut changed = token;
            changed.identity.thread += 1;
            altered.push(changed);
            for index in 0..2 {
                let mut changed = token;
                changed.identity.address_space[index] += 1;
                altered.push(changed);
            }
            for index in 0..4 {
                let mut changed = token;
                changed.identity.private_owner[index] += 1;
                altered.push(changed);
            }
            let mut changed = token;
            changed.identity.private_version += 1;
            altered.push(changed);
            let mut requests: Vec<_> = altered
                .into_iter()
                .map(|token| (encode_request(token).unwrap(), false))
                .collect();
            // No forgery may consume the genuine Pending operation.
            requests.push((exact, true));
            requests
        }
        _ => vec![(exact, false)],
    };
    let expected_calls = requests.len() + 1;
    static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "reverie-mapping-control-{}-{}.sock",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    ));
    let global = Arc::new(Echo::default());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server = {
        let _entered = runtime.enter();
        let server = RpcServer::bind(&path, Arc::clone(&global), CONFIG.to_owned()).unwrap();
        if case == Case::NoServerOwner {
            server
        } else {
            server.mapping_capture(run.clone())
        }
    };
    let serving = std::thread::spawn(move || {
        runtime.block_on(async {
            tokio::time::timeout(DEADLINE, server.serve_one())
                .await
                .expect("server did not finish the real connection")
        })
    });
    let packet = Some(Packet {
        socket: path.to_str().unwrap().to_owned(),
        requests,
    });
    if case == Case::WrongPeer {
        // The actual bound root stays alive, blocked on its private stdin.
        // A different real connecting process presents its exact valid token.
        let mut peer = TestChild::spawn(name);
        assert_ne!(peer.child().id(), root.child().id());
        peer.release(packet);
        peer.wait(name);
        assert!(
            !run.begin_observation(token),
            "foreign peer authorized root Pending"
        );
        root.release(None);
    } else {
        root.release(packet);
    }
    root.wait(name);
    serving
        .join()
        .unwrap()
        .expect("ordinary framing or server handling failed");
    assert_eq!(
        global.0.load(Ordering::SeqCst),
        expected_calls,
        "control payload escaped into the ordinary GlobalTool request path"
    );
    if matches!(case, Case::ExactOnce | Case::AlteredPending) {
        // Accounting hooks are exercised only after the real connected peer
        // received ACK. This is not a native-observation/restoration claim.
        assert!(run.begin_observation(token));
        assert!(!run.begin_observation(token));
        assert!(run.complete(token, true));
        owner.finish().unwrap();
    } else {
        assert!(
            !run.begin_observation(token),
            "refused control authorized a read"
        );
    }
}

#[test]
fn exact_pending_is_authorized_once_and_preserves_ordinary_rpc() {
    exercise(
        "exact_pending_is_authorized_once_and_preserves_ordinary_rpc",
        Case::ExactOnce,
    );
}

#[test]
fn capture_without_server_owner_is_refused() {
    exercise(
        "capture_without_server_owner_is_refused",
        Case::NoServerOwner,
    );
}

#[test]
fn capture_with_unbound_run_is_refused() {
    exercise("capture_with_unbound_run_is_refused", Case::UnboundRun);
}

#[test]
fn capture_without_pending_is_refused() {
    exercise("capture_without_pending_is_refused", Case::NoPending);
}

#[test]
fn altered_pending_fields_cannot_consume_genuine_authorization() {
    exercise(
        "altered_pending_fields_cannot_consume_genuine_authorization",
        Case::AlteredPending,
    );
}

#[test]
fn exact_pending_from_another_connected_process_is_refused() {
    exercise(
        "exact_pending_from_another_connected_process_is_refused",
        Case::WrongPeer,
    );
}
