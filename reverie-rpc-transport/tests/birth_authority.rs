/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */

#![cfg(target_os = "linux")]

//! D1/D3 spike exit tests at the transport-authority seam. These use
//! real sockets and the current process pidfd; they do not claim a
//! kernel exec or mapped-image installation.

use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use reverie_rpc_transport::Admitted;
use reverie_rpc_transport::BlockingRpcClient;
use reverie_rpc_transport::ConnectionAdmission;
use reverie_rpc_transport::ConnectionFailure;
use reverie_rpc_transport::RpcError;
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::birth_authority::BirthAuthority;
use reverie_rpc_transport::birth_authority::StageClient;
use reverie_rpc_transport::birth_authority::StampedPacket;
use reverie_rpc_transport::birth_authority::frame_tool_state;
use reverie_rpc_transport::birth_authority::verify_and_split_runtime;
use reverie_rpc_transport::codec::encode;
use reverie_rpc_transport::exec_ticket::ExecControlError;
use reverie_rpc_transport::exec_ticket::ExecStage;
use reverie_rpc_transport::exec_ticket::ExecTicket;
use reverie_rpc_transport::initial_image::config_digest;
use reverie_rpc_transport::successor::ExpectedSuccessor;
use reverie_rpc_transport::successor::NativeImageConnection;
use reverie_rpc_transport::successor::SuccessorAdmission;
use reverie_rpc_transport::successor::SuccessorRequest;

const CONFIG: &str = "spike config";
const WAIT: Duration = Duration::from_secs(5);

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

fn pid() -> i32 {
    std::process::id() as i32
}

fn admitted() -> Admitted {
    Admitted { process_id: pid() }
}

fn own_pidfd() -> OwnedFd {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid(), 0) };
    assert!(raw >= 0, "pidfd_open: {}", io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

use std::os::fd::FromRawFd;

fn config_digest_value() -> [u8; 32] {
    config_digest(&encode(&CONFIG.to_owned()).unwrap())
}

fn make_authority() -> Arc<BirthAuthority> {
    Arc::new(
        BirthAuthority::new(
            admitted(),
            config_digest_value(),
            b"initial-only".to_vec(),
            [7u8; 32],
        )
        .unwrap(),
    )
}

fn stamp_packet(
    captured: &Arc<Mutex<Option<ExecTicket>>>,
) -> impl FnOnce(ExecTicket, [u8; 32]) -> Result<StampedPacket, ExecControlError> + '_ {
    move |ticket, sealed| {
        *captured.lock().unwrap() = Some(ticket);
        Ok(StampedPacket {
            expected: ExpectedSuccessor {
                config: config_digest_value(),
                state: sealed,
            },
            redemption: ticket.0.to_vec(),
        })
    }
}

fn stage_and_stop(
    authority: &BirthAuthority,
    framed: Vec<u8>,
    captured: &Arc<Mutex<Option<ExecTicket>>>,
) -> ExpectedSuccessor {
    authority.stage_snapshot(admitted(), framed).unwrap();
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    authority
        .at_successor_stop(stop, stamp_packet(captured))
        .unwrap()
}

#[test]
fn mailbox_stage_stop_issue_redeem_exactly_once() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    let captured = Arc::new(Mutex::new(None));
    let framed = frame_tool_state(b"spike-state-v1").unwrap();
    let expected = stage_and_stop(&authority, framed, &captured);
    let ticket = captured.lock().unwrap().unwrap();
    assert_eq!(authority.stage(ticket), Some(ExecStage::Issued));
    let state = authority
        .redeem(
            own_pidfd(),
            admitted(),
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
    let (runtime, tool) =
        verify_and_split_runtime(&state, config_digest_value(), config_digest(&ticket.0)).unwrap();
    assert_eq!(runtime.exec_ordinal, 1);
    assert_eq!(&tool[4..], b"spike-state-v1");
    assert!(matches!(
        authority.redeem(
            own_pidfd(),
            admitted(),
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        ),
        Err(error) if error.to_string().contains("Transition")
    ));
    authority.complete(ticket).unwrap();
    assert_eq!(authority.stage(ticket), Some(ExecStage::Completed));
}

#[test]
fn stale_after_failed_exec_and_unstaged_exec_refused() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    // Unstaged stop refuses and does not mint.
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    assert!(matches!(
        authority.at_successor_stop(stop, stamp_packet(&Arc::new(Mutex::new(None)))),
        Err(ExecControlError::Unavailable)
    ));
    // Failed-exec path explicitly invalidates; a restage is required.
    authority
        .stage_snapshot(admitted(), frame_tool_state(b"first").unwrap())
        .unwrap();
    authority.invalidate_mailbox(admitted()).unwrap();
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    assert!(matches!(
        authority.at_successor_stop(stop, stamp_packet(&Arc::new(Mutex::new(None)))),
        Err(ExecControlError::Unavailable)
    ));
    // Restaged second snapshot is the only one redeemable.
    let captured = Arc::new(Mutex::new(None));
    let expected = stage_and_stop(
        &authority,
        frame_tool_state(b"second-snapshot").unwrap(),
        &captured,
    );
    let ticket = captured.lock().unwrap().unwrap();
    let state = authority
        .redeem(
            own_pidfd(),
            admitted(),
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
    let (_runtime, tool) =
        verify_and_split_runtime(&state, config_digest_value(), config_digest(&ticket.0)).unwrap();
    assert_eq!(&tool[4..], b"second-snapshot");
}

#[test]
fn close_resolver_orderings() {
    let authority = make_authority();
    let initial = NativeImageConnection::Initial;
    // Initial EOF before any recorded fact is held pending, never
    // accepted yet and never resolved by a timed wait. This is the
    // close_cloexec_files-before-PTRACE_EVENT_EXEC ordering.
    authority.connection_closed(admitted(), &initial).unwrap();
    assert_eq!(authority.pending_eof_count(), 1);
    assert_eq!(authority.accepted_eof_count(), 0);
    assert!(authority.connection_closed(admitted(), &initial).is_err());

    authority.record_initial_consumed(admitted()).unwrap();
    assert_eq!(authority.pending_eof_count(), 1);
    // A staged mailbox for this birth is itself a recorded fact.
    authority
        .stage_snapshot(admitted(), frame_tool_state(b"close-state").unwrap())
        .unwrap();
    assert_eq!(authority.pending_eof_count(), 0);
    assert_eq!(authority.accepted_eof_count(), 1);

    let captured = Arc::new(Mutex::new(None));
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    let expected = authority
        .at_successor_stop(stop, stamp_packet(&captured))
        .unwrap();
    let ticket = captured.lock().unwrap().unwrap();
    let successor_image = NativeImageConnection::Successor {
        ticket: ticket.0.to_vec(),
    };
    // Unknown and Issued Successor EOFs are contradictions: refused
    // at EOF time, never held pending.
    assert!(
        authority
            .connection_closed(
                admitted(),
                &NativeImageConnection::Successor {
                    ticket: vec![9; 32],
                },
            )
            .is_err()
    );
    assert!(
        authority
            .connection_closed(admitted(), &successor_image)
            .is_err()
    );
    assert_eq!(authority.pending_eof_count(), 0);
    assert_eq!(authority.accepted_eof_count(), 1);
    // The genuine EOF after redemption is then accepted.
    authority
        .redeem(
            own_pidfd(),
            admitted(),
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
    authority
        .connection_closed(admitted(), &successor_image)
        .unwrap();
    assert_eq!(authority.pending_eof_count(), 0);
    assert_eq!(authority.accepted_eof_count(), 2);
    authority.finish().unwrap();

    // Initial pending, then terminal: accepted by the watch fact.
    let authority2 = make_authority();
    authority2.connection_closed(admitted(), &initial).unwrap();
    assert_eq!(authority2.pending_eof_count(), 1);
    authority2.record_watch_terminal().unwrap();
    assert_eq!(authority2.accepted_eof_count(), 1);
    assert_eq!(authority2.pending_eof_count(), 0);
    assert_eq!(authority2.refused_eof_count(), 0);

    // No fact ever arrives: finish gives the visible refusal.
    let authority3 = make_authority();
    authority3.connection_closed(admitted(), &initial).unwrap();
    assert!(authority3.finish().is_err());
    assert_eq!(authority3.accepted_eof_count(), 0);
    assert_eq!(authority3.pending_eof_count(), 0);
    assert_eq!(authority3.refused_eof_count(), 1);
}

#[test]
fn exec_ordinal_mismatch_refuses_before_stamp() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    authority
        .stage_snapshot(admitted(), frame_tool_state(b"ordinal-one").unwrap())
        .unwrap();
    let _stop1 = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    let stop2 = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    let stamp_calls = std::sync::atomic::AtomicUsize::new(0);
    let result = authority.at_successor_stop(stop2, |ticket, sealed| {
        stamp_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(StampedPacket {
            expected: ExpectedSuccessor {
                config: config_digest_value(),
                state: sealed,
            },
            redemption: ticket.0.to_vec(),
        })
    });
    assert_eq!(result, Err(ExecControlError::Identity));
    assert_eq!(stamp_calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    let stop3 = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    assert_eq!(
        authority.at_successor_stop(stop3, stamp_packet(&Arc::new(Mutex::new(None)))),
        Err(ExecControlError::Unavailable)
    );
}

#[test]
fn stage_after_watch_terminal_is_refused() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    authority.record_watch_terminal().unwrap();
    assert_eq!(
        authority.stage_snapshot(admitted(), frame_tool_state(b"too-late").unwrap()),
        Err(ExecControlError::Transition)
    );
}

#[test]
fn recorded_stop_resolves_pending_initial_eof() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    let initial = NativeImageConnection::Initial;
    authority.connection_closed(admitted(), &initial).unwrap();
    assert_eq!(authority.pending_eof_count(), 1);
    assert_eq!(authority.accepted_eof_count(), 0);
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    assert_eq!(authority.pending_eof_count(), 0);
    assert_eq!(authority.accepted_eof_count(), 1);
    assert_eq!(
        authority.at_successor_stop(stop, stamp_packet(&Arc::new(Mutex::new(None)))),
        Err(ExecControlError::Unavailable)
    );
    authority.finish().unwrap();
}

#[test]
fn terminal_first_then_initial_eof_accepted_at_once() {
    let authority = make_authority();
    authority.record_watch_terminal().unwrap();
    let initial = NativeImageConnection::Initial;
    authority.connection_closed(admitted(), &initial).unwrap();
    assert_eq!(authority.accepted_eof_count(), 1);
    assert_eq!(authority.pending_eof_count(), 0);
    authority.finish().unwrap();
}

#[test]
fn initial_eof_after_issue_accepted_at_once() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    let captured = Arc::new(Mutex::new(None));
    let _expected = stage_and_stop(
        &authority,
        frame_tool_state(b"after-issue").unwrap(),
        &captured,
    );
    let initial = NativeImageConnection::Initial;
    authority.connection_closed(admitted(), &initial).unwrap();
    assert_eq!(authority.accepted_eof_count(), 1);
    assert_eq!(authority.pending_eof_count(), 0);
    assert!(authority.connection_closed(admitted(), &initial).is_err());
    authority.finish().unwrap();
}

struct Watch;
impl ConnectionAdmission for Watch {
    fn admit(&self, peer: OwnedFd) -> io::Result<Admitted> {
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd()))?;
        let process_id = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .ok_or_else(|| io::Error::other("pidfd has no process"))?
            .trim()
            .parse()
            .map_err(io::Error::other)?;
        Ok(Admitted { process_id })
    }
}

struct SocketPath(PathBuf);
impl SocketPath {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        Self(std::env::temp_dir().join(format!(
            "rv-birth-authority-{}-{}.sock",
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

#[tokio::test]
async fn scalar_stream_initial_stage_stop_successor_end_to_end() {
    let path = SocketPath::new();
    let global = Arc::new(Echo::default());
    let authority = make_authority();
    let mut server = RpcServer::bind(&path.0, global.clone(), CONFIG.to_owned()).unwrap();
    server.set_connection_admission(Arc::new(Watch)).unwrap();
    let issues = server.retain_connection_issues();
    server.set_birth_authority(authority.clone()).unwrap();
    let serve = tokio::spawn(async move { server.serve().await });

    let client_authority = authority.clone();
    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let tid = Tid::from_raw(pid());
        let initial = BlockingRpcClient::<Echo>::connect_initial_image(
            &client_path,
            tid,
            b"initial-only",
            config_digest_value(),
        )
        .unwrap()
        .into_client();
        assert_eq!(initial.config(), CONFIG);
        assert_eq!(initial.try_send_rpc(1).unwrap(), 2);

        // Stage-only RPC over a fresh accepted connection to the
        // same coordinator endpoint, routed by first frame. The
        // client object exposes no seal/mark/issue operation.
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        stage
            .stage_snapshot(frame_tool_state(b"scalar-stream-state").unwrap())
            .unwrap();
        drop(stage);

        // Host-side stop sequence (same test process stands in for the
        // watched birth; the pidfd and Admitted are real).
        let captured = Arc::new(Mutex::new(None));
        let stop = client_authority
            .record_successor_stop(admitted(), &own_pidfd())
            .unwrap();
        let expected = client_authority
            .at_successor_stop(stop, stamp_packet(&captured))
            .unwrap();
        let ticket = captured.lock().unwrap().unwrap();

        let successor = BlockingRpcClient::<Echo>::connect_successor(
            &client_path,
            tid,
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
        let (_runtime, tool) = verify_and_split_runtime(
            successor.state().bytes(),
            config_digest_value(),
            successor.state().ticket_digest(),
        )
        .unwrap();
        assert_eq!(&tool[4..], b"scalar-stream-state");
        let (client, _verified) = successor.into_parts();
        assert_eq!(client.try_send_rpc(4).unwrap(), 5);
        client_authority.complete(ticket).unwrap();
        drop(client);
        drop(initial);
        // Let the server's close hooks run, then take the verdict.
        for _ in 0..200 {
            if client_authority.accepted_eof_count() >= 2
                && client_authority.pending_eof_count() == 0
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(client_authority.pending_eof_count(), 0);
        assert_eq!(client_authority.accepted_eof_count(), 2);
        client_authority.finish().unwrap();
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}; issues={:?}", issues.snapshot()),
    }
    assert!(
        issues.snapshot().is_empty(),
        "issues={:?}",
        issues.snapshot()
    );
    serve.abort();
}

fn raw_write_frame(stream: &mut UnixStream, payload: &[u8]) {
    use std::io::Write;
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(payload).unwrap();
    stream.flush().unwrap();
}

/// The server must close this connection without any response frame.
fn assert_raw_refused(path: &PathBuf, payload: &[u8]) {
    use std::io::Read;
    let mut stream = UnixStream::connect(path).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    raw_write_frame(&mut stream, payload);
    let mut header = [0_u8; 4];
    assert!(
        stream.read_exact(&mut header).is_err(),
        "refused frame unexpectedly got a response"
    );
}

/// Capture the exact payload bytes `StageClient` sends for one
/// stage attempt, by acting as its peer and then closing.
fn capture_stage_payload(framed: Vec<u8>) -> Vec<u8> {
    use std::io::Read;
    let (guest, mut peer) = UnixStream::pair().unwrap();
    let client = std::thread::spawn(move || {
        let mut stage = StageClient::new(guest);
        let _ = stage.stage_snapshot(framed);
    });
    let mut header = [0_u8; 4];
    peer.read_exact(&mut header).unwrap();
    let mut payload = vec![0_u8; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut payload).unwrap();
    drop(peer);
    let _ = client.join();
    payload
}

fn authority_server(path: &SocketPath, authority: &Arc<BirthAuthority>) -> RpcServer<Echo> {
    let mut server =
        RpcServer::bind(&path.0, Arc::new(Echo::default()), CONFIG.to_owned()).unwrap();
    server.set_connection_admission(Arc::new(Watch)).unwrap();
    server.retain_connection_issues();
    server.set_birth_authority(authority.clone()).unwrap();
    server
}

#[tokio::test]
async fn stage_routing_through_authority_server() {
    let path = SocketPath::new();
    let authority = make_authority();
    let mut server = authority_server(&path, &authority);
    let issues = server.retain_connection_issues();
    let serve = tokio::spawn(async move { server.serve().await });

    let client_authority = authority.clone();
    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let tid = Tid::from_raw(pid());
        // Stage before the initial image is consumed refuses
        // fail-closed with the exact Transition error.
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        assert!(matches!(
            stage.stage_snapshot(frame_tool_state(b"early-state").unwrap()),
            Err(ExecControlError::Transition)
        ));
        drop(stage);

        // The valid Initial handshake is preserved on this route.
        let initial = BlockingRpcClient::<Echo>::connect_initial_image(
            &client_path,
            tid,
            b"initial-only",
            config_digest_value(),
        )
        .unwrap()
        .into_client();
        assert_eq!(initial.config(), CONFIG);
        assert_eq!(initial.try_send_rpc(1).unwrap(), 2);

        // A stage frame larger than the native 4096 control bound
        // is accepted on the authority route.
        let big_state = vec![0x5A_u8; 6000];
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        stage
            .stage_snapshot(frame_tool_state(&big_state).unwrap())
            .unwrap();
        drop(stage);

        // Malformed frames bearing either native magic refuse in
        // their native decoders and never reach staging.
        assert_raw_refused(&client_path, b"RVINITRQgarbage");
        assert_raw_refused(&client_path, b"RVSUCCRQgarbage");
        // A trailing byte after an otherwise valid stage payload
        // refuses by exact decode, also without a response.
        let mut trailing = capture_stage_payload(frame_tool_state(b"small-state").unwrap());
        trailing.push(0xAB);
        assert_raw_refused(&client_path, &trailing);

        // The mailbox still holds exactly the big snapshot: issue
        // and redeem it through the valid Successor handshake.
        let captured = Arc::new(Mutex::new(None));
        let stop = client_authority
            .record_successor_stop(admitted(), &own_pidfd())
            .unwrap();
        let expected = client_authority
            .at_successor_stop(stop, stamp_packet(&captured))
            .unwrap();
        let ticket = captured.lock().unwrap().unwrap();
        let successor = BlockingRpcClient::<Echo>::connect_successor(
            &client_path,
            tid,
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
        let (_runtime, tool) = verify_and_split_runtime(
            successor.state().bytes(),
            config_digest_value(),
            successor.state().ticket_digest(),
        )
        .unwrap();
        assert_eq!(&tool[4..], &big_state[..]);
        let (client, _verified) = successor.into_parts();
        assert_eq!(client.try_send_rpc(4).unwrap(), 5);
        client_authority.complete(ticket).unwrap();
        drop(client);
        drop(initial);
        for _ in 0..200 {
            if client_authority.accepted_eof_count() >= 2
                && client_authority.pending_eof_count() == 0
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(client_authority.pending_eof_count(), 0);
        assert_eq!(client_authority.accepted_eof_count(), 2);
        client_authority.finish().unwrap();
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}; issues={:?}", issues.snapshot()),
    }
    // Exactly the two malformed-magic connections and the
    // trailing-byte connection are recorded failures, each with
    // its own decoder's refusal text; stage and native
    // handshakes complete cleanly.
    let snapshot = issues.snapshot();
    assert_eq!(snapshot.len(), 3, "issues={snapshot:?}");
    let texts = format!("{snapshot:?}");
    for expected in [
        "InitialImage magic or version mismatch",
        "successor request length is invalid",
        "stage request decode refused",
    ] {
        assert!(texts.contains(expected), "missing {expected} in {texts}");
    }
    serve.abort();
}

#[tokio::test]
async fn stage_refused_without_birth_authority() {
    let path = SocketPath::new();
    let authority = make_authority();
    let mut server =
        RpcServer::bind(&path.0, Arc::new(Echo::default()), CONFIG.to_owned()).unwrap();
    server.set_connection_admission(Arc::new(Watch)).unwrap();
    let issues = server.retain_connection_issues();
    // Same hooks, but installed without stage routing.
    server
        .set_native_image_admission(authority.clone(), authority.clone())
        .unwrap();
    let serve = tokio::spawn(async move { server.serve().await });

    let client_authority = authority.clone();
    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let tid = Tid::from_raw(pid());
        let initial = BlockingRpcClient::<Echo>::connect_initial_image(
            &client_path,
            tid,
            b"initial-only",
            config_digest_value(),
        )
        .unwrap()
        .into_client();
        assert_eq!(initial.try_send_rpc(1).unwrap(), 2);
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        assert!(
            stage
                .stage_snapshot(frame_tool_state(&vec![0x5A_u8; 6000]).unwrap())
                .is_err(),
            "stage frame must refuse without the authority route"
        );
        drop(stage);
        // Pin the non-authority 4096 first-frame bound: a header
        // claiming 4097 bytes (no payload ever sent) must refuse
        // at read with FrameTooLarge, not be awaited as a
        // plausible stage payload.
        {
            use std::io::Write;
            let mut raw = UnixStream::connect(&client_path).unwrap();
            raw.write_all(&4097_u32.to_be_bytes()).unwrap();
            raw.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            drop(raw);
        }
        drop(initial);
        // Nothing was staged: issue at a recorded stop is Unavailable.
        let captured = Arc::new(Mutex::new(None));
        let stop = client_authority
            .record_successor_stop(admitted(), &own_pidfd())
            .unwrap();
        assert!(matches!(
            client_authority.at_successor_stop(stop, stamp_packet(&captured)),
            Err(ExecControlError::Unavailable)
        ));
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}"),
    }
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let found = issues.snapshot().iter().any(|issue| {
            matches!(
                &issue.failure,
                ConnectionFailure::Transport(error)
                    if matches!(error.as_ref(), RpcError::FrameTooLarge { len: 4097, max: 4096 })
            )
        });
        if found {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no FrameTooLarge 4097/4096 issue recorded: {:?}",
            issues.snapshot()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    serve.abort();
}

#[tokio::test]
async fn wrong_birth_stage_refuses_identity() {
    let path = SocketPath::new();
    let authority = Arc::new(
        BirthAuthority::new(
            Admitted {
                process_id: pid() + 1,
            },
            config_digest_value(),
            b"initial-only".to_vec(),
            [7u8; 32],
        )
        .unwrap(),
    );
    let server = authority_server(&path, &authority);
    let serve = tokio::spawn(async move { server.serve().await });

    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        assert!(matches!(
            stage.stage_snapshot(frame_tool_state(b"wrong-birth").unwrap()),
            Err(ExecControlError::Identity)
        ));
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}"),
    }
    serve.abort();
}

#[test]
fn wrong_birth_stage_and_invalidate_do_not_mutate_mailbox() {
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    authority
        .stage_snapshot(admitted(), frame_tool_state(b"snapshot-a").unwrap())
        .unwrap();
    let wrong = Admitted {
        process_id: pid() + 1,
    };
    assert!(matches!(
        authority.stage_snapshot(wrong, frame_tool_state(b"snapshot-b").unwrap()),
        Err(ExecControlError::Identity)
    ));
    assert!(matches!(
        authority.invalidate_mailbox(wrong),
        Err(ExecControlError::Identity)
    ));
    // The staged snapshot survives both wrong-birth attempts
    // byte-for-byte through issue and redeem.
    let captured = Arc::new(Mutex::new(None));
    let expected = stage_and_stop_resume(&authority, &captured);
    let ticket = captured.lock().unwrap().unwrap();
    let state = authority
        .redeem(
            own_pidfd(),
            admitted(),
            SuccessorRequest {
                ticket: &ticket.0,
                expected,
            },
        )
        .unwrap();
    let (_runtime, tool) =
        verify_and_split_runtime(&state, config_digest_value(), config_digest(&ticket.0)).unwrap();
    assert_eq!(&tool[4..], b"snapshot-a");
    authority.complete(ticket).unwrap();
}

fn stage_and_stop_resume(
    authority: &BirthAuthority,
    captured: &Arc<Mutex<Option<ExecTicket>>>,
) -> ExpectedSuccessor {
    let stop = authority
        .record_successor_stop(admitted(), &own_pidfd())
        .unwrap();
    authority
        .at_successor_stop(stop, stamp_packet(captured))
        .unwrap()
}

#[tokio::test]
async fn reconfiguration_clears_stage_routing() {
    let path = SocketPath::new();
    let authority = make_authority();
    let mut server = authority_server(&path, &authority);
    // Reconfiguring with plain native admission must switch
    // stage routing off (no stale birth_authority retained).
    server
        .set_native_image_admission(authority.clone(), authority.clone())
        .unwrap();
    let serve = tokio::spawn(async move { server.serve().await });

    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let tid = Tid::from_raw(pid());
        let initial = BlockingRpcClient::<Echo>::connect_initial_image(
            &client_path,
            tid,
            b"initial-only",
            config_digest_value(),
        )
        .unwrap()
        .into_client();
        assert_eq!(initial.try_send_rpc(1).unwrap(), 2);
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        assert!(
            stage
                .stage_snapshot(frame_tool_state(b"stale-route").unwrap())
                .is_err(),
            "stage must refuse after routing was reconfigured off"
        );
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}"),
    }
    serve.abort();
}

#[tokio::test]
async fn serve_one_stage_connection_completes_cleanly() {
    let path = SocketPath::new();
    let authority = make_authority();
    authority.record_initial_consumed(admitted()).unwrap();
    let server = authority_server(&path, &authority);
    let serve = tokio::spawn(async move { server.serve_one().await });

    let client_path = path.0.clone();
    let client = tokio::task::spawn_blocking(move || {
        let mut stage = StageClient::new(UnixStream::connect(&client_path).unwrap());
        stage
            .stage_snapshot(frame_tool_state(b"serve-one-state").unwrap())
            .unwrap();
        drop(stage);
    });
    match tokio::time::timeout(WAIT, client).await {
        Ok(Ok(())) => {}
        other => panic!("client failed: {other:?}"),
    }
    match tokio::time::timeout(WAIT, serve).await {
        Ok(Ok(Ok(()))) => {}
        other => panic!("serve_one failed: {other:?}"),
    }
    // The serve_one stage path really staged: issue succeeds.
    let captured = Arc::new(Mutex::new(None));
    stage_and_stop_resume(&authority, &captured);
}
