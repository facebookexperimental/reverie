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
use reverie_rpc_transport::RpcServer;
use reverie_rpc_transport::birth_authority::BirthAuthority;
use reverie_rpc_transport::birth_authority::StageClient;
use reverie_rpc_transport::birth_authority::StampedPacket;
use reverie_rpc_transport::birth_authority::frame_tool_state;
use reverie_rpc_transport::birth_authority::serve_stage_snapshot;
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
        assert_eq!(initial.config(), CONFIG);
        assert_eq!(initial.try_send_rpc(1).unwrap(), 2);

        // Stage-only RPC over a separate admitted sync stream. The
        // client object exposes no seal/mark/issue operation.
        let (guest_stream, host_stream) = UnixStream::pair().unwrap();
        let stage_authority = client_authority.clone();
        let stage_server = std::thread::spawn(move || {
            serve_stage_snapshot(host_stream, &stage_authority, admitted())
        });
        let mut stage = StageClient::new(guest_stream);
        stage
            .stage_snapshot(frame_tool_state(b"scalar-stream-state").unwrap())
            .unwrap();
        drop(stage);
        stage_server.join().unwrap().unwrap();

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
