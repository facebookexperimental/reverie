#![cfg(target_os = "linux")]

//! N1 adversarial tests: replay, forgery, capacity, lifecycle order.

use std::os::fd::OwnedFd;

use reverie_rpc_transport::exec_ticket::ExecControlError;
use reverie_rpc_transport::exec_ticket::ExecStage;
use reverie_rpc_transport::exec_ticket::ExecTicket;
use reverie_rpc_transport::exec_ticket::ExecTicketRegistry;
use reverie_rpc_transport::exec_ticket::TicketBinding;
use reverie_rpc_transport::exec_ticket::TicketProof;
use sha2::Digest;
use sha2::Sha256;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Binding {
    owner: i32,
    config: [u8; 32],
}

impl TicketBinding for Binding {
    type Owner = i32;
    fn owner(&self) -> i32 {
        self.owner
    }
    fn config_digest(&self) -> [u8; 32] {
        self.config
    }
}

struct Proof {
    owner: i32,
    peer_ok: bool,
}

impl TicketProof<Binding> for Proof {
    fn owner(&self) -> i32 {
        self.owner
    }
    fn matches_peer(&self, _peer: &OwnedFd) -> bool {
        self.peer_ok
    }
    fn qualify_prepare(&self, _binding: &Binding, _snapshot: &[u8]) -> bool {
        true
    }
    fn qualify_runtime(&self, _runtime: &[u8]) -> bool {
        true
    }
    fn qualify_completion(&self, _ticket: ExecTicket, _binding: &Binding) -> bool {
        true
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn registry() -> ExecTicketRegistry<Proof, Binding> {
    ExecTicketRegistry::new(
        Proof {
            owner: 7,
            peer_ok: true,
        },
        [9u8; 32],
    )
}

fn prepared(r: &mut ExecTicketRegistry<Proof, Binding>) -> ExecTicket {
    let snap = b"tool-bytes".to_vec();
    let d = digest(&snap);
    r.prepare(
        7,
        Binding {
            owner: 7,
            config: [3u8; 32],
        },
        snap,
        d,
    )
    .unwrap()
}

fn issued(r: &mut ExecTicketRegistry<Proof, Binding>) -> (ExecTicket, [u8; 32]) {
    let t = prepared(r);
    let rt = b"runtime-bytes";
    let sealed = r.seal(7, t, digest(rt), rt).unwrap();
    r.mark_provision_delivered(7, t).unwrap();
    r.issue(7, t, sealed).unwrap();
    (t, sealed)
}

#[test]
fn happy_path_prepare_seal_issue_redeem_complete() {
    let mut r = registry();
    let (t, sealed) = issued(&mut r);
    assert_eq!(r.stage(t), Some(ExecStage::Issued));
    let peer = std::fs::File::open("/dev/null").unwrap();
    let state = r
        .redeem(&OwnedFd::from(peer), t, [3u8; 32], sealed)
        .unwrap();
    assert_eq!(state, b"tool-bytesruntime-bytes");
    assert_eq!(r.stage(t), Some(ExecStage::Redeemed));
    r.complete(7, t).unwrap();
    assert_eq!(r.stage(t), Some(ExecStage::Completed));
}

#[test]
fn replay_after_redeem_and_after_cancel_refused() {
    let mut r = registry();
    let (t, sealed) = issued(&mut r);
    let peer = std::fs::File::open("/dev/null").unwrap();
    let peer: OwnedFd = peer.into();
    r.redeem(&peer, t, [3u8; 32], sealed).unwrap();
    assert_eq!(
        r.redeem(&peer, t, [3u8; 32], sealed),
        Err(ExecControlError::Transition),
        "second redeem must refuse (single-use)"
    );
    r.complete(7, t).unwrap();
    let t2 = prepared(&mut r);
    r.cancel(7, t2).unwrap();
    assert_eq!(r.issue(7, t2, [0u8; 32]), Err(ExecControlError::Transition));
}

#[test]
fn forgery_and_wrong_owner_and_bad_digests_refused() {
    let mut r = registry();
    let (t, sealed) = issued(&mut r);
    let peer: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    // Forged ticket (never minted).
    assert_eq!(
        r.redeem(&peer, ExecTicket([0xff; 32]), [3u8; 32], sealed),
        Err(ExecControlError::Identity)
    );
    // Wrong config/state digests do not consume the ticket.
    assert_eq!(
        r.redeem(&peer, t, [9u8; 32], sealed),
        Err(ExecControlError::Digest)
    );
    assert_eq!(r.stage(t), Some(ExecStage::Issued));
    // Wrong owner on lifecycle calls.
    assert_eq!(r.cancel(8, t), Err(ExecControlError::Identity));
    // Bad snapshot digest at prepare.
    let mut r2 = registry();
    assert_eq!(
        r2.prepare(
            7,
            Binding {
                owner: 7,
                config: [3u8; 32]
            },
            b"x".to_vec(),
            [0u8; 32]
        ),
        Err(ExecControlError::Digest)
    );
}

#[test]
fn peer_mismatch_refuses_without_consuming() {
    let mut r = ExecTicketRegistry::new(
        Proof {
            owner: 7,
            peer_ok: false,
        },
        [9u8; 32],
    );
    let snap = b"tool-bytes".to_vec();
    let d = digest(&snap);
    let t = r
        .prepare(
            7,
            Binding {
                owner: 7,
                config: [3u8; 32],
            },
            snap,
            d,
        )
        .unwrap();
    let rt = b"runtime-bytes";
    let sealed = r.seal(7, t, digest(rt), rt).unwrap();
    r.mark_provision_delivered(7, t).unwrap();
    r.issue(7, t, sealed).unwrap();
    let peer: OwnedFd = std::fs::File::open("/dev/null").unwrap().into();
    assert_eq!(
        r.redeem(&peer, t, [3u8; 32], sealed),
        Err(ExecControlError::Identity)
    );
    assert_eq!(r.stage(t), Some(ExecStage::Issued), "not consumed");
}

#[test]
fn issue_requires_seal_and_delivery_in_order() {
    let mut r = registry();
    let t = prepared(&mut r);
    assert_eq!(r.issue(7, t, [0u8; 32]), Err(ExecControlError::Transition));
    let rt = b"rt";
    let sealed = r.seal(7, t, digest(rt), rt).unwrap();
    // Sealed but not delivered: still refuses.
    assert_eq!(r.issue(7, t, sealed), Err(ExecControlError::Transition));
    r.mark_provision_delivered(7, t).unwrap();
    r.issue(7, t, sealed).unwrap();
}

#[test]
fn died_and_failed_are_terminal() {
    let mut r = registry();
    let t = prepared(&mut r);
    r.died();
    assert_eq!(r.stage(t), Some(ExecStage::Dead));
    assert_eq!(
        r.prepare(
            7,
            Binding {
                owner: 7,
                config: [3u8; 32]
            },
            b"y".to_vec(),
            digest(b"y")
        ),
        Err(ExecControlError::Dead)
    );
}

#[test]
fn control_client_round_trip_over_socketpair() {
    use reverie_rpc_transport::exec_control::ExecControlClient;
    use reverie_rpc_transport::exec_control::ExecIssuer;
    use reverie_rpc_transport::exec_control::serve_exec_control;
    let registry = std::sync::Arc::new(std::sync::Mutex::new(registry()));
    let (client_stream, server_stream) = std::os::unix::net::UnixStream::pair().unwrap();
    let server_registry = registry.clone();
    let server = std::thread::spawn(move || serve_exec_control(server_stream, &server_registry));
    let mut client = ExecControlClient::new(client_stream);
    let snap = b"tool".to_vec();
    let t = client
        .prepare(
            Binding {
                owner: 7,
                config: [3u8; 32],
            },
            snap.clone(),
            digest(&snap),
        )
        .unwrap();
    let rt = b"runtime";
    let sealed = client.seal(t, digest(rt), rt).unwrap();
    client.mark_provision_delivered(t).unwrap();
    assert_eq!(client.issue(t, sealed).unwrap(), t);
    // Replay over the wire is refused by name, not served twice.
    assert_eq!(client.issue(t, sealed), Err(ExecControlError::Transition));
    drop(client);
    server.join().unwrap().unwrap();
    let registry = registry.lock().unwrap();
    assert_eq!(registry.stage(t), Some(ExecStage::Issued));
}
