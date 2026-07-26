/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Synchronous Unix-domain-socket client for the GlobalTool RPC.
//!
//! The DBI guest client runs inside the (DynamoRIO-instrumented) guest process
//! and has no async runtime, so it cannot use the tokio-based
//! [`reverie_rpc_transport::RpcClient`]. This module provides a blocking client
//! that is *wire-compatible* with that crate's [`reverie_rpc_transport::RpcServer`]:
//!
//! * each frame is a big-endian `u32` length prefix followed by a
//!   `bincode`(legacy)-encoded payload;
//! * on connect the server sends exactly one `Config` frame, which we read and
//!   discard (the guest carries no config in its address space);
//! * every request is a [`RequestEnvelope`] `{ from, request }` and the
//!   response travels back bare.
//!
//! When [`RPC_SOCKET_ENV`] is set, a coordinator process (e.g. `hermit-cli`)
//! owns the single shared `GlobalState`; every guest process — including every
//! `fork(2)` child, which inherits the environment and re-connects with its own
//! socket — routes [`reverie::GlobalRPC::send_rpc`] here, giving one shared
//! `GlobalState` across the whole process tree. When the variable is unset,
//! callers fall back to the in-process `GlobalState::receive_rpc`.
//!
//! Because the round-trip is fully synchronous, the `async fn send_rpc` that
//! calls it resolves on its first poll, so the DBI driver's `run_ready` never
//! spins waiting on a cross-thread wake for an RPC.

use std::io::Read;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::OnceLock;

use reverie::Tid;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Environment variable naming the coordinator's Unix-domain socket path. Set
/// by the coordinator (which hosts the [`reverie_rpc_transport::RpcServer`])
/// before launching the guest; inherited across `fork`/`exec`.
pub const RPC_SOCKET_ENV: &str = "HERMIT_DBI_RPC_SOCKET";

/// Mirror of [`reverie_rpc_transport::codec::DEFAULT_MAX_FRAME_LEN`] (16 MiB).
const MAX_FRAME_LEN: usize = 16 * (1 << 20);

/// Local mirror of `reverie_rpc_transport::envelope::RequestEnvelope`, kept here
/// so the injected guest `.so` need not link the transport crate's async
/// runtime. The field order and types match exactly, so the `bincode` encoding
/// is byte-identical and the tokio server decodes it transparently.
#[derive(Serialize)]
struct RequestEnvelope<Req> {
    from: Tid,
    request: Req,
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::legacy())
        .expect("reverie-dbi sync_rpc: bincode encode failed")
}

fn decode<T: DeserializeOwned>(bytes: &[u8]) -> T {
    let (value, _consumed) = bincode::serde::decode_from_slice(bytes, bincode::config::legacy())
        .expect("reverie-dbi sync_rpc: bincode decode failed");
    value
}

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).expect("reverie-dbi sync_rpc: frame too large");
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_frame(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(
        len <= MAX_FRAME_LEN,
        "reverie-dbi sync_rpc: frame length {len} exceeds {MAX_FRAME_LEN}"
    );
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// The process-wide client connection, established lazily on first use from
/// [`RPC_SOCKET_ENV`]. `None` means no coordinator is configured, so callers
/// fall back to the in-process `GlobalState::receive_rpc`.
static CLIENT: OnceLock<Option<Mutex<UnixStream>>> = OnceLock::new();

fn client() -> Option<&'static Mutex<UnixStream>> {
    CLIENT
        .get_or_init(|| {
            let path = std::env::var_os(RPC_SOCKET_ENV)?;
            let mut stream = UnixStream::connect(&path).unwrap_or_else(|error| {
                panic!(
                    "reverie-dbi sync_rpc: failed to connect to coordinator at {path:?}: {error}"
                )
            });
            // Consume the server's one-shot config handshake frame.
            let _config = read_frame(&mut stream).unwrap_or_else(|error| {
                panic!("reverie-dbi sync_rpc: failed to read config handshake: {error}")
            });
            Some(Mutex::new(stream))
        })
        .as_ref()
}

/// True when a coordinator socket is configured, i.e. `send_rpc` should route to
/// the shared cross-process `GlobalState` instead of the in-process one.
pub fn is_active() -> bool {
    client().is_some()
}

/// Perform one blocking request/response round-trip against the coordinator.
///
/// Panics — like the in-process ptrace path's `.expect()`ed serialization and
/// [`reverie_rpc_transport::RpcClient`]'s `send_rpc` — if the coordinator that
/// owns all shared state is unreachable, since there is no meaningful way to
/// continue a deterministic run without it.
pub fn send_rpc<Req, Resp>(from: Tid, request: Req) -> Resp
where
    Req: Serialize,
    Resp: DeserializeOwned,
{
    let mutex = client().expect("reverie-dbi sync_rpc: no coordinator socket configured");
    let mut stream = mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let request_bytes = encode(&RequestEnvelope { from, request });
    write_frame(&mut stream, &request_bytes)
        .expect("reverie-dbi sync_rpc: failed to write request frame");
    let response_bytes =
        read_frame(&mut stream).expect("reverie-dbi sync_rpc: failed to read response frame");
    decode(&response_bytes)
}
