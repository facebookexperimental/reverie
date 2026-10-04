/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Guest (client) side of the cross-process GlobalTool RPC.
//!
//! Each guest process — and, per the architecture, each guest *thread* — opens
//! its own connection to the coordinator and drives it through [`RpcClient`].
//! The client implements [`reverie::GlobalRPC`], so a backend's `Guest`
//! implementation can forward `send_rpc` to it unchanged: the request is
//! bincode-encoded, framed, written to the socket, and the response frame is
//! read back and decoded.

use std::marker::PhantomData;
use std::path::Path;

use async_trait::async_trait;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Tid;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

use crate::codec::DEFAULT_MAX_FRAME_LEN;
use crate::codec::decode;
use crate::codec::encode;
use crate::codec::read_message;
use crate::codec::write_message;
use crate::envelope::RequestEnvelope;
use crate::error::RpcError;

/// A per-connection client to a coordinator serving `G`'s global state.
///
/// `send_rpc` is synchronous request/response with a single message in flight,
/// matching the [`GlobalRPC`] contract (one blocking call per guest thread), so
/// no request-id multiplexing is needed. The stream is guarded by an async
/// [`Mutex`] purely to satisfy the `&self` + `Sync` signature; a per-thread
/// client is never contended.
pub struct RpcClient<G: GlobalTool> {
    tid: Tid,
    config: G::Config,
    stream: Mutex<UnixStream>,
    _phantom: PhantomData<fn() -> G>,
}

impl<G> RpcClient<G>
where
    G: GlobalTool,
{
    /// Connect to the coordinator listening at `path`, identifying requests
    /// from this connection as originating from `tid`.
    ///
    /// The coordinator sends the static [`GlobalTool::Config`] as a handshake
    /// frame immediately on connect (a guest process does not otherwise have
    /// the config in its address space); this is read and cached so
    /// [`GlobalRPC::config`] can return it synchronously.
    pub async fn connect(path: impl AsRef<Path>, tid: Tid) -> Result<Self, RpcError> {
        let mut stream = UnixStream::connect(path.as_ref()).await?;
        let config_bytes = read_message(&mut stream, DEFAULT_MAX_FRAME_LEN).await?;
        let config: G::Config = decode(&config_bytes)?;
        Ok(Self {
            tid,
            config,
            stream: Mutex::new(stream),
            _phantom: PhantomData,
        })
    }

    /// The tid this client tags its requests with.
    pub fn tid(&self) -> Tid {
        self.tid
    }

    /// Fallible form of [`GlobalRPC::send_rpc`]. Returns transport/codec errors
    /// instead of panicking, for callers that can handle a dead coordinator.
    pub async fn try_send_rpc(&self, message: G::Request) -> Result<G::Response, RpcError> {
        // Serialize before touching the socket so the non-`Sync` `&Request`
        // borrow stays in this synchronous scope and never crosses an await.
        let envelope = RequestEnvelope {
            from: self.tid,
            request: message,
        };
        let request_bytes = encode(&envelope)?;

        let mut stream = self.stream.lock().await;
        write_message(&mut *stream, &request_bytes).await?;
        let response_bytes = read_message(&mut *stream, DEFAULT_MAX_FRAME_LEN).await?;
        decode(&response_bytes)
    }
}

#[async_trait]
impl<G> GlobalRPC<G> for RpcClient<G>
where
    G: GlobalTool,
{
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        // The `GlobalRPC` contract is infallible; a broken connection means the
        // coordinator (which owns all deterministic state) is gone, so there is
        // no meaningful way to continue. This mirrors how the in-process ptrace
        // path `.expect()`s its debug-mode serialization round-trip.
        self.try_send_rpc(message)
            .await
            .expect("reverie-rpc-transport: RPC to coordinator failed")
    }

    fn config(&self) -> &G::Config {
        &self.config
    }
}
