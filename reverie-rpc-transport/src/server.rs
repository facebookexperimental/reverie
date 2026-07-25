/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Coordinator (server) side of the cross-process GlobalTool RPC.
//!
//! The coordinator process owns the single [`GlobalTool`] instance (for
//! Detcore this is the `GlobalState` holding the scheduler and virtual clock)
//! and listens on a Unix-domain socket. Each guest process connects, and every
//! request it sends is dispatched to [`GlobalTool::receive_rpc`] on the shared
//! instance. Because the instance is shared behind an [`Arc`], all connected
//! guests — including forked children that connect later — observe one unified
//! global state, which is exactly the property the DBI backend currently lacks.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use reverie::GlobalTool;
use tokio::net::UnixListener;
use tokio::net::UnixStream;

use crate::codec::DEFAULT_MAX_FRAME_LEN;
use crate::codec::decode;
use crate::codec::encode;
use crate::codec::read_message;
use crate::codec::write_message;
use crate::envelope::RequestEnvelope;
use crate::error::RpcError;

/// A coordinator that serves one shared [`GlobalTool`] instance to many guest
/// processes over a Unix-domain socket.
pub struct RpcServer<G: GlobalTool> {
    global: Arc<G>,
    config: G::Config,
    listener: UnixListener,
    path: PathBuf,
}

impl<G> RpcServer<G>
where
    G: GlobalTool + 'static,
{
    /// Bind a coordinator to `path`, serving the shared `global` instance whose
    /// static configuration is `config`.
    ///
    /// A stale socket file left at `path` by a previous run is removed first so
    /// the bind does not fail with `EADDRINUSE`. The socket file is removed
    /// again when the server is dropped.
    pub fn bind(
        path: impl AsRef<Path>,
        global: Arc<G>,
        config: G::Config,
    ) -> Result<Self, RpcError> {
        let path = path.as_ref().to_path_buf();
        // Best-effort removal of a stale socket; ignore "not found".
        match std::fs::remove_file(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(RpcError::Io(e)),
        }
        let listener = UnixListener::bind(&path)?;
        Ok(Self {
            global,
            config,
            listener,
            path,
        })
    }

    /// The filesystem path this coordinator is listening on. Guests connect
    /// here with [`crate::RpcClient::connect`].
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A cheap handle to the shared global instance (for the coordinator's own
    /// use, e.g. to generate the final run summary after serving).
    pub fn global(&self) -> Arc<G> {
        self.global.clone()
    }

    /// Accept connections forever, spawning one task per connection. Returns
    /// only if the listener itself fails.
    ///
    /// Per-connection errors are not fatal to the server: a guest that
    /// disconnects (cleanly or otherwise) simply ends its own task.
    pub async fn serve(self) -> Result<(), RpcError> {
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let global = self.global.clone();
            let config = self.config.clone();
            tokio::spawn(async move {
                if let Err(e) = serve_connection(global, config, stream).await {
                    // A clean close is the normal way a guest connection ends.
                    if !matches!(e, RpcError::Closed) {
                        tracing_disconnect(&e);
                    }
                }
            });
        }
    }

    /// Accept and fully serve exactly one connection on the current task. This
    /// is primarily useful for tests and for single-guest scenarios.
    pub async fn serve_one(&self) -> Result<(), RpcError> {
        let (stream, _addr) = self.listener.accept().await?;
        serve_connection(self.global.clone(), self.config.clone(), stream).await
    }
}

impl<G: GlobalTool> Drop for RpcServer<G> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Serve a single connected guest: send the config handshake, then loop
/// dispatching request frames to [`GlobalTool::receive_rpc`] and writing back
/// the response frame. Returns [`RpcError::Closed`] on a clean disconnect.
pub async fn serve_connection<G>(
    global: Arc<G>,
    config: G::Config,
    mut stream: UnixStream,
) -> Result<(), RpcError>
where
    G: GlobalTool,
{
    // Handshake: the guest process does not have the config in its address
    // space (it is a separate process), so the coordinator sends it first.
    //
    // NOTE: `G::Request`/`G::Response` are `Send` but not `Sync`, so we always
    // serialize/deserialize at this call site (owned bytes only) rather than
    // passing a `&Request`/`&Response` into an async fn. Holding such a borrow
    // across an await would make this future non-`Send` and break
    // `tokio::spawn`.
    let config_bytes = encode(&config)?;
    write_message(&mut stream, &config_bytes).await?;

    loop {
        let request_bytes = match read_message(&mut stream, DEFAULT_MAX_FRAME_LEN).await {
            Ok(bytes) => bytes,
            Err(RpcError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        let RequestEnvelope { from, request } =
            decode::<RequestEnvelope<G::Request>>(&request_bytes)?;
        let response = global.receive_rpc(from, request).await;
        let response_bytes = encode(&response)?;
        write_message(&mut stream, &response_bytes).await?;
    }
}

// Keep the tracing dependency optional/soft: the reverie tree uses `tracing`
// widely, but this crate stays lean. We only emit to stderr on an unexpected
// connection error so a coordinator operator can see it.
fn tracing_disconnect(e: &RpcError) {
    eprintln!("reverie-rpc-transport: guest connection ended with error: {e}");
}
