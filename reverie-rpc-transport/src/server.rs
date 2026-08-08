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
//! global state, which is exactly the property the DBT backend currently lacks.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

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
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
    connection_count: Arc<AtomicUsize>,
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
        Self::bind_inner(path, global, config, None, None)
    }

    // TODO-HUMAN-REVIEW(PR-128): Review the externally shared fallback-readiness boundary.
    /// Binds a coordinator and marks `readiness` after the first complete
    /// guest request arrives.
    pub fn bind_with_readiness(
        path: impl AsRef<Path>,
        global: Arc<G>,
        config: G::Config,
        readiness: Arc<AtomicBool>,
    ) -> Result<Self, RpcError> {
        Self::bind_inner(path, global, config, Some(readiness), None)
    }

    // TODO-HUMAN-REVIEW(PR-139): Review the public config-handshake readiness boundary.
    /// Binds a coordinator and marks `readiness` after a guest receives its
    /// configuration handshake, before that guest sends its first request.
    pub fn bind_with_connection_readiness(
        path: impl AsRef<Path>,
        global: Arc<G>,
        config: G::Config,
        readiness: Arc<AtomicBool>,
    ) -> Result<Self, RpcError> {
        Self::bind_inner(path, global, config, None, Some(readiness))
    }

    fn bind_inner(
        path: impl AsRef<Path>,
        global: Arc<G>,
        config: G::Config,
        readiness: Option<Arc<AtomicBool>>,
        connection_readiness: Option<Arc<AtomicBool>>,
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
            readiness,
            connection_readiness,
            connection_count: Arc::new(AtomicUsize::new(0)),
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

    /// A live count of accepted guest connections.
    ///
    /// Fork children inherit the underlying socket descriptor, so the count
    /// remains nonzero until the last process holding that connection exits or
    /// reconnects. Coordinators can therefore drain an in-guest process tree
    /// without attaching an external lifecycle tracer.
    pub fn connection_count(&self) -> Arc<AtomicUsize> {
        self.connection_count.clone()
    }

    /// Accept connections forever, spawning one task per connection. Returns
    /// only if the listener itself fails.
    ///
    /// Per-connection errors are not fatal to the server: a guest that
    /// disconnects (cleanly or otherwise) simply ends its own task.
    pub async fn serve(self) -> Result<(), RpcError> {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-170): Review connection cancellation on server shutdown.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _addr) = self.listener.accept().await?;
            let global = self.global.clone();
            let config = self.config.clone();
            let readiness = self.readiness.clone();
            let connection_readiness = self.connection_readiness.clone();
            self.connection_count.fetch_add(1, Ordering::AcqRel);
            let connection_guard = ConnectionGuard(self.connection_count.clone());
            connections.spawn(async move {
                let _connection_guard = connection_guard;
                if let Err(e) =
                    serve_connection_inner(global, config, stream, readiness, connection_readiness)
                        .await
                {
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
        self.connection_count.fetch_add(1, Ordering::AcqRel);
        let _connection_guard = ConnectionGuard(self.connection_count.clone());
        serve_connection_inner(
            self.global.clone(),
            self.config.clone(),
            stream,
            self.readiness.clone(),
            self.connection_readiness.clone(),
        )
        .await
    }
}

struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
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
    stream: UnixStream,
) -> Result<(), RpcError>
where
    G: GlobalTool,
{
    serve_connection_inner(global, config, stream, None, None).await
}

async fn serve_connection_inner<G>(
    global: Arc<G>,
    config: G::Config,
    mut stream: UnixStream,
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
) -> Result<(), RpcError>
where
    G: GlobalTool,
{
    // space (it is a separate process), so the coordinator sends it first.
    //
    // NOTE: `G::Request`/`G::Response` are `Send` but not `Sync`, so we always
    // serialize/deserialize at this call site (owned bytes only) rather than
    // passing a `&Request`/`&Response` into an async fn. Holding such a borrow
    // across an await would make this future non-`Send` and break
    // `tokio::spawn`.
    let config_bytes = encode(&config)?;
    write_message(&mut stream, &config_bytes).await?;
    if let Some(readiness) = &connection_readiness {
        readiness.store(true, Ordering::Release);
    }

    loop {
        let request_bytes = match read_message(&mut stream, DEFAULT_MAX_FRAME_LEN).await {
            Ok(bytes) => bytes,
            Err(RpcError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        let RequestEnvelope { from, request } =
            decode::<RequestEnvelope<G::Request>>(&request_bytes)?;
        if let Some(readiness) = &readiness {
            readiness.store(true, Ordering::Release);
        }
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
