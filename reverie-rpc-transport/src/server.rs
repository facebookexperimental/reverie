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

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::GlobalTool;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::sync::Notify;

use crate::codec::DEFAULT_MAX_FRAME_LEN;
use crate::codec::decode;
use crate::codec::encode;
use crate::codec::read_message;
use crate::codec::write_message;
use crate::envelope::RequestEnvelope;
use crate::error::RpcError;
use crate::initial_image::InitialImageAdmission;

/// `SO_PEERPIDFD` (Linux 6.5): a pidfd for the process that connected the
/// socket. Defined here because the libc crate exports it only from its
/// unstable `new` module. The value is asm-generic's, which x86_64 uses.
const SO_PEERPIDFD: libc::c_int = 77;

/// The process a guest connection's requests must come from, as decided by a
/// [`ConnectionAdmission`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Admitted {
    /// The id the connection's first request must name as its sender.
    pub process_id: i32,
}

/// Decides whether an accepted guest connection may be served.
///
/// The server calls it once per connection, after `accept` and before the
/// configuration handshake or any request, with a pidfd for the connecting
/// process from `SO_PEERPIDFD`. The kernel recorded that process at
/// `connect`, so the descriptor cannot name another process and does not
/// follow a reused pid. An error refuses the connection: the server closes it
/// unserved, and a retained issue monitor records the refusal.
pub trait ConnectionAdmission: Send + Sync {
    /// Admits the connecting process, returning the id its requests must
    /// come from, or refuses it.
    fn admit(&self, peer: OwnedFd) -> std::io::Result<Admitted>;

    /// Receives, before any connection is admitted, the coordinator's
    /// [`ExitReporter`]. An admission that observes exits through the pidfds
    /// it admits keeps it; the default ignores it.
    fn attach_exit_reporter(&self, _reporter: Arc<dyn ExitReporter>) {}

    /// Told when an accepted connection cannot be offered to
    /// [`ConnectionAdmission::admit`] at all, because the connecting
    /// process's pidfd could not be obtained (for example, descriptor
    /// exhaustion, or the process already reaped). The server then refuses
    /// the connection, as for a refused admission. An admission that fails
    /// the run on a refused connection should fail it here too; the default
    /// ignores it.
    fn admission_failed(&self, _error: &std::io::Error) {}
}

/// What an admission that observes guest exits may tell, and ask, the
/// coordinator's global tool during the run; see
/// [`ConnectionAdmission::attach_exit_reporter`]. Each method forwards to the
/// global tool's hook of the same purpose. None waits for guest progress, and
/// after the run each does nothing (or returns nothing).
pub trait ExitReporter: Send + Sync {
    /// Guest process `pid` has physically exited
    /// (`GlobalTool::on_backend_process_exited`).
    fn process_exited(&self, pid: i32);

    /// The processes whose exit the tool granted and is waiting to see
    /// complete (`GlobalTool::backend_pending_process_exits`), for a
    /// watchdog.
    fn pending_process_exits(&self) -> Vec<i32>;

    /// The run cannot continue faithfully
    /// (`GlobalTool::report_backend_failure`).
    fn backend_failed(&self, failure: reverie::BackendFailure);
}

/// A pidfd for the process that connected `stream`.
fn peer_pidfd(stream: &impl AsRawFd) -> std::io::Result<OwnedFd> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            &mut fd as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if fd < 0 || len as usize != std::mem::size_of::<libc::c_int>() {
        return Err(std::io::Error::other(format!(
            "SO_PEERPIDFD returned descriptor {fd} (length {len})"
        )));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Runs `admission`, if any, on an accepted connection.
fn admit_connection(
    admission: Option<&Arc<dyn ConnectionAdmission>>,
    stream: &UnixStream,
) -> Result<Option<Admitted>, RpcError> {
    let Some(admission) = admission else {
        return Ok(None);
    };
    let peer = match peer_pidfd(stream) {
        Ok(peer) => peer,
        Err(error) => {
            admission.admission_failed(&error);
            return Err(error.into());
        }
    };
    Ok(Some(admission.admit(peer)?))
}

/// A coordinator that serves one shared [`GlobalTool`] instance to many guest
/// processes over a Unix-domain socket.
pub struct RpcServer<G: GlobalTool> {
    global: Arc<G>,
    config: G::Config,
    listener: UnixListener,
    path: PathBuf,
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
    connections: ConnectionMonitor,
    issues: Option<RpcIssueMonitor>,
    admission: Option<Arc<dyn ConnectionAdmission>>,
    initial_image: Option<InitialImageSetup>,
}

#[derive(Clone)]
struct InitialImageSetup {
    admission: Arc<dyn InitialImageAdmission>,
    config_bytes: Arc<Vec<u8>>,
}

/// Actual connection failures, retained independently of the serving task.
#[derive(Clone, Debug)]
pub enum ConnectionFailure {
    Transport(Arc<RpcError>),
    Panicked(Arc<PanicPayload>),
    UnresolvedPanic,
    Interrupted,
}

pub struct PanicPayload(pub Mutex<Box<dyn std::any::Any + Send>>);
impl std::fmt::Debug for PanicPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let payload = self.0.lock().unwrap();
        if let Some(message) = payload.downcast_ref::<String>() {
            message.fmt(formatter)
        } else if let Some(message) = payload.downcast_ref::<&str>() {
            message.fmt(formatter)
        } else {
            formatter.write_str("non-string panic payload retained")
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionIssue {
    pub connection: usize,
    pub failure: ConnectionFailure,
}

#[derive(Clone, Default)]
pub struct RpcIssueMonitor {
    issues: Arc<Mutex<Vec<ConnectionIssue>>>,
    changed: Arc<Notify>,
    planned: Arc<AtomicBool>,
    reserved: Arc<AtomicUsize>,
}

impl RpcIssueMonitor {
    fn reserve(&self) -> Result<(), RpcError> {
        self.reserved
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < 64).then_some(count + 1)
            })
            .map(|_| ())
            .map_err(|_| {
                std::io::Error::other(
                    "retained RPC issue capacity exhausted before connection dispatch",
                )
                .into()
            })
    }
    pub fn snapshot(&self) -> Vec<ConnectionIssue> {
        self.issues.lock().unwrap().clone()
    }
    pub fn planned_shutdown(&self) {
        self.planned.store(true, Ordering::Release);
    }
    pub async fn failed(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.issues.lock().unwrap().is_empty() {
                return;
            }
            notified.await;
        }
    }
    fn record(&self, connection: usize, failure: ConnectionFailure) {
        self.issues.lock().unwrap().push(ConnectionIssue {
            connection,
            failure,
        });
        self.changed.notify_waiters();
    }
}

struct IssueGuard {
    monitor: Option<RpcIssueMonitor>,
    connection: usize,
    completed: bool,
}

impl IssueGuard {
    fn panic(&mut self, payload: Box<dyn std::any::Any + Send>) {
        self.completed = true;
        if let Some(monitor) = &self.monitor {
            monitor.record(
                self.connection,
                ConnectionFailure::Panicked(Arc::new(PanicPayload(Mutex::new(payload)))),
            );
        }
    }
    fn complete(&mut self, result: Result<(), RpcError>) {
        self.completed = true;
        if let Err(error) = result {
            if !matches!(error, RpcError::Closed) {
                if let Some(monitor) = &self.monitor {
                    monitor.record(
                        self.connection,
                        ConnectionFailure::Transport(Arc::new(error)),
                    );
                    return;
                } else {
                    tracing_disconnect(&error);
                }
            }
        }
        if let Some(monitor) = &self.monitor {
            monitor.reserved.fetch_sub(1, Ordering::Release);
        }
    }
}

impl Drop for IssueGuard {
    fn drop(&mut self) {
        if let Some(monitor) = &self.monitor {
            if !self.completed
                && (!monitor.planned.load(Ordering::Acquire) || std::thread::panicking())
            {
                monitor.record(
                    self.connection,
                    if std::thread::panicking() {
                        ConnectionFailure::UnresolvedPanic
                    } else {
                        ConnectionFailure::Interrupted
                    },
                );
            } else if !self.completed {
                monitor.reserved.fetch_sub(1, Ordering::Release);
            }
        }
    }
}

/// A live, waitable view of a coordinator's accepted connections.
///
/// Unlike polling [`RpcServer::connection_count`], [`wait_for_idle`](Self::wait_for_idle)
/// blocks the current task until the last connection closes. Clones share the
/// same count and wakeup, so a launcher can obtain a monitor before moving the
/// server into its serving task.
#[derive(Clone)]
pub struct ConnectionMonitor {
    count: Arc<AtomicUsize>,
    idle: Arc<Notify>,
}

impl ConnectionMonitor {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            idle: Arc::new(Notify::new()),
        }
    }

    fn connected(&self) -> ConnectionGuard {
        self.count.fetch_add(1, Ordering::AcqRel);
        ConnectionGuard(self.clone())
    }

    /// Returns the current number of accepted connections.
    pub fn active_connections(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Waits without polling until every currently tracked connection closes.
    pub async fn wait_for_idle(&self) {
        loop {
            let notified = self.idle.notified();
            tokio::pin!(notified);
            // Register before loading the count so a last-close notification
            // cannot race between the observation and the await.
            notified.as_mut().enable();
            if self.active_connections() == 0 {
                return;
            }
            notified.await;
        }
    }
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

    /// Bind a new coordinator without removing any existing directory entry.
    ///
    /// An occupied path returns the kernel's bind error unchanged, even if
    /// the entry appeared after a caller's absence check. Failed binds do not
    /// construct a server or clean up the path. Successful servers use the
    /// same owned-path cleanup as [`Self::bind`].
    pub fn bind_exclusive(
        path: impl AsRef<Path>,
        global: Arc<G>,
        config: G::Config,
    ) -> Result<Self, RpcError> {
        let path = path.as_ref().to_path_buf();
        let listener = UnixListener::bind(&path)?;
        Ok(Self {
            global,
            config,
            listener,
            path,
            readiness: None,
            connection_readiness: None,
            connections: ConnectionMonitor::new(),
            issues: None,
            admission: None,
            initial_image: None,
        })
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
            connections: ConnectionMonitor::new(),
            issues: None,
            admission: None,
            initial_image: None,
        })
    }

    /// Admits every later connection through `admission` before serving it;
    /// see [`ConnectionAdmission`].
    pub fn set_connection_admission(&mut self, admission: Arc<dyn ConnectionAdmission>) {
        self.admission = Some(admission);
    }

    /// Require InitialImage redemption on every connection to this server.
    ///
    /// The normal process admission/watcher and retained issue monitor must
    /// already be configured. There is no protocol detection or ordinary
    /// fallback. This initial slice does not admit successor exec, fork or
    /// thread transactions; an ordinary fork reconnect to this server fails
    /// closed. Unconfigured legacy servers retain their config-first protocol.
    /// Config is canonically encoded once here and those immutable bytes are
    /// used for every digest and config frame on this server. The hook
    /// implements launcher policy; transport does not authenticate it.
    pub fn set_initial_image_admission(
        &mut self,
        admission: Arc<dyn InitialImageAdmission>,
    ) -> Result<(), RpcError> {
        if self.admission.is_none() || self.issues.is_none() {
            return Err(crate::initial_image::invalid(
                "InitialImage requires process admission and retained connection issues",
            ));
        }
        self.initial_image = Some(InitialImageSetup {
            admission,
            config_bytes: Arc::new(encode(&self.config)?),
        });
        Ok(())
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
        self.connections.count.clone()
    }

    /// A blocking-wakeup monitor for accepted connection lifetime.
    pub fn connection_monitor(&self) -> ConnectionMonitor {
        self.connections.clone()
    }

    /// Opt-in for `serve`: reserves evidence before dispatch (64 outstanding or
    /// failed connections). Clean completion releases capacity; failures retain
    /// their original cause. Exhaustion ends serving rather than losing an issue.
    pub fn retain_connection_issues(&mut self) -> RpcIssueMonitor {
        self.issues
            .get_or_insert_with(RpcIssueMonitor::default)
            .clone()
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
        let mut connection = 0usize;
        loop {
            let (stream, _addr) = tokio::select! {
                result = self.listener.accept() => result?,
                _ = connections.join_next(), if !connections.is_empty() => continue,
            };
            connection = connection
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("RPC connection identity exhausted"))?;
            let global = self.global.clone();
            let config = self.config.clone();
            let readiness = self.readiness.clone();
            let connection_readiness = self.connection_readiness.clone();
            let connection_guard = self.connections.connected();
            if let Some(issues) = &self.issues {
                issues.reserve()?;
            }
            let mut issue_guard = IssueGuard {
                monitor: self.issues.clone(),
                connection,
                completed: false,
            };
            let retain_issues = self.issues.is_some();
            let admission = self.admission.clone();
            let initial_image = self.initial_image.clone();
            connections.spawn(async move {
                let _connection_guard = connection_guard;
                let future = async move {
                    let mut stream = stream;
                    let admitted = admit_connection(admission.as_ref(), &stream)?;
                    let config_bytes = match initial_image {
                        Some(hook) => Some(
                            initial_image_handshake(
                                &mut stream,
                                admitted,
                                hook.admission.as_ref(),
                                hook.config_bytes,
                            )
                            .await?,
                        ),
                        None => None,
                    };
                    serve_connection_inner(
                        global,
                        config,
                        stream,
                        readiness,
                        connection_readiness,
                        admitted,
                        config_bytes,
                    )
                    .await
                };
                if retain_issues {
                    let mut future = std::pin::pin!(future);
                    let result = std::future::poll_fn(|context| {
                        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            std::future::Future::poll(future.as_mut(), context)
                        })) {
                            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
                            Ok(std::task::Poll::Ready(result)) => {
                                std::task::Poll::Ready(Ok(result))
                            }
                            Err(payload) => std::task::Poll::Ready(Err(payload)),
                        }
                    })
                    .await;
                    match result {
                        Ok(result) => issue_guard.complete(result),
                        Err(payload) => issue_guard.panic(payload),
                    }
                } else {
                    issue_guard.complete(future.await);
                }
            });
        }
    }

    /// Accept and fully serve exactly one connection on the current task. This
    /// is primarily useful for tests and for single-guest scenarios.
    pub async fn serve_one(&self) -> Result<(), RpcError> {
        let (mut stream, _addr) = self.listener.accept().await?;
        let _connection_guard = self.connections.connected();
        // Legacy serve_one retains its original error-return behavior. The
        // explicit InitialImage path also retains every admission/redemption
        // failure independently of this task, including missing redemption EOF.
        let monitor = self.initial_image.as_ref().and(self.issues.clone());
        if let Some(monitor) = &monitor {
            monitor.reserve()?;
        }
        let mut guard = IssueGuard {
            monitor,
            connection: 1,
            completed: false,
        };
        let result = async {
            let admitted = admit_connection(self.admission.as_ref(), &stream)?;
            let config = self.config.clone();
            let config_bytes = match &self.initial_image {
                Some(hook) => Some(
                    initial_image_handshake(
                        &mut stream,
                        admitted,
                        hook.admission.as_ref(),
                        hook.config_bytes.clone(),
                    )
                    .await?,
                ),
                None => None,
            };
            serve_connection_inner(
                self.global.clone(),
                config,
                stream,
                self.readiness.clone(),
                self.connection_readiness.clone(),
                admitted,
                config_bytes,
            )
            .await
        }
        .await;
        match result {
            Err(error) if guard.monitor.is_some() => {
                let error = Arc::new(error);
                guard.completed = true;
                guard.monitor.as_ref().unwrap().record(
                    guard.connection,
                    ConnectionFailure::Transport(error.clone()),
                );
                Err(RpcError::Io(std::io::Error::other(error)))
            }
            other => {
                guard.complete(Ok(()));
                other
            }
        }
    }
}

struct ConnectionGuard(ConnectionMonitor);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let previous = self.0.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "connection count underflow");
        if previous == 1 {
            self.0.idle.notify_waiters();
        }
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
    serve_connection_inner(global, config, stream, None, None, None, None).await
}

/// Serve an independently owned asynchronous byte stream using the same
/// handshake, framing and GlobalTool dispatch as a Unix connection.
///
/// This reports logical connection completion, not process exit. The caller
/// owns task lifetime/cancellation and must keep separate streams independently
/// polled; a pending response must not block other connections.
pub async fn serve_stream<G, S>(
    global: Arc<G>,
    config: G::Config,
    stream: S,
) -> Result<(), RpcError>
where
    G: GlobalTool,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    serve_connection_inner(global, config, stream, None, None, None, None).await
}

/// Admission has already installed the normal process watch. A second pidfd
/// comes from this exact socket; the watcher continues owning its first one.
async fn initial_image_handshake(
    stream: &mut UnixStream,
    admitted: Option<Admitted>,
    hook: &dyn InitialImageAdmission,
    config_bytes: Arc<Vec<u8>>,
) -> Result<Arc<Vec<u8>>, RpcError> {
    let admitted = admitted.ok_or_else(|| {
        crate::initial_image::invalid("InitialImage connection has no watched process admission")
    })?;
    let peer = peer_pidfd(stream)?;
    let request = read_message(stream, crate::initial_image::MAX_FRAME_LEN)
        .await
        .map_err(|error| match error {
            RpcError::Closed => crate::initial_image::invalid("InitialImage redemption is missing"),
            other => other,
        })?;
    let redemption = crate::initial_image::decode_redemption(&request)?;
    let digest = crate::initial_image::config_digest(&config_bytes);
    hook.redeem(peer, admitted, redemption, digest)?;
    let ack = crate::initial_image::encode_ack(digest);
    write_message(stream, &ack).await?;
    Ok(config_bytes)
}

async fn serve_connection_inner<G, S>(
    global: Arc<G>,
    config: G::Config,
    mut stream: S,
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
    mut admitted: Option<Admitted>,
    config_bytes: Option<Arc<Vec<u8>>>,
) -> Result<(), RpcError>
where
    G: GlobalTool,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // space (it is a separate process), so the coordinator sends it first.
    //
    // NOTE: `G::Request`/`G::Response` are `Send` but not `Sync`, so we always
    // serialize/deserialize at this call site (owned bytes only) rather than
    // passing a `&Request`/`&Response` into an async fn. Holding such a borrow
    // across an await would make this future non-`Send` and break
    // `tokio::spawn`.
    let config_bytes = match &config_bytes {
        Some(bytes) => std::borrow::Cow::Borrowed(bytes.as_slice()),
        None => std::borrow::Cow::Owned(encode(&config)?),
    };
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
        // An admitted connection's first request must come from the admitted
        // process: a guest process is single-threaded, and a forked child
        // reconnects before it sends anything, so its first sender is itself.
        if let Some(Admitted { process_id }) = admitted.take() {
            if from.as_raw() != process_id {
                return Err(RpcError::Io(std::io::Error::other(format!(
                    "connection admitted for process {process_id} sent its first request as {}",
                    from.as_raw()
                ))));
            }
        }
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

#[cfg(test)]
mod exclusive_bind_tests {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    use std::sync::atomic::AtomicU64;

    use super::*;

    #[derive(Default)]
    struct EmptyGlobal;

    #[reverie::global_tool]
    impl GlobalTool for EmptyGlobal {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: reverie::Tid, _request: ()) {}
    }

    struct Directory(PathBuf);

    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = PathBuf::from(format!(
                "/tmp/reverie-rpc-new-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("rpc.sock")
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn identity(path: &Path) -> (u64, u64, u32) {
        let entry = std::fs::symlink_metadata(path).unwrap();
        (entry.dev(), entry.ino(), entry.mode())
    }

    fn expect_occupied(path: &Path) {
        match RpcServer::bind_exclusive(path, Arc::new(EmptyGlobal), ()) {
            Err(RpcError::Io(error)) => {
                assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE));
            }
            Err(error) => panic!("unexpected exclusive bind error: {error}"),
            Ok(_) => panic!("exclusive bind replaced an occupied entry"),
        }
    }

    #[tokio::test]
    async fn initial_stats_exclusive_bind_preserves_regular_file() {
        let directory = Directory::new();
        let path = directory.socket();
        let bytes = b"existing file\0with exact bytes\xff";
        std::fs::write(&path, bytes).unwrap();
        let before = identity(&path);
        expect_occupied(&path);
        assert_eq!(identity(&path), before);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn initial_stats_exclusive_bind_preserves_symlink_and_target() {
        let directory = Directory::new();
        let path = directory.socket();
        let target = directory.0.join("target");
        let bytes = b"untouched symlink target\0\xfe";
        std::fs::write(&target, bytes).unwrap();
        std::os::unix::fs::symlink("target", &path).unwrap();
        let before = identity(&path);
        let target_before = identity(&target);
        let link_before = std::fs::read_link(&path).unwrap();
        expect_occupied(&path);
        assert_eq!(identity(&path), before);
        assert_eq!(std::fs::read_link(&path).unwrap(), link_before);
        assert_eq!(identity(&target), target_before);
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }

    #[tokio::test]
    async fn initial_stats_exclusive_bind_preserves_existing_live_socket() {
        let directory = Directory::new();
        let path = directory.socket();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let before = identity(&path);
        expect_occupied(&path);
        assert_eq!(identity(&path), before);
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(identity(&path), before);
    }

    #[tokio::test]
    async fn initial_stats_exclusive_bind_preserves_entry_created_after_absence_check() {
        let directory = Directory::new();
        let path = directory.socket();
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        // Deterministically occupy the named check/bind window.
        let bytes = b"created after the absence check";
        std::fs::write(&path, bytes).unwrap();
        let before = identity(&path);
        expect_occupied(&path);
        assert_eq!(identity(&path), before);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn initial_stats_exclusive_bind_cleanup_and_ordinary_replacement_are_preserved() {
        let directory = Directory::new();
        let path = directory.socket();
        let server = RpcServer::bind_exclusive(&path, Arc::new(EmptyGlobal), ()).unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        drop(server);
        assert_eq!(
            std::fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );

        std::fs::write(&path, b"ordinary bind still replaces this stale entry").unwrap();
        let server = RpcServer::bind(&path, Arc::new(EmptyGlobal), ()).unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        drop(server);
        assert!(!path.exists());
    }
}

#[cfg(test)]
mod admission_tests {
    use std::os::fd::FromRawFd;
    use std::sync::Mutex;

    use super::*;

    /// Records what the server told it.
    #[derive(Default)]
    struct Recording {
        admitted: Mutex<bool>,
        failed: Mutex<Option<std::io::ErrorKind>>,
    }

    impl ConnectionAdmission for Recording {
        fn admit(&self, _peer: OwnedFd) -> std::io::Result<Admitted> {
            *self.admitted.lock().unwrap() = true;
            Ok(Admitted { process_id: 1 })
        }

        fn admission_failed(&self, error: &std::io::Error) {
            *self.failed.lock().unwrap() = Some(error.kind());
        }
    }

    /// A connection whose peer pidfd cannot be obtained is reported through
    /// `admission_failed` and refused, and never reaches `admit`. A pipe
    /// stands in for the socket so `SO_PEERPIDFD` fails deterministically.
    #[tokio::test]
    async fn a_connection_without_a_peer_pidfd_is_reported_and_refused() {
        let mut pipe = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let _write_end = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(pipe[0]) };
        std_stream.set_nonblocking(true).unwrap();
        let stream = UnixStream::from_std(std_stream).unwrap();
        let recording = Arc::new(Recording::default());
        let admission: Arc<dyn ConnectionAdmission> = recording.clone();
        assert!(admit_connection(Some(&admission), &stream).is_err());
        assert!(
            recording.failed.lock().unwrap().is_some(),
            "the server must report a connection it could not offer for admission"
        );
        assert!(!*recording.admitted.lock().unwrap());
    }
}
