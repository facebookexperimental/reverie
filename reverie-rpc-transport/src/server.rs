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
use crate::successor::SuccessorAdmission;
use crate::tool_activation::ActivationConnection;
use crate::tool_activation::ActivationRun;

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

fn mapping_capture_peer(
    run: Option<reverie::MappingCaptureRun>,
    stream: &UnixStream,
) -> Result<Option<(reverie::MappingCaptureRun, i32)>, RpcError> {
    let Some(run) = run else {
        return Ok(None);
    };
    let peer = stream
        .peer_cred()?
        .pid()
        .ok_or_else(|| std::io::Error::other("mapping capture connection has no physical peer"))?;
    Ok(Some((run, peer)))
}

fn tool_activation_peer(
    run: Option<&ActivationRun>,
    stream: &UnixStream,
) -> Result<Option<ActivationConnection>, RpcError> {
    let Some(run) = run else {
        return Ok(None);
    };
    let result = (|| {
        let peer = stream.peer_cred()?.pid().ok_or_else(|| {
            crate::tool_activation::invalid("Tool activation connection has no physical peer")
        })?;
        run.accepted(peer)
    })();
    if result.is_err() {
        run.fail("Tool activation accepted socket authentication failed");
    }
    result.map(Some)
}

/// A coordinator that serves one shared [`GlobalTool`] instance to many guest
/// processes over a Unix-domain socket.
pub struct RpcServer<G: GlobalTool> {
    global: Arc<G>,
    config: G::Config,
    listener: UnixListener,
    path: PathBuf,
    cleanup_path: bool,
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
    connections: ConnectionMonitor,
    issues: Option<RpcIssueMonitor>,
    admission: Option<Arc<dyn ConnectionAdmission>>,
    initial_image: Option<InitialImageSetup>,
    native_successor: Option<Arc<dyn SuccessorAdmission>>,
    mapping_capture: Option<reverie::MappingCaptureRun>,
    tool_activation: Option<ActivationRun>,
}

#[derive(Clone)]
struct InitialImageSetup {
    admission: Arc<dyn InitialImageAdmission>,
    config_bytes: Arc<Vec<u8>>,
}

struct HandshakeFrames {
    config: Arc<Vec<u8>>,
    successor_state: Option<Vec<u8>>,
    strict_sender: bool,
    native_image: Option<crate::successor::NativeImageConnection>,
}

/// Per-connection state retained by the same serving future, not a new owner.
#[derive(Default)]
struct ConnectionSetup {
    readiness: Option<Arc<AtomicBool>>,
    connection_readiness: Option<Arc<AtomicBool>>,
    admitted: Option<Admitted>,
    handshake: Option<HandshakeFrames>,
    native_close: Option<Arc<dyn SuccessorAdmission>>,
    cancellation: Option<(usize, RequestCancellation)>,
    mapping_capture: Option<(reverie::MappingCaptureRun, i32)>,
    tool_activation: Option<ActivationConnection>,
}

/// Actual error outcome of cancelling a received, admitted request. Fields are
/// constructed only by the connection loop, not from the host's numeric intent.
/// This is observation data, never execution or process-retirement authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelledRequest {
    connection: usize,
    process_id: i32,
    sender: i32,
    request: usize,
}
impl CancelledRequest {
    /// Actual server connection ordinal whose task was joined.
    pub fn connection(&self) -> usize {
        self.connection
    }
    /// Process authenticated by this connection's existing admission.
    pub fn process_id(&self) -> i32 {
        self.process_id
    }
    /// Sender of the actual received request, checked against admission.
    pub fn sender(&self) -> i32 {
        self.sender
    }
    /// One-based request ordinal within that actual connection.
    pub fn request(&self) -> usize {
        self.request
    }
}
impl std::fmt::Display for CancelledRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "owned admitted RPC cancelled without response: connection={} process={} sender={} request={}",
            self.connection, self.process_id, self.sender, self.request
        )
    }
}
impl std::error::Error for CancelledRequest {}

#[derive(Default)]
struct RequestCancellationState {
    process: Option<i32>,
    // Appended ONLY by the server after JoinSet::join_next yields the actual
    // completed connection task. Completion inside a task is not a join receipt.
    joined: Vec<CancelledRequest>,
    overflow: bool,
    idle_connections: Vec<usize>,
    drained: bool,
}

/// A drain of this serving owner's original task set, after accepts stopped.
/// Empty request outcomes are valid only as drain data, not as a canceled RPC.
#[derive(Clone, Debug)]
pub struct CancellationDrain {
    process_id: i32,
    cancelled_requests: Vec<CancelledRequest>,
    idle_connections: Vec<usize>,
}
impl CancellationDrain {
    /// Actual PID requested by this owner's explicit cancellation intent.
    pub fn process_id(&self) -> i32 {
        self.process_id
    }
    /// Actual pending-dispatch cancellation errors whose tasks were joined.
    pub fn cancelled_requests(&self) -> &[CancelledRequest] {
        &self.cancelled_requests
    }
    /// Actual admitted framing/handshake-idle connections canceled and joined.
    pub fn idle_connections(&self) -> &[usize] {
        &self.idle_connections
    }
}

/// Explicit control of this server's existing owned request futures. Creating
/// or requesting this handle proves neither process death nor execution safety.
/// The embedding owner must establish its own cancellation authority. It must
/// keep the sole server future running until actual joined outcomes are read.
#[derive(Clone, Default)]
pub struct RequestCancellation {
    state: Arc<Mutex<RequestCancellationState>>,
    changed: Arc<Notify>,
}
impl RequestCancellation {
    /// Request cancellation once. A dead-peer error which occurred earlier is
    /// never cleared or relabelled by this operation. No matching request means
    /// no outcome; the caller's ordinary deadline must fail that case. Intent
    /// also stops further accepts by this serving owner; this is a drain, not a
    /// per-request retry or a replacement admission mechanism.
    pub fn request(&self, process_id: i32) -> Result<(), RpcError> {
        if process_id <= 0 {
            return Err(
                std::io::Error::other("RPC cancellation requires positive admitted PID").into(),
            );
        }
        let mut state = self.state.lock().unwrap();
        if state.process.is_some() {
            return Err(std::io::Error::other("RPC cancellation already requested").into());
        }
        state.process = Some(process_id);
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }
    async fn requested_any(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.lock().unwrap().process.is_some() {
                return;
            }
            notified.await;
        }
    }
    async fn requested(&self, process_id: i32) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state.lock().unwrap().process == Some(process_id) {
                return;
            }
            notified.await;
        }
    }
    fn joined(&self, connection: CancelledConnection) {
        let mut state = self.state.lock().unwrap();
        if state.joined.len() + state.idle_connections.len() == 64 {
            state.overflow = true;
        } else {
            match connection {
                CancelledConnection::Request(request) => state.joined.push(request),
                CancelledConnection::Idle {
                    connection,
                    process_id,
                } => {
                    if state.process != Some(process_id) {
                        state.overflow = true;
                    } else {
                        state.idle_connections.push(connection);
                    }
                }
            }
        }
        drop(state);
        self.changed.notify_waiters();
    }
    fn drained(&self) {
        self.state.lock().unwrap().drained = true;
        self.changed.notify_waiters();
    }
    /// Wait until accepts stopped and this owner's original JoinSet is empty
    /// because every connection task was actually joined. No RPC is invented
    /// when there were zero tasks, or only read-idle connections.
    pub async fn wait_for_drain(&self) -> Result<CancellationDrain, RpcError> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state.lock().unwrap();
                if state.overflow {
                    return Err(
                        std::io::Error::other("RPC cancelled outcome capacity exhausted").into(),
                    );
                }
                if state.drained {
                    let process_id = state.process.ok_or_else(|| {
                        std::io::Error::other("RPC drain lacks cancellation intent")
                    })?;
                    return Ok(CancellationDrain {
                        process_id,
                        cancelled_requests: state.joined.clone(),
                        idle_connections: state.idle_connections.clone(),
                    });
                }
            }
            notified.await;
        }
    }
    /// Wait for real connection-task join, not simply for intent publication or
    /// dropping an initializer observer future. No timeout is hidden here.
    pub async fn wait_for_joined(&self) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.state.lock().unwrap().joined.is_empty() {
                return;
            }
            notified.await;
        }
    }
    /// Actual joined cancellation errors, or an explicit bounded-storage failure.
    pub fn joined_outcomes(&self) -> Result<Vec<CancelledRequest>, RpcError> {
        let state = self.state.lock().unwrap();
        if state.overflow {
            return Err(std::io::Error::other("RPC cancelled outcome capacity exhausted").into());
        }
        Ok(state.joined.clone())
    }
}

// Private control-flow result, never recovered from a public/cloneable error
// payload. An admission/handshake hook may return any RpcError (even one wrapping
// an old CancelledRequest); that remains Rpc and cannot mint cancellation.
enum ConnectionError {
    Rpc(RpcError),
    Cancelled(CancelledConnection),
}
enum CancelledConnection {
    Request(CancelledRequest),
    Idle { connection: usize, process_id: i32 },
}
impl From<RpcError> for ConnectionError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}
impl From<std::io::Error> for ConnectionError {
    fn from(error: std::io::Error) -> Self {
        Self::Rpc(error.into())
    }
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
    fn cancelled(&mut self, outcome: CancelledConnection) -> CancelledConnection {
        // Distinct error completion, not normal reply success. Its typed value
        // is retained only when the sole serving owner actually joins this task.
        // Other connection issues already recorded are never cleared here.
        self.completed = true;
        if let Some(monitor) = &self.monitor {
            monitor.reserved.fetch_sub(1, Ordering::Release);
        }
        outcome
    }

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
        match result {
            Err(error) if !matches!(error, RpcError::Closed) => {
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
            _ => {}
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
            cleanup_path: true,
            readiness: None,
            connection_readiness: None,
            connections: ConnectionMonitor::new(),
            issues: None,
            admission: None,
            initial_image: None,
            native_successor: None,
            mapping_capture: None,
            tool_activation: None,
        })
    }

    /// Consume an already-bound ordinary listener without unlinking/rebinding.
    ///
    /// This preserves the exact listener FD and filesystem socket inode for a
    /// common container's retained mount source. Call only inside the actual
    /// Tokio reactor, after its common namespace setup; the caller bound the
    /// listener before workers existed and owns its path/directory through all
    /// connection drains. This server closes the listener but deliberately
    /// leaves path retirement to that original owner.
    pub fn from_prebound(
        listener: std::os::unix::net::UnixListener,
        global: Arc<G>,
        config: G::Config,
    ) -> Result<Self, RpcError> {
        let path = listener
            .local_addr()?
            .as_pathname()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "prebound RPC listener has no filesystem path",
                )
            })?
            .to_path_buf();
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;
        Ok(Self {
            global,
            config,
            listener,
            path,
            cleanup_path: false,
            readiness: None,
            connection_readiness: None,
            connections: ConnectionMonitor::new(),
            issues: None,
            admission: None,
            initial_image: None,
            native_successor: None,
            mapping_capture: None,
            tool_activation: None,
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
            cleanup_path: true,
            readiness,
            connection_readiness,
            connections: ConnectionMonitor::new(),
            issues: None,
            admission: None,
            initial_image: None,
            native_successor: None,
            mapping_capture: None,
            tool_activation: None,
        })
    }

    /// Install only a launcher's existing enabled mapping-capture containment
    /// owner. Authorization uses the accepted socket's physical peer, never a
    /// Tool-supplied numeric sender. No connection or cleanup policy is enabled.
    pub fn mapping_capture(mut self, run: reverie::MappingCaptureRun) -> Self {
        self.mapping_capture = Some(run);
        self
    }

    /// Require explicit root-bound Tool activation and completion receipts.
    ///
    /// Bind `run` to the actual child before polling this server. Configuration
    /// readers and ordinary RPC retain their existing behavior but provide no
    /// activation credit. The launcher must join `run.completed()` with the
    /// actual waited normal exit. This does not change legacy readiness flags.
    pub fn tool_activation(mut self, run: ActivationRun) -> Self {
        self.tool_activation = Some(run);
        self
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
        self.native_successor = None;
        Ok(())
    }

    /// Explicitly serve both InitialImage and successor-v1 requests.
    ///
    /// Both hooks are launcher-owned policies, with the same actual process
    /// watcher and retained issue monitor required by InitialImage admission.
    /// Only the two configured magics/versions are accepted; there is no
    /// config-first fallback. Each RPC sender stays bound to its accepted
    /// socket's admitted process for the lifetime of this single-thread route.
    pub fn set_native_image_admission(
        &mut self,
        initial: Arc<dyn InitialImageAdmission>,
        successor: Arc<dyn SuccessorAdmission>,
    ) -> Result<(), RpcError> {
        self.set_initial_image_admission(initial)?;
        self.native_successor = Some(successor);
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
        self.serve_until(std::future::pending()).await
    }

    /// Serve until explicit owner shutdown, then cancel and join every owned
    /// connection before returning. Listener errors take the same joined path.
    /// Cancelling this future itself still uses JoinSet's abort-on-drop; callers
    /// needing completion must retain and await this cooperative owner.
    pub async fn serve_until<F>(self, shutdown: F) -> Result<(), RpcError>
    where
        F: std::future::Future<Output = ()>,
    {
        self.serve_owned(shutdown, None).await
    }

    /// Same serving owner, admission, framing and JoinSet as serve_until. The
    /// opt-in handle can cancel an admitted request while receive_rpc is pending;
    /// every other failure and normal response retains its original behavior.
    pub async fn serve_until_with_request_cancellation<F>(
        self,
        shutdown: F,
        cancellation: RequestCancellation,
    ) -> Result<(), RpcError>
    where
        F: std::future::Future<Output = ()>,
    {
        self.serve_owned(shutdown, Some(cancellation)).await
    }

    async fn serve_owned<F>(
        self,
        shutdown: F,
        cancellation: Option<RequestCancellation>,
    ) -> Result<(), RpcError>
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::pin!(shutdown);
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-170): Review connection cancellation on server shutdown.
        let mut connections = tokio::task::JoinSet::<Option<CancelledConnection>>::new();
        let mut connection = 0usize;
        let mut accepting = true;
        let result = async {
            loop {
                if let (true, Some(cancellation)) =
                    (!accepting && connections.is_empty(), &cancellation)
                {
                    cancellation.drained();
                }
                let (stream, _addr) = tokio::select! {
                    biased;
                    () = &mut shutdown => return Ok(()),
                    () = async {
                        if let Some(cancellation) = &cancellation { cancellation.requested_any().await; }
                    }, if accepting && cancellation.is_some() => {
                        // Same owner stops new admission before processing any
                        // completed cancellation or accepting another connection.
                        accepting = false;
                        continue;
                    },
                    result = self.listener.accept(), if accepting => result?,
                    joined = connections.join_next(), if !connections.is_empty() => {
                        if let (Some(Ok(Some(outcome))), Some(cancellation)) =
                            (joined, &cancellation)
                        {
                            cancellation.joined(outcome);
                        }
                        continue;
                    },
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
                let native_successor = self.native_successor.clone();
                let request_cancellation = cancellation.clone();
                let mapping_capture = self.mapping_capture.clone();
                let activation_run = self.tool_activation.clone();
                connections.spawn(async move {
                    let _connection_guard = connection_guard;
                    let future = async move {
                        let mut stream = stream;
                        let tool_activation = tool_activation_peer(activation_run.as_ref(), &stream)?;
                        let result = async {
                            let mapping_capture = mapping_capture_peer(mapping_capture, &stream)?;
                            let admitted = admit_connection(admission.as_ref(), &stream)?;
                            let cancellation = request_cancellation.map(|cancel| (connection, cancel));
                            let config_bytes = match initial_image {
                                Some(hook) => Some(connection_io(
                                    image_handshake(&mut stream, admitted, &hook,
                                        native_successor.as_deref()),
                                    admitted, cancellation.as_ref()).await?),
                                None => None,
                            };
                            serve_connection_owned(
                                global,
                                config,
                                stream,
                                ConnectionSetup {
                                    readiness,
                                    connection_readiness,
                                    admitted,
                                    handshake: config_bytes,
                                    native_close: native_successor,
                                    cancellation,
                                    mapping_capture,
                                    tool_activation,
                                },
                            )
                            .await
                        }.await;
                        if result.is_err() {
                            if let Some(run) = &activation_run {
                                run.fail("Tool activation connection setup or serving failed");
                            }
                        }
                        result
                    };
                    if retain_issues {
                        let mut future = std::pin::pin!(future);
                        let result =
                            std::future::poll_fn(|context| {
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
                            Ok(Err(ConnectionError::Cancelled(outcome))) => {
                                return Some(issue_guard.cancelled(outcome));
                            }
                            Ok(Err(ConnectionError::Rpc(error))) => issue_guard.complete(Err(error)),
                            Ok(Ok(())) => issue_guard.complete(Ok(())),
                            Err(payload) => issue_guard.panic(payload),
                        }
                    } else {
                        match future.await {
                            Err(ConnectionError::Cancelled(outcome)) => {
                                return Some(issue_guard.cancelled(outcome));
                            }
                            Err(ConnectionError::Rpc(error)) => issue_guard.complete(Err(error)),
                            Ok(()) => issue_guard.complete(Ok(())),
                        }
                    }
                    None
                });
            }
        }
        .await;
        connections.abort_all();
        while let Some(joined) = connections.join_next().await {
            if let (Ok(Some(outcome)), Some(cancellation)) = (joined, &cancellation) {
                cancellation.joined(outcome);
            }
        }
        if result.is_err() {
            if let Some(run) = &self.tool_activation {
                run.fail("Tool activation serving owner failed");
            }
        }
        result
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
            let tool_activation = tool_activation_peer(self.tool_activation.as_ref(), &stream)?;
            let mapping_capture = mapping_capture_peer(self.mapping_capture.clone(), &stream)?;
            let admitted = admit_connection(self.admission.as_ref(), &stream)?;
            let config = self.config.clone();
            let config_bytes = match &self.initial_image {
                Some(hook) => Some(
                    image_handshake(
                        &mut stream,
                        admitted,
                        hook,
                        self.native_successor.as_deref(),
                    )
                    .await?,
                ),
                None => None,
            };
            serve_connection_inner(
                self.global.clone(),
                config,
                stream,
                ConnectionSetup {
                    readiness: self.readiness.clone(),
                    connection_readiness: self.connection_readiness.clone(),
                    admitted,
                    handshake: config_bytes,
                    native_close: self.native_successor.clone(),
                    cancellation: None,
                    mapping_capture,
                    tool_activation,
                },
            )
            .await
        }
        .await;
        if result.is_err() {
            if let Some(run) = &self.tool_activation {
                run.fail("Tool activation connection setup or serving failed");
            }
        }
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
        if self.cleanup_path {
            let _ = std::fs::remove_file(&self.path);
        }
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
    serve_connection_inner(global, config, stream, ConnectionSetup::default()).await
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
    serve_connection_inner(global, config, stream, ConnectionSetup::default()).await
}

/// Admission has already installed the normal process watch. A second pidfd
/// comes from this exact socket; the watcher continues owning its first one.
async fn image_handshake(
    stream: &mut UnixStream,
    admitted: Option<Admitted>,
    initial: &InitialImageSetup,
    successor: Option<&dyn SuccessorAdmission>,
) -> Result<HandshakeFrames, RpcError> {
    let Some(successor) = successor else {
        return Ok(HandshakeFrames {
            config: initial_image_handshake(
                stream,
                admitted,
                initial.admission.as_ref(),
                initial.config_bytes.clone(),
            )
            .await?,
            successor_state: None,
            strict_sender: false,
            native_image: None,
        });
    };
    let admitted = admitted.ok_or_else(|| {
        crate::successor::invalid("native image connection has no watched process admission")
    })?;
    let peer = peer_pidfd(stream)?;
    let request = read_message(stream, crate::successor::MAX_CONTROL_LEN)
        .await
        .map_err(|error| match error {
            RpcError::Closed => crate::successor::invalid("native image redemption is missing"),
            other => other,
        })?;
    let digest = crate::initial_image::config_digest(&initial.config_bytes);
    let (successor_state, native_image) =
        if request.starts_with(&crate::initial_image::REQUEST_MAGIC) {
            let redemption = crate::initial_image::decode_redemption(&request)?;
            initial
                .admission
                .redeem(peer, admitted, redemption, digest)?;
            write_message(stream, &crate::initial_image::encode_ack(digest)).await?;
            (None, crate::successor::NativeImageConnection::Initial)
        } else {
            // The exact successor decoder refuses every unknown magic/version,
            // malformed length, empty ticket and trailing byte. Never fall back.
            let redemption = crate::successor::decode_redemption(&request)?;
            if redemption.expected.config != digest {
                return Err(crate::successor::invalid(
                    "successor expected Config differs from run",
                ));
            }
            let state = successor.redeem(peer, admitted, redemption)?;
            crate::successor::check_state(&state, redemption.expected.state)?;
            write_message(stream, &crate::successor::encode_ack(redemption)).await?;
            (
                Some(state),
                crate::successor::NativeImageConnection::Successor {
                    ticket: redemption.ticket.to_vec(),
                },
            )
        };
    Ok(HandshakeFrames {
        config: initial.config_bytes.clone(),
        successor_state,
        strict_sender: true,
        native_image: Some(native_image),
    })
}

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

// Cancel an admitted connection which is waiting for framing/handshake IO, without
// pretending that it had dispatched a GlobalTool request. Once explicit intent
// is published, no further handshake/frame IO is polled. Earlier returned IO
// errors retain the ordinary Rpc result and issue path; none is reclassified.
async fn connection_io<T>(
    io: impl std::future::Future<Output = Result<T, RpcError>>,
    admitted: Option<Admitted>,
    cancellation: Option<&(usize, RequestCancellation)>,
) -> Result<T, ConnectionError> {
    if let (Some(owner), Some((connection, cancel))) = (admitted, cancellation) {
        tokio::select! {
            biased;
            () = cancel.requested(owner.process_id) => Err(ConnectionError::Cancelled(
                CancelledConnection::Idle { connection: *connection, process_id: owner.process_id })),
            result = io => result.map_err(ConnectionError::Rpc),
        }
    } else {
        io.await.map_err(ConnectionError::Rpc)
    }
}

async fn serve_connection_inner<G, S>(
    global: Arc<G>,
    config: G::Config,
    stream: S,
    setup: ConnectionSetup,
) -> Result<(), RpcError>
where
    G: GlobalTool,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // All ordinary callers pass cancellation=None; preserve their public result
    // type without granting any interpretation to arbitrary RpcError payloads.
    match serve_connection_owned(global, config, stream, setup).await {
        Ok(()) => Ok(()),
        Err(ConnectionError::Rpc(error)) => Err(error),
        Err(ConnectionError::Cancelled(_)) => Err(std::io::Error::other(
            "unexpected request cancellation in ordinary connection",
        )
        .into()),
    }
}

async fn serve_connection_owned<G, S>(
    global: Arc<G>,
    config: G::Config,
    stream: S,
    mut setup: ConnectionSetup,
) -> Result<(), ConnectionError>
where
    G: GlobalTool,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut activation = setup.tool_activation.take();
    let result =
        serve_connection_requests(global, config, stream, setup, activation.as_mut()).await;
    if result.is_err() {
        if let Some(activation) = &activation {
            activation.fail();
        }
    }
    result
}

async fn serve_connection_requests<G, S>(
    global: Arc<G>,
    config: G::Config,
    mut stream: S,
    setup: ConnectionSetup,
    mut activation: Option<&mut ActivationConnection>,
) -> Result<(), ConnectionError>
where
    G: GlobalTool,
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let ConnectionSetup {
        readiness,
        connection_readiness,
        mut admitted,
        handshake,
        native_close,
        cancellation,
        mapping_capture,
        tool_activation: _,
    } = setup;
    let cancellation_admitted = admitted;
    let mut request_number = 0usize;
    // space (it is a separate process), so the coordinator sends it first.
    //
    // NOTE: `G::Request`/`G::Response` are `Send` but not `Sync`, so we always
    // serialize/deserialize at this call site (owned bytes only) rather than
    // passing a `&Request`/`&Response` into an async fn. Holding such a borrow
    // across an await would make this future non-`Send` and break
    // `tokio::spawn`.
    let config_bytes = match &handshake {
        Some(frames) => std::borrow::Cow::Borrowed(frames.config.as_slice()),
        None => std::borrow::Cow::Owned(encode(&config)?),
    };
    if let Some(activation) = activation.as_deref_mut() {
        activation.config(&config_bytes);
    }
    connection_io(
        write_message(&mut stream, &config_bytes),
        cancellation_admitted,
        cancellation.as_ref(),
    )
    .await?;
    if let Some(state) = handshake
        .as_ref()
        .and_then(|frames| frames.successor_state.as_ref())
    {
        connection_io(
            write_message(&mut stream, state),
            cancellation_admitted,
            cancellation.as_ref(),
        )
        .await?;
    }
    let strict_sender = handshake
        .as_ref()
        .is_some_and(|frames| frames.strict_sender);
    if let Some(readiness) = &connection_readiness {
        readiness.store(true, Ordering::Release);
    }

    loop {
        let request_bytes = match connection_io(
            read_message(&mut stream, DEFAULT_MAX_FRAME_LEN),
            cancellation_admitted,
            cancellation.as_ref(),
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(ConnectionError::Rpc(RpcError::Closed)) => {
                if let Some(activation) = activation.as_deref_mut() {
                    activation.closed()?;
                }
                if strict_sender {
                    let hook = native_close.as_ref().ok_or_else(|| {
                        crate::successor::invalid("native stream lost its lifecycle owner")
                    })?;
                    let image = handshake
                        .as_ref()
                        .and_then(|frames| frames.native_image.as_ref())
                        .ok_or_else(|| {
                            crate::successor::invalid("native stream lost its image incarnation")
                        })?;
                    hook.connection_closed(
                        admitted.ok_or_else(|| {
                            crate::successor::invalid("native stream lost its watched sender")
                        })?,
                        image,
                    )?;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        // The existing mapping-capture family has the same reserved negative
        // Tid prefix. Its full eight-byte discriminator is checked first; all
        // other reserved frames still reach activation rejection, never G.
        if let Some(token) = crate::mapping_capture::decode_request(&request_bytes)? {
            if let Some(activation) = activation.as_deref() {
                activation.before_application()?;
            }
            let authorized = mapping_capture
                .as_ref()
                .is_some_and(|(run, peer)| run.authorize(token, *peer));
            let response = crate::mapping_capture::reply(&request_bytes, authorized);
            connection_io(
                write_message(&mut stream, &response),
                cancellation_admitted,
                cancellation.as_ref(),
            )
            .await?;
            continue;
        }
        // Reserve the whole control family before ANY application decode,
        // including legacy G::Request=(), which can accept trailing bytes.
        if let Some(control) = crate::tool_activation::decode_request(&request_bytes)? {
            let activation = activation.as_deref().ok_or_else(|| {
                crate::tool_activation::invalid("Tool activation control on a legacy RPC server")
            })?;
            let pending = activation.stage(control)?;
            connection_io(
                write_message(&mut stream, &control.acknowledgement()),
                cancellation_admitted,
                cancellation.as_ref(),
            )
            .await?;
            pending.commit()?;
            continue;
        }
        if let Some(activation) = activation.as_deref() {
            activation.before_application()?;
        }
        let RequestEnvelope { from, request } =
            decode::<RequestEnvelope<G::Request>>(&request_bytes)?;
        let _application = activation
            .as_deref()
            .map(|activation| activation.application(from.as_raw()))
            .transpose()?;
        // Combined native-image admission binds every RPC sender to this
        // accepted process. Legacy/InitialImage-only admission retains its
        // first-request check; a forked child reconnects before sending.
        let request_owner = if strict_sender {
            admitted
        } else {
            admitted.take()
        };
        match request_owner {
            Some(Admitted { process_id }) if from.as_raw() != process_id => {
                let which = if strict_sender { "a" } else { "its first" };
                return Err(RpcError::Io(std::io::Error::other(format!(
                    "connection admitted for process {process_id} sent {which} request as {}",
                    from.as_raw()
                )))
                .into());
            }
            _ => {}
        }
        if let Some(readiness) = &readiness {
            readiness.store(true, Ordering::Release);
        }
        let response = if let (Some((connection, cancel)), Some(owner)) =
            (&cancellation, cancellation_admitted)
        {
            request_number = request_number
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("RPC request identity exhausted"))?;
            if owner.process_id != from.as_raw() {
                return Err(std::io::Error::other(
                    "RPC cancellation sender differs from admitted process",
                )
                .into());
            }
            // This select owns the actual receive_rpc future. Returning the
            // typed error drops it before the task can encode/write a response.
            // A host Pause remains held until this task has actually joined.
            tokio::select! {
                biased;
                () = cancel.requested(owner.process_id) => {
                    return Err(ConnectionError::Cancelled(CancelledConnection::Request(CancelledRequest {
                        connection: *connection, process_id: owner.process_id,
                        sender: from.as_raw(), request: request_number,
                    })));
                }
                response = global.receive_rpc(from, request) => response,
            }
        } else {
            global.receive_rpc(from, request).await
        };
        let response_bytes = encode(&response)?;
        connection_io(
            write_message(&mut stream, &response_bytes),
            cancellation_admitted,
            cancellation.as_ref(),
        )
        .await?;
    }
}

// Keep the tracing dependency optional/soft: the reverie tree uses `tracing`
// widely, but this crate stays lean. We only emit to stderr on an unexpected
// connection error so a coordinator operator can see it.
fn tracing_disconnect(e: &RpcError) {
    eprintln!("reverie-rpc-transport: guest connection ended with error: {e}");
}

#[cfg(test)]
mod tool_activation_tests {
    use std::pin::Pin;
    use std::sync::atomic::AtomicU64;
    use std::task::Context;
    use std::task::Poll;
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;
    use tokio::io::ReadBuf;

    use super::*;
    use crate::tool_activation::ExitOrigin;
    use crate::tool_activation::FinishedReceipt;
    use crate::tool_activation::ToolControl;

    const LIMIT: Duration = Duration::from_secs(2);
    const CONFIG: u64 = 0x1234_5678_9abc_def0;

    #[derive(Default)]
    struct CountingGlobal {
        requests: AtomicUsize,
    }

    #[reverie::global_tool]
    impl GlobalTool for CountingGlobal {
        type Request = ();
        type Response = u64;
        type Config = u64;

        async fn receive_rpc(&self, _from: reverie::Tid, _request: ()) -> u64 {
            self.requests.fetch_add(1, Ordering::SeqCst) as u64 + 1
        }
    }

    fn root() -> i32 {
        std::process::id() as i32
    }

    async fn bounded<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(LIMIT, future)
            .await
            .expect("Tool transport fixture timed out")
    }

    fn run() -> ActivationRun {
        let run = ActivationRun::new();
        run.bind_root(root()).unwrap();
        run
    }

    fn server(run: Option<ActivationRun>) -> (RpcServer<CountingGlobal>, Arc<CountingGlobal>) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-tool-activation-{}-{}.sock",
            root(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let global = Arc::new(CountingGlobal::default());
        let server = RpcServer::bind_exclusive(path, global.clone(), CONFIG).unwrap();
        (
            match run {
                Some(run) => server.tool_activation(run),
                None => server,
            },
            global,
        )
    }

    async fn config(stream: &mut UnixStream) -> crate::initial_image::ConfigDigest {
        let bytes = read_message(stream, DEFAULT_MAX_FRAME_LEN).await.unwrap();
        assert_eq!(crate::codec::decode_exact::<u64>(&bytes).unwrap(), CONFIG);
        crate::initial_image::config_digest(&bytes)
    }

    async fn control(stream: &mut UnixStream, request: ToolControl) -> Result<(), RpcError> {
        write_message(stream, &request.encode()).await?;
        let bytes = read_message(stream, crate::tool_activation::FRAME_LEN).await?;
        request.check_ack(&bytes)
    }

    fn finished(digest: crate::initial_image::ConfigDigest) -> ToolControl {
        ToolControl::Finished {
            digest,
            receipt: FinishedReceipt::explicit_exit(23, 231, ExitOrigin::Deferred).unwrap(),
        }
    }

    async fn application(stream: &mut UnixStream, sender: i32) -> Result<u64, RpcError> {
        let bytes = encode(&RequestEnvelope {
            from: reverie::Tid::from_raw(sender),
            request: (),
        })?;
        write_message(stream, &bytes).await?;
        decode(&read_message(stream, DEFAULT_MAX_FRAME_LEN).await?)
    }

    #[tokio::test]
    async fn actual_primary_allows_startup_and_exit_hook_rpc_with_exact_receipt() {
        let run = run();
        let (server, global) = server(Some(run.clone()));
        let path = server.path().to_owned();
        let client_run = run.clone();
        let client = tokio::task::spawn_blocking(move || {
            let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
            stream.set_read_timeout(Some(LIMIT)).unwrap();
            stream.set_write_timeout(Some(LIMIT)).unwrap();
            let bytes = crate::read_config_frame(&mut stream).unwrap();
            let config: u64 = crate::codec::decode_exact(&bytes).unwrap();
            assert_eq!(config, CONFIG);
            let digest = crate::initial_image::config_digest(&bytes);
            // Ordinary Config and application requests are not activation.
            assert!(client_run.completed().is_err());
            {
                let rpc = crate::BlockingRpcClient::<CountingGlobal>::from_borrowed_stream(
                    &mut stream,
                    reverie::Tid::from_raw(root()),
                    &config,
                );
                assert_eq!(rpc.try_send_rpc(()).unwrap(), 1);
            }
            assert!(client_run.completed().is_err());
            crate::exchange_tool_control(&mut stream, &ToolControl::Claim { digest }).unwrap();
            // A real startup hook can use this same G before Started.
            {
                let rpc = crate::BlockingRpcClient::<CountingGlobal>::from_borrowed_stream(
                    &mut stream,
                    reverie::Tid::from_raw(root()),
                    &config,
                );
                assert_eq!(rpc.try_send_rpc(()).unwrap(), 2);
            }
            crate::exchange_tool_control(&mut stream, &ToolControl::Started { digest }).unwrap();
            assert!(client_run.completed().is_err());
            // Likewise, awaited consuming-hook RPC precedes Finished.
            {
                let rpc = crate::BlockingRpcClient::<CountingGlobal>::from_borrowed_stream(
                    &mut stream,
                    reverie::Tid::from_raw(root()),
                    &config,
                );
                assert_eq!(rpc.try_send_rpc(()).unwrap(), 3);
            }
            crate::exchange_tool_control(&mut stream, &finished(digest)).unwrap();
        });
        tokio::time::timeout(LIMIT, server.serve_one())
            .await
            .unwrap()
            .unwrap();
        client.await.unwrap();
        let receipt = run.completed().unwrap();
        assert_eq!(receipt.exit_code(), 23);
        assert_eq!(receipt.syscall(), 231);
        assert_eq!(
            receipt.scope(),
            crate::tool_activation::ExitScope::ExitGroup
        );
        assert_eq!(receipt.origin(), ExitOrigin::Deferred);
        assert_eq!(global.requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn mapping_capture_and_activation_share_the_primary_without_cross_decoding() {
        let run = run();
        let (server, global) = server(Some(run.clone()));
        let request = crate::mapping_capture::encode_request(reverie::MappingCaptureToken {
            nonce: 1,
            identity: reverie::MappingCaptureIdentity {
                process: root(),
                thread: root(),
                address_space: [1, 2],
                private_owner: [3, 4, 5, 6],
                private_version: 7,
            },
        })
        .unwrap();
        assert_eq!(&request[..8], &[255, 255, 255, 255, b'M', b'C', 1, 0]);
        let client = async {
            let mut stream = UnixStream::connect(server.path()).await.unwrap();
            let digest = config(&mut stream).await;
            control(&mut stream, ToolControl::Claim { digest })
                .await
                .unwrap();
            for started in [false, true] {
                if started {
                    control(&mut stream, ToolControl::Started { digest })
                        .await
                        .unwrap();
                }
                write_message(&mut stream, &request).await.unwrap();
                let response = read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)
                    .await
                    .unwrap();
                // No mapping owner is installed: preserve its exact framed
                // refusal and the live primary, without dispatching to G.
                assert_eq!(response, crate::mapping_capture::reply(&request, false));
                assert!(!crate::mapping_capture::is_ack(&request, &response));
                assert_eq!(
                    application(&mut stream, root()).await.unwrap(),
                    u64::from(started) + 1
                );
            }
            control(&mut stream, finished(digest)).await.unwrap();
        };
        let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
        result.unwrap();
        assert_eq!(run.completed().unwrap().exit_code(), 23);
        assert_eq!(global.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn temporary_config_readers_do_not_claim_and_can_close() {
        let run = run();
        let (server, global) = server(Some(run.clone()));
        let path = server.path().to_owned();
        for _ in 0..2 {
            let client = async {
                let mut stream = UnixStream::connect(&path).await.unwrap();
                config(&mut stream).await;
            };
            let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
            result.unwrap();
            assert!(run.completed().is_err());
        }
        let client = async {
            let mut stream = UnixStream::connect(&path).await.unwrap();
            let digest = config(&mut stream).await;
            control(&mut stream, ToolControl::Claim { digest })
                .await
                .unwrap();
            control(&mut stream, ToolControl::Started { digest })
                .await
                .unwrap();
            control(&mut stream, finished(digest)).await.unwrap();
        };
        let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
        result.unwrap();
        assert_eq!(run.completed().unwrap().exit_code(), 23);
        assert_eq!(global.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unbound_or_rebound_root_cannot_serve_config() {
        for rebound in [false, true] {
            let run = ActivationRun::new();
            if rebound {
                run.bind_root(root()).unwrap();
                assert!(run.bind_root(root()).is_err());
            }
            let (server, global) = server(Some(run.clone()));
            let client = async {
                let mut stream = UnixStream::connect(server.path()).await.unwrap();
                assert!(
                    read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)
                        .await
                        .is_err()
                );
            };
            let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
            assert!(result.is_err());
            assert!(run.bind_root(root()).is_err());
            assert!(run.completed().is_err());
            assert_eq!(global.requests.load(Ordering::SeqCst), 0);
        }
    }

    fn invalid_controls(digest: crate::initial_image::ConfigDigest) -> Vec<Vec<u8>> {
        let claim = ToolControl::Claim { digest }.encode();
        let mut result = vec![claim[..4].to_vec(), claim[..47].to_vec()];
        let mut trailing = claim.to_vec();
        trailing.push(0);
        result.push(trailing);
        for (index, value) in [
            (4, b'X'),
            (6, 1),
            (6, 3),
            (7, 0),
            (7, 2),
            (7, 4),
            (7, 6),
            (7, 7),
            (40, 1),
        ] {
            let mut bytes = claim.to_vec();
            bytes[index] = value;
            result.push(bytes);
        }
        for (index, value) in [
            (40, 0),
            (40, 2),
            (42, 0),
            (42, 1),
            (42, 3),
            (43, 0),
            (43, 3),
            (44, 1),
            (47, 60),
        ] {
            let mut bytes = finished(digest).encode().to_vec();
            bytes[index] = value;
            result.push(bytes);
        }
        result
    }

    #[tokio::test]
    async fn malformed_reserved_frames_are_sticky_and_never_unit_requests() {
        let digest = crate::initial_image::config_digest(&encode(&CONFIG).unwrap());
        for enabled in [false, true] {
            let mut frames = invalid_controls(digest);
            // All six valid kinds are reserved even for a legacy unit-request G.
            if !enabled {
                for request in [
                    ToolControl::Claim { digest },
                    ToolControl::Started { digest },
                    finished(digest),
                ] {
                    frames.push(request.encode().to_vec());
                    frames.push(request.acknowledgement().to_vec());
                }
            }
            for bytes in frames {
                let run = run();
                let (server, global) = server(enabled.then(|| run.clone()));
                let client = async {
                    let mut stream = UnixStream::connect(server.path()).await.unwrap();
                    config(&mut stream).await;
                    write_message(&mut stream, &bytes).await.unwrap();
                    assert!(
                        read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)
                            .await
                            .is_err()
                    );
                };
                let (result, ()) =
                    bounded(async { tokio::join!(server.serve_one(), client) }).await;
                assert!(result.is_err());
                assert!(run.completed().is_err());
                if enabled {
                    assert!(run.accepted(root()).is_err());
                }
                assert_eq!(global.requests.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn generic_legacy_stream_rejects_reserved_control_before_unit_dispatch() {
        let global = Arc::new(CountingGlobal::default());
        let (server, mut client) = tokio::io::duplex(256);
        let request = ToolControl::Claim { digest: [0; 32] }.encode();
        let future = serve_stream(global.clone(), CONFIG, server);
        let client = async {
            read_message(&mut client, DEFAULT_MAX_FRAME_LEN)
                .await
                .unwrap();
            write_message(&mut client, &request).await.unwrap();
            assert!(
                read_message(&mut client, DEFAULT_MAX_FRAME_LEN)
                    .await
                    .is_err()
            );
        };
        let (result, ()) = bounded(async { tokio::join!(future, client) }).await;
        assert!(result.is_err());
        assert_eq!(global.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicate_out_of_order_wrong_digest_sender_and_post_finished_refuse() {
        for scenario in 0..10 {
            let run = run();
            let (server, global) = server(Some(run.clone()));
            let client = async {
                let mut stream = UnixStream::connect(server.path()).await.unwrap();
                let digest = config(&mut stream).await;
                if scenario == 0 {
                    assert!(
                        control(&mut stream, ToolControl::Started { digest })
                            .await
                            .is_err()
                    );
                    return;
                }
                if scenario == 1 {
                    assert!(control(&mut stream, finished(digest)).await.is_err());
                    return;
                }
                if scenario == 2 {
                    let mut wrong = digest;
                    wrong[0] ^= 1;
                    assert!(
                        control(&mut stream, ToolControl::Claim { digest: wrong })
                            .await
                            .is_err()
                    );
                    return;
                }
                control(&mut stream, ToolControl::Claim { digest })
                    .await
                    .unwrap();
                match scenario {
                    3 => assert!(
                        control(&mut stream, ToolControl::Claim { digest })
                            .await
                            .is_err()
                    ),
                    4 => assert!(control(&mut stream, finished(digest)).await.is_err()),
                    5 => assert!(application(&mut stream, root() + 1).await.is_err()),
                    _ => {
                        control(&mut stream, ToolControl::Started { digest })
                            .await
                            .unwrap();
                        if scenario == 6 {
                            assert!(
                                control(&mut stream, ToolControl::Started { digest })
                                    .await
                                    .is_err()
                            );
                        } else if scenario == 7 {
                            let mut wrong = digest;
                            wrong[31] ^= 1;
                            assert!(control(&mut stream, finished(wrong)).await.is_err());
                        } else {
                            control(&mut stream, finished(digest)).await.unwrap();
                            if scenario == 8 {
                                assert!(control(&mut stream, finished(digest)).await.is_err());
                            } else {
                                assert!(application(&mut stream, root()).await.is_err());
                            }
                        }
                    }
                }
            };
            let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
            assert!(result.is_err());
            assert!(run.completed().is_err());
            assert!(run.accepted(root()).is_err());
            assert_eq!(global.requests.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn claimed_primary_close_is_sticky_before_and_after_started() {
        for started in [false, true] {
            let run = run();
            let (server, global) = server(Some(run.clone()));
            let client = async {
                let mut stream = UnixStream::connect(server.path()).await.unwrap();
                let digest = config(&mut stream).await;
                control(&mut stream, ToolControl::Claim { digest })
                    .await
                    .unwrap();
                if started {
                    control(&mut stream, ToolControl::Started { digest })
                        .await
                        .unwrap();
                }
            };
            let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
            assert!(result.is_err());
            assert!(run.completed().is_err());
            // The next actual accepted root socket cannot replace that owner.
            let replacement = async {
                let mut stream = UnixStream::connect(server.path()).await.unwrap();
                assert!(
                    read_message(&mut stream, DEFAULT_MAX_FRAME_LEN)
                        .await
                        .is_err()
                );
            };
            let (result, ()) =
                bounded(async { tokio::join!(server.serve_one(), replacement) }).await;
            assert!(result.is_err());
            assert_eq!(global.requests.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn second_root_stream_cannot_claim_start_finish_or_hide_malformed_control() {
        for operation in 0..4 {
            let run = run();
            let (server, global) = server(Some(run.clone()));
            let path = server.path().to_owned();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let serving = tokio::spawn(server.serve_until(async {
                let _ = stopped.await;
            }));
            let scenario = async {
                let mut primary = UnixStream::connect(&path).await.unwrap();
                let digest = config(&mut primary).await;
                control(&mut primary, ToolControl::Claim { digest })
                    .await
                    .unwrap();
                control(&mut primary, ToolControl::Started { digest })
                    .await
                    .unwrap();
                let mut second = UnixStream::connect(&path).await.unwrap();
                assert_eq!(config(&mut second).await, digest);
                if operation == 3 {
                    let mut malformed = ToolControl::Claim { digest }.encode();
                    malformed[6] = 1;
                    write_message(&mut second, &malformed).await.unwrap();
                    assert!(
                        read_message(&mut second, DEFAULT_MAX_FRAME_LEN)
                            .await
                            .is_err()
                    );
                } else {
                    let request = match operation {
                        0 => ToolControl::Claim { digest },
                        1 => ToolControl::Started { digest },
                        _ => finished(digest),
                    };
                    assert!(control(&mut second, request).await.is_err());
                }
                assert!(control(&mut primary, finished(digest)).await.is_err());
            };
            tokio::time::timeout(LIMIT, scenario).await.unwrap();
            stop.send(()).unwrap();
            tokio::time::timeout(LIMIT, serving)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert!(run.completed().is_err());
            assert_eq!(global.requests.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn existing_nonprimary_cannot_dispatch_after_finished() {
        let run = run();
        let (server, global) = server(Some(run.clone()));
        let path = server.path().to_owned();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(server.serve_until(async {
            let _ = stopped.await;
        }));
        bounded(async {
            let mut primary = UnixStream::connect(&path).await.unwrap();
            let digest = config(&mut primary).await;
            let mut other = UnixStream::connect(&path).await.unwrap();
            config(&mut other).await;
            control(&mut primary, ToolControl::Claim { digest })
                .await
                .unwrap();
            control(&mut primary, ToolControl::Started { digest })
                .await
                .unwrap();
            control(&mut primary, finished(digest)).await.unwrap();
            assert!(application(&mut other, root()).await.is_err());
        })
        .await;
        stop.send(()).unwrap();
        bounded(serving).await.unwrap().unwrap();
        assert!(run.completed().is_err());
        assert_eq!(global.requests.load(Ordering::SeqCst), 0);
    }

    #[derive(Default)]
    struct PendingGlobal {
        entered: Notify,
        requests: AtomicUsize,
    }

    #[reverie::global_tool]
    impl GlobalTool for PendingGlobal {
        type Request = ();
        type Response = u64;
        type Config = u64;

        async fn receive_rpc(&self, _from: reverie::Tid, _request: ()) -> u64 {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn pending_application_cannot_cross_finished_commit() {
        let run = run();
        let global = Arc::new(PendingGlobal::default());
        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..2 {
            let (stream, client) = UnixStream::pair().unwrap();
            let tool_activation = tool_activation_peer(Some(&run), &stream).unwrap();
            servers.push(tokio::spawn(serve_connection_inner(
                global.clone(),
                CONFIG,
                stream,
                ConnectionSetup {
                    tool_activation,
                    ..ConnectionSetup::default()
                },
            )));
            clients.push(client);
        }
        let mut pending = clients.pop().unwrap();
        let mut primary = clients.pop().unwrap();
        bounded(async {
            let digest = config(&mut primary).await;
            config(&mut pending).await;
            control(&mut primary, ToolControl::Claim { digest })
                .await
                .unwrap();
            control(&mut primary, ToolControl::Started { digest })
                .await
                .unwrap();
            let bytes = encode(&RequestEnvelope {
                from: reverie::Tid::from_raw(root()),
                request: (),
            })
            .unwrap();
            write_message(&mut pending, &bytes).await.unwrap();
            global.entered.notified().await;
            assert!(control(&mut primary, finished(digest)).await.is_err());
        })
        .await;
        for server in servers {
            server.abort();
            let _ = bounded(server).await;
        }
        assert!(run.completed().is_err());
        assert_eq!(global.requests.load(Ordering::SeqCst), 1);
    }

    // Re-executed as a real child with its own kernel socket peer credentials.
    // In an ordinary test run it performs no operation.
    #[test]
    fn activation_peer_child_fixture() {
        let Some(path) = std::env::var_os("REVERIE_TOOL_ACTIVATION_TEST_SOCKET") else {
            return;
        };
        let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        stream.set_write_timeout(Some(LIMIT)).unwrap();
        let bytes = crate::read_config_frame(&mut stream).unwrap();
        let digest = crate::initial_image::config_digest(&bytes);
        assert!(crate::exchange_tool_control(&mut stream, &ToolControl::Claim { digest }).is_err());
    }

    #[tokio::test]
    async fn actual_helper_child_peer_cannot_claim_bound_parent_root() {
        let run = run();
        let (server, global) = server(Some(run.clone()));
        let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "server::tool_activation_tests::activation_peer_child_fixture",
            ])
            .env("REVERIE_TOOL_ACTIVATION_TEST_SOCKET", server.path())
            .kill_on_drop(true);
        let scenario = async {
            let (result, output) = tokio::join!(server.serve_one(), child.output());
            assert!(result.is_err());
            let output = output.unwrap();
            assert!(
                output.status.success(),
                "child assertion failed: {:?}",
                output
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let summaries = stdout
                .lines()
                .filter(|line| line.starts_with("test result:"))
                .collect::<Vec<_>>();
            assert_eq!(
                summaries.len(),
                1,
                "missing or duplicate child summary: {stdout}"
            );
            assert!(
                summaries[0].starts_with("test result: ok. 1 passed;"),
                "wrong child selection: {stdout}"
            );
        };
        tokio::time::timeout(LIMIT, scenario).await.unwrap();
        assert!(run.completed().is_err());
        assert_eq!(global.requests.load(Ordering::SeqCst), 0);
    }

    struct FaultWrite {
        stream: UnixStream,
        remaining: usize,
        fail_flush: bool,
        run: ActivationRun,
    }

    impl AsyncRead for FaultWrite {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, bytes)
        }
    }

    impl AsyncWrite for FaultWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            assert!(
                self.run.completed().is_err(),
                "ack committed before complete write"
            );
            if self.remaining == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            let len = bytes.len().min(self.remaining);
            match Pin::new(&mut self.stream).poll_write(cx, &bytes[..len]) {
                Poll::Ready(Ok(written)) => {
                    self.remaining -= written;
                    Poll::Ready(Ok(written))
                }
                other => other,
            }
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            // Include a full payload whose final flush fails.
            assert!(self.run.completed().is_err(), "ack committed before flush");
            if self.remaining == 0 && self.fail_flush {
                return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
            }
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn failed_partial_and_unflushed_ack_never_commit_a_receipt() {
        for phase in 0..3 {
            for partial in [0, 1, 4, 17, 51, 52] {
                let run = run();
                let global = Arc::new(CountingGlobal::default());
                let (stream, mut client) = UnixStream::pair().unwrap();
                let activation = tool_activation_peer(Some(&run), &stream).unwrap();
                let config_length = 4 + encode(&CONFIG).unwrap().len();
                let stream = FaultWrite {
                    stream,
                    remaining: config_length + phase * 52 + partial,
                    fail_flush: partial == 52,
                    run: run.clone(),
                };
                let server = serve_connection_inner(
                    global.clone(),
                    CONFIG,
                    stream,
                    ConnectionSetup {
                        tool_activation: activation,
                        ..ConnectionSetup::default()
                    },
                );
                let client = async {
                    let digest = config(&mut client).await;
                    let requests = [
                        ToolControl::Claim { digest },
                        ToolControl::Started { digest },
                        finished(digest),
                    ];
                    for (index, request) in requests.into_iter().enumerate().take(phase + 1) {
                        let result = control(&mut client, request).await;
                        if index == phase && partial != 52 {
                            assert!(result.is_err());
                        } else {
                            // A complete payload is visible even if server flush
                            // then fails; only server commit grants the receipt.
                            result.unwrap();
                        }
                    }
                };
                let (result, ()) =
                    tokio::time::timeout(LIMIT, async { tokio::join!(server, client) })
                        .await
                        .unwrap();
                assert!(result.is_err());
                assert!(run.completed().is_err());
                assert!(run.accepted(root()).is_err());
                assert_eq!(global.requests.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn truncated_control_header_or_payload_is_sticky() {
        for truncate in [1, 3, 4, 5, 51] {
            let run = run();
            let (server, global) = server(Some(run.clone()));
            let client = async {
                let mut stream = UnixStream::connect(server.path()).await.unwrap();
                let digest = config(&mut stream).await;
                let mut bytes = 48u32.to_be_bytes().to_vec();
                bytes.extend_from_slice(&ToolControl::Claim { digest }.encode());
                stream.write_all(&bytes[..truncate]).await.unwrap();
                stream.shutdown().await.unwrap();
            };
            let (result, ()) = bounded(async { tokio::join!(server.serve_one(), client) }).await;
            assert!(result.is_err());
            assert!(run.completed().is_err());
            assert!(run.accepted(root()).is_err());
            assert_eq!(global.requests.load(Ordering::SeqCst), 0);
        }
    }
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

#[cfg(test)]
mod owned_request_cancellation_tests {
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    use super::*;

    #[derive(Default)]
    struct WaitingGlobal {
        entered: Notify,
        release: Notify,
        dropped: Arc<AtomicBool>,
    }
    struct Dropped(Arc<AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    #[reverie::global_tool]
    impl GlobalTool for WaitingGlobal {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn receive_rpc(&self, _from: reverie::Tid, _request: ()) {
            let _drop = Dropped(self.dropped.clone());
            self.entered.notify_one();
            self.release.notified().await;
        }
    }
    struct SelfPeer;
    impl ConnectionAdmission for SelfPeer {
        fn admit(&self, peer: OwnedFd) -> std::io::Result<Admitted> {
            // Test uses an actual same-process Unix connection and its kernel
            // SO_PEERPIDFD. This is transport coverage, NOT a reaped-child claim.
            let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd()))?;
            let pid = text
                .lines()
                .find_map(|line| line.strip_prefix("Pid:"))
                .and_then(|pid| pid.trim().parse::<i32>().ok())
                .ok_or_else(|| std::io::Error::other("actual peer pidfd PID absent"))?;
            if pid != std::process::id() as i32 {
                return Err(std::io::Error::other("transport fixture peer differs"));
            }
            Ok(Admitted { process_id: pid })
        }
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = PathBuf::from(format!(
                "/tmp/rpc-cancel-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    const LIMIT: Duration = Duration::from_secs(2);

    async fn opened_request(path: &Path, global: &WaitingGlobal) -> UnixStream {
        let mut client = UnixStream::connect(path).await.unwrap();
        let config = read_message(&mut client, DEFAULT_MAX_FRAME_LEN)
            .await
            .unwrap();
        assert_eq!(decode::<()>(&config).unwrap(), ());
        let request = encode(&RequestEnvelope {
            from: reverie::Tid::from_raw(std::process::id() as i32),
            request: (),
        })
        .unwrap();
        write_message(&mut client, &request).await.unwrap();
        tokio::time::timeout(LIMIT, global.entered.notified())
            .await
            .unwrap();
        client
    }

    #[tokio::test]
    async fn actual_pending_request_is_dropped_joined_and_never_replied() {
        let directory = Directory::new();
        let path = directory.0.join("rpc.sock");
        let global = Arc::new(WaitingGlobal::default());
        let mut server = RpcServer::bind_exclusive(&path, global.clone(), ()).unwrap();
        server.set_connection_admission(Arc::new(SelfPeer));
        let issues = server.retain_connection_issues();
        let connections = server.connection_monitor();
        let cancellation = RequestCancellation::default();
        let task_cancel = cancellation.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until_with_request_cancellation(
            async move {
                let _ = stopped.await;
            },
            task_cancel,
        ));
        let mut client = opened_request(&path, &global).await;
        assert!(!global.dropped.load(Ordering::Acquire));
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
        cancellation.request(std::process::id() as i32).unwrap();
        tokio::time::timeout(LIMIT, cancellation.wait_for_joined())
            .await
            .unwrap();
        assert!(global.dropped.load(Ordering::Acquire));
        tokio::time::timeout(LIMIT, connections.wait_for_idle())
            .await
            .unwrap();
        let outcomes = cancellation.joined_outcomes().unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].connection(), 1);
        assert_eq!(outcomes[0].process_id(), std::process::id() as i32);
        assert_eq!(outcomes[0].sender(), std::process::id() as i32);
        assert_eq!(outcomes[0].request(), 1);
        assert!(matches!(
            tokio::time::timeout(LIMIT, read_message(&mut client, DEFAULT_MAX_FRAME_LEN))
                .await
                .unwrap(),
            Err(RpcError::Closed)
        ));
        assert!(issues.snapshot().is_empty());
        // A queued connection cannot be accepted/configured after cancellation.
        let mut late = UnixStream::connect(&path).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                read_message(&mut late, DEFAULT_MAX_FRAME_LEN)
            )
            .await
            .is_err()
        );
        assert_eq!(connections.active_connections(), 0);
        drop(late);
        stop.send(()).unwrap();
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(issues.snapshot().is_empty());
    }

    #[tokio::test]
    async fn different_process_cannot_cancel_the_owned_request() {
        let directory = Directory::new();
        let path = directory.0.join("rpc.sock");
        let global = Arc::new(WaitingGlobal::default());
        let mut server = RpcServer::bind_exclusive(&path, global.clone(), ()).unwrap();
        server.set_connection_admission(Arc::new(SelfPeer));
        let issues = server.retain_connection_issues();
        let cancellation = RequestCancellation::default();
        let task_cancel = cancellation.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until_with_request_cancellation(
            async move {
                let _ = stopped.await;
            },
            task_cancel,
        ));
        let _client = opened_request(&path, &global).await;
        let actual = std::process::id() as i32;
        let other = if actual == 1 { 2 } else { 1 };
        cancellation.request(other).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), cancellation.wait_for_joined())
                .await
                .is_err()
        );
        assert!(!global.dropped.load(Ordering::Acquire));
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
        assert!(issues.snapshot().is_empty());
        stop.send(()).unwrap();
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(global.dropped.load(Ordering::Acquire));
        assert!(matches!(
            issues.snapshot().as_slice(),
            [ConnectionIssue {
                failure: ConnectionFailure::Interrupted,
                ..
            }]
        ));
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn actual_broken_pipe_remains_a_transport_failure() {
        let directory = Directory::new();
        let path = directory.0.join("rpc.sock");
        let global = Arc::new(WaitingGlobal::default());
        let mut server = RpcServer::bind_exclusive(&path, global.clone(), ()).unwrap();
        server.set_connection_admission(Arc::new(SelfPeer));
        let issues = server.retain_connection_issues();
        let connections = server.connection_monitor();
        let cancellation = RequestCancellation::default();
        let task_cancel = cancellation.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until_with_request_cancellation(
            async move {
                let _ = stopped.await;
            },
            task_cancel,
        ));
        let client = opened_request(&path, &global).await;
        drop(client);
        global.release.notify_one();
        tokio::time::timeout(LIMIT, connections.wait_for_idle())
            .await
            .unwrap();
        let before = issues.snapshot();
        assert!(matches!(before.as_slice(), [ConnectionIssue {
            failure: ConnectionFailure::Transport(error), .. }]
            if matches!(error.as_ref(), RpcError::Io(error)
                if error.raw_os_error() == Some(libc::EPIPE))));
        cancellation.request(std::process::id() as i32).unwrap();
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
        assert_eq!(issues.snapshot().len(), before.len());
        stop.send(()).unwrap();
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[test]
    fn cancellation_error_identity_is_not_diagnostic_text() {
        let spoof = RpcError::Io(std::io::Error::other(
            "owned admitted RPC cancelled without response: connection=1 process=2 sender=2 request=1",
        ));
        assert!(matches!(
            ConnectionError::from(spoof),
            ConnectionError::Rpc(_)
        ));
        // Even an actual previous public observation replayed by a hook stays a
        // transport error. Only the private dispatch branch can cancel a task.
        let replay = CancelledRequest {
            connection: 1,
            process_id: 2,
            sender: 2,
            request: 1,
        };
        let hook_error = RpcError::Io(std::io::Error::other(replay));
        assert!(matches!(
            ConnectionError::from(hook_error),
            ConnectionError::Rpc(_)
        ));
        let cancellation = RequestCancellation::default();
        assert!(cancellation.request(0).is_err());
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
        cancellation.request(2).unwrap();
        assert!(cancellation.request(2).is_err());
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
    }

    #[tokio::test]
    async fn replayed_public_outcome_from_admission_is_still_transport_failure() {
        struct Replay;
        impl ConnectionAdmission for Replay {
            fn admit(&self, _peer: OwnedFd) -> std::io::Result<Admitted> {
                Err(std::io::Error::other(CancelledRequest {
                    connection: 1,
                    process_id: std::process::id() as i32,
                    sender: std::process::id() as i32,
                    request: 1,
                }))
            }
        }
        let directory = Directory::new();
        let path = directory.0.join("rpc.sock");
        let mut server =
            RpcServer::bind_exclusive(&path, Arc::new(WaitingGlobal::default()), ()).unwrap();
        server.set_connection_admission(Arc::new(Replay));
        let issues = server.retain_connection_issues();
        let connections = server.connection_monitor();
        let cancellation = RequestCancellation::default();
        let task_cancel = cancellation.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until_with_request_cancellation(
            async move {
                let _ = stopped.await;
            },
            task_cancel,
        ));
        let mut client = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            tokio::time::timeout(LIMIT, read_message(&mut client, DEFAULT_MAX_FRAME_LEN))
                .await
                .unwrap(),
            Err(RpcError::Closed)
        ));
        tokio::time::timeout(LIMIT, connections.wait_for_idle())
            .await
            .unwrap();
        assert!(matches!(issues.snapshot().as_slice(), [ConnectionIssue {
            failure: ConnectionFailure::Transport(error), .. }]
            if matches!(error.as_ref(), RpcError::Io(error)
                if error.get_ref().is_some_and(|payload| payload.is::<CancelledRequest>()))));
        assert!(cancellation.joined_outcomes().unwrap().is_empty());
        stop.send(()).unwrap();
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(issues.snapshot().len(), 1);
    }

    #[tokio::test]
    async fn cancellation_precedes_ready_dispatch_without_pause() {
        let directory = Directory::new();
        let path = directory.0.join("rpc.sock");
        let global = Arc::new(WaitingGlobal::default());
        let mut server = RpcServer::bind_exclusive(&path, global.clone(), ()).unwrap();
        server.set_connection_admission(Arc::new(SelfPeer));
        let issues = server.retain_connection_issues();
        let cancellation = RequestCancellation::default();
        let task_cancel = cancellation.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_until_with_request_cancellation(
            async move {
                let _ = stopped.await;
            },
            task_cancel,
        ));
        let mut client = opened_request(&path, &global).await;
        // No Pause or physical-test probe. Simulate the existing watcher wake
        // making the normal dispatch continuation ready at the first await.
        // Intent must already be visible when that actual future is repolled.
        cancellation.request(std::process::id() as i32).unwrap();
        global.release.notify_one();
        let drained = tokio::time::timeout(LIMIT, cancellation.wait_for_drain())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(drained.cancelled_requests().len(), 1);
        assert!(drained.idle_connections().is_empty());
        assert!(global.dropped.load(Ordering::Acquire));
        assert!(matches!(
            tokio::time::timeout(LIMIT, read_message(&mut client, DEFAULT_MAX_FRAME_LEN))
                .await
                .unwrap(),
            Err(RpcError::Closed)
        ));
        assert!(issues.snapshot().is_empty());
        stop.send(()).unwrap();
        tokio::time::timeout(LIMIT, task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn empty_closed_and_read_idle_drains_never_invent_a_cancelled_rpc() {
        for mode in ["empty", "closed", "read_idle"] {
            let directory = Directory::new();
            let path = directory.0.join("rpc.sock");
            let global = Arc::new(WaitingGlobal::default());
            let mut server = RpcServer::bind_exclusive(&path, global.clone(), ()).unwrap();
            server.set_connection_admission(Arc::new(SelfPeer));
            let issues = server.retain_connection_issues();
            let connections = server.connection_monitor();
            let cancellation = RequestCancellation::default();
            let task_cancel = cancellation.clone();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(server.serve_until_with_request_cancellation(
                async move {
                    let _ = stopped.await;
                },
                task_cancel,
            ));
            let mut idle = None;
            if mode != "empty" {
                let mut client = UnixStream::connect(&path).await.unwrap();
                let config =
                    tokio::time::timeout(LIMIT, read_message(&mut client, DEFAULT_MAX_FRAME_LEN))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(decode::<()>(&config).unwrap(), ());
                if mode == "closed" {
                    drop(client);
                    tokio::time::timeout(LIMIT, connections.wait_for_idle())
                        .await
                        .unwrap();
                } else {
                    idle = Some(client);
                }
            }
            cancellation.request(std::process::id() as i32).unwrap();
            let drained = tokio::time::timeout(LIMIT, cancellation.wait_for_drain())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(drained.process_id(), std::process::id() as i32);
            assert!(drained.cancelled_requests().is_empty());
            assert_eq!(
                drained.idle_connections(),
                if mode == "read_idle" {
                    &[1][..]
                } else {
                    &[][..]
                }
            );
            assert_eq!(connections.active_connections(), 0);
            assert!(!global.dropped.load(Ordering::Acquire)); // receive_rpc never ran
            assert!(issues.snapshot().is_empty());
            if let Some(mut client) = idle {
                assert!(matches!(
                    tokio::time::timeout(LIMIT, read_message(&mut client, DEFAULT_MAX_FRAME_LEN))
                        .await
                        .unwrap(),
                    Err(RpcError::Closed)
                ));
            }
            stop.send(()).unwrap();
            tokio::time::timeout(LIMIT, task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}
