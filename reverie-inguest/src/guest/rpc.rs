/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Coordinator RPC handle for in-guest Reverie tools.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::Ordering;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie_rpc_transport::BlockingRpcClient;

use crate::sync::SpinMutex;
use crate::trap::raw_syscall6;

mod stream;
pub use stream::GuestRpcStream;
pub use stream::move_ordinary_coordinator_stream;

#[cfg(feature = "exec-private-successor")]
mod native;
#[cfg(feature = "exec-private-successor")]
pub use native::NativeFrameError;
#[cfg(feature = "exec-private-successor")]
pub use native::NativeFrameReply;

/// Set in a freshly forked child by [`note_fork_in_child`]. The guest RPC hot
/// path consults this flag instead of issuing a `getpid` syscall on every hop,
/// so an ordinary (non-forking) round-trip performs no identity syscalls at all.
static FORKED_SINCE_LAST_RPC: AtomicBool = AtomicBool::new(false);

/// Record that this process is a freshly forked child whose inherited
/// coordinator connection still belongs to the parent.
///
/// The tool host calls this from `finish_fork_child`, which is driven by
/// *syscall interception* rather than libc. That placement is load-bearing for
/// two reasons:
///
///   - It observes every supported fork, including a raw `SYS_fork` or a raw
///     plain `SYS_clone` issued without libc (Go's runtime, hand-written
///     `syscall(2)` call sites). A `pthread_atfork` child handler would see
///     only forks that went through glibc's `fork()` wrapper and would silently
///     leave such a child on the parent's connection.
///   - It runs before the child's `handle_thread_start` callback, which is the
///     child's first opportunity to issue an RPC. A `pthread_atfork` handler
///     runs later, inside the libc wrapper after the fork syscall returns, so a
///     tool that sends an RPC from `handle_thread_start` would be attributed to
///     the parent.
///
/// The actual reconnect happens lazily on the child's next
/// [`CoordinatorRpc::send_rpc`]; this is only a flag store, so it stays safe in
/// the restricted post-fork context.
pub fn note_fork_in_child() {
    FORKED_SINCE_LAST_RPC.store(true, Ordering::Release);
}

struct RpcConnection<G: GlobalTool> {
    pid: Pid,
    client: BlockingRpcClient<G, GuestRpcStream>,
}

// Native application callbacks own their separate primary/contention routes.
// They need the authenticated shared config, not an unused ordinary socket.
// Keeping this owner explicit also prevents ordinary/private RPC APIs from
// manufacturing a connection or selecting a fallback on a native config owner.
enum ConnectionOwner<G: GlobalTool> {
    Ordinary(SpinMutex<RpcConnection<G>>),
    NativeConfiguration,
}

impl<G: GlobalTool> ConnectionOwner<G> {
    fn try_lock(&self) -> Option<crate::sync::SpinGuard<'_, RpcConnection<G>>> {
        match self {
            Self::Ordinary(connection) => connection.try_lock(),
            Self::NativeConfiguration => None,
        }
    }

    fn lock(&self) -> crate::sync::SpinGuard<'_, RpcConnection<G>> {
        match self {
            Self::Ordinary(connection) => connection.lock(),
            // An ordinary send on a native config owner is an owner mismatch,
            // not permission to open another route or a fake successful reply.
            Self::NativeConfiguration => rpc_fatal(123),
        }
    }
}

// TODO-HUMAN-REVIEW(PR-326): Review the common blocking
// transport and fork-child reconnect used by LiteInst's synchronous Tool callback.
/// Blocking guest-side RPC handle backed by the common Reverie RPC transport.
///
/// The connection is process-local and reconnects after `fork`. Thread-style
/// clone remains rejected: [`BlockingRpcClient`] stamps its connect-time TID,
/// and Detcore requires one independently blocking connection per guest thread.
pub struct CoordinatorRpc<G: GlobalTool> {
    connection: ConnectionOwner<G>,
    config: Arc<G::Config>,
    path: Option<PathBuf>,
    fd: AtomicI32,
    on_reconnect: ReconnectHook,
    #[cfg(feature = "exec-private-successor")]
    native_failed: AtomicBool,
}

/// Called when a forked child replaces its inherited connection with its own,
/// with the inherited descriptor and the new one, so the runtime can move the
/// protection it keeps on the coordinator descriptor. An error ends the child,
/// as a failed reconnect does.
pub type ReconnectHook = fn(old: libc::c_int, new: libc::c_int) -> io::Result<()>;

impl<G: GlobalTool> CoordinatorRpc<G> {
    /// Retain the exact configuration already received by a native image's
    /// authenticated temporary-config owner. This opens or owns no socket.
    ///
    /// This is configuration storage only, not image/thread admission. Actual
    /// native calls must use their NativeRpc/NativeBackgroundRpc owner and the
    /// same Arc. Ordinary sends, descriptor relocation and private frame I/O
    /// refuse on this owner; none may create an ambient or fallback connection.
    /// The native initializer remains responsible for the fingerprint, complete
    /// frame and closing its temporary connection before publishing readiness.
    pub fn from_native_configuration(
        path: impl AsRef<Path>,
        config: Arc<G::Config>,
    ) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Self {
            connection: ConnectionOwner::NativeConfiguration,
            config,
            path: Some(path),
            fd: AtomicI32::new(-1),
            on_reconnect: |_, _| Err(io::Error::from_raw_os_error(libc::EPROTO)),
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        })
    }

    /// Retain an explicitly selected in-process native GlobalTool's config.
    /// No path, descriptor, ordinary connection or coordinator fallback exists.
    /// This is config storage only; the real native entry owner still supplies
    /// the separate NativeRpc::local route and actual callback authority.
    pub fn from_native_local_configuration(config: Arc<G::Config>) -> Self {
        Self {
            connection: ConnectionOwner::NativeConfiguration,
            config,
            path: None,
            fd: AtomicI32::new(-1),
            on_reconnect: |_, _| Err(io::Error::from_raw_os_error(libc::EPROTO)),
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        }
    }

    /// Share the launch configuration cached by this connection owner.
    pub fn shared_config(&self) -> Arc<G::Config> {
        Arc::clone(&self.config)
    }

    /// The current connection's descriptor.
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd.load(Ordering::Acquire)
    }

    /// Moves this process's coordinator connection off `from`, a number a
    /// guest `dup2`, `dup3` or `F_DUPFD` is about to take
    /// (protect::make_room_for_guest_descriptor): the same socket continues on
    /// another free number (protect::runtime_fd_minimums), recorded as the
    /// coordinator's, and the new number is returned. `from` is left open and
    /// owned by no one, for the caller to close (protect::relocate_runtime_fd
    /// keeps it protected if it survives that close). Fails, moving
    /// nothing, when `from` is not this connection's number, no number is
    /// free, or a request of this process is in flight on the connection
    /// (`EBUSY`; waiting would spin forever under re-entry). The caller blocks
    /// every signal (protect::block_all_signals); no syscall here goes through
    /// libc.
    pub(crate) fn relocate(&self, from: libc::c_int) -> io::Result<libc::c_int> {
        let connection = self
            .connection
            .try_lock()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EBUSY))?;
        if connection.client.as_raw_fd() != from {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        let moved = crate::guest::protect::dup_into_runtime_range(from);
        if moved < 0 {
            return Err(io::Error::from_raw_os_error(-moved as i32));
        }
        let moved = moved as libc::c_int;
        // SAFETY: `moved` is a fresh duplicate of the connection's socket,
        // owned from here by the client's new stream.
        let stream = GuestRpcStream::from(unsafe { UnixStream::from_raw_fd(moved) });
        match connection.client.replace_stream(stream) {
            // The old number is released without closing it; see above.
            GuestRpcStream::Ordinary(previous) => {
                let _ = previous.into_raw_fd();
            }
            #[cfg(feature = "exec-private-init")]
            GuestRpcStream::Native(previous) => core::mem::forget(previous),
        }
        self.fd.store(moved, Ordering::Release);
        crate::guest::protect::replace_coordinator_fd(from, moved)?;
        Ok(moved)
    }

    /// Adopt a live blocking client without reconnecting or duplicating its fd.
    ///
    /// This transfers connection ownership only; it does not authenticate a
    /// client or confer InitialImage authorization. The genuine initializer
    /// must explicitly complete `connect_initial_image` first. The normal
    /// ToolHost installation still reserves/protects the actual descriptor.
    /// An inherited client whose stamped TID belongs to the parent is refused;
    /// later supported forks keep the ordinary lazy reconnect protocol.
    pub fn from_live_client(
        path: impl AsRef<Path>,
        client: BlockingRpcClient<G, GuestRpcStream>,
        on_reconnect: ReconnectHook,
    ) -> io::Result<Self> {
        let pid = current_id(libc::SYS_getpid)?;
        let tid = current_id(libc::SYS_gettid)?;
        if client.tid() != tid {
            return Err(io::Error::other(
                "live coordinator client belongs to another thread",
            ));
        }
        let fd = client.as_raw_fd();
        let valid = unsafe {
            raw_syscall6(
                libc::SYS_fcntl,
                [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
            )
        };
        if fd < 0 || valid < 0 {
            return Err(io::Error::other("live coordinator descriptor is invalid"));
        }
        let config = Arc::new(client.config().clone());
        Ok(Self {
            connection: ConnectionOwner::Ordinary(SpinMutex::new(RpcConnection { pid, client })),
            config,
            path: Some(path.as_ref().to_path_buf()),
            fd: AtomicI32::new(fd),
            on_reconnect,
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        })
    }

    /// Connect before installing seccomp and decode the coordinator config.
    /// `on_reconnect` runs when a forked child reconnects; see
    /// [`ReconnectHook`].
    pub fn connect(path: impl AsRef<Path>, on_reconnect: ReconnectHook) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let pid = current_id(libc::SYS_getpid)?;
        let tid = current_id(libc::SYS_gettid)?;
        let client = connect_ordinary::<G>(&path, tid, |_| Ok(()))
            .map_err(|error| io::Error::other(describe_rpc_error(&error)))?;
        let config = Arc::new(client.config().clone());
        let fd = client.as_raw_fd();
        Ok(Self {
            connection: ConnectionOwner::Ordinary(SpinMutex::new(RpcConnection { pid, client })),
            config,
            path: Some(path),
            fd: AtomicI32::new(fd),
            on_reconnect,
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        })
    }
}

/// A blocking request found another request of this process in flight on
/// the connection; see [`CoordinatorRpc::send_blocking_unless_in_flight`].
#[derive(Debug)]
pub struct RequestInFlight;

impl<G: GlobalTool> CoordinatorRpc<G> {
    /// Sends `message` and waits for the response, from Tool code that runs
    /// outside a Tool callback's own `send_rpc` (for example inside a
    /// synchronous method the callback called). A process's guest code is
    /// single-threaded and its callbacks complete each request before
    /// returning, so another request in flight means re-entry; that is
    /// refused rather than waited on, because waiting would deadlock.
    pub fn send_blocking_unless_in_flight(
        &self,
        message: G::Request,
    ) -> Result<G::Response, RequestInFlight> {
        let connection = self.connection.try_lock().ok_or(RequestInFlight)?;
        Ok(self.exchange(connection, message))
    }

    /// One request and response on `connection`, reconnecting first in a
    /// freshly forked child.
    fn exchange(
        &self,
        mut connection: crate::sync::SpinGuard<'_, RpcConnection<G>>,
        message: G::Request,
    ) -> G::Response {
        #[cfg(feature = "exec-private-successor")]
        if self.native_failed.load(Ordering::Acquire) {
            rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
        }
        // Fork detection without a per-hop syscall: the common round-trip only
        // reads the atfork flag. It is set exclusively in a freshly forked
        // child, so `getpid`/`gettid` are issued only when a fork has actually
        // happened and the inherited connection may still belong to the parent.
        if FORKED_SINCE_LAST_RPC.swap(false, Ordering::AcqRel) {
            // Both installed private domains already refuse fork/thread. A
            // retained native stream can never reconnect as ordinary I/O.
            #[cfg(feature = "exec-private-init")]
            if super::exec_private::active() {
                rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
            }
            let pid = current_id(libc::SYS_getpid).unwrap_or_else(|_| rpc_fatal(122));
            if connection.pid != pid {
                let tid = current_id(libc::SYS_gettid).unwrap_or_else(|_| rpc_fatal(122));
                // The new connection is recorded as the coordinator's
                // before the placement unblocks signals, so a guest handler
                // run then already finds it protected.
                let path = self.path.as_deref().unwrap_or_else(|| rpc_fatal(123));
                let client = connect_ordinary::<G>(path, tid, |new_fd| {
                    let old_fd = self.fd.swap(new_fd, Ordering::AcqRel);
                    (self.on_reconnect)(old_fd, new_fd)
                })
                .unwrap_or_else(|_| rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE));
                let inherited = std::mem::replace(&mut *connection, RpcConnection { pid, client });
                let (_, _, stream) = inherited.client.into_parts();
                match stream {
                    // This child's copy of its parent's connection. The
                    // runtime closes it with its own syscall, with every
                    // signal blocked until it has checked the number: a close
                    // a guest seccomp filter faked leaves that number open,
                    // and the runtime then keeps it as its own, so it is
                    // neither reachable nor unreported.
                    GuestRpcStream::Ordinary(stream) => {
                        let inherited_fd = stream.into_raw_fd();
                        let blocked =
                            crate::guest::protect::block_all_signals().unwrap_or_else(|_| {
                                rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE)
                            });
                        unsafe {
                            raw_syscall6(libc::SYS_close, [inherited_fd as u64, 0, 0, 0, 0, 0])
                        };
                        crate::guest::protect::record_if_open(inherited_fd).unwrap_or_else(|_| {
                            rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE)
                        });
                        drop(blocked);
                    }
                    // Not reached: connect_ordinary builds only Ordinary
                    // streams, and an active exec-private domain exits with
                    // 123 above. Dropped as before, without the survivor
                    // check.
                    #[cfg(feature = "exec-private-init")]
                    GuestRpcStream::Native(stream) => drop(stream),
                }
            }
        }
        match connection.client.try_send_rpc(message) {
            Ok(response) => response,
            Err(_) => rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE),
        }
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for CoordinatorRpc<G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        self.exchange(self.connection.lock(), message)
    }

    fn config(&self) -> &G::Config {
        &self.config
    }
}

/// Describes `error` without asking the C library for an errno message; see
/// [`crate::guest::support::describe_io_error`].
pub fn describe_rpc_error(error: &reverie_rpc_transport::RpcError) -> String {
    match error {
        reverie_rpc_transport::RpcError::Io(inner) => format!(
            "rpc i/o error: {}",
            crate::guest::support::describe_io_error(inner)
        ),
        other => other.to_string(),
    }
}

/// Connects to the coordinator at `path` and places the connection in the
/// runtime's range; `record` records its number before signals are unblocked
/// (protect::place_runtime_fd_and).
fn connect_ordinary<G: GlobalTool>(
    path: &Path,
    tid: Pid,
    record: impl FnOnce(libc::c_int) -> io::Result<()>,
) -> Result<BlockingRpcClient<G, GuestRpcStream>, reverie_rpc_transport::RpcError> {
    // The connection goes to the runtime's numbers (protect::runtime_fd_minimums:
    // 1025, or just below a soft RLIMIT_NOFILE that leaves no number free
    // there), so the guest's own descriptors get the numbers they would get
    // without the runtime (its first is 3). Where no number is free at all it
    // stays where connect put it; either way it is protected, and a guest dup2
    // onto its number moves it first (CoordinatorRpc::relocate). A
    // placement that cannot record a surviving old number fails the connection
    // rather than leave that number reachable.
    // Authenticated initial-image callers keep their own high descriptor
    // helper and separate descriptor contract.
    let connected = UnixStream::connect(path)?;
    let placed = crate::guest::protect::place_runtime_fd_and(connected.into_raw_fd(), record)?;
    // SAFETY: `placed` is the connected socket's only descriptor, owned here.
    let stream = unsafe { UnixStream::from_raw_fd(placed) };
    BlockingRpcClient::from_connected_stream(GuestRpcStream::from(stream), tid)
}

fn current_id(number: i64) -> io::Result<Pid> {
    let id = unsafe { raw_syscall6(number, [0; 6]) };
    if id <= 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Pid::from_raw(id as i32))
    }
}

fn rpc_fatal(status: i32) -> ! {
    unsafe {
        let _ = raw_syscall6(libc::SYS_exit_group, [status as u64, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}
