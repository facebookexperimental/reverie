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
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::collections::HashMap;
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
    /// The fork generation this connection's `pid` was last verified
    /// against. A connection inherited across fork carries the parent's
    /// generation, so `exchange` can spot the stale `pid` from this
    /// mismatch alone, even if the one-shot atfork flag was already
    /// consumed by another exchange in the child.
    fork_generation: u64,
    client: BlockingRpcClient<G, GuestRpcStream>,
}

impl<G: GlobalTool> RpcConnection<G> {
    fn new(pid: Pid, fork_generation: u64, client: BlockingRpcClient<G, GuestRpcStream>) -> Self {
        Self {
            pid,
            fork_generation,
            client,
        }
    }
}

/// One guest thread's connection plus its descriptor mirror. The mirror
/// lives OUTSIDE the connection lock so relocation lookup and fork-child
/// cleanup can read (and close) the descriptor even when the lock state
/// was copied mid-exchange by fork: those paths must never need to
/// acquire a lock whose owner no longer exists.
struct ThreadConnection<G: GlobalTool> {
    fd: AtomicI32,
    connection: SpinMutex<RpcConnection<G>>,
}

impl<G: GlobalTool> ThreadConnection<G> {
    fn new(connection: RpcConnection<G>) -> Self {
        Self {
            fd: AtomicI32::new(connection.client.as_raw_fd()),
            connection: SpinMutex::new(connection),
        }
    }

    fn fd(&self) -> libc::c_int {
        self.fd.load(Ordering::Acquire)
    }

    fn set_fd(&self, fd: libc::c_int) {
        self.fd.store(fd, Ordering::Release);
    }

    fn lock(&self) -> crate::sync::SpinGuard<'_, RpcConnection<G>> {
        self.connection.lock()
    }

    fn try_lock(&self) -> Option<crate::sync::SpinGuard<'_, RpcConnection<G>>> {
        self.connection.try_lock()
    }
}

// Native application callbacks own their separate primary/contention routes.
// They need the authenticated shared config, not an unused ordinary socket.
// Keeping this owner explicit also prevents ordinary/private RPC APIs from
// manufacturing a connection or selecting a fallback on a native config owner.
enum ConnectionOwner<G: GlobalTool> {
    Ordinary(OrdinaryConnections<G>),
    NativeConfiguration,
}

/// One independently blocking coordinator connection per guest thread
/// (W7): `BlockingRpcClient` stamps its connect-time TID, and Detcore
/// requires a connection per thread so a scheduler RPC that blocks until
/// a sibling runs cannot deadlock against that sibling's own RPC.
/// Connections open lazily on a thread's first send and are closed when
/// its host thread state retires ([`CoordinatorRpc::close_current_thread`]).
/// The map lock is held only to look up or insert an `Arc`, never across
/// an exchange.
struct OrdinaryConnections<G: GlobalTool> {
    by_tid: SpinMutex<HashMap<i32, Arc<ThreadConnection<G>>>>,
}

impl<G: GlobalTool> OrdinaryConnections<G> {
    fn new(root_tid: i32, root: RpcConnection<G>) -> Self {
        let mut by_tid = HashMap::new();
        by_tid.insert(root_tid, Arc::new(ThreadConnection::new(root)));
        Self {
            by_tid: SpinMutex::new(by_tid),
        }
    }

    fn get(&self, tid: i32) -> Option<Arc<ThreadConnection<G>>> {
        self.by_tid.lock().get(&tid).cloned()
    }

    fn insert(&self, tid: i32, connection: RpcConnection<G>) -> Arc<ThreadConnection<G>> {
        let connection = Arc::new(ThreadConnection::new(connection));
        self.by_tid.lock().insert(tid, Arc::clone(&connection));
        connection
    }

    fn remove(&self, tid: i32) -> Option<Arc<ThreadConnection<G>>> {
        self.by_tid.lock().remove(&tid)
    }

    /// Leak-replace the whole map (fork child: every entry is a copy of
    /// a parent thread's connection). The copied map is forgotten
    /// without iteration or drop — a sibling may have been mid-insert
    /// at the fork instant, and a copied connection may sit
    /// mid-exchange — so no inherited connection is ever locked,
    /// traversed, or dropped here. Their descriptors are closed by
    /// the caller from the lock-free protect registry and the root
    /// descriptor mirror, never through these `Arc`s.
    fn forget_all_for_fork(&self) {
        // Reuse the copied map's hasher (fixed at construction):
        // a fresh RandomState would issue getrandom through libc,
        // outside the trusted gate, in the fork child.
        let copied = {
            let mut by_tid = self.by_tid.lock();
            let hasher = by_tid.hasher().clone();
            core::mem::replace(&mut *by_tid, HashMap::with_hasher(hasher))
        };
        core::mem::forget(copied);
    }

    /// Remove every connection but `keep` (the exchange-level fork
    /// reconnect: entries here were all created in this process, so
    /// the map is this process's own consistent one).
    fn drain_except(&self, keep: i32) -> Vec<Arc<ThreadConnection<G>>> {
        let mut by_tid = self.by_tid.lock();
        let kept = by_tid.remove(&keep);
        let drained: Vec<_> = by_tid.drain().map(|(_, connection)| connection).collect();
        if let Some(kept) = kept {
            by_tid.insert(keep, kept);
        }
        drained
    }

    fn snapshot(&self) -> Vec<Arc<ThreadConnection<G>>> {
        self.by_tid.lock().values().cloned().collect()
    }
}

impl<G: GlobalTool> ConnectionOwner<G> {
    fn ordinary(&self) -> &OrdinaryConnections<G> {
        match self {
            Self::Ordinary(connections) => connections,
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
/// The connections are process-local (one per guest thread, opened lazily)
/// and reconnect after `fork`: [`BlockingRpcClient`] stamps its
/// connect-time TID, and Detcore requires one independently blocking
/// connection per guest thread.
pub struct CoordinatorRpc<G: GlobalTool> {
    connection: ConnectionOwner<G>,
    config: Arc<G::Config>,
    path: Option<PathBuf>,
    fd: AtomicI32,
    transport: reverie_rpc_transport::RpcTransport,
    on_reconnect: ReconnectHook,
    // Root rebinding after fork rides the inherited root entry's
    // pid-mismatch reconnect in `exchange` (fork_child_reset_if_needed).
    /// Serializes the once-per-fork-child connection reset and records
    /// the pid it completed for. Keyed by pid, not a plain bool: the
    /// record is inherited across fork, so a grandchild (whose pid
    /// differs) must run its own reset instead of seeing its parent's
    /// completion. See `fork_child_reset_if_needed`.
    fork_reset: SpinMutex<Option<Pid>>,
    /// Bumped by every fork-child reset. Each connection stamps the
    /// generation at which its pid was verified; `exchange` re-verifies
    /// (and reconnects if the pid is stale) whenever a connection's
    /// stamp lags, so reconnect is tied to the connection's own stale
    /// pid rather than the one-shot atfork flag alone.
    fork_generation: AtomicU64,
    /// The inherited root descriptor a fork child still owes a rebind
    /// for (-1 when none): the reset forgets the inherited root
    /// connection without locking it (its lock state may have been
    /// copied while the parent's root thread was parked mid-exchange,
    /// so the child must never lock it) but leaves the descriptor
    /// itself open; the leader's first lazy connection in the child
    /// runs the reconnect hook against this number and then closes
    /// it, exactly as the old in-place root reconnect ordered things.
    /// A leader that never sends again leaves it open for the
    /// child's lifetime — a bounded one-descriptor leak, accepted
    /// so the root record never names a closed number.
    root_rebind_fd: AtomicI32,
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
            transport: reverie_rpc_transport::RpcTransport::Socket,
            on_reconnect: |_, _| Err(io::Error::from_raw_os_error(libc::EPROTO)),
            fork_reset: SpinMutex::new(None),
            fork_generation: AtomicU64::new(0),
            root_rebind_fd: AtomicI32::new(-1),
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
            transport: reverie_rpc_transport::RpcTransport::Socket,
            on_reconnect: |_, _| Err(io::Error::from_raw_os_error(libc::EPROTO)),
            fork_reset: SpinMutex::new(None),
            fork_generation: AtomicU64::new(0),
            root_rebind_fd: AtomicI32::new(-1),
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
        // In a fork child that has not sent yet, run the reset first:
        // the snapshot below must never traverse the copied connection
        // map or lock a copied connection.
        self.fork_child_reset_if_needed();
        // A pending root rebind: the inherited root socket is still
        // open under `from` with no connection object behind it. Move
        // the socket itself and retarget the rebind, so the leader's
        // later reconnect hooks and closes the moved number.
        if from >= 0
            && self.root_rebind_fd.load(Ordering::Acquire) == from
            && self.fd.load(Ordering::Acquire) == from
        {
            let moved = crate::guest::protect::dup_into_runtime_range(from);
            if moved < 0 {
                return Err(io::Error::from_raw_os_error(-moved as i32));
            }
            let moved = moved as libc::c_int;
            self.root_rebind_fd.store(moved, Ordering::Release);
            self.fd.store(moved, Ordering::Release);
            crate::guest::protect::replace_coordinator_fd(from, moved)?;
            return Ok(moved);
        }
        // Find the owning per-thread connection by its lock-free
        // descriptor mirror, then lock only that one: relocating under
        // an in-flight request would move its socket mid-exchange, so a
        // busy owner is EBUSY exactly as the single-connection lock was.
        let mut busy = false;
        for candidate in self.connection.ordinary().snapshot() {
            if candidate.fd() != from {
                continue;
            }
            let Some(connection) = candidate.try_lock() else {
                busy = true;
                continue;
            };
            if connection.client.as_raw_fd() != from {
                continue;
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
                // Unreachable: mapped reports fd -1, rejected by the `from`
                // check above. Defensive forget mirrors Native below.
                #[cfg(target_os = "linux")]
                GuestRpcStream::Mapped(previous) => core::mem::forget(previous),
                #[cfg(feature = "exec-private-init")]
                GuestRpcStream::Native(previous) => core::mem::forget(previous),
            }
            candidate.set_fd(moved);
            if self.fd.load(Ordering::Acquire) == from {
                self.fd.store(moved, Ordering::Release);
                crate::guest::protect::replace_coordinator_fd(from, moved)?;
            } else {
                crate::guest::protect::replace_coordinator_conn_fd(from, moved)?;
            }
            return Ok(moved);
        }
        if busy {
            return Err(io::Error::from_raw_os_error(libc::EBUSY));
        }
        Err(io::Error::from_raw_os_error(libc::EBADF))
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
        // Mapped streams retain no descriptor (as_raw_fd() == -1 by
        // construction); every other GuestRpcStream kind has a real fd.
        let fd = client.as_raw_fd();
        let (transport, supplied) = if fd < 0 {
            (reverie_rpc_transport::RpcTransport::Mapped, "mapped")
        } else {
            (reverie_rpc_transport::RpcTransport::Socket, "socket")
        };
        reverie_rpc_transport::RpcTransport::from_env()
            .and_then(|selected| selected.require(supplied))
            .map_err(|e| io::Error::other(e.to_string()))?;
        if transport == reverie_rpc_transport::RpcTransport::Socket {
            let valid = unsafe {
                raw_syscall6(
                    libc::SYS_fcntl,
                    [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                )
            };
            if valid < 0 {
                return Err(io::Error::other("live coordinator descriptor is invalid"));
            }
        }
        let config = Arc::new(client.config().clone());
        Ok(Self {
            connection: ConnectionOwner::Ordinary(OrdinaryConnections::new(
                tid.as_raw(),
                RpcConnection::new(pid, 0, client),
            )),
            config,
            path: Some(path.as_ref().to_path_buf()),
            fd: AtomicI32::new(fd),
            transport,
            on_reconnect,
            fork_reset: SpinMutex::new(None),
            fork_generation: AtomicU64::new(0),
            root_rebind_fd: AtomicI32::new(-1),
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        })
    }

    /// Adopt a mapped (shared-memory) stream issued by the coordinator
    /// (C1 PR1). Performs the ordinary config handshake over it.
    /// Fork and successor flows over mapped refuse by name in PR1
    /// (see `exchange`); fd delivery for children is PR2.
    #[cfg(target_os = "linux")]
    pub fn from_mapped_stream(
        stream: reverie_rpc_transport::mapped::MappedStream,
        on_reconnect: ReconnectHook,
    ) -> io::Result<Self> {
        reverie_rpc_transport::RpcTransport::from_env()
            .and_then(|selected| selected.require("mapped"))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let pid = current_id(libc::SYS_getpid)?;
        let tid = current_id(libc::SYS_gettid)?;
        let client = BlockingRpcClient::<G, GuestRpcStream>::from_connected_stream(
            GuestRpcStream::Mapped(stream),
            tid,
        )
        .map_err(|error| io::Error::other(describe_rpc_error(&error)))?;
        let config = Arc::new(client.config().clone());
        Ok(Self {
            connection: ConnectionOwner::Ordinary(OrdinaryConnections::new(
                tid.as_raw(),
                RpcConnection::new(pid, 0, client),
            )),
            config,
            path: None,
            fd: AtomicI32::new(-1),
            transport: reverie_rpc_transport::RpcTransport::Mapped,
            on_reconnect,
            fork_reset: SpinMutex::new(None),
            fork_generation: AtomicU64::new(0),
            root_rebind_fd: AtomicI32::new(-1),
            #[cfg(feature = "exec-private-successor")]
            native_failed: AtomicBool::new(false),
        })
    }

    /// Connect before installing seccomp and decode the coordinator config.
    /// `on_reconnect` runs when a forked child reconnects; see
    /// [`ReconnectHook`].
    pub fn connect(path: impl AsRef<Path>, on_reconnect: ReconnectHook) -> io::Result<Self> {
        // Path connect is the socket transport by definition; a mapped
        // selection here is a named mismatch, never a silent fallback.
        let transport = reverie_rpc_transport::RpcTransport::Socket;
        reverie_rpc_transport::RpcTransport::from_env()
            .and_then(|selected| selected.require("socket"))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let path = path.as_ref().to_path_buf();
        let pid = current_id(libc::SYS_getpid)?;
        let tid = current_id(libc::SYS_gettid)?;
        let client = connect_ordinary::<G>(&path, tid, |_| Ok(()))
            .map_err(|error| io::Error::other(describe_rpc_error(&error)))?;
        let config = Arc::new(client.config().clone());
        let fd = client.as_raw_fd();
        Ok(Self {
            connection: ConnectionOwner::Ordinary(OrdinaryConnections::new(
                tid.as_raw(),
                RpcConnection::new(pid, 0, client),
            )),
            config,
            path: Some(path),
            fd: AtomicI32::new(fd),
            transport,
            on_reconnect,
            fork_reset: SpinMutex::new(None),
            fork_generation: AtomicU64::new(0),
            root_rebind_fd: AtomicI32::new(-1),
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
    /// Force this handle's registry locks open in a fork child whose
    /// copies may have been made mid-hold by sibling threads that do
    /// not exist here. Per-connection locks are deliberately left
    /// alone, and no inherited connection is ever locked in the
    /// child — the root included: when a *non-root* thread forks
    /// while the root thread is parked inside a blocking exchange,
    /// the root connection's lock and client were copied mid-exchange
    /// by a thread that does not exist here. The reset
    /// ([`Self::fork_child_reset_if_needed`]) therefore forgets every
    /// inherited connection without locking or dropping it and
    /// closes sibling sockets from the lock-free protect registry;
    /// the root descriptor is rebound by the leader's first fresh
    /// connection (see `root_rebind_fd`).
    ///
    /// The two locks released here guard only a pid word and the
    /// registry map header; the map's copied contents are never
    /// traversed afterwards (the reset leak-replaces the map), which
    /// is the data-consistency half of the force-unlock contract.
    ///
    /// # Safety
    ///
    /// Same contract as [`SpinMutex::force_unlock`]: no live holder
    /// can exist in this process and no stale guard will drop. The
    /// host calls this from its fork-child reinit, before the child
    /// creates any thread.
    pub(crate) unsafe fn reinit_after_fork(&self) {
        // SAFETY: the caller establishes the force-unlock contract.
        unsafe { self.fork_reset.force_unlock() };
        if let ConnectionOwner::Ordinary(connections) = &self.connection {
            // SAFETY: same contract.
            unsafe { connections.by_tid.force_unlock() };
        }
    }

    /// Test stand-in for sibling threads that held this handle's
    /// registry locks at the fork instant and do not exist in the
    /// child.
    #[cfg(test)]
    pub(crate) fn forget_lock_guards_for_test(&self) {
        core::mem::forget(self.fork_reset.lock());
        if let ConnectionOwner::Ordinary(connections) = &self.connection {
            core::mem::forget(connections.by_tid.lock());
        }
    }

    /// Whether both registry locks are free (the wiring test's
    /// post-reinit assertion, so deleting the host's call to
    /// [`Self::reinit_after_fork`] is caught).
    #[cfg(test)]
    pub(crate) fn registry_locks_free_for_test(&self) -> bool {
        if self.fork_reset.try_lock().is_none() {
            return false;
        }
        match &self.connection {
            ConnectionOwner::Ordinary(connections) => connections.by_tid.try_lock().is_some(),
            ConnectionOwner::NativeConfiguration => true,
        }
    }

    fn current_tid() -> Pid {
        current_id(libc::SYS_gettid).unwrap_or_else(|_| rpc_fatal(122))
    }

    /// This thread's own coordinator connection, opened lazily on first
    /// use. The root thread's connection is the one built at construction
    /// (its descriptor is the process's reserved coordinator FD); later
    /// threads register theirs in the per-thread coordinator FD set as
    /// the placement records them.
    fn thread_connection(&self) -> Arc<ThreadConnection<G>> {
        self.fork_child_reset_if_needed();
        let tid = Self::current_tid().as_raw();
        let connections = self.connection.ordinary();
        if let Some(connection) = connections.get(tid) {
            return connection;
        }
        // A mapped run has no per-thread socket to open: refusing by name
        // (124, as the fork path does) instead of silently falling back
        // to a socket connect for later threads. Mapped fd delivery for
        // children/threads is C1 PR2 scope.
        if self.transport == reverie_rpc_transport::RpcTransport::Mapped {
            rpc_fatal(124);
        }
        let pid = current_id(libc::SYS_getpid).unwrap_or_else(|_| rpc_fatal(122));
        let path = self.path.as_deref().unwrap_or_else(|| rpc_fatal(123));
        // The leader's first connection in a fork child is the new
        // root: it runs the reconnect hook against the inherited root
        // descriptor the reset left open, then closes that copy. A
        // newborn thread sending first must not consume the rebind
        // (later native-frame root checks name the leader as owner),
        // so only the leader (tid == pid) takes it.
        let inherited_root = if tid == pid.as_raw() {
            self.root_rebind_fd.swap(-1, Ordering::AcqRel)
        } else {
            -1
        };
        let client = connect_ordinary::<G>(path, Pid::from_raw(tid), |new_fd| {
            if inherited_root >= 0 {
                let old_fd = self.fd.swap(new_fd, Ordering::AcqRel);
                (self.on_reconnect)(old_fd, new_fd)
            } else {
                crate::guest::protect::register_coordinator_conn_fd(new_fd)
            }
        })
        .unwrap_or_else(|_| rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE));
        if inherited_root >= 0 {
            close_inherited_fd(inherited_root);
        }
        connections.insert(
            tid,
            RpcConnection::new(pid, self.fork_generation.load(Ordering::Acquire), client),
        )
    }

    /// Once per fork child, before its first lazy connection exists:
    /// drain and close every inherited connection copy, and mark the
    /// next connection opened here as the new root. Keying connections
    /// by the *child's* tid alone would never run this (P2): the map
    /// miss would open a fresh, pid-correct connection and `exchange`'s
    /// pid-mismatch fork path would never fire, leaking the parent's
    /// sockets and leaving the root descriptor record pointing at an
    /// inherited copy. Doing the reset here, before any insert, also
    /// covers a fork that happened on a thread which had never sent.
    fn fork_child_reset_if_needed(&self) {
        if matches!(self.connection, ConnectionOwner::NativeConfiguration) {
            return;
        }
        // Common case (no fork): one atomic load, no lock, no syscall.
        // The flag is set in the child before its first thread-start
        // callback, so no racing store can be missed here.
        if !FORKED_SINCE_LAST_RPC.load(Ordering::Acquire) {
            return;
        }
        let mut done = self.fork_reset.lock();
        let pid = current_id(libc::SYS_getpid).unwrap_or_else(|_| rpc_fatal(122));
        if *done == Some(pid) {
            return;
        }
        *done = Some(pid);
        // Both installed private domains already refuse fork/thread. A
        // retained native stream can never reconnect as ordinary I/O.
        #[cfg(feature = "exec-private-init")]
        if super::exec_private::active() {
            rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
        }
        // Forget every inherited connection copy without locking,
        // traversing, or dropping any of them: the copied map may be
        // mid-rehash and any copied connection (the root above all,
        // when a non-root thread did the forking) may be mid-exchange.
        // Sibling sockets close from the lock-free protect registry,
        // which the atomics keep consistent at every fork stopping
        // point. The inherited root descriptor stays open as the
        // pending rebind: the leader's first fresh connection runs
        // the reconnect hook against it and closes it, so the root
        // record never names a closed number. The leader owns that
        // rebind whoever performs the reset — a newborn thread
        // sending first opens its own connection instead.
        let connections = self.connection.ordinary();
        connections.forget_all_for_fork();
        let mut inherited = [-1; crate::guest::protect::COORDINATOR_CONN_CAPACITY];
        let count = crate::guest::protect::take_coordinator_conn_fds(&mut inherited);
        for fd in &inherited[..count] {
            close_inherited_fd(*fd);
        }
        self.root_rebind_fd
            .store(self.fd.load(Ordering::Acquire), Ordering::Release);
        self.fork_generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Close and forget this thread's coordinator connection (thread
    /// exit). For the root thread this removes its map entry only; the
    /// reserved coordinator descriptor record stays, so the number
    /// remains protected for the process's lifetime.
    pub fn close_current_thread(&self) {
        // A fork child whose leader exits without ever sending still
        // owes the reset: the copied map must not be traversed here.
        self.fork_child_reset_if_needed();
        let ConnectionOwner::Ordinary(connections) = &self.connection else {
            return;
        };
        let tid = Self::current_tid().as_raw();
        if let Some(connection) = connections.remove(tid) {
            // Close through the trusted gate and forget the Arc, exactly
            // as fork-drained copies are closed. Dropping the stream here
            // would close through libc from a non-gate address: the guest
            // filter traps that close back into this runtime, descriptor
            // protection answers EBADF for the coordinator number, and
            // std aborts the guest on the "already closed" owned
            // descriptor. An exchange still in flight on this thread
            // cannot exist at its exit callbacks.
            close_drained_connections(vec![connection]);
        }
    }

    /// Sends `message` and waits for the response, from Tool code that runs
    /// outside a Tool callback's own `send_rpc` (for example inside a
    /// synchronous method the callback called). Each guest thread has its
    /// own connection and its callbacks complete each request before
    /// returning, so another request in flight *on this thread's
    /// connection* means re-entry; that is refused rather than waited on,
    /// because waiting would deadlock.
    pub fn send_blocking_unless_in_flight(
        &self,
        message: G::Request,
    ) -> Result<G::Response, RequestInFlight> {
        // A native-configuration owner has no ordinary connection to try:
        // the refusal this returned before per-thread connections.
        if matches!(self.connection, ConnectionOwner::NativeConfiguration) {
            return Err(RequestInFlight);
        }
        let thread = self.thread_connection();
        let connection = thread.try_lock().ok_or(RequestInFlight)?;
        Ok(self.exchange(&thread, connection, message))
    }

    /// One request and response on `connection`, reconnecting first in a
    /// freshly forked child.
    fn exchange(
        &self,
        thread: &ThreadConnection<G>,
        mut connection: crate::sync::SpinGuard<'_, RpcConnection<G>>,
        message: G::Request,
    ) -> G::Response {
        #[cfg(feature = "exec-private-successor")]
        if self.native_failed.load(Ordering::Acquire) {
            rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
        }
        // Fork detection without a per-hop syscall: the common round-trip only
        // reads the atfork flag and this connection's fork-generation stamp.
        // The flag is set exclusively in a freshly forked child and the stamp
        // lags on a connection inherited from the parent, so `getpid`/`gettid`
        // are issued only when a fork has actually happened and the inherited
        // connection may still belong to the parent. Reconnect then keys on
        // the connection's own stale pid, not on either signal alone.
        let generation = self.fork_generation.load(Ordering::Acquire);
        let connection_unverified = connection.fork_generation != generation;
        if FORKED_SINCE_LAST_RPC.swap(false, Ordering::AcqRel) || connection_unverified {
            // C1 PR1: a mapped endpoint must never be duplicated by fork
            // (SPSC contract). Refuse by name (exit 124) instead of
            // operating the inherited copy; PR2 delivers fresh pairs.
            #[cfg(target_os = "linux")]
            if self.transport == reverie_rpc_transport::RpcTransport::Mapped {
                rpc_fatal(124);
            }
            // Both installed private domains already refuse fork/thread. A
            // retained native stream can never reconnect as ordinary I/O.
            #[cfg(feature = "exec-private-init")]
            if super::exec_private::active() {
                rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE);
            }
            let pid = current_id(libc::SYS_getpid).unwrap_or_else(|_| rpc_fatal(122));
            if connection.pid != pid {
                let tid = current_id(libc::SYS_gettid).unwrap_or_else(|_| rpc_fatal(122));
                // Sibling threads do not exist in this child: close
                // every inherited sibling connection copy here.
                let drained = self.connection.ordinary().drain_except(tid.as_raw());
                close_drained_connections(drained);
                // The new connection is recorded as the coordinator's
                // before the placement unblocks signals, so a guest handler
                // run then already finds it protected. The reconnect hook
                // (which rebinds the reserved root descriptor) runs only
                // when this connection is the root one; a per-thread
                // connection re-registers in the connection set instead.
                let path = self.path.as_deref().unwrap_or_else(|| rpc_fatal(123));
                let was_root = self.fd.load(Ordering::Acquire) == thread.fd();
                let client = connect_ordinary::<G>(path, tid, |new_fd| {
                    if was_root {
                        let old_fd = self.fd.swap(new_fd, Ordering::AcqRel);
                        (self.on_reconnect)(old_fd, new_fd)
                    } else {
                        crate::guest::protect::register_coordinator_conn_fd(new_fd)
                    }
                })
                .unwrap_or_else(|_| rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE));
                if !was_root {
                    crate::guest::protect::unregister_coordinator_conn_fd(thread.fd());
                }
                let inherited = std::mem::replace(
                    &mut *connection,
                    RpcConnection::new(pid, generation, client),
                );
                thread.set_fd(connection.client.as_raw_fd());
                let (_, _, stream) = inherited.client.into_parts();
                close_inherited_stream(stream);
            } else {
                connection.fork_generation = generation;
            }
        }
        match connection.client.try_send_rpc(message) {
            Ok(response) => response,
            Err(_) => rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE),
        }
    }
}

/// Close every drained sibling connection copy in a fork child. Each
/// descriptor is read from the lock-free mirror on
/// [`ThreadConnection`]: a connection whose lock state was copied
/// mid-exchange is closed exactly like an unlocked one -- no drained
/// descriptor is skipped, and none keeps a stale protected-fd record.
/// The Arcs are forgotten rather than dropped so a copied locked client
/// cannot close the same number a second time.
fn close_drained_connections<G: GlobalTool>(drained: Vec<Arc<ThreadConnection<G>>>) {
    for other in drained {
        let fd = other.fd();
        if fd >= 0 {
            crate::guest::protect::unregister_coordinator_conn_fd(fd);
            close_inherited_fd(fd);
        }
        core::mem::forget(other);
    }
}

/// Close one inherited coordinator descriptor by number, with every
/// signal blocked until the number has been checked: a close a guest
/// seccomp filter faked leaves that number open, and the runtime
/// then keeps it as its own, so it is neither reachable nor
/// unreported. The caller owns the protect-registry bookkeeping for
/// the number (the fork reset's take, or a drained connection's
/// unregister above).
fn close_inherited_fd(fd: libc::c_int) {
    if fd < 0 {
        return;
    }
    let blocked = crate::guest::protect::block_all_signals()
        .unwrap_or_else(|_| rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE));
    unsafe { raw_syscall6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
    crate::guest::protect::record_if_open(fd)
        .unwrap_or_else(|_| rpc_fatal(reverie_rpc_transport::TOOL_RPC_FAILURE_EXIT_CODE));
    drop(blocked);
}

/// Close this child's copy of a parent connection's stream, with every
/// signal blocked until the number has been checked: a close a guest
/// seccomp filter faked leaves that number open, and the runtime then
/// keeps it as its own, so it is neither reachable nor unreported.
fn close_inherited_stream(stream: GuestRpcStream) {
    match stream {
        GuestRpcStream::Ordinary(stream) => {
            close_inherited_fd(stream.into_raw_fd());
        }
        // Not reached for mapped either: the fork branch refuses mapped
        // (124) before reconnecting. Defensive.
        #[cfg(target_os = "linux")]
        GuestRpcStream::Mapped(stream) => drop(stream),
        // Not reached on the ordinary path: connect_ordinary builds only
        // Ordinary streams. Dropped as before, without the survivor check.
        #[cfg(feature = "exec-private-init")]
        GuestRpcStream::Native(stream) => drop(stream),
    }
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for CoordinatorRpc<G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        let thread = self.thread_connection();
        self.exchange(&thread, thread.lock(), message)
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Arc;

    use super::CoordinatorRpc;
    use super::GuestRpcStream;
    use crate::guest::native_test_support::Remote;

    /// Re-exec component marker: the mapped-refusal tests below run
    /// their bodies in a fresh exact-test process with
    /// `REVERIE_RPC_TRANSPORT=mapped` passed through `Command::env`,
    /// never via `set_var` in a forked child of the (multi-threaded)
    /// libtest process, whose parallel runs hang. Same convention as
    /// native_exec_leaf_tests.
    const CHILD: &str = "REVERIE_RPC_MAPPED_REFUSAL_COMPONENT";

    /// Parent side: re-exec this exact test in a fresh process with
    /// the mapped selection in its environment. Returns the output
    /// when called in the parent, or `None` in the re-exec'd child,
    /// which then runs the test body directly.
    fn reexec(test_name: &'static str) -> Option<std::process::Output> {
        if std::env::var_os(CHILD).is_some() {
            return None;
        }
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .env("REVERIE_RPC_TRANSPORT", "mapped")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            // Own process group: the deadline kill below must reach
            // fork-test grandchildren too, or a wedged grandchild
            // holds the output pipes open past the bound.
            .process_group(0)
            .spawn()
            .unwrap();
        // Bound the whole group so a wedged refusal path fails this
        // test instead of hanging the suite.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                return Some(child.wait_with_output().unwrap());
            }
            if std::time::Instant::now() >= deadline {
                // Kill the child's process group (pgid == child pid
                // under process_group(0)), then reap and drain.
                unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                let out = child.wait_with_output().unwrap();
                panic!(
                    "isolated component timed out: {}; stdout={}; stderr={}",
                    out.status,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn mapped_rpc_from_live_client() -> Arc<CoordinatorRpc<Remote>> {
        use reverie_rpc_transport::mapped::MappedStream;
        // SAFETY: the setup descriptor goes to the sole importer
        // below; no writes through the descriptor itself.
        let (mut host, guest_fd) = unsafe { MappedStream::create(256 * 1024) }.unwrap();
        let server = std::thread::spawn(move || {
            let config = reverie_rpc_transport::codec::encode(&71_u64).unwrap();
            host.write_all(&(config.len() as u32).to_be_bytes())
                .unwrap();
            host.write_all(&config).unwrap();
            // Keep the host end mapped until this process exits.
            std::thread::park();
        });
        let _ = &server;
        // SAFETY: sole importer of the setup descriptor.
        let stream = unsafe { MappedStream::from_owned_fd(guest_fd) }.unwrap();
        let tid = super::current_id(libc::SYS_gettid).unwrap();
        let client = reverie_rpc_transport::BlockingRpcClient::<Remote, _>::from_connected_stream(
            GuestRpcStream::Mapped(stream),
            tid,
        )
        .unwrap();
        let rpc = Arc::new(
            CoordinatorRpc::<Remote>::from_live_client("unused-mapped-test", client, |_, _| Ok(()))
                .unwrap(),
        );
        assert_eq!(
            rpc.transport,
            reverie_rpc_transport::RpcTransport::Mapped,
            "adopted client must be classified mapped (fd -1)"
        );
        rpc
    }

    fn second_thread_must_refuse(rpc: &Arc<CoordinatorRpc<Remote>>) {
        let second = {
            let rpc = Arc::clone(rpc);
            std::thread::spawn(move || {
                let _connection = rpc.thread_connection();
            })
        };
        // rpc_fatal(124) in the second thread exit_groups the whole
        // process; reaching join means no refusal happened.
        let _ = second.join();
        panic!("second-thread connection returned instead of refusing by name");
    }

    /// F2: a mapped client adopted through `from_live_client` must
    /// refuse by name (exit 124) when a second thread needs its own
    /// connection, never silently connect a socket to `path`.
    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_second_thread_connection_refuses_124() {
        if let Some(out) = reexec("guest::rpc::tests::mapped_second_thread_connection_refuses_124")
        {
            assert_eq!(
                out.status.code(),
                Some(124),
                "isolated component must exit 124: {}; stdout={}; stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        second_thread_must_refuse(&mapped_rpc_from_live_client());
    }

    /// F2, `from_mapped_stream` constructor: same named 124 refusal
    /// for a second thread (previously this only failed closed with
    /// the ambiguous 123 from the missing path).
    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_stream_second_thread_connection_refuses_124() {
        if let Some(out) =
            reexec("guest::rpc::tests::mapped_stream_second_thread_connection_refuses_124")
        {
            assert_eq!(
                out.status.code(),
                Some(124),
                "isolated component must exit 124: {}; stdout={}; stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        use reverie_rpc_transport::mapped::MappedStream;
        // SAFETY: the setup descriptor goes to the sole importer
        // below; no writes through the descriptor itself.
        let (mut host, guest_fd) = unsafe { MappedStream::create(256 * 1024) }.unwrap();
        let server = std::thread::spawn(move || {
            let config = reverie_rpc_transport::codec::encode(&71_u64).unwrap();
            host.write_all(&(config.len() as u32).to_be_bytes())
                .unwrap();
            host.write_all(&config).unwrap();
            std::thread::park();
        });
        let _ = &server;
        // SAFETY: sole importer of the setup descriptor.
        let stream = unsafe { MappedStream::from_owned_fd(guest_fd) }.unwrap();
        let rpc =
            Arc::new(CoordinatorRpc::<Remote>::from_mapped_stream(stream, |_, _| Ok(())).unwrap());
        second_thread_must_refuse(&rpc);
    }

    /// F2, fork control: a fork child's first connection lookup (its
    /// TID has no entry; the root entry is the parent's) must meet the
    /// same named 124 mapped refusal before any socket connect. The
    /// adopted mapped endpoint is never operated across the fork: the
    /// parent only waits, and the child's lookup refuses before
    /// touching the stream.
    #[cfg(target_os = "linux")]
    #[test]
    fn mapped_fork_child_connection_refuses_124() {
        if let Some(out) = reexec("guest::rpc::tests::mapped_fork_child_connection_refuses_124") {
            assert!(
                out.status.success(),
                "isolated component failed: {}; stdout={}; stderr={}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                out.stdout
                    .windows(b"mapped-fork-refusal-complete".len())
                    .filter(|item| *item == b"mapped-fork-refusal-complete")
                    .count(),
                1,
                "exact-test child must print the completion marker exactly once: stdout={}",
                String::from_utf8_lossy(&out.stdout)
            );
            return;
        }
        let rpc = mapped_rpc_from_live_client();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // New TID, no entry: must refuse 124 before connecting.
            let _connection = rpc.thread_connection();
            unsafe { libc::_exit(0) }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 124);
        // Completion marker: the re-exec parent requires exactly one
        // occurrence, so a child that never reached this assert (or a
        // misspelled --exact name running zero tests) cannot pass.
        println!("mapped-fork-refusal-complete");
    }
}
