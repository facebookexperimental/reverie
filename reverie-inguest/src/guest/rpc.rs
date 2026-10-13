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
use std::path::Path;
use std::path::PathBuf;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie_rpc_transport::BlockingRpcClient;

use crate::sync::SpinMutex;
use crate::trap::raw_syscall6;

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
    client: BlockingRpcClient<G>,
}

// TODO-HUMAN-REVIEW(PR-326): Review the common blocking
// transport and fork-child reconnect used by LiteInst's synchronous Tool callback.
/// Blocking guest-side RPC handle backed by the common Reverie RPC transport.
///
/// The connection is process-local and reconnects after `fork`. Thread-style
/// clone remains rejected: [`BlockingRpcClient`] stamps its connect-time TID,
/// and Detcore requires one independently blocking connection per guest thread.
pub struct CoordinatorRpc<G: GlobalTool> {
    connection: SpinMutex<RpcConnection<G>>,
    config: G::Config,
    path: PathBuf,
    fd: AtomicI32,
    on_reconnect: ReconnectHook,
}

/// Called when a forked child replaces its inherited connection with its own,
/// with the inherited descriptor and the new one, so the runtime can move the
/// protection it keeps on the coordinator descriptor. An error ends the child,
/// as a failed reconnect does.
pub type ReconnectHook = fn(old: libc::c_int, new: libc::c_int) -> io::Result<()>;

impl<G: GlobalTool> CoordinatorRpc<G> {
    /// The current connection's descriptor.
    pub fn raw_fd(&self) -> libc::c_int {
        self.fd.load(Ordering::Acquire)
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
        client: BlockingRpcClient<G>,
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
        let config = client.config().clone();
        Ok(Self {
            connection: SpinMutex::new(RpcConnection { pid, client }),
            config,
            path: path.as_ref().to_path_buf(),
            fd: AtomicI32::new(fd),
            on_reconnect,
        })
    }

    /// Connect before installing seccomp and decode the coordinator config.
    /// `on_reconnect` runs when a forked child reconnects; see
    /// [`ReconnectHook`].
    pub fn connect(path: impl AsRef<Path>, on_reconnect: ReconnectHook) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let pid = current_id(libc::SYS_getpid)?;
        let tid = current_id(libc::SYS_gettid)?;
        let client: BlockingRpcClient<G> = BlockingRpcClient::connect(&path, tid)
            .map_err(|error| io::Error::other(describe_rpc_error(&error)))?;
        let config = client.config().clone();
        let fd = client.as_raw_fd();
        Ok(Self {
            connection: SpinMutex::new(RpcConnection { pid, client }),
            config,
            path,
            fd: AtomicI32::new(fd),
            on_reconnect,
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
        // Fork detection without a per-hop syscall: the common round-trip only
        // reads the atfork flag. It is set exclusively in a freshly forked
        // child, so `getpid`/`gettid` are issued only when a fork has actually
        // happened and the inherited connection may still belong to the parent.
        if FORKED_SINCE_LAST_RPC.swap(false, Ordering::AcqRel) {
            let pid = current_id(libc::SYS_getpid).unwrap_or_else(|_| rpc_fatal(122));
            if connection.pid != pid {
                let tid = current_id(libc::SYS_gettid).unwrap_or_else(|_| rpc_fatal(122));
                let client =
                    BlockingRpcClient::connect(&self.path, tid).unwrap_or_else(|_| rpc_fatal(123));
                let new_fd = client.as_raw_fd();
                let old_fd = self.fd.swap(new_fd, Ordering::AcqRel);
                (self.on_reconnect)(old_fd, new_fd).unwrap_or_else(|_| rpc_fatal(123));
                *connection = RpcConnection { pid, client };
            }
        }
        match connection.client.try_send_rpc(message) {
            Ok(response) => response,
            Err(_) => rpc_fatal(123),
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
