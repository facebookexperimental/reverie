/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The host process that opened the RPC connection a request arrived on.

use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;

/// The host process that opened the RPC connection a request arrived on, as
/// the kernel recorded it at `connect` (`SO_PEERPIDFD`), with the thread-group
/// id the kernel reported for it when the connection was accepted.
///
/// The pidfd names that process for as long as it is held: it cannot name
/// another process, and it does not follow a reused pid. A connection opened
/// by any thread of a process names the whole process (a process pidfd), so a
/// request's sender thread and its connection's process are separate facts;
/// a [`crate::GlobalTool`] that needs them to agree must check that itself.
///
/// The pidfd is shared, so it stays open while any request from the
/// connection is still being handled, even after the connection closes.
///
/// A transport hands this only to a coordinator that asked for it (see
/// `reverie_rpc_transport::RpcServer::require_connection_identity`), through
/// [`crate::GlobalTool::receive_rpc_with_identity`].
#[derive(Clone, Debug)]
pub struct ConnectionIdentity {
    pidfd: Arc<OwnedFd>,
    tgid: i32,
}

impl ConnectionIdentity {
    /// An identity for the process `pidfd` names, whose thread-group id the
    /// kernel reported as `tgid` (in the coordinator's PID namespace).
    pub fn new(pidfd: Arc<OwnedFd>, tgid: i32) -> Self {
        Self { pidfd, tgid }
    }

    /// The process pidfd of the connecting process.
    pub fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// The same pidfd, shared, for a caller that keeps it beyond this request.
    pub fn shared_pidfd(&self) -> Arc<OwnedFd> {
        Arc::clone(&self.pidfd)
    }

    /// The connecting process's thread-group id, as the kernel reported it
    /// when the connection was accepted.
    pub fn tgid(&self) -> i32 {
        self.tgid
    }
}
