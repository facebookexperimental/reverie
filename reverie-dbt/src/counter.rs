/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A syscall-counting [`GlobalTool`] with real (non-`()`) serde state, used to
//! validate the DBT backend's cross-process GlobalState IPC.
//!
//! Unlike the process-local histogram in [`crate::tools`], this global lives in
//! a single coordinator process (e.g. `hermit-cli`, which hosts a
//! [`reverie_rpc_transport::RpcServer`]). Every guest process — including every
//! `fork(2)` child — records its syscalls into this one instance over a
//! Unix-domain socket (see [`crate::sync_rpc`]), so the final histogram is the
//! true total across the whole process tree rather than a per-process count.
//!
//! The type is intentionally public and not gated behind `prototype-runtime` so
//! the coordinator crate can name it when binding its `RpcServer`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use reverie::GlobalTool;
use reverie::Tid;
use serde::Deserialize;
use serde::Serialize;

/// RPC request: record one syscall, identified by its raw number, into the
/// shared histogram. Mirrors the `IncrMsg` pattern of `reverie-examples/counter1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSyscall(pub i32);

/// The shared, cross-process syscall histogram.
#[derive(Debug, Default)]
pub struct SyscallCounterGlobal {
    histogram: Mutex<BTreeMap<i32, u64>>,
}

#[reverie::global_tool]
impl GlobalTool for SyscallCounterGlobal {
    type Request = RecordSyscall;
    type Response = ();
    type Config = ();

    async fn receive_rpc(
        &self,
        _from: Tid,
        RecordSyscall(number): RecordSyscall,
    ) -> Self::Response {
        *self
            .histogram
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(number)
            .or_insert(0) += 1;
    }
}

impl SyscallCounterGlobal {
    /// Snapshot the shared histogram as `(syscall number, count)` pairs, sorted
    /// by syscall number.
    pub fn snapshot(&self) -> Vec<(i32, u64)> {
        self.histogram
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(number, count)| (*number, *count))
            .collect()
    }

    /// Total number of syscalls recorded across every connected process.
    pub fn total(&self) -> u64 {
        self.histogram
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .sum()
    }
}
