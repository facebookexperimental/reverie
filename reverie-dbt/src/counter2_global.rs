/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The launcher decodes this global state without loading the in-process
// prototype runtime. Keep its wire request and accounting in both feature shapes.
use std::sync::Mutex;

use reverie::GlobalTool;
use reverie::Tid;
use serde::Deserialize;
use serde::Serialize;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-150): Review the DBT counter2 Tool port and lifecycle accounting.
#[derive(Debug, Default)]
struct Counter2Totals {
    total_syscalls: u64,
    exited_processes: u64,
    exited_threads: u64,
}

/// Coordinator-owned totals reported by DBT counter2 processes at exit.
#[derive(Debug, Default)]
pub struct Counter2Global {
    totals: Mutex<Counter2Totals>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counter2Request {
    pub(super) syscalls: u64,
    pub(super) threads: u64,
}

#[reverie::global_tool]
impl GlobalTool for Counter2Global {
    type Request = Counter2Request;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, request: Counter2Request) {
        let mut totals = self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        totals.total_syscalls += request.syscalls;
        totals.exited_threads += request.threads;
        totals.exited_processes += 1;
    }
}

impl Counter2Global {
    /// Returns aggregate `(syscalls, processes, threads)` totals.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        let totals = self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            totals.total_syscalls,
            totals.exited_processes,
            totals.exited_threads,
        )
    }
}
