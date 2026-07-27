/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Ptrace launcher for the shared counter2 tool.

mod counter2_tool;

use clap::Parser;
use counter2_tool::CounterLocal;
use reverie::Error;
use reverie_util::CommonToolArguments;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::parse();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<CounterLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    let (total, processes, threads) = global_state.totals();
    eprintln!(
        " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
        total, processes, threads
    );
    drop(log_guard);
    status.raise_or_exit()
}
