/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Launcher for the shared counter2 tool on any Reverie backend (`--backend`).

mod counter2_tool;

#[path = "backend.rs"]
mod backend;

use clap::Parser;
use counter2_tool::CounterLocal;
use reverie_util::CommonToolArguments;

/// Run PROGRAM under the counter2 tool on BACKEND.
#[derive(Debug, Parser)]
struct Args {
    /// The Reverie backend to run the program on.
    #[clap(long, value_enum, default_value = "ptrace", alias = "runner")]
    backend: backend::BackendKind,
    /// The example preload the in-guest backends host the tool in; by
    /// default `libreverie_examples.so` beside this binary.
    #[clap(long)]
    preload: Option<std::path::PathBuf>,
    #[clap(flatten)]
    common: CommonToolArguments,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let log_guard = args.common.init_tracing();
    let run = backend::run_blocking::<CounterLocal>(
        args.backend,
        &args.common,
        (),
        "counter2",
        args.preload.clone(),
    )?;
    let (total, processes, threads) = run.global_state.totals();
    eprintln!(
        " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
        total, processes, threads
    );
    drop(log_guard);
    run.status.raise_or_exit()
}
