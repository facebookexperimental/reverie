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
    if args.backend == backend::BackendKind::E9patch {
        // SAFETY: no other thread runs yet; the runtime starts below.
        unsafe { backend::use_bundled_e9patch() };
    }
    let preload_path = args.preload.clone().or_else(|| {
        std::env::current_exe()
            .ok()
            .and_then(|executable| backend::default_preload_path(&executable))
    });
    let preload = preload_path.as_deref().map(|path| backend::Preload {
        tool: "counter2",
        path,
    });
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let run = runtime
        .block_on(backend::run::<CounterLocal>(
            args.backend,
            &args.common,
            (),
            preload,
        ))
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if let Some((stdout, stderr)) = &run.captured {
        use std::io::Write as _;
        std::io::stdout().write_all(stdout)?;
        std::io::stderr().write_all(stderr)?;
    }
    let (total, processes, threads) = run.global_state.totals();
    eprintln!(
        " [counter tool] Total system calls in process tree: {}, from {} processes, {} thread(s).",
        total, processes, threads
    );
    drop(log_guard);
    std::process::exit(run.exit_code)
}
