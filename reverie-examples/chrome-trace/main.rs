/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runs a process, gathering metadata about all of the processes that were ran
//! and displays it as a tree using Graphviz.

mod event;
mod global_state;
mod tool;

#[path = "../src/kvm_runner.rs"]
mod kvm_runner;

use std::fs;
use std::io;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use reverie::ExitStatus;
use reverie_util::CommonToolArguments;
// TODO-HUMAN-REVIEW(PR-159): Review crate-local reuse of the production ChromeTrace tool.
pub(crate) use tool::ChromeTrace;

/// A tool to render a summary of the process tree.
#[derive(Debug, Parser)]
struct Args {
    // TODO-HUMAN-REVIEW(PR-195): Review Chrome trace runner selection.
    /// Execution runner; KVM selects the prototype KvmGuest host.
    #[clap(long, value_enum, default_value = "ptrace")]
    runner: kvm_runner::Runner,

    #[clap(flatten)]
    common: CommonToolArguments,

    /// The path to write out Chrome trace file. This can be loaded with
    /// `chrome://tracing`.
    #[clap(long)]
    out: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let stdin = match args.runner {
        kvm_runner::Runner::Ptrace => None,
        kvm_runner::Runner::Kvm => kvm_runner::reserve_stdin()?,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_main(args, stdin))
}

async fn run_main(args: Args, stdin: Option<std::fs::File>) -> anyhow::Result<()> {
    let log_guard = args.common.init_tracing();
    let (status, global_state) = match args.runner {
        kvm_runner::Runner::Ptrace => {
            let tracer =
                reverie_ptrace::TracerBuilder::<ChromeTrace>::new(args.common.clone().into())
                    .spawn()
                    .await?;
            tracer.wait().await?
        }
        kvm_runner::Runner::Kvm => {
            let result = kvm_runner::run::<ChromeTrace>(&args.common, (), stdin).await?;
            (ExitStatus::Exited(result.exit_code), result.global_state)
        }
    };

    if let Some(path) = args.out {
        let mut f = io::BufWriter::new(fs::File::create(path)?);
        global_state
            .chrome_trace(&mut f)
            .context("failed to generate Chrome trace")?;
    }

    // Flush logs before exiting.
    drop(log_guard);
    status.raise_or_exit()
}
