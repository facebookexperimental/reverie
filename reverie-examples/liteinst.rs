/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Run the production Reverie example tools with the LiteInst backend.

use std::io::Write;
use std::path::PathBuf;

use anyhow::bail;
use clap::Parser;
use reverie::ExitStatus;
use reverie::process::Command;
#[path = "src/host.rs"]
mod example_tools;

// TODO-HUMAN-REVIEW(PR-139): Review crate-local strace source reuse.
pub(crate) use example_tools::config;
pub(crate) use example_tools::filter;
pub(crate) use example_tools::global_state;

#[derive(Debug, Default, clap::Args)]
struct ChaosCliOptions {
    /// Skips the first N syscalls before doing any intervention.
    #[clap(long, value_name = "N")]
    skip: Option<u64>,

    /// Does not modify read-like system calls.
    #[clap(long)]
    no_read: bool,

    /// Does not modify recv-like system calls.
    #[clap(long)]
    no_recv: bool,

    /// Does not inject interrupted-read errors.
    #[clap(long)]
    no_interrupt: bool,
}

impl ChaosCliOptions {
    fn was_supplied(&self) -> bool {
        self.skip.is_some() || self.no_read || self.no_recv || self.no_interrupt
    }

    fn into_config(self) -> example_tools::ChaosOpts {
        example_tools::ChaosOpts::for_liteinst(
            self.skip,
            self.no_read,
            self.no_recv,
            self.no_interrupt,
        )
    }
}

#[derive(Debug, Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    #[clap(long, value_enum)]
    tool: example_tools::ToolKind,

    #[clap(long)]
    preload: Option<PathBuf>,

    #[clap(long = "trace")]
    filters: Vec<String>,

    // TODO-HUMAN-REVIEW(PR-157): Review the production chaos option surface.
    #[clap(flatten)]
    chaos_options: ChaosCliOptions,

    #[clap(required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.tool != example_tools::ToolKind::Strace && !args.filters.is_empty() {
        bail!("--trace is only valid with --tool strace");
    }
    if args.tool != example_tools::ToolKind::Chaos && args.chaos_options.was_supplied() {
        bail!("chaos options are only valid with --tool chaos");
    }
    let chaos_options = args.chaos_options.into_config();

    let preload = match args.preload {
        Some(path) => path,
        None => example_tools::default_preload_path()?,
    };
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    let result =
        example_tools::run(args.tool, command, args.filters, chaos_options, preload).await?;

    std::io::stdout().write_all(&result.output.stdout)?;
    std::io::stderr().write_all(&result.output.stderr)?;
    match result.counter_summary {
        Some(example_tools::CounterSummary::Counter1 { total_syscalls }) => {
            eprintln!(" [counter tool] Total system calls in process tree: {total_syscalls}");
        }
        Some(example_tools::CounterSummary::Counter2 {
            total_syscalls,
            processes,
            threads,
        }) => {
            eprintln!(
                " [counter tool] Total system calls in process tree: {total_syscalls}, from {processes} processes, {threads} thread(s)."
            );
        }
        None => {}
    }

    let status: ExitStatus = result.output.status.into();
    status.raise_or_exit()
}
