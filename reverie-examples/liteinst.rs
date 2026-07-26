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

#[derive(Debug, Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    #[clap(long, value_enum)]
    tool: example_tools::ToolKind,

    #[clap(long)]
    preload: Option<PathBuf>,

    #[clap(long = "trace")]
    filters: Vec<String>,

    #[clap(required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if args.tool != example_tools::ToolKind::Strace && !args.filters.is_empty() {
        bail!("--trace is only valid with --tool strace");
    }

    let preload = match args.preload {
        Some(path) => path,
        None => example_tools::default_preload_path()?,
    };
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    let result = example_tools::run(args.tool, command, args.filters, preload).await?;

    std::io::stdout().write_all(&result.output.stdout)?;
    std::io::stderr().write_all(&result.output.stderr)?;
    if let Some(total) = result.counter_total {
        eprintln!(" [counter tool] Total system calls in process tree: {total}");
    }

    let status: ExitStatus = result.output.status.into();
    status.raise_or_exit()
}
