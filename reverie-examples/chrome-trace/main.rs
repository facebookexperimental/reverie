/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
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

use tool::ChromeTrace;

use structopt::StructOpt;

use anyhow::Context;
use reverie::Error;
use reverie_util::CommonToolArguments;

use std::fs;
use std::io;
use std::path::PathBuf;

/// A tool to render a summary of the process tree.
#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(flatten)]
    common: CommonToolArguments,

    /// The path to write out Chrome trace file. This can be loaded with
    /// `chrome://tracing`.
    #[structopt(long)]
    out: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::from_args();

    let log_guard = args.common.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<ChromeTrace>::new(args.common.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;

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
