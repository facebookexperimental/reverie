/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

mod global_state;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use global_state::GlobalState;
use reverie_process::Command;
use reverie_process::ExitStatus;
use riptrace_rpc::Config;
use riptrace_rpc::MyService;

/// A super fast strace.
#[derive(Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    /// Count the number of calls for each system call and report a summary on
    /// program exit.
    #[clap(long, short = 'c')]
    summary: bool,

    /// Only log syscalls that failed.
    #[clap(long)]
    only_failures: bool,

    /// Don't log anything.
    #[clap(long, short)]
    quiet: bool,

    /// Output to this file instead of stderr.
    #[clap(long, short)]
    output: Option<PathBuf>,

    /// Path to the sabre binary used to launch the plugin.
    #[clap(long, env = "SABRE_PATH")]
    sabre: Option<PathBuf>,

    /// Path to the plugin.
    #[clap(long, env = "SABRE_PLUGIN")]
    plugin: Option<PathBuf>,

    /// The program and arguments.
    #[clap(required = true, multiple_values = true)]
    command: Vec<String>,
}

impl Args {
    async fn run(self) -> Result<ExitStatus> {
        let mut command = Command::new(&self.command[0]);
        command.args(&self.command[1..]);

        let config = Config {
            only_failures: self.only_failures,
            quiet: self.quiet,
        };

        let mut global_state = GlobalState::new(config);

        if let Some(path) = self.output {
            global_state.with_output(fs::File::create(path)?);
        }

        let global_state = Arc::new(global_state.serve());

        let mut child = reverie_host::TracerBuilder::new(command)
            .plugin(self.plugin)
            .sabre(self.sabre)
            .global_state(global_state.clone())
            .spawn()?;

        let exit_status = child.wait().await?;

        if self.summary {
            let count = global_state
                .count
                .load(core::sync::atomic::Ordering::Relaxed);

            eprintln!("Saw {} syscalls", count);
        }

        Ok(exit_status)
    }
}

fn main() {
    #[tokio::main]
    async fn _main() -> ExitStatus {
        match Args::parse().run().await {
            Ok(exit_status) => exit_status,
            Err(err) => {
                eprintln!("{:?}", err);
                ExitStatus::Exited(1)
            }
        }
    }

    // Make sure the tokio runtime exits before propagating the exit status.
    // This ensures that any Drop code gets a chance to run.
    //
    // TODO: Add a proc macro that does this instead.
    _main().raise_or_exit()
}
