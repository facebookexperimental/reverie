/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use reverie_process::Command;
use reverie_process::ExitStatus;

/// Run a program under the shared Reverie strace tool using SaBRe.
#[derive(Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    /// Path to the SaBRe executable.
    #[clap(long, env = "SABRE_BINARY")]
    sabre: Option<PathBuf>,

    /// Path to libreverie_sabre_strace_plugin.so.
    #[clap(long, env = "SABRE_PLUGIN")]
    plugin: Option<PathBuf>,

    /// Program and arguments to trace.
    #[clap(required = true, multiple_values = true)]
    command: Vec<String>,
}

impl Args {
    async fn run(self) -> Result<ExitStatus> {
        let mut command = Command::new(&self.command[0]);
        command.args(&self.command[1..]);
        let mut child = reverie_host::TracerBuilder::new(command)
            .sabre(self.sabre)
            .plugin(self.plugin)
            .spawn()?;
        Ok(child.wait().await?)
    }
}

fn main() {
    #[tokio::main(flavor = "current_thread")]
    async fn run() -> ExitStatus {
        Args::parse().run().await.unwrap_or_else(|error| {
            eprintln!("reverie-sabre-strace: {error:#}");
            ExitStatus::Exited(1)
        })
    }

    run().raise_or_exit();
}
