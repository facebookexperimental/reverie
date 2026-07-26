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
use clap::ValueEnum;
use reverie_process::Command;
use reverie_process::ExitStatus;

const TOOL_ENV: &str = "REVERIE_SABRE_TOOL";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ToolKind {
    Strace,
    Counter1,
    Noop,
}

impl ToolKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Strace => "strace",
            Self::Counter1 => "counter1",
            Self::Noop => "noop",
        }
    }
}

/// Run a program under a shared Reverie example tool using SaBRe.
#[derive(Parser)]
#[clap(trailing_var_arg = true)]
struct Args {
    /// Path to the SaBRe executable.
    #[clap(long, env = "SABRE_BINARY")]
    sabre: Option<PathBuf>,

    /// Path to libreverie_sabre_strace_plugin.so.
    #[clap(long, env = "SABRE_PLUGIN")]
    plugin: Option<PathBuf>,

    /// Shared Reverie tool to run in the SaBRe plugin.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-137): Review the SaBRe example-tool selector.
    #[clap(long, value_enum, default_value = "strace")]
    tool: ToolKind,

    /// Program and arguments to trace.
    #[clap(required = true, multiple_values = true)]
    command: Vec<String>,
}

impl Args {
    async fn run(self) -> Result<ExitStatus> {
        let mut command = Command::new(&self.command[0]);
        command.args(&self.command[1..]);
        command.env(TOOL_ENV, self.tool.as_str());
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
