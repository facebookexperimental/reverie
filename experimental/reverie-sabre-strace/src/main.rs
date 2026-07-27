/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::path::PathBuf;

use anyhow::Result;
use anyhow::bail;
use clap::Parser;
use clap::ValueEnum;
use reverie_process::Command;
use reverie_process::ExitStatus;
use reverie_sabre_strace_plugin::ChaosOptions;
use reverie_sabre_strace_plugin::CounterTool;

const TOOL_ENV: &str = "REVERIE_SABRE_TOOL";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum ToolKind {
    Chaos,
    ChromeTrace,
    ChunkyPrint,
    Strace,
    Counter1,
    Counter1Exact,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-142): Review counter2 CLI selection.
    Counter2,
    Counter2Exact,
    Noop,
}

impl ToolKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chaos => "chaos",
            Self::ChromeTrace => "chrome-trace",
            Self::ChunkyPrint => "chunky-print",
            Self::Strace => "strace",
            Self::Counter1 => "counter1",
            Self::Counter1Exact => "counter1-exact",
            Self::Counter2 => "counter2",
            Self::Counter2Exact => "counter2-exact",
            Self::Noop => "noop",
        }
    }
}

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
}

impl From<ChaosCliOptions> for ChaosOptions {
    fn from(options: ChaosCliOptions) -> Self {
        Self {
            skip: options.skip,
            no_read: options.no_read,
            no_recv: options.no_recv,
            no_interrupt: options.no_interrupt,
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

    /// Path to write the Chrome trace artifact.
    #[clap(long)]
    out: Option<PathBuf>,

    #[clap(flatten)]
    chaos_options: ChaosCliOptions,

    /// Program and arguments to trace.
    #[clap(required = true, num_args = 1.., allow_hyphen_values = true)]
    command: Vec<String>,
}

impl Args {
    async fn run(self) -> Result<ExitStatus> {
        if self.tool != ToolKind::ChromeTrace && self.out.is_some() {
            bail!("--out is only valid with --tool chrome-trace");
        }
        if self.tool != ToolKind::Chaos && self.chaos_options.was_supplied() {
            bail!("chaos options are only valid with --tool chaos");
        }

        let mut command = Command::new(&self.command[0]);
        command.args(&self.command[1..]);
        command.env(TOOL_ENV, self.tool.as_str());

        let counter = match self.tool {
            ToolKind::Counter1 => Some(CounterTool::Counter1),
            ToolKind::Counter1Exact => Some(CounterTool::Counter1Exact),
            ToolKind::Counter2 => Some(CounterTool::Counter2),
            ToolKind::Counter2Exact => Some(CounterTool::Counter2Exact),
            _ => None,
        };
        if let Some(counter) = counter {
            return reverie_sabre_strace_plugin::run_counter(
                counter,
                command,
                self.sabre,
                self.plugin,
            )
            .await;
        }

        match self.tool {
            ToolKind::Chaos => {
                return reverie_sabre_strace_plugin::run_chaos(
                    command,
                    self.sabre,
                    self.plugin,
                    self.chaos_options.into(),
                )
                .await;
            }
            ToolKind::ChromeTrace => {
                return reverie_sabre_strace_plugin::run_chrome_trace(
                    command,
                    self.sabre,
                    self.plugin,
                    self.out,
                )
                .await;
            }
            ToolKind::ChunkyPrint => {
                return reverie_sabre_strace_plugin::run_chunky_print(
                    command,
                    self.sabre,
                    self.plugin,
                )
                .await;
            }
            _ => {}
        }

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
