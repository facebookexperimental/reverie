/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! LiteInst hosting support for the production Reverie example tools.

#![forbid(unsafe_op_in_unsafe_fn)]
// The reused production tool sources each declare the same test-only KVM helper.
#![allow(clippy::duplicate_mod)]

use std::io;
use std::path::PathBuf;
use std::process::Output;

use reverie::process::Command;
use reverie_liteinst::LiteinstBackend;

#[allow(dead_code)]
#[path = "../chaos.rs"]
mod chaos;

// TODO-HUMAN-REVIEW(PR-157): Review the narrow chaos config re-export.
pub(crate) use chaos::ChaosOpts;

#[allow(dead_code)]
#[path = "../chrome-trace/main.rs"]
mod chrome_trace;

#[allow(dead_code)]
#[path = "../chunky_print.rs"]
mod chunky_print;
#[allow(dead_code)]
#[path = "../counter1_tool.rs"]
mod counter1;

#[allow(dead_code)]
#[path = "../counter2_tool.rs"]
mod counter2;
#[allow(dead_code)]
#[path = "../noop.rs"]
mod noop;
#[allow(dead_code)]
#[path = "../strace/main.rs"]
pub(crate) mod strace;

pub(crate) use strace::config;
pub(crate) use strace::filter;
pub(crate) use strace::global_state;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the LiteInst example-tool selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
/// Production example tool hosted by the LiteInst preload.
pub(crate) enum ToolKind {
    /// Introduce short reads and optional interrupted reads.
    // TODO-HUMAN-REVIEW(PR-157): Review the chaos LiteInst selector extension.
    Chaos,
    /// Capture process lifecycle and syscall events as a Chrome trace.
    // TODO-HUMAN-REVIEW(PR-159): Review the ChromeTrace LiteInst selector extension.
    ChromeTrace,
    /// Count every intercepted syscall through the shared global state.
    Counter1,
    /// Aggregate per-thread and per-process syscall counts in global state.
    // TODO-HUMAN-REVIEW(PR-146): Review the counter2 LiteInst selector extension.
    Counter2,
    /// Buffer standard output and error writes by logical epochs.
    // TODO-HUMAN-REVIEW(PR-152): Review the chunky_print LiteInst selector extension.
    ChunkyPrint,
    /// Decode and print subscribed syscalls.
    Strace,
    /// Preserve guest behavior without subscribing to events.
    Noop,
}

impl ToolKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chaos => "chaos",
            Self::Counter1 => "counter1",
            Self::ChromeTrace => "chrome-trace",
            Self::Counter2 => "counter2",
            Self::Strace => "strace",
            Self::ChunkyPrint => "chunky-print",
            Self::Noop => "noop",
        }
    }
}

// TODO-HUMAN-REVIEW(PR-146): Review the shared LiteInst counter result API.
pub(crate) enum CounterSummary {
    Counter1 {
        total_syscalls: u64,
    },
    Counter2 {
        total_syscalls: u64,
        processes: u64,
        threads: u64,
    },
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the LiteInst example-tool result.
/// Captured result of a LiteInst example-tool run.
pub(crate) struct RunOutput {
    /// Guest process status and captured standard streams.
    pub(crate) output: Output,
    /// Serialized Chrome trace events; present only for `ChromeTrace`.
    // TODO-HUMAN-REVIEW(PR-159): Review the ChromeTrace artifact result field.
    pub(crate) chrome_trace: Option<Vec<u8>>,
    /// Final structured result for counter tools; absent for other tools.
    // TODO-HUMAN-REVIEW(PR-146): Review the typed counter result field.
    pub(crate) counter_summary: Option<CounterSummary>,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the LiteInst example-tool launch boundary.
/// Runs one production example tool through `LiteinstBackend`.
///
/// `filters` accepts strace syscall filters and must be empty for other tools.
// TODO-HUMAN-REVIEW(PR-157): Review the chaos config extension to the host API.
pub(crate) async fn run(
    kind: ToolKind,
    command: Command,
    filters: Vec<String>,
    chaos_options: ChaosOpts,
    preload: PathBuf,
) -> Result<RunOutput, reverie::Error> {
    if kind != ToolKind::Chaos && chaos_options != ChaosOpts::default() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "chaos options require the chaos tool",
        )
        .into());
    }
    let filters = if kind == ToolKind::Strace {
        filters
            .into_iter()
            .map(|filter| filter.parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
    } else if filters.is_empty() {
        Vec::new()
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "strace filters require the strace tool",
        )
        .into());
    };
    let tool_data = kind.as_str().as_bytes().to_vec();
    match kind {
        // TODO-HUMAN-REVIEW(PR-157): Review the exact chaos LiteInst host path.
        ToolKind::Chaos => {
            let (output, _) =
                LiteinstBackend::run_with_output_and_preload_data::<chaos::ChaosTool>(
                    command,
                    chaos_options,
                    preload,
                    tool_data,
                )
                .await?;
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: None,
            })
        }
        // TODO-HUMAN-REVIEW(PR-159): Review the exact ChromeTrace LiteInst host path.
        ToolKind::ChromeTrace => {
            let (output, global) = LiteinstBackend::run_with_output_and_preload_data::<
                chrome_trace::ChromeTrace,
            >(command, (), preload, tool_data)
            .await?;
            let mut trace = Vec::new();
            global
                .chrome_trace(&mut trace)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            Ok(RunOutput {
                output,
                chrome_trace: Some(trace),
                counter_summary: None,
            })
        }
        ToolKind::Counter1 => {
            let (output, global) = LiteinstBackend::run_with_output_and_preload_data::<
                counter1::CounterLocal,
            >(command, (), preload, tool_data)
            .await?;
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: Some(CounterSummary::Counter1 {
                    total_syscalls: global.total(),
                }),
            })
        }
        // TODO-HUMAN-REVIEW(PR-146): Review the exact counter2 LiteInst host path.
        ToolKind::Counter2 => {
            let (output, global) = LiteinstBackend::run_with_output_and_preload_data::<
                counter2::CounterLocal,
            >(command, (), preload, tool_data)
            .await?;
            let counter_summary = {
                let inner = global.inner.lock().unwrap();
                CounterSummary::Counter2 {
                    total_syscalls: inner.total_syscalls,
                    processes: inner.exited_procs,
                    threads: inner.exited_threads,
                }
            };
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: Some(counter_summary),
            })
        }
        // TODO-HUMAN-REVIEW(PR-152): Review the exact chunky_print LiteInst host path.
        ToolKind::ChunkyPrint => {
            let (output, global) = LiteinstBackend::run_with_inherited_stdio_and_preload_data::<
                chunky_print::ChunkyPrintLocal,
            >(command, (), preload, tool_data)
            .await?;
            let _ = global.flush();
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: None,
            })
        }
        ToolKind::Strace => {
            let (output, _) = LiteinstBackend::run_with_output_and_preload_data::<strace::Strace>(
                command,
                strace::Config { filters },
                preload,
                tool_data,
            )
            .await?;
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: None,
            })
        }
        ToolKind::Noop => {
            let (output, _) = LiteinstBackend::run_with_output_and_preload_data::<noop::NoopTool>(
                command,
                (),
                preload,
                tool_data,
            )
            .await?;
            Ok(RunOutput {
                output,
                chrome_trace: None,
                counter_summary: None,
            })
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the example preload discovery API.
/// Finds the package preload DSO beside the current executable.
pub(crate) fn default_preload_path() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    let parent = executable.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "launcher executable has no parent")
    })?;
    [
        parent.join("libreverie_examples.so"),
        parent.join("deps/libreverie_examples.so"),
        parent
            .parent()
            .unwrap_or(parent)
            .join("libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find libreverie_examples.so beside {}",
                executable.display()
            ),
        )
    })
}
