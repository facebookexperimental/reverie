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
#[path = "../counter1.rs"]
mod counter1;
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
    /// Count every intercepted syscall through the shared global state.
    Counter1,
    /// Decode and print subscribed syscalls.
    Strace,
    /// Preserve guest behavior without subscribing to events.
    Noop,
}

impl ToolKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Counter1 => "counter1",
            Self::Strace => "strace",
            Self::Noop => "noop",
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the LiteInst example-tool result.
/// Captured result of a LiteInst example-tool run.
pub(crate) struct RunOutput {
    /// Guest process status and captured standard streams.
    pub(crate) output: Output,
    /// Final counter value for `counter1`; absent for other tools.
    pub(crate) counter_total: Option<u64>,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-139): Review the LiteInst example-tool launch boundary.
/// Runs one production example tool through `LiteinstBackend`.
///
/// `filters` accepts strace syscall filters and must be empty for other tools.
pub(crate) async fn run(
    kind: ToolKind,
    command: Command,
    filters: Vec<String>,
    preload: PathBuf,
) -> Result<RunOutput, reverie::Error> {
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
        ToolKind::Counter1 => {
            let (output, global) = LiteinstBackend::run_with_output_and_preload_data::<
                counter1::CounterLocal,
            >(command, (), preload, tool_data)
            .await?;
            Ok(RunOutput {
                output,
                counter_total: Some(global.total()),
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
                counter_total: None,
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
                counter_total: None,
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
