/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Correctness-first hybrid backend for e9patch syscall events.

use std::io;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;
use reverie::process::Output;
use reverie_ptrace::Tracer;
use reverie_ptrace::TracerBuilder;

use crate::E9PATCH_SYSCALL_TRAP_MARKER;
use crate::E9patchRewriter;

/// Hybrid e9patch backend with ptrace lifecycle and full `Guest` semantics.
///
/// Recovered syscall instructions in the root ELF are replaced by e9patch
/// trampolines and originate events through an injected register frame.
/// Ptrace remains attached for process lifecycle, shared-library syscalls,
/// signals, timers, and arbitrary-tool `Guest` operations. This is a real
/// e9patch event path, but it is not yet the planned ptrace-free fast path.
// TODO-HUMAN-REVIEW(PR-102): Review the public hybrid backend contract.
pub struct E9patchBackend;

impl E9patchBackend {
    async fn spawn<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Tracer<T::GlobalState>, tempfile::TempPath), Error>
    where
        T: Tool + 'static,
    {
        let source = command.find_program()?;
        let arg0 = command.get_arg0().to_owned();
        let prepared = E9patchRewriter::from_env()?.prepare(&source)?;

        // E9patch's loader reopens the executable, so an anonymous memfd is not
        // sufficient. Keep its path alive through tracer wait, but close the
        // writable descriptor before execve to avoid ETXTBSY.
        let mut executable = tempfile::Builder::new()
            .prefix("reverie-e9patch-guest-")
            .tempfile()?;
        let mut artifact = prepared.artifact()?;
        io::copy(&mut artifact, executable.as_file_mut())?;
        executable.as_file_mut().flush()?;
        let mut permissions = executable.as_file().metadata()?.permissions();
        permissions.set_mode(0o500);
        executable.as_file().set_permissions(permissions)?;
        let executable = executable.into_temp_path();

        command.program(&executable).arg0(arg0);
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .injected_syscall_trap(E9PATCH_SYSCALL_TRAP_MARKER)
            .spawn()
            .await?;
        Ok((tracer, executable))
    }

    /// Runs a tool and captures the rewritten guest's stdout and stderr.
    // TODO-HUMAN-REVIEW(PR-102): Review the public captured-output backend API.
    pub async fn run_with_output<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Output, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, executable) = Self::spawn::<T>(command, config).await?;
        let result = tracer.wait_with_output().await;
        drop(executable);
        result
    }
}

#[reverie::backend(?Send)]
impl Backend for E9patchBackend {
    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        let (tracer, executable) = Self::spawn::<T>(command, config).await?;
        let result = tracer.wait().await;
        drop(executable);
        result
    }
}
