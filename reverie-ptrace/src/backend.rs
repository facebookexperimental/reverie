/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's implementation of the [`reverie::Backend`] contract.

use reverie::Backend;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;

use crate::TracerBuilder;

/// The reference Reverie backend: supervises the guest with `ptrace` + `seccomp`
/// and keeps all tool state centralized in the tracer's address space.
///
/// This is a zero-sized marker type. Its purpose is to implement the
/// [`reverie::Backend`] trait, giving the ptrace backend a name in terms of the
/// abstract contract. It is a thin adapter over [`TracerBuilder`]/`Tracer`,
/// which is the richer, ptrace-specific API most callers reach for directly
/// (and which additionally supports output capture, a GDB server, and spawning
/// a function under instrumentation).
///
/// # Example
///
/// ```no_run
/// use reverie::Backend;
/// use reverie::process::Command;
/// use reverie_ptrace::PtraceBackend;
///
/// # async fn run() -> Result<(), reverie::Error> {
/// // Run `ls` under a no-op tool (`()` implements `Tool`).
/// let (status, _global_state) = PtraceBackend::run::<()>(Command::new("ls"), ()).await?;
/// println!("guest exited with {:?}", status);
/// # Ok(())
/// # }
/// ```
pub struct PtraceBackend;

#[reverie::backend(?Send)]
impl Backend for PtraceBackend {
    async fn run<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState), Error>
    where
        T: Tool + 'static,
    {
        // `spawn` drives `init_global_state`, computes `subscriptions`, spawns
        // the guest, and installs the seccomp filter; `wait` runs the guest to
        // completion, routing every subscribed event to `T`'s handlers, and
        // returns the exit status together with the tool's final global state.
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .spawn()
            .await?;
        tracer.wait().await
    }
}
