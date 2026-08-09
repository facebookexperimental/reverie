/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's implementation of the [`reverie::Backend`] contract.

use reverie::Backend;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Tool;
use reverie::process::Command;

use crate::PtraceBackendStatsSnapshot;
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
    type Stats = PtraceBackendStatsSnapshot;

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

    async fn run_with_stats<T>(
        command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(ExitStatus, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .backend_stats(BackendStatsRequest::ENABLED)
            .spawn()
            .await?;
        let stats = tracer
            .backend_stats()
            .expect("enabled ptrace run must create an activity-statistics source");
        let (status, global) = tracer.wait().await?;
        Ok((status, global, stats.backend_stats()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn stats_run_observes_real_tracee_activity() {
        let (status, (), stats) =
            PtraceBackend::run_with_stats::<()>(Command::new("/bin/true"), ())
                .await
                .unwrap();

        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(stats.tracees_started(), 1);
        assert!(stats.stop_events() > 0);
        assert_eq!(stats.exited_tracees(), 1);
        assert!(stats.exec_stops() > 0);
    }
}
