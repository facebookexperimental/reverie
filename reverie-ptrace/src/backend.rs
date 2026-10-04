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
use reverie::process::Output;
use reverie::process::Stdio;

use crate::PtraceBackendStatsSnapshot;
use crate::TracerBuilder;

/// The reference Reverie backend: supervises the guest with `ptrace` + `seccomp`
/// and keeps all tool state centralized in the tracer's address space.
///
/// This is a zero-sized marker type. Its purpose is to implement the
/// [`reverie::Backend`] trait, giving the ptrace backend a name in terms of the
/// abstract contract. It is a thin adapter over [`TracerBuilder`]/`Tracer`,
/// which is the richer, ptrace-specific API most callers reach for directly
/// (and which additionally supports a GDB server, spawning a function under
/// instrumentation, and lower-level lifecycle and stdio control).
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

    async fn run_with_output<T>(
        mut command: Command,
        config: <T::GlobalState as GlobalTool>::Config,
    ) -> Result<(Output, T::GlobalState, Self::Stats), Error>
    where
        T: Tool + 'static,
    {
        // `wait_with_output` only collects a stream the caller actually piped;
        // an inherited handle would yield empty buffers that read as "the guest
        // printed nothing". Pipe both here so the returned `Output` always
        // means what it says.
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        let tracer = TracerBuilder::<T>::new(command)
            .config(config)
            .backend_stats(BackendStatsRequest::ENABLED)
            .spawn()
            .await?;
        let stats = tracer
            .backend_stats()
            .expect("enabled ptrace run must create an activity-statistics source");
        let (output, global) = tracer.wait_with_output().await?;
        Ok((output, global, stats.backend_stats()))
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

    /// Assert on guest output through the backend-agnostic front door.
    ///
    /// This helper deliberately names **no concrete backend**. Before
    /// `run_with_output` was on the trait, a test that needed the guest's
    /// stdout had to reach for `TracerBuilder` + `Tracer::wait_with_output`,
    /// which is ptrace-specific -- so it could not be written once and run
    /// against any backend. That it compiles for an arbitrary `B: Backend` is
    /// the portability claim.
    async fn echoed_stdout_through_the_front_door<B: Backend>() -> Vec<u8> {
        let mut command = Command::new("/bin/echo");
        command.arg("front-door");
        let (output, (), _stats) = B::run_with_output::<()>(command, ()).await.unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));
        output.stdout
    }

    #[tokio::test(flavor = "current_thread")]
    async fn output_run_captures_guest_stdout_generically() {
        let stdout = echoed_stdout_through_the_front_door::<PtraceBackend>().await;
        assert_eq!(stdout, b"front-door\n");
    }

    /// The output path must not trade statistics away for output.
    ///
    /// A backend that piped stdio but returned an empty snapshot here would
    /// satisfy the type and still lose the measurement, which is the failure
    /// the no-default rule on `Stats` exists to prevent.
    #[tokio::test(flavor = "current_thread")]
    async fn output_run_also_reports_real_backend_activity() {
        let (output, (), stats) =
            PtraceBackend::run_with_output::<()>(Command::new("/bin/true"), ())
                .await
                .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));
        assert!(output.stdout.is_empty());
        assert_eq!(stats.tracees_started(), 1);
        assert!(stats.stop_events() > 0);
        assert_eq!(stats.exited_tracees(), 1);
    }

    /// An empty `stdout` must mean the guest printed nothing.
    ///
    /// Paired with `output_run_captures_guest_stdout_generically`, this is the
    /// two-sided bracket: a guest that prints yields those exact bytes, and a
    /// guest that does not yields empty -- so empty can never be read as "this
    /// backend declined to capture".
    #[tokio::test(flavor = "current_thread")]
    async fn output_run_reports_exact_bytes_for_loud_and_silent_guests() {
        let loud = echoed_stdout_through_the_front_door::<PtraceBackend>().await;
        let (quiet, (), _stats) =
            PtraceBackend::run_with_output::<()>(Command::new("/bin/true"), ())
                .await
                .unwrap();

        assert_eq!(loud, b"front-door\n");
        assert!(quiet.stdout.is_empty());
    }
}
