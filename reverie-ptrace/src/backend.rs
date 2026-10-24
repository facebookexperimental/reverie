/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's implementation of the [`reverie::Backend`] contract.

use reverie::Backend;
use reverie::BackendCapabilities;
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

    fn capabilities() -> BackendCapabilities {
        BackendCapabilities::PTRACE
    }

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
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use reverie::BackendStatsSnapshot;
    use reverie::Errno;
    use reverie::Guest;
    use reverie::Pid;
    use reverie::Subscription;
    use reverie::Tid;
    use reverie::syscalls::Syscall;
    use reverie::syscalls::SyscallInfo;
    use reverie::syscalls::Sysno;

    use super::*;

    #[derive(Debug, Default)]
    struct SyscallCount(AtomicU64, Mutex<HashSet<i32>>);

    impl SyscallCount {
        fn only_tracee_tid(&self) -> i32 {
            let tids = self
                .1
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(tids.len(), 1, "the control must identify its actual tracee");
            *tids.iter().next().unwrap()
        }
    }

    #[reverie::global_tool]
    impl GlobalTool for SyscallCount {
        type Config = ();
        type Request = ();
        type Response = ();

        async fn receive_rpc(&self, _from: Pid, _request: ()) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug, Default)]
    struct CountEverySyscall;

    #[reverie::tool]
    impl Tool for CountEverySyscall {
        type GlobalState = SyscallCount;
        type ThreadState = ();

        fn subscriptions(_config: &()) -> Subscription {
            Subscription::all_syscalls()
        }

        fn on_thread_state_ready(
            &self,
            tid: Tid,
            global: &SyscallCount,
            _state: &Self::ThreadState,
        ) -> Result<(), Error> {
            global
                .1
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(tid.as_raw());
            Ok(())
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            guest.send_rpc(()).await;
            guest.tail_inject(syscall).await
        }
    }

    /// Plain ptrace dispatches every syscall through a seccomp stop: none is
    /// patched, and each stop reaches a Tool subscribed to all of them exactly
    /// once, in whichever process made it.
    #[tokio::test(flavor = "current_thread")]
    async fn dispatch_record_counts_each_tool_syscall_once_per_process() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/true; :"]);
        let (status, global, stats) =
            PtraceBackend::run_with_stats::<CountEverySyscall>(command, ())
                .await
                .unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        let record = stats.dispatch_stats().expect("ptrace measures dispatch");
        assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
        assert_eq!(record.backend, "ptrace");
        assert_eq!(record.counters.patched_direct_calls, Some(0), "{record}");
        assert_eq!(record.counters.signal_traps, Some(0), "{record}");
        assert_eq!(record.counters.ptrace_sigtrap_stops, Some(0), "{record}");
        assert_eq!(record.sites.patched, Some(0), "{record}");
        assert_eq!(stats.internal_seccomp_stops(), 0, "{record}");
        let tool_syscalls = global.0.load(Ordering::SeqCst);
        assert!(tool_syscalls > 0);
        assert_eq!(
            record.counters.dispatches(),
            Some(tool_syscalls),
            "{record}"
        );
        let processes = record
            .per_process
            .as_ref()
            .expect("ptrace attributes stops");
        assert_eq!(processes.len(), 2, "the shell forked /bin/true: {record}");
        assert_eq!(
            processes
                .iter()
                .map(|process| process.counters.ptrace_seccomp_stops)
                .sum::<Option<u64>>(),
            record.counters.ptrace_seccomp_stops,
            "{record}"
        );
    }

    /// Count only this host's actual tracee, retaining any pre-exec record too.
    fn canonicalized_count(tid: i32) -> usize {
        let host = std::thread::current().id();
        crate::task::CANONICALIZED_FOR_TEST
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(owner, recorded_tid)| *owner == host && *recorded_tid == tid)
            .count()
    }

    /// A new image gets the canonical vDSO and auxv at its exec stop:
    /// glibc's loader, asked to show the auxv, reports the canonical vDSO
    /// address and AT_HWCAP, and the image was canonicalized exactly once.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn an_execd_image_gets_the_canonical_vdso_and_auxv_once() {
        let mut command = Command::new("/bin/true");
        command.env("LD_SHOW_AUXV", "1");
        let (output, global, _stats) =
            PtraceBackend::run_with_output::<CountEverySyscall>(command, ())
                .await
                .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = |key: &str| {
            stdout
                .lines()
                .find(|line| line.starts_with(key))
                .unwrap_or_else(|| panic!("no {key} line in: {stdout}"))
                .to_owned()
        };
        assert!(line("AT_SYSINFO_EHDR:").ends_with("0x14f000"), "{stdout}");
        assert!(
            line("AT_HWCAP:").trim_end().ends_with("78bfbfd"),
            "{stdout}"
        );
        assert_eq!(canonicalized_count(global.only_tracee_tid()), 1);
    }

    /// The root's first stop comes before its exec, while its stack is still
    /// the launcher's (here a spawned function's). It must not be read as an
    /// initial process stack, so nothing is canonicalized for a tracee that
    /// never execs.
    #[tokio::test(flavor = "current_thread")]
    async fn a_tracee_that_never_execs_is_not_canonicalized() {
        let tracer = crate::tracer::spawn_fn::<CountEverySyscall, _>(|| {})
            .await
            .unwrap();
        let (status, global) = tracer.wait().await.unwrap();
        assert_eq!(status, ExitStatus::Exited(0));
        assert_eq!(canonicalized_count(global.only_tracee_tid()), 0);
    }

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

    /// The fixed address `guest_traced_mmap.c` asks `mmap` for.
    const TRACED_MMAP_HINT: u64 = 0x1000_0000_0000;

    #[derive(Debug, Default)]
    struct MappingCalls(AtomicU64);

    #[reverie::global_tool]
    impl GlobalTool for MappingCalls {
        /// Whether the Tool subscribes to `mmap`.
        type Config = bool;
        type Request = ();
        type Response = ();

        async fn receive_rpc(&self, _from: Pid, _request: ()) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Refuses the fixture's own `mmap` with `EACCES` and counts every call it
    /// sees, so a run shows whether that `mmap` reached the Tool.
    #[derive(Debug, Default)]
    struct RefuseFixtureMapping;

    #[reverie::tool]
    impl Tool for RefuseFixtureMapping {
        type GlobalState = MappingCalls;
        type ThreadState = ();

        fn subscriptions(subscribe_mmap: &bool) -> Subscription {
            let mut events = Subscription::none();
            if *subscribe_mmap {
                events.syscall(Sysno::mmap);
            }
            events
        }

        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> Result<i64, Error> {
            guest.send_rpc(()).await;
            let (nr, args) = syscall.into_parts();
            if nr == Sysno::mmap && args.arg0 as u64 == TRACED_MMAP_HINT {
                return Err(Errno::EACCES.into());
            }
            guest.tail_inject(Syscall::from_raw(nr, args)).await
        }
    }

    /// Builds `tests/fixtures/guest_traced_mmap.c` into the temporary
    /// directory and returns the binary's path.
    fn guest_traced_mmap() -> std::path::PathBuf {
        let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/guest_traced_mmap.c");
        let output =
            std::env::temp_dir().join(format!("reverie-guest-traced-mmap-{}", std::process::id()));
        let status = std::process::Command::new("timeout")
            .args([
                "--signal=TERM",
                "--kill-after=1s",
                "10s",
                "cc",
                "-std=c11",
                "-O1",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("run cc");
        assert!(status.success(), "cc {}: {status}", source.display());
        output
    }

    /// A guest-installed seccomp filter can return `SECCOMP_RET_TRACE` for a
    /// memory-mapping syscall the Tool did not subscribe to. The tracer runs
    /// that call itself and counts it in `internal_seccomp_stops`; the Tool
    /// never sees it, because only subscribed syscalls reach its handler.
    /// When the Tool does subscribe, the same call reaches it, and the
    /// tracer does not count it as internal.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test(flavor = "current_thread")]
    async fn unsubscribed_mapping_syscall_at_a_guest_trace_stop_bypasses_the_tool() {
        let binary = guest_traced_mmap();

        let (output, calls, stats) =
            PtraceBackend::run_with_output::<RefuseFixtureMapping>(Command::new(&binary), false)
                .await
                .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(String::from_utf8_lossy(&output.stdout), "mmap ok byte=42\n");
        assert_eq!(calls.0.load(Ordering::SeqCst), 0);
        assert_eq!(stats.internal_seccomp_stops(), 1);

        let (output, calls, stats) =
            PtraceBackend::run_with_output::<RefuseFixtureMapping>(Command::new(&binary), true)
                .await
                .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(String::from_utf8_lossy(&output.stdout), "mmap errno=13\n");
        assert!(calls.0.load(Ordering::SeqCst) > 0);
        assert_eq!(stats.internal_seccomp_stops(), 0);

        let _ = std::fs::remove_file(&binary);
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
