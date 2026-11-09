/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie ptrace backend.
//!
//! Part of [Hermit](https://hermetic-infra.org). For the command-line interface,
//! see [`hermit-run`](https://crates.io/crates/hermit-run), and for background,
//! see [Hermit: Deterministic Linux for Controlled Testing and Software Bug-finding](https://developers.facebook.com/blog/post/2022/11/22/hermit-deterministic-linux-testing/).
//!
//! Default features build on stable Rust. The optional `nightly` feature lets
//! [`spawn_fn_with_config`] clear libtest's capture of printing macros before
//! forking; see that function's documentation for stable test alternatives.
//!
//! ptraced task implements `Guest` trait.
//!
//! `TracedTask` implements handlers for ptrace events including
//! seccomp. Notable ptrace events include:
//!
//! `PTRACE_EVENT_EXEC`: `execvpe` is about to return, tracee stopped
//!  at entry point.
//!
//! `PTRACE_EVENT_FORK/VFORK/CLONE`: when `fork`/`vfork`/`clone` is about
//! to return
//!
//! `PTRACE_EVENT_SECCOMP`: seccomp stop caused by `RET_TRACE`
//! NB: we patch syscall in seccomp ptrace stop.
//!
//! `PTRACE_EVENT_EXIT`: process is about to exit
//!
//! signals: tracee's pending signal stop.
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg(target_os = "linux")]
#![cfg_attr(feature = "nightly", feature(internal_output_capture))]

// The crate's own unit tests share test modules with its integration tests
// (`task::sigtrap_repair_page_tests` includes `tests/sigtrap_steps`), which
// name the crate as `reverie_ptrace`.
#[cfg(test)]
extern crate self as reverie_ptrace;

mod backend;
#[cfg(any(test, target_arch = "aarch64"))]
mod branch_step;
mod capture;
mod children;
mod cp;
#[allow(unused)]
#[cfg(target_arch = "x86_64")]
mod debug;
#[cfg(target_arch = "x86_64")]
pub mod decoder;
mod descriptor_status;
mod error;
mod failure;
mod gdbstub;
mod injected_syscall;
mod link_path;
mod memory_map;
#[cfg(all(test, target_arch = "x86_64"))]
mod offset_step_interruption_tests;
mod perf;
mod pidfd_self;
mod poll_on_wake;
pub mod regs;
mod segv_state;
#[cfg(all(test, target_arch = "x86_64"))]
mod signal_action_boundary_tests;
mod signal_sets;
mod sigtrap_state;
mod stack;
mod stats;
mod task;
pub mod testing;
mod timer;
mod tool_memory;
mod tracer;
mod validation;
mod vdso;
mod watch;

// Shared with the transient opens in reverie-core and safeptrace.
pub use backend::PtraceBackend;
pub use failure::BrokenSignalApproval;
pub use failure::CapturedPrefix;
pub use failure::LegacyCleanupDiagnostics;
pub use failure::LegacyFailureProjection;
pub use failure::PendingSigtrapAtStep;
pub use failure::PtraceCallbackDecision;
pub use failure::PtraceCallbackDiagnostic;
pub use failure::PtraceCallbackOutcome;
pub use failure::PtraceCallbackRefusal;
pub use failure::PtraceCallbackStop;
pub use failure::PtraceCleanupFailure;
pub use failure::PtraceRunFailure;
pub use failure::QueuedSigtrapAtStep;
pub use failure::ToolRunCompletion;
pub use failure::UnattributedSigtrap;
pub use failure::UnprovenPrivateSyscallCompletion;
pub use failure::UntracedStubSyscall;
pub use injected_syscall::InjectedSyscallFrame;
pub use perf::is_perf_supported;
pub use perf::pmu_validation;
pub use reverie::InGuestRcbCounter;
use reverie::process::launch_window;
pub use reverie::vdso::VdsoSyscallSite;
#[cfg(target_arch = "x86_64")]
pub use reverie::vdso::patch_current_vdso;
#[cfg(target_arch = "x86_64")]
pub use reverie::vdso::patch_current_vdso_trapping;
#[cfg(target_arch = "x86_64")]
pub use reverie::vdso::patch_current_vdso_trapping_owned;
pub use stats::PtraceBackendStatsSnapshot;
pub use stats::PtraceBackendStatsSource;
pub use timer::PmuConfig;
pub use timer::SKID_OVERSHOOT_MARKER;
pub use timer::host_pmu_profile;
pub use timer::set_pmu_config;
pub use timer::set_skid_margin_override;
pub use tool_memory::ToolMemory;
pub use tracer::CleanupAdmissionRefused;
pub use tracer::CleanupLookupError;
pub use tracer::CleanupUnconfirmed;
pub use tracer::GdbConnection;
pub use tracer::InjectedCleanupUnconfirmed;
pub use tracer::PendingPtraceCleanup;
pub use tracer::PtraceCleanupResource;
pub use tracer::PtraceTerminationHandle;
pub use tracer::ToolRunOutcome;
pub use tracer::Tracer;
pub use tracer::TracerBuilder;
pub use tracer::quarantine_cleanup_resource;
pub use tracer::spawn_fn;
pub use tracer::spawn_fn_with_config;
pub use validation::PmuValidationError;

/// CPU-seconds a test's `cc` fixture build may consume. Each fixture
/// is tens of lines of C and builds in well under a CPU-second, so
/// this is generous headroom against a runaway compiler, not a
/// scheduling deadline.
#[cfg(test)]
const FIXTURE_COMPILE_CPU_SECONDS: u64 = 30;

/// Compiles one `tests/fixtures` C source for a unit test, bounding
/// the compiler by CPU time rather than wall time.
///
/// Fixtures build on the test host at run time (the binary may be
/// built elsewhere), so the bound must not be a wall clock: under
/// host load a 1 s wall timeout killed compiles that had used only
/// milliseconds of CPU, failing tests before they tested anything
/// (dh-uelw3). `RLIMIT_CPU` is inherited by the `cc` driver's
/// children, each holding its own budget; wall time is left to the
/// test harness.
#[cfg(test)]
pub(crate) fn compile_c_fixture(
    source: &std::path::Path,
    output: &std::path::Path,
) -> std::process::ExitStatus {
    compile_c_fixture_bounded(source, output, FIXTURE_COMPILE_CPU_SECONDS)
}

#[cfg(test)]
fn compile_c_fixture_bounded(
    source: &std::path::Path,
    output: &std::path::Path,
    cpu_seconds: u64,
) -> std::process::ExitStatus {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new("cc");
    command
        .args(["-std=c11", "-O1"])
        .arg(source)
        .arg("-o")
        .arg(output);
    // SAFETY: the callback only sets this child's own CPU rlimit
    // between fork and exec and touches no other state.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: cpu_seconds,
                rlim_max: cpu_seconds,
            };
            if libc::setrlimit(libc::RLIMIT_CPU, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.status().expect("run cc")
}

#[cfg(test)]
mod compile_c_fixture_tests {
    #[test]
    fn fixture_compile_uses_a_cpu_bound_not_a_wall_bound() {
        let directory =
            std::env::temp_dir().join(format!("reverie-compile-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("probe.c");
        std::fs::write(&source, "int main(void) { return 42; }\n").unwrap();

        let output = directory.join("probe");
        let status = super::compile_c_fixture(&source, &output);
        assert!(status.success(), "compile probe fixture: {status}");
        let ran = std::process::Command::new(&output).status().unwrap();
        assert_eq!(ran.code(), Some(42));

        // A zero CPU budget kills the compiler itself: the bound is
        // really on the toolchain's CPU, and a nonzero budget many
        // times the fixture's own CPU cost is what lets it build.
        let starved = super::compile_c_fixture_bounded(&source, &directory.join("starved"), 0);
        assert!(!starved.success(), "zero CPU budget built: {starved}");

        std::fs::remove_dir_all(&directory).unwrap();
    }
}
