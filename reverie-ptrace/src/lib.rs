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

mod backend;
mod capture;
mod children;
mod cp;
#[allow(unused)]
#[cfg(target_arch = "x86_64")]
mod debug;
#[cfg(target_arch = "x86_64")]
pub mod decoder;
mod error;
mod failure;
mod gdbstub;
mod injected_syscall;
mod perf;
mod poll_on_wake;
pub mod regs;
mod segv_state;
#[cfg(all(test, target_arch = "x86_64"))]
mod signal_action_boundary_tests;
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
pub use failure::ToolRunCompletion;
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
