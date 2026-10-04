/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie ptrace backend.
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
#![feature(internal_output_capture)]

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
mod in_guest;
mod injected_syscall;
pub mod liteinst_census;
mod liteinst_restart;
mod liteinst_stats;
mod liteinst_trap_only;
mod perf;
mod poll_on_wake;
pub mod regs;
mod stack;
mod stats;
#[cfg(target_arch = "x86_64")]
pub mod target_loader;
mod task;
pub mod testing;
mod timer;
mod tracer;
mod validation;
mod vdso;

pub use backend::PtraceBackend;
pub use failure::CapturedPrefix;
pub use failure::LegacyCleanupDiagnostics;
pub use failure::LegacyFailureProjection;
pub use failure::PtraceCallbackDecision;
pub use failure::PtraceCallbackDiagnostic;
pub use failure::PtraceCallbackOutcome;
pub use failure::PtraceCallbackRefusal;
pub use failure::PtraceCallbackStop;
pub use failure::PtraceCleanupFailure;
pub use failure::PtraceRunFailure;
pub use failure::ToolRunCompletion;
pub use in_guest::InGuestRcbCounter;
pub use injected_syscall::InjectedSyscallFrame;
pub use liteinst_stats::LiteinstInstrumentationStats;
pub use liteinst_stats::LiteinstInstrumentationStatsHandle;
pub use liteinst_trap_only::Ia32EmulationProbe;
pub use liteinst_trap_only::Ia32EmulationUnavailable;
pub use liteinst_trap_only::Ia32EntryClobbersRegisters;
pub use liteinst_trap_only::LiteinstTrapOnlyHandle;
pub use liteinst_trap_only::SitePatching;
pub use liteinst_trap_only::SiteTable;
pub use liteinst_trap_only::probe_ia32_emulation;
pub use perf::is_perf_supported;
pub use stats::PtraceBackendStatsSnapshot;
pub use stats::PtraceBackendStatsSource;
pub use timer::PmuConfig;
pub use timer::SKID_OVERSHOOT_MARKER;
pub use timer::set_pmu_config;
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
pub use vdso::VdsoSyscallSite;
#[cfg(target_arch = "x86_64")]
pub use vdso::patch_current_vdso;
