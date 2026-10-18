/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The optional patcher behind the shared in-guest runtime.
//!
//! The runtime owns every entry into the installed Tool: the SIGSYS
//! dispatcher and its fallback continuation, and the instruction (CPUID,
//! RDTSC, RDTSCP) fault handler. A patcher only decides whether a trapped
//! site gets a faster entry: a jump into a hook that enters the same shared
//! dispatch. Every [`Patcher`] method has a default that declines, and a
//! decline leaves the site as it is, so the original trapping instruction
//! keeps taking the trapped route. [`NoPatcher`] declines everything.
//!
//! LiteInst's patcher (its site tables, installation, jump-target proofs and
//! straddler policy) and SaBRe's load-time rewriting both sit behind this one
//! seam; nothing about syscall handling, state or RPC differs between them.

use crate::guest::event::InstructionEventKind;
use crate::guest::event::SyscallEvent;
use crate::guest::instruction::FaultSite;
use crate::guest::instruction::PatchOutcome;
use crate::guest::trap_dispatch::SitePatch;
use crate::stats::LiteinstDispatchPath;

/// What the shared runtime asks of an optional patcher.
///
/// The methods are called from the SIGSYS and SIGSEGV handlers (or a hook
/// that dispatches like them) and from the runtime's handling of a completed
/// syscall, inside the same callback-guard and branch-count extent as before
/// the seam existed. They must be async-signal-safe: no lock a guest thread
/// could hold and no system allocator (no `brk` or `mmap` from a handler).
/// Allocation from a heap reserved before the guest runs and safe to use from
/// a signal handler, as LiteInst's patch allocator is, is permitted. Any
/// syscall they make is nested runtime work.
///
/// # Safety
///
/// An implementation must keep each method's contract below. In particular a
/// method that declines ([`SitePatch::NotPatched`], [`FaultSite::Unpatchable`],
/// [`PatchOutcome::Emulate`]) must have left the site's code unchanged: the
/// runtime then resumes the guest just past the trapping instruction, which
/// is only correct while the code after it is the original.
pub unsafe trait Patcher: Send + Sync + 'static {
    /// The address of the trapped `syscall` instruction, given the address the
    /// trap resumes at (just past it).
    ///
    /// # Safety
    ///
    /// `resume_address` is the arrival resume address of a SIGSYS-delivered
    /// trap that has not run, so the code just before it was executing.
    unsafe fn syscall_site(&self, resume_address: u64) -> u64 {
        resume_address.saturating_sub(2)
    }

    /// Selects or installs a hook for this trap's site; [`SitePatch::NotPatched`]
    /// declines and the trap runs through the fallback continuation.
    ///
    /// # Safety
    ///
    /// `instruction_pointer` is what [`Self::syscall_site`] returned for a
    /// SIGSYS-delivered trap that has not run, and `number` is that trap's.
    unsafe fn patch_syscall_site(&self, _instruction_pointer: u64, _number: i64) -> SitePatch {
        SitePatch::NotPatched
    }

    /// How a trap the fallback continuation runs is classified in the backend
    /// statistics. Called only when statistics are collected.
    fn fallback_path(&self, _instruction_pointer: u64) -> LiteinstDispatchPath {
        LiteinstDispatchPath::PatchingDisabledFallback
    }

    /// Where a subscribed-instruction fault lies and whether its site can be
    /// patched. [`FaultSite::Unpatchable`] declines: the instruction is
    /// emulated through the fallback continuation.
    ///
    /// # Safety
    ///
    /// Called only from the instruction `SIGSEGV` handler for a fault at
    /// `address` (the frame's RIP). `info` may be null; `context` is the
    /// handler's kernel frame, valid for reads during the call.
    unsafe fn locate_instruction(
        &self,
        _address: u64,
        _info: *const libc::siginfo_t,
        _context: *const libc::ucontext_t,
    ) -> FaultSite {
        FaultSite::Unpatchable
    }

    /// Patches the site of a subscribed instruction that
    /// [`Self::locate_instruction`] reported as [`FaultSite::Patchable`];
    /// [`PatchOutcome::Emulate`] declines.
    ///
    /// # Safety
    ///
    /// Called only from the instruction `SIGSEGV` handler, never inside a Tool
    /// callback, with what [`Self::locate_instruction`] returned for `address`.
    unsafe fn patch_instruction(
        &self,
        _address: u64,
        _kind: InstructionEventKind,
        _encoding: &'static [u8],
    ) -> PatchOutcome {
        PatchOutcome::Emulate
    }

    /// Sees a completed syscall that may have changed the process's mappings
    /// (a Tool callback's own syscall, or a guest syscall the runtime ran).
    fn observe_mapping(&self, _event: &SyscallEvent) {}

    /// Counts a trap that no hook takes, before the continuation or refusal.
    fn record_fallback(&self, _number: i64) {}

    /// Counts a refused trap.
    fn record_refusal(&self, _number: i64) {}
}

/// The patcher that patches nothing: every trapped syscall runs through the
/// fallback continuation and every subscribed instruction is emulated.
pub struct NoPatcher;

// SAFETY: every method keeps its declining default, which changes no code.
unsafe impl Patcher for NoPatcher {}
