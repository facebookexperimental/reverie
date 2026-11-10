/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! arm64 watchpoints: not implemented, so a thread holds none and every
//! request is refused ([`WatchError::Unsupported`]).
//!
//! The plan, for when they are needed:
//!
//! - Arm through `PTRACE_SETREGSET` with `NT_ARM_HW_WATCH` (a
//!   `struct user_hwdebug_state`); the thread's slot count is the low byte of
//!   its `dbg_info`.
//! - A hit is matched to its slot by the siginfo's `si_addr`, which is the
//!   accessed address.
//! - arm64 watchpoints are faults: the access has not happened when the hit
//!   is reported ([`HitTiming::BeforeAccess`]). The backend disarms the slot,
//!   single-steps the access (a load or store, never a conditional branch, so
//!   the step retires no branch the timer counts), rearms the slot and
//!   resumes. The step's stop is one without a Tool callback, and finishes a
//!   timer event it interrupts as such stops do.

use reverie::HitTiming;
use reverie::WatchError;
use reverie::WatchSpec;
use safeptrace::Error as TraceError;
use safeptrace::Stopped;

use super::HwWatch;

/// No watchpoints.
pub(crate) struct Unsupported;

impl HwWatch for Unsupported {
    const HIT_TIMING: HitTiming = HitTiming::BeforeAccess;

    fn slots(_task: &Stopped) -> Result<u8, TraceError> {
        Ok(0)
    }

    fn check(_spec: &WatchSpec) -> Result<(), WatchError> {
        Err(WatchError::Unsupported)
    }

    fn arm(_task: &Stopped, _slot: u8, _spec: &WatchSpec) -> Result<(), TraceError> {
        Err(TraceError::Errno(reverie::Errno::EOPNOTSUPP))
    }

    fn disarm(_task: &Stopped, _slot: u8) -> Result<(), TraceError> {
        Ok(())
    }

    fn take_hits(_task: &Stopped) -> Result<u8, TraceError> {
        Ok(0)
    }

    fn read(_task: &Stopped, _slot: u8) -> Result<Option<WatchSpec>, TraceError> {
        Ok(None)
    }
}
