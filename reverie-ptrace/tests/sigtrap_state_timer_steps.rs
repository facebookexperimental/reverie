/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest's SIGTRAP action and mask survive the single-steps of a precise
//! timer (see `sigtrap_steps`), with the repair page sealed where the kernel
//! has `mseal`.

mod sigtrap_steps;

#[test]
fn sigtrap_action_and_mask_survive_precise_timer_steps() {
    sigtrap_steps::sigtrap_action_and_mask_survive_precise_timer_steps();
}

#[test]
fn sigtrap_state_survives_a_timer_step_over_sigreturn() {
    sigtrap_steps::sigtrap_state_survives_a_timer_step_over_sigreturn();
}

#[test]
fn a_repair_at_a_seccomp_stop_runs_the_syscall_once() {
    sigtrap_steps::a_repair_at_a_seccomp_stop_runs_the_syscall_once();
}
