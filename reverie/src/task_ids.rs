/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! How a backend that assigns guest task IDs itself numbers new tasks.
//!
//! A guest sees task IDs directly (`getpid`, `gettid`, `clone`'s result), and
//! Hermit's Detcore uses them as its thread IDs, so the backends a Hermit run
//! compares must number tasks the same way. Plain Linux gives each new task
//! the next free ID: 3, 4, 5, ... ([`LINUX_IDS_PER_TASK`]).
//!
//! Hermit's reference backend, ptrace, does not. There the kernel assigns IDs
//! inside the guest's pid namespace, where Hermit itself is pid 1, and Hermit's
//! tracer starts one thread, named `guest-<pid>`, for each guest task it
//! follows; each such thread takes the next ID in the namespace. So the root
//! task is followed by its tracer thread, every new task by its own, and guest
//! tasks are numbered 3, 5, 7, ... ([`HERMIT_PTRACE_IDS_PER_TASK`]).
//!
//! A backend that numbers tasks itself gets the step from its caller and
//! advances by [`next_task_id`]. This is the one place the rule lives, for
//! every non-ptrace backend: Hermit passes [`HERMIT_PTRACE_IDS_PER_TASK`] to the
//! KVM backend today, and the other backends are to adopt it the same way, so
//! their guests see the same IDs as under ptrace. If the ptrace backend stops
//! spending an ID per task, that constant becomes 1 and every backend follows.
//! Any unused ID is a valid Linux pid, so either numbering is Linux behaviour.

/// Task IDs plain Linux spends per new task.
pub const LINUX_IDS_PER_TASK: i32 = 1;

/// Task IDs Hermit's ptrace backend spends per guest task: the task's own and
/// the one its tracer thread takes.
pub const HERMIT_PTRACE_IDS_PER_TASK: i32 = 2;

/// The ID of the task created after the task numbered `previous` (the root
/// task, for the first one), spending `ids_per_task` IDs per task, or `None`
/// when it would not fit in a pid.
pub fn next_task_id(previous: i32, ids_per_task: i32) -> Option<i32> {
    previous.checked_add(ids_per_task)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under Hermit's ptrace backend a guest sees root 3, then 5, 7, 9, ...
    /// for every new process or thread; under plain Linux 3, 4, 5, ...
    #[test]
    fn task_ids_follow_the_ptrace_reference_or_linux() {
        assert_eq!(HERMIT_PTRACE_IDS_PER_TASK, 2);
        assert_eq!(LINUX_IDS_PER_TASK, 1);
        assert_eq!(next_task_id(3, HERMIT_PTRACE_IDS_PER_TASK), Some(5));
        assert_eq!(next_task_id(5, HERMIT_PTRACE_IDS_PER_TASK), Some(7));
        assert_eq!(next_task_id(3, LINUX_IDS_PER_TASK), Some(4));
        assert_eq!(next_task_id(i32::MAX - 1, HERMIT_PTRACE_IDS_PER_TASK), None);
    }
}
