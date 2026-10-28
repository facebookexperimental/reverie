/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// A fixture of the child-wait unit tests, shared with the ones that need the
// KVM backend (reverie-kvm/src/linuxemu_tests.rs).

fn ready_family_child(parent: &mut ElfExecutor, pid: i32) -> ElfExecutor {
    let mut child = parent.fork_child(pid, false, false).unwrap();
    let child_id = identity(&child);
    child.retire_current_thread(reverie::ExitStatus::Exited(23), false);
    assert!(child.signal_task_identity().is_none());
    assert_eq!(child.retired_process_identity(), child_id);
    parent
        .record_child_completion(
            child_id,
            crate::executor::ChildCompletion::Waitable(reverie::ExitStatus::Exited(23)),
        )
        .unwrap();
    child
}
