/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Fixtures of the process_signal_publication unit tests, shared with the
// ones that need the KVM backend (reverie-kvm/src/linuxemu_tests.rs).

fn executor() -> ElfExecutor {
    ElfExecutor::new(native_loaded_state(std::path::Path::new("/tmp")), false)
}

fn identity(executor: &ElfExecutor) -> SignalProcessId {
    executor.signal_task_identity().unwrap().process
}

fn wait_until(failure: &str, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "{failure}");
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
