/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(feature = "native-test-support")]
#[test]
fn cached_handler_uses_the_address_installed_in_the_kernel() {
    // Integration tests link reverie-kvm without cfg(test). In an optimized
    // build this keeps both production empty signal handlers eligible for code
    // folding, which is the code shape this regression must exercise.
    reverie_kvm::native_test_support::check_reserved_entry_signal_handler().unwrap();
    reverie_kvm::native_test_support::check_reserved_entry_signal_handler().unwrap();
}
