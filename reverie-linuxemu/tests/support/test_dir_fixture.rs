/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// The temporary-directory fixture of the executor unit tests, shared with the
// ones that need the KVM backend (reverie-kvm/src/linuxemu_tests.rs).

static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        // AF_UNIX paths are limited to 107 bytes on Linux. The validation
        // checkout deliberately has a long TMPDIR, so keep this fixture's
        // private, nonce-qualified directory directly under /tmp.
        let path =
            Path::new("/tmp").join(format!("reverie-kvm-fs-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
