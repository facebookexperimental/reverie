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
        Self::create(std::process::id())
    }

    // Split from `new` so the collision test can seed stale directories
    // under a pid no live process holds.
    fn create(pid: u32) -> Self {
        loop {
            let id = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
            // AF_UNIX paths are limited to 107 bytes on Linux. The
            // validation checkout deliberately has a long TMPDIR, so keep
            // this fixture's private, nonce-qualified directory directly
            // under /tmp.
            let path = Path::new("/tmp").join(format!("reverie-kvm-fs-{pid}-{id}"));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                // An existing directory under this name is never ours to
                // touch: it is either a leak left by a process that was
                // killed before its Drop ran (a timeout or an abort), or
                // a live peer in another PID namespace that draws the
                // same pid while sharing /tmp. Advancing the counter is
                // safe in both cases precisely because it AVOIDS the
                // existing directory: this fixture only ever creates a
                // fresh directory and only ever removes directories it
                // created itself.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create {path:?}: {error}"),
            }
        }
    }
}

/// Removes the directories the collision test seeded, even when the
/// test fails. Every path here was created by this test process, so a
/// failed removal (for example because the code under test deleted a
/// seeded directory instead of avoiding it) is a loud failure, never
/// ignored.
struct SeededDirs(Vec<PathBuf>);

impl Drop for SeededDirs {
    fn drop(&mut self) {
        // Remove every seed even when one removal fails, and never
        // panic out of a drop that is already unwinding for another
        // failure: that aborts the whole test process (killing every
        // other test in the binary) and skips the remaining removals.
        // The failure is recorded *before* the fallback runs: a seed
        // that gained contents is one the code under test touched,
        // even though the fallback then removes it. Only this test
        // creates these fake-pid names, so the fallback is safe here.
        let mut failed = Vec::new();
        for path in &self.0 {
            if let Err(error) = std::fs::remove_dir(path) {
                failed.push(format!("{path:?}: {error}"));
                let _ = std::fs::remove_dir_all(path);
            }
        }
        if !failed.is_empty() && !std::thread::panicking() {
            panic!("seeded directories were touched: {failed:?}");
        }
    }
}

/// A stale directory left by a killed process must not panic the next
/// process that draws the same (pid, counter) name: creation skips it,
/// and never deletes, reuses, or otherwise touches it — each seed
/// keeps its inode and mode across the create.
#[test]
fn test_dir_skips_stale_leaked_directories() {
    use std::os::unix::fs::MetadataExt;

    // A pid no live process holds, so seeding cannot collide with a peer.
    let pid = u32::MAX;
    let next = NEXT_TEST_DIR.load(Ordering::Relaxed);
    let mut seeded = SeededDirs(Vec::new());
    for id in next..next + 64 {
        let path = Path::new("/tmp").join(format!("reverie-kvm-fs-{pid}-{id}"));
        match std::fs::create_dir(&path) {
            Ok(()) => seeded.0.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("seed {path:?}: {error}"),
        }
    }
    let before: Vec<(u64, u32)> = seeded
        .0
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path)
                .unwrap_or_else(|error| panic!("stat seed {path:?}: {error}"));
            (metadata.ino(), metadata.mode())
        })
        .collect();
    let dir = TestDir::create(pid);
    assert!(dir.0.is_dir(), "created directory is missing: {:?}", dir.0);
    assert!(
        !seeded.0.contains(&dir.0),
        "returned a seeded stale directory: {:?}",
        dir.0
    );
    for (path, (ino, mode)) in seeded.0.iter().zip(&before) {
        let metadata = std::fs::metadata(path)
            .unwrap_or_else(|error| panic!("seeded directory was touched: {path:?}: {error}"));
        assert_eq!(
            (metadata.ino(), metadata.mode()),
            (*ino, *mode),
            "seeded directory was replaced or chmodded: {path:?}"
        );
    }
    drop(dir);
}

impl Drop for TestDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
