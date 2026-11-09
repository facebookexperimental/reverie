/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Fixtures of the capture-identity unit tests, shared with the ones that need
// the KVM backend (reverie-kvm/src/linuxemu_tests.rs).

fn capture_native_stat(fd: RawFd) -> libc::stat {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }, 0);
    unsafe { stat.assume_init() }
}

fn capture_test_child(test: &str, marker: &str) -> bool {
    const ENV: &str = "REVERIE_CAPTURE_IDENTITY_CHILD";
    if std::env::var(ENV).as_deref() == Ok(test) {
        return true;
    }
    assert!(std::env::var_os(ENV).is_none());
    let output = std::process::Command::new("/usr/bin/timeout")
        .args(["--kill-after=2s", "10s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=1", "--nocapture"])
        .env(ENV, test)
        .output()
        .unwrap();
    eprintln!(
        "capture child status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .filter(|line| *line == marker)
            .count(),
        1
    );
    false
}
