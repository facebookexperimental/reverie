/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! glibc_compat in a non-PIE executable that holds libc functions' canonical
//! PLT entries (src/bin/glibc_compat_guest.rs). The unit tests cover ordinary
//! position-independent processes.

use std::process::Command;

/// In a non-PIE executable whose PLT entries are the addresses of
/// `dl_iterate_phdr` and `gnu_get_libc_version` for every object, the resolver
/// still finds glibc's `_dl_find_object` exactly where `dlvsym` does, and a
/// panic through a frame in a new `dlmopen` namespace is caught. The guest
/// first checks that it is such an executable and that it unwinds with the
/// static unwinder and glibc_compat's `_dl_find_object`, as the guest preload
/// does.
#[test]
fn a_newlm_panic_is_caught_where_the_executable_holds_libcs_plt_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("bridge.c");
    let bridge = directory.path().join("bridge.so");
    std::fs::write(
        &source,
        "void bridge_call(void (*callback)(void)) { callback(); }\n",
    )
    .unwrap();
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-fexceptions", "-O0", "-o"])
        .arg(&bridge)
        .arg(&source)
        .status()
        .expect("this test needs a C compiler (cc) on PATH");
    assert!(built.success(), "cc failed: {built}");
    let output = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-glibc-compat-guest"))
        .arg(&bridge)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.trim() == "canonical=1 static=1 resolved=1 caught=1",
        "the guest exited with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
