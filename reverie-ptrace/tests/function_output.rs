/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Function-guest capture with stable descriptor writes and nightly printing
//! macros. Neither test disables libtest's own capture.

use reverie::process::ExitStatus;
use reverie_ptrace::testing::test_fn;

#[test]
fn descriptor_output_is_captured_under_libtest() {
    let (output, ()) = test_fn::<(), _>(|| {
        use std::io::Write;

        std::io::stdout().write_all(b"out\0\xff\n").unwrap();
        std::io::stderr().write_all(b"err\xfe\0\n").unwrap();
    })
    .expect("run the guest");
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout, b"out\0\xff\n");
    assert_eq!(output.stderr, b"err\xfe\0\n");
}

#[cfg(feature = "nightly")]
#[test]
fn printing_macros_are_captured_under_libtest() {
    let (output, ()) = test_fn::<(), _>(|| {
        println!("guest stdout");
        eprintln!("guest stderr");
    })
    .expect("run the guest");
    assert_eq!(output.status, ExitStatus::Exited(0));
    assert_eq!(output.stdout, b"guest stdout\n");
    assert_eq!(output.stderr, b"guest stderr\n");
}
