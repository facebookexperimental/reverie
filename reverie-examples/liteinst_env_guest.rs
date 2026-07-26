/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Guest checks for LiteInst example-tool integration tests.

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => check_environment(),
        Some("check-fd-198") => check_inherited_descriptor(),
        Some("check-coordinator-environment") => check_coordinator_environment(),
        Some(argument) => panic!("unknown argument {argument:?}"),
    }
}

fn check_environment() {
    let data = std::fs::read("/proc/self/environ").unwrap();
    let entries = data.split(|byte| *byte == 0).collect::<Vec<_>>();
    assert_eq!(
        entries.last(),
        Some(&&[][..]),
        "environment lacks final NUL"
    );
    assert!(
        entries[..entries.len() - 1]
            .iter()
            .all(|entry| !entry.is_empty()),
        "environment contains empty entries"
    );
    for control in [
        b"REVERIE_LITEINST_COORDINATOR=".as_slice(),
        b"REVERIE_LITEINST_EXAMPLE_TOOL=".as_slice(),
    ] {
        assert!(!data.windows(control.len()).any(|window| window == control));
    }
    println!("raw-environment-ok");
}

fn check_coordinator_environment() {
    assert_eq!(
        std::env::var("REVERIE_LITEINST_COORDINATOR").unwrap(),
        "guest-value"
    );
    println!("coordinator-environment-preserved");
}

fn check_inherited_descriptor() {
    assert_eq!(
        std::fs::read_link("/proc/self/fd/198").unwrap(),
        std::path::Path::new("/dev/null")
    );
    println!("fd-198-preserved");
}
