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
        // TODO-HUMAN-REVIEW(PR-148): Review the allocator-reentry test guest mode.
        Some("exercise-allocator") => exercise_allocator(),
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

// TODO-HUMAN-REVIEW(PR-148): Review deterministic guest allocator growth coverage.
fn exercise_allocator() {
    let mut blocks = Vec::with_capacity(256);
    for value in 0_u8..=255 {
        blocks.push(vec![value; 64 * 1024]);
    }
    let checksum = blocks
        .iter()
        .map(|block| usize::from(block[0]) + usize::from(block[block.len() - 1]))
        .sum::<usize>();
    assert_eq!(checksum, 2 * (0_usize..=255).sum::<usize>());

    let mut large = vec![0x5a_u8; 8 * 1024 * 1024];
    let last = large.len() - 1;
    large[last] = 0xa5;
    assert_eq!(large[0], 0x5a);
    assert_eq!(large[last], 0xa5);

    println!("allocator-growth-ok");
}
