/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::process::Command;

mod parallel_tasks_child;

#[test]
fn parallel_tasks_reports_switch_points() {
    let output =
        parallel_tasks_child::output(&mut Command::new(env!("CARGO_BIN_EXE_parallel_tasks")))
            .expect("failed to run parallel_tasks");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "parallel_tasks failed with {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        stdout,
        stderr
    );

    let switch_points = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Switch points: "))
        .and_then(|value| value.parse::<usize>().ok())
        .expect("parallel_tasks did not report its switch-point count");
    assert!(
        switch_points > 1,
        "parallel_tasks reported only {switch_points} switch points"
    );
}
