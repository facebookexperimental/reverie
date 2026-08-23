/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live process-clone callback delivery regression coverage.

use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

fn compile_fixture(output: &Path) {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/process_clone_results.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("compile process-clone fixture");
    assert!(status.success(), "fixture compilation failed");
}

fn callback_results(stderr: &[u8]) -> Vec<(i64, i64)> {
    const PREFIX: &str = "reverie-dbt-test: process-clone-result ";

    String::from_utf8_lossy(stderr)
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .map(|fields| {
            let mut fields = fields.split_whitespace();
            let sysnum = fields
                .next()
                .expect("clone-result row must contain sysnum")
                .strip_prefix("sysnum=")
                .expect("clone-result row sysnum must use sysnum=<integer>")
                .parse()
                .expect("clone-result row sysnum must be an integer");
            let result = fields
                .next()
                .expect("clone-result row must contain result")
                .strip_prefix("result=")
                .expect("clone-result row result must use result=<integer>")
                .parse()
                .expect("clone-result row result must be an integer");
            assert!(
                fields.next().is_none(),
                "clone-result row must contain exactly two fields: {fields:?}"
            );
            (sysnum, result)
        })
        .collect()
}

#[test]
#[should_panic(expected = "clone-result row must contain result")]
fn malformed_callback_rows_fail_closed() {
    let _ = callback_results(b"reverie-dbt-test: process-clone-result sysnum=56\n");
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run explicitly with --ignored"]
fn process_clone_result_delivery_matches_the_public_contract() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("process-clone-results");
    compile_fixture(&fixture);

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(fixture);
    guest.env("REVERIE_DBT_TEST_PROCESS_CLONE_RESULTS", "1");
    let output = runner
        .output(&guest)
        .expect("process-clone matrix must run");
    assert!(output.status.success(), "guest failed: {output:?}");
    assert_eq!(output.stdout, b"process-clone-results-ok\n");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("stale process-clone result state"),
        "clone-result state leaked past its post-event: {output:?}"
    );

    let results = callback_results(&output.stderr);
    let mut expected = vec![
        (libc::SYS_clone, -libc::EINVAL as i64),
        (libc::SYS_clone, -libc::EINVAL as i64),
        (libc::SYS_fork, 1),
        (libc::SYS_fork, 0),
        (libc::SYS_clone, 1),
        (libc::SYS_clone, 0),
        (libc::SYS_clone, 1),
    ];
    #[cfg(target_arch = "x86_64")]
    expected.extend([(libc::SYS_clone3, 1), (libc::SYS_clone3, 0)]);
    expected.push((libc::SYS_vfork, 1));

    assert_eq!(
        results.len(),
        expected.len(),
        "callback stream must contain exactly one row for every delivered result: {results:?}"
    );
    for (index, ((sysnum, result), (expected_sysnum, expected_result))) in
        results.iter().zip(&expected).enumerate()
    {
        assert_eq!(
            sysnum, expected_sysnum,
            "callback {index} belongs to the wrong process-clone call: {results:?}"
        );
        if *expected_result > 0 {
            assert!(
                *result > 0,
                "callback {index} must contain a parent-positive result: {results:?}"
            );
        } else {
            assert_eq!(
                result, expected_result,
                "callback {index} must contain the exact child/error result: {results:?}"
            );
        }
    }
}
