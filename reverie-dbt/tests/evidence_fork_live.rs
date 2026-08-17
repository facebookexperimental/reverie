/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Live copied-child protected-evidence regression coverage.
//!
//! Run after `scripts/build-client.sh` with:
//!
//! ```text
//! DYNAMORIO_HOME=<...> REVERIE_DBT_CLIENT=<...>/libreverie_dbt_client.so \
//!   cargo test -p reverie-dbt --test evidence_fork_live -- --ignored --nocapture
//! ```

use std::io::Read as _;
use std::io::Seek as _;
use std::path::Path;
use std::process::Command;

use reverie_dbt::Counter2Global;
use reverie_dbt::DbtRunner;

fn compile_fixture(source_name: &str, output: &Path, extra_arguments: &[&str]) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(source_name);
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let compile_status = Command::new(compiler)
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .args(extra_arguments)
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("compile evidence fixture");
    assert!(compile_status.success(), "fixture compilation failed");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn protected_evidence_survives_fork_pthread_lifecycle() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("fork-pthread-identity");
    compile_fixture("fork_pthread_identity.c", &fixture, &["-pthread"]);

    let mut evidence_file = tempfile::tempfile().expect("evidence tempfile");
    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .evidence_file(&evidence_file)
        .expect("configure protected evidence")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(fixture);
    guest.env("HERMIT_DBT_COUNTER2", "1");

    let (output, _global) = runner
        .output_with_global::<Counter2Global>(&guest, ())
        .await
        .expect("fork/pthread evidence run should complete");
    assert!(
        output.status.success(),
        "fork/pthread guest exited unsuccessfully: {output:?}"
    );
    assert_eq!(output.stdout, b"fork-pthread-race=64\n");

    evidence_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("rewind evidence artifact");
    let mut evidence_bytes = Vec::new();
    evidence_file
        .read_to_end(&mut evidence_bytes)
        .expect("read evidence artifact");
    let evidence = reverie_dbt::decode_evidence(&evidence_bytes)
        .expect("fork/pthread evidence artifact must decode");
    assert!(
        !evidence.records().is_empty(),
        "fork/pthread run must publish protected evidence"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
fn protected_evidence_covers_vfork_open_and_exec() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("vfork-open-exec");
    compile_fixture("evidence_vfork_open_exec.c", &fixture, &[]);

    let mut evidence_file = tempfile::tempfile().expect("evidence tempfile");
    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .evidence_file(&evidence_file)
        .expect("configure protected evidence")
        .client_argument("-test-wait-for-background");
    let output = runner
        .output(&Command::new(fixture))
        .expect("vfork/open/exec evidence run should complete");
    assert!(
        output.status.success(),
        "vfork/open/exec guest exited unsuccessfully: {output:?}"
    );
    assert_eq!(output.stdout, b"vfork-open-exec-ok\n");

    evidence_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("rewind evidence artifact");
    let mut evidence_bytes = Vec::new();
    evidence_file
        .read_to_end(&mut evidence_bytes)
        .expect("read evidence artifact");
    let evidence = reverie_dbt::decode_evidence(&evidence_bytes)
        .expect("vfork/open/exec evidence artifact must decode");
    let initialized_images = evidence
        .records()
        .iter()
        .filter(|record| {
            record
                .windows(b"protected evidence initialized".len())
                .any(|window| window == b"protected evidence initialized")
        })
        .count();
    assert!(
        initialized_images >= 2,
        "parent and exec child must both contribute protected evidence; got {initialized_images} initialization records"
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
fn protected_evidence_follows_last_thread_explicit_exit() {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("explicit-exit");
    compile_fixture("evidence_explicit_exit.c", &fixture, &[]);

    let mut evidence_file = tempfile::tempfile().expect("evidence tempfile");
    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .evidence_file(&evidence_file)
        .expect("configure protected evidence")
        .client_argument("-test-thread-exit-evidence");
    let output = runner
        .output(&Command::new(fixture))
        .expect("explicit SYS_exit evidence run should complete");
    assert!(
        output.status.success(),
        "explicit SYS_exit guest exited unsuccessfully: {output:?}"
    );

    evidence_file
        .seek(std::io::SeekFrom::Start(0))
        .expect("rewind evidence artifact");
    let mut evidence_bytes = Vec::new();
    evidence_file
        .read_to_end(&mut evidence_bytes)
        .expect("read evidence artifact");
    let evidence = reverie_dbt::decode_evidence(&evidence_bytes)
        .expect("explicit SYS_exit evidence artifact must decode");
    assert!(
        evidence.records().iter().any(|record| {
            record
                .windows(b"explicit SYS_exit thread callback completed".len())
                .any(|window| window == b"explicit SYS_exit thread callback completed")
        }),
        "last-thread SYS_exit must publish thread-exit evidence before FINAL"
    );
}
