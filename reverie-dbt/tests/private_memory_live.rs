/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Actual native ownership callback controls, including followed-exec backing loss.

use std::path::Path;
use std::process::Command;

use reverie_dbt::DbtRunner;

fn observe(mode: &str, exec: bool) -> Vec<String> {
    let directory = tempfile::tempdir().unwrap();
    let program = directory.path().join("private_memory_exec");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/private_memory_exec.c");
    let compile = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&program)
        .output()
        .unwrap();
    assert!(compile.status.success(), "{compile:?}");
    let runner = DbtRunner::from_env()
        .expect("built DynamoRIO and native client")
        .client_argument("-test-private-memory")
        .client_argument(mode);
    let mut command = Command::new(program);
    if exec {
        command.arg("exec");
    }
    let output = runner.output(&command).unwrap();
    eprintln!("private memory {mode}, exec={exec}: {output:?}");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"private memory guest completed\n");
    String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("PRIVATE_MEMORY_TEST "))
        .map(str::to_owned)
        .collect()
}

const FIRST_READY: &str =
    "PRIVATE_MEMORY_TEST ready=1 followed_exec=0 wrong_owner_rejected=1 wrong_version_rejected=1";
const EXEC_READY: &str =
    "PRIVATE_MEMORY_TEST ready=1 followed_exec=1 wrong_owner_rejected=1 wrong_version_rejected=1";

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn private_memory_current_and_followed_exec_tokens_are_validated() {
    assert_eq!(observe("ready", true), [FIRST_READY, EXEC_READY]);
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn private_memory_retirement_rejects_saved_and_current_tokens() {
    assert_eq!(
        observe("retire", false),
        [FIRST_READY, "PRIVATE_MEMORY_TEST retired=1"]
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn private_memory_followed_exec_with_lost_backing_is_unavailable() {
    // The native option explicitly injects transport loss before the real exec;
    // it does not claim to exercise a normal guest close admission route.
    assert_eq!(
        observe("lost-exec", true),
        [
            FIRST_READY,
            "PRIVATE_MEMORY_TEST control-backing-loss-injected=1",
            "PRIVATE_MEMORY_TEST followed-exec-unavailable=1",
        ]
    );
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn private_memory_mapping_routes_retire_only_on_replacement() {
    // Synthetic operands enter the same dispatcher/overlap path used before
    // native syscall transfer. No kernel operation unmaps the running runtime.
    let mut expected = vec![FIRST_READY.to_owned()];
    for (name, notifications) in [
        ("mmap-fixed-overlap", 1),
        ("mmap-nonfixed-overlap", 0),
        ("mmap-noreplace-overlap", 0),
        ("mmap-fixed-disjoint", 0),
        ("mmap-fixed-overflow", 1),
        ("munmap-overlap", 1),
        ("munmap-disjoint", 0),
        ("munmap-left-adjacent", 0),
        ("munmap-right-adjacent", 0),
        ("munmap-left-crossing", 1),
        ("munmap-right-crossing", 1),
        ("munmap-zero", 0),
        ("munmap-overflow", 1),
        ("mremap-source", 1),
        ("mremap-source-shrink", 1),
        ("mremap-source-growth", 1),
        ("mremap-zero-size-alias", 1),
        ("mremap-zero-extents", 0),
        ("mremap-fixed-destination", 1),
        ("mremap-ignored-destination", 0),
        ("mremap-disjoint", 0),
        ("mremap-source-overflow", 1),
        ("mremap-destination-overflow", 1),
        ("mremap-both-overlap", 2),
        ("mprotect-commit", 0),
        ("shmat-remap", 1),
        ("shmat-nonremap", 0),
    ] {
        expected.push(format!(
            "PRIVATE_MEMORY_TEST route={name} notifications={notifications}"
        ));
    }
    expected.push("PRIVATE_MEMORY_TEST routes=27 live_token=1".to_owned());
    assert_eq!(observe("routes", false), expected);
}
