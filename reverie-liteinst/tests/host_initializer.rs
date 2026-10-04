/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Exercise the explicit host entry on a real loaded runtime. The C fixture
//! services only its own expected handshake traps; it does not qualify ptrace
//! activation, target-loader injection, or any backend comparator.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn run(mode: &str, expected: &[u8]) {
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("host-initializer");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/host_initializer.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = Command::new(compiler)
        .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
        .arg(source)
        .arg("-ldl")
        .arg("-o")
        .arg(&fixture)
        .output()
        .unwrap();
    assert!(output.status.success(), "compiler: {output:?}");

    let launcher = PathBuf::from(env!("CARGO_BIN_EXE_reverie-liteinst-strace"));
    let target = launcher.parent().unwrap();
    let preload = [
        target.join("libreverie_liteinst.so"),
        target.join("deps/libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the LiteInst preload cdylib");
    let stdout = std::fs::File::create(directory.path().join("stdout")).unwrap();
    let stderr = std::fs::File::create(directory.path().join("stderr")).unwrap();
    let mut command = Command::new(fixture);
    command
        .arg(mode)
        .env("LD_PRELOAD", preload)
        .env_remove("REVERIE_LITEINST_HOST_RUNTIME")
        .env_remove("REVERIE_LITEINST_TOOL")
        .env_remove("REVERIE_PRELOAD_TOOL")
        .env_remove("REVERIE_LITEINST_STRADDLER_STALENESS_TICKS")
        .stdout(stdout)
        .stderr(stderr);
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("explicit host initializer timed out: {mode}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = std::fs::read(directory.path().join("stdout")).unwrap();
    let stderr = std::fs::read(directory.path().join("stderr")).unwrap();
    assert!(status.success(), "{mode}: {status:?}, stderr={stderr:?}");
    assert!(stderr.is_empty(), "{mode}: unexpected stderr={stderr:?}");
    assert_eq!(stdout, expected, "{mode}");
}

#[test]
fn explicit_host_prepares_real_sites_with_disabled_and_explicit_policy() {
    for mode in ["disabled", "configured"] {
        run(mode, b"explicit-host-initialized\n");
    }
}

#[test]
fn explicit_host_retains_real_preparation_failure_without_a_second_handshake() {
    run("preparation-failure", b"preparation-failure-retained\n");
}

#[test]
fn explicit_host_rejects_an_active_shared_builtin_before_begin() {
    run("builtin-active", b"published-dispatcher-refused\n");
}
