/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A DBT guest sees the environment it was given, before and after an exec,
//! and the runtime still finds its private variables.
//!
//! DynamoRIO's early injection runs the guest on the stack the kernel built for
//! drrun's exec, so the guest's initial environment used to carry DynamoRIO's
//! variables (`DYNAMORIO_CONFIGDIR`, `DYNAMORIO_EXE_PATH`, ...) and the
//! launcher's `HERMIT_DBT_*` ones, including a coordinator socket path that is
//! random per run. The bundled DynamoRIO now removes them before the guest's
//! first instruction, and passes them on to the children it follows, which
//! remove them again. The client keeps its own copy for the runtime.
//!
//! This runs [`tests/fixtures/guest_environment.c`] natively with an exact
//! environment, and under the client with the same environment plus
//! `HERMIT_DBT_COUNTER2`, coordinated by [`Counter2Global`]. The parent forks a
//! child that execs the fixture again by its path, and that child execs it
//! once more through `/proc/self/exe`; then the parent forks a child that
//! execs it with a NULL argv, and one that execs it with a read-only argv
//! whose `argv[0]` is `/proc/self/exe` (DynamoRIO fixes that argument up when
//! it redirects the exec). Every image must print the native `environ`, the
//! native non-empty `/proc/self/environ` entries, the native `AT_EXECFN`, and
//! whether that string is on the stack, and all four processes must report to
//! the coordinator at exit: the parent reaches it only through the client's
//! copy of the socket variable, and each exec'd child only through DynamoRIO
//! passing the hidden variables on (a child that escaped the client would not
//! report at all).
//!
//! The second test runs a copy of the fixture under a path longer than
//! DynamoRIO's own library path, so `AT_EXECFN` cannot reuse the kernel's exec
//! filename storage and DynamoRIO places it in a private mapping instead: the
//! one expected difference is "execfn-on-stack 0" where native prints 1.
//!
//! `/proc/self/environ` is compared without its empty entries: the kernel's
//! range still covers the removed strings' bytes, which are erased to NULs, so
//! its length differs from native (a known residual). The non-empty entries
//! carry every non-NUL byte, so no private byte can pass unseen.
//!
//! `#[ignore]`d like the other live tests; run it with:
//!
//! ```text
//! DYNAMORIO_HOME=<...> REVERIE_DBT_CLIENT=<...>/libreverie_dbt_client.so \
//!   cargo test -p reverie-dbt --test guest_environment_live -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::OnceLock;

use reverie_dbt::Counter2Global;
use reverie_dbt::DbtRunner;

/// Compiles the fixture once; both tests use it, and they may run at once.
fn compile_fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(compile_fixture_now).clone()
}

fn compile_fixture_now() -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/guest_environment.c");
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("guest_environment");
    let compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap_or_else(|error| panic!("failed to start the C compiler: {error}"));
    assert!(
        compile.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&compile.stderr)
    );
    binary
}

fn stdout_of(label: &str, output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{label} exited with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// Runs `fixture` natively and under the client; returns both stdouts after
/// checking the native control and the coordinator's process count.
async fn native_and_dbt(fixture: &Path) -> (String, String) {
    let given = BTreeMap::from([
        (OsString::from("GUEST_A"), OsString::from("1")),
        (OsString::from("GUEST_B"), OsString::from("two words")),
    ]);

    let native = Command::new(fixture)
        .env_clear()
        .envs(&given)
        .output()
        .unwrap_or_else(|error| panic!("failed to run the fixture natively: {error}"));
    let native = stdout_of("native run", &native);
    // The control: the fixture printed both entries in every image.
    for image in ["parent", "child", "grandchild", "emptyargv", "readonly"] {
        for kind in ["env", "procenv"] {
            let line = format!("{image} {kind} GUEST_B=two words");
            assert!(
                native.lines().any(|printed| printed == line),
                "the native run did not print `{line}`:\n{native}"
            );
        }
    }

    let mut private = given.clone();
    private.insert(
        OsString::from(format!("{}COUNTER2", reverie_dbt::PRIVATE_ENV_PREFIX)),
        OsString::from("1"),
    );
    // The exec leaves the pre-exec image's background thread behind (it
    // predates this test); terminating the process group keeps it from holding
    // stdout open.
    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .terminate_process_group_on_exit(true);
    let (dbt, global) = runner
        .output_with_environment_and_global::<Counter2Global>(&Command::new(fixture), &private, ())
        .await
        .unwrap_or_else(|error| panic!("the DBT run failed: {error}"));
    let dbt = stdout_of("DBT run", &dbt);
    let (_, processes, _) = global.snapshot();
    assert_eq!(
        processes, 4,
        "the parent and its three exec'd children must all report to the \
         coordinator through their private variables\n{dbt}"
    );
    (native, dbt)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn guest_sees_only_its_own_environment_and_the_runtime_keeps_its_variables() {
    let fixture = compile_fixture();
    let (native, dbt) = native_and_dbt(&fixture).await;
    assert_eq!(
        dbt, native,
        "the DBT guest's environment differs from the native one"
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn a_program_path_longer_than_dynamorios_keeps_the_native_environment() {
    let fixture = compile_fixture();
    // About 450 bytes: longer than DynamoRIO's library path (the kernel's exec
    // filename) and shorter than DynamoRIO's 512-byte MAXIMUM_PATH, which
    // drrun enforces. If the path still fit the kernel's storage, DBT would
    // print "execfn-on-stack 1" and the comparison below would fail.
    let mut directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let mut level = 0;
    while directory.as_os_str().len() < 430 {
        directory.push(format!("{level}{}", "d".repeat(39)));
        level += 1;
    }
    std::fs::create_dir_all(&directory).expect("create the long program directory");
    let long = directory.join("guest_environment");
    assert!(long.as_os_str().len() < 512, "{}", long.display());
    std::fs::copy(&fixture, &long).expect("copy the fixture to the long path");
    let (native, dbt) = native_and_dbt(&long).await;

    let expected = native.replace("execfn-on-stack 1", "execfn-on-stack 0");
    assert_ne!(
        expected, native,
        "the native run printed no stack placement"
    );
    assert_eq!(
        dbt, expected,
        "the DBT guest's environment differs from the native one beyond the \
         private-mapping placement of a long AT_EXECFN"
    );
}
