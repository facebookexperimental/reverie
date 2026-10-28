/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The DBT guest-stack scrub must not erase the guest's own dead stack.
//!
//! `scrub_guest_stack_residue` removes DynamoRIO's re-randomized addresses from
//! the dead part of the guest's `[stack]` VMA so Detcore's `--detlog-stack`
//! hash is stable run to run. Servicing a clone re-arms it, and at that point
//! the guest has already written dead frames into the same range. An earlier
//! revision selected bytes by position and deleted them: native and ptrace
//! preserved a planted marker while DBT zeroed it after a clone in 4 of 4 runs.
//! Nothing in the DBT suite noticed, because a deterministic deletion looks
//! exactly like a deterministic preservation to a repeat-run oracle.
//!
//! This runs [`tests/fixtures/stack_scrub_marker.c`] natively and under the
//! client and requires both to preserve the marker. Running the same binary
//! natively is the control that keeps the test honest: if the fixture stopped
//! planting anything, the native leg would still pass but so would a
//! scrub-everything client, so the DBT leg alone proves nothing.
//!
//! It is `#[ignore]`d for the same reason as `stats_provider_live.rs`: it needs
//! a built DynamoRIO tree and the native client, which hosted CI does not
//! provide. `cargo test --workspace --all-features` still compiles it, so it
//! cannot silently rot. Run it with:
//!
//! ```text
//! DYNAMORIO_HOME=<...> REVERIE_DBT_CLIENT=<...>/libreverie_dbt_client.so \
//!   cargo test -p reverie-dbt --test stack_scrub_preserves_guest_data \
//!   -- --ignored --nocapture
//! ```

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

/// Every planted word must survive. Mirrors `MARKER_WORDS` in the fixture.
const MARKER_WORDS: i32 = 90;
/// Exit status the fixture uses for "a marker word was modified", kept distinct
/// from its harness-failure status so a broken environment cannot masquerade as
/// the product bug this test exists to catch.
const MARKER_MISMATCH: i32 = 42;
/// Repeats. The original erasure was deterministic, so one run is enough to see
/// it; the repeats guard against the opposite mistake of a flaky pass.
const RUNS: usize = 4;

fn compile_fixture() -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stack_scrub_marker.c");
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("stack_scrub_marker");
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

/// Parses `before=<n> after_plain=<n> after_clone=<n>` and asserts the exit
/// status and all three counts. Asserting the counts as well as the status
/// pins *which* read lost the marker, so a regression report names the path.
fn assert_marker_preserved(label: &str, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!("{label}\nstdout:\n{stdout}\nstderr:\n{stderr}");

    assert_ne!(
        output.status.code(),
        Some(2),
        "the fixture reported a harness failure, so this run measured nothing\n{context}"
    );
    let field = |name: &str| -> i32 {
        stdout
            .split_whitespace()
            .find_map(|token| token.strip_prefix(name)?.parse().ok())
            .unwrap_or_else(|| panic!("no `{name}<n>` field in the fixture output\n{context}"))
    };
    assert_eq!(
        field("before="),
        MARKER_WORDS,
        "the plant never took\n{context}"
    );
    assert_eq!(
        field("after_plain="),
        MARKER_WORDS,
        "an ordinary syscall erased guest-owned dead stack\n{context}"
    );
    assert_eq!(
        field("after_clone="),
        MARKER_WORDS,
        "the clone-re-armed scrub erased guest-owned dead stack; the scrub is \
         selecting by position instead of by DynamoRIO ownership\n{context}"
    );
    assert_ne!(
        output.status.code(),
        Some(MARKER_MISMATCH),
        "the fixture reported a marker mismatch\n{context}"
    );
    assert!(
        output.status.success(),
        "the fixture exited unsuccessfully\n{context}"
    );
}

/// Compiles [`tests/fixtures/first_scrub_marker.c`].
///
/// `-static -nostdlib -nostartfiles` is the whole point, not a detail: the
/// marker has to be planted before the process's FIRST syscall, and a libc
/// guest cannot do that because glibc startup has already issued several by the
/// time `main` runs. `-fno-builtin` keeps the compiler from lowering the plant
/// loop into a `memset` call that does not exist in a freestanding binary.
fn compile_first_scrub_fixture() -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/first_scrub_marker.c");
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("first_scrub_marker");
    let compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args([
            "-O2",
            "-g",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-static",
            "-nostdlib",
            "-nostartfiles",
            "-fno-builtin",
        ])
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

/// Exit-status and count assertions for the freestanding first-scrub fixture.
///
/// Deliberately not `assert_marker_preserved`: that one pins the clone
/// fixture's three counts (`after_plain`/`after_clone`), which this fixture
/// does not have. Same discipline though -- assert the counts, not just the
/// status, so a failure names WHICH read lost the marker rather than only that
/// one did.
fn assert_first_scrub_marker_preserved(label: &str, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!("{label}\nstdout:\n{stdout}\nstderr:\n{stderr}");

    assert_ne!(
        output.status.code(),
        Some(2),
        "the fixture reported a harness failure, so this run measured nothing\n{context}"
    );
    let field = |name: &str| -> i32 {
        stdout
            .split_whitespace()
            .find_map(|token| token.strip_prefix(name)?.parse().ok())
            .unwrap_or_else(|| panic!("no `{name}<n>` field in the fixture output\n{context}"))
    };
    assert_eq!(
        field("before="),
        MARKER_WORDS,
        "the plant never took\n{context}"
    );
    assert_eq!(
        field("after_first_syscall="),
        MARKER_WORDS,
        "the INITIAL scrub erased guest data written before the first syscall; \
         it is still selecting by position from the pre-syscall hook instead of \
         running before the guest's first instruction\n{context}"
    );
    assert!(
        output.status.success(),
        "the fixture exited unsuccessfully\n{context}"
    );
}

/// The INITIAL scrub must not erase what the guest wrote before its first
/// syscall.
///
/// The initial scrub selects by POSITION -- it zeroes everything below the
/// stack pointer -- which is sound only if the guest has not run yet. It used
/// to run from the pre-syscall hook, by which point the guest has executed
/// arbitrarily much code, so anything it had written into dead stack was
/// deleted. Measured at `bb7b17f4` with this fixture: native preserved the
/// marker while DBT erased it in 4 of 4 runs, deterministically -- which is
/// what makes it dangerous, since a repeat-run oracle sees perfect stability.
///
/// The fix moves the initial scrub to the guest's first application
/// instruction, where "the guest has not run yet" is true by construction
/// rather than by hope.
#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
fn initial_scrub_preserves_guest_data_written_before_the_first_syscall() {
    let fixture = compile_first_scrub_fixture();

    // Control: uninstrumented. If this fails, the fixture or host is at fault
    // and the DBT legs below prove nothing either way.
    let native = Command::new(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run the fixture natively: {error}"));
    assert_first_scrub_marker_preserved("native (no instrumentation)", &native);

    let runner = reverie_dbt::DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set");
    for run in 1..=RUNS {
        let guest = Command::new(&fixture);
        let output = runner
            .output(&guest)
            .unwrap_or_else(|error| panic!("DBT run {run} failed to start: {error}"));
        assert_first_scrub_marker_preserved(&format!("DBT run {run} of {RUNS}"), &output);
    }
}

#[test]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
fn clone_rearmed_scrub_preserves_guest_written_dead_stack() {
    let fixture = compile_fixture();

    // Control: the same binary with no instrumentation at all. If this fails,
    // the fixture or the host is at fault and the DBT legs prove nothing.
    let native = Command::new(&fixture)
        .output()
        .unwrap_or_else(|error| panic!("failed to run the fixture natively: {error}"));
    assert_marker_preserved("native (no instrumentation)", &native);

    let runner = reverie_dbt::DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set");
    for run in 1..=RUNS {
        let guest = Command::new(&fixture);
        let output = runner
            .output(&guest)
            .unwrap_or_else(|error| panic!("DBT run {run} failed to start: {error}"));
        assert_marker_preserved(&format!("DBT run {run} of {RUNS}"), &output);
    }
}
