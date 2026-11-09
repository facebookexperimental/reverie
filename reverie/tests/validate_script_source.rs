/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

const VALIDATE_SCRIPT: &str = include_str!("../../validate.sh");
const E2E_SCRIPT: &str = include_str!("../../reverie-examples/e2e/run.sh");
const PERCRATE_SCRIPT: &str = include_str!("../../scripts/run-percrate-tests.sh");

#[test]
fn percrate_results_are_absolute_before_counted_tests() {
    // The counted runner hands libtest a FIFO path derived from the counts
    // file, and cargo runs each test binary from its own package directory.
    // A relative --results therefore makes libtest look for that FIFO
    // under the package directory and fail with ENOENT. The script must
    // make RESULTS absolute before it creates or hands out any path under
    // it.
    const ABSOLUTIZE: &str = r#"case $RESULTS in
    /*) ;;
    *) RESULTS="$STARTUP_PWD/$RESULTS" ;;
esac"#;
    let startup = PERCRATE_SCRIPT
        .find("STARTUP_PWD=$PWD\nROOT_DIR=")
        .expect("startup directory must be captured before the script changes directory");
    assert!(startup < PERCRATE_SCRIPT.find("cd \"$ROOT_DIR\"").unwrap());
    assert!(
        PERCRATE_SCRIPT.contains("--results needs a non-empty directory"),
        "an empty --results must be rejected, not resolved to the startup directory"
    );
    let absolutize = PERCRATE_SCRIPT.find(ABSOLUTIZE).unwrap_or_else(|| {
        panic!("run-percrate-tests.sh must resolve --results to an absolute path at startup")
    });
    let create = PERCRATE_SCRIPT
        .find("mkdir -p \"$RESULTS/logs\" \"$RESULTS/counts\"")
        .unwrap();
    let counts = PERCRATE_SCRIPT
        .find("counts=\"$RESULTS/counts/$pkg.json\"")
        .unwrap();
    assert!(absolutize < create && create < counts);
}

#[test]
fn validation_ledger_writer_follows_the_discovered_parent() {
    const LEDGER_SELECTION: &str = r#"if [[ -n $DEV_HERMIT_PARENT ]]; then
    VALIDATION_LEDGER_TOOL="$DEV_HERMIT_PARENT/ci-hub/ledger/validate_rows.py"
else
    VALIDATION_LEDGER_TOOL="${HOME:?HOME is required}/work/dev-hermit/ci-hub/ledger/validate_rows.py"
fi"#;

    assert!(
        VALIDATE_SCRIPT.contains(LEDGER_SELECTION),
        "a nested validation must publish through its discovered parent; the home-relative adapter is only the standalone fallback"
    );
}

#[test]
fn e2e_build_uses_an_isolated_cargo_target_dir() {
    // The DAG's shared target is also populated by build.test_binaries with
    // $STABLE_FEATURES. The e2e runner intentionally builds with defaults,
    // so sharing target/debug/deps lets the two feature graphs replace the
    // same unhashed libreverie_examples.so. Its build must therefore use a
    // distinct Cargo target directory and look for its binaries there.
    assert!(
        E2E_SCRIPT.contains("CARGO_TARGET_DIR=\"$e2e_target_dir\" cargo build"),
        "e2e must build into its isolated Cargo target directory"
    );
    assert!(
        E2E_SCRIPT.contains("binaries=$e2e_target_dir/debug"),
        "e2e must execute the binaries from its isolated build"
    );
}

const VALIDATE_DAG: &str = include_str!("../../ci/dag/validate.json");

#[test]
fn validation_dag_builds_once_and_counts_every_test_node() {
    // One workspace test build feeds every counted nextest node.
    assert!(
        VALIDATE_DAG.contains("cargo nextest list --workspace --features \\\"$STABLE_FEATURES\\\"")
    );
    assert!(VALIDATE_DAG.contains("--binaries-metadata target/validate/binaries-metadata.json"));
    // The duplicate serial `cargo build` gate is gone from the DAG: its
    // 274 artifact identities are a subset of the test build's 420
    // (measured 2026-11-05), with clippy --all-targets covering the
    // non-test lib profile.
    assert!(!VALIDATE_DAG.contains("\"cmd\": \"cargo build --workspace"));
    assert!(
        VALIDATE_DAG
            .contains("cargo clippy --workspace --all-targets --features \\\"$STABLE_FEATURES\\\"")
    );
    // No DAG test node may fall back to serialized libtest execution.
    assert!(!VALIDATE_DAG.contains("--test-threads=1"));
    // Nine counted nextest test nodes (the launch_descriptor_window
    // binary runs at low width in its own node), each over one shared skip list
    // derived in validate.sh from REGULAR_TEST_SKIP_ARGS.
    assert_eq!(VALIDATE_DAG.matches("counts-test-").count(), 9);
    assert_eq!(
        VALIDATE_DAG.matches("REVERIE_NEXTEST_SKIP_FILTER").count(),
        9
    );
    assert!(VALIDATE_SCRIPT.contains("derive_nextest_skip_filter"));
    assert!(VALIDATE_SCRIPT.contains("run_validation_dag"));
    // The fixture node must run the release-profile producer and feed the
    // LiteInst A node that owns tool_tls; a SKIP echo is not evidence.
    assert!(VALIDATE_DAG.contains(
        r#"./scripts/build-liteinst-test-runtime.rs --for-ci \"$PWD/target/validate/liteinst-fixtures\""#
    ));
    assert!(VALIDATE_DAG.contains("source target/validate/liteinst-fixtures/bundle/fixture.env"));
    assert!(!VALIDATE_DAG.contains("SKIP (dh-hkdh0)"));
    assert!(!VALIDATE_SCRIPT.contains("--skip authenticated_"));
    // Every counted test node waits for the one build and the fixtures
    // node; fixtures therefore run concurrently with the test build.
    assert_eq!(VALIDATE_DAG.matches("\"build.test_binaries\",").count(), 9);
    // CPU-first limits: every step declares a CPU timeout.
    assert_eq!(
        VALIDATE_DAG.matches("\"cpu_timeout\"").count(),
        VALIDATE_DAG.matches("\"group\":").count()
    );
}

#[test]
fn validation_dag_checks_the_reverie_ptrace_library_for_aarch64() {
    let dag: serde_json::Value =
        serde_json::from_str(VALIDATE_DAG).expect("validate DAG must be valid JSON");
    let steps = dag["steps"]
        .as_array()
        .expect("validate DAG must declare its steps");
    let matches: Vec<_> = steps
        .iter()
        .filter(|step| step["group"] == "build" && step["job"] == "ptrace_aarch64")
        .collect();
    assert_eq!(matches.len(), 1, "expected one AArch64 ptrace check node");
    let step = matches[0];
    assert_eq!(
        step["cmd"],
        "cargo check --locked -p reverie-ptrace --lib --target aarch64-unknown-linux-gnu"
    );
    assert_eq!(step["deps"], serde_json::json!([]));
    assert_eq!(
        step["env"],
        serde_json::json!({"PKG_CONFIG_ALLOW_CROSS": "1"})
    );
    assert_eq!(step["labels"], serde_json::json!(["full"]));
    assert_eq!(step["hint"]["resources"]["cargo-build"], 1);
}

const WORKFLOW: &str = include_str!("../../.github/workflows/ci.yml");
const CORE_MANIFEST: &str = include_str!("../../reverie-liteinst/Cargo.toml");
const ALLOCATOR_TESTS: &str = include_str!("../../reverie-liteinst/tests/allocator_contract.rs");

#[test]
fn allocator_contract_is_required_by_local_and_ci_workspace_gates() {
    const REGISTERED_TARGET: &str = r#"[[test]]
name = "allocator_contract"
path = "tests/allocator_contract.rs"
required-features = ["allocator-fixture"]"#;
    assert!(CORE_MANIFEST.contains(REGISTERED_TARGET));
    assert!(!ALLOCATOR_TESTS.contains("#[ignore"));
    for name in [
        "standalone_private_allocator_matrix",
        "host_caller_keeps_its_96_mib_allocator",
        "system_roots_are_refused_before_all_three_installation_entries",
        "private_pointer_guard_has_exact_failure_and_fallback_outcomes",
        "bounded_controls_have_closed_stdin_and_fixture_input_stays_exact",
    ] {
        assert!(
            ALLOCATOR_TESTS.contains(&format!("#[test]\nfn {name}(")),
            "missing required allocator test {name}"
        );
    }
    assert_eq!(ALLOCATOR_TESTS.matches("#[test]").count(), 5);
    let build = VALIDATE_SCRIPT
        .find(
            "run_check \"Build workspace\" cargo build --workspace --features \"$STABLE_FEATURES\"",
        )
        .unwrap();
    let producer = VALIDATE_SCRIPT
        .find("run_check \"LiteInst allocator fixtures\" build_liteinst_allocator_fixtures")
        .unwrap();
    // The counted runner accepts only a command that starts with `cargo
    // test`, so the fixture paths reach this step through the environment:
    // exported immediately before it and un-exported immediately after.
    let export = VALIDATE_SCRIPT
        .find("export REVERIE_LITEINST_PRELOAD ")
        .unwrap();
    let tests = VALIDATE_SCRIPT
        .find(
            "run_test_check \"Test regular workspace cases\" cargo test --workspace --features \"$STABLE_FEATURES\"",
        )
        .unwrap();
    let unexport = VALIDATE_SCRIPT
        .find("export -n REVERIE_LITEINST_PRELOAD ")
        .unwrap();
    let docs = VALIDATE_SCRIPT
        .find("run_test_check \"Documentation tests\"")
        .unwrap();
    assert!(build < producer && producer < export && export < tests);
    assert!(tests < unexport && unexport < docs);
    let exported = &VALIDATE_SCRIPT[export..tests];
    let test_command = &VALIDATE_SCRIPT[tests..unexport];
    let unexported = &VALIDATE_SCRIPT[unexport..docs];
    assert!(!test_command.contains(" env "));
    assert!(test_command.contains("\"${REGULAR_TEST_SKIP_ARGS[@]}\""));
    for input in [
        "REVERIE_LITEINST_PRELOAD",
        "REVERIE_LITEINST_TEST_RUNTIME_MANIFEST",
        "REVERIE_LITEINST_ALLOCATOR_GUEST",
        "REVERIE_LITEINST_ALLOCATOR_GUEST_MANIFEST",
    ] {
        assert!(
            exported.contains(input),
            "{input} is not exported for the step"
        );
        assert!(
            unexported.contains(input),
            "{input} stays exported after the step"
        );
    }
    assert!(
        VALIDATE_SCRIPT
            .contains("build-liteinst-test-runtime.rs\" --for-ci \"$generation\" || return")
    );
    assert!(WORKFLOW.contains("cargo test --workspace --exclude reverie-kvm --exclude reverie-kvm-core --exclude reverie-linuxemu --exclude reverie-inguest --features \"${STABLE_FEATURES_REGULAR}\" --no-fail-fast --"));
    assert!(
        WORKFLOW.contains(
            "cargo test --workspace --features \"${STABLE_FEATURES}\" -- --test-threads=1"
        )
    );
    for job in ["  regular:", "  hardware:"] {
        let section = &WORKFLOW[WORKFLOW.find(job).unwrap()..];
        let producer = section
            .find("scripts/build-liteinst-test-runtime.rs --for-ci \"$generation\"")
            .unwrap();
        let tests = section.find("cargo test --workspace").unwrap();
        assert!(
            producer < tests,
            "{job} must qualify the actual preload before all-feature tests"
        );
        assert!(
            section[..tests].contains("cat \"$generation/bundle/github.env\" >> \"$GITHUB_ENV\"")
        );
    }
}
