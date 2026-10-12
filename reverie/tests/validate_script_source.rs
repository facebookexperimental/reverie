/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

const VALIDATE_SCRIPT: &str = include_str!("../../validate.sh");

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
        .find("run_check \"Build workspace\" cargo build --workspace --all-features")
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
            "run_test_check \"Test regular workspace cases\" cargo test --workspace --all-features",
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
    assert!(WORKFLOW.contains("cargo test --workspace --exclude reverie-kvm --exclude reverie-inguest --all-features --no-fail-fast --"));
    assert!(WORKFLOW.contains("cargo test --workspace --all-features -- --test-threads=1"));
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
