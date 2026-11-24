/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `e2e/run.sh`'s ledger decision (e2e/README.md), on a stand-in build: a
//! `cargo` first on PATH logs its call and writes stand-in
//! `reverie-e2e-compare` and `recorder` executables where run.sh looks for
//! them (run.sh calls it with CARGO_TARGET_DIR set to its isolated build
//! directory), and the stand-in comparator logs its arguments and exits with
//! the status the test chooses. Without a ledger for its environment run.sh
//! judges nothing, so it fails by name (`NO LEDGER`) before it builds,
//! unless `--report-only` asks for a report, or `--report-only-if-no-ledger`
//! asks for one where no ledger exists (and judges where one does): those are
//! the only ways to exit 0 without judging. A measurement run
//! (`--write-ledger` without `--report-only`) writes its rows and then fails
//! the same way.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// An environment with a committed ledger (e2e/ledgers/<environment>.tsv).
const LEDGERED: &str = "centos-9-glibc2.34";
/// An environment with none.
const UNLEDGERED: &str = "no-such-os-0-glibc0.0";
/// The rows file a measurement names; the stand-in comparator never writes
/// it.
const ROWS: &str = "measured-rows.tsv";

/// The stand-in `cargo`.
const CARGO: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$STUB_LOG_DIR/cargo.calls"
mkdir -p "$CARGO_TARGET_DIR/debug" || exit 1
cat > "$CARGO_TARGET_DIR/debug/reverie-e2e-compare" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$STUB_LOG_DIR/compare.argv"
exit "$STUB_COMPARE_EXIT"
EOF
printf '#!/bin/sh\nexit 0\n' > "$CARGO_TARGET_DIR/debug/recorder"
chmod 0755 "$CARGO_TARGET_DIR/debug/reverie-e2e-compare" "$CARGO_TARGET_DIR/debug/recorder"
"#;

/// What one run.sh run did.
struct Run {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    cargo_called: bool,
    /// The stand-in comparator's arguments, one per line, if it ran.
    compare_argv: Option<Vec<String>>,
}

impl Run {
    fn transcript(&self) -> String {
        format!(
            "status {:?}\nstdout:\n{}\nstderr:\n{}",
            self.status, self.stdout, self.stderr
        )
    }

    /// The value the comparator got after `flag`, if it got the flag.
    fn compare_value(&self, flag: &str) -> Option<&str> {
        let argv = self.compare_argv.as_ref()?;
        let at = argv.iter().position(|arg| arg == flag)?;
        argv.get(at + 1).map(String::as_str)
    }

    fn compare_has(&self, flag: &str) -> bool {
        self.compare_argv
            .as_ref()
            .is_some_and(|argv| argv.iter().any(|arg| arg == flag))
    }
}

/// Run e2e/run.sh with `args` on the stand-in build, the stand-in
/// comparator exiting with `compare_exit`.
fn run(args: &[&str], compare_exit: i32) -> Run {
    let directory = tempfile::tempdir().unwrap();
    let bin = directory.path().join("bin");
    let logs = directory.path().join("logs");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&logs).unwrap();
    let cargo = bin.join("cargo");
    fs::write(&cargo, CARGO).unwrap();
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("e2e/run.sh");
    let output = Command::new(&script)
        .args(args)
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", directory.path().join("target"))
        .env("STUB_LOG_DIR", &logs)
        .env("STUB_COMPARE_EXIT", compare_exit.to_string())
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", script.display()));
    Run {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        cargo_called: logs.join("cargo.calls").exists(),
        compare_argv: fs::read_to_string(logs.join("compare.argv"))
            .ok()
            .map(|text| text.lines().map(str::to_owned).collect()),
    }
}

/// Case (i): no ledger, no flags: exit 1 by name, before any build.
#[test]
fn missing_ledger_fails_by_name_before_any_build() {
    let run = run(&["--environment", UNLEDGERED, "--backends", "ptrace"], 0);
    assert_eq!(
        run.status,
        Some(1),
        "case (i): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        !run.cargo_called,
        "case (i): stub cargo was called; {}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains(&format!("NO LEDGER for environment {UNLEDGERED}")),
        "case (i): NO LEDGER line; {}",
        run.transcript()
    );
    assert!(
        run.compare_argv.is_none(),
        "case (i): the comparator ran; {}",
        run.transcript()
    );
}

/// Case (ii): no ledger, `--write-ledger`: measured in report mode, rows
/// written, then exit 1 by name.
#[test]
fn missing_ledger_measurement_run_still_fails() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--write-ledger",
            ROWS,
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(1),
        "case (ii): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.cargo_called,
        "case (ii): stub cargo was not called; {}",
        run.transcript()
    );
    assert_eq!(
        run.compare_value("--write-ledger"),
        Some(ROWS),
        "case (ii): comparator --write-ledger; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (ii): comparator --report-only; {}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains(&format!("NO LEDGER for environment {UNLEDGERED}")),
        "case (ii): NO LEDGER line; {}",
        run.transcript()
    );
}

/// Case (iii): no ledger, explicit `--report-only`: exit 0.
#[test]
fn explicit_report_only_without_ledger_exits_zero() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--report-only",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (iii): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (iii): comparator --report-only; {}",
        run.transcript()
    );
}

/// Case (iii'): no ledger, `--report-only --write-ledger`, README's
/// measurement form: exit 0, and the comparator writes the rows.
#[test]
fn explicit_report_only_with_write_ledger_exits_zero() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--report-only",
            "--write-ledger",
            ROWS,
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (iii'): run.sh exit status; {}",
        run.transcript()
    );
    assert_eq!(
        run.compare_value("--write-ledger"),
        Some(ROWS),
        "case (iii'): comparator --write-ledger; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (iii'): comparator --report-only; {}",
        run.transcript()
    );
}

/// Case (iv): a ledgered environment is judged against its ledger, and the
/// comparator's success is run.sh's.
#[test]
fn ledgered_env_is_judged_and_passes_comparator_success() {
    let run = run(&["--environment", LEDGERED, "--backends", "ptrace"], 0);
    assert_eq!(
        run.status,
        Some(0),
        "case (iv): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains(&format!("judging against ledgers/{LEDGERED}.tsv")),
        "case (iv): judging line; {}",
        run.transcript()
    );
    assert!(
        run.compare_value("--expected")
            .is_some_and(|ledger| ledger.ends_with(&format!("/ledgers/{LEDGERED}.tsv"))),
        "case (iv): comparator --expected; {}",
        run.transcript()
    );
    assert!(
        !run.compare_has("--report-only"),
        "case (iv): comparator --report-only; {}",
        run.transcript()
    );
}

/// Case (iv'): the comparator's failure is run.sh's.
#[test]
fn ledgered_env_forwards_comparator_failure() {
    let run = run(&["--environment", LEDGERED, "--backends", "ptrace"], 1);
    assert_eq!(
        run.status,
        Some(1),
        "case (iv'): run.sh exit status; {}",
        run.transcript()
    );
}

/// Case (vii): `--require-compared` reaches the comparator unchanged.
#[test]
fn require_compared_is_forwarded_to_the_comparator() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace,liteinst,in-guest-trap",
            "--require-compared",
            "ptrace,liteinst,in-guest-trap",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (vii): run.sh exit status; {}",
        run.transcript()
    );
    assert_eq!(
        run.compare_value("--require-compared"),
        Some("ptrace,liteinst,in-guest-trap"),
        "case (vii): comparator --require-compared; {}",
        run.transcript()
    );
}

/// Case (viii): a `--require-compared` backend that `--backends` does not
/// request is a usage error, before any build.
#[test]
fn require_compared_backend_not_requested_is_a_usage_error() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace",
            "--require-compared",
            "ptrace,liteinst",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(2),
        "case (viii): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        !run.cargo_called,
        "case (viii): stub cargo was called; {}",
        run.transcript()
    );
    assert!(
        run.stderr.contains("--require-compared lists liteinst"),
        "case (viii): the refusal names liteinst; {}",
        run.transcript()
    );
}

/// Case (ix): an empty item in `--require-compared` (a trailing, a leading or
/// a doubled comma) is a usage error, before any build. The trailing comma
/// comes first.
#[test]
fn require_compared_empty_item_is_a_usage_error() {
    for list in ["ptrace,", ",ptrace", "ptrace,,liteinst"] {
        let run = run(
            &[
                "--environment",
                LEDGERED,
                "--backends",
                "ptrace",
                "--require-compared",
                list,
            ],
            0,
        );
        assert_eq!(
            run.status,
            Some(2),
            "case (ix), list {list:?}: run.sh exit status; {}",
            run.transcript()
        );
        assert!(
            !run.cargo_called,
            "case (ix), list {list:?}: stub cargo was called; {}",
            run.transcript()
        );
        assert!(
            run.stderr
                .contains(&format!("--require-compared has an empty item: {list}")),
            "case (ix), list {list:?}: the refusal names the list; {}",
            run.transcript()
        );
    }
}

/// Case (x): a measurement keeps the comparator's own nonzero status.
#[test]
fn missing_ledger_measurement_keeps_a_comparator_failure() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--write-ledger",
            ROWS,
        ],
        2,
    );
    assert_eq!(
        run.status,
        Some(2),
        "case (x): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains(&format!("NO LEDGER for environment {UNLEDGERED}")),
        "case (x): NO LEDGER line; {}",
        run.transcript()
    );
}

/// Case (xi): a ledgered environment with `--report-only` is reported, not
/// judged: exit 0, and the comparator gets no ledger.
#[test]
fn ledgered_env_report_only_exits_zero() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace",
            "--report-only",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (xi): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (xi): comparator --report-only; {}",
        run.transcript()
    );
    assert!(
        !run.compare_has("--expected"),
        "case (xi): comparator --expected; {}",
        run.transcript()
    );
    assert!(
        run.stdout.contains("report only, by request"),
        "case (xi): report-only line; {}",
        run.transcript()
    );
}

/// Case (xi'): the same with `--write-ledger`: exit 0, and the comparator
/// writes the rows.
#[test]
fn ledgered_env_report_only_with_write_ledger_exits_zero() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace",
            "--report-only",
            "--write-ledger",
            ROWS,
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (xi'): run.sh exit status; {}",
        run.transcript()
    );
    assert_eq!(
        run.compare_value("--write-ledger"),
        Some(ROWS),
        "case (xi'): comparator --write-ledger; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (xi'): comparator --report-only; {}",
        run.transcript()
    );
}

/// Case (xii): a ledgered environment with `--write-ledger` (no
/// `--report-only`) is judged against its ledger, the comparator also writes
/// the rows, and the comparator's status is run.sh's.
#[test]
fn ledgered_env_write_ledger_is_judged_and_writes_rows() {
    let args = [
        "--environment",
        LEDGERED,
        "--backends",
        "ptrace",
        "--write-ledger",
        ROWS,
    ];
    let pass = run(&args, 0);
    assert_eq!(
        pass.status,
        Some(0),
        "case (xii): run.sh exit status; {}",
        pass.transcript()
    );
    assert!(
        pass.stdout
            .contains(&format!("judging against ledgers/{LEDGERED}.tsv")),
        "case (xii): judging line; {}",
        pass.transcript()
    );
    assert!(
        pass.compare_value("--expected")
            .is_some_and(|ledger| ledger.ends_with(&format!("/ledgers/{LEDGERED}.tsv"))),
        "case (xii): comparator --expected; {}",
        pass.transcript()
    );
    assert_eq!(
        pass.compare_value("--write-ledger"),
        Some(ROWS),
        "case (xii): comparator --write-ledger; {}",
        pass.transcript()
    );
    assert!(
        !pass.compare_has("--report-only"),
        "case (xii): comparator --report-only; {}",
        pass.transcript()
    );
    let fail = run(&args, 1);
    assert_eq!(
        fail.status,
        Some(1),
        "case (xii): run.sh exit status on a comparator failure; {}",
        fail.transcript()
    );
}

/// Case (xiii): `--report-only-if-no-ledger` in a ledgered environment changes
/// nothing: judged against the ledger, exactly as without it.
#[test]
fn report_only_if_no_ledger_judges_where_a_ledger_exists() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace",
            "--report-only-if-no-ledger",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (xiii): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.stdout
            .contains(&format!("judging against ledgers/{LEDGERED}.tsv")),
        "case (xiii): judging line; {}",
        run.transcript()
    );
    assert!(
        run.compare_value("--expected")
            .is_some_and(|ledger| ledger.ends_with(&format!("/ledgers/{LEDGERED}.tsv"))),
        "case (xiii): comparator --expected; {}",
        run.transcript()
    );
    assert!(
        !run.compare_has("--report-only"),
        "case (xiii): comparator --report-only; {}",
        run.transcript()
    );
}

/// Case (xiii'): there, the comparator's failure is still run.sh's.
#[test]
fn report_only_if_no_ledger_forwards_comparator_failure_where_a_ledger_exists() {
    let run = run(
        &[
            "--environment",
            LEDGERED,
            "--backends",
            "ptrace",
            "--report-only-if-no-ledger",
        ],
        1,
    );
    assert_eq!(
        run.status,
        Some(1),
        "case (xiii'): run.sh exit status; {}",
        run.transcript()
    );
}

/// Case (xiv): `--report-only-if-no-ledger` without a ledger builds, reports
/// without judging, names why, and exits 0.
#[test]
fn report_only_if_no_ledger_reports_without_a_ledger() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--report-only-if-no-ledger",
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (xiv): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.cargo_called,
        "case (xiv): stub cargo was not called; {}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(&format!(
            "NO LEDGER for environment {UNLEDGERED} (ledgers/{UNLEDGERED}.tsv): report only, --report-only-if-no-ledger"
        )),
        "case (xiv): the named report-only line; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (xiv): comparator --report-only; {}",
        run.transcript()
    );
    assert!(
        !run.compare_has("--expected"),
        "case (xiv): comparator --expected; {}",
        run.transcript()
    );
}

/// Case (xv): `--report-only-if-no-ledger --write-ledger` without a ledger
/// reports and writes the rows, and exits 0: the option makes the
/// measurement a report, not the failing measurement of case (ii).
#[test]
fn report_only_if_no_ledger_with_write_ledger_reports_and_writes() {
    let run = run(
        &[
            "--environment",
            UNLEDGERED,
            "--backends",
            "ptrace",
            "--report-only-if-no-ledger",
            "--write-ledger",
            ROWS,
        ],
        0,
    );
    assert_eq!(
        run.status,
        Some(0),
        "case (xv): run.sh exit status; {}",
        run.transcript()
    );
    assert!(
        run.cargo_called,
        "case (xv): stub cargo was not called; {}",
        run.transcript()
    );
    assert!(
        run.stdout.contains(&format!(
            "NO LEDGER for environment {UNLEDGERED} (ledgers/{UNLEDGERED}.tsv): report only, --report-only-if-no-ledger"
        )),
        "case (xv): the named report-only line; {}",
        run.transcript()
    );
    assert!(
        run.compare_has("--report-only"),
        "case (xv): comparator --report-only; {}",
        run.transcript()
    );
    assert_eq!(
        run.compare_value("--write-ledger"),
        Some(ROWS),
        "case (xv): comparator --write-ledger; {}",
        run.transcript()
    );
    assert!(
        !run.compare_has("--expected"),
        "case (xv): comparator --expected; {}",
        run.transcript()
    );
}
