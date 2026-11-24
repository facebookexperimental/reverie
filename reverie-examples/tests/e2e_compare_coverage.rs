/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The comparator's coverage rule (`--require-compared`, e2e/compare.rs) on
//! the real binary, with a stand-in recorder and a one-cell corpus: every
//! corpus cell must be compared (`match` or `mismatch`) on every listed
//! backend. A refusal or an unstable native baseline is a gap even where the
//! ledger expects it, and also under `--report-only`; a listed backend the
//! run does not compare is a usage error.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const CELL: &str = "one";

/// The tracking issue measured ledger rows link (compare.rs).
const ISSUE: &str = "https://github.com/rrnewton/hermit/issues/4485";

/// The stand-in recorder, called as `--backend BACKEND --output RECORD --
/// PROGRAM ARGS...`. STUB_MODE picks a behaviour: `refuse-liteinst` refuses
/// on liteinst by name, `native-unstable` gives each native run another exit
/// code; otherwise every backend records the same calls.
const RECORDER: &str = r#"#!/bin/sh
backend=$2
output=$4
case "$STUB_MODE:$backend" in
    refuse-liteinst:liteinst)
        echo "REFUSED: liteinst is not available to this stand-in" >&2
        exit 1
        ;;
    native-unstable:native)
        count=$(cat "$STUB_DIR/native.count" 2>/dev/null || echo 0)
        count=$((count + 1))
        echo "$count" > "$STUB_DIR/native.count"
        printf 'exit %s\nthread 0\nexecve=ok\nbrk=ok\nwrite=3\nexit_group\n' "$count" > "$output"
        exit 0
        ;;
esac
printf 'exit 0\nthread 0\nexecve=ok\nbrk=ok\nwrite=3\nexit_group\n' > "$output"
"#;

struct Compare {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    /// Whether the cell's artifacts directory exists: the cell ran.
    cell_ran: bool,
}

impl Compare {
    fn transcript(&self) -> String {
        format!(
            "status {:?}\nstdout:\n{}\nstderr:\n{}",
            self.status, self.stdout, self.stderr
        )
    }

    /// Whether stdout names a coverage gap for `backend` on the cell.
    fn gap(&self, backend: &str) -> bool {
        self.stdout
            .lines()
            .any(|line| line.starts_with(&format!("COVERAGE\t{CELL}\t{backend}\t")))
    }
}

/// Run the comparator over the one-cell corpus. `ledger` is the expected
/// rows (None: `--report-only`).
fn compare(mode: &str, backends: &str, required: &str, ledger: Option<&str>) -> Compare {
    let directory = tempfile::tempdir().unwrap();
    let recorder = directory.path().join("recorder");
    fs::write(&recorder, RECORDER).unwrap();
    fs::set_permissions(&recorder, fs::Permissions::from_mode(0o755)).unwrap();
    let corpus = directory.path().join("corpus.tsv");
    fs::write(&corpus, format!("{CELL}\t/bin/true\n")).unwrap();
    let artifacts = directory.path().join("artifacts");
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-e2e-compare"));
    command
        .env("STUB_MODE", mode)
        .env("STUB_DIR", directory.path())
        .arg("--recorder")
        .arg(&recorder)
        .args(["--backends", backends])
        .arg("--corpus")
        .arg(&corpus)
        .arg("--artifacts")
        .arg(&artifacts)
        .args(["--require-compared", required]);
    match ledger {
        Some(rows) => {
            let path = directory.path().join("ledger.tsv");
            fs::write(&path, format!("# expected rows for this test\n{rows}")).unwrap();
            command.arg("--expected").arg(path);
        }
        None => {
            command.arg("--report-only");
        }
    }
    let output = command.output().expect("run reverie-e2e-compare");
    Compare {
        status: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        cell_ran: Path::new(&artifacts).join(CELL).exists(),
    }
}

/// (a) Every listed backend compared the cell: exit 0.
#[test]
fn coverage_all_match_passes() {
    let run = compare("match", "ptrace,liteinst", "ptrace,liteinst", Some(""));
    assert_eq!(run.status, Some(0), "exit status; {}", run.transcript());
    assert!(
        run.stdout
            .contains("reverie e2e: coverage: 2 of 2 required comparisons made (ptrace,liteinst)"),
        "coverage line; {}",
        run.transcript()
    );
    assert!(
        !run.gap("ptrace") && !run.gap("liteinst"),
        "a gap was named; {}",
        run.transcript()
    );
}

/// (b) liteinst refuses: exit 1, naming liteinst and the cell, although the
/// ledger expects the refusal.
#[test]
fn coverage_refused_backend_fails_by_name() {
    let rows = format!("{CELL}\tliteinst\trefused\t\t{ISSUE}\n");
    let run = compare(
        "refuse-liteinst",
        "ptrace,liteinst",
        "ptrace,liteinst",
        Some(&rows),
    );
    assert_eq!(run.status, Some(1), "exit status; {}", run.transcript());
    assert!(
        run.stdout
            .contains(&format!("{CELL}\tliteinst\trefused\t\tEXPECTED {ISSUE}")),
        "the ledger did not accept the refusal; {}",
        run.transcript()
    );
    assert!(
        run.gap("liteinst"),
        "no gap named for liteinst; {}",
        run.transcript()
    );
    assert!(
        !run.gap("ptrace"),
        "a gap named for ptrace; {}",
        run.transcript()
    );
}

/// (c) The native baseline is unstable, so no backend ran the cell: exit 1,
/// naming every listed backend, although the ledger expects the native row.
#[test]
fn coverage_native_disagreement_fails_for_every_listed_backend() {
    let rows = format!("{CELL}\tnative\tunstable\t1 -> 2\t{ISSUE}\n");
    let run = compare(
        "native-unstable",
        "ptrace,liteinst,in-guest-trap",
        "ptrace,liteinst,in-guest-trap",
        Some(&rows),
    );
    assert_eq!(run.status, Some(1), "exit status; {}", run.transcript());
    assert!(
        run.stdout.contains(&format!(
            "{CELL}\tnative\tunstable\t1 -> 2\tEXPECTED {ISSUE}"
        )),
        "the ledger did not accept the native row; {}",
        run.transcript()
    );
    for backend in ["ptrace", "liteinst", "in-guest-trap"] {
        assert!(
            run.gap(backend),
            "no gap named for {backend}; {}",
            run.transcript()
        );
    }
}

/// (d) A --require-compared backend the run does not compare: exit 2, by
/// name, before any cell runs.
#[test]
fn coverage_unlisted_backend_is_a_usage_error() {
    let run = compare("match", "ptrace", "ptrace,liteinst", Some(""));
    assert_eq!(run.status, Some(2), "exit status; {}", run.transcript());
    assert!(
        run.stderr.contains("--require-compared lists liteinst"),
        "the usage error does not name liteinst; {}",
        run.transcript()
    );
    assert!(!run.cell_ran, "a cell ran; {}", run.transcript());
}

/// (e) The refusal of (b) under --report-only: still exit 1.
#[test]
fn coverage_is_enforced_under_report_only() {
    let run = compare(
        "refuse-liteinst",
        "ptrace,liteinst",
        "ptrace,liteinst",
        None,
    );
    assert_eq!(run.status, Some(1), "exit status; {}", run.transcript());
    assert!(
        run.gap("liteinst"),
        "no gap named for liteinst; {}",
        run.transcript()
    );
}
