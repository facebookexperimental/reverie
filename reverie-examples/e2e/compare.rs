/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Compare, program by program, the syscall results each backend gives a
//! program with those native Linux gives it, through one pass-through
//! Reverie tool (`recorder`, reverie-examples/recorder.rs). A backend only
//! intercepts and injects, so every difference is a backend defect, named in
//! the ledger with its issue or failing this check.
//!
//! ```text
//! target/debug/reverie-e2e-compare \
//!     --recorder target/debug/recorder \
//!     --backends ptrace,kvm,dbt,liteinst,in-guest-trap,sabre,e9patch \
//!     --corpus reverie-examples/e2e/corpus.tsv \
//!     --expected reverie-examples/e2e/ledgers/<environment>.tsv \
//!     --artifacts target/e2e
//! ```
//!
//! (`run.sh` builds what this needs and picks the ledger.) `--report-only`
//! prints the verdicts without judging them, with no ledger; `--write-ledger
//! FILE` also writes every verdict other than `match` as a ledger row.
//! `--require-compared BACKENDS` requires every corpus cell to be compared
//! (`match` or `mismatch`) on each listed backend, judged from the verdicts
//! alone, whatever the ledger accepts and also under `--report-only`: a
//! `refused` or `no_result` verdict, or a native baseline that is `unstable`
//! or `no_result` (so no backend ran the cell), fails the run, naming each
//! cell and backend. A listed backend that `--backends` does not name is a
//! usage error.
//!
//! Each program runs natively twice (plain ptrace syscall stops); if the runs
//! disagree, the program has no stable baseline (`unstable`). Each backend's
//! run is then compared with the first: the exit code, the number of
//! threads, and each thread's syscalls with their results. The verdict is
//! `match`, `mismatch` (with the first difference as its signature),
//! `refused` (the recorder cannot run on the backend, said by name), or
//! `no_result` (the run failed).
//!
//! Ledger rows: `cell<TAB>backend<TAB>verdict<TAB>signature<TAB>issue`, `*`
//! for any cell or signature. A signature may list alternatives separated by
//! ` || `, for a first difference that varies between runs; the ledger's
//! comment above the row says why. Every verdict other than `match` needs a
//! row, and every row naming a cell and backend that ran must match its
//! verdict: an unexpected difference and a stale row both fail.
//!
//! Every program runs in the C locale, natively and on every backend,
//! whatever the host's locale ([`LOCALE`]), so that the results do not depend
//! on which locale files the host maps where.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(300);

/// The sanitizer settings reverie-ptrace adds to its guest's environment
/// (tracer.rs). Every recorder run gets them, so the ptrace guest's
/// environment is the native one. The number of variables decides when a
/// shell grows its heap: without them, `sh -c` recorded an extra brk on ptrace
/// alone when 36 or 37 variables were added to a session's environment.
const PTRACE_ENVIRONMENT: [(&str, &str); 2] = [
    ("ASAN_OPTIONS", "detect_leaks=0"),
    ("LSAN_OPTIONS", "detect_leaks=0"),
];

/// The locale every recorder run gets, replacing the host's. In a UTF-8
/// locale glibc maps locale files (`gconv-modules.cache`, `SYS_LC_MESSAGES`),
/// and the loader leaves a hole where it unmapped `/etc/ld.so.cache`, so
/// whether they land in that hole depends on the cache's size in pages. Each
/// mapping is a line of `/proc/self/maps`, and a read of it returns whole
/// lines up to one page, so the byte counts a program reads there, natively
/// and on a backend that adds mappings of its own, moved when a rewrite of
/// the host's cache changed its size in pages. The C locale maps no locale
/// file.
const LOCALE: [(&str, &str); 1] = [("LC_ALL", "C")];

struct Cell {
    name: String,
    argv: Vec<String>,
}

struct Row {
    cell: String,
    backend: String,
    verdict: String,
    signature: String,
    issue: String,
}

struct Outcome {
    verdict: &'static str,
    signature: String,
}

/// A run's record (see the recorder's documentation): the exit code and each
/// thread's calls.
#[derive(PartialEq)]
struct Record {
    exit: String,
    threads: Vec<Vec<String>>,
}

fn parse_record(text: &str) -> Option<Record> {
    let mut lines = text.lines();
    let exit = lines.next()?.strip_prefix("exit ")?.to_owned();
    let mut threads: Vec<Vec<String>> = Vec::new();
    for line in lines {
        if line.starts_with("thread ") {
            threads.push(Vec::new());
        } else {
            threads.last_mut()?.push(line.to_owned());
        }
    }
    Some(Record { exit, threads })
}

/// The first difference between the native record and a backend's.
fn first_difference(native: &Record, backend: &Record) -> Option<String> {
    for (thread, (expected, got)) in native.threads.iter().zip(&backend.threads).enumerate() {
        for (index, (a, b)) in expected.iter().zip(got).enumerate() {
            if a != b {
                return Some(format!("thread {thread} call {index}: {a} -> {b}"));
            }
        }
        if expected.len() != got.len() {
            let index = expected.len().min(got.len());
            let a = expected.get(index).map_or("(end)", String::as_str);
            let b = got.get(index).map_or("(end)", String::as_str);
            return Some(format!("thread {thread} call {index}: {a} -> {b}"));
        }
    }
    if native.threads.len() != backend.threads.len() {
        return Some(format!(
            "threads: {} -> {}",
            native.threads.len(),
            backend.threads.len()
        ));
    }
    (native.exit != backend.exit).then(|| format!("exit: {} -> {}", native.exit, backend.exit))
}

/// The backends whose tool starts after the program does: the in-guest
/// backends at their preload's constructor, after the dynamic loader's calls,
/// SaBRe once its loader has loaded the program and the plugin, and DBT after
/// the `execve` that starts the program, which runs before DynamoRIO takes
/// over. They cannot see those calls, at the start and again after each
/// successful `execve`.
// The external DynamoRIO name retains the legacy dbt startup semantics.
const LATE_START: &[&str] = &[
    "liteinst",
    "in-guest-trap",
    "e9patch",
    "dbt",
    "dynamorio",
    "sabre",
];

/// How many calls, by name, place a late-starting backend's record in the
/// native one.
const ALIGNMENT_CALLS: usize = 8;

fn call_name(call: &str) -> &str {
    call.split_once('=').map_or(call, |(name, _)| name)
}

/// The first difference between the native record and the record of a
/// backend in [`LATE_START`]. At the start of the first thread and after each
/// successful `execve`, the native calls the backend could not see are
/// skipped: the native record moves forward to the first place where the
/// longest run of the backend's next call names (at most [`ALIGNMENT_CALLS`],
/// at least two; names only, as descriptor numbers can differ) appears. From
/// there every call is compared exactly, as for any backend, so a call the
/// backend missed after its start is a difference.
fn first_late_start_difference(native: &Record, backend: &Record) -> Option<String> {
    for (thread, (expected, got)) in native.threads.iter().zip(&backend.threads).enumerate() {
        let (mut i, mut j) = (0, 0);
        let mut align = thread == 0;
        loop {
            if align {
                // The longest run of the backend's next call names, from
                // ALIGNMENT_CALLS down to two (one would place it anywhere),
                // found in the native record; its first place there.
                let found = (2..=(got.len() - j).min(ALIGNMENT_CALLS))
                    .rev()
                    .find_map(|window| {
                        let names: Vec<&str> =
                            got[j..j + window].iter().map(|c| call_name(c)).collect();
                        (i..=expected.len().saturating_sub(window)).find(|&k| {
                            expected[k..k + window]
                                .iter()
                                .map(|c| call_name(c))
                                .eq(names.iter().copied())
                        })
                    });
                // A single call left (an exec'd program whose tool saw only
                // its `exit_group`) is the thread's last: its last place.
                let found = found.or_else(|| {
                    (got.len() - j == 1)
                        .then(|| {
                            expected[i..]
                                .iter()
                                .rposition(|c| call_name(c) == call_name(&got[j]))
                                .map(|k| i + k)
                        })
                        .flatten()
                });
                match found {
                    Some(k) => i = k,
                    None if got.len() == j => {}
                    None => {
                        let b = got.get(j).map_or("(end)", String::as_str);
                        return Some(format!(
                            "thread {thread} call {i}: (no aligned start) -> {b}"
                        ));
                    }
                }
            }
            match (expected.get(i), got.get(j)) {
                (None, None) => break,
                (Some(a), Some(b)) if a == b => {
                    align = a == "execve=ok";
                    i += 1;
                    j += 1;
                }
                (a, b) => {
                    return Some(format!(
                        "thread {thread} call {i}: {} -> {}",
                        a.map_or("(end)", String::as_str),
                        b.map_or("(end)", String::as_str)
                    ));
                }
            }
        }
    }
    if native.threads.len() != backend.threads.len() {
        return Some(format!(
            "threads: {} -> {}",
            native.threads.len(),
            backend.threads.len()
        ));
    }
    (native.exit != backend.exit).then(|| format!("exit: {} -> {}", native.exit, backend.exit))
}

/// The signature a ledger row names: the first difference without its
/// position, which moves when an earlier, unrelated call changes.
fn signature(difference: &str) -> String {
    difference
        .split_once(": ")
        .map_or(difference, |(_, change)| change)
        .to_owned()
}

/// Run the recorder for `cell` on `backend`, with a deadline; the record and
/// the recorder's stderr, or why there is none.
fn record(
    recorder: &Path,
    backend: &str,
    cell: &Cell,
    output: &Path,
) -> Result<Record, (bool, String)> {
    let stderr_path = output.with_extension("stderr");
    let stderr = fs::File::create(&stderr_path).map_err(|e| (false, e.to_string()))?;
    let stdout =
        fs::File::create(output.with_extension("stdout")).map_err(|e| (false, e.to_string()))?;
    let _ = fs::remove_file(output);
    let mut child = Command::new(recorder)
        .envs(PTRACE_ENVIRONMENT)
        .envs(LOCALE)
        .arg("--backend")
        .arg(backend)
        .arg("--output")
        .arg(output)
        .arg("--")
        .args(&cell.argv)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| (false, format!("cannot start the recorder: {e}")))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err((false, format!("no result within {TIMEOUT:?}")));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err((false, e.to_string())),
        }
    };
    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    if !status.success() {
        let refused = stderr.contains("REFUSED:");
        let reason = stderr
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .unwrap_or("(no stderr)")
            .to_owned();
        return Err((refused, format!("recorder {status}: {reason}")));
    }
    let text = fs::read_to_string(output).map_err(|e| (false, format!("no record: {e}")))?;
    parse_record(&text).ok_or_else(|| (false, "unreadable record".to_owned()))
}

fn read_corpus(path: &Path) -> Vec<Cell> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    parse_corpus(&text)
}

/// The corpus's cells, one per line that is neither blank nor a comment: a
/// name, then the command. Coverage looks a cell up by name, so a name that
/// appears twice would let one cell's verdict answer for the other; it is
/// refused by name.
fn parse_corpus(text: &str) -> Vec<Cell> {
    let mut cells: Vec<Cell> = Vec::new();
    for line in text
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
    {
        let mut fields = line.split('\t').map(str::to_owned);
        let name = fields.next().expect("a cell name");
        let argv: Vec<String> = fields.collect();
        assert!(!argv.is_empty(), "cell {name} has no command");
        assert!(
            !cells.iter().any(|cell| cell.name == name),
            "corpus cell {name} appears twice"
        );
        cells.push(Cell { name, argv });
    }
    cells
}

fn read_ledger(path: &Path) -> Vec<Row> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert!(
                fields.len() == 5,
                "ledger row needs 5 tab-separated fields: {line}"
            );
            assert!(
                fields[4].starts_with("https://github.com/"),
                "ledger row needs a full issue URL: {line}"
            );
            Row {
                cell: fields[0].to_owned(),
                backend: fields[1].to_owned(),
                verdict: fields[2].to_owned(),
                signature: fields[3].to_owned(),
                issue: fields[4].to_owned(),
            }
        })
        .collect()
}

/// Separates the signatures a ledger row accepts, for a first difference that
/// varies between runs.
const SIGNATURE_ALTERNATIVES: &str = " || ";

fn row_matches(row: &Row, cell: &str, backend: &str, outcome: &Outcome) -> bool {
    (row.cell == "*" || row.cell == cell)
        && row.backend == backend
        && row.verdict == outcome.verdict
        && (row.signature == "*"
            || row
                .signature
                .split(SIGNATURE_ALTERNATIVES)
                .any(|signature| signature == outcome.signature))
}

/// The issue a measured row links until its own issue is filed.
const TRACKING_ISSUE: &str = "https://github.com/rrnewton/hermit/issues/4485";

/// The required comparisons that did not happen, each `(cell, backend,
/// why)`: every cell of `cells` must have a `match` or `mismatch` verdict on
/// every backend of `required`. `verdicts` holds each `(cell, backend,
/// verdict)` the run gave, including a cell's `native` verdict when its
/// baseline failed and no backend ran it.
fn coverage_gaps(
    cells: &[Cell],
    required: &[String],
    verdicts: &[(String, String, &str)],
) -> Vec<(String, String, String)> {
    let verdict = |cell: &str, backend: &str| {
        verdicts
            .iter()
            .find(|(c, b, _)| c == cell && b == backend)
            .map(|(_, _, verdict)| *verdict)
    };
    let mut gaps = Vec::new();
    for cell in cells {
        for backend in required {
            let why = match verdict(cell.name.as_str(), backend.as_str()) {
                Some("match" | "mismatch") => continue,
                Some(other) => other.to_owned(),
                None => match verdict(cell.name.as_str(), "native") {
                    Some(native) => format!("native baseline {native}; no backend ran"),
                    None => "not run".to_owned(),
                },
            };
            gaps.push((cell.name.clone(), backend.clone(), why));
        }
    }
    gaps
}

fn main() {
    let mut recorder = None;
    let mut backends = Vec::new();
    let mut corpus = None;
    let mut expected = None;
    let mut artifacts = None;
    let mut report_only = false;
    let mut write_ledger = None;
    let mut require_compared: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        if flag == "--report-only" {
            report_only = true;
            continue;
        }
        let value = args
            .next()
            .unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--write-ledger" => write_ledger = Some(PathBuf::from(value)),
            "--recorder" => recorder = Some(PathBuf::from(value)),
            "--backends" => backends = value.split(',').map(str::to_owned).collect(),
            "--corpus" => corpus = Some(PathBuf::from(value)),
            "--expected" => expected = Some(PathBuf::from(value)),
            "--artifacts" => artifacts = Some(PathBuf::from(value)),
            "--require-compared" => {
                require_compared = value.split(',').map(str::to_owned).collect()
            }
            _ => panic!("unknown flag {flag}"),
        }
    }
    // A coverage rule over a backend this run does not compare could not be
    // met: a usage error, before anything runs.
    for backend in &require_compared {
        if !backends.contains(backend) {
            eprintln!(
                "reverie e2e: --require-compared lists {backend}, which --backends does not name ({})",
                backends.join(",")
            );
            std::process::exit(2);
        }
    }
    let recorder = recorder.expect("--recorder");
    let cells = read_corpus(&corpus.expect("--corpus"));
    // A report-only run judges nothing: it has no ledger, or ignores one.
    let ledger = if report_only {
        Vec::new()
    } else {
        read_ledger(&expected.expect("--expected (or --report-only)"))
    };
    let mut measured = Vec::new();
    let artifacts = artifacts.expect("--artifacts");
    fs::create_dir_all(&artifacts).expect("artifacts directory");
    assert!(!backends.is_empty(), "--backends names none");

    let mut used = vec![false; ledger.len()];
    let mut ran: Vec<(String, String)> = Vec::new();
    let mut verdicts: Vec<(String, String, &str)> = Vec::new();
    let mut unexpected = 0;
    let mut counts = std::collections::BTreeMap::<(String, &str), usize>::new();
    for cell in &cells {
        let dir = artifacts.join(&cell.name);
        fs::create_dir_all(&dir).expect("cell directory");
        let first = record(&recorder, "native", cell, &dir.join("native-1.txt"));
        let second = record(&recorder, "native", cell, &dir.join("native-2.txt"));
        let baseline = match (first, second) {
            (Ok(a), Ok(b)) if a == b => Ok(a),
            (Ok(a), Ok(b)) => Err(Outcome {
                verdict: "unstable",
                signature: signature(&first_difference(&a, &b).unwrap_or_default()),
            }),
            (Err((_, why)), _) | (_, Err((_, why))) => Err(Outcome {
                verdict: "no_result",
                signature: why,
            }),
        };
        let mut results = Vec::new();
        match baseline {
            Err(outcome) => results.push(("native".to_owned(), outcome)),
            Ok(native) => {
                for backend in &backends {
                    let outcome = match record(
                        &recorder,
                        backend,
                        cell,
                        &dir.join(format!("{backend}.txt")),
                    ) {
                        Ok(got) => match if LATE_START.contains(&backend.as_str()) {
                            first_late_start_difference(&native, &got)
                        } else {
                            first_difference(&native, &got)
                        } {
                            None => Outcome {
                                verdict: "match",
                                signature: String::new(),
                            },
                            Some(difference) => {
                                println!("    {} {backend}: {difference}", cell.name);
                                Outcome {
                                    verdict: "mismatch",
                                    signature: signature(&difference),
                                }
                            }
                        },
                        Err((true, _)) => Outcome {
                            verdict: "refused",
                            signature: String::new(),
                        },
                        Err((false, why)) => Outcome {
                            verdict: "no_result",
                            signature: why,
                        },
                    };
                    results.push((backend.clone(), outcome));
                }
            }
        }
        for (backend, outcome) in results {
            if outcome.verdict != "match" {
                measured.push(format!(
                    "{}\t{backend}\t{}\t{}\t{TRACKING_ISSUE}",
                    cell.name,
                    outcome.verdict,
                    outcome.signature.replace(['\t', '\n'], " ")
                ));
            }
            ran.push((cell.name.clone(), backend.clone()));
            verdicts.push((cell.name.clone(), backend.clone(), outcome.verdict));
            *counts
                .entry((backend.clone(), outcome.verdict))
                .or_default() += 1;
            let row = ledger
                .iter()
                .position(|row| row_matches(row, &cell.name, &backend, &outcome));
            let note = match (outcome.verdict, row) {
                (_, Some(index)) => {
                    used[index] = true;
                    format!("EXPECTED {}", ledger[index].issue)
                }
                ("match", None) => String::new(),
                (_, None) if report_only => "REPORTED".to_owned(),
                (_, None) => {
                    unexpected += 1;
                    "UNEXPECTED".to_owned()
                }
            };
            println!(
                "{}\t{backend}\t{}\t{}\t{note}",
                cell.name, outcome.verdict, outcome.signature
            );
        }
    }
    // A row for a cell and backend that ran, and matched nothing, is stale:
    // the backend no longer behaves as the row says.
    let mut stale = 0;
    for (index, row) in ledger.iter().enumerate() {
        let applies = ran.iter().any(|(cell, backend)| {
            (row.cell == "*" || &row.cell == cell) && &row.backend == backend
        });
        if applies && !used[index] {
            stale += 1;
            println!(
                "STALE\t{}\t{}\t{}\t{}\t{}",
                row.cell, row.backend, row.verdict, row.signature, row.issue
            );
        }
    }
    for ((backend, verdict), count) in &counts {
        println!("summary\t{backend}\t{verdict}\t{count}");
    }
    println!(
        "reverie e2e: {} cells, {} backends, {unexpected} unexpected, {stale} stale",
        cells.len(),
        backends.len()
    );
    if let Some(path) = write_ledger {
        let header = "# cell<TAB>backend<TAB>verdict<TAB>signature<TAB>issue (full URL), measured by \
                      --write-ledger; add a comment above each group naming its defect.\n";
        fs::write(&path, format!("{header}{}\n", measured.join("\n")))
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        println!(
            "reverie e2e: wrote {} ledger rows to {}",
            measured.len(),
            path.display()
        );
    }
    // Coverage, from the verdicts alone and before the report-only return:
    // every corpus cell compared on every --require-compared backend.
    if !require_compared.is_empty() {
        let gaps = coverage_gaps(&cells, &require_compared, &verdicts);
        for (cell, backend, why) in &gaps {
            println!("COVERAGE\t{cell}\t{backend}\t{why}");
        }
        let required = cells.len() * require_compared.len();
        println!(
            "reverie e2e: coverage: {} of {required} required comparisons made ({})",
            required - gaps.len(),
            require_compared.join(",")
        );
        if cells.is_empty() {
            println!("reverie e2e: coverage: the corpus names no cell");
            std::process::exit(1);
        }
        if !gaps.is_empty() {
            std::process::exit(1);
        }
    }
    if report_only {
        println!("reverie e2e: report only; nothing was judged");
        return;
    }
    if unexpected > 0 || stale > 0 {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// A corpus cell name that appears twice is refused by name: coverage
    /// looks cells up by name, so one cell's verdict would answer for the
    /// other.
    #[test]
    #[should_panic(expected = "corpus cell alpha appears twice")]
    fn a_duplicate_corpus_cell_is_refused() {
        parse_corpus("alpha\t/bin/true\nbeta\t/bin/true\nalpha\t/bin/false\n");
    }

    /// Every recorder run, native or not, gets the C locale and the
    /// sanitizer settings, whatever this process's environment holds: a
    /// stand-in recorder writes the values it got into its record.
    #[test]
    fn every_recorder_run_gets_the_c_locale() {
        let dir = std::env::temp_dir().join(format!("reverie-e2e-compare-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let recorder = dir.join("recorder");
        // Called as: --backend BACKEND --output RECORD -- PROGRAM ARGS...
        fs::write(
            &recorder,
            "#!/bin/sh\nprintf 'exit 0\\nthread 0\\nLC_ALL=%s\\nASAN_OPTIONS=%s\\n%s\\n' \
             \"${LC_ALL-unset}\" \"${ASAN_OPTIONS-unset}\" \"$2 $6\" > \"$4\"\n",
        )
        .unwrap();
        fs::set_permissions(&recorder, fs::Permissions::from_mode(0o755)).unwrap();
        let cell = Cell {
            name: "awk".to_owned(),
            argv: vec!["/bin/awk".to_owned(), "BEGIN{print 1}".to_owned()],
        };
        for backend in ["native", "ptrace"] {
            let output = dir.join(format!("{backend}.txt"));
            let got = record(&recorder, backend, &cell, &output)
                .unwrap_or_else(|(_, why)| panic!("{backend}: {why}"));
            assert_eq!(
                got.threads,
                [[
                    "LC_ALL=C".to_owned(),
                    "ASAN_OPTIONS=detect_leaks=0".to_owned(),
                    format!("{backend} /bin/awk"),
                ]]
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    fn cells(names: &[&str]) -> Vec<Cell> {
        names
            .iter()
            .map(|name| Cell {
                name: (*name).to_owned(),
                argv: vec!["/bin/true".to_owned()],
            })
            .collect()
    }

    fn required(backends: &[&str]) -> Vec<String> {
        backends
            .iter()
            .map(|backend| (*backend).to_owned())
            .collect()
    }

    /// Only `match` and `mismatch` count as compared; `refused` and
    /// `no_result` are gaps, named with their verdict.
    #[test]
    fn coverage_counts_only_match_and_mismatch() {
        let verdicts = [
            ("a".to_owned(), "ptrace".to_owned(), "match"),
            ("a".to_owned(), "liteinst".to_owned(), "refused"),
            ("a".to_owned(), "in-guest-trap".to_owned(), "no_result"),
            ("b".to_owned(), "ptrace".to_owned(), "mismatch"),
            ("b".to_owned(), "liteinst".to_owned(), "match"),
            ("b".to_owned(), "in-guest-trap".to_owned(), "mismatch"),
        ];
        let gaps = coverage_gaps(
            &cells(&["a", "b"]),
            &required(&["ptrace", "liteinst", "in-guest-trap"]),
            &verdicts,
        );
        assert_eq!(
            gaps,
            [
                ("a".to_owned(), "liteinst".to_owned(), "refused".to_owned()),
                (
                    "a".to_owned(),
                    "in-guest-trap".to_owned(),
                    "no_result".to_owned(),
                ),
            ]
        );
    }

    /// A cell whose native baseline failed ran on no backend: a gap on
    /// every listed backend, naming the baseline's verdict.
    #[test]
    fn coverage_names_every_backend_when_the_native_baseline_fails() {
        let verdicts = [("a".to_owned(), "native".to_owned(), "unstable")];
        let gaps = coverage_gaps(
            &cells(&["a"]),
            &required(&["ptrace", "liteinst"]),
            &verdicts,
        );
        let why = "native baseline unstable; no backend ran".to_owned();
        assert_eq!(
            gaps,
            [
                ("a".to_owned(), "ptrace".to_owned(), why.clone()),
                ("a".to_owned(), "liteinst".to_owned(), why),
            ]
        );
    }
}
