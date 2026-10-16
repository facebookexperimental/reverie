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
//!     --expected reverie-examples/e2e/expected-mismatches.tsv \
//!     --artifacts target/e2e
//! ```
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
//! for any cell or signature. Every verdict other than `match` needs a row,
//! and every row naming a cell and backend that ran must match its verdict:
//! an unexpected difference and a stale row both fail.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(300);

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

/// The backends whose tool runs in the program, from its preload's
/// constructor: they cannot see the calls the dynamic loader makes before it,
/// at the start and again after each successful `execve`.
const LATE_START: &[&str] = &["liteinst", "in-guest-trap", "e9patch"];

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
    text.lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t').map(str::to_owned);
            let name = fields.next().expect("a cell name");
            let argv: Vec<String> = fields.collect();
            assert!(!argv.is_empty(), "cell {name} has no command");
            Cell { name, argv }
        })
        .collect()
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

fn row_matches(row: &Row, cell: &str, backend: &str, outcome: &Outcome) -> bool {
    (row.cell == "*" || row.cell == cell)
        && row.backend == backend
        && row.verdict == outcome.verdict
        && (row.signature == "*" || row.signature == outcome.signature)
}

fn main() {
    let mut recorder = None;
    let mut backends = Vec::new();
    let mut corpus = None;
    let mut expected = None;
    let mut artifacts = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args
            .next()
            .unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--recorder" => recorder = Some(PathBuf::from(value)),
            "--backends" => backends = value.split(',').map(str::to_owned).collect(),
            "--corpus" => corpus = Some(PathBuf::from(value)),
            "--expected" => expected = Some(PathBuf::from(value)),
            "--artifacts" => artifacts = Some(PathBuf::from(value)),
            _ => panic!("unknown flag {flag}"),
        }
    }
    let recorder = recorder.expect("--recorder");
    let cells = read_corpus(&corpus.expect("--corpus"));
    let ledger = read_ledger(&expected.expect("--expected"));
    let artifacts = artifacts.expect("--artifacts");
    fs::create_dir_all(&artifacts).expect("artifacts directory");
    assert!(!backends.is_empty(), "--backends names none");

    let mut used = vec![false; ledger.len()];
    let mut ran: Vec<(String, String)> = Vec::new();
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
            ran.push((cell.name.clone(), backend.clone()));
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
    if unexpected > 0 || stale > 0 {
        std::process::exit(1);
    }
}
