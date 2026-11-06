#!/usr/bin/env -S rust-script --force
//! Copyright (c) Meta Platforms, Inc. and affiliates.
//! All rights reserved.
//!
//! This source code is licensed under the BSD-style license found in the
//! LICENSE file in the root directory of this source tree.
//!
//! Join the validation DAG definition with dagrun's per-step profile
//! CSVs and print one ledger gate row per node, in DAG order:
//!
//!   <gate name>\t<exit status>\t<whole seconds>\t<counts file or ->
//!
//! validate.sh ingests these rows with the same refusal rules as its
//! serial counted checks (a passing node with missing or inconsistent
//! counts evidence is refused). The counts-file convention is shared
//! with the DAG's node commands: test.<job> nodes write
//! target/validate/counts-test-<job>.json, and test.doc writes
//! target/validate/counts-doc.json.
//!
//! ```cargo
//! [dependencies]
//! serde_json = "1"
//! ```

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

const HELP: &str = "Usage: dag-gates.rs [--since ISO8601_UTC] VALIDATE_JSON PERF_DIR\n\
\n\
Print one tab-separated ledger gate row per DAG step (latest dagrun\n\
run in PERF_DIR): gate name, exit status, whole seconds, counts file.\n\
With --since, only profile rows timestamped at or after that instant\n\
are gate evidence, so an append-only perf store can never lend a\n\
previous run's rows to a run that wrote none. A step the run skipped\n\
(failed dependency) or never launched is reported with status 3 so\n\
the gate is recorded, never dropped.\n\
\n\
Options:\n\
  --since T   only consider profile rows at or after UTC instant T\n\
  -h, --help  Show this help";

struct StepRow {
    status: i64,
    seconds: u64,
}

fn csv_field<'a>(row: &[&'a str], header: &BTreeMap<&str, usize>, name: &str) -> Option<&'a str> {
    header.get(name).and_then(|index| row.get(*index)).copied()
}

fn read_profiles(
    perf_dir: &Path,
    since: Option<&str>,
) -> Result<BTreeMap<String, StepRow>, String> {
    let mut files = Vec::new();
    let entries = fs::read_dir(perf_dir).map_err(|error| {
        format!(
            "cannot read dagrun perf dir {}: {error}",
            perf_dir.display()
        )
    })?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with("step_profiles_") && name.ends_with(".csv") {
            files.push(entry.path());
        }
    }
    if files.is_empty() {
        return Err(format!(
            "no step_profiles_*.csv in {}; the dagrun run left no gate evidence",
            perf_dir.display()
        ));
    }
    files.sort();
    // Rows from the latest run only: the run_id of the final row wins.
    let mut latest_run = String::new();
    let mut by_run: BTreeMap<String, BTreeMap<String, StepRow>> = BTreeMap::new();
    for file in &files {
        let text = fs::read_to_string(file)
            .map_err(|error| format!("cannot read {}: {error}", file.display()))?;
        let mut lines = text.lines();
        let Some(header_line) = lines.next() else {
            continue;
        };
        let header: BTreeMap<&str, usize> = header_line
            .split(',')
            .enumerate()
            .map(|(index, name)| (name, index))
            .collect();
        for name in [
            "timestamp",
            "step",
            "elapsed_s",
            "returncode",
            "ok",
            "run_id",
        ] {
            if !header.contains_key(name) {
                return Err(format!(
                    "{} header has no {name} column; dagrun profile schema drifted",
                    file.display()
                ));
            }
        }
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let row: Vec<&str> = line.split(',').collect();
            // The perf store is append-only (dagrun learns widths and
            // memory caps from it), so a run that wrote no new profiles
            // must never ingest an older run's rows as its gate
            // evidence: callers pass the validation start instant and
            // only rows at or after it are considered. Timestamps are
            // UTC ISO-8601 in both places, so string order is time order.
            if let Some(since) = since {
                let Some(timestamp) = csv_field(&row, &header, "timestamp") else {
                    return Err(format!("{} has a row without a timestamp", file.display()));
                };
                if timestamp < since {
                    continue;
                }
            }
            let (Some(step), Some(elapsed), Some(returncode), Some(ok), Some(run_id)) = (
                csv_field(&row, &header, "step"),
                csv_field(&row, &header, "elapsed_s"),
                csv_field(&row, &header, "returncode"),
                csv_field(&row, &header, "ok"),
                csv_field(&row, &header, "run_id"),
            ) else {
                return Err(format!("{} has a malformed profile row", file.display()));
            };
            let seconds = elapsed
                .parse::<f64>()
                .map(|value| value.round() as u64)
                .map_err(|_| format!("{} has a non-numeric elapsed_s", file.display()))?;
            let returncode: i64 = returncode
                .parse()
                .map_err(|_| format!("{} has a non-numeric returncode", file.display()))?;
            let status = if ok == "true" && returncode == 0 {
                0
            } else if returncode != 0 {
                returncode
            } else {
                1
            };
            latest_run = run_id.to_string();
            by_run
                .entry(run_id.to_string())
                .or_default()
                .insert(step.to_string(), StepRow { status, seconds });
        }
    }
    by_run.remove(&latest_run).ok_or_else(|| match since {
        Some(since) => format!(
            "dagrun perf CSVs contain no step rows at or after {since}; \
                 the run left no gate evidence"
        ),
        None => "dagrun perf CSVs contain no step rows".to_string(),
    })
}

fn run(dag_path: &Path, perf_dir: &Path, since: Option<&str>) -> Result<(), String> {
    let text = fs::read_to_string(dag_path)
        .map_err(|error| format!("cannot read {}: {error}", dag_path.display()))?;
    let dag: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("cannot parse {}: {error}", dag_path.display()))?;
    let steps = dag
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("{} has no steps array", dag_path.display()))?;
    let profiles = read_profiles(perf_dir, since)?;
    for step in steps {
        let group = step.get("group").and_then(serde_json::Value::as_str);
        let job = step.get("job").and_then(serde_json::Value::as_str);
        let desc = step.get("desc").and_then(serde_json::Value::as_str);
        let (Some(group), Some(job), Some(desc)) = (group, job, desc) else {
            return Err(format!(
                "{} has a step without group/job/desc",
                dag_path.display()
            ));
        };
        let key = format!("{group}.{job}");
        let counts = if group == "test" && job == "doc" {
            "target/validate/counts-doc.json".to_string()
        } else if group == "test" {
            format!("target/validate/counts-test-{job}.json")
        } else {
            "-".to_string()
        };
        match profiles.get(&key) {
            Some(row) => println!("{desc}\t{}\t{}\t{counts}", row.status, row.seconds),
            None => println!("{desc}\t3\t0\t{counts}"),
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag] if flag == "-h" || flag == "--help" => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        [dag, perf] => run(Path::new(dag), Path::new(perf), None),
        [flag, since, dag, perf] if flag == "--since" => {
            run(Path::new(dag), Path::new(perf), Some(since))
        }
        [dag, perf, flag, since] if flag == "--since" => {
            run(Path::new(dag), Path::new(perf), Some(since))
        }
        [since_arg, dag, perf] if since_arg.starts_with("--since=") => {
            let Some(since) = since_arg.strip_prefix("--since=") else {
                unreachable!("checked prefix above")
            };
            if since.is_empty() {
                Err("--since requires a UTC instant".to_string())
            } else {
                run(Path::new(dag), Path::new(perf), Some(since))
            }
        }
        _ => Err("expected [--since ISO8601_UTC] VALIDATE_JSON PERF_DIR".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dag-gates: {error}\n{HELP}");
            ExitCode::from(2)
        }
    }
}
