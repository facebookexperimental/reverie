#!/usr/bin/env -S rust-script --force
//! Copyright (c) Meta Platforms, Inc. and affiliates.
//! All rights reserved.
//!
//! This source code is licensed under the BSD-style license found in the
//! LICENSE file in the root directory of this source tree.
//!
//! Run one Cargo test command and record producer-owned libtest counts.
//!
//! Test execution writes its result records to a private FIFO through
//! libtest's `--logfile`. The FIFO keeps records from successive test binaries
//! in one isolated stream instead of letting each binary truncate a regular
//! file. Separate `--list --format json` invocations describe the selected and
//! unfiltered test sets without executing test bodies. The count file is only
//! published when the execution records and discovery records agree.
//!
//! ```cargo
//! [dependencies]
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! ```

use std::env;
use std::fs;
use std::io;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use serde::Deserialize;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 2;
const MAX_LEDGER_TEST_COUNT: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TestCounts {
    schema_version: u32,
    executed_tests: u64,
    passed_tests: u64,
    filtered_tests: u64,
}

impl TestCounts {
    fn from_channels(
        execution: ExecutionCounts,
        selected: DiscoveryCounts,
        unfiltered: DiscoveryCounts,
    ) -> Result<Self, String> {
        let recorded = execution
            .executed
            .checked_add(execution.ignored)
            .ok_or_else(|| "execution record count overflowed u64".to_string())?;
        if recorded != selected.selected {
            return Err(format!(
                "execution recorded {recorded} tests but discovery selected {}",
                selected.selected
            ));
        }
        if execution.ignored != selected.ignored {
            return Err(format!(
                "execution recorded {} ignored tests but discovery recorded {}",
                execution.ignored, selected.ignored
            ));
        }
        if execution.passed > execution.executed {
            return Err(format!(
                "execution recorded {} passed tests but only {} executed tests",
                execution.passed, execution.executed
            ));
        }
        let classified = execution
            .passed
            .checked_add(execution.failed)
            .ok_or_else(|| "classified execution count overflowed u64".to_string())?;
        if classified != execution.executed {
            return Err(format!(
                "execution classified {classified} passed-or-failed tests but recorded {} executed tests",
                execution.executed
            ));
        }
        let filtered_tests = unfiltered
            .selected
            .checked_sub(selected.selected)
            .ok_or_else(|| {
                format!(
                    "selected discovery reported {} tests but unfiltered discovery reported {}",
                    selected.selected, unfiltered.selected
                )
            })?;
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            executed_tests: execution.executed,
            passed_tests: execution.passed,
            filtered_tests,
        })
    }

    fn validate(self) -> Result<Self, String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "unsupported test-count schema {}; expected schema {SCHEMA_VERSION}",
                self.schema_version
            ));
        }
        if self.passed_tests > self.executed_tests {
            return Err(format!(
                "passed_tests {} exceeds executed_tests {}",
                self.passed_tests, self.executed_tests
            ));
        }
        for (label, value) in [
            ("executed_tests", self.executed_tests),
            ("passed_tests", self.passed_tests),
            ("filtered_tests", self.filtered_tests),
        ] {
            if value > MAX_LEDGER_TEST_COUNT {
                return Err(format!(
                    "{label} {value} exceeds the validation ledger's supported maximum {MAX_LEDGER_TEST_COUNT}"
                ));
            }
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ExecutionCounts {
    executed: u64,
    passed: u64,
    ignored: u64,
    failed: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DiscoveryCounts {
    selected: u64,
    ignored: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct DiscoverySuite {
    discovered: u64,
    ignored: u64,
}

/// One completed libtest execution record with attributed cost. CPU is the
/// process-group CPU delta since the previous record (serial harness), so
/// it includes descendants that stayed in the group; wall is the elapsed
/// time until the record arrived. Attempt 0 is the counted run itself.
#[derive(Clone, Debug, Serialize)]
struct ExecutionRecord {
    name: String,
    outcome: String,
    cpu_usec: u64,
    wall_usec: u64,
    attempt: u32,
}

/// Per-test timeout budgets. The CPU cap is the primary limit; the wall
/// backstop is eight times the CPU cap, capped at 600 seconds (Hermit
/// policy), unless explicitly overridden by environment.
#[derive(Clone, Debug)]
struct TestBudgets {
    default_cpu_seconds: u64,
    wall_seconds_override: Option<u64>,
    per_test_cpu_seconds: std::collections::BTreeMap<String, u64>,
}

impl TestBudgets {
    fn from_env() -> Result<Self, String> {
        let mut budgets = Self {
            default_cpu_seconds: 120,
            wall_seconds_override: None,
            per_test_cpu_seconds: Default::default(),
        };
        if let Some(path) = env::var_os("REVERIE_TEST_BUDGETS") {
            let text = fs::read_to_string(&path).map_err(|error| {
                format!(
                    "cannot read REVERIE_TEST_BUDGETS {}: {error}",
                    Path::new(&path).display()
                )
            })?;
            let value: serde_json::Value = serde_json::from_str(&text)
                .map_err(|error| format!("REVERIE_TEST_BUDGETS is not JSON: {error}"))?;
            if let Some(default) = value.get("default_cpu_seconds") {
                budgets.default_cpu_seconds = default
                    .as_u64()
                    .filter(|v| *v > 0)
                    .ok_or_else(|| "default_cpu_seconds must be a positive integer".to_string())?;
            }
            if let Some(tests) = value.get("tests") {
                let tests = tests
                    .as_object()
                    .ok_or_else(|| "tests in REVERIE_TEST_BUDGETS must be an object".to_string())?;
                for (name, seconds) in tests {
                    let seconds = seconds.as_u64().filter(|v| *v > 0).ok_or_else(|| {
                        format!("CPU budget for {name} must be a positive integer")
                    })?;
                    budgets.per_test_cpu_seconds.insert(name.clone(), seconds);
                }
            }
        }
        budgets.default_cpu_seconds =
            parse_positive_env_u64("REVERIE_TEST_CPU_SECONDS", budgets.default_cpu_seconds)?;
        if env::var_os("REVERIE_TEST_WALL_SECONDS").is_some() {
            budgets.wall_seconds_override =
                Some(parse_positive_env_u64("REVERIE_TEST_WALL_SECONDS", 600)?);
        }
        Ok(budgets)
    }

    fn cpu_seconds(&self, test: &str) -> u64 {
        self.per_test_cpu_seconds
            .get(test)
            .copied()
            .unwrap_or(self.default_cpu_seconds)
    }

    fn wall_seconds(&self, test: &str) -> u64 {
        self.wall_seconds_override
            .unwrap_or_else(|| (8 * self.cpu_seconds(test)).min(600))
    }
}

fn parse_positive_env_u64(name: &str, default: u64) -> Result<u64, String> {
    match env::var(name) {
        Ok(text) => text
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| format!("{name} must be a positive integer, got {text:?}")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("{name} must be valid UTF-8: {error}")),
    }
}

fn retries_from_env() -> Result<u32, String> {
    let retries = parse_positive_env_u64("REVERIE_TEST_RETRIES", 2).or_else(|_| {
        // Zero is a valid explicit choice even though it is not positive.
        match env::var("REVERIE_TEST_RETRIES").as_deref() {
            Ok("0") => Ok(0),
            _ => Err("REVERIE_TEST_RETRIES must be an integer in 0..=2".to_string()),
        }
    })?;
    if retries > 2 {
        return Err(format!(
            "REVERIE_TEST_RETRIES={retries} exceeds the maximum of 2 counted retries"
        ));
    }
    Ok(retries as u32)
}

/// Sum utime+stime+cutime+cstime (clock ticks) over one process group.
/// USER_HZ is 100 on Linux x86_64/aarch64 userspace.
fn process_group_cpu_usec(pgid: u32) -> u64 {
    const TICKS_PER_SECOND: u64 = 100;
    let mut total_ticks = 0_u64;
    let Ok(entries) = fs::read_dir("/proc") else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        if let Some(ticks) = proc_stat_cpu_ticks_for_group(&stat, pgid) {
            total_ticks = total_ticks.saturating_add(ticks);
        }
    }
    total_ticks.saturating_mul(1_000_000 / TICKS_PER_SECOND)
}

fn proc_stat_cpu_ticks_for_group(stat: &str, pgid: u32) -> Option<u64> {
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    // After comm: state ppid pgrp session tty tpgid flags minflt cminflt
    // majflt cmajflt utime stime cutime cstime ...
    if fields.get(2).and_then(|v| v.parse::<u32>().ok()) != Some(pgid) {
        return None;
    }
    let mut total = 0_u64;
    for index in [11_usize, 12, 13, 14] {
        total = total.saturating_add(fields.get(index).and_then(|v| v.parse::<u64>().ok())?);
    }
    Some(total)
}

fn kill_process_group(pgid: u32) {
    let _ = Command::new("kill")
        .args(["-KILL", &format!("-{pgid}")])
        .status();
}

fn increment(value: &mut u64, label: &str) -> Result<(), String> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| format!("{label} overflowed u64"))?;
    Ok(())
}

fn parse_execution_record_line(line: &str) -> Result<(&str, &str), String> {
    let (outcome, name) = line
        .split_once(' ')
        .ok_or_else(|| format!("malformed libtest execution record: {line:?}"))?;
    if name.is_empty() {
        return Err("libtest execution record has an empty test name".to_string());
    }
    Ok((outcome, name))
}

fn count_execution_record(
    counts: &mut ExecutionCounts,
    outcome: &str,
    line: &str,
) -> Result<(), String> {
    match outcome {
        "ok" => {
            increment(&mut counts.executed, "executed test count")?;
            increment(&mut counts.passed, "passed test count")
        }
        "failed" => {
            increment(&mut counts.executed, "executed test count")?;
            increment(&mut counts.failed, "failed test count")
        }
        "ignored" | "ignored:" => increment(&mut counts.ignored, "ignored test count"),
        _ => Err(format!(
            "unknown libtest execution outcome {outcome:?} in record {line:?}"
        )),
    }
}

fn parse_execution_records<R: BufRead>(reader: R) -> Result<ExecutionCounts, String> {
    let mut counts = ExecutionCounts::default();
    for line in reader.lines() {
        let line = line.map_err(|error| format!("cannot read libtest execution log: {error}"))?;
        let (outcome, _name) = parse_execution_record_line(&line)?;
        count_execution_record(&mut counts, outcome, &line)?;
    }
    Ok(counts)
}

fn parse_discovery<R: BufRead>(reader: R, echo: impl Write) -> Result<DiscoveryCounts, String> {
    parse_discovery_names(reader, echo).map(|(counts, _names)| counts)
}

fn parse_discovery_names<R: BufRead>(
    reader: R,
    mut echo: impl Write,
) -> Result<(DiscoveryCounts, Vec<String>), String> {
    let mut names = Vec::new();
    let mut counts = DiscoveryCounts::default();
    let mut suite = None;
    let mut completed = 0_u64;

    for line in reader.lines() {
        let line = line.map_err(|error| format!("cannot read libtest discovery JSON: {error}"))?;
        writeln!(echo, "{line}").map_err(|error| format!("cannot copy test output: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|error| format!("libtest emitted a non-JSON line: {error}: {line:?}"))?;
        let record_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "libtest discovery record lacks string type".to_string())?;
        let event = value.get("event").and_then(serde_json::Value::as_str);
        match (record_type, event) {
            ("suite", Some("discovery")) => {
                if suite.is_some() {
                    return Err(
                        "a discovery suite started before the preceding suite completed"
                            .to_string(),
                    );
                }
                suite = Some(DiscoverySuite::default());
            }
            ("test" | "bench", Some("discovered")) => {
                let current = suite
                    .as_mut()
                    .ok_or_else(|| "a test was discovered outside a discovery suite".to_string())?;
                increment(&mut current.discovered, "discovered test count")?;
                match value.get("name").and_then(serde_json::Value::as_str) {
                    Some(name) if !name.is_empty() => names.push(name.to_string()),
                    _ => return Err("discovered test lacks a nonempty name".to_string()),
                }
                match value.get("ignore").and_then(serde_json::Value::as_bool) {
                    Some(true) => increment(&mut current.ignored, "discovered ignored count")?,
                    Some(false) => {}
                    None => return Err("discovered test lacks boolean ignore".to_string()),
                }
            }
            ("suite", Some("completed")) => {
                let current = suite
                    .take()
                    .ok_or_else(|| "a discovery suite completed without starting".to_string())?;
                let number = |field: &str| {
                    value
                        .get(field)
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| {
                            format!("completed discovery suite lacks nonnegative {field}")
                        })
                };
                let tests = number("tests")?;
                let benchmarks = number("benchmarks")?;
                let total = number("total")?;
                let ignored = number("ignored")?;
                let typed_total = tests
                    .checked_add(benchmarks)
                    .ok_or_else(|| "discovery suite total overflowed u64".to_string())?;
                if typed_total != total {
                    return Err(format!(
                        "discovery suite reports {tests} tests and {benchmarks} benchmarks but total {total}"
                    ));
                }
                if current.discovered != total || current.ignored != ignored {
                    return Err(format!(
                        "discovery records counted {} tests and {} ignored but suite reports {total} tests and {ignored} ignored",
                        current.discovered, current.ignored
                    ));
                }
                counts.selected = counts
                    .selected
                    .checked_add(total)
                    .ok_or_else(|| "selected discovery count overflowed u64".to_string())?;
                counts.ignored = counts
                    .ignored
                    .checked_add(ignored)
                    .ok_or_else(|| "ignored discovery count overflowed u64".to_string())?;
                increment(&mut completed, "completed discovery suite count")?;
            }
            ("report", None) if suite.is_none() => {}
            _ => {
                return Err(format!(
                    "unknown libtest discovery record type {record_type:?} event {event:?}"
                ));
            }
        }
    }

    if suite.is_some() {
        return Err("a discovery suite lacks a completed event".to_string());
    }
    if completed == 0 {
        return Err("libtest emitted no completed discovery suite".to_string());
    }
    Ok((counts, names))
}

fn write_counts(path: &Path, counts: TestCounts) -> Result<(), String> {
    let counts = counts.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("count path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("count path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut bytes = serde_json::to_vec(&counts)
        .map_err(|error| format!("cannot encode test counts: {error}"))?;
    bytes.push(b'\n');
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!(
            "cannot publish {} as {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn read_counts(path: &Path) -> Result<TestCounts, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "cannot read {}: {error}; rerun the counted test command to regenerate schema-{SCHEMA_VERSION} evidence",
            path.display()
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "malformed {}: {error}; rerun the counted test command to regenerate schema-{SCHEMA_VERSION} evidence",
            path.display()
        )
    })?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            format!(
                "malformed {}: schema_version must be a nonnegative integer; rerun the counted test command to regenerate schema-{SCHEMA_VERSION} evidence",
                path.display()
            )
        })?;
    if schema_version != u64::from(SCHEMA_VERSION) {
        let reason = if schema_version == 1 {
            "schema 1 has no authoritative passed_tests"
        } else {
            "the schema is unsupported"
        };
        return Err(format!(
            "cannot use {}: {reason}; rerun the counted test command to regenerate schema-{SCHEMA_VERSION} evidence",
            path.display()
        ));
    }
    let counts: TestCounts = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "malformed schema-{SCHEMA_VERSION} counts in {}: {error}; rerun the counted test command to regenerate this evidence",
            path.display()
        )
    })?;
    counts.validate().map_err(|error| {
        format!(
            "invalid schema-{SCHEMA_VERSION} counts in {}: {error}; rerun the counted test command to regenerate this evidence",
            path.display()
        )
    })
}

#[derive(Debug)]
struct CargoTestCommands {
    execution: Vec<String>,
    retry_base: Vec<String>,
    selected_discovery: Vec<String>,
    unfiltered_discovery: Vec<String>,
}

fn append_discovery_args(mut args: Vec<String>, harness_args: &[String]) -> Vec<String> {
    args.push("--".to_string());
    args.extend_from_slice(harness_args);
    args.extend([
        "--list".to_string(),
        "-Z".to_string(),
        "unstable-options".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ]);
    args
}

fn selection_args(args: &[String]) -> Result<(Vec<String>, Vec<String>), String> {
    let mut selected = Vec::new();
    let mut unfiltered = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--skip" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--skip lacks its filter".to_string())?;
                selected.extend([arg.clone(), value.clone()]);
                index += 2;
            }
            "--exact" | "--ignored" | "--include-ignored" | "--exclude-should-panic" => {
                selected.push(arg.clone());
                index += 1;
            }
            "--test" | "--bench" => {
                selected.push(arg.clone());
                unfiltered.push(arg.clone());
                index += 1;
            }
            "--test-threads" | "--logfile" | "--color" | "--format" | "--shuffle-seed" | "-Z" => {
                if args.get(index + 1).is_none() {
                    return Err(format!("{arg} lacks its value"));
                }
                index += 2;
            }
            "--force-run-in-process"
            | "--list"
            | "--fail-fast"
            | "-h"
            | "--help"
            | "--no-capture"
            | "-q"
            | "--quiet"
            | "--show-output"
            | "--report-time"
            | "--ensure-time"
            | "--shuffle" => index += 1,
            _ if arg.starts_with("--skip=") => {
                selected.push(arg.clone());
                index += 1;
            }
            _ if arg.starts_with("--test-threads=")
                || arg.starts_with("--logfile=")
                || arg.starts_with("--color=")
                || arg.starts_with("--format=")
                || arg.starts_with("--shuffle-seed=") =>
            {
                index += 1;
            }
            _ if arg.starts_with('-') => {
                return Err(format!(
                    "unsupported libtest option in counted command: {arg}"
                ));
            }
            _ => {
                selected.push(arg.clone());
                index += 1;
            }
        }
    }
    Ok((selected, unfiltered))
}

fn split_cargo_args(args: &[String]) -> Result<(Vec<String>, Option<String>), String> {
    let mut cargo_args = args[..2].to_vec();
    let mut test_name = None;
    let mut index = 2;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--message-format" | "--color" | "--config" | "-Z" | "-p" | "--package"
            | "--exclude" | "--bin" | "--example" | "--test" | "--bench" | "-F" | "--features"
            | "-j" | "--jobs" | "--profile" | "--target" | "--target-dir" | "-m"
            | "--manifest-path" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("cargo test option {arg} lacks its value"))?;
                cargo_args.extend([arg.clone(), value.clone()]);
                index += 2;
            }
            _ if arg.starts_with('-') => {
                cargo_args.push(arg.clone());
                index += 1;
            }
            _ => {
                if test_name.replace(arg.clone()).is_some() {
                    return Err("cargo test accepts at most one TESTNAME filter".to_string());
                }
                index += 1;
            }
        }
    }
    Ok((cargo_args, test_name))
}

fn cargo_test_commands(
    args: Vec<String>,
    execution_log: &Path,
) -> Result<CargoTestCommands, String> {
    if args.first().map(String::as_str) != Some("cargo")
        || args.get(1).map(String::as_str) != Some("test")
    {
        return Err(
            "run requires a cargo test command; run `libtest-counts.rs run --help` for usage"
                .to_string(),
        );
    }
    if args.iter().any(|arg| arg == "--no-run") {
        return Err("run refuses cargo test --no-run because no tests execute".to_string());
    }
    let separator = args.iter().position(|arg| arg == "--");
    let (cargo_portion, harness_args) = match separator {
        Some(index) => (&args[..index], args[index + 1..].to_vec()),
        None => (args.as_slice(), Vec::new()),
    };
    let (cargo_args, cargo_test_name) = split_cargo_args(cargo_portion)?;
    let has_no_fail_fast = cargo_portion.iter().any(|arg| arg == "--no-fail-fast");
    let (mut selected_args, unfiltered_args) = selection_args(&harness_args)?;
    if let Some(test_name) = cargo_test_name {
        selected_args.insert(0, test_name);
    }

    let mut execution = args;
    if !has_no_fail_fast {
        execution.insert(
            separator.unwrap_or(execution.len()),
            "--no-fail-fast".to_string(),
        );
    }
    if separator.is_none() {
        execution.push("--".to_string());
    }
    let retry_base = execution.clone();
    execution.extend(["--logfile".to_string(), execution_log.display().to_string()]);

    Ok(CargoTestCommands {
        execution,
        retry_base,
        selected_discovery: append_discovery_args(cargo_args.clone(), &selected_args),
        unfiltered_discovery: append_discovery_args(cargo_args, &unfiltered_args),
    })
}

fn status_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

fn discover(args: &[String]) -> Result<DiscoveryCounts, String> {
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot start cargo test discovery: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cargo test discovery stdout was not piped".to_string())?;
    let parsed = parse_discovery(io::BufReader::new(stdout), io::stdout().lock());
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for cargo test discovery: {error}"))?;
    if !status.success() {
        return Err(format!(
            "cargo test discovery exited with {}",
            status_code(status)
        ));
    }
    parsed
}

fn execution_channel_path(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("count path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("count path has no UTF-8 file name: {}", path.display()))?;
    Ok(parent.join(format!(".{file_name}.{}.libtest.fifo", std::process::id())))
}

fn create_execution_channel(path: &Path) -> Result<(fs::File, fs::File), String> {
    let status = Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(path)
        .status()
        .map_err(|error| format!("cannot start mkfifo for {}: {error}", path.display()))?;
    if !status.success() {
        return Err(format!(
            "mkfifo refused {} with exit {}",
            path.display(),
            status_code(status)
        ));
    }
    let anchor = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("cannot anchor {}: {error}", path.display()))?;
    let reader =
        fs::File::open(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok((anchor, reader))
}

fn read_execution_channel(mut reader: fs::File) -> Result<ExecutionCounts, String> {
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read libtest execution channel: {error}"))?;
    parse_execution_records(io::Cursor::new(bytes))
}

fn discover_names(args: &[String]) -> Result<(DiscoveryCounts, Vec<String>), String> {
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot start cargo test discovery: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cargo test discovery stdout was not piped".to_string())?;
    let parsed = parse_discovery_names(io::BufReader::new(stdout), io::stdout().lock());
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for cargo test discovery: {error}"))?;
    if !status.success() {
        return Err(format!(
            "cargo test discovery exited with {}",
            status_code(status)
        ));
    }
    parsed
}

struct SupervisedExecution {
    counts: ExecutionCounts,
    failed: Vec<String>,
    records: Vec<ExecutionRecord>,
    code: i32,
    timeout: Option<String>,
}

fn run_supervised(
    command: &[String],
    reader: fs::File,
    mut anchor: Option<fs::File>,
    selected_names: &[String],
    budgets: &TestBudgets,
) -> Result<SupervisedExecution, String> {
    let (sender, receiver) = std::sync::mpsc::channel::<io::Result<String>>();
    let reader_thread = std::thread::spawn(move || {
        let mut lines = io::BufReader::new(reader).lines();
        loop {
            match lines.next() {
                Some(result) => {
                    if sender.send(result).is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    });
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .process_group(0)
        .spawn()
        .map_err(|error| format!("cannot start cargo test execution: {error}"))?;
    let pgid = child.id();
    let mut counts = ExecutionCounts::default();
    let mut failed = Vec::new();
    let mut records = Vec::new();
    let mut timeout = None;
    let mut status = None;
    let mut segment_start = Instant::now();
    let mut segment_cpu_start = process_group_cpu_usec(pgid);
    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(line)) => {
                let (outcome, name) = parse_execution_record_line(&line)?;
                count_execution_record(&mut counts, outcome, &line)?;
                let cpu_now = process_group_cpu_usec(pgid);
                records.push(ExecutionRecord {
                    name: name.to_string(),
                    outcome: outcome.to_string(),
                    cpu_usec: cpu_now.saturating_sub(segment_cpu_start),
                    wall_usec: segment_start.elapsed().as_micros() as u64,
                    attempt: 0,
                });
                if outcome == "failed" {
                    failed.push(name.to_string());
                }
                segment_start = Instant::now();
                segment_cpu_start = cpu_now;
            }
            Ok(Err(error)) => {
                return Err(format!("cannot read libtest execution log: {error}"));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if status.is_none() {
            if let Some(done) = child
                .try_wait()
                .map_err(|error| format!("cannot wait for cargo test execution: {error}"))?
            {
                status = Some(done);
                drop(anchor.take());
                continue;
            }
            let recorded = counts.executed.saturating_add(counts.ignored) as usize;
            let in_flight = selected_names
                .get(recorded)
                .map(String::as_str)
                .unwrap_or("<unknown in-flight test>");
            let cpu_used = process_group_cpu_usec(pgid).saturating_sub(segment_cpu_start);
            let wall_used = segment_start.elapsed();
            let cpu_cap = budgets.cpu_seconds(in_flight).saturating_mul(1_000_000);
            let wall_cap = Duration::from_secs(budgets.wall_seconds(in_flight));
            if cpu_used > cpu_cap || wall_used > wall_cap {
                timeout = Some(format!(
                    "test {in_flight} exceeded timeout budget: used {:.1}s CPU (cap {}s) and {:.1}s wall (backstop {}s)",
                    cpu_used as f64 / 1e6,
                    budgets.cpu_seconds(in_flight),
                    wall_used.as_secs_f64(),
                    budgets.wall_seconds(in_flight),
                ));
                kill_process_group(pgid);
                status = Some(
                    child
                        .wait()
                        .map_err(|error| format!("cannot wait for timed-out test: {error}"))?,
                );
                drop(anchor.take());
            }
        }
    }
    let status = match status {
        Some(status) => status,
        None => child
            .wait()
            .map_err(|error| format!("cannot wait for cargo test execution: {error}"))?,
    };
    let _ = reader_thread.join();
    Ok(SupervisedExecution {
        counts,
        failed,
        records,
        code: status_code(status),
        timeout,
    })
}

/// One bounded batch rerun of the named failed tests. Returns the names
/// that passed. Output is echoed so the validate log keeps full evidence.
fn run_retry_batch(retry_base: &[String], names: &[String]) -> Result<Vec<String>, String> {
    let retryable: Vec<&String> = names.iter().filter(|n| !n.contains(' ')).collect();
    if retryable.is_empty() {
        return Ok(Vec::new());
    }
    let mut args: Vec<String> = retry_base.to_vec();
    args.push("--exact".to_string());
    args.extend(retryable.iter().map(|n| n.to_string()));
    let mut child = Command::new(&args[0])
        .args(&args[1..])
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start cargo test retry: {error}"))?;
    let pgid = child.id();
    let deadline = Instant::now() + Duration::from_secs(600);
    let output = loop {
        match child.try_wait() {
            Ok(Some(_)) => break child.wait_with_output(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    kill_process_group(pgid);
                    break child.wait_with_output();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(format!("cannot wait for cargo test retry: {error}")),
        }
    }
    .map_err(|error| format!("cannot collect cargo test retry output: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    let mut passed = Vec::new();
    for line in stdout.lines().chain(stderr.lines()) {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("test ") {
            if let Some(name) = rest.strip_suffix(" ... ok") {
                if retryable.iter().any(|n| n.as_str() == name)
                    && !passed.contains(&name.to_string())
                {
                    passed.push(name.to_string());
                }
            }
        }
    }
    Ok(passed)
}

fn write_cpu_report(path: &Path, records: &[ExecutionRecord]) -> Result<(), String> {
    let report = env::var_os("REVERIE_TEST_CPU_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| path.with_extension("cpu.jsonl"));
    let mut text = String::new();
    for record in records {
        text.push_str(
            &serde_json::to_string(record)
                .map_err(|error| format!("cannot serialize CPU report record: {error}"))?,
        );
        text.push('\n');
    }
    fs::write(&report, text)
        .map_err(|error| format!("cannot write CPU report {}: {error}", report.display()))
}

fn run(path: PathBuf, args: Vec<String>) -> Result<i32, String> {
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("cannot remove stale {}: {error}", path.display()))?;
    }
    let execution_channel = execution_channel_path(&path)?;
    if execution_channel.exists() {
        fs::remove_file(&execution_channel).map_err(|error| {
            format!(
                "cannot remove stale {}: {error}",
                execution_channel.display()
            )
        })?;
    }
    if let Some(parent) = execution_channel.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let commands = cargo_test_commands(args, &execution_channel)?;
    let budgets = TestBudgets::from_env()?;
    let max_retries = retries_from_env()?;
    let (selected, selected_names) = discover_names(&commands.selected_discovery)?;
    let unfiltered = discover(&commands.unfiltered_discovery)?;

    let (anchor, reader) = create_execution_channel(&execution_channel)?;
    let outcome = run_supervised(
        &commands.execution,
        reader,
        Some(anchor),
        &selected_names,
        &budgets,
    );
    fs::remove_file(&execution_channel)
        .map_err(|error| format!("cannot remove {}: {error}", execution_channel.display()))?;
    let mut outcome = outcome?;
    if let Some(timeout) = &outcome.timeout {
        write_cpu_report(&path, &outcome.records)?;
        return Err(timeout.clone());
    }
    let mut code = outcome.code;
    // Blanket counted retries (owner policy): every failed test gets up to
    // REVERIE_TEST_RETRIES (default/max 2) batch reruns. A pass on retry is
    // recorded as FLAKY in the output and CPU report, never silent.
    let mut flaky_total = 0_usize;
    for attempt in 1..=max_retries {
        if outcome.failed.is_empty() {
            break;
        }
        let passed = run_retry_batch(&commands.retry_base, &outcome.failed)?;
        if passed.is_empty() {
            break;
        }
        flaky_total += passed.len();
        for name in &passed {
            eprintln!("REVERIE_FLAKY: {name} passed on retry attempt {attempt}");
            outcome.records.push(ExecutionRecord {
                name: name.clone(),
                outcome: "ok".to_string(),
                cpu_usec: 0,
                wall_usec: 0,
                attempt,
            });
            outcome.counts.failed = outcome.counts.failed.saturating_sub(1);
            outcome.counts.passed = outcome.counts.passed.saturating_add(1);
        }
        outcome.failed.retain(|name| !passed.contains(name));
        if outcome.failed.is_empty() {
            eprintln!(
                "REVERIE_FLAKY_SUMMARY: {} test(s) passed only on retry",
                flaky_total
            );
            code = 0;
        }
    }
    write_cpu_report(&path, &outcome.records)?;
    let execution = outcome.counts;
    if code == 0 && execution.failed != 0 {
        return Err(format!(
            "cargo test exited successfully but its execution log recorded {} failures",
            execution.failed
        ));
    }
    let counts = TestCounts::from_channels(execution, selected, unfiltered)?;
    write_counts(&path, counts)?;
    Ok(code)
}

fn self_test() -> Result<(), String> {
    // Timeout budget and process-group CPU accounting primitives.
    let budgets = TestBudgets {
        default_cpu_seconds: 120,
        wall_seconds_override: None,
        per_test_cpu_seconds: [("slow".to_string(), 90)].into_iter().collect(),
    };
    if budgets.cpu_seconds("slow") != 90
        || budgets.cpu_seconds("other") != 120
        || budgets.wall_seconds("slow") != 600
        || budgets.wall_seconds("other") != 600
    {
        return Err("timeout budget resolution differs".to_string());
    }
    let stat = "123 (a b) S 1 4242 4242 0 -1 0 0 0 0 0 100 50 20 10 0 0 1 0 0";
    if proc_stat_cpu_ticks_for_group(stat, 4242) != Some(180)
        || proc_stat_cpu_ticks_for_group(stat, 7).is_some()
    {
        return Err("process-group CPU tick parsing differs".to_string());
    }
    let selected = concat!(
        "{\"type\":\"suite\",\"event\":\"discovery\"}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"a\",\"ignore\":false}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"b\",\"ignore\":false}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"c\",\"ignore\":true}\n",
        "{\"type\":\"suite\",\"event\":\"completed\",\"tests\":3,",
        "\"benchmarks\":0,\"total\":3,\"ignored\":1}\n"
    );
    let unfiltered = concat!(
        "{\"type\":\"suite\",\"event\":\"discovery\"}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"a\",\"ignore\":false}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"b\",\"ignore\":false}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"c\",\"ignore\":true}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"d\",\"ignore\":false}\n",
        "{\"type\":\"suite\",\"event\":\"completed\",\"tests\":4,",
        "\"benchmarks\":0,\"total\":4,\"ignored\":1}\n"
    );
    let selected_counts = parse_discovery(selected.as_bytes(), io::sink())?;
    let unfiltered_counts = parse_discovery(unfiltered.as_bytes(), io::sink())?;
    let execution =
        parse_execution_records("ok a\nfailed b\nignored: reason supplied c\n".as_bytes())?;
    let counts = TestCounts::from_channels(execution, selected_counts, unfiltered_counts)?;
    if execution.executed != 2
        || execution.passed != 1
        || execution.failed != 1
        || execution.ignored != 1
        || counts.executed_tests != 2
        || counts.passed_tests != 1
        || counts.filtered_tests != 1
    {
        return Err(format!("typed channels produced {counts:?}"));
    }

    let mutated_execution = parse_execution_records("ok a\nignored c\n".as_bytes())?;
    if TestCounts::from_channels(mutated_execution, selected_counts, unfiltered_counts).is_ok() {
        return Err("missing execution result was accepted".to_string());
    }
    let mutated_discovery = DiscoveryCounts {
        selected: 4,
        ignored: 1,
    };
    if TestCounts::from_channels(execution, mutated_discovery, unfiltered_counts).is_ok() {
        return Err("execution and discovery disagreement was accepted".to_string());
    }
    if parse_execution_records("passed a\n".as_bytes()).is_ok() {
        return Err("unknown execution outcome was accepted".to_string());
    }
    if parse_discovery("same rendered text\n".as_bytes(), io::sink()).is_ok() {
        return Err("human output was accepted as libtest JSON".to_string());
    }
    if parse_discovery(
        "{\"type\":\"suite\",\"event\":\"discovery\"}\n".as_bytes(),
        io::sink(),
    )
    .is_ok()
    {
        return Err("incomplete discovery evidence was accepted".to_string());
    }
    let mismatched = concat!(
        "{\"type\":\"suite\",\"event\":\"discovery\"}\n",
        "{\"type\":\"test\",\"event\":\"discovered\",\"name\":\"a\",\"ignore\":false}\n",
        "{\"type\":\"suite\",\"event\":\"completed\",\"tests\":2,",
        "\"benchmarks\":0,\"total\":2,\"ignored\":0}\n"
    );
    if parse_discovery(mismatched.as_bytes(), io::sink()).is_ok() {
        return Err("mutated discovery total was accepted".to_string());
    }

    let command = cargo_test_commands(
        ["cargo", "test", "--workspace", "--", "selected"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        Path::new("/tmp/libtest-counts-self-test.fifo"),
    )?;
    let no_fail_fast = command
        .execution
        .iter()
        .position(|argument| argument == "--no-fail-fast")
        .ok_or_else(|| "execution command did not force --no-fail-fast".to_string())?;
    let separator = command
        .execution
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| "execution command has no harness separator".to_string())?;
    if no_fail_fast >= separator {
        return Err("--no-fail-fast was not placed in Cargo's argument portion".to_string());
    }
    let command = cargo_test_commands(
        ["cargo", "test", "--no-fail-fast"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        Path::new("/tmp/libtest-counts-self-test.fifo"),
    )?;
    if command
        .execution
        .iter()
        .filter(|argument| argument.as_str() == "--no-fail-fast")
        .count()
        != 1
    {
        return Err("execution command duplicated --no-fail-fast".to_string());
    }

    let channel_path = env::temp_dir().join(format!(
        "reverie-libtest-counts-self-test.{}.fifo",
        std::process::id()
    ));
    if channel_path.exists() {
        fs::remove_file(&channel_path).map_err(|error| {
            format!(
                "cannot remove stale self-test channel {}: {error}",
                channel_path.display()
            )
        })?;
    }
    let (anchor, reader) = create_execution_channel(&channel_path)?;
    let reader_thread = std::thread::spawn(move || read_execution_channel(reader));
    for records in ["ok first\n", "ok second\nignored third\n"] {
        let mut writer = fs::OpenOptions::new()
            .write(true)
            .open(&channel_path)
            .map_err(|error| format!("cannot open self-test channel: {error}"))?;
        writer
            .write_all(records.as_bytes())
            .map_err(|error| format!("cannot write self-test channel: {error}"))?;
    }
    drop(anchor);
    let channel_counts = reader_thread
        .join()
        .map_err(|_| "self-test execution-channel reader panicked".to_string())??;
    fs::remove_file(&channel_path)
        .map_err(|error| format!("cannot remove self-test channel: {error}"))?;
    if channel_counts.executed != 2
        || channel_counts.passed != 2
        || channel_counts.failed != 0
        || channel_counts.ignored != 1
    {
        return Err(format!(
            "successive execution-channel writers produced {channel_counts:?}"
        ));
    }

    let counts_path = env::temp_dir().join(format!(
        "reverie-libtest-counts-reader-self-test.{}.json",
        std::process::id()
    ));
    let reader_result = (|| {
        let valid = TestCounts {
            schema_version: SCHEMA_VERSION,
            executed_tests: 2,
            passed_tests: 1,
            filtered_tests: 3,
        };
        write_counts(&counts_path, valid)?;
        if read_counts(&counts_path)? != valid {
            return Err("well-formed current counts did not round trip".to_string());
        }
        let cases = [
            (
                "executed_tests",
                r#"{"schema_version":2,"executed_tests":2,"passed_tests":1,"filtered_tests":0,"executed_tests":1}"#,
            ),
            (
                "executed_tests",
                r#"{"schema_version":2,"executed_tests":2,"passed_tests":1,"filtered_tests":0,"executed_tests":2}"#,
            ),
            (
                "passed_tests",
                r#"{"schema_version":2,"executed_tests":1,"passed_tests":0,"filtered_tests":0,"passed_tests":1}"#,
            ),
            (
                "passed_tests",
                r#"{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"passed_tests":1}"#,
            ),
            (
                "filtered_tests",
                r#"{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":3,"filtered_tests":0}"#,
            ),
            (
                "filtered_tests",
                r#"{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"filtered_tests":0}"#,
            ),
            (
                "schema_version",
                r#"{"schema_version":1,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"schema_version":2}"#,
            ),
            (
                "schema_version",
                r#"{"schema_version":2,"executed_tests":1,"passed_tests":1,"filtered_tests":0,"schema_version":2}"#,
            ),
        ];
        for (field, bytes) in cases {
            fs::write(&counts_path, bytes)
                .map_err(|error| format!("cannot write reader fixture: {error}"))?;
            match read_counts(&counts_path) {
                Err(error) if error.contains(&format!("duplicate field `{field}`")) => {}
                other => {
                    return Err(format!(
                        "duplicate {field} counts were not refused as duplicate evidence: {other:?}"
                    ));
                }
            }
        }
        fs::write(
            &counts_path,
            r#"{"schema_version":1,"executed_tests":2,"filtered_tests":3}"#,
        )
        .map_err(|error| format!("cannot write legacy reader fixture: {error}"))?;
        match read_counts(&counts_path) {
            Err(error) if error.contains("schema 1 has no authoritative passed_tests") => Ok(()),
            other => Err(format!(
                "legacy counts lost their refusal diagnostic: {other:?}"
            )),
        }
    })();
    let reader_cleanup = fs::remove_file(&counts_path);
    reader_result?;
    reader_cleanup.map_err(|error| format!("cannot remove reader fixture: {error}"))?;
    println!(
        "PASS: libtest execution and discovery counts are isolated, typed, and mutation-sensitive"
    );
    Ok(())
}

const TOP_LEVEL_HELP: &str = "Usage: libtest-counts.rs COMMAND [ARGS...]\n\
\n\
Record and read authoritative libtest execution counts.\n\
\n\
Commands:\n\
  run OUTPUT -- cargo test [ARGS...]  Run tests and write schema-2 counts\n\
  read OUTPUT                         Print: executed passed filtered\n\
\n\
Options:\n\
  -h, --help    Show this help\n\
  --self-test   Exercise the typed count parser and execution channel";

const RUN_HELP: &str = "Usage: libtest-counts.rs run OUTPUT -- cargo test [ARGS...]\n\
\n\
Run one Cargo test command, derive authoritative counts from libtest's private\n\
execution records, and atomically write schema-2 JSON to OUTPUT.\n\
\n\
Environment:\n\
  REVERIE_TEST_CPU_SECONDS   Per-test CPU cap in seconds (default 120)\n\
  REVERIE_TEST_WALL_SECONDS  Wall backstop override (default min(8x CPU, 600))\n\
  REVERIE_TEST_BUDGETS       JSON {default_cpu_seconds, tests:{name:seconds}}\n\
  REVERIE_TEST_RETRIES       Blanket counted retries 0..=2 (default 2)\n\
  REVERIE_TEST_CPU_REPORT    Per-test CPU report JSONL (default OUTPUT.cpu.jsonl)\n\
\n\
Options:\n\
  -h, --help  Show this help";

const READ_HELP: &str = "Usage: libtest-counts.rs read OUTPUT\n\
\n\
Validate one schema-2 count file and print: executed passed filtered.\n\
\n\
Options:\n\
  -h, --help  Show this help";

fn print_help(help: &str) {
    println!("{help}");
}

fn usage() {
    eprintln!("{TOP_LEVEL_HELP}");
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("-h" | "--help") if args.next().is_none() => {
            print_help(TOP_LEVEL_HELP);
            Ok(ExitCode::SUCCESS)
        }
        Some("run") => {
            let path = args.next().map(PathBuf::from);
            if path.as_deref() == Some(Path::new("-h"))
                || path.as_deref() == Some(Path::new("--help"))
            {
                if args.next().is_none() {
                    print_help(RUN_HELP);
                    return ExitCode::SUCCESS;
                }
                eprintln!("libtest-counts: run help accepts no additional arguments");
                eprintln!("{RUN_HELP}");
                return ExitCode::from(2);
            }
            let separator = args.next();
            match (path, separator.as_deref()) {
                (Some(path), Some("--")) => run(path, args.collect()).map(|code| {
                    if code == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(u8::try_from(code).unwrap_or(1))
                    }
                }),
                _ => Err(
                    "run requires OUTPUT -- cargo test [ARGS...]; run `libtest-counts.rs run --help` for usage"
                        .to_string(),
                ),
            }
        }
        Some("read") => {
            let path = args.next();
            if matches!(path.as_deref(), Some("-h" | "--help")) {
                if args.next().is_none() {
                    print_help(READ_HELP);
                    return ExitCode::SUCCESS;
                }
                eprintln!("libtest-counts: read help accepts no additional arguments");
                eprintln!("{READ_HELP}");
                return ExitCode::from(2);
            }
            match (path, args.next()) {
                (Some(path), None) => read_counts(Path::new(&path)).map(|counts| {
                    println!(
                        "{} {} {}",
                        counts.executed_tests, counts.passed_tests, counts.filtered_tests
                    );
                    ExitCode::SUCCESS
                }),
                _ => Err(
                    "read requires exactly one OUTPUT path; run `libtest-counts.rs read --help` for usage"
                        .to_string(),
                ),
            }
        }
        Some("--self-test") if args.next().is_none() => self_test().map(|()| ExitCode::SUCCESS),
        _ => {
            eprintln!(
                "libtest-counts: expected exactly one supported command; run `libtest-counts.rs --help` for usage"
            );
            usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("libtest-counts: {error}");
            ExitCode::from(2)
        }
    }
}
