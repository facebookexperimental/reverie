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
//! file. Separate `--list` invocations (all tests, then `--ignored` only)
//! describe the selected and unfiltered test sets without executing test
//! bodies, using libtest's default listing whose per-binary footers frame
//! each suite on stable Rust; libtest's JSON listing needs
//! `-Z unstable-options`. The count file is only
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

/// CPU time for one process group: live members contribute utime+stime
/// only. Child times (cutime/cstime) are excluded everywhere: guests
/// commonly leave the group (setsid), so their whole lifetime CPU
/// enters a parent's cutime at the reap instant and would be falsely
/// attributed to whichever test segment straddles that reap (measured
/// false kills: 129.6s CPU in 0.1s wall, green5; 269.3s in 0.1s,
/// green7). Live-only accounting undercounts CPU of processes that die
/// between samples; the per-test wall backstop still bounds a churn
/// loop. USER_HZ is 100 on Linux x86_64/aarch64 userspace.
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
        let Ok(_pid) = name.parse::<u32>() else {
            continue;
        };
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
    for index in [11_usize, 12] {
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

/// One default-format listing as a multiset: the same `name: test` line
/// from two binaries is two tests, so counts are per (name, kind), never
/// a set. Each binary's footer (`N tests, M benchmarks`) frames its suite:
/// listed lines must match the footer exactly, and at least one completed
/// suite is required, so empty output is refused while a genuinely
/// zero-test binary (footer `0 tests, 0 benchmarks`) is accepted.
type ListedTests = std::collections::BTreeMap<(String, &'static str), u64>;

fn parse_duration(token: &str) -> Option<()> {
    let number = token.strip_suffix('s')?;
    if number.is_empty()
        || !number.chars().all(|c| c.is_ascii_digit() || c == '.')
        || number.matches('.').count() > 1
    {
        return None;
    }
    match number.parse::<f64>() {
        Ok(value) if value.is_finite() && value >= 0.0 => Some(()),
        _ => None,
    }
}

/// Rustdoc ends a doctest listing with one timing line. Accept only its
/// exact shape; near-misses stay refused like any other unknown line.
fn is_doctest_timing(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("all doctests ran in ") else {
        return false;
    };
    match rest.split_once("; merged doctests compilation took ") {
        Some((ran, took)) => parse_duration(ran).is_some() && parse_duration(took).is_some(),
        None => parse_duration(rest).is_some(),
    }
}

fn parse_footer(line: &str) -> Option<(u64, u64)> {
    let (tests, benchmarks) = line.split_once(", ")?;
    let tests = tests
        .strip_suffix(" tests")
        .or_else(|| tests.strip_suffix(" test"))?;
    let benchmarks = benchmarks
        .strip_suffix(" benchmarks")
        .or_else(|| benchmarks.strip_suffix(" benchmark"))?;
    Some((tests.parse().ok()?, benchmarks.parse().ok()?))
}

fn parse_pretty_list<R: BufRead>(reader: R, echo: impl Write) -> Result<ListedTests, String> {
    parse_pretty_list_names(reader, echo).map(|(list, _names)| list)
}

fn parse_pretty_list_names<R: BufRead>(
    reader: R,
    mut echo: impl Write,
) -> Result<(ListedTests, Vec<String>), String> {
    let mut names = Vec::new();
    let mut list = ListedTests::new();
    let mut suite_tests = 0_u64;
    let mut suite_benchmarks = 0_u64;
    let mut completed = 0_u64;
    for line in reader.lines() {
        let line = line.map_err(|error| format!("cannot read libtest discovery list: {error}"))?;
        writeln!(echo, "{line}").map_err(|error| format!("cannot copy test output: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if is_doctest_timing(&line) {
            continue;
        }
        if let Some((tests, benchmarks)) = parse_footer(&line) {
            if suite_tests != tests || suite_benchmarks != benchmarks {
                return Err(format!(
                    "discovery suite listed {suite_tests} tests and {suite_benchmarks} benchmarks but its footer reports {tests} tests and {benchmarks} benchmarks"
                ));
            }
            suite_tests = 0;
            suite_benchmarks = 0;
            increment(&mut completed, "completed discovery suite count")?;
            continue;
        }
        let (name, kind) = line
            .rsplit_once(": ")
            .ok_or_else(|| format!("malformed libtest list line: {line:?}"))?;
        if name.is_empty() {
            return Err("libtest list line has an empty test name".to_string());
        }
        let kind = match kind {
            "test" => {
                increment(&mut suite_tests, "discovered test count")?;
                "test"
            }
            "bench" => {
                increment(&mut suite_benchmarks, "discovered benchmark count")?;
                "bench"
            }
            _ => {
                return Err(format!(
                    "unknown libtest list kind {kind:?} in line {line:?}"
                ));
            }
        };
        names.push(name.to_string());
        let count = list.entry((name.to_string(), kind)).or_default();
        increment(count, "discovered test count")?;
    }
    if suite_tests != 0 || suite_benchmarks != 0 {
        return Err("a discovery suite lacks its footer".to_string());
    }
    if completed == 0 {
        return Err("libtest emitted no completed discovery suite".to_string());
    }
    Ok((list, names))
}

fn discovery_counts(
    all: &ListedTests,
    ignored_only: &ListedTests,
) -> Result<DiscoveryCounts, String> {
    let mut counts = DiscoveryCounts::default();
    for ((name, kind), ignored) in ignored_only {
        let listed = all.get(&(name.clone(), *kind)).copied().unwrap_or(0);
        if *ignored > listed {
            return Err(format!(
                "ignored discovery lists {name:?} ({kind}) {ignored} times but full discovery lists it {listed} times"
            ));
        }
        counts.ignored = counts
            .ignored
            .checked_add(*ignored)
            .ok_or_else(|| "ignored discovery count overflowed u64".to_string())?;
    }
    for total in all.values() {
        counts.selected = counts
            .selected
            .checked_add(*total)
            .ok_or_else(|| "selected discovery count overflowed u64".to_string())?;
    }
    Ok(counts)
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
    args.push("--list".to_string());
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

fn run_list(args: &[String]) -> Result<ListedTests, String> {
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
    let parsed = parse_pretty_list(io::BufReader::new(stdout), io::stdout().lock());
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

fn discover(args: &[String]) -> Result<DiscoveryCounts, String> {
    let all = run_list(args)?;
    let mut ignored_args = args.to_vec();
    ignored_args.push("--ignored".to_string());
    let ignored_only = run_list(&ignored_args)?;
    discovery_counts(&all, &ignored_only)
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

fn run_list_names(args: &[String]) -> Result<(ListedTests, Vec<String>), String> {
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
    let parsed = parse_pretty_list_names(io::BufReader::new(stdout), io::stdout().lock());
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

fn discover_names(args: &[String]) -> Result<(DiscoveryCounts, Vec<String>), String> {
    let (all, names) = run_list_names(args)?;
    let mut ignored_args = args.to_vec();
    ignored_args.push("--ignored".to_string());
    let ignored_only = run_list(&ignored_args)?;
    let counts = discovery_counts(&all, &ignored_only)?;
    Ok((counts, names))
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

/// Test binaries open the execution FIFO (and counted outputs) from
/// their own working directories, so a relative OUTPUT would resolve
/// differently per binary. Absolutize once at entry.
fn absolutize(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot resolve the working directory: {error}"))?;
    Ok(cwd.join(path))
}

fn run(path: PathBuf, args: Vec<String>) -> Result<i32, String> {
    let path = absolutize(path)?;
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
        // Each attempt is an independent shot: a batch in which nothing
        // passes must not consume the remaining attempts (a load-correlated
        // flake fails the whole first batch, which previously broke the
        // loop and never used attempt 2).
        let passed = run_retry_batch(&commands.retry_base, &outcome.failed)?;
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

/// Aggregated nextest evidence for one counted run. Counts are derived
/// from nextest's libtest-json-plus event stream with the same
/// channel agreement rules as the libtest path: per-suite finish events
/// must reconcile with that suite's started discovery count, and the
/// per-test finish events must reconcile with the suite tallies.
#[derive(Debug)]
struct NextestRun {
    execution: ExecutionCounts,
    selected: DiscoveryCounts,
    unfiltered: DiscoveryCounts,
    records: Vec<ExecutionRecord>,
    /// (test name, retry attempt that passed), in finish order.
    flaky: Vec<(String, u32)>,
    /// (test name, captured stdout) for finally-failed tests.
    failures: Vec<(String, String)>,
}

/// One binary's segments. nextest usually emits exactly one
/// started/finished pair per binary, but it can emit a second segment
/// for the same binary (observed 2026-11-05: reverie-liteinst
/// generic_bootstrap, where one test's process died mid-stream and a
/// later segment re-ran one test). Counts therefore aggregate final
/// per-test outcomes by name; segment tallies are cross-checked, with
/// exact equality required for the common single-segment case.
#[derive(Default)]
struct NextestSuite {
    /// Largest suite-started test_count across segments.
    selected: u64,
    /// Largest ignored tally across segments (the same ignored tests
    /// are recounted in every segment).
    ignored: u64,
    started_segments: u64,
    finished_segments: u64,
    /// Sum of passed+failed tallies across finished segments.
    tally_outcomes: u64,
    /// Test finish events attributed to this suite, before dedup.
    finish_events: u64,
}

fn nextest_suite_key(value: &serde_json::Value) -> Result<String, String> {
    let nextest = value
        .get("nextest")
        .ok_or_else(|| "nextest suite event has no nextest object".to_string())?;
    let krate = nextest
        .get("crate")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "nextest suite event has no crate".to_string())?;
    let binary = nextest
        .get("test_binary")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "nextest suite event has no test_binary".to_string())?;
    Ok(format!("{krate}::{binary}"))
}

fn nextest_u64(value: &serde_json::Value, field: &str) -> Result<u64, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("nextest event field {field} must be an unsigned integer"))
}

/// Split a nextest test identity `crate::binary$name[#attempt]` into
/// (suite key, test name, retry attempt). Attempt 0 is the first run;
/// `#k` marks the k-th run overall, i.e. retry attempt k-1.
fn split_nextest_test_name(raw: &str) -> Result<(String, String, u32), String> {
    let (suite, rest) = raw
        .split_once('$')
        .ok_or_else(|| format!("nextest test name has no suite separator: {raw}"))?;
    let (name, attempt) = match rest.rsplit_once('#') {
        Some((name, suffix))
            if !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()) =>
        {
            let run: u32 = suffix
                .parse()
                .map_err(|_| format!("nextest test name has a bad attempt suffix: {raw}"))?;
            if run == 0 {
                return Err(format!("nextest test name has attempt #0: {raw}"));
            }
            (name, run - 1)
        }
        _ => (rest, 0),
    };
    Ok((suite.to_string(), name.to_string(), attempt))
}

fn parse_nextest_events(lines: impl Iterator<Item = String>) -> Result<NextestRun, String> {
    let mut suites: std::collections::BTreeMap<String, NextestSuite> =
        std::collections::BTreeMap::new();
    // Final outcome per (suite, test): a later finish event (a retry, or
    // a re-run in a later suite segment) replaces the earlier one.
    let mut finals: std::collections::BTreeMap<(String, String), ExecutionRecord> =
        std::collections::BTreeMap::new();
    let mut final_stdout: std::collections::BTreeMap<(String, String), String> =
        std::collections::BTreeMap::new();
    let mut had_failure: std::collections::BTreeSet<(String, String)> =
        std::collections::BTreeSet::new();
    let mut saw_event = false;
    for line in lines {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(kind) = value.get("type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let event = value
            .get("event")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        match (kind, event.as_str()) {
            ("suite", "started") => {
                saw_event = true;
                let key = nextest_suite_key(&value)?;
                let suite = suites.entry(key).or_default();
                suite.started_segments += 1;
                suite.selected = suite.selected.max(nextest_u64(&value, "test_count")?);
            }
            ("suite", "ok" | "failed") => {
                saw_event = true;
                let key = nextest_suite_key(&value)?;
                let suite = suites.entry(key).or_default();
                suite.finished_segments += 1;
                suite.tally_outcomes +=
                    nextest_u64(&value, "passed")? + nextest_u64(&value, "failed")?;
                suite.ignored = suite.ignored.max(nextest_u64(&value, "ignored")?);
            }
            ("test", "ok" | "failed") => {
                saw_event = true;
                let raw = value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "nextest test event has no name".to_string())?;
                let (suite_key, name, attempt) = split_nextest_test_name(raw)?;
                suites.entry(suite_key.clone()).or_default().finish_events += 1;
                let wall_usec = value
                    .get("exec_time")
                    .and_then(serde_json::Value::as_f64)
                    .map(|seconds| (seconds * 1_000_000.0) as u64)
                    .unwrap_or(0);
                let identity = (suite_key, name.clone());
                if event == "failed" {
                    had_failure.insert(identity.clone());
                }
                if let Some(stdout) = value.get("stdout").and_then(serde_json::Value::as_str) {
                    final_stdout.insert(identity.clone(), stdout.to_string());
                }
                finals.insert(
                    identity,
                    ExecutionRecord {
                        name,
                        outcome: event.clone(),
                        cpu_usec: 0,
                        wall_usec,
                        attempt,
                    },
                );
            }
            _ => {}
        }
    }
    if !saw_event {
        return Err("nextest emitted no libtest-json-plus events".to_string());
    }
    // Re-segmentation keeps the discovery invariant (TestCounts::
    // from_channels checks executed + ignored == selected per run) but
    // segment tallies can recount a re-run test, so the tally check is
    // exact only for single-segment suites, as documented on
    // NextestSuite.
    let mut per_suite_finals: std::collections::BTreeMap<&str, u64> =
        std::collections::BTreeMap::new();
    for (suite_key, _) in finals.keys() {
        *per_suite_finals.entry(suite_key.as_str()).or_default() += 1;
    }
    let mut selected = DiscoveryCounts::default();
    let mut ignored_total = 0_u64;
    for (key, suite) in &suites {
        if suite.started_segments == 0 {
            return Err(format!(
                "nextest suite {key} has events without a started segment"
            ));
        }
        if suite.finished_segments == 0 {
            return Err(format!(
                "nextest suite {key} started without a finished segment"
            ));
        }
        let deduped = per_suite_finals.get(key.as_str()).copied().unwrap_or(0);
        if suite.started_segments == 1 && suite.finished_segments == 1 {
            if suite.finish_events != suite.tally_outcomes || deduped != suite.tally_outcomes {
                return Err(format!(
                    "nextest suite {key} recorded {} test finish events ({} final) but tallied {} outcomes",
                    suite.finish_events, deduped, suite.tally_outcomes
                ));
            }
        } else if deduped > suite.tally_outcomes || suite.finish_events < deduped {
            return Err(format!(
                "nextest suite {key} re-segmented tallies disagree: {} finish events, {} final, {} tallied",
                suite.finish_events, deduped, suite.tally_outcomes
            ));
        }
        selected.selected += suite.selected;
        selected.ignored += suite.ignored;
        ignored_total += suite.ignored;
    }
    let mut execution = ExecutionCounts {
        ignored: ignored_total,
        ..ExecutionCounts::default()
    };
    let mut records = Vec::new();
    let mut flaky = Vec::new();
    let mut failures = Vec::new();
    for (identity, record) in finals {
        if record.outcome == "ok" {
            execution.passed += 1;
            if record.attempt > 0 || had_failure.contains(&identity) {
                flaky.push((record.name.clone(), record.attempt.max(1)));
            }
        } else {
            execution.failed += 1;
            failures.push((
                record.name.clone(),
                final_stdout.get(&identity).cloned().unwrap_or_default(),
            ));
        }
        records.push(record);
    }
    execution.executed = execution.passed + execution.failed;
    // Unfiltered discovery is supplied independently by the caller
    // (cargo nextest list); default to the selected channel here.
    let unfiltered = selected;
    Ok(NextestRun {
        execution,
        selected,
        unfiltered,
        records,
        flaky,
        failures,
    })
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Named host-capability refusals (`REVERIE_SKIP:` lines) are printed by
/// passing tests, whose stdout nextest's event stream does not carry.
/// The JUnit report stores it; harvest the lines verbatim so the
/// validation log keeps the same named-refusal evidence as the serial
/// libtest path.
fn harvest_junit_skips(path: &Path) -> Result<Vec<String>, String> {
    let text = fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read nextest JUnit report {}: {error}; rerun the counted command",
            path.display()
        )
    })?;
    let text = xml_unescape(&text);
    Ok(text
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| line.starts_with("REVERIE_SKIP:"))
        .collect())
}

/// Package and binary names a counted command restricts itself to,
/// read from its -p/--package flags and the `package(...)` /
/// `binary(...)` terms of its -E filters. Test-name terms (the skip
/// list) only narrow the selected set, never the discovery universe.
fn nextest_selection_scope(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut packages = Vec::new();
    let mut binaries = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if (arg == "-p" || arg == "--package") && index + 1 < args.len() {
            packages.push(args[index + 1].clone());
            index += 2;
            continue;
        }
        if let Some(value) = arg.strip_prefix("--package=") {
            packages.push(value.to_string());
        }
        let filter = if (arg == "-E" || arg == "--filter-expr") && index + 1 < args.len() {
            index += 1;
            Some(args[index].as_str())
        } else {
            arg.strip_prefix("--filter-expr=")
        };
        if let Some(filter) = filter {
            // Negated binary terms shrink the universe; record them
            // with a '!' prefix and keep them out of the positive scan.
            let mut masked = filter.to_string();
            while let Some(at) = masked.find("not binary(") {
                let tail = &masked[at + "not binary(".len()..];
                let Some(end) = tail.find(')') else { break };
                let name = tail[..end].trim().trim_start_matches('=').trim();
                if !name.is_empty()
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    binaries.push(format!("!{name}"));
                }
                masked.replace_range(at..at + "not binary(".len() + end + 1, " ");
            }
            let filter: &str = &masked;
            for (marker, sink) in [("package(", &mut packages), ("binary(", &mut binaries)] {
                let mut rest = filter;
                while let Some(at) = rest.find(marker) {
                    let tail = &rest[at + marker.len()..];
                    let Some(end) = tail.find(')') else { break };
                    let name = tail[..end].trim().trim_start_matches('=').trim();
                    if !name.is_empty()
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    {
                        sink.push(name.to_string());
                    }
                    rest = &tail[end..];
                }
            }
        }
        index += 1;
    }
    (packages, binaries)
}

/// Total listed tests for the caller's package selection, from
/// `cargo nextest list` over the same arguments. The list JSON reports
/// every test case in its binaries regardless of -E test filters, so
/// the universe is the sum over suites inside the caller's
/// package/binary scope — exactly the unfiltered discovery channel,
/// including binaries in which the run selects nothing.
fn discover_nextest_total(args: &[String]) -> Result<u64, String> {
    let mut list_args: Vec<String> = args.to_vec();
    list_args[2] = "list".to_string();
    let output = Command::new(&list_args[0])
        .args(&list_args[1..])
        .arg("--message-format")
        .arg("json")
        .arg("--list-type")
        .arg("full")
        .output()
        .map_err(|error| format!("cannot start cargo nextest list: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo nextest list failed with {}; discovery evidence is incomplete",
            output.status
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let start = text
        .find('{')
        .ok_or_else(|| "cargo nextest list emitted no JSON object".to_string())?;
    let value: serde_json::Value = serde_json::from_str(&text[start..])
        .map_err(|error| format!("cannot parse cargo nextest list JSON: {error}"))?;
    let (packages, binaries) = nextest_selection_scope(args);
    if packages.is_empty() && binaries.is_empty() {
        return value
            .get("test-count")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "cargo nextest list JSON has no test-count".to_string());
    }
    let suites = value
        .get("rust-suites")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "cargo nextest list JSON has no rust-suites object".to_string())?;
    let mut total = 0_u64;
    for suite in suites.values() {
        let package = suite
            .get("package-name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let binary = suite
            .get("binary-name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !packages.is_empty() && !packages.iter().any(|name| name == package) {
            continue;
        }
        let excluded = binaries
            .iter()
            .any(|name| name.strip_prefix('!') == Some(binary));
        if excluded {
            continue;
        }
        let positives: Vec<&String> = binaries
            .iter()
            .filter(|name| !name.starts_with('!'))
            .collect();
        if !positives.is_empty() && !positives.iter().any(|name| *name == binary) {
            continue;
        }
        total += suite
            .get("testcases")
            .and_then(serde_json::Value::as_object)
            .map(|cases| cases.len() as u64)
            .ok_or_else(|| "cargo nextest list suite has no testcases object".to_string())?;
    }
    Ok(total)
}

fn run_nextest(path: PathBuf, args: Vec<String>) -> Result<i32, String> {
    let path = absolutize(path)?;
    if args.len() < 3 || args[0] != "cargo" || args[1] != "nextest" || args[2] != "run" {
        return Err("run-nextest requires a command starting with `cargo nextest run`".to_string());
    }
    if args.iter().any(|arg| arg == "--") {
        return Err(
            "run-nextest does not accept libtest pass-through arguments after `--`; \
             express skips as nextest -E filters"
                .to_string(),
        );
    }
    for owned in [
        "--message-format",
        "--message-format-version",
        "--retries",
        "--fail-fast",
        "--no-fail-fast",
        "--profile",
        "--config-file",
        "--tool-config-file",
        "--test-threads",
    ] {
        if args
            .iter()
            .any(|arg| arg == owned || arg.starts_with(&format!("{owned}=")))
        {
            return Err(format!(
                "run-nextest owns {owned}; remove it from the counted command"
            ));
        }
    }
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|error| format!("cannot remove stale {}: {error}", path.display()))?;
    }
    let retries = retries_from_env()?;
    // Independent discovery, mirroring the libtest path: the event
    // stream only describes binaries with at least one selected test,
    // so the unfiltered universe (and therefore filtered_tests) comes
    // from a separate list over the same package selection.
    let discovered_total = discover_nextest_total(&args)?;
    let junit_path = path.with_extension("junit.xml");
    let junit_absolute = if junit_path.is_absolute() {
        junit_path.clone()
    } else {
        env::current_dir()
            .map_err(|error| format!("cannot resolve the working directory: {error}"))?
            .join(&junit_path)
    };
    if let Some(parent) = junit_absolute.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    // A per-invocation profile keeps concurrent counted runs (DAG test
    // nodes) from sharing one JUnit report file. It must be passed as a
    // tool config file: --config-file would REPLACE the repository
    // .config/nextest.toml, silently dropping its [profile.default]
    // slow-timeout backstop for nextest's built-in default (musestable
    // review of PR 1295, proven on nextest 0.9.100).
    let config_path = path.with_extension("nextest-config.toml");
    let junit_escaped = junit_absolute
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(
        &config_path,
        format!(
            "[profile.reverie-counted.junit]\npath = \"{junit_escaped}\"\nstore-success-output = true\nstore-failure-output = true\n"
        ),
    )
    .map_err(|error| format!("cannot write {}: {error}", config_path.display()))?;

    let mut command = Command::new(&args[0]);
    command.args(&args[1..]);
    if let Ok(threads) = env::var("REVERIE_NEXTEST_TEST_THREADS") {
        let threads: u32 = threads
            .parse()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                format!("REVERIE_NEXTEST_TEST_THREADS must be a positive integer, got {threads:?}")
            })?;
        command.arg("--test-threads").arg(threads.to_string());
    }
    command
        .arg("--message-format")
        .arg("libtest-json-plus")
        .arg("--retries")
        .arg(retries.to_string())
        .arg("--no-fail-fast")
        .arg("--profile")
        .arg("reverie-counted")
        .arg("--tool-config-file")
        .arg(format!("reverie:{}", config_path.display()))
        .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start cargo nextest: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "nextest stdout was not piped".to_string())?;
    let lines: Vec<String> = io::BufReader::new(stdout)
        .lines()
        .collect::<Result<_, _>>()
        .map_err(|error| format!("cannot read nextest output: {error}"))?;
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for cargo nextest: {error}"))?;
    let code = status.code().unwrap_or(1);
    let _ = fs::remove_file(&config_path);

    let mut run = parse_nextest_events(lines.into_iter())?;
    run.unfiltered.selected = discovered_total;
    for (name, stdout) in &run.failures {
        println!("FAIL: {name}\n{stdout}");
    }
    let flaky_total = run.flaky.len();
    for (name, attempt) in &run.flaky {
        eprintln!("REVERIE_FLAKY: {name} passed on retry attempt {attempt}");
    }
    if flaky_total > 0 && run.failures.is_empty() {
        eprintln!("REVERIE_FLAKY_SUMMARY: {flaky_total} test(s) passed only on retry");
    }
    let skips = harvest_junit_skips(&junit_absolute)?;
    for line in &skips {
        println!("{line}");
    }
    // Side files carry this node's evidence through enclosing runners
    // (dagrun summarizes passing-step output, which would otherwise
    // drop REVERIE_SKIP / REVERIE_FLAKY lines on the floor). validate.sh
    // ingests them into the validation log and refuses a counted node
    // whose side files are missing.
    let write_side = |extension: &str, lines: &[String]| -> Result<(), String> {
        let side = path.with_extension(extension);
        let mut text = lines.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        fs::write(&side, text).map_err(|error| format!("cannot write {}: {error}", side.display()))
    };
    write_side("skips.txt", &skips)?;
    let flaky_lines: Vec<String> = run
        .flaky
        .iter()
        .map(|(name, attempt)| format!("REVERIE_FLAKY: {name} passed on retry attempt {attempt}"))
        .collect();
    write_side("flaky.txt", &flaky_lines)?;
    write_side("universe", &[discovered_total.to_string()])?;
    // CPU attribution on this path is the dagrun node's cgroup account
    // (per-node user/sys in the perf CSV), not per test: under parallel
    // nextest a process-group delta cannot be attributed to one test.
    // Records therefore carry wall time and attempt only; do not derive
    // REVERIE_TEST_BUDGETS CPU caps from a nextest report.
    write_cpu_report(&path, &run.records)?;
    if code == 0 && run.execution.failed != 0 {
        return Err(format!(
            "cargo nextest exited successfully but its event stream recorded {} failures",
            run.execution.failed
        ));
    }
    let counts = TestCounts::from_channels(run.execution, run.selected, run.unfiltered)?;
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
    if proc_stat_cpu_ticks_for_group(stat, 4242) != Some(150)
        || proc_stat_cpu_ticks_for_group(stat, 7).is_some()
    {
        return Err("process-group CPU tick parsing differs".to_string());
    }
    let (_selected_list, selected_names) = parse_pretty_list_names(
        "a: test\nb: test\nc: test\n\n3 tests, 0 benchmarks\n".as_bytes(),
        io::sink(),
    )?;
    if selected_names != ["a", "b", "c"] {
        return Err("discovered-name set or order differs".to_string());
    }
    let selected_counts = discovery_counts(
        &parse_pretty_list(
            "a: test\nb: test\nc: test\n\n3 tests, 0 benchmarks\n".as_bytes(),
            io::sink(),
        )?,
        &parse_pretty_list("c: test\n\n1 test, 0 benchmarks\n".as_bytes(), io::sink())?,
    )?;
    let unfiltered_counts = discovery_counts(
        &parse_pretty_list(
            "a: test\nb: test\nc: test\nd: test\n\n4 tests, 0 benchmarks\n".as_bytes(),
            io::sink(),
        )?,
        &parse_pretty_list("c: test\n\n1 test, 0 benchmarks\n".as_bytes(), io::sink())?,
    )?;
    // Rustdoc's exact timing line after a doctest suite is accepted.
    parse_pretty_list(
        "x: test\n\n1 test, 0 benchmarks\nall doctests ran in 0.12s; merged doctests compilation took 0.12s\n"
            .as_bytes(),
        io::sink(),
    )?;
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
    if parse_pretty_list("same rendered text\n".as_bytes(), io::sink()).is_ok() {
        return Err("human output was accepted as a libtest list".to_string());
    }
    if parse_pretty_list("".as_bytes(), io::sink()).is_ok() {
        return Err("empty discovery evidence was accepted".to_string());
    }
    if parse_pretty_list("a: test\n".as_bytes(), io::sink()).is_ok() {
        return Err("discovery without a suite footer was accepted".to_string());
    }
    if parse_pretty_list("a: test\n\n2 tests, 0 benchmarks\n".as_bytes(), io::sink()).is_ok() {
        return Err("mutated discovery total was accepted".to_string());
    }
    if parse_pretty_list(
        "a: test\n\n1 test, 0 benchmarks\nall doctests ran in Xs; merged doctests compilation took 0.12s\n"
            .as_bytes(),
        io::sink(),
    )
    .is_ok()
    {
        return Err("malformed doctest timing line was accepted".to_string());
    }
    if discovery_counts(
        &parse_pretty_list("a: test\n\n1 test, 0 benchmarks\n".as_bytes(), io::sink())?,
        &parse_pretty_list("z: test\n\n1 test, 0 benchmarks\n".as_bytes(), io::sink())?,
    )
    .is_ok()
    {
        return Err("ignored test absent from full discovery was accepted".to_string());
    }
    if discovery_counts(
        &parse_pretty_list("a: test\n\n1 test, 0 benchmarks\n".as_bytes(), io::sink())?,
        &parse_pretty_list(
            "a: test\na: test\n\n2 tests, 0 benchmarks\n".as_bytes(),
            io::sink(),
        )?,
    )
    .is_ok()
    {
        return Err("mutated discovery multiplicity was accepted".to_string());
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
    self_test_nextest()?;
    println!(
        "PASS: libtest execution and discovery counts are isolated, typed, and mutation-sensitive"
    );
    Ok(())
}

fn self_test_nextest() -> Result<(), String> {
    let lines = [
        "    Finished `test` profile in 0.01s",
        r#"{"type":"suite","event":"started","test_count":3,"nextest":{"crate":"demo","test_binary":"demo","kind":"lib"}}"#,
        r#"{"type":"test","event":"started","name":"demo::demo$tests::a"}"#,
        r#"{"type":"test","event":"ok","name":"demo::demo$tests::a","exec_time":0.001}"#,
        r#"{"type":"test","event":"ok","name":"demo::demo$tests::b#3","exec_time":0.002}"#,
        r#"{"type":"test","event":"failed","name":"demo::demo$tests::c#2","exec_time":0.003,"stdout":"boom"}"#,
        r#"{"type":"suite","event":"failed","passed":2,"failed":1,"ignored":0,"measured":0,"filtered_out":40,"exec_time":0.01,"nextest":{"crate":"demo","test_binary":"demo","kind":"lib"}}"#,
    ];
    let run = parse_nextest_events(lines.iter().map(|line| line.to_string()))?;
    if run.execution.executed != 3 || run.execution.passed != 2 || run.execution.failed != 1 {
        return Err(format!(
            "nextest self-test execution mismatch: {:?}",
            run.execution
        ));
    }
    if run.flaky != [("tests::b".to_string(), 2)] {
        return Err(format!("nextest self-test flaky mismatch: {:?}", run.flaky));
    }
    if run.failures.len() != 1 || run.failures[0].0 != "tests::c" {
        return Err(format!(
            "nextest self-test failures mismatch: {:?}",
            run.failures
        ));
    }
    // Production supplies unfiltered discovery from cargo nextest list;
    // mirror that here (3 selected of 43 listed).
    let mut unfiltered = run.unfiltered;
    unfiltered.selected = 43;
    let counts = TestCounts::from_channels(run.execution, run.selected, unfiltered)?;
    if counts.executed_tests != 3 || counts.passed_tests != 2 || counts.filtered_tests != 40 {
        return Err(format!("nextest self-test counts mismatch: {counts:?}"));
    }
    // A suite tally that disagrees with its finish events must refuse.
    let lying = [
        r#"{"type":"suite","event":"started","test_count":1,"nextest":{"crate":"demo","test_binary":"demo","kind":"lib"}}"#,
        r#"{"type":"suite","event":"ok","passed":1,"failed":0,"ignored":0,"measured":0,"filtered_out":0,"nextest":{"crate":"demo","test_binary":"demo","kind":"lib"}}"#,
    ];
    match parse_nextest_events(lying.iter().map(|line| line.to_string())) {
        Err(error) if error.contains("finish events") => Ok(()),
        other => Err(format!(
            "nextest self-test accepted a lying suite tally: {other:?}"
        )),
    }?;
    // A re-segmented suite (nextest re-runs part of a binary after a
    // test process dies mid-stream) aggregates by final outcome.
    let resegmented = [
        r#"{"type":"suite","event":"started","test_count":3,"nextest":{"crate":"demo","test_binary":"demo","kind":"test"}}"#,
        r#"{"type":"test","event":"ok","name":"demo::demo$tests::a","exec_time":0.001}"#,
        r#"{"type":"test","event":"failed","name":"demo::demo$tests::b","exec_time":0.002,"stdout":"boom"}"#,
        r#"{"type":"suite","event":"failed","passed":1,"failed":1,"ignored":1,"measured":0,"filtered_out":0,"nextest":{"crate":"demo","test_binary":"demo","kind":"test"}}"#,
        r#"{"type":"suite","event":"started","test_count":3,"nextest":{"crate":"demo","test_binary":"demo","kind":"test"}}"#,
        r#"{"type":"test","event":"ok","name":"demo::demo$tests::b","exec_time":0.004}"#,
        r#"{"type":"suite","event":"ok","passed":1,"failed":0,"ignored":1,"measured":0,"filtered_out":1,"nextest":{"crate":"demo","test_binary":"demo","kind":"test"}}"#,
    ];
    let run = parse_nextest_events(resegmented.iter().map(|line| line.to_string()))?;
    if run.execution.executed != 2 || run.execution.passed != 2 || run.execution.failed != 0 {
        return Err(format!(
            "nextest self-test re-segmented execution mismatch: {:?}",
            run.execution
        ));
    }
    if run.flaky != [("tests::b".to_string(), 1)] {
        return Err(format!(
            "nextest self-test re-segmented flaky mismatch: {:?}",
            run.flaky
        ));
    }
    let counts = TestCounts::from_channels(run.execution, run.selected, run.unfiltered)?;
    if counts.executed_tests != 2 || counts.passed_tests != 2 || counts.filtered_tests != 0 {
        return Err(format!(
            "nextest self-test re-segmented counts mismatch: {counts:?}"
        ));
    }
    // JUnit named-refusal harvest: REVERIE_SKIP lines survive XML
    // escaping and the (stdout/stderr-combined) success output.
    let junit_path = std::env::temp_dir().join(format!(
        "reverie-libtest-counts-junit-self-test.{}.xml",
        std::process::id()
    ));
    let junit_result = (|| -> Result<(), String> {
        fs::write(
            &junit_path,
            "<testsuite><testcase name=\"x\"><system-out>running 1 test\n\
             REVERIE_SKIP: broker::x: ambient mount absent &amp; refused\n\
             test x ... ok</system-out></testcase></testsuite>\n",
        )
        .map_err(|error| format!("cannot write JUnit self-test fixture: {error}"))?;
        let skips = harvest_junit_skips(&junit_path)?;
        if skips != ["REVERIE_SKIP: broker::x: ambient mount absent & refused".to_string()] {
            return Err(format!(
                "nextest self-test JUnit harvest mismatch: {skips:?}"
            ));
        }
        Ok(())
    })();
    let _ = fs::remove_file(&junit_path);
    junit_result?;
    let scope_args: Vec<String> = [
        "cargo",
        "nextest",
        "run",
        "--workspace",
        "-E",
        "(package(reverie-liteinst) | package(=reverie-kvm)) & binary(strace) & not binary(=rpc_tool) & not test(tests::mount_proc)",
        "-p",
        "safeptrace",
    ]
    .iter()
    .map(|arg| arg.to_string())
    .collect();
    let (packages, binaries) = nextest_selection_scope(&scope_args);
    if packages != ["reverie-liteinst", "reverie-kvm", "safeptrace"]
        || binaries != ["!rpc_tool", "strace"]
    {
        return Err(format!(
            "nextest self-test scope mismatch: packages={packages:?} binaries={binaries:?}"
        ));
    }
    println!("PASS: nextest event counts are typed, cross-checked, and flaky-aware");
    Ok(())
}

const TOP_LEVEL_HELP: &str = "Usage: libtest-counts.rs COMMAND [ARGS...]\n\
\n\
Record and read authoritative libtest execution counts.\n\
\n\
Commands:\n\
  run OUTPUT -- cargo test [ARGS...]         Run tests and write schema-2 counts\n\
  run-nextest OUTPUT -- cargo nextest run [ARGS...]\n\
                                             Same contract over nextest events\n\
  read OUTPUT                                Print: executed passed filtered\n\
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

const RUN_NEXTEST_HELP: &str = "Usage: libtest-counts.rs run-nextest OUTPUT -- cargo nextest run [ARGS...]\n\
\n\
Run one cargo-nextest command (one process per test), derive authoritative\n\
counts from its libtest-json-plus event stream, and atomically write schema-2\n\
JSON to OUTPUT. The runner owns --message-format, --retries, --fail-fast,\n\
--profile, --config-file, and --tool-config-file (the JUnit profile is\n\
layered via --tool-config-file so the repository config still applies);\n\
a per-invocation profile writes JUnit to\n\
OUTPUT.junit.xml so REVERIE_SKIP lines from passing tests stay harvestable.\n\
Passes on retry are reported as REVERIE_FLAKY, never silent. Per-test records\n\
carry wall time and attempt (OUTPUT.cpu.jsonl); CPU bounds on this path are\n\
the enclosing runner's (a dagrun node's cgroup account), not per-test caps.\n\
\n\
Environment:\n\
  REVERIE_TEST_RETRIES       Counted retries 0..=2 (default 2)\n\
  REVERIE_NEXTEST_TEST_THREADS  Test-process width (default: nextest profile)\n\
  REVERIE_TEST_CPU_REPORT    Per-test report JSONL (default OUTPUT.cpu.jsonl)\n\
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
        Some("run-nextest") => {
            let path = args.next().map(PathBuf::from);
            if path.as_deref() == Some(Path::new("-h"))
                || path.as_deref() == Some(Path::new("--help"))
            {
                if args.next().is_none() {
                    print_help(RUN_NEXTEST_HELP);
                    return ExitCode::SUCCESS;
                }
                eprintln!("libtest-counts: run-nextest help accepts no additional arguments");
                eprintln!("{RUN_NEXTEST_HELP}");
                return ExitCode::from(2);
            }
            let separator = args.next();
            match (path, separator.as_deref()) {
                (Some(path), Some("--")) => run_nextest(path, args.collect()).map(|code| {
                    if code == 0 {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(u8::try_from(code).unwrap_or(1))
                    }
                }),
                _ => Err(
                    "run-nextest requires OUTPUT -- cargo nextest run [ARGS...]; run `libtest-counts.rs run-nextest --help` for usage"
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
