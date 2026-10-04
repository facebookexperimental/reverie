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
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitCode;
use std::process::Stdio;

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

fn increment(value: &mut u64, label: &str) -> Result<(), String> {
    *value = value
        .checked_add(1)
        .ok_or_else(|| format!("{label} overflowed u64"))?;
    Ok(())
}

fn parse_execution_records<R: BufRead>(reader: R) -> Result<ExecutionCounts, String> {
    let mut counts = ExecutionCounts::default();
    for line in reader.lines() {
        let line = line.map_err(|error| format!("cannot read libtest execution log: {error}"))?;
        let (outcome, name) = line
            .split_once(' ')
            .ok_or_else(|| format!("malformed libtest execution record: {line:?}"))?;
        if name.is_empty() {
            return Err("libtest execution record has an empty test name".to_string());
        }
        match outcome {
            "ok" => {
                increment(&mut counts.executed, "executed test count")?;
                increment(&mut counts.passed, "passed test count")?;
            }
            "failed" => {
                increment(&mut counts.executed, "executed test count")?;
                increment(&mut counts.failed, "failed test count")?;
            }
            "ignored" | "ignored:" => increment(&mut counts.ignored, "ignored test count")?,
            _ => {
                return Err(format!(
                    "unknown libtest execution outcome {outcome:?} in record {line:?}"
                ));
            }
        }
    }
    Ok(counts)
}

fn parse_discovery<R: BufRead>(reader: R, mut echo: impl Write) -> Result<DiscoveryCounts, String> {
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
    execution.extend(["--logfile".to_string(), execution_log.display().to_string()]);

    Ok(CargoTestCommands {
        execution,
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
    let selected = discover(&commands.selected_discovery)?;
    let unfiltered = discover(&commands.unfiltered_discovery)?;

    let (anchor, reader) = create_execution_channel(&execution_channel)?;
    let reader_thread = std::thread::spawn(move || read_execution_channel(reader));
    let status = Command::new(&commands.execution[0])
        .args(&commands.execution[1..])
        .status()
        .map_err(|error| format!("cannot start cargo test execution: {error}"));
    drop(anchor);
    let execution = reader_thread.join();
    fs::remove_file(&execution_channel)
        .map_err(|error| format!("cannot remove {}: {error}", execution_channel.display()))?;
    let execution =
        execution.map_err(|_| "libtest execution-channel reader panicked".to_string())??;
    let status = status?;
    let code = status_code(status);
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
