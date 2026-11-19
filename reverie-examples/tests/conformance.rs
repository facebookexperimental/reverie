/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Cross-tool, cross-backend conformance for the environment-independent
//! programs (the full corpus with its expected-mismatch ledger lives in
//! `reverie-examples/e2e/`).
//!
//! One program runs under several example tools on every first-party
//! backend. The pass-through recorder is the reference: its record is the
//! syscall stream the backend gave the program. The other tools must agree
//! with that record on the same backend, and must not change what the
//! program prints or how it exits:
//!
//! * `counter1` counts every syscall event its tool handler receives. The
//!   recorder's comparable record omits the vDSO calls (`VDSO` in
//!   `recorder_tool.rs`), so in a separate execution of the same program
//!   on the same backend the counter total is the record's call count plus
//!   the vDSO calls `strace_minimal` saw in its own execution. These
//!   programs make the same calls every run; a vDSO call no tool was
//!   delivered would not be caught by this arithmetic, so the judged
//!   native comparison remains the e2e comparator's job.
//! * `strace_minimal` prints each syscall it intercepts. With the vDSO
//!   calls removed, its call-name sequence is the recorder's. One named
//!   exception: an in-guest tool prints through the guest's own stderr, so
//!   when the guest closes stderr during exit cleanup (for example
//!   `/bin/echo` closes descriptors 1 and 2 before `exit_group`), the
//!   in-guest print for that final call has nowhere to go. The recorder
//!   and counter report through tool RPC and still record it.
//! * `noop` subscribes to nothing and must be transparent: the program's
//!   stdout, stderr, and exit status are its own.
//!
//! Agreement between tools is not enough on its own: a backend that
//! delivered no events to any tool would satisfy it vacuously. Each
//! backend's record is therefore also anchored to a native record of the
//! same program, and to landmark calls every run of it must contain. The
//! judged call-by-call comparison against native, with its ledger of known
//! backend differences, is the e2e comparator's job.

use std::path::Path;
use std::process::Command;
use std::process::Output;

/// The vDSO calls the recorder's comparable record omits: the kernel
/// usually answers them in the process, while a backend may turn them
/// into syscalls a tool can see. The list is the recorder's own, so the
/// two cannot drift apart.
use reverie_examples::recorder_tool::VDSO;

/// Every run gets the sanitizer settings reverie-ptrace adds to its guest's
/// environment (tracer.rs), so every tool's guest has the same one: the
/// number of variables decides when `sh -c` grows its heap. Cargo's own
/// loader variables for test binaries (`LD_LIBRARY_PATH`, and any ambient
/// `LD_PRELOAD`) are removed: inherited into a guest they change the
/// dynamic loader's searches, and each backend's loader answers those
/// searches with a different number of syscalls.
fn tool_command(binary: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .env("ASAN_OPTIONS", "detect_leaks=0")
        .env("LSAN_OPTIONS", "detect_leaks=0")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD");
    command
}

/// Report a skipped backend leg where a scorecard can see it. Libtest
/// captures this test's standard error, so the line is written to the
/// descriptor directly; `scripts/run-percrate-tests.sh` counts these
/// lines in its `skipped` column instead of counting the leg as passed.
fn report_skip(reason: &str) {
    // The leading newline matters: libtest has already printed
    // `test NAME ... ` with no newline when this runs, so without it the
    // marker lands mid-line in the log. The scorecard matcher is
    // unanchored as well, so either side alone would still count it.
    let line = format!("\nREVERIE_SKIP: {reason}\n");
    let mut rest = line.as_bytes();
    while !rest.is_empty() {
        // SAFETY: writing a borrowed byte slice to the stderr descriptor.
        let written = unsafe { libc::write(2, rest.as_ptr().cast(), rest.len()) };
        if written <= 0 {
            eprint!("{line}");
            return;
        }
        rest = &rest[written as usize..];
    }
}

/// Whether this host can run the KVM backend. KVM needs a usable
/// `/dev/kvm`; when `REVERIE_REQUIRE_KVM` is set its absence is a failure,
/// as in `tests/kvm_cli.rs`. Otherwise the leg is reported as a skip
/// through [`report_skip`], never silently counted as a pass.
fn kvm_available() -> bool {
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => true,
        Err(error) if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() => {
            panic!("conformance tests require usable /dev/kvm: {error}")
        }
        Err(error) => {
            report_skip(&format!(
                "kvm conformance backend: cannot open /dev/kvm: {error}"
            ));
            false
        }
    }
}

/// An example tool's run of a program: the program's exit status and
/// streams as the tool left them (through `Deref`), and the directory of
/// the tool's own log. If the test fails while the run is in scope, the
/// log is kept and printed, so a failing comparison still shows it.
struct ToolRun {
    output: Output,
    logs: Option<tempfile::TempDir>,
}

const TOOL_LOG: &str = "tool.log";

impl std::ops::Deref for ToolRun {
    type Target = Output;

    fn deref(&self) -> &Output {
        &self.output
    }
}

impl ToolRun {
    /// The tool's own log, as far as the run wrote it.
    fn log(&self) -> String {
        let logs = self
            .logs
            .as_ref()
            .expect("the log directory is kept until drop");
        std::fs::read_to_string(logs.path().join(TOOL_LOG)).unwrap_or_default()
    }
}

impl Drop for ToolRun {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let Some(logs) = self.logs.take() else {
            return;
        };
        let path = logs.keep().join(TOOL_LOG);
        let log = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| format!("<not readable: {error}>"));
        eprintln!("tool log, kept at {}:\n{log}", path.display());
    }
}

/// Run `program` under an example tool. The tool's own `tracing` log goes
/// to a file of its own (`--log-file`), not to the standard error it
/// shares with the program, so the streams the tests compare are the
/// program's alone: a backend diagnostic, such as reverie-ptrace's PMU
/// validation error on some AMD hosts, never reads as program output.
fn run(binary: &str, backend: &str, program: &[&str]) -> ToolRun {
    run_tool(tool_command(binary), backend, program)
}

/// [`run`], with the tool started by `command`.
fn run_tool(mut command: Command, backend: &str, program: &[&str]) -> ToolRun {
    let logs = tempfile::tempdir().unwrap();
    let output = command
        .arg("--log-file")
        .arg(logs.path().join(TOOL_LOG))
        .args(["--backend", backend, "--"])
        .args(program)
        .output()
        .expect("run the tool launcher");
    ToolRun {
        output,
        logs: Some(logs),
    }
}

fn run_direct(program: &[&str]) -> Output {
    tool_command(program[0])
        .args(&program[1..])
        .output()
        .expect("run the program directly")
}

/// The recorder's record for one run: its exit line and every call as
/// (name, outcome), in the record's thread order (these programs are
/// single-threaded). Outcomes are the recorder text after `=`
/// (`ok`, an errno name, or an exact value for the calls in
/// `recorder_tool::EXACT`).
fn record_detailed(backend: &str, program: &[&str], output: &Path) -> (i32, Vec<(String, String)>) {
    let run = tool_command(env!("CARGO_BIN_EXE_recorder"))
        .args(["--backend", backend, "--output"])
        .arg(output)
        .args(program)
        .output()
        .expect("run the recorder");
    assert!(
        run.status.success(),
        "recorder {backend} {program:?}: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let text = std::fs::read_to_string(output).unwrap();
    let mut lines = text.lines();
    let exit: i32 = lines
        .next()
        .and_then(|line| line.strip_prefix("exit "))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("recorder {backend} {program:?}: bad record: {text}"));
    let calls = lines
        .filter(|line| !line.starts_with("thread "))
        .map(|line| {
            line.split_once('=')
                .map_or((line.to_owned(), String::new()), |(name, outcome)| {
                    (name.to_owned(), outcome.to_owned())
                })
        })
        .collect();
    (exit, calls)
}

/// The syscall names `strace_minimal` printed, one per intercepted call.
/// Only the tool's own `[pid N] name(...) = ?` lines count: the guest's
/// stderr reaches the same stream on some backends, and a guest line that
/// merely contains `] ` is not a syscall.
fn strace_names(output: &Output) -> Vec<String> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| {
            let call = line.strip_prefix("[pid ")?.split_once("] ")?.1;
            let (name, _) = call.split_once('(')?;
            (!name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
            .then(|| name.to_owned())
        })
        .collect()
}

fn counter1_total(output: &Output, backend: &str, program: &[&str]) -> usize {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("counter1-global syscalls="))
        .and_then(|total| total.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "counter1 {backend} {program:?}: no total in stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
}

const PROGRAMS: &[&[&str]] = &[
    &["/bin/true"],
    &["/bin/echo", "hello"],
    &["/bin/sh", "-c", "echo a; exit 3"],
];

/// The calls every record of `program` must contain, in order, ending the
/// run: the anchor that keeps tool agreement from passing on an empty or
/// nearly empty stream. `/bin/true` makes no observable call but its exit;
/// the other two write before they exit.
fn assert_landmarks(program: &[&str], backend: &str, recorded: &[String]) {
    assert!(!recorded.is_empty(), "{backend} {program:?}: empty record");
    assert_eq!(
        recorded.last().map(String::as_str),
        Some("exit_group"),
        "{backend} {program:?}: record does not end in exit_group: {recorded:?}"
    );
    if program[0] != "/bin/true" {
        let write = recorded
            .iter()
            .position(|call| call == "write")
            .unwrap_or_else(|| panic!("{backend} {program:?}: no write in {recorded:?}"));
        assert!(
            write < recorded.len() - 1,
            "{backend} {program:?}: write is not before the exit: {recorded:?}"
        );
    }
}

/// Whether every call in `needle` appears in `haystack`, in order.
fn is_subsequence(needle: &[String], haystack: &[String]) -> bool {
    let mut rest = haystack.iter();
    needle
        .iter()
        .all(|call| rest.any(|candidate| candidate == call))
}

/// Named conformance-ledger entry, in-guest backends only:
/// in-guest `/proc/self/maps` lists runtime mappings, so its
/// content is about 3x the kernel's length and a guest reading
/// it makes a different number of `read` calls (measured
/// 2026-11-16 on Ubuntu 26.04 for `/bin/echo`: native 5,449
/// bytes vs in-guest-trap 16,287 and liteinst 17,268, all in
/// full 1 KiB returns). The reads are the guest's own and the
/// content difference is real, so this is named here rather
/// than hidden in a looser comparison; whether synthetic maps
/// should trim runtime mappings is
/// https://github.com/facebookexperimental/hermit/issues/241.
/// The run is probably glibc reading toward the `[stack]`
/// line (inference from the seek-back shape, not re-read in
/// glibc source), so the name says read run, not read-to-EOF.
/// The token a collapsed run is replaced by in both records
/// before the subsequence check. The same synthetic content
/// can also change the guest's computed main-thread stack
/// bound (the mapping below the stack differs in-guest);
/// that guest-visible effect is part of issue 241 and is not
/// excused here — only the read count is.
const MAPS_READ_RUN: &str = "read_run(/proc/self/maps)";

/// The call texts `strace_minimal` printed, in order. Only the
/// tool's own `[pid N] name(...) = ?` lines count: the guest's
/// stderr reaches the same stream on some backends, and a
/// guest line that merely looks like a call is not evidence.
fn strace_calls(stderr: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter_map(|line| {
            let call = line
                .strip_prefix("[pid ")?
                .split_once("] ")
                .map(|(_, call)| call)?;
            call.ends_with(" = ?").then(|| call.to_owned())
        })
        .collect()
}

/// The first argument of a pretty call (`read(3, ...)` gives
/// `Some(3)`), for the calls whose first argument is the
/// descriptor the maps binding tracks.
fn pretty_first_arg(call: &str) -> Option<i64> {
    call.split_once('(')?
        .1
        .split([',', ')'])
        .next()?
        .trim()
        .parse()
        .ok()
}

/// Each detailed entry's aligned strace call text: walk both
/// streams in order, matching by call name (strace lines with
/// no record entry — the vDSO calls the recorder omits — are
/// skipped). An entry with no matching line left is `None`,
/// which every binding check below treats as unconfirmed.
fn aligned_pretty(detailed: &[(String, String)], strace_calls: &[String]) -> Vec<Option<String>> {
    let mut rest = strace_calls.iter();
    detailed
        .iter()
        .map(|(name, _)| {
            rest.find(|call| {
                call.split_once('(')
                    .is_some_and(|(printed, _)| printed == name)
            })
            .cloned()
        })
        .collect()
}

/// Whether the segment ending at `run_end + 2` (its `close`)
/// is bound to `/proc/self/maps` by descriptor: the latest
/// `openat` that returned the segment's descriptor names
/// exactly that path in the aligned strace text, only
/// `prlimit64` calls (the measured glibc shape) sit between
/// that openat and the `fstat`, and every call from `fstat`
/// through `close` is on that descriptor in the aligned
/// text. The allowlist refuses by default: a denylist of
/// descriptor-freeing or -returning calls cannot be complete
/// (descriptors also arrive and leave through pointers,
/// control messages, ioctls, io_uring, and exec), while the
/// measured sequence needs nothing but `prlimit64` there.
/// Any missing aligned line, a failed open, or another path
/// fails closed.
fn segment_bound_to_maps(
    detailed: &[(String, String)],
    aligned: &[Option<String>],
    fstat_index: usize,
    run_end: usize,
) -> bool {
    let Some(fd) = aligned[fstat_index].as_deref().and_then(pretty_first_arg) else {
        return false;
    };
    let on_fd = |index: usize| aligned[index].as_deref().and_then(pretty_first_arg) == Some(fd);
    if !(fstat_index..=run_end + 2).all(&on_fd) {
        return false;
    }
    let Some(openat_index) = (0..fstat_index)
        .rev()
        .find(|&index| detailed[index].0 == "openat" && detailed[index].1.parse::<i64>() == Ok(fd))
    else {
        return false;
    };
    if !aligned[openat_index]
        .as_deref()
        .is_some_and(|call| call.contains("\"/proc/self/maps\""))
    {
        return false;
    }
    (openat_index + 1..fstat_index).all(|index| detailed[index].0 == "prlimit64")
}

/// Collapse every bound `/proc/self/maps` read run in a
/// detailed record into [`MAPS_READ_RUN`], returning call
/// names. The segment shape is exact: an `fstat`, a run of at
/// least two `read`s returning one full size each (the last
/// may be short), then `lseek` returning exactly the run's
/// byte total, a second `lseek`, and `close` — and the whole
/// segment bound to a successful `openat` of
/// `/proc/self/maps` by [`segment_bound_to_maps`]. Anything
/// else — another call inside the run, non-uniform full
/// sizes, a sum mismatch, a missing `lseek`, an unbound
/// descriptor — is left untouched, and every call outside a
/// collapsed segment is still compared strictly.
fn collapse_maps_read_run(detailed: &[(String, String)], strace_calls: &[String]) -> Vec<String> {
    let aligned = aligned_pretty(detailed, strace_calls);
    let outcome = |index: usize| detailed[index].1.parse::<i64>().ok();
    let mut names = Vec::with_capacity(detailed.len());
    let mut index = 0;
    while index < detailed.len() {
        names.push(detailed[index].0.clone());
        if detailed[index].0 != "fstat" {
            index += 1;
            continue;
        }
        let run_start = index + 1;
        let mut run_end = run_start;
        while run_end < detailed.len() && detailed[run_end].0 == "read" {
            run_end += 1;
        }
        let run = &detailed[run_start..run_end];
        let sizes: Option<Vec<i64>> = run
            .iter()
            .map(|(_, outcome)| outcome.parse::<i64>().ok())
            .collect();
        let is_maps_segment = sizes.is_some_and(|sizes| {
            sizes.len() >= 2
                && sizes[..sizes.len() - 1]
                    .iter()
                    .all(|&size| size > 0 && size == sizes[0])
                && sizes[sizes.len() - 1] > 0
                && sizes[sizes.len() - 1] <= sizes[0]
                && detailed
                    .get(run_end)
                    .is_some_and(|(name, _)| name == "lseek")
                && outcome(run_end) == Some(sizes.iter().sum())
                && detailed
                    .get(run_end + 1)
                    .is_some_and(|(name, _)| name == "lseek")
                && detailed
                    .get(run_end + 2)
                    .is_some_and(|(name, _)| name == "close")
        });
        if is_maps_segment && segment_bound_to_maps(detailed, &aligned, index, run_end) {
            names.push(MAPS_READ_RUN.to_owned());
            index = run_end;
        } else {
            index += 1;
        }
    }
    names
}

/// Second named conformance-ledger entry, in-guest backends
/// only: where `brk` falls. The in-guest runtime grows the
/// guest's `brk` heap before `main` and adds `LD_PRELOAD` to
/// the guest's environment, so the call at which a program
/// such as `sh` grows its heap depends on the runtime and on
/// the environment's size; making the guest heap match native
/// is https://github.com/facebookexperimental/reverie/issues/98.
/// The in-guest order check therefore leaves `brk` out and
/// compares only its count: the in-guest record may not hold
/// more `brk` calls than the native one. Every other call keeps
/// its order check, and the ptrace and KVM legs still compare
/// every name exactly, `brk` included.
const HEAP_GROWTH: &str = "brk";

/// The production pairing for the in-guest subsequence check:
/// each record collapses only segments its own strace run
/// binds to `/proc/self/maps` (the native side's strace run
/// uses the ptrace backend, whose name stream the ptrace leg
/// proves equal to the native record), then [`HEAP_GROWTH`]
/// is compared by count rather than position. Tested directly
/// below so replacing either confirmation with `true`, or
/// dropping the count, fails a test.
fn in_guest_is_native_subsequence(
    recorded_detailed: &[(String, String)],
    native_detailed: &[(String, String)],
    recorded_strace_stderr: &[u8],
    native_strace_stderr: &[u8],
) -> bool {
    let recorded = collapse_maps_read_run(recorded_detailed, &strace_calls(recorded_strace_stderr));
    let native = collapse_maps_read_run(native_detailed, &strace_calls(native_strace_stderr));
    let heap_growths = |names: &[String]| names.iter().filter(|name| *name == HEAP_GROWTH).count();
    let ordered = |names: &[String]| -> Vec<String> {
        names
            .iter()
            .filter(|name| *name != HEAP_GROWTH)
            .cloned()
            .collect()
    };
    heap_growths(&recorded) <= heap_growths(&native)
        && is_subsequence(&ordered(&recorded), &ordered(&native))
}

/// One detailed segment (open through close) on `fd`, for the
/// ledger tests below. The read sizes and byte totals are the
/// measured Ubuntu 26.04 `/bin/echo` ones.
fn segment_detailed(fd: i64, reads: &[i64], seek_total: i64) -> Vec<(String, String)> {
    let mut detailed = vec![
        ("openat".to_owned(), fd.to_string()),
        ("prlimit64".to_owned(), "ok".to_owned()),
        ("fstat".to_owned(), "ok".to_owned()),
    ];
    detailed.extend(
        reads
            .iter()
            .map(|size| ("read".to_owned(), size.to_string())),
    );
    detailed.push(("lseek".to_owned(), seek_total.to_string()));
    detailed.push(("lseek".to_owned(), (seek_total - 84).to_string()));
    detailed.push(("close".to_owned(), "ok".to_owned()));
    detailed
}

/// The strace call texts aligned with [`segment_detailed`].
fn segment_strace(fd: i64, path: &str, reads: &[i64]) -> Vec<String> {
    let mut calls = vec![
        format!("openat(-100, 0x1000 -> \"{path}\", OFlag(O_CLOEXEC)) = ?"),
        "prlimit64(0, 3, 0x1000, 0x1000) = ?".to_owned(),
        format!("fstat({fd}, 0x1000) = ?"),
    ];
    calls.extend(
        reads
            .iter()
            .map(|_| format!("read({fd}, 0x1000, 1024) = ?")),
    );
    calls.push(format!("lseek({fd}, 0, SEEK_CUR) = ?"));
    calls.push(format!("lseek({fd}, 0, SEEK_SET) = ?"));
    calls.push(format!("close({fd}) = ?"));
    calls
}

/// A whole record around one or more segments, with the
/// strace text that aligns with it call for call.
fn record_with_segments(segments: &[(i64, &str, &[i64])]) -> (Vec<(String, String)>, Vec<u8>) {
    let mut detailed: Vec<(String, String)> = ["fcntl", "rt_sigaction", "poll"]
        .iter()
        .map(|name| (name.to_string(), "ok".to_string()))
        .collect();
    let mut strace = vec![
        "[pid 7] fcntl(0, F_GETFD) = ?".to_owned(),
        "[pid 7] rt_sigaction(1, 0x1000, 0x1000) = ?".to_owned(),
        "[pid 7] poll(0x1000, 0, 0) = ?".to_owned(),
    ];
    for &(fd, path, reads) in segments {
        let seek_total: i64 = reads.iter().sum();
        detailed.extend(segment_detailed(fd, reads, seek_total));
        strace.extend(
            segment_strace(fd, path, reads)
                .into_iter()
                .map(|call| format!("[pid 7] {call}")),
        );
    }
    detailed.push(("write".to_owned(), "6".to_owned()));
    detailed.push(("exit_group".to_owned(), "?".to_owned()));
    strace.push("[pid 7] write(1, 0x1000, 6) = ?".to_owned());
    strace.push("[pid 7] exit_group(0) = ?".to_owned());
    (detailed, strace.join("\n").into_bytes())
}

fn maps_segment_record(reads: &[i64], seek_total: i64) -> Vec<(String, String)> {
    let mut detailed: Vec<(String, String)> = ["fcntl", "rt_sigaction", "poll"]
        .iter()
        .map(|name| (name.to_string(), "ok".to_string()))
        .collect();
    detailed.extend(segment_detailed(3, reads, seek_total));
    detailed.push(("write".to_owned(), "6".to_owned()));
    detailed.push(("exit_group".to_owned(), "?".to_owned()));
    detailed
}

#[test]
fn maps_read_run_segment_is_the_named_ledger_difference() {
    // Native: 5 full reads + 329. In-guest: 15 full reads + 927.
    let (native, native_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 1024, 1024, 329])]);
    let mut inguest_reads = vec![1024; 15];
    inguest_reads.push(927);
    let (inguest, inguest_strace) = record_with_segments(&[(3, "/proc/self/maps", &inguest_reads)]);
    let names = |detailed: &[(String, String)]| {
        detailed
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>()
    };
    // Without the ledger entry the in-guest record is not a
    // subsequence; through the production pairing it is.
    assert!(!is_subsequence(&names(&inguest), &names(&native)));
    assert!(in_guest_is_native_subsequence(
        &inguest,
        &native,
        &inguest_strace,
        &native_strace
    ));
    assert!(
        collapse_maps_read_run(&native, &strace_calls(&native_strace))
            .iter()
            .any(|name| name == MAPS_READ_RUN)
    );
}

#[test]
fn brk_position_is_the_named_ledger_difference() {
    // The measured `sh -c` shape: natively the shell grows its heap
    // inside a signal-mask pair; in-guest the same growth comes first.
    let record = |names: &[&str]| -> Vec<(String, String)> {
        names
            .iter()
            .map(|name| (name.to_string(), "ok".to_string()))
            .collect()
    };
    let names = |detailed: &[(String, String)]| -> Vec<String> {
        detailed.iter().map(|(name, _)| name.clone()).collect()
    };
    let native = record(&[
        "getpgrp",
        "ioctl",
        "rt_sigaction",
        "ioctl",
        "prlimit64",
        "rt_sigprocmask",
        "brk",
        "rt_sigprocmask",
        "fstat",
        "write",
        "exit_group",
    ]);
    let inguest = record(&[
        "getpgrp",
        "ioctl",
        "ioctl",
        "prlimit64",
        "brk",
        "rt_sigprocmask",
        "rt_sigprocmask",
        "fstat",
        "write",
        "exit_group",
    ]);
    // Without the entry the in-guest record is not a subsequence;
    // through the production pairing it is.
    assert!(!is_subsequence(&names(&inguest), &names(&native)));
    assert!(in_guest_is_native_subsequence(&inguest, &native, b"", b""));
    // Control: the entry exempts only brk. The same record with one
    // other call moved out of native order still fails.
    let mut moved = inguest.clone();
    let mask = moved
        .iter()
        .position(|(name, _)| name == "rt_sigprocmask")
        .unwrap();
    let call = moved.remove(mask);
    let fstat = moved.iter().position(|(name, _)| name == "fstat").unwrap();
    moved.insert(fstat + 1, call);
    assert!(!in_guest_is_native_subsequence(&moved, &native, b"", b""));
    // Control: brk keeps its count check. A brk the native run never
    // made fails, wherever it sits.
    let mut extra = inguest.clone();
    extra.insert(1, (HEAP_GROWTH.to_owned(), "ok".to_owned()));
    assert!(!in_guest_is_native_subsequence(&extra, &native, b"", b""));
}

#[test]
fn maps_segment_shape_is_exact() {
    let bound = |detailed: &[(String, String)]| {
        let (_, strace) = record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
        collapse_maps_read_run(detailed, &strace_calls(&strace))
            .iter()
            .any(|name| name == MAPS_READ_RUN)
    };
    // Sum mismatch: the run stays literal.
    assert!(!bound(&maps_segment_record(&[1024, 1024, 329], 9999)));
    // Non-uniform full sizes: no collapse.
    assert!(!bound(&maps_segment_record(&[1024, 512, 1024], 2560)));
    // No leading fstat anchor: no collapse.
    let mut unanchored = maps_segment_record(&[1024, 329], 1353);
    unanchored.retain(|(name, _)| name != "fstat");
    assert!(!bound(&unanchored));
    // A call inside the read run breaks the shape.
    let mut interrupted = maps_segment_record(&[1024, 1024, 329], 2377);
    let second_read = interrupted
        .iter()
        .position(|(name, _)| name == "read")
        .unwrap()
        + 1;
    interrupted.insert(second_read, ("getpid".to_owned(), "ok".to_owned()));
    assert!(!bound(&interrupted));
    // An extra call after the segment is still compared: a
    // collapsed in-guest record is a subsequence only while
    // every other call matches native order.
    let (native, native_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
    let (mut extra, extra_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
    let after_close = extra.iter().position(|(name, _)| name == "close").unwrap() + 1;
    extra.insert(after_close, ("getpid".to_owned(), "ok".to_owned()));
    assert!(!in_guest_is_native_subsequence(
        &extra,
        &native,
        &extra_strace,
        &native_strace
    ));
}

#[test]
fn maps_segment_binding_fails_closed() {
    let (native, native_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
    let (inguest, inguest_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
    // Missing strace record on either side: that side stays
    // literal and the pairing diverges. This also pins the
    // production pairing (in-guest unconfirmed, native bound):
    // a call site passing an empty or garbage strace record
    // can never confirm.
    for (recorded_strace, native_strace) in [
        (&b""[..], &native_strace[..]),
        (&inguest_strace[..], &b""[..]),
        (&b"garbage\n"[..], &native_strace[..]),
        (
            &b"openat(-100, 0x1000 -> \"/proc/self/maps\", OFlag(O_CLOEXEC)) = ?\n"[..],
            &native_strace[..],
        ),
    ] {
        assert!(!in_guest_is_native_subsequence(
            &inguest,
            &native,
            recorded_strace,
            native_strace
        ));
    }
    // Same shape on another descriptor and file, in a run
    // that did open maps earlier: the other segment is not
    // the bound one, so its different read count diverges.
    let (two_native, two_native_strace) = record_with_segments(&[
        (3, "/proc/self/maps", &[1024, 1024, 329]),
        (4, "/etc/hostname", &[1024, 329]),
    ]);
    let (two_inguest, two_inguest_strace) = record_with_segments(&[
        (3, "/proc/self/maps", &[1024, 1024, 1024, 329]),
        (4, "/etc/hostname", &[1024, 1024, 329]),
    ]);
    assert!(!in_guest_is_native_subsequence(
        &two_inguest,
        &two_native,
        &two_inguest_strace,
        &two_native_strace
    ));
    // Descriptor reuse: maps closed, another file reopened on
    // the same descriptor, same shape there. The latest open
    // for the descriptor names the other file: no collapse.
    let (reuse_native, reuse_native_strace) = record_with_segments(&[
        (3, "/proc/self/maps", &[1024, 329]),
        (3, "/etc/hostname", &[1024, 329]),
    ]);
    let (reuse_inguest, reuse_inguest_strace) = record_with_segments(&[
        (3, "/proc/self/maps", &[1024, 1024, 329]),
        (3, "/etc/hostname", &[1024, 1024, 329]),
    ]);
    assert!(!in_guest_is_native_subsequence(
        &reuse_inguest,
        &reuse_native,
        &reuse_inguest_strace,
        &reuse_native_strace
    ));
    // A failed maps open confirms nothing: its descriptor was
    // never returned, so no segment can bind to it.
    let (mut failed, failed_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
    failed
        .iter_mut()
        .find(|(name, _)| name == "openat")
        .unwrap()
        .1 = "ENOENT".to_owned();
    assert!(!in_guest_is_native_subsequence(
        &failed,
        &native,
        &failed_strace,
        &native_strace
    ));
}

#[test]
fn maps_segment_binding_clauses_each_have_a_twin() {
    // Insert one call just before the segment's fstat, in a
    // record and its aligned strace text together.
    let insert_before_fstat = |detailed: &mut Vec<(String, String)>,
                               strace: &mut Vec<u8>,
                               name: &str,
                               outcome: &str,
                               call: &str| {
        let fstat_at = detailed
            .iter()
            .position(|(name, _)| name == "fstat")
            .unwrap();
        detailed.insert(fstat_at, (name.to_owned(), outcome.to_owned()));
        let mut lines: Vec<String> = String::from_utf8(strace.clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        let fstat_line = lines
            .iter()
            .position(|line| line.contains("fstat(3,"))
            .unwrap();
        lines.insert(fstat_line, format!("[pid 7] {call}"));
        *strace = lines.join("\n").into_bytes();
    };
    // Intervening-call clause: the SAME freeing call sits
    // before the fstat on both sides, so only the binding
    // decides. With the clause both sides stay literal and
    // the read counts diverge; without it both collapse and
    // the check would pass.
    for (freed_name, freed_outcome, freed_call) in [
        ("close", "ok", "close(3) = ?"),
        ("dup2", "3", "dup2(9, 3) = ?"),
        ("close_range", "ok", "close_range(3, 4294967295, 0) = ?"),
    ] {
        let (mut native, mut native_strace) =
            record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
        let (mut freed, mut freed_strace) =
            record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
        insert_before_fstat(
            &mut native,
            &mut native_strace,
            freed_name,
            freed_outcome,
            freed_call,
        );
        insert_before_fstat(
            &mut freed,
            &mut freed_strace,
            freed_name,
            freed_outcome,
            freed_call,
        );
        assert!(
            !in_guest_is_native_subsequence(&freed, &native, &freed_strace, &native_strace),
            "{freed_name} twin"
        );
    }
    // The strict shape: even a descriptor-free getpid there
    // on both sides refuses the collapse (only prlimit64 may
    // sit between the binding open and the fstat), while an
    // extra prlimit64 on both sides still collapses.
    for (name, outcome, call, expect_subsequence) in [
        ("getpid", "ok", "getpid() = ?", false),
        (
            "prlimit64",
            "ok",
            "prlimit64(0, 3, 0x1000, 0x1000) = ?",
            true,
        ),
    ] {
        let (mut native, mut native_strace) =
            record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
        let (mut inguest, mut inguest_strace) =
            record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
        insert_before_fstat(&mut native, &mut native_strace, name, outcome, call);
        insert_before_fstat(&mut inguest, &mut inguest_strace, name, outcome, call);
        assert_eq!(
            in_guest_is_native_subsequence(&inguest, &native, &inguest_strace, &native_strace),
            expect_subsequence,
            "{name} twin"
        );
    }
    let (native, native_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 329])]);
    // Every-call-on-the-descriptor clause: the fstat is on
    // the maps descriptor but the reads are on another one.
    let (other_fd, other_fd_strace) =
        record_with_segments(&[(3, "/proc/self/maps", &[1024, 1024, 1024, 329])]);
    let other_fd_strace = String::from_utf8(other_fd_strace)
        .unwrap()
        .replace("read(3,", "read(4,");
    assert!(!in_guest_is_native_subsequence(
        &other_fd,
        &native,
        other_fd_strace.as_bytes(),
        &native_strace
    ));
}

fn tools_agree_with_the_recorder(backend: &str) {
    let directory = tempfile::tempdir().unwrap();
    for (index, program) in PROGRAMS.iter().enumerate() {
        // The native anchor for this program: plain ptrace syscall stops,
        // no Reverie. Its stream is what a backend is compared against
        // call by call in the judged e2e run; here it bounds this test.
        let (native_exit, native_detailed) = record_detailed(
            "native",
            program,
            &directory.path().join(format!("native-{index}")),
        );
        let native: Vec<String> = native_detailed
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        assert_landmarks(program, "native", &native);
        let (exit, recorded_detailed) = record_detailed(
            backend,
            program,
            &directory.path().join(format!("{backend}-{index}")),
        );
        let recorded: Vec<String> = recorded_detailed
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        assert_eq!(exit, native_exit, "{backend} {program:?}");
        assert_landmarks(program, backend, &recorded);
        match backend {
            // Call names must match native exactly. Results may still
            // differ (for example KVM answering `rseq` with ENOSYS);
            // only the recorder's record, judged in the e2e run, compares
            // those.
            "ptrace" | "kvm" => assert_eq!(recorded, native, "{backend} {program:?}"),
            // In-guest tools start late and legitimately miss calls, so
            // their names must appear in native order with none the
            // program never made. That subsequence check runs below,
            // after the strace runs it needs for the maps ledger entry
            // (MAPS_READ_RUN above; the other entry, HEAP_GROWTH,
            // needs none). The judged native comparison, with its
            // ledger of known missing calls, is the e2e comparator's
            // job.
            "liteinst" | "in-guest-trap" => {}
            other => unreachable!("unknown backend {other}"),
        }
        let direct = run_direct(program);
        assert_eq!(direct.status.code(), Some(exit), "{backend} {program:?}");

        let strace = run(env!("CARGO_BIN_EXE_strace_minimal"), backend, program);
        assert_eq!(strace.status.code(), Some(exit), "{backend} {program:?}");
        assert_eq!(strace.stdout, direct.stdout, "{backend} {program:?}");
        let printed = strace_names(&strace);
        let vdso = printed
            .iter()
            .filter(|name| VDSO.contains(&name.as_str()))
            .count();
        let comparable: Vec<String> = printed
            .iter()
            .filter(|name| !VDSO.contains(&name.as_str()))
            .cloned()
            .collect();
        // The one named exception from the module documentation: the
        // in-guest print of a final call the guest makes after closing
        // its own stderr. Everything before it must still agree. Among
        // PROGRAMS only `/bin/echo` takes this path (its record ends
        // `close(1), close(2), exit_group`); `/bin/true` and the shell
        // keep stderr open and take full equality, so this exemption
        // cannot hide a missing print there.
        let in_guest = matches!(backend, "liteinst" | "in-guest-trap");
        if in_guest
            && recorded.len() >= 3
            && recorded[recorded.len() - 3..] == ["close", "close", "exit_group"]
            && comparable.len() + 1 == recorded.len()
            && comparable[..] == recorded[..recorded.len() - 1]
        {
            // The guest closed stderr before `exit_group` (see above).
        } else {
            assert_eq!(comparable, recorded, "{backend} {program:?}");
        }
        if in_guest {
            // The in-guest subsequence check, with both ledger
            // entries: HEAP_GROWTH is compared by count, not
            // position, and for the maps entry each record
            // collapses only segments bound by descriptor to a
            // successful /proc/self/maps open in its own strace
            // run. The native side's pretty source is a ptrace
            // strace run (strace_minimal has no native backend; the
            // ptrace leg above proves its name stream equal to the
            // native record). Programs make the same calls every
            // run (the stability the counter transfer below also
            // assumes), so each strace execution can bind its
            // recorder execution's segment.
            let native_strace = run(env!("CARGO_BIN_EXE_strace_minimal"), "ptrace", program);
            // Pin the native binding source in this same test:
            // its exit and its call-name stream must be the
            // native record's, not merely borrow that proof
            // from the ptrace leg's own test function. The
            // index alignment relies on this equality.
            assert_eq!(
                native_strace.status.code(),
                Some(native_exit),
                "{backend} {program:?}"
            );
            let native_comparable: Vec<String> = strace_names(&native_strace)
                .into_iter()
                .filter(|name| !VDSO.contains(&name.as_str()))
                .collect();
            assert_eq!(native_comparable, native, "{backend} {program:?}");
            assert!(
                in_guest_is_native_subsequence(
                    &recorded_detailed,
                    &native_detailed,
                    &strace.stderr,
                    &native_strace.stderr
                ),
                "{backend} {program:?}: in-guest calls are not a native subsequence:\n{recorded:?}\nnative:\n{native:?}"
            );
        }

        // A separate execution from the strace run above: transferring
        // its vDSO count assumes these programs make the same calls
        // every run, the stability the e2e corpus requires natively.
        let counter = run(env!("CARGO_BIN_EXE_counter1"), backend, program);
        assert_eq!(counter.status.code(), Some(exit), "{backend} {program:?}");
        assert_eq!(counter.stdout, direct.stdout, "{backend} {program:?}");
        assert_eq!(
            counter1_total(&counter, backend, program),
            recorded.len() + vdso,
            "{backend} {program:?}"
        );

        let noop = run(env!("CARGO_BIN_EXE_noop"), backend, program);
        assert_noop_is_direct(&noop, &direct, backend, program);
    }
}

/// `noop` changes nothing a program shows: its exit status and both of its
/// streams are the direct run's, byte for byte.
fn assert_noop_is_direct(noop: &Output, direct: &Output, backend: &str, program: &[&str]) {
    assert_eq!(
        noop.status.code(),
        direct.status.code(),
        "{backend} {program:?}"
    );
    assert_eq!(noop.stdout, direct.stdout, "{backend} {program:?}");
    assert_eq!(noop.stderr, direct.stderr, "{backend} {program:?}");
}

/// With the tool's own logging at its most verbose (`RUST_LOG=trace`), the
/// log goes to the tool's log file, and the program's streams under `noop`
/// are still the direct run's.
#[test]
fn a_tool_logging_at_trace_level_leaves_the_program_s_streams_unchanged() {
    let program = ["/bin/sh", "-c", "echo out; echo err >&2; exit 3"];
    let direct = run_direct(&program);
    assert_eq!(direct.status.code(), Some(3));
    let mut command = tool_command(env!("CARGO_BIN_EXE_noop"));
    command.env("RUST_LOG", "trace");
    let noop = run_tool(command, "ptrace", &program);
    assert_noop_is_direct(&noop, &direct, "ptrace", &program);
    let log = noop.log();
    assert!(
        log.contains("TRACE"),
        "the tool logged nothing at trace level: {} bytes",
        log.len()
    );
}

/// The `noop` comparison is exact: the tool's log is kept out of the
/// program's standard error, not filtered from it. A program that writes
/// reverie-ptrace's PMU validation error line itself, here only while it
/// is traced, still makes the two runs' standard error differ.
#[test]
fn a_program_writing_the_tracer_s_error_line_still_differs_from_direct() {
    // The line as reverie-ptrace emitted it on such a host, colours aside.
    const LINE: &str = "2026-11-17T20:34:14.125889Z ERROR reverie_ptrace::perf: PMU validation failed; \
                        RCB timers may be unreliable error=AmdSpecLockMapShouldBeDisabled \
                        { speclockmap_commits: 88629, locked_instructions: Measured(88632) }";
    let script = format!(
        "while read -r key value; do \
         if [ \"$key\" = TracerPid: ] && [ \"$value\" != 0 ]; then echo '{LINE}' >&2; fi; \
         done < /proc/self/status"
    );
    let program = ["/bin/sh", "-c", script.as_str()];
    let direct = run_direct(&program);
    let noop = run(env!("CARGO_BIN_EXE_noop"), "ptrace", &program);
    assert_eq!(direct.stderr, b"");
    assert_eq!(noop.stderr, format!("{LINE}\n").into_bytes());
    // Status and stdout agree, so only the comparison of standard error can
    // fail below.
    assert_eq!(noop.status.code(), direct.status.code());
    assert_eq!(noop.stdout, direct.stdout);
    let compared = std::panic::catch_unwind(|| {
        assert_noop_is_direct(&noop, &direct, "ptrace", &program);
    });
    assert!(
        compared.is_err(),
        "the comparison let the tracer's line through"
    );
}

#[test]
fn ptrace_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("ptrace");
}

#[test]
fn liteinst_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("liteinst");
}

#[test]
fn in_guest_trap_tools_agree_with_the_recorder() {
    tools_agree_with_the_recorder("in-guest-trap");
}

#[test]
fn kvm_tools_agree_with_the_recorder() {
    if kvm_available() {
        tools_agree_with_the_recorder("kvm");
    }
}
