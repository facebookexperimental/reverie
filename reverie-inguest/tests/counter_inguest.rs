/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The counting runtime on the exec-stop lane, proven against the
//! ptrace backend: zero guest instructions and zero guest syscalls
//! before arming (guest witness slots plus the measured journal
//! count), and post-arm syscall counts and sequences equal to the
//! ptrace lane's for the same programs.
//!
//! Lane boundary, named rather than normalized away: the ptrace
//! tools count the `execve` that launches the program, because the
//! tool is already watching when its launcher forks and execs. The
//! in-guest lane arms *at* the exec stop, exactly after that one
//! syscall, so its journal starts with the new image's first
//! syscall. The parity checks below therefore require the ptrace
//! record to begin with exactly that single `execve=ok`, ledger it
//! as the lane boundary, and require everything after it — totals
//! and full (name, outcome) sequence — to match exactly. Any other
//! delta fails the test with its first difference; refusals issued
//! by the counting runtime appear as `=EOPNOTSUPP` outcomes and so
//! cannot hide inside a matching total.
//!
//! Narrowed parity criterion, explicit follow-up (PR1311 Minor 2):
//! full ptrace parity is proven only for the static hello and
//! `/bin/ls` guests. The clone3 guest is refusal-only and excluded
//! from count parity (the ptrace lane would really create its
//! thread), and the constructor-witness guest has no parity check:
//! the counting runtime refuses its `rt_sigaction(SIGSEGV)` (the
//! Rust runtime installing its stack-overflow handler), so
//! "executes exactly as uninstrumented" does **not** hold for Rust
//! std guests on this lane. Restoring parity for the clone3 and
//! constructor guests is tracked as a follow-up minibead (named in
//! the landing commit) and plan §3 remains open for those two
//! guests; nothing in this file claims their parity.
//!
//! Baseline binaries (fail-closed, never skipped): `counter1` and
//! `recorder` from the examples, located via `REVERIE_COUNTER1_BIN`
//! / `REVERIE_RECORDER_BIN` when set, else beside this test binary's
//! target directory. Build them with:
//! `cargo build -p reverie-examples --features runtime --bin counter1 --bin recorder`
#![cfg(all(feature = "stage1a-probe", target_os = "linux", target_arch = "x86_64"))]

#[path = "fixtures/probe_protocol.rs"]
mod protocol;

use std::fs::File;
use std::fs::{self};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use protocol::*;
use reverie_loader::artifact::check_image;
use reverie_loader::artifact::check_loader;
use reverie_loader::manifest::COUNTER_RUNTIME_MANIFEST;
use serde_json::Value;
use serde_json::json;

const PROBE: &str = env!("CARGO_BIN_EXE_reverie-loader-stage1a-probe");
const CAPTURE_LIMIT: u64 = 32 * 1024 * 1024;

/// The syscalls whose exact return value the ptrace recorder's text
/// form compares. Mirrors `recorder_tool::EXACT` in the examples so
/// the journal adapter renders the identical text form.
const EXACT: &[&str] = &[
    "read",
    "write",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "lseek",
    "open",
    "openat",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "readlink",
    "readlinkat",
    "getdents64",
    "fcntl",
];

/// The calls the vDSO answers, excluded from the recorder's text
/// form (`recorder_tool::VDSO`): the ptrace backend turns them into
/// syscalls while the in-guest lane leaves the guest vDSO native,
/// so neither side may count them.
const VDSO: &[&str] = &[
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "time",
    "getcpu",
];

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        // Requiring TMPDIR keeps fixture compilers inside the
        // runner's retained artifact/disk domain.
        let parent =
            PathBuf::from(std::env::var_os("TMPDIR").expect("bounded recipe must set TMPDIR"));
        assert!(parent.is_dir(), "TMPDIR must already exist");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for serial in 0..100 {
            let path = parent.join(format!(
                "reverie-counter-{name}-{}-{nanos}-{serial}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    eprintln!("COUNTER_ARTIFACTS={}", path.display());
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating {}: {error}", path.display()),
            }
        }
        panic!("could not create fresh retained scratch directory");
    }
}

// Deliberately no Drop cleanup: failures must remain inspectable.
struct Capture {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn retained_command(command: &mut Command, dir: &Path, name: &str, wall: Duration) -> Capture {
    fs::write(
        dir.join(format!("{name}.argv.txt")),
        format!("{command:?}\n"),
    )
    .unwrap();
    command
        .stdin(Stdio::null())
        .stdout(File::create(dir.join(format!("{name}.stdout"))).unwrap())
        .stderr(File::create(dir.join(format!("{name}.stderr"))).unwrap())
        .process_group(0);
    let started = Instant::now();
    let mut child = command.spawn().expect("spawn retained command");
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() >= wall {
            timed_out = true;
            // SAFETY: this unreaped child is still the owner of the
            // process group created above. Do not signal a numeric
            // group after reap.
            let result = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            assert!(
                result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            );
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    fs::write(
        dir.join(format!("{name}.status.json")),
        serde_json::to_vec_pretty(&json!({
            "exit_code":status.code(), "signal":status.signal(), "timed_out":timed_out,
            "wall_seconds":started.elapsed().as_secs_f64(),
        }))
        .unwrap(),
    )
    .unwrap();
    assert!(
        !timed_out,
        "{name} exceeded its wall bound; retained at {}",
        dir.display()
    );
    let read = |suffix: &str| {
        let path = dir.join(format!("{name}.{suffix}"));
        assert!(
            fs::metadata(&path).unwrap().len() <= CAPTURE_LIMIT,
            "oversized retained capture {}",
            path.display()
        );
        fs::read(path).unwrap()
    };
    Capture {
        status,
        stdout: read("stdout"),
        stderr: read("stderr"),
    }
}

fn fixture_source(dir: &Path, name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixtures = if matches!(
        name,
        "guest_cpuid.rs" | "guest_first_store.rs" | "guest_static.ld"
    ) {
        root.join("../reverie-loader/tests/fixtures")
    } else {
        root.join("tests/fixtures")
    };
    let source = fixtures.join(name);
    let target = dir.join(name);
    fs::copy(source, &target).unwrap();
    target
}

fn compile(dir: &Path, stem: &str, linker: Option<&str>) -> PathBuf {
    let source = fixture_source(dir, &format!("{stem}.rs"));
    let output = dir.join(stem);
    let mut command = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
    command.args([
        "--edition=2024",
        "--crate-type=bin",
        "-O",
        "-C",
        "panic=abort",
    ]);
    if let Some(linker) = linker {
        let linker = fixture_source(dir, linker);
        command
            .args([
                "-C",
                "relocation-model=static",
                "-C",
                "code-model=large",
                "-C",
                "no-redzone=yes",
            ])
            .args([
                "-C",
                "link-arg=-nostartfiles",
                "-C",
                "link-arg=-nostdlib",
                "-C",
                "link-arg=-static",
            ])
            .args(["-C", "link-arg=-Wl,--build-id=none"])
            .arg("-C")
            .arg(format!("link-arg=-T{}", linker.display()));
    } else {
        // Demand a real interpreter-bearing dynamic executable below.
        command.args(["-C", "relocation-model=pic", "-C", "link-arg=-pie"]);
    }
    command.arg("-o").arg(&output).arg(source);
    let result = retained_command(
        &mut command,
        dir,
        &format!("link-{stem}"),
        Duration::from_secs(120),
    );
    assert!(
        result.status.success(),
        "link-{stem} failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

struct Images {
    _scratch: Scratch,
    loader: PathBuf,
    runtime: PathBuf,
    loader_bytes: Vec<u8>,
    runtime_bytes: Vec<u8>,
}

fn images() -> &'static Images {
    static IMAGES: OnceLock<Images> = OnceLock::new();
    IMAGES.get_or_init(|| {
        let scratch = Scratch::new("images");
        fixture_source(&scratch.0, "probe_protocol.rs");
        let loader = compile(&scratch.0, "probe_loader", Some("probe_loader.ld"));
        let runtime = compile(&scratch.0, "counter_runtime", Some("counter_runtime.ld"));
        let loader_bytes = fs::read(&loader).unwrap();
        let runtime_bytes = fs::read(&runtime).unwrap();
        check_loader(&loader_bytes).expect("actual linked loader must pass artifact checks");
        check_image(&runtime_bytes, &COUNTER_RUNTIME_MANIFEST)
            .expect("actual linked counting runtime must pass check_image under its manifest");
        Images {
            _scratch: scratch,
            loader,
            runtime,
            loader_bytes,
            runtime_bytes,
        }
    })
}

struct Observation {
    _scratch: Scratch,
    capture: Capture,
    report: Value,
}

fn observe_counter(
    scratch: Scratch,
    program: &Path,
    args: &[&str],
    witness: Option<u64>,
) -> Observation {
    let report_path = scratch.0.join("report.json");
    let mut command = Command::new(PROBE);
    command.arg("--runtime-kind=counter");
    if let Some(witness) = witness {
        command.arg("--witness").arg(format!("{witness:#x}"));
    }
    command
        .arg(&images().loader)
        .arg(&images().runtime)
        .arg(&report_path)
        .arg("--")
        .arg(program)
        .args(args);
    let capture = retained_command(&mut command, &scratch.0, "probe", Duration::from_secs(60));
    assert!(fs::metadata(&report_path).unwrap().len() <= CAPTURE_LIMIT);
    let report = serde_json::from_slice(&fs::read(report_path).unwrap())
        .expect("complete JSON probe report");
    Observation {
        _scratch: scratch,
        capture,
        report,
    }
}

/// The probe (mechanics) runtime image, compiled once, for the
/// kind/image swap refusal test.
fn probe_runtime() -> &'static Path {
    static PROBE_RUNTIME: OnceLock<PathBuf> = OnceLock::new();
    PROBE_RUNTIME.get_or_init(|| {
        let scratch = Scratch::new("probe-runtime");
        fixture_source(&scratch.0, "probe_protocol.rs");
        // Scratch has no Drop cleanup; the retained directory (and
        // the compiled image in it) outlives this handle.
        compile(&scratch.0, "probe_runtime", Some("probe_runtime.ld"))
    })
}

/// Runs the probe host with an explicitly paired runtime kind and
/// runtime image (the swap test pairs them wrong on purpose).
fn observe_swapped(
    scratch: Scratch,
    counter_kind: bool,
    runtime: &Path,
    program: &Path,
) -> Observation {
    let report_path = scratch.0.join("report.json");
    let mut command = Command::new(PROBE);
    if counter_kind {
        command.arg("--runtime-kind=counter");
    }
    command
        .arg(&images().loader)
        .arg(runtime)
        .arg(&report_path)
        .arg("--")
        .arg(program);
    let capture = retained_command(&mut command, &scratch.0, "probe", Duration::from_secs(60));
    assert!(fs::metadata(&report_path).unwrap().len() <= CAPTURE_LIMIT);
    let report = serde_json::from_slice(&fs::read(report_path).unwrap())
        .expect("complete JSON probe report");
    Observation {
        _scratch: scratch,
        capture,
        report,
    }
}

/// Runs a guest natively so a witness is proven live, not dead.
fn observe_native(scratch: &Scratch, program: &Path, args: &[&str]) -> Capture {
    let mut command = Command::new(program);
    command.args(args);
    retained_command(&mut command, &scratch.0, "native", Duration::from_secs(30))
}

/// Locates a baseline example binary, fail-closed (see module docs).
fn baseline_bin(env_name: &str, file_name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(env_name) {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "{env_name}={} is not a file; build it with: cargo build -p reverie-examples \
             --features runtime --bin counter1 --bin recorder",
            path.display()
        );
        return path;
    }
    // Beside the test binary: <target>/<profile>/deps/<test> has the
    // example binaries in <target>/<profile>/ when they were built
    // into the same target directory.
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent()?.parent().map(|dir| dir.join(file_name)));
    match beside {
        Some(path) if path.is_file() => path,
        other => panic!(
            "ptrace baseline {file_name} not found (looked beside the test binary: {other:?}); \
             this check fails closed rather than skipping. Build it with: cargo build \
             -p reverie-examples --features runtime --bin counter1 --bin recorder, \
             or set {env_name}"
        ),
    }
}

/// The ptrace lane's total syscall count for the same program, from
/// the counter example tool on the ptrace backend. This includes
/// the launching `execve`; callers ledger that one syscall.
fn ptrace_count(scratch: &Scratch, program: &Path, args: &[&str]) -> u64 {
    let counter1 = baseline_bin("REVERIE_COUNTER1_BIN", "counter1");
    let mut command = Command::new(&counter1);
    command
        .arg("--backend=ptrace")
        .arg("--")
        .arg(program)
        .args(args);
    let capture = retained_command(
        &mut command,
        &scratch.0,
        "counter1-ptrace",
        Duration::from_secs(60),
    );
    let stderr = String::from_utf8_lossy(&capture.stderr);
    stderr
        .lines()
        .find_map(|line| line.strip_prefix("counter1-global syscalls="))
        .and_then(|n| n.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            panic!(
                "counter1 --backend=ptrace printed no total; status={} stderr:\n{stderr}",
                capture.status
            )
        })
}

/// The ptrace lane's (name, outcome) record lines for the same
/// program, from the recorder example on the ptrace backend, with
/// the launching `execve` ledgered off (see module docs).
fn ptrace_record(scratch: &Scratch, program: &Path, args: &[&str], exit_code: i32) -> Vec<String> {
    let recorder = baseline_bin("REVERIE_RECORDER_BIN", "recorder");
    let output = scratch.0.join("ptrace-record.txt");
    let mut command = Command::new(&recorder);
    command
        .arg("--backend")
        .arg("ptrace")
        .arg("--output")
        .arg(&output)
        .arg(program)
        .args(args);
    let capture = retained_command(
        &mut command,
        &scratch.0,
        "recorder-ptrace",
        Duration::from_secs(60),
    );
    assert_eq!(
        capture.status.code(),
        Some(exit_code),
        "recorder on ptrace: {}",
        String::from_utf8_lossy(&capture.stderr)
    );
    let text = fs::read_to_string(&output).expect("recorder wrote its record");
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(format!("exit {exit_code}").as_str()));
    assert_eq!(
        lines.next(),
        Some("thread 0"),
        "single-threaded guests only"
    );
    let mut calls: Vec<String> = lines.map(str::to_owned).collect();
    assert_eq!(
        calls.first().map(String::as_str),
        Some("execve=ok"),
        "the ptrace record must start with the launching execve this lane ledgers"
    );
    calls.remove(0);
    calls
}

fn u(value: &Value) -> u64 {
    value.as_u64().expect("unsigned report field")
}
fn array(value: &Value) -> &[Value] {
    value.as_array().expect("report array")
}

fn syscall_name(number: u64) -> String {
    syscalls::Sysno::new(number as usize)
        .map(|sysno| sysno.name().to_owned())
        .unwrap_or_else(|| format!("syscall_{number}"))
}

fn errno_name(errno: i32) -> String {
    reverie::syscalls::Errno::new(errno)
        .name()
        .map_or_else(|| format!("E{errno}"), str::to_owned)
}

/// One journaled guest syscall: its ENTER row, an optional REFUSAL
/// row, and its RETURN row when one exists.
struct JournalCall<'a> {
    enter: &'a Value,
    refusal: Option<&'a Value>,
    result: Option<i64>,
}

fn journal_calls(report: &Value) -> Vec<JournalCall<'_>> {
    let events = array(&report["guest_events"]);
    let mut calls = Vec::new();
    let mut index = 0;
    while index < events.len() {
        let enter = &events[index];
        assert_eq!(
            u(&enter["kind"]),
            EVENT_SYSCALL_ENTER as u64,
            "guest journal must be ENTER-led: {enter}"
        );
        index += 1;
        let mut refusal = None;
        if events
            .get(index)
            .is_some_and(|e| u(&e["kind"]) == EVENT_REFUSAL as u64)
        {
            refusal = Some(&events[index]);
            index += 1;
        }
        let mut result = None;
        if events
            .get(index)
            .is_some_and(|e| u(&e["kind"]) == EVENT_SYSCALL_RETURN as u64)
        {
            assert_eq!(events[index]["nr_or_opcode"], enter["nr_or_opcode"]);
            result = Some(u(&events[index]["results"][0]) as i64);
            index += 1;
        } else {
            // No return row is only honest for a noreturn syscall.
            assert_ne!(
                u(&enter["flags"]) & FLAG_EXPECTED_NORETURN as u64,
                0,
                "guest syscall without a return row must be noreturn: {enter}"
            );
        }
        calls.push(JournalCall {
            enter,
            refusal,
            result,
        });
    }
    calls
}

/// Renders the guest journal in the ptrace recorder's text form so
/// the two lanes compare line by line.
fn journal_record(report: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    for call in journal_calls(report) {
        let name = syscall_name(u(&call.enter["nr_or_opcode"]));
        if VDSO.contains(&name.as_str()) {
            continue;
        }
        let outcome = match call.result {
            None => "?".to_owned(),
            Some(value) if (-4095..=-1).contains(&value) => {
                errno_name(i32::try_from(-value).unwrap())
            }
            Some(value) if EXACT.contains(&name.as_str()) => value.to_string(),
            Some(_) => "ok".to_owned(),
        };
        lines.push(format!("{name}={outcome}"));
    }
    lines
}

/// The first point where two records disagree, named for the panic.
fn first_difference(expected: &[String], got: &[String]) -> Option<String> {
    for (index, (a, b)) in expected.iter().zip(got).enumerate() {
        if a != b {
            return Some(format!("call {index}: {a} -> {b}"));
        }
    }
    if expected.len() != got.len() {
        let index = expected.len().min(got.len());
        let a = expected.get(index).map_or("(end)", String::as_str);
        let b = got.get(index).map_or("(end)", String::as_str);
        return Some(format!("call {index}: {a} -> {b}"));
    }
    None
}

/// Asserts totals and the full sequence match the ptrace lane, with
/// the single launching execve ledgered as the lane boundary.
fn assert_count_parity(
    scratch: &Scratch,
    report: &Value,
    program: &Path,
    args: &[&str],
    exit_code: i32,
) {
    let calls = journal_calls(report);
    let journal_total = calls.len() as u64;
    let total = ptrace_count(scratch, program, args);
    assert_eq!(
        total,
        journal_total + 1,
        "ptrace total must equal the journal total plus the one ledgered launching execve"
    );
    let expected = ptrace_record(scratch, program, args, exit_code);
    let got = journal_record(report);
    if let Some(difference) = first_difference(&expected, &got) {
        panic!(
            "in-guest journal sequence differs from the ptrace record at {difference}\n\
             ptrace: {expected:?}\njournal: {got:?}"
        );
    }
    eprintln!(
        "count parity: journal={journal_total} ptrace={total} (difference is the one \
         ledgered launching execve); sequence of {} calls identical",
        got.len()
    );
}

fn assert_counter_handoff(observation: &Observation, status: i32) {
    assert_eq!(
        observation.capture.status.code(),
        Some(status),
        "{}",
        String::from_utf8_lossy(&observation.capture.stderr)
    );
    let report = &observation.report;
    assert_eq!(report["outcome"], "handoff", "{report:#}");
    assert_eq!(report["runtime_kind"], "counter");
    assert_eq!(report["guest_status"], status);
    assert!(report["guest_signal"].is_null());
    for field in [
        "exec_return_drained",
        "ready_nonce_matches",
        "entry_bytes_restored",
        "stack_unchanged",
        "bootstrap_fds_closed",
        "detached",
    ] {
        assert_eq!(report[field], true, "missing handoff proof {field}");
    }
    // The measured (not asserted) pre-arm guest count.
    assert_eq!(report["pre_arm_guest_syscalls"], 0, "{report:#}");
    assert_eq!(u(&report["controls"]), COUNTER_REQUIRED_CONTROLS);
    assert_eq!(u(&report["ready_stop_ip"]), READY_STOP_IP);
    assert!(u(&report["entry_ip"]) > 0 && u(&report["entry_sp"]) > 0);
    assert_eq!(u(&report["entry_rax"]), 0);
    // Self-test evidence is the loader's trapped gettid and nothing
    // else: counting arms no instruction control, so the journal
    // must contain no CPUID or TSC row in either partition.
    let self_tests = array(&report["self_test_events"]);
    assert_eq!(
        self_tests.len(),
        2,
        "gettid ENTER+RETURN only: {self_tests:?}"
    );
    for event in self_tests.iter().chain(array(&report["guest_events"])) {
        let kind = u(&event["kind"]);
        assert!(
            !matches!(
                kind as u32,
                EVENT_CPUID | EVENT_RDTSC | EVENT_RDTSCP | EVENT_FAILURE
            ),
            "counting journal holds only syscall rows: {event}"
        );
    }
    let entered = self_tests
        .iter()
        .any(|e| u(&e["kind"]) == EVENT_SYSCALL_ENTER as u64 && u(&e["nr_or_opcode"]) == 186);
    let returned = self_tests.iter().any(|e| {
        u(&e["kind"]) == EVENT_SYSCALL_RETURN as u64
            && u(&e["nr_or_opcode"]) == 186
            && u(&e["results"][0]) > 0
    });
    assert!(
        entered && returned,
        "trapped-gettid evidence: {self_tests:?}"
    );
    let runtime = &report["runtime"];
    assert_eq!(u(&runtime["runtime_error"]), ERROR_NONE as u64);
    assert_eq!(u(&runtime["controls"]), COUNTER_REQUIRED_CONTROLS);
    assert_eq!(u(&runtime["overflow"]), 0);
    assert_eq!(runtime["events_reserved"], runtime["events_committed"]);
}

// Minimal independent ELF inspection (guests are not loader images).
// (type, flags, offset, vaddr, filesz, memsz) per program header.
type ElfProgramHeader = (u32, u32, u64, u64, u64, u64);

fn le16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn le64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn elf_headers(bytes: &[u8]) -> (u64, Vec<ElfProgramHeader>) {
    assert!(bytes.len() >= 64);
    assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
    assert_eq!(le16(bytes, 18), 62);
    assert_eq!(le16(bytes, 54), 56);
    let base = usize::try_from(le64(bytes, 32)).unwrap();
    let count = usize::from(le16(bytes, 56));
    assert!((1..=128).contains(&count));
    assert!(base.checked_add(count.checked_mul(56).unwrap()).unwrap() <= bytes.len());
    let headers = (0..count)
        .map(|n| {
            let p = base + n * 56;
            (
                le32(bytes, p),
                le32(bytes, p + 4),
                le64(bytes, p + 8),
                le64(bytes, p + 16),
                le64(bytes, p + 32),
                le64(bytes, p + 40),
            )
        })
        .collect();
    (le64(bytes, 24), headers)
}

/// File bytes of a virtual address range in a file-backed segment.
fn elf_bytes_at(bytes: &[u8], address: u64, len: u64) -> &[u8] {
    let (_, headers) = elf_headers(bytes);
    let end = address.checked_add(len).unwrap();
    let (_, _, offset, base, filesz, _) = headers
        .iter()
        .find(|(kind, _, _, base, filesz, _)| {
            *kind == 1 && *base <= address && end <= base.checked_add(*filesz).unwrap()
        })
        .expect("address in a file-backed PT_LOAD");
    let start = usize::try_from(offset.checked_add(address - *base).unwrap()).unwrap();
    let _ = filesz;
    &bytes[start..start + usize::try_from(len).unwrap()]
}

/// Link-time virtual address of a symbol from the ELF symbol table.
fn symbol_vaddr(bytes: &[u8], wanted: &str) -> u64 {
    let shoff = usize::try_from(le64(bytes, 40)).unwrap();
    let shentsize = usize::from(le16(bytes, 58));
    let shnum = usize::from(le16(bytes, 60));
    assert_eq!(shentsize, 64);
    assert!((1..=256).contains(&shnum));
    let section = |index: usize| {
        let p = shoff + index * 64;
        (
            le32(bytes, p + 4),  // sh_type
            le64(bytes, p + 24), // sh_offset
            le64(bytes, p + 32), // sh_size
            le32(bytes, p + 40), // sh_link
            le64(bytes, p + 56), // sh_entsize
        )
    };
    for index in 0..shnum {
        let (sh_type, sh_offset, sh_size, sh_link, sh_entsize) = section(index);
        if sh_type != 2 {
            continue; // SHT_SYMTAB only.
        }
        assert_eq!(sh_entsize, 24);
        let (_, str_offset, str_size, _, _) = section(sh_link as usize);
        let strings = &bytes[str_offset as usize..(str_offset + str_size) as usize];
        let count = (sh_size / 24) as usize;
        for symbol in 0..count {
            let p = sh_offset as usize + symbol * 24;
            let name_at = le32(bytes, p) as usize;
            let name = &strings[name_at..];
            let name = &name[..name.iter().position(|b| *b == 0).unwrap()];
            if name == wanted.as_bytes() {
                return le64(bytes, p + 8);
            }
        }
    }
    panic!("symbol {wanted} not found in guest ELF");
}

#[test]
fn counter_image_passes_check_image_under_counter_manifest() {
    let images = images();
    let checked = check_image(&images.runtime_bytes, &COUNTER_RUNTIME_MANIFEST)
        .expect("counting runtime must pass check_image under the counter manifest");
    assert!(
        reverie_loader::artifact::RUNTIME_WINDOW.contains(&checked.entry()),
        "entry {:#x} in the runtime window",
        checked.entry()
    );
    // The manifest the image rides requests exactly the counting
    // controls, and validates on its own.
    assert_eq!(COUNTER_RUNTIME_MANIFEST.validate(), Ok(()));
    assert_eq!(
        COUNTER_RUNTIME_MANIFEST.controls,
        reverie_loader::manifest::Controls {
            trap_filter: true,
            sigsys_handler: true,
            ..reverie_loader::manifest::Controls::NONE
        }
    );
    // The loader beside it still passes its own fixed check.
    check_loader(&images.loader_bytes).expect("loader must pass check_loader");
}

#[test]
fn counter_static_hello_witness_untouched_before_arm_and_count_matches_ptrace() {
    let scratch = Scratch::new("static-hello");
    let guest = compile(&scratch.0, "guest_first_store", Some("guest_static.ld"));
    // Absolute path for every launcher (the probe requires it).
    let guest = fs::canonicalize(guest).unwrap();
    let bytes = fs::read(&guest).unwrap();
    let (entry, _) = elf_headers(&bytes);
    // The first instruction is literally the witness store:
    // C7 05 <disp32> <imm32> = mov dword ptr [rip+disp32], imm32.
    let first = elf_bytes_at(&bytes, entry, 10);
    assert_eq!(
        &first[..2],
        [0xc7, 0x05],
        "first opcode must be the witness store"
    );
    let disp = i64::from(i32::from_le_bytes(first[2..6].try_into().unwrap()));
    let magic = u32::from_le_bytes(first[6..10].try_into().unwrap());
    let slot = (entry as i64 + 10 + disp) as u64;
    assert_eq!(slot, symbol_vaddr(&bytes, "witness_slot"));
    let expected_stdout = {
        let mut value = [0_u8; 8];
        value[..4].copy_from_slice(&magic.to_le_bytes());
        value
    };
    // Liveness: natively the store runs and its bytes reach stdout.
    let native = observe_native(&scratch, &guest, &[]);
    assert_eq!(native.status.code(), Some(0));
    assert_eq!(native.stdout, expected_stdout);

    let observation = observe_counter(scratch, &guest, &[], Some(slot));
    assert_counter_handoff(&observation, 0);
    assert!(observation.report["refusal"].is_null());
    assert_eq!(observation.capture.stdout, expected_stdout);
    // Zero guest instructions before arming: the slot the first
    // instruction overwrites still holds zero at both stops.
    assert_eq!(u(&observation.report["witness_address"]), slot);
    assert_eq!(u(&observation.report["witness_at_exec_drain"]), 0);
    assert_eq!(u(&observation.report["witness_at_ready"]), 0);
    // The journal is exactly write+exit, the static-hello count.
    let numbers: Vec<u64> = journal_calls(&observation.report)
        .iter()
        .map(|call| u(&call.enter["nr_or_opcode"]))
        .collect();
    assert_eq!(
        numbers,
        [libc::SYS_write as u64, libc::SYS_exit as u64],
        "static hello journal must be write+exit"
    );
    assert_count_parity(&observation._scratch, &observation.report, &guest, &[], 0);
}

#[test]
fn counter_dynamic_ls_no_pre_arm_guest_event_and_count_matches_ptrace() {
    let scratch = Scratch::new("dynamic-ls");
    let ls = Path::new("/bin/ls");
    let observation = observe_counter(scratch, ls, &["/dev/null"], None);
    assert_counter_handoff(&observation, 0);
    assert!(
        observation.report["refusal"].is_null(),
        "ls must need no named refusal: {:#}",
        observation.report
    );
    assert_eq!(observation.capture.stdout, b"/dev/null\n");
    assert!(
        !journal_calls(&observation.report).is_empty(),
        "ls syscalls are journaled after handoff"
    );
    // No refusals at all: any refusal would also surface as an
    // =EOPNOTSUPP difference in the sequence comparison.
    let refusals = journal_calls(&observation.report)
        .iter()
        .filter(|call| call.refusal.is_some())
        .count();
    assert_eq!(refusals, 0);
    assert_count_parity(
        &observation._scratch,
        &observation.report,
        ls,
        &["/dev/null"],
        0,
    );
}

#[test]
fn counter_dynamic_ctor_witness_runs_only_after_arm() {
    let scratch = Scratch::new("ctor-witness");
    let guest = compile(&scratch.0, "guest_ctor_witness", None);
    let guest = fs::canonicalize(guest).unwrap();
    let bytes = fs::read(&guest).unwrap();
    assert!(
        elf_headers(&bytes).1.iter().any(|h| h.0 == 3),
        "fixture must have a real PT_INTERP"
    );
    let slot = symbol_vaddr(&bytes, "WITNESS_SLOT");
    // Liveness: natively the constructor runs before main.
    let native = observe_native(&scratch, &guest, &[]);
    assert_eq!(native.status.code(), Some(0));
    assert_eq!(native.stdout, b"CTOR_RAN\nCTOR_WITNESS_OK\n");

    let observation = observe_counter(scratch, &guest, &[], Some(slot));
    assert_counter_handoff(&observation, 0);
    assert_eq!(observation.capture.stdout, b"CTOR_RAN\nCTOR_WITNESS_OK\n");
    // Zero loader/libc instructions before arming: the constructor's
    // slot is untouched at both stops even though the kernel entry
    // here is the dynamic loader's, and the guest image was not yet
    // relocated when the host first read it.
    let resolved = u(&observation.report["witness_address"]);
    assert_eq!(
        resolved % 0x1000,
        slot % 0x1000,
        "PIE bias is page-granular"
    );
    assert!(resolved > slot, "dynamic image resolves through its bias");
    assert_eq!(u(&observation.report["witness_at_exec_drain"]), 0);
    assert_eq!(u(&observation.report["witness_at_ready"]), 0);
    assert!(
        !journal_calls(&observation.report).is_empty(),
        "loader/startup syscalls are journaled after handoff"
    );
    // Named ledger: the one expected refusal is the Rust runtime's
    // attempt to install its SIGSEGV stack-overflow handler, which
    // the shared refusal table rejects for both test runtimes; the
    // guest tolerates EOPNOTSUPP and completes. No other refusal
    // may appear.
    let refusals: Vec<&Value> = journal_calls(&observation.report)
        .iter()
        .filter_map(|call| call.refusal)
        .collect();
    assert_eq!(refusals.len(), 1, "refusals: {refusals:?}");
    assert_eq!(
        u(&refusals[0]["nr_or_opcode"]),
        libc::SYS_rt_sigaction as u64
    );
    assert_eq!(u(&refusals[0]["args"][0]), libc::SIGSEGV as u64);
    assert_eq!(u(&refusals[0]["results"][0]), REFUSAL_GUEST_CONTROL);
    assert_eq!(u(&refusals[0]["results"][1]), libc::EOPNOTSUPP as u64);
}

#[test]
fn counter_clone3_named_refusal_without_guest_thread() {
    let scratch = Scratch::new("clone3-refusal");
    let guest = compile(&scratch.0, "guest_clone3", None);
    let guest = fs::canonicalize(guest).unwrap();
    assert!(
        elf_headers(&fs::read(&guest).unwrap())
            .1
            .iter()
            .any(|h| h.0 == 3),
        "fixture must have a real PT_INTERP"
    );
    // Refusal-only cell: under the ptrace backend the thread would
    // really be created, so this guest is excluded from count parity.
    let observation = observe_counter(scratch, &guest, &[], None);
    assert_counter_handoff(&observation, EXIT_FAILURE);
    assert_eq!(observation.report["refusal"], "test_domain_clone");
    assert_eq!(
        observation.capture.stdout,
        b"DIRECT_CLONE3_REQUEST\nDIRECT_CLONE3_REFUSED\n"
    );
    assert!(
        !String::from_utf8_lossy(&observation.capture.stdout)
            .contains("UNEXPECTED_GUEST_THREAD_RAN")
    );
    let calls = journal_calls(&observation.report);
    let clone_refusals: Vec<&JournalCall<'_>> = calls
        .iter()
        .filter(|call| {
            call.refusal
                .is_some_and(|r| u(&r["results"][0]) == REFUSAL_CLONE)
        })
        .collect();
    assert_eq!(clone_refusals.len(), 1);
    let call = clone_refusals[0];
    let refusal = call.refusal.unwrap();
    assert_eq!(u(&refusal["nr_or_opcode"]), libc::SYS_clone3 as u64);
    assert_eq!(u(&refusal["results"][1]), libc::EOPNOTSUPP as u64);
    assert_eq!(call.enter["args"], refusal["args"]);
    assert_eq!(call.result, Some(-i64::from(libc::EOPNOTSUPP)));
    // Any other refusal is the one named Rust-runtime SIGSEGV
    // sigaction ledgered in the constructor-witness test.
    for other in calls.iter().filter_map(|call| call.refusal) {
        if u(&other["results"][0]) != REFUSAL_CLONE {
            assert_eq!(u(&other["nr_or_opcode"]), libc::SYS_rt_sigaction as u64);
            assert_eq!(u(&other["args"][0]), libc::SIGSEGV as u64);
            assert_eq!(u(&other["results"][0]), REFUSAL_GUEST_CONTROL);
        }
    }
}

#[test]
fn runtime_kind_paired_with_the_other_kinds_image_is_refused_both_ways() {
    // Fail-closed in both directions (PR1311 Major (c)): each
    // runtime kind paired with the other kind's image is refused
    // with no handoff — the host demands the kind's control word
    // and ready evidence, and each image refuses a control page
    // whose required word is not its own. The guest never runs.
    let true_bin = Path::new("/bin/true");
    assert!(true_bin.is_file(), "swap guest /bin/true must exist");
    for (name, counter_kind, runtime) in [
        ("probe-kind-counter-image", false, images().runtime.clone()),
        (
            "counter-kind-probe-image",
            true,
            probe_runtime().to_path_buf(),
        ),
    ] {
        let observation = observe_swapped(Scratch::new(name), counter_kind, &runtime, true_bin);
        assert_eq!(
            observation.capture.status.code(),
            Some(122),
            "{name} must exit with the probe refusal code; stderr: {}",
            String::from_utf8_lossy(&observation.capture.stderr)
        );
        assert_eq!(
            observation.report["outcome"], "refused",
            "{name} report: {}",
            observation.report
        );
        assert_ne!(
            observation.report["detached"], true,
            "{name} must never detach a handed-off guest"
        );
        assert!(
            observation.report["refusal"].is_string()
                || observation.report["journal_error"].is_string(),
            "{name} must name its refusal: {}",
            observation.report
        );
    }
}
