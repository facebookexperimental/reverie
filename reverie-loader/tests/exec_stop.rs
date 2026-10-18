/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real, opt-in exec-stop mechanics tests. Each observation runs in a separate
//! probe subprocess. The official recipe must additionally contain its whole
//! process tree with PID/cgroup/disk bounds and serialize this test binary.
//! Linked images, compiler output, reports and guest output are retained under
//! TMPDIR on success and failure. These are mechanics/test-domain checks, not
//! Detcore integration or successful guest multithreading.
#![cfg(all(feature = "stage1a-probe", target_os = "linux", target_arch = "x86_64"))]

#[path = "fixtures/probe_protocol.rs"]
mod protocol;

use std::collections::BTreeSet;
use std::fs::File;
use std::fs::{self};
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::FileExt;
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
use reverie_loader::artifact::check_loader;
use reverie_loader::artifact::check_runtime;
use reverie_loader::artifact::{self};
use reverie_loader::image::ValidatedImage;
use serde_json::Value;
use serde_json::json;

const PROBE: &str = env!("CARGO_BIN_EXE_reverie-loader-stage1a-probe");
const CAPTURE_LIMIT: u64 = 32 * 1024 * 1024;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        // Requiring TMPDIR prevents fixture compilers from quietly escaping
        // the runner's retained artifact/disk domain.
        let parent =
            PathBuf::from(std::env::var_os("TMPDIR").expect("bounded recipe must set TMPDIR"));
        assert!(parent.is_dir(), "TMPDIR must already exist");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for serial in 0..100 {
            let path = parent.join(format!(
                "reverie-exec-stop-{name}-{}-{nanos}-{serial}",
                std::process::id()
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => {
                    eprintln!("EXEC_STOP_ARTIFACTS={}", path.display());
                    return Self(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating {}: {error}", path.display()),
            }
        }
        panic!("could not create fresh retained scratch directory");
    }
}

// Deliberately no Drop cleanup: a failed compiler/trace must remain inspectable.
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
            // SAFETY: this unreaped child is still the owner of the process
            // group created above. Do not signal a numeric group after reap.
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
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
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
        let runtime = compile(&scratch.0, "probe_runtime", Some("probe_runtime.ld"));
        let loader_bytes = fs::read(&loader).unwrap();
        let runtime_bytes = fs::read(&runtime).unwrap();
        check_loader(&loader_bytes).expect("actual linked loader must pass artifact checks");
        check_runtime(&runtime_bytes).expect("actual linked runtime must pass artifact checks");
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

fn observe(scratch: Scratch, loader: &Path, program: &Path, args: &[&str]) -> Observation {
    observe_with_fault(scratch, loader, program, args, None)
}

fn observe_with_fault(
    scratch: Scratch,
    loader: &Path,
    program: &Path,
    args: &[&str],
    fault: Option<&str>,
) -> Observation {
    let report_path = scratch.0.join("report.json");
    let mut command = Command::new(PROBE);
    if let Some(fault) = fault {
        command.arg(fault);
    }
    command
        .arg(loader)
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

fn u(value: &Value) -> u64 {
    value.as_u64().expect("unsigned report field")
}
fn array(value: &Value) -> &[Value] {
    value.as_array().expect("report array")
}
fn args(value: &Value, count: usize) -> Vec<u64> {
    let values = array(value);
    assert_eq!(values.len(), count);
    values.iter().map(u).collect()
}

fn bytes_at<'a>(image: &ValidatedImage<'_>, bytes: &'a [u8], address: u64, len: u64) -> &'a [u8] {
    let end = address.checked_add(len).unwrap();
    let segment = image
        .segments()
        .find(|s| {
            s.permissions.execute
                && s.memory.start <= address
                && end <= s.memory.end
                && end - s.memory.start <= s.file.end - s.file.start
        })
        .expect("IP in file-backed executable segment");
    let start = usize::try_from(segment.file.start + address - segment.memory.start).unwrap();
    &bytes[start..start + usize::try_from(len).unwrap()]
}

fn assert_gate(row: &Value, images: &Images) {
    let ip = u(&row["ip"]);
    let opcode = ip.checked_sub(2).unwrap();
    let (image, bytes) = match row["gate"].as_str().unwrap() {
        "loader" => {
            assert!(artifact::LOADER_GATE.contains(&opcode));
            assert!(ip <= artifact::LOADER_GATE.end);
            (
                check_loader(&images.loader_bytes).unwrap(),
                &images.loader_bytes,
            )
        }
        "runtime" => {
            assert!(artifact::RUNTIME_GATE.contains(&opcode));
            assert!(ip <= artifact::RUNTIME_GATE.end);
            (
                check_runtime(&images.runtime_bytes).unwrap(),
                &images.runtime_bytes,
            )
        }
        other => panic!("unexpected gate {other}"),
    };
    assert_eq!(bytes_at(&image, bytes, opcode, 2), [0x0f, 0x05]);
}

fn assert_trace(report: &Value) {
    let trace = array(&report["bootstrap_syscalls"]);
    assert!(!trace.is_empty());
    assert_eq!(
        trace.len() % 2,
        0,
        "all bootstrap calls must complete before ready"
    );
    let images = images();
    let mut arms = 0;
    for pair in trace.as_chunks::<2>().0 {
        let (entry, exit) = (&pair[0], &pair[1]);
        assert_eq!(entry["phase"], "entry");
        assert_eq!(exit["phase"], "exit");
        assert_eq!(entry["number"], exit["number"]);
        assert_eq!(entry["effective_number"], entry["number"]);
        assert_eq!(exit["effective_number"], exit["number"]);
        assert_eq!(args(&entry["args"], 6), args(&exit["args"], 6));
        assert_gate(entry, images);
        assert!(u(&entry["sp"]) > 0 && u(&exit["sp"]) > 0);
        if u(&entry["number"]) == libc::SYS_rt_sigreturn as u64 {
            // rt_sigreturn restores the interrupted tool context. It does
            // not return at the gate's post-syscall address.
            assert_eq!(exit["gate"], "sigreturn-context");
            let ip = u(&exit["ip"]);
            let loader = check_loader(&images.loader_bytes).unwrap();
            let runtime = check_runtime(&images.runtime_bytes).unwrap();
            assert!(
                loader
                    .segments()
                    .chain(runtime.segments())
                    .any(|s| s.permissions.execute && s.memory.contains(&ip))
            );
        } else {
            assert_eq!(entry["ip"], exit["ip"]);
            assert_eq!(entry["sp"], exit["sp"]);
            assert_eq!(entry["gate"], exit["gate"]);
            assert_gate(exit, images);
        }
        exit["return_value"].as_i64().expect("signed kernel return");
        exit["is_error"].as_bool().expect("kernel error flag");
        if u(&entry["number"]) == libc::SYS_seccomp as u64 {
            assert_eq!(u(&entry["args"][0]), libc::SECCOMP_SET_MODE_FILTER as u64);
            assert_eq!(exit["return_value"], 0);
            assert_eq!(exit["is_error"], false);
            arms += 1;
        }
    }
    assert_eq!(
        arms, 1,
        "exact successful filter arm observed before handoff"
    );
    // These are patched-entry tool injections, deliberately separate from
    // the syscall trace once execution is redirected into owned images.
    let injections = array(&report["injected_syscalls"]);
    let reserve = injections
        .first()
        .expect("actual ToolRegion reservation injection");
    assert_eq!(u(&reserve["number"]), libc::SYS_mmap as u64);
    let reserve_args = args(&reserve["args"], 6);
    assert_eq!(reserve_args[0], artifact::TOOL_REGION.start);
    assert_eq!(
        reserve_args[1],
        artifact::TOOL_REGION.end - artifact::TOOL_REGION.start
    );
    assert_eq!(reserve_args[2], libc::PROT_NONE as u64);
    assert_eq!(
        reserve_args[3],
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64
    );
    assert_eq!(u(&reserve["result"]), artifact::TOOL_REGION.start);
    for call in injections {
        args(&call["args"], 6);
        let result = u(&call["result"]);
        assert!(result < u64::MAX - 4095, "failed mapping injection");
    }
    assert_eq!(report["pre_arm_guest_syscalls"], 0);
}

fn assert_events(report: &Value) {
    let mut seen = BTreeSet::new();
    for (name, flag) in [
        ("self_test_events", FLAG_SELF_TEST),
        ("guest_events", FLAG_GUEST),
    ] {
        let mut previous = None;
        for event in array(&report[name]) {
            let seq = u(&event["seq"]);
            assert_eq!(u(&event["commit"]), seq.checked_add(1).unwrap());
            assert!(
                seen.insert(seq),
                "journal event duplicated between partitions"
            );
            assert!(previous.is_none_or(|last| seq > last));
            previous = Some(seq);
            let flags = u(&event["flags"]);
            assert_ne!(flags & flag as u64, 0);
            assert_eq!(flags & (FLAG_SELF_TEST | FLAG_GUEST) as u64, flag as u64);
            assert_ne!(u(&event["kind"]), EVENT_FAILURE as u64);
            assert!(u(&event["ip"]) > 0 && u(&event["sp"]) > 0);
            args(&event["args"], 6);
            args(&event["results"], 4);
            u(&event["nr_or_opcode"]);
        }
    }
    let self_tests = array(&report["self_test_events"]);
    assert!(
        self_tests
            .iter()
            .any(|e| u(&e["kind"]) == EVENT_RDTSCP as u64 && u(&e["results"][1]) == TSC_AUX_REPLY)
    );
    assert!(
        self_tests
            .iter()
            .any(|e| u(&e["kind"]) == EVENT_CPUID as u64
                && u(&e["args"][0]) == MAGIC_CPUID_LEAF as u64
                && args(&e["results"], 4) == CPUID_REPLY)
    );
    for kind in [EVENT_RDTSC, EVENT_RDTSCP] {
        assert!(
            self_tests
                .iter()
                .any(|e| u(&e["kind"]) == kind as u64 && u(&e["results"][0]) == TSC_REPLY)
        );
    }
    assert!(
        self_tests
            .iter()
            .any(|e| u(&e["kind"]) == EVENT_SYSCALL_ENTER as u64
                && u(&e["nr_or_opcode"]) == libc::SYS_gettid as u64)
    );
    assert!(
        self_tests
            .iter()
            .any(|e| u(&e["kind"]) == EVENT_SYSCALL_RETURN as u64
                && u(&e["nr_or_opcode"]) == libc::SYS_gettid as u64
                && u(&e["results"][0]) > 0)
    );
    let runtime = &report["runtime"];
    assert_eq!(u(&runtime["runtime_error"]), ERROR_NONE as u64);
    assert_eq!(u(&runtime["controls"]), REQUIRED_CONTROLS);
    assert_eq!(u(&runtime["overflow"]), 0);
    assert_eq!(runtime["events_reserved"], runtime["events_committed"]);
    assert!(u(&runtime["events_committed"]) >= seen.len() as u64);
}

fn assert_handoff(observation: &Observation, status: i32) {
    assert_eq!(
        observation.capture.status.code(),
        Some(status),
        "{}",
        String::from_utf8_lossy(&observation.capture.stderr)
    );
    assert_eq!(observation.report["guest_status"], status);
    assert!(observation.report["guest_signal"].is_null());
    assert_handoff_facts(&observation.report);
}

fn assert_handoff_facts(report: &Value) {
    assert_eq!(report["outcome"], "handoff", "{report:#}");
    assert_eq!(report["fault_requested"], "none");
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
    assert_eq!(u(&report["controls"]), REQUIRED_CONTROLS);
    assert_eq!(u(&report["ready_stop_ip"]), READY_STOP_IP);
    assert!(u(&report["entry_ip"]) > 0 && u(&report["entry_sp"]) > 0);
    assert_eq!(u(&report["entry_rax"]), 0);
    assert_exec_drain_facts(report);
    assert!(u(&report["stack_bytes"]) >= PAGE_BYTES);
    assert_trace(report);
    assert_events(report);
}

// Minimal independent ELF inspection also accepts the dynamic guest. Guest
// validation is not loader/runtime artifact validation: their domains differ.
type ElfProgramHeader = (u32, u32, u64, u64, u64, u64);

fn elf_headers(bytes: &[u8]) -> (u64, Vec<ElfProgramHeader>) {
    assert!(bytes.len() >= 64);
    assert_eq!(&bytes[..7], b"\x7fELF\x02\x01\x01");
    let le16 = |offset| u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
    let le32 = |offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let le64 = |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    assert_eq!(le16(18), 62);
    assert_eq!(le16(54), 56);
    let base = usize::try_from(le64(32)).unwrap();
    let count = usize::from(le16(56));
    assert!((1..=128).contains(&count));
    assert!(base.checked_add(count.checked_mul(56).unwrap()).unwrap() <= bytes.len());
    let headers = (0..count)
        .map(|n| {
            let p = base + n * 56;
            (
                le32(p),
                le32(p + 4),
                le64(p + 8),
                le64(p + 16),
                le64(p + 32),
                le64(p + 40),
            )
        })
        .collect();
    (le64(24), headers)
}

fn assert_static_guest_opcodes(report: &Value, bytes: &[u8]) {
    let (_, headers) = elf_headers(bytes);
    for event in array(&report["guest_events"]) {
        let kind = u(&event["kind"]);
        let (address, opcode): (u64, &[u8]) = match kind as u32 {
            EVENT_SYSCALL_ENTER | EVENT_SYSCALL_RETURN => {
                (u(&event["ip"]).checked_sub(2).unwrap(), &[0x0f, 0x05])
            }
            EVENT_CPUID => (u(&event["ip"]), &[0x0f, 0xa2]),
            other => panic!("unexpected event in static fixture: {other}"),
        };
        let (_, _, offset, base, _, _) = headers
            .iter()
            .find(|(kind, flags, _, base, filesz, _)| {
                *kind == 1
                    && flags & 1 != 0
                    && *base <= address
                    && address.checked_add(opcode.len() as u64).unwrap()
                        <= base.checked_add(*filesz).unwrap()
            })
            .unwrap();
        let start = usize::try_from(offset.checked_add(address - base).unwrap()).unwrap();
        assert_eq!(
            &bytes[start..start + opcode.len()],
            opcode,
            "actual guest event must identify its own ELF instruction"
        );
    }
}

#[test]
fn dynamic_ls_has_no_pre_arm_guest_syscall() {
    let scratch = Scratch::new("ls");
    let observation = observe(
        scratch,
        &images().loader,
        Path::new("/bin/ls"),
        &["/dev/null"],
    );
    assert_handoff(&observation, 0);
    assert!(observation.report["refusal"].is_null());
    assert_eq!(observation.capture.stdout, b"/dev/null\n");
    assert!(!array(&observation.report["guest_events"]).is_empty());
}

#[test]
fn literal_first_cpuid_uses_original_kernel_entry_and_is_intercepted() {
    let scratch = Scratch::new("first-cpuid");
    let guest = compile(&scratch.0, "guest_cpuid", Some("guest_static.ld"));
    let bytes = fs::read(&guest).unwrap();
    let (entry, headers) = elf_headers(&bytes);
    let (_, _, offset, address, file_bytes, _) = headers
        .into_iter()
        .find(|(kind, flags, _, address, size, _)| {
            *kind == 1 && flags & 1 != 0 && *address <= entry && entry + 2 <= address + size
        })
        .unwrap();
    assert!(entry - address + 2 <= file_bytes);
    let offset = usize::try_from(offset + entry - address).unwrap();
    assert_eq!(
        &bytes[offset..offset + 2],
        [0x0f, 0xa2],
        "CPUID must be the literal ELF entry opcode"
    );
    let observation = observe(scratch, &images().loader, &guest, &[]);
    assert_handoff(&observation, 0);
    assert_eq!(u(&observation.report["entry_ip"]), entry);
    assert!(observation.report["refusal"].is_null());
    let mut expected = Vec::new();
    for register in CPUID_REPLY {
        expected.extend_from_slice(&register.to_le_bytes());
    }
    expected.extend_from_slice(b"FIRST_CPUID_OK\n");
    assert_eq!(observation.capture.stdout, expected);
    assert_eq!(array(&observation.report["guest_events"]).len(), 6);
    assert_static_guest_opcodes(&observation.report, &bytes);
    let cpuid: Vec<_> = array(&observation.report["guest_events"])
        .iter()
        .filter(|e| u(&e["kind"]) == EVENT_CPUID as u64)
        .collect();
    assert_eq!(cpuid.len(), 1);
    assert_eq!(u(&cpuid[0]["ip"]), entry);
    assert_eq!(u(&observation.report["entry_rax"]), 0);
    assert_eq!(u(&cpuid[0]["args"][0]), 0);
    assert_eq!(
        u(&cpuid[0]["args"][0]),
        u(&observation.report["entry_rax"]) & u32::MAX as u64
    );
    assert_eq!(args(&cpuid[0]["results"], 4), CPUID_REPLY);
}

#[test]
fn static_write_exit_is_observed_after_handoff() {
    let scratch = Scratch::new("static-marker");
    let guest = compile(&scratch.0, "guest_static_marker", Some("guest_static.ld"));
    let bytes = fs::read(&guest).unwrap();
    let observation = observe(scratch, &images().loader, &guest, &[]);
    assert_handoff(&observation, 0);
    assert!(observation.report["refusal"].is_null());
    assert_eq!(observation.capture.stdout, b"STATIC_GUEST_OK\n");
    assert_eq!(array(&observation.report["guest_events"]).len(), 3);
    assert_static_guest_opcodes(&observation.report, &bytes);
    let events = array(&observation.report["guest_events"]);
    let enters: Vec<_> = events
        .iter()
        .filter(|e| u(&e["kind"]) == EVENT_SYSCALL_ENTER as u64)
        .collect();
    assert_eq!(enters.len(), 2);
    assert_eq!(u(&enters[0]["nr_or_opcode"]), libc::SYS_write as u64);
    assert_eq!(u(&enters[0]["args"][0]), 1);
    assert_eq!(u(&enters[0]["args"][2]), b"STATIC_GUEST_OK\n".len() as u64);
    assert_eq!(u(&enters[1]["nr_or_opcode"]), libc::SYS_exit as u64);
    assert_ne!(u(&enters[1]["flags"]) & FLAG_EXPECTED_NORETURN as u64, 0);
    let returns: Vec<_> = events
        .iter()
        .filter(|e| u(&e["kind"]) == EVENT_SYSCALL_RETURN as u64)
        .collect();
    assert_eq!(returns.len(), 1);
    assert_eq!(u(&returns[0]["nr_or_opcode"]), libc::SYS_write as u64);
    assert_eq!(
        u(&returns[0]["results"][0]),
        b"STATIC_GUEST_OK\n".len() as u64
    );
}

#[test]
fn dynamic_direct_clone3_is_recorded_and_refused_without_a_guest_thread() {
    let scratch = Scratch::new("direct-clone3");
    let guest = compile(&scratch.0, "guest_clone3", None);
    assert!(
        elf_headers(&fs::read(&guest).unwrap())
            .1
            .iter()
            .any(|h| h.0 == 3),
        "fixture must have a real PT_INTERP"
    );
    let observation = observe(scratch, &images().loader, &guest, &[]);
    assert_handoff(&observation, EXIT_FAILURE);
    assert_eq!(observation.report["refusal"], "test_domain_clone");
    assert_eq!(
        observation.capture.stdout,
        b"DIRECT_CLONE3_REQUEST\nDIRECT_CLONE3_REFUSED\n"
    );
    let events = array(&observation.report["guest_events"]);
    let refusals: Vec<_> = events
        .iter()
        .filter(|e| u(&e["kind"]) == EVENT_REFUSAL as u64)
        .collect();
    assert_eq!(refusals.len(), 1);
    let refusal = refusals[0];
    assert_eq!(u(&refusal["nr_or_opcode"]), libc::SYS_clone3 as u64);
    assert_eq!(u(&refusal["results"][0]), REFUSAL_CLONE);
    assert_eq!(u(&refusal["results"][1]), libc::EOPNOTSUPP as u64);
    let entered = events
        .iter()
        .find(|e| {
            u(&e["kind"]) == EVENT_SYSCALL_ENTER as u64
                && e["nr_or_opcode"] == refusal["nr_or_opcode"]
        })
        .unwrap();
    let returned = events
        .iter()
        .find(|e| {
            u(&e["kind"]) == EVENT_SYSCALL_RETURN as u64
                && e["nr_or_opcode"] == refusal["nr_or_opcode"]
        })
        .unwrap();
    assert!(u(&entered["seq"]) < u(&refusal["seq"]) && u(&refusal["seq"]) < u(&returned["seq"]));
    assert_eq!(entered["args"], refusal["args"]);
    assert_eq!(
        returned["results"][0].as_u64().unwrap(),
        (-i64::from(libc::EOPNOTSUPP)) as u64
    );
}

/// This row intentionally records a test-domain gap. It does not count an
/// expected reserved-signal/clone refusal as successful guest multithreading.
#[test]
fn dynamic_std_thread_startup_records_its_named_domain_gap() {
    let scratch = Scratch::new("std-thread-startup");
    let guest = compile(&scratch.0, "guest_threads", None);
    assert!(
        elf_headers(&fs::read(&guest).unwrap())
            .1
            .iter()
            .any(|h| h.0 == 3),
        "fixture must have a real PT_INTERP"
    );
    let observation = observe(scratch, &images().loader, &guest, &[]);
    assert_handoff_facts(&observation.report);
    assert_eq!(observation.capture.status.code(), Some(122));
    assert!(observation.report["guest_status"].is_null());
    assert_eq!(observation.report["guest_signal"], libc::SIGABRT);
    let output = String::from_utf8_lossy(&observation.capture.stdout);
    assert!(output.starts_with("THREAD_CLONE_REQUEST\n"));
    assert!(!output.contains("UNEXPECTED_GUEST_THREAD_RAN"));
    let events = array(&observation.report["guest_events"]);
    let refusals: Vec<_> = events
        .iter()
        .filter(|e| u(&e["kind"]) == EVENT_REFUSAL as u64)
        .collect();
    // Pin the observed std::thread creation attempt, including the earlier
    // signal-mask refusal and the later abort cleanup. A different refusal
    // sequence must fail this row rather than masquerade as thread support.
    assert_eq!(observation.capture.stdout, b"THREAD_CLONE_REQUEST\n");
    assert_eq!(refusals.len(), 3);
    for (refusal, (number, category)) in refusals.iter().zip([
        (libc::SYS_rt_sigprocmask as u64, REFUSAL_GUEST_CONTROL),
        (libc::SYS_clone3 as u64, REFUSAL_CLONE),
        (libc::SYS_rt_sigprocmask as u64, REFUSAL_GUEST_CONTROL),
    ]) {
        assert_eq!(u(&refusal["nr_or_opcode"]), number);
        assert_eq!(u(&refusal["results"][0]), category);
        assert_eq!(u(&refusal["results"][1]), libc::EOPNOTSUPP as u64);
        let position = events
            .iter()
            .position(|event| event["seq"] == refusal["seq"])
            .unwrap();
        assert!(position > 0 && position + 1 < events.len());
        let entered = &events[position - 1];
        let returned = &events[position + 1];
        assert_eq!(u(&entered["kind"]), EVENT_SYSCALL_ENTER as u64);
        assert_eq!(u(&returned["kind"]), EVENT_SYSCALL_RETURN as u64);
        assert_eq!(u(&entered["seq"]).checked_add(1), Some(u(&refusal["seq"])));
        assert_eq!(u(&refusal["seq"]).checked_add(1), Some(u(&returned["seq"])));
        assert_eq!(u(&entered["nr_or_opcode"]), number);
        assert_eq!(u(&returned["nr_or_opcode"]), number);
        assert_eq!(entered["args"], refusal["args"]);
        assert_eq!(returned["args"], refusal["args"]);
        assert_eq!(
            u(&returned["results"][0]),
            (-i64::from(libc::EOPNOTSUPP)) as u64
        );
    }
    let first = refusals[0];
    assert_eq!(u(&first["args"][0]), libc::SIG_BLOCK as u64);
    assert_eq!(u(&first["args"][3]), 8);
    assert_eq!(u(&refusals[1]["args"][1]), 88, "actual clone3 request size");
    assert_eq!(u(&refusals[2]["args"][0]), libc::SIG_SETMASK as u64);
    assert_eq!(u(&refusals[2]["args"][2]), 0);
    assert_eq!(u(&refusals[2]["args"][3]), 8);
    assert_eq!(observation.report["refusal"], "test_domain_guest_control");
    // Preserve every raw refusal and the actual SIGABRT outcome as a domain
    // gap, never a successful multithreaded execution.
    fs::write(
        observation._scratch.0.join("limited-domain-gap.json"),
        serde_json::to_vec_pretty(&json!({
            "classification":"EXPECTED_TEST_DOMAIN_GAP_NOT_MULTITHREADING_SUCCESS",
            "first_refusal":first, "all_refusals":refusals,
            "guest_status":observation.report["guest_status"],
            "guest_signal":observation.report["guest_signal"],
        }))
        .unwrap(),
    )
    .unwrap();
}

/// Fault injection substitutes an invalid syscall number at the *actual*
/// ARCH_SET_CPUID(0) entry. This checks propagation of a real kernel ENOSYS;
/// it is not evidence of unavailable CPUID-faulting hardware.
#[test]
fn injected_cpuid_arm_enosys_refuses_without_guest_release() {
    let scratch = Scratch::new("cpuid-arm-enosys");
    let guest = compile(&scratch.0, "guest_static_marker", Some("guest_static.ld"));
    let observation = observe_with_fault(
        scratch,
        &images().loader,
        &guest,
        &[],
        Some("--inject-cpuid-arm-enosys"),
    );
    let report = &observation.report;
    assert_eq!(observation.capture.status.code(), Some(122));
    assert_eq!(report["outcome"], "refused");
    assert_eq!(report["fault_requested"], "cpuid_arm_enosys");
    assert_refused_child_retired(report);
    assert_eq!(
        u(&report["runtime"]["runtime_error"]),
        ERROR_CPUID_ARM as u64
    );
    assert_eq!(
        u(&report["runtime"]["runtime_phase"]),
        PHASE_FAILED as u64,
        "the runtime itself must fail closed before the parent backstop"
    );
    assert_ne!(report["detached"], true);
    assert!(report["guest_status"].is_null());
    assert!(array(&report["guest_events"]).is_empty());
    assert!(observation.capture.stdout.is_empty());
    let trace = array(&report["bootstrap_syscalls"]);
    let injected: Vec<_> = trace
        .iter()
        .filter(|r| r["phase"] == "entry" && r["number"] != r["effective_number"])
        .collect();
    assert_eq!(injected.len(), 1);
    let entry = injected[0];
    assert_eq!(u(&entry["number"]), libc::SYS_arch_prctl as u64);
    assert_eq!(u(&entry["effective_number"]), u64::MAX);
    assert_eq!(&args(&entry["args"], 6)[..2], [0x1012, 0]);
    assert_gate(entry, images());
    let exits: Vec<_> = trace
        .iter()
        .filter(|r| r["phase"] == "exit" && r["number"] != r["effective_number"])
        .collect();
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0]["number"], entry["number"]);
    assert_eq!(exits[0]["effective_number"], entry["effective_number"]);
    assert_eq!(exits[0]["args"], entry["args"]);
    assert_eq!(exits[0]["return_value"], -i64::from(libc::ENOSYS));
    assert_eq!(exits[0]["is_error"], true);
    assert_gate(exits[0], images());
    for row in trace.iter().filter(|r| r["phase"] == "entry") {
        assert_gate(row, images());
    }
}

#[test]
fn invalid_loader_image_is_a_named_refusal_before_guest_entry() {
    let scratch = Scratch::new("invalid-image");
    let invalid = scratch.0.join("invalid-loader");
    fs::write(&invalid, b"\x7fELF").unwrap();
    assert!(check_loader(&fs::read(&invalid).unwrap()).is_err());
    let guest = compile(&scratch.0, "guest_static_marker", Some("guest_static.ld"));
    let observation = observe(scratch, &invalid, &guest, &[]);
    assert_eq!(observation.capture.status.code(), Some(122));
    assert_eq!(observation.report["outcome"], "refused");
    assert!(
        observation.report["refusal"]
            .as_str()
            .unwrap()
            .starts_with("invalid_loader_image")
    );
    assert!(observation.report["guest_status"].is_null());
    assert!(observation.capture.stdout.is_empty());
    assert_eq!(observation.report["cleanup"]["child_created"], false);
    assert_eq!(observation.report["cleanup"]["owner"], "none");
    assert_eq!(observation.report["cleanup"]["kill_requested"], false);
    assert!(observation.report["cleanup"]["wait_error"].is_null());
}

#[test]
fn an_actual_guest_load_segment_collision_is_refused_before_guest_entry() {
    let scratch = Scratch::new("tool-region-collision");
    let guest = compile(&scratch.0, "guest_collision", Some("guest_collision.ld"));
    let bytes = fs::read(&guest).unwrap();
    let (entry, headers) = elf_headers(&bytes);
    assert!(artifact::TOOL_REGION.contains(&entry));
    assert!(
        headers
            .iter()
            .any(|(kind, _, _, address, _, mem_size)| *kind == 1
                && *mem_size > 0
                && *address < artifact::TOOL_REGION.end
                && address.checked_add(*mem_size).unwrap() > artifact::TOOL_REGION.start)
    );
    let observation = observe(scratch, &images().loader, &guest, &[]);
    assert_eq!(observation.capture.status.code(), Some(122));
    assert_eq!(observation.report["outcome"], "refused");
    assert!(
        observation.report["refusal"]
            .as_str()
            .unwrap()
            .starts_with("tool_region_collision")
    );
    assert!(observation.report["guest_status"].is_null());
    assert!(observation.capture.stdout.is_empty());
    assert_refused_child_retired(&observation.report);
}

// Additional integration tests and helpers for the exec-stop negative controls.

fn assert_refused_child_retired(report: &Value) {
    assert_eq!(report["cleanup"]["child_created"], true);
    assert_eq!(report["cleanup"]["confirmed"], true);
    assert!(report["cleanup"]["wait_error"].is_null());
    assert_eq!(report["cleanup"]["owner"], "ptracer");
    assert_eq!(
        report["cleanup"]["confirmation"],
        "safeptrace_terminal_wait"
    );
}

// The assertions select the native x86-64 execve ELF path used by these
// fixtures, rather than claiming a contract for compat or other launch ABIs.
fn assert_exec_drain_facts(report: &Value) {
    let event = &report["exec_event"];
    let exit = &report["exec_exit"];
    assert_eq!(event["event"], "exec");
    assert_eq!(exit["event"], "syscall");
    assert!(u(&event["pid"]) > 0);
    assert_eq!(event["pid"], event["former_tid"]);
    assert_eq!(event["pid"], exit["pid"]);
    assert_eq!(u(&event["orig_rax"]), libc::SYS_execve as u64);
    assert_eq!(exit["orig_rax"], event["orig_rax"]);
    assert_eq!(u(&exit["rax"]), 0);
    assert_eq!(event["ip"], exit["ip"]);
    assert_eq!(event["sp"], exit["sp"]);
    let at_event = &event["syscall_info"];
    assert_eq!(u(&at_event["architecture"]), 0xc000_003e);
    assert_eq!(at_event["operation"], "none");
    assert_eq!(at_event["ip"], event["ip"]);
    assert_eq!(at_event["sp"], event["sp"]);
    assert!(u(&at_event["kernel_size"]) >= 24);
    u(&event["rax"]); // Retain the observed value before kernel exec completion.
    let info = &exit["syscall_info"];
    assert_eq!(u(&info["architecture"]), 0xc000_003e);
    assert_eq!(info["operation"], "exit");
    assert_eq!(info["return_value"], 0);
    assert_eq!(info["is_error"], false);
    assert_eq!(info["ip"], exit["ip"]);
    assert_eq!(info["sp"], exit["sp"]);
    assert!(u(&info["kernel_size"]) >= 33);
    assert_eq!(report["exec_return_drained"], true);
    assert_eq!(report["entry_ip"], exit["ip"]);
    assert_eq!(report["entry_sp"], exit["sp"]);
    assert_eq!(u(&report["entry_rax"]), 0);
}

#[test]
fn wrong_ready_token_is_refused_after_real_runtime_self_tests() {
    let scratch = Scratch::new("wrong-ready-token");
    let guest = compile(&scratch.0, "guest_static_marker", Some("guest_static.ld"));
    let actual = images();
    let checked = check_loader(&actual.loader_bytes).unwrap();
    let mut pattern = vec![0x48, 0xb8]; // movabs rax, imm64
    pattern.extend_from_slice(&READY_MAGIC.to_le_bytes());
    let mut locations = Vec::new();
    for segment in checked
        .segments()
        .filter(|segment| segment.permissions.execute)
    {
        let start = usize::try_from(segment.file.start).unwrap();
        let end = usize::try_from(segment.file.end).unwrap();
        for (offset, window) in actual.loader_bytes[start..end]
            .windows(pattern.len())
            .enumerate()
        {
            if window == pattern {
                locations.push(start.checked_add(offset).unwrap());
            }
        }
    }
    assert_eq!(
        locations.len(),
        1,
        "the actual RX ready-token load must be unique"
    );
    let immediate = locations[0].checked_add(2).unwrap();
    let wrong = READY_MAGIC ^ 1;
    let copied = scratch.0.join("loader-wrong-ready-token");
    fs::copy(&actual.loader, &copied).unwrap();
    assert_eq!(fs::read(&copied).unwrap(), actual.loader_bytes);
    let file = fs::OpenOptions::new().write(true).open(&copied).unwrap();
    file.write_all_at(&wrong.to_le_bytes(), immediate as u64)
        .unwrap();
    file.sync_all().unwrap();
    let bytes = fs::read(&copied).unwrap();
    let mut expected = actual.loader_bytes.clone();
    expected[immediate..immediate + 8].copy_from_slice(&wrong.to_le_bytes());
    assert_eq!(
        bytes, expected,
        "only the eight-byte token immediate may change"
    );
    check_loader(&bytes).expect("wrong token must still pass the real artifact checker");

    let observation = observe(scratch, &copied, &guest, &[]);
    let report = &observation.report;
    assert_eq!(observation.capture.status.code(), Some(122));
    assert_eq!(report["outcome"], "refused");
    assert_eq!(report["fault_requested"], "none");
    assert_eq!(
        report["refusal"],
        "loader refused: unauthenticated ready breakpoint"
    );
    assert_eq!(u(&report["ready_stop_ip"]), READY_STOP_IP);
    assert_eq!(u(&report["ready_rax"]), wrong);
    assert_exec_drain_facts(report);
    assert_ne!(report["detached"], true);
    assert!(report["guest_status"].is_null());
    assert!(report["guest_signal"].is_null());
    assert!(observation.capture.stdout.is_empty());
    assert!(array(&report["guest_events"]).is_empty());
    assert_refused_child_retired(report);
    assert_events(report);
    assert_eq!(
        u(&report["runtime"]["runtime_phase"]),
        PHASE_TEST_CONTROLS_READY as u64
    );
    let self_tests = array(&report["self_test_events"]);
    assert_eq!(self_tests.len(), 5);
    assert_eq!(
        self_tests
            .iter()
            .map(|event| u(&event["kind"]))
            .collect::<Vec<_>>(),
        [
            EVENT_CPUID as u64,
            EVENT_RDTSC as u64,
            EVENT_RDTSCP as u64,
            EVENT_SYSCALL_ENTER as u64,
            EVENT_SYSCALL_RETURN as u64,
        ]
    );
    assert_eq!(args(&self_tests[3]["args"], 6), [0; 6]);
    assert_eq!(args(&self_tests[4]["args"], 6), [0; 6]);
    assert_eq!(u(&report["runtime"]["events_committed"]), 5);
    let trace = array(&report["bootstrap_syscalls"]);
    assert!(!trace.is_empty());
    assert_eq!(trace.len() % 2, 0);
    let mut arms = 0;
    for pair in trace.as_chunks::<2>().0 {
        assert_eq!(pair[0]["phase"], "entry");
        assert_eq!(pair[1]["phase"], "exit");
        assert_eq!(pair[0]["number"], pair[1]["number"]);
        assert_eq!(pair[0]["effective_number"], pair[0]["number"]);
        assert_eq!(pair[1]["effective_number"], pair[1]["number"]);
        assert_gate(&pair[0], actual);
        if u(&pair[0]["number"]) == libc::SYS_seccomp as u64 {
            assert_eq!(u(&pair[0]["args"][0]), libc::SECCOMP_SET_MODE_FILTER as u64);
            assert_eq!(pair[1]["return_value"], 0);
            assert_eq!(pair[1]["is_error"], false);
            arms += 1;
        }
    }
    assert_eq!(
        arms, 1,
        "actual successful kernel filter arm precedes token refusal"
    );
}

const EXITKILL_HELPER_ENV: &str = "REVERIE_EXEC_STOP_EXITKILL_HELPER";
const EXITKILL_SCRATCH_ENV: &str = "REVERIE_EXEC_STOP_EXITKILL_SCRATCH";

struct ScopedSubreaper {
    previous: i32,
    active: bool,
}

impl ScopedSubreaper {
    fn new() -> Self {
        let mut previous = 0_i32;
        // SAFETY: the writable scalar remains live for this synchronous prctl.
        let result = unsafe {
            libc::prctl(
                libc::PR_GET_CHILD_SUBREAPER,
                &raw mut previous,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        assert_eq!(result, 0, "query helper subreaper flag");
        assert!(matches!(previous, 0 | 1));
        // SAFETY: this changes only the isolated helper process's flag.
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                1_usize,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        assert_eq!(result, 0, "enable scoped isolated-helper subreaper");
        Self {
            previous,
            active: true,
        }
    }

    fn restore(&mut self) {
        // SAFETY: this restores only this helper's previously queried flag.
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_CHILD_SUBREAPER,
                self.previous as usize,
                0_usize,
                0_usize,
                0_usize,
            )
        };
        assert_eq!(result, 0, "restore helper subreaper flag");
        self.active = false;
    }
}

impl Drop for ScopedSubreaper {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: failure cleanup changes only this isolated helper's flag.
            // It cannot turn failed evidence into a passing test.
            unsafe {
                libc::prctl(
                    libc::PR_SET_CHILD_SUBREAPER,
                    self.previous as usize,
                    0_usize,
                    0_usize,
                    0_usize,
                );
            }
        }
    }
}

fn open_pidfd(pid: u32) -> OwnedFd {
    assert!(pid > 0 && pid <= i32::MAX as u32);
    // SAFETY: pidfd_open has integer arguments and returns one new owned fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0_u32) };
    assert!(
        fd >= 0,
        "pidfd_open({pid}): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: the successful syscall transferred this unique fd to the caller.
    unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) }
}

fn signal_pidfd(fd: &OwnedFd, signal: i32) -> i64 {
    // SAFETY: the owned fd remains live; null siginfo requests the ordinary
    // signal. This targets one exact process generation, never a process group.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0_u32,
        )
    }
}

fn assert_pidfd_nonterminal(fd: &OwnedFd) {
    let mut request = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live initialized pollfd is supplied for a nonblocking query.
    let result = unsafe { libc::poll(&raw mut request, 1, 0) };
    assert_eq!(result, 0, "pidfd was terminal or observation failed");
    assert_eq!(request.revents, 0);
}

struct ExitkillChildren {
    probe: std::process::Child,
    probe_pidfd: OwnedFd,
    tracee_pidfd: Option<OwnedFd>,
    complete: bool,
    dir: PathBuf,
}

impl Drop for ExitkillChildren {
    fn drop(&mut self) {
        if self.complete {
            return;
        }
        // This path is cleanup only. A marker and failed helper status prevent
        // a fallback kill from being counted as EXITKILL evidence.
        let _ = fs::write(
            self.dir.join("exitkill-fallback-cleanup.txt"),
            b"FAILURE CLEANUP ONLY; NOT EXITKILL EVIDENCE\n",
        );
        let _ = self.probe.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.probe.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        if let Some(fd) = &self.tracee_pidfd {
            let _ = signal_pidfd(fd, libc::SIGKILL);
            // SAFETY: initialized output is passed with a live pidfd; WNOHANG
            // makes failure cleanup nonblocking. Its result is never evidence.
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            // SAFETY: the owned pidfd and initialized output remain live here.
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    fd.as_raw_fd() as libc::id_t,
                    &raw mut info,
                    libc::WEXITED | libc::WNOHANG,
                );
            }
        }
    }
}

fn proc_identity(pid: u32) -> (u32, u64, String) {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let end = text.rfind(')').expect("proc stat comm terminator");
    let fields: Vec<_> = text[end + 1..].split_whitespace().collect();
    assert!(fields.len() > 19);
    (
        fields[1].parse().unwrap(),
        fields[19].parse().unwrap(),
        fields[0].to_owned(),
    )
}

fn wait_pidfd_readable(fd: &OwnedFd, deadline: Instant) {
    loop {
        assert!(
            Instant::now() < deadline,
            "EXITKILL child did not become terminal"
        );
        let mut request = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live initialized pollfd is supplied; each wait is 10 ms
        // and the enclosing deadline is checked on every iteration.
        let result = unsafe { libc::poll(&raw mut request, 1, 10) };
        if result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        assert!(
            result >= 0,
            "poll pidfd: {}",
            std::io::Error::last_os_error()
        );
        if result == 0 {
            continue;
        }
        assert_eq!(result, 1);
        assert_ne!(request.revents & libc::POLLIN, 0);
        assert_eq!(request.revents & (libc::POLLNVAL | libc::POLLERR), 0);
        return;
    }
}

fn pidfd_sigkill_wait(fd: &OwnedFd, expected_pid: u32, nowait: bool) -> Value {
    // SAFETY: zeroed siginfo_t is valid writable output storage. The live
    // pidfd names this helper's adopted child; WNOHANG forbids blocking here.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    let flags = libc::WEXITED | libc::WNOHANG | if nowait { libc::WNOWAIT } else { 0 };
    // SAFETY: output storage and pidfd stay live for this synchronous waitid.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            fd.as_raw_fd() as libc::id_t,
            &raw mut info,
            flags,
        )
    };
    assert_eq!(
        result,
        0,
        "pidfd waitid: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(info.si_signo, libc::SIGCHLD);
    assert_eq!(info.si_code, libc::CLD_KILLED);
    assert_eq!(info.si_errno, 0);
    // SAFETY: successful waitid supplied the SIGCHLD/CLD_KILLED union payload.
    let (pid, signal) = unsafe { (info.si_pid(), info.si_status()) };
    assert_eq!(pid, expected_pid as libc::pid_t);
    assert_eq!(signal, libc::SIGKILL);
    json!({"pid":pid,"si_signo":info.si_signo,"si_code":info.si_code,
           "si_status":signal,"flags":flags,"via":"waitid_P_PIDFD"})
}

fn exitkill_helper(dir: &Path) {
    let actual = images();
    let guest = compile(dir, "guest_static_marker", Some("guest_static.ld"));
    let mut subreaper = ScopedSubreaper::new();
    let checkpoint_path = dir.join("exec-drain-checkpoint.json");
    assert!(!checkpoint_path.exists());
    let report_path = dir.join("probe-report.json");
    assert!(!report_path.exists());
    let mut command = Command::new(PROBE);
    command
        .arg("--pause-after-exec-drain")
        .arg(&checkpoint_path)
        .arg(&actual.loader)
        .arg(&actual.runtime)
        .arg(&report_path)
        .arg("--")
        .arg(&guest)
        .stdin(Stdio::null())
        .stdout(File::create(dir.join("probe.stdout")).unwrap())
        .stderr(File::create(dir.join("probe.stderr")).unwrap());
    fs::write(dir.join("probe.argv.txt"), format!("{command:?}\n")).unwrap();
    let probe = command.spawn().expect("spawn checkpoint probe");
    let probe_pid = probe.id();
    let probe_pidfd = open_pidfd(probe_pid);
    let mut children = ExitkillChildren {
        probe,
        probe_pidfd,
        tracee_pidfd: None,
        complete: false,
        dir: dir.to_owned(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while !checkpoint_path.exists() {
        assert!(Instant::now() < deadline, "exec-drain checkpoint deadline");
        assert!(
            children.probe.try_wait().unwrap().is_none(),
            "probe exited before checkpoint"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(fs::metadata(&checkpoint_path).unwrap().len() <= CAPTURE_LIMIT);
    let checkpoint: Value = serde_json::from_slice(&fs::read(&checkpoint_path).unwrap()).unwrap();
    assert_eq!(
        checkpoint["schema"],
        "reverie_loader_exec_stop_checkpoint_v1"
    );
    assert_eq!(checkpoint["mode"], "pause_after_exec_drain");
    let child_pid = u32::try_from(u(&checkpoint["child_pid"])).unwrap();
    assert_ne!(child_pid, 0);
    assert_ne!(child_pid, probe_pid);
    assert_eq!(u(&checkpoint["tracer_pid"]), probe_pid as u64);
    assert_eq!(u(&checkpoint["exec_event"]["pid"]), child_pid as u64);
    assert_exec_drain_facts(&checkpoint);
    for field in [
        "pdeathsig_checked",
        "tracee_held_stopped",
        "entry_bytes_restored",
        "registers_restored",
        "sigmask_restored",
        "xstate_restored",
    ] {
        assert_eq!(checkpoint[field], true, "missing checkpoint fact {field}");
    }
    assert_eq!(checkpoint["pdeathsig"], 0);
    assert_eq!(checkpoint["controls_armed"], false);
    assert_eq!(checkpoint["detached"], false);
    let slot = &checkpoint["stack_slot"];
    assert_eq!(slot["address"], checkpoint["entry_sp"]);
    assert_eq!(args(&slot["before"], 8).len(), 8);
    assert_eq!(slot["restored"], slot["before"]);
    assert_eq!(
        args(&slot["observed"], 8),
        [0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5]
    );
    let injected = array(&checkpoint["pdeathsig_injected_syscalls"]);
    assert_eq!(injected.len(), 2);
    assert_eq!(u(&injected[0]["number"]), libc::SYS_prctl as u64);
    assert_eq!(u(&injected[1]["number"]), libc::SYS_prctl as u64);
    assert_eq!(
        args(&injected[0]["args"], 6),
        [libc::PR_SET_PDEATHSIG as u64, 0, 0, 0, 0, 0]
    );
    assert_eq!(
        args(&injected[1]["args"], 6),
        [
            libc::PR_GET_PDEATHSIG as u64,
            u(&checkpoint["entry_sp"]),
            0,
            0,
            0,
            0
        ]
    );
    assert_eq!(injected[0]["result"], 0);
    assert_eq!(injected[1]["result"], 0);
    children.tracee_pidfd = Some(open_pidfd(child_pid));
    let (parent_pid, starttime, state) = proc_identity(child_pid);
    assert_eq!(parent_pid, probe_pid);
    assert_eq!(starttime, u(&checkpoint["child_starttime_ticks"]));
    assert_eq!(
        state, "t",
        "child must still be ptrace-stopped at the checkpoint"
    );
    let status = fs::read_to_string(format!("/proc/{child_pid}/status")).unwrap();
    let tracer: u32 = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("TracerPid:")
                .map(|value| value.trim().parse().unwrap())
        })
        .expect("TracerPid");
    assert_eq!(tracer, probe_pid);
    assert!(children.probe.try_wait().unwrap().is_none());
    assert_pidfd_nonterminal(&children.probe_pidfd);
    assert_pidfd_nonterminal(children.tracee_pidfd.as_ref().unwrap());
    fs::write(
        dir.join("before-probe-death.json"),
        serde_json::to_vec_pretty(&json!({
            "probe_pid":probe_pid,"child_pid":child_pid,"child_starttime_ticks":starttime,
            "probe_pidfd_nonterminal":true,"child_pidfd_nonterminal":true,
            "pdeathsig":0,"tracee_held_stopped":true,"fallback_cleanup_used":false,
        }))
        .unwrap(),
    )
    .unwrap();
    // The only intentional kill on the success path targets the tracer pidfd.
    // In particular, there is no process-group kill or child-directed signal.
    assert_eq!(signal_pidfd(&children.probe_pidfd, libc::SIGKILL), 0);
    let probe_status = loop {
        assert!(
            Instant::now() < deadline,
            "probe did not terminate after SIGKILL"
        );
        if let Some(status) = children.probe.try_wait().unwrap() {
            break status;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(probe_status.signal(), Some(libc::SIGKILL));
    let child_fd = children.tracee_pidfd.as_ref().unwrap();
    wait_pidfd_readable(child_fd, deadline);
    let terminal = pidfd_sigkill_wait(child_fd, child_pid, true);
    let reaped = pidfd_sigkill_wait(child_fd, child_pid, false);
    // SAFETY: initialized output is supplied with the same still-owned pidfd.
    // The previous consuming wait must leave no child to reap by this handle.
    let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
    // SAFETY: the owned pidfd and initialized output remain live for waitid.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            child_fd.as_raw_fd() as libc::id_t,
            &raw mut info,
            libc::WEXITED | libc::WNOHANG,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(
        !report_path.exists(),
        "killed checkpoint probe cannot publish a handoff report"
    );
    assert_eq!(fs::metadata(dir.join("probe.stdout")).unwrap().len(), 0);
    assert!(!dir.join("exitkill-fallback-cleanup.txt").exists());
    subreaper.restore();
    fs::write(
        dir.join("exitkill-evidence.json"),
        serde_json::to_vec_pretty(&json!({
            "probe_pid":probe_pid,"probe_signal":libc::SIGKILL,
            "child_pid":child_pid,"child_starttime_ticks":starttime,
            "pdeathsig":0,"probe_pidfd_nonterminal_before_kill":true,
            "child_pidfd_nonterminal_before_kill":true,
            "only_intentional_kill_target":"probe_pidfd",
            "terminal":terminal,"reaped":reaped,"post_reap_errno":libc::ECHILD,
            "subreaper_previous":subreaper.previous,"subreaper_restored":true,
            "fallback_cleanup_used":false,"detached":false,"guest_stdout_bytes":0,
        }))
        .unwrap(),
    )
    .unwrap();
    children.complete = true;
}

#[test]
fn exitkill_kills_and_reaps_the_stopped_child_when_only_the_probe_dies() {
    if std::env::var_os(EXITKILL_HELPER_ENV).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let dir = PathBuf::from(std::env::var_os(EXITKILL_SCRATCH_ENV).expect("helper scratch"));
        exitkill_helper(&dir);
        return;
    }
    let scratch = Scratch::new("exitkill");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg("exitkill_kills_and_reaps_the_stopped_child_when_only_the_probe_dies")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(EXITKILL_HELPER_ENV, "1")
        .env(EXITKILL_SCRATCH_ENV, &scratch.0);
    let capture = retained_command(
        &mut command,
        &scratch.0,
        "exitkill-helper",
        Duration::from_secs(60),
    );
    assert!(
        capture.status.success(),
        "isolated helper failed: {}",
        String::from_utf8_lossy(&capture.stderr)
    );
    assert!(!scratch.0.join("exitkill-fallback-cleanup.txt").exists());
    let evidence: Value =
        serde_json::from_slice(&fs::read(scratch.0.join("exitkill-evidence.json")).unwrap())
            .unwrap();
    assert_eq!(evidence["fallback_cleanup_used"], false);
    assert_eq!(evidence["only_intentional_kill_target"], "probe_pidfd");
    assert_eq!(evidence["subreaper_restored"], true);
    assert_eq!(evidence["pdeathsig"], 0);
    assert_eq!(evidence["probe_signal"], libc::SIGKILL);
    assert_eq!(evidence["terminal"]["si_code"], libc::CLD_KILLED);
    assert_eq!(evidence["terminal"]["si_status"], libc::SIGKILL);
    assert_eq!(evidence["reaped"]["si_code"], libc::CLD_KILLED);
    assert_eq!(evidence["reaped"]["si_status"], libc::SIGKILL);
    assert_eq!(evidence["post_reap_errno"], libc::ECHILD);
    assert_eq!(evidence["detached"], false);
    assert_eq!(evidence["guest_stdout_bytes"], 0);
}
