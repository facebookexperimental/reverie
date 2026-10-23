/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Read-only task queries can name live tasks outside the DBT client.

use std::io::Read;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

use reverie_dbt::DbtRunner;

struct HeldChild(Child);

impl Drop for HeldChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().expect("reap held ordinary child");
    }
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn original_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("original");
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn tail_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("tail");
}

#[test]
#[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
fn returning_group_queries_reach_a_live_unregistered_process() {
    compare_with_linux("returning");
}

fn raw_priority(which: libc::c_long, who: libc::c_long) -> i64 {
    // syscall returns the kernel's 20-minus-nice value, not libc getpriority's
    // converted nice value. Normalize only the syscall wrapper's errno case.
    let result = unsafe { libc::syscall(libc::SYS_getpriority, which, who) };
    if result == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    }
}

const PARAMETER_SENTINEL: u32 = 0x1357_9bdf;

fn raw_parameter(target: libc::c_long, pointer_kind: usize) -> (i64, u32) {
    assert_eq!(std::mem::size_of::<libc::sched_param>(), 4);
    let mut output = [0x2468_ace0_u32, PARAMETER_SENTINEL, 0xfdb9_7531];
    let address = match pointer_kind {
        0 => &mut output[1] as *mut u32,
        1 => std::ptr::null_mut(),
        2 => std::ptr::without_provenance_mut::<u32>(1),
        _ => unreachable!(),
    };
    // The output is independent of every fixture and returning-injection buffer.
    // NULL and address 1 remain literal Linux error controls.
    let result = unsafe { libc::syscall(libc::SYS_sched_getparam, target, address) };
    let result = if result == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    };
    assert_eq!(output[0], 0x2468_ace0);
    assert_eq!(output[2], 0xfdb9_7531);
    (result, output[1])
}

const AFFINITY_CAPACITY: usize = 128;

fn affinity_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|&byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}

fn raw_affinity(
    target: libc::c_long,
    length: usize,
    pointer_kind: usize,
) -> (i64, [u8; AFFINITY_CAPACITY]) {
    let mut output = [0x7f_u8; AFFINITY_CAPACITY + 16];
    output[..8].fill(0xa5);
    output[AFFINITY_CAPACITY + 8..].fill(0x5a);
    let address = match pointer_kind {
        0 => output.as_mut_ptr().wrapping_add(8),
        1 => std::ptr::null_mut(),
        2 => std::ptr::without_provenance_mut::<u8>(1),
        _ => unreachable!(),
    };
    // Keep the raw byte-count return; libc sched_getaffinity would normalize
    // success to zero. This storage never aliases any guest/Tool output.
    let result = unsafe { libc::syscall(libc::SYS_sched_getaffinity, target, length, address) };
    let result = if result == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    };
    assert_eq!(&output[..8], &[0xa5; 8]);
    assert_eq!(&output[AFFINITY_CAPACITY + 8..], &[0x5a; 8]);
    (result, output[8..AFFINITY_CAPACITY + 8].try_into().unwrap())
}

const ROBUST_HEAD_SENTINEL: u64 = 0x1357_9bdf_1357_9bdf;
const ROBUST_LENGTH_SENTINEL: u64 = 0xfedc_ba98_7654_3210;
const ROBUST_BEFORE: u64 = 0x2468_ace0_2468_ace0;
const ROBUST_AFTER: u64 = 0xfdb9_7531_fdb9_7531;
const ROBUST_BAD_HEAD: [bool; 7] = [false, false, false, true, false, false, true];
const ROBUST_BAD_LENGTH: [bool; 7] = [false, false, false, false, true, false, true];
const ROBUST_LABELS: [&str; 7] = [
    "zero",
    "self",
    "live",
    "live-bad-head",
    "live-bad-length",
    "absent",
    "absent-bad-both",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RobustObservation {
    raw: i64,
    head: u64,
    length: u64,
}

fn raw_robust(target: libc::c_long, bad_head: bool, bad_length: bool) -> RobustObservation {
    let mut head = [ROBUST_BEFORE, ROBUST_HEAD_SENTINEL, ROBUST_AFTER];
    let mut length = [ROBUST_BEFORE, ROBUST_LENGTH_SENTINEL, ROBUST_AFTER];
    let head_address = if bad_head {
        std::ptr::without_provenance_mut::<u64>(1)
    } else {
        &mut head[1]
    };
    let length_address = if bad_length {
        std::ptr::without_provenance_mut::<u64>(1)
    } else {
        &mut length[1]
    };
    // The returned head is an opaque address in the target. Neither it nor
    // address1 is dereferenced here. Preserve both outputs even on EFAULT.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_get_robust_list,
            target,
            head_address,
            length_address,
        )
    };
    let raw = if raw == -1 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        raw
    };
    assert_eq!(head[0], ROBUST_BEFORE);
    assert_eq!(head[2], ROBUST_AFTER);
    assert_eq!(length[0], ROBUST_BEFORE);
    assert_eq!(length[2], ROBUST_AFTER);
    RobustObservation {
        raw,
        head: head[1],
        length: length[1],
    }
}

fn observation_field<'a>(fields: &[&'a str], key: &str) -> &'a str {
    fields
        .iter()
        .find_map(|field| field.strip_prefix(key))
        .expect(key)
}

struct RobustFixtureObservation {
    pid: i64,
    tid: i64,
    context: Vec<String>,
    rows: Vec<RobustObservation>,
}

fn robust_fixture_observation(
    output: &Output,
    held: i64,
    absent: i64,
    expected: &[RobustObservation],
) -> RobustFixtureObservation {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let contexts: Vec<_> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("robust-context "))
        .collect();
    assert_eq!(
        contexts.len(),
        1,
        "missing actual caller context: {output:?}"
    );
    let fields: Vec<_> = contexts[0].split_whitespace().collect();
    assert_eq!(fields.len(), 8);
    let pid: i64 = observation_field(&fields, "pid=").parse().unwrap();
    let tid: i64 = observation_field(&fields, "tid=").parse().unwrap();
    assert!(pid > 0 && pid != held);
    assert_eq!(tid, pid, "the fixture must query its actual main task");
    let targets = [0, pid, held, held, held, absent, absent];
    let raw_rows: Vec<_> = stderr
        .lines()
        .filter_map(|line| line.strip_prefix("robust-raw "))
        .collect();
    assert_eq!(
        raw_rows.len(),
        7,
        "missing complete robust outcomes: {output:?}"
    );
    let mut rows = Vec::new();
    for (index, row) in raw_rows.iter().enumerate() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 10, "malformed robust observation: {row}");
        assert_eq!(fields[0], format!("index={index}"));
        assert_eq!(fields[1], format!("target={}", targets[index]));
        let rc: i64 = observation_field(&fields, "rc=").parse().unwrap();
        let error: i64 = observation_field(&fields, "errno=").parse().unwrap();
        let raw = if rc == -1 {
            -error
        } else {
            assert_eq!(error, 0);
            rc
        };
        let head = u64::from_str_radix(observation_field(&fields, "head="), 16).unwrap();
        let length = u64::from_str_radix(observation_field(&fields, "length="), 16).unwrap();
        assert_eq!(raw, expected[index].raw, "robust result: {row}");
        assert_eq!(
            length, expected[index].length,
            "robust length output: {row}"
        );
        if index >= 2 {
            assert_eq!(
                head, expected[index].head,
                "same held lifetime/error output: {row}"
            );
        }
        for (key, value) in [
            ("head_before=", ROBUST_BEFORE),
            ("head_after=", ROBUST_AFTER),
            ("length_before=", ROBUST_BEFORE),
            ("length_after=", ROBUST_AFTER),
        ] {
            assert_eq!(observation_field(&fields, key), format!("{value:016x}"));
        }
        rows.push(RobustObservation { raw, head, length });
    }
    // No cross-process self pointer constant: NULL is legal, but both queries
    // of this same task/image must succeed and return the exact same words.
    assert_eq!(rows[0].raw, 0);
    assert_eq!(rows[0], rows[1]);
    RobustFixtureObservation {
        pid,
        tid,
        context: fields[2..]
            .iter()
            .map(|field| (*field).to_owned())
            .collect(),
        rows,
    }
}

fn compare_with_linux(mode: &str) {
    let directory = tempfile::tempdir().expect("fixture tempdir");
    let fixture = directory.path().join("group-session-getters");
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/group_session_getters.c");
    let status = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&fixture)
        .status()
        .expect("compile group/session getter fixture");
    assert!(status.success(), "fixture compilation failed");

    // This is the test parent's ordinary child, never instrumented or entered
    // in the DBT client's membership. EOF is withheld until all queries finish.
    // Its separate group, session and policy make target-to-self substitutions observable.
    let mut holder = Command::new("/bin/cat");
    holder
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: setsid and the raw scheduler syscall are async-signal-safe; the child
    // calls no Rust code that
    // allocates or acquires locks between fork and exec.
    unsafe {
        holder.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let parameter = libc::sched_param { sched_priority: 0 };
            if libc::syscall(
                libc::SYS_sched_setscheduler,
                0,
                libc::SCHED_BATCH,
                &parameter,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = HeldChild(holder.spawn().expect("hold ordinary unregistered child"));
    // An exact echo proves cat has completed libc startup before its robust
    // registration is sampled. Keep stdin open; no timing sleep or retry.
    child
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"R")
        .expect("cat readiness write");
    let mut ready = [0_u8; 1];
    child
        .0
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut ready)
        .expect("cat readiness echo");
    assert_eq!(ready, *b"R");
    let pid = child.0.id() as libc::pid_t;
    // SAFETY: these read-only queries name our live child.
    let pgid = unsafe { libc::getpgid(pid) };
    let sid = unsafe { libc::getsid(pid) };
    let policy = unsafe { libc::sched_getscheduler(pid) };
    assert_eq!(pgid, pid, "held child must lead its own group");
    assert_eq!(sid, pid, "held child must lead its own session");
    assert_eq!(policy, libc::SCHED_BATCH, "held child must use SCHED_BATCH");
    let process = libc::PRIO_PROCESS as libc::c_long;
    let own_pid = unsafe { libc::getpid() } as libc::c_long;
    let priority_cases = [
        (process, 0),
        (process, own_pid),
        (process, i64::from(pid)),
        (process, i64::from(i32::MAX)),
        (process, -1),
        (-1, 0),
        (3, i64::from(pid)),
        (999, i64::from(i32::MAX)),
    ];
    let priority_values: Vec<_> = priority_cases
        .iter()
        .map(|&(which, who)| raw_priority(which, who))
        .collect();
    assert!((1..=40).contains(&priority_values[0]));
    assert_eq!(priority_values[1], priority_values[0]);
    assert!((1..=40).contains(&priority_values[2]));
    assert_eq!(
        &priority_values[3..],
        &[
            -i64::from(libc::ESRCH),
            -i64::from(libc::ESRCH),
            -i64::from(libc::EINVAL),
            -i64::from(libc::EINVAL),
            -i64::from(libc::EINVAL),
        ],
        "native target/selector controls changed"
    );
    // nice19 can make self and target equal. Do not require value-based target
    // discrimination: the live target and exact raw arguments are the witness.
    let parameter_targets = [0, own_pid, i64::from(pid), i64::from(i32::MAX), -1, 0, 0];
    let pointer_kinds = [0, 0, 0, 0, 0, 1, 2];
    let parameter_values: Vec<_> = parameter_targets
        .iter()
        .zip(pointer_kinds)
        .map(|(&target, pointer_kind)| raw_parameter(target, pointer_kind))
        .collect();
    assert_eq!(
        parameter_values[2],
        (0, 0),
        "held SCHED_BATCH target must write all four bytes"
    );
    let affinity_targets = [
        0,
        own_pid,
        i64::from(pid),
        i64::from(i32::MAX),
        -1,
        0,
        0,
        0,
        0,
    ];
    let affinity_lengths = [
        AFFINITY_CAPACITY,
        AFFINITY_CAPACITY,
        AFFINITY_CAPACITY,
        AFFINITY_CAPACITY,
        AFFINITY_CAPACITY,
        0,
        1,
        AFFINITY_CAPACITY,
        AFFINITY_CAPACITY,
    ];
    let affinity_pointers = [0, 0, 0, 0, 0, 0, 0, 1, 2];
    let affinity_values: Vec<_> = affinity_targets
        .iter()
        .zip(affinity_lengths)
        .zip(affinity_pointers)
        .map(|((&target, length), pointer)| raw_affinity(target, length, pointer))
        .collect();
    for &(result, bytes) in &affinity_values[..3] {
        assert!(
            result > 0 && result as usize <= AFFINITY_CAPACITY,
            "native affinity setup requires a successful bounded buffer, got {result}"
        );
        assert!(
            bytes[..result as usize].iter().any(|&byte| byte != 0),
            "native allowed mask must be nonempty"
        );
        assert!(
            bytes[result as usize..].iter().all(|&byte| byte == 0x7f),
            "native unwritten suffix changed"
        );
    }
    let own_tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let pid_max_text = std::fs::read_to_string("/proc/sys/kernel/pid_max").expect("read pid_max");
    let pid_max: i64 = pid_max_text.trim().parse().expect("numeric pid_max");
    let absent = pid_max
        .checked_add(1)
        .filter(|&pid| pid <= i64::from(i32::MAX))
        .expect("an unavailable positive PID above measured pid_max");
    let robust_targets = [
        0,
        own_tid,
        i64::from(pid),
        i64::from(pid),
        i64::from(pid),
        absent,
        absent,
    ];
    let robust_values: Vec<_> = robust_targets
        .iter()
        .enumerate()
        .map(|(index, &target)| {
            raw_robust(target, ROBUST_BAD_HEAD[index], ROBUST_BAD_LENGTH[index])
        })
        .collect();
    assert_eq!(
        robust_values[0].raw, 0,
        "native caller robust query prerequisite"
    );
    assert_eq!(robust_values[0], robust_values[1]);
    assert_eq!(
        robust_values[2].raw, 0,
        "test-parent held-target permission prerequisite"
    );
    assert_eq!(
        robust_values[5].raw,
        -i64::from(libc::ESRCH),
        "pid_max absence proof"
    );
    let held_namespaces: Vec<_> = ["pid", "user"]
        .iter()
        .map(|name| {
            let metadata =
                std::fs::metadata(format!("/proc/{pid}/ns/{name}")).expect("held namespace");
            format!("{name}ns={}:{}", metadata.dev(), metadata.ino())
        })
        .collect();
    assert!(
        child
            .0
            .try_wait()
            .expect("held target before fixtures")
            .is_none()
    );
    eprintln!(
        "{mode} robust prerequisite: target={pid} pid_max={pid_max} absent={absent} namespaces={held_namespaces:?} native={robust_values:?}"
    );
    let mut arguments = vec![
        pid.to_string(),
        pgid.to_string(),
        sid.to_string(),
        policy.to_string(),
        priority_values[2].to_string(),
        priority_values[0].to_string(),
    ];
    for &(result, bytes) in &parameter_values {
        arguments.push(result.to_string());
        arguments.push(format!("{bytes:08x}"));
    }
    for (result, bytes) in &affinity_values {
        arguments.push(result.to_string());
        arguments.push(affinity_hex(bytes));
    }
    arguments.push(absent.to_string());
    for value in &robust_values {
        arguments.push(value.raw.to_string());
        arguments.push(format!("{:016x}", value.head));
        arguments.push(format!("{:016x}", value.length));
    }
    let mut expected = format!(
        "getpgid live={pgid} errno=0\ngetpgid zero-is-self=1\n\
         getpgid negative rc=-1 errno={}\ngetpgid absent rc=-1 errno={}\n\
         getsid live={sid} errno=0\ngetsid zero-is-self=1\n\
         getsid negative rc=-1 errno={}\ngetsid absent rc=-1 errno={}\n\
         sched_getscheduler live={policy} errno=0\nsched_getscheduler zero-is-self=1\n\
         sched_getscheduler negative rc=-1 errno={}\n\
         sched_getscheduler absent rc=-1 errno={}\n",
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
        libc::ESRCH,
        libc::EINVAL,
        libc::ESRCH,
    );
    let priority_labels = [
        "zero",
        "self",
        "live",
        "absent",
        "negative",
        "invalid-negative-zero",
        "invalid-three-live",
        "invalid-999-absent",
    ];
    for (label, &value) in priority_labels.iter().zip(&priority_values) {
        let (rc, error) = if value < 0 { (-1, -value) } else { (value, 0) };
        expected.push_str(&format!("getpriority {label} rc={rc} errno={error}\n"));
    }
    let parameter_labels = ["zero", "self", "live", "absent", "negative", "null", "bad"];
    for (label, &(value, bytes)) in parameter_labels.iter().zip(&parameter_values) {
        let (rc, error) = if value < 0 { (-1, -value) } else { (value, 0) };
        expected.push_str(&format!(
            "sched_getparam {label} rc={rc} errno={error} bytes={bytes:08x} canaries=1\n"
        ));
    }
    let affinity_labels = [
        "zero",
        "self",
        "live",
        "absent",
        "negative",
        "zero-size",
        "one-byte",
        "null",
        "bad",
    ];
    for (index, (label, (value, bytes))) in affinity_labels.iter().zip(&affinity_values).enumerate()
    {
        let (rc, error) = if *value < 0 {
            (-1, -*value)
        } else {
            (*value, 0)
        };
        expected.push_str(&format!(
            "sched_getaffinity {label} len={} rc={rc} errno={error} mask={} canaries=1\n",
            affinity_lengths[index],
            affinity_hex(bytes)
        ));
    }
    for (index, (label, value)) in ROBUST_LABELS.iter().zip(&robust_values).enumerate() {
        let (rc, error) = if value.raw < 0 {
            (-1, -value.raw)
        } else {
            (value.raw, 0)
        };
        let head = if index < 2 {
            "same-image-self".to_owned()
        } else {
            format!("{:016x}", value.head)
        };
        expected.push_str(&format!(
            "get_robust_list {label} rc={rc} errno={error} head={head} length={:016x} canaries=1\n",
            value.length,
        ));
    }
    expected.push_str("group-session-getters=ok\n");
    let native = Command::new(&fixture)
        .arg("original")
        .args(&arguments)
        .output()
        .expect("run Linux oracle");
    eprintln!("{mode} native: {native:?}");
    assert!(native.status.success(), "native oracle failed: {native:?}");
    assert_eq!(native.stdout, expected.as_bytes());
    let native_robust = robust_fixture_observation(&native, i64::from(pid), absent, &robust_values);
    assert_eq!(&native_robust.context[4..], held_namespaces);

    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must be set")
        .client_argument("-test-wait-for-background");
    let mut guest = Command::new(&fixture);
    guest
        .arg(mode)
        .args(&arguments)
        .env_remove(reverie_dbt::TOOL_ENV);
    // The named registry selector takes precedence over the legacy selectors.
    // Select exactly the route whose native injection contract this test checks.
    for selector in [
        "HERMIT_DBT_TEST_REWRITE_EXIT",
        "HERMIT_DBT_TEST_INJECT_INVALID_CLONE",
        "HERMIT_DBT_TEST_SET_REG",
        "HERMIT_DBT_TEST_COMPARE_EXCHANGE",
        "HERMIT_DBT_TEST_PPID",
        "HERMIT_DBT_TEST_BACKTRACE",
        "HERMIT_DBT_STRACE",
        "HERMIT_DBT_SYSCALL_HISTOGRAM",
        "HERMIT_DBT_COUNTER1",
        "HERMIT_DBT_COUNTER2",
        "HERMIT_DBT_CHUNKY_PRINT",
        "HERMIT_DBT_CHROME_TRACE",
        "HERMIT_DBT_CHAOS",
        "HERMIT_DBT_NOOP",
        "HERMIT_DBT_COUNTER1_EXACT",
        "HERMIT_DBT_COUNTER2_EXACT",
    ] {
        guest.env_remove(selector);
    }
    match mode {
        "tail" => {
            guest.env("HERMIT_DBT_NOOP", "1");
        }
        "returning" => {
            guest.env("HERMIT_DBT_TEST_SET_REG", "1");
        }
        "original" => {}
        _ => unreachable!(),
    }
    let output = runner.output(&guest).expect("run DBT getter fixture");
    assert!(
        child.0.try_wait().expect("inspect held child").is_none(),
        "the independent target must stay live through every query"
    );
    eprintln!("{mode}: {output:?}");
    assert_eq!(
        raw_robust(i64::from(pid), false, false),
        robust_values[2],
        "held target's exact registration/lifetime changed during comparison"
    );
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/pid_max").unwrap(),
        pid_max_text
    );
    assert_eq!(raw_robust(absent, false, false), robust_values[5]);
    assert!(output.status.success(), "{mode} fixture failed: {output:?}");
    assert_eq!(output.stdout, native.stdout, "{mode} differs from Linux");
    let guest_robust = robust_fixture_observation(&output, i64::from(pid), absent, &robust_values);
    assert_eq!(guest_robust.context, native_robust.context);
    eprintln!(
        "{mode} robust permission scope: namespace/credential equality is supporting evidence only; returning has an exact-caller raw kernel witness, original/tail have the separately executed native oracle and no same-caller permission proof"
    );
    if mode == "returning" {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-group-query "))
            .collect();
        assert_eq!(rows.len(), 15, "missing returning observations: {output:?}");
        for row in rows {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 4, "malformed kernel observation: {row}");
            let kernel = fields[2].strip_prefix("kernel=").unwrap();
            let injected = fields[3].strip_prefix("injected=").unwrap();
            assert_eq!(injected, kernel, "native membership altered a query: {row}");
        }
        let identity_prefix = format!(
            "reverie-dbt-test: kernel-identity sysnum={} ",
            libc::SYS_getpid
        );
        let identities: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix(&identity_prefix))
            .collect();
        assert_eq!(identities.len(), 1, "missing own-PID witness: {output:?}");
        let guest_pid: i64 = identities[0]
            .split_whitespace()
            .find_map(|field| field.strip_prefix("kernel="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(guest_pid > 0 && guest_pid != i64::from(pid));
        assert_eq!(guest_robust.pid, guest_pid);
        let mut guest_cases = priority_cases;
        guest_cases[1].1 = guest_pid;
        let priority_rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-priority-query "))
            .collect();
        assert_eq!(
            priority_rows.len(),
            8,
            "missing priority observations: {output:?}"
        );
        for (index, row) in priority_rows.iter().enumerate() {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 5, "malformed priority observation: {row}");
            assert_eq!(fields[0], format!("sysnum={}", libc::SYS_getpriority));
            assert_eq!(fields[1], format!("which={}", guest_cases[index].0));
            assert_eq!(fields[2], format!("who={}", guest_cases[index].1));
            assert_eq!(fields[3], format!("kernel={}", priority_values[index]));
            assert_eq!(fields[4], format!("injected={}", priority_values[index]));
        }
        let mut guest_parameter_targets = parameter_targets;
        guest_parameter_targets[1] = guest_pid;
        let parameter_rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-parameter-query "))
            .collect();
        assert_eq!(
            parameter_rows.len(),
            7,
            "missing parameter observations: {output:?}"
        );
        for (index, row) in parameter_rows.iter().enumerate() {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 9, "malformed parameter observation: {row}");
            let pointer = match pointer_kinds[index] {
                0 => "valid",
                1 => "null",
                2 => "bad",
                _ => unreachable!(),
            };
            let (result, bytes) = parameter_values[index];
            let (before, after) = if pointer_kinds[index] == 0 {
                (format!("{PARAMETER_SENTINEL:08x}"), format!("{bytes:08x}"))
            } else {
                ("unaddressed".to_owned(), "unaddressed".to_owned())
            };
            assert_eq!(fields[0], format!("sysnum={}", libc::SYS_sched_getparam));
            assert_eq!(
                fields[1],
                format!("target={}", guest_parameter_targets[index])
            );
            assert_eq!(fields[2], format!("pointer={pointer}"));
            assert_eq!(fields[3], format!("kernel={result}"));
            assert_eq!(fields[4], format!("injected={result}"));
            assert_eq!(fields[5], format!("kernel_bytes={bytes:08x}"));
            assert_eq!(fields[6], format!("guest_before={before}"));
            assert_eq!(fields[7], format!("guest_after={after}"));
            assert_eq!(fields[8], "kernel_canaries=1");
        }
        let mut guest_affinity_targets = affinity_targets;
        guest_affinity_targets[1] = guest_pid;
        let affinity_rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-affinity-query "))
            .collect();
        assert_eq!(
            affinity_rows.len(),
            9,
            "missing affinity observations: {output:?}"
        );
        for (index, row) in affinity_rows.iter().enumerate() {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 10, "malformed affinity observation: {row}");
            let pointer = match affinity_pointers[index] {
                0 => "valid",
                1 => "null",
                2 => "bad",
                _ => unreachable!(),
            };
            let (result, bytes) = &affinity_values[index];
            let (before, after) = if affinity_pointers[index] == 0 {
                (
                    affinity_hex(&[0x7f; AFFINITY_CAPACITY]),
                    affinity_hex(bytes),
                )
            } else {
                ("unaddressed".to_owned(), "unaddressed".to_owned())
            };
            assert_eq!(fields[0], format!("sysnum={}", libc::SYS_sched_getaffinity));
            assert_eq!(
                fields[1],
                format!("target={}", guest_affinity_targets[index])
            );
            assert_eq!(fields[2], format!("len={}", affinity_lengths[index]));
            assert_eq!(fields[3], format!("pointer={pointer}"));
            assert_eq!(fields[4], format!("kernel={result}"));
            assert_eq!(fields[5], format!("injected={result}"));
            assert_eq!(fields[6], format!("kernel_mask={}", affinity_hex(bytes)));
            assert_eq!(fields[7], format!("guest_before={before}"));
            assert_eq!(fields[8], format!("guest_after={after}"));
            assert_eq!(fields[9], "kernel_canaries=1");
        }
        let robust_rows: Vec<_> = stderr
            .lines()
            .filter_map(|line| line.strip_prefix("reverie-dbt-test: kernel-robust-query "))
            .collect();
        assert_eq!(
            robust_rows.len(),
            7,
            "missing robust observations: {output:?}"
        );
        let targets = [
            0,
            guest_pid,
            i64::from(pid),
            i64::from(pid),
            i64::from(pid),
            absent,
            absent,
        ];
        let guarded = |word: u64| format!("{ROBUST_BEFORE:016x}:{word:016x}:{ROBUST_AFTER:016x}");
        for (index, row) in robust_rows.iter().enumerate() {
            let fields: Vec<_> = row.split_whitespace().collect();
            assert_eq!(fields.len(), 15, "malformed robust observation: {row}");
            assert_eq!(fields[0], format!("sysnum={}", libc::SYS_get_robust_list));
            assert_eq!(fields[1], format!("target={}", targets[index]));
            assert_eq!(fields[2], format!("caller_pid={guest_pid}"));
            assert_eq!(fields[3], format!("caller_tid={}", guest_robust.tid));
            assert_eq!(
                fields[4],
                format!(
                    "head_pointer={}",
                    if ROBUST_BAD_HEAD[index] {
                        "bad"
                    } else {
                        "valid"
                    }
                )
            );
            assert_eq!(
                fields[5],
                format!(
                    "length_pointer={}",
                    if ROBUST_BAD_LENGTH[index] {
                        "bad"
                    } else {
                        "valid"
                    }
                )
            );
            let value = robust_values[index];
            assert_eq!(
                fields[6],
                format!("kernel={}", value.raw),
                "same-caller kernel prerequisite: {row}"
            );
            assert_eq!(fields[7], format!("injected={}", value.raw));
            let kernel_head =
                u64::from_str_radix(observation_field(&fields, "kernel_head="), 16).unwrap();
            let kernel_length =
                u64::from_str_radix(observation_field(&fields, "kernel_length="), 16).unwrap();
            assert_eq!(
                kernel_head, guest_robust.rows[index].head,
                "actual same-task/lifetime head: {row}"
            );
            assert_eq!(kernel_length, guest_robust.rows[index].length);
            let before_head = if ROBUST_BAD_HEAD[index] {
                "unaddressed".to_owned()
            } else {
                guarded(ROBUST_HEAD_SENTINEL)
            };
            let after_head = if ROBUST_BAD_HEAD[index] {
                "unaddressed".to_owned()
            } else {
                guarded(kernel_head)
            };
            let before_length = if ROBUST_BAD_LENGTH[index] {
                "unaddressed".to_owned()
            } else {
                guarded(ROBUST_LENGTH_SENTINEL)
            };
            let after_length = if ROBUST_BAD_LENGTH[index] {
                "unaddressed".to_owned()
            } else {
                guarded(kernel_length)
            };
            assert_eq!(fields[10], format!("guest_head_before={before_head}"));
            assert_eq!(fields[11], format!("guest_head_after={after_head}"));
            assert_eq!(fields[12], format!("guest_length_before={before_length}"));
            assert_eq!(fields[13], format!("guest_length_after={after_length}"));
            assert_eq!(fields[14], "kernel_canaries=1");
        }
    }
}
