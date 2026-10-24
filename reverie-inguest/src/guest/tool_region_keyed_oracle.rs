/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Frozen native oracle, not a production protection/clock claim.
//! The baseline's desired adapter uses the existing key-zero owner, so its
//! 16 required denials must fail physically with access_allowed. All 32 rows,
//! supplemental coverage, legacy controls and guards run before assertions.
//! No keyed SUT implementation or missing new API is needed to build this.

use super::super::BASE;
use super::super::CONTROL_BYTES;
use super::super::END;
use super::super::PAGE;
use super::super::raw_syscall6;

#[path = "tool_region_keyed_oracle_adapter.rs"]
mod adapter;
#[path = "tool_region_keyed_oracle_probe.rs"]
mod probe;
#[path = "tool_region_keyed_oracle_vma.rs"]
mod vma;

const MAIN_ROWS: usize = 32;
const DENIAL_ROWS: usize = 16;
const GUARD_ROWS: usize = 16;
const COMPLETE: u64 = 0x4b45_594f_5241_434c;
const FORK_NS: u64 = 3_000_000_000;
const SEGV_PKUERR: i32 = 4; // Linux UAPI: protection-key access violation.
const SEGV_ACCERR: i32 = 2; // Linux UAPI: PROT_NONE guard violation.

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(super) struct Span {
    pub bottom: usize,
    pub top: usize,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(super) struct OwnerSnapshot {
    pub owner_identity: usize,
    pub key: u32,
    pub reserved: u32,
    pub reservation: Span,
    pub interiors: [Span; 4],
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SetupError {
    pub unsupported: bool,
    pub errno: i32,
}

impl SetupError {
    pub(super) fn error(errno: i32) -> Self {
        Self {
            unsupported: false,
            errno,
        }
    }
    pub(super) fn unsupported(errno: i32) -> Self {
        Self {
            unsupported: true,
            errno,
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub(super) struct Observation {
    pub kind: u32, // 0 empty, 1 real MOV completed, 2 SIGSEGV, 3 timeout, 4 setup error.
    pub signal: i32,
    pub code: i32,
    pub setup_errno: i32,
    pub address: usize,
    pub rip: usize,
    pub expected_address: usize,
    pub expected_rip: usize,
    pub pkru_before: u32,
    pub pkru_after: u32,
    pub expected_pkru: u32,
    pub requested_pkru: u32,
    pub byte_before: u8,
    pub byte_after: u8,
    pub byte_observed: u8,
    pub reserved: u8,
    pub wait_status: i32,
    pub wait_errno: i32,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct Report {
    completion: u64,
    setup_status: u32, // 0 complete, 1 NOT_MEASURED, 2 setup error.
    setup_errno: i32,
    pid: i64,
    tid: i64,
    owner: OwnerSnapshot,
    coverage: vma::Coverage,
    observed_rows: u32,
    observed_guards: u32,
    main: [Observation; MAIN_ROWS],
    guards: [Observation; GUARD_ROWS],
}

fn raw(number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: fixture callers supply owned ranges and live key-zero buffers.
    unsafe { raw_syscall6(number, args) }
}

fn raw_exit(code: i32) -> ! {
    raw(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]);
    // SAFETY: exit_group must not return, and raw children never unwind.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn map(bytes: usize, shared: bool) -> Result<Span, SetupError> {
    let result = raw(
        libc::SYS_mmap,
        [
            0,
            bytes as u64,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_ANONYMOUS
                | if shared {
                    libc::MAP_SHARED
                } else {
                    libc::MAP_PRIVATE
                }) as u64,
            u64::MAX,
            0,
        ],
    );
    if result <= 0 {
        return Err(SetupError::error(-result as i32));
    }
    let bottom = result as usize;
    if bottom.checked_add(bytes).is_none() {
        return Err(SetupError::error(libc::EOVERFLOW));
    }
    Ok(Span {
        bottom,
        top: bottom + bytes,
    })
}

fn now() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if raw(
        libc::SYS_clock_gettime,
        [
            libc::CLOCK_MONOTONIC as u64,
            &mut time as *mut libc::timespec as u64,
            0,
            0,
            0,
            0,
        ],
    ) != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return None;
    }
    Some(
        (time.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(time.tv_nsec as u64),
    )
}

fn pause() {
    let delay = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000,
    };
    raw(
        libc::SYS_nanosleep,
        [&delay as *const libc::timespec as u64, 0, 0, 0, 0, 0],
    );
}

// No libc allocation, libtest call or panic in a raw descendant's wait path.
fn wait(pid: i64) -> (i32, i32, bool) {
    let Some(start) = now() else {
        raw(
            libc::SYS_kill,
            [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
        );
        return (0, libc::EIO, false);
    };
    let mut deadline = start.saturating_add(FORK_NS);
    let mut killed = false;
    loop {
        let mut status = 0_i32;
        let result = raw(
            libc::SYS_wait4,
            [
                pid as u64,
                &mut status as *mut i32 as u64,
                libc::WNOHANG as u64,
                0,
                0,
                0,
            ],
        );
        if result == pid {
            return (status, 0, killed);
        }
        if result != 0 && result != -i64::from(libc::EINTR) {
            raw(
                libc::SYS_kill,
                [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            );
            return (status, -result as i32, killed);
        }
        let Some(current) = now() else {
            raw(
                libc::SYS_kill,
                [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            );
            return (status, libc::EIO, killed);
        };
        if current >= deadline {
            if killed {
                return (status, libc::ETIMEDOUT, true);
            }
            let result = raw(
                libc::SYS_kill,
                [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            );
            if result != 0 && result != -i64::from(libc::ESRCH) {
                return (status, -result as i32, true);
            }
            killed = true;
            deadline = current.saturating_add(FORK_NS);
        }
        pause();
    }
}

fn status_ok(row: &Observation) -> bool {
    row.wait_errno == 0
        && libc::WIFEXITED(row.wait_status)
        && libc::WEXITSTATUS(row.wait_status) == 0
        && row.setup_errno == 0
}

fn completed(row: &Observation) -> bool {
    status_ok(row)
        && row.kind == 1
        && row.byte_observed == row.byte_before
        && row.byte_after == row.byte_before
        && row.pkru_before == row.expected_pkru
        && row.pkru_after == row.expected_pkru
}

fn faulted(row: &Observation, code: i32) -> bool {
    status_ok(row)
        && row.kind == 2
        && row.signal == libc::SIGSEGV
        && row.code == code
        && row.address == row.expected_address
        && row.rip == row.expected_rip
}

fn valid(owner: &OwnerSnapshot) -> bool {
    owner.owner_identity != 0
        && (1..=15).contains(&owner.key)
        && owner.reservation.bottom == BASE
        && owner.reservation.top == END
        && owner.interiors[0].bottom == BASE + PAGE
        && owner.interiors[0].top == BASE + CONTROL_BYTES
        && owner.interiors[1].bottom == BASE + 0x1000_0000
        && owner.interiors[1].top == BASE + 0x1200_0000
        && owner.interiors[2].bottom == BASE + 0x1400_0000
        && owner.interiors[2].top == BASE + 0x1600_0000
        && owner.interiors[3]
            .top
            .checked_sub(owner.interiors[3].bottom)
            == Some(PAGE)
        && owner.interiors[3].bottom == BASE + CONTROL_BYTES + PAGE
        && owner.interiors[3].top == BASE + CONTROL_BYTES + 2 * PAGE
}

fn guards(owner: &OwnerSnapshot) -> [usize; 8] {
    [
        BASE,
        END - PAGE,
        owner.interiors[1].bottom - PAGE,
        owner.interiors[1].top,
        owner.interiors[2].bottom - PAGE,
        owner.interiors[2].top,
        owner.interiors[3].bottom - PAGE,
        owner.interiors[3].top,
    ]
}

fn run_probe(
    record: *mut Observation,
    observer: Span,
    target: usize,
    mask: u32,
    write: bool,
    original: u8,
) {
    // SAFETY: one raw parent initializes this separate live shared row.
    unsafe {
        core::ptr::addr_of_mut!((*record).expected_address).write_volatile(target);
        core::ptr::addr_of_mut!((*record).expected_rip).write_volatile(probe::instruction(write));
        core::ptr::addr_of_mut!((*record).expected_pkru).write_volatile(probe::rights());
        core::ptr::addr_of_mut!((*record).requested_pkru).write_volatile(mask);
        core::ptr::addr_of_mut!((*record).byte_before).write_volatile(original);
    }
    let pid = raw(libc::SYS_fork, [0; 6]);
    if pid == 0 {
        probe::child(record, observer, target, mask, write, original);
    }
    if pid < 0 {
        // SAFETY: no fork child exists; report the actual setup failure.
        unsafe {
            core::ptr::addr_of_mut!((*record).setup_errno).write_volatile(-pid as i32);
            core::ptr::addr_of_mut!((*record).kind).write_volatile(4);
        }
        return;
    }
    let (status, error, timed_out) = wait(pid);
    // SAFETY: wait has completed or boundedly failed; failed rows never pass.
    unsafe {
        core::ptr::addr_of_mut!((*record).wait_status).write_volatile(status);
        core::ptr::addr_of_mut!((*record).wait_errno).write_volatile(error);
        if timed_out {
            core::ptr::addr_of_mut!((*record).kind).write_volatile(3);
        }
    }
    if error != 0 {
        // The exact self-reexec subreaper owns cleanup of an unreaped probe.
        // Never continue probing after an indeterminate raw wait.
        raw_exit(94);
    }
}

fn fail_setup(report: *mut Report, error: SetupError) -> ! {
    // SAFETY: this raw native leader exclusively owns setup fields on key zero.
    unsafe {
        core::ptr::addr_of_mut!((*report).setup_status).write_volatile(if error.unsupported {
            1
        } else {
            2
        });
        core::ptr::addr_of_mut!((*report).setup_errno).write_volatile(error.errno);
        core::ptr::addr_of_mut!((*report).completion).write_volatile(COMPLETE);
    }
    raw_exit(if error.unsupported { 77 } else { 85 });
}

fn native_body(report: *mut Report, output: Span, desired: bool) -> ! {
    let pid = raw(libc::SYS_getpid, [0; 6]);
    let tid = raw(libc::SYS_gettid, [0; 6]);
    // Construction occurs AFTER raw fork: only this native leader survives.
    unsafe {
        core::ptr::addr_of_mut!((*report).pid).write_volatile(pid);
        core::ptr::addr_of_mut!((*report).tid).write_volatile(tid);
    }
    if pid <= 0
        || pid != tid
        || raw(
            libc::SYS_prctl,
            [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0],
        ) != 0
    {
        fail_setup(report, SetupError::error(libc::EPERM));
    }
    if !probe::supported() {
        fail_setup(report, SetupError::unsupported(libc::EOPNOTSUPP));
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if raw(
        libc::SYS_setrlimit,
        [
            libc::RLIMIT_CORE as u64,
            &limit as *const libc::rlimit as u64,
            0,
            0,
            0,
            0,
        ],
    ) != 0
    {
        fail_setup(report, SetupError::error(libc::EIO));
    }
    let owner = match if desired {
        adapter::desired()
    } else {
        adapter::legacy()
    } {
        Ok(owner) => owner,
        Err(error) => fail_setup(report, error),
    };
    if !valid(&owner) || (output.bottom < END && BASE < output.top) {
        fail_setup(report, SetupError::error(libc::EIO));
    }
    let observer = match map(16 * PAGE, false) {
        Ok(span) => span,
        Err(error) => fail_setup(report, error),
    };
    if observer.bottom < END && BASE < observer.top {
        fail_setup(report, SetupError::error(libc::EIO));
    }
    let entry = probe::rights();
    if entry & 3 != 0 || entry & (3 << (2 * owner.key)) != 0 {
        fail_setup(report, SetupError::error(libc::EACCES));
    }
    // Only non-Control payloads get distinct sentinels. Never corrupt held or
    // other typed metadata to make a control store look more impressive.
    for role in 1..4 {
        let span = owner.interiors[role];
        unsafe {
            core::ptr::write_volatile(span.bottom as *mut u8, 0x60 + role as u8);
            core::ptr::write_volatile((span.top - 1) as *mut u8, 0xa0 + role as u8);
        }
    }
    // Supplemental metadata failure NEVER short-circuits actual access rows.
    let coverage = vma::inspect(
        &owner,
        output,
        observer,
        if desired { owner.key } else { 0 },
    );
    unsafe {
        core::ptr::addr_of_mut!((*report).owner).write_volatile(owner);
        core::ptr::addr_of_mut!((*report).coverage).write_volatile(coverage);
    }
    let allow = entry & !(3 << (2 * owner.key));
    let deny = allow | (3 << (2 * owner.key));
    let mut index = 0;
    for role in 0..4 {
        let span = owner.interiors[role];
        for target in [span.bottom, span.top - 1] {
            // Actual valid owner bytes are sampled only with the key open.
            let original = unsafe { core::ptr::read_volatile(target as *const u8) };
            for write in [false, true] {
                for mask in [allow, deny] {
                    let row = unsafe {
                        core::ptr::addr_of_mut!((*report).main)
                            .cast::<Observation>()
                            .add(index)
                    };
                    run_probe(row, observer, target, mask, write, original);
                    index += 1;
                    unsafe {
                        core::ptr::addr_of_mut!((*report).observed_rows)
                            .write_volatile(index as u32);
                    }
                }
            }
        }
    }
    index = 0;
    for target in guards(&owner) {
        for write in [false, true] {
            let row = unsafe {
                core::ptr::addr_of_mut!((*report).guards)
                    .cast::<Observation>()
                    .add(index)
            };
            run_probe(row, observer, target, allow, write, 0x5a);
            index += 1;
            unsafe {
                core::ptr::addr_of_mut!((*report).observed_guards).write_volatile(index as u32);
            }
        }
    }
    unsafe {
        core::ptr::addr_of_mut!((*report).completion).write_volatile(COMPLETE);
    }
    // Completion is transport status, never proof that the assertions passed.
    raw_exit(0);
}

fn reap_adopted() -> bool {
    use std::io::Read;
    use std::time::Duration;
    use std::time::Instant;
    let deadline = Instant::now() + Duration::from_secs(3);
    let process = raw(libc::SYS_getpid, [0; 6]);
    let thread = raw(libc::SYS_gettid, [0; 6]);
    let mut leftovers = false;
    loop {
        let mut status = 0_i32;
        let result = raw(
            libc::SYS_wait4,
            [
                u64::MAX,
                &mut status as *mut i32 as u64,
                libc::WNOHANG as u64,
                0,
                0,
                0,
            ],
        );
        if result == -i64::from(libc::ECHILD) {
            return leftovers;
        }
        if result > 0 {
            leftovers = true;
            continue;
        }
        assert!(
            result == 0 || result == -i64::from(libc::EINTR),
            "private subreaper wait failed: {result}"
        );
        // Ordinary supervisor only: identify children of the test worker and
        // native process leader after any raw-parent death, kill each and reap.
        // This is not process-wide authority discovery and never reads environ.
        for task in [process, thread] {
            let path = format!("/proc/self/task/{task}/children");
            let input = std::fs::File::open(path).expect("private subreaper child list");
            let mut bytes = Vec::new();
            input
                .take((super::OUTPUT_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(
                bytes.len() <= super::OUTPUT_LIMIT,
                "child list exceeded bounded storage"
            );
            for value in std::str::from_utf8(&bytes).unwrap().split_whitespace() {
                let pid: u64 = value.parse().expect("kernel child PID");
                assert!(pid > 0 && pid != process as u64, "foreign child-list entry");
                let killed = raw(libc::SYS_kill, [pid, libc::SIGKILL as u64, 0, 0, 0, 0]);
                assert!(
                    killed == 0 || killed == -i64::from(libc::ESRCH),
                    "failed to kill adopted child {pid}: {killed}"
                );
                leftovers = true;
            }
        }
        assert!(
            Instant::now() < deadline,
            "adopted descendants were not killed/reaped in 3s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn collect(desired: bool) -> (Report, i32, i32, bool) {
    let bytes = core::mem::size_of::<Report>().div_ceil(PAGE) * PAGE;
    let mapping = map(bytes, true).expect("ordinary supervisor report mapping");
    let pointer = mapping.bottom as *mut Report;
    let pid = raw(libc::SYS_fork, [0; 6]);
    assert!(pid >= 0, "native construction fork failed: {pid}");
    if pid == 0 {
        native_body(pointer, mapping, desired);
    }
    let (status, mut error, timed_out) = wait(pid);
    // The private exact child became a subreaper before constructing anything.
    // Complete descendant cleanup before reading or freeing shared transport.
    if reap_adopted() {
        error = libc::ECHILD;
    }
    // SAFETY: zeroed anonymous storage is valid for this scalar-only repr(C)
    // record. No row can qualify after an incomplete wait/setup/transport.
    let report = unsafe { core::ptr::read_volatile(pointer) };
    let unmapped = raw(
        libc::SYS_munmap,
        [mapping.bottom as u64, bytes as u64, 0, 0, 0, 0],
    );
    assert_eq!(unmapped, 0, "ordinary supervisor report cleanup");
    (report, status, error, timed_out)
}

fn show(label: &str, report: &Report) {
    println!("KEYED_OWNER_ORACLE:{label}:actual_owner={:?}", report.owner);
    println!(
        "KEYED_OWNER_ORACLE:{label}:setup={} errno={} pid={} tid={} rows={} guards={} key={} owner={:#x}",
        report.setup_status,
        report.setup_errno,
        report.pid,
        report.tid,
        report.observed_rows,
        report.observed_guards,
        report.owner.key,
        report.owner.owner_identity
    );
    if report.setup_status == 1 {
        println!("KEYED_OWNER_ORACLE:{label}:NOT_MEASURED:qualified_protection_rows=0");
    }
    for (index, row) in report
        .main
        .iter()
        .enumerate()
        .take(report.observed_rows as usize)
    {
        let denial = label == "desired" && index % 2 == 1;
        let passed = if denial {
            faulted(row, SEGV_PKUERR)
        } else {
            completed(row)
        };
        let reason = if denial && row.kind == 1 {
            "access_allowed"
        } else if passed {
            "predicate_satisfied"
        } else {
            "predicate_failed"
        };
        println!(
            "KEYED_OWNER_ORACLE:{label}:row={index} role={} endpoint={} operation={} rights={} result={} reason={reason} kind={} signal={} code={} addr={:#x} expected_addr={:#x} rip={:#x} expected_rip={:#x} pkru_before={:#x} pkru_after={:#x} expected_pkru={:#x} requested_pkru={:#x} before={:#x} observed={:#x} after={:#x} wait={:#x} wait_errno={} setup_errno={}",
            index / 8,
            (index / 4) % 2,
            (index / 2) % 2,
            index % 2,
            if passed { "PASS" } else { "FAIL" },
            row.kind,
            row.signal,
            row.code,
            row.address,
            row.expected_address,
            row.rip,
            row.expected_rip,
            row.pkru_before,
            row.pkru_after,
            row.expected_pkru,
            row.requested_pkru,
            row.byte_before,
            row.byte_observed,
            row.byte_after,
            row.wait_status,
            row.wait_errno,
            row.setup_errno
        );
    }
    for (index, row) in report
        .guards
        .iter()
        .enumerate()
        .take(report.observed_guards as usize)
    {
        println!(
            "KEYED_OWNER_ORACLE:{label}:guard={index} result={} kind={} signal={} code={} addr={:#x} expected_addr={:#x} rip={:#x} expected_rip={:#x} wait={:#x} wait_errno={} setup_errno={}",
            if faulted(row, SEGV_ACCERR) {
                "PASS"
            } else {
                "FAIL"
            },
            row.kind,
            row.signal,
            row.code,
            row.address,
            row.expected_address,
            row.rip,
            row.expected_rip,
            row.wait_status,
            row.wait_errno,
            row.setup_errno
        );
    }
    println!(
        "KEYED_OWNER_ORACLE:{label}:supplemental_vma={:?}",
        report.coverage
    );
}

fn inspect_body() {
    #[repr(C)]
    struct ChildAction {
        handler: usize,
        flags: usize,
        restorer: usize,
        mask: u64,
    }
    let action = ChildAction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    // Do not inherit SIG_IGN/SA_NOCLDWAIT and accidentally release a child's
    // PID before this private supervisor has waited for it.
    assert_eq!(
        raw(
            libc::SYS_rt_sigaction,
            [
                libc::SIGCHLD as u64,
                &action as *const ChildAction as u64,
                0,
                8,
                0,
                0
            ]
        ),
        0,
        "private exact child SIGCHLD disposition"
    );
    // This applies only inside the private --exact self-reexec child. The
    // original/shared libtest process is untouched. Adopt raw grandchildren
    // on failure, so group killing cannot leave unreaped orphan controls.
    assert_eq!(
        raw(
            libc::SYS_prctl,
            [libc::PR_SET_CHILD_SUBREAPER as u64, 1, 0, 0, 0, 0]
        ),
        0,
        "private exact child subreaper setup"
    );
    // These are separate fresh native processes: neither construction touches
    // the exact self-reexec libtest parent or the other child's private region.
    let (desired, desired_status, desired_error, desired_timeout) = collect(true);
    let (legacy, legacy_status, legacy_error, legacy_timeout) = collect(false);
    show("desired", &desired);
    show("legacy", &legacy);
    // Print all actual observations before any assertion, including the VMA
    // supplement. Hardware/setup/build/timeouts provide no failing-first credit.
    for (label, report, status, error, timed_out) in [
        (
            "desired",
            &desired,
            desired_status,
            desired_error,
            desired_timeout,
        ),
        (
            "legacy",
            &legacy,
            legacy_status,
            legacy_error,
            legacy_timeout,
        ),
    ] {
        assert!(
            !timed_out && error == 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "{label}: incomplete native transport {status:#x}/{error}"
        );
        assert_eq!(
            report.completion, COMPLETE,
            "{label}: no actual completed record"
        );
        assert_eq!(
            report.setup_status, 0,
            "{label}: NOT_MEASURED or setup failure"
        );
        assert_eq!(
            report.observed_rows as usize, MAIN_ROWS,
            "{label}: missing rows"
        );
        assert_eq!(
            report.observed_guards as usize, GUARD_ROWS,
            "{label}: missing guards"
        );
        assert!(
            report.guards.iter().all(|row| faulted(row, SEGV_ACCERR)),
            "{label}: actual guards failed"
        );
    }
    assert!(
        legacy.main.iter().all(completed),
        "unchanged legacy positive controls failed"
    );
    assert!(
        desired
            .main
            .iter()
            .enumerate()
            .filter(|(i, _)| i % 2 == 0)
            .all(|(_, row)| completed(row)),
        "owned-key allow controls failed"
    );
    let actual_denials = desired
        .main
        .iter()
        .enumerate()
        .filter(|(i, row)| i % 2 == 1 && faulted(row, SEGV_PKUERR))
        .count();
    assert_eq!(
        actual_denials, DENIAL_ROWS,
        "required physical read/write denials failed; completed denied accesses are FAIL(access_allowed)"
    );
    assert!(
        desired.coverage.qualified() && legacy.coverage.qualified(),
        "complete VMA supplement failed; actual accesses were still executed"
    );
    println!("KEYED_OWNER_ORACLE:QUALIFIED:rows=32 denials=16 legacy_rows=32 guards=32");
}

#[test]
#[ignore = "requires native OSPKE and available pkeys; explicit supported-host selection"]
fn actual_keyed_interiors_deny_read_write() {
    // Reuse the unchanged exact self-reexec supervisor: 30s process, 3s fork,
    // 64KiB per output stream, dedicated group cleanup and exact marker once.
    super::isolated(
        "keyed_oracle::actual_keyed_interiors_deny_read_write",
        inspect_body,
    );
}
