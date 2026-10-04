/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's seccomp filter, pinned instruction by instruction.
//!
//! The plain filter must stay byte-identical to the one captured before the
//! trap-only filter existed (the fixtures). The trap-only filter must decode
//! to exactly the specified routing, which a small seccomp-BPF interpreter
//! checks here; the interpreter's verdicts on the plain filter's untraced
//! range are checked against the kernel's in a real child, and the trap-only
//! filter is loaded into a real child.

use reverie::process::seccomp::Filter;

use super::*;
use crate::liteinst_trap_only::SLOT;
use crate::liteinst_trap_only::SLOT_RET;
use crate::liteinst_trap_only::TAG_I386;
use crate::liteinst_trap_only::TAG_SLOT;

const AUDIT_ARCH_I386: u32 = 0x4000_0003;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_TRACE: u32 = 0x7ff0_0000;

type Insn = (u16, u8, u8, u32);

fn insns(filter: &Filter) -> Vec<Insn> {
    filter
        .instructions()
        .iter()
        .map(|insn| (insn.code, insn.jt, insn.jf, insn.k))
        .collect()
}

fn render(filter: &Filter) -> String {
    insns(filter)
        .into_iter()
        .map(|(code, jt, jf, k)| format!("{code:#06x} {jt:#04x} {jf:#04x} {k:#010x}\n"))
        .collect()
}

fn fixture_body(text: &str) -> String {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// Runs a seccomp-BPF program on `seccomp_data { nr, arch, ip }` and returns
/// its verdict. Only the instructions the builder emits are accepted.
fn run(program: &[Insn], nr: u32, arch: u32, ip: u64) -> u32 {
    let (mut acc, mut mem, mut pc) = (0u32, [0u32; 16], 0usize);
    loop {
        let (code, jt, jf, k) = *program
            .get(pc)
            .unwrap_or_else(|| panic!("fell off the program at {pc}"));
        pc += 1;
        let jump = |taken: bool| usize::from(if taken { jt } else { jf });
        match code {
            // BPF_LD | BPF_W | BPF_ABS
            0x20 => {
                acc = match k {
                    0 => nr,
                    4 => arch,
                    8 => ip as u32,
                    12 => (ip >> 32) as u32,
                    _ => panic!("load of unmodelled seccomp_data offset {k}"),
                }
            }
            // BPF_ST
            0x02 => mem[k as usize] = acc,
            // BPF_LD | BPF_MEM
            0x60 => acc = mem[k as usize],
            // BPF_JMP | BPF_JEQ | BPF_K
            0x15 => pc += jump(acc == k),
            // BPF_JMP | BPF_JGT | BPF_K
            0x25 => pc += jump(acc > k),
            // BPF_JMP | BPF_JGE | BPF_K
            0x35 => pc += jump(acc >= k),
            // BPF_RET | BPF_K
            0x06 => return k,
            _ => panic!("unmodelled opcode {code:#x} at {}", pc - 1),
        }
    }
}

fn plain(events: &Subscription) -> Vec<Insn> {
    insns(&seccomp_filter(events, false))
}

fn trap_only(events: &Subscription) -> Vec<Insn> {
    insns(&seccomp_filter(events, true))
}

/// M7: the plain filter for the Hermit subscription (`Subscription::all()`)
/// is the one captured before the trap-only filter existed (see the fixture's
/// header for the exact commit).
#[test]
fn plain_filter_for_all_syscalls_is_byte_identical_to_the_capture() {
    assert_eq!(
        render(&seccomp_filter(&Subscription::all(), false)),
        fixture_body(include_str!(
            "../tests/fixtures/ptrace_seccomp_filter_all_syscalls.txt"
        ))
    );
}

/// M7: the plain filter for an empty subscription is the one captured before
/// the trap-only filter existed (see the fixture's header for the exact
/// commit).
#[test]
fn plain_filter_for_no_syscalls_is_byte_identical_to_the_capture() {
    assert_eq!(
        render(&seccomp_filter(&Subscription::none(), false)),
        fixture_body(include_str!(
            "../tests/fixtures/ptrace_seccomp_filter_no_syscalls.txt"
        ))
    );
}

/// The trap-only filter is the plain one with exactly two insertions: the
/// I386 architecture route replacing the three-instruction architecture
/// check, and the exact `SLOT_RET` rule placed first after the instruction
/// pointer load.
#[test]
fn trap_only_filter_has_exactly_the_specified_instructions() {
    assert_eq!(SLOT, 0x7100_0004);
    assert_eq!(SLOT_RET, 0x7100_0006);
    assert_eq!((TAG_I386, TAG_SLOT), (0x7101, 0x7102));
    for events in [Subscription::all(), Subscription::none()] {
        let plain = plain(&events);
        let on = trap_only(&events);
        let prologue: [Insn; 5] = [
            (0x20, 0, 0, 4),
            (0x15, 3, 0, AUDIT_ARCH_X86_64),
            (0x15, 0, 1, AUDIT_ARCH_I386),
            (0x06, 0, 0, RET_TRACE | 0x7101),
            (0x06, 0, 0, RET_KILL_PROCESS),
        ];
        let plain_arch_check: [Insn; 3] = [
            (0x20, 0, 0, 4),
            (0x15, 1, 0, AUDIT_ARCH_X86_64),
            (0x06, 0, 0, RET_KILL_PROCESS),
        ];
        let load_ip: [Insn; 4] = [
            (0x20, 0, 0, 8),
            (0x02, 0, 0, 0),
            (0x20, 0, 0, 12),
            (0x02, 0, 0, 1),
        ];
        let slot_rule: [Insn; 5] = [
            (0x15, 0, 3, 0),
            (0x60, 0, 0, 0),
            (0x15, 0, 1, 0x7100_0006),
            (0x06, 0, 0, RET_TRACE | 0x7102),
            (0x60, 0, 0, 1),
        ];
        assert_eq!(plain[..3], plain_arch_check);
        assert_eq!(plain[3..7], load_ip);
        let mut expected = prologue.to_vec();
        expected.extend(load_ip);
        expected.extend(slot_rule);
        expected.extend(&plain[7..]);
        assert_eq!(on, expected);
    }
}

/// The trap-only filter's verdicts, decoded: every I386 syscall stops with
/// `TAG_I386`; every x86_64 syscall at `SLOT_RET` stops with `TAG_SLOT`,
/// whatever its number (including `rt_sigreturn`, which plain ptrace always
/// allows, and numbers no tool subscribes to); every other x86_64 syscall gets
/// plain ptrace's verdict; any other architecture is killed.
#[test]
fn trap_only_filter_decodes_as_specified() {
    let numbers = [0u32, 1, 15, 20, 39, 59, 173, 435, 1000, u32::MAX];
    let ips = [
        0,
        0x40_1000,
        SLOT - 2,
        SLOT - 1,
        SLOT,
        SLOT_RET - 1,
        SLOT_RET + 1,
        0x7100_0002,
        0x7100_0003,
        0x8000_0002,
        0x7fff_ffff_f000,
        SLOT_RET | (1 << 32),
    ];
    for events in [Subscription::all(), Subscription::none()] {
        let plain = plain(&events);
        let on = trap_only(&events);
        for nr in numbers {
            for ip in ips.into_iter().chain([SLOT_RET]) {
                assert_eq!(
                    run(&on, nr, AUDIT_ARCH_I386, ip),
                    RET_TRACE | u32::from(TAG_I386),
                    "I386 nr {nr} ip {ip:#x}"
                );
                assert_eq!(
                    run(&plain, nr, AUDIT_ARCH_I386, ip),
                    RET_KILL_PROCESS,
                    "plain ptrace must still kill I386 nr {nr}"
                );
                for arch in [AUDIT_ARCH_AARCH64, 0] {
                    assert_eq!(run(&on, nr, arch, ip), RET_KILL_PROCESS);
                    assert_eq!(run(&plain, nr, arch, ip), RET_KILL_PROCESS);
                }
            }
            assert_eq!(
                run(&on, nr, AUDIT_ARCH_X86_64, SLOT_RET),
                RET_TRACE | u32::from(TAG_SLOT),
                "x86_64 nr {nr} at SLOT_RET"
            );
            for ip in ips {
                assert_eq!(
                    run(&on, nr, AUDIT_ARCH_X86_64, ip),
                    run(&plain, nr, AUDIT_ARCH_X86_64, ip),
                    "x86_64 nr {nr} ip {ip:#x} must keep plain ptrace's verdict"
                );
            }
        }
    }
    // The plain verdicts compared against above are the real ones: a
    // subscribed number is traced with data 0, and rt_sigreturn is allowed.
    let all = plain(&Subscription::all());
    assert_eq!(run(&all, 39, AUDIT_ARCH_X86_64, 0x40_1000), RET_TRACE);
    assert_eq!(run(&all, 15, AUDIT_ARCH_X86_64, 0x40_1000), RET_ALLOW);
    let none = plain(&Subscription::none());
    assert_eq!(run(&none, 39, AUDIT_ARCH_X86_64, 0x40_1000), RET_ALLOW);
}

// Signals that report the child's verdict. The child cannot exit with a
// status: under a filter for `Subscription::all()` `exit_group` is traced, so
// without a tracer it fails with ENOSYS. A synchronous fault needs no syscall.
const ALLOWED: libc::c_int = libc::SIGILL; // ud2
const TRACED: libc::c_int = libc::SIGTRAP; // int3
const OTHER: libc::c_int = libc::SIGFPE; // divide by zero

/// The kernel's verdict on `getpid` at return address `ip` under `filter`: a
/// child loads the filter and calls `getpid` through a `syscall; ret` stub
/// mapped so that the syscall's return address is exactly `ip`. Without a
/// tracer, `SECCOMP_RET_TRACE` fails the syscall with ENOSYS, and
/// `SECCOMP_RET_ALLOW` returns the pid.
fn kernel_verdict(filter: &Filter, ip: u64) -> u32 {
    let page = 0x1000u64;
    let first = (ip - 2) & !(page - 1);
    let len = ((ip + 1 + page - 1) & !(page - 1)) - first;
    // SAFETY: the child only makes raw syscalls on memory it maps itself,
    // then ends with a fault without returning to the test harness.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe {
            // A fault must not dump core.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            let base = libc::mmap(
                first as *mut libc::c_void,
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            );
            if base as u64 != first {
                libc::_exit(10);
            }
            // syscall; ret
            let stub = [0x0f, 0x05, 0xc3u8];
            std::ptr::copy_nonoverlapping(stub.as_ptr(), (ip - 2) as *mut u8, 3);
            let expected = libc::syscall(libc::SYS_getpid);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || filter.load().is_err() {
                libc::_exit(11);
            }
            let ret: i64;
            core::arch::asm!(
                "call {stub}",
                stub = in(reg) ip - 2,
                inlateout("rax") libc::SYS_getpid => ret,
                out("rcx") _,
                out("r11") _,
            );
            if ret == expected {
                core::arch::asm!("ud2", options(noreturn));
            } else if ret == -(libc::ENOSYS as i64) {
                core::arch::asm!("int3", options(noreturn));
            } else {
                core::arch::asm!("xor ecx, ecx", "div ecx", options(noreturn));
            }
        }
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    match status {
        _ if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 10 => {
            panic!("could not map a stub page at {first:#x}")
        }
        _ if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == ALLOWED => RET_ALLOW,
        _ if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == TRACED => RET_TRACE,
        _ if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == OTHER => {
            panic!("getpid at ip {ip:#x} returned neither the pid nor ENOSYS")
        }
        _ => panic!("child for ip {ip:#x} ended with status {status:#x}"),
    }
}

/// The plain filter's untraced range `[PAGE+2, PAGE+3)` matches exactly
/// `0x7100_0002`, and the interpreter and the kernel agree on it: a child
/// loads the plain filter for `Subscription::all()` and calls `getpid` through
/// a `syscall; ret` stub mapped so that the syscall's return address is
/// exactly `ip`. Without a tracer, `SECCOMP_RET_TRACE` fails the syscall with
/// ENOSYS, and `SECCOMP_RET_ALLOW` returns the pid. The probes include
/// `SLOT_RET` and addresses above the range in the same 4 GiB half.
#[test]
fn plain_ip_range_verdicts_match_the_kernel_witness() {
    let filter = seccomp_filter(&Subscription::all(), false);
    let all = insns(&filter);
    let mut rows = Vec::new();
    for ip in [
        0x7100_0001u64,
        0x7100_0002,
        0x7100_0003,
        SLOT_RET,
        0x7100_000a,
        0x8000_0002,
        0x2_0000_0002,
    ] {
        let expected = if ip == 0x7100_0002 {
            RET_ALLOW
        } else {
            RET_TRACE
        };
        let interpreted = run(&all, 39, AUDIT_ARCH_X86_64, ip);
        let kernel = kernel_verdict(&filter, ip);
        if (interpreted, kernel) != (expected, expected) {
            rows.push(format!(
                "ip {ip:#x}: expected {expected:#x}, interpreter {interpreted:#x}, kernel {kernel:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// The kernel applies the trap-only filter's exact `SLOT_RET` rule: under the
/// trap-only filter for `Subscription::none()`, where no syscall number is
/// traced, `getpid` whose return address is exactly `SLOT_RET` is traced
/// (ENOSYS without a tracer), and the near misses are allowed: one byte either
/// side, the same low 32 bits with a high bit set, the untraced range's
/// `0x7100_0002`, and an ordinary address on the same page. Under the plain
/// filter every probe, `SLOT_RET` included, is allowed, so the trace comes
/// from the slot rule alone. The interpreter gives the same actions, with
/// `TAG_SLOT` as the trace data at `SLOT_RET` (the kernel witness sees only the
/// action).
#[test]
fn kernel_applies_the_trap_only_slot_ret_rule_exactly() {
    let events = Subscription::none();
    let on = seccomp_filter(&events, true);
    let off = seccomp_filter(&events, false);
    let (on_insns, off_insns) = (insns(&on), insns(&off));
    let mut rows = Vec::new();
    for ip in [
        SLOT_RET,
        SLOT_RET - 1,
        SLOT_RET + 1,
        SLOT_RET | (1 << 32),
        0x7100_0002,
        0x7100_000a,
    ] {
        for (label, filter, program, expected) in [
            (
                "trap-only",
                &on,
                &on_insns,
                if ip == SLOT_RET {
                    RET_TRACE | u32::from(TAG_SLOT)
                } else {
                    RET_ALLOW
                },
            ),
            ("plain", &off, &off_insns, RET_ALLOW),
        ] {
            let interpreted = run(program, 39, AUDIT_ARCH_X86_64, ip);
            let kernel = kernel_verdict(filter, ip);
            // SECCOMP_RET_ACTION_FULL: the kernel witness sees only the action.
            if (interpreted, kernel) != (expected, expected & 0xffff_0000) {
                rows.push(format!(
                    "{label} ip {ip:#x}: expected {expected:#x}, interpreter {interpreted:#x}, kernel {kernel:#x}"
                ));
            }
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// The kernel accepts the trap-only filter and applies its I386 route: in an
/// untraced child, `SECCOMP_RET_TRACE` without a tracer fails the syscall with
/// ENOSYS, whereas the plain filter kills the child with SIGSYS. An x86_64
/// getpid from ordinary code is still allowed.
#[test]
fn kernel_applies_the_trap_only_i386_route() {
    fn child_status(filter: &Filter) -> libc::c_int {
        // SAFETY: the child only makes raw syscalls and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                // A SIGSYS kill must not dump core.
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || filter.load().is_err()
                {
                    libc::_exit(10);
                }
                let expected = libc::syscall(libc::SYS_getpid) as u64;
                if expected as i64 <= 0 {
                    // The x86_64 getpid was not allowed through.
                    libc::_exit(13);
                }
                let result: u64;
                core::arch::asm!(
                    "int 0x80",
                    inlateout("rax") 20u64 => result,
                    lateout("r8") _,
                    lateout("r9") _,
                    lateout("r10") _,
                    lateout("r11") _,
                    options(nostack),
                );
                let code = if result == -(libc::ENOSYS as i64) as u64 {
                    0
                } else if result == expected {
                    11
                } else {
                    12
                };
                libc::_exit(code);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        status
    }
    let events = Subscription::none();
    let status = child_status(&seccomp_filter(&events, true));
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "trap-only filter: I386 getpid did not stop for a tracer (status {status:#x})"
    );
    let status = child_status(&seccomp_filter(&events, false));
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
        "plain filter: I386 getpid was not killed with SIGSYS (status {status:#x})"
    );
}
