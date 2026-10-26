/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's seccomp filter, pinned instruction by instruction.
//!
//! The filter must stay byte-identical to the one captured in the fixtures.
//! A small seccomp-BPF interpreter decodes it here, and the interpreter's
//! verdicts on the filter's untraced range are checked against the kernel's
//! in a real child.

use reverie::process::seccomp::Filter;

use super::*;

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

/// The filter's verdicts, decoded: every I386 syscall and every syscall of
/// any other non-x86_64 architecture is killed; a subscribed x86_64 number is
/// traced with data 0, `rt_sigreturn` is allowed, and with no subscription an
/// x86_64 number is allowed. (These are the plain-filter checks the deleted
/// trap-only comparison tests made.)
#[test]
fn filter_decodes_as_specified() {
    let numbers = [0u32, 1, 15, 20, 39, 59, 173, 435, 1000, u32::MAX];
    // The instruction pointers the deleted trap-only test checked, including
    // the addresses around the patch helper's former slot.
    let ips = [
        0,
        0x40_1000,
        0x7100_0002,
        0x7100_0003,
        0x7100_0004,
        0x7100_0005,
        0x7100_0006,
        0x7100_0007,
        0x8000_0002,
        0x7fff_ffff_f000,
        0x1_7100_0006,
    ];
    for events in [Subscription::all(), Subscription::none()] {
        let filter = insns(&seccomp_filter(&events, false));
        for nr in numbers {
            for ip in ips {
                assert_eq!(
                    run(&filter, nr, AUDIT_ARCH_I386, ip),
                    RET_KILL_PROCESS,
                    "plain ptrace must kill I386 nr {nr}"
                );
                for arch in [AUDIT_ARCH_AARCH64, 0] {
                    assert_eq!(run(&filter, nr, arch, ip), RET_KILL_PROCESS);
                }
            }
        }
    }
    let all = insns(&seccomp_filter(&Subscription::all(), false));
    assert_eq!(run(&all, 39, AUDIT_ARCH_X86_64, 0x40_1000), RET_TRACE);
    assert_eq!(run(&all, 15, AUDIT_ARCH_X86_64, 0x40_1000), RET_ALLOW);
    let none = insns(&seccomp_filter(&Subscription::none(), false));
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
/// `0x7100_0006` and addresses above the range in the same 4 GiB half.
#[test]
#[cfg_attr(
    reverie_asan,
    ignore = "AddressSanitizer build (cfg reverie_asan): ASan reserves [0x7fff7000, 0x10007fff8000), so MAP_FIXED_NOREPLACE of a probe stub page there fails with EEXIST; the feasible assertions run in the interpreter, low-page and high-memory tests; not a product pass"
)]
fn plain_ip_range_verdicts_match_the_kernel_witness() {
    let filter = seccomp_filter(&Subscription::all(), false);
    let all = insns(&filter);
    let mut rows = Vec::new();
    for ip in [
        0x7100_0001u64,
        0x7100_0002,
        0x7100_0003,
        0x7100_0006,
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

/// Under the filter for `Subscription::none()`, where no syscall number is
/// traced, `getpid` is allowed at every return address, and the interpreter
/// and the kernel agree: one byte either side of `0x7100_0006` (the address
/// of the patch helper's former slot return), the same low 32 bits with a
/// high bit set, the untraced range's `0x7100_0002`, and an ordinary address
/// on the same page. (These are the plain-filter probes of the deleted
/// trap-only slot rule test.)
#[test]
#[cfg_attr(
    reverie_asan,
    ignore = "AddressSanitizer build (cfg reverie_asan): ASan reserves [0x7fff7000, 0x10007fff8000), so MAP_FIXED_NOREPLACE of a probe stub page there fails with EEXIST; the feasible assertions run in the interpreter, low-page and high-memory tests; not a product pass"
)]
fn kernel_allows_every_ip_under_the_filter_for_no_syscalls() {
    let filter = seccomp_filter(&Subscription::none(), false);
    let program = insns(&filter);
    let mut rows = Vec::new();
    for ip in [
        0x7100_0006u64,
        0x7100_0005,
        0x7100_0007,
        0x1_7100_0006,
        0x7100_0002,
        0x7100_000a,
    ] {
        let interpreted = run(&program, 39, AUDIT_ARCH_X86_64, ip);
        let kernel = kernel_verdict(&filter, ip);
        if (interpreted, kernel) != (RET_ALLOW, RET_ALLOW) {
            rows.push(format!(
                "ip {ip:#x}: expected {RET_ALLOW:#x}, interpreter {interpreted:#x}, kernel {kernel:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// The interpreter half of `plain_ip_range_verdicts_match_the_kernel_witness`:
/// the same seven probes and expected verdicts without the kernel witness, so
/// it also runs where the witness cannot map its stub pages (AddressSanitizer
/// reserves [0x7fff7000, 0x10007fff8000)).
#[test]
fn plain_ip_range_interpreter_verdicts() {
    let all = insns(&seccomp_filter(&Subscription::all(), false));
    let mut rows = Vec::new();
    for ip in [
        0x7100_0001u64,
        0x7100_0002,
        0x7100_0003,
        0x7100_0006,
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
        if interpreted != expected {
            rows.push(format!(
                "ip {ip:#x}: expected {expected:#x}, interpreter {interpreted:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// `plain_ip_range_verdicts_match_the_kernel_witness` over its probes whose
/// stub pages lie below AddressSanitizer's shadow (0x7fff7000), with the same
/// assertion: the interpreter and the kernel both give the expected verdict.
#[test]
fn plain_ip_range_low_page_verdicts_match_the_kernel_witness() {
    let filter = seccomp_filter(&Subscription::all(), false);
    let all = insns(&filter);
    let mut rows = Vec::new();
    for ip in [
        0x7100_0001u64,
        0x7100_0002,
        0x7100_0003,
        0x7100_0006,
        0x7100_000a,
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

/// The interpreter half of
/// `kernel_allows_every_ip_under_the_filter_for_no_syscalls`: the same six
/// probes, each allowed, without the kernel witness.
#[test]
fn interpreter_allows_every_ip_under_the_filter_for_no_syscalls() {
    let program = insns(&seccomp_filter(&Subscription::none(), false));
    let mut rows = Vec::new();
    for ip in [
        0x7100_0006u64,
        0x7100_0005,
        0x7100_0007,
        0x1_7100_0006,
        0x7100_0002,
        0x7100_000a,
    ] {
        let interpreted = run(&program, 39, AUDIT_ARCH_X86_64, ip);
        if interpreted != RET_ALLOW {
            rows.push(format!(
                "ip {ip:#x}: expected {RET_ALLOW:#x}, interpreter {interpreted:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// `kernel_allows_every_ip_under_the_filter_for_no_syscalls` over its probes
/// whose stub pages lie below AddressSanitizer's shadow (0x7fff7000), with the
/// same assertion: the interpreter and the kernel both allow `getpid`.
#[test]
fn kernel_allows_every_low_page_ip_under_the_filter_for_no_syscalls() {
    let filter = seccomp_filter(&Subscription::none(), false);
    let program = insns(&filter);
    let mut rows = Vec::new();
    for ip in [
        0x7100_0006u64,
        0x7100_0005,
        0x7100_0007,
        0x7100_0002,
        0x7100_000a,
    ] {
        let interpreted = run(&program, 39, AUDIT_ARCH_X86_64, ip);
        let kernel = kernel_verdict(&filter, ip);
        if (interpreted, kernel) != (RET_ALLOW, RET_ALLOW) {
            rows.push(format!(
                "ip {ip:#x}: expected {RET_ALLOW:#x}, interpreter {interpreted:#x}, kernel {kernel:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// The high 32-bit half of the plain filter's untraced range, from stub pages
/// in high application memory (above AddressSanitizer's shadow, which ends at
/// 0x10007fff8000, and ordinary user memory in every build): `0x1001_7100_0002`
/// has the range's low word with a high word set and `0x1002_0000_0002` is
/// another high address; both are traced, by the interpreter and the kernel,
/// with the assertion of `plain_ip_range_verdicts_match_the_kernel_witness`.
#[test]
fn plain_ip_range_high_memory_verdicts_match_the_kernel_witness() {
    let filter = seccomp_filter(&Subscription::all(), false);
    let all = insns(&filter);
    let mut rows = Vec::new();
    for ip in [0x1001_7100_0002u64, 0x1002_0000_0002] {
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

/// `kernel_allows_every_ip_under_the_filter_for_no_syscalls` from a stub page
/// in high application memory: `0x1001_7100_0006`, the low 32 bits of the
/// patch helper's former slot return with a high word set, is allowed by the
/// interpreter and the kernel.
#[test]
fn kernel_allows_a_high_memory_ip_under_the_filter_for_no_syscalls() {
    let filter = seccomp_filter(&Subscription::none(), false);
    let program = insns(&filter);
    let mut rows = Vec::new();
    {
        let ip = 0x1001_7100_0006u64;
        let interpreted = run(&program, 39, AUDIT_ARCH_X86_64, ip);
        let kernel = kernel_verdict(&filter, ip);
        if (interpreted, kernel) != (RET_ALLOW, RET_ALLOW) {
            rows.push(format!(
                "ip {ip:#x}: expected {RET_ALLOW:#x}, interpreter {interpreted:#x}, kernel {kernel:#x}"
            ));
        }
    }
    assert!(rows.is_empty(), "wrong verdicts:\n{}", rows.join("\n"));
}

/// The kernel applies the filter's I386 route: an untraced child that loads
/// the filter for `Subscription::none()` and then makes an I386 `getpid`
/// through `int 0x80` is killed with SIGSYS, after an x86_64 `getpid` from
/// ordinary code is allowed through. (This is the plain-filter arm of the
/// deleted trap-only I386 route test.)
#[test]
fn kernel_kills_an_i386_syscall_with_sigsys() {
    let filter = seccomp_filter(&Subscription::none(), false);
    // SAFETY: the child only makes raw syscalls and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe {
            // A SIGSYS kill must not dump core.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 || filter.load().is_err() {
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
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS,
        "I386 getpid was not killed with SIGSYS (status {status:#x})"
    );
}
