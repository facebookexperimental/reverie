/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The ptrace backend's untraced window is one return address.
//!
//! `seccomp_filter` lets a syscall through untraced only when it returns to
//! `TRAMPOLINE_BASE + SYSCALL_INSTR_SIZE` (`0x7100_0002`), the untraced stub
//! of Reverie's private page. Every other subscribed syscall must stop the
//! tracer, including syscalls issued from guest code mapped elsewhere below
//! 4 GiB (for example `MAP_32BIT` JIT code).

use std::sync::Mutex;

use reverie::Guest;
use reverie::process::seccomp::Filter;
use reverie::syscalls::Syscall;

use super::*;

const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_TRACE: u32 = libc::SECCOMP_RET_TRACE;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// Runs a seccomp-BPF program in user space on
/// `seccomp_data { nr, arch, instruction_pointer }` and returns its verdict.
/// Only the instructions `FilterBuilder` emits are modelled.
fn run(filter: &Filter, nr: u32, arch: u32, ip: u64) -> u32 {
    let (mut acc, mut mem, mut pc) = (0u32, [0u32; 16], 0usize);
    let program = filter.instructions();
    loop {
        let insn = program
            .get(pc)
            .unwrap_or_else(|| panic!("fell off the program at {pc}"));
        pc += 1;
        let jump = |taken: bool| usize::from(if taken { insn.jt } else { insn.jf });
        match insn.code {
            // BPF_LD | BPF_W | BPF_ABS
            0x20 => {
                acc = match insn.k {
                    0 => nr,
                    4 => arch,
                    8 => ip as u32,
                    12 => (ip >> 32) as u32,
                    k => panic!("load of unmodelled seccomp_data offset {k}"),
                }
            }
            // BPF_ST
            0x02 => mem[insn.k as usize] = acc,
            // BPF_LD | BPF_MEM
            0x60 => acc = mem[insn.k as usize],
            // BPF_JMP | BPF_JEQ | BPF_K
            0x15 => pc += jump(acc == insn.k),
            // BPF_JMP | BPF_JGT | BPF_K
            0x25 => pc += jump(acc > insn.k),
            // BPF_JMP | BPF_JGE | BPF_K
            0x35 => pc += jump(acc >= insn.k),
            // BPF_RET | BPF_K
            0x06 => return insn.k,
            code => panic!("unmodelled opcode {code:#x} at {}", pc - 1),
        }
    }
}

/// Decodes the backend filter: with every syscall subscribed, exactly the
/// return address `0x7100_0002` is allowed untraced; any other address,
/// including the rest of the low 4 GiB above it, is traced.
#[test]
fn only_the_untraced_stub_return_address_bypasses_the_tracer() {
    let untraced = (cp::TRAMPOLINE_BASE + cp::SYSCALL_INSTR_SIZE) as u64;
    assert_eq!(untraced, 0x7100_0002);
    let all = seccomp_filter(&Subscription::all(), false);
    let none = seccomp_filter(&Subscription::none(), false);
    let getpgid = Sysno::getpgid as u32;
    let mut wrong = Vec::new();
    for ip in [
        0,
        0x40_0000,
        untraced - 2,
        untraced - 1,
        untraced,
        untraced + 1,
        untraced + 4,
        0x7100_1000,
        0x7200_0002,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1_0000_0000,
        0x1_7100_0002,
        0x7fff_ffff_f000,
    ] {
        let expected = if ip == untraced { RET_ALLOW } else { RET_TRACE };
        let got = run(&all, getpgid, AUDIT_ARCH_X86_64, ip);
        if got != expected {
            wrong.push(format!("ip {ip:#x}: {got:#x}, expected {expected:#x}"));
        }
        // Unsubscribed syscalls are never traced, and rt_sigreturn is always
        // allowed.
        assert_eq!(run(&none, getpgid, AUDIT_ARCH_X86_64, ip), RET_ALLOW);
        assert_eq!(
            run(&all, Sysno::rt_sigreturn as u32, AUDIT_ARCH_X86_64, ip),
            RET_ALLOW
        );
    }
    assert!(
        wrong.is_empty(),
        "{} addresses routed wrongly:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// `getpgid` arguments that name no process (above the largest `pid_max`),
/// one per call site, so each observed syscall identifies where it came from.
const TAG_LIBC: u64 = 0x7fff_0001;
const TAG_LOW: u64 = 0x7fff_0002;
const TAG_HIGH: u64 = 0x7fff_0003;

/// Pages mapped by the guest, in the part of the low 4 GiB the old filter let
/// through untraced (`[0x7100_0002, 0xffff_ffff]`).
const LOW_PAGE: u64 = 0x7200_0000;
const HIGH_PAGE: u64 = 0xffff_e000;

const EXIT_MAP_FAILED: i32 = 71;

#[derive(Default)]
struct Observed(Mutex<Vec<(u64, u64)>>);

#[reverie::global_tool]
impl GlobalTool for Observed {
    type Config = ();
    type Request = (u64, u64);
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, call: (u64, u64)) {
        self.0.lock().unwrap().push(call);
    }
}

#[derive(Default)]
struct GetpgidWatcher;

#[reverie::tool]
impl Tool for GetpgidWatcher {
    type GlobalState = Observed;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut events = Subscription::none();
        events.syscalls([Sysno::getpgid]);
        events
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let regs = guest.regs().await;
        guest.send_rpc((regs.rdi, regs.rip)).await;
        guest.tail_inject(call).await
    }
}

/// Maps a `syscall; ret` stub at `page` and calls `getpgid(tag)` through it,
/// so the syscall's return address is `page + 2`.
fn getpgid_from_page(page: u64, tag: u64) -> i64 {
    // SAFETY: the page is fresh (MAP_FIXED_NOREPLACE) and only this stub runs
    // there; the call clobbers exactly what `syscall` clobbers.
    unsafe {
        let base = libc::mmap(
            page as *mut libc::c_void,
            0x1000,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        );
        if base as u64 != page {
            libc::_exit(EXIT_MAP_FAILED);
        }
        // syscall; ret
        std::ptr::copy_nonoverlapping([0x0f, 0x05, 0xc3u8].as_ptr(), page as *mut u8, 3);
        let ret: i64;
        std::arch::asm!(
            "call {stub}",
            stub = in(reg) page,
            inlateout("rax") libc::SYS_getpgid => ret,
            in("rdi") tag,
            out("rcx") _,
            out("r11") _,
        );
        ret
    }
}

/// A live guest issues a subscribed syscall from code at `0x7200_0000` and at
/// `0xffff_e000`; the tool must observe both, as it observes the ordinary
/// libc call.
#[test]
fn subscribed_syscalls_from_low_guest_code_are_traced() {
    let (output, observed) = crate::testing::test_fn::<GetpgidWatcher, _>(|| {
        let libc_ret = unsafe { libc::syscall(libc::SYS_getpgid, TAG_LIBC) };
        let low = getpgid_from_page(LOW_PAGE, TAG_LOW);
        let high = getpgid_from_page(HIGH_PAGE, TAG_HIGH);
        // No such process: each call reached the kernel (traced or not).
        assert_eq!(libc_ret, -1);
        assert_eq!(low, -(libc::ESRCH as i64));
        assert_eq!(high, -(libc::ESRCH as i64));
    })
    .unwrap();
    assert_ne!(
        output.status,
        ExitStatus::Exited(EXIT_MAP_FAILED),
        "the guest could not map its stub pages"
    );
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "guest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observed = observed.0.lock().unwrap().clone();
    let tagged: Vec<(u64, u64)> = observed
        .into_iter()
        .filter(|(tag, _)| [TAG_LIBC, TAG_LOW, TAG_HIGH].contains(tag))
        .collect();
    let seen = |tag: u64, ip: Option<u64>| {
        tagged
            .iter()
            .any(|&(t, rip)| t == tag && ip.is_none_or(|ip| rip == ip))
    };
    assert!(seen(TAG_LIBC, None), "control not traced: {tagged:x?}");
    assert!(
        seen(TAG_LOW, Some(LOW_PAGE + 2)),
        "syscall returning to {:#x} escaped the tracer: {tagged:x?}",
        LOW_PAGE + 2
    );
    assert!(
        seen(TAG_HIGH, Some(HIGH_PAGE + 2)),
        "syscall returning to {:#x} escaped the tracer: {tagged:x?}",
        HIGH_PAGE + 2
    );
    assert_eq!(tagged.len(), 3, "each call observed once: {tagged:x?}");
}
