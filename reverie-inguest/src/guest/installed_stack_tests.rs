/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Native controls of the production entry, not actual Detcore placement.
//!
//! Reservation, signal and irreversible-filter controls run in dedicated
//! re-executed test processes. Test worker threads exercise private ownership
//! concurrency; they do not expand the supported guest thread population.
//! No existing guest-stack, allocator, constructor or leaf oracle is changed.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use iced_x86::Decoder;
use iced_x86::DecoderOptions;
use iced_x86::Mnemonic;

use super::*;
use crate::trap::raw_syscall6;

const CHILD_ENV: &str = "REVERIE_INSTALLED_STACK_CONTROL_CHILD";
const OUTPUT_LIMIT: usize = 128 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);
const FORK_DEADLINE: Duration = Duration::from_secs(3);

#[path = "installed_stack_external_tests.rs"]
mod external;

// Each use owns the only child/tracee population in its isolated control.
// Reap stopped ptrace children explicitly on assertion unwinding as well as
// on the normal path. This is a bounded cleanup attempt, not a guarantee
// against a kernel task that cannot be killed/reaped; the outer box remains
// the final backstop.
struct OwnedProcess {
    pid: i64,
    group: bool,
    armed: bool,
}

impl OwnedProcess {
    fn new(pid: i64) -> Self {
        Self {
            pid,
            group: false,
            armed: true,
        }
    }

    fn complete(&mut self) {
        self.armed = false;
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let target = if self.group { -self.pid } else { self.pid };
        raw(
            libc::SYS_kill,
            [target as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
        );
        let end = Instant::now() + FORK_DEADLINE;
        loop {
            let mut status = 0_i32;
            let got = raw(
                libc::SYS_wait4,
                [
                    u64::MAX,
                    (&raw mut status) as u64,
                    (libc::WNOHANG | libc::__WALL) as u64,
                    0,
                    0,
                    0,
                ],
            );
            if got > 0 {
                if libc::WIFSTOPPED(status) {
                    raw(
                        libc::SYS_ptrace,
                        [
                            libc::PTRACE_CONT as u64,
                            got as u64,
                            0,
                            libc::SIGKILL as u64,
                            0,
                            0,
                        ],
                    );
                }
                continue;
            }
            if got == -i64::from(libc::ECHILD) {
                return;
            }
            if got != 0 && got != -i64::from(libc::EINTR) {
                eprintln!(
                    "owned cleanup pid{}: wait4={got}, status={status:#x}",
                    self.pid
                );
                return;
            }
            if Instant::now() >= end {
                eprintln!(
                    "owned cleanup pid{}: bounded kill/reap attempt expired",
                    self.pid
                );
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn raw(number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: each control supplies live scalar buffers and owned ranges.
    unsafe { raw_syscall6(number, args) }
}

fn raw_exit(code: i32) -> ! {
    raw(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]);
    // SAFETY: a returned terminal syscall is not allowed to return to a test.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

fn capture(mut stream: impl Read) -> io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut exceeded = false;
    let mut buffer = [0_u8; 4096];
    loop {
        let count = match stream.read(&mut buffer) {
            Ok(0) => return Ok((output, exceeded)),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let retained = count.min(OUTPUT_LIMIT - output.len());
        output.extend_from_slice(&buffer[..retained]);
        exceeded |= retained != count;
        // Continue draining; an exceeded cap still fails the control.
    }
}

fn exact_name(name: &str) -> String {
    let module = module_path!().split_once("::").unwrap().1;
    format!("{module}::{name}")
}

fn isolated(name: &str, body: fn()) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        body();
        println!("\nINSTALLED_STACK_CONTROL_OK:{name}");
        return;
    }
    let exact = exact_name(name);
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &exact, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut ownership = OwnedProcess::new(i64::from(child.id()));
    ownership.group = true;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || capture(stdout));
    let err_reader = std::thread::spawn(move || capture(stderr));
    let group = -(child.id() as i32);
    let end = Instant::now() + DEADLINE;
    let mut timed_out = false;
    // Observe completion without reaping, keeping the process-group identity
    // reserved until all descendants have been cleaned up.
    loop {
        let mut info = core::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        assert_eq!(result, 0, "{exact}: waitid: {}", io::Error::last_os_error());
        if unsafe { info.assume_init().si_pid() } != 0 {
            break;
        }
        if Instant::now() >= end {
            timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // This dedicated group is still owned, including its unreaped leader.
    let killed = unsafe { libc::kill(group, libc::SIGKILL) };
    assert!(killed == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    let reap_end = Instant::now() + FORK_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < reap_end,
            "{exact}: killed leader was not reaped"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    ownership.complete();
    let drain_end = Instant::now() + FORK_DEADLINE;
    while !out_reader.is_finished() || !err_reader.is_finished() {
        assert!(Instant::now() < drain_end, "{exact}: output did not close");
        std::thread::sleep(Duration::from_millis(5));
    }
    let (out, out_exceeded) = out_reader.join().unwrap().unwrap();
    let (err, err_exceeded) = err_reader.join().unwrap().unwrap();
    let out = String::from_utf8_lossy(&out);
    let err = String::from_utf8_lossy(&err);
    // Print the retained bounded bytes before any observation assertion.
    // A failed marker/status/cap must not discard its child diagnostics.
    print!("{out}");
    eprint!("{err}");
    assert!(!timed_out, "{exact}: exceeded {DEADLINE:?}");
    assert!(
        !out_exceeded && !err_exceeded,
        "{exact}: output cap exceeded"
    );
    assert!(status.success(), "{exact}: {status}\n{out}\n{err}");
    let marker = format!("INSTALLED_STACK_CONTROL_OK:{name}");
    assert_eq!(out.lines().filter(|line| *line == marker).count(), 1);
}

fn wait_raw(pid: i64) -> i32 {
    let mut end = Instant::now() + FORK_DEADLINE;
    let mut killed = false;
    loop {
        let mut status = 0;
        let result = raw(
            libc::SYS_wait4,
            [
                pid as u64,
                (&raw mut status) as u64,
                libc::WNOHANG as u64,
                0,
                0,
                0,
            ],
        );
        if result == pid {
            assert!(
                !killed,
                "raw child {pid} timed out; actual cleanup status {status:#x}"
            );
            return status;
        }
        assert!(result == 0 || result == -i64::from(libc::EINTR));
        if !killed && Instant::now() >= end {
            raw(
                libc::SYS_kill,
                [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0],
            );
            killed = true;
            end = Instant::now() + FORK_DEADLINE;
        }
        assert!(
            !killed || Instant::now() < end,
            "raw child {pid}: kill was not reaped"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn expect_exit(status: i32, code: i32) {
    assert!(libc::WIFEXITED(status), "status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), code);
}

fn pool() -> &'static Pool {
    let pointer = LOCATOR.load(Ordering::Acquire);
    assert_ne!(pointer, 0);
    unsafe { &*(pointer as *const Pool) }
}

fn slot_of(rsp: usize) -> usize {
    snapshot()
        .unwrap()
        .slots
        .iter()
        .position(|slot| slot.bottom <= rsp && rsp < slot.top)
        .expect("actual native body RSP must be in one precise slot")
}

#[repr(C)]
#[derive(Default)]
struct Sample {
    rsp: usize,
    context: usize,
    word: u64,
}

#[unsafe(naked)]
unsafe extern "C" fn sample(_context: *mut libc::c_void) {
    core::arch::naked_asm!(
        "endbr64",
        "mov [rdi], rsp",
        "mov [rdi + 8], rdi",
        "mov rax, [rip + {locator}]",
        "mov rax, [rax]",
        "mov [rdi + 16], rax",
        "mov rax, 0x5152535455565758",
        "ret",
        locator = sym LOCATOR,
    );
}

#[test]
fn preparation_is_nonwaiting_and_publishes_all_guarded_leases() {
    isolated(
        "preparation_is_nonwaiting_and_publishes_all_guarded_leases",
        || {
            assert!(snapshot().is_none());
            PREPARING.store(true, Ordering::Release);
            assert_eq!(prepare().unwrap_err().raw_os_error(), Some(libc::EAGAIN));
            assert!(snapshot().is_none());
            PREPARING.store(false, Ordering::Release);
            let token = prepare().unwrap();
            assert!(!core::mem::needs_drop::<PreparedCallbacks>());
            let _copied = token;
            let before = snapshot().unwrap();
            let _again = prepare().unwrap();
            assert_eq!(before.address, snapshot().unwrap().address);
            assert_eq!(before.occupied, 0);
            assert_eq!(before.address % 64, 0);
            assert_eq!(before.metadata.bottom, before.address);
            assert_eq!(before.metadata.top - before.metadata.bottom, PAGE);
            let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
            let permission = |address: usize| {
                maps.lines()
                    .find_map(|line| {
                        let mut fields = line.split_whitespace();
                        let (start, end) = fields.next()?.split_once('-')?;
                        let start = usize::from_str_radix(start, 16).ok()?;
                        let end = usize::from_str_radix(end, 16).ok()?;
                        (start <= address && address < end).then(|| fields.next().unwrap())
                    })
                    .unwrap()
            };
            for (index, stack) in before.slots.iter().enumerate() {
                assert_eq!(stack.top - stack.bottom, STACK_BYTES);
                assert_eq!(stack.extent_start + PAGE, stack.bottom);
                assert_eq!(stack.top + PAGE, stack.extent_end);
                assert!(super::super::tool_region::BASE <= stack.extent_start);
                assert!(stack.extent_end <= super::super::tool_region::END);
                assert_eq!(permission(stack.bottom), "rw-p");
                assert_eq!(permission(stack.top - 1), "rw-p");
                assert_eq!(permission(stack.extent_start), "---p");
                assert_eq!(permission(stack.top), "---p");
                for previous in &before.slots[..index] {
                    assert!(
                        previous.extent_end <= stack.extent_start
                            || stack.extent_end <= previous.extent_start
                    );
                }
                assert!(
                    before.metadata.extent_end <= stack.extent_start
                        || stack.extent_end <= before.metadata.extent_start
                );
            }
            println!("native preparation: actual64 guarded leases; no real Detcore claim");
        },
    );
}

unsafe extern "C" {
    static reverie_inguest_installed_callback_entry_end: u8;
}

#[test]
fn production_entry_has_no_conditional_branch_and_one_body_call() {
    let start = entry as *const () as usize;
    let end = (&raw const reverie_inguest_installed_callback_entry_end) as usize;
    assert!(start < end && end - start < 4096);
    let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, end - start) };
    assert_eq!(&bytes[..4], &[0xf3, 0x0f, 0x1e, 0xfa]);
    let mut decoder = Decoder::with_ip(64, bytes, start as u64, DecoderOptions::NONE);
    let mut calls = 0;
    let mut returns = 0;
    let mut bits = 0;
    let mut release = 0;
    while decoder.can_decode() {
        let instruction = decoder.decode();
        assert!(!instruction.is_invalid(), "{instruction:?}");
        assert!(
            !matches!(
                instruction.mnemonic(),
                Mnemonic::Jo
                    | Mnemonic::Jno
                    | Mnemonic::Jb
                    | Mnemonic::Jae
                    | Mnemonic::Je
                    | Mnemonic::Jne
                    | Mnemonic::Jbe
                    | Mnemonic::Ja
                    | Mnemonic::Js
                    | Mnemonic::Jns
                    | Mnemonic::Jp
                    | Mnemonic::Jnp
                    | Mnemonic::Jl
                    | Mnemonic::Jge
                    | Mnemonic::Jle
                    | Mnemonic::Jg
                    | Mnemonic::Jcxz
                    | Mnemonic::Jecxz
                    | Mnemonic::Jrcxz
                    | Mnemonic::Loop
                    | Mnemonic::Loope
                    | Mnemonic::Loopne
            ),
            "pre-clock or epilogue Jcc: {instruction:?}"
        );
        calls += usize::from(instruction.mnemonic() == Mnemonic::Call);
        returns += usize::from(instruction.mnemonic() == Mnemonic::Ret);
        bits +=
            usize::from(instruction.mnemonic() == Mnemonic::Bts && instruction.has_lock_prefix());
        release +=
            usize::from(instruction.mnemonic() == Mnemonic::And && instruction.has_lock_prefix());
        assert_ne!(
            instruction.mnemonic(),
            Mnemonic::Syscall,
            "only the existing private gate is used"
        );
    }
    assert_eq!(decoder.position(), bytes.len());
    assert_eq!((calls, returns, bits, release), (1, 1, 1, 1));
}

#[repr(C)]
struct AbiObservation {
    registers: [usize; 6],
    entry_rsp: usize,
    expected_return: usize,
    actual_return: usize,
    before: [u8; 264],
    after: [u8; 264],
    scalar: usize,
}

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global installed_stack_abi_observe
    .hidden installed_stack_abi_observe
    .type installed_stack_abi_observe,@function
installed_stack_abi_observe:
    endbr64
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    mov r14, rdi
    mov [rsp + 280], rsi
    mov r13, rdx
    mov [rsp + 288], rcx
    mov rdi, rsp
    mov ecx, 33
    mov rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rsi, rsp
    lea rdi, [r13 + 72]
    mov ecx, 264
    rep movsb
    lea rax, [rsp + 264]
    mov [r13 + 48], rax
    lea rax, [rip + .Linstalled_abi_return]
    mov [r13 + 56], rax
    mov [rsp + 264], rax
    cmp qword ptr [rsp + 288], 0
    je .Linstalled_abi_clean
    mov byte ptr [rsp + 100], 0x33
.Linstalled_abi_clean:
    mov rbx, 0x123456789abcdef0
    mov rbp, 0x23456789abcdef01
    mov r12, 0x3456789abcdef012
    mov r15, 0x456789abcdef0123
    mov rsi, [rsp + 280]
    mov rdi, r14
    add rsp, 272
    call {entry}
.Linstalled_abi_return:
    endbr64
    mov [r13 + 600], rax
    mov [r13], rbx
    mov [r13 + 8], rbp
    mov [r13 + 16], r12
    mov [r13 + 24], r13
    mov [r13 + 32], r14
    mov [r13 + 40], r15
    mov rax, [rsp - 8]
    mov [r13 + 64], rax
    sub rsp, 272
    mov rsi, rsp
    lea rdi, [r13 + 336]
    mov ecx, 264
    rep movsb
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    .size installed_stack_abi_observe, .-installed_stack_abi_observe
    "#,
    entry = sym entry,
);

unsafe extern "C" {
    fn installed_stack_abi_observe(
        context: *mut libc::c_void,
        body: unsafe extern "C" fn(*mut libc::c_void),
        output: *mut AbiObservation,
        corrupt: usize,
    );
}

#[test]
fn real_abi_scalar_callee_state_return_slot_and_literal_red_zone() {
    isolated(
        "real_abi_scalar_callee_state_return_slot_and_literal_red_zone",
        || {
            prepare().unwrap();
            for corrupt in [0, 1] {
                let mut context = Sample::default();
                let mut observed = AbiObservation {
                    registers: [0; 6],
                    entry_rsp: 0,
                    expected_return: 0,
                    actual_return: 0,
                    before: [0; 264],
                    after: [0; 264],
                    scalar: 0,
                };
                let output = (&raw mut observed) as usize;
                let argument = (&raw mut context) as usize;
                unsafe {
                    installed_stack_abi_observe(
                        argument as *mut _,
                        sample,
                        &raw mut observed,
                        corrupt,
                    )
                };
                assert_eq!(
                    observed.registers,
                    [
                        0x1234_5678_9abc_def0,
                        0x2345_6789_abcd_ef01,
                        0x3456_789a_bcde_f012,
                        output,
                        argument,
                        0x4567_89ab_cdef_0123
                    ]
                );
                assert_eq!(observed.entry_rsp % 16, 8);
                assert_eq!(observed.expected_return, observed.actual_return);
                assert_eq!(observed.scalar, 0x5152_5354_5556_5758);
                assert_eq!(context.context, argument);
                let slot = slot_of(context.rsp);
                assert_eq!(context.rsp, snapshot().unwrap().slots[slot].top - 40);
                assert_eq!(context.rsp % 16, 8);
                assert_eq!(context.word, 1_u64 << slot);
                assert_eq!(snapshot().unwrap().occupied, 0);
                assert_eq!(observed.before, [0xa5; 264]);
                let changes = observed
                    .before
                    .iter()
                    .zip(&observed.after)
                    .filter(|(a, b)| a != b)
                    .count();
                assert_eq!(
                    changes, corrupt,
                    "literal comparator must detect the positive writer"
                );
                if corrupt != 0 {
                    assert_eq!(observed.after[100], 0x33);
                }
            }
            println!(
                "native264-byte ABI control only; earlier69632-byte LI window remains separate"
            );
        },
    );
}

#[repr(C)]
struct Nested {
    rsp: usize,
    depth: usize,
    target: usize,
    failed: bool,
}

#[unsafe(naked)]
unsafe extern "C" fn nested(_context: *mut libc::c_void) {
    core::arch::naked_asm!("endbr64", "mov [rdi], rsp", "jmp {body}", body = sym nested_body);
}

unsafe extern "C" fn nested_body(context: *mut libc::c_void) {
    let frame = unsafe { &mut *context.cast::<Nested>() };
    let index = slot_of(frame.rsp);
    let before = pool().occupied.load(Ordering::Acquire);
    let mut canary = [0x57_u8; 512];
    unsafe { core::ptr::write_volatile(canary.as_mut_ptr(), 0x91) };
    frame.failed |= before.count_ones() as usize != frame.depth + 1 || before & (1 << index) == 0;
    if frame.depth < frame.target {
        let mut child = Nested {
            rsp: 0,
            depth: frame.depth + 1,
            target: frame.target,
            failed: false,
        };
        unsafe { entry((&raw mut child).cast(), nested) };
        frame.failed |= child.failed || child.rsp == frame.rsp;
    }
    frame.failed |= pool().occupied.load(Ordering::Acquire) != before;
    frame.failed |=
        unsafe { core::ptr::read_volatile(canary.as_ptr()) } != 0x91 || canary[1..] != [0x57; 511];
}

#[test]
fn nested_callbacks_preserve_exact_live_bits_and_outer_stack() {
    isolated(
        "nested_callbacks_preserve_exact_live_bits_and_outer_stack",
        || {
            prepare().unwrap();
            let mut context = Nested {
                rsp: 0,
                depth: 0,
                target: 7,
                failed: false,
            };
            unsafe { entry((&raw mut context).cast(), nested) };
            assert!(!context.failed);
            assert_eq!(snapshot().unwrap().occupied, 0);
        },
    );
}

#[repr(C)]
struct Parked {
    rsp: AtomicUsize,
    entered: core::sync::atomic::AtomicU32,
    release: core::sync::atomic::AtomicU32,
    word: AtomicU64,
}

impl Parked {
    fn new() -> Self {
        Self {
            rsp: AtomicUsize::new(0),
            entered: core::sync::atomic::AtomicU32::new(0),
            release: core::sync::atomic::AtomicU32::new(0),
            word: AtomicU64::new(0),
        }
    }
    fn wait_entered(&self) {
        let end = Instant::now() + FORK_DEADLINE;
        while self.entered.load(Ordering::Acquire) == 0 {
            assert!(Instant::now() < end, "callback did not enter");
            std::thread::yield_now();
        }
    }
    fn leave(&self) {
        self.release.store(1, Ordering::Release);
        raw(
            libc::SYS_futex,
            [
                (&raw const self.release) as u64,
                (libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG) as u64,
                1,
                0,
                0,
                0,
            ],
        );
    }
}

#[unsafe(naked)]
unsafe extern "C" fn parked(_context: *mut libc::c_void) {
    core::arch::naked_asm!("endbr64", "mov [rdi], rsp", "jmp {body}", body = sym parked_body);
}

unsafe extern "C" fn parked_body(context: *mut libc::c_void) {
    let context = unsafe { &*context.cast::<Parked>() };
    context
        .word
        .store(pool().occupied.load(Ordering::Acquire), Ordering::Relaxed);
    context.entered.store(1, Ordering::Release);
    while context.release.load(Ordering::Acquire) == 0 {
        raw(
            libc::SYS_futex,
            [
                (&raw const context.release) as u64,
                (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as u64,
                0,
                0,
                0,
                0,
            ],
        );
    }
}

#[test]
fn out_of_order_completion_never_reuses_a_live_slot() {
    isolated("out_of_order_completion_never_reuses_a_live_slot", || {
        prepare().unwrap();
        let a = Parked::new();
        let b = Parked::new();
        let c = Parked::new();
        std::thread::scope(|threads| {
            fn run(state: &Parked) {
                unsafe { entry((state as *const Parked).cast_mut().cast(), parked) }
            }
            let first = threads.spawn(|| run(&a));
            a.wait_entered();
            let second = threads.spawn(|| run(&b));
            b.wait_entered();
            let a_slot = slot_of(a.rsp.load(Ordering::Acquire));
            let b_slot = slot_of(b.rsp.load(Ordering::Acquire));
            assert_ne!(a_slot, b_slot);
            a.leave();
            first.join().unwrap();
            assert_eq!(pool().occupied.load(Ordering::Acquire), 1_u64 << b_slot);
            let third = threads.spawn(|| run(&c));
            c.wait_entered();
            let c_slot = slot_of(c.rsp.load(Ordering::Acquire));
            assert_eq!(c_slot, a_slot);
            assert_ne!(c_slot, b_slot);
            assert_eq!(
                pool().occupied.load(Ordering::Acquire),
                (1_u64 << b_slot) | (1_u64 << c_slot)
            );
            c.leave();
            third.join().unwrap();
            assert_eq!(pool().occupied.load(Ordering::Acquire), 1_u64 << b_slot);
            b.leave();
            second.join().unwrap();
        });
        assert_eq!(pool().occupied.load(Ordering::Acquire), 0);
    });
}

#[repr(C)]
struct Forked {
    rsp: usize,
    child: i64,
    prior: u64,
}

#[unsafe(naked)]
unsafe extern "C" fn forked(_context: *mut libc::c_void) {
    core::arch::naked_asm!("endbr64", "mov [rdi], rsp", "jmp {body}", body = sym forked_body);
}

unsafe extern "C" fn forked_body(context: *mut libc::c_void) {
    let context = unsafe { &mut *context.cast::<Forked>() };
    context.prior = pool().occupied.load(Ordering::Acquire);
    context.child = raw(libc::SYS_fork, [0; 6]);
}

#[test]
fn plain_fork_returns_its_own_bit_and_retains_vanished_worker_holes() {
    isolated(
        "plain_fork_returns_its_own_bit_and_retains_vanished_worker_holes",
        || {
            prepare().unwrap();
            let other = Parked::new();
            std::thread::scope(|threads| {
                let worker = threads
                    .spawn(|| unsafe { entry((&raw const other).cast_mut().cast(), parked) });
                other.wait_entered();
                let hole = 1_u64 << slot_of(other.rsp.load(Ordering::Acquire));
                let mut context = Forked {
                    rsp: 0,
                    child: -1,
                    prior: 0,
                };
                unsafe { entry((&raw mut context).cast(), forked) };
                if context.child == 0 {
                    // Only raw/COW reads and exit: no post-fork libc allocation,
                    // unwinding or joining the vanished std worker.
                    if pool().occupied.load(Ordering::Acquire) != hole
                        || context.prior.count_ones() != 2
                    {
                        raw_exit(91);
                    }
                    raw_exit(0);
                }
                assert!(context.child > 0);
                assert_eq!(context.prior.count_ones(), 2);
                assert_eq!(pool().occupied.load(Ordering::Acquire), hole);
                expect_exit(wait_raw(context.child), 0);
                other.leave();
                worker.join().unwrap();
            });
            assert_eq!(pool().occupied.load(Ordering::Acquire), 0);
        },
    );
}

fn read_mask() -> u64 {
    let mut mask = 0;
    assert_eq!(
        raw(
            libc::SYS_rt_sigprocmask,
            [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0]
        ),
        0
    );
    mask
}

fn altstack() -> libc::stack_t {
    let mut stack = unsafe { core::mem::zeroed::<libc::stack_t>() };
    assert_eq!(
        raw(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0]
        ),
        0
    );
    stack
}

fn readable_byte(address: usize) -> i64 {
    let mut byte = 0_u8;
    let local = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: address as *mut _,
        iov_len: 1,
    };
    raw(
        libc::SYS_process_vm_readv,
        [
            raw(libc::SYS_getpid, [0; 6]) as u64,
            (&raw const local) as u64,
            1,
            (&raw const remote) as u64,
            1,
            0,
        ],
    )
}

static OUTER_FIRST: AtomicUsize = AtomicUsize::new(0);
static INNER_FIRST: AtomicUsize = AtomicUsize::new(0);
static OUTER_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static INNER_CALLBACK: AtomicUsize = AtomicUsize::new(0);
static ALT_FAILURES: AtomicUsize = AtomicUsize::new(0);

#[unsafe(naked)]
unsafe extern "C" fn outer_signal(
    _number: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    core::arch::naked_asm!("endbr64", "mov [rip + {first}], rsp", "jmp {body}", first = sym OUTER_FIRST, body = sym outer_signal_body);
}

#[unsafe(naked)]
unsafe extern "C" fn inner_signal(
    _number: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    core::arch::naked_asm!("endbr64", "mov [rip + {first}], rsp", "jmp {body}", first = sym INNER_FIRST, body = sym inner_signal_body);
}

fn signal_sample(output: &AtomicUsize) {
    let mask = read_mask();
    let before = pool().occupied.load(Ordering::Acquire);
    let mut observed = Sample::default();
    unsafe { entry((&raw mut observed).cast(), sample) };
    output.store(observed.rsp, Ordering::Release);
    if before != observed.word
        || pool().occupied.load(Ordering::Acquire) != before
        || read_mask() != mask
        || altstack().ss_flags & libc::SS_ONSTACK == 0
    {
        ALT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe extern "C" fn outer_signal_body(
    _number: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    let mut canary = [0x97_u8; 1024];
    unsafe { core::ptr::write_volatile(canary.as_mut_ptr(), 0x23) };
    signal_sample(&OUTER_CALLBACK);
    if unsafe { crate::signal::raw_raise(libc::SIGUSR2) }.is_err() {
        ALT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if unsafe { core::ptr::read_volatile(canary.as_ptr()) } != 0x23 || canary[1..] != [0x97; 1023] {
        ALT_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe extern "C" fn inner_signal_body(
    _number: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    signal_sample(&INNER_CALLBACK);
}

#[test]
fn genuine_registered_altstack_keeps_current_position_and_nested_frames() {
    isolated(
        "genuine_registered_altstack_keeps_current_position_and_nested_frames",
        || {
            prepare().unwrap();
            let region = ToolRegion::reserve().unwrap();
            assert!(region.registered_alternate_stack().is_none());
            let base = unsafe {
                crate::signal::install_alt_stack_with_backing(
                    super::super::tool_region::StackBacking::ToolRegion(region),
                )
            }
            .unwrap() as usize;
            let registered = region.registered_alternate_stack().unwrap();
            let kernel = altstack();
            assert_eq!(kernel.ss_sp as usize, base);
            assert_eq!(kernel.ss_size, registered.top - registered.bottom);
            assert_eq!(registered.bottom, base);
            assert_eq!(registered.extent_start + PAGE, base);
            assert_eq!(registered.extent_end, registered.top + PAGE);
            assert_eq!(readable_byte(base), 1);
            assert_eq!(readable_byte(registered.top - 1), 1);
            assert_eq!(readable_byte(base - 1), -i64::from(libc::EFAULT));
            assert_eq!(readable_byte(registered.top), -i64::from(libc::EFAULT));
            unsafe {
                crate::signal::install_runtime_handler(
                    libc::SIGUSR1,
                    outer_signal,
                    libc::SA_ONSTACK,
                )
                .unwrap();
                crate::signal::install_runtime_handler(
                    libc::SIGUSR2,
                    inner_signal,
                    libc::SA_ONSTACK,
                )
                .unwrap();
            }
            let mask = read_mask() & !((1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1)));
            unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&mask), None) }
                .unwrap();
            for word in [0, u64::MAX] {
                // The all-ones case is explicitly a representation control. The
                // separate capacity control must fill64 real live activations.
                pool().occupied.store(word, Ordering::Release);
                unsafe { crate::signal::raw_raise(libc::SIGUSR1) }.unwrap();
                assert_eq!(ALT_FAILURES.load(Ordering::Acquire), 0);
                assert_eq!(pool().occupied.load(Ordering::Acquire), word);
                let outer = OUTER_FIRST.load(Ordering::Acquire);
                let inner = INNER_FIRST.load(Ordering::Acquire);
                let outer_callback = OUTER_CALLBACK.load(Ordering::Acquire);
                let inner_callback = INNER_CALLBACK.load(Ordering::Acquire);
                assert!(base <= inner_callback && inner_callback < inner);
                assert!(inner < outer_callback && outer_callback < outer && outer < registered.top);
                assert_eq!(outer_callback % 16, 8);
                assert_eq!(inner_callback % 16, 8);
                assert_eq!(read_mask(), mask);
                assert_eq!(altstack().ss_flags & libc::SS_ONSTACK, 0);
            }
            pool().occupied.store(0, Ordering::Release);
            println!(
                "actual ToolRegion kernel alt registration and two nested SA_ONSTACK handlers; no top reset"
            );
        },
    );
}

#[test]
fn zero_length_atomic_publication_never_borrows_an_unpublished_base() {
    isolated(
        "zero_length_atomic_publication_never_borrows_an_unpublished_base",
        || {
            prepare().unwrap();
            let descriptor = ToolRegion::reserve().unwrap().registered_altstack();
            assert_eq!(descriptor.length.load(Ordering::Acquire), 0);
            // This is the actual atomic representation during an interrupted
            // publication, not a claim that a synthetic descriptor was registered.
            let mut stack_sample = Sample::default();
            let here = (&raw const stack_sample) as usize;
            descriptor
                .base
                .store(here.saturating_sub(4096), Ordering::Relaxed);
            unsafe { entry((&raw mut stack_sample).cast(), sample) };
            assert_eq!(stack_sample.word.count_ones(), 1);
            slot_of(stack_sample.rsp);
            assert_eq!(pool().occupied.load(Ordering::Acquire), 0);
            assert!(
                ToolRegion::reserve()
                    .unwrap()
                    .registered_alternate_stack()
                    .is_none()
            );
        },
    );
}

fn disable_dumping() {
    assert_eq!(
        raw(
            libc::SYS_prctl,
            [libc::PR_SET_DUMPABLE as u64, 0, 0, 0, 0, 0]
        ),
        0
    );
}

fn signal_default(number: i32) {
    let action = crate::signal::KernelSigaction {
        handler: libc::SIG_DFL as u64,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    unsafe { crate::signal::raw_sigaction(number, Some(&action), None) }.unwrap();
    let mask = read_mask() & !(1 << (number - 1));
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&mask), None) }.unwrap();
}

#[test]
fn unprepared_entry_attempts_native_exit127_without_incoming_stack_fallback() {
    isolated(
        "unprepared_entry_attempts_native_exit127_without_incoming_stack_fallback",
        || {
            assert!(snapshot().is_none());
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                disable_dumping();
                unsafe { entry(core::ptr::null_mut(), sample) };
                raw_exit(92);
            }
            expect_exit(wait_raw(child), 127);
            assert!(snapshot().is_none());
            println!(
                "actual unprepared native outcome127 is a runtime failure, not guest compatibility"
            );
        },
    );
}

fn exit_policy(action: u32) {
    let mut instructions = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_exit_group as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: action,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    assert_eq!(
        raw(
            libc::SYS_prctl,
            [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        raw(
            libc::SYS_seccomp,
            [
                libc::SECCOMP_SET_MODE_FILTER as u64,
                0,
                (&raw const program) as u64,
                0,
                0,
                0
            ]
        ),
        0
    );
}

#[test]
fn external_exit_errno_and_forged_success_are_not_normal_terminal_success() {
    isolated(
        "external_exit_errno_and_forged_success_are_not_normal_terminal_success",
        || {
            for action in [
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                libc::SECCOMP_RET_ERRNO,
            ] {
                let child = raw(libc::SYS_fork, [0; 6]);
                assert!(child >= 0);
                if child == 0 {
                    disable_dumping();
                    signal_default(libc::SIGILL);
                    exit_policy(action);
                    unsafe { entry(core::ptr::null_mut(), sample) };
                    raw_exit(93);
                }
                let status = wait_raw(child);
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGILL);
                println!("external action{action:#x}: actual SIGILL, no normal127 credit");
            }
        },
    );
}

// This callback makes all Tool-stack stores before publishing entered=1.
// A futex interruption/retry writes registers only, so a complete live-stack
// snapshot can be taken without timing-dependent Rust spill exclusions.
#[unsafe(naked)]
unsafe extern "C" fn capacity_parked(_context: *mut libc::c_void) {
    core::arch::naked_asm!(
        "endbr64",
        "mov [rdi + {rsp}], rsp",
        "push r12",
        "mov r8, rdi",
        "mov rax, [rip + {locator}]",
        "mov rax, [rax]",
        "mov [r8 + {word}], rax",
        "lea rdi, [r8 + {release}]",
        "mov esi, {wait}",
        "xor edx, edx",
        "xor r10d, r10d",
        "lea r12, [rip + .Lcapacity_parked_return]",
        "mov dword ptr [r8 + {entered}], 1",
        ".Lcapacity_parked_wait:",
        "mov eax, {futex}",
        "jmp {gate}",
        ".Lcapacity_parked_return:",
        "endbr64",
        "cmp dword ptr [r8 + {release}], 0",
        "je .Lcapacity_parked_wait",
        "pop r12",
        "ret",
        rsp = const offset_of!(Parked, rsp),
        entered = const offset_of!(Parked, entered),
        release = const offset_of!(Parked, release),
        word = const offset_of!(Parked, word),
        locator = sym LOCATOR,
        gate = sym native_gate,
        futex = const libc::SYS_futex,
        wait = const libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG,
    );
}

const CAPACITY_MODE: &str = "REVERIE_INSTALLED_STACK_CAPACITY_TRACE_CHILD";
const CONTROL_FD: &str = "REVERIE_INSTALLED_STACK_CONTROL_FD";

fn fill_stderr_to_blocking_saturation() {
    let mut descriptors = [0_i32; 2];
    assert_eq!(
        raw(
            libc::SYS_pipe2,
            [
                descriptors.as_mut_ptr() as u64,
                libc::O_NONBLOCK as u64,
                0,
                0,
                0,
                0
            ]
        ),
        0
    );
    let block = [0x41_u8; 4096];
    let mut actual = 0;
    loop {
        let count = raw(
            libc::SYS_write,
            [
                descriptors[1] as u64,
                block.as_ptr() as u64,
                block.len() as u64,
                0,
                0,
                0,
            ],
        );
        if count == -i64::from(libc::EAGAIN) {
            break;
        }
        assert!(count > 0);
        actual += count;
    }
    assert!(actual >= 4096);
    assert_eq!(
        raw(
            libc::SYS_fcntl,
            [descriptors[1] as u64, libc::F_SETFL as u64, 0, 0, 0, 0]
        ),
        0
    );
    assert_eq!(
        raw(
            libc::SYS_fcntl,
            [descriptors[1] as u64, libc::F_GETFL as u64, 0, 0, 0, 0]
        ) & i64::from(libc::O_NONBLOCK),
        0
    );
    assert_eq!(
        raw(libc::SYS_dup2, [descriptors[1] as u64, 2, 0, 0, 0, 0]),
        2
    );
    // Both ends stay open and nobody reads. A positive-length stderr write
    // would block. The production capacity path must not make that attempt.
}

unsafe extern "C" fn unexpected_sigsys(
    _signal: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    raw_exit(95);
}

fn capacity_trace_child() -> ! {
    let control: i32 = std::env::var(CONTROL_FD).unwrap().parse().unwrap();
    prepare().unwrap();
    let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates_with_signal_return(
        crate::trap::trusted_gate(),
        crate::trap::guest_syscall_gate(),
        Some(crate::signal::signal_restorer_return_ip()),
    )
    .unwrap();
    // A dedicated kernel-registered observer altstack is not a ToolRegion
    // published alternate. An unexpected trap must not write its signal frame
    // into any occupied pool stack. No SIGSYS is expected in the normal case.
    unsafe {
        crate::signal::install_alt_stack().unwrap();
        crate::signal::install_runtime_handler(libc::SIGSYS, unexpected_sigsys, libc::SA_ONSTACK)
            .unwrap();
    }
    let states: [Parked; CAPACITY] = core::array::from_fn(|_| Parked::new());
    std::thread::scope(|threads| {
        for state in &states {
            threads.spawn(move || unsafe {
                entry((state as *const Parked).cast_mut().cast(), capacity_parked)
            });
        }
        for state in &states {
            state.wait_entered();
        }
        assert_eq!(pool().occupied.load(Ordering::Acquire), u64::MAX);
        assert_eq!(
            raw(
                libc::SYS_ptrace,
                [libc::PTRACE_TRACEME as u64, 0, 0, 0, 0, 0]
            ),
            0
        );
        fill_stderr_to_blocking_saturation();
        unsafe { filter.install() }.unwrap();
        let wire = [
            raw(libc::SYS_getpid, [0; 6]) as u64,
            raw(libc::SYS_gettid, [0; 6]) as u64,
            LOCATOR.load(Ordering::Acquire) as u64,
            states.as_ptr() as u64,
            CAPACITY as u64,
        ];
        assert_eq!(
            raw(
                libc::SYS_write,
                [
                    control as u64,
                    wire.as_ptr() as u64,
                    size_of_val(&wire) as u64,
                    0,
                    0,
                    0
                ]
            ),
            size_of_val(&wire) as i64
        );
        unsafe { crate::signal::raw_raise(libc::SIGSTOP) }.unwrap();
        // The parent already opened the source-bound /proc/<pid>/mem FD at
        // the stop. Disable dumps before any terminal/fault attempt; reads
        // through that held FD do not require reopening a nondumpable task.
        disable_dumping();
        // Legitimate caller effects occur on this non-pool test stack. All64
        // occupied pool interiors were already frozen before the stop. The
        // failed65th claim must perform no writes to any of their bytes.
        unsafe { entry(core::ptr::null_mut(), sample) };
        raw_exit(96);
    });
    raw_exit(97)
}

fn ptrace_wait(tid: i64) -> i32 {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let mut status = 0_i32;
        let result = raw(
            libc::SYS_wait4,
            [
                tid as u64,
                (&raw mut status) as u64,
                (libc::WNOHANG | libc::__WALL) as u64,
                0,
                0,
                0,
            ],
        );
        if result == tid {
            return status;
        }
        assert!(
            result == 0 || result == -i64::from(libc::EINTR),
            "ptrace wait({tid})={result}"
        );
        assert!(Instant::now() < end, "ptrace event deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn ptrace(request: u32, tid: i64, data: u64) {
    assert_eq!(
        raw(
            libc::SYS_ptrace,
            [request as u64, tid as u64, 0, data, 0, 0]
        ),
        0
    );
}

fn remote_word(memory: &std::fs::File, address: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    memory.read_exact_at(&mut bytes, address as u64).unwrap();
    u64::from_ne_bytes(bytes)
}

fn remote_slots(memory: &std::fs::File, address: usize) -> [StackDescriptor; CAPACITY] {
    core::array::from_fn(|index| {
        let base = address + offset_of!(Pool, slots) + index * size_of::<StackDescriptor>();
        StackDescriptor {
            bottom: remote_word(memory, base) as usize,
            top: remote_word(memory, base + 8) as usize,
            extent_start: remote_word(memory, base + 16) as usize,
            extent_end: remote_word(memory, base + 24) as usize,
        }
    })
}

#[test]
fn sixty_four_real_live_claims_preserve_every_byte_on_saturated_stderr_exit127() {
    const NAME: &str =
        "sixty_four_real_live_claims_preserve_every_byte_on_saturated_stderr_exit127";
    isolated(NAME, || {
        if std::env::var(CAPACITY_MODE).as_deref() == Ok("1") {
            capacity_trace_child();
        }
        let (mut control, inherited) = UnixStream::pair().unwrap();
        control
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let fd = inherited.as_raw_fd();
        assert_eq!(
            raw(
                libc::SYS_fcntl,
                [fd as u64, libc::F_SETFD as u64, 0, 0, 0, 0]
            ),
            0
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &exact_name(NAME),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, NAME)
            .env(CAPACITY_MODE, "1")
            .env(CONTROL_FD, fd.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut ownership = OwnedProcess::new(i64::from(child.id()));
        drop(inherited);
        let mut wire = [0_u8; 40];
        control.read_exact(&mut wire).unwrap();
        let words: [u64; 5] = core::array::from_fn(|index| {
            u64::from_ne_bytes(wire[index * 8..index * 8 + 8].try_into().unwrap())
        });
        let [pid, tid, address, states, count] = words;
        assert_eq!(pid, u64::from(child.id()));
        assert_eq!(count as usize, CAPACITY);
        let status = ptrace_wait(tid as i64);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGSTOP);
        ptrace(
            libc::PTRACE_SETOPTIONS,
            tid as i64,
            libc::PTRACE_O_TRACEEXIT as u64,
        );
        let memory = std::fs::File::open(format!("/proc/{pid}/mem")).unwrap();
        assert_eq!(remote_word(&memory, address as usize), u64::MAX);
        let slots = remote_slots(&memory, address as usize);
        let mut actual_bits = 0_u64;
        for index in 0..CAPACITY {
            let rsp = remote_word(&memory, states as usize + index * size_of::<Parked>()) as usize;
            let slot = slots.iter().position(|slot| rsp == slot.top - 40).unwrap();
            assert_eq!(actual_bits & (1 << slot), 0);
            actual_bits |= 1 << slot;
        }
        assert_eq!(
            actual_bits,
            u64::MAX,
            "64 actual production-entry callbacks are live"
        );
        let mut before = vec![0_u8; CAPACITY * STACK_BYTES];
        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(slot.top - slot.bottom, STACK_BYTES);
            memory
                .read_exact_at(
                    &mut before[index * STACK_BYTES..(index + 1) * STACK_BYTES],
                    slot.bottom as u64,
                )
                .unwrap();
        }
        ptrace(libc::PTRACE_CONT, tid as i64, 0);
        let status = ptrace_wait(tid as i64);
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
        let mut exit_message = 0_u64;
        assert_eq!(
            raw(
                libc::SYS_ptrace,
                [
                    libc::PTRACE_GETEVENTMSG as u64,
                    tid,
                    0,
                    (&raw mut exit_message) as u64,
                    0,
                    0
                ]
            ),
            0
        );
        assert_eq!(exit_message, 127 << 8);
        assert_eq!(remote_word(&memory, address as usize), u64::MAX);
        let mut observed = [0_u8; 64 * 1024];
        let mut changed = 0_usize;
        for (index, slot) in slots.iter().enumerate() {
            for offset in (0..STACK_BYTES).step_by(observed.len()) {
                memory
                    .read_exact_at(&mut observed, (slot.bottom + offset) as u64)
                    .unwrap();
                let expected = &before
                    [index * STACK_BYTES + offset..index * STACK_BYTES + offset + observed.len()];
                changed += expected
                    .iter()
                    .zip(&observed)
                    .filter(|(a, b)| a != b)
                    .count();
            }
        }
        assert_eq!(changed, 0, "every512MiB live interior byte, no exclusions");
        ptrace(libc::PTRACE_CONT, tid as i64, 0);
        let final_status = ptrace_wait(tid as i64);
        expect_exit(final_status, 127);
        let end = Instant::now() + FORK_DEADLINE;
        let leader = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < end);
            std::thread::sleep(Duration::from_millis(1));
        };
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(leader.code(), Some(127));
        assert_eq!(leader.signal(), None);
        ownership.complete();
        println!(
            "native capacity:64 real live claims, actual runtime TSYNC filter, blocking-full stderr, occupied=ffffffffffffffff, all536870912 live bytes equal, actualexit127 (runtime FAIL); lifecycle ptrace is test observation only"
        );
    });
}

#[repr(C, align(16))]
struct NativeJumpBuffer([u8; 512]);

unsafe extern "C" {
    fn __sigsetjmp(environment: *mut libc::c_void, save_mask: i32) -> i32;
    fn siglongjmp(environment: *mut libc::c_void, value: i32) -> !;
    fn installed_stack_escape_observe(environment: *mut libc::c_void) -> i32;
}

// Keep returns-twice entirely in native assembly. No Rust frame is bypassed
// by the escape. glibc restores the real saved C ABI (including its CET
// handling where enabled), rather than fabricating a mismatched RET.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global installed_stack_escape_observe
    .hidden installed_stack_escape_observe
    .type installed_stack_escape_observe,@function
installed_stack_escape_observe:
    endbr64
    push r12
    mov r12, rdi
    xor esi, esi
    call {setjmp}
    test eax, eax
    jne .Linstalled_escape_return
    mov rdi, r12
    lea rsi, [rip + {escape}]
    call {entry}
    ud2
.Linstalled_escape_return:
    endbr64
    pop r12
    ret
    .size installed_stack_escape_observe, .-installed_stack_escape_observe
    "#,
    setjmp = sym __sigsetjmp,
    escape = sym escape_body,
    entry = sym entry,
);

#[unsafe(naked)]
unsafe extern "C" fn escape_body(_context: *mut libc::c_void) {
    core::arch::naked_asm!("endbr64", "mov esi, 1", "jmp {escape}", escape = sym siglongjmp);
}

#[test]
fn genuine_nonlocal_escape_retains_exact_bit_and_every_old_stack_byte() {
    isolated(
        "genuine_nonlocal_escape_retains_exact_bit_and_every_old_stack_byte",
        || {
            prepare().unwrap();
            let mut environment = NativeJumpBuffer([0; 512]);
            let value =
                unsafe { installed_stack_escape_observe(environment.0.as_mut_ptr().cast()) };
            assert_eq!(
                value, 1,
                "genuine native siglongjmp returned to its saved C caller"
            );
            let leaked = snapshot().unwrap();
            assert_eq!(leaked.occupied.count_ones(), 1);
            let index = leaked.occupied.trailing_zeros() as usize;
            let old = leaked.slots[index];
            let bytes =
                unsafe { core::slice::from_raw_parts(old.bottom as *const u8, STACK_BYTES) };
            let before = bytes.to_vec();
            let mut observed = Sample::default();
            unsafe { entry((&raw mut observed).cast(), sample) };
            let next = slot_of(observed.rsp);
            assert_ne!(next, index);
            assert_eq!(observed.word, leaked.occupied | (1 << next));
            assert_eq!(snapshot().unwrap().occupied, leaked.occupied);
            assert_eq!(
                bytes, before,
                "all8MiB of the escaped claim remain unchanged, no exclusions"
            );
            println!(
                "native genuine escape: bit{index} remains occupied, next bit{next}, all{STACK_BYTES} old bytes equal; no guest longjmp/Tool-state parity claim"
            );
        },
    );
}

#[unsafe(naked)]
unsafe extern "C" fn headroom_attempt(_base: usize) -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "lea rsp, [rdi + 16]",
        "xor edi, edi",
        "lea rsi, [rip + {sample}]",
        "call {entry}",
        ".global installed_stack_headroom_return",
        ".hidden installed_stack_headroom_return",
        "installed_stack_headroom_return:",
        "endbr64",
        "ud2",
        entry = sym entry,
        sample = sym sample,
    );
}

unsafe extern "C" {
    static installed_stack_headroom_return: u8;
}

fn wait_stop(tid: i64, signal: i32) {
    let status = ptrace_wait(tid);
    assert!(libc::WIFSTOPPED(status), "tid{tid}: status{status:#x}");
    assert_eq!(libc::WSTOPSIG(status), signal);
    assert_eq!(status >> 16, 0, "ordinary signal-delivery stop required");
}

fn exit_event(tid: i64, code: i32) {
    let status = ptrace_wait(tid);
    assert!(libc::WIFSTOPPED(status));
    assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
    assert_eq!(status >> 16, libc::PTRACE_EVENT_EXIT);
    let mut message = 0_u64;
    ptrace(libc::PTRACE_GETEVENTMSG, tid, (&raw mut message) as u64);
    assert_eq!(message, (code as u64) << 8);
}

fn registers(tid: i64) -> libc::user_regs_struct {
    let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
    ptrace(libc::PTRACE_GETREGS, tid, (&raw mut regs) as u64);
    regs
}

#[test]
fn registered_alt_headroom_refusal_preserves_full_interior_and_word() {
    isolated(
        "registered_alt_headroom_refusal_preserves_full_interior_and_word",
        || {
            prepare().unwrap();
            let region = ToolRegion::reserve().unwrap();
            unsafe {
                crate::signal::install_alt_stack_with_backing(
                    super::super::tool_region::StackBacking::ToolRegion(region),
                )
            }
            .unwrap();
            let registered = region.registered_alternate_stack().unwrap();
            let base = registered.bottom;
            let length = registered.top - base;
            assert_eq!(altstack().ss_sp as usize, base);
            assert_eq!(altstack().ss_size, length);
            assert_eq!(readable_byte(base - 1), -i64::from(libc::EFAULT));
            assert_eq!(readable_byte(registered.top), -i64::from(libc::EFAULT));
            // The genuine CALL writes its required slot. Seed the exact same
            // return PC before the literal snapshot; no arbitrary span is excluded.
            unsafe {
                (base as *mut usize)
                    .add(1)
                    .write((&raw const installed_stack_headroom_return) as usize)
            };
            let mut filter = crate::seccomp::SeccompFilter::for_trusted_gates_with_signal_return(
                crate::trap::trusted_gate(),
                crate::trap::guest_syscall_gate(),
                Some(crate::signal::signal_restorer_return_ip()),
            )
            .unwrap();
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                assert_eq!(
                    raw(
                        libc::SYS_ptrace,
                        [libc::PTRACE_TRACEME as u64, 0, 0, 0, 0, 0]
                    ),
                    0
                );
                unsafe { crate::signal::raw_raise(libc::SIGSTOP) }.unwrap();
                disable_dumping();
                unsafe { filter.install() }.unwrap();
                unsafe { headroom_attempt(base) }
            }
            let mut ownership = OwnedProcess::new(child);
            wait_stop(child, libc::SIGSTOP);
            ptrace(
                libc::PTRACE_SETOPTIONS,
                child,
                libc::PTRACE_O_TRACEEXIT as u64,
            );
            let memory = std::fs::File::open(format!("/proc/{child}/mem")).unwrap();
            assert_eq!(remote_word(&memory, LOCATOR.load(Ordering::Acquire)), 0);
            let mut before = vec![0_u8; length];
            memory.read_exact_at(&mut before, base as u64).unwrap();
            ptrace(libc::PTRACE_CONT, child, 0);
            exit_event(child, 127);
            assert_eq!(registers(child).rsp as usize, base + 8);
            assert_eq!(remote_word(&memory, LOCATOR.load(Ordering::Acquire)), 0);
            let mut after = vec![0_u8; length];
            memory.read_exact_at(&mut after, base as u64).unwrap();
            assert_eq!(
                after, before,
                "complete registered-alt interior, zero excluded bytes"
            );
            ptrace(libc::PTRACE_CONT, child, 0);
            expect_exit(ptrace_wait(child), 127);
            ownership.complete();
            println!(
                "native real registered alt headroom: RSP=base+8, actual runtime filter, all{length} interior bytes equal, occupied0, actual127(runtime FAIL); only seeded genuine CALL slot effects are identical"
            );
        },
    );
}

unsafe extern "C" {
    static reverie_inguest_installed_callback_preclaim: u8;
    static reverie_inguest_installed_callback_postclaim: u8;
    static reverie_inguest_installed_callback_postrestore: u8;
}

// The checkpoint occurs only after the genuine nested handler/callbacks
// returned. SIGSTOP has no userspace handler frame. The paused original entry
// has not resumed or written its owned stack at this observation boundary.
#[unsafe(naked)]
unsafe extern "C" fn interrupted_signal(
    _number: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    core::arch::naked_asm!("endbr64", "mov [rip + {first}], rsp", "jmp {body}", first = sym OUTER_FIRST, body = sym interrupted_signal_body);
}

unsafe extern "C" fn interrupted_signal_body(
    number: i32,
    info: *mut libc::siginfo_t,
    frame: *mut libc::c_void,
) {
    unsafe { outer_signal_body(number, info, frame) };
    if unsafe { crate::signal::raw_raise(libc::SIGSTOP) }.is_err() {
        raw_exit(98);
    }
}

fn debug_register(tid: i64, index: usize, value: usize) {
    assert!(index < 8);
    let offset = offset_of!(libc::user, u_debugreg) + index * size_of::<usize>();
    assert_eq!(
        raw(
            libc::SYS_ptrace,
            [
                libc::PTRACE_POKEUSER as u64,
                tid as u64,
                offset as u64,
                value as u64,
                0,
                0
            ]
        ),
        0
    );
}

#[test]
fn real_handlers_preserve_claims_at_three_prefixes_and_live_body() {
    isolated(
        "real_handlers_preserve_claims_at_three_prefixes_and_live_body",
        || {
            prepare().unwrap();
            let region = ToolRegion::reserve().unwrap();
            unsafe {
                crate::signal::install_alt_stack_with_backing(
                    super::super::tool_region::StackBacking::ToolRegion(region),
                )
                .unwrap();
                crate::signal::install_runtime_handler(
                    libc::SIGUSR1,
                    interrupted_signal,
                    libc::SA_ONSTACK,
                )
                .unwrap();
                crate::signal::install_runtime_handler(
                    libc::SIGUSR2,
                    inner_signal,
                    libc::SA_ONSTACK,
                )
                .unwrap();
            }
            let registered = region.registered_alternate_stack().unwrap();
            let mask = read_mask() & !((1 << (libc::SIGUSR1 - 1)) | (1 << (libc::SIGUSR2 - 1)));
            unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, Some(&mask), None) }
                .unwrap();
            let addresses = [
                (&raw const reverie_inguest_installed_callback_preclaim) as usize,
                (&raw const reverie_inguest_installed_callback_postclaim) as usize,
                sample as *const () as usize + 4, // first real body instruction after ENDBR64
                (&raw const reverie_inguest_installed_callback_postrestore) as usize,
            ];
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                assert_eq!(
                    raw(
                        libc::SYS_ptrace,
                        [libc::PTRACE_TRACEME as u64, 0, 0, 0, 0, 0]
                    ),
                    0
                );
                for _ in addresses {
                    unsafe { crate::signal::raw_raise(libc::SIGSTOP) }.unwrap();
                    let mut observed = Sample::default();
                    unsafe { entry((&raw mut observed).cast(), sample) };
                    if observed.word.count_ones() != 1
                        || pool().occupied.load(Ordering::Acquire) != 0
                        || ALT_FAILURES.load(Ordering::Acquire) != 0
                        || read_mask() != mask
                    {
                        raw_exit(99);
                    }
                }
                raw_exit(0);
            }
            let mut ownership = OwnedProcess::new(child);
            wait_stop(child, libc::SIGSTOP);
            let memory = std::fs::File::open(format!("/proc/{child}/mem")).unwrap();
            let address = LOCATOR.load(Ordering::Acquire);
            let slots = snapshot().unwrap().slots;
            for (stage, &pc) in addresses.iter().enumerate() {
                if stage != 0 {
                    wait_stop(child, libc::SIGSTOP);
                }
                debug_register(child, 0, pc);
                debug_register(child, 6, 0);
                debug_register(child, 7, 1);
                ptrace(libc::PTRACE_CONT, child, 0);
                wait_stop(child, libc::SIGTRAP);
                let mut info = unsafe { core::mem::zeroed::<libc::siginfo_t>() };
                ptrace(libc::PTRACE_GETSIGINFO, child, (&raw mut info) as u64);
                assert_eq!(info.si_code, 4, "TRAP_HWBKPT, not a software trap");
                let stopped = registers(child);
                assert_eq!(stopped.rip as usize, pc);
                debug_register(child, 7, 0);
                debug_register(child, 0, 0);
                debug_register(child, 6, 0);
                let word = remote_word(&memory, address);
                assert_eq!(word, u64::from(stage != 0));
                let claimed = if word == 0 {
                    None
                } else {
                    Some(slots[word.trailing_zeros() as usize])
                };
                let mut before = claimed.map(|slot| {
                    let mut bytes = vec![0_u8; STACK_BYTES];
                    memory
                        .read_exact_at(&mut bytes, slot.bottom as u64)
                        .unwrap();
                    bytes
                });
                if stage == 2 {
                    assert_eq!(stopped.rsp as usize, claimed.unwrap().top - 40);
                }
                assert_eq!(
                    raw(
                        libc::SYS_tgkill,
                        [child as u64, child as u64, libc::SIGUSR1 as u64, 0, 0, 0]
                    ),
                    0
                );
                ptrace(libc::PTRACE_CONT, child, 0);
                wait_stop(child, libc::SIGUSR1);
                // Reinject the genuine signal; never edit registers, code, a
                // syscall result, or the kernel signal frame.
                ptrace(libc::PTRACE_CONT, child, libc::SIGUSR1 as u64);
                wait_stop(child, libc::SIGUSR2);
                ptrace(libc::PTRACE_CONT, child, libc::SIGUSR2 as u64);
                wait_stop(child, libc::SIGSTOP);
                assert_eq!(remote_word(&memory, address), word);
                assert_eq!(remote_word(&memory, (&raw const ALT_FAILURES) as usize), 0);
                let outer = remote_word(&memory, (&raw const OUTER_FIRST) as usize) as usize;
                let inner = remote_word(&memory, (&raw const INNER_FIRST) as usize) as usize;
                let outer_callback =
                    remote_word(&memory, (&raw const OUTER_CALLBACK) as usize) as usize;
                let inner_callback =
                    remote_word(&memory, (&raw const INNER_CALLBACK) as usize) as usize;
                assert!(registered.bottom <= inner_callback && inner_callback < inner);
                assert!(inner < outer_callback && outer_callback < outer && outer < registered.top);
                if let Some(slot) = claimed {
                    let mut after = vec![0_u8; STACK_BYTES];
                    memory
                        .read_exact_at(&mut after, slot.bottom as u64)
                        .unwrap();
                    assert_eq!(
                        after,
                        before.take().unwrap(),
                        "stage{stage}: all8MiB live slot, zero exclusions"
                    );
                }
                println!(
                    "native hardware stop stage{stage} PC{pc:#x} RSP{:#x} word{word:#x}; genuine two nested SA_ONSTACK handlers preserve exact claim and full live slot; ptrace/RF/timing perturbations are measurement only",
                    stopped.rsp
                );
                ptrace(libc::PTRACE_CONT, child, 0);
            }
            expect_exit(ptrace_wait(child), 0);
            ownership.complete();
        },
    );
}

static HANDLED_FAULT_FD: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);

unsafe extern "C" fn held_fault(
    _signal: i32,
    _info: *mut libc::siginfo_t,
    _frame: *mut libc::c_void,
) {
    let byte = [0x73_u8];
    if raw(
        libc::SYS_write,
        [
            HANDLED_FAULT_FD.load(Ordering::Relaxed) as u64,
            byte.as_ptr() as u64,
            1,
            0,
            0,
            0,
        ],
    ) != 1
    {
        raw(
            libc::SYS_kill,
            [
                raw(libc::SYS_getpid, [0; 6]) as u64,
                libc::SIGKILL as u64,
                0,
                0,
                0,
                0,
            ],
        );
    }
    loop {
        raw(libc::SYS_pause, [0; 6]);
    }
}

#[test]
fn caught_fallback_fault_is_observed_held_then_explicitly_killed() {
    isolated(
        "caught_fallback_fault_is_observed_held_then_explicitly_killed",
        || {
            assert!(snapshot().is_none());
            let (mut witness, writer) = UnixStream::pair().unwrap();
            witness.set_read_timeout(Some(FORK_DEADLINE)).unwrap();
            let fd = writer.as_raw_fd();
            signal_default(libc::SIGILL);
            HANDLED_FAULT_FD.store(fd, Ordering::Relaxed);
            unsafe {
                crate::signal::install_alt_stack().unwrap();
                crate::signal::install_runtime_handler(libc::SIGILL, held_fault, libc::SA_ONSTACK)
                    .unwrap();
            }
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                // Kernel altstack/disposition and the witness FD are inherited.
                // No std/libc allocation is made after this native fork.
                disable_dumping();
                exit_policy(libc::SECCOMP_RET_ERRNO);
                unsafe { entry(core::ptr::null_mut(), sample) };
                raw_exit(100);
            }
            let mut ownership = OwnedProcess::new(child);
            drop(writer);
            let mut byte = [0_u8];
            witness.read_exact(&mut byte).unwrap();
            assert_eq!(byte, [0x73], "actual SIGILL handler witness");
            let end = Instant::now() + Duration::from_millis(100);
            while Instant::now() < end {
                let mut status = 0_i32;
                assert_eq!(
                    raw(
                        libc::SYS_wait4,
                        [
                            child as u64,
                            (&raw mut status) as u64,
                            libc::WNOHANG as u64,
                            0,
                            0,
                            0
                        ]
                    ),
                    0,
                    "caught fallback is deliberately held, not terminal success"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                raw(
                    libc::SYS_kill,
                    [child as u64, libc::SIGKILL as u64, 0, 0, 0, 0]
                ),
                0
            );
            let status = wait_raw(child);
            assert!(libc::WIFSIGNALED(status));
            assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
            ownership.complete();
            println!(
                "external forged exit return + genuine caught SIGILL: actual handler held100ms, explicit owned SIGKILL/reap; no normal127 or universal bounded-death credit"
            );
        },
    );
}
