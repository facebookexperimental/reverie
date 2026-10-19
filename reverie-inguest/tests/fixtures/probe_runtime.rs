/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Minimal stage-1a mechanics runtime. This is not Detcore and has no allocator,
//! libc start-up, TLS, vDSO rewrite, scheduler, or production activation path.
//! Every actual syscall is in `.gate`; handlers record before forwarding. The
//! parent restores the real kernel entry image after the loader's ready stop.

#![no_std]
#![no_main]

#[path = "probe_protocol.rs"]
mod protocol;

use core::arch::asm;
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::offset_of;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use protocol::*;

const SIGSEGV: i32 = 11;
const SIGSYS: i32 = 31;
const SI_KERNEL: i32 = 128;
const SYS_SECCOMP: i32 = 1;
const RESERVED_SIGNALS: u64 = (1 << (SIGSYS - 1)) | (1 << (SIGSEGV - 1));
const UNMASKABLE_SIGNALS: u64 = (1 << (9 - 1)) | (1 << (19 - 1));
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const ARCH_SET_CPUID: u64 = 0x1012;
const ARCH_GET_CPUID: u64 = 0x1011;
const PR_SET_TSC: u64 = 26;
const PR_GET_TSC: u64 = 25;
const PR_TSC_SIGSEGV: u64 = 2;
const EOPNOTSUPP: i64 = 95;
const EINVAL: i64 = 22;
const EFAULT: i64 = 14;

// SAFETY (assembly contract): the checked fixed RX image owns these symbols.
// The ordinary gate preserves every SysV callee-saved register and the stack;
// its seventh C argument is at rsp+8, while Linux takes argument4 in R10. The
// restorer is entered only by the kernel with a live signal frame. Probe
// functions preserve RBX and follow the C ABI; native_cpuid's caller supplies
// one live writable [u64; 4]. Only .gate contains syscall instructions, which
// the parent must confirm on the actual linked file with the opcode audit.
global_asm!(
    ".section .gate,\"ax\",@progbits",
    ".global probe_runtime_gate",
    ".type probe_runtime_gate,@function",
    "probe_runtime_gate:",
    "mov rax, rdi",
    "mov rdi, rsi",
    "mov rsi, rdx",
    "mov rdx, rcx",
    "mov r10, r8",
    "mov r8, r9",
    "mov r9, [rsp + 8]",
    "syscall",
    "ret",
    ".size probe_runtime_gate, .-probe_runtime_gate",
    ".p2align 4",
    ".global probe_runtime_restorer",
    ".type probe_runtime_restorer,@function",
    "probe_runtime_restorer:",
    "mov eax, 15",
    "syscall",
    "ud2",
    ".size probe_runtime_restorer, .-probe_runtime_restorer",
    ".section .text.probes,\"ax\",@progbits",
    ".global probe_cpuid_selftest",
    ".type probe_cpuid_selftest,@function",
    "probe_cpuid_selftest:",
    "push rbx",
    "mov eax, {magic_leaf}",
    "xor ecx, ecx",
    ".global probe_cpuid_probe_ip",
    "probe_cpuid_probe_ip:",
    "cpuid",
    "cmp eax, {reply_a}",
    "jne 2f",
    "cmp ebx, {reply_b}",
    "jne 2f",
    "cmp ecx, {reply_c}",
    "jne 2f",
    "cmp edx, {reply_d}",
    "jne 2f",
    "xor eax, eax",
    "pop rbx",
    "ret",
    "2: mov eax, 1",
    "pop rbx",
    "ret",
    ".size probe_cpuid_selftest, .-probe_cpuid_selftest",
    ".global probe_rdtsc_selftest",
    ".type probe_rdtsc_selftest,@function",
    "probe_rdtsc_selftest:",
    ".global probe_rdtsc_probe_ip",
    "probe_rdtsc_probe_ip:",
    "rdtsc",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r10, {tsc_reply}",
    "cmp rax, r10",
    "jne 3f",
    "xor eax, eax",
    "ret",
    "3: mov eax, 1",
    "ret",
    ".size probe_rdtsc_selftest, .-probe_rdtsc_selftest",
    ".global probe_rdtscp_selftest",
    ".type probe_rdtscp_selftest,@function",
    "probe_rdtscp_selftest:",
    ".global probe_rdtscp_probe_ip",
    "probe_rdtscp_probe_ip:",
    "rdtscp",
    "shl rdx, 32",
    "or rax, rdx",
    "mov r10, {tsc_reply}",
    "cmp rax, r10",
    "jne 4f",
    "cmp ecx, {tsc_aux}",
    "jne 4f",
    "xor eax, eax",
    "ret",
    "4: mov eax, 1",
    "ret",
    ".size probe_rdtscp_selftest, .-probe_rdtscp_selftest",
    ".global probe_native_cpuid",
    ".type probe_native_cpuid,@function",
    "probe_native_cpuid:",
    "push rbx",
    "mov r8, rdx",
    "mov eax, edi",
    "mov ecx, esi",
    "cpuid",
    "mov [r8], rax",
    "mov [r8 + 8], rbx",
    "mov [r8 + 16], rcx",
    "mov [r8 + 24], rdx",
    "pop rbx",
    "ret",
    ".size probe_native_cpuid, .-probe_native_cpuid",
    magic_leaf = const MAGIC_CPUID_LEAF,
    reply_a = const CPUID_REPLY[0],
    reply_b = const CPUID_REPLY[1],
    reply_c = const CPUID_REPLY[2],
    reply_d = const CPUID_REPLY[3],
    tsc_reply = const TSC_REPLY,
    tsc_aux = const TSC_AUX_REPLY,
);

unsafe extern "C" {
    fn probe_runtime_gate(nr: i64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64;
    fn probe_runtime_restorer();
    fn probe_cpuid_selftest() -> u64;
    fn probe_rdtsc_selftest() -> u64;
    fn probe_rdtscp_selftest() -> u64;
    fn probe_native_cpuid(leaf: u32, subleaf: u32, out: *mut [u64; 4]);
    static probe_cpuid_probe_ip: u8;
    static probe_rdtsc_probe_ip: u8;
    static probe_rdtscp_probe_ip: u8;
}

static CONTROL: AtomicPtr<ProbeControlV1> = AtomicPtr::new(ptr::null_mut());
static IN_HANDLER: AtomicU32 = AtomicU32::new(0);

/// Kernel x86-64 rt_sigaction ABI; this is not glibc's sigaction wrapper.
#[repr(C)]
struct KernelAction {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[repr(C)]
struct KernelStack {
    sp: u64,
    flags: i32,
    pad: u32,
    bytes: u64,
}

/// Only the fixed Linux x86-64 ucontext prefix is borrowed. FP/XSTATE remains
/// kernel-owned and untouched by this code; the real restorer restores it.
#[repr(C)]
struct KernelContext {
    flags: u64,
    link: u64,
    stack: KernelStack,
    gregs: [u64; 23],
    fpregs: u64,
    reserved: [u64; 8],
    sigmask: u64,
}

#[repr(C)]
struct KernelInfo {
    signo: i32,
    errno: i32,
    code: i32,
    pad: i32,
    data: [u8; 112],
}

#[repr(C)]
struct IoVec {
    base: u64,
    bytes: u64,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    pad: [u8; 6],
    filter: *const SockFilter,
}

const R8: usize = 0;
const R9: usize = 1;
const R10: usize = 2;
const RDI: usize = 8;
const RSI: usize = 9;
const RBX: usize = 11;
const RDX: usize = 12;
const RAX: usize = 13;
const RCX: usize = 14;
const RSP: usize = 15;
const RIP: usize = 16;
const TRAPNO: usize = 20;

const _: () = {
    assert!(size_of::<KernelAction>() == 32);
    assert!(size_of::<KernelStack>() == 24);
    assert!(offset_of!(KernelContext, gregs) == 40);
    assert!(offset_of!(KernelContext, sigmask) == 296);
    assert!(size_of::<KernelInfo>() == 128);
    assert!(offset_of!(KernelInfo, data) == 16);
    assert!(size_of::<SockFilter>() == 8);
    assert!(offset_of!(SockFprog, filter) == 8);
};

#[inline(never)]
fn gate(nr: i64, a: [u64; 6]) -> i64 {
    // SAFETY: the assembly implements the declared seven-argument C ABI and
    // preserves its callee-saved state. Trusted runtime pointers passed here
    // refer to live, correctly sized locals or owned mappings until return.
    // Guest addresses are kernel-checked; the entry contract restricts the
    // fixture guest from writing runtime-owned storage. Gate placement alone
    // is not an ownership or hostile-guest isolation proof.
    unsafe { probe_runtime_gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
}

fn control() -> &'static ProbeControlV1 {
    let address = CONTROL.load(Ordering::Acquire);
    if address.is_null() {
        exit_failure();
    }
    // SAFETY: publication follows the unsafe entry's owned/initialized page
    // preconditions and input checks. The sole parent never mutates inputs
    // after starting the image; atomics hold every mutable status field. The
    // qualified fixture preserves this mapping for the process's lifetime.
    unsafe { &*address }
}

fn exit_failure() -> ! {
    gate(231, [EXIT_FAILURE as u64, 0, 0, 0, 0, 0]);
    loop {
        core::hint::spin_loop();
    }
}

fn fail(error: u32) -> ! {
    let address = CONTROL.load(Ordering::Acquire);
    if !address.is_null() {
        // SAFETY: only the unsafe entry publishes this initialized, aligned
        // control pointer; its mapping remains live, and only atomic status
        // fields are modified through the shared reference.
        let c = unsafe { &*address };
        c.error.store(error, Ordering::Release);
        c.phase.store(PHASE_FAILED, Ordering::Release);
    }
    exit_failure()
}

fn add_control(bit: u64) {
    control().controls.fetch_or(bit, Ordering::Release);
}

fn append(kind: u32, flags: u32, ip: u64, sp: u64, number: u64, args: [u64; 6], results: [u64; 4]) {
    let c = control();
    let seq = c.events_reserved.fetch_add(1, Ordering::Relaxed);
    if seq >= c.journal_capacity {
        c.overflow.store(1, Ordering::Release);
        fail(ERROR_JOURNAL_FULL);
    }
    // SAFETY: the exact fixed journal extent and capacity were validated before
    // installation by the entry contract. The 128-byte stride preserves
    // eight-byte alignment, and every byte belongs to this owned writable
    // mapping. All blockable signals are masked in each handler; IN_HANDLER
    // also fails closed. Each reservation writes a unique, never-reused slot;
    // the parent reads only committed rows while stopped or after exit.
    unsafe {
        let event = (c.journal_base as *mut ProbeEventV1).add(seq as usize);
        ptr::addr_of_mut!((*event).seq).write(seq);
        ptr::addr_of_mut!((*event).kind).write(kind);
        ptr::addr_of_mut!((*event).flags).write(flags);
        ptr::addr_of_mut!((*event).ip).write(ip);
        ptr::addr_of_mut!((*event).sp).write(sp);
        ptr::addr_of_mut!((*event).nr_or_opcode).write(number);
        ptr::addr_of_mut!((*event).args).write(args);
        ptr::addr_of_mut!((*event).results).write(results);
        (*event).commit.store(seq + 1, Ordering::Release);
    }
    c.events_committed.fetch_add(1, Ordering::Release);
}

fn valid_control(c: &ProbeControlV1) -> bool {
    if c.magic != CONTROL_MAGIC
        || c.abi_version != ABI_VERSION
        || c.bytes != CONTROL_BYTES as u32
        || c.nonce == [0; 2]
        || c.flags != 0
        || !(RUNTIME_GATE + PAGE_BYTES..TOOL_BASE + 0xff00_0000).contains(&c.runtime_entry)
        || c.guest_rip == 0
        || c.guest_rsp == 0
        || c.guest_sigmask & RESERVED_SIGNALS != 0
        || c.runtime_stack_lo != STACK_BOTTOM
        || c.runtime_stack_hi != STACK_TOP
        || c.altstack_lo != ALTSTACK_BOTTOM
        || c.altstack_hi != ALTSTACK_TOP
        || c.journal_base != JOURNAL_ADDRESS
        || c.journal_capacity != EVENT_CAPACITY
        || c.fd_count == 0
        || c.fd_count > 8
        || c.phase.load(Ordering::Acquire) != PHASE_BOOTSTRAP
        || c.error.load(Ordering::Acquire) != 0
        || c.controls.load(Ordering::Acquire) != 0
        || c.events_reserved.load(Ordering::Acquire) != 0
        || c.events_committed.load(Ordering::Acquire) != 0
        || c.overflow.load(Ordering::Acquire) != 0
        || c.ready_nonce.iter().any(|n| n.load(Ordering::Acquire) != 0)
        || c.reserved_input.iter().any(|&n| n != 0)
        || c.reserved_status.iter().any(|&n| n != 0)
    {
        return false;
    }
    for index in 0..c.fd_count as usize {
        if c.fds[index] < 3 || c.fds[..index].contains(&c.fds[index]) {
            return false;
        }
    }
    c.fds[c.fd_count as usize..].iter().all(|&fd| fd == -1)
}

/// Called exactly once, on the parent's Tool stack. Returns0 to the loader
/// only when installation and the instruction self-tests actually succeeded.
///
/// # Safety
/// The attached parent must own the complete NOREPLACE ToolRegion reservation
/// and have installed the checked loader/runtime images and fixed writable
/// control, journal, Tool stack and alternate-stack interiors with their guard
/// pages. `address` must denote one aligned, fully initialized ProbeControlV1
/// with live initialized atomics, not merely equal its fixed numeric address.
/// The parent must not modify its inputs while this image executes. The journal
/// must hold EVENT_CAPACITY aligned initialized event slots. The inherited
/// descriptor list must identify only child-owned bootstrap copies. The guest
/// must remain one of the qualified cooperative fixtures: it cannot overwrite
/// runtime storage or jump into the raw gates. This is no hostile-guest boundary.
// SAFETY: this unique exported entry is linked without a C startup/runtime;
// the checked loader calls it using the C ABI and the contract above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn probe_runtime_start(address: *mut ProbeControlV1) -> u64 {
    if address as u64 != CONTROL_ADDRESS {
        exit_failure();
    }
    // SAFETY: the caller, rather than the numeric-address comparison, proves
    // the owned aligned page's validity, initialization and lifetime above.
    let c = unsafe { &*address };
    if !valid_control(c) {
        exit_failure();
    }
    if CONTROL
        .compare_exchange(
            ptr::null_mut(),
            address,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        fail(ERROR_CONTROL);
    }
    c.phase.store(PHASE_INSTALLING, Ordering::Release);
    let install_mask = u64::MAX & !RESERVED_SIGNALS;
    if gate(14, [2, (&raw const install_mask) as u64, 0, 8, 0, 0]) != 0 {
        fail(ERROR_MASK);
    }
    for index in 0..c.fd_count as usize {
        let fd = c.fds[index] as u64;
        if gate(3, [fd, 0, 0, 0, 0, 0]) != 0 || gate(72, [fd, 1, 0, 0, 0, 0]) != -9 {
            fail(ERROR_CLOSE);
        }
    }
    add_control(CONTROL_FDS_CLOSED);
    let stack = KernelStack {
        sp: ALTSTACK_BOTTOM,
        flags: 0,
        pad: 0,
        bytes: ALTSTACK_TOP - ALTSTACK_BOTTOM,
    };
    if gate(131, [(&raw const stack) as u64, 0, 0, 0, 0, 0]) != 0 {
        fail(ERROR_ALTSTACK);
    }
    add_control(CONTROL_ALTSTACK);
    for (signal, handler, bit) in [
        (SIGSYS, syscall_handler as *const () as u64, CONTROL_SIGSYS),
        (
            SIGSEGV,
            instruction_handler as *const () as u64,
            CONTROL_SIGSEGV,
        ),
    ] {
        let action = KernelAction {
            handler,
            flags: 4 | 0x0400_0000 | 0x0800_0000, // SIGINFO|RESTORER|ONSTACK
            restorer: probe_runtime_restorer as *const () as u64,
            mask: u64::MAX,
        };
        if gate(13, [signal as u64, (&raw const action) as u64, 0, 8, 0, 0]) != 0 {
            fail(ERROR_SIGACTION);
        }
        add_control(bit);
    }
    if gate(158, [ARCH_SET_CPUID, 0, 0, 0, 0, 0]) != 0
        || gate(158, [ARCH_GET_CPUID, 0, 0, 0, 0, 0]) != 0
    {
        fail(ERROR_CPUID_ARM);
    }
    add_control(CONTROL_CPUID);
    let mut mode = 0_u32;
    if gate(157, [PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0, 0]) != 0
        || gate(157, [PR_GET_TSC, (&raw mut mode) as u64, 0, 0, 0, 0]) != 0
        || mode != PR_TSC_SIGSEGV as u32
    {
        fail(ERROR_TSC_ARM);
    }
    add_control(CONTROL_TSC);
    if gate(157, [38, 1, 0, 0, 0, 0]) != 0 {
        fail(ERROR_NO_NEW_PRIVS);
    }
    install_filter();
    add_control(CONTROL_FILTER);
    c.phase.store(PHASE_SELF_TESTING, Ordering::Release);
    // SAFETY: these known sites deliberately fault through the installed
    // SIGSEGV handler; only exact canary replies let each function return0.
    if unsafe {
        probe_cpuid_selftest() != 0 || probe_rdtsc_selftest() != 0 || probe_rdtscp_selftest() != 0
    } {
        fail(ERROR_SELF_TEST);
    }
    if c.controls.load(Ordering::Acquire) != REQUIRED_CONTROLS & !CONTROL_SYSCALL_PROBE {
        fail(ERROR_SELF_TEST);
    }
    // Loader gettid is the final real SIGSYS probe. Its handler, not this
    // return value, will publish TestControlsReady before the ready INT3.
    0
}

const fn bpf(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn install_filter() {
    // Audit x86-64, reject x32. Runtime gate is allowed; loader gate is
    // allowed except gettid, the deliberate SIGSYS self-test. Everything
    // else traps. IP comparisons use post-SYSCALL instruction pointers.
    let filter = [
        bpf(0x20, 0, 0, 4),                                  // 0: arch
        bpf(0x15, 1, 0, AUDIT_ARCH_X86_64),                  // 1
        bpf(0x06, 0, 0, 0x8000_0000),                        // 2: KILL_PROCESS
        bpf(0x20, 0, 0, 0),                                  // 3: nr
        bpf(0x45, 0, 1, 0x4000_0000),                        // 4: x32
        bpf(0x06, 0, 0, 0x8000_0000),                        // 5
        bpf(0x20, 0, 0, 12),                                 // 6: IP high
        bpf(0x15, 0, 10, (RUNTIME_GATE >> 32) as u32),       // 7 ->18
        bpf(0x20, 0, 0, 8),                                  // 8: IP low
        bpf(0x35, 0, 3, (RUNTIME_GATE + 2) as u32),          // 9 ->13
        bpf(0x25, 7, 0, (RUNTIME_GATE + PAGE_BYTES) as u32), // 10 ->18
        bpf(0x06, 0, 0, 0x7fff_0000),                        // 11: ALLOW
        bpf(0x06, 0, 0, 0x0003_0000),                        // 12: unreachable TRAP
        bpf(0x35, 0, 4, (LOADER_GATE + 2) as u32),           // 13 ->18
        bpf(0x25, 3, 0, (LOADER_GATE + PAGE_BYTES) as u32),  // 14 ->18
        bpf(0x20, 0, 0, 0),                                  // 15: nr
        bpf(0x15, 1, 0, 186),                                // 16 ->18 if gettid
        bpf(0x06, 0, 0, 0x7fff_0000),                        // 17: ALLOW
        bpf(0x06, 0, 0, 0x0003_0000),                        // 18: TRAP
    ];
    let program = SockFprog {
        len: filter.len() as u16,
        pad: [0; 6],
        filter: filter.as_ptr(),
    };
    if gate(317, [1, 0, (&raw const program) as u64, 0, 0, 0]) != 0 {
        fail(ERROR_FILTER);
    }
}

fn enter_handler() {
    if IN_HANDLER
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        fail(ERROR_REENTRANT);
    }
    let rsp: u64;
    // SAFETY: scalar observation only; no guest stack or TLS is touched.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    if !(ALTSTACK_BOTTOM..ALTSTACK_TOP).contains(&rsp) {
        fail(ERROR_ALTSTACK);
    }
}

fn event_flags() -> u32 {
    match control().phase.load(Ordering::Acquire) {
        PHASE_SELF_TESTING => FLAG_SELF_TEST,
        PHASE_TEST_CONTROLS_READY => {
            control()
                .phase
                .store(PHASE_GUEST_OBSERVED, Ordering::Release);
            FLAG_GUEST
        }
        PHASE_GUEST_OBSERVED => FLAG_GUEST,
        _ => fail(ERROR_SIGNAL),
    }
}

/// # Safety
/// Only kernel SA_SIGINFO delivery may call this C ABI entry, with a live
/// initialized siginfo and unique writable native x86-64 ucontext prefix on
/// the owned alternate stack. The installed CONTROL mapping must remain live.
unsafe extern "C" fn syscall_handler(signal: i32, info: *mut KernelInfo, raw: *mut KernelContext) {
    if signal != SIGSYS || info.is_null() || raw.is_null() {
        fail(ERROR_SIGNAL);
    }
    // SAFETY: the callback contract supplies a valid initialized siginfo for
    // this delivery. The provenance check below rejects software signals; it
    // is not itself the proof that this pointer can first be borrowed.
    let information = unsafe { &*info };
    if information.signo != SIGSYS || information.code != SYS_SECCOMP {
        fail(ERROR_SIGNAL);
    }
    // siginfo's seccomp payload is call_addr:u64, syscall:i32, arch:u32.
    // SAFETY: SYS_SECCOMP identifies the native siginfo payload. Offsets8..12
    // and12..16 are wholly inside its 112-byte data array; read_unaligned
    // avoids imposing a stronger alignment than that byte array provides.
    let (nr_info, arch) = unsafe {
        (
            (information.data.as_ptr().add(8) as *const u32).read_unaligned(),
            (information.data.as_ptr().add(12) as *const u32).read_unaligned(),
        )
    };
    if arch != AUDIT_ARCH_X86_64 {
        fail(ERROR_SIGNAL);
    }
    enter_handler();
    // SAFETY: the callback contract gives this handler the unique writable
    // native ucontext prefix for the current delivery. No reference to that
    // prefix is held by interrupted code; FP/XSTATE and guest stack storage
    // are neither borrowed nor modified through this prefix.
    let context = unsafe { &mut *raw };
    let number = context.gregs[RAX];
    if number as u32 != nr_info {
        fail(ERROR_SIGNAL);
    }
    let ip = context.gregs[RIP];
    let sp = context.gregs[RSP];
    let args = [
        context.gregs[RDI],
        context.gregs[RSI],
        context.gregs[RDX],
        context.gregs[R10],
        context.gregs[R8],
        context.gregs[R9],
    ];
    let flags = event_flags();
    let self_test = flags == FLAG_SELF_TEST;
    if self_test && (ip != LOADER_GETTID_POST_IP || number as u32 != 186) {
        fail(ERROR_SELF_TEST);
    }
    let no_return = matches!(number as u32, 60 | 231);
    append(
        EVENT_SYSCALL_ENTER,
        flags | if no_return { FLAG_EXPECTED_NORETURN } else { 0 },
        ip,
        sp,
        number,
        args,
        [0; 4],
    );
    let result = if number as u32 == 14 {
        signal_mask_call(context, args, flags)
    } else if let Some(category) = refusal(number as u32, args) {
        append(
            EVENT_REFUSAL,
            flags,
            ip,
            sp,
            number,
            args,
            [category, EOPNOTSUPP as u64, 0, 0],
        );
        -EOPNOTSUPP
    } else {
        gate(number as i64, args)
    };
    if no_return {
        // A genuine exit cannot return through the gate. A returned errno is
        // retained rather than silently treated as completed termination.
        append(
            EVENT_SYSCALL_RETURN,
            flags,
            ip,
            sp,
            number,
            args,
            [result as u64, 0, 0, 0],
        );
        fail(ERROR_GUEST_CONTROL);
    }
    append(
        EVENT_SYSCALL_RETURN,
        flags,
        ip,
        sp,
        number,
        args,
        [result as u64, 0, 0, 0],
    );
    context.gregs[RAX] = result as u64;
    if self_test {
        if result <= 0 {
            fail(ERROR_SELF_TEST);
        }
        add_control(CONTROL_SYSCALL_PROBE);
        let c = control();
        if c.controls.load(Ordering::Acquire) != REQUIRED_CONTROLS {
            fail(ERROR_SELF_TEST);
        }
        c.ready_nonce[0].store(c.nonce[0], Ordering::Relaxed);
        c.ready_nonce[1].store(c.nonce[1], Ordering::Relaxed);
        c.phase.store(PHASE_TEST_CONTROLS_READY, Ordering::Release);
    }
    IN_HANDLER.store(0, Ordering::Release);
}

fn overlaps_tool(base: u64, bytes: u64) -> bool {
    bytes != 0 && base < TOOL_END && base.checked_add(bytes).is_none_or(|end| end > TOOL_BASE)
}

fn refusal(number: u32, a: [u64; 6]) -> Option<u64> {
    match number {
        56 | 57 | 58 | 435 => Some(REFUSAL_CLONE),
        59 | 322 => Some(REFUSAL_EXEC),
        13 if a[1] != 0 && matches!(a[0] as i32, SIGSYS | SIGSEGV) => Some(REFUSAL_GUEST_CONTROL),
        131 if a[0] != 0 => Some(REFUSAL_GUEST_CONTROL),
        15 | 317 => Some(REFUSAL_GUEST_CONTROL),
        158 if a[0] == ARCH_SET_CPUID => Some(REFUSAL_GUEST_CONTROL),
        157 if a[0] == PR_SET_TSC => Some(REFUSAL_GUEST_CONTROL),
        9 if a[3] & (0x10 | 0x10_0000) != 0 && overlaps_tool(a[0], a[1]) => {
            Some(REFUSAL_GUEST_CONTROL)
        }
        10 | 11 | 28 | 329 if overlaps_tool(a[0], a[1]) => Some(REFUSAL_GUEST_CONTROL),
        25 if overlaps_tool(a[0], a[1].max(a[2]))
            || (a[3] & 2 != 0 && overlaps_tool(a[4], a[2])) =>
        {
            Some(REFUSAL_GUEST_CONTROL)
        }
        _ => None,
    }
}

fn copy_guest_word(address: u64, value: &mut u64, write: bool) -> i64 {
    let local = IoVec {
        base: value as *mut u64 as u64,
        bytes: 8,
    };
    let remote = IoVec {
        base: address,
        bytes: 8,
    };
    let pid = gate(39, [0; 6]);
    if pid <= 0 {
        return -EFAULT;
    }
    let result = gate(
        if write { 311 } else { 310 },
        [
            pid as u64,
            (&raw const local) as u64,
            1,
            (&raw const remote) as u64,
            1,
            0,
        ],
    );
    if result == 8 {
        0
    } else if result < 0 {
        result
    } else {
        -EFAULT
    }
}

fn signal_mask_call(context: &mut KernelContext, a: [u64; 6], flags: u32) -> i64 {
    // Forwarding rt_sigprocmask inside a handler would operate on the
    // handler's mask, then be undone by sigreturn. Operate on the saved guest
    // mask instead. Version1 refuses blocking the runtime's reserved signals.
    if a[3] != 8 {
        return -EINVAL;
    }
    let mut previous = context.sigmask;
    let mut replacement = previous;
    if a[1] != 0 {
        let mut requested = 0;
        let result = copy_guest_word(a[1], &mut requested, false);
        if result != 0 {
            return result;
        }
        replacement = match a[0] {
            0 => previous | requested,
            1 => previous & !requested,
            2 => requested,
            _ => return -EINVAL,
        } & !UNMASKABLE_SIGNALS;
        if replacement & RESERVED_SIGNALS != 0 {
            append(
                EVENT_REFUSAL,
                flags,
                context.gregs[RIP],
                context.gregs[RSP],
                14,
                a,
                [REFUSAL_GUEST_CONTROL, EOPNOTSUPP as u64, 0, 0],
            );
            return -EOPNOTSUPP;
        }
    }
    if a[2] != 0 {
        let result = copy_guest_word(a[2], &mut previous, true);
        if result != 0 {
            return result;
        }
    }
    context.sigmask = replacement;
    0
}

fn read_instruction_bytes(address: u64, bytes: usize) -> [u8; 3] {
    if !(1..=3).contains(&bytes) || address.checked_add(bytes as u64).is_none() {
        fail(ERROR_INSTRUCTION_READ);
    }
    let mut value = [0_u8; 3];
    let local = IoVec {
        base: value.as_mut_ptr() as u64,
        bytes: bytes as u64,
    };
    let remote = IoVec {
        base: address,
        bytes: bytes as u64,
    };
    let pid = gate(39, [0; 6]);
    if pid <= 0 {
        fail(ERROR_INSTRUCTION_READ);
    }
    // SAFETY (kernel buffer contract): both iovecs and the initialized local
    // byte array remain live until this synchronous gate call returns. The
    // writable local extent is at most three bytes. The remote integer is
    // never dereferenced by Rust; Linux checks readability and the exact copy
    // count is required, including at page boundaries.
    let result = gate(
        310,
        [
            pid as u64,
            (&raw const local) as u64,
            1,
            (&raw const remote) as u64,
            1,
            0,
        ],
    );
    if result != bytes as i64 {
        fail(ERROR_INSTRUCTION_READ);
    }
    value
}

/// # Safety
/// Only kernel SA_SIGINFO delivery may call this C ABI entry, with a live
/// initialized siginfo and unique writable native x86-64 ucontext prefix on
/// the owned alternate stack. The installed CONTROL mapping must remain live.
unsafe extern "C" fn instruction_handler(
    signal: i32,
    info: *mut KernelInfo,
    raw: *mut KernelContext,
) {
    if signal != SIGSEGV || info.is_null() || raw.is_null() {
        fail(ERROR_SIGNAL);
    }
    // SAFETY: the callback contract supplies a valid initialized siginfo.
    // The provenance checks below decide which delivery is supported.
    let information = unsafe { &*info };
    // SAFETY: the callback contract uniquely grants this delivery's writable
    // native ucontext prefix; no interrupted Rust reference aliases it.
    let context = unsafe { &mut *raw };
    if information.signo != SIGSEGV || information.code != SI_KERNEL || context.gregs[TRAPNO] != 13
    {
        fail(ERROR_SIGNAL);
    }
    enter_handler();
    let flags = event_flags();
    let ip = context.gregs[RIP];
    let sp = context.gregs[RSP];
    // A #GP does not prove readable text. Fallible gate copies refuse an
    // unreadable/cross-boundary opcode without dereferencing guest pointers.
    let opcode = read_instruction_bytes(ip, 2);
    let first = opcode[0];
    let second = opcode[1];
    if [first, second] == [0x0f, 0xa2] {
        let leaf = context.gregs[RAX] as u32;
        let subleaf = context.gregs[RCX] as u32;
        let self_ip = ptr::addr_of!(probe_cpuid_probe_ip) as u64;
        let self_test = flags == FLAG_SELF_TEST;
        if self_test && (ip != self_ip || leaf != MAGIC_CPUID_LEAF) {
            fail(ERROR_SELF_TEST);
        }
        let synthetic = leaf == MAGIC_CPUID_LEAF || ip == control().guest_rip;
        let mut result = CPUID_REPLY;
        if !synthetic {
            // Test-only faithful host CPUID. All blockable signals are masked by the
            // kernel action while native faulting is temporarily disabled;
            // it is rearmed before any return toward guest instructions.
            if gate(158, [ARCH_SET_CPUID, 1, 0, 0, 0, 0]) != 0 {
                fail(ERROR_CPUID_FORWARD);
            }
            // SAFETY: result is a live aligned writable four-word array. The
            // checked assembly writes exactly those four words, preserves
            // RBX and the stack, and obeys the declared C ABI.
            unsafe { probe_native_cpuid(leaf, subleaf, &raw mut result) };
            if gate(158, [ARCH_SET_CPUID, 0, 0, 0, 0, 0]) != 0 {
                fail(ERROR_CPUID_FORWARD);
            }
        }
        append(
            EVENT_CPUID,
            flags | if synthetic { 0 } else { FLAG_NATIVE_CPUID },
            ip,
            sp,
            leaf as u64,
            [leaf as u64, subleaf as u64, 0, 0, 0, 0],
            result,
        );
        context.gregs[RAX] = result[0];
        context.gregs[RBX] = result[1];
        context.gregs[RCX] = result[2];
        context.gregs[RDX] = result[3];
        context.gregs[RIP] = ip + 2;
        if self_test {
            add_control(CONTROL_CPUID_PROBE);
        }
    } else if [first, second] == [0x0f, 0x31]
        || ([first, second] == [0x0f, 0x01]
            && read_instruction_bytes(
                ip.checked_add(2)
                    .unwrap_or_else(|| fail(ERROR_INSTRUCTION_READ)),
                1,
            )[0] == 0xf9)
    {
        let rdtscp = second == 0x01;
        let self_test = flags == FLAG_SELF_TEST;
        let probe_ip = if rdtscp {
            ptr::addr_of!(probe_rdtscp_probe_ip) as u64
        } else {
            ptr::addr_of!(probe_rdtsc_probe_ip) as u64
        };
        if self_test && ip != probe_ip {
            fail(ERROR_SELF_TEST);
        }
        append(
            if rdtscp { EVENT_RDTSCP } else { EVENT_RDTSC },
            flags,
            ip,
            sp,
            if rdtscp { 0x0f01f9 } else { 0x0f31 },
            [0; 6],
            [TSC_REPLY, if rdtscp { TSC_AUX_REPLY } else { 0 }, 0, 0],
        );
        context.gregs[RAX] = TSC_REPLY as u32 as u64;
        context.gregs[RDX] = TSC_REPLY >> 32;
        if rdtscp {
            context.gregs[RCX] = TSC_AUX_REPLY;
        }
        context.gregs[RIP] = ip + if rdtscp { 3 } else { 2 };
        if self_test {
            add_control(CONTROL_TSC_PROBE);
        }
    } else {
        fail(ERROR_INSTRUCTION);
    }
    IN_HANDLER.store(0, Ordering::Release);
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    fail(ERROR_PANIC)
}

/// Prebuilt core may retain a DW.ref to the personality even with panic=abort.
/// This image never unwinds: any unexpected call is a named fatal refusal.
// SAFETY: this freestanding image supplies the unique link symbol. It borrows
// no unwinder arguments or frames and cannot return into an unwinding path.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() -> ! {
    fail(ERROR_PERSONALITY)
}

// LLVM may lower Rust aggregate copies/initialization to these symbols. They
// are our own scalar Rust operations, never a libc dependency or syscall path.
// Volatile accesses prevent the implementation from lowering to itself.
/// # Safety
/// Source must be valid for `bytes` initialized byte reads and destination for
/// `bytes` writes; the ranges must not overlap. The destination must permit
/// mutation with no aliasing Rust reference. A zero byte count performs no
/// pointer access.
// SAFETY: this freestanding image is linked without libc; this is its unique
// conventional memcpy export used by compiler-generated copies.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(
    destination: *mut c_void,
    source: *const c_void,
    bytes: usize,
) -> *mut c_void {
    let destination = destination.cast::<u8>();
    let source = source.cast::<u8>();
    for offset in 0..bytes {
        // SAFETY: the caller supplies nonoverlapping in-bounds byte extents;
        // offset is strictly below bytes and u8 imposes no extra alignment.
        unsafe {
            destination
                .add(offset)
                .write_volatile(source.add(offset).read_volatile())
        };
    }
    destination.cast()
}

/// # Safety
/// The source must be valid for `bytes` initialized byte reads and destination
/// for `bytes` writes, with mutation permitted by Rust aliasing rules. The
/// ranges may overlap. A zero byte count performs no pointer access.
// SAFETY: this is the freestanding image's unique conventional memmove export.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(
    destination: *mut c_void,
    source: *const c_void,
    bytes: usize,
) -> *mut c_void {
    let destination = destination.cast::<u8>();
    let source = source.cast::<u8>();
    if (destination as usize) <= source as usize {
        for offset in 0..bytes {
            // SAFETY: both extents are valid. Forward order reads every
            // source byte before an overlapping destination can replace it;
            // no memcpy nonoverlap contract is assumed on this path.
            unsafe {
                destination
                    .add(offset)
                    .write_volatile(source.add(offset).read_volatile())
            };
        }
        destination.cast()
    } else {
        for offset in (0..bytes).rev() {
            // SAFETY: both extents are valid. Reverse order preserves unread
            // source bytes when destination begins above source.
            unsafe {
                destination
                    .add(offset)
                    .write_volatile(source.add(offset).read_volatile())
            };
        }
        destination.cast()
    }
}

/// # Safety
/// Destination must be writable for `bytes` bytes with mutation permitted by
/// Rust aliasing rules. A zero byte count performs no pointer access.
// SAFETY: this is the freestanding image's unique conventional memset export.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(destination: *mut c_void, value: i32, bytes: usize) -> *mut c_void {
    let destination = destination.cast::<u8>();
    for offset in 0..bytes {
        // SAFETY: the caller grants the full writable byte extent and offset
        // is in bounds; truncation to u8 matches memset's byte semantics.
        unsafe { destination.add(offset).write_volatile(value as u8) };
    }
    destination.cast()
}

/// # Safety
/// Both inputs must be valid for `bytes` initialized byte reads. The ranges
/// may overlap. A zero byte count performs no pointer access.
// SAFETY: this is the freestanding image's unique conventional memcmp export.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const c_void, right: *const c_void, bytes: usize) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for offset in 0..bytes {
        // SAFETY: the caller supplies both initialized readable extents;
        // offset is in bounds and byte accesses need no stronger alignment.
        let (a, b) = unsafe {
            (
                left.add(offset).read_volatile(),
                right.add(offset).read_volatile(),
            )
        };
        if a != b {
            return i32::from(a) - i32::from(b);
        }
    }
    0
}
