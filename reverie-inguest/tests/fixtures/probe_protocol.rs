/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Stage-1a test-only ABI. This contains no platform operations and is usable
//! from a `no_std` image and from the host probe. None of its stages claims
//! Detcore registration, a scheduler grant, vDSO control, or production readiness.

#![allow(dead_code)]

use core::mem::align_of;
use core::mem::offset_of;
use core::mem::size_of;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;

pub const PAGE_BYTES: u64 = 4096;
pub const TOOL_BASE: u64 = 0x6000_0000_0000;
pub const TOOL_END: u64 = 0x6001_0000_0000;
pub const PROBE_WINDOW: core::ops::Range<u64> = TOOL_BASE + 0xdf00_0000..TOOL_BASE + 0xe000_0000;
pub const LOADER_GATE: u64 = TOOL_BASE + 0xe000_0000;
pub const RUNTIME_GATE: u64 = TOOL_BASE + 0xe100_0000;
pub const CONTROL_ADDRESS: u64 = PROBE_WINDOW.start;
pub const STACK_BOTTOM: u64 = PROBE_WINDOW.start + 0x2000;
pub const STACK_TOP: u64 = PROBE_WINDOW.start + 0x20_2000;
pub const ALTSTACK_BOTTOM: u64 = PROBE_WINDOW.start + 0x20_4000;
pub const ALTSTACK_TOP: u64 = PROBE_WINDOW.start + 0x30_4000;
pub const JOURNAL_ADDRESS: u64 = PROBE_WINDOW.start + 0x40_0000;
pub const JOURNAL_END: u64 = PROBE_WINDOW.start + 0xc0_0000;
pub const CONTROL_BYTES: usize = 4096;
pub const EVENT_BYTES: usize = 128;
pub const EVENT_CAPACITY: u64 = 65_536;
pub const JOURNAL_BYTES: u64 = EVENT_CAPACITY * EVENT_BYTES as u64;
pub const ABI_VERSION: u32 = 1;
pub const CONTROL_MAGIC: u64 = u64::from_le_bytes(*b"RVLDTST1");
pub const READY_MAGIC: u64 = u64::from_le_bytes(*b"RVREADY1");
/// The actual INT3 byte, not the RIP reported after its execution.
pub const READY_IP: u64 = LOADER_GATE + 0x100;
pub const READY_STOP_IP: u64 = READY_IP + 1;
/// The loader's deliberately trapped gettid: `mov eax,186; syscall; ret`.
pub const LOADER_GETTID_IP: u64 = LOADER_GATE + 5;
pub const LOADER_GETTID_POST_IP: u64 = LOADER_GATE + 7;

pub const PHASE_BOOTSTRAP: u32 = 0;
pub const PHASE_INSTALLING: u32 = 1;
pub const PHASE_SELF_TESTING: u32 = 2;
pub const PHASE_TEST_CONTROLS_READY: u32 = 3;
/// First intercepted guest operation observed; not an instruction census.
pub const PHASE_GUEST_OBSERVED: u32 = 4;
pub const PHASE_FAILED: u32 = u32::MAX;

pub const CONTROL_SIGSYS: u64 = 1 << 0;
pub const CONTROL_SIGSEGV: u64 = 1 << 1;
pub const CONTROL_ALTSTACK: u64 = 1 << 2;
pub const CONTROL_FILTER: u64 = 1 << 3;
pub const CONTROL_CPUID: u64 = 1 << 4;
pub const CONTROL_TSC: u64 = 1 << 5;
pub const CONTROL_FDS_CLOSED: u64 = 1 << 6;
pub const CONTROL_CPUID_PROBE: u64 = 1 << 7;
pub const CONTROL_TSC_PROBE: u64 = 1 << 8;
pub const CONTROL_SYSCALL_PROBE: u64 = 1 << 9;
pub const REQUIRED_CONTROLS: u64 = (1 << 10) - 1;

pub const EVENT_BOOTSTRAP: u32 = 1;
pub const EVENT_SYSCALL_ENTER: u32 = 2;
pub const EVENT_SYSCALL_RETURN: u32 = 3;
pub const EVENT_CPUID: u32 = 4;
pub const EVENT_RDTSC: u32 = 5;
pub const EVENT_RDTSCP: u32 = 6;
pub const EVENT_REFUSAL: u32 = 7;
pub const EVENT_FAILURE: u32 = 8;
pub const FLAG_SELF_TEST: u32 = 1;
pub const FLAG_GUEST: u32 = 2;
pub const FLAG_EXPECTED_NORETURN: u32 = 4;
/// CPUID was forwarded natively under a temporary, handler-local control toggle.
pub const FLAG_NATIVE_CPUID: u32 = 8;

pub const ERROR_NONE: u32 = 0;
pub const ERROR_CONTROL: u32 = 1;
pub const ERROR_ALTSTACK: u32 = 2;
pub const ERROR_SIGACTION: u32 = 3;
pub const ERROR_CPUID_ARM: u32 = 4;
pub const ERROR_TSC_ARM: u32 = 5;
pub const ERROR_NO_NEW_PRIVS: u32 = 6;
pub const ERROR_FILTER: u32 = 7;
pub const ERROR_CLOSE: u32 = 8;
pub const ERROR_SELF_TEST: u32 = 9;
pub const ERROR_JOURNAL_FULL: u32 = 10;
pub const ERROR_SIGNAL: u32 = 11;
pub const ERROR_REENTRANT: u32 = 12;
pub const ERROR_GUEST_CONTROL: u32 = 13;
pub const ERROR_INSTRUCTION: u32 = 14;
pub const ERROR_CPUID_FORWARD: u32 = 15;
pub const ERROR_MASK: u32 = 16;
pub const ERROR_INSTRUCTION_READ: u32 = 17;
pub const ERROR_PERSONALITY: u32 = 18;
pub const ERROR_PANIC: u32 = 19;

pub const EXIT_FAILURE: i32 = 125;
pub const REFUSAL_CLONE: u64 = 1;
pub const REFUSAL_EXEC: u64 = 2;
pub const REFUSAL_GUEST_CONTROL: u64 = 3;
pub const MAGIC_CPUID_LEAF: u32 = 0x4fff_e001;
pub const CPUID_REPLY: [u64; 4] = [0x1357_2468, 0x2468_1357, 0x3141_5926, 0x2718_2818];
pub const TSC_REPLY: u64 = 0x0102_0304_0506_0708;
pub const TSC_AUX_REPLY: u64 = 0x1234_5678;

/// Exactly one shared page. The first512 bytes are parent-owned immutable
/// inputs by protocol. Parent-owned ptrace snapshots, never these advisory
/// copies of entry values, supply the final guest register restoration.
#[repr(C)]
pub struct ProbeControlV1 {
    pub magic: u64,
    pub abi_version: u32,
    pub bytes: u32,
    pub nonce: [u64; 2],
    pub runtime_entry: u64,
    pub guest_rip: u64,
    pub guest_rsp: u64,
    pub guest_fs: u64,
    pub guest_gs: u64,
    pub guest_sigmask: u64,
    pub runtime_stack_lo: u64,
    pub runtime_stack_hi: u64,
    pub altstack_lo: u64,
    pub altstack_hi: u64,
    pub journal_base: u64,
    pub journal_capacity: u64,
    pub fd_count: u32,
    /// Version1 has no selectable behavioral flags. Nonzero is refused.
    pub flags: u32,
    pub fds: [i32; 8],
    pub reserved_input: [u64; 43],
    pub phase: AtomicU32,
    pub error: AtomicU32,
    pub controls: AtomicU64,
    pub events_reserved: AtomicU64,
    pub events_committed: AtomicU64,
    pub overflow: AtomicU64,
    /// Published before TestControlsReady's release store.
    pub ready_nonce: [AtomicU64; 2],
    pub reserved_status: [u8; 3528],
}

impl ProbeControlV1 {
    /// A zero-input page with initialized scalar atomics. The host fills its
    /// inputs before mapping/starting an image. This does not establish readiness.
    pub const fn empty() -> Self {
        Self {
            magic: CONTROL_MAGIC,
            abi_version: ABI_VERSION,
            bytes: CONTROL_BYTES as u32,
            nonce: [0; 2],
            runtime_entry: 0,
            guest_rip: 0,
            guest_rsp: 0,
            guest_fs: 0,
            guest_gs: 0,
            guest_sigmask: 0,
            runtime_stack_lo: STACK_BOTTOM,
            runtime_stack_hi: STACK_TOP,
            altstack_lo: ALTSTACK_BOTTOM,
            altstack_hi: ALTSTACK_TOP,
            journal_base: JOURNAL_ADDRESS,
            journal_capacity: EVENT_CAPACITY,
            fd_count: 0,
            flags: 0,
            fds: [-1; 8],
            reserved_input: [0; 43],
            phase: AtomicU32::new(PHASE_BOOTSTRAP),
            error: AtomicU32::new(ERROR_NONE),
            controls: AtomicU64::new(0),
            events_reserved: AtomicU64::new(0),
            events_committed: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            ready_nonce: [AtomicU64::new(0), AtomicU64::new(0)],
            reserved_status: [0; 3528],
        }
    }
}

/// A lossless append-only event. `commit == seq+1` publishes all preceding
/// fields. An unused/uncommitted slot has commit0. No slot is reused. A syscall
/// ENTER precedes forwarding; its RETURN carries `results[0]`, or ENTER records
/// FLAG_EXPECTED_NORETURN for exit. CPUID uses args[0..2] for leaf/subleaf and
/// results for EAX/EBX/ECX/EDX. TSC uses `results[0]` for the 64-bit value and
/// `results[1]` for RDTSCP's AUX. Refusals retain the original syscall and arguments;
/// `results[0]` holds the named `REFUSAL_*` category and `results[1]` the errno.
#[repr(C)]
pub struct ProbeEventV1 {
    pub seq: u64,
    pub kind: u32,
    pub flags: u32,
    pub ip: u64,
    pub sp: u64,
    pub nr_or_opcode: u64,
    pub args: [u64; 6],
    pub results: [u64; 4],
    pub commit: AtomicU64,
}

/// seccomp reports the instruction pointer after the two-byte syscall. Both
/// bytes must lie in the gate; the first excluded post-IP is gate.end+1.
pub const fn gate_contains_post_ip(gate: u64, ip: u64) -> bool {
    gate + 2 <= ip && ip <= gate + PAGE_BYTES
}

const _: () = {
    assert!(size_of::<ProbeControlV1>() == CONTROL_BYTES);
    assert!(align_of::<ProbeControlV1>() == 8);
    assert!(offset_of!(ProbeControlV1, runtime_entry) == 32);
    assert!(offset_of!(ProbeControlV1, fds) == 136);
    assert!(offset_of!(ProbeControlV1, phase) == 512);
    assert!(offset_of!(ProbeControlV1, controls) == 520);
    assert!(offset_of!(ProbeControlV1, events_reserved) == 528);
    assert!(offset_of!(ProbeControlV1, events_committed) == 536);
    assert!(offset_of!(ProbeControlV1, overflow) == 544);
    assert!(offset_of!(ProbeControlV1, ready_nonce) == 552);
    assert!(size_of::<ProbeEventV1>() == EVENT_BYTES);
    assert!(align_of::<ProbeEventV1>() == 8);
    assert!(offset_of!(ProbeEventV1, ip) == 16);
    assert!(offset_of!(ProbeEventV1, args) == 40);
    assert!(offset_of!(ProbeEventV1, results) == 88);
    assert!(offset_of!(ProbeEventV1, commit) == 120);
    assert!(JOURNAL_BYTES == JOURNAL_END - JOURNAL_ADDRESS);
    assert!(PROBE_WINDOW.end == LOADER_GATE);
    assert!(STACK_TOP + PAGE_BYTES <= ALTSTACK_BOTTOM);
    assert!(ALTSTACK_TOP + PAGE_BYTES <= JOURNAL_ADDRESS);
    assert!(JOURNAL_END + PAGE_BYTES <= PROBE_WINDOW.end);
};
