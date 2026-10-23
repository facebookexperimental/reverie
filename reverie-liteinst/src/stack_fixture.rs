//! Separate M2 stack observations in the actual constructor-bearing runtime.
//!
//! This module never prepares a continuation, registers a stack, selects stack
//! storage, or allocates. Its own C-ABI entry is not an isolated-stack claim.
//! Fixed M1 exports and their workload remain independent of these diagnostics.

use std::cell::Cell;
use std::mem::align_of;
use std::mem::size_of;

use reverie_inguest::guest::continuation;
use reverie_inguest::trap::raw_syscall6;

const ABI_VERSION: u64 = 1;
const PROBE_CONTROL: u64 = 1;
const PROBE_LOWER: u64 = 2;
const PROBE_UPPER: u64 = 4;

/// Fixed C/Rust observation layout. Probe results are literal kernel returns.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct M2StackQuery {
    pub abi_version: u64,
    pub status: u64,
    pub current_tid: u64,
    pub alt_result: i64,
    pub alt_sp: u64,
    pub alt_size: u64,
    pub alt_flags: u64,
    pub continuation_prepared: u64,
    pub continuation_bottom: u64,
    pub continuation_top: u64,
    pub continuation_owner_tid: u64,
    pub marker_number: u64,
    pub marker_guest_ip: u64,
    pub marker_arm_tid: u64,
    pub marker_armed: u64,
    pub marker_hits: u64,
    pub reached_rsp: u64,
    pub reached_tid: u64,
    pub reached_guest_ip: u64,
    pub owned_entries: u64,
    pub owned_callbacks: u64,
    pub owned_completions: u64,
    pub alt_probe_mask: u64,
    pub alt_read_result: i64,
    pub alt_lower_result: i64,
    pub alt_upper_result: i64,
    pub continuation_probe_mask: u64,
    pub continuation_read_result: i64,
    pub continuation_lower_result: i64,
    pub continuation_upper_result: i64,
}

const _: [(); 240] = [(); size_of::<M2StackQuery>()];

#[derive(Clone, Copy)]
struct MarkerObservation {
    number: u64,
    guest_ip: u64,
    arm_tid: u64,
    armed: u64,
    hits: u64,
    rsp: u64,
    tid: u64,
    reached_ip: u64,
}

impl MarkerObservation {
    const EMPTY: Self = Self {
        number: 0,
        guest_ip: 0,
        arm_tid: 0,
        armed: 0,
        hits: 0,
        rsp: 0,
        tid: 0,
        reached_ip: 0,
    };
}

thread_local! {
    // Native, const-initialized TLS with no destructor or heap-backed state.
    // TLS placement is a separately outstanding isolation boundary.
    static MARKER: Cell<MarkerObservation> = const { Cell::new(MarkerObservation::EMPTY) };
}

fn raw_tid() -> i64 {
    // SAFETY: the trusted gate performs this scalar Linux syscall directly.
    unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) }
}

/// Arm this thread's observer for one known syscall instruction.
///
/// This resets only fixture state. It neither prepares nor executes a callback.
#[unsafe(no_mangle)]
pub extern "C" fn m2_stack_arm(number: usize, guest_ip: usize) -> i32 {
    if number > i64::MAX as usize || guest_ip == 0 {
        return -libc::EINVAL;
    }
    let tid = raw_tid();
    if tid <= 0 {
        return -libc::EIO;
    }
    MARKER.set(MarkerObservation {
        number: number as u64,
        guest_ip: guest_ip as u64,
        arm_tid: tid as u64,
        armed: 1,
        ..MarkerObservation::EMPTY
    });
    0
}

/// Called only from genuine fallback dispatch after its existing RCB boundary.
#[inline(never)]
pub(crate) fn record_fallback(number: usize, guest_ip: usize) {
    let mut observation = MARKER.get();
    if observation.armed == 0
        || observation.number != number as u64
        || observation.guest_ip != guest_ip as u64
    {
        return;
    }
    let tid = raw_tid();
    if tid <= 0 || observation.arm_tid != tid as u64 {
        return;
    }
    let rsp: usize;
    // SAFETY: read the hardware stack pointer at this actual dispatch entry.
    // No caller-supplied address, descriptor or async-local pointer replaces it.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem, preserves_flags),
        );
    }
    observation.hits = observation.hits.saturating_add(1);
    observation.rsp = rsp as u64;
    observation.tid = tid as u64;
    observation.reached_ip = guest_ip as u64;
    MARKER.set(observation);
}

#[derive(Clone, Copy)]
struct ReadProbes {
    mask: u64,
    control: i64,
    lower: i64,
    upper: i64,
}

impl ReadProbes {
    const NOT_PROBED: Self = Self {
        mask: 0,
        control: 0,
        lower: 0,
        upper: 0,
    };
}

fn read_byte(pid: i64, address: usize) -> i64 {
    let mut byte = 0u8;
    let local = libc::iovec {
        iov_base: (&raw mut byte).cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: 1,
    };
    // SAFETY: the local one-byte output and both iovecs remain live throughout
    // the direct syscall. The kernel checks the remote address without a Rust
    // dereference or a destructive write to a baseline boundary.
    unsafe {
        raw_syscall6(
            libc::SYS_process_vm_readv,
            [
                pid as u64,
                (&raw const local) as u64,
                1,
                (&raw const remote) as u64,
                1,
                0,
            ],
        )
    }
}

fn probe_range(pid: i64, bottom: usize, bytes: usize) -> ReadProbes {
    if pid <= 0 || bottom == 0 || bytes == 0 {
        return ReadProbes::NOT_PROBED;
    }
    let Some(top) = bottom.checked_add(bytes) else {
        return ReadProbes::NOT_PROBED;
    };
    let Some(lower) = bottom.checked_sub(1) else {
        return ReadProbes::NOT_PROBED;
    };
    ReadProbes {
        mask: PROBE_CONTROL | PROBE_LOWER | PROBE_UPPER,
        control: read_byte(pid, bottom),
        lower: read_byte(pid, lower),
        upper: read_byte(pid, top),
    }
}

/// Read actual kernel altstack registration and already prepared owner state.
///
/// Disabled, unprepared and invalid ranges have a zero probe mask; their zero
/// result slots are not claimed as kernel permission denials. A boundary
/// -EFAULT is a real denied read, not by itself proof of a reserved mapping.
///
/// # Safety
///
/// `out` must point to a writable, properly aligned 240-byte output record that
/// the caller exclusively owns. This is the diagnostic ABI, not a guest-memory
/// authorization API. It never initializes or enters a continuation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m2_stack_query(out: *mut M2StackQuery, bytes: usize) -> i32 {
    if out.is_null()
        || bytes != size_of::<M2StackQuery>()
        || (out as usize) & (align_of::<M2StackQuery>() - 1) != 0
    {
        return -libc::EINVAL;
    }
    let tid = raw_tid();
    // SAFETY: this syscall takes no user pointers.
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let mut stack = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    // SAFETY: direct query only. The kernel writes the live local stack_t;
    // nullptr first argument cannot install or replace the registered stack.
    let alt_result = unsafe {
        raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0],
        )
    };
    let (prepared, bottom, top, owner_tid) = continuation::fixture_stack_descriptor()
        .map_or((0, 0, 0, 0), |(bottom, top, tid)| (1, bottom, top, tid));
    let alt_probes = if alt_result == 0 && stack.ss_flags & libc::SS_DISABLE == 0 {
        probe_range(pid, stack.ss_sp as usize, stack.ss_size)
    } else {
        ReadProbes::NOT_PROBED
    };
    let continuation_probes = if prepared == 1 {
        top.checked_sub(bottom)
            .map_or(ReadProbes::NOT_PROBED, |bytes| {
                probe_range(pid, bottom, bytes)
            })
    } else {
        ReadProbes::NOT_PROBED
    };
    let observation = MARKER.get();
    let result = if tid <= 0 || pid <= 0 {
        -libc::EIO
    } else {
        alt_result as i32
    };
    let record = M2StackQuery {
        abi_version: ABI_VERSION,
        status: u64::from(result != 0),
        current_tid: tid as u64,
        alt_result,
        alt_sp: stack.ss_sp as u64,
        alt_size: stack.ss_size as u64,
        alt_flags: u64::from(stack.ss_flags as u32),
        continuation_prepared: prepared,
        continuation_bottom: bottom as u64,
        continuation_top: top as u64,
        continuation_owner_tid: u64::from(owner_tid),
        marker_number: observation.number,
        marker_guest_ip: observation.guest_ip,
        marker_arm_tid: observation.arm_tid,
        marker_armed: observation.armed,
        marker_hits: observation.hits,
        reached_rsp: observation.rsp,
        reached_tid: observation.tid,
        reached_guest_ip: observation.reached_ip,
        owned_entries: continuation::owned_observation(0),
        owned_callbacks: continuation::owned_observation(1),
        owned_completions: continuation::owned_observation(2),
        alt_probe_mask: alt_probes.mask,
        alt_read_result: alt_probes.control,
        alt_lower_result: alt_probes.lower,
        alt_upper_result: alt_probes.upper,
        continuation_probe_mask: continuation_probes.mask,
        continuation_read_result: continuation_probes.control,
        continuation_lower_result: continuation_probes.lower,
        continuation_upper_result: continuation_probes.upper,
    };
    // SAFETY: the caller's output contract and alignment were checked above.
    unsafe { out.write(record) };
    result
}
