//! Read-only kernel observations for the separate standalone constructor test.
//!
//! Native Strace/Compat intentionally refuse the probe's unpublished guest
//! syscall site except for read/write. This diagnostic uses the same existing
//! trusted syscall gate as M2; it never changes that guest admission, initializes
//! a region, registers a stack, mutates a constructor record or allocates.

use std::mem::align_of;
use std::mem::size_of;

use reverie_inguest::guest::tool_region::BASE;
use reverie_inguest::guest::tool_region::ConstructorStackRecord;
use reverie_inguest::guest::tool_region::reverie_inguest_constructor_stack_query;
use reverie_inguest::trap::raw_syscall6;

/// Version-one, 64-word scalar ABI, separate from the frozen M1/M2 exports.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct M3StandaloneQuery {
    /// Literal ABI version 1.
    pub version: u64,
    /// Kernel TID/PID/query coherence status; absent reservation is not an error.
    pub status: i64,
    /// Actual kernel TID, unaffected by a built-in getpid spoof.
    pub kernel_tid: i64,
    /// Actual kernel PID, distinct from an intercepted guest getpid operation.
    pub kernel_pid: i64,
    /// Actual query-only sigaltstack return value.
    pub alt_result: i64,
    /// Actual registered alternate stack base.
    pub alt_sp: u64,
    /// Actual registered alternate stack size.
    pub alt_size: u64,
    /// Actual registered alternate stack flags.
    pub alt_flags: u64,
    /// Actual mincore return at the fixed reservation's first page.
    pub mincore_result: i64,
    /// Existing constructor query result; -1 means genuinely absent/unpublished.
    pub constructor_result: i64,
    /// Unchanged actual constructor scalar record, zero when absent.
    pub constructor: ConstructorStackRecord,
    /// Bits 1/2/4/8 mean interior/lower/upper/bitmap probes were attempted.
    pub probe_mask: u64,
    /// Actual kernel one-byte interior read result.
    pub interior_result: i64,
    /// Actual kernel one-byte lower guard read result.
    pub lower_result: i64,
    /// Actual kernel one-byte upper guard read result.
    pub upper_result: i64,
    /// Actual kernel copy result for the bootstrap occupancy words.
    pub bitmap_result: i64,
    /// Raw occupied words covering all 2050 bootstrap pages, guards included.
    pub bitmap: [u64; 33],
}

const _: () = assert!(size_of::<M3StandaloneQuery>() == 512);
const _: () = assert!(align_of::<M3StandaloneQuery>() == 8);

fn read_bytes(pid: i64, address: u64, output: *mut libc::c_void, bytes: usize) -> i64 {
    let local = libc::iovec {
        iov_base: output,
        iov_len: bytes,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: bytes,
    };
    // SAFETY: every caller supplies a live writable local buffer of this size.
    // The kernel checks remote readability; guard failures do not dereference it.
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

fn read_one(pid: i64, address: u64) -> i64 {
    let mut byte = 0_u8;
    read_bytes(pid, address, (&raw mut byte).cast(), 1)
}

/// Copy actual kernel state and the existing authenticated constructor record.
/// No caller-selected lease/guard address is accepted. Query success has no
/// first-instruction, guest-write protection or caller-window isolation credit.
///
/// # Safety
/// `output` must point to 512 writable bytes aligned to 8, unless null. It must
/// not alias live Tool metadata. Call only from this trusted diagnostic fixture.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m3_standalone_query(output: *mut M3StandaloneQuery, bytes: usize) -> i32 {
    if output.is_null()
        || bytes != size_of::<M3StandaloneQuery>()
        || (output as usize) & (align_of::<M3StandaloneQuery>() - 1) != 0
    {
        return -libc::EINVAL;
    }
    // SAFETY: these syscalls take no user pointers and use the existing gate.
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let mut alternate = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    // SAFETY: null input is query-only; the kernel writes the live local output.
    let alt_result = unsafe {
        raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut alternate) as u64, 0, 0, 0, 0],
        )
    };
    let mut residency = 0_u8;
    // SAFETY: mincore does not map/protect/write the probed page; the one-byte
    // local residency output is valid for this literal one-page request.
    let mincore_result = unsafe {
        raw_syscall6(
            libc::SYS_mincore,
            [BASE as u64, 4096, (&raw mut residency) as u64, 0, 0, 0],
        )
    };
    // SAFETY: the original constructor ABI consists exclusively of u64 scalars.
    let mut constructor: ConstructorStackRecord = unsafe { std::mem::zeroed() };
    // SAFETY: the original read-only query writes one complete live record.
    let constructor_result =
        unsafe { reverie_inguest_constructor_stack_query(&raw mut constructor) };
    let status = if tid <= 0 || pid <= 0 {
        -i64::from(libc::EIO)
    } else {
        alt_result
    };
    let mut query = M3StandaloneQuery {
        version: 1,
        status,
        kernel_tid: tid,
        kernel_pid: pid,
        alt_result,
        alt_sp: alternate.ss_sp as u64,
        alt_size: alternate.ss_size as u64,
        alt_flags: alternate.ss_flags as u64,
        mincore_result,
        constructor_result: i64::from(constructor_result),
        constructor,
        probe_mask: 0,
        interior_result: 0,
        lower_result: 0,
        upper_result: 0,
        bitmap_result: 0,
        bitmap: [0; 33],
    };
    if constructor_result == 0 && pid > 0 {
        query.probe_mask = 15;
        query.interior_result = read_one(pid, query.constructor.bottom);
        query.lower_result = read_one(pid, query.constructor.bottom - 1);
        query.upper_result = read_one(pid, query.constructor.top);
        // Frozen repr(C) Control has held at 0, padding then occupied u64[] at 8.
        // The real bootstrap owns pages 256..2305: 32 full words and 2 bits.
        // Return raw kernel-copied words; the consumer decides occupancy.
        query.bitmap_result = read_bytes(
            pid,
            query.constructor.control_address + 8 + 4 * 8,
            query.bitmap.as_mut_ptr().cast(),
            size_of::<[u64; 33]>(),
        );
    }
    // SAFETY: the caller promises a writable correctly aligned output record.
    unsafe { output.write(query) };
    status as i32
}
