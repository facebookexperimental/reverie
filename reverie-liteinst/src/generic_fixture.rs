//! Read-only generic-origin/kernel observations, separate from frozen M1/M2/M3.
//! No reservation, adoption, stack registration, getter or phase mutation occurs.
use std::mem::align_of;
use std::mem::size_of;

use reverie_inguest::guest::tool_region::BASE;
use reverie_inguest::guest::tool_region::ConstructorStackRecord;
use reverie_inguest::guest::tool_region::reverie_inguest_constructor_stack_query;
use reverie_inguest::guest::tool_region::reverie_inguest_generic_stack_query;
use reverie_inguest::trap::raw_syscall6;

/// Version-one 81-word ABI; samples are retained records, not first instructions.
#[repr(C)]
#[allow(missing_docs)]
pub struct GenericKernelQuery {
    pub version: u64,
    pub status: i64,
    pub tid: i64,
    pub pid: i64,
    pub alt_result: i64,
    pub alt_sp: u64,
    pub alt_size: u64,
    pub alt_flags: u64,
    pub mincore_result: i64,
    pub constructor_result: i64,
    pub constructor: ConstructorStackRecord,
    pub generic_result: i64,
    pub generic: ConstructorStackRecord,
    pub probe_mask: u64,
    pub interior: i64,
    pub lower: i64,
    pub upper: i64,
    pub bitmap_result: i64,
    pub bitmap: [u64; 33],
}
const _: () = assert!(size_of::<GenericKernelQuery>() == 81 * 8);
const _: () = assert!(align_of::<GenericKernelQuery>() == 8);

fn read(pid: i64, address: u64, output: *mut libc::c_void, length: usize) -> i64 {
    let local = libc::iovec {
        iov_base: output,
        iov_len: length,
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: length,
    };
    // SAFETY: callers provide live local storage; the kernel checks the remote.
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

/// Query real kernel state and separately authenticated constructor/generic owners.
/// No caller-supplied remote addresses and no initialization on an absent query.
///
/// # Safety
/// Output must designate 648 writable, eight-byte-aligned bytes without aliasing
/// live Tool metadata. This export is only for the trusted diagnostic fixture.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn m4_generic_query(output: *mut GenericKernelQuery, bytes: usize) -> i32 {
    if output.is_null() || bytes != size_of::<GenericKernelQuery>() || (output as usize) & 7 != 0 {
        return -libc::EINVAL;
    }
    // SAFETY: these use the existing trusted gate and live local scalar outputs.
    let tid = unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let mut alt: libc::stack_t = unsafe { std::mem::zeroed() };
    let alt_result = unsafe {
        raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut alt) as u64, 0, 0, 0, 0],
        )
    };
    let mut residency = 0_u8;
    let mincore_result = unsafe {
        raw_syscall6(
            libc::SYS_mincore,
            [BASE as u64, 4096, (&raw mut residency) as u64, 0, 0, 0],
        )
    };
    let mut constructor: ConstructorStackRecord = unsafe { std::mem::zeroed() };
    let mut generic: ConstructorStackRecord = unsafe { std::mem::zeroed() };
    let constructor_result =
        unsafe { reverie_inguest_constructor_stack_query(&raw mut constructor) };
    let generic_result = unsafe { reverie_inguest_generic_stack_query(&raw mut generic) };
    let status = if tid <= 0 || pid <= 0 {
        -i64::from(libc::EIO)
    } else {
        alt_result
    };
    let mut q = GenericKernelQuery {
        version: 1,
        status,
        tid,
        pid,
        alt_result,
        alt_sp: alt.ss_sp as u64,
        alt_size: alt.ss_size as u64,
        alt_flags: alt.ss_flags as u64,
        mincore_result,
        constructor_result: i64::from(constructor_result),
        constructor,
        generic_result: i64::from(generic_result),
        generic,
        probe_mask: 0,
        interior: 0,
        lower: 0,
        upper: 0,
        bitmap_result: 0,
        bitmap: [0; 33],
    };
    if generic_result == 0 && pid > 0 {
        let mut byte = 0_u8;
        q.probe_mask = 15;
        q.interior = read(pid, q.generic.bottom, (&raw mut byte).cast(), 1);
        q.lower = read(pid, q.generic.bottom - 1, (&raw mut byte).cast(), 1);
        q.upper = read(pid, q.generic.top, (&raw mut byte).cast(), 1);
        // Source-frozen Control occupied[] offset8, bootstrap pages256..2305.
        q.bitmap_result = read(
            pid,
            q.generic.control_address + 8 + 4 * 8,
            q.bitmap.as_mut_ptr().cast(),
            size_of::<[u64; 33]>(),
        );
    }
    // SAFETY: the caller promises one complete writable output.
    unsafe { output.write(q) };
    status as i32
}
