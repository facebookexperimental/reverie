//! Linux syscall-buffer ABI, independent of the tool's target C library.
//!
//! A musl-built tool can supervise GNU, musl or freestanding guests. Guest
//! syscall buffers follow the kernel UAPI, not the tool libc's wrapper structs.
//! GNU aliases retain existing public pointer and conversion signatures.

/// Generated Linux statx layout used to validate the serializable adapter.
pub use linux_raw_sys::general::statx as KernelStatx;
/// Generated Linux statx timestamp layout.
pub use linux_raw_sys::general::statx_timestamp as KernelStatxTimestamp;
/// Generated Linux sysinfo layout; never the extended musl wrapper structure.
pub use linux_raw_sys::system::sysinfo as KernelSysinfo;

/// statx buffer used by typed syscall arguments.
#[cfg(not(target_env = "musl"))]
pub type Statx = libc::statx;
/// statx buffer used by typed syscall arguments.
#[cfg(target_env = "musl")]
pub type Statx = crate::StatxBuf;
/// statx timestamp used by typed syscall arguments.
#[cfg(not(target_env = "musl"))]
pub type StatxTimestamp = libc::statx_timestamp;
/// statx timestamp used by typed syscall arguments.
#[cfg(target_env = "musl")]
pub type StatxTimestamp = crate::StatxTimestamp;
/// sysinfo buffer used by typed syscall arguments.
#[cfg(not(target_env = "musl"))]
pub type Sysinfo = libc::sysinfo;
/// sysinfo buffer used by typed syscall arguments.
#[cfg(target_env = "musl")]
pub type Sysinfo = KernelSysinfo;

/// Query statx with the target-libc adapter for the kernel ABI.
///
/// GNU retains its existing libc wrapper semantics. Musl uses the syscall
/// directly, without requiring a libc-version-specific statx symbol.
///
/// # Safety
/// `path` must be NUL-terminated and `out` must designate a writable Statx.
pub unsafe fn statx(
    dirfd: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mask: libc::c_uint,
    out: *mut Statx,
) -> libc::c_int {
    // SAFETY: the caller supplies the syscall's pointer validity requirements;
    // Statx has the kernel layout, checked against generated UAPI in tests.
    #[cfg(not(target_env = "musl"))]
    unsafe {
        libc::statx(dirfd, path, flags, mask, out)
    }
    #[cfg(target_env = "musl")]
    unsafe {
        libc::syscall(libc::SYS_statx, dirfd, path, flags, mask, out) as libc::c_int
    }
}

// The existing Detcore mask/projection logic uses these same kernel values.
/// Attribute bit marking a filesystem mount root.
pub use linux_raw_sys::general::STATX_ATTR_MOUNT_ROOT;
/// statx request/result bit for the inode number.
pub use linux_raw_sys::general::STATX_INO;
/// statx request/result bit for the mount identifier.
pub use linux_raw_sys::general::STATX_MNT_ID;
/// statx request/result bit for the file type.
pub use linux_raw_sys::general::STATX_TYPE;

// The GNU compatibility alias must remain the same kernel wire layout.
const _: () = {
    assert!(core::mem::size_of::<Sysinfo>() == core::mem::size_of::<KernelSysinfo>());
    assert!(core::mem::align_of::<Sysinfo>() == core::mem::align_of::<KernelSysinfo>());
    assert!(core::mem::offset_of!(Sysinfo, uptime) == core::mem::offset_of!(KernelSysinfo, uptime));
    assert!(core::mem::offset_of!(Sysinfo, loads) == core::mem::offset_of!(KernelSysinfo, loads));
    assert!(
        core::mem::offset_of!(Sysinfo, totalram) == core::mem::offset_of!(KernelSysinfo, totalram)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, freeram) == core::mem::offset_of!(KernelSysinfo, freeram)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, sharedram)
            == core::mem::offset_of!(KernelSysinfo, sharedram)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, bufferram)
            == core::mem::offset_of!(KernelSysinfo, bufferram)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, totalswap)
            == core::mem::offset_of!(KernelSysinfo, totalswap)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, freeswap) == core::mem::offset_of!(KernelSysinfo, freeswap)
    );
    assert!(core::mem::offset_of!(Sysinfo, procs) == core::mem::offset_of!(KernelSysinfo, procs));
    assert!(core::mem::offset_of!(Sysinfo, pad) == core::mem::offset_of!(KernelSysinfo, pad));
    assert!(
        core::mem::offset_of!(Sysinfo, totalhigh)
            == core::mem::offset_of!(KernelSysinfo, totalhigh)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, freehigh) == core::mem::offset_of!(KernelSysinfo, freehigh)
    );
    assert!(
        core::mem::offset_of!(Sysinfo, mem_unit) == core::mem::offset_of!(KernelSysinfo, mem_unit)
    );
};

// Linux UAPI values whose libc exports vary by target environment. Their signed
// aliases match syscall flag/advice/notification arguments, not libc wrappers.
/// Request cached statx attributes without forcing synchronization.
pub const AT_STATX_DONT_SYNC: i32 = linux_raw_sys::general::AT_STATX_DONT_SYNC as i32;
/// Mask selecting the statx synchronization mode.
pub const AT_STATX_SYNC_TYPE: i32 = linux_raw_sys::general::AT_STATX_SYNC_TYPE as i32;
/// Linux synchronous transparent-hugepage collapse advice.
pub const MADV_COLLAPSE: i32 = linux_raw_sys::general::MADV_COLLAPSE as i32;
/// Linux POSIX timer notification directed to a particular thread.
pub const SIGEV_THREAD_ID: i32 = linux_raw_sys::general::SIGEV_THREAD_ID as i32;

// Resource IDs are unsigned kernel syscall arguments, even when target libc
// exposes signed C enum constants. No libc resource wrapper is changed here.
/// Linux procfs filesystem type identifier.
pub use linux_raw_sys::general::PROC_SUPER_MAGIC;
/// Resource identifier for the maximum core dump size.
pub use linux_raw_sys::general::RLIMIT_CORE;
/// Resource identifier for process CPU time.
pub use linux_raw_sys::general::RLIMIT_CPU;
/// Resource identifier for the data segment size.
pub use linux_raw_sys::general::RLIMIT_DATA;
/// Resource identifier for the open file descriptor limit.
pub use linux_raw_sys::general::RLIMIT_NOFILE;
/// Resource identifier for uninterrupted real-time CPU time.
pub use linux_raw_sys::general::RLIMIT_RTTIME;
/// Resource identifier for the process stack size.
pub use linux_raw_sys::general::RLIMIT_STACK;
/// Linux sysfs filesystem type identifier.
pub use linux_raw_sys::general::SYSFS_MAGIC;

/// Linux scheduler's single signed-priority word, independent of libc wrappers.
/// GNU keeps the existing public pointer type for source compatibility.
#[cfg(not(target_env = "musl"))]
pub type SchedParam = libc::sched_param;
/// Linux scheduler wire buffer; musl libc may expose obsolete wrapper extensions.
#[cfg(target_env = "musl")]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SchedParam {
    /// Linux scheduling priority (not an extended userspace wrapper).
    pub sched_priority: i32,
}

const _: () = {
    assert!(core::mem::size_of::<SchedParam>() == 4);
    assert!(core::mem::align_of::<SchedParam>() == 4);
    assert!(core::mem::offset_of!(SchedParam, sched_priority) == 0);
};

#[cfg(test)]
mod non_socket_wire_tests {
    use super::*;

    #[test]
    fn linux_uapi_constants_preserve_flag_and_resource_meanings() {
        assert_eq!(AT_STATX_DONT_SYNC, 0x4000);
        assert_eq!(AT_STATX_SYNC_TYPE, 0x6000);
        assert_eq!(AT_STATX_DONT_SYNC & AT_STATX_SYNC_TYPE, AT_STATX_DONT_SYNC);
        assert_eq!(MADV_COLLAPSE, 25);
        assert_eq!(SIGEV_THREAD_ID, 4);
        assert_ne!(SIGEV_THREAD_ID, libc::SIGEV_THREAD);
        assert_eq!(
            [
                RLIMIT_CPU,
                RLIMIT_DATA,
                RLIMIT_STACK,
                RLIMIT_CORE,
                RLIMIT_NOFILE,
                RLIMIT_RTTIME
            ],
            [0, 2, 3, 4, 7, 15]
        );
    }

    #[test]
    fn sched_param_is_exactly_one_signed_kernel_word() {
        assert_eq!(core::mem::size_of::<SchedParam>(), 4);
        assert_eq!(core::mem::align_of::<SchedParam>(), 4);
        for priority in [i32::MIN, -1, 0, 1, i32::MAX] {
            let parameter = SchedParam {
                sched_priority: priority,
            };
            // SAFETY: repr(C) single i32, statically checked no padding; all
            // four initialized bytes belong to this live value.
            let bytes = unsafe {
                core::slice::from_raw_parts((&parameter as *const SchedParam).cast::<u8>(), 4)
            };
            assert_eq!(bytes, priority.to_ne_bytes());
        }
    }
}

mod socket;

/// Generated x86-64 raw kernel alternate-stack descriptor.
pub use linux_raw_sys::general::stack_t as KernelStack;
/// Generated x86-64 raw kernel fstat buffer.
pub use linux_raw_sys::general::stat as KernelStat;
pub use socket::Cmsghdr;
pub use socket::Mmsghdr;
pub use socket::Msghdr;
