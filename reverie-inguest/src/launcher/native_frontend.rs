//! Prebuilt native frontend in the actual Command child, with one filter.
//! Source/data identity is not permission to launch an arbitrary native image.

use std::io;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use crate::seccomp::SeccompFilter;

/// Fixed native bootstrap gate address shared with the actual C/ASM producer.
pub const GATE_BASE: usize = 0x5000_0000_0000;
/// Entire copied and verified gate PT_LOAD length, including padding.
pub const GATE_BYTES: usize = 4096;

unsafe extern "C" {
    fn reverie_native_launch_syscall(
        number: i64,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> i64;
}

core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl reverie_native_launch_syscall",
    ".hidden reverie_native_launch_syscall",
    ".type reverie_native_launch_syscall,@function",
    "reverie_native_launch_syscall:",
    "endbr64",
    "push r12",
    "mov rax,rdi",
    "mov rdi,rsi",
    "mov rsi,rdx",
    "mov rdx,rcx",
    "mov r10,r8",
    "mov r8,r9",
    "mov r9,[rsp+16]",
    "lea r12,[rip+.Lnative_launch_return]",
    "mov rcx,0x50000000007c",
    "jmp rcx",
    ".Lnative_launch_return:",
    "endbr64",
    "pop r12",
    "ret",
    ".size reverie_native_launch_syscall,.-reverie_native_launch_syscall",
);

/// Final target entry for Command's unchanged prepared path/argv/envp.
/// Every returned kernel exec result takes the surviving fixed fatal edge.
///
/// # Safety
/// The admitted native child mapped the complete qualified fixed gate page and
/// installed the exact inherited native filter. All pointers are Command's
/// actual prepared unchanged vectors, live until the kernel copies them.
pub unsafe extern "C" fn terminal_execve(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    unsafe {
        reverie_native_launch_syscall(
            libc::SYS_execve,
            path as u64,
            argv as u64,
            envp as u64,
            0,
            0,
            0,
        );
        reverie_native_launch_syscall(libc::SYS_exit_group, 127, 0, 0, 0, 0, 0);
        core::arch::asm!("ud2", options(noreturn));
    }
}

/// Preallocated qualified gate bytes and the actual distinct filter recipe.
/// This object is created only from producer-qualified sealed artifact roles.
pub struct NativeFrontend {
    gate: Box<[u8; GATE_BYTES]>,
    filter: SeccompFilter,
    prepared: AtomicBool,
    installed: AtomicBool,
}

impl NativeFrontend {
    /// # Safety
    /// The caller has validated the actual sealed bootstrap PT_LOAD, complete
    /// gate bytes/ABI and compiled native source/artifact identities. These
    /// bytes must not be taken from a request, guessed digest or mutable image.
    /// The object is one physical launch; no caller reuses child transitions.
    pub unsafe fn new(gate: Box<[u8; GATE_BYTES]>) -> io::Result<Self> {
        Ok(Self {
            gate,
            filter: SeccompFilter::for_native_exec_domain()?,
            prepared: AtomicBool::new(false),
            installed: AtomicBool::new(false),
        })
    }

    /// Establish W→RX gates and drop all namespace-changing capabilities.
    /// Call after common root entry, before sending the startup observation.
    ///
    /// # Safety
    /// Single actual Command child, no guest code/threads/filter, all source
    /// pins retained. This operation is fork-safe and uses no heap/formatter.
    pub unsafe fn prepare_child(&mut self) -> io::Result<()> {
        if self.prepared.swap(true, Ordering::AcqRel)
            || unsafe { libc::getpid() } != unsafe { libc::syscall(libc::SYS_gettid) } as i32
            || unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 0
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let page = unsafe {
            libc::mmap(
                GATE_BASE as *mut _,
                GATE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if page as usize != GATE_BASE {
            return Err(io::Error::from_raw_os_error(libc::EADDRINUSE));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(self.gate.as_ptr(), page.cast::<u8>(), GATE_BYTES)
        };
        if unsafe { libc::mprotect(page, GATE_BYTES, libc::PROT_READ | libc::PROT_EXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for index in 0..GATE_BYTES {
            if unsafe { page.cast::<u8>().add(index).read_volatile() } != self.gate[index] {
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
        }
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let personality = unsafe { libc::personality(0xffff_ffff) };
        if personality < 0
            || personality as u32 & libc::READ_IMPLIES_EXEC as u32 != 0
            || unsafe {
                libc::personality(
                    personality as libc::c_ulong | libc::ADDR_NO_RANDOMIZE as libc::c_ulong,
                )
            } < 0
        {
            return Err(io::Error::last_os_error());
        }
        unsafe { drop_capabilities()? };
        Ok(())
    }

    /// Install the one native filter after actual host startup acknowledgement.
    /// The next operation must be Command's terminal target execution entry.
    ///
    /// # Safety
    /// Actual same-child prepared root/gates/capabilities and host ACK remain
    /// live; no other filter or callback may run. There is no teardown path
    /// after publication: any failed post-install check uses the fixed exit.
    pub unsafe fn install_child(&mut self) -> io::Result<()> {
        if !self.prepared.load(Ordering::Acquire)
            || self.installed.swap(true, Ordering::AcqRel)
            || unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 0
        {
            return Err(io::Error::from_raw_os_error(libc::EPERM));
        }
        let program = self.filter.native_program();
        if unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                libc::SECCOMP_FILTER_FLAG_TSYNC,
                &program,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe {
            reverie_native_launch_syscall(
                libc::SYS_prctl,
                libc::PR_GET_SECCOMP as u64,
                0,
                0,
                0,
                0,
                0,
            )
        } != 2
        {
            unsafe {
                reverie_native_launch_syscall(libc::SYS_exit_group, 127, 0, 0, 0, 0, 0);
                core::arch::asm!("ud2", options(noreturn));
            }
        }
        Ok(())
    }
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}
#[derive(Clone, Copy)]
#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe fn drop_capabilities() -> io::Result<()> {
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    for capability in 0..64 {
        let value = unsafe { libc::prctl(libc::PR_CAPBSET_READ, capability, 0, 0, 0) };
        if value < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                break;
            }
            return Err(io::Error::last_os_error());
        }
        if value != 0 && unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // NOROOT/locked, NO_SETUID_FIXUP/locked and KEEP_CAPS_LOCKED.
    if unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 1 | 2 | 4 | 8 | 32, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &header, &data) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
