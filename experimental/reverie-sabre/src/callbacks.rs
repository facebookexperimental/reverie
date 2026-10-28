/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie_syscalls::LocalMemory;
use reverie_syscalls::Syscall;
use syscalls::Errno;
use syscalls::SyscallArgs;
use syscalls::Sysno;
use syscalls::syscall;

use super::ffi;
use super::thread;
use super::thread::GuestTransitionErr;
use super::thread::PidTid;
use super::thread::Thread;
use super::tool::SyscallExt;
use super::tool::Tool;
use super::tool::ToolGlobal;
use super::utils;
use super::vdso;
use crate::protected_files;
use crate::signal::guard;
use crate::stats;
use crate::stats::SabreSlowPath;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-140): Review the loader-owned syscall-frame lifetime boundary.
thread_local! {
    static CURRENT_SYSCALL_FRAME: std::cell::Cell<*mut ffi::syscall_stackframe> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
    static TAIL_INJECTED_EXIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

const VFORK_CHILD_SLOT_COUNT: usize = 64;
const VFORK_CHILD_SIGHAND: u64 = 1 << 32;
const VFORK_CHILD_RESERVED: u64 = 1 << 63;
const NO_VFORK_SLOT: usize = usize::MAX;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-285): Review private vfork memory and exec-order handshake.
struct VforkChildSlot {
    entry: AtomicU64,
    pid_namespace: AtomicU64,
    sync_read: AtomicI32,
    sync_write: AtomicI32,
}

impl VforkChildSlot {
    const fn new() -> Self {
        Self {
            entry: AtomicU64::new(0),
            pid_namespace: AtomicU64::new(0),
            sync_read: AtomicI32::new(-1),
            sync_write: AtomicI32::new(-1),
        }
    }
}

// Parents reserve slots before entering the kernel and pass the slot index to
// child trampolines in a syscall-preserved XMM register. Child identity is the
// PID-namespace inode plus namespace-relative PID, so CLONE_NEWPID children do
// not collide with PID 1 in the parent's namespace. The fixed table remains
// visible across CLONE_VM even when CLONE_SETTLS replaces child TLS.
static VFORK_CHILDREN: [VforkChildSlot; VFORK_CHILD_SLOT_COUNT] =
    [const { VforkChildSlot::new() }; VFORK_CHILD_SLOT_COUNT];

/// Keeps a vfork child on a native pre-exec gate while its parent is blocked
/// inside the kernel and owns an in-flight tool/RPC request.
struct VforkBoundaryGuard {
    slot: usize,
    _signal_restore: guard::VforkSignalGuardRestore,
}

impl VforkBoundaryGuard {
    fn enter() -> Option<Self> {
        for (slot_index, slot) in VFORK_CHILDREN.iter().enumerate() {
            if slot
                .entry
                .compare_exchange(0, VFORK_CHILD_RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.pid_namespace.store(0, Ordering::Release);
                let pipe = match protected_files::protect_raw_pair_with(|| {
                    let mut pipe = [-1i32; 2];
                    unsafe {
                        syscalls::syscall2(
                            Sysno::pipe2,
                            pipe.as_mut_ptr() as usize,
                            libc::O_CLOEXEC as usize,
                        )?;
                    }
                    Ok::<_, Errno>((pipe[0], pipe[1]))
                }) {
                    Ok(pipe) => pipe,
                    Err(_) => {
                        slot.entry.store(0, Ordering::Release);
                        return None;
                    }
                };
                slot.sync_read.store(pipe.0, Ordering::Release);
                slot.sync_write.store(pipe.1, Ordering::Release);
                return Some(Self {
                    slot: slot_index,
                    _signal_restore: guard::preserve_signal_guard_count_across_vfork(),
                });
            }
        }
        None
    }

    fn slot(&self) -> usize {
        self.slot
    }

    fn wait_for_child_exec(&self, result: usize) -> usize {
        if result as isize <= 0 {
            return result;
        }
        let slot = &VFORK_CHILDREN[self.slot];
        close_slot_fd(&slot.sync_write);
        let read_fd = slot.sync_read.load(Ordering::Acquire);
        if read_fd >= 0 {
            let mut byte = 0u8;
            loop {
                match unsafe {
                    syscalls::syscall3(
                        Sysno::read,
                        read_fd as usize,
                        (&mut byte as *mut u8) as usize,
                        1,
                    )
                } {
                    Ok(0) => break,
                    Ok(_) | Err(Errno::EINTR) => continue,
                    Err(_) => break,
                }
            }
        }
        close_slot_fd(&slot.sync_read);
        result
    }
}

impl Drop for VforkBoundaryGuard {
    fn drop(&mut self) {
        let slot = &VFORK_CHILDREN[self.slot];
        close_slot_fd(&slot.sync_read);
        close_slot_fd(&slot.sync_write);
        slot.pid_namespace.store(0, Ordering::Release);
        slot.entry.store(0, Ordering::Release);
    }
}

fn close_slot_fd(fd: &AtomicI32) {
    let fd = fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        protected_files::unprotect_raw_fd(fd);
        let _ = unsafe { syscalls::syscall1(Sysno::close, fd as usize) };
    }
}

fn prepare_private_vfork_child(slot_index: usize) -> bool {
    let Some(slot) = VFORK_CHILDREN.get(slot_index) else {
        return false;
    };
    if slot.entry.load(Ordering::Acquire) != VFORK_CHILD_RESERVED {
        return false;
    }
    // The child keeps the close-on-exec write end open while it registers with
    // the tool. Closing the read end ensures only the parent observes EOF.
    close_slot_fd(&slot.sync_read);
    let write_fd = slot.sync_write.load(Ordering::Acquire);
    if write_fd < 0 {
        return false;
    }
    protected_files::protect_raw_fd(write_fd);
    true
}

fn is_vfork_child_process() -> bool {
    vfork_child_flags().is_some()
}

fn vfork_child_flags() -> Option<usize> {
    let current_pid = current_process_id();
    if current_pid == 0 {
        return None;
    }
    let has_pid_match = VFORK_CHILDREN.iter().any(|slot| {
        let entry = slot.entry.load(Ordering::Acquire);
        entry & VFORK_CHILD_RESERVED == 0 && entry as u32 == current_pid
    });
    has_pid_match
        .then(current_pid_namespace)
        .flatten()
        .and_then(|pid_namespace| vfork_child_flags_for(current_pid, pid_namespace))
}

fn vfork_child_flags_for(current_pid: u32, pid_namespace: u64) -> Option<usize> {
    VFORK_CHILDREN.iter().find_map(|slot| {
        let entry = slot.entry.load(Ordering::Acquire);
        (entry & VFORK_CHILD_RESERVED == 0
            && entry as u32 == current_pid
            && current_pid != 0
            && slot.pid_namespace.load(Ordering::Acquire) == pid_namespace)
            .then_some(if entry & VFORK_CHILD_SIGHAND != 0 {
                libc::CLONE_SIGHAND as usize
            } else {
                0
            })
    })
}

/// Update the vfork registry before a clone child reaches its first guest callback.
///
/// This function is called directly from clone trampolines. It must remain
/// allocation-free and independent of TLS because clone may install guest TLS.
#[no_mangle]
pub extern "C" fn reverie_sabre_after_clone_child(clone_flags: usize, vfork_slot: usize) {
    // Process-forming raw clone trampolines abandon their Rust frames in the
    // child, so the copied guard cannot release the slot-map lock there.
    // Release it before any child callback can consult thread state.
    if clone_flags & libc::CLONE_VM as usize == 0 {
        unsafe { crate::slot_map::unlock_after_fork_child() };
    }

    let vfork_flags = (libc::CLONE_VM | libc::CLONE_VFORK) as usize;
    if clone_flags & vfork_flags != vfork_flags {
        if prepare_private_vfork_child(vfork_slot) {
            return;
        }
        // A private fork child inherited a snapshot of the parent's registry,
        // but none of the parent's other threads or vfork children. Scrub that
        // private copy before PID reuse can make a stale entry match.
        if clone_flags & libc::CLONE_VM as usize == 0 {
            for slot in &VFORK_CHILDREN {
                slot.pid_namespace.store(0, Ordering::Release);
                slot.entry.store(0, Ordering::Release);
            }
        }
        return;
    }

    let child_pid = current_process_id();
    let pid_namespace = current_pid_namespace().unwrap_or(0);
    if activate_vfork_child(vfork_slot, child_pid, pid_namespace, clone_flags) {
        return;
    }

    // Continuing without a registry slot could re-enter the blocked parent's
    // RPC transport. Fail closed using a raw per-task exit.
    unsafe {
        loop {
            let _ = syscalls::syscall1(Sysno::exit, libc::EAGAIN as usize);
        }
    }
}

fn activate_vfork_child(
    slot_index: usize,
    child_pid: u32,
    pid_namespace: u64,
    clone_flags: usize,
) -> bool {
    if slot_index >= VFORK_CHILD_SLOT_COUNT || child_pid == 0 || pid_namespace == 0 {
        return false;
    }
    let slot = &VFORK_CHILDREN[slot_index];
    if slot.entry.load(Ordering::Acquire) != VFORK_CHILD_RESERVED {
        return false;
    }
    let mut entry = u64::from(child_pid);
    if clone_flags & libc::CLONE_SIGHAND as usize != 0 {
        entry |= VFORK_CHILD_SIGHAND;
    }
    slot.pid_namespace.store(pid_namespace, Ordering::Release);
    slot.entry.store(entry, Ordering::Release);
    true
}

fn current_process_id() -> u32 {
    unsafe { syscalls::syscall0(Sysno::getpid) }.unwrap_or(0) as u32
}

fn current_pid_namespace() -> Option<u64> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    unsafe {
        syscalls::syscall4(
            Sysno::newfstatat,
            libc::AT_FDCWD as usize,
            c"/proc/self/ns/pid".as_ptr() as usize,
            metadata.as_mut_ptr() as usize,
            0,
        )
        .ok()?;
        Some(metadata.assume_init().st_ino)
    }
}

fn is_vfork_native_syscall_allowed(sys_no: Sysno) -> bool {
    matches!(
        sys_no,
        Sysno::rt_sigaction
            | Sysno::rt_sigprocmask
            | Sysno::sigaltstack
            | Sysno::getuid
            | Sysno::geteuid
            | Sysno::getgid
            | Sysno::getegid
            | Sysno::setresuid
            | Sysno::setresgid
            | Sysno::execve
            | Sysno::execveat
            | Sysno::exit
            | Sysno::exit_group
    )
}

/// Keeps the loader's live syscall frame available to the synchronous shared-tool callback.
pub(crate) struct SyscallFrameGuard {
    previous: *mut ffi::syscall_stackframe,
}

impl SyscallFrameGuard {
    pub(crate) fn enter(frame: *mut ffi::syscall_stackframe) -> Self {
        let previous = CURRENT_SYSCALL_FRAME.replace(frame);
        Self { previous }
    }

    pub(crate) fn suspend() -> Self {
        Self::enter(std::ptr::null_mut())
    }
}

impl Drop for SyscallFrameGuard {
    fn drop(&mut self) {
        CURRENT_SYSCALL_FRAME.set(self.previous);
    }
}

pub(crate) fn current_syscall_frame() -> Option<*mut ffi::syscall_stackframe> {
    CURRENT_SYSCALL_FRAME.with(|frame| {
        let frame = frame.get();
        (!frame.is_null()).then_some(frame)
    })
}

pub(crate) fn request_tail_injected_exit(exit_code: usize) {
    TAIL_INJECTED_EXIT.with(|status| {
        assert!(
            status.replace(Some(exit_code)).is_none(),
            "nested tail-injected exits are unsupported"
        );
    });
}

pub(crate) fn terminate_tail_injected_exit_if_requested<E: thread::EventSink>(
    thread: &mut Thread<E>,
) {
    if let Some(exit_code) = TAIL_INJECTED_EXIT.with(std::cell::Cell::take) {
        // Publish the runtime slot before the raw exit. Group teardown waits on this state and a
        // direct raw exit would otherwise leave the slot permanently in Handler.
        let _ = thread.try_exit();
        terminate(exit_code);
    }
}

pub const CONTROLLED_EXIT_SIGNAL: libc::c_int = libc::SIGSTKFLT;

const CLONE_ARGS_MIN_SIZE: usize = 64;
const CLONE_ARGS_MAX_SIZE: usize = 4096;

#[derive(Clone)]
#[repr(C, align(8))]
struct Clone3Buffer([u8; CLONE_ARGS_MAX_SIZE]);

#[derive(Clone)]
struct Clone3Fields {
    size: usize,
    buffer: Clone3Buffer,
}

impl Clone3Fields {
    fn flags(&self) -> u64 {
        u64::from_ne_bytes(self.buffer.0[0..8].try_into().unwrap())
    }

    fn stack(&self) -> u64 {
        u64::from_ne_bytes(self.buffer.0[40..48].try_into().unwrap())
    }

    fn is_vfork(&self) -> bool {
        let required = (libc::CLONE_VM | libc::CLONE_VFORK) as u64;
        self.flags() & required == required
    }

    fn args_ptr(&self) -> usize {
        self.buffer.0.as_ptr() as usize
    }

    fn private_fork(&self) -> Result<Self, Errno> {
        let mut fields = self.clone();
        let flags = private_vfork_flags(self.flags())?;
        fields.buffer.0[0..8].copy_from_slice(&flags.to_ne_bytes());
        Ok(fields)
    }
}

fn private_vfork_flags(flags: u64) -> Result<u64, Errno> {
    let incompatible = (libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64;
    if flags & incompatible != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(flags & !(libc::CLONE_VM | libc::CLONE_VFORK) as u64)
}

/// Snapshot clone3's arguments without directly dereferencing guest memory.
///
/// `process_vm_readv` asks the kernel to validate the address, preserving the
/// syscall's `EFAULT` behavior when the guest supplies an invalid pointer. The
/// syscall consumes this stable copy so a sibling cannot change flags between
/// the vfork decision and the child trampoline.
fn read_clone3_fields(pid: u32, args: usize, size: usize) -> Result<Box<Clone3Fields>, Errno> {
    // Let clone3 itself report EINVAL for undersized argument structures.
    if size < CLONE_ARGS_MIN_SIZE {
        return Ok(Box::new(Clone3Fields {
            size,
            buffer: Clone3Buffer([0; CLONE_ARGS_MAX_SIZE]),
        }));
    }
    if size > CLONE_ARGS_MAX_SIZE {
        return Err(Errno::E2BIG);
    }

    let mut buffer = Clone3Buffer([0; CLONE_ARGS_MAX_SIZE]);
    let local = libc::iovec {
        iov_base: buffer.0.as_mut_ptr().cast(),
        iov_len: size,
    };
    let remote = libc::iovec {
        iov_base: args as *mut libc::c_void,
        iov_len: size,
    };
    let copied = unsafe {
        syscall!(
            Sysno::process_vm_readv,
            pid as usize,
            &local as *const libc::iovec as usize,
            1,
            &remote as *const libc::iovec as usize,
            1,
            0
        )?
    };

    if copied != size {
        return Err(Errno::EFAULT);
    }

    Ok(Box::new(Clone3Fields { size, buffer }))
}

/// Implement the thread notifier trait for any global tools
impl<T> thread::EventSink for T
where
    T: ToolGlobal,
{
    #[inline]
    fn on_new_thread(pid_tid: PidTid) {
        T::global().on_thread_start(pid_tid.tid);
    }

    fn on_thread_exit(pid_tid: PidTid) {
        T::global().on_thread_exit(pid_tid.tid);
    }
}

static POST_LOAD_PENDING: AtomicBool = AtomicBool::new(false);

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-194): Review the SaBRe loader-to-tool post-load bridge.
pub extern "C" fn handle_post_load<T: ToolGlobal>(is_static: bool) {
    // A static client has no client-side dynamic-loader phase in which to
    // construct the tool. Initialize it while SaBRe's libc startup state is
    // still intact, before the loader rewrites the initial stack for the
    // guest. Post-load delivery remains deferred until the first callback,
    // after the guest thread has been registered.
    if is_static {
        let _ = T::global();
    }
    POST_LOAD_PENDING.store(true, Ordering::Release);
}

pub extern "C" fn handle_syscall<T: ToolGlobal>(
    syscall: isize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    wrapper_sp: *mut ffi::syscall_stackframe,
) -> usize {
    // A vfork child shares the blocked parent's address space, including an
    // in-flight RPC transport. Calling the tool before exec would deadlock on
    // that inherited request. Run only the child preparation syscalls through
    // SaBRe's native syscall policy; a successful exec creates a fresh image
    // and resumes normal tool interception at its first callback.
    if let Some(clone_flags) = vfork_child_flags() {
        let sys_no = Sysno::from(syscall as i32);
        if !is_vfork_native_syscall_allowed(sys_no) {
            stats::increment_guest_slow_path(SabreSlowPath::VforkChildRejected);
            return -Errno::ENOSYS.into_raw() as usize;
        }
        if sys_no == Sysno::rt_sigaction {
            // CLONE_SIGHAND makes the kernel signal-action table shared with
            // the blocked parent. Without it, issue the raw syscall so the
            // child's private kernel table changes without mutating Reverie's
            // process-global handler metadata in the shared address space.
            if clone_flags & libc::CLONE_SIGHAND as usize != 0 {
                stats::increment_guest_slow_path(SabreSlowPath::VforkChildRejected);
                return -Errno::ENOSYS.into_raw() as usize;
            }
            stats::increment_guest_slow_path(SabreSlowPath::VforkChildNativeDispatch);
            return unsafe {
                syscalls::syscall6(sys_no, arg1, arg2, arg3, arg4, arg5, arg6)
                    .unwrap_or_else(|error| -error.into_raw() as usize)
            };
        }
        let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);
        let intercepted = Syscall::from_raw(sys_no, args);
        stats::increment_guest_slow_path(SabreSlowPath::VforkChildNativeDispatch);
        return unsafe { intercepted.call() }.unwrap_or_else(|error| -error.into_raw() as usize);
    }

    let mut thread = if let Some(thread) = Thread::<T>::current() {
        thread
    } else {
        terminate(1);
    };

    // The loader callback runs before libc has published the client's
    // environment. Defer tool construction and post-exec delivery until the
    // first rewritten syscall, when private tool selection is available.
    if POST_LOAD_PENDING.swap(false, Ordering::AcqRel) {
        T::global().on_post_load();
    }

    match handle_syscall_with_thread::<T>(
        &mut thread,
        syscall,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
        arg6,
        wrapper_sp,
    ) {
        Ok(return_code) => return_code,
        Err(GuestTransitionErr::ExitNow) => terminate(0),
        Err(GuestTransitionErr::ExitingElsewhere) => 0,
    }
}

/// Handle the critical section for the given system call on the given thread
// The arguments intentionally mirror SaBRe's raw syscall callback ABI.
#[allow(clippy::if_same_then_else, clippy::too_many_arguments)]
fn handle_syscall_with_thread<T: ToolGlobal>(
    thread: &mut Thread<T>,
    syscall: isize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    wrapper_sp: *mut ffi::syscall_stackframe,
) -> Result<usize, GuestTransitionErr> {
    let _guard = guard::enter_signal_exclusion_zone();
    thread.leave_guest_execution()?;
    guard::drain_pending();

    let sys_no = Sysno::from(syscall as i32);
    let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);
    let intercepted = Syscall::from_raw(sys_no, args);
    let wrapper_address = wrapper_sp as usize;
    let return_address = unsafe { (*wrapper_sp).ret } as usize;
    let _frame_guard = SyscallFrameGuard::enter(wrapper_sp);

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-214): Review eager child registration before guest resume.
    // Register clone children lazily at their first intercepted syscall. Rust
    // bookkeeping at the raw clone return can allocate before pthread startup
    // completes, deadlocking the in-guest allocator under concurrent clones.
    // TODO-HUMAN-REVIEW(PR-226): Review deferred clone-child registration.
    let is_clone_vfork = sys_no == Sysno::clone && utils::is_vfork(sys_no, arg1);
    let result = if is_clone_vfork {
        if let Some(vfork_boundary) = VforkBoundaryGuard::enter() {
            thread.maybe_fork_as_guest(|| {
                T::global()
                    .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                        let private_flags = match private_vfork_flags(arg1 as u64) {
                            Ok(flags) => flags as usize,
                            Err(errno) => return -errno.into_raw() as usize,
                        };
                        let result = if arg2 == 0 {
                            ffi::fork_syscall(
                                private_flags,
                                arg3 as *mut i32,
                                arg4 as *mut i32,
                                arg5,
                                wrapper_address as *const ffi::syscall_stackframe,
                                vfork_boundary.slot() as u64,
                            )
                        } else {
                            ffi::clone_syscall(
                                private_flags,
                                arg2 as *mut libc::c_void,
                                arg3 as *mut i32,
                                arg4 as *mut i32,
                                arg5,
                                return_address as *const libc::c_void,
                                vfork_boundary.slot() as u64,
                            )
                        };
                        vfork_boundary.wait_for_child_exec(result)
                    })
                    .unwrap_or_else(|e| -e.into_raw() as usize)
            })?
        } else {
            -Errno::EAGAIN.into_raw() as usize
        }
    } else if sys_no == Sysno::clone && arg2 != 0 {
        // New thread with its own stack: the kernel sets the child's %rsp to
        // `child_stack`, so clone_syscall's `jmp r9` shortcut is correct.
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                    ffi::clone_syscall(
                        arg1,
                        arg2 as *mut libc::c_void,
                        arg3 as *mut i32,
                        arg4 as *mut i32,
                        arg5,
                        return_address as *const libc::c_void,
                        NO_VFORK_SLOT as u64,
                    )
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if sys_no == Sysno::clone {
        // clone(2) without a new stack behaves like fork: the child shares the
        // parent's stack layout and must resume the guest on its ORIGINAL %rsp,
        // which fork_syscall restores from the SaBRe syscall frame.
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                    ffi::fork_syscall(
                        arg1,
                        arg3 as *mut i32,
                        arg4 as *mut i32,
                        arg5,
                        wrapper_address as *const ffi::syscall_stackframe,
                        NO_VFORK_SLOT as u64,
                    )
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if sys_no == Sysno::fork {
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                    ffi::fork_syscall(
                        libc::SIGCHLD as usize,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        0,
                        wrapper_address as *const ffi::syscall_stackframe,
                        NO_VFORK_SLOT as u64,
                    )
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if utils::is_vfork(sys_no, arg1) {
        // SaBRe executes callbacks on the guest stack. A real vfork child would
        // therefore overwrite the blocked parent's live Rust callback frames
        // before it reaches execve. Use a private fork image instead; the shared
        // tool still classifies the original syscall as vfork and keeps the
        // parent behind its child-registration/exec barrier.
        if let Some(vfork_boundary) = VforkBoundaryGuard::enter() {
            thread.maybe_fork_as_guest(|| {
                T::global()
                    .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                        let result = ffi::fork_syscall(
                            libc::SIGCHLD as usize,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            0,
                            wrapper_address as *const ffi::syscall_stackframe,
                            vfork_boundary.slot() as u64,
                        );
                        vfork_boundary.wait_for_child_exec(result)
                    })
                    .unwrap_or_else(|e| -e.into_raw() as usize)
            })?
        } else {
            -Errno::EAGAIN.into_raw() as usize
        }
    } else if sys_no == Sysno::clone3 {
        let fields = read_clone3_fields(thread.get_process_and_thread_ids().pid, arg1, arg2);
        let clone3_intercepted = match &fields {
            Ok(fields) => Syscall::from_raw(
                sys_no,
                SyscallArgs::new(fields.args_ptr(), fields.size, arg3, arg4, arg5, arg6),
            ),
            Err(_) => intercepted,
        };
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(clone3_intercepted, &LocalMemory::new(), || match &fields {
                    Err(errno) => -(*errno).into_raw() as usize,
                    Ok(fields) => {
                        let flags = fields.flags();
                        let stack = fields.stack();
                        if fields.is_vfork() {
                            let private_fields = match fields.private_fork() {
                                Ok(fields) => fields,
                                Err(errno) => return -errno.into_raw() as usize,
                            };
                            let Some(boundary) = VforkBoundaryGuard::enter() else {
                                return -Errno::EAGAIN.into_raw() as usize;
                            };
                            unsafe {
                                let result = if private_fields.stack() == 0 {
                                    ffi::clone3_fork_syscall(
                                        private_fields.args_ptr(),
                                        private_fields.size,
                                        arg3,
                                        0,
                                        arg5,
                                        wrapper_address as *const ffi::syscall_stackframe,
                                        private_fields.flags(),
                                        boundary.slot() as u64,
                                    )
                                } else {
                                    ffi::clone3_syscall(
                                        private_fields.args_ptr(),
                                        private_fields.size,
                                        arg3,
                                        0,
                                        arg5,
                                        return_address as *mut libc::c_void,
                                        private_fields.flags(),
                                        boundary.slot() as u64,
                                    )
                                };
                                boundary.wait_for_child_exec(result)
                            }
                        } else if stack == 0 {
                            unsafe {
                                ffi::clone3_fork_syscall(
                                    fields.args_ptr(),
                                    fields.size,
                                    arg3,
                                    0,
                                    arg5,
                                    wrapper_address as *const ffi::syscall_stackframe,
                                    flags,
                                    NO_VFORK_SLOT as u64,
                                )
                            }
                        } else {
                            unsafe {
                                ffi::clone3_syscall(
                                    fields.args_ptr(),
                                    fields.size,
                                    arg3,
                                    0,
                                    arg5,
                                    return_address as *mut libc::c_void,
                                    flags,
                                    NO_VFORK_SLOT as u64,
                                )
                            }
                        }
                    }
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if sys_no == Sysno::exit {
        T::global()
            .syscall_with_inject(intercepted, &LocalMemory::new(), || {
                if thread.try_exit() {
                    terminate(arg1);
                }
                0
            })
            .unwrap_or_else(|e| -e.into_raw() as usize)
    } else if sys_no == Sysno::exit_group {
        T::global()
            .syscall_with_inject(intercepted, &LocalMemory::new(), || {
                exit_group_with_thread(thread, arg1)
            })
            .unwrap_or_else(|e| -e.into_raw() as usize)
    } else {
        thread.execute_as_guest(|| {
            T::global()
                .syscall(intercepted, &LocalMemory::new())
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    };

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-265): Review callback-bound tail-injected thread termination.
    terminate_tail_injected_exit_if_requested(thread);

    guard::drain_pending();
    thread.enter_guest_execution()?;

    Ok(result)
}

/// Terminate this thread with no notifications
fn terminate(exit_code: usize) -> ! {
    unsafe {
        syscalls::syscall1(Sysno::exit, exit_code).expect("Exit should succeed");
    }
    unreachable!("The thread should have ended by now");
}

/// Perform and exit group with the current thread
fn exit_group_with_thread<T: ToolGlobal>(thread: &mut Thread<T>, exit_code: usize) -> usize {
    prepare_group_exit(thread);
    T::global().on_process_exit(exit_code as i32);
    terminate_group(exit_code)
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-265): Review exit_group ESRCH race handling.
fn signal_controlled_exit(process_and_thread_id: PidTid) {
    let result = unsafe {
        syscalls::syscall3(
            Sysno::tgkill,
            process_and_thread_id.pid as usize,
            process_and_thread_id.tid as usize,
            CONTROLLED_EXIT_SIGNAL as usize,
        )
    };
    match result {
        Err(errno) if errno != Errno::ESRCH => panic!("Signaling thread failed: {errno}"),
        _ => {}
    }
}

fn prepare_group_exit<T: ToolGlobal>(thread: &mut Thread<T>) {
    thread.try_exit();
    if let Some(exiting_pid) =
        thread::exit_all(|_, process_and_thread_id| signal_controlled_exit(process_and_thread_id))
    {
        if !thread::wait_for_all_to_exit(exiting_pid, T::global().get_exit_timeout()) {
            let _ = T::global().on_exit_timeout();
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-175): Review default-fatal-signal lifecycle completion.
/// Runs thread-exit callbacks before the signal dispatcher restores and re-raises a fatal signal.
pub(crate) fn prepare_signal_termination<T: ToolGlobal>() {
    if let Some(mut thread) = Thread::<T>::current() {
        prepare_group_exit(&mut thread);
    }
}

pub fn exit_group<T: ToolGlobal>(exit_code: usize) -> usize {
    if let Some(mut thread) = Thread::<T>::current() {
        exit_group_with_thread(&mut thread, exit_code)
    } else {
        0
    }
}

/// If any thread receives the exit signal call, this handler will gracefully
/// exit that thread
pub extern "C" fn handle_exit_signal<T: ToolGlobal>(
    _: libc::c_int,
    _: *const libc::siginfo_t,
    _: *const libc::c_void,
) {
    let mut thread = if let Some(thread) = Thread::<T>::current() {
        thread
    } else {
        terminate(0);
    };

    if thread.try_exit() {
        terminate(0);
    }
}

extern "C" fn handle_vdso_clock_gettime<T: ToolGlobal>(
    clockid: libc::clockid_t,
    tp: *mut libc::timespec,
) -> i32 {
    if is_vfork_child_process() {
        return -libc::ENOSYS;
    }
    T::global().vdso_clock_gettime(clockid, tp)
}

extern "C" fn handle_vdso_getcpu<T: ToolGlobal>(
    cpu: *mut u32,
    node: *mut u32,
    _unused: usize,
) -> i32 {
    if is_vfork_child_process() {
        return -libc::ENOSYS;
    }
    T::global().vdso_getcpu(cpu, node, _unused)
}

extern "C" fn handle_vdso_gettimeofday<T: ToolGlobal>(
    tv: *mut libc::timeval,
    tz: *mut libc::timezone,
) -> i32 {
    if is_vfork_child_process() {
        return -libc::ENOSYS;
    }
    T::global().vdso_gettimeofday(tv, tz)
}

extern "C" fn handle_vdso_time<T: ToolGlobal>(tloc: *mut libc::time_t) -> i32 {
    if is_vfork_child_process() {
        return -libc::ENOSYS;
    }
    T::global().vdso_time(tloc)
}

pub extern "C" fn handle_vdso<T: ToolGlobal>(
    syscall: isize,
    actual_fn: ffi::void_void_fn,
) -> Option<ffi::void_void_fn> {
    use core::mem::transmute;

    unsafe {
        match Sysno::from(syscall as i32) {
            Sysno::clock_gettime => {
                vdso::clock_gettime =
                    transmute::<*const (), ffi::vdso_clock_gettime_fn>(actual_fn as *const ());
                Some(transmute::<*const (), ffi::void_void_fn>(
                    handle_vdso_clock_gettime::<T> as *const (),
                ))
            }
            Sysno::getcpu => {
                vdso::getcpu = transmute::<*const (), ffi::vdso_getcpu_fn>(actual_fn as *const ());
                Some(transmute::<*const (), ffi::void_void_fn>(
                    handle_vdso_getcpu::<T> as *const (),
                ))
            }
            Sysno::gettimeofday => {
                vdso::gettimeofday =
                    transmute::<*const (), ffi::vdso_gettimeofday_fn>(actual_fn as *const ());
                Some(transmute::<*const (), ffi::void_void_fn>(
                    handle_vdso_gettimeofday::<T> as *const (),
                ))
            }
            Sysno::time => {
                vdso::time = transmute::<*const (), ffi::vdso_time_fn>(actual_fn as *const ());
                Some(transmute::<*const (), ffi::void_void_fn>(
                    handle_vdso_time::<T> as *const (),
                ))
            }
            _ => None,
        }
    }
}

pub extern "C" fn handle_rdtsc<T: ToolGlobal>() -> u64 {
    if is_vfork_child_process() {
        terminate(libc::ENOSYS as usize);
    }
    T::global().rdtsc()
}

/// Terminate every thread in the process, including threads that have not yet
/// crossed a SaBRe interception boundary and therefore are not in our table.
fn terminate_group(exit_code: usize) -> ! {
    unsafe {
        let _ = syscalls::syscall1(Sysno::exit_group, exit_code);
    }
    unreachable!("The process should have ended by now");
}

#[cfg(test)]
mod exit_group_tests {
    use syscalls::Errno;
    use syscalls::Sysno;

    use super::NO_VFORK_SLOT;
    use super::activate_vfork_child;
    use super::is_vfork_child_process;
    use super::is_vfork_native_syscall_allowed;
    use super::private_vfork_flags;
    use super::read_clone3_fields;
    use super::reverie_sabre_after_clone_child;
    use super::signal_controlled_exit;
    use super::terminate_group;
    use super::vfork_child_flags_for;
    use crate::thread::PidTid;

    #[test]
    fn clone3_stack_read_rejects_invalid_guest_pointer() {
        assert!(matches!(
            read_clone3_fields(std::process::id(), 1, 88),
            Err(Errno::EFAULT)
        ));
    }

    #[test]
    fn clone3_fields_identify_vfork_and_stack() {
        let mut fields = [
            (libc::CLONE_VM | libc::CLONE_VFORK) as u64,
            0,
            0,
            0,
            libc::SIGCHLD as u64,
            0x1234,
            0x2000,
            0,
        ];

        let mut actual = read_clone3_fields(
            std::process::id(),
            fields.as_ptr() as usize,
            std::mem::size_of_val(&fields),
        )
        .unwrap();

        fields[0] = 0;
        assert_eq!(fields[0], 0);
        assert!(actual.is_vfork());
        assert_eq!(actual.stack(), 0x1234);
        assert_eq!(
            unsafe { *(actual.args_ptr() as *const u64) },
            (libc::CLONE_VM | libc::CLONE_VFORK) as u64
        );
        let private = actual.private_fork().unwrap();
        assert_eq!(private.flags(), 0);
        assert_eq!(private.stack(), 0x1234);
        assert_eq!(
            u64::from_ne_bytes(private.buffer.0[48..56].try_into().unwrap()),
            0x2000
        );

        // The injection path rereads the same image after Tool handling, so a
        // Tool rewrite cannot leave cached boundary or trampoline decisions.
        actual.buffer.0[0..8].copy_from_slice(&0u64.to_ne_bytes());
        actual.buffer.0[40..48].copy_from_slice(&0x5678u64.to_ne_bytes());
        assert!(!actual.is_vfork());
        assert_eq!(actual.stack(), 0x5678);
    }

    #[test]
    fn private_vfork_flags_reject_incompatible_sharing() {
        let required = (libc::CLONE_VM | libc::CLONE_VFORK) as u64;
        assert_eq!(
            private_vfork_flags(required | libc::SIGCHLD as u64),
            Ok(libc::SIGCHLD as u64)
        );
        for incompatible in [libc::CLONE_FILES, libc::CLONE_SIGHAND, libc::CLONE_THREAD] {
            assert_eq!(
                private_vfork_flags(required | incompatible as u64),
                Err(Errno::EINVAL)
            );
        }
    }

    #[test]
    fn vfork_child_gate_distinguishes_parent_and_child_processes() {
        assert!(super::current_pid_namespace().is_some());
        // Linux's configured PID maximum is far below i32::MAX, so a real
        // fork below cannot accidentally reuse this synthetic vfork PID.
        let child_pid = i32::MAX as u32;
        let child_pid_namespace = 0x1234;
        let boundary = super::VforkBoundaryGuard::enter().unwrap();

        assert!(!is_vfork_child_process());
        assert!(activate_vfork_child(
            boundary.slot(),
            child_pid,
            child_pid_namespace,
            (libc::CLONE_VM | libc::CLONE_VFORK | libc::CLONE_SIGHAND) as usize,
        ));

        assert!(!is_vfork_child_process());
        assert_eq!(
            vfork_child_flags_for(child_pid, child_pid_namespace),
            Some(libc::CLONE_SIGHAND as usize)
        );
        assert_eq!(vfork_child_flags_for(child_pid, 0x5678), None);

        // An ordinary fork inherits the registry snapshot, but its exact PID
        // differs from the active vfork child and therefore must not enter the
        // native gate.
        let ordinary_fork_pid = unsafe { libc::fork() };
        assert!(ordinary_fork_pid >= 0);
        if ordinary_fork_pid == 0 {
            let entered_gate = is_vfork_child_process();
            reverie_sabre_after_clone_child(libc::SIGCHLD as usize, NO_VFORK_SLOT);
            let stale_entry = vfork_child_flags_for(child_pid, child_pid_namespace).is_some();
            unsafe { libc::_exit(i32::from(entered_gate || stale_entry)) };
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(ordinary_fork_pid, &mut status, 0) },
            ordinary_fork_pid
        );
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        drop(boundary);
        assert!(vfork_child_flags_for(child_pid, child_pid_namespace).is_none());

        let boundaries: Vec<_> = (0..super::VFORK_CHILD_SLOT_COUNT)
            .map(|_| super::VforkBoundaryGuard::enter().unwrap())
            .collect();
        assert!(super::VforkBoundaryGuard::enter().is_none());
        drop(boundaries);
        assert!(super::VforkBoundaryGuard::enter().is_some());
    }

    #[test]
    fn private_vfork_pipe_releases_parent_after_child_handoff() {
        let boundary = super::VforkBoundaryGuard::enter().unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let prepared = super::prepare_private_vfork_child(boundary.slot());
            if prepared {
                super::close_slot_fd(&super::VFORK_CHILDREN[boundary.slot()].sync_write);
            }
            unsafe { libc::_exit(i32::from(!prepared)) };
        }

        assert_eq!(boundary.wait_for_child_exec(child as usize), child as usize);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn vfork_child_native_gate_is_fail_closed() {
        assert!(is_vfork_native_syscall_allowed(Sysno::rt_sigaction));
        assert!(is_vfork_native_syscall_allowed(Sysno::getuid));
        assert!(is_vfork_native_syscall_allowed(Sysno::execve));
        assert!(is_vfork_native_syscall_allowed(Sysno::exit_group));
        assert!(!is_vfork_native_syscall_allowed(Sysno::getpid));
        assert!(!is_vfork_native_syscall_allowed(Sysno::clock_gettime));
        assert!(!is_vfork_native_syscall_allowed(Sysno::openat));
    }

    #[test]
    fn exited_group_member_is_a_successful_teardown_target() {
        signal_controlled_exit(PidTid {
            pid: std::process::id(),
            // Linux's configured PID maximum is far below i32::MAX.
            tid: i32::MAX as u32,
        });
    }

    #[test]
    fn final_exit_group_terminates_untracked_threads() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let _untracked = std::thread::spawn(|| {
                loop {
                    core::hint::spin_loop();
                }
            });
            terminate_group(23);
        }

        let mut status = 0;
        assert_eq!(child, unsafe { libc::waitpid(child, &mut status, 0) });
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 23);
    }
}
