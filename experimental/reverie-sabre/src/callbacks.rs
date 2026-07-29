/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicBool;
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
use crate::signal::guard;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-140): Review the loader-owned syscall-frame lifetime boundary.
thread_local! {
    static CURRENT_SYSCALL_FRAME: std::cell::Cell<*mut ffi::syscall_stackframe> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
    static TAIL_INJECTED_EXIT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

// Pack the owning process ID into the high half and the number of concurrent
// vfork callers into the low half. This process-global state remains visible
// when clone(2)/clone3(2) installs new child TLS with CLONE_SETTLS.
static VFORK_BOUNDARY_STATE: AtomicU64 = AtomicU64::new(0);
const VFORK_COUNT_MASK: u64 = u32::MAX as u64;

/// Keeps a vfork child on a native pre-exec gate while its parent is blocked
/// inside the kernel and owns an in-flight tool/RPC request.
struct VforkBoundaryGuard {
    parent_pid: u32,
    _signal_restore: guard::VforkSignalGuardRestore,
}

impl VforkBoundaryGuard {
    fn enter() -> Self {
        let parent_pid = current_process_id();
        let mut state = VFORK_BOUNDARY_STATE.load(Ordering::Acquire);
        loop {
            let owner = (state >> 32) as u32;
            let count = state & VFORK_COUNT_MASK;
            assert!(count < VFORK_COUNT_MASK, "too many concurrent vforks");
            assert!(
                owner == 0 || owner == parent_pid,
                "cross-process vfork boundary"
            );
            let next = (u64::from(parent_pid) << 32) | (count + 1);
            match VFORK_BOUNDARY_STATE.compare_exchange_weak(
                state,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
        Self {
            parent_pid,
            _signal_restore: guard::preserve_signal_guard_count_across_vfork(),
        }
    }
}

impl Drop for VforkBoundaryGuard {
    fn drop(&mut self) {
        let mut state = VFORK_BOUNDARY_STATE.load(Ordering::Acquire);
        loop {
            let owner = (state >> 32) as u32;
            let count = state & VFORK_COUNT_MASK;
            assert_eq!(owner, self.parent_pid, "vfork owner changed");
            assert!(count > 0, "vfork count went negative");
            let next = if count == 1 { 0 } else { state - 1 };
            match VFORK_BOUNDARY_STATE.compare_exchange_weak(
                state,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => state = observed,
            }
        }
    }
}

fn is_vfork_child_process() -> bool {
    is_vfork_child_pid(current_process_id())
}

fn is_vfork_child_pid(current_pid: u32) -> bool {
    let state = VFORK_BOUNDARY_STATE.load(Ordering::Acquire);
    let parent_pid = (state >> 32) as u32;
    state & VFORK_COUNT_MASK != 0 && parent_pid != current_pid
}

fn current_process_id() -> u32 {
    unsafe { syscalls::syscall0(Sysno::getpid) }.expect("getpid should succeed") as u32
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Clone3Fields {
    flags: u64,
    stack: u64,
}

impl Clone3Fields {
    fn is_vfork(self) -> bool {
        let required = (libc::CLONE_VM | libc::CLONE_VFORK) as u64;
        self.flags & required == required
    }
}

/// Read clone3's flags and stack pointer without directly dereferencing guest memory.
///
/// `process_vm_readv` asks the kernel to validate the address, preserving the
/// syscall's `EFAULT` behavior when the guest supplies an invalid pointer.
fn read_clone3_fields(pid: u32, args: usize, size: usize) -> Result<Clone3Fields, Errno> {
    const CLONE_ARGS_MIN_SIZE: usize = 64;

    // Let clone3 itself report EINVAL for undersized argument structures.
    if size < CLONE_ARGS_MIN_SIZE {
        return Ok(Clone3Fields { flags: 0, stack: 0 });
    }

    let mut fields = [0u64; 6];
    let local = libc::iovec {
        iov_base: fields.as_mut_ptr().cast(),
        iov_len: std::mem::size_of_val(&fields),
    };
    let remote = libc::iovec {
        iov_base: args as *mut libc::c_void,
        iov_len: std::mem::size_of_val(&fields),
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

    (copied == std::mem::size_of_val(&fields))
        .then_some(Clone3Fields {
            flags: fields[0],
            stack: fields[5],
        })
        .ok_or(Errno::EFAULT)
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
pub extern "C" fn handle_post_load(_is_static: bool) {
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
    if is_vfork_child_process() {
        let sys_no = Sysno::from(syscall as i32);
        if !is_vfork_native_syscall_allowed(sys_no) {
            return -Errno::ENOSYS.into_raw() as usize;
        }
        let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);
        let intercepted = Syscall::from_raw(sys_no, args);
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
    let result = if sys_no == Sysno::clone && arg2 != 0 {
        let _vfork_boundary = utils::is_vfork(sys_no, arg1).then(VforkBoundaryGuard::enter);
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
                    )
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if sys_no == Sysno::clone {
        let _vfork_boundary = utils::is_vfork(sys_no, arg1).then(VforkBoundaryGuard::enter);
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
                    )
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if utils::is_vfork(sys_no, arg1) {
        let _vfork_boundary = VforkBoundaryGuard::enter();
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                    let pid = ffi::vfork_syscall();
                    if pid == 0 {
                        // The child is already in Guest state and jumps back to
                        // SaBRe's trampoline instead of returning through Rust.
                        ffi::vfork_return_from_child(
                            wrapper_address as *const ffi::syscall_stackframe,
                        )
                    } else {
                        pid
                    }
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if sys_no == Sysno::clone3 {
        let fields = read_clone3_fields(thread.get_process_and_thread_ids().pid, arg1, arg2);
        let is_vfork = fields.as_ref().is_ok_and(|fields| fields.is_vfork());
        let _vfork_boundary = is_vfork.then(VforkBoundaryGuard::enter);
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || match fields {
                    Err(errno) => -errno.into_raw() as usize,
                    Ok(Clone3Fields { stack: 0, .. }) => unsafe {
                        syscall!(sys_no, arg1, arg2, arg3, arg4, arg5, arg6)
                            .unwrap_or_else(|e| -e.into_raw() as usize)
                    },
                    Ok(_) => unsafe {
                        ffi::clone3_syscall(
                            arg1,
                            arg2,
                            arg3,
                            0,
                            arg5,
                            return_address as *mut libc::c_void,
                        )
                    },
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
    use std::sync::atomic::Ordering;

    use syscalls::Errno;
    use syscalls::Sysno;

    use super::VFORK_BOUNDARY_STATE;
    use super::is_vfork_child_pid;
    use super::is_vfork_child_process;
    use super::is_vfork_native_syscall_allowed;
    use super::read_clone3_fields;
    use super::signal_controlled_exit;
    use super::terminate_group;
    use crate::thread::PidTid;

    #[test]
    fn clone3_stack_read_rejects_invalid_guest_pointer() {
        assert_eq!(
            read_clone3_fields(std::process::id(), 1, 88),
            Err(Errno::EFAULT)
        );
    }

    #[test]
    fn clone3_fields_identify_vfork_and_stack() {
        let fields = [
            (libc::CLONE_VM | libc::CLONE_VFORK) as u64,
            0,
            0,
            0,
            libc::SIGCHLD as u64,
            0x1234,
            0x2000,
            0,
        ];

        let actual = read_clone3_fields(
            std::process::id(),
            fields.as_ptr() as usize,
            std::mem::size_of_val(&fields),
        )
        .unwrap();

        assert!(actual.is_vfork());
        assert_eq!(actual.stack, 0x1234);
    }

    #[test]
    fn vfork_child_gate_distinguishes_parent_and_child_processes() {
        let current_pid = super::current_process_id();
        assert_eq!(VFORK_BOUNDARY_STATE.load(Ordering::Acquire), 0);
        let boundary = super::VforkBoundaryGuard::enter();
        assert!(!is_vfork_child_process());
        assert!(is_vfork_child_pid(current_pid + 1));
        drop(boundary);
        assert_eq!(VFORK_BOUNDARY_STATE.load(Ordering::Acquire), 0);
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
