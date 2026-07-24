/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

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
use super::tool::Tool;
use super::tool::ToolGlobal;
use super::utils;
use super::vdso;
use crate::signal::guard;

pub const CONTROLLED_EXIT_SIGNAL: libc::c_int = libc::SIGSTKFLT;

/// Read clone3's stack pointer without directly dereferencing guest memory.
///
/// `process_vm_readv` asks the kernel to validate the address, preserving the
/// syscall's `EFAULT` behavior when the guest supplies an invalid pointer.
fn read_clone3_stack(pid: u32, args: usize, size: usize) -> Result<u64, Errno> {
    const CLONE_ARGS_MIN_SIZE: usize = 64;
    const STACK_OFFSET: usize = 5 * std::mem::size_of::<u64>();

    // Let clone3 itself report EINVAL for undersized argument structures.
    if size < CLONE_ARGS_MIN_SIZE {
        return Ok(0);
    }

    let stack_address = args.checked_add(STACK_OFFSET).ok_or(Errno::EFAULT)?;
    let mut stack = 0u64;
    let local = libc::iovec {
        iov_base: (&mut stack as *mut u64).cast(),
        iov_len: std::mem::size_of_val(&stack),
    };
    let remote = libc::iovec {
        iov_base: stack_address as *mut libc::c_void,
        iov_len: std::mem::size_of_val(&stack),
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

    (copied == std::mem::size_of_val(&stack))
        .then_some(stack)
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
    let mut thread = if let Some(thread) = Thread::<T>::current() {
        thread
    } else {
        terminate(1);
    };

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

    let result = if sys_no == Sysno::clone && arg2 != 0 {
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
    } else if sys_no == Sysno::clone || sys_no == Sysno::fork {
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || unsafe {
                    syscall!(sys_no, arg1, arg2, arg3, arg4, arg5, arg6)
                        .unwrap_or_else(|e| -e.into_raw() as usize)
                })
                .unwrap_or_else(|e| -e.into_raw() as usize)
        })?
    } else if utils::is_vfork(sys_no, arg1) {
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
        let stack = read_clone3_stack(thread.get_process_and_thread_ids().pid, arg1, arg2);
        thread.maybe_fork_as_guest(|| {
            T::global()
                .syscall_with_inject(intercepted, &LocalMemory::new(), || match stack {
                    Err(errno) => -errno.into_raw() as usize,
                    Ok(0) => unsafe {
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
    thread.try_exit();
    if let Some(exiting_pid) = thread::exit_all(|_, process_and_thread_id| unsafe {
        syscalls::syscall3(
            Sysno::tgkill,
            process_and_thread_id.pid as usize,
            process_and_thread_id.tid as usize,
            CONTROLLED_EXIT_SIGNAL as usize,
        )
        .expect("Signaling thread failed");
    }) {
        if !thread::wait_for_all_to_exit(exiting_pid, T::global().get_exit_timeout()) {
            let _ = T::global().on_exit_timeout();
        }
    }
    terminate_group(exit_code)
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
    T::global().vdso_clock_gettime(clockid, tp)
}

extern "C" fn handle_vdso_getcpu<T: ToolGlobal>(
    cpu: *mut u32,
    node: *mut u32,
    _unused: usize,
) -> i32 {
    T::global().vdso_getcpu(cpu, node, _unused)
}

extern "C" fn handle_vdso_gettimeofday<T: ToolGlobal>(
    tv: *mut libc::timeval,
    tz: *mut libc::timezone,
) -> i32 {
    T::global().vdso_gettimeofday(tv, tz)
}

extern "C" fn handle_vdso_time<T: ToolGlobal>(tloc: *mut libc::time_t) -> i32 {
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

    use super::read_clone3_stack;
    use super::terminate_group;

    #[test]
    fn clone3_stack_read_rejects_invalid_guest_pointer() {
        assert_eq!(
            read_clone3_stack(std::process::id(), 1, 88),
            Err(Errno::EFAULT)
        );
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
