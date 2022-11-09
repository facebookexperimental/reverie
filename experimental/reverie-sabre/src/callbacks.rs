/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie_syscalls::LocalMemory;
use reverie_syscalls::Syscall;
use syscalls::syscall;
use syscalls::SyscallArgs;
use syscalls::Sysno;

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
#[allow(clippy::if_same_then_else)]
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

    let sys_no = Sysno::from(syscall as i32);

    let result = if sys_no == Sysno::clone && arg2 != 0 {
        thread.maybe_fork_as_guest(|| unsafe {
            ffi::clone_syscall(
                arg1,
                arg2 as *mut libc::c_void,
                arg3 as *mut i32,
                arg4 as *mut i32,
                arg5,
                (*wrapper_sp).ret,
            )
        })?
    } else if sys_no == Sysno::clone {
        thread.maybe_fork_as_guest(|| {
            let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);
            let syscall = Syscall::from_raw(sys_no, args);

            T::global()
                .syscall(syscall, &LocalMemory::new())
                .map_or_else(|e| -e.into_raw() as usize, |x| x as usize)
        })?
    } else if utils::is_vfork(sys_no, arg1) {
        thread.maybe_fork_as_guest(|| unsafe {
            let pid = ffi::vfork_syscall();
            if pid == 0 {
                // Child

                // Even though this function doesn't return, this is
                // safe because the thread is in `Guest` and that state
                // will be correct in the child application when the
                // jmp takes it there
                ffi::vfork_return_from_child(wrapper_sp)
            } else {
                // parent
                pid
            }
        })?
    } else if sys_no == Sysno::clone3 {
        let cl_args = unsafe { &*(arg1 as *const ffi::clone_args) };
        if cl_args.stack == 0 {
            thread.maybe_fork_as_guest(|| unsafe {
                syscall!(sys_no, arg1, arg2, arg3, arg4, arg5, arg6)
                    .map_or_else(|e| -e.into_raw() as usize, |x| x as usize)
            })?
        } else {
            thread.maybe_fork_as_guest(|| unsafe {
                ffi::clone3_syscall(arg1, arg2, arg3, 0, arg5, (*wrapper_sp).ret)
            })?
        }
    } else if sys_no == Sysno::exit {
        // intercept the exit_group syscall and signal all the threads to exit
        // in a predictable and trackable way
        if thread.try_exit() {
            terminate(arg1);
        }
        0
    } else if sys_no == Sysno::exit_group {
        // intercept the exit_group syscall and signal all the threads to exit
        // in a predictable and trackable way
        exit_group_with_thread(thread, arg1)
    } else {
        let args = SyscallArgs::new(arg1, arg2, arg3, arg4, arg5, arg6);
        let syscall = Syscall::from_raw(sys_no, args);

        thread.execute_as_guest(|| {
            T::global()
                .syscall(syscall, &LocalMemory::new())
                .map_or_else(|e| -e.into_raw() as usize, |x| x as usize)
        })?
    };

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
            T::global().on_exit_timeout()
        } else {
            terminate(exit_code)
        }
    } else {
        0
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
                vdso::clock_gettime = transmute(actual_fn as *const ());
                transmute(handle_vdso_clock_gettime::<T> as *const ())
            }
            Sysno::getcpu => {
                vdso::getcpu = transmute(actual_fn as *const ());
                transmute(handle_vdso_getcpu::<T> as *const ())
            }
            Sysno::gettimeofday => {
                vdso::gettimeofday = transmute(actual_fn as *const ());
                transmute(handle_vdso_gettimeofday::<T> as *const ())
            }
            Sysno::time => {
                vdso::time = transmute(actual_fn as *const ());
                transmute(handle_vdso_time::<T> as *const ())
            }
            _ => None,
        }
    }
}

pub extern "C" fn handle_rdtsc<T: ToolGlobal>() -> u64 {
    T::global().rdtsc()
}
