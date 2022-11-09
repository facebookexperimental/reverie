/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::time::Duration;

use reverie_rpc::MakeClient;
use reverie_syscalls::LocalMemory;
use reverie_syscalls::Syscall;
use syscalls::syscall;
use syscalls::Errno;
use syscalls::Sysno;

use super::protected_files::uses_protected_fd;
use super::utils;
use super::vdso;
use crate::ffi::fn_icept;

/// A trait that every Reverie *tool* must implement. The primary function of the
/// tool specifies how syscalls and signals are handled.
///
/// The type that a `Tool` is implemented for represents the process-level state.
/// That is, one runtime instance of this type will be created for each guest
/// process. This type is in turn a factory for *thread level states*, which are
/// allocated dynamically upon guest thread creation. Instances of the thread
/// state are also managed by Reverie.
pub trait Tool {
    /// The client used to make global state RPC calls.
    ///
    /// This can be set to the unit type `()` if the tool does not require
    /// global state.
    type Client: MakeClient;

    /// Called when the process first starts. The global state RPC client is
    /// passed in and may be used to send/recv messages to/from the global
    /// state.
    ///
    /// The point at which this is called in the lifetime of the process is
    /// undefined. It may not be called until *after* libc is loaded.
    fn new(client: Self::Client) -> Self;

    /// This is called in place of a system call. For example, if the program
    /// called the `open` syscall, this callback would be called instead. By
    /// default, the real syscall is simply called.
    #[inline]
    fn syscall(&self, syscall: Syscall, _memory: &LocalMemory) -> Result<usize, Errno> {
        unsafe { syscall.call() }
    }

    /// Called when a thread first starts.
    #[inline]
    fn on_thread_start(&self, _thread_id: u32) {}

    /// Called just before the thread exits. A thread may exit due a variety of
    /// reasons:
    ///  - The thread called `exit(2)`.
    ///  - This, or another, thread called `exit_group(2)`.
    ///  - This thread was killed by a signal.
    ///
    /// NOTE: From the tool's persective, it is possible for this api method to
    /// be called without the accompanying call to `on_thread_start` for the
    /// same thread id. This is very unlikely, but can happen if a thread is
    /// signaled to exit before `on_thread_start` is called.
    #[inline]
    fn on_thread_exit(&self, _thread_id: u32) {}

    /// Called whenever the `rdtsc` instruction was executed. This should return
    /// the RDTSC timestamp counter.
    ///
    /// By default, this returns the result of the `rdtsc` instruction.
    #[inline]
    fn rdtsc(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    /// Called whenever the VDSO function `clock_gettime` was called. By
    /// default, the original `clock_gettime` VDSO function is called.
    #[inline]
    fn vdso_clock_gettime(&self, clockid: libc::clockid_t, tp: *mut libc::timespec) -> i32 {
        unsafe { vdso::clock_gettime(clockid, tp) }
    }

    /// Called whenever the VDSO function `getcpu` was called. By default, the
    /// original `getcpu` VDSO function is called.
    #[inline]
    fn vdso_getcpu(&self, cpu: *mut u32, node: *mut u32, _unused: usize) -> i32 {
        unsafe { vdso::getcpu(cpu, node, _unused) }
    }

    /// Called whenever the VDSO function `gettimeofday` was called. By default,
    /// the original `gettimeofday` VDSO function is called.
    #[inline]
    fn vdso_gettimeofday(&self, tv: *mut libc::timeval, tz: *mut libc::timezone) -> i32 {
        unsafe { vdso::gettimeofday(tv, tz) }
    }

    /// Called whenever the VDSO function `time` was called. By default, the
    /// original `time` VDSO function is called.
    #[inline]
    fn vdso_time(&self, tloc: *mut libc::time_t) -> i32 {
        unsafe { vdso::time(tloc) }
    }

    /// Returns the time limit for waiting for all threads to exit when an
    /// `exit_group` syscall is observed. By default, `None` is returned, which
    /// indicates no timeout. That is, the default behavior is to wait
    /// indefinitely for all threads to exit.
    fn get_exit_timeout(&self) -> Option<Duration> {
        None
    }

    /// Called when the timeout duration provided by `get_exit_timeout` elapses
    /// before all threads in the guest application exit. The default behavior
    /// in this case is to issue an un-intercepted `exit_group(1)` syscall.
    fn on_exit_timeout(&self) -> usize {
        let _ = unsafe { syscalls::syscall1(Sysno::exit_group, 1) };
        unreachable!("All threads will exit before this is called")
    }

    /// Called when a signal of the given value is received before any handlers
    /// for that signal are evaluated
    fn handle_signal_event(&self, _signal: i32) {}
    /// This is called early on from sbr_init to get a list of functions we want
    /// to be detoured. Because this is called very early on, this function
    /// should not be doing *any* allocations or library calls.
    fn detours() -> &'static [fn_icept] {
        &[]
    }
}

pub trait ToolGlobal {
    type Target: Tool + 'static;

    /// Returns a reference to the global (process-level) instance of this tool.
    fn global() -> &'static Self::Target;
}

/// Helper methods for syscalls.
pub trait SyscallExt {
    /// Executes the syscall, returning the result.
    unsafe fn call(self) -> Result<usize, Errno>;
}

impl SyscallExt for Syscall {
    unsafe fn call(self) -> Result<usize, Errno> {
        use reverie_syscalls::SyscallInfo;

        let (sysno, args) = self.into_parts();

        // Some syscalls need to be handled in a special way.
        if sysno == Sysno::readlink {
            utils::sys_readlink(
                args.arg0 as *const libc::c_char,
                args.arg1 as *mut libc::c_char,
                args.arg2 as usize,
            )
        } else if sysno == Sysno::execve {
            utils::sys_execve(
                args.arg0 as *const libc::c_char,
                args.arg1 as *const *const libc::c_char,
                args.arg2 as *const *const libc::c_char,
            )
        } else if sysno == Sysno::rt_sigprocmask {
            utils::sys_rt_sigprocmask(
                args.arg0 as libc::c_int,
                args.arg1 as *const _,
                args.arg2 as *mut _,
                args.arg3 as usize,
            )
        } else if sysno == Sysno::close && args.arg0 == libc::STDERR_FILENO as usize {
            // Prevent stderr from getting closed. We need this for logging
            // purposes.
            // FIXME: All logging should go through the global state instead.
            Ok(0)
        } else if uses_protected_fd(sysno, args.arg0, args.arg1) {
            // If this syscall operates on a protected file descriptor, we
            // should return EBADF to indicate that the file descriptor isn't
            // opened (even if it really is).
            Err(Errno::EBADF)
        } else {
            syscall!(
                sysno, args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5
            )
        }
    }
}
