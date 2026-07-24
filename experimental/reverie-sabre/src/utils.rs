/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::CStr;
use std::mem::MaybeUninit;

use syscalls::Errno;
use syscalls::Sysno;
use syscalls::syscall;
use syscalls::syscall3;

use super::paths;
use super::signal;
use crate::callbacks::CONTROLLED_EXIT_SIGNAL;

/// `readlink` needs to be handled in a special way. If we're trying to read
/// `/proc/self/exe`, then we can't return the path to the sabre executable. We
/// need to replace it with the path to the real binary.
///
/// NOTE: This doesn't handle numerous other cases such as:
///  1. Using `readlinkat(-100, "/proc/self/exe", ...)`
///  2. Using `readlinkat(dir_fd, "exe", ...)`
///  3. Using `readlink("/proc/{pid}/exe", ...)`
pub fn sys_readlink(
    path: *const libc::c_char,
    buf: *mut libc::c_char,
    bufsize: usize,
) -> Result<usize, Errno> {
    if unsafe { CStr::from_ptr(path) }.to_bytes() == b"/proc/self/exe" {
        if buf.is_null() {
            return Err(Errno::EFAULT);
        }

        let client_path = paths::client_path();
        let len = client_path.to_bytes().len().min(bufsize);

        unsafe { core::ptr::copy_nonoverlapping(client_path.as_ptr(), buf, len) };

        Ok(len)
    } else {
        unsafe { syscall3(Sysno::readlink, path as usize, buf as usize, bufsize) }
    }
}

const MAX_EXEC_ARG_POINTERS: usize = 1 << 18;

/// Read one pointer from guest memory without risking a process-local fault.
fn read_guest_pointer(address: usize) -> Result<*const libc::c_char, Errno> {
    let mut pointer = MaybeUninit::<*const libc::c_char>::uninit();
    let local = libc::iovec {
        iov_base: pointer.as_mut_ptr().cast(),
        iov_len: std::mem::size_of::<*const libc::c_char>(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: std::mem::size_of::<*const libc::c_char>(),
    };
    let copied = unsafe {
        syscall!(
            Sysno::process_vm_readv,
            std::process::id() as usize,
            &local as *const libc::iovec as usize,
            1,
            &remote as *const libc::iovec as usize,
            1,
            0
        )?
    };
    if copied != std::mem::size_of::<*const libc::c_char>() {
        return Err(Errno::EFAULT);
    }
    Ok(unsafe { pointer.assume_init() })
}

/// Copy the argv pointer list while leaving each argument string in guest memory.
fn collect_exec_arguments(
    argv: *const *const libc::c_char,
) -> Result<Vec<*const libc::c_char>, Errno> {
    if argv.is_null() {
        return Ok(Vec::new());
    }

    let mut arguments = Vec::new();
    for index in 0..MAX_EXEC_ARG_POINTERS {
        let offset = index
            .checked_mul(std::mem::size_of::<*const libc::c_char>())
            .ok_or(Errno::EFAULT)?;
        let address = (argv as usize).checked_add(offset).ok_or(Errno::EFAULT)?;
        let argument = read_guest_pointer(address)?;
        if argument.is_null() {
            return Ok(arguments);
        }
        arguments.push(argument);
    }
    Err(Errno::E2BIG)
}

/// Re-enter SaBRe around a new guest image so the plugin remains active.
///
/// SaBRe expects `sabre plugin.so -- program args...`. The kernel still reads
/// the guest's strings and environment directly, while `process_vm_readv`
/// safely copies only the argv pointer list needed to prepend the loader.
pub fn sys_execve(
    filename: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> Result<usize, Errno> {
    // Ask the kernel to validate the pathname before constructing SaBRe's
    // argv. This also prevents a null filename from truncating the new list.
    unsafe { syscall!(Sysno::access, filename as usize, libc::F_OK as usize)? };

    let arguments = collect_exec_arguments(argv)?;
    let environment = collect_exec_arguments(envp)?;
    let sabre = paths::sabre_path().as_ptr();
    let mut new_argv = Vec::with_capacity(arguments.len() + 5);
    new_argv.push(sabre);
    new_argv.push(paths::plugin_path().as_ptr());
    new_argv.push(c"--".as_ptr());
    new_argv.push(filename);
    new_argv.extend(arguments.into_iter().skip(1));
    new_argv.push(core::ptr::null());

    // Preserve reserved tool settings even when the guest deliberately
    // supplies an empty environment. Individual tools consume their own
    // settings before the replacement guest observes them.
    let tool_environment = paths::tool_env();
    let mut new_env = Vec::with_capacity(environment.len() + tool_environment.len() + 1);
    new_env.extend(tool_environment.iter().map(|entry| entry.as_ptr()));
    new_env.extend(environment);
    new_env.push(core::ptr::null());

    unsafe {
        syscall3(
            Sysno::execve,
            sabre as usize,
            new_argv.as_ptr() as usize,
            new_env.as_ptr() as usize,
        )
    }
}

pub fn sys_execveat() -> Result<usize, Errno> {
    Err(Errno::ENOSYS)
}

/// glibc defines this to be much larger than what the kernel accepts. Since we
/// have to make a direct syscall to `rt_sigaction`, we must use the same sigset
/// as the kernel does.
///
/// The kernel currently uses 64 bits for the sigset. See:
/// https://elixir.bootlin.com/linux/v5.17.5/source/arch/x86/include/uapi/asm/signal.h#L17
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct KernelSigset(u64);

impl KernelSigset {
    /// Check if the sigset contains a signal.
    #[allow(unused)]
    pub fn contains(&self, sig: libc::c_int) -> bool {
        let mask = sigmask(sig);
        (self.0 & mask) == mask
    }

    /// Removes the given signal from the sigset.
    pub fn remove(&mut self, sig: libc::c_int) {
        let mask = sigmask(sig);
        self.0 &= !mask
    }
}

/// The x86_64 kernel ABI representation of `struct sigaction`. libc's
/// representation embeds its much larger userspace `sigset_t`, so it cannot be
/// passed directly to the raw syscall.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KernelSigaction {
    handler: libc::sighandler_t,
    flags: libc::c_ulong,
    restorer: usize,
    mask: KernelSigset,
}

const _: () = assert!(core::mem::size_of::<KernelSigaction>() == 32);

impl KernelSigaction {
    fn from_libc(action: libc::sigaction) -> Self {
        let mask = unsafe { *(&action.sa_mask as *const libc::sigset_t as *const KernelSigset) };
        let restorer = action
            .sa_restorer
            .map(|function| function as usize)
            .unwrap_or(0);

        Self {
            handler: action.sa_sigaction,
            flags: action.sa_flags as libc::c_ulong,
            restorer,
            mask,
        }
    }

    fn into_libc(self) -> libc::sigaction {
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = self.handler;
        action.sa_flags = self.flags as libc::c_int;
        action.sa_restorer = if self.restorer == 0 {
            None
        } else {
            Some(unsafe { core::mem::transmute::<usize, extern "C" fn()>(self.restorer) })
        };
        unsafe {
            *(&mut action.sa_mask as *mut libc::sigset_t as *mut KernelSigset) = self.mask;
        }
        action
    }
}

#[inline]
fn sigmask(sig: libc::c_int) -> u64 {
    // wrapping_sub is safe because signal numbers start at 1.
    1 << (sig as u64).wrapping_sub(1)
}

/// Preserve Reverie's central handler while exposing the guest-facing action
/// through the normal `rt_sigaction` ABI. Signals not mediated by Reverie are
/// passed directly to the kernel.
pub fn sys_rt_sigaction(
    signal_value: libc::c_int,
    new_action_ptr: *const KernelSigaction,
    old_action_ptr: *mut KernelSigaction,
    sigset_size: usize,
) -> Result<usize, Errno> {
    if sigset_size != core::mem::size_of::<KernelSigset>() {
        return Err(Errno::EINVAL);
    }

    if !signal::handles_signal(signal_value) {
        return unsafe {
            syscalls::syscall4(
                Sysno::rt_sigaction,
                signal_value as usize,
                new_action_ptr as usize,
                old_action_ptr as usize,
                sigset_size,
            )
        };
    }

    // Read the new action first because Linux permits the old and new pointers
    // to alias.
    let new_action = if new_action_ptr.is_null() {
        None
    } else {
        Some(unsafe { *new_action_ptr })
    };

    let old_action = match new_action {
        Some(action) => signal::register_guest_handler(signal_value, action.into_libc())?,
        None => signal::registered_guest_handler(signal_value)?,
    };

    if !old_action_ptr.is_null() {
        unsafe {
            *old_action_ptr = KernelSigaction::from_libc(old_action);
        }
    }

    Ok(0)
}

/// rt_sigprocmask needs special handling because if the guest tries to set a
/// signal mask that prevents our control signal from being received by a
/// thread, we are going to create and pass our own sigset that only differs
/// from the client's in that it does not suppress our control signal
pub fn sys_rt_sigprocmask(
    operation: libc::c_int,
    sigset_ptr: *const KernelSigset,
    prev_sigset_ptr: *mut KernelSigset,
    // Should always 8 for x86_64
    sigset_size: usize,
) -> Result<usize, Errno> {
    if sigset_ptr.is_null() {
        return unsafe {
            syscalls::syscall4(
                Sysno::rt_sigprocmask,
                operation as usize,
                sigset_ptr as usize,
                prev_sigset_ptr as usize,
                sigset_size,
            )
        };
    }

    let mut new_sigset = unsafe { *sigset_ptr };

    if matches!(operation, libc::SIG_SETMASK | libc::SIG_BLOCK) {
        new_sigset.remove(CONTROLLED_EXIT_SIGNAL);
    }

    unsafe {
        syscalls::syscall4(
            Sysno::rt_sigprocmask,
            operation as usize,
            &new_sigset as *const _ as usize,
            prev_sigset_ptr as usize,
            sigset_size,
        )
    }
}

#[inline]
pub fn is_vfork(sys_no: Sysno, arg1: usize) -> bool {
    const VFORK_FLAGS: usize = (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as usize;
    sys_no == Sysno::vfork || (sys_no == Sysno::clone && (arg1 & VFORK_FLAGS == VFORK_FLAGS))
}

#[cfg(test)]
mod exec_tests {
    use super::*;

    #[test]
    fn execve_rejects_invalid_filename_without_replacing_the_process() {
        assert_eq!(
            sys_execve(core::ptr::null(), core::ptr::null(), core::ptr::null()),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            sys_execve(
                usize::MAX as *const libc::c_char,
                usize::MAX as *const *const libc::c_char,
                usize::MAX as *const *const libc::c_char,
            ),
            Err(Errno::EFAULT)
        );
        let missing = c"/definitely/missing/reverie-sabre-exec-test";
        assert_eq!(
            sys_execve(missing.as_ptr(), core::ptr::null(), core::ptr::null()),
            Err(Errno::ENOENT)
        );
    }

    #[test]
    fn execve_reads_argv_pointers_without_dereferencing_strings() {
        let custom_arg0 = b"custom-argv-zero\0";
        let argument = usize::MAX as *const libc::c_char;
        let argv = [
            custom_arg0.as_ptr() as *const libc::c_char,
            argument,
            core::ptr::null(),
        ];
        assert_eq!(
            collect_exec_arguments(argv.as_ptr()),
            Ok(argv[..2].to_vec())
        );
        assert_eq!(collect_exec_arguments(core::ptr::null()), Ok(Vec::new()));
        assert_eq!(
            collect_exec_arguments(usize::MAX as *const *const libc::c_char),
            Err(Errno::EFAULT)
        );
    }

    #[test]
    fn execveat_remains_explicitly_unsupported() {
        assert_eq!(sys_execveat(), Err(Errno::ENOSYS));
    }
}
