/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use syscalls::Errno;

use super::Pid;

/// Usable bytes in a cloned child's stack, excluding the guard pages.
///
/// A command's child runs on this stack only until it execs; exec replaces
/// its address space, so the program never runs on it. A container's child
/// does not exec: the in-container tracer's main thread runs on this stack
/// for the whole run, including the tokio `block_on` frames and everything
/// the tool does underneath them. That can be a whole guest process: the KVM
/// backend runs a run's first process on the thread that polls the run,
/// where a debug build of a large Tool used 2,412 KiB. So the child gets 16
/// MiB, twice the 8 MiB default `RLIMIT_STACK` of a main thread, and the KVM
/// backend gives each of its own host threads the same: reverie-kvm-core
/// defines `KVM_SUPERVISOR_THREAD_STACK_BYTES` as this constant, and keeps
/// the measurements behind it. `RUST_MIN_STACK` does not change this stack:
/// that variable sizes the threads the standard library spawns without an
/// explicit size, and a cloned child is not one of them. 2 MiB was measured
/// to be too small for a debug build of an embedder's LiteInst statistics
/// path: with the guard pages below, it faulted in them, and a core taken
/// before they existed showed all 0x200000 bytes in use, about 1.1 MB of it
/// in the embedder's own async frames. Only the pages the child actually
/// touches get physical memory, though strict overcommit charges the whole
/// mapping.
pub const CHILD_STACK_SIZE: usize = 16 * 1024 * 1024;

// Supported Linux clone ABIs grow the stack down. Keep several inaccessible
// pages below the usable stack; they are in addition to CHILD_STACK_SIZE.
const GUARD_PAGES: usize = 4;

pub(super) struct ChildStack {
    mapping: *mut libc::c_void,
    mapping_len: usize,
    guard_len: usize,
}

pub(super) fn child_stack() -> Result<ChildStack, Errno> {
    let page_size = Errno::result(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })? as usize;
    let guard_len = page_size * GUARD_PAGES;
    let mapping_len = guard_len + CHILD_STACK_SIZE;
    // Reserve the whole mapping inaccessible first: a failed mprotect must
    // never leave an unguarded stack available to a caller.
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mapping_len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(Errno::last());
    }
    let stack = ChildStack {
        mapping,
        mapping_len,
        guard_len,
    };
    // SAFETY: mmap returned an owned mapping; guard_len is page-aligned and
    // the writable range lies entirely inside it. Drop also covers failure.
    Errno::result(unsafe {
        libc::mprotect(
            stack.bottom().cast(),
            CHILD_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    })?;
    Ok(stack)
}

impl ChildStack {
    fn bottom(&self) -> *mut u8 {
        unsafe { self.mapping.cast::<u8>().add(self.guard_len) }
    }

    fn top(&mut self) -> *mut libc::c_void {
        // SAFETY: one past the writable region, rounded down for the clone ABI.
        let top = unsafe { self.bottom().add(CHILD_STACK_SIZE) };
        unsafe { top.sub(top as usize % 16) }.cast()
    }
}

impl Drop for ChildStack {
    fn drop(&mut self) {
        // Only the parent drops this owner. Without CLONE_VM its unmap cannot
        // affect the child's private mapping, which the kernel releases on
        // exec/exit. The child must never unmap the stack it is executing on.
        unsafe { libc::munmap(self.mapping, self.mapping_len) };
    }
}

/// `struct clone_args` through `set_tid_size`: `CLONE_ARGS_SIZE_VER1`, the
/// layout since Linux 5.5 (include/uapi/linux/sched.h).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
}

/// Linux's `CSIGNAL`: the exit-signal bits of `clone`'s flags. Spelled here
/// because the `libc` crate does not define it for Android.
const CSIGNAL: libc::c_int = 0xff;

/// Like [`clone`] without namespaces, but the child gets process ID `pid`
/// through `clone3`'s `set_tid`, in the PID namespace this process creates
/// its children in (normally its own). `flags` may hold only the child's exit
/// signal; any other flag is refused with `EINVAL` before the call (see
/// [`Command::pid`](crate::Command::pid)).
///
/// The kernel's errors stand: `EPERM` without `CAP_SYS_ADMIN` or
/// `CAP_CHECKPOINT_RESTORE` over that namespace, `EEXIST` when a task,
/// process group or session holds `pid`, `EINVAL` when `pid` is not in
/// `1..pid_max`, `E2BIG` on Linux 5.3 and 5.4 (`clone3` without `set_tid`),
/// and `ENOSYS` where `clone3` is unavailable: before Linux 5.3, or refused by
/// a seccomp filter.
///
/// The child runs on a copy of the calling thread's stack, as after `fork`:
/// a raw `clone3` cannot start a function on a new stack without an assembly
/// trampoline, and without `CLONE_VM` it needs none. `cb` runs behind an
/// `extern "C"` frame, as [`clone`]'s callback does, so a panic in it aborts
/// the child rather than unwinding into the frames it copied from its
/// parent. As after the raw `clone` of [`clone`], a C library that caches the
/// process ID (bionic does) still holds the parent's in the child, so `cb`
/// must not rely on `getpid()`.
pub(super) fn clone_with_pid<F>(cb: F, flags: libc::c_int, pid: Pid) -> Result<Pid, Errno>
where
    F: FnMut() -> i32,
{
    extern "C" fn run<G: FnMut() -> i32>(cb: &mut G) -> libc::c_int {
        // No pthread_atfork handler runs in this child.
        super::launch_window::reset_after_raw_clone();
        cb()
    }

    if flags & !CSIGNAL != 0 {
        return Err(Errno::EINVAL);
    }
    let set_tid: libc::pid_t = pid.as_raw();
    let args = CloneArgs {
        exit_signal: (flags & CSIGNAL) as u64,
        set_tid: std::ptr::from_ref(&set_tid) as u64,
        set_tid_size: 1,
        ..CloneArgs::default()
    };
    // The callback stays on this thread's stack: the child gets its own copy.
    let mut cb = cb;
    let res = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_ref(&args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if res == 0 {
        let code = run(&mut cb);
        unsafe { libc::_exit(code) }
    }
    Errno::result(res).map(|child| Pid::from_raw(child as libc::pid_t))
}

pub fn clone<F>(cb: F, flags: libc::c_int) -> Result<Pid, Errno>
where
    F: FnMut() -> i32,
{
    // The child runs container setup and libc's exec path on this stack. In an
    // optimized build, Mount::mount alone can reserve PATH_MAX bytes in its
    // frame, so one page cannot hold that call plus its callers. Match the
    // stack size Container::run provides for the same setup path, and allocate
    // it before clone so the child remains allocation-free before exec.
    let mut stack = child_stack()?;
    clone_with_stack(cb, flags, &mut stack)
}

pub(super) fn clone_with_stack<F>(
    cb: F,
    flags: libc::c_int,
    stack: &mut ChildStack,
) -> Result<Pid, Errno>
where
    F: FnMut() -> i32,
{
    // Both the stack and the callback, passed by address, may be dropped as
    // soon as clone returns in the parent, so the child must have its own
    // address space.
    if flags & libc::CLONE_VM != 0 {
        return Err(Errno::EINVAL);
    }
    extern "C" fn callback<G: FnMut() -> i32>(data: *mut libc::c_void) -> libc::c_int {
        // No pthread_atfork handler runs in this child.
        super::launch_window::reset_after_raw_clone();
        // SAFETY: `data` is the parent's `cb`, of type `G`; without CLONE_VM
        // the child has its own copy of it.
        let cb = unsafe { &mut *data.cast::<G>() };
        cb() as libc::c_int
    }

    // The callback is passed by address rather than boxed: Command::spawn
    // calls this under a launch's lock (`launch_window`), where nothing may
    // allocate.
    let mut cb = cb;

    let res = unsafe {
        libc::clone(
            callback::<F>,
            stack.top(),
            flags,
            (&mut cb as *mut F).cast::<libc::c_void>(),
        )
    };

    Errno::result(res).map(Pid::from_raw)
}

// The owned Container route deliberately has no arbitrary-flags interface.
// In particular, VM/files/signal handlers and the parent-tid output are private.
pub(super) struct OwnedClone {
    pub(super) pid: Pid,
    pub(super) pidfd: Option<std::os::fd::OwnedFd>,
}

pub(super) fn clone_with_stack_owned<F>(
    cb: F,
    namespaces: super::Namespace,
    stack: &mut ChildStack,
) -> Result<OwnedClone, Errno>
where
    F: FnMut() -> i32,
{
    use std::os::fd::FromRawFd;

    if namespaces.bits() & !super::Namespace::all().bits() != 0 {
        return Err(Errno::EINVAL);
    }
    // CLONE_PIDFD reused a formerly ignored bit. An actual pidfd_open probe
    // refuses unsupported kernels before clone, rather than guessing a version.
    #[cfg(test)]
    if let OwnedCloneTestFault::Probe(error) = OWNED_CLONE_FAULT.with(|f| f.get()) {
        return Err(error);
    }
    drop(super::fd::Fd::pidfd_open(unsafe { libc::getpid() }, 0)?);
    #[cfg(test)]
    if OWNED_CLONE_FAULT.with(|f| f.get()) == OwnedCloneTestFault::ExhaustAtClone {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        Errno::result(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) })?;
    }

    type CloneCb<'a> = Box<dyn FnMut() -> i32 + 'a>;
    extern "C" fn callback(data: *mut CloneCb) -> libc::c_int {
        // No pthread_atfork handler runs in this child.
        super::launch_window::reset_after_raw_clone();
        let cb: &mut CloneCb = unsafe { &mut *data };
        (*cb)() as libc::c_int
    }
    // As in the legacy helper, this box is destroyed in O immediately on
    // return. Container supplies a borrowing adapter, never teardown owners.
    let mut cb: CloneCb = Box::new(cb);
    let mut pidfd = -1;
    let result = unsafe {
        libc::clone(
            core::mem::transmute::<
                extern "C" fn(*mut CloneCb) -> i32,
                extern "C" fn(*mut libc::c_void) -> libc::c_int,
            >(callback),
            stack.top(),
            namespaces.bits() | libc::SIGCHLD | libc::CLONE_PIDFD,
            (&mut cb as *mut CloneCb).cast::<libc::c_void>(),
            // libc's parent_tid (first vararg), NOT the raw syscall order.
            &mut pidfd as *mut libc::c_int,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_int>(),
        )
    };
    let pid = Pid::from_raw(Errno::result(result)?);
    let pidfd = if pidfd >= 0 {
        // SAFETY: successful CLONE_PIDFD created exactly this parent-owned FD.
        Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) })
    } else {
        // A violated kernel contract still leaves an actual child wait owner.
        // The caller must retain that wait and refuse success, not manufacture
        // pidfd authority or assume that the child has not started.
        None
    };
    #[cfg(test)]
    let pidfd = if OWNED_CLONE_FAULT.with(|f| f.get()) == OwnedCloneTestFault::MissingPidfd {
        drop(pidfd);
        None
    } else {
        pidfd
    };
    Ok(OwnedClone { pid, pidfd })
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OwnedCloneTestFault {
    None,
    Probe(Errno),
    ExhaustAtClone,
    MissingPidfd,
}
#[cfg(test)]
thread_local! {
    pub(super) static OWNED_CLONE_FAULT: std::cell::Cell<OwnedCloneTestFault> = const { std::cell::Cell::new(OwnedCloneTestFault::None) };
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::Ordering;

    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::sys::wait::waitpid;

    use super::*;
    use crate::fd::pipe;

    fn wait(pid: Pid) -> WaitStatus {
        loop {
            match waitpid(nix::unistd::Pid::from(pid), None) {
                Err(nix::errno::Errno::EINTR) => continue,
                result => return result.unwrap(),
            }
        }
    }

    #[test]
    fn default_child_stack_keeps_the_container_run_minimum() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stack = child_stack().unwrap();
        let size = stack.top() as usize - stack.bottom() as usize;
        assert!(
            size >= 2 * 1024 * 1024,
            "the cloned child runs container setup before exec and needs at least 2 MiB"
        );
        assert_eq!(size, CHILD_STACK_SIZE);
        assert_eq!(stack.top() as usize % 16, 0);
        assert!(stack.guard_len >= unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize);
    }

    #[test]
    fn default_child_stack_holds_a_backends_first_guest_process() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stack = child_stack().unwrap();
        let size = stack.top() as usize - stack.bottom() as usize;
        assert!(
            size >= 16 * 1024 * 1024,
            "the in-container tracer's main thread runs on the child stack, and with \
             it a KVM run's first guest process, which needs the 16 MiB the KVM \
             backend gives each of its process threads"
        );
        // The guard pages are added to the mapping, not carved out of the
        // usable stack.
        assert_eq!(stack.mapping_len, stack.guard_len + CHILD_STACK_SIZE);
    }

    #[test]
    fn child_keeps_its_stack_after_parent_unmaps() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stack = child_stack().unwrap();
        let bottom = stack.bottom() as usize;
        let top = stack.top() as usize;
        let (reader, mut writer) = pipe().unwrap();
        let reader_fd = reader.as_raw_fd();
        let writer_fd = writer.as_raw_fd();
        let pid = clone_with_stack(
            || {
                // Only async-signal-safe operations in the cloned child.
                unsafe {
                    libc::alarm(5);
                    libc::close(writer_fd);
                    let mut byte = 0_u8;
                    if libc::read(reader_fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                        return 1;
                    }
                    let address = &byte as *const u8 as usize;
                    if (bottom..top).contains(&address) && byte == 42 {
                        42
                    } else {
                        2
                    }
                }
            },
            libc::SIGCHLD,
            &mut stack,
        )
        .unwrap();
        drop(stack);
        drop(reader);
        writer.write_all(&[42]).unwrap();
        drop(writer);
        assert_eq!(wait(pid), WaitStatus::Exited(pid.into(), 42));
    }

    #[test]
    fn stack_is_unmapped_after_clone_failure() {
        if crate::test_runs_in_own_process() {
            return;
        }
        // Isolate the address space so another test thread cannot reuse the
        // just-unmapped addresses before mincore checks them.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let check = || -> Result<(), Errno> {
                let mut stack = child_stack()?;
                let mapping = stack.mapping;
                let len = stack.mapping_len;
                let page_size = stack.guard_len / GUARD_PAGES;
                // CLONE_SIGHAND without CLONE_VM must fail in the kernel.
                if clone_with_stack(|| 99, libc::SIGCHLD | libc::CLONE_SIGHAND, &mut stack)
                    != Err(Errno::EINVAL)
                {
                    return Err(Errno::EINVAL);
                }
                drop(stack);
                for offset in (0..len).step_by(page_size) {
                    let mut resident = 0;
                    let result = unsafe {
                        libc::mincore(
                            mapping.cast::<u8>().wrapping_add(offset).cast(),
                            1,
                            &mut resident,
                        )
                    };
                    if result != -1 || Errno::last() != Errno::ENOMEM {
                        return Err(Errno::EINVAL);
                    }
                }
                Ok(())
            };
            unsafe {
                libc::alarm(5);
                // Do not unwind into the copied libtest worker: when that
                // child thread exits, the process can incorrectly exit 0.
                libc::_exit(match std::panic::catch_unwind(check) {
                    Ok(Ok(())) => 0,
                    Ok(Err(_)) => 1,
                    Err(_) => 2,
                });
            }
        }
        assert_eq!(
            wait(Pid::from_raw(pid)),
            WaitStatus::Exited(nix::unistd::Pid::from_raw(pid), 0)
        );
    }

    #[test]
    fn shared_address_space_is_rejected() {
        if crate::test_runs_in_own_process() {
            return;
        }
        assert_eq!(
            clone(|| 99, libc::SIGCHLD | libc::CLONE_VM),
            Err(Errno::EINVAL)
        );
    }

    // Set only in the child's private address space, before enabling its
    // handler. The handler reports the actual kernel fault, then SA_RESETHAND
    // lets the retried instruction terminate the child with SIGSEGV.
    static FAULT_FD: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn report_fault(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
        unsafe {
            let report = [(*info).si_addr() as usize, (*info).si_code as usize];
            let size = std::mem::size_of_val(&report);
            if libc::write(
                FAULT_FD.load(Ordering::Relaxed),
                report.as_ptr().cast(),
                size,
            ) != size as isize
            {
                libc::_exit(100);
            }
        }
    }

    #[inline(never)]
    fn recurse_into_guard(bottom: usize) -> u8 {
        // The address escapes and the frame is read after recursion, preventing
        // frame elimination and tail calls in optimized builds. Stop within the
        // guard: making it writable must produce a normal exit, not a later
        // unrelated SIGSEGV below the entire mapping.
        let mut frame = [0_u8; 1024];
        std::hint::black_box(&mut frame);
        if frame.as_ptr() as usize >= bottom {
            frame[0] = recurse_into_guard(std::hint::black_box(bottom));
        }
        unsafe { std::ptr::read_volatile(frame.as_ptr()) }
    }

    #[test]
    fn stack_overflow_faults_in_guard() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stack = child_stack().unwrap();
        let guard_start = stack.mapping as usize;
        let bottom = stack.bottom() as usize;
        let mut signal_stack = vec![0_u8; 64 * 1024];
        let alternate = libc::stack_t {
            ss_sp: signal_stack.as_mut_ptr().cast(),
            ss_size: signal_stack.len(),
            ss_flags: 0,
        };
        let (mut reader, writer) = pipe().unwrap();
        let writer_fd = writer.as_raw_fd();
        let reader_fd = reader.as_raw_fd();
        let pid = clone_with_stack(
            || {
                unsafe {
                    libc::alarm(5);
                    libc::close(reader_fd);
                    let limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = report_fault as *const () as usize;
                    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESETHAND;
                    libc::sigemptyset(&mut action.sa_mask);
                    FAULT_FD.store(writer_fd, Ordering::Relaxed);
                    if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
                        || libc::sigaltstack(&alternate, std::ptr::null_mut()) != 0
                        || libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()) != 0
                    {
                        return 101;
                    }
                }
                i32::from(recurse_into_guard(bottom))
            },
            libc::SIGCHLD,
            &mut stack,
        )
        .unwrap();
        drop(stack);
        drop(signal_stack);
        drop(writer);
        // Reap even when the assertion fails (including mutation controls).
        let status = wait(pid);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert!(
            matches!(status, WaitStatus::Signaled(_, Signal::SIGSEGV, _)),
            "{status:?}"
        );
        assert_eq!(bytes.len(), 2 * std::mem::size_of::<usize>());
        let (address, code) = bytes.split_at(std::mem::size_of::<usize>());
        let address = usize::from_ne_bytes(address.try_into().unwrap());
        let code = usize::from_ne_bytes(code.try_into().unwrap());
        assert!(
            (guard_start..bottom).contains(&address),
            "fault at {address:#x} outside guard {guard_start:#x}..{bottom:#x}"
        );
        assert_eq!(
            code, 2,
            "expected SEGV_ACCERR for the protected guard mapping"
        );
    }
}
