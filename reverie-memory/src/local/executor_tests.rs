/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicIsize;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;

use super::*;

// Each test uses the existing bounded, single-test subprocess helper. The
// observer needs no allocator, lock, TLS initialization, or pointer retention
// inside the executor. It always forwards the original syscall and arguments,
// including errors and partial results; observations cannot change its result.
static GETPIDS: AtomicUsize = AtomicUsize::new(0);
static TRANSFERS: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicUsize = AtomicUsize::new(0);
static PID: AtomicUsize = AtomicUsize::new(0);
static BAD: AtomicBool = AtomicBool::new(false);
static RAW_RESULT: AtomicIsize = AtomicIsize::new(isize::MIN);
static NUMBER: AtomicUsize = AtomicUsize::new(0);
static LOCAL_ARRAY: AtomicUsize = AtomicUsize::new(0);
static LOCAL_COUNT: AtomicUsize = AtomicUsize::new(0);
static REMOTE_ARRAY: AtomicUsize = AtomicUsize::new(0);
static REMOTE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn result_code(result: Result<usize, Errno>) -> isize {
    match result {
        Ok(count) => count as isize,
        Err(error) => -(error.into_raw() as isize),
    }
}

unsafe fn observed_syscall(number: syscalls::Sysno, args: [usize; 6]) -> Result<usize, Errno> {
    if number == syscalls::Sysno::getpid {
        GETPIDS.fetch_add(1, Relaxed);
        BAD.fetch_or(args != [0; 6] || PHASE.swap(1, Relaxed) != 0, Relaxed);
    } else {
        TRANSFERS.fetch_add(1, Relaxed);
        let local = LOCAL_ARRAY.load(Relaxed);
        let remote = REMOTE_ARRAY.load(Relaxed);
        BAD.fetch_or(
            PHASE.swap(0, Relaxed) != 1
                || number as usize != NUMBER.load(Relaxed)
                || args[0] != PID.load(Relaxed)
                || args[1] == 0
                || (local != 0 && args[1] != local)
                || args[2] != LOCAL_COUNT.load(Relaxed)
                || args[3] == 0
                || (remote != 0 && args[3] != remote)
                || args[4] != REMOTE_COUNT.load(Relaxed)
                || args[5] != 0,
            Relaxed,
        );
    }
    // SAFETY: forward the caller's six arguments, synchronously and unchanged.
    // The observer never dereferences the syscall's descriptor/guest pointers.
    let result =
        unsafe { syscalls::syscall6(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if number == syscalls::Sysno::getpid {
        if let Ok(pid) = result {
            PID.store(pid, Relaxed);
        }
    } else {
        RAW_RESULT.store(result_code(result), Relaxed);
    }
    result
}

fn memory() -> LocalMemory {
    // SAFETY: the executor always performs the exact synchronous raw syscall.
    // Fixed atomic observations add no allocation, lock, retry or callback.
    unsafe { LocalMemory::with_syscall_executor(observed_syscall) }
}

// Expected array addresses come from live test-owned descriptors, not from
// retaining pointers supplied to the executor. Zero leaves a scalar method's
// private stack descriptor address unspecified; its counts, bytes and results
// are still checked. Vectored cases check every one of the six arguments.
fn prepare(number: syscalls::Sysno, local: usize, locals: usize, remote: usize, remotes: usize) {
    GETPIDS.store(0, Relaxed);
    TRANSFERS.store(0, Relaxed);
    PHASE.store(0, Relaxed);
    PID.store(0, Relaxed);
    BAD.store(false, Relaxed);
    RAW_RESULT.store(isize::MIN, Relaxed);
    NUMBER.store(number as usize, Relaxed);
    LOCAL_ARRAY.store(local, Relaxed);
    LOCAL_COUNT.store(locals, Relaxed);
    REMOTE_ARRAY.store(remote, Relaxed);
    REMOTE_COUNT.store(remotes, Relaxed);
}

fn assert_forwarded(result: Result<usize, Errno>) {
    assert_eq!(GETPIDS.load(Relaxed), 1, "fresh getpid for this transfer");
    assert_eq!(TRANSFERS.load(Relaxed), 1, "one kernel copy attempt");
    assert_eq!(PHASE.load(Relaxed), 0);
    assert!(!BAD.load(Relaxed), "syscall order or arguments changed");
    assert_eq!(RAW_RESULT.load(Relaxed), result_code(result));
    assert_eq!(PID.load(Relaxed), unsafe {
        syscalls::syscall0(syscalls::Sysno::getpid).unwrap()
    });
    LOCAL_ARRAY.store(0, Relaxed);
    REMOTE_ARRAY.store(0, Relaxed);
}

fn assert_not_called() {
    assert_eq!(GETPIDS.load(Relaxed), 0);
    assert_eq!(TRANSFERS.load(Relaxed), 0);
    assert_eq!(PHASE.load(Relaxed), 0);
    assert_eq!(RAW_RESULT.load(Relaxed), isize::MIN);
    assert!(!BAD.load(Relaxed));
}

fn isolated(test: &str) -> bool {
    // libtest's discovered names omit the crate prefix in module_path!().
    let (_, module) = module_path!().split_once("::").unwrap();
    in_isolated_process(&format!("{module}::{test}"))
}

#[test]
fn supplied_executor_forwards_scalar_and_vector_arguments_with_fresh_pids() {
    if !isolated("supplied_executor_forwards_scalar_and_vector_arguments_with_fresh_pids") {
        return;
    }
    let mut memory = memory();
    let source = [0x13, 0x27, 0x45, 0x69];
    let mut observed = [0; 4];
    prepare(syscalls::Sysno::process_vm_readv, 0, 1, 0, 1);
    assert_eq!(
        memory.read(Addr::from_ptr(source.as_ptr()).unwrap(), &mut observed),
        Ok(4)
    );
    assert_eq!(observed, source);
    assert_forwarded(Ok(4));

    prepare(syscalls::Sysno::process_vm_writev, 0, 1, 0, 1);
    observed.fill(0);
    assert_eq!(
        memory.write(AddrMut::from_ptr(observed.as_mut_ptr()).unwrap(), &source),
        Ok(4)
    );
    assert_eq!(observed, source);
    assert_forwarded(Ok(4));

    for write in [false, true] {
        observed.fill(0);
        let mut local = [
            iovec(observed.as_mut_ptr() as usize, 1),
            iovec(observed.as_mut_ptr() as usize + 1, 3),
        ];
        let mut remote = [
            iovec(source.as_ptr() as usize, 2),
            iovec(source.as_ptr() as usize + 2, 2),
        ];
        if write {
            local = [
                iovec(source.as_ptr() as usize, 1),
                iovec(source.as_ptr() as usize + 1, 3),
            ];
            remote = [
                iovec(observed.as_mut_ptr() as usize, 2),
                iovec(observed.as_mut_ptr() as usize + 2, 2),
            ];
        }
        prepare(
            if write {
                syscalls::Sysno::process_vm_writev
            } else {
                syscalls::Sysno::process_vm_readv
            },
            local.as_ptr() as usize,
            local.len(),
            remote.as_ptr() as usize,
            remote.len(),
        );
        let result = unsafe {
            if write {
                memory.write_vectored(read_descriptors(&local), write_descriptors(&mut remote))
            } else {
                memory.read_vectored(read_descriptors(&remote), write_descriptors(&mut local))
            }
        };
        assert_eq!(result, Ok(4));
        assert_eq!(observed, source);
        assert_forwarded(Ok(4));
    }
}

#[test]
fn supplied_executor_preserves_kernel_partial_fault_and_invalid_vector_results() {
    if !isolated("supplied_executor_preserves_kernel_partial_fault_and_invalid_vector_results") {
        return;
    }
    let mut memory = memory();
    for write in [false, true] {
        let number = if write {
            syscalls::Sysno::process_vm_writev
        } else {
            syscalls::Sysno::process_vm_readv
        };
        for partial in [false, true] {
            let control = Mapping::new();
            let candidate = Mapping::new();
            let offset = if partial {
                control.page - 3
            } else {
                control.page
            };
            control.protect_second(libc::PROT_NONE);
            candidate.protect_second(libc::PROT_NONE);
            let mut expected = [0xa7; 9];
            let mut observed = expected;
            let raw = native(
                write,
                &[iovec(expected.as_mut_ptr() as usize, expected.len())],
                &[iovec(control.address(offset), expected.len())],
            );
            assert_eq!(raw, if partial { Ok(3) } else { Err(Errno::EFAULT) });
            prepare(number, 0, 1, 0, 1);
            let result = if write {
                memory.write(
                    AddrMut::from_raw(candidate.address(offset)).unwrap(),
                    &observed,
                )
            } else {
                memory.read(
                    Addr::from_raw(candidate.address(offset)).unwrap(),
                    &mut observed,
                )
            };
            assert_eq!(result, raw);
            assert_forwarded(raw);
            assert_eq!(observed, expected);
            assert_eq!(candidate.snapshot(), control.snapshot());
        }

        for case in 0..3 {
            let control = Mapping::new();
            let candidate = Mapping::new();
            control.protect_second(libc::PROT_NONE);
            candidate.protect_second(libc::PROT_NONE);
            let vectors = |mapping: &Mapping| match case {
                0 => vec![iovec(mapping.address(mapping.page - 3), 9)],
                1 => vec![iovec(mapping.address(mapping.page), 1)],
                _ => vec![iovec(1, 0); 1025],
            };
            let mut expected = [0x35; 9];
            let mut observed = expected;
            let raw = native(
                write,
                &[iovec(expected.as_mut_ptr() as usize, expected.len())],
                &vectors(&control),
            );
            assert_eq!(
                raw,
                match case {
                    0 => Ok(3),
                    1 => Err(Errno::EFAULT),
                    _ => Err(Errno::EINVAL),
                }
            );
            let mut local = [iovec(observed.as_mut_ptr() as usize, observed.len())];
            let mut remote = vectors(&candidate);
            prepare(
                number,
                local.as_ptr() as usize,
                local.len(),
                remote.as_ptr() as usize,
                remote.len(),
            );
            let result = unsafe {
                if write {
                    memory.write_vectored(read_descriptors(&local), write_descriptors(&mut remote))
                } else {
                    memory.read_vectored(read_descriptors(&remote), write_descriptors(&mut local))
                }
            };
            assert_eq!(
                result,
                if raw == Err(Errno::EFAULT) {
                    Ok(0)
                } else {
                    raw
                }
            );
            assert_forwarded(raw);
            assert_eq!(observed, expected);
            assert_eq!(candidate.snapshot(), control.snapshot());
        }
    }
}

#[test]
fn executor_is_instance_owned_and_debug_and_scalar_bypasses_are_stable() {
    if !isolated("executor_is_instance_owned_and_debug_and_scalar_bypasses_are_stable") {
        return;
    }
    let mut supplied = memory();
    prepare(syscalls::Sysno::process_vm_readv, 0, 1, 0, 1);
    let source = [0x73; 4];
    let address = Addr::from_ptr(source.as_ptr()).unwrap();
    for ordinary in [LocalMemory::new(), LocalMemory::default()] {
        assert_eq!(format!("{ordinary:?}"), "LocalMemory");
        let mut buffer = [0; 4];
        assert_eq!(ordinary.read(address, &mut buffer), Ok(4));
        assert_eq!(buffer, source);
        assert_not_called();
    }
    assert_eq!(format!("{supplied:?}"), "LocalMemory");
    let invalid = Addr::from_raw(usize::MAX - 1).unwrap();
    let invalid_mut = AddrMut::from_raw(usize::MAX - 1).unwrap();
    assert_eq!(supplied.read(invalid, &mut []), Ok(0));
    assert_eq!(supplied.write(invalid_mut, &[]), Ok(0));
    assert_eq!(supplied.read_exact(invalid, &mut []), Ok(()));
    assert_eq!(supplied.write_exact(invalid_mut, &[]), Ok(()));
    let mut unchanged = [0xa7; 4];
    assert_eq!(supplied.read(invalid, &mut unchanged), Err(Errno::EFAULT));
    assert_eq!(supplied.write(invalid_mut, &source), Err(Errno::EFAULT));
    assert_eq!(unchanged, [0xa7; 4]);
    assert_not_called();
    assert_eq!(supplied.read(address, &mut unchanged), Ok(4));
    assert_eq!(unchanged, source);
    assert_forwarded(Ok(4));
}

#[cfg(target_arch = "x86_64")] // This test exercises the raw SYS_fork syscall.
#[test]
fn inherited_executor_handle_uses_child_pid_after_a_real_fork() {
    if !isolated("inherited_executor_handle_uses_child_pid_after_a_real_fork") {
        return;
    }
    let memory = memory();
    let mut source = [0x35];
    let address = Addr::from_ptr(source.as_ptr()).unwrap();
    let mut observed = [0];
    prepare(syscalls::Sysno::process_vm_readv, 0, 1, 0, 1);
    assert_eq!(memory.read(address, &mut observed), Ok(1));
    assert_eq!(observed, source);
    assert_forwarded(Ok(1));
    let parent = PID.load(Relaxed);
    let child = unsafe { syscalls::syscall0(syscalls::Sysno::fork) }.unwrap() as libc::pid_t;
    if child == 0 {
        // No allocation, locks, formatting, unwinding or test-harness calls in
        // the child. A cached parent PID would read 0x35 from the parent's COW
        // page, rather than this child's byte, even if that copy succeeded.
        unsafe { std::ptr::write_volatile(source.as_mut_ptr(), 0xa6) };
        prepare(syscalls::Sysno::process_vm_readv, 0, 1, 0, 1);
        let current = unsafe { syscalls::syscall0(syscalls::Sysno::getpid) }.unwrap_or(0);
        let result = memory.read(address, &mut observed);
        let correct = current != 0
            && current != parent
            && result == Ok(1)
            && observed == [0xa6]
            && PID.load(Relaxed) == current
            && GETPIDS.load(Relaxed) == 1
            && TRANSFERS.load(Relaxed) == 1
            && PHASE.load(Relaxed) == 0
            && RAW_RESULT.load(Relaxed) == 1
            && !BAD.load(Relaxed);
        unsafe { libc::_exit(if correct { 0 } else { 1 }) };
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        if waited < 0 {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        } else {
            assert_eq!(waited, 0);
        }
        if Instant::now() >= deadline {
            assert_eq!(unsafe { libc::kill(child, libc::SIGKILL) }, 0);
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            panic!("fork child exceeded its three-second wall limit");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert_eq!(source, [0x35]);
    assert_forwarded(Ok(1));
}
