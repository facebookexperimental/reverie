/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Native and real SIGSYS forwarding with guest buffers on protection keys.
//! These tests intentionally unregister their own glibc rseq before denying
//! its TLS key, then restore registration after permissions are restored. A
//! registered rseq area must remain accessible to kernel signal/preemption
//! fixups; a successful short raw syscall alone does not establish that.

use std::ptr;

use reverie_preload::dispatch::PassthroughDispatcher;
use reverie_preload::lifecycle::InProcessSeccomp;
use reverie_preload::lifecycle::LifecycleController;
use reverie_preload::lifecycle::RuntimeConfig;
use reverie_preload::trap;

const CHILD: &str = "REVERIE_TEST_PKEY_BUFFERS";
const MARKER: &str = "buffer row: ";

#[repr(C)]
struct Operation {
    number: u64,
    fd: u64,
    buffer: u64,
    length: u64,
    pkru: u64,
    stack: u64,
    result: i64,
    original_pkru: u64,
    returned_pkru: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

core::arch::global_asm!(include_str!("pkey_buffers/syscall.S"));
unsafe extern "C" {
    fn pkey_buffer_syscall(operation: *mut Operation);
}

unsafe fn map(bytes: usize, key: i32) -> *mut u8 {
    let result = unsafe {
        libc::mmap(
            ptr::null_mut(),
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(result, libc::MAP_FAILED);
    if key != 0 {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pkey_mprotect,
                    result,
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    key,
                )
            },
            0
        );
    }
    result.cast()
}

unsafe fn rseq_registration() -> Option<*mut libc::c_void> {
    let offset =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_offset".as_ptr()).cast::<isize>() };
    let size = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_size".as_ptr()).cast::<u32>() };
    assert!(!offset.is_null() && !size.is_null());
    let size = unsafe { *size };
    // glibc exports the supported feature length (20 on this host), while its
    // original Linux registration used the 32-byte ABI structure. Unregister
    // and restore that exact ABI length; reject an unknown extended layout.
    assert!(size <= 32, "unknown glibc rseq layout: {size}");
    if size == 0 {
        return None;
    }
    let mut fs = 0usize;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003, &raw mut fs) },
        0
    );
    let area = fs.wrapping_add_signed(unsafe { *offset }) as *mut libc::c_void;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_rseq, area, 32, 1, 0x5305_3053u32) },
        0
    );
    Some(area)
}

unsafe fn invoke(operation: &mut Operation) {
    unsafe {
        *libc::__errno_location() = libc::E2BIG;
    }
    unsafe {
        pkey_buffer_syscall(operation);
    }
    assert_eq!(unsafe { *libc::__errno_location() }, libc::E2BIG);
    assert_eq!(operation.returned_pkru, operation.pkru);
}

fn protected_buffers_child() {
    let Ok(mode) = std::env::var(CHILD) else {
        return;
    };
    if core::arch::x86_64::__cpuid(0).eax < 7
        || core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) == 0
    {
        println!("OSPKE unavailable");
        return;
    }
    unsafe {
        let rseq = rseq_registration();
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let buffer_key = libc::syscall(libc::SYS_pkey_alloc, 0, 0);
        let stack_key = libc::syscall(libc::SYS_pkey_alloc, 0, 0);
        assert_eq!(buffer_key, 1);
        assert_eq!(stack_key, 2);
        let buffers = [map(page, 0), map(page, buffer_key as i32)];
        let operation_memory = map(page + 1024 * 1024, stack_key as i32);
        let operation = &mut *operation_memory.cast::<Operation>();
        operation.stack = operation_memory.add(page + 1024 * 1024) as u64;
        let partial = map(2 * page, 0);
        assert_eq!(
            libc::syscall(
                libc::SYS_pkey_mprotect,
                partial.add(page),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                buffer_key
            ),
            0
        );
        let mut pipe = [-1; 2];
        assert_eq!(
            libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC),
            0
        );
        assert!(libc::fcntl(pipe[1], libc::F_GETPIPE_SZ) >= (2 * page) as i32);

        if mode != "native" {
            trap::set_dispatcher(Box::new(PassthroughDispatcher::new()));
            InProcessSeccomp
                .install(&RuntimeConfig {
                    use_alt_stack: mode == "alt-stack",
                })
                .unwrap();
        }
        for (key, &buffer) in buffers.iter().enumerate() {
            for direction in 0..2 {
                for rights in 0..3 {
                    let sent = 0x69u8;
                    let mut received = 0u8;
                    *buffer = 0x35;
                    if direction == 0 {
                        assert_eq!(libc::write(pipe[1], (&raw const sent).cast(), 1), 1);
                    }
                    operation.number = if direction == 0 {
                        libc::SYS_read
                    } else {
                        libc::SYS_write
                    } as u64;
                    operation.fd = pipe[direction] as u64;
                    operation.buffer = buffer as u64;
                    operation.length = 1;
                    operation.pkru = rights << (key * 2);
                    invoke(operation);
                    let denied = rights == 1 || (direction == 0 && rights == 2);
                    assert_eq!(
                        operation.result,
                        if denied { -i64::from(libc::EFAULT) } else { 1 }
                    );
                    assert_eq!(
                        *buffer,
                        if direction == 0 && !denied {
                            0x69
                        } else {
                            0x35
                        }
                    );
                    let remaining = libc::read(pipe[0], (&raw mut received).cast(), 1);
                    let has_byte = (direction == 0 && denied) || (direction == 1 && !denied);
                    assert_eq!(remaining, if has_byte { 1 } else { -1 });
                    assert_eq!(
                        received,
                        if has_byte {
                            if direction == 0 { 0x69 } else { 0x35 }
                        } else {
                            0
                        }
                    );
                    println!(
                        "{MARKER}key={key} direction={direction} rights={rights} result={} raw_errno={} buffer={} remaining={remaining} pipe={received} pkru={}",
                        operation.result,
                        if operation.result < 0 {
                            -operation.result
                        } else {
                            0
                        },
                        *buffer,
                        operation.returned_pkru
                    );
                }
            }
        }
        for direction in 0..2 {
            for deny_second in [false, true] {
                ptr::write_bytes(partial, 0x35, 2 * page);
                let seed = vec![0x69u8; 2 * page];
                if direction == 0 {
                    assert_eq!(
                        libc::write(pipe[1], seed.as_ptr().cast(), seed.len()),
                        seed.len() as isize
                    );
                }
                operation.number = if direction == 0 {
                    libc::SYS_read
                } else {
                    libc::SYS_write
                } as u64;
                operation.fd = pipe[direction] as u64;
                operation.buffer = partial as u64;
                operation.length = (2 * page) as u64;
                operation.pkru = if deny_second { 4 } else { 0 };
                invoke(operation);
                let transferred = if deny_second { page } else { 2 * page };
                assert_eq!(operation.result, transferred as i64);
                let mut remainder = vec![0u8; 2 * page];
                let remaining = libc::read(pipe[0], remainder.as_mut_ptr().cast(), remainder.len());
                let expected_remaining = if direction == 0 {
                    2 * page - transferred
                } else {
                    transferred
                };
                assert_eq!(
                    remaining,
                    if expected_remaining == 0 {
                        -1
                    } else {
                        expected_remaining as isize
                    }
                );
                assert!(
                    remainder[..expected_remaining]
                        .iter()
                        .all(|&byte| byte == if direction == 0 { 0x69 } else { 0x35 })
                );
                let bytes = std::slice::from_raw_parts(partial, 2 * page);
                if direction == 0 {
                    assert!(bytes[..transferred].iter().all(|&byte| byte == 0x69));
                    assert!(bytes[transferred..].iter().all(|&byte| byte == 0x35));
                } else {
                    assert!(bytes.iter().all(|&byte| byte == 0x35));
                }
                println!(
                    "{MARKER}partial direction={direction} denied={deny_second} result={} raw_errno=0 remaining={remaining} buffer_sum={} pipe_sum={} pkru={}",
                    operation.result,
                    bytes.iter().map(|&byte| u64::from(byte)).sum::<u64>(),
                    remainder.iter().map(|&byte| u64::from(byte)).sum::<u64>(),
                    operation.returned_pkru
                );
            }
        }
        // The shared Builtin forwards these operations too. Check denied
        // output buffers and signal-action inputs, not only pipe copies.
        // Successful clock values are inherently time-varying: assert their
        // structure/range, while refused buffers must stay byte-identical.
        for (key, &buffer) in buffers.iter().enumerate() {
            for rights in 0..3 {
                for kind in [
                    "clock_gettime",
                    "gettimeofday",
                    "sigaction-query",
                    "sigaction-set",
                ] {
                    ptr::write_bytes(buffer, 0x35, 32);
                    operation.pkru = rights << (key * 2);
                    operation.arg3 = 0;
                    operation.arg4 = 0;
                    operation.arg5 = 0;
                    operation.length = 0;
                    let input = kind == "sigaction-set";
                    match kind {
                        "clock_gettime" => {
                            operation.number = libc::SYS_clock_gettime as u64;
                            operation.fd = libc::CLOCK_REALTIME as u64;
                            operation.buffer = buffer as u64;
                        }
                        "gettimeofday" => {
                            operation.number = libc::SYS_gettimeofday as u64;
                            operation.fd = buffer as u64;
                            operation.buffer = 0;
                        }
                        "sigaction-query" => {
                            operation.number = libc::SYS_rt_sigaction as u64;
                            operation.fd = libc::SIGUSR1 as u64;
                            operation.buffer = 0;
                            operation.length = buffer as u64;
                            operation.arg3 = 8;
                        }
                        "sigaction-set" => {
                            ptr::write_bytes(buffer, 0, 32);
                            buffer.cast::<u64>().write(libc::SIG_IGN as u64);
                            operation.number = libc::SYS_rt_sigaction as u64;
                            operation.fd = libc::SIGUSR1 as u64;
                            operation.buffer = buffer as u64;
                            operation.arg3 = 8;
                        }
                        _ => unreachable!(),
                    }
                    let original = std::slice::from_raw_parts(buffer, 32).to_vec();
                    invoke(operation);
                    let denied = rights == 1 || (!input && rights == 2);
                    assert_eq!(
                        operation.result,
                        if denied { -i64::from(libc::EFAULT) } else { 0 }
                    );
                    let bytes = std::slice::from_raw_parts(buffer, 32);
                    if denied || input {
                        assert_eq!(bytes, original);
                    }
                    let first = buffer.cast::<i64>().read();
                    let second = buffer.add(8).cast::<i64>().read();
                    if !denied {
                        match kind {
                            "clock_gettime" => {
                                assert!(first > 0);
                                assert!((0..1_000_000_000).contains(&second));
                            }
                            "gettimeofday" => {
                                assert!(first > 0);
                                assert!((0..1_000_000).contains(&second));
                            }
                            "sigaction-query" => assert!(bytes.iter().all(|&byte| byte == 0)),
                            _ => {}
                        }
                    }
                    if input {
                        let mut action = [0u64; 4];
                        assert_eq!(
                            libc::syscall(
                                libc::SYS_rt_sigaction,
                                libc::SIGUSR1,
                                0,
                                action.as_mut_ptr(),
                                8
                            ),
                            0
                        );
                        assert_eq!(
                            action[0],
                            if denied { libc::SIG_DFL } else { libc::SIG_IGN } as u64
                        );
                        let reset = [0u64; 4];
                        assert_eq!(
                            libc::syscall(
                                libc::SYS_rt_sigaction,
                                libc::SIGUSR1,
                                reset.as_ptr(),
                                0,
                                8
                            ),
                            0
                        );
                    }
                    println!(
                        "{MARKER}{kind} key={key} rights={rights} result={} raw_errno={} unchanged={} pkru={}",
                        operation.result,
                        if operation.result < 0 {
                            -operation.result
                        } else {
                            0
                        },
                        bytes == original,
                        operation.returned_pkru
                    );
                }
            }
        }
        if let Some(area) = rseq {
            assert_eq!(
                libc::syscall(libc::SYS_rseq, area, 32, 0, 0x5305_3053u32),
                0
            );
        }
    }
}

fn main() {
    // Install on the process main thread before any application threads exist.
    protected_buffers_child();
}
