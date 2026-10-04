/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::fd::AsRawFd;

use super::*;

thread_local! {
    static SETUP_CALLS: std::cell::RefCell<Vec<(i64, [u64; 6])>> = const { std::cell::RefCell::new(Vec::new()) };
}

// A synchronous setup fixture, not an async-safe gate or hardware PMU. Use an
// owned memfd for the metadata mapping so real close/munmap lifetime is tested
// without closing a fabricated descriptor that another test might own.
unsafe fn setup_gate(number: i64, arguments: [u64; 6]) -> i64 {
    use perf_event_open_sys::bindings as perf;
    SETUP_CALLS.with_borrow_mut(|calls| calls.push((number, arguments)));
    if number == libc::SYS_perf_event_open {
        let attr = unsafe { &*(arguments[0] as *const perf::perf_event_attr) };
        assert_eq!(attr.disabled(), 1);
        assert_eq!(attr.pinned(), 1);
        assert_eq!(attr.exclude_kernel(), 1);
        assert_eq!(unsafe { attr.__bindgen_anon_1.sample_period }, 0);
        assert_eq!(arguments[1], 0);
        assert_eq!(arguments[2], u64::MAX);
        assert_eq!(arguments[3], u64::MAX);
        assert_eq!(arguments[4], u64::from(perf::PERF_FLAG_FD_CLOEXEC));
        let fd = unsafe {
            native_gate(
                libc::SYS_memfd_create,
                [
                    c"paused-clock-fixture".as_ptr() as u64,
                    libc::MFD_CLOEXEC as u64,
                    0,
                    0,
                    0,
                    0,
                ],
            )
        };
        assert!(fd >= 0);
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(page_size > 0);
        assert_eq!(
            unsafe {
                native_gate(
                    libc::SYS_ftruncate,
                    [fd as u64, page_size as u64, 0, 0, 0, 0],
                )
            },
            0
        );
        fd
    } else if number == libc::SYS_ioctl {
        assert!(arguments[1] == perf::RESET as u64 || arguments[1] == perf::ENABLE as u64);
        0
    } else {
        assert!(matches!(
            number,
            libc::SYS_mmap | libc::SYS_munmap | libc::SYS_close | libc::SYS_read
        ));
        unsafe { native_gate(number, arguments) }
    }
}

#[test]
fn disabled_creation_preserves_enabled_setup_and_owns_its_descriptor() {
    use perf_event_open_sys::bindings as perf;
    for enabled in [false, true] {
        SETUP_CALLS.with_borrow_mut(Vec::clear);
        let config = PmuConfig::try_from_family_model(0x06, 0x3c);
        let clock = if enabled {
            InGuestRcbCounter::current_thread_with_config(config, Some(setup_gate))
        } else {
            InGuestRcbCounter::create_with_config(config, Some(setup_gate))
        }
        .unwrap();
        let fd = unsafe { clock.boundary_fd() }.as_raw_fd();
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, libc::FD_CLOEXEC);
        SETUP_CALLS.with_borrow(|calls| {
            let numbers: Vec<_> = calls.iter().map(|call| call.0).collect();
            if enabled {
                assert_eq!(
                    numbers,
                    [
                        libc::SYS_perf_event_open,
                        libc::SYS_mmap,
                        libc::SYS_ioctl,
                        libc::SYS_ioctl
                    ]
                );
                assert_eq!(calls[2].1[1], perf::RESET as u64);
                assert_eq!(calls[3].1[1], perf::ENABLE as u64);
            } else {
                assert_eq!(numbers, [libc::SYS_perf_event_open, libc::SYS_mmap]);
            }
            assert_eq!(calls[1].1[4], fd as u64);
            assert_eq!(calls[1].1[2], libc::PROT_READ as u64);
        });
        drop(clock);
        SETUP_CALLS.with_borrow(|calls| {
            assert_eq!(calls[calls.len() - 2].0, libc::SYS_munmap);
            assert_eq!(calls.last().unwrap().0, libc::SYS_close);
            assert_eq!(calls.last().unwrap().1[0], fd as u64);
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call.0 == libc::SYS_close)
                    .count(),
                1
            );
        });
        // Do not inspect the closed descriptor number: another parallel test
        // may already have reused it. Drop checked the trusted close result.
    }
}

core::arch::global_asm!(
    r#"
    .text
    .global reverie_test_counted_boundary
    .hidden reverie_test_counted_boundary
    .type reverie_test_counted_boundary,@function
reverie_test_counted_boundary:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov eax, {ioctl}
    mov esi, {enable}
    xor edx, edx
    syscall
    test rax, rax
    lea rdx, [rip + .Lboundary_return]
    lea rcx, [rip + .Lboundary_count]
    cmovns rdx, rcx
    jmp rdx
.Lboundary_count:
    mov rcx, r13
.Lboundary_loop:
    dec rcx
    jnz .Lboundary_loop
    mov eax, {ioctl}
    mov rdi, r12
    mov esi, {disable}
    xor edx, edx
    syscall
.Lboundary_return:
    pop r13
    pop r12
    ret
    .size reverie_test_counted_boundary, .-reverie_test_counted_boundary
    "#,
    ioctl = const libc::SYS_ioctl,
    enable = const perf_event_open_sys::bindings::ENABLE,
    disable = const perf_event_open_sys::bindings::DISABLE,
);

unsafe extern "C" {
    fn reverie_test_counted_boundary(fd: i32, branches: u64) -> i64;
}

unsafe fn native_gate(number: i64, arguments: [u64; 6]) -> i64 {
    let result;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") arguments[0],
            in("rsi") arguments[1],
            in("rdx") arguments[2],
            in("r10") arguments[3],
            in("r8") arguments[4],
            in("r9") arguments[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[test]
fn hardware_paused_clock_preserves_exact_branch_trajectory() {
    std::thread::spawn(|| {
        for workload in [0, 100, 10000] {
            let clock = unsafe {
                InGuestRcbCounter::current_thread_disabled_with_syscall_gate(native_gate)
            }
            .expect("hardware PMU clock required; this test does not skip unavailable hosts");
            let fd = unsafe { clock.boundary_fd() };
            assert_eq!(unsafe { clock.read_paused_once() }, Ok(0));
            let mut expected = 0;
            let mut trajectory = vec![0];
            for branches in [1, 2, 17, 33, 1, 9] {
                for branch in 0..workload {
                    std::hint::black_box(branch);
                }
                assert_eq!(unsafe { clock.read_paused_once() }, Ok(expected));
                assert_eq!(
                    unsafe { reverie_test_counted_boundary(fd.as_raw_fd(), branches) },
                    0
                );
                expected += branches;
                let observed = unsafe { clock.read_paused_once() }.unwrap();
                assert_eq!(observed, expected);
                trajectory.push(observed);
            }
            assert_eq!(trajectory, [0, 1, 3, 20, 53, 54, 63]);
            eprintln!("paused runtime workload={workload}: RCB trajectory={trajectory:?}");
        }
    })
    .join()
    .unwrap();
}
