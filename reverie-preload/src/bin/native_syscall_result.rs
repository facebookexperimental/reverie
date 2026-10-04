/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Bounded native controls for one physical syscall and returned PKRU.
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::ptr;

use reverie_preload::trap::NativeSyscallResult;
use reverie_preload::trap::raw_syscall6;
use reverie_preload::trap::raw_syscall6_with_pkru;
use reverie_preload::trap::raw_syscall6_with_result;

fn pkru() -> u32 {
    let result: u32;
    unsafe {
        core::arch::asm!("rdpkru", in("ecx") 0_u32, out("eax") result, out("edx") _, options(nostack, nomem, preserves_flags));
    }
    result
}
fn set_pkru(value: u32) {
    unsafe {
        core::arch::asm!("wrpkru", "lfence", in("eax") value, in("ecx") 0_u32, in("edx") 0_u32, options(nostack, preserves_flags));
    }
}
fn native(number: i64, args: [u64; 6]) -> NativeSyscallResult {
    let result: i64;
    let rights: u64;
    // This independent direct instruction never enters the runtime gate. All
    // native cases leave key 0 accessible; returned rights are captured before
    // Rust can make another syscall or touch any other protection key.
    unsafe {
        core::arch::asm!(
            "syscall", "mov r12, rax", "xor ecx, ecx", "rdpkru",
            inlateout("rax") number => rights, in("rdi") args[0], in("rsi") args[1],
            inlateout("rdx") args[2] => _, in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("r12") result, lateout("rcx") _, lateout("r11") _, options(nostack)
        );
    }
    NativeSyscallResult {
        result,
        pkru: Some(rights as u32),
    }
}
fn helper(number: i64, args: [u64; 6], guest: u32) -> NativeSyscallResult {
    let caller = pkru();
    let result = unsafe { raw_syscall6_with_result(number, args, Some(guest)) };
    assert_eq!(
        pkru(),
        caller,
        "caller rights were not restored before Rust returned"
    );
    result
}
fn page() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}
fn map(length: usize) -> *mut u8 {
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED);
    p.cast()
}
fn unmap(p: *mut u8, length: usize) {
    assert_eq!(unsafe { libc::munmap(p.cast(), length) }, 0);
}
fn allocation() {
    for rights in 0..4 {
        let initial = 0x5555_5554;
        set_pkru(initial);
        let expected = native(libc::SYS_pkey_alloc, [0, rights, 0, 0, 0, 0]);
        assert!(
            (1..16).contains(&expected.result),
            "pkey_alloc unavailable: {expected:?}"
        );
        let shift = expected.result as u32 * 2;
        assert_eq!(
            expected.pkru,
            Some((initial & !(3 << shift)) | ((rights as u32) << shift))
        );
        let native_free = native(libc::SYS_pkey_free, [expected.result as u64, 0, 0, 0, 0, 0]);
        assert_eq!(native_free.result, 0);
        set_pkru(0);
        let actual = helper(libc::SYS_pkey_alloc, [0, rights, 0, 0, 0, 0], initial);
        assert_eq!(actual, expected);
        let free = helper(
            libc::SYS_pkey_free,
            [actual.result as u64, 0, 0, 0, 0, 0],
            actual.pkru.unwrap(),
        );
        assert_eq!(
            free,
            NativeSyscallResult {
                result: 0,
                pkru: actual.pkru
            }
        );
        assert_eq!(free, native_free);
        println!(
            "allocation rights={rights} native={expected:?} helper={actual:?} native_free={native_free:?} helper_free={free:?}"
        );
    }
    for args in [[0, 4, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0]] {
        set_pkru(0x5555_5554);
        let expected = native(libc::SYS_pkey_alloc, args);
        set_pkru(0);
        let actual = helper(libc::SYS_pkey_alloc, args, 0x5555_5554);
        assert_eq!(expected.result, -i64::from(libc::EINVAL));
        assert_eq!(actual, expected);
        println!("invalid {args:?} native={expected:?} helper={actual:?}");
    }
}
fn execute_only(partial: bool) {
    let perform = |use_helper: bool| {
        set_pkru(0);
        let bytes = page();
        let p = map(2 * bytes);
        if partial {
            unmap(unsafe { p.add(bytes) }, bytes);
        }
        let args = [
            p as u64,
            (2 * bytes) as u64,
            libc::PROT_EXEC as u64,
            0,
            0,
            0,
        ];
        let result = if use_helper {
            helper(libc::SYS_mprotect, args, 0)
        } else {
            native(libc::SYS_mprotect, args)
        };
        set_pkru(0);
        assert_eq!(
            result.result,
            if partial { -i64::from(libc::ENOMEM) } else { 0 }
        );
        assert_ne!(
            result.pkru,
            Some(0),
            "implicit execute-only key effect was not measured"
        );
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let prefix = format!("{:x}-", p as usize);
        let line = maps.lines().find(|line| line.starts_with(&prefix)).unwrap();
        assert_eq!(
            line.split_whitespace().nth(1),
            Some("--xp"),
            "first VMA effect missing: {line}"
        );
        println!("mprotect helper={use_helper} partial={partial} result={result:?} vma={line}");
        unmap(p, if partial { bytes } else { 2 * bytes });
        result
    };
    let expected = perform(false);
    let actual = perform(true);
    assert_eq!(actual, expected);
}
fn pointers() {
    set_pkru(0);
    let key = unsafe { raw_syscall6(libc::SYS_pkey_alloc, [0; 6]) };
    assert!((1..16).contains(&key), "pkey allocation unavailable: {key}");
    set_pkru(0);
    let p = map(page());
    unsafe {
        p.copy_from_nonoverlapping(b"key".as_ptr(), 3);
    }
    assert_eq!(
        unsafe {
            raw_syscall6(
                libc::SYS_pkey_mprotect,
                [
                    p as u64,
                    page() as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    key as u64,
                    0,
                    0,
                ],
            )
        },
        0
    );
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let denied = 1 << (key as u32 * 2);
    let args = [write.as_raw_fd() as u64, p as u64, 3, 0, 0, 0];
    set_pkru(denied);
    let expected = native(libc::SYS_write, args);
    set_pkru(0);
    let actual = helper(libc::SYS_write, args, denied);
    assert_eq!(actual, expected);
    assert_eq!(actual.result, -i64::from(libc::EFAULT));
    let mut bytes = [0; 3];
    assert_eq!(
        unsafe { libc::read(read.as_raw_fd(), bytes.as_mut_ptr().cast(), 3) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN)
    );
    let permitted = helper(libc::SYS_write, args, 0);
    assert_eq!(
        permitted,
        NativeSyscallResult {
            result: 3,
            pkru: Some(0)
        }
    );
    assert_eq!(
        unsafe { libc::read(read.as_raw_fd(), bytes.as_mut_ptr().cast(), 3) },
        3
    );
    assert_eq!(&bytes, b"key");
    println!(
        "original pointer={p:p} native={expected:?} helper={actual:?} permitted={permitted:?}"
    );
    unmap(p, page());
    assert_eq!(
        unsafe { raw_syscall6(libc::SYS_pkey_free, [key as u64, 0, 0, 0, 0, 0]) },
        0
    );
}
fn six_arguments() {
    set_pkru(0);
    let bytes = page();
    let raw = unsafe { libc::memfd_create(c"native-result".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(
        raw >= 0,
        "memfd_create failed: {}",
        std::io::Error::last_os_error()
    );
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    assert_eq!(
        unsafe { libc::ftruncate(fd.as_raw_fd(), (2 * bytes) as i64) },
        0
    );
    let data = vec![0x73; bytes];
    assert_eq!(
        unsafe { libc::pwrite(fd.as_raw_fd(), data.as_ptr().cast(), bytes, bytes as i64) },
        bytes as isize
    );
    let p = map(bytes);
    unmap(p, bytes);
    let args = [
        p as u64,
        bytes as u64,
        libc::PROT_READ as u64,
        (libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE) as u64,
        fd.as_raw_fd() as u64,
        bytes as u64,
    ];
    let actual = helper(libc::SYS_mmap, args, 0);
    assert_eq!(actual.result, p as i64);
    assert_eq!(actual.pkru, Some(0));
    assert_eq!(unsafe { std::slice::from_raw_parts(p, bytes) }, data);
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let prefix = format!("{:x}-", p as usize);
    let line = maps.lines().find(|line| line.starts_with(&prefix)).unwrap();
    assert_eq!(line.split_whitespace().nth(1), Some("r--s"));
    assert_eq!(
        line.split_whitespace().nth(2),
        Some(format!("{bytes:08x}").as_str())
    );
    println!("six args={args:?} result={actual:?} vma={line}");
    unmap(p, bytes);
}
fn caller_rights() {
    // The guest denies key 0 only inside the register-only gate. Unregister the
    // exact current glibc rseq first, matching the existing native pkey fixture.
    let offset =
        unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_offset".as_ptr()).cast::<isize>() };
    let size = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_size".as_ptr()).cast::<u32>() };
    assert!(!offset.is_null() && !size.is_null());
    assert!(unsafe { *size } <= 32);
    let mut fs = 0_usize;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003, &raw mut fs) },
        0
    );
    let area = fs.wrapping_add_signed(unsafe { *offset }) as *mut libc::c_void;
    let registered = unsafe { *size } != 0;
    if registered {
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_rseq, area, 32, 1, 0x5305_3053_u32) },
            0
        );
    }
    set_pkru(0x5555_5554);
    let expected = unsafe { libc::getpid() } as i64;
    let actual = helper(libc::SYS_getpid, [0; 6], 1);
    assert_eq!(
        actual,
        NativeSyscallResult {
            result: expected,
            pkru: Some(1)
        }
    );
    assert_eq!(pkru(), 0x5555_5554);
    let old = unsafe { raw_syscall6_with_pkru(libc::SYS_getpid, [0; 6], 1) };
    assert_eq!(old, expected);
    assert_eq!(pkru(), 0x5555_5554);
    set_pkru(0);
    if registered {
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_rseq, area, 32, 0, 0x5305_3053_u32) },
            0
        );
    }
    println!("denied guest stack result={actual:?}; original scalar={old}");
}
fn main() {
    let mode = std::env::args().nth(1).expect("native result case");
    if mode == "no-pkru" {
        let result = unsafe { raw_syscall6_with_result(libc::SYS_getpid, [0; 6], None) };
        assert_eq!(
            result,
            NativeSyscallResult {
                result: unsafe { libc::getpid() } as i64,
                pkru: None
            }
        );
        println!("scalar path {result:?}; no capability claim");
        return;
    }
    assert!(
        core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) != 0,
        "OSPKE unavailable: requested hardware case remains unmeasured"
    );
    let original = pkru();
    match mode.as_str() {
        "allocation" => allocation(),
        "mprotect" => execute_only(false),
        "partial-error" => execute_only(true),
        "pointers" => pointers(),
        "six-arguments" => six_arguments(),
        "caller-rights" => caller_rights(),
        _ => panic!("unknown case"),
    }
    set_pkru(original);
}
