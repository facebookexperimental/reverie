/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style license in the repository root LICENSE.
 */

//! A real installed FullTool probe. Also built in the ordinary artifact so
//! its literal fixed-address assertion can demonstrate the failing baseline.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_inguest::trap::raw_syscall6;

const BASE: u64 = 0x5000_0000_0000;
static CALLS: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct FixedGateTool;

#[reverie::tool]
impl Tool for FixedGateTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        CALLS.fetch_add(1, Ordering::Relaxed);
        let private = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
        let forwarded = guest.inject(syscall).await?;
        assert_eq!(forwarded, private);
        Ok(forwarded)
    }
}

unsafe extern "C" {
    fn reverie_inguest_trusted_syscall(
        number: u64,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> i64;
}

fn fixed_addresses() {
    let scalar = reverie_inguest::trap::trusted_gate();
    let guest = reverie_inguest::trap::guest_syscall_gate();
    assert_eq!(scalar.syscall_ip, BASE + 0x80);
    assert_eq!(scalar.return_ip, BASE + 0x82);
    assert_eq!(guest.syscall_ip, BASE + 0x200);
    assert_eq!(guest.return_ip, BASE + 0x202);
    assert_eq!(reverie_inguest::signal::signal_restorer(), BASE + 0x300);
    assert_eq!(
        reverie_inguest::signal::signal_restorer_return_ip(),
        BASE + 0x30b
    );
}

fn guest_getpid() -> i64 {
    let result;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") libc::SYS_getpid => result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn reserve_page() {
    assert_eq!(
        unsafe {
            raw_syscall6(
                libc::SYS_mmap,
                [
                    BASE,
                    4096,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
            )
        },
        BASE as i64
    );
}

fn release_page() {
    assert_eq!(
        unsafe { raw_syscall6(libc::SYS_munmap, [BASE, 4096, 0, 0, 0, 0]) },
        0
    );
}

pub fn collision(path: &Path) {
    reserve_page();
    unsafe {
        (BASE as *mut u64).write_volatile(0x1234_5678_9abc_def0);
    }
    let error = unsafe { reverie_liteinst::install_tool::<FixedGateTool>(path) }.unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EEXIST));
    assert!(!reverie_inguest::trap::fixed_gates_published());
    assert!(!reverie_inguest::trap::has_dispatcher());
    assert_eq!(
        unsafe { (BASE as *const u64).read_volatile() },
        0x1234_5678_9abc_def0
    );
    release_page();
    println!("fixed gate collision: EEXIST original-page=preserved dispatcher=absent");
}

pub fn inherited_filter(path: &Path) {
    let mut instruction = libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    };
    let filter = libc::sock_fprog {
        len: 1,
        filter: &mut instruction,
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &filter) },
        0
    );
    let error = unsafe { reverie_liteinst::install_tool::<FixedGateTool>(path) }.unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert!(!reverie_inguest::trap::fixed_gates_published());
    assert!(!reverie_inguest::trap::has_dispatcher());
    reserve_page();
    release_page();
    println!("fixed gate inherited filter: refused page=absent dispatcher=absent");
}

pub fn install_failure(path: &Path) {
    // The caller supplies a path with no server. Preparation succeeds, then
    // the real coordinator connection fails after irreversible publication.
    let _ = unsafe { reverie_liteinst::install_tool::<FixedGateTool>(path) };
    panic!("a failed published installation resumed the caller");
}

pub fn run(path: &Path) {
    unsafe {
        std::env::set_var(reverie_liteinst::SITE_PATCHING_ENV, "0");
        reverie_liteinst::install_tool::<FixedGateTool>(path).unwrap();
    }
    fixed_addresses();
    let private = unsafe { raw_syscall6(libc::SYS_getpid, [0; 6]) };
    assert_eq!(CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(guest_getpid(), private);
    assert_eq!(CALLS.load(Ordering::Relaxed), 1);
    // The old DSO gate is now an ordinary trapped site. Calling its original
    // public ABI must reach the Tool instead of escaping the fixed filter.
    assert_eq!(
        unsafe { reverie_inguest_trusted_syscall(libc::SYS_getpid as u64, 0, 0, 0, 0, 0, 0) },
        private
    );
    assert_eq!(CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(
        unsafe { raw_syscall6(libc::SYS_close, [u64::MAX, 0, 0, 0, 0, 0]) },
        -i64::from(libc::EBADF)
    );

    let before: [u8; 4096] = unsafe { *(BASE as *const [u8; 4096]) };
    let spare = unsafe {
        raw_syscall6(
            libc::SYS_mmap,
            [
                0,
                4096,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        )
    };
    assert!(spare > 0);
    // A disjoint mapping remains usable through the same physical guest route.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_mprotect, spare, 4096, libc::PROT_READ) },
        0
    );
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_mprotect,
                spare,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        },
        0
    );
    for (number, args) in [
        (
            libc::SYS_mprotect,
            [BASE, 1, libc::PROT_WRITE as u64, 0, 0, 0],
        ),
        (libc::SYS_munmap, [BASE, 1, 0, 0, 0, 0]),
        (
            libc::SYS_madvise,
            [BASE, 1, libc::MADV_DONTNEED as u64, 0, 0, 0],
        ),
        (
            libc::SYS_mmap,
            [
                BASE,
                4096,
                libc::PROT_READ as u64,
                (libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        ),
        (
            libc::SYS_pkey_mprotect,
            [BASE, 1, libc::PROT_READ as u64, 0, 0, 0],
        ),
        (
            libc::SYS_mmap,
            [
                BASE,
                4096,
                libc::PROT_READ as u64,
                (libc::MAP_FIXED_NOREPLACE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                u64::MAX,
                0,
            ],
        ),
        (
            libc::SYS_mremap,
            [BASE, 4096, 8192, libc::MREMAP_MAYMOVE as u64, 0, 0],
        ),
        (
            libc::SYS_mremap,
            [
                spare as u64,
                4096,
                4096,
                (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64,
                BASE,
                0,
            ],
        ),
    ] {
        let result =
            unsafe { libc::syscall(number, args[0], args[1], args[2], args[3], args[4], args[5]) };
        assert_eq!(result, -1, "mapping call {number}");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(unsafe { &*(BASE as *const [u8; 4096]) }, &before);
    }
    let current_break = unsafe { libc::syscall(libc::SYS_brk, 0) };
    assert!(current_break > 0);
    assert_eq!(unsafe { libc::syscall(libc::SYS_brk, BASE) }, current_break);
    assert_eq!(unsafe { libc::syscall(libc::SYS_brk, 0) }, current_break);
    assert_eq!(unsafe { &*(BASE as *const [u8; 4096]) }, &before);
    assert_eq!(unsafe { libc::syscall(libc::SYS_munmap, spare, 4096) }, 0);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        fixed_addresses();
        assert_eq!(guest_getpid(), unsafe {
            raw_syscall6(libc::SYS_getpid, [0; 6])
        });
        assert_eq!(CALLS.load(Ordering::Relaxed), 3);
        unsafe { libc::_exit(0) };
    }
    let mut status = -1;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    assert_eq!(CALLS.load(Ordering::Relaxed), 2);
    println!(
        "fixed FullTool: private=untrapped guest=trapped legacy=trapped errno=EBADF mappings=8-refused outside=usable brk=unchanged fork=inherited restorer=fixed"
    );
}
