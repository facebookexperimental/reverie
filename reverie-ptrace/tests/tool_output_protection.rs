/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A Tool's output write respects the guest's page protection at every size,
//! as the kernel's own `put_user` does. Before, an eight-byte write went
//! through `PTRACE_POKEDATA` and silently wrote read-only pages, including
//! Reverie's private page (https://github.com/rrnewton/reverie/issues/1064).
//! The same holds for a Tool's stack commit, whose address the guest controls
//! through its stack pointer, and an eight-byte scalar is published entirely
//! or not at all.

use reverie::Error;
use reverie::Guest;
use reverie::Stack;
use reverie::Subscription;
use reverie::Tool;
use reverie::process::ExitStatus;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;

/// Emulates `time(tloc)`: writes the eight-byte result to `tloc` itself, the
/// way a determinizing Tool does, then returns it.
#[derive(Debug, Default, Clone)]
struct EmulatedTime;

const EMULATED_SECONDS: i64 = 1_234_567_890;

#[reverie::tool]
impl Tool for EmulatedTime {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::time].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let Syscall::Time(call) = syscall else {
            return Ok(guest.inject(syscall).await?);
        };
        if let Some(tloc) = call.tloc() {
            guest.memory().write_value(tloc, &EMULATED_SECONDS)?;
        }
        Ok(EMULATED_SECONDS)
    }
}

/// Raw `time(2)`, so the call reaches the tracer rather than the vDSO.
fn raw_time(tloc: *mut i64) -> (i64, i32) {
    let result = unsafe { libc::syscall(libc::SYS_time, tloc) };
    let errno = if result == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    (result, errno)
}

#[test]
fn eight_byte_tool_output_into_a_read_only_page_fails_with_efault() {
    let (output, ()) = test_fn::<EmulatedTime, _>(|| {
        let page = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let slot = page as *mut i64;
        unsafe { slot.write(0x5a5a_5a5a_5a5a_5a5a) };
        assert_eq!(unsafe { libc::mprotect(page, 4096, libc::PROT_READ) }, 0);

        // As the kernel's put_user would: EFAULT, and the page is unchanged.
        assert_eq!(raw_time(slot), (-1, libc::EFAULT));
        assert_eq!(unsafe { slot.read() }, 0x5a5a_5a5a_5a5a_5a5a);

        // Control: a writable output is written.
        assert_eq!(
            unsafe { libc::mprotect(page, 4096, libc::PROT_READ | libc::PROT_WRITE) },
            0
        );
        assert_eq!(raw_time(slot), (EMULATED_SECONDS, 0));
        assert_eq!(unsafe { slot.read() }, EMULATED_SECONDS);
    })
    .expect("run the guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tool_output_into_reverie_private_page_is_refused_and_leaves_it_intact() {
    let (output, ()) = test_fn::<EmulatedTime, _>(|| {
        // Reverie's private page: `syscall; ud2; ...` at 0x7100_0000.
        let stub = 0x7100_0000usize as *const [u8; 4];
        let before = unsafe { stub.read() };
        assert_eq!(before, [0x0f, 0x05, 0x0f, 0x0b]);

        // The eight bytes at 0x7100_0002 would replace the guarding `ud2`.
        assert_eq!(raw_time(0x7100_0002usize as *mut i64), (-1, libc::EFAULT));
        assert_eq!(unsafe { stub.read() }, before);
    })
    .expect("run the guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Two adjacent pages with eight `0xa5` bytes straddling their boundary, the
/// second page read-only. Returns the straddling address.
fn straddling_slot(second_page_prot: libc::c_int) -> *mut i64 {
    let pages = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(pages, libc::MAP_FAILED);
    let slot = unsafe { (pages as *mut u8).add(4096 - 4) } as *mut i64;
    unsafe { slot.write_unaligned(0xa5a5_a5a5_a5a5_a5a5u64 as i64) };
    let second = unsafe { (pages as *mut u8).add(4096) } as *mut libc::c_void;
    assert_eq!(unsafe { libc::mprotect(second, 4096, second_page_prot) }, 0);
    slot
}

#[test]
fn eight_byte_tool_output_straddling_a_read_only_page_writes_nothing() {
    let (output, ()) = test_fn::<EmulatedTime, _>(|| {
        // As the kernel's put_user would: EFAULT, and none of the eight bytes
        // change, not even the four on the writable page.
        let slot = straddling_slot(libc::PROT_READ);
        assert_eq!(raw_time(slot), (-1, libc::EFAULT));
        assert_eq!(
            unsafe { slot.read_unaligned() },
            0xa5a5_a5a5_a5a5_a5a5u64 as i64
        );

        // Control: the same straddling output with both pages writable.
        let slot = straddling_slot(libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(raw_time(slot), (EMULATED_SECONDS, 0));
        assert_eq!(unsafe { slot.read_unaligned() }, EMULATED_SECONDS);
    })
    .expect("run the guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// On `getppid`, pushes one eight-byte word on the guest stack and commits it,
/// as Detcore does for a filtered signal mask, then returns
/// [`STACK_COMMITTED`] or the commit's error.
#[derive(Debug, Default, Clone)]
struct StackPush;

const STACK_WORD: u64 = 0x1122_3344_5566_7788;
const STACK_COMMITTED: i64 = 7;
/// Reverie's stack keeps a 128-byte red zone below the stack pointer, so one
/// pushed word lands at `rsp - 136`.
const PUSHED_WORD_BELOW_RSP: usize = 128 + 8;

#[reverie::tool]
impl Tool for StackPush {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getppid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let Syscall::Getppid(_) = syscall else {
            return Ok(guest.inject(syscall).await?);
        };
        let mut stack = guest.stack().await;
        stack.push(STACK_WORD);
        let _guard = stack.commit()?;
        Ok(STACK_COMMITTED)
    }
}

/// Raw `getppid` issued with the stack pointer set to `rsp`, so the Tool's
/// stack commit targets memory the guest chose. Returns the raw result.
fn getppid_with_stack_pointer(rsp: usize) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "mov {saved}, rsp",
            "mov rsp, {new}",
            "syscall",
            "mov rsp, {saved}",
            saved = out(reg) _,
            new = in(reg) rsp,
            inlateout("rax") libc::SYS_getppid => result,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    result
}

fn pattern_page(prot: libc::c_int) -> *mut u8 {
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    unsafe { std::ptr::write_bytes(page as *mut u8, 0x5a, 4096) };
    assert_eq!(unsafe { libc::mprotect(page, 4096, prot) }, 0);
    page as *mut u8
}

#[test]
fn eight_byte_stack_commit_respects_protection_and_the_private_page() {
    let (output, ()) = test_fn::<StackPush, _>(|| {
        let efault = -(libc::EFAULT as i64);

        // An executable, read-only page: the commit fails, nothing changes.
        let code = pattern_page(libc::PROT_READ | libc::PROT_EXEC);
        let target = unsafe { code.add(8) } as *const u64;
        let rsp = target as usize + PUSHED_WORD_BELOW_RSP;
        assert_eq!(getppid_with_stack_pointer(rsp), efault);
        assert_eq!(unsafe { target.read() }, 0x5a5a_5a5a_5a5a_5a5a);

        // Reverie's private page: the word would replace the guarding `ud2`.
        let stub = 0x7100_0000usize as *const [u8; 16];
        let before = unsafe { stub.read() };
        assert_eq!(&before[..4], &[0x0f, 0x05, 0x0f, 0x0b]);
        assert_eq!(
            getppid_with_stack_pointer(0x7100_0002 + PUSHED_WORD_BELOW_RSP),
            efault
        );
        assert_eq!(unsafe { stub.read() }, before);

        // Control: a writable stack target receives the word.
        let data = pattern_page(libc::PROT_READ | libc::PROT_WRITE);
        let target = unsafe { data.add(8) } as *const u64;
        let rsp = target as usize + PUSHED_WORD_BELOW_RSP;
        assert_eq!(getppid_with_stack_pointer(rsp), STACK_COMMITTED);
        assert_eq!(unsafe { target.read() }, STACK_WORD);
    })
    .expect("run the guest");
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
