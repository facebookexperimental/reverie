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

use reverie::Error;
use reverie::Guest;
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
