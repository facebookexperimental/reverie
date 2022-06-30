/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![cfg_attr(feature = "llvm_asm", feature(llvm_asm))]

// when we convert syscall, such as open -> openat, the old syscall
// args should not be clobbered, even with the conversion.

use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalStateTailInject;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct LocalStateInject;

#[reverie::tool]
impl Tool for LocalStateTailInject {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Open(open_syscall) => {
                guest
                    .tail_inject(reverie::syscalls::Openat::from(open_syscall))
                    .await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[reverie::tool]
impl Tool for LocalStateInject {
    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Open(open_syscall) => Ok(guest
                .inject(reverie::syscalls::Openat::from(open_syscall))
                .await?),
            _ => guest.tail_inject(syscall).await,
        }
    }
}

#[cfg(all(not(sanitized), test))]
mod tests {
    use super::*;
    use nix::unistd;
    use reverie_ptrace::testing::check_fn;

    #[cfg(target_arch = "x86_64")]
    #[cfg(not(feature = "llvm_asm"))]
    #[allow(unused_mut)]
    unsafe fn open_syscall_sanity_check() -> i32 {
        let path = b"/dev/null\0".as_ptr() as usize;
        let flags: usize = 0x8000; // O_LARGEFILE
        let mode: usize = 0o644;

        let mut ret: usize;

        // // The following asm block does this:
        // let ret = open("/dev/null", 0x8000, 0644);
        // if ret >= -4095 as u64 { exit_group(1) }
        // // Sanity check input registers to ensure they didn't change.
        // if %rsi != 0x8000 { exit_group(1) }
        // if %rdx != 0644 { exit_roup(1) }
        // return fd
        core::arch::asm!(
            "mov r8, rdi",
            // Set syscall to `SYS_open`
            "mov rax, 2",
            "syscall",
            // if (ret >= -4095 as u64) goto 1
            "cmp rax, 0xfffffffffffff001",
            "jae 2f",
            // if (rax != r8) goto label1;
            "cmp r8, rdi",
            "jne 2f",
            // if (rsi != 0x8000) goto label1;
            "cmp rsi, 0x8000",
            "jne 2f",
            // if (rdx != 0644) goto label1;
            "cmp rdx, 0x1a4",
            "jne 2f",
            // Otherwise, we're successful.
            "jmp 3f",
            "2:",
            // Set syscall arg1 to label1
            "mov rdi, 0x1",
            // Set syscall to SYS_exit_group
            "mov rax, 231",
            // Do the syscall
            "syscall",
            "3:",
            lateout("rax") ret,
            in("rdi") path,
            in("rsi") flags,
            in("rdx") mode,
            out("r8") _, // Clobbered
            out("rcx") _, // rcx is used to store old rip
            out("r11") _, // r11 is used to store old rflags
        );

        ret as i32
    }

    #[cfg(target_arch = "x86_64")]
    #[cfg(feature = "llvm_asm")]
    #[allow(unused_mut)]
    #[allow(deprecated)]
    unsafe fn open_syscall_sanity_check() -> i32 {
        let mut ret;
        let path = b"/dev/null\0";
        llvm_asm!(r#"movq %rdi, %r8
                    movq $$0x8000, %rsi # O_LARGEFILE
                    movq $$0x1a4, %rdx  # 0644
                    mov $$2, %eax
                    syscall
                    cmp $$0xfffffffffffff001,%rax
                    jae 1f
                    cmp %rdi, %r8
                    jne 1f
                    cmp $$0x8000, %rsi
                    jne 1f
                    cmp $$0x1a4, %rdx
                    jne 1f
                    jmp 2f
                1:mov $$1, %rdi
                    mov $$231, %rax # call exit_group(1)
                    syscall
                2:
                "#
                :"={rax}"(ret)
                :"{rdi}"(path.as_ptr() as u64)
                :"rcx", "r11", "memory");
        ret
    }

    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn open_syscall_sanity_check() -> i32 {
        unimplemented!()
    }

    #[test]
    fn open_into_openat_tail_inject_test() {
        check_fn::<LocalStateTailInject, _>(move || {
            let fd = unsafe { open_syscall_sanity_check() };
            assert!(unistd::close(fd).is_ok());
        })
    }

    #[test]
    fn open_into_openat_inject_test() {
        check_fn::<LocalStateInject, _>(move || {
            let fd = unsafe { open_syscall_sanity_check() };
            assert!(unistd::close(fd).is_ok());
        })
    }
}
