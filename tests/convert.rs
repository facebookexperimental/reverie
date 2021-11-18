/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![feature(llvm_asm)]

// when we convert syscall, such as open -> openat, the old syscall
// args should not be clobbered, even with the conversion.

use reverie::{syscalls::Syscall, Error, Guest, Tool};
use serde::{Deserialize, Serialize};

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
    #[allow(unused_mut)]
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
