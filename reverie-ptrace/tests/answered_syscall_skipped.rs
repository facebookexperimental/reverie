/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A syscall that the Tool answers itself, without injecting it, never runs:
//! Reverie skips it at its seccomp stop. On x86_64 the skip writes -1 to
//! `orig_rax`; on aarch64 it must write the kernel's own syscall number
//! (`NT_ARM_SYSTEM_CALL`), since writing x8 there changes nothing the kernel
//! reads. The guest's `mkdirat` is answered with 0, so the directory must not
//! exist afterwards, while the guest sees the Tool's 0.

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

/// Answers every `mkdirat` with 0 without running it.
#[derive(Debug, Default, Clone)]
struct AnsweringTool;

#[reverie::tool]
impl Tool for AnsweringTool {
    type GlobalState = ();
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::mkdirat].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::mkdirat);
        Ok(0)
    }
}

#[test]
fn an_answered_syscall_is_skipped() {
    let path = std::env::temp_dir().join(format!(
        "reverie-answered-mkdirat-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    reverie_ptrace::testing::check_fn::<AnsweringTool, _>(move || {
        // SAFETY: a NUL-terminated path; mkdirat touches no other memory.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_mkdirat,
                libc::AT_FDCWD,
                c_path.as_ptr(),
                0o755 as libc::c_long,
            )
        };
        assert_eq!(ret, 0, "the guest sees the Tool's answer");
    });
    let ran = path.exists();
    let _ = std::fs::remove_dir(&path);
    assert!(!ran, "the answered mkdirat ran: {} exists", path.display());
}
