/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A guest that jumps to the untraced `syscall` of Reverie's private page
//! makes a syscall no tool sees, then takes a SIGILL at the `ud2` after it
//! (<https://github.com/rrnewton/reverie/issues/1064>). Reverie used to deliver
//! that SIGILL, so a handler could keep the result and continue, and a forked
//! child could die of it with its effect already made. Now the run ends with
//! the named `UntracedStubSyscall` failure in both cases, while Reverie's own
//! injections, which use the same instruction, keep working.

#![cfg(target_arch = "x86_64")]

use reverie::Error;
use reverie::ExitStatus;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Getpid;
use reverie::syscalls::Syscall;
use reverie_ptrace::UntracedStubSyscall;

/// Passes every syscall through.
#[derive(Debug, Default, Clone)]
struct PassthroughTool;

#[reverie::tool]
impl Tool for PassthroughTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(syscall).await
    }
}

/// Injects an extra `getpid` through the private page before passing each
/// syscall on, so Reverie's own use of the untraced `syscall` runs often.
#[derive(Debug, Default, Clone)]
struct InjectingTool;

#[reverie::tool]
impl Tool for InjectingTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.inject(Getpid::new()).await?;
        guest.tail_inject(syscall).await
    }
}

/// The untraced `syscall` of Reverie's private page (`cp::TRAMPOLINE_BASE`).
const UNTRACED_STUB: u64 = 0x7100_0000;
/// The `ud2` after it.
const AFTER_STUB: u64 = UNTRACED_STUB + 2;

/// Makes `getpid` through the untraced stub. The `ud2` after the `syscall`
/// raises SIGILL, so this never returns.
fn getpid_through_the_stub() -> ! {
    // SAFETY: jumps to Reverie's private page; the guest does not continue
    // past the `ud2` there.
    unsafe {
        std::arch::asm!(
            "jmp {stub}",
            stub = in(reg) UNTRACED_STUB,
            in("rax") libc::SYS_getpid,
            options(noreturn),
        )
    }
}

/// The run's error must be the named failure, at the stub's `ud2`.
fn assert_untraced_stub_refusal(result: Result<(reverie::process::Output, ()), Error>) {
    let error = match result {
        Ok((output, ())) => panic!(
            "the run continued after a syscall through the untraced stub: {:?}",
            output.status
        ),
        Err(error) => error,
    };
    let refusal = match &error {
        Error::Tool(inner) => inner.downcast_ref::<UntracedStubSyscall>(),
        _ => None,
    };
    let refusal = refusal.unwrap_or_else(|| panic!("expected UntracedStubSyscall, got {error:?}"));
    assert_eq!(refusal.address, AFTER_STUB, "{refusal}");
}

/// A guest with a SIGILL handler does not get to run it: the run ends at the
/// stop. Exit status 77 is the handler running, as it did before.
#[test]
fn a_handled_syscall_through_the_untraced_stub_ends_the_run() {
    extern "C" fn on_sigill(_: libc::c_int) {
        // SAFETY: async-signal-safe exit.
        unsafe { libc::_exit(77) };
    }
    let result = reverie_ptrace::testing::test_fn::<PassthroughTool, _>(|| {
        // SAFETY: installs a handler for the SIGILL raised next.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_sigill as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGILL, &action, std::ptr::null_mut()),
                0
            );
        }
        getpid_through_the_stub();
    });
    assert_untraced_stub_refusal(result);
}

/// A forked child that makes the call and dies of the SIGILL ends the whole
/// run. Exit status 0 is the parent carrying on after the child's call, as it
/// did before.
#[test]
fn a_forked_childs_syscall_through_the_untraced_stub_ends_the_run() {
    let result = reverie_ptrace::testing::test_fn::<PassthroughTool, _>(|| {
        // SAFETY: plain fork; the child only jumps to the stub.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork");
        if child == 0 {
            getpid_through_the_stub();
        }
        let mut status = 0;
        // SAFETY: waits for the child forked above.
        unsafe { libc::waitpid(child, &mut status, 0) };
        std::process::exit(0);
    });
    assert_untraced_stub_refusal(result);
}

/// Reverie's own injections use the same untraced `syscall` and are not
/// refused: a tool that injects before every syscall runs a guest to a clean
/// exit.
#[test]
fn reveries_own_injections_through_the_stub_still_run() {
    let (output, ()) = reverie_ptrace::testing::test_fn::<InjectingTool, _>(|| {
        for _ in 0..20 {
            // SAFETY: plain syscalls.
            unsafe {
                libc::getppid();
                libc::getuid();
            }
        }
    })
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0));
}
