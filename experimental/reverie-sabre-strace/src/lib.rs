/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe plugin that runs shared Reverie example tools.

mod tools;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::Guest;
use reverie::Tool as ReverieTool;
use reverie_sabre as sabre;
use reverie_syscalls::Displayable;
use reverie_syscalls::LocalMemory;
use reverie_syscalls::MemoryAccess;
use reverie_syscalls::Syscall;
use syscalls::Errno;

// AUTONOMOUS-BOT-IMPLEMENTED
/// Suppress syscall diagnostics while retaining the same shared Tool path.
pub const QUIET_ENV: &str = "REVERIE_SABRE_STRACE_QUIET";
static QUIET: AtomicBool = AtomicBool::new(false);

/// Minimal shared Reverie tool that prints every intercepted syscall.
#[derive(Default)]
pub struct StraceTool {
    quiet: bool,
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-155): Review exec argument decoding and envp redaction.
fn display_exec_redacted<M: MemoryAccess>(syscall: &Syscall, memory: &M) -> Option<String> {
    match syscall {
        // AUTONOMOUS-BOT-IMPLEMENTED
        Syscall::Execve(execve) => {
            let path = execve.path();
            let argv = execve.argv();
            Some(format!(
                "execve({}, {}, <envp redacted>)",
                path.display(memory),
                argv.display(memory)
            ))
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        Syscall::Execveat(execveat) => {
            let path = execveat.path();
            let argv = execveat.argv();
            Some(format!(
                "execveat({}, {}, {}, <envp redacted>, {})",
                execveat.dirfd(),
                path.display(memory),
                argv.display(memory),
                execveat.flags()
            ))
        }
        _ => None,
    }
}

#[reverie::tool]
impl ReverieTool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-153): Review decoded syscall memory access and logging.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if self.quiet {
            return guest.inject(syscall).await.map_err(Error::from);
        }

        let tid = guest.tid();
        match syscall {
            // AUTONOMOUS-BOT-IMPLEMENTED
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                nostd_print::eprintln!("[{tid}] {}", syscall.display(&guest.memory()));
                guest.tail_inject(syscall).await
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                // A successful exec replaces the address space, so format its
                // input pointers while the old image is still readable. Do not
                // log envp because it commonly contains credentials.
                let memory = guest.memory();
                let pretty = display_exec_redacted(&syscall, &memory)
                    .expect("exec match arm must contain an exec syscall");
                nostd_print::eprintln!("[{tid}] {pretty}");
                guest.inject(syscall).await.map_err(Error::from)
            }
            // AUTONOMOUS-BOT-IMPLEMENTED
            _ => {
                let result = guest.inject(syscall).await;
                let memory = guest.memory();
                let syscall = syscall.display_with_outputs(&memory);
                nostd_print::eprintln!("[{tid}] {syscall} = {result:?}");
                result.map_err(Error::from)
            }
        }
    }
}

struct Plugin {
    adapter: tools::SharedAdapter,
}

#[sabre::tool]
impl sabre::Tool for Plugin {
    type Client = ();

    fn new(_client: Self::Client) -> Self {
        let kind = tools::ToolKind::from_environment();
        // SAFETY: Plugin construction runs before SaBRe starts guest callbacks.
        let quiet = unsafe { reverie_sabre::take_private_env(QUIET_ENV) }.is_some()
            || QUIET.load(Ordering::Acquire);
        QUIET.store(quiet, Ordering::Release);

        Self {
            adapter: tools::SharedAdapter::new(kind, quiet),
        }
    }

    fn syscall(&self, syscall: Syscall, _memory: &LocalMemory) -> Result<usize, Errno> {
        self.adapter.handle_syscall(syscall)
    }
    fn syscall_with_inject<F>(
        &self,
        syscall: Syscall,
        _memory: &LocalMemory,
        inject: F,
    ) -> Result<usize, Errno>
    where
        F: FnMut() -> usize + Send + Sync,
    {
        self.adapter.handle_syscall_with_inject(syscall, inject)
    }

    fn on_thread_start(&self, thread_id: u32) {
        self.adapter.handle_thread_start(thread_id);
    }

    fn on_thread_exit(&self, thread_id: u32) {
        self.adapter.handle_thread_exit(thread_id);
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use reverie_syscalls::SyscallArgs;
    use reverie_syscalls::Sysno;

    use super::*;

    #[test]
    fn exec_displays_path_and_argv_without_environment() {
        let path = CString::new("/bin/echo").unwrap();
        let argument = CString::new("visible-argument").unwrap();
        let secret = CString::new("SECRET_TOKEN=do-not-log").unwrap();
        let argv = [path.as_ptr(), argument.as_ptr(), ptr::null()];
        let envp = [secret.as_ptr(), ptr::null()];
        let memory = LocalMemory::new();

        let execve = Syscall::from_raw(
            Sysno::execve,
            SyscallArgs::new(
                path.as_ptr() as usize,
                argv.as_ptr() as usize,
                envp.as_ptr() as usize,
                0,
                0,
                0,
            ),
        );
        let execveat = Syscall::from_raw(
            Sysno::execveat,
            SyscallArgs::new(
                libc::AT_FDCWD as usize,
                path.as_ptr() as usize,
                argv.as_ptr() as usize,
                envp.as_ptr() as usize,
                0,
                0,
            ),
        );

        for syscall in [execve, execveat] {
            let display = display_exec_redacted(&syscall, &memory).unwrap();
            assert!(display.contains("/bin/echo"));
            assert!(display.contains("visible-argument"));
            assert!(display.contains("<envp redacted>"));
            assert!(!display.contains("SECRET_TOKEN"));
            assert!(!display.contains("do-not-log"));
        }
    }
}
