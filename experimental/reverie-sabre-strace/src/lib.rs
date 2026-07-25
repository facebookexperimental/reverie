/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! SaBRe plugin that runs a shared Reverie strace tool.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::Guest;
use reverie::Tool as ReverieTool;
use reverie_sabre as sabre;
use reverie_syscalls::LocalMemory;
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

#[reverie::tool]
impl ReverieTool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let tid = guest.tid();
        if !self.quiet {
            // Debug formatting prints typed scalar fields and pointer addresses but
            // never dereferences guest pointers. This avoids crashing on EFAULT
            // inputs and prevents execve environment contents from leaking.
            let pretty = format!("{syscall:?}");
            nostd_print::eprintln!("[{tid}] {pretty}");
        }
        let result = guest.inject(syscall).await;
        if !self.quiet {
            match result {
                Ok(value) => nostd_print::eprintln!("[{tid}] -> {value}"),
                Err(errno) => nostd_print::eprintln!("[{tid}] -> {errno}"),
            }
        }
        result.map_err(Error::from)
    }
}

struct Plugin {
    adapter: sabre::ReverieAdapter<StraceTool>,
}

#[sabre::tool]
impl sabre::Tool for Plugin {
    type Client = ();

    fn new(_client: Self::Client) -> Self {
        let quiet = std::env::var_os(QUIET_ENV).is_some() || QUIET.load(Ordering::Acquire);
        QUIET.store(quiet, Ordering::Release);
        if quiet {
            std::env::remove_var(QUIET_ENV);
        }

        Self {
            adapter: sabre::ReverieAdapter::new(StraceTool { quiet }, (), ()),
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
