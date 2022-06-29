/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::config::Config;
use crate::global_state::GlobalState;

use reverie::syscalls::{Displayable, Errno, Syscall, SyscallInfo};
use reverie::{Error, ExitStatus, GlobalRPC, Guest, Pid, Signal, Subscription, Tid, Tool};

use serde::{Deserialize, Serialize};

// Strace has no need for process-level state, so this is a unit struct.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Strace;

/// Here we use the same dummy type for both our local and global trait
/// implementations.
#[reverie::tool]
impl Tool for Strace {
    type GlobalState = GlobalState;

    fn subscriptions(cfg: &Config) -> Subscription {
        // Check if we're only excluding things.
        let exclude_only = cfg.filters.iter().all(|f| f.inverse);

        let mut subs = if exclude_only {
            // Only excluding syscalls.
            Subscription::all_syscalls()
        } else {
            // Only including syscalls.
            Subscription::none()
        };

        for filter in &cfg.filters {
            let syscalls = filter.syscalls.iter().copied();
            if filter.inverse {
                subs.disable_syscalls(syscalls);
            } else {
                subs.syscalls(syscalls);
            }
        }

        subs
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                eprintln!(
                    "[pid {}] {} = ?",
                    guest.tid().colored(),
                    syscall.display_with_outputs(&guest.memory()),
                );
                guest.tail_inject(syscall).await
            }
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                let tid = guest.tid();

                // must be pre-formatted, otherwise the memory references become
                // invalid when execve/execveat returns success because the original
                // program got wiped out.
                eprintln!(
                    "[pid {}] {}",
                    tid.colored(),
                    syscall.display_with_outputs(&guest.memory())
                );

                let errno = guest.inject(syscall).await.unwrap_err();

                eprintln!(
                    "[pid {}] ({}) = {:?}",
                    tid.colored(),
                    syscall.number(),
                    errno
                );

                Err(errno.into())
            }
            _otherwise => {
                let syscall_ret = guest.inject(syscall).await;
                eprintln!(
                    "[pid {}] {} = {}",
                    guest.tid().colored(),
                    syscall.display_with_outputs(&guest.memory()),
                    // TODO: Pretty print the return value according to its type.
                    syscall_ret.unwrap_or_else(|errno| -errno.into_raw() as i64)
                );
                Ok(syscall_ret?)
            }
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        eprintln!(
            "[pid {}] Received signal: {}",
            guest.tid().colored(),
            signal
        );
        Ok(Some(signal))
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!(
            "Thread {} exited with status {:?}",
            tid.colored(),
            exit_status
        );
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        _global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!(
            "Process {} exited with status {:?}",
            pid.colored(),
            exit_status
        );
        Ok(())
    }
}
