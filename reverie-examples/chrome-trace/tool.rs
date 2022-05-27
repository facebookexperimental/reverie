/*
 * Copyright (c) Meta Platforms, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use crate::event::Event;
use crate::event::Program;
use crate::event::ThreadExit;
use crate::global_state::GlobalState;

use reverie::syscalls::SyscallInfo;
use reverie::{
    syscalls::{Displayable, Syscall},
    Errno, Error, ExitStatus, GlobalRPC, GlobalTool, Guest, Pid, Subscription, Tid, Tool,
};
use serde::{Deserialize, Serialize};

use std::borrow::Cow;
use std::fs;
use std::str;
use std::time::SystemTime;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChromeTrace(Pid);

impl Default for ChromeTrace {
    fn default() -> Self {
        unreachable!("never used")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreadState {
    /// Time stamp when this thread was spawned.
    start: SystemTime,

    /// The events that have occurred on this thread. These will be sent to the
    /// global state upon thread exit.
    events: Vec<Event>,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            start: SystemTime::now(),
            events: Vec::new(),
        }
    }
}

impl ThreadState {
    pub fn push(&mut self, event: Event) {
        self.events.push(event)
    }
}

#[reverie::tool]
impl Tool for ChromeTrace {
    type GlobalState = GlobalState;
    type ThreadState = ThreadState;

    fn new(pid: Pid, _cfg: &<Self::GlobalState as GlobalTool>::Config) -> Self {
        Self(pid)
    }

    fn subscriptions(_cfg: &<Self::GlobalState as GlobalTool>::Config) -> Subscription {
        Subscription::all_syscalls()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                // TODO: Record exits
                guest.tail_inject(syscall).await
            }
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                // TODO: Record failed execs
                guest.tail_inject(syscall).await
            }
            _ => {
                let start = SystemTime::now();

                let result = guest.inject(syscall).await;

                let end = SystemTime::now();

                let sysno = syscall.number();
                let pretty = syscall.display_with_outputs(&guest.memory()).to_string();

                guest.thread_state_mut().push(Event::Syscall {
                    start,
                    end,
                    sysno,
                    pretty,
                    result,
                });

                Ok(result?)
            }
        }
    }

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        let program = fs::read_link(format!("/proc/{}/exe", guest.pid())).unwrap();

        let mut cmdline = fs::read(format!("/proc/{}/cmdline", guest.pid())).unwrap();

        // Shave off the extra NUL terminator at the end so we don't end up with
        // an empty arg at the end.
        assert_eq!(cmdline.pop(), Some(b'\0'));

        let args: Vec<_> = cmdline
            .split(|byte| *byte == 0)
            .map(String::from_utf8_lossy)
            .map(Cow::into_owned)
            .collect();

        guest.thread_state_mut().push(Event::Exec {
            timestamp: SystemTime::now(),
            program: Program::new(program, args),
        });

        Ok(())
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        global_state: &G,
        thread_state: Self::ThreadState,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state
            .send_rpc(ThreadExit {
                pid: self.0,
                tid,
                start: thread_state.start,
                end: SystemTime::now(),
                events: thread_state.events,
                exit_status,
            })
            .await?;

        Ok(())
    }
}
