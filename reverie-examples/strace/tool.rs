/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::Pid;
use reverie::Signal;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Displayable;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;

use crate::config::Config;
use crate::global_state::GlobalState;
use crate::global_state::OutputEvent;

async fn send_output<G: GlobalRPC<GlobalState>>(
    global: &G,
    event: OutputEvent,
) -> Result<(), Error> {
    global.send_rpc(event).await.map_err(|message| {
        std::io::Error::other(format!("Strace controller output failed: {message}")).into()
    })
}

#[cfg(test)]
static HANDLED_SYSCALLS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn take_handled_syscalls() -> usize {
    HANDLED_SYSCALLS.swap(0, Ordering::SeqCst)
}

// Strace has no need for process-level state, so this is a unit struct.
#[derive(Debug, Default, Clone)]
pub struct Strace;

/// Here we use the same dummy type for both our local and global trait
/// implementations.
#[reverie::tool]
impl Tool for Strace {
    type GlobalState = GlobalState;
    type ThreadState = ();

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
        #[cfg(test)]
        HANDLED_SYSCALLS.fetch_add(1, Ordering::SeqCst);
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                let line = format!(
                    "[pid {}] {} = ?",
                    guest.tid().colored(),
                    syscall.display_with_outputs(&guest.memory()),
                );
                send_output(guest, OutputEvent::Syscall(line)).await?;
                guest.tail_inject(syscall).await
            }
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                let tid = guest.tid();

                // must be pre-formatted, otherwise the memory references become
                // invalid when execve/execveat returns success because the original
                // program got wiped out.
                let line = format!(
                    "[pid {}] {}",
                    tid.colored(),
                    syscall.display_with_outputs(&guest.memory())
                );
                send_output(guest, OutputEvent::Syscall(line)).await?;

                let errno = guest.inject(syscall).await.unwrap_err();

                let line = format!(
                    "[pid {}] ({}) = {:?}",
                    tid.colored(),
                    syscall.number(),
                    errno
                );
                send_output(guest, OutputEvent::Syscall(line)).await?;

                Err(errno.into())
            }
            _otherwise => {
                let syscall_ret = guest.inject(syscall).await;
                let line = format!(
                    "[pid {}] {} = {}",
                    guest.tid().colored(),
                    syscall.display_with_outputs(&guest.memory()),
                    // TODO: Pretty print the return value according to its type.
                    syscall_ret.unwrap_or_else(|errno| -errno.into_raw() as i64)
                );
                send_output(guest, OutputEvent::Syscall(line)).await?;
                Ok(syscall_ret?)
            }
        }
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        let line = format!(
            "[pid {}] Received signal: {}",
            guest.tid().colored(),
            signal
        );
        send_output(guest, OutputEvent::Signal(line))
            .await
            .map_err(|_| Errno::EIO)?;
        Ok(Some(signal))
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        global_state: &G,
        _thread_state: Self::ThreadState,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let line = format!(
            "Thread {} exited with status {:?}",
            tid.colored(),
            exit_status
        );
        send_output(global_state, OutputEvent::ThreadExit(line)).await
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let line = format!(
            "Process {} exited with status {:?}",
            pid.colored(),
            exit_status
        );
        send_output(global_state, OutputEvent::ProcessExit(line)).await
    }
}

#[cfg(test)]
mod output_tests {
    use std::future::Future;
    use std::sync::Mutex;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct Endpoint {
        events: Mutex<Vec<OutputEvent>>,
        config: Config,
        fail: bool,
    }

    #[reverie::tool]
    impl GlobalRPC<GlobalState> for Endpoint {
        async fn send_rpc(&self, event: OutputEvent) -> Result<(), String> {
            self.events.lock().unwrap().push(event);
            if self.fail {
                Err("controller stream unavailable".into())
            } else {
                Ok(())
            }
        }

        fn config(&self) -> &Config {
            &self.config
        }
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the recording output endpoint must complete immediately"),
        }
    }

    #[test]
    fn consuming_hooks_report_exact_events_and_propagate_output_failure() {
        let pid = Pid::from_raw(17);
        let tid = Tid::from_raw(19);
        let status = ExitStatus::Exited(23);
        let endpoint = Endpoint::default();
        ready(Strace.on_exit_thread(tid, &endpoint, (), status)).unwrap();
        ready(Strace.on_exit_process(pid, &endpoint, status)).unwrap();
        assert_eq!(
            *endpoint.events.lock().unwrap(),
            [
                OutputEvent::ThreadExit(format!(
                    "Thread {} exited with status {:?}",
                    tid.colored(),
                    status
                )),
                OutputEvent::ProcessExit(format!(
                    "Process {} exited with status {:?}",
                    pid.colored(),
                    status
                )),
            ]
        );

        let failed = Endpoint {
            fail: true,
            ..Endpoint::default()
        };
        for result in [
            ready(Strace.on_exit_thread(tid, &failed, (), status)),
            ready(Strace.on_exit_process(pid, &failed, status)),
        ] {
            let Error::Io(error) = result.unwrap_err() else {
                panic!("output failure must not become a guest syscall errno");
            };
            assert_eq!(
                error.to_string(),
                "Strace controller output failed: controller stream unavailable"
            );
        }
        assert_eq!(failed.events.lock().unwrap().len(), 2);
    }
}
