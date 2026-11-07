/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! The actual native Tool over the shared fixture protocol.
//! No native callback, terminal fact, or activation frame is manufactured here.

use std::io::Write;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use super::lifecycle::raw_call;
use super::protocol::Config;
use super::protocol::DisconnectPoint;
use super::protocol::Event;
use super::protocol::LifecycleGlobal;
use super::protocol::Mode;
use super::protocol::Reply;
use super::protocol::Request;

pub const MARKER_COOKIE: u64 = 0x4341_4c4c;

static SELECTIONS: AtomicUsize = AtomicUsize::new(0);
static CONSTRUCTORS: AtomicUsize = AtomicUsize::new(0);
static CONFIGURATION_ADDRESS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default, Serialize, Deserialize)]
pub struct ThreadState {
    tid: i32,
    stamp: u64,
    continued: bool,
}

pub struct LifecycleTool {
    pid: Pid,
    config: Config,
    config_address: usize,
    attempts: AtomicUsize,
    drops: AtomicUsize,
    messages: AtomicUsize,
    thread_exits: AtomicUsize,
}

impl Default for LifecycleTool {
    fn default() -> Self {
        panic!("LifecycleTool requires its actual PID and received configuration");
    }
}

struct Attempt<'a>(&'a AtomicUsize);

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl LifecycleTool {
    fn witness(config: &Config, pid: Pid, event: &str, create: bool) {
        if config.mode != Mode::NoApplicationRpc {
            return;
        }
        let path = config.witness.as_ref().expect("explicit witness path");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .append(!create)
            .create_new(create)
            .open(path)
            .expect("fixture witness must be writable exactly once at construction");
        writeln!(file, "{} {} {event}", pid.as_raw(), config.nonce).unwrap();
        file.flush().unwrap();
    }

    fn check_config(&self, config: &Config) {
        assert_eq!(config, &self.config);
        assert_eq!(config as *const Config as usize, self.config_address);
    }

    async fn report<R: GlobalRPC<LifecycleGlobal>>(&self, rpc: &R, event: Event) {
        self.check_config(rpc.config());
        if self.config.mode == Mode::NoApplicationRpc {
            assert_eq!(self.messages.load(Ordering::SeqCst), 0);
            Self::witness(&self.config, self.pid, &format!("{event:?}"), false);
            return;
        }
        let sequence = self.messages.fetch_add(1, Ordering::SeqCst) + 1;
        let reply = rpc
            .send_rpc(Request {
                config: self.config.clone(),
                event,
            })
            .await;
        assert_eq!(
            reply,
            Reply {
                nonce: self.config.nonce,
                sequence,
            }
        );
    }
}

#[reverie::tool]
impl Tool for LifecycleTool {
    type GlobalState = LifecycleGlobal;
    type ThreadState = ThreadState;

    fn subscriptions(config: &Config) -> Subscription {
        config.validate();
        assert_eq!(SELECTIONS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(CONSTRUCTORS.load(Ordering::SeqCst), 0);
        assert_eq!(
            CONFIGURATION_ADDRESS.swap(config as *const Config as usize, Ordering::SeqCst),
            0
        );
        let mut subscriptions = Subscription::none();
        if config.mode == Mode::NoApplicationRpc {
            return subscriptions;
        }
        subscriptions.syscall(Sysno::getppid);
        match config.mode {
            Mode::OriginalExit => {}
            Mode::RewriteToTerminal | Mode::RpcDisconnect => {
                subscriptions.syscall(Sysno::getpid);
            }
            _ => {
                subscriptions.syscall(config.terminal.number());
            }
        }
        subscriptions
    }

    fn new(pid: Pid, config: &Config) -> Self {
        config.validate();
        assert!(pid.as_raw() > 0);
        assert_eq!(SELECTIONS.load(Ordering::SeqCst), 1);
        assert_eq!(CONSTRUCTORS.fetch_add(1, Ordering::SeqCst), 0);
        assert_eq!(
            CONFIGURATION_ADDRESS.load(Ordering::SeqCst),
            config as *const Config as usize
        );
        if config.mode == Mode::NoApplicationRpc {
            assert_eq!(pid.as_raw() as u32, std::process::id());
        }
        Self::witness(config, pid, "Constructed selections=1", true);
        Self {
            pid,
            config: config.clone(),
            config_address: config as *const Config as usize,
            attempts: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            messages: AtomicUsize::new(0),
            thread_exits: AtomicUsize::new(0),
        }
    }

    fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &ThreadState)>) -> ThreadState {
        assert_eq!(tid, self.pid);
        assert!(parent.is_none());
        Self::witness(&self.config, tid, "ThreadState", false);
        ThreadState {
            tid: tid.as_raw(),
            stamp: self.config.nonce,
            continued: false,
        }
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        assert_eq!(guest.pid(), self.pid);
        assert_eq!(guest.tid(), self.pid);
        assert_eq!(guest.ppid(), None);
        assert_eq!(guest.thread_state().tid, self.pid.as_raw());
        assert_eq!(guest.thread_state().stamp, self.config.nonce);
        self.report(guest, Event::StartHook).await;
        guest.thread_state_mut().stamp += 1;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        assert_eq!(guest.thread_state().stamp, self.config.nonce + 1);
        self.report(guest, Event::PostExecHook).await;
        guest.thread_state_mut().stamp += 2;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        self.check_config(guest.config());
        assert_eq!(guest.pid(), self.pid);
        assert_eq!(guest.tid(), self.pid);
        if self.config.mode == Mode::RpcDisconnect {
            assert_eq!(syscall.number(), Sysno::getpid);
            assert_eq!(raw_call(syscall).args, self.config.args);
            let point = self.config.disconnect;
            if point == DisconnectPoint::Sync {
                let sequence = self.messages.fetch_add(1, Ordering::SeqCst) + 1;
                let request = Request {
                    config: self.config.clone(),
                    event: Event::Disconnect { point },
                };
                // An unsupported sync method is not a transport failure and
                // must not silently switch to the async method for this case.
                let reply = guest.try_send_rpc_sync(request).map_err(|_| {
                    Error::Io(std::io::Error::other(
                        "fixture requires actual synchronous RPC",
                    ))
                })?;
                assert_eq!(
                    reply,
                    Reply {
                        nonce: self.config.nonce,
                        sequence
                    }
                );
            } else {
                assert!(matches!(
                    point,
                    DisconnectPoint::Async | DisconnectPoint::AsyncControllerPanic
                ));
                self.report(guest, Event::Disconnect { point }).await;
            }
            // A wrongly returned response lets the guest print an unexpected
            // continuation. The native fatal path must never reach this value.
            return Ok(self.config.nonce as i64);
        }
        if syscall.number() == Sysno::getppid {
            assert!(self.config.mode.continues());
            assert!(!guest.thread_state().continued);
            assert_eq!(self.attempts.load(Ordering::SeqCst), 1);
            assert_eq!(self.drops.load(Ordering::SeqCst), 1);
            let observed = raw_call(syscall);
            let value = if self.config.mode == Mode::SuppressOnce {
                0
            } else {
                i64::from(self.pid.as_raw())
            };
            assert_eq!(observed.args, [MARKER_COOKIE, value as u64, 3, 4, 5, 6]);
            self.report(guest, Event::Continued { result: value }).await;
            guest.thread_state_mut().continued = true;
            guest.thread_state_mut().stamp += 8;
            return Ok(self.config.nonce as i64);
        }

        assert_ne!(self.config.mode, Mode::OriginalExit);
        assert_eq!(syscall, self.config.trigger_call());
        assert_eq!(self.attempts.fetch_add(1, Ordering::SeqCst), 0);
        let _attempt = Attempt(&self.drops);
        guest.thread_state_mut().stamp += 4;
        let replacement = self.config.replacement();
        self.report(
            guest,
            Event::Attempt {
                observed: raw_call(syscall),
                requested_replacement: replacement.map(raw_call),
            },
        )
        .await;
        match replacement {
            Some(replacement) => guest.tail_inject(replacement).await,
            None => Ok(0),
        }
    }

    async fn on_exit_thread<R: GlobalRPC<LifecycleGlobal>>(
        &self,
        tid: Pid,
        rpc: &R,
        state: ThreadState,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(tid, self.pid);
        assert_eq!(state.tid, tid.as_raw());
        assert_eq!(self.thread_exits.fetch_add(1, Ordering::SeqCst), 0);
        let expected_attempts = usize::from(self.config.mode.has_terminal_attempt());
        let attempts = self.attempts.load(Ordering::SeqCst);
        let drops = self.drops.load(Ordering::SeqCst);
        assert_eq!(attempts, expected_attempts);
        assert_eq!(
            drops, attempts,
            "Tool future still borrowed at consuming hook"
        );
        assert_eq!(state.continued, self.config.mode.continues());
        assert_eq!(
            state.stamp,
            self.config.nonce + 3 + 4 * attempts as u64 + 8 * u64::from(state.continued)
        );
        assert_eq!(status, ExitStatus::Exited(self.config.exit_code()));
        self.report(
            rpc,
            Event::ThreadExit {
                code: status.code().expect("normal explicit exit"),
                attempts,
                drops,
                continued: state.continued,
            },
        )
        .await;
        Ok(())
    }

    async fn on_exit_process<R: GlobalRPC<LifecycleGlobal>>(
        self,
        pid: Pid,
        rpc: &R,
        status: ExitStatus,
    ) -> Result<(), Error> {
        assert_eq!(pid, self.pid);
        assert_eq!(self.thread_exits.load(Ordering::SeqCst), 1);
        assert_eq!(status, ExitStatus::Exited(self.config.exit_code()));
        self.report(
            rpc,
            Event::ProcessExit {
                code: status.code().expect("normal explicit exit"),
            },
        )
        .await;
        Ok(())
    }
}
