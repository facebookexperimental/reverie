/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use serde::Deserialize;
use serde::Serialize;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use structopt::StructOpt;

use reverie::syscalls::Displayable;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie_util::CommonToolArguments;

/// A tool to introduce inject "chaos" into a running process. A pathological
/// kernel is simulated by forcing reads to only return one byte a time.
#[derive(Debug, StructOpt)]
struct Args {
    #[structopt(flatten)]
    common_opts: CommonToolArguments,

    #[structopt(flatten)]
    chaos_opts: ChaosOpts,
}

#[derive(StructOpt, Debug, Serialize, Deserialize, Clone, Default)]
struct ChaosOpts {
    /// Skips the first N syscalls of a process before doing any intervention.
    /// This is useful when you need to skip past an error caused by the tool.
    #[structopt(long, value_name = "N", default_value = "0")]
    skip: u64,

    /// If set, does not intercept `read`-like system calls and modify them.
    #[structopt(long)]
    no_read: bool,

    /// If set, does not intercept `recv`-like system calls and modify them.
    #[structopt(long)]
    no_recv: bool,

    /// If set, does not inject random `EINTR` errors.
    #[structopt(long)]
    no_interrupt: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ChaosTool {
    count: AtomicU64,
}

impl Clone for ChaosTool {
    fn clone(&self) -> Self {
        ChaosTool {
            count: AtomicU64::new(self.count.load(Ordering::SeqCst)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct ChaosToolGlobal {}

#[reverie::global_tool]
impl GlobalTool for ChaosToolGlobal {
    type Config = ChaosOpts;

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

#[reverie::tool]
impl Tool for ChaosTool {
    type ThreadState = bool;
    type GlobalState = ChaosToolGlobal;

    fn new(_pid: Pid, _cfg: &ChaosOpts) -> Self {
        Self {
            count: AtomicU64::new(0),
        }
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let count = self.count.fetch_add(1, Ordering::SeqCst);

        let config = guest.config().clone();
        let memory = guest.memory();

        // This provides a way to wait until the dynamic linker has done its job
        // before we start trying to create chaos. glibc's dynamic linker has a
        // bug where it doesn't retry `read` calls that don't return the
        // expected amount of data.
        if count < config.skip {
            eprintln!(
                "SKIPPED [pid={}, n={}] {}",
                guest.pid(),
                count,
                syscall.display(&memory),
            );

            return guest.tail_inject(syscall).await;
        }

        // Transform the syscall arguments.
        let syscall = match syscall {
            Syscall::Read(read) => {
                if !config.no_interrupt && !*guest.thread_state() {
                    // Return an EINTR instead of running the syscall.
                    // Programs should always retry the read in this case.
                    *guest.thread_state_mut() = true;

                    // XXX: inject a signal like SIGINT?
                    let ret = Err(Errno::ERESTARTSYS);

                    eprintln!(
                        "[pid={}, n={}] {} = {}",
                        guest.pid(),
                        count,
                        syscall.display(&memory),
                        ret.unwrap_or_else(|errno| -errno.into_raw() as i64)
                    );

                    return Ok(ret?);
                } else if !config.no_read {
                    // Reduce read length to 1 byte at most.
                    Syscall::Read(read.with_len(1.min(read.len())))
                } else {
                    // Return syscall unmodified.
                    Syscall::Read(read)
                }
            }
            Syscall::Recvfrom(recv) if !config.no_recv => {
                // Reduce recv length to 1 byte at most.
                Syscall::Recvfrom(recv.with_len(1.min(recv.len())))
            }
            x => {
                eprintln!(
                    "[pid={}, n={}] {}",
                    guest.pid(),
                    count,
                    syscall.display(&memory),
                );
                return guest.tail_inject(x).await;
            }
        };

        *guest.thread_state_mut() = false;

        let ret = guest.inject(syscall).await;

        eprintln!(
            "[pid={}, n={}] {} = {}",
            guest.pid(),
            count,
            syscall.display_with_outputs(&memory),
            ret.unwrap_or_else(|errno| -errno.into_raw() as i64)
        );

        Ok(ret?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::from_args();
    let log_guard = args.common_opts.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<ChaosTool>::new(args.common_opts.into())
        .config(args.chaos_opts)
        .spawn()
        .await?;
    let (status, _) = tracer.wait().await?;
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
