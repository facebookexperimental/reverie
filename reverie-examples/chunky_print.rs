/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
use reverie::{
    syscalls::{Addr, MemoryAccess, Syscall},
    Error, GlobalTool, Guest, Tid, Tool,
};
use reverie_util::CommonToolArguments;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Write,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    vec::Vec,
};
use structopt::StructOpt;
use tracing::{debug, info, trace};

/// This tool will chunk together printed output from each thread, over fixed time intervals.

/// How many system calls (in each thread) define an epoch?
const EPOCH: u64 = 10;

#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize, Copy)]
pub enum Which {
    Stderr,
    Stdout,
}

/// Send individual print attepmts (write calls) to the global object:
#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize)]
pub enum Msg {
    /// Route a print over to the tracer to issue.
    Print(Which, Vec<u8>),
    /// Tick the logical clock.
    Tick,
    /// Print all buffered messages, cutting off the epoch early
    Flush,
}

type LogicalTime = u64;

#[derive(Debug, Default)]
struct ChunkyPrintGlobal(Mutex<Inner>);

#[derive(Debug, Default)]
struct Inner {
    times: HashMap<Tid, LogicalTime>,
    printbuf: HashMap<Tid, Vec<(Which, Vec<u8>)>>,
    epoch_num: u64,
}

#[reverie::global_tool]
impl GlobalTool for ChunkyPrintGlobal {
    type Request = Msg;
    type Response = ();
    async fn receive_rpc(&self, from: Tid, m: Msg) {
        let mut mg = self.0.lock().unwrap();
        match m {
            Msg::Print(w, s) => {
                let v = mg.printbuf.entry(from).or_insert_with(Vec::new);
                v.push((w, s));
            }
            Msg::Tick => {
                let ticks = mg.times.entry(from).or_insert(0);
                *ticks += 1;
                mg.check_epoch();
            }
            Msg::Flush => {
                let _ = mg.flush_messages();
            }
        }
    }
}

impl Inner {
    /// Check if the epoch has expired and flush the buffer.
    fn check_epoch(&mut self) {
        if self.times.iter().all(|(_p, t)| (*t > EPOCH)) {
            let _ = self.flush_messages();
            self.times.iter_mut().for_each(|(_, t)| *t -= EPOCH);
            self.epoch_num += 1;
        }
    }

    fn flush_messages(&mut self) -> io::Result<()> {
        let non_empty = self
            .printbuf
            .iter()
            .fold(0, |acc, (_, v)| if v.is_empty() { acc } else { acc + 1 });
        if non_empty > 1 {
            let mut strbuf = String::new();
            for (tid, v) in self.printbuf.iter() {
                let _ = write!(&mut strbuf, "tid {}:{{", tid);
                let mut iter = v.iter();
                if let Some((_, b)) = iter.next() {
                    let _ = write!(&mut strbuf, "{}", b.len());
                    for (_, b) in iter {
                        let _ = write!(&mut strbuf, ", {}", b.len());
                    }
                }
                let _ = write!(&mut strbuf, "}} ");
            }
            info!(
                " [chunky_print] {} threads concurrent output in epoch {}, sizes: {}",
                non_empty, self.epoch_num, strbuf
            );
        } else {
            debug!(
                " [chunky_print] output from {} thread(s) in epoch {}: {} bytes",
                non_empty,
                self.epoch_num,
                self.printbuf
                    .iter()
                    .fold(0, |acc, (_, v)| v.iter().fold(acc, |a, (_, b)| a + b.len()))
            );
        }
        for (tid, v) in self.printbuf.iter_mut() {
            for (w, b) in v.iter() {
                match w {
                    Which::Stdout => {
                        trace!(
                            " [chunky_print] writing {} bytes to stdout from tid {}",
                            b.len(),
                            tid
                        );
                        io::Write::write_all(&mut io::stdout(), b)?;
                    }
                    Which::Stderr => {
                        trace!(
                            " [chunky_print] writing {} bytes to stderr from tid {}",
                            b.len(),
                            tid
                        );
                        io::Write::write_all(&mut io::stderr(), b)?;
                    }
                }
            }
            v.clear();
        }
        io::Write::flush(&mut io::stdout())?;
        io::Write::flush(&mut io::stderr())?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ChunkyPrintLocal {
    stdout_disconnected: AtomicBool,
    stderr_disconnected: AtomicBool,
}

impl Clone for ChunkyPrintLocal {
    fn clone(&self) -> Self {
        ChunkyPrintLocal {
            stdout_disconnected: AtomicBool::new(self.stdout_disconnected.load(Ordering::SeqCst)),
            stderr_disconnected: AtomicBool::new(self.stderr_disconnected.load(Ordering::SeqCst)),
        }
    }
}

fn read_tracee_memory<T: Guest<ChunkyPrintLocal>>(
    guest: &T,
    addr: Addr<u8>,
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; len];
    guest.memory().read_exact(addr, &mut buf)?;
    Ok(buf)
}

#[reverie::tool]
impl Tool for ChunkyPrintLocal {
    type GlobalState = ChunkyPrintGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        let _ = guest.send_rpc(Msg::Tick).await;
        match call {
            // Here we make some attempt to catch redirections:
            Syscall::Dup2(d) => {
                let newfd = d.newfd();
                if newfd == 1 {
                    self.stdout_disconnected.store(true, Ordering::SeqCst);
                }
                if newfd == 2 {
                    self.stderr_disconnected.store(true, Ordering::SeqCst);
                }

                guest.tail_inject(call).await
            }
            Syscall::Write(w) => {
                match w.fd() {
                    1 | 2 => {
                        let which = if w.fd() == 1 {
                            if self.stdout_disconnected.load(Ordering::SeqCst) {
                                debug!(
                                    " [chunky_print] letting through write on redirected stdout, {} bytes.",
                                    w.len()
                                );
                                return guest.tail_inject(call).await;
                            }
                            Which::Stdout
                        } else {
                            if self.stderr_disconnected.load(Ordering::SeqCst) {
                                debug!(
                                    " [chunky_print] letting through write on redirected stderr, {} bytes.",
                                    w.len()
                                );
                                return guest.tail_inject(call).await;
                            }
                            Which::Stderr
                        };

                        let buf = read_tracee_memory(guest, w.buf().unwrap(), w.len())?;
                        let _ = guest.send_rpc(Msg::Print(which, buf)).await;
                        info!(
                            " [chunky_print] suppressed write of {} bytes to fd {}",
                            w.len(),
                            w.fd()
                        );
                        // Suppress the original system call:
                        Ok(w.len() as i64)
                    }
                    _ => guest.tail_inject(call).await,
                }
            }
            _ => guest.tail_inject(call).await,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = CommonToolArguments::from_args();
    let log_guard = args.init_tracing();
    let tracer = reverie_ptrace::TracerBuilder::<ChunkyPrintLocal>::new(args.into())
        .spawn()
        .await?;
    let (status, global_state) = tracer.wait().await?;
    trace!(" [chunky_print] global exit, flushing last messages.");
    let _ = global_state.0.lock().unwrap().flush_messages();
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}
