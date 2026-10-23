/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The pass-through recorder: a Reverie tool that injects every syscall
//! unchanged and records its number and result, and the comparable text form
//! of a run. A backend only intercepts and injects, so every backend running
//! it should give a program the results native Linux gives it
//! (`reverie-examples/e2e/`, the cross-backend end-to-end check).
//!
//! The text form is `exit <code>`, then for each thread, in the order the
//! kernel numbered them (thread IDs are increasing), a `thread <n>` line and
//! one `name=outcome` line per syscall, in the thread's order. The outcome is
//! `ok`, an errno name, `?` for a call that does not return (`exit`,
//! `exit_group`; a successful `execve`, which never returns to the caller, is
//! `ok`), or, for the calls in [`EXACT`], the exact return value, which does
//! not depend on addresses, process IDs or time. The calls the vDSO answers
//! ([`VDSO`]) are left out.

use std::collections::BTreeMap;
use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

/// The name the example preload's selector knows the recorder by
/// (`src/lib.rs`), for the in-guest backends.
pub const NAME: &str = "recorder";

/// The syscalls whose exact return value is compared: byte counts, offsets
/// and descriptor numbers, which native Linux gives the same in every run.
pub const EXACT: &[&str] = &[
    "read",
    "write",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "lseek",
    "open",
    "openat",
    "creat",
    "dup",
    "dup2",
    "dup3",
    "readlink",
    "readlinkat",
    "getdents64",
    "fcntl",
];

/// The calls the vDSO answers in the process, which natively mostly never
/// enter the kernel, while reverie-ptrace turns them into syscalls (it
/// disables the vDSO): not compared.
pub const VDSO: &[&str] = &[
    "clock_gettime",
    "clock_getres",
    "gettimeofday",
    "time",
    "getcpu",
];

/// What a syscall returned.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Outcome {
    Value(i64),
    Errno(i32),
    /// It does not return (`exit`, `exit_group`).
    NoReturn,
    /// Recorded before the call (`execve`); replaced if the call returns.
    Pending,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Event {
    pub tid: i32,
    pub sysno: i32,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct Recorded {
    pub events: Mutex<Vec<Event>>,
}

#[reverie::global_tool]
impl GlobalTool for Recorded {
    type Request = Event;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, event: Event) {
        let mut events = self.events.lock().unwrap();
        // A returning `execve` replaces its pending record, the thread's last.
        // (No let chain: SaBRe's plugin includes this file in edition 2021.)
        let pending = (event.outcome != Outcome::Pending)
            .then(|| {
                events
                    .iter_mut()
                    .rev()
                    .find(|e| e.tid == event.tid)
                    .filter(|e| e.outcome == Outcome::Pending && e.sysno == event.sysno)
            })
            .flatten();
        match pending {
            Some(pending) => pending.outcome = event.outcome,
            None => events.push(event),
        }
    }
}

/// The pass-through tool: every syscall goes to the kernel unchanged.
#[derive(Debug, Default, Clone)]
pub struct Recorder;

#[reverie::tool]
impl Tool for Recorder {
    type GlobalState = Recorded;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let tid = guest.tid().as_raw();
        let sysno = syscall.number() as i32;
        let event = |outcome| Event {
            tid,
            sysno,
            outcome,
        };
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                guest.send_rpc(event(Outcome::NoReturn)).await;
                guest.tail_inject(syscall).await
            }
            Syscall::RtSigreturn(_) => {
                // It never returns to its caller: it restores the context the
                // signal interrupted. A backend that runs the tool inside the
                // program (DBT) cannot do that from an injection, so it goes
                // back as the program's own call. Its result is the restored
                // context's, which Linux reports as success.
                guest.send_rpc(event(Outcome::Pending)).await;
                guest.tail_inject(syscall).await
            }
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                // A successful `execve` does not come back here.
                guest.send_rpc(event(Outcome::Pending)).await;
                let errno = guest.inject(syscall).await.unwrap_err();
                guest
                    .send_rpc(event(Outcome::Errno(errno.into_raw())))
                    .await;
                Err(errno.into())
            }
            _ => {
                let result = guest.inject(syscall).await;
                let outcome = match result {
                    Ok(value) => Outcome::Value(value),
                    Err(errno) => Outcome::Errno(errno.into_raw()),
                };
                guest.send_rpc(event(outcome)).await;
                Ok(result?)
            }
        }
    }
}

/// The comparable form of a run.
#[derive(Debug)]
pub struct Report {
    pub exit_code: i32,
    pub threads: Vec<Vec<String>>,
}

impl Report {
    pub fn text(&self) -> String {
        let mut text = format!("exit {}\n", self.exit_code);
        for (number, calls) in self.threads.iter().enumerate() {
            text.push_str(&format!("thread {number}\n"));
            for call in calls {
                text.push_str(call);
                text.push('\n');
            }
        }
        text
    }
}

pub fn errno_name(errno: i32) -> String {
    reverie::syscalls::Errno::new(errno)
        .name()
        .map_or_else(|| format!("E{errno}"), str::to_owned)
}

pub fn outcome_text(name: &str, outcome: Outcome) -> String {
    match outcome {
        Outcome::Value(value) if EXACT.contains(&name) => value.to_string(),
        Outcome::Value(_) | Outcome::Pending => "ok".to_owned(),
        Outcome::Errno(errno) => errno_name(errno),
        Outcome::NoReturn => "?".to_owned(),
    }
}

/// Group `(tid, name, outcome)` by thread, threads in increasing ID order.
pub fn report(exit_code: i32, events: Vec<(i32, String, Outcome)>) -> Report {
    let mut threads: BTreeMap<i32, Vec<String>> = BTreeMap::new();
    for (tid, name, outcome) in events {
        if VDSO.contains(&name.as_str()) {
            continue;
        }
        let text = format!("{name}={}", outcome_text(&name, outcome));
        threads.entry(tid).or_default().push(text);
    }
    Report {
        exit_code,
        threads: threads.into_values().collect(),
    }
}

pub fn reverie_events(events: Vec<Event>) -> Vec<(i32, String, Outcome)> {
    events
        .into_iter()
        .map(|event| {
            let name = Sysno::from(event.sysno).name().to_owned();
            (event.tid, name, event.outcome)
        })
        .collect()
}
