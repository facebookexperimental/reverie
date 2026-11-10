/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Backend-neutral implementation of the counter2 Reverie tool.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;
use tracing::debug;

/// Global counter2 totals.
#[derive(Debug, Default)]
pub struct GlobalInner {
    pub total_syscalls: u64,
    pub exited_procs: u64,
    pub exited_threads: u64,
}

#[derive(Debug, Default)]
pub struct CounterGlobal {
    pub inner: Mutex<GlobalInner>,
}

impl CounterGlobal {
    /// Returns process-tree syscall, process, and thread totals.
    #[allow(dead_code)]
    pub fn totals(&self) -> (u64, u64, u64) {
        let state = self.inner.lock().unwrap();
        (
            state.total_syscalls,
            state.exited_procs,
            state.exited_threads,
        )
    }
}

/// Local, per-process state for counter2.
#[derive(Debug, Default)]
pub struct CounterLocal {
    proc_syscalls: AtomicU64,
    exited_threads: AtomicU64,
    thread_exit_reporter: Option<fn(Tid, u64)>,
}

impl CounterLocal {
    /// Selects where this backend writes the existing thread-exit diagnostic.
    ///
    /// Injected backends must use their runtime output path because the guest
    /// may close its own stderr before the lifecycle callback runs.
    #[allow(dead_code)]
    pub fn with_thread_exit_reporter(mut self, reporter: fn(Tid, u64)) -> Self {
        self.thread_exit_reporter = Some(reporter);
        self
    }

    /// Returns the process-local syscall and exited-thread totals.
    #[allow(dead_code)]
    pub fn process_totals(&self) -> (u64, u64) {
        (
            self.proc_syscalls.load(Ordering::SeqCst),
            self.exited_threads.load(Ordering::SeqCst),
        )
    }
}

impl Clone for CounterLocal {
    fn clone(&self) -> Self {
        CounterLocal {
            proc_syscalls: AtomicU64::new(self.proc_syscalls.load(Ordering::SeqCst)),
            exited_threads: AtomicU64::new(self.exited_threads.load(Ordering::SeqCst)),
            thread_exit_reporter: self.thread_exit_reporter,
        }
    }
}

/// Process-exit contribution to the global counter2 state.
#[derive(PartialEq, Debug, Eq, Hash, Clone, Serialize, Deserialize, Copy)]
pub struct IncrMsg(pub u64, pub u64);

/// Reports a consumed thread or contributes a completed process's totals.
#[derive(PartialEq, Debug, Eq, Clone, Serialize, Deserialize)]
pub enum CounterRequest {
    ThreadReport { tid: Tid, syscalls: u64 },
    ProcessExit(IncrMsg),
}

/// The output operation that failed before a report could be acknowledged.
#[derive(PartialEq, Debug, Eq, Clone, Serialize, Deserialize)]
pub enum CounterOutputError {
    Write(String),
    Flush(String),
}

impl CounterOutputError {
    fn into_error(self) -> Error {
        let (operation, message) = match self {
            Self::Write(message) => ("write", message),
            Self::Flush(message) => ("flush", message),
        };
        std::io::Error::other(format!("Counter2 report {operation} failed: {message}")).into()
    }
}

fn write_thread_report(
    writer: &mut impl Write,
    tid: Tid,
    syscalls: u64,
) -> Result<(), CounterOutputError> {
    let line = format!("counter2-local thread={tid} syscalls={syscalls}\n");
    writer
        .write_all(line.as_bytes())
        .map_err(|error| CounterOutputError::Write(error.to_string()))?;
    writer
        .flush()
        .map_err(|error| CounterOutputError::Flush(error.to_string()))
}

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = CounterRequest;
    type Response = Result<(), CounterOutputError>;
    type Config = ();

    async fn init_global_state(_: &Self::Config) -> Self {
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, request: Self::Request) -> Self::Response {
        match request {
            CounterRequest::ThreadReport { tid, syscalls } => {
                // The GlobalState owner completes output before acknowledging.
                // A report does not also contribute to the process-tree totals.
                write_thread_report(&mut std::io::stderr().lock(), tid, syscalls)
            }
            CounterRequest::ProcessExit(IncrMsg(n, t)) => {
                let mut state = self.inner.lock().unwrap();
                state.total_syscalls += n;
                state.exited_threads += t;
                state.exited_procs += 1;
                Ok(())
            }
        }
    }
}

#[reverie::tool]
impl Tool for CounterLocal {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    fn new(pid: Pid, _cfg: &()) -> Self {
        debug!(" [counter] initialize counter for pid {}", pid);
        Self::default()
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        call: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        debug!(
            "thread count at syscall ({:?}): {}, process count: {}",
            call.number(),
            guest.thread_state(),
            self.proc_syscalls.load(Ordering::SeqCst)
        );
        guest.tail_inject(call).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Tid,
        global_state: &G,
        thread_syscalls: u64,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        debug!("count at exit thread {} = {}", tid, thread_syscalls);
        self.proc_syscalls
            .fetch_add(thread_syscalls, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        if let Some(report) = self.thread_exit_reporter {
            report(tid, thread_syscalls);
        } else {
            global_state
                .send_rpc(CounterRequest::ThreadReport {
                    tid,
                    syscalls: thread_syscalls,
                })
                .await
                .map_err(CounterOutputError::into_error)?;
        }
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let count = self.proc_syscalls.load(Ordering::SeqCst);
        let threads = self.exited_threads.load(Ordering::SeqCst);
        debug!(
            "At ExitProc (pid {}), contributing {} to global count.",
            pid, count
        );
        global_state
            .send_rpc(CounterRequest::ProcessExit(IncrMsg(count, threads)))
            .await
            .map_err(CounterOutputError::into_error)
    }
}

#[cfg(test)]
mod output_tests {
    use std::future::Future;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;

    use super::*;

    #[derive(Default)]
    struct Output {
        bytes: Vec<u8>,
        flushes: usize,
        fail_write: bool,
        fail_flush: bool,
    }

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::other("stream unavailable"));
            }
            // Force write_all to complete several short writes.
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                Err(std::io::Error::other("flush unavailable"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn report_is_complete_and_flushed_before_acknowledgement() {
        let mut output = Output::default();
        write_thread_report(&mut output, Tid::from_raw(41), 17).unwrap();
        assert_eq!(output.bytes, b"counter2-local thread=41 syscalls=17\n");
        assert_eq!(output.flushes, 1);
    }

    #[test]
    fn report_write_and_flush_failures_are_distinct() {
        let mut output = Output {
            fail_write: true,
            ..Output::default()
        };
        assert_eq!(
            write_thread_report(&mut output, Tid::from_raw(41), 17),
            Err(CounterOutputError::Write("stream unavailable".into()))
        );
        assert!(output.bytes.is_empty());
        assert_eq!(output.flushes, 0);

        let mut output = Output {
            fail_flush: true,
            ..Output::default()
        };
        assert_eq!(
            write_thread_report(&mut output, Tid::from_raw(41), 17),
            Err(CounterOutputError::Flush("flush unavailable".into()))
        );
        assert_eq!(output.bytes, b"counter2-local thread=41 syscalls=17\n");
        assert_eq!(output.flushes, 1);
    }

    #[derive(Default)]
    struct Endpoint {
        requests: Mutex<Vec<CounterRequest>>,
        global: CounterGlobal,
        failure: Option<CounterOutputError>,
    }

    #[reverie::tool]
    impl GlobalRPC<CounterGlobal> for Endpoint {
        async fn send_rpc(&self, request: CounterRequest) -> Result<(), CounterOutputError> {
            self.requests.lock().unwrap().push(request.clone());
            match &self.failure {
                Some(error) => Err(error.clone()),
                None => self.global.receive_rpc(Pid::from_raw(41), request).await,
            }
        }

        fn config(&self) -> &() {
            &()
        }
    }

    fn ready<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the recording endpoint must complete immediately"),
        }
    }

    #[test]
    fn default_report_precedes_single_process_contribution_without_double_count() {
        let tool = CounterLocal::default();
        let endpoint = Endpoint::default();
        let tid = Tid::from_raw(41);
        ready(tool.on_exit_thread(tid, &endpoint, 17, ExitStatus::SUCCESS)).unwrap();
        assert_eq!(tool.process_totals(), (17, 1));
        assert_eq!(endpoint.global.totals(), (0, 0, 0));
        ready(tool.on_exit_process(tid, &endpoint, ExitStatus::SUCCESS)).unwrap();
        assert_eq!(endpoint.global.totals(), (17, 1, 1));
        assert_eq!(
            *endpoint.requests.lock().unwrap(),
            [
                CounterRequest::ThreadReport { tid, syscalls: 17 },
                CounterRequest::ProcessExit(IncrMsg(17, 1)),
            ]
        );
    }

    #[test]
    fn both_consuming_hooks_propagate_structured_output_failure() {
        for (failure, message) in [
            (
                CounterOutputError::Write("stream unavailable".into()),
                "Counter2 report write failed: stream unavailable",
            ),
            (
                CounterOutputError::Flush("flush unavailable".into()),
                "Counter2 report flush failed: flush unavailable",
            ),
        ] {
            let endpoint = Endpoint {
                failure: Some(failure),
                ..Endpoint::default()
            };
            let tool = CounterLocal::default();
            let tid = Tid::from_raw(41);
            for result in [
                ready(tool.on_exit_thread(tid, &endpoint, 17, ExitStatus::SUCCESS)),
                ready(tool.on_exit_process(tid, &endpoint, ExitStatus::SUCCESS)),
            ] {
                let Error::Io(error) = result.unwrap_err() else {
                    panic!("report failure must not become a guest syscall errno");
                };
                assert_eq!(error.to_string(), message);
            }
            assert_eq!(endpoint.global.totals(), (0, 0, 0));
            assert_eq!(
                *endpoint.requests.lock().unwrap(),
                [
                    CounterRequest::ThreadReport { tid, syscalls: 17 },
                    CounterRequest::ProcessExit(IncrMsg(17, 1)),
                ]
            );
        }
    }
}
