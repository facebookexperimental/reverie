/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Typed activity statistics for the ptrace backend.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::BackendStatsRequest;
use reverie::BackendStatsSnapshot;
use reverie::BackendStatsSource;
use safeptrace::ChildOp;
use safeptrace::Event;
use safeptrace::Wait;

/// The prefix [`PtraceBackendStatsSource::mark_last_stop_internal`] puts on a
/// recorded stop description.
#[cfg(test)]
pub(crate) const INTERNAL_STOP_PREFIX: &str = "internal ";

/// Stable counts of lifecycle transitions observed by the ptrace run loops.
///
/// Every field is supported by ptrace. A zero therefore means the named
/// transition was measured and did not occur; it never means collection was
/// unavailable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PtraceBackendStatsSnapshot {
    tracees_started: u64,
    stop_events: u64,
    exited_tracees: u64,
    seccomp_stops: u64,
    signal_stops: u64,
    exec_stops: u64,
    fork_stops: u64,
    vfork_stops: u64,
    clone_stops: u64,
    vfork_done_stops: u64,
}

impl PtraceBackendStatsSnapshot {
    /// Number of root and child tracees admitted to the ptrace lifecycle.
    pub const fn tracees_started(&self) -> u64 {
        self.tracees_started
    }

    /// Number of stopped transitions entering a top-level tracee run loop.
    pub const fn stop_events(&self) -> u64 {
        self.stop_events
    }

    /// Number of final tracee-exit transitions observed by those run loops.
    pub const fn exited_tracees(&self) -> u64 {
        self.exited_tracees
    }

    /// Number of seccomp syscall-entry stops.
    pub const fn seccomp_stops(&self) -> u64 {
        self.seccomp_stops
    }

    /// Number of signal-delivery stops.
    pub const fn signal_stops(&self) -> u64 {
        self.signal_stops
    }

    /// Number of exec stops.
    pub const fn exec_stops(&self) -> u64 {
        self.exec_stops
    }

    /// Number of fork child-creation stops.
    pub const fn fork_stops(&self) -> u64 {
        self.fork_stops
    }

    /// Number of vfork child-creation stops.
    pub const fn vfork_stops(&self) -> u64 {
        self.vfork_stops
    }

    /// Number of clone child-creation stops.
    pub const fn clone_stops(&self) -> u64 {
        self.clone_stops
    }

    /// Number of vfork-completion stops.
    pub const fn vfork_done_stops(&self) -> u64 {
        self.vfork_done_stops
    }
}

impl fmt::Display for PtraceBackendStatsSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "ptrace activity stats: tracees_started={} stop_events={} exited_tracees={} seccomp_stops={} signal_stops={} exec_stops={} child_stops[fork={},vfork={},clone={}] vfork_done_stops={}",
            self.tracees_started,
            self.stop_events,
            self.exited_tracees,
            self.seccomp_stops,
            self.signal_stops,
            self.exec_stops,
            self.fork_stops,
            self.vfork_stops,
            self.clone_stops,
            self.vfork_done_stops,
        )
    }
}

impl BackendStatsSnapshot for PtraceBackendStatsSnapshot {
    const BACKEND_NAME: &'static str = "ptrace";
}

#[derive(Debug, Default)]
struct PtraceBackendStatsCollector {
    tracees_started: AtomicU64,
    stop_events: AtomicU64,
    exited_tracees: AtomicU64,
    seccomp_stops: AtomicU64,
    signal_stops: AtomicU64,
    exec_stops: AtomicU64,
    fork_stops: AtomicU64,
    vfork_stops: AtomicU64,
    clone_stops: AtomicU64,
    vfork_done_stops: AtomicU64,
    #[cfg(test)]
    stop_trace: std::sync::Mutex<Vec<(reverie::Pid, String)>>,
    #[cfg(test)]
    signal_trace: std::sync::Mutex<Vec<(reverie::Pid, String)>>,
}

/// Live source for a ptrace backend activity snapshot.
#[derive(Clone, Debug)]
pub struct PtraceBackendStatsSource {
    collector: Arc<PtraceBackendStatsCollector>,
}

impl PtraceBackendStatsSource {
    pub(crate) fn from_request(request: BackendStatsRequest) -> Option<Self> {
        request.is_enabled().then(|| {
            let collector = PtraceBackendStatsCollector::default();
            collector.tracees_started.store(1, Ordering::Relaxed);
            Self {
                collector: Arc::new(collector),
            }
        })
    }

    pub(crate) fn record_wait(&self, wait: &Wait) {
        #[cfg(test)]
        self.record_stop_trace(wait);
        match wait {
            Wait::Exited(_, _) => {}
            Wait::Stopped(_, event) => {
                self.collector.stop_events.fetch_add(1, Ordering::Relaxed);
                match event {
                    Event::NewChild(operation, _) => {
                        self.collector
                            .tracees_started
                            .fetch_add(1, Ordering::Relaxed);
                        let counter = match operation {
                            ChildOp::Fork => &self.collector.fork_stops,
                            ChildOp::Vfork => &self.collector.vfork_stops,
                            ChildOp::Clone => &self.collector.clone_stops,
                        };
                        counter.fetch_add(1, Ordering::Relaxed);
                    }
                    Event::Exec(_) => {
                        self.collector.exec_stops.fetch_add(1, Ordering::Relaxed);
                    }
                    Event::VforkDone => {
                        self.collector
                            .vfork_done_stops
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Event::Seccomp => {
                        self.collector.seccomp_stops.fetch_add(1, Ordering::Relaxed);
                    }
                    Event::Signal(_) => {
                        self.collector.signal_stops.fetch_add(1, Ordering::Relaxed);
                    }
                    Event::Exit | Event::Stop | Event::Syscall => {}
                }
            }
        }
    }

    /// Appends one run-loop wait to the test-only stop sequence.
    ///
    /// Seccomp stops carry the syscall number, vfork-done stops the parent's
    /// rax, and new-child stops carry the child's PID, so that two runs of
    /// the same guest can be compared stop by stop and task by task.
    #[cfg(test)]
    fn record_stop_trace(&self, wait: &Wait) {
        let (pid, description) = match wait {
            Wait::Exited(pid, status) => (*pid, format!("exited {status:?}")),
            Wait::Stopped(stopped, event) => {
                let description = match event {
                    Event::NewChild(operation, child) => {
                        format!("new-child {operation:?} {}", child.pid())
                    }
                    Event::Exec(_) => "exec".to_owned(),
                    // A vfork parent is still inside the call at this stop, so
                    // its rax is whatever the tracer left there (the kernel
                    // writes the result only when the call returns).
                    Event::VforkDone => match stopped.getregs() {
                        #[cfg(target_arch = "x86_64")]
                        Ok(regs) => format!("VforkDone rax={}", regs.rax as i64),
                        #[cfg(not(target_arch = "x86_64"))]
                        Ok(_) => "VforkDone".to_owned(),
                        Err(error) => format!("VforkDone <getregs failed: {error}>"),
                    },
                    Event::Seccomp => match stopped.getregs() {
                        #[cfg(target_arch = "x86_64")]
                        Ok(regs) => format!("seccomp {}", regs.orig_rax),
                        #[cfg(not(target_arch = "x86_64"))]
                        Ok(_) => "seccomp".to_owned(),
                        Err(error) => format!("seccomp <getregs failed: {error}>"),
                    },
                    other => format!("{other:?}"),
                };
                (stopped.pid(), description)
            }
        };
        self.collector
            .stop_trace
            .lock()
            .expect("stop trace lock poisoned")
            .push((pid, description));
    }

    /// Appends one signal-delivery stop, as the run loop is about to handle
    /// it, to the test-only signal sequence: the signal, its siginfo (the
    /// sender's pid and uid only for a signal a process sent, where they are
    /// defined, and for SIGCHLD with its status), and the registers that show
    /// where the stop took effect.
    #[cfg(test)]
    pub(crate) fn record_signal_stop(
        &self,
        stopped: &safeptrace::Stopped,
        signal: nix::sys::signal::Signal,
    ) {
        let info = match stopped.getsiginfo() {
            Ok(info) => {
                let mut text = format!(
                    "signo={} code={} errno={}",
                    info.si_signo, info.si_code, info.si_errno
                );
                if info.si_code <= 0 || info.si_signo == libc::SIGCHLD {
                    // SAFETY: these union members are defined for a signal a
                    // process sent (si_code <= 0) and for SIGCHLD.
                    let (pid, uid) = unsafe { (info.si_pid(), info.si_uid()) };
                    text += &format!(" pid={pid} uid={uid}");
                }
                if info.si_signo == libc::SIGCHLD {
                    // SAFETY: defined for SIGCHLD.
                    text += &format!(" status={}", unsafe { info.si_status() });
                }
                text
            }
            Err(error) => format!("<getsiginfo failed: {error}>"),
        };
        #[cfg(target_arch = "x86_64")]
        let registers = match stopped.getregs() {
            Ok(regs) => format!(
                " rip={:#x} rax={} orig_rax={}",
                regs.rip, regs.rax as i64, regs.orig_rax as i64
            ),
            Err(error) => format!(" <getregs failed: {error}>"),
        };
        #[cfg(not(target_arch = "x86_64"))]
        let registers = String::new();
        self.collector
            .signal_trace
            .lock()
            .expect("signal trace lock poisoned")
            .push((stopped.pid(), format!("{signal:?} {info}{registers}")));
    }

    /// Returns every recorded signal-delivery stop in arrival order.
    #[cfg(test)]
    pub(crate) fn signal_trace(&self) -> Vec<(reverie::Pid, String)> {
        self.collector
            .signal_trace
            .lock()
            .expect("signal trace lock poisoned")
            .clone()
    }

    /// Marks `pid`'s most recent recorded wait as tracer-internal: a stop
    /// plain ptrace never produces (a trap-only Allow-class entry), which the
    /// P2 comparator accounts for explicitly instead of comparing.
    #[cfg(test)]
    pub(crate) fn mark_last_stop_internal(&self, pid: reverie::Pid) {
        let mut trace = self
            .collector
            .stop_trace
            .lock()
            .expect("stop trace lock poisoned");
        if let Some((_, description)) = trace.iter_mut().rev().find(|(stop, _)| *stop == pid) {
            description.insert_str(0, INTERNAL_STOP_PREFIX);
        }
    }

    /// Returns every recorded run-loop wait in arrival order.
    #[cfg(test)]
    pub(crate) fn stop_trace(&self) -> Vec<(reverie::Pid, String)> {
        self.collector
            .stop_trace
            .lock()
            .expect("stop trace lock poisoned")
            .clone()
    }

    pub(crate) fn record_tracee_exit(&self) {
        self.collector
            .exited_tracees
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl BackendStatsSource for PtraceBackendStatsSource {
    type Snapshot = PtraceBackendStatsSnapshot;

    fn backend_stats(&self) -> Self::Snapshot {
        PtraceBackendStatsSnapshot {
            tracees_started: self.collector.tracees_started.load(Ordering::Relaxed),
            stop_events: self.collector.stop_events.load(Ordering::Relaxed),
            exited_tracees: self.collector.exited_tracees.load(Ordering::Relaxed),
            seccomp_stops: self.collector.seccomp_stops.load(Ordering::Relaxed),
            signal_stops: self.collector.signal_stops.load(Ordering::Relaxed),
            exec_stops: self.collector.exec_stops.load(Ordering::Relaxed),
            fork_stops: self.collector.fork_stops.load(Ordering::Relaxed),
            vfork_stops: self.collector.vfork_stops.load(Ordering::Relaxed),
            clone_stops: self.collector.clone_stops.load(Ordering::Relaxed),
            vfork_done_stops: self.collector.vfork_done_stops.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_source_reports_root_as_measured_activity() {
        let source = PtraceBackendStatsSource::from_request(BackendStatsRequest::ENABLED)
            .expect("enabled collection must create a source");
        let snapshot = source.backend_stats();
        assert_eq!(snapshot.tracees_started(), 1);
        assert_eq!(snapshot.stop_events(), 0);
        assert!(PtraceBackendStatsSource::from_request(BackendStatsRequest::DISABLED).is_none());
    }
}
