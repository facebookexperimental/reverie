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
