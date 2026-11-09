/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;
use std::sync::Mutex;

use reverie::Pid;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use super::CoreRegs;
use super::Error;
use super::GdbRequest;
use super::commands::*;

/// Thread id and Pid use to uniquely indentify an inferior.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InferiorThreadId {
    pub tid: Pid,
    pub pid: Pid,
}

impl InferiorThreadId {
    pub fn new(tid: Pid, pid: Pid) -> Self {
        InferiorThreadId { tid, pid }
    }
}
impl From<InferiorThreadId> for ThreadId {
    fn from(id: InferiorThreadId) -> Self {
        ThreadId::pid_tid(id.pid.as_raw(), id.tid.as_raw())
    }
}

impl TryFrom<ThreadId> for InferiorThreadId {
    type Error = Error;

    fn try_from(threadid: ThreadId) -> Result<Self, Self::Error> {
        let pid = threadid.getpid().ok_or(Error::ThreadIdNotSpecified)?;
        let tid = threadid.gettid().ok_or(Error::ThreadIdNotSpecified)?;
        Ok(InferiorThreadId::new(tid, pid))
    }
}

/// What gdb can learn about a traced thread outside its own requests channel.
///
/// A thread answers gdb's requests only while it waits in a gdb stop. A tool
/// that sequentializes threads, such as Detcore, holds every other thread in
/// a callback, waiting for its turn, where it cannot answer. Such a thread
/// publishes the registers it stopped with, which is all gdb needs to show it.
#[derive(Clone, Debug, Default)]
pub struct ThreadView(Arc<Mutex<ThreadState>>);

/// Where a traced thread is, as far as gdb is concerned.
#[derive(Clone, Debug, Default)]
pub enum ThreadState {
    /// Executing, or stopped somewhere it publishes nothing.
    #[default]
    Running,
    /// In a gdb stop, answering requests.
    InGdbStop,
    /// Stopped in a tool callback with these registers. The guest cannot run
    /// before the callback returns, so they stay current until then.
    Parked(Box<CoreRegs>),
}

impl ThreadView {
    pub fn state(&self) -> ThreadState {
        self.0
            .lock()
            .expect("should not be poisoned: no code panics while holding it")
            .clone()
    }

    /// Sets the state until the returned guard drops, which restores the one
    /// it replaced, so that nested states unwind in order.
    pub fn enter(&self, state: ThreadState) -> ThreadStateGuard {
        let previous = std::mem::replace(
            &mut *self
                .0
                .lock()
                .expect("should not be poisoned: no code panics while holding it"),
            state,
        );
        ThreadStateGuard {
            view: self.clone(),
            previous: Some(previous),
        }
    }
}

/// Restores a [`ThreadView`]'s previous state when dropped.
#[must_use]
pub struct ThreadStateGuard {
    view: ThreadView,
    previous: Option<ThreadState>,
}

impl Drop for ThreadStateGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            *self
                .view
                .0
                .lock()
                .expect("should not be poisoned: no code panics while holding it") = previous;
        }
    }
}

/// Inferior controlled by gdbstub
pub struct Inferior {
    /// Inferior id
    pub id: InferiorThreadId,

    /// Where the thread is, for requests it cannot answer itself.
    pub view: ThreadView,

    /// Resume attached tracee
    pub resume_tx: Option<mpsc::Sender<ResumeInferior>>,

    /// Send request to reverie
    pub request_tx: Option<mpsc::Sender<GdbRequest>>,

    /// Channel to receive new gdb stop event
    pub stop_rx: Option<mpsc::Receiver<StoppedInferior>>,

    /// Has a pending resume
    pub resume_pending: bool,
}

impl Inferior {
    pub fn new(id: InferiorThreadId) -> Self {
        Inferior {
            id,
            view: ThreadView::default(),
            resume_tx: None,
            request_tx: None,
            stop_rx: None,
            resume_pending: false,
        }
    }

    pub fn gettid(&self) -> Pid {
        self.id.tid
    }

    pub fn getpid(&self) -> Pid {
        self.id.pid
    }

    pub fn matches(&self, threadid: &ThreadId) -> bool {
        let this_threadid: ThreadId = self.id.into();
        this_threadid.matches(threadid)
    }

    /// Notify target to resume given `Inferior`.
    // NB: The inferior could have been resumed previously, meaning there could
    // be a pending stop state from last resume. This is possible when
    // `vCont;p<pid>:-1` is called while there are multiple threads in the same
    // process group. The pending flag is cleared when a stop event is reported
    // by the target (reverie).
    pub async fn notify_resume(&mut self, resume: ResumeInferior) -> Result<(), Error> {
        if !self.resume_pending {
            let tx = self.resume_tx.as_ref().ok_or(Error::Detached)?;
            tx.send(resume).await.map_err(|_| Error::GdbResumeError)?;
            self.resume_pending = true;
        }
        Ok(())
    }

    /// Wait for stop event reported by the target. Returns the stop and, for
    /// one whose reporter waits until gdb has its reply
    /// (`StoppedInferior::replied`), the channel to tell it.
    pub async fn wait_for_stop(
        &mut self,
    ) -> Result<(StopReason, Option<oneshot::Sender<()>>), Error> {
        let rx = self.stop_rx.as_mut().ok_or(Error::Detached)?;
        let stopped = rx.recv().await.ok_or(Error::GdbServerStopEventRecvError)?;
        // clear `resume_pending` flag as we got a new stop event, implying
        //  a new resume *is* to be expected.
        self.resume_pending = false;
        Ok((stopped.reason, stopped.replied))
    }
}

/// Inferior is in stopped state. sent by reverie.
#[derive(Debug)]
pub struct StoppedInferior {
    /// Reason why inferior has stopped.
    pub reason: StopReason,
    /// tx channel to send gdb request (by gdb)
    pub request_tx: mpsc::Sender<GdbRequest>,
    /// tx channel to send gdb resume/step (by gdb)
    pub resume_tx: mpsc::Sender<ResumeInferior>,
    /// Where the stopped thread is when another thread is in a gdb stop.
    pub view: ThreadView,
    /// Told once the stop reply is written to gdb. A process exit's reporter
    /// waits for it: the run, and with it the connection, can end as soon as
    /// the reporter returns, which could drop a reply not yet written. Dropped
    /// unsent if the session goes away first, which releases the reporter too.
    pub replied: Option<oneshot::Sender<()>>,
}

/// Inferior is in stopped state. send to reverie.
#[derive(Debug, Clone, Copy)]
pub struct ResumeInferior {
    /// Resume action, step, continue, until, ...
    pub action: ResumeAction,
    /// Detach (from gdb) after this resume.
    pub detach: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_parked(view: &ThreadView) -> bool {
        matches!(view.state(), ThreadState::Parked(_))
    }

    #[test]
    fn nested_states_unwind_in_order() {
        let view = ThreadView::default();
        assert!(
            matches!(view.state(), ThreadState::Running),
            "a new thread runs"
        );

        let parked = view.enter(ThreadState::Parked(Box::default()));
        assert!(is_parked(&view));
        let stopped = view.enter(ThreadState::InGdbStop);
        assert!(matches!(view.state(), ThreadState::InGdbStop));

        drop(stopped);
        assert!(
            is_parked(&view),
            "leaving the gdb stop returns to the callback"
        );
        drop(parked);
        assert!(
            matches!(view.state(), ThreadState::Running),
            "leaving the callback resumes"
        );
    }

    #[test]
    fn clones_share_the_state() {
        let view = ThreadView::default();
        let session_side = view.clone();
        let _parked = view.enter(ThreadState::Parked(Box::default()));
        assert!(
            is_parked(&session_side),
            "the session sees what the task publishes"
        );
    }
}
