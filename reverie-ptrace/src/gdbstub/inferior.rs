/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Pid;
use tokio::sync::mpsc;

use super::commands::*;
use super::Error;
use super::GdbRequest;

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

/// Inferior controlled by gdbstub
pub struct Inferior {
    /// Inferior id
    pub id: InferiorThreadId,

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

    /// Wait for stop event reported by the target.
    pub async fn wait_for_stop(&mut self) -> Result<StopReason, Error> {
        let rx = self.stop_rx.as_mut().ok_or(Error::Detached)?;
        let stopped = rx.recv().await.ok_or(Error::GdbServerStopEventRecvError)?;
        // clear `resume_pending` flag as we got a new stop event, implying
        //  a new resume *is* to be expected.
        self.resume_pending = false;
        Ok(stopped.reason)
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
}

/// Inferior is in stopped state. send to reverie.
#[derive(Debug, Clone, Copy)]
pub struct ResumeInferior {
    /// Resume action, step, continue, until, ...
    pub action: ResumeAction,
    /// Detach (from gdb) after this resume.
    pub detach: bool,
}
