/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Returning injections through the existing full native syscall callback.
//!
//! The host kernel keeps the Linux state. This stateless handle neither
//! emulates a syscall nor chooses a different callback for particular calls.
//! Backend protection runs before constructing its per-call context. The
//! context is lent only on the issuing guest's callback thread and is never
//! retained. Its task check validates that binding, not the physical host tid.
//!
//! `async_trait` boxes one future per forwarded call. It is polled once on
//! that same thread; `execute` never awaits. This adds no suspension point,
//! but the allocation is not a claim of unchanged layout or measured cost.
//! Native ownership, SIGPIPE identity, lifecycle bookkeeping and interruption
//! receipts remain owned by the supplied full callback. An integer errno
//! does not establish a not-run interruption: every returning value is a
//! `Return`, including -EINTR and -ERESTARTSYS.

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::InjectionPurpose;
use reverie::Pid;
use reverie::Tid;
use reverie::provider::LinuxProvider;
use reverie::provider::ProviderOutcome;
use reverie::provider::SyscallRequest;

use crate::SyscallInvoker;

pub(super) struct HostLinux;

/// Borrowed facts for one admitted call on this native callback thread.
pub(super) struct Invocation {
    pub(super) tid: Tid,
    pub(super) pid: Pid,
    pub(super) context: usize,
    pub(super) invoke: SyscallInvoker,
    pub(super) purpose: InjectionPurpose,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct WrongTask {
    task: Tid,
    bound: Tid,
    bound_process: Pid,
}

#[reverie::provider]
impl LinuxProvider for HostLinux {
    type Context = Invocation;
    type Plan = Infallible;
    type Error = WrongTask;

    async fn execute(
        &mut self,
        task: Tid,
        request: &SyscallRequest,
        cx: &mut Invocation,
    ) -> Result<ProviderOutcome<Infallible>, WrongTask> {
        if task != cx.tid {
            return Err(WrongTask {
                task,
                bound: cx.tid,
                bound_process: cx.pid,
            });
        }
        #[cfg(test)]
        OBSERVED.with(|calls| {
            calls.borrow_mut().push(Observed {
                tid: task,
                pid: cx.pid,
                context: cx.context,
                callback: cx.invoke as usize,
                request: *request,
                purpose: cx.purpose,
            });
        });
        // The caller lent the actual task's full native invoker after backend
        // admission. Keep its bookkeeping, guards and interruption owner.
        let raw = unsafe {
            (cx.invoke)(
                cx.context,
                request.number() as i64,
                request.args().as_ptr(),
                cx.purpose as u32,
            )
        };
        Ok(ProviderOutcome::Return(raw))
    }
}

pub(super) fn forward(
    tid: Tid,
    pid: Pid,
    context: usize,
    invoke: SyscallInvoker,
    purpose: InjectionPurpose,
    request: &SyscallRequest,
) -> i64 {
    let mut cx = Invocation {
        tid,
        pid,
        context,
        invoke,
        purpose,
    };
    forward_with(&mut HostLinux, tid, request, &mut cx)
}

fn invariant_failure(message: impl std::fmt::Display) -> ! {
    // An installed subscriber may retain this event. Termination must not
    // depend on a subscriber, and is process-local, not native tree cleanup.
    tracing::error!(%message, "DBT LinuxProvider invariant failure");
    std::process::abort()
}

pub(super) fn forward_with<P>(
    provider: &mut P,
    task: Tid,
    request: &SyscallRequest,
    cx: &mut Invocation,
) -> i64
where
    P: LinuxProvider<Context = Invocation, Plan = Infallible>,
    P::Error: Debug,
{
    let mut future = std::pin::pin!(provider.execute(task, request, cx));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(ProviderOutcome::Return(raw))) => raw,
        Poll::Ready(Ok(outcome)) => invariant_failure(format_args!(
            "non-returning outcome {outcome:?} for syscall {}",
            request.number()
        )),
        Poll::Ready(Err(error)) => invariant_failure(format_args!(
            "provider error {error:?} for syscall {}",
            request.number()
        )),
        Poll::Pending => invariant_failure(format_args!(
            "syscall {} did not finish on its first poll",
            request.number()
        )),
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Observed {
    pub(super) tid: Tid,
    pub(super) pid: Pid,
    pub(super) context: usize,
    pub(super) callback: usize,
    pub(super) request: SyscallRequest,
    pub(super) purpose: InjectionPurpose,
}

#[cfg(test)]
std::thread_local! {
    static OBSERVED: std::cell::RefCell<Vec<Observed>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn take_observed() -> Vec<Observed> {
    OBSERVED.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}
