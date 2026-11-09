/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! The existing single-poll LinuxProvider over a borrowed native invoker.
//! Protection precedes this mechanism. Every raw returning value, including
//! EINTR and ERESTARTSYS, remains Return rather than a synthesized not-run fact.

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

use super::native_rpc::NativeInvocation;

struct HostLinux<'callback>(std::marker::PhantomData<&'callback ()>);

pub(super) struct Invocation<'callback> {
    pub(super) native: NativeInvocation<'callback>,
    pub(super) purpose: InjectionPurpose,
}

#[derive(Debug, PartialEq, Eq)]
struct WrongTask {
    task: Tid,
    bound: Tid,
    bound_process: Pid,
}

#[reverie::provider]
impl<'callback> LinuxProvider for HostLinux<'callback> {
    type Context = Invocation<'callback>;
    type Plan = Infallible;
    type Error = WrongTask;

    async fn execute(
        &mut self,
        task: Tid,
        request: &SyscallRequest,
        cx: &mut Self::Context,
    ) -> Result<ProviderOutcome<Infallible>, WrongTask> {
        let identity = cx.native.identity();
        if task != identity.tid() {
            return Err(WrongTask {
                task,
                bound: identity.tid(),
                bound_process: identity.pid(),
            });
        }
        let raw = unsafe {
            cx.native
                .invoke(request.number() as i64, *request.args(), cx.purpose)
        };
        Ok(ProviderOutcome::Return(raw))
    }
}

/// Poll the unchanged returning-provider mechanism exactly once, while the
/// caller still owns the actual callback. No context is cached or spawned.
pub(super) fn forward(
    invocation: NativeInvocation<'_>,
    purpose: InjectionPurpose,
    request: &SyscallRequest,
) -> i64 {
    let tid = invocation.identity().tid();
    let mut context = Invocation {
        native: invocation,
        purpose,
    };
    forward_with(
        &mut HostLinux(std::marker::PhantomData),
        tid,
        request,
        &mut context,
    )
}

fn invariant_failure(native: NativeInvocation<'_>, message: impl std::fmt::Display) -> ! {
    // coordinator-rpc does not require a tracing subscriber/launcher feature.
    // Retain a fatal diagnostic through this callback's actual native I/O,
    // without entering a host stdio lock or an alternative syscall mechanism.
    struct Diagnostic(super::support::StackLine);
    impl std::fmt::Write for Diagnostic {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0.push_bytes(text.as_bytes());
            Ok(())
        }
    }
    let mut diagnostic = Diagnostic(super::support::StackLine::new());
    let _ = std::fmt::write(
        &mut diagnostic,
        format_args!("native LinuxProvider invariant failure: {message}\n"),
    );
    let bytes = diagnostic.0.as_bytes();
    let _ = unsafe {
        native.invoke(
            libc::SYS_write,
            [
                libc::STDERR_FILENO as u64,
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                0,
                0,
                0,
            ],
            InjectionPurpose::Application,
        )
    };
    std::process::abort()
}

fn forward_with<'callback, P>(
    provider: &mut P,
    task: Tid,
    request: &SyscallRequest,
    cx: &mut Invocation<'callback>,
) -> i64
where
    P: LinuxProvider<Context = Invocation<'callback>, Plan = Infallible>,
    P::Error: Debug,
{
    let native = cx.native;
    let mut future = std::pin::pin!(provider.execute(task, request, cx));
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Ok(ProviderOutcome::Return(raw))) => raw,
        Poll::Ready(Ok(outcome)) => invariant_failure(
            native,
            format_args!(
                "non-returning outcome {outcome:?} for syscall {}",
                request.number()
            ),
        ),
        Poll::Ready(Err(error)) => invariant_failure(
            native,
            format_args!("provider error {error:?} for syscall {}", request.number()),
        ),
        Poll::Pending => invariant_failure(
            native,
            format_args!(
                "syscall {} did not finish on its first poll",
                request.number()
            ),
        ),
    }
}
