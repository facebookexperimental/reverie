/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Panic payloads held by the concrete Tool owner until its cleanup finishes.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use super::owned_future::CaughtFuture;
use super::owned_future::PanicPayload;
use crate::Error;
use crate::Result;

#[derive(Default)]
pub(crate) struct ToolPanics {
    pending: Mutex<Vec<PanicPayload>>,
    worker_execution_panicked: AtomicBool,
}

impl ToolPanics {
    pub(crate) fn take(&self) -> Vec<PanicPayload> {
        std::mem::take(&mut *self.pending.lock().expect("KVM Tool panic lock poisoned"))
    }

    pub(crate) fn append(&self, mut payloads: Vec<PanicPayload>) {
        self.pending
            .lock()
            .expect("KVM Tool panic lock poisoned")
            .append(&mut payloads);
    }

    pub(crate) fn drop_value<T>(&self, value: T, phase: &'static str) -> Result<()> {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(value))).err();
        self.finish(
            CaughtFuture {
                output: Some(Ok(())),
                panics: panic.into_iter().collect(),
            },
            phase,
        )
    }

    /// Only this worker's execution catches set this disposition. Payloads
    /// transferred from children or caught while consuming cleanup must not
    /// suppress this owner's still-owed exit hooks.
    pub(crate) fn worker_execution_panicked(&self) -> bool {
        self.worker_execution_panicked.load(Ordering::Acquire)
    }

    pub(crate) fn finish_worker_execution<R>(
        &self,
        caught: CaughtFuture<Result<R>>,
        phase: &'static str,
    ) -> Result<R> {
        if !caught.panics.is_empty() {
            self.worker_execution_panicked
                .store(true, Ordering::Release);
        }
        self.finish_with_panic_kind(caught, phase, true)
    }

    /// Keep both an already returned error and any polling/destruction panic.
    /// A derived cancellation cannot hide a newly caught real panic.
    pub(crate) fn finish<R>(
        &self,
        caught: CaughtFuture<Result<R>>,
        phase: &'static str,
    ) -> Result<R> {
        self.finish_with_panic_kind(caught, phase, false)
    }

    fn finish_with_panic_kind<R>(
        &self,
        caught: CaughtFuture<Result<R>>,
        phase: &'static str,
        worker_execution: bool,
    ) -> Result<R> {
        let count = caught.panics.len();
        self.append(caught.panics);
        if count == 0 {
            return caught.output.expect("caught Tool future lost its outcome");
        }
        let panic_is_primary = !matches!(
            caught.output.as_ref(),
            Some(Err(error)) if !matches!(error.primary(), Error::RunAborted)
        );
        let mut diagnostics = (0..count)
            .map(|index| {
                if worker_execution && panic_is_primary && index == 0 {
                    // Match the uncaught worker-unwind cause before its first
                    // publication. This is execution failure, not cleanup;
                    // later panics retain their individual cleanup phases.
                    Error::GuestWorkerPanic
                } else {
                    Error::GuestWorkerPanic.cleanup(phase)
                }
            })
            .collect::<Vec<_>>();
        match caught.output {
            Some(Err(error)) if !matches!(error.primary(), Error::RunAborted) => {
                Err(error.with_cleanup(diagnostics))
            }
            Some(Err(error)) => {
                let primary = diagnostics.remove(0);
                diagnostics.insert(0, error);
                Err(primary.with_cleanup(diagnostics))
            }
            Some(Ok(_)) | None => {
                let primary = diagnostics.remove(0);
                Err(primary.with_cleanup(diagnostics))
            }
        }
    }
}

#[cfg(test)]
#[path = "tool_panics_tests.rs"]
mod tests;
