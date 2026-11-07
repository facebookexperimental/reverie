/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::sync::Arc;

pub use reverie_kvm_core::error::Error;

/// The error operations that were crate-private inherent methods of [`Error`]
/// before it moved to reverie-kvm-core (step U6b-1 of the provider seam). A
/// crate-private extension trait keeps them out of the public API, which an
/// inherent impl in the new crate could not; the bodies are unchanged.
pub(crate) trait ErrorExt: Sized {
    fn retains_primary(&self, primary: &std::sync::Arc<Error>) -> bool;
    fn worker_tid(&self) -> Option<i32>;
    fn cleanup(self, phase: &'static str) -> Self;
    fn with_cleanup(self, cleanup: Vec<Error>) -> Self;
    fn combine(errors: Vec<Error>) -> crate::Result<()>;
    fn complete_after_failure(self, first: Arc<Error>, first_tid: i32) -> Self;
}

impl ErrorExt for Error {
    fn retains_primary(&self, primary: &std::sync::Arc<Error>) -> bool {
        match self {
            Self::SignalEffects { cause: error, .. }
            | Self::SharedFailure(error)
            | Self::WorkerFailure { error, .. }
            | Self::WithCleanup { primary: error, .. }
            | Self::Cleanup { error, .. } => {
                std::sync::Arc::ptr_eq(error, primary) || error.retains_primary(primary)
            }
            Self::ExecWorkerTeardown(error) => error.retains_primary(primary),
            _ => false,
        }
    }

    /// Identity of the primary worker cause, never a secondary cleanup error.
    fn worker_tid(&self) -> Option<i32> {
        match self {
            Self::WorkerFailure { tid, .. } => Some(*tid),
            Self::SignalEffects { cause: error, .. }
            | Self::SharedFailure(error)
            | Self::WithCleanup { primary: error, .. }
            | Self::Cleanup { error, .. } => error.worker_tid(),
            Self::ExecWorkerTeardown(error) => error.worker_tid(),
            _ => None,
        }
    }

    fn cleanup(self, phase: &'static str) -> Self {
        Self::Cleanup {
            phase,
            error: Arc::new(self),
        }
    }

    fn with_cleanup(self, cleanup: Vec<Error>) -> Self {
        if cleanup.is_empty() {
            self
        } else {
            Self::WithCleanup {
                primary: Arc::new(self),
                cleanup: cleanup.into_iter().map(Arc::new).collect(),
            }
        }
    }

    fn combine(mut errors: Vec<Error>) -> crate::Result<()> {
        if errors.is_empty() {
            Ok(())
        } else {
            let primary = errors.remove(0);
            Err(primary.with_cleanup(errors))
        }
    }

    /// Compose the final result after all publishers and owned joins returned.
    /// The first published Arc is authoritative. Shared aggregate children stay
    /// shared, so separating a cancellation marker cannot discard a real hook
    /// error or clone a non-Clone host error into a different cause.
    fn complete_after_failure(self, first: Arc<Error>, first_tid: i32) -> Self {
        assert!(!matches!(first.primary(), Error::RunAborted));
        #[derive(Clone)]
        enum Context {
            Worker(i32),
            Cleanup(&'static str),
            Exec,
        }
        struct Cause {
            error: Arc<Error>,
            context: Vec<Context>,
        }
        impl Cause {
            fn into_error(self) -> Error {
                self.context.into_iter().rev().fold(
                    Error::SharedFailure(self.error),
                    |error, context| match context {
                        Context::Worker(tid) => Error::WorkerFailure {
                            tid,
                            error: Arc::new(error),
                        },
                        Context::Cleanup(phase) => error.cleanup(phase),
                        Context::Exec => Error::ExecWorkerTeardown(Box::new(error)),
                    },
                )
            }
            fn worker_tid(&self) -> Option<i32> {
                self.context
                    .iter()
                    .find_map(|context| match context {
                        Context::Worker(tid) => Some(*tid),
                        _ => None,
                    })
                    .or_else(|| self.error.worker_tid())
            }
        }
        fn split(
            error: Arc<Error>,
            first: &Arc<Error>,
            context: &mut Vec<Context>,
            causes: &mut Vec<Cause>,
        ) {
            if Arc::ptr_eq(&error, first) || !split_aggregate(&error, first, context, causes) {
                causes.push(Cause {
                    error,
                    context: context.clone(),
                });
            }
        }
        // Return false for an opaque cause. Exec's existing boxed API remains
        // intact: its wrapper is reproduced only when the child is an aggregate
        // or shared reference; otherwise the original complete Arc is retained.
        fn split_aggregate(
            error: &Error,
            first: &Arc<Error>,
            context: &mut Vec<Context>,
            causes: &mut Vec<Cause>,
        ) -> bool {
            match error {
                Error::RunAborted => {}
                Error::SharedFailure(error) => split(error.clone(), first, context, causes),
                Error::WithCleanup { primary, cleanup } => {
                    split(primary.clone(), first, context, causes);
                    for error in cleanup {
                        split(error.clone(), first, context, causes);
                    }
                }
                Error::WorkerFailure { tid, error } => {
                    context.push(Context::Worker(*tid));
                    split(error.clone(), first, context, causes);
                    context.pop();
                }
                Error::Cleanup { phase, error } => {
                    context.push(Context::Cleanup(phase));
                    split(error.clone(), first, context, causes);
                    context.pop();
                }
                Error::ExecWorkerTeardown(error) => {
                    context.push(Context::Exec);
                    let split = split_aggregate(error, first, context, causes);
                    context.pop();
                    return split;
                }
                _ => return false,
            }
            true
        }
        let mut causes = Vec::new();
        split(Arc::new(self), &first, &mut Vec::new(), &mut causes);
        // Prefer the already present worker context for the published identity
        // over a context-free notification alias. A canceled peer carrying the
        // same cause cannot supply its own TID as the cause's identity. Other
        // real errors retain their order, regardless of host completion/TID.
        let selected = causes
            .iter()
            .enumerate()
            .filter(|(_, cause)| {
                Arc::ptr_eq(&cause.error, &first)
                    && cause.worker_tid().is_none_or(|tid| tid == first_tid)
            })
            .max_by_key(|(index, cause)| {
                (
                    cause.worker_tid() == Some(first_tid),
                    std::cmp::Reverse(*index),
                )
            })
            .map(|(index, _)| index);
        let primary = selected
            .map(|index| causes.remove(index).into_error())
            .unwrap_or_else(|| Error::SharedFailure(first.clone()));
        let cleanup = causes
            .into_iter()
            .filter(|cause| !Arc::ptr_eq(&cause.error, &first))
            .map(Cause::into_error)
            .collect();
        primary.with_cleanup(cleanup)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn signal_effects_preserve_first_failure_and_cancellation_evidence() {
        let first = Arc::new(Error::GuestClock("original".to_owned()));
        let context = reverie::ParkedSignalFailureContext {
            site: reverie::CallbackSignalSite {
                process: reverie::SignalProcessId {
                    tgid: reverie::Pid::from_raw(1),
                    generation: 2,
                },
                tid: reverie::Pid::from_raw(1),
                task_generation: 3,
                callback_nonce: 7,
                boundary_nonce: 8,
            },
            ledger_nonce: 8,
        };
        let ledger = |cause| Error::SignalEffects {
            cause: Arc::new(cause),
            dequeues: Vec::new(),
            acknowledged_through: 17,
            publications: Vec::new(),
            raw_result: Some(-14),
            context: Some(Box::new(context)),
        };
        let worker = ledger(Error::WorkerFailure {
            tid: 3,
            error: first.clone(),
        });
        assert!(worker.retains_primary(&first));
        assert_eq!(worker.worker_tid(), Some(3));
        assert!(matches!(worker.primary(), Error::GuestClock(message) if message == "original"));
        let cancelled = ledger(Error::RunAborted);
        assert!(matches!(cancelled.primary(), Error::RunAborted));
        let completed = cancelled.complete_after_failure(first.clone(), 3);
        assert!(completed.retains_primary(&first));
        assert!(matches!(completed.primary(), Error::GuestClock(message) if message == "original"));
        let Error::WithCleanup { cleanup, .. } = completed else {
            panic!("ledger lost")
        };
        assert_eq!(cleanup.len(), 1);
        let Error::SharedFailure(retained) = cleanup[0].as_ref() else {
            panic!("ledger not retained")
        };
        assert!(matches!(retained.as_ref(), Error::SignalEffects {
            acknowledged_through: 17, raw_result: Some(-14), context: Some(actual), ..
        } if **actual == context));
    }

    #[test]
    fn worker_diagnostic_and_primary_survive_exec_and_cleanup_wrappers() {
        let cause = Arc::new(Error::Reverie(reverie::syscalls::Errno::EIO.into()));
        let error = Error::ExecWorkerTeardown(Box::new(Error::WorkerFailure {
            tid: 2,
            error: cause.clone(),
        }));
        assert_eq!(
            error.to_string(),
            "unexpected vCPU exit: KVM worker cleanup failed: thread 2: Reverie tool failed: -5 EIO (I/O error)"
        );
        assert!(
            matches!(error.primary(), Error::Reverie(reverie::Error::Errno(errno))
            if *errno == reverie::syscalls::Errno::EIO)
        );
        assert!(error.retains_primary(&cause));
        assert_eq!(error.worker_tid(), Some(2));
        let error = error.with_cleanup(vec![Error::GuestClock("secondary".to_owned())]);
        assert!(error.retains_primary(&cause));
        assert_eq!(error.worker_tid(), Some(2));
        assert!(matches!(error.primary(), Error::Reverie(_)));
    }
}
