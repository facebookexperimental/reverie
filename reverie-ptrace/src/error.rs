/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::Pid;
use thiserror::Error;

/// A reverie-ptrace error. This error type isn't meant to be exposed to the
/// user.
#[derive(Error, Debug)]
pub enum Error {
    /// An internal error that is only ever meant to be used as a reverie-ptrace
    /// implementation detail. None of these errors should make it through to the
    /// user.
    #[error(transparent)]
    Internal(#[from] safeptrace::Error),

    /// A ptrace failure annotated with the operation and tracee that failed.
    #[error("{operation} failed for tracee {pid}: {source}")]
    Tracee {
        /// The high-level ptrace operation that was in progress.
        operation: &'static str,
        /// The tracee on which the operation was attempted.
        pid: Pid,
        /// The underlying ptrace error.
        #[source]
        source: safeptrace::Error,
    },

    /// An internal runtime failure that is not represented by safeptrace.
    #[error("{operation} failed for tracee {pid}: {message}")]
    Runtime {
        /// The runtime operation that was in progress.
        operation: &'static str,
        /// The affected tracee.
        pid: Pid,
        /// Additional diagnostic detail.
        message: &'static str,
    },

    /// A public error.
    #[error(transparent)]
    External(#[from] reverie::Error),
}

impl Error {
    pub(crate) fn runtime(pid: Pid, operation: &'static str, message: &'static str) -> Self {
        Self::Runtime {
            operation,
            pid,
            message,
        }
    }
}

pub(crate) trait TraceResultExt<T> {
    fn tracee_context(self, pid: Pid, operation: &'static str) -> Result<T, Error>;
}

impl<T> TraceResultExt<T> for Result<T, safeptrace::Error> {
    fn tracee_context(self, pid: Pid, operation: &'static str) -> Result<T, Error> {
        self.map_err(|source| Error::Tracee {
            operation,
            pid,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use reverie::Errno;

    use super::*;

    #[test]
    fn tracee_error_includes_operation_and_pid() {
        let error = Err::<(), _>(safeptrace::Error::Errno(Errno::EPERM))
            .tracee_context(Pid::from_raw(42), "resume after seccomp stop")
            .expect_err("the synthetic ptrace operation should fail");

        let message = error.to_string();
        assert!(message.contains("resume after seccomp stop"));
        assert!(message.contains("42"));
        assert!(message.contains("Operation not permitted"));
    }
}
