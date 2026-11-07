/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Fixed callback completion rules shared by in-process Tool frontends.
//!
//! These functions classify observed facts; they do not poll a future, execute
//! a syscall, authenticate an ending, or own any frontend state.

use std::task::Poll;

use crate::Error;
use crate::ExitStatus;
use crate::Pid;
use crate::syscalls::Errno;

/// Whether the current attempt handles a syscall or another Tool callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackPhase {
    /// The attempt may resolve the intercepted syscall.
    Syscall,
    /// Startup, instruction, signal, or another non-syscall callback.
    Callback,
}

/// A frontend's observed tail fact after polling a Tool callback.
#[derive(Debug, Eq, PartialEq)]
pub enum TailFact<E> {
    /// An ordinary tail syscall already executed. Never forward it again.
    Completed(i64),
    /// Operands were queued, but the syscall has not executed or established
    /// an ending. A frontend must still validate them before forwarding.
    Deferred {
        /// Linux syscall number.
        number: i64,
        /// Linux syscall arguments.
        args: [u64; 6],
    },
    /// An ending established by this frontend's authenticated admission path.
    Established(E),
    /// A plain fork already returned in the child with these actual identities.
    ForkChild {
        /// Thread that made the fork.
        parent_tid: Pid,
        /// Process that made the fork.
        parent_pid: Pid,
        /// Child thread now executing.
        child_tid: Pid,
        /// Child process now executing.
        child_pid: Pid,
    },
}

/// The fixed disposition of one observed callback poll and its staged facts.
#[derive(Debug, Eq, PartialEq)]
pub enum CallbackDecision<V, E> {
    /// The callback returned; discard any non-ending staged fact.
    Ready(V),
    /// Resolve the syscall with this already-executed tail result.
    Completed(i64),
    /// Hand the exact unexecuted operands back to frontend validation.
    Deferred {
        /// Linux syscall number.
        number: i64,
        /// Linux syscall arguments.
        args: [u64; 6],
    },
    /// Consume this exact established ending after dropping callback borrows.
    Established(E),
    /// Reconstruct the child owner using the already-observed identities.
    ForkChild {
        /// Thread that made the fork.
        parent_tid: Pid,
        /// Process that made the fork.
        parent_pid: Pid,
        /// Child thread now executing.
        child_tid: Pid,
        /// Child process now executing.
        child_pid: Pid,
    },
    /// Refuse an attempt that has not already established an ending.
    Refused(&'static str),
    /// No completion fact: retain the frontend's existing progress mechanism.
    Wait,
}

/// Classify a poll with fixed established-ending precedence and phase rules.
///
/// Established endings survive both `Ready` and later attempted effects.
/// Otherwise a latched refusal ends the attempt. `Ready` discards completed,
/// deferred and fork facts, as the trap host has always done. Only a pending
/// syscall attempt may consume one of those non-ending facts.
pub fn classify_callback<V, E>(
    phase: CallbackPhase,
    poll: Poll<V>,
    tail: Option<TailFact<E>>,
    refusal: Option<&'static str>,
) -> CallbackDecision<V, E> {
    let tail = match tail {
        Some(TailFact::Established(ending)) => return CallbackDecision::Established(ending),
        tail => tail,
    };
    if let Some(reason) = refusal {
        return CallbackDecision::Refused(reason);
    }
    if let Poll::Ready(value) = poll {
        return CallbackDecision::Ready(value);
    }
    match (phase, tail) {
        (_, None) => CallbackDecision::Wait,
        (CallbackPhase::Syscall, Some(TailFact::Completed(value))) => {
            CallbackDecision::Completed(value)
        }
        (CallbackPhase::Syscall, Some(TailFact::Deferred { number, args })) => {
            CallbackDecision::Deferred { number, args }
        }
        (
            CallbackPhase::Syscall,
            Some(TailFact::ForkChild {
                parent_tid,
                parent_pid,
                child_tid,
                child_pid,
            }),
        ) => CallbackDecision::ForkChild {
            parent_tid,
            parent_pid,
            child_tid,
            child_pid,
        },
        (CallbackPhase::Callback, Some(TailFact::Completed(_) | TailFact::Deferred { .. })) => {
            CallbackDecision::Refused(
                "tail_inject of a call that does not end the guest, outside a syscall handler",
            )
        }
        (CallbackPhase::Callback, Some(TailFact::ForkChild { .. })) => {
            CallbackDecision::Refused("a plain fork injected outside a syscall handler")
        }
        (_, Some(TailFact::Established(_))) => {
            unreachable!("ending handled before callback result")
        }
    }
}

/// Conversion of a Tool syscall result, before frontend writeback or re-entry.
#[derive(Debug)]
pub enum SyscallResult {
    /// Final Linux result, including an ordinary negative errno.
    Value(i64),
    /// Drop the completed attempt and invoke the handler with a fresh borrow.
    Restart,
    /// A non-errno Tool error, which must remain fatal to the run.
    Fatal(Error),
}

/// Preserve the trap host's syscall conversion and private ERESTARTSYS rule.
pub fn classify_syscall_result(result: Result<i64, Error>) -> SyscallResult {
    match result {
        Ok(value) => SyscallResult::Value(value),
        Err(error) => match error.into_errno() {
            Ok(Errno::ERESTARTSYS) => SyscallResult::Restart,
            Ok(errno) => SyscallResult::Value(-i64::from(errno.into_raw())),
            Err(error) => SyscallResult::Fatal(error),
        },
    }
}

/// Linux's observable normal exit status from the raw syscall's first operand.
pub fn exit_status_from_raw(code: u64) -> ExitStatus {
    ExitStatus::Exited((code & 0xff) as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> [Option<TailFact<u64>>; 5] {
        [
            None,
            Some(TailFact::Completed(-9)),
            Some(TailFact::Deferred {
                number: 1,
                args: [2, 3, 4, 5, 6, 7],
            }),
            Some(TailFact::Established(23)),
            Some(TailFact::ForkChild {
                parent_tid: Pid::from_raw(11),
                parent_pid: Pid::from_raw(12),
                child_tid: Pid::from_raw(13),
                child_pid: Pid::from_raw(14),
            }),
        ]
    }

    #[test]
    fn ready_discards_only_nonending_facts_and_established_beats_later_refusal() {
        for phase in [CallbackPhase::Syscall, CallbackPhase::Callback] {
            for (index, fact) in facts().into_iter().enumerate() {
                let decision = classify_callback(phase, Poll::Ready(71), fact, None);
                assert_eq!(
                    decision,
                    if index == 3 {
                        CallbackDecision::Established(23)
                    } else {
                        CallbackDecision::Ready(71)
                    }
                );
            }
            for poll in [Poll::Ready(71), Poll::Pending] {
                for (index, fact) in facts().into_iter().enumerate() {
                    assert_eq!(
                        classify_callback(phase, poll, fact, Some("refused")),
                        if index == 3 {
                            CallbackDecision::Established(23)
                        } else {
                            CallbackDecision::Refused("refused")
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn pending_syscalls_consume_completed_deferred_and_all_four_fork_identities() {
        let decisions = facts()
            .map(|fact| classify_callback(CallbackPhase::Syscall, Poll::<()>::Pending, fact, None));
        assert_eq!(
            decisions,
            [
                CallbackDecision::Wait,
                CallbackDecision::Completed(-9),
                CallbackDecision::Deferred {
                    number: 1,
                    args: [2, 3, 4, 5, 6, 7]
                },
                CallbackDecision::Established(23),
                CallbackDecision::ForkChild {
                    parent_tid: Pid::from_raw(11),
                    parent_pid: Pid::from_raw(12),
                    child_tid: Pid::from_raw(13),
                    child_pid: Pid::from_raw(14),
                },
            ]
        );
        for (index, fact) in facts().into_iter().enumerate() {
            let decision =
                classify_callback(CallbackPhase::Callback, Poll::<()>::Pending, fact, None);
            match index {
                0 => assert_eq!(decision, CallbackDecision::Wait),
                3 => assert_eq!(decision, CallbackDecision::Established(23)),
                _ => assert!(matches!(decision, CallbackDecision::Refused(_))),
            }
        }
    }

    #[test]
    fn result_conversion_preserves_value_errno_restart_and_fatal_error() {
        assert!(matches!(
            classify_syscall_result(Ok(-512)),
            SyscallResult::Value(-512)
        ));
        assert!(matches!(
            classify_syscall_result(Ok(71)),
            SyscallResult::Value(71)
        ));
        assert!(matches!(
            classify_syscall_result(Err(Errno::ERESTARTSYS.into())),
            SyscallResult::Restart
        ));
        assert!(
            matches!(classify_syscall_result(Err(Errno::EACCES.into())), SyscallResult::Value(value) if value == -i64::from(Errno::EACCES.into_raw()))
        );
        match classify_syscall_result(Err(std::io::Error::other("fatal witness").into())) {
            SyscallResult::Fatal(Error::Io(error)) => {
                assert_eq!(error.to_string(), "fatal witness")
            }
            other => panic!("fatal error changed: {other:?}"),
        }
        assert_eq!(exit_status_from_raw(0x123), ExitStatus::Exited(0x23));
        assert_eq!(exit_status_from_raw(u64::MAX), ExitStatus::Exited(255));
    }
}
