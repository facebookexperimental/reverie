/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::ChildExitSignalDisposition;
use reverie::ChildExitSignalErrorKind;
use reverie::ChildExitSignalOutcome;

use super::*;

#[derive(Default)]
struct LowerTool;
#[reverie::tool]
impl Tool for LowerTool {
    type GlobalState = ();
    type ThreadState = ();
}
#[derive(Default)]
struct AdapterTool(LowerTool);
impl AsMut<LowerTool> for AdapterTool {
    fn as_mut(&mut self) -> &mut LowerTool {
        &mut self.0
    }
}
#[reverie::tool]
impl Tool for AdapterTool {
    type GlobalState = ();
    type ThreadState = Box<()>;
}
struct QueueExecutor {
    expected: SignalEvent,
    outcome: ChildExitSignalOutcome,
    calls: usize,
}
impl GuestSyscallExecutor<AdapterTool> for QueueExecutor {
    fn read_clock(&self) -> Result<u64> {
        Err(Error::GuestClock(
            "signal test adapter has no guest counter".into(),
        ))
    }

    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("queue operation executed a guest syscall")
    }
    fn defer_signal_delivery(&mut self, _: SignalEvent) -> std::result::Result<(), Errno> {
        panic!("queue operation used private signal deferral")
    }
    fn queue_child_exit_signal(&mut self, event: SignalEvent) -> ChildExitSignalOutcome {
        assert_eq!(event, self.expected);
        self.calls += 1;
        self.outcome
    }
    fn complete_injection<'a>(
        &'a mut self,
        _: ToolContext<'a, AdapterTool>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        AdapterTool: 'a,
    {
        panic!("queue operation completed an injection")
    }
}

#[test]
fn child_exit_signal_into_guest_forwards_complete_outcomes_without_guest_effects() {
    use ChildExitSignalDisposition::Ignored;
    use ChildExitSignalDisposition::PendingBlocked;
    use ChildExitSignalDisposition::PendingEligible;
    use ChildExitSignalErrorKind::Backend;
    use ChildExitSignalErrorKind::Invalid;
    use ChildExitSignalErrorKind::Unsupported;
    use ChildExitSignalOutcome::Accepted;
    use ChildExitSignalOutcome::FailedAfterCommit;
    use ChildExitSignalOutcome::RejectedBeforeCommit;
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGCHLD.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::CLD_EXITED.to_ne_bytes());
    info[16..20].copy_from_slice(&41_i32.to_ne_bytes());
    info[24..28].copy_from_slice(&37_i32.to_ne_bytes());
    info[127] = 0xa5;
    let event = SignalEvent::new(
        libc::SIGCHLD,
        info,
        reverie::SignalTarget::Process {
            pid: Pid::from_raw(1),
        },
    )
    .unwrap();
    let outcomes = [
        Accepted {
            disposition: Ignored,
            pending_generation: 3,
            coalesced: false,
        },
        Accepted {
            disposition: PendingBlocked,
            pending_generation: 4,
            coalesced: true,
        },
        Accepted {
            disposition: PendingEligible,
            pending_generation: 5,
            coalesced: false,
        },
        RejectedBeforeCommit {
            kind: Unsupported,
            errno: Errno::ENOSYS,
        },
        RejectedBeforeCommit {
            kind: Invalid,
            errno: Errno::ESRCH,
        },
        RejectedBeforeCommit {
            kind: Backend,
            errno: Errno::EBADF,
        },
        FailedAfterCommit {
            errno: Errno::EIO,
            pending_generation: 7,
        },
    ];
    for adapted in [false, true] {
        for outcome in outcomes {
            let mut executor = QueueExecutor {
                expected: event,
                outcome,
                calls: 0,
            };
            let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
            let mut state = Box::new(());
            let subscriptions = Subscription::none();
            let signal = Arc::new(Mutex::new(None));
            let starts = Arc::new(Mutex::new(Vec::new()));
            let (sender, receiver) = std::sync::mpsc::channel();
            starts.lock().unwrap().push(PendingChildStart::tool_thread(
                2,
                ChildStartGate::new(sender),
            ));
            let observed = {
                let mut guest = KvmGuest::<AdapterTool>::new(
                    Pid::from_raw(1),
                    Pid::from_raw(1),
                    Arc::new(AdapterTool::default()),
                    memory,
                    &[],
                    unsafe { std::mem::zeroed() },
                    &mut state,
                    &mut executor,
                    &(),
                    None,
                    &(),
                    &subscriptions,
                    signal.clone(),
                    starts.clone(),
                    crate::bootstrap::TOOL_STACK_TOP,
                    Arc::new(AtomicBool::new(false)),
                );
                futures::executor::block_on(async {
                    if adapted {
                        <_ as Guest<LowerTool>>::queue_child_exit_signal(
                            &mut guest.into_guest(),
                            event,
                        )
                        .await
                    } else {
                        guest.queue_child_exit_signal(event).await
                    }
                })
            };
            assert_eq!(observed, outcome, "adapted={adapted}");
            assert_eq!(executor.calls, 1);
            assert!(signal.lock().unwrap().is_none());
            assert_eq!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            );
            assert_eq!(starts.lock().unwrap().len(), 1);
        }
    }
}
