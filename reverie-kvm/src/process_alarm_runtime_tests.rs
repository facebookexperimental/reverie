/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use reverie::ProcessAlarmSignalDisposition;
use reverie::ProcessAlarmSignalErrorKind;
use reverie::ProcessAlarmSignalOutcome;
use reverie::ProcessAlarmSignalReceipt;

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
    outcome: ProcessAlarmSignalOutcome,
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
    fn queue_process_alarm_signal(&mut self, event: SignalEvent) -> ProcessAlarmSignalOutcome {
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
fn process_alarm_signal_into_guest_forwards_complete_outcomes_without_guest_effects() {
    use ProcessAlarmSignalDisposition::Caught;
    use ProcessAlarmSignalDisposition::DefaultFatal;
    use ProcessAlarmSignalDisposition::Ignored;
    use ProcessAlarmSignalErrorKind::Backend;
    use ProcessAlarmSignalErrorKind::Invalid;
    use ProcessAlarmSignalErrorKind::Unsupported;
    use ProcessAlarmSignalOutcome::Accepted;
    use ProcessAlarmSignalOutcome::FailedAfterCommit;
    use ProcessAlarmSignalOutcome::RejectedBeforeCommit;
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    let event = SignalEvent::new(
        libc::SIGALRM,
        info,
        reverie::SignalTarget::Process {
            pid: Pid::from_raw(1),
        },
    )
    .unwrap();
    let mut outcomes = Vec::new();
    for blocked in [false, true] {
        for disposition in [Ignored, Caught, DefaultFatal] {
            for coalesced in [false, true] {
                let receipt = ProcessAlarmSignalReceipt {
                    blocked,
                    disposition,
                    coalesced,
                    pending_generation: 7,
                };
                outcomes.push(Accepted(receipt));
                outcomes.push(FailedAfterCommit {
                    errno: Errno::EIO,
                    receipt,
                });
            }
        }
    }
    for (kind, errno) in [
        (Unsupported, Errno::ENOSYS),
        (Invalid, Errno::ESRCH),
        (Backend, Errno::EBADF),
    ] {
        outcomes.push(RejectedBeforeCommit { kind, errno });
    }
    for adapted in [false, true] {
        for &outcome in &outcomes {
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
                        <_ as Guest<LowerTool>>::queue_process_alarm_signal(
                            &mut guest.into_guest(),
                            event,
                        )
                        .await
                    } else {
                        guest.queue_process_alarm_signal(event).await
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

struct UnsupportedExecutor;
impl GuestSyscallExecutor<AdapterTool> for UnsupportedExecutor {
    fn read_clock(&self) -> Result<u64> {
        panic!("refusal read a guest counter")
    }
    fn execute(&mut self, _: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        panic!("refusal executed a guest syscall")
    }
}

#[test]
fn process_alarm_signal_guest_executor_default_refuses_explicitly() {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    let event = SignalEvent::new(
        libc::SIGALRM,
        info,
        reverie::SignalTarget::Process {
            pid: Pid::from_raw(1),
        },
    )
    .unwrap();
    let mut executor = UnsupportedExecutor;
    let memory = GuestMemory::new(0, STACK_CAPACITY).unwrap();
    let mut state = Box::new(());
    let subscriptions = Subscription::none();
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
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
    assert_eq!(
        futures::executor::block_on(guest.queue_process_alarm_signal(event)),
        ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: ProcessAlarmSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    );
    assert!(signal.lock().unwrap().is_none());
    assert!(starts.lock().unwrap().is_empty());
}

#[test]
fn process_alarm_signal_transport_contexts_match_resumable_boundaries() {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGSEGV.to_ne_bytes());
    info[8..12].copy_from_slice(&crate::signal::SEGV_MAPERR.to_ne_bytes());
    let fault = PageZeroFault::for_test(
        SignalEvent::new(
            libc::SIGSEGV,
            info,
            reverie::SignalTarget::Thread {
                pid: Pid::from_raw(1),
                tid: Pid::from_raw(1),
            },
        )
        .unwrap(),
    );
    let contexts = [
        (
            "initial exec",
            ProcessExecutionContext::InitialExec(SyscallRequest::new(
                libc::SYS_execve as u64,
                [0; 6],
            )),
            false,
        ),
        (
            "initial exec completed",
            ProcessExecutionContext::InitialExecCompleted,
            false,
        ),
        ("lifecycle", ProcessExecutionContext::Lifecycle, false),
        (
            "thread entry signal",
            ProcessExecutionContext::ThreadEntrySignal,
            true,
        ),
        (
            "signal",
            ProcessExecutionContext::SignalBoundary(CompletedSyscallBoundary::for_test()),
            true,
        ),
        (
            "fault",
            ProcessExecutionContext::FaultBoundary(Box::new(fault)),
            true,
        ),
        (
            "syscall",
            ProcessExecutionContext::SyscallBoundary(CompletedSyscallBoundary::for_test()),
            true,
        ),
    ];
    for (name, context, expected) in contexts {
        assert_eq!(context.has_resumable_signal_boundary(), expected, "{name}");
    }
}
