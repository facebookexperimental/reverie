/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Ordinary operation admission through the actual Tool and MemoryAccess APIs.
//! These controls use host memory and a counting executor, never KVM_RUN.

use std::sync::atomic::AtomicUsize;
use std::task::Context;
use std::task::Waker;

use super::*;
use crate::entry::owner::DriverScope;
use crate::entry::owner::OperationOrigin;

const BASE: u64 = 0x10000;

#[derive(Clone, Copy, Default, Debug)]
enum Operation {
    #[default]
    Rpc,
    Inject,
    TailInject,
    Defer,
    ChildSignal,
    AlarmSignal,
    Stack,
    Observe,
    DequeuePoison,
}

#[derive(Default)]
struct Counts {
    constructed: AtomicUsize,
    rpc_polls: AtomicUsize,
    rpc_drops: AtomicUsize,
    callback_drops: AtomicUsize,
    completed: AtomicUsize,
    invalidations: AtomicUsize,
    preparations: AtomicUsize,
    dispatches: AtomicUsize,
    effects: AtomicUsize,
    completions: AtomicUsize,
    signal_removals: AtomicUsize,
    signal_acknowledgments: AtomicUsize,
    signal_filters: AtomicUsize,
    signal_reservations: AtomicUsize,
    structured_hooks: AtomicUsize,
    failures: AtomicUsize,
    thread_exits: AtomicUsize,
    process_exits: AtomicUsize,
}

#[derive(Default)]
struct ProbeGlobal {
    counts: Arc<Counts>,
    origin: Mutex<Option<OperationOrigin>>,
    rpc_pending: AtomicBool,
    poison_on_rpc: Mutex<Option<GuestMemory>>,
}

struct RpcFuture<'a>(&'a ProbeGlobal);
impl Future for RpcFuture<'_> {
    type Output = i64;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<i64> {
        self.0.counts.rpc_polls.fetch_add(1, Ordering::SeqCst);
        if let Some(memory) = self.0.poison_on_rpc.lock().unwrap().take() {
            memory.entry_gate().poison(
                memory.entry_origin(),
                Error::GuestClock("RPC poll private cause".into()),
            );
            let mut byte = [0xa5];
            assert_eq!(
                MemoryAccess::read(
                    &memory.user(),
                    Addr::from_raw(BASE as usize).unwrap(),
                    &mut byte,
                ),
                Err(Errno::EIO)
            );
        }
        if self.0.rpc_pending.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Poll::Ready(41)
        }
    }
}
impl Drop for RpcFuture<'_> {
    fn drop(&mut self) {
        self.0.counts.rpc_drops.fetch_add(1, Ordering::SeqCst);
    }
}

// The explicit async_trait ABI counts construction separately from polling.
impl GlobalTool for ProbeGlobal {
    type Request = ();
    type Response = i64;
    type Config = ();

    fn receive_rpc<'life0, 'async_trait>(
        &'life0 self,
        _: Pid,
        _: (),
    ) -> Pin<Box<dyn Future<Output = i64> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.counts.constructed.fetch_add(1, Ordering::SeqCst);
        Box::pin(RpcFuture(self))
    }

    fn report_backend_failure(&self, _: reverie::BackendFailure) {
        assert_eq!(self.counts.callback_drops.load(Ordering::SeqCst), 1);
        assert!(
            self.origin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .callback_dropped()
        );
        self.counts.failures.fetch_add(1, Ordering::SeqCst);
    }
}

struct CallbackDrop(Arc<ProbeGlobal>);
impl Drop for CallbackDrop {
    fn drop(&mut self) {
        assert_eq!(self.0.counts.failures.load(Ordering::SeqCst), 0);
        assert!(
            !self
                .0
                .origin
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .callback_dropped()
        );
        self.0.counts.callback_drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct ProbeTool {
    operation: Operation,
    global: Arc<ProbeGlobal>,
    poison: bool,
    retained_memory: bool,
    memory: Option<GuestMemory>,
    prior: Option<Arc<Error>>,
    signal: Option<SharedHandlerSignal>,
}

impl ProbeTool {
    fn poison_and_read<G: Guest<Self>>(&self, guest: &G) {
        let memory = self.memory.as_ref().unwrap();
        memory.entry_gate().poison(
            memory.entry_origin(),
            Error::GuestClock("caught memory adapter EIO".into()),
        );
        let mut bytes = [0xa5];
        // The old mapping case uses the actual retained UserMemory adapter;
        // the ordinary case obtains the real adapter from Guest::memory.
        let result = if self.retained_memory {
            MemoryAccess::read(
                &memory.user(),
                Addr::from_raw(BASE as usize).unwrap(),
                &mut bytes,
            )
        } else {
            guest
                .memory()
                .read(Addr::from_raw(BASE as usize).unwrap(), &mut bytes)
        };
        assert_eq!(result, Err(Errno::EIO));
        assert_eq!(bytes, [0xa5]);
    }
}

#[reverie::tool]
impl Tool for ProbeTool {
    type GlobalState = ProbeGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: reverie::syscalls::Syscall,
    ) -> std::result::Result<i64, reverie::Error> {
        let _drop = CallbackDrop(self.global.clone());
        if self.poison
            && !matches!(
                self.operation,
                Operation::Observe | Operation::DequeuePoison
            )
        {
            self.poison_and_read(guest);
        }
        if let Some(prior) = &self.prior {
            *self.signal.as_ref().unwrap().lock().unwrap() = Some(HandlerSignal::RuntimeError(
                Error::SharedFailure(prior.clone()),
            ));
        }
        match self.operation {
            Operation::Rpc => {
                assert_eq!(guest.send_rpc(()).await, 41);
            }
            Operation::Inject => {
                assert_eq!(
                    guest
                        .inject(reverie::syscalls::Close::new().with_fd(9))
                        .await?,
                    0
                );
            }
            Operation::TailInject => {
                guest
                    .tail_inject(reverie::syscalls::Close::new().with_fd(9))
                    .await;
            }
            Operation::Defer => {
                guest.defer_signal_delivery(event()).await?;
            }
            Operation::ChildSignal => {
                let _ = guest.queue_child_exit_signal(event()).await;
            }
            Operation::AlarmSignal => {
                let _ = guest.queue_process_alarm_signal(event()).await;
            }
            Operation::Stack => {
                let _stack = guest.stack().await;
            }
            Operation::Observe | Operation::DequeuePoison => {
                let _ = guest
                    .observe_parked_signal(site(), reverie::ParkedObservationLease { nonce: 13 })
                    .await;
            }
        }
        self.global.counts.completed.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        if matches!(self.operation, Operation::DequeuePoison) {
            self.poison_and_read(guest);
        }
        assert_eq!(guest.send_rpc(()).await, 41);
        Ok(())
    }

    async fn on_exit_thread<G: GlobalRPC<ProbeGlobal>>(
        &self,
        tid: Pid,
        global: &G,
        _: (),
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        assert_eq!(tid, Pid::from_raw(17));
        assert_eq!(status, ExitStatus::Exited(1));
        assert_eq!(self.global.counts.failures.load(Ordering::SeqCst), 1);
        assert_eq!(global.send_rpc(()).await, 41);
        self.global
            .counts
            .thread_exits
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<ProbeGlobal>>(
        self,
        pid: Pid,
        global: &G,
        status: ExitStatus,
    ) -> std::result::Result<(), reverie::Error> {
        assert_eq!(pid, Pid::from_raw(17));
        assert_eq!(status, ExitStatus::Exited(1));
        assert_eq!(self.global.counts.thread_exits.load(Ordering::SeqCst), 1);
        assert_eq!(global.send_rpc(()).await, 41);
        self.global
            .counts
            .process_exits
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> std::result::Result<Option<SignalEvent>, Errno> {
        self.global
            .counts
            .structured_hooks
            .fetch_add(1, Ordering::SeqCst);
        if self.poison {
            self.poison_and_read(guest);
        }
        Ok(Some(event))
    }
}

fn event() -> SignalEvent {
    let mut info = [0; 128];
    info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    SignalEvent::new(
        libc::SIGALRM,
        info,
        reverie::SignalTarget::Process {
            pid: Pid::from_raw(17),
        },
    )
    .unwrap()
}

fn site() -> reverie::CallbackSignalSite {
    reverie::CallbackSignalSite {
        process: reverie::SignalProcessId {
            tgid: Pid::from_raw(17),
            generation: 2,
        },
        tid: Pid::from_raw(17),
        task_generation: 3,
        callback_nonce: 5,
        boundary_nonce: 7,
    }
}

fn dequeue() -> reverie::SignalDequeue {
    reverie::SignalDequeue {
        process: site().process,
        sequence: 19,
        consumer: reverie::SignalConsumer::ReturnToUser,
        domain: reverie::PendingDomain::Process,
        event: event(),
    }
}

struct ProbeExecutor {
    counts: Arc<Counts>,
    failure: FailureContext,
    pending_dequeue: bool,
    ledger: Vec<reverie::SignalDequeue>,
}
impl GuestSyscallExecutor<ProbeTool> for ProbeExecutor {
    fn read_clock(&self) -> Result<u64> {
        Ok(1)
    }
    fn failure_subscription(&self) -> Option<crate::failure::FailureSubscription> {
        Some(self.failure.run.subscribe())
    }
    fn invalidate_polled_read_attempt(&mut self) {
        self.counts.invalidations.fetch_add(1, Ordering::SeqCst);
    }
    fn prepare_signal_effects(&mut self) -> std::result::Result<(), Errno> {
        self.counts.preparations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn execute(&mut self, request: &SyscallRequest, _: &GuestMemory) -> Result<i64> {
        assert_eq!(request.number(), libc::SYS_close as u64);
        assert_eq!(request.args()[0], 9);
        self.counts.dispatches.fetch_add(1, Ordering::SeqCst);
        self.counts.effects.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
    fn complete_injection<'a>(
        &'a mut self,
        _: ToolContext<'a, ProbeTool>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        ProbeTool: 'a,
    {
        self.counts.completions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Ok(InjectionCompletion::Returns {
                syscall_result: None,
            })
        })
    }
    fn defer_signal_delivery(&mut self, _: SignalEvent) -> std::result::Result<(), Errno> {
        self.counts.effects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn queue_child_exit_signal(&mut self, _: SignalEvent) -> reverie::ChildExitSignalOutcome {
        self.counts.effects.fetch_add(1, Ordering::SeqCst);
        reverie::ChildExitSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ChildExitSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }
    fn queue_process_alarm_signal(&mut self, _: SignalEvent) -> reverie::ProcessAlarmSignalOutcome {
        self.counts.effects.fetch_add(1, Ordering::SeqCst);
        reverie::ProcessAlarmSignalOutcome::RejectedBeforeCommit {
            kind: reverie::ProcessAlarmSignalErrorKind::Unsupported,
            errno: Errno::ENOSYS,
        }
    }
    fn parked_signal_site(&self) -> Option<reverie::CallbackSignalSite> {
        Some(site())
    }
    fn admit_signal_observation(
        &mut self,
        actual: reverie::CallbackSignalSite,
        _: reverie::ParkedObservationLease,
    ) -> std::result::Result<(), Errno> {
        assert_eq!(actual, site());
        Ok(())
    }
    fn take_signal_for_observation(&mut self) -> std::result::Result<Option<PendingSignal>, Errno> {
        self.counts.signal_removals.fetch_add(1, Ordering::SeqCst);
        self.pending_dequeue = true;
        Ok(Some(PendingSignal {
            event: event(),
            domain: crate::executor::PendingSignalDomain::Process,
        }))
    }
    fn signal_dequeue_front(&self) -> Option<reverie::SignalDequeue> {
        self.pending_dequeue.then(dequeue)
    }
    fn retain_signal_dequeue(&mut self, effect: reverie::SignalDequeue) {
        self.ledger.push(effect);
    }
    fn acknowledge_signal_dequeue(
        &mut self,
        effect: reverie::SignalDequeue,
    ) -> std::result::Result<(), Errno> {
        assert_eq!(effect, dequeue());
        self.pending_dequeue = false;
        self.counts
            .signal_acknowledgments
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn filter_signal_replacement(
        &mut self,
        event: SignalEvent,
        domain: crate::executor::PendingSignalDomain,
    ) -> std::result::Result<Option<PendingSignal>, Errno> {
        self.counts.signal_filters.fetch_add(1, Ordering::SeqCst);
        Ok(Some(PendingSignal { event, domain }))
    }
    fn reserve_signal_delivery(
        &mut self,
        _: PendingSignal,
        _: reverie::DequeueId,
        _: bool,
    ) -> std::result::Result<reverie::PreparedSignalToken, Errno> {
        self.counts
            .signal_reservations
            .fetch_add(1, Ordering::SeqCst);
        Ok(reverie::PreparedSignalToken {
            site: site(),
            selection_nonce: 23,
        })
    }
    fn with_signal_effects(&mut self, cause: Error, raw_result: Option<i64>) -> Error {
        Error::SignalEffects {
            cause: Arc::new(cause),
            dequeues: self.ledger.clone(),
            acknowledged_through: if self.ledger.is_empty() { 0 } else { 19 },
            publications: Vec::new(),
            raw_result,
            context: None,
        }
    }
}

struct Fixture {
    memory: GuestMemory,
    old_memory: GuestMemory,
    scope: DriverScope,
    callback: crate::entry::owner::CallbackScope,
    global: Arc<ProbeGlobal>,
    failure: FailureContext,
}
impl Fixture {
    fn new() -> Self {
        let scope = DriverScope::new();
        let callback = scope.owner().begin_callback(None).unwrap();
        let global = Arc::new(ProbeGlobal::default());
        *global.origin.lock().unwrap() = Some(callback.origin());
        let failure = FailureContext::new(
            RunFailure::new(&global),
            Pid::from_raw(17),
            Pid::from_raw(17),
        );
        let make_memory = || {
            let mut memory = GuestMemory::new(BASE, TOOL_STACK_SIZE as usize).unwrap();
            memory.set_operation_origin(Some(callback.origin()));
            memory.set_failure_context(Some(failure.clone()));
            memory
        };
        Self {
            memory: make_memory(),
            old_memory: make_memory(),
            scope,
            callback,
            global,
            failure,
        }
    }
    fn executor(&self) -> ProbeExecutor {
        ProbeExecutor {
            counts: self.global.counts.clone(),
            failure: self.failure.clone(),
            pending_dequeue: false,
            ledger: Vec::new(),
        }
    }
}

fn run_callback(operation: Operation, poison: bool, old_mapping: bool, prior: Option<Arc<Error>>) {
    let fixture = Fixture::new();
    let poisoned = if old_mapping {
        &fixture.old_memory
    } else {
        &fixture.memory
    };
    let signal = Arc::new(Mutex::new(None));
    let tool = Arc::new(ProbeTool {
        operation,
        global: fixture.global.clone(),
        poison,
        retained_memory: old_mapping,
        memory: Some(poisoned.clone()),
        prior: prior.clone(),
        signal: Some(signal.clone()),
    });
    let mut executor = fixture.executor();
    let mut state = ();
    let config = ();
    let subscriptions = Subscription::none();
    let starts = Arc::new(Mutex::new(Vec::new()));
    let stack_checked_out = Arc::new(AtomicBool::new(false));
    let mut guest = KvmGuest::new(
        Pid::from_raw(17),
        Pid::from_raw(17),
        tool.clone(),
        fixture.memory.clone(),
        &[],
        unsafe { std::mem::zeroed() },
        &mut state,
        &mut executor,
        fixture.global.as_ref(),
        Some(fixture.global.clone()),
        &config,
        &subscriptions,
        signal.clone(),
        starts.clone(),
        BASE + TOOL_STACK_SIZE,
        stack_checked_out.clone(),
    );
    let completion = futures::executor::block_on(drive_handler_completion_from(
        || {
            tool.handle_syscall_event(
                &mut guest,
                reverie::syscalls::Close::new().with_fd(9).into(),
            )
        },
        signal,
        starts,
        std::future::pending(),
    ));
    assert!(completion.panics.is_empty());
    drop(guest);
    let counts = &fixture.global.counts;
    assert_eq!(counts.callback_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.failures.load(Ordering::SeqCst), 0);
    assert!(!fixture.callback.origin().callback_dropped());
    assert!(!stack_checked_out.load(Ordering::SeqCst));
    if poison {
        let Some(HandlerOutcome::RuntimeError(error)) = completion.output else {
            panic!("caught fatal memory result resumed {operation:?}");
        };
        let cause = poisoned.entry_gate().pending_failure().unwrap().causes()[0].clone();
        assert!(crate::failure::references_shared_error(&error, &cause));
        if let Some(prior) = prior {
            assert!(crate::failure::references_shared_error(&error, &prior));
        }
        assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
        assert_eq!(counts.invalidations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.preparations.load(Ordering::SeqCst), 0);
        assert_eq!(counts.dispatches.load(Ordering::SeqCst), 0);
        assert_eq!(counts.effects.load(Ordering::SeqCst), 0);
        assert_eq!(counts.completions.load(Ordering::SeqCst), 0);
        if matches!(operation, Operation::Observe | Operation::DequeuePoison) {
            assert_eq!(counts.constructed.load(Ordering::SeqCst), 1);
            assert_eq!(counts.signal_removals.load(Ordering::SeqCst), 1);
            assert_eq!(counts.signal_acknowledgments.load(Ordering::SeqCst), 1);
            assert_eq!(
                counts.structured_hooks.load(Ordering::SeqCst),
                usize::from(matches!(operation, Operation::Observe))
            );
            assert_eq!(counts.signal_filters.load(Ordering::SeqCst), 0);
            assert_eq!(counts.signal_reservations.load(Ordering::SeqCst), 0);
            let Error::SignalEffects {
                dequeues,
                acknowledged_through,
                ..
            } = &error
            else {
                panic!("private interruption lost actual signal ledger");
            };
            assert_eq!(dequeues, &[dequeue()]);
            assert_eq!(*acknowledged_through, 19);
        } else {
            assert_eq!(counts.constructed.load(Ordering::SeqCst), 0);
            assert_eq!(counts.rpc_polls.load(Ordering::SeqCst), 0);
        }
        drop(fixture.callback);
        let error = fixture
            .failure
            .publish("operation admission control", error);
        assert!(crate::failure::references_shared_error(&error, &cause));
        assert_eq!(counts.failures.load(Ordering::SeqCst), 1);
        let before = counts.constructed.load(Ordering::SeqCst);
        let consuming = KvmGlobal {
            tid: Pid::from_raw(17),
            state: fixture.global.as_ref(),
            config: &config,
        };
        futures::executor::block_on(tool.on_exit_thread(
            Pid::from_raw(17),
            &consuming,
            (),
            ExitStatus::Exited(1),
        ))
        .unwrap();
        let tool = Arc::try_unwrap(tool)
            .ok()
            .expect("callback retained process Tool");
        futures::executor::block_on(tool.on_exit_process(
            Pid::from_raw(17),
            &consuming,
            ExitStatus::Exited(1),
        ))
        .unwrap();
        assert_eq!(counts.constructed.load(Ordering::SeqCst), before + 2);
        assert_eq!(counts.thread_exits.load(Ordering::SeqCst), 1);
        assert_eq!(counts.process_exits.load(Ordering::SeqCst), 1);
    } else {
        assert!(matches!(
            completion.output,
            Some(HandlerOutcome::Returned(Ok(0)))
        ));
        assert_eq!(counts.completed.load(Ordering::SeqCst), 1);
        match operation {
            Operation::Rpc => assert_eq!(counts.constructed.load(Ordering::SeqCst), 1),
            Operation::Inject => {
                assert_eq!(counts.dispatches.load(Ordering::SeqCst), 1);
                assert_eq!(counts.effects.load(Ordering::SeqCst), 1);
                assert_eq!(counts.completions.load(Ordering::SeqCst), 1);
            }
            Operation::Observe | Operation::DequeuePoison => {
                assert_eq!(counts.signal_removals.load(Ordering::SeqCst), 1);
                assert_eq!(counts.signal_acknowledgments.load(Ordering::SeqCst), 1);
                assert_eq!(counts.signal_filters.load(Ordering::SeqCst), 1);
                assert_eq!(counts.signal_reservations.load(Ordering::SeqCst), 1);
            }
            _ => {}
        }
        drop(fixture.callback);
    }
    let retirement = fixture.scope.retire();
    assert!(retirement.result.is_ok());
    retirement.notification.notify();
}

#[test]
fn caught_memory_failure_refuses_ready_rpc_before_construction() {
    run_callback(Operation::Rpc, true, false, None);
}

#[test]
fn caught_memory_failure_refuses_injection_before_executor_mutation() {
    run_callback(Operation::Inject, true, false, None);
    run_callback(Operation::TailInject, true, false, None);
}

#[test]
fn owner_failure_from_other_mapping_refuses_rpc_and_injection() {
    run_callback(Operation::Rpc, true, true, None);
    run_callback(Operation::Inject, true, true, None);
}

#[test]
fn caught_memory_failure_refuses_signal_queue_and_stack_admission() {
    for operation in [
        Operation::Defer,
        Operation::ChildSignal,
        Operation::AlarmSignal,
        Operation::Stack,
    ] {
        run_callback(operation, true, false, None);
    }
}

#[test]
fn private_admission_retains_previous_signal_effects_error() {
    let prior = Arc::new(Error::SignalEffects {
        cause: Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
            libc::ENOSPC,
        ))),
        dequeues: vec![dequeue()],
        acknowledged_through: 19,
        publications: Vec::new(),
        raw_result: Some(-(libc::EFAULT as i64)),
        context: None,
    });
    run_callback(Operation::Rpc, true, false, Some(prior));
}

#[test]
fn ready_nested_signal_hook_cannot_reserve_after_caught_memory_failure() {
    run_callback(Operation::Observe, true, false, None);
}

#[test]
fn healthy_rpc_injection_and_parked_observation_still_complete() {
    for operation in [Operation::Rpc, Operation::Inject, Operation::Observe] {
        run_callback(operation, false, false, None);
    }
}

#[test]
fn private_failure_does_not_cancel_owned_dequeue_rpc_or_consuming_hooks() {
    run_callback(Operation::DequeuePoison, true, false, None);
}

fn rpc_interruption(poison_when_ready: bool) {
    let fixture = Fixture::new();
    fixture
        .global
        .rpc_pending
        .store(!poison_when_ready, Ordering::SeqCst);
    if poison_when_ready {
        *fixture.global.poison_on_rpc.lock().unwrap() = Some(fixture.memory.clone());
    }
    let signal = Arc::new(Mutex::new(None));
    let tool = Arc::new(ProbeTool {
        global: fixture.global.clone(),
        ..ProbeTool::default()
    });
    let mut executor = fixture.executor();
    let mut state = ();
    let subscriptions = Subscription::none();
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut guest = KvmGuest::new(
        Pid::from_raw(17),
        Pid::from_raw(17),
        tool.clone(),
        fixture.memory.clone(),
        &[],
        unsafe { std::mem::zeroed() },
        &mut state,
        &mut executor,
        fixture.global.as_ref(),
        Some(fixture.global.clone()),
        &(),
        &subscriptions,
        signal.clone(),
        starts.clone(),
        BASE + TOOL_STACK_SIZE,
        Arc::new(AtomicBool::new(false)),
    );
    let mut driven = Box::pin(drive_handler_completion_from(
        || {
            tool.handle_syscall_event(
                &mut guest,
                reverie::syscalls::Close::new().with_fd(9).into(),
            )
        },
        signal,
        starts,
        std::future::pending(),
    ));
    let mut context = Context::from_waker(Waker::noop());
    let completion = if poison_when_ready {
        let Poll::Ready(completion) = driven.as_mut().poll(&mut context) else {
            panic!("RPC poll captured failure without returning its callback to the driver");
        };
        completion
    } else {
        assert!(driven.as_mut().poll(&mut context).is_pending());
        assert_eq!(fixture.global.counts.rpc_polls.load(Ordering::SeqCst), 1);
        fixture.memory.entry_gate().poison(
            fixture.memory.entry_origin(),
            Error::GuestClock("private cause before RPC resume".into()),
        );
        let mut byte = [0xa5];
        assert_eq!(
            MemoryAccess::read(
                &fixture.memory.user(),
                Addr::from_raw(BASE as usize).unwrap(),
                &mut byte,
            ),
            Err(Errno::EIO)
        );
        let Poll::Ready(completion) = driven.as_mut().poll(&mut context) else {
            panic!("suspended RPC did not observe private failure");
        };
        completion
    };
    drop(driven);
    drop(guest);
    assert!(completion.panics.is_empty());
    let Some(HandlerOutcome::RuntimeError(error)) = completion.output else {
        panic!("RPC yielded an ordinary response after private failure");
    };
    let cause = fixture
        .memory
        .entry_gate()
        .pending_failure()
        .unwrap()
        .causes()[0]
        .clone();
    assert!(crate::failure::references_shared_error(&error, &cause));
    let counts = &fixture.global.counts;
    assert_eq!(counts.constructed.load(Ordering::SeqCst), 1);
    assert_eq!(counts.rpc_polls.load(Ordering::SeqCst), 1);
    assert_eq!(counts.rpc_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.callback_drops.load(Ordering::SeqCst), 1);
    assert_eq!(counts.completed.load(Ordering::SeqCst), 0);
    assert_eq!(counts.failures.load(Ordering::SeqCst), 0);
    drop(fixture.callback);
    let error = fixture.failure.publish("RPC interruption control", error);
    assert!(crate::failure::references_shared_error(&error, &cause));
    assert_eq!(counts.failures.load(Ordering::SeqCst), 1);
    let retirement = fixture.scope.retire();
    assert!(retirement.result.is_ok());
    retirement.notification.notify();
}

#[test]
fn pending_rpc_checks_private_failure_before_polling_again() {
    rpc_interruption(false);
}

#[test]
fn ready_rpc_cannot_return_response_after_capturing_private_failure() {
    rpc_interruption(true);
}

#[test]
fn stack_commit_refuses_another_mapping_failure_without_writing() {
    let fixture = Fixture::new();
    let checked_out = Arc::new(AtomicBool::new(false));
    let mut stack = KvmStack::new(
        fixture.memory.clone(),
        BASE + TOOL_STACK_SIZE,
        checked_out.clone(),
    );
    let address = stack.push(0x7788_u64);
    fixture.old_memory.entry_gate().poison(
        fixture.old_memory.entry_origin(),
        Error::GuestClock("retained other mapping".into()),
    );
    let mut byte = [0xa5];
    assert_eq!(
        MemoryAccess::read(
            &fixture.old_memory.user(),
            Addr::from_raw(BASE as usize).unwrap(),
            &mut byte,
        ),
        Err(Errno::EIO)
    );
    assert!(matches!(stack.commit(), Err(Errno::EIO)));
    assert!(!checked_out.load(Ordering::SeqCst));
    let mut untouched = [0xa5; 8];
    assert_eq!(
        MemoryAccess::read(&fixture.memory.user(), address.cast::<u8>(), &mut untouched,),
        Ok(8)
    );
    assert_eq!(untouched, [0; 8]);
    drop(fixture.callback);
    let retirement = fixture.scope.retire();
    assert!(retirement.result.is_ok());
    retirement.notification.notify();
}

#[test]
fn private_admission_preserves_already_selected_nonlocal_disposition() {
    let fixture = Fixture::new();
    fixture.memory.entry_gate().poison(
        fixture.memory.entry_origin(),
        Error::GuestClock("cause after nonlocal selection".into()),
    );
    let signal = Arc::new(Mutex::new(Some(HandlerSignal::TailInjected {
        result: Ok(73),
        image_replaced: true,
        process_exited: false,
    })));
    let tool = Arc::new(ProbeTool::default());
    let mut executor = fixture.executor();
    let mut state = ();
    let subscriptions = Subscription::none();
    let guest = KvmGuest::new(
        Pid::from_raw(17),
        Pid::from_raw(17),
        tool,
        fixture.memory.clone(),
        &[],
        unsafe { std::mem::zeroed() },
        &mut state,
        &mut executor,
        fixture.global.as_ref(),
        Some(fixture.global.clone()),
        &(),
        &subscriptions,
        signal.clone(),
        Arc::new(Mutex::new(Vec::new())),
        BASE + TOOL_STACK_SIZE,
        Arc::new(AtomicBool::new(false)),
    );
    let mut rpc = Box::pin(guest.send_rpc(()));
    assert!(
        rpc.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(fixture.global.counts.constructed.load(Ordering::SeqCst), 0);
    assert!(matches!(
        *signal.lock().unwrap(),
        Some(HandlerSignal::TailInjected {
            result: Ok(73),
            image_replaced: true,
            process_exited: false,
        })
    ));
    assert_eq!(fixture.scope.owner().pending().len(), 1);
    drop(rpc);
    drop(guest);
    drop(fixture.callback);
    let retirement = fixture.scope.retire();
    assert_eq!(retirement.pending.len(), 1);
    assert!(retirement.result.is_ok());
    retirement.notification.notify();
}
