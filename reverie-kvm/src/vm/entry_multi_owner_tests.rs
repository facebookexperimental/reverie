/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Included within vm::tests for its unchanged minimal_test_elf builder.
mod entry_multi_owner_tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::io::IoSliceMut;
    use std::sync::Condvar;
    use std::sync::Weak;
    use std::task::Context;
    use std::task::Poll;
    use std::task::Waker;
    use std::thread::ThreadId;
    use std::time::Duration;
    use std::time::Instant;

    use futures::FutureExt;
    use futures::task::AtomicWaker;
    use reverie::Guest;
    use reverie::syscalls::Addr;
    use reverie::syscalls::AddrSlice;
    use reverie::syscalls::Errno;
    use reverie::syscalls::MemoryAccess;
    use reverie::syscalls::Sysno;

    use super::*;
    use crate::entry::EntryGate;
    use crate::entry::EntryOrigin;
    use crate::entry::PendingFailure;
    use crate::entry::driver::test_observation;
    use crate::failure::FailureContext;
    use crate::failure::RunFailure;

    const BOUND: Duration = Duration::from_secs(5);
    const MASK: u64 = 0x20_1000;
    const TIMEOUT: u64 = 0x20_1010;
    const BYTES: u64 = 0x20_1030;
    static CASE_LOCK: Mutex<()> = Mutex::new(());
    static ACTIVE: Mutex<Option<Arc<Observed>>> = Mutex::new(None);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Case {
        AFirst,
        CFirst,
        BFirst,
        Healthy,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(usize)]
    enum Role {
        Parent,
        A,
        B,
        C,
    }
    const ROLES: [Role; 4] = [Role::Parent, Role::A, Role::B, Role::C];

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Started(Role),
        Callback(Role),
        Effects(Role),
        Copy(Role),
        Dropped(Role),
        ForeignPending(Role),
        Hook(Role),
        Consumed(Role),
        ProcessConsumed(Role),
        Report(Role, &'static str),
        JoinStart(Role, ThreadId, bool),
        JoinReturn(Role, ThreadId, bool),
        Completed,
    }

    // Every blocking hold has an independent controller release and a finite
    // rescue. Async holds register the actual worker's waker before checking.
    #[derive(Default)]
    struct Release {
        open: Mutex<bool>,
        cv: Condvar,
        wake: AtomicWaker,
    }
    impl Release {
        fn release(&self) {
            *self.open.lock().unwrap_or_else(|p| p.into_inner()) = true;
            self.cv.notify_all();
            self.wake.wake();
        }
        fn blocking(&self) {
            let open = self.open.lock().unwrap();
            let (open, _) = self
                .cv
                .wait_timeout_while(open, BOUND, |open| !*open)
                .unwrap();
            let released = *open;
            drop(open);
            assert!(
                released,
                "controller did not release a real worker callback within its bound"
            );
        }
        async fn waiting(&self) {
            std::future::poll_fn(|cx| {
                self.wake.register(cx.waker());
                if *self.open.lock().unwrap() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }

    #[derive(Clone, Default)]
    struct State {
        identities: [Option<(i32, i32)>; 4],
        states: [Option<Weak<u64>>; 4],
        hosts: [Option<ThreadId>; 4],
        origins: [Option<EntryOrigin>; 4],
        gates: [Option<Arc<EntryGate>>; 4],
        effects: [Vec<reverie::SignalDequeue>; 4],
        signal_tasks: [Option<reverie::SignalTaskIdentity>; 4],
        events: Vec<Event>,
        causes: BTreeMap<&'static str, usize>,
        statuses: [Option<ExitStatus>; 4],
        pending: Option<Arc<PendingFailure>>,
    }
    struct Observed {
        case: Case,
        state: Mutex<State>,
        changed: Condvar,
        prepare: [Release; 4],
        copy_b: Release,
        finish: [Release; 4],
        c_report: Release,
        copy_armed: [AtomicBool; 4],
        registrations: Mutex<Vec<test_observation::Guard>>,
        cause: Arc<Error>,
    }
    impl Observed {
        fn new(case: Case) -> Self {
            Self {
                case,
                state: Mutex::new(State::default()),
                changed: Condvar::new(),
                prepare: std::array::from_fn(|_| Release::default()),
                copy_b: Release::default(),
                finish: std::array::from_fn(|_| Release::default()),
                c_report: Release::default(),
                copy_armed: std::array::from_fn(|_| AtomicBool::new(false)),
                registrations: Mutex::new(Vec::new()),
                cause: Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(
                    libc::EOWNERDEAD,
                ))),
            }
        }
        // Assertions and diagnostic formatting use owned observations. A
        // failed controller assertion must not poison the state that real
        // callback destruction and finite rescue still need.
        fn snapshot(&self) -> State {
            self.state.lock().unwrap().clone()
        }
        fn event(&self, event: Event) {
            self.state.lock().unwrap().events.push(event);
            self.changed.notify_all();
        }
        fn wait(&self, event: Event) {
            let state = self.state.lock().unwrap();
            let (state, _) = self
                .changed
                .wait_timeout_while(state, BOUND, |state| !state.events.contains(&event))
                .unwrap();
            let events = state.events.clone();
            drop(state);
            assert!(
                events.contains(&event),
                "missing {event:?}; observed {events:?}"
            );
        }
        fn has(&self, event: Event) -> bool {
            self.state.lock().unwrap().events.contains(&event)
        }
        fn role(&self, tid: Pid) -> Role {
            let state = self.snapshot();
            *ROLES
                .iter()
                .find(|role| {
                    state.identities[**role as usize].is_some_and(|(_, id)| id == tid.as_raw())
                })
                .unwrap()
        }
        fn origin(&self, role: Role) -> EntryOrigin {
            self.snapshot().origins[role as usize]
                .as_ref()
                .unwrap()
                .clone()
        }
        fn context(&self, role: Role) -> FailureContext {
            self.origin(role).failure.unwrap()
        }
        fn run(&self) -> Arc<RunFailure> {
            self.context(Role::Parent).run
        }
        fn receipt(&self) -> bool {
            let run = self.run();
            let ready = matches!(run.subscribe().now_or_never(), Some(Ok(())));
            assert_eq!(ready, run.published_primary().is_some());
            ready
        }
        fn await_receipt(&self, role: Role) {
            let run = self.run();
            let deadline = Instant::now() + BOUND;
            let mut notification = Box::pin(run.subscribe());
            let mut cx = Context::from_waker(Waker::noop());
            loop {
                match notification.as_mut().poll(&mut cx) {
                    Poll::Ready(Ok(())) => break,
                    Poll::Ready(Err(_)) => panic!("publication notification disconnected"),
                    Poll::Pending => {
                        assert!(Instant::now() < deadline, "no actual publication receipt")
                    }
                }
                std::thread::yield_now();
            }
            let primary = run
                .published_primary()
                .expect("notification precedes published primary");
            match role {
                Role::A => assert!(crate::failure::references_shared_error(
                    &primary,
                    &self.cause
                )),
                Role::B => assert_eq!(
                    io_causes(&primary),
                    vec![("B callback", self.address("B callback"))]
                ),
                Role::C => assert_eq!(
                    io_causes(&primary),
                    vec![("C callback", self.address("C callback"))]
                ),
                Role::Parent => unreachable!(),
            }
        }
        fn address(&self, name: &'static str) -> usize {
            self.snapshot().causes[name]
        }
        fn error(&self, name: &'static str) -> reverie::Error {
            let cause = Box::new(IoCause(name));
            let address = std::ptr::from_ref(cause.as_ref()) as usize;
            let previous = self.state.lock().unwrap().causes.insert(name, address);
            assert!(previous.is_none());
            let cause: Box<dyn std::error::Error + Send + Sync> = cause;
            reverie::Error::Io(std::io::Error::other(cause))
        }
        fn release_all(&self) {
            for release in &self.prepare {
                release.release();
            }
            for release in &self.finish {
                release.release();
            }
            self.copy_b.release();
            self.c_report.release();
        }
        fn observe(&self, role: Role, event: test_observation::Event) {
            match event {
                test_observation::Event::Copy(gate, origin) => {
                    if !self.copy_armed[role as usize].swap(false, Ordering::SeqCst) {
                        return;
                    }
                    assert!(origin.operation.as_ref().unwrap().callback_id().is_some());
                    assert!(!origin.operation.as_ref().unwrap().callback_dropped());
                    assert!(origin.failure.is_some());
                    let (previous_origin, previous_gate) = {
                        let mut state = self.state.lock().unwrap();
                        (
                            state.origins[role as usize].replace(origin.clone()),
                            state.gates[role as usize].replace(gate.clone()),
                        )
                    };
                    assert!(previous_origin.is_none());
                    assert!(previous_gate.is_none());
                    if role == Role::A && self.case != Case::Healthy {
                        gate.poison(origin, Error::SharedFailure(self.cause.clone()));
                        let pending = gate.pending_failure().unwrap();
                        assert!(pending.owner_registered());
                        assert!(pending.causes().iter().any(|error| {
                            crate::failure::references_shared_error(error, &self.cause)
                        }));
                        self.state.lock().unwrap().pending = Some(pending);
                    }
                }
                test_observation::Event::ForeignPending(pending) => {
                    if role != Role::B {
                        return;
                    }
                    let expected = self.snapshot().pending.unwrap();
                    assert!(Arc::ptr_eq(&pending, &expected));
                    assert!(self.has(Event::Dropped(Role::B)));
                    assert!(self.origin(Role::B).operation.unwrap().callback_dropped());
                    self.event(Event::ForeignPending(role));
                }
                test_observation::Event::JoinStarted {
                    target,
                    joiner,
                    process,
                } => {
                    assert_eq!(self.snapshot().hosts[role as usize], Some(target));
                    assert_ne!(target, joiner);
                    assert_eq!(process, role == Role::C);
                    if self.case != Case::Healthy {
                        assert!(self.receipt(), "physical join before real publication");
                    }
                    self.event(Event::JoinStart(role, joiner, process));
                }
                test_observation::Event::JoinReturned {
                    target,
                    joiner,
                    process,
                } => {
                    assert_eq!(self.snapshot().hosts[role as usize], Some(target));
                    self.event(Event::JoinReturn(role, joiner, process));
                }
            }
        }
    }

    #[derive(Debug)]
    struct IoCause(&'static str);
    impl std::fmt::Display for IoCause {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for IoCause {}

    struct ActiveCase(Arc<Observed>);
    impl Drop for ActiveCase {
        fn drop(&mut self) {
            self.0.release_all();
            self.0
                .registrations
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
            ACTIVE.lock().unwrap_or_else(|p| p.into_inner()).take();
        }
    }
    struct CallbackDrop(Arc<Observed>, Role);
    impl Drop for CallbackDrop {
        fn drop(&mut self) {
            assert!(!self.0.has(Event::Dropped(self.1)));
            if let Some(origin) = &self.0.snapshot().origins[self.1 as usize] {
                assert!(!origin.operation.as_ref().unwrap().callback_dropped());
            }
            self.0.event(Event::Dropped(self.1));
        }
    }
    fn observed() -> Arc<Observed> {
        ACTIVE.lock().unwrap().as_ref().unwrap().clone()
    }

    #[derive(Default)]
    struct MultiGlobal {
        observed: Option<Arc<Observed>>,
    }
    #[reverie::global_tool]
    impl GlobalTool for MultiGlobal {
        type Request = ();
        type Response = ();
        type Config = ();
        async fn init_global_state(_: &()) -> Self {
            Self {
                observed: Some(observed()),
            }
        }
        async fn receive_rpc(&self, _: Pid, _: ()) {
            panic!("multi-owner fixture issues no ordinary RPC");
        }
        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            let observed = self.observed.as_ref().unwrap();
            assert_ne!(observed.case, Case::Healthy);
            let role = observed.role(event.tid);
            assert_ne!(
                role,
                Role::Parent,
                "a derived root must not publish another owner's cause"
            );
            assert!(observed.has(Event::Dropped(role)));
            assert!(observed.origin(role).operation.unwrap().callback_dropped());
            observed.event(Event::Report(role, event.phase));
            if role == Role::C && observed.case == Case::CFirst {
                observed.c_report.blocking();
            }
        }
    }

    #[derive(Default)]
    struct MultiTool {
        pid: i32,
    }
    #[reverie::tool]
    impl Tool for MultiTool {
        type GlobalState = MultiGlobal;
        type ThreadState = Arc<u64>;
        fn new(pid: Pid, _: &()) -> Self {
            Self { pid: pid.as_raw() }
        }
        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.syscall(Sysno::getpid);
            subscriptions
        }
        fn observe_signal_dequeues(_: &()) -> bool {
            true
        }
        fn init_thread_state(&self, tid: Pid, parent: Option<(Pid, &Arc<u64>)>) -> Arc<u64> {
            let observed = observed();
            let parent_tid = parent.map(|(parent_tid, parent_state)| {
                assert_eq!(**parent_state, Role::Parent as u64);
                parent_tid.as_raw()
            });
            if parent_tid.is_none() {
                assert_eq!(self.pid, tid.as_raw());
            }
            let (original, previous_identity, previous_state, parent_identity) = {
                let mut state = observed.state.lock().unwrap();
                let role = if parent_tid.is_none() {
                    Role::Parent
                } else if self.pid == tid.as_raw() {
                    Role::C
                } else if state.identities[Role::A as usize].is_none() {
                    Role::A
                } else {
                    Role::B
                };
                let parent_identity = state.identities[Role::Parent as usize];
                let previous_identity =
                    state.identities[role as usize].replace((self.pid, tid.as_raw()));
                let original = Arc::new(role as u64);
                let previous_state = state.states[role as usize].replace(Arc::downgrade(&original));
                (original, previous_identity, previous_state, parent_identity)
            };
            if let Some(parent_tid) = parent_tid {
                assert_eq!(parent_identity.unwrap().1, parent_tid);
            }
            assert!(previous_identity.is_none());
            assert!(previous_state.is_none());
            original
        }
        async fn handle_thread_start<G: Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = observed();
            let role = observed.role(guest.tid());
            let previous_host = observed.state.lock().unwrap().hosts[role as usize]
                .replace(std::thread::current().id());
            assert!(previous_host.is_none());
            let weak = Arc::downgrade(&observed);
            let guard = test_observation::Guard::current(Arc::new(move |event| {
                if let Some(observed) = weak.upgrade() {
                    observed.observe(role, event);
                }
            }));
            observed.registrations.lock().unwrap().push(guard);
            observed.event(Event::Started(role));
            Ok(())
        }
        async fn handle_signal_dequeue<G: Guest<Self>>(
            &self,
            guest: &mut G,
            dequeue: reverie::SignalDequeue,
        ) -> std::result::Result<(), Errno> {
            let observed = observed();
            let role = observed.role(guest.tid());
            assert_ne!(role, Role::Parent);
            let identity = guest
                .signal_task_identity()
                .expect("real signal task lifetime");
            assert_eq!(identity.tid, guest.tid());
            assert_eq!(identity.process, dequeue.process);
            assert_eq!(dequeue.process.tgid, guest.pid());
            assert_eq!(dequeue.consumer, reverie::SignalConsumer::SignalTimedWait);
            assert_eq!(dequeue.domain, reverie::PendingDomain::Thread);
            assert_eq!(dequeue.event.signal(), libc::SIGUSR1);
            let (effects_were_empty, previous_task) = {
                let mut state = observed.state.lock().unwrap();
                let effects_were_empty = state.effects[role as usize].is_empty();
                let previous_task = state.signal_tasks[role as usize].replace(identity);
                state.effects[role as usize].push(dequeue);
                (effects_were_empty, previous_task)
            };
            assert!(effects_were_empty);
            assert!(previous_task.is_none());
            Ok(())
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            syscall: Syscall,
        ) -> std::result::Result<i64, reverie::Error> {
            assert!(matches!(syscall, Syscall::Getpid(_)));
            let observed = observed();
            let role = observed.role(guest.tid());
            assert!(!observed.has(Event::Callback(role)));
            observed.event(Event::Callback(role));
            let _drop = CallbackDrop(observed.clone(), role);
            if role == Role::Parent {
                copy(guest, &observed, role);
                observed.finish[role as usize].waiting().await;
                return Ok(0);
            }
            observed.prepare[role as usize].waiting().await;
            for (number, args, expected) in [
                (
                    libc::SYS_rt_sigprocmask,
                    [libc::SIG_BLOCK as u64, MASK, 0, 8, 0, 0],
                    0,
                ),
                (
                    libc::SYS_tgkill,
                    [
                        guest.pid().as_raw() as u64,
                        guest.tid().as_raw() as u64,
                        libc::SIGUSR1 as u64,
                        0,
                        0,
                        0,
                    ],
                    0,
                ),
                (
                    libc::SYS_rt_sigtimedwait,
                    [MASK, 0, TIMEOUT, 8, 0, 0],
                    i64::from(libc::SIGUSR1),
                ),
            ] {
                let syscall = SyscallRequest::new(number as u64, args)
                    .into_syscall()
                    .unwrap();
                assert_eq!(
                    guest.inject(syscall).await,
                    Ok(expected),
                    "real signal setup for {role:?}"
                );
            }
            assert_eq!(observed.snapshot().effects[role as usize].len(), 1);
            observed.event(Event::Effects(role));
            if role == Role::B {
                observed.copy_b.blocking();
            }
            copy(guest, &observed, role);
            match role {
                Role::A => {
                    observed.finish[role as usize].blocking();
                    Ok(0)
                }
                Role::B if observed.case == Case::BFirst => Err(observed.error("B callback")),
                Role::B if observed.case == Case::Healthy => Ok(0),
                Role::B => std::future::pending().await,
                Role::C => {
                    observed.finish[role as usize].blocking();
                    if observed.case == Case::CFirst {
                        Err(observed.error("C callback"))
                    } else {
                        assert!(
                            observed
                                .context(role)
                                .driver_subscription(false)
                                .now_or_never()
                                .is_none()
                        );
                        assert!(
                            observed.snapshot().gates[role as usize]
                                .as_ref()
                                .unwrap()
                                .pending_failure()
                                .is_none()
                        );
                        Ok(17)
                    }
                }
                Role::Parent => unreachable!(),
            }
        }
        async fn on_exit_thread<G: reverie::GlobalRPC<MultiGlobal>>(
            &self,
            tid: Pid,
            _: &G,
            original: Arc<u64>,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = observed();
            let role = observed.role(tid);
            assert_eq!(*original, role as u64);
            assert_eq!(Arc::strong_count(&original), 1);
            assert!(observed.has(Event::Dropped(role)));
            assert!(observed.origin(role).operation.unwrap().callback_dropped());
            if observed.case != Case::Healthy && !(role == Role::C && observed.case != Case::CFirst)
            {
                assert!(
                    observed.receipt(),
                    "consuming hook before actual notification"
                );
            }
            let expected = if role == Role::C && observed.case != Case::CFirst {
                17
            } else if observed.case == Case::Healthy
                || (role == Role::B && matches!(observed.case, Case::AFirst | Case::CFirst))
            {
                // A started peer cancelled by another owner's failure retains
                // ordinary retirement status. Its returned run error and owned
                // effects must still survive; B's own error below remains 255.
                0
            } else {
                255
            };
            assert_eq!(status, ExitStatus::Exited(expected));
            let (previous_status, original_state) = {
                let mut state = observed.state.lock().unwrap();
                (
                    state.statuses[role as usize].replace(status),
                    state.states[role as usize].clone(),
                )
            };
            assert!(previous_status.is_none());
            assert!(Arc::ptr_eq(
                &original,
                &original_state.as_ref().unwrap().upgrade().unwrap()
            ));
            observed.event(Event::Hook(role));
            drop(original);
            assert!(
                observed.snapshot().states[role as usize]
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .is_none()
            );
            observed.event(Event::Consumed(role));
            match (observed.case, role) {
                (Case::Healthy, _) => Ok(()),
                (_, Role::A) => Err(observed.error("A exit")),
                (Case::AFirst | Case::CFirst, Role::B) => Err(observed.error("B exit")),
                _ => Ok(()),
            }
        }
        async fn on_exit_process<G: reverie::GlobalRPC<MultiGlobal>>(
            self,
            pid: Pid,
            _: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            let observed = observed();
            let role = observed.role(pid);
            assert!(matches!(role, Role::Parent | Role::C));
            assert_eq!(self.pid, pid.as_raw());
            assert_eq!(observed.snapshot().statuses[role as usize], Some(status));
            assert!(observed.has(Event::Consumed(role)));
            assert!(!observed.has(Event::ProcessConsumed(role)));
            observed.event(Event::ProcessConsumed(role));
            Ok(())
        }
    }

    fn copy<G: Guest<MultiTool>>(guest: &mut G, observed: &Observed, role: Role) {
        assert!(!observed.copy_armed[role as usize].swap(true, Ordering::SeqCst));
        let remote =
            unsafe { AddrSlice::from_raw_parts(Addr::<u8>::from_raw(BYTES as usize).unwrap(), 4) };
        let from = [unsafe { remote.as_ioslice() }];
        let mut bytes = [0xa5; 4];
        let mut to = [IoSliceMut::new(&mut bytes)];
        let result = guest.memory().read_vectored(&from, &mut to);
        assert!(!observed.copy_armed[role as usize].load(Ordering::SeqCst));
        if observed.case != Case::Healthy && matches!(role, Role::A | Role::B) {
            assert_eq!(result, Err(Errno::EIO));
            assert_eq!(bytes, [0xa5; 4]);
            let state = observed.snapshot();
            let pending = state.gates[role as usize]
                .as_ref()
                .unwrap()
                .pending_failure()
                .unwrap();
            assert!(Arc::ptr_eq(&pending, state.pending.as_ref().unwrap()));
            assert!(
                pending.operation.as_ref().unwrap().same_callback(
                    state.origins[Role::A as usize]
                        .as_ref()
                        .unwrap()
                        .operation
                        .as_ref()
                        .unwrap()
                )
            );
        } else {
            assert_eq!(result, Ok(4));
            assert_eq!(&bytes, b"ABCD");
        }
        observed.event(Event::Copy(role));
    }

    // Actual Linux guest instructions create C first, then A and B with valid
    // distinct stacks. Each task reaches one subscribed marker and one exit.
    fn guest_code() -> Vec<u8> {
        let mut code = vec![0xb8, 57, 0, 0, 0, 0x0f, 0x05];
        let mut branches = Vec::new();
        let branch = |code: &mut Vec<u8>, branches: &mut Vec<usize>| {
            code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]);
            branches.push(code.len());
            code.extend_from_slice(&[0; 4]);
        };
        branch(&mut code, &mut branches);
        for stack_delta in [0x4000_u32, 0x8000_u32] {
            code.push(0xbf);
            let flags = libc::CLONE_VM
                | libc::CLONE_FS
                | libc::CLONE_FILES
                | libc::CLONE_SIGHAND
                | libc::CLONE_THREAD;
            code.extend_from_slice(&(flags as u32).to_le_bytes());
            code.extend_from_slice(&[0x48, 0x89, 0xe6, 0x48, 0x81, 0xee]);
            code.extend_from_slice(&stack_delta.to_le_bytes());
            code.extend_from_slice(&[
                0x31, 0xd2, 0x45, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0xb8, 56, 0, 0, 0, 0x0f, 0x05,
            ]);
            branch(&mut code, &mut branches);
        }
        let marker = code.len();
        for displacement in branches {
            code[displacement..displacement + 4]
                .copy_from_slice(&((marker - displacement - 4) as i32).to_le_bytes());
        }
        code.extend_from_slice(&[
            0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0xb8, 60, 0, 0, 0, 0x0f, 0x05, 0x0f,
            0x0b,
        ]);
        code
    }

    fn assert_a_alive(observed: &Observed) {
        assert!(!observed.has(Event::Dropped(Role::A)));
        assert!(
            !observed
                .origin(Role::A)
                .operation
                .unwrap()
                .callback_dropped()
        );
    }
    fn drive(observed: &Observed) {
        for role in ROLES {
            observed.wait(Event::Started(role));
            observed.wait(Event::Callback(role));
        }
        observed.wait(Event::Copy(Role::Parent));
        observed.prepare[Role::C as usize].release();
        observed.wait(Event::Copy(Role::C));
        observed.prepare[Role::B as usize].release();
        observed.wait(Event::Effects(Role::B));
        observed.prepare[Role::A as usize].release();
        observed.wait(Event::Copy(Role::A));
        assert_a_alive(observed);
        assert!(!observed.receipt());
        observed.copy_b.release();
        observed.wait(Event::Copy(Role::B));
        {
            let state = observed.snapshot();
            let a = state.origins[Role::A as usize].as_ref().unwrap();
            let b = state.origins[Role::B as usize].as_ref().unwrap();
            let c = state.origins[Role::C as usize].as_ref().unwrap();
            assert!(
                !a.operation
                    .as_ref()
                    .unwrap()
                    .same_driver(b.operation.as_ref().unwrap())
            );
            assert!(
                !a.operation
                    .as_ref()
                    .unwrap()
                    .same_callback(b.operation.as_ref().unwrap())
            );
            assert!(Arc::ptr_eq(
                state.gates[1].as_ref().unwrap(),
                state.gates[2].as_ref().unwrap()
            ));
            assert!(!Arc::ptr_eq(
                state.gates[1].as_ref().unwrap(),
                state.gates[3].as_ref().unwrap()
            ));
            assert!(Arc::ptr_eq(
                &a.failure.as_ref().unwrap().run,
                &b.failure.as_ref().unwrap().run
            ));
            assert!(Arc::ptr_eq(
                &a.failure.as_ref().unwrap().run,
                &c.failure.as_ref().unwrap().run
            ));
            assert_eq!(state.effects[2][0].sequence, 1);
            assert_eq!(state.effects[1][0].sequence, 2);
            assert_eq!(state.effects[1][0].process, state.effects[2][0].process);
            assert_ne!(state.effects[1][0].process, state.effects[3][0].process);
            assert_ne!(state.signal_tasks[1], state.signal_tasks[2]);
            for role in [Role::A, Role::B, Role::C] {
                let task = state.signal_tasks[role as usize].unwrap();
                assert_eq!(
                    task.tid.as_raw(),
                    state.identities[role as usize].unwrap().1
                );
                assert_eq!(task.process, state.effects[role as usize][0].process);
            }
        }
        if matches!(observed.case, Case::AFirst | Case::CFirst) {
            observed.wait(Event::ForeignPending(Role::B));
            assert_a_alive(observed);
            assert!(!observed.receipt());
            assert!(!observed.has(Event::Hook(Role::B)));
            assert!(
                !observed
                    .snapshot()
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Report(..) | Event::JoinStart(..)))
            );
        }
        match observed.case {
            Case::AFirst => {
                observed.finish[Role::A as usize].release();
                observed.await_receipt(Role::A);
                observed.finish[Role::C as usize].release();
            }
            Case::CFirst => {
                observed.finish[Role::C as usize].release();
                // The real loop publishes callback failure before its later
                // execution cleanup. The report hook still holds publication:
                // RunFailure notifies only after this hook returns.
                observed.wait(Event::Report(Role::C, "Tool callback"));
                assert_a_alive(observed);
                assert!(!observed.receipt());
                assert!(!observed.has(Event::Hook(Role::B)));
                assert!(observed.run().published_primary().is_none());
                observed.c_report.release();
                observed.await_receipt(Role::C);
                observed.wait(Event::Consumed(Role::B));
                // This real outer boundary follows the consuming future's
                // Ready error and destruction, not merely our local marker.
                observed.wait(Event::Report(Role::B, "thread exit hook"));
                assert_a_alive(observed);
                observed.finish[Role::A as usize].release();
            }
            Case::BFirst => {
                observed.await_receipt(Role::B);
                assert_a_alive(observed);
                assert!(!observed.has(Event::ForeignPending(Role::B)));
                observed.finish[Role::A as usize].release();
                observed.finish[Role::C as usize].release();
            }
            Case::Healthy => {
                observed.finish[Role::A as usize].release();
                observed.finish[Role::C as usize].release();
                for role in [Role::A, Role::B, Role::C] {
                    observed.wait(Event::Consumed(role));
                }
                observed.finish[Role::Parent as usize].release();
            }
        }
    }

    // Visit each actual error allocation once. Shared Arc aliases do not make
    // a second owner; separate owned SignalEffects with equal IDs still do.
    fn visit<'a>(error: &'a Error, seen: &mut BTreeSet<usize>, output: &mut Vec<&'a Error>) {
        if !seen.insert(std::ptr::from_ref(error) as usize) {
            return;
        }
        output.push(error);
        match error {
            Error::SignalEffects { cause, .. }
            | Error::SharedFailure(cause)
            | Error::WorkerFailure { error: cause, .. }
            | Error::Cleanup { error: cause, .. } => visit(cause, seen, output),
            Error::WithCleanup { primary, cleanup } => {
                visit(primary, seen, output);
                for error in cleanup {
                    visit(error, seen, output);
                }
            }
            Error::ExecWorkerTeardown(error) => visit(error, seen, output),
            _ => {}
        }
    }
    fn io_causes(error: &Error) -> Vec<(&'static str, usize)> {
        let mut errors = Vec::new();
        visit(error, &mut BTreeSet::new(), &mut errors);
        let mut causes = Vec::new();
        for error in errors {
            if let Error::Reverie(reverie::Error::Io(error)) = error {
                let cause = error.get_ref().unwrap().downcast_ref::<IoCause>().unwrap();
                causes.push((cause.0, std::ptr::from_ref(cause) as usize));
            }
        }
        causes.sort();
        causes
    }
    fn verify(observed: &Observed, result: crate::Result<(i32, Vec<u8>, Vec<u8>)>) {
        let state = observed.snapshot();
        for role in ROLES {
            for event in [
                Event::Started(role),
                Event::Callback(role),
                Event::Copy(role),
                Event::Dropped(role),
                Event::Hook(role),
                Event::Consumed(role),
            ] {
                assert_eq!(
                    state.events.iter().filter(|seen| **seen == event).count(),
                    1,
                    "{event:?}"
                );
            }
            assert!(
                state.states[role as usize]
                    .as_ref()
                    .unwrap()
                    .upgrade()
                    .is_none()
            );
        }
        for role in [Role::Parent, Role::C] {
            assert_eq!(
                state
                    .events
                    .iter()
                    .filter(|event| **event == Event::ProcessConsumed(role))
                    .count(),
                1
            );
        }
        for role in [Role::A, Role::B, Role::C] {
            let starts: Vec<_> = state
                .events
                .iter()
                .enumerate()
                .filter_map(|(index, event)| match event {
                    Event::JoinStart(target, joiner, process) if *target == role => {
                        Some((index, *joiner, *process))
                    }
                    _ => None,
                })
                .collect();
            let returns: Vec<_> = state
                .events
                .iter()
                .enumerate()
                .filter_map(|(index, event)| match event {
                    Event::JoinReturn(target, joiner, process) if *target == role => {
                        Some((index, *joiner, *process))
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(starts.len(), 1, "one physical join for {role:?}");
            assert_eq!(returns.len(), 1, "one physical join result for {role:?}");
            assert_eq!((starts[0].1, starts[0].2), (returns[0].1, returns[0].2));
            assert!(starts[0].0 < returns[0].0);
            assert!(
                returns[0].0
                    < state
                        .events
                        .iter()
                        .position(|event| *event == Event::Completed)
                        .unwrap()
            );
        }
        if observed.case == Case::Healthy {
            assert_eq!(result.unwrap(), (0, Vec::new(), Vec::new()));
            assert!(
                !state
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Report(..) | Event::ForeignPending(..)))
            );
            assert!(state.causes.is_empty());
            assert!(state.pending.is_none());
            return;
        }
        let error = result.unwrap_err();
        assert!(crate::failure::references_shared_error(
            &error,
            &observed.cause
        ));
        let expected_causes: Vec<_> = state
            .causes
            .iter()
            .map(|(name, address)| (*name, *address))
            .collect();
        assert_eq!(io_causes(&error), expected_causes);
        let names: Vec<_> = expected_causes.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            match observed.case {
                Case::AFirst => vec!["A exit", "B exit"],
                Case::BFirst => vec!["A exit", "B callback"],
                Case::CFirst => vec!["A exit", "B exit", "C callback"],
                Case::Healthy => unreachable!(),
            }
        );
        let mut errors = Vec::new();
        visit(&error, &mut BTreeSet::new(), &mut errors);
        assert_eq!(
            errors
                .iter()
                .filter(|error| std::ptr::eq(**error, observed.cause.as_ref()))
                .count(),
            1
        );
        let mut ledgers = Vec::new();
        for error in errors {
            match error {
                Error::SignalEffects {
                    dequeues,
                    acknowledged_through,
                    publications,
                    raw_result,
                    context,
                    ..
                } => {
                    assert_eq!(
                        dequeues.len(),
                        1,
                        "one real removal owned by each failed callback"
                    );
                    assert!(publications.is_empty());
                    assert!(context.is_none());
                    assert_eq!(*raw_result, Some(i64::from(libc::SIGUSR1)));
                    ledgers.push((dequeues.clone(), *acknowledged_through));
                }
                Error::RunAborted
                | Error::SharedFailure(_)
                | Error::WorkerFailure { .. }
                | Error::Cleanup { .. }
                | Error::WithCleanup { .. }
                | Error::ExecWorkerTeardown(_)
                | Error::Reverie(reverie::Error::Io(_)) => {}
                Error::HostIo(_) if std::ptr::eq(error, observed.cause.as_ref()) => {}
                other => panic!("unexpected retained diagnostic: {other:?}"),
            }
        }
        let failed_roles = if observed.case == Case::CFirst {
            &[Role::A, Role::B, Role::C][..]
        } else {
            &[Role::A, Role::B][..]
        };
        assert_eq!(
            ledgers.len(),
            failed_roles.len(),
            "distinct owned effect ledgers, without ID deduplication"
        );
        for role in failed_roles {
            let expected = (
                &state.effects[*role as usize],
                if *role == Role::C { 1 } else { 2 },
            );
            assert_eq!(ledgers.iter().filter(|(effects, watermark)| effects == expected.0 && *watermark == expected.1).count(), 1);
        }
        assert_eq!(state.events.iter().filter(|event| matches!(event, Event::Report(Role::A, phase) if *phase != "thread exit hook")).count(), 1, "A alone reports the captured gate cause once");
        let first = state
            .events
            .iter()
            .find_map(|event| match event {
                Event::Report(role, _) => Some(*role),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            first,
            match observed.case {
                Case::AFirst => Role::A,
                Case::BFirst => Role::B,
                Case::CFirst => Role::C,
                Case::Healthy => unreachable!(),
            }
        );
    }

    fn run_case(case: Case) {
        let _case = CASE_LOCK.lock().unwrap();
        let observed = Arc::new(Observed::new(case));
        assert!(ACTIVE.lock().unwrap().replace(observed.clone()).is_none());
        let _active = ActiveCase(observed.clone());
        let mut backend =
            KvmBackend::new(16 * 1024 * 1024).expect("real multi-owner controls require /dev/kvm");
        backend
            .install_static_elf(
                &minimal_test_elf(&guest_code()),
                "/bin/entry-multi-owner-control",
            )
            .unwrap();
        backend
            .memory
            .write(MASK, &(1_u64 << (libc::SIGUSR1 - 1)).to_le_bytes())
            .unwrap();
        backend.memory.write(TIMEOUT, &[0; 16]).unwrap();
        backend.memory.write(BYTES, b"ABCD").unwrap();
        backend.set_backend_stats_request(BackendStatsRequest::new(true));
        let exits = backend.exit_collector.as_ref().unwrap().clone();
        let group = backend.thread_group.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let run_observed = observed.clone();
        let host = std::thread::spawn(move || {
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let completion = futures::executor::block_on(
                    backend.run_static_elf_with_tool_completion::<MultiTool>((), false),
                )
                .unwrap();
                assert!(!group.has_worker_handles());
                assert!(backend.tool_failure.is_none());
                assert!(backend.tool_panics.take().is_empty());
                run_observed.event(Event::Completed);
                completion.result
            }));
            sender.send(caught).unwrap();
        });
        let control = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drive(&observed)));
        // Always release before waiting for public completion or host join,
        // including an assertion failure in the controller.
        observed.release_all();
        let completion = receiver
            .recv_timeout(BOUND)
            .expect("public driver did not complete after finite rescue releases");
        host.join().unwrap();
        if let Err(payload) = control {
            std::panic::resume_unwind(payload);
        }
        let result = completion.unwrap_or_else(|payload| std::panic::resume_unwind(payload));
        assert!(
            exits.snapshot().total_exits() > 0,
            "actual ELF instructions must execute"
        );
        if case == Case::Healthy {
            assert!(!observed.receipt());
        } else {
            observed.await_receipt(match case {
                Case::AFirst => Role::A,
                Case::BFirst => Role::B,
                Case::CFirst => Role::C,
                Case::Healthy => unreachable!(),
            });
        }
        verify(&observed, result);
    }

    #[test]
    fn public_elf_owner_a_publishes_after_real_peer_observation() {
        run_case(Case::AFirst);
    }
    #[test]
    fn public_elf_independent_c_publication_releases_peer_before_owner_a() {
        run_case(Case::CFirst);
    }
    #[test]
    fn public_elf_peer_b_keeps_own_error_before_owner_a_publication() {
        run_case(Case::BFirst);
    }
    #[test]
    fn public_elf_multi_owner_healthy_callbacks_complete_once() {
        run_case(Case::Healthy);
    }
}
