/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// These controls force the production group cleanup protocol on a modern
// kernel too. Safeptrace separately forces its actual legacy descriptor
// opens; the stock Linux 6.8 release gate exercises both together.
struct GroupStopScope(std::marker::PhantomData<std::rc::Rc<()>>);

#[tokio::test(flavor = "current_thread")]
async fn ptracer_task_recovers_same_driver_after_pending_adapter_cancellation() {
    let deadline = Instant::now() + Duration::from_secs(3);
    let stopped = group_fixture_root(GroupFixtureAttach::Traceme, false).await;
    let root = stopped.pid();
    let generation = stopped.generation();
    let terminal = stopped.terminal_cleanup();
    let events = Subscription::none();
    let (orphanage, _orphans) = mpsc::channel(1);
    let (daemon_kill, _) = broadcast::channel(1);
    // This is the production enclosing task, created and bound before its
    // wait adapter can suspend. No extra fixture owner keeps the core alive.
    let task = TracedTask::<InitFailureTool>::new(
        root,
        (),
        Arc::new(()),
        TracedTaskOptions {
            command_bootstrap: false,
            events: &events,
            injected_syscall_trap: None,
            liteinst_runtime: None,
            liteinst_trap_only: None,
            backend_stats: None,
            final_resume_signal_for_test: None,
            pre_syscall_for_test: None,
            preinit_point_for_test: None,
        },
        orphanage,
        daemon_kill,
        None,
    );
    task.ptracer_waits.bind_stopped(&stopped);
    task.ptracer_waits.bind_stopped(&stopped);
    assert_eq!(
        *task.ptracer_waits.generation.lock().unwrap(),
        Some(generation.clone())
    );
    assert!(task.ptracer_waits.waits.lock().unwrap().is_empty());
    let exit = task.ptracer_waits.exit_stopped(&stopped);
    let running = stopped.resume(None).unwrap();
    let mut adapter = task.ptracer_waits.wait_running(running);
    let waker = futures::task::noop_waker();
    let mut context = std::task::Context::from_waker(&waker);
    assert!(matches!(
        std::future::Future::poll(adapter.as_mut(), &mut context),
        std::task::Poll::Pending
    ));
    let weak_slot = {
        let retained = task.ptracer_waits.waits.lock().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(
            retained[0].lock().unwrap().as_ref().unwrap().generation(),
            Some(generation.clone())
        );
        Arc::downgrade(&retained[0])
    };
    drop(adapter);
    {
        let retained = task.ptracer_waits.waits.lock().unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(
            Arc::strong_count(&retained[0]),
            1,
            "the task field, not a spare adapter/fixture owner, retains the slot"
        );
        assert!(std::sync::Weak::ptr_eq(
            &weak_slot,
            &Arc::downgrade(&retained[0])
        ));
        assert_eq!(
            retained[0].lock().unwrap().as_ref().unwrap().generation(),
            Some(generation.clone())
        );
    }
    task.ptracer_waits.progress().unwrap();
    assert!(!terminal.wait(Duration::ZERO));
    terminal.request_sigkill().unwrap();
    let stopped = tokio::time::timeout_at(deadline.into(), exit)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.generation(), generation);
    assert_eq!(stopped.getevent().unwrap(), libc::SIGKILL as i64);
    assert!(
        !terminal.wait(Duration::ZERO),
        "real EXIT stop is not terminal completion"
    );
    let running = stopped.resume(None).unwrap();
    let slot = weak_slot
        .upgrade()
        .expect("the same task still retains its cancelled wait");
    let actual = tokio::time::timeout_at(
        deadline.into(),
        futures::future::poll_fn(|cx| {
            slot.lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .poll_on_ptracer_thread(cx)
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        actual.assume_exited(),
        (root, ExitStatus::Signaled(Signal::SIGKILL, false))
    );
    assert!(matches!(
        slot.lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .poll_on_ptracer_thread(&mut context),
        std::task::Poll::Ready(Err(OwnedWaitError::Completed))
    ));
    assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
    assert_eq!(
        terminal.observed_exit_status(),
        Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
    );
    assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
    drop(running);
    assert_reaped("cancelled task adapter original root", root);
    assert!(Instant::now() <= deadline);
    println!("ACTUAL_TRACED_TASK_PENDING_DRIVER_RECOVERY_EXERCISED");
}

impl GroupStopScope {
    fn new(force: bool, control: Arc<GroupStopControl>) -> Self {
        FORCE_GROUP_STOP_CLEANUP.with(|slot| assert!(!slot.replace(force)));
        GROUP_STOP_CONTROL.with(|slot| {
            assert!(slot.borrow().is_none());
            *slot.borrow_mut() = Some(control);
        });
        Self(std::marker::PhantomData)
    }
}

impl Drop for GroupStopScope {
    fn drop(&mut self) {
        FORCE_GROUP_STOP_CLEANUP.with(|slot| slot.set(false));
        GROUP_STOP_CONTROL.with(|slot| *slot.borrow_mut() = None);
        NATIVE_SIGSTOP_ERROR.with(|slot| slot.set(None));
    }
}

fn block_fixture_sigcont() {
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigemptyset(&mut mask) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut mask, libc::SIGCONT) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) },
        0
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupFixtureAttach {
    Traceme,
    Attach,
    Seize,
}

fn group_fixture_options() -> ptrace::Options {
    ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_TRACEEXIT
        | ptrace::Options::PTRACE_O_EXITKILL
}

async fn group_fixture_root(method: GroupFixtureAttach, forks: bool) -> Stopped {
    let mut start = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(start.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let root = match unsafe { unistd::fork() }.unwrap() {
        ForkResult::Child => {
            if unsafe { libc::setpgid(0, 0) } != 0 {
                unsafe { libc::_exit(124) };
            }
            block_fixture_sigcont();
            unsafe { libc::close(start[1]) };
            if method == GroupFixtureAttach::Traceme {
                safeptrace::traceme_and_stop().unwrap();
            } else {
                let mut byte = 0u8;
                if unsafe { libc::read(start[0], (&mut byte as *mut u8).cast(), 1) } != 1 {
                    unsafe { libc::_exit(125) };
                }
            }
            unsafe { libc::close(start[0]) };
            // SIGCHLD selects a real FORK ptrace event. CLONE_PARENT keeps
            // this fixture's real-parent wait authority in the harness too,
            // so its final wait does not depend on init reaping an orphan.
            // The event parent remains this tracee, deliberately unlike PPid.
            if forks
                && unsafe {
                    libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_PARENT | libc::SIGCHLD,
                        0,
                        0,
                        0,
                        0,
                    )
                } < 0
            {
                unsafe { libc::_exit(126) };
            }
            loop {
                unsafe { libc::pause() };
            }
        }
        ForkResult::Parent { child } => Pid::from_raw(child.as_raw()),
    };
    unsafe { libc::close(start[0]) };
    let running = match method {
        GroupFixtureAttach::Traceme => Running::new_on_ptracer_thread(root).unwrap(),
        GroupFixtureAttach::Attach => Running::attach_on_ptracer_thread(root).unwrap(),
        GroupFixtureAttach::Seize => {
            let running = Running::seize_on_ptracer_thread(root, group_fixture_options()).unwrap();
            running.interrupt().unwrap();
            running
        }
    };
    let (stopped, event) = tokio::time::timeout(
        Duration::from_secs(3),
        running.wait_owned_on_ptracer_thread(),
    )
    .await
    .unwrap()
    .unwrap()
    .assume_stopped();
    assert_eq!(
        event,
        if method == GroupFixtureAttach::Seize {
            Event::Stop
        } else {
            Event::Signal(Signal::SIGSTOP)
        }
    );
    stopped.setoptions(group_fixture_options()).unwrap();
    assert_eq!(unsafe { libc::write(start[1], c"s".as_ptr().cast(), 1) }, 1);
    unsafe { libc::close(start[1]) };
    stopped
}

async fn finish_group_fixture_root(
    running: Running,
    exit: impl std::future::Future<Output = Result<Stopped, TraceError>>,
    deadline: Instant,
) {
    let terminal = running.terminal_cleanup();
    terminal.request_sigkill().unwrap();
    let stop = tokio::time::timeout_at(deadline.into(), exit)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !terminal.wait(Duration::ZERO),
        "actual EXIT stop is not a final wait"
    );
    assert_eq!(
        tokio::time::timeout_at(
            deadline.into(),
            stop.resume(None).unwrap().wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (running.pid(), ExitStatus::Signaled(Signal::SIGKILL, false))
    );
    assert!(terminal.wait(deadline.saturating_duration_since(Instant::now())));
    assert_eq!(terminal.request_sigkill(), Err(Errno::ESRCH));
    assert_reaped("group cleanup fixture root", running.pid());
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_cleanup_holds_real_classic_and_seized_stops() {
    for method in [
        GroupFixtureAttach::Traceme,
        GroupFixtureAttach::Attach,
        GroupFixtureAttach::Seize,
    ] {
        let deadline = Instant::now() + Duration::from_secs(3);
        let control = Arc::new(GroupStopControl::default());
        control.coalesce_requests.store(true, Ordering::SeqCst);
        let _scope = GroupStopScope::new(true, control.clone());
        let stopped = group_fixture_root(method, false).await;
        let root = stopped.pid();
        let session = FatalSession::for_test(root);
        session.capture_root(&stopped);
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        let terminal = running.terminal_cleanup();
        let mut emergency = LiteinstTraceeCleanup::new(
            root,
            Arc::new(StdMutex::new(HashMap::new())),
            Arc::new(StdMutex::new(None)),
        )
        .unwrap();
        emergency.register_notifier(&running);
        let waits = Arc::new(PtracerWaitOwner::default());
        waits.bind_running(&running);
        let stop = FatalTaskStop {
            tid: root,
            terminal,
            held: Arc::new(StdMutex::new(None)),
            frozen: AtomicBool::new(false),
            waits: waits.clone(),
        };
        let mut retained = None;
        session.request_legacy_group_sigstop().unwrap();
        tokio::time::timeout_at(
            deadline.into(),
            stop.freeze(
                deadline,
                |parent, op, child| {
                    panic!("unexpected child {} of {parent} by {op:?}", child.pid())
                },
                || session.request_legacy_group_sigstop(),
                &mut retained,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            !stop.frozen.load(Ordering::SeqCst),
            "only the caller's all-task barrier marks frozen"
        );
        assert!(retained.is_none());
        assert!(
            stop.held
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|held| held.armed && held.terminal.same_generation(&stop.terminal))
        );
        assert!(control.requests.load(Ordering::SeqCst) >= 7);
        assert!(control.relay_attempts.load(Ordering::SeqCst) >= 1);
        let expected = if method == GroupFixtureAttach::Seize {
            "seized-group"
        } else {
            "classic-group"
        };
        assert!(
            control
                .held
                .lock()
                .unwrap()
                .iter()
                .any(|(tid, class)| *tid == root && *class == expected)
        );
        finish_group_fixture_root(running, exit, deadline).await;
        emergency.terminate_and_confirm().unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_cleanup_captures_newchild_before_parent_commit() {
    let deadline = Instant::now() + Duration::from_secs(3);
    let control = Arc::new(GroupStopControl::default());
    let _scope = GroupStopScope::new(true, control);
    let stopped = group_fixture_root(GroupFixtureAttach::Traceme, true).await;
    let root = stopped.pid();
    let session = FatalSession::for_test(root);
    session.capture_root(&stopped);
    let exit = stopped.exit_event_on_ptracer_thread();
    let running = stopped.resume(None).unwrap();
    let terminal = running.terminal_cleanup();
    let newborns = Arc::new(StdMutex::new(HashMap::new()));
    let mut emergency =
        LiteinstTraceeCleanup::new(root, newborns.clone(), Arc::new(StdMutex::new(None))).unwrap();
    emergency.register_notifier(&running);
    while !terminal
        .queued_raw_statuses()
        .iter()
        .any(|status| status >> 16 == libc::PTRACE_EVENT_FORK)
    {
        assert!(
            Instant::now() < deadline,
            "actual fork stop was not published"
        );
        tokio::task::yield_now().await;
    }
    let waits = Arc::new(PtracerWaitOwner::default());
    waits.bind_running(&running);
    let stop = FatalTaskStop {
        tid: root,
        terminal,
        held: Arc::new(StdMutex::new(None)),
        frozen: AtomicBool::new(false),
        waits: waits.clone(),
    };
    let captured = StdMutex::new(None);
    let mut retained = None;
    stop.freeze(
        deadline,
        |parent, op, child| {
            assert_eq!(parent, root);
            assert_eq!(op, ChildOp::Fork);
            session.capture_for_group_stop_test(parent, op, child);
            NewbornTracee::register(&newborns, parent, op, child);
            assert!(
                captured
                    .lock()
                    .unwrap()
                    .replace(child.terminal_cleanup())
                    .is_none()
            );
        },
        || session.request_legacy_group_sigstop(),
        &mut retained,
    )
    .await
    .unwrap();
    let child = captured
        .lock()
        .unwrap()
        .take()
        .expect("captured original newborn generation");
    let newborn = session
        .take_group_stop_newborn_for_test(&child)
        .expect("original captured exit receiver");
    assert!(newborn.terminal.same_generation(&child));
    assert_eq!(
        session.observed_child_ops.lock().unwrap().as_slice(),
        &[(root, ChildOp::Fork, newborn.tid)]
    );
    {
        let held = stop.held.lock().unwrap();
        assert_eq!(
            held.as_ref().unwrap().status,
            HeldRootStopStatus::NewChild(EventChildLink {
                tid: newborn.tid,
                parent_tid: root,
                op: ChildOp::Fork
            })
        );
        assert!(
            held.as_ref()
                .unwrap()
                .child
                .as_ref()
                .unwrap()
                .same_generation(&child)
        );
    }
    assert!(stop.terminal.pending_is_empty());
    let child_tid = newborn.tid;
    assert_eq!(
        tracee_snapshot(child_tid).unwrap().ppid,
        Pid::from_raw(unsafe { libc::getpid() }),
        "actual fork-event parent differs from the real wait parent"
    );
    newborn.signal().unwrap();
    let child_exit = tokio::time::timeout_at(deadline.into(), newborn.into_exit())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::time::timeout_at(
            deadline.into(),
            child_exit
                .resume(None)
                .unwrap()
                .wait_owned_on_ptracer_thread()
        )
        .await
        .unwrap()
        .unwrap()
        .assume_exited(),
        (child_tid, ExitStatus::Signaled(Signal::SIGKILL, false))
    );
    assert_eq!(
        child.observed_exit_status(),
        Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
    );
    assert!(child.wait(deadline.saturating_duration_since(Instant::now())));
    // This fixture consumed the original newborn exit receiver itself. Hand
    // its exact completed record out of the emergency owner's table, as the
    // task handoff does, before that guard validates its remaining tree.
    let completed = newborns
        .lock()
        .unwrap()
        .remove(&child_tid)
        .expect("original newborn emergency record remains until final wait");
    assert!(completed.terminal.same_generation(&child));
    assert!(completed.history.is_empty());
    assert!(newborns.lock().unwrap().is_empty());
    finish_group_fixture_root(running, exit, deadline).await;
    assert_reaped("captured group-stop newborn", child_tid);
    emergency.terminate_and_confirm().unwrap();
}

async fn legacy_group_backend_control(
    refuse: bool,
    cancel: bool,
    coalesce: bool,
    automatic_mode: bool,
) {
    let deadline = Instant::now() + Duration::from_secs(3);
    let control = Arc::new(GroupStopControl::default());
    control.refuse_next_relay.store(refuse, Ordering::SeqCst);
    control.cancel_next_relay.store(cancel, Ordering::SeqCst);
    control.coalesce_requests.store(coalesce, Ordering::SeqCst);
    let _scope = GroupStopScope::new(!automatic_mode, control.clone());
    let _observations = FatalReapObservationScope::new();
    let words = FatalWords::new();
    let address = words.0 as usize;
    control.pause_word.store(
        address + std::mem::size_of::<std::sync::atomic::AtomicUsize>(),
        Ordering::SeqCst,
    );
    let tracer = spawn_fn_with_config::<FatalTool, _>(
        move || {
            block_fixture_sigcont();
            std::thread::spawn(|| {
                loop {
                    unsafe { libc::pause() };
                }
            });
            std::thread::spawn(move || {
                unsafe { libc::syscall(libc::SYS_getpgid, 0) };
                unsafe { &*(address as *const std::sync::atomic::AtomicUsize) }
                    .store(1, Ordering::SeqCst);
                loop {
                    unsafe { libc::pause() };
                }
            });
            unsafe { &*((address as *const std::sync::atomic::AtomicUsize).add(1)) }
                .store(1, Ordering::SeqCst);
            loop {
                unsafe { libc::pause() };
            }
        },
        5,
        false,
    )
    .await
    .unwrap();
    let root = tracer.guest_pid();
    let native = Running::new_on_ptracer_thread(root)
        .unwrap()
        .terminal_cleanup()
        .has_thread_pidfd()
        .unwrap();
    *control.group_identity.lock().unwrap() =
        Some(Arc::new(TraceeIdentity::open_root(root).unwrap()));
    let log = tracer.gref.0.clone();
    let inject_native_error = automatic_mode && native;
    if inject_native_error {
        NATIVE_SIGSTOP_ERROR.with(|slot| slot.set(Some(Errno::EOPNOTSUPP)));
    }
    let mut emergency = LiteinstTraceeCleanup::new(
        root,
        Arc::new(StdMutex::new(HashMap::new())),
        Arc::new(StdMutex::new(None)),
    )
    .unwrap();
    emergency.register_notifier(&Running::new_on_ptracer_thread(root).unwrap());
    let outcome = tokio::time::timeout_at(deadline.into(), tracer.wait_completion())
        .await
        .unwrap();
    let completed = if refuse || inject_native_error {
        let ToolRunOutcome::CleanupPending(pending) = outcome else {
            panic!("refusal falsely acknowledged completion")
        };
        assert!(
            matches!(pending.failure().primary(), Error::Tool(error) if error.downcast_ref::<NonleaderFailure>().is_some())
        );
        let session = control.session.lock().unwrap().clone().unwrap();
        assert!(session.cleanup_was_refused());
        assert_eq!(session.unconfirmed_task_count(), 3);
        assert_eq!(session.retained_group_counts_for_test(), (3, 0, 0));
        assert_eq!(words.read(0), 0, "failed member resumed guest code");
        assert_eq!(
            log.lock().unwrap().len(),
            3,
            "unconfirmed tasks acquired fabricated exit hooks"
        );
        if refuse {
            let refused = control
                .refused
                .lock()
                .unwrap()
                .take()
                .expect("returned original stopped generation");
            assert_eq!(
                refused
                    .queued_raw_statuses()
                    .iter()
                    .filter(|status| libc::WSTOPSIG(**status) == libc::SIGSTOP)
                    .count(),
                0,
                "relay attempted before committing its FIFO reservation"
            );
            FATAL_REAP_OBSERVATIONS.with(|slot| {
                let owners = slot.borrow();
                let owner = owners
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|owner| owner.terminal.same_generation(&refused))
                    .unwrap();
                assert!(!owner.frozen.load(Ordering::SeqCst));
                assert!(owner.held.lock().unwrap().is_none());
                assert!(!owner.terminal.wait(Duration::ZERO));
            });
        }
        if inject_native_error {
            assert_eq!(
                control.requests.load(Ordering::SeqCst),
                0,
                "native EOPNOTSUPP selected legacy signaling"
            );
        }
        let next = tokio::time::timeout_at(deadline.into(), pending.resume_cleanup())
            .await
            .unwrap();
        let ToolRunOutcome::Complete(completed) = next else {
            panic!("original owner failed to resume cleanup")
        };
        completed
    } else {
        let ToolRunOutcome::Complete(completed) = outcome else {
            panic!("real group cleanup did not complete")
        };
        completed
    };
    let root_absent = !std::path::Path::new(&format!("/proc/{root}")).exists();
    let hooks = log.lock().unwrap().clone();
    let owner_complete = FATAL_REAP_OBSERVATIONS.with(|slot| {
        let owners = slot.borrow();
        let owners = owners.as_ref().unwrap();
        owners.len() == 3
            && owners.iter().all(|owner| {
                owner.frozen.load(Ordering::SeqCst)
                    && owner.terminal.wait(Duration::ZERO)
                    && owner.terminal.observed_exit_status()
                        == Ok(Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
            })
    });
    // Capture product completion before emergency cleanup, which cannot
    // satisfy the physical-stop, actual-wait or consuming-hook assertions.
    eprintln!(
        "group cleanup product proof: root={root}, native={native}, refuse={refuse}, cancel={cancel}, requests={}, relays={}, held={:?}, root_absent={root_absent}, original_owners_complete={owner_complete}, hooks={hooks:?}",
        control.requests.load(Ordering::SeqCst),
        control.relay_attempts.load(Ordering::SeqCst),
        control.held.lock().unwrap()
    );
    emergency.terminate_and_confirm().unwrap();
    assert!(root_absent);
    assert!(owner_complete);
    assert_eq!(words.read(0), 0);
    let failure = completed.result.expect_err("original Tool failure lost");
    assert!(
        matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<NonleaderFailure>().is_some())
    );
    let starts: Vec<_> = hooks
        .iter()
        .filter_map(|(tid, status)| status.is_none().then_some(*tid))
        .collect();
    assert_eq!(starts.len(), 3);
    assert_eq!(hooks.len(), 6);
    for tid in starts {
        assert_reaped("group-cleanup original task", tid);
        assert_eq!(
            hooks
                .iter()
                .filter(|(exited, status)| *exited == tid
                    && *status == Some(ExitStatus::Signaled(Signal::SIGKILL, false)))
                .count(),
            1
        );
    }
    if inject_native_error {
        assert!(
            failure
                .secondary()
                .iter()
                .any(|item| matches!(item.error(), Error::Errno(Errno::EOPNOTSUPP)))
        );
        assert_eq!(control.requests.load(Ordering::SeqCst), 0);
    } else {
        assert!(control.requests.load(Ordering::SeqCst) > 0);
        assert!(control.relay_attempts.load(Ordering::SeqCst) > 0);
        assert!(!control.held.lock().unwrap().is_empty());
    }
    if coalesce {
        assert!(control.requests.load(Ordering::SeqCst) >= 7);
    }
    if cancel {
        assert!(control.cancelled_returned_running.load(Ordering::SeqCst));
        assert!(control.relay_attempts.load(Ordering::SeqCst) >= 2);
        assert!(control.requests.load(Ordering::SeqCst) >= 2);
    }
    if refuse {
        assert!(
            failure
                .secondary()
                .iter()
                .any(|item| matches!(item.error(), Error::Errno(Errno::EIO)))
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_coalesces_stops_across_owned_members() {
    legacy_group_backend_control(false, false, true, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_retries_sigcont_cancelled_delivery() {
    legacy_group_backend_control(false, true, false, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_retains_original_resume_refusal_owner() {
    legacy_group_backend_control(true, false, false, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn group_cleanup_mode_preserves_native_error_and_legacy_selection() {
    legacy_group_backend_control(false, false, false, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_preserves_pending_newborn_owner() {
    let _scope = GroupStopScope::new(true, Arc::new(GroupStopControl::default()));
    ordinary_nonleader_control(true, false, true).await;
}

// Re-execute the unchanged pending-newborn control in isolated libtest
// processes. Only the forced cell installs seccomp; the shared runner keeps
// its original syscall policy and generic Native API behavior.
#[cfg(target_arch = "x86_64")]
#[test]
fn pending_newborn_emergency_observer_retains_original_generation() {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::process::Stdio;

    const CELL_ENV: &str = "REVERIE_PENDING_NEWBORN_OWNER_CELL";
    if let Ok(cell) = std::env::var(CELL_ENV) {
        assert!(cell == "normal" || cell == "forced");
        // This alarm is confined to the re-executed owned cell.
        unsafe { libc::alarm(10) };
        if cell == "forced" {
            let insn = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
            let filter = [
                insn(0x20, 0, 0, 4),
                insn(0x15, 1, 0, 0xc000_003e),
                insn(0x06, 0, 0, 0x8000_0000),
                insn(0x20, 0, 0, 0),
                insn(0x15, 0, 3, libc::SYS_pidfd_open as u32),
                insn(0x20, 0, 0, 24),
                insn(0x15, 0, 1, libc::O_EXCL as u32),
                insn(0x06, 0, 0, 0x0005_0000 | libc::EINVAL as u32),
                insn(0x06, 0, 0, 0x7fff_0000),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr().cast_mut(),
            };
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
        }
        let native = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), libc::O_EXCL) };
        let native_available = native >= 0;
        if native_available {
            assert_ne!(cell, "forced", "flags128 seccomp was not exercised");
            assert_eq!(unsafe { libc::close(native as i32) }, 0);
        } else {
            assert_eq!(unsafe { *libc::__errno_location() }, libc::EINVAL);
        }
        let ordinary = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
        assert!(ordinary >= 0, "ordinary process pidfd must remain allowed");
        assert_eq!(unsafe { libc::close(ordinary as i32) }, 0);
        println!(
            "PENDING_NEWBORN_DESCRIPTOR_CONTROL cell={cell} native={native_available} ordinary=true"
        );
        legacy_group_backend_preserves_pending_newborn_owner();
        println!("PENDING_NEWBORN_OWNER_CELL_PASSED {cell}");
        return;
    }
    let mut all_passed = true;
    for cell in ["normal", "forced"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "tracer::tests::pending_newborn_emergency_observer_retains_original_generation",
                "--exact",
                "--nocapture",
            ])
            .env(CELL_ENV, cell)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let child_pid = i32::try_from(child.id()).unwrap();
        // This unreaped child anchors its exact process-group number during
        // cleanup, including if a failing fixture leaves its owned sentinel.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child_pid, 0) };
        assert!(raw >= 0);
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let read = |pipe: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                pipe.take(65537).read_to_end(&mut bytes).unwrap();
                bytes
            })
        };
        let stdout = read(Box::new(stdout));
        let stderr = read(Box::new(stderr));
        let deadline = Instant::now() + Duration::from_secs(15);
        let timed_out = loop {
            let mut pollfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut pollfd, 1, 10) };
            assert!(result >= 0 || Errno::last() == Errno::EINTR);
            if result == 1 {
                assert_ne!(pollfd.revents & libc::POLLIN, 0);
                break false;
            }
            if Instant::now() >= deadline {
                break true;
            }
        };
        // The child is still unreaped, so no reused numeric process group can
        // be selected. Every member was spawned by this controlled cell.
        let killed = unsafe { libc::kill(-child_pid, libc::SIGKILL) };
        assert!(killed == 0 || Errno::last() == Errno::ESRCH);
        let status = child.wait().unwrap();
        let stdout = stdout.join().unwrap();
        let stderr = stderr.join().unwrap();
        assert!(stdout.len() <= 65536 && stderr.len() <= 65536);
        let stdout = String::from_utf8(stdout).unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        println!(
            "pending newborn owner cell {cell}, actual status {status}, timed_out={timed_out}:\n{stdout}"
        );
        eprintln!("{stderr}");
        let passed = !timed_out
            && status.success()
            && stdout
                .lines()
                .filter(|line| *line == format!("PENDING_NEWBORN_OWNER_CELL_PASSED {cell}"))
                .count()
                == 1
            && stdout
                .lines()
                .filter(|line| {
                    *line == "ACTUAL_PENDING_NEWBORN_EMERGENCY_ORIGINAL_GENERATION_EXERCISED"
                })
                .count()
                == 1
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && !stdout.contains("SKIP:")
            && !stdout.contains("SKIPPED:")
            && !stderr.contains("SKIP:")
            && !stderr.contains("SKIPPED:");
        all_passed &= passed;
    }
    assert!(
        all_passed,
        "both actual normal and PIDFD_THREAD-EINVAL pending-newborn cells must pass"
    );
    println!("ACTUAL_PENDING_NEWBORN_EMERGENCY_NORMAL_AND_FORCED_EXERCISED");
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_reaps_unhanded_fork_child() {
    let _scope = GroupStopScope::new(true, Arc::new(GroupStopControl::default()));
    fatal_unhanded_control(
        "tracer::tests::legacy_group_backend_reaps_unhanded_fork_child",
        false,
        UnhandedChild::Fork,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_backend_reaps_unhanded_vfork_child() {
    let _scope = GroupStopScope::new(true, Arc::new(GroupStopControl::default()));
    fatal_unhanded_control(
        "tracer::tests::legacy_group_backend_reaps_unhanded_vfork_child",
        false,
        UnhandedChild::Vfork,
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_group_cleanup_preserves_existing_seized_job_control_stops() {
    for signal in [Signal::SIGTSTP, Signal::SIGTTIN, Signal::SIGTTOU] {
        let deadline = Instant::now() + Duration::from_secs(3);
        let control = Arc::new(GroupStopControl::default());
        control.coalesce_requests.store(true, Ordering::SeqCst);
        let _scope = GroupStopScope::new(true, control.clone());
        let stopped = group_fixture_root(GroupFixtureAttach::Seize, false).await;
        let root = stopped.pid();
        let session = FatalSession::for_test(root);
        session.capture_root(&stopped);
        let group = TraceeIdentity::open_root(root).unwrap();
        let exit = stopped.exit_event_on_ptracer_thread();
        let running = stopped.resume(None).unwrap();
        let mut emergency = LiteinstTraceeCleanup::new(
            root,
            Arc::new(StdMutex::new(HashMap::new())),
            Arc::new(StdMutex::new(None)),
        )
        .unwrap();
        emergency.register_notifier(&running);
        group.send_signal(signal).unwrap();
        let (delivery, event) =
            tokio::time::timeout_at(deadline.into(), running.wait_owned_on_ptracer_thread())
                .await
                .unwrap()
                .unwrap()
                .assume_stopped();
        assert_eq!(event, Event::Signal(signal));
        assert_eq!(delivery.getsiginfo().unwrap().si_signo, signal as i32);
        let running = delivery.resume(Some(signal)).unwrap();
        let terminal = running.terminal_cleanup();
        let mut local_cleanup = running.terminal_cleanup_on_ptracer_thread();
        let expected = (libc::PTRACE_EVENT_STOP << 16) | ((signal as i32) << 8) | 0x7f;
        while !terminal.queued_raw_statuses().contains(&expected) {
            assert!(
                Instant::now() < deadline,
                "actual seized job-control stop was not published"
            );
            local_cleanup.progress().unwrap();
            tokio::task::yield_now().await;
        }
        let pending = local_cleanup
            .reserve_pending_for_cleanup(Duration::ZERO)
            .unwrap()
            .unwrap();
        let Wait::Stopped(current, Event::Stop) = pending.decode().unwrap() else {
            panic!("missing current seized event stop")
        };
        let observer = current.observation();
        let before = observer.sample(false).siginfo().unwrap().unwrap();
        assert_eq!(before.signo, signal as i32);
        assert_eq!(before.code, (libc::PTRACE_EVENT_STOP << 8) | signal as i32);
        drop(current);
        drop(pending); // Roll back, leaving the actual owned report for freeze.
        session.request_legacy_group_sigstop().unwrap();
        let waits = Arc::new(PtracerWaitOwner::default());
        waits.bind_running(&running);
        let stop = FatalTaskStop {
            tid: root,
            terminal,
            held: Arc::new(StdMutex::new(None)),
            frozen: AtomicBool::new(false),
            waits: waits.clone(),
        };
        let mut retained = None;
        stop.freeze(
            deadline,
            |_, _, _| panic!("single-member job-control fixture created a child"),
            || session.request_legacy_group_sigstop(),
            &mut retained,
        )
        .await
        .unwrap();
        assert!(retained.is_none());
        assert_eq!(observer.sample(false).siginfo(), Some(Ok(before)));
        assert!(stop.terminal.pending_is_empty());
        assert_eq!(
            control.relay_attempts.load(Ordering::SeqCst),
            0,
            "held job-control stop was resumed as SIGSTOP delivery"
        );
        assert!(
            control
                .held
                .lock()
                .unwrap()
                .iter()
                .any(|(tid, class)| *tid == root && *class == "seized-other")
        );
        finish_group_fixture_root(running, exit, deadline).await;
        emergency.terminate_and_confirm().unwrap();
    }
}
