// Signals a guest sends to other processes, and process-directed signals to a
// process with several threads, which a Tool that selects recipients asks for
// (`ProcessSignalControl::enable_cross_process_signals`).

/// Installs the run's signal control in `mode`, after asking for signals to
/// other processes if `declare`.
fn xsig_install(
    executor: &ElfExecutor,
    declare: bool,
    mode: reverie::BackendSignalControlMode,
) -> Arc<crate::failure::RunFailure> {
    if declare {
        executor
            .backend_signal_control()
            .process
            .enable_cross_process_signals()
            .unwrap();
    }
    let global = Arc::new(());
    let run = crate::failure::RunFailure::new(&global);
    executor.install_signal_control(mode, &run);
    run
}

fn xsig_kill(executor: &mut ElfExecutor, pid: i32, signal: i32) -> i64 {
    let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    executor.execute(
        &SyscallRequest::new(
            libc::SYS_kill as u64,
            [pid as u64, signal as u64, 0, 0, 0, 0],
        ),
        &memory,
    )
}

fn xsig_refusal(reason: &'static str) -> Option<reverie::UnsupportedRefusal> {
    Some(reverie::UnsupportedRefusal::new(
        reverie::UnsupportedOperation::Signal,
        reverie::Errno::ENOSYS,
        reason,
    ))
}

/// Registers a delivery permit for `executor`'s task.
fn xsig_permit(executor: &ElfExecutor, sequence: u64) -> reverie::SignalDeliveryPermit {
    let permit = reverie::SignalDeliveryPermit {
        task: executor.admitted_signal_identity(),
        sequence,
        site: None,
    };
    executor
        .backend_signal_control()
        .process
        .reserve_delivery(permit)
        .unwrap();
    permit
}

/// The request takes effect only in `ToolControlled` mode, and can be made
/// only before the control is installed.
#[test]
fn signals_to_other_processes_are_asked_for_before_installation_under_tool_control() {
    use reverie::BackendSignalControlMode::ToolControlled;
    use reverie::BackendSignalControlMode::Unchanged;
    for (declare, mode, effective) in [
        (false, ToolControlled, false),
        (true, Unchanged, false),
        (true, ToolControlled, true),
    ] {
        let root = TestDir::new();
        let executor = ElfExecutor::new(test_state(&root.0), false);
        let _run = xsig_install(&executor, declare, mode);
        assert_eq!(
            executor.signal_registry.cross_process_signals(),
            effective,
            "asked: {declare}, mode: {mode:?}"
        );
        assert_eq!(
            executor
                .backend_signal_control()
                .process
                .enable_cross_process_signals(),
            Err(reverie::syscalls::Errno::EBUSY)
        );
    }
}

/// A process-directed signal to the sender's own process while it has
/// another thread is refused, unless the Tool selects the thread that takes
/// it. Then it waits in the process's shared queue, in neither thread's own
/// queue, until a thread the Tool permits takes it.
#[test]
fn a_threaded_processs_signal_to_itself_waits_for_the_thread_the_tool_permits() {
    for declare in [false, true] {
        let root = TestDir::new();
        let mut leader = ElfExecutor::new(test_state(&root.0), false);
        let _run = xsig_install(
            &leader,
            declare,
            reverie::BackendSignalControlMode::ToolControlled,
        );
        let mut sibling = leader.thread_child(2).unwrap();
        let pid = leader.state.pid;
        let result = xsig_kill(&mut leader, pid, libc::SIGUSR1);
        let shared = |executor: &ElfExecutor| {
            executor
                .state
                .process_signals
                .lock()
                .unwrap()
                .shared_pending
                .contains(libc::SIGUSR1)
        };
        if !declare {
            assert_eq!(result, negative_errno(libc::ENOSYS));
            assert_eq!(
                leader.take_unsupported_refusal(),
                xsig_refusal(SignalRefusal::THREADED_PROCESS)
            );
            assert!(!shared(&leader), "a refused send queued nothing");
            continue;
        }
        assert_eq!(result, 0);
        assert_eq!(leader.take_unsupported_refusal(), None);
        assert!(shared(&leader));
        assert!(leader.state.thread_signals.lock().pending.is_empty());
        assert!(sibling.state.thread_signals.lock().pending.is_empty());
        assert!(
            leader.take_pending_signal_for_delivery().unwrap().is_none(),
            "no permit"
        );
        assert!(
            sibling
                .take_pending_signal_for_delivery()
                .unwrap()
                .is_none(),
            "no permit"
        );
        let permit = xsig_permit(&sibling, 1);
        let pending = sibling
            .take_pending_signal_for_delivery()
            .unwrap()
            .expect("the shared event");
        assert_eq!(pending.domain, PendingSignalDomain::Process);
        assert_eq!(pending.event.signal(), libc::SIGUSR1);
        let info = pending.event.siginfo();
        assert_eq!(
            i32::from_ne_bytes(info[8..12].try_into().unwrap()),
            libc::SI_USER
        );
        assert_eq!(i32::from_ne_bytes(info[16..20].try_into().unwrap()), pid);
        assert!(!shared(&leader), "taken once");
        sibling
            .backend_signal_control()
            .process
            .release_delivery(permit)
            .unwrap();
    }
}

/// `kill` and `rt_sigqueueinfo` find a positive id as any live task's and
/// signal that task's process (`kill_pid_info_type`), so a thread's id that
/// is not its process's names its process: a liveness probe answers 0, and a
/// signal goes to the process, here to the refusals a process gets.
#[test]
fn a_threads_id_names_its_process_in_kill_and_rt_sigqueueinfo() {
    const INFO: u64 = 0x100;
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let mut sibling = leader.thread_child(2).unwrap();
    let child = leader.fork_child(3, false, false).unwrap();
    let child_thread = child.thread_child(4).unwrap();
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut info = [0_u8; 128];
    info[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    memory.write(INFO, &info).unwrap();
    let sigqueueinfo = |executor: &mut ElfExecutor, pid: i32, signal: i32| {
        executor.execute(
            &SyscallRequest::new(
                libc::SYS_rt_sigqueueinfo as u64,
                [pid as u64, signal as u64, INFO, 0, 0, 0],
            ),
            &memory,
        )
    };
    // The sender's own id, from a thread that does not lead its process; a
    // sibling's; another process's thread's; and an id no task has.
    assert_eq!(xsig_kill(&mut sibling, 2, 0), 0);
    assert_eq!(xsig_kill(&mut leader, 2, 0), 0);
    assert_eq!(xsig_kill(&mut leader, 4, 0), 0);
    assert_eq!(sigqueueinfo(&mut leader, 4, 0), 0);
    assert_eq!(xsig_kill(&mut leader, 5, 0), negative_errno(libc::ESRCH));
    assert_eq!(leader.take_unsupported_refusal(), None);
    // A signal through a thread's id is its process's: the sender's own
    // process has another thread, and the child is another process.
    assert_eq!(
        xsig_kill(&mut sibling, 2, libc::SIGUSR1),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        sibling.take_unsupported_refusal(),
        xsig_refusal(SignalRefusal::THREADED_PROCESS)
    );
    for queued in [false, true] {
        let result = if queued {
            sigqueueinfo(&mut leader, 4, libc::SIGUSR1)
        } else {
            xsig_kill(&mut leader, 4, libc::SIGUSR1)
        };
        assert_eq!(result, negative_errno(libc::ENOSYS));
        assert_eq!(
            leader.take_unsupported_refusal(),
            xsig_refusal(SignalRefusal::OTHER_PROCESS)
        );
    }
    drop((child_thread, child));
}

fn xsig_tgkill(executor: &mut ElfExecutor, tgid: i32, tid: i32, signal: i32) -> i64 {
    let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    executor.execute(
        &SyscallRequest::new(
            libc::SYS_tgkill as u64,
            [tgid as u64, tid as u64, signal as u64, 0, 0, 0],
        ),
        &memory,
    )
}

/// Whether `signal` is queued in the shared queue of `executor`'s process,
/// and in `executor`'s own queue.
fn xsig_queued(executor: &ElfExecutor, signal: i32) -> (bool, bool) {
    (
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .contains(signal),
        executor
            .state
            .thread_signals
            .lock()
            .pending
            .contains(signal),
    )
}

/// `prepare_signal`'s queue effects for a signal a thread sends within its
/// own process: a stop signal, here a caught SIGTSTP, removes SIGCONT from
/// the process's shared queue and from each thread's own queue, and SIGCONT,
/// whose default action ignores it, removes every stop signal from them. A
/// stop signal whose action is the default is refused before any of that,
/// so a queued SIGCONT stays.
#[test]
fn a_stop_signal_and_sigcont_flush_each_other_from_every_queue_of_a_process() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let mut sibling = leader.thread_child(2).unwrap();
    let pid = leader.state.pid;
    // What is queued stays queued.
    for state in [&mut leader.state, &mut sibling.state] {
        for signal in [libc::SIGCONT, libc::SIGTSTP, libc::SIGTTIN] {
            test_block_signal(state, signal);
        }
    }
    queue_signal_event(
        &mut leader.state,
        event_for_process(libc::SIGCONT, pid).unwrap(),
        true,
    )
    .unwrap();
    queue_signal_event(
        &mut leader.state,
        event_for_thread(libc::SIGCONT, pid, pid).unwrap(),
        false,
    )
    .unwrap();
    queue_signal_event(
        &mut sibling.state,
        event_for_thread(libc::SIGCONT, pid, 2).unwrap(),
        false,
    )
    .unwrap();
    assert_eq!(
        xsig_tgkill(&mut leader, pid, 2, libc::SIGTSTP),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        leader.take_unsupported_refusal(),
        xsig_refusal(SignalRefusal::STOP)
    );
    assert_eq!(xsig_queued(&leader, libc::SIGCONT), (true, true));
    assert_eq!(xsig_queued(&sibling, libc::SIGCONT), (true, true));

    test_install_signal_action(&leader.state, libc::SIGTSTP, custom_action(0x1000));
    test_install_signal_action(&leader.state, libc::SIGTTIN, custom_action(0x1000));
    assert_eq!(xsig_tgkill(&mut leader, pid, 2, libc::SIGTSTP), 0);
    assert_eq!(xsig_queued(&leader, libc::SIGCONT), (false, false));
    assert_eq!(xsig_queued(&sibling, libc::SIGCONT), (false, false));
    assert_eq!(xsig_queued(&sibling, libc::SIGTSTP), (false, true));

    queue_signal_event(
        &mut leader.state,
        event_for_process(libc::SIGTTIN, pid).unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(xsig_tgkill(&mut sibling, pid, pid, libc::SIGCONT), 0);
    assert_eq!(xsig_queued(&sibling, libc::SIGTSTP), (false, false));
    assert_eq!(xsig_queued(&leader, libc::SIGTTIN), (false, false));
    assert_eq!(
        xsig_queued(&leader, libc::SIGCONT),
        (false, true),
        "blocked, so queued"
    );
}

/// The same for `kill` of the sender's own process; and the keeper of a
/// signalfd for the flushed signal stops showing it.
#[test]
fn sigcont_to_its_own_process_flushes_a_stop_signal_and_its_signalfd_readiness() {
    const MASK: u64 = 0x100;
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let pid = executor.state.pid;
    test_block_signal(&mut executor.state, libc::SIGTSTP);
    test_install_signal_action(&executor.state, libc::SIGTSTP, custom_action(0x1000));
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut mask = KernelSigset::default();
    mask.insert(libc::SIGTSTP);
    memory.write(MASK, &mask.to_bytes()).unwrap();
    let fd = executor.execute(
        &SyscallRequest::new(
            libc::SYS_signalfd4 as u64,
            [
                u64::MAX,
                MASK,
                KERNEL_SIGSET_SIZE as u64,
                (libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) as u64,
                0,
                0,
            ],
        ),
        &memory,
    );
    assert!(fd >= 0, "signalfd4: {fd}");
    let keeper_ready = |executor: &ElfExecutor| {
        let carrier = executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .signalfd_carriers
            .get(&(fd as i32))
            .expect("the signalfd's keeper")
            .clone();
        let mut poll = libc::pollfd {
            fd: carrier.file().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized descriptor, and no wait.
        assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
        poll.revents & libc::POLLIN != 0
    };
    assert_eq!(xsig_kill(&mut executor, pid, libc::SIGTSTP), 0);
    assert_eq!(xsig_queued(&executor, libc::SIGTSTP), (true, false));
    assert!(keeper_ready(&executor));
    assert_eq!(xsig_kill(&mut executor, pid, libc::SIGCONT), 0);
    assert_eq!(xsig_queued(&executor, libc::SIGTSTP), (false, false));
    assert!(
        !keeper_ready(&executor),
        "the keeper still shows the flushed SIGTSTP"
    );
}

/// A parent and its forked child under a run whose Tool selects recipients
/// and asked for signals to other processes, if `declare`.
fn xsig_parent_and_child(
    root: &TestDir,
    declare: bool,
) -> (ElfExecutor, ElfExecutor, Arc<crate::failure::RunFailure>) {
    let parent = ElfExecutor::new(test_state(&root.0), false);
    let run = xsig_install(
        &parent,
        declare,
        reverie::BackendSignalControlMode::ToolControlled,
    );
    let child = parent
        .fork_child(parent.state.pid + 1, false, false)
        .unwrap();
    (parent, child, run)
}

fn xsig_rt_sigqueueinfo(executor: &mut ElfExecutor, pid: i32, signal: i32, value: u64) -> i64 {
    const INFO: u64 = 0x100;
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut info = [0_u8; 128];
    info[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    info[24..32].copy_from_slice(&value.to_ne_bytes());
    memory.write(INFO, &info).unwrap();
    executor.execute(
        &SyscallRequest::new(
            libc::SYS_rt_sigqueueinfo as u64,
            [pid as u64, signal as u64, INFO, 0, 0, 0],
        ),
        &memory,
    )
}

/// The `si_code`, `si_pid` and `si_uid` of a pending signal's siginfo.
fn xsig_sender(pending: &PendingSignal) -> (i32, i32, u32) {
    let info = pending.event.siginfo();
    (
        i32::from_ne_bytes(info[8..12].try_into().unwrap()),
        i32::from_ne_bytes(info[16..20].try_into().unwrap()),
        u32::from_ne_bytes(info[20..24].try_into().unwrap()),
    )
}

/// `kill` and `rt_sigqueueinfo` of another process queue on that process's
/// shared queue, with `kill`'s siginfo naming the sender's thread group
/// (`SI_USER`, uid 0) and `rt_sigqueueinfo`'s the caller's. A second copy of
/// a pending standard signal keeps the first siginfo. The child's thread
/// takes each only under the Tool's permit, and a keeper of the child's
/// signalfd for the signal shows it.
#[test]
fn a_signal_to_another_process_waits_in_its_shared_queue_with_the_senders_siginfo() {
    const MASK: u64 = 0x100;
    let root = TestDir::new();
    let (mut parent, mut child, _run) = xsig_parent_and_child(&root, true);
    let (pid, child_pid) = (parent.state.pid, child.state.pid);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let mut mask = KernelSigset::default();
    mask.insert(libc::SIGUSR1);
    memory.write(MASK, &mask.to_bytes()).unwrap();
    let fd = child.execute(
        &SyscallRequest::new(
            libc::SYS_signalfd4 as u64,
            [
                u64::MAX,
                MASK,
                KERNEL_SIGSET_SIZE as u64,
                libc::SFD_NONBLOCK as u64,
                0,
                0,
            ],
        ),
        &memory,
    );
    assert!(fd >= 0, "signalfd4: {fd}");

    assert_eq!(xsig_kill(&mut parent, child_pid, libc::SIGUSR1), 0);
    assert_eq!(parent.take_unsupported_refusal(), None);
    assert_eq!(
        xsig_rt_sigqueueinfo(&mut parent, child_pid, libc::SIGUSR1, 7),
        0
    );
    assert_eq!(
        xsig_rt_sigqueueinfo(&mut parent, child_pid, libc::SIGUSR2, 9),
        0
    );
    assert_eq!(xsig_queued(&child, libc::SIGUSR1), (true, false));
    assert_eq!(xsig_queued(&child, libc::SIGUSR2), (true, false));
    assert_eq!(xsig_queued(&parent, libc::SIGUSR1), (false, false));
    let carrier = child
        .state
        .process_signals
        .lock()
        .unwrap()
        .signalfd_carriers
        .get(&(fd as i32))
        .expect("the signalfd's keeper")
        .clone();
    let mut poll = libc::pollfd {
        fd: carrier.file().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized descriptor, and no wait.
    assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);

    assert!(child.take_pending_signal_for_delivery().unwrap().is_none());
    let permit = xsig_permit(&child, 1);
    let first = child
        .take_pending_signal_for_delivery()
        .unwrap()
        .expect("SIGUSR1");
    assert_eq!(first.domain, PendingSignalDomain::Process);
    assert_eq!(first.event.signal(), libc::SIGUSR1);
    assert_eq!(
        xsig_sender(&first),
        (libc::SI_USER, pid, 0),
        "the first siginfo"
    );
    let second = child
        .take_pending_signal_for_delivery()
        .unwrap()
        .expect("SIGUSR2");
    assert_eq!(second.event.signal(), libc::SIGUSR2);
    assert_eq!(xsig_sender(&second).0, libc::SI_QUEUE);
    assert_eq!(
        u64::from_ne_bytes(second.event.siginfo()[24..32].try_into().unwrap()),
        9
    );
    assert!(child.take_pending_signal_for_delivery().unwrap().is_none());
    child
        .backend_signal_control()
        .process
        .release_delivery(permit)
        .unwrap();
}

/// `tgkill` and `tkill` of another process's thread queue on that thread's
/// own queue, with `SI_TKILL` and the sender's thread group id.
#[test]
fn a_signal_to_another_processs_thread_waits_in_its_own_queue() {
    let root = TestDir::new();
    let (mut parent, child, _run) = xsig_parent_and_child(&root, true);
    let (pid, child_pid) = (parent.state.pid, child.state.pid);
    let mut thread = child.thread_child(child_pid + 1).unwrap();
    let tid = thread.state.tid;
    let memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(xsig_tgkill(&mut parent, child_pid, tid, libc::SIGUSR1), 0);
    assert_eq!(
        parent.execute(
            &SyscallRequest::new(
                libc::SYS_tkill as u64,
                [tid as u64, libc::SIGUSR2 as u64, 0, 0, 0, 0]
            ),
            &memory,
        ),
        0
    );
    assert_eq!(
        xsig_tgkill(&mut parent, pid, tid, libc::SIGUSR1),
        negative_errno(libc::ESRCH),
        "another thread group's id"
    );
    for signal in [libc::SIGUSR1, libc::SIGUSR2] {
        assert_eq!(xsig_queued(&thread, signal), (false, true));
        assert_eq!(xsig_queued(&child, signal), (false, false));
    }
    let permit = xsig_permit(&thread, 1);
    for signal in [libc::SIGUSR1, libc::SIGUSR2] {
        let pending = thread
            .take_pending_signal_for_delivery()
            .unwrap()
            .expect("the thread's own signal");
        assert_eq!(pending.domain, PendingSignalDomain::Thread);
        assert_eq!(pending.event.signal(), signal);
        assert_eq!(xsig_sender(&pending), (libc::SI_TKILL, pid, 0));
    }
    thread
        .backend_signal_control()
        .process
        .release_delivery(permit)
        .unwrap();
}

/// What a send to another process still refuses, by name and before any
/// effect: everything without the request; SIGKILL, real-time signals and
/// SIGCHLD; and a stop signal whose action at the target is the default,
/// which leaves a queued SIGCONT in place. A caught stop signal flushes the
/// target's SIGCONT, and SIGCONT flushes its queued stop signals, from the
/// shared queue and its threads' own.
#[test]
fn a_signal_to_another_process_keeps_its_refusals_and_flushes() {
    let root = TestDir::new();
    let (mut parent, child, _run) = xsig_parent_and_child(&root, false);
    let child_pid = child.state.pid;
    for result in [
        xsig_kill(&mut parent, child_pid, libc::SIGUSR1),
        xsig_tgkill(&mut parent, child_pid, child_pid, libc::SIGUSR1),
    ] {
        assert_eq!(result, negative_errno(libc::ENOSYS));
    }
    assert_eq!(
        parent.take_unsupported_refusal(),
        xsig_refusal(SignalRefusal::OTHER_PROCESS)
    );
    assert_eq!(xsig_queued(&child, libc::SIGUSR1), (false, false));
    drop((parent, child));

    let root = TestDir::new();
    let (mut parent, mut child, _run) = xsig_parent_and_child(&root, true);
    let child_pid = child.state.pid;
    let thread = child.thread_child(child_pid + 1).unwrap();
    let tid = thread.state.tid;
    for (number, signal, reason) in [
        (
            libc::SYS_kill,
            libc::SIGKILL,
            SignalRefusal::SIGKILL_OTHER_PROCESS,
        ),
        (
            libc::SYS_tgkill,
            libc::SIGKILL,
            SignalRefusal::SIGKILL_OTHER_PROCESS,
        ),
        (libc::SYS_kill, 34, SignalRefusal::REALTIME_OR_SIGCHLD),
        (
            libc::SYS_tgkill,
            libc::SIGCHLD,
            SignalRefusal::REALTIME_OR_SIGCHLD,
        ),
        (libc::SYS_kill, libc::SIGTSTP, SignalRefusal::STOP),
        (libc::SYS_tgkill, libc::SIGTTIN, SignalRefusal::STOP),
    ] {
        let result = if number == libc::SYS_kill {
            xsig_kill(&mut parent, child_pid, signal)
        } else {
            xsig_tgkill(&mut parent, child_pid, tid, signal)
        };
        assert_eq!(result, negative_errno(libc::ENOSYS), "{number} {signal}");
        assert_eq!(
            parent.take_unsupported_refusal(),
            xsig_refusal(reason),
            "{number} {signal}"
        );
    }
    assert!(
        child
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .is_empty()
    );
    assert!(thread.state.thread_signals.lock().pending.is_empty());

    // Caught and blocked in the child, so what is queued stays queued.
    for signal in [libc::SIGCONT, libc::SIGTSTP] {
        test_install_signal_action(&child.state, signal, custom_action(0x1000));
        test_block_signal(&mut child.state, signal);
    }
    assert_eq!(xsig_kill(&mut parent, child_pid, libc::SIGCONT), 0);
    assert_eq!(xsig_tgkill(&mut parent, child_pid, tid, libc::SIGCONT), 0);
    assert_eq!(xsig_queued(&child, libc::SIGCONT), (true, false));
    assert_eq!(xsig_queued(&thread, libc::SIGCONT), (true, true));
    // SIGTTIN keeps its default action: refused, and SIGCONT stays.
    assert_eq!(
        xsig_kill(&mut parent, child_pid, libc::SIGTTIN),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(xsig_queued(&thread, libc::SIGCONT), (true, true));
    assert_eq!(xsig_kill(&mut parent, child_pid, libc::SIGTSTP), 0);
    assert_eq!(xsig_queued(&thread, libc::SIGCONT), (false, false));
    assert_eq!(xsig_queued(&child, libc::SIGTSTP), (true, false));
    assert_eq!(xsig_tgkill(&mut parent, child_pid, tid, libc::SIGTSTP), 0);
    assert_eq!(xsig_queued(&thread, libc::SIGTSTP), (true, true));
    assert_eq!(xsig_kill(&mut parent, child_pid, libc::SIGCONT), 0);
    assert_eq!(xsig_queued(&thread, libc::SIGTSTP), (false, false));
    assert_eq!(xsig_queued(&child, libc::SIGCONT), (true, false));
}

/// The target is revalidated under its own transaction: a process lifetime
/// or task lifetime the sender's lookup did not find there is refused, and
/// nothing is queued.
#[test]
fn a_send_to_a_target_that_does_not_match_is_refused() {
    let root = TestDir::new();
    let (parent, child, _run) = xsig_parent_and_child(&root, true);
    let process = child.admitted_signal_identity().process;
    let event = |target| {
        reverie::SignalEvent::new(
            libc::SIGUSR1,
            crate::signal::signal_info_user(libc::SIGUSR1, parent.state.pid, 0, libc::SI_USER),
            target,
        )
        .unwrap()
    };
    let forged_process = reverie::SignalProcessId {
        generation: process.generation + 100,
        ..process
    };
    let mut forged_task = child.admitted_signal_identity();
    forged_task.task_generation += 100;
    for destination in [
        process_signal_publication::SignalDestination::Process(forged_process),
        process_signal_publication::SignalDestination::Thread(forged_task),
    ] {
        assert_eq!(
            parent.signal_registry.send_to_other_process(
                destination,
                event(reverie::SignalTarget::Process { pid: process.tgid })
            ),
            Err(process_signal_publication::UnsentSignal::TargetChanged),
            "{destination:?}"
        );
    }
    assert_eq!(xsig_queued(&child, libc::SIGUSR1), (false, false));
}

/// A send within the sender's process keeps the single-lock path: it never
/// takes another process's transaction, so the hook that runs before that
/// never runs.
#[test]
fn a_send_within_the_senders_process_keeps_its_single_lock_path() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let _run = xsig_install(
        &leader,
        true,
        reverie::BackendSignalControlMode::ToolControlled,
    );
    let sibling = leader.thread_child(leader.state.pid + 1).unwrap();
    let pid = leader.state.pid;
    let reached = Arc::new(AtomicU64::new(0));
    process_signal_publication::IMAGE_CLONED_TEST_HOOK.with(|hook| {
        let reached = reached.clone();
        *hook.borrow_mut() = Some(Box::new(move || {
            reached.fetch_add(1, Ordering::SeqCst);
        }));
    });
    assert_eq!(xsig_kill(&mut leader, pid, libc::SIGUSR1), 0);
    assert_eq!(
        xsig_tgkill(&mut leader, pid, sibling.state.tid, libc::SIGUSR2),
        0
    );
    process_signal_publication::IMAGE_CLONED_TEST_HOOK.with(|hook| hook.borrow_mut().take());
    assert_eq!(reached.load(Ordering::SeqCst), 0);
    assert_eq!(xsig_queued(&leader, libc::SIGUSR1), (true, false));
    assert_eq!(xsig_queued(&sibling, libc::SIGUSR2), (false, true));
}

/// A child's exit interleaved with its parent's send, on each side of the
/// moment the send takes the child's transaction. The exit holds the
/// child's transaction while it takes the parent's (`record_process_exit`),
/// so the send must hold neither of them while it waits for the other.
/// - The exit runs to its end before the send takes the child's
///   transaction: no deadlock, and the send finds the child gone, refused by
///   name with nothing queued.
/// - The exit starts while the send holds the child's transaction: it waits,
///   the send queues the signal and answers 0, and then the exit completes.
#[test]
fn a_childs_exit_interleaved_with_its_parents_send_neither_deadlocks_nor_loses_the_answer() {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;
    for held in [false, true] {
        let root = TestDir::new();
        let (mut parent, child, _run) = xsig_parent_and_child(&root, true);
        let child_pid = child.state.pid;
        let child = Arc::new(Mutex::new(Some(child)));
        let exiting = Arc::new(Mutex::new(None));
        let (exited, exit_seen) = std::sync::mpsc::channel();
        let hook = {
            let (child, exiting) = (child.clone(), exiting.clone());
            move || {
                let mut child = child.lock().unwrap().take().expect("one exit");
                let exited = exited.clone();
                let thread = std::thread::spawn(move || {
                    let exit = commit_test_exit(&mut child, 0, true);
                    // Where the send held the child's transaction, nobody
                    // is listening by now: the join reports the exit.
                    let _ = exited.send(());
                    (child, exit)
                });
                if held {
                    // It needs the child's transaction, which the send holds.
                    assert_eq!(
                        exit_seen.recv_timeout(Duration::from_millis(200)),
                        Err(RecvTimeoutError::Timeout),
                        "the child exited while the send held its transaction"
                    );
                } else {
                    exit_seen
                        .recv_timeout(Duration::from_secs(60))
                        .expect("the child's exit deadlocked against its parent's send");
                }
                *exiting.lock().unwrap() = Some(thread);
            }
        };
        let slot = if held {
            &process_signal_publication::TRANSACTION_HELD_TEST_HOOK
        } else {
            &process_signal_publication::IMAGE_CLONED_TEST_HOOK
        };
        slot.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        let result = xsig_kill(&mut parent, child_pid, libc::SIGUSR1);
        slot.with(|slot| slot.borrow_mut().take());
        let (child, exit) = exiting
            .lock()
            .unwrap()
            .take()
            .expect("the hook ran")
            .join()
            .unwrap();
        assert_eq!(exit.status, ExitStatus::Exited(0));
        let queued = xsig_queued(&child, libc::SIGUSR1);
        if held {
            assert_eq!(result, 0);
            assert_eq!(queued, (true, false), "queued before the exit");
        } else {
            assert_eq!(result, negative_errno(libc::ENOSYS));
            assert_eq!(
                parent.take_unsupported_refusal(),
                xsig_refusal(SignalRefusal::TARGET_CHANGED)
            );
            assert_eq!(queued, (false, false));
        }
    }
}

/// With the request, a signal through the id of another process's thread
/// that does not lead it waits in that process's shared queue, as
/// `kill_pid_info_type` signals the task's thread group, for `kill` and
/// `rt_sigqueueinfo` alike. The siginfo `kill` builds names the sender's
/// thread group, also when a thread that does not lead its process sends.
#[test]
fn a_signal_through_another_processs_thread_id_waits_in_its_shared_queue() {
    let root = TestDir::new();
    let (mut parent, child, _run) = xsig_parent_and_child(&root, true);
    let (pid, child_pid) = (parent.state.pid, child.state.pid);
    let thread = child.thread_child(child_pid + 1).unwrap();
    let tid = thread.state.tid;
    let mut sibling = parent.thread_child(child_pid + 2).unwrap();
    assert_eq!(xsig_kill(&mut sibling, tid, libc::SIGUSR1), 0);
    assert_eq!(sibling.take_unsupported_refusal(), None);
    assert_eq!(xsig_rt_sigqueueinfo(&mut parent, tid, libc::SIGUSR2, 5), 0);
    assert_eq!(parent.take_unsupported_refusal(), None);
    for signal in [libc::SIGUSR1, libc::SIGUSR2] {
        assert_eq!(xsig_queued(&thread, signal), (true, false), "{signal}");
    }
    assert_eq!(
        pss_take(&child, libc::SIGUSR1, true),
        Some((libc::SI_USER, pid, 0))
    );
    assert_eq!(
        pss_take(&child, libc::SIGUSR2, true),
        Some((libc::SI_QUEUE, 0, 0))
    );
}
