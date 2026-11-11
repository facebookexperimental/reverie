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
