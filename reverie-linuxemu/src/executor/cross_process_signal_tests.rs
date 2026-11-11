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
