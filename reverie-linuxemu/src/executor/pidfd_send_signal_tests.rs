// `pidfd_send_signal` (`executor/sys_signal.rs`): Linux's checks in Linux's
// order (`pidfd_send_signal` and `do_pidfd_send_signal`, kernel/signal.c),
// the scope a descriptor and the flags give, and the target's lifetime.

const PSS_SELF_THREAD: i64 = -10000;
const PSS_SELF_THREAD_GROUP: i64 = -10001;
const PSS_INFO: u64 = 0x200;

fn pss_send(
    executor: &mut ElfExecutor,
    memory: &GuestMemory,
    pidfd: i64,
    signal: i32,
    info: u64,
    flags: libc::c_uint,
) -> i64 {
    executor.execute(
        &SyscallRequest::new(
            libc::SYS_pidfd_send_signal as u64,
            [pidfd as u64, signal as u64, info, u64::from(flags), 0, 0],
        ),
        memory,
    )
}

/// Writes a siginfo with `signo` and `code` at `PSS_INFO`, and returns its
/// address.
fn pss_info(memory: &mut GuestMemory, signo: i32, code: i32) -> u64 {
    let mut info = [0_u8; 128];
    info[0..4].copy_from_slice(&signo.to_ne_bytes());
    info[8..12].copy_from_slice(&code.to_ne_bytes());
    info[24..32].copy_from_slice(&0x5eed_u64.to_ne_bytes());
    memory.write(PSS_INFO, &info).unwrap();
    PSS_INFO
}

/// Removes `signal` from the shared queue of `executor`'s process, if
/// `shared`, or else from `executor`'s own queue, and returns the `si_code`,
/// `si_pid` and `si_uid` of its siginfo.
fn pss_take(executor: &ElfExecutor, signal: i32, shared: bool) -> Option<(i32, i32, u32)> {
    let event = if shared {
        executor
            .state
            .process_signals
            .lock()
            .unwrap()
            .shared_pending
            .remove(signal)
    } else {
        executor.state.thread_signals.lock().pending.remove(signal)
    }?;
    let info = event.siginfo();
    Some((
        i32::from_ne_bytes(info[8..12].try_into().unwrap()),
        i32::from_ne_bytes(info[16..20].try_into().unwrap()),
        u32::from_ne_bytes(info[20..24].try_into().unwrap()),
    ))
}

/// Flags come first, then the descriptor: an unknown flag or two scopes is
/// EINVAL whatever the descriptor; a descriptor that is not open, or not a
/// pidfd, is EBADF; and a pidfd this executor keeps no record of, as one
/// from outside the run, is refused by name, signal 0 included.
#[test]
fn pidfd_send_signal_checks_its_flags_then_its_descriptor() {
    const PIPE: i32 = 60;
    const OUTSIDE: i32 = 61;
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let (read, write) = std::io::pipe().unwrap();
    // SAFETY: pidfd_open takes no pointers.
    let host = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) as libc::c_int };
    assert!(host >= 0);
    // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
    let host = unsafe { std::fs::File::from_raw_fd(host) };
    let read = std::fs::File::from(std::os::fd::OwnedFd::from(read));
    assert!(state.insert_file(PIPE, read).is_empty());
    assert!(state.insert_file(OUTSIDE, host).is_empty());
    let mut executor = ElfExecutor::new(state, false);
    let memory = pidfd_test_memory();
    for flags in [
        1 << 3,
        libc::PIDFD_SIGNAL_THREAD | libc::PIDFD_SIGNAL_THREAD_GROUP,
        libc::PIDFD_SIGNAL_THREAD_GROUP | libc::PIDFD_SIGNAL_PROCESS_GROUP,
    ] {
        for pidfd in [PSS_SELF_THREAD, 999] {
            assert_eq!(
                pss_send(&mut executor, &memory, pidfd, libc::SIGUSR1, 0, flags),
                negative_errno(libc::EINVAL),
                "flags {flags:#x}, pidfd {pidfd}"
            );
        }
    }
    for pidfd in [999, -1, i64::from(PIPE)] {
        assert_eq!(
            pss_send(&mut executor, &memory, pidfd, 0, 0, 0),
            negative_errno(libc::EBADF),
            "pidfd {pidfd}"
        );
    }
    drop(write);
    for signal in [0, libc::SIGUSR1] {
        assert_eq!(
            pss_send(&mut executor, &memory, i64::from(OUTSIDE), signal, 0, 0),
            negative_errno(libc::ENOSYS)
        );
        assert_eq!(
            executor.take_unsupported_refusal(),
            xsig_refusal(SignalRefusal::PIDFD_WITHOUT_RECORD)
        );
    }
    assert_eq!(xsig_queued(&executor, libc::SIGUSR1), (false, false));
}

/// Without a siginfo, a send builds `tgkill`'s siginfo in thread scope and
/// `kill`'s in thread-group scope, each with the sender's thread group id;
/// a scope flag overrides the descriptor's scope, which is the thread for
/// `PIDFD_SELF_THREAD` and the thread group for `PIDFD_SELF_THREAD_GROUP`
/// and for a pidfd. A send to a process group is refused by name.
#[test]
fn pidfd_send_signal_takes_its_scope_from_its_descriptor_unless_a_flag_overrides_it() {
    let root = TestDir::new();
    let mut executor = ElfExecutor::new(test_state(&root.0), false);
    let memory = pidfd_test_memory();
    let pid = executor.state.pid;
    let own = pidfd_test_open(&mut executor, &memory, i64::from(pid), 0);
    assert!(own >= 0, "pidfd_open of itself: {own}");
    let tkill = Some((libc::SI_TKILL, pid, 0));
    let kill = Some((libc::SI_USER, pid, 0));
    for (pidfd, flags, shared, expected) in [
        (PSS_SELF_THREAD, 0, false, tkill),
        (PSS_SELF_THREAD, libc::PIDFD_SIGNAL_THREAD_GROUP, true, kill),
        (PSS_SELF_THREAD_GROUP, 0, true, kill),
        (
            PSS_SELF_THREAD_GROUP,
            libc::PIDFD_SIGNAL_THREAD,
            false,
            tkill,
        ),
        (own, 0, true, kill),
        (own, libc::PIDFD_SIGNAL_THREAD, false, tkill),
    ] {
        assert_eq!(
            pss_send(&mut executor, &memory, pidfd, libc::SIGUSR1, 0, flags),
            0,
            "pidfd {pidfd}, flags {flags:#x}"
        );
        assert_eq!(executor.take_unsupported_refusal(), None);
        assert_eq!(
            pss_take(&executor, libc::SIGUSR1, shared),
            expected,
            "pidfd {pidfd}, flags {flags:#x}"
        );
        assert_eq!(xsig_queued(&executor, libc::SIGUSR1), (false, false));
    }
    for pidfd in [PSS_SELF_THREAD, PSS_SELF_THREAD_GROUP, own] {
        assert_eq!(
            pss_send(
                &mut executor,
                &memory,
                pidfd,
                libc::SIGUSR1,
                0,
                libc::PIDFD_SIGNAL_PROCESS_GROUP
            ),
            negative_errno(libc::ENOSYS)
        );
        assert_eq!(
            executor.take_unsupported_refusal(),
            xsig_refusal(SignalRefusal::PIDFD_PROCESS_GROUP)
        );
    }
    assert_eq!(xsig_queued(&executor, libc::SIGUSR1), (false, false));
}

/// A caller's siginfo is copied in (EFAULT) and must carry the signal
/// (EINVAL), for signal 0 too. A kernel or `tkill` code (`si_code >= 0` or
/// `SI_TKILL`) is EPERM unless the descriptor names exactly the caller's
/// thread and the scope is not a process group: `PIDFD_SELF_THREAD`, or the
/// leader's own `PIDFD_SELF_THREAD_GROUP` or pidfd, whose sends queue the
/// caller's siginfo, but not a sibling's `PIDFD_SELF_THREAD_GROUP`, which
/// names the leader.
#[test]
fn pidfd_send_signal_checks_a_callers_siginfo() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let _run = xsig_install(
        &leader,
        true,
        reverie::BackendSignalControlMode::ToolControlled,
    );
    let mut memory = pidfd_test_memory();
    let pid = leader.state.pid;
    let own = pidfd_test_open(&mut leader, &memory, i64::from(pid), 0);
    assert!(own >= 0);
    let mut sibling = leader.thread_child(pid + 1).unwrap();

    for signal in [0, libc::SIGUSR1] {
        assert_eq!(
            pss_send(&mut leader, &memory, PSS_SELF_THREAD, signal, 0x10_0000, 0),
            negative_errno(libc::EFAULT),
            "signal {signal}"
        );
        let info = pss_info(&mut memory, libc::SIGUSR2, libc::SI_QUEUE);
        assert_eq!(
            pss_send(&mut leader, &memory, PSS_SELF_THREAD, signal, info, 0),
            negative_errno(libc::EINVAL),
            "signal {signal}"
        );
    }

    for code in [libc::SI_USER, libc::SI_TKILL, libc::SI_KERNEL] {
        let info = pss_info(&mut memory, libc::SIGUSR1, code);
        // A sibling's PIDFD_SELF_THREAD_GROUP names the leader, not itself;
        // a process group is never the caller's thread.
        for (from_sibling, pidfd, flags) in [
            (true, PSS_SELF_THREAD_GROUP, 0),
            (true, own, 0),
            (false, PSS_SELF_THREAD, libc::PIDFD_SIGNAL_PROCESS_GROUP),
        ] {
            let executor = if from_sibling {
                &mut sibling
            } else {
                &mut leader
            };
            assert_eq!(
                pss_send(executor, &memory, pidfd, libc::SIGUSR1, info, flags),
                negative_errno(libc::EPERM),
                "code {code}, pidfd {pidfd}, flags {flags:#x}"
            );
            assert_eq!(executor.take_unsupported_refusal(), None);
        }
        for (from_sibling, pidfd, shared) in [
            (true, PSS_SELF_THREAD, false),
            (false, PSS_SELF_THREAD, false),
            (false, PSS_SELF_THREAD_GROUP, true),
            (false, own, true),
        ] {
            let executor = if from_sibling {
                &mut sibling
            } else {
                &mut leader
            };
            assert_eq!(
                pss_send(executor, &memory, pidfd, libc::SIGUSR1, info, 0),
                0,
                "code {code}, pidfd {pidfd}"
            );
            assert_eq!(
                pss_take(executor, libc::SIGUSR1, shared),
                Some((code, 0, 0)),
                "code {code}, pidfd {pidfd}"
            );
        }
    }
    // A code a user may send, SI_QUEUE, through the sibling's
    // PIDFD_SELF_THREAD_GROUP: queued with the caller's siginfo.
    let info = pss_info(&mut memory, libc::SIGUSR1, libc::SI_QUEUE);
    assert_eq!(
        pss_send(
            &mut sibling,
            &memory,
            PSS_SELF_THREAD_GROUP,
            libc::SIGUSR1,
            info,
            0
        ),
        0
    );
    assert_eq!(
        pss_take(&leader, libc::SIGUSR1, true),
        Some((libc::SI_QUEUE, 0, 0))
    );
}

/// A pidfd for another process takes the path `kill` takes, and with
/// `PIDFD_SIGNAL_THREAD` the one `tgkill` takes to its leader: refused by
/// name unless the Tool asked for signals to other processes, and then
/// queued on the child's shared queue or its leader's own queue, with the
/// sender's thread group id. Signal 0 answers 0 either way.
#[test]
fn pidfd_send_signal_to_another_process_takes_the_kill_and_tgkill_paths() {
    for declare in [false, true] {
        let root = TestDir::new();
        let (mut parent, child, _run) = xsig_parent_and_child(&root, declare);
        let memory = pidfd_test_memory();
        let (pid, child_pid) = (parent.state.pid, child.state.pid);
        let pidfd = pidfd_test_open(&mut parent, &memory, i64::from(child_pid), 0);
        assert!(pidfd >= 0);
        for flags in [
            0,
            libc::PIDFD_SIGNAL_THREAD,
            libc::PIDFD_SIGNAL_THREAD_GROUP,
        ] {
            assert_eq!(pss_send(&mut parent, &memory, pidfd, 0, 0, flags), 0);
            let sent = pss_send(&mut parent, &memory, pidfd, libc::SIGUSR1, 0, flags);
            if !declare {
                assert_eq!(sent, negative_errno(libc::ENOSYS), "flags {flags:#x}");
                assert_eq!(
                    parent.take_unsupported_refusal(),
                    xsig_refusal(SignalRefusal::OTHER_PROCESS)
                );
                assert_eq!(xsig_queued(&child, libc::SIGUSR1), (false, false));
                continue;
            }
            assert_eq!(sent, 0, "flags {flags:#x}");
            assert_eq!(parent.take_unsupported_refusal(), None);
            let shared = flags != libc::PIDFD_SIGNAL_THREAD;
            let code = if shared {
                libc::SI_USER
            } else {
                libc::SI_TKILL
            };
            assert_eq!(
                pss_take(&child, libc::SIGUSR1, shared),
                Some((code, pid, 0)),
                "flags {flags:#x}"
            );
            assert_eq!(xsig_queued(&child, libc::SIGUSR1), (false, false));
        }
    }
}

/// A process that has exited and has not been reaped answers 0 and drops
/// the signal, after the siginfo checks and the check of the signal; once
/// reaped it is ESRCH, before the check of the signal.
#[test]
fn pidfd_send_signal_to_an_exited_process_answers_0_until_it_is_reaped() {
    let root = TestDir::new();
    let (mut parent, mut child, _run) = xsig_parent_and_child(&root, true);
    let mut memory = pidfd_test_memory();
    let child_pid = child.state.pid;
    let pidfd = pidfd_test_open(&mut parent, &memory, i64::from(child_pid), 0);
    assert!(pidfd >= 0);
    pidfd_test_exit(&mut parent, &mut child);
    for signal in [0, libc::SIGUSR1, libc::SIGKILL] {
        assert_eq!(
            pss_send(&mut parent, &memory, pidfd, signal, 0, 0),
            0,
            "signal {signal}"
        );
        assert_eq!(parent.take_unsupported_refusal(), None);
    }
    assert_eq!(
        pss_send(&mut parent, &memory, pidfd, 65, 0, 0),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(
        pss_send(&mut parent, &memory, pidfd, libc::SIGUSR1, 0x10_0000, 0),
        negative_errno(libc::EFAULT)
    );
    let forged = pss_info(&mut memory, libc::SIGUSR1, libc::SI_USER);
    assert_eq!(
        pss_send(&mut parent, &memory, pidfd, libc::SIGUSR1, forged, 0),
        negative_errno(libc::EPERM)
    );

    pidfd_test_reap(&mut parent, &memory, child_pid);
    for signal in [0, libc::SIGUSR1, 65] {
        assert_eq!(
            pss_send(&mut parent, &memory, pidfd, signal, 0, 0),
            negative_errno(libc::ESRCH),
            "signal {signal}"
        );
    }
}

/// Once its leader has exited, a process's other thread can still send to
/// the process through `PIDFD_SELF_THREAD_GROUP`; in thread scope, which
/// names the exited leader, signal 0 answers 0 and a signal is refused by
/// name.
#[test]
fn pidfd_send_signal_in_thread_scope_to_an_exited_leader_is_refused() {
    let root = TestDir::new();
    let mut leader = ElfExecutor::new(test_state(&root.0), false);
    let memory = pidfd_test_memory();
    let pid = leader.state.pid;
    let mut sibling = leader.thread_child(pid + 1).unwrap();
    leader.retire_current_thread(ExitStatus::Exited(0), false);
    assert_eq!(
        pss_send(
            &mut sibling,
            &memory,
            PSS_SELF_THREAD_GROUP,
            0,
            0,
            libc::PIDFD_SIGNAL_THREAD
        ),
        0
    );
    assert_eq!(
        pss_send(
            &mut sibling,
            &memory,
            PSS_SELF_THREAD_GROUP,
            libc::SIGUSR1,
            0,
            libc::PIDFD_SIGNAL_THREAD
        ),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        sibling.take_unsupported_refusal(),
        xsig_refusal(SignalRefusal::EXITED_LEADER)
    );
    assert_eq!(xsig_queued(&sibling, libc::SIGUSR1), (false, false));
    assert_eq!(
        pss_send(
            &mut sibling,
            &memory,
            PSS_SELF_THREAD_GROUP,
            libc::SIGUSR1,
            0,
            0
        ),
        0
    );
    assert_eq!(
        pss_take(&sibling, libc::SIGUSR1, true),
        Some((libc::SI_USER, pid, 0))
    );
}
