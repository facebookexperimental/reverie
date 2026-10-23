// Actual initialized KvmGuest/Tool/frame controls. This component has no Hermit
// scheduler or timer: repeated publications are explicit fixture stimuli.
use reverie::CallbackSignalSite;
use reverie::DequeueId;
use reverie::ParkedObservationLease;
use reverie::PendingDomain;
use reverie::ProcessAlarmSignalOutcome;
use reverie::SignalConsumer;
use reverie::SignalDequeue;
use reverie::SignalObservationStep;
use reverie::SignalObservationStop;
use reverie::SignalTaskIdentity;
use reverie::syscalls::Addr;

use super::*;

#[derive(Clone, Debug)]
enum Seen {
    Start(SignalTaskIdentity),
    Dequeue(SignalDequeue),
    Hook(DequeueId),
    Finish(CallbackSignalSite),
    RestartReadCallback(Option<CallbackSignalSite>, i32),
    RestartReadResult(Result<i64, Errno>),
    Exit(ExitStatus),
}
static SEEN: Mutex<Vec<Seen>> = Mutex::new(Vec::new());
fn seen(value: Seen) {
    SEEN.lock().unwrap().push(value);
}
fn alarm(pid: Pid) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    SignalEvent::new(libc::SIGALRM, info, SignalTarget::Process { pid }).unwrap()
}
fn foreign_sites(site: CallbackSignalSite) -> Vec<CallbackSignalSite> {
    let mut sites = vec![site; 6];
    sites[0].process.generation += 1;
    sites[1].process.tgid = Pid::from_raw(site.process.tgid.as_raw() + 10);
    sites[2].tid = Pid::from_raw(site.tid.as_raw() + 10);
    sites[3].task_generation += 1;
    sites[4].callback_nonce += 1;
    sites[5].boundary_nonce += 1;
    sites
}
#[derive(Default, Debug)]
struct Global;
#[reverie::global_tool]
impl GlobalTool for Global {
    type Request = u64;
    type Response = u64;
    type Config = u8;
    async fn receive_rpc(&self, _: Pid, value: u64) -> u64 {
        let mut first = true;
        futures::future::poll_fn(|cx| {
            if std::mem::take(&mut first) {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(value)
            }
        })
        .await
    }
}
#[derive(Default)]
struct ParkedTool {
    mode: u8,
    removed: AtomicU64,
    hooks: AtomicU64,
    restart_read_calls: AtomicU64,
}
#[reverie::tool]
impl Tool for ParkedTool {
    type GlobalState = Global;
    type ThreadState = ();
    fn new(_: Pid, mode: &u8) -> Self {
        Self {
            mode: *mode,
            ..Default::default()
        }
    }
    fn may_observe_signal_dequeues(_: &u8) -> bool {
        true
    }
    fn subscriptions(mode: &u8) -> Subscription {
        let mut subscription = Subscription::all();
        if *mode == 8 {
            subscription.disable_syscall(Sysno::read);
        }
        if *mode == 9 {
            subscription.disable_syscall(Sysno::rt_sigtimedwait);
        }
        subscription
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let identity = guest
            .signal_task_identity()
            .expect("identity before first guest instruction");
        assert_eq!(identity.tid, guest.tid());
        assert_eq!(identity.process.tgid, guest.pid());
        assert!(identity.task_generation > 0 && identity.process.generation > 0);
        assert!(guest.parked_signal_site().is_none());
        // This GlobalState keeps the default installation: observing dequeues
        // does not make the run controlled.
        assert_eq!(
            guest.signal_control_mode(),
            reverie::BackendSignalControlMode::Unchanged
        );
        seen(Seen::Start(identity));
        Ok(())
    }
    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        effect: SignalDequeue,
    ) -> Result<(), Errno> {
        let ordinal = self.removed.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(effect.sequence, ordinal);
        assert_eq!(
            effect.process,
            guest.signal_task_identity().unwrap().process
        );
        assert_eq!(effect.domain, PendingDomain::Process);
        assert_eq!(effect.event, alarm(guest.pid()));
        assert_eq!(
            guest.inject(reverie::syscalls::Getpid::new()).await,
            Err(Errno::ENOSYS)
        );
        assert_eq!(guest.send_rpc(ordinal).await, ordinal);
        seen(Seen::Dequeue(effect));
        if self.mode == 13 {
            guest.cancel_current_thread().await;
        }
        if self.mode == 10 {
            Err(Errno::EIO)
        } else {
            Ok(())
        }
    }
    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let ordinal = self.hooks.fetch_add(1, Ordering::SeqCst);
        let identity = guest.signal_task_identity().unwrap();
        let id = DequeueId {
            process: identity.process,
            sequence: self.removed.load(Ordering::SeqCst),
        };
        assert!(id.sequence > 0);
        assert_eq!(event, alarm(guest.pid()));
        assert!(guest.signal_observation_lease().is_some());
        assert_eq!(guest.send_rpc(0x100 + ordinal).await, 0x100 + ordinal);
        assert_eq!(
            guest.inject(reverie::syscalls::Getpid::new()).await?,
            i64::from(guest.pid().as_raw())
        );
        assert_eq!(guest.inject(Fork::new()).await, Err(Errno::ENOSYS));
        assert_eq!(
            guest.inject(ExitGroup::new().with_status(99)).await,
            Err(Errno::ENOSYS)
        );
        seen(Seen::Hook(id));
        if self.mode == 14 {
            let mut stack = guest.stack().await;
            let action = stack.push([libc::SIG_IGN as u64, 0, 0, 0]).as_raw() as usize;
            let _guard = stack.commit()?;
            let mutate = Syscall::from_raw(
                Sysno::rt_sigaction,
                SyscallArgs::new(libc::SIGALRM as usize, action, 0, 8, 0, 0),
            );
            assert_eq!(
                guest.inject(mutate).await?,
                0,
                "pre-selection action work remains supported"
            );
        }
        if self.mode == 11 {
            guest.tail_inject(reverie::syscalls::Getpid::new()).await;
        }
        if self.mode == 1 || self.mode == 15 {
            return Ok(None);
        }
        if self.mode == 2 && ordinal == 0 {
            let mut stack = guest.stack().await;
            let mask = stack.push(1_u64 << (libc::SIGALRM - 1)).as_raw() as usize;
            let _guard = stack.commit()?;
            let call = Syscall::from_raw(
                Sysno::rt_sigprocmask,
                SyscallArgs::new(libc::SIG_BLOCK as usize, mask, 0, 8, 0, 0),
            );
            assert_eq!(guest.inject(call).await?, 0);
        }
        Ok(Some(event))
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let (_, args) = syscall.into_parts();
        let restart_read = (17..=19).contains(&self.mode)
            && syscall.number() == Sysno::read
            && args.arg3 == 0x7061726b;
        let mut completed_read = None;
        if restart_read {
            assert_eq!(args.arg4 as u8, self.mode);
            let handled = guest
                .memory()
                .read_value(Addr::<i32>::from_raw(args.arg5).ok_or(Errno::EFAULT)?)?;
            seen(Seen::RestartReadCallback(
                guest.parked_signal_site(),
                handled,
            ));
            let ordinal = self.restart_read_calls.fetch_add(1, Ordering::SeqCst);
            if ordinal != 0 {
                assert_eq!(ordinal, 1, "the read restarted more than once");
                assert_eq!(self.mode, 18, "only SA_RESTART may repeat the read");
                assert_eq!(
                    handled, 1,
                    "callback re-entered before the prepared handler ran"
                );
                assert!(
                    guest.parked_signal_site().is_some(),
                    "restart needs a fresh callback site"
                );
                let result = guest.inject(syscall).await;
                seen(Seen::RestartReadResult(result));
                assert_eq!(result, Ok(1), "handler supplied the real restart byte");
                assert!(
                    guest
                        .polled_read_signal_site(reverie::syscalls::Read::from(args))
                        .is_none()
                );
                return result.map_err(Into::into);
            }
            assert_eq!(handled, 0);
            let read = reverie::syscalls::Read::from(args);
            assert!(
                guest.polled_read_signal_site(read).is_none(),
                "no actual attempt yet"
            );
            let result = guest.inject(syscall).await;
            seen(Seen::RestartReadResult(result));
            if self.mode == 19 {
                assert!(
                    guest.polled_read_signal_site(read).is_none(),
                    "partial result is complete"
                );
                assert_eq!(
                    result,
                    Ok(3),
                    "control requires an actual positive short read"
                );
                completed_read = Some(3);
            } else {
                assert_eq!(
                    result,
                    Err(Errno::EAGAIN),
                    "control requires actual zero progress"
                );
                let site = guest
                    .polled_read_signal_site(read)
                    .expect("exact real EAGAIN");
                let raw = [
                    args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
                ];
                for index in 0..6 {
                    let mut wrong = raw;
                    wrong[index] = wrong[index].wrapping_add(1);
                    let wrong_read = reverie::syscalls::Read::from(SyscallArgs::new(
                        wrong[0], wrong[1], wrong[2], wrong[3], wrong[4], wrong[5],
                    ));
                    assert!(guest.polled_read_signal_site(wrong_read).is_none());
                }
                let stack = guest.stack().await;
                assert!(
                    guest.polled_read_signal_site(read).is_none(),
                    "checked-out scratch"
                );
                drop(stack);
                assert_eq!(guest.polled_read_signal_site(read), Some(site));
                // EAGAIN from a different real read is not this original read's witness.
                let wrong = reverie::syscalls::Read::from(SyscallArgs::new(
                    args.arg0,
                    args.arg1 + 1,
                    args.arg2,
                    args.arg3,
                    args.arg4,
                    args.arg5,
                ));
                assert_eq!(guest.inject(wrong).await, Err(Errno::EAGAIN));
                assert!(guest.polled_read_signal_site(read).is_none());
                assert!(guest.polled_read_signal_site(wrong).is_none());
                assert_eq!(guest.inject(read).await, Err(Errno::EAGAIN));
                assert_eq!(guest.polled_read_signal_site(read), Some(site));
                assert_eq!(
                    guest.inject(reverie::syscalls::Getpid::new()).await?,
                    i64::from(guest.pid().as_raw())
                );
                assert!(
                    guest.polled_read_signal_site(read).is_none(),
                    "later injection invalidates witness"
                );
                assert_eq!(guest.inject(read).await, Err(Errno::EAGAIN));
                assert_eq!(guest.polled_read_signal_site(read), Some(site));
            }
        } else {
            if syscall.number() != Sysno::getpid || args.arg0 != 0x7061726b {
                guest.tail_inject(syscall).await;
            }
            assert_eq!(args.arg1 as u8, self.mode);
        }
        let site = guest
            .parked_signal_site()
            .expect("actual original syscall boundary");
        let cycles = if self.mode <= 1 { 3 } else { 1 };
        for cycle in 0..cycles {
            let outcome = guest.queue_process_alarm_signal(alarm(guest.pid())).await;
            assert!(
                matches!(outcome, ProcessAlarmSignalOutcome::Accepted(_)),
                "{outcome:?}"
            );
            if (6..=10).contains(&self.mode) || self.mode == 13 {
                if self.mode == 8 || self.mode == 9 || self.mode == 13 {
                    return Ok(123);
                }
                let call = if self.mode == 7 {
                    Syscall::from_raw(
                        Sysno::rt_sigtimedwait,
                        SyscallArgs::new(args.arg2, 1, 0, 8, 0, 0),
                    )
                } else {
                    Syscall::from_raw(Sysno::read, SyscallArgs::new(args.arg3, 1, 128, 0, 0, 0))
                };
                assert_eq!(guest.inject(call).await, Err(Errno::EFAULT));
                assert_eq!(
                    self.removed.load(Ordering::SeqCst),
                    1,
                    "effect acknowledgment preceded errno return"
                );
                return Ok(123);
            }
            if self.mode <= 1 && cycle > 0 {
                let removed = self.removed.load(Ordering::SeqCst);
                let hooks = self.hooks.load(Ordering::SeqCst);
                let context = guest.parked_signal_failure_context();
                assert_eq!(
                    guest
                        .observe_parked_signal(site, ParkedObservationLease { nonce: cycle })
                        .await,
                    Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                        errno: Errno::EINVAL
                    })
                );
                assert_eq!(self.removed.load(Ordering::SeqCst), removed);
                assert_eq!(self.hooks.load(Ordering::SeqCst), hooks);
                assert_eq!(guest.parked_signal_failure_context(), context);
                assert!(
                    matches!(guest.queue_process_alarm_signal(alarm(guest.pid())).await,
                    ProcessAlarmSignalOutcome::Accepted(receipt) if receipt.coalesced)
                );
            }
            let mut observation = guest
                .observe_parked_signal(site, ParkedObservationLease { nonce: cycle + 1 })
                .await
                .unwrap();
            assert!(guest.signal_observation_lease().is_none());
            if self.mode == 2 {
                assert!(matches!(
                    observation.steps.as_slice(),
                    [SignalObservationStep::Reblocked {
                        domain: PendingDomain::Process,
                        ..
                    }]
                ));
                assert_eq!(observation.stop, SignalObservationStop::NoEligibleSignal);
                let call = Syscall::from_raw(
                    Sysno::rt_sigprocmask,
                    SyscallArgs::new(libc::SIG_UNBLOCK as usize, args.arg2, 0, 8, 0, 0),
                );
                assert_eq!(guest.inject(call).await?, 0);
                observation = guest
                    .observe_parked_signal(site, ParkedObservationLease { nonce: 2 })
                    .await
                    .unwrap();
            }
            match observation.stop {
                SignalObservationStop::NoEligibleSignal => {
                    assert!(self.mode <= 1 || self.mode == 14 || self.mode == 15);
                    assert_eq!(observation.steps.len(), 1);
                    assert!(matches!(
                        observation.steps[0],
                        SignalObservationStep::Ignored { .. }
                            | SignalObservationStep::Suppressed { .. }
                    ));
                }
                SignalObservationStop::Caught(_) => {
                    assert!(matches!(self.mode, 2 | 3 | 5 | 12 | 16..=19));
                    let context = guest
                        .parked_signal_failure_context()
                        .expect("ledger survives caught handoff");
                    assert_eq!(context.site, site);
                    for foreign in foreign_sites(site) {
                        let mut wrong = context;
                        wrong.site = foreign;
                        assert_eq!(
                            guest.cancel_parked_signal(wrong).await,
                            Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                                errno: Errno::EINVAL
                            })
                        );
                        assert_eq!(guest.parked_signal_failure_context(), Some(context));
                    }
                    let mut wrong = context;
                    wrong.ledger_nonce += 1;
                    assert_eq!(
                        guest.cancel_parked_signal(wrong).await,
                        Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                            errno: Errno::EINVAL
                        })
                    );
                    if self.mode == 5 {
                        guest.cancel_parked_signal(context).await.unwrap();
                    }
                    assert_eq!(guest.inject(Fork::new()).await, Err(Errno::ENOSYS));
                    assert_eq!(
                        guest.inject(ExitGroup::new().with_status(99)).await,
                        Err(Errno::ENOSYS)
                    );
                    if self.mode == 3 {
                        for handler in [libc::SIG_IGN, libc::SIG_DFL] {
                            let mut stack = guest.stack().await;
                            let action = stack.push([handler as u64, 0, 0, 0]).as_raw() as usize;
                            let _guard = stack.commit()?;
                            let mutate = Syscall::from_raw(
                                Sysno::rt_sigaction,
                                SyscallArgs::new(libc::SIGALRM as usize, action, 0, 8, 0, 0),
                            );
                            assert_eq!(guest.inject(mutate).await, Err(Errno::ENOSYS));
                            let unrelated = Syscall::from_raw(
                                Sysno::rt_sigaction,
                                SyscallArgs::new(libc::SIGUSR1 as usize, action, 0, 8, 0, 0),
                            );
                            assert_eq!(guest.inject(unrelated).await?, 0);
                            let query = Syscall::from_raw(
                                Sysno::rt_sigaction,
                                SyscallArgs::new(libc::SIGALRM as usize, 0, 0, 8, 0, 0),
                            );
                            assert_eq!(guest.inject(query).await?, 0);
                        }
                    }
                    if self.mode == 16 {
                        let mask = Syscall::from_raw(
                            Sysno::rt_sigprocmask,
                            SyscallArgs::new(libc::SIG_BLOCK as usize, args.arg2, 0, 8, 0, 0),
                        );
                        assert_eq!(guest.inject(mask).await?, 0);
                        let alternate = Syscall::from_raw(
                            Sysno::sigaltstack,
                            SyscallArgs::new(args.arg4, 0, 0, 0, 0, 0),
                        );
                        assert_eq!(guest.inject(alternate).await?, 0);
                    }
                    // A real posthook RPC/injection runs while the original callback is alive.
                    assert_eq!(guest.send_rpc(0x200).await, 0x200);
                    assert_eq!(
                        guest.inject(reverie::syscalls::Getpid::new()).await?,
                        i64::from(guest.pid().as_raw())
                    );
                    seen(Seen::Finish(site));
                    if let Some(count) = completed_read {
                        return Ok(count);
                    }
                    if restart_read {
                        return Err(Errno::ERESTARTSYS.into());
                    }
                    return Err(if self.mode == 12 {
                        Errno::EFAULT
                    } else {
                        Errno::EINTR
                    }
                    .into());
                }
                SignalObservationStop::Fatal(token) => {
                    assert_eq!(self.mode, 4);
                    assert_eq!(token.site, site);
                    for foreign in foreign_sites(site) {
                        let mut wrong = token;
                        wrong.site = foreign;
                        assert_eq!(
                            guest.terminate_from_parked_signal(wrong).await,
                            Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                                errno: Errno::EINVAL
                            })
                        );
                    }
                    let mut wrong = token;
                    wrong.selection_nonce += 1;
                    assert_eq!(
                        guest.terminate_from_parked_signal(wrong).await,
                        Err(reverie::SignalObservationFailure::RejectedBeforeRemoval {
                            errno: Errno::EINVAL
                        })
                    );
                    guest.terminate_from_parked_signal(token).await.unwrap();
                }
            }
        }
        if self.mode == 15 {
            // Fill the production receipt limit with genuine accepted/coalesced
            // publications after one acknowledged removal. No reduced test cap.
            for _ in 1..4096 {
                assert!(matches!(
                    guest.queue_process_alarm_signal(alarm(guest.pid())).await,
                    ProcessAlarmSignalOutcome::Accepted(_)
                ));
            }
            let result = guest.inject(reverie::syscalls::Getpid::new()).await;
            panic!("bookkeeping exhaustion must be terminal, never getpid's result: {result:?}");
        }
        seen(Seen::Finish(site));
        Ok(123)
    }
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Pid,
        _: &G,
        _: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        seen(Seen::Exit(status));
        Ok(())
    }
}

type EffectEvidence<'a> = (
    &'a [SignalDequeue],
    u64,
    &'a [ProcessAlarmSignalOutcome],
    Option<i64>,
);

fn effect_error(error: &Error) -> Option<EffectEvidence<'_>> {
    match error {
        Error::SignalEffects {
            dequeues,
            acknowledged_through,
            publications,
            raw_result,
            ..
        } => Some((dequeues, *acknowledged_through, publications, *raw_result)),
        Error::SharedFailure(error) | Error::WorkerFailure { error, .. } => effect_error(error),
        Error::WithCleanup { primary, cleanup } => {
            effect_error(primary).or_else(|| cleanup.iter().find_map(|error| effect_error(error)))
        }
        _ => None,
    }
}

#[test]
fn parked_signal_actual_callback_frame_and_dequeue_contract() {
    const TEST: &str = "parked_signals::parked_signal_actual_callback_frame_and_dequeue_contract";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    run_parked_modes(0..=14_u8);
}

#[test]
fn parked_signal_caught_action_posthook_refusal() {
    const TEST: &str = "parked_signals::parked_signal_caught_action_posthook_refusal";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    run_parked_modes(std::iter::once(3));
}

fn run_parked_modes(modes: impl IntoIterator<Item = u8>) {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "parked-signal",
        include_str!("../fixtures/parked_signal.c"),
    );
    for mode in modes {
        SEEN.lock().unwrap().clear();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), &mode.to_string()],
                &[],
                &directory.0,
            )
            .unwrap();
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<ParkedTool>(mode, true));
        let seen = SEEN.lock().unwrap().clone();
        if mode == 15 {
            eprintln!(
                "parked-signal capacity result={:?} seen={seen:?}",
                result
                    .as_ref()
                    .map(|(_, code, _, _)| code)
                    .map_err(ToString::to_string)
            );
        } else {
            eprintln!("parked-signal mode={mode} result={result:?} seen={seen:?}");
        }
        let starts = seen
            .iter()
            .filter_map(|s| {
                if let Seen::Start(id) = s {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(starts.len(), 1);
        let dequeues = seen
            .iter()
            .filter_map(|s| {
                if let Seen::Dequeue(d) = s {
                    Some(*d)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            dequeues.len(),
            if mode <= 1 {
                3
            } else if mode == 2 {
                2
            } else {
                1
            }
        );
        for (index, effect) in dequeues.iter().enumerate() {
            assert_eq!(effect.sequence, index as u64 + 1);
            assert_eq!(effect.process, starts[0].process);
        }
        let hooks = seen
            .iter()
            .filter_map(|s| {
                if let Seen::Hook(id) = s {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            hooks.len(),
            if (6..=10).contains(&mode) || mode == 13 {
                0
            } else {
                dequeues.len()
            }
        );
        for id in hooks {
            assert!(dequeues.iter().any(|effect| effect.id() == id));
        }
        if matches!(mode, 5 | 10 | 11 | 13 | 15) {
            let error = result.unwrap_err();
            let (retained, ack, receipts, raw) =
                effect_error(&error).expect("committed effects attached to original failure");
            assert_eq!(retained, dequeues);
            assert_eq!(
                receipts.len(),
                if mode == 15 {
                    4096
                } else {
                    usize::from(mode != 13)
                }
            );
            if mode == 15 {
                assert!(error.primary().to_string().contains("EOVERFLOW"));
            }
            assert_eq!(ack, if mode == 10 || mode == 13 { 0 } else { 1 });
            if mode == 13 {
                assert!(matches!(error.primary(), Error::RunAborted));
            }
            assert_eq!(
                raw,
                if mode == 10 || mode == 13 {
                    Some(-(libc::EFAULT as i64))
                } else {
                    None
                }
            );
        } else {
            let (_, code, stdout, stderr) = result.unwrap();
            assert!(stderr.is_empty());
            if mode == 4 {
                assert_eq!(code, 128 + libc::SIGALRM);
                assert!(stdout.is_empty());
            } else {
                assert_eq!(code, 0, "mode {mode}");
                assert_eq!(stdout, b"parked-signal-checked\n");
            }
            let exits = seen
                .iter()
                .filter_map(|s| {
                    if let Seen::Exit(status) = s {
                        Some(*status)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                exits,
                [if mode == 4 {
                    ExitStatus::Signaled(reverie::Signal::SIGALRM, false)
                } else {
                    ExitStatus::Exited(0)
                }]
            );
        }
        if (17..=19).contains(&mode) {
            let callbacks = seen
                .iter()
                .filter_map(|event| match event {
                    Seen::RestartReadCallback(site, handled) => Some((*site, *handled)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(callbacks.len(), if mode == 18 { 2 } else { 1 });
            assert_eq!(callbacks[0].1, 0);
            let original = callbacks[0]
                .0
                .expect("original read callback has a real site");
            if mode == 18 {
                assert_eq!(callbacks[1].1, 1, "handler precedes restart");
                let restarted = callbacks[1].0.expect("restart has a real site");
                assert_eq!(restarted.process, original.process);
                assert_eq!(restarted.tid, original.tid);
                assert_eq!(restarted.task_generation, original.task_generation);
                assert!(restarted.callback_nonce > original.callback_nonce);
            }
            let reads = seen
                .iter()
                .filter_map(|event| match event {
                    Seen::RestartReadResult(result) => Some(*result),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                reads,
                match mode {
                    17 => vec![Err(Errno::EAGAIN)],
                    18 => vec![Err(Errno::EAGAIN), Ok(1)],
                    19 => vec![Ok(3)],
                    _ => unreachable!(),
                }
            );
            assert_eq!(
                seen.iter()
                    .filter(|event| matches!(event, Seen::Finish(_)))
                    .count(),
                1
            );
        }
        for finish in seen.iter().filter_map(|s| {
            if let Seen::Finish(site) = s {
                Some(site)
            } else {
                None
            }
        }) {
            assert_eq!(finish.process, starts[0].process);
        }
        for effect in dequeues {
            assert_eq!(
                effect.consumer,
                if matches!(mode, 6 | 8 | 10 | 13) {
                    SignalConsumer::SignalFd
                } else if matches!(mode, 7 | 9) {
                    SignalConsumer::SignalTimedWait
                } else {
                    SignalConsumer::ReturnToUser
                }
            );
        }
    }
}

#[derive(Default)]
struct SiblingTool {
    first_notifying: AtomicBool,
    second_pending: AtomicBool,
    first_waker: futures::task::AtomicWaker,
    second_waker: futures::task::AtomicWaker,
    notifications: AtomicU64,
    mode: u8,
}
static SIBLING_DEQUEUES: Mutex<Vec<(Pid, SignalDequeue)>> = Mutex::new(Vec::new());
#[reverie::tool]
impl Tool for SiblingTool {
    type GlobalState = Global;
    type ThreadState = ();
    fn new(_: Pid, mode: &u8) -> Self {
        Self {
            mode: *mode,
            ..Default::default()
        }
    }
    fn may_observe_signal_dequeues(_: &u8) -> bool {
        true
    }
    fn subscriptions(_: &u8) -> Subscription {
        Subscription::all()
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert_eq!(guest.signal_task_identity().unwrap().tid, guest.tid());
        Ok(())
    }
    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        effect: SignalDequeue,
    ) -> Result<(), Errno> {
        assert_eq!(effect.domain, PendingDomain::Thread);
        assert_eq!(effect.consumer, SignalConsumer::SignalTimedWait);
        assert_eq!(
            effect.event.target(),
            SignalTarget::Thread {
                pid: guest.pid(),
                tid: guest.tid()
            },
            "only the removing Guest may report its private signal"
        );
        assert_eq!(
            effect.sequence,
            self.notifications.fetch_add(1, Ordering::SeqCst) + 1
        );
        SIBLING_DEQUEUES.lock().unwrap().push((guest.tid(), effect));
        if effect.sequence == 1 {
            assert_eq!(guest.tid() == guest.pid(), self.mode < 2);
            self.first_notifying.store(true, Ordering::Release);
            self.second_waker.wake();
            if self.mode == 3 {
                // This owner progresses independently; the sibling must wait
                // for the real FIFO wake, without releasing this callback.
                std::thread::sleep(std::time::Duration::from_millis(20));
                return Ok(());
            }
            futures::future::poll_fn(|cx| {
                self.first_waker.register(cx.waker());
                if self.second_pending.load(Ordering::Acquire) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            if self.mode == 2 {
                panic!("deliberate dequeuing worker panic");
            }
            if self.mode == 1 {
                return Err(Errno::EIO);
            }
        } else {
            assert_eq!(effect.sequence, 2);
            assert_eq!(guest.tid() == guest.pid(), self.mode >= 2);
        }
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let (_, args) = syscall.into_parts();
        if syscall.number() != Sysno::getpid || args.arg0 != 0x7369626c {
            guest.tail_inject(syscall).await;
        }
        let first = (guest.tid() == guest.pid()) == (self.mode < 2);
        if !first {
            futures::future::poll_fn(|cx| {
                self.second_waker.register(cx.waker());
                if self.first_notifying.load(Ordering::Acquire) {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            assert_eq!(
                guest.inject(reverie::syscalls::Getpid::new()).await?,
                i64::from(guest.pid().as_raw()),
                "unrelated injection must not flush sibling state"
            );
        }
        let signal = if first { libc::SIGUSR1 } else { libc::SIGUSR2 };
        let mut info = [0; reverie::SIGNAL_INFO_SIZE];
        info[..4].copy_from_slice(&signal.to_ne_bytes());
        info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
        guest
            .defer_signal_delivery(
                SignalEvent::new(
                    signal,
                    info,
                    SignalTarget::Thread {
                        pid: guest.pid(),
                        tid: guest.tid(),
                    },
                )
                .unwrap(),
            )
            .await?;
        let call = Syscall::from_raw(
            Sysno::rt_sigtimedwait,
            SyscallArgs::new(args.arg1, 1, 0, 8, 0, 0),
        );
        let result = if first || self.mode == 3 {
            guest.inject(call).await
        } else {
            let future = guest.inject(call);
            futures::pin_mut!(future);
            futures::future::poll_fn(|cx| {
                let result = std::future::Future::poll(future.as_mut(), cx);
                if result.is_pending() {
                    self.second_pending.store(true, Ordering::Release);
                    self.first_waker.wake();
                }
                result
            })
            .await
        };
        assert_eq!(result, Err(Errno::EFAULT));
        assert!(
            !matches!(self.mode, 1 | 2),
            "failed predecessor cannot resume an injected syscall"
        );
        Ok(123)
    }
}

fn run_sibling_dequeues_mode(mode: u8) {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "sibling-dequeues",
        r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
static sigset_t set;
static void *worker(void *unused) {
    (void)unused;
    return (void *)(syscall(SYS_getpid, 0x7369626c, &set) == 123 ? 0L : 9L);
}
int main(void) {
    sigemptyset(&set); sigaddset(&set, SIGUSR1); sigaddset(&set, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &set, 0)) return 1;
    pthread_t thread; if (pthread_create(&thread, 0, worker, 0)) return 2;
    if (syscall(SYS_getpid, 0x7369626c, &set) != 123) return 3;
    void *result; if (pthread_join(thread, &result) || result) return 4;
    puts("sibling-dequeues-checked"); return 0;
}
"#,
    );
    SIBLING_DEQUEUES.lock().unwrap().clear();
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap()],
            &[],
            &directory.0,
        )
        .unwrap();
    let result =
        futures::executor::block_on(backend.run_static_elf_with_tool::<SiblingTool>(mode, true));
    let seen = SIBLING_DEQUEUES.lock().unwrap().clone();
    eprintln!("sibling-dequeues mode={mode} result={result:?} seen={seen:?}");
    if matches!(mode, 1 | 2) {
        let error = result.unwrap_err();
        if mode == 2 {
            assert!(matches!(error.primary(), Error::GuestWorkerPanic));
        }
        let mut effects = Vec::new();
        collect_sibling_effects(&error, &mut effects);
        effects.sort_by_key(|d| d.sequence);
        effects.dedup();
        assert_eq!(
            effects.len(),
            2,
            "each owner retains its own committed removal on failure"
        );
        assert_eq!(effects[0], seen[0].1);
        assert_eq!(effects[1].sequence, 2);
        assert_eq!(effects[1].event.signal(), libc::SIGUSR2);
        assert_eq!(
            seen.len(),
            1,
            "a failed predecessor must not notify its successor"
        );
    } else {
        let (_, status, stdout, stderr) = result.unwrap();
        assert_eq!(status, 0);
        assert_eq!(stdout, b"sibling-dequeues-checked\n");
        assert!(stderr.is_empty());
        assert_eq!(seen.len(), 2);
        assert_ne!(seen[0].0, seen[1].0);
        assert_eq!(seen[0].1.sequence, 1);
        assert_eq!(seen[1].1.sequence, 2);
        assert_eq!(seen[0].1.process, seen[1].1.process);
    }
}
fn collect_sibling_effects(error: &Error, into: &mut Vec<SignalDequeue>) {
    match error {
        Error::SignalEffects {
            cause, dequeues, ..
        } => {
            into.extend(dequeues);
            collect_sibling_effects(cause, into);
        }
        Error::SharedFailure(error)
        | Error::WorkerFailure { error, .. }
        | Error::Cleanup { error, .. } => collect_sibling_effects(error, into),
        Error::WithCleanup { primary, cleanup } => {
            collect_sibling_effects(primary, into);
            for error in cleanup {
                collect_sibling_effects(error, into);
            }
        }
        _ => {}
    }
}
#[test]
fn parked_signal_two_thread_owned_dequeues() {
    if !leader_self_exec_bounded("parked_signals::parked_signal_two_thread_owned_dequeues") {
        return;
    }
    run_sibling_dequeues_mode(0);
}
#[test]
fn parked_signal_two_thread_failed_predecessor_retains_both_owners() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_two_thread_failed_predecessor_retains_both_owners",
    ) {
        return;
    }
    run_sibling_dequeues_mode(1);
}

#[test]
fn parked_signal_capacity_failure_is_terminal_before_getpid() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_capacity_failure_is_terminal_before_getpid",
    ) {
        return;
    }
    run_parked_modes(std::iter::once(15));
}

#[test]
fn parked_signal_worker_panic_retains_both_dequeue_owners() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_worker_panic_retains_both_dequeue_owners",
    ) {
        return;
    }
    run_sibling_dequeues_mode(2);
}

#[test]
fn parked_signal_independent_delayed_worker_ack_wakes_sibling() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_independent_delayed_worker_ack_wakes_sibling",
    ) {
        return;
    }
    run_sibling_dequeues_mode(3);
}

#[test]
fn parked_signal_caught_posthook_mask_and_altstack_reach_real_frame() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_caught_posthook_mask_and_altstack_reach_real_frame",
    ) {
        return;
    }
    run_parked_modes(std::iter::once(16));
}

#[test]
fn parked_signal_prepared_read_returns_eintr_without_restart() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_prepared_read_returns_eintr_without_restart",
    ) {
        return;
    }
    run_parked_modes(std::iter::once(17));
}

#[test]
fn parked_signal_prepared_read_restarts_only_after_handler() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_prepared_read_restarts_only_after_handler",
    ) {
        return;
    }
    run_parked_modes(std::iter::once(18));
}

#[test]
fn parked_signal_prepared_partial_read_is_not_replayed() {
    if !leader_self_exec_bounded(
        "parked_signals::parked_signal_prepared_partial_read_is_not_replayed",
    ) {
        return;
    }
    run_parked_modes(std::iter::once(19));
}

static ADMISSION_GLOBALS: AtomicU64 = AtomicU64::new(0);
static ADMISSION_STARTS: AtomicU64 = AtomicU64::new(0);
#[derive(Debug, Default)]
struct AdmissionGlobal;
#[reverie::global_tool]
impl GlobalTool for AdmissionGlobal {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn init_global_state(_: &u8) -> Self {
        ADMISSION_GLOBALS.fetch_add(1, Ordering::SeqCst);
        Self
    }
    async fn receive_rpc(&self, _: Pid, _: ()) {}
}
#[derive(Default)]
struct AdmissionTool;
#[reverie::tool]
impl Tool for AdmissionTool {
    type GlobalState = AdmissionGlobal;
    type ThreadState = ();
    fn may_observe_signal_dequeues(mode: &u8) -> bool {
        *mode != 2
    }
    fn thread_ownership(mode: &u8) -> reverie::ThreadOwnership {
        if *mode == 0 {
            reverie::ThreadOwnership::Tool
        } else {
            reverie::ThreadOwnership::Host
        }
    }
    async fn handle_thread_start<G: Guest<Self>>(&self, _: &mut G) -> Result<(), reverie::Error> {
        ADMISSION_STARTS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn parked_signal_admission_resolves_actual_thread_owner_before_global_or_guest() {
    const TEST: &str = "parked_signals::parked_signal_admission_resolves_actual_thread_owner_before_global_or_guest";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "observation-admission",
        r#"
#include <pthread.h>
#include <stdio.h>
static void *worker(void *p) { (void)p; puts("worker"); return 0; }
int main(void) { pthread_t thread; if (pthread_create(&thread, 0, worker, 0)) return 1;
if (pthread_join(thread, 0)) return 2; puts("admitted"); return 0; }
"#,
    );
    use reverie::ThreadOwnership::Host;
    use reverie::ThreadOwnership::Tool;
    for (mode, override_owner, refused, starts) in [
        (1, None, true, 2),
        (0, Some(Host), true, 2),
        (1, Some(Tool), false, 2),
        (2, None, false, 1),
        (0, None, false, 2),
    ] {
        ADMISSION_GLOBALS.store(0, Ordering::SeqCst);
        ADMISSION_STARTS.store(0, Ordering::SeqCst);
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &directory.0,
            )
            .unwrap();
        if let Some(owner) = override_owner {
            backend.set_thread_ownership(owner);
        }
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<AdmissionTool>(mode, true),
        );
        let (_, status, stdout, stderr) = if refused {
            assert!(
                matches!(result, Err(Error::SignalObservationRequiresToolThreads)),
                "incompatible effective ownership must fail during admission"
            );
            assert_eq!(ADMISSION_GLOBALS.load(Ordering::SeqCst), 0);
            assert_eq!(ADMISSION_STARTS.load(Ordering::SeqCst), 0);
            // Refusal did not consume the installed image. Explicitly choosing
            // Tool ownership admits that same image; the backend never forces it.
            backend.set_thread_ownership(Tool);
            futures::executor::block_on(
                backend.run_static_elf_with_tool::<AdmissionTool>(mode, true),
            )
            .unwrap()
        } else {
            result.unwrap()
        };
        assert_eq!(status, 0);
        assert_eq!(stdout, b"worker\nadmitted\n");
        assert!(stderr.is_empty());
        assert_eq!(ADMISSION_GLOBALS.load(Ordering::SeqCst), 1);
        assert_eq!(ADMISSION_STARTS.load(Ordering::SeqCst), starts);
    }
}
