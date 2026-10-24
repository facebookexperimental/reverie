// Real KvmGuest -> StaticElfSyscallExecutor -> shared pending -> Tool/frame path.
// This fixture has no scheduler timer, periodic rearm, or parked-wait bridge.
use reverie::ProcessAlarmSignalDisposition;
use reverie::ProcessAlarmSignalErrorKind;
use reverie::ProcessAlarmSignalOutcome;
use reverie::ProcessAlarmSignalReceipt;

use super::*;

#[derive(Clone, Debug)]
enum Observation {
    Refused(&'static str),
    Published(ProcessAlarmSignalOutcome),
    ForkReaped(i64),
    Signal(SignalEvent),
    ThreadExit(ExitStatus),
    ProcessExit(ExitStatus),
}
static OBSERVATIONS: Mutex<Vec<Observation>> = Mutex::new(Vec::new());
fn observe(value: Observation) {
    OBSERVATIONS.lock().unwrap().push(value);
}
fn event(pid: Pid) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    SignalEvent::new(libc::SIGALRM, info, SignalTarget::Process { pid }).unwrap()
}
#[derive(Default)]
struct AlarmLog;
#[reverie::global_tool]
impl GlobalTool for AlarmLog {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn receive_rpc(&self, _: Pid, _: ()) {}
}
#[derive(Default)]
struct AlarmTool {
    mode: u8,
    observations: AtomicU64,
}
impl AlarmTool {
    async fn refused<G: Guest<Self>>(&self, guest: &mut G, context: &'static str) {
        let alarm = event(guest.pid());
        assert_eq!(
            guest.queue_process_alarm_signal(alarm).await,
            ProcessAlarmSignalOutcome::RejectedBeforeCommit {
                kind: ProcessAlarmSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            },
            "{context}"
        );
        observe(Observation::Refused(context));
    }
}
#[reverie::tool]
impl Tool for AlarmTool {
    type GlobalState = AlarmLog;
    type ThreadState = ();
    fn new(_: Pid, mode: &u8) -> Self {
        Self {
            mode: *mode,
            ..Self::default()
        }
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        self.refused(guest, "thread start").await;
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        self.refused(guest, "post exec").await;
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if matches!(syscall, Syscall::Execve(_)) {
            self.refused(guest, "initial exec").await;
        }
        let (_, args) = syscall.into_parts();
        if syscall.number() == Sysno::getpid && args.arg0 == 0x616c726d {
            assert_eq!(args.arg1 as u8, self.mode);
            if self.mode == 9 {
                // A real returning process action consumes this callback's
                // transport even though its SyscallBoundary context remains.
                let child = guest.inject(Fork::new()).await?;
                assert!(child > 0);
                self.refused(guest, "returning fork").await;
                assert_eq!(self.observations.load(Ordering::SeqCst), 0);
                let wait = Syscall::from_raw(
                    Sysno::wait4,
                    SyscallArgs::new(child as usize, 0, 0, 0, 0, 0),
                );
                assert_eq!(guest.inject(wait).await?, child);
                observe(Observation::ForkReaped(child));
                return Ok(i64::from(guest.pid().as_raw()));
            }
            let alarm = event(guest.pid());
            let registers = guest.regs().await;
            for coalesced in [false, true] {
                let outcome = guest.queue_process_alarm_signal(alarm).await;
                observe(Observation::Published(outcome));
                let receipt = ProcessAlarmSignalReceipt {
                    blocked: matches!(self.mode, 1 | 3 | 4 | 8),
                    disposition: match self.mode {
                        2 | 3 => ProcessAlarmSignalDisposition::Ignored,
                        7 => ProcessAlarmSignalDisposition::DefaultFatal,
                        _ => ProcessAlarmSignalDisposition::Caught,
                    },
                    pending_generation: u64::from(matches!(self.mode, 2 | 3)),
                    coalesced,
                };
                assert_eq!(outcome, ProcessAlarmSignalOutcome::Accepted(receipt));
                assert_eq!(
                    self.observations.load(Ordering::SeqCst),
                    0,
                    "publication must not invoke the Tool hook"
                );
            }
            let after = guest.regs().await;
            assert_eq!(after.rip, registers.rip);
            assert_eq!(after.rsp, registers.rsp);
            assert_eq!(after.rax, registers.rax);
            return Ok(i64::from(guest.pid().as_raw()));
        }
        guest.tail_inject(syscall).await
    }
    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        alarm: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(alarm, event(guest.pid()));
        observe(Observation::Signal(alarm));
        let ordinal = self.observations.fetch_add(1, Ordering::SeqCst);
        if self.mode == 6 {
            return Ok(None);
        }
        if self.mode == 5 && ordinal == 0 {
            let mut stack = guest.stack().await;
            let mask = stack.push(1_u64 << (libc::SIGALRM - 1)).as_raw() as u64;
            let _guard = stack.commit()?;
            let block = reverie_kvm::SyscallRequest::new(
                libc::SYS_rt_sigprocmask as u64,
                [libc::SIG_BLOCK as u64, mask, 0, 8, 0, 0],
            )
            .into_syscall()
            .unwrap();
            assert_eq!(guest.inject(block).await?, 0);
        }
        Ok(Some(alarm))
    }
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Pid,
        _: &G,
        _: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        observe(Observation::ThreadExit(status));
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        observe(Observation::ProcessExit(status));
        Ok(())
    }
}

#[test]
fn process_alarm_signal_tool_boundary_contract() {
    const TEST: &str = "process_alarm_signals::process_alarm_signal_tool_boundary_contract";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "process-alarm-signal",
        include_str!("../fixtures/process_alarm_signal.c"),
    );
    for mode in 0..=9_u8 {
        OBSERVATIONS.lock().unwrap().clear();
        let argument = mode.to_string();
        let program = executable.to_str().unwrap();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[program, &argument],
                &[],
                &directory.0,
            )
            .unwrap();
        let (_, code, stdout, stderr) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<AlarmTool>(mode, true))
                .unwrap();
        let observations = OBSERVATIONS.lock().unwrap().clone();
        eprintln!("process-alarm mode={mode} code={code} observations={observations:?}");
        assert!(stderr.is_empty(), "mode={mode} stderr={stderr:?}");
        if mode == 7 {
            assert_eq!(code, 128 + libc::SIGALRM);
            assert!(stdout.is_empty());
        } else {
            assert_eq!(code, 0, "mode={mode} stdout={stdout:?}");
            assert_eq!(stdout, b"process-alarm-boundary-checked\n");
        }
        let expected_status = if mode == 7 {
            ExitStatus::Signaled(reverie::Signal::SIGALRM, false)
        } else {
            ExitStatus::Exited(0)
        };
        let thread_exits: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::ThreadExit(status) => Some(*status),
                _ => None,
            })
            .collect();
        let process_exits: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::ProcessExit(status) => Some(*status),
                _ => None,
            })
            .collect();
        if mode == 9 {
            assert_eq!(thread_exits, [expected_status, expected_status]);
            assert_eq!(process_exits, [expected_status, expected_status]);
        } else {
            assert_eq!(thread_exits, [expected_status]);
            assert_eq!(process_exits, [expected_status]);
        }
        let refusals: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Refused(context) => Some(*context),
                _ => None,
            })
            .collect();
        if mode == 9 {
            let mut refusals = refusals;
            refusals.sort_unstable();
            assert_eq!(
                refusals,
                [
                    "initial exec",
                    "post exec",
                    "returning fork",
                    "thread start",
                    "thread start"
                ]
            );
        } else {
            assert_eq!(refusals, ["thread start", "initial exec", "post exec"]);
        }
        let children: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::ForkReaped(child) => Some(*child),
                _ => None,
            })
            .collect();
        if mode == 9 {
            assert_eq!(children.len(), 1);
            assert!(children[0] > 1);
        } else {
            assert!(children.is_empty());
        }
        let published: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Published(outcome) => Some(*outcome),
                _ => None,
            })
            .collect();
        assert_eq!(published.len(), if mode == 9 { 0 } else { 2 });
        let signals: Vec<_> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Signal(event) => Some(*event),
                _ => None,
            })
            .collect();
        assert_eq!(
            signals.len(),
            match mode {
                4 | 8 | 9 => 0,
                5 => 2,
                _ => 1,
            }
        );
        for alarm in signals {
            assert_eq!(alarm, event(Pid::from_raw(1)));
        }
    }
}
