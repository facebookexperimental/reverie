use reverie::ChildExitSignalDisposition;
use reverie::ChildExitSignalErrorKind;
use reverie::ChildExitSignalOutcome;

use super::*;

#[derive(Clone, Debug)]
enum Observation {
    Start(i32),
    ContextRefusal(i32, &'static str),
    Published(i32, SignalEvent, ChildExitSignalOutcome),
    Signal(i32, SignalEvent),
    ThreadExit(i32, ExitStatus),
    ProcessExit(i32, ExitStatus),
}
static OBSERVATIONS: Mutex<Vec<Observation>> = Mutex::new(Vec::new());

fn observe(value: Observation) {
    OBSERVATIONS.lock().unwrap().push(value);
}

fn event(pid: Pid, child: i32, uid: u32) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[0..4].copy_from_slice(&libc::SIGCHLD.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::CLD_EXITED.to_ne_bytes());
    info[16..20].copy_from_slice(&child.to_ne_bytes());
    info[20..24].copy_from_slice(&uid.to_ne_bytes());
    info[24..28].copy_from_slice(&37_i32.to_ne_bytes());
    info[32..40].copy_from_slice(&11_i64.to_ne_bytes());
    info[40..48].copy_from_slice(&13_i64.to_ne_bytes());
    info[127] = 0xa5;
    SignalEvent::new(libc::SIGCHLD, info, SignalTarget::Process { pid }).unwrap()
}

#[derive(Default)]
struct ChildExitLog;
#[reverie::global_tool]
impl GlobalTool for ChildExitLog {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn receive_rpc(&self, _: Pid, _: ()) {}
}

#[derive(Default)]
struct ChildExitTool {
    mode: u8,
    selected: Mutex<Option<SignalEvent>>,
}
impl ChildExitTool {
    async fn refused_context<G: Guest<Self>>(&self, guest: &mut G, context: &'static str) {
        let event = event(guest.pid(), 41, 0);
        assert_eq!(
            guest.queue_child_exit_signal(event).await,
            ChildExitSignalOutcome::RejectedBeforeCommit {
                kind: ChildExitSignalErrorKind::Unsupported,
                errno: Errno::ENOSYS,
            },
            "{context}"
        );
        observe(Observation::ContextRefusal(guest.tid().as_raw(), context));
    }

    async fn publish<G: Guest<Self>>(&self, guest: &mut G) {
        let selected = self
            .selected
            .lock()
            .unwrap()
            .expect("selected actual child");
        self.publish_event(guest, selected, false).await;
    }

    async fn publish_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        selected: SignalEvent,
        expected_coalesced: bool,
    ) {
        let outcome = guest.queue_child_exit_signal(selected).await;
        observe(Observation::Published(
            guest.tid().as_raw(),
            selected,
            outcome,
        ));
        let disposition = match self.mode {
            3 | 4 => ChildExitSignalDisposition::Ignored,
            2 | 7 | 13 => ChildExitSignalDisposition::PendingBlocked,
            _ => ChildExitSignalDisposition::PendingEligible,
        };
        let ChildExitSignalOutcome::Accepted {
            disposition: actual,
            coalesced,
            ..
        } = outcome
        else {
            panic!("live child-exit publication failed: {outcome:?}");
        };
        assert_eq!(actual, disposition);
        assert_eq!(coalesced, expected_coalesced);
    }
}

#[reverie::tool]
impl Tool for ChildExitTool {
    type GlobalState = ChildExitLog;
    type ThreadState = bool;

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
        assert!(!guest.thread_state());
        *guest.thread_state_mut() = true;
        observe(Observation::Start(guest.tid().as_raw()));
        self.refused_context(guest, "thread start").await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        self.refused_context(guest, "post exec").await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert!(*guest.thread_state());
        if matches!(syscall, Syscall::Execve(_)) {
            self.refused_context(guest, "initial exec").await;
        }
        let (_, args) = syscall.into_parts();
        if syscall.number() == Sysno::getpid && args.arg0 == 0x63686c64 {
            assert_eq!(args.arg1 as u8, self.mode);
            let child = args.arg2 as i32;
            let observations = OBSERVATIONS.lock().unwrap().clone();
            assert!(
                observations.iter().any(|value| matches!(
                    value,
                    Observation::ThreadExit(tid, ExitStatus::Exited(37)) if *tid == child
                )),
                "actual child's consuming exit must precede this waited-for publication"
            );
            *self.selected.lock().unwrap() = Some(event(guest.pid(), child, args.arg3 as u32));
            if self.mode != 10 && self.mode != 11 {
                self.publish(guest).await;
            }
            if self.mode == 13 {
                let second = args.arg4 as i32;
                assert!(
                    observations.iter().any(|value| matches!(value,
                        Observation::ThreadExit(tid, ExitStatus::Exited(43)) if *tid == second
                    )),
                    "second child's exact status must precede publication"
                );
                let mut info = event(guest.pid(), second, args.arg3 as u32).siginfo();
                info[24..28].copy_from_slice(&43_i32.to_ne_bytes());
                let event = SignalEvent::new(
                    libc::SIGCHLD,
                    info,
                    SignalTarget::Process { pid: guest.pid() },
                )?;
                self.publish_event(guest, event, true).await;
            }
            return Ok(i64::from(guest.pid().as_raw()));
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        observe(Observation::Signal(guest.tid().as_raw(), signal));
        if signal.signal() == libc::SIGUSR1 && self.mode == 10
            || signal.signal() == libc::SIGSEGV && self.mode == 11
        {
            self.publish(guest).await;
            return Ok(Some(signal));
        }
        assert_eq!(signal.signal(), libc::SIGCHLD);
        assert_eq!(signal, self.selected.lock().unwrap().unwrap());
        if self.mode == 8 {
            return Ok(None);
        }
        if self.mode == 9 || self.mode == 12 {
            let mut info = signal.siginfo();
            let status: i32 = if self.mode == 9 { 43 } else { 256 };
            info[24..28].copy_from_slice(&status.to_ne_bytes());
            return Ok(Some(SignalEvent::new(
                libc::SIGCHLD,
                info,
                signal.target(),
            )?));
        }
        Ok(Some(signal))
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _: &G,
        state: bool,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert!(state);
        observe(Observation::ThreadExit(tid.as_raw(), status));
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        observe(Observation::ProcessExit(pid.as_raw(), status));
        Ok(())
    }
}

fn artifact(name: &str, bytes: &[u8]) {
    if let Some(directory) = std::env::var_os("REVERIE_CHILD_EXIT_ARTIFACTS") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(PathBuf::from(directory).join(name), bytes).unwrap();
    }
}

#[test]
fn child_exit_signal_native_and_tool_receiver_contract() {
    const TEST: &str = "child_exit_signals::child_exit_signal_native_and_tool_receiver_contract";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "child-exit-signals",
        include_str!("../fixtures/child_exit_signals.c"),
    );
    artifact("guest", &std::fs::read(&executable).unwrap());
    artifact(
        "guest.c",
        include_bytes!("../fixtures/child_exit_signals.c"),
    );
    artifact(
        "compiler.txt",
        b"/usr/bin/gcc -O2 -pthread child-exit-signals.c -o child-exit-signals\n",
    );
    for mode in 0..=13_u8 {
        let argument = mode.to_string();
        let started = std::time::Instant::now();
        let native = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "7s"])
            .arg(&executable)
            .args([argument.as_str(), "0"])
            .output()
            .unwrap();
        artifact(&format!("native-{mode}.stdout"), &native.stdout);
        artifact(&format!("native-{mode}.stderr"), &native.stderr);
        artifact(
            &format!("native-{mode}.result"),
            format!(
                "status={:?}\nseconds={}\n",
                native.status.code(),
                started.elapsed().as_secs_f64()
            )
            .as_bytes(),
        );
        assert!(native.status.success(), "mode={mode} native={native:?}");
        assert_eq!(native.stdout, b"child-exit-receiver-checked\n");
        assert!(native.stderr.is_empty());

        OBSERVATIONS.lock().unwrap().clear();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), &argument, "1"],
                &[],
                &directory.0,
            )
            .unwrap();
        let started = std::time::Instant::now();
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<ChildExitTool>(mode, true),
        );
        let observations = OBSERVATIONS.lock().unwrap().clone();
        artifact(
            &format!("tool-{mode}.events"),
            format!("{observations:#?}\n").as_bytes(),
        );
        artifact(
            &format!("tool-{mode}.result"),
            format!(
                "seconds={}\nerror={:?}\n",
                started.elapsed().as_secs_f64(),
                result.as_ref().err()
            )
            .as_bytes(),
        );
        eprintln!("child-exit mode={mode} observations={observations:?}");
        if mode == 12 {
            let error = result
                .err()
                .expect("malformed Tool return must fail")
                .to_string();
            assert!(
                error.contains("EINVAL"),
                "original validator error: {error}"
            );
        } else {
            let (_, code, stdout, stderr) = result.unwrap();
            artifact(&format!("tool-{mode}.stdout"), &stdout);
            artifact(&format!("tool-{mode}.stderr"), &stderr);
            assert_eq!(code, 0, "mode={mode} stdout={stdout:?} stderr={stderr:?}");
            assert_eq!(stdout, b"child-exit-receiver-checked\n");
            assert!(stderr.is_empty(), "mode={mode} stderr={stderr:?}");
        }
        let starts = observations
            .iter()
            .filter_map(|value| {
                if let Observation::Start(tid) = value {
                    Some(*tid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            starts.len(),
            if mode == 13 { 3 } else { 2 },
            "root and actual children"
        );
        assert_ne!(starts[0], starts[1]);
        for (index, tid) in starts.iter().enumerate() {
            if mode == 12 && index == 0 {
                continue;
            }
            let expected = ExitStatus::Exited(match index {
                0 => 0,
                1 => 37,
                2 => 43,
                _ => unreachable!(),
            });
            assert_eq!(observations.iter().filter(|value| matches!(value,
                Observation::ThreadExit(found, status) if found == tid && *status == expected
            )).count(), 1, "exact consuming thread hook");
            assert_eq!(observations.iter().filter(|value| matches!(value,
                Observation::ProcessExit(found, status) if found == tid && *status == expected
            )).count(), 1, "exact consuming process hook");
        }
        let published = observations
            .iter()
            .filter_map(|value| match value {
                Observation::Published(tid, event, outcome) => Some((*tid, *event, *outcome)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(published.len(), if mode == 13 { 2 } else { 1 });
        assert_eq!(published[0].0, starts[0]);
        if mode == 13 {
            assert_eq!(published[1].0, starts[0]);
            assert_ne!(published[0].1, published[1].1);
        }
        let signals = observations
            .iter()
            .filter_map(|value| match value {
                Observation::Signal(tid, event) if event.signal() == libc::SIGCHLD => {
                    Some((*tid, *event))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            signals.len(),
            if matches!(mode, 2..=4 | 13) { 0 } else { 1 }
        );
        for (tid, event) in signals {
            assert_eq!(tid, starts[0]);
            assert_eq!(event, published[0].1);
        }
        let refusals = observations
            .iter()
            .filter_map(|value| match value {
                Observation::ContextRefusal(tid, context) => Some((*tid, *context)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let mut expected_refusals = vec![
            (starts[0], "thread start"),
            (starts[0], "initial exec"),
            (starts[0], "post exec"),
            (starts[1], "thread start"),
        ];
        if mode == 13 {
            expected_refusals.push((starts[2], "thread start"));
        }
        assert_eq!(refusals, expected_refusals);
        if mode == 12 {
            assert!(!observations.iter().any(|value| matches!(value,
                Observation::ThreadExit(tid, ExitStatus::Exited(0)) | Observation::ProcessExit(tid, ExitStatus::Exited(0)) if *tid == starts[0]
            )), "malformed Tool return cannot become guest success");
        }
    }
}
