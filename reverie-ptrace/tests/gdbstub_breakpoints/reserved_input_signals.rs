/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real GDB choices while a separate process shares the signal target's MM.
//! The survivor owns a blocked native read and attempts a real staged getpid
//! after EOF. The debugger never writes memory or edits the tested signal mask.

use std::sync::Arc;
use std::sync::Mutex;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tid;
use reverie::reserved_input::*;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::SyscallArgs;

use super::*;

// The same cases are interpreted by the C guest. Every row has an exact answer.
const SAME: u8 = 0;
const SUPPRESS: u8 = 1;
const FATAL_REPLACEMENT: u8 = 2;
const NONFATAL_REPLACEMENT: u8 = 3;
const SUPPRESS_EXISTING: u8 = 4;
const STEP_SAME: u8 = 5;
const STEP_REPLACEMENT: u8 = 6;
const TOOL_REPLACEMENT: u8 = 7;

#[derive(Default)]
struct SignalInputs {
    control: Option<ReservedInputControl>,
    registrations: Mutex<Vec<InputTaskRegistration>>,
    events: Mutex<Vec<u8>>,
}

#[reverie::global_tool]
impl GlobalTool for SignalInputs {
    type Config = u8;
    // Test-only rendezvous and observations; no production callback/RPC changes.
    type Request = u8;
    type Response = bool;

    async fn receive_rpc(&self, _: Pid, event: u8) -> bool {
        let mut events = self.events.lock().unwrap();
        if event != 0 {
            events.push(event);
        }
        events.contains(&1)
    }

    fn install_reserved_input_control(
        &mut self,
        control: ReservedInputControl,
    ) -> Result<(), Error> {
        self.control = Some(control);
        Ok(())
    }

    fn on_reserved_input_task(&self, task: InputTaskRegistration) -> Result<(), Error> {
        self.registrations.lock().unwrap().push(task);
        Ok(())
    }

    fn admit_reserved_input_initial_state(
        &self,
        _: &InputNativeFacts,
    ) -> Result<InputAdmission, Error> {
        // Only this controlled transport fixture: one staged issuer, after its
        // parent's pipe closes. This is not general host-environment admission.
        Ok(InputAdmission::Qualified)
    }

    fn on_reserved_input_setup(&self, receipt: InputSetupReceipt) -> Result<(), Error> {
        assert!(
            matches!(receipt.outcome, InputSetupOutcome::Qualified(_)),
            "{receipt:?}"
        );
        Ok(())
    }
}

#[derive(Default)]
struct SignalInputTool;

fn physical_description(call: Syscall) -> PhysicalInjectionDescription {
    let (number, args) = call.into_parts();
    PhysicalInjectionDescription {
        number: number as u64,
        args: [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ],
        input: InputCallInput::Registers,
        expected_sharing: InputExpectedSharing::default(),
        transient: vec![],
        prospective: vec![],
        unknown_lifecycle: None,
    }
}

fn expected_cause(case: u8) -> Option<&'static str> {
    match case {
        FATAL_REPLACEMENT | NONFATAL_REPLACEMENT | STEP_REPLACEMENT => {
            Some("unclassified-signal-forward")
        }
        SUPPRESS_EXISTING => Some("fixture-prior-signal-exposure"),
        SAME | SUPPRESS | STEP_SAME | TOOL_REPLACEMENT => None,
        _ => panic!("unknown signal case {case}"),
    }
}

#[reverie::tool]
impl Tool for SignalInputTool {
    type GlobalState = SignalInputs;
    type ThreadState = bool;

    fn enforces_serialized_execution(_: &u8) -> bool {
        // The test's gate permits only the surviving child to stage, after the
        // parent has either closed the pipe or died; no concurrent staged user.
        true
    }

    fn reserved_input_requirement(_: &u8) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }

    fn subscriptions(_: &u8) -> Subscription {
        [Sysno::clone, Sysno::write].into_iter().collect()
    }

    async fn handle_signal_event<G: TracedGuest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        if signal == Signal::SIGUSR1 {
            assert!(guest.send_rpc(0).await, "the survivor owns its read lease");
            guest.send_rpc(4).await;
            if *guest.config() == SUPPRESS_EXISTING {
                guest
                    .reserved_input_control()
                    .unwrap()
                    .add_exposure(InputExposure {
                        target: InputTarget::Unknown,
                        cause: "fixture-prior-signal-exposure".into(),
                    })
                    .unwrap();
            }
            if *guest.config() == TOOL_REPLACEMENT {
                // A completed Tool verdict for SIGUSR2, which GDB keeps. This
                // must not be confused with a subsequent backend replacement.
                return Ok(Some(Signal::SIGUSR2));
            }
        }
        Ok(Some(signal))
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Tid,
        global: &G,
        survivor: bool,
        status: ExitStatus,
    ) -> Result<(), Error> {
        if survivor {
            assert_eq!(status, ExitStatus::Exited(0), "the actual survivor exit");
            global.send_rpc(5).await;
        }
        Ok(())
    }

    async fn handle_syscall_event<G: TracedGuest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let (number, args) = call.into_parts();
        let control = guest.reserved_input_control().unwrap();
        let owner = guest.reserved_input_task().unwrap();
        if number == Sysno::clone {
            assert_eq!(args.arg0, (libc::CLONE_VM | libc::SIGCHLD) as usize);
            control.grant(owner, InputGrantKind::Ordinary).unwrap();
            let mut description = physical_description(call);
            description.expected_sharing = InputExpectedSharing {
                memory: Some(true),
                files: Some(false),
                may_create: true,
                thread_group: Some(false),
            };
            description.unknown_lifecycle = Some(InputExposure {
                target: InputTarget::Unknown,
                cause: "fixture-unobserved-birth".into(),
            });
            let receipt = control
                .prepare_observed_injection(owner, 1, description)
                .unwrap();
            return Ok(guest
                .inject_observed(call, receipt)
                .await
                .map_err(anyhow::Error::new)??);
        }
        if number != Sysno::write {
            return Ok(guest.inject(call).await?);
        }
        match args.arg0 as i32 {
            -912 => Ok(i64::from(guest.send_rpc(0).await)),
            -911 => {
                *guest.thread_state_mut() = true;
                // The real blocking pipe read stays owned across the debugger
                // stop and, in the fatal case, the other process's death.
                let grant = control.grant(owner, InputGrantKind::Ordinary).unwrap();
                let lease = control
                    .acquire_access(
                        owner,
                        InputAccess {
                            target: InputTarget::Region(
                                control.registration(owner).unwrap().region,
                            ),
                            span: InputSpan::range(args.arg2 as u64, 1).unwrap(),
                            direction: InputAccessDirection::Write,
                            lifetime: InputAccessLifetime::Transient,
                            cause: "fixture-pipe-copyout".into(),
                        },
                    )
                    .unwrap();
                guest.send_rpc(1).await;
                let read = Syscall::from_raw(
                    Sysno::read,
                    SyscallArgs::new(args.arg1, args.arg2, 1, 0, 0, 0),
                );
                assert_eq!(guest.inject(read).await?, 0, "real EOF, not cancellation");
                control.complete_access_after_return(&lease, owner).unwrap();
                control.readmit_access(lease, owner, grant).unwrap();
                guest.send_rpc(2).await;
                Ok(0)
            }
            -910 => {
                let layout = control.layout(owner).unwrap();
                let address = Addr::<u8>::from_raw(layout.base as usize).unwrap();
                let mut before = vec![0; layout.page_bytes];
                guest.memory().read_exact(address, &mut before)?;
                control.grant(owner, InputGrantKind::Ordinary).unwrap();
                let scope = control.begin_operation(owner, 2).unwrap();
                let bytes = vec![0x6c; layout.page_bytes];
                let image = ReservedInputImage::new(
                    layout,
                    &[InputWrite {
                        offset: 0,
                        bytes: &bytes,
                    }],
                )
                .unwrap();
                let submitted =
                    Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                let mut description = physical_description(submitted);
                description.input = InputCallInput::Immutable {
                    address: layout.base,
                    bytes: Arc::from(image.bytes()),
                };
                let receipt = control.prepare_injection(&scope, description).unwrap();
                let id = receipt.id();
                let result = guest
                    .inject_staged_input(submitted, &scope, image.clone(), receipt)
                    .await;
                let observation = control.injection_observation(id).unwrap();
                match expected_cause(*guest.config()) {
                    Some(cause) => {
                        let Err(InputInjectionError::Unavailable(error)) = result else {
                            panic!("expected exact {cause} before page fill, got {result:?}");
                        };
                        assert_eq!(error.reason(), cause);
                        assert_eq!(observation.state, PhysicalInjectionState::ProvedNoChild);
                        assert_eq!(observation.verified_image, None);
                        let mut after = vec![0; layout.page_bytes];
                        guest.memory().read_exact(address, &mut after)?;
                        assert_eq!(after, before, "refused publication changed the page");
                    }
                    None => {
                        assert_eq!(result.unwrap().unwrap(), i64::from(guest.pid().as_raw()));
                        assert_eq!(observation.verified_image.as_ref(), Some(&image));
                    }
                }
                control.finish_operation(scope).unwrap();
                guest.send_rpc(3).await;
                Ok(0)
            }
            _ => Ok(guest.inject(call).await?),
        }
    }
}

#[tokio::test]
async fn debugger_signal_choices_retain_only_unclassified_forwarding_for_a_shared_mm_survivor() {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        build_guest(
            "gdbstub_reserved_input_signals",
            &["-Wall", "-Wextra", "-Werror"],
            &[],
        )
        .0
    });
    for case in [
        SAME,
        SUPPRESS,
        FATAL_REPLACEMENT,
        NONFATAL_REPLACEMENT,
        SUPPRESS_EXISTING,
        STEP_SAME,
        STEP_REPLACEMENT,
        TOOL_REPLACEMENT,
    ] {
        let socket = std::env::temp_dir().join(format!(
            "reverie-gdbstub-input-signal-{case}-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket);
        let mut command = Command::new(&*GUEST);
        command.arg(case.to_string());
        let tracer = async {
            TracerBuilder::<SignalInputTool>::new(command)
                .config(case)
                .sequentialized_guest()
                .gdbserver(socket.clone())
                .spawn()
                .await
                .expect("spawn the signal guest")
                .wait()
                .await
                .expect("wait for both real native processes")
        };
        let gdb = async {
            let mut remote = Remote::connect(&socket).await;
            // Keep the shared-MM child detached from GDB, but fully traced by
            // Reverie. SIGCHLD passes unchanged, without a new debugger choice.
            remote.supported(NO_EVENTS).await;
            let stop = remote.resume().await;
            let reported = if case == TOOL_REPLACEMENT {
                "T1f"
            } else {
                "T1e"
            };
            assert!(stop.starts_with(reported), "case {case}: {stop:?}");
            let thread = stop_thread(&stop).to_owned();
            let action = match case {
                SAME => "C1e",
                SUPPRESS | SUPPRESS_EXISTING => "c",
                FATAL_REPLACEMENT => "C0f",
                NONFATAL_REPLACEMENT | TOOL_REPLACEMENT => "C1f",
                STEP_SAME => "S1e",
                STEP_REPLACEMENT => "S1f",
                _ => unreachable!(),
            };
            let mut end = remote.request(&format!("vCont;{action}:{thread}")).await;
            if matches!(case, STEP_SAME | STEP_REPLACEMENT) {
                assert!(end.starts_with("T05"), "the real step trap: {end:?}");
                end = remote.resume().await;
            }
            if case == FATAL_REPLACEMENT {
                assert!(
                    end.starts_with("X0f"),
                    "the actual SIGTERM delivery: {end:?}"
                );
            } else {
                assert_exited_zero(&end, "signal/mask/siginfo and survivor controls");
            }
        };
        let ((status, evidence), ()) =
            tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(tracer, gdb) })
                .await
                .expect("the debugger and shared-MM survivor finish");
        let _ = std::fs::remove_file(&socket);
        if case == FATAL_REPLACEMENT {
            assert!(
                matches!(status, ExitStatus::Signaled(Signal::SIGTERM, _)),
                "{status:?}"
            );
        } else {
            assert_eq!(status, ExitStatus::Exited(0));
        }
        assert_eq!(evidence.events.into_inner().unwrap(), [1, 4, 2, 3, 5]);
        let registrations = evidence.registrations.into_inner().unwrap();
        let child = registrations
            .iter()
            .find(|entry| entry.parent.is_some())
            .unwrap();
        let parent = registrations
            .iter()
            .find(|entry| Some(entry.task) == child.parent)
            .unwrap();
        assert_eq!(parent.region, child.region, "actual shared MM");
        assert_ne!(
            parent.group, child.group,
            "the child survives a fatal parent signal"
        );
        assert_ne!(parent.native_pid, child.native_pid);
    }
}
