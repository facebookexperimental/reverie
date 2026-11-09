/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Public RSP choices without a preceding Tool signal verdict. Distinct native
//! processes share an MM; the survivor stages only after the parent's pipe EOF.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tid;
use reverie::reserved_input::*;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::SyscallArgs;
use tokio::sync::Semaphore;

use super::*;

struct StagedEvidence {
    result: Result<Result<i64, Errno>, InputInjectionError>,
    observation: PhysicalInjectionObservation,
    before: Vec<u8>,
    after: Option<Vec<u8>>,
    image: ReservedInputImage,
    pid: Pid,
}

struct Evidence {
    registrations: Mutex<Vec<InputTaskRegistration>>,
    staged: Mutex<Vec<StagedEvidence>>,
    events: Mutex<Vec<u8>>,
    parent_ready: Semaphore,
    parked_ready: Semaphore,
    release: Semaphore,
    parent_may_finish: AtomicBool,
    writer_ready: Semaphore,
    fatal_seen: Semaphore,
    writer: Mutex<Option<PhysicalInjectionId>>,
    failures: Mutex<Vec<(String, PhysicalInjectionObservation, usize, usize)>>,
    parent_calls: AtomicUsize,
    parked_polls: AtomicUsize,
}

impl Default for Evidence {
    fn default() -> Self {
        Self {
            registrations: Mutex::new(Vec::new()),
            staged: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            parent_ready: Semaphore::new(0),
            parked_ready: Semaphore::new(0),
            release: Semaphore::new(0),
            parent_may_finish: AtomicBool::new(false),
            writer_ready: Semaphore::new(0),
            fatal_seen: Semaphore::new(0),
            writer: Mutex::new(None),
            failures: Mutex::new(Vec::new()),
            parent_calls: AtomicUsize::new(0),
            parked_polls: AtomicUsize::new(0),
        }
    }
}

static CURRENT: Mutex<Option<Arc<Evidence>>> = Mutex::new(None);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn evidence() -> Arc<Evidence> {
    CURRENT.lock().unwrap().as_ref().unwrap().clone()
}

#[derive(Default)]
struct InterruptInputs {
    control: Option<ReservedInputControl>,
}

#[reverie::global_tool]
impl GlobalTool for InterruptInputs {
    type Config = u8;
    type Request = u8;
    type Response = bool;

    async fn receive_rpc(&self, _: Pid, event: u8) -> bool {
        let evidence = evidence();
        let mut events = evidence.events.lock().unwrap();
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
        evidence().registrations.lock().unwrap().push(task);
        Ok(())
    }

    fn admit_reserved_input_initial_state(
        &self,
        _: &InputNativeFacts,
    ) -> Result<InputAdmission, Error> {
        // This fixture has exactly one staged issuer, after actual parent EOF.
        Ok(InputAdmission::Qualified)
    }

    fn on_reserved_input_setup(&self, receipt: InputSetupReceipt) -> Result<(), Error> {
        assert!(
            matches!(receipt.outcome, InputSetupOutcome::Qualified(_)),
            "{receipt:?}"
        );
        Ok(())
    }

    fn report_backend_failure(&self, _: reverie::BackendFailure) {
        let evidence = evidence();
        if let Some(id) = *evidence.writer.lock().unwrap() {
            let control = self.control.as_ref().unwrap();
            evidence.failures.lock().unwrap().push((
                control.failure().unwrap_or_default(),
                control.injection_observation(id).unwrap(),
                evidence.parent_calls.load(Ordering::Acquire),
                evidence.parked_polls.load(Ordering::Acquire),
            ));
        }
        evidence.fatal_seen.add_permits(1);
    }
}

fn description(call: Syscall) -> PhysicalInjectionDescription {
    let (number, a) = call.into_parts();
    PhysicalInjectionDescription {
        number: number as u64,
        args: [
            a.arg0 as u64,
            a.arg1 as u64,
            a.arg2 as u64,
            a.arg3 as u64,
            a.arg4 as u64,
            a.arg5 as u64,
        ],
        input: InputCallInput::Registers,
        expected_sharing: InputExpectedSharing::default(),
        transient: vec![],
        prospective: vec![],
        unknown_lifecycle: None,
    }
}

#[derive(Default)]
struct InterruptTool;

#[reverie::tool]
impl Tool for InterruptTool {
    type GlobalState = InterruptInputs;
    type ThreadState = bool;

    fn enforces_serialized_execution(_: &u8) -> bool {
        true
    }
    fn reserved_input_requirement(_: &u8) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }
    fn subscriptions(_: &u8) -> Subscription {
        [Sysno::clone, Sysno::fork, Sysno::vfork, Sysno::write]
            .into_iter()
            .collect()
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Tid,
        global: &G,
        survivor: bool,
        status: ExitStatus,
    ) -> Result<(), Error> {
        if survivor {
            if evidence().writer.lock().unwrap().is_some() {
                // Failed runs keep native cleanup separate from the successful
                // EOF/staging oracle; the test requires the exact fatal cause.
                return Ok(());
            }
            assert_eq!(status, ExitStatus::Exited(0));
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
        if matches!(number, Sysno::clone | Sysno::fork | Sysno::vfork) {
            if number == Sysno::clone {
                assert!(
                    args.arg0 == (libc::CLONE_VM | libc::SIGCHLD) as usize
                        || (*guest.config() & 128 != 0 && args.arg0 & libc::CLONE_VM as usize == 0)
                );
            }
            control.grant(owner, InputGrantKind::Ordinary).unwrap();
            let mut call_description = description(call);
            call_description.expected_sharing = InputExpectedSharing {
                memory: Some(
                    number == Sysno::vfork
                        || (number == Sysno::clone && args.arg0 & libc::CLONE_VM as usize != 0),
                ),
                files: Some(false),
                may_create: true,
                thread_group: Some(false),
            };
            call_description.unknown_lifecycle = Some(InputExposure {
                target: InputTarget::Unknown,
                cause: "fixture-unobserved-birth".into(),
            });
            let receipt = control
                .prepare_observed_injection(owner, 1, call_description)
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
            -920 => {
                evidence().parent_ready.add_permits(1);
                Ok(0)
            }
            -921 => {
                let evidence = evidence();
                evidence.parked_ready.add_permits(1);
                let wait = evidence.release.acquire();
                tokio::pin!(wait);
                std::future::poll_fn(|cx| {
                    evidence.parked_polls.fetch_add(1, Ordering::AcqRel);
                    wait.as_mut().poll(cx)
                })
                .await
                .unwrap()
                .forget();
                // The kill rows never release this callback.
                assert!(!matches!(*guest.config() & 7, 2 | 3));
                Ok(0)
            }
            -922 => {
                let evidence = evidence();
                evidence.parent_calls.fetch_add(1, Ordering::AcqRel);
                Ok(i64::from(
                    evidence.parent_may_finish.load(Ordering::Acquire),
                ))
            }
            -930 => {
                // A real separate process is stopped inside its callback. Put
                // its generic transaction at the final-stop phase without a
                // native page write; then hold the exact scope/receipt. This is
                // a scripted phase conflict, not a claim of image transport.
                control.grant(owner, InputGrantKind::Ordinary).unwrap();
                let scope = control.begin_operation(owner, 93).unwrap();
                let receipt = control
                    .prepare_injection(
                        &scope,
                        description(Syscall::from_raw(
                            Sysno::getpid,
                            SyscallArgs::new(0, 0, 0, 0, 0, 0),
                        )),
                    )
                    .unwrap();
                let image = ReservedInputImage::new(control.layout(owner).unwrap(), &[]).unwrap();
                control
                    .backend_begin_preparation(&receipt, &scope, image)
                    .unwrap();
                control.backend_prepared_stopped(receipt.id()).unwrap();
                let evidence = evidence();
                *evidence.writer.lock().unwrap() = Some(receipt.id());
                evidence.writer_ready.add_permits(1);
                std::future::pending::<()>().await;
                drop((scope, receipt));
                unreachable!("only actual fatal cleanup may cancel this owner")
            }
            -911 => {
                *guest.thread_state_mut() = true;
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
                assert_eq!(guest.inject(read).await?, 0, "native EOF, not cancellation");
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
                let bytes = vec![0x5d; layout.page_bytes];
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
                let mut call_description = description(submitted);
                call_description.input = InputCallInput::Immutable {
                    address: layout.base,
                    bytes: Arc::from(image.bytes()),
                };
                let receipt = control.prepare_injection(&scope, call_description).unwrap();
                let id = receipt.id();
                let result = guest
                    .inject_staged_input(submitted, &scope, image.clone(), receipt)
                    .await;
                let observation = control.injection_observation(id).unwrap();
                let after = if (*guest.config() & 7) >= 2 {
                    let mut after = vec![0; layout.page_bytes];
                    guest.memory().read_exact(address, &mut after)?;
                    Some(after)
                } else {
                    None
                };
                // Retain the live pre-cleanup evidence. Assertions in this
                // descendant callback invoke the production fatal-panic exit,
                // so the outer test checks it after the native tree joins.
                evidence().staged.lock().unwrap().push(StagedEvidence {
                    result,
                    observation,
                    before,
                    after,
                    image,
                    pid: guest.pid(),
                });
                control.finish_operation(scope).unwrap();
                guest.send_rpc(3).await;
                Ok(0)
            }
            _ => Ok(guest.inject(call).await?),
        }
    }
}

#[tokio::test]
async fn interrupt_and_trap_resumes_publish_before_a_shared_mm_survivor_stages() {
    let _serial = TEST_LOCK.lock().await;
    static GUEST: LazyLock<(PathBuf, Vec<u64>)> = LazyLock::new(|| {
        build_guest(
            "gdbstub_reserved_input_interrupts",
            &["-Wall", "-Wextra", "-Werror"],
            &["input_interrupt_breakpoint"],
        )
    });
    // 0: ordinary ptrace interrupt, 1: callback that stays parked on kill,
    // 2: guest int3, 3: debugger breakpoint, 4: its single-step trap,
    // 5: an injected vfork's in-place vforkdone callback.
    for route in 0..6u8 {
        for (action, rsp) in ["c", "s", "C09", "S09", "C1e", "S1e"]
            .into_iter()
            .enumerate()
        {
            let case = (route << 3) | action as u8;
            let evidence = Arc::new(Evidence::default());
            *CURRENT.lock().unwrap() = Some(evidence.clone());
            let socket = std::env::temp_dir().join(format!(
                "reverie-gdb-input-interrupt-{case}-{}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&socket);
            let mut command = Command::new(&GUEST.0);
            command.arg(case.to_string());
            let tracer = async {
                let builder = TracerBuilder::<InterruptTool>::new(command)
                    .config(case)
                    .gdbserver(socket.clone());
                let builder = if route == 1 {
                    builder.sequentialized_guest()
                } else {
                    builder
                };
                builder
                    .spawn()
                    .await
                    .expect("spawn shared-MM guest")
                    .wait()
                    .await
                    .expect("wait for both native groups")
            };
            let gdb = async {
                let mut remote = Remote::connect(&socket).await;
                let features = if route == 5 {
                    format!("{NO_EVENTS};vfork-events+")
                } else {
                    NO_EVENTS.to_owned()
                };
                remote.supported(&features).await;
                let parent = remote.thread.clone();
                if matches!(route, 3 | 4) {
                    remote.insert(GUEST.1[0]).await;
                }
                remote.resume_in_background().await;
                let stop = if route <= 1 {
                    if route == 1 {
                        evidence.parked_ready.acquire().await.unwrap().forget();
                    } else {
                        evidence.parent_ready.acquire().await.unwrap().forget();
                    }
                    remote.interrupt().await
                } else {
                    remote.recv().await
                };
                let stop = if route == 5 {
                    let child = stop
                        .strip_prefix("T05vfork:")
                        .and_then(|s| s.split(';').next())
                        .expect("real injected vfork stop");
                    let pid = child.strip_prefix('p').unwrap().split('.').next().unwrap();
                    assert_eq!(remote.request(&format!("D;{pid}")).await, "OK");
                    // The parent is still at the real PTRACE_EVENT_VFORK.
                    // These signal arguments are ignored by Linux; the two
                    // no-signal vforkdone rows must still stage successfully.
                    let event_action = match action {
                        0 => "C1e",
                        1 => "S1e",
                        _ => "c",
                    };
                    let done = remote
                        .request(&format!("vCont;{event_action}:{parent}"))
                        .await;
                    assert!(done.starts_with("T05vforkdone:"), "{done:?}");
                    done
                } else {
                    assert!(
                        stop.starts_with(if route <= 1 { "T02" } else { "T05" }),
                        "route {route}: {stop:?}"
                    );
                    stop
                };
                assert_eq!(
                    stop_thread(&stop),
                    parent,
                    "the selected process owns this stop"
                );
                if matches!(route, 3 | 4) {
                    remote.remove(GUEST.1[0]).await;
                }
                if route == 4 {
                    let stepped = remote.request(&format!("vCont;s:{parent}")).await;
                    assert!(
                        stepped.starts_with("T05"),
                        "actual single-step delivery stop: {stepped:?}"
                    );
                    assert_eq!(stop_thread(&stepped), parent);
                    assert_eq!(
                        stop_rip(&stepped),
                        GUEST.1[0] + 1,
                        "the no-signal step executed exactly the first one-byte nop"
                    );
                }
                remote.send(&format!("vCont;{rsp}:{parent}")).await;
                if !matches!(action, 2 | 3) {
                    evidence.parent_may_finish.store(true, Ordering::Release);
                    if route == 1 {
                        evidence.release.add_permits(1);
                    }
                }
                let mut end = remote.recv().await;
                if matches!(action, 1 | 5) {
                    assert!(end.starts_with("T05"), "actual step result: {end:?}");
                    end = remote.resume().await;
                }
                if matches!(action, 2 | 3) {
                    assert!(end.starts_with("X09"), "actual SIGKILL: {end:?}");
                } else {
                    assert_exited_zero(&end, "full mask, siginfo, and surviving process");
                }
            };
            let ((status, _), ()) =
                tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(tracer, gdb) })
                    .await
                    .expect("the exact case finishes");
            let _ = std::fs::remove_file(&socket);
            // wait() above returned after native task-tree completion. Move the
            // snapshots out of the lock before any assertion can unwind.
            let mut staged = std::mem::take(&mut *evidence.staged.lock().unwrap()).into_iter();
            let StagedEvidence {
                result,
                observation,
                before,
                after,
                image,
                pid,
            } = staged
                .next()
                .expect("the survivor recorded its live staging result");
            assert!(
                staged.next().is_none(),
                "exactly one survivor staging attempt"
            );
            if (case & 7) >= 2 {
                let Err(InputInjectionError::Unavailable(error)) = result else {
                    panic!("expected unclassified-signal-forward, got {result:?}");
                };
                assert_eq!(error.reason(), "unclassified-signal-forward");
                assert_eq!(observation.state, PhysicalInjectionState::ProvedNoChild);
                assert_eq!(observation.verified_image, None);
                let after = after.expect("the stopped survivor's complete post-call page");
                assert_eq!(after, before);
            } else {
                assert_eq!(result.unwrap().unwrap(), i64::from(pid.as_raw()));
                assert_eq!(observation.verified_image.as_ref(), Some(&image));
            }
            if matches!(action, 2 | 3) {
                assert!(
                    matches!(status, ExitStatus::Signaled(Signal::SIGKILL, _)),
                    "{status:?}"
                );
            } else {
                assert_eq!(status, ExitStatus::Exited(0));
            }
            assert_eq!(*evidence.events.lock().unwrap(), [1, 2, 3, 5]);
            let registrations = evidence.registrations.lock().unwrap();
            let child = registrations.iter().find(|r| r.parent.is_some()).unwrap();
            let parent = registrations
                .iter()
                .find(|r| Some(r.task) == child.parent)
                .unwrap();
            assert_eq!(parent.region, child.region);
            assert_ne!(parent.group, child.group);
            assert_ne!(parent.native_pid, child.native_pid);
            assert_eq!(evidence.release.available_permits(), 0);
        }
    }
    *CURRENT.lock().unwrap() = None;
}

#[tokio::test]
async fn interrupt_publication_conflict_fails_before_send_or_callback_continuation() {
    let _serial = TEST_LOCK.lock().await;
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        build_guest(
            "gdbstub_reserved_input_interrupts",
            &["-Wall", "-Wextra", "-Werror"],
            &[],
        )
        .0
    });
    for route in 0..2u8 {
        for (action, rsp) in [(2u8, "C09"), (3, "S09")] {
            let case = 128 | (route << 3) | action;
            let evidence = Arc::new(Evidence::default());
            *CURRENT.lock().unwrap() = Some(evidence.clone());
            let socket = std::env::temp_dir().join(format!(
                "reverie-gdb-input-conflict-{case}-{}.sock",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&socket);
            let mut command = Command::new(&*GUEST);
            command.arg(case.to_string());
            let tracer = async {
                let builder = TracerBuilder::<InterruptTool>::new(command)
                    .config(case)
                    .gdbserver(socket.clone());
                let builder = if route == 1 {
                    builder.sequentialized_guest()
                } else {
                    builder
                };
                builder
                    .spawn()
                    .await
                    .expect("spawn conflict guest")
                    .wait()
                    .await
            };
            let gdb = async {
                let mut remote = Remote::connect(&socket).await;
                remote.supported(NO_EVENTS).await;
                let parent = remote.thread.clone();
                remote.resume_in_background().await;
                evidence.writer_ready.acquire().await.unwrap().forget();
                if route == 1 {
                    evidence.parked_ready.acquire().await.unwrap().forget();
                } else {
                    evidence.parent_ready.acquire().await.unwrap().forget();
                }
                let stop = remote.interrupt().await;
                assert!(stop.starts_with("T02"), "{stop:?}");
                assert_eq!(stop_thread(&stop), parent);
                remote.send(&format!("vCont;{rsp}:{parent}")).await;
                // A run failure closes the debugger instead of pretending the
                // requested signal was a successful native guest result.
                evidence.fatal_seen.acquire().await.unwrap().forget();
            };
            let (result, ()) =
                tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(tracer, gdb) })
                    .await
                    .expect("fatal cleanup accounts for the real process tree");
            let _ = std::fs::remove_file(&socket);
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("a conflicting publication must fail the run"),
            };
            assert!(
                format!("{error:#}").contains("input-transaction-busy"),
                "{error:#}"
            );
            let failures = evidence.failures.lock().unwrap();
            let first = failures.first().expect("synchronous failure publication");
            assert_eq!(first.0, "input-transaction-busy");
            assert_eq!(first.1.state, PhysicalInjectionState::Prepared);
            assert_eq!(first.1.verified_image, None);
            assert_eq!(
                evidence.parent_calls.load(Ordering::Acquire),
                first.2,
                "the parent callback cannot continue after failed publication"
            );
            assert_eq!(
                evidence.parked_polls.load(Ordering::Acquire),
                first.3,
                "the parked callback cannot be repolled after failed publication"
            );
            assert!(
                !evidence.events.lock().unwrap().contains(&3),
                "survivor did not stage"
            );
            assert_eq!(evidence.release.available_permits(), 0);
            let registrations = evidence.registrations.lock().unwrap();
            let root = registrations
                .iter()
                .find(|parent| {
                    registrations.iter().any(|child| {
                        child.parent == Some(parent.task) && child.region == parent.region
                    })
                })
                .expect("the actual parent image has a shared-MM child");
            assert!(
                registrations
                    .iter()
                    .any(|r| r.parent == Some(root.task) && r.region != root.region),
                "the conflicting transaction belongs to an actual different MM"
            );
        }
    }
    *CURRENT.lock().unwrap() = None;
}
