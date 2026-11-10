/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

use reverie::Error;
use reverie::GlobalTool;
use reverie::NativeOperationGuest;
use reverie::Subscription;
use reverie::syscalls::Close;
use reverie::syscalls::Getppid;
use reverie::syscalls::Getuid;
use reverie::syscalls::OFlag;
use reverie::syscalls::Openat;
use reverie::syscalls::PathPtr;
use serde::Deserialize;
use serde::Serialize;

use super::*;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
enum Mode {
    #[default]
    Exact,
    Private,
    Tail,
    Emulated,
    Errno,
    Operation,
    Open,
    Exit,
    NotRun,
    UnobservedDefault,
    Request,
    RequestChangedNumber,
    RequestChangedArgument,
    Exec,
    ExecPrivate,
    ExecPreparing,
}
impl Mode {
    fn binds_request(self) -> bool {
        matches!(
            self,
            Self::Request
                | Self::RequestChangedNumber
                | Self::RequestChangedArgument
                | Self::ExecPreparing
        )
    }
}

#[derive(Debug, Clone)]
struct Seen {
    operation: bool,
    call: NativeSyscallCall,
    event: NativeSyscallEvent,
    descriptor: Option<InputDescriptorFacts>,
    operation_complete: Option<bool>,
}
#[derive(Debug, Default)]
struct Evidence {
    events: Vec<Seen>,
    setup_events: Vec<setup_origin::SetupSeen>,
    setup_target: bool,
    operation_returned: bool,
    operation_readmitted: bool,
    completion: Option<NativeOperationCompletion>,
    unrelated: Option<NativeOperation>,
    post_exec_complete: bool,
    tail_boundary_observed: bool,
}
thread_local! {
    static EVIDENCE: RefCell<Arc<StdMutex<Evidence>>> = RefCell::new(Arc::default());
}
fn evidence() -> Arc<StdMutex<Evidence>> {
    EVIDENCE.with(|value| value.borrow().clone())
}

#[derive(Debug)]
struct Cookie {
    operation: bool,
    evidence: Arc<StdMutex<Evidence>>,
}
impl NativeSyscallObserver for Cookie {
    fn observe(
        &self,
        call: &NativeSyscallCall,
        event: NativeSyscallEvent,
        facts: Option<&dyn NativeSyscallFacts>,
    ) -> Result<(), Error> {
        let descriptor = if call.number == Sysno::openat as u64 {
            if let NativeSyscallEvent::NativeResult(Ok(fd)) = event {
                Some(
                    facts
                        .expect("actual result stop")
                        .descriptor(fd as i32)
                        .map_err(anyhow::Error::new)?,
                )
            } else {
                None
            }
        } else {
            None
        };
        let mut evidence = self.evidence.lock().unwrap();
        let operation_complete = evidence
            .completion
            .as_ref()
            .map(NativeOperationCompletion::effects_complete);
        evidence.events.push(Seen {
            operation: self.operation,
            call: call.clone(),
            event,
            descriptor,
            operation_complete,
        });
        Ok(())
    }
}
#[derive(Debug)]
struct Operation(Arc<StdMutex<Evidence>>);
impl NativeOperationObserver for Operation {
    fn observe(
        &self,
        _facts: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
        assert!(call.operation_bound);
        assert!(!self.0.lock().unwrap().operation_returned);
        Ok(Some(Arc::new(Cookie {
            operation: true,
            evidence: self.0.clone(),
        })))
    }
}

struct CloseOperation {
    operation: NativeOperation,
    evidence: Arc<StdMutex<Evidence>>,
}
impl Drop for CloseOperation {
    fn drop(&mut self) {
        self.operation.close();
        self.evidence.lock().unwrap().completion = Some(self.operation.completion());
    }
}

#[derive(Default)]
struct NativeGlobal;
#[reverie::global_tool]
impl GlobalTool for NativeGlobal {
    type Config = Mode;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn admit_reserved_input_initial_state(
        &self,
        _: &InputNativeFacts,
    ) -> Result<InputAdmission, Error> {
        // Single issuing thread in this request-transport fixture. This is
        // neither production environment admission nor Linux policy evidence.
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
struct NativeTool {
    mode: Mode,
    pid: Option<Pid>,
}
#[reverie::tool]
impl Tool for NativeTool {
    type GlobalState = NativeGlobal;
    type ThreadState = ();
    fn new(pid: Pid, mode: &Mode) -> Self {
        Self {
            mode: *mode,
            pid: Some(pid),
        }
    }
    fn subscriptions(mode: &Mode) -> Subscription {
        let mut calls = vec![Sysno::getpid, Sysno::getppid];
        if matches!(mode, Mode::Exec | Mode::ExecPrivate | Mode::ExecPreparing) {
            calls.push(Sysno::execve);
        }
        if matches!(mode, Mode::Exec) {
            // The setup-origin control requires an actual clock replacement;
            // it does not accept an absent host-vDSO patch as coverage.
            calls.push(Sysno::clock_gettime);
        }
        calls.into_iter().collect()
    }
    fn enforces_serialized_execution(mode: &Mode) -> bool {
        mode.binds_request()
    }
    fn reserved_input_requirement(mode: &Mode) -> Option<ReservedInputRequirement> {
        mode.binds_request()
            .then(ReservedInputRequirement::sealed_page)
    }
    fn observes_native_syscalls(mode: &Mode) -> bool {
        !matches!(mode, Mode::UnobservedDefault)
    }
    fn observe_native_syscall(
        &self,
        _: &(),
        _: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
        assert!(
            !matches!(self.mode, Mode::UnobservedDefault),
            "default path must not invoke observer"
        );
        if matches!(self.mode, Mode::Exec)
            && let Some(observer) = setup_origin::observe(self.pid.unwrap(), call)
        {
            return Ok(Some(observer));
        }
        if call.purpose != NativeSyscallPurpose::Application {
            return Ok(None);
        }
        Ok(Some(Arc::new(Cookie {
            operation: false,
            evidence: evidence(),
        })))
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, _: &mut G) -> Result<(), Errno> {
        if matches!(
            self.mode,
            Mode::Exec | Mode::ExecPrivate | Mode::ExecPreparing
        ) {
            let evidence = evidence();
            let (completion, unrelated) = {
                let seen = evidence.lock().unwrap();
                (seen.completion.clone(), seen.unrelated.clone())
            };
            // Assert without poisoning the evidence needed by CloseOperation
            // during failure cleanup. Both handles retain the same live state.
            assert!(
                completion
                    .as_ref()
                    .expect("old operation retained")
                    .effects_complete(),
                "old owner's close/effects proof precedes new-image Tool callback"
            );
            assert!(
                !unrelated.as_ref().unwrap().effects_complete(),
                "an unassociated owner is not closed by another task's exec"
            );
            evidence.lock().unwrap().post_exec_complete = true;
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        if matches!(self.mode, Mode::Exec) && call.into_parts().0 == Sysno::clock_gettime {
            return guest.inject(call).await.map_err(Into::into);
        }
        if matches!(
            self.mode,
            Mode::Exec | Mode::ExecPrivate | Mode::ExecPreparing
        ) && call.into_parts().0 == Sysno::execve
        {
            if matches!(self.mode, Mode::Exec) {
                evidence().lock().unwrap().setup_target = true;
            }
            if !matches!(self.mode, Mode::ExecPreparing) {
                assert!(
                    guest.reserved_input_control().is_none(),
                    "generic exec control must not depend on facility"
                );
            }
            let owner = evidence();
            let operation = NativeOperation::new(Arc::new(Operation(owner.clone())));
            {
                let mut seen = owner.lock().unwrap();
                seen.completion = Some(operation.completion());
                seen.unrelated = Some(NativeOperation::new(Arc::new(Operation(Arc::default()))));
            }
            let _close = CloseOperation {
                operation: operation.clone(),
                evidence: owner,
            };
            if matches!(self.mode, Mode::ExecPreparing) {
                let control = guest.reserved_input_control().unwrap();
                let task = guest.reserved_input_task().unwrap();
                control
                    .grant(task, InputGrantKind::Ordinary)
                    .map_err(anyhow::Error::new)?;
                let pending =
                    guest.bind_native_request(&operation, Close::default().with_fd(-1))?;
                assert!(!pending.effects_complete());
                control.invalidate_operation(task);
                // An independent actual exec replaces the owner before this
                // bound request ever constructs an injection context. The old
                // callback (and _close) is still alive during post-exec hooks.
                guest.inject(call).await?;
                unreachable!("preparing-owner exec returned");
            }
            let mut bound = NativeOperationGuest::<_, Self>::new(guest, operation.clone())?;
            if matches!(self.mode, Mode::ExecPrivate) {
                // Multiple attempts share this exact owner, but a successful
                // ordinary return must leave admission open until exec.
                bound.inject(Getuid::default()).await?;
                assert!(!operation.effects_complete());
                bound.inject(call).await?;
                unreachable!("injected exec returned");
            }
            bound.tail_inject(call).await
        }
        if self.mode.binds_request() && call.into_parts().0 == Sysno::getpid {
            let control = guest
                .reserved_input_control()
                .expect("actual request control");
            let task = guest
                .reserved_input_task()
                .expect("actual registered request task");
            let operation = NativeOperation::new(Arc::new(Operation(evidence())));
            let intended = Close::default().with_fd(-1);
            assert!(
                guest.bind_native_request(&operation, intended).is_err(),
                "missing grant cannot bind"
            );
            control
                .grant(task, InputGrantKind::Ordinary)
                .map_err(anyhow::Error::new)?;
            let constrained = guest.bind_native_request(&operation, intended)?;
            assert!(
                constrained
                    .completion()
                    .same_operation(&operation.completion())
            );
            assert!(operation.bound_request().is_none());
            assert_eq!(
                constrained.bound_request().unwrap().number,
                Sysno::close as u64
            );
            // Releasing the real grant is legitimate. Binding another request
            // after it, even for the same operation, is not.
            control.invalidate_operation(task);
            assert!(
                guest.bind_native_request(&operation, intended).is_err(),
                "released grant cannot bind"
            );
            let result = {
                let mut bound = NativeOperationGuest::<_, Self>::new(guest, constrained)?;
                match self.mode {
                    Mode::Request => bound.inject(intended).await,
                    Mode::RequestChangedNumber => bound.inject(Getuid::default()).await,
                    Mode::RequestChangedArgument => {
                        bound.inject(Close::default().with_fd(-2)).await
                    }
                    _ => unreachable!(),
                }
            };
            assert_eq!(
                result,
                Err(Errno::EBADF),
                "unchanged native request keeps actual errno"
            );
            operation.close();
            assert!(operation.effects_complete());
            return Ok(45);
        }
        if matches!(self.mode, Mode::Tail) && call.into_parts().0 == Sysno::getppid {
            let log = evidence();
            let mut log = log.lock().unwrap();
            assert!(
                !log.tail_boundary_observed,
                "one existing follow-up boundary"
            );
            let tail = log
                .events
                .iter()
                .filter(|event| event.call.number == Sysno::getpid as u64)
                .collect::<Vec<_>>();
            assert_eq!(
                tail.len(),
                3,
                "existing next syscall entry must settle tail effects before its Tool callback"
            );
            assert_eq!(tail[0].event, NativeSyscallEvent::ResumeIssued);
            assert_eq!(tail[1].event, NativeSyscallEvent::ResultUnobserved);
            assert_eq!(tail[2].event, NativeSyscallEvent::EffectsComplete);
            for event in &tail {
                assert_eq!(event.call.id, tail[0].call.id);
                assert_eq!(event.call.abi, tail[0].call.abi);
                assert_eq!(event.call.number, tail[0].call.number);
                assert_eq!(event.call.args, tail[0].call.args);
                assert_eq!(event.call.purpose, tail[0].call.purpose);
                assert_eq!(event.call.operation_bound, tail[0].call.operation_bound);
                assert_eq!(event.call.input_receipt, tail[0].call.input_receipt);
                assert_eq!(event.call.staged_image, tail[0].call.staged_image);
            }
            log.tail_boundary_observed = true;
        }
        if call.into_parts().0 != Sysno::getpid {
            return Ok(guest.inject(call).await?);
        }
        match self.mode {
            Mode::Exact
            | Mode::UnobservedDefault
            | Mode::Exec
            | Mode::ExecPrivate
            | Mode::ExecPreparing => Ok(guest.inject(call).await?),
            Mode::Request | Mode::RequestChangedNumber | Mode::RequestChangedArgument => {
                unreachable!()
            }
            Mode::NotRun => {
                assert_eq!(
                    guest.inject(Close::default().with_fd(-1)).await,
                    Err(Errno::ENOSYS)
                );
                Ok(44)
            }
            Mode::Private => Ok(guest.inject(Getuid::default()).await?),
            Mode::Tail => guest.tail_inject(call).await,
            Mode::Emulated => Ok(1234),
            Mode::Errno => {
                assert_eq!(
                    guest.inject(Close::default().with_fd(-1)).await,
                    Err(Errno::EBADF)
                );
                Ok(42)
            }
            Mode::Operation => {
                // This independent helper cannot consume the upcoming owner.
                assert!(guest.inject(Getppid::default()).await? > 0);
                let owner = evidence();
                let operation = NativeOperation::new(Arc::new(Operation(owner.clone())));
                let value = {
                    let mut bound = NativeOperationGuest::<_, Self>::new(guest, operation.clone())?;
                    bound.inject(Getuid::default()).await?
                };
                assert!(
                    !operation.effects_complete(),
                    "open caller still owns its operation"
                );
                operation.close();
                assert!(operation.effects_complete());
                let mut state = owner.lock().unwrap();
                state.operation_returned = true;
                assert!(
                    !state.operation_readmitted,
                    "native completion cannot retire caller ownership"
                );
                assert!(state.events.iter().any(|event| event.operation
                    && matches!(event.event, NativeSyscallEvent::NativeResult(Ok(_)))));
                // The caller, not the native receipt, owns this later cut.
                state.operation_readmitted = true;
                Ok(value)
            }
            Mode::Open => {
                let fd = guest
                    .inject(
                        Openat::default()
                            .with_dirfd(libc::AT_FDCWD)
                            .with_path(PathPtr::from_ptr(c"/dev/null".as_ptr()))
                            .with_flags(OFlag::O_RDONLY),
                    )
                    .await?;
                assert!(fd >= 0);
                guest.inject(Close::default().with_fd(fd as i32)).await?;
                Ok(43)
            }
            Mode::Exit => {
                let owner = evidence();
                let operation = NativeOperation::new(Arc::new(Operation(owner.clone())));
                let _close = CloseOperation {
                    operation: operation.clone(),
                    evidence: owner,
                };
                let mut guest = NativeOperationGuest::<_, Self>::new(guest, operation)?;
                guest
                    .inject(reverie::syscalls::ExitGroup::default())
                    .await?;
                unreachable!("native exit continued")
            }
        }
    }
}

fn run_attempt(mode: Mode) -> Result<(), String> {
    EVIDENCE.with(|value| *value.borrow_mut() = Arc::default());
    crate::testing::run_tokio_test(async move {
        let tracer = crate::tracer::spawn_fn_with_config::<NativeTool, _>(
            move || unsafe {
                let uid = libc::getuid() as i64;
                if matches!(mode, Mode::Exec | Mode::ExecPrivate | Mode::ExecPreparing) {
                    let argv = [c"/bin/true".as_ptr(), std::ptr::null()];
                    libc::execv(argv[0], argv.as_ptr());
                    panic!("native exec returned");
                }
                if matches!(mode, Mode::NotRun) {
                    extern "C" fn trapped(_: i32) {}
                    assert_ne!(
                        libc::signal(libc::SIGSYS, trapped as *const () as usize),
                        libc::SIG_ERR
                    );
                    reverie::process::seccomp::FilterBuilder::new()
                        .default_action(reverie::process::seccomp::Action::Allow)
                        .syscall(Sysno::close, reverie::process::seccomp::Action::Trap)
                        .build()
                        .load()
                        .unwrap();
                }
                let result = libc::syscall(libc::SYS_getpid) as i64;
                match mode {
                    Mode::Exact | Mode::UnobservedDefault => assert!(result > 0),
                    Mode::NotRun => assert_eq!(result, 44),
                    Mode::Tail => {
                        assert!(result > 0);
                        // Existing next syscall-entry is the effects-ended
                        // witness; the tail still has no invented exit stop.
                        assert!(libc::syscall(libc::SYS_getppid) > 0);
                    }
                    Mode::Private | Mode::Operation => assert_eq!(result, uid),
                    Mode::Emulated => assert_eq!(result, 1234),
                    Mode::Errno => assert_eq!(result, 42),
                    Mode::Open => assert_eq!(result, 43),
                    Mode::Exit | Mode::Exec | Mode::ExecPrivate | Mode::ExecPreparing => {
                        panic!("native terminal operation returned to guest")
                    }
                    Mode::Request => assert_eq!(result, 45),
                    Mode::RequestChangedNumber | Mode::RequestChangedArgument => {
                        panic!("request mismatch reached guest")
                    }
                }
            },
            mode,
            true,
        )
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tracer.wait_with_output(),
        )
        .await
        .expect("native observation control timed out")
    })
    .map(|(output, _)| assert!(output.status.success(), "{output:?}"))
    .map_err(|error| format!("{error:?}"))
}

fn run(mode: Mode) -> Vec<Seen> {
    run_attempt(mode).unwrap();
    evidence().lock().unwrap().events.clone()
}

#[test]
fn native_observation_distinguishes_exact_private_tail_emulation_and_errno() {
    for (mode, number) in [
        (Mode::Exact, Sysno::getpid),
        (Mode::Private, Sysno::getuid),
        (Mode::Tail, Sysno::getpid),
        (Mode::Errno, Sysno::close),
    ] {
        let events = run(mode);
        let events = events
            .iter()
            .filter(|event| event.call.number == number as u64)
            .collect::<Vec<_>>();
        let expected = if matches!(mode, Mode::Tail) { 3 } else { 2 };
        assert_eq!(events.len(), expected, "{mode:?}: {events:?}");
        #[cfg(target_arch = "x86_64")]
        let audit_arch = 0xc000003e;
        #[cfg(target_arch = "aarch64")]
        let audit_arch = 0xc00000b7;
        assert!(
            events
                .iter()
                .all(|event| event.call.abi == NativeSyscallAbi::Linux { audit_arch })
        );
        assert_eq!(events[0].event, NativeSyscallEvent::ResumeIssued);
        assert_eq!(events[0].call.id, events[1].call.id);
        match mode {
            Mode::Tail => {
                assert!(
                    evidence().lock().unwrap().tail_boundary_observed,
                    "the existing follow-up callback must assert completion before retirement"
                );
                assert_eq!(events[1].event, NativeSyscallEvent::ResultUnobserved);
                assert_eq!(events[2].event, NativeSyscallEvent::EffectsComplete);
                assert_eq!(events[0].call.id, events[2].call.id);
            }
            Mode::Errno => assert_eq!(
                events[1].event,
                NativeSyscallEvent::NativeResult(Err(Errno::EBADF))
            ),
            _ => assert!(matches!(
                events[1].event,
                NativeSyscallEvent::NativeResult(Ok(_))
            )),
        }
        assert!(
            !events
                .iter()
                .any(|event| event.event == NativeSyscallEvent::ProvedNotRun)
        );
    }
    assert!(
        run(Mode::Emulated)
            .iter()
            .all(|event| event.call.number != Sysno::getpid as u64)
    );
}

#[test]
fn native_operation_binding_survives_forwarding_without_becoming_a_next_call_slot() {
    let events = run(Mode::Operation);
    let owned = events
        .iter()
        .filter(|event| event.operation)
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 2);
    assert!(
        owned
            .iter()
            .all(|event| event.call.number == Sysno::getuid as u64 && event.call.operation_bound)
    );
    assert!(
        events
            .iter()
            .any(|event| event.call.number == Sysno::getppid as u64 && !event.call.operation_bound)
    );
    assert_eq!(owned[0].call.id, owned[1].call.id);
    assert!(evidence().lock().unwrap().operation_readmitted);
}

#[test]
fn native_result_observer_pins_the_actual_returned_descriptor_before_tool_copyout() {
    let events = run(Mode::Open);
    let result = events
        .iter()
        .find(|event| event.descriptor.is_some())
        .expect("real open result-stop facts");
    let facts = result.descriptor.as_ref().unwrap();
    let NativeSyscallEvent::NativeResult(Ok(fd)) = result.event else {
        panic!("not an actual result")
    };
    assert_eq!(facts.fd, fd as i32);
    assert_eq!(
        facts.identity.as_ref().unwrap().2 & libc::S_IFMT,
        libc::S_IFCHR
    );
    assert_eq!(
        facts.status_flags.as_ref().unwrap() & libc::O_ACCMODE,
        libc::O_RDONLY
    );
}

#[test]
fn native_exit_retains_issued_obligation_when_the_injection_future_cannot_return() {
    let events = run(Mode::Exit);
    let exit = events
        .iter()
        .filter(|event| event.call.number == Sysno::exit_group as u64 && event.operation)
        .collect::<Vec<_>>();
    assert_eq!(exit.len(), 3);
    assert_eq!(exit[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(exit[1].event, NativeSyscallEvent::ResultUnobserved);
    assert_eq!(
        exit[1].operation_complete,
        Some(false),
        "callback cancellation cannot release unresolved effects"
    );
    assert_eq!(exit[2].event, NativeSyscallEvent::EffectsComplete);
    assert_eq!(
        exit[2].operation_complete,
        Some(true),
        "actual terminal completion ends the closed native operation"
    );
    assert_eq!(exit[0].call.id, exit[1].call.id);
    assert_eq!(exit[0].call.id, exit[2].call.id);
}

#[test]
fn native_trap_is_proved_not_run_and_does_not_become_an_errno_result() {
    let events = run(Mode::NotRun);
    let calls = events
        .iter()
        .filter(|event| event.call.number == Sysno::close as u64)
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(calls[1].event, NativeSyscallEvent::ProvedNotRun);
    assert_eq!(calls[0].call.id, calls[1].call.id);
    assert!(
        !calls
            .iter()
            .any(|event| matches!(event.event, NativeSyscallEvent::NativeResult(_)))
    );
}

#[test]
fn an_uninterested_tool_runs_native_calls_without_observer_queries() {
    assert!(run(Mode::UnobservedDefault).is_empty());
}

#[test]
fn a_pre_release_request_keeps_its_exact_operands_after_release() {
    let events = run(Mode::Request);
    let owned = events
        .iter()
        .filter(|event| event.operation)
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 2);
    assert_eq!(owned[0].call.number, Sysno::close as u64);
    assert_eq!(owned[0].call.args[0], (-1i64) as u64);
    assert_eq!(owned[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(
        owned[1].event,
        NativeSyscallEvent::NativeResult(Err(Errno::EBADF))
    );
    assert_eq!(owned[0].call.id, owned[1].call.id);
}

#[test]
fn the_same_operation_cannot_issue_a_different_bound_request() {
    for mode in [Mode::RequestChangedNumber, Mode::RequestChangedArgument] {
        let error = run_attempt(mode).expect_err("changed physical request must not execute");
        assert!(
            error.contains("native-request-ownership-mismatch"),
            "{mode:?}: {error}"
        );
        assert!(
            evidence()
                .lock()
                .unwrap()
                .events
                .iter()
                .all(|event| !event.operation),
            "ownership fails before observers or native effects"
        );
    }
}

#[test]
fn exec_completes_generic_native_effects_without_the_input_facility() {
    let events = run(Mode::Exec);
    setup_origin::assert_complete_setup();
    let exec = events
        .iter()
        .filter(|event| event.operation && event.call.number == Sysno::execve as u64)
        .collect::<Vec<_>>();
    assert_eq!(exec.len(), 3, "{exec:?}");
    assert_eq!(exec[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(exec[1].event, NativeSyscallEvent::ResultUnobserved);
    assert_eq!(exec[2].event, NativeSyscallEvent::EffectsComplete);
    assert_eq!(exec[2].operation_complete, Some(true));
    assert!(exec.iter().all(|event| event.call.id == exec[0].call.id));
    assert!(evidence().lock().unwrap().post_exec_complete);

    let events = run(Mode::ExecPrivate);
    let exec = events
        .iter()
        .filter(|event| event.operation && event.call.number == Sysno::execve as u64)
        .collect::<Vec<_>>();
    assert_eq!(exec.len(), 2, "{exec:?}");
    assert_eq!(exec[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(exec[1].event, NativeSyscallEvent::NativeResult(Ok(0)));
    assert_eq!(
        exec[1].operation_complete,
        Some(false),
        "ordinary result cannot close outer owner"
    );
    assert!(
        evidence().lock().unwrap().post_exec_complete,
        "actual exec closes all old-owner attempts before old callback Drop"
    );
}

#[test]
fn exec_settles_a_pre_release_bound_owner_before_any_physical_attempt_exists() {
    let events = run(Mode::ExecPreparing);
    assert!(
        events.iter().all(|event| !event.operation),
        "preparing owner never produced a physical native observation"
    );
    assert!(
        evidence().lock().unwrap().post_exec_complete,
        "actual exec, not callback Drop, settles the never-issued owner"
    );
}

#[cfg(target_arch = "x86_64")]
mod register_edits;

mod held_signal;

mod setup_origin;
