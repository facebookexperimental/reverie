/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

// These controls exercise existing Tool register writes, not a remote
// debugger's parked-register admission.
use super::*;

const X32_BIT: u64 = 0x4000_0000;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
enum RegisterEdit {
    #[default]
    Unchanged,
    NativeNumber,
    X32Number,
    BoundUnchanged,
    BoundNumber,
    BoundArgument,
}
impl RegisterEdit {
    fn bound(self) -> bool {
        matches!(
            self,
            Self::BoundUnchanged | Self::BoundNumber | Self::BoundArgument
        )
    }
}

#[derive(Debug, Clone)]
struct RegisterCell {
    baseline: [i64; 3],
    args: [u64; 6],
    expected: i64,
}
thread_local! {
    static REGISTER_CELL: RefCell<Option<RegisterCell>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct RegisterGlobal;
#[reverie::global_tool]
impl GlobalTool for RegisterGlobal {
    type Config = RegisterEdit;
    type Request = ();
    type Response = ();
    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn admit_reserved_input_initial_state(
        &self,
        _: &InputNativeFacts,
    ) -> Result<InputAdmission, Error> {
        // Controlled, single-thread request-transport fixture, not production
        // environment or syscall-family policy qualification.
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
struct RegisterTool(RegisterEdit);
#[reverie::tool]
impl Tool for RegisterTool {
    type GlobalState = RegisterGlobal;
    type ThreadState = ();
    fn new(_: Pid, mode: &RegisterEdit) -> Self {
        Self(*mode)
    }
    fn subscriptions(_: &RegisterEdit) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }
    fn enforces_serialized_execution(_: &RegisterEdit) -> bool {
        true
    }
    fn reserved_input_requirement(_: &RegisterEdit) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }
    fn observes_native_syscalls(_: &RegisterEdit) -> bool {
        true
    }
    fn observe_native_syscall(
        &self,
        _: &(),
        facts: &dyn NativeSyscallFacts,
        call: &NativeSyscallCall,
    ) -> Result<Option<Arc<dyn NativeSyscallObserver>>, Error> {
        if call.purpose != NativeSyscallPurpose::Application {
            return Ok(None);
        }
        assert_eq!(facts.authority().unwrap().grant.is_none(), self.0.bound());
        Ok(Some(Arc::new(Cookie {
            operation: false,
            evidence: evidence(),
        })))
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let (number, raw) = call.into_parts();
        assert_eq!(number, Sysno::getpid);
        let args = [
            raw.arg0 as u64,
            raw.arg1 as u64,
            raw.arg2 as u64,
            raw.arg3 as u64,
            raw.arg4 as u64,
            raw.arg5 as u64,
        ];
        let baseline: [i64; 3] = guest
            .memory()
            .read_value(Addr::from_raw(raw.arg5).expect("guest's baseline array"))?;
        assert_eq!(baseline[0], guest.tid().as_raw() as i64);
        let expected = match self.0 {
            RegisterEdit::NativeNumber => baseline[1],
            RegisterEdit::X32Number => baseline[2],
            _ => baseline[0],
        };
        REGISTER_CELL.with(|cell| {
            *cell.borrow_mut() = Some(RegisterCell {
                baseline,
                args,
                expected,
            })
        });
        let control = guest.reserved_input_control().unwrap();
        let task = guest.reserved_input_task().unwrap();
        control
            .grant(task, InputGrantKind::Ordinary)
            .map_err(anyhow::Error::new)?;
        let operation = self
            .0
            .bound()
            .then(|| NativeOperation::new(Arc::new(Operation(evidence()))));
        let constrained = operation
            .as_ref()
            .map(|owner| guest.bind_native_request(owner, call))
            .transpose()?;
        let _close = operation.as_ref().map(|owner| CloseOperation {
            operation: owner.clone(),
            evidence: evidence(),
        });
        if self.0.bound() {
            control.invalidate_operation(task);
        }
        // The SAME saved typed call is injected below. Only actual registers
        // change after binding, so this reaches the final stop comparison and
        // is distinct from supplying a different Syscall to inject().
        let mut regs = guest.regs().await;
        assert_eq!(regs.orig_rax, Sysno::getpid as u64);
        match self.0 {
            RegisterEdit::NativeNumber | RegisterEdit::BoundNumber => {
                regs.orig_rax = Sysno::getuid as u64;
            }
            RegisterEdit::X32Number => regs.orig_rax |= X32_BIT,
            RegisterEdit::BoundArgument => regs.rdi ^= 1,
            RegisterEdit::Unchanged | RegisterEdit::BoundUnchanged => {}
        }
        guest.set_regs(regs).await?;
        let result = if let Some(constrained) = constrained {
            let mut bound = NativeOperationGuest::<_, Self>::new(guest, constrained)?;
            bound.inject(call).await
        } else {
            guest.inject(call).await
        };
        assert!(
            !matches!(
                self.0,
                RegisterEdit::BoundNumber | RegisterEdit::BoundArgument
            ),
            "changed bound request returned from native issue: {result:?}"
        );
        let raw_result = result.unwrap_or_else(|errno| -(errno.into_raw() as i64));
        assert_eq!(
            raw_result, expected,
            "actual kernel result must equal the raw native baseline"
        );
        if let Some(owner) = operation {
            owner.close();
            assert!(owner.effects_complete());
        }
        result.map_err(Into::into)
    }
}

unsafe fn raw_native(number: u64, args: [u64; 6]) -> i64 {
    let result: i64;
    // SAFETY: callers use only getpid/gettid/getuid (including the raw x32
    // getpid number), which do not dereference the otherwise identical args.
    unsafe {
        std::arch::asm!(
            "syscall", inlateout("rax") number => result,
            in("rdi") args[0], in("rsi") args[1], in("rdx") args[2],
            in("r10") args[3], in("r8") args[4], in("r9") args[5],
            lateout("rcx") _, lateout("r11") _, options(nostack),
        );
    }
    result
}

fn run_register_edit(mode: RegisterEdit) -> Result<(), String> {
    EVIDENCE.with(|value| *value.borrow_mut() = Arc::default());
    REGISTER_CELL.with(|cell| *cell.borrow_mut() = None);
    crate::testing::run_tokio_test(async move {
        let tracer = crate::tracer::spawn_fn_with_config::<RegisterTool, _>(
            move || unsafe {
                let mut baseline = [0i64; 3];
                let args = [11, 13, 17, 19, 23, baseline.as_mut_ptr() as u64];
                // All native references have the same six arguments as the
                // actual edited call. x32 retains its real native answer;
                // ENOSYS is neither manufactured nor treated as a skip.
                baseline
                    .as_mut_ptr()
                    .write_volatile(raw_native(Sysno::gettid as u64, args));
                baseline
                    .as_mut_ptr()
                    .add(1)
                    .write_volatile(raw_native(Sysno::getuid as u64, args));
                if matches!(mode, RegisterEdit::X32Number) {
                    baseline
                        .as_mut_ptr()
                        .add(2)
                        .write_volatile(raw_native(X32_BIT | Sysno::getpid as u64, args));
                }
                let result = raw_native(Sysno::getpid as u64, args);
                let expected = match mode {
                    RegisterEdit::NativeNumber => baseline[1],
                    RegisterEdit::X32Number => baseline[2],
                    RegisterEdit::BoundNumber | RegisterEdit::BoundArgument => {
                        panic!("changed bound request reached guest continuation")
                    }
                    _ => baseline[0],
                };
                assert_eq!(result, expected);
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
        .expect("register-edit native control timed out")
    })
    .map(|(output, _)| assert!(output.status.success(), "{output:?}"))
    .map_err(|error| format!("{error:?}"))
}

#[test]
fn tool_register_edits_preserve_native_results_and_the_x32_number() {
    for (mode, number) in [
        (RegisterEdit::Unchanged, Sysno::getpid as u64),
        (RegisterEdit::NativeNumber, Sysno::getuid as u64),
        (RegisterEdit::X32Number, X32_BIT | Sysno::getpid as u64),
    ] {
        run_register_edit(mode).unwrap();
        let cell = REGISTER_CELL.with(|cell| cell.borrow().clone().unwrap());
        let events = evidence().lock().unwrap().events.clone();
        assert_eq!(events.len(), 2, "{mode:?}: {events:?}");
        assert_eq!(events[0].event, NativeSyscallEvent::ResumeIssued);
        let result = Errno::from_ret(cell.expected as usize).map(|value| value as i64);
        assert_eq!(events[1].event, NativeSyscallEvent::NativeResult(result));
        assert_eq!(events[0].call.id, events[1].call.id);
        for event in &events {
            assert_eq!(
                event.call.abi,
                NativeSyscallAbi::Linux {
                    audit_arch: 0xc000_003e
                }
            );
            assert_eq!(event.call.number, number, "do not mask the x32 bit");
            assert_eq!(event.call.args, cell.args);
            assert!(!event.call.operation_bound);
        }
        eprintln!("actual native reference {mode:?}: {:?}", cell.baseline);
    }
}

#[test]
fn a_bound_original_entry_rejects_late_register_edits_before_issue() {
    run_register_edit(RegisterEdit::BoundUnchanged).unwrap();
    let cell = REGISTER_CELL.with(|cell| cell.borrow().clone().unwrap());
    let events = evidence().lock().unwrap().events.clone();
    let owned = events
        .iter()
        .filter(|event| event.operation)
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 2, "{events:?}");
    assert_eq!(owned[0].event, NativeSyscallEvent::ResumeIssued);
    assert_eq!(
        owned[1].event,
        NativeSyscallEvent::NativeResult(Ok(cell.baseline[0]))
    );
    assert_eq!(owned[0].call.id, owned[1].call.id);
    assert!(
        owned
            .iter()
            .all(|event| event.call.number == Sysno::getpid as u64 && event.call.args == cell.args)
    );
    for mode in [RegisterEdit::BoundNumber, RegisterEdit::BoundArgument] {
        let error = run_register_edit(mode).expect_err("late register mutation must not issue");
        assert!(
            error.contains("native-request-ownership-mismatch"),
            "{mode:?}: {error}"
        );
        assert!(
            REGISTER_CELL.with(|cell| cell.borrow().is_some()),
            "actual entry was reached"
        );
        assert!(
            evidence().lock().unwrap().events.is_empty(),
            "must fail before observation or ResumeIssued"
        );
    }
}
