/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! These controls use the real ptrace page and clone decoder. Faults alter only
//! the return boundary of a real transport request, never the guest's oracle.

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Subscription;
use serde::Deserialize;
use serde::Serialize;

use super::*;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    BeforeFirstWord,
    AfterFirstWord,
    AfterLaterWord,
    ReadbackTail,
    Normalization,
    Debugger,
    FutureView,
}

#[derive(Default)]
struct Evidence {
    config: Fault,
    control: Option<ReservedInputControl>,
    tasks: Vec<InputTaskId>,
    expected: Option<ReservedInputImage>,
    calls: Vec<PhysicalInjectionObservation>,
    prepared: Vec<PhysicalInjectionId>,
    child_page_reads: usize,
    after_clone: usize,
    transport_failures: usize,
    normalization_words: usize,
    debugger_requests: usize,
    exec_old_tasks: Vec<InputTaskId>,
    exec_callbacks: usize,
    before_fill: Vec<(Vec<u8>, ReservedInputImage)>,
}

thread_local! {
    static EVIDENCE: RefCell<Arc<Mutex<Evidence>>> = RefCell::new(Arc::default());
    static FAULT: RefCell<Option<Fault>> = const { RefCell::new(None) };
}

fn evidence() -> Arc<Mutex<Evidence>> {
    EVIDENCE.with(|slot| slot.borrow().clone())
}

pub(super) fn write_fault(index: usize, after: bool, normalizing: bool) -> Result<(), Errno> {
    if normalizing && after {
        evidence().lock().unwrap().normalization_words += 1;
    }
    let fail = FAULT.with(|slot| {
        let mut fault = slot.borrow_mut();
        let fail = match *fault {
            Some(Fault::BeforeFirstWord) => !normalizing && index == 0 && !after,
            Some(Fault::AfterFirstWord) => !normalizing && index == 0 && after,
            Some(Fault::AfterLaterWord) => !normalizing && index == 37 && after,
            Some(Fault::Normalization) => index == 0 && after,
            _ => false,
        };
        if fail && (*fault != Some(Fault::Normalization) || normalizing) {
            *fault = None;
        }
        fail
    });
    if fail {
        evidence().lock().unwrap().transport_failures += 1;
        Err(Errno::EIO)
    } else {
        Ok(())
    }
}

pub(super) fn readback_fault(mut bytes: Vec<u8>, normalizing: bool) -> Vec<u8> {
    FAULT.with(|slot| {
        if !normalizing && *slot.borrow() == Some(Fault::ReadbackTail) {
            *slot.borrow_mut() = None;
            *bytes.last_mut().unwrap() ^= 1;
            evidence().lock().unwrap().transport_failures += 1;
        }
    });
    bytes
}

#[derive(Default)]
struct PageGlobal;

#[reverie::global_tool]
impl GlobalTool for PageGlobal {
    type Config = Fault;
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, _: Pid, _: ()) {}

    fn install_reserved_input_control(
        &mut self,
        control: ReservedInputControl,
    ) -> Result<(), Error> {
        evidence().lock().unwrap().control = Some(control);
        Ok(())
    }

    fn on_reserved_input_task(&self, task: InputTaskRegistration) -> Result<(), Error> {
        evidence().lock().unwrap().tasks.push(task.task);
        Ok(())
    }

    fn admit_reserved_input_initial_state(
        &self,
        _: &InputNativeFacts,
    ) -> Result<InputAdmission, Error> {
        // This narrowly controlled transport fixture has one issuing parent;
        // descendants only read the page and exit. This is not a general native
        // environment admission policy or an rseq isolation claim.
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
struct PageTool {
    fault: Fault,
}

fn description(
    call: Syscall,
    image: Option<&ReservedInputImage>,
    creates: bool,
) -> PhysicalInjectionDescription {
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
        input: image.map_or(InputCallInput::Unknown, |image| InputCallInput::Immutable {
            address: image.layout().base,
            bytes: Arc::from(image.bytes()),
        }),
        expected_sharing: InputExpectedSharing {
            memory: image.map(|image| {
                u64::from_ne_bytes(image.bytes()[..8].try_into().unwrap()) & libc::CLONE_VM as u64
                    != 0
            }),
            files: image.map(|image| {
                u64::from_ne_bytes(image.bytes()[..8].try_into().unwrap())
                    & libc::CLONE_FILES as u64
                    != 0
            }),
            may_create: creates,
            thread_group: Some(false),
        },
        transient: vec![],
        prospective: vec![],
        unknown_lifecycle: Some(InputExposure {
            target: InputTarget::Unknown,
            cause: "fixture-unobserved-birth".into(),
        }),
    }
}

#[reverie::tool]
impl Tool for PageTool {
    type GlobalState = PageGlobal;
    type ThreadState = ();

    fn new(_: Pid, fault: &Fault) -> Self {
        Self { fault: *fault }
    }

    fn enforces_serialized_execution(_: &Fault) -> bool {
        true
    }

    fn reserved_input_requirement(_: &Fault) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }

    fn observes_native_syscalls(config: &Fault) -> bool {
        *config == Fault::FutureView
    }

    fn observe_native_syscall(
        &self,
        _: &(),
        facts: &dyn reverie::native_syscall::NativeSyscallFacts,
        call: &reverie::native_syscall::NativeSyscallCall,
    ) -> Result<Option<Arc<dyn reverie::native_syscall::NativeSyscallObserver>>, Error> {
        if let Some(image) = &call.staged_image {
            let mut actual = vec![0u8; image.bytes().len()];
            let local = libc::iovec {
                iov_base: actual.as_mut_ptr().cast(),
                iov_len: actual.len(),
            };
            let remote = libc::iovec {
                iov_base: image.layout().base as *mut libc::c_void,
                iov_len: actual.len(),
            };
            let tid = facts.task().expect("owned stopped image").native_tid();
            let read = unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) };
            assert_eq!(
                read,
                actual.len() as isize,
                "real old page must remain fully readable before fill"
            );
            evidence()
                .lock()
                .unwrap()
                .before_fill
                .push((actual, image.clone()));
        }
        Ok(None)
    }

    fn subscriptions(_: &Fault) -> Subscription {
        [Sysno::write, Sysno::clone3].into_iter().collect()
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        let control = guest
            .reserved_input_control()
            .expect("actual backend control");
        let task = guest
            .reserved_input_task()
            .expect("actual registered generation");
        if control.registration(task).unwrap().parent.is_some() {
            let image = evidence()
                .lock()
                .unwrap()
                .expected
                .clone()
                .expect("parent prepared full B");
            let mut actual = vec![0; image.bytes().len()];
            guest.memory().read_exact(
                Addr::<u8>::from_raw(image.layout().base as usize).unwrap(),
                &mut actual,
            )?;
            assert_eq!(
                actual,
                image.bytes(),
                "first child Tool callback must see all of B"
            );
            evidence().lock().unwrap().child_page_reads += 1;
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let (number, args) = call.into_parts();
        if number == Sysno::write && args.arg0 as i32 == -901 {
            evidence().lock().unwrap().after_clone += 1;
            return Ok(0);
        }
        if self.fault == Fault::FutureView && number == Sysno::write && args.arg0 as i32 == -900 {
            // This control observes the initial zero page A. Other controls
            // deliberately prefill it to distinguish normalization from A.
            return Ok(0);
        }
        if number != Sysno::clone3 && !(number == Sysno::write && args.arg0 as i32 == -900) {
            return Ok(guest.inject(call).await?);
        }
        let creating = number == Sysno::clone3;
        let control = guest.reserved_input_control().unwrap();
        let task = guest.reserved_input_task().unwrap();
        let layout = control.layout(task).expect("authenticated actual page");
        let is_vfork = if creating {
            guest
                .memory()
                .read_value::<_, u64>(Addr::<u64>::from_raw(args.arg0).unwrap())?
                & libc::CLONE_VFORK as u64
                != 0
        } else {
            false
        };
        control
            .grant(
                task,
                if is_vfork {
                    InputGrantKind::PendingVfork {
                        logical_operation: 2,
                    }
                } else {
                    InputGrantKind::Ordinary
                },
            )
            .unwrap();
        let scope = control
            .begin_operation(task, if creating { 2 } else { 1 })
            .unwrap();
        let mut bytes = vec![if creating { 0xa7 } else { 0x5c }; layout.page_bytes];
        if creating {
            assert_eq!(args.arg1, 88);
            guest
                .memory()
                .read_exact(Addr::<u8>::from_raw(args.arg0).unwrap(), &mut bytes[..88])?;
        }
        let image = ReservedInputImage::new(
            layout,
            &[InputWrite {
                offset: 0,
                bytes: &bytes,
            }],
        )
        .unwrap();
        let submitted = if creating {
            Syscall::from_raw(
                Sysno::clone3,
                SyscallArgs {
                    arg0: layout.base as usize,
                    ..args
                },
            )
        } else {
            Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0))
        };
        let receipt = control
            .prepare_injection(&scope, description(submitted, Some(&image), creating))
            .unwrap();
        let receipt_id = receipt.id();
        evidence().lock().unwrap().prepared.push(receipt_id);
        if creating {
            evidence().lock().unwrap().expected = Some(image.clone());
            FAULT.with(|slot| *slot.borrow_mut() = Some(self.fault));
        }
        let result = guest
            .inject_staged_input(submitted, &scope, image.clone(), receipt)
            .await;
        let observation = control.injection_observation(receipt_id).unwrap();
        evidence().lock().unwrap().calls.push(observation.clone());
        let result = match result {
            Ok(result) => {
                assert_eq!(observation.verified_image.as_ref(), Some(&image));
                if creating {
                    assert!(
                        matches!(observation.state, PhysicalInjectionState::RetainedBirth(_)),
                        "{observation:?}"
                    );
                }
                result
            }
            Err(InputInjectionError::Unavailable(_))
                if creating
                    && matches!(
                        self.fault,
                        Fault::BeforeFirstWord
                            | Fault::AfterFirstWord
                            | Fault::AfterLaterWord
                            | Fault::ReadbackTail
                    ) =>
            {
                assert_eq!(observation.state, PhysicalInjectionState::ProvedNoChild);
                assert_eq!(observation.verified_image.as_ref(), Some(&image));
                let mut actual = vec![0; layout.page_bytes];
                guest.memory().read_exact(
                    Addr::<u8>::from_raw(layout.base as usize).unwrap(),
                    &mut actual,
                )?;
                assert_eq!(
                    actual,
                    image.bytes(),
                    "fallback sees the complete normalized B, including unused tail"
                );
                let receipt = control
                    .prepare_observed_injection(
                        task,
                        scope.logical_operation(),
                        description(call, None, true),
                    )
                    .unwrap();
                let id = receipt.id();
                let result = guest
                    .inject_observed(call, receipt)
                    .await
                    .map_err(anyhow::Error::new)?;
                let observed = control.injection_observation(id).unwrap();
                assert!(
                    matches!(observed.state, PhysicalInjectionState::RetainedBirth(_)),
                    "{observed:?}"
                );
                evidence().lock().unwrap().calls.push(observed);
                result
            }
            Err(error) => return Err(anyhow::Error::new(error).into()),
        };
        control.finish_operation(scope).unwrap();
        if creating {
            Ok(result?)
        } else {
            assert!(result? > 0);
            Ok(0)
        }
    }
}

struct ChildContext {
    original: [u64; 11],
    page_bytes: usize,
}

unsafe extern "C" fn child_on_new_stack(context: *const ChildContext) -> ! {
    // No allocation, TLS operation or parent-stack write in the shared-MM
    // child. The native wrapper gives it a distinct aligned stack.
    let context = unsafe { &*context };
    let expected = context.original.as_ptr().cast::<u8>();
    let mut code = 0;
    for at in 0..context.page_bytes {
        let wanted = if at < 88 {
            unsafe { expected.add(at).read() }
        } else {
            0xa7
        };
        if unsafe { ((RESERVED_INPUT_BASE as usize + at) as *const u8).read_volatile() } != wanted {
            code = 19;
        }
    }
    unsafe {
        libc::syscall(libc::SYS_exit, code);
        libc::_exit(20)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn clone_on_new_stack(args: &[u64; 11], context: &ChildContext) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "syscall", "test rax, rax", "jnz 2f", "mov rdi, r12", "call r13", "ud2", "2:",
            inlateout("rax") libc::SYS_clone3 => result,
            inlateout("rdi") args.as_ptr() => _, inlateout("rsi") 88usize => _,
            in("r12") context as *const ChildContext,
            in("r13") child_on_new_stack as unsafe extern "C" fn(*const ChildContext) -> !,
            lateout("rcx") _, lateout("r11") _,
        );
    }
    result
}

#[cfg(target_arch = "aarch64")]
unsafe fn clone_on_new_stack(args: &[u64; 11], context: &ChildContext) -> i64 {
    let result: i64;
    unsafe {
        std::arch::asm!(
            "svc #0", "cbnz x0, 2f", "mov x0, x19", "blr x20", "brk #0", "2:",
            in("x8") libc::SYS_clone3, inlateout("x0") args.as_ptr() => result,
            inlateout("x1") 88usize => _, in("x19") context as *const ChildContext,
            in("x20") child_on_new_stack as unsafe extern "C" fn(*const ChildContext) -> !,
            lateout("x30") _,
        );
    }
    result
}

fn guest_clone_and_read(flags: u64) {
    // No test-side mmap or page write: the backend owns the real RO mapping.
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_write, -900i32, 0usize, 0usize) },
        0
    );
    let mut args = [0u64; 11];
    args[0] = flags;
    args[4] = libc::SIGCHLD as u64;
    let mut stack = vec![0u128; 8192];
    if flags & libc::CLONE_VM as u64 != 0 {
        args[5] = stack.as_mut_ptr() as u64;
        args[6] = (stack.len() * 16) as u64;
    }
    let before = args;
    let page_bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let context = ChildContext {
        original: before,
        page_bytes,
    };
    let result = if flags & libc::CLONE_VM as u64 != 0 {
        unsafe { clone_on_new_stack(&args, &context) }
    } else {
        unsafe { libc::syscall(libc::SYS_clone3, args.as_ptr(), 88usize) }
    };
    assert!(
        result >= 0,
        "actual native clone3 failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        args, before,
        "original argument bytes must remain unchanged"
    );
    let page_bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let page = unsafe { std::slice::from_raw_parts(RESERVED_INPUT_BASE as *const u8, page_bytes) };
    let original = unsafe { std::slice::from_raw_parts(before.as_ptr().cast::<u8>(), 88) };
    assert_eq!(&page[..88], original);
    assert!(
        page[88..].iter().all(|byte| *byte == 0xa7),
        "native parent/copied child sees full tail B"
    );
    if result == 0 {
        unsafe { libc::_exit(0) }
    }
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(result as i32, &mut status, 0) },
        result as i32
    );
    assert_eq!(
        status, 0,
        "copied child must execute its actual page oracle"
    );
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_write, -901i32, 0usize, 0usize) },
        0
    );
}

fn run_page_control(
    fault: Fault,
    flags: u64,
) -> Result<(reverie::process::Output, PageGlobal), Error> {
    // All hooks run on the same LocalSet thread. Each native run is bounded;
    // there is no host capability skip and no failed-run-as-success shortcut.
    EVIDENCE.with(|slot| {
        *slot.borrow_mut() = Arc::new(Mutex::new(Evidence {
            config: fault,
            ..Evidence::default()
        }))
    });
    FAULT.with(|slot| *slot.borrow_mut() = None);
    crate::testing::run_tokio_test(async move {
        let tracer = crate::tracer::spawn_fn_with_config::<PageTool, _>(
            move || guest_clone_and_read(flags),
            fault,
            true,
        )
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tracer.wait_with_output(),
        )
        .await
        .expect("owned page/clone control timed out")
    })
}

#[test]
fn native_staged_clone_copies_the_complete_readback_image_before_child_start() {
    let (output, _) = run_page_control(Fault::None, 0).expect("native staged clone succeeds");
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    let log = evidence();
    let log = log.lock().unwrap();
    assert_eq!(log.tasks.len(), 2);
    assert_eq!(log.child_page_reads, 1);
    assert_eq!(log.after_clone, 1);
    assert_eq!(log.transport_failures, 0);
    assert_eq!(log.calls.len(), 2);
}

#[test]
fn native_partial_and_unknown_progress_failures_normalize_all_bytes_before_fallback() {
    for fault in [
        Fault::BeforeFirstWord,
        Fault::AfterFirstWord,
        Fault::AfterLaterWord,
        Fault::ReadbackTail,
    ] {
        let (output, _) =
            run_page_control(fault, 0).expect("normalized original-call fallback succeeds");
        assert_eq!(
            output.status,
            ExitStatus::Exited(0),
            "{fault:?}: {output:?}"
        );
        let log = evidence();
        let log = log.lock().unwrap();
        assert_eq!(log.tasks.len(), 2, "{fault:?}");
        assert_eq!(log.child_page_reads, 1, "{fault:?}");
        assert_eq!(log.after_clone, 1, "{fault:?}");
        assert_eq!(log.transport_failures, 1, "{fault:?}");
        assert_eq!(
            log.normalization_words * 8,
            log.expected.as_ref().unwrap().bytes().len()
        );
        assert_eq!(
            log.calls.len(),
            3,
            "one prefill, one failed staged call, one original call"
        );
    }
}

#[test]
fn native_failed_normalization_prevents_clone_child_and_guest_continuation() {
    let error = run_page_control(Fault::Normalization, 0)
        .err()
        .expect("failed normalization is terminal");
    assert!(
        error.to_string().contains("input-normalization"),
        "{error:#}"
    );
    let log = evidence();
    let log = log.lock().unwrap();
    assert_eq!(log.transport_failures, 2);
    assert_eq!(log.tasks.len(), 1, "no native child was registered");
    assert_eq!(log.child_page_reads, 0);
    assert_eq!(
        log.after_clone, 0,
        "guest did not reach the post-clone marker"
    );
    let control = log.control.as_ref().unwrap();
    for task in &log.tasks {
        assert_eq!(
            control.native_terminal(*task),
            Some(true),
            "fatal cleanup retained an unsettled task"
        );
    }
}

#[test]
fn native_shared_and_both_vfork_forms_observe_b_without_parent_return_repair() {
    for flags in [
        libc::CLONE_VM,
        libc::CLONE_VFORK,
        libc::CLONE_VM | libc::CLONE_VFORK,
    ] {
        let (output, _) =
            run_page_control(Fault::None, flags as u64).expect("native sharing control");
        assert_eq!(
            output.status,
            ExitStatus::Exited(0),
            "flags={flags:#x}: {output:?}"
        );
        let log = evidence();
        let log = log.lock().unwrap();
        assert_eq!(log.tasks.len(), 2);
        assert_eq!(log.child_page_reads, 1);
        assert_eq!(log.after_clone, 1);
        assert_eq!(log.transport_failures, 0);
        let control = log.control.as_ref().unwrap();
        let parent = control.registration(log.tasks[0]).unwrap();
        let child = control.registration(log.tasks[1]).unwrap();
        assert_eq!(parent.region == child.region, flags & libc::CLONE_VM != 0);
    }
}

pub(super) fn debugger_requests(
    task: &mut Stopped,
    control: &ReservedInputControl,
    identity: InputTaskId,
) {
    use tokio::sync::oneshot;

    use crate::gdbstub::Breakpoint;
    use crate::gdbstub::BreakpointType;
    use crate::gdbstub::GdbRequest;
    use crate::task::gdb_stop::GdbTracee;
    if evidence().lock().unwrap().config != Fault::Debugger {
        return;
    }
    let layout = control.layout(identity).unwrap();
    let before = read_image(task, layout).unwrap();
    let stack_address = task.getregs().unwrap().stack_ptr();
    let stack = AddrMut::<u64>::from_raw(stack_address as usize).unwrap();
    let saved: u64 = task.read_value(stack).unwrap();
    let breakpoints = Mutex::new(HashMap::new());
    let mut view = GdbTracee {
        task,
        breakpoints: &breakpoints,
        parked_registers: None,
        reserved_input: Some((control.clone(), identity)),
    };
    {
        let mut request = |make: &dyn Fn(oneshot::Sender<Result<(), TraceError>>) -> GdbRequest| {
            let (tx, mut rx) = oneshot::channel();
            view.answer(make(tx));
            evidence().lock().unwrap().debugger_requests += 1;
            rx.try_recv().expect("synchronous actual debugger reply")
        };
        let tagged = match layout.abi {
            InputAbi::X86_64 => layout.base | (1 << 57),
            InputAbi::Aarch64 => layout.base | (0xab << 56),
        };
        for address in [layout.base, tagged] {
            assert!(matches!(
                request(&|tx| GdbRequest::WriteInferiorMemory(address, 8, vec![0x33; 8], tx)),
                Err(TraceError::Errno(Errno::EPERM))
            ));
        }
        // An int3 is one byte, but the existing transport writes an entire word.
        // Even an unmapped preceding address must be refused before its read.
        for address in [layout.base - 7, layout.base, tagged] {
            assert!(matches!(
                request(&|tx| GdbRequest::SetBreakpoint(
                    Breakpoint {
                        ty: BreakpointType::Software,
                        addr: address,
                        bytecode: None
                    },
                    tx
                )),
                Err(TraceError::Errno(Errno::EPERM))
            ));
        }
        breakpoints.lock().unwrap().insert(layout.base, 0x55);
        assert!(matches!(
            request(&|tx| GdbRequest::RemoveBreakpoint(
                Breakpoint {
                    ty: BreakpointType::Software,
                    addr: layout.base,
                    bytecode: None
                },
                tx
            )),
            Err(TraceError::Errno(Errno::EPERM))
        ));
        assert_eq!(breakpoints.lock().unwrap().get(&layout.base), Some(&0x55));
        breakpoints.lock().unwrap().clear();
        // Real ordinary-memory write and breakpoint add/remove remain supported.
        request(&|tx| {
            GdbRequest::WriteInferiorMemory(
                stack_address,
                8,
                saved.wrapping_add(1).to_ne_bytes().to_vec(),
                tx,
            )
        })
        .unwrap();
        request(&|tx| {
            GdbRequest::WriteInferiorMemory(stack_address, 8, saved.to_ne_bytes().to_vec(), tx)
        })
        .unwrap();
        request(&|tx| {
            GdbRequest::SetBreakpoint(
                Breakpoint {
                    ty: BreakpointType::Software,
                    addr: stack_address,
                    bytecode: None,
                },
                tx,
            )
        })
        .unwrap();
        request(&|tx| {
            GdbRequest::RemoveBreakpoint(
                Breakpoint {
                    ty: BreakpointType::Software,
                    addr: stack_address,
                    bytecode: None,
                },
                tx,
            )
        })
        .unwrap();
    }
    assert_eq!(view.task.read_value::<_, u64>(stack).unwrap(), saved);
    assert_eq!(
        read_image(view.task, layout).unwrap(),
        before,
        "debugger force writes must leave every reserved byte unchanged"
    );
}

#[test]
fn native_debugger_requests_protect_tagged_page_and_keep_ordinary_memory_working() {
    let (output, _) =
        run_page_control(Fault::Debugger, 0).expect("debugger guarded actual transport");
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(evidence().lock().unwrap().debugger_requests, 10);
}

#[derive(Default)]
struct ExitFactsTool;

#[reverie::tool]
impl Tool for ExitFactsTool {
    type GlobalState = PageGlobal;
    type ThreadState = ();
    fn enforces_serialized_execution(_: &Fault) -> bool {
        true
    }
    fn reserved_input_requirement(_: &Fault) -> Option<ReservedInputRequirement> {
        Some(ReservedInputRequirement::sealed_page())
    }
    fn subscriptions(_: &Fault) -> Subscription {
        [Sysno::write, Sysno::clone, Sysno::clone3, Sysno::execve]
            .into_iter()
            .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let (number, args) = call.into_parts();
        let control = guest.reserved_input_control().unwrap();
        let owner = guest.reserved_input_task().unwrap();
        if number == Sysno::execve {
            let old = evidence().lock().unwrap().tasks.clone();
            for task in &old {
                control.freeze_tasks(&[*task]).unwrap();
            }
            evidence().lock().unwrap().exec_old_tasks = old;
            guest.tail_inject(call).await;
        }
        if matches!(number, Sysno::clone | Sysno::clone3) {
            control.grant(owner, InputGrantKind::Ordinary).unwrap();
            let mut desc = description(call, None, true);
            desc.expected_sharing = InputExpectedSharing {
                may_create: true,
                ..InputExpectedSharing::default()
            };
            if number == Sysno::clone {
                desc.input = InputCallInput::Registers;
            }
            let receipt = control.prepare_observed_injection(owner, 11, desc).unwrap();
            return Ok(guest
                .inject_observed(call, receipt)
                .await
                .map_err(anyhow::Error::new)??);
        }
        if number == Sysno::write && args.arg0 as i32 == -903 {
            assert!(
                !control.observe_exit_effects(owner).unwrap(),
                "a live retained owner is not effects-complete"
            );
            return Ok(0);
        }
        if number == Sysno::write && args.arg0 as i32 == -902 {
            // The fixture's surviving thread has already read Z from its
            // leader. This observation asserts that existing boundary; it
            // never decides when a staged operation may run.
            let root = evidence().lock().unwrap().tasks[0];
            assert_ne!(owner, root);
            assert_eq!(
                control.native_terminal(root),
                Some(false),
                "leader still has a live sibling, so final status must not be fabricated"
            );
            let fence = control.freeze_tasks(&[root]).unwrap();
            assert!(
                control.settle_fenced_tasks(&[root]).is_err(),
                "logical intent alone cannot settle native effects"
            );
            assert!(control.observe_exit_effects(root).unwrap());
            control.settle_fenced_tasks(&[root]).unwrap();
            assert!(
                control.cohort_members(&fence).is_err(),
                "the complete exact fence should settle"
            );
            evidence().lock().unwrap().after_clone += 1;
            return Ok(0);
        }
        Ok(guest.inject(call).await?)
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let control = guest.reserved_input_control().unwrap();
        let replacement = guest.reserved_input_task().unwrap();
        let old = evidence().lock().unwrap().exec_old_tasks.clone();
        assert!(!old.is_empty());
        assert!(!old.contains(&replacement));
        for task in &old {
            assert!(control.observe_exit_effects(*task).unwrap());
        }
        control.settle_fenced_tasks(&old).unwrap();
        control
            .grant(replacement, InputGrantKind::Ordinary)
            .unwrap();
        let layout = control
            .layout(replacement)
            .expect("new target image has independent authenticated setup");
        let mut actual = vec![0; layout.page_bytes];
        guest.memory().read_exact(
            Addr::<u8>::from_raw(layout.base as usize).unwrap(),
            &mut actual,
        )?;
        assert!(
            actual.iter().all(|byte| *byte == 0),
            "new image starts with a complete new page"
        );
        evidence().lock().unwrap().exec_callbacks += 1;
        Ok(())
    }
}

#[test]
fn native_zombie_leader_effects_settle_before_live_sibling_and_final_reap() {
    EVIDENCE.with(|slot| *slot.borrow_mut() = Arc::default());
    let (output, _) = crate::testing::run_tokio_test(async {
        let tracer = crate::tracer::spawn_fn_with_config::<ExitFactsTool, _>(
            || {
                let leader = unsafe { libc::getpid() };
                assert_eq!(
                    unsafe { libc::syscall(libc::SYS_write, -903i32, 0usize, 0usize) },
                    0
                );
                std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    loop {
                        let stat = std::fs::read_to_string(format!("/proc/{leader}/stat")).unwrap();
                        let state = stat
                            .rsplit_once(')')
                            .unwrap()
                            .1
                            .split_whitespace()
                            .next()
                            .unwrap();
                        if state == "Z" {
                            break;
                        }
                        assert!(
                            std::time::Instant::now() < deadline,
                            "leader never reached its actual exit-effects boundary"
                        );
                        std::thread::yield_now();
                    }
                    assert_eq!(
                        unsafe { libc::syscall(libc::SYS_write, -902i32, 0usize, 0usize) },
                        0
                    );
                });
                unsafe {
                    libc::syscall(libc::SYS_exit, 0);
                    libc::_exit(99);
                }
            },
            Fault::None,
            true,
        )
        .await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tracer.wait_with_output(),
        )
        .await
        .expect("zombie-leader control timed out")
    })
    .expect("native leader/sibling control");
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(evidence().lock().unwrap().after_clone, 1);
}

#[test]
fn native_decoder_retains_child_and_image_when_the_injection_future_is_cancelled() {
    for flags in [0, libc::CLONE_VM | libc::CLONE_VFORK] {
        EVIDENCE.with(|slot| *slot.borrow_mut() = Arc::default());
        FAULT.with(|slot| *slot.borrow_mut() = None);
        let pause = Arc::new(crate::task::FatalForkPause::default());
        crate::task::FATAL_FORK_PAUSE.with(|slot| *slot.borrow_mut() = Some(pause.clone()));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                crate::task::FATAL_FORK_PAUSE.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        crate::testing::run_tokio_test(async {
            let tracer = crate::tracer::spawn_fn_with_config::<PageTool, _>(
                move || guest_clone_and_read(flags as u64),
                Fault::None,
                true,
            )
            .await
            .unwrap();
            let termination = tracer.termination_handle().unwrap();
            let cancel = async {
                loop {
                    let notified = pause.ready.notified();
                    if pause.child.lock().unwrap().is_some() {
                        break;
                    }
                    notified.await;
                }
                let (pid, terminal) = {
                    let slot = pause.child.lock().unwrap();
                    let child = slot.as_ref().unwrap();
                    (child.pid(), child.terminal_cleanup())
                };
                let (control, image, id) = {
                    let log = evidence();
                    let log = log.lock().unwrap();
                    (
                        log.control.clone().unwrap(),
                        log.expected.clone().unwrap(),
                        *log.prepared.last().unwrap(),
                    )
                };
                let child = control
                    .task_identity(pid.as_raw())
                    .expect("decoder retained exact native child before Tool publication");
                let observed = control.injection_observation(id).unwrap();
                assert_eq!(observed.state, PhysicalInjectionState::RetainedBirth(child));
                assert_eq!(observed.verified_image.as_ref(), Some(&image));
                let mut bytes = vec![0u8; image.bytes().len()];
                let local = libc::iovec {
                    iov_base: bytes.as_mut_ptr().cast(),
                    iov_len: bytes.len(),
                };
                let remote = libc::iovec {
                    iov_base: image.layout().base as *mut libc::c_void,
                    iov_len: bytes.len(),
                };
                assert_eq!(
                    unsafe { libc::process_vm_readv(pid.as_raw(), &local, 1, &remote, 1, 0) },
                    bytes.len() as isize
                );
                assert_eq!(
                    bytes,
                    image.bytes(),
                    "actual decoder-retained child already holds complete B"
                );
                assert!(
                    termination.terminate(anyhow::anyhow!("fixture-cancel-after-retention").into())
                );
                (control, child, terminal)
            };
            let (result, (control, child, terminal)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(tracer.wait_with_output(), cancel)
                })
                .await
                .expect("cancelled native child was not settled");
            let error = result
                .err()
                .expect("supervisor cancellation must remain a failure");
            assert!(
                error.to_string().contains("fixture-cancel-after-retention"),
                "{error:#}"
            );
            assert_eq!(control.native_terminal(child), Some(true));
            assert!(terminal.wait(std::time::Duration::ZERO));
            assert_eq!(
                terminal.observed_exit_status().unwrap(),
                Some(ExitStatus::Signaled(Signal::SIGKILL, false))
            );
            let log = evidence();
            let log = log.lock().unwrap();
            assert_eq!(
                log.child_page_reads, 0,
                "child Tool start was never entered"
            );
            assert_eq!(log.after_clone, 0);
            assert_eq!(
                log.tasks.len(),
                1,
                "native retention is distinct from ordinary Tool registration"
            );
            assert!(matches!(
                control
                    .injection_observation(*log.prepared.last().unwrap())
                    .unwrap()
                    .state,
                PhysicalInjectionState::RetainedBirth(_)
            ));
        });
    }
}

fn exec_true() -> ! {
    let argv = [c"true".as_ptr(), std::ptr::null()];
    let env = [std::ptr::null::<libc::c_char>()];
    unsafe {
        libc::execve(c"/bin/true".as_ptr(), argv.as_ptr(), env.as_ptr());
        libc::_exit(98);
    }
}

#[test]
fn native_exec_and_nonleader_exec_keep_old_fences_separate_from_new_page_owner() {
    for nonleader in [false, true] {
        EVIDENCE.with(|slot| *slot.borrow_mut() = Arc::default());
        let (output, _) = crate::testing::run_tokio_test(async move {
            let tracer = crate::tracer::spawn_fn_with_config::<ExitFactsTool, _>(
                move || {
                    if nonleader {
                        std::thread::spawn(|| exec_true()).join().unwrap();
                        panic!("nonleader exec returned");
                    } else {
                        exec_true();
                    }
                },
                Fault::None,
                true,
            )
            .await?;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tracer.wait_with_output(),
            )
            .await
            .expect("exec owner transfer timed out")
        })
        .expect("native successful exec control");
        assert_eq!(
            output.status,
            ExitStatus::Exited(0),
            "nonleader={nonleader}: {output:?}"
        );
        let log = evidence();
        let log = log.lock().unwrap();
        assert_eq!(log.exec_callbacks, 1);
        assert_eq!(log.exec_old_tasks.len(), if nonleader { 2 } else { 1 });
        assert_eq!(log.tasks.len(), if nonleader { 3 } else { 2 });
        let control = log.control.as_ref().unwrap();
        let replacement = *log.tasks.last().unwrap();
        let current = control.registration(replacement).unwrap();
        assert_eq!(current.tool_tid, Some(current.native_tid));
        assert_eq!(current.tool_pid, Some(current.native_pid));
        assert_eq!(control.native_terminal(replacement), Some(true));
        for old in &log.exec_old_tasks {
            assert_ne!(control.registration(*old).unwrap().region, current.region);
            assert!(control.observe_exit_effects(*old).unwrap());
        }
    }
}

#[test]
fn native_final_observation_sees_immutable_future_b_while_the_real_page_is_still_a() {
    let (output, _) = run_page_control(Fault::FutureView, 0).unwrap();
    assert!(output.status.success());
    let state = evidence();
    let state = state.lock().unwrap();
    assert_eq!(
        state.before_fill.len(),
        1,
        "one final observer, never a callback after fill"
    );
    let (actual, future) = &state.before_fill[0];
    assert!(actual.iter().all(|byte| *byte == 0), "initial real page A");
    assert_ne!(
        actual.as_slice(),
        future.bytes(),
        "future clone input B is distinct"
    );
    assert_eq!(actual.len(), future.layout().page_bytes);
    assert_eq!(state.expected.as_ref().unwrap(), future);
    assert_eq!(
        state.child_page_reads, 1,
        "the copied child subsequently saw complete B"
    );
}
