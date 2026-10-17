/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the LICENSE file.
 */
//! The pending FS/GS base staged by `arch_prctl` during one Tool handler.
//!
//! These tests drive `KvmGuest::inject` through the real static-ELF adapter
//! and then read, through `staged_segment`, the base the vCPU loop would
//! apply when the handler returns. They pin the rule the vCPU loop relies
//! on: the last base set during a handler wins, and an exec before the
//! handler's return, injected by the handler or run right after it,
//! discards it.

use super::*;
use crate::bootstrap::SegmentBase;

const MEMORY_SIZE: usize = 16 * 1024 * 1024;
const ARCH_SET_FS: u64 = 0x1002;

/// The base the vCPU loop would apply when the handler returns, taken as
/// the loop takes it.
fn staged_segment(
    backend: &mut KvmBackend,
    _executor: &mut ElfExecutor,
) -> Option<(SegmentBase, u64)> {
    backend.take_pending_segment()
}

/// A backend with a minimal static ELF installed, and that image's executor.
fn installed() -> (KvmBackend, ElfExecutor) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).expect("segment slot tests require /dev/kvm");
    backend
        .install_static_elf(&crate::vm::minimal_test_elf(&[0xf4]), "/bin/segment-slot")
        .unwrap();
    let executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
    (backend, executor)
}

fn arch_prctl_set_fs(base: u64) -> reverie::syscalls::Syscall {
    SyscallRequest::new(libc::SYS_arch_prctl as u64, [ARCH_SET_FS, base, 0, 0, 0, 0])
        .into_syscall()
        .unwrap()
}

/// Runs `handler` against a KvmGuest built on the static-ELF adapter in a
/// lifecycle callback and returns the handler's outcome.
fn run_handler<F>(
    backend: &mut KvmBackend,
    executor: &mut ElfExecutor,
    handler: F,
) -> HandlerOutcome<std::result::Result<i64, Errno>>
where
    F: for<'g, 'k> FnOnce(
        &'g mut KvmGuest<'k, crate::StraceTool>,
    )
        -> Pin<Box<dyn Future<Output = std::result::Result<i64, Errno>> + 'g>>,
{
    let pid = Pid::from_raw(executor.task_tid());
    let memory = backend.memory.clone();
    let tool = Arc::new(crate::StraceTool);
    let global = Arc::new(crate::StraceLog::default());
    let mut state = ();
    let subscriptions = Subscription::none();
    let stack = Arc::new(AtomicBool::new(false));
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut completed = false;
    let top = backend.tool_stack_top();
    let mut adapter = StaticElfSyscallExecutor {
        backend,
        executor,
        memory: memory.clone(),
        process_context: ProcessExecutionContext::Lifecycle,
        last_result: None,
        polled_read_attempt: None,
        process_completed: &mut completed,
        callback_site: None,
        original_syscall: None,
        signal_guard: SignalGuard::Ordinary,
    };
    // No instruction executes in this initialized VM control.
    let registers = unsafe { std::mem::zeroed() };
    let mut guest = KvmGuest::new(
        pid,
        pid,
        tool.clone(),
        memory,
        &[],
        registers,
        &mut state,
        &mut adapter,
        global.as_ref(),
        Some(global.clone()),
        &(),
        &subscriptions,
        signal.clone(),
        starts.clone(),
        top,
        stack,
    );
    futures::executor::block_on(drive_handler(
        handler(&mut guest),
        signal,
        starts,
        std::future::pending(),
    ))
}

/// Two `arch_prctl(ARCH_SET_FS)` injections in one handler: the base the
/// vCPU loop applies when the handler returns is the second one.
#[test]
fn last_fs_base_set_in_a_handler_is_the_one_staged() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move {
            assert_eq!(guest.inject(arch_prctl_set_fs(0x1000)).await, Ok(0));
            guest.inject(arch_prctl_set_fs(0x2000)).await
        })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(
        matches!(staged, Some((SegmentBase::Fs, 0x2000))),
        "staged: {staged:?}"
    );
}

/// `arch_prctl(ARCH_SET_FS)` in a handler, then an exec before the base is
/// applied: no base from the old image survives the exec. The exec here runs
/// right after the handler returns, through `KvmBackend::exec_process`, the
/// function every injected exec reaches (from `complete_injection` in a
/// lifecycle callback, and through the process-action runner at a syscall
/// boundary). The next test injects the exec from the handler itself.
#[test]
fn exec_process_discards_a_staged_fs_base() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move { guest.inject(arch_prctl_set_fs(0x1000)).await })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    backend
        .exec_process(
            &mut executor,
            (std::path::Path::new("/bin/segment-slot-exec"), None),
            None,
            &crate::vm::minimal_test_elf(&[0xf4]),
            &["/bin/segment-slot-exec".to_owned()],
            &[],
        )
        .unwrap();
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(staged.is_none(), "staged: {staged:?}");
}

/// `arch_prctl(ARCH_SET_FS)` and then an `execve`, both injected by one
/// lifecycle handler. The exec completes through `complete_injection`, which
/// replaces the image with `KvmBackend::exec_process`, and no base staged for
/// the old image survives it. The exec names a real file holding the same
/// minimal image, and reuses the installed image's own initial `argv` and
/// `envp`, so every pointer it passes is on the guest's initial stack.
#[test]
fn an_exec_injected_in_the_handler_discards_the_fs_base_staged_before_it() {
    use std::os::unix::fs::PermissionsExt;
    let image = crate::vm::minimal_test_elf(&[0xf4]);
    let path = std::env::temp_dir().join(format!(
        "reverie-kvm-segment-slot-exec-{}",
        std::process::id()
    ));
    std::fs::write(&path, &image).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut backend = KvmBackend::new(MEMORY_SIZE).expect("segment slot tests require /dev/kvm");
    backend
        .install_static_elf(&image, path.to_str().unwrap())
        .unwrap();
    // The initial stack holds argc, then argv = [path, NULL], then
    // envp = [NULL].
    let stack = backend.static_elf.as_ref().unwrap().stack_pointer;
    let stack_word = |address: u64| {
        let mut bytes = [0_u8; 8];
        backend.memory.user().read(address, &mut bytes).unwrap();
        u64::from_le_bytes(bytes)
    };
    assert_eq!(stack_word(stack), 1, "fixture argc");
    let argv = stack + 8;
    let envp = stack + 24;
    let filename = stack_word(argv);
    let execve = SyscallRequest::new(libc::SYS_execve as u64, [filename, argv, envp, 0, 0, 0])
        .into_syscall()
        .unwrap();
    let mut executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
    let outcome = run_handler(&mut backend, &mut executor, move |guest| {
        Box::pin(async move {
            assert_eq!(guest.inject(arch_prctl_set_fs(0x1000)).await, Ok(0));
            guest.inject(execve).await
        })
    });
    let _ = std::fs::remove_file(&path);
    assert!(
        matches!(
            outcome,
            HandlerOutcome::TailInjected {
                image_replaced: true,
                ..
            }
        ),
        "the injected exec did not replace the image"
    );
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(staged.is_none(), "staged: {staged:?}");
}

/// Control for the test above: without the exec, the same handler leaves
/// the base staged, so the exec is what discards it.
#[test]
fn without_an_exec_the_fs_base_set_in_a_handler_stays_staged() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move { guest.inject(arch_prctl_set_fs(0x1000)).await })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(
        matches!(staged, Some((SegmentBase::Fs, 0x1000))),
        "staged: {staged:?}"
    );
}

/// A staged base from a task lifetime that ended without reaching the guest
/// (for example a startup callback that set FS and then exited before any
/// vCPU entry) does not survive a reinstallation: the new image starts with
/// an empty slot, as each new executor's slot did before E2e.
#[test]
fn reinstalling_an_image_discards_a_base_staged_for_the_old_one() {
    let (mut backend, mut executor) = installed();
    let outcome = run_handler(&mut backend, &mut executor, |guest| {
        Box::pin(async move { guest.inject(arch_prctl_set_fs(0x1000)).await })
    });
    assert!(matches!(outcome, HandlerOutcome::Returned(Ok(0))));
    // The callback's lifetime ends here without any vCPU entry, so nothing
    // applied the base. Install a new image on the same backend; its
    // executor replaces the old one below.
    backend
        .install_static_elf(
            &crate::vm::minimal_test_elf(&[0xf4]),
            "/bin/segment-slot-again",
        )
        .unwrap();
    let mut executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
    let staged = staged_segment(&mut backend, &mut executor);
    assert!(staged.is_none(), "staged: {staged:?}");
}

/// A provider that breaks the contract: it reports a segment base with a
/// failed result.
struct FailedSegment;

#[reverie::provider]
impl LinuxProvider for FailedSegment {
    type Context = GuestMemory;
    type Plan = crate::executor::StagedProcessAction;
    type Error = crate::Error;

    async fn execute(
        &mut self,
        _task: reverie::Tid,
        _: &ProviderRequest,
        _: &mut GuestMemory,
    ) -> Result<ProviderOutcome> {
        Ok(ProviderOutcome::SegmentBase {
            result: -i64::from(libc::EPERM),
            register: reverie::provider::SegmentRegister::Fs,
            base: 0x1000,
        })
    }
}

impl LinuxEmuSignalControl for FailedSegment {}

impl LinuxEmuMemoryMap for FailedSegment {}

impl GuestSyscallExecutor<crate::StraceTool> for FailedSegment {
    fn read_clock(&self) -> Result<u64> {
        panic!("the failed-segment control requested a guest clock")
    }

    fn stage_segment(&mut self, _: SegmentBase, _: u64) -> Result<()> {
        panic!("a segment base with a failed result must not be staged")
    }
}

/// A provider that reports a successful segment base through an adapter
/// that cannot apply one, which keeps `stage_segment`'s refusing default.
struct SegmentWithoutSlot;

#[reverie::provider]
impl LinuxProvider for SegmentWithoutSlot {
    type Context = GuestMemory;
    type Plan = crate::executor::StagedProcessAction;
    type Error = crate::Error;

    async fn execute(
        &mut self,
        _task: reverie::Tid,
        _: &ProviderRequest,
        _: &mut GuestMemory,
    ) -> Result<ProviderOutcome> {
        Ok(ProviderOutcome::SegmentBase {
            result: 0,
            register: reverie::provider::SegmentRegister::Fs,
            base: 0x1000,
        })
    }
}

impl LinuxEmuSignalControl for SegmentWithoutSlot {}

impl LinuxEmuMemoryMap for SegmentWithoutSlot {}

impl GuestSyscallExecutor<crate::StraceTool> for SegmentWithoutSlot {
    fn read_clock(&self) -> Result<u64> {
        panic!("the segment-without-slot control requested a guest clock")
    }
}

/// Injects one arch_prctl through a KvmGuest built on `provider` and returns
/// the handler's outcome.
fn inject_through(
    provider: &mut dyn GuestSyscallExecutor<crate::StraceTool>,
) -> HandlerOutcome<std::result::Result<i64, Errno>> {
    let tool = Arc::new(crate::StraceTool);
    let global = Arc::new(crate::StraceLog::default());
    let mut state = ();
    let subscriptions = Subscription::none();
    let signal = Arc::new(Mutex::new(None));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let mut guest = KvmGuest::<crate::StraceTool>::new(
        Pid::from_raw(1),
        Pid::from_raw(1),
        tool,
        GuestMemory::new(0, STACK_CAPACITY).unwrap(),
        &[],
        // This mock has no vCPU and never accesses registers.
        unsafe { std::mem::zeroed() },
        &mut state,
        provider,
        global.as_ref(),
        Some(global.clone()),
        &(),
        &subscriptions,
        signal.clone(),
        starts.clone(),
        crate::bootstrap::TOOL_STACK_TOP,
        Arc::new(AtomicBool::new(false)),
    );
    futures::executor::block_on(drive_handler(
        guest.inject(arch_prctl_set_fs(0x1000)),
        signal,
        starts,
        std::future::pending(),
    ))
}

/// `KvmGuest::inject` treats a `SegmentBase` outcome with a failed result as
/// a broken provider invariant: the handler ends with a run error and the
/// base is never staged.
#[test]
fn a_segment_base_with_a_failed_result_is_a_run_error() {
    match inject_through(&mut FailedSegment) {
        HandlerOutcome::RuntimeError(Error::UnexpectedVcpuExit(message)) => {
            assert!(message.contains("segment base with result"), "{message}")
        }
        _ => panic!("a SegmentBase outcome with a failed result must end the run"),
    }
}

/// An adapter that cannot apply a segment base refuses it (the default
/// `stage_segment`): the handler ends with a run error instead of dropping
/// the base.
#[test]
fn an_adapter_without_a_segment_slot_refuses_a_segment_base() {
    match inject_through(&mut SegmentWithoutSlot) {
        HandlerOutcome::RuntimeError(Error::UnexpectedVcpuExit(message)) => {
            assert!(message.contains("cannot apply a segment base"), "{message}")
        }
        _ => panic!("an adapter without a segment slot must refuse a segment base"),
    }
}

/// A base for the next tests' startup callback, inside the 16 MiB arena so
/// arch_prctl accepts it, and distinct from anything an image sets up.
const STARTUP_STALE_FS: u64 = 0x80_0000;

/// A Tool whose startup callback sets FS and then exits the guest, so the
/// run ends before any vCPU entry applies the base.
#[derive(Default)]
struct StartupFsThenExitTool;

#[reverie::tool]
impl reverie::Tool for StartupFsThenExitTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_thread_start<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> std::result::Result<(), reverie::Error> {
        assert_eq!(
            guest.inject(arch_prctl_set_fs(STARTUP_STALE_FS)).await,
            Ok(0)
        );
        guest
            .tail_inject(reverie::syscalls::ExitGroup::new().with_status(0))
            .await
    }
}

/// A Tool that observes nothing.
#[derive(Default)]
struct QuietTool;

#[reverie::tool]
impl reverie::Tool for QuietTool {
    type GlobalState = ();
    type ThreadState = ();
}

/// Codex's scenario, end to end. A first Tool run's startup callback sets FS
/// and exits before any vCPU entry. The same backend then installs a new
/// image and runs it with another Tool. The vCPU's FS base after the second
/// run must not be the first run's base: that base belonged to a task
/// lifetime that ended, as it did on the base, where it died with the first
/// run's executor.
#[test]
fn a_startup_callback_base_does_not_reach_the_next_run_on_the_same_backend() {
    // mov eax, 60; xor edi, edi; syscall
    let exit0 = [0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05];
    let mut backend = KvmBackend::new(MEMORY_SIZE).expect("segment slot tests require /dev/kvm");
    backend
        .install_static_elf(&crate::vm::minimal_test_elf(&exit0), "/bin/startup-fs")
        .unwrap();
    let first = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<StartupFsThenExitTool>((), false),
    )
    .unwrap();
    let (status, _, _) = first.result.unwrap();
    assert_eq!(status, reverie::ExitStatus::Exited(0));
    backend
        .install_static_elf(&crate::vm::minimal_test_elf(&exit0), "/bin/startup-fs-next")
        .unwrap();
    // The install's own FS base (`configure_long_mode`'s user data segment,
    // base 0). The second guest never sets FS, so the run must leave exactly
    // this base on the vCPU.
    let installed_fs = backend.vcpu.get_sregs().unwrap().fs.base;
    assert_eq!(installed_fs, 0, "the install sets a zero FS base");
    let second = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<QuietTool>((), false),
    )
    .unwrap();
    let (status, _, _) = second.result.unwrap();
    assert_eq!(status, reverie::ExitStatus::Exited(0));
    let fs = backend.vcpu.get_sregs().unwrap().fs.base;
    assert_eq!(
        fs, installed_fs,
        "the second run's vCPU FS base is not the one its install set \
         (the first run's staged base was {STARTUP_STALE_FS:#x})"
    );
}

/// A provider that breaks KVM's contract with an outcome only a host-kernel
/// provider produces: a call that a signal stopped before it ran.
struct InterruptedCall;

#[reverie::provider]
impl LinuxProvider for InterruptedCall {
    type Context = GuestMemory;
    type Plan = crate::executor::StagedProcessAction;
    type Error = crate::Error;

    async fn execute(
        &mut self,
        _task: reverie::Tid,
        _: &ProviderRequest,
        _: &mut GuestMemory,
    ) -> Result<ProviderOutcome> {
        Ok(ProviderOutcome::Interrupted)
    }
}

impl LinuxEmuSignalControl for InterruptedCall {}

impl LinuxEmuMemoryMap for InterruptedCall {}

impl GuestSyscallExecutor<crate::StraceTool> for InterruptedCall {
    fn read_clock(&self) -> Result<u64> {
        panic!("the interrupted-call control requested a guest clock")
    }
}

/// `KvmGuest::inject` treats `Interrupted` as a broken provider invariant:
/// KVM's provider runs every call itself, so the handler ends with a run
/// error rather than a fabricated `ERESTARTSYS`.
#[test]
fn an_interrupted_outcome_is_a_run_error_on_kvm() {
    match inject_through(&mut InterruptedCall) {
        HandlerOutcome::RuntimeError(Error::UnexpectedVcpuExit(message)) => {
            assert!(message.contains("interrupted call"), "{message}")
        }
        _ => panic!("an Interrupted outcome must end the run on KVM"),
    }
}
