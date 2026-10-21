/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![cfg(target_arch = "x86_64")]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use kvm_ioctls::Kvm;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tool;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie_kvm::KvmBackend;
use reverie_kvm::SyscallInfo;
use reverie_kvm::SyscallRequest;
use reverie_kvm::Sysno;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;
const MESSAGE_ADDRESS: u64 = 0x3000;
const CPUID_RESULT_ADDRESS: u16 = 0x4000;

fn kvm_is_unavailable(error: &kvm_ioctls::Error) -> bool {
    matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM)
}

fn kvm_available(test: &str) -> bool {
    match Kvm::new() {
        Ok(_) => true,
        Err(error) if kvm_is_unavailable(&error) => {
            if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                panic!("{test} requires usable /dev/kvm: {error}");
            }
            eprintln!("skipping {test}: cannot open /dev/kvm: {error}");
            false
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }
}

#[test]
fn identifies_unavailable_kvm_errors() {
    for errno in [libc::ENOENT, libc::EACCES, libc::EPERM] {
        let error = kvm_ioctls::Error::new(errno);
        assert!(kvm_is_unavailable(&error));
    }

    let error = kvm_ioctls::Error::new(libc::EINVAL);
    assert!(!kvm_is_unavailable(&error));
}

#[test]
fn guest_write_syscall_is_intercepted_via_vmcall() {
    if !kvm_available("guest_write_syscall_is_intercepted_via_vmcall") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
        .unwrap()
        .write(MESSAGE_ADDRESS, b"hello")
        .unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_write as u64, [1, MESSAGE_ADDRESS, 5, 0, 0, 0]),
        )
        .unwrap();

    let mut intercepted = None;
    backend
        .run(|syscall, memory| {
            let (number, args) = syscall.into_parts();
            let mut message = vec![0; args.arg2];
            memory.read(args.arg1 as u64, &mut message).unwrap();
            intercepted = Some((number, args.arg0, message));
            args.arg2 as i64
        })
        .unwrap();

    assert_eq!(intercepted, Some((Sysno::write, 1, b"hello".to_vec())));
}

#[test]
fn guest_program_routes_required_syscalls_via_vmcall() {
    if !kvm_available("guest_program_routes_required_syscalls_via_vmcall") {
        return;
    }

    let expected = [
        Sysno::read,
        Sysno::write,
        Sysno::open,
        Sysno::close,
        Sysno::mmap,
        Sysno::munmap,
        Sysno::brk,
        Sysno::ioctl,
    ];
    let requests = expected.map(|number| SyscallRequest::new(number.id() as u64, [0; 6]));

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscalls(ENTRY_POINT, FRAME_ADDRESS, &requests)
        .unwrap();

    let mut intercepted = Vec::new();
    backend
        .run(|syscall, _memory| {
            intercepted.push(syscall.number());
            0
        })
        .unwrap();

    assert_eq!(intercepted, expected);
}

#[test]
fn host_cpuid_rows_are_visible_inside_vm() {
    if !kvm_available("host_cpuid_rows_are_visible_inside_vm") {
        return;
    }

    // No Tool traps CPUID here, so the vCPU's table answers, and it holds the
    // host's rows: the backend keeps no CPUID profile of its own.
    let probes: [(u32, u32); 7] = [
        (0, 0),
        (0x8000_0000, 0),
        (0x8000_0001, 0),
        (0x8000_0002, 0),
        (0x8000_0003, 0),
        (0x8000_0004, 0),
        (0xd, 2),
    ];
    let mut program = Vec::new();
    for (index, (leaf, subleaf)) in probes.iter().enumerate() {
        append_cpuid_probe(
            &mut program,
            *leaf,
            *subleaf,
            CPUID_RESULT_ADDRESS + 16 * index as u16,
        );
    }
    let xstate_address = CPUID_RESULT_ADDRESS + 16 * probes.len() as u16;
    append_cpuid_probe(&mut program, 0xd, 0, xstate_address);
    append_cpuid_probe(&mut program, 0xd, 17, xstate_address + 16);
    append_cpuid_probe(&mut program, 0xd, 19, xstate_address + 32);
    program.push(0xf4); // hlt

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_real_mode_program(ENTRY_POINT, &program)
        .unwrap();
    backend
        .run(|_, _| panic!("CPUID program must not issue a syscall"))
        .unwrap();

    for (index, (leaf, subleaf)) in probes.iter().enumerate() {
        let host = core::arch::x86_64::__cpuid_count(*leaf, *subleaf);
        assert_eq!(
            read_cpuid_result(&backend, CPUID_RESULT_ADDRESS + 16 * index as u16),
            [host.eax, host.ebx, host.ecx, host.edx],
            "leaf {leaf:#x}, subleaf {subleaf}"
        );
    }
    // Leaf 0xd advertises only the x87, SSE and YMM components the signal
    // frames carry, and the rows of every other component are gone.
    assert_eq!(read_cpuid_result(&backend, xstate_address)[0] & !0x7, 0);
    assert_eq!(read_cpuid_result(&backend, xstate_address + 16), [0; 4]);
    assert_eq!(read_cpuid_result(&backend, xstate_address + 32), [0; 4]);
}

fn append_cpuid_probe(program: &mut Vec<u8>, leaf: u32, subleaf: u32, output: u16) {
    program.extend_from_slice(&[0x66, 0xb8]); // mov eax, leaf
    program.extend_from_slice(&leaf.to_le_bytes());
    program.extend_from_slice(&[0x66, 0xb9]); // mov ecx, subleaf
    program.extend_from_slice(&subleaf.to_le_bytes());
    program.extend_from_slice(&[0x0f, 0xa2]); // cpuid

    program.extend_from_slice(&[0x66, 0xa3]); // mov [output], eax
    program.extend_from_slice(&output.to_le_bytes());
    for (register, offset) in [(0x1e, 4), (0x0e, 8), (0x16, 12)] {
        program.extend_from_slice(&[0x66, 0x89, register]);
        program.extend_from_slice(&(output + offset).to_le_bytes());
    }
}

fn read_cpuid_result(backend: &KvmBackend, address: u16) -> [u32; 4] {
    let mut bytes = [0; 16];
    backend
        .memory()
        .unwrap()
        .read(address.into(), &mut bytes)
        .unwrap();
    std::array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

#[derive(Default)]
struct PassthroughTool;

#[reverie::tool]
impl Tool for PassthroughTool {
    type GlobalState = ();
    type ThreadState = ();
}

#[derive(Default)]
struct RecordingGlobal {
    events: AtomicUsize,
}

#[reverie::global_tool]
impl GlobalTool for RecordingGlobal {
    type Request = usize;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, event: usize) {
        self.events.fetch_or(event, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct RecordingTool;

#[reverie::tool]
impl Tool for RecordingTool {
    type GlobalState = RecordingGlobal;
    type ThreadState = usize;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let Syscall::Write(write) = syscall else {
            panic!("expected a typed write syscall, got {syscall:?}");
        };
        assert_eq!(write.fd(), 1);
        let registers = guest.regs().await;
        assert_eq!(registers.orig_rax, libc::SYS_write as u64);
        // The guest program loads the transport number and frame address with
        // two 0x66-prefixed movs (6 bytes each) before the hypercall, so rip
        // reports the transport instruction 12 bytes into the program.
        assert_eq!(registers.rip, ENTRY_POINT + 12);

        let mut message = vec![0; write.len()];
        guest.memory().read_exact(
            write.buf().expect("write buffer must be non-null"),
            &mut message,
        )?;
        assert_eq!(message, b"hello");

        *guest.thread_state_mut() += 1;
        guest.send_rpc(1).await;
        Ok(write.len() as i64)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        thread_state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(thread_state, 1);
        assert_eq!(status, ExitStatus::SUCCESS);
        global.send_rpc(2).await;
        Ok(())
    }
}

#[test]
fn guest_write_syscall_runs_shared_reverie_tool() {
    if !kvm_available("guest_write_syscall_runs_shared_reverie_tool") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
        .unwrap()
        .write(MESSAGE_ADDRESS, b"hello")
        .unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_write as u64, [1, MESSAGE_ADDRESS, 5, 0, 0, 0]),
        )
        .unwrap();

    let global = futures::executor::block_on(backend.run_with_tool::<RecordingTool, _>(
        (),
        |_: &SyscallRequest, _: &reverie_kvm::GuestMemory| {
            panic!("intercepting tool must not inject its write syscall")
        },
    ))
    .unwrap();
    assert_eq!(global.events.load(Ordering::SeqCst), 3);
}

#[test]
fn default_tool_handler_tail_injects_through_executor() {
    if !kvm_available("default_tool_handler_tail_injects_through_executor") {
        return;
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
        .unwrap()
        .write(MESSAGE_ADDRESS, b"hello")
        .unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_write as u64, [1, MESSAGE_ADDRESS, 5, 0, 0, 0]),
        )
        .unwrap();

    let observed = Arc::new(Mutex::new(None));
    let executor_observed = observed.clone();
    futures::executor::block_on(backend.run_with_tool::<PassthroughTool, _>(
        (),
        move |request: &SyscallRequest, memory: &reverie_kvm::GuestMemory| {
            let mut message = vec![0; request.args()[2] as usize];
            memory.read(request.args()[1], &mut message).unwrap();
            *executor_observed.lock().unwrap() = Some((request.number(), message));
            request.args()[2] as i64
        },
    ))
    .unwrap();

    assert_eq!(
        *observed.lock().unwrap(),
        Some((libc::SYS_write as u64, b"hello".to_vec()))
    );
}

/// How many GlobalStates the dequeue-observation fixtures initialized.
static OBSERVING_GLOBALS: AtomicUsize = AtomicUsize::new(0);

/// How many times those GlobalStates were asked to install signal control.
static OBSERVING_INSTALLS: AtomicUsize = AtomicUsize::new(0);

/// The fixtures' Config.
#[derive(Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
struct ObservingConfig {
    /// Tool::may_observe_signal_dequeues.
    may_observe: bool,
    /// Tool::requires_signal_control.
    requires_control: bool,
    /// Installation answers ToolControlled rather than Unchanged.
    claim_control: bool,
}

#[derive(Default)]
struct ObservingGlobal {
    claim_control: bool,
}

#[reverie::global_tool]
impl GlobalTool for ObservingGlobal {
    type Request = ();
    type Response = ();
    type Config = ObservingConfig;

    async fn init_global_state(config: &ObservingConfig) -> Self {
        OBSERVING_GLOBALS.fetch_add(1, Ordering::SeqCst);
        Self {
            claim_control: config.claim_control,
        }
    }

    fn install_backend_signal_control(
        &self,
        control: Option<reverie::BackendSignalControl>,
    ) -> Result<reverie::BackendSignalControlMode, reverie::Error> {
        assert!(control.is_none(), "the non-ELF loop offers no control");
        OBSERVING_INSTALLS.fetch_add(1, Ordering::SeqCst);
        Ok(if self.claim_control {
            reverie::BackendSignalControlMode::ToolControlled
        } else {
            reverie::BackendSignalControlMode::Unchanged
        })
    }

    async fn receive_rpc(&self, _from: Pid, _request: ()) {}
}

#[derive(Default)]
struct ObservingTool;

#[reverie::tool]
impl Tool for ObservingTool {
    type GlobalState = ObservingGlobal;
    type ThreadState = ();

    fn may_observe_signal_dequeues(config: &ObservingConfig) -> bool {
        config.may_observe
    }

    fn requires_signal_control(config: &ObservingConfig) -> bool {
        config.requires_control
    }
}

/// The run's result, and how many GlobalStates it initialized and asked to
/// install signal control.
fn run_observing_tool(config: ObservingConfig) -> (Result<(), reverie_kvm::Error>, usize, usize) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_syscall(
            ENTRY_POINT,
            FRAME_ADDRESS,
            SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
        )
        .unwrap();
    let globals = OBSERVING_GLOBALS.load(Ordering::SeqCst);
    let installs = OBSERVING_INSTALLS.load(Ordering::SeqCst);
    let result = futures::executor::block_on(backend.run_with_tool::<ObservingTool, _>(
        config,
        |_: &SyscallRequest, _: &reverie_kvm::GuestMemory| 7,
    ))
    .map(|_| ());
    (
        result,
        OBSERVING_GLOBALS.load(Ordering::SeqCst) - globals,
        OBSERVING_INSTALLS.load(Ordering::SeqCst) - installs,
    )
}

fn refused_with(result: &Result<(), reverie_kvm::Error>, errno: reverie::syscalls::Errno) -> bool {
    matches!(
        result,
        Err(reverie_kvm::Error::Reverie(reverie::Error::Errno(actual))) if *actual == errno
    )
}

#[test]
fn non_elf_loop_runs_observers_and_refuses_required_or_unoffered_control() {
    if !kvm_available("non_elf_loop_runs_observers_and_refuses_required_or_unoffered_control") {
        return;
    }
    let config = |may_observe, requires_control, claim_control| ObservingConfig {
        may_observe,
        requires_control,
        claim_control,
    };
    // The fixtures share counters, so one test runs every case in order.
    // A Tool whose run requires process signal control, which this loop
    // cannot offer, is refused once its GlobalState exists, so its startup
    // record is kept, and before it is asked to install a control. Admitting
    // observation as well does not change that.
    for may_observe in [false, true] {
        let (result, globals, installs) = run_observing_tool(config(may_observe, true, false));
        assert!(
            refused_with(&result, reverie::syscalls::Errno::ENOSYS),
            "{result:?}"
        );
        assert_eq!(globals, 1, "the refusal follows GlobalState");
        assert_eq!(installs, 0, "the refusal precedes installation");
    }

    // Claiming control that was never offered is refused after installation.
    let (result, globals, installs) = run_observing_tool(config(false, false, true));
    assert!(
        refused_with(&result, reverie::syscalls::Errno::EINVAL),
        "{result:?}"
    );
    assert_eq!((globals, installs), (1, 1));

    // A Tool that only admits dequeue observation, or neither observes nor
    // claims control, runs to completion as it did before the bound existed.
    for may_observe in [true, false] {
        let (result, globals, installs) = run_observing_tool(config(may_observe, false, false));
        assert!(result.is_ok(), "{result:?}");
        assert_eq!((globals, installs), (1, 1));
    }
}
