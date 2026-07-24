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
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM vmcall test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
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
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM vmcall test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
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
fn deterministic_cpuid_policy_is_visible_inside_vm() {
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM CPUID test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut program = Vec::new();
    append_cpuid_probe(&mut program, 0, 0, CPUID_RESULT_ADDRESS);
    append_cpuid_probe(&mut program, 1, 0, CPUID_RESULT_ADDRESS + 16);
    append_cpuid_probe(&mut program, 7, 0, CPUID_RESULT_ADDRESS + 32);
    append_cpuid_probe(&mut program, 7, 1, CPUID_RESULT_ADDRESS + 48);
    append_cpuid_probe(&mut program, 0xd, 0, CPUID_RESULT_ADDRESS + 64);
    program.push(0xf4); // hlt

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .install_real_mode_program(ENTRY_POINT, &program)
        .unwrap();
    backend
        .run(|_, _| panic!("CPUID program must not issue a syscall"))
        .unwrap();

    let vendor = read_cpuid_result(&backend, CPUID_RESULT_ADDRESS);
    assert_ne!([vendor[1], vendor[2], vendor[3]], [0; 3]);

    let leaf1 = read_cpuid_result(&backend, CPUID_RESULT_ADDRESS + 16);
    assert_eq!(leaf1[2] & bit(30), 0, "RDRAND must be hidden");

    let leaf7 = read_cpuid_result(&backend, CPUID_RESULT_ADDRESS + 32);
    assert_eq!(leaf7[1] & bit(18), 0, "RDSEED must be hidden");
    assert_eq!(leaf7[1] & (bit(4) | bit(11)), 0, "TSX must be hidden");
    assert_eq!(
        leaf7[1] & (bit(16) | bit(17) | bit(21) | bit(26) | bit(27) | bit(28) | bit(30) | bit(31)),
        0,
        "AVX-512 EBX features must be hidden",
    );
    assert_eq!(
        leaf7[2] & (bit(1) | bit(6) | bit(11) | bit(12) | bit(14)),
        0,
        "AVX-512 ECX features must be hidden",
    );
    assert_eq!(
        leaf7[3] & (bit(2) | bit(3) | bit(8) | bit(23)),
        0,
        "AVX-512 EDX features must be hidden",
    );

    let leaf7_subleaf1 = read_cpuid_result(&backend, CPUID_RESULT_ADDRESS + 48);
    assert_eq!(leaf7_subleaf1[0] & bit(5), 0, "AVX512_BF16 must be hidden");

    let xstate = read_cpuid_result(&backend, CPUID_RESULT_ADDRESS + 64);
    assert_eq!(
        xstate[0] & (bit(5) | bit(6) | bit(7)),
        0,
        "AVX-512 xstate must be hidden",
    );
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
    backend.memory().read(address.into(), &mut bytes).unwrap();
    std::array::from_fn(|index| {
        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

const fn bit(index: u32) -> u32 {
    1 << index
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
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM Reverie Tool test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
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
    match Kvm::new() {
        Ok(_) => {}
        Err(error) if kvm_is_unavailable(&error) => {
            eprintln!("skipping KVM tail-injection test: cannot open /dev/kvm: {error}");
            return;
        }
        Err(error) => panic!("failed to probe /dev/kvm: {error}"),
    }

    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend
        .memory_mut()
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
