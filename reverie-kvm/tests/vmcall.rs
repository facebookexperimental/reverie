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
use reverie_kvm::SyscallRequest;

const MEMORY_SIZE: usize = 0x10_000;
const ENTRY_POINT: u64 = 0x1000;
const FRAME_ADDRESS: u64 = 0x2000;
const MESSAGE_ADDRESS: u64 = 0x3000;

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
        .run(|request, memory| {
            let mut message = vec![0; request.args()[2] as usize];
            memory.read(request.args()[1], &mut message).unwrap();
            intercepted = Some((request.number(), request.args()[0], message));
            request.args()[2] as i64
        })
        .unwrap();

    assert_eq!(
        intercepted,
        Some((libc::SYS_write as u64, 1, b"hello".to_vec()))
    );
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
        assert_eq!(registers.rip, ENTRY_POINT);

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
