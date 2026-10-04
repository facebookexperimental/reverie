/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Exact clocks through the production CPL3 SYSCALL transport. These tests
//! require KVM and the raw PMU event; unavailable hardware is not a pass.

#![cfg(target_arch = "x86_64")]

use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_kvm::CounterTool;
use reverie_kvm::KvmBackend;

const MEMORY: usize = 16 * 1024 * 1024;

fn bounded(test: &str) -> bool {
    if std::env::var_os("REVERIE_KVM_CLOCK_TEST_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "40s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("REVERIE_KVM_CLOCK_TEST_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{test}: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

struct Program {
    directory: PathBuf,
    executable: PathBuf,
    bytes: Vec<u8>,
}

impl Program {
    fn new(body: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-kvm-clock-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join("guest.S");
        let executable = directory.join("guest");
        std::fs::write(&source, format!(".global _start\n.text\n_start:\n{body}\n")).unwrap();
        let output = std::process::Command::new("timeout")
            .args([
                "--kill-after=2s",
                "10s",
                "/usr/bin/gcc",
                "-nostdlib",
                "-static",
                "-Wl,--build-id=none",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&executable).unwrap();
        Self {
            directory,
            executable,
            bytes,
        }
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn branches(iterations: u32) -> String {
    // Exactly three conditional branches per iteration: one taken JZ, one
    // not-taken JNZ, and the counted loop branch (including its final exit).
    format!(
        "mov ${iterations}, %ecx\n1: xor %eax,%eax\njz 2f\nud2\n2: jnz 3f\n3: dec %ecx\njnz 1b\n"
    )
}

const GETPID: &str = "mov $39,%eax\nsyscall\n";
const EXIT: &str = "xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n";

#[derive(Default)]
struct ClockLog(Mutex<Vec<(i32, u8, u64, i32)>>);

#[reverie::global_tool]
impl GlobalTool for ClockLog {
    type Config = bool;
    type Request = (i32, u8, u64, i32);
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, event: Self::Request) {
        self.0.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct ClockTool;

fn host_tid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

async fn yield_once() {
    let mut first = true;
    futures::future::poll_fn(|cx| {
        if std::mem::take(&mut first) {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
}

#[reverie::tool]
impl Tool for ClockTool {
    type GlobalState = ClockLog;
    type ThreadState = ();

    fn subscriptions(_config: &bool) -> Subscription {
        Subscription::all()
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let value = guest.read_clock()?;
        guest
            .send_rpc((guest.tid().as_raw(), 0, value, host_tid()))
            .await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let value = guest
            .read_clock()
            .expect("post-exec clock must remain available");
        guest
            .send_rpc((guest.tid().as_raw(), 2, value, host_tid()))
            .await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if syscall.number() == Sysno::getpid {
            let before = guest.read_clock()?;
            for i in 0..10_000 {
                std::hint::black_box(i);
            }
            yield_once().await;
            if *guest.config() {
                // A distinct vCPU runs on this same host task while the outer
                // guest is stopped. Leaving its counter enabled counts these
                // branches incorrectly despite exclude_host=1.
                let program = Program::new(&(branches(19) + GETPID + EXIT));
                let mut nested = KvmBackend::new(MEMORY).unwrap();
                nested
                    .install_static_elf(&program.bytes, "nested-clock")
                    .unwrap();
                let (_, code, _, _) = nested
                    .run_static_elf_with_tool::<CounterTool>((), true)
                    .await
                    .unwrap();
                assert_eq!(code, 0);
            }
            assert_eq!(
                guest.read_clock()?,
                before,
                "host work, await or another vCPU changed the stopped clock"
            );
            guest
                .send_rpc((guest.tid().as_raw(), 1, before, host_tid()))
                .await;
        }
        guest.tail_inject(syscall).await
    }
}

fn values(log: &ClockLog) -> Vec<u64> {
    log.0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|&(_, kind, count, _)| (kind == 1).then_some(count))
        .collect()
}

#[test]
fn read_clock_counts_userspace_and_excludes_callbacks_and_other_vcpus() {
    if bounded("read_clock_counts_userspace_and_excludes_callbacks_and_other_vcpus") {
        return;
    }
    let body = branches(100_000)
        + GETPID
        + ".rept 1024\ncall 4f\njmp 5f\n4: ret\n5:\n.endr\n"
        + GETPID
        + &branches(17)
        + GETPID
        + EXIT;
    let program = Program::new(&body);
    // Each new initial lifetime uses a fresh backend. Reinstallation after
    // execution has a separate explicit-refusal test below.
    for iteration in 0..3 {
        let mut backend = KvmBackend::new(MEMORY).unwrap();
        backend.install_static_elf(&program.bytes, "clock").unwrap();
        let (log, code, out, err) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<ClockTool>(true, true))
                .unwrap_or_else(|error| panic!("initial image iteration {iteration}: {error}"));
        assert_eq!((code, out, err), (0, vec![], vec![]));
        assert_eq!(values(&log), [300_000, 300_000, 300_051]);
        assert!(
            log.0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.1 == 0 || e.1 == 2)
                .all(|e| e.2 == 0)
        );
    }
}

#[test]
fn read_clock_preserves_values_above_u32() {
    if bounded("read_clock_preserves_values_above_u32") {
        return;
    }
    let program = Program::new(&(branches(1_431_655_770) + GETPID + &branches(17) + GETPID + EXIT));
    let mut backend = KvmBackend::new(MEMORY).unwrap();
    backend
        .install_static_elf(&program.bytes, "wide-clock")
        .unwrap();
    let (log, code, _, _) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<ClockTool>(false, true))
            .unwrap();
    assert_eq!(code, 0);
    assert_eq!(values(&log), [4_294_967_310, 4_294_967_361]);
}

#[test]
fn read_clock_follows_a_guest_between_host_threads() {
    if bounded("read_clock_follows_a_guest_between_host_threads") {
        return;
    }
    let program = Program::new(&(branches(21) + GETPID + &branches(17) + GETPID + EXIT));
    let mut backend = KvmBackend::new(MEMORY).unwrap();
    backend
        .install_static_elf(&program.bytes, "migrating-clock")
        .unwrap();
    let future = Box::pin(backend.run_static_elf_with_tool::<ClockTool>(false, true));
    let (log, code, _, _) = std::thread::scope(|scope| {
        let mut future = scope
            .spawn(move || {
                let mut future = future;
                let mut cx = Context::from_waker(futures::task::noop_waker_ref());
                assert!(future.as_mut().poll(&mut cx).is_pending());
                future
            })
            .join()
            .unwrap();
        scope
            .spawn(move || futures::executor::block_on(&mut future))
            .join()
            .unwrap()
            .unwrap()
    });
    assert_eq!(code, 0);
    assert_eq!(values(&log), [63, 114]);
    let events = log.0.lock().unwrap();
    let first = events.iter().find(|e| e.1 == 0).unwrap().3;
    let after_await = events.iter().find(|e| e.1 == 1).unwrap().3;
    assert_ne!(first, after_await, "test must really change Linux TIDs");
}

#[test]
fn read_clock_starts_fork_vfork_and_thread_children_at_zero() {
    if bounded("read_clock_starts_fork_vfork_and_thread_children_at_zero") {
        return;
    }
    for kind in ["fork", "vfork", "thread"] {
        let create = match kind {
            "fork" => "mov $57,%eax\nsyscall\n",
            "vfork" => "mov $58,%eax\nsyscall\n",
            "thread" => {
                "mov $0x50f00,%edi\nlea child_stack+4096(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\nxor %r8d,%r8d\nmov $56,%eax\nsyscall\n"
            }
            _ => unreachable!(),
        };
        // A parent exit can cancel a thread before its first guest instruction.
        // Wait for an explicit child write so this test measures both clocks.
        let body = String::from("lea fds(%rip),%rdi\nxor %esi,%esi\nmov $293,%eax\nsyscall\n")
            + &branches(11)
            + GETPID
            + create
            + "test %rax,%rax\njz child\n"
            + &branches(17)
            + GETPID
            + "mov fds(%rip),%edi\nlea done(%rip),%rsi\nmov $1,%edx\nxor %eax,%eax\nsyscall\ncmp $1,%rax\njne failed\n"
            + GETPID
            + EXIT
            + "child:\n"
            + &branches(7)
            + GETPID
            + "mov fds+4(%rip),%edi\nlea done(%rip),%rsi\nmov $1,%edx\nmov $1,%eax\nsyscall\ncmp $1,%rax\njne failed\n"
            + EXIT
            + "failed: mov $9,%edi\nmov $60,%eax\nsyscall\nud2\n.data\nfds: .long 0,0\ndone: .byte 88\n.bss\n.balign 16\nchild_stack: .skip 4096\n";
        let program = Program::new(&body);
        let mut backend = KvmBackend::new(MEMORY).unwrap();
        backend
            .install_static_elf(&program.bytes, "family-clock")
            .unwrap();
        let (log, code, _, _) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<ClockTool>(false, true))
                .unwrap_or_else(|e| panic!("{kind}: {e}"));
        assert_eq!(code, 0, "{kind}");
        let events = log.0.lock().unwrap();
        let starts: Vec<_> = events.iter().filter(|e| e.1 == 0).collect();
        assert_eq!(starts.len(), 2, "{kind}: {events:?}");
        assert!(starts.iter().all(|e| e.2 == 0), "{kind}: {events:?}");
        let parent = starts[0].0;
        let child = starts[1].0;
        assert_ne!(parent, child);
        let read = |tid| {
            events
                .iter()
                .filter_map(|e| (e.0 == tid && e.1 == 1).then_some(e.2))
                .collect::<Vec<_>>()
        };
        assert_eq!(read(parent), [33, 85, 86], "{kind}: {events:?}");
        assert_eq!(read(child), [22], "{kind}: {events:?}");
    }
}

#[test]
fn read_clock_survives_successful_and_failed_exec() {
    if bounded("read_clock_survives_successful_and_failed_exec") {
        return;
    }
    let second = Program::new(&(branches(17) + GETPID + EXIT));
    let body = branches(11)
        + GETPID
        + "lea missing(%rip),%rdi\nxor %esi,%esi\nxor %edx,%edx\nmov $59,%eax\nsyscall\n"
        + GETPID
        + "lea path(%rip),%rdi\nlea argv(%rip),%rsi\nxor %edx,%edx\nmov $59,%eax\nsyscall\nud2\n.data\nmissing: .asciz \"/nonexistent-kvm-clock-exec\"\n"
        + &format!(
            "path: .asciz \"{}\"\n.balign 8\nargv: .quad path,0\n",
            second.executable.display()
        );
    let first = Program::new(&body);
    let mut backend = KvmBackend::new(MEMORY).unwrap();
    backend
        .install_static_elf(&first.bytes, "exec-clock")
        .unwrap();
    let (log, code, _, _) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<ClockTool>(false, true))
            .unwrap();
    assert_eq!(code, 0);
    assert_eq!(values(&log), [33, 33, 84]);
    let events = log.0.lock().unwrap();
    let exec_clocks: Vec<_> = events
        .iter()
        .filter_map(|e| (e.1 == 2).then_some(e.2))
        .collect();
    assert_eq!(exec_clocks, [0, 33]);
}

#[test]
fn initial_elf_reinstallation_is_refused_before_modifying_the_image() {
    if bounded("initial_elf_reinstallation_is_refused_before_modifying_the_image") {
        return;
    }
    let program = Program::new(&(branches(11) + GETPID + EXIT));
    let entry = goblin::elf::Elf::parse(&program.bytes).unwrap().entry;
    let replacement = Program::new(&(branches(17) + GETPID + EXIT));
    for tracked in [false, true] {
        let mut backend = KvmBackend::new(MEMORY).unwrap();
        backend
            .install_static_elf(&program.bytes, "initial-clock")
            .unwrap();
        if tracked {
            let (log, code, _, _) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<ClockTool>(false, true),
            )
            .unwrap();
            assert_eq!(code, 0);
            assert_eq!(values(&log), [33]);
        } else {
            assert_eq!(backend.run_static_elf_captured().unwrap().0, 0);
        }
        let mut before = [0; 64];
        backend.memory().unwrap().read(entry, &mut before).unwrap();
        assert!(matches!(
            backend.install_static_elf(&replacement.bytes, "replacement-clock"),
            Err(reverie_kvm::Error::InitialElfReinstallationUnsupported)
        ));
        let file = std::fs::File::open(&replacement.executable).unwrap();
        assert!(matches!(
            backend.install_static_elf_file_with_context(
                file,
                &["replacement-clock"],
                &[],
                &replacement.directory
            ),
            Err(reverie_kvm::Error::InitialElfReinstallationUnsupported)
        ));
        let mut after = [0; 64];
        backend.memory().unwrap().read(entry, &mut after).unwrap();
        assert_eq!(after, before);
    }
}

fn kernel_branch_program() -> KvmBackend {
    let mut backend = KvmBackend::new(0x1_0000).unwrap();
    backend
        .install_syscall(
            0x2000,
            0x4000,
            reverie_kvm::SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
        )
        .unwrap();
    // Real-mode CPL0: mov si,1000; dec si; jnz dec; jmp installed transport.
    // Unlike the straight-line syscall parking code, this executes exactly
    // 1000 conditional branches and discriminates the kernel exclusion bit.
    backend
        .install_real_mode_program(
            0x1000,
            &[0xbe, 0xe8, 0x03, 0x4e, 0x75, 0xfd, 0xe9, 0xf7, 0x0f],
        )
        .unwrap();
    backend
}

#[test]
fn read_clock_excludes_actual_guest_kernel_branches() {
    if bounded("read_clock_excludes_actual_guest_kernel_branches") {
        return;
    }
    let mut backend = kernel_branch_program();
    let log = futures::executor::block_on(backend.run_with_tool::<ClockTool, _>(
        false,
        |_request: &reverie_kvm::SyscallRequest, _memory: &reverie_kvm::GuestMemory| 0,
    ))
    .unwrap();
    assert_eq!(values(&log), [0]);
}

#[test]
fn read_clock_refuses_activation_after_untracked_execution() {
    if bounded("read_clock_refuses_activation_after_untracked_execution") {
        return;
    }
    let mut backend = kernel_branch_program();
    backend.run(|_, _| 0).unwrap();
    let result = futures::executor::block_on(backend.run_with_tool::<ClockTool, _>(
        false,
        |_request: &reverie_kvm::SyscallRequest, _memory: &reverie_kvm::GuestMemory| 0,
    ));
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("late activation cannot account for past execution"),
    };
    assert!(
        error
            .to_string()
            .contains("after untracked guest execution")
    );
}
