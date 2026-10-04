/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Actual CPUID terminal transitions. These controls exercise the real
// Tool/Guest/driver and consuming hooks; they do not model Detcore's clock RPC.
use futures::channel::oneshot;

use super::*;

#[derive(Debug, Default)]
struct SiblingGates {
    entered: bool,
    leader_entry: Option<oneshot::Sender<()>>,
    worker_terminal: Option<oneshot::Sender<()>>,
    leader_exit: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Default)]
struct TerminalLog {
    events: Mutex<Vec<(u8, i32, ExitStatus)>>,
    gates: Mutex<SiblingGates>,
}

#[reverie::global_tool]
impl GlobalTool for TerminalLog {
    type Request = (u8, ExitStatus);
    type Response = ();
    type Config = u8;

    async fn receive_rpc(&self, from: Pid, (kind, status): Self::Request) {
        self.events
            .lock()
            .unwrap()
            .push((kind, from.as_raw(), status));
        match kind {
            10 => {
                assert_eq!(from.as_raw(), 2);
                let (sender, receiver) = oneshot::channel();
                {
                    let mut gates = self.gates.lock().unwrap();
                    assert!(!gates.entered);
                    gates.entered = true;
                    assert!(gates.worker_terminal.replace(sender).is_none());
                    if let Some(leader) = gates.leader_entry.take() {
                        leader.send(()).unwrap();
                    }
                }
                receiver
                    .await
                    .expect("leader must release the CPUID callback");
            }
            11 => {
                assert_eq!(from.as_raw(), 1);
                let wait = {
                    let mut gates = self.gates.lock().unwrap();
                    if gates.entered {
                        None
                    } else {
                        let (sender, receiver) = oneshot::channel();
                        assert!(gates.leader_entry.replace(sender).is_none());
                        Some(receiver)
                    }
                };
                if let Some(wait) = wait {
                    wait.await.expect("worker must enter its CPUID callback");
                }
                let (sender, receiver) = oneshot::channel();
                {
                    let mut gates = self.gates.lock().unwrap();
                    assert!(gates.leader_exit.replace(sender).is_none());
                    gates.worker_terminal.take().unwrap().send(()).unwrap();
                }
                // Do not hold a mutex across either actual RPC wait. The worker
                // must consume its exit hook before the leader's physical exit.
                receiver
                    .await
                    .expect("worker must acknowledge its consuming exit hook");
            }
            2 if from.as_raw() == 2 => {
                let sender = self.gates.lock().unwrap().leader_exit.take().unwrap();
                sender.send(()).unwrap();
            }
            _ => {}
        }
    }
}

#[derive(Debug, Default)]
struct TerminalTool {
    mode: u8,
}

#[reverie::tool]
impl Tool for TerminalTool {
    type GlobalState = TerminalLog;
    type ThreadState = bool;

    fn new(_: Pid, mode: &u8) -> Self {
        Self { mode: *mode }
    }

    fn subscriptions(mode: &u8) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.cpuid();
        if *mode == 7 {
            subscriptions.syscalls([Sysno::exit_group]);
        }
        subscriptions
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert!(!*guest.thread_state());
        *guest.thread_state_mut() = true;
        guest.send_rpc((0, ExitStatus::SUCCESS)).await;
        Ok(())
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _eax: u32,
        _ecx: u32,
    ) -> Result<reverie::CpuIdResult, Errno> {
        assert!(guest.has_cpuid_interception());
        guest.send_rpc((1, ExitStatus::SUCCESS)).await;
        let call = match self.mode {
            0 | 2 | 8 => Syscall::from_raw(Sysno::exit, SyscallArgs::new(23, 0, 0, 0, 0, 0)),
            1 | 9 => Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(29, 0, 0, 0, 0, 0)),
            3 => Syscall::from_raw(
                Sysno::uname,
                SyscallArgs::new((LOAD_ADDRESS + 0x100) as usize, 0, 0, 0, 0, 0),
            ),
            4 => Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
            5 => Syscall::from_raw(Sysno::fork, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
            6 => Syscall::from_raw(Sysno::execve, SyscallArgs::new(0, 0, 0, 0, 0, 0)),
            7 => {
                assert_eq!(guest.tid().as_raw(), 2);
                guest.send_rpc((10, ExitStatus::SUCCESS)).await;
                Syscall::from_raw(Sysno::exit, SyscallArgs::new(0, 0, 0, 0, 0, 0))
            }
            _ => panic!("unknown terminal CPUID mode"),
        };
        if matches!(self.mode, 8 | 9) {
            let result = guest.inject(call).await;
            panic!("successful terminal injection must never return to the Tool: {result:?}");
        }
        guest.tail_inject(call).await
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert_eq!(self.mode, 7);
        assert_eq!(guest.tid().as_raw(), 1);
        assert!(matches!(call, Syscall::ExitGroup(_)));
        guest.send_rpc((11, ExitStatus::SUCCESS)).await;
        guest.tail_inject(call).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Pid,
        global: &G,
        started: bool,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert!(started);
        global.send_rpc((2, status)).await;
        if self.mode == 2 {
            Err(Errno::EIO.into())
        } else {
            Ok(())
        }
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc((3, status)).await;
        Ok(())
    }
}

fn terminal_program() -> Vec<u8> {
    let mut code = vec![
        0x0f, 0xa2, // cpuid: callback must never return a value to this frame
        0x0f, 0xa2, // a resumed frame would produce a forbidden second callback
        0xb8, 0xe7, 0, 0, 0, // mov eax, SYS_exit_group
        0xbf, 77, 0, 0, 0, // mov edi, 77
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ];
    code.resize(0x100, 0);
    code.extend_from_slice(&[0x5a; 16]);
    code
}

fn run_terminal(mode: u8, code: &[u8]) -> (reverie_kvm::ToolRunCompletion<TerminalLog>, [u8; 16]) {
    let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
    backend.set_thread_ownership(ThreadOwnership::Tool);
    backend
        .install_static_elf(&static_elf(code), "/bin/CPUID-terminal")
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TerminalTool>(mode, true),
    )
    .unwrap();
    let mut marker = [0; 16];
    backend
        .memory()
        .unwrap()
        .read(LOAD_ADDRESS + 0x100, &mut marker)
        .unwrap();
    (completion, marker)
}

#[test]
fn terminal_exit_preserves_status_and_consuming_cleanup() {
    for mode in [0, 1, 2, 8, 9] {
        let (completion, marker) = run_terminal(mode, &terminal_program());
        assert_eq!(marker, [0x5a; 16]);
        let expected_status = if matches!(mode, 1 | 9) { 29 } else { 23 };
        let expected = ExitStatus::Exited(expected_status);
        assert_eq!(
            *completion.global_state.events.lock().unwrap(),
            vec![
                (0, 1, ExitStatus::SUCCESS),
                (1, 1, ExitStatus::SUCCESS),
                (2, 1, expected),
                (3, 1, expected),
            ],
            "mode={mode}",
        );
        if mode == 2 {
            let error = completion.result.unwrap_err();
            eprintln!("actual terminal exit cleanup failure: {error:?}");
            let Error::SharedFailure(cause) = error else {
                panic!("expected exactly the real shared exit-hook failure");
            };
            assert!(
                matches!(cause.as_ref(), Error::Reverie(reverie::Error::Errno(e)) if *e == Errno::EIO)
            );
        } else {
            let (status, stdout, stderr) = completion.result.unwrap();
            assert_eq!(status, expected_status);
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
        }
    }
}

#[test]
fn nonterminal_tails_refuse_before_side_effects() {
    for mode in [3, 4, 5, 6] {
        let (completion, marker) = run_terminal(mode, &terminal_program());
        assert_eq!(
            marker, [0x5a; 16],
            "refused uname must not write guest memory"
        );
        let error = completion.result.unwrap_err();
        eprintln!("actual refused CPUID tail mode={mode}: {error:?}");
        let Error::SharedFailure(cause) = error else {
            panic!("refusal must have exactly one shared cause and no hidden cleanup error");
        };
        assert!(
            matches!(cause.as_ref(), Error::Reverie(reverie::Error::Errno(e)) if *e == Errno::ENOSYS)
        );
        let events = completion.global_state.events.lock().unwrap();
        assert_eq!(
            *events,
            vec![
                (0, 1, ExitStatus::SUCCESS),
                (1, 1, ExitStatus::SUCCESS),
                (2, 1, ExitStatus::Exited(255)),
                (3, 1, ExitStatus::Exited(255)),
            ],
            "mode={mode}: no new child/image or resumed CPUID",
        );
    }
}

#[test]
fn worker_terminal_rpc_precedes_real_sibling_exit_group() {
    const STACK: u64 = LOAD_ADDRESS + 0x1900;
    let flags = libc::CLONE_VM as u64
        | libc::CLONE_FS as u64
        | libc::CLONE_FILES as u64
        | libc::CLONE_SIGHAND as u64
        | libc::CLONE_THREAD as u64
        | libc::CLONE_SYSVSEM as u64;
    let mut code = vec![
        0xb8, 0xb3, 0x01, 0, 0, // mov eax, SYS_clone3
        0x48, 0xbf, // movabs rdi, clone_args
    ];
    let args_operand = code.len();
    code.extend_from_slice(&0_u64.to_le_bytes());
    code.extend_from_slice(&[
        0xbe, 88, 0, 0, 0, 0x0f, 0x05, // mov esi, 88; syscall
        0x85, 0xc0, // test eax, eax
        0x0f, 0x84, 0, 0, 0, 0, // jz worker
        0x83, 0xf8, 0x02, // cmp eax, 2
        0x0f, 0x85, 0, 0, 0, 0, // jne failure
        0xb8, 0xe7, 0, 0, 0, 0xbf, 17, 0, 0, 0, 0x0f, 0x05, // exit_group(17)
        0x0f, 0x0b,
    ]);
    let child_jump = args_operand + 8 + 11;
    let failure_jump = child_jump + 4 + 5;
    let worker = code.len();
    code.extend_from_slice(&terminal_program()[..18]);
    let failure = code.len();
    code.extend_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 78, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b,
    ]);
    patch_stats_jump(&mut code, child_jump, worker);
    patch_stats_jump(&mut code, failure_jump, failure);
    while !code.len().is_multiple_of(8) {
        code.push(0);
    }
    let args_address = LOAD_ADDRESS + code.len() as u64;
    code[args_operand..args_operand + 8].copy_from_slice(&args_address.to_le_bytes());
    let mut args = [0_u8; 88];
    args[0..8].copy_from_slice(&flags.to_le_bytes());
    args[40..48].copy_from_slice(&STACK.to_le_bytes());
    args[48..56].copy_from_slice(&0x600_u64.to_le_bytes());
    code.extend_from_slice(&args);
    let (completion, _) = run_terminal(7, &code);
    let (status, stdout, stderr) = completion.result.unwrap();
    assert_eq!(status, 17);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    let events = completion.global_state.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|(kind, _, _)| *kind == 1)
            .copied()
            .collect::<Vec<_>>(),
        vec![(1, 2, ExitStatus::SUCCESS)]
    );
    assert_eq!(events.iter().filter(|(kind, _, _)| *kind == 0).count(), 2);
    assert_eq!(
        events
            .iter()
            .filter(|(kind, _, _)| *kind == 2)
            .copied()
            .collect::<Vec<_>>(),
        vec![(2, 2, ExitStatus::SUCCESS), (2, 1, ExitStatus::Exited(17))]
    );
    assert_eq!(
        events
            .iter()
            .filter(|(kind, _, _)| *kind == 3)
            .copied()
            .collect::<Vec<_>>(),
        vec![(3, 1, ExitStatus::Exited(17))]
    );
}
