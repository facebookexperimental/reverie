/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Real original callbacks and captured bytes; no Hermit timer/scheduler model.
use reverie::CallbackSignalSite;
use reverie::ParkedObservationLease;
use reverie::ProcessAlarmSignalOutcome;
use reverie::SignalDequeue;
use reverie::SignalObservationStop;
use reverie::syscalls::Write;

use super::*;

fn saved_write(args: [usize; 6]) -> Write {
    Write::from(SyscallArgs::new(
        args[0], args[1], args[2], args[3], args[4], args[5],
    ))
}

#[derive(Clone, Debug, PartialEq)]
enum Event {
    Query(Option<CallbackSignalSite>),
    Published,
    WriteResult(Result<i64, Errno>),
    Dequeue,
    Hook,
}
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());
fn record(event: Event) {
    EVENTS.lock().unwrap().push(event);
}

#[derive(Default, Debug)]
struct Global;
#[reverie::global_tool]
impl GlobalTool for Global {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn receive_rpc(&self, _: Pid, _: ()) {}
}
#[derive(Default)]
struct CaptureTool {
    mode: u8,
}
#[reverie::tool]
impl Tool for CaptureTool {
    type GlobalState = Global;
    type ThreadState = Option<[usize; 6]>;
    fn new(_: Pid, mode: &u8) -> Self {
        Self { mode: *mode }
    }
    fn observe_signal_dequeues(_: &u8) -> bool {
        true
    }
    fn subscriptions(_: &u8) -> Subscription {
        Subscription::all()
    }
    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _: SignalDequeue,
    ) -> Result<(), Errno> {
        let call = saved_write(guest.thread_state().expect("original write recorded"));
        assert!(guest.captured_write_signal_site(call).is_none());
        record(Event::Dequeue);
        Ok(())
    }
    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        let call = saved_write(guest.thread_state().expect("original write recorded"));
        assert!(guest.captured_write_signal_site(call).is_none());
        assert_eq!(guest.signal_observation_lease().is_some(), self.mode == 16);
        record(Event::Hook);
        Ok(Some(event))
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let (_, args) = syscall.into_parts();
        if !matches!(syscall.number(), Sysno::write | Sysno::getpid) || args.arg3 != 0x63617077 {
            guest.tail_inject(syscall).await;
        }
        assert_eq!(args.arg4, usize::from(self.mode));
        let call = Write::from(args);
        *guest.thread_state_mut() = Some([
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ]);
        if self.mode == 10 {
            assert_eq!(
                guest.inject(reverie::syscalls::Getpid::new()).await?,
                i64::from(guest.pid().as_raw())
            );
        }
        let expected = self.mode <= 3 || (11..=17).contains(&self.mode);
        let site = guest.captured_write_signal_site(call);
        assert_eq!(site.is_some(), expected, "mode {}", self.mode);
        record(Event::Query(site));
        if let Some(site) = site {
            assert_eq!(guest.parked_signal_site(), Some(site));
            // Every raw argument belongs to the original call, including the
            // three unused ABI words retained by the typed syscall wrapper.
            let raw = [
                args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
            ];
            for index in 0..6 {
                let mut wrong = raw;
                wrong[index] = wrong[index].wrapping_add(1);
                assert!(
                    guest
                        .captured_write_signal_site(Write::from(SyscallArgs::new(
                            wrong[0], wrong[1], wrong[2], wrong[3], wrong[4], wrong[5],
                        )))
                        .is_none()
                );
            }
            // The same low fd is insufficient: admission requires the exact
            // original upper bits as well as all other raw arguments.
            let mut same_fd = raw;
            same_fd[0] ^= 1_usize << 32;
            assert!(
                guest
                    .captured_write_signal_site(saved_write(same_fd))
                    .is_none()
            );
            if self.mode == 12 {
                let stack = guest.stack().await;
                assert!(guest.captured_write_signal_site(call).is_none());
                drop(stack);
            }
            // Refused queries and an ordinary metadata RPC have no effects and
            // cannot consume the original callback or change its identity.
            guest.send_rpc(()).await;
            assert_eq!(guest.captured_write_signal_site(call), Some(site));
            assert_eq!(EVENTS.lock().unwrap().len(), 1);
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
            let event = SignalEvent::new(
                libc::SIGALRM,
                info,
                SignalTarget::Process { pid: guest.pid() },
            )
            .unwrap();
            assert!(matches!(guest.queue_process_alarm_signal(event).await,
                ProcessAlarmSignalOutcome::Accepted(receipt) if receipt.blocked == (self.mode == 15)));
            record(Event::Published);
            if self.mode == 16 {
                let observation = guest
                    .observe_parked_signal(site, ParkedObservationLease { nonce: 1 })
                    .await
                    .unwrap();
                assert!(matches!(observation.stop, SignalObservationStop::Caught(_)));
                assert!(guest.captured_write_signal_site(call).is_none());
            }
        }
        let result = guest.inject(syscall).await;
        record(Event::WriteResult(result));
        assert!(
            guest.captured_write_signal_site(call).is_none(),
            "executed callback was reused"
        );
        result.map_err(Into::into)
    }
}

fn run_modes(modes: impl IntoIterator<Item = u8>) {
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "captured-write-signal",
        include_str!("../fixtures/captured_write_signal.c"),
    );
    for mode in modes {
        EVENTS.lock().unwrap().clear();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), &mode.to_string()],
                &[],
                &directory.0,
            )
            .unwrap();
        let (_, status, stdout, stderr) = futures::executor::block_on(
            backend.run_static_elf_with_tool::<CaptureTool>(mode, !matches!(mode, 4 | 19)),
        )
        .unwrap();
        let events = EVENTS.lock().unwrap().clone();
        assert_eq!(status, 0, "mode={mode} events={events:?}");
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Query(_)))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::WriteResult(_)))
                .count(),
            1
        );
        let published = mode <= 3 || (11..=17).contains(&mode);
        for kind in [Event::Published, Event::Dequeue, Event::Hook] {
            assert_eq!(
                events.iter().filter(|e| **e == kind).count(),
                usize::from(published),
                "mode={mode} {kind:?}"
            );
        }
        if published && mode != 16 {
            let write = events
                .iter()
                .position(|e| matches!(e, Event::WriteResult(_)))
                .unwrap();
            let hook = events.iter().position(|e| *e == Event::Hook).unwrap();
            assert!(write < hook, "signal hook ran before actual write result");
        }
        if matches!(mode, 17 | 19) {
            assert!(events.contains(&Event::WriteResult(Ok(3))));
        } else if mode == 18 {
            assert!(events.contains(&Event::WriteResult(Err(Errno::EBADF))));
        }
        let standard_output = matches!(mode, 0 | 2 | 10 | 11 | 12 | 15 | 16 | 17);
        if mode == 14 {
            assert_eq!(stdout.len(), 16 * 1024 * 1024 + 1);
            assert!(stdout[..stdout.len() - 1].iter().all(|byte| *byte == b'a'));
            assert_eq!(stdout.last(), Some(&b'!'));
        } else {
            let expected = if standard_output {
                if published {
                    b"abc!".as_slice()
                } else {
                    b"abc".as_slice()
                }
            } else if published {
                b"!".as_slice()
            } else {
                b"".as_slice()
            };
            assert_eq!(stdout, expected, "mode={mode}");
        }
        assert_eq!(
            stderr,
            if matches!(mode, 1 | 3) {
                b"abc".as_slice()
            } else {
                b"".as_slice()
            },
            "mode={mode}"
        );
        if matches!(mode, 5 | 7 | 8) {
            assert_eq!(std::fs::read(directory.0.join("backing")).unwrap(), b"abc");
        }
    }
}

#[test]
fn captured_write_signal_capability_routes_and_refusals() {
    if leader_self_exec_bounded(
        "captured_write_signals::captured_write_signal_capability_routes_and_refusals",
    ) {
        run_modes(0..=12);
    }
}

#[test]
fn captured_write_signal_capability_preserves_fault_and_partial_result() {
    if leader_self_exec_bounded(
        "captured_write_signals::captured_write_signal_capability_preserves_fault_and_partial_result",
    ) {
        run_modes([13, 14]);
    }
}

#[test]
fn captured_write_signal_capability_blocks_nested_and_malformed_admission() {
    if leader_self_exec_bounded(
        "captured_write_signals::captured_write_signal_capability_blocks_nested_and_malformed_admission",
    ) {
        run_modes([15, 16, 17, 18, 19]);
    }
}
