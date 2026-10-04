/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Actual KVM callbacks and driver cleanup; complementary to the Detcore RPC
// control. These stimuli do not claim to reproduce a scheduler grant race.
use super::*;

#[derive(Default)]
struct RetirementGlobal {
    control: Mutex<Option<reverie::BackendSignalControl>>,
    permit: Mutex<Option<reverie::SignalDeliveryPermit>>,
    receipts: Mutex<Vec<reverie::SignalBoundaryReceipt>>,
    removals: Mutex<Vec<reverie::SignalDequeue>>,
    exits: Mutex<Vec<(bool, ExitStatus)>>,
}
// Existing serializable sum types avoid adding a test-only crate dependency.
type RetirementRequest = std::result::Result<
    (reverie::SignalTaskIdentity, reverie::CallbackSignalSite),
    std::result::Result<reverie::SignalDequeue, (bool, ExitStatus)>,
>;
#[reverie::global_tool]
impl GlobalTool for RetirementGlobal {
    type Request = RetirementRequest;
    type Response = ();
    type Config = u8;
    fn install_backend_signal_control(
        &self,
        control: Option<reverie::BackendSignalControl>,
    ) -> Result<reverie::BackendSignalControlMode, reverie::Error> {
        *self.control.lock().unwrap() = Some(control.expect("real run capability"));
        Ok(reverie::BackendSignalControlMode::ToolControlled)
    }
    async fn receive_rpc(&self, _: Pid, request: Self::Request) {
        let (task, site) = match request {
            Ok((task, site)) => (task, site),
            Err(Ok(effect)) => {
                self.removals.lock().unwrap().push(effect);
                return;
            }
            Err(Err((process, status))) => {
                self.exits.lock().unwrap().push((process, status));
                return;
            }
        };
        let permit = reverie::SignalDeliveryPermit {
            task,
            site: Some(site),
            sequence: 7,
        };
        assert!(self.permit.lock().unwrap().is_none());
        self.control
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .process
            .reserve_delivery(permit)
            .unwrap();
        *self.permit.lock().unwrap() = Some(permit);
    }
    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<reverie::SignalDeliveryPermit>, reverie::Error> {
        Ok(self
            .permit
            .lock()
            .unwrap()
            .filter(|permit| permit.task == task))
    }
    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> Result<(), reverie::Error> {
        assert_eq!(self.permit.lock().unwrap().take(), Some(receipt.permit));
        self.receipts.lock().unwrap().push(receipt);
        Ok(())
    }
}
#[derive(Default)]
struct ParkedRetirementTool;
#[reverie::tool]
impl Tool for ParkedRetirementTool {
    type GlobalState = RetirementGlobal;
    type ThreadState = ();
    fn observe_signal_dequeues(_: &u8) -> bool {
        true
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        if call.number() == Sysno::getpid && call.into_parts().1.arg0 == 0x72657469 {
            let site = guest
                .parked_signal_site()
                .expect("real original syscall callback");
            guest
                .send_rpc(Ok((guest.signal_task_identity().unwrap(), site)))
                .await;
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
            let event = SignalEvent::new(
                libc::SIGALRM,
                info,
                SignalTarget::Process { pid: guest.pid() },
            )?;
            assert!(matches!(
                guest.queue_process_alarm_signal(event).await,
                reverie::ProcessAlarmSignalOutcome::Accepted(_)
            ));
            if *guest.config() == 0 {
                guest.retire_current_thread().await;
            }
            if *guest.config() == 2 {
                let _ = guest
                    .observe_parked_signal(site, reverie::ParkedObservationLease { nonce: 7 })
                    .await;
                panic!("nested observation resumed after retirement");
            }
            return Ok(i64::from(guest.pid().as_raw()));
        }
        guest.tail_inject(call).await
    }
    async fn handle_signal_dequeue<G: Guest<Self>>(
        &self,
        guest: &mut G,
        effect: reverie::SignalDequeue,
    ) -> Result<(), Errno> {
        assert_eq!(effect.sequence, 1);
        assert_eq!(effect.event.signal(), libc::SIGALRM);
        guest.send_rpc(Err(Ok(effect))).await;
        if *guest.config() == 3 {
            guest.retire_current_thread().await;
        }
        Ok(())
    }
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Pid,
        global: &G,
        _: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc(Err(Err((false, status)))).await;
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _: Pid,
        global: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc(Err(Err((true, status)))).await;
        Ok(())
    }
    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(event.signal(), libc::SIGALRM);
        assert!(guest.parked_signal_failure_context().is_some());
        assert_eq!(
            guest.signal_observation_lease().is_some(),
            *guest.config() == 2
        );
        guest.retire_current_thread().await
    }
}

#[test]
fn parked_retirement_consumes_original_and_structured_callbacks_with_exact_receipts() {
    const TEST: &str = "natural_retirement::parked_retirement_consumes_original_and_structured_callbacks_with_exact_receipts";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "parked-retirement",
        r#"
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
int main(void) { syscall(SYS_getpid, 0x72657469); return 87; }
"#,
    );
    for mode in [0u8, 1, 2, 3] {
        eprintln!("parked retirement real mode={mode} starting");
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &directory.0,
            )
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<ParkedRetirementTool>(mode, true),
        )
        .unwrap();
        let global = completion.global_state;
        let receipts = global.receipts.into_inner().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].permit.sequence, 7);
        assert!(global.permit.into_inner().unwrap().is_none());
        assert_eq!(
            global.removals.into_inner().unwrap().len(),
            usize::from(mode != 0)
        );
        let exits = global.exits.into_inner().unwrap();
        assert_eq!(
            exits.iter().map(|entry| entry.0).collect::<Vec<_>>(),
            vec![false, true]
        );
        if mode == 3 {
            let error = completion
                .result
                .expect_err("retirement cannot acknowledge a removal from inside its notification");
            assert!(
                matches!(error.primary(), reverie_kvm::Error::RunAborted),
                "{error:?}"
            );
            assert!(error.to_string().contains("1 removals"), "{error:?}");
            assert_eq!(receipts[0].outcome, reverie::SignalBoundaryOutcome::Failed);
        } else {
            let (status, stdout, stderr) = completion.result.unwrap();
            assert_eq!(status, 0);
            assert!(stdout.is_empty() && stderr.is_empty());
            assert_eq!(
                receipts[0].outcome,
                reverie::SignalBoundaryOutcome::Cancelled
            );
            assert_eq!(
                exits,
                vec![(false, ExitStatus::SUCCESS), (true, ExitStatus::SUCCESS)]
            );
        }
        eprintln!("parked retirement real mode={mode} checked");
    }
}

#[derive(Default)]
struct LateExitGlobal {
    exits: Mutex<Vec<(i32, bool, ExitStatus)>>,
}
#[reverie::global_tool]
impl GlobalTool for LateExitGlobal {
    type Request = (bool, ExitStatus);
    type Response = ();
    type Config = bool;
    async fn receive_rpc(&self, from: Pid, (process, status): Self::Request) {
        self.exits
            .lock()
            .unwrap()
            .push((from.as_raw(), process, status));
    }
}
struct LateExitTool {
    rendezvous: std::sync::Barrier,
    retired_observed: AtomicBool,
}
impl Default for LateExitTool {
    fn default() -> Self {
        Self {
            rendezvous: std::sync::Barrier::new(2),
            retired_observed: AtomicBool::new(false),
        }
    }
}
#[reverie::tool]
impl Tool for LateExitTool {
    type GlobalState = LateExitGlobal;
    type ThreadState = ();
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        if call.number() == Sysno::getpid && call.into_parts().1.arg0 == 0x6c617465 {
            assert_eq!(guest.pid(), guest.tid());
            let mut info = [0; reverie::SIGNAL_INFO_SIZE];
            info[..4].copy_from_slice(&libc::SIGUSR1.to_ne_bytes());
            info[8..12].copy_from_slice(&libc::SI_TKILL.to_ne_bytes());
            guest
                .defer_signal_delivery(SignalEvent::new(
                    libc::SIGUSR1,
                    info,
                    SignalTarget::Thread {
                        pid: guest.pid(),
                        tid: guest.tid(),
                    },
                )?)
                .await?;
            return Ok(i64::from(guest.pid().as_raw()));
        }
        if matches!(call, Syscall::ExitGroup(_)) && guest.pid() != guest.tid() {
            // Hold the actual winning exit-group syscall before its status is
            // installed, while the leader is inside the structured hook.
            self.rendezvous.wait();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                match guest
                    .inject(
                        reverie::syscalls::Tgkill::new()
                            .with_tgid(guest.pid().as_raw())
                            .with_tid(guest.pid().as_raw())
                            .with_sig(0),
                    )
                    .await
                {
                    Err(Errno::ESRCH) => break,
                    Ok(0) => {}
                    other => panic!("unexpected exact-leader liveness result: {other:?}"),
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "leader never retired before issuer commit"
                );
                let mut first = true;
                futures::future::poll_fn(|cx| {
                    if std::mem::take(&mut first) {
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    } else {
                        std::task::Poll::Ready(())
                    }
                })
                .await;
            }
            self.retired_observed.store(true, Ordering::SeqCst);
            if *guest.config() {
                // Errno is a guest syscall result; a fatal Tool I/O error must
                // reach RunFailure while the retired leader owns the join.
                return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
            }
        }
        guest.tail_inject(call).await
    }
    async fn handle_structured_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        event: SignalEvent,
    ) -> Result<Option<SignalEvent>, Errno> {
        assert_eq!(guest.pid(), guest.tid());
        assert_eq!(event.signal(), libc::SIGUSR1);
        self.rendezvous.wait();
        guest.retire_current_thread().await
    }
    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _: Pid,
        global: &G,
        _: (),
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        global.send_rpc((false, status)).await;
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _: Pid,
        global: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert!(self.retired_observed.load(Ordering::SeqCst));
        global.send_rpc((true, status)).await;
        Ok(())
    }
}

#[test]
fn retired_leader_joins_held_issuer_and_adopts_late_status_or_failure() {
    const TEST: &str =
        "natural_retirement::retired_leader_joins_held_issuer_and_adopts_late_status_or_failure";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "late-group-exit",
        r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
static void *issuer(void *value) { syscall(SYS_exit_group, (long)(intptr_t)value); return 0; }
int main(int argc, char **argv) {
    if (argc != 2) return 80;
    pthread_t worker;
    if (pthread_create(&worker, 0, issuer, (void *)(intptr_t)atoi(argv[1]))) return 81;
    syscall(SYS_getpid, 0x6c617465);
    return 87;
}
"#,
    );
    for (status, failure) in [(17, false), (95, false), (17, true)] {
        let argument = status.to_string();
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap(), &argument],
                &[],
                &directory.0,
            )
            .unwrap();
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<LateExitTool>(failure, true),
        )
        .unwrap();
        if failure {
            let error = completion
                .result
                .expect_err("late issuer failure cannot become a successful retired leader");
            assert!(
                matches!(
                    error.primary(),
                    reverie_kvm::Error::Reverie(reverie::Error::Io(cause))
                        if cause.raw_os_error() == Some(libc::EIO)
                ),
                "{error:?}"
            );
        } else {
            let (actual, stdout, stderr) = completion.result.unwrap();
            assert_eq!(actual, status);
            assert!(stdout.is_empty() && stderr.is_empty());
        }
        let events = completion.global_state.exits.into_inner().unwrap();
        assert_eq!(events.len(), 3, "two thread hooks and one process hook");
        assert!(!events[0].1 && !events[1].1 && events[2].1);
        assert_ne!(events[0].0, events[1].0);
        assert_eq!(events[1].0, events[2].0, "leader follows joined worker");
        if !failure {
            assert!(
                events
                    .iter()
                    .all(|event| event.2 == ExitStatus::Exited(status))
            );
        }
        eprintln!(
            "late issuer status={status} failure={failure}: real leader retirement and consuming hooks checked"
        );
    }
}
