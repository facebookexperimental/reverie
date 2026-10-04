/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real group exits, descriptor EOF, and the process-retirement callback.
//! Each case runs in an exact-test subprocess so concurrent tests cannot
//! inherit the host FIFO reader or interfere with the control singleton.

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::*;

const PEERS: usize = 2;
const WRITER_MARKER: usize = 0x454f4657;
const PEER_MARKER: usize = 0x454f4650;
static CONTROL: Mutex<Option<Arc<Control>>> = Mutex::new(None);

#[derive(Debug, Default)]
struct State {
    root: Option<Pid>,
    writer: Option<SignalProcessId>,
    peers: Vec<reverie::SignalTaskIdentity>,
    permit: Option<SignalDeliveryPermit>,
    receipts: Vec<reverie::SignalBoundaryReceipt>,
    peer_hooks_entered: usize,
    peer_hooks_completed: usize,
    release_peer_hooks: bool,
    retirements: Vec<reverie::BackendProcessRetirement>,
    leader_hook_seen: bool,
    owner_hook_seen: bool,
    waiters: Vec<Waker>,
    retirement_entered: bool,
    failed: bool,
}

#[derive(Debug, Default)]
struct Control {
    state: Mutex<State>,
    witness: Mutex<Option<std::fs::File>>,
    backend: Mutex<Option<BackendSignalControl>>,
    changed: Condvar,
    fatal: bool,
    orphan: bool,
    worker_issuer: bool,
}

fn control() -> Arc<Control> {
    CONTROL.lock().unwrap().as_ref().unwrap().clone()
}

impl Control {
    fn expected_status(&self) -> ExitStatus {
        ExitStatus::from_raw(if self.fatal { libc::SIGTERM } else { 0 })
    }

    fn changed(&self) {
        let wakers = {
            let mut state = self.state.lock().unwrap();
            std::mem::take(&mut state.waiters)
        };
        self.changed.notify_all();
        for waker in wakers {
            waker.wake();
        }
    }

    async fn wait_for(&self, condition: impl Fn(&State) -> bool + Send) {
        poll_fn(|cx| {
            let mut state = self.state.lock().unwrap();
            if condition(&state) {
                Poll::Ready(())
            } else {
                state.waiters.push(cx.waker().clone());
                Poll::Pending
            }
        })
        .await
    }

    fn assert_writer_open(&self) {
        let mut byte = [0];
        let error = self
            .witness
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .read(&mut byte)
            .expect_err("the live group must still own a FIFO writer");
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[derive(Default)]
struct RetirementGlobal {
    control: Arc<Control>,
}

#[reverie::global_tool]
impl GlobalTool for RetirementGlobal {
    type Request = reverie::SignalTaskIdentity;
    type Response = ();
    type Config = ();

    async fn init_global_state(_: &()) -> Self {
        Self { control: control() }
    }

    fn install_backend_signal_control(
        &self,
        backend: Option<BackendSignalControl>,
    ) -> Result<BackendSignalControlMode, reverie::Error> {
        *self.control.backend.lock().unwrap() = Some(backend.expect("real run capability"));
        Ok(BackendSignalControlMode::ToolControlled)
    }

    async fn receive_rpc(&self, _: Pid, task: Self::Request) {
        let permit = SignalDeliveryPermit {
            task,
            site: None,
            sequence: 1,
        };
        let mut state = self.control.state.lock().unwrap();
        assert_eq!(Some(task.process), state.writer);
        assert_eq!(state.peers.len(), PEERS);
        assert_eq!(task.tid != task.process.tgid, self.control.worker_issuer);
        assert!(state.permit.is_none() && state.receipts.is_empty());
        self.control
            .backend
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .process
            .reserve_delivery(permit)
            .unwrap();
        state.permit = Some(permit);
    }

    fn report_backend_failure(&self, _: reverie::BackendFailure) {
        {
            let mut state = self.control.state.lock().unwrap();
            state.failed = true;
            state.release_peer_hooks = true;
        }
        self.control.changed();
    }

    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<SignalDeliveryPermit>, reverie::Error> {
        Ok(self
            .control
            .state
            .lock()
            .unwrap()
            .permit
            .filter(|permit| permit.task == task))
    }

    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> Result<(), reverie::Error> {
        {
            let mut state = self.control.state.lock().unwrap();
            assert_eq!(state.permit.take(), Some(receipt.permit));
            assert!(state.receipts.is_empty());
            assert_eq!(
                receipt.outcome,
                reverie::SignalBoundaryOutcome::Terminated {
                    group: true,
                    wait_status: self.control.expected_status().into_raw(),
                }
            );
            state.receipts.push(receipt);
        }
        // This receipt cancels peer callbacks. It is deliberately NOT treated
        // as proof that every peer's descriptor references have retired.
        self.control.changed();
        Ok(())
    }

    fn on_backend_process_retired(
        &self,
        event: reverie::BackendProcessRetirement,
    ) -> Result<(), reverie::Error> {
        let (receipts, entered, completed, released, duplicate, owner_seen) = {
            let mut state = self.control.state.lock().unwrap();
            if Some(event.process) != state.writer {
                return Ok(());
            }
            state.retirement_entered = true;
            (
                state.receipts.len(),
                state.peer_hooks_entered,
                state.peer_hooks_completed,
                state.release_peer_hooks,
                !state.retirements.is_empty(),
                state.leader_hook_seen || state.owner_hook_seen,
            )
        };
        // Wake the independent controller even for an early-callback mutation;
        // it can release peers and let the assertion failure complete cleanup.
        self.control.changed();
        assert_eq!(event.status, self.control.expected_status());
        assert_eq!(receipts, 1);
        assert_eq!(entered, PEERS);
        assert_eq!(
            completed, PEERS,
            "process retirement preceded physical peer joins"
        );
        assert!(released);
        assert!(!duplicate, "duplicate process retirement");
        assert!(!owner_seen);
        let mut byte = [0];
        assert_eq!(
            self.control
                .witness
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .read(&mut byte)
                .expect("all writer references must be released at retirement"),
            0,
            "the empty FIFO must report EOF"
        );
        self.control.state.lock().unwrap().retirements.push(event);
        Ok(())
    }
}

#[derive(Default)]
struct RetirementTool {
    pid: Option<Pid>,
    control: Arc<Control>,
}

#[reverie::tool]
impl Tool for RetirementTool {
    type GlobalState = RetirementGlobal;
    type ThreadState = bool;

    fn new(pid: Pid, _: &()) -> Self {
        let control = control();
        control.state.lock().unwrap().root.get_or_insert(pid);
        Self {
            pid: Some(pid),
            control,
        }
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, reverie::Error> {
        let task = guest.signal_task_identity().unwrap();
        if call.number() == Sysno::getpid {
            let marker = call.into_parts().1.arg0;
            if marker == WRITER_MARKER {
                let mut state = self.control.state.lock().unwrap();
                assert!(state.writer.replace(task.process).is_none());
                assert_eq!(task.tid, task.process.tgid);
                assert_eq!(Some(task.process.tgid) != state.root, self.control.orphan);
            } else if marker == PEER_MARKER {
                *guest.thread_state_mut() = true;
                {
                    let mut state = self.control.state.lock().unwrap();
                    assert_eq!(Some(task.process), state.writer);
                    assert_ne!(task.tid, task.process.tgid);
                    assert!(!state.peers.contains(&task));
                    state.peers.push(task);
                    assert!(state.peers.len() <= PEERS);
                }
                self.control.assert_writer_open();
                self.control.changed();
                // Like a killed Detcore RPC, this callback settles only after
                // the exact group terminal receipt makes the peer ineligible.
                // Group exit alone does not drop arbitrary Tool futures.
                self.control
                    .wait_for(|state| state.receipts.len() == 1 || state.failed)
                    .await;
                guest.cancel_current_thread().await
            }
        }
        let writer = self.control.state.lock().unwrap().writer;
        if Some(task.process) == writer
            && (call.number() == Sysno::exit_group
                || (self.control.fatal && call.number() == Sysno::tgkill))
        {
            self.control
                .wait_for(|state| state.peers.len() == PEERS)
                .await;
            // Exit admission uses the exact task generation, with no parked
            // syscall observation site, matching Detcore's exit permit.
            guest.send_rpc(task).await;
        }
        guest.tail_inject(call).await
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        _: &G,
        peer: bool,
        _: ExitStatus,
    ) -> Result<(), reverie::Error> {
        if peer {
            self.control.state.lock().unwrap().peer_hooks_entered += 1;
            self.control.changed();
            // Descriptors are already released, but the worker's consuming
            // hook keeps its physical join incomplete until the controller releases it.
            self.control
                .wait_for(|state| state.release_peer_hooks)
                .await;
            self.control.state.lock().unwrap().peer_hooks_completed += 1;
            self.control.changed();
        } else {
            let leader = {
                let mut state = self.control.state.lock().unwrap();
                if state.writer.map(|writer| writer.tgid) == Some(tid) {
                    let previous = (state.retirements.len(), state.leader_hook_seen);
                    state.leader_hook_seen = true;
                    Some(previous)
                } else {
                    None
                }
            };
            // Do not poison control state on a missing-notification mutation;
            // failure settlement must still release every cleanup gate.
            if let Some((retirements, already_seen)) = leader {
                assert_eq!(retirements, 1, "missing retirement before leader hook");
                assert!(!already_seen);
            }
        }
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(Some(pid), self.pid);
        let owner = {
            let mut state = self.control.state.lock().unwrap();
            if state.writer.map(|writer| writer.tgid) == Some(pid) {
                let previous = (
                    state.retirements.len(),
                    state.leader_hook_seen,
                    state.owner_hook_seen,
                );
                state.owner_hook_seen = true;
                Some(previous)
            } else {
                None
            }
        };
        if let Some((retirements, leader_seen, owner_seen)) = owner {
            assert_eq!(retirements, 1);
            assert!(leader_seen && !owner_seen);
            assert_eq!(status, self.control.expected_status());
        }
        Ok(())
    }
}

fn run_case(mode: &str, executable: &std::path::Path, directory: &std::path::Path) {
    let fifo = directory.join(format!("{mode}.fifo"));
    let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: name is a live nul-terminated path, and mkfifo retains no pointer.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&fifo)
        .unwrap();
    let control = Arc::new(Control {
        witness: Mutex::new(Some(reader)),
        fatal: mode.ends_with("-fatal"),
        orphan: mode.starts_with("orphan-"),
        worker_issuer: mode.contains("-worker-"),
        ..Control::default()
    });
    assert!(CONTROL.lock().unwrap().replace(control.clone()).is_none());
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    // Match Hermit's traced root and distinguish it from namespace init (1),
    // so the orphan fixture can observe a changed numeric parent identity.
    backend.set_root_pid(3).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(executable).unwrap(),
            &[executable.to_str().unwrap(), mode, fifo.to_str().unwrap()],
            &[],
            directory,
        )
        .unwrap();
    let completion = std::thread::scope(|scope| {
        let controller = scope.spawn(|| {
            let state = control.state.lock().unwrap();
            let mut state = control
                .changed
                .wait_while(state, |state| {
                    !state.failed
                        && !state.retirement_entered
                        && (state.peer_hooks_entered != PEERS || state.receipts.len() != 1)
                })
                .unwrap();
            // This is a causal gate, not a delay. The callback itself requires
            // both hook completions and EOF. There is no public notification
            // for the leader entering a synchronous host join, so an arbitrary
            // earlier placement requires measured mutation evidence as well.
            if state.failed {
                return;
            }
            let early = state.retirement_entered;
            assert_eq!(state.peer_hooks_completed, 0);
            state.release_peer_hooks = true;
            drop(state);
            control.changed();
            assert!(
                !early,
                "process retirement ran while peer consuming hooks were held"
            );
        });
        // Worker joins are synchronous. The controller must be an independent
        // host thread, not another future on this blocked executor.
        let completion = futures::executor::block_on(
            backend.run_static_elf_with_tool_completion::<RetirementTool>((), true),
        );
        controller.join().unwrap();
        completion.unwrap()
    });
    // Keep backend and the captured global alive through all assertions: their
    // Drop cleanup cannot supply the EOF that the callback was required to see.
    let (code, stdout, stderr) = completion.result.unwrap();
    assert_eq!(
        code,
        if control.fatal && !control.orphan {
            128 + libc::SIGTERM
        } else {
            0
        }
    );
    assert!(
        stderr.is_empty(),
        "{mode}: stderr={}",
        String::from_utf8_lossy(&stderr)
    );
    let class = if control.orphan {
        "direct-parent-terminal"
    } else {
        "root"
    };
    let termination = if control.fatal { "fatal" } else { "exit_group" };
    assert_eq!(
        stdout,
        format!("writer: class={class} termination={termination} peers=2\nreader: EOF class={class} termination={termination} peers=2\n").as_bytes(),
        "{mode}"
    );
    {
        let state = control.state.lock().unwrap();
        assert_eq!(state.receipts.len(), 1);
        assert!(state.permit.is_none());
        assert_eq!(state.peers.len(), PEERS);
        assert_eq!(state.peer_hooks_entered, PEERS);
        assert_eq!(state.peer_hooks_completed, PEERS);
        assert_eq!(state.retirements.len(), 1);
        assert!(state.leader_hook_seen && state.owner_hook_seen);
    }
    eprintln!(
        "group descriptor retirement: {mode}: exact receipt, joined peers, callback EOF, independent reader EOF"
    );
    drop(completion.global_state);
    drop(backend);
    CONTROL.lock().unwrap().take();
}

#[test]
fn real_group_exits_retire_descriptors_before_process_notification() {
    const TEST: &str =
        "exit_descriptor_ordering::real_group_exits_retire_descriptors_before_process_notification";
    if !kvm_available(TEST) {
        return;
    }
    if std::env::var("REVERIE_EXIT_DESCRIPTOR_CHILD").as_deref() != Ok(TEST) {
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("REVERIE_EXIT_DESCRIPTOR_CHILD", TEST)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "status={:?} stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test result: ok. 1 passed; 0 failed;"),
            "the exact subprocess must execute one assertion-bearing test"
        );
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(
        &directory.0,
        "exit-descriptor-ordering",
        include_str!("../fixtures/exit_descriptor_ordering.c"),
    );
    for mode in [
        "root-exit-group",
        "root-worker-exit-group",
        "root-fatal",
        "orphan-exit-group",
        "orphan-worker-exit-group",
        "orphan-fatal",
    ] {
        eprintln!("group descriptor retirement: {mode}: starting");
        run_case(mode, &executable, &directory.0);
    }
}
