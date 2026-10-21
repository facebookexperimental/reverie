use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use super::*;

#[derive(Clone, Debug)]
struct Event {
    kind: &'static str,
    pid: i32,
    value: i64,
}

#[derive(Debug, Default)]
struct State {
    events: Vec<Event>,
    parent_ready: bool,
    release_first_error: bool,
    release_child: bool,
    global_dropped: bool,
}

#[derive(Debug, Default)]
struct Control {
    state: Mutex<State>,
    changed: Condvar,
}

static CONTROL: Mutex<Option<Arc<Control>>> = Mutex::new(None);

fn control() -> Arc<Control> {
    CONTROL.lock().unwrap().as_ref().unwrap().clone()
}

impl Control {
    fn record(&self, kind: &'static str, pid: i32, value: i64) {
        self.state
            .lock()
            .unwrap()
            .events
            .push(Event { kind, pid, value });
        self.changed.notify_all();
    }

    async fn wait_for(&self, condition: impl Fn(&State) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        futures::future::poll_fn(|cx| {
            let state = self.state.lock().unwrap();
            assert!(
                Instant::now() < deadline,
                "child progress timed out: {state:?}"
            );
            if condition(&state) {
                std::task::Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await;
    }
}

struct HostExit(RefCell<Option<(Arc<Control>, i32)>>);
impl Drop for HostExit {
    fn drop(&mut self) {
        if let Some((control, pid)) = self.0.get_mut().take() {
            control.record("host-exit", pid, 0);
        }
    }
}
thread_local! {
    // A child reaches this TLS destructor only after its complete backend
    // closure, including the global child-wait callback, has returned.
    static HOST_EXIT: HostExit = const { HostExit(RefCell::new(None)) };
}

#[derive(Debug, Default)]
struct Log {
    control: Arc<Control>,
    mode: u8,
}
impl Drop for Log {
    fn drop(&mut self) {
        self.control.state.lock().unwrap().global_dropped = true;
        self.control.changed.notify_all();
    }
}
#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = ();
    type Response = ();
    type Config = u8;
    async fn init_global_state(mode: &u8) -> Self {
        Self {
            control: control(),
            mode: *mode,
        }
    }
    async fn receive_rpc(&self, _: Pid, _: ()) {}
    async fn on_backend_child_wait_event(
        &self,
        event: BackendChildWaitEvent,
    ) -> Result<(), reverie::Error> {
        assert_eq!(event.parent.tgid.as_raw(), 1);
        assert_eq!(
            event.state,
            BackendChildWaitState::Exited {
                status: ExitStatus::SUCCESS,
                waitable: true,
                uid: 0,
                user_ticks: 0,
                system_ticks: 0,
            }
        );
        self.control
            .record("wait-event", event.child.tgid.as_raw(), 0);
        if matches!(self.mode, 2 | 6) {
            // The backend polls this synchronous admission before publishing
            // waitability, then retains this same suspended callback. Hold its
            // remainder until the parent has collected the now-visible status
            // and reached the intended cancellation point.
            self.control.wait_for(|state| state.release_child).await;
            if self.mode == 6 {
                panic!("controlled child wait callback panic");
            }
            return Err(if event.child.tgid.as_raw() == 2 {
                Errno::EIO
            } else {
                Errno::E2BIG
            }
            .into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct ForkTool {
    pid: i32,
    mode: u8,
    control: Arc<Control>,
}
impl Drop for ForkTool {
    fn drop(&mut self) {
        self.control.record("tool-drop", self.pid, 0);
    }
}
#[reverie::tool]
impl Tool for ForkTool {
    type GlobalState = Log;
    type ThreadState = (i32, bool);
    fn new(pid: Pid, mode: &u8) -> Self {
        Self {
            pid: pid.as_raw(),
            mode: *mode,
            control: control(),
        }
    }
    fn subscriptions(_: &u8) -> Subscription {
        let mut result = Subscription::none();
        result.syscalls([Sysno::getpid, Sysno::gettid, Sysno::write]);
        result
    }
    fn init_thread_state(
        &self,
        tid: Pid,
        _: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        (tid.as_raw(), false)
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        assert_eq!(guest.thread_state(), &(self.pid, false));
        guest.thread_state_mut().1 = true;
        self.control.record("start", self.pid, unsafe {
            libc::syscall(libc::SYS_gettid)
        });
        HOST_EXIT.with(|exit| {
            assert!(
                exit.0
                    .borrow_mut()
                    .replace((self.control.clone(), self.pid))
                    .is_none()
            );
        });
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        assert_eq!(guest.thread_state(), &(self.pid, true));
        if syscall.number() == Sysno::getpid {
            assert_eq!(self.pid, 1);
            let count = if (2..=5).contains(&self.mode) { 2 } else { 1 };
            let mut children = Vec::new();
            for expected in 2..2 + count {
                let child = guest.inject(Fork::new()).await?;
                assert_eq!(child, expected);
                children.push(child as i32);
            }
            if matches!(self.mode, 2 | 6) {
                self.control
                    .wait_for(|state| {
                        children.iter().all(|pid| {
                            state
                                .events
                                .iter()
                                .any(|event| event.kind == "wait-event" && event.pid == *pid)
                        })
                    })
                    .await;
                for child in &children {
                    // Waitable completion is published after the callback's
                    // synchronous prefix and before its held remainder. This
                    // actual wait moves its live handle into completed_processes.
                    let wait = Syscall::from_raw(
                        Sysno::wait4,
                        SyscallArgs::new(*child as usize, 0, libc::WNOHANG as usize, 0, 0, 0),
                    );
                    assert_eq!(guest.inject(wait).await?, i64::from(*child));
                    self.control.record("wait-collected", *child, 0);
                }
            } else {
                let blocked = *children.last().unwrap();
                self.control
                    .wait_for(|state| {
                        state
                            .events
                            .iter()
                            .any(|event| event.kind == "blocked" && event.pid == blocked)
                            && (self.mode < 3
                                || state
                                    .events
                                    .iter()
                                    .any(|event| event.kind == "process-exit" && event.pid == 2))
                    })
                    .await;
            }
            {
                let mut state = self.control.state.lock().unwrap();
                state.parent_ready = true;
                state.events.push(Event {
                    kind: "parent-ready",
                    pid: self.pid,
                    value: i64::from(self.mode),
                });
                self.control.changed.notify_all();
            }
            if matches!(self.mode, 1 | 5) {
                return Ok(i64::from(children[0]));
            }
            // The same callback has registered its children and now terminates.
            guest.cancel_current_thread().await;
        }
        if syscall.number() == Sysno::gettid {
            assert_ne!(self.pid, 1);
            if self.mode < 2 {
                self.control.record("blocked", self.pid, 0);
                let state = self.control.state.lock().unwrap();
                let (state, timeout) = self
                    .control
                    .changed
                    .wait_timeout_while(state, Duration::from_secs(5), |state| !state.release_child)
                    .unwrap();
                assert!(!timeout.timed_out(), "child release timed out: {state:?}");
            }
            return Ok(i64::from(self.pid));
        }
        assert_eq!(syscall.number(), Sysno::write);
        let args = syscall.into_parts().1;
        let mut bytes = vec![0; args.arg2];
        guest.memory().read_exact(
            reverie::syscalls::Addr::from_raw(args.arg1).unwrap(),
            &mut bytes,
        )?;
        let expected: &[u8] = if self.pid == 1 {
            b"parent\n"
        } else if args.arg0 == 1 {
            b"child\n"
        } else {
            b"child stderr\n"
        };
        assert_eq!(bytes, expected);
        let result = guest.inject(syscall).await?;
        assert_eq!(result, expected.len() as i64);
        self.control.record("write", self.pid, args.arg0 as i64);
        Ok(result)
    }
    async fn on_exit_thread<G: GlobalRPC<Log>>(
        &self,
        tid: Pid,
        _: &G,
        state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(state, (self.pid, true));
        assert_eq!(tid.as_raw(), self.pid);
        assert_eq!(status, ExitStatus::SUCCESS);
        self.control.record("thread-exit", self.pid, 0);
        if self.mode == 4 && self.pid == 1 {
            return Err(Errno::ENOSPC.into());
        }
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Log>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(pid.as_raw(), self.pid);
        assert_eq!(status, ExitStatus::SUCCESS);
        self.control.record("process-exit", self.pid, 0);
        if (3..=5).contains(&self.mode) && self.pid == 2 {
            // Failure is run-wide. Inject it only after the parent reaches the
            // intended terminal path and the sibling has captured its output.
            self.control
                .wait_for(|state| state.release_first_error)
                .await;
            return Err(Errno::EIO.into());
        }
        if (3..=5).contains(&self.mode) && self.pid == 3 {
            // Keep the later worker alive after its output and success status
            // are known. The controller releases it after the first error's
            // worker has exited, preserving the ordered cleanup obligation.
            self.control.record("blocked", self.pid, 0);
            self.control.wait_for(|state| state.release_child).await;
        }
        if self.mode == 4 {
            return Err(if self.pid == 1 {
                Errno::EACCES
            } else {
                Errno::E2BIG
            }
            .into());
        }
        Ok(())
    }
}

fn guest_program() -> Vec<u8> {
    fn write(code: &mut Vec<u8>, fd: u32, message: &[u8]) -> (usize, Vec<u8>) {
        code.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf]);
        code.extend_from_slice(&fd.to_le_bytes());
        code.extend_from_slice(&[0x48, 0xbe]);
        let address = code.len();
        code.extend_from_slice(&[0; 8]);
        code.push(0xba);
        code.extend_from_slice(&(message.len() as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05]);
        (address, message.to_vec())
    }
    fn exit(code: &mut Vec<u8>) {
        code.extend_from_slice(&[0xb8, 0xe7, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0x0f, 0x0b]);
    }
    let mut code = vec![
        0xb8, 0x27, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0, 0x0f, 0x85, 0, 0, 0, 0,
    ];
    let parent_jump = 11;
    code.extend_from_slice(&[0xb8, 0xba, 0, 0, 0, 0x0f, 0x05]);
    let stdout = write(&mut code, 1, b"child\n");
    let stderr = write(&mut code, 2, b"child stderr\n");
    exit(&mut code);
    let parent = code.len();
    code[parent_jump..parent_jump + 4].copy_from_slice(
        &i32::try_from(parent - (parent_jump + 4))
            .unwrap()
            .to_le_bytes(),
    );
    let parent_output = write(&mut code, 1, b"parent\n");
    exit(&mut code);
    for (operand, bytes) in [stdout, stderr, parent_output] {
        let address = LOAD_ADDRESS + code.len() as u64;
        code[operand..operand + 8].copy_from_slice(&address.to_le_bytes());
        code.extend_from_slice(&bytes);
    }
    static_elf(&code)
}

fn task_virtual_memory_size(tid: i64) -> Option<i64> {
    let stat = match std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")) {
        Ok(stat) => stat,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            return None;
        }
        Err(error) => panic!("cannot inspect host thread {tid}: {error}"),
    };
    // The final ')' ends comm; vsize is field 23, twenty fields after state.
    Some(
        stat.rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(20)
            .unwrap()
            .parse()
            .unwrap(),
    )
}

fn bounded(test: &str) -> bool {
    if !kvm_available(test) {
        return false;
    }
    if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() != Ok(test) {
        // Inherit stdout/stderr so successful child observations remain in the
        // retained Cargo log, under the same bounded subprocess convention.
        let status = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("REVERIE_LEADER_EXEC_CHILD", test)
            .status()
            .unwrap();
        assert!(status.success(), "{test}: status={status:?}");
        return false;
    }
    true
}

fn snapshot_at_return(control: &Control) -> (Vec<Event>, bool) {
    let state = control.state.lock().unwrap();
    let mut events = state.events.clone();
    for event in &state.events {
        if event.kind == "start"
            && event.pid != 1
            && let Some(bytes) = task_virtual_memory_size(event.value)
        {
            events.push(Event {
                kind: "host-memory-at-return",
                pid: event.pid,
                value: bytes,
            });
        }
    }
    let result = (events, state.global_dropped);
    drop(state);
    result
}

fn run_case(test: &str, mode: u8) {
    if !bounded(test) {
        return;
    }
    let control = Arc::new(Control::default());
    *CONTROL.lock().unwrap() = Some(control.clone());
    let worker_control = control.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut backend = KvmBackend::new(MEMORY_SIZE).unwrap();
        backend
            .install_static_elf(&guest_program(), "/bin/terminal-fork-test")
            .unwrap();
        let result =
            futures::executor::block_on(backend.run_static_elf_with_tool::<ForkTool>(mode, true));
        let at_return = snapshot_at_return(&worker_control);
        sender.send((result, at_return)).unwrap();
    });
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| !state.parent_ready)
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "parent never reached cancellation/exit: {state:?}"
    );
    if !matches!(mode, 2 | 6) {
        let child = if mode < 3 { 2 } else { 3 };
        let tid = state
            .events
            .iter()
            .find(|event| event.kind == "start" && event.pid == child)
            .unwrap()
            .value;
        assert!(
            task_virtual_memory_size(tid).is_some_and(|bytes| bytes > 0),
            "the blocked-worker control must observe its live host address space"
        );
    }
    drop(state);
    // Except for the deliberately completed-child case, the child is held by
    // an explicit gate. No public result is permitted before that release.
    let early = if matches!(mode, 2 | 6) {
        None
    } else {
        receiver.recv_timeout(Duration::from_millis(100)).ok()
    };
    if (3..=5).contains(&mode) {
        let mut state = control.state.lock().unwrap();
        state.release_first_error = true;
        control.changed.notify_all();
        let (state, timeout) = control
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| {
                !state
                    .events
                    .iter()
                    .any(|event| event.kind == "host-exit" && event.pid == 2)
            })
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "first child error did not finish before sibling release: {state:?}"
        );
    }
    {
        let mut state = control.state.lock().unwrap();
        state.release_child = true;
        control.changed.notify_all();
    }
    let returned_early = early.is_some();
    let (result, (at_return, global_dropped)) =
        early.unwrap_or_else(|| receiver.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
    // Clean up even a broken baseline that detached its child before asserting.
    let child_count = if (2..=5).contains(&mode) { 2 } else { 1 };
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| {
            state
                .events
                .iter()
                .filter(|event| event.kind == "host-exit" && event.pid != 1)
                .count()
                != child_count
        })
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "fixture could not finish detached children: {state:?}"
    );
    drop(state);
    eprintln!(
        "terminal fork mode={mode} early={returned_early} result={result:?} at_return={at_return:?} global_dropped={global_dropped}"
    );
    assert!(
        !returned_early,
        "public API returned while an owned child was still blocked"
    );
    for pid in 1..=child_count as i32 + 1 {
        for kind in ["start", "thread-exit", "process-exit", "tool-drop"] {
            assert_eq!(
                at_return
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == kind)
                    .count(),
                1,
                "each owned state must be consumed once before return: pid={pid} kind={kind} events={at_return:?}"
            );
        }
        if pid != 1 {
            let position = |kind| {
                at_return
                    .iter()
                    .position(|event| event.pid == pid && event.kind == kind)
            };
            let expected_wait_event = (2..=6).contains(&mode);
            assert_eq!(
                at_return
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == "wait-event")
                    .count(),
                usize::from(expected_wait_event),
                "a child gets one wait event after a live-parent exit, while parent-terminal teardown suppresses and auto-reaps it: pid={pid} events={at_return:?}",
            );
            if expected_wait_event {
                let wait_event = position("wait-event").unwrap();
                assert!(
                    wait_event < position("thread-exit").unwrap()
                        && position("thread-exit").unwrap() < position("process-exit").unwrap(),
                    "logical wait publication must precede consuming exit hooks: pid={pid} events={at_return:?}"
                );
            }
            if matches!(mode, 2 | 6) {
                assert!(
                    position("wait-collected").unwrap() < position("thread-exit").unwrap(),
                    "the parent must be able to reap while the callback still holds physical cleanup: pid={pid} events={at_return:?}"
                );
            }
            // A successfully joined native pthread can briefly remain in
            // /proc during kernel exit bookkeeping, after releasing its mm.
            // Any remaining entry must have no userspace address space; TLS
            // completion and owned-state destruction are required separately.
            assert!(
                !at_return.iter().any(|event| event.pid == pid
                    && event.kind == "host-memory-at-return"
                    && event.value != 0),
                "child retained a host address space after API return: {at_return:?}"
            );
            assert_eq!(
                at_return
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == "host-exit")
                    .count(),
                1,
                "child host worker survived API return: {at_return:?}"
            );
            for fd in [1, 2] {
                assert_eq!(
                    at_return
                        .iter()
                        .filter(|event| event.pid == pid
                            && event.kind == "write"
                            && event.value == fd)
                        .count(),
                    1
                );
            }
        }
    }
    if mode < 2 {
        let (log, status, stdout, stderr) = result.unwrap();
        assert_eq!(status, 0);
        assert_eq!(
            stdout,
            if mode == 1 {
                b"parent\nchild\n".as_slice()
            } else {
                b"child\n".as_slice()
            }
        );
        assert_eq!(stderr, b"child stderr\n");
        assert!(!global_dropped);
        drop(log);
    } else {
        let error = result.unwrap_err().to_string();
        for (name, count) in [
            ("EIO", usize::from((2..=5).contains(&mode))),
            ("E2BIG", usize::from(matches!(mode, 2 | 4))),
            ("ENOSPC", usize::from(mode == 4)),
            ("EACCES", usize::from(mode == 4)),
        ] {
            assert_eq!(
                error.matches(name).count(),
                count,
                "original errors must survive exactly once: {error}"
            );
        }
        assert!(global_dropped, "global Tool state survived error return");
        if mode == 2 {
            assert_eq!(
                at_return
                    .iter()
                    .filter(|event| event.kind == "wait-collected")
                    .count(),
                2
            );
        } else if mode == 6 {
            assert_eq!(error.matches("child wait hook").count(), 1, "{error}");
            assert_eq!(
                error
                    .matches("guest thread panicked during teardown")
                    .count(),
                1,
                "{error}"
            );
            assert_eq!(
                at_return
                    .iter()
                    .filter(|event| event.kind == "wait-collected")
                    .count(),
                1
            );
        }
    }
    assert!(control.state.lock().unwrap().global_dropped);
    *CONTROL.lock().unwrap() = None;
}

#[test]
fn cancellation_joins_live_fork_and_captures_output() {
    run_case(
        "terminal_fork::cancellation_joins_live_fork_and_captures_output",
        0,
    );
}
#[test]
fn ordinary_exit_joins_live_fork_and_captures_output() {
    run_case(
        "terminal_fork::ordinary_exit_joins_live_fork_and_captures_output",
        1,
    );
}
#[test]
fn cancellation_preserves_completed_child_errors() {
    run_case(
        "terminal_fork::cancellation_preserves_completed_child_errors",
        2,
    );
}
#[test]
fn cancellation_finishes_later_children_after_first_child_error() {
    run_case(
        "terminal_fork::cancellation_finishes_later_children_after_first_child_error",
        3,
    );
}
#[test]
fn cancellation_consumes_hooks_and_preserves_all_errors() {
    run_case(
        "terminal_fork::cancellation_consumes_hooks_and_preserves_all_errors",
        4,
    );
}
#[test]
fn ordinary_exit_finishes_later_children_after_first_child_error() {
    run_case(
        "terminal_fork::ordinary_exit_finishes_later_children_after_first_child_error",
        5,
    );
}

#[test]
fn cancellation_preserves_status_across_child_wait_callback_panic() {
    run_case(
        "terminal_fork::cancellation_preserves_status_across_child_wait_callback_panic",
        6,
    );
}

#[derive(Default)]
struct ExecForkTool {
    pid: i32,
    mode: u8,
    control: Arc<Control>,
}
impl Drop for ExecForkTool {
    fn drop(&mut self) {
        self.control.record("tool-drop", self.pid, 0);
    }
}
#[reverie::tool]
impl Tool for ExecForkTool {
    type GlobalState = Log;
    type ThreadState = (i32, bool);
    fn new(pid: Pid, mode: &u8) -> Self {
        Self {
            pid: pid.as_raw(),
            mode: *mode,
            control: control(),
        }
    }
    fn subscriptions(mode: &u8) -> Subscription {
        let mut result = Subscription::all_syscalls();
        if mode % 2 == 1 {
            result.disable_syscalls([Sysno::execve, Sysno::execveat]);
        }
        result
    }
    fn init_thread_state(
        &self,
        tid: Pid,
        _: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        (tid.as_raw(), false)
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let tid = guest.tid().as_raw();
        assert_eq!(guest.thread_state(), &(tid, false));
        guest.thread_state_mut().1 = true;
        self.control
            .record("start", tid, unsafe { libc::syscall(libc::SYS_gettid) });
        HOST_EXIT.with(|exit| {
            assert!(
                exit.0
                    .borrow_mut()
                    .replace((self.control.clone(), tid))
                    .is_none()
            );
        });
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        self.control.record("post-exec", guest.tid().as_raw(), 0);
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        if syscall.number() == Sysno::fork {
            let child = guest.inject(syscall).await?;
            assert_eq!(child, 2);
            return Ok(child);
        }
        let args = syscall.into_parts().1;
        if syscall.number() == Sysno::gettid && self.pid == 2 && args.arg0 == 0x74666f72 {
            self.control.record("blocked", 2, 0);
            let state = self.control.state.lock().unwrap();
            let (state, timeout) = self
                .control
                .changed
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.release_child)
                .unwrap();
            assert!(
                !timeout.timed_out(),
                "fork child release timed out: {state:?}"
            );
            return Ok(2);
        }
        if syscall.number() == Sysno::getpid && args.arg0 == 0x74666f72 {
            assert_eq!(guest.tid().as_raw(), 1);
            self.control
                .wait_for(|state| {
                    state
                        .events
                        .iter()
                        .any(|event| event.kind == "blocked" && event.pid == 2)
                        && state
                            .events
                            .iter()
                            .any(|event| event.kind == "start" && event.pid == 3)
                })
                .await;
            return Ok(1);
        }
        if syscall.number() == Sysno::write {
            assert_eq!(
                self.pid, 2,
                "failed exec must not enter the replacement image"
            );
            let mut bytes = vec![0; args.arg2];
            guest.memory().read_exact(
                reverie::syscalls::Addr::from_raw(args.arg1).unwrap(),
                &mut bytes,
            )?;
            let expected: &[u8] = if args.arg0 == 1 {
                b"child\n"
            } else {
                b"child stderr\n"
            };
            assert_eq!(bytes, expected);
            let result = guest.inject(syscall).await?;
            assert_eq!(result, expected.len() as i64);
            self.control.record("write", self.pid, args.arg0 as i64);
            return Ok(result);
        }
        guest.tail_inject(syscall).await
    }
    async fn on_exit_thread<G: GlobalRPC<Log>>(
        &self,
        tid: Pid,
        _: &G,
        state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        let tid = tid.as_raw();
        assert_eq!(state, (tid, true));
        assert_eq!(
            status,
            if tid == 1 {
                ExitStatus::Exited(255)
            } else {
                ExitStatus::SUCCESS
            }
        );
        self.control.record("thread-exit", tid, 0);
        if tid == 3 {
            // This is the exec teardown failure itself, after its sibling
            // cancellation has begun while the fork child remains blocked.
            self.control.state.lock().unwrap().parent_ready = true;
            self.control.changed.notify_all();
            return Err(Errno::EIO.into());
        }
        if tid == 1 && self.mode >= 8 {
            return Err(Errno::ENOSPC.into());
        }
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Log>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(pid.as_raw(), self.pid);
        assert_eq!(
            status,
            if self.pid == 1 {
                ExitStatus::Exited(255)
            } else {
                ExitStatus::SUCCESS
            }
        );
        self.control.record("process-exit", self.pid, 0);
        if self.mode >= 8 {
            return Err(if self.pid == 1 {
                Errno::EACCES
            } else {
                Errno::E2BIG
            }
            .into());
        }
        Ok(())
    }
}

const EXEC_FORK_GUEST: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <sys/syscall.h>
#include <unistd.h>
static _Atomic int entered;
static void *worker(void *unused) {
  (void)unused;
  atomic_store(&entered, 1);
  for (;;) sched_yield();
  return NULL;
}
int main(int argc, char **argv) {
  if (argc == 2) { write(1, "replacement\n", 12); return 0; }
  long child = syscall(SYS_fork);
  if (child < 0) return 20;
  if (!child) {
    syscall(SYS_gettid, 0x74666f72);
    if (write(1, "child\n", 6) != 6) return 21;
    if (write(2, "child stderr\n", 13) != 13) return 22;
    syscall(SYS_exit_group, 0);
  }
  pthread_t thread;
  if (pthread_create(&thread, NULL, worker, NULL)) return 23;
  while (!atomic_load(&entered)) sched_yield();
  syscall(SYS_getpid, 0x74666f72);
  char *next[] = {argv[0], "replacement", NULL};
  execv(argv[0], next);
  return 24;
}
"#;

fn run_exec_case(test: &str, mode: u8) {
    if !bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "terminal-fork-exec", EXEC_FORK_GUEST);
    let control = Arc::new(Control::default());
    *CONTROL.lock().unwrap() = Some(control.clone());
    let worker_control = control.clone();
    let cwd = directory.0.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &cwd,
            )
            .unwrap();
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<ExecForkTool>(mode, true),
        );
        sender
            .send((result, snapshot_at_return(&worker_control)))
            .unwrap();
    });
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| !state.parent_ready)
        .unwrap();
    assert!(!timeout.timed_out(), "parent never reached exec: {state:?}");
    let child_tid = state
        .events
        .iter()
        .find(|event| event.kind == "start" && event.pid == 2)
        .unwrap()
        .value;
    assert!(task_virtual_memory_size(child_tid).is_some_and(|bytes| bytes > 0));
    drop(state);
    let early = receiver.recv_timeout(Duration::from_millis(100)).ok();
    control.state.lock().unwrap().release_child = true;
    control.changed.notify_all();
    let returned_early = early.is_some();
    let (result, (events, global_dropped)) =
        early.unwrap_or_else(|| receiver.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| {
            state
                .events
                .iter()
                .filter(|event| event.kind == "host-exit" && event.pid != 1)
                .count()
                != 2
        })
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "fixture could not finish child workers: {state:?}"
    );
    drop(state);
    eprintln!(
        "terminal fork exec mode={mode} early={returned_early} result={result:?} at_return={events:?} global_dropped={global_dropped}"
    );
    assert!(
        !returned_early,
        "failed exec returned while an owned fork child was still blocked"
    );
    assert!(global_dropped, "failed exec retained global Tool state");
    for tid in [1, 2, 3] {
        for kind in ["start", "thread-exit"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == tid && event.kind == kind)
                    .count(),
                1,
                "exactly one consuming hook for each thread: {events:?}"
            );
        }
        if tid != 1 {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == tid && event.kind == "host-exit")
                    .count(),
                1
            );
            assert!(!events.iter().any(|event| event.pid == tid
                && event.kind == "host-memory-at-return"
                && event.value != 0));
        }
    }
    for pid in [1, 2] {
        for kind in ["process-exit", "tool-drop"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == kind)
                    .count(),
                1,
                "each process state must be consumed: {events:?}"
            );
        }
    }
    for fd in [1, 2] {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "write" && event.pid == 2 && event.value == fd)
                .count(),
            1
        );
    }
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == "post-exec" && event.pid == 1)
            .count(),
        1,
        "the failed exec must not reach a replacement post-exec hook"
    );
    let error = result.unwrap_err().to_string();
    for name in ["EIO", "E2BIG", "ENOSPC", "EACCES"] {
        assert_eq!(
            error.matches(name).count(),
            usize::from(name == "EIO" || mode >= 8),
            "{error}"
        );
    }
    if mode < 8 {
        assert_eq!(
            error,
            "unexpected vCPU exit: KVM worker cleanup failed: thread 3: Reverie tool failed: -5 EIO (I/O error)"
        );
    }
    *CONTROL.lock().unwrap() = None;
}

#[test]
fn injected_exec_failure_joins_live_fork() {
    run_exec_case("terminal_fork::injected_exec_failure_joins_live_fork", 6);
}
#[test]
fn backend_exec_failure_joins_live_fork() {
    run_exec_case("terminal_fork::backend_exec_failure_joins_live_fork", 7);
}
#[test]
fn injected_exec_failure_preserves_child_and_owner_errors() {
    run_exec_case(
        "terminal_fork::injected_exec_failure_preserves_child_and_owner_errors",
        8,
    );
}
#[test]
fn backend_exec_failure_preserves_child_and_owner_errors() {
    run_exec_case(
        "terminal_fork::backend_exec_failure_preserves_child_and_owner_errors",
        9,
    );
}

#[derive(Default)]
struct TerminalRouteTool {
    pid: i32,
    mode: u8,
    control: Arc<Control>,
}
impl Drop for TerminalRouteTool {
    fn drop(&mut self) {
        self.control.record("tool-drop", self.pid, 0);
    }
}
#[reverie::tool]
impl Tool for TerminalRouteTool {
    type GlobalState = Log;
    type ThreadState = (i32, bool);
    fn new(pid: Pid, mode: &u8) -> Self {
        Self {
            pid: pid.as_raw(),
            mode: *mode,
            control: control(),
        }
    }
    fn subscriptions(_: &u8) -> Subscription {
        Subscription::all_syscalls()
    }
    fn init_thread_state(
        &self,
        tid: Pid,
        _: Option<(Pid, &Self::ThreadState)>,
    ) -> Self::ThreadState {
        (tid.as_raw(), false)
    }
    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        let tid = guest.tid().as_raw();
        assert_eq!(*guest.thread_state(), (tid, false));
        guest.thread_state_mut().1 = true;
        self.control
            .record("start", tid, unsafe { libc::syscall(libc::SYS_gettid) });
        HOST_EXIT.with(|exit| {
            assert!(
                exit.0
                    .borrow_mut()
                    .replace((self.control.clone(), tid))
                    .is_none()
            )
        });
        Ok(())
    }
    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        let tid = guest.tid().as_raw();
        self.control.record("post-exec", tid, 0);
        if self.mode == 12 && tid == 1 {
            let mut state = self.control.state.lock().unwrap();
            if state
                .events
                .iter()
                .filter(|event| event.kind == "post-exec" && event.pid == 1)
                .count()
                == 2
            {
                state.parent_ready = true;
                self.control.changed.notify_all();
                return Err(Errno::EIO);
            }
        }
        Ok(())
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let args = syscall.into_parts().1;
        if syscall.number() == Sysno::getuid && args.arg0 == 0x7465726d {
            return Ok(i64::from(self.mode));
        }
        if syscall.number() == Sysno::fork {
            return Ok(guest.inject(syscall).await?);
        }
        if syscall.number() == Sysno::gettid && args.arg0 == 0x7465726d {
            self.control.record("blocked", self.pid, 0);
            if matches!(self.mode, 14 | 16 | 18) {
                self.wait_for_parent_exit(guest.tid().as_raw()).await;
                return Ok(i64::from(self.pid));
            }
            let state = self.control.state.lock().unwrap();
            let (state, timeout) = self
                .control
                .changed
                .wait_timeout_while(state, Duration::from_secs(5), |state| !state.release_child)
                .unwrap();
            assert!(!timeout.timed_out(), "fork release timed out: {state:?}");
            return Ok(i64::from(self.pid));
        }
        if syscall.number() == Sysno::getpid && args.arg0 == 0x7465726d {
            self.control
                .wait_for(|state| state.events.iter().any(|event| event.kind == "blocked"))
                .await;
            if self.mode == 13 {
                self.control.state.lock().unwrap().parent_ready = true;
                self.control.changed.notify_all();
                return Err(std::io::Error::other("controlled fatal Tool callback").into());
            }
            self.control.record("parent-marker", 1, 0);
            return Ok(1);
        }
        if syscall.number() == Sysno::getpid && args.arg0 == 0x7465726f {
            self.control.record("blocked", guest.tid().as_raw(), 0);
            // Workers complete before the leader hook, as required by ptrace.
            return Ok(1);
        }
        if syscall.number() == Sysno::getpid && args.arg0 == 0x7465726e {
            self.control
                .wait_for(|state| {
                    state
                        .events
                        .iter()
                        .any(|event| event.kind == "parent-marker")
                })
                .await;
            return Ok(1);
        }
        if matches!(self.mode, 11 | 14 | 15 | 16 | 18)
            && guest.tid().as_raw() == 1
            && syscall.number() == Sysno::exit_group
        {
            self.control.state.lock().unwrap().parent_ready = true;
            self.control.changed.notify_all();
        }
        if syscall.number() == Sysno::write {
            assert_ne!(
                self.pid, 1,
                "terminal parent cannot execute replacement/continuation writes"
            );
            let mut bytes = vec![0; args.arg2];
            guest.memory().read_exact(
                reverie::syscalls::Addr::from_raw(args.arg1).unwrap(),
                &mut bytes,
            )?;
            let expected: &[u8] = if args.arg0 == 1 {
                b"child\n"
            } else {
                b"child stderr\n"
            };
            assert_eq!(bytes, expected);
            let count = guest.inject(syscall).await?;
            assert_eq!(count, expected.len() as i64);
            self.control.record("write", self.pid, args.arg0 as i64);
            return Ok(count);
        }
        guest.tail_inject(syscall).await
    }
    async fn on_exit_thread<G: GlobalRPC<Log>>(
        &self,
        tid: Pid,
        _: &G,
        state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        let tid = tid.as_raw();
        assert_eq!(state, (tid, true));
        let expected = if self.pid != 1 {
            0
        } else if self.mode == 10 {
            37
        } else if matches!(self.mode, 12 | 13) {
            255
        } else {
            0
        };
        assert_eq!(status, ExitStatus::Exited(expected));
        self.control.record("thread-exit", tid, i64::from(expected));
        if self.mode == 10 && tid == 3 {
            self.control.state.lock().unwrap().parent_ready = true;
            self.control.changed.notify_all();
        }
        Ok(())
    }
    async fn on_exit_process<G: GlobalRPC<Log>>(
        self,
        pid: Pid,
        _: &G,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        assert_eq!(pid.as_raw(), self.pid);
        let expected = if self.pid != 1 {
            0
        } else if self.mode == 10 {
            37
        } else if matches!(self.mode, 12 | 13) {
            255
        } else {
            0
        };
        assert_eq!(status, ExitStatus::Exited(expected));
        self.control
            .record("process-exit", self.pid, i64::from(expected));
        Ok(())
    }
}
const TERMINAL_ROUTE_GUEST: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
static int mode;
static void fork_child(void) {
  syscall(SYS_gettid, 0x7465726d);
  if (write(1, "child\n", 6) != 6) syscall(SYS_exit_group, 41);
  if (write(2, "child stderr\n", 13) != 13) syscall(SYS_exit_group, 42);
  syscall(SYS_exit_group, 0);
}
static void *worker(void *unused) {
  (void)unused;
  if (mode == 15) { syscall(SYS_getpid, 0x7465726f); return 0; }
  if (mode == 11 || mode == 16) {
    long child = syscall(SYS_fork);
    if (child < 0) syscall(SYS_exit_group, 43);
    if (!child) fork_child();
    for (;;) sched_yield();
  }
  syscall(SYS_getpid, 0x7465726e);
  syscall(SYS_exit_group, 37);
  return 0;
}
int main(int argc, char **argv) {
  if (argc == 2) { write(1, "replacement\n", 12); return 44; }
  mode = syscall(SYS_getuid, 0x7465726d);
  if (mode != 11 && mode != 15 && mode != 16) {
    long child = syscall(SYS_fork);
    if (child < 0) return 45;
    if (!child) fork_child();
  }
  pthread_t thread;
  if ((mode <= 11 || mode == 15 || mode == 16) && pthread_create(&thread, 0, worker, 0)) return 46;
  syscall(SYS_getpid, 0x7465726d);
  if (mode == 11 || mode == 14 || mode == 15 || mode == 16 || mode == 18) syscall(SYS_exit_group, 0);
  if (mode == 12) { char *next[] = {argv[0], "replacement", 0}; execv(argv[0], next); return 47; }
  for (;;) sched_yield();
}
"#;
fn run_terminal_route(test: &str, mode: u8) {
    if !bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "terminal-route", TERMINAL_ROUTE_GUEST);
    let control = Arc::new(Control::default());
    *CONTROL.lock().unwrap() = Some(control.clone());
    let captured = control.clone();
    let cwd = directory.0.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &cwd,
            )
            .unwrap();
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<TerminalRouteTool>(mode, true),
        );
        sender
            .send((result, snapshot_at_return(&captured)))
            .unwrap();
    });
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| !state.parent_ready)
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "terminal boundary not reached: {state:?}"
    );
    let child = if mode == 11 { 3 } else { 2 };
    let child_tid = state
        .events
        .iter()
        .find(|event| event.kind == "start" && event.pid == child)
        .unwrap()
        .value;
    assert!(task_virtual_memory_size(child_tid).is_some_and(|bytes| bytes > 0));
    drop(state);
    let early = receiver.recv_timeout(Duration::from_millis(100)).ok();
    control.state.lock().unwrap().release_child = true;
    control.changed.notify_all();
    let returned_early = early.is_some();
    let (result, (events, global_dropped)) =
        early.unwrap_or_else(|| receiver.recv_timeout(Duration::from_secs(5)).unwrap());
    worker.join().unwrap();
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| {
            !state
                .events
                .iter()
                .any(|event| event.kind == "host-exit" && event.pid == child)
        })
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "detached baseline child did not finish"
    );
    drop(state);
    eprintln!(
        "terminal route mode={mode} early={returned_early} result={result:?} events={events:?} global_dropped={global_dropped}"
    );
    assert!(
        !returned_early,
        "terminal route returned while its fork child was blocked"
    );
    let tids = if mode <= 11 {
        vec![1, 2, 3]
    } else {
        vec![1, 2]
    };
    for tid in tids {
        for kind in ["start", "thread-exit"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == tid && event.kind == kind)
                    .count(),
                1,
                "each thread must be consumed: {events:?}"
            );
        }
        if tid != 1 {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == tid && event.kind == "host-exit")
                    .count(),
                1
            );
            assert!(!events.iter().any(|event| event.pid == tid
                && event.kind == "host-memory-at-return"
                && event.value != 0));
        }
    }
    for pid in [1, child] {
        for kind in ["process-exit", "tool-drop"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == kind)
                    .count(),
                1,
                "each process must be consumed: {events:?}"
            );
        }
    }
    for fd in [1, 2] {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.pid == child && event.kind == "write" && event.value == fd)
                .count(),
            1
        );
    }
    if mode <= 11 {
        let (global, status, stdout, stderr) = result.unwrap();
        assert_eq!(status, if mode == 10 { 37 } else { 0 });
        assert_eq!(stdout, b"child\n");
        assert_eq!(stderr, b"child stderr\n");
        assert!(!global_dropped);
        drop(global);
    } else {
        let error = result.unwrap_err().to_string();
        assert_eq!(
            error,
            if mode == 12 {
                "Reverie post-exec hook failed: -5 EIO (I/O error)"
            } else {
                "Reverie tool failed: controlled fatal Tool callback"
            }
        );
        assert!(global_dropped);
    }
    assert!(control.state.lock().unwrap().global_dropped);
    *CONTROL.lock().unwrap() = None;
}
#[test]
fn terminal_route_group_exit_joins_root_fork() {
    run_terminal_route(
        "terminal_fork::terminal_route_group_exit_joins_root_fork",
        10,
    );
}
#[test]
fn terminal_route_cancelled_worker_joins_its_fork() {
    run_terminal_route(
        "terminal_fork::terminal_route_cancelled_worker_joins_its_fork",
        11,
    );
}
#[test]
fn terminal_route_post_exec_error_joins_fork() {
    run_terminal_route(
        "terminal_fork::terminal_route_post_exec_error_joins_fork",
        12,
    );
}
#[test]
fn terminal_route_fatal_tool_error_joins_fork() {
    run_terminal_route(
        "terminal_fork::terminal_route_fatal_tool_error_joins_fork",
        13,
    );
}

#[derive(Default)]
struct ExitFilesTool;
#[reverie::tool]
impl Tool for ExitFilesTool {
    type GlobalState = ();
    type ThreadState = ();
    fn subscriptions(_: &()) -> Subscription {
        Subscription::all_syscalls()
    }
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let args = syscall.into_parts().1;
        if syscall.number() == Sysno::read && args.arg0 > 2 {
            eprintln!(
                "exit-files before read tid={} fd={}",
                guest.tid(),
                args.arg0
            );
            let result = guest.inject(syscall).await?;
            eprintln!(
                "exit-files completed read tid={} result={result}",
                guest.tid()
            );
            return Ok(result);
        }
        if syscall.number() == Sysno::exit || syscall.number() == Sysno::exit_group {
            eprintln!(
                "exit-files terminal syscall tid={} status={}",
                guest.tid(),
                args.arg0
            );
        }
        guest.tail_inject(syscall).await
    }
}
const EXIT_FILES_GUEST: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
static void *worker(void *unused) { (void)unused; syscall(SYS_exit, 0); return 0; }
int main(int argc, char **argv) {
  if (argc != 2) return 60;
  int p[2];
  if (pipe(p)) return 61;
  if (argv[1][0] == '2') {
    pthread_t thread;
    if (pthread_create(&thread, 0, worker, 0) || pthread_join(thread, 0)) return 62;
    if (fcntl(p[1], F_GETFD) < 0 || write(p[1], "x", 1) != 1 || close(p[1])) return 63;
    char byte = 0;
    if (read(p[0], &byte, 1) != 1 || byte != 'x' || read(p[0], &byte, 1) != 0) return 64;
    return write(1, "EOF\n", 4) != 4;
  }
  long child = syscall(SYS_fork);
  if (child < 0) return 65;
  if (!child) {
    if (close(p[1])) return 66;
    char byte;
    if (read(p[0], &byte, 1) != 0) return 67;
    if (write(1, "EOF\n", 4) != 4) return 68;
    syscall(SYS_exit_group, 0);
  }
  if (close(p[0])) return 69;
  if (argv[1][0] == '1' && close(p[1])) return 70;
  syscall(SYS_exit_group, 0);
  return 71;
}
"#;
fn run_exit_files(test: &str, mode: &str) {
    if std::env::var_os("REVERIE_EXIT_FILES_CHILD").as_deref() != Some(std::ffi::OsStr::new(test)) {
        let status = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "10s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("REVERIE_EXIT_FILES_CHILD", test)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "exit-files subprocess did not complete: {status:?}"
        );
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "terminal-exit-files", EXIT_FILES_GUEST);
    let native = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "5s"])
        .arg(&executable)
        .arg(mode)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "native failed: {native:?}");
    assert_eq!(native.stdout, b"EOF\n");
    assert!(native.stderr.is_empty());
    eprintln!("exit-files native mode={mode} code=0 exact_stdout=EOF");
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&executable).unwrap(),
            &[executable.to_str().unwrap(), mode],
            &[],
            &directory.0,
        )
        .unwrap();
    let (_, status, stdout, stderr) =
        futures::executor::block_on(backend.run_static_elf_with_tool::<ExitFilesTool>((), true))
            .unwrap();
    assert_eq!(status, 0);
    assert_eq!(stdout, b"EOF\n");
    assert!(stderr.is_empty());
}
#[test]
fn terminal_exit_releases_parent_pipe_writer_before_joining_child() {
    run_exit_files(
        "terminal_fork::terminal_exit_releases_parent_pipe_writer_before_joining_child",
        "0",
    );
}
#[test]
fn terminal_exit_explicit_pipe_close_control() {
    run_exit_files(
        "terminal_fork::terminal_exit_explicit_pipe_close_control",
        "1",
    );
}
#[test]
fn terminal_exit_preserves_live_sibling_shared_files() {
    run_exit_files(
        "terminal_fork::terminal_exit_preserves_live_sibling_shared_files",
        "2",
    );
}

impl TerminalRouteTool {
    async fn wait_for_parent_exit(&self, tid: i32) {
        let hook = if self.mode == 18 {
            "process-exit"
        } else {
            "thread-exit"
        };
        let state = self.control.state.lock().unwrap();
        let (state, timeout) = self
            .control
            .changed
            .wait_timeout_while(state, Duration::from_secs(5), |state| {
                !state
                    .events
                    .iter()
                    .any(|event| event.kind == hook && event.pid == 1)
            })
            .unwrap();
        let acknowledged = state
            .events
            .iter()
            .any(|event| event.kind == hook && event.pid == 1);
        drop(state);
        assert!(
            !timeout.timed_out(),
            "parent hook did not precede fork completion"
        );
        self.control
            .record("parent-exit-ack", tid, i64::from(acknowledged));
    }
}
fn run_parent_exit_ack(test: &str, mode: u8) {
    if !bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let executable = compile_c_program(&directory.0, "terminal-parent-ack", TERMINAL_ROUTE_GUEST);
    let control = Arc::new(Control::default());
    *CONTROL.lock().unwrap() = Some(control.clone());
    let capture = control.clone();
    let cwd = directory.0.clone();
    let (send, recv) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_file_with_context(
                std::fs::File::open(&executable).unwrap(),
                &[executable.to_str().unwrap()],
                &[],
                &cwd,
            )
            .unwrap();
        let result = futures::executor::block_on(
            backend.run_static_elf_with_tool::<TerminalRouteTool>(mode, true),
        );
        send.send((result, snapshot_at_return(&capture))).unwrap();
    });
    let state = control.state.lock().unwrap();
    let (state, timeout) = control
        .changed
        .wait_timeout_while(state, Duration::from_secs(5), |state| !state.parent_ready)
        .unwrap();
    assert!(!timeout.timed_out(), "parent never reached exit: {state:?}");
    drop(state);
    // Only the required parent hook may release the fork; there is no timed
    // fallback that can manufacture child progress before that acknowledgment.
    let (result, (events, global_dropped)) = recv.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
    eprintln!("parent-exit acknowledgment mode={mode} result={result:?} events={events:?}");
    let (global, status, stdout, stderr) = result.unwrap();
    assert_eq!(status, 0);
    assert_eq!(
        stdout,
        if mode != 15 {
            b"child\n".as_slice()
        } else {
            b""
        }
    );
    assert_eq!(
        stderr,
        if mode != 15 {
            b"child stderr\n".as_slice()
        } else {
            b""
        }
    );
    let tids = if mode == 16 {
        vec![1, 2, 3]
    } else {
        vec![1, 2]
    };
    for &tid in &tids {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.pid == tid && event.kind == "thread-exit")
                .count(),
            1
        );
    }
    for &tid in &tids[1..] {
        assert_eq!(
            events
                .iter()
                .filter(|event| event.pid == tid && event.kind == "host-exit")
                .count(),
            1
        );
        assert!(!events.iter().any(|event| event.pid == tid
            && event.kind == "host-memory-at-return"
            && event.value != 0));
    }
    let child = if mode == 16 { 3 } else { 2 };
    for pid in if mode != 15 { vec![1, child] } else { vec![1] } {
        for kind in ["process-exit", "tool-drop"] {
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.pid == pid && event.kind == kind)
                    .count(),
                1
            );
        }
    }
    let hook = if mode == 18 {
        "process-exit"
    } else {
        "thread-exit"
    };
    let parent = events
        .iter()
        .position(|event| event.kind == hook && event.pid == 1)
        .unwrap();
    if mode == 15 || mode == 16 {
        let worker = events
            .iter()
            .position(|event| event.kind == "thread-exit" && event.pid == 2)
            .unwrap();
        assert!(
            worker < parent,
            "leader must observe completed worker hooks"
        );
    }
    if mode != 15 {
        let ack = events
            .iter()
            .position(|event| {
                event.kind == "parent-exit-ack" && event.pid == child && event.value == 1
            })
            .expect("parent exit was not acknowledged before child progress");
        assert!(parent < ack);
    }
    assert!(!global_dropped);
    drop(global);
    assert!(control.state.lock().unwrap().global_dropped);
    *CONTROL.lock().unwrap() = None;
}
#[test]
fn terminal_parent_thread_exit_precedes_fork_join() {
    run_parent_exit_ack(
        "terminal_fork::terminal_parent_thread_exit_precedes_fork_join",
        14,
    );
}
#[test]
fn terminal_worker_thread_exit_precedes_leader_hook() {
    run_parent_exit_ack(
        "terminal_fork::terminal_worker_thread_exit_precedes_leader_hook",
        15,
    );
}

#[test]
fn terminal_exit_releases_reserved_stdin_description() {
    use std::io::Read;
    use std::os::fd::FromRawFd;
    const TEST: &str = "terminal_fork::terminal_exit_releases_reserved_stdin_description";
    if !bounded(TEST) {
        return;
    }
    // dup(0); close(0); exit(0). A legal write-only fd 0 and its guest alias
    // must both lose this process's references at exit, even while the backend
    // object itself remains alive. No byte is written to the pipe.
    let code = [
        0xb8, 32, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0xb8, 3, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, 0xb8,
        60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05,
    ];
    let image = static_elf(&code);
    let directory = TestDirectory::new();
    let executable = directory.0.join("exit-reserved-stdin");
    std::fs::write(&executable, &image).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    for native in [true, false] {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
            0
        );
        let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let mut backend = None;
        if native {
            let status = std::process::Command::new(&executable)
                .stdin(std::process::Stdio::from(writer))
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(0));
        } else {
            let mut vm = KvmBackend::new_with_stdin(MEMORY_SIZE, Some(writer)).unwrap();
            vm.install_static_elf(&image, "/bin/exit-reserved-stdin")
                .unwrap();
            let (_, status, stdout, stderr) =
                futures::executor::block_on(vm.run_static_elf_with_tool::<ExitFilesTool>((), true))
                    .unwrap();
            assert_eq!(status, 0);
            assert!(stdout.is_empty() && stderr.is_empty());
            backend = Some(vm);
        }
        let mut byte = [0];
        let observed = reader.read(&mut byte);
        eprintln!(
            "reserved stdin native={native} reader={observed:?} backend_alive={}",
            backend.is_some()
        );
        assert_eq!(
            observed.unwrap(),
            0,
            "exited process retained its reserved stdin description"
        );
        drop(backend);
    }
}

#[test]
fn terminal_parent_thread_exit_precedes_worker_owned_fork_join() {
    run_parent_exit_ack(
        "terminal_fork::terminal_parent_thread_exit_precedes_worker_owned_fork_join",
        16,
    );
}
#[test]
fn terminal_parent_process_exit_precedes_fork_join() {
    run_parent_exit_ack(
        "terminal_fork::terminal_parent_process_exit_precedes_fork_join",
        18,
    );
}
