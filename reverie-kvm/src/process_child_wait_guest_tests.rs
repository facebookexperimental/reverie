/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Real guest instructions and public Direct/Tool APIs; no fake wait publication.
mod blocking_wait_guest_tests {
    use std::ffi::CString;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use reverie::ExitStatus;
    use reverie::GlobalRPC;
    use reverie::GlobalTool;
    use reverie::Guest;
    use reverie::Pid;
    use reverie::Subscription;
    use reverie::Tool;
    use reverie::syscalls::Syscall;
    use reverie::syscalls::Sysno;

    use super::*;
    use crate::KvmBackend;

    const PREFIX: &str = "executor::process_signal_publication::tests::blocking_wait_guest_tests::";
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "reverie-blocked-wait-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn pipe() -> (File, File) {
        let mut fds = [-1; 2];
        // SAFETY: fds is a writable two-element array; each resulting fd is owned once.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }
    fn fifo(path: &Path) -> File {
        let path_c = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path_c is a stable NUL-terminated private path.
        assert_eq!(unsafe { libc::mkfifo(path_c.as_ptr(), 0o600) }, 0);
        // A private RDWR host endpoint prevents FIFO open from becoming a barrier.
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap()
    }
    struct Gates {
        child: File,
        ready: File,
    }
    impl Gates {
        fn new(directory: &Path) -> Self {
            Self {
                child: fifo(&directory.join("child-gate")),
                ready: fifo(&directory.join("waiter-ready")),
            }
        }
        fn native_ready(&mut self) -> std::io::Result<[i32; 2]> {
            let mut pfd = libc::pollfd {
                fd: self.ready.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid initialized pollfd, finite observation deadline.
            if unsafe { libc::poll(&mut pfd, 1, 5000) } != 1 {
                return Err(std::io::Error::other("native before-wait marker absent"));
            }
            let mut bytes = [0; 8];
            self.ready.read_exact(&mut bytes)?;
            Ok([
                i32::from_ne_bytes(bytes[..4].try_into().unwrap()),
                i32::from_ne_bytes(bytes[4..].try_into().unwrap()),
            ])
        }
    }

    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        serde::Serialize,
        serde::Deserialize
    )]
    struct WaitCall {
        tid: i32,
        syscall: i64,
        which: Option<i32>,
        pid: i32,
        options: i32,
    }
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        serde::Serialize,
        serde::Deserialize
    )]
    enum WaitCallback {
        Entered(WaitCall),
        Returned(WaitCall, Result<i64, i32>),
    }
    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    struct WaitThreadState {
        started: bool,
        callbacks: Vec<WaitCallback>,
    }
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    enum WaitEvent {
        Exit(u8, i32, ExitStatus),
        Callbacks(i32, Vec<WaitCallback>),
    }
    #[derive(Debug, Default)]
    struct WaitLog {
        exits: Mutex<Vec<(u8, i32, ExitStatus)>>,
        callbacks: Mutex<std::collections::BTreeMap<i32, Vec<WaitCallback>>>,
    }
    #[reverie::global_tool]
    impl GlobalTool for WaitLog {
        type Request = WaitEvent;
        type Response = ();
        type Config = bool;
        async fn receive_rpc(&self, _: Pid, event: Self::Request) {
            match event {
                WaitEvent::Exit(kind, tid, status) => {
                    self.exits.lock().unwrap().push((kind, tid, status));
                }
                WaitEvent::Callbacks(tid, callbacks) => {
                    assert!(
                        self.callbacks
                            .lock()
                            .unwrap()
                            .insert(tid, callbacks)
                            .is_none(),
                        "duplicate callback-state retirement for tid {tid}"
                    );
                }
            }
        }
    }
    #[derive(Debug, Default)]
    struct WaitTool;
    #[reverie::tool]
    impl Tool for WaitTool {
        type GlobalState = WaitLog;
        type ThreadState = WaitThreadState;
        fn subscriptions(subscribe_waits: &bool) -> Subscription {
            let mut subscriptions = Subscription::none();
            if *subscribe_waits {
                subscriptions.syscalls([Sysno::wait4, Sysno::waitid]);
            }
            subscriptions
        }
        async fn handle_thread_start<G: Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> Result<(), reverie::Error> {
            assert!(!guest.thread_state().started);
            guest.thread_state_mut().started = true;
            Ok(())
        }
        async fn handle_syscall_event<G: Guest<Self>>(
            &self,
            guest: &mut G,
            call: Syscall,
        ) -> Result<i64, reverie::Error> {
            assert!(
                *guest.config(),
                "unsubscribed Tool received a syscall callback"
            );
            let witness = match &call {
                Syscall::Wait4(wait) => WaitCall {
                    tid: guest.tid().as_raw(),
                    syscall: libc::SYS_wait4,
                    which: None,
                    pid: wait.pid(),
                    options: wait.options().bits(),
                },
                Syscall::Waitid(wait) => WaitCall {
                    tid: guest.tid().as_raw(),
                    syscall: libc::SYS_waitid,
                    which: Some(wait.which()),
                    pid: wait.pid(),
                    options: wait.options(),
                },
                other => panic!("unexpected subscribed syscall: {other:?}"),
            };
            // Owned per-thread state survives cancellation of this callback.
            // No ordinary RPC admission can suppress either local observation.
            guest
                .thread_state_mut()
                .callbacks
                .push(WaitCallback::Entered(witness));
            let result = guest.inject(call).await;
            let observed = match &result {
                Ok(value) => Ok(*value),
                Err(error) => Err(error.into_raw()),
            };
            guest
                .thread_state_mut()
                .callbacks
                .push(WaitCallback::Returned(witness, observed));
            Ok(result?)
        }
        async fn on_exit_thread<G: GlobalRPC<WaitLog>>(
            &self,
            tid: Pid,
            global: &G,
            state: WaitThreadState,
            status: ExitStatus,
        ) -> Result<(), reverie::Error> {
            assert!(state.started);
            // Consuming-hook RPC remains available after clean group termination.
            global
                .send_rpc(WaitEvent::Callbacks(tid.as_raw(), state.callbacks))
                .await;
            global
                .send_rpc(WaitEvent::Exit(0, tid.as_raw(), status))
                .await;
            Ok(())
        }
        async fn on_exit_process<G: GlobalRPC<WaitLog>>(
            self,
            pid: Pid,
            global: &G,
            status: ExitStatus,
        ) -> Result<(), reverie::Error> {
            global
                .send_rpc(WaitEvent::Exit(1, pid.as_raw(), status))
                .await;
            Ok(())
        }
    }

    fn bounded(test: &str) -> bool {
        match kvm_ioctls::Kvm::new() {
            Ok(_) => {}
            Err(error) if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "{test} requires /dev/kvm: {error}"
                );
                eprintln!("skipping {test}: cannot open /dev/kvm: {error}");
                return false;
            }
            Err(error) => panic!("cannot probe KVM: {error}"),
        }
        if std::env::var("REVERIE_LEADER_EXEC_CHILD").as_deref() == Ok(test) {
            return true;
        }
        let output = Command::new("timeout")
            .args(["--kill-after=2s", "30s"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture"])
            .env("REVERIE_LEADER_EXEC_CHILD", test)
            .output()
            .unwrap();
        assert!(output.status.success(), "{test}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("test result: ok. 1 passed; 0 failed;"),
            "one named child test must run: {output:?}"
        );
        false
    }
    fn compile(directory: &Path) -> PathBuf {
        let source = directory.join("blocked-wait.c");
        let executable = directory.join("blocked-wait");
        std::fs::write(
            &source,
            include_str!("../tests/fixtures/blocked_sibling_wait.c"),
        )
        .unwrap();
        // Same supported dynamic libc path as existing leader_wait_status.c.
        let output = Command::new("/usr/bin/gcc")
            .args([
                "-O2",
                "-pthread",
                "-fno-pie",
                "-no-pie",
                "-std=gnu11",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Wformat=2",
                "-Werror",
            ])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(output.status.success(), "gcc failed: {output:?}");
        executable
    }
    fn expected(cancel: bool) -> &'static [u8] {
        if cancel {
            b"peer exit_group\nchild released\n"
        } else {
            b"child released\nblocked wait completed\n"
        }
    }

    fn native(
        executable: &Path,
        directory: &Path,
        arguments: &[&str; 3],
        cancel: bool,
        group_status: i32,
    ) {
        let mut gates = Gates::new(directory);
        let (input, mut command) = pipe();
        let mut process = Command::new("timeout")
            .args(["--kill-after=2s", "5s"])
            .arg(executable)
            .args(arguments)
            .current_dir(directory)
            .stdin(Stdio::from(input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = gates.native_ready();
        let sent = command.write_all(if cancel { b"c" } else { b"w" });
        // Native readiness means "about to call", not proof of kernel blocking.
        // Only the KVM observer below proves actual blocked family membership.
        if cancel && ready.is_ok() && sent.is_ok() {
            // Wait for the root process to exit before letting its orphan child
            // finish. wait() does not wait for stdout EOF inherited by the child.
            let status = process.wait();
            let released = gates.child.write_all(b"g");
            let output = process.wait_with_output().unwrap();
            assert!(released.is_ok(), "native release: {released:?}");
            assert_eq!(
                status.unwrap().code(),
                Some(group_status),
                "native group result: {output:?}"
            );
            assert_eq!(output.stdout, expected(cancel));
            assert!(output.stderr.is_empty(), "{output:?}");
        } else {
            let released = gates.child.write_all(b"g");
            let output = process.wait_with_output().unwrap();
            assert!(
                ready.is_ok() && sent.is_ok() && released.is_ok(),
                "native protocol: {ready:?} {sent:?} {released:?}"
            );
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert_eq!(output.stdout, expected(cancel));
            assert!(output.stderr.is_empty(), "{output:?}");
        }
    }

    fn observe(
        registry: Arc<ProcessSignalRegistry>,
        mut command: File,
        mut child_gate: File,
        cancel: bool,
    ) -> Result<(), String> {
        let result = (|| {
            if !registry.wait_for_guest_waiter() {
                return Err("actual child-wait registration absent".to_owned());
            }
            let family = registry.family.lock().unwrap();
            if family.waiters != 1 || family.wait_publications.len() != 1 {
                return Err("expected exactly one actual wait and one live child".to_owned());
            }
            let (&child, publication) = family.wait_publications.first_key_value().unwrap();
            let parent = process_key(publication.parent);
            if publication.phase != WaitPhase::Pending
                || family.terminal.contains_key(&child)
                || family.terminal.contains_key(&parent)
                || family.wait_failed
            {
                return Err(
                    "wait barrier must precede child or parent terminal publication".to_owned(),
                );
            }
            drop(family);
            command
                .write_all(if cancel { b"c" } else { b"w" })
                .map_err(|e| e.to_string())?;
            if cancel {
                let family = registry.family.lock().unwrap();
                let (family, timeout) = registry
                    .wait_changed
                    .wait_timeout_while(family, Duration::from_secs(5), |f| {
                        !f.terminal.contains_key(&parent)
                    })
                    .unwrap();
                if timeout.timed_out()
                    || family.terminal.get(&parent) != Some(&ProcessFamilyExit::Root)
                    || family.wait_failed
                {
                    return Err("clean root group transition was not preserved".to_owned());
                }
            }
            child_gate.write_all(b"g").map_err(|e| e.to_string())?;
            Ok(())
        })();
        // Always unblock real guest owners before reporting an observation error.
        // These best-effort repeats cannot turn that error into success.
        let _ = command.write_all(if cancel { b"c" } else { b"w" });
        let _ = child_gate.write_all(b"g");
        result
    }
    fn hooks(events: Vec<(u8, i32, ExitStatus)>, group_status: i32) {
        let mut actual = events.clone();
        actual.sort_by_key(|(kind, tid, _)| (*kind, *tid));
        let status = ExitStatus::Exited(group_status);
        let mut wanted = vec![
            (0, 3, status),
            (0, 4, status),
            (0, 5, status),
            (0, 6, ExitStatus::Exited(73)),
            (1, 3, status),
            (1, 6, ExitStatus::Exited(73)),
        ];
        wanted.sort_by_key(|(kind, tid, _)| (*kind, *tid));
        assert_eq!(
            actual, wanted,
            "exact lifecycle identity/status/cardinality"
        );
        let index = |kind, tid| {
            events
                .iter()
                .position(|(k, t, _)| *k == kind && *t == tid)
                .unwrap()
        };
        assert!(index(0, 6) < index(1, 6));
        for tid in [3, 4, 5] {
            assert!(index(0, tid) < index(1, 3));
        }
    }
    fn wait_callbacks(
        actual: std::collections::BTreeMap<i32, Vec<WaitCallback>>,
        worker_creator: bool,
        cancel: bool,
        syscall: &str,
        subscribe_waits: bool,
    ) {
        // Same exact four guest thread identities already required by hooks().
        // Compare per-thread order, not the host order of exit-hook delivery.
        let mut expected = std::collections::BTreeMap::from([
            (3, Vec::new()),
            (4, Vec::new()),
            (5, Vec::new()),
            (6, Vec::new()),
        ]);
        if !subscribe_waits {
            assert_eq!(
                actual, expected,
                "unsubscribed Tool must have zero callbacks"
            );
            return;
        }
        let waiter = if worker_creator { 3 } else { 5 };
        let creator = if worker_creator { 5 } else { 3 };
        let wait4 = |tid, options| WaitCall {
            tid,
            syscall: libc::SYS_wait4,
            which: None,
            pid: 6,
            options,
        };
        let waitid = |tid, which, pid, options| WaitCall {
            tid,
            syscall: libc::SYS_waitid,
            which: Some(which),
            pid,
            options,
        };
        let first = match syscall {
            "wait4" => wait4(waiter, 0),
            "waitid" => waitid(waiter, libc::P_PID as i32, 6, libc::WEXITED | libc::WNOWAIT),
            other => panic!("unknown wait case: {other}"),
        };
        if cancel {
            expected
                .get_mut(&waiter)
                .unwrap()
                .push(WaitCallback::Entered(first));
            assert_eq!(
                actual, expected,
                "cancelled wait must enter its exact callback and never return"
            );
            return;
        }
        fn returned(events: &mut Vec<WaitCallback>, call: WaitCall, result: Result<i64, i32>) {
            events.push(WaitCallback::Entered(call));
            events.push(WaitCallback::Returned(call, result));
        }
        let waiter_events = expected.get_mut(&waiter).unwrap();
        if syscall == "wait4" {
            returned(waiter_events, first, Ok(6));
        } else {
            returned(waiter_events, first, Ok(0));
            returned(waiter_events, first, Ok(0));
            returned(
                waiter_events,
                waitid(waiter, libc::P_PID as i32, 6, libc::WEXITED),
                Ok(0),
            );
        }
        // The unchanged guest sends its creator acknowledgment only after the
        // waiter's final ECHILD. That pipe gives the cross-thread causal edge;
        // no ordering is inferred from independent consuming-hook scheduling.
        for tid in [waiter, creator] {
            let events = expected.get_mut(&tid).unwrap();
            returned(events, wait4(tid, libc::WNOHANG), Err(libc::ECHILD));
            returned(
                events,
                waitid(tid, libc::P_ALL as i32, 0, libc::WEXITED | libc::WNOHANG),
                Err(libc::ECHILD),
            );
        }
        assert_eq!(
            actual, expected,
            "exact per-TID injected wait entry/result sequence"
        );
    }
    fn run(name: &str, worker_creator: bool, cancel: bool, tool: bool) {
        run_with_subscriptions(name, worker_creator, cancel, tool, true);
    }
    fn run_with_subscriptions(
        name: &str,
        worker_creator: bool,
        cancel: bool,
        tool: bool,
        subscribe_waits: bool,
    ) {
        let test = format!("{PREFIX}{name}");
        if !bounded(&test) {
            return;
        }
        let directory = Directory::new();
        let executable = compile(&directory.0);
        for &group_status in if cancel { &[0, 61][..] } else { &[0][..] } {
            for syscall in ["waitid", "wait4"] {
                let direction = if worker_creator {
                    "worker-child"
                } else {
                    "leader-child"
                };
                let action = if group_status == 61 {
                    "cancel61"
                } else if cancel {
                    "cancel"
                } else {
                    "publish"
                };
                let arguments = [direction, action, syscall];
                let native_dir = directory.0.join(format!("native-{syscall}-{group_status}"));
                std::fs::create_dir(&native_dir).unwrap();
                native(&executable, &native_dir, &arguments, cancel, group_status);
                let guest_dir = directory.0.join(format!("guest-{syscall}-{group_status}"));
                std::fs::create_dir(&guest_dir).unwrap();
                let gates = Gates::new(&guest_dir);
                let (input, command) = pipe();
                let mut backend =
                    KvmBackend::new_with_stdin(256 * 1024 * 1024, Some(input)).unwrap();
                // Root3 has a real outside namespace init. Root1 orphan refusal is
                // a separate existing contract, not the cancellation behavior here.
                backend.set_root_pid(3).unwrap();
                let argv = [executable.to_str().unwrap(), direction, action, syscall];
                backend
                    .install_static_elf_file_with_context(
                        File::open(&executable).unwrap(),
                        &argv,
                        &[],
                        &guest_dir,
                    )
                    .unwrap();
                let empty_context = ChildWaitContext::test_root();
                let registry = empty_context.registry().unwrap();
                // with_output reuses only this empty registry, registers the real
                // loaded root and overwrites context identity before execution.
                // No child, status, failure or signal is seeded by the test.
                backend.static_elf.as_mut().unwrap().children = empty_context;
                // Keep the ready FIFO endpoint open through the complete guest run.
                let Gates {
                    child,
                    ready: _ready_owner,
                } = gates;
                // Keep the FIFO instance and writer alive until the backend
                // has physically joined its independent child. Parent wait
                // registration does not prove that the child opened this FIFO.
                let child_gate_owner = child.try_clone().unwrap();
                let observer =
                    std::thread::spawn(move || observe(registry, command, child, cancel));
                let result = if tool {
                    futures::executor::block_on(
                        backend.run_static_elf_with_tool::<WaitTool>(subscribe_waits, true),
                    )
                    .map(|(log, code, stdout, stderr)| {
                        (
                            Some((
                                log.exits.into_inner().unwrap(),
                                log.callbacks.into_inner().unwrap(),
                            )),
                            code,
                            stdout,
                            stderr,
                        )
                    })
                } else {
                    backend
                        .run_static_elf_captured()
                        .map(|(code, stdout, stderr)| (None, code, stdout, stderr))
                };
                let observation = observer.join().unwrap();
                drop(child_gate_owner);
                // Preserve both facts before either assertion can hide the other.
                eprintln!("{arguments:?}: observer={observation:?}; backend={result:?}");
                assert_eq!(observation, Ok(()), "{arguments:?}");
                let (events, code, stdout, stderr) = result.unwrap();
                assert_eq!(code, group_status, "{arguments:?}");
                assert_eq!(stdout, expected(cancel), "{arguments:?}");
                assert!(stderr.is_empty(), "{arguments:?}: {stderr:?}");
                if let Some((events, callbacks)) = events {
                    hooks(events, group_status);
                    wait_callbacks(callbacks, worker_creator, cancel, syscall, subscribe_waits);
                }
            }
        }
    }
    #[test]
    fn blocked_worker_wait_is_published_direct() {
        run(
            "blocked_worker_wait_is_published_direct",
            false,
            false,
            false,
        );
    }
    #[test]
    fn blocked_leader_wait_is_published_direct() {
        run(
            "blocked_leader_wait_is_published_direct",
            true,
            false,
            false,
        );
    }
    #[test]
    fn blocked_worker_wait_is_published_tool() {
        run("blocked_worker_wait_is_published_tool", false, false, true);
    }
    #[test]
    fn blocked_leader_wait_is_published_tool() {
        run("blocked_leader_wait_is_published_tool", true, false, true);
    }
    #[test]
    fn blocked_worker_wait_clean_group_exit_direct() {
        run(
            "blocked_worker_wait_clean_group_exit_direct",
            false,
            true,
            false,
        );
    }
    #[test]
    fn blocked_leader_wait_clean_group_exit_direct() {
        run(
            "blocked_leader_wait_clean_group_exit_direct",
            true,
            true,
            false,
        );
    }
    #[test]
    fn blocked_worker_wait_clean_group_exit_tool() {
        run(
            "blocked_worker_wait_clean_group_exit_tool",
            false,
            true,
            true,
        );
    }
    #[test]
    fn blocked_leader_wait_clean_group_exit_tool() {
        run(
            "blocked_leader_wait_clean_group_exit_tool",
            true,
            true,
            true,
        );
    }
    #[test]
    fn blocked_worker_wait_is_published_unsubscribed_tool() {
        run_with_subscriptions(
            "blocked_worker_wait_is_published_unsubscribed_tool",
            false,
            false,
            true,
            false,
        );
    }
    #[test]
    fn blocked_worker_wait_clean_group_exit_unsubscribed_tool() {
        run_with_subscriptions(
            "blocked_worker_wait_clean_group_exit_unsubscribed_tool",
            false,
            true,
            true,
            false,
        );
    }
    #[test]
    fn blocked_leader_wait_is_published_unsubscribed_tool() {
        run_with_subscriptions(
            "blocked_leader_wait_is_published_unsubscribed_tool",
            true,
            false,
            true,
            false,
        );
    }
    #[test]
    fn blocked_leader_wait_clean_group_exit_unsubscribed_tool() {
        run_with_subscriptions(
            "blocked_leader_wait_clean_group_exit_unsubscribed_tool",
            true,
            true,
            true,
            false,
        );
    }
}
