/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::ffi::OsString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::LazyLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[cfg(target_arch = "x86_64")]
use reverie::CpuIdResult;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
#[cfg(target_arch = "x86_64")]
use reverie::Rdtsc;
#[cfg(target_arch = "x86_64")]
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tid;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Addr;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_liteinst::LiteinstBackend;
use reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV;
use reverie_ptrace::testing::assert_at_target_unless_witnessed;

// Linux truncates PR_SET_NAME to 15 bytes.  Give every concurrently running
// fixture a distinct, exact-width marker so one test never mistakes another
// test's still-live process (or terminal zombie awaiting its own reaper) for a
// cleanup failure.  The cleanup assertions remain fail-closed: they still
// require zero processes carrying this test's marker.
static PROCESS_NAME_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique_process_name() -> String {
    let sequence = PROCESS_NAME_SEQUENCE.fetch_add(1, Ordering::SeqCst) & 0x000f_ffff;
    let identity = ((std::process::id() as u64) << 20) | sequence;
    format!("li{:013x}", identity)
}

#[derive(Debug, Default)]
struct EventCounter {
    delivered: AtomicU64,
    task_creation_events: AtomicU64,
    cpuid_events: AtomicU64,
    cpuid_interception: AtomicU64,
    rdtsc_events: AtomicU64,
    last_getpid_rip: AtomicU64,
    last_getpid_r12: AtomicU64,
    helper_mprotect_callbacks: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for EventCounter {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, increment: u64) {
        if increment & (1_u64 << 63) != 0 {
            self.last_getpid_rip
                .store(increment & ((1_u64 << 62) - 1), Ordering::SeqCst);
            self.delivered.fetch_add(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 62) != 0 {
            self.last_getpid_r12
                .store(increment & ((1_u64 << 62) - 1), Ordering::SeqCst);
        } else if increment & (1_u64 << 61) != 0 {
            self.helper_mprotect_callbacks
                .fetch_add(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 60) != 0 {
            self.cpuid_events.fetch_add(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 59) != 0 {
            self.rdtsc_events.fetch_add(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 58) != 0 {
            self.cpuid_interception.store(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 57) != 0 {
            self.task_creation_events.fetch_add(1, Ordering::SeqCst);
        } else {
            self.delivered.fetch_add(increment, Ordering::SeqCst);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Default)]
struct ActivationCpuEvents;

#[cfg(target_arch = "x86_64")]
#[reverie::tool]
impl Tool for ActivationCpuEvents {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::all()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), reverie::Errno> {
        if guest.has_cpuid_interception() {
            guest.send_rpc(1_u64 << 58).await;
        }
        Ok(())
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        guest.send_rpc(1_u64 << 60).await;
        // Keep the loader's required x86-64 feature floor while proving that
        // the Tool, rather than the guest, decides the observed result.
        let native = std::arch::x86_64::__cpuid_count(eax, ecx);
        Ok(CpuIdResult {
            eax: native.eax,
            ebx: native.ebx,
            ecx: native.ecx,
            edx: native.edx,
        })
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        guest.send_rpc(1_u64 << 59).await;
        Ok(RdtscResult {
            tsc: 0x1234_5678,
            aux: (request == Rdtsc::Tscp).then_some(0x42),
        })
    }
}

#[derive(Default)]
struct CountSyscalls;

#[derive(Debug, Default)]
struct ExecEvents {
    events: std::sync::Mutex<Vec<(u64, u64, u64)>>,
}

#[reverie::global_tool]
impl GlobalTool for ExecEvents {
    type Request = (u64, u64, u64);
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, event: Self::Request) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
struct ExecTool;

#[reverie::tool]
impl Tool for ExecTool {
    type GlobalState = ExecEvents;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid, Sysno::execve, Sysno::execveat]
            .into_iter()
            .collect()
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), reverie::Errno> {
        // A successful exec has a new initial stack. In particular, a Tool
        // callback must not read registers from the replaced hook frame.
        let regs = guest.regs().await;
        let argc: u64 = guest
            .memory()
            .read_value(Addr::from_raw(regs.rsp as usize).unwrap())?;
        guest.send_rpc((0, argc, 0)).await;
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state
            .send_rpc((
                4,
                pid.as_raw() as u64,
                u64::from(exit_status == ExitStatus::Exited(0)),
            ))
            .await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        if nr == Sysno::getpid && args.arg0 == 0x6e786578 {
            guest
                .send_rpc((1, args.arg1 as u64, args.arg2 as u64))
                .await;
            return Ok(0x4242);
        }
        if matches!(nr, Sysno::execve | Sysno::execveat) {
            guest.send_rpc((2, nr as u64, 0)).await;
        }
        match guest.inject(syscall).await {
            Ok(value) => Ok(value),
            Err(error) => {
                guest
                    .send_rpc((3, nr as u64, error.into_raw() as u64))
                    .await;
                Err(error.into())
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_reactivates_after_exec() {
    let (_directory, guest) = compile_fixture("hybrid_exec_generation.c");
    for mode in ["cold", "hot", "execveat"] {
        let mut command = Command::new(&guest);
        command.arg(mode).arg("0");
        let (output, global) = tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(
                command,
                (),
                preload_path(),
            ),
        )
        .await
        .expect("exec did not finish")
        .unwrap();
        assert!(output.status.success(), "mode={mode} output={output:?}");
        assert_eq!(output.stdout, b"exec-generations-finished\n", "mode={mode}");
        let events = global.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 0)
                .copied()
                .collect::<Vec<_>>(),
            vec![(0, 3, 0); 3],
            "mode={mode} events={events:?}"
        );
        let next_exec = if mode == "execveat" {
            Sysno::execveat
        } else {
            Sysno::execve
        };
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 2)
                .copied()
                .collect::<Vec<_>>(),
            vec![
                (2, Sysno::execve as u64, 0),
                (2, next_exec as u64, 0),
                (2, next_exec as u64, 0)
            ],
            "initial launch and two replacement execs: mode={mode} events={events:?}"
        );
        let stages = if mode == "cold" { 2..3 } else { 0..3 };
        let expected = stages
            .flat_map(|stage| (0..3).map(move |i| (1, stage, i)))
            .collect::<Vec<_>>();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 1)
                .copied()
                .collect::<Vec<_>>(),
            expected,
            "mode={mode} events={events:?}"
        );
        assert!(
            !events.iter().any(|e| e.0 == 3),
            "mode={mode} events={events:?}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_failed_exec_preserves_installed_site() {
    let (_directory, guest) = compile_fixture("hybrid_exec_generation.c");
    let mut command = Command::new(guest);
    command.arg("failed").arg("0");
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(command, (), preload_path()),
    )
    .await
    .expect("failed exec did not return")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"failed-exec-preserved\n");
    let events = global.events.lock().unwrap();
    assert_eq!(events.iter().filter(|e| e.0 == 0).count(), 1, "{events:?}");
    assert_eq!(events.iter().filter(|e| e.0 == 1).count(), 6, "{events:?}");
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 3)
            .copied()
            .collect::<Vec<_>>(),
        vec![
            (3, Sysno::execve as u64, libc::ENOENT as u64),
            (3, Sysno::execveat as u64, libc::ENOENT as u64)
        ],
        "{events:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_worker_exec_is_refused_and_reaped() {
    for mode in ["worker", "worker-execveat"] {
        let (_directory, guest) = compile_fixture("hybrid_thread_exec.c");
        let files = tempfile::tempdir().unwrap();
        let ids = files.path().join("ids");
        let marker = files.path().join("entered");
        let mut command = Command::new(guest);
        command.arg(mode).arg(&ids).arg(&marker);
        let unrelated = UnrelatedStoppedProcess::spawn();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(
                command,
                (),
                preload_path(),
            ),
        )
        .await
        .expect("nonleader exec did not reach session cleanup");
        let error = result.expect_err("nonleader exec unexpectedly reported success");
        let ids = fs::read_to_string(ids).unwrap();
        let ids = ids
            .split_whitespace()
            .map(|id| id.parse::<u32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2, "{ids:?}");
        let (pid, former_tid) = (ids[0], ids[1]);
        assert_ne!(pid, former_tid, "the exec caller was not a worker");
        let text = error.to_string();
        assert_eq!(
            text,
            format!(
                "reject LiteInst post-start exec failed for tracee {pid}: exec requires the original thread-group leader (former tid {former_tid}, event tid {pid}, pid {pid})"
            ),
            "mode={mode}: nonleader exec did not retain its precise refusal"
        );
        assert!(!marker.exists(), "nonleader exec reached application entry");
        eprintln!("mode={mode}: {text}; identities={ids:?}");
        assert_pid_reaped(pid);
        assert_pid_reaped(former_tid);
        unrelated.assert_live_and_unreaped();
        unrelated.kill_and_reap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_worker_failed_exec_preserves_the_running_image() {
    let (_directory, guest) = compile_fixture("hybrid_thread_exec.c");
    let files = tempfile::tempdir().unwrap();
    let ids = files.path().join("ids");
    let marker = files.path().join("entered");
    let mut command = Command::new(guest);
    command.arg("failed").arg(&ids).arg(&marker);
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(3),
        LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(command, (), preload_path()),
    )
    .await
    .expect("worker failed exec did not continue")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"worker-failed-exec-preserved\n");
    assert!(!marker.exists(), "failed exec replaced the application");
    let events = global.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 0)
            .copied()
            .collect::<Vec<_>>(),
        vec![(0, 4, 0)],
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 1)
            .copied()
            .collect::<Vec<_>>(),
        vec![(1, 4, 0), (1, 4, 1)],
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 2)
            .copied()
            .collect::<Vec<_>>(),
        vec![
            (2, Sysno::execve as u64, 0),
            (2, Sysno::execve as u64, 0),
            (2, Sysno::execveat as u64, 0)
        ],
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 3)
            .copied()
            .collect::<Vec<_>>(),
        vec![
            (3, Sysno::execve as u64, libc::ENOENT as u64),
            (3, Sysno::execveat as u64, libc::ENOENT as u64)
        ],
        "{events:?}"
    );
    let ids = fs::read_to_string(ids).unwrap();
    let ids = ids
        .split_whitespace()
        .map(|id| id.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1]);
    assert_pid_reaped(ids[0]);
    assert_pid_reaped(ids[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_exec_during_preinit_is_refused_and_reaped() {
    let (_directory, guest) = compile_fixture("hybrid_exec_during_preinit.c");
    let files = tempfile::tempdir().unwrap();
    let ids = files.path().join("pid");
    let marker = files.path().join("entered");
    let mut command = Command::new(guest);
    command.arg("start").arg(&ids).arg(&marker);
    let error = run_fail_closed_and_assert_reaped(command, &ids).await;
    let pid = fs::read_to_string(ids).unwrap();
    let pid = pid.trim().parse::<u32>().unwrap();
    assert!(
        error.to_string().contains(&format!(
            "reject LiteInst post-start exec failed for tracee {pid}: exec requires an activated thread-group leader (phase Waiting, tid {pid}, pid {pid})"
        )),
        "exec during real ELF preinit did not retain its phase refusal: {error}"
    );
    assert!(!marker.exists(), "preinit exec reached application entry");
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_leader_exec_with_a_live_sibling_reactivates() {
    let (_directory, guest) = compile_fixture("hybrid_thread_exec.c");
    let files = tempfile::tempdir().unwrap();
    let ids = files.path().join("ids");
    let marker = files.path().join("entered");
    let mut command = Command::new(guest);
    command.arg("leader").arg(&ids).arg(&marker);
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(3),
        LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(command, (), preload_path()),
    )
    .await
    .expect("leader exec with a live sibling did not complete")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"threaded-leader-exec-followed\n");
    assert_eq!(fs::read(marker).unwrap(), b"entered\n");
    let events = global.events.lock().unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 0)
            .copied()
            .collect::<Vec<_>>(),
        vec![(0, 4, 0); 2],
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 1)
            .copied()
            .collect::<Vec<_>>(),
        vec![(1, 4, 0)],
        "{events:?}"
    );
    assert_eq!(
        events
            .iter()
            .filter(|e| e.0 == 2)
            .copied()
            .collect::<Vec<_>>(),
        vec![(2, Sysno::execve as u64, 0); 2],
        "{events:?}"
    );
    assert!(!events.iter().any(|e| e.0 == 3), "{events:?}");
    let ids = fs::read_to_string(ids).unwrap();
    let ids = ids
        .split_whitespace()
        .map(|id| id.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert_ne!(ids[0], ids[1]);
    assert_pid_reaped(ids[0]);
    assert_pid_reaped(ids[1]);
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_exec_requires_preload_and_selector_before_entry() {
    let (_directory, guest) = compile_fixture("hybrid_exec_generation.c");
    let markers = tempfile::tempdir().unwrap();
    for mode in ["drop-preload", "drop-selector"] {
        let marker = markers.path().join(mode);
        let mut command = Command::new(&guest);
        command.arg(mode).arg(&marker);
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(
                command,
                (),
                preload_path(),
            ),
        )
        .await
        .expect("missing-runtime exec did not reach the entry guard");
        let error = result.expect_err("exec without the required runtime reported success");
        assert!(
            error
                .to_string()
                .contains("verify LiteInst runtime before executable entry failed")
                && error
                    .to_string()
                    .contains("before the required preload handshake completed"),
            "mode={mode}: {error}"
        );
        assert!(
            !marker.exists(),
            "mode={mode} reached its first application side effect"
        );
        let pid = error
            .to_string()
            .split("tracee ")
            .nth(1)
            .and_then(|suffix| suffix.split(':').next())
            .and_then(|pid| pid.parse::<u32>().ok())
            .expect("entry guard omitted tracee identity");
        assert_pid_reaped(pid);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_fork_child_exec_completes_before_and_after_root_exit() {
    const CHILD_ENV: &str = "REVERIE_LITEINST_FORK_EXEC_REAPER_TEST_CHILD";
    const TEST: &str = "host_hybrid_fork_child_exec_completes_before_and_after_root_exit";
    if std::env::var(CHILD_ENV).as_deref() != Ok(TEST) {
        use std::os::unix::process::CommandExt;

        // Own the orphan's real-parent wait as well as its ptrace wait. A
        // foreign init/subreaper may retain a released zero-exit zombie after
        // the backend returns. Isolate this process-wide setting from every
        // other test, and keep the immediate reaping assertions below intact.
        let mut child = ProcessCommand::new(std::env::current_exe().unwrap());
        child
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, TEST);
        // SAFETY: the post-fork callback makes only the Linux prctl syscall;
        // it does not allocate, lock, or alter the parent test process.
        unsafe {
            child.pre_exec(|| {
                if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = child.status().unwrap();
        assert!(
            status.success(),
            "isolated fork/exec reaping test failed: {status}"
        );
        return;
    }
    let mut subreaper: libc::c_int = 0;
    // SAFETY: PR_GET_CHILD_SUBREAPER writes one integer to this live pointer.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper, 0, 0, 0) },
        0
    );
    assert_eq!(subreaper, 1, "isolated test must own the real-parent reap");

    for fixture in ["hybrid_fork_exec.c", "hybrid_fork_exec_after_root_exit.c"] {
        let (_directory, guest) = compile_fixture(fixture);
        let name = unique_process_name();
        let pids = tempfile::tempdir().unwrap();
        let pid_file = pids.path().join("root.pid");
        let mut command = Command::new(guest);
        command.arg(&name).arg(&pid_file);
        let (output, global) = tokio::time::timeout(
            Duration::from_secs(10),
            LiteinstBackend::run_host_with_output_and_preload::<ExecTool>(
                command,
                (),
                preload_path(),
            ),
        )
        .await
        .expect("forked exec did not complete")
        .unwrap();
        assert_eq!(
            output.status,
            ExitStatus::Exited(0),
            "fixture={fixture} {output:?}"
        );
        assert_eq!(
            output.stdout, b"fork-exec-root-finished\n",
            "fixture={fixture} {output:?}"
        );
        let events = global.events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 0)
                .copied()
                .collect::<Vec<_>>(),
            vec![(0, 3, 0), (0, 1, 0)],
            "fixture={fixture} {events:?}"
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| e.0 == 2)
                .copied()
                .collect::<Vec<_>>(),
            vec![(2, Sysno::execve as u64, 0); 2],
            "fixture={fixture} {events:?}"
        );
        assert!(
            !events.iter().any(|e| e.0 == 3),
            "fixture={fixture} {events:?}"
        );
        let exits = events
            .iter()
            .filter(|e| e.0 == 4)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(exits.len(), 2, "fixture={fixture} {events:?}");
        assert!(
            exits.iter().all(|e| e.2 == 1),
            "fixture={fixture} {events:?}"
        );
        assert_ne!(exits[0].1, exits[1].1, "fixture={fixture} {events:?}");
        let root_pid: u32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(
            exits.iter().any(|e| e.1 == root_pid as u64),
            "fixture={fixture} {events:?}"
        );
        for exit in exits {
            assert_pid_reaped(exit.1 as u32);
        }
        assert_processes_named_eventually_reaped(&name, "completed exec left a process behind");
    }
}

#[reverie::tool]
impl Tool for CountSyscalls {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getrandom, Sysno::getpid, Sysno::mprotect]
            .into_iter()
            .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert!(matches!(
            syscall.number(),
            Sysno::getrandom | Sysno::getpid | Sysno::mprotect
        ));
        if syscall.number() == Sysno::getpid {
            let regs = guest.regs().await;
            guest.send_rpc((1_u64 << 62) | regs.r12).await;
            guest.send_rpc((1_u64 << 63) | regs.rip).await;
        } else if syscall.number() == Sysno::mprotect {
            guest.send_rpc(1_u64 << 61).await;
        } else {
            guest.send_rpc(1).await;
        }
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct PassthroughGetpid;

#[reverie::tool]
impl Tool for PassthroughGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct PassthroughGetpidAndTaskCreation;

#[reverie::tool]
impl Tool for PassthroughGetpidAndTaskCreation {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [
            Sysno::getpid,
            Sysno::clone,
            Sysno::clone3,
            Sysno::fork,
            Sysno::vfork,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            guest.send_rpc(1).await;
        } else {
            assert!(matches!(
                syscall.number(),
                Sysno::clone | Sysno::clone3 | Sysno::fork | Sysno::vfork
            ));
            guest.send_rpc(1_u64 << 57).await;
        }
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct ExitRecorder {
    path: PathBuf,
}

#[reverie::global_tool]
impl GlobalTool for ExitRecorder {
    type Request = i32;
    type Response = ();
    type Config = PathBuf;

    async fn init_global_state(path: &PathBuf) -> Self {
        Self { path: path.clone() }
    }

    async fn receive_rpc(&self, _from: Tid, pid: i32) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{pid}").unwrap();
    }
}

/// Passes through `futex` and the calls that create a task, so that the hybrid
/// discovers the `futex` sites of glibc's timed waits.
#[derive(Default)]
struct PassthroughFutexAndTaskCreation;

#[reverie::tool]
impl Tool for PassthroughFutexAndTaskCreation {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [
            Sysno::futex,
            Sysno::clone,
            Sysno::clone3,
            Sysno::fork,
            Sysno::vfork,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::futex {
            guest.send_rpc(1).await;
        } else {
            guest.send_rpc(1_u64 << 57).await;
        }
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct PassthroughTaskCreationAndRecordExits;

#[reverie::tool]
impl Tool for PassthroughTaskCreationAndRecordExits {
    type GlobalState = ExitRecorder;
    type ThreadState = ();

    fn subscriptions(_config: &PathBuf) -> Subscription {
        [
            Sysno::getpid,
            Sysno::clone,
            Sysno::clone3,
            Sysno::fork,
            Sysno::vfork,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        global_state.send_rpc(pid.as_raw()).await;
        Ok(())
    }
}

#[derive(Default)]
struct PassthroughTaskCreationWithPendingProcessExit;

#[reverie::tool]
impl Tool for PassthroughTaskCreationWithPendingProcessExit {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [
            Sysno::getpid,
            Sysno::clone,
            Sysno::clone3,
            Sysno::fork,
            Sysno::vfork,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        _global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        std::future::pending().await
    }
}

#[derive(Default)]
struct ObservePkey;

#[reverie::tool]
impl Tool for ObservePkey {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid, Sysno::pkey_mprotect].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.send_rpc(1).await;
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct ReplaceGetpid;

#[reverie::tool]
impl Tool for ReplaceGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let replacement = Syscall::from_raw(Sysno::getppid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        Ok(guest.inject(replacement).await?)
    }
}

#[derive(Default)]
struct DoubleInjectGetpid;

#[reverie::tool]
impl Tool for DoubleInjectGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let _ = guest.inject(syscall).await?;
        Ok(guest.inject(syscall).await?)
    }
}

// Prefer the run-time values, which the fbsource BUCK rule sets. The
// compile-time values are paths on the build host and are missing on the test
// host when the binary was built remotely. Cargo sets CARGO_MANIFEST_DIR at run
// time too, but CARGO_BIN_EXE_* only at compile time.
fn build_path(name: &str, compile_time: &str) -> PathBuf {
    std::env::var_os(name).map_or_else(|| PathBuf::from(compile_time), PathBuf::from)
}

/// What `SteppedHookTool` tells its global state.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum SteppedHookNote {
    /// The guest's RCB clock at a getpid.
    Getpid(u64),
    TimerEvent,
}

#[derive(Debug, Default)]
struct SteppedHookEvents {
    /// The guest's RCB clock at each getpid, in order.
    getpid_clocks: std::sync::Mutex<Vec<u64>>,
    timer_events: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for SteppedHookEvents {
    type Request = SteppedHookNote;
    type Response = ();
    /// The timer's RCBs from each getpid to its target.
    type Config = u64;

    async fn receive_rpc(&self, _from: Tid, note: SteppedHookNote) {
        match note {
            SteppedHookNote::Getpid(clock) => self.getpid_clocks.lock().unwrap().push(clock),
            SteppedHookNote::TimerEvent => {
                self.timer_events.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Answers every getpid itself, with 0x4242, and requests a precise timer
/// there.
#[derive(Default)]
struct SteppedHookTool;

#[reverie::tool]
impl Tool for SteppedHookTool {
    type GlobalState = SteppedHookEvents;
    type ThreadState = ();

    fn subscriptions(_config: &u64) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let clock = guest.read_clock()?;
        guest.send_rpc(SteppedHookNote::Getpid(clock)).await;
        let rcbs = *guest.config();
        guest.set_timer_precise(TimerSchedule::Rcbs(rcbs))?;
        Ok(0x4242)
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        guest.send_rpc(SteppedHookNote::TimerEvent).await;
    }
}

fn preload_path() -> PathBuf {
    let launcher = build_path(
        "CARGO_BIN_EXE_reverie-liteinst-strace",
        env!("CARGO_BIN_EXE_reverie-liteinst-strace"),
    );
    let target = launcher.parent().unwrap();
    [
        target.join("libreverie_liteinst.so"),
        target.join("deps/libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the LiteInst preload cdylib")
}

fn compile_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    compile_fixture_with(name, &[])
}

/// Compiles a fixture like `compile_fixture`, passing `extra` to the compiler
/// driver after the source and output.
fn compile_fixture_with(name: &str, extra: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = build_path("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .args(extra)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

/// Compiles the fixture `name` into the shared object `lib<library>.so`, in a
/// new temporary directory, with its executable segment on pages of its own.
fn compile_shared_fixture(name: &str, library: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = build_path("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(format!("lib{library}.so"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args([
            "-std=gnu11",
            "-O0",
            "-shared",
            "-fPIC",
            "-Wl,-z,separate-code",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

fn compile_static_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = build_path("CARGO_MANIFEST_DIR", env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join("li-static-exit");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args([
            "-std=gnu11",
            "-O0",
            "-nostdlib",
            "-static",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-Wl,--build-id=none",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

fn symbol_address(binary: &std::path::Path, symbol: &str) -> u64 {
    let output = ProcessCommand::new("nm").arg(binary).output().unwrap();
    assert!(output.status.success(), "nm failed: {output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == symbol).then(|| u64::from_str_radix(address, 16).unwrap())
        })
        .unwrap_or_else(|| panic!("missing symbol {symbol}"))
}

fn processes_named(name: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").unwrap() {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() == name {
            found.push(pid);
        }
    }
    found
}

fn assert_processes_named_eventually_reaped(name: &str, context: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let remaining = processes_named(name);
        if remaining.is_empty() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            let remaining_status = remaining
                .iter()
                .map(|pid| fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default())
                .collect::<Vec<_>>();
            panic!("{context}: {remaining:?} {remaining_status:?}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn assert_pid_reaped(pid: u32) {
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "failed LiteInst process {pid} remains stopped or unreaped"
    );
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1,
        "failed LiteInst process {pid} still has a waitable state"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "failed LiteInst process {pid} was not fully reaped"
    );
}

struct UnrelatedStoppedProcess {
    child: Option<std::process::Child>,
}

impl UnrelatedStoppedProcess {
    fn spawn() -> Self {
        let child = ProcessCommand::new("/bin/sleep")
            .arg("300")
            .spawn()
            .expect("spawn unrelated process");
        let pid = child.id() as i32;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGSTOP) }, 0);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
            pid,
            "wait for unrelated process to stop"
        );
        assert!(
            libc::WIFSTOPPED(status),
            "unrelated process did not enter a stopped state: {status}"
        );
        Self { child: Some(child) }
    }

    fn assert_live_and_unreaped(&self) {
        let pid = self.child.as_ref().unwrap().id() as i32;
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "cleanup signaled an unrelated process"
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            0,
            "cleanup made an unrelated process waitable"
        );
    }

    fn kill_and_reap(mut self) {
        let mut child = self.child.take().unwrap();
        child.kill().expect("kill unrelated process after bracket");
        child.wait().expect("reap unrelated process after bracket");
    }
}

impl Drop for UnrelatedStoppedProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn is_original_liteinst_session_refusal(text: &str, operation: &str) -> bool {
    text.contains("LiteInst session failed closed in a non-root task")
        && text.contains(&format!("{operation} failed for tracee "))
        && !text.contains("LiteInst tracee cleanup failed")
        && !text.contains("notifier did not acknowledge terminal cleanup")
}

fn assert_original_liteinst_session_refusal(error: &Error, operation: &str) {
    let text = error.to_string();
    assert!(
        is_original_liteinst_session_refusal(&text, operation),
        "session failure did not retain the original refused {operation}, or cleanup replaced it: {text}"
    );
}

#[test]
fn session_refusal_assertion_rejects_terminal_cleanup_wrapper() {
    let original = "LiteInst session failed closed in a non-root task: refuse vfork under the LiteInst hybrid failed for tracee 42: vfork child refused";
    let wrapped = format!(
        "LiteInst tracee cleanup failed after {original}: notifier did not acknowledge terminal cleanup"
    );
    assert!(is_original_liteinst_session_refusal(
        original,
        "refuse vfork under the LiteInst hybrid"
    ));
    assert!(!is_original_liteinst_session_refusal(
        &wrapped,
        "refuse vfork under the LiteInst hybrid"
    ));
    let entry = "LiteInst session failed closed in a non-root task: verify LiteInst runtime before executable entry failed for tracee 42: before the required preload handshake completed";
    assert!(is_original_liteinst_session_refusal(
        entry,
        "verify LiteInst runtime before executable entry"
    ));
    assert!(!is_original_liteinst_session_refusal(entry, "exec"));
    assert!(!is_original_liteinst_session_refusal(
        entry,
        "reject LiteInst post-start exec"
    ));
}

async fn wait_for_pid_file(pid_file: &std::path::Path) -> u32 {
    loop {
        if let Ok(contents) = fs::read_to_string(pid_file)
            && let Ok(pid) = contents.trim().parse::<u32>()
        {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn run_fail_closed_and_assert_reaped(command: Command, pid_file: &std::path::Path) -> Error {
    let mut run = Box::pin(LiteinstBackend::run_host_with_output_and_preload::<
        PassthroughGetpid,
    >(command, (), preload_path()));
    let mut early_result = None;
    let pid = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut run => {
                early_result = Some(result);
                wait_for_pid_file(pid_file).await
            }
            pid = wait_for_pid_file(pid_file) => pid,
        }
    })
    .await
    .expect("fail-closed fixture did not publish its pid");
    let result = if let Some(result) = early_result {
        result
    } else {
        match tokio::time::timeout(Duration::from_secs(3), &mut run).await {
            Ok(result) => result,
            Err(_) => {
                drop(run);
                assert_pid_reaped(pid);
                panic!("fail-closed fixture hung; cancellation cleanup reaped pid {pid}");
            }
        }
    };
    let error = match result {
        Ok(_) => panic!("required LiteInst runtime unexpectedly remained active"),
        Err(error) => error,
    };
    assert_pid_reaped(pid);
    error
}

#[tokio::test(flavor = "current_thread")]
async fn initial_dynamic_preload_handshake_activates_host_lifecycle() {
    let (_directory, guest) = compile_fixture("allocator_getrandom.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<CountSyscalls>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        global.delivered.load(Ordering::SeqCst),
        3,
        "host lifecycle missed allocator/pre-constructor entropy: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn initial_static_image_without_the_runtime_fails_closed() {
    let (_directory, guest) = compile_static_fixture("hybrid_static_exit.c");
    assert!(processes_named("li-static-exit").is_empty());
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("guest.pid");
    let mut command = Command::new(guest);
    command.arg(&pid_file);

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
            command,
            (),
            preload_path(),
        ),
    )
    .await
    .expect("static image did not reach the entry guard");
    let error = result.expect_err("static image unexpectedly passed the entry guard");
    assert!(
        !pid_file.exists(),
        "static image executed its first side-effecting syscall before failing closed"
    );
    assert!(
        error
            .to_string()
            .contains("verify LiteInst runtime before executable entry failed")
            && error
                .to_string()
                .contains("before the required preload handshake completed"),
        "static image did not report the guarded entry boundary: {error}"
    );
    let pid = error
        .to_string()
        .split("tracee ")
        .nth(1)
        .and_then(|suffix| suffix.split(':').next())
        .and_then(|pid| pid.parse::<u32>().ok())
        .expect("entry-guard error did not identify the exact tracee");
    assert_pid_reaped(pid);
    assert!(
        processes_named("li-static-exit").is_empty(),
        "failed static image remains stopped or unreaped"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn valid_dynamic_run_observes_restored_executable_entry() {
    let (_directory, guest) = compile_fixture("hybrid_entry_guard.c");
    let (output, _global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(output.stdout, b"entry-int3=0\n", "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[cfg(target_arch = "x86_64")]
#[tokio::test(flavor = "current_thread")]
async fn loader_cpu_events_are_determinized_before_ready_and_entry_is_restored() {
    let (_directory, guest) = compile_fixture("hybrid_pre_ready_cpu.c");
    let (output, global) =
        LiteinstBackend::run_host_with_output_and_preload::<ActivationCpuEvents>(
            Command::new(guest),
            (),
            preload_path(),
        )
        .await
        .unwrap();

    assert_eq!(output.stdout, b"entry-int3=0 probe=1\n", "{output:?}");
    assert!(output.status.success(), "{output:?}");
    if global.cpuid_interception.load(Ordering::SeqCst) == 1 {
        assert!(
            global.cpuid_events.load(Ordering::SeqCst) >= 1,
            "the pre-constructor IFUNC CPUID did not reach the Tool despite verified kernel interception"
        );
    } else {
        assert_eq!(
            global.cpuid_events.load(Ordering::SeqCst),
            0,
            "CPUID reached the Tool after the kernel reported interception unavailable"
        );
    }
    assert!(
        global.rdtsc_events.load(Ordering::SeqCst) >= 1,
        "the pre-constructor IFUNC RDTSC did not reach the Tool"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn exec_without_preload_reaches_application_entry_guard() {
    let (_directory, guest) = compile_fixture("hybrid_exec_drop_preload.c");
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("guest.pid");
    let mut command = Command::new(guest);
    command.arg(&pid_file);

    let error = run_fail_closed_and_assert_reaped(command, &pid_file).await;
    assert!(
        error
            .to_string()
            .contains("verify LiteInst runtime before executable entry failed")
            && error
                .to_string()
                .contains("before the required preload handshake completed"),
        "post-start exec did not report the lost runtime boundary: {error}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn first_site_is_installed_once_and_hot_calls_use_liteinst() {
    let (_baseline_directory, baseline_guest) = compile_fixture("allocator_getrandom.c");
    let (baseline_output, baseline_global) = LiteinstBackend::run_host_with_output_and_preload::<
        CountSyscalls,
    >(Command::new(baseline_guest), (), preload_path())
    .await
    .unwrap();
    assert!(baseline_output.status.success(), "{baseline_output:?}");

    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let site = symbol_address(&guest, "reverie_liteinst_hybrid_getpid_site");
    let (output, global, stats) = LiteinstBackend::run_host_with_output_and_preload_and_stats::<
        CountSyscalls,
    >(Command::new(guest), (), preload_path())
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 33, "{output:?}");
    assert_eq!(
        global.last_getpid_rip.load(Ordering::SeqCst),
        site + 2,
        "the host Tool must see the original logical post-syscall RIP"
    );
    assert_eq!(
        global.last_getpid_r12.load(Ordering::SeqCst),
        0x0012_3456_789a_bcde,
        "logical guest R12 must remain distinct from the controller HookContext base"
    );
    assert_eq!(
        global.helper_mprotect_callbacks.load(Ordering::SeqCst)
            - baseline_global
                .helper_mprotect_callbacks
                .load(Ordering::SeqCst),
        0,
        "the patch helper must add zero mprotect Tool callbacks above the loader baseline"
    );
    let decisions = stats.decision_counts();
    assert_eq!(
        decisions.into_iter().sum::<usize>(),
        stats.patch_candidates()
    );
    assert_eq!(stats.distinct_rips(), decisions[0] + decisions[1]);
    assert!(
        decisions[1] >= 1,
        "the known hot site must use a relocated patch: {stats}"
    );
    assert!(
        stats.instruction_length_counts()[3] >= 1,
        "the known hot site begins with a two-byte syscall: {stats}"
    );
    assert_eq!(
        stats.instruction_length_counts().into_iter().sum::<usize>(),
        stats.classified_candidates()
    );
    assert_eq!(
        stats.non_straddling() + stats.cacheline_straddlers(),
        stats.classified_candidates()
    );
    assert_eq!(
        stats.straddle_prefix_counts().into_iter().sum::<usize>(),
        stats.cacheline_straddlers()
    );
    assert!(output.status.success(), "{output:?}");
}

/// A site is patched only when the entry census proves that no known control
/// transfer lands inside the bytes the patch displaces
/// (https://github.com/rrnewton/reverie/issues/812). The fixture branches to
/// two bytes past one syscall, as glibc's posix_madvise does; patching that
/// site made the branch execute the middle of the patch jump.
#[tokio::test(flavor = "current_thread")]
async fn sites_with_an_interior_entry_or_no_unwind_entry_stay_on_ptrace() {
    let (_directory, guest) = compile_fixture("hybrid_interior_entry.c");
    let interior = symbol_address(&guest, "reverie_liteinst_interior_site");
    assert_eq!(
        symbol_address(&guest, "reverie_liteinst_interior_after"),
        interior + 2,
        "the fixture branch must target the byte after the two-byte syscall"
    );
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert!(output.status.success(), "{output:?}");
    // Each site's first syscall calls the patch helper once. The two refused
    // sites then stay on ptrace for all 16 calls; the control site takes its
    // other 16 calls through the patch.
    assert_eq!(
        output.stdout,
        b"interior traps=1 hooks=0 unlisted traps=1 hooks=0 control traps=1 hooks=16\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 49, "{output:?}");
}

/// A `syscall` site in an anonymous executable mapping that the guest makes
/// after LiteInst initialized, as a JIT does, stays on ptrace and still returns
/// the right result (https://github.com/rrnewton/reverie/issues/812).
///
/// LiteInst records its trampoline arenas when it initializes, so this mapping
/// has none and the patch helper cannot patch the site whatever the tracer's
/// entry census says. The census refuses the site as well, because it decodes
/// only file-backed objects. This test therefore does not show the census
/// refusing anything; `an_anonymous_syscall_site_stays_on_the_fallback_path`
/// in `rpc_tool.rs` does, for an anonymous mapping that has an arena.
#[tokio::test(flavor = "current_thread")]
async fn a_site_in_an_executable_mapping_made_after_initialization_stays_on_ptrace() {
    let (_directory, guest) = compile_fixture("hybrid_anonymous_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    // The fixture exits nonzero if either site returns a result other than
    // the process ID.
    assert!(output.status.success(), "{output:?}");
    // Each site's first syscall calls the patch helper once. The helper finds
    // no arena for the anonymous site, so none of its 16 calls enters a hook;
    // the control site takes its other 16 calls through the patch.
    assert_eq!(
        output.stdout, b"anonymous traps=1 hooks=0 control traps=1 hooks=16\n",
        "{output:?}"
    );
    // All 33 calls reach the tool. With no hook entry at the anonymous site,
    // its 16 calls arrived through ptrace stops.
    assert_eq!(global.delivered.load(Ordering::SeqCst), 33, "{output:?}");
}

/// A site in a shared object whose file the guest truncated after LiteInst
/// initialized stays on ptrace, and the run goes on (review finding F7 on
/// https://github.com/rrnewton/reverie/pull/818).
///
/// The guest cuts the file at the start of the object's untouched data pages,
/// so they lie past the end of its file and fault when read. The tracer's
/// entry census for the library site reads them through `/proc/<pid>/mem` and
/// gets `EIO`. The fault is the guest's own doing, so the census refuses the
/// object's sites instead of failing the run. The object's code and unwind
/// table stay in the file, so the site is refused because of the fault: a
/// census that read the cut pages as zeros would patch it. The `keep` run
/// leaves the file alone, and the same site is patched.
#[tokio::test(flavor = "current_thread")]
async fn a_site_in_an_object_cut_short_by_its_guest_stays_on_ptrace() {
    for (mode, expected) in [
        (
            "truncate",
            &b"library traps=1 hooks=0 control traps=1 hooks=16\n"[..],
        ),
        (
            "keep",
            &b"library traps=1 hooks=15 control traps=1 hooks=16\n"[..],
        ),
    ] {
        let (library_directory, library) = compile_shared_fixture(
            "hybrid_truncated_object_lib.c",
            "reverie_liteinst_truncated",
        );
        let library_directory = library_directory.path().to_str().unwrap().to_owned();
        let (_directory, guest) = compile_fixture_with(
            "hybrid_truncated_object.c",
            &[
                "-L",
                &library_directory,
                "-lreverie_liteinst_truncated",
                &format!("-Wl,-rpath,{library_directory}"),
                // Binds the call into the library at load time, before the
                // guest cuts the file that holds the library's symbol tables.
                "-Wl,-z,now",
            ],
        );
        let mut command = Command::new(guest);
        command.arg(&library).arg(mode);
        let (output, global) =
            LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
                command,
                (),
                preload_path(),
            )
            .await
            .unwrap();

        // The fixture exits nonzero if either site returns a result other
        // than the process ID, or if its own read of the untouched pages
        // through /proc/self/mem does not fail with EIO after the cut and
        // succeed without it.
        assert!(output.status.success(), "{mode}: {output:?}");
        // Each site's first call calls the patch helper once. The control
        // site takes its other 16 calls through the patch; the library site
        // takes its other 15 through the patch only when its file is whole.
        assert_eq!(output.stdout, expected, "{mode}: {output:?}");
        assert_eq!(
            global.delivered.load(Ordering::SeqCst),
            33,
            "{mode}: {output:?}"
        );
    }
}

/// A site whose object has a page that the guest made `PROT_NONE` after
/// LiteInst initialized is patched like any other (review finding F7 on
/// https://github.com/rrnewton/reverie/pull/818).
///
/// The tracer's entry census reads the object through `/proc/<pid>/mem`, which
/// reads a page whatever its protection, so the guest's `mprotect` neither
/// refuses the site nor fails the run. A census read through
/// `process_vm_readv`, which honours the protection, fails at that page.
#[tokio::test(flavor = "current_thread")]
async fn a_site_in_an_object_with_a_page_made_unreadable_is_patched() {
    let (_directory, guest) = compile_fixture("hybrid_unreadable_object_page.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    // The fixture exits nonzero if the site returns a result other than the
    // process ID.
    assert!(output.status.success(), "{output:?}");
    // The site's first call calls the patch helper once, and its other 16
    // calls enter the hook. The guarded page still holds its first byte.
    assert_eq!(
        output.stdout, b"control traps=1 hooks=16 guarded=1\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 17, "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn cacheline_straddler_uses_quiescent_patch_and_is_counted() {
    let (_directory, guest) = compile_fixture("hybrid_straddler_site.c");
    let site = symbol_address(&guest, "reverie_liteinst_straddler_site");
    assert_eq!(site % 64, 63, "fixture syscall must straddle a cache line");

    let (output, global, stats) = LiteinstBackend::run_host_with_output_and_preload_and_stats::<
        PassthroughGetpid,
    >(Command::new(guest), (), preload_path())
    .await
    .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"straddler-quiescent-patch-ok\n");
    assert_eq!(global.delivered.load(Ordering::SeqCst), 8);
    assert_eq!(stats.distinct_rips(), 1);
    assert_eq!(stats.patch_candidates(), 1);
    assert_eq!(stats.decision_counts(), [0, 1, 0, 0]);
    assert_eq!(stats.classified_candidates(), 1);
    assert_eq!(stats.cacheline_straddlers(), 1);
    assert_eq!(stats.non_straddling(), 0);
    assert_eq!(stats.instruction_length_counts(), [0, 0, 0, 1, 0]);
    assert_eq!(stats.straddle_prefix_counts(), [1, 0, 0, 0]);
}

#[tokio::test(flavor = "current_thread")]
async fn quiescent_helper_patches_every_cache_line_split_without_calibration() {
    let (_directory, guest) = compile_fixture("hybrid_straddler_sites.c");
    let mut command = Command::new(guest);
    command.env_remove(STRADDLER_STALENESS_TICKS_ENV);
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"offsets=57..63 calls=14 traps=7 hooks=7\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 14, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

async fn run_cpuid_policy_mode(
    mode: Option<&str>,
) -> Option<(reverie::process::Output, EventCounter)> {
    let (_directory, guest) = compile_fixture("hybrid_cpuid_policy.c");
    let mut command = Command::new(guest);
    if let Some(mode) = mode {
        command.arg(mode);
    }
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .unwrap();
    if output.status.code() == Some(77) {
        eprintln!("skipping: this host does not support ARCH_GET_CPUID");
        return None;
    }
    Some((output, global))
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_disabled_cpuid_after_installing_a_site() {
    let Some((output, global)) = run_cpuid_policy_mode(None).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=active calls=32 traps=1 hooks=31 cpuid=0\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_disabled_cpuid_after_fallback() {
    let Some((output, global)) = run_cpuid_policy_mode(Some("fallback")).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=fallback calls=2 traps=1 hooks=0 cpuid=0\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 2, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

async fn run_tsc_policy_mode(
    mode: Option<&str>,
) -> Option<(reverie::process::Output, EventCounter)> {
    let (_directory, guest) = compile_fixture("hybrid_tsc_policy.c");
    let mut command = Command::new(guest);
    if let Some(mode) = mode {
        command.arg(mode);
    }
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .unwrap();
    if output.status.code() == Some(77) {
        eprintln!("skipping: this host does not support PR_GET_TSC/PR_SET_TSC");
        return None;
    }
    Some((output, global))
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_faulting_tsc_after_installing_a_site() {
    let Some((output, global)) = run_tsc_policy_mode(None).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=active calls=32 traps=1 hooks=31 tsc=2\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_faulting_tsc_after_fallback() {
    let Some((output, global)) = run_tsc_policy_mode(Some("fallback")).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=fallback calls=2 traps=1 hooks=0 tsc=2\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 2, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn first_discovery_event_can_replace_the_syscall() {
    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<ReplaceGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn first_discovery_event_can_inject_more_than_once() {
    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<DoubleInjectGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

/// Runs a multi-task fixture that is expected to complete, and requires the
/// guest's own end-of-run marker.
///
/// Exit status alone is not enough: every fixture here prints its marker only
/// after the task it creates has been created, run and reaped, so a regression
/// that skips the task cannot satisfy the assertion by exiting zero.
async fn run_multi_task_fixture<T>(fixture: &str, marker_line: &str) -> EventCounter
where
    T: Tool<GlobalState = EventCounter, ThreadState = ()> + 'static,
{
    let (_directory, guest) = compile_fixture(fixture);
    let name = unique_process_name();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let mut command = Command::new(guest);
    command.arg(&name).arg(&pid_file);
    let (output, global) =
        LiteinstBackend::run_host_with_output_and_preload::<T>(command, (), preload_path())
            .await
            .unwrap_or_else(|error| panic!("hybrid refused to follow {fixture}: {error}"));

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        marker_line.as_bytes(),
        "guest did not reach the end of {fixture}: {output:?}"
    );
    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_pid_reaped(root_pid);
    assert!(
        processes_named(&name).is_empty(),
        "LiteInst root/child remains stopped or as a zombie"
    );
    global
}

/// The hybrid follows a forked child instead of refusing at the clone boundary.
///
/// This exercises the supported fork path end-to-end. It does not independently
/// isolate the root-TID identity and root-stop lease re-arm mechanisms.
#[tokio::test(flavor = "current_thread")]
async fn hybrid_follows_a_forked_child() {
    let global = run_multi_task_fixture::<PassthroughGetpidAndTaskCreation>(
        "hybrid_fork.c",
        "fork-followed\n",
    )
    .await;
    assert!(
        global.task_creation_events.load(Ordering::SeqCst) > 0,
        "the task-subscribing tool did not observe the fork lifecycle"
    );
}

/// The hybrid follows a second thread created with `clone3(CLONE_THREAD)`.
///
/// This exercises the supported thread-creation path end-to-end. It does not
/// independently isolate the task-creating-site patch guard.
#[tokio::test(flavor = "current_thread")]
async fn hybrid_follows_a_created_thread() {
    let global = run_multi_task_fixture::<PassthroughGetpidAndTaskCreation>(
        "hybrid_thread.c",
        "thread-followed\n",
    )
    .await;
    assert!(
        global.task_creation_events.load(Ordering::SeqCst) > 0,
        "the task-subscribing tool did not observe the clone lifecycle"
    );
}

/// A timed wait before the first thread and another after it both time out.
/// On glibc 2.34 the multithreaded wait jumps to the instruction after the
/// single-threaded wait's `syscall`, so the entry census must leave that site
/// on ptrace (<https://github.com/rrnewton/reverie/issues/812>).
#[tokio::test(flavor = "current_thread")]
async fn timed_waits_before_and_after_the_first_thread_both_time_out() {
    run_multi_task_fixture::<PassthroughFutexAndTaskCreation>(
        "hybrid_timed_wait_thread.c",
        "timed-waits-timed-out\n",
    )
    .await;
}

/// The task-subscribing tool remains active without manufacturing a task event
/// when the guest makes subscribed `getpid` calls but creates no task.
#[tokio::test(flavor = "current_thread")]
async fn task_subscriber_does_not_report_task_creation_without_one() {
    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<
        PassthroughGetpidAndTaskCreation,
    >(Command::new(guest), (), preload_path())
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert_eq!(
        global.task_creation_events.load(Ordering::SeqCst),
        0,
        "the tool reported task creation for a single-task fixture: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

/// KNOWN GAP, committed as a reproducer rather than described: two generations
/// of children do not reliably complete under this harness.
///
/// The grandchild's new-task event belongs to a NON-root parent, which is the
/// case the cleanup guard's newborn registration has to cover -- scoping that
/// registration to the root leaves the grandchild unregistered and
/// `handle_new_task` aborts on `stored child event ownership must remain
/// registered`. That much is fixed and this fixture does reach
/// `fork-tree-followed`: it passed once here, and Hermit's
/// `determinism-stress-c/fork-tree` reaches canonical L2 under the real Detcore
/// tool, which sequentializes the guest.
///
/// It is `ignore`d because it is NOT reliable here: after that single pass it
/// wedged with no forward progress on three consecutive runs, under both this
/// tool and a variant that also subscribes to the task-creating syscalls. A
/// flaky hang is worse than no test, so it does not run by default. Do not
/// treat the fix it covers as verified until this is diagnosed and the `ignore`
/// removed.
#[tokio::test(flavor = "current_thread")]
#[ignore = "known gap: second-generation fork does not reliably complete in this harness"]
async fn hybrid_follows_a_grandchild() {
    run_multi_task_fixture::<PassthroughGetpid>("hybrid_fork_tree.c", "fork-tree-followed\n").await;
}

/// A child that removes the required preload before exec fails the whole
/// session; the root must not report the success it would otherwise reach.
/// The original session failure and pending-exit cleanup controls remain
/// necessary now that exec with an inherited preload is supported.
#[tokio::test(flavor = "current_thread")]
async fn a_child_missing_preload_fails_the_session_instead_of_reporting_success() {
    let (_directory, guest) = compile_fixture("hybrid_fork_exec.c");
    let name = unique_process_name();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let exit_file = pid_directory.path().join("process-exits");
    let mut command = Command::new(guest);
    command.arg(&name).arg(&pid_file).arg("drop-preload");
    let result =
        tokio::time::timeout(
            Duration::from_secs(60),
            LiteinstBackend::run_host_with_output_and_preload::<
                PassthroughTaskCreationAndRecordExits,
            >(command, exit_file.clone(), preload_path()),
        )
        .await
        .expect("a failed non-root task was never released from the tool: the session hung");

    let error = match result {
        Ok((output, _global)) => panic!(
            "SILENT GREEN: the session reported success over a child that could not be \
             followed through exec: {output:?}"
        ),
        Err(error) => error,
    };
    assert_original_liteinst_session_refusal(
        &error,
        "verify LiteInst runtime before executable entry",
    );
    assert!(
        error
            .to_string()
            .contains("before the required preload handshake completed")
    );
    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let exits = fs::read_to_string(&exit_file).unwrap_or_default();
    let non_root_exits = exits
        .lines()
        .map(|pid| pid.parse::<i32>().unwrap())
        .filter(|pid| *pid != root_pid as i32)
        .count();
    assert_eq!(
        non_root_exits, 1,
        "the failed non-root process did not run its Tool exit callback: root={root_pid} exits={exits:?}"
    );
    assert_pid_reaped(root_pid);
    assert_processes_named_eventually_reaped(
        &name,
        "failed LiteInst root/child remains stopped or as a zombie",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn missing_preload_entry_guard_reaches_cleanup_while_process_exit_is_pending() {
    let (_directory, guest) = compile_fixture("hybrid_fork_exec.c");
    let name = unique_process_name();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let mut command = Command::new(guest);
    command.arg(&name).arg(&pid_file).arg("drop-preload");

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        LiteinstBackend::run_host_with_output_and_preload::<
            PassthroughTaskCreationWithPendingProcessExit,
        >(command, (), preload_path()),
    )
    .await
    .expect("missing-preload entry guard never reached session cleanup");
    let error = result.expect_err("missing-preload entry guard reported success");
    assert_original_liteinst_session_refusal(
        &error,
        "verify LiteInst runtime before executable entry",
    );
    assert!(
        error
            .to_string()
            .contains("before the required preload handshake completed")
    );

    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_pid_reaped(root_pid);
    assert_processes_named_eventually_reaped(
        &name,
        "missing-preload entry failure left a LiteInst process behind",
    );
}

/// A root that has already exited must stop joining its child when that child
/// reaches the missing-preload entry guard, even if its Tool exit callback is pending.
#[tokio::test(flavor = "current_thread")]
async fn missing_preload_entry_guard_cancels_root_join_while_process_exit_is_pending() {
    let (_directory, guest) = compile_fixture("hybrid_fork_exec_after_root_exit.c");
    let name = unique_process_name();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let mut command = Command::new(guest);
    command.arg(&name).arg(&pid_file).arg("drop-preload");
    let unrelated = UnrelatedStoppedProcess::spawn();

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        LiteinstBackend::run_host_with_output_and_preload::<
            PassthroughTaskCreationWithPendingProcessExit,
        >(command, (), preload_path()),
    )
    .await
    .expect("missing-preload entry guard did not cancel the root's child join");
    let error = result.expect_err("missing-preload entry guard reported success");
    assert_original_liteinst_session_refusal(
        &error,
        "verify LiteInst runtime before executable entry",
    );
    assert!(
        error
            .to_string()
            .contains("before the required preload handshake completed")
    );

    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_pid_reaped(root_pid);
    assert_processes_named_eventually_reaped(
        &name,
        "missing-preload entry failure left a LiteInst process behind",
    );
    unrelated.assert_live_and_unreaped();
    unrelated.kill_and_reap();
}

/// A vfork refusal in a non-root task fails the whole session even when it is
/// recorded only after the root has reached its own clean exit.
#[tokio::test(flavor = "current_thread")]
async fn vfork_in_a_forked_child_fails_the_session_after_root_exit() {
    let (_directory, guest) = compile_fixture("hybrid_fork_vfork.c");
    let name = unique_process_name();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let mut command = Command::new(guest);
    command.arg(&name).arg(&pid_file);
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
            command,
            (),
            preload_path(),
        ),
    )
    .await
    .expect("a refused non-root vfork was never released from the tool: the session hung");

    let error = match result {
        Ok((output, _global)) => panic!(
            "SILENT GREEN: the session reported success before a non-root vfork refusal: {output:?}"
        ),
        Err(error) => error,
    };
    assert_original_liteinst_session_refusal(&error, "refuse vfork under the LiteInst hybrid");
    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_pid_reaped(root_pid);
    assert_processes_named_eventually_reaped(
        &name,
        "failed LiteInst root/child remains stopped or as a zombie",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reused_mapping_invalidates_and_rediscovers_the_syscall_site() {
    let (_directory, guest) = compile_fixture("hybrid_mapping_churn.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(output.stdout, b"reuse traps=2 hooks=0\n", "{output:?}");
    assert_eq!(
        global.delivered.load(Ordering::SeqCst),
        4,
        "both generations must use the correct ptrace fallback: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn moving_a_patched_mapping_rejects_stale_hot_provenance() {
    let (_directory, guest) = compile_fixture("hybrid_mremap_patched.c");
    let command = Command::new(guest);
    let error = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .expect_err("mremap unexpectedly moved a live patched site");

    assert!(
        error
            .to_string()
            .contains("mremap overlaps an active LiteInst hook footprint"),
        "mapping was not rejected by the pre-mutation provenance check: {error}"
    );
}

async fn run_active_footprint_mode(
    mode: &str,
) -> Result<(reverie::process::Output, EventCounter), Error> {
    let (_directory, guest) = compile_fixture("hybrid_active_footprint.c");
    let mut command = Command::new(guest);
    command.arg(mode);
    LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn active_hook_noop_mprotect_preserves_the_hook() {
    for (mode, stdout) in [
        ("noop", "active no-op protection preserved\n"),
        ("short-noop", "active short no-op protection preserved\n"),
    ] {
        let (output, global) = run_active_footprint_mode(mode).await.unwrap();
        assert_eq!(output.stdout, stdout.as_bytes());
        assert_eq!(global.delivered.load(Ordering::SeqCst), 3);
        assert!(output.status.success(), "{output:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn active_hook_mapping_footprints_reject_mprotect_before_mutation() {
    for (mode, syscall) in [
        ("site", "mprotect"),
        ("trampoline", "mprotect"),
        ("arena-rw", "mprotect"),
        ("short-site", "mprotect"),
        ("short-trampoline", "mprotect"),
        ("short-arena-rw", "mprotect"),
        ("short-munmap", "munmap"),
        ("short-map-fixed", "mmap"),
        ("short-mremap", "mremap"),
        ("short-mremap-fixed", "mremap"),
        ("zero-old-mremap-fixed", "mremap"),
    ] {
        let error = run_active_footprint_mode(mode)
            .await
            .expect_err("active footprint mutation unexpectedly completed");
        assert!(
            error.to_string().contains(&format!(
                "{syscall} overlaps an active LiteInst hook footprint"
            )),
            "{mode} footprint was not rejected before mutation: {error}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_mprotect_is_controller_owned_unless_subscribed() {
    let (_directory, guest) = compile_fixture("hybrid_active_footprint.c");
    let mut command = Command::new(&guest);
    command.arg("pkey-noop");
    let (unsubscribed_output, unsubscribed) = LiteinstBackend::run_host_with_output_and_preload::<
        PassthroughGetpid,
    >(command, (), preload_path())
    .await
    .unwrap();

    let mut command = Command::new(guest);
    command.arg("pkey-noop");
    let (subscribed_output, subscribed) = LiteinstBackend::run_host_with_output_and_preload::<
        ObservePkey,
    >(command, (), preload_path())
    .await
    .unwrap();
    assert_eq!(unsubscribed_output.stdout, subscribed_output.stdout);
    assert_eq!(
        subscribed.delivered.load(Ordering::SeqCst),
        unsubscribed.delivered.load(Ordering::SeqCst) + 1,
        "pkey_mprotect must reach the Tool exactly when subscribed"
    );

    let error = run_active_footprint_mode("pkey-site")
        .await
        .expect_err("destructive pkey_mprotect unexpectedly completed");
    assert!(
        error
            .to_string()
            .contains("pkey_mprotect overlaps an active LiteInst hook footprint"),
        "pkey_mprotect was not rejected before mutation: {error}"
    );
}

async fn cancel_host_wait(capture_output: bool) {
    let (_directory, guest) = compile_fixture("hybrid_wait_cancel.c");
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("guest.pid");
    let mut command = Command::new(guest);
    command.arg(&pid_file);

    let mut run = if capture_output {
        Box::pin(LiteinstBackend::run_host_with_output_and_preload::<
            PassthroughGetpid,
        >(command, (), preload_path()))
            as std::pin::Pin<Box<dyn std::future::Future<Output = _>>>
    } else {
        Box::pin(async move {
            LiteinstBackend::run_host_with_preload::<PassthroughGetpid>(command, (), preload_path())
                .await
                .map(|(status, global)| {
                    (
                        reverie::process::Output {
                            status,
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                        },
                        global,
                    )
                })
        })
    };
    let wait_for_pid = async {
        loop {
            if let Ok(contents) = fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.trim().parse::<u32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let pid = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut run => panic!("wait completed before cancellation: {result:?}"),
            pid = wait_for_pid => pid,
        }
    })
    .await
    .expect("guest did not enter the wait phase");
    drop(run);
    assert_pid_reaped(pid);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_wait_reaps_and_unregisters_liteinst_root() {
    cancel_host_wait(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_wait_with_output_reaps_and_unregisters_liteinst_root() {
    cancel_host_wait(true).await;
}

/// Branches from a timer request to its PMU notification. The fixture
/// `hybrid_timer_signal_at_helper.c` retires about this many between each
/// request and the syscall that follows it.
const HELPER_NOTIFICATION_RCBS: u64 = 9_000;

/// The skid margin differs between processors, so the interval is set from
/// it: the notification then comes HELPER_NOTIFICATION_RCBS branches after
/// the request.
static HELPER_REQUEST_RCBS: LazyLock<u64> =
    LazyLock::new(|| reverie_ptrace::PmuConfig::new().skid_margin() + HELPER_NOTIFICATION_RCBS);

#[derive(Debug, Default)]
struct TimerEvents {
    fired: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for TimerEvents {
    type Request = ();
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, _fired: ()) {
        self.fired.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Debug, Default, Clone)]
struct RequestAtClockGetres;

#[reverie::tool]
impl Tool for RequestAtClockGetres {
    type GlobalState = TimerEvents;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::clock_getres, Sysno::getppid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::clock_getres {
            guest.set_timer_precise(TimerSchedule::Rcbs(*HELPER_REQUEST_RCBS))?;
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        guest.send_rpc(()).await;
    }
}

/// The timer's counter also counts the branches of the LiteInst patch
/// helper, which runs in the guest at a site's first seccomp stop, so a
/// precise timer's overflow can be raised while the helper runs. That signal
/// is the timer's: it must neither fail the helper nor reach the guest,
/// which has no handler for it.
#[tokio::test(flavor = "current_thread")]
async fn timer_overflow_in_the_patch_helper_is_the_timers() {
    reverie_ptrace::ret_without_perf!();
    let helper_before = reverie_ptrace::testing::liteinst_helper_timer_signals_discarded();
    let injection_before = reverie_ptrace::testing::late_timer_signals_discarded();
    let skid = reverie_ptrace::PmuConfig::new().skid_margin();
    let (_directory, guest) = compile_fixture("hybrid_timer_signal_at_helper.c");
    let mut command = Command::new(guest);
    command.arg(skid.to_string());
    let (output, global) =
        LiteinstBackend::run_host_with_output_and_preload::<RequestAtClockGetres>(
            command,
            (),
            preload_path(),
        )
        .await
        .unwrap();

    assert_eq!(output.stdout, b"rounds=32\n", "{output:?}");
    assert!(output.status.success(), "{output:?}");
    // Each request's target lies past the getppid that follows it. Its
    // signal is discarded before any stop can fire it, or, if it is
    // delivered before getppid, stepping to the target is cut short by
    // getppid's seccomp stop.
    assert_eq!(global.fired.load(Ordering::SeqCst), 0, "{output:?}");
    // In the 4 of every 16 rounds that retire fewer than
    // HELPER_NOTIFICATION_RCBS branches before getppid, the counter reaches
    // its threshold in getppid's helper. In the other rounds it reaches it
    // before getppid. When the processor raises each signal depends on its
    // interrupt latency: a helper round's signal can come after the helper
    // returns, and another round's can come once the helper has started. So
    // the count is not required to be exactly 8. A signal already pending at
    // the getppid stop is taken during the CPUID policy injection instead.
    let helper = reverie_ptrace::testing::liteinst_helper_timer_signals_discarded() - helper_before;
    let injection = reverie_ptrace::testing::late_timer_signals_discarded() - injection_before;
    eprintln!(
        "timer signals discarded in the patch helper: {helper}, at injected syscalls: {injection}"
    );
    assert!(
        helper > 0,
        "no helper run had the timer's signal: {output:?}"
    );
}

/// Records, in delivery order, every syscall the Tool receives and whether
/// the backend attributed it to its runtime's bootstrap. The log lives in a
/// file so that a failed session, which returns no global state, still
/// yields it.
#[derive(Default)]
struct BootstrapLog {
    path: PathBuf,
}

/// The log path, and whether the Tool refuses every file open that the
/// backend attributes to the runtime's bootstrap.
type BootstrapLogConfig = (PathBuf, bool);

#[reverie::global_tool]
impl GlobalTool for BootstrapLog {
    type Request = String;
    type Response = ();
    type Config = BootstrapLogConfig;

    async fn init_global_state(config: &BootstrapLogConfig) -> Self {
        Self {
            path: config.0.clone(),
        }
    }

    async fn receive_rpc(&self, _from: Tid, line: String) {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .unwrap();
        writeln!(file, "{line}").unwrap();
    }
}

#[derive(Default)]
struct RecordRuntimeBootstrap;

#[reverie::tool]
impl Tool for RecordRuntimeBootstrap {
    type GlobalState = BootstrapLog;
    type ThreadState = ();

    fn subscriptions(_config: &BootstrapLogConfig) -> Subscription {
        Subscription::all()
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), reverie::Errno> {
        let bootstrap = u8::from(guest.is_backend_runtime_bootstrap());
        guest.send_rpc(format!("exec {bootstrap}")).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        let in_bootstrap = guest.is_backend_runtime_bootstrap();
        // hybrid_exec_generation.c tags its own application calls this way.
        let marker = u8::from(nr == Sysno::getpid && args.arg0 == 0x6e786578);
        guest
            .send_rpc(format!(
                "syscall {} {} {marker}",
                nr as i64,
                u8::from(in_bootstrap)
            ))
            .await;
        if marker == 1 {
            return Ok(0x4242);
        }
        if in_bootstrap && guest.config().1 && matches!(nr, Sysno::open | Sysno::openat) {
            return Err(reverie::Errno::EPERM.into());
        }
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Clone, Copy, Debug)]
struct RecordedSyscall {
    nr: Sysno,
    bootstrap: bool,
    marker: bool,
}

/// The recorded syscalls, split at each post-exec callback. Element zero
/// holds what preceded the first successful exec (the launcher).
fn read_bootstrap_log(path: &std::path::Path) -> Vec<Vec<RecordedSyscall>> {
    let text = fs::read_to_string(path).expect("the Tool recorded no events");
    let mut generations = vec![Vec::new()];
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.as_slice() {
            ["exec", bootstrap] => {
                assert_eq!(
                    *bootstrap, "0",
                    "a post-exec callback ran inside the runtime bootstrap window"
                );
                generations.push(Vec::new());
            }
            ["syscall", nr, bootstrap, marker] => {
                generations.last_mut().unwrap().push(RecordedSyscall {
                    nr: Sysno::from(nr.parse::<i32>().unwrap()),
                    bootstrap: *bootstrap == "1",
                    marker: *marker == "1",
                })
            }
            _ => panic!("malformed bootstrap log line {line:?}"),
        }
    }
    generations
}

fn format_generation(syscalls: &[RecordedSyscall]) -> String {
    syscalls
        .iter()
        .map(|s| format!("{}{}", s.nr, if s.bootstrap { "*" } else { "" }))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Returns the exact index range of the one contiguous run of syscalls
/// attributed to the runtime bootstrap in one exec generation, requiring it
/// to contain each of `runtime_work`.
fn bootstrap_window(
    generation: usize,
    syscalls: &[RecordedSyscall],
    runtime_work: &[Sysno],
) -> std::ops::Range<usize> {
    let first = syscalls
        .iter()
        .position(|s| s.bootstrap)
        .unwrap_or_else(|| {
            panic!(
                "generation {generation}: no syscall was attributed to the runtime bootstrap: {}",
                format_generation(syscalls)
            )
        });
    let end = first
        + syscalls[first..]
            .iter()
            .position(|s| !s.bootstrap)
            .unwrap_or(syscalls.len() - first);
    assert!(
        syscalls[end..].iter().all(|s| !s.bootstrap),
        "generation {generation}: the bootstrap window is not one contiguous run: {}",
        format_generation(syscalls)
    );
    // The dynamic loader maps the preload before its constructor reaches the
    // begin trap, so the window never starts at the generation's first call.
    assert!(
        first > 0,
        "generation {generation}: loader syscalls before the begin trap were attributed to the runtime: {}",
        format_generation(syscalls)
    );
    let window = &syscalls[first..end];
    for &expected in runtime_work {
        assert!(
            window.iter().any(|s| s.nr == expected),
            "generation {generation}: the bootstrap window lacks the runtime's {expected}: {}",
            format_generation(syscalls)
        );
    }
    assert!(
        window.iter().all(|s| !s.marker),
        "generation {generation}: an application call was attributed to the runtime: {}",
        format_generation(syscalls)
    );
    first..end
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_bootstrap_window_is_exactly_between_begin_and_ready_in_every_exec_generation() {
    let (_directory, guest) = compile_fixture("hybrid_exec_generation.c");
    let log_directory = tempfile::tempdir().unwrap();
    let log = log_directory.path().join("bootstrap.log");
    let mut command = Command::new(&guest);
    command.arg("hot").arg("0");
    let (output, _global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_host_with_output_and_preload::<RecordRuntimeBootstrap>(
            command,
            (log.clone(), false),
            preload_path(),
        ),
    )
    .await
    .expect("exec generations did not finish")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"exec-generations-finished\n");

    let generations = read_bootstrap_log(&log);
    // The launcher, then the initial image and its two replacement execs.
    assert_eq!(generations.len(), 4, "{generations:?}");
    assert!(
        generations[0].iter().all(|s| !s.bootstrap),
        "the launcher's syscalls were attributed to the runtime: {}",
        format_generation(&generations[0])
    );
    for (generation, syscalls) in generations.iter().enumerate().skip(1) {
        // The runtime reads /proc/self/maps and allocates memfd-backed
        // trampoline arenas between its begin and ready traps.
        let window = bootstrap_window(generation, syscalls, &[Sysno::openat, Sysno::memfd_create]);
        // Everything after the ready trap is guest work, including the
        // application's three tagged calls through its (then hooked) site
        // and the final exec or exit.
        let after_ready = &syscalls[window.end..];
        assert_eq!(
            after_ready.iter().filter(|s| s.marker).count(),
            3,
            "generation {generation}: {}",
            format_generation(syscalls)
        );
        let last = after_ready.last().expect("no syscall followed Ready");
        let expected_last = if generation == 3 {
            Sysno::exit_group
        } else {
            Sysno::execve
        };
        assert_eq!(
            last.nr,
            expected_last,
            "generation {generation}: {}",
            format_generation(syscalls)
        );
    }
}

/// Runs the stage-2 image, whose runtime preparation fails after the begin
/// trap, and returns its one exec generation and the session's refusal.
async fn run_failed_runtime_preparation(
    refuse_bootstrap_opens: bool,
    invalid_staleness: bool,
) -> (Vec<RecordedSyscall>, String) {
    let (_directory, guest) = compile_fixture("hybrid_exec_generation.c");
    let log_directory = tempfile::tempdir().unwrap();
    let log = log_directory.path().join("bootstrap.log");
    let mut command = Command::new(&guest);
    command.arg("hot").arg("2");
    if invalid_staleness {
        // Preparation parses this before it issues any syscall.
        command.env(STRADDLER_STALENESS_TICKS_ENV, "not-a-tick-count");
    }
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_host_with_output_and_preload::<RecordRuntimeBootstrap>(
            command,
            (log.clone(), refuse_bootstrap_opens),
            preload_path(),
        ),
    )
    .await
    .expect("failed runtime preparation hung");
    let error = match result {
        Ok((output, _)) => panic!("failed runtime preparation reported a run: {output:?}"),
        Err(error) => error.to_string(),
    };
    let mut generations = read_bootstrap_log(&log);
    assert_eq!(generations.len(), 2, "{generations:?}");
    (generations.pop().unwrap(), error)
}

/// The constructor reports a failed preparation and calls _exit(127): the
/// failure report must end the window, so its report and exit are not the
/// runtime's bootstrap, and the session still refuses the run.
fn assert_failure_closed_the_window(syscalls: &[RecordedSyscall], window_end: usize, error: &str) {
    assert!(
        error.contains(
            "tracee terminated after its preload runtime reported that preparation failed"
        ),
        "the session did not refuse the failed runtime precisely: {error}"
    );
    let after = &syscalls[window_end..];
    assert!(
        after.iter().all(|s| !s.bootstrap && !s.marker),
        "the window did not end at the failure report, or application code ran: {}",
        format_generation(syscalls)
    );
    assert!(
        after.iter().any(|s| s.nr == Sysno::write),
        "the constructor's failure report followed no closed window: {}",
        format_generation(syscalls)
    );
    assert_eq!(
        after.last().map(|s| s.nr),
        Some(Sysno::exit_group),
        "{}",
        format_generation(syscalls)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_preparation_failure_ends_the_bootstrap_window_and_fails_the_session() {
    let (syscalls, error) = run_failed_runtime_preparation(true, false).await;
    // The refused /proc/self/maps open is the runtime's last call in the
    // window; the failure report at the ready site closes it.
    let window = bootstrap_window(1, &syscalls, &[Sysno::openat]);
    assert_eq!(
        syscalls[window.end - 1].nr,
        Sysno::openat,
        "{}",
        format_generation(&syscalls)
    );
    assert_failure_closed_the_window(&syscalls, window.end, &error);
}

#[tokio::test(flavor = "current_thread")]
async fn runtime_preparation_failure_before_any_runtime_syscall_leaves_no_window() {
    let (syscalls, error) = run_failed_runtime_preparation(false, true).await;
    assert!(
        syscalls.iter().all(|s| !s.bootstrap),
        "{}",
        format_generation(&syscalls)
    );
    assert_failure_closed_the_window(&syscalls, 0, &error);
}

/// Records every syscall with the calling thread, so that the bootstrapping
/// thread and another thread of the same process can be told apart.
#[derive(Default)]
struct RecordRuntimeBootstrapByThread;

/// hybrid_bootstrap_thread.c tags the second thread's call inside the
/// bootstrap window, and main's call after the ready trap, with these.
const BOOTSTRAP_THREAD_MARKER: usize = 0x74687264;
const BOOTSTRAP_MAIN_MARKER: usize = 0x6d61696e;

#[reverie::tool]
impl Tool for RecordRuntimeBootstrapByThread {
    type GlobalState = BootstrapLog;
    type ThreadState = ();

    fn subscriptions(_config: &BootstrapLogConfig) -> Subscription {
        Subscription::all()
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), reverie::Errno> {
        let bootstrap = u8::from(guest.is_backend_runtime_bootstrap());
        guest.send_rpc(format!("exec {bootstrap}")).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        let marker = match (nr, args.arg0) {
            (Sysno::getpid, BOOTSTRAP_THREAD_MARKER) => "thread",
            (Sysno::getpid, BOOTSTRAP_MAIN_MARKER) => "main",
            _ => "-",
        };
        let bootstrap = u8::from(guest.is_backend_runtime_bootstrap());
        guest
            .send_rpc(format!(
                "syscall {} {} {} {bootstrap} {marker}",
                guest.pid(),
                guest.tid(),
                nr as i64
            ))
            .await;
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Clone, Debug)]
struct ThreadSyscall {
    pid: i32,
    tid: i32,
    nr: Sysno,
    bootstrap: bool,
    marker: String,
}

/// A second guest thread that runs while the runtime is inside its bootstrap
/// window executes guest code. Only the thread that executed the begin trap is
/// the runtime's, although the window's phase is shared by every thread of the
/// address space.
///
/// The fixture's open64 interposes on the runtime's /proc/self/maps open, a
/// call the runtime makes between its begin and ready traps, and creates the
/// thread there. The bootstrapping thread waits for the new thread's tagged
/// call before it returns to the runtime, and the new thread stays alive
/// until main releases it after the ready trap. So the tagged call always lies
/// inside the window, and no thread exits before Ready.
///
/// The interposed open64 itself runs on the bootstrapping thread inside the
/// window, so its pipe, thread creation and wait are attributed to the
/// runtime. That is the residual for guest code interposed on the runtime's
/// imports tracked in https://github.com/rrnewton/hermit/issues/3352; this
/// test pins it rather than hides it.
#[tokio::test(flavor = "current_thread")]
async fn runtime_bootstrap_window_excludes_another_thread_of_the_process() {
    let (_directory, guest) =
        compile_fixture_with("hybrid_bootstrap_thread.c", &["-pthread", "-rdynamic"]);
    let log_directory = tempfile::tempdir().unwrap();
    let log = log_directory.path().join("bootstrap.log");
    let mut command = Command::new(&guest);
    command.arg("thread");
    let (output, _global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_host_with_output_and_preload::<RecordRuntimeBootstrapByThread>(
            command,
            (log.clone(), false),
            preload_path(),
        ),
    )
    .await
    .expect("the bootstrap-thread fixture did not finish")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"bootstrap-thread-joined\n");

    let text = fs::read_to_string(&log).expect("the Tool recorded no events");
    let mut generations: Vec<Vec<ThreadSyscall>> = vec![Vec::new()];
    for line in text.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.as_slice() {
            ["exec", bootstrap] => {
                assert_eq!(
                    *bootstrap, "0",
                    "a post-exec callback ran inside the runtime bootstrap window"
                );
                generations.push(Vec::new());
            }
            ["syscall", pid, tid, nr, bootstrap, marker] => {
                generations.last_mut().unwrap().push(ThreadSyscall {
                    pid: pid.parse().unwrap(),
                    tid: tid.parse().unwrap(),
                    nr: Sysno::from(nr.parse::<i32>().unwrap()),
                    bootstrap: *bootstrap == "1",
                    marker: (*marker).to_owned(),
                })
            }
            _ => panic!("malformed bootstrap log line {line:?}"),
        }
    }
    // The launcher, then the one image.
    assert_eq!(generations.len(), 2, "{generations:?}");
    assert!(
        generations[0].iter().all(|s| !s.bootstrap),
        "the launcher's syscalls were attributed to the runtime: {:?}",
        generations[0]
    );
    let image = &generations[1];
    let describe = |syscalls: &[ThreadSyscall]| {
        syscalls
            .iter()
            .map(|s| {
                format!(
                    "{}:{}{}{}",
                    s.tid,
                    s.nr,
                    if s.bootstrap { "*" } else { "" },
                    if s.marker == "-" {
                        String::new()
                    } else {
                        format!("[{}]", s.marker)
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let leader = image[0].pid;
    assert!(
        image.iter().all(|s| s.pid == leader),
        "a second process ran: {}",
        describe(image)
    );
    let second_tids: std::collections::BTreeSet<i32> = image
        .iter()
        .filter(|s| s.tid != leader)
        .map(|s| s.tid)
        .collect();
    assert_eq!(
        second_tids.len(),
        1,
        "expected exactly one second thread: {}",
        describe(image)
    );

    // The bootstrapping thread: one contiguous window holding the runtime's
    // work and the interposed thread creation, with main after it.
    let leader_syscalls: Vec<RecordedSyscall> = image
        .iter()
        .filter(|s| s.tid == leader)
        .map(|s| RecordedSyscall {
            nr: s.nr,
            bootstrap: s.bootstrap,
            marker: s.marker == "main",
        })
        .collect();
    let window = bootstrap_window(1, &leader_syscalls, &[Sysno::openat, Sysno::memfd_create]);
    assert!(
        leader_syscalls[window.clone()]
            .iter()
            .any(|s| matches!(s.nr, Sysno::clone | Sysno::clone3)),
        "the second thread was not created inside the bootstrap window: {}",
        describe(image)
    );
    assert_eq!(
        leader_syscalls[window.end..]
            .iter()
            .filter(|s| s.marker)
            .count(),
        1,
        "main's tagged call did not follow the ready trap: {}",
        describe(image)
    );

    // Every call of the second thread is guest work, including its tagged
    // call, which lies strictly inside the bootstrapping thread's window in
    // the order the Tool received them.
    let second: Vec<&ThreadSyscall> = image.iter().filter(|s| s.tid != leader).collect();
    assert!(
        second.iter().all(|s| !s.bootstrap),
        "a syscall of the second thread was attributed to the runtime bootstrap: {}",
        describe(image)
    );
    let tagged = image
        .iter()
        .position(|s| s.marker == "thread")
        .unwrap_or_else(|| {
            panic!(
                "the second thread's tagged call is missing: {}",
                describe(image)
            )
        });
    assert_ne!(image[tagged].tid, leader, "{}", describe(image));
    let leader_before = image[..tagged].iter().rev().find(|s| s.tid == leader);
    let leader_after = image[tagged + 1..].iter().find(|s| s.tid == leader);
    assert!(
        leader_before.is_some_and(|s| s.bootstrap) && leader_after.is_some_and(|s| s.bootstrap),
        "the second thread's tagged call was not inside the bootstrap window: {}",
        describe(image)
    );
}

/// Runs `hybrid_stepped_hook.c` with a precise timer `rcbs` RCBs past each
/// getpid. Returns the guest's output, the number of timer events, and the RCBs
/// from each getpid to the next.
async fn run_stepped_hook(rcbs: u64) -> (String, u64, Vec<u64>) {
    let (_directory, guest) = compile_fixture("hybrid_stepped_hook.c");
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(60),
        LiteinstBackend::run_host_with_output_and_preload::<SteppedHookTool>(
            Command::new(guest),
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the stepped hook guest did not complete")
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    let clocks = global.getpid_clocks.into_inner().unwrap();
    let distances = clocks.windows(2).map(|pair| pair[1] - pair[0]).collect();
    (
        String::from_utf8(output.stdout).unwrap(),
        global.timer_events.load(Ordering::SeqCst),
        distances,
    )
}

// A precise timer single-steps the guest toward its target, and the steps must
// pass a LiteInst hook's `int3` on to Reverie. If they took the trap's stop for
// a step's, the hook's syscall would not reach the Tool: the getpid would
// return its syscall number, 39, and the timer would fire as if no hook had run.
//
// Each getpid's timer is 200 RCBs away, and the next getpid's hook traps 111
// RCBs later in a debug build on an AMD EPYC 9D85. 200 RCBs is within the skid
// margin of every AMD processor in Reverie's PMU table, so there the timer is
// delivered with an artificial signal, the steps start at the getpid, and they
// run the next hook's trap. On Intel the timer uses the PMU, and the steps
// start at most 100 or 125 RCBs before the target.
#[tokio::test(flavor = "current_thread")]
async fn a_hook_trap_in_the_timer_steps_reaches_the_tool() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 200;
    let (stdout, timer_events, distances) = run_stepped_hook(rcbs).await;
    assert_eq!(
        stdout, "calls=64 wrong=0 last_wrong=0\n",
        "timer_events={timer_events} distances={distances:?}"
    );
    assert_eq!(distances.len(), 63);
    assert!(
        distances.iter().all(|&distance| distance < rcbs),
        "each hook must trap before the previous getpid's timer target: {distances:?}"
    );
    // Each hook's trap cancels the previous getpid's timer, and only the last
    // getpid's timer fires, after the loop.
    assert_eq!(timer_events, 1);
}

// The control: each getpid's timer is 50 RCBs away, before the next hook's
// trap, so every timer fires. 50 RCBs is within every skid margin in the table,
// so the steps start at the getpid on every host.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_before_the_next_hook_trap_fires() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 50;
    let (stdout, timer_events, distances) = run_stepped_hook(rcbs).await;
    assert_eq!(
        stdout, "calls=64 wrong=0 last_wrong=0\n",
        "timer_events={timer_events} distances={distances:?}"
    );
    assert_eq!(distances.len(), 63);
    assert!(
        distances.iter().all(|&distance| distance > rcbs),
        "each getpid's timer target must come before the next hook's trap: {distances:?}"
    );
    assert_eq!(timer_events, 64);
}

/// What `UnsubscribedHookTimerTool` tells its global state.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum UnsubscribedHookTimerNote {
    Getpid,
    /// The guest's RCBs from the latest getpid to a getppid, when the Tool
    /// subscribes it.
    Getppid(u64),
    /// The guest's RCBs from the latest getpid to a timer event.
    TimerEvent(u64),
}

#[derive(Debug, Default)]
struct UnsubscribedHookTimerEvents {
    getpids: AtomicU64,
    getppids: std::sync::Mutex<Vec<u64>>,
    timer_events: std::sync::Mutex<Vec<u64>>,
}

/// The configuration of `UnsubscribedHookTimerTool`.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct UnsubscribedHookTimerConfig {
    /// The timer's RCBs from each getpid to its target.
    rcbs: u64,
    /// Whether the Tool also subscribes getppid, to measure where it traps.
    getppid: bool,
}

#[reverie::global_tool]
impl GlobalTool for UnsubscribedHookTimerEvents {
    type Request = UnsubscribedHookTimerNote;
    type Response = ();
    type Config = UnsubscribedHookTimerConfig;

    async fn receive_rpc(&self, _from: Tid, note: UnsubscribedHookTimerNote) {
        match note {
            UnsubscribedHookTimerNote::Getpid => {
                self.getpids.fetch_add(1, Ordering::SeqCst);
            }
            UnsubscribedHookTimerNote::Getppid(rcbs) => self.getppids.lock().unwrap().push(rcbs),
            UnsubscribedHookTimerNote::TimerEvent(rcbs) => {
                self.timer_events.lock().unwrap().push(rcbs)
            }
        }
    }
}

/// Answers every getpid itself, with 0x4242, and requests a precise timer
/// there. It subscribes nothing else, unless configured to measure getppid.
#[derive(Default)]
struct UnsubscribedHookTimerTool;

#[reverie::tool]
impl Tool for UnsubscribedHookTimerTool {
    type GlobalState = UnsubscribedHookTimerEvents;
    /// The guest's RCB clock at the latest getpid.
    type ThreadState = u64;

    fn subscriptions(config: &UnsubscribedHookTimerConfig) -> Subscription {
        if config.getppid {
            [Sysno::getpid, Sysno::getppid].into_iter().collect()
        } else {
            [Sysno::getpid].into_iter().collect()
        }
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::getpid => {
                *guest.thread_state_mut() = guest.read_clock()?;
                guest.send_rpc(UnsubscribedHookTimerNote::Getpid).await;
                guest.set_timer_precise(TimerSchedule::Rcbs(guest.config().rcbs))?;
                Ok(0x4242)
            }
            Sysno::getppid => {
                let rcbs = guest.read_clock()? - *guest.thread_state();
                guest
                    .send_rpc(UnsubscribedHookTimerNote::Getppid(rcbs))
                    .await;
                guest.tail_inject(syscall).await
            }
            other => panic!("unsubscribed {other}"),
        }
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let rcbs = guest.read_clock().unwrap() - *guest.thread_state();
        guest
            .send_rpc(UnsubscribedHookTimerNote::TimerEvent(rcbs))
            .await;
    }
}

// The precise timer checks here use
// `reverie_ptrace::testing::assert_at_target_unless_witnessed`: an event may
// fire past its target only as a skid overshoot that Reverie witnessed.
// Whether a trap that keeps an event left its PMU programming as the request
// made it is checked at the trap, and again at the thread's next stop, by
// `KeptProgrammingChecks`, and not inferred from how many events fire late:
// the notification's latency on a loaded host makes some events late, in
// bursts, whatever the trap does. `assert_late_within_backstop` fails only a
// run whose events were all late, at a margin at which that is not seen, or
// all grossly late (see there), and prints how many were late, and how many
// more than `GROSS_OVERSHOOT_RCBS` past the target. These counts are process
// global, so these tests run with `--test-threads=1`.

// The kept timer events whose PMU programming Reverie checked in one run
// (see `reverie_ptrace::testing::check_kept_timer_programming`). At every
// hook trap without a Tool callback that keeps a scheduled event, no call
// that changes the counter's programming (enable, disable, refresh, reset,
// period or signal delivery) may have been made on it since the event's
// request, and the counter must still overflow at the clock at which the
// request programmed it to, the target less the skid margin, exactly. At
// the thread's next stop, or the event's next request or retirement, no
// such call may have been made since either, which covers the rest of the
// trap's handling. A trap that re-programmed the counter, reset it, changed
// only its period (which re-arms it without moving its count), disabled it
// or ended its programming would be counted as a change, and the event
// would fire late or not at all. Neither check depends on host timing: the
// calls are counted, and both counters hold still while the guest is
// stopped at the trap. `keeps` asserts that no check found a change and that
// every kept event was checked again, none having been handed on to single
// steps, and returns the keeps.
use reverie_ptrace::testing::KeptTimerProgrammingChecks as KeptProgrammingChecks;

/// Runs `hybrid_unsubscribed_hook_timer.c` with a precise timer `rcbs` RCBs
/// past each getpid, which the guest follows with `before + i % leads`
/// branches in round `i`, a getppid through the same patched site, and
/// `after` branches. Returns the RCBs from the getpid to each timer event,
/// and, if the Tool subscribes `getppid`, to each getppid, and the number of
/// kept events whose programming was checked unchanged (see
/// `KeptProgrammingChecks`).
async fn run_unsubscribed_hook_timer(
    config: UnsubscribedHookTimerConfig,
    before: u64,
    leads: u64,
    rounds: u64,
    after: u64,
) -> (Vec<u64>, Vec<u64>, u64) {
    let checks = KeptProgrammingChecks::start();
    let (_directory, guest) = compile_fixture("hybrid_unsubscribed_hook_timer.c");
    let mut command = Command::new(guest);
    command.args([
        before.to_string(),
        leads.to_string(),
        rounds.to_string(),
        after.to_string(),
    ]);
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(120),
        LiteinstBackend::run_host_with_output_and_preload::<UnsubscribedHookTimerTool>(
            command,
            config,
            preload_path(),
        ),
    )
    .await
    .expect("the unsubscribed hook guest did not complete")
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rounds={rounds} wrong=0\n")
    );
    assert_eq!(global.getpids.load(Ordering::SeqCst), rounds + 1);
    (
        global.timer_events.into_inner().unwrap(),
        global.getppids.into_inner().unwrap(),
        checks.keeps(),
    )
}

/// Runs the guest with no timer target in reach, `rcbs` RCBs past each
/// getpid, `before` branches from each getpid to its getppid, and the Tool
/// subscribed to getppid.
async fn run_unsubscribed_hook_timer_steps(rcbs: u64, before: u64) -> Vec<u64> {
    let config = UnsubscribedHookTimerConfig {
        rcbs,
        getppid: false,
    };
    let rounds = 16;
    let (events, getppids, _) =
        run_unsubscribed_hook_timer(config, before, 1, rounds, 2 * rcbs).await;
    assert!(getppids.is_empty());
    assert_eq!(events.len(), rounds as usize + 1, "{events:?}");
    events
}

// A getppid through a patched site is a LiteInst hook trap that the Tool does
// not observe, because it subscribes only getpid. Without LiteInst the
// getppid would make no stop at all, so the trap must not change the timer
// event that the getpid before it requested: every round's event fires once,
// at its target, in the branches after the getppid.
//
// Each target is 200 RCBs past its getpid, and the getppid's trap 100 RCBs
// and the hook's own branches past it. 200 RCBs is within the skid margin of
// every AMD processor in Reverie's PMU table, so there the timer is delivered
// with an artificial signal, the steps start at the getpid, and the trap
// interrupts them. On Intel the steps start at most 100 or 125 RCBs before
// the target.
#[tokio::test(flavor = "current_thread")]
async fn an_unsubscribed_hook_trap_in_the_timer_steps_keeps_the_event() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 200;
    let events = run_unsubscribed_hook_timer_steps(rcbs, 100).await;
    assert!(events.iter().all(|&event| event == rcbs), "{events:?}");
}

// The control: the target is 50 RCBs past each getpid, before the getppid, so
// the steps reach it before the trap.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_before_an_unsubscribed_hook_trap_fires() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 50;
    let events = run_unsubscribed_hook_timer_steps(rcbs, 100).await;
    assert!(events.iter().all(|&event| event == rcbs), "{events:?}");
}

// The timer's PMU notification can be pending at the unsubscribed hook trap,
// when the counter overflows a few branches before it and the processor's
// interrupt latency lands the signal after the trap. The notification then
// reaches the syscall that Reverie injects for the hook, before any stop has
// decided the event. It is the event's own: the event must fire once the
// syscall returns, at its target, or past it only as a witnessed skid
// overshoot (see `assert_late_within_backstop`), and not be taken for a late
// notification of a cancelled event and discarded.
//
// A first run, with the Tool subscribed to getppid, measures how many
// branches past the guest's loop the getppid traps. In the second run each
// round's counter then overflows one of `leads` distances before or after
// the trap, as in reverie-ptrace/tests/late_timer_signal.rs. Whichever side
// of the trap the signal comes, the event must fire at its target, or past
// it only as a witnessed skid overshoot. Each trap reached before the
// notification keeps the event, and must leave its programming as the
// request made it (see `KeptProgrammingChecks`), which
// `Timer::disregard_stop` checks.
#[tokio::test(flavor = "current_thread")]
async fn a_timer_notification_at_an_unsubscribed_hook_syscall_fires_the_event() {
    reverie_ptrace::ret_without_perf!();
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    let period = 10_000;
    let leads = 80.min(margin / 4);
    let rounds = 200;
    let rcbs = period + margin;
    let measure = UnsubscribedHookTimerConfig {
        rcbs: 4 * period,
        getppid: true,
    };
    let (_, getppids, _) = run_unsubscribed_hook_timer(measure, period, 1, 4, 1).await;
    // The guest's first getppid precedes every getpid, and the site's first
    // getpid reaches the Tool through seccomp rather than the hook.
    assert_eq!(getppids.len(), 6, "{getppids:?}");
    let hook = getppids[2] - period;
    assert!(
        getppids[2..].iter().all(|&rcbs| rcbs == period + hook),
        "the getppid must trap at one distance past the loop: {getppids:?}"
    );
    assert!(
        hook + leads < margin,
        "the trap must come before the target: {hook} branches past the loop"
    );
    eprintln!("the getppid traps {hook} branches past the loop");
    let config = UnsubscribedHookTimerConfig {
        rcbs,
        getppid: false,
    };
    // These counts are process global, so the deltas are this run's only
    // with `--test-threads=1`, as the workspace runs its tests.
    let live_before = reverie_ptrace::testing::live_timer_signals_taken();
    let late_before = reverie_ptrace::testing::late_timer_signals_discarded();
    let _ = reverie::take_skid_overshoot_count();
    let (events, _, keeps) =
        run_unsubscribed_hook_timer(config, period - hook - leads / 2, leads, rounds, 2 * margin)
            .await;
    let witnesses = reverie::take_skid_overshoot_count();
    let live = reverie_ptrace::testing::live_timer_signals_taken() - live_before;
    let late = reverie_ptrace::testing::late_timer_signals_discarded() - late_before;
    eprintln!("notifications taken at injected syscalls: {live}, discarded as late: {late}");
    // Every round's event fires, none is lost or cancelled, and each at its
    // target unless its notification came too late (see
    // `assert_at_target_unless_witnessed`). At a skid margin of
    // `LATE_BACKSTOP_LEAST_MARGIN` or more not every event may be late, and
    // at any margin not every event may be more than `GROSS_OVERSHOOT_RCBS`
    // late (see `late_events_within_backstop`).
    assert_eq!(events.len(), rounds as usize + 1, "{events:?}");
    assert_at_target_unless_witnessed(&events, rcbs, witnesses);
    assert_late_within_backstop(&events, rcbs);
    assert_eq!(late, 0, "no notification here is late");
    // Otherwise no round tested the notification at the injection.
    assert!(live > 0, "no notification reached an injected syscall");
    // Otherwise no round tested a trap that keeps the event.
    assert!(
        keeps > 0 && keeps <= rounds,
        "some of the {rounds} traps, and at most one per round, must keep the event: {keeps}"
    );
}

/// What the rt_sigreturn hook tests' Tools tell their global state.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum SigreturnHookTimerNote {
    /// A timer request's round, and the guest's RCB clock at the request.
    Request { round: u64, clock: u64 },
    /// A timer event's round, and the guest's RCBs from its request.
    TimerEvent { round: u64, rcbs: u64 },
}

#[derive(Debug, Default)]
struct SigreturnHookTimerEvents {
    requests: AtomicU64,
    /// The round of each timer request, and the guest's RCB clock at it.
    request_clocks: std::sync::Mutex<Vec<(u64, u64)>>,
    /// The round of each timer event's request, and the guest's RCBs from
    /// the request to the event.
    timer_events: std::sync::Mutex<Vec<(u64, u64)>>,
}

#[reverie::global_tool]
impl GlobalTool for SigreturnHookTimerEvents {
    type Request = SigreturnHookTimerNote;
    type Response = ();
    /// The timer's RCBs from each request to its target.
    type Config = u64;

    async fn receive_rpc(&self, _from: Tid, note: SigreturnHookTimerNote) {
        match note {
            SigreturnHookTimerNote::Request { round, clock } => {
                self.requests.fetch_add(1, Ordering::SeqCst);
                self.request_clocks.lock().unwrap().push((round, clock));
            }
            SigreturnHookTimerNote::TimerEvent { round, rcbs } => {
                self.timer_events.lock().unwrap().push((round, rcbs))
            }
        }
    }
}

/// Answers every getpid itself, with 0x4242, and requests a precise timer at
/// a getpid whose first argument is 1, for the round in its second. It
/// subscribes nothing else.
#[derive(Default)]
struct SigreturnHookTimerTool;

#[reverie::tool]
impl Tool for SigreturnHookTimerTool {
    type GlobalState = SigreturnHookTimerEvents;
    /// The guest's RCB clock at the latest request, and its round.
    type ThreadState = (u64, u64);

    fn subscriptions(_config: &u64) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let (_, args) = syscall.into_parts();
        if args.arg0 == 1 {
            let (clock, round) = (guest.read_clock()?, args.arg1 as u64);
            *guest.thread_state_mut() = (clock, round);
            guest
                .send_rpc(SigreturnHookTimerNote::Request { round, clock })
                .await;
            guest.set_timer_precise(TimerSchedule::Rcbs(*guest.config()))?;
        }
        Ok(0x4242)
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let (clock, round) = *guest.thread_state();
        let rcbs = guest.read_clock().unwrap() - clock;
        guest
            .send_rpc(SigreturnHookTimerNote::TimerEvent { round, rcbs })
            .await;
    }
}

/// `SigreturnHookTimerTool`, subscribed to exit_group too, which it makes
/// as the guest asked.
#[derive(Default)]
struct ExitSeenTimerTool;

#[reverie::tool]
impl Tool for ExitSeenTimerTool {
    type GlobalState = SigreturnHookTimerEvents;
    /// The guest's RCB clock at the latest request, and its round.
    type ThreadState = (u64, u64);

    fn subscriptions(_config: &u64) -> Subscription {
        [Sysno::getpid, Sysno::exit_group].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::exit_group {
            guest.tail_inject(syscall).await
        }
        assert_eq!(syscall.number(), Sysno::getpid);
        let (_, args) = syscall.into_parts();
        if args.arg0 == 1 {
            let (clock, round) = (guest.read_clock()?, args.arg1 as u64);
            *guest.thread_state_mut() = (clock, round);
            guest
                .send_rpc(SigreturnHookTimerNote::Request { round, clock })
                .await;
            guest.set_timer_precise(TimerSchedule::Rcbs(*guest.config()))?;
        }
        Ok(0x4242)
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let (clock, round) = *guest.thread_state();
        let rcbs = guest.read_clock().unwrap() - clock;
        guest
            .send_rpc(SigreturnHookTimerNote::TimerEvent { round, rcbs })
            .await;
    }
}

/// Runs `hybrid_sigreturn_hook_timer.c` for `rounds` signals, with a precise
/// timer `rcbs` RCBs past the request in each handler, which returns
/// `before + (i % leads) * stride` branches after it in round `i`, and
/// `after` branches after each signal, and with the timer's signal blocked
/// throughout if `block_timer_signal`. Returns each timer event's round and
/// RCBs from its request, and the skid overshoots Reverie witnessed.
async fn run_sigreturn_hook_timer(
    rcbs: u64,
    before: u64,
    leads: u64,
    stride: u64,
    rounds: u64,
    after: u64,
    block_timer_signal: bool,
) -> (Vec<(u64, u64)>, u64) {
    let run = run_sigreturn_hook_timer_overtaken(
        rcbs,
        before,
        leads,
        stride,
        rounds,
        after,
        block_timer_signal,
    )
    .await;
    (run.events, run.witnesses)
}

/// Runs `hybrid_sigreturn_hook_timer.c` as `run_sigreturn_hook_timer` does,
/// and returns the rounds whose event was overtaken with its notification
/// queued too.
async fn run_sigreturn_hook_timer_overtaken(
    rcbs: u64,
    before: u64,
    leads: u64,
    stride: u64,
    rounds: u64,
    after: u64,
    block_timer_signal: bool,
) -> SigreturnHookTimerRun {
    run_sigreturn_hook_timer_args(
        rcbs,
        rounds,
        &[
            before,
            rounds,
            after,
            leads,
            stride,
            u64::from(block_timer_signal),
        ],
    )
    .await
}

/// Runs `hybrid_sigreturn_hook_timer.c` as `run_sigreturn_hook_timer` does,
/// one request per round, with one more getpid that the Tool sees but that
/// requests nothing `observe_at` branches after each request, if
/// `observe_at` is nonzero, and after each handler's return, if
/// `observe_after`.
async fn run_sigreturn_hook_timer_observed(
    rcbs: u64,
    before: u64,
    rounds: u64,
    after: u64,
    block_timer_signal: bool,
    observe_at: u64,
    observe_after: bool,
) -> (Vec<(u64, u64)>, u64) {
    let run = run_sigreturn_hook_timer_args(
        rcbs,
        rounds,
        &[
            before,
            rounds,
            after,
            1,
            0,
            u64::from(block_timer_signal),
            observe_at,
            u64::from(observe_after),
        ],
    )
    .await;
    (run.events, run.witnesses)
}

/// A run of `hybrid_sigreturn_hook_timer.c`.
struct SigreturnHookTimerRun {
    /// Each timer event's round and RCBs from its request, in order.
    events: Vec<(u64, u64)>,
    /// The skid overshoots Reverie witnessed.
    witnesses: u64,
    /// The rounds whose event a stop other than its notification decided,
    /// and Reverie witnessed, past its target while its notification was
    /// already queued, each with the guest's RCBs from the round's request
    /// to that stop, in the order witnessed (see
    /// `reverie_ptrace::testing::precise_events_overtaken_with_notification_queued`).
    overtaken: Vec<(u64, u64)>,
    /// Each round's request, by round, with the guest's RCB clock at it.
    requests: std::collections::BTreeMap<u64, u64>,
    /// The kept events whose programming was checked unchanged at the trap
    /// that kept them and again at the thread's next stop (see
    /// `KeptProgrammingChecks`): one per rt_sigreturn hook trap that kept its
    /// round's event.
    keeps: u64,
}

impl SigreturnHookTimerRun {
    /// The guest's RCBs from round `round`'s request at which the next
    /// round's signal can stop the guest, for a run whose handler returns
    /// `lead` branches after its request in that round, and which runs
    /// `after` branches after each signal: from the end of those `after`
    /// branches up to the next round's request, inclusive, which the handler
    /// makes after the signal's stop. After an rt_sigreturn hook trap that keeps the
    /// event, that stop is the only one before the next request, so it is
    /// the only stop that can overtake the kept event. Empty for the last
    /// round, after which the guest makes no stop before it exits.
    fn next_signal(&self, round: u64, lead: u64, after: u64) -> std::ops::Range<u64> {
        match self.requests.get(&(round + 1)) {
            Some(next) => lead + after..next - self.requests[&round] + 1,
            None => 0..0,
        }
    }
}

/// The most rounds of a run whose kept event may be overtaken with its
/// notification queued, of `kept` rounds whose event could be: the least
/// count that a Poisson count with a mean of 4 in 1000 kept rounds exceeds
/// with a probability under 1 in 10000 (see `poisson_cap`). That mean is
/// four times the measured rate rounded up to 1 in 1000: 4 overtaken in 5000
/// kept rounds in the round-6 diagnosis
/// (https://github.com/rrnewton/reverie/issues/726#issuecomment-5881024175),
/// and 4 in 400 runs of `an_rt_sigreturn_hook_trap_keeps_the_timer_event`,
/// 6000 kept rounds that could be overtaken, in the round-6 review of
/// https://github.com/rrnewton/reverie/pull/665, on devbig014, an AMD EPYC
/// 9D85, at load averages of 30 to 127. In the later round-6 campaigns' 571
/// runs of the rt_sigreturn hook tests that print the count, of 16, 34, 256
/// and 434 rounds, 1 of 39884 rounds was overtaken, and no run had more than
/// one. The Poisson model only sizes the cap: it is not the probability that a
/// run fails, which it does not give, since the host latency behind an
/// overtaken round comes in bursts, as that behind late events does (see
/// `assert_late_within_backstop`). A change that made a kept event's
/// notification late much more often fails the run: 3 overtaken of 15 kept
/// rounds, 4 of 44, or 9 of 400. A trap that re-programs a kept event's
/// counter fails the check of `KeptProgrammingChecks` instead, whatever the
/// host does.
fn overtaken_cap(kept: u64) -> u64 {
    poisson_cap(kept as f64 * 4.0 / 1000.0, 1e-4)
}

/// The least count that a Poisson count with a mean of `mean` exceeds with a
/// probability under `probability`.
fn poisson_cap(mean: f64, probability: f64) -> u64 {
    // The probability of each count, and of at most `cap`.
    let mut term = (-mean).exp();
    let mut at_most = term;
    let mut cap = 0;
    while 1.0 - at_most >= probability {
        cap += 1;
        term *= mean / cap as f64;
        at_most += term;
    }
    cap
}

/// Checks the events that a run counted as overtaken with their notification
/// queued (see `SigreturnHookTimerRun::overtaken`) against the one host
/// effect that explains them (see `sweep_sigreturn_hook_trap`), and returns
/// them by round, each with the guest's RCBs from its request to the stop
/// that overtook it. Every witness must be an event fired past its target,
/// `rcbs`, or an overtaken one, and no other. No round may be overtaken
/// twice, or both overtaken and fired. Each overtaken round must be one of
/// the run's `rounds`, and its event must be overtaken at or past its target
/// by a stop at `overtaking_stop(round)` RCBs from its request, where the
/// only stop that can overtake its kept event lies. Prints how many rounds
/// were overtaken, so that the rate is seen in every run.
fn overtaken_rounds(
    run: &SigreturnHookTimerRun,
    rcbs: u64,
    rounds: u64,
    overtaking_stop: impl Fn(u64) -> std::ops::Range<u64>,
) -> std::collections::BTreeMap<u64, u64> {
    let SigreturnHookTimerRun {
        events,
        witnesses,
        overtaken,
        ..
    } = run;
    let late = events.iter().filter(|&&(_, clock)| clock > rcbs).count() as u64;
    eprintln!(
        "{} of {rounds} rounds were overtaken with their notification queued, by round and RCBs \
         from its request: {overtaken:?}",
        overtaken.len()
    );
    assert_eq!(
        *witnesses,
        late + overtaken.len() as u64,
        "every witness must be an event fired past its target, or one overtaken with its \
         notification queued: {late} fired late, overtaken {overtaken:?}, events {events:?}"
    );
    let fired: std::collections::BTreeMap<u64, u64> = events.iter().copied().collect();
    let by_round: std::collections::BTreeMap<u64, u64> = overtaken.iter().copied().collect();
    assert_eq!(
        by_round.len(),
        overtaken.len(),
        "no round may be overtaken twice: {overtaken:?}"
    );
    for (&round, &clock) in &by_round {
        let stop = overtaking_stop(round);
        assert!(
            round < rounds && !fired.contains_key(&round) && clock >= rcbs && stop.contains(&clock),
            "an overtaken round's event must not fire, and must be overtaken at or past its \
             target {rcbs} by the one stop that can overtake it, {stop:?} RCBs from its \
             request: round {round} at {clock}, events {events:?}"
        );
    }
    by_round
}

/// Asserts that no more of `kept` rounds were overtaken than
/// `overtaken_cap(kept)`.
fn assert_overtaken_within_cap(overtaken: &std::collections::BTreeMap<u64, u64>, kept: u64) {
    let cap = overtaken_cap(kept);
    assert!(
        overtaken.len() as u64 <= cap,
        "at most {cap} of {kept} kept events may be overtaken with their notification queued, \
         at four times the measured rate: {overtaken:?}"
    );
}

/// The overshoot past its target, in RCBs, beyond which
/// `late_events_within_backstop` counts an event as grossly late, and fails a
/// run all of whose events were, at any skid margin. It is twice the skid
/// margin of 1000 RCBs of devbig014, an AMD EPYC 9D85, and under half of the
/// overshoot of an event that is re-programmed for a full notification period
/// at a keeping trap, about 4200 RCBs past the target in
/// `an_rt_sigreturn_hook_trap_keeps_the_timer_event` and 9771 or more in the
/// sweeps. No bound under that overshoot holds for every event on a loaded
/// host. In 400 runs of these tests at the head of the round-6 review of
/// https://github.com/rrnewton/reverie/pull/665, on devbig014 at load
/// averages of 25 to 130, 7 of about 21560 fired events at a margin of 1000
/// or 10000 were more than 2000 RCBs past the target, at 3227, 3684, 5555,
/// 11053, 12764, 30050 and 42765 RCBs, and no other was more than 1138 RCBs
/// past it. Later, a single run of
/// `an_rt_sigreturn_hook_trap_decides_the_timer_by_the_guest_clock` had 8 of
/// its 182 events more than 2000 RCBs past the target, up to 7271, all
/// witnessed, in the round-6 DSR review of that pull request, and a run of
/// `an_rt_sigreturn_hook_trap_keeps_the_timer_event` in its round-7 DSR
/// review had 5 of its 16, up to 7536. Those are notifications serviced only
/// at a later kernel entry, as for the overtaken rounds (see
/// `overtaken_cap`), and they come in bursts, so a count of them per event,
/// or a cap on it from a rate, does not bound a run.
const GROSS_OVERSHOOT_RCBS: u64 = 2_000;

/// The least skid margin at which `late_events_within_backstop` fails a run
/// all of whose events fired past their target, however little. At a
/// smaller margin the notification's latency often exceeds the margin: on
/// devbig014 at a margin of 100, 175 of 240 events were past the target, and
/// all 16 of two runs.
const LATE_BACKSTOP_LEAST_MARGIN: u64 = 1_000;

/// Checks the RCBs from each request to its fired event, `clocks`, whose
/// target is `rcbs`, at a skid margin of `margin`, against a backstop: at any
/// margin, not every event may have fired more than `GROSS_OVERSHOOT_RCBS`
/// past its target, and at a margin of `LATE_BACKSTOP_LEAST_MARGIN` or more,
/// not every event may have fired past its target at all. Returns what it
/// counted, or why the events fail. Whether each event past its target is
/// witnessed is `assert_at_target_unless_witnessed`'s to check, and whether
/// a trap that kept an event changed its programming is
/// `KeptProgrammingChecks`'s, which counts every call that changes it: the
/// backstop is not what tells a correct keep from one that re-programs the
/// counter, only a last check that a run's events are not all late.
///
/// Late events come from the notification's latency on the host, which
/// comes in bursts within a run, so the backstop is set per run, and only at
/// all of a run's events, rather than from a rate per event or a fraction of
/// a run. Round 7 of https://github.com/rrnewton/reverie/pull/665 failed a
/// run in which half or more of the events fired past the target, and its
/// DSR review then saw a correct run of
/// `an_rt_sigreturn_hook_trap_keeps_the_timer_event` at a margin of 1000
/// fire 8 of its 16 events past the target, by 1259 to 7536 RCBs, all
/// witnessed, which failed that backstop. In the 542 logs of the round-7
/// campaigns and of both round-7 reviews on devbig014, 1850 groups of events
/// counted at a margin of 1000 had at most 8 of 16, 4 of 44, 3 of 181 and 15
/// of 182 past the target, and none had every event past it; at a margin of
/// 100, 2 of 4 groups of 16 had every event past it; and at no margin did a
/// group have every event more than 2000 RCBs past it. The one-minute load
/// averages those logs recorded ranged from 26 to 332: of the 451 logs with
/// groups that recorded one, 51 recorded one above 130. A trap that
/// re-programs every kept event's counter for a full period made 16 of 16
/// and 182 of 182 more than 4000 RCBs late at a margin of 1000, and 16 of 16
/// and 182 of 182 at a margin of 100. A trap that re-arms the counter of one
/// kept event in four with a period change made 11 of 44 late, which no
/// backstop on how many events are late tells from latency; the programming
/// checks count it.
fn late_events_within_backstop(clocks: &[u64], rcbs: u64, margin: u64) -> Result<String, String> {
    let events = clocks.len() as u64;
    let late = clocks.iter().filter(|&&clock| clock > rcbs).count() as u64;
    let beyond = clocks
        .iter()
        .filter(|&&clock| clock > rcbs + GROSS_OVERSHOOT_RCBS)
        .count() as u64;
    let fraction = if events == 0 {
        0.0
    } else {
        late as f64 / events as f64
    };
    let counted = format!(
        "{late} of {events} events fired past the target {rcbs} at a skid margin of {margin}, \
         a fraction of {fraction:.3}, {beyond} of them more than {GROSS_OVERSHOOT_RCBS} RCBs \
         past it"
    );
    if events > 0 && beyond == events {
        return Err(format!(
            "{counted}: not every event may fire more than {GROSS_OVERSHOOT_RCBS} RCBs past the \
             target: {clocks:?}"
        ));
    }
    if margin < LATE_BACKSTOP_LEAST_MARGIN {
        return Ok(format!(
            "{counted}; not all more than {GROSS_OVERSHOOT_RCBS} RCBs past it, and the backstop \
             on all late applies from a skid margin of {LATE_BACKSTOP_LEAST_MARGIN}"
        ));
    }
    if events > 0 && late == events {
        return Err(format!(
            "{counted}: not every event may fire past the target: {clocks:?}"
        ));
    }
    Ok(format!("{counted}, not all"))
}

/// Asserts `late_events_within_backstop` at this process's skid margin,
/// which a re-run at another margin overrides, and prints what it counted.
fn assert_late_within_backstop(clocks: &[u64], rcbs: u64) {
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    match late_events_within_backstop(clocks, rcbs, margin) {
        Ok(counted) => eprintln!("{counted}"),
        Err(failure) => panic!("{failure}"),
    }
}

#[test]
fn overtaken_cap_has_its_measured_values() {
    let overtaken: Vec<u64> = [15, 16, 44, 400, 434].map(overtaken_cap).to_vec();
    assert_eq!(overtaken, [2, 2, 3, 8, 8]);
}

#[test]
fn the_late_event_backstop_rejects_a_full_period_overshoot() {
    let rcbs = SIGRETURN_RCBS;
    let at = |events: usize, overshoots: &[u64]| -> Vec<u64> {
        let mut clocks = vec![rcbs; events - overshoots.len()];
        clocks.extend(overshoots.iter().map(|overshoot| rcbs + overshoot));
        clocks
    };
    // An event re-programmed for a full notification period at the keeping
    // trap of `an_rt_sigreturn_hook_trap_keeps_the_timer_event` fires about
    // 4200 RCBs past its target in every round, witnessed.
    let full_period: Vec<u64> = (0..16).map(|round| rcbs + 4203 + 4 * round).collect();
    let seven = [3477, 2709, 687, 7271, 223, 30_050, 10];
    // The run of the round-7 DSR review of
    // https://github.com/rrnewton/reverie/pull/665 that failed round 7's
    // backstop, which counted half or more late.
    let dsr_run_010 = [2540, 2869, 1282, 1339, 3838, 1259, 4356, 7536];
    for margin in [100, 1000, 10_000] {
        assert!(late_events_within_backstop(&full_period, rcbs, margin).is_err());
        assert!(late_events_within_backstop(&at(16, &[2001; 16]), rcbs, margin).is_err());
        assert!(late_events_within_backstop(&at(182, &[4641; 182]), rcbs, margin).is_err());
        assert!(late_events_within_backstop(&at(182, &[4641; 181]), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&at(16, &[4203; 15]), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&at(16, &[3; 15]), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&at(16, &dsr_run_010), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&at(16, &seven), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&at(16, &[]), rcbs, margin).is_ok());
        assert!(late_events_within_backstop(&[], rcbs, margin).is_ok());
    }
    for margin in [1000, 10_000] {
        assert!(late_events_within_backstop(&at(16, &[3; 16]), rcbs, margin).is_err());
        assert!(late_events_within_backstop(&at(16, &[2000; 16]), rcbs, margin).is_err());
    }
    assert!(late_events_within_backstop(&at(16, &[3; 16]), rcbs, 100).is_ok());
    assert!(late_events_within_backstop(&at(16, &[2000; 16]), rcbs, 100).is_ok());
}

/// Runs `hybrid_sigreturn_hook_timer.c` with `args`, for `rounds` signals,
/// with a precise timer `rcbs` RCBs past each request.
async fn run_sigreturn_hook_timer_args(
    rcbs: u64,
    rounds: u64,
    args: &[u64],
) -> SigreturnHookTimerRun {
    let (_directory, guest) = compile_fixture("hybrid_sigreturn_hook_timer.c");
    let mut command = Command::new(guest);
    command.args(args.iter().map(u64::to_string));
    // Process global; see `assert_at_target_unless_witnessed`.
    let _ = reverie::take_skid_overshoot_count();
    let overtaken_before =
        reverie_ptrace::testing::precise_events_overtaken_with_notification_queued();
    let _ = reverie_ptrace::testing::take_precise_events_overtaken_with_notification_queued();
    let checks = KeptProgrammingChecks::start();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(120),
        LiteinstBackend::run_host_with_output_and_preload::<SigreturnHookTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the rt_sigreturn hook guest did not complete")
    .unwrap();
    let keeps = checks.keeps();
    let witnesses = reverie::take_skid_overshoot_count();
    let counted = reverie_ptrace::testing::precise_events_overtaken_with_notification_queued()
        - overtaken_before;
    let overtaken =
        reverie_ptrace::testing::take_precise_events_overtaken_with_notification_queued();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rounds={rounds} handled={rounds} wrong=0\n")
    );
    assert_eq!(global.requests.load(Ordering::SeqCst), rounds);
    let events = global.timer_events.into_inner().unwrap();
    // One event per request at most, in order.
    assert!(
        events.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "{events:?}"
    );
    assert_eq!(
        overtaken.len() as u64,
        counted,
        "every overtaken event must be listed: {overtaken:?}"
    );
    // Each overtaken event is one of this run's requests, the one whose
    // target, `rcbs` past it, is the event's.
    let requests = global.request_clocks.into_inner().unwrap();
    let overtaken = overtaken
        .iter()
        .map(|&(target, clock)| {
            let &(round, request) = requests
                .iter()
                .find(|&&(_, request)| request + rcbs == target)
                .unwrap_or_else(|| {
                    panic!(
                        "the event overtaken at clock {clock} must have the target of one of \
                         this run's requests, not {target}: {requests:?}"
                    )
                });
            (round, clock - request)
        })
        .collect();
    SigreturnHookTimerRun {
        events,
        witnesses,
        overtaken,
        requests: requests.into_iter().collect(),
        keeps,
    }
}

/// The timer's RCBs from each handler's request to its target in the
/// rt_sigreturn hook tests that keep or sweep: above the largest skid margin
/// in Reverie's PMU table, so that the request programs a PMU notification
/// on every processor in the table, and the same on every processor.
const SIGRETURN_RCBS: u64 = 30_000;

/// The distance from a handler's request at and after which an rt_sigreturn
/// hook trap cancels its `SIGRETURN_RCBS` event: the keep margin
/// (`PmuConfig::keep_margin`) short of the target. The same on every
/// processor in the table.
fn sigreturn_keep_point() -> u64 {
    SIGRETURN_RCBS - reverie_ptrace::PmuConfig::new().keep_margin()
}

// A signal handler's restorer that makes its rt_sigreturn through a patched
// site traps into LiteInst, and Reverie makes the rt_sigreturn for the hook
// without a Tool callback. Without LiteInst the rt_sigreturn would make no
// stop, so the trap must not change the timer event that the handler
// requested: each handler requests an event whose PMU notification comes
// after the rt_sigreturn, and it must fire after the handler has returned,
// at its target, or past it only as a witnessed skid overshoot (see
// `assert_late_within_backstop`). Each round's trap keeps its event, and
// must leave the event's programming as the request made it (see
// `KeptProgrammingChecks`).
//
// The one exception is the host timing that `sweep_sigreturn_hook_trap`
// identifies by its cause: a notification serviced only at the next round's
// signal, which overtakes the kept event past its target with the
// notification queued, and witnesses it. Such a round alone may be missing,
// at that stop, and every other round must fire (see `overtaken_rounds`).
// The last round cannot be overtaken, since the guest makes no stop between
// its handler's return and its exit.
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_keeps_the_timer_event() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = SIGRETURN_RCBS;
    let (lead, after) = (5_000, 2 * rcbs);
    let rounds = 16;
    let run = run_sigreturn_hook_timer_overtaken(rcbs, lead, 1, 0, rounds, after, false).await;
    let overtaken = overtaken_rounds(&run, rcbs, rounds, |round| {
        run.next_signal(round, lead, after)
    });
    assert_overtaken_within_cap(&overtaken, rounds - 1);
    assert_eq!(
        run.keeps, rounds,
        "each round's trap must keep its event, with its programming unchanged"
    );
    let events = &run.events;
    assert_eq!(
        events.iter().map(|&(round, _)| round).collect::<Vec<_>>(),
        (0..rounds)
            .filter(|round| !overtaken.contains_key(round))
            .collect::<Vec<_>>(),
        "every round's event must fire, unless overtaken with its notification queued: \
         {events:?}, overtaken {overtaken:?}"
    );
    let clocks: Vec<u64> = events.iter().map(|&(_, rcbs)| rcbs).collect();
    assert_at_target_unless_witnessed(&clocks, rcbs, run.witnesses - overtaken.len() as u64);
    assert_late_within_backstop(&clocks, rcbs);
}

/// A bound on the branches from the return of `hybrid_sigreturn_hook_timer.c`'s
/// handler to the rt_sigreturn hook's trap. They are those of the handler's
/// epilogue, the restorer and the hook's trampoline. On devbig014, an AMD
/// EPYC 9D85, the event is cancelled from 109 branches before the keep point.
const SIGRETURN_TRAP_BRANCHES: u64 = 200;

/// Sweeps the rt_sigreturn hook's trap across `leads` distances from the
/// handler's request, `before + j * stride` branches for `j` in `0..leads`,
/// `repeats` times each, with the timer's target, `SIGRETURN_RCBS` past the
/// request, past the last trap.
///
/// Nothing of a timer event is continued across the context switch of an
/// rt_sigreturn hook trap: an event within the keep margin of its target at
/// the trap is cancelled, and one farther from it is kept, to be delivered by
/// its notification after the handler returns. Whether the notification of a
/// programming past its period has arrived at the trap, and whether its
/// single steps have begun, depends on the processor's interrupt latency, and
/// where the period lies depends on the processor's skid margin, so the rule
/// must depend on neither: the guest's clock at the trap alone decides the
/// event's fate, and the keep margin is at least the largest skid margin in
/// the table, so the keep point is at or before the period on every
/// processor.
///
/// So every repeat of a distance must meet one fate, and the fate must change
/// exactly once, from firing to cancelled, where the trap reaches the keep
/// point. Every trap is short of the target, so no cancellation is a
/// witnessed skid overshoot, and every fired event is at its target, or past
/// it only as a witnessed skid overshoot (see
/// `assert_at_target_unless_witnessed` and `assert_late_within_backstop`).
/// Every trap that keeps its event must leave the event's programming as the
/// request made it (see `KeptProgrammingChecks`), and every round of a
/// distance that fired, and no other, must have been kept so. Returns the
/// last distance at which the event fired.
///
/// The one exception is host timing, and the run identifies it by its cause
/// rather than tolerating it: the notification of a kept event can be
/// serviced so late that the next round's first stop, the guest's own
/// signal, is dequeued before it, and that stop decides the event past its
/// target, with its notification already queued, and witnesses it (see
/// https://github.com/rrnewton/reverie/issues/726#issuecomment-5881024175).
/// Reverie counts each such witness (see
/// `reverie_ptrace::testing::precise_events_overtaken_with_notification_queued`),
/// and the run must have exactly one witness per event fired past its target
/// and per such overtaken event, and no other. An overtaken round must be one
/// whose event was kept, which did not fire and was overtaken at or past its
/// target by the next round's signal (see `overtaken_rounds` and
/// `SigreturnHookTimerRun::next_signal`), and every other repeat of its
/// distance must have fired; the fate of each distance is read from the
/// repeats that were not overtaken, of which there must be at least one. No
/// more kept rounds may be overtaken than `overtaken_cap` allows. No round is
/// run again.
async fn sweep_sigreturn_hook_trap(before: u64, leads: u64, stride: u64, repeats: u64) -> u64 {
    let rcbs = SIGRETURN_RCBS;
    let keep_point = sigreturn_keep_point();
    assert!(
        before < keep_point && before + (leads - 1) * stride + SIGRETURN_TRAP_BRANCHES < rcbs,
        "the sweep must start before the keep point, and every trap come before the target"
    );
    let rounds = leads * repeats;
    let after = 2 * rcbs;
    let run =
        run_sigreturn_hook_timer_overtaken(rcbs, before, leads, stride, rounds, after, false).await;
    let overtaken_rounds = overtaken_rounds(&run, rcbs, rounds, |round| {
        run.next_signal(round, before + (round % leads) * stride, after)
    });
    let SigreturnHookTimerRun {
        events,
        witnesses,
        overtaken,
        keeps,
        ..
    } = run;
    let fired: std::collections::BTreeMap<u64, u64> = events.iter().copied().collect();
    let fates: Vec<bool> = (0..leads)
        .map(|j| {
            let distance = before + j * stride;
            let repeats: Vec<u64> = (0..repeats).map(|repeat| j + repeat * leads).collect();
            let counted: Vec<u64> = repeats
                .iter()
                .copied()
                .filter(|round| !overtaken_rounds.contains_key(round))
                .collect();
            assert!(
                !counted.is_empty(),
                "a trap {distance} branches past the handler's request must meet its fate in \
                 at least one round not overtaken: rounds {repeats:?}, overtaken {overtaken:?}"
            );
            let fate = fired.contains_key(&counted[0]);
            for round in &counted[1..] {
                assert_eq!(
                    fired.contains_key(round),
                    fate,
                    "every trap {distance} branches past the handler's request must meet one \
                     fate: fired in rounds {:?}, overtaken {overtaken:?}",
                    fired.keys().collect::<Vec<_>>()
                );
            }
            assert!(
                fate || counted.len() == repeats.len(),
                "only a kept event can be overtaken, yet the trap {distance} branches past the \
                 handler's request cancelled it: rounds {repeats:?}, overtaken {overtaken:?}"
            );
            fate
        })
        .collect();
    let boundary = fates.iter().position(|&fate| !fate).unwrap_or(fates.len());
    assert!(
        boundary > 0 && boundary < fates.len(),
        "the sweep must cross the keep point: {fates:?}"
    );
    // The rounds whose event was kept, and could be overtaken: every round of
    // a distance that fired, but the last round, which cannot be.
    let kept = (0..rounds - 1)
        .filter(|round| fates[(round % leads) as usize])
        .count() as u64;
    assert_overtaken_within_cap(&overtaken_rounds, kept);
    // Every round of a distance that fired, the last round too, was kept at
    // its trap, and checked; a trap at or past the keep point cancels the
    // event, and checks nothing.
    let fired_rounds = (0..rounds)
        .filter(|round| fates[(round % leads) as usize])
        .count() as u64;
    assert_eq!(
        keeps, fired_rounds,
        "every trap before the keep point must keep its event, with its programming unchanged, \
         and none past it: {fates:?}"
    );
    assert!(
        fates[boundary..].iter().all(|&fate| !fate),
        "a trap past the keep point must cancel the event, and one before it keep it: {fates:?}"
    );
    let last_fired = before + (boundary as u64 - 1) * stride;
    // The handler's return before its trap, by at most
    // `SIGRETURN_TRAP_BRANCHES`, puts the change at the keep point: the last
    // trap that kept the event came before the keep point, and the first that
    // cancelled it at or past the keep point.
    assert!(
        last_fired < keep_point && last_fired + stride + SIGRETURN_TRAP_BRANCHES >= keep_point,
        "the fate must change where the trap reaches the keep point {keep_point}: the event \
         fired with the handler returning up to {last_fired} branches after its request, and \
         was cancelled from {}",
        last_fired + stride
    );
    eprintln!(
        "the event fired with the handler returning up to {last_fired} branches after its \
         request, and was cancelled from {}",
        last_fired + stride
    );
    let clocks: Vec<u64> = events.iter().map(|&(_, rcbs)| rcbs).collect();
    assert_at_target_unless_witnessed(&clocks, rcbs, witnesses - overtaken.len() as u64);
    assert_late_within_backstop(&clocks, rcbs);
    last_fired
}

// The trap one branch apart across the keep point, from the first handler
// return that `SIGRETURN_TRAP_BRANCHES` guarantees still keeps the event, to
// 16 branches past the keep point. Farther from the keep point, where
// `SIGRETURN_TRAP_BRANCHES` alone decides the fate, the sweep across the skid
// margins takes the trap at 224 and 208 branches before the keep point, and
// at 32 past it, and the sweep up to the target from 2000 before it, 184
// apart.
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_decides_the_timer_by_the_guest_clock() {
    reverie_ptrace::ret_without_perf!();
    let before = sigreturn_keep_point() - SIGRETURN_TRAP_BRANCHES - 1;
    sweep_sigreturn_hook_trap(before, SIGRETURN_TRAP_BRANCHES + 17, 1, 2).await;
}

// The trap from 2000 branches before the keep point up to the target, across
// this processor's period, where the notification may have arrived at the
// trap, and its single steps toward the target, which may have begun.
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_up_to_the_target_cancels_the_timer() {
    reverie_ptrace::ret_without_perf!();
    const LEADS: u64 = 64;
    let before = sigreturn_keep_point() - 2_000;
    let stride = (SIGRETURN_RCBS - SIGRETURN_TRAP_BRANCHES - before) / LEADS;
    sweep_sigreturn_hook_trap(before, LEADS, stride, 4).await;
}

/// This test's name, which its re-runs select.
const SIGRETURN_MARGIN_TEST: &str =
    "the_rt_sigreturn_hook_keep_point_does_not_depend_on_the_skid_margin";

/// The line on which a re-run of `SIGRETURN_MARGIN_TEST` reports its sweep's
/// boundary.
const SIGRETURN_BOUNDARY_LINE: &str = "rt_sigreturn keep point boundary: ";

// The same sweep across the keep point finds the same boundary at this
// processor's skid margin, at 100, as on Intel processors, and at 10000, the
// largest in Reverie's PMU table, where the keep point is at the period. So a
// trap's outcome does not depend on the processor. Each margin needs a
// process of its own, since a process fixes its margin with its first timer.
#[tokio::test(flavor = "current_thread")]
async fn the_rt_sigreturn_hook_keep_point_does_not_depend_on_the_skid_margin() {
    reverie_ptrace::ret_without_perf!();
    // From the first multiple of 16 before the keep point at which
    // `SIGRETURN_TRAP_BRANCHES` guarantees the event is kept.
    let before = sigreturn_keep_point() - 224;
    let boundary = sweep_sigreturn_hook_trap(before, 17, 16, 2).await;
    if reverie_ptrace::testing::rerun_skid_margin().is_some() {
        println!("{SIGRETURN_BOUNDARY_LINE}{boundary}");
        return;
    }
    for margin in [100, 10_000] {
        let output = reverie_ptrace::testing::rerun_at_skid_margin(
            &[SIGRETURN_MARGIN_TEST, "--exact"],
            margin,
            1,
            Duration::from_secs(300),
        );
        let reported: Vec<u64> = output
            .lines()
            // The harness prints the test's name, without a newline, before
            // the test's own output.
            .filter_map(|line| line.split_once(SIGRETURN_BOUNDARY_LINE))
            .map(|(_, value)| value.trim().parse().unwrap())
            .collect();
        eprintln!("the keep point boundary at skid margin {margin}: {reported:?}");
        assert_eq!(
            reported,
            [boundary],
            "the keep point at skid margin {margin} must be the one at this processor's \
             margin, {}:\n{output}",
            reverie_ptrace::PmuConfig::new().skid_margin()
        );
    }
}

// Each handler requests an event that its rt_sigreturn hook trap keeps, with
// the timer's signal blocked, so that no notification can deliver it, and the
// guest runs past the target. The next round's signal overtakes the event,
// and Reverie witnesses a skid overshoot for it; the last round's event is
// still undecided when the thread exits, and its exit must witness it too,
// once, so that every round is witnessed and nothing fires. Each overtaking
// stop finds the event's notification queued, held back by the blocked
// signal, and Reverie counts it so (which the sweeps rely on to identify a
// notification held back by host latency instead); the exit cannot read the
// pending signals and does not.
#[tokio::test(flavor = "current_thread")]
async fn an_event_kept_across_an_rt_sigreturn_hook_trap_and_overtaken_is_witnessed_once() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = SIGRETURN_RCBS;
    let (lead, after) = (5_000, 2 * rcbs);
    let rounds = 16;
    let run = run_sigreturn_hook_timer_overtaken(rcbs, lead, 1, 0, rounds, after, true).await;
    assert_eq!(
        run.keeps, rounds,
        "each round's trap must keep its event, with its programming unchanged"
    );
    // The next round's signal overtook each event.
    for &(round, clock) in &run.overtaken {
        let stop = run.next_signal(round, lead, after);
        assert!(
            stop.contains(&clock),
            "round {round} was overtaken at {clock}, not by the next round's signal, {stop:?} \
             RCBs from its request"
        );
    }
    let SigreturnHookTimerRun {
        events,
        witnesses,
        overtaken,
        ..
    } = run;
    assert_eq!(events, [], "no notification can deliver an event");
    assert_eq!(
        witnesses, rounds,
        "each round's kept event was overtaken, and must be witnessed once"
    );
    assert_eq!(
        overtaken
            .iter()
            .map(|&(round, _)| round)
            .collect::<Vec<_>>(),
        (0..rounds - 1).collect::<Vec<_>>(),
        "the next round's stop overtook each round's event but the last, with its notification \
         queued: {overtaken:?}"
    );
    assert!(
        overtaken.iter().all(|&(_, clock)| clock >= rcbs),
        "{overtaken:?}"
    );
}

// The rt_sigreturn hook's trap past the target, with the timer's signal
// blocked, so that no notification can deliver the event before the trap:
// the limiting case of an interrupt so late that the trap comes first. The
// trap cancels the event, whose programming has passed its period, and
// `Timer::retire` records its delivery point as a skid overshoot, once per
// round, and nothing fires.
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_past_the_target_is_witnessed_once() {
    reverie_ptrace::ret_without_perf!();
    let margin = reverie_ptrace::PmuConfig::new().skid_margin();
    let rcbs = 10_000 + margin;
    let rounds = 16;
    let (events, witnesses) =
        run_sigreturn_hook_timer(rcbs, 2 * rcbs, 1, 0, rounds, 1_000, true).await;
    assert_eq!(events, [], "the cancelled timer must not fire");
    assert_eq!(
        witnesses, rounds,
        "each round's trap overtook its due event, and must be witnessed once"
    );
}

// Each handler requests an event whose target comes before its return, with
// the timer's signal unblocked, so that the notification delivers the event
// at its target inside the handler. The handler then runs on, and its
// rt_sigreturn hook trap comes well past that target, where
// `disregard_stop_before_period` retires the event. The event was delivered,
// so the retirement must not witness a skid overshoot for it, although the
// delivered event's target stays stored until the next request and the
// guest's clock is past it. Every round's event must fire, at its target, or
// past it only as a witnessed skid overshoot (see
// `assert_late_within_backstop`) when its own notification came too late,
// and nothing else may be witnessed (`assert_at_target_unless_witnessed`
// requires exactly one witness per late event, so a run with no late event
// must have none). No trap here keeps an event. The targets are 11000 RCBs,
// past the period on every processor in Reverie's PMU table, and
// `SIGRETURN_RCBS`.
//
// A third run alternates the two: at `SIGRETURN_RCBS`, even rounds return
// 5000 branches after the request, where the trap keeps the event, which
// fires in the branches after the handler, and odd rounds return past the
// target, after the event was delivered in the handler. The kept events'
// programming must be unchanged (see `KeptProgrammingChecks`), and every
// round's event must fire as in the other runs.
//
// The one exception is the host timing that `sweep_sigreturn_hook_trap`
// identifies by its cause, here with the rt_sigreturn hook trap as the
// overtaking stop: a notification not serviced before the trap, although
// queued at it, so that the trap decides the event past its target and
// witnesses it. Such a round alone may be missing, overtaken at the trap,
// and every other round must fire (see `overtaken_rounds`).
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_past_a_delivered_event_is_not_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rounds = 16;
    for rcbs in [11_000, SIGRETURN_RCBS] {
        let lead = 2 * rcbs;
        let run = run_sigreturn_hook_timer_overtaken(rcbs, lead, 1, 0, rounds, 1_000, false).await;
        // The handler's return, and its rt_sigreturn hook trap at most
        // `SIGRETURN_TRAP_BRANCHES` after it, is the first stop after the
        // target.
        let overtaken = overtaken_rounds(&run, rcbs, rounds, |_| {
            lead..lead + SIGRETURN_TRAP_BRANCHES + 1
        });
        assert_overtaken_within_cap(&overtaken, rounds);
        assert_eq!(run.keeps, 0, "no trap past a delivered event keeps it");
        let events = &run.events;
        assert_eq!(
            events.iter().map(|&(round, _)| round).collect::<Vec<_>>(),
            (0..rounds)
                .filter(|round| !overtaken.contains_key(round))
                .collect::<Vec<_>>(),
            "every round's event must fire before its handler returns, unless overtaken with \
             its notification queued: {events:?}, overtaken {overtaken:?}"
        );
        let clocks: Vec<u64> = events.iter().map(|&(_, rcbs)| rcbs).collect();
        assert_at_target_unless_witnessed(&clocks, rcbs, run.witnesses - overtaken.len() as u64);
        assert_late_within_backstop(&clocks, rcbs);
    }
    // Even rounds keep, odd rounds deliver in the handler.
    let rcbs = SIGRETURN_RCBS;
    let (kept_lead, delivered_lead, after) = (5_000, 2 * rcbs, 2 * rcbs);
    let lead = |round: u64| {
        if round.is_multiple_of(2) {
            kept_lead
        } else {
            delivered_lead
        }
    };
    let run = run_sigreturn_hook_timer_overtaken(
        rcbs,
        kept_lead,
        2,
        delivered_lead - kept_lead,
        rounds,
        after,
        false,
    )
    .await;
    // A kept event's only overtaking stop is the next round's signal, and a
    // delivered one's the trap.
    let overtaken = overtaken_rounds(&run, rcbs, rounds, |round| {
        if round.is_multiple_of(2) {
            run.next_signal(round, kept_lead, after)
        } else {
            lead(round)..lead(round) + SIGRETURN_TRAP_BRANCHES + 1
        }
    });
    assert_overtaken_within_cap(&overtaken, rounds);
    assert_eq!(
        run.keeps,
        rounds / 2,
        "each even round's trap must keep its event, with its programming unchanged, and no \
         odd round's"
    );
    let events = &run.events;
    assert_eq!(
        events.iter().map(|&(round, _)| round).collect::<Vec<_>>(),
        (0..rounds)
            .filter(|round| !overtaken.contains_key(round))
            .collect::<Vec<_>>(),
        "every round's event must fire, unless overtaken with its notification queued: \
         {events:?}, overtaken {overtaken:?}"
    );
    let clocks: Vec<u64> = events.iter().map(|&(_, rcbs)| rcbs).collect();
    assert_at_target_unless_witnessed(&clocks, rcbs, run.witnesses - overtaken.len() as u64);
    assert_late_within_backstop(&clocks, rcbs);
}

// Each handler requests an event, with the timer's signal blocked, and then
// makes a getpid that the Tool sees, short of the target, which decides the
// event: the Tool requests nothing at it, so the event is cancelled, and its
// status stays Armed, since the timer's signal, which the cancelled event's
// programming still raises, is blocked and makes no stop before the trap.
// The rt_sigreturn hook trap comes well past the target, where
// `disregard_stop_before_period` retires the event. A stop the Tool saw had
// already decided the event before the target, so nothing may be witnessed,
// and nothing fires. (`Timer::retire` must not record an Armed event.)
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_past_an_event_a_seen_stop_decided_is_not_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rounds = 16;
    for (rcbs, observe_at) in [(11_000, 500), (SIGRETURN_RCBS, 5_000)] {
        let (events, witnesses) = run_sigreturn_hook_timer_observed(
            rcbs,
            2 * rcbs,
            rounds,
            1_000,
            true,
            observe_at,
            false,
        )
        .await;
        assert_eq!(events, [], "the cancelled timer must not fire");
        assert_eq!(
            witnesses, 0,
            "a stop the Tool saw cancelled each event {observe_at} RCBs after its request, \
             short of its target {rcbs}, and nothing may witness it later"
        );
    }
}

// As above, but with the timer's signal unblocked: the getpid that the Tool
// sees, short of the target, cancels the event, and the notification that
// its programming still raises at the target, inside the handler, makes a
// stop that finds the event cancelled, and discards the signal, so the event
// is Cancelled when the rt_sigreturn hook trap comes well past the target.
// `Timer::retire` must not record a Cancelled event either: nothing may be
// witnessed, nothing fires, and every round's signal is discarded as a
// cancelled event's, none delivered.
#[tokio::test(flavor = "current_thread")]
async fn an_rt_sigreturn_hook_trap_past_a_cancelled_event_is_not_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rounds = 16;
    for (rcbs, observe_at) in [(11_000, 500), (SIGRETURN_RCBS, 5_000)] {
        let discarded_before = reverie_ptrace::testing::cancelled_timer_signals_discarded();
        let run = run_sigreturn_hook_timer_args(
            rcbs,
            rounds,
            &[2 * rcbs, rounds, 1_000, 1, 0, 0, observe_at, 0],
        )
        .await;
        let discarded =
            reverie_ptrace::testing::cancelled_timer_signals_discarded() - discarded_before;
        assert_eq!(run.events, [], "the cancelled timer must not fire");
        assert_eq!(
            run.witnesses, 0,
            "a stop the Tool saw cancelled each event {observe_at} RCBs after its request, \
             short of its target {rcbs}, and nothing may witness it later"
        );
        assert_eq!(run.overtaken, [], "no event reached its target undecided");
        assert_eq!(
            discarded, rounds,
            "each round's notification must find its event cancelled"
        );
    }
}

// An event decided past its target is witnessed exactly once, whichever stop
// decides it, however many stops come after:
// - A getpid that the Tool sees, 5000 RCBs past the target, overtakes the
//   event, whose notification the blocked timer signal holds back, and
//   witnesses it. The rt_sigreturn hook trap that follows retires the
//   decided event and must not witness it again.
// - With no such getpid, the rt_sigreturn hook trap past the target is the
//   first stop to decide the event, and `Timer::retire` witnesses it. A
//   getpid that the Tool sees after the handler has returned then finds the
//   event cancelled and must not witness it again.
#[tokio::test(flavor = "current_thread")]
async fn an_event_decided_past_its_target_is_witnessed_once_by_the_first_stop() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 11_000;
    let rounds = 16;
    for (observe_at, observe_after, first) in [
        (rcbs + 5_000, false, "the getpid the Tool sees"),
        (0, true, "the rt_sigreturn hook trap"),
    ] {
        let (events, witnesses) = run_sigreturn_hook_timer_observed(
            rcbs,
            2 * rcbs,
            rounds,
            1_000,
            true,
            observe_at,
            observe_after,
        )
        .await;
        assert_eq!(events, [], "no notification can deliver an event");
        assert_eq!(
            witnesses, rounds,
            "{first} overtook each round's due event, which must be witnessed once"
        );
    }
}

/// Runs `hybrid_held_signal_hook_timer.c` for `rounds` rounds, with a precise
/// timer `rcbs` RCBs past each round's request and the round's rt_sigsuspend,
/// which the guest's seccomp filter traps, `before` branches past it, a getpid
/// that the Tool sees but that requests nothing `observe_at` branches past it
/// if `observe_at` is nonzero, and the timer's signal blocked throughout if
/// `block_timer_signal`. Returns each timer event's round and RCBs from its
/// request, the skid overshoots Reverie witnessed, and the kept events whose
/// programming was checked unchanged (see `KeptProgrammingChecks`). Every
/// round's SIGSYS must reach the guest's handler before its rt_sigsuspend
/// returns.
async fn run_held_signal_hook_timer(
    rcbs: u64,
    before: u64,
    rounds: u64,
    after: u64,
    observe_at: u64,
    block_timer_signal: bool,
) -> (Vec<(u64, u64)>, u64, u64) {
    run_held_signal_hook_timer_handler(
        rcbs,
        before,
        rounds,
        after,
        observe_at,
        block_timer_signal,
        0,
    )
    .await
}

/// As `run_held_signal_hook_timer`, with the SIGSYS handler running
/// `handler_branches` branches before it returns.
async fn run_held_signal_hook_timer_handler(
    rcbs: u64,
    before: u64,
    rounds: u64,
    after: u64,
    observe_at: u64,
    block_timer_signal: bool,
    handler_branches: u64,
) -> (Vec<(u64, u64)>, u64, u64) {
    let (_directory, guest) = compile_fixture("hybrid_held_signal_hook_timer.c");
    let mut command = Command::new(guest);
    command.args([
        before.to_string(),
        rounds.to_string(),
        after.to_string(),
        observe_at.to_string(),
        u64::from(block_timer_signal).to_string(),
        handler_branches.to_string(),
    ]);
    // Process global; see `assert_at_target_unless_witnessed`.
    let _ = reverie::take_skid_overshoot_count();
    let checks = KeptProgrammingChecks::start();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(120),
        LiteinstBackend::run_host_with_output_and_preload::<SigreturnHookTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the held signal guest did not complete")
    .unwrap();
    let witnesses = reverie::take_skid_overshoot_count();
    let keeps = checks.keeps();
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("rounds={rounds} handled={rounds} wrong=0\n")
    );
    assert_eq!(global.requests.load(Ordering::SeqCst), rounds);
    let events = global.timer_events.into_inner().unwrap();
    assert!(
        events.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "{events:?}"
    );
    (events, witnesses, keeps)
}

// An unsubscribed hook trap whose injected syscall ends at a guest signal,
// which Reverie holds for the guest's resume, cancels the timer event with
// `Timer::retire` whatever its state, and `Timer::retire` records only an
// event that no stop has decided. An event delivered on time, before the
// trap, and one that a stop the Tool sees cancelled before its target, whose
// notification then finds it cancelled, have both been decided: the trap
// past their old targets must not witness them. Neither trap finds a
// scheduled event to keep, so no kept programming is checked here (see
// `KeptProgrammingChecks`).
#[tokio::test(flavor = "current_thread")]
async fn a_held_signal_past_a_delivered_or_cancelled_event_is_not_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 11_000;
    let rounds = 16;
    let (events, witnesses, keeps) =
        run_held_signal_hook_timer(rcbs, 2 * rcbs, rounds, 1_000, 0, false).await;
    assert_eq!(keeps, 0, "a trap past a delivered event keeps nothing");
    let fired: Vec<u64> = events.iter().map(|&(round, _)| round).collect();
    assert_eq!(fired, (0..rounds).collect::<Vec<_>>(), "{events:?}");
    let clocks: Vec<u64> = events.iter().map(|&(_, rcbs)| rcbs).collect();
    assert_at_target_unless_witnessed(&clocks, rcbs, witnesses);
    assert_late_within_backstop(&clocks, rcbs);
    let (events, witnesses, keeps) =
        run_held_signal_hook_timer(rcbs, 2 * rcbs, rounds, 1_000, 500, true).await;
    assert_eq!(keeps, 0, "a trap past a cancelled event keeps nothing");
    assert_eq!(events, [], "the getpid the Tool sees cancels each event");
    assert_eq!(witnesses, 0, "a cancelled event must not be witnessed");
}

// With the timer's signal blocked, no notification delivers an event, and
// the trap past its target is the first stop to decide it: each round's
// event must be witnessed once, and nothing must fire. The event is still
// scheduled at the trap, which first keeps it, with its programming
// unchanged (see `KeptProgrammingChecks`), and then, for the held signal,
// retires it.
#[tokio::test(flavor = "current_thread")]
async fn a_held_signal_past_an_undecided_event_is_witnessed_once() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 11_000;
    let rounds = 16;
    let (events, witnesses, keeps) =
        run_held_signal_hook_timer(rcbs, 2 * rcbs, rounds, 1_000, 0, true).await;
    assert_eq!(
        keeps, rounds,
        "each trap must keep its scheduled event, with its programming unchanged, before \
         retiring it"
    );
    assert_eq!(events, [], "no notification can deliver an event");
    assert_eq!(
        witnesses, rounds,
        "each round's due event must be witnessed once"
    );
}

/// How many of `rounds` held-signal hook traps keep their event, and so
/// check its programming (see `KeptProgrammingChecks`), in the tests below,
/// at a skid margin of `margin`. At a margin of 100 each trap, about 110 or
/// 260 RCBs past the request, comes before the notification period of 300
/// RCBs: the event is still scheduled, and the trap keeps it, checked, before
/// the held signal makes it retire the event. At a margin of 1000 the steps
/// started at the request, so no event is scheduled at the trap.
fn held_signal_trap_keeps(margin: u64, rounds: u64) -> u64 {
    match margin {
        100 => rounds,
        1_000 => 0,
        _ => panic!("the held-signal tests re-run at skid margins of 100 and 1000, not {margin}"),
    }
}

/// This test's name, which its re-runs select.
const HELD_SIGNAL_STEPS_TEST: &str =
    "a_held_signal_at_a_hook_trap_in_the_timer_steps_cancels_the_event";

// The target is 400 RCBs past each request, and the trap about 110 RCBs, the
// getpid hook's own return path and the round's lead, past it. At a skid
// margin of 1000, as on AMD processors, the timer is delivered with an
// artificial signal at the request, the steps start there, and the trap
// interrupts them. At a skid margin of 100, as on Intel processors, the trap
// comes before the period. At both, the held SIGSYS's handler must run
// before the guest's next instruction, so nothing of the event can be
// continued first: the trap cancels the event with `Timer::retire`,
// unwitnessed since its target was not reached, and the handler must run
// before the rt_sigsuspend returns, which the guest checks. (Were the trap
// not to cancel it, the stale single step SIGTRAP of the injected syscall,
// which Reverie discards, would be the next stop, and decide the event at
// the same clock.) The outcome is the same at both margins; each needs a
// process of its own. At a margin of 100 each trap first keeps its event,
// whose programming must be unchanged (see `held_signal_trap_keeps`).
#[tokio::test(flavor = "current_thread")]
async fn a_held_signal_at_a_hook_trap_in_the_timer_steps_cancels_the_event() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 400;
    let rounds = 16;
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            for margin in [100, 1_000] {
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[HELD_SIGNAL_STEPS_TEST, "--exact"],
                    margin,
                    1,
                    Duration::from_secs(300),
                );
            }
        }
        Some(margin) => {
            for before in [1, 150] {
                let (events, witnesses, keeps) =
                    run_held_signal_hook_timer(rcbs, before, rounds, 1_000, 0, false).await;
                assert_eq!(events, [], "each event must be cancelled");
                assert_eq!(witnesses, 0, "no event reached its target");
                assert_eq!(
                    keeps,
                    held_signal_trap_keeps(margin, rounds),
                    "at a skid margin of {margin}"
                );
            }
        }
    }
}

/// This test's name, which its re-runs select.
const HELD_SIGNAL_LONG_HANDLER_TEST: &str =
    "a_held_signal_cancels_the_event_before_a_handler_that_runs_past_the_target";

// As above, with the SIGSYS handler running 5000 branches, past the target:
// the trap's cancellation must also end the event's programming, so that no
// notification arrives inside the handler, whose signal a stop would find
// for a cancelled event and discard. Nothing fires, nothing is witnessed,
// and no timer signal is discarded, at both skid margins. The traps keep and
// check events as above (see `held_signal_trap_keeps`).
#[tokio::test(flavor = "current_thread")]
async fn a_held_signal_cancels_the_event_before_a_handler_that_runs_past_the_target() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 400;
    let rounds = 16;
    match reverie_ptrace::testing::rerun_skid_margin() {
        None => {
            for margin in [100, 1_000] {
                reverie_ptrace::testing::rerun_at_skid_margin(
                    &[HELD_SIGNAL_LONG_HANDLER_TEST, "--exact"],
                    margin,
                    1,
                    Duration::from_secs(300),
                );
            }
        }
        Some(margin) => {
            for before in [1, 150] {
                let discarded_before = reverie_ptrace::testing::cancelled_timer_signals_discarded();
                let (events, witnesses, keeps) = run_held_signal_hook_timer_handler(
                    rcbs, before, rounds, 1_000, 0, false, 5_000,
                )
                .await;
                let discarded =
                    reverie_ptrace::testing::cancelled_timer_signals_discarded() - discarded_before;
                assert_eq!(events, [], "each event must be cancelled");
                assert_eq!(witnesses, 0, "no event reached its target undecided");
                assert_eq!(
                    keeps,
                    held_signal_trap_keeps(margin, rounds),
                    "at a skid margin of {margin}"
                );
                assert_eq!(
                    discarded, 0,
                    "the trap must end each event's programming, before the handler runs \
                     past its target"
                );
            }
        }
    }
}

// A LiteInst thread whose timer event is overtaken, and which then exits with
// the event undecided. The guest blocks the timer's signal, requests the
// event at getpid, runs twice its RCBs, and makes a getppid and an exit_group
// through the patched site. Each is a hook trap that the Tool does not see,
// so neither decides the event, and the thread's exit ends it. The event was
// due before the first trap, so Reverie must witness one skid overshoot, as
// it does when a stop the Tool sees overtakes a due event, and nothing must
// fire.
#[tokio::test(flavor = "current_thread")]
async fn an_exit_through_a_hook_trap_past_the_target_is_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 10_000 + reverie_ptrace::PmuConfig::new().skid_margin();
    let (_directory, guest) = compile_fixture("hybrid_exit_after_hook_trap.c");
    let mut command = Command::new(guest);
    command.arg((2 * rcbs).to_string());
    // Process global; see `assert_at_target_unless_witnessed`.
    let _ = reverie::take_skid_overshoot_count();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(60),
        LiteinstBackend::run_host_with_output_and_preload::<SigreturnHookTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the exiting guest did not complete")
    .unwrap();
    let witnesses = reverie::take_skid_overshoot_count();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(global.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        global.timer_events.into_inner().unwrap(),
        Vec::<(u64, u64)>::new(),
        "no notification can deliver the event"
    );
    assert_eq!(
        witnesses, 1,
        "the exit must settle the overtaken event, witnessed once"
    );
}

// The same guest, with the Tool subscribed to exit_group. The getppid's hook
// trap still leaves the event, but the exit_group's stop, which the Tool
// sees, decides it, past the target, and the thread exits before that stop's
// handling ends. The thread's exit must settle the stop, which witnesses the
// overtaken event once, and nothing must fire.
#[tokio::test(flavor = "current_thread")]
async fn an_exit_the_tool_sees_past_the_target_is_witnessed() {
    reverie_ptrace::ret_without_perf!();
    let rcbs = 10_000 + reverie_ptrace::PmuConfig::new().skid_margin();
    let (_directory, guest) = compile_fixture("hybrid_exit_after_hook_trap.c");
    let mut command = Command::new(guest);
    command.arg((2 * rcbs).to_string());
    // Process global; see `assert_at_target_unless_witnessed`.
    let _ = reverie::take_skid_overshoot_count();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(60),
        LiteinstBackend::run_host_with_output_and_preload::<ExitSeenTimerTool>(
            command,
            rcbs,
            preload_path(),
        ),
    )
    .await
    .expect("the exiting guest did not complete")
    .unwrap();
    let witnesses = reverie::take_skid_overshoot_count();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(global.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        global.timer_events.into_inner().unwrap(),
        Vec::<(u64, u64)>::new(),
        "no notification can deliver the event"
    );
    assert_eq!(
        witnesses, 1,
        "the exit must settle the stop that overtook the event, witnessed once"
    );
}

// Host-hybrid syscall restart (hybrid_restart.c). The fixture routes every
// syscall under test through one asm site, so after the subscribed warm-up
// read patches it, each call reaches the tracer through the runtime's int3
// trap, where the controller's `orig_rax` is -1 and Linux never restarts the
// syscall by itself. The same Tool runs under plain ptrace for comparison.
const RESTART_WARM_FD: u64 = 0x7e56;
const RESTART_MAGIC_FD: u64 = 0x7e57;
const RESTART_QUERY_FD: u64 = 0x7e58;
const RESTART_RESULT: i64 = 4243;
/// Read by the `handler-nested` handlers; see `RestartTool`.
const RESTART_NESTED_FD: u64 = 0x7e59;
const RESTART_NESTED_RESULT: i64 = 4244;

/// `RestartTool` configuration, packed into the `u64` Tool config.
#[derive(Clone, Copy, Default)]
struct RestartPlan {
    /// Linux restart code returned for the first `restarts` magic reads.
    errno: i32,
    /// How many magic invocations return `errno` before `RESTART_RESULT`.
    restarts: u8,
    /// A signal the Tool sends the thread on the first magic invocation.
    signal: i32,
    /// Also subscribe `restart_syscall`.
    subscribe_restart_syscall: bool,
    /// Request a precise timer due within the skid margin on the first magic
    /// invocation, so the timer's single-step runs across the restart re-trap.
    timer: bool,
    /// A syscall the Tool injects on the first magic invocation, after any
    /// `signal`.
    inject: RestartInject,
    /// Request a precise timer `SIGNAL_TIMER_RCBS` ahead from the signal
    /// event of `signal`, due after the guest handler returns.
    signal_timer: bool,
    /// Inject `getpid` from the signal event of `signal`.
    inject_in_signal: bool,
    /// Deliver `SIGTRAP` in place of `signal` from its signal event.
    deliver_sigtrap: bool,
    /// With `signal_timer`, request the timer `SIGNAL_TIMER_NEAR_RCBS` ahead
    /// instead, so its single-step window covers the handler's return.
    signal_timer_near: bool,
    /// Pass the original magic read through (`Guest::inject`) right after
    /// sending `signal`, instead of returning a result.
    inject_original: bool,
}

/// Far enough past the delivery of a quiet guest handler that neither the
/// timer's notification nor its single-step window reaches the handler's
/// return, and well within the fixture's `-spin` loop after the read.
const SIGNAL_TIMER_RCBS: u64 = 50_000;

/// Near enough that, with the skid margin pinned to `TIMER_TEST_SKID_MARGIN`,
/// the timer's single-step window covers the quiet handler's return, so the
/// step loop reaches a restart landing.
const SIGNAL_TIMER_NEAR_RCBS: u64 = 1000;

/// A syscall `RestartTool` injects inside the first magic invocation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RestartInject {
    #[default]
    None,
    /// `getpid`, with the Tool's signal already pending: the signal arrives
    /// during the injection, and the tracer holds it for the resume.
    Getpid,
    /// `rt_sigprocmask(SIG_UNBLOCK, arg1)`: the magic read's buffer is the
    /// guest's blocked set, so this unblocks a signal already pending.
    UnblockBuffer,
}

impl RestartPlan {
    fn encode(self) -> u64 {
        (self.errno as u64 & 0xffff)
            | ((self.signal as u64 & 0xff) << 16)
            | ((self.restarts as u64) << 24)
            | ((self.subscribe_restart_syscall as u64) << 32)
            | ((self.timer as u64) << 33)
            | ((self.inject as u64) << 34)
            | ((self.signal_timer as u64) << 36)
            | ((self.inject_in_signal as u64) << 37)
            | ((self.deliver_sigtrap as u64) << 38)
            | ((self.signal_timer_near as u64) << 39)
            | ((self.inject_original as u64) << 40)
    }

    fn decode(config: u64) -> Self {
        Self {
            errno: (config & 0xffff) as i32,
            signal: ((config >> 16) & 0xff) as i32,
            restarts: ((config >> 24) & 0xff) as u8,
            subscribe_restart_syscall: (config >> 32) & 1 != 0,
            timer: (config >> 33) & 1 != 0,
            inject: match (config >> 34) & 3 {
                0 => RestartInject::None,
                1 => RestartInject::Getpid,
                2 => RestartInject::UnblockBuffer,
                other => panic!("bad RestartInject {other}"),
            },
            signal_timer: (config >> 36) & 1 != 0,
            inject_in_signal: (config >> 37) & 1 != 0,
            deliver_sigtrap: (config >> 38) & 1 != 0,
            signal_timer_near: (config >> 39) & 1 != 0,
            inject_original: (config >> 40) & 1 != 0,
        }
    }
}

#[derive(Debug, Default)]
struct RestartLog {
    events: std::sync::Mutex<Vec<String>>,
    magic_calls: AtomicU64,
    nested_calls: AtomicU64,
    signals: AtomicU64,
}

impl RestartLog {
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for RestartLog {
    type Request = String;
    type Response = u64;
    type Config = u64;

    /// Records one Tool-visible event. A magic or nested call returns its
    /// 0-based index among its kind; `query` returns the number of signals
    /// seen, without recording.
    async fn receive_rpc(&self, _from: Tid, event: String) -> u64 {
        if event == "query" {
            return self.signals.load(Ordering::SeqCst);
        }
        let index = if event.starts_with("magic ") {
            self.magic_calls.fetch_add(1, Ordering::SeqCst)
        } else if event.starts_with("nested ") {
            self.nested_calls.fetch_add(1, Ordering::SeqCst)
        } else {
            0
        };
        if event.starts_with("signal ") {
            self.signals.fetch_add(1, Ordering::SeqCst);
        }
        self.events.lock().unwrap().push(event);
        index
    }
}

#[derive(Default)]
struct RestartTool;

#[reverie::tool]
impl Tool for RestartTool {
    type GlobalState = RestartLog;
    /// The clock when the signal event requested its precise timer, so the
    /// timer event can report how many RCBs later it fired.
    type ThreadState = Option<u64>;

    fn subscriptions(config: &u64) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::read);
        if RestartPlan::decode(*config).subscribe_restart_syscall {
            subscription.syscall(Sysno::restart_syscall);
        }
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        let plan = RestartPlan::decode(*guest.config());
        if nr == Sysno::read && args.arg0 as u64 == RESTART_WARM_FD {
            guest.send_rpc("read(warm)".to_owned()).await;
            return Ok(0);
        }
        if nr == Sysno::read && args.arg0 as u64 == RESTART_QUERY_FD {
            return Ok(guest.send_rpc("query".to_owned()).await as i64);
        }
        if nr == Sysno::read && args.arg0 as u64 == RESTART_NESTED_FD {
            // A restart with no signal, made from inside a signal handler.
            let index = guest
                .send_rpc(format!("nested {nr}({:#x},{})", args.arg0, args.arg2))
                .await;
            if index == 0 {
                return Err(reverie::Errno::ERESTARTSYS.into());
            }
            return Ok(RESTART_NESTED_RESULT);
        }
        if args.arg0 as u64 == RESTART_MAGIC_FD
            && (nr == Sysno::read || nr == Sysno::restart_syscall)
        {
            let index = guest
                .send_rpc(format!("magic {nr}({:#x},{})", args.arg0, args.arg2))
                .await;
            if index == 0 && plan.signal != 0 {
                // SAFETY: tgkill has no memory effects.
                let sent = unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        guest.pid().as_raw(),
                        guest.tid().as_raw(),
                        plan.signal,
                    )
                };
                assert_eq!(sent, 0, "tgkill failed");
            }
            if plan.inject_original {
                return Ok(guest.inject(syscall).await?);
            }
            if index == 0 {
                match plan.inject {
                    RestartInject::None => {}
                    RestartInject::Getpid => {
                        // The result is not asserted: the pending signal can
                        // interrupt the injection itself.
                        let getpid =
                            Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                        let _ = guest.inject(getpid).await;
                    }
                    RestartInject::UnblockBuffer => {
                        let unblock = Syscall::from_raw(
                            Sysno::rt_sigprocmask,
                            SyscallArgs::new(libc::SIG_UNBLOCK as usize, args.arg1, 0, 8, 0, 0),
                        );
                        assert_eq!(guest.inject(unblock).await, Ok(0), "unblock failed");
                    }
                }
            }
            if index == 0 && plan.timer {
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(1))
                    .unwrap();
            }
            if index < plan.restarts as u64 {
                return Err(reverie::Errno::new(plan.errno).into());
            }
            return Ok(RESTART_RESULT);
        }
        if nr == Sysno::restart_syscall {
            guest.send_rpc("restart_syscall".to_owned()).await;
        }
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, reverie::Errno> {
        guest.send_rpc(format!("signal {}", signal.as_str())).await;
        let plan = RestartPlan::decode(*guest.config());
        if signal as i32 == plan.signal {
            if plan.signal_timer {
                let rcbs = if plan.signal_timer_near {
                    SIGNAL_TIMER_NEAR_RCBS
                } else {
                    SIGNAL_TIMER_RCBS
                };
                guest
                    .set_timer_precise(reverie::TimerSchedule::Rcbs(rcbs))
                    .unwrap();
                let armed = guest.read_clock().unwrap();
                *guest.thread_state_mut() = Some(armed);
            }
            if plan.inject_in_signal {
                let getpid = Syscall::from_raw(Sysno::getpid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
                assert_eq!(
                    guest.inject(getpid).await,
                    Ok(guest.pid().as_raw() as i64),
                    "getpid injected from the signal event failed"
                );
            }
            if plan.deliver_sigtrap {
                return Ok(Some(reverie::Signal::SIGTRAP));
            }
        }
        Ok(Some(signal))
    }

    /// A timer requested from a signal event reports the RCBs since the
    /// request, which a precise timer makes exactly the requested count.
    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let event = match guest.thread_state_mut().take() {
            Some(armed) => format!("timer +{}", guest.read_clock().unwrap() - armed),
            None => "timer".to_owned(),
        };
        guest.send_rpc(event).await;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RestartBackend {
    HostHybrid,
    Ptrace,
}

async fn run_restart_fixture(
    backend: RestartBackend,
    mode: &str,
    plan: RestartPlan,
) -> Result<(String, Vec<String>), Error> {
    let (output, events) = run_restart_fixture_output(backend, mode, plan).await?;
    assert!(
        output.status.success(),
        "{backend:?} {mode} guest failed: {output:?}"
    );
    Ok((String::from_utf8(output.stdout).unwrap(), events))
}

/// As `run_restart_fixture`, for a guest that may exit unsuccessfully.
async fn run_restart_fixture_output(
    backend: RestartBackend,
    mode: &str,
    plan: RestartPlan,
) -> Result<(reverie::process::Output, Vec<String>), Error> {
    let (_directory, guest) = compile_fixture("hybrid_restart.c");
    let mut command = Command::new(guest);
    command.arg(mode);
    let (output, log) = match backend {
        RestartBackend::HostHybrid => {
            LiteinstBackend::run_host_with_output_and_preload::<RestartTool>(
                command,
                plan.encode(),
                preload_path(),
            )
            .await?
        }
        RestartBackend::Ptrace => {
            command
                .stdout(reverie::process::Stdio::piped())
                .stderr(reverie::process::Stdio::piped());
            reverie_ptrace::TracerBuilder::<RestartTool>::new(command)
                .config(plan.encode())
                .spawn()
                .await?
                .wait_with_output()
                .await?
        }
    };
    Ok((output, log.events()))
}

fn restart_counts(backend: RestartBackend, hooks: u64) -> String {
    match backend {
        RestartBackend::HostHybrid => format!("traps=1 hooks={hooks}"),
        RestartBackend::Ptrace => "traps=- hooks=-".to_owned(),
    }
}

const RESTART_BACKENDS: [RestartBackend; 2] = [RestartBackend::HostHybrid, RestartBackend::Ptrace];

/// A Tool-returned restart code re-traps and re-invokes the Tool instead of
/// reaching the guest as a raw `-ERESTART*`, as the kernel restarts the
/// syscall under plain ptrace. The re-trap re-executes only the runtime int3,
/// so the site's hook count stays at the single hook entry.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_tool_restart_codes_re_invoke_the_syscall() {
    for errno in [
        reverie::Errno::ERESTARTSYS,
        reverie::Errno::ERESTARTNOINTR,
        reverie::Errno::ERESTARTNOHAND,
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 2,
            ..Default::default()
        };
        for backend in RESTART_BACKENDS {
            let (stdout, events) = run_restart_fixture(backend, "read", plan).await.unwrap();
            assert_eq!(
                stdout,
                format!(
                    "read-result={RESTART_RESULT} {}\n",
                    restart_counts(backend, 1)
                ),
                "{backend:?} {errno}"
            );
            assert_eq!(
                events,
                [
                    "read(warm)",
                    "magic read(0x7e57,1)",
                    "magic read(0x7e57,1)",
                    "magic read(0x7e57,1)"
                ],
                "{backend:?} {errno}"
            );
        }
    }
}

/// `-ERESTART_RESTARTBLOCK` re-dispatches as `restart_syscall` with the
/// original argument registers, as Linux does.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restartblock_re_invokes_restart_syscall() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTART_RESTARTBLOCK.into_raw(),
        restarts: 2,
        subscribe_restart_syscall: true,
        ..Default::default()
    };
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "read", plan).await.unwrap();
        assert_eq!(
            stdout,
            format!(
                "read-result={RESTART_RESULT} {}\n",
                restart_counts(backend, 1)
            ),
            "{backend:?}"
        );
        assert_eq!(
            events,
            [
                "read(warm)",
                "magic read(0x7e57,1)",
                "magic restart_syscall(0x7e57,1)",
                "magic restart_syscall(0x7e57,1)"
            ],
            "{backend:?}"
        );
    }
}

/// A signal pending when the Tool returns `-ERESTARTSYS` is delivered, and
/// seen by the Tool, before the syscall is re-invoked: the restart resumes the
/// guest rather than re-dispatching inside the tracer.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_delivers_the_signal_before_re_invoking() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGURG,
        ..Default::default()
    };
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "read", plan).await.unwrap();
        assert_eq!(
            stdout,
            format!(
                "read-result={RESTART_RESULT} {}\n",
                restart_counts(backend, 1)
            ),
            "{backend:?}"
        );
        assert_eq!(
            events,
            [
                "read(warm)",
                "magic read(0x7e57,1)",
                "signal SIGURG",
                "magic read(0x7e57,1)"
            ],
            "{backend:?}"
        );
    }
}

/// Runs `mode` under both backends and requires the same guest output (up to
/// the site counters, with `hooks` host-hybrid hook entries) and the same
/// Tool-visible events, returning plain ptrace's.
async fn restart_parity(
    mode: &str,
    plan: RestartPlan,
    hooks: u64,
    label: &str,
) -> (String, Vec<String>) {
    let (ptrace_stdout, ptrace_events) = run_restart_fixture(RestartBackend::Ptrace, mode, plan)
        .await
        .unwrap();
    let (hybrid_stdout, hybrid_events) =
        run_restart_fixture(RestartBackend::HostHybrid, mode, plan)
            .await
            .unwrap();
    assert_eq!(
        hybrid_stdout,
        ptrace_stdout.replace(
            &restart_counts(RestartBackend::Ptrace, 1),
            &restart_counts(RestartBackend::HostHybrid, hooks)
        ),
        "{label}: host-hybrid output differs from plain ptrace"
    );
    assert_eq!(
        hybrid_events, ptrace_events,
        "{label}: host-hybrid Tool events differ from plain ptrace"
    );
    (ptrace_stdout, ptrace_events)
}

/// Attempts `timer_restart_parity` may make when an attempt diverges.
const SKID_ATTEMPTS: usize = 3;

/// Skid margin the precise-timer restart tests pin in their child process,
/// through reverie-ptrace's `REVERIE_SKID_MARGIN_OVERRIDE`. A precise timer
/// single-steps its last `skid margin` RCBs, so with this margin the window
/// of a timer due `SIGNAL_TIMER_NEAR_RCBS` after its request starts at the
/// request and covers the quiet handler's return on every host. The
/// processor defaults differ (100 or 125 RCBs on the Intel profiles), and
/// with them the landing would come before the window.
const TIMER_TEST_SKID_MARGIN: u64 = SIGNAL_TIMER_NEAR_RCBS;

/// Names the precise-timer restart test that a child test process runs.
const TIMER_TEST_CHILD_ENV: &str = "REVERIE_LITEINST_TIMER_TEST_CHILD";

/// Whether this process is the child test process that runs `test`. If it
/// is not, runs `test` in a fresh exact-test child process with one test
/// thread and the skid margin pinned to `TIMER_TEST_SKID_MARGIN`, and
/// requires it to pass. The skid-overshoot count and the reverie-ptrace
/// test counters `timer_restart_parity` reads are process-global, so only a
/// process that runs one test at a time can attribute them to one backend's
/// run.
fn in_timer_test_child(test: &str) -> bool {
    if std::env::var(TIMER_TEST_CHILD_ENV).as_deref() == Ok(test) {
        let args: Vec<String> = std::env::args().collect();
        assert!(
            args.iter().any(|arg| arg == "--exact")
                && args.iter().any(|arg| arg == "--test-threads=1"),
            "{test} must run as the only test of its process: {args:?}"
        );
        return true;
    }
    let status = ProcessCommand::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(TIMER_TEST_CHILD_ENV, test)
        .env(
            "REVERIE_SKID_MARGIN_OVERRIDE",
            TIMER_TEST_SKID_MARGIN.to_string(),
        )
        .status()
        .unwrap();
    assert!(
        status.success(),
        "isolated precise-timer test {test} failed: {status}"
    );
    false
}

/// One backend's run in a `timer_restart_parity` attempt.
struct TimerRun {
    stdout: String,
    events: Vec<String>,
    /// Skid overshoots recorded during the run
    /// (`reverie::take_skid_overshoot_count`).
    overshoots: u64,
    /// Restart landings that interrupted a precise timer's single steps,
    /// after which the steps continued.
    step_landings: u64,
    /// SIGTRAP stops resumed with nothing claiming them.
    unclaimed_sigtraps: u64,
}

async fn run_timer_fixture(backend: RestartBackend, mode: &str, plan: RestartPlan) -> TimerRun {
    let _ = reverie::take_skid_overshoot_count();
    let step_landings = reverie_ptrace::testing::liteinst_timer_step_landings_resolved();
    let unclaimed_sigtraps = reverie_ptrace::testing::unclaimed_sigtraps_suppressed();
    let (stdout, events) = run_restart_fixture(backend, mode, plan).await.unwrap();
    TimerRun {
        stdout,
        events,
        overshoots: reverie::take_skid_overshoot_count(),
        step_landings: reverie_ptrace::testing::liteinst_timer_step_landings_resolved()
            - step_landings,
        unclaimed_sigtraps: reverie_ptrace::testing::unclaimed_sigtraps_suppressed()
            - unclaimed_sigtraps,
    }
}

/// Whether `events` differ from `expected` only in the last event, and that
/// event is `timer +N` for an `expected` last event `timer +R` with N > R:
/// the timer fired late, the one divergence a skid overshoot causes.
fn is_late_timer(events: &[String], expected: &[&str]) -> bool {
    let (Some((last, prefix)), Some((expected_last, expected_prefix))) =
        (events.split_last(), expected.split_last())
    else {
        return false;
    };
    let rcbs = |event: &str| {
        event
            .strip_prefix("timer +")
            .and_then(|rcbs| rcbs.parse::<u64>().ok())
    };
    prefix == expected_prefix
        && matches!((rcbs(last), rcbs(expected_last)), (Some(late), Some(requested)) if late > requested)
}

/// Whether skid explains every difference between the two runs' events and
/// `expected`: each run's events equal `expected`, or that same run recorded
/// a skid overshoot and its events differ only in a late last timer event
/// (`is_late_timer`). The caller has already required everything else to
/// match exactly.
fn skid_explains_divergence(ptrace: &TimerRun, hybrid: &TimerRun, expected: &[&str]) -> bool {
    let explained = |run: &TimerRun| {
        run.events == expected || (run.overshoots > 0 && is_late_timer(&run.events, expected))
    };
    explained(ptrace) && explained(hybrid)
}

/// As `restart_parity`, for a plan whose Tool requests a precise timer, run
/// inside `in_timer_test_child`. Requires plain ptrace's output to equal
/// `expected_stdout` and its events to equal `expected`, host-hybrid to
/// match (up to the site counters, with `hooks` hook entries), host-hybrid to
/// continue a timer's single steps after exactly `step_landings` restart
/// landings that interrupted them (plain ptrace none), and neither backend
/// to resume an unclaimed SIGTRAP stop, which is what a single-step trap flag
/// left set in the guest produces.
///
/// A precise timer that the PMU delivers past its programmed target
/// (`reverie::SKID_OVERSHOOT_MARKER`) fires late, so its `timer +N` event
/// exceeds the requested distance. The skid tail is heavy and no fixed
/// margin covers it; reverie's documented policy is that a divergence caused
/// by skid may be retried. An attempt is therefore retried, up to
/// `SKID_ATTEMPTS`, only when `skid_explains_divergence`: the only
/// difference is a late last timer event of a backend whose own run recorded
/// an overshoot. Any other difference fails the attempt at once.
async fn timer_restart_parity(
    mode: &str,
    plan: RestartPlan,
    hooks: u64,
    expected_stdout: &str,
    expected: &[&str],
    step_landings: u64,
) {
    assert!(
        std::env::var_os(TIMER_TEST_CHILD_ENV).is_some(),
        "timer_restart_parity runs only inside in_timer_test_child"
    );
    let expected_hybrid_stdout = expected_stdout.replace(
        &restart_counts(RestartBackend::Ptrace, 1),
        &restart_counts(RestartBackend::HostHybrid, hooks),
    );
    for attempt in 1..=SKID_ATTEMPTS {
        let ptrace = run_timer_fixture(RestartBackend::Ptrace, mode, plan).await;
        let hybrid = run_timer_fixture(RestartBackend::HostHybrid, mode, plan).await;
        let context = format!(
            "{mode}: attempt {attempt}, skid overshoots: plain ptrace {}, host-hybrid {}",
            ptrace.overshoots, hybrid.overshoots
        );
        assert_eq!(
            ptrace.stdout, expected_stdout,
            "{context}: plain ptrace output differs from the expected"
        );
        assert_eq!(
            hybrid.stdout, expected_hybrid_stdout,
            "{context}: host-hybrid output differs from plain ptrace"
        );
        assert_eq!(
            (ptrace.step_landings, hybrid.step_landings),
            (0, step_landings),
            "{context}: restart landings after which a timer's single steps \
             continued (plain ptrace, host-hybrid)"
        );
        assert_eq!(
            (ptrace.unclaimed_sigtraps, hybrid.unclaimed_sigtraps),
            (0, 0),
            "{context}: unclaimed SIGTRAP stops resumed (plain ptrace, host-hybrid); \
             a single-step trap flag was left set"
        );
        if ptrace.events == expected && hybrid.events == expected {
            return;
        }
        if attempt < SKID_ATTEMPTS && skid_explains_divergence(&ptrace, &hybrid, expected) {
            eprintln!(
                "{context}: only a late timer event of a backend that overshot differs \
                 (plain ptrace {:?}, host-hybrid {:?}); retrying",
                ptrace.events, hybrid.events
            );
            continue;
        }
        assert_eq!(
            hybrid.events, ptrace.events,
            "{context}: host-hybrid Tool events differ from plain ptrace"
        );
        assert_eq!(
            ptrace.events, expected,
            "{context}: plain ptrace Tool events differ from the expected"
        );
    }
    unreachable!("the last attempt returns or fails an assertion")
}

fn timer_run(events: &[&str], overshoots: u64) -> TimerRun {
    TimerRun {
        stdout: String::new(),
        events: events.iter().map(|event| event.to_string()).collect(),
        overshoots,
        step_landings: 0,
        unclaimed_sigtraps: 0,
    }
}

/// `timer_restart_parity` retries only a late last timer event of a backend
/// whose own run recorded a skid overshoot.
#[test]
fn skid_explains_only_a_late_timer_of_the_backend_that_overshot() {
    let expected = ["read(warm)", "signal SIGUSR1", "timer +50000"];
    let exact = ["read(warm)", "signal SIGUSR1", "timer +50000"];
    let late = ["read(warm)", "signal SIGUSR1", "timer +50075"];
    let early = ["read(warm)", "signal SIGUSR1", "timer +49990"];
    let extra = ["read(warm)", "signal SIGUSR1", "timer +50000", "bogus"];
    let late_and_extra = ["read(warm)", "signal SIGUSR2", "timer +50075"];
    let missing = ["read(warm)", "signal SIGUSR1"];
    for (ptrace, hybrid, explained, case) in [
        (
            timer_run(&exact, 0),
            timer_run(&late, 1),
            true,
            "host-hybrid late, overshot",
        ),
        (
            timer_run(&late, 1),
            timer_run(&exact, 0),
            true,
            "ptrace late, overshot",
        ),
        (
            timer_run(&late, 1),
            timer_run(&late, 1),
            true,
            "both late, both overshot",
        ),
        (
            timer_run(&late, 1),
            timer_run(&late, 0),
            false,
            "host-hybrid late, only ptrace overshot",
        ),
        (
            timer_run(&exact, 1),
            timer_run(&late, 0),
            false,
            "host-hybrid late, only ptrace overshot",
        ),
        (
            timer_run(&exact, 0),
            timer_run(&late, 0),
            false,
            "late with no overshoot",
        ),
        (
            timer_run(&exact, 0),
            timer_run(&early, 1),
            false,
            "early timer",
        ),
        (
            timer_run(&exact, 0),
            timer_run(&extra, 1),
            false,
            "extra event, host-hybrid overshot",
        ),
        (
            timer_run(&exact, 1),
            timer_run(&extra, 0),
            false,
            "extra event, ptrace overshot",
        ),
        (
            timer_run(&exact, 0),
            timer_run(&missing, 1),
            false,
            "missing timer",
        ),
        (
            timer_run(&exact, 0),
            timer_run(&late_and_extra, 1),
            false,
            "late timer and another difference",
        ),
    ] {
        assert_eq!(
            skid_explains_divergence(&ptrace, &hybrid, &expected),
            explained,
            "{case}"
        );
    }
    let restarted = ["read(warm)", "signal SIGUSR1", "magic read(0x7e57,1)"];
    assert!(
        !skid_explains_divergence(&timer_run(&restarted, 0), &timer_run(&late, 1), &restarted),
        "a timer where none is expected"
    );
}

/// A restart code with a signal whose guest handler lacks `SA_RESTART`
/// follows Linux: `-ERESTARTSYS`, `-ERESTARTNOHAND` and
/// `-ERESTART_RESTARTBLOCK` become `EINTR` after the handler runs, and
/// `-ERESTARTNOINTR` restarts. The kernel makes that decision at delivery;
/// host-hybrid must present it the restartable syscall to decide.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_with_a_guest_handler_follows_linux() {
    for (errno, result) in [
        (reverie::Errno::ERESTARTSYS, -4),
        (reverie::Errno::ERESTARTNOHAND, -4),
        (reverie::Errno::ERESTART_RESTARTBLOCK, -4),
        (reverie::Errno::ERESTARTNOINTR, RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity("handler", plan, 2, &format!("{errno}")).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{errno}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{errno}");
    }
}

/// An `SA_RESTART` handler restarts `-ERESTARTSYS` but not
/// `-ERESTARTNOHAND`, as Linux does.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_with_an_sa_restart_handler_follows_linux() {
    for (errno, result) in [
        (reverie::Errno::ERESTARTSYS, RESTART_RESULT),
        (reverie::Errno::ERESTARTNOHAND, -4),
    ] {
        let plan = RestartPlan {
            errno: errno.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) =
            restart_parity("handler-restart", plan, 2, &format!("{errno}")).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{errno}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{errno}");
    }
}

/// The guest handler of the signal that interrupts a restart makes a syscall
/// that itself restarts, before the kernel's decision for the outer one is
/// reported. Both restarts are pending at once; each must resolve as Linux
/// resolves it: the nested one restarts (no signal), and the outer one
/// follows the handler's `SA_RESTART`.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_nested_inside_the_handler_resolves_both() {
    for (mode, result) in [
        ("handler-nested", -4),
        ("handler-nested-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, 2, mode).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=1 traps=- hooks=-\n"),
            "{mode}"
        );
        let mut expected = vec![
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            "nested read(0x7e59,1)",
            "nested read(0x7e59,1)",
        ];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// The shell pattern (bash reaps children from an `SA_RESTART` SIGCHLD
/// handler): a real child exits, and its SIGCHLD reaches that handler while a
/// Tool-restarted syscall is in progress. The syscall must restart.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_with_an_sa_restart_sigchld_handler_restarts() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        inject: RestartInject::UnblockBuffer,
        ..Default::default()
    };
    let (stdout, events) = restart_parity("sigchld", plan, 1, "sigchld").await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} reaped=1 traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGCHLD",
            "magic read(0x7e57,1)"
        ]
    );
}

/// The signal arrives while the Tool injects a syscall, so the tracer holds
/// it and delivers it on the restart's resume instead of at a fresh signal
/// stop. The Linux rule must apply to that delivery too: a handler without
/// `SA_RESTART` interrupts, an `SA_RESTART` one restarts, and no handler
/// restarts. As under plain ptrace, a signal that interrupts a Tool
/// injection reaches the guest without a Tool signal event, so the handler
/// count is the evidence of delivery.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_with_a_signal_held_across_an_injection_follows_linux() {
    for (mode, signal, result) in [
        ("handler", libc::SIGUSR1, -4),
        ("handler-restart", libc::SIGUSR1, RESTART_RESULT),
        ("read", libc::SIGURG, RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal,
            inject: RestartInject::Getpid,
            ..Default::default()
        };
        let hooks = if mode == "read" { 1 } else { 2 };
        let (stdout, events) = restart_parity(mode, plan, hooks, mode).await;
        let handled = if mode == "read" {
            ""
        } else {
            " handled=1 nested-ok=1"
        };
        assert_eq!(
            stdout,
            format!("read-result={result}{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)"];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A precise timer due within the skid margin makes the timer single-step
/// the guest across the restart's int3 re-trap. That SIGTRAP is the syscall
/// trap, not a completed step: it must reach the run loop, which re-invokes
/// the Tool, rather than being consumed by the timer. As under plain ptrace,
/// the re-invoked syscall is the next event, so the timer is cancelled and
/// never fires.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restart_survives_an_imminent_precise_timer() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        timer: true,
        ..Default::default()
    };
    let (stdout, events) = restart_parity("read", plan, 1, "timer").await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "magic read(0x7e57,1)"]
    );
}

/// A real kernel interruption of an unsubscribed syscall: the timer's SIGURG
/// interrupts a 400 ms nanosleep, which returns `-ERESTART_RESTARTBLOCK`
/// inside the private-page step. The guest must still see 0 after the full
/// sleep, and the Tool must see the signal as under plain ptrace.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_interrupted_unsubscribed_sleep_restarts() {
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "sleep", RestartPlan::default())
            .await
            .unwrap();
        assert_eq!(
            stdout,
            format!(
                "sleep-result=0 slept-enough=1 {}\n",
                restart_counts(backend, 1)
            ),
            "{backend:?}"
        );
        assert_eq!(events, ["read(warm)", "signal SIGURG"], "{backend:?}");
    }
}

/// A blocking pipe readv the Tool does not subscribe, interrupted by a real
/// signal: the kernel's ERESTARTSYS restarts the readv, which returns the byte
/// written later, never -512 or EINTR.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_interrupted_unsubscribed_readv_restarts() {
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "readv", RestartPlan::default())
            .await
            .unwrap();
        assert_eq!(
            stdout,
            format!("readv-result=1 byte=x {}\n", restart_counts(backend, 1)),
            "{backend:?}"
        );
        assert_eq!(events, ["read(warm)", "signal SIGURG"], "{backend:?}");
    }
}

/// The interrupted nanosleep continues through `restart_syscall`, which a
/// subscribing Tool sees after the signal, exactly as under plain ptrace.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_interrupted_sleep_continues_through_restart_syscall() {
    let plan = RestartPlan {
        subscribe_restart_syscall: true,
        ..Default::default()
    };
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "sleep", plan).await.unwrap();
        assert_eq!(
            stdout,
            format!(
                "sleep-result=0 slept-enough=1 {}\n",
                restart_counts(backend, 1)
            ),
            "{backend:?}"
        );
        assert_eq!(
            events,
            ["read(warm)", "signal SIGURG", "restart_syscall"],
            "{backend:?}"
        );
    }
}

/// A syscall that completes with a signal pending is not re-executed: the
/// thread's self-sent SIGURG reaches the Tool exactly once.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_completed_syscall_with_pending_signal_runs_once() {
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "tgkill", RestartPlan::default())
            .await
            .unwrap();
        assert_eq!(
            stdout,
            format!("tgkill-result=0 {}\n", restart_counts(backend, 1)),
            "{backend:?}"
        );
        assert_eq!(events, ["read(warm)", "signal SIGURG"], "{backend:?}");
    }
}

/// Signals race the site's unsubscribed getppid and nanosleep calls, landing
/// before the private-page step, during a sleep, or at completion. A second
/// thread sends each SIGURG only after the Tool saw the previous one, so
/// every result must be correct and the Tool must see all 300 exactly once.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_signals_racing_unsubscribed_syscalls_are_seen_once() {
    for backend in RESTART_BACKENDS {
        let (stdout, events) = run_restart_fixture(backend, "stress", RestartPlan::default())
            .await
            .unwrap();
        let prefix = "stress-bad=0 ran=1 tool-signals=300 ";
        let counts = stdout
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("{backend:?}: {stdout}"));
        match backend {
            RestartBackend::Ptrace => assert_eq!(counts, "traps=- hooks=-\n"),
            // How many rounds the guest runs before the last signal depends
            // on host scheduling, so the hook entries are bounded below only:
            // each round makes a getppid and a nanosleep through the site,
            // which the warm read's trap patched, and `ran=1` shows a round.
            RestartBackend::HostHybrid => {
                let hooks: u64 = counts
                    .strip_prefix("traps=1 hooks=")
                    .and_then(|hooks| hooks.strip_suffix('\n')?.parse().ok())
                    .unwrap_or_else(|| panic!("{backend:?}: {stdout}"));
                assert!(
                    hooks >= 2,
                    "{backend:?}: the site's hook must run the calls: {stdout}"
                );
            }
        }
        assert_eq!(events[0], "read(warm)", "{backend:?}");
        assert_eq!(events.len(), 301, "{backend:?}: {events:?}");
        assert!(
            events[1..].iter().all(|event| event == "signal SIGURG"),
            "{backend:?}: {events:?}"
        );
    }
}

/// A kernel-generated synchronous signal during the private-page step (here
/// the guest's own `SECCOMP_RET_TRAP` SIGSYS) is dequeued ahead of the
/// step's single-step report. The syscall did not run; the SIGSYS is returned
/// to the kernel's queue behind the report and delivered when the guest
/// resumes, as plain ptrace delivers it, and kills this handler-less guest on
/// both backends after the Tool saw it once. The guest dies before it prints
/// the site's counts, so this test does not show that the step ran
/// (https://github.com/rrnewton/reverie/issues/837).
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_guest_seccomp_trap_in_private_step_follows_ptrace() {
    for backend in RESTART_BACKENDS {
        let (output, events) =
            run_restart_fixture_output(backend, "seccomp", RestartPlan::default())
                .await
                .unwrap();
        // Whether a core is dumped is host policy; only the signal is asserted.
        assert!(
            matches!(
                output.status,
                ExitStatus::Signaled(reverie::Signal::SIGSYS, _)
            ),
            "{backend:?}: {output:?}"
        );
        assert_eq!(events, ["read(warm)", "signal SIGSYS"], "{backend:?}");
    }
}

/// A synchronous-class signal that becomes deliverable only under the
/// temporary mask of an unsubscribed `rt_sigsuspend` stops the private-page
/// step after the syscall returned, ahead of the single-step report. The
/// signal cannot be returned to the queue without discarding the saved mask,
/// so it is held for delivery at the guest's syscall site. The guest must see
/// what plain ptrace gives it: the handler runs once, the sleep fails with
/// `EINTR`, the saved mask that blocks the signal is restored, and the Tool
/// sees the signal once.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_signal_held_after_a_mask_swapping_syscall_follows_ptrace() {
    let (stdout, events) = restart_parity(
        "sigsuspend-held",
        RestartPlan::default(),
        1,
        "sigsuspend-held",
    )
    .await;
    assert_eq!(
        stdout,
        "sigsuspend-result=-4 handled=1 blocked=1 traps=- hooks=-\n"
    );
    assert_eq!(events, ["read(warm)", "signal SIGSYS"]);
}

/// A handler that decides the magic read's restart leaves a nested
/// unsubscribed nanosleep by `siglongjmp` from a SIGALRM handler, abandoning
/// that sleep's own armed restart, and then returns. The landing it reaches
/// belongs to the magic read, whose stack pointer it carries, not to the
/// newer abandoned restart; plain ptrace interrupts or restarts the read and
/// never resumes the sleep.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_landing_after_a_siglongjmp_resolves_the_restart_it_returns_to() {
    for (mode, result) in [
        ("handler-longjmp", -4),
        ("handler-longjmp-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, 2, mode).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\nafter-sleep=0\n"),
            "{mode}"
        );
        let mut expected = vec![
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            "signal SIGALRM",
        ];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A handler that abandons more restarts than
/// `LITEINST_PENDING_RESTART_LIMIT`, each by `siglongjmp` out of a nested
/// handler from the same frame, still returns to the landing of the restart
/// it interrupted. Each abandoned restart shares the next one's controller
/// stack pointer, so it is replaced rather than piling up and evicting the
/// live restart below them.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_restarts_abandoned_at_one_depth_keep_the_live_restart() {
    const ABANDONED: usize = 70;
    for (mode, result) in [
        ("handler-abandon", -4),
        ("handler-abandon-restart", RESTART_RESULT),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, 1 + ABANDONED as u64, mode).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\nafter-sleep=0\n"),
            "{mode}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        expected.extend(std::iter::repeat_n("signal SIGALRM", ABANDONED));
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A handler that edits the saved `rax` of the syscall it interrupted changes
/// the result of an interrupted syscall, and the syscall number of a
/// restarted one, as under plain ptrace.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_handler_edit_of_rax_follows_linux() {
    for (mode, result) in [
        ("handler-edit-rax", 777),
        ("handler-edit-rax-restart", -libc::EBADF as i64),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, 1, mode).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n"),
            "{mode}"
        );
        assert_eq!(
            events,
            ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"],
            "{mode}"
        );
    }
}

/// Under host-hybrid, a handler deciding a restart sees the runtime's trap
/// context, not the guest's syscall registers, so an edit of any register but
/// `rax` has no plain-ptrace meaning to apply and fails closed. Plain ptrace
/// lets the guest's handler edit r11, which the syscall clobbers anyway.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_handler_edit_of_another_register_fails_closed() {
    let plan = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGUSR1,
        ..Default::default()
    };
    let (stdout, events) = run_restart_fixture(RestartBackend::Ptrace, "handler-edit-r11", plan)
        .await
        .unwrap();
    assert_eq!(
        stdout,
        "read-result=-4 handled=1 nested-ok=0 traps=- hooks=-\n"
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"]
    );
    let error = run_restart_fixture(RestartBackend::HostHybrid, "handler-edit-r11", plan)
        .await
        .expect_err("a handler edit of r11 across the landing must fail closed");
    let error = error.to_string();
    assert!(
        error.contains("restart LiteInst host-hybrid syscall")
            && error.contains("changed controller register r11"),
        "landing did not fail closed: {error}"
    );
}

/// The handler deciding a restart forks. The child returns from its copy of
/// the handler to its copy of the interrupted read, which must resolve by the
/// same rule as the parent's (its exit code encodes the result: 4 for EINTR,
/// 43 for the restarted read's result).
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_fork_inside_the_deciding_handler_resolves_the_child_restart() {
    for (mode, result, child_exit) in [
        ("handler-fork", -4, 4),
        ("handler-fork-restart", RESTART_RESULT, 43),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, 1, mode).await;
        assert_eq!(
            stdout,
            format!("read-result={result} handled=1 child-exit={child_exit} traps=- hooks=-\n"),
            "{mode}"
        );
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"];
        if result == RESTART_RESULT {
            // The child's restarted read, then the parent's.
            expected.push("magic read(0x7e57,1)");
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(events, expected, "{mode}");
    }
}

/// A precise timer the Tool requests at the signal that decides a restart is
/// due after the quiet handler returns. Plain ptrace has no stop between the
/// delivery and the timer when the read is interrupted, so the timer fires;
/// the host-hybrid landing stop in between must not cancel or re-arm it, so
/// it fires exactly `SIGNAL_TIMER_RCBS` after the request. A restarted read's
/// re-entry is a stop on both backends, so the timer is cancelled. The
/// landing comes long before the timer's single steps, so it interrupts no
/// steps, and none continue after it.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_landing_stop_does_not_cancel_a_timer() {
    if !in_timer_test_child("host_hybrid_landing_stop_does_not_cancel_a_timer") {
        return;
    }
    for (mode, restarted) in [
        ("handler-quiet-spin", false),
        ("handler-quiet-spin-restart", true),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            signal_timer: true,
            ..Default::default()
        };
        let last = if restarted {
            "magic read(0x7e57,1)".to_owned()
        } else {
            format!("timer +{SIGNAL_TIMER_RCBS}")
        };
        let expected = [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            last.as_str(),
        ];
        let result = if restarted { RESTART_RESULT } else { -4 };
        let stdout = format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n");
        timer_restart_parity(mode, plan, 1, &stdout, &expected, 0).await;
    }
}

/// As `host_hybrid_landing_stop_does_not_cancel_a_timer`, with the timer due
/// `SIGNAL_TIMER_NEAR_RCBS` after the deciding signal. With the skid margin
/// pinned to `TIMER_TEST_SKID_MARGIN`, the timer's single-step window starts
/// at the request and covers the handler's return, so the restart landing
/// interrupts the timer's single steps. The run loop resolves the landing and
/// the steps then continue; the test requires exactly one landing after which
/// they did. They must continue: an interrupted read continues and the timer
/// fires in the spin loop exactly `SIGNAL_TIMER_NEAR_RCBS` after the request,
/// as under plain ptrace; a restarted read stops at its re-entry on both
/// backends. Continuing needs overflow records: without them the landing
/// cancels the event (reverie-liteinst/tests/hybrid_without_records.rs).
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_landing_inside_a_timer_step_window_keeps_the_timer() {
    if !in_timer_test_child("host_hybrid_landing_inside_a_timer_step_window_keeps_the_timer") {
        return;
    }
    for (mode, restarted) in [
        ("handler-quiet-spin", false),
        ("handler-quiet-spin-restart", true),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal: libc::SIGUSR1,
            signal_timer: true,
            signal_timer_near: true,
            ..Default::default()
        };
        let last = if restarted {
            "magic read(0x7e57,1)".to_owned()
        } else {
            format!("timer +{SIGNAL_TIMER_NEAR_RCBS}")
        };
        let expected = [
            "read(warm)",
            "magic read(0x7e57,1)",
            "signal SIGUSR1",
            last.as_str(),
        ];
        let result = if restarted { RESTART_RESULT } else { -4 };
        let stdout = format!("read-result={result} handled=1 nested-ok=0 traps=- hooks=-\n");
        timer_restart_parity(mode, plan, 1, &stdout, &expected, 1).await;
    }
}

/// The Tool sends a signal and then passes the original magic read through
/// (`Guest::inject`) while the signal is still pending. Plain ptrace runs the
/// read from its seccomp stop with the signal pending: the read of the
/// unopened descriptor fails with `EBADF` at once, and the signal is
/// delivered on the way back to the guest, as a signal event the Tool sees.
/// Host-hybrid's private step stops at the signal before the syscall
/// instruction; it must still run the syscall once with the signal pending,
/// not return a restart code that re-invokes the Tool, and must leave the
/// signal for a Tool-visible delivery. Covered with a handler without and
/// with `SA_RESTART` (whose `getppid` through the site is the second hook
/// entry), and with a signal that has no handler.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_original_injection_with_a_pending_signal_follows_ptrace() {
    for (mode, signal, handled, hooks) in [
        ("handler", libc::SIGUSR1, " handled=1 nested-ok=1", 2),
        (
            "handler-restart",
            libc::SIGUSR1,
            " handled=1 nested-ok=1",
            2,
        ),
        ("read", libc::SIGURG, "", 1),
    ] {
        let plan = RestartPlan {
            signal,
            inject_original: true,
            ..Default::default()
        };
        let (stdout, events) = restart_parity(mode, plan, hooks, mode).await;
        assert_eq!(
            stdout,
            format!("read-result=-9{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        let signal_event = format!(
            "signal {}",
            reverie::Signal::try_from(signal).unwrap().as_str()
        );
        assert_eq!(
            events,
            ["read(warm)", "magic read(0x7e57,1)", signal_event.as_str()],
            "{mode}"
        );
    }
}

/// The Tool injects a syscall from the signal event that decides a restart.
/// Under host-hybrid that stop is at the rewound runtime `int3`, whose `rax`
/// must still hold the syscall marker when the controller re-executes it.
///
/// An injection the guest cannot observe must leave the outcome of the run
/// without it, so the reference is plain ptrace with no injection. Plain
/// ptrace with the injection is not a reference: its signal-stop injection
/// does not restore `rax`, which holds the pending `-ERESTARTSYS`, so the
/// kernel returns the injected `getpid` result from the read instead of
/// deciding the restart.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_tool_injection_at_the_deciding_signal_keeps_the_restart() {
    for (mode, signal, result, hooks) in [
        ("handler", libc::SIGUSR1, -4, 2),
        ("handler-restart", libc::SIGUSR1, RESTART_RESULT, 2),
        ("read", libc::SIGURG, RESTART_RESULT, 1),
    ] {
        let plan = RestartPlan {
            errno: reverie::Errno::ERESTARTSYS.into_raw(),
            restarts: 1,
            signal,
            ..Default::default()
        };
        let injected = RestartPlan {
            inject_in_signal: true,
            ..plan
        };
        let (reference_stdout, reference_events) =
            run_restart_fixture(RestartBackend::Ptrace, mode, plan)
                .await
                .unwrap();
        let (hybrid_stdout, hybrid_events) =
            run_restart_fixture(RestartBackend::HostHybrid, mode, injected)
                .await
                .unwrap();
        let handled = if mode == "read" {
            ""
        } else {
            " handled=1 nested-ok=1"
        };
        assert_eq!(
            reference_stdout,
            format!("read-result={result}{handled} traps=- hooks=-\n"),
            "{mode}"
        );
        assert_eq!(
            hybrid_stdout,
            reference_stdout.replace(
                &restart_counts(RestartBackend::Ptrace, 1),
                &restart_counts(RestartBackend::HostHybrid, hooks)
            ),
            "{mode}: host-hybrid output with the injection differs from plain ptrace without it"
        );
        let signal = if mode == "read" {
            "signal SIGURG"
        } else {
            "signal SIGUSR1"
        };
        let mut expected = vec!["read(warm)", "magic read(0x7e57,1)", signal];
        if result == RESTART_RESULT {
            expected.push("magic read(0x7e57,1)");
        }
        assert_eq!(reference_events, expected, "{mode}");
        assert_eq!(hybrid_events, expected, "{mode}");
    }
}

/// The guest replaces the runtime's SIGTRAP router with a handler without
/// `SA_RESTART` while a `-ERESTARTSYS` restart is pending.
///
/// A SIGTRAP the guest sends itself never reaches the guest on either
/// backend: the tracer suppresses a SIGTRAP it did not cause, so the read
/// restarts with no Tool signal event. When the Tool instead delivers SIGTRAP
/// from the deciding signal event, plain ptrace runs the guest handler and
/// interrupts the read. Host-hybrid cannot tell that handler from the
/// router, whose `SA_RESTART` would restart the read, so it fails closed.
#[tokio::test(flavor = "current_thread")]
async fn host_hybrid_sigtrap_deciding_a_restart_fails_closed() {
    let sent = RestartPlan {
        errno: reverie::Errno::ERESTARTSYS.into_raw(),
        restarts: 1,
        signal: libc::SIGTRAP,
        ..Default::default()
    };
    let (stdout, events) = restart_parity("handler-sigtrap", sent, 1, "guest-sent SIGTRAP").await;
    assert_eq!(
        stdout,
        format!("read-result={RESTART_RESULT} handled=0 traps=- hooks=-\n")
    );
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "magic read(0x7e57,1)"]
    );

    let delivered = RestartPlan {
        signal: libc::SIGUSR1,
        deliver_sigtrap: true,
        ..sent
    };
    let (stdout, events) =
        run_restart_fixture(RestartBackend::Ptrace, "handler-sigtrap", delivered)
            .await
            .unwrap();
    assert_eq!(stdout, "read-result=-4 handled=1 traps=- hooks=-\n");
    assert_eq!(
        events,
        ["read(warm)", "magic read(0x7e57,1)", "signal SIGUSR1"]
    );
    let error = run_restart_fixture(RestartBackend::HostHybrid, "handler-sigtrap", delivered)
        .await
        .expect_err("a SIGTRAP deciding a restart must fail closed");
    let error = error.to_string();
    assert!(
        error.contains("restart LiteInst host-hybrid syscall")
            && error.contains(
                "SIGTRAP delivered while a -512 ERESTARTSYS (Restart syscall) restart is pending"
            ),
        "SIGTRAP delivery did not fail closed: {error}"
    );
}
