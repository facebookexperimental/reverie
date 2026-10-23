/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Guest;
use reverie::TimerSchedule;
use reverie::syscalls::Exit;
use reverie::syscalls::Getpid;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use serde::Deserialize;
use serde::Serialize;

use super::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Config {
    injected_exec: bool,
    startup_request: u8,
    post_exec_request: bool,
    initial_failure: bool,
}

#[derive(Debug, Deserialize, Serialize)]
enum Observation {
    Start(u64),
    ExecCall(u64),
    PostExec(u64),
    Timer(u64),
    Boundary(u64),
    FailedExec(u64),
}

#[derive(Default)]
struct ClockLog(Mutex<Vec<Observation>>);

#[reverie::global_tool]
impl GlobalTool for ClockLog {
    type Config = Config;
    type Request = Observation;
    type Response = ();

    async fn receive_rpc(&self, _from: Pid, observation: Observation) {
        self.0.lock().unwrap().push(observation);
    }
}

#[derive(Default)]
struct ClockTool;

fn request_startup_timer<G: Guest<ClockTool>>(guest: &mut G, kind: u8) {
    match kind {
        0 => {}
        1 => guest.set_timer_precise(TimerSchedule::Rcbs(1)).unwrap(),
        2 => guest.set_timer(TimerSchedule::Rcbs(1)).unwrap(),
        3 => guest
            .set_timer_precise(TimerSchedule::RcbsAndInstructions(1, 2))
            .unwrap(),
        _ => panic!("unknown control timer kind"),
    }
}

#[reverie::tool]
impl Tool for ClockTool {
    type GlobalState = ClockLog;
    type ThreadState = bool;

    fn subscriptions(config: &Config) -> Subscription {
        let mut events = Subscription::none();
        events.syscalls([Sysno::getpid]);
        if config.injected_exec {
            events.syscalls([Sysno::execve]);
        }
        events
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        assert!(guest.is_command_bootstrap());
        let clock = guest.read_clock()?;
        eprintln!("CLOCK_ORIGIN_TEST start={clock}");
        assert_eq!(clock, 0);
        guest.send_rpc(Observation::Start(clock)).await;
        let kind = guest.config().startup_request;
        request_startup_timer(guest, kind);
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        if call.number() == Sysno::execve {
            assert!(guest.is_command_bootstrap());
            let clock = guest.read_clock()?;
            eprintln!("CLOCK_ORIGIN_TEST intercepted_exec={clock}");
            assert_eq!(clock, 0, "the command launcher is outside guest accounting");
            guest.send_rpc(Observation::ExecCall(clock)).await;
            // This request is newer than handle_thread_start and exercises
            // the injected route's missing ordinary observe_event call.
            let kind = guest.config().startup_request;
            request_startup_timer(guest, kind);
            if guest.config().initial_failure {
                assert_eq!(guest.inject(call).await, Err(Errno::ENOENT));
                assert!(guest.is_command_bootstrap());
                assert!(!*guest.thread_state());
                let clock = guest.read_clock()?;
                eprintln!("CLOCK_ORIGIN_TEST failed_exec={clock}");
                assert_eq!(clock, 0, "failed initial exec did not activate the clock");
                guest.send_rpc(Observation::FailedExec(clock)).await;
                guest.tail_inject(Exit::default().with_status(27)).await
            }
            guest.tail_inject(call).await
        } else {
            assert_eq!(call.number(), Sysno::getpid);
            assert!(*guest.thread_state());
            let clock = guest.read_clock()?;
            eprintln!("CLOCK_ORIGIN_TEST boundary={clock}");
            guest.send_rpc(Observation::Boundary(clock)).await;
            Ok(guest.inject(call).await?)
        }
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        assert!(!guest.is_command_bootstrap());
        assert!(!*guest.thread_state());
        *guest.thread_state_mut() = true;
        let clock = guest
            .read_clock()
            .expect("post-exec clock must be available");
        eprintln!("CLOCK_ORIGIN_TEST post_exec={clock}");
        assert_eq!(
            clock, 0,
            "post-exec setup must not execute and rewind the entry branch"
        );
        assert_eq!(guest.regs().await.rip, 0x401000);
        guest.send_rpc(Observation::PostExec(clock)).await;
        // The real Tool callback is live immediately. A returned injected
        // syscall is not an initial command and does not reopen the hold.
        assert!(guest.inject(Getpid::default()).await? > 0);
        assert_eq!(guest.regs().await.rip, 0x401000);
        assert_eq!(
            guest.read_clock().expect("clock after post-exec injection"),
            0,
            "injection must not retire guest work"
        );
        if guest.config().post_exec_request {
            guest
                .set_timer_precise(TimerSchedule::Rcbs(1))
                .expect("new ordinary post-exec timer");
        }
        Ok(())
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        assert!(
            *guest.thread_state(),
            "a timer fired in the excluded launcher interval"
        );
        assert!(
            guest.config().post_exec_request,
            "a retired initial request fired later"
        );
        let clock = guest.read_clock().unwrap();
        eprintln!("CLOCK_ORIGIN_TEST timer={clock}");
        guest.send_rpc(Observation::Timer(clock)).await;
    }
}

struct Fixture(std::path::PathBuf);

impl Fixture {
    fn new(pre_boundary_loop: bool, initial_failure: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-clock-origin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // The first instruction is itself a conditional branch. Both outcomes
        // reach the next instruction; its incoming condition does not matter.
        let mut code = vec![0x75, 0x00]; // jne +0
        fn loop64(code: &mut Vec<u8>) {
            code.extend_from_slice(&[0xb9, 64, 0, 0, 0, 0xff, 0xc9, 0x75, 0xfc]);
        }
        fn getpid(code: &mut Vec<u8>) {
            code.extend_from_slice(&[0xb8, 39, 0, 0, 0, 0x0f, 0x05]);
        }
        if pre_boundary_loop {
            loop64(&mut code);
        }
        getpid(&mut code);
        loop64(&mut code);
        getpid(&mut code);
        code.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
        let size = 0x1000 + code.len();
        let mut elf = vec![0u8; size];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[88..96].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&(size as u64).to_le_bytes());
        elf[104..112].copy_from_slice(&(size as u64).to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        if initial_failure {
            use std::os::unix::ffi::OsStrExt;
            let missing_loader = path.with_extension("uncreated-interpreter");
            assert!(!missing_loader.exists());
            let mut interpreter = missing_loader.as_os_str().as_bytes().to_vec();
            interpreter.push(0);
            assert!(0x200 + interpreter.len() < 0x1000);
            elf[56..58].copy_from_slice(&2u16.to_le_bytes());
            elf[120..124].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
            elf[124..128].copy_from_slice(&4u32.to_le_bytes());
            elf[128..136].copy_from_slice(&0x200u64.to_le_bytes());
            elf[152..160].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            elf[160..168].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            elf[168..176].copy_from_slice(&1u64.to_le_bytes());
            elf[0x200..0x200 + interpreter.len()].copy_from_slice(&interpreter);
        }
        elf[0x1000..].copy_from_slice(&code);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, &elf).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        drop(file);
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).unwrap();
    }
}

async fn run(config: Config, launcher_branches: u64) {
    let fixture = Fixture::new(config.post_exec_request, config.initial_failure);
    let mut builder =
        TracerBuilder::<ClockTool>::new(Command::new(&fixture.0)).config(config.clone());
    builder.clock_test_launcher_branches = launcher_branches;
    let tracer = builder.spawn().await.unwrap();
    let (status, log) = tokio::time::timeout(Duration::from_secs(5), tracer.wait())
        .await
        .expect("initial-command control hung")
        .unwrap();
    assert_eq!(
        status,
        ExitStatus::Exited(if config.initial_failure { 27 } else { 0 })
    );
    let observations = log.0.into_inner().unwrap();
    let mut start = Vec::new();
    let mut exec = Vec::new();
    let mut post = Vec::new();
    let mut timer = Vec::new();
    let mut boundary = Vec::new();
    let mut failed_exec = Vec::new();
    for observation in observations {
        match observation {
            Observation::Start(c) => start.push(c),
            Observation::ExecCall(c) => exec.push(c),
            Observation::PostExec(c) => post.push(c),
            Observation::Timer(c) => timer.push(c),
            Observation::Boundary(c) => boundary.push(c),
            Observation::FailedExec(c) => failed_exec.push(c),
        }
    }
    assert_eq!(start, vec![0]);
    assert_eq!(
        exec,
        if config.injected_exec {
            vec![0]
        } else {
            vec![]
        }
    );
    if config.initial_failure {
        assert_eq!(failed_exec, vec![0]);
        assert_eq!(post, Vec::<u64>::new());
        assert_eq!(timer, Vec::<u64>::new());
        assert_eq!(boundary, Vec::<u64>::new());
        return;
    }
    assert_eq!(failed_exec, Vec::<u64>::new());
    assert_eq!(post, vec![0]);
    assert_eq!(
        timer,
        if config.post_exec_request {
            // Rcbs(1) from post-exec zero targets the first real guest branch.
            vec![1]
        } else {
            vec![]
        }
    );
    assert_eq!(
        boundary,
        if config.post_exec_request {
            vec![65, 129]
        } else {
            vec![1, 65]
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn initial_command_clock_counts_first_branch_and_guest_loop() {
    for injected_exec in [false, true] {
        run(
            Config {
                injected_exec,
                ..Config::default()
            },
            0,
        )
        .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn initial_exec_retires_thread_start_and_intercepted_exec_timers() {
    for injected_exec in [false, true] {
        for startup_request in [1, 2, 3] {
            run(
                Config {
                    injected_exec,
                    startup_request,
                    ..Config::default()
                },
                0,
            )
            .await;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn initial_post_exec_injection_and_new_timer_remain_live() {
    for injected_exec in [false, true] {
        run(
            Config {
                injected_exec,
                startup_request: 1,
                post_exec_request: true,
                ..Config::default()
            },
            0,
        )
        .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn initial_command_clock_excludes_added_post_stop_launcher_branches() {
    for injected_exec in [false, true] {
        run(
            Config {
                injected_exec,
                ..Config::default()
            },
            257,
        )
        .await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_initial_exec_keeps_clock_and_notifications_inactive() {
    run(
        Config {
            injected_exec: true,
            startup_request: 1,
            initial_failure: true,
            ..Config::default()
        },
        257,
    )
    .await;
}
