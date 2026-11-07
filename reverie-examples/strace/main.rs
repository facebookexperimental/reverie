/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// TODO-HUMAN-REVIEW(PR-139): Review module visibility for the shared LiteInst host.
pub(crate) mod config;
pub(crate) mod filter;
pub(crate) mod global_state;
pub(crate) mod tool;

#[path = "../backend.rs"]
mod backend;

use clap::Parser;
// TODO-HUMAN-REVIEW(PR-139): Review type visibility for the shared LiteInst host.
pub(crate) use config::Config;
pub(crate) use filter::Filter;
use reverie_util::CommonToolArguments;
pub(crate) use tool::Strace;

/// A tool to trace system calls.
#[derive(Parser, Debug)]
struct Opts {
    // TODO-HUMAN-REVIEW(PR-151): Review strace runner selection.
    /// The Reverie backend to run the program on (`--runner` is accepted).
    #[clap(long, value_enum, default_value = "ptrace", alias = "runner")]
    backend: backend::BackendKind,

    /// The example preload the in-guest backends host the tool in; by
    /// default `libreverie_examples.so` beside this binary.
    #[clap(long)]
    preload: Option<std::path::PathBuf>,

    /// Verified caller artifact manifest for DBT. Defaults to
    /// reverie-dbt-callers/strace/manifest.json beside this binary.
    #[clap(long, env = "REVERIE_DBT_CALLER_ARTIFACT")]
    dbt_artifact: Option<std::path::PathBuf>,

    #[clap(flatten)]
    common: CommonToolArguments,

    /// The set of syscalls to trace. By default, all syscalls are traced. If
    /// this is used, then only the specified syscalls are traced. By limiting
    /// the set of traced syscalls, we can reduce the overhead of the tracer.
    #[clap(long)]
    trace: Vec<Filter>,
}

fn main() -> anyhow::Result<()> {
    run_main(Opts::parse())
}

fn run_main(args: Opts) -> anyhow::Result<()> {
    let caller = if args.backend == backend::BackendKind::Dbt {
        let path = match &args.dbt_artifact {
            Some(path) => path.clone(),
            None => std::env::current_exe()?
                .parent()
                .ok_or_else(|| anyhow::anyhow!("strace executable has no profile directory"))?
                .join("reverie-dbt-callers/strace/manifest.json"),
        };
        Some(reverie_dbt::CallerArtifact::load(&path).map_err(|error| {
            anyhow::anyhow!("cannot load DBT caller artifact {}: {error}; run reverie-dbt/scripts/build-client.sh --caller-manifest reverie-examples/strace-dbt-runtime/Cargo.toml --profile <this binary's Cargo profile>", path.display())
        })?)
    } else {
        None
    };
    let config = Config {
        filters: args.trace,
    };
    let log_guard = args.common.init_tracing();
    let run = backend::run_blocking_with_caller::<Strace>(
        args.backend,
        &args.common,
        config,
        "strace",
        args.preload.clone(),
        caller,
    )?;
    let (status, _) = (run.status, run.global_state);
    drop(log_guard); // Flush logs before exiting.
    status.raise_or_exit()
}

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "../kvm_test_support.rs"]
mod kvm_test_support;

#[cfg(all(test, target_arch = "x86_64"))]
mod kvm_tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use reverie::syscalls::Sysno;
    use tokio::sync::Mutex;

    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::const_new(());

    #[tokio::test]
    async fn exact_strace_tool_forwards_kvm_guest_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_syscall(
            "exact_strace_tool_forwards_kvm_guest_syscall",
            Sysno::getpid,
        ) else {
            return;
        };
        let _guard = TEST_LOCK.lock().await;
        tool::take_handled_syscalls();
        let calls = Arc::new(AtomicUsize::new(0));
        let executor_calls = calls.clone();
        let config = Config {
            filters: vec![Filter {
                inverse: false,
                syscalls: vec![Sysno::getpid],
            }],
        };

        backend
            .run_with_tool::<Strace, _>(
                config,
                move |_request: &reverie_kvm::SyscallRequest,
                      _memory: &reverie_kvm::GuestMemory| {
                    executor_calls.fetch_add(1, Ordering::SeqCst);
                    1234
                },
            )
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(tool::take_handled_syscalls(), 1);
    }

    #[tokio::test]
    async fn exact_strace_tool_runs_static_kvm_syscall() {
        let Some(mut backend) = kvm_test_support::backend_with_static_syscall(
            "exact_strace_tool_runs_static_kvm_syscall",
        ) else {
            return;
        };
        let _guard = TEST_LOCK.lock().await;
        tool::take_handled_syscalls();
        let config = Config {
            filters: vec![Filter {
                inverse: false,
                syscalls: vec![Sysno::getpid],
            }],
        };

        let (_, exit_code, stdout, stderr) = backend
            .run_static_elf_with_tool::<Strace>(config, true)
            .await
            .unwrap();

        assert_eq!(exit_code, 0);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        assert_eq!(tool::take_handled_syscalls(), 1);
    }
}

#[cfg(test)]
mod typed_configuration_tests {
    use std::cell::Cell;
    use std::io::Read;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::time::Instant;

    use reverie::GlobalRPC;
    use reverie::GlobalTool;
    use reverie::Guest;
    use reverie::InjectionPurpose;
    use reverie::Pid;
    use reverie::Tool;
    use reverie::ToolConfiguration;
    use reverie::syscalls::Displayable;
    use reverie::syscalls::Syscall;
    use reverie::syscalls::SyscallArgs;
    use reverie::syscalls::Sysno;
    use reverie_dbt::DbtGuest;
    use reverie_dbt::DbtSyscallOutcome;
    use reverie_dbt::read_tool_configuration;
    use reverie_dbt::run_tool_syscall_with_guest;
    use reverie_rpc_transport::codec::encode;

    use super::*;

    struct Endpoint<'a> {
        configuration: &'a ToolConfiguration<Strace>,
        expected: Mutex<Option<global_state::OutputEvent>>,
        events: Mutex<Vec<global_state::OutputEvent>>,
    }
    #[reverie::tool]
    impl GlobalRPC<global_state::GlobalState> for Endpoint<'_> {
        async fn send_rpc(&self, event: global_state::OutputEvent) -> Result<(), String> {
            assert_eq!(
                Some(&event),
                self.expected.lock().unwrap().as_ref(),
                "only the exact post-construction write diagnostic is expected"
            );
            self.events.lock().unwrap().push(event.clone());
            global_state::GlobalState
                .receive_rpc(Pid::from_raw(unsafe { libc::getpid() }), event)
                .await
        }
        fn config(&self) -> &Config {
            self.configuration.config()
        }
    }

    unsafe extern "C" fn invoke(
        context: usize,
        number: i64,
        args: *const u64,
        purpose: u32,
    ) -> i64 {
        let calls = unsafe { &*(context as *const Cell<usize>) };
        assert_eq!(number, libc::SYS_write);
        assert_eq!(purpose, InjectionPurpose::Application as u32);
        let args = unsafe { &*args.cast::<[u64; 6]>() };
        assert_eq!((args[0], args[2]), (1, 6));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(args[1] as *const u8, 6) },
            b"hello\n"
        );
        calls.set(calls.get() + 1);
        assert_eq!(calls.get(), 1, "duplicate returning injection");
        unsafe { libc::syscall(number, args[0], args[1], args[2]) }
    }
    unsafe extern "C" fn read_regs(_: usize, _: *mut libc::user_regs_struct) -> i32 {
        panic!("write handler does not read registers")
    }
    unsafe extern "C" fn write_regs(_: usize, _: *const libc::user_regs_struct) -> i32 {
        panic!("write handler does not replace registers")
    }

    #[test]
    fn retained_configuration_drives_the_real_strace_write_handler() {
        const CHILD: &str = "REVERIE_STRACE_CONFIGURATION_CHILD";
        // This file is also included by the examples library. Preserve the
        // actual libtest identity in either compilation, not a guessed prefix.
        let test = concat!(
            module_path!(),
            "::retained_configuration_drives_the_real_strace_write_handler"
        )
        .split_once("::")
        .unwrap()
        .1;
        if std::env::var_os(CHILD).is_none() {
            // Keep libtest's own output separate from the application's exact
            // stdout bytes. The child redirects this inherited stream only
            // once it enters the test body, before the real write syscall.
            let (mut application_stdout, child_stream) = UnixStream::pair().unwrap();
            application_stdout
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env(CHILD, "1")
                .stdin(Stdio::from(OwnedFd::from(child_stream)))
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    panic!("Strace library control exceeded ten seconds");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let mut stdout = Vec::new();
            application_stdout.read_to_end(&mut stdout).unwrap();
            assert_eq!(stdout, b"hello\n");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains("write(1,"), "{stderr}");
            assert!(stderr.contains(" = 6"), "{stderr}");
            return;
        }

        assert_eq!(unsafe { libc::dup2(0, 1) }, 1);
        let options =
            Opts::try_parse_from(["strace", "--trace", "write", "--", "/bin/echo", "hello"])
                .unwrap();
        let config = Config {
            filters: options.trace,
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("configuration.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let payload = encode(&config).unwrap();
            stream
                .write_all(&(payload.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(&payload).unwrap();
            assert_eq!(
                stream.read(&mut [0_u8; 1]).unwrap(),
                0,
                "bootstrap sent an application request"
            );
        });
        let owner = read_tool_configuration::<Strace>(&path).unwrap();
        server.join().unwrap();
        assert_eq!(owner.config().filters, ["write".parse::<Filter>().unwrap()]);
        assert_eq!(
            owner.subscriptions().iter_syscalls().collect::<Vec<_>>(),
            [Sysno::write]
        );
        assert!(
            !owner
                .subscriptions()
                .iter_syscalls()
                .any(|s| s == Sysno::read)
        );
        let endpoint = Endpoint {
            configuration: &owner,
            expected: Mutex::new(None),
            events: Mutex::new(Vec::new()),
        };
        let pid = Pid::from_raw(unsafe { libc::getpid() });
        let tid = Pid::from_raw(unsafe { libc::syscall(libc::SYS_gettid) } as i32);
        let tool = owner.new_process(pid);
        tool.init_thread_state(tid, None);
        let state = &mut ();
        let calls = Cell::new(0_usize);
        let guest = DbtGuest::<Strace>::new_with_rpc(
            &calls as *const Cell<usize> as usize,
            tid,
            pid,
            None,
            0,
            state,
            &endpoint,
            invoke,
            read_regs,
            write_regs,
        );
        assert!(std::ptr::eq(guest.config(), owner.config()));
        let message = b"hello\n";
        let syscall = Syscall::from_raw(
            Sysno::write,
            SyscallArgs::new(1, message.as_ptr() as usize, message.len(), 0, 0, 0),
        );
        let expected = global_state::OutputEvent::Syscall(format!(
            "[pid {}] {} = 6",
            tid.colored(),
            syscall.display_with_outputs(&guest.memory())
        ));
        *endpoint.expected.lock().unwrap() = Some(expected.clone());
        assert!(matches!(
            run_tool_syscall_with_guest(&tool, guest, syscall).unwrap(),
            DbtSyscallOutcome::Suppress(6)
        ));
        assert_eq!(calls.get(), 1);
        assert_eq!(tool::take_handled_syscalls(), 1);
        assert_eq!(*endpoint.events.lock().unwrap(), [expected]);
        // Avoid writing libtest's completion line onto application stdout.
        std::process::exit(0);
    }
}
