use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV;

const INSTRUCTION_CONTROL_UNAVAILABLE_STATUS: i32 = 77;
const TEST_STRADDLER_STALENESS_TICKS: &str = "20000";

#[test]
fn fallback_uses_owned_frames_after_guest_stack_revocation() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    for on_alt_stack in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("coordinator.sock");
        let mut coordinator = Command::new(binary)
            .arg("coordinator")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let ready = socket.exists();
        let mut command = Command::new(binary);
        command
            .arg("owned-frame")
            .arg(&socket)
            .env_remove(STRADDLER_STALENESS_TICKS_ENV);
        reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
        let output = ready.then(|| owned_frame_output(command));
        let _ = coordinator.kill();
        let _ = coordinator.wait();
        let output = output.expect("coordinator socket was not created");
        assert!(output.stderr.is_empty(), "{output:?}");
        if output.status.code() == Some(77) {
            assert_eq!(output.stdout, b"owned frame: OSPKE unavailable\n");
            eprintln!("owned frame PKRU controls unmeasured: OSPKE unavailable");
            continue;
        }
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout
                .lines()
                .filter(|line| line.starts_with("owned frame observation: "))
                .count(),
            8
        );
        let bytes = stdout.lines().last().unwrap()
            .strip_prefix("owned frame: rseq=unregistered native=4 Tool=4 registers=equal xstate-bytes=")
            .and_then(|line| line.strip_suffix(" callback-stack=owned guest-stack-revoked=preserved negative-pkru=preserved hooks=0 traps=4"))
            .expect("complete owned-frame observations").parse::<usize>().unwrap();
        assert!(bytes >= 576);
        println!("alt_stack={on_alt_stack}\n{stdout}");
    }
}

fn owned_frame_output(mut command: Command) -> Output {
    use std::io::Read;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    const LIMIT: u64 = 1024 * 1024;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let exceeded = Arc::new(AtomicBool::new(false));
    let read = |pipe: Box<dyn Read + Send>, exceeded: Arc<AtomicBool>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.take(LIMIT + 1).read_to_end(&mut bytes).unwrap();
            if bytes.len() as u64 > LIMIT {
                exceeded.store(true, Ordering::Relaxed);
            }
            bytes
        })
    };
    // Drain full raw XSTATE observations while the child runs. Waiting for
    // exit before reading would deadlock on a full pipe, not test the runtime.
    let stdout = read(Box::new(child.stdout.take().unwrap()), exceeded.clone());
    let stderr = read(Box::new(child.stderr.take().unwrap()), exceeded.clone());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bounded = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline || exceeded.load(Ordering::Relaxed) {
            bounded = true;
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    };
    assert!(
        !bounded && !exceeded.load(Ordering::Relaxed),
        "owned-frame child exceeded five seconds/one MiB: {output:?}"
    );
    output
}

#[test]
fn ordinary_tool_memory_and_scratch_work_with_protected_guest_state() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    for on_alt_stack in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("coordinator.sock");
        let mut coordinator = Command::new(binary)
            .arg("coordinator")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let ready = socket.exists();
        let mut command = Command::new(binary);
        command.arg("memory-access").arg(&socket);
        reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
        let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
        let _ = coordinator.kill();
        let _ = coordinator.wait();
        let output = output.expect("coordinator socket was not created");
        assert!(output.stderr.is_empty(), "{output:?}");
        if output.status.code() == Some(77) {
            assert_eq!(output.stdout, b"memory access: OSPKE unavailable\n");
            eprintln!("ordinary memory protected-state control unmeasured: OSPKE unavailable");
            continue;
        }
        assert!(output.status.success(), "{output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let bytes = stdout.strip_prefix("memory access: rseq=unregistered native=2 Tool=2 pkru=0,1 xstate-bytes=")
            .and_then(|line| line.strip_suffix(" scratch=complete readlink=complete inspection=complete faults=EFAULT rpc=2 hooks=0 traps=2\n"))
            .expect("complete memory-access evidence").parse::<usize>().unwrap();
        assert!(bytes >= 576);
        println!("alt_stack={on_alt_stack} {stdout}");
    }
}

#[test]
fn unpatchable_syscall_dispatches_tool_after_signal_return() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let mut command = Command::new(binary);
    command.arg("syscall-fallback").arg(&socket);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let output = output.expect("coordinator socket was not created");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"fallback: calls=6 rpc=7 hooks=0 bytes=unchanged abi=preserved\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn unpatchable_syscall_preserves_xstate_with_native_controls() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let mut command = Command::new(binary);
    command.arg("syscall-fallback-xstate").arg(&socket);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let output = output.expect("coordinator socket was not created");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("fallback xstate: mask=0x"), "{stdout}");
    assert!(
        stdout.ends_with(" native=preserved clobber=detected tool=preserved\n"),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    print!("{stdout}");
}

#[test]
fn unpatchable_syscall_preserves_protection_keys() {
    protection_keys_with_signal_stack(true);
}

#[test]
fn unpatchable_syscall_preserves_protection_keys_without_alt_stack() {
    protection_keys_with_signal_stack(false);
}

fn protection_keys_with_signal_stack(on_alt_stack: bool) {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let mut command = Command::new(binary);
    command.arg("syscall-fallback-pkey").arg(&socket);
    reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let output = output.expect("coordinator socket was not created");
    if output.status.code() == Some(77) {
        assert_eq!(output.stdout, b"fallback pkeys: OSPKE unavailable\n");
        assert!(output.stderr.is_empty(), "{output:?}");
        eprintln!("pkey control unavailable: OSPKE is not enabled");
        return;
    }
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(" pkru=0: state=preserved\n"), "{stdout}");
    assert!(stdout.contains(" pkru=1: state=preserved\n"), "{stdout}");
    assert!(
        stdout.contains("fallback pkeys: zero=preserved key0-denied=preserved bytes="),
        "{stdout}"
    );
    assert!(stdout.ends_with(" tool=424242 rpc=2\n"), "{stdout}");
    assert_eq!(stdout.lines().count(), 6, "{stdout}");
    assert!(
        stdout.starts_with("pkey fixture: rseq=unregistered before native and Tool controls\n"),
        "{stdout}"
    );
    println!("alt_stack={on_alt_stack}");
    print!("{stdout}");
}

#[test]
fn fork_child_accounts_for_fallback_and_installed_dispatch() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let outputs = ready.then(|| {
        ["installed", "fallback"].map(|kind| {
            let mut command = Command::new(binary);
            command.arg(format!("syscall-{kind}-fork")).arg(&socket);
            output_with_timeout(command, Duration::from_secs(20))
        })
    });
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let [installed, fallback] = outputs.expect("coordinator socket was not created");
    assert!(installed.status.success(), "{installed:?}");
    assert_eq!(installed.stdout, b"installed fork child: hooks=1 traps=0 fallback=0 syscall=0\ninstalled fork parent: hooks=2 traps=1 fallback=0 syscall=0\n");
    assert!(installed.stderr.is_empty(), "{installed:?}");
    assert!(fallback.status.success(), "{fallback:?}");
    assert_eq!(fallback.stdout, b"fallback fork child: hooks=0 traps=1 fallback=1 syscall=1\nfallback fork parent: hooks=0 traps=1 fallback=1 syscall=1\n");
    assert!(fallback.stderr.is_empty(), "{fallback:?}");
    print!(
        "{}{}",
        String::from_utf8(installed.stdout).unwrap(),
        String::from_utf8(fallback.stdout).unwrap()
    );
}

/// A patchable `syscall` site in an anonymous executable mapping that exists
/// when LiteInst initializes has an arena but no object for the entry census to
/// decode, so it stays on the fallback path while a text site is patched
/// (<https://github.com/rrnewton/reverie/issues/812>).
#[test]
fn an_anonymous_syscall_site_stays_on_the_fallback_path() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let mut command = Command::new(binary);
    command.arg("syscall-anonymous-site").arg(&socket);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let output = output.expect("coordinator socket was not created");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "anonymous: calls=3 traps=3 hooks=0 fallback=3 bytes=unchanged \
         control: calls=3 traps=1 hooks=6 fallback=0 bytes=patched\n"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn fallback_refusal_is_counted_separately_from_tool_errors() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest"));
    command.arg("syscall-fallback-refusal").arg("unused");
    let output = output_with_timeout(command, Duration::from_secs(20));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"fallback refusal: result=-95 attempts=1 refused=1 syscall=1 hooks=0 bytes=unchanged\n"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.is_empty());
    for line in stderr.lines() {
        let number = line
            .strip_prefix("reverie-liteinst: tool=compat syscall=")
            .expect("unexpected runtime diagnostic");
        number
            .parse::<i64>()
            .expect("invalid compatibility syscall record");
    }
}

/// Own direct-child cleanup through capture errors and caller unwinding.
/// This deliberately retains the tests' existing process-group semantics.
struct KillOnDropChild(Option<std::process::Child>);

impl KillOnDropChild {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn child(&mut self) -> &mut std::process::Child {
        self.0.as_mut().expect("child has not been reaped")
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let status = self.child().try_wait()?;
        if status.is_some() {
            // try_wait reaped the child: never direct later cleanup at its PID.
            self.0 = None;
        }
        Ok(status)
    }

    fn kill_and_wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        // It may have exited between polling and killing. wait still owns and
        // reaps that child; a kill error must not replace the timeout failure.
        let _ = self.child().kill();
        let status = self.child().wait()?;
        self.0 = None;
        Ok(status)
    }
}

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn output_with_timeout(mut command: Command, timeout: Duration) -> Output {
    use std::io::Read;
    use std::os::fd::AsRawFd;

    fn nonblocking(fd: libc::c_int) -> std::io::Result<()> {
        // SAFETY: fd is one of this invocation's owned pipe read handles.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_chunk(pipe: &mut impl Read, bytes: &mut Vec<u8>) -> std::io::Result<bool> {
        // One bounded chunk per stream keeps a continuously writable stream
        // from starving the other stream or the absolute deadline check.
        let mut buffer = [0; 8192];
        match pipe.read(&mut buffer) {
            Ok(0) => Ok(true),
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                Ok(false)
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = KillOnDropChild::new(command.spawn().unwrap());
    let deadline = Instant::now() + timeout;
    let mut stdout = child.child().stdout.take().unwrap();
    let mut stderr = child.child().stderr.take().unwrap();
    nonblocking(stdout.as_raw_fd()).unwrap();
    nonblocking(stderr.as_raw_fd()).unwrap();
    let (mut stdout_bytes, mut stderr_bytes) = (Vec::new(), Vec::new());
    let (mut stdout_eof, mut stderr_eof) = (false, false);
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            // Closing the readers before reaping never waits for a descendant
            // that retained a pipe writer. Subtree cleanup belongs to the
            // outer test box; kernel-uninterruptible reaping needs that bound.
            drop(stdout);
            drop(stderr);
            let status = status.unwrap_or_else(|| child.kill_and_wait().unwrap());
            let output = Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            };
            panic!("child exceeded {timeout:?}: {output:?}");
        }
        if status.is_none() {
            status = child.try_wait().unwrap();
        }
        if !stdout_eof {
            stdout_eof = read_chunk(&mut stdout, &mut stdout_bytes).unwrap_or_else(|error| {
                panic!("stdout capture failed: {error}; stdout={stdout_bytes:?} stderr={stderr_bytes:?}")
            });
        }
        if !stderr_eof && Instant::now() < deadline {
            stderr_eof = read_chunk(&mut stderr, &mut stderr_bytes).unwrap_or_else(|error| {
                panic!("stderr capture failed: {error}; stdout={stdout_bytes:?} stderr={stderr_bytes:?}")
            });
        }
        if Instant::now() >= deadline {
            continue;
        }
        if let Some(status) = status
            && stdout_eof
            && stderr_eof
        {
            return Output {
                status,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            };
        }
        let mut pipes = [
            libc::pollfd {
                fd: if stdout_eof { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: if stderr_eof { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            },
        ];
        // Poll child status even when both pipes closed before child exit.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let millis = remaining.as_millis().min(10) as libc::c_int;
        // SAFETY: pipes contains two initialized, owned (or disabled) fds.
        if unsafe { libc::poll(pipes.as_mut_ptr(), pipes.len() as libc::nfds_t, millis) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                panic!(
                    "capture poll failed: {error}; stdout={stdout_bytes:?} stderr={stderr_bytes:?}"
                );
            }
        }
    }
}

#[test]
fn timeout_capture_drains_both_8192_byte_pipes_while_child_runs() {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(
        "i=0; while [ \"$i\" -lt 4096 ]; do \
         printf 'out-0123456789abcdef\\n'; \
         printf 'err-0123456789abcdef\\n' >&2; i=$((i+1)); done",
    );
    // Control only this regression's pipe capacity. The workload must exceed
    // both pipes, rather than relying on the host's default capacity.
    unsafe {
        command.pre_exec(|| {
            for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
                if libc::fcntl(fd, libc::F_SETPIPE_SZ, 8192) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_GETPIPE_SZ) != 8192 {
                    return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
                }
            }
            Ok(())
        });
    }
    let output = output_with_timeout(command, Duration::from_secs(20));
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"out-0123456789abcdef\n".repeat(4096));
    assert_eq!(output.stderr, b"err-0123456789abcdef\n".repeat(4096));
}

#[test]
fn timeout_capture_preserves_prefixes_and_reaps_child_and_coordinator_on_unwind() {
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("child.pid");
    let mut coordinator = KillOnDropChild::new(
        Command::new("/bin/sh")
            .args(["-c", "while :; do :; done"])
            .spawn()
            .unwrap(),
    );
    let coordinator_pid = coordinator.child().id();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf '%s\\n' \"$$\" > \"$1\"; printf 'stdout-prefix\\n'; \
             printf 'stderr-prefix\\n' >&2; while :; do :; done",
            "timeout-control",
        ])
        .arg(&pid_file);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _coordinator = coordinator;
        output_with_timeout(command, Duration::from_secs(1))
    }))
    .expect_err("a live child must remain a timeout failure");
    let message = failure.downcast_ref::<String>().unwrap();
    assert!(message.contains("child exceeded 1s:"), "{message}");
    assert!(
        message.contains("stdout: \"stdout-prefix\\n\""),
        "{message}"
    );
    assert!(
        message.contains("stderr: \"stderr-prefix\\n\""),
        "{message}"
    );
    let child_pid: u32 = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for pid in [child_pid, coordinator_pid] {
        let mut status = 0;
        // SAFETY: these are the two direct children owned by this test. A
        // successful cleanup has already reaped them, so neither is waitable.
        assert_eq!(
            unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

#[test]
fn installed_hook_reentry_bypasses_tool_with_shared_coordinator_rpc() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = std::path::Path::new("/tmp").join(format!("li-rpc-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let socket = directory.join("coordinator.sock");

    let mut coordinator = Command::new(binary)
        .arg("coordinator")
        .arg(&socket)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists(), "coordinator socket was not created");

    let rejected_handler = Command::new(binary)
        .arg("preinstalled-handler")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(rejected_handler.status.success(), "{rejected_handler:?}");
    assert_eq!(rejected_handler.stdout, b"preinstalled-handler-reset\n");

    let pending_sigsys = Command::new(binary)
        .arg("pending-sigsys")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(
        pending_sigsys.status.code(),
        Some(126),
        "{pending_sigsys:?}"
    );

    let preblocked_sigsys = Command::new(binary)
        .arg("preblocked-sigsys")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(preblocked_sigsys.status.success(), "{preblocked_sigsys:?}");
    assert_eq!(preblocked_sigsys.stdout, b"inherited-sigsys-unblocked\n");

    let spoofed_sigsys = Command::new(binary)
        .arg("spoof-sigsys")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(
        spoofed_sigsys.status.code(),
        Some(126),
        "{spoofed_sigsys:?}"
    );

    let signal_runtime = Command::new(binary)
        .arg("tool-signal-runtime")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(signal_runtime.status.success(), "{signal_runtime:?}");
    assert_eq!(signal_runtime.stdout, b"tool-signal-runtime-ok\n");

    for (mode, reached) in [
        ("tool-sigreturn-trap", "sigreturn-site-fresh\n"),
        ("tool-sigreturn-hook", "numbered-site-hooked\n"),
        ("tool-sigreturn-trap-alias", "sigreturn-site-fresh\n"),
        ("tool-sigreturn-hook-alias", "numbered-site-hooked\n"),
    ] {
        let output = Command::new(binary)
            .arg(mode)
            .arg(&socket)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(reverie_inguest::trap::GUEST_SIGNAL_RETURN_STATUS),
            "{mode} {output:?}"
        );
        assert_eq!(output.stdout, reached.as_bytes(), "{mode} {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).ends_with(
                "reverie-inguest: the guest made its own rt_sigreturn; only the runtime's \
                 signal restorer may return from a signal, so the process ends\n"
            ),
            "{mode} {output:?}"
        );
    }

    let admitted = |mode: &str, on: bool| {
        let mut command = Command::new(binary);
        command
            .arg(mode)
            .arg(&socket)
            .env(reverie_liteinst::SITE_PATCHING_ENV, "0")
            .env(
                reverie_liteinst::SIGALRM_HANDLERS_ENV,
                if on { "1" } else { "0" },
            );
        command.output().unwrap()
    };
    let virtual_state = admitted("sigalrm-virtual", true);
    assert!(virtual_state.status.success(), "{virtual_state:?}");
    assert_eq!(virtual_state.stdout, b"sigalrm-virtual-ok\n");
    let unprepared = admitted("sigalrm-unprepared", true);
    assert_eq!(
        unprepared.status.code(),
        Some(reverie_inguest::guest::sigalrm::UNPREPARED_SIGALRM_STATUS),
        "{unprepared:?}"
    );
    assert_eq!(unprepared.stdout, b"sigalrm-handler-installed\n");
    // The pending-at-installation refusal, admitted; and with handlers not
    // admitted, the refusal of every handler (the same guest, same answer).
    for on in [true, false] {
        let refused = admitted("sigalrm-refused", on);
        assert!(refused.status.success(), "{on} {refused:?}");
        assert_eq!(refused.stdout, b"sigalrm-refused-ok\n");
    }
    let extra_filter = admitted("sigalrm-extra-filter", true);
    assert!(extra_filter.status.success(), "{extra_filter:?}");
    assert_eq!(extra_filter.stdout, b"sigalrm-extra-filter-ok\n");
    let inherited_filter = admitted("sigalrm-inherited-filter", true);
    assert!(inherited_filter.status.success(), "{inherited_filter:?}");
    assert_eq!(inherited_filter.stdout, b"sigalrm-inherited-filter-ok\n");
    let pkey_before = admitted("sigalrm-pkey-before-install", true);
    assert!(pkey_before.status.success(), "{pkey_before:?}");
    assert_eq!(pkey_before.stdout, b"sigalrm-pkey-before-install-ok\n");
    // Delivery and its refusals, with the runtime's SIGSYS handler on its own
    // alternate stack and on the guest's stack.
    let admitted_on_stack = |mode: &str, on: bool, on_alt_stack: bool| {
        let mut command = Command::new(binary);
        command
            .arg(mode)
            .arg(&socket)
            .env(reverie_liteinst::SITE_PATCHING_ENV, "0")
            .env(
                reverie_liteinst::SIGALRM_HANDLERS_ENV,
                if on { "1" } else { "0" },
            );
        reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
        command.output().unwrap()
    };
    for on_alt_stack in [true, false] {
        let delivery = admitted_on_stack("sigalrm-delivery", true, on_alt_stack);
        assert!(delivery.status.success(), "{on_alt_stack} {delivery:?}");
        assert_eq!(delivery.stdout, b"sigalrm-delivery-ok\n");
        let entry_delivery = admitted_on_stack("sigalrm-entry-delivery", true, on_alt_stack);
        assert!(
            entry_delivery.status.success(),
            "{on_alt_stack} {entry_delivery:?}"
        );
        assert_eq!(entry_delivery.stdout, b"sigalrm-entry-delivery-ok\n");
        let stack_edit = admitted_on_stack("sigalrm-stack-edit", true, on_alt_stack);
        assert_eq!(
            stack_edit.status.code(),
            Some(reverie_inguest::guest::sigalrm::DELIVERY_LOST_STATUS),
            "{on_alt_stack} {stack_edit:?}"
        );
        assert_eq!(stack_edit.stdout, b"sigalrm-stack-edit-armed\n");
        assert!(
            String::from_utf8_lossy(&stack_edit.stderr).contains("changed uc_stack"),
            "{on_alt_stack} {stack_edit:?}"
        );
        for mode in ["sigalrm-entry-mask", "sigalrm-entry-stack"] {
            let entry = admitted_on_stack(mode, true, on_alt_stack);
            assert_eq!(
                entry.status.code(),
                Some(reverie_inguest::guest::sigalrm::SIGNAL_STATE_LOST_STATUS),
                "{on_alt_stack} {mode} {entry:?}"
            );
            assert_eq!(entry.stdout, b"sigalrm-entry-frame-armed\n", "{mode}");
            assert!(
                String::from_utf8_lossy(&entry.stderr).contains(
                    "frame shows a signal mask or alternate stack the runtime did not set"
                ),
                "{on_alt_stack} {mode} {entry:?}"
            );
        }
        let pkru = admitted_on_stack("sigalrm-handler-pkru", true, on_alt_stack);
        assert!(pkru.status.success(), "{on_alt_stack} {pkru:?}");
        if pkru.stdout == b"sigalrm-handler-pkru: OSPKE unavailable\n" {
            eprintln!("SIGALRM handler PKRU return unmeasured: OSPKE unavailable");
        } else {
            assert_eq!(pkru.stdout, b"sigalrm-handler-pkru-ok\n");
        }
    }
    let not_admitted = admitted("sigalrm-unprepared", false);
    assert!(!not_admitted.status.success(), "{not_admitted:?}");
    assert!(not_admitted.stdout.is_empty(), "{not_admitted:?}");

    // With site patching on (the default) the guard router takes this
    // SIGTRAP and passes it to the default action; with it off no router is
    // installed and the kernel's own default action ends the process.
    for patching in ["1", "0"] {
        let sigtrap_default = Command::new(binary)
            .arg("tool-sigtrap-default")
            .arg(&socket)
            .env(reverie_liteinst::SITE_PATCHING_ENV, patching)
            .output()
            .unwrap();
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(
                sigtrap_default.status.signal(),
                Some(libc::SIGTRAP),
                "patching={patching} {sigtrap_default:?}"
            );
        }
        assert_eq!(
            sigtrap_default.stdout, b"raising-sigtrap\n",
            "patching={patching}"
        );
    }

    // A5 step 3c slice 0c: the runtime installs LiteInst's SIGTRAP guard
    // router only with site patching on. With it off, SIGTRAP's action after
    // installation is the one the guest left, default or ignored, and
    // SIGTRAP is not left blocked.
    for (patching, prior, expected) in [
        (
            None,
            "default",
            "sigtrap-action prior=default kernel=router blocked=false site-patching=true\n",
        ),
        (
            Some("1"),
            "ignore",
            "sigtrap-action prior=ignore kernel=router blocked=false site-patching=true\n",
        ),
        (
            Some("0"),
            "default",
            "sigtrap-action prior=default kernel=default blocked=false site-patching=false\n",
        ),
        (
            Some("0"),
            "ignore",
            "sigtrap-action prior=ignore kernel=ignore blocked=false site-patching=false\n",
        ),
    ] {
        let mut command = Command::new(binary);
        command.arg("tool-sigtrap-action").arg(&socket).arg(prior);
        match patching {
            Some(value) => command.env(reverie_liteinst::SITE_PATCHING_ENV, value),
            None => command.env_remove(reverie_liteinst::SITE_PATCHING_ENV),
        };
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "patching={patching:?} prior={prior} {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            expected,
            "patching={patching:?} prior={prior} {output:?}"
        );
    }

    let mut instruction_positives = 0;
    let mut instruction_refusals = 0;
    for (mode, concurrent) in [
        ("instruction-guest", true),
        ("instruction-guest-quiescent", false),
    ] {
        let mut instruction_command = Command::new(binary);
        instruction_command.arg(mode).arg(&socket);
        if concurrent {
            instruction_command.env(
                STRADDLER_STALENESS_TICKS_ENV,
                TEST_STRADDLER_STALENESS_TICKS,
            );
        } else {
            instruction_command.env_remove(STRADDLER_STALENESS_TICKS_ENV);
        }
        let instruction_guest = output_with_timeout(instruction_command, Duration::from_secs(10));
        if instruction_guest.status.code() == Some(INSTRUCTION_CONTROL_UNAVAILABLE_STATUS) {
            assert!(
                instruction_guest.stdout.is_empty(),
                "{mode}: {instruction_guest:?}"
            );
            assert_eq!(
                instruction_guest.stderr, b"instruction-control-unavailable\n",
                "{mode}: the refusal path must emit exactly one diagnostic"
            );
            instruction_refusals += 1;
            eprintln!("instruction publication evidence: mode={mode} positive=0 refusal=1");
        } else {
            assert!(
                instruction_guest.status.success(),
                "{mode}: {instruction_guest:?}"
            );
            assert_eq!(
                instruction_guest.stdout,
                b"cpuid=tool rdtsc=tool rdtscp=tool rdrand=masked rdseed=masked instruction-handler-rpc=1 patched-native=1 first-use-native=1 nested-syscall-native=1 tool-callbacks=9\n",
                "{mode}"
            );
            assert!(
                instruction_guest.stderr.is_empty(),
                "{mode}: the successful instruction path emitted a refusal diagnostic: {instruction_guest:?}"
            );
            instruction_positives += 1;
            eprintln!("instruction publication evidence: mode={mode} positive=1 refusal=0");
        }
    }
    assert!(
        matches!(
            (instruction_positives, instruction_refusals),
            (2, 0) | (0, 2)
        ),
        "Concurrent and Quiescent instruction controls must agree: positive={instruction_positives} refusal={instruction_refusals}"
    );
    eprintln!(
        "instruction publication total: positive={instruction_positives} refusal={instruction_refusals}"
    );
    let instruction_control_available = instruction_positives == 2;

    if instruction_control_available {
        let nested_instruction_fork = Command::new(binary)
            .arg("nested-instruction-fork")
            .arg(&socket)
            .env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1")
            .output()
            .unwrap();
        assert!(
            nested_instruction_fork.status.success(),
            "{nested_instruction_fork:?}"
        );
        assert_eq!(
            nested_instruction_fork.stdout,
            b"nested-cpuid=native nested-rdtsc=native nested-rdtscp=native guest-cpuid=tool guest-rdtsc=tool guest-rdtscp=tool child-getpid=complete child-exit=0\n"
        );
        let nested_stderr = String::from_utf8(nested_instruction_fork.stderr).unwrap();
        let stage_count = |stage: &str| {
            nested_stderr
                .lines()
                .filter(|line| line.ends_with(stage))
                .count()
        };
        for stage in [
            "stage=fork-child-thread-start-begin",
            "stage=fork-child-thread-start-complete",
        ] {
            assert_eq!(
                stage_count(stage),
                1,
                "stage marker {stage:?} must appear exactly once: {nested_stderr}"
            );
        }
        assert!(
            stage_count("stage=nested-instruction-native-cpuid") >= 1,
            "at least the planted nested CPUID must take the native path: {nested_stderr}"
        );
        assert!(
            stage_count("stage=nested-instruction-fault-native-cpuid") >= 1,
            "unpatched Tool-internal CPUID must bypass publication: {nested_stderr}"
        );
        for stage in [
            "stage=nested-instruction-native-rdtsc",
            "stage=nested-instruction-native-rdtscp",
        ] {
            assert_eq!(
                stage_count(stage),
                1,
                "the planted nested instruction must take the native path once: {nested_stderr}"
            );
        }
    }

    let clock_and_vdso_guest = Command::new(binary)
        .arg("clock-and-vdso-guest")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(
        clock_and_vdso_guest.status.success(),
        "{clock_and_vdso_guest:?}"
    );
    let clock_and_vdso_stdout = String::from_utf8(clock_and_vdso_guest.stdout).unwrap();
    eprintln!("clock/vDSO evidence: {}", clock_and_vdso_stdout.trim_end());
    assert!(
        clock_and_vdso_stdout == "rcb=unmeasured vdso-calls=1\n"
            || clock_and_vdso_stdout.starts_with("rcb=measured "),
        "{clock_and_vdso_stdout}"
    );
    assert!(
        clock_and_vdso_stdout.ends_with("vdso-calls=1\n"),
        "{clock_and_vdso_stdout}"
    );

    // The guest queries and allocates vDSO getrandom state before installing
    // the Tool, as glibc's early startup does, then requires the patched entry
    // point to refuse new queries and forward every draw to the Tool.
    let vdso_getrandom = Command::new(binary)
        .arg("vdso-getrandom-guest")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(vdso_getrandom.status.success(), "{vdso_getrandom:?}");
    let vdso_getrandom_stdout = String::from_utf8(vdso_getrandom.stdout).unwrap();
    eprintln!(
        "vDSO getrandom evidence: {}",
        vdso_getrandom_stdout.trim_end()
    );
    assert!(
        vdso_getrandom_stdout == "vdso-getrandom=patched draws=5\n"
            || vdso_getrandom_stdout == "vdso-getrandom=absent\n"
            || vdso_getrandom_stdout.starts_with("vdso-getrandom=unqueryable "),
        "{vdso_getrandom_stdout}"
    );

    // An entry point with no syscall equivalent must not stay native once a
    // Tool observing any syscall is installed: the guest calls the SGX enclave
    // entry natively, installs a Tool observing only openat, and requires the
    // -ENOSYS stub.
    let vdso_fail_closed = Command::new(binary)
        .arg("vdso-fail-closed-guest")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(vdso_fail_closed.status.success(), "{vdso_fail_closed:?}");
    let vdso_fail_closed_stdout = String::from_utf8(vdso_fail_closed.stdout).unwrap();
    eprintln!(
        "vDSO fail-closed evidence: {}",
        vdso_fail_closed_stdout.trim_end()
    );
    assert!(
        vdso_fail_closed_stdout == "vdso-sgx=stubbed\n"
            || vdso_fail_closed_stdout == "vdso-sgx=absent\n",
        "{vdso_fail_closed_stdout}"
    );

    let unsubscribed_lifecycle = Command::new(binary)
        .arg("unsubscribed-lifecycle")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(
        unsubscribed_lifecycle.status.code(),
        Some(0x34),
        "{unsubscribed_lifecycle:?}"
    );
    assert_eq!(
        unsubscribed_lifecycle.stdout,
        b"unsubscribed-clone-rejected\n"
    );
    assert_eq!(
        unsubscribed_lifecycle.stderr,
        b"unsubscribed-thread=Exited(52)\nunsubscribed-process=Exited(52)\n"
    );

    let injected_exit = Command::new(binary)
        .arg("injected-exit")
        .arg(&socket)
        .output()
        .unwrap();
    assert_eq!(injected_exit.status.code(), Some(0x34), "{injected_exit:?}");
    assert!(injected_exit.stdout.is_empty(), "{injected_exit:?}");
    assert_eq!(
        injected_exit.stderr,
        b"injected-thread=Exited(52)\ninjected-process=Exited(52)\n"
    );

    let fork_guest = Command::new(binary)
        .arg("fork-guest")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(fork_guest.status.success(), "{fork_guest:?}");
    let fork_stdout = String::from_utf8(fork_guest.stdout).unwrap();
    let mut fields = fork_stdout.split_whitespace();
    let fork_total: u64 = fields
        .next()
        .and_then(|field| field.strip_prefix("fork-rpc-total="))
        .expect("fork guest must print the shared RPC total")
        .parse()
        .unwrap();
    let sender_delta: u64 = fields
        .next()
        .and_then(|field| field.strip_prefix("fork-rpc-sender-delta="))
        .expect("fork guest must print the shared RPC sender delta")
        .parse()
        .unwrap();
    assert_eq!(fields.next(), None, "{fork_stdout}");
    assert!(fork_total >= 5, "{fork_stdout}");
    assert_eq!(sender_delta, 1, "{fork_stdout}");

    // Same contract, but the child is created by a bare `SYS_fork` instruction
    // that never enters libc — the shape Go's runtime and hand-written
    // `syscall(2)` sites produce. A `pthread_atfork`-based detector cannot see
    // this fork, so the child would silently keep sending on the parent's
    // inherited connection and the sender delta would be 0.
    let raw_fork_guest = Command::new(binary)
        .arg("raw-fork-guest")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(raw_fork_guest.status.success(), "{raw_fork_guest:?}");
    let raw_fork_stdout = String::from_utf8(raw_fork_guest.stdout).unwrap();
    let mut raw_fields = raw_fork_stdout.split_whitespace();
    let raw_fork_total: u64 = raw_fields
        .next()
        .and_then(|field| field.strip_prefix("raw-fork-rpc-total="))
        .expect("raw fork guest must print the shared RPC total")
        .parse()
        .unwrap();
    let raw_sender_delta: u64 = raw_fields
        .next()
        .and_then(|field| field.strip_prefix("raw-fork-rpc-sender-delta="))
        .expect("raw fork guest must print the shared RPC sender delta")
        .parse()
        .unwrap();
    assert_eq!(raw_fields.next(), None, "{raw_fork_stdout}");
    assert!(raw_fork_total >= 5, "{raw_fork_stdout}");
    assert_eq!(
        raw_sender_delta, 1,
        "a raw SYS_fork child must reconnect under its own identity: {raw_fork_stdout}"
    );

    for (mode, expected) in [
        (
            "clone3-guest",
            b"clone3=child-reconstructed sender-delta=1\n".as_slice(),
        ),
        (
            "vfork-guest",
            b"vfork=translated-cow-child sender-delta=1\n".as_slice(),
        ),
    ] {
        let output = Command::new(binary)
            .arg(mode)
            .arg(&socket)
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
        eprintln!(
            "process evidence: {}",
            String::from_utf8_lossy(&output.stdout).trim_end()
        );
        assert_eq!(output.stdout, expected, "{mode}: {output:?}");
    }

    for (mode, expected) in [
        (
            "unsubscribed-fork",
            b"unsubscribed-fork-reconstructed\n".as_slice(),
        ),
        ("tail-fork", b"tail-fork-reconstructed\n".as_slice()),
        (
            "mask-inject",
            b"inject-mask full=0xffffffffbffbfeff write-only-set first-call fallback-site trap-after-full-mask\nblocking-wait during=0xffffffffbffbfeff probe=EINVAL,EFAULT parent-asleep-in-wait seeded-mask-restored blocked-signal-pending\n".as_slice(),
        ),
        (
            "mask-unsubscribed",
            b"unsubscribed-mask full=0xffffffffbffbfeff write-only-set first-call fallback-site trap-after-full-mask\n".as_slice(),
        ),
        (
            "mask-tail",
            b"tail-mask full=0xffffffffbffbfeff write-only-set first-call fallback-site trap-after-full-mask\n".as_slice(),
        ),
    ] {
        let output = Command::new(binary)
            .arg(mode)
            .arg(&socket)
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
        assert_eq!(output.stdout, expected, "{mode}: {output:?}");
    }

    // With CPUID and RDTSC subscribed, the runtime also keeps SIGSEGV out of
    // the guest's mask, and an RDTSC after a full-mask set still reaches the
    // Tool. The Tool subscribes the same instructions as the instruction
    // modes above, so their capability result decides this mode's outcome.
    let mut mask_instruction = Command::new(binary);
    mask_instruction.arg("mask-instruction").arg(&socket).env(
        STRADDLER_STALENESS_TICKS_ENV,
        TEST_STRADDLER_STALENESS_TICKS,
    );
    let mask_instruction = output_with_timeout(mask_instruction, Duration::from_secs(10));
    if instruction_control_available {
        assert!(mask_instruction.status.success(), "{mask_instruction:?}");
        assert_eq!(
            mask_instruction.stdout,
            b"instruction-mask full=0xffffffffbffbfaff write-only-set first-call fallback-site trap-after-full-mask\nrdtsc-after-full-mask=tool\n",
            "{mask_instruction:?}"
        );
        assert!(mask_instruction.stderr.is_empty(), "{mask_instruction:?}");
    } else {
        assert_eq!(
            mask_instruction.status.code(),
            Some(INSTRUCTION_CONTROL_UNAVAILABLE_STATUS),
            "{mask_instruction:?}"
        );
        assert!(mask_instruction.stdout.is_empty(), "{mask_instruction:?}");
        assert_eq!(
            mask_instruction.stderr, b"instruction-control-unavailable\n",
            "{mask_instruction:?}"
        );
    }

    let guest = Command::new(binary)
        .arg("guest")
        .arg(&socket)
        .output()
        .unwrap();
    let _ = coordinator.kill();
    let _ = coordinator.wait();
    let _ = std::fs::remove_dir_all(&directory);

    assert!(
        guest.status.success(),
        "status={} stdout={} stderr={}",
        guest.status,
        String::from_utf8_lossy(&guest.stdout),
        String::from_utf8_lossy(&guest.stderr)
    );
    let stdout = String::from_utf8(guest.stdout).unwrap();
    assert!(
        stdout.starts_with(
            "calls=32 traps=1 hooks=32 rpc_delta=34 nested_traps=1 nested_hooks=33 mask_traps=1 mask_hooks=33 mask_result=-1 first_use_exec_result=-95 first_use_signal_result=-1 "
        ),
        "{stdout}"
    );
}

/// Run one `rpc_tool_guest` mode against its own coordinator.
fn late_code_guest(
    mode: &str,
    extra: &[&std::ffi::OsStr],
    on_alt_stack: bool,
    configure: impl FnOnce(&mut Command),
) -> Output {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let coordinator = KillOnDropChild::new(
        Command::new(binary)
            .arg("coordinator")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready = socket.exists();
    let mut command = Command::new(binary);
    command.arg(mode).arg(&socket).args(extra);
    reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
    configure(&mut command);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    drop(coordinator);
    output.expect("coordinator socket was not created")
}

/// Whether the host refused CPUID/TSC faulting; asserts the single refusal
/// diagnostic so an unrelated failure cannot be mistaken for a refusal.
fn instruction_control_refused(output: &Output, label: &str) -> bool {
    if output.status.code() != Some(INSTRUCTION_CONTROL_UNAVAILABLE_STATUS) {
        return false;
    }
    assert_eq!(
        output.stderr, b"instruction-control-unavailable\n",
        "{label}: {output:?}"
    );
    eprintln!("{label}: instruction controls unavailable on this host; unmeasured");
    true
}

// CPUID/RDTSC/RDTSCP in an executable page mapped after the runtime started has
// no arena. Each one must still reach the Tool on the owned continuation, with
// the same result as the patched path, and resume after the instruction with
// every other register intact.
#[test]
fn late_code_instructions_reach_the_tool_through_the_continuation() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("late-code-instruction", &[], on_alt_stack, |_| {});
        if instruction_control_refused(&output, "late-code-instruction") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "late-code cpuid=tool rdtsc=tool rdtscp=tool equals-patched=1 continuation=163 owned-stack=163 sites=0 registers=preserved\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert!(
            output.stderr.is_empty(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// One Tool reached three ways must observe the same results (in-guest
// layering step 2): LiteInst with site patching on, where the binary's
// getpid site is patched and a site in an anonymous executable page (no
// arena) is declined; LiteInst with site patching off, which declines every
// site, as in-guest-trap runs it; and the shared runtime's installer with no
// patcher at all. The first line is what the Tool and guest observe; the
// second shows which route each site took.
#[test]
fn patched_declined_and_unpatched_sites_give_one_tool_the_same_results() {
    const TOOL_OBSERVED: &str = "same-tool getpid=pid tool-getpid=16 rpc=16 clock=0 tool-clock=1 \
                                 cpuid=tool tool-cpuid=1 rdtsc=tool tool-rdtsc=1";
    let zero = "binary-site traps=0 hooks=0 anonymous-site traps=0 hooks=0";
    let cases = [
        (
            "liteinst",
            Some("1"),
            "binary-site traps=1 hooks=8 anonymous-site traps=8 hooks=0",
        ),
        ("liteinst", Some("0"), zero),
        ("no-patcher", None, zero),
    ];
    for on_alt_stack in [true, false] {
        for (installer, site_patching, routes) in cases {
            let label =
                format!("{installer} site_patching={site_patching:?} alt_stack={on_alt_stack}");
            let output = late_code_guest(
                "same-tool",
                &[std::ffi::OsStr::new(installer)],
                on_alt_stack,
                |command| {
                    command.env(
                        STRADDLER_STALENESS_TICKS_ENV,
                        TEST_STRADDLER_STALENESS_TICKS,
                    );
                    if let Some(value) = site_patching {
                        command.env(reverie_liteinst::SITE_PATCHING_ENV, value);
                    }
                },
            );
            // This control has no unmeasured outcome: every case must run,
            // so a host that refuses CPUID/TSC faulting fails it.
            assert!(
                !instruction_control_refused(&output, &label),
                "{label}: CPUID/TSC faulting is unavailable, so the same-Tool control cannot run"
            );
            assert!(output.status.success(), "{label}: {output:?}");
            assert!(output.stderr.is_empty(), "{label}: {output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();
            assert_eq!(lines.next(), Some(TOOL_OBSERVED), "{label}: {output:?}");
            assert_eq!(lines.next(), Some(routes), "{label}: {output:?}");
            assert_eq!(lines.next(), None, "{label}: {output:?}");
        }
    }
}

// With site patching off (the trap-only mode in-guest-trap needs), CPUID,
// RDTSC and RDTSCP inside an arena are emulated through the continuation like
// late code: no site is patched, and each reaches the Tool once with the same
// result.
#[test]
fn site_patching_off_emulates_in_arena_instructions_through_the_continuation() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest(
            "late-code-instruction-trap-only",
            &[],
            on_alt_stack,
            |command| {
                command.env(reverie_liteinst::SITE_PATCHING_ENV, "0");
            },
        );
        if instruction_control_refused(&output, "late-code-instruction-trap-only") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "late-code trap-only cpuid=tool rdtsc=tool rdtscp=tool equals-in-arena=1 continuation=163+7 owned-stack=170 sites=0 registers=preserved\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert!(
            output.stderr.is_empty(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// With site patching off, a fork runs entirely on the fallback continuation,
// and the child first reads its RCB clock while still on that continuation.
// Binding the child's fresh PMU counter reads CPUID; that is the runtime's own
// code and must run natively, not be emulated through the busy continuation
// (which used to kill the child with SIGSEGV and leave the parent waiting).
#[test]
fn site_patching_off_fork_child_binds_its_clock_and_exits() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("nested-instruction-fork", &[], on_alt_stack, |command| {
            command.env(reverie_liteinst::SITE_PATCHING_ENV, "0");
        });
        if instruction_control_refused(&output, "nested-instruction-fork trap-only") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "nested-cpuid=native nested-rdtsc=native nested-rdtscp=native guest-cpuid=tool guest-rdtsc=tool guest-rdtscp=tool child-getpid=complete child-exit=0\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// The libcrypto shape: a dlopen'd library's constructor runs CPUID and RDTSC in
// code the runtime never saw at startup.
#[test]
fn dlopen_constructor_cpuid_reaches_the_tool_through_the_continuation() {
    let directory = tempfile::tempdir().unwrap();
    let library = directory.path().join("liblate_code_cpuid.so");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/late_code_cpuid_constructor.c");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let compiled = Command::new(compiler)
        .args(["-std=gnu11", "-O0", "-shared", "-fPIC"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{compiled:?}");
    for on_alt_stack in [true, false] {
        let output = late_code_guest(
            "late-code-dlopen",
            &[library.as_os_str()],
            on_alt_stack,
            |command| {
                command.env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1");
            },
        );
        if instruction_control_refused(&output, "late-code-dlopen") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "late-code dlopen constructor-cpuid=tool constructor-rdtsc=tool owned-stack=2\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stage_count = |stage: &str| stderr.lines().filter(|line| line.ends_with(stage)).count();
        for stage in [
            "stage=instruction-fault-continuation-cpuid",
            "stage=instruction-fault-continuation-rdtsc",
        ] {
            assert_eq!(stage_count(stage), 1, "{stage}: {stderr}");
        }
        assert!(
            !stderr.contains("instruction-sigsegv-"),
            "no refusal stage may appear: {stderr}"
        );
    }
}

// The production case itself: the host's libcrypto runs OPENSSL_cpuid_setup
// from its initializer during dlopen. Skipped on a host without libcrypto 3.
#[test]
fn dlopen_system_libcrypto_initializer_reaches_the_tool() {
    let Some(library) = [
        "/usr/lib64/libcrypto.so.3",
        "/lib64/libcrypto.so.3",
        "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
        "/lib/x86_64-linux-gnu/libcrypto.so.3",
    ]
    .into_iter()
    .map(std::path::Path::new)
    .find(|path| path.exists()) else {
        eprintln!("libcrypto.so.3 is not installed; the system dlopen case is unmeasured");
        return;
    };
    for on_alt_stack in [true, false] {
        let output = late_code_guest(
            "late-code-dlopen-system",
            &[library.as_os_str()],
            on_alt_stack,
            |command| {
                command.env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1");
            },
        );
        if instruction_control_refused(&output, "late-code-dlopen-system") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "late-code dlopen-system initializer-cpuid=tool\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr
                .lines()
                .any(|line| line.ends_with("stage=instruction-fault-continuation-cpuid")),
            "{stderr}"
        );
        assert!(
            !stderr.contains("instruction-sigsegv-"),
            "no refusal stage may appear: {stderr}"
        );
    }
}

// A fault in code without an arena that is not an emulated instruction (a #GP
// on a non-canonical load, and a NULL page fault) keeps the guest's native
// fate: death by a genuine SIGSEGV, never an ordinary exit status 139.
#[test]
fn undecodable_late_code_fault_ends_the_guest_by_sigsegv() {
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    for mode in ["late-code-gp-fault", "late-code-null-load"] {
        for on_alt_stack in [true, false] {
            let output = late_code_guest(mode, &[], on_alt_stack, |command| {
                command.env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1");
                // Keep the expected crash from writing a core file.
                unsafe {
                    command.pre_exec(|| {
                        let limit = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    })
                };
            });
            if instruction_control_refused(&output, mode) {
                return;
            }
            let label = format!("{mode} alt_stack={on_alt_stack}: {output:?}");
            assert_eq!(output.status.code(), None, "{label}");
            assert_eq!(output.status.signal(), Some(libc::SIGSEGV), "{label}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let rip = stdout
                .lines()
                .find_map(|line| line.strip_prefix("fault-rip="))
                .unwrap_or_else(|| panic!("{label}"));
            assert!(!stdout.contains("survived"), "{label}");
            let refusal = format!(
                "stage=instruction-sigsegv-no-reachable-arena rip={rip} bytes=48-8b-00-c3-00-00-00-00 map=[anon]"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                stderr
                    .lines()
                    .filter(|line| line.ends_with(&refusal))
                    .count(),
                1,
                "{label}"
            );
        }
    }
}

// A CPUID/RDTSC/RDTSCP inside an arena whose 8-byte word patch would cross a
// cache line is refused before any byte changes while cross-line publication
// is disabled. The guest must keep running: each execution traps and reaches
// the Tool through the continuation, and the site is never patched. Nix's
// coreutils runs this shape in `__cpu_indicator_init` before `main`.
// A patchable neighbour whose patch would cover such a site, and so the
// point where a thread in its continuation resumes, must stay unpatched too.
#[test]
fn cross_line_instruction_site_reaches_the_tool_through_the_continuation() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("straddler-instruction", &[], on_alt_stack, |command| {
            command
                .env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV)
                .env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1");
        });
        if instruction_control_refused(&output, "straddler-instruction") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "straddler cpuid=tool rdtsc=tool rdtscp=tool calls=56 continuation=56 owned-stack=56 hooks=0 registers=preserved\n\
             straddler-neighbour cpuid=tool callbacks=32 traps=8+24 hooks=0\n\
             straddler-stale-jump cpuid=tool traps=8 hooks=0\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stage_count = |stage: &str| stderr.lines().filter(|line| line.ends_with(stage)).count();
        for (stage, expected) in [
            ("stage=instruction-fault-continuation-cpuid", 80),
            ("stage=instruction-fault-continuation-rdtsc", 8),
            ("stage=instruction-fault-continuation-rdtscp", 8),
        ] {
            assert_eq!(stage_count(stage), expected, "{stage}: {stderr}");
        }
        assert!(
            !stderr.contains("instruction-sigsegv-"),
            "no refusal stage may appear: {stderr}"
        );
    }
}

// A patched CPUID whose cross-line jump spans a page boundary, with only the
// first page later replaced by its original bytes: executing the CPUID again
// reclaims the site while the jump's displacement survives on the second
// page. The runtime must end the guest (the earlier patch may survive)
// rather than resume through the continuation into those bytes.
#[test]
fn reclaiming_a_site_whose_jump_partly_survives_fails_closed() {
    use std::os::unix::process::ExitStatusExt;

    for on_alt_stack in [true, false] {
        let output = late_code_guest("straddler-reclaim-partial", &[], on_alt_stack, |command| {
            command
                .env(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV, "20000")
                .env(reverie_liteinst::IN_GUEST_STAGE_STREAM_ENV, "1");
        });
        if instruction_control_refused(&output, "straddler-reclaim-partial") {
            return;
        }
        assert_eq!(
            output.status.signal(),
            Some(libc::SIGSEGV),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "reclaim-partial ready\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stage_count = |stage: &str| stderr.lines().filter(|line| line.ends_with(stage)).count();
        assert_eq!(
            stage_count("stage=instruction-sigsegv-site-install-failed"),
            1,
            "alt_stack={on_alt_stack}: {stderr}"
        );
        // The site was patched, never emulated, and the reclaim must not
        // resume through the continuation.
        assert!(
            !stderr.contains("stage=instruction-fault-continuation-cpuid"),
            "alt_stack={on_alt_stack}: {stderr}"
        );
    }
}

// A syscall refused before any publication runs through the SIGSYS
// continuation and leaves no footprint. After a no-op mremap makes it STALE,
// a CPUID whose patch would cover it must still not be patched.
#[test]
fn a_stale_syscall_fallback_site_keeps_its_continuation_reservation() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest(
            "straddler-syscall-reservation",
            &[],
            on_alt_stack,
            |command| {
                command.env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
            },
        );
        if instruction_control_refused(&output, "straddler-syscall-reservation") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "straddler-syscall-reservation cpuid=tool syscall=getpid traps=8 hooks=0+0\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// LiteInst publishes only into private mappings: a write through a shared
// executable mapping would change the page cache that every alias and every
// other process executes, behind their site tables. CPUIDs in a shared
// mapping, even one whose word fits a cache line, must trap every time, reach
// the Tool through the continuation, and leave the shared page unchanged.
#[test]
fn a_shared_executable_mapping_is_never_patched() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("straddler-shared-mapping", &[], on_alt_stack, |command| {
            command.env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
        });
        if instruction_control_refused(&output, "straddler-shared-mapping") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "shared-mapping cpuid=tool traps=8+8 hooks=0+0 page=unchanged\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// A refused CPUID at a private page end resumes in an adjacent shared
// mapping. LiteInst never publishes into shared mappings, so the resume
// bytes are the original ones and the continuation must work.
#[test]
fn a_refused_site_resuming_into_a_shared_mapping_runs_through_the_continuation() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("straddler-split-mapping", &[], on_alt_stack, |command| {
            command.env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
        });
        if instruction_control_refused(&output, "straddler-split-mapping") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "split-mapping cpuid=tool traps=8\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// A syscall refused before anything was written runs through the SIGSYS
// continuation without leaving a footprint, so the patchable RDTSC starting
// exactly at its resume point must still be patched.
#[test]
fn an_instruction_at_a_fallback_syscalls_resume_point_is_still_patched() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest(
            "fallback-syscall-then-rdtsc",
            &[],
            on_alt_stack,
            |command| {
                command.env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
            },
        );
        if instruction_control_refused(&output, "fallback-syscall-then-rdtsc") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "fallback-syscall-then-rdtsc rdtsc=tool traps=1 patched=1\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// One file page mapped private and shared. The shared alias executes first
// and must not be patched (the write would show through the clean private
// alias); the private continuation site then runs on its original bytes.
#[test]
fn a_shared_alias_is_not_patched_under_a_private_continuation_site() {
    for on_alt_stack in [true, false] {
        let output = late_code_guest("straddler-private-alias", &[], on_alt_stack, |command| {
            command.env_remove(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
        });
        if instruction_control_refused(&output, "straddler-private-alias") {
            return;
        }
        assert!(
            output.status.success(),
            "alt_stack={on_alt_stack}: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "private-alias shared=unpatched private=original cpuid=tool traps=8+8\n",
            "alt_stack={on_alt_stack}: {output:?}"
        );
    }
}

// This is Tool-selected full-event fidelity, not a Linux arbitrary-padding
// comparison or a claim that the legacy mask/action owner has migrated.
#[test]
fn deferred_sigalrm_preserves_full_event_at_completion_and_before_syscall() {
    let expected_info = |seed: u8| {
        let mut bytes: [u8; 128] =
            core::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(seed));
        bytes[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
        bytes[4..8].copy_from_slice(&73_i32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut failures = Vec::new();
    for mode in ["completion", "entry"] {
        let mut expected = String::new();
        for (round, seed) in [0x31, 0xa7].into_iter().enumerate() {
            let count = round + 1;
            expected.push_str(&format!(
                "full-event {mode} round={round} siginfo={}\nfull-event {mode} round={round} registers=preserved runs={count} handlers={count} replacement=EINVAL\n",
                expected_info(seed),
            ));
        }
        expected.push_str(&format!("full-event {mode} complete\n"));
        for on_alt_stack in [true, false] {
            let output = late_code_guest(
                &format!("sigalrm-full-event-{mode}"),
                &[],
                on_alt_stack,
                |command| {
                    command
                        .env(reverie_liteinst::SITE_PATCHING_ENV, "0")
                        .env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "1");
                },
            );
            // Keep all four actual outcomes on the red run. There is no
            // unavailable/skip success path, timeout increase or byte filter.
            eprintln!("full-event {mode} alt_stack={on_alt_stack}: {output:?}");
            if !output.status.success()
                || output.stdout != expected.as_bytes()
                || !output.stderr.is_empty()
            {
                failures.push(format!("{mode} alt_stack={on_alt_stack}: {output:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "full-event fidelity failures:\n{}",
        failures.join("\n")
    );
}
