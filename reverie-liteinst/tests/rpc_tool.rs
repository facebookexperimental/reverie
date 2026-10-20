/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

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

fn output_with_timeout(mut command: Command, timeout: Duration) -> Output {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("child exceeded {timeout:?}: {output:?}");
        }
        thread::sleep(Duration::from_millis(10));
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
    command.arg(mode).arg(&socket).args(extra);
    reverie_liteinst::set_guest_alt_stack(&mut command, on_alt_stack);
    configure(&mut command);
    let output = ready.then(|| output_with_timeout(command, Duration::from_secs(20)));
    let _ = coordinator.kill();
    let _ = coordinator.wait();
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
