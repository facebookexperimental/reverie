use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[test]
fn installed_hook_reentry_bypasses_tool_with_shared_coordinator_rpc() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = std::env::temp_dir().join(format!("li-rpc-{}", std::process::id()));
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

    for (mode, expected) in [
        (
            "unsubscribed-fork",
            b"unsubscribed-fork-reconstructed\n".as_slice(),
        ),
        ("tail-fork", b"tail-fork-reconstructed\n".as_slice()),
    ] {
        let output = Command::new(binary)
            .arg(mode)
            .arg(&socket)
            .output()
            .unwrap();
        assert!(output.status.success(), "{mode}: {output:?}");
        assert_eq!(output.stdout, expected, "{mode}: {output:?}");
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
