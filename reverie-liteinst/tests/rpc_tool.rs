use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[test]
fn first_sigsys_then_hook_callbacks_use_shared_coordinator_rpc() {
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
        stdout.starts_with("calls=32 traps=1 hooks=32 rpc="),
        "{stdout}"
    );
    let rpc = stdout
        .trim()
        .rsplit_once("rpc=")
        .unwrap()
        .1
        .parse::<u64>()
        .unwrap();
    assert!(rpc >= 32, "{stdout}");
}
