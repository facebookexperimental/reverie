//! Ordinary discovered driver for the fixture's actual main-thread fork.
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

fn run(mode: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mapped_rpc_fork_fixture"))
        .arg(mode)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut expired = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            expired = true;
            assert_eq!(
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) },
                0
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        !expired,
        "main-thread fork fixture exceeded original five-second bound; reaped {:?}",
        output.status
    );
    assert!(
        output.status.success(),
        "main-thread fork fixture failed with {:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    eprintln!(
        "FORK_FIXTURE mode={mode} status={:?}\n{stdout}",
        output.status
    );
    assert!(
        stdout.contains("vma_absent=true arc_deallocated=1 config_drops=1"),
        "{stdout}"
    );
    assert!(
        stdout.contains("PARENT_CONTINUED child_status=0 shared_bytes=4096"),
        "{stdout}"
    );
}
#[test]
fn sole_inherited_client_releases_child_vma_and_preserves_parent_rpc() {
    run("sole");
}
#[test]
fn extra_copied_alias_keeps_owned_error_until_explicit_retry() {
    run("alias");
}

#[test]
fn injected_unmap_failure_keeps_child_owner_until_real_retry() {
    run("unmap-failure");
}
#[test]
fn successful_release_does_not_unmap_a_new_mapping_at_the_same_address() {
    run("single-unmap");
}
