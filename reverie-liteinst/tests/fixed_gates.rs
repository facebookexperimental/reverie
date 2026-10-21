//! Actual FullTool installation in a disposable guest and coordinator.

use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

struct Coordinator(std::process::Child);

impl Drop for Coordinator {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bounded_output(mut command: Command) -> std::process::Output {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    const LIMIT: usize = 64 * 1024;
    let mut child = Coordinator(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut bytes = [Vec::new(), Vec::new()];
    let mut done = [false; 2];
    let mut status = None;
    loop {
        assert!(
            Instant::now() < deadline,
            "fixed-gate guest timed out: {bytes:?}"
        );
        for (index, pipe) in [&mut stdout as &mut dyn Read, &mut stderr as &mut dyn Read]
            .into_iter()
            .enumerate()
        {
            if done[index] {
                continue;
            }
            let mut buffer = [0; 8192];
            match pipe.read(&mut buffer) {
                Ok(0) => done[index] = true,
                Ok(count) => {
                    assert!(
                        bytes[index].len() + count <= LIMIT,
                        "fixed-gate output limit"
                    );
                    bytes[index].extend_from_slice(&buffer[..count]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("fixed-gate output read: {error}"),
            }
        }
        if status.is_none() {
            status = child.0.try_wait().unwrap();
        }
        if let Some(status) = status
            && done == [true, true]
        {
            let [stdout, stderr] = bytes;
            return std::process::Output {
                status,
                stdout,
                stderr,
            };
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn full_tool_uses_fixed_gates_and_protects_them_across_fork() {
    let binary = env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest");
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("coordinator.sock");
    let mut coordinator = Coordinator(
        Command::new(binary)
            .arg("coordinator")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            coordinator.0.try_wait().unwrap().is_none(),
            "coordinator exited"
        );
        assert!(Instant::now() < deadline, "coordinator did not bind");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut command = Command::new(binary);
    command.arg("fixed-gates").arg(&socket);
    let output = bounded_output(command);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(output.stdout, b"fixed FullTool: private=untrapped guest=trapped legacy=trapped errno=EBADF mappings=8-refused outside=usable brk=unchanged fork=inherited restorer=fixed\n");
}

#[test]
fn fixed_gate_installation_refuses_collisions_and_inherited_filters() {
    for (mode, expected) in [
        (
            "fixed-gate-collision",
            "fixed gate collision: EEXIST original-page=preserved dispatcher=absent\n",
        ),
        (
            "fixed-gate-inherited-filter",
            "fixed gate inherited filter: refused page=absent dispatcher=absent\n",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest"));
        command.arg(mode).arg(directory.path().join("no-server"));
        let output = bounded_output(command);
        assert!(output.status.success(), "{mode}: {output:?}");
        assert_eq!(output.stdout, expected.as_bytes());
        assert!(output.stderr.is_empty(), "{mode}: {output:?}");
    }
}

#[test]
fn failed_installation_after_publication_terminates_through_fixed_gate() {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest"));
    command
        .arg("fixed-gate-install-failure")
        .arg(directory.path().join("no-server"));
    let output = bounded_output(command);
    assert_eq!(output.status.code(), Some(127), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn failed_published_installation_exits_even_with_saturated_stderr() {
    use std::os::fd::FromRawFd;
    let mut descriptors = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
    let writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    let buffer = [b'x'; 4096];
    loop {
        let count = unsafe { libc::write(descriptors[1], buffer.as_ptr().cast(), buffer.len()) };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            break;
        }
        assert!(count > 0);
    }
    let flags = unsafe { libc::fcntl(descriptors[1], libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(descriptors[1], libc::F_SETFL, flags & !libc::O_NONBLOCK) },
        0
    );
    let directory = tempfile::tempdir().unwrap();
    let mut child = Coordinator(
        Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-rpc-tool-guest"))
            .arg("fixed-gate-install-failure")
            .arg(directory.path().join("no-server"))
            .stdout(Stdio::null())
            .stderr(writer)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "fatal path blocked on a full stderr pipe"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status.code(), Some(127));
    drop(reader);
}
