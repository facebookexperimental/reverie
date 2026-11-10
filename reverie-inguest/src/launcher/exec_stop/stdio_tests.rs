//! Physical stdio controls on the original exec-stop child and wait owner.
//! These exercise launch mechanics and physical cleanup.
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use reverie::process::PreparedStdio;
use reverie::process::Stdio;

use super::*;

fn request(program: &str, arguments: &[&str]) -> PreparedExec<'static> {
    PreparedExec::new(
        Path::new(program),
        &arguments
            .iter()
            .map(|arg| (*arg).into())
            .collect::<Vec<_>>(),
        &[],
        None,
        vec![],
    )
    .unwrap()
    .with_stdio(PreparedStdio::new(Stdio::piped(), Stdio::piped(), Stdio::piped()).unwrap())
}

fn complete_bytes(fd: OwnedFd) -> Vec<u8> {
    // At these cuts the original owner has already reaped the child. A retained
    // parent writer is an error, not a reason to wait for another owner to drop.
    let mut descriptor = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one live owned fd and fully initialized pollfd output.
    let ready = unsafe { libc::poll(&raw mut descriptor, 1, 1000) };
    assert_eq!(ready, 1, "real EOF must not depend on dropping the request");
    assert_ne!(descriptor.revents & libc::POLLHUP, 0);
    let mut bytes = Vec::new();
    std::fs::File::from(fd).read_to_end(&mut bytes).unwrap();
    bytes
}

#[test]
fn prepared_stdio_keeps_streams_distinct_at_the_original_exec_stop() {
    let mut stop = ExecStop::spawn(
        request("/bin/true", &["stdio-stop"]),
        CleanupReceipt::default(),
    )
    .unwrap();
    let pipes = stop.take_parent_stdio().unwrap();
    assert!(stop.take_parent_stdio().is_none());
    let parent = [
        pipes.stdin.as_ref(),
        pipes.stdout.as_ref(),
        pipes.stderr.as_ref(),
    ];
    let pid = stop.pid().as_raw();
    let mut identities = std::collections::BTreeSet::new();
    for (number, parent) in parent.into_iter().enumerate() {
        let parent = parent.unwrap();
        assert!(parent.as_raw_fd() > 2);
        // SAFETY: only inspect this actual retained parent descriptor.
        let flags = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
        let peer = std::fs::metadata(format!("/proc/{pid}/fd/{number}")).unwrap();
        let own = std::fs::metadata(format!("/proc/self/fd/{}", parent.as_raw_fd())).unwrap();
        assert_eq!((peer.dev(), peer.ino()), (own.dev(), own.ino()));
        assert!(identities.insert((peer.dev(), peer.ino())));
        let info = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{number}")).unwrap();
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:\t"))
            .map(|value| u32::from_str_radix(value, 8).unwrap())
            .unwrap();
        assert_eq!(flags & (libc::O_CLOEXEC | libc::O_NONBLOCK) as u32, 0);
        assert_eq!(
            flags & libc::O_ACCMODE as u32,
            if number == 0 {
                libc::O_RDONLY
            } else {
                libc::O_WRONLY
            } as u32,
        );
    }
    assert!(stop.cancel().unwrap().confirmed);
}

#[test]
fn prepared_stdio_returns_real_input_output_and_status() {
    let mut stop = ExecStop::spawn(
        request(
            "/bin/sh",
            &[
                "stdio-guest",
                "-c",
                "IFS= read -r value; printf 'out:%s' \"$value\"; printf 'err:%s' \"$value\" >&2; exit 23",
            ],
        ),
        CleanupReceipt::default(),
    )
    .unwrap();
    let mut pipes = stop.take_parent_stdio().unwrap();
    let mut input = std::fs::File::from(pipes.stdin.take().unwrap());
    // This fixed 12-byte control fits the pipe before release. Large-output
    // backpressure belongs to the subsequent concurrent-drain adapter tests.
    input.write_all(b"actual-data\n").unwrap();
    drop(input);
    let InitialExecStop { task, owner, .. } = stop;
    let running = task.detach(None).unwrap();
    assert_eq!(owner.wait(running).unwrap(), ExitStatus::Exited(23));
    assert_eq!(
        complete_bytes(pipes.stdout.take().unwrap()),
        b"out:actual-data"
    );
    assert_eq!(
        complete_bytes(pipes.stderr.take().unwrap()),
        b"err:actual-data"
    );
}

#[test]
fn prepared_stdio_eof_does_not_wait_for_the_retained_request() {
    let mut stop = ExecStop::spawn(
        request("/bin/true", &["stdio-retained-request"]),
        CleanupReceipt::default(),
    )
    .unwrap();
    let mut pipes = stop.take_parent_stdio().unwrap();
    drop(pipes.stdin.take());
    // Keep the actual request/owner alive across EOF, including after its
    // original ptracer has killed and reaped the unstarted guest.
    stop.owner.retire();
    assert!(stop.owner.receipt.snapshot().confirmed);
    assert!(complete_bytes(pipes.stdout.take().unwrap()).is_empty());
    assert!(complete_bytes(pipes.stderr.take().unwrap()).is_empty());
    assert!(stop.owner.complete);
}

#[test]
fn prepared_stdio_failed_exec_preserves_parent_endpoints_without_writers() {
    let mut failure = match ExecStop::spawn(
        request("/__reverie_missing_stdio_exec__", &["stdio-missing"]),
        CleanupReceipt::default(),
    ) {
        Ok(stop) => {
            assert!(stop.cancel().unwrap().confirmed);
            panic!("missing image unexpectedly reached an exec stop");
        }
        Err(failure) => failure,
    };
    assert!(failure.cleanup().confirmed, "{failure:?}");
    let mut pipes = failure.take_parent_stdio().unwrap();
    assert!(failure.take_parent_stdio().is_none());
    drop(pipes.stdin.take());
    assert!(complete_bytes(pipes.stdout.take().unwrap()).is_empty());
    assert!(complete_bytes(pipes.stderr.take().unwrap()).is_empty());
    assert!(failure.cleanup().confirmed);
}
