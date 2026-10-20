/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A drop-in replacement for `std::process::Command` that provides the ability
//! to set up namespaces, a seccomp filter, and more.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg(target_os = "linux")]
#![cfg_attr(feature = "nightly", feature(internal_output_capture))]

mod builder;
mod child;
mod clone;
mod container;
mod env;
mod error;
mod exit_status;
mod fd;
mod id_map;
#[doc(hidden)]
pub mod launch_window;
mod mount;
mod namespace;
mod net;
mod pid;
mod pty;
pub mod seccomp;
mod spawn;
mod stdio;
mod util;

use std::ffi::CString;
use std::io;

pub use child::Child;
pub use child::Output;
pub use container::ChildCleanupObservation;
pub use container::ChildStartContext;
pub use container::Container;
pub use container::DeferredContainerRun;
pub use container::MAX_STARTUP_FDS;
pub use container::OwnedContainerCleanup;
pub use container::OwnedDecodeFailure;
pub use container::OwnedDeferredContainerRun;
pub use container::OwnedFinalization;
pub use container::OwnedFinalize;
pub use container::OwnedReapedResult;
pub use container::OwnedRunFailure;
pub use container::ParentStartContext;
pub use container::RunError;
pub use container::StartupError;
pub use container::StartupOwnedFailure;
pub use container::StartupRunError;
pub use error::Context;
pub use error::Error;
pub use exit_status::ExitStatus;
pub use mount::Bind;
pub use mount::Mount;
pub use mount::MountFlags;
pub use mount::MountParseError;
pub use namespace::Namespace;
// Re-export Signal since it is used by `Child::signal`.
pub use nix::sys::signal::Signal;
pub use pid::Pid;
pub use pty::Pty;
pub use pty::PtyChild;
pub use stdio::ChildStderr;
pub use stdio::ChildStdin;
pub use stdio::ChildStdout;
pub use stdio::Stdio;
use syscalls::Errno;

/// A builder for spawning a process.
// See the builder.rs for documentation of each field.
pub struct Command {
    program: CString,
    args: util::CStringArray,
    pre_exec: Vec<Box<dyn FnMut() -> Result<(), Errno> + Send + Sync>>,
    container: Container,
}

impl Command {
    /// Converts [`std::process::Command`] into [`Command`]. Note that this is a
    /// very basic and *lossy* conversion.
    ///
    /// This only preserves the
    ///  - program path,
    ///  - arguments,
    ///  - environment variables,
    ///  - and working directory.
    ///
    /// # Caveats
    ///
    /// Since [`std::process::Command`] is rather opaque and doesn't provide
    /// access to all fields, this will *not* preserve:
    ///  - stdio handles,
    ///  - `env_clear`,
    ///  - any `pre_exec` callbacks,
    ///  - `arg0` (if not the same as `program`),
    ///  - `uid`, `gid`, or `groups`.
    pub fn from_std_lossy(cmd: &std::process::Command) -> Command {
        let mut result = Command::new(cmd.get_program());
        result.args(cmd.get_args());

        for (key, value) in cmd.get_envs() {
            match value {
                Some(value) => result.env(key, value),
                None => result.env_remove(key),
            };
        }

        if let Some(dir) = cmd.get_current_dir() {
            result.current_dir(dir);
        }

        result
    }

    /// Converts this command to [`std::process::Command`].
    ///
    /// This fails if the command contains container configuration that cannot
    /// be represented by [`std::process::Command`], rather than silently
    /// discarding that configuration. This includes namespaces, mounts,
    /// seccomp filters, pseudoterminals, and CPU affinity.
    pub fn try_into_std(self) -> io::Result<std::process::Command> {
        let blockers = self.container.std_conversion_blockers();
        if !blockers.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot convert to std::process::Command without losing: {}",
                    blockers.join(", ")
                ),
            ));
        }

        Ok(self.into_std())
    }

    /// Converts this command to [`std::process::Command`], refusing to discard
    /// any container configuration.
    ///
    /// This compatibility shim preserves the former return type for callers
    /// whose commands are representable. It panics instead of silently losing
    /// unsupported configuration. New callers should use [`Self::try_into_std`]
    /// to handle that refusal explicitly.
    pub fn into_std_lossy(self) -> std::process::Command {
        self.try_into_std().unwrap_or_else(|error| {
            panic!("Command::into_std_lossy refused unsupported configuration: {error}")
        })
    }

    fn into_std(self) -> std::process::Command {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        // Keep this exhaustive: adding Command state must fail to compile until
        // the standard-command conversion explicitly preserves or refuses it.
        let Self {
            program,
            args,
            pre_exec,
            container,
        } = self;

        let mut result = std::process::Command::new(OsStr::from_bytes(program.to_bytes()));
        result.args(
            args.iter()
                .skip(1)
                .map(|arg| OsStr::from_bytes(arg.to_bytes())),
        );

        if container.env.is_cleared() {
            result.env_clear();
        }

        for (key, value) in container.get_envs() {
            match value {
                Some(value) => result.env(key, value),
                None => result.env_remove(key),
            };
        }

        if let Some(dir) = container.get_current_dir() {
            result.current_dir(dir);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            result.arg0(OsStr::from_bytes(args.get(0).to_bytes()));

            for mut f in pre_exec {
                unsafe {
                    result.pre_exec(move || f().map_err(Into::into));
                }
            }
        }

        result.stdin(container.stdin);
        result.stdout(container.stdout);
        result.stderr(container.stderr);

        result
    }
}

/// Names the unit test that a fresh single-test process was started to run; it
/// is set only in that process, never in the libtest harness process.
#[cfg(test)]
pub(crate) const ISOLATED_TEST_MARKER: &str = "REVERIE_PROCESS_ISOLATED_TEST";

/// Runs the calling unit test in a fresh single-test process.
///
/// Returns `true` in the libtest harness process, after the fresh process has
/// run the test body and passed; the caller must then return without running
/// the body itself. Returns `false` inside the fresh process, where the caller
/// runs the body. Use it as the first statement of every test that creates a
/// child process:
///
/// ```ignore
/// if crate::test_runs_in_own_process() {
///     return;
/// }
/// ```
///
/// The children these tests create are made with a raw `clone` that shares
/// neither the file-descriptor table nor glibc's `atfork` handlers, and most of
/// them never `execve`. Such a child therefore receives a copy of every
/// descriptor open anywhere in the process that runs the test, including the
/// pipe ends and pidfds of tests running on other libtest threads, and a copy
/// of every userspace lock another thread held at the instant of the clone.
/// That is why the `Container` entry points require a single-threaded caller.
/// The multi-threaded libtest harness breaks that requirement: another test's
/// child can hold this test's pipe ends open (so a closed reader raises no
/// `SIGPIPE` and a drain to end-of-file waits forever), a startup child counts
/// another test's pidfd, a closed descriptor number is reused by another
/// thread, and a panicking child can block forever on an allocator lock that
/// one of libtest's own threads held at the clone. A mutex around the tests
/// cannot stop libtest's own threads from allocating. The fresh process runs
/// with `--test-threads=1`, where the only other thread is libtest's main
/// thread blocked in a channel receive, which is the documented
/// single-threaded setting.
#[cfg(test)]
#[must_use]
pub(crate) fn test_runs_in_own_process() -> bool {
    let thread = std::thread::current();
    let name = thread
        .name()
        .expect("libtest names each test thread after its test")
        .to_owned();
    if let Some(marker) = std::env::var_os(ISOLATED_TEST_MARKER) {
        assert_eq!(
            marker.to_str(),
            Some(name.as_str()),
            "the isolated test process ran a test other than the one it was started for"
        );
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name.as_str(), "--exact", "--test-threads=1", "--nocapture"])
        .env(ISOLATED_TEST_MARKER, &name)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    print!("{stdout}");
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "the isolated process for {name} failed: {:?}",
        output.status
    );
    assert!(
        stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "the isolated process for {name} did not run exactly that one test"
    );
    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;
    use std::str::from_utf8;

    use super::*;
    use crate::ExitStatus;

    #[tokio::test]
    async fn spawn() {
        if crate::test_runs_in_own_process() {
            return;
        }
        assert_eq!(
            Command::new("true").spawn().unwrap().wait().await.unwrap(),
            ExitStatus::Exited(0)
        );

        assert_eq!(
            Command::new("false").spawn().unwrap().wait().await.unwrap(),
            ExitStatus::Exited(1)
        );
    }

    #[test]
    fn wait_blocking() {
        if crate::test_runs_in_own_process() {
            return;
        }
        assert_eq!(
            Command::new("true")
                .spawn()
                .unwrap()
                .wait_blocking()
                .unwrap(),
            ExitStatus::Exited(0)
        );

        assert_eq!(
            Command::new("false")
                .spawn()
                .unwrap()
                .wait_blocking()
                .unwrap(),
            ExitStatus::Exited(1)
        );
    }

    #[tokio::test]
    async fn spawn_fail() {
        if crate::test_runs_in_own_process() {
            return;
        }
        assert_eq!(
            Command::new("/iprobablydonotexist").spawn().unwrap_err(),
            Error::new(Errno::ENOENT, Context::Exec)
        );
    }

    #[tokio::test]
    async fn double_wait() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut child = Command::new("true").spawn().unwrap();
        assert_eq!(child.wait().await.unwrap(), ExitStatus::Exited(0));
        assert_eq!(child.wait().await.unwrap(), ExitStatus::Exited(0));
    }

    #[tokio::test]
    async fn output() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("echo")
            .arg("foo")
            .arg("bar")
            .output()
            .await
            .unwrap();
        assert_eq!(output.stdout, b"foo bar\n");
        assert_eq!(output.stderr, b"");
        assert_eq!(output.status, ExitStatus::Exited(0));
    }

    fn parse_proc_status(stdout: &[u8]) -> BTreeMap<&str, &str> {
        from_utf8(stdout)
            .unwrap()
            .trim_end()
            .split('\n')
            .map(|line| {
                let (first, second) = line.split_once(':').unwrap();
                (first, second.trim())
            })
            .collect()
    }

    #[tokio::test]
    async fn uid_namespace() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/proc/self/status")
            .map_root()
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));

        let proc_status = parse_proc_status(&output.stdout);

        // We should be root user inside of the container.
        assert_eq!(proc_status["Uid"], "0\t0\t0\t0");
    }

    #[tokio::test]
    async fn pid_namespace() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/proc/self/status")
            .map_root()
            .unshare(Namespace::PID)
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));

        let proc_status = parse_proc_status(&output.stdout);

        assert_eq!(proc_status["NSpid"].split('\t').nth(1), Some("1"),);

        // Note that, since we haven't mounted a fresh /proc into the container,
        // the child still sees what the parent sees and so the PID will *not*
        // be 1.
        assert_ne!(proc_status["Pid"], "1");
    }

    #[tokio::test]
    async fn mount_proc() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/proc/self/status")
            .map_root()
            .unshare(Namespace::PID)
            .mount(Mount::proc())
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));

        let proc_status = parse_proc_status(&output.stdout);

        // With /proc mounted, the child really believes it is the root process.
        assert_eq!(proc_status["NSpid"], "1");
        assert_eq!(proc_status["Pid"], "1");
    }

    #[tokio::test]
    async fn mount_proc_with_readonly_fallback() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let proc = tempfile::tempdir().unwrap();
        let proc_path = proc.path().to_str().unwrap();
        let output = Command::new("sh")
            .arg("-c")
            .arg(
                "cat \"$REVERIE_PROC_PATH/mounts\"; echo __STATUS__; \
                 exec cat \"$REVERIE_PROC_PATH/self/status\"",
            )
            .env("REVERIE_PROC_PATH", proc_path)
            .map_root()
            .unshare(Namespace::PID)
            .mount(
                Mount::new(proc.path())
                    .fstype("proc")
                    .allow_readonly_fallback(),
            )
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));

        let stdout = from_utf8(&output.stdout).unwrap();
        let (mounts, status) = stdout.split_once("__STATUS__\n").unwrap();
        let proc_options = mounts
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let _source = fields.next()?;
                let target = fields.next()?;
                let fstype = fields.next()?;
                let options = fields.next()?;
                (target == proc_path && fstype == "proc").then_some(options)
            })
            .unwrap();
        assert!(
            proc_options
                .split(',')
                .any(|option| option == "ro" || option == "rw")
        );
        println!("nested_proc_options={proc_options}");

        let proc_status = parse_proc_status(status.as_bytes());
        assert_eq!(proc_status["NSpid"], "1");
        assert_eq!(proc_status["Pid"], "1");
    }

    #[tokio::test]
    async fn hostname() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/proc/sys/kernel/hostname")
            .map_root()
            .hostname("foobar.local")
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0));

        let hostname = from_utf8(&output.stdout).unwrap().trim();

        assert_eq!(hostname, "foobar.local");
    }

    #[tokio::test]
    async fn domainname() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/proc/sys/kernel/domainname")
            .map_root()
            .domainname("foobar")
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));

        let domainname = from_utf8(&output.stdout).unwrap().trim();

        assert_eq!(domainname, "foobar");
    }

    #[tokio::test]
    async fn pty() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use tokio::io::AsyncReadExt;

        let mut pty = Pty::open().unwrap();
        let pty_child = pty.child().unwrap();

        let mut tty = pty_child.terminal_params().unwrap();
        // Prevent post-processing of output so `\n` isn't translated to `\r\n`.
        tty.c_oflag &= !libc::OPOST;
        pty_child.set_terminal_params(&tty).unwrap();

        pty_child.set_window_size(40, 80).unwrap();

        // stty is in coreutils and should be available on most systems.
        let mut child = Command::new("stty")
            .arg("size")
            .pty(pty_child)
            .spawn()
            .unwrap();

        // NOTE: read_to_end returns an EIO error once the child has exited.
        let mut buf = Vec::new();
        assert!(pty.read_to_end(&mut buf).await.is_err());

        assert_eq!(from_utf8(&buf).unwrap(), "40 80\n");

        assert_eq!(child.wait().await.unwrap(), ExitStatus::SUCCESS);
    }

    #[tokio::test]
    async fn mount_devpts_basic() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("ls")
            .arg("/dev/pts")
            .map_root()
            .mount(Mount::devpts("/dev/pts"))
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));

        // Should be totally empty except for `/dev/pts/ptmx` since we mounted a
        // new devpts.
        assert_eq!(output.stderr, b"");
        assert_eq!(output.stdout, b"ptmx\n");
    }

    #[tokio::test]
    async fn mount_devpts_isolated() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("ls")
            .arg("/dev/pts")
            .map_root()
            .mount(Mount::devpts("/dev/pts").data("newinstance,ptmxmode=0666"))
            .mount(Mount::bind("/dev/pts/ptmx", "/dev/ptmx"))
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));

        // Should be totally empty except for `/dev/pts/ptmx` since we mounted a
        // new devpts.
        assert_eq!(output.stderr, b"");
        assert_eq!(output.stdout, b"ptmx\n");
    }

    #[tokio::test]
    async fn mount_tmpfs() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mount = "type=tmpfs,target=/tmp"
            .parse::<Mount>()
            .expect("tmpfs mount syntax should parse");
        let output = Command::new("ls")
            .arg("/tmp")
            .map_root()
            .mount(mount)
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));

        // Should be totally empty since we mounted a new tmpfs.
        assert_eq!(output.stderr, b"");
        assert_eq!(output.stdout, b"");
    }

    #[tokio::test]
    async fn mount_and_move_tmpfs() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let tmpfs = tempfile::tempdir().unwrap();

        // Create a temporary directory that will be the only thing to remain in
        // the `/tmp` mount.
        let persistent = tempfile::tempdir().unwrap();
        fs::write(persistent.path().join("foobar"), b"").unwrap();

        let output = Command::new("ls")
            .arg("/tmp")
            .map_root()
            .mount(Mount::tmpfs(tmpfs.path()))
            // Bind-mount a directory from our upper /tmp to our new /tmp.
            .mount(Mount::bind(persistent.path(), tmpfs.path().join("my-dir")).touch_target())
            // Move our newly-created tmpfs to hide the upper /tmp folder.
            .mount(Mount::rename(tmpfs.path(), Path::new("/tmp")))
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));

        // The only thing there should be our bind-mounted directory.
        assert_eq!(output.stderr, b"");
        assert_eq!(output.stdout, b"my-dir\n");
    }

    #[tokio::test]
    async fn mount_bind() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a");
        let b = temp.path().join("b");

        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();

        fs::write(a.join("foobar"), "im a test").unwrap();

        let output = Command::new("ls")
            .arg(&b)
            .map_root()
            .mount(Mount::bind(&a, &b))
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0));
        assert_eq!(output.stdout, b"foobar\n");
        assert_eq!(output.stderr, b"");
    }

    #[tokio::test]
    async fn mount_bind_readonly_rejects_writes() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("data"), "original").unwrap();

        let output = Command::new("sh")
            .args(["-c", "printf changed > \"$TARGET\""])
            .env("TARGET", target.join("data"))
            .map_root()
            .mount(Mount::bind(&source, &target).readonly())
            .output()
            .await
            .unwrap();

        assert_ne!(output.status, ExitStatus::Exited(0));
        assert_eq!(fs::read(source.join("data")).unwrap(), b"original");
    }

    #[tokio::test]
    async fn local_networking_ping() {
        if crate::test_runs_in_own_process() {
            return;
        }
        const CHILD_ENV: &str = "REVERIE_PROCESS_LOOPBACK_TEST_CHILD";

        if std::env::var_os(CHILD_ENV).is_some() {
            let socket = std::net::UdpSocket::bind("[::1]:0").unwrap();
            let address = socket.local_addr().unwrap();
            assert_eq!(socket.send_to(b"ping", address).unwrap(), 4);

            let mut buffer = [0; 4];
            let (length, source) = socket.recv_from(&mut buffer).unwrap();
            assert_eq!(source, address);
            assert_eq!(&buffer[..length], b"ping");
            return;
        }

        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("tests::local_networking_ping")
            .env(CHILD_ENV, "1")
            .map_root()
            .local_networking_only()
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0), "{:?}", output);
    }

    #[tokio::test]
    async fn local_networking_loopback_flags() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("cat")
            .arg("/sys/class/net/lo/flags")
            .map_root()
            .local_networking_only()
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0), "{:?}", output);
        assert_eq!(output.stdout, b"0x9\n", "{:?}", output);
    }

    /// Show that processes in two separate network namespaces can bind to the
    /// same port.
    #[tokio::test]
    async fn port_isolation() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::thread::sleep;
        use std::time::Duration;

        let mut command = Command::new("nc");
        command
            .arg("-l")
            .arg("127.0.0.1")
            // Can bind to a low port without real root inside the namespace.
            .arg("80")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .map_root()
            .local_networking_only();

        let server1 = match command.spawn() {
            // If netcat is not installed just exit successfully.
            Err(error) if error.errno() == Errno::ENOENT => return,
            other => other,
        }
        .unwrap();

        let server2 = command.spawn().unwrap();

        // Give them both time to start up.
        sleep(Duration::from_millis(100));

        // Stop them with a signal that cannot be ignored. A test binary launched
        // as a background shell job inherits SIGINT as ignored, and that
        // disposition survives exec into nc.
        server1.signal(Signal::SIGKILL).unwrap();
        server2.signal(Signal::SIGKILL).unwrap();

        let (output1, output2) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(1), server1.wait_with_output()),
            tokio::time::timeout(Duration::from_secs(1), server2.wait_with_output()),
        );
        let output1 = output1
            .expect("port_isolation: server 1 did not exit within 1 second after SIGKILL")
            .unwrap();
        let output2 = output2
            .expect("port_isolation: server 2 did not exit within 1 second after SIGKILL")
            .unwrap();

        // Without network isolation, one of the servers would exit with an
        // "Address already in use" (exit status 2) error.
        assert_eq!(
            output1.status,
            ExitStatus::Signaled(Signal::SIGKILL, false),
            "{:?}",
            output1
        );
        assert_eq!(
            output2.status,
            ExitStatus::Signaled(Signal::SIGKILL, false),
            "{:?}",
            output2
        );
    }

    /// Make sure we can call `.local_networking_only` more than once.
    #[tokio::test]
    async fn local_networking_there_can_be_only_one() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let output = Command::new("true")
            .map_root()
            .local_networking_only()
            // If calling this twice mounted /sys twice, then we'd get a "Device
            // or resource busy" error.
            .local_networking_only()
            .output()
            .await
            .unwrap();
        assert_eq!(output.status, ExitStatus::Exited(0), "{:?}", output);
        assert_eq!(output.stdout, b"", "{:?}", output);
        assert_eq!(output.stderr, b"", "{:?}", output);
    }

    #[test]
    fn from_std_lossy() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut stdcmd = std::process::Command::new("echo");
        stdcmd.args(["arg1", "arg2"]);
        stdcmd.current_dir("/foo/bar");
        stdcmd.env_clear();
        stdcmd.env("FOO", "1");
        stdcmd.env("BAR", "2");

        let cmd = Command::from_std_lossy(&stdcmd);

        assert_eq!(cmd.get_program(), "echo");
        assert_eq!(cmd.get_arg0(), "echo");
        assert_eq!(cmd.get_args().collect::<Vec<_>>(), ["arg1", "arg2"]);

        let envs = cmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?, v.and_then(|v| v.to_str()))))
            .collect::<Vec<_>>();
        assert_eq!(envs, [("BAR", Some("2")), ("FOO", Some("1"))]);
    }

    #[test]
    fn into_std_lossy_compatibility() {
        if crate::test_runs_in_own_process() {
            return;
        }
        let mut cmd = Command::new("env");
        cmd.args(["-0"]);
        cmd.current_dir("/foo/bar");
        cmd.env_clear();
        cmd.env("FOO", "1");
        cmd.env("BAR", "2");

        let stdcmd = cmd.into_std_lossy();

        assert_eq!(stdcmd.get_program(), "env");
        assert_eq!(stdcmd.get_args().collect::<Vec<_>>(), ["-0"]);

        let envs = stdcmd
            .get_envs()
            .filter_map(|(k, v)| Some((k.to_str()?, v.and_then(|v| v.to_str()))))
            .collect::<Vec<_>>();

        assert_eq!(envs, [("BAR", Some("2")), ("FOO", Some("1"))]);
    }

    #[test]
    fn try_into_std_refuses_container_configuration() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use syscalls::Sysno;

        use super::seccomp::Action;
        use super::seccomp::FilterBuilder;

        let filter = FilterBuilder::new()
            .default_action(Action::Allow)
            .syscalls([(Sysno::brk, Action::KillProcess)])
            .build();
        let mut command = Command::new("true");
        command.seccomp(filter);
        let error = command.try_into_std().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "cannot convert to std::process::Command without losing: seccomp filter"
        );

        let filter = FilterBuilder::new()
            .default_action(Action::Allow)
            .syscalls([(Sysno::brk, Action::KillProcess)])
            .build();
        let mut command = Command::new("true");
        command.seccomp(filter);
        let panic =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command.into_std_lossy()))
                .unwrap_err();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("legacy conversion panic must carry a string diagnostic");
        assert_eq!(
            message,
            "Command::into_std_lossy refused unsupported configuration: cannot convert to std::process::Command without losing: seccomp filter"
        );

        let mut command = Command::new("true");
        command.unshare(Namespace::MOUNT);
        let error = command.try_into_std().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "cannot convert to std::process::Command without losing: Linux namespaces"
        );

        let mut command = Command::new("true");
        command.container.affinity(0);
        let error = command.try_into_std().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            error.to_string(),
            "cannot convert to std::process::Command without losing: CPU affinity"
        );
    }

    #[tokio::test]
    async fn seccomp() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use syscalls::Sysno;

        use super::seccomp::*;

        let filter = FilterBuilder::new()
            .default_action(Action::Allow)
            .syscalls([(Sysno::brk, Action::KillProcess)])
            .build();

        let output = Command::new("cat")
            .arg("/proc/self/status")
            .seccomp(filter)
            .output()
            .await
            .unwrap();
        assert!(
            matches!(output.status, ExitStatus::Signaled(Signal::SIGSYS, _)),
            "Expected Signaled(SIGSYS, _), got {:?}",
            output.status
        );
    }

    /// The launcher's `execve` must reach the kernel with the argument
    /// registers that `execve` ignores (arg3..arg5: r10, r8 and r9) set to
    /// zero. A ptrace tracer records all six argument registers at the seccomp
    /// stop, so whatever the launcher's own code last left in them would
    /// otherwise enter the recorded launch as host-dependent state.
    ///
    /// A SIGSYS handler observes the registers at the `execve` instruction:
    /// the filter traps `execve`, the handler reports the three registers
    /// through a pipe, and the child exits before any exec happens. The
    /// `pre_exec` callback leaves a recognizable value in those registers, the
    /// way arbitrary launcher code can.
    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    async fn exec_zeroes_unused_argument_registers() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::sync::atomic::AtomicI32;
        use std::sync::atomic::Ordering;

        use syscalls::Sysno;

        use super::seccomp::*;

        const POISON: u64 = 0x5a5a_0000_0000_0030;
        static REPORT_FD: AtomicI32 = AtomicI32::new(-1);

        extern "C" fn on_sigsys(
            _sig: libc::c_int,
            _info: *mut libc::siginfo_t,
            ctx: *mut libc::c_void,
        ) {
            // SAFETY: SA_SIGINFO handlers receive a valid ucontext_t.
            let gregs = unsafe { &(*(ctx as *const libc::ucontext_t)).uc_mcontext.gregs };
            let words = [
                gregs[libc::REG_R10 as usize] as u64,
                gregs[libc::REG_R8 as usize] as u64,
                gregs[libc::REG_R9 as usize] as u64,
            ];
            let fd = REPORT_FD.load(Ordering::Relaxed);
            // SAFETY: write and _exit are async-signal-safe.
            unsafe {
                libc::write(fd, words.as_ptr() as *const libc::c_void, 24);
                libc::_exit(0);
            }
        }

        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (reader, writer) = (fds[0], fds[1]);
        REPORT_FD.store(writer, Ordering::Relaxed);

        let filter = FilterBuilder::new()
            .default_action(Action::Allow)
            .syscalls([(Sysno::execve, Action::Trap)])
            .build();

        let mut command = Command::new("/bin/true");
        command.seccomp(filter);
        // SAFETY: the callback only calls async-signal-safe sigaction and
        // writes registers; it does not allocate.
        unsafe {
            command.pre_exec(|| {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_sigsys as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO;
                if libc::sigaction(libc::SIGSYS, &action, std::ptr::null_mut()) != 0 {
                    return Err(Errno::last());
                }
                std::arch::asm!(
                    "mov r8, {poison}",
                    "mov r9, {poison}",
                    "mov r10, {poison}",
                    poison = in(reg) POISON,
                    out("r8") _,
                    out("r9") _,
                    out("r10") _,
                );
                Ok(())
            });
        }

        let status = command.spawn().unwrap().wait().await.unwrap();
        unsafe { libc::close(writer) };
        let mut words = [0u64; 3];
        let n = unsafe { libc::read(reader, words.as_mut_ptr() as *mut libc::c_void, 24) };
        unsafe { libc::close(reader) };

        assert_eq!(status, ExitStatus::SUCCESS);
        assert_eq!(
            n, 24,
            "the SIGSYS handler did not report the execve registers"
        );
        assert_eq!(
            words,
            [0, 0, 0],
            "execve reached the kernel with leftover launcher registers \
             [r10, r8, r9] = [{:#x}, {:#x}, {:#x}]",
            words[0],
            words[1],
            words[2],
        );
    }

    /// `Command` resolves its program the way glibc's `execvpe(3)` does: the
    /// `PATH` of the spawning process (default `/bin:/usr/bin`), an empty entry
    /// meaning the current directory, `EACCES` remembered while the search
    /// continues past `ENOENT` and `ENOTDIR`, any other error ending the
    /// search, and a script without a shebang (`ENOEXEC`) run through
    /// `/bin/sh`. The expected values are glibc's results, so this passes
    /// whether the launcher calls glibc's `execvpe` or reimplements its search.
    #[tokio::test]
    async fn exec_path_search_matches_glibc_execvpe() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;

        const NAME: &str = "reverie-exec-probe";

        // The directory holding this test binary is on a mount that allows
        // exec, which the script cases need; a temporary directory may not be.
        let exe = std::env::current_exe().unwrap();
        let scratch = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        let make_dir = |name: &str| {
            let dir = scratch.path().join(name);
            fs::create_dir(&dir).unwrap();
            dir
        };
        let empty = make_dir("empty");
        let not_executable = make_dir("not-executable");
        let script = make_dir("script");
        let symlink_loop = make_dir("symlink-loop");
        let regular_file = scratch.path().join("regular-file");
        fs::write(&regular_file, "").unwrap();

        let write_probe = |dir: &Path, mode: u32| {
            let path = dir.join(NAME);
            fs::write(&path, "exit 7\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        };
        write_probe(&not_executable, 0o644);
        // No shebang: `execve` fails with ENOEXEC and the shell runs it.
        write_probe(&script, 0o755);
        std::os::unix::fs::symlink(NAME, symlink_loop.join(NAME)).unwrap();

        // The search reads PATH from this process, not from the child's
        // environment. This test runs alone in its own process.
        let set_path = |entries: &[&Path]| {
            let value = entries
                .iter()
                .map(|entry| entry.to_str().unwrap())
                .collect::<Vec<_>>()
                .join(":");
            unsafe { std::env::set_var("PATH", value) };
        };
        let exec_error = |errno| Error::new(errno, Context::Exec);

        assert_eq!(
            Command::new("").spawn().unwrap_err(),
            exec_error(Errno::ENOENT),
            "an empty program name"
        );
        assert_eq!(
            Command::new("x".repeat(libc::NAME_MAX as usize + 1))
                .spawn()
                .unwrap_err(),
            exec_error(Errno::ENAMETOOLONG),
            "a program name longer than NAME_MAX"
        );

        set_path(&[&empty]);
        assert_eq!(
            Command::new(NAME).spawn().unwrap_err(),
            exec_error(Errno::ENOENT),
            "a program that is on no PATH entry"
        );

        set_path(&[&not_executable, &empty]);
        assert_eq!(
            Command::new(NAME).spawn().unwrap_err(),
            exec_error(Errno::EACCES),
            "EACCES from an earlier entry outranks a later ENOENT"
        );

        set_path(&[&symlink_loop, &script]);
        assert_eq!(
            Command::new(NAME).spawn().unwrap_err(),
            exec_error(Errno::ELOOP),
            "an error other than EACCES, ENOENT or ENOTDIR ends the search"
        );

        set_path(&[&not_executable, &regular_file, &script]);
        assert_eq!(
            Command::new(NAME).spawn().unwrap().wait().await.unwrap(),
            ExitStatus::Exited(7),
            "the search continues past EACCES and ENOTDIR to a script without a shebang"
        );

        set_path(&[&empty, Path::new("")]);
        assert_eq!(
            Command::new(NAME)
                .current_dir(&script)
                .spawn()
                .unwrap()
                .wait()
                .await
                .unwrap(),
            ExitStatus::Exited(7),
            "an empty PATH entry means the current directory"
        );

        assert_eq!(
            Command::new(script.join(NAME))
                .spawn()
                .unwrap()
                .wait()
                .await
                .unwrap(),
            ExitStatus::Exited(7),
            "a name containing a slash is executed without a search"
        );

        unsafe { std::env::remove_var("PATH") };
        assert_eq!(
            Command::new("true").spawn().unwrap().wait().await.unwrap(),
            ExitStatus::Exited(0),
            "an unset PATH defaults to /bin:/usr/bin"
        );
    }

    #[tokio::test]
    async fn seccomp_notify() {
        if crate::test_runs_in_own_process() {
            return;
        }
        use std::collections::HashMap;

        use futures::future::Either;
        use futures::future::select;
        use futures::stream::TryStreamExt;
        use syscalls::Sysno;

        use super::seccomp::*;

        let filter = FilterBuilder::new()
            .default_action(Action::Notify)
            .syscalls([
                // FIXME: Because the first execve happens when the child is
                // spawned, we must allow this through. Otherwise, the
                // `.spawn()` below will deadlock because we can't process
                // seccomp notifications until after it returns.
                (Sysno::execve, Action::Allow),
            ])
            .build();

        let mut child = Command::new("cat")
            .arg("/proc/self/status")
            .seccomp(filter)
            .seccomp_notify()
            .stdout(Stdio::null())
            .spawn()
            .unwrap();

        let mut summary = HashMap::new();

        let exit_status = {
            let seccomp_notif = child.seccomp_notif.take();

            let notifier = async {
                if let Some(mut notifier) = seccomp_notif {
                    while let Some(notif) = notifier.try_next().await.unwrap() {
                        *summary.entry(Sysno::from(notif.data.nr)).or_insert(0u64) += 1;

                        // Simply let the syscall through.
                        let resp = seccomp_notif_resp {
                            id: notif.id,
                            val: 0,
                            error: 0,
                            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                        };
                        notifier.send(&resp).unwrap();
                    }
                }
            };

            let exit_status = child.wait();

            futures::pin_mut!(notifier);
            futures::pin_mut!(exit_status);

            match select(notifier, exit_status).await {
                Either::Left((_, _)) => unreachable!(),
                Either::Right((exit_status, _)) => exit_status.unwrap(),
            }
        };

        assert_eq!(exit_status, ExitStatus::SUCCESS);

        assert!(summary[&Sysno::read] > 0);
        assert!(summary[&Sysno::write] > 0);
        assert!(summary[&Sysno::close] > 0);
    }
}
