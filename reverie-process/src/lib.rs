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
#![cfg_attr(feature = "nightly", feature(internal_output_capture))]
#![cfg_attr(feature = "nightly", feature(rustc_attrs))]

mod builder;
mod child;
mod clone;
mod container;
mod env;
mod error;
mod exit_status;
mod fd;
mod id_map;
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

pub use child::Child;
pub use child::Output;
pub use container::Container;
pub use container::RunError;
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

    /// This provides a *lossy* conversion to [`std::process::Command`]. The
    /// features that are not supported by [`std::process::Command`] but *are*
    /// supported by [`Command`] cannot be converted. For example, namespace and
    /// mount configurations cannot be converted since they are not supported by
    /// [`std::process::Command`].
    pub fn into_std_lossy(self) -> std::process::Command {
        let mut result = std::process::Command::new(self.get_program());
        result.args(self.get_args());

        if self.container.env.is_cleared() {
            result.env_clear();
        }

        for (key, value) in self.get_envs() {
            match value {
                Some(value) => result.env(key, value),
                None => result.env_remove(key),
            };
        }

        if let Some(dir) = self.get_current_dir() {
            result.current_dir(dir);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            result.arg0(self.get_arg0());

            for mut f in self.pre_exec {
                unsafe {
                    result.pre_exec(move || f().map_err(Into::into));
                }
            }
        }

        result.stdin(self.container.stdin);
        result.stdout(self.container.stdout);
        result.stderr(self.container.stderr);

        result
    }
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
        assert_eq!(
            Command::new("/iprobablydonotexist").spawn().unwrap_err(),
            Error::new(Errno::ENOENT, Context::Exec)
        );
    }

    #[tokio::test]
    async fn double_wait() {
        let mut child = Command::new("true").spawn().unwrap();
        assert_eq!(child.wait().await.unwrap(), ExitStatus::Exited(0));
        assert_eq!(child.wait().await.unwrap(), ExitStatus::Exited(0));
    }

    #[tokio::test]
    async fn output() {
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
                let mut items = line.splitn(2, ':');
                let first = items.next().unwrap();
                let second = items.next().unwrap();
                (first, second.trim())
            })
            .collect()
    }

    #[tokio::test]
    async fn uid_namespace() {
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
    async fn hostname() {
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
        let output = Command::new("ls")
            .arg("/tmp")
            .map_root()
            .mount(Mount::tmpfs("/tmp"))
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
            .mount(Mount::bind(persistent.path(), &tmpfs.path().join("my-dir")).touch_target())
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
    async fn local_networking_ping() {
        let output = Command::new("ping")
            .arg("-c1")
            .arg("::1")
            .map_root()
            .local_networking_only()
            .output()
            .await
            .unwrap();

        assert_eq!(output.status, ExitStatus::Exited(0), "{:?}", output);
    }

    #[tokio::test]
    async fn local_networking_loopback_flags() {
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

        // Signal them to shut down. Otherwise, they will wait forever for a
        // connection that will never come.
        server1.signal(Signal::SIGINT).unwrap();
        server2.signal(Signal::SIGINT).unwrap();

        let output1 = server1.wait_with_output().await.unwrap();
        let output2 = server2.wait_with_output().await.unwrap();

        // Without network isolation, one of the servers would exit with an
        // "Address already in use" (exit status 2) error.
        assert_eq!(
            output1.status,
            ExitStatus::Signaled(Signal::SIGINT, false),
            "{:?}",
            output1
        );
        assert_eq!(
            output2.status,
            ExitStatus::Signaled(Signal::SIGINT, false),
            "{:?}",
            output2
        );
    }

    /// Make sure we can call `.local_networking_only` more than once.
    #[tokio::test]
    async fn local_networking_there_can_be_only_one() {
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
    fn into_std_lossy() {
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

    #[tokio::test]
    async fn seccomp() {
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
        assert_eq!(
            output.status,
            ExitStatus::Signaled(Signal::SIGSYS, true),
            "{:?}",
            output
        );
    }

    #[tokio::test]
    async fn seccomp_notify() {
        use std::collections::HashMap;

        use futures::future::select;
        use futures::future::Either;
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
