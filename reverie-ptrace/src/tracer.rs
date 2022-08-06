/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Tracer` type, plus ways to spawn it and retrieve its output.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use futures::future;
use futures::future::BoxFuture;
use futures::future::Either;
use futures::stream::StreamExt;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::unistd;
use nix::unistd::ForkResult;
use reverie::process::seccomp;
use reverie::process::ChildStderr;
use reverie::process::ChildStdin;
use reverie::process::ChildStdout;
use reverie::process::Command;
use reverie::process::Output;
use reverie::syscalls::Sysno;
use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::cp;
use crate::gdbstub::GdbServer;
use crate::task::Child;
use crate::task::TracedTask;
use crate::trace;
use crate::trace::Error as TraceError;
use crate::trace::Event;
use crate::trace::Running;
use crate::trace::Stopped;

/// Represents the tracer.
///
/// We need to simultaneously capture stderr/stdout while handling events. These
/// can be two separate futures. The stderr/stdout future will finish when the
/// pipes are closed.
///
/// The stderr/stdout capture can be a `Stream<Item = Either<Bytes, Bytes>>`
/// where each item is either a chunk of stderr bytes or stdout bytes. Zipping
/// together the two streams like this preserves ordering.
pub struct Tracer<G> {
    /// PID of the root guest process.
    guest_pid: Pid,

    // Future of the running handler.
    tracer: BoxFuture<'static, Result<ExitStatus, Error>>,

    // A reference to the global state.
    gref: Arc<G>,

    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl<G: Default> Tracer<G> {
    /// Returns the PID of the root guest process.
    pub fn guest_pid(&self) -> Pid {
        self.guest_pid
    }

    /// Simultaneously waits for the tracee to exit and collect all remaining
    /// output on the stdout/stderr handles, returning an `Output` instance.
    ///
    /// The stdin handle to the child process, if any, will be closed before
    /// waiting. This helps avoid deadlock: it ensures that the child does not
    /// block waiting for input from the parent, while the parent waits for the
    /// child to exit.
    ///
    /// By default, stdin, stdout and stderr are inherited from the parent. In
    /// order to capture the output it is necessary to create new pipes between
    /// parent and child. Use `stdout(Stdio::piped())` or
    /// `stderr(Stdio::piped())`, respectively.
    pub async fn wait_with_output(mut self) -> Result<(Output, G), Error> {
        use tokio::io::AsyncRead;
        use tokio::io::AsyncReadExt;

        async fn read_to_end<A: AsyncRead + Unpin>(io: Option<A>) -> Result<Vec<u8>, Error> {
            let mut vec = Vec::new();
            if let Some(mut io) = io {
                io.read_to_end(&mut vec).await?;
            }
            Ok(vec)
        }

        drop(self.stdin.take());

        let stdout = read_to_end(self.stdout.take());
        let stderr = read_to_end(self.stderr.take());

        let ((status, state), stdout, stderr) =
            future::try_join3(self.wait(), stdout, stderr).await?;

        Ok((
            Output {
                status,
                stdout,
                stderr,
            },
            state,
        ))
    }

    /// Waits for the tracee to exit and returns its exit status and global
    /// state.
    pub async fn wait(self) -> Result<(ExitStatus, G), Error> {
        // Note: The usage of LocalSet is *very* important here. Once polled,
        // the `tracer` future drives all tracees to completion. The `fork` for
        // the root tracee and all subsequent ptrace operations *MUST* be done
        // on the same thread. Thus, we use `LocalSet` in combination with
        // `tokio::task::spawn_local` to ensure that everything happens on the
        // same thread. Otherwise, ptrace operations will start returning
        // `ESRCH` errors and they will be (incorrectly) interpretted to mean
        // that the tracee has died unexpectedly.
        let local_set = tokio::task::LocalSet::new();
        let exit_status = local_set.run_until(self.tracer).await?;

        let g = Arc::try_unwrap(self.gref).unwrap_or_else(|_| {
            panic!("Reverie internal invariant broken. Arc::try_unwrap on global state failed.")
        });

        Ok((exit_status, g))
    }
}

fn from_nix_error(err: nix::Error) -> Errno {
    Errno::new(err as i32)
}

/// Sets up the child process for ptracing right before execve is called.
fn init_tracee(intercept_rdtsc: bool) -> Result<(), Errno> {
    // NOTE: There should be *NO* allocations along the happy path here.
    // Allocating between a fork() and execve() can cause deadlocks in glibc
    // when using jemalloc.

    // hardcoded because `libc` does not export these.
    const PER_LINUX: u64 = 0x0;
    const ADDR_NO_RANDOMIZE: u64 = 0x0004_0000;

    if intercept_rdtsc {
        unsafe {
            assert_eq!(
                libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV, 0, 0, 0),
                0
            )
        };
    }

    unsafe {
        assert!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert!(libc::personality(PER_LINUX | ADDR_NO_RANDOMIZE) != -1);
    }

    // FIXME: This is a hacky workaround for `std::process::Command::spawn`
    // getting stuck in a deadlock because of the SIGSTOP below.
    // `Command::spawn` uses a pipe to communicate the error code to the parent
    // process if the `execve` fails. The idea is that the write end of the pipe
    // will be closed upon a successful call to `execve` and the parent will
    // abort the blocking read on the read end of the pipe. We don't know
    // exactly which file descriptor the pipe uses, so we attempt to close the
    // first N file descriptors hoping it is among those. Unfortunately, in
    // doing so, we lose the ability to capture `execve` failures.
    //
    // There are a couple options for a better implementation:
    //  1. Recreate the entire `std::process` module to provide better ptrace
    //     support. (A lot of work!)
    //  2. Don't raise a SIGSTOP, but instead let the ptracer stop on the call to
    //     `execve` and have the parent set the ptrace options at that point.
    for i in 3..256 {
        unsafe {
            libc::close(i);
        }
    }

    trace::traceme_and_stop()?;

    unsafe {
        signal::sigaction(
            signal::SIGTTIN,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::SA_RESTART,
                signal::SigSet::empty(),
            ),
        )
        .map_err(from_nix_error)?;

        signal::sigaction(
            signal::SIGTTOU,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::SA_RESTART,
                signal::SigSet::empty(),
            ),
        )
        .map_err(from_nix_error)?;
    }

    Ok(())
}

async fn run_orphaned(orphans: mpsc::Receiver<Child>) {
    tokio_stream::wrappers::ReceiverStream::new(orphans)
        .for_each_concurrent(None, |orphan| async {
            let pid = orphan.id();
            let mut daemonizer = orphan.daemonizer_rx.unwrap();

            let daemonizer = daemonizer.recv();
            futures::pin_mut!(daemonizer);

            match future::select(Box::pin(orphan.handle), daemonizer).await {
                Either::Left((exit_status, _)) => {
                    tracing::debug!(
                        "[reverie] Orphan {} exited with status {:?}",
                        pid,
                        exit_status
                    );
                }
                Either::Right((kill_switch, handle)) => {
                    tracing::debug!("[reverie] pid {} daemonized", pid);
                    if let Some(mut kill_switch) = kill_switch {
                        let kill_switch = kill_switch.recv();
                        futures::pin_mut!(kill_switch);
                        match future::select(Box::pin(handle), kill_switch).await {
                            Either::Left((exit_status, _)) => {
                                tracing::debug!(
                                    "[reverie] Daemon {} exited with status {:?}",
                                    pid,
                                    exit_status
                                );
                            }
                            Either::Right((_, handle)) => {
                                tracing::debug!("sending sigkill {}", pid);
                                unsafe {
                                    libc::kill(pid.as_raw(), libc::SIGKILL);
                                }
                                let status = handle.await;
                                tracing::debug!(
                                    "[reverie] Daemon {} exited with status {:?}",
                                    pid,
                                    status
                                );
                            }
                        }
                    }
                }
            }
        })
        .await;
}

/// Runs the task tree to completion and returns the exit status of the root
/// task.
async fn run_task_tree<T: Tool + 'static>(
    root: TracedTask<T>,
    child: Stopped,
    orphanage: mpsc::Receiver<Child>,
) -> Result<ExitStatus, Error> {
    future::join(
        // Run the root task to completion
        root.run(child),
        // ...and wait for all orphans simultaneously.
        run_orphaned(orphanage),
    )
    .await
    .0
}

/// Helper function for everything after the child is spawned.
async fn postspawn<L: Tool + 'static>(
    child: Running,
    gref: Arc<L::GlobalState>,
    config: <L::GlobalState as GlobalTool>::Config,
    events: &Subscription,
    gdbserver: Option<GdbServer>,
) -> Result<BoxFuture<'static, Result<ExitStatus, Error>>, TraceError> {
    let pid = child.pid();

    // Wait for the child to enter a stopped state. The child will enter a
    // stopped state immediately after ptrace::traceme is called.
    //
    // NOTE: We may rarely get spurious signals here, like SIGWINCH, so we must
    // skip past them.
    let (mut child, event) = child
        .wait_for_signal(Signal::SIGSTOP)
        .await?
        .assume_stopped();
    assert_eq!(event, Event::Signal(Signal::SIGSTOP));

    child.setoptions(
        ptrace::Options::PTRACE_O_TRACEEXEC
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK
            | ptrace::Options::PTRACE_O_TRACEVFORKDONE
            | ptrace::Options::PTRACE_O_TRACEEXIT
            | ptrace::Options::PTRACE_O_TRACESECCOMP
            | ptrace::Options::PTRACE_O_TRACESYSGOOD,
    )?;

    let (orphan_sender, orphan_receiver) = mpsc::channel(1);
    let (daemon_kill, _) = broadcast::channel(1);

    // This is the root task, so there's no reason to make run its init routine
    // asynchronously, as there isn't any other work to do.
    let mut tracer = TracedTask::<L>::new(
        pid,
        config,
        gref,
        events,
        orphan_sender,
        daemon_kill,
        gdbserver,
    );

    child = tracer.tracee_preinit(child).await?;

    let tracer = Box::pin(run_task_tree(tracer, child, orphan_receiver));
    Ok(tracer)
}

/// Creates the seccomp filter. This lets us control which syscalls are traced
/// and which ones are allowed through.
fn seccomp_filter(events: &Subscription) -> seccomp::Filter {
    use reverie::process::seccomp::Action;

    seccomp::FilterBuilder::new()
        // By default, all syscalls are allowed through untraced. Then, we can
        // intercept only the syscalls we are interested in.
        .default_action(Action::Allow)
        .syscalls(
            events
                .iter_syscalls()
                .map(|syscall| (syscall, Action::Trace(0))),
        )
        // Always allow these syscalls to pass through untraced.
        .syscall(Sysno::restart_syscall, Action::Allow)
        .syscall(Sysno::rt_sigreturn, Action::Allow)
        // Allow untraced syscalls through without tracing them.
        // NOTE: 2 is the length of a syscall instruction (0x0f 0x05) and we
        // want to allow the ud2 instruction immediately following it.
        .ip_range(
            cp::TRAMPOLINE_BASE + 2,
            cp::TRAMPOLINE_BASE + 3,
            Action::Allow,
        )
        .build()
}

/// Specifies *how* the GDB server should listen for incoming connections.
pub enum GdbConnection {
    /// The server shall bind to and listen on the given socket address.
    Addr(SocketAddr),

    /// The server shall bind to and listen on the given unix domain socket. This
    /// path must not exist, otherwise the bind will fail with `EADDRINUSE`.
    Path(PathBuf),
}

impl From<SocketAddr> for GdbConnection {
    fn from(addr: SocketAddr) -> Self {
        Self::Addr(addr)
    }
}

impl From<PathBuf> for GdbConnection {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl From<u16> for GdbConnection {
    fn from(port: u16) -> Self {
        Self::Addr(([127, 0, 0, 1], port).into())
    }
}

/// A builder for creating a tracer.
pub struct TracerBuilder<T: Tool + 'static> {
    /// The program to execute that will be traced.
    command: Command,

    /// The global state static config.
    config: Option<<T::GlobalState as GlobalTool>::Config>,

    /// Set to `Some` if we should spawn a GDB server.
    gdbserver: Option<GdbConnection>,

    /// Indicates that the guest's scheduling will be serialized by the Reverie
    /// tool. This is only relevant for the GDB server.
    sequentialized_guest: bool,
}

impl<T: Tool + 'static> TracerBuilder<T> {
    /// Creates the builder with the given command.
    pub fn new(command: Command) -> Self {
        Self {
            command,
            config: None,
            gdbserver: None,
            sequentialized_guest: false,
        }
    }

    /// Returns a reference to the command to be traced.
    pub fn command(&self) -> &Command {
        &self.command
    }

    /// Sets the static configuration that will be made available to the tool.
    pub fn config(mut self, config: <T::GlobalState as GlobalTool>::Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Configures the tracer to create a GDB server and listen for incoming
    /// connections. The tracer will start in a stopped state and will not
    /// proceed until a connection is made. This allows the GDB client to observe
    /// the full execution of the guest.
    pub fn gdbserver<C: Into<GdbConnection>>(mut self, connection: C) -> Self {
        self.gdbserver = Some(connection.into());
        self
    }

    /// Make the GDB server aware that guest threads are sequentialized. This is
    /// needed when the Reverie tool has full control of scheduling and already
    /// sequentializes thread execution. This helps avoid deadlocks.
    pub fn sequentialized_guest(mut self) -> Self {
        self.sequentialized_guest = true;
        self
    }

    /// Spawns the tracer.
    pub async fn spawn(self) -> Result<Tracer<T::GlobalState>, Error> {
        let mut command = self.command;
        let config = self.config.unwrap_or_default();

        // Because this ptrace backend is CENTRALIZED, it can keep all the
        // tool's state here in a single address space.
        let global_state = <T::GlobalState as GlobalTool>::init_global_state(&config).await;
        let events = T::subscriptions(&config);
        let gref = Arc::new(global_state);

        // Get the full path to the program and change the command to use it. This
        // also checks that the path exists and provides an early exit just in case
        // it doesn't.
        //
        // Normally, we'd rely upon the `exit(1)` following a failed call to
        // `execve`, but that is tricky when ptracing the `execve` call.
        let program = command
            .find_program()
            .with_context(|| format!("Could not execute {:?}", command.get_program()))?;
        command.program(program);

        // Disable sanitizers that use ptrace from running on tracer.
        command.env("LSAN_OPTIONS", "detect_leaks=0");
        command.env("ASAN_OPTIONS", "detect_leaks=0");

        let intercept_rdtsc = events.has_rdtsc();
        unsafe {
            command.pre_exec(move || init_tracee(intercept_rdtsc));
        }

        command.seccomp(seccomp_filter(&events));

        let mut child = command.spawn().context("Failed to spawn tracee")?;
        let guest_pid = child.id();
        let running_child = Running::new(guest_pid);

        // Configure the gdb server (if any).
        let gdbserver = match self.gdbserver {
            None => None,
            Some(connection) => {
                let server = match connection {
                    GdbConnection::Addr(addr) => GdbServer::from_addr(addr).await,
                    GdbConnection::Path(path) => GdbServer::from_path(&path).await,
                };

                // FIXME: Don't panic. Return an error here instead.
                let mut server = server.unwrap();

                if self.sequentialized_guest {
                    server.sequentialized_guest();
                }

                Some(server)
            }
        };

        let tracer =
            match postspawn::<T>(running_child, gref.clone(), config, &events, gdbserver).await {
                Ok(tracer) => tracer,
                Err(TraceError::Errno(err)) => return Err(Error::Errno(err)),
                Err(TraceError::Died(zombie)) => panic!(
                    "tracee {} died unexpectedly during initialization",
                    zombie.pid()
                ),
            };

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        // Don't let the drop logic run for the child. Tokio will add the child to a
        // "orphan queue" that will try to call `waitpid` on the process when a
        // `SIGCHLD` signal is received. This interferes with our own process
        // handling where we need full control over the lifetime of the child
        // process.
        core::mem::forget(child);

        Ok(Tracer {
            guest_pid,
            tracer,
            gref,
            stdin,
            stdout,
            stderr,
        })
    }
}

/// Spawn a *function* to be executed under instrumentation instrumentation
/// (rather than a subprocess indicated with a Command).
///
/// This still creates a fresh child process and runs it under ptrace. However,
/// the child process is a fork of the current process, and is used to run the
/// indicated function.
pub async fn spawn_fn<L, F>(fun: F) -> Result<Tracer<L::GlobalState>, Error>
where
    L: Tool + 'static,
    F: FnOnce(),
{
    spawn_fn_with_config::<L, F>(fun, Default::default(), true).await
}

/// Spawn a function with instrumentation rather than a subprocess indicated with
/// a Command. This still creates a fresh child process and runs it under ptrace.
/// However, the child process is a fork of the current process, and is used to
/// run the indicated function.
///
/// The main use case for this entrypoint into the library is testing.
pub async fn spawn_fn_with_config<L, F>(
    fun: F,
    config: <L::GlobalState as GlobalTool>::Config,
    capture_output: bool,
) -> Result<Tracer<L::GlobalState>, Error>
where
    L: Tool + 'static,
    F: FnOnce(),
{
    use std::os::unix::io::FromRawFd;

    // Because this ptrace backend is CENTRALIZED, it can keep all the
    // tool's state here in a single address space.
    let global_state = <L::GlobalState as GlobalTool>::init_global_state(&config).await;
    let events = L::subscriptions(&config);
    let gref = Arc::new(global_state);

    let seccomp_filter = seccomp_filter(&events);

    let (read1, write1) = unistd::pipe().map_err(from_nix_error)?;
    let (read2, write2) = unistd::pipe().map_err(from_nix_error)?;

    // Disable io redirection just before forking. We want the child process to
    // be able to call `println!()` and have that output go to stdout.
    //
    // See: https://github.com/rust-lang/rust/issues/35136
    let output_capture = std::io::set_output_capture(None);

    // Warning: fork is wildely unsafe in Rust because of runtime issues (printing,
    // panicking, etc).  We make a best-effort attempt to solve some of these issues.
    match unsafe { unistd::fork() }.expect("unistd::fork failed") {
        ForkResult::Child => {
            unistd::close(read1)
                .and_then(|_| unistd::close(read2))
                .map_err(from_nix_error)?;
            if capture_output {
                unistd::dup2(write1, 1)
                    .and_then(|_| unistd::dup2(write2, 2))
                    .and_then(|_| unistd::close(write1))
                    .and_then(|_| unistd::close(write2))
                    .map_err(from_nix_error)?;
            }

            init_tracee(events.has_rdtsc()).expect("init_tracee failed");

            seccomp_filter.load().expect("Failed to set seccomp filter");

            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(fun)) {
                Ok(()) => {
                    std::io::stdout().flush()?;
                    std::process::exit(0);
                }
                Err(e) => {
                    std::io::stdout().flush()?;
                    let _ = nix::unistd::write(
                        2,
                        format!("Forked Rust process panicked, cause: {:?}", e).as_ref(),
                    );
                    std::process::exit(1);
                }
            };
        }
        ForkResult::Parent { child } => {
            std::io::set_output_capture(output_capture);

            let guest_pid = Pid::from(child);
            let child = Running::new(guest_pid);
            unistd::close(write1)
                .and_then(|_| unistd::close(write2))
                .map_err(from_nix_error)
                .unwrap();

            let stdout = unsafe { ChildStdout::from_raw_fd(read1) };
            let stderr = unsafe { ChildStderr::from_raw_fd(read2) };
            let tracer = match postspawn::<L>(child, gref.clone(), config, &events, None).await {
                Ok(tracer) => tracer,
                Err(TraceError::Errno(err)) => return Err(Error::Errno(err)),
                Err(TraceError::Died(zombie)) => panic!(
                    "tracee {} died unexpectedly during initialization",
                    zombie.pid()
                ),
            };

            Ok(Tracer {
                guest_pid,
                tracer,
                gref,
                stdin: None,
                stdout: Some(stdout),
                stderr: Some(stderr),
            })
        }
    }
}
