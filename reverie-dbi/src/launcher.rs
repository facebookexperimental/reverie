/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::process::Output;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use reverie::GlobalTool;
use reverie_rpc_transport::RpcServer;

const CLIENT_ENV: &str = "REVERIE_DBI_CLIENT";
const DYNAMORIO_ENV: &str = "DYNAMORIO_HOME";
const DYNAMORIO_DIR_ENV: &str = "DynamoRIO_DIR";
const SUMMARY_ENV: &str = "REVERIE_DBI_SUMMARY";
const PATH_ENV: &str = "PATH";
const BINPRM_BUF_SIZE: usize = 256;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#90): Confirm the reserved descriptor across followed execs.
// Keep client diagnostics on launcher stderr across guest fd 2 redirects and execs.
const DIAGNOSTIC_FD: libc::c_int = 198;

// TODO-HUMAN-REVIEW(PR-134): Review the native bootstrap failure ABI.
/// Exit code used when DynamoRIO cannot start the sideline runtime thread before guest code runs.
pub const CLIENT_THREAD_START_FAILURE_EXIT_CODE: i32 = 125;

/// Launches Linux programs under the Reverie DynamoRIO client.
///
/// The native client is built separately by
/// `reverie-dbi/scripts/build-client.sh`. Set [`REVERIE_DBI_CLIENT`] to that
/// script's output, or build it in this Reverie workspace's default target
/// directory. [`DYNAMORIO_HOME`] must identify a built DynamoRIO source tree,
/// build directory, or install directory. Set `REVERIE_DBI_SUMMARY=1` to print
/// instrumentation totals after the guest exits.
///
/// [`REVERIE_DBI_CLIENT`]: https://github.com/rrnewton/reverie/tree/main/reverie-dbi
/// [`DYNAMORIO_HOME`]: https://dynamorio.org/page_deploy.html
#[derive(Clone, Debug)]
pub struct DbiRunner {
    drrun: PathBuf,
    client: PathBuf,
    client_arguments: Vec<OsString>,
    summary: bool,
    isolated_process_group: bool,
    terminate_process_group_on_exit: bool,
}

impl DbiRunner {
    /// Resolves DynamoRIO and the Reverie DBI client from the environment.
    pub fn from_env() -> io::Result<Self> {
        let dynamorio_home = env::var_os(DYNAMORIO_ENV)
            .or_else(|| env::var_os(DYNAMORIO_DIR_ENV))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "DYNAMORIO_HOME or DynamoRIO_DIR is not set; point one to a built DynamoRIO tree",
                )
            })?;
        let drrun = resolve_drrun(Path::new(&dynamorio_home))?;
        let client = resolve_client()?;
        let mut runner = Self::new(drrun, client)?;
        runner.summary = env::var_os(SUMMARY_ENV).is_some_and(|value| {
            !value.is_empty() && value != OsStr::new("0") && value != OsStr::new("false")
        });
        Ok(runner)
    }

    /// Creates a runner from explicit `drrun` and native-client paths.
    pub fn new(drrun: impl Into<PathBuf>, client: impl Into<PathBuf>) -> io::Result<Self> {
        let drrun = drrun.into();
        let client = client.into();
        require_file(&drrun, "DynamoRIO launcher")?;
        require_file(&client, "Reverie DBI client")?;
        Ok(Self {
            drrun,
            client,
            client_arguments: Vec::new(),
            summary: false,
            isolated_process_group: false,
            terminate_process_group_on_exit: false,
        })
    }

    /// Enables or disables the instrumentation summary written at process exit.
    pub fn summary(mut self, enabled: bool) -> Self {
        self.summary = enabled;
        self
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-84): Review persistent DynamoRIO client argument propagation.
    /// Adds an argument passed to the native client in every instrumented process image.
    pub fn client_argument(mut self, argument: impl Into<OsString>) -> Self {
        self.client_arguments.push(argument.into());
        self
    }

    /// Runs the DynamoRIO launcher in a new process group when enabled.
    ///
    /// This lets a Tool terminate the complete instrumented process tree without signaling
    /// the launcher's caller.
    pub fn isolated_process_group(mut self, enabled: bool) -> Self {
        self.isolated_process_group = enabled;
        self
    }

    /// Places the launcher in a new process group and terminates any residual
    /// descendants after the root process exits.
    ///
    /// Unlike [`Self::isolated_process_group`], this does not ask the DBI client
    /// to reject guest process-group mutations. It is intended for backends that
    /// must drain followed DynamoRIO children without changing non-strict guest
    /// syscall behavior.
    pub fn terminate_process_group_on_exit(mut self, enabled: bool) -> Self {
        self.terminate_process_group_on_exit = enabled;
        self
    }

    /// Runs `guest` with inherited standard streams and waits for it to exit.
    pub fn status(&self, guest: &Command) -> io::Result<ExitStatus> {
        let child = self.command(guest, None).spawn()?;
        self.wait_for_status(child)
    }

    /// Runs `guest` with an exact environment instead of inheriting the launcher environment.
    pub fn status_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<ExitStatus> {
        let child = self.command(guest, Some(environment)).spawn()?;
        self.wait_for_status(child)
    }

    /// Runs `guest` and captures its standard output and standard error.
    pub fn output(&self, guest: &Command) -> io::Result<Output> {
        let child = self
            .command(guest, None)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        self.wait_with_output(child)
    }

    /// Captures guest output while preserving an inherited terminal stdin.
    pub fn output_with_inherited_stdin(&self, guest: &Command) -> io::Result<Output> {
        let child = self
            .command(guest, None)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        self.wait_with_output(child)
    }

    /// Runs `guest` with captured output and supplies `input` on standard input.
    pub fn output_with_input(&self, guest: &Command, input: &[u8]) -> io::Result<Output> {
        self.output_with_reader(guest, io::Cursor::new(input))
    }

    /// Runs `guest` with captured output while streaming its standard input.
    pub fn output_with_reader<R>(&self, guest: &Command, mut input: R) -> io::Result<Output>
    where
        R: Read + Send,
    {
        let mut child = self
            .command(guest, None)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBI guest stdin")
        })?;

        std::thread::scope(|scope| {
            let writer = scope.spawn(move || io::copy(&mut input, &mut stdin));
            let output = self.wait_with_output(child);
            let write_result = writer
                .join()
                .map_err(|_| io::Error::other("DBI guest stdin writer thread panicked"))?;
            if let Err(error) = write_result
                && error.kind() != io::ErrorKind::BrokenPipe
            {
                return Err(error);
            }
            output
        })
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-84): Review the owned, detachable input-pump API.
    /// Streams owned standard input without waiting for a source-blocked pump after child exit.
    ///
    /// A pump still blocked on its source is detached until that source unblocks or the caller exits.
    pub fn output_with_detached_reader<R>(&self, guest: &Command, input: R) -> io::Result<Output>
    where
        R: Read + Send + 'static,
    {
        let child = self
            .command(guest, None)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        self.wait_with_output_and_detached_reader(child, input)
    }

    /// Captures `guest` output while supplying an exact guest environment.
    pub fn output_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Output> {
        let child = self
            .command(guest, Some(environment))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        self.wait_with_output(child)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review typed DBI coordinator lifecycle.
    /// Runs `guest` while one coordinator-owned global serves every DBI process.
    ///
    /// The coordinator socket is inherited across fork and exec. Each process's
    /// [`reverie::GlobalRPC`] requests therefore reach the single returned
    /// global instead of a process-local fallback.
    pub async fn output_with_global<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(Output, G)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(guest, None, config, true, CoordinatedInput::Null)
            .await?
        {
            CoordinatedWait::Output(output, global) => Ok((output, global)),
            CoordinatedWait::Status(_, _) => unreachable!("output launch returned only status"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review exact-environment DBI coordinator launch.
    /// Runs `guest` with captured output, one shared global, and an exact environment.
    pub async fn output_with_environment_and_global<G>(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
        config: G::Config,
    ) -> io::Result<(Output, G)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(
                guest,
                Some(environment),
                config,
                true,
                CoordinatedInput::Null,
            )
            .await?
        {
            CoordinatedWait::Output(output, global) => Ok((output, global)),
            CoordinatedWait::Status(_, _) => unreachable!("output launch returned only status"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-247): Review coordinated owned-input pumping.
    /// Runs `guest` with captured output, replayable input, and one shared global.
    pub async fn output_with_detached_reader_and_global<G, R>(
        &self,
        guest: &Command,
        input: R,
        config: G::Config,
    ) -> io::Result<(Output, G)>
    where
        G: GlobalTool + 'static,
        R: Read + Send + 'static,
    {
        match self
            .run_with_global::<G>(
                guest,
                None,
                config,
                true,
                CoordinatedInput::Reader(Box::new(input)),
            )
            .await?
        {
            CoordinatedWait::Output(output, global) => Ok((output, global)),
            CoordinatedWait::Status(_, _) => unreachable!("output launch returned only status"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-247): Review coordinated inherited-stdin capture.
    /// Runs `guest` with captured output, inherited stdin, and one shared global.
    pub async fn output_with_inherited_stdin_and_global<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(Output, G)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(guest, None, config, true, CoordinatedInput::Inherit)
            .await?
        {
            CoordinatedWait::Output(output, global) => Ok((output, global)),
            CoordinatedWait::Status(_, _) => unreachable!("output launch returned only status"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review inherited-stdio DBI coordinator launch.
    /// Runs `guest` with inherited streams while one coordinator owns its global state.
    pub async fn status_with_global<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(ExitStatus, G)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(guest, None, config, false, CoordinatedInput::Inherit)
            .await?
        {
            CoordinatedWait::Status(status, global) => Ok((status, global)),
            CoordinatedWait::Output(_, _) => unreachable!("status launch captured output"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review exact-environment DBI status launch.
    /// Runs `guest` with one shared global and an exact environment.
    pub async fn status_with_environment_and_global<G>(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
        config: G::Config,
    ) -> io::Result<(ExitStatus, G)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(
                guest,
                Some(environment),
                config,
                false,
                CoordinatedInput::Inherit,
            )
            .await?
        {
            CoordinatedWait::Status(status, global) => Ok((status, global)),
            CoordinatedWait::Output(_, _) => unreachable!("status launch captured output"),
        }
    }

    async fn run_with_global<G>(
        &self,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
        config: G::Config,
        capture_output: bool,
        input: CoordinatedInput,
    ) -> io::Result<CoordinatedWait<G>>
    where
        G: GlobalTool + 'static,
    {
        let directory = tempfile::Builder::new().prefix("reverie-dbi-").tempdir()?;
        let socket = directory.path().join("coordinator.sock");
        let mut global = Arc::new(G::init_global_state(&config).await);
        let connected = Arc::new(AtomicBool::new(false));
        let server = RpcServer::bind_with_connection_readiness(
            &socket,
            Arc::clone(&global),
            config,
            Arc::clone(&connected),
        )
        .map_err(|error| io::Error::other(error.to_string()))?;

        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-247): Review native external-global capability propagation.
        // The root records this explicit capability in shared state before any
        // fork. Copied DynamoRIO runtimes cannot reliably re-read Rust's
        // process environment after fork.
        let runner = self.clone().client_argument("-external-global");
        let mut command = runner.command(guest, environment);
        command.env(crate::sync_rpc::RPC_SOCKET_ENV, &socket);
        match &input {
            CoordinatedInput::Null => {
                command.stdin(Stdio::null());
            }
            CoordinatedInput::Inherit => {
                command.stdin(Stdio::inherit());
            }
            CoordinatedInput::Reader(_) => {
                command.stdin(Stdio::piped());
            }
        }
        if capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let child = command.spawn()?;
        let wait = tokio::task::spawn_blocking(move || match input {
            CoordinatedInput::Reader(input) => runner
                .wait_with_output_and_detached_reader(child, input)
                .map(ChildWait::Output),
            CoordinatedInput::Null | CoordinatedInput::Inherit if capture_output => {
                runner.wait_with_output(child).map(ChildWait::Output)
            }
            CoordinatedInput::Null | CoordinatedInput::Inherit => {
                runner.wait_for_status(child).map(ChildWait::Status)
            }
        });
        let wait = serve_rpc_until(server, async move {
            wait.await
                .map_err(|error| io::Error::other(error.to_string()))?
        })
        .await?;
        if !connected.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DBI guest exited before connecting to the global-state coordinator",
            ));
        }
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-247): Review bounded coordinator-owner drain.
        // Aborting the server drops its connection JoinSet, but Tokio may not
        // poll those cancellations before the outer server task completes.
        // Give cancelled connection futures time to release their Arc<G>.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
        let global = loop {
            match Arc::try_unwrap(global) {
                Ok(global) => break global,
                Err(still_owned) if tokio::time::Instant::now() < deadline => {
                    global = still_owned;
                    tokio::task::yield_now().await;
                }
                Err(still_owned) => {
                    return Err(io::Error::other(format!(
                        "DBI coordinator state still has {} owners after shutdown",
                        Arc::strong_count(&still_owned)
                    )));
                }
            }
        };
        Ok(match wait {
            ChildWait::Status(status) => CoordinatedWait::Status(status, global),
            ChildWait::Output(output) => CoordinatedWait::Output(output, global),
        })
    }

    fn wait_for_status(&self, mut child: Child) -> io::Result<ExitStatus> {
        if !self.manages_process_group() {
            return child.wait();
        }

        let process_group = child.id() as i32;
        let observed = wait_for_exit_without_reaping(child.id());
        let terminated = match observed {
            Ok(()) => terminate_process_group(process_group),
            Err(_) => Ok(()),
        };
        let status = child.wait();

        observed?;
        terminated?;
        status
    }

    fn wait_with_output(&self, mut child: Child) -> io::Result<Output> {
        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                self.terminate_and_reap(&mut child);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed to capture DBI guest stdout",
                ));
            }
        };
        let mut stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                self.terminate_and_reap(&mut child);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed to capture DBI guest stderr",
                ));
            }
        };

        if let Err(error) = set_nonblocking(&stdout).and_then(|_| set_nonblocking(&stderr)) {
            self.terminate_and_reap(&mut child);
            return Err(error);
        }

        std::thread::scope(|scope| {
            let cancelled = Arc::new(AtomicBool::new(false));
            let stdout_cancelled = Arc::clone(&cancelled);
            let stderr_cancelled = Arc::clone(&cancelled);
            let stdout_reader =
                scope.spawn(move || read_cancellable(&mut stdout, &stdout_cancelled));
            let stderr_reader =
                scope.spawn(move || read_cancellable(&mut stderr, &stderr_cancelled));
            let status = self.wait_for_status(child);
            if status.is_err() {
                cancelled.store(true, Ordering::Release);
            }
            let stdout = stdout_reader
                .join()
                .map_err(|_| io::Error::other("DBI stdout reader thread panicked"));
            let stderr = stderr_reader
                .join()
                .map_err(|_| io::Error::other("DBI stderr reader thread panicked"));

            Ok(Output {
                status: status?,
                stdout: stdout??,
                stderr: stderr??,
            })
        })
    }

    fn wait_with_output_and_detached_reader<R>(
        &self,
        mut child: Child,
        mut input: R,
    ) -> io::Result<Output>
    where
        R: Read + Send + 'static,
    {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBI guest stdin")
        })?;

        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-84): Review detaching a source-blocked input pump at child exit.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = sender.send(io::copy(&mut input, &mut stdin));
        });
        let output = self.wait_with_output(child)?;
        match receiver.try_recv() {
            Ok(Err(error)) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(io::Error::other("DBI guest stdin writer thread panicked"))
            }
            Ok(_) | Err(std::sync::mpsc::TryRecvError::Empty) => Ok(output),
        }
    }

    fn terminate_and_reap(&self, child: &mut Child) {
        if self.manages_process_group() {
            let _ = terminate_process_group(child.id() as i32);
        }
        let _ = child.wait();
    }

    fn manages_process_group(&self) -> bool {
        self.isolated_process_group || self.terminate_process_group_on_exit
    }

    fn command(
        &self,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
    ) -> Command {
        let mut command = Command::new(&self.drrun);
        command
            .arg("-quiet")
            .arg("-disable_rseq")
            .args(["-stack_size", "2M"])
            .arg("-c")
            .arg(&self.client)
            .arg("-diagnostic_fd")
            .arg(DIAGNOSTIC_FD.to_string());
        command.args(&self.client_arguments);
        if self.isolated_process_group {
            command.arg("-isolated-process-group");
        }
        if self.summary {
            command.arg("-summary");
        }
        command.arg("--");

        let resolved_program = resolve_program(guest, environment);
        let inspected_program = resolved_program
            .as_deref()
            .unwrap_or_else(|| Path::new(guest.get_program()));
        if let Some((interpreter, interpreter_args)) = shebang(inspected_program.as_os_str()) {
            command
                .arg(interpreter)
                .args(interpreter_args)
                .arg(inspected_program);
        } else {
            command.arg(guest.get_program());
        }
        command.args(guest.get_args());

        if let Some(directory) = guest.get_current_dir() {
            command.current_dir(directory);
        }
        if let Some(environment) = environment {
            command.env_clear().envs(environment);
        } else {
            for (key, value) in guest.get_envs() {
                match value {
                    Some(value) => {
                        command.env(key, value);
                    }
                    None => {
                        command.env_remove(key);
                    }
                }
            }
        }
        if self.manages_process_group() {
            command.process_group(0);
        }

        // SAFETY: personality(2) and dup2(2) are async-signal-safe and the closure
        // captures no process state. Both settings survive drrun and guest execs.
        unsafe {
            command.pre_exec(|| {
                if libc::dup2(libc::STDERR_FILENO, DIAGNOSTIC_FD) == -1 {
                    return Err(io::Error::last_os_error());
                }
                let current = libc::personality(0xffff_ffff);
                if current == -1 {
                    return Err(io::Error::last_os_error());
                }
                let deterministic =
                    current as libc::c_ulong | libc::ADDR_NO_RANDOMIZE as libc::c_ulong;
                if libc::personality(deterministic) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
}

enum ChildWait {
    Status(ExitStatus),
    Output(Output),
}

enum CoordinatedInput {
    Null,
    Inherit,
    Reader(Box<dyn Read + Send>),
}

enum CoordinatedWait<G> {
    Status(ExitStatus, G),
    Output(Output, G),
}

async fn serve_rpc_until<G, F, T>(server: RpcServer<G>, completion: F) -> io::Result<T>
where
    G: GlobalTool + 'static,
    F: Future<Output = io::Result<T>>,
{
    let mut serving = tokio::task::JoinSet::new();
    serving.spawn(server.serve());
    tokio::pin!(completion);

    let result = tokio::select! {
        biased;
        result = &mut completion => result,
        result = serving.join_next() => {
            let message = match result {
                Some(Ok(Ok(()))) => "DBI coordinator stopped unexpectedly".to_owned(),
                Some(Ok(Err(error))) => error.to_string(),
                Some(Err(error)) => error.to_string(),
                None => "DBI coordinator task disappeared".to_owned(),
            };
            return Err(io::Error::other(message));
        }
    };

    serving.abort_all();
    while let Some(server_result) = serving.join_next().await {
        match server_result {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(())) => {
                return Err(io::Error::other("DBI coordinator stopped unexpectedly"));
            }
            Ok(Err(error)) => return Err(io::Error::other(error.to_string())),
            Err(error) => return Err(io::Error::other(error.to_string())),
        }
    }
    result
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#57): Confirm PATH lookup matches Command/execvp semantics.
fn resolve_program(
    guest: &Command,
    environment: Option<&BTreeMap<OsString, OsString>>,
) -> Option<PathBuf> {
    let program = guest.get_program();
    if program.as_bytes().contains(&b'/') {
        return None;
    }

    let path = if let Some(environment) = environment {
        environment.get(OsStr::new(PATH_ENV)).cloned()
    } else {
        let mut command_path = None;
        let mut path_overridden = false;
        for (key, value) in guest.get_envs() {
            if key == OsStr::new(PATH_ENV) {
                path_overridden = true;
                command_path = value.map(OsStr::to_os_string);
                break;
            }
        }
        if path_overridden {
            command_path
        } else {
            env::var_os(PATH_ENV)
        }
    }?;

    let current_dir = guest.get_current_dir();
    env::split_paths(&path)
        .map(|directory| {
            let directory = match current_dir {
                Some(current_dir) if directory.is_relative() => current_dir.join(directory),
                _ => directory,
            };
            directory.join(program)
        })
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn set_nonblocking(stream: &impl AsRawFd) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    // SAFETY: fd is owned by the live ChildStdout/ChildStderr value.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL updates status flags on the same live descriptor.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_cancellable(reader: &mut impl Read, cancelled: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "DBI output capture cancelled after process-group cleanup failed",
            ));
        }
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(bytes),
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if cancelled.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "DBI output capture cancelled after process-group cleanup failed",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

// Wait for the group leader to exit without releasing its PID/PGID identity.
// This prevents a cleanup signal from reaching a newly reused process group.
fn wait_for_exit_without_reaping(pid: u32) -> io::Result<()> {
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: info points to writable siginfo_t storage, and P_PID selects
        // the child identified by pid. WNOWAIT deliberately leaves it waitable.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn terminate_process_group(process_group: i32) -> io::Result<()> {
    // SAFETY: the launcher created a distinct process group whose id is the
    // still-unreaped child pid. The negative id targets only that group.
    let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if result == -1 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn shebang(program: &OsStr) -> Option<(PathBuf, Vec<OsString>)> {
    let mut bytes = Vec::new();
    File::open(Path::new(program))
        .ok()?
        .take(BINPRM_BUF_SIZE as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if !bytes.starts_with(b"#!") {
        return None;
    }

    let body = &bytes[2..];
    let start = body.iter().position(|byte| !matches!(byte, b' ' | b'\t'))?;
    let end = body[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(body.len(), |offset| start + offset);
    let mut fields = body[start..end]
        .split(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
        .filter(|field| !field.is_empty());
    let interpreter = PathBuf::from(OsStr::from_bytes(fields.next()?));
    let arguments = fields
        .map(|field| OsString::from(OsStr::from_bytes(field)))
        .collect();
    Some((interpreter, arguments))
}

fn resolve_drrun(home: &Path) -> io::Result<PathBuf> {
    let mut candidates = vec![
        home.join("build/bin64/drrun"),
        home.join("install/bin64/drrun"),
        home.join("bin64/drrun"),
    ];
    // CMake conventionally supplies DynamoRIO_DIR as the build/cmake or
    // install/cmake directory rather than its containing SDK root.
    if home.file_name().is_some_and(|name| name == "cmake")
        && let Some(prefix) = home.parent()
    {
        candidates.push(prefix.join("bin64/drrun"));
    }

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "DynamoRIO launcher was not found under {}; build DynamoRIO or correct DYNAMORIO_HOME",
                    home.display()
                ),
            )
        })
}

fn resolve_client() -> io::Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_target = manifest_dir
        .parent()
        .expect("reverie-dbi must be inside its workspace")
        .join("target");
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os(CLIENT_ENV) {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(path).join("reverie-dbi-native/libreverie_dbi_client.so"));
    }
    candidates.push(workspace_target.join("reverie-dbi-native/libreverie_dbi_client.so"));

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Reverie DBI client was not found; set REVERIE_DBI_CLIENT to libreverie_dbi_client.so or run reverie-dbi/scripts/build-client.sh",
            )
        })
}

fn require_file(path: &Path, description: &str) -> io::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{description} does not exist at {}", path.display()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner() -> DbiRunner {
        DbiRunner {
            drrun: PathBuf::from("/opt/dynamorio/bin64/drrun"),
            client: PathBuf::from("/opt/reverie/libreverie_dbi_client.so"),
            client_arguments: Vec::new(),
            summary: false,
            isolated_process_group: false,
            terminate_process_group_on_exit: false,
        }
    }

    fn write_executable_script(path: &Path, contents: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, contents).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    struct BlockingReader(std::sync::mpsc::Receiver<()>);

    impl Read for BlockingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    #[test]
    fn process_group_modes_are_opt_in() {
        let default_runner = runner();
        assert!(!default_runner.isolated_process_group);
        assert!(!default_runner.terminate_process_group_on_exit);
        assert!(
            default_runner
                .isolated_process_group(true)
                .isolated_process_group
        );
        assert!(
            runner()
                .terminate_process_group_on_exit(true)
                .terminate_process_group_on_exit
        );

        let cleanup_only = runner()
            .terminate_process_group_on_exit(true)
            .command(&Command::new("/bin/true"), None);
        assert!(
            !cleanup_only
                .get_args()
                .any(|argument| argument == OsStr::new("-isolated-process-group"))
        );
    }

    #[test]
    fn client_arguments_and_isolation_flag_precede_guest_separator() {
        let wrapped = runner()
            .client_argument("-panic-on-unsupported-syscalls")
            .isolated_process_group(true)
            .command(&Command::new("/bin/true"), None);
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                "-quiet",
                "-disable_rseq",
                "-stack_size",
                "2M",
                "-c",
                "/opt/reverie/libreverie_dbi_client.so",
                "-diagnostic_fd",
                "198",
                "-panic-on-unsupported-syscalls",
                "-isolated-process-group",
                "--",
                "/bin/true",
            ]
            .map(OsStr::new)
        );
    }
    #[test]
    fn wraps_guest_program_arguments_directory_and_environment() {
        let mut guest = Command::new("/bin/echo");
        guest
            .args(["hello", "dbi"])
            .current_dir("/tmp")
            .env("EXPLICIT", "value")
            .env_remove("REMOVED");

        let wrapped = runner().command(&guest, None);
        assert_eq!(
            wrapped.get_program(),
            OsStr::new("/opt/dynamorio/bin64/drrun")
        );
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                "-quiet",
                "-disable_rseq",
                "-stack_size",
                "2M",
                "-c",
                "/opt/reverie/libreverie_dbi_client.so",
                "-diagnostic_fd",
                "198",
                "--",
                "/bin/echo",
                "hello",
                "dbi",
            ]
            .map(OsStr::new)
        );
        assert_eq!(wrapped.get_current_dir(), Some(Path::new("/tmp")));
        assert!(wrapped.get_envs().any(|(key, value)| {
            key == OsStr::new("EXPLICIT") && value == Some(OsStr::new("value"))
        }));
        assert!(
            wrapped
                .get_envs()
                .any(|(key, value)| key == OsStr::new("REMOVED") && value.is_none())
        );
    }

    #[test]
    fn wraps_shebang_program_with_its_interpreter() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("guest-script");
        std::fs::write(&script, b"#!/usr/bin/env bash\necho guest\n").unwrap();
        let mut guest = Command::new(&script);
        guest.arg("argument");

        let wrapped = runner().command(&guest, None);
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-disable_rseq"),
                OsStr::new("-stack_size"),
                OsStr::new("2M"),
                OsStr::new("-c"),
                OsStr::new("/opt/reverie/libreverie_dbi_client.so"),
                OsStr::new("-diagnostic_fd"),
                OsStr::new("198"),
                OsStr::new("--"),
                OsStr::new("/usr/bin/env"),
                OsStr::new("bash"),
                script.as_os_str(),
                OsStr::new("argument"),
            ]
        );
    }

    #[test]
    fn resolves_bare_shebang_program_from_command_path() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let script = bin.join("guest-script");
        write_executable_script(&script, b"#!/bin/sh\necho guest\n");

        let mut guest = Command::new("guest-script");
        guest.env(PATH_ENV, &bin).arg("argument");

        let wrapped = runner().command(&guest, None);
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-disable_rseq"),
                OsStr::new("-stack_size"),
                OsStr::new("2M"),
                OsStr::new("-c"),
                OsStr::new("/opt/reverie/libreverie_dbi_client.so"),
                OsStr::new("-diagnostic_fd"),
                OsStr::new("198"),
                OsStr::new("--"),
                OsStr::new("/bin/sh"),
                script.as_os_str(),
                OsStr::new("argument"),
            ]
        );
    }

    #[test]
    fn resolves_bare_shebang_program_from_exact_environment_path() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let script = bin.join("guest-script");
        write_executable_script(&script, b"#!/usr/bin/env bash\necho guest\n");
        let environment = BTreeMap::from([(OsString::from(PATH_ENV), bin.into_os_string())]);

        let mut guest = Command::new("guest-script");
        guest.arg("argument");

        let wrapped = runner().command(&guest, Some(&environment));
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-disable_rseq"),
                OsStr::new("-stack_size"),
                OsStr::new("2M"),
                OsStr::new("-c"),
                OsStr::new("/opt/reverie/libreverie_dbi_client.so"),
                OsStr::new("-diagnostic_fd"),
                OsStr::new("198"),
                OsStr::new("--"),
                OsStr::new("/usr/bin/env"),
                OsStr::new("bash"),
                script.as_os_str(),
                OsStr::new("argument"),
            ]
        );
    }

    #[test]
    fn resolves_relative_path_from_guest_directory() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let script = bin.join("guest-script");
        write_executable_script(&script, b"#!/bin/sh\necho guest\n");

        let mut guest = Command::new("guest-script");
        guest.current_dir(root.path()).env(PATH_ENV, "bin");

        let wrapped = runner().command(&guest, None);
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[9], OsStr::new("/bin/sh"));
        assert_eq!(args[10], script.as_os_str());
        assert_eq!(wrapped.get_current_dir(), Some(root.path()));
    }

    #[test]
    fn resolves_symlinked_shebang_program_without_canonicalizing() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let script = bin.join("real-script");
        let wrapper = bin.join("guest-wrapper");
        write_executable_script(&script, b"#!/bin/sh\necho guest\n");
        std::os::unix::fs::symlink(&script, &wrapper).unwrap();

        let mut guest = Command::new("guest-wrapper");
        guest.env(PATH_ENV, &bin);

        let wrapped = runner().command(&guest, None);
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[9], OsStr::new("/bin/sh"));
        assert_eq!(args[10], wrapper.as_os_str());
    }

    #[test]
    fn preserves_bare_non_script_program_token() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let executable = bin.join("guest-elf");
        write_executable_script(&executable, b"\x7fELFplaceholder");

        let mut guest = Command::new("guest-elf");
        guest.env(PATH_ENV, &bin).arg("argument");

        let wrapped = runner().command(&guest, None);
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[9], OsStr::new("guest-elf"));
        assert_eq!(args[10], OsStr::new("argument"));
    }

    #[test]
    fn exact_environment_replaces_launcher_environment() {
        let guest = Command::new("/usr/bin/env");
        let environment = BTreeMap::from([(OsString::from("ONLY"), OsString::from("guest"))]);

        let wrapped = runner().command(&guest, Some(&environment));
        assert_eq!(
            wrapped.get_envs().collect::<Vec<_>>(),
            [(OsStr::new("ONLY"), Some(OsStr::new("guest")))]
        );
    }

    #[test]
    fn supplies_captured_standard_input() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let drrun = root.path().join("drrun");
        let client = root.path().join("client.so");
        std::fs::write(
            &drrun,
            b"#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&drrun, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&client, b"placeholder").unwrap();

        let runner = DbiRunner::new(drrun, client).unwrap();
        let output = runner
            .output_with_input(&Command::new("/bin/cat"), b"hello from stdin\n")
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"hello from stdin\n");

        let large_input = vec![b'x'; 1024 * 1024];
        let output = runner
            .output_with_input(&Command::new("/bin/cat"), &large_input)
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, large_input);

        let output = runner
            .output_with_input(&Command::new("/bin/true"), &output.stdout)
            .unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn cancellable_output_reader_stops_with_a_live_writer() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        set_nonblocking(&reader).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || while writer.write_all(&[b'x'; 4096]).is_ok() {});
            let reader_cancelled = Arc::clone(&cancelled);
            let handle = scope.spawn(move || read_cancellable(&mut reader, &reader_cancelled));
            std::thread::sleep(std::time::Duration::from_millis(5));
            cancelled.store(true, Ordering::Release);
            let error = handle.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            writer.join().unwrap();
        });
    }

    #[test]
    fn keeps_diagnostics_out_of_guest_stderr_redirections() {
        let root = tempfile::tempdir().unwrap();
        let drrun = root.path().join("drrun");
        let client = root.path().join("client.so");
        write_executable_script(
            &drrun,
            b"#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
        );
        std::fs::write(&client, b"placeholder").unwrap();

        let script = format!(
            "output=$(/bin/bash -c 'printf guest-stderr >&2; printf backend-diagnostic >&{DIAGNOSTIC_FD}' 2>&1); printf 'captured=<%s>\\n' \"$output\""
        );
        let mut guest = Command::new("/bin/bash");
        guest.args(["-c", &script]);

        let output = DbiRunner::new(drrun, client)
            .unwrap()
            .output(&guest)
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"captured=<guest-stderr>\n");
        assert_eq!(output.stderr, b"backend-diagnostic");
    }

    #[test]
    fn process_group_cleanup_terminates_descendants_after_root_exit() {
        let root = tempfile::tempdir().unwrap();
        let drrun = root.path().join("drrun");
        let client = root.path().join("client.so");
        write_executable_script(
            &drrun,
            b"#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
        );
        std::fs::write(&client, b"placeholder").unwrap();
        let runner = DbiRunner::new(drrun, client)
            .unwrap()
            .terminate_process_group_on_exit(true);
        let mut guest = Command::new("/bin/sh");
        guest.args(["-c", "sleep 60 & printf descendant-started; exit 7"]);
        let started = std::time::Instant::now();

        let output = runner.output(&guest).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"descendant-started");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn returns_when_child_exits_while_input_source_is_blocked() {
        let root = tempfile::tempdir().unwrap();
        let drrun = root.path().join("drrun");
        let client = root.path().join("client.so");
        write_executable_script(
            &drrun,
            b"#!/bin/sh\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"\n",
        );
        std::fs::write(&client, b"placeholder").unwrap();
        let runner = DbiRunner::new(drrun, client).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let started = std::time::Instant::now();

        let output = runner
            .output_with_detached_reader(&Command::new("/bin/true"), BlockingReader(receiver))
            .unwrap();
        assert!(output.status.success());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        drop(sender);
    }

    #[test]
    fn resolves_source_root_and_cmake_directory_layouts() {
        for relative_drrun in ["build/bin64/drrun", "install/bin64/drrun", "bin64/drrun"] {
            let root = tempfile::tempdir().unwrap();
            let drrun = root.path().join(relative_drrun);
            std::fs::create_dir_all(drrun.parent().unwrap()).unwrap();
            std::fs::write(&drrun, b"marker").unwrap();
            assert_eq!(resolve_drrun(root.path()).unwrap(), drrun);

            let cmake = drrun.parent().unwrap().parent().unwrap().join("cmake");
            std::fs::create_dir_all(&cmake).unwrap();
            assert_eq!(resolve_drrun(&cmake).unwrap(), drrun);
        }
    }
}
