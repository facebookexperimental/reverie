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

use reverie::BackendStatsRequest;
use reverie::GlobalTool;
use reverie_rpc_transport::RpcServer;

use crate::backend_stats::DbtBackendStatsAggregator;
use crate::backend_stats::DbtBackendStatsSource;
use crate::evidence::DbtEvidenceLogLevel;
use crate::evidence::EvidenceSession;

const CLIENT_ENV: &str = "REVERIE_DBT_CLIENT";
const DYNAMORIO_ENV: &str = "DYNAMORIO_HOME";
const DYNAMORIO_DIR_ENV: &str = "DynamoRIO_DIR";
const SUMMARY_ENV: &str = "REVERIE_DBT_SUMMARY";
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
/// `reverie-dbt/scripts/build-client.sh`. Set [`REVERIE_DBT_CLIENT`] to that
/// script's output, or build it in this Reverie workspace's default target
/// directory. [`DYNAMORIO_HOME`] must identify a built DynamoRIO source tree,
/// build directory, or install directory. Set `REVERIE_DBT_SUMMARY=1` to print
/// instrumentation totals after the guest exits.
///
/// [`REVERIE_DBT_CLIENT`]: https://github.com/rrnewton/reverie/tree/main/reverie-dbt
/// [`DYNAMORIO_HOME`]: https://dynamorio.org/page_deploy.html
#[derive(Clone, Debug)]
pub struct DbtRunner {
    drrun: PathBuf,
    client: PathBuf,
    client_arguments: Vec<OsString>,
    evidence: Option<Arc<EvidenceSession>>,
    evidence_log_level: DbtEvidenceLogLevel,
    summary: bool,
    isolated_process_group: bool,
    terminate_process_group_on_exit: bool,
}

impl DbtRunner {
    /// Resolves DynamoRIO and the Reverie DBT client from the environment.
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
        require_file(&client, "Reverie DBT client")?;
        Ok(Self {
            drrun,
            client,
            client_arguments: Vec::new(),
            evidence: None,
            evidence_log_level: DbtEvidenceLogLevel::Info,
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

    /// Collects canonical runtime evidence over a protected one-run sideband.
    ///
    /// `file` must be a fresh, empty, unlinked `O_RDWR` regular file. The caller
    /// retains its handle for reading after the complete followed process tree
    /// exits. During execution, authenticated length-framed records live only in
    /// launcher memory; the file is non-authoritative and may be guest-mutable.
    /// After every image sends its final marker and the tree is reaped, the
    /// launcher truncates and publishes one checksummed framed artifact. Use
    /// [`crate::decode_evidence`] rather than splitting that artifact on newlines.
    ///
    /// One configured collector is valid for exactly one run. Clones share that
    /// same run; a later run requires a new runner and a new empty file.
    pub fn evidence_file(mut self, file: &File) -> io::Result<Self> {
        self.evidence = Some(Arc::new(EvidenceSession::new(file)?));
        // Evidence is published only after this non-escapable process group is
        // empty. The native client rejects guest setpgid/setsid while this mode
        // is active, so no followed descendant can outlive publication.
        self.isolated_process_group = true;
        Ok(self)
    }

    /// Sets the protected tracing level used only by the evidence subscriber.
    ///
    /// This client argument is not added to the guest environment, so selecting
    /// INFO for verification does not overwrite a guest's own `HERMIT_LOG`.
    pub fn evidence_log_level(mut self, level: DbtEvidenceLogLevel) -> Self {
        self.evidence_log_level = level;
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
    /// Unlike [`Self::isolated_process_group`], this does not ask the DBT client
    /// to reject guest process-group mutations. It is intended for backends that
    /// must drain followed DynamoRIO children without changing non-strict guest
    /// syscall behavior.
    pub fn terminate_process_group_on_exit(mut self, enabled: bool) -> Self {
        self.terminate_process_group_on_exit = enabled;
        self
    }

    /// Runs `guest` with inherited standard streams and waits for it to exit.
    pub fn status(&self, guest: &Command) -> io::Result<ExitStatus> {
        let child = self.spawn_command(&mut self.command(guest, None))?;
        self.wait_for_status(child)
    }

    /// Runs `guest` with an exact environment instead of inheriting the launcher environment.
    pub fn status_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<ExitStatus> {
        let child = self.spawn_command(&mut self.command(guest, Some(environment)))?;
        self.wait_for_status(child)
    }

    /// Runs `guest` and captures its standard output and standard error.
    pub fn output(&self, guest: &Command) -> io::Result<Output> {
        let child = self.spawn_command(
            self.command(guest, None)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output(child)
    }

    /// Captures guest output while preserving an inherited terminal stdin.
    pub fn output_with_inherited_stdin(&self, guest: &Command) -> io::Result<Output> {
        let child = self.spawn_command(
            self.command(guest, None)
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
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
        let mut child = self.spawn_command(
            self.command(guest, None)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBT guest stdin")
        })?;

        std::thread::scope(|scope| {
            let writer = scope.spawn(move || io::copy(&mut input, &mut stdin));
            let output = self.wait_with_output(child);
            let write_result = writer
                .join()
                .map_err(|_| io::Error::other("DBT guest stdin writer thread panicked"))?;
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
        let child = self.spawn_command(
            self.command(guest, None)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output_and_detached_reader(child, input)
    }

    /// Captures `guest` output while supplying an exact guest environment.
    pub fn output_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<Output> {
        let child = self.spawn_command(
            self.command(guest, Some(environment))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output(child)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review typed DBT coordinator lifecycle.
    /// Runs `guest` while one coordinator-owned global serves every DBT process.
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
            .run_with_global::<G>(
                guest,
                None,
                config,
                true,
                CoordinatedInput::Null,
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Output(output, global, _) => Ok((output, global)),
            CoordinatedWait::Status(_, _, _) => {
                unreachable!("output launch returned only status")
            }
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review exact-environment DBT coordinator launch.
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
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Output(output, global, _) => Ok((output, global)),
            CoordinatedWait::Status(_, _, _) => {
                unreachable!("output launch returned only status")
            }
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
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Output(output, global, _) => Ok((output, global)),
            CoordinatedWait::Status(_, _, _) => {
                unreachable!("output launch returned only status")
            }
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
            .run_with_global::<G>(
                guest,
                None,
                config,
                true,
                CoordinatedInput::Inherit,
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Output(output, global, _) => Ok((output, global)),
            CoordinatedWait::Status(_, _, _) => {
                unreachable!("output launch returned only status")
            }
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review inherited-stdio DBT coordinator launch.
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
            .run_with_global::<G>(
                guest,
                None,
                config,
                false,
                CoordinatedInput::Inherit,
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Status(status, global, _) => Ok((status, global)),
            CoordinatedWait::Output(_, _, _) => unreachable!("status launch captured output"),
        }
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(impl-dbi-gap-closure): Review exact-environment DBT status launch.
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
                BackendStatsRequest::DISABLED,
            )
            .await?
        {
            CoordinatedWait::Status(status, global, _) => Ok((status, global)),
            CoordinatedWait::Output(_, _, _) => unreachable!("status launch captured output"),
        }
    }

    /// Runs `guest` with captured output, one shared global, and DBT backend statistics.
    ///
    /// Behaves like [`Self::output_with_global`] but additionally collects the
    /// typed per-process instrumentation records emitted by every followed image
    /// and aggregates them into a [`DbtBackendStatsSource`]. The source is
    /// `Some` even when no image reached `event_exit` (an empty snapshot); it is
    /// `None` only when statistics collection is not requested, which never
    /// happens on this path.
    pub async fn output_with_global_and_stats<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(Output, G, Option<DbtBackendStatsSource>)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(
                guest,
                None,
                config,
                true,
                CoordinatedInput::Null,
                BackendStatsRequest::ENABLED,
            )
            .await?
        {
            CoordinatedWait::Output(output, global, stats) => Ok((output, global, stats)),
            CoordinatedWait::Status(_, _, _) => {
                unreachable!("output launch returned only status")
            }
        }
    }

    /// Runs `guest` with inherited streams, one shared global, and DBT backend statistics.
    ///
    /// Behaves like [`Self::status_with_global`] but additionally aggregates the
    /// typed per-process instrumentation records into a
    /// [`DbtBackendStatsSource`]. See [`Self::output_with_global_and_stats`] for
    /// the meaning of the returned option.
    pub async fn status_with_global_and_stats<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(ExitStatus, G, Option<DbtBackendStatsSource>)>
    where
        G: GlobalTool + 'static,
    {
        match self
            .run_with_global::<G>(
                guest,
                None,
                config,
                false,
                CoordinatedInput::Inherit,
                BackendStatsRequest::ENABLED,
            )
            .await?
        {
            CoordinatedWait::Status(status, global, stats) => Ok((status, global, stats)),
            CoordinatedWait::Output(_, _, _) => unreachable!("status launch captured output"),
        }
    }

    async fn run_with_global<G>(
        &self,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
        config: G::Config,
        capture_output: bool,
        input: CoordinatedInput,
        stats: BackendStatsRequest,
    ) -> io::Result<CoordinatedWait<G>>
    where
        G: GlobalTool + 'static,
    {
        let directory = tempfile::Builder::new().prefix("reverie-dbt-").tempdir()?;
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
        let mut runner = self.clone().client_argument("-external-global");
        let stats_sink = if stats.is_enabled() {
            let sink = StatsSink::new()?;
            for argument in sink.client_arguments() {
                runner = runner.client_argument(argument);
            }
            Some(sink)
        } else {
            None
        };
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
        let child = runner.spawn_command(&mut command)?;
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
                "DBT guest exited before connecting to the global-state coordinator",
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
                        "DBT coordinator state still has {} owners after shutdown",
                        Arc::strong_count(&still_owned)
                    )));
                }
            }
        };
        // The whole followed process tree has been reaped, so every image that
        // reached `event_exit` has already appended its record. Draining now is
        // race-free.
        let stats_source = match stats_sink {
            Some(sink) => Some(sink.drain()?),
            None => None,
        };
        Ok(match wait {
            ChildWait::Status(status) => CoordinatedWait::Status(status, global, stats_source),
            ChildWait::Output(output) => CoordinatedWait::Output(output, global, stats_source),
        })
    }

    fn spawn_command(&self, command: &mut Command) -> io::Result<Child> {
        if let Some(evidence) = &self.evidence {
            evidence.claim_run()?;
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = self.finish_evidence(false);
                return Err(error);
            }
        };
        if let Some(evidence) = &self.evidence
            && let Err(error) = evidence.publish_root(child.id())
        {
            if self.manages_process_group() {
                let _ = terminate_process_group(child.id() as i32);
                let _ = wait_for_process_group_no_live_members(child.id() as i32);
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            let _ = self.finish_evidence(false);
            return Err(error);
        }
        Ok(child)
    }

    fn wait_for_status(&self, mut child: Child) -> io::Result<ExitStatus> {
        let status = if !self.manages_process_group() {
            child.wait()
        } else {
            let process_group = child.id() as i32;
            let observed = wait_for_exit_without_reaping(child.id());
            let terminated = if observed.is_ok() {
                terminate_process_group(process_group)
            } else {
                Ok(())
            };
            let emptied = match (&observed, &terminated) {
                (Ok(()), Ok(())) => wait_for_process_group_no_live_members(process_group),
                _ => Ok(()),
            };
            let status = child.wait();
            match (observed.and(terminated).and(emptied), status) {
                (Ok(()), status) => status,
                (Err(error), _) => Err(error),
            }
        };
        let evidence = self.finish_evidence(status.is_ok());
        match (status, evidence) {
            (Ok(status), Ok(())) => Ok(status),
            (Err(error), _) => Err(error),
            (Ok(status), Err(error)) => Err(io::Error::new(
                error.kind(),
                format!(
                    "DBT guest exited with status {:?} while protected evidence failed: {error}",
                    status.code()
                ),
            )),
        }
    }

    fn wait_with_output(&self, mut child: Child) -> io::Result<Output> {
        let mut stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                self.terminate_and_reap(&mut child);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed to capture DBT guest stdout",
                ));
            }
        };
        let mut stderr = match child.stderr.take() {
            Some(stderr) => stderr,
            None => {
                self.terminate_and_reap(&mut child);
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed to capture DBT guest stderr",
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
                .map_err(|_| io::Error::other("DBT stdout reader thread panicked"));
            let stderr = stderr_reader
                .join()
                .map_err(|_| io::Error::other("DBT stderr reader thread panicked"));

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
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBT guest stdin")
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
                Err(io::Error::other("DBT guest stdin writer thread panicked"))
            }
            Ok(_) | Err(std::sync::mpsc::TryRecvError::Empty) => Ok(output),
        }
    }

    fn terminate_and_reap(&self, child: &mut Child) {
        if self.manages_process_group() {
            let _ = terminate_process_group(child.id() as i32);
            let _ = wait_for_process_group_no_live_members(child.id() as i32);
        }
        let _ = child.wait();
        let _ = self.finish_evidence(false);
    }

    fn manages_process_group(&self) -> bool {
        self.evidence.is_some()
            || self.isolated_process_group
            || self.terminate_process_group_on_exit
    }

    fn finish_evidence(&self, publication_allowed: bool) -> io::Result<()> {
        match &self.evidence {
            Some(evidence) => evidence.finish(publication_allowed),
            None => Ok(()),
        }
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
        if let Some(evidence) = &self.evidence {
            command.args(evidence.client_arguments());
            command
                .arg("-evidence-log-level")
                .arg(self.evidence_log_level.code().to_string());
        }
        command.args(&self.client_arguments);
        if self.evidence.is_some() || self.isolated_process_group {
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

        // SAFETY: personality(2) and dup2(2) are async-signal-safe. Process-group
        // isolation is configured above through CommandExt::process_group; all
        // settings survive drrun and guest execs.
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

/// A per-run sink that collects fixed-size DBT stats records from every
/// instrumented process image in the guest tree.
///
/// The native client appends one wire record per real runtime image to a shared
/// file (see `native/client.c`). A shared path with append-mode opens (O_APPEND)
/// keeps concurrent appends atomic and side-steps the drrun -> guest exec fd
/// inheritance problem the diagnostic fd works around. After the whole tree is
/// reaped, [`StatsSink::drain`] decodes and commutatively aggregates every
/// record into one snapshot.
struct StatsSink {
    // Owns the temporary directory; dropping it removes the backing file. Held
    // until after `drain` reads the records.
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl StatsSink {
    fn new() -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("reverie-dbt-stats-")
            .tempdir()?;
        let path = directory.path().join("records.bin");
        Ok(Self {
            _directory: directory,
            path,
        })
    }

    /// The `-stats_path <path>` client arguments passed to the native client.
    fn client_arguments(&self) -> [OsString; 2] {
        [
            OsString::from("-stats_path"),
            self.path.clone().into_os_string(),
        ]
    }

    /// Decodes and aggregates every record written by the process tree.
    ///
    /// A missing file means no instrumented image reported (for example the
    /// guest died before `event_exit`); that yields an empty snapshot rather
    /// than an error. A present but malformed or truncated stream is a hard
    /// error, matching [`DbtBackendStatsAggregator::absorb_wire_stream`].
    fn drain(self) -> io::Result<DbtBackendStatsSource> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        let mut aggregator = DbtBackendStatsAggregator::new();
        aggregator
            .absorb_wire_stream(&bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(aggregator.into_source())
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
    Status(ExitStatus, G, Option<DbtBackendStatsSource>),
    Output(Output, G, Option<DbtBackendStatsSource>),
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
                Some(Ok(Ok(()))) => "DBT coordinator stopped unexpectedly".to_owned(),
                Some(Ok(Err(error))) => error.to_string(),
                Some(Err(error)) => error.to_string(),
                None => "DBT coordinator task disappeared".to_owned(),
            };
            return Err(io::Error::other(message));
        }
    };

    serving.abort_all();
    while let Some(server_result) = serving.join_next().await {
        match server_result {
            Err(error) if error.is_cancelled() => {}
            Ok(Ok(())) => {
                return Err(io::Error::other("DBT coordinator stopped unexpectedly"));
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
                "DBT output capture cancelled after process-group cleanup failed",
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
                        "DBT output capture cancelled after process-group cleanup failed",
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

fn wait_for_process_group_no_live_members(process_group: i32) -> io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    wait_for_process_group_no_live_members_until(process_group, deadline)
}

fn wait_for_process_group_no_live_members_until(
    process_group: i32,
    deadline: std::time::Instant,
) -> io::Result<()> {
    loop {
        let mut live_member = false;
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if entry
                .file_name()
                .as_bytes()
                .iter()
                .any(|byte| !byte.is_ascii_digit())
            {
                continue;
            }
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(after_name) = stat.rsplit_once(')').map(|(_, tail)| tail.trim_start()) else {
                continue;
            };
            let mut fields = after_name.split_ascii_whitespace();
            let Some(state) = fields.next() else {
                continue;
            };
            let _parent = fields.next();
            let Some(group) = fields.next().and_then(|field| field.parse::<i32>().ok()) else {
                continue;
            };
            if group == process_group && !matches!(state, "Z" | "X") {
                live_member = true;
                break;
            }
        }
        if !live_member {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DBT process group still had live members after termination",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
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
        .expect("reverie-dbt must be inside its workspace")
        .join("target");
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os(CLIENT_ENV) {
        candidates.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("CARGO_TARGET_DIR") {
        candidates.push(PathBuf::from(path).join("reverie-dbt-native/libreverie_dbt_client.so"));
    }
    candidates.push(workspace_target.join("reverie-dbt-native/libreverie_dbt_client.so"));

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Reverie DBT client was not found; set REVERIE_DBT_CLIENT to libreverie_dbt_client.so or run reverie-dbt/scripts/build-client.sh",
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
    use std::io::Seek as _;

    use super::*;

    fn runner() -> DbtRunner {
        DbtRunner {
            drrun: PathBuf::from("/opt/dynamorio/bin64/drrun"),
            client: PathBuf::from("/opt/reverie/libreverie_dbt_client.so"),
            client_arguments: Vec::new(),
            evidence: None,
            evidence_log_level: DbtEvidenceLogLevel::Info,
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

    fn compile_evidence_forge_fixture(directory: &Path) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evidence_forge.c");
        let output = directory.join("evidence_forge");
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let status = Command::new(compiler)
            .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .arg("-o")
            .arg(&output)
            .status()
            .expect("failed to invoke the C compiler for evidence_forge.c");
        assert!(status.success(), "failed to compile evidence_forge.c");
        output
    }

    fn disclose_evidence_credentials(runner: &DbtRunner, guest: &mut Command) {
        let arguments = runner
            .evidence
            .as_ref()
            .expect("test runner has no evidence session")
            .client_arguments();
        guest
            .env("EVIDENCE_SOCKET", &arguments[1])
            .env("EVIDENCE_TOKEN", &arguments[3]);
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
    fn process_group_wait_times_out_while_a_live_member_remains() {
        let process_group = unsafe { libc::getpgrp() };
        let error =
            wait_for_process_group_no_live_members_until(process_group, std::time::Instant::now())
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
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
                "/opt/reverie/libreverie_dbt_client.so",
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
            .args(["hello", "dbt"])
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
                "/opt/reverie/libreverie_dbt_client.so",
                "-diagnostic_fd",
                "198",
                "--",
                "/bin/echo",
                "hello",
                "dbt",
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
                OsStr::new("/opt/reverie/libreverie_dbt_client.so"),
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
                OsStr::new("/opt/reverie/libreverie_dbt_client.so"),
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
                OsStr::new("/opt/reverie/libreverie_dbt_client.so"),
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

        let runner = DbtRunner::new(drrun, client).unwrap();
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

        let output = DbtRunner::new(drrun, client)
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
        let runner = DbtRunner::new(drrun, client)
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
        let runner = DbtRunner::new(drrun, client).unwrap();
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

    /// Appends one already-encoded wire record to `path`, mirroring how each
    /// followed image's `event_exit` appends to the shared sink file.
    fn append_record(path: &Path, record: &crate::backend_stats::DbtProcessRecord) {
        use std::io::Write as _;

        let encoded = crate::backend_stats::encode_process_record(record);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(&encoded).unwrap();
    }

    #[test]
    fn stats_sink_passes_the_records_path_to_the_client() {
        let sink = StatsSink::new().unwrap();
        let arguments = sink.client_arguments();
        assert_eq!(arguments[0], OsStr::new("-stats_path"));
        assert_eq!(arguments[1], sink.path.clone().into_os_string());
        assert_eq!(arguments[1], sink.path.as_os_str());
    }

    #[test]
    fn stats_sink_drain_of_missing_file_yields_an_empty_snapshot() {
        let sink = StatsSink::new().unwrap();
        // No image ever wrote the file (e.g. the guest died before event_exit).
        assert!(!sink.path.exists());
        let source = sink.drain().unwrap();
        let snapshot = source.snapshot();
        assert_eq!(snapshot.process_images(), 0);
        assert_eq!(snapshot.counted_branches(), 0);
        assert_eq!(snapshot.translation().process_images_with_stats(), 0);
    }

    #[test]
    fn stats_sink_drains_and_aggregates_appended_records() {
        use crate::backend_stats::DbtProcessRecord;
        use crate::backend_stats::DbtRuntimeKind;

        let sink = StatsSink::new().unwrap();

        // One image with DynamoRIO translation stats present.
        append_record(
            &sink.path,
            &DbtProcessRecord {
                runtime_kind: DbtRuntimeKind::Counter1,
                dr_stats_present: true,
                branches: 100,
                syscalls: 10,
                rewritten: 2,
                stdin_reads: 1,
                basic_blocks_built: 70,
                threads_created: 3,
                code_cache_exits: 30,
                peak_threads: 3,
                peak_reachable_cache_blocks: 400,
                ..DbtProcessRecord::default()
            },
        );
        // A second image (e.g. a followed exec) without translation stats.
        append_record(
            &sink.path,
            &DbtProcessRecord {
                runtime_kind: DbtRuntimeKind::PrototypeTool,
                dr_stats_present: false,
                branches: 5,
                syscalls: 1,
                peak_threads: 9,
                ..DbtProcessRecord::default()
            },
        );

        let source = sink.drain().unwrap();
        let snapshot = source.snapshot();

        // Additive fields sum across images.
        assert_eq!(snapshot.process_images(), 2);
        assert_eq!(snapshot.counted_branches(), 105);
        assert_eq!(snapshot.intercepted_syscalls(), 11);
        assert_eq!(snapshot.rewritten_syscalls(), 2);
        assert_eq!(snapshot.stdin_reads(), 1);

        let translation = snapshot.translation();
        // Translation totals only fold in the image that reported them.
        assert_eq!(translation.basic_blocks_built(), 70);
        assert_eq!(translation.threads_created(), 3);
        assert_eq!(translation.code_cache_exits(), 30);
        assert_eq!(translation.process_images_with_stats(), 1);
        assert_eq!(translation.process_images_without_stats(), 1);
        // Peak gauges are max-reduced, but only over images that reported
        // dr_stats: the no-stats image's peak_threads=9 is deliberately ignored,
        // so the peak stays at the stats-bearing image's 3.
        assert_eq!(translation.peak_threads_per_process(), 3);
        assert_eq!(
            translation.peak_reachable_code_cache_blocks_per_process(),
            400
        );
    }

    #[test]
    fn stats_sink_drain_of_a_truncated_stream_is_an_error() {
        use std::io::Write as _;

        let sink = StatsSink::new().unwrap();
        let encoded =
            crate::backend_stats::encode_process_record(&crate::backend_stats::DbtProcessRecord {
                branches: 42,
                ..crate::backend_stats::DbtProcessRecord::default()
            });
        // Write a whole record followed by a partial one: a corrupt tail must be
        // a hard error, not a silent end-of-stream.
        let mut file = std::fs::File::create(&sink.path).unwrap();
        file.write_all(&encoded).unwrap();
        file.write_all(&encoded[..encoded.len() - 1]).unwrap();
        drop(file);

        let error = sink.drain().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_rejects_disclosed_credentials_and_config_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = compile_evidence_forge_fixture(directory.path());
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-wait-for-background");
        let mut guest = Command::new(fixture);
        disclose_evidence_credentials(&runner, &mut guest);

        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;
        let output = child.wait_with_output().unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        if let Err(error) = runner.finish_evidence(true) {
            panic!(
                "protected evidence guard run failed: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "guard fixture failed: status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"evidence-guards-ok\n");
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let evidence = crate::decode_evidence(&bytes).unwrap();
        assert!(
            !evidence.records().is_empty(),
            "live integrity run produced no canonical evidence records"
        );
        assert!(evidence.records().iter().all(|record| {
            !record
                .windows(b"forged-evidence".len())
                .any(|window| window == b"forged-evidence")
        }));
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_refuses_a_valid_frame_from_outside_the_guest_tree() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = compile_evidence_forge_fixture(directory.path());
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-wait-for-background");
        let mut guest = Command::new("/bin/sleep");
        guest.arg("30");
        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;

        let mut outside = Command::new(fixture);
        outside.env("EVIDENCE_FORGE_MODE", "outside-tree");
        disclose_evidence_credentials(&runner, &mut outside);
        let outside_output = outside.output().unwrap();
        assert!(
            outside_output.status.success(),
            "outside-tree probe failed: {outside_output:?}"
        );
        assert_eq!(outside_output.stdout, b"outside-tree-evidence-refused\n");

        terminate_process_group(process_group).unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        let _ = child.wait();
        let error = runner.finish_evidence(true).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.to_string(),
            "DBT evidence peer is outside the launched process tree"
        );
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(
            bytes.is_empty(),
            "refused outside-tree frame published evidence"
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_retries_after_a_dropped_acknowledgement() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-wait-for-background");
        runner
            .evidence
            .as_ref()
            .unwrap()
            .drop_next_acknowledgement();
        let guest = Command::new("/bin/true");
        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;
        let output = child.wait_with_output().unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        if let Err(error) = runner.finish_evidence(true) {
            panic!(
                "protected evidence retry run failed: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            output.status.success(),
            "retry guest failed: status={:?} stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let evidence = crate::decode_evidence(&bytes).unwrap();
        assert!(
            !evidence.records().is_empty(),
            "retry run produced no canonical evidence records"
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_refuses_an_announced_child_killed_before_start() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = compile_evidence_forge_fixture(directory.path());
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-kill-announced-child");
        let mut guest = Command::new(fixture);
        guest.env("EVIDENCE_FORGE_MODE", "killed-child");
        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;
        let output = child.wait_with_output().unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        assert!(
            output.status.success(),
            "killed-child control failed: {output:?}"
        );
        assert_eq!(output.stdout, b"killed-announced-child-ok\n");
        let error = runner.finish_evidence(true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing a child process START or FINAL frame"),
            "collector refused the killed child for the wrong reason: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(
            bytes.is_empty(),
            "refused evidence run published an artifact"
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_rejects_direct_emitter_entry() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-direct-evidence-entry");
        let guest = Command::new("/bin/true");
        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;
        let output = child.wait_with_output().unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        assert!(runner.finish_evidence(true).is_err());
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(output.status.code(), Some(101));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("rejected evidence outside a protected callback"),
            "direct emitter failed for the wrong reason: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            bytes.is_empty(),
            "failed evidence run published an artifact"
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn native_runtime_abi_mismatch_fails_before_guest_execution() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-runtime-abi-mismatch");
        let guest = Command::new("/bin/true");
        let mut command = runner.command(&guest, None);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let process_group = child.id() as i32;
        let output = child.wait_with_output().unwrap();
        wait_for_process_group_no_live_members(process_group).unwrap();
        assert!(runner.finish_evidence(true).is_err());
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(output.status.code(), Some(101));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("native/runtime ABI version or callback size mismatch"),
            "runtime ABI mismatch failed for the wrong reason: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            bytes.is_empty(),
            "runtime ABI mismatch published an evidence artifact"
        );
    }
}
