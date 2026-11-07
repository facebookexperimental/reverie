/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::env;
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
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
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

use reverie::BackendStatsRequest;
use reverie::GlobalTool;
use reverie_rpc_transport::RpcServer;
use sha2::Digest;
use sha2::Sha256;

use crate::backend_stats::DbtBackendStatsSource;
use crate::backend_stats::DbtStatsCapture;
use crate::evidence::DbtEvidenceLogLevel;
use crate::evidence::EvidenceSession;

const CLIENT_ENV: &str = "REVERIE_DBT_CLIENT";
const DYNAMORIO_ENV: &str = "DYNAMORIO_HOME";
const DYNAMORIO_DIR_ENV: &str = "DynamoRIO_DIR";
const SUMMARY_ENV: &str = "REVERIE_DBT_SUMMARY";
const PATH_ENV: &str = "PATH";
/// Names, for the bundled DynamoRIO, the variable prefixes it removes from the
/// guest's initial environment (with its own `DYNAMORIO_*` variables) and passes
/// on to the children it follows.
const HIDE_ENV_PREFIXES_ENV: &str = "DYNAMORIO_HIDE_ENV_PREFIXES";
/// Tells the bundled DynamoRIO that the tool answers the guest's `brk(2)`
/// itself ([`DbtRunner::tool_answers_brk`]). A `DYNAMORIO_*` variable, so the
/// guest never sees it.
const TOOL_ANSWERS_BRK_ENV: &str = "DYNAMORIO_TOOL_ANSWERS_BRK";
/// Existing native preemption control; its value is private runtime input.
const PREEMPT_ANYPC_ENV: &str = "HERMIT_DBT_PREEMPT_ANYPC";
const BINPRM_BUF_SIZE: usize = 256;
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#90): Confirm the reserved descriptor across followed execs.
// Keep client diagnostics on launcher stderr across guest fd 2 redirects and execs.
const DIAGNOSTIC_FD: libc::c_int = 198;

// TODO-HUMAN-REVIEW(PR-134): Review the native bootstrap failure ABI.
/// Exit code used when DynamoRIO cannot start the sideline runtime thread before guest code runs.
pub const CLIENT_THREAD_START_FAILURE_EXIT_CODE: i32 = 125;

/// Selects the random offset used for DynamoRIO's private mapping reservation.
///
/// This affects the engine's preferred-base placement path. Near-application
/// placement, relocation and reservation failure handling remain engine-owned;
/// neither choice promises a fixed address or identical guest mappings.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DbtPrivatePlacement {
    /// Leave the option unset and use the bundled engine's default.
    #[default]
    SdkDefault,
    /// Request no random offset from the engine's preferred private base.
    NoRandomOffset,
}

/// Launches Linux programs under the Reverie DynamoRIO client.
///
/// The native client is built separately by
/// `reverie-dbt/scripts/build-client.sh`. Set [`REVERIE_DBT_CLIENT`] to that
/// script's output, or build it in this Reverie workspace's default target
/// directory. [`DYNAMORIO_HOME`] must identify a built DynamoRIO source tree,
/// build directory, or install directory containing the frontend selected when
/// this crate was built. The constructor checks frontend bytes, not SDK layout.
/// Relocated identical bytes are accepted by that check, but execution requires
/// an intact SDK layout. Independently built frontends require a matching
/// consuming-crate build.
/// Set `REVERIE_DBT_SUMMARY=1` to print
/// instrumentation totals after the guest exits.
///
/// [`REVERIE_DBT_CLIENT`]: https://github.com/rrnewton/reverie/tree/main/reverie-dbt
/// [`DYNAMORIO_HOME`]: https://dynamorio.org/page_deploy.html
#[derive(Clone, Debug)]
pub struct DbtRunner {
    drrun: PathBuf,
    client: PathBuf,
    client_arguments: Vec<OsString>,
    private_placement: DbtPrivatePlacement,
    private_environment: Vec<OsString>,
    diagnostic_file: Option<Arc<File>>,
    evidence: Option<Arc<EvidenceSession>>,
    evidence_log_level: DbtEvidenceLogLevel,
    summary: bool,
    isolated_process_group: bool,
    terminate_process_group_on_exit: bool,
    defer_evidence_finish: bool,
    tool_answers_brk: bool,
    caller_tool: bool,
}

// A blocking socket-to-pipe splice can hold the child's stdin pipe mutex
// while waiting for the next input byte. Read first, then write, so a child
// can consume each chunk while its producer remains open.
fn copy_streaming_input<R: Read, W: io::Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buffer = [0u8; 8192];
    let mut copied = 0;
    loop {
        let count = match reader.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(copied);
        }
        writer.write_all(&buffer[..count])?;
        copied += count as u64;
    }
}

fn validate_private_environment_selector(name: &OsStr) -> io::Result<()> {
    if name.is_empty()
        || name
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0 | b':' | b'='))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private environment selectors must be nonempty and contain no NUL, ':' or '='",
        ));
    }
    Ok(())
}

impl DbtRunner {
    /// The static facts about how this backend runs a guest that a tool may
    /// need, in the same form [`reverie::Backend::capabilities`] reports them
    /// for backends that implement that trait.
    pub const fn capabilities() -> reverie::BackendCapabilities {
        reverie::BackendCapabilities::DBT
    }

    /// Resolves DynamoRIO and the Reverie DBT client from the environment.
    ///
    /// The selected frontend must match this crate's attested build, as for
    /// [`Self::new`]; discovery does not permit an older or independent frontend.
    /// Execution still requires an intact SDK layout; frontend validation does
    /// not verify that layout.
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
    ///
    /// The frontend must have the exact bytes selected and attested when this
    /// crate was built. This validates frontend bytes, not SDK layout. Relocated
    /// identical bytes pass this check, but execution requires an intact SDK
    /// layout. Independently built frontends require rebuilding the consuming
    /// crate against that maintained SDK.
    /// A relative frontend is bound to the constructor's current directory.
    /// This is a compatibility preflight, not an inode pin: the caller must keep
    /// the selected SDK immutable until execution, including its shared libraries.
    pub fn new(drrun: impl Into<PathBuf>, client: impl Into<PathBuf>) -> io::Result<Self> {
        let drrun = drrun.into();
        let drrun = if drrun.is_absolute() {
            drrun
        } else {
            env::current_dir()?.join(drrun)
        };
        let client = client.into();
        require_file(&drrun, "DynamoRIO launcher")?;
        let expected = option_env!("REVERIE_DBT_DRRUN_SHA256").unwrap_or_default();
        let actual = format!("{:x}", Sha256::digest(std::fs::read(&drrun)?));
        if expected.is_empty() || actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "incompatible DynamoRIO frontend: use the SDK selected by this crate, \
                 or rebuild the consuming crate against the matching maintained SDK; \
                 only relocated byte-identical frontends are supported",
            ));
        }
        require_file(&client, "Reverie DBT client")?;
        Ok(Self {
            drrun,
            client,
            client_arguments: Vec::new(),
            private_placement: DbtPrivatePlacement::SdkDefault,
            private_environment: Vec::new(),
            diagnostic_file: None,
            evidence: None,
            evidence_log_level: DbtEvidenceLogLevel::Info,
            summary: false,
            isolated_process_group: false,
            terminate_process_group_on_exit: false,
            defer_evidence_finish: false,
            tool_answers_brk: false,
            caller_tool: false,
        })
    }

    /// Enables or disables the instrumentation summary written at process exit.
    pub fn summary(mut self, enabled: bool) -> Self {
        self.summary = enabled;
        self
    }

    /// Selects the engine's private mapping offset policy.
    ///
    /// The default leaves `vm_max_offset` unset. Callers that require the
    /// historical zero-offset request can select
    /// [`DbtPrivatePlacement::NoRandomOffset`]. This does not change guest ASLR
    /// handling or the engine's reservation ownership and failure rules.
    /// Clones preserve the selection; a later call replaces it, including
    /// returning to [`DbtPrivatePlacement::SdkDefault`].
    pub fn private_placement(mut self, policy: DbtPrivatePlacement) -> Self {
        self.private_placement = policy;
        self
    }

    /// Hides exactly `name` from the guest and preserves it privately across
    /// instrumented execs. Values whose names merely start with `name` stay visible.
    ///
    /// The backend always hides its RPC endpoint and native preemption control;
    /// DynamoRIO also hides its own controls. Other runtime or Tool variables are
    /// visible unless the caller selects them. Unselected values follow ordinary
    /// environment inheritance and do not survive an exec with a replaced
    /// environment through private reinjection.
    ///
    /// Names must be nonempty and contain no NUL, `:` or `=`. This restriction
    /// applies only to the selector, not to unrelated guest environment entries.
    /// Non-UTF8 names are supported. Selection is preserved by runner clones.
    pub fn private_environment_key(mut self, name: impl Into<OsString>) -> io::Result<Self> {
        let mut name = name.into();
        validate_private_environment_selector(&name)?;
        name.push("=");
        self.private_environment.push(name);
        Ok(self)
    }

    /// Hides every variable whose name starts with `prefix`, preserving those
    /// values privately across instrumented execs.
    ///
    /// The validation, inheritance and clone rules of
    /// [`Self::private_environment_key`] also apply. The default does not select
    /// any caller namespace. Select a prefix only when the caller owns its
    /// privacy policy; arbitrary guest variables otherwise remain visible.
    pub fn private_environment_prefix(mut self, prefix: impl Into<OsString>) -> io::Result<Self> {
        let prefix = prefix.into();
        validate_private_environment_selector(&prefix)?;
        self.private_environment.push(prefix);
        Ok(self)
    }

    fn encoded_private_environment(&self) -> OsString {
        let mut selectors = self.private_environment.clone();
        for key in [crate::sync_rpc::RPC_SOCKET_ENV, PREEMPT_ANYPC_ENV] {
            let mut selector = OsString::from(key);
            selector.push("=");
            selectors.push(selector);
        }
        selectors.sort();
        selectors.dedup();
        let mut selected: Vec<OsString> = Vec::new();
        for selector in selectors {
            if !selected
                .iter()
                .any(|prefix| selector.as_bytes().starts_with(prefix.as_bytes()))
            {
                selected.push(selector);
            }
        }
        let mut encoded = OsString::new();
        for selector in selected {
            if !encoded.is_empty() {
                encoded.push(":");
            }
            encoded.push(selector);
        }
        encoded
    }

    /// Declares that the tool answers the guest's `brk(2)` itself, without
    /// the kernel's program break. DynamoRIO then reserves nothing for the
    /// break: no region of its own to emulate it in, no nudge of the kernel's
    /// break, and no inaccessible page after the images it maps for the app
    /// (the guest's own, where the break starts, and its interpreter's).
    /// Without this, DynamoRIO answers `brk` from its own emulation, and the
    /// runner removes the variable that tells DynamoRIO otherwise from every
    /// environment the launch would pass on.
    pub fn tool_answers_brk(mut self, enabled: bool) -> Self {
        self.tool_answers_brk = enabled;
        self
    }

    /// Routes DBT client diagnostics to `file` instead of the launcher's standard error.
    ///
    /// The runner clones the open file handle, so the caller may close its handle
    /// after this method returns. The file must be writable. When output capture is
    /// requested, the returned [`Output::stderr`] then contains the guest's file
    /// descriptor 2 stream on a successful `-quiet` DynamoRIO launch. A launcher or
    /// DynamoRIO failure may still report through its own standard error before the
    /// guest runs.
    ///
    /// When this option is not set, diagnostics retain their historical behavior and
    /// share the launcher's standard error.
    pub fn diagnostic_file(mut self, file: &File) -> io::Result<Self> {
        let file = clone_diagnostic_fd(file.as_raw_fd())?;
        require_writable_diagnostic_fd(file.as_raw_fd())?;
        self.diagnostic_file = Some(Arc::new(file));
        Ok(self)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-84): Review persistent DynamoRIO client argument propagation.
    /// Adds an argument passed to the native client in every instrumented process image.
    pub fn client_argument(mut self, argument: impl Into<OsString>) -> Self {
        self.client_arguments.push(argument.into());
        self
    }

    /// Collects bounded runtime evidence records over a protected one-run sideband.
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
    /// A preparation refusal also consumes that attempt without publication.
    pub fn evidence_file(self, file: &File) -> io::Result<Self> {
        self.configure_evidence_file(file, None)
    }

    /// Collects evidence with one immutable Tool-owned record validator.
    ///
    /// Guest records and coordinator appenders use the same policy, including
    /// appenders obtained from runner clones. Backend initialization records
    /// and lookalikes are checked separately by the transport, so a Tool policy
    /// need not know their representation. All transport bounds, authentication,
    /// and lifecycle checks remain enforced. The validator must satisfy the
    /// nonblocking, nonpanicking contract of [`crate::EvidenceRecordValidator`].
    /// Decode with [`crate::decode_evidence_with_validator`] and the same policy.
    pub fn evidence_file_with_validator(
        self,
        file: &File,
        validator: crate::EvidenceRecordValidator,
    ) -> io::Result<Self> {
        self.configure_evidence_file(file, Some(validator))
    }

    fn configure_evidence_file(
        mut self,
        file: &File,
        validator: Option<crate::EvidenceRecordValidator>,
    ) -> io::Result<Self> {
        self.evidence = Some(Arc::new(EvidenceSession::new(file, validator)?));
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

    /// The appender for records the coordinator emits into this run's
    /// protected evidence, when an evidence file is configured.
    pub fn coordinator_evidence(&self) -> Option<crate::CoordinatorEvidence> {
        self.evidence
            .as_ref()
            .map(|evidence| evidence.coordinator_evidence())
    }

    /// Keeps the protected evidence open after the guest tree is reaped, until
    /// [`Self::finish_deferred_evidence`].
    ///
    /// A coordinator that appends records through [`Self::coordinator_evidence`]
    /// keeps emitting after the guest exits (Detcore's scheduler logs that its
    /// run queue emptied), so finishing when the tree is reaped would make
    /// whether those records are in the stream depend on timing. The caller
    /// finishes its own shutdown first, then finishes the evidence. Failure
    /// paths still finish immediately and refuse publication.
    pub fn defer_evidence_finish(mut self) -> Self {
        self.defer_evidence_finish = true;
        self
    }

    /// Finishes evidence whose finish [`Self::defer_evidence_finish`] deferred,
    /// combining the guest's `status` with the evidence result as an undeferred
    /// run does.
    pub fn finish_deferred_evidence(&self, status: ExitStatus) -> io::Result<ExitStatus> {
        let evidence = match &self.evidence {
            Some(evidence) => evidence.finish_deferred(),
            None => Ok(()),
        };
        combine_status_and_evidence(Ok(status), evidence)
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
        let child = self.spawn_command(&mut self.command(guest, None)?)?;
        self.wait_for_status(child, None)
    }

    /// Runs `guest` with an exact environment instead of inheriting the launcher environment.
    pub fn status_with_environment(
        &self,
        guest: &Command,
        environment: &BTreeMap<OsString, OsString>,
    ) -> io::Result<ExitStatus> {
        let child = self.spawn_command(&mut self.command(guest, Some(environment))?)?;
        self.wait_for_status(child, None)
    }

    /// Runs `guest` and captures its standard output and standard error.
    pub fn output(&self, guest: &Command) -> io::Result<Output> {
        let child = self.spawn_command(
            self.command(guest, None)?
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output(child, None)
    }

    /// Captures guest output while preserving an inherited terminal stdin.
    pub fn output_with_inherited_stdin(&self, guest: &Command) -> io::Result<Output> {
        let child = self.spawn_command(
            self.command(guest, None)?
                .stdin(Stdio::inherit())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output(child, None)
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
            self.command(guest, None)?
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBT guest stdin")
        })?;

        std::thread::scope(|scope| {
            let writer = match std::thread::Builder::new()
                .spawn_scoped(scope, move || copy_streaming_input(&mut input, &mut stdin))
            {
                Ok(writer) => writer,
                Err(error) => {
                    self.terminate_and_reap(&mut child);
                    return Err(error);
                }
            };
            let output = self.wait_with_output(child, None);
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
            self.command(guest, None)?
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
            self.command(guest, Some(environment))?
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )?;
        self.wait_with_output(child, None)
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

    /// Run a paired caller Tool runtime whose actual root acknowledges its
    /// installed owner and consuming exit through the shared RPC protocol.
    ///
    /// A Config-only connection or application RPC is not activation. The
    /// final receipt must match the real child's exit code. Legacy launch
    /// methods keep their existing application-request guard.
    ///
    /// The initial caller domain requires an unfiltered application root. The
    /// controller verifies its owned child's proc status before serving Config;
    /// missing, malformed, or restricted status refuses before constructing the
    /// Tool. A query issued by the child alone cannot establish this condition.
    pub async fn output_with_caller_tool<G>(
        &self,
        guest: &Command,
        config: G::Config,
    ) -> io::Result<(Output, G)>
    where
        G: GlobalTool + 'static,
    {
        let mut runner = self.clone();
        runner.caller_tool = true;
        runner.output_with_global::<G>(guest, config).await
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
        let directory = tempfile::Builder::new()
            .prefix("reverie-dbt-")
            .tempdir_in("/tmp")?;
        let socket = directory.path().join("coordinator.sock");
        let inherited_input = match &input {
            CoordinatedInput::Reader(_) => Some(reverie::InheritedInput::pipe(libc::STDIN_FILENO)?),
            CoordinatedInput::Null | CoordinatedInput::Inherit => None,
        };
        let input_lease = inherited_input
            .as_ref()
            .map(reverie::InheritedInput::lease)
            .transpose()?;
        let mut global = G::init_global_state(&config).await;
        // The broader terminate-on-exit option does not prevent group escape.
        // Only these existing modes install the native containment guard (or
        // run under namespace-init cleanup); no runner default is changed.
        let containment_enabled = self.evidence.is_some() || self.isolated_process_group;
        let (mapping_capture_owner, mapping_capture_control) = if containment_enabled {
            reverie::MappingCaptureRunOwner::new()
        } else {
            reverie::MappingCaptureRunOwner::disabled()
        };
        // Failure accounting is present even when capture authority is absent:
        // a pre-Prepare refusal must not become an ordinary guest exit101.
        global.install_mapping_capture_run(mapping_capture_control.clone());
        if let Some(input) = input_lease {
            global.install_inherited_input(input);
        }
        let mut global = Arc::new(global);
        let requested = Arc::new(AtomicBool::new(false));
        let activation = self
            .caller_tool
            .then(reverie_rpc_transport::tool_activation::ActivationRun::new);
        let mut server = RpcServer::bind_with_readiness(
            &socket,
            Arc::clone(&global),
            config,
            Arc::clone(&requested),
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
        if containment_enabled {
            server = server.mapping_capture(mapping_capture_control);
        }
        if let Some(run) = &activation {
            server = server.tool_activation(run.clone());
        }

        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-247): Review native external-global capability propagation.
        // The root records this explicit capability in shared state before any
        // fork. Copied DynamoRIO runtimes cannot reliably re-read Rust's
        // process environment after fork.
        let mut runner = self.clone().client_argument("-external-global");
        let stats_sink = if stats.is_enabled() {
            let sink = DbtStatsSink::new()?;
            runner = sink.configure(runner);
            Some(sink)
        } else {
            None
        };
        let mut command = runner.command(guest, environment)?;
        command.env(crate::sync_rpc::RPC_SOCKET_ENV, &socket);
        let mut input_writer = None;
        match &input {
            CoordinatedInput::Null => {
                command.stdin(Stdio::null());
            }
            CoordinatedInput::Inherit => {
                command.stdin(Stdio::inherit());
            }
            CoordinatedInput::Reader(_) => {
                let (reader, writer) = inherited_input
                    .expect("Reader input was prepared")
                    .into_reader_and_writer();
                command.stdin(Stdio::from(reader));
                input_writer = Some(writer);
            }
        }
        if capture_output {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = runner.spawn_command(&mut command)?;
        if activation.is_some()
            && let Err(error) = require_unfiltered_caller_root(&child)
        {
            return Err(runner.refuse_caller_admission(child, capture_output, error));
        }
        if let Err(error) = mapping_capture_owner.bind_root(&child) {
            runner.terminate_and_reap(&mut child);
            return Err(error);
        }
        if let Some(run) = &activation
            && let Err(error) = run.bind_root(child.id() as i32)
        {
            runner.terminate_and_reap(&mut child);
            return Err(io::Error::other(error.to_string()));
        }
        // A reusable Command retains a caller-supplied Stdio owner after spawn.
        // Keep no parent reader beyond the Tool's temporary initial-image lease.
        drop(command);
        // Do not serve the existing config handshake until all parent I/O
        // threads exist. The guest's native helper cannot publish READY before
        // receiving that config, including runs without protected evidence.
        let (setup_sender, setup) = tokio::sync::oneshot::channel();
        let wait = tokio::task::spawn_blocking(move || match input {
            CoordinatedInput::Reader(input) => runner
                .wait_with_output_and_input_writer(
                    child,
                    input,
                    input_writer.expect("Reader writer was retained"),
                    Some(setup_sender),
                )
                .map(ChildWait::Output),
            CoordinatedInput::Null | CoordinatedInput::Inherit if capture_output => runner
                .wait_with_output(child, Some(setup_sender))
                .map(ChildWait::Output),
            CoordinatedInput::Null | CoordinatedInput::Inherit => runner
                .wait_for_status(child, Some(setup_sender))
                .map(ChildWait::Status),
        });
        let completion = async move {
            wait.await
                .map_err(|error| io::Error::other(error.to_string()))?
        };
        if setup.await.is_err() {
            // Setup owns cleanup before dropping its sender. Await its real
            // error rather than starting the server or losing the child wait.
            return match completion.await {
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::other("DBT launch setup ended without readiness")),
            };
        }
        let wait = serve_rpc_until(server, completion).await?;
        // The wait owns real child/tree cleanup. Only then may a complete
        // capture become an ordinary guest status, including verify-allow.
        mapping_capture_owner.finish()?;
        if let Some(run) = &activation {
            let receipt = match run.completed() {
                Ok(receipt) => receipt,
                Err(error) => {
                    return Err(DbtFailedRunOutput::attach_wait(
                        io::Error::other(error.to_string()),
                        wait,
                    ));
                }
            };
            if wait.status().code() != Some(i32::from(receipt.exit_code())) {
                return Err(DbtFailedRunOutput::attach_wait(
                    io::Error::other("caller Finished receipt does not match actual child exit"),
                    wait,
                ));
            }
        } else if missing_coordinator_request_is_error(requested.load(Ordering::Acquire), &wait) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "DBT guest exited successfully without sending a request to the global-state coordinator",
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
                return Err(if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "required execute-access query/launch operation unavailable; \
                         check kernel and sandbox support",
                    )
                } else {
                    error
                });
            }
        };
        if let Some(evidence) = &self.evidence
            && let Err(error) = evidence.publish_root(child.id())
        {
            if self.manages_process_group() {
                let _ = child.kill();
                let _ = wait_for_exit_without_reaping(child.id());
                let _ = terminate_run(child.id() as i32);
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
            let _ = self.finish_evidence(false);
            return Err(error);
        }
        Ok(child)
    }

    fn finish_launch_setup(
        &self,
        setup: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> io::Result<()> {
        if let Some(evidence) = &self.evidence {
            evidence.start()?;
        }
        if let Some(setup) = setup {
            setup
                .send(())
                .map_err(|_| io::Error::other("DBT launch owner was cancelled"))?;
        }
        Ok(())
    }

    fn wait_for_status(
        &self,
        mut child: Child,
        setup: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> io::Result<ExitStatus> {
        if let Err(error) = self.finish_launch_setup(setup) {
            self.terminate_and_reap(&mut child);
            return Err(error);
        }
        let status = self.reap_tree(child);
        self.finish_status(status)
    }

    /// Waits for the guest's root and, when this runner manages the process
    /// group, empties the group, then reaps the root. An error here means the
    /// tree may still hold the guest's output pipes open.
    fn reap_tree(&self, mut child: Child) -> io::Result<ExitStatus> {
        if !self.manages_process_group() {
            child.wait()
        } else {
            let observed = wait_for_exit_without_reaping(child.id());
            let terminated = match &observed {
                Ok(()) => terminate_run(child.id() as i32),
                Err(_) => Ok(()),
            };
            let status = child.wait();
            match (observed.and(terminated), status) {
                (Ok(()), status) => status,
                (Err(error), _) => Err(error),
            }
        }
    }

    /// Finishes protected evidence for a reaped tree and folds its result into
    /// the tree's status.
    fn finish_status(&self, status: io::Result<ExitStatus>) -> io::Result<ExitStatus> {
        if self.defer_evidence_finish
            && let Some(evidence) = &self.evidence
        {
            evidence.defer_finish(status.is_ok());
            return status;
        }
        let evidence = self.finish_evidence(status.is_ok());
        combine_status_and_evidence(status, evidence)
    }

    fn wait_with_output(
        &self,
        mut child: Child,
        setup: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> io::Result<Output> {
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
            let stop = Arc::new(AtomicU8::new(READ_ON));
            let stdout_stop = Arc::clone(&stop);
            let stderr_stop = Arc::clone(&stop);
            let stdout_reader = match std::thread::Builder::new()
                .spawn_scoped(scope, move || read_cancellable(&mut stdout, &stdout_stop))
            {
                Ok(reader) => reader,
                Err(error) => {
                    self.terminate_and_reap(&mut child);
                    return Err(error);
                }
            };
            let stderr_reader = match std::thread::Builder::new()
                .spawn_scoped(scope, move || read_cancellable(&mut stderr, &stderr_stop))
            {
                Ok(reader) => reader,
                Err(error) => {
                    stop.store(READ_DISCARD, Ordering::Release);
                    self.terminate_and_reap(&mut child);
                    let _ = stdout_reader.join();
                    return Err(error);
                }
            };
            // Input and blocking-waiter tasks, when needed, already exist.
            // Only now release START and the coordinator config handshake.
            let reaped = match self.finish_launch_setup(setup) {
                Ok(()) => self.reap_tree(child),
                Err(error) => {
                    self.terminate_and_reap(&mut child);
                    Err(error)
                }
            };
            let reap_failed = reaped.is_err();
            if reap_failed {
                // A tree member may still hold the pipes; what was read so far
                // is not the run's output.
                stop.store(READ_DISCARD, Ordering::Release);
            }
            let status = self.finish_status(reaped);
            if status.is_err() && !reap_failed {
                // The tree was reaped, so its members have closed the pipes,
                // and the readers normally reach end of file at once. A guest
                // may still have handed a pipe to a process outside the tree;
                // do not let that hold the error back. Keep what was read.
                let deadline = std::time::Instant::now() + FAILED_RUN_OUTPUT_DRAIN;
                while !(stdout_reader.is_finished() && stderr_reader.is_finished())
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                stop.store(READ_KEEP, Ordering::Release);
            }
            let stdout = stdout_reader
                .join()
                .map_err(|_| io::Error::other("DBT stdout reader thread panicked"));
            let stderr = stderr_reader
                .join()
                .map_err(|_| io::Error::other("DBT stderr reader thread panicked"));

            match status {
                Ok(status) => Ok(Output {
                    status,
                    stdout: stdout??,
                    stderr: stderr??,
                }),
                Err(error) => Err(match (stdout, stderr) {
                    (Ok(Ok(stdout)), Ok(Ok(stderr))) => {
                        DbtFailedRunOutput::attach(error, stdout, stderr)
                    }
                    _ => error,
                }),
            }
        })
    }

    fn wait_with_output_and_detached_reader<R>(
        &self,
        mut child: Child,
        input: R,
    ) -> io::Result<Output>
    where
        R: Read + Send + 'static,
    {
        let stdin = child.stdin.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "failed to open DBT guest stdin")
        })?;
        self.wait_with_output_and_input_writer(child, input, stdin, None)
    }

    fn wait_with_output_and_input_writer<R, W>(
        &self,
        mut child: Child,
        mut input: R,
        mut stdin: W,
        setup: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> io::Result<Output>
    where
        R: Read + Send + 'static,
        W: io::Write + Send + 'static,
    {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-84): Review detaching a source-blocked input pump at child exit.
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        if let Err(error) = std::thread::Builder::new().spawn(move || {
            let _ = sender.send(copy_streaming_input(&mut input, &mut stdin));
        }) {
            self.terminate_and_reap(&mut child);
            return Err(error);
        }
        let output = self.wait_with_output(child, setup)?;
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
            let _ = child.kill();
            let _ = wait_for_exit_without_reaping(child.id());
            let _ = terminate_run(child.id() as i32);
        } else {
            let _ = child.kill();
        }
        let _ = child.wait();
        let _ = self.finish_evidence(false);
    }

    /// Refuse before serving Config, retaining the actual cleanup status and
    /// already-written bytes without starting evidence or admitting the Tool.
    fn refuse_caller_admission(
        &self,
        mut child: Child,
        capture_output: bool,
        error: io::Error,
    ) -> io::Error {
        self.terminate_and_reap(&mut child);
        let captured: io::Result<ChildWait> = (|| {
            // Child caches its reaped status; this does not wait for another
            // process or replace a native status with a fabricated exit code.
            let status = child.wait()?;
            if !capture_output {
                return Ok(ChildWait::Status(status));
            }
            let mut stdout = child.stdout.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "missing refused caller stdout")
            })?;
            let mut stderr = child.stderr.take().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "missing refused caller stderr")
            })?;
            set_nonblocking(&stdout)?;
            set_nonblocking(&stderr)?;
            let stop = AtomicU8::new(READ_KEEP);
            Ok(ChildWait::Output(Output {
                status,
                stdout: read_cancellable(&mut stdout, &stop)?,
                stderr: read_cancellable(&mut stderr, &stop)?,
            }))
        })();
        match captured {
            Ok(wait) => DbtFailedRunOutput::attach_wait(error, wait),
            Err(capture) => io::Error::other(format!(
                "{error}; refused caller cleanup/output capture failed: {capture}"
            )),
        }
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
    ) -> io::Result<Command> {
        match self.prepare_command(guest, environment) {
            Ok(command) => Ok(command),
            Err(error) => {
                if let Some(evidence) = &self.evidence {
                    if let Err(claim) = evidence.claim_run() {
                        return Err(io::Error::new(
                            claim.kind(),
                            format!("{claim}; launch preparation failed: {error}"),
                        ));
                    }
                    // A refused preparation consumes its own one-shot attempt,
                    // closes pending evidence resources and cannot publish success.
                    let _ = evidence.finish(false);
                }
                Err(error)
            }
        }
    }

    fn prepare_command(
        &self,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
    ) -> io::Result<Command> {
        let prepared = prepare_program(guest, environment)?;
        let mut command = Command::new(&self.drrun);
        command
            .arg("-quiet")
            .arg("-app_path")
            .arg(&prepared.image)
            .arg("-disable_rseq");
        if self.private_placement == DbtPrivatePlacement::NoRandomOffset {
            // DynamoRIO parses address options as hexadecimal.
            command.args(["-vm_max_offset", "0x0"]);
        }
        command
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
            // The client finds the run's root from this pid (the process whose
            // parent is this one), whatever process groups or sessions the
            // guest makes.
            command
                .arg("-launcher-pid")
                .arg(std::process::id().to_string());
            // Outside a PID namespace of its own the run is contained by its
            // process group (`terminate_run`), which the client then keeps
            // the guest from leaving.
            if !is_namespace_init() {
                command.arg("-contain-by-process-group");
            }
        }
        if self.summary {
            command.arg("-summary");
        }
        command.arg("--");

        command.args(&prepared.arguments);
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
        command.env(HIDE_ENV_PREFIXES_ENV, self.encoded_private_environment());
        // DynamoRIO acts on the variable's presence, whatever its value, so
        // without the option it is removed from whichever environment the
        // launch would otherwise pass on: inherited, the guest's, or explicit.
        if self.tool_answers_brk {
            command.env(TOOL_ANSWERS_BRK_ENV, "1");
        } else {
            command.env_remove(TOOL_ANSWERS_BRK_ENV);
        }
        // A PID namespace's init contains the run by the namespace
        // (`terminate_run`); elsewhere the run gets its own process group.
        if self.manages_process_group() && !is_namespace_init() {
            command.process_group(0);
        }

        let diagnostic_file = self.diagnostic_file.clone();
        let execute_paths = prepared.execute_paths;
        // SAFETY: the access paths were allocated in the parent. The child only
        // issues raw faccessat2, personality, dup2 and fcntl operations; it does
        // not allocate, search PATH or inspect environment state.
        // Process-group isolation is configured above through
        // CommandExt::process_group; all settings survive drrun and guest execs.
        unsafe {
            command.pre_exec(move || {
                for path in &execute_paths {
                    if let Err(error) = query_execute_access(path) {
                        return Err(child_execute_access_error(error));
                    }
                }
                let diagnostic_source = diagnostic_file
                    .as_ref()
                    .map_or(libc::STDERR_FILENO, |file| file.as_raw_fd());
                duplicate_to_diagnostic_fd(diagnostic_source)?;
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
        Ok(command)
    }
}

/// Combine the guest's exit status with the evidence-session outcome.
///
/// Pulled out of `wait_for_status` as a free function ON PURPOSE: the contract
/// below is about ERROR KINDS, and every other evidence test in this file needs a
/// real DynamoRIO run to reach the code it checks. A contract that can only be
/// exercised end-to-end is a contract that stops being exercised. This one is
/// pure, so the regression test costs nothing and always runs.
///
/// THE CONTRACT: when the guest produced an exit status, THE GUEST RAN -- a
/// process that never launched cannot produce one -- so the resulting error must
/// not carry a kind a caller can read as a spawn failure.
///
/// This used to re-emit `error.kind()`, and the evidence layer produces
/// spawn-shaped kinds after the guest is already running: `PermissionDenied` from
/// its peer-credential checks (see `evidence.rs::handle_connection`, and
/// `protected_evidence_refuses_a_valid_frame_from_outside_the_guest_tree`, which
/// asserts exactly that kind), and `NotFound` from a bare `?` on
/// `/proc/<pid>/stat` when the peer exits before it is read.
///
/// No in-tree Reverie caller branches on the error returned from this arm; the
/// public status/output entry points propagate it. Current Hermit also wraps all
/// DBT runner errors in an unconditional "failed to launch drrun" message and
/// does not inspect `ErrorKind`, so this change alone does not correct that
/// diagnostic. It establishes the truthful distinction required by the paired
/// Hermit fix: errors produced after an exit status exists become `Other`,
/// while spawn errors bypass this helper and retain their original kind.
///
/// `other` is the honest kind: the failure is in evidence finalization, which is
/// not an `io::ErrorKind` any caller should branch on. The underlying error is
/// preserved verbatim in the message, which is where the cause has always been
/// read.
/// The output a DBT run captured before its status or its protected evidence
/// failed.
///
/// The output methods of [`DbtRunner`] return an [`io::Error`] that carries
/// this value, with the original error's kind and message, when the guest tree
/// was reaped. A run that ends on a backend or Tool failure usually wrote the
/// reason to its stderr just before, so a caller can still show it. Read it
/// with [`failed_run_output`]. The streams hold everything the tree wrote,
/// unless a guest handed a pipe to a process outside the tree: the readers
/// then stop after a bounded drain, and the streams end there.
#[derive(Debug)]
pub struct DbtFailedRunOutput {
    /// Actual reaped child status, when failure followed a completed wait.
    /// Earlier wait/evidence failures may not retain a status.
    pub status: Option<ExitStatus>,
    /// Everything the guest tree wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the guest tree wrote to stderr.
    pub stderr: Vec<u8>,
    error: io::Error,
}

impl DbtFailedRunOutput {
    fn attach(error: io::Error, stdout: Vec<u8>, stderr: Vec<u8>) -> io::Error {
        io::Error::new(
            error.kind(),
            Self {
                status: None,
                stdout,
                stderr,
                error,
            },
        )
    }

    fn attach_wait(error: io::Error, wait: ChildWait) -> io::Error {
        let status = wait.status();
        let (stdout, stderr) = match wait {
            ChildWait::Output(output) => (output.stdout, output.stderr),
            ChildWait::Status(_) => (Vec::new(), Vec::new()),
        };
        io::Error::new(
            error.kind(),
            Self {
                status: Some(status),
                stdout,
                stderr,
                error,
            },
        )
    }
}

impl fmt::Display for DbtFailedRunOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)?;
        if let Some(status) = self.status {
            write!(formatter, " (native child status: {status})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DbtFailedRunOutput {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// The output that a failed DBT run captured, when `error` came from one of
/// [`DbtRunner`]'s output methods and the output was read in full.
pub fn failed_run_output(error: &io::Error) -> Option<&DbtFailedRunOutput> {
    error.get_ref()?.downcast_ref()
}

fn combine_status_and_evidence(
    status: io::Result<ExitStatus>,
    evidence: io::Result<()>,
) -> io::Result<ExitStatus> {
    match (status, evidence) {
        (Ok(status), Ok(())) => Ok(status),
        // An error without an exit status keeps its own kind. Spawn errors
        // bypass this helper entirely and likewise remain unchanged.
        (Err(error), _) => Err(error),
        (Ok(status), Err(error)) => Err(io::Error::other(format!(
            "DBT guest exited with status {:?} while protected evidence failed: {error}",
            status.code()
        ))),
    }
}

/// A per-run sink that collects fixed-size DBT stats records from every
/// instrumented process image in the guest tree.
///
/// The native client appends one wire record per real runtime image to a shared
/// file (see `native/client.c`). A shared path with append-mode opens (O_APPEND)
/// keeps concurrent appends atomic and side-steps the drrun -> guest exec fd
/// inheritance problem the diagnostic fd works around. After the whole tree is
/// reaped, [`Self::capture`] retains the exact artifact; [`DbtStatsCapture::snapshot`]
/// decodes and commutatively aggregates its records.
pub struct DbtStatsSink {
    // Owns the temporary directory; dropping it removes the backing file. Held
    // until after `drain` reads the records.
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl DbtStatsSink {
    /// Allocate using this launcher's existing prefix and the caller's TMPDIR.
    pub fn new() -> io::Result<Self> {
        Self::with_prefix("reverie-dbt-stats-")
    }

    /// Allocate with a caller's existing visible name prefix and TMPDIR.
    ///
    /// A caller entering a private filesystem can declare a bind of
    /// [`Self::directory`] before launch, keeping this owner until completion.
    pub fn with_prefix(prefix: &str) -> io::Result<Self> {
        let directory = tempfile::Builder::new().prefix(prefix).tempdir()?;
        let path = directory.path().join("records.bin");
        Ok(Self {
            _directory: directory,
            path,
        })
    }

    /// Borrow the backing directory for an existing container mount declaration.
    pub fn directory(&self) -> &Path {
        self._directory.path()
    }

    /// Configure the native client to append its records to this owned sink.
    pub fn configure(&self, runner: DbtRunner) -> DbtRunner {
        self.configure_at(runner, self.directory())
    }

    /// Configure the client using this sink's directory as seen by the guest.
    ///
    /// The caller must make `guest_directory` refer to [`Self::directory`] in
    /// the guest's filesystem. This only changes the client argument: the sink
    /// still owns and reads its unique host path until [`Self::capture`].
    pub fn configure_at(&self, mut runner: DbtRunner, guest_directory: &Path) -> DbtRunner {
        for argument in self.client_arguments(guest_directory) {
            runner = runner.client_argument(argument);
        }
        runner
    }

    /// Read exact records after the caller has reaped the followed process tree.
    ///
    /// This consumes and removes the sink. Read failures remain completion data
    /// so the caller can preserve its guest-result and evidence-error precedence.
    pub fn capture(self) -> DbtStatsCapture {
        DbtStatsCapture::read(&self.path)
    }

    /// The `-stats_path <path>` client arguments passed to the native client.
    fn client_arguments(&self, directory: &Path) -> [OsString; 2] {
        let filename = self
            .path
            .file_name()
            .expect("the owned stats path has a filename");
        [
            OsString::from("-stats_path"),
            directory.join(filename).into_os_string(),
        ]
    }

    /// Decodes and aggregates every record written by the process tree.
    ///
    /// A missing file means no instrumented image reported (for example the
    /// guest died before `event_exit`); that yields an empty snapshot rather
    /// than an error. A present but malformed or truncated stream is a hard
    /// error, matching [`crate::backend_stats::DbtBackendStatsAggregator::absorb_wire_stream`].
    fn drain(self) -> io::Result<DbtBackendStatsSource> {
        self.capture().legacy_source()
    }
}

enum ChildWait {
    Status(ExitStatus),
    Output(Output),
}

impl ChildWait {
    fn status(&self) -> ExitStatus {
        match self {
            Self::Status(status) => *status,
            Self::Output(output) => output.status,
        }
    }
}

fn missing_coordinator_request_is_error(requested: bool, wait: &ChildWait) -> bool {
    !requested && wait.status().success()
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
#[derive(Debug)]
struct PreparedProgram {
    image: PathBuf,
    arguments: Vec<OsString>,
    execute_paths: Vec<CString>,
}

fn prepare_program(
    guest: &Command,
    environment: Option<&BTreeMap<OsString, OsString>>,
) -> io::Result<PreparedProgram> {
    if let Some(directory) = guest.get_current_dir() {
        // Command applies chdir before attempting exec. Preserve that ordering
        // before our parent-side image inspection, without changing parent cwd.
        // The child chdir remains authoritative if the directory changes later.
        if !directory.metadata()?.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        query_execute_access(&execute_path(directory)?).map_err(parent_execute_access_error)?;
    }
    let program = guest.get_program();
    if program.is_empty() {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }
    if program.as_bytes().contains(&b'/') {
        return prepare_candidate(guest, PathBuf::from(program));
    }

    let path = if let Some(environment) = environment {
        environment.get(OsStr::new(PATH_ENV)).cloned()
    } else {
        guest
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(PATH_ENV))
            .map_or_else(
                || env::var_os(PATH_ENV),
                |(_, value)| value.map(OsStr::to_os_string),
            )
    };
    let path = match path {
        Some(path) => path,
        None => default_search_path()?,
    };
    let mut denied = false;
    let mut last = io::Error::from_raw_os_error(libc::ENOENT);
    // Path::join normalizes empty/trailing components. Keep the exact spelling
    // execvp selects, including bare names and a component's trailing slash.
    for directory in path.as_bytes().split(|byte| *byte == b':') {
        let mut spelling = directory.to_vec();
        if !directory.is_empty() {
            spelling.push(b'/');
        }
        spelling.extend_from_slice(program.as_bytes());
        let candidate = PathBuf::from(OsStr::from_bytes(&spelling));
        match prepare_candidate(guest, candidate) {
            Ok(prepared) => return Ok(prepared),
            Err(error) => match error.raw_os_error() {
                Some(libc::EACCES) => {
                    denied = true;
                    last = error;
                }
                Some(
                    libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT,
                ) => {
                    last = error;
                }
                _ => return Err(error),
            },
        }
    }
    Err(if denied {
        io::Error::from_raw_os_error(libc::EACCES)
    } else {
        last
    })
}

fn default_search_path() -> io::Result<OsString> {
    // confstr includes the terminating NUL in the required size.
    let size = unsafe { libc::confstr(libc::_CS_PATH, std::ptr::null_mut(), 0) };
    if size == 0 {
        return Err(io::Error::other(
            "cannot obtain the system executable search path",
        ));
    }
    let mut bytes = vec![0u8; size];
    let written = unsafe { libc::confstr(libc::_CS_PATH, bytes.as_mut_ptr().cast(), bytes.len()) };
    if written != size || bytes.last() != Some(&0) {
        return Err(io::Error::other(
            "system executable search path changed while reading",
        ));
    }
    bytes.pop();
    Ok(OsString::from(OsStr::from_bytes(&bytes)))
}

fn inspection_path(guest: &Command, selected: &Path) -> PathBuf {
    match guest.get_current_dir() {
        Some(directory) if selected.is_relative() => directory.join(selected),
        _ => selected.to_path_buf(),
    }
}

fn execute_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "executable path contains a NUL byte",
        )
    })
}

fn require_executable_file(path: &Path) -> io::Result<()> {
    if !path.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    query_execute_access(&execute_path(path)?).map_err(parent_execute_access_error)
}

fn prepare_candidate(guest: &Command, selected: PathBuf) -> io::Result<PreparedProgram> {
    let inspected = inspection_path(guest, &selected);
    require_executable_file(&inspected)?;
    let mut execute_paths = vec![execute_path(&selected)?];
    let header = shebang(inspected.as_os_str()).map_err(|error| {
        // Execute access succeeded. A read failure is an unsupported image,
        // not an execvp EACCES that permits trying a different PATH candidate.
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "DBT requires a readable executable image; cannot inspect {}: {error}",
                inspected.display()
            ),
        )
    })?;
    let (image, arguments) = match header {
        Some((interpreter, optional_arguments)) => {
            require_executable_file(&inspection_path(guest, &interpreter))?;
            execute_paths.push(execute_path(&interpreter)?);
            let mut arguments = vec![interpreter.as_os_str().to_os_string()];
            arguments.extend(optional_arguments);
            arguments.push(selected.into_os_string());
            (interpreter, arguments)
        }
        None => (selected, vec![guest.get_program().to_os_string()]),
    };
    Ok(PreparedProgram {
        image,
        arguments,
        execute_paths,
    })
}

/// Ask the kernel with the effective IDs; never substitute mode-bit policy.
fn query_execute_access(path: &CStr) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn execute_access_unavailable(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::ENOSYS | libc::EINVAL)
    )
}

fn parent_execute_access_error(error: io::Error) -> io::Error {
    if execute_access_unavailable(&error) {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "kernel execute-access query unavailable ({error}); check kernel and sandbox support"
            ),
        )
    } else {
        error
    }
}

fn child_execute_access_error(error: io::Error) -> io::Error {
    // Command's child error channel carries only errno. This sentinel does not
    // claim the lost original errno or distinguish every possible spawn failure.
    if execute_access_unavailable(&error) {
        io::Error::from_raw_os_error(libc::EOPNOTSUPP)
    } else {
        error
    }
}

/// Caller mode currently requires no inherited seccomp restriction. A prctl
/// query executed by the application is not authoritative: an inherited filter
/// can return ERRNO|0 for that query. Read the still-owned root task from the
/// controller instead, before binding admission or serving any Config frame.
/// The server is only bound at this point, so the child cannot publish READY,
/// complete Claim, construct T, or enter application code while this runs.
fn require_unfiltered_caller_root(child: &Child) -> io::Result<()> {
    let pid = child.id();
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/status")).map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("caller-inherited-seccomp-unsupported: cannot read root status: {error}"),
            )
        })?;
    // read_to_string reaches EOF and closes its temporary descriptor before
    // returning. Root ownership keeps this PID from being recycled meanwhile.
    if !caller_root_status_is_unfiltered(&status, pid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "caller-inherited-seccomp-unsupported: root identity or unfiltered status not established",
        ));
    }
    Ok(())
}

fn caller_root_status_is_unfiltered(status: &str, pid: u32) -> bool {
    if pid == 0 || !status.ends_with('\n') || status.contains('\0') {
        return false;
    }
    let mut fields = [None; 4];
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        let index = match name {
            "Pid" => 0,
            "Tgid" => 1,
            "Seccomp" => 2,
            "Seccomp_filters" => 3,
            _ => continue,
        };
        let value = value.trim();
        if fields[index].is_some()
            || value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return false;
        }
        let Ok(value) = value.parse::<u64>() else {
            return false;
        };
        fields[index] = Some(value);
    }
    // Both mode and count are required: strict mode can have zero filters.
    fields == [Some(u64::from(pid)), Some(u64::from(pid)), Some(0), Some(0)]
        && reverie::pidfd_self::status_has_exactly_seccomp_filters(status, 0)
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

/// The output readers keep reading.
const READ_ON: u8 = 0;
/// Process-group cleanup failed: the readers stop and return an error.
const READ_DISCARD: u8 = 1;
/// The run failed after its tree was reaped: the readers read what is already
/// in their pipes, then stop and return everything they have read.
const READ_KEEP: u8 = 2;

/// At most this many more bytes are read after [`READ_KEEP`] is seen, so a
/// writer outside the reaped tree that never pauses cannot hold a reader.
const KEPT_OUTPUT_DRAIN_BYTES: usize = 1 << 20;

/// How long the output readers may keep draining after a run that was reaped
/// has failed. A reaped tree has closed its pipes, so this bounds only a pipe
/// that a guest handed to a process outside the tree.
const FAILED_RUN_OUTPUT_DRAIN: std::time::Duration = std::time::Duration::from_secs(1);

fn read_cancellable(reader: &mut impl Read, stop: &AtomicU8) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    // Bytes still allowed after READ_KEEP was seen; None until then.
    let mut kept_budget: Option<usize> = None;
    loop {
        match stop.load(Ordering::Acquire) {
            READ_DISCARD => {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "DBT output capture cancelled after process-group cleanup failed",
                ));
            }
            READ_KEEP if kept_budget.is_none() => kept_budget = Some(KEPT_OUTPUT_DRAIN_BYTES),
            _ => {}
        }
        let limit = match kept_budget {
            Some(0) => return Ok(bytes),
            Some(budget) => budget.min(buffer.len()),
            None => buffer.len(),
        };
        match reader.read(&mut buffer[..limit]) {
            Ok(0) => return Ok(bytes),
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if let Some(budget) = &mut kept_budget {
                    *budget = budget.saturating_sub(read);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // The pipe is empty for now. After READ_KEEP that is the end of
                // the output; otherwise wait for more, or for a stop, which the
                // top of the loop handles before the next read.
                if kept_budget.is_some() {
                    return Ok(bytes);
                }
                if stop.load(Ordering::Acquire) == READ_ON {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
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

/// Whether this process is the init of its PID namespace (pid 1), as Hermit's
/// container init is: then the namespace holds only the run.
fn is_namespace_init() -> bool {
    std::process::id() == 1
}

/// Kill every process of the run but its root, which has exited and is not
/// yet reaped, and wait until none is left.
///
/// As a PID namespace's init, kill and reap direct children repeatedly. Their
/// descendants are adopted by init even if they changed process groups or
/// sessions. Elsewhere, containment is by the run's own process group.
fn terminate_run(root: i32) -> io::Result<()> {
    if root <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DBT containment: invalid run root PID",
        ));
    }
    if !is_namespace_init() {
        terminate_process_group(root)?;
        return wait_for_process_group_no_live_members(root);
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut left = false;
        for (pid, state) in own_children(Path::new("/proc"))? {
            if pid == root {
                continue;
            }
            left = true;
            if matches!(state, 'Z' | 'X') {
                // Reaping happens only here, after the complete scan. A dying
                // direct child remains visible as a zombie until then, and its
                // descendants have been adopted before it can be reaped. Thus
                // a nonempty pass always precedes checking for those orphans.
                let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
                if result == pid {
                    continue;
                }
                if result == -1 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                    continue;
                }
                // A thread-group leader can be a zombie while other threads
                // still run. waitpid returns zero in that case: kill the
                // group through its positive PID before trying to reap again.
            }
            // Only positive, namespace-local child PIDs are signaled. Keep
            // the root zombie for the caller's Child::wait(), which also
            // prevents its PID/process-group identity being reused.
            let result = unsafe { libc::kill(pid, libc::SIGKILL) };
            if result == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        if !left {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DBT containment: the run's processes did not die within 5 s",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn own_children(proc: &Path) -> io::Result<Vec<(i32, char)>> {
    let me = std::process::id() as i32;
    // A proc mount inherited from an ancestor PID namespace uses different
    // numeric PIDs. Never use those numbers as local signal destinations.
    if std::fs::read_link(proc.join("self"))? != Path::new(&me.to_string()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DBT containment: /proc is not mounted for the current PID namespace",
        ));
    }
    let mut children = Vec::new();
    for entry in std::fs::read_dir(proc)? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let stat = match std::fs::read(entry.path().join("stat")) {
            Ok(stat) => stat,
            // Nonchildren may disappear during the scan. An owned child
            // cannot disappear before we reap it; other read errors must not
            // turn an incomplete scan into successful containment.
            Err(error) if proc_entry_vanished(&error) => continue,
            Err(error) => return Err(error),
        };
        let (state, parent) = child_stat(&stat)?;
        if parent == me {
            if pid <= 1 || pid == me {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DBT containment: invalid child PID in /proc",
                ));
            }
            children.push((pid, state));
        }
    }
    Ok(children)
}

fn proc_entry_vanished(error: &io::Error) -> bool {
    // proc_single_show can return ESRCH when the process disappears after
    // open but before read. Rust does not classify that errno as NotFound.
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn child_stat(stat: &[u8]) -> io::Result<(char, i32)> {
    // comm can contain spaces, ')' and non-UTF-8 bytes; only the fields after
    // its final ')' are ASCII. Do not parse the name as whitespace fields.
    let parsed = (|| {
        let end = stat.iter().rposition(|byte| *byte == b')')?;
        let tail = std::str::from_utf8(&stat[end + 1..]).ok()?;
        let mut fields = tail.split_ascii_whitespace();
        let state = fields.next()?;
        if state.len() != 1 || !"RSDZTtXxKWPI".contains(state) {
            return None;
        }
        let parent = fields.next()?.parse::<i32>().ok()?;
        (parent >= 0).then_some((state.chars().next()?, parent))
    })();
    parsed.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "DBT containment: malformed /proc stat",
        )
    })
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

fn shebang(program: &OsStr) -> io::Result<Option<(PathBuf, Vec<OsString>)>> {
    let mut bytes = Vec::new();
    File::open(Path::new(program))?
        .take(BINPRM_BUF_SIZE as u64)
        .read_to_end(&mut bytes)?;
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }

    let body = &bytes[2..];
    let Some(start) = body.iter().position(|byte| !matches!(byte, b' ' | b'\t')) else {
        return Ok(None);
    };
    let end = body[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(body.len(), |offset| start + offset);
    let mut fields = body[start..end]
        .split(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
        .filter(|field| !field.is_empty());
    let Some(interpreter) = fields.next() else {
        return Ok(None);
    };
    let interpreter = PathBuf::from(OsStr::from_bytes(interpreter));
    let arguments = fields
        .map(|field| OsString::from(OsStr::from_bytes(field)))
        .collect();
    Ok(Some((interpreter, arguments)))
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

fn require_writable_diagnostic_fd(descriptor: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DBT diagnostic file is not writable",
        ));
    }
    Ok(())
}

fn clone_diagnostic_fd(source: libc::c_int) -> io::Result<File> {
    // Keep the owned descriptor out of the standard-stream range. Command's
    // child setup can replace 0, 1, and 2 before pre_exec hooks run.
    let descriptor = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 3) };
    if descriptor == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn duplicate_to_diagnostic_fd(source: libc::c_int) -> io::Result<()> {
    if source != DIAGNOSTIC_FD {
        if unsafe { libc::dup2(source, DIAGNOSTIC_FD) } == -1 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }

    // dup2(fd, fd) is a no-op and therefore does not clear FD_CLOEXEC. A
    // caller can legitimately supply descriptor 198, so clear the flag
    // explicitly rather than letting the diagnostic channel disappear at exec.
    let flags = unsafe { libc::fcntl(source, libc::F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(source, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    mod caller_transport_failure;
    mod fcntl_owner_identity_live;
    mod inherited_input;
    mod namespace_cleanup;
    mod pidfd_identity_live;
    mod queued_signal_identity_live;
    mod startup_failure;
    mod stats_capture;
    mod thread_start_live;
    use std::io::Seek as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::ExitStatusExt as _;

    use super::*;

    const TEST_DRRUN_STDERR: &str = "REVERIE_DBT_TEST_DRRUN_STDERR";
    const TEST_DRRUN_DIAGNOSTIC: &str = "REVERIE_DBT_TEST_DRRUN_DIAGNOSTIC";

    #[test]
    fn caller_root_status_requires_exact_identity_and_unfiltered_mode() {
        let valid = "Name:\tguest\nTgid:\t123\nPid:\t123\nSeccomp:\t0\nSeccomp_filters:\t0\n";
        assert!(caller_root_status_is_unfiltered(valid, 123));
        assert!(!caller_root_status_is_unfiltered(valid, 0));
        assert!(!caller_root_status_is_unfiltered(valid, 124));
        assert!(!caller_root_status_is_unfiltered(valid.trim_end(), 123));
        for invalid in [
            valid.replace("Tgid:\t123", "Tgid:\t124"),
            valid.replace("Pid:\t123", "Pid:\t124"),
            // Strict mode has no BPF filters but is still restricted.
            valid.replace("Seccomp:\t0", "Seccomp:\t1"),
            valid.replace("Seccomp:\t0", "Seccomp:\t2"),
            valid.replace("Seccomp_filters:\t0", "Seccomp_filters:\t1"),
            valid.replace("Pid:\t123", "Pid:\t+123"),
            valid.replace("Pid:\t123", "Pid:\t123 123"),
            valid.replace("Pid:\t123", "Pid:\t18446744073709551616"),
            valid.replace("Seccomp:\t0", "Seccomp:\t"),
            valid.replace("Seccomp:\t0", "Seccomp:\tinvalid"),
            valid.replace("Seccomp:\t0", "Seccomp 0"),
            format!("{valid}\0\n"),
        ] {
            assert!(
                !caller_root_status_is_unfiltered(&invalid, 123),
                "{invalid:?}"
            );
        }
        for field in [
            "Tgid:\t123\n",
            "Pid:\t123\n",
            "Seccomp:\t0\n",
            "Seccomp_filters:\t0\n",
        ] {
            assert!(!caller_root_status_is_unfiltered(
                &valid.replace(field, ""),
                123
            ));
            assert!(!caller_root_status_is_unfiltered(
                &format!("{valid}{field}"),
                123
            ));
        }
    }

    #[test]
    fn failed_guest_status_is_preserved_before_coordinator_request() {
        let bootstrap_failure = ChildWait::Status(ExitStatus::from_raw(125 << 8));
        let other_failure = ChildWait::Status(ExitStatus::from_raw(1 << 8));
        let success = ChildWait::Status(ExitStatus::from_raw(0));

        assert!(!missing_coordinator_request_is_error(
            false,
            &bootstrap_failure
        ));
        assert!(!missing_coordinator_request_is_error(false, &other_failure));
        assert!(missing_coordinator_request_is_error(false, &success));
        assert!(!missing_coordinator_request_is_error(true, &success));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn config_only_bootstrap_cannot_satisfy_the_application_request_guard() {
        use reverie::GlobalRPC as _;
        use reverie::Tid;
        use reverie_rpc_transport::BlockingRpcClient;

        use crate::Counter2Global;
        use crate::counter2_global::Counter2Request;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("coordinator.sock");
        let global = Arc::new(Counter2Global::default());
        let requested = Arc::new(AtomicBool::new(false));
        let server =
            RpcServer::bind_with_readiness(&path, Arc::clone(&global), (), Arc::clone(&requested))
                .unwrap();
        let serving = tokio::spawn(server.serve());
        let bootstrap_path = path.clone();
        tokio::task::spawn_blocking(move || {
            crate::sync_rpc::read_initial_config::<()>(&bootstrap_path).unwrap();
        })
        .await
        .unwrap();
        assert!(!requested.load(Ordering::Acquire));
        assert_eq!(global.snapshot(), (0, 0, 0));
        assert!(missing_coordinator_request_is_error(
            false,
            &ChildWait::Status(ExitStatus::from_raw(0)),
        ));

        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let client =
                BlockingRpcClient::<Counter2Global>::connect(&path, Tid::from_raw(17)).unwrap();
            runtime.block_on(client.send_rpc(Counter2Request {
                syscalls: 5,
                threads: 2,
            }));
        })
        .await
        .unwrap();
        assert!(requested.load(Ordering::Acquire));
        assert_eq!(global.snapshot(), (5, 1, 2));
        assert!(!missing_coordinator_request_is_error(
            true,
            &ChildWait::Status(ExitStatus::from_raw(0)),
        ));
        serving.abort();
        assert!(serving.await.unwrap_err().is_cancelled());
    }

    fn runner() -> DbtRunner {
        DbtRunner {
            drrun: PathBuf::from("/opt/dynamorio/bin64/drrun"),
            client: PathBuf::from("/opt/reverie/libreverie_dbt_client.so"),
            client_arguments: Vec::new(),
            private_placement: DbtPrivatePlacement::SdkDefault,
            private_environment: Vec::new(),
            diagnostic_file: None,
            evidence: None,
            evidence_log_level: DbtEvidenceLogLevel::Info,
            summary: false,
            isolated_process_group: false,
            terminate_process_group_on_exit: false,
            defer_evidence_finish: false,
            tool_answers_brk: false,
            caller_tool: false,
        }
    }

    // These stand-ins exercise I/O/lifecycle behavior, not public frontend
    // compatibility. The public constructor is never relaxed under cfg(test).
    fn fixture_runner(drrun: PathBuf, client: PathBuf) -> io::Result<DbtRunner> {
        require_file(&drrun, "fixture launcher")?;
        require_file(&client, "fixture client")?;
        Ok(DbtRunner {
            drrun,
            client,
            ..runner()
        })
    }

    // Live fixture wrappers retain their original timeout/session/PID-namespace
    // topology and output lifecycle. Validate the real maintained frontend first,
    // then substitute only the fixed wrapper created by the calling private test.
    // This gives no public-constructor wrapper-support or selection credit.
    fn bounded_fixture_runner(
        wrapper: impl Into<PathBuf>,
        client: impl Into<PathBuf>,
    ) -> io::Result<DbtRunner> {
        let mut runner = DbtRunner::new(crate::bundled_drrun_path(), client)?;
        let wrapper = wrapper.into();
        require_file(&wrapper, "owned fixture supervisor")?;
        runner.drrun = wrapper;
        Ok(runner)
    }

    #[test]
    fn cancelled_launch_setup_reaps_the_owned_child() {
        for (capture, process_group) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let runner = runner().terminate_process_group_on_exit(process_group);
            let mut command = Command::new("/bin/sleep");
            command.arg("60").process_group(0);
            if capture {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
            let child = command.spawn().unwrap();
            let pid = child.id();
            let (sender, receiver) = tokio::sync::oneshot::channel();
            drop(receiver);
            let error = if capture {
                runner.wait_with_output(child, Some(sender)).unwrap_err()
            } else {
                runner.wait_for_status(child, Some(sender)).unwrap_err()
            };
            assert!(error.to_string().contains("DBT launch owner was cancelled"));
            // Cleanup, including reap, completes before setup failure returns.
            let waited = unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) };
            assert_eq!(waited, -1);
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    async fn queued_launch_readiness_survives_coordinator_cancellation() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("coordinator.sock");
        let requested = Arc::new(AtomicBool::new(false));
        let server = RpcServer::bind_with_readiness(
            &socket,
            Arc::new(crate::Counter2Global::default()),
            (),
            Arc::clone(&requested),
        )
        .unwrap();
        let evidence = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .private_environment_key("HERMIT_DBT_COUNTER2")
            .expect("valid Tool environment key")
            .evidence_file(&evidence)
            .unwrap()
            .defer_evidence_finish()
            .terminate_process_group_on_exit(true)
            .client_argument("-external-global");
        let mut guest = Command::new("/bin/echo");
        guest
            .arg("application-started")
            .env("HERMIT_DBT_COUNTER2", "1");
        let mut command = runner.command(&guest, None).unwrap();
        command
            .env(crate::sync_rpc::RPC_SOCKET_ENV, &socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        let pid = child.id() as i32;
        drop(command);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let (done, completed) = std::sync::mpsc::channel();
        let waiting_runner = runner.clone();
        let waiter = std::thread::spawn(move || {
            let _ = done.send(waiting_runner.wait_with_output(child, Some(sender)));
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while receiver.is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Observe successful send without consuming readiness. This is the
        // window after setup succeeds but before run_with_global serves RPC.
        let readiness_queued = !receiver.is_empty();
        drop(receiver);
        drop(server);
        let result = completed.recv_timeout(std::time::Duration::from_secs(10));
        if result.is_err() {
            // Bound a regression without allowing cleanup to make it pass.
            terminate_process_group(pid).unwrap();
        }
        waiter.join().unwrap();
        assert!(readiness_queued, "launch readiness was not queued");
        let output = result
            .expect("cancelled coordinator left its guest running")
            .unwrap();
        assert_eq!(output.status.signal(), Some(libc::SIGKILL), "{output:?}");
        assert!(output.stdout.is_empty(), "application ran: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("reverie-dbt: startup refused:"),
            "the real initial-config request did not refuse startup: {output:?}"
        );
        assert!(!requested.load(Ordering::Acquire));
        assert!(runner.finish_deferred_evidence(output.status).is_err());
        let waited = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }

    fn write_executable_script(path: &Path, contents: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::write(path, contents).unwrap();
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    fn fake_drrun(directory: &Path) -> PathBuf {
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake_drrun.sh");
        let path = directory.join("drrun");
        std::os::unix::fs::symlink(source, &path).unwrap();
        path
    }

    fn fake_client() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
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
            .command(&Command::new("/bin/true"), None)
            .unwrap();
        assert!(
            !cleanup_only
                .get_args()
                .any(|argument| argument == OsStr::new("-launcher-pid"))
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
    fn private_placement_is_replaced_and_preserved_by_clones() {
        let configured = runner().private_placement(DbtPrivatePlacement::NoRandomOffset);
        let guest = Command::new("/bin/true");
        let expected = [
            "-quiet",
            "-app_path",
            "/bin/true",
            "-disable_rseq",
            "-vm_max_offset",
            "0x0",
            "-stack_size",
            "2M",
            "-c",
            "/opt/reverie/libreverie_dbt_client.so",
            "-diagnostic_fd",
            "198",
            "--",
            "/bin/true",
        ]
        .map(OsStr::new);
        assert_eq!(
            configured
                .command(&guest, None)
                .unwrap()
                .get_args()
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            configured
                .clone()
                .command(&guest, None)
                .unwrap()
                .get_args()
                .collect::<Vec<_>>(),
            expected
        );
        let reset = configured.private_placement(DbtPrivatePlacement::SdkDefault);
        let default = runner().command(&guest, None).unwrap();
        assert_eq!(
            reset
                .command(&guest, None)
                .unwrap()
                .get_args()
                .collect::<Vec<_>>(),
            default.get_args().collect::<Vec<_>>()
        );
    }

    #[test]
    fn client_arguments_and_isolation_flag_precede_guest_separator() {
        let wrapped = runner()
            .client_argument("-panic-on-unsupported-syscalls")
            .isolated_process_group(true)
            .command(&Command::new("/bin/true"), None)
            .unwrap();
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                "-quiet",
                "-app_path",
                "/bin/true",
                "-disable_rseq",
                "-stack_size",
                "2M",
                "-c",
                "/opt/reverie/libreverie_dbt_client.so",
                "-diagnostic_fd",
                "198",
                "-panic-on-unsupported-syscalls",
                "-launcher-pid",
                &std::process::id().to_string(),
                "-contain-by-process-group",
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

        let wrapped = runner().command(&guest, None).unwrap();
        assert_eq!(
            wrapped.get_program(),
            OsStr::new("/opt/dynamorio/bin64/drrun")
        );
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                "-quiet",
                "-app_path",
                "/bin/echo",
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
    fn rejects_nonexecutable_shebang_before_starting_launcher() {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("guest-script");
        std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("guest-link");
        std::os::unix::fs::symlink(&script, &link).unwrap();
        let marker = directory.path().join("launcher-started");
        let drrun = directory.path().join("drrun");
        write_executable_script(
            &drrun,
            b"#!/bin/sh\nprintf started > \"$DBT_LAUNCH_WITNESS\"\nexit 0\n",
        );
        let runner = DbtRunner { drrun, ..runner() };

        for program in [
            script.as_os_str(),
            OsStr::new("./guest-script"),
            OsStr::new("guest-script"),
            link.as_os_str(),
        ] {
            let mut guest = Command::new(program);
            guest
                .current_dir(directory.path())
                .env(PATH_ENV, directory.path())
                .env("DBT_LAUNCH_WITNESS", &marker);
            let error = runner
                .output(&guest)
                .expect_err("a non-executable script must refuse before starting the launcher");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(
                !marker.exists(),
                "the launcher ran before permission refusal"
            );

            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let output = runner.output(&guest).unwrap();
            assert!(output.status.success(), "{output:?}");
            assert_eq!(std::fs::read(&marker).unwrap(), b"started");
            std::fs::remove_file(&marker).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn marker_runner(directory: &Path) -> (DbtRunner, PathBuf) {
        let marker = directory.join("launcher-started");
        let drrun = directory.join("marker-drrun");
        write_executable_script(
            &drrun,
            b"#!/bin/sh\nprintf started > \"$DBT_LAUNCH_WITNESS\"\nexit 0\n",
        );
        (DbtRunner { drrun, ..runner() }, marker)
    }

    #[test]
    fn child_execute_access_recheck_refuses_permission_change() {
        for deny_interpreter in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let interpreter = directory.path().join("interpreter");
            write_executable_script(&interpreter, b"#!/bin/sh\nexit 0\n");
            let script = directory.path().join("script");
            write_executable_script(
                &script,
                format!("#!{}\nexit 0\n", interpreter.display()).as_bytes(),
            );
            let (runner, marker) = marker_runner(directory.path());
            let mut guest = Command::new("./script");
            guest
                .current_dir(directory.path())
                .env("DBT_LAUNCH_WITNESS", &marker);
            let mut prepared = runner.command(&guest, None).unwrap();
            let denied = if deny_interpreter {
                &interpreter
            } else {
                &script
            };
            std::fs::set_permissions(denied, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = runner.spawn_command(&mut prepared).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(!marker.exists());
            std::fs::set_permissions(denied, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(runner.output(&guest).unwrap().status.success());
            assert_eq!(std::fs::read(&marker).unwrap(), b"started");
        }
    }

    #[test]
    fn preparation_refusal_finishes_evidence_without_publication() {
        for cwd_case in ["unchanged", "missing", "non-directory"] {
            let directory = tempfile::tempdir().unwrap();
            let denied = directory.path().join("denied");
            std::fs::write(&denied, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o600)).unwrap();
            let (runner, marker) = marker_runner(directory.path());
            let output = tempfile::tempfile().unwrap();
            let runner = runner.evidence_file(&output).unwrap();
            let mut guest = Command::new(&denied);
            guest.env("DBT_LAUNCH_WITNESS", &marker);
            let expected_errno = match cwd_case {
                "missing" => {
                    guest.current_dir(directory.path().join("missing"));
                    libc::ENOENT
                }
                "non-directory" => {
                    guest.current_dir(&denied);
                    libc::ENOTDIR
                }
                _ => libc::EACCES,
            };
            let error = runner.output(&guest).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(expected_errno));
            assert!(!marker.exists());
            assert_eq!(output.metadata().unwrap().len(), 0);
            let evidence = runner.evidence.as_ref().unwrap();
            assert_eq!(
                evidence.claim_run().unwrap_err().kind(),
                io::ErrorKind::AlreadyExists
            );
            let first = evidence.finish(false).unwrap_err().to_string();
            assert!(first.contains("never started"), "{first}");
            assert_eq!(evidence.finish(false).unwrap_err().to_string(), first);
        }
    }

    #[test]
    fn refused_preparation_preserves_an_already_claimed_evidence_attempt() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let file = tempfile::tempfile().unwrap();
        let runner = runner().evidence_file(&file).unwrap();
        let evidence = runner.evidence.as_ref().unwrap();
        evidence.claim_run().unwrap();
        let primary = std::fs::metadata(&missing).unwrap_err().to_string();
        let error = runner.command(&Command::new(&missing), None).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains(&primary), "{error}");
        assert!(error.to_string().contains("one-shot"), "{error}");
        // Publication still requires RUNNING: the refused second attempt did
        // not finalize the first one's state or consume its root slot.
        evidence.publish_root(std::process::id()).unwrap();
        assert!(
            evidence
                .finish(false)
                .unwrap_err()
                .to_string()
                .contains("never started")
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
    }

    #[test]
    fn execute_access_query_unavailable_is_not_guest_permission_denial() {
        for errno in [libc::EPERM, libc::ENOSYS, libc::EINVAL] {
            let error = parent_execute_access_error(io::Error::from_raw_os_error(errno));
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(
                error
                    .to_string()
                    .contains("kernel execute-access query unavailable")
            );
            assert!(
                error
                    .to_string()
                    .contains(&io::Error::from_raw_os_error(errno).to_string())
            );
            assert_eq!(
                child_execute_access_error(io::Error::from_raw_os_error(errno)).raw_os_error(),
                Some(libc::EOPNOTSUPP),
            );
        }
        for errno in [libc::EACCES, libc::ENOENT] {
            assert_eq!(
                parent_execute_access_error(io::Error::from_raw_os_error(errno)).raw_os_error(),
                Some(errno),
            );
            assert_eq!(
                child_execute_access_error(io::Error::from_raw_os_error(errno)).raw_os_error(),
                Some(errno),
            );
        }
        let mut command = runner().command(&Command::new("/bin/true"), None).unwrap();
        // This independent operation runs after the access query. A raw EPERM
        // here must not be attributed to the query or normalized.
        unsafe {
            command.pre_exec(|| Err(io::Error::from_raw_os_error(libc::EPERM)));
        }
        let error = runner().spawn_command(&mut command).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        assert!(!error.to_string().contains("query"));
    }

    #[test]
    fn path_candidates_preserve_execvp_failure_precedence() {
        let directory = tempfile::tempdir().unwrap();
        let bad = directory.path().join("bad");
        let good = directory.path().join("good");
        let missing = directory.path().join("missing");
        std::fs::create_dir(&bad).unwrap();
        std::fs::create_dir(&good).unwrap();
        let candidate = bad.join("probe");
        let valid = good.join("probe");
        std::fs::copy("/bin/true", &valid).unwrap();
        std::fs::set_permissions(&valid, std::fs::Permissions::from_mode(0o700)).unwrap();
        let denied_interpreter = directory.path().join("denied-interpreter");
        std::fs::write(&denied_interpreter, b"\x7fELF").unwrap();
        std::fs::set_permissions(&denied_interpreter, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        for (name, bytes, errno) in [
            ("directory", None, libc::EACCES),
            ("denied", Some(b"\x7fELF".to_vec()), libc::EACCES),
            (
                "missing-interpreter",
                Some(format!("#!{}\n", missing.display()).into_bytes()),
                libc::ENOENT,
            ),
            (
                "denied-interpreter",
                Some(format!("#!{}\n", denied_interpreter.display()).into_bytes()),
                libc::EACCES,
            ),
        ] {
            match bytes {
                None => std::fs::create_dir(&candidate).unwrap(),
                Some(bytes) => {
                    std::fs::write(&candidate, bytes).unwrap();
                    let mode = if name == "denied" { 0o600 } else { 0o700 };
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(mode))
                        .unwrap();
                }
            }
            let mut guest = Command::new("probe");
            guest.env(PATH_ENV, env::join_paths([&bad, &good]).unwrap());
            assert_eq!(prepare_program(&guest, None).unwrap().image, valid);
            assert!(guest.output().unwrap().status.success(), "native {name}");
            guest.env(PATH_ENV, env::join_paths([&bad, &missing]).unwrap());
            assert_eq!(
                prepare_program(&guest, None).unwrap_err().raw_os_error(),
                Some(errno),
                "{name}"
            );
            assert_eq!(
                guest.output().unwrap_err().raw_os_error(),
                Some(errno),
                "native {name}"
            );
            if candidate.is_dir() {
                std::fs::remove_dir(&candidate).unwrap();
            } else {
                std::fs::remove_file(&candidate).unwrap();
            }
        }
    }

    #[test]
    fn public_constructor_requires_attested_frontend() {
        let selected = crate::bundled_drrun_path();
        assert!(DbtRunner::new(selected, fake_client()).is_ok());
        let directory = tempfile::tempdir().unwrap();
        let copied = directory.path().join("relocated-drrun");
        std::fs::copy(selected, &copied).unwrap();
        assert!(DbtRunner::new(&copied, fake_client()).is_ok());
        let mut bytes = std::fs::read(&copied).unwrap();
        let at = bytes.len() - 1;
        bytes[at] ^= 1;
        std::fs::write(&copied, bytes).unwrap();
        for frontend in [&copied, &fake_drrun(directory.path())] {
            let error = DbtRunner::new(frontend, fake_client()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            assert!(
                error
                    .to_string()
                    .contains("incompatible DynamoRIO frontend")
            );
            assert!(error.to_string().contains("rebuild the consuming crate"));
        }
        let cwd = env::current_dir().unwrap();
        let mut relative = PathBuf::new();
        for _ in cwd.components().skip(1) {
            relative.push("..");
        }
        relative.push(selected.strip_prefix("/").unwrap());
        let runner = DbtRunner::new(&relative, fake_client()).unwrap();
        let mut guest = Command::new("/bin/true");
        guest.current_dir(directory.path());
        let command = runner.command(&guest, None).unwrap();
        assert_eq!(command.get_program(), cwd.join(relative).as_os_str());
        assert!(Path::new(command.get_program()).is_absolute());
        assert_eq!(
            Sha256::digest(std::fs::read(command.get_program()).unwrap()),
            Sha256::digest(std::fs::read(selected).unwrap()),
        );
    }

    #[test]
    fn wraps_shebang_program_with_its_interpreter() {
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("guest-script");
        write_executable_script(&script, b"#!/usr/bin/env bash\necho guest\n");
        let mut guest = Command::new(&script);
        guest.arg("argument");

        let wrapped = runner().command(&guest, None).unwrap();
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-app_path"),
                OsStr::new("/usr/bin/env"),
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

        let wrapped = runner().command(&guest, None).unwrap();
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-app_path"),
                OsStr::new("/bin/sh"),
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

        let wrapped = runner().command(&guest, Some(&environment)).unwrap();
        assert_eq!(
            wrapped.get_args().collect::<Vec<_>>(),
            [
                OsStr::new("-quiet"),
                OsStr::new("-app_path"),
                OsStr::new("/usr/bin/env"),
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

        let wrapped = runner().command(&guest, None).unwrap();
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[11], OsStr::new("/bin/sh"));
        assert_eq!(args[12], OsStr::new("bin/guest-script"));
        assert_eq!(args[1], OsStr::new("-app_path"));
        assert_eq!(args[2], OsStr::new("/bin/sh"));
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

        let wrapped = runner().command(&guest, None).unwrap();
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[11], OsStr::new("/bin/sh"));
        assert_eq!(args[12], wrapper.as_os_str());
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

        let wrapped = runner().command(&guest, None).unwrap();
        let args = wrapped.get_args().collect::<Vec<_>>();
        assert_eq!(args[1], OsStr::new("-app_path"));
        assert_eq!(args[2], executable.as_os_str());
        assert_eq!(args[11], OsStr::new("guest-elf"));
        assert_eq!(args[12], OsStr::new("argument"));
    }

    #[test]
    fn exact_environment_replaces_launcher_environment() {
        let guest = Command::new("/usr/bin/env");
        let environment = BTreeMap::from([(OsString::from("ONLY"), OsString::from("guest"))]);

        let wrapped = runner().command(&guest, Some(&environment)).unwrap();
        // drrun also receives the bundled DynamoRIO's prefix list, a
        // `DYNAMORIO_*` variable DynamoRIO removes from the guest's environment
        // with the prefixed ones (tests/guest_environment_live.rs).
        assert_eq!(
            wrapped.get_envs().collect::<Vec<_>>(),
            [
                (
                    OsStr::new(HIDE_ENV_PREFIXES_ENV),
                    Some(OsStr::new(
                        "HERMIT_DBT_PREEMPT_ANYPC=:HERMIT_DBT_RPC_SOCKET="
                    ))
                ),
                (OsStr::new("ONLY"), Some(OsStr::new("guest")))
            ]
        );
    }

    #[test]
    fn private_environment_selection_is_canonical_and_survives_cloning() {
        let selected = runner()
            .private_environment_key("TOOL_SECRET")
            .unwrap()
            .private_environment_prefix("TOOL_PRIVATE_")
            .unwrap()
            .private_environment_key("TOOL_PRIVATE_ONE")
            .unwrap()
            .private_environment_key("TOOL_SECRET")
            .unwrap();
        let reordered = runner()
            .private_environment_prefix("TOOL_PRIVATE_")
            .unwrap()
            .private_environment_key("TOOL_SECRET")
            .unwrap();
        let expected = OsStr::new(
            "HERMIT_DBT_PREEMPT_ANYPC=:HERMIT_DBT_RPC_SOCKET=:TOOL_PRIVATE_:TOOL_SECRET=",
        );
        for configured in [selected.clone(), selected, reordered] {
            assert_eq!(configured.encoded_private_environment(), expected);
        }
        assert_eq!(
            runner()
                .private_environment_key("TOOL_SECRET")
                .unwrap()
                .private_environment_prefix("TOOL_")
                .unwrap()
                .encoded_private_environment(),
            "HERMIT_DBT_PREEMPT_ANYPC=:HERMIT_DBT_RPC_SOCKET=:TOOL_"
        );
    }

    #[test]
    fn private_environment_selectors_reject_ambiguous_bytes_and_preserve_non_utf8() {
        for invalid in [b"".as_slice(), b"NUL\0KEY", b"TWO:KEYS", b"KEY=VALUE"] {
            let invalid = OsStr::from_bytes(invalid).to_os_string();
            for result in [
                runner().private_environment_key(invalid.clone()),
                runner().private_environment_prefix(invalid.clone()),
            ] {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            }
        }
        let configured = runner()
            .private_environment_key(OsStr::from_bytes(b"KEY_\xff"))
            .unwrap()
            .private_environment_prefix(OsStr::from_bytes(b"PREFIX_\xfe"))
            .unwrap();
        assert_eq!(
            configured.encoded_private_environment().as_bytes(),
            b"HERMIT_DBT_PREEMPT_ANYPC=:HERMIT_DBT_RPC_SOCKET=:KEY_\xff=:PREFIX_\xfe"
        );
    }

    #[test]
    fn guest_environment_cannot_replace_the_launchers_private_selection() {
        let selected = runner().private_environment_key("TOOL_SECRET").unwrap();
        for value in ["", "FORGED_"] {
            let environment =
                BTreeMap::from([(OsString::from(HIDE_ENV_PREFIXES_ENV), OsString::from(value))]);
            let plain = Command::new("/usr/bin/true");
            let mut guest = Command::new("/usr/bin/true");
            guest.env(HIDE_ENV_PREFIXES_ENV, value);
            for (guest, environment) in [(&plain, Some(&environment)), (&guest, None)] {
                assert_eq!(
                    selected
                        .command(guest, environment)
                        .unwrap()
                        .get_envs()
                        .find(|(key, _)| *key == HIDE_ENV_PREFIXES_ENV)
                        .unwrap()
                        .1,
                    Some(selected.encoded_private_environment().as_os_str()),
                );
            }
        }
    }

    #[test]
    #[ignore = "subprocess probe for inherited selector override"]
    fn inherited_private_environment_selection_probe() {
        assert_eq!(std::env::var("REVERIE_DBT_PRIVATE_ENV_PROBE").unwrap(), "1");
        let selected = runner().private_environment_key("TOOL_SECRET").unwrap();
        let expected = format!(
            "{HIDE_ENV_PREFIXES_ENV}={}",
            selected.encoded_private_environment().to_str().unwrap()
        );
        let environment = drrun_environment(selected, &Command::new("/usr/bin/true"), None);
        assert!(
            environment.lines().any(|line| line == expected),
            "{environment}"
        );
        println!("inherited-private-selection-overridden");
    }

    #[test]
    fn inherited_environment_cannot_replace_the_launchers_private_selection() {
        for value in ["", "FORGED_"] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "launcher::tests::inherited_private_environment_selection_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("REVERIE_DBT_PRIVATE_ENV_PROBE", "1")
                .env(HIDE_ENV_PREFIXES_ENV, value)
                .output()
                .unwrap();
            assert!(output.status.success(), "probe failed: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("inherited-private-selection-overridden"),
                "probe did not run: {output:?}"
            );
        }
    }

    /// The environment a launch through `runner` gives drrun, as a stand-in
    /// drrun that prints its environment reports it.
    fn drrun_environment(
        runner: DbtRunner,
        guest: &Command,
        environment: Option<&BTreeMap<OsString, OsString>>,
    ) -> String {
        let directory = tempfile::tempdir().expect("stand-in drrun directory");
        let drrun = directory.path().join("drrun");
        std::fs::write(&drrun, "#!/bin/sh\nexec /usr/bin/env\n").expect("write stand-in drrun");
        std::fs::set_permissions(&drrun, std::fs::Permissions::from_mode(0o755))
            .expect("make stand-in drrun executable");
        let runner = DbtRunner { drrun, ..runner };
        // Another test's fork can still hold the script's write descriptor
        // for a moment after it is written (ETXTBSY).
        let mut attempts = 0;
        let output = loop {
            match runner.command(guest, environment).unwrap().output() {
                Err(error) if error.raw_os_error() == Some(libc::ETXTBSY) && attempts < 50 => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                result => break result.expect("run the stand-in drrun"),
            }
        };
        assert!(output.status.success(), "stand-in drrun: {output:?}");
        String::from_utf8(output.stdout).expect("environment should be UTF-8")
    }

    /// The variable's line in an environment listing, if any.
    fn answers_brk_line(environment: &str) -> Option<String> {
        environment
            .lines()
            .find(|line| line.starts_with(&format!("{TOOL_ANSWERS_BRK_ENV}=")))
            .map(str::to_owned)
    }

    const ANSWERS_BRK: &str = "DYNAMORIO_TOOL_ANSWERS_BRK=1";

    #[test]
    fn only_a_tool_that_answers_brk_tells_dynamorio_so_whatever_the_guests_environment() {
        let off = || runner().tool_answers_brk(true).tool_answers_brk(false);
        // DynamoRIO acts on presence, so empty and "0" count as set.
        for value in ["", "0", "1"] {
            let environment =
                BTreeMap::from([(OsString::from(TOOL_ANSWERS_BRK_ENV), OsString::from(value))]);
            let plain = Command::new("/usr/bin/true");
            let mut guest = Command::new("/usr/bin/true");
            guest.env(TOOL_ANSWERS_BRK_ENV, value);
            for (label, guest, environment) in [
                ("an explicit environment", &plain, Some(&environment)),
                ("the guest's environment", &guest, None),
            ] {
                for (mode, runner) in [("default", runner()), ("turned off", off())] {
                    assert_eq!(
                        answers_brk_line(&drrun_environment(runner, guest, environment)),
                        None,
                        "{mode}, {label} carrying {value:?}"
                    );
                }
                assert_eq!(
                    answers_brk_line(&drrun_environment(
                        runner().tool_answers_brk(true),
                        guest,
                        environment
                    ))
                    .as_deref(),
                    Some(ANSWERS_BRK),
                    "on, {label} carrying {value:?}"
                );
            }
        }
    }

    /// Set (to any value) only in the copy of this test binary that
    /// [`a_tool_that_does_not_answer_brk_drops_an_inherited_variable`] runs,
    /// where it asks [`inherited_tool_answers_brk_probe`] to report.
    const INHERITED_PROBE_ENV: &str = "REVERIE_DBT_TEST_INHERITED_ANSWERS_BRK_PROBE";

    /// Reports, from a process that inherited the variable, what drrun gets
    /// with the option off and on. Run only by
    /// [`a_tool_that_does_not_answer_brk_drops_an_inherited_variable`].
    #[test]
    #[ignore = "a probe that a_tool_that_does_not_answer_brk_drops_an_inherited_variable runs in a child"]
    fn inherited_tool_answers_brk_probe() {
        if std::env::var_os(INHERITED_PROBE_ENV).is_none() {
            return;
        }
        let guest = Command::new("/usr/bin/true");
        for (mode, runner) in [("off", runner()), ("on", runner().tool_answers_brk(true))] {
            let line = answers_brk_line(&drrun_environment(runner, &guest, None));
            println!("probe {mode}: {}", line.as_deref().unwrap_or("absent"));
        }
    }

    #[test]
    fn a_tool_that_does_not_answer_brk_drops_an_inherited_variable() {
        // The variable is set in a child copy of this test binary, never in
        // this process, whose environment the parallel tests share.
        for value in ["", "0", "1"] {
            let output = Command::new(std::env::current_exe().expect("this test binary"))
                .args([
                    "--exact",
                    "launcher::tests::inherited_tool_answers_brk_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(TOOL_ANSWERS_BRK_ENV, value)
                .env(INHERITED_PROBE_ENV, "1")
                .output()
                .expect("run the probe");
            assert!(output.status.success(), "probe: {output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            // libtest's own "test ... " may share the first probe line.
            let reported = |mode: &str| {
                let marker = format!("probe {mode}: ");
                stdout
                    .lines()
                    .find_map(|line| line.split_once(&marker).map(|(_, rest)| rest.to_owned()))
            };
            assert_eq!(
                reported("off").as_deref(),
                Some("absent"),
                "{value:?}: {stdout}"
            );
            assert_eq!(
                reported("on").as_deref(),
                Some(ANSWERS_BRK),
                "{value:?}: {stdout}"
            );
        }
    }

    #[test]
    fn streaming_input_reaches_child_before_source_closes() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;
        use std::sync::mpsc;
        use std::time::Duration;
        use std::time::Instant;

        let (mut source, mut producer) = UnixStream::pair().unwrap();
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = child.stdout.take().unwrap();
        let pump = std::thread::spawn(move || copy_streaming_input(&mut source, &mut input));
        let (send, receive) = mpsc::channel();
        let echoes = std::thread::spawn(move || {
            for _ in 0..2 {
                let mut byte = [0];
                let result = output.read_exact(&mut byte).map(|()| byte[0]);
                if send.send(result).is_err() {
                    break;
                }
            }
        });
        let bound = Duration::from_secs(3);
        let mut progress = Vec::new();
        for byte in *b"AB" {
            let sent = producer.write_all(&[byte]);
            let echoed = receive.recv_timeout(bound);
            let complete = sent.is_ok() && matches!(echoed, Ok(Ok(value)) if value == byte);
            progress.push((byte, sent, echoed));
            if !complete {
                break;
            }
        }
        // Snapshot the oracle while the producer is still open. EOF below is
        // cleanup only and cannot turn a failed progress assertion into a pass.
        let before_eof = progress.len() == 2
            && progress.iter().all(|(byte, sent, echoed)| {
                sent.is_ok() && matches!(echoed, Ok(Ok(value)) if value == byte)
            });
        drop(producer);
        let deadline = Instant::now() + bound;
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                break child.wait().unwrap();
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let copied = pump.join().unwrap();
        echoes.join().unwrap();
        assert!(
            before_eof,
            "input did not reach child before EOF: {progress:?}"
        );
        assert_eq!(copied.unwrap(), 2);
        assert!(status.success(), "{status}");
    }

    #[test]
    fn supplies_captured_standard_input() {
        let root = tempfile::tempdir().unwrap();
        let runner = fixture_runner(fake_drrun(root.path()), fake_client()).unwrap();
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
        let stop = Arc::new(AtomicU8::new(READ_ON));
        std::thread::scope(|scope| {
            let writer = scope.spawn(move || while writer.write_all(&[b'x'; 4096]).is_ok() {});
            let reader_stop = Arc::clone(&stop);
            let handle = scope.spawn(move || read_cancellable(&mut reader, &reader_stop));
            std::thread::sleep(std::time::Duration::from_millis(5));
            stop.store(READ_DISCARD, Ordering::Release);
            let error = handle.join().unwrap().unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            writer.join().unwrap();
        });
    }

    #[test]
    fn a_kept_output_reader_returns_what_it_read_while_a_writer_still_holds_the_pipe() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        set_nonblocking(&reader).unwrap();
        writer.write_all(b"the reason the run failed\n").unwrap();
        // The stop comes before the reader has read anything, the worst case
        // for a slow reader. `writer` stays open, as a pipe held outside the
        // reaped tree would, so the reader never sees end of file; what is
        // already in the pipe must still be returned.
        let stop = AtomicU8::new(READ_KEEP);
        assert_eq!(
            read_cancellable(&mut reader, &stop).unwrap(),
            b"the reason the run failed\n"
        );
        drop(writer);
    }

    #[test]
    fn a_kept_output_reader_reads_exactly_its_cap_from_a_source_that_never_ends() {
        // Never reports end of file or EAGAIN, like a writer that never pauses
        // and always wins the race with the reader. Its reads are one byte
        // short of the reader's buffer, so a cap that did not limit each read
        // to the remaining budget would overshoot.
        struct ShortReads;
        impl Read for ShortReads {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let length = buffer.len().min(8191);
                buffer[..length].fill(b'x');
                Ok(length)
            }
        }
        let mut endless = ShortReads;
        let stop = AtomicU8::new(READ_KEEP);
        let kept = read_cancellable(&mut endless, &stop).unwrap();
        assert_eq!(kept.len(), KEPT_OUTPUT_DRAIN_BYTES);
    }

    #[test]
    fn a_kept_output_reader_stops_although_a_writer_never_pauses() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        set_nonblocking(&reader).unwrap();
        let stop = AtomicU8::new(READ_KEEP);
        std::thread::scope(|scope| {
            // Writes until the reader is dropped.
            let writer = scope.spawn(move || while writer.write_all(&[b'x'; 4096]).is_ok() {});
            // The reader may find the socket empty before the writer runs and
            // return at once; this test checks only that it returns and that
            // the writer is released. The cap itself is pinned above.
            let kept = read_cancellable(&mut reader, &stop).unwrap();
            assert!(
                kept.len() <= KEPT_OUTPUT_DRAIN_BYTES,
                "read {} bytes after the stop",
                kept.len()
            );
            drop(reader);
            writer.join().unwrap();
        });
    }

    #[test]
    fn keeps_diagnostics_out_of_guest_stderr_redirections() {
        let root = tempfile::tempdir().unwrap();

        let script = format!(
            "output=$(/bin/bash -c 'printf guest-stderr >&2; printf backend-diagnostic >&{DIAGNOSTIC_FD}' 2>&1); printf 'captured=<%s>\\n' \"$output\""
        );
        let mut guest = Command::new("/bin/bash");
        guest.args(["-c", &script]);

        let output = fixture_runner(fake_drrun(root.path()), fake_client())
            .unwrap()
            .output(&guest)
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"captured=<guest-stderr>\n");
        assert_eq!(output.stderr, b"backend-diagnostic");
    }

    #[test]
    fn diagnostic_file_separates_guest_stderr_from_diagnostics() {
        let root = tempfile::tempdir().unwrap();
        let diagnostics = tempfile::tempfile().unwrap();
        let mut diagnostic_reader = diagnostics.try_clone().unwrap();
        let mut guest = Command::new("/bin/bash");
        guest
            .args([
                "-c",
                "printf guest-stdout; printf guest-stderr >&2; printf client-diagnostic >&198; exit 7",
            ])
            .env(TEST_DRRUN_STDERR, "drrun-stderr")
            .env(TEST_DRRUN_DIAGNOSTIC, "drrun-diagnostic");

        let runner = fixture_runner(fake_drrun(root.path()), fake_client())
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap();
        let owned_descriptor = runner.diagnostic_file.as_ref().unwrap().as_raw_fd();
        assert!(owned_descriptor >= 3);
        let descriptor_flags = unsafe { libc::fcntl(owned_descriptor, libc::F_GETFD) };
        assert_ne!(descriptor_flags, -1);
        assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
        drop(diagnostics);

        let output = runner.output(&guest).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"guest-stdout");
        assert_eq!(output.stderr, b"drrun-stderrguest-stderr");

        diagnostic_reader.rewind().unwrap();
        let mut diagnostic_bytes = Vec::new();
        diagnostic_reader
            .read_to_end(&mut diagnostic_bytes)
            .unwrap();
        assert_eq!(diagnostic_bytes, b"drrun-diagnosticclient-diagnostic");
    }

    #[test]
    fn unset_diagnostic_file_preserves_the_shared_stderr_stream() {
        let root = tempfile::tempdir().unwrap();
        let mut guest = Command::new("/bin/sh");
        guest
            .args(["-c", "printf guest-stderr >&2"])
            .env(TEST_DRRUN_STDERR, "drrun-stderr")
            .env(TEST_DRRUN_DIAGNOSTIC, "drrun-diagnostic");

        let output = fixture_runner(fake_drrun(root.path()), fake_client())
            .unwrap()
            .output(&guest)
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stderr, b"drrun-stderrdrrun-diagnosticguest-stderr");
    }

    #[test]
    fn diagnostic_file_rejects_a_read_only_handle() {
        let read_only = File::open("/dev/null").unwrap();
        let error = runner().diagnostic_file(&read_only).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn missing_or_closed_diagnostic_descriptor_fails_closed() {
        let clone_error = clone_diagnostic_fd(-1).unwrap_err();
        assert_eq!(clone_error.raw_os_error(), Some(libc::EBADF));

        let validation_error = require_writable_diagnostic_fd(-1).unwrap_err();
        assert_eq!(validation_error.raw_os_error(), Some(libc::EBADF));

        let duplication_error = duplicate_to_diagnostic_fd(-1).unwrap_err();
        assert_eq!(duplication_error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn diagnostic_descriptor_198_clears_cloexec_and_survives_exec() {
        use std::os::unix::net::UnixStream;

        let (mut reader, writer) = UnixStream::pair().unwrap();
        let writer_descriptor = writer.as_raw_fd();
        let mut command = Command::new("/bin/bash");
        command
            .args(["-c", "printf diagnostic-fd-survived >&198"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // SAFETY: the hook uses only async-signal-safe descriptor operations.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(writer_descriptor, DIAGNOSTIC_FD) == -1 {
                    return Err(io::Error::last_os_error());
                }
                let flags = libc::fcntl(DIAGNOSTIC_FD, libc::F_GETFD);
                if flags == -1
                    || libc::fcntl(DIAGNOSTIC_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(DIAGNOSTIC_FD, libc::F_GETFD) & libc::FD_CLOEXEC == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }

                duplicate_to_diagnostic_fd(DIAGNOSTIC_FD)?;
                if libc::fcntl(DIAGNOSTIC_FD, libc::F_GETFD) & libc::FD_CLOEXEC != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                Ok(())
            });
        }

        let mut child = command.spawn().unwrap();
        drop(writer);
        assert!(child.wait().unwrap().success());
        let mut diagnostic_bytes = Vec::new();
        reader.read_to_end(&mut diagnostic_bytes).unwrap();
        assert_eq!(diagnostic_bytes, b"diagnostic-fd-survived");
    }

    #[test]
    fn diagnostic_file_preserves_process_group_cleanup_and_exit_status() {
        let root = tempfile::tempdir().unwrap();
        let mut diagnostics = tempfile::tempfile().unwrap();
        let runner = fixture_runner(fake_drrun(root.path()), fake_client())
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap()
            .terminate_process_group_on_exit(true);
        let mut guest = Command::new("/bin/bash");
        guest.args([
            "-c",
            "sleep 60 & printf descendant-started; printf cleanup-diagnostic >&198; exit 7",
        ]);
        let started = std::time::Instant::now();

        let output = runner.output(&guest).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"descendant-started");
        assert!(output.stderr.is_empty());
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        diagnostics.rewind().unwrap();
        let mut diagnostic_bytes = Vec::new();
        diagnostics.read_to_end(&mut diagnostic_bytes).unwrap();
        assert_eq!(diagnostic_bytes, b"cleanup-diagnostic");
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn diagnostic_file_keeps_live_summary_out_of_guest_stderr() {
        let mut diagnostics = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .summary(true)
            .diagnostic_file(&diagnostics)
            .unwrap();
        let mut guest = Command::new("/bin/sh");
        guest.args(["-c", "printf exact-guest-stderr >&2"]);

        let output = runner.output(&guest).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stderr, b"exact-guest-stderr");
        diagnostics.rewind().unwrap();
        let mut diagnostic_bytes = Vec::new();
        diagnostics.read_to_end(&mut diagnostic_bytes).unwrap();
        assert!(
            diagnostic_bytes
                .windows(b"reverie-dbt: tool=".len())
                .any(|window| window == b"reverie-dbt: tool="),
            "summary was not written to the diagnostic file: {}",
            String::from_utf8_lossy(&diagnostic_bytes)
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn quiet_live_runtime_does_not_write_to_guest_stderr() {
        let diagnostics = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .diagnostic_file(&diagnostics)
            .unwrap();

        let output = runner.output(&Command::new("/bin/true")).unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.is_empty(),
            "successful -quiet DynamoRIO launch wrote non-guest bytes to fd 2: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_preserves_a_normal_guest_exit_101() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap();
        let mut guest = Command::new("/bin/sh");
        guest.args(["-c", "exit 101"]);

        let output = runner.output(&guest).unwrap();
        assert_eq!(output.status.code(), Some(101));
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(crate::decode_evidence(&bytes).is_ok());
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_preserves_a_normal_guest_signal_with_an_exit_callback() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap();
        let mut guest = Command::new("/bin/sh");
        guest.args(["-c", "kill -TERM $$"]);

        let output = runner.output(&guest).unwrap();
        assert!(!output.status.success());
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert!(crate::decode_evidence(&bytes).is_ok());
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_refuses_a_backend_failure_before_returning_output() {
        let file = tempfile::tempfile().unwrap();
        let mut diagnostics = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap()
            .client_argument("-test-backend-failure");

        let error = runner.output(&Command::new("/bin/true")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DBT backend or Tool reported an internal failure"),
            "backend failure was reported as the wrong error: {error}"
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
        diagnostics.rewind().unwrap();
        let mut diagnostic_bytes = Vec::new();
        diagnostics.read_to_end(&mut diagnostic_bytes).unwrap();
        assert!(
            diagnostic_bytes
                .windows(b"requested backend failure for testing".len())
                .any(|window| window == b"requested backend failure for testing")
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn a_backend_failure_under_protected_evidence_keeps_the_captured_stderr() {
        let file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .client_argument("-test-backend-failure");

        let error = runner.output(&Command::new("/bin/true")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DBT backend or Tool reported an internal failure"),
            "backend failure was reported as the wrong error: {error}"
        );
        // Without a diagnostic file the client writes its diagnostics to the
        // guest's stderr, which the runner captured before evidence failed.
        let output = failed_run_output(&error)
            .unwrap_or_else(|| panic!("the error dropped the captured output: {error:?}"));
        assert!(
            output
                .stderr
                .windows(b"requested backend failure for testing".len())
                .any(|window| window == b"requested backend failure for testing"),
            "captured stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn a_terminal_exit_marks_its_stats_record_as_a_backend_failure() {
        for (test_failure, expected_code, expected_failures) in
            [(false, Some(0), 0), (true, Some(101), 1)]
        {
            let sink = DbtStatsSink::new().unwrap();
            let [flag, path] = sink.client_arguments(sink.directory());
            let mut runner = DbtRunner::from_env()
                .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
                .client_argument(flag)
                .client_argument(path);
            if test_failure {
                runner = runner.client_argument("-test-backend-failure");
            }

            let output = runner.output(&Command::new("/bin/true")).unwrap();
            assert_eq!(output.status.code(), expected_code, "{output:?}");
            let snapshot = sink.drain().unwrap().snapshot().clone();
            assert_eq!(snapshot.process_images(), 1, "{snapshot}");
            assert_eq!(snapshot.backend_failures(), expected_failures, "{snapshot}");
        }
    }

    #[test]
    #[ignore = "requires a built DynamoRIO and native client; run explicitly with --ignored"]
    fn private_memory_loss_injection_failure_is_a_backend_failure() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("private_memory_exec");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/private_memory_exec.c");
        let compile = Command::new("cc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .arg("-o")
            .arg(&program)
            .output()
            .unwrap();
        assert!(compile.status.success(), "{compile:?}");

        // This is the explicit control-backing fault injector, not guest close
        // admission. A real close(-1) fails without destroying the live backing.
        let mut snapshots = Vec::new();
        for protected in [false, true] {
            let evidence = tempfile::tempfile().unwrap();
            let sink = DbtStatsSink::new().unwrap();
            let [flag, path] = sink.client_arguments(sink.directory());
            let mut runner = DbtRunner::from_env()
                .expect("built DynamoRIO and native client")
                .client_argument(flag)
                .client_argument(path)
                .client_argument("-test-private-memory")
                .client_argument("lost-exec-close-failure");
            if protected {
                runner = runner.evidence_file(&evidence).unwrap();
            }
            let mut command = Command::new(&program);
            command.arg("exec");
            let result = runner.output(&command);
            eprintln!("private memory close failure protected={protected}: {result:?}");
            let (stdout, stderr) = if protected {
                let error = result.unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("DBT backend or Tool reported an internal failure"),
                    "{error}"
                );
                assert_eq!(evidence.metadata().unwrap().len(), 0);
                let output = failed_run_output(&error).expect("retained failure output");
                (output.stdout.clone(), output.stderr.clone())
            } else {
                let output = result.unwrap();
                assert_eq!(output.status.code(), Some(101), "{output:?}");
                (output.stdout, output.stderr)
            };
            assert!(stdout.is_empty(), "{stdout:?}");
            let stderr = String::from_utf8(stderr).unwrap();
            assert_eq!(
                stderr
                    .matches("PRIVATE_MEMORY_TEST loss-injection-failed\n")
                    .count(),
                1
            );
            assert!(!stderr.contains("followed_exec=1"), "{stderr}");
            let snapshot = sink.drain().unwrap().snapshot().clone();
            eprintln!(
                "private memory close failure protected={protected}: failures={} {snapshot}",
                snapshot.backend_failures()
            );
            assert_eq!(snapshot.process_images(), 1, "{snapshot}");
            snapshots.push(snapshot);
        }
        for snapshot in snapshots {
            assert_eq!(snapshot.backend_failures(), 1, "{snapshot}");
        }
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn a_copied_failure_publishes_its_record_before_root_termination() {
        use crate::backend_stats::DbtProcessRecord;
        use crate::backend_stats::WIRE_RECORD_LEN;
        use crate::backend_stats::decode_process_record;

        let directory = tempfile::tempdir().unwrap();
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/evidence_vfork_open_exec.c");
        let fixture = directory.path().join("copied-terminal-failure");
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        assert!(
            Command::new(compiler)
                .args(["-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(source)
                .arg("-o")
                .arg(&fixture)
                .status()
                .unwrap()
                .success()
        );

        // First force cleanup omission, then check ordinary termination does
        // not append a second record. Neither run can rely on event_exit.
        for skip_cleanup in [true, false] {
            let sink = DbtStatsSink::new().unwrap();
            let [flag, path] = sink.client_arguments(sink.directory());
            let mut runner = DbtRunner::from_env()
                .unwrap()
                .isolated_process_group(true)
                .client_argument(flag)
                .client_argument(path)
                .client_argument("-test-copied-backend-failure");
            if skip_cleanup {
                runner = runner.client_argument("-test-skip-terminal-cleanup");
            }
            let mut guest = Command::new(&fixture);
            guest.arg("terminal-failure").env_remove(crate::TOOL_ENV);
            for selector in [
                "HERMIT_DBT_TEST_REWRITE_EXIT",
                "HERMIT_DBT_TEST_INJECT_INVALID_CLONE",
                "HERMIT_DBT_TEST_SET_REG",
                "HERMIT_DBT_TEST_COMPARE_EXCHANGE",
                "HERMIT_DBT_TEST_PPID",
                "HERMIT_DBT_TEST_BACKTRACE",
                "HERMIT_DBT_STRACE",
                "HERMIT_DBT_SYSCALL_HISTOGRAM",
                "HERMIT_DBT_COUNTER1",
                "HERMIT_DBT_COUNTER2",
                "HERMIT_DBT_CHUNKY_PRINT",
                "HERMIT_DBT_CHROME_TRACE",
                "HERMIT_DBT_CHAOS",
                "HERMIT_DBT_NOOP",
                "HERMIT_DBT_COUNTER1_EXACT",
                "HERMIT_DBT_COUNTER2_EXACT",
            ] {
                guest.env_remove(selector);
            }
            let output = runner.output(&guest).unwrap();
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("unsupported syscall 145 in copied child"),
                "{output:?}"
            );
            eprintln!("forced copied failure: skip_cleanup={skip_cleanup} {output:?}");
            assert_eq!(output.status.signal(), Some(libc::SIGKILL), "{output:?}");
            assert_eq!(
                output.stdout.len(),
                12,
                "identity only, no after-call marker: {output:?}"
            );
            let identities: Vec<_> = output
                .stdout
                .as_chunks::<4>()
                .0
                .iter()
                .map(|bytes| i32::from_ne_bytes(*bytes))
                .collect();
            assert!(identities[0] > 0);
            assert_ne!(identities[0], identities[1]);
            assert_eq!(identities[1], identities[2]);
            let capture = sink.capture();
            let bytes = capture
                .records()
                .expect("failure must be published before root termination");
            assert_eq!(
                bytes.len(),
                WIRE_RECORD_LEN,
                "exactly one failing child record"
            );
            let (record, consumed) = decode_process_record(bytes).unwrap();
            assert_eq!(consumed, bytes.len());
            assert_eq!(
                record,
                DbtProcessRecord {
                    backend_failure: true,
                    image_generation: record.image_generation,
                    process_identity: identities[0] as u64,
                    parent_identity: identities[1] as u64,
                    ..Default::default()
                }
            );
            let snapshot = capture.snapshot().unwrap();
            assert_eq!(snapshot.process_images(), 1);
            assert_eq!(snapshot.backend_failures(), 1);
            eprintln!(
                "copied terminal record: skip_cleanup={skip_cleanup} pid={} ppid={} bytes={}",
                identities[0],
                identities[1],
                bytes.len()
            );
        }
    }

    #[tokio::test]
    async fn caller_activation_failure_retains_the_reaped_child_output() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("child-pid");
        let runner = fixture_runner(fake_drrun(directory.path()), fake_client())
            .unwrap()
            .terminate_process_group_on_exit(true);
        let mut guest = Command::new("/bin/bash");
        guest.args([
            "-c",
            "printf '%s' \"$$\" > \"$1\"; printf 'native-out\\n'; printf 'native-diagnostic\\n' >&198; exit 7",
            "caller-capture-fixture",
        ]);
        guest.arg(&pid_file);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            runner.output_with_caller_tool::<crate::Counter2Global>(&guest, ()),
        )
        .await
        .expect("caller capture fixture timed out")
        .unwrap_err();
        let pid: i32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        // The real wait and existing containment finish before a protocol error
        // returns; this fixture does not execute a DynamoRIO/native Tool host.
        let waited = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(error.to_string().contains("Tool"), "{error}");
        let output = failed_run_output(&error)
            .unwrap_or_else(|| panic!("caller protocol error dropped reaped output: {error}"));
        assert_eq!(output.status.unwrap().code(), Some(7));
        assert_eq!(output.stdout, b"native-out\n");
        assert_eq!(output.stderr, b"native-diagnostic\n");
    }

    #[test]
    fn a_failed_run_keeps_its_error_and_carries_its_output() {
        let original = io::Error::new(io::ErrorKind::InvalidData, "evidence failed");
        let error = DbtFailedRunOutput::attach(original, b"out".to_vec(), b"why\n".to_vec());
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "evidence failed");
        let output = failed_run_output(&error).expect("captured output");
        assert_eq!(output.status, None);
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"why\n");
        assert!(failed_run_output(&io::Error::other("plain")).is_none());
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_keeps_a_backend_failure_after_sender_lookup_misses() {
        let file = tempfile::tempfile().unwrap();
        let mut diagnostics = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap()
            .client_argument("-test-backend-failure")
            .client_argument("-test-backend-failure-sender-lookup-miss");

        let error = runner.output(&Command::new("/bin/true")).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("DBT backend or Tool reported an internal failure"),
            "backend failure was reported as the wrong error: {error}"
        );
        assert_eq!(file.metadata().unwrap().len(), 0);
        diagnostics.rewind().unwrap();
        let mut diagnostic_bytes = Vec::new();
        diagnostics.read_to_end(&mut diagnostic_bytes).unwrap();
        assert!(
            diagnostic_bytes
                .windows(b"skipped backend failure sender lookup for testing".len())
                .any(|window| window == b"skipped backend failure sender lookup for testing")
        );
    }

    #[test]
    #[ignore = "requires built DynamoRIO and native client; run explicitly with --ignored"]
    fn protected_evidence_initializes_when_tracing_is_off() {
        let mut file = tempfile::tempfile().unwrap();
        let runner = DbtRunner::from_env()
            .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
            .evidence_file(&file)
            .unwrap()
            .evidence_log_level(DbtEvidenceLogLevel::Off);

        let output = runner.output(&Command::new("/bin/true")).unwrap();
        assert!(output.status.success());
        file.rewind().unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        let evidence = crate::decode_evidence(&bytes).unwrap();
        assert!(evidence.initialization_records() > 0);
        assert!(evidence.records().is_empty());
    }

    #[test]
    fn returns_when_child_exits_while_input_source_is_blocked() {
        let root = tempfile::tempdir().unwrap();
        let runner = fixture_runner(fake_drrun(root.path()), fake_client()).unwrap();
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
        let sink = DbtStatsSink::new().unwrap();
        let arguments = sink.client_arguments(sink.directory());
        assert_eq!(arguments[0], OsStr::new("-stats_path"));
        assert_eq!(arguments[1], sink.path.clone().into_os_string());
        assert_eq!(arguments[1], sink.path.as_os_str());
    }

    #[test]
    fn stats_sink_drain_of_missing_file_yields_an_empty_snapshot() {
        let sink = DbtStatsSink::new().unwrap();
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

        let sink = DbtStatsSink::new().unwrap();

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

        let sink = DbtStatsSink::new().unwrap();
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

    /// A post-launch evidence failure must NOT surface a spawn-shaped kind.
    ///
    /// Current Hermit does not yet inspect this kind: it reports every DBT
    /// runner error as "failed to launch drrun". The paired Hermit change needs
    /// an honest discriminator before it can correct that message. This test
    /// guarantees that evidence finalization cannot retain a spawn-shaped kind
    /// after the guest has already produced an exit status.
    ///
    /// NOT `#[ignore]`, unlike every other evidence test here: those need built
    /// DynamoRIO and so only run when someone asks for them. This contract is
    /// about error kinds, not about DynamoRIO, and it runs on every `cargo test`.
    #[test]
    fn a_post_launch_evidence_failure_never_reports_a_spawn_kind() {
        use std::os::unix::process::ExitStatusExt;

        let exited = ExitStatus::from_raw(0x100); // exit code 1
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ExecutableFileBusy,
            io::ErrorKind::InvalidData,
            io::ErrorKind::TimedOut,
        ] {
            let error = combine_status_and_evidence(
                Ok(exited),
                Err(io::Error::new(kind, "evidence collector said no")),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                io::ErrorKind::Other,
                "a post-launch failure must not surface {kind:?} to a caller that branches on the kind to blame the binary"
            );
            // The cause must survive verbatim; truncating it is what cost the
            // original investigation its answer.
            assert!(
                error.to_string().contains("evidence collector said no"),
                "underlying cause lost: {error}"
            );
            assert!(
                error.to_string().contains("DBT guest exited with status"),
                "the message must say the guest ran: {error}"
            );
        }
    }

    /// The other direction, so the fix above cannot be over-applied. An error
    /// without an exit status keeps its kind, and genuine spawn errors bypass
    /// this helper entirely.
    #[test]
    fn an_error_without_exit_status_keeps_its_own_kind() {
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
            let error =
                combine_status_and_evidence(Err(io::Error::new(kind, "no such file")), Ok(()))
                    .unwrap_err();
            assert_eq!(
                error.kind(),
                kind,
                "an error without an exit status must keep its kind"
            );
        }
        // An evidence failure alongside a status error must not mask it.
        let error = combine_status_and_evidence(
            Err(io::Error::new(io::ErrorKind::NotFound, "no such file")),
            Err(io::Error::other("evidence also failed")),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
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

        let mut command = runner.command(&guest, None).unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        runner.finish_launch_setup(None).unwrap();
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
            evidence.initialization_records() > 0,
            "live integrity run produced no process image initialization evidence"
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
        let mut command = runner.command(&guest, None).unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = runner.spawn_command(&mut command).unwrap();
        runner.finish_launch_setup(None).unwrap();
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
        let mut command = runner.command(&guest, None).unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        runner.finish_launch_setup(None).unwrap();
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
            evidence.initialization_records() > 0,
            "retry run produced no process image initialization evidence"
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
        let mut command = runner.command(&guest, None).unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        runner.finish_launch_setup(None).unwrap();
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
        let mut command = runner.command(&guest, None).unwrap();
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = runner.spawn_command(&mut command).unwrap();
        runner.finish_launch_setup(None).unwrap();
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
        for argument in [
            "-test-runtime-abi-mismatch",
            "-test-runtime-abi12-mismatch",
            "-test-runtime-abi13-mismatch",
        ] {
            let mut file = tempfile::tempfile().unwrap();
            let runner = DbtRunner::from_env()
                .expect("DYNAMORIO_HOME and REVERIE_DBT_CLIENT must select the live native client")
                .evidence_file(&file)
                .unwrap()
                .client_argument(argument);
            let guest = Command::new("/bin/true");
            let mut command = runner.command(&guest, None).unwrap();
            command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let child = runner.spawn_command(&mut command).unwrap();
            runner.finish_launch_setup(None).unwrap();
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
}
