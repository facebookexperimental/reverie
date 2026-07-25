/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Validated invocation of the external e9patch toolchain.

use std::env;
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::process::Stdio;

use anyhow::Context;
use anyhow::anyhow;
use goblin::elf::Elf;
use goblin::elf::header::EM_X86_64;
use goblin::elf::header::ET_DYN;
use goblin::elf::header::ET_EXEC;
use goblin::elf::program_header::PT_LOAD;
use reverie::Error;
use sha2::Digest;
use sha2::Sha256;

/// Environment variable that selects the e9tool executable.
// TODO-HUMAN-REVIEW(PR-101): Review the public external-tool override.
pub const E9TOOL_ENV: &str = "REVERIE_E9TOOL";

/// Environment variable that selects the e9patch backend executable.
// TODO-HUMAN-REVIEW(PR-101): Review the public external-tool override.
pub const E9PATCH_BACKEND_ENV: &str = "REVERIE_E9PATCH_BACKEND";

const E9PATCH_LOADER_BASE: u64 = 0x20e9_e9000;

/// Auditable, digest-bound information about one e9patch preparation.
// TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RewriteReport {
    source: PathBuf,
    input_sha256: String,
    output_sha256: String,
    e9tool_sha256: String,
    e9patch_sha256: String,
    patched_sites: usize,
    recovered_sites: usize,
    b0_sites: usize,
}

impl RewriteReport {
    /// Returns the canonical source executable.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Returns the SHA-256 digest of the snapshotted input.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Returns the SHA-256 digest of the sealed output.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn output_sha256(&self) -> &str {
        &self.output_sha256
    }

    /// Returns the SHA-256 digest of the snapshotted e9tool executable.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn e9tool_sha256(&self) -> &str {
        &self.e9tool_sha256
    }

    /// Returns the SHA-256 digest of the snapshotted e9patch backend.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn e9patch_sha256(&self) -> &str {
        &self.e9patch_sha256
    }

    /// Returns the number of sites rewritten by e9tool.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn patched_sites(&self) -> usize {
        self.patched_sites
    }

    /// Returns the number of sites recovered by e9tool.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn recovered_sites(&self) -> usize {
        self.recovered_sites
    }

    /// Returns the number of signal-based B0 sites.
    // TODO-HUMAN-REVIEW(PR-101): Review the public rewrite report API.
    pub fn b0_sites(&self) -> usize {
        self.b0_sites
    }
}

/// A validated e9patch artifact held in a sealed anonymous file.
///
/// Values can only be produced by E9patchRewriter. The kernel seals prevent
/// modification through this value or any duplicated descriptor.
// TODO-HUMAN-REVIEW(PR-101): Review the prepared-artifact API.
#[derive(Debug)]
pub struct PreparedBinary {
    report: RewriteReport,
    artifact: File,
}

impl PreparedBinary {
    /// Returns the digest-bound preparation report.
    // TODO-HUMAN-REVIEW(PR-101): Review the prepared-artifact API.
    pub fn report(&self) -> &RewriteReport {
        &self.report
    }

    /// Opens an independent read-only handle to the sealed artifact.
    // TODO-HUMAN-REVIEW(PR-101): Review the public prepared-artifact API.
    pub fn artifact(&self) -> Result<File, Error> {
        File::open(format!("/proc/self/fd/{}", self.artifact.as_raw_fd())).map_err(Into::into)
    }
}

/// Configuration for invoking a separately installed e9tool/e9patch pair.
///
/// The GPL-3.0 e9patch executables remain separate programs. This BSD-licensed
/// crate does not link or copy their runtime code into its own binary.
// TODO-HUMAN-REVIEW(PR-101): Review the external rewriter API and license boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E9patchRewriter {
    e9tool: PathBuf,
    e9patch_backend: PathBuf,
}

impl E9patchRewriter {
    /// Creates a rewriter for explicit tool paths.
    // TODO-HUMAN-REVIEW(PR-101): Review this public e9patch preparation API.
    pub fn new(e9tool: impl Into<PathBuf>, e9patch_backend: impl Into<PathBuf>) -> Self {
        Self {
            e9tool: e9tool.into(),
            e9patch_backend: e9patch_backend.into(),
        }
    }

    /// Resolves the external tools from the process environment.
    // TODO-HUMAN-REVIEW(PR-101): Review this public e9patch preparation API.
    pub fn from_env() -> Result<Self, Error> {
        let e9tool = resolve_requested_executable(E9TOOL_ENV, OsStr::new("e9tool"))?;
        let backend_default = e9tool.with_file_name("e9patch");
        let e9patch_backend =
            resolve_requested_executable(E9PATCH_BACKEND_ENV, backend_default.as_os_str())?;
        Ok(Self::new(e9tool, e9patch_backend))
    }

    /// Rewrites one x86-64 ELF into a sealed, digest-bound artifact.
    ///
    /// Preparation is synchronous and may be expensive. Callers should invoke
    /// it outside an async executor worker when blocking is undesirable.
    // TODO-HUMAN-REVIEW(PR-101): Review this public e9patch preparation API.
    pub fn prepare(&self, source: impl AsRef<Path>) -> Result<PreparedBinary, Error> {
        self.prepare_program(source.as_ref())
    }

    fn prepare_program(&self, source: &Path) -> Result<PreparedBinary, Error> {
        let source = fs::canonicalize(source)
            .with_context(|| format!("failed to resolve e9patch input {}", source.display()))?;
        let (input_bytes, input_mode) = snapshot_input(&source)?;
        let input_elf = validate_elf_image(&input_bytes, &source)?;
        let input_type = input_elf.header.e_type;

        let (e9tool_bytes, e9tool_mode) = snapshot_tool(&self.e9tool, "e9tool")?;
        let (e9patch_bytes, e9patch_mode) =
            snapshot_tool(&self.e9patch_backend, "e9patch backend")?;

        let temporary = tempfile::Builder::new()
            .prefix("reverie-e9patch-")
            .tempdir()
            .context("failed to create e9patch preparation directory")?;
        let input_snapshot = temporary.path().join("input.elf");
        let e9tool_snapshot = temporary.path().join("e9tool");
        let e9patch_snapshot = temporary.path().join("e9patch");
        let output = temporary.path().join("output.elf");
        write_snapshot(&input_snapshot, &input_bytes, input_mode)?;
        write_snapshot(&e9tool_snapshot, &e9tool_bytes, e9tool_mode)?;
        write_snapshot(&e9patch_snapshot, &e9patch_bytes, e9patch_mode)?;

        let mut tool = ProcessCommand::new(&e9tool_snapshot);
        tool.stdin(Stdio::null());
        tool.arg("--backend")
            .arg(&e9patch_snapshot)
            .arg("--seed=1")
            .arg("--option=--tactic-B0=false")
            .arg("-O0")
            .arg("-M")
            .arg("asm=\"syscall\"")
            .arg("-P")
            .arg("before empty")
            .arg(&input_snapshot)
            .arg("-o")
            .arg(&output);
        let result = run_with_bounded_output(&mut tool)
            .with_context(|| format!("failed to execute e9tool {}", self.e9tool.display()))?;
        let diagnostic = command_diagnostic(&result.stdout, &result.stderr);
        if !result.status.success() {
            return Err(anyhow!(
                "e9tool failed for {} with status {}:\n{}",
                source.display(),
                result.status,
                diagnostic
            )
            .into());
        }

        let (patched_sites, recovered_sites) = parse_metric_output(&result, "num_patched")
            .ok_or_else(|| {
                anyhow!(
                    "e9tool did not report patch coverage for {}:\n{}",
                    source.display(),
                    diagnostic
                )
            })?;
        if patched_sites != recovered_sites {
            return Err(anyhow!(
                "e9tool patched only {patched_sites}/{recovered_sites} recovered sites in {}",
                source.display()
            )
            .into());
        }

        // The pinned tool only emits this metric when B0 is enabled. We pass
        // tactic-B0=false, so a missing metric means zero; any site requiring B0
        // instead makes patched_sites differ from recovered_sites above.
        let (b0_sites, b0_total) =
            parse_metric_output(&result, "num_patched_B0").unwrap_or((0, recovered_sites));
        if b0_total != recovered_sites {
            return Err(anyhow!(
                "e9tool B0 total {b0_total} differs from recovered-site total {recovered_sites}"
            )
            .into());
        }
        if b0_sites != 0 {
            return Err(anyhow!(
                "e9tool required {b0_sites} signal-based B0 sites in {}; refusing changed signal semantics",
                source.display()
            )
            .into());
        }

        let output_metadata = fs::symlink_metadata(&output)
            .with_context(|| format!("e9tool did not create {}", output.display()))?;
        if !output_metadata.is_file() || output_metadata.file_type().is_symlink() {
            return Err(
                anyhow!("e9tool output is not a regular file: {}", output.display()).into(),
            );
        }
        let output_bytes = fs::read(&output)
            .with_context(|| format!("failed to read e9tool output {}", output.display()))?;
        validate_elf_output(
            &input_bytes,
            input_type,
            &output_bytes,
            &output,
            patched_sites,
        )?;

        let mut artifact = create_sealed_artifact(&output_bytes, input_mode)?;
        artifact.seek(SeekFrom::Start(0))?;
        let report = RewriteReport {
            source,
            input_sha256: sha256(&input_bytes),
            output_sha256: sha256(&output_bytes),
            e9tool_sha256: sha256(&e9tool_bytes),
            e9patch_sha256: sha256(&e9patch_bytes),
            patched_sites,
            recovered_sites,
            b0_sites,
        };
        Ok(PreparedBinary { report, artifact })
    }
}

fn snapshot_input(path: &Path) -> Result<(Vec<u8>, u32), Error> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open e9patch input {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("failed to inspect e9patch input {}", path.display()))?;
    validate_input(&file, path, &before)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to snapshot e9patch input {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("failed to reinspect e9patch input {}", path.display()))?;
    validate_input(&file, path, &after)?;
    if !same_file_state(&before, &after) {
        return Err(anyhow!(
            "e9patch input changed while it was being snapshotted: {}",
            path.display()
        )
        .into());
    }
    Ok((bytes, before.permissions().mode() & 0o777))
}

fn snapshot_tool(path: &Path, description: &str) -> Result<(Vec<u8>, u32), Error> {
    let path = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve {description} {}", path.display()))?;
    let mut file = File::open(&path)
        .with_context(|| format!("cannot open {description} {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("cannot inspect {description} {}", path.display()))?;
    validate_executable_metadata(&before, &path, description)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("cannot snapshot {description} {}", path.display()))?;
    let after = file
        .metadata()
        .with_context(|| format!("cannot reinspect {description} {}", path.display()))?;
    validate_executable_metadata(&after, &path, description)?;
    if !same_file_state(&before, &after) {
        return Err(anyhow!(
            "{description} changed while it was being snapshotted: {}",
            path.display()
        )
        .into());
    }
    Ok((bytes, before.permissions().mode() & 0o777))
}

fn write_snapshot(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

fn create_sealed_artifact(bytes: &[u8], mode: u32) -> Result<File, Error> {
    let name = CString::new("reverie-e9patch-artifact").expect("static string has no NUL");
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(fd as i32) };
    file.write_all(bytes)?;
    file.flush()?;
    let result = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
    if result != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals) };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(file)
}

fn validate_elf_output(
    input: &[u8],
    input_type: u16,
    output: &[u8],
    output_path: &Path,
    patched_sites: usize,
) -> Result<(), Error> {
    let input_elf = validate_elf_image(input, Path::new("input snapshot"))?;
    let output_elf = validate_elf_image(output, output_path)?;
    if input_elf.header.e_machine != output_elf.header.e_machine
        || input_elf.is_64 != output_elf.is_64
        || input_elf.little_endian != output_elf.little_endian
        || input_type != output_elf.header.e_type
    {
        return Err(anyhow!(
            "e9tool output architecture or ELF type differs from the input: {}",
            output_path.display()
        )
        .into());
    }
    if patched_sites != 0 && !elf_has_e9patch_loader(output)? {
        return Err(anyhow!(
            "e9tool reported patched sites without an e9patch loader mapping: {}",
            output_path.display()
        )
        .into());
    }
    Ok(())
}

fn validate_elf_image<'bytes>(bytes: &'bytes [u8], path: &Path) -> Result<Elf<'bytes>, Error> {
    let elf =
        Elf::parse(bytes).with_context(|| format!("invalid ELF executable {}", path.display()))?;
    if !elf.is_64 || !elf.little_endian || elf.header.e_machine != EM_X86_64 {
        return Err(anyhow!(
            "e9patch supports only little-endian x86-64 ELF executables: {}",
            path.display()
        )
        .into());
    }
    if !matches!(elf.header.e_type, ET_EXEC | ET_DYN) {
        return Err(anyhow!(
            "e9patch input must be an ET_EXEC or ET_DYN ELF: {}",
            path.display()
        )
        .into());
    }
    Ok(elf)
}

fn elf_has_e9patch_loader(bytes: &[u8]) -> Result<bool, Error> {
    let elf = Elf::parse(bytes).context("invalid prepared e9patch ELF")?;
    Ok(elf
        .program_headers
        .iter()
        .any(|header| header.p_type == PT_LOAD && header.p_vaddr == E9PATCH_LOADER_BASE))
}

fn validate_input(file: &File, source: &Path, metadata: &fs::Metadata) -> Result<(), Error> {
    validate_executable_metadata(metadata, source, "e9patch input")?;
    if metadata.permissions().mode() & 0o6000 != 0 || has_security_capability(file)? {
        return Err(anyhow!(
            "e9patch refuses privilege-bearing executable {}",
            source.display()
        )
        .into());
    }
    Ok(())
}

fn validate_executable_metadata(
    metadata: &fs::Metadata,
    path: &Path,
    description: &str,
) -> Result<(), Error> {
    if !metadata.is_file() {
        return Err(anyhow!("{description} is not a regular file: {}", path.display()).into());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(anyhow!("{description} is not executable: {}", path.display()).into());
    }
    Ok(())
}

fn has_security_capability(file: &File) -> Result<bool, Error> {
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size >= 0 {
        return Ok(size != 0);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(error.into()),
    }
}

fn same_file_state(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn validate_tool(path: &Path, description: &str) -> Result<(), Error> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("cannot access {description} {}", path.display()))?;
    validate_executable_metadata(&metadata, path, description)
}

fn resolve_requested_executable(variable: &str, default: &OsStr) -> Result<PathBuf, Error> {
    let requested = env::var_os(variable).unwrap_or_else(|| default.to_owned());
    if requested.is_empty() {
        return Err(anyhow!("{variable} is empty").into());
    }
    let requested = PathBuf::from(requested);
    if requested.components().count() > 1 {
        validate_tool(&requested, variable)?;
        return fs::canonicalize(&requested)
            .with_context(|| format!("failed to resolve {variable}={}", requested.display()))
            .map_err(Into::into);
    }

    let path = env::var_os("PATH").unwrap_or_default();
    for directory in env::split_paths(&path) {
        let candidate = directory.join(&requested);
        if validate_tool(&candidate, variable).is_ok() {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("failed to resolve {}", candidate.display()))
                .map_err(Into::into);
        }
    }
    Err(anyhow!(
        "could not find {} in PATH; set {variable} to an executable path",
        requested.display()
    )
    .into())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct BoundedOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_with_bounded_output(command: &mut ProcessCommand) -> io::Result<BoundedOutput> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("e9tool stdout pipe was not created"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("e9tool stderr pipe was not created"))?;
    let stdout = std::thread::spawn(move || capture_bounded(stdout));
    let stderr = std::thread::spawn(move || capture_bounded(stderr));
    let status = child.wait()?;
    let stdout = join_capture(stdout)?;
    let stderr = join_capture(stderr)?;
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn join_capture(handle: std::thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    handle
        .join()
        .map_err(|_| io::Error::other("e9tool output reader panicked"))?
}

fn capture_bounded(mut reader: impl Read) -> io::Result<Vec<u8>> {
    const PART_LIMIT: usize = 8 * 1024;
    let mut head = Vec::with_capacity(PART_LIMIT);
    let mut tail = Vec::with_capacity(PART_LIMIT);
    let mut total = 0_usize;
    let mut chunk = [0_u8; 8192];

    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        total = total.saturating_add(count);
        let remaining = PART_LIMIT.saturating_sub(head.len());
        head.extend_from_slice(&chunk[..count.min(remaining)]);
        tail.extend_from_slice(&chunk[..count]);
        if tail.len() > PART_LIMIT {
            tail.drain(..tail.len() - PART_LIMIT);
        }
    }

    if total <= PART_LIMIT {
        return Ok(head);
    }
    let omitted = total.saturating_sub(head.len() + tail.len());
    head.extend_from_slice(format!("\n...[{omitted} bytes omitted]...\n").as_bytes());
    head.extend_from_slice(&tail);
    Ok(head)
}

fn command_diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
    const PER_STREAM_LIMIT: usize = 32 * 1024;
    let stdout = &stdout[..stdout.len().min(PER_STREAM_LIMIT)];
    let stderr = &stderr[..stderr.len().min(PER_STREAM_LIMIT)];
    let mut diagnostic = String::from_utf8_lossy(stdout).into_owned();
    diagnostic.push_str(&String::from_utf8_lossy(stderr));
    diagnostic
}

fn parse_metric_output(output: &BoundedOutput, name: &str) -> Option<(usize, usize)> {
    parse_metric_streams(&output.stdout, &output.stderr, name)
}

fn parse_metric_streams(stdout: &[u8], stderr: &[u8], name: &str) -> Option<(usize, usize)> {
    parse_metric(&String::from_utf8_lossy(stdout), name)
        .or_else(|| parse_metric(&String::from_utf8_lossy(stderr), name))
}

fn parse_metric(diagnostic: &str, name: &str) -> Option<(usize, usize)> {
    diagnostic.lines().find_map(|line| {
        let counts = line
            .trim()
            .strip_prefix(name)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        let (value, total) = counts.split_once('/')?;
        let total = total.split_whitespace().next()?;
        Some((value.trim().parse().ok()?, total.parse().ok()?))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command as ProcessCommand;

    use super::*;

    fn make_executable(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn fake_rewriter_with_coverage(
        patched: usize,
        recovered: usize,
        b0: Option<usize>,
    ) -> (tempfile::TempDir, E9patchRewriter) {
        let directory = tempfile::tempdir().unwrap();
        let e9tool = directory.path().join("e9tool");
        let e9patch = directory.path().join("e9patch");
        let b0_metric = b0.map_or_else(String::new, |value| {
            format!("printf 'num_patched_B0 = {value} / {recovered}\\n'\n")
        });
        let script = format!(
            r#"#!/bin/sh
set -eu
input=
output=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --backend|-M|-P)
            shift 2
            ;;
        --seed=*|--option=*|-O0)
            shift
            ;;
        -o)
            output=$2
            shift 2
            ;;
        *)
            input=$1
            shift
            ;;
    esac
done
cp "$input" "$output"
printf 'num_patched = {patched} / {recovered}\n'
{b0_metric}"#
        );
        make_executable(&e9tool, script.as_bytes());
        make_executable(&e9patch, b"#!/bin/sh\nexit 0\n");
        let rewriter = E9patchRewriter::new(e9tool, e9patch);
        (directory, rewriter)
    }

    fn fake_rewriter() -> (tempfile::TempDir, E9patchRewriter) {
        fake_rewriter_with_coverage(0, 0, None)
    }

    fn execute_materialized(prepared: &PreparedBinary) -> std::process::ExitStatus {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("guest");
        let mut artifact = prepared.artifact().unwrap();
        let mut output = File::create(&path).unwrap();
        io::copy(&mut artifact, &mut output).unwrap();
        drop(output);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).unwrap();
        ProcessCommand::new(path).status().unwrap()
    }

    #[test]
    fn prepares_exact_sealed_executable_bytes() {
        let input = fs::read("/bin/true").unwrap();
        let (_directory, rewriter) = fake_rewriter();
        let prepared = rewriter.prepare("/bin/true").unwrap();
        let report = prepared.report();

        assert_eq!(report.input_sha256(), sha256(&input));
        assert_eq!(report.output_sha256(), sha256(&input));
        assert_eq!(report.patched_sites(), 0);
        assert_eq!(report.recovered_sites(), 0);
        assert_eq!(report.b0_sites(), 0);

        let mut artifact = prepared.artifact().unwrap();
        let seals = unsafe { libc::fcntl(artifact.as_raw_fd(), libc::F_GET_SEALS) };
        assert!(
            seals >= 0,
            "F_GET_SEALS failed: {}",
            io::Error::last_os_error()
        );
        let expected =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(seals & expected, expected);

        let mut bytes = Vec::new();
        artifact.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, input);
        assert_eq!(sha256(&bytes), report.output_sha256());
        artifact.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            artifact.write_all(b"changed").unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        let mut sealed_writer = prepared.artifact.try_clone().unwrap();
        assert_eq!(
            sealed_writer
                .write_all(b"changed")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            sealed_writer
                .set_len((bytes.len() + 1) as u64)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(
            sealed_writer
                .set_len((bytes.len() - 1) as u64)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(execute_materialized(&prepared).success());
    }

    #[test]
    fn successive_artifacts_have_independent_zeroed_cursors() {
        let (_directory, rewriter) = fake_rewriter();
        let prepared = rewriter.prepare("/bin/true").unwrap();
        let expected = fs::read("/bin/true").unwrap();

        let mut first = prepared.artifact().unwrap();
        let mut second = prepared.artifact().unwrap();
        let mut first_bytes = Vec::new();
        let mut second_bytes = Vec::new();
        first.read_to_end(&mut first_bytes).unwrap();
        second.read_to_end(&mut second_bytes).unwrap();
        assert_eq!(first_bytes, expected);
        assert_eq!(second_bytes, expected);
    }

    #[test]
    fn duplicated_artifact_outlives_token() {
        let (_directory, rewriter) = fake_rewriter();
        let prepared = rewriter.prepare("/bin/true").unwrap();
        let expected = prepared.report().output_sha256().to_owned();
        let mut artifact = prepared.artifact().unwrap();
        drop(prepared);

        let mut bytes = Vec::new();
        artifact.read_to_end(&mut bytes).unwrap();
        assert_eq!(sha256(&bytes), expected);
    }

    #[test]
    fn rejects_non_elf_tool_output() {
        let input = fs::read("/bin/true").unwrap();
        let input_type = validate_elf_image(&input, Path::new("input"))
            .unwrap()
            .header
            .e_type;
        let error = validate_elf_output(
            &input,
            input_type,
            b"#!/bin/sh\nexit 0\n",
            Path::new("output"),
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid ELF executable"));
    }

    #[test]
    fn rejects_relocatable_elf_input() {
        let mut input = fs::read("/bin/true").unwrap();
        input[16..18].copy_from_slice(&goblin::elf::header::ET_REL.to_le_bytes());
        let error = validate_elf_image(&input, Path::new("input")).unwrap_err();
        assert!(error.to_string().contains("ET_EXEC or ET_DYN"));
    }

    #[test]
    fn partial_patch_coverage_fails_closed() {
        let (_directory, rewriter) = fake_rewriter_with_coverage(1, 2, None);
        let error = match rewriter.prepare("/bin/true") {
            Ok(_) => panic!("partial coverage was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("patched only 1/2"));
    }

    #[test]
    fn signal_fallback_sites_fail_closed_when_reported() {
        let (_directory, rewriter) = fake_rewriter_with_coverage(2, 2, Some(1));
        let error = match rewriter.prepare("/bin/true") {
            Ok(_) => panic!("B0 coverage was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("signal-based B0"));
    }

    #[test]
    fn absent_b0_metric_is_valid_when_tactic_is_disabled() {
        let (_directory, rewriter) = fake_rewriter_with_coverage(0, 0, None);
        let prepared = rewriter.prepare("/bin/true").unwrap();
        assert_eq!(prepared.report().b0_sites(), 0);
    }

    #[test]
    fn privilege_bearing_input_fails_before_tool_execution() {
        let directory = tempfile::tempdir().unwrap();
        let guest = directory.path().join("guest");
        fs::copy("/bin/true", &guest).unwrap();
        let mut permissions = fs::metadata(&guest).unwrap().permissions();
        permissions.set_mode(0o4755);
        fs::set_permissions(&guest, permissions).unwrap();
        let missing = directory.path().join("missing");
        let rewriter = E9patchRewriter::new(&missing, &missing);
        let error = match rewriter.prepare(&guest) {
            Ok(_) => panic!("privilege-bearing input was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("privilege-bearing"));
    }

    #[test]
    fn missing_external_tool_is_actionable() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing");
        let rewriter = E9patchRewriter::new(&missing, &missing);
        let error = match rewriter.prepare("/bin/true") {
            Ok(_) => panic!("missing tool was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("cannot resolve e9tool"));
        assert!(error.to_string().contains(&missing.display().to_string()));
    }

    #[test]
    fn parses_patch_and_b0_metrics_exactly() {
        let diagnostic = "num_patched = 7 / 7 (100.00%)\nnum_patched_B0 = 0 / 7 (0.00%)\n";
        assert_eq!(parse_metric(diagnostic, "num_patched"), Some((7, 7)));
        assert_eq!(parse_metric(diagnostic, "num_patched_B0"), Some((0, 7)));
        assert_eq!(parse_metric(diagnostic, "num_patched_B1"), None);
    }

    #[test]
    fn parses_metrics_after_bounded_diagnostic_prefix() {
        let mut emitted = vec![b'a'; 40 * 1024];
        emitted.push(b'\n');
        emitted.extend_from_slice(b"num_patched = 3 / 3 (100.00%)\n");
        let stdout = capture_bounded(io::Cursor::new(emitted)).unwrap();
        assert!(stdout.len() < 17 * 1024);
        assert_eq!(
            parse_metric_streams(&stdout, &[], "num_patched"),
            Some((3, 3))
        );
        assert!(command_diagnostic(&stdout, &[]).contains("num_patched"));
    }

    #[test]
    fn diagnostic_is_bounded_per_stream() {
        let stdout = capture_bounded(io::Cursor::new(vec![b'a'; 40 * 1024])).unwrap();
        let stderr = capture_bounded(io::Cursor::new(vec![b'b'; 40 * 1024])).unwrap();
        let diagnostic = command_diagnostic(&stdout, &stderr);
        assert!(diagnostic.len() < 34 * 1024);
        assert!(diagnostic.starts_with('a'));
        assert!(diagnostic.ends_with('b'));
    }

    #[test]
    #[ignore = "requires a built e9tool/e9patch pair and direct-syscall guest"]
    fn real_toolchain_rewrites_direct_syscall_guest() {
        let guest = std::env::var_os("REVERIE_E9PATCH_REAL_GUEST")
            .expect("set REVERIE_E9PATCH_REAL_GUEST to a direct-syscall ELF");
        let prepared = E9patchRewriter::from_env().unwrap().prepare(guest).unwrap();
        assert!(prepared.report().patched_sites() > 0);
        assert_eq!(
            prepared.report().patched_sites(),
            prepared.report().recovered_sites()
        );
        assert!(execute_materialized(&prepared).success());
    }
}
