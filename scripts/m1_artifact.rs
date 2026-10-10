//! Shared, fail-closed constructor and diagnostic artifact qualification.
//! No Cargo invocation is implicit in consumer verification. Producer commands
//! are bounded separately from the enclosing validation DAG's CPU/memory/PID containment.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use goblin::elf::Elf;
use goblin::elf::header;
use goblin::elf::program_header;
use goblin::elf::reloc;
use goblin::elf::section_header;
use goblin::elf::sym;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

pub type Result<T> = std::result::Result<T, String>;
pub const SCHEMA: u32 = 2;
/// Explicit constructor contract for the genuine standalone preload. Generic
/// embeddings and Detcore continue to request their exported initializer name.
pub const STANDALONE_ROOT: &str = "reverie_liteinst_standalone_entry";
const GENERIC_INITIALIZER: &str = "reverie_liteinst_initialize";
const STANDALONE_BODY: &str = "reverie_liteinst_standalone_body";
const STANDALONE_INITIALIZER: &str = "reverie_liteinst_standalone_initialize";
const STANDALONE_RESOLVER: &str = "reverie_liteinst_resolve_real_dl_find_object";
const CONSTRUCTOR_BRIDGE: &str = "reverie_inguest_constructor_entry";
const CONSTRUCTOR_ADOPTION: &str = "reverie_inguest_constructor_adopt_entry";
const CONSTRUCTOR_GATE: &str = "reverie_inguest_trusted_syscall_ip";
const CONSTRUCTOR_GATE_OWNER: &str = "reverie_inguest_trusted_syscall";
const CONSTRUCTOR_GATE_RETURN: &str = "reverie_inguest_trusted_syscall_return_ip";
pub const FROZEN_RUST_ORACLE: &str =
    "d85c3094519855dde18571047b945aeca112b8e4df2138cff83fc33bfba0bce8";
pub const FROZEN_C_ORACLE: &str =
    "e21fd8768d61edc7d14f51b98e2c5f9087fd4ddcfa08a19a2ca646b6df912b2e";
pub const EXPORTS: [&str; 5] = [
    "m1_alloc",
    "m1_realloc",
    "m1_dealloc",
    "m1_query",
    "m1_probe_private",
];
pub const SHIMS: [&str; 4] = [
    "__rust_alloc",
    "__rust_alloc_zeroed",
    "__rust_realloc",
    "__rust_dealloc",
];
const ALLOWED_NEEDED: [&str; 7] = [
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libutil.so.1",
];

fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Hash the exact source compiled into this host proof library/module. Consumers
/// compare it with Cargo metadata's canonical library target source, independent
/// of the runtime artifact's package and source identity.
pub fn qualifier_source_sha256() -> String {
    sha256(include_bytes!("m1_artifact.rs"))
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("hash {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn real_file(path: &Path) -> Result<PathBuf> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("metadata {}: {e}", path.display()))?;
    require(
        metadata.file_type().is_file(),
        format!("not a real regular file: {}", path.display()),
    )?;
    fs::canonicalize(path).map_err(|e| format!("canonicalize {}: {e}", path.display()))
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub path: PathBuf,
    pub sha256: String,
}

impl FileIdentity {
    pub fn read(path: &Path) -> Result<Self> {
        let path = real_file(path)?;
        let sha256 = file_sha256(&path)?;
        Ok(Self { path, sha256 })
    }
    pub fn verify(&self) -> Result<()> {
        require(
            Self::read(&self.path)? == *self,
            format!("file identity changed: {}", self.path.display()),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEvidence {
    pub program: String,
    pub arguments: Vec<String>,
    pub cwd: PathBuf,
    pub status: i32,
    pub elapsed_millis: u128,
    pub stdout: FileIdentity,
    pub stderr: FileIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestReceipt {
    pub schema_version: u32,
    pub source: FileIdentity,
    pub binary: FileIdentity,
    pub compiler_version: String,
    pub command: CommandEvidence,
    pub executed_tests: u64,
}

pub fn verify_guest_receipt(
    receipt_path: &Path,
    binary_path: &Path,
    expected_source: &Path,
    expected_source_hash: &str,
) -> Result<GuestReceipt> {
    let bytes = fs::read(real_file(receipt_path)?).map_err(|e| e.to_string())?;
    let receipt: GuestReceipt =
        serde_json::from_slice(&bytes).map_err(|e| format!("C guest receipt: {e}"))?;
    require(
        receipt.schema_version == 1 && receipt.executed_tests == 0 && receipt.command.status == 0,
        "C guest is not a successful source-bound producer receipt",
    )?;
    require(
        receipt.source.path == real_file(expected_source)?
            && receipt.source.sha256 == expected_source_hash,
        "C guest frozen source identity differs",
    )?;
    require(
        receipt.binary.path == real_file(binary_path)?,
        "C guest selected path differs",
    )?;
    receipt.source.verify()?;
    receipt.binary.verify()?;
    receipt.command.stdout.verify()?;
    receipt.command.stderr.verify()?;
    let expected_arguments = vec![
        "-std=c11".to_owned(),
        "-O0".to_owned(),
        "-fno-builtin".to_owned(),
        "-fno-lto".to_owned(),
        "-Wl,--export-dynamic".to_owned(),
        "-Wl,-z,now".to_owned(),
        receipt
            .source
            .path
            .to_str()
            .ok_or("C source path is not UTF-8")?
            .to_owned(),
        "-o".to_owned(),
        receipt
            .binary
            .path
            .to_str()
            .ok_or("C binary path is not UTF-8")?
            .to_owned(),
        "-ldl".to_owned(),
    ];
    require(
        receipt.command.arguments == expected_arguments,
        "C guest compile recipe differs from fixed source/output/flags",
    )?;
    Ok(receipt)
}

/// One shared absolute deadline; each stream has its own strict byte ceiling.
/// Every child is placed in a fresh process group. Overflow/deadline kills that
/// group; the enclosing DAG cgroup remains the authoritative descendant guard.
pub struct Runner {
    pub logs: PathBuf,
    pub deadline: Instant,
    pub max_stream_bytes: usize,
    serial: u32,
    pub commands: Vec<CommandEvidence>,
}

impl Runner {
    pub fn new(logs: PathBuf, budget: Duration, max_stream_bytes: usize) -> Result<Self> {
        require(
            budget.as_secs() > 0 && max_stream_bytes > 0,
            "command bounds must be positive",
        )?;
        fs::create_dir(&logs).map_err(|e| format!("create unique log directory: {e}"))?;
        Ok(Self {
            logs,
            deadline: Instant::now() + budget,
            max_stream_bytes,
            serial: 0,
            commands: Vec::new(),
        })
    }

    pub fn run(&mut self, program: &str, args: &[String], cwd: &Path) -> Result<Vec<u8>> {
        self.run_with_combined_limit(program, args, cwd, None)
    }

    fn run_with_combined_limit(
        &mut self,
        program: &str,
        args: &[String],
        cwd: &Path,
        combined_limit: Option<usize>,
    ) -> Result<Vec<u8>> {
        require(
            combined_limit != Some(0),
            "command aggregate byte limit must be positive",
        )?;
        require(
            Instant::now() < self.deadline,
            "producer command deadline exhausted",
        )?;
        self.serial += 1;
        let prefix = self.logs.join(format!("{:04}", self.serial));
        let mut command = Command::new(program);
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Do not let a diagnostic producer inherit runtime selectors into Cargo,
        // linker/tools or readelf; these only belong on the guest test launch.
        for name in [
            "LD_PRELOAD",
            "HERMIT_LITEINST_STAGE",
            "HERMIT_LITEINST_TOOL_RUNTIME",
            "REVERIE_LITEINST_PRELOAD",
            "REVERIE_LITEINST_TEST_RUNTIME_MANIFEST",
        ] {
            command.env_remove(name);
        }
        command.env("LC_ALL", "C").process_group(0);
        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|e| format!("spawn {program}: {e}"))?;
        let overflow = Arc::new(AtomicBool::new(false));
        let combined_bytes = Arc::new(AtomicUsize::new(0));
        let byte_limit_description = if combined_limit.is_some() {
            "command stream/aggregate byte limit"
        } else {
            "command stream byte limit"
        };
        let stop_reading = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for fd in [
            child.stdout.as_ref().unwrap().as_raw_fd(),
            child.stderr.as_ref().unwrap().as_raw_fd(),
        ] {
            // SAFETY: this child owns these valid pipe descriptors.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                return Err("cannot make producer pipes nonblocking".to_owned());
            }
        }
        let pipes: Vec<Box<dyn Read + Send>> = vec![
            Box::new(child.stdout.take().unwrap()),
            Box::new(child.stderr.take().unwrap()),
        ];
        for mut pipe in pipes {
            let overflow = Arc::clone(&overflow);
            let combined_bytes = Arc::clone(&combined_bytes);
            let stop_reading = Arc::clone(&stop_reading);
            let cap = self.max_stream_bytes;
            readers.push(thread::spawn(move || -> Result<Vec<u8>> {
                let mut kept = Vec::new();
                let mut bytes = [0u8; 8192];
                let mut drain_started = None;
                loop {
                    if stop_reading.load(Ordering::Acquire) {
                        let at = drain_started.get_or_insert_with(Instant::now);
                        if at.elapsed() >= Duration::from_millis(250) {
                            overflow.store(true, Ordering::Release);
                            break;
                        }
                    }
                    let n = match pipe.read(&mut bytes) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stop_reading.load(Ordering::Acquire) {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(format!("read child stream: {e}")),
                    };
                    if n == 0 {
                        break;
                    }
                    let combined_room = if let Some(limit) = combined_limit {
                        let mut before = combined_bytes.load(Ordering::Acquire);
                        loop {
                            match combined_bytes.compare_exchange_weak(
                                before,
                                before.saturating_add(n),
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            ) {
                                Ok(_) => break limit.saturating_sub(before),
                                Err(observed) => before = observed,
                            }
                        }
                    } else {
                        usize::MAX
                    };
                    let room = cap.saturating_sub(kept.len()).min(combined_room);
                    kept.extend_from_slice(&bytes[..n.min(room)]);
                    if n > room {
                        overflow.store(true, Ordering::Release);
                    }
                }
                Ok(kept)
            }));
        }
        let mut bounds_failure = None;
        let mut killed_at = None;
        let status = loop {
            if killed_at.is_none()
                && (overflow.load(Ordering::Acquire) || Instant::now() >= self.deadline)
            {
                bounds_failure = Some(if overflow.load(Ordering::Acquire) {
                    byte_limit_description
                } else {
                    "producer deadline"
                });
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                killed_at = Some(Instant::now());
            }
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // WNOWAIT reserves the leader PID until killpg; reaping first could
            // target another job if the group identity were reused.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                bounds_failure =
                    Some("producer waitid failed; enclosing cgroup must reclaim child");
                break std::process::ExitStatus::from_raw(libc::SIGKILL);
            }
            if unsafe { info.si_pid() } != 0 {
                unsafe {
                    libc::kill(-(child.id() as i32), libc::SIGKILL);
                }
                break child
                    .wait()
                    .map_err(|e| format!("reap exited {program}: {e}"))?;
            }
            if killed_at.is_some_and(|at| at.elapsed() >= Duration::from_secs(1)) {
                bounds_failure =
                    Some("producer cleanup deadline; enclosing cgroup must reclaim child");
                break std::process::ExitStatus::from_raw(libc::SIGKILL);
            }
            thread::sleep(Duration::from_millis(50));
        };
        stop_reading.store(true, Ordering::Release);
        let stdout = readers
            .remove(0)
            .join()
            .map_err(|_| "stdout reader panicked")??;
        let stderr = readers
            .remove(0)
            .join()
            .map_err(|_| "stderr reader panicked")??;
        if overflow.load(Ordering::Acquire) {
            bounds_failure = Some(byte_limit_description);
        }
        let stdout_path = prefix.with_extension("stdout");
        let stderr_path = prefix.with_extension("stderr");
        write_new(&stdout_path, &stdout)?;
        write_new(&stderr_path, &stderr)?;
        let evidence = CommandEvidence {
            program: program.to_owned(),
            arguments: args.to_vec(),
            cwd: fs::canonicalize(cwd).map_err(|e| e.to_string())?,
            status: status.code().unwrap_or(-1),
            elapsed_millis: start.elapsed().as_millis(),
            stdout: FileIdentity::read(&stdout_path)?,
            stderr: FileIdentity::read(&stderr_path)?,
        };
        write_new(
            &prefix.with_extension("command.json"),
            &serde_json::to_vec_pretty(&evidence).map_err(|e| e.to_string())?,
        )?;
        self.commands.push(evidence);
        require(
            bounds_failure.is_none(),
            format!(
                "{program} exceeded {}; logs {}",
                bounds_failure.unwrap_or(""),
                prefix.display()
            ),
        )?;
        require(
            status.success(),
            format!("{program} failed ({status}); logs {}", prefix.display()),
        )?;
        Ok(stdout)
    }

    pub fn text(&mut self, program: &str, args: &[&str], cwd: &Path) -> Result<String> {
        let args: Vec<_> = args.iter().map(|s| (*s).to_owned()).collect();
        String::from_utf8(self.run(program, &args, cwd)?)
            .map_err(|e| format!("{program} output is not UTF-8: {e}"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub root: PathBuf,
    pub head: String,
    pub tree: String,
    pub status: String,
    pub lock: FileIdentity,
    /// Includes both unchanged Rust export and fixed C workload sources.
    pub oracles: BTreeMap<String, FileIdentity>,
}

pub fn source_identity(
    root: &Path,
    lock: &Path,
    oracles: &BTreeMap<String, PathBuf>,
    runner: &mut Runner,
) -> Result<SourceIdentity> {
    let root = fs::canonicalize(root).map_err(|e| format!("source root: {e}"))?;
    let observed_root = runner.text("git", &["rev-parse", "--show-toplevel"], &root)?;
    require(
        Path::new(observed_root.trim()) == root,
        "source root must be the exact Git worktree root",
    )?;
    let head = runner
        .text("git", &["rev-parse", "HEAD"], &root)?
        .trim()
        .to_owned();
    let tree = runner
        .text("git", &["rev-parse", "HEAD^{tree}"], &root)?
        .trim()
        .to_owned();
    require(
        head.len() == 40
            && tree.len() == 40
            && head
                .bytes()
                .chain(tree.bytes())
                .all(|b| b.is_ascii_hexdigit()),
        "source is not a 40-hex commit/tree",
    )?;
    let status = runner.text(
        "git",
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        &root,
    )?;
    require(
        status.is_empty(),
        format!("source must be clean before/after build: {status}"),
    )?;
    let lock = FileIdentity::read(lock)?;
    require(
        lock.path.starts_with(&root),
        "lock must be inside source worktree",
    )?;
    require(
        oracles.contains_key("rust_exports") && oracles.contains_key("c_workload"),
        "both fixed oracle source identities are required",
    )?;
    let oracles = oracles
        .iter()
        .map(|(label, path)| Ok((label.clone(), FileIdentity::read(path)?)))
        .collect::<Result<_>>()?;
    Ok(SourceIdentity {
        root,
        head,
        tree,
        status,
        lock,
        oracles,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub id: String,
    pub name: String,
    pub manifest: PathBuf,
    pub source: Option<String>,
    pub target: String,
    pub kind: Vec<String>,
    pub crate_types: Vec<String>,
    pub target_source: PathBuf,
}

/// Explicit expected manifest/source prevents selecting a lookalike workspace
/// package or wrong Cargo Git checkout with the same name. H passes the resolved
/// exact-pin Git package manifest and full metadata source string here.
pub fn select_package(
    metadata: &Value,
    name: &str,
    target_name: &str,
    expected_manifest: &Path,
    expected_source: Option<&str>,
) -> Result<PackageIdentity> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("metadata has no packages")?;
    let candidates: Vec<_> = packages.iter().filter(|p| p["name"] == name).collect();
    require(
        candidates.len() == 1,
        format!("expected exactly one metadata package {name}"),
    )?;
    let p = candidates[0];
    let manifest = real_file(Path::new(
        p["manifest_path"]
            .as_str()
            .ok_or("package manifest missing")?,
    ))?;
    require(
        manifest == real_file(expected_manifest)?,
        "selected package manifest differs from required checkout",
    )?;
    let source = p["source"].as_str().map(str::to_owned);
    require(
        source.as_deref() == expected_source,
        "selected Cargo package source differs from expected exact pin",
    )?;
    let targets = p["targets"]
        .as_array()
        .ok_or("metadata package has no targets")?;
    let targets: Vec<_> = targets
        .iter()
        .filter(|t| t["name"] == target_name)
        .collect();
    require(targets.len() == 1, "expected exactly one named leaf target")?;
    let t = targets[0];
    let kind = strings(&t["kind"])?;
    let crate_types = strings(&t["crate_types"])?;
    require(
        kind == ["cdylib"] && crate_types == ["cdylib"],
        "real preload target must be cdylib-only",
    )?;
    Ok(PackageIdentity {
        id: p["id"]
            .as_str()
            .ok_or("metadata package ID missing")?
            .to_owned(),
        name: name.to_owned(),
        manifest,
        source,
        target: target_name.to_owned(),
        kind,
        crate_types,
        target_source: real_file(Path::new(
            t["src_path"].as_str().ok_or("target src_path missing")?,
        ))?,
    })
}

fn strings(value: &Value) -> Result<Vec<String>> {
    value
        .as_array()
        .ok_or_else(|| "expected string array".to_owned())?
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "non-string array entry".to_owned())
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CargoArtifact {
    pub package: PackageIdentity,
    pub features: Vec<String>,
    /// Exact Cargo message profile. Custom profiles cannot be inferred from
    /// its fields alone; receipt separately records the explicit command name.
    pub profile: Value,
    pub fresh: bool,
    pub reported_path: PathBuf,
}

pub fn select_artifact(
    messages: &str,
    package: &PackageIdentity,
    expected_features: &[String],
    expected_profile: &Value,
    target_dir: &Path,
) -> Result<CargoArtifact> {
    let mut candidates = Vec::new();
    let mut finished = Vec::new();
    let mut expected_features = expected_features.to_vec();
    expected_features.sort();
    expected_features.dedup();
    for (index, line) in messages.lines().filter(|line| !line.is_empty()).enumerate() {
        let m: Value = serde_json::from_str(line)
            .map_err(|e| format!("Cargo JSON line {}: {e}", index + 1))?;
        if m["reason"] == "build-finished" {
            finished.push(m["success"].as_bool());
        }
        if m["reason"] != "compiler-artifact"
            || m["package_id"] != package.id
            || m["target"]["name"] != package.target
        {
            continue;
        }
        require(
            real_file(Path::new(
                m["manifest_path"]
                    .as_str()
                    .ok_or("artifact manifest_path missing")?,
            ))? == package.manifest,
            "artifact manifest mismatch",
        )?;
        require(
            strings(&m["target"]["kind"])? == package.kind
                && strings(&m["target"]["crate_types"])? == package.crate_types,
            "artifact target kind/crate-types mismatch",
        )?;
        require(
            real_file(Path::new(
                m["target"]["src_path"]
                    .as_str()
                    .ok_or("artifact target source missing")?,
            ))? == package.target_source,
            "artifact target source mismatch",
        )?;
        let mut features = strings(&m["features"])?;
        features.sort();
        require(
            features == expected_features,
            format!("artifact feature set differs: {features:?}, expected {expected_features:?}"),
        )?;
        require(
            &m["profile"] == expected_profile,
            format!("artifact profile differs: {}", m["profile"]),
        )?;
        let outputs: Vec<_> = strings(&m["filenames"])?
            .into_iter()
            .map(PathBuf::from)
            .filter(|p| p.extension().is_some_and(|e| e == "so"))
            .collect();
        require(
            outputs.len() == 1,
            "leaf compiler-artifact must report exactly one shared object",
        )?;
        let reported_path = real_file(&outputs[0])?;
        let target_dir = fs::canonicalize(target_dir).map_err(|e| e.to_string())?;
        require(
            reported_path.starts_with(target_dir),
            "artifact output is outside explicit separate target directory",
        )?;
        candidates.push(CargoArtifact {
            package: package.clone(),
            features,
            profile: m["profile"].clone(),
            fresh: m["fresh"].as_bool().ok_or("artifact freshness missing")?,
            reported_path,
        });
    }
    require(
        finished == [Some(true)],
        "Cargo must report exactly one successful build-finished message",
    )?;
    require(
        candidates.len() == 1,
        format!(
            "expected one current compiler-artifact; found {}",
            candidates.len()
        ),
    )?;
    Ok(candidates.remove(0))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolEvidence {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub binding: u8,
    pub visibility: u8,
}

/// Constructor-only evidence for the normal, feature-empty standalone leaf.
/// This distinct type cannot satisfy the mandatory diagnostic RuntimeReceipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructorQualification {
    pub artifact: FileIdentity,
    pub initializer: SymbolEvidence,
    pub init_array_slot: u64,
    pub init_array_resolution: String,
    pub standalone_constructor: StandaloneConstructorEvidence,
    pub needed: Vec<String>,
    pub required_versions: Vec<String>,
    pub readelf_versions: FileIdentity,
    pub readelf_symbols_relocations: FileIdentity,
    pub objdump_disassembly: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElfQualification {
    pub initializer: SymbolEvidence,
    pub init_array_slot: u64,
    pub init_array_resolution: String,
    /// Present only for the explicit standalone contract. This is emitted
    /// constructor routing evidence, not execution or whole-memory isolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standalone_constructor: Option<StandaloneConstructorEvidence>,
    pub exports: Vec<SymbolEvidence>,
    pub allocation_shims: BTreeMap<String, SymbolEvidence>,
    pub needed: Vec<String>,
    pub required_versions: Vec<String>,
    /// Each route lists direct locally resolved call/tail-call addresses from
    /// the actual exported entry point to its compiler-selected shim.
    pub call_paths: BTreeMap<String, Vec<u64>>,
    /// Inlined operations have an actual endpoint proof, never an invented
    /// export->unused-shim edge. Both actual entry and its respective LOCAL shim
    /// must reach the same LOCAL owned allocation endpoint.
    pub inline_routes: BTreeMap<String, InlineAllocationRoute>,
    /// Local, nonpreemptible RIP-relative GOT routes encountered in actual
    /// selected proof-source instructions. Each entry records the instruction, slot and RELATIVE
    /// target; a generic indirect instruction alone earns no qualification.
    pub local_got_edges: Vec<GotEdge>,
    /// Named methods can be optimized away. These optional emitted paths are
    /// observations; absence never waives the frozen runtime ownership oracle.
    pub named_private_allocator_paths: BTreeMap<String, Vec<u64>>,
    pub named_private_allocator_observation: String,
    pub readelf_versions: FileIdentity,
    pub readelf_symbols_relocations: FileIdentity,
    pub objdump_disassembly: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructorTransfer {
    pub instruction: u64,
    pub target: u64,
    pub local_got_slot: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandaloneConstructorEvidence {
    pub generic_initializer: SymbolEvidence,
    pub body: SymbolEvidence,
    pub selected_initializer: SymbolEvidence,
    pub resolver: SymbolEvidence,
    pub bridge: SymbolEvidence,
    pub adoption: SymbolEvidence,
    /// Zero-size interior instruction label, not a standalone function.
    pub native_gate: SymbolEvidence,
    pub native_gate_owner: SymbolEvidence,
    pub native_gate_return: SymbolEvidence,
    pub native_gate_offset: u64,
    /// Finite dev Result::is_err call route; never a generic graph edge.
    pub adoption_helper_edges: Vec<GotEdge>,
    pub function_sha256: BTreeMap<String, String>,
    pub environ_got_slot: u64,
    pub selector_address: u64,
    pub active_body_materialization: u64,
    pub active_bridge_transfer: ConstructorTransfer,
    pub inert_resolver_transfer: ConstructorTransfer,
    pub body_initializer_call: ConstructorTransfer,
    pub body_resolver_transfer: ConstructorTransfer,
    pub bridge_adoption_call: ConstructorTransfer,
    pub body_pointer_load: u64,
    pub adoption_body_call: u64,
    pub adoption_recipe: String,
    pub bootstrap_record: u64,
    pub bootstrap_bottom: u64,
    pub bootstrap_top: u64,
    pub observation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotEdge {
    pub source_function: u64,
    pub instruction: u64,
    pub slot: u64,
    pub target_function: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineAllocationRoute {
    pub entry: SymbolEvidence,
    pub shim: SymbolEvidence,
    pub target: SymbolEvidence,
    pub entry_to_endpoint: Vec<u64>,
    pub shim_to_endpoint: Vec<u64>,
    pub entry_got_edges: Vec<GotEdge>,
    pub shim_got_edges: Vec<GotEdge>,
    pub observation: String,
}

fn qualifies_owned_endpoint(name: &str) -> bool {
    let name = name.split(".llvm.").next().unwrap_or(name);
    ((name.contains("PrivatePatchAllocator") || name.contains("PrivateToolAllocator"))
        && name.contains("GlobalAlloc")
        && (name.ends_with("5alloc") || name.ends_with("12alloc_zeroed")))
        || (name.contains("ToolHeap") && name.ends_with("8allocate"))
}

fn allocation_wrapper(name: &str) -> bool {
    name.contains("allocator_fixture") && name.contains("m1_")
        || [
            "5alloc5alloc5alloc",
            "5alloc5alloc12alloc_zeroed",
            "5alloc5alloc7realloc",
            "5alloc5alloc7dealloc",
        ]
        .iter()
        .any(|pattern| name.contains(pattern))
}

fn called_shim_path(
    elf: &Elf<'_>,
    graph: &BTreeMap<u64, BTreeSet<u64>>,
    entry: u64,
    shim: u64,
) -> Result<Vec<u64>> {
    let wrappers: BTreeSet<_> = elf
        .syms
        .iter()
        .filter_map(|s| {
            elf.strtab
                .get_at(s.st_name)
                .filter(|name| allocation_wrapper(name))
                .map(|_| s.st_value)
        })
        .chain([entry, shim])
        .collect();
    // Panic/cleanup/container allocation is not evidence that the exported
    // operation's std::alloc call executes its compiler-selected shim.
    let restricted = graph
        .iter()
        .filter(|(source, _)| wrappers.contains(source))
        .map(|(source, targets)| {
            (
                *source,
                targets
                    .iter()
                    .filter(|target| wrappers.contains(target))
                    .copied()
                    .collect(),
            )
        })
        .collect();
    shortest_path(&restricted, entry, shim)
}

fn qualify_inline_route(
    key: &str,
    elf: &Elf<'_>,
    entry: &SymbolEvidence,
    shim: &SymbolEvidence,
    graph: &BTreeMap<u64, BTreeSet<u64>>,
    got_edges: &[GotEdge],
) -> Result<InlineAllocationRoute> {
    require(
        matches!(
            key,
            "m1_alloc->__rust_alloc" | "m1_alloc->__rust_alloc_zeroed"
        ),
        "unsupported optimized allocation route",
    )?;
    let names: BTreeMap<_, _> = elf
        .syms
        .iter()
        .filter(|s| executable_symbol(elf, s))
        .filter_map(|s| elf.strtab.get_at(s.st_name).map(|name| (s.st_value, name)))
        .collect();
    let route_nodes: BTreeSet<_> = names
        .iter()
        .filter(|(_, name)| allocation_wrapper(name) || qualifies_owned_endpoint(name))
        .map(|(address, _)| *address)
        .chain([entry.address, shim.address])
        .collect();
    let restricted = graph
        .iter()
        .filter(|(source, _)| route_nodes.contains(source))
        .map(|(source, targets)| {
            (
                *source,
                targets
                    .iter()
                    .filter(|target| route_nodes.contains(target))
                    .copied()
                    .collect(),
            )
        })
        .collect();
    let avoids_legacy = |path: &[u64]| {
        path.iter().all(|address| {
            names.get(address).is_none_or(|name| {
                !name.contains("GuestAllocator")
                    && !(name.contains("PatchAllocator") && !name.contains("PrivatePatchAllocator"))
            })
        })
    };
    let path_edges = |path: &[u64]| {
        got_edges
            .iter()
            .filter(|edge| {
                path.windows(2)
                    .any(|pair| edge.source_function == pair[0] && edge.target_function == pair[1])
            })
            .cloned()
            .collect()
    };
    let mut candidates = Vec::new();
    for symbol in elf
        .syms
        .iter()
        .filter(|s| executable_symbol(elf, s) && s.st_bind() == sym::STB_LOCAL)
    {
        let Some(name) = elf
            .strtab
            .get_at(symbol.st_name)
            .filter(|name| qualifies_owned_endpoint(name))
        else {
            continue;
        };
        let Ok(entry_path) = shortest_path(&restricted, entry.address, symbol.st_value) else {
            continue;
        };
        let Ok(shim_path) = shortest_path(&restricted, shim.address, symbol.st_value) else {
            continue;
        };
        if avoids_legacy(&entry_path) && avoids_legacy(&shim_path) {
            candidates.push((entry_path, shim_path, symbol_evidence(name, &symbol)));
        }
    }
    candidates.sort_by_key(|(entry, shim, target)| (entry.len() + shim.len(), target.address));
    let (entry_to_endpoint, shim_to_endpoint, target) = candidates.into_iter().next().ok_or_else(|| format!("{key}: no actual export and respective LOCAL shim routes to the same LOCAL owned allocation endpoint; emitted evidence incomplete"))?;
    Ok(InlineAllocationRoute {
        entry: entry.clone(), shim: shim.clone(), target,
        entry_got_edges: path_edges(&entry_to_endpoint), shim_got_edges: path_edges(&shim_to_endpoint),
        entry_to_endpoint, shim_to_endpoint,
        observation: "Actual export reaches the same LOCAL owned endpoint as its separately emitted LOCAL compiler shim; the operation does not execute that shim. Distinct alloc/zeroed semantics and zero foreign allocator entries remain runtime assertions.".to_owned(),
    })
}

fn executable_symbol(elf: &Elf<'_>, s: &sym::Sym) -> bool {
    s.st_type() == sym::STT_FUNC
        && s.st_shndx != section_header::SHN_UNDEF as usize
        && s.st_value != 0
        && s.st_size > 0
        && elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_LOAD
                && p.p_flags & program_header::PF_X != 0
                && s.st_value >= p.p_vaddr
                && s.st_value
                    .checked_add(s.st_size)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        })
}

fn symbol_evidence(name: &str, s: &sym::Sym) -> SymbolEvidence {
    SymbolEvidence {
        name: name.to_owned(),
        address: s.st_value,
        size: s.st_size,
        binding: s.st_bind(),
        visibility: s.st_visibility(),
    }
}

fn export(elf: &Elf<'_>, name: &str) -> Result<(usize, sym::Sym)> {
    let candidates: Vec<_> = elf
        .dynsyms
        .iter()
        .enumerate()
        .filter(|(_, s)| elf.dynstrtab.get_at(s.st_name) == Some(name) && executable_symbol(elf, s))
        .collect();
    require(
        candidates.len() == 1,
        format!("required unique defined dynamic function {name} is absent/ambiguous"),
    )?;
    let (index, s) = candidates[0];
    require(
        s.st_bind() == sym::STB_GLOBAL
            && matches!(s.st_visibility(), sym::STV_DEFAULT | sym::STV_PROTECTED),
        format!("required function {name} is not externally exported"),
    )?;
    Ok((index, s))
}

fn private_function(elf: &Elf<'_>, name: &str) -> Result<sym::Sym> {
    let candidates: Vec<_> =
        elf.syms
            .iter()
            .filter(|s| elf.strtab.get_at(s.st_name) == Some(name) && executable_symbol(elf, s))
            .chain(elf.dynsyms.iter().filter(|s| {
                elf.dynstrtab.get_at(s.st_name) == Some(name) && executable_symbol(elf, s)
            }))
            .collect();
    require(
        !candidates.is_empty(),
        format!("missing private constructor function {name}"),
    )?;
    let first = candidates[0];
    require(
        candidates.iter().all(|s| {
            s.st_value == first.st_value
                && s.st_size == first.st_size
                && private_constructor_binding(s.st_bind(), s.st_visibility())
        }),
        format!("constructor function {name} is ambiguous/preemptible"),
    )?;
    Ok(first)
}

fn private_constructor_binding(binding: u8, visibility: u8) -> bool {
    binding == sym::STB_LOCAL || matches!(visibility, sym::STV_HIDDEN | sym::STV_INTERNAL)
}

fn unique_standalone_slot(root_slots: &[u64], generic_slots: &[u64]) -> Result<u64> {
    require(
        generic_slots.is_empty(),
        "generic initializer is a second leaf init_array root",
    )?;
    require(
        root_slots.len() == 1,
        "standalone native root must have exactly one relocated init_array slot",
    )?;
    Ok(root_slots[0])
}

fn standalone_symbols(elf: &Elf<'_>) -> Result<BTreeMap<String, sym::Sym>> {
    let mut symbols = BTreeMap::new();
    for name in [
        STANDALONE_ROOT,
        STANDALONE_BODY,
        STANDALONE_INITIALIZER,
        STANDALONE_RESOLVER,
        CONSTRUCTOR_BRIDGE,
        CONSTRUCTOR_ADOPTION,
        CONSTRUCTOR_GATE_OWNER,
    ] {
        symbols.insert(name.to_owned(), private_function(elf, name)?);
    }
    // The dev adoption compiler emits a local Result<&ToolRegion,i32>::is_err
    // call. Select its full range only by the exact type/method role. Optimized
    // code may inline it; no arbitrary std function becomes a graph endpoint.
    for (name, symbol) in constructor_result_helpers(elf)? {
        symbols.insert(name, symbol);
    }
    // This cannot be inferred from an rlib/no_mangle declaration. Require the
    // actual public dynamic export even when the real leaf no longer calls it.
    symbols.insert(
        GENERIC_INITIALIZER.to_owned(),
        export(elf, GENERIC_INITIALIZER)?.1,
    );
    require(
        symbols
            .values()
            .map(|s| s.st_value)
            .collect::<BTreeSet<_>>()
            .len()
            == symbols.len(),
        "standalone constructor roles alias one another",
    )?;
    Ok(symbols)
}

fn constructor_result_helpers(elf: &Elf<'_>) -> Result<BTreeMap<String, sym::Sym>> {
    let mut result = BTreeMap::new();
    for symbol in elf.syms.iter().filter(|s| executable_symbol(elf, s)) {
        let Some(name) = elf.strtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.contains("_4core6result")
            && name.contains("6ResultR")
            && name.contains("15reverie_inguest5guest11tool_region10ToolRegionlE6is_err")
        {
            require(
                symbol.st_bind() == sym::STB_LOCAL,
                "constructor Result::is_err helper is preemptible",
            )?;
            if let Some(prior) = result.insert(name.to_owned(), symbol) {
                require(
                    prior.st_value == symbol.st_value
                        && prior.st_size == symbol.st_size
                        && prior.st_bind() == symbol.st_bind()
                        && prior.st_visibility() == symbol.st_visibility(),
                    "conflicting constructor Result::is_err symbol",
                )?;
            }
        }
    }
    require(
        result.len() <= 1,
        "ambiguous constructor Result::is_err helper",
    )?;
    Ok(result)
}

fn constructor_interior_label(elf: &Elf<'_>, name: &str, owner: &sym::Sym) -> Result<sym::Sym> {
    let labels: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .chain(
            elf.dynsyms
                .iter()
                .filter(|s| elf.dynstrtab.get_at(s.st_name) == Some(name)),
        )
        .collect();
    require(
        labels.len() == 1,
        format!("constructor interior label {name} is absent/ambiguous"),
    )?;
    let label = labels[0];
    require(
        owner.st_bind() == sym::STB_LOCAL
            && owner.st_visibility() == sym::STV_HIDDEN
            && label.st_type() == sym::STT_NOTYPE
            && label.st_size == 0
            && label.st_bind() == sym::STB_LOCAL
            && label.st_visibility() == sym::STV_HIDDEN
            && label.st_shndx == owner.st_shndx
            && label.st_value >= owner.st_value
            && owner
                .st_value
                .checked_add(owner.st_size)
                .is_some_and(|end| label.st_value < end),
        format!(
            "constructor label {name} is not a unique hidden interior label of its actual function"
        ),
    )?;
    Ok(label)
}

const CONSTRUCTOR_GATE_OWNER_BYTES: &[u8] = &[
    0x41, 0x54, 0x4c, 0x8d, 0x25, 0x1c, 0, 0, 0, 0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89,
    0xd6, 0x48, 0x89, 0xca, 0x4d, 0x89, 0xc2, 0x4d, 0x89, 0xc8, 0x4c, 0x8b, 0x4c, 0x24, 0x10, 0x0f,
    0x05, 0x41, 0xff, 0xe4, 0xf3, 0x0f, 0x1e, 0xfa, 0x41, 0x5c, 0xc3,
];
const CONSTRUCTOR_RESULT_HELPER_BYTES: &[u8] = &[
    0x48, 0x89, 0x7c, 0x24, 0xf8, 0x8b, 0x07, 0x48, 0x83, 0xf8, 0, 0x0f, 0x94, 0xc0, 0x34, 0xff,
    0x24, 0x01, 0xc3,
];

fn constructor_gate_operands(code: &[u8], ip_offset: u64, return_offset: u64) -> Result<()> {
    require(
        code == CONSTRUCTOR_GATE_OWNER_BYTES
            && ip_offset == 0x20
            && return_offset == 0x22
            && code.get(0x20..0x25) == Some(&[0x0f, 0x05, 0x41, 0xff, 0xe4]),
        "constructor gate owner/label offset is not the complete existing syscall/JMP R12 gate",
    )
}

// Objdump annotates NOTYPE interior labels with additional headers. Authenticate
// exactly these two annotations and their instruction cursor; retain the raw
// evidence verbatim and feed all instruction bytes to the unchanged strict
// verifier. This is not acceptance of arbitrary nested headers/functions.
fn constructor_gate_disassembly_view(
    text: &str,
    owner: &sym::Sym,
    labels: &BTreeMap<u64, &str>,
) -> Result<String> {
    let end = owner
        .st_value
        .checked_add(owner.st_size)
        .ok_or("gate owner range overflows")?;
    let mut within = false;
    let mut cursor = owner.st_value;
    let mut seen = BTreeSet::new();
    let mut output = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((address, suffix)) = trimmed.split_once(" <").filter(|(_, s)| s.ends_with(">:"))
        {
            let address = u64::from_str_radix(address, 16)
                .map_err(|_| "invalid constructor disassembly header")?;
            if let Some(name) = labels.get(&address) {
                require(
                    within
                        && cursor == address
                        && suffix == format!("{name}>:")
                        && seen.insert(address),
                    "gate interior header is duplicate/misplaced or names the wrong actual label",
                )?;
                continue;
            }
            if within {
                require(cursor == end, "gate owner raw disassembly is truncated")?;
            }
            within = address == owner.st_value;
            if within {
                cursor = address;
            }
        } else if let Some((address, raw)) = trimmed
            .split_once(':')
            .and_then(|(address, raw)| {
                u64::from_str_radix(address.trim(), 16)
                    .ok()
                    .map(|address| (address, raw))
            })
            .filter(|_| within)
        {
            let bytes = raw
                .split_whitespace()
                .map_while(raw_byte)
                .collect::<Vec<_>>();
            require(
                address == cursor && !bytes.is_empty(),
                "gate annotation cursor has a gap or missing bytes",
            )?;
            cursor = cursor
                .checked_add(bytes.len() as u64)
                .ok_or("gate instruction cursor overflow")?;
            require(
                cursor <= end,
                "gate disassembly overruns its complete function",
            )?;
        }
        output.push_str(line);
        output.push('\n');
    }
    if within {
        require(cursor == end, "gate owner raw disassembly is incomplete")?;
    }
    require(
        seen.len() == labels.len(),
        "actual gate interior label header is missing",
    )?;
    Ok(output)
}

// Producer and independent consumer use the same constructor-specific header
// treatment. Generic byte coverage and graph rules remain unchanged.
fn verify_constructor_complete_bytes(
    elf: &Elf<'_>,
    initializer: &str,
    text: &str,
    expected: &BTreeMap<u64, Vec<u8>>,
) -> Result<()> {
    if initializer == STANDALONE_ROOT {
        let owner = private_function(elf, CONSTRUCTOR_GATE_OWNER)?;
        let ip = constructor_interior_label(elf, CONSTRUCTOR_GATE, &owner)?;
        let return_ip = constructor_interior_label(elf, CONSTRUCTOR_GATE_RETURN, &owner)?;
        let view = constructor_gate_disassembly_view(
            text,
            &owner,
            &BTreeMap::from([
                (ip.st_value, CONSTRUCTOR_GATE),
                (return_ip.st_value, CONSTRUCTOR_GATE_RETURN),
            ]),
        )?;
        verify_disassembly_bytes(&view, expected)
    } else {
        verify_disassembly_bytes(text, expected)
    }
}

fn standalone_init_slot(elf: &Elf<'_>, bytes: &[u8], root: &sym::Sym) -> Result<(u64, String)> {
    let (generic_index, generic) = export(elf, GENERIC_INITIALIZER)?;
    let sections: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|s| {
            s.sh_type == section_header::SHT_INIT_ARRAY
                && elf.shdr_strtab.get_at(s.sh_name) == Some(".init_array")
        })
        .collect();
    require(
        sections.len() == 1,
        "standalone requires one .init_array section",
    )?;
    let s = sections[0];
    require(
        s.sh_size > 0 && s.sh_size % 8 == 0 && s.sh_addr % 8 == 0,
        "standalone has invalid .init_array layout",
    )?;
    require(
        elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_LOAD
                && s.sh_addr >= p.p_vaddr
                && s.sh_addr
                    .checked_add(s.sh_size)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_filesz))
                && p.p_offset.checked_add(s.sh_addr - p.p_vaddr) == Some(s.sh_offset)
        }),
        "standalone .init_array is not wholly file-backed at its actual load address",
    )?;
    let start = usize::try_from(s.sh_offset).map_err(|e| e.to_string())?;
    let len = usize::try_from(s.sh_size).map_err(|e| e.to_string())?;
    let entries = bytes
        .get(start..start.checked_add(len).ok_or("init_array overflow")?)
        .ok_or("init_array outside ELF")?;
    let relocations: Vec<_> = elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .collect();
    let mut root_slots = Vec::new();
    let mut generic_slots = Vec::new();
    for (i, entry) in entries.as_chunks::<8>().0.iter().enumerate() {
        let slot = s.sh_addr + i as u64 * 8;
        let raw = u64::from_le_bytes(*entry);
        let records: Vec<_> = relocations.iter().filter(|r| r.r_offset == slot).collect();
        require(
            records.len() <= 1,
            "overlapping standalone init_array relocations",
        )?;
        let mut resolved = None;
        if let Some(r) = records.first() {
            let addend = r.r_addend.unwrap_or(raw as i64);
            if r.r_type == reloc::R_X86_64_RELATIVE && r.r_sym == 0 && addend >= 0 {
                resolved = Some(addend as u64);
            } else if r.r_type == reloc::R_X86_64_64 && addend == 0 {
                if r.r_sym == generic_index {
                    resolved = Some(generic.st_value);
                } else if let Some(symbol) = elf
                    .dynsyms
                    .get(r.r_sym)
                    .filter(|symbol| symbol.st_shndx != section_header::SHN_UNDEF as usize)
                {
                    resolved = Some(symbol.st_value);
                }
            }
        } else {
            require(
                raw != root.st_value && raw != generic.st_value,
                "standalone/generic initializer pointer lacks loader relocation",
            )?;
        }
        if resolved == Some(generic.st_value) {
            generic_slots.push(slot);
        }
        if resolved == Some(root.st_value) {
            let record = records
                .first()
                .ok_or("standalone root lacks loader relocation")?;
            let addend = record.r_addend.unwrap_or(raw as i64);
            require(
                record.r_type == reloc::R_X86_64_RELATIVE
                    && record.r_sym == 0
                    && addend >= 0
                    && addend as u64 == root.st_value,
                "standalone root requires an exact RELATIVE/symbol-zero relocation; a dynamic alias is not its loader identity",
            )?;
            root_slots.push(slot);
        }
    }
    Ok((unique_standalone_slot(&root_slots, &generic_slots)?,
        "Unique loader relocation to exact hidden standalone root; no generic initializer registration".to_owned()))
}

fn init_array_slot(
    elf: &Elf<'_>,
    bytes: &[u8],
    initializer_index: usize,
    initializer: &sym::Sym,
) -> Result<(u64, String)> {
    let sections: Vec<_> = elf
        .section_headers
        .iter()
        .filter(|s| {
            s.sh_type == section_header::SHT_INIT_ARRAY
                && elf.shdr_strtab.get_at(s.sh_name) == Some(".init_array")
        })
        .collect();
    require(
        sections.len() == 1,
        "required unique .init_array section absent",
    )?;
    let section = sections[0];
    require(
        section.sh_size > 0 && section.sh_size % 8 == 0 && section.sh_addr % 8 == 0,
        "invalid x86_64 init_array layout",
    )?;
    let start = usize::try_from(section.sh_offset).map_err(|e| e.to_string())?;
    let len = usize::try_from(section.sh_size).map_err(|e| e.to_string())?;
    let entries = bytes
        .get(
            start
                ..start
                    .checked_add(len)
                    .ok_or("init_array file range overflow")?,
        )
        .ok_or("init_array outside ELF file")?;
    require(
        elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_LOAD
                && section.sh_addr >= p.p_vaddr
                && section
                    .sh_addr
                    .checked_add(section.sh_size)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        }),
        ".init_array is not in a loaded segment",
    )?;
    let relocations: Vec<_> = elf.dynrelas.iter().chain(elf.dynrels.iter()).collect();
    for (i, entry) in entries.as_chunks::<8>().0.iter().enumerate() {
        let slot = section.sh_addr + (i as u64) * 8;
        let raw = u64::from_le_bytes(*entry);
        let at_slot: Vec<_> = relocations.iter().filter(|r| r.r_offset == slot).collect();
        require(at_slot.len() <= 1, "overlapping init_array relocations")?;
        if let Some(r) = at_slot.first() {
            let addend = r.r_addend.unwrap_or(raw as i64);
            if r.r_type == reloc::R_X86_64_RELATIVE
                && r.r_sym == 0
                && addend >= 0
                && addend as u64 == initializer.st_value
            {
                return Ok((
                    slot,
                    "R_X86_64_RELATIVE to exact initializer address".to_owned(),
                ));
            }
            if r.r_type == reloc::R_X86_64_64 && r.r_sym == initializer_index && addend == 0 {
                return Ok((
                    slot,
                    "R_X86_64_64 exact initializer symbol plus zero".to_owned(),
                ));
            }
        } else if raw == initializer.st_value {
            // A nonrelocated relative virtual address in ET_DYN is not a
            // callable pointer after ASLR. It cannot prove a real constructor.
            return Err("initializer address in init_array has no loader relocation".to_owned());
        }
    }
    Err(".init_array does not resolve an aligned slot to the required initializer".to_owned())
}

fn required_versions(text: &str) -> Result<Vec<String>> {
    let mut versions = BTreeSet::new();
    for line in text.lines() {
        let Some((_, rest)) = line.split_once("Name:") else {
            continue;
        };
        require(rest.contains("Flags:"), "malformed readelf version record")?;
        let name = rest
            .split_whitespace()
            .next()
            .ok_or("missing symbol version name")?;
        let components: Vec<_> = name
            .strip_prefix("GLIBC_2.")
            .ok_or_else(|| format!("guest preload requires unsupported version {name}"))?
            .split('.')
            .collect();
        require(
            (1..=2).contains(&components.len())
                && components
                    .iter()
                    .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit())),
            format!("unsupported guest symbol version {name}"),
        )?;
        let minor: u32 = components[0]
            .parse()
            .map_err(|e| format!("glibc version: {e}"))?;
        require(
            minor <= 34,
            format!("guest preload requires {name}, above GLIBC_2.34 floor"),
        )?;
        versions.insert(name.to_owned());
    }
    Ok(versions.into_iter().collect())
}

fn elf_required_versions(elf: &Elf<'_>) -> Result<Vec<String>> {
    let mut names = BTreeSet::new();
    if let Some(verneed) = &elf.verneed {
        for need in verneed.iter() {
            let mut observed = 0usize;
            for auxiliary in need.iter() {
                let name = elf
                    .dynstrtab
                    .get_at(auxiliary.vna_name)
                    .ok_or("ELF version need has invalid string offset")?;
                // Use exactly the same version parser as retained readelf.
                names.extend(required_versions(&format!("Name: {name} Flags: none"))?);
                observed += 1;
            }
            require(
                observed == usize::from(need.vn_cnt),
                "truncated ELF symbol-version requirements",
            )?;
        }
    }
    Ok(names.into_iter().collect())
}

/// Resolve a GOT slot only when the loader's unique relocation computes an
/// exact locally bound function address without lookup in another DSO.
fn local_got_targets(elf: &Elf<'_>) -> Result<BTreeMap<u64, u64>> {
    let local_functions: BTreeSet<_> = elf
        .syms
        .iter()
        .filter(|s| executable_symbol(elf, s) && s.st_bind() == sym::STB_LOCAL)
        .map(|s| s.st_value)
        .collect();
    let mut slots = BTreeMap::<u64, Vec<_>>::new();
    for r in elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
    {
        slots.entry(r.r_offset).or_default().push(r);
    }
    let mut qualified = BTreeMap::new();
    for (slot, records) in slots {
        if records.len() != 1 {
            continue;
        }
        let r = &records[0];
        if r.r_type != reloc::R_X86_64_RELATIVE || r.r_sym != 0 {
            continue;
        }
        let Some(addend) = r.r_addend else {
            continue;
        };
        if addend < 0 || !local_functions.contains(&(addend as u64)) {
            continue;
        }
        // Slot must be loader-mapped and made read-only after relocations;
        // otherwise runtime writes could change the observed pointer route.
        let in_load = elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_LOAD
                && slot >= p.p_vaddr
                && slot
                    .checked_add(8)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        });
        let in_relro = elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_GNU_RELRO
                && slot >= p.p_vaddr
                && slot
                    .checked_add(8)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        });
        if in_load && in_relro {
            qualified.insert(slot, addend as u64);
        }
    }
    Ok(qualified)
}

/// Direct calls/tail calls and RIP-relative indirect calls with independently
/// qualified local RELATIVE GOT slots are admissible. Register-indirect calls
/// and other unsupported paths earn no edge, so required unresolved paths fail.
type CallGraph = BTreeMap<u64, BTreeSet<u64>>;

const MAX_OBJDUMP_BYTES: usize = 64 * 1024 * 1024;

/// The complete node union admitted by the existing required-route and named
/// allocator graphs. Scope is derived from the ELF, not a receipt or a successful
/// path: unchosen alternatives remain part of the required byte evidence.
fn proof_functions(elf: &Elf<'_>, initializer_name: &str) -> Result<BTreeMap<u64, u64>> {
    let mut addresses: BTreeSet<_> = elf
        .syms
        .iter()
        .filter(|s| executable_symbol(elf, s))
        .filter_map(|s| {
            elf.strtab
                .get_at(s.st_name)
                .filter(|name| {
                    allocation_wrapper(name)
                        || qualifies_owned_endpoint(name)
                        || (s.st_bind() == sym::STB_LOCAL
                            && (name.contains("PrivatePatchAllocator")
                                || name.contains("PrivateToolAllocator")))
                })
                .map(|_| s.st_value)
        })
        .collect();
    // Do not let a naming predicate prune a mandatory entry or compiler shim.
    for name in EXPORTS {
        addresses.insert(export(elf, name)?.1.st_value);
    }
    if initializer_name == STANDALONE_ROOT {
        addresses.extend(constructor_proof_functions(elf)?.keys().copied());
    } else {
        addresses.insert(export(elf, initializer_name)?.1.st_value);
    }
    for shim in SHIMS {
        let candidates: Vec<_> = elf
            .syms
            .iter()
            .filter(|s| executable_symbol(elf, s))
            .filter(|s| {
                elf.strtab
                    .get_at(s.st_name)
                    .is_some_and(|name| name == shim || name.ends_with(shim))
            })
            .collect();
        require(
            candidates.len() == 1,
            format!("required unique compiler-selected shim {shim} absent/ambiguous"),
        )?;
        addresses.insert(candidates[0].st_value);
    }
    selected_function_ranges(elf, addresses)
}

/// The standalone constructor scope is independent of diagnostic M1 exports,
/// but retains every private role and the actual public generic initializer.
fn constructor_proof_functions(elf: &Elf<'_>) -> Result<BTreeMap<u64, u64>> {
    selected_function_ranges(
        elf,
        standalone_symbols(elf)?
            .values()
            .map(|s| s.st_value)
            .collect(),
    )
}

fn selected_function_ranges(elf: &Elf<'_>, addresses: BTreeSet<u64>) -> Result<BTreeMap<u64, u64>> {
    let mut functions = BTreeMap::new();
    for address in addresses {
        let sizes: BTreeSet<_> = elf
            .syms
            .iter()
            .chain(elf.dynsyms.iter())
            .filter(|s| {
                s.st_type() == sym::STT_FUNC
                    && s.st_shndx != section_header::SHN_UNDEF as usize
                    && s.st_value == address
            })
            .map(|s| s.st_size)
            .collect();
        require(
            sizes.len() == 1 && !sizes.contains(&0),
            format!("selected function {address:#x} has absent/conflicting alias sizes"),
        )?;
        let size = *sizes.iter().next().unwrap();
        require(
            address.checked_add(size).is_some(),
            format!("selected function {address:#x} overflows its address range"),
        )?;
        functions.insert(address, size);
    }
    Ok(functions)
}

/// Independently read every selected function's complete bytes from its
/// file-backed executable PT_LOAD range. Memory-only tails are not evidence.
fn proof_function_bytes(
    elf: &Elf<'_>,
    bytes: &[u8],
    functions: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<u64, Vec<u8>>> {
    let mut expected = BTreeMap::new();
    let mut total = 0usize;
    for (&address, &size) in functions {
        let end = address.checked_add(size).ok_or("function range overflow")?;
        let mut offsets = BTreeSet::new();
        for p in elf.program_headers.iter().filter(|p| {
            p.p_type == program_header::PT_LOAD && p.p_flags & program_header::PF_X != 0
        }) {
            let file_end = p
                .p_vaddr
                .checked_add(p.p_filesz)
                .ok_or("executable segment range overflow")?;
            if address >= p.p_vaddr && end <= file_end {
                offsets.insert(
                    p.p_offset
                        .checked_add(address - p.p_vaddr)
                        .ok_or("function file offset overflow")?,
                );
            }
        }
        require(
            offsets.len() == 1,
            format!(
                "selected function {address:#x} lacks a unique complete file-backed executable range"
            ),
        )?;
        let offset = usize::try_from(*offsets.iter().next().unwrap())
            .map_err(|_| "function file offset exceeds usize")?;
        let size = usize::try_from(size).map_err(|_| "function size exceeds usize")?;
        let end = offset
            .checked_add(size)
            .ok_or("function file range overflow")?;
        let code = bytes
            .get(offset..end)
            .ok_or("function bytes exceed actual ELF file")?;
        total = total
            .checked_add(size)
            .ok_or("selected function byte total overflow")?;
        require(
            total <= MAX_OBJDUMP_BYTES,
            "selected function bytes exceed disassembly output cap",
        )?;
        expected.insert(address, code.to_vec());
    }
    Ok(expected)
}

fn raw_byte(word: &str) -> Option<u8> {
    (word.len() == 2 && word.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u8::from_str_radix(word, 16).unwrap())
}

/// A header is not completeness evidence. Require each selected interval once,
/// contiguous instruction addresses, and an exact match for every ELF byte.
fn verify_disassembly_bytes(text: &str, expected: &BTreeMap<u64, Vec<u8>>) -> Result<()> {
    require(!expected.is_empty(), "no selected disassembly functions")?;
    let mut consumed = BTreeMap::<u64, usize>::new();
    let mut current = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let header = trimmed
            .split_once(" <")
            .filter(|(_, suffix)| suffix.ends_with(">:"))
            .and_then(|(addr, _)| u64::from_str_radix(addr, 16).ok());
        if let Some(address) = header {
            if let Some(source) = current {
                require(
                    consumed[&source] == expected[&source].len(),
                    format!("selected function {source:#x} disassembly is truncated"),
                )?;
            }
            require(
                expected.contains_key(&address),
                format!("unselected disassembly function {address:#x}"),
            )?;
            require(
                !consumed.contains_key(&address),
                format!("duplicate disassembly function {address:#x}"),
            )?;
            consumed.insert(address, 0);
            current = Some(address);
            continue;
        }
        let Some((address, instruction)) = trimmed.split_once(':') else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(address.trim(), 16) else {
            continue;
        };
        let source = current.ok_or("instruction outside selected function header")?;
        let mut words = instruction.split_whitespace().peekable();
        let mut raw = Vec::new();
        while let Some(byte) = words.peek().and_then(|word| raw_byte(word)) {
            raw.push(byte);
            words.next();
        }
        require(
            !raw.is_empty() && raw.len() <= 15 && words.next().is_some(),
            format!("instruction {address:#x} lacks complete raw x86 bytes/mnemonic"),
        )?;
        let offset = consumed[&source];
        let next = source
            .checked_add(offset as u64)
            .ok_or("instruction address overflow")?;
        require(
            address == next,
            format!("function {source:#x} has a gap/duplicate at {address:#x}, expected {next:#x}"),
        )?;
        let end = offset
            .checked_add(raw.len())
            .ok_or("instruction byte range overflow")?;
        let code = expected[&source]
            .get(offset..end)
            .ok_or_else(|| format!("function {source:#x} disassembly overruns its ELF interval"))?;
        require(
            raw == code,
            format!("instruction {address:#x} raw bytes differ from actual ELF"),
        )?;
        consumed.insert(source, end);
    }
    require(
        consumed.len() == expected.len(),
        "selected function disassembly is missing a range",
    )?;
    for (address, bytes) in expected {
        require(
            consumed.get(address) == Some(&bytes.len()),
            format!("selected function {address:#x} disassembly is incomplete"),
        )?;
    }
    Ok(())
}

// These are finite checks for the reviewed constructor, not another call-graph
// rule. In particular no register-indirect edge is added to disassembly_edges.
struct ConstructorCode<'a> {
    address: u64,
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ConstructorCode<'a> {
    fn ip(&self) -> u64 {
        self.address + self.offset as u64
    }
    fn exact(&mut self, expected: &[u8]) -> Result<u64> {
        let ip = self.ip();
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or("constructor byte overflow")?;
        require(
            self.bytes.get(self.offset..end) == Some(expected),
            format!("unsupported constructor instruction/operand at {ip:#x}"),
        )?;
        self.offset = end;
        Ok(ip)
    }
    fn relative(&mut self, opcode: &[u8]) -> Result<(u64, u64)> {
        let ip = self.exact(opcode)?;
        let end = self
            .offset
            .checked_add(4)
            .ok_or("constructor displacement overflow")?;
        let raw = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated constructor displacement")?;
        let displacement = i32::from_le_bytes(raw.try_into().unwrap());
        self.offset = end;
        let target = self
            .ip()
            .checked_add_signed(i64::from(displacement))
            .ok_or("constructor relative address overflow")?;
        Ok((ip, target))
    }
    fn conditional(&mut self, condition: u8) -> Result<u64> {
        if self.bytes.get(self.offset) == Some(&(0x70 | condition)) {
            self.exact(&[0x70 | condition])?;
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or("truncated constructor branch")?;
            self.offset += 1;
            self.ip()
                .checked_add_signed(i64::from(byte as i8))
                .ok_or_else(|| "constructor branch overflow".to_owned())
        } else {
            self.relative(&[0x0f, 0x80 | condition])
                .map(|(_, target)| target)
        }
    }
    fn jump(&mut self) -> Result<ConstructorTransfer> {
        let ip = self.ip();
        let target = if self.bytes.get(self.offset) == Some(&0xeb) {
            self.exact(&[0xeb])?;
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or("truncated constructor jump")?;
            self.offset += 1;
            self.ip()
                .checked_add_signed(i64::from(byte as i8))
                .ok_or("constructor jump overflow")?
        } else {
            self.relative(&[0xe9])?.1
        };
        Ok(ConstructorTransfer {
            instruction: ip,
            target,
            local_got_slot: None,
        })
    }
    fn transfer(&mut self, call: bool, got: &BTreeMap<u64, u64>) -> Result<ConstructorTransfer> {
        if self.bytes.get(self.offset) == Some(&(if call { 0xe8 } else { 0xe9 })) {
            let (instruction, target) = self.relative(&[if call { 0xe8 } else { 0xe9 }])?;
            Ok(ConstructorTransfer {
                instruction,
                target,
                local_got_slot: None,
            })
        } else {
            let (instruction, slot) = self.relative(&[0xff, if call { 0x15 } else { 0x25 }])?;
            let target = *got
                .get(&slot)
                .ok_or("constructor transfer is not an exact LOCAL RELATIVE GOT route")?;
            Ok(ConstructorTransfer {
                instruction,
                target,
                local_got_slot: Some(slot),
            })
        }
    }
    fn done(&self) -> Result<()> {
        require(
            self.offset == self.bytes.len(),
            "constructor has unchecked trailing instructions",
        )
    }
}

fn loaded_bytes<'a>(
    elf: &Elf<'_>,
    bytes: &'a [u8],
    address: u64,
    length: usize,
) -> Result<&'a [u8]> {
    let end = address
        .checked_add(length as u64)
        .ok_or("constructor data range overflow")?;
    let offsets: BTreeSet<_> = elf
        .program_headers
        .iter()
        .filter_map(|p| {
            (p.p_type == program_header::PT_LOAD
                && p.p_flags & program_header::PF_R != 0
                && address >= p.p_vaddr
                && end <= p.p_vaddr.checked_add(p.p_filesz)?)
            .then(|| p.p_offset.checked_add(address - p.p_vaddr))
            .flatten()
        })
        .collect();
    require(
        offsets.len() == 1,
        "constructor data lacks unique readable file-backed range",
    )?;
    let offset = usize::try_from(*offsets.iter().next().unwrap()).map_err(|e| e.to_string())?;
    bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or("constructor data offset overflow")?,
        )
        .ok_or_else(|| "constructor data outside actual ELF".to_owned())
}

struct PrefixRoute {
    environ: u64,
    selector: u64,
    materialization: u64,
    active: ConstructorTransfer,
    inert: ConstructorTransfer,
}

fn standalone_prefix(
    code: &[u8],
    address: u64,
    body: u64,
    bridge: u64,
    resolver: u64,
) -> Result<PrefixRoute> {
    let mut c = ConstructorCode {
        address,
        bytes: code,
        offset: 0,
    };
    c.exact(&[0xf3, 0x0f, 0x1e, 0xfa])?;
    let (_, environ) = c.relative(&[0x48, 0x8b, 0x05])?;
    c.exact(&[0x48, 0x8b, 0x10, 0x48, 0x85, 0xd2])?;
    let no_vector = c.conditional(4)?;
    let (_, selector) = c.relative(&[0x4c, 0x8d, 0x05])?;
    let vector_loop = c.ip();
    c.exact(&[0x4c, 0x8b, 0x12, 0x4d, 0x85, 0xd2])?;
    let vector_end = c.conditional(4)?;
    c.exact(&[0x45, 0x31, 0xc9])?;
    let byte_loop = c.ip();
    c.exact(&[0x43, 0x8a, 0x04, 0x0a, 0x84, 0xc0])?;
    let short_entry = c.conditional(4)?;
    c.exact(&[0x43, 0x3a, 0x04, 0x08])?;
    let mismatch = c.conditional(5)?;
    c.exact(&[0x41, 0xff, 0xc1, 0x41, 0x83, 0xf9, 22])?;
    require(
        c.conditional(5)? == byte_loop,
        "selector byte loop has wrong destination",
    )?;
    let (materialization, supplied_body) = c.relative(&[0x48, 0x8d, 0x3d])?;
    let active = c.jump()?;
    let next_entry = c.ip();
    c.exact(&[0x48, 0x83, 0xc2, 8])?;
    require(
        c.jump()?.target == vector_loop,
        "selector vector loop has wrong destination",
    )?;
    let inert_entry = c.ip();
    let inert = c.jump()?;
    c.done()?;
    require(
        supplied_body == body && active.target == bridge && inert.target == resolver,
        "standalone prefix does not materialize/transfer to its actual owned body/bridge/resolver",
    )?;
    require(
        no_vector == inert_entry
            && vector_end == inert_entry
            && short_entry == next_entry
            && mismatch == next_entry,
        "standalone missing/short/mismatched selector branch is wrong",
    )?;
    Ok(PrefixRoute {
        environ,
        selector,
        materialization,
        active,
        inert,
    })
}

fn standalone_body_order(
    code: &[u8],
    address: u64,
    helper: u64,
    resolver: u64,
    got: &BTreeMap<u64, u64>,
) -> Result<(ConstructorTransfer, ConstructorTransfer)> {
    let mut c = ConstructorCode {
        address,
        bytes: code,
        offset: 0,
    };
    if c.bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
        c.exact(&[0xf3, 0x0f, 0x1e, 0xfa])?;
    }
    let push = c.bytes.get(c.offset) == Some(&0x50);
    c.exact(if push {
        &[0x50]
    } else {
        &[0x48, 0x83, 0xec, 8]
    })?;
    let initialization = c.transfer(true, got)?;
    let resolution = if c.bytes.get(c.offset) == Some(&0x58)
        || c.bytes.get(c.offset..c.offset + 4) == Some(&[0x48, 0x83, 0xc4, 8])
    {
        c.exact(if push {
            &[0x58]
        } else {
            &[0x48, 0x83, 0xc4, 8]
        })?;
        c.transfer(false, got)?
    } else {
        let resolution = c.transfer(true, got)?;
        c.exact(if push {
            &[0x58]
        } else {
            &[0x48, 0x83, 0xc4, 8]
        })?;
        c.exact(&[0xc3])?;
        resolution
    };
    c.done()?;
    require(
        initialization.target == helper && resolution.target == resolver,
        "active standalone body does not finish its exact initializer before explicit resolution",
    )?;
    Ok((initialization, resolution))
}

// Canonical complete scalar native bridge at RV780. Only the explicitly
// checked same-owner RIP displacements may differ. This matches instructions
// and operands; hashes below remain hashes of the entire unmodified ELF bytes.
// The template includes the original diagnostic/exit route and its limitations.
const CONSTRUCTOR_NATIVE_HEX: &str = concat!(
    "f30f1efa66480f6ec466480f6ecb66480f6ed566490f6edc66490f6ee566490f6eee66490f6ef766480f6eff31c0b201f00fb015f54216040f85bf010000b80900000048bf000000000060000048be000000000100000031d241ba2200100049c7c0ffffffff4531c94c8d2505000000e9bfd1ffff",
    "f30f1efa4885c00f887b01000049bd00000000006000004c39e874274889c748be0000000001000000b80b0000004c8d2505000000e985d1fffff30f1efae94501000048bf0010000000600000be00f00f00ba03000000b80a0000004c8d2505000000e957d1ffff",
    "f30f1efa4885c00f851301000049bd001000000060000041c6450000498d7d28b92000000048c707ffffffff4883c708ffc975f148c7070300000049be301002000060000066480f7ec049890666480f7ec84989460866480f7ed04989461066480f7ed84989461866480f7ee04989462066480f7ee84989462866480f7ef04989463066480f7ef84989463849c746500100000049c7464801000000b8ba0000004c8d2505000000e9aad0ffff",
    "f30f1efa4885c07e6a4989464048bf0010100000600000be00008000ba03000000b80a0000004c8d2505000000e978d0fffff30f1efa4885c0753848bc00109000006000004c89f7e83d05000048b83010020000600000488b5808488b68104c8b60184c8b68204c8b70284c8b7830488b20c3",
    "b801000000bf02000000488d3531000000ba250000004c8d2505000000e915d0fffff30f1efab8e7000000bf7f0000004c8d2505000000e9fbcffffff30f1efa0f0b",
);
const CONSTRUCTOR_RECORD: u64 = 0x6000_0002_1030;
const CONSTRUCTOR_BOTTOM: u64 = 0x6000_0010_1000;
const CONSTRUCTOR_TOP: u64 = 0x6000_0090_1000;

fn native_template() -> Vec<u8> {
    let mut bytes = CONSTRUCTOR_NATIVE_HEX
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    bytes.extend_from_slice(b"reverie constructor bootstrap failed\n");
    bytes
}

fn constructor_native_bridge(
    code: &[u8],
    address: u64,
    initializing: u64,
    gate: u64,
    adopt: u64,
) -> Result<ConstructorTransfer> {
    let template = native_template();
    require(
        code.len() == template.len(),
        "native constructor bridge has unsupported extent",
    )?;
    let fields = [
        (0x34, initializing, 0x38),
        (0x71, gate, 0x75),
        (0xab, gate, 0xaf),
        (0xd9, gate, 0xdd),
        (0x186, gate, 0x18a),
        (0x1b8, gate, 0x1bc),
        (0x1d3, adopt, 0x1d7),
        (0x21b, gate, 0x21f),
        (0x235, gate, 0x239),
    ];
    for (offset, target, end) in fields {
        let displacement = i32::from_le_bytes(code[offset..offset + 4].try_into().unwrap());
        require(
            (address + end).checked_add_signed(i64::from(displacement)) == Some(target),
            format!(
                "native constructor relocation/transfer at {:#x} is not its exact local target",
                address + offset as u64
            ),
        )?;
    }
    for (offset, (&actual, &expected)) in code.iter().zip(&template).enumerate() {
        if !fields
            .iter()
            .any(|(start, _, _)| (*start..*start + 4).contains(&offset))
        {
            require(
                actual == expected,
                format!(
                    "native constructor opcode/operand differs at {:#x}",
                    address + offset as u64
                ),
            )?;
        }
    }
    // In this complete template RDI is saved in XMM7 at +0x27, recovered into
    // RAX and stored to record+0x38 at +0x165. Fresh NOREPLACE/2050 occupied
    // pages/RW guarded interior precede MOV RSP,top (+0x1c5), and only then
    // record->RDI and the actual local adoption CALL (+0x1d2) are executed.
    Ok(ConstructorTransfer {
        instruction: address + 0x1d2,
        target: adopt,
        local_got_slot: None,
    })
}

#[derive(Clone)]
struct EncodedConstructorInstruction {
    address: u64,
    bytes: Vec<u8>,
}

fn constructor_instructions(
    text: &str,
    function: u64,
) -> Result<Vec<EncodedConstructorInstruction>> {
    let mut selected = false;
    let mut instructions = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((address, suffix)) = line
            .split_once(" <")
            .filter(|(_, suffix)| suffix.ends_with(">:"))
        {
            let _ = suffix;
            selected = u64::from_str_radix(address, 16).ok() == Some(function);
            continue;
        }
        if !selected {
            continue;
        }
        let Some((address, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(address.trim(), 16) else {
            continue;
        };
        let bytes = rest
            .split_whitespace()
            .map_while(raw_byte)
            .collect::<Vec<_>>();
        require(
            !bytes.is_empty(),
            "constructor instruction lacks checked raw bytes",
        )?;
        instructions.push(EncodedConstructorInstruction { address, bytes });
    }
    require(
        !instructions.is_empty(),
        "constructor instruction range missing",
    )?;
    Ok(instructions)
}

// An optimized recipe relies only on one callee-saved record register. Decode
// the finite integer instruction families used by this adoption prefix to
// reject a write to that register (including a 32-bit write). Unknown encodings
// fail; this never resolves a generic indirect call or executes arbitrary CFGs.
fn keeps_adoption_register(bytes: &[u8], register: u8) -> bool {
    let mut offset = 0;
    while bytes
        .get(offset)
        .is_some_and(|b| matches!(*b, 0xf0 | 0x66 | 0xf3))
    {
        offset += 1;
    }
    let rex = bytes
        .get(offset)
        .copied()
        .filter(|b| (0x40..=0x4f).contains(b))
        .unwrap_or(0);
    if rex != 0 {
        offset += 1;
    }
    let Some(&op) = bytes.get(offset) else {
        return false;
    };
    if (0x50..=0x57).contains(&op) {
        return register != 4;
    }
    if matches!(
        op,
        0xe8 | 0xe9
            | 0xeb
            | 0x84
            | 0x85
            | 0x38
            | 0x39
            | 0x3a
            | 0x3b
            | 0x90
            | 0xa8
            | 0xa9
            | 0x04
            | 0x0c
            | 0x14
            | 0x1c
            | 0x24
            | 0x2c
            | 0x34
            | 0x3c
    ) || (0x70..=0x7f).contains(&op)
    {
        return true;
    }
    if (0x58..=0x5f).contains(&op) {
        return register != 4 && (op - 0x58 + (rex & 1) * 8) != register;
    }
    let byte_reg = |r: u8| if rex == 0 && r >= 4 { r - 4 } else { r };
    if (0xb0..=0xb7).contains(&op) {
        return byte_reg(op - 0xb0 + (rex & 1) * 8) != register;
    }
    if (0xb8..=0xbf).contains(&op) {
        return op - 0xb8 + (rex & 1) * 8 != register;
    }
    if op == 0x0f {
        return match bytes.get(offset + 1) {
            Some(0x80..=0x8f | 0x1f | 0xa3) => true,
            Some(0xb1) => bytes
                .get(offset + 2)
                .is_some_and(|m| m >> 6 != 3 || (m & 7) + (rex & 1) * 8 != register),
            Some(0x90..=0x9f) => bytes
                .get(offset + 2)
                .is_some_and(|m| m >> 6 != 3 || byte_reg((m & 7) + (rex & 1) * 8) != register),
            Some(0xb6 | 0xb7 | 0xbe | 0xbf) => bytes
                .get(offset + 2)
                .is_some_and(|m| ((m >> 3) & 7) + ((rex >> 2) & 1) * 8 != register),
            _ => false,
        };
    }
    let Some(&m) = bytes.get(offset + 1) else {
        return false;
    };
    let reg = ((m >> 3) & 7) + ((rex >> 2) & 1) * 8;
    let rm = (m & 7) + (rex & 1) * 8;
    match op {
        0x8b | 0x8d => reg != register,
        0x8a => byte_reg(reg) != register,
        0x88 | 0xc0 | 0xd2 | 0xc6 => m >> 6 != 3 || byte_reg(rm) != register,
        0x89 | 0x01 | 0x09 | 0x11 | 0x19 | 0x21 | 0x29 | 0x31 | 0xc1 | 0xd3 | 0xc7 => {
            m >> 6 != 3 || rm != register
        }
        0x03 | 0x0b | 0x13 | 0x1b | 0x23 | 0x2b | 0x33 => reg != register,
        0x80 => (m >> 3) & 7 == 7 || m >> 6 != 3 || byte_reg(rm) != register,
        0x81 | 0x83 => (m >> 3) & 7 == 7 || m >> 6 != 3 || rm != register,
        0xff => {
            matches!((m >> 3) & 7, 2 | 4)
                || ((m >> 3) & 7 == 6 && register != 4)
                || (!matches!((m >> 3) & 7, 2 | 4 | 6) && (m >> 6 != 3 || rm != register))
        }
        _ => false,
    }
}

fn adoption_memory_write(bytes: &[u8]) -> Result<Option<(u8, i32, i32)>> {
    let mut offset = 0;
    let mut word = false;
    while bytes
        .get(offset)
        .is_some_and(|b| matches!(*b, 0xf0 | 0x66 | 0xf3))
    {
        word |= bytes[offset] == 0x66;
        offset += 1;
    }
    let rex = bytes
        .get(offset)
        .copied()
        .filter(|b| (0x40..=0x4f).contains(b))
        .unwrap_or(0);
    if rex != 0 {
        offset += 1;
    }
    let op = *bytes.get(offset).ok_or("empty adoption instruction")?;
    offset += 1;
    let (writes, byte) = if op == 0x0f {
        let second = *bytes.get(offset).ok_or("truncated adoption instruction")?;
        offset += 1;
        (
            second == 0xb1 || (0x90..=0x9f).contains(&second),
            (0x90..=0x9f).contains(&second),
        )
    } else {
        let group = bytes.get(offset).map(|m| (m >> 3) & 7);
        (
            matches!(
                op,
                0x88 | 0x89
                    | 0xc6
                    | 0xc7
                    | 0x01
                    | 0x09
                    | 0x11
                    | 0x19
                    | 0x21
                    | 0x29
                    | 0x31
                    | 0xc0
                    | 0xc1
                    | 0xd2
                    | 0xd3
            ) || (matches!(op, 0x80 | 0x81 | 0x83) && group != Some(7))
                || (op == 0xff && matches!(group, Some(0 | 1))),
            matches!(op, 0x88 | 0xc6 | 0xc0 | 0xd2 | 0x80),
        )
    };
    if !writes {
        return Ok(None);
    }
    let m = *bytes.get(offset).ok_or("truncated adoption write")?;
    offset += 1;
    if m >> 6 == 3 {
        return Ok(None);
    }
    let base = if m & 7 == 4 {
        let sib = *bytes
            .get(offset)
            .ok_or("truncated adoption stack address")?;
        offset += 1;
        require(
            (sib >> 3) & 7 == 4 && rex & 2 == 0,
            "unsupported indexed adoption write",
        )?;
        sib & 7
    } else {
        m & 7
    };
    if m >> 6 == 0 && base == 5 {
        return Ok(None);
    } // RIP-relative, not either owned frame slot.
    let displacement = match m >> 6 {
        0 => 0,
        1 => i32::from(
            *bytes
                .get(offset)
                .ok_or("truncated adoption write displacement")? as i8,
        ),
        2 => i32::from_le_bytes(
            bytes
                .get(offset..offset + 4)
                .ok_or("truncated adoption write displacement")?
                .try_into()
                .unwrap(),
        ),
        _ => unreachable!(),
    };
    let width = if byte {
        1
    } else if word {
        2
    } else if rex & 8 != 0 {
        8
    } else {
        4
    };
    require(
        displacement.checked_add(width).is_some(),
        "adoption write extent overflows",
    )?;
    Ok(Some((base + (rex & 1) * 8, displacement, width)))
}

fn constructor_adoption_helper_edges(
    instructions: &[EncodedConstructorInstruction],
    supplied: usize,
    got: &BTreeMap<u64, u64>,
    helpers: &BTreeSet<u64>,
) -> Result<Vec<GotEdge>> {
    let mut edges = Vec::new();
    // Census the complete function, not only exact CALL RAX instructions or
    // the prefix before the supplied-body call. Prefix parsing here identifies
    // unsupported FF /2..5 transfers; it never admits their prefixed forms.
    // Only the original bare encodings earn the proofs below.
    for (index, call) in instructions.iter().enumerate() {
        let opcode = call
            .bytes
            .iter()
            .take_while(|byte| {
                matches!(
                    **byte,
                    0xf0 | 0xf2
                        | 0xf3
                        | 0x26
                        | 0x2e
                        | 0x36
                        | 0x3e
                        | 0x64
                        | 0x65
                        | 0x66
                        | 0x67
                        | 0x40..=0x4f
                )
            })
            .count();
        if call.bytes.get(opcode) != Some(&0xff) {
            continue;
        }
        let modrm = *call
            .bytes
            .get(opcode + 1)
            .ok_or("truncated adoption FF instruction")?;
        if !matches!((modrm >> 3) & 7, 2..=5) {
            continue;
        }
        if call.bytes.len() == 6 && call.bytes.starts_with(&[0xff, 0x15]) {
            let slot = call
                .address
                .checked_add(6)
                .and_then(|end| {
                    end.checked_add_signed(i64::from(i32::from_le_bytes(
                        call.bytes[2..6].try_into().unwrap(),
                    )))
                })
                .ok_or("adoption RIP-relative call address overflows")?;
            require(
                got.contains_key(&slot),
                "adoption RIP-relative call lacks its independently qualified local RELATIVE GOT target",
            )?;
            continue;
        }
        require(
            call.bytes == [0xff, 0xd0],
            "unsupported adoption indirect call/jump encoding or prefix",
        )?;
        if index == supplied {
            continue;
        }
        require(
            index >= 2
                && index < supplied
                && edges.is_empty()
                && instructions[0].bytes == [0x48, 0x83, 0xec, 0x68]
                && instructions[index - 1].bytes == [0x48, 0x8d, 0x7c, 0x24, 0x38],
            "unrecognized/extra adoption register-indirect helper call",
        )?;
        let load = &instructions[index - 2];
        require(
            load.bytes.len() == 7 && load.bytes.starts_with(&[0x48, 0x8b, 0x05]),
            "adoption helper lacks exact RIP-relative GOT load into RAX",
        )?;
        let slot = load
            .address
            .checked_add(7)
            .and_then(|end| {
                end.checked_add_signed(i64::from(i32::from_le_bytes(
                    load.bytes[3..7].try_into().unwrap(),
                )))
            })
            .ok_or("adoption helper GOT address overflows")?;
        let target = *got
            .get(&slot)
            .ok_or("adoption helper GOT target is unresolved/preemptible")?;
        require(
            helpers.contains(&target),
            "adoption indirect helper is not its exact local Result::is_err role",
        )?;
        edges.push(GotEdge {
            source_function: instructions[0].address,
            instruction: call.address,
            slot,
            target_function: target,
        });
    }
    Ok(edges)
}

fn adoption_body_operand(
    instructions: &[EncodedConstructorInstruction],
    got: &BTreeMap<u64, u64>,
    helpers: &BTreeSet<u64>,
) -> Result<(u64, u64, String, Vec<GotEdge>)> {
    let calls: Vec<_> = instructions
        .iter()
        .enumerate()
        .filter(|(_, i)| i.bytes == [0xff, 0xd0])
        .collect();
    let supplied: Vec<_> = calls
        .iter()
        .copied()
        .filter(|(index, _)| {
            *index > 0
                && (instructions[*index - 1].bytes == [0x48, 0x8b, 0x04, 0x24]
                    || (*index >= 3
                        && instructions[*index - 3].bytes == [0x48, 0x8b, 0x43, 0x38]
                        && instructions[*index - 2].bytes == [0x48, 0x89, 0xe1]
                        && instructions[*index - 1].bytes == [0x48, 0x89, 0x4b, 0x60]))
        })
        .collect();
    require(
        supplied.len() == 1,
        "adoption must have one specifically proved supplied-body CALL RAX",
    )?;
    let (call_index, call) = supplied[0];
    let helper_edges = constructor_adoption_helper_edges(instructions, call_index, got, helpers)?;
    let prefix = &instructions[..call_index];
    if prefix.len() >= 7
        && prefix[prefix.len() - 3].bytes == [0x48, 0x8b, 0x43, 0x38]
        && prefix[prefix.len() - 2].bytes == [0x48, 0x89, 0xe1]
        && prefix[prefix.len() - 1].bytes == [0x48, 0x89, 0x4b, 0x60]
    {
        require(
            prefix[0].bytes == [0x41, 0x56]
                && prefix[1].bytes == [0x53]
                && prefix[2].bytes == [0x48, 0x83, 0xec, 0x28]
                && prefix[3].bytes
                    == [vec![0x48, 0xbb], CONSTRUCTOR_RECORD.to_le_bytes().to_vec()].concat()
                && prefix[4].bytes == [0x49, 0x89, 0xe6]
                && prefix[5].bytes == [0x48, 0x39, 0xdf]
                && prefix[6].bytes.starts_with(&[0x0f, 0x85])
                && prefix[4..].iter().all(|i| {
                    keeps_adoption_register(&i.bytes, 3) && keeps_adoption_register(&i.bytes, 4)
                }),
            "optimized adoption record register is not the checked native record or is overwritten",
        )?;
        for instruction in &prefix[4..] {
            if let Some((3, displacement, width)) = adoption_memory_write(&instruction.bytes)? {
                require(
                    displacement >= 0x40 || displacement + width <= 0x38,
                    "optimized adoption overwrites its supplied-body field",
                )?;
            }
        }
        return Ok((prefix[prefix.len() - 3].address, call.address, "Optimized checked native-record RBX; literal +0x38 load into RAX, sample store +0x60, CALL RAX".to_owned(), helper_edges));
    }
    // Dev code preserves the entry record argument in an owned frame. This is
    // deliberately a separate finite recipe, not acceptance of arbitrary
    // spilled/register-indirect callees. The two eight-byte slots may not be
    // overwritten by another instruction in this adoption function.
    require(
        prefix.len() >= 4
            && prefix[0].bytes == [0x48, 0x83, 0xec, 0x68]
            && prefix[1].bytes == [0x48, 0x89, 0xfe]
            && prefix[2].bytes == [0x48, 0x89, 0x74, 0x24, 0x18]
            && prefix.last().unwrap().bytes == [0x48, 0x8b, 0x04, 0x24],
        "unsupported adoption supplied-body operand recipe",
    )?;
    let loads: Vec<_> = prefix
        .windows(3)
        .filter(|w| {
            w[0].bytes == [0x48, 0x8b, 0x44, 0x24, 0x18]
                && w[1].bytes == [0x48, 0x8b, 0x48, 0x38]
                && w[2].bytes == [0x48, 0x89, 0x0c, 0x24]
        })
        .collect();
    require(
        loads.len() == 1,
        "dev adoption does not load the unique original-record body field",
    )?;
    // Every explicit frame-memory write is inspected, and stack-pointer writes
    // other than the one entry subtraction are rejected. Calls use the scalar
    // ABI; the source-bound from_native/publish/atomic helpers do not receive
    // an address overlapping either retained pointer slot.
    for (index, instruction) in prefix.iter().enumerate().skip(1) {
        let b = &instruction.bytes;
        require(
            keeps_adoption_register(b, 4),
            "dev adoption changes its retained frame base",
        )?;
        if let Some((4, displacement, width)) = adoption_memory_write(b)? {
            if displacement < 0x20 && displacement + width > 0x18 {
                require(
                    index == 2,
                    "dev adoption overwrites its original record-pointer slot",
                )?;
            }
            if displacement < 8 && displacement + width > 0 {
                require(
                    instruction.address == loads[0][2].address,
                    "dev adoption overwrites its supplied-body slot",
                )?;
            }
        }
    }
    Ok((loads[0][1].address, call.address, "Dev owned-frame original RDI slot +0x18; literal record+0x38 load, body slot +0, reload RAX and CALL RAX".to_owned(), helper_edges))
}

fn qualify_standalone_constructor(
    elf: &Elf<'_>,
    bytes: &[u8],
    code: &BTreeMap<u64, Vec<u8>>,
    disassembly: &str,
    got: &BTreeMap<u64, u64>,
) -> Result<StandaloneConstructorEvidence> {
    let symbols = standalone_symbols(elf)?;
    let symbol = |name| symbol_evidence(name, &symbols[name]);
    let address = |name| symbols[name].st_value;
    let prefix = standalone_prefix(
        &code[&address(STANDALONE_ROOT)],
        address(STANDALONE_ROOT),
        address(STANDALONE_BODY),
        address(CONSTRUCTOR_BRIDGE),
        address(STANDALONE_RESOLVER),
    )?;
    let environ: Vec<_> = elf
        .dynrelas
        .iter()
        .chain(elf.dynrels.iter())
        .chain(elf.pltrelocs.iter())
        .filter(|r| r.r_offset == prefix.environ)
        .collect();
    require(
        environ.len() == 1
            && environ[0].r_type == reloc::R_X86_64_GLOB_DAT
            && environ[0].r_addend.unwrap_or(0) == 0
            && elf.dynsyms.get(environ[0].r_sym).is_some_and(|s| {
                elf.dynstrtab.get_at(s.st_name) == Some("environ")
                    && s.st_shndx == section_header::SHN_UNDEF as usize
            }),
        "standalone prefix does not use its actual dynamically relocated environ",
    )?;
    require(
        elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_GNU_RELRO
                && prefix.environ >= p.p_vaddr
                && prefix
                    .environ
                    .checked_add(8)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        }),
        "standalone environ relocation slot is outside RELRO",
    )?;
    loaded_bytes(elf, bytes, prefix.environ, 8)?;
    require(
        loaded_bytes(elf, bytes, prefix.selector, 22)? == b"REVERIE_LITEINST_TOOL=",
        "standalone selector bytes differ",
    )?;
    let (body_initializer_call, body_resolver_transfer) = standalone_body_order(
        &code[&address(STANDALONE_BODY)],
        address(STANDALONE_BODY),
        address(STANDALONE_INITIALIZER),
        address(STANDALONE_RESOLVER),
        got,
    )?;
    let gate_owner = &symbols[CONSTRUCTOR_GATE_OWNER];
    let gate_label = constructor_interior_label(elf, CONSTRUCTOR_GATE, gate_owner)?;
    let gate_return = constructor_interior_label(elf, CONSTRUCTOR_GATE_RETURN, gate_owner)?;
    constructor_gate_operands(
        &code[&gate_owner.st_value],
        gate_label.st_value - gate_owner.st_value,
        gate_return.st_value - gate_owner.st_value,
    )?;
    let result_helpers = constructor_result_helpers(elf)?;
    for helper in result_helpers.values() {
        require(
            code[&helper.st_value] == CONSTRUCTOR_RESULT_HELPER_BYTES,
            "constructor Result::is_err helper has unsupported complete bytes",
        )?;
    }
    let initializing: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| {
            s.st_type() == sym::STT_OBJECT
                && s.st_shndx != section_header::SHN_UNDEF as usize
                && s.st_size == 1
                && s.st_bind() == sym::STB_LOCAL
        })
        .filter(|s| {
            elf.strtab
                .get_at(s.st_name)
                .is_some_and(|name| name.contains("tool_region") && name.ends_with("INITIALIZING"))
        })
        .collect();
    require(
        initializing.len() == 1,
        "native constructor initializing guard is absent/ambiguous",
    )?;
    require(
        elf.program_headers.iter().any(|p| {
            p.p_type == program_header::PT_LOAD
                && p.p_flags & program_header::PF_W != 0
                && initializing[0].st_value >= p.p_vaddr
                && initializing[0]
                    .st_value
                    .checked_add(1)
                    .is_some_and(|end| end <= p.p_vaddr.saturating_add(p.p_memsz))
        }),
        "native constructor initializing guard is not loader-mapped writable data",
    )?;
    let bridge_adoption_call = constructor_native_bridge(
        &code[&address(CONSTRUCTOR_BRIDGE)],
        address(CONSTRUCTOR_BRIDGE),
        initializing[0].st_value,
        gate_label.st_value,
        address(CONSTRUCTOR_ADOPTION),
    )?;
    let adoption_instructions =
        constructor_instructions(disassembly, address(CONSTRUCTOR_ADOPTION))?;
    let (body_pointer_load, adoption_body_call, adoption_recipe, adoption_helper_edges) =
        adoption_body_operand(
            &adoption_instructions,
            got,
            &result_helpers.values().map(|s| s.st_value).collect(),
        )?;
    let function_sha256 = symbols
        .iter()
        .map(|(name, s)| (name.clone(), sha256(&code[&s.st_value])))
        .collect();
    Ok(StandaloneConstructorEvidence {
        generic_initializer: symbol(GENERIC_INITIALIZER), body: symbol(STANDALONE_BODY),
        selected_initializer: symbol(STANDALONE_INITIALIZER), resolver: symbol(STANDALONE_RESOLVER),
        bridge: symbol(CONSTRUCTOR_BRIDGE), adoption: symbol(CONSTRUCTOR_ADOPTION),
        native_gate: symbol_evidence(CONSTRUCTOR_GATE, &gate_label), native_gate_owner: symbol(CONSTRUCTOR_GATE_OWNER),
        native_gate_return: symbol_evidence(CONSTRUCTOR_GATE_RETURN, &gate_return),
        native_gate_offset: gate_label.st_value - gate_owner.st_value, adoption_helper_edges,
        function_sha256, environ_got_slot: prefix.environ, selector_address: prefix.selector,
        active_body_materialization: prefix.materialization, active_bridge_transfer: prefix.active,
        inert_resolver_transfer: prefix.inert, body_initializer_call, body_resolver_transfer, bridge_adoption_call,
        body_pointer_load, adoption_body_call, adoption_recipe, bootstrap_record: CONSTRUCTOR_RECORD,
        bootstrap_bottom: CONSTRUCTOR_BOTTOM, bootstrap_top: CONSTRUCTOR_TOP,
        observation: "Complete actual function bytes; exact native missing/present selector branches, same-owner hidden body/bridge/adoption, supplied-body operand recipe and explicit initializer-then-resolver order. Dynamic environ provider is not authenticated. Scalar ABI and source-bound unchanged adoption helpers remain premises; this is not universal CFG/provider/protected-interior proof, execution, first-entire-DSO-Rust isolation or whole caller-window equality.".to_owned(),
    })
}

fn disassembly_edges(
    text: &str,
    functions: &BTreeMap<u64, u64>,
    got_targets: &BTreeMap<u64, u64>,
) -> Result<(CallGraph, Vec<GotEdge>)> {
    let mut graph = BTreeMap::<u64, BTreeSet<u64>>::new();
    let mut got_edges = Vec::new();
    let mut current = None;
    let mut headers = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        let header = trimmed
            .split_once(" <")
            .filter(|(_, suffix)| suffix.ends_with(">:"))
            .and_then(|(addr, _)| u64::from_str_radix(addr, 16).ok());
        if let Some(addr) = header {
            current = functions.contains_key(&addr).then_some(addr);
            headers += 1;
            continue;
        }
        let Some(source) = current else {
            continue;
        };
        let Some((addr, instruction)) = trimmed.split_once(':') else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(addr.trim(), 16) else {
            continue;
        };
        // Objdump prints linker alignment padding between function ranges under
        // the preceding header. Padding contributes no call-path evidence.
        if address < source || address >= source.saturating_add(functions[&source]) {
            continue;
        }
        let mut words = instruction
            .split_whitespace()
            .skip_while(|word| raw_byte(word).is_some());
        let Some(opcode) = words.next() else {
            continue;
        };
        if !matches!(opcode, "call" | "callq" | "jmp" | "jmpq") {
            continue;
        }
        let Some(destination) = words.next() else {
            continue;
        };
        if destination.starts_with('*') {
            if !destination.ends_with("(%rip)") {
                continue;
            }
            let Some((_, comment)) = instruction.split_once('#') else {
                continue;
            };
            let Some(slot) = comment.split_whitespace().next() else {
                continue;
            };
            let Ok(slot) = u64::from_str_radix(slot, 16) else {
                continue;
            };
            let Some(target) = got_targets.get(&slot) else {
                continue;
            };
            graph.entry(source).or_default().insert(*target);
            got_edges.push(GotEdge {
                source_function: source,
                instruction: address,
                slot,
                target_function: *target,
            });
            continue;
        }
        let Ok(destination) = u64::from_str_radix(destination, 16) else {
            continue;
        };
        if functions.contains_key(&destination) {
            graph.entry(source).or_default().insert(destination);
        }
    }
    require(headers > 0, "objdump yielded no function disassembly")?;
    Ok((graph, got_edges))
}

fn shortest_path(graph: &BTreeMap<u64, BTreeSet<u64>>, from: u64, to: u64) -> Result<Vec<u64>> {
    let mut queue = VecDeque::from([from]);
    let mut predecessors = BTreeMap::from([(from, from)]);
    while let Some(current) = queue.pop_front() {
        if current == to {
            let mut path = vec![to];
            while *path.last().unwrap() != from {
                path.push(predecessors[path.last().unwrap()]);
            }
            path.reverse();
            return Ok(path);
        }
        if let Some(edges) = graph.get(&current) {
            for next in edges {
                if !predecessors.contains_key(next) {
                    predecessors.insert(*next, current);
                    queue.push_back(*next);
                }
            }
        }
    }
    Err(format!(
        "no direct locally resolved compiled call path from {from:#x} to {to:#x}; evidence incomplete"
    ))
}

struct CollectedProofEvidence {
    readelf_versions: FileIdentity,
    readelf_symbols_relocations: FileIdentity,
    objdump_disassembly: FileIdentity,
}

fn collect_proof_evidence(
    artifact: &FileIdentity,
    elf: &Elf<'_>,
    bytes: &[u8],
    initializer_name: &str,
    scope: &BTreeMap<u64, u64>,
    runner: &mut Runner,
) -> Result<CollectedProofEvidence> {
    let cwd = artifact.path.parent().ok_or("artifact has no parent")?;
    let path_string = artifact.path.to_str().ok_or("artifact path is not UTF-8")?;
    runner.text("readelf", &["--version-info", "--wide", path_string], cwd)?;
    let readelf_versions = runner.commands.last().unwrap().stdout.clone();
    let expected_bytes = proof_function_bytes(elf, bytes, scope)?;
    let mut disassembly = Vec::new();
    let mut emitted = 0usize;
    let limit = MAX_OBJDUMP_BYTES.min(runner.max_stream_bytes);
    for (&address, &size) in scope {
        // One aggregate budget covers all stdout/stderr from all intervals.
        // Reserve the separator before spawning; neither a per-range nor a
        // concatenated-output cap can silently grow with the function count.
        let remaining = limit
            .checked_sub(emitted)
            .and_then(|remaining| remaining.checked_sub(1))
            .filter(|remaining| *remaining > 0)
            .ok_or("objdump aggregate byte limit exhausted")?;
        let end = address.checked_add(size).ok_or("function range overflow")?;
        let arguments = vec![
            "--disassemble".to_owned(),
            "--show-raw-insn".to_owned(),
            "--disassemble-zeroes".to_owned(),
            "--insn-width=16".to_owned(),
            "--wide".to_owned(),
            format!("--start-address={address:#x}"),
            format!("--stop-address={end:#x}"),
            path_string.to_owned(),
        ];
        let stdout = runner.run_with_combined_limit("objdump", &arguments, cwd, Some(remaining))?;
        let stderr_bytes = fs::metadata(&runner.commands.last().unwrap().stderr.path)
            .map_err(|e| e.to_string())?
            .len();
        emitted = emitted
            .checked_add(stdout.len())
            .and_then(|n| n.checked_add(usize::try_from(stderr_bytes).ok()?))
            .and_then(|n| n.checked_add(1))
            .ok_or("objdump aggregate byte count overflow")?;
        require(
            emitted <= limit,
            "objdump aggregate output exceeds unchanged byte cap",
        )?;
        disassembly.extend_from_slice(&stdout);
        disassembly.push(b'\n');
    }
    let text = std::str::from_utf8(&disassembly)
        .map_err(|e| format!("objdump output is not UTF-8: {e}"))?;
    verify_constructor_complete_bytes(elf, initializer_name, text, &expected_bytes)?;
    let disassembly_path = runner
        .logs
        .join(format!("objdump-scope-{:04}.stdout", runner.serial));
    write_new(&disassembly_path, &disassembly)?;
    let objdump_disassembly = FileIdentity::read(&disassembly_path)?;
    runner.text(
        "readelf",
        &["--symbols", "--relocs", "--dynamic", "--wide", path_string],
        cwd,
    )?;
    let readelf_symbols_relocations = runner.commands.last().unwrap().stdout.clone();
    artifact.verify()?;
    Ok(CollectedProofEvidence {
        readelf_versions,
        readelf_symbols_relocations,
        objdump_disassembly,
    })
}

pub fn qualify_elf(
    path: &Path,
    initializer_name: &str,
    runner: &mut Runner,
) -> Result<ElfQualification> {
    let artifact = FileIdentity::read(path)?;
    let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("parse actual runtime ELF: {e}"))?;
    let scope = proof_functions(&elf, initializer_name)?;
    let evidence =
        collect_proof_evidence(&artifact, &elf, &bytes, initializer_name, &scope, runner)?;
    qualify_elf_from_evidence(
        path,
        initializer_name,
        evidence.readelf_versions,
        evidence.readelf_symbols_relocations,
        evidence.objdump_disassembly,
    )
}

/// Qualify the exact standalone loader route, never diagnostic allocator work.
/// Uses the same complete-byte/tool/portability/constructor proof as the M1
/// interfaces, with an explicit constructor-only collection and result type.
pub fn qualify_constructor(path: &Path, runner: &mut Runner) -> Result<ConstructorQualification> {
    let artifact = FileIdentity::read(path)?;
    let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("parse actual runtime ELF: {e}"))?;
    let scope = constructor_proof_functions(&elf)?;
    let evidence =
        collect_proof_evidence(&artifact, &elf, &bytes, STANDALONE_ROOT, &scope, runner)?;
    qualify_constructor_from_evidence(
        path,
        evidence.readelf_versions,
        evidence.readelf_symbols_relocations,
        evidence.objdump_disassembly,
    )
}

fn retained_tool_text(
    readelf_versions: &FileIdentity,
    readelf_symbols_relocations: &FileIdentity,
    objdump_disassembly: &FileIdentity,
) -> Result<(String, String)> {
    readelf_versions.verify()?;
    readelf_symbols_relocations.verify()?;
    objdump_disassembly.verify()?;
    let version_text = fs::read_to_string(&readelf_versions.path)
        .map_err(|e| format!("read retained version evidence: {e}"))?;
    require(
        fs::metadata(&objdump_disassembly.path)
            .map_err(|e| e.to_string())?
            .len()
            <= MAX_OBJDUMP_BYTES as u64,
        "retained disassembly exceeds unchanged byte cap",
    )?;
    let disassembly = fs::read_to_string(&objdump_disassembly.path)
        .map_err(|e| format!("read retained disassembly: {e}"))?;
    Ok((version_text, disassembly))
}

fn qualify_portability(elf: &Elf<'_>, version_text: &str) -> Result<Vec<String>> {
    require(
        elf.header.e_type == header::ET_DYN
            && elf.header.e_machine == header::EM_X86_64
            && elf.is_64
            && elf.little_endian,
        "runtime must be little-endian x86_64 ET_DYN",
    )?;
    require(elf.dynamic.is_some(), "runtime lacks a dynamic section")?;
    require(
        elf.rpaths.is_empty() && elf.runpaths.is_empty(),
        "runtime must have no RPATH/RUNPATH",
    )?;
    // Inspect tags as well: even an empty-string RPATH/RUNPATH is forbidden.
    require(
        !elf.dynamic.as_ref().unwrap().dyns.iter().any(|d| {
            matches!(
                d.d_tag,
                goblin::elf::dynamic::DT_RPATH | goblin::elf::dynamic::DT_RUNPATH
            )
        }),
        "runtime records a library search path",
    )?;
    require(
        elf.libraries.iter().all(|n| ALLOWED_NEEDED.contains(n)),
        format!("runtime needs non-glibc library: {:?}", elf.libraries),
    )?;
    let required_versions = required_versions(version_text)?;
    require(
        required_versions == elf_required_versions(elf)?,
        "retained readelf and actual ELF symbol-version requirements differ",
    )?;
    Ok(required_versions)
}

/// Independently requalify the mandatory standalone constructor using actual
/// selected ELF bytes and retained, hashed tool evidence. No Cargo/tools run.
pub fn qualify_constructor_from_evidence(
    path: &Path,
    readelf_versions: FileIdentity,
    readelf_symbols_relocations: FileIdentity,
    objdump_disassembly: FileIdentity,
) -> Result<ConstructorQualification> {
    let (version_text, disassembly) = retained_tool_text(
        &readelf_versions,
        &readelf_symbols_relocations,
        &objdump_disassembly,
    )?;
    let artifact = FileIdentity::read(path)?;
    let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("parse actual runtime ELF: {e}"))?;
    let required_versions = qualify_portability(&elf, &version_text)?;
    let initializer = private_function(&elf, STANDALONE_ROOT)?;
    let (init_array_slot, init_array_resolution) =
        standalone_init_slot(&elf, &bytes, &initializer)?;
    let scope = constructor_proof_functions(&elf)?;
    let expected_bytes = proof_function_bytes(&elf, &bytes, &scope)?;
    verify_constructor_complete_bytes(&elf, STANDALONE_ROOT, &disassembly, &expected_bytes)?;
    let got_targets = local_got_targets(&elf)?;
    let standalone_constructor =
        qualify_standalone_constructor(&elf, &bytes, &expected_bytes, &disassembly, &got_targets)?;
    artifact.verify()?;
    Ok(ConstructorQualification {
        artifact,
        initializer: symbol_evidence(STANDALONE_ROOT, &initializer),
        init_array_slot,
        init_array_resolution,
        standalone_constructor,
        needed: elf.libraries.iter().map(|s| (*s).to_owned()).collect(),
        required_versions,
        readelf_versions,
        readelf_symbols_relocations,
        objdump_disassembly,
    })
}

/// Consumer-side requalification uses the same ELF parser, call-path builder and
/// portability oracle with retained, hashed producer evidence; no tools/builds.
pub fn qualify_elf_from_evidence(
    path: &Path,
    initializer_name: &str,
    readelf_versions: FileIdentity,
    readelf_symbols_relocations: FileIdentity,
    objdump_disassembly: FileIdentity,
) -> Result<ElfQualification> {
    let artifact = FileIdentity::read(path)?;
    let bytes = fs::read(&artifact.path).map_err(|e| e.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("parse actual runtime ELF: {e}"))?;
    let (initializer, init_array_slot, init_array_resolution) =
        if initializer_name == STANDALONE_ROOT {
            let initializer = private_function(&elf, STANDALONE_ROOT)?;
            let (slot, resolution) = standalone_init_slot(&elf, &bytes, &initializer)?;
            (initializer, slot, resolution)
        } else {
            let (index, initializer) = export(&elf, initializer_name)?;
            let (slot, resolution) = init_array_slot(&elf, &bytes, index, &initializer)?;
            (initializer, slot, resolution)
        };
    let exports = EXPORTS
        .iter()
        .map(|name| export(&elf, name).map(|(_, s)| symbol_evidence(name, &s)))
        .collect::<Result<Vec<_>>>()?;
    let mut allocation_shims = BTreeMap::new();
    for shim in SHIMS {
        // rustc's v0 symbol names end in the allocation shim identifier; older
        // compilers emit the unmangled identifier. Require the exact suffix,
        // not a broad `alloc` substring that might name an unrelated helper.
        let candidates: Vec<_> = elf
            .syms
            .iter()
            .filter(|s| executable_symbol(&elf, s))
            .filter_map(|s| {
                elf.strtab
                    .get_at(s.st_name)
                    .filter(|name| *name == shim || name.ends_with(shim))
                    .map(|name| (name, s))
            })
            .collect();
        require(
            candidates.len() == 1,
            format!("required unique compiler-selected shim {shim} absent/ambiguous"),
        )?;
        let (name, s) = candidates[0];
        require(
            s.st_bind() == sym::STB_LOCAL,
            format!("allocation shim {name} is not LOCAL"),
        )?;
        require(
            !elf.dynsyms
                .iter()
                .any(|d| elf.dynstrtab.get_at(d.st_name) == Some(name)),
            format!("allocation shim {name} appears in dynamic symbol table"),
        )?;
        require(
            !elf.dynrelas
                .iter()
                .chain(elf.dynrels.iter())
                .chain(elf.pltrelocs.iter())
                .any(|r| {
                    elf.dynsyms
                        .get(r.r_sym)
                        .is_some_and(|s| elf.dynstrtab.get_at(s.st_name) == Some(name))
                }),
            format!("allocation shim {name} has a dynamic preemption route"),
        )?;
        allocation_shims.insert(shim.to_owned(), symbol_evidence(name, &s));
    }
    let (version_text, disassembly) = retained_tool_text(
        &readelf_versions,
        &readelf_symbols_relocations,
        &objdump_disassembly,
    )?;
    let required_versions = qualify_portability(&elf, &version_text)?;
    let scope = proof_functions(&elf, initializer_name)?;
    let expected_bytes = proof_function_bytes(&elf, &bytes, &scope)?;
    verify_constructor_complete_bytes(&elf, initializer_name, &disassembly, &expected_bytes)?;
    let functions = elf
        .syms
        .iter()
        .filter(|s| executable_symbol(&elf, s))
        .map(|s| (s.st_value, s.st_size))
        .collect();
    let got_targets = local_got_targets(&elf)?;
    let (graph, local_got_edges) = disassembly_edges(&disassembly, &functions, &got_targets)?;
    let standalone_constructor = if initializer_name == STANDALONE_ROOT {
        Some(qualify_standalone_constructor(
            &elf,
            &bytes,
            &expected_bytes,
            &disassembly,
            &got_targets,
        )?)
    } else {
        None
    };
    let mut call_paths = BTreeMap::new();
    let mut inline_routes = BTreeMap::new();
    for (entry, shim) in [
        ("m1_alloc", "__rust_alloc"),
        ("m1_alloc", "__rust_alloc_zeroed"),
        ("m1_realloc", "__rust_realloc"),
        ("m1_dealloc", "__rust_dealloc"),
    ] {
        let key = format!("{entry}->{shim}");
        let entry = exports.iter().find(|s| s.name == entry).unwrap();
        let shim = &allocation_shims[shim];
        match called_shim_path(&elf, &graph, entry.address, shim.address) {
            Ok(path) => {
                call_paths.insert(key, path);
            }
            Err(_) => {
                let route =
                    qualify_inline_route(&key, &elf, entry, shim, &graph, &local_got_edges)?;
                inline_routes.insert(key, route);
            }
        }
    }
    let private_methods: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| executable_symbol(&elf, s) && s.st_bind() == sym::STB_LOCAL)
        .filter_map(|s| {
            elf.strtab
                .get_at(s.st_name)
                .filter(|name| {
                    name.contains("PrivatePatchAllocator") || name.contains("PrivateToolAllocator")
                })
                .map(|name| (name, s.st_value))
        })
        .collect();
    // Named implementation observations must not wander through panic/cleanup
    // paths to another unrelated allocation. They are additional emitted-code
    // evidence, independent of the required export-to-shim routes above.
    let private_nodes: BTreeSet<_> = private_methods
        .iter()
        .map(|(_, address)| *address)
        .chain(allocation_shims.values().map(|s| s.address))
        .collect();
    let private_graph = graph
        .iter()
        .filter(|(source, _)| private_nodes.contains(source))
        .map(|(source, targets)| {
            (
                *source,
                targets
                    .iter()
                    .filter(|target| private_nodes.contains(target))
                    .copied()
                    .collect(),
            )
        })
        .collect();
    let mut named_private_allocator_paths = BTreeMap::new();
    for (shim, symbol) in &allocation_shims {
        for (name, target) in &private_methods {
            if let Ok(path) = shortest_path(&private_graph, symbol.address, *target) {
                named_private_allocator_paths.insert(format!("{shim}->{name}"), path);
            }
        }
    }
    let named_private_allocator_observation = if named_private_allocator_paths.is_empty() {
        "No emitted named private allocator path qualified; methods may be inlined or routes require manual emitted-code review. This observation does not establish private ownership."
    } else {
        "Named private allocator methods are reachable through recorded locally resolved compiled paths. Runtime watcher/ownership assertions and frozen source audit remain required."
    }.to_owned();
    artifact.verify()?;
    Ok(ElfQualification {
        initializer: symbol_evidence(initializer_name, &initializer),
        init_array_slot,
        init_array_resolution,
        standalone_constructor,
        exports,
        allocation_shims,
        needed: elf.libraries.iter().map(|s| (*s).to_owned()).collect(),
        required_versions,
        call_paths,
        inline_routes,
        local_got_edges,
        named_private_allocator_paths,
        named_private_allocator_observation,
        readelf_versions,
        readelf_symbols_relocations,
        objdump_disassembly,
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeReceipt {
    pub schema_version: u32,
    pub source_before: SourceIdentity,
    pub source_after: SourceIdentity,
    pub cargo_artifact: CargoArtifact,
    pub profile_name: String,
    pub artifact: FileIdentity,
    pub qualification: ElfQualification,
    pub rustc_verbose: String,
    pub cargo_version: String,
    pub readelf_version: String,
    pub objdump_version: String,
    pub build_environment: BTreeMap<String, Option<String>>,
    pub target_directory: PathBuf,
    pub commands: Vec<CommandEvidence>,
    /// Artifact qualification is never a runtime M1 passing result.
    pub executed_tests: u64,
    pub full_m1_pass_claimed: bool,
}

pub struct ConsumerExpectation<'a> {
    pub package: &'a PackageIdentity,
    pub features: &'a [String],
    pub profile_name: &'a str,
    pub profile: &'a Value,
    pub initializer: &'a str,
    pub source_head: &'a str,
    pub source_tree: &'a str,
    pub source_lock_sha256: &'a str,
    pub oracle_sha256: &'a BTreeMap<String, String>,
}

/// Requires caller-provided identities independent of this receipt. Does not
/// dlopen, invoke Cargo or silently return on absence. The test must separately
/// validate dladdr owner/base/hash and the genuine configured guest bootstrap.
pub fn verify_runtime_receipt(
    receipt_path: &Path,
    selected_path: &Path,
    expected: &ConsumerExpectation<'_>,
) -> Result<RuntimeReceipt> {
    real_file(receipt_path)?;
    let bytes =
        fs::read(receipt_path).map_err(|e| format!("read required runtime receipt: {e}"))?;
    let receipt: RuntimeReceipt = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse required runtime receipt: {e}"))?;
    require(
        receipt.schema_version == SCHEMA,
        "unsupported runtime receipt schema",
    )?;
    require(
        receipt.source_before == receipt.source_after && receipt.source_before.status.is_empty(),
        "runtime source identity changed or dirty",
    )?;
    let source = &receipt.source_before;
    require(
        source.head == expected.source_head
            && source.tree == expected.source_tree
            && source.lock.sha256 == expected.source_lock_sha256,
        "runtime source HEAD/tree/lock identity differs",
    )?;
    let observed_oracles: BTreeMap<_, _> = source
        .oracles
        .iter()
        .map(|(label, file)| (label.clone(), file.sha256.clone()))
        .collect();
    require(
        &observed_oracles == expected.oracle_sha256,
        "runtime oracle identities differ",
    )?;
    source.lock.verify()?;
    for oracle in source.oracles.values() {
        oracle.verify()?;
    }
    require(
        &receipt.cargo_artifact.package == expected.package,
        "runtime package/manifest/target identity differs",
    )?;
    let mut features = expected.features.to_vec();
    features.sort();
    features.dedup();
    require(
        receipt.cargo_artifact.features == features
            && &receipt.cargo_artifact.profile == expected.profile
            && receipt.profile_name == expected.profile_name,
        "runtime features/profile identity differs",
    )?;
    for command in &receipt.commands {
        require(
            command.status == 0,
            "success receipt contains a failed producer command",
        )?;
        command.stdout.verify()?;
        command.stderr.verify()?;
    }
    let builds: Vec<_> = receipt
        .commands
        .iter()
        .filter(|c| c.program == "cargo" && c.arguments.first().is_some_and(|a| a == "build"))
        .collect();
    require(
        builds.len() == 1,
        "runtime receipt requires one explicit successful Cargo leaf build",
    )?;
    let arguments = &builds[0].arguments;
    for flag in [
        "--locked",
        "--offline",
        "--lib",
        "--message-format=json-render-diagnostics",
    ] {
        require(
            arguments.iter().any(|a| a == flag),
            format!("producer command lacks required {flag}"),
        )?;
    }
    for (option, value) in [
        ("-p", expected.package.name.as_str()),
        ("--features", "allocator-fixture"),
        ("--profile", expected.profile_name),
    ] {
        require(
            arguments
                .windows(2)
                .any(|w| w[0] == option && w[1] == value),
            format!("producer command has wrong/missing {option} {value}"),
        )?;
    }
    require(
        arguments
            .windows(2)
            .any(|w| w[0] == "--target-dir" && Path::new(&w[1]) == receipt.target_directory),
        "producer command target directory differs",
    )?;
    let build_messages = fs::read_to_string(&builds[0].stdout.path).map_err(|e| e.to_string())?;
    let selected_again = select_artifact(
        &build_messages,
        expected.package,
        expected.features,
        expected.profile,
        &receipt.target_directory,
    )?;
    require(
        selected_again == receipt.cargo_artifact,
        "producer current-Cargo artifact selection does not match receipt",
    )?;
    require(
        real_file(selected_path)? == receipt.artifact.path,
        "selected runtime path differs from qualified loaded-artifact path",
    )?;
    receipt.artifact.verify()?;
    require(
        receipt.qualification.initializer.name == expected.initializer
            && receipt.qualification.init_array_slot != 0
            && !receipt.qualification.init_array_resolution.is_empty()
            && receipt.qualification.standalone_constructor.is_some()
                == (expected.initializer == STANDALONE_ROOT),
        "runtime constructor identity is unqualified",
    )?;
    let exports: BTreeSet<_> = receipt
        .qualification
        .exports
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    require(
        exports == BTreeSet::from(EXPORTS),
        "runtime required export identity differs",
    )?;
    require(
        receipt
            .qualification
            .allocation_shims
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(SHIMS),
        "runtime lacks four qualified compiler allocation shims",
    )?;
    require(
        receipt
            .qualification
            .allocation_shims
            .values()
            .all(|s| s.binding == sym::STB_LOCAL),
        "runtime allocation shims are preemptible",
    )?;
    let routes: BTreeSet<_> = receipt
        .qualification
        .call_paths
        .keys()
        .chain(receipt.qualification.inline_routes.keys())
        .map(String::as_str)
        .collect();
    require(
        routes
            == BTreeSet::from([
                "m1_alloc->__rust_alloc",
                "m1_alloc->__rust_alloc_zeroed",
                "m1_realloc->__rust_realloc",
                "m1_dealloc->__rust_dealloc",
            ])
            && receipt.qualification.call_paths.len() + receipt.qualification.inline_routes.len()
                == 4
            && receipt
                .qualification
                .call_paths
                .values()
                .all(|p| p.len() >= 2),
        "runtime compiled allocation paths are incomplete/duplicated",
    )?;
    receipt.qualification.readelf_versions.verify()?;
    receipt.qualification.objdump_disassembly.verify()?;
    let independent = qualify_elf_from_evidence(
        selected_path,
        expected.initializer,
        receipt.qualification.readelf_versions.clone(),
        receipt.qualification.readelf_symbols_relocations.clone(),
        receipt.qualification.objdump_disassembly.clone(),
    )?;
    require(
        independent == receipt.qualification,
        "runtime ELF/evidence requalification differs from producer record",
    )?;
    require(
        receipt.executed_tests == 0 && !receipt.full_m1_pass_claimed,
        "artifact receipt mislabels build evidence as M1 runtime execution",
    )?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_endpoints_require_owned_allocator_allocation_methods() {
        assert!(qualifies_owned_endpoint(
            "_RNvPrivatePatchAllocatorGlobalAlloc5alloc"
        ));
        assert!(qualifies_owned_endpoint(
            "_RNvPrivateToolAllocatorGlobalAlloc12alloc_zeroed"
        ));
        assert!(qualifies_owned_endpoint("_RNvToolHeap8allocate"));
        for name in [
            "_RNvGuestAllocatorGlobalAlloc5alloc",
            "_RNvPatchAllocatorGlobalAlloc5alloc",
            "_RNvPrivatePatchAllocatorGlobalAlloc7dealloc",
            "_RNvToolHeap10deallocate",
            "__rust_alloc",
        ] {
            assert!(!qualifies_owned_endpoint(name), "{name}");
        }
        assert!(allocation_wrapper(
            "_RNvNtCs1ahl_5alloc5alloc5allocCsh_16reverie_liteinst"
        ));
        assert!(!allocation_wrapper("_RNvNtCscore9panicking_alloc"));
    }

    #[test]
    fn refuses_new_or_unrecognized_guest_symbol_versions() {
        for version in [
            "GLIBC_2.35",
            "GLIBC_ABI_DT_RELR",
            "GCC_3.0",
            "GLIBC_2.",
            "GLIBC_2.34.0.1",
        ] {
            assert!(
                required_versions(&format!("Name: {version} Flags: none")).is_err(),
                "{version}"
            );
        }
        assert_eq!(
            required_versions("Name: GLIBC_2.2.5 Flags: none\nName: GLIBC_2.34 Flags: none")
                .unwrap(),
            ["GLIBC_2.2.5", "GLIBC_2.34"]
        );
    }

    #[test]
    fn credits_exact_local_relative_got_route_and_direct_tailcall() {
        let functions = BTreeMap::from([(0x1000, 16), (0x2000, 16), (0x3000, 16)]);
        let got = BTreeMap::from([(0x4000, 0x2000)]);
        let text = "0000000000001000 <m1_alloc>:\n1000: call *0x2ffa(%rip) # 4000 <_DYNAMIC+0x10>\n0000000000002000 <wrapper>:\n2000: jmp 3000 <__rust_alloc>\n0000000000003000 <__rust_alloc>:\n3000: ret\n";
        let (graph, edges) = disassembly_edges(text, &functions, &got).unwrap();
        assert_eq!(
            shortest_path(&graph, 0x1000, 0x3000).unwrap(),
            [0x1000, 0x2000, 0x3000]
        );
        assert_eq!(
            edges,
            [GotEdge {
                source_function: 0x1000,
                instruction: 0x1000,
                slot: 0x4000,
                target_function: 0x2000
            }]
        );
        let raw = "0000000000001000 <m1_alloc>:\n1000: ff 15 fa 2f 00 00 call *0x2ffa(%rip) # 4000 <_DYNAMIC+0x10>\n1006: c3 ret\n0000000000002000 <wrapper>:\n2000: e9 fb 0f 00 00 jmp 3000 <__rust_alloc>\n0000000000003000 <__rust_alloc>:\n3000: c3 ret\n";
        let expected = BTreeMap::from([
            (0x1000, vec![0xff, 0x15, 0xfa, 0x2f, 0x00, 0x00, 0xc3]),
            (0x2000, vec![0xe9, 0xfb, 0x0f, 0x00, 0x00]),
            (0x3000, vec![0xc3]),
        ]);
        verify_disassembly_bytes(raw, &expected).unwrap();
        let (raw_graph, raw_edges) = disassembly_edges(raw, &functions, &got).unwrap();
        assert_eq!(raw_graph, graph);
        assert_eq!(raw_edges, edges);
        for incomplete in [
            raw.split("0000000000003000").next().unwrap().to_owned(),
            raw.replace("1006: c3 ret\n", ""),
            raw.replace("1006: c3", "1007: c3"),
            raw.replace("ff 15 fa 2f", "ff 15 fb 2f"),
            raw.replace("3000: c3 ret", "3000: c3 ret\n3001: c3 ret"),
            format!("{raw}0000000000003000 <__rust_alloc>:\n3000: c3 ret\n"),
            text.to_owned(),
        ] {
            assert!(verify_disassembly_bytes(&incomplete, &expected).is_err());
        }
        standalone_constructor_mutation_controls();
        standalone_registration_mutation_controls();
    }

    // Exercise the affected loader-relocation resolution, not only the pure
    // slot-count/binding predicates. This ELF is parsed from self-contained
    // encoded ELF64 headers, dynamic symbols and a real RELA init-array slot.
    fn standalone_registration_mutation_controls() {
        fn registration(kind: u32, symbol: u32, addend: i64) -> Result<(u64, String)> {
            fn put(bytes: &mut [u8], offset: usize, width: usize, value: u64) {
                bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
            }
            const ROOT: u64 = 0x1100;
            const GENERIC: u64 = 0x1200;
            const SLOT: u64 = 0x1800;
            let mut bytes = vec![0u8; 0x1000];
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            for (offset, width, value) in [
                (16, 2, u64::from(header::ET_DYN)),
                (18, 2, u64::from(header::EM_X86_64)),
                (20, 4, 1),
                (32, 8, 64),
                (40, 8, 0xa00),
                (52, 2, 64),
                (54, 2, 56),
                (56, 2, 2),
                (58, 2, 64),
                (60, 2, 4),
                (62, 2, 3),
            ] {
                put(&mut bytes, offset, width, value);
            }
            for (index, kind, offset, address, size) in [
                (0, program_header::PT_LOAD, 0, 0x1000, 0x1000),
                (1, program_header::PT_DYNAMIC, 0x300, 0x1300, 0x90),
            ] {
                let start = 64 + index * 56;
                for (field, width, value) in [
                    (0, 4, u64::from(kind)),
                    (4, 4, u64::from(program_header::PF_R | program_header::PF_X)),
                    (8, 8, offset),
                    (16, 8, address),
                    (24, 8, address),
                    (32, 8, size),
                    (40, 8, size),
                    (48, 8, 8),
                ] {
                    put(&mut bytes, start + field, width, value);
                }
            }
            let names = format!("\0{GENERIC_INITIALIZER}\0preemptible_root_alias\0");
            bytes[0x500..0x500 + names.len()].copy_from_slice(names.as_bytes());
            for (index, name, value) in [(1, 1, GENERIC), (2, GENERIC_INITIALIZER.len() + 2, ROOT)]
            {
                let start = 0x400 + index * 24;
                put(&mut bytes, start, 4, name as u64);
                bytes[start + 4] = (sym::STB_GLOBAL << 4) | sym::STT_FUNC;
                bytes[start + 5] = sym::STV_DEFAULT;
                put(&mut bytes, start + 6, 2, 1);
                put(&mut bytes, start + 8, 8, value);
                put(&mut bytes, start + 16, 8, 16);
            }
            // One SysV hash bucket and three dynamic symbols, including the
            // defined DEFAULT-visible alias at the hidden root's exact address.
            for (index, value) in [1, 3, 1, 0, 2, 0].into_iter().enumerate() {
                put(&mut bytes, 0x600 + index * 4, 4, value);
            }
            put(&mut bytes, 0x700, 8, SLOT);
            put(
                &mut bytes,
                0x708,
                8,
                (u64::from(symbol) << 32) | u64::from(kind),
            );
            put(&mut bytes, 0x710, 8, addend as u64);
            put(&mut bytes, 0x800, 8, ROOT);
            for (index, (tag, value)) in [
                (5, 0x1500),              // DT_STRTAB
                (10, names.len() as u64), // DT_STRSZ
                (6, 0x1400),              // DT_SYMTAB
                (11, 24),                 // DT_SYMENT
                (4, 0x1600),              // DT_HASH
                (7, 0x1700),              // DT_RELA
                (8, 24),                  // DT_RELASZ
                (9, 24),                  // DT_RELAENT
                (0, 0),                   // DT_NULL
            ]
            .into_iter()
            .enumerate()
            {
                put(&mut bytes, 0x300 + index * 16, 8, tag);
                put(&mut bytes, 0x308 + index * 16, 8, value);
            }
            let section_names = b"\0.text\0.init_array\0.shstrtab\0";
            bytes[0x900..0x900 + section_names.len()].copy_from_slice(section_names);
            for (index, name, kind, flags, address, offset, size, alignment, entry) in [
                (
                    1,
                    1,
                    section_header::SHT_PROGBITS,
                    6,
                    ROOT,
                    0x100,
                    0x200,
                    16,
                    0,
                ),
                (
                    2,
                    7,
                    section_header::SHT_INIT_ARRAY,
                    3,
                    SLOT,
                    0x800,
                    8,
                    8,
                    8,
                ),
                (
                    3,
                    19,
                    section_header::SHT_STRTAB,
                    0,
                    0,
                    0x900,
                    section_names.len() as u64,
                    1,
                    0,
                ),
            ] {
                let start = 0xa00 + index * 64;
                for (field, width, value) in [
                    (0, 4, name),
                    (4, 4, u64::from(kind)),
                    (8, 8, flags),
                    (16, 8, address),
                    (24, 8, offset),
                    (32, 8, size),
                    (48, 8, alignment),
                    (56, 8, entry),
                ] {
                    put(&mut bytes, start + field, width, value);
                }
            }
            let elf = Elf::parse(&bytes).expect("self-contained relocation-control ELF parses");
            let alias = elf.dynsyms.get(2).unwrap();
            assert_eq!(alias.st_bind(), sym::STB_GLOBAL);
            assert_eq!(alias.st_visibility(), sym::STV_DEFAULT);
            assert_eq!(alias.st_value, ROOT);
            assert_eq!(elf.dynrelas.len(), 1);
            let root = sym::Sym {
                st_info: (sym::STB_LOCAL << 4) | sym::STT_FUNC,
                st_other: sym::STV_HIDDEN,
                st_shndx: 1,
                st_value: ROOT,
                st_size: 16,
                ..sym::Sym::default()
            };
            standalone_init_slot(&elf, &bytes, &root)
        }
        assert_eq!(
            registration(reloc::R_X86_64_RELATIVE, 0, 0x1100).unwrap().0,
            0x1800
        );
        assert!(registration(reloc::R_X86_64_RELATIVE, 2, 0x1100).is_err());
        assert!(registration(reloc::R_X86_64_RELATIVE, 0, 0x1108).is_err());
        assert!(
            registration(reloc::R_X86_64_64, 2, 0).is_err(),
            "a loader-preemptible DEFAULT alias must not certify the hidden root by nominal address"
        );
    }

    // Rejection controls share the existing helper test identity; they do not
    // replace any allocation/coverage assertion or claim execution of this
    // synthetic encoding. Actual producer bytes remain a separate prerequisite.
    fn standalone_constructor_mutation_controls() {
        assert!(private_constructor_binding(
            sym::STB_LOCAL,
            sym::STV_DEFAULT
        ));
        assert!(private_constructor_binding(
            sym::STB_GLOBAL,
            sym::STV_HIDDEN
        ));
        assert!(!private_constructor_binding(
            sym::STB_GLOBAL,
            sym::STV_DEFAULT
        ));
        assert!(!private_constructor_binding(
            sym::STB_GLOBAL,
            sym::STV_PROTECTED
        ));
        assert_eq!(unique_standalone_slot(&[0x8000], &[]).unwrap(), 0x8000);
        for (root, generic) in [
            (vec![], vec![]),
            (vec![0x8000, 0x8008], vec![]),
            (vec![0x8000], vec![0x8010]),
        ] {
            assert!(unique_standalone_slot(&root, &generic).is_err());
        }

        fn emit(code: &mut Vec<u8>, opcode: &[u8]) -> usize {
            code.extend_from_slice(opcode);
            let displacement = code.len();
            code.extend_from_slice(&[0; 4]);
            displacement
        }
        fn patch(code: &mut [u8], displacement: usize, target: u64) {
            let delta = i32::try_from(target as i64 - (0x1000 + displacement as i64 + 4)).unwrap();
            code[displacement..displacement + 4].copy_from_slice(&delta.to_le_bytes());
        }
        let mut prefix = vec![0xf3, 0x0f, 0x1e, 0xfa];
        let environ = emit(&mut prefix, &[0x48, 0x8b, 0x05]);
        prefix.extend_from_slice(&[0x48, 0x8b, 0x10, 0x48, 0x85, 0xd2]);
        let no_vector = emit(&mut prefix, &[0x0f, 0x84]);
        let selector = emit(&mut prefix, &[0x4c, 0x8d, 0x05]);
        let vector_loop = 0x1000 + prefix.len() as u64;
        prefix.extend_from_slice(&[0x4c, 0x8b, 0x12, 0x4d, 0x85, 0xd2]);
        let vector_end = emit(&mut prefix, &[0x0f, 0x84]);
        prefix.extend_from_slice(&[0x45, 0x31, 0xc9]);
        let byte_loop = 0x1000 + prefix.len() as u64;
        prefix.extend_from_slice(&[0x43, 0x8a, 0x04, 0x0a, 0x84, 0xc0]);
        let short_entry = emit(&mut prefix, &[0x0f, 0x84]);
        prefix.extend_from_slice(&[0x43, 0x3a, 0x04, 0x08]);
        let mismatch = emit(&mut prefix, &[0x0f, 0x85]);
        prefix.extend_from_slice(&[0x41, 0xff, 0xc1, 0x41, 0x83, 0xf9, 22]);
        let byte_again = emit(&mut prefix, &[0x0f, 0x85]);
        let body = emit(&mut prefix, &[0x48, 0x8d, 0x3d]);
        let bridge = emit(&mut prefix, &[0xe9]);
        let next_entry = 0x1000 + prefix.len() as u64;
        prefix.extend_from_slice(&[0x48, 0x83, 0xc2, 8]);
        let vector_again = emit(&mut prefix, &[0xe9]);
        let inert_entry = 0x1000 + prefix.len() as u64;
        let resolver = emit(&mut prefix, &[0xe9]);
        for (offset, target) in [
            (environ, 0x6000),
            (selector, 0x5000),
            (no_vector, inert_entry),
            (vector_end, inert_entry),
            (short_entry, next_entry),
            (mismatch, next_entry),
            (byte_again, byte_loop),
            (body, 0x2000),
            (bridge, 0x3000),
            (vector_again, vector_loop),
            (resolver, 0x4000),
        ] {
            patch(&mut prefix, offset, target);
        }
        let route = standalone_prefix(&prefix, 0x1000, 0x2000, 0x3000, 0x4000).unwrap();
        assert_eq!(route.environ, 0x6000);
        assert_eq!(route.selector, 0x5000);
        for offset in [no_vector, short_entry, body, bridge, resolver] {
            let mut bad = prefix.clone();
            bad[offset] ^= 1;
            assert!(standalone_prefix(&bad, 0x1000, 0x2000, 0x3000, 0x4000).is_err());
        }

        let mut body_code = vec![0x50];
        let init_call = emit(&mut body_code, &[0xe8]);
        body_code.push(0x58);
        let resolve_tail = emit(&mut body_code, &[0xe9]);
        patch(&mut body_code, init_call, 0x2000);
        patch(&mut body_code, resolve_tail, 0x3000);
        standalone_body_order(&body_code, 0x1000, 0x2000, 0x3000, &BTreeMap::new()).unwrap();
        let mut reversed = body_code.clone();
        patch(&mut reversed, init_call, 0x3000);
        patch(&mut reversed, resolve_tail, 0x2000);
        assert!(
            standalone_body_order(&reversed, 0x1000, 0x2000, 0x3000, &BTreeMap::new()).is_err()
        );

        let mut native = native_template();
        for (offset, target) in [
            (0x34, 0x9000),
            (0x71, 0xa000),
            (0xab, 0xa000),
            (0xd9, 0xa000),
            (0x186, 0xa000),
            (0x1b8, 0xa000),
            (0x1d3, 0xb000),
            (0x21b, 0xa000),
            (0x235, 0xa000),
        ] {
            patch(&mut native, offset, target);
        }
        constructor_native_bridge(&native, 0x1000, 0x9000, 0xa000, 0xb000).unwrap();
        for offset in [0x34, 0x71, 0x168, 0x1c8, 0x1d3] {
            let mut bad = native.clone();
            bad[offset] ^= 1;
            assert!(constructor_native_bridge(&bad, 0x1000, 0x9000, 0xa000, 0xb000).is_err());
        }
        for clobber in [&[0x31, 0xdb][..], &[0xb7, 0][..], &[0x48, 0x89, 0xc3][..]] {
            assert!(!keeps_adoption_register(clobber, 3));
        }
        assert!(!keeps_adoption_register(&[0x48, 0x83, 0xc4, 8], 4));

        let mut optimized = vec![
            vec![0x41, 0x56],
            vec![0x53],
            vec![0x48, 0x83, 0xec, 0x28],
            [vec![0x48, 0xbb], CONSTRUCTOR_RECORD.to_le_bytes().to_vec()].concat(),
            vec![0x49, 0x89, 0xe6],
            vec![0x48, 0x39, 0xdf],
            vec![0x0f, 0x85, 0, 0, 0, 0],
            vec![0x48, 0x8b, 0x43, 0x38],
            vec![0x48, 0x89, 0xe1],
            vec![0x48, 0x89, 0x4b, 0x60],
            vec![0xff, 0xd0],
        ];
        fn encoded(code: &[Vec<u8>]) -> Vec<EncodedConstructorInstruction> {
            let mut address = 0x1000;
            code.iter()
                .map(|bytes| {
                    let instruction = EncodedConstructorInstruction {
                        address,
                        bytes: bytes.clone(),
                    };
                    address += bytes.len() as u64;
                    instruction
                })
                .collect()
        }
        adoption_body_operand(&encoded(&optimized), &BTreeMap::new(), &BTreeSet::new()).unwrap();
        optimized[7][3] = 0x30;
        assert!(
            adoption_body_operand(&encoded(&optimized), &BTreeMap::new(), &BTreeSet::new())
                .is_err()
        );
        optimized[7][3] = 0x38;
        optimized.insert(7, vec![0x48, 0xc7, 0x43, 0x38, 0, 0, 0, 0]);
        assert!(
            adoption_body_operand(&encoded(&optimized), &BTreeMap::new(), &BTreeSet::new())
                .is_err()
        );

        let mut dev = vec![
            vec![0x48, 0x83, 0xec, 0x68],
            vec![0x48, 0x89, 0xfe],
            vec![0x48, 0x89, 0x74, 0x24, 0x18],
            vec![0x48, 0x8b, 0x44, 0x24, 0x18],
            vec![0x48, 0x8b, 0x48, 0x38],
            vec![0x48, 0x89, 0x0c, 0x24],
            vec![0x48, 0x8b, 0x04, 0x24],
            vec![0xff, 0xd0],
        ];
        adoption_body_operand(&encoded(&dev), &BTreeMap::new(), &BTreeSet::new()).unwrap();
        dev.insert(6, vec![0xc6, 0x04, 0x24, 0]);
        assert!(adoption_body_operand(&encoded(&dev), &BTreeMap::new(), &BTreeSet::new()).is_err());
        dev.remove(6);
        dev.insert(3, vec![0x48, 0xc7, 0x44, 0x24, 0x18, 0, 0, 0, 0]);
        assert!(adoption_body_operand(&encoded(&dev), &BTreeMap::new(), &BTreeSet::new()).is_err());
        constructor_gate_operands(CONSTRUCTOR_GATE_OWNER_BYTES, 0x20, 0x22).unwrap();
        for (ip, ret) in [(0x21, 0x22), (0x20, 0x23)] {
            assert!(constructor_gate_operands(CONSTRUCTOR_GATE_OWNER_BYTES, ip, ret).is_err());
        }
        let mut bad_gate = CONSTRUCTOR_GATE_OWNER_BYTES.to_vec();
        bad_gate[0x24] ^= 1;
        assert!(constructor_gate_operands(&bad_gate, 0x20, 0x22).is_err());
        let mut helper_case = vec![
            vec![0x48, 0x83, 0xec, 0x68],
            vec![0x48, 0x89, 0xfe],
            vec![0x48, 0x89, 0x74, 0x24, 0x18],
            vec![0x48, 0x8b, 0x05, 0, 0, 0, 0],
            vec![0x48, 0x8d, 0x7c, 0x24, 0x38],
            vec![0xff, 0xd0],
            vec![0x48, 0x8b, 0x44, 0x24, 0x18],
            vec![0x48, 0x8b, 0x48, 0x38],
            vec![0x48, 0x89, 0x0c, 0x24],
            vec![0x48, 0x8b, 0x04, 0x24],
            vec![0xff, 0xd0],
        ];
        let helper_encoding = encoded(&helper_case);
        let slot = helper_encoding[3].address + 7;
        let got = BTreeMap::from([(slot, 0x7000)]);
        let helpers = BTreeSet::from([0x7000]);
        let (_, _, _, edges) = adoption_body_operand(&helper_encoding, &got, &helpers).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target_function, 0x7000);
        assert!(
            adoption_body_operand(
                &helper_encoding,
                &BTreeMap::from([(slot, 0x7001)]),
                &helpers
            )
            .is_err()
        );
        assert!(adoption_body_operand(&helper_encoding, &BTreeMap::new(), &helpers).is_err());
        helper_case.insert(6, vec![0xff, 0xd0]);
        assert!(adoption_body_operand(&encoded(&helper_case), &got, &helpers).is_err());
        helper_case.remove(6);
        helper_case[4][4] = 0x30;
        assert!(adoption_body_operand(&encoded(&helper_case), &got, &helpers).is_err());

        let mut raw_gate = format!("0000000000001000 <{CONSTRUCTOR_GATE_OWNER}>:\n");
        let mut offset = 0usize;
        for length in [2usize, 7, 3, 3, 3, 3, 3, 3, 5, 2, 3, 4, 2, 1] {
            if offset == 0x20 {
                raw_gate.push_str(&format!("0000000000001020 <{CONSTRUCTOR_GATE}>:\n"));
            }
            if offset == 0x22 {
                raw_gate.push_str(&format!("0000000000001022 <{CONSTRUCTOR_GATE_RETURN}>:\n"));
            }
            raw_gate.push_str(&format!(
                "{:x}: {} mnemonic\n",
                0x1000 + offset,
                CONSTRUCTOR_GATE_OWNER_BYTES[offset..offset + length]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            offset += length;
        }
        assert_eq!(offset, 44);
        let owner = sym::Sym {
            st_value: 0x1000,
            st_size: 44,
            ..sym::Sym::default()
        };
        let labels = BTreeMap::from([
            (0x1020, CONSTRUCTOR_GATE),
            (0x1022, CONSTRUCTOR_GATE_RETURN),
        ]);
        let view = constructor_gate_disassembly_view(&raw_gate, &owner, &labels).unwrap();
        verify_disassembly_bytes(
            &view,
            &BTreeMap::from([(0x1000, CONSTRUCTOR_GATE_OWNER_BYTES.to_vec())]),
        )
        .unwrap();
        for bad in [
            raw_gate.replace(CONSTRUCTOR_GATE_RETURN,"wrong_gate_label"),
            raw_gate.replace("0000000000001022 <","0000000000001023 <"),
            raw_gate.replace(&format!("0000000000001022 <{CONSTRUCTOR_GATE_RETURN}>:\n"),""),
            raw_gate.replace(&format!("0000000000001022 <{CONSTRUCTOR_GATE_RETURN}>:\n"),
                &format!("0000000000001022 <{CONSTRUCTOR_GATE_RETURN}>:\n0000000000001022 <{CONSTRUCTOR_GATE_RETURN}>:\n")),
        ] {
            assert!(constructor_gate_disassembly_view(&bad,&owner,&labels).is_err());
        }
    }

    fn standalone_adoption_indirect_mutation_controls() {
        fn encoded(code: &[Vec<u8>]) -> Vec<EncodedConstructorInstruction> {
            let mut address = 0x1000;
            code.iter()
                .map(|bytes| {
                    let instruction = EncodedConstructorInstruction {
                        address,
                        bytes: bytes.clone(),
                    };
                    address += bytes.len() as u64;
                    instruction
                })
                .collect()
        }
        let helper_case = vec![
            vec![0x48, 0x83, 0xec, 0x68],
            vec![0x48, 0x89, 0xfe],
            vec![0x48, 0x89, 0x74, 0x24, 0x18],
            vec![0x48, 0x8b, 0x05, 0, 0, 0, 0],
            vec![0x48, 0x8d, 0x7c, 0x24, 0x38],
            vec![0xff, 0xd0],
            vec![0x48, 0x8b, 0x44, 0x24, 0x18],
            vec![0x48, 0x8b, 0x48, 0x38],
            vec![0x48, 0x89, 0x0c, 0x24],
            vec![0x48, 0x8b, 0x04, 0x24],
            vec![0xff, 0xd0],
        ];
        let helper_encoding = encoded(&helper_case);
        let slot = helper_encoding[3].address + 7;
        let got = BTreeMap::from([(slot, 0x7000)]);
        let helpers = BTreeSet::from([0x7000]);
        let (_, _, _, edges) = adoption_body_operand(&helper_encoding, &got, &helpers).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target_function, 0x7000);
        // Keep the later proved supplied-body CALL RAX present in every case.
        // Target certification cannot be obtained by simply omitting another
        // indirect transfer from the helper enumerator.
        let unsupported: &[(&str, &[u8])] = &[
            ("CALL RCX", &[0xff, 0xd1]),
            ("CALL RDX", &[0xff, 0xd2]),
            ("REX CALL R8", &[0x41, 0xff, 0xd0]),
            ("REX.W CALL RAX", &[0x48, 0xff, 0xd0]),
            ("operand-prefix CALL RAX", &[0x66, 0xff, 0xd0]),
            ("REP-prefix CALL RCX", &[0xf3, 0xff, 0xd1]),
            ("BND-prefix CALL RCX", &[0xf2, 0xff, 0xd1]),
            ("NOTRACK CALL RCX", &[0x3e, 0xff, 0xd1]),
            ("CALL [RAX]", &[0xff, 0x10]),
            ("CALL [RCX]", &[0xff, 0x11]),
            ("CALL [RSP]", &[0xff, 0x14, 0x24]),
            ("CALL [RSP+8]", &[0xff, 0x54, 0x24, 8]),
            ("REX CALL [R8]", &[0x41, 0xff, 0x10]),
            ("JMP RAX", &[0xff, 0xe0]),
            ("JMP RCX", &[0xff, 0xe1]),
            ("REX JMP R8", &[0x41, 0xff, 0xe0]),
            ("JMP [RAX]", &[0xff, 0x20]),
            ("JMP [RSP]", &[0xff, 0x24, 0x24]),
            ("JMP [RSP+8]", &[0xff, 0x64, 0x24, 8]),
            ("far CALL [RAX]", &[0xff, 0x18]),
            ("far JMP [RAX]", &[0xff, 0x28]),
            ("address-prefix CALL", &[0x67, 0xff, 0x15, 0, 0, 0, 0]),
        ];
        let mut accepted = Vec::new();
        for &(name, replacement) in unsupported {
            let mut mutated = helper_case.clone();
            mutated[5] = replacement.to_vec();
            if adoption_body_operand(&encoded(&mutated), &got, &helpers).is_ok() {
                accepted.push(name);
            }
        }
        // The enumeration must cover the full function, including instructions
        // after the supplied-body call, rather than only the prefix.
        for (name, extra) in [
            ("late CALL RCX", vec![0xff, 0xd1]),
            ("late REX CALL R8", vec![0x41, 0xff, 0xd0]),
            ("late JMP [RAX]", vec![0xff, 0x20]),
        ] {
            let mut mutated = helper_case.clone();
            mutated.push(extra);
            if adoption_body_operand(&encoded(&mutated), &got, &helpers).is_ok() {
                accepted.push(name);
            }
        }
        // The only separately admitted memory-call encoding is the original
        // bare CALL [RIP+disp32], with its independently qualified local GOT.
        let mut rip_case = helper_case.clone();
        rip_case.insert(6, vec![0xff, 0x15, 0, 0, 0, 0]);
        let rip_encoding = encoded(&rip_case);
        let rip_slot = rip_encoding[6].address + 6;
        let mut local_got = got.clone();
        local_got.insert(rip_slot, 0x7100);
        adoption_body_operand(&rip_encoding, &local_got, &helpers).unwrap();
        if adoption_body_operand(&rip_encoding, &got, &helpers).is_ok() {
            accepted.push("unresolved RIP CALL");
        }
        for (name, replacement) in [
            ("RIP JMP", vec![0xff, 0x25, 0, 0, 0, 0]),
            ("prefixed RIP CALL", vec![0x3e, 0xff, 0x15, 0, 0, 0, 0]),
        ] {
            let mut mutated = rip_case.clone();
            mutated[6] = replacement;
            let encoded = encoded(&mutated);
            let mut local_got = got.clone();
            local_got.insert(encoded[6].address + encoded[6].bytes.len() as u64, 0x7100);
            if adoption_body_operand(&encoded, &local_got, &helpers).is_ok() {
                accepted.push(name);
            }
        }
        assert!(
            accepted.is_empty(),
            "unproved adoption transfers qualified: {accepted:?}"
        );
    }

    #[test]
    fn unresolved_or_preemptible_indirect_calls_do_not_earn_a_path() {
        let functions = BTreeMap::from([(0x1000, 16), (0x2000, 16)]);
        for instruction in ["call *%rax", "call *0x2ffa(%rip) # 4000 <malloc@GOT>"] {
            let text = format!(
                "0000000000001000 <m1_alloc>:\n1000: {instruction}\n0000000000002000 <__rust_alloc>:\n2000: ret\n"
            );
            let (graph, edges) = disassembly_edges(&text, &functions, &BTreeMap::new()).unwrap();
            assert!(edges.is_empty());
            assert!(shortest_path(&graph, 0x1000, 0x2000).is_err());
        }
        standalone_adoption_indirect_mutation_controls();
    }

    #[test]
    fn missing_build_finished_is_a_failed_current_artifact_selection() {
        let package = PackageIdentity {
            id: "exact-id".to_owned(),
            name: "reverie-liteinst-preload".to_owned(),
            manifest: "/source/leaf/Cargo.toml".into(),
            source: None,
            target: "reverie_liteinst_preload".to_owned(),
            kind: vec!["cdylib".to_owned()],
            crate_types: vec!["cdylib".to_owned()],
            target_source: "/source/leaf/src/lib.rs".into(),
        };
        assert!(
            select_artifact(
                "",
                &package,
                &["allocator-fixture".to_owned()],
                &Value::Null,
                Path::new("/separate-target")
            )
            .unwrap_err()
            .contains("build-finished")
        );
        assert!(
            select_artifact(
                "{\"reason\":\"build-finished\",\"success\":false}",
                &package,
                &[],
                &Value::Null,
                Path::new("/separate-target")
            )
            .is_err()
        );
    }
}
