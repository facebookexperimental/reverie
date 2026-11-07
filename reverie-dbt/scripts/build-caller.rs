#!/usr/bin/env -S rust-script --force
//! Build and stage one explicitly paired external caller using the existing target.
//!
//! ```cargo
//! [package]
//! edition = "2024"
//!
//! [dependencies]
//! libc = "=0.2.190"
//! serde_json = "=1.0.154"
//! sha2 = "=0.10.9"
//! ```

#[path = "lib/rust_script_prelude.rs"]
mod rust_script_prelude;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use serde_json::Value;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;

// Reuse the maintained recipe and install attestation exactly. This module's
// main/build functions are never called: a missing or stale SDK is a refusal.
#[allow(dead_code)]
mod sdk {
    include!("../build.rs");

    pub fn cached(workspace: &Path, target: &Path, profile: &str) -> io::Result<(PathBuf, String)> {
        let crate_dir = workspace.join("reverie-dbt");
        let cmake = env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
        let generator = env::var_os("CMAKE_GENERATOR");
        let epoch = dynamorio_source_date_epoch(env::var_os("SOURCE_DATE_EPOCH"));
        let key = source_recipe_key(
            &crate_dir.join("vendor/dynamorio"),
            &crate_dir.join("build.rs"),
            &cmake,
            generator.as_deref(),
            &epoch,
        );
        let install = target
            .join(profile)
            .join("reverie-dbt-native-cache")
            .join(format!("dynamorio-install-{key}"));
        if !install_is_usable(&install, &key) {
            return Err(io::Error::other(format!(
                "caller production requires the already validated SDK cache {}; no cold SDK build is permitted",
                install.display()
            )));
        }
        Ok((install, key))
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct Options {
    workspace: PathBuf,
    caller: PathBuf,
    output: Option<PathBuf>,
    profile: String,
    target: PathBuf,
    jobs: usize,
    check: bool,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn options() -> Result<Option<Options>> {
    let mut values = BTreeMap::new();
    let mut check = false;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(name) = arguments.next() {
        if name == "--help" {
            println!(
                "Usage: build-client.sh --caller-manifest PATH [--artifact-output DIR] [--profile debug|release|validate] [--jobs 1..8] [--check]\n\nRequires an existing CARGO_TARGET_DIR (default: workspace/target), a matching validated SDK cache, and cached Cargo dependencies. --check also runs the standalone check, format, Clippy and rustdoc gates with the actual generated identity. Images are immutable; the default manifest advances atomically. An explicit output must not already contain a manifest."
            );
            return Ok(None);
        }
        if name == "--check" {
            check = true;
            continue;
        }
        if ![
            "--workspace",
            "--caller-manifest",
            "--artifact-output",
            "--profile",
            "--jobs",
        ]
        .iter()
        .any(|allowed| name == *allowed)
        {
            return Err(invalid(format!("unknown caller producer option {name:?}")).into());
        }
        let value = arguments
            .next()
            .ok_or_else(|| invalid(format!("missing value for {name:?}")))?;
        if values.insert(name.clone(), value).is_some() {
            return Err(invalid(format!("duplicate option {name:?}")).into());
        }
    }
    let mut take = |name: &str| values.remove(OsStr::new(name));
    let workspace = fs::canonicalize(
        take("--workspace")
            .ok_or_else(|| invalid("use build-client.sh to provide the workspace"))?,
    )?;
    let caller = PathBuf::from(
        take("--caller-manifest").ok_or_else(|| invalid("--caller-manifest is required"))?,
    );
    let caller = canonical_source(&if caller.is_absolute() {
        caller
    } else {
        std::env::current_dir()?.join(caller)
    })?;
    let output = take("--artifact-output").map(PathBuf::from);
    let profile = take("--profile")
        .or_else(|| std::env::var_os("PROFILE"))
        .unwrap_or_else(|| "debug".into())
        .into_string()
        .map_err(|_| invalid("profile is not UTF-8"))?;
    if !matches!(profile.as_str(), "debug" | "release" | "validate") {
        return Err(invalid("profile must be debug, release or validate").into());
    }
    let jobs = take("--jobs")
        .or_else(|| std::env::var_os("CARGO_BUILD_JOBS"))
        .unwrap_or_else(|| "8".into())
        .into_string()
        .map_err(|_| invalid("jobs is not UTF-8"))?
        .parse::<usize>()?;
    if !(1..=8).contains(&jobs) {
        return Err(invalid("caller producer requires 1 through 8 jobs").into());
    }
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace.join("target"));
    // A new physical target or a target-triple layout is never a fallback.
    let target = fs::canonicalize(target)?;
    if !target.is_dir() || std::env::var_os("CARGO_BUILD_TARGET").is_some() {
        return Err(
            invalid("use the existing host target directory without CARGO_BUILD_TARGET").into(),
        );
    }
    Ok(Some(Options {
        workspace,
        caller,
        output,
        profile,
        target,
        jobs,
        check,
    }))
}

struct Producer {
    options: Options,
    deadline: Instant,
}

impl Producer {
    fn command(&self, program: impl AsRef<OsStr>) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(&self.options.workspace)
            .env("CARGO_TARGET_DIR", &self.options.target)
            .env("CARGO_BUILD_JOBS", self.options.jobs.to_string())
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_NET_OFFLINE", "true");
        command
    }

    // GNU timeout contains each process group under the remaining whole-producer
    // deadline. Resource admission/cgroup ownership belongs to the invoking lane.
    fn run(&self, command: Command) -> Result<Vec<u8>> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| invalid("caller producer exceeded its 900-second deadline"))?;
        let seconds = remaining.as_secs().max(1).to_string();
        let mut bounded = Command::new("timeout");
        bounded
            .args(["--kill-after=2s", &seconds])
            .arg(command.get_program())
            .args(command.get_args());
        if let Some(directory) = command.get_current_dir() {
            bounded.current_dir(directory);
        }
        for (key, value) in command.get_envs() {
            match value {
                Some(value) => {
                    bounded.env(key, value);
                }
                None => {
                    bounded.env_remove(key);
                }
            }
        }
        let output = bounded
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()?;
        if !output.status.success() {
            // Cargo JSON diagnostics live on stdout. Retain their human-readable
            // rendering, as well as ordinary CMake/check output, on refusal.
            for line in output.stdout.split(|byte| *byte == b'\n') {
                match serde_json::from_slice::<Value>(line) {
                    Ok(value) => {
                        if let Some(rendered) =
                            value.pointer("/message/rendered").and_then(Value::as_str)
                        {
                            eprint!("{rendered}");
                        }
                    }
                    Err(_) => eprintln!("{}", String::from_utf8_lossy(line)),
                }
            }
            return Err(io::Error::other(format!(
                "caller producer command {:?} failed with {}",
                command.get_program(),
                output.status
            ))
            .into());
        }
        if output.stdout.len() > 64 * 1024 * 1024 {
            return Err(invalid("caller producer command output exceeded 64 MiB").into());
        }
        Ok(output.stdout)
    }

    fn cargo(&self, action: &str, identity: Option<&str>) -> Command {
        let mut command = self.command("cargo");
        command
            .args([action, "--offline", "--locked", "--manifest-path"])
            .arg(&self.options.caller);
        if action != "metadata" {
            command
                .args([
                    "--profile",
                    if self.options.profile == "debug" {
                        "dev"
                    } else {
                        &self.options.profile
                    },
                ])
                .args(["--jobs", &self.options.jobs.to_string()]);
        }
        if let Some(identity) = identity {
            command.env("REVERIE_DBT_CALLER_INPUT_IDENTITY", identity);
        }
        command
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing string {key}")).into())
}

fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(format!("missing array {key}")).into())
}

struct Graph {
    root_id: String,
    label: String,
    local_roots: BTreeSet<PathBuf>,
}

fn graph(metadata: &Value, caller: &Path, workspace: &Path) -> Result<Graph> {
    let packages = array(metadata, "packages")?
        .iter()
        .map(|package| Ok((string(package, "id")?, package)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let resolve = metadata
        .get("resolve")
        .ok_or_else(|| invalid("metadata has no resolved graph"))?;
    let nodes = array(resolve, "nodes")?
        .iter()
        .map(|node| Ok((string(node, "id")?, node)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let root_id = string(resolve, "root")?;
    let package = packages
        .get(root_id)
        .ok_or_else(|| invalid("resolved root package is missing"))?;
    if canonical_source(Path::new(string(package, "manifest_path")?))? != caller {
        return Err(invalid("metadata root is not the supplied standalone caller manifest").into());
    }
    let label = package
        .pointer("/metadata/reverie-dbt/artifact-label")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("caller requires package.metadata.reverie-dbt.artifact-label"))?;
    if label.is_empty()
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return Err(invalid(
            "artifact-label must contain only letters, digits, hyphens or underscores",
        )
        .into());
    }
    let mut pending = vec![root_id];
    let mut seen = BTreeSet::new();
    let mut local_roots = BTreeSet::new();
    // Cargo package roots cannot describe #[path]/include! inputs outside the
    // package. Declare those directories explicitly; never infer Rust syntax.
    let extra_roots = package
        .pointer("/metadata/reverie-dbt/input-roots")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid("caller requires package.metadata.reverie-dbt.input-roots (possibly empty)")
        })?;
    for root in extra_roots {
        let relative = Path::new(
            root.as_str()
                .ok_or_else(|| invalid("input-root is not a string"))?,
        );
        if relative.is_absolute() {
            return Err(invalid("input-roots must be relative to the caller package").into());
        }
        let root = canonical_source(&caller.parent().unwrap().join(relative))?;
        if !root.is_dir() || root == workspace || !root.starts_with(workspace) {
            return Err(invalid("input-root must be a directory below the workspace").into());
        }
        local_roots.insert(root);
    }
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .ok_or_else(|| invalid("dependency node is missing"))?;
        let package = packages
            .get(id)
            .ok_or_else(|| invalid("dependency package is missing"))?;
        let name = string(package, "name")?;
        if matches!(name, "reverie-inguest" | "reverie-examples") {
            return Err(invalid(
                "caller graph includes a constructor-bearing example/in-guest package",
            )
            .into());
        }
        if name == "reverie-dbt"
            && array(node, "features")?
                .iter()
                .any(|feature| feature == "prototype-runtime")
        {
            return Err(invalid("caller graph enables DBT prototype exports").into());
        }
        if package.get("source").is_none_or(Value::is_null) {
            let manifest = canonical_source(Path::new(string(package, "manifest_path")?))?;
            local_roots.insert(
                manifest
                    .parent()
                    .ok_or_else(|| invalid("manifest lacks parent"))?
                    .to_owned(),
            );
        }
        for dependency in array(node, "deps")? {
            if array(dependency, "dep_kinds")?
                .iter()
                .any(|kind| kind.get("kind").is_none_or(|value| value != "dev"))
            {
                pending.push(string(dependency, "pkg")?);
            }
        }
    }
    Ok(Graph {
        root_id: root_id.to_owned(),
        label: label.to_owned(),
        local_roots,
    })
}

fn canonical_source(path: &Path) -> Result<PathBuf> {
    for component in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        if fs::symlink_metadata(component)?.file_type().is_symlink() {
            return Err(invalid(format!(
                "source input symlink is unsupported: {}",
                component.display()
            ))
            .into());
        }
    }
    Ok(fs::canonicalize(path)?)
}

fn hash_file(path: &Path) -> Result<String> {
    canonical_source(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "input must be a regular non-symlink file: {}",
            path.display()
        ))
        .into());
    }
    let mut input = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let size = input.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hash.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn source_tree(directory: &Path, paths: &mut BTreeSet<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if ["target", ".git", ".agents", ".llms", ".claude", "ignored"]
            .iter()
            .any(|skip| name == *skip)
        {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(invalid(format!(
                "source input symlink is unsupported: {}",
                path.display()
            ))
            .into());
        } else if kind.is_dir() {
            source_tree(&path, paths)?;
        } else if kind.is_file() {
            paths.insert(path);
        } else {
            return Err(invalid(format!("unsupported source input: {}", path.display())).into());
        }
    }
    Ok(())
}

fn inputs(options: &Options, graph: &Graph, sdk: &Path) -> Result<BTreeMap<PathBuf, String>> {
    let mut paths = BTreeSet::new();
    for root in &graph.local_roots {
        source_tree(root, &mut paths)?;
    }
    for relative in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        paths.insert(options.workspace.join(relative));
    }
    let config = options.workspace.join(".cargo");
    if config.exists() {
        source_tree(&config, &mut paths)?;
    }
    for marker in [
        ".reverie-dbt-install.provenance",
        ".reverie-dbt-install.sha256",
    ] {
        paths.insert(sdk.join(marker));
    }
    paths
        .into_iter()
        .map(|path| {
            if !path.is_absolute() || path.to_str().is_none() {
                return Err(invalid("manifest inputs require absolute UTF-8 paths").into());
            }
            let hash = hash_file(&path)?;
            Ok((path, hash))
        })
        .collect()
}

fn input_identity(inputs: &BTreeMap<PathBuf, String>) -> String {
    let mut hash = Sha256::new();
    for (path, digest) in ordered_inputs(inputs) {
        hash.update(path.as_os_str().as_bytes());
        hash.update([0]);
        hash.update(digest.as_bytes());
        hash.update(b"\n");
    }
    format!("{:x}", hash.finalize())
}

fn ordered_inputs(inputs: &BTreeMap<PathBuf, String>) -> Vec<(&PathBuf, &String)> {
    let mut inputs = inputs.iter().collect::<Vec<_>>();
    inputs.sort_by(|(a, _), (b, _)| a.as_os_str().as_bytes().cmp(b.as_os_str().as_bytes()));
    inputs
}

fn actual_cdylib(messages: &[u8], package: &str, target: &Path) -> Result<PathBuf> {
    let mut images = BTreeSet::new();
    let mut finished = 0;
    for line in messages
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let message: Value = serde_json::from_slice(line)?;
        if message["reason"] == "build-finished" {
            if message["success"] != true {
                return Err(invalid("Cargo reported an unsuccessful build").into());
            }
            finished += 1;
        }
        if message["reason"] == "compiler-artifact"
            && message["package_id"] == package
            && message
                .pointer("/target/crate_types")
                .and_then(Value::as_array)
                .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"))
        {
            for filename in array(&message, "filenames")? {
                let filename = filename
                    .as_str()
                    .ok_or_else(|| invalid("Cargo filename is not a string"))?;
                let path = PathBuf::from(filename);
                if path.extension() == Some(OsStr::new("so")) {
                    images.insert(fs::canonicalize(path)?);
                }
            }
        }
    }
    if finished != 1 || images.len() != 1 {
        return Err(invalid(
            "Cargo must report exactly one successful build and one actual caller cdylib",
        )
        .into());
    }
    let image = images.pop_first().unwrap();
    if !image.starts_with(target) {
        return Err(invalid("Cargo cdylib is outside the sole supplied target").into());
    }
    Ok(image)
}

fn stage(source: &Path, destination: &Path) -> Result<String> {
    let mut input = fs::File::open(source)?;
    let mut magic = [0; 4];
    input.read_exact(&mut magic)?;
    if magic != *b"\x7fELF" {
        return Err(invalid("staged image is not ELF").into());
    }
    let expected = hash_file(source)?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    let mut input = fs::File::open(source)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(destination, fs::metadata(source)?.permissions())?;
    if hash_file(destination)? != expected {
        return Err(invalid("image changed while staging").into());
    }
    Ok(expected)
}

fn generation(output: &Path, identity: &str) -> Result<PathBuf> {
    let generations = output.join("generations");
    fs::create_dir_all(&generations)?;
    for counter in 0..1024 {
        let path = generations.join(format!("{identity}-{}-{counter}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(invalid("could not allocate an unused immutable generation").into())
}

fn publish_manifest(
    output: &Path,
    generation: &Path,
    manifest: &Value,
    explicit: bool,
) -> Result<PathBuf> {
    let pending = generation.join("manifest.pending.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    let path = output.join("manifest.json");
    if explicit {
        // A hard link is an atomic create-if-absent on the same filesystem.
        // Leave the pending name as provenance; no artifact cleanup is implicit.
        fs::hard_link(&pending, &path)?;
    } else {
        fs::rename(&pending, &path)?;
    }
    fs::File::open(output)?.sync_all()?;
    Ok(path)
}

fn checks(producer: &Producer, identity: &str) -> Result<()> {
    let mut check = producer.cargo("check", Some(identity));
    check.args(["--all-targets", "--all-features"]);
    producer.run(check)?;
    let mut fmt = producer.command("cargo");
    fmt.arg("fmt")
        .arg("--manifest-path")
        .arg(&producer.options.caller)
        .args(["--", "--check"]);
    producer.run(fmt)?;
    let mut clippy = producer.cargo("clippy", Some(identity));
    clippy.args(["--all-targets", "--all-features", "--", "-D", "warnings"]);
    producer.run(clippy)?;
    let mut rustdoc = producer.cargo("rustdoc", Some(identity));
    rustdoc.args(["--lib", "--all-features", "--", "-D", "warnings"]);
    producer.run(rustdoc)?;
    Ok(())
}

fn produce(options: Options) -> Result<()> {
    let producer = Producer {
        options,
        deadline: Instant::now() + Duration::from_secs(900),
    };
    let mut version = producer.command("rustc");
    version.arg("-Vv");
    let toolchain = String::from_utf8(producer.run(version)?)?;
    if !toolchain
        .lines()
        .any(|line| line == "host: x86_64-unknown-linux-gnu")
    {
        return Err(invalid(
            "caller production requires the native x86_64-unknown-linux-gnu toolchain",
        )
        .into());
    }
    let mut metadata_command = producer.cargo("metadata", None);
    metadata_command.args([
        "--format-version",
        "1",
        "--filter-platform",
        "x86_64-unknown-linux-gnu",
    ]);
    let metadata_bytes = producer.run(metadata_command)?;
    let metadata: Value = serde_json::from_slice(&metadata_bytes)?;
    let graph = graph(
        &metadata,
        &producer.options.caller,
        &producer.options.workspace,
    )?;
    let (sdk, recipe) = sdk::cached(
        &producer.options.workspace,
        &producer.options.target,
        &producer.options.profile,
    )?;
    let source_inputs = inputs(&producer.options, &graph, &sdk)?;
    let identity = input_identity(&source_inputs);
    let output = producer.options.output.clone().unwrap_or_else(|| {
        producer
            .options
            .target
            .join(&producer.options.profile)
            .join("reverie-dbt-callers")
            .join(&graph.label)
    });
    fs::create_dir_all(&output)?;
    let output = fs::canonicalize(output)?;
    let explicit = producer.options.output.is_some();
    if explicit && output.join("manifest.json").symlink_metadata().is_ok() {
        return Err(invalid(
            "explicit output already contains a descriptor; select an unused --artifact-output",
        )
        .into());
    }
    let generation = generation(&output, &identity)?;
    let mut cargo = producer.cargo("build", Some(&identity));
    cargo.args(["--lib", "--message-format=json-render-diagnostics"]);
    let messages = producer.run(cargo)?;
    let runtime = actual_cdylib(
        &messages,
        &graph.root_id,
        &producer.options.target.join(&producer.options.profile),
    )?;
    let runtime_hash = stage(&runtime, &generation.join("libcaller_tool.so"))?;
    let build = producer
        .options
        .target
        .join(&producer.options.profile)
        .join("reverie-dbt-caller-native")
        .join(&graph.label);
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| OsString::from("cmake"));
    let mut configure = producer.command(&cmake);
    configure
        .arg("-S")
        .arg(producer.options.workspace.join("reverie-dbt/native"))
        .arg("-B")
        .arg(&build)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DDynamoRIO_DIR={}", sdk.join("cmake").display()))
        .arg(format!(
            "-DREVERIE_DBT_RUNTIME={}",
            generation.join("libcaller_tool.so").display()
        ))
        .arg(format!("-DREVERIE_DBT_CALLER_INPUT_IDENTITY={identity}"));
    producer.run(configure)?;
    let mut native = producer.command(&cmake);
    native
        .arg("--build")
        .arg(&build)
        .args(["--parallel", &producer.options.jobs.to_string()]);
    producer.run(native)?;
    let client_hash = stage(
        &build.join("libreverie_dbt_client.so"),
        &generation.join("libreverie_dbt_client.so"),
    )?;
    if producer.options.check {
        checks(&producer, &identity)?;
    }
    let (_, after_recipe) = sdk::cached(
        &producer.options.workspace,
        &producer.options.target,
        &producer.options.profile,
    )?;
    if recipe != after_recipe || source_inputs != inputs(&producer.options, &graph, &sdk)? {
        return Err(invalid("caller source or SDK inputs changed during production").into());
    }
    let manifest = json!({
        "schema": 1, "abi": 16, "capabilities": 7,
        "runtime_input_identity": identity,
        "runtime": { "path": generation.join("libcaller_tool.so").strip_prefix(&output)?, "sha256": runtime_hash },
        "client": { "path": generation.join("libreverie_dbt_client.so").strip_prefix(&output)?, "sha256": client_hash },
        "profile": producer.options.profile,
        "target_triple": "x86_64-unknown-linux-gnu",
        "toolchain": toolchain,
        "sdk_recipe": format!("sha256:{recipe}"),
        "inputs": ordered_inputs(&source_inputs).into_iter().map(|(path, sha256)| json!({"path": path, "sha256": sha256})).collect::<Vec<_>>()
    });
    let path = publish_manifest(&output, &generation, &manifest, explicit)?;
    println!("{}", path.display());
    Ok(())
}

fn main() {
    rust_script_prelude::init();
    let result = options().and_then(|options| match options {
        Some(options) => produce(options),
        None => Ok(()),
    });
    if let Err(error) = result {
        eprintln!("caller artifact production failed: {error}");
        std::process::exit(1);
    }
}
