/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sha2::Digest;
use sha2::Sha256;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#53): validate the pinned dr_invoke_syscall_as_app mmap fix.
const DYNAMORIO_REVISION: &str = "929840ad9190e5086775e8debc0f0b79b4208d59";
const MAX_PARALLEL_JOBS: usize = 16;
// Provenance: three clean builds of this curated source tree on 2026-08-03:
// 13.91s and 14.54s with 16 jobs on a development runner, and 71.49s with 4 jobs on a
// GitHub-hosted runner. Their elapsed-seconds * jobs proxies were
// 222.56, 232.64, and 285.96 job-seconds. The slowest one ran 4 jobs on a
// 4-vCPU runner, so every job it counted could run at once; the build therefore
// caps the job count at the available CPUs (dynamorio_build_jobs) rather than
// counting jobs that could only queue behind each other.
// The CI ratchet is 2x the slowest observation, rounded up; local source
// installs report without enforcing it.
const CI_MAX_BUILD_JOB_SECONDS: f64 = 572.0;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/dynamorio");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
    println!("cargo:rerun-if-env-changed=CI");
    println!("cargo:rerun-if-env-changed=REVERIE_DBT_MAX_BUILD_SECONDS");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source_dir = manifest_dir.join("vendor/dynamorio");
    let revision = fs::read_to_string(source_dir.join("REVISION"))
        .expect("the vendored DynamoRIO source is missing its REVISION marker");
    assert_eq!(
        revision.trim(),
        DYNAMORIO_REVISION,
        "the vendored DynamoRIO source revision marker changed"
    );
    for required in [
        "CMakeLists.txt",
        "core/lib/globals_shared.h",
        "core/unix/memcache.c",
        "tools/drdeploy.c",
        "ext/drmgr/drmgr.c",
        "ext/drreg/drreg.c",
        "ext/drwrap/drwrap.c",
        "ext/drx/drx.c",
    ] {
        assert!(
            source_dir.join(required).is_file(),
            "the vendored DynamoRIO source is incomplete: missing {required}"
        );
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let cmake = env::var_os("CMAKE").unwrap_or_else(|| OsString::from("cmake"));
    let generator = env::var_os("CMAKE_GENERATOR");
    let source_date_epoch = dynamorio_source_date_epoch(env::var_os("SOURCE_DATE_EPOCH"));
    let source_key = source_recipe_key(
        &source_dir,
        &manifest_dir.join("build.rs"),
        &cmake,
        generator.as_deref(),
        &source_date_epoch,
    );
    let cache_root = cache_root_for_out_dir(&out_dir);
    let install_dir = cache_root.join(format!("dynamorio-install-{source_key}"));
    let drrun = install_dir.join("bin64/drrun");
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time predates the Unix epoch")
        .as_secs();

    let _invalid_install = if install_dir.exists() && !install_is_usable(&install_dir, &source_key)
    {
        println!(
            "cargo:warning=DynamoRIO build cache INVALID key=sha256:{source_key} install={}; rebuilding",
            install_dir.display()
        );
        StagingDirectory::quarantine(&cache_root, &install_dir, &source_key)
    } else {
        None
    };

    if !install_is_usable(&install_dir, &source_key) {
        println!(
            "cargo:warning=DynamoRIO build cache MISS key=sha256:{source_key} observed_unix_seconds={observed_at}"
        );
        let staging = StagingDirectory::create(&cache_root, &source_key);
        let build_dir = staging.path().join("build");
        let staged_install = staging.path().join("install");
        build_dynamorio(
            &source_dir,
            &build_dir,
            &staged_install,
            &cmake,
            generator.as_deref(),
            &source_date_epoch,
        );
        write_install_attestation(&staged_install, &source_key);
        assert!(
            install_is_usable(&staged_install, &source_key),
            "DynamoRIO source build produced an incomplete install at {}",
            staged_install.display()
        );
        let published = publish_install(&staged_install, &install_dir, &source_key);
        println!(
            "cargo:warning=DynamoRIO build cache {} key=sha256:{source_key} install={}",
            if published { "PUBLISHED" } else { "RACE-HIT" },
            install_dir.display()
        );
    } else {
        println!(
            "cargo:warning=DynamoRIO build cache HIT key=sha256:{source_key} observed_unix_seconds={observed_at} install={}",
            install_dir.display()
        );
    }

    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_HOME={}",
        install_dir.display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_CMAKE={}",
        install_dir.join("cmake").display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_DRRUN={}",
        drrun.display()
    );
}

/// Put native artifacts outside Cargo's package-fingerprint directory.
///
/// Cargo gives the same package a different `OUT_DIR` when build-dependency
/// profiles differ (for example, `cargo build` versus `cargo doc`). Cargo uses
/// both `build/reverie-dbt-HASH/out` for workspace packages and
/// `build/reverie-dbt/HASH/out` for some external consumers. In either layout,
/// the profile directory above `build` is the narrowest cache scope the
/// fingerprints can safely share.
fn shared_cache_root(out_dir: &Path) -> Option<PathBuf> {
    let fingerprint_dir = out_dir.parent()?;
    let fingerprint_parent = fingerprint_dir.parent()?;
    let cargo_build_dir = if fingerprint_parent.file_name() == Some(OsStr::new("build")) {
        fingerprint_parent
    } else if fingerprint_parent.file_name() == Some(OsStr::new("reverie-dbt")) {
        let candidate = fingerprint_parent.parent()?;
        (candidate.file_name() == Some(OsStr::new("build"))).then_some(candidate)?
    } else {
        return None;
    };
    Some(cargo_build_dir.parent()?.join("reverie-dbt-native-cache"))
}

/// Unknown Cargo layouts must not abort the consuming build or share an
/// unproven cache scope. Fall back to this fingerprint's own `OUT_DIR`; the
/// first use rebuilds and later uses may reuse only that isolated entry.
fn cache_root_for_out_dir(out_dir: &Path) -> PathBuf {
    shared_cache_root(out_dir).unwrap_or_else(|| {
        println!(
            "cargo:warning=DynamoRIO shared cache disabled for unrecognized OUT_DIR {}; rebuilding in an isolated cache",
            out_dir.display()
        );
        out_dir.join("reverie-dbt-native-cache")
    })
}

const REQUIRED_INSTALL_ARTIFACTS: &[&str] = &[
    "bin64/drrun",
    "cmake/DynamoRIOConfig.cmake",
    "cmake/DynamoRIOTarget64.cmake",
    "cmake/DynamoRIOTarget64-release.cmake",
    "include/dr_api.h",
    "lib64/release/libdynamorio.so",
    "lib64/release/libdrpreload.so",
    "ext/include/drmgr.h",
    "ext/include/drreg.h",
    "ext/include/drwrap.h",
    "ext/include/drx.h",
    "ext/lib64/release/libdrmgr.so",
    "ext/lib64/release/libdrreg.so",
    "ext/lib64/release/libdrwrap.so",
    "ext/lib64/release/libdrx.so",
];
const ELF_INSTALL_ARTIFACTS: &[&str] = &[
    "bin64/drrun",
    "lib64/release/libdynamorio.so",
    "lib64/release/libdrpreload.so",
    "ext/lib64/release/libdrmgr.so",
    "ext/lib64/release/libdrreg.so",
    "ext/lib64/release/libdrwrap.so",
    "ext/lib64/release/libdrx.so",
];
const INSTALL_MANIFEST: &str = ".reverie-dbt-install.sha256";
const INSTALL_PROVENANCE: &str = ".reverie-dbt-install.provenance";
const INSTALL_PROVENANCE_SCHEMA: &str = "reverie-dbt-dynamorio-install-v1";

fn install_is_usable(install_dir: &Path, expected_source_key: &str) -> bool {
    let artifacts_present = REQUIRED_INSTALL_ARTIFACTS.iter().all(|relative| {
        install_dir
            .join(relative)
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0)
    });
    if !artifacts_present {
        return false;
    }
    let drrun_executable = install_dir
        .join("bin64/drrun")
        .metadata()
        .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0);
    if !drrun_executable
        || !ELF_INSTALL_ARTIFACTS
            .iter()
            .all(|relative| has_elf_magic(&install_dir.join(relative)))
    {
        return false;
    }

    let Some((recorded_manifest, actual_manifest, recorded_provenance)) =
        fs::read_to_string(install_dir.join(INSTALL_MANIFEST))
            .ok()
            .zip(install_manifest_contents(install_dir).ok())
            .zip(fs::read_to_string(install_dir.join(INSTALL_PROVENANCE)).ok())
            .map(|((recorded, actual), provenance)| (recorded, actual, provenance))
    else {
        return false;
    };
    if recorded_manifest != actual_manifest {
        return false;
    }
    recorded_provenance == install_provenance(expected_source_key, &recorded_manifest)
}

fn has_elf_magic(path: &Path) -> bool {
    fs::read(path)
        .ok()
        .is_some_and(|contents| contents.starts_with(b"\x7fELF"))
}

fn write_install_attestation(install_dir: &Path, source_key: &str) {
    let contents = install_manifest_contents(install_dir).unwrap_or_else(|error| {
        panic!(
            "failed to inventory DynamoRIO install {}: {error}",
            install_dir.display()
        )
    });
    fs::write(install_dir.join(INSTALL_MANIFEST), contents).unwrap_or_else(|error| {
        panic!(
            "failed to write DynamoRIO install manifest in {}: {error}",
            install_dir.display()
        )
    });
    let manifest = fs::read_to_string(install_dir.join(INSTALL_MANIFEST))
        .expect("the just-written DynamoRIO install manifest must be readable");
    fs::write(
        install_dir.join(INSTALL_PROVENANCE),
        install_provenance(source_key, &manifest),
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to write DynamoRIO install provenance in {}: {error}",
            install_dir.display()
        )
    });
}

fn install_provenance(source_key: &str, manifest: &str) -> String {
    let manifest_digest = Sha256::digest(manifest.as_bytes());
    format!(
        "schema={INSTALL_PROVENANCE_SCHEMA}\nsource_recipe_sha256={source_key}\nmanifest_sha256={manifest_digest:x}\n"
    )
}

fn install_manifest_contents(install_dir: &Path) -> io::Result<String> {
    fn walk(root: &Path, directory: &Path, lines: &mut Vec<String>) -> io::Result<()> {
        let mut paths = fs::read_dir(directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<Vec<_>>>()?;
        paths.sort();
        for path in paths {
            let relative = path.strip_prefix(root).map_err(io::Error::other)?;
            if relative == Path::new(INSTALL_MANIFEST) || relative == Path::new(INSTALL_PROVENANCE)
            {
                continue;
            }
            let file_type = fs::symlink_metadata(&path)?.file_type();
            if file_type.is_dir() {
                walk(root, &path, lines)?;
            } else if file_type.is_symlink() {
                lines.push(format!(
                    "symlink {} {}",
                    fs::read_link(&path)?.display(),
                    relative.display()
                ));
            } else if file_type.is_file() {
                let mut hasher = Sha256::new();
                hasher.update(fs::read(&path)?);
                lines.push(format!(
                    "sha256:{:x} {}",
                    hasher.finalize(),
                    relative.display()
                ));
            } else {
                return Err(io::Error::other(format!(
                    "unsupported installed artifact {}",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    let mut lines = Vec::new();
    walk(install_dir, install_dir, &mut lines)?;
    Ok(format!("{}\n", lines.join("\n")))
}

/// Atomically publish a complete install without overwriting another builder.
///
/// Two Cargo invocations can miss simultaneously. They may both do temporary
/// work, but directory rename ensures consumers observe either no cache entry
/// or one complete immutable install. The loser verifies and reuses the winner.
fn publish_install(staged_install: &Path, install_dir: &Path, source_key: &str) -> bool {
    publish_install_after_precheck(staged_install, install_dir, source_key, || {})
}

fn publish_install_after_precheck<F>(
    staged_install: &Path,
    install_dir: &Path,
    source_key: &str,
    after_precheck: F,
) -> bool
where
    F: FnOnce(),
{
    assert!(
        install_is_usable(staged_install, source_key),
        "refusing to publish incomplete DynamoRIO install {}",
        staged_install.display()
    );
    if install_dir.exists() {
        if install_is_usable(install_dir, source_key) {
            return false;
        }
        panic!(
            "refusing to replace incomplete DynamoRIO cache entry {}",
            install_dir.display()
        );
    }
    after_precheck();

    match fs::rename(staged_install, install_dir) {
        Ok(()) => true,
        Err(error) if install_is_usable(install_dir, source_key) => {
            println!(
                "cargo:warning=another builder published the DynamoRIO cache entry first: {error}"
            );
            false
        }
        Err(error) => panic!(
            "failed to atomically publish DynamoRIO install {} -> {}: {error}",
            staged_install.display(),
            install_dir.display()
        ),
    }
}

struct StagingDirectory {
    path: PathBuf,
}

impl StagingDirectory {
    fn create(cache_root: &Path, source_key: &str) -> Self {
        fs::create_dir_all(cache_root).unwrap_or_else(|error| {
            panic!(
                "failed to create DynamoRIO cache root {}: {error}",
                cache_root.display()
            )
        });
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time predates the Unix epoch")
            .as_nanos();
        for attempt in 0..100 {
            let path = cache_root.join(format!(
                ".staging-{source_key}-{}-{nonce}-{attempt}",
                process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!(
                    "failed to create DynamoRIO staging directory {}: {error}",
                    path.display()
                ),
            }
        }
        panic!("failed to allocate a unique DynamoRIO staging directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn quarantine(cache_root: &Path, install_dir: &Path, source_key: &str) -> Option<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time predates the Unix epoch")
            .as_nanos();
        for attempt in 0..100 {
            let path = cache_root.join(format!(
                ".invalid-{source_key}-{}-{nonce}-{attempt}",
                process::id()
            ));
            if path.exists() {
                continue;
            }
            match fs::rename(install_dir, &path) {
                Ok(()) => return Some(Self { path }),
                Err(_) if !install_dir.exists() || install_is_usable(install_dir, source_key) => {
                    return None;
                }
                Err(error) => panic!(
                    "failed to quarantine unusable DynamoRIO cache entry {} -> {}: {error}",
                    install_dir.display(),
                    path.display()
                ),
            }
        }
        panic!("failed to allocate a unique DynamoRIO quarantine path")
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "reverie-dbt: failed to remove staging directory {}: {error}",
                self.path.display()
            );
        }
    }
}

fn source_recipe_key(
    source_dir: &Path,
    build_script: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
    source_date_epoch: &std::ffi::OsStr,
) -> String {
    let mut hasher = Sha256::new();
    hash_tree(&mut hasher, source_dir, source_dir);
    hash_file(&mut hasher, b"build.rs", build_script);
    hash_value(&mut hasher, b"CMAKE", cmake.as_encoded_bytes());
    hash_value(
        &mut hasher,
        b"CMAKE_GENERATOR",
        generator.map_or(b"<unset>", std::ffi::OsStr::as_encoded_bytes),
    );
    hash_value(
        &mut hasher,
        b"SOURCE_DATE_EPOCH",
        source_date_epoch.as_encoded_bytes(),
    );
    format!("{:x}", hasher.finalize())
}

fn hash_value(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update(b"value\0");
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
    hasher.update(value.len().to_le_bytes());
    hasher.update(value);
}

fn hash_tree(hasher: &mut Sha256, root: &Path, directory: &Path) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    panic!("failed to inspect {}: {error}", directory.display())
                })
                .path()
        })
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        let relative = path
            .strip_prefix(root)
            .expect("vendored path escaped its root");
        if path.is_dir() {
            hasher.update(b"directory\0");
            hash_name(hasher, relative);
            hash_tree(hasher, root, &path);
        } else {
            hash_file(hasher, relative.as_os_str().as_encoded_bytes(), &path);
        }
    }
}

fn hash_file(hasher: &mut Sha256, name: &[u8], path: &Path) {
    hasher.update(b"file\0");
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
    let contents =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    hasher.update(contents.len().to_le_bytes());
    hasher.update(contents);
}

fn hash_name(hasher: &mut Sha256, path: &Path) {
    let name = path.as_os_str().as_encoded_bytes();
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
}

/// Used when the caller sets no SOURCE_DATE_EPOCH, so DynamoRIO's
/// __DATE__/__TIME__ never depend on when the cache was first filled. The value
/// is hashed into the cache key either way.
const DEFAULT_SOURCE_DATE_EPOCH: &str = "0";

fn dynamorio_source_date_epoch(caller: Option<OsString>) -> OsString {
    caller
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_SOURCE_DATE_EPOCH))
}

/// Characters a path may contain and still reach GCC unchanged through
/// CFLAGS: CMake splits CFLAGS on whitespace, GCC splits a map at its first
/// '=', and Make expands '$'. Anything else is refused rather than escaped.
fn path_char_survives_cflags(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '+' | '-')
}

/// The GCC path maps that make a DynamoRIO build independent of where it ran:
/// the staging directory and the source directory, each also by its
/// canonical path when that differs (a symlinked target directory, or a
/// generator that resolves paths, still reaches the real one). Refused when a
/// path cannot travel through CFLAGS (see `path_char_survives_cflags`).
fn dynamorio_prefix_maps(staging_root: &Path, source_dir: &Path) -> Result<String, String> {
    let mut maps = Vec::new();
    for (path, to) in [
        (staging_root, "/dynamorio-build"),
        (source_dir, "/dynamorio-src"),
    ] {
        let mut spellings = vec![path.to_path_buf()];
        if let Ok(canonical) = fs::canonicalize(path)
            && canonical != path
        {
            spellings.push(canonical);
        }
        for spelling in spellings {
            let text = spelling
                .to_str()
                .ok_or_else(|| format!("{} is not UTF-8", spelling.display()))?;
            if let Some(bad) = text.chars().find(|&c| !path_char_survives_cflags(c)) {
                return Err(format!(
                    "{text} contains {bad:?}; only [A-Za-z0-9/._+-] survive CFLAGS intact"
                ));
            }
            maps.push(format!("-ffile-prefix-map={text}={to}"));
            maps.push(format!("-fdebug-prefix-map={text}={to}"));
        }
    }
    Ok(maps.join(" "))
}

/// The DynamoRIO configure command, and the reason the path maps were left
/// out when they had to be. `inherited` reads the caller's environment.
fn dynamorio_configure_command(
    source_dir: &Path,
    build_dir: &Path,
    install_dir: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
    source_date_epoch: &std::ffi::OsStr,
    inherited: impl Fn(&str) -> Option<OsString>,
) -> (Command, Option<String>) {
    let mut configure = Command::new(cmake);
    // Reproducible artifacts: the build runs in a per-build staging directory
    // (`.staging-<key>-<pid>-<nonce>-<attempt>`) and reads the source from
    // wherever Cargo checked Reverie out. Both paths reach DWARF (DW_AT_comp_dir
    // and file names), and through the split .debug files they reach each
    // library's GNU build-id and .gnu_debuglink CRC, so two builds of the same
    // source differed in exactly those bytes. Map both to fixed names.
    // DynamoRIO's CMakeLists sets CMAKE_C_FLAGS/CMAKE_CXX_FLAGS itself and
    // appends $ENV{CFLAGS}/$ENV{CXXFLAGS}, so the maps go there, after any
    // flags the caller already set. __FILE__ in DynamoRIO's assert messages
    // then reads /dynamorio-src/... instead of the checkout path.
    let staging_root = build_dir
        .parent()
        .expect("the DynamoRIO build directory has a staging parent");
    let unmapped = match dynamorio_prefix_maps(staging_root, source_dir) {
        Ok(maps) => {
            for flags in ["CFLAGS", "CXXFLAGS"] {
                let mut value = inherited(flags).unwrap_or_default();
                if !value.is_empty() {
                    value.push(" ");
                }
                value.push(&maps);
                configure.env(flags, value);
            }
            None
        }
        Err(reason) => Some(reason),
    };
    configure.env("SOURCE_DATE_EPOCH", source_date_epoch);
    configure
        .arg("-S")
        .arg(source_dir)
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()))
        .args([
            "-DBUILD_TESTS=OFF",
            "-DBUILD_SAMPLES=OFF",
            "-DBUILD_DOCS=OFF",
            "-DBUILD_CLIENTS=OFF",
            "-DBUILD_EXT=ON",
            "-DBUILD_TOOLS=ON",
        ]);
    if let Some(generator) = generator {
        configure.arg("-G").arg(generator);
    }
    (configure, unmapped)
}

/// The DynamoRIO build-and-install command. __DATE__/__TIME__ (DynamoRIO's
/// version banner) are evaluated while compiling, so this step needs the
/// epoch as well as the configure.
fn dynamorio_build_command(
    cmake: &std::ffi::OsStr,
    build_dir: &Path,
    jobs: usize,
    source_date_epoch: &std::ffi::OsStr,
) -> Command {
    let mut build = Command::new(cmake);
    build.env("SOURCE_DATE_EPOCH", source_date_epoch);
    build.arg("--build").arg(build_dir).args([
        "--config",
        "Release",
        "--target",
        "install",
        "--parallel",
    ]);
    build.arg(jobs.to_string());
    build
}

fn build_dynamorio(
    source_dir: &Path,
    build_dir: &Path,
    install_dir: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
    source_date_epoch: &std::ffi::OsStr,
) {
    let started = Instant::now();
    let (mut configure, unmapped) = dynamorio_configure_command(
        source_dir,
        build_dir,
        install_dir,
        cmake,
        generator,
        source_date_epoch,
        |name| env::var_os(name),
    );
    if let Some(reason) = unmapped {
        println!(
            "cargo:warning=DynamoRIO is built without path maps ({reason}); its binaries embed this build's paths and differ between builds"
        );
    }
    run(&mut configure, "configure DynamoRIO");

    let requested_jobs = env::var("NUM_JOBS").ok();
    let available_cpus =
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let jobs = dynamorio_build_jobs(requested_jobs.as_deref(), available_cpus);
    let mut build = dynamorio_build_command(cmake, build_dir, jobs, source_date_epoch);
    run(&mut build, "build and install DynamoRIO");

    let seconds = started.elapsed().as_secs_f64();
    let job_seconds = seconds * jobs as f64;
    println!(
        "cargo:warning=DynamoRIO source build completed in {seconds:.2}s (jobs={jobs}, {job_seconds:.2} job-seconds; NUM_JOBS={}, available CPUs={available_cpus})",
        requested_jobs.as_deref().unwrap_or("unset")
    );
    if let Ok(limit) = env::var("REVERIE_DBT_MAX_BUILD_SECONDS") {
        let limit = limit
            .parse::<f64>()
            .expect("REVERIE_DBT_MAX_BUILD_SECONDS must be a positive number");
        assert!(
            limit > 0.0,
            "REVERIE_DBT_MAX_BUILD_SECONDS must be positive"
        );
        assert!(
            seconds <= limit,
            "DynamoRIO source build took {seconds:.2}s, exceeding the {limit:.2}s CI ratchet"
        );
    } else if env::var_os("CI").is_some() {
        enforce_ci_build_ratchet(seconds, jobs);
    }
}

/// Number of parallel jobs for the DynamoRIO source build, which is also the
/// job count the CI ratchet multiplies by. `NUM_JOBS` asks for a count, but jobs
/// beyond the CPUs this process may run on cannot execute in parallel: passing
/// them to cmake only oversubscribes, and counting them in the ratchet inflates
/// the job-second product without any extra work being done. So the request is
/// clamped to `1..=MAX_PARALLEL_JOBS` and then capped at the available CPUs.
fn dynamorio_build_jobs(requested: Option<&str>, available_cpus: usize) -> usize {
    requested
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PARALLEL_JOBS)
        .min(available_cpus.max(1))
}

fn enforce_ci_build_ratchet(seconds: f64, jobs: usize) {
    let job_seconds = seconds * jobs as f64;
    assert!(
        job_seconds <= CI_MAX_BUILD_JOB_SECONDS,
        "DynamoRIO source build took {seconds:.2}s with {jobs} jobs ({job_seconds:.2} job-seconds), exceeding the {CI_MAX_BUILD_JOB_SECONDS:.2} job-second CI ratchet"
    );
}

fn run(command: &mut Command, description: &str) {
    eprintln!("reverie-dbt: {description}: {command:?}");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}

fn required_env(name: &str) -> OsString {
    env::var_os(name).unwrap_or_else(|| panic!("Cargo did not set {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SOURCE_KEY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn source_recipe_key_changes_with_source_or_recipe() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/input.c"), "first\n").unwrap();
        let recipe = directory.path().join("build.rs");
        fs::write(&recipe, "recipe one\n").unwrap();
        let initial = source_recipe_key(&source, &recipe, "cmake".as_ref(), None, "0".as_ref());
        assert_eq!(
            initial,
            source_recipe_key(&source, &recipe, "cmake".as_ref(), None, "0".as_ref())
        );

        fs::write(source.join("nested/input.c"), "second\n").unwrap();
        let source_changed =
            source_recipe_key(&source, &recipe, "cmake".as_ref(), None, "0".as_ref());
        assert_ne!(initial, source_changed);

        fs::write(&recipe, "recipe two\n").unwrap();
        let recipe_changed =
            source_recipe_key(&source, &recipe, "cmake".as_ref(), None, "0".as_ref());
        assert_ne!(source_changed, recipe_changed);

        let cmake_changed = source_recipe_key(
            &source,
            &recipe,
            "custom-cmake".as_ref(),
            None,
            "0".as_ref(),
        );
        assert_ne!(recipe_changed, cmake_changed);

        let generator_changed = source_recipe_key(
            &source,
            &recipe,
            "custom-cmake".as_ref(),
            Some("Ninja".as_ref()),
            "0".as_ref(),
        );
        assert_ne!(cmake_changed, generator_changed);

        // A cache filled under one SOURCE_DATE_EPOCH must not answer another:
        // the epoch is in DynamoRIO's __DATE__/__TIME__ banner.
        let epoch_changed = source_recipe_key(
            &source,
            &recipe,
            "custom-cmake".as_ref(),
            Some("Ninja".as_ref()),
            "1791400000".as_ref(),
        );
        assert_ne!(generator_changed, epoch_changed);
    }

    #[test]
    fn source_date_epoch_defaults_when_unset_or_empty() {
        assert_eq!(dynamorio_source_date_epoch(None), "0");
        assert_eq!(dynamorio_source_date_epoch(Some(OsString::new())), "0");
        assert_eq!(
            dynamorio_source_date_epoch(Some(OsString::from("1791400000"))),
            "1791400000"
        );
    }

    #[test]
    fn prefix_maps_cover_both_directories_and_their_canonical_paths() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let staging = real.join(".staging-key-1-2-0");
        let source = directory.path().join("src");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&source).unwrap();
        let canonical_staging = fs::canonicalize(&staging).unwrap();
        let canonical_source = fs::canonicalize(&source).unwrap();
        let maps = dynamorio_prefix_maps(&canonical_staging, &canonical_source).unwrap();
        assert_eq!(
            maps,
            format!(
                "-ffile-prefix-map={0}=/dynamorio-build -fdebug-prefix-map={0}=/dynamorio-build \
                 -ffile-prefix-map={1}=/dynamorio-src -fdebug-prefix-map={1}=/dynamorio-src",
                canonical_staging.display(),
                canonical_source.display()
            )
        );

        // Reached through a symlink, both spellings are mapped.
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let through_alias = alias.join(".staging-key-1-2-0");
        let maps = dynamorio_prefix_maps(&through_alias, &canonical_source).unwrap();
        for spelling in [&through_alias, &canonical_staging] {
            assert!(
                maps.contains(&format!(
                    "-ffile-prefix-map={}=/dynamorio-build",
                    spelling.display()
                )),
                "{maps}"
            );
        }
    }

    #[test]
    fn prefix_maps_refuse_paths_cflags_cannot_carry() {
        let directory = tempfile::tempdir().unwrap();
        for name in [
            "with space",
            "with=equals",
            "with\ttab",
            "with$dollar",
            "with\"quote",
        ] {
            let path = directory.path().join(name);
            fs::create_dir_all(&path).unwrap();
            let error = dynamorio_prefix_maps(&path, directory.path()).unwrap_err();
            assert!(error.contains("survive CFLAGS"), "{name}: {error}");
            let error = dynamorio_prefix_maps(directory.path(), &path).unwrap_err();
            assert!(error.contains("survive CFLAGS"), "{name}: {error}");
        }
        let plain = directory.path().join("plain_dir-1.2+x");
        fs::create_dir_all(&plain).unwrap();
        dynamorio_prefix_maps(&plain, &plain).unwrap();
    }

    fn command_env(command: &Command, name: &str) -> Option<OsString> {
        command
            .get_envs()
            .find(|(key, _)| *key == name)
            .and_then(|(_, value)| value.map(OsStr::to_os_string))
    }

    #[test]
    fn configure_and_build_carry_the_epoch_and_the_maps() {
        let directory = tempfile::tempdir().unwrap();
        let staging = fs::canonicalize(directory.path()).unwrap().join("staging");
        let build_dir = staging.join("build");
        let source = staging.join("src");
        fs::create_dir_all(&build_dir).unwrap();
        fs::create_dir_all(&source).unwrap();
        let (configure, unmapped) = dynamorio_configure_command(
            &source,
            &build_dir,
            &staging.join("install"),
            "cmake".as_ref(),
            None,
            "1791400000".as_ref(),
            |name| (name == "CFLAGS").then(|| OsString::from("-O1")),
        );
        assert_eq!(unmapped, None);
        assert_eq!(
            command_env(&configure, "SOURCE_DATE_EPOCH"),
            Some(OsString::from("1791400000"))
        );
        let cflags = command_env(&configure, "CFLAGS").unwrap();
        let cflags = cflags.to_str().unwrap();
        assert!(cflags.starts_with("-O1 "), "{cflags}");
        assert!(
            cflags.contains(&format!(
                "-ffile-prefix-map={}=/dynamorio-build",
                staging.display()
            )),
            "{cflags}"
        );
        let cxxflags = command_env(&configure, "CXXFLAGS").unwrap();
        assert!(
            cxxflags.to_str().unwrap().starts_with("-ffile-prefix-map="),
            "{cxxflags:?}"
        );

        // The build step compiles, so it needs the epoch too; without it the
        // banner takes the wall clock.
        let build = dynamorio_build_command("cmake".as_ref(), &build_dir, 8, "1791400000".as_ref());
        assert_eq!(
            command_env(&build, "SOURCE_DATE_EPOCH"),
            Some(OsString::from("1791400000"))
        );
    }

    #[test]
    fn configure_without_maps_still_carries_the_epoch() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join("with space");
        let build_dir = staging.join("build");
        fs::create_dir_all(&build_dir).unwrap();
        let (configure, unmapped) = dynamorio_configure_command(
            directory.path(),
            &build_dir,
            &staging.join("install"),
            "cmake".as_ref(),
            None,
            "0".as_ref(),
            |_| None,
        );
        assert!(unmapped.unwrap().contains("survive CFLAGS"));
        assert_eq!(command_env(&configure, "CFLAGS"), None);
        assert_eq!(
            command_env(&configure, "SOURCE_DATE_EPOCH"),
            Some(OsString::from("0"))
        );
    }

    #[test]
    fn workspace_and_consumer_fingerprints_share_one_profile_cache() {
        let directory = tempfile::tempdir().unwrap();
        for profile in ["debug", "release"] {
            let workspace_first = directory
                .path()
                .join(format!("target/{profile}/build/reverie-dbt-first/out"));
            let workspace_second = directory
                .path()
                .join(format!("target/{profile}/build/reverie-dbt-second/out"));
            let consumer_first = directory
                .path()
                .join(format!("target/{profile}/build/reverie-dbt/first/out"));
            let consumer_second = directory
                .path()
                .join(format!("target/{profile}/build/reverie-dbt/second/out"));
            let expected = directory
                .path()
                .join(format!("target/{profile}/reverie-dbt-native-cache"));

            for out_dir in [
                workspace_first,
                workspace_second,
                consumer_first,
                consumer_second,
            ] {
                assert_eq!(shared_cache_root(&out_dir), Some(expected.clone()));
                assert_eq!(cache_root_for_out_dir(&out_dir), expected);
            }
        }
    }

    #[test]
    fn unrecognized_out_dir_uses_an_isolated_cache() {
        let directory = tempfile::tempdir().unwrap();
        let out_dir = directory.path().join("unrecognized/layout/out");
        assert_eq!(shared_cache_root(&out_dir), None);
        assert_eq!(
            cache_root_for_out_dir(&out_dir),
            out_dir.join("reverie-dbt-native-cache")
        );
    }

    fn complete_fixture(path: &Path, marker: &str) {
        for relative in REQUIRED_INSTALL_ARTIFACTS {
            let artifact = path.join(relative);
            fs::create_dir_all(artifact.parent().unwrap()).unwrap();
            if ELF_INSTALL_ARTIFACTS.contains(relative) {
                fs::write(
                    &artifact,
                    [
                        b"\x7fELF".as_slice(),
                        relative.as_bytes(),
                        marker.as_bytes(),
                    ]
                    .concat(),
                )
                .unwrap();
            } else {
                fs::write(&artifact, marker).unwrap();
            }
        }
        let drrun = path.join("bin64/drrun");
        let mut permissions = drrun.metadata().unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(drrun, permissions).unwrap();
        write_install_attestation(path, TEST_SOURCE_KEY);
    }

    #[test]
    fn atomic_publish_never_overwrites_a_complete_winner() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let published = directory.path().join("published");
        complete_fixture(&first, "first");
        complete_fixture(&second, "second");

        assert!(publish_install(&first, &published, TEST_SOURCE_KEY));
        assert!(!publish_install(&second, &published, TEST_SOURCE_KEY));
        assert!(
            fs::read_to_string(published.join("bin64/drrun"))
                .unwrap()
                .ends_with("first")
        );
        assert!(
            second.exists(),
            "losing builder still owns its staging tree"
        );
    }

    #[test]
    fn concurrent_publishers_produce_one_complete_winner() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let published = directory.path().join("published");
        complete_fixture(&first, "first");
        complete_fixture(&second, "second");
        let barrier = std::sync::Barrier::new(2);

        let (first_won, second_won) = std::thread::scope(|scope| {
            let first_thread = scope.spawn(|| {
                barrier.wait();
                publish_install(&first, &published, TEST_SOURCE_KEY)
            });
            let second_thread = scope.spawn(|| {
                barrier.wait();
                publish_install(&second, &published, TEST_SOURCE_KEY)
            });
            (first_thread.join().unwrap(), second_thread.join().unwrap())
        });

        assert_ne!(first_won, second_won, "exactly one publisher must win");
        assert!(install_is_usable(&published, TEST_SOURCE_KEY));
        let marker = fs::read_to_string(published.join("bin64/drrun")).unwrap();
        assert!(marker.ends_with("first") || marker.ends_with("second"));
    }

    #[test]
    fn publisher_losing_after_precheck_reuses_winner_without_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let winner = directory.path().join("winner");
        let loser = directory.path().join("loser");
        let published = directory.path().join("published");
        complete_fixture(&winner, "winner");
        complete_fixture(&loser, "loser");

        let loser_won = publish_install_after_precheck(&loser, &published, TEST_SOURCE_KEY, || {
            assert!(publish_install(&winner, &published, TEST_SOURCE_KEY))
        });

        assert!(
            !loser_won,
            "the publisher that lost the race must fall back"
        );
        assert!(loser.exists(), "the loser must retain its staging tree");
        assert!(install_is_usable(&published, TEST_SOURCE_KEY));
        assert!(
            fs::read_to_string(published.join("bin64/drrun"))
                .unwrap()
                .ends_with("winner")
        );
    }

    #[test]
    fn self_consistent_wrong_elf_does_not_match_publisher_provenance() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path().join("install");
        complete_fixture(&install, "correct");
        assert!(install_is_usable(&install, TEST_SOURCE_KEY));

        fs::copy(
            install.join("lib64/release/libdrpreload.so"),
            install.join("lib64/release/libdynamorio.so"),
        )
        .unwrap();
        let forged_manifest = install_manifest_contents(&install).unwrap();
        fs::write(install.join(INSTALL_MANIFEST), forged_manifest).unwrap();

        assert!(
            !install_is_usable(&install, TEST_SOURCE_KEY),
            "regenerating a self-consistent inventory must not rewrite publisher provenance"
        );
    }

    #[test]
    fn attestation_is_bound_to_the_expected_source_recipe() {
        let directory = tempfile::tempdir().unwrap();
        let install = directory.path().join("install");
        complete_fixture(&install, "correct");

        assert!(install_is_usable(&install, TEST_SOURCE_KEY));
        assert!(!install_is_usable(
            &install,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ));
    }

    #[test]
    #[should_panic(expected = "refusing to replace incomplete DynamoRIO cache entry")]
    fn incomplete_cache_entry_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("staged");
        let incomplete = directory.path().join("incomplete");
        complete_fixture(&staged, "complete");
        fs::create_dir(&incomplete).unwrap();
        publish_install(&staged, &incomplete, TEST_SOURCE_KEY);
    }

    #[test]
    fn deleted_runtime_library_is_quarantined_and_rebuilt() {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("cache");
        let install = cache.join("dynamorio-install-key");
        complete_fixture(&install, "original");
        assert!(install_is_usable(&install, TEST_SOURCE_KEY));

        fs::remove_file(install.join("lib64/release/libdynamorio.so")).unwrap();
        assert!(!install_is_usable(&install, TEST_SOURCE_KEY));
        let quarantined = StagingDirectory::quarantine(&cache, &install, "key")
            .expect("the unusable entry must be quarantined");
        assert!(!install.exists());

        let staged = directory.path().join("replacement");
        complete_fixture(&staged, "replacement");
        assert!(publish_install(&staged, &install, TEST_SOURCE_KEY));
        assert!(install_is_usable(&install, TEST_SOURCE_KEY));
        drop(quarantined);
    }

    #[test]
    fn measured_clean_builds_satisfy_the_ci_ratchet() {
        for (seconds, jobs) in [(13.91, 16), (14.54, 16), (71.49, 4)] {
            enforce_ci_build_ratchet(seconds, jobs);
        }
    }

    #[test]
    #[should_panic(expected = "exceeding the 572.00 job-second CI ratchet")]
    fn throughput_regression_fails_the_ci_ratchet() {
        enforce_ci_build_ratchet(144.0, 4);
    }

    #[test]
    fn build_jobs_are_capped_at_the_available_cpus() {
        // A request above the CPU count runs, and is counted, at the CPU count.
        assert_eq!(dynamorio_build_jobs(Some("32"), 4), 4);
        assert_eq!(dynamorio_build_jobs(Some("16"), 4), 4);
        // With enough CPUs the existing 16-job clamp still applies.
        assert_eq!(dynamorio_build_jobs(Some("32"), 64), MAX_PARALLEL_JOBS);
        assert_eq!(dynamorio_build_jobs(Some("8"), 64), 8);
        // A request within the CPU count is used unchanged.
        assert_eq!(dynamorio_build_jobs(Some("4"), 4), 4);
        assert_eq!(dynamorio_build_jobs(Some("2"), 8), 2);
    }

    #[test]
    fn build_jobs_fall_back_to_one() {
        assert_eq!(dynamorio_build_jobs(None, 8), 1);
        assert_eq!(dynamorio_build_jobs(Some("0"), 8), 1);
        assert_eq!(dynamorio_build_jobs(Some("not-a-number"), 8), 1);
        // A zero CPU count cannot come from available_parallelism, but the cap
        // must still leave one job rather than ask cmake for zero.
        assert_eq!(dynamorio_build_jobs(Some("8"), 0), 1);
    }

    #[test]
    fn oversubscribed_request_no_longer_inflates_the_ratchet() {
        // A 16-job request on a 4-vCPU runner does the same CPU work as the
        // 71.49s 4-job baseline. Counted as 16 jobs that would be about 1144
        // job-seconds and fail; capped at the 4 CPUs it is the baseline again.
        let jobs = dynamorio_build_jobs(Some("16"), 4);
        assert_eq!(jobs, 4);
        enforce_ci_build_ratchet(71.49, jobs);
    }
}
