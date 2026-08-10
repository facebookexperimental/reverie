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
// GitHub-hosted runner. Their elapsed-seconds * requested-jobs proxies were
// 222.56, 232.64, and 285.96 job-seconds. The CI ratchet is 2x the slowest
// observation, rounded up; local source installs report without enforcing it.
const CI_MAX_BUILD_JOB_SECONDS: f64 = 572.0;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/dynamorio");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
    println!("cargo:rerun-if-env-changed=CI");
    println!("cargo:rerun-if-env-changed=REVERIE_DBT_MAX_BUILD_SECONDS");

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
    let source_key = source_recipe_key(
        &source_dir,
        &manifest_dir.join("build.rs"),
        &cmake,
        generator.as_deref(),
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
        if let Err(error) = fs::remove_dir_all(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "reverie-dbt: failed to remove staging directory {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

fn source_recipe_key(
    source_dir: &Path,
    build_script: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
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

fn build_dynamorio(
    source_dir: &Path,
    build_dir: &Path,
    install_dir: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
) {
    let started = Instant::now();
    let mut configure = Command::new(cmake);
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
    run(&mut configure, "configure DynamoRIO");

    let mut build = Command::new(cmake);
    build.arg("--build").arg(build_dir).args([
        "--config",
        "Release",
        "--target",
        "install",
        "--parallel",
    ]);
    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PARALLEL_JOBS);
    build.arg(jobs.to_string());
    run(&mut build, "build and install DynamoRIO");

    let seconds = started.elapsed().as_secs_f64();
    println!("cargo:warning=DynamoRIO source build completed in {seconds:.2}s (jobs={jobs})");
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
        let initial = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_eq!(
            initial,
            source_recipe_key(&source, &recipe, "cmake".as_ref(), None)
        );

        fs::write(source.join("nested/input.c"), "second\n").unwrap();
        let source_changed = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_ne!(initial, source_changed);

        fs::write(&recipe, "recipe two\n").unwrap();
        let recipe_changed = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_ne!(source_changed, recipe_changed);

        let cmake_changed = source_recipe_key(&source, &recipe, "custom-cmake".as_ref(), None);
        assert_ne!(recipe_changed, cmake_changed);

        let generator_changed = source_recipe_key(
            &source,
            &recipe,
            "custom-cmake".as_ref(),
            Some("Ninja".as_ref()),
        );
        assert_ne!(cmake_changed, generator_changed);
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
}
