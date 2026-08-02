/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#53): validate the pinned dr_invoke_syscall_as_app mmap fix.
const DYNAMORIO_REVISION: &str = "929840ad9190e5086775e8debc0f0b79b4208d59";
const DYNAMORIO_URL: &str = "https://github.com/rrnewton/dynamorio.git";
const DYNAMORIO_SUBMODULE_PATH: &str = "third-party/dynamorio";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../third-party/dynamorio/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../third-party/dynamorio/.git");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source_dir = manifest_dir.join("../third-party/dynamorio");
    ensure_dynamorio_source(&source_dir);
    verify_revision(&source_dir);

    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let build_dir = out_dir.join("dynamorio-build");
    let install_dir = out_dir.join("dynamorio-install");
    let revision_stamp = out_dir.join("dynamorio-revision");
    let drrun = install_dir.join("bin64/drrun");
    let cmake_config = install_dir.join("cmake/DynamoRIOConfig.cmake");

    let installed_revision = fs::read_to_string(&revision_stamp).unwrap_or_default();
    if installed_revision.trim() != DYNAMORIO_REVISION
        || !drrun.is_file()
        || !cmake_config.is_file()
    {
        build_dynamorio(&source_dir, &build_dir, &install_dir);
        fs::write(&revision_stamp, format!("{DYNAMORIO_REVISION}\n"))
            .expect("failed to write the DynamoRIO revision stamp");
    }

    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_HOME={}",
        install_dir.display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_CMAKE={}",
        install_dir.join("cmake").display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_DRRUN={}",
        drrun.display()
    );
}

/// Materialize the pinned DynamoRIO source tree that lives beside `reverie-dbi`.
///
/// `make validate` (and cargo in general) builds `reverie-dbi` in several
/// profiles concurrently, and every one of those builds shares a *single* git
/// dependency checkout under `~/.cargo/git/checkouts/`. DynamoRIO is a git
/// submodule that cargo does not reliably materialize for a git dependency, so
/// this build script checks it out itself. Doing that naively races: one build
/// runs `git submodule update`, which writes `CMakeLists.txt` early in the
/// checkout, and a second build sees that file, assumes the tree is complete,
/// and runs cmake against a half-populated source tree. That fails with
/// "No such file or directory" for core sources such as `arch_exports.h`,
/// `dispatch.h`, and `unix/memcache.c` — the historical `build.rs:163` panic.
///
/// To make a cold build robust we (a) serialize population with an exclusive
/// advisory file lock so only one build mutates the shared checkout at a time,
/// and (b) treat the tree as ready only when it is *complete*, not merely when
/// `CMakeLists.txt` exists.
fn ensure_dynamorio_source(source_dir: &Path) {
    let reverie_root = source_dir
        .parent()
        .and_then(Path::parent)
        .expect("DynamoRIO source is not inside the Reverie repository");

    // Serialize population across the concurrent `reverie-dbi` builds that share
    // this cargo git-dependency checkout. The lock is released when `_lock` is
    // dropped or the process exits.
    let _lock = SourceLock::acquire(source_dir);

    // Check under the lock: another build may be populating this shared tree,
    // and readiness includes a clean tracked worktree.
    if source_dir_is_complete(source_dir) {
        return;
    }

    populate_dynamorio_source(reverie_root, source_dir);

    assert!(
        source_dir_is_complete(source_dir),
        "DynamoRIO source at {} is still incomplete after initialization",
        source_dir.display()
    );
}

/// A DynamoRIO source tree is only usable once *every* tracked file is present.
/// A partially checked-out submodule still has `CMakeLists.txt` (git writes the
/// working tree roughly in path order) yet is missing core sources, so checking
/// for `CMakeLists.txt` alone is not enough. We verify completeness with a
/// couple of deep sentinel files and by requiring git to report a clean tracked
/// worktree. Inspection failures are incomplete rather than an excuse to trust
/// the sentinels.
fn source_dir_is_complete(source_dir: &Path) -> bool {
    if !source_dir.join("CMakeLists.txt").is_file() {
        return false;
    }
    // Deep files whose absence produced the historical partial-checkout panics.
    for sentinel in ["core/lib/globals_shared.h", "core/unix/memcache.c"] {
        if !source_dir.join(sentinel).is_file() {
            return false;
        }
    }
    if !source_dir.join(".git").exists() {
        return false;
    }
    // No tracked file may differ from HEAD. Ignore untracked build output.
    match Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .args(["status", "--porcelain=v1", "--untracked-files=no"])
        .output()
    {
        Ok(output) if output.status.success() => output.stdout.is_empty(),
        _ => false,
    }
}

/// Check out the pinned DynamoRIO submodule, honoring the checkout-by-default
/// policy even on long-lived checkouts whose local `.git/config` still records
/// the retired `update = none` for this submodule. `submodule sync` refreshes
/// the recorded URL, and the explicit `-c submodule.<path>.update=checkout`
/// plus `--checkout --force` override any stale local policy. If the submodule
/// machinery is unavailable (for example cargo pruned the git metadata), fall
/// back to fetching the pinned revision directly by URL + SHA.
fn populate_dynamorio_source(reverie_root: &Path, source_dir: &Path) {
    // Refresh the recorded submodule URL, ignoring failure on an odd checkout.
    let _ = Command::new("git")
        .arg("-C")
        .arg(reverie_root)
        .args(["submodule", "sync", "--", DYNAMORIO_SUBMODULE_PATH])
        .status();

    let update_policy = format!("submodule.{DYNAMORIO_SUBMODULE_PATH}.update=checkout");
    let submodule_ok = Command::new("git")
        .arg("-C")
        .arg(reverie_root)
        .args([
            "-c",
            &update_policy,
            "submodule",
            "update",
            "--init",
            "--recursive",
            "--checkout",
            "--force",
            "--",
            DYNAMORIO_SUBMODULE_PATH,
        ])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);

    if submodule_ok && source_dir_is_complete(source_dir) {
        return;
    }

    // Fallback: fetch the exact pinned revision directly into the source tree.
    clone_dynamorio_by_revision(source_dir);
}

/// Last-resort population when the submodule is not wired up in the checkout:
/// initialize a repository in place (idempotent on an existing one), fetch the
/// pinned revision from the fork by URL, and force-check-out every tracked file.
fn clone_dynamorio_by_revision(source_dir: &Path) {
    fs::create_dir_all(source_dir).unwrap_or_else(|error| {
        panic!(
            "failed to create the DynamoRIO source directory {}: {error}",
            source_dir.display()
        )
    });
    if !source_dir.join(".git").exists() {
        run(
            Command::new("git")
                .arg("-C")
                .arg(source_dir)
                .args(["init", "-q"]),
            "initialize a DynamoRIO source checkout",
        );
    }
    run(
        Command::new("git").arg("-C").arg(source_dir).args([
            "fetch",
            "--depth",
            "1",
            DYNAMORIO_URL,
            DYNAMORIO_REVISION,
        ]),
        "fetch the pinned DynamoRIO revision",
    );
    run(
        Command::new("git").arg("-C").arg(source_dir).args([
            "checkout",
            "--force",
            DYNAMORIO_REVISION,
        ]),
        "check out the pinned DynamoRIO revision",
    );
    // Ensure every tracked file is materialized, repairing a partial tree.
    run(
        Command::new("git")
            .arg("-C")
            .arg(source_dir)
            .args(["checkout", "--force", "--", "."]),
        "restore the pinned DynamoRIO working tree",
    );
}

/// An exclusive advisory lock guarding population of the shared DynamoRIO
/// source checkout. Held via `flock(2)` on a lock file beside the source tree;
/// released automatically when dropped or when the build script exits.
struct SourceLock {
    _file: fs::File,
}

impl SourceLock {
    fn acquire(source_dir: &Path) -> SourceLock {
        let lock_path = source_dir
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(".dynamorio-source.lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap_or_else(|error| {
                panic!(
                    "failed to open the DynamoRIO source lock {}: {error}",
                    lock_path.display()
                )
            });
        // Block until we hold the exclusive lock.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            panic!(
                "failed to lock the DynamoRIO source: {}",
                std::io::Error::last_os_error()
            );
        }
        SourceLock { _file: file }
    }
}

fn verify_revision(source_dir: &Path) {
    let output = Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("failed to query the DynamoRIO submodule revision");
    if !output.status.success() {
        panic!(
            "failed to query the DynamoRIO submodule revision: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let actual = String::from_utf8(output.stdout)
        .expect("DynamoRIO revision is not UTF-8")
        .trim()
        .to_string();
    assert_eq!(
        actual, DYNAMORIO_REVISION,
        "DynamoRIO submodule is not at the tested revision"
    );
}

fn build_dynamorio(source_dir: &Path, build_dir: &Path, install_dir: &Path) {
    let cmake = env::var_os("CMAKE").unwrap_or_else(|| OsString::from("cmake"));
    let mut configure = Command::new(&cmake);
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
            "-DBUILD_CLIENTS=ON",
            "-DBUILD_EXT=ON",
            "-DBUILD_TOOLS=ON",
        ]);
    if let Some(generator) = env::var_os("CMAKE_GENERATOR") {
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
    if let Some(jobs) = env::var_os("NUM_JOBS") {
        build.arg(jobs);
    }
    run(&mut build, "build and install DynamoRIO");
}

fn run(command: &mut Command, description: &str) {
    eprintln!("reverie-dbi: {description}: {command:?}");
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

    fn write_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed with {status}");
    }

    fn complete_source_repo() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        git(root, &["init", "-q"]);
        write_file(root, "CMakeLists.txt", "project(DynamoRIO)\n");
        write_file(root, "core/lib/globals_shared.h", "/* sentinel */\n");
        write_file(root, "core/unix/memcache.c", "/* sentinel */\n");
        write_file(root, "core/extra.c", "/* tracked */\n");
        git(root, &["add", "."]);
        git(
            root,
            &[
                "-c",
                "user.name=Reverie Test",
                "-c",
                "user.email=reverie-test@example.com",
                "commit",
                "-q",
                "-m",
                "fixture",
            ],
        );
        temp
    }

    #[test]
    fn complete_clean_source_is_accepted() {
        let source = complete_source_repo();
        assert!(source_dir_is_complete(source.path()));
    }

    #[test]
    fn modified_tracked_source_is_rejected() {
        let source = complete_source_repo();
        write_file(source.path(), "core/extra.c", "/* modified */\n");
        assert!(!source_dir_is_complete(source.path()));
    }

    #[test]
    fn deleted_tracked_source_is_rejected() {
        let source = complete_source_repo();
        fs::remove_file(source.path().join("core/extra.c")).unwrap();
        assert!(!source_dir_is_complete(source.path()));
    }

    #[test]
    fn git_inspection_failure_is_rejected() {
        let source = tempfile::tempdir().unwrap();
        write_file(source.path(), "CMakeLists.txt", "project(DynamoRIO)\n");
        write_file(
            source.path(),
            "core/lib/globals_shared.h",
            "/* sentinel */\n",
        );
        write_file(source.path(), "core/unix/memcache.c", "/* sentinel */\n");
        fs::create_dir(source.path().join(".git")).unwrap();
        assert!(!source_dir_is_complete(source.path()));
    }
}
