/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Real private-loader controls: direct RUNPATH dependencies and existing precedence.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs::File;
use std::fs::{self};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;

const LEAF: &str = "libdrsearch_leaf_20260917.so";
const PARENT: &str = "libdrsearch_parent_20260917.so";
const OTHER_LEAF: &str = "libdrsearch_other_leaf_20260917.so";
const OTHER_PARENT: &str = "libdrsearch_other_parent_20260917.so";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Case {
    Direct,
    Environment,
    ClientDirectory,
    Missing,
    IndirectOnly,
    Rpath,
    OrderedRunpath,
    NoPromotion,
    Origin,
    ExplicitPath,
}

fn checked(command: &mut Command) -> String {
    let output = command.output().expect("execute fixture compiler/readelf");
    assert!(output.status.success(), "{command:?}: {output:?}");
    String::from_utf8(output.stdout).expect("tool output is UTF-8")
}

fn dynamic(path: &Path, needed: &[&str], tag: Option<&str>) {
    let text = checked(
        Command::new("readelf")
            .env("LC_ALL", "C")
            .arg("-d")
            .arg(path),
    );
    let actual: Vec<_> = text
        .lines()
        .filter_map(|line| {
            line.split_once("(NEEDED)").and_then(|(_, tail)| {
                tail.split_once('[')
                    .and_then(|(_, value)| value.split_once(']'))
                    .map(|(value, _)| value)
            })
        })
        .collect();
    assert_eq!(actual, needed, "{path:?}: {text}");
    assert_eq!(text.contains("(RUNPATH)"), tag == Some("RUNPATH"), "{text}");
    assert_eq!(text.contains("(RPATH)"), tag == Some("RPATH"), "{text}");
}

struct Fixture {
    temp: tempfile::TempDir,
    sources: PathBuf,
    drrun: PathBuf,
    compiler: std::ffi::OsString,
}

impl Fixture {
    fn new() -> Self {
        for name in std::env::vars_os().map(|(name, _)| name) {
            let name = name.to_string_lossy();
            assert!(
                // Cargo sets LD_LIBRARY_PATH for libtest. execute() replaces it
                // explicitly for each child; other loader overrides are not replaced.
                (!name.starts_with("LD_") || name == "LD_LIBRARY_PATH")
                    && !name.starts_with("DYNAMORIO_"),
                "inherited loader override would invalidate fixture: {name}"
            );
        }
        Self {
            temp: tempfile::tempdir().expect("private loader fixture directory"),
            sources: Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/private_loader_search"),
            drrun: reverie_dbt::bundled_drrun_path().to_owned(),
            compiler: std::env::var_os("CC").unwrap_or_else(|| "cc".into()),
        }
    }

    fn cc(&self, source: &str, output: &Path) -> Command {
        let mut command = Command::new(&self.compiler);
        command
            .args(["-fPIC", "-shared", "-nostdlib", "-fno-stack-protector"])
            .arg(self.sources.join(source))
            .arg("-o")
            .arg(output);
        command
    }

    fn leaf(&self, directory: &Path, value: u32, other: bool) -> PathBuf {
        let soname = if other { OTHER_LEAF } else { LEAF };
        let output = directory.join(soname);
        let mut command = self.cc("leaf.c", &output);
        command
            .arg(format!("-DLEAF_VALUE={value}"))
            .arg(format!("-Wl,-soname,{soname}"));
        if other {
            command.arg("-Dleaf_value=other_leaf_value");
        }
        checked(&mut command);
        dynamic(&output, &[], None);
        output
    }

    fn parent(&self, directory: &Path, value: u32, leaf: &Path, other: bool) -> PathBuf {
        let soname = if other { OTHER_PARENT } else { PARENT };
        let output = directory.join(soname);
        let mut command = self.cc("parent.c", &output);
        command
            .arg(format!("-DPARENT_VALUE={value}"))
            .arg(format!("-Wl,-soname,{soname}"))
            .arg("-Wl,--no-as-needed")
            .arg(leaf);
        if other {
            command.args([
                "-Dleaf_value=other_leaf_value",
                "-Dparent_value=other_parent_value",
            ]);
        }
        checked(&mut command);
        dynamic(&output, &[if other { OTHER_LEAF } else { LEAF }], None);
        output
    }

    fn execute(&self, label: &str, argv: &[&Path], environment: &Path) -> (ExitStatus, Vec<u8>) {
        let config = self.temp.path().join(format!("config-{label}"));
        fs::create_dir(&config).unwrap();
        let stdout = self.temp.path().join(format!("{label}.stdout"));
        let stderr = self.temp.path().join(format!("{label}.stderr"));
        let mut command = Command::new("timeout");
        command
            .args(["--signal=TERM", "--kill-after=2s", "10s"])
            .args(argv)
            .current_dir(self.temp.path())
            .env("LD_LIBRARY_PATH", environment)
            .env("DYNAMORIO_CONFIGDIR", config)
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap());
        // timeout owns the fresh command process group. File capture is bounded
        // independently of the ten-second timeout, including a noisy loader error.
        unsafe {
            command.pre_exec(|| {
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                let capture = libc::rlimit {
                    rlim_cur: 1 << 20,
                    rlim_max: 1 << 20,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
                    || libc::setrlimit(libc::RLIMIT_FSIZE, &capture) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let status = command.status().expect("run bounded native/DR fixture");
        let mut output = fs::read(stdout).unwrap();
        let error = fs::read(stderr).unwrap();
        assert!(
            output.len() < 1 << 20 && error.len() < 1 << 20,
            "capture overflow"
        );
        output.extend(error);
        assert!(
            !matches!(status.code(), Some(124 | 137 | 143 | 153)),
            "timeout/forced termination/output limit: {status}; {}",
            String::from_utf8_lossy(&output)
        );
        (status, output)
    }

    fn explicit_path(&self) {
        // The file exists beneath RUNPATH, but DT_NEEDED names a relative
        // pathname. Neither the native loader nor our new fallback may search it.
        let root = self.temp.path();
        let ld = root.join("ld");
        let paths = root.join("paths");
        fs::create_dir(&ld).unwrap();
        fs::create_dir_all(paths.join("needed")).unwrap();
        let relative = format!("needed/{LEAF}");
        let leaf = paths.join(&relative);
        checked(
            self.cc("leaf.c", &leaf)
                .arg(format!("-Wl,-soname,{relative}")),
        );
        dynamic(&leaf, &[], None);
        let parent = ld.join(PARENT);
        checked(
            self.cc("parent.c", &parent)
                .arg(format!("-Wl,-soname,{PARENT}"))
                .arg("-Wl,--no-as-needed")
                .arg(&leaf),
        );
        dynamic(&parent, &[&relative], None);
        let client = root.join("client.so");
        let install = self.drrun.parent().unwrap().parent().unwrap();
        checked(
            self.cc("client.c", &client)
                .args(["-DLINUX", "-DX86_64"])
                .arg("-I")
                .arg(install.join("include"))
                .arg("-Wl,--no-as-needed")
                .arg(&parent)
                .arg(&leaf)
                .arg("-Wl,--enable-new-dtags")
                .arg(format!("-Wl,-rpath,{}", paths.display())),
        );
        dynamic(&client, &[PARENT, &relative], Some("RUNPATH"));
        let app = root.join("app");
        checked(
            Command::new(&self.compiler)
                .args(["-static", "-nostdlib", "-nostartfiles", "-Wl,-e,_start"])
                .arg(self.sources.join("app.S"))
                .arg("-o")
                .arg(&app),
        );
        let native = root.join("native");
        checked(
            Command::new(&self.compiler)
                .arg(self.sources.join("native.c"))
                .arg("-ldl")
                .arg("-o")
                .arg(&native),
        );
        let (status, output) = self.execute("native", &[&native, &client], &ld);
        assert_result(
            "native",
            Case::ExplicitPath,
            status,
            &output,
            None,
            &relative,
        );
        let (status, output) = self.execute(
            "dr",
            &[
                &self.drrun,
                Path::new("-quiet"),
                Path::new("-c"),
                &client,
                Path::new("--"),
                &app,
            ],
            &ld,
        );
        assert_result("DR", Case::ExplicitPath, status, &output, None, &relative);
    }

    fn check(&self, case: Case) {
        let root = self.temp.path();
        let dirs: Vec<_> = ["client", "ld", "runpath", "second", "link-inputs"]
            .map(|n| root.join(n))
            .into();
        for directory in &dirs {
            fs::create_dir(directory).unwrap();
        }
        let (client_dir, ld, runpath, second, link) =
            (&dirs[0], &dirs[1], &dirs[2], &dirs[3], &dirs[4]);
        let leaf = self.leaf(link, 7, false);
        let parent = self.parent(link, 100, &leaf, false);
        if case != Case::Missing {
            self.leaf(runpath, 7, false);
        }
        let conflicting = matches!(
            case,
            Case::Environment | Case::ClientDirectory | Case::Rpath
        );
        self.parent(ld, if conflicting { 200 } else { 100 }, &leaf, false);
        if conflicting {
            self.leaf(ld, 11, false);
        }
        if matches!(case, Case::Environment | Case::Rpath) {
            self.parent(runpath, 100, &leaf, false);
        }
        if case == Case::ClientDirectory {
            self.parent(client_dir, 100, &leaf, false);
        }
        let client = client_dir.join("client.so");
        let mut cc = self.cc("client.c", &client);
        let install = self.drrun.parent().unwrap().parent().unwrap();
        cc.args(["-DLINUX", "-DX86_64"])
            .arg("-I")
            .arg(install.join("include"));
        if case == Case::IndirectOnly {
            cc.arg("-DINDIRECT_ONLY");
        }
        cc.arg("-Wl,--no-as-needed").arg(parent);
        let mut needed = vec![PARENT];
        if case != Case::IndirectOnly {
            cc.arg(&leaf);
            needed.push(LEAF);
        }
        if case == Case::NoPromotion {
            let other_leaf = self.leaf(runpath, 19, true);
            let other_parent = self.parent(ld, 300, &other_leaf, true);
            cc.arg(other_parent);
            needed.push(OTHER_PARENT);
        }
        let path = if case == Case::Origin {
            "$ORIGIN/../runpath".to_owned()
        } else if case == Case::OrderedRunpath {
            self.leaf(second, 13, false);
            format!("{}:{}", runpath.display(), second.display())
        } else {
            runpath.display().to_string()
        };
        cc.arg(if case == Case::Rpath {
            "-Wl,--disable-new-dtags"
        } else {
            "-Wl,--enable-new-dtags"
        })
        .arg(format!("-Wl,-rpath,{path}"));
        checked(&mut cc);
        dynamic(
            &client,
            &needed,
            Some(if case == Case::Rpath {
                "RPATH"
            } else {
                "RUNPATH"
            }),
        );
        let app = root.join("app");
        checked(
            Command::new(&self.compiler)
                .args(["-static", "-nostdlib", "-nostartfiles", "-Wl,-e,_start"])
                .arg(self.sources.join("app.S"))
                .arg("-o")
                .arg(&app),
        );
        let native = root.join("native");
        checked(
            Command::new(&self.compiler)
                .arg(self.sources.join("native.c"))
                .arg("-ldl")
                .arg("-o")
                .arg(&native),
        );
        let expected = match case {
            Case::Environment => Some(211011),
            Case::ClientDirectory => Some(111011),
            Case::Missing | Case::IndirectOnly | Case::NoPromotion => None,
            _ => Some(107007),
        };
        let missing = if case == Case::NoPromotion {
            OTHER_LEAF
        } else {
            LEAF
        };
        if case != Case::ClientDirectory {
            let (status, output) = self.execute("native", &[&native, &client], ld);
            assert_result("native", case, status, &output, expected, missing);
        }
        let (status, output) = self.execute(
            "dr",
            &[
                &self.drrun,
                Path::new("-quiet"),
                Path::new("-c"),
                &client,
                Path::new("--"),
                &app,
            ],
            ld,
        );
        assert_result("DR", case, status, &output, expected, missing);
    }
}

fn assert_result(
    engine: &str,
    case: Case,
    status: ExitStatus,
    output: &[u8],
    expected: Option<u32>,
    missing: &str,
) {
    let text = String::from_utf8_lossy(output);
    let markers: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("LOADER_VALUE="))
        .collect();
    if let Some(value) = expected {
        assert!(status.success(), "{engine} {case:?}: {status}: {text}");
        assert_eq!(
            markers,
            [format!("LOADER_VALUE={value:06}")],
            "{engine} {case:?}: {text}"
        );
    } else {
        assert_eq!(
            status.code(),
            Some(if engine == "native" { 1 } else { 255 }),
            "{engine} {case:?} must retain the loader failure status: {text}"
        );
        assert!(
            markers.is_empty() && text.contains(missing),
            "{engine} {case:?}: {status}: {text}"
        );
    }
}

#[test]
fn later_direct_dependency_uses_client_runpath() {
    Fixture::new().check(Case::Direct);
}
#[test]
fn environment_keeps_existing_search_precedence() {
    Fixture::new().check(Case::Environment);
}
#[test]
fn client_directory_keeps_existing_search_precedence() {
    Fixture::new().check(Case::ClientDirectory);
}
#[test]
fn missing_direct_dependency_still_fails() {
    Fixture::new().check(Case::Missing);
}
#[test]
fn runpath_does_not_supply_indirect_only_dependency() {
    Fixture::new().check(Case::IndirectOnly);
}
#[test]
fn legacy_rpath_keeps_existing_search_precedence() {
    Fixture::new().check(Case::Rpath);
}
#[test]
fn fallback_keeps_ordered_runpath_selection() {
    Fixture::new().check(Case::OrderedRunpath);
}
#[test]
fn fallback_does_not_promote_unrelated_indirect_path() {
    Fixture::new().check(Case::NoPromotion);
}
#[test]
fn fallback_expands_origin_from_client_directory() {
    Fixture::new().check(Case::Origin);
}

#[test]
fn fallback_does_not_search_explicit_relative_dependency() {
    Fixture::new().explicit_path();
}
