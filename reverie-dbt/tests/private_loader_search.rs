/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style LICENSE in the root directory.
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
        // The pinned root's compiler wrapper otherwise adds RUNPATH entries for
        // link-input directories, changing the exact search contract under test.
        // Ordinary compilers ignore these wrapper-specific environment settings.
        command
            .env("NIX_DONT_SET_RPATH", "1")
            .env("NIX_DONT_SET_RPATH_FOR_TARGET", "1")
            .env("NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu", "1")
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
        self.execute_with_layout(label, argv, environment, false)
    }

    fn execute_with_layout(
        &self,
        label: &str,
        argv: &[&Path],
        environment: &Path,
        fixed_layout: bool,
    ) -> (ExitStatus, Vec<u8>) {
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
            command.pre_exec(move || {
                if fixed_layout {
                    // Same pre-exec ASLR policy as the production DBT launcher.
                    // Refuse when unavailable; random layouts cannot test this invariant.
                    let current = libc::personality(0xffff_ffff);
                    if current == -1
                        || libc::personality(
                            current as libc::c_ulong | libc::ADDR_NO_RANDOMIZE as libc::c_ulong,
                        ) == -1
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                }
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

// These are functional working-set variants, not a fixed padding budget. Each
// DSO reads every initialized table word and writes/reads every BSS workspace word.
const FOOTPRINT_RUNTIME: &str = "libdrfootprint_runtime.so";
const SMALL_WORK_ITEMS: u64 = 256;
const LARGE_WORK_ITEMS: u64 = 8192;
const FOOTPRINT_TABLE_WORD: u64 = 0x9e37_79b9_7f4a_7c15;

#[derive(Clone, Copy, Debug)]
struct FootprintImage {
    span: u64,
    file_bytes: u64,
}

fn footprint_image(path: &Path) -> FootprintImage {
    let text = checked(
        Command::new("readelf")
            .env("LC_ALL", "C")
            .args(["-W", "-l"])
            .arg(path),
    );
    let mut first = u64::MAX;
    let mut end = 0;
    let mut file_bytes = 0_u64;
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        if words.first() != Some(&"LOAD") {
            continue;
        }
        assert!(words.len() >= 8, "{path:?}: {line}");
        let hex = |word: &str| u64::from_str_radix(word.trim_start_matches("0x"), 16).unwrap();
        let offset = hex(words[1]);
        let address = hex(words[2]);
        let file_size = hex(words[4]);
        let memory_size = hex(words[5]);
        assert!(file_size <= memory_size, "{path:?}: {line}");
        if address == 0 {
            assert_eq!(offset, 0, "reported __ehdr_start must be the image base");
        }
        first = first.min(address & !4095);
        end = end.max(
            address
                .checked_add(memory_size)
                .unwrap()
                .checked_add(4095)
                .unwrap()
                & !4095,
        );
        file_bytes = file_bytes.checked_add(file_size).unwrap();
    }
    assert_eq!(first, 0, "fixture must have a zero-based PT_LOAD: {text}");
    assert!(end > 0 && file_bytes > 0, "{text}");
    FootprintImage {
        span: end,
        file_bytes,
    }
}

fn footprint_field(line: &str, name: &str) -> u64 {
    let prefix = format!("{name}=0x");
    let values: Vec<_> = line
        .split_whitespace()
        .filter_map(|word| word.strip_prefix(&prefix))
        .collect();
    assert_eq!(values.len(), 1, "{name}: {line}");
    u64::from_str_radix(values[0], 16).unwrap()
}

fn footprint_checksum(items: u64, seed: u64) -> u64 {
    (0..items).fold(0_u64, |sum, index| {
        sum.wrapping_add(FOOTPRINT_TABLE_WORD.wrapping_add(seed).wrapping_add(index))
    })
}

#[derive(Debug)]
struct FootprintObservation {
    label: &'static str,
    client: FootprintImage,
    runtime: FootprintImage,
    client_base: u64,
    runtime_base: u64,
    guest_mmap: u64,
}

#[test]
fn client_and_runtime_footprints_preserve_guest_null_mmap() {
    footprint_variants(false);
}

#[test]
fn environment_runtime_footprints_preserve_guest_null_mmap() {
    footprint_variants(true);
}

fn maps_snapshot(stdout: &[u8]) -> &[u8] {
    const PREFIX: &[u8] = b"MAPS_BEGIN bytes=0x";
    const END: &[u8] = b"MAPS_END\n";
    let header = PREFIX.len() + 17;
    assert!(stdout.starts_with(PREFIX) && stdout.len() >= header);
    assert_eq!(stdout[header - 1], b'\n');
    let count = std::str::from_utf8(&stdout[PREFIX.len()..header - 1]).unwrap();
    assert!(count.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let count = usize::from_str_radix(count, 16).unwrap();
    assert!(
        count > 0 && count < (1 << 20) - 1,
        "empty/full maps snapshot"
    );
    let end = header.checked_add(count).unwrap();
    assert_eq!(stdout.get(end..), Some(END), "truncated/extra maps output");
    let maps = &stdout[header..end];
    assert_eq!(maps.last(), Some(&b'\n'));
    assert!(!maps.contains(&0));
    maps
}

fn footprint_variants(environment_search: bool) {
    let fixture = Fixture::new();
    let root = fixture.temp.path();
    let app = root.join("footprint-app");
    // Compile the guest exactly once. All three variants execute these same bytes.
    checked(
        Command::new(&fixture.compiler)
            .args(["-static", "-nostdlib", "-nostartfiles", "-Wl,-e,_start"])
            .arg(fixture.sources.join("footprint_app.S"))
            .arg("-o")
            .arg(&app),
    );
    let maps_app = root.join("maps-app");
    checked(
        Command::new(&fixture.compiler)
            .args(["-static", "-nostdlib", "-nostartfiles", "-Wl,-e,_start"])
            .arg(fixture.sources.join("maps_app.S"))
            .arg("-o")
            .arg(&maps_app),
    );
    let empty_search = root.join("empty-search");
    fs::create_dir(&empty_search).unwrap();
    // Optional retained evidence for the bounded external mapping trace. This
    // changes no guest arguments or assertions and refuses to replace old data.
    let artifacts = std::env::var_os("REVERIE_DBT_PRIVATE_LOADER_ARTIFACTS").map(|root| {
        let root = PathBuf::from(root);
        fs::create_dir_all(&root).unwrap();
        root.join(if environment_search {
            "environment"
        } else {
            "rpath"
        })
    });
    if let Some(directory) = &artifacts {
        fs::create_dir(directory).expect("fresh private-loader artifact directory");
        for (name, file) in [("footprint-app", &app), ("maps-app", &maps_app)] {
            fs::copy(file, directory.join(name)).unwrap();
            fs::write(
                directory.join(format!("{name}.phdrs")),
                checked(Command::new("readelf").args(["-W", "-l"]).arg(file)),
            )
            .unwrap();
        }
    }
    let install = fixture.drrun.parent().unwrap().parent().unwrap();
    let mut observations = Vec::new();
    for (label, client_items, runtime_items) in [
        ("ss", SMALL_WORK_ITEMS, SMALL_WORK_ITEMS),
        ("ls", LARGE_WORK_ITEMS, SMALL_WORK_ITEMS),
        ("sl", SMALL_WORK_ITEMS, LARGE_WORK_ITEMS),
    ] {
        // Equal-length paths avoid introducing an argv/environment length change.
        let directory = root.join(label);
        fs::create_dir(&directory).unwrap();
        let runtime = directory.join(FOOTPRINT_RUNTIME);
        checked(
            fixture
                .cc("footprint.c", &runtime)
                .arg(format!("-DFOOTPRINT_ITEMS={runtime_items}"))
                .arg(format!("-Wl,-soname,{FOOTPRINT_RUNTIME}")),
        );
        dynamic(&runtime, &[], None);
        let client = directory.join("client.so");
        let mut client_command = fixture.cc("footprint.c", &client);
        client_command
            .args(["-DFOOTPRINT_CLIENT=1", "-DLINUX", "-DX86_64"])
            .arg(format!("-DFOOTPRINT_ITEMS={client_items}"))
            .arg("-I")
            .arg(install.join("include"))
            .arg("-Wl,--no-as-needed")
            .arg(&runtime);
        if !environment_search {
            client_command.args(["-Wl,--disable-new-dtags", "-Wl,-rpath,$ORIGIN"]);
        }
        checked(&mut client_command);
        dynamic(
            &client,
            &[FOOTPRINT_RUNTIME],
            if environment_search {
                None
            } else {
                Some("RPATH")
            },
        );
        let client_image = footprint_image(&client);
        let runtime_image = footprint_image(&runtime);
        if let Some(artifacts) = &artifacts {
            let destination = artifacts.join(label);
            fs::create_dir(&destination).unwrap();
            fs::copy(&client, destination.join("client.so")).unwrap();
            fs::copy(&runtime, destination.join(FOOTPRINT_RUNTIME)).unwrap();
            for (name, file) in [("client.phdrs", &client), ("runtime.phdrs", &runtime)] {
                fs::write(
                    destination.join(name),
                    checked(Command::new("readelf").args(["-W", "-l"]).arg(file)),
                )
                .unwrap();
            }
        }
        let mut argv = [
            &fixture.drrun,
            Path::new("-quiet"),
            Path::new("-disable_rseq"),
            Path::new("-vm_max_offset"),
            Path::new("0x0"),
            Path::new("-vm_base"),
            Path::new("0x40000000"),
            Path::new("-vm_size"),
            Path::new("64M"),
            Path::new("-no_vm_base_near_app"),
            Path::new("-no_vm_allow_not_at_base"),
            Path::new("-no_vm_allow_smaller"),
            Path::new("-c"),
            &client,
            Path::new("--"),
            &app,
        ];
        let search_path = if environment_search {
            &directory
        } else {
            &empty_search
        };
        let (status, output) = fixture.execute_with_layout(label, &argv, search_path, true);
        let text = String::from_utf8(output).unwrap();
        if let Some(artifacts) = &artifacts {
            fs::write(artifacts.join(label).join("output.txt"), &text).unwrap();
        }
        assert!(status.success(), "{label}: {status}: {text}");
        let markers: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("FOOTPRINT "))
            .collect();
        assert_eq!(markers.len(), 1, "{label}: {text}");
        let marker = markers[0];
        assert_eq!(footprint_field(marker, "client_items"), client_items);
        assert_eq!(footprint_field(marker, "runtime_items"), runtime_items);
        assert_eq!(
            footprint_field(marker, "client_sum"),
            footprint_checksum(client_items, 17)
        );
        assert_eq!(
            footprint_field(marker, "runtime_sum"),
            footprint_checksum(runtime_items, 31)
        );
        let mappings: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("MMAP=0x"))
            .collect();
        assert_eq!(mappings.len(), 1, "{label}: {text}");
        assert_eq!(mappings[0].len(), "MMAP=0x".len() + 16, "{text}");
        // Observe a separate, identical static guest at its first application
        // syscall. Keep every maps byte; external mapping traces establish the
        // actual arena bounds and coherence of the open/read/close interval.
        argv[argv.len() - 1] = &maps_app;
        let snapshot_label = format!("maps-{label}");
        let (snapshot_status, snapshot_output) =
            fixture.execute_with_layout(&snapshot_label, &argv, search_path, true);
        let snapshot_stdout = fs::read(root.join(format!("{snapshot_label}.stdout"))).unwrap();
        let snapshot_stderr = fs::read(root.join(format!("{snapshot_label}.stderr"))).unwrap();
        if let Some(artifacts) = &artifacts {
            let destination = artifacts.join(label);
            fs::write(destination.join("maps.stdout"), &snapshot_stdout).unwrap();
            fs::write(destination.join("maps.stderr"), &snapshot_stderr).unwrap();
            fs::write(destination.join("maps.status"), snapshot_status.to_string()).unwrap();
        }
        assert!(
            snapshot_status.success(),
            "{label}: {snapshot_status}: {}",
            String::from_utf8_lossy(&snapshot_output)
        );
        let snapshot_text = std::str::from_utf8(&snapshot_stderr).unwrap();
        assert_eq!(
            snapshot_text
                .lines()
                .filter(|line| line.starts_with("FOOTPRINT "))
                .collect::<Vec<_>>(),
            [marker],
            "snapshot must retain the same checked client/runtime computation"
        );
        let maps = maps_snapshot(&snapshot_stdout);
        eprintln!(
            "MAPS_OBSERVATION {label} bytes={} rows={}",
            maps.len(),
            maps.iter().filter(|byte| **byte == b'\n').count()
        );
        if let Some(artifacts) = &artifacts {
            fs::write(artifacts.join(label).join("maps.raw"), maps).unwrap();
        }
        observations.push(FootprintObservation {
            label,
            client: client_image,
            runtime: runtime_image,
            client_base: footprint_field(marker, "client_base"),
            runtime_base: footprint_field(marker, "runtime_base"),
            guest_mmap: footprint_field(mappings[0], "MMAP"),
        });
    }
    let [small, client_large, runtime_large] = observations.as_slice() else {
        unreachable!();
    };
    assert!(
        client_large.client.span > small.client.span,
        "{observations:#?}"
    );
    assert!(
        client_large.client.file_bytes > small.client.file_bytes,
        "{observations:#?}"
    );
    assert!(
        runtime_large.runtime.span > small.runtime.span,
        "{observations:#?}"
    );
    assert!(
        runtime_large.runtime.file_bytes > small.runtime.file_bytes,
        "{observations:#?}"
    );
    assert_eq!(
        client_large.runtime.span, small.runtime.span,
        "{observations:#?}"
    );
    assert_eq!(
        runtime_large.client.span, small.client.span,
        "{observations:#?}"
    );
    for observation in &observations {
        // Emit actual bases/extents for a separate reservation/containment trace.
        // Arena membership is deliberately not inferred from an internal-address bit.
        eprintln!(
            "FOOTPRINT_OBSERVATION {} client={:#x}+{:#x} runtime={:#x}+{:#x} mmap={:#x}",
            observation.label,
            observation.client_base,
            observation.client.span,
            observation.runtime_base,
            observation.runtime.span,
            observation.guest_mmap,
        );
    }
    assert_eq!(
        client_large.guest_mmap, small.guest_mmap,
        "{observations:#?}"
    );
    assert_eq!(
        runtime_large.guest_mmap, small.guest_mmap,
        "{observations:#?}"
    );
}

// These controls use the actual auxiliary-loader API. They do not infer VMM
// ownership from dr_memory_is_dr_internal or turn setup failures into skips.
const AUX_MISSING_LEAF: &str = "libdr_private_missing_20261020.so";
const AUX_ARENA_BYTES: u64 = 64 * 1024 * 1024;
const AUX_OWNER_FAILURE: &str =
    "private image VMM ownership indeterminate after fixed mapping or restoration failure";
const AUX_EXHAUSTED: &str = "private image VMM unavailable or exhausted";
const AUX_OPTION_REFUSAL: &str = "private image VMM requires vm_reserve without satisfy_w_xor_x";

struct AuxControlFixture {
    fixture: Fixture,
    client: PathBuf,
    app: PathBuf,
    empty_search: PathBuf,
}

impl AuxControlFixture {
    fn new() -> Self {
        let fixture = Fixture::new();
        let root = fixture.temp.path();
        let empty_search = root.join("empty-search");
        fs::create_dir(&empty_search).unwrap();
        fs::create_dir(root.join("images")).unwrap();
        fs::create_dir(root.join("link-only")).unwrap();
        let client = root.join("aux-client.so");
        let install = fixture.drrun.parent().unwrap().parent().unwrap();
        checked(
            fixture
                .cc("aux_loader_client.c", &client)
                .args(["-DLINUX", "-DX86_64"])
                .arg("-I")
                .arg(install.join("include")),
        );
        dynamic(&client, &[], None);
        let app = root.join("aux-app");
        checked(
            Command::new(&fixture.compiler)
                .args(["-static", "-nostdlib", "-nostartfiles", "-Wl,-e,_start"])
                .arg(fixture.sources.join("app.S"))
                .arg("-o")
                .arg(&app),
        );
        Self {
            fixture,
            client,
            app,
            empty_search,
        }
    }

    fn workspace(&self, name: &str, bytes: u64, dependency: Option<&Path>) -> PathBuf {
        let output = self.fixture.temp.path().join("images").join(name);
        let mut command = self.fixture.cc("aux_workspace.c", &output);
        command
            .arg(format!("-DWORKSPACE_BYTES={bytes}"))
            .arg(format!("-Wl,-soname,{name}"));
        if let Some(dependency) = dependency {
            command
                .arg("-DAUX_REQUIRES_LEAF")
                .arg("-Wl,--no-as-needed")
                .arg(dependency);
        }
        checked(&mut command);
        dynamic(
            &output,
            if dependency.is_some() {
                &[AUX_MISSING_LEAF]
            } else {
                &[]
            },
            None,
        );
        let image = footprint_image(&output);
        assert!(image.span >= bytes, "workspace omitted: {image:?}");
        assert!(
            image.file_bytes < 1024 * 1024,
            "BSS must not become file padding"
        );
        eprintln!(
            "AUX_IMAGE path={} span={:#x} file_bytes={:#x}",
            output.display(),
            image.span,
            image.file_bytes
        );
        output
    }

    fn argv(&self, client_args: &[&Path], no_reserve: bool) -> Vec<PathBuf> {
        let mut argv = vec![self.fixture.drrun.clone()];
        argv.extend(
            [
                "-quiet",
                "-disable_rseq",
                "-vm_max_offset",
                "0x0",
                "-vm_base",
                "0x40000000",
                "-vm_size",
                "64M",
                "-no_vm_base_near_app",
                "-no_vm_allow_not_at_base",
                "-no_vm_allow_smaller",
            ]
            .map(PathBuf::from),
        );
        if no_reserve {
            argv.push("-no_vm_reserve".into());
        }
        argv.push("-c".into());
        argv.push(self.client.clone());
        argv.extend(client_args.iter().map(|path| path.to_path_buf()));
        argv.push("--".into());
        argv.push(self.app.clone());
        argv
    }

    fn execute(&self, label: &str, argv: &[PathBuf]) -> (ExitStatus, String) {
        let artifacts = std::env::var_os("REVERIE_DBT_PRIVATE_LOADER_ARTIFACTS").map(|root| {
            let root = PathBuf::from(root).join("auxiliary");
            fs::create_dir_all(&root).unwrap();
            let destination = root.join(label);
            fs::create_dir(&destination).expect("fresh auxiliary-loader evidence directory");
            for file in [&self.client, &self.app] {
                fs::copy(file, destination.join(file.file_name().unwrap())).unwrap();
            }
            let images = destination.join("images");
            fs::create_dir(&images).unwrap();
            for entry in fs::read_dir(self.fixture.temp.path().join("images")).unwrap() {
                let file = entry.unwrap().path();
                assert!(file.is_file(), "fixture image must be a regular file");
                let name = file.file_name().unwrap();
                fs::copy(&file, images.join(name)).unwrap();
                fs::write(
                    images.join(name).with_extension("phdrs"),
                    checked(Command::new("readelf").args(["-W", "-l"]).arg(&file)),
                )
                .unwrap();
            }
            destination
        });
        let borrowed: Vec<_> = argv.iter().map(PathBuf::as_path).collect();
        let (status, output) =
            self.fixture
                .execute_with_layout(label, &borrowed, &self.empty_search, true);
        let text = String::from_utf8(output).unwrap();
        if let Some(directory) = artifacts {
            fs::write(directory.join("output.txt"), &text).unwrap();
        }
        eprintln!("AUX_CONTROL {label} status={status}\n{text}");
        (status, text)
    }
}

fn assert_aux_recovery(text: &str, mode: &str, attempts: usize) {
    assert!(!text.contains("AUX_FIXTURE_FAILURE"), "{text}");
    let returned: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("AUX_FAILURE_RETURNED "))
        .collect();
    let recovered: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("AUX_RECOVERY_OK "))
        .collect();
    let expected_returned: Vec<_> = (1..=attempts)
        .map(|attempt| format!("AUX_FAILURE_RETURNED mode={mode} attempt={attempt}"))
        .collect();
    let expected_recovered: Vec<_> = (1..=attempts)
        .map(|attempt| format!("AUX_RECOVERY_OK mode={mode} attempt={attempt}"))
        .collect();
    assert_eq!(returned, expected_returned, "{text}");
    assert_eq!(recovered, expected_recovered, "{text}");
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("AUX_CONTROL_OK "))
            .collect::<Vec<_>>(),
        [format!("AUX_CONTROL_OK {mode}")],
        "{text}"
    );
}

#[test]
fn missing_aux_dependency_releases_known_owned_image() {
    let control = AuxControlFixture::new();
    let sentinel = control.workspace("libaux_sentinel.so", 4096, None);
    let valid = control.workspace("libaux_valid.so", 8192, None);
    let leaf = control
        .fixture
        .temp
        .path()
        .join("link-only")
        .join(AUX_MISSING_LEAF);
    checked(
        control
            .fixture
            .cc("leaf.c", &leaf)
            .arg(format!("-Wl,-soname,{AUX_MISSING_LEAF}")),
    );
    dynamic(&leaf, &[], None);
    let bad = control.workspace("libaux_missing.so", 32 * 1024 * 1024, Some(&leaf));
    // No DT_NEEDED dependency has loaded before the sole lookup fails. This
    // avoids asserting new recursive dependency unload/refcount behavior.
    fs::rename(&leaf, leaf.with_extension("link-input-only")).unwrap();
    assert!(!leaf.exists());
    let extent = footprint_image(&bad).span.checked_add(4096).unwrap();
    assert!(extent < AUX_ARENA_BYTES, "one image must fit: {extent:#x}");
    assert!(
        extent.checked_mul(3).unwrap() > AUX_ARENA_BYTES,
        "three retained image claims must exceed the whole arena"
    );
    let (status, text) = control.execute(
        "missing-import",
        &control.argv(&[Path::new("missing"), &sentinel, &valid, &bad], false),
    );
    assert!(status.success(), "{status}: {text}");
    assert_aux_recovery(&text, "missing", 3);
    assert!(
        !text.contains(AUX_EXHAUSTED) && !text.contains(AUX_OWNER_FAILURE),
        "{text}"
    );
    for attempt in 1..=3 {
        let start = format!("AUX_FAILURE_ATTEMPT mode=missing attempt={attempt}\n");
        let end = format!("AUX_FAILURE_RETURNED mode=missing attempt={attempt}\n");
        let diagnostic = text
            .split_once(&start)
            .unwrap()
            .1
            .split_once(&end)
            .unwrap()
            .0;
        assert!(
            diagnostic.contains(AUX_MISSING_LEAF)
                && diagnostic.contains("Unable to locate library!"),
            "attempt {attempt} must reach the existing import failure: {text}"
        );
    }
}

#[test]
fn oversized_aux_image_refuses_and_keeps_loader_usable() {
    let control = AuxControlFixture::new();
    let sentinel = control.workspace("libaux_sentinel.so", 4096, None);
    let valid = control.workspace("libaux_valid.so", 8192, None);
    let huge = control.workspace("libaux_oversized.so", 80 * 1024 * 1024, None);
    assert!(footprint_image(&huge).span > AUX_ARENA_BYTES);
    let (status, text) = control.execute(
        "exhaustion",
        &control.argv(&[Path::new("exhaustion"), &sentinel, &valid, &huge], false),
    );
    assert!(status.success(), "{status}: {text}");
    assert_aux_recovery(&text, "exhaustion", 1);
    assert!(text.contains(AUX_EXHAUSTED), "{text}");
    assert!(!text.contains(AUX_OWNER_FAILURE), "{text}");
}

#[test]
fn private_client_refuses_disabled_vm_reserve() {
    let control = AuxControlFixture::new();
    let (status, text) = control.execute(
        "disabled-reserve",
        &control.argv(&[Path::new("startup")], true),
    );
    assert_eq!(
        status.code(),
        Some(255),
        "retain initial-client load failure: {text}"
    );
    assert!(text.contains(AUX_OPTION_REFUSAL), "{text}");
    assert!(
        !text.contains("AUX_CONTROL_OK") && !text.contains("AUX_FIXTURE_FAILURE"),
        "{text}"
    );
}

#[test]
fn noexec_aux_segment_failure_is_terminal() {
    let control = AuxControlFixture::new();
    let image = control.workspace("libaux_noexec.so", 65536, None);
    let headers = checked(
        Command::new("readelf")
            .env("LC_ALL", "C")
            .args(["-W", "-l"])
            .arg(&image),
    );
    let loads: Vec<Vec<_>> = headers
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .filter(|words| words.first() == Some(&"LOAD"))
        .collect();
    assert!(loads.len() >= 2, "{headers}");
    assert!(
        loads[0].len() >= 8 && !loads[0][6..].contains(&"E"),
        "{headers}"
    );
    let first_file_bytes = u64::from_str_radix(loads[0][4].trim_start_matches("0x"), 16).unwrap();
    assert!(
        first_file_bytes > 0,
        "earlier segment must have file bytes: {headers}"
    );
    let executable = loads
        .iter()
        .skip(1)
        .find(|words| words[6..].contains(&"E"))
        .expect("a later actual executable PT_LOAD");
    let executable_file_bytes =
        u64::from_str_radix(executable[4].trim_start_matches("0x"), 16).unwrap();
    assert!(
        executable_file_bytes > 0,
        "later segment must have file bytes: {headers}"
    );
    let rx_offset = u64::from_str_radix(executable[1].trim_start_matches("0x"), 16).unwrap();
    assert!(rx_offset > 0 && rx_offset % 4096 == 0, "{headers}");
    eprintln!("AUX_NOEXEC_PHDRS {}\n{headers}", image.display());
    let probe = control.fixture.temp.path().join("noexec-probe");
    checked(
        Command::new(&control.fixture.compiler)
            .arg(control.fixture.sources.join("noexec_probe.c"))
            .arg("-o")
            .arg(&probe),
    );
    let mountpoint = control.fixture.temp.path().join("private-noexec");
    fs::create_dir(&mountpoint).unwrap();
    let mounted_image = mountpoint.join("libaux_noexec.so");
    // Existing private user/mount namespace pattern. Only the data DSO is on
    // noexec. The shell/probe/drrun/client/application execute outside it.
    // set -e makes unavailable namespace/mount/preflight a failure, never a skip.
    let script = r#"
source=$1
mountpoint=$2
probe=$3
rx_offset=$4
shift 4
mount -t tmpfs -o noexec,nosuid,nodev,size=1M none "$mountpoint"
cp -- "$source" "$mountpoint/libaux_noexec.so"
cmp -- "$source" "$mountpoint/libaux_noexec.so"
"$probe" "$mountpoint/libaux_noexec.so" "$rx_offset"
exec "$@"
"#;
    let mut argv: Vec<PathBuf> = [
        "unshare",
        "--user",
        "--map-root-user",
        "--mount",
        "--propagation",
        "private",
        "sh",
        "-eu",
        "-c",
        script,
        "sh",
    ]
    .map(PathBuf::from)
    .into();
    argv.extend([image, mountpoint, probe, format!("{rx_offset:#x}").into()]);
    argv.extend(control.argv(&[Path::new("terminal"), &mounted_image], false));
    let (status, text) = control.execute("noexec-terminal", &argv);
    assert!(
        text.contains("NOEXEC_PROBE nonexec_mmap=ok executable_mmap=EPERM"),
        "{text}"
    );
    assert!(text.contains("AUX_TERMINAL_ATTEMPT"), "{text}");
    assert!(text.contains(AUX_OWNER_FAILURE), "{status}: {text}");
    // Observe the terminal status rather than guessing os_terminate's platform
    // encoding. Existing execute() separately refuses timeouts/forced kills.
    assert!(
        !status.success(),
        "terminal failure unexpectedly succeeded: {text}"
    );
    assert!(
        !text.contains("AUX_TERMINAL_RETURNED")
            && !text.contains("AUX_FIXTURE_FAILURE")
            && !text.contains("AUX_CONTROL_OK"),
        "failure returned or retried: {text}"
    );
    // The companion external mapping trace, not this message alone, must prove
    // a prior non-X MAP_FIXED commit, later kernel EPERM, and no destructive
    // restoration/unreserve/fallback before death. No same-process retry claim.
}

// This exercises the existing initial-arena collision guard. It is not new
// owned-image behavior; the external trace checks non-destructive reservation.
#[test]
fn private_arena_collision_refuses_without_running_guest() {
    let control = AuxControlFixture::new();
    checked(
        Command::new(&control.fixture.compiler)
            .args(["-static", "-nostdlib", "-nostartfiles"])
            .arg(format!(
                "-Wl,-T,{}",
                control.fixture.sources.join("collision_app.ld").display()
            ))
            .arg(control.fixture.sources.join("collision_app.S"))
            .arg("-o")
            .arg(&control.app),
    );
    let phdrs = checked(Command::new("readelf").args(["-W", "-l"]).arg(&control.app));
    assert!(
        phdrs.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.first() == Some(&"LOAD") && fields.get(2) == Some(&"0x0000000040000000")
        }),
        "missing actual application PT_LOAD at the requested arena: {phdrs}"
    );
    let (native_status, native) = control.fixture.execute_with_layout(
        "collision-native",
        &[&control.app],
        &control.empty_search,
        true,
    );
    assert!(native_status.success(), "{native_status}: {native:?}");
    assert_eq!(native, b"COLLISION_CANARY_OK\n");
    let (status, output) = control.execute(
        "arena-collision",
        &control.argv(&[Path::new("startup")], false),
    );
    assert_eq!(status.code(), Some(255), "{status}: {output}");
    assert!(
        output.contains("Out of memory.  Program aborted."),
        "expected existing named initial-reservation refusal: {output}"
    );
    assert!(!output.contains("COLLISION_CANARY_OK"), "{output}");
    assert!(!output.contains("AUX_CONTROL_OK startup"), "{output}");
}
